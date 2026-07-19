// SPDX-License-Identifier: AGPL-3.0-or-later
/// E2c (#738) -- RPC protx-list MN-set seed KAT.
///
/// E2a proved the TIP half of NodeCoinState::populated() flips off the live
/// coin-P2P feed, but the DMN half had NO cold-start source: the P2P
/// Simplified MN List omits scriptPayout + nLastPaidHeight, and apply_block
/// only folds special txs from blocks we connect. mn_seed.hpp closes that gap
/// by converting dashd's `protx list valid true` JSON (payoutAddress +
/// lastPaidHeight -- everything GetMNPayee ordering needs) into the
/// (proTxHash -> MNState) vector the maintainer's leg-4 resync takes.
///
/// This suite pins, network-free:
///   * parse: payoutAddress -> scriptPayout is BYTE-EXACT (round-trip through
///     the same script_to_address encoding embedded_gbt emits), ordering
///     fields (lastPaid/registered/PoSe) land, dashd's -1 "never" sentinels
///     normalize to 0 (the UINT32_MAX wrap bug class), Evo typing, stats;
///   * fail-closed: ONE undecodable payoutAddress aborts the WHOLE seed
///     (empty return) -- a partial set could mint a wrong payee (the
///     bad-cb-payee class #746 fixed), an empty set is a safe set-gap;
///   * end-to-end: publishing the parsed seed through the REAL leg-4 event
///     (mn_list_update -> wire_mn_list_ingest -> on_mn_list_update) + a live
///     tip (new_tip -> wire_tip_ingest) flips populated() TRUE, select_work()
///     takes the EMBEDDED arm without touching the fallback, and the
///     template's MN payee is the seeded MN dashd's GetMNPayee ordering picks
///     (lowest lastPaid) -- the payee-correctness the E2c gate asserts.

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_seed.hpp>              // parse_protx_list_seed (DUT)
#include <impl/dash/coin/node_interface.hpp>       // dash::interfaces::Node
#include <impl/dash/coin/mn_list_ingest.hpp>       // wire_mn_list_ingest (leg 4)
#include <impl/dash/coin/tip_ingest.hpp>           // wire_tip_ingest (leg 2)
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/rpc_data.hpp>

#include <core/address_utils.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using dash::coin::CoinStateMaintainer;
using dash::coin::MNState;
using dash::coin::MnSeedStats;
using dash::coin::NodeCoinState;
using dash::coin::parse_protx_list_seed;
using dash::coin::WorkSource;
using nlohmann::json;

static constexpr uint8_t  DASH_PUBKEY_VER = 76;   // mainnet 'X...'
static constexpr uint8_t  DASH_P2SH_VER   = 16;   // mainnet '7...'
static constexpr uint32_t H = 2'400'000;          // past MN_RR

// A deterministic 25-byte P2PKH scriptPubKey.
static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

// The base58 address dashd's EncodeDestination would report for that script --
// produced by the SAME script_to_address the embedded template payee encoding
// uses, so the KAT pins the full round trip address -> script -> address.
static std::string addr_of(const std::vector<unsigned char>& script) {
    return ::core::script_to_address(script, /*bech32_hrp=*/"",
                                     DASH_PUBKEY_VER, DASH_P2SH_VER);
}

// One detailed `protx list valid true` entry, dashd JSON shape.
static json protx_entry(uint8_t idbyte, const std::string& payout_addr,
                        int64_t last_paid, int64_t registered,
                        const std::string& type = "Regular") {
    std::string protx(64, '0');
    protx[0] = static_cast<char>('0' + (idbyte % 10));
    std::string coll(64, 'a');
    return json{
        {"type", type},
        {"proTxHash", protx},
        {"collateralHash", coll},
        {"collateralIndex", 1},
        {"operatorReward", 0.0},
        {"state", {
            {"version", 2},
            {"service", "203.0.113.7:9999"},
            {"registeredHeight", registered},
            {"lastPaidHeight", last_paid},
            {"consecutivePayments", 0},
            {"PoSePenalty", 0},
            {"PoSeRevivedHeight", -1},   // dashd "never" sentinel
            {"PoSeBanHeight", -1},       // dashd "never" sentinel
            {"revocationReason", 0},
            {"ownerAddress", payout_addr},
            {"votingAddress", payout_addr},
            {"payoutAddress", payout_addr},
            {"pubKeyOperator", std::string(96, '0')}
        }}
    };
}

// ── parse: payout script byte-exact + ordering fields + sentinels ──────────
TEST(DashMnSeed, ParsesPayoutBearingSet)
{
    const auto script_a = p2pkh_script(0x11);
    const auto script_b = p2pkh_script(0x22);
    json list = json::array({
        protx_entry(1, addr_of(script_a), 2'350'000, 2'300'000),
        protx_entry(2, addr_of(script_b), 2'351'000, 2'300'100, "Evo"),
    });

    MnSeedStats st;
    auto seed = parse_protx_list_seed(list, DASH_PUBKEY_VER, DASH_P2SH_VER, &st);
    ASSERT_EQ(seed.size(), 2u);
    EXPECT_EQ(st.total, 2u);
    EXPECT_EQ(st.seeded, 2u);
    EXPECT_EQ(st.evo, 1u);
    EXPECT_EQ(st.payout_decode_failed, 0u);

    // THE keystone: scriptPayout reproduced byte-exactly from the address.
    EXPECT_EQ(seed[0].second.scriptPayout.m_data, script_a);
    EXPECT_EQ(seed[1].second.scriptPayout.m_data, script_b);

    // GetMNPayee ordering inputs (what the P2P SML can never provide).
    EXPECT_EQ(seed[0].second.nLastPaidHeight,   2'350'000u);
    EXPECT_EQ(seed[0].second.nRegisteredHeight, 2'300'000u);
    EXPECT_EQ(seed[1].second.nLastPaidHeight,   2'351'000u);

    // dashd -1 sentinels normalize to 0 -- NOT the UINT32_MAX wrap that made
    // one never-paid MN win find_expected_payee forever (mn_state_machine
    // SENTINEL note).
    EXPECT_EQ(seed[0].second.nPoSeRevivedHeight, 0u);
    EXPECT_EQ(seed[0].second.nPoSeBanHeight,     0u);
    EXPECT_TRUE(seed[0].second.isValid);

    // Evo typing.
    EXPECT_EQ(seed[1].second.nType, dash::coin::vendor::MnType::EVO);
    EXPECT_EQ(seed[0].second.nType, dash::coin::vendor::MnType::REGULAR);
}

// ── fail-closed: one bad payoutAddress aborts the WHOLE seed ───────────────
TEST(DashMnSeed, FailsClosedOnUndecodablePayoutAddress)
{
    json list = json::array({
        protx_entry(1, addr_of(p2pkh_script(0x11)), 2'350'000, 2'300'000),
        protx_entry(2, "not-a-dash-address", 2'351'000, 2'300'100),
    });
    MnSeedStats st;
    auto seed = parse_protx_list_seed(list, DASH_PUBKEY_VER, DASH_P2SH_VER, &st);
    EXPECT_TRUE(seed.empty());
    EXPECT_EQ(st.payout_decode_failed, 1u);

    // Wrong-chain version byte (a TESTNET address against mainnet versions)
    // must equally fail closed -- never seed a cross-net payee.
    const std::string testnet_addr = ::core::script_to_address(
        p2pkh_script(0x33), "", /*testnet p2pkh=*/140, /*testnet p2sh=*/19);
    json list2 = json::array({
        protx_entry(1, testnet_addr, 2'350'000, 2'300'000),
    });
    MnSeedStats st2;
    auto seed2 = parse_protx_list_seed(list2, DASH_PUBKEY_VER, DASH_P2SH_VER, &st2);
    EXPECT_TRUE(seed2.empty());
    EXPECT_EQ(st2.payout_decode_failed, 1u);
}

// ── non-array / empty results are safe set-gaps ────────────────────────────
TEST(DashMnSeed, EmptyOrNonArrayYieldsEmptySeed)
{
    MnSeedStats st;
    EXPECT_TRUE(parse_protx_list_seed(json::object(), DASH_PUBKEY_VER,
                                      DASH_P2SH_VER, &st).empty());
    EXPECT_TRUE(parse_protx_list_seed(json::array(), DASH_PUBKEY_VER,
                                      DASH_P2SH_VER, &st).empty());
}

// ── end-to-end: seed -> leg-4 event -> populated() flips -> EMBEDDED
//    template pays the CORRECT (lowest-lastPaid) seeded MN ──────────────────
TEST(DashMnSeed, SeedFlipsPopulatedAndEmbeddedTemplatePaysSeededPayee)
{
    dash::interfaces::Node node;
    NodeCoinState state;
    CoinStateMaintainer maint(state);
    auto sub_mn  = c2pool::dash::wire_mn_list_ingest(node, maint);
    auto sub_tip = c2pool::dash::wire_tip_ingest(node, maint);

    // Two seeded MNs; MN A (lower lastPaid) is what dashd's GetMNPayee
    // ordering pays next -- the embedded template must agree.
    const auto script_a = p2pkh_script(0x11);
    const auto script_b = p2pkh_script(0x22);
    const std::string addr_a = addr_of(script_a);
    json list = json::array({
        protx_entry(1, addr_a, 2'350'000, 2'300'000),
        protx_entry(2, addr_of(script_b), 2'351'000, 2'300'100),
    });
    auto seed = parse_protx_list_seed(list, DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_EQ(seed.size(), 2u);

    // Publish through the REAL leg-4 event -- no direct maintainer poke.
    dash::interfaces::MnListUpdate up;
    up.mnstates = std::move(seed);
    node.mn_list_update.happened(up);
    EXPECT_FALSE(state.populated());   // DMN half armed; tip half missing

    // Tip arrives (leg 2, real event): populated() flips.
    dash::interfaces::TipAdvance ta;
    ta.prev_height          = H - 1;
    ta.prev_hash            = uint256S("00000000000000000000000000000000"
                                       "000000000000000000000000000000aa");
    ta.bits_for_next        = 0x1a012345u;
    ta.mtp_at_tip           = 1'750'000'000u;
    ta.address_version      = DASH_PUBKEY_VER;
    ta.address_p2sh_version = DASH_P2SH_VER;
    node.new_tip.happened(ta);
    ASSERT_TRUE(state.populated());

    // get_work now takes the EMBEDDED arm; the fallback must NOT be touched.
    bool fallback_called = false;
    auto sel = state.select_work([&fallback_called]() {
        fallback_called = true;
        return dash::coin::DashWorkData{};
    });
    EXPECT_FALSE(fallback_called);
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_EQ(sel.work.m_height, H);

    // The MN payee in the packed payments is the seeded lowest-lastPaid MN's
    // address -- the same base58 wire form dashd's GBT "masternode" reports.
    bool found_payee = false;
    for (const auto& pp : sel.work.m_packed_payments) {
        if (pp.payee == addr_a) {
            found_payee = true;
            EXPECT_GT(pp.amount, 0u);
        }
        EXPECT_NE(pp.payee, addr_of(script_b));  // wrong MN must not be paid
    }
    EXPECT_TRUE(found_payee);

    // An EMPTY resync (set-gap) demotes back to the fallback.
    node.mn_list_update.happened(dash::interfaces::MnListUpdate{});
    EXPECT_FALSE(state.populated());
}
