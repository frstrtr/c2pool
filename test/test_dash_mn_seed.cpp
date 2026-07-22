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
#include <impl/dash/coin/block_connect_ingest.hpp> // wire_block_connect_ingest (leg 3)
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
    // Unique per-entry collateral: DIP3 consensus enforces unique collateral
    // outpoints, and the parser fail-closes on duplicates.
    std::string coll(64, 'a');
    coll[0] = static_cast<char>('0' + (idbyte % 10));
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

// ── malformed entries fail closed, never throw ─────────────────────────────
TEST(DashMnSeed, MalformedEntriesFailClosedWithoutThrowing)
{
    const std::string good_addr = addr_of(p2pkh_script(0x11));

    // Numeric proTxHash (type mismatch) -> empty, no escaping throw.
    auto bad_type = protx_entry(1, good_addr, 1, 1);
    bad_type["proTxHash"] = 12345;
    MnSeedStats st1;
    EXPECT_TRUE(parse_protx_list_seed(json::array({bad_type}),
                                      DASH_PUBKEY_VER, DASH_P2SH_VER,
                                      &st1).empty());
    EXPECT_EQ(st1.malformed, 1u);

    // Short/garbage proTxHash hex (uint256S would tolerate it and key the MN
    // under a wrong hash) -> empty.
    auto bad_hex = protx_entry(1, good_addr, 1, 1);
    bad_hex["proTxHash"] = "deadbeef";
    MnSeedStats st2;
    EXPECT_TRUE(parse_protx_list_seed(json::array({bad_hex}),
                                      DASH_PUBKEY_VER, DASH_P2SH_VER,
                                      &st2).empty());
    EXPECT_EQ(st2.malformed, 1u);

    // Type-guarded numeric fields degrade gracefully (no throw, no abort):
    // a string lastPaidHeight parses as 0 via the is_number guard.
    auto odd_height = protx_entry(1, good_addr, 1, 1);
    odd_height["state"]["lastPaidHeight"] = "not-a-number";
    MnSeedStats st3;
    auto seed3 = parse_protx_list_seed(json::array({odd_height}),
                                       DASH_PUBKEY_VER, DASH_P2SH_VER, &st3);
    ASSERT_EQ(seed3.size(), 1u);
    EXPECT_EQ(seed3[0].second.nLastPaidHeight, 0u);

    // A json type error on an unguarded .value() path (non-string "type")
    // is caught INSIDE the parser -> fail-closed empty, no escaping throw.
    auto bad_type_field = protx_entry(1, good_addr, 1, 1);
    bad_type_field["type"] = 5;
    MnSeedStats st5;
    EXPECT_TRUE(parse_protx_list_seed(json::array({bad_type_field}),
                                      DASH_PUBKEY_VER, DASH_P2SH_VER,
                                      &st5).empty());
    EXPECT_EQ(st5.malformed, 1u);

    // Duplicate collateral outpoint (impossible in a real DIP3 set; would
    // silently shadow in MnStateMachine::load's collateral index) -> empty.
    auto a = protx_entry(1, good_addr, 1, 1);
    auto b = protx_entry(2, addr_of(p2pkh_script(0x22)), 2, 2);
    b["collateralHash"]  = a["collateralHash"];
    b["collateralIndex"] = a["collateralIndex"];
    MnSeedStats st4;
    EXPECT_TRUE(parse_protx_list_seed(json::array({a, b}),
                                      DASH_PUBKEY_VER, DASH_P2SH_VER,
                                      &st4).empty());
    EXPECT_EQ(st4.malformed, 1u);
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

// ── snapshot as-of fence: blocks the seed already reflects must NOT
//    re-attribute their coinbase payments (the shared-payoutAddress queue
//    scramble observed live with the E2b 288-block bootstrap replay) ───────
TEST(DashMnSeed, SnapshotHeightFencesReplayedBlocks)
{
    dash::interfaces::Node node;
    NodeCoinState state;
    CoinStateMaintainer maint(state);
    auto sub_mn  = c2pool::dash::wire_mn_list_ingest(node, maint);
    auto sub_blk = c2pool::dash::wire_block_connect_ingest(node, maint);

    // Two MNs SHARING one payout script (the testnet reality that exposed
    // the bug), lastPaid current at the snapshot height 2'399'901.
    const auto shared = p2pkh_script(0x44);
    const std::string shared_addr = addr_of(shared);
    json list = json::array({
        protx_entry(1, shared_addr, 2'399'900, 2'300'000),
        protx_entry(2, shared_addr, 2'399'901, 2'300'100),
    });
    auto seed = parse_protx_list_seed(list, DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_EQ(seed.size(), 2u);
    const uint256 mn_a = seed[0].first;   // lastPaid 2'399'900 (queue front)

    dash::interfaces::MnListUpdate up;
    up.mnstates     = std::move(seed);
    up.as_of_height = 2'399'901;
    node.mn_list_update.happened(up);

    // A REPLAYED block at height <= as_of (its payment is already reflected
    // in the seed's lastPaid values) must not re-bump the queue front.
    auto paying_block = [&](uint32_t /*h*/) {
        dash::interfaces::BlockConnected bc;
        dash::coin::MutableTransaction cb;
        cb.version = 1; cb.type = 0;
        bitcoin_family::coin::TxOut o;
        o.value = 100'000'000;
        o.scriptPubKey.m_data = shared;
        cb.vout.push_back(o);
        bc.block.m_txs.push_back(cb);
        return bc;
    };
    auto bc_old = paying_block(2'399'901);
    bc_old.height = 2'399'901;
    node.block_connected.happened(bc_old);
    EXPECT_EQ(state.mnstates().entries().at(mn_a).nLastPaidHeight, 2'399'900u)
        << "replayed (<= as_of) block must not re-attribute its payment";

    // A NEW block above the snapshot height applies normally: the queue-front
    // MN (lowest lastPaid) is attributed the payment.
    auto bc_new = paying_block(2'399'902);
    bc_new.height = 2'399'902;
    node.block_connected.happened(bc_new);
    EXPECT_EQ(state.mnstates().entries().at(mn_a).nLastPaidHeight, 2'399'902u)
        << "post-snapshot block must fold normally";
}

// ════════════════════════════════════════════════════════════════════════
// FROM-WIRE regression vector (soak e4-e1e2b, bad-cb-payee class,
// captured 2026-07-23 from the REAL Dash testnet node @192.168.86.52):
//
//   - seed: the FRONT SIX of dashd's deterministic payment queue at height
//     1519543 (`protx list valid true 1519543`), verbatim JSON. Two of them
//     are Evo MNs; two payout-address GROUPS are shared (3x yVXDAM73…,
//     2x yeRZBWYf…) — the exact shared-address shape the soak corruption
//     exploited.
//   - blocks: the REAL testnet blocks 1519544/1519545/1519546 (getblock
//     verbosity 0), whose coinbases dashd accepted.
//
// dashd's authoritative attributions (protx list @h vs @h-1):
//   1519544 -> dc2e02ac… (yVXDAM73…)   1519545 -> 9b653e76… (Evo, yeRZBWYf…)
//   1519546 -> 91bbce94… (Evo, yeRZBWYf…)   next payee @1519547 -> 72ee70fa…
//
// The KAT asserts the embedded machine reproduces that schedule EXACTLY,
// and that a duplicated delivery of block 1519546 cannot advance the
// yeRZBWYf… group cursor (the soak failure mode: post-duplicate the machine
// projected the wrong payee at ~10%% of heights and dashd rejected the
// embedded block with bad-cb-payee).
// ════════════════════════════════════════════════════════════════════════

namespace {

// Dash TESTNET address version bytes (yeRZ…/yVXD… are testnet addresses).
constexpr uint8_t TESTNET_PUBKEY_VER = 140;
constexpr uint8_t TESTNET_P2SH_VER   = 19;

const char* kProtxFront6At1519543 =
        "[{\"type\":\"Regular\",\"proTxHash\":\"dc2e02ac95ce4ccc9843c38de7bdaf32f2a1d5966c054127a3f4ca4f4bbd5991\",\"c"
        "ollateralHash\":\"4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8\",\"collateralIndex\":"
        "34,\"collateralAddress\":\"yRXyymKDuWytHMJE9odBkUJjaayqk3giCq\",\"operatorReward\":0,\"state\":{\"version\":1,"
        "\"service\":\"68.67.122.64:19999\",\"registeredHeight\":838365,\"lastPaidHeight\":1519459,\"consecutivePaymen"
        "ts\":0,\"PoSePenalty\":0,\"PoSeRevivedHeight\":1367840,\"PoSeBanHeight\":-1,\"revocationReason\":0,\"ownerAddr"
        "ess\":\"yQxgY6sdiHRWmi8STNftizktwqy4zhndfS\",\"votingAddress\":\"yQxgY6sdiHRWmi8STNftizktwqy4zhndfS\",\"payo"
        "utAddress\":\"yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48\",\"pubKeyOperator\":\"0db85a27cd589d225beff9977aa0ac3255"
        "1d15bd906a899bc1ef33458d7c979118f92bf1de4ddb55144acc2f7cf6d854\"},\"confirmations\":681326,\"wallet\":{\"h"
        "asOwnerKey\":false,\"hasOperatorKey\":false,\"hasVotingKey\":false,\"ownsCollateral\":false,\"ownsPayeeScrip"
        "t\":false,\"ownsOperatorRewardScript\":false},\"metaInfo\":{\"lastDSQ\":578542,\"mixingTxCount\":0,\"outboundA"
        "ttemptCount\":0,\"lastOutboundAttempt\":0,\"lastOutboundAttemptElapsed\":1784749234,\"lastOutboundSuccess\""
        ":1783259090,\"lastOutboundSuccessElapsed\":1490144}},{\"type\":\"Evo\",\"proTxHash\":\"9b653e767b978c10346d93"
        "8c08dc8c5acd03c495f9d913e6fc652bfcae11a348\",\"collateralHash\":\"75fe9d8d90619576ef11deb8550d023366bf9d"
        "85e686dc6d5afba0aca8827e21\",\"collateralIndex\":2,\"collateralAddress\":\"yaBTTTgGBro5U3MHAMXDC4GbHj6Rnc8"
        "prr\",\"operatorReward\":0,\"state\":{\"version\":2,\"service\":\"68.67.122.4:19999\",\"registeredHeight\":142762"
        "3,\"lastPaidHeight\":1519460,\"consecutivePayments\":0,\"PoSePenalty\":0,\"PoSeRevivedHeight\":1446613,\"PoSe"
        "BanHeight\":-1,\"revocationReason\":0,\"ownerAddress\":\"ygDPwRAi4XVcgNjTTR71kayENznYRwinhy\",\"votingAddres"
        "s\":\"ygDPwRAi4XVcgNjTTR71kayENznYRwinhy\",\"platformNodeID\":\"0785881ea118c05df7bb9dd2195a78f10cdde0bb\","
        "\"platformP2PPort\":36656,\"platformHTTPPort\":1443,\"payoutAddress\":\"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A\""
        ",\"pubKeyOperator\":\"80ab2701950ef7a1e068b97d02a2ed1e64a8d38dd2d0e5a0d9de5432b3e1ad2c318109d89326d48ab"
        "6e285d6ac0bb22e\"},\"confirmations\":92096,\"wallet\":{\"hasOwnerKey\":false,\"hasOperatorKey\":false,\"hasVot"
        "ingKey\":false,\"ownsCollateral\":false,\"ownsPayeeScript\":false,\"ownsOperatorRewardScript\":false},\"meta"
        "Info\":{\"lastDSQ\":578522,\"mixingTxCount\":0,\"outboundAttemptCount\":0,\"lastOutboundAttempt\":0,\"lastOutb"
        "oundAttemptElapsed\":1784749234,\"lastOutboundSuccess\":1783455154,\"lastOutboundSuccessElapsed\":1294080"
        "}},{\"type\":\"Evo\",\"proTxHash\":\"91bbce94c34ebde0d099c0a2cb7635c0c31425ebabcec644f4f1a0854bfa605d\",\"col"
        "lateralHash\":\"6ce8545e25d4f03aba1527062d9583ae01827c65b234bd979aca5954c6ae3a59\",\"collateralIndex\":30"
        ",\"collateralAddress\":\"yhgAPgRNVEdK6eDG3ngvTDc4eUKdRM2woR\",\"operatorReward\":0,\"state\":{\"version\":2,\"s"
        "ervice\":\"68.67.122.15:19999\",\"registeredHeight\":850334,\"lastPaidHeight\":1519461,\"consecutivePayments"
        "\":0,\"PoSePenalty\":0,\"PoSeRevivedHeight\":1368973,\"PoSeBanHeight\":-1,\"revocationReason\":0,\"ownerAddres"
        "s\":\"yfEfxRYgc2LMY7LjunL9vHWfb5FPnHgowZ\",\"votingAddress\":\"yfEfxRYgc2LMY7LjunL9vHWfb5FPnHgowZ\",\"platfo"
        "rmNodeID\":\"02aa69f8ef6666e7cad6d9323755a0ef3c1b6bd9\",\"platformP2PPort\":36656,\"platformHTTPPort\":1443"
        ",\"payoutAddress\":\"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A\",\"pubKeyOperator\":\"81ad0f9be5a88ae62ff54fe938df"
        "ceea71be03bd4c6a7aebf75896e8d495d310acc4146aa4820bc0e5f5b06579dedea5\"},\"confirmations\":669357,\"walle"
        "t\":{\"hasOwnerKey\":false,\"hasOperatorKey\":false,\"hasVotingKey\":false,\"ownsCollateral\":false,\"ownsPaye"
        "eScript\":false,\"ownsOperatorRewardScript\":false},\"metaInfo\":{\"lastDSQ\":578540,\"mixingTxCount\":0,\"out"
        "boundAttemptCount\":0,\"lastOutboundAttempt\":0,\"lastOutboundAttemptElapsed\":1784749234,\"lastOutboundSu"
        "ccess\":1784208362,\"lastOutboundSuccessElapsed\":540872}},{\"type\":\"Regular\",\"proTxHash\":\"72ee70fa75262"
        "781a17d1eb69a6c3e97328208be98b59d5530164f31e481d3aa\",\"collateralHash\":\"4ee3ff5074723d995f4cb957a9545"
        "87c6c637a42655ada8f4054037b28d1e7a8\",\"collateralIndex\":96,\"collateralAddress\":\"yfbqanJdStcfLwYDxGNVV"
        "HZiT6qUbvcDdQ\",\"operatorReward\":0,\"state\":{\"version\":1,\"service\":\"68.67.122.67:19999\",\"registeredHei"
        "ght\":838365,\"lastPaidHeight\":1519462,\"consecutivePayments\":0,\"PoSePenalty\":0,\"PoSeRevivedHeight\":136"
        "7330,\"PoSeBanHeight\":-1,\"revocationReason\":0,\"ownerAddress\":\"yYmpgYanZZNmYprdTLhSvscUqzGMHCD5F7\",\"vo"
        "tingAddress\":\"yYmpgYanZZNmYprdTLhSvscUqzGMHCD5F7\",\"payoutAddress\":\"yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT4"
        "8\",\"pubKeyOperator\":\"91f9052f62561db112ddca7df3d914d546866b130124eccb2ae1e8419563e51f239b2efec3d1b3f"
        "d388072610939d694\"},\"confirmations\":681326,\"wallet\":{\"hasOwnerKey\":false,\"hasOperatorKey\":false,\"has"
        "VotingKey\":false,\"ownsCollateral\":false,\"ownsPayeeScript\":false,\"ownsOperatorRewardScript\":false},\"m"
        "etaInfo\":{\"lastDSQ\":578487,\"mixingTxCount\":0,\"outboundAttemptCount\":0,\"lastOutboundAttempt\":0,\"lastO"
        "utboundAttemptElapsed\":1784749234,\"lastOutboundSuccess\":1783435021,\"lastOutboundSuccessElapsed\":1314"
        "213}},{\"type\":\"Regular\",\"proTxHash\":\"c87218fb9d031f4926c22430c69b4edf1f0fb80c331c1a79e3b1b3873407c0a"
        "c\",\"collateralHash\":\"4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8\",\"collateralIn"
        "dex\":62,\"collateralAddress\":\"yWausFtKkqUgPXsBen7H84fJ2vhqwXoA6K\",\"operatorReward\":0,\"state\":{\"versio"
        "n\":1,\"service\":\"68.67.122.56:19999\",\"registeredHeight\":838365,\"lastPaidHeight\":1519463,\"consecutiveP"
        "ayments\":0,\"PoSePenalty\":0,\"PoSeRevivedHeight\":1367840,\"PoSeBanHeight\":-1,\"revocationReason\":0,\"owne"
        "rAddress\":\"yUi9YLkmErtbsrkbyCBFkwN4ic31GbCtB3\",\"votingAddress\":\"yUi9YLkmErtbsrkbyCBFkwN4ic31GbCtB3\","
        "\"payoutAddress\":\"yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48\",\"pubKeyOperator\":\"842c53c3aa11ae4b985a52ae6a317"
        "0bdb58f88ec04c62013f9322bd5fda4417939836b6f41741dd864c348103a1155d3\"},\"confirmations\":681326,\"wallet"
        "\":{\"hasOwnerKey\":false,\"hasOperatorKey\":false,\"hasVotingKey\":false,\"ownsCollateral\":false,\"ownsPayee"
        "Script\":false,\"ownsOperatorRewardScript\":false},\"metaInfo\":{\"lastDSQ\":578525,\"mixingTxCount\":0,\"outb"
        "oundAttemptCount\":0,\"lastOutboundAttempt\":0,\"lastOutboundAttemptElapsed\":1784749234,\"lastOutboundSuc"
        "cess\":1777357130,\"lastOutboundSuccessElapsed\":7392104}},{\"type\":\"Regular\",\"proTxHash\":\"ecebeb952f56a"
        "61abaccd7bda7f4df5eccbd5f87a91bc4a8969535df1058158e\",\"collateralHash\":\"f329c4c9d194159e81597e50144ce"
        "41a40e2b40860c7813a85eabb0454700a3d\",\"collateralIndex\":1,\"collateralAddress\":\"yMaRbUBSrfEqSGjJUPiC2N"
        "icdVQB4m4zuQ\",\"operatorReward\":0,\"state\":{\"version\":2,\"service\":\"78.17.70.175:19999\",\"registeredHeig"
        "ht\":1491043,\"lastPaidHeight\":1519464,\"consecutivePayments\":0,\"PoSePenalty\":0,\"PoSeRevivedHeight\":150"
        "7780,\"PoSeBanHeight\":-1,\"revocationReason\":0,\"ownerAddress\":\"yfZjU5gZQhzh85VBo2sxoH1Ut8Y5Ro6Ncr\",\"vo"
        "tingAddress\":\"yfVwUDTsuvbphbaR671SskWmek6SMsHbc6\",\"payoutAddress\":\"yjTpMw9buZfv4jNkf87AHpDj95YSAFuDi"
        "X\",\"pubKeyOperator\":\"93b72005436c6e4dbd6b59cf5818fd9679a4a2c51548fb9205c88852b4bb5f05d1bfc72a54035b6"
        "85fceaaae2115d43f\"},\"confirmations\":28647,\"wallet\":{\"hasOwnerKey\":false,\"hasOperatorKey\":false,\"hasV"
        "otingKey\":false,\"ownsCollateral\":false,\"ownsPayeeScript\":false,\"ownsOperatorRewardScript\":false},\"me"
        "taInfo\":{\"lastDSQ\":578533,\"mixingTxCount\":0,\"outboundAttemptCount\":0,\"lastOutboundAttempt\":0,\"lastOu"
        "tboundAttemptElapsed\":1784749234,\"lastOutboundSuccess\":1784716675,\"lastOutboundSuccessElapsed\":32559"
        "}}]";

const char* kBlockHex1519544 =
        "000000201b543a9bb905794129b5b965a55176e1d6169de90d22d464d37f41ba4800000095d95cbd42771d55f34c46009d29"
        "27f0684b22ca85667a2c0cb1626b0952138dfcc9606a4518511d0002780e0103000500010000000000000000000000000000"
        "000000000000000000000000000000000000ffffffff1303b82f170e2f5032506f6f6c2d74444153482fffffffff05056583"
        "03000000001976a9142629e1bbb4960da4c86226c876019e55c7c0346288ac2ed5fd0300000000016af80da7060000000019"
        "76a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788acb3e60800000000001976a91420cb5c22b1e4d5947e5c112c76"
        "96b51ad9af3c6188ac00000000000000002a6a282ad8f902c1ae2fece365590e4009eda31825336f273077a41697c43a54c0"
        "835f000000000000000000000000af0300b82f17007edd5fec21fd07f7b9d44b5029884ebc71d2e2812fd3029a76690045ce"
        "5c1647eb3ef20c2f89e9b8525f21e7064a47305b867ed642db1166faa9e0461fa0ee1d01b1a377ba4ad754bcc9bc00da609a"
        "d3482ad7acc7847039a0424300c35a2e99c4ea6f3659e987f86eb9559fb88a020bf404d9fe2c33e097e13647f55fbe0d6941"
        "e306f7bf206728634bff7e52a49d9e4b1b969017abd30c32ebc08d0c623cd98bb460a399f41e0000";

const char* kBlockHex1519545 =
        "0000002013912532ebf7d4e655abf829f99d670de25fdb46d2cbcc6d567b6f294200000070151825df25a1f90162dfc2d978"
        "8b7dfdc8a690f9a61f0f8dd3f93e43bb5a2234ca606ac3fd4c1d00358c470103000500010000000000000000000000000000"
        "000000000000000000000000000000000000ffffffff1303b92f170e2f5032506f6f6c2d74444153482fffffffff050c6583"
        "03000000001976a9142629e1bbb4960da4c86226c876019e55c7c0346288ac2ed5fd0300000000016af80da7060000000019"
        "76a914c69a0bda7daaae481be8def95e5f347a1d00a4b488acace60800000000001976a91420cb5c22b1e4d5947e5c112c76"
        "96b51ad9af3c6188ac00000000000000002a6a2863ff5a8eb9b8e769435056d98f1831c46eaee642b6d17d0e9148d9b8385e"
        "434a000000000000000000000000af0300b92f17007edd5fec21fd07f7b9d44b5029884ebc71d2e2812fd3029a76690045ce"
        "5c1647eb3ef20c2f89e9b8525f21e7064a47305b867ed642db1166faa9e0461fa0ee1d0191d1a83a98f0b7b8cfb7f7ffca11"
        "6dd416960ec91ef8a0052ca0ac2ff7f0fcddf0c38f6894765f7ba11c6fa25385ca9d1498cd5d5581b9ca2603fd2d35a16dfe"
        "24cfd3dd49326da6d0d371cf3f97921c471ab5ad2eba487f680ced98063b26a9e235a19df41e0000";

const char* kBlockHex1519546 =
        "00000020c9497b889ffb56364da48fd35c7673dc51df02c382bc2a3876b91e5138000000a2de65097455b4ae92412e868d9a"
        "c9d71c6f79322c1c10ddcab218e0bf004ff4e2ca606a76b04b1d000441980403000500010000000000000000000000000000"
        "000000000000000000000000000000000000ffffffff1303ba2f170e2f5032506f6f6c2d74444153482fffffffff05e16483"
        "03000000001976a9142629e1bbb4960da4c86226c876019e55c7c0346288ac2ed5fd0300000000016af80da7060000000019"
        "76a914c69a0bda7daaae481be8def95e5f347a1d00a4b488acd7e60800000000001976a91420cb5c22b1e4d5947e5c112c76"
        "96b51ad9af3c6188ac00000000000000002a6a2867e657696ff842bd354401663fb597a5edb52be7d029fdbdc710894c9776"
        "3512000000000000000000000000af0300ba2f17007edd5fec21fd07f7b9d44b5029884ebc71d2e2812fd3029a76690045ce"
        "5c1647eb3ef20c2f89e9b8525f21e7064a47305b867ed642db1166faa9e0461fa0ee1d01b836c031e91cc8b43129c7b1a93b"
        "2bf2e5ce31803a848318680d8144ba28379a8d769a313882306a5e3f4a10814466a511415c388a2ab98201c312e7ec291194"
        "31693053caad6df9d98a187588145cea3eb42b741eb3959abdf9138167fe993a100b9fa1f41e000003000600000000000000"
        "fd49010100ba2f170003000148f97725a2106d1fa6c4dc099de8acdc72b5b6b601751e65201adf9512000000320000000000"
        "0000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000003000600000000000000fd55010100ba2f17"
        "0003000448f97725a2106d1fa6c4dc099de8acdc72b5b6b601751e65201adf95120000006400000000000000000000000000"
        "6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000003000600000000000000fd430101"
        "00ba2f170003000648f97725a2106d1fa6c4dc099de8acdc72b5b6b601751e65201adf951200000019000000001900000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000";

dash::coin::BlockType block_from_hex(const char* hex) {
    std::string h(hex);
    std::vector<unsigned char> raw;
    raw.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        raw.push_back(static_cast<unsigned char>(
            std::stoul(h.substr(i, 2), nullptr, 16)));
    ::PackStream ps(raw);
    dash::coin::BlockType blk;
    ps >> blk;
    return blk;
}

} // namespace

TEST(DashMnSeed, RealTestnetVectorProjectionTracksDashdSchedule) {
    MnSeedStats st;
    auto seed = parse_protx_list_seed(json::parse(kProtxFront6At1519543),
                                      TESTNET_PUBKEY_VER, TESTNET_P2SH_VER, &st);
    ASSERT_EQ(seed.size(), 6u) << "all six from-wire entries must seed";
    EXPECT_EQ(st.evo, 2u);

    dash::coin::MnStateMachine m;
    m.load(std::move(seed));

    const uint256 mn_1519544 = uint256S(
        "dc2e02ac95ce4ccc9843c38de7bdaf32f2a1d5966c054127a3f4ca4f4bbd5991");
    const uint256 mn_1519545 = uint256S(
        "9b653e767b978c10346d938c08dc8c5acd03c495f9d913e6fc652bfcae11a348");
    const uint256 mn_1519546 = uint256S(
        "91bbce94c34ebde0d099c0a2cb7635c0c31425ebabcec644f4f1a0854bfa605d");
    const uint256 mn_1519547 = uint256S(
        "72ee70fa75262781a17d1eb69a6c3e97328208be98b59d5530164f31e481d3aa");

    // Projection at 1519544 (list @1519543) == dashd's payee.
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, mn_1519544);

    // Apply the real accepted blocks; each attribution must land on exactly
    // the MN dashd credited.
    auto b44 = block_from_hex(kBlockHex1519544);
    auto b45 = block_from_hex(kBlockHex1519545);
    auto b46 = block_from_hex(kBlockHex1519546);
    ASSERT_FALSE(b44.m_txs.empty());
    ASSERT_FALSE(b45.m_txs.empty());
    ASSERT_FALSE(b46.m_txs.empty());

    auto r44 = m.apply_block(b44, 1519544);
    EXPECT_EQ(r44.paid, 1u);
    EXPECT_FALSE(r44.payee_desync);
    EXPECT_EQ(m.entries().at(mn_1519544).nLastPaidHeight, 1519544u);

    exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, mn_1519545) << "next payee after 1519544 must be the Evo MN 9b653e76";

    auto r45 = m.apply_block(b45, 1519545);
    EXPECT_EQ(r45.paid, 1u);
    EXPECT_EQ(m.entries().at(mn_1519545).nLastPaidHeight, 1519545u);

    exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, mn_1519546);

    auto r46 = m.apply_block(b46, 1519546);
    EXPECT_EQ(r46.paid, 1u);
    EXPECT_EQ(m.entries().at(mn_1519546).nLastPaidHeight, 1519546u);

    exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, mn_1519547) << "projection after the three real blocks";

    // THE soak failure mode: a duplicated delivery of block 1519546. Pre-fix
    // the observation attribution re-picked inside the shared yeRZBWYf… group
    // and marked 9b653e76 a second time — shifting the group cursor one slot
    // ahead of dashd forever. Post-fix the duplicate is skipped whole.
    auto rdup = m.apply_block(b46, 1519546);
    EXPECT_TRUE(rdup.skipped_out_of_order);
    EXPECT_EQ(rdup.paid, 0u);
    EXPECT_EQ(m.entries().at(mn_1519545).nLastPaidHeight, 1519545u)
        << "duplicate apply must not advance the shared-address group cursor";
    exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, mn_1519547)
        << "projection must be unchanged by a duplicated block delivery";
}
