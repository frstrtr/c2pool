/// Regression tests for the Phase C-PAY attribution bugs found by the
/// 2026-04-25 mainnet shadow soak. Three bugs all produced the same
/// surface symptom (constant `expected` hash → 100% [PAY] MISMATCH)
/// but each had a distinct root cause; the tests below pin each fix
/// independently so a future refactor can't silently regress one.
///
/// Bug 1  (`e4c7c108`)  — UINT32_MAX wrap from JSON int(-1) sentinel
/// Bug 2  (`03fa0aa1`)  — OOO bootstrap blocks re-applied, rolling
///                        nLastPaidHeight backwards (defense-in-depth
///                        Pass-3 idempotency in `8d809ea6`)
/// Bug 3  (`8d809ea6`)  — multiple MNs sharing the same payoutAddress;
///                        find_by_payout_script picked the wrong one
/// Bug 12 (this file)   — apply_block can't see PoSe bans (consensus-
///                        rule, not tx-driven); SML carries the truth
///                        via mnlistdiff. Tests below pin the
///                        sync_validity_from_sml contract.

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <core/uint256.hpp>
#include <util/strencodings.h>

#include <vector>
#include <utility>

using dash::coin::MnStateMachine;
using dash::coin::MNState;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;

namespace {

// Build a uint256 with a 1-byte little-endian "tag" so tests can refer
// to MNs by short name (helps debugging when assertions fail).
uint256 mk_hash(uint8_t tag) {
    uint256 h;
    std::memset(h.data(), 0, 32);
    h.data()[0] = tag;
    return h;
}

// 25-byte canonical P2PKH script with a 20-byte hash160 of all `fill` bytes.
std::vector<unsigned char> mk_p2pkh_script(uint8_t fill) {
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

MNState mk_mn(const std::vector<unsigned char>& script,
              uint32_t lastPaid,
              uint32_t registered = 100,
              uint32_t revived = 0)
{
    MNState s;
    s.scriptPayout.m_data = script;
    s.nLastPaidHeight     = lastPaid;
    s.nRegisteredHeight   = registered;
    s.nPoSeRevivedHeight  = revived;
    s.isValid             = true;
    s.nType               = dash::coin::vendor::MnType::REGULAR;
    return s;
}

} // namespace

// ─── Bug 3: shared payoutAddress, lowest-h disambiguation ──────────────

TEST(DashPayAttribution, Bug3_SharedScript_PicksLowestH)
{
    // Two MNs share the SAME scriptPayout (the live mainnet pattern:
    // operators running multiple MNs to one wallet). MN_A has higher h
    // (paid more recently) → MN_B should be picked.
    auto script = mk_p2pkh_script(0xab);
    auto hash_a = mk_hash(0x01);  // lowest hash (would win pre-fix)
    auto hash_b = mk_hash(0x02);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    entries.emplace_back(hash_a, mk_mn(script, /*lastPaid=*/2000));
    entries.emplace_back(hash_b, mk_mn(script, /*lastPaid=*/1000));
    m.load(std::move(entries));

    auto picked = m.pick_paid_mn(script);
    ASSERT_TRUE(picked.has_value()) << "must find one of the two";
    EXPECT_EQ(*picked, hash_b)
        << "Bug 3 regression: pick_paid_mn returned the higher-h MN. "
           "Pre-fix find_by_payout_script returned hash_a (lowest map key) "
           "which is the bug — should mirror dashd's CompareByLastPaid.";
}

TEST(DashPayAttribution, Bug3_SharedScript_RevivedHeightTakesPrecedence)
{
    // Per dashcore: h = max(lastPaid, revived). MN_A.lastPaid=500 +
    // revived=3000 → h=3000. MN_B.lastPaid=2000 + revived=0 → h=2000.
    // MN_B should win.
    auto script = mk_p2pkh_script(0xcd);
    auto hash_a = mk_hash(0x10);
    auto hash_b = mk_hash(0x20);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    entries.emplace_back(hash_a, mk_mn(script, /*lastPaid=*/500, 100, /*revived=*/3000));
    entries.emplace_back(hash_b, mk_mn(script, /*lastPaid=*/2000));
    m.load(std::move(entries));

    auto picked = m.pick_paid_mn(script);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, hash_b)
        << "revived-height precedence broken — MN_A.h should be 3000, "
           "MN_B.h should be 2000, MN_B should win";
}

TEST(DashPayAttribution, Bug3_SharedScript_NeverPaidUsesRegisteredHeight)
{
    // dashcore: if lastPaid==0 (never paid), h = nRegisteredHeight.
    // MN_A never paid, registered at h=500 → h=500. MN_B paid at
    // h=2000. MN_A should win.
    auto script = mk_p2pkh_script(0xef);
    auto hash_a = mk_hash(0x30);
    auto hash_b = mk_hash(0x40);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    entries.emplace_back(hash_a, mk_mn(script, /*lastPaid=*/0, /*registered=*/500));
    entries.emplace_back(hash_b, mk_mn(script, /*lastPaid=*/2000));
    m.load(std::move(entries));

    auto picked = m.pick_paid_mn(script);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, hash_a)
        << "never-paid MN should use registeredHeight as h, beating "
           "the recently-paid MN";
}

TEST(DashPayAttribution, Bug3_TiebreakOnHashWhenSameH)
{
    // Two MNs with EQUAL h → tiebreak by proRegTxHash ascending
    // (memcmp on raw uint256 bytes, mirroring dashcore's uint256
    // operator< — same Bug-A gotcha as in vendor/simplifiedmns.hpp).
    auto script = mk_p2pkh_script(0x11);
    auto hash_a = mk_hash(0x05);  // memcmp-lower
    auto hash_b = mk_hash(0x06);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    entries.emplace_back(hash_a, mk_mn(script, 1000));
    entries.emplace_back(hash_b, mk_mn(script, 1000));  // identical h
    m.load(std::move(entries));

    auto picked = m.pick_paid_mn(script);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, hash_a) << "tiebreak should pick lowest-byte hash";
}

TEST(DashPayAttribution, Bug3_BannedMNExcluded)
{
    // isValid=false MNs (PoSe-banned) must be excluded from
    // pick_paid_mn — even if they'd otherwise have the lowest h.
    auto script = mk_p2pkh_script(0x22);
    auto hash_banned = mk_hash(0x07);
    auto hash_active = mk_hash(0x08);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    auto mn_banned = mk_mn(script, /*lastPaid=*/100);  // very low h
    mn_banned.isValid = false;
    entries.emplace_back(hash_banned, mn_banned);
    entries.emplace_back(hash_active, mk_mn(script, /*lastPaid=*/5000));
    m.load(std::move(entries));

    auto picked = m.pick_paid_mn(script);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, hash_active)
        << "banned MN must be skipped despite lowest h";
}

// ─── Bug 1: UINT32_MAX sentinel normalization ──────────────────────────

TEST(DashPayAttribution, Bug1_Uint32MaxSentinelDoesntWinProjection)
{
    // Pre-fix: a MN whose snapshot stored UINT32_MAX (from int -1
    // wrap) would cast back to int -1 in find_expected_payee, beating
    // every positive-height MN. Defensive sane_height() in
    // find_expected_payee normalizes UINT32_MAX → 0.
    auto script_a = mk_p2pkh_script(0x33);
    auto script_b = mk_p2pkh_script(0x44);
    auto hash_poisoned = mk_hash(0x09);
    auto hash_normal   = mk_hash(0x0a);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    auto poisoned = mk_mn(script_a,
                          /*lastPaid=*/std::numeric_limits<uint32_t>::max(),
                          /*registered=*/2'000'000);
    entries.emplace_back(hash_poisoned, poisoned);
    entries.emplace_back(hash_normal, mk_mn(script_b, /*lastPaid=*/1500));
    m.load(std::move(entries));

    auto winner = m.find_expected_payee();
    ASSERT_TRUE(winner.has_value());
    EXPECT_EQ(*winner, hash_normal)
        << "Bug 1 regression: UINT32_MAX-sentinel MN won find_expected_payee. "
           "Defensive sane_height() must normalize it before the "
           "static_cast<int> in CompareByLastPaid_GetHeight.";
}

// ─── Bug 2 / 8d809ea6 idempotency safety net ───────────────────────────

TEST(DashPayAttribution, Bug2_Pass3_NeverRollsLastPaidBackwards)
{
    // Construct a MN with lastPaid=2000. Synthesize a block at h=1500
    // whose coinbase pays this MN. apply_block must NOT roll lastPaid
    // back to 1500 — defense-in-depth against any future caller
    // bypassing the OOO guard.
    auto script = mk_p2pkh_script(0x55);
    auto hash = mk_hash(0x0b);

    MnStateMachine m;
    std::vector<std::pair<uint256, MNState>> entries;
    entries.emplace_back(hash, mk_mn(script, /*lastPaid=*/2000));
    m.load(std::move(entries));

    // Synthesize a block paying this script at h=1500 (older than current).
    dash::coin::BlockType block;
    dash::coin::MutableTransaction cb;
    bitcoin_family::coin::TxOut out;
    out.scriptPubKey.m_data = script;
    out.value = 100;
    cb.vout.push_back(out);
    block.m_txs.push_back(cb);

    m.apply_block(block, /*height=*/1500);

    auto it = m.entries().find(hash);
    ASSERT_NE(it, m.entries().end());
    EXPECT_EQ(it->second.nLastPaidHeight, 2000u)
        << "Pass-3 idempotency safety net broken — a re-applied OOO "
           "block bumped lastPaid backwards. The original Bug 2 (03fa0aa1) "
           "would re-introduce the constant-expected projection bug.";
}

// ─── Bug 12: apply_block doesn't see PoSe bans → SML must reconcile ──
//
// Live observed 2026-04-30..05-03: MN 7a9b3753... was PoSe-banned by
// Dash Core at h=2463018 (consensus rule, no special tx). c2pool's
// apply_block walks special txs and never observed the ban — the MN
// stayed isValid=true in MnStateMachine forever, and find_expected_payee
// deterministically picked it 1858 times in a row. The SML feed
// (mnlistdiff p2p, root-verified bit-exact) carries the authoritative
// CSimplifiedMNListEntry::isValid — these tests pin the new
// sync_validity_from_sml() that projects SML truth onto m_entries.

namespace {
// Build a minimal SML with a few entries; only proRegTxHash + isValid
// matter for these tests (the rest of CSimplifiedMNListEntry is wire
// scaffolding).
CSimplifiedMNListEntry mk_sml_entry(uint256 protx, bool valid)
{
    CSimplifiedMNListEntry e;
    e.proRegTxHash = protx;
    e.isValid      = valid;
    // nVersion + zero-init for the rest is fine — we don't serialize.
    return e;
}
} // namespace

TEST(DashPayAttribution, Bug12_SyncFromSml_FlipsBannedToInvalid)
{
    // The exact failure mode: MN was paid + revived previously, then
    // PoSe-banned by dashd between blocks. apply_block didn't see the
    // ban (it's not a tx). MnStateMachine's m_entries[h].isValid is
    // STILL true. find_expected_payee picks this MN forever.
    auto h = mk_hash(0x7a);
    MnStateMachine m;
    m.load({{h, mk_mn(mk_p2pkh_script(0x57), /*lastPaid=*/2461646,
                      /*registered=*/2163364, /*revived=*/2434048)}});
    ASSERT_TRUE(m.entries().at(h).isValid)
        << "Precondition: pre-sync, ban-oblivious m_entries thinks it's valid.";

    // SML carries the authoritative ban (isValid=false).
    CSimplifiedMNList sml;
    sml.mnList.push_back(mk_sml_entry(h, /*valid=*/false));

    auto sr = m.sync_validity_from_sml(sml);

    EXPECT_EQ(sr.scanned, 1u);
    EXPECT_EQ(sr.matched, 1u);
    EXPECT_EQ(sr.flipped_to_invalid, 1u);
    EXPECT_EQ(sr.flipped_to_valid, 0u);
    EXPECT_EQ(sr.sml_only, 0u);
    EXPECT_FALSE(m.entries().at(h).isValid)
        << "sync_validity_from_sml must project SML's ban onto m_entries.";

    // The downstream effect: find_expected_payee must now skip it.
    auto expected = m.find_expected_payee();
    EXPECT_FALSE(expected.has_value())
        << "After SML ban-sync, the only MN is invalid; "
           "find_expected_payee must return nullopt, not the banned MN.";
}

TEST(DashPayAttribution, Bug12_SyncFromSml_FlipsRevivedBackToValid)
{
    // Symmetric: a previously-banned MN that gets revived in dashd
    // (PoSeBanHeight cleared, isValid back to true in SML) must also
    // be reflected. apply_block CAN catch some revivals via ProUpServTx
    // but the SML-driven path is the safety net.
    auto h = mk_hash(0xab);
    MnStateMachine m;
    auto state = mk_mn(mk_p2pkh_script(0xcd), /*lastPaid=*/2461000);
    state.isValid = false;  // currently locally believed banned
    m.load({{h, state}});

    CSimplifiedMNList sml;
    sml.mnList.push_back(mk_sml_entry(h, /*valid=*/true));  // dashd revived it

    auto sr = m.sync_validity_from_sml(sml);

    EXPECT_EQ(sr.flipped_to_valid, 1u);
    EXPECT_EQ(sr.flipped_to_invalid, 0u);
    EXPECT_TRUE(m.entries().at(h).isValid);
}

TEST(DashPayAttribution, Bug12_SyncFromSml_Idempotent)
{
    // Calling repeatedly with the same SML must produce zero deltas
    // after the first call — required so we can call after EVERY
    // mnlistdiff without log spam or wasted work.
    auto h = mk_hash(0x42);
    MnStateMachine m;
    m.load({{h, mk_mn(mk_p2pkh_script(0x99), 1000)}});

    CSimplifiedMNList sml;
    sml.mnList.push_back(mk_sml_entry(h, /*valid=*/false));

    auto first  = m.sync_validity_from_sml(sml);
    auto second = m.sync_validity_from_sml(sml);
    auto third  = m.sync_validity_from_sml(sml);

    EXPECT_EQ(first.flipped_to_invalid, 1u);
    EXPECT_EQ(second.flipped_to_invalid, 0u)
        << "Second call must be a no-op — already in SML state.";
    EXPECT_EQ(third.flipped_to_invalid, 0u);
}

TEST(DashPayAttribution, Bug12_SyncFromSml_SmlOnlyIsNoOp)
{
    // SML may contain MNs that aren't yet in MnStateMachine
    // (registration tx hasn't been processed by apply_block yet, or
    // we just loaded a stale snapshot). These must be counted but
    // NOT inserted — apply_block owns the registration path.
    MnStateMachine m;  // empty
    CSimplifiedMNList sml;
    sml.mnList.push_back(mk_sml_entry(mk_hash(0x01), true));
    sml.mnList.push_back(mk_sml_entry(mk_hash(0x02), false));

    auto sr = m.sync_validity_from_sml(sml);

    EXPECT_EQ(sr.scanned,  2u);
    EXPECT_EQ(sr.matched,  0u);
    EXPECT_EQ(sr.sml_only, 2u);
    EXPECT_EQ(sr.flipped_to_invalid, 0u);
    EXPECT_EQ(sr.flipped_to_valid,   0u);
    EXPECT_EQ(m.size(), 0u)
        << "sync must not insert MNs; that's apply_block's job.";
}

// ─── Bug 13: CProUpServTx nType width regression ──────────────────────
//
// dashcore wire format encodes nType as uint16_t (LE). c2pool's vendor
// struct had it as uint8_t which silently shifted every subsequent field
// by 1 byte for v2+ ProUpServTx payloads. Effect: parse_protx_payload
// failed for EVO-type updates (read past end of payload) AND parsed a
// garbage proTxHash for REGULAR updates. Live-observed via 6+
// "[MNS-SM] CProUpServTx parse failed" warnings 2026-04-26..05-03 on
// the Dash mainnet shadow soak, including h=2462994 — the missed
// PoSe revival of MN 788707b3...80f4 that produced 1858 [PAY] MISMATCH
// events before Bug 12's SML sync masked the symptom.
//
// This test parses the actual on-the-wire extraPayload bytes from
// block 2462994 and verifies the post-fix parser produces the correct
// proTxHash + netInfo + EVO platform fields.

TEST(DashPayAttribution, Bug13_CProUpServTx_v2_EVO_RealPayload_Parses)
{
    // The exact 207-byte extraPayload from Dash mainnet block 2462994's
    // tx[17] (txid 1b942a809dc16da2...). nVersion=2 (BASIC_BLS),
    // nType=1 (EVO), proTxHash=788707b373dab06acf...80f4.
    const std::string ep_hex =
        "02000100"  // nVersion=2 LE, nType=1 LE (uint16_t)
        "f4804ebdec582b7362646ee0fdab70634881ecb0948154cf6ab0da73b3078778"  // proTxHash LE
        "00000000000000000000ffff416d54cc"  // netInfo IPv6 (IPv4-mapped 65.109.84.204)
        "270f"                              // netInfo port BE = 9999
        "00"                                // scriptOperatorPayout varint len=0
        "94333438ff7bee3af289faf952eb1b9807f01a0730f9a09c53a3fbeba86ff7de" // inputsHash
        "6c63e53baaf8e32d90d08171ce28e66924847e1a"  // platformNodeID (uint160)
        "2068"                                       // platformP2PPort BE = 8296
        "bb01"                                       // platformHTTPPort BE = 47873
        // 96-byte BLS sig (no need to verify content, just that it consumes)
        "afd50d34db71cf453c6b6943360045883befbceb80a7b62cfcab6433ebbdd8a5"
        "c9c135d9a8806c628bcbca6fcc63d92f01c9f6fce815a22bd6998e90417f3c15"
        "2b4956e03d91aecbab6708248157c92dddb77b2db381175ef1b817812c9aae0a";

    auto bytes = ParseHex(ep_hex);
    ASSERT_EQ(bytes.size(), 207u) << "test payload size sanity";

    dash::coin::vendor::CProUpServTx ptx;
    ASSERT_TRUE(dash::coin::vendor::parse_protx_payload(bytes, ptx))
        << "Bug 13 regression: CProUpServTx parser fails on v2 EVO real-world "
           "payload because nType was uint8_t instead of uint16_t — every "
           "subsequent field shifted by 1 byte.";

    EXPECT_EQ(ptx.nVersion, 2u);
    EXPECT_EQ(ptx.nType, 1u) << "EVO type must round-trip cleanly through uint16_t";

    // Hex of the proTxHash, BE (display) form.
    EXPECT_EQ(ptx.proTxHash.GetHex(),
              "788707b373dab06acf548194b0ec81486370abfde06e6462732b58ecbd4e80f4")
        << "proTxHash misread (the diagnostic symptom that masked Bug 13 for days)";

    // EVO platform fields (nVersion < EXT_ADDR=3 so they're inline).
    EXPECT_EQ(ptx.platformP2PPort,  8296u);
    EXPECT_EQ(ptx.platformHTTPPort, 47873u);
}

TEST(DashPayAttribution, Bug12_SyncFromSml_OnlyTouchesIsValid)
{
    // Field-ownership contract: SML owns isValid; MnStateMachine owns
    // nLastPaidHeight, nRegisteredHeight, scriptPayout, etc. The sync
    // must NOT write any of MnStateMachine's owned fields even if
    // SML has them.
    auto h = mk_hash(0x55);
    MnStateMachine m;
    auto state = mk_mn(mk_p2pkh_script(0x33),
                       /*lastPaid=*/12345, /*registered=*/1000,
                       /*revived=*/5000);
    m.load({{h, state}});

    CSimplifiedMNList sml;
    sml.mnList.push_back(mk_sml_entry(h, /*valid=*/false));

    m.sync_validity_from_sml(sml);

    const auto& after = m.entries().at(h);
    EXPECT_FALSE(after.isValid);
    EXPECT_EQ(after.nLastPaidHeight,    12345u);
    EXPECT_EQ(after.nRegisteredHeight,  1000u);
    EXPECT_EQ(after.nPoSeRevivedHeight, 5000u);
    EXPECT_EQ(after.scriptPayout.m_data, mk_p2pkh_script(0x33));
}
