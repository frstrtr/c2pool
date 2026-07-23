// SPDX-License-Identifier: AGPL-3.0-or-later
/// R3 — governance-vote BLS operator-key signature verification KATs.
///
/// This is the piece that ENABLES daemonless superblock serving: #810's govsync
/// store tallies a funding vote ONLY when the maintainer's vote-verifier accepts
/// its signature. R3 makes that verifier real — dashcore CGovernanceVote::
/// CheckSignature(const CBLSPublicKey&): a TRIGGER funding vote is BLS-signed by
/// the voting masternode's OPERATOR key (NOT the ECDSA voting key — that path is
/// PROPOSAL-funding-only) over govvote_signature_hash().
///
/// ───────────────────────── REAL vs SYNTHETIC ─────────────────────────
/// REAL (from-wire) vector — captured read-only from testnet dashd
/// @192.168.86.52 (P2P 19999 govobjvote + RPC 19998 protx/gobject):
///
///   * Governance object 4fe428f7…140f ("infraclaw-delete-test-20260716",
///     ObjectType 1 = proposal).
///   * A DELETE-signal vote on it (gobject getcurrentvotes vote-hash
///     3760895388…c43f). DELETE (signal 3) votes — like TRIGGER FUNDING votes —
///     are BLS-signed by the MN OPERATOR key, so they exercise the EXACT crypto
///     path R3 adds. Captured govobjvote: 96-byte vchSig (BLS, not the 65-byte
///     ECDSA a proposal-FUNDING vote carries — that contrast is pinned below).
///   * The voting MN (collateral 4ee3ff50…e7a8-95, proTxHash bc77a5a2…b121)
///     operator key from `protx list registered true`: pubKeyOperator
///     174de566…4a8f, registration version 1 (LEGACY_BLS), type Regular,
///     PoSeBanHeight -1 (valid).
///
/// A FUNDED superblock TRIGGER with real trigger-funding votes does NOT exist on
/// testnet (top proposal is under the funding threshold — governance never
/// promoted a trigger), so the end-to-end THRESHOLD → winner → payee selection
/// is exercised SYNTHETICALLY on the real GovernanceStore/maintainer code with a
/// verifier stub, while the SIGNATURE-VERIFY primitive itself (the only new
/// crypto R3 introduces) is pinned against the REAL from-wire operator-key vote
/// above. A tampered sig / wrong key / wrong digest / wrong size all REJECT.

#include <gtest/gtest.h>

#include <impl/dash/coin/utxo_adapter.hpp>          // dash_txid (subsidy template dep)
#include <impl/dash/coin/governance_object.hpp>     // govvote_signature_hash
#include <impl/dash/coin/governance_store.hpp>      // GovernanceStore, weights
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp> // on_govvote / set_vote_verifier
#include <impl/dash/coin/vendor/bls_verify.hpp>     // verify_govvote_operator_sig

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using dash::coin::vendor::verify_govvote_operator_sig;
using dash::coin::vendor::bls_backend_available;
using dash::coin::VOTE_OUTCOME_YES;
using dash::coin::VOTE_OUTCOME_NO;
using dash::coin::VOTE_SIGNAL_FUNDING;

// hex (big-endian, as printed) -> raw bytes, no reversal (opaque BLS wire bytes).
std::vector<uint8_t> hx(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return out;
}
std::array<uint8_t, 48> pubkey48(const std::string& s) {
    auto v = hx(s);
    std::array<uint8_t, 48> a{};
    for (size_t i = 0; i < 48 && i < v.size(); ++i) a[i] = v[i];
    return a;
}

// ── REAL from-wire vector (testnet dashd, DELETE-signal operator-key vote) ────
// Collateral outpoint hash is passed in DISPLAY order to uint256S (SetHex
// reverses to the wire/internal bytes govvote_signature_hash serializes).
const char* kMnCollateralDisplay =
    "4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8";
const uint32_t kMnCollateralIndex = 95;
const char* kParentDisplay =
    "4fe428f7b538ce0b3c08caf187894afcd7c867877495d0b28872c9f9e7e4140f";
const int32_t kOutcome = 1;   // yes
const int32_t kSignal  = 3;   // DELETE (operator-key path, same as trigger-FUNDING)
const int64_t kTime    = 1784232979;
const char* kVchSigHex =
    "8918e91decb5ca31bf75d6120f1cf36c5df3249f0b7b6e4329d4b7229180da4e"
    "c8644af2ceabd2b9666d23bd53294867068a5bd5b7d9433b310f12171d923a4c"
    "5f961aaa7883d5af33c1a16aca56f4f650692f28ad095a0e32605cbb19608d7b";
const char* kPubKeyOperatorHex =
    "174de56654f2bb6417e15ff06361ea0becc00bd72a3eba0f83b60feac8605707"
    "69fbf28482a706f10906a1e96dae4a8f";
const bool kKeyLegacyScheme = true;   // protx state.version == 1 => LEGACY_BLS

uint256 real_vote_digest() {
    return dash::coin::govvote_signature_hash(
        uint256S(kMnCollateralDisplay), kMnCollateralIndex,
        uint256S(kParentDisplay), kOutcome, kSignal, kTime);
}

// ── 1. REAL vote sig VERIFIES against the real operator key ──────────────────
// Simultaneously pins: (a) the govvote_signature_hash preimage (a wrong digest
// would not verify), (b) the BLS operator-key verify, (c) the scheme handling.
TEST(DashGovVoteBLS, RealDeleteVoteVerifiesAgainstOperatorKey) {
    if (!bls_backend_available())
        GTEST_SKIP() << "built without C2POOL_DASH_BLS — verifier is a fail-closed stub";
    EXPECT_TRUE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme,
        real_vote_digest(), hx(kVchSigHex)));
}

// ── 2. TAMPERED sig REJECTS ──────────────────────────────────────────────────
TEST(DashGovVoteBLS, TamperedSignatureRejects) {
    if (!bls_backend_available()) GTEST_SKIP();
    auto sig = hx(kVchSigHex);
    sig[0] ^= 0x01;                                   // flip one bit
    EXPECT_FALSE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme,
        real_vote_digest(), sig));
    auto sig2 = hx(kVchSigHex);
    sig2[sig2.size() - 1] ^= 0x80;                    // flip a trailing bit
    EXPECT_FALSE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme,
        real_vote_digest(), sig2));
}

// ── 3. WRONG operator key REJECTS ────────────────────────────────────────────
TEST(DashGovVoteBLS, WrongOperatorKeyRejects) {
    if (!bls_backend_available()) GTEST_SKIP();
    auto pk = pubkey48(kPubKeyOperatorHex);
    pk[0] ^= 0x01;                                    // a different (still-valid-form) key
    EXPECT_FALSE(verify_govvote_operator_sig(
        pk, kKeyLegacyScheme, real_vote_digest(), hx(kVchSigHex)));
}

// ── 4. WRONG digest (any signed field mutated) REJECTS ───────────────────────
TEST(DashGovVoteBLS, WrongDigestRejects) {
    if (!bls_backend_available()) GTEST_SKIP();
    // time+1 → a different GetSignatureHash → the real sig no longer matches.
    uint256 bad = dash::coin::govvote_signature_hash(
        uint256S(kMnCollateralDisplay), kMnCollateralIndex,
        uint256S(kParentDisplay), kOutcome, kSignal, kTime + 1);
    EXPECT_FALSE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme, bad, hx(kVchSigHex)));
    // outcome flipped (yes→no) → different digest → reject.
    uint256 bad2 = dash::coin::govvote_signature_hash(
        uint256S(kMnCollateralDisplay), kMnCollateralIndex,
        uint256S(kParentDisplay), 2 /*no*/, kSignal, kTime);
    EXPECT_FALSE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme, bad2, hx(kVchSigHex)));
}

// ── 5. WRONG-SIZE sig REJECTS (a 65-byte ECDSA proposal-FUNDING vote) ─────────
// Real from-wire contrast: proposal FUNDING votes carry a 65-byte ECDSA
// voting-key sig, NOT a BLS operator-key sig — the size guard fails them closed,
// which is correct: the superblock tally consults only BLS trigger-funding votes.
TEST(DashGovVoteBLS, EcdsaSizedSigRejects) {
    if (!bls_backend_available()) GTEST_SKIP();
    std::vector<uint8_t> ecdsa_sized(65, 0x20);       // 65 bytes, not 96
    EXPECT_FALSE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme,
        real_vote_digest(), ecdsa_sized));
    EXPECT_FALSE(verify_govvote_operator_sig(
        pubkey48(kPubKeyOperatorHex), kKeyLegacyScheme,
        real_vote_digest(), {}));                     // empty
}

// ── 6. END-TO-END fail-closed chain (synthetic trigger + tally) ──────────────
// No REAL funded trigger exists on testnet, so the winner-selection ladder is
// exercised on the real GovernanceStore code with synthetic triggers/votes. The
// point: a superblock is served ONLY with enough VERIFIED funding votes past the
// weighted threshold. Enabling the verifier must NOT open a serve path for an
// under-verified or under-threshold trigger.
namespace {
uint256 h(uint8_t b) { uint256 x; x.data()[0] = b; return x; }   // distinct object hashes
dash::coin::GovernanceTrigger mk_trigger(const uint256& oh, int32_t height) {
    dash::coin::GovernanceTrigger t;
    t.object_hash = oh;
    t.event_block_height = height;
    // one well-formed payee so the trigger is a valid schedule (amount is not
    // consulted by the tally/selection under test here).
    dash::coin::SuperblockPayment p;
    p.script = {0x76, 0xa9, 0x14};   // opaque; selection doesn't parse it
    p.amount = 1000;
    t.payments.push_back(p);
    return t;
}
} // namespace

TEST(DashGovVoteBLS, TallyServesOnlyWithEnoughVerifiedVotes) {
    dash::coin::GovernanceStore store;
    const int32_t H = 1519824;
    auto oh = h(0xAA);
    store.add_trigger(mk_trigger(oh, H));

    // Weight seam: 3 known regular MNs (weight 1 each), everything else 0.
    store.set_vote_weight_fn([](const std::string& key) -> int {
        if (key == "mn-1" || key == "mn-2" || key == "mn-3") return 1;
        return 0;   // unknown MN / not in valid set → dropped
    });
    store.set_funding_threshold(3);   // need weighted-yes >= 3

    // Two VERIFIED yes votes: 2 < 3 → NOT triggered (fail closed).
    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_YES, 100);
    store.add_verified_funding_vote(oh, "mn-2", VOTE_OUTCOME_YES, 100);
    EXPECT_FALSE(store.is_superblock_triggered(H));
    EXPECT_FALSE(store.get_best_superblock(H).has_value());

    // Third verified yes → 3 >= 3 → triggered, winner is our trigger.
    store.add_verified_funding_vote(oh, "mn-3", VOTE_OUTCOME_YES, 100);
    EXPECT_TRUE(store.is_superblock_triggered(H));
    auto best = store.get_best_superblock(H);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->object_hash, oh);

    // An unknown-MN vote adds 0 weight (membership-at-tally) — cannot push a
    // sub-threshold trigger over on its own.
    dash::coin::GovernanceStore store2;
    store2.add_trigger(mk_trigger(oh, H));
    store2.set_vote_weight_fn([](const std::string& k) -> int {
        return (k == "mn-1") ? 1 : 0; });
    store2.set_funding_threshold(3);
    store2.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_YES, 100);
    store2.add_verified_funding_vote(oh, "ghost-mn", VOTE_OUTCOME_YES, 100);
    EXPECT_FALSE(store2.get_best_superblock(H).has_value());   // 1 weighted < 3

    // Unknown/unset threshold fails closed even with votes past any count.
    dash::coin::GovernanceStore store3;
    store3.add_trigger(mk_trigger(oh, H));
    store3.set_vote_weight_fn([](const std::string&) { return 1; });
    // threshold left 0 (unset) → governance_funding_threshold semantics: closed.
    store3.add_verified_funding_vote(oh, "a", VOTE_OUTCOME_YES, 100);
    store3.add_verified_funding_vote(oh, "b", VOTE_OUTCOME_YES, 100);
    EXPECT_FALSE(store3.get_best_superblock(H).has_value());
}

// ── 7. maintainer on_govvote gate: UNVERIFIED votes are never tallied ────────
// The verifier seam is what makes the tally count anything. With it UNSET
// (default) or REJECTING, a funding vote never reaches the store → fail closed.
// With it ACCEPTING (the R3 wiring, modelled here by a stub that stands in for
// the real BLS verify), verified votes tally and a funded trigger can win.
TEST(DashGovVoteBLS, MaintainerCountsOnlyVerifiedVotes) {
    using Ctx = dash::coin::CoinStateMaintainer::GovVoteContext;
    const int32_t H = 1519824;
    auto oh = h(0xBB);

    auto build_ctx = [&](const std::string& key) {
        Ctx v;
        v.parent_hash = oh;
        v.outcome = VOTE_OUTCOME_YES;
        v.signal  = VOTE_SIGNAL_FUNDING;
        v.time    = 100;
        // vote_hash/vch_sig unused by the stub verifiers below.
        return v;
    };

    // (a) verifier UNSET → default fail closed: nothing tallies.
    {
        dash::coin::NodeCoinState ncs;
        dash::coin::CoinStateMaintainer m(ncs);
        m.set_gov_params(/*testnet=*/true, /*min_quorum=*/1);
        m.gov_store().add_trigger(mk_trigger(oh, H));
        m.gov_store().set_vote_weight_fn([](const std::string&) { return 1; });
        m.gov_store().set_funding_threshold(2);
        m.on_govvote(build_ctx("mn-1"), "mn-1");
        m.on_govvote(build_ctx("mn-2"), "mn-2");
        EXPECT_FALSE(m.gov_store().get_best_superblock(H).has_value());
    }
    // (b) verifier REJECTS every vote → still fail closed.
    {
        dash::coin::NodeCoinState ncs;
        dash::coin::CoinStateMaintainer m(ncs);
        m.set_gov_params(true, 1);
        m.gov_store().add_trigger(mk_trigger(oh, H));
        m.gov_store().set_vote_weight_fn([](const std::string&) { return 1; });
        m.gov_store().set_funding_threshold(2);
        m.set_vote_verifier([](const Ctx&) { return false; });
        m.on_govvote(build_ctx("mn-1"), "mn-1");
        m.on_govvote(build_ctx("mn-2"), "mn-2");
        EXPECT_FALSE(m.gov_store().get_best_superblock(H).has_value());
    }
    // (c) verifier ACCEPTS (stands in for the wired BLS verify) → verified votes
    //     tally and, past threshold, the trigger wins.
    {
        dash::coin::NodeCoinState ncs;
        dash::coin::CoinStateMaintainer m(ncs);
        m.set_gov_params(true, 1);
        m.gov_store().add_trigger(mk_trigger(oh, H));
        m.gov_store().set_vote_weight_fn([](const std::string&) { return 1; });
        m.gov_store().set_funding_threshold(2);
        m.set_vote_verifier([](const Ctx&) { return true; });
        m.on_govvote(build_ctx("mn-1"), "mn-1");
        EXPECT_FALSE(m.gov_store().get_best_superblock(H).has_value());  // 1 < 2
        m.on_govvote(build_ctx("mn-2"), "mn-2");
        auto best = m.gov_store().get_best_superblock(H);
        ASSERT_TRUE(best.has_value());
        EXPECT_EQ(best->object_hash, oh);
    }
}

} // namespace
