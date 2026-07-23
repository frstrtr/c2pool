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

#ifdef C2POOL_DASH_BLS
// Synthetic operator keypair for the legacy-scheme-signed-vote KAT (a
// legacy-SIGNED vote cannot be captured from the wire — post-V19 dashd
// rejects and never relays one; that is exactly the parity under test).
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>
#endif

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using dash::coin::vendor::verify_govvote_operator_sig;
using dash::coin::vendor::bls_backend_available;
using dash::coin::VOTE_OUTCOME_NONE;
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

// ═══════════ #818 review must-fix KATs — governance-tally dashcore parity ═══
// All three are the SAME hazard class: c2pool tallying votes dashd does NOT
// (or not counting ones it does) => tally divergence => wrong trigger wins =>
// wrong superblock payees => lost block. Parity target: dashcore v23.1.7
// governance/vote.cpp + governance/object.cpp.

// ── 8. must-fix 1: a LEGACY-SCHEME-SIGNED vote REJECTS ───────────────────────
// dashcore CGovernanceVote::CheckSignature(const CBLSPublicKey&) does
// sig.SetBytes(vchSig, false) + sig.VerifyInsecure(pubKey, hash, false) — the
// SIGNATURE axis is hard-pinned BASIC (SetBytes has no legacy/CheckMalleable
// retry; that exists only in stream Unserialize). Post-V19 dashd therefore
// REJECTS a legacy-scheme-signed governance vote. The pre-fix legacy-sig
// fallback ACCEPTED it — a hostile registered MN could legacy-sign a YES on a
// near-threshold trigger and feed it only to c2pool (dashd would not relay
// it), inflating the local tally. FAILS on the pre-fix code / PASSES after.
#ifdef C2POOL_DASH_BLS
TEST(DashGovVoteBLS, LegacySchemeSignedVoteRejects) {
    if (!bls_backend_available()) GTEST_SKIP();
    std::vector<uint8_t> seed(32, 0x5a);
    bls::PrivateKey sk = bls::BasicSchemeMPL().KeyGen(seed);
    const uint256 digest = real_vote_digest();   // real vote structure/preimage
    const bls::Bytes msg(digest.data(), 32);

    // The hostile MN legacy-SIGNS the (otherwise well-formed) vote digest and
    // may hand us the sig in either wire encoding, claiming either key
    // registration — dashd rejects EVERY combination, and so must we.
    bls::G2Element legacy_sig = bls::LegacySchemeMPL().Sign(sk, msg);
    for (bool sig_enc_legacy : {true, false}) {
        const std::vector<uint8_t> sig_bytes = legacy_sig.Serialize(sig_enc_legacy);
        for (bool key_enc_legacy : {true, false}) {
            const std::array<uint8_t, 48> pk48 =
                sk.GetG1Element().SerializeToArray(key_enc_legacy);
            EXPECT_FALSE(verify_govvote_operator_sig(
                pk48, /*key_legacy_scheme=*/key_enc_legacy, digest, sig_bytes))
                << "legacy-SIGNED vote accepted (sig_enc_legacy="
                << sig_enc_legacy << ", key_enc_legacy=" << key_enc_legacy
                << ") — dashd rejects it; tally-inflation hazard";
        }
    }

    // Positive control: the SAME key BASIC-signs (the post-V19 network
    // scheme) => ACCEPT — under BOTH pubkey wire-encodings and BOTH declared
    // registration flags. This pins that must-fix 1 removed ONLY the
    // signature-axis fallback and KEPT the pubkey-ENCODING fallback (dashcore
    // CBLSLazyPublicKey ingest decodes the operator key per its registration
    // version before CheckSignature ever sees it).
    bls::G2Element basic_sig = bls::BasicSchemeMPL().Sign(sk, msg);
    const std::vector<uint8_t> basic_sig_bytes = basic_sig.Serialize(false);
    for (bool key_enc_legacy : {false, true}) {
        const std::array<uint8_t, 48> pk48 =
            sk.GetG1Element().SerializeToArray(key_enc_legacy);
        for (bool declared_legacy : {false, true}) {
            EXPECT_TRUE(verify_govvote_operator_sig(
                pk48, declared_legacy, digest, basic_sig_bytes))
                << "basic-signed vote must verify (key_enc_legacy="
                << key_enc_legacy << ", declared_legacy=" << declared_legacy
                << ") — pubkey-encoding fallback must be preserved";
        }
    }
}
#endif // C2POOL_DASH_BLS

// ── 9. must-fix 2: banned-MN votes COUNT; threshold denominator is VALID-only ─
// dashcore resolves the voting MN with the UNFILTERED GetMNByCollateral in
// BOTH CGovernanceVote::IsValid and CGovernanceObject::CountMatchingVotes — a
// PoSe-BANNED MN's vote verifies and counts at FULL weight. Only the funding
// THRESHOLD denominator (UpdateSentinelVariables: max(minQuorum,
// m_valid_weighted/10)) is computed over the VALID set. Pre-fix c2pool
// filtered banned MNs out of both closures: natural PoSe-ban churn (no
// attacker needed) then dropped e.g. a banned MN's NO and inflated yes−no vs
// dashd. FAILS on the pre-fix semantics / PASSES after.
TEST(DashGovVoteBLS, BannedMnVoteCountsAtWeightThresholdUsesValidSet) {
    using dash::coin::gov_mn_by_collateral;
    using dash::coin::gov_vote_weight_for_key;

    dash::coin::NodeCoinState ncs;
    dash::coin::CoinStateMaintainer m(ncs);

    // SML: 30 valid + 20 PoSe-banned regular MNs. The DENOMINATOR half of the
    // asymmetry: valid-weighted = 30 => threshold = max(1, 30/10) = 3 — the
    // banned 20 are EXCLUDED here (dashcore m_valid_weighted), even though
    // their votes still count below.
    for (int i = 0; i < 50; ++i) {
        dash::coin::vendor::CSimplifiedMNListEntry e;
        e.isValid = (i < 30);
        e.nType   = dash::coin::vendor::CSimplifiedMNListEntry::TYPE_REGULAR;
        ncs.sml().mnList.push_back(e);
    }
    m.set_gov_params(/*testnet=*/true, /*min_quorum=*/1);   // reseeds threshold
    EXPECT_EQ(m.gov_store().funding_threshold(), 3)
        << "threshold denominator must be the VALID-weighted count only";

    // DMN view: one valid regular MN, one PoSe-BANNED EvoNode.
    dash::coin::MNState valid_mn;
    valid_mn.collateralOutpoint.hash  = h(0x01);
    valid_mn.collateralOutpoint.index = 1;
    valid_mn.isValid = true;
    valid_mn.nType   = dash::coin::vendor::MnType::REGULAR;

    dash::coin::MNState banned_evo;
    banned_evo.collateralOutpoint.hash  = h(0x02);
    banned_evo.collateralOutpoint.index = 2;
    banned_evo.isValid = false;                             // PoSe-banned
    banned_evo.nType   = dash::coin::vendor::MnType::EVO;

    ncs.mnstates().load({{h(0x11), valid_mn}, {h(0x12), banned_evo}});

    const std::string valid_key =
        valid_mn.collateralOutpoint.hash.GetHex() + "-1";
    const std::string banned_key =
        banned_evo.collateralOutpoint.hash.GetHex() + "-2";

    // VERIFY path (CGovernanceVote::IsValid): the banned MN still RESOLVES —
    // its vote reaches the BLS verify (unfiltered GetMNByCollateral).
    EXPECT_NE(gov_mn_by_collateral(ncs.mnstates(),
                                   banned_evo.collateralOutpoint),
              nullptr)
        << "banned MN must resolve on the verify path (dashd verifies its vote)";

    // TALLY path (CountMatchingVotes): banned EvoNode counts at FULL weight 4;
    // an unknown collateral is the ONLY membership drop dashcore performs.
    EXPECT_EQ(gov_vote_weight_for_key(ncs.mnstates(), valid_key), 1);
    EXPECT_EQ(gov_vote_weight_for_key(ncs.mnstates(), banned_key), 4)
        << "banned MN's vote must count at full weight (dashcore unfiltered)";
    EXPECT_EQ(gov_vote_weight_for_key(ncs.mnstates(),
                                      h(0x03).GetHex() + "-0"), 0);

    // End-to-end through the store with the wired weight fn: the banned
    // EvoNode's verified YES (weight 4) alone reaches the valid-only
    // threshold 3; its later NO pulls the tally NEGATIVE — exactly the swing
    // the pre-fix isValid filter would have hidden.
    const int32_t H = 1519824;
    auto oh = h(0xCC);
    auto& store = m.gov_store();
    store.add_trigger(mk_trigger(oh, H));
    store.set_vote_weight_fn([&ncs](const std::string& k) {
        return dash::coin::gov_vote_weight_for_key(ncs.mnstates(), k);
    });
    store.add_verified_funding_vote(oh, banned_key, VOTE_OUTCOME_YES, 100);
    EXPECT_EQ(store.absolute_yes_count(oh), 4);
    EXPECT_TRUE(store.is_superblock_triggered(H));
    store.add_verified_funding_vote(oh, banned_key, VOTE_OUTCOME_NO, 101);
    EXPECT_EQ(store.absolute_yes_count(oh), -4)
        << "a banned MN's NO must count (dropping it inflates yes-no vs dashd)";
    EXPECT_FALSE(store.is_superblock_triggered(H));
}

// ── 10. must-fix 3: NONE replaces a stored YES; exact replacement tie-break ──
// dashcore CGovernanceObject::ProcessVote STORES outcome NONE (IsValid's
// outcome range starts AT VOTE_OUTCOME_NONE) — a newer NONE replaces a stored
// YES and the yes-count drops. Replacement rule, matched exactly: reject when
// new nTime < stored ("Obsolete vote"); on EQUAL nTime reject ONLY when the
// new outcome < the stored outcome (upstream's explicit tie-break); otherwise
// replace. Pre-fix c2pool dropped NONE (stale YES lingered after the voter
// withdrew it) and rejected ALL equal-nTime re-votes. FAILS pre-fix / PASSES
// after.
TEST(DashGovVoteBLS, NoneVoteReplacesYesAndEqualTimeTieBreakMatchesDashcore) {
    dash::coin::GovernanceStore store;
    const int32_t H = 1519824;
    auto oh = h(0xDD);
    store.add_trigger(mk_trigger(oh, H));
    store.set_vote_weight_fn([](const std::string&) { return 1; });
    store.set_funding_threshold(1);

    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_YES, 100);
    EXPECT_EQ(store.absolute_yes_count(oh), 1);
    EXPECT_TRUE(store.is_superblock_triggered(H));

    // Newer NONE REPLACES the stored YES → yes-count drops, trigger unfunds.
    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_NONE, 101);
    EXPECT_EQ(store.absolute_yes_count(oh), 0)
        << "a newer NONE must remove the stored YES from the tally";
    EXPECT_FALSE(store.is_superblock_triggered(H));

    // Obsolete (older nTime) => rejected.
    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_YES, 50);
    EXPECT_EQ(store.absolute_yes_count(oh), 0);

    // Equal-nTime tie-break — reject ONLY new outcome < stored:
    // stored NONE(0)@101, new YES(1)@101: 1 >= 0 => ACCEPTED (replaces).
    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_YES, 101);
    EXPECT_EQ(store.absolute_yes_count(oh), 1);
    // stored YES(1)@101, new NONE(0)@101: 0 < 1 => REJECTED.
    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_NONE, 101);
    EXPECT_EQ(store.absolute_yes_count(oh), 1);
    // stored YES(1)@101, new NO(2)@101: 2 >= 1 => ACCEPTED (yes -> no).
    store.add_verified_funding_vote(oh, "mn-1", VOTE_OUTCOME_NO, 101);
    EXPECT_EQ(store.absolute_yes_count(oh), -1);
}

// ── 11. must-fix 3 (ingest leg): on_govvote must NOT drop outcome NONE ───────
TEST(DashGovVoteBLS, MaintainerIngestsNoneVote) {
    using Ctx = dash::coin::CoinStateMaintainer::GovVoteContext;
    const int32_t H = 1519824;
    auto oh = h(0xEE);

    dash::coin::NodeCoinState ncs;
    dash::coin::CoinStateMaintainer m(ncs);
    m.set_gov_params(true, 1);
    m.gov_store().add_trigger(mk_trigger(oh, H));
    m.gov_store().set_vote_weight_fn([](const std::string&) { return 1; });
    m.gov_store().set_funding_threshold(1);
    m.set_vote_verifier([](const Ctx&) { return true; });

    Ctx yes;
    yes.parent_hash = oh;
    yes.outcome = VOTE_OUTCOME_YES;
    yes.signal  = VOTE_SIGNAL_FUNDING;
    yes.time    = 100;
    m.on_govvote(yes, "mn-1");
    EXPECT_TRUE(m.gov_store().is_superblock_triggered(H));

    // The voter withdraws: a newer NONE vote. Pre-fix on_govvote dropped it
    // at the outcome filter and the stale YES kept the trigger funded here
    // while dashd's tally had already dropped it.
    Ctx none = yes;
    none.outcome = VOTE_OUTCOME_NONE;
    none.time    = 101;
    m.on_govvote(none, "mn-1");
    EXPECT_FALSE(m.gov_store().is_superblock_triggered(H))
        << "on_govvote must ingest NONE — the withdrawn YES must leave the tally";
}

} // namespace
