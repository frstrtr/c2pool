// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Live-path ChainLock acquisition + verification KATs.
//
// THE REAL VECTOR. Captured read-only from a mainnet dashd (v23.1.7) via
// `dash-cli getbestchainlock` at tip 2515965, plus `dash-cli quorum list` /
// `quorum info 2 <hash>` for the LLMQ_400_60 candidate set and their aggregate
// public keys. Everything below is real mainnet consensus data, not synthetic.
//
//   clsig wire (132 B, from getbestchainlock "hex"):
//     fd632600                          int32LE height   = 2515965
//     8ba8205c...00                     blockHash (LE)
//     b37fa65f...7dd                    recovered threshold sig (96 B)
//
// WHAT EACH TEST LOCKS
//
//   RequestIdMatchesDashcore      -- GenSigRequestId preimage/hash
//                                    (clsig.cpp:29-32). Cross-checked below by
//                                    the fact that dashd's OWN `quorum
//                                    selectquorum 2 <requestId>` returns the
//                                    quorum this request id selects.
//   ScanSetMatchesDashdQuorumList -- the DKG-window snapping + newest-N pool
//                                    reproduces exactly the 4 quorums dashd
//                                    lists for llmq_400_60.
//   SelectsTheQuorumDashdSelected -- SelectQuorumForSigning picks the SAME
//                                    quorum dashd's selectquorum RPC returned.
//   ScoreOrderingIsMemcmpNotBignum-- THE ordering trap: c2pool's
//                                    uint256::operator< (bignum, MSW-first)
//                                    selects a DIFFERENT quorum than dashcore's
//                                    base_blob memcmp (LSB-first). This test
//                                    fails if anyone "simplifies" score_less
//                                    into operator<.
//   SignHashMatchesDashcore       -- BuildSignHash/SignHash preimage.
//   RealChainLockVerifies         -- the real sig verifies (BLS-gated).
//   TamperedSignatureIsRejected   -- ** the load-bearing negative **
//   ForgedSignatureIsRejected     -- attacker-keyed valid G2 point rejected.
//   WrongQuorumKeyIsRejected      -- right sig, wrong quorum key.
//   WrongHeightIsRejected         -- right sig, off-by-one height.
//   FailClosed*                   -- empty/short candidate sets.
//
// The BLS-dependent tests are gated on C2POOL_DASH_BLS; the hash/selection
// tests ALWAYS run, so the hardest-to-get-right pieces (request id, quorum
// selection, sign hash) are locked even in a build without dashbls.

#include <gtest/gtest.h>

#include <impl/dash/coin/chainlock_verify.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

using namespace dash::coin;
using namespace dash::coin::chainlock;

namespace {

std::vector<uint8_t> unhex(const std::string& s)
{
    std::vector<uint8_t> o;
    o.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        o.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return o;
}

template <size_t N>
std::array<uint8_t, N> to_array(const std::string& hex)
{
    auto v = unhex(hex);
    std::array<uint8_t, N> a{};
    EXPECT_EQ(v.size(), N);
    for (size_t i = 0; i < N && i < v.size(); ++i) a[i] = v[i];
    return a;
}

/// uint256 from raw little-endian wire bytes (as they appear on the wire).
uint256 u256_le(const std::string& le_hex) { return uint256(unhex(le_hex)); }

// ── the real mainnet ChainLock (tip 2515965) ────────────────────────────────

constexpr int32_t kClHeight = 2515965;
const char* kClBlockHashLe =
    "8ba8205c0861bc9b6063b67aeff818075a148d1a989502250b00000000000000";
const char* kClSig =
    "b37fa65f662141fde71d5ead7f3548547aa08915274c188c47554e814770a381"
    "6b0c772c10fdb6ca1cc8bf851bcb218301454d5aa6c2fd0d3d25162096f416b9"
    "a629196307efe214b20380c2606c9191550cbefee9ad7e59c05d691929d4a7dd";

// dashd's own answers, for cross-checking:
//   requestId  (from `quorum selectquorum 2 <id>` input)
//   signHash   (derived; locked here so a preimage regression is caught)
const char* kExpectRequestIdLe =
    "79727ab893d36d0fd3a3a5c6d35b1e26587613570870e4fe9854cb1885b5d3a2";
const char* kExpectSignHashLe =
    "f17e368f665809c68a083f55ea08865ad9059de62e1b7ebf2ed2ec4788b177b9";

// The four active LLMQ_400_60 quorums as dashd listed them (newest first),
// each with the height of its base block and its aggregate public key.
// Index 0 is the one dashd's `quorum selectquorum` returned for kClHeight.
struct RawQuorum { const char* hash_le; uint32_t height; const char* pubkey; };
const RawQuorum kQuorums[4] = {
    {"c3477828c2736b7a8c5f860a80b5fca78a2d901ac73779cf2d00000000000000", 2515680,
     "a87321e6161b32915457b292bd32d568765f99e13c9b892fb539ffa66d10c4a2"
     "2eccb7ac3fb510d219cab1dcaa6c1771"},
    {"bc8914c62c17d66b30a32808d60f3d8e942511cfa18555770000000000000000", 2515392,
     "89a90b1a63ef64930b6b758de2ef664c58a7d13eec3db9fe1d65eacfb4fd51f1"
     "8bfdca398b5e5e7b5ec092ccdb8969ea"},
    {"e1cff3e1a2884f4c6bf683716b43d4ab450c720fc0304c2e1f00000000000000", 2515104,
     "990586fe72b887e6237120c8247346acbb0335e13bda9ca228c1cc201c7afe52"
     "8fe14b21533cbdc3d6a9f3f71245c38b"},
    {"2e55076a38ec415a176e5f8917fceb39ce5a1f9a6660bde02c00000000000000", 2514816,
     "84818d01b681fd6ea8f438f834b5296341695e17019c77967a861f7877828e97"
     "ec965eb8cf7d8a87ed9f77997bc683de"},
};

std::vector<QuorumCandidate> all_candidates()
{
    std::vector<QuorumCandidate> v;
    for (const auto& r : kQuorums) {
        QuorumCandidate c;
        c.quorum_hash       = u256_le(r.hash_le);
        c.base_height       = r.height;
        c.quorum_public_key = to_array<48>(r.pubkey);
        v.push_back(c);
    }
    return v;
}

const LlmqParamsView& mainnet_params()
{
    return *chainlock_params(LlmqNetwork::Mainnet);   // LLMQ_400_60
}

} // namespace

// ── hash / selection layer (always runs, no BLS backend needed) ─────────────

TEST(DashChainLockVerify, ChainLockParamsAreLlmq400_60OnMainnet)
{
    const auto& p = mainnet_params();
    // dashcore chainparams.cpp:274 + params.h llmq_400_60 row.
    EXPECT_EQ(p.type, 2u);
    EXPECT_EQ(p.dkg_interval, 288u);
    EXPECT_EQ(p.mining_window_start, 20u);
    EXPECT_EQ(p.mining_window_end, 28u);
    EXPECT_EQ(p.signing_active_quorum_count, 4u);
    EXPECT_FALSE(p.use_rotation);
    // testnet signs ChainLocks with LLMQ_50_60 (chainparams.cpp:467).
    EXPECT_EQ(chainlock_params(LlmqNetwork::Testnet)->type, 1u);
}

TEST(DashChainLockVerify, RequestIdMatchesDashcore)
{
    // dashcore GenSigRequestId: SHA256d(0x05 "clsig" int32LE(height)).
    EXPECT_EQ(gen_sig_request_id(kClHeight), u256_le(kExpectRequestIdLe));
    // Mutation: a different height must give a different request id (this is
    // what binds the signature to the height).
    EXPECT_NE(gen_sig_request_id(kClHeight + 1), u256_le(kExpectRequestIdLe));
}

TEST(DashChainLockVerify, ScanSetMatchesDashdQuorumList)
{
    auto set = scan_quorum_set(mainnet_params(), all_candidates(), kClHeight);
    ASSERT_EQ(set.size(), 4u) << "signingActiveQuorumCount for llmq_400_60";
    // Newest-first, exactly the order+membership dashd's `quorum list` gave.
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(set[i].quorum_hash, u256_le(kQuorums[i].hash_le)) << "index " << i;
        EXPECT_EQ(set[i].base_height, kQuorums[i].height) << "index " << i;
    }
}

// The pool MUST be capped at signingActiveQuorumCount. dashd's `quorum list`
// happened to show exactly 4 active llmq_400_60 quorums, but the
// mnlistdiff-sourced active set we feed the verifier in production also
// retains OLDER quorums (dashcore keeps keepOldConnections=5 and the SML does
// not drop them the instant they leave the signing pool). Without the cap those
// stale quorums get scored and can win the selection — picking a quorum that
// never signed, so every ChainLock would fail to verify.
TEST(DashChainLockVerify, ScanSetIsCappedAtSigningActiveQuorumCount)
{
    auto cands = all_candidates();
    // Four EXPIRED quorums, older than the signing pool (288 apart, as real
    // llmq_400_60 cycles are). Keys are irrelevant — they must never be chosen.
    for (uint32_t i = 1; i <= 4; ++i) {
        QuorumCandidate old = cands.back();
        old.base_height = 2514816 - 288 * i;
        auto raw = unhex(kQuorums[3].hash_le);
        raw[0] = static_cast<uint8_t>(i);        // distinct hashes
        old.quorum_hash = uint256(raw);
        cands.push_back(old);
    }
    ASSERT_EQ(cands.size(), 8u);

    auto set = scan_quorum_set(mainnet_params(), cands, kClHeight);
    ASSERT_EQ(set.size(), 4u) << "pool must be capped at signingActiveQuorumCount";
    for (size_t i = 0; i < 4; ++i)
        EXPECT_EQ(set[i].quorum_hash, u256_le(kQuorums[i].hash_le)) << "index " << i;

    // And the selection is unchanged by the presence of the expired quorums.
    auto q = select_quorum_for_signing(mainnet_params(), set,
                                       gen_sig_request_id(kClHeight));
    ASSERT_TRUE(q.has_value());
    EXPECT_EQ(q->quorum_hash, u256_le(kQuorums[0].hash_le));
}

TEST(DashChainLockVerify, ScanSetExcludesQuorumsNotYetMinedAtScanHeight)
{
    // A quorum whose commitment could not have been mined by (height - 8),
    // snapped to the DKG mining window, must not enter the pool. Give the
    // newest quorum a base height far past the ChainLock and it drops out.
    auto cands = all_candidates();
    cands[0].base_height = static_cast<uint32_t>(kClHeight) + 288;
    auto set = scan_quorum_set(mainnet_params(), cands, kClHeight);
    ASSERT_EQ(set.size(), 3u);
    EXPECT_EQ(set[0].quorum_hash, u256_le(kQuorums[1].hash_le));
}

// SIGN_HEIGHT_OFFSET must be 8 (dashcore quorumsman.h:184). At most heights
// the offset is invisible — h and h-8 snap to the same DKG mining window, so
// the scan set is identical and an offset regression hides. This height is
// chosen to STRADDLE the window end of cycle 2515680 (mining window
// [2515700, 2515708]): with the correct offset 8 the scan starts at 2515701,
// INSIDE the window, so the cycle's own quorum is not yet usable; with a
// wrong offset of 0 the scan starts at 2515709, PAST the window, and the
// 2515680 quorum would wrongly enter the pool.
TEST(DashChainLockVerify, SignHeightOffsetIsEightAndChangesTheScanSet)
{
    constexpr int32_t kStraddle = 2515680 + 29;   // 2515709
    auto set = scan_quorum_set(mainnet_params(), all_candidates(), kStraddle);
    ASSERT_EQ(set.size(), 3u)
        << "with offset 8 the cycle-2515680 quorum is not yet in the pool";
    EXPECT_EQ(set[0].quorum_hash, u256_le(kQuorums[1].hash_le));

    // Control: with offset 0 the same height DOES pull in the newest quorum —
    // proving this height actually discriminates the offset.
    auto set0 = scan_quorum_set(mainnet_params(), all_candidates(), kStraddle,
                                /*sign_offset=*/0);
    ASSERT_EQ(set0.size(), 4u);
    EXPECT_EQ(set0[0].quorum_hash, u256_le(kQuorums[0].hash_le));
}

TEST(DashChainLockVerify, SelectsTheQuorumDashdSelected)
{
    auto set = scan_quorum_set(mainnet_params(), all_candidates(), kClHeight);
    auto q = select_quorum_for_signing(mainnet_params(), set,
                                       gen_sig_request_id(kClHeight));
    ASSERT_TRUE(q.has_value());
    // Ground truth: `dash-cli quorum selectquorum 2 a2d3b585...7279` returned
    // quorumHash 000000000000002dcf7937c71a902d8aa7fcb5800a865f8c7a6b73c2287847c3.
    EXPECT_EQ(q->quorum_hash, u256_le(kQuorums[0].hash_le));
}

// THE ORDERING TRAP. dashcore sorts selection scores with base_blob's memcmp
// (LSB-first); c2pool's uint256::operator< is an MSW-first bignum compare.
// On this real vector the two disagree — memcmp picks candidate 0 (what dashd
// picked), bignum picks candidate 1. If score_less is ever "simplified" into
// operator<, this test goes red and SelectsTheQuorumDashdSelected goes red too.
TEST(DashChainLockVerify, ScoreOrderingIsMemcmpNotBignum)
{
    const auto& p = mainnet_params();
    const uint256 rid = gen_sig_request_id(kClHeight);
    auto set = scan_quorum_set(p, all_candidates(), kClHeight);
    ASSERT_EQ(set.size(), 4u);

    std::vector<uint256> scores;
    for (const auto& c : set)
        scores.push_back(build_selection_score(p.type, c.quorum_hash, rid));

    size_t memcmp_win = 0, bignum_win = 0;
    for (size_t i = 1; i < scores.size(); ++i) {
        if (score_less(scores[i], scores[memcmp_win]))  memcmp_win = i;
        if (scores[i] < scores[bignum_win])             bignum_win = i;  // uint256::operator<
    }
    EXPECT_EQ(memcmp_win, 0u) << "dashcore memcmp ordering must pick candidate 0";
    EXPECT_NE(memcmp_win, bignum_win)
        << "this vector is only a useful guard while the two orderings differ";
}

TEST(DashChainLockVerify, SignHashMatchesDashcore)
{
    auto t = build_sign_target(mainnet_params(), all_candidates(), kClHeight,
                               u256_le(kClBlockHashLe));
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->request_id, u256_le(kExpectRequestIdLe));
    EXPECT_EQ(t->sign_hash,  u256_le(kExpectSignHashLe));
    EXPECT_EQ(t->quorum.quorum_hash, u256_le(kQuorums[0].hash_le));
}

TEST(DashChainLockVerify, FailsClosedWithNoCandidates)
{
    EXPECT_FALSE(build_sign_target(mainnet_params(), {}, kClHeight,
                                   u256_le(kClBlockHashLe)).has_value());
}

TEST(DashChainLockVerify, FailsClosedBelowScanHeight)
{
    // A ChainLock height below the sign offset cannot select a quorum.
    EXPECT_FALSE(build_sign_target(mainnet_params(), all_candidates(), 4,
                                   u256_le(kClBlockHashLe)).has_value());
}

// ── BLS layer (gated on the dashbls backend) ────────────────────────────────

#ifdef C2POOL_DASH_BLS

// dashbls — needed by the wrong-quorum attack test, which must MINT a real
// threshold key and produce a genuinely valid signature to attack with.
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>

namespace {
/// The full live path: select the quorum for this ChainLock, then BLS-verify.
bool verify_real_chainlock(int32_t height, const uint256& block_hash,
                           const std::array<uint8_t, 96>& sig,
                           std::vector<QuorumCandidate> cands)
{
    auto t = build_sign_target(mainnet_params(), std::move(cands), height, block_hash);
    if (!t) return false;
    return vendor::verify_chainlock_sig(t->quorum.quorum_public_key, t->sign_hash, sig);
}
} // namespace

TEST(DashChainLockVerify, RealChainLockVerifies)
{
    EXPECT_TRUE(verify_real_chainlock(kClHeight, u256_le(kClBlockHashLe),
                                      to_array<96>(kClSig), all_candidates()))
        << "a real mainnet ChainLock must verify end-to-end";
}

// ** THE LOAD-BEARING NEGATIVE **
// A verifier that accepts everything would pass "does it verify?" trivially.
// This flips ONE BIT of the real signature. The chosen bit (byte 0, bit 5) was
// picked because the result STILL DESERIALIZES as a valid G2 point — so the
// rejection comes from the pairing check itself, not from the decoder. The
// second case flips a bit that breaks the encoding, covering the decoder path.
TEST(DashChainLockVerify, TamperedSignatureIsRejected)
{
    // (a) parseable tamper — exercises the actual BLS verify
    auto tampered = to_array<96>(kClSig);
    tampered[0] ^= 0x20;                       // byte 0, bit 5
    EXPECT_FALSE(verify_real_chainlock(kClHeight, u256_le(kClBlockHashLe),
                                       tampered, all_candidates()))
        << "a one-bit-tampered ChainLock signature MUST NOT verify";

    // (b) every other single-bit flip in the signature must also fail. This is
    // the strongest form of the claim and cheap enough to assert exhaustively
    // over a sample of positions.
    for (size_t byte_i : {1u, 7u, 31u, 48u, 64u, 95u}) {
        for (int bit = 0; bit < 8; ++bit) {
            auto t = to_array<96>(kClSig);
            t[byte_i] ^= static_cast<uint8_t>(1u << bit);
            EXPECT_FALSE(verify_real_chainlock(kClHeight, u256_le(kClBlockHashLe),
                                               t, all_candidates()))
                << "flip byte " << byte_i << " bit " << bit << " verified!";
        }
    }
}

TEST(DashChainLockVerify, ForgedSignatureIsRejected)
{
    // A structurally PERFECT signature over the correct sign hash, produced by
    // a key the attacker controls. Deserializes cleanly; must still fail,
    // because it is not the selected quorum's threshold key.
    const char* kForged =
        "a1f776cce2360d4ac9d6cb86e79673a2ae75f1c5cd2a6d3f4a459ff17e6c49cd"
        "90f68ae9c2c334dbf74c36bb68c8df730215c0e0bad3ccfe6f5e0d96244e0372"
        "c926d4bbf954fa23a0f1e1d483d605c4a80b8e23685e4e0100b64ebff7e78532";
    EXPECT_FALSE(verify_real_chainlock(kClHeight, u256_le(kClBlockHashLe),
                                       to_array<96>(kForged), all_candidates()))
        << "an attacker-keyed signature MUST NOT verify";
}

// ** THE WRONG-QUORUM ATTACK **
//
// The sharpest form of the safety property, and the one a naive "does the BLS
// math check out" implementation PASSES and a correct one rejects.
//
// The attacker produces a signature that is *internally perfect*: a real BLS
// signature over a correctly-constructed ChainLock sign hash, verifying under
// the very public key that ChainLock names. It is simply the WRONG QUORUM —
// not the one dashcore's SelectQuorumForSigning designates for this height.
//
// An implementation that verified "the signature against whichever quorum the
// message points at" would accept this and commit a hostile ChainLock into our
// coinbase. Ours pins the quorum by the deterministic selection rule FIRST and
// verifies only against that quorum's key, so it rejects.
//
// The control assertion is what makes this test meaningful: the same signature
// DOES verify against the quorum it was made for. So the rejection is
// specifically the selection binding, not a broken signature.
TEST(DashChainLockVerify, InternallyValidSignatureFromWrongQuorumIsRejected)
{
    // Selection for this ChainLock designates candidate 0.
    auto set = scan_quorum_set(mainnet_params(), all_candidates(), kClHeight);
    auto designated = select_quorum_for_signing(mainnet_params(), set,
                                                gen_sig_request_id(kClHeight));
    ASSERT_TRUE(designated.has_value());
    ASSERT_EQ(designated->quorum_hash, u256_le(kQuorums[0].hash_le));

    // The attacker controls a different quorum slot (candidate 1) — they mint
    // their own threshold key and substitute it into the active set.
    std::vector<uint8_t> seed(32, 0x7E);
    auto attacker_sk = bls::BasicSchemeMPL().KeyGen(bls::Bytes(seed.data(), seed.size()));
    auto attacker_pk = attacker_sk.GetG1Element();
    auto attacker_pk_bytes = attacker_pk.Serialize(/*fLegacy=*/false);
    ASSERT_EQ(attacker_pk_bytes.size(), 48u);

    auto cands = all_candidates();
    std::array<uint8_t, 48> apk{};
    for (size_t i = 0; i < 48; ++i) apk[i] = attacker_pk_bytes[i];
    cands[1].quorum_public_key = apk;

    // They sign the sign hash built for THEIR quorum — a fully well-formed
    // ChainLock signature, just from the wrong signer.
    const uint256 rid = gen_sig_request_id(kClHeight);
    const uint256 wrong_sign_hash = build_sign_hash(
        mainnet_params().type, cands[1].quorum_hash, rid, u256_le(kClBlockHashLe));
    auto forged = bls::BasicSchemeMPL().Sign(
        attacker_sk, bls::Bytes(wrong_sign_hash.data(), 32));
    auto forged_bytes = forged.Serialize(/*fLegacy=*/false);
    ASSERT_EQ(forged_bytes.size(), 96u);
    std::array<uint8_t, 96> fsig{};
    for (size_t i = 0; i < 96; ++i) fsig[i] = forged_bytes[i];

    // CONTROL: the signature really is internally valid — it verifies against
    // the quorum it was made for, over that quorum's own sign hash.
    ASSERT_TRUE(vendor::verify_chainlock_sig(apk, wrong_sign_hash, fsig))
        << "the attack vector must itself be a VALID signature, else this "
           "test proves nothing";

    // THE CLAIM: presented as a ChainLock for kClHeight it is REJECTED,
    // because selection designates candidate 0, not the attacker's slot.
    EXPECT_FALSE(verify_real_chainlock(kClHeight, u256_le(kClBlockHashLe),
                                       fsig, cands))
        << "an internally valid signature from a NON-DESIGNATED quorum MUST "
           "NOT be adopted";
}

TEST(DashChainLockVerify, WrongQuorumKeyIsRejected)
{
    // Right signature, right sign hash — but verified against a DIFFERENT real
    // quorum's public key. Fails closed.
    auto t = build_sign_target(mainnet_params(), all_candidates(), kClHeight,
                               u256_le(kClBlockHashLe));
    ASSERT_TRUE(t.has_value());
    EXPECT_FALSE(vendor::verify_chainlock_sig(to_array<48>(kQuorums[1].pubkey),
                                              t->sign_hash, to_array<96>(kClSig)));
    EXPECT_FALSE(vendor::verify_chainlock_sig(to_array<48>(kQuorums[2].pubkey),
                                              t->sign_hash, to_array<96>(kClSig)));
    // Control: the correct key DOES verify the same sign hash.
    EXPECT_TRUE(vendor::verify_chainlock_sig(to_array<48>(kQuorums[0].pubkey),
                                             t->sign_hash, to_array<96>(kClSig)));
}

TEST(DashChainLockVerify, WrongHeightIsRejected)
{
    // The height is bound into the signature twice: through the request id
    // (which selects the quorum) and through the sign hash. Claiming the same
    // signature locks a different height must fail.
    for (int32_t d : {-2, -1, 1, 2, 288}) {
        EXPECT_FALSE(verify_real_chainlock(kClHeight + d, u256_le(kClBlockHashLe),
                                           to_array<96>(kClSig), all_candidates()))
            << "height offset " << d << " verified!";
    }
}

TEST(DashChainLockVerify, WrongBlockHashIsRejected)
{
    // msgHash is the locked block's hash — a ChainLock replayed onto a
    // different block must fail.
    auto bad = unhex(kClBlockHashLe);
    bad[0] ^= 0x01;
    EXPECT_FALSE(verify_real_chainlock(kClHeight, uint256(bad),
                                       to_array<96>(kClSig), all_candidates()))
        << "a ChainLock pointed at a different block MUST NOT verify";
}

TEST(DashChainLockVerify, RejectedWhenSigningQuorumIsMissingFromTheSet)
{
    // We hold the other three quorums but not the one that actually signed.
    // Selection then picks a quorum that did not sign => verify fails closed.
    // (This is the daemonless SML-gap case: a refusal, never a wrong adoption.)
    auto cands = all_candidates();
    cands.erase(cands.begin());
    EXPECT_FALSE(verify_real_chainlock(kClHeight, u256_le(kClBlockHashLe),
                                       to_array<96>(kClSig), cands));
}

#endif // C2POOL_DASH_BLS
