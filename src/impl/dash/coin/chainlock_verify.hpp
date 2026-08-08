// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Live-path ChainLock verification — the gate a clsig MUST pass before its
/// height may move `best_cl_height`.
///
/// WHY THIS EXISTS. The daemonless CCbTx path commits bestCLHeightDiff /
/// bestCLSignature. Until this file existed, the only live writer of
/// best_cl_height was the LAGGING derivation from a block's already-committed
/// bestCLHeightDiff (coin_state_maintainer.hpp) — our template freshness was
/// coupled to whatever ChainLock some OTHER miner's node happened to hold. The
/// clsig p2p message carries a fresher ChainLock directly, but adopting one
/// unverified would let a hostile peer feed a bogus (height, blockHash, sig)
/// triple straight into the coinbase we mine — a template we cannot justify,
/// and a lost block. An unverified fetch is WORSE than the lagging derivation,
/// because the lagging value is at least chain-committed. So: acquisition and
/// verification land together, and adoption is gated on verification.
///
/// REUSE-FIRST (operator mandate — mirror Dash Core, do not invent). Every step
/// below is dashcore v23.1.7, cited at the line it came from:
///
///   requestId = SerializeHash(make_pair("clsig"sv, nHeight))
///               -- src/chainlock/clsig.cpp:29-32 (GenSigRequestId), with
///                  CLSIG_REQUESTID_PREFIX at :12. SerializeHash is
///                  CHashWriter(SER_GETHASH, PROTOCOL_VERSION) + GetHash()
///                  (SHA256d) -- src/hash.h:231-236. A string_view serializes
///                  as CompactSize(len) + bytes, so the preimage is exactly
///                  0x05 "clsig" int32LE(nHeight) -- 10 bytes.
///
///   quorum    = SelectQuorumForSigning(params, chain, qman, requestId,
///                                      signHeight = clsig.nHeight, offset = 8)
///               -- src/llmq/quorumsman.cpp:676-737, SIGN_HEIGHT_OFFSET at
///                  src/llmq/quorumsman.h:184. Non-rotated branch (:718-735):
///                  score each of the signingActiveQuorumCount newest quorums
///                  with CHashWriter(SER_NETWORK,0) << llmqType << quorumHash
///                  << selectionHash, sort ASCENDING, take the LOWEST.
///
///   signHash  = SHA256d(u8(llmqType) || quorumHash || requestId || msgHash)
///               -- src/llmq/signhash.cpp:14-22 (SignHash ctor, formerly
///                  BuildSignHash). msgHash is the ChainLock's blockHash
///                  -- src/chainlock/handler.cpp:330-333 (VerifyChainLock).
///
///   verify    = sig.VerifyInsecure(quorum.quorumPublicKey, signHash)
///               -- src/llmq/quorumsman.cpp:749-751. VerifyInsecure is
///                  Scheme(legacy)->Verify(pk, hash_bytes, sig)
///                  -- src/bls/bls.cpp:294-310; post-V19 the scheme is
///                  BasicSchemeMPL (bls_legacy_scheme flipped false at V19
///                  activation, src/evo/specialtxman.cpp). The 32 signHash
///                  bytes are the MESSAGE; the scheme's own hash-to-curve
///                  (DST "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") is
///                  applied to them -- do NOT pre-hash again.
///
///   llmqTypeChainLocks: mainnet LLMQ_400_60 (=2), testnet LLMQ_50_60 (=1)
///               -- src/chainparams.cpp:274 / :467.
///
/// ⚠ ORDERING TRAP (locked by a real-vector KAT). dashcore sorts the selection
/// scores with uint256::operator<, which for its base_blob is
/// memcmp(m_data, ...) -- LEAST-significant byte first (src/uint256.h:55).
/// c2pool's uint256 is base_uint<256>, an ARITHMETIC bignum whose operator<
/// is CompareTo -- MOST-significant word first (core/uint256.cpp:122-131).
/// The two orderings DISAGREE, and on the real mainnet vector in
/// test_dash_chainlock_verify.cpp they select DIFFERENT quorums (dashd picks
/// the memcmp winner; the bignum ordering picks another candidate, which
/// fails to verify). So the score comparison here is an explicit
/// LSB-first memcmp over the raw hash bytes and must NEVER be replaced by
/// uint256::operator<.
///
/// FAIL-CLOSED. Every entry point returns false / nullopt when anything is
/// uncertain: no BLS backend, no candidate quorums, the quorum we selected is
/// not one whose public key we hold, a size mismatch, or the BLS verify fails.
/// A refusal costs us the freshness of one ChainLock (we fall back to the
/// lagging chain-committed derivation, i.e. exactly today's behaviour); an
/// erroneous acceptance costs us a block.

#include <impl/dash/coin/dkg_commitments.hpp>   // LlmqParamsView, kLlmq*, LlmqNetwork
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace dash {
namespace coin {
namespace chainlock {

/// dashcore SIGN_HEIGHT_OFFSET (src/llmq/quorumsman.h:184). Signing and
/// verification both scan from (signHeight - 8) so that a node which is not
/// exactly at the tip still selects the same quorum.
inline constexpr int32_t kSignHeightOffset = 8;

/// One candidate signing quorum: its base block (the DKG cycle-start block
/// whose hash IS the quorumHash), that block's height, and the aggregate
/// quorum public key the recovered threshold signature verifies against
/// (CFinalCommitment::quorumPublicKey, G1/48 bytes).
struct QuorumCandidate {
    uint256                                                           quorum_hash;
    uint32_t                                                          base_height{0};
    std::array<uint8_t, vendor::CFinalCommitment::BLS_PUBKEY_SIZE>    quorum_public_key{};
};

// ── primitive hashes ────────────────────────────────────────────────────────

/// SHA256d over a PackStream's contents. (PackStream::get_span is non-const,
/// so this takes a mutable reference; all callers own a local stream.)
inline uint256 sha256d_of(::PackStream& s)
{
    auto sp = s.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

/// dashcore chainlock::GenSigRequestId (src/chainlock/clsig.cpp:29-32).
/// Preimage: CompactSize(5) || "clsig" || int32LE(nHeight), then SHA256d.
inline uint256 gen_sig_request_id(int32_t n_height)
{
    static constexpr std::string_view kPrefix{"clsig"};
    ::PackStream s;
    WriteCompactSize(s, kPrefix.size());
    s.write(std::as_bytes(std::span{kPrefix.data(), kPrefix.size()}));
    s << n_height;                       // int32, little-endian
    return sha256d_of(s);
}

/// dashcore llmq::SignHash ctor (src/llmq/signhash.cpp:14-22), formerly
/// BuildSignHash: SHA256d(u8(llmqType) || quorumHash || id || msgHash).
inline uint256 build_sign_hash(uint8_t llmq_type, const uint256& quorum_hash,
                               const uint256& id, const uint256& msg_hash)
{
    ::PackStream s;
    s << llmq_type;                      // LLMQType is enum class : uint8_t
    s << quorum_hash;
    s << id;
    s << msg_hash;
    return sha256d_of(s);
}

/// The per-candidate selection score, dashcore quorumsman.cpp:725-732:
/// CHashWriter(SER_NETWORK,0) << llmqType << quorumHash << selectionHash.
/// (SER_NETWORK vs SER_GETHASH is immaterial here — neither uint8_t nor
/// uint256 has a version-dependent encoding — but we mirror the call anyway.)
inline uint256 build_selection_score(uint8_t llmq_type, const uint256& quorum_hash,
                                     const uint256& selection_hash)
{
    ::PackStream s;
    s << llmq_type;
    s << quorum_hash;
    s << selection_hash;
    return sha256d_of(s);
}

/// dashcore's uint256 score ordering: memcmp over the internal byte array,
/// LEAST-significant byte first (src/uint256.h:55). See the ORDERING TRAP note
/// at the top of this file — this must NOT become uint256::operator<, whose
/// c2pool implementation is a most-significant-word-first bignum compare and
/// selects a DIFFERENT quorum.
inline bool score_less(const uint256& a, const uint256& b)
{
    return std::memcmp(a.data(), b.data(), 32) < 0;
}

// ── quorum scan set + selection ─────────────────────────────────────────────

/// Reproduce the SET dashcore's ScanQuorums(llmqType, pindexStart, poolSize)
/// yields for a NON-ROTATED type (src/llmq/quorumsman.cpp:199-243).
///
/// Upstream snaps pindexStart to the enclosing DKG mining window, then walks
/// mined commitments backwards taking the newest `signingActiveQuorumCount`.
/// We hold the quorums' BASE heights (the quorumHash's own block), not their
/// mined-commitment heights; for a non-rotated type the commitment for base B
/// is mined within [B + mining_window_start, B + mining_window_end], so a
/// quorum is eligible iff its LATEST possible mined height (B +
/// mining_window_end) is at or before the snapped store height. That is the
/// conservative direction: it can only ever omit a quorum that upstream would
/// have included (=> selection mismatch => verify fails => we fall back), never
/// admit one upstream would not.
///
/// `all` may be in any order and may contain older quorums than the pool size;
/// the result is the newest-first pool, capped at signingActiveQuorumCount.
inline std::vector<QuorumCandidate>
scan_quorum_set(const LlmqParamsView& p, std::vector<QuorumCandidate> all,
                int32_t sign_height, int32_t sign_offset = kSignHeightOffset)
{
    if (p.dkg_interval == 0 || p.use_rotation) return {};   // rotated => unsupported here

    const int32_t start_height = sign_height - sign_offset;
    if (start_height < 0) return {};

    // Snap to the DKG mining window exactly as ScanQuorums does
    // (quorumsman.cpp:213-226).
    const int32_t interval    = static_cast<int32_t>(p.dkg_interval);
    const int32_t cycle_start = start_height - (start_height % interval);
    const int32_t mining_start = cycle_start + static_cast<int32_t>(p.mining_window_start);
    const int32_t mining_end   = cycle_start + static_cast<int32_t>(p.mining_window_end);

    int32_t store_height;
    if (start_height < mining_start) {
        // Too early for this cycle — use the previous one.
        if (mining_end < interval) return {};   // below genesis; upstream bails
        store_height = mining_end - interval;
    } else if (start_height > mining_end) {
        store_height = mining_end;
    } else {
        store_height = start_height;
    }
    if (store_height < 0) return {};

    std::vector<QuorumCandidate> eligible;
    eligible.reserve(all.size());
    for (auto& c : all) {
        const int64_t latest_mined =
            static_cast<int64_t>(c.base_height) + static_cast<int64_t>(p.mining_window_end);
        if (latest_mined <= static_cast<int64_t>(store_height))
            eligible.push_back(std::move(c));
    }

    // Newest first (upstream reads DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT,
    // i.e. descending mined height), then cap at the signing pool size.
    std::sort(eligible.begin(), eligible.end(),
              [](const QuorumCandidate& a, const QuorumCandidate& b) {
                  if (a.base_height != b.base_height) return a.base_height > b.base_height;
                  return score_less(a.quorum_hash, b.quorum_hash);   // deterministic tie-break
              });
    if (eligible.size() > p.signing_active_quorum_count)
        eligible.resize(p.signing_active_quorum_count);
    return eligible;
}

/// dashcore SelectQuorumForSigning, non-rotated branch
/// (src/llmq/quorumsman.cpp:718-735): score every quorum in the scan set and
/// return the LOWEST. Ties break on the candidate's index in the scan set,
/// matching upstream's std::sort over std::pair<uint256, size_t>.
inline std::optional<QuorumCandidate>
select_quorum_for_signing(const LlmqParamsView& p,
                          const std::vector<QuorumCandidate>& scan_set,
                          const uint256& selection_hash)
{
    if (scan_set.empty()) return std::nullopt;

    size_t  best_i = 0;
    uint256 best_score = build_selection_score(p.type, scan_set[0].quorum_hash, selection_hash);
    for (size_t i = 1; i < scan_set.size(); ++i) {
        const uint256 sc = build_selection_score(p.type, scan_set[i].quorum_hash, selection_hash);
        if (score_less(sc, best_score)) {
            best_score = sc;
            best_i     = i;
        }
    }
    return scan_set[best_i];
}

/// The full pre-BLS half of dashcore's VerifyChainLock: from a ChainLock's
/// height, pick the quorum that must have signed it and build the sign hash
/// its recovered threshold signature has to verify against. Returns nullopt
/// (fail closed) when no quorum can be selected.
struct SignTarget {
    QuorumCandidate quorum;
    uint256         request_id;
    uint256         sign_hash;
};

inline std::optional<SignTarget>
build_sign_target(const LlmqParamsView& p, std::vector<QuorumCandidate> candidates,
                  int32_t cl_height, const uint256& cl_block_hash,
                  int32_t sign_offset = kSignHeightOffset)
{
    const uint256 request_id = gen_sig_request_id(cl_height);
    auto scan_set = scan_quorum_set(p, std::move(candidates), cl_height, sign_offset);
    auto q = select_quorum_for_signing(p, scan_set, request_id);
    if (!q) return std::nullopt;

    SignTarget t;
    t.quorum     = *q;
    t.request_id = request_id;
    // msgHash is the ChainLock's blockHash (handler.cpp:330-333).
    t.sign_hash  = build_sign_hash(p.type, q->quorum_hash, request_id, cl_block_hash);
    return t;
}

/// The LLMQ type used for ChainLock signing on a network
/// (src/chainparams.cpp:274 mainnet, :467 testnet).
inline const LlmqParamsView* chainlock_params(LlmqNetwork net)
{
    // LlmqNetwork has exactly these two enumerators; a devnet/regtest network
    // would need its own row before ChainLock verification could run there.
    return net == LlmqNetwork::Mainnet ? &kLlmq400_60    // LLMQ_400_60
                                       : &kLlmq50_60;    // LLMQ_50_60
}

} // namespace chainlock
} // namespace coin
} // namespace dash
