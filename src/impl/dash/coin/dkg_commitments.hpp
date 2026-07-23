// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 — daemonless type-6 (LLMQ quorum-commitment) sourcing at DKG
/// mining-window heights. The follow-through that turns dkg_window.hpp's
/// PHASE-1 "refuse the embedded arm" posture into "serve daemonlessly".
///
/// CONSENSUS MODEL (dashcore llmq/blockprocessor.cpp @ develop cfad414,
/// the same pin as vendor/llmq_commitment.hpp):
///
///   * ProcessBlock requires, PER enabled llmqType, that the number of
///     type-6 special txs in block N EQUALS GetNumCommitmentsRequired
///     (numRequired > inBlock => bad-qc-missing; < => bad-qc-not-allowed).
///   * GetNumCommitmentsRequired(params, N): 0 unless N is inside the
///     type's DKG mining window ([cycleStart+dkgMiningWindowStart,
///     cycleStart+dkgMiningWindowEnd], cycleStart = N - N%dkgInterval).
///     Inside it, one commitment is required for every quorumIndex in
///     [0, rotation ? signingActiveQuorumCount : 1) whose quorum base
///     block hash (block at cycleStart+quorumIndex) exists and whose
///     commitment has NOT already been mined earlier in the window.
///   * A required commitment may be NULL (llmq/commitment.cpp
///     CheckLLMQCommitment / ProcessCommitment: IsNull => VerifyNull,
///     which checks only llmqType validity + all-null fields + bitset
///     sizes == params.size). dashd's OWN miner mines a null commitment
///     whenever it has no verified mineable commitment
///     (GetMineableCommitments: "null commitment required" arm). A null
///     commitment never enters the active quorum set and is SKIPPED by
///     CalcCbTxMerkleRootQuorums ("having null commitments is ok but we
///     don't use them here").
///
/// DAEMONLESS DERIVABILITY (why no dashd and no BLS lib are needed for a
/// consensus-valid block at these heights):
///
///   * "which commitments are mandatory": pure params-table math over the
///     next height + the quorum base block hashes, which the embedded
///     header chain already carries (HeaderChain::get_header_by_height).
///   * "already mined this cycle?": the mnlistdiff-fed QuorumManager IS
///     dashd's GetMinedAndActiveCommitmentsUntilBlock(tip) set
///     (evo/smldiff.cpp BuildQuorumsDiff builds the diff from exactly
///     that call, inclusive of commitments mined AT the diff's tip), and
///     embedded viability already requires the SML/quorum state to be
///     CURRENT AT the tip we build on. A quorum mined earlier in the
///     current window is guaranteed still active (active spans
///     signingActiveQuorumCount cycles >= 4), so
///     has_mined == qmgr.find(type, quorumBaseHash).has_value().
///   * "content": NULL commitments (the same ones dashd's miner builds
///     from thin air) are fully synthesizable locally: version =
///     CFinalCommitment::GetVersion(rotation, basic_bls=true), llmqType,
///     quorumHash = base block hash, quorumIndex, size-sized all-false
///     bitsets, zero key/vvec/sigs.
///   * merkleRootQuorums: unchanged by null commitments — the PROVEN
///     compute_merkle_root_quorums(qmgr) (byte-identical to dashd from
///     the wire, test_dash_mnlistdiff_root_parity) stays the root.
///
/// PHASE-L LINE (real, non-null commitments — the only remaining piece),
/// stated REUSE-FIRST per the operator mandate (vendor Dash Core's own
/// code, do not hand-roll):
///
/// dashd's own template carries the REAL finalized commitment when its
/// DKG succeeded and the qfcommit was relayed. Sourcing that content
/// daemonlessly already works off the coin-P2P `qfcommit` relay
/// (MSG_QUORUM_FINAL_COMMITMENT inv 21 + "qfcommit" message — the same
/// CFinalCommitment wire struct vendored here); MineableCommitmentCache
/// below ingests + structurally validates them (VerifySizes + threshold
/// counts + version + non-null crypto fields — every check dashcore's
/// CFinalCommitment::Verify performs EXCEPT the BLS math). What remains
/// before an unverified relayed commitment may be MINED is dashcore's
/// cryptographic verification, and the plan is to VENDOR it, not
/// re-derive it:
///
///   (1) LIFT (same vendor/ pattern as llmq_commitment.hpp, pin cfad414):
///       * llmq/commitment.cpp — CFinalCommitment::Verify(checkSigs) +
///         BuildCommitmentHash (the signed preimage);
///       * llmq/utils.cpp — GetAllQuorumMembers/ComputeQuorumMembers
///         (deterministic member selection: score = hash(proTxHash,
///         confirmedHash, modifier) over the MN list at the quorum base
///         block — the SML we already sync carries proRegTxHash +
///         confirmedHash + pubKeyOperator, i.e. every input);
///       * llmq/snapshot.{h,cpp} — CQuorumRotationInfo/CQuorumSnapshot
///         (the `qrinfo`/`getqrinfo` light-client protocol) for ROTATED
///         member computation (ComputeQuorumMembersByQuarterRotation) —
///         qrinfo also carries the mnlistdiffs at the cycle base blocks,
///         which is exactly the historical-SML input member selection
///         needs (the seam: feed it from the SAME coin-P2P client that
///         already speaks getmnlistd/mnlistdiff).
///   (2) LINK dash Core's BLS backend rather than any substitute:
///       dashpay/bls-signatures ("bls-dash", the Chia-BLS fork dashd
///       itself links via src/bls/bls.h CBLSPublicKey/CBLSSignature) —
///       relic-backed, CMake, Apache-2.0 (license-compatible with the
///       Apache engine). NO BLS lib is currently vendored or in
///       conanfile.txt (verified) — this is the ONE new third-party
///       dependency Phase L introduces; dashcore's src/bls/bls.h wrapper
///       is then vendored thinly so Verify() runs verbatim: quorumSig =
///       threshold sig by quorumPublicKey and membersSig = aggregate over
///       the signers' pubKeyOperator, both over BuildCommitmentHash(...),
///       basic scheme post-V19.
///   (3) SEAM: MineableCommitmentCache::set_bls_verify_fn — Phase L
///       installs the vendored verifier there; nothing else changes.
///   (4) RESIDUAL after that: none for producing/validating block-N's
///       mandatory commitments — c2pool never PARTICIPATES in DKG (that
///       genuinely requires operator keys and is not a miner concern);
///       it only needs to verify-and-include, which (1)+(2) cover.
///
/// Until then an unverified relayed commitment MUST NOT be mined (a
/// malicious peer could hand us a bad-qc-invalid block), so the provider
/// falls back to the always-consensus-valid NULL commitment for that
/// slot — exactly what dashd mines when IT has no verified commitment.
///
/// MAINTENANCE: the params table + enabled sets + V19 floors below are
/// copied VERBATIM from dashcore llmq/params.h + chainparams.cpp @
/// cfad414. RE-DIFF on every vendored-dashcore pin bump (same rule as
/// dkg_window.hpp) — a params change silently mis-shapes the mandatory
/// set at window heights.

#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// ── LLMQ params (dashcore llmq/params.h @ cfad414, verbatim values) ────────

enum class LlmqNetwork : uint8_t { Mainnet, Testnet };

struct LlmqParamsView {
    uint8_t  type;
    uint16_t size;
    uint16_t min_size;              // dashcore .minSize — the FLOOR Verify enforces
    uint16_t threshold;
    uint32_t dkg_interval;
    uint32_t mining_window_start;   // offset from cycle start
    uint32_t mining_window_end;     // offset from cycle start, inclusive
    uint16_t signing_active_quorum_count;
    bool     use_rotation;
};

// llmq/params.h rows for the production types (LLMQ_25_67 is
// .useRotation=false at this pin — do NOT confuse with the DIP-24 types).
// min_size is dashcore .minSize (the CFinalCommitment::Verify floor: signers/
// validMembers must be >= minSize, NOT merely >= threshold — a
// >=threshold-but-<minSize commitment verifies cryptographically yet is invalid
// to every dashd, so admitting it and serving it loses the block).
inline constexpr LlmqParamsView kLlmq50_60  {1, 50,  40,  30,  24,  10, 18, 24, false};
inline constexpr LlmqParamsView kLlmq60_75  {5, 60,  50,  45,  288, 42, 50, 32, true };
inline constexpr LlmqParamsView kLlmq400_60 {2, 400, 300, 240, 288, 20, 28, 4,  false};
inline constexpr LlmqParamsView kLlmq400_85 {3, 400, 350, 340, 576, 20, 48, 4,  false};
inline constexpr LlmqParamsView kLlmq100_67 {4, 100, 80,  67,  24,  10, 18, 24, false};
inline constexpr LlmqParamsView kLlmq25_67  {6, 25,  22,  17,  24,  10, 18, 24, false};

/// Enabled LLMQ types per network, IN dashd's AddLLMQ ORDER (chainparams.cpp:
/// mainnet 269-273, testnet 459-464). The order matters for byte parity: the
/// miner emits qc txs in GetEnabledQuorumParams enumeration order
/// (node/miner.cpp CreateNewBlock), which is AddLLMQ insertion order.
inline const std::vector<LlmqParamsView>& enabled_llmqs(LlmqNetwork net)
{
    static const std::vector<LlmqParamsView> kMainnet{
        kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67};
    static const std::vector<LlmqParamsView> kTestnet{
        kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67,
        kLlmq25_67};
    return net == LlmqNetwork::Mainnet ? kMainnet : kTestnet;
}

/// Daemonless-qc serve floor = V19Height (chainparams.cpp: mainnet 1899072,
/// testnet 850100). Below it the basic-BLS commitment versions this module
/// hardcodes are wrong AND (far below, pre-DIP0003) a qc tx is
/// bad-qc-premature — both true of the c2pool "--regtest folds into
/// testnet=true" harness chains. Below the floor the provider preserves the
/// PHASE-1 posture exactly: refuse the embedded arm inside any window.
inline constexpr uint32_t kQcServeFloorMainnet = 1'899'072u;
inline constexpr uint32_t kQcServeFloorTestnet = 850'100u;

inline uint32_t qc_serve_floor(LlmqNetwork net)
{
    return net == LlmqNetwork::Mainnet ? kQcServeFloorMainnet
                                       : kQcServeFloorTestnet;
}

/// dashcore llmq/blockprocessor.cpp IsMiningPhase, verbatim semantics.
inline bool is_mining_phase(const LlmqParamsView& p, uint32_t height)
{
    const uint32_t phase = height % p.dkg_interval;
    return phase >= p.mining_window_start && phase <= p.mining_window_end;
}

// ── Mandatory-slot computation ─────────────────────────────────────────────

struct RequiredQcSlot {
    LlmqParamsView params;
    int16_t        quorum_index{0};
    uint256        quorum_hash;      // base block hash at cycleStart+index
};

/// dashcore GetNumCommitmentsRequired, computed daemonlessly.
///
///   hash_at_height : header-chain lookup (height -> block hash);
///                    std::nullopt when the header is not held locally.
///   has_mined      : HasMinedCommitment proxy — true iff (type, quorumHash)
///                    is in the mnlistdiff-fed active set (see header note).
///
/// Returns std::nullopt when the mandatory set CANNOT be derived safely
/// (below the serve floor inside a window, or a needed quorum base header is
/// missing) — the caller must FAIL CLOSED to the dashd fallback. Otherwise
/// the exact ordered slot list (possibly empty: non-window height, or every
/// window commitment already mined).
inline std::optional<std::vector<RequiredQcSlot>> compute_required_qc_slots(
    LlmqNetwork net, uint32_t next_height,
    const std::function<std::optional<uint256>(uint32_t)>& hash_at_height,
    const std::function<bool(uint8_t, const uint256&)>& has_mined)
{
    std::vector<RequiredQcSlot> slots;
    const bool below_floor = next_height < qc_serve_floor(net);
    for (const auto& p : enabled_llmqs(net)) {
        if (!is_mining_phase(p, next_height)) continue;
        if (below_floor) return std::nullopt;   // PHASE-1 refusal preserved
        const uint32_t cycle_start =
            next_height - (next_height % p.dkg_interval);
        const uint32_t n = p.use_rotation ? p.signing_active_quorum_count : 1;
        for (uint32_t qi = 0; qi < n; ++qi) {
            const uint32_t base_h = cycle_start + qi;
            if (base_h >= next_height) return std::nullopt;  // hash unknowable
            auto qh = hash_at_height(base_h);
            if (!qh || qh->IsNull()) return std::nullopt;    // header gap
            if (has_mined(p.type, *qh)) continue;            // already mined
            slots.push_back(RequiredQcSlot{p, static_cast<int16_t>(qi), *qh});
        }
    }
    return slots;
}

// ── Null-commitment + qc-tx construction ───────────────────────────────────

/// dashcore CFinalCommitment(params, quorumHash) + the GetMineableCommitments
/// "null commitment required" arm: size-sized all-false bitsets, zero
/// pubkey/vvec/sigs, nVersion = GetVersion(rotation, basic_bls=true) (the
/// serve floor guarantees post-V19 basic scheme): 3 non-rotated, 4 rotated.
inline vendor::CFinalCommitment build_null_commitment(
    const LlmqParamsView& p, const uint256& quorum_hash, int16_t quorum_index)
{
    vendor::CFinalCommitment c;
    c.nVersion = p.use_rotation
        ? vendor::CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION
        : vendor::CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType    = p.type;
    c.quorumHash  = quorum_hash;
    c.quorumIndex = quorum_index;   // serialized only by the indexed versions
    c.signers.assign(p.size, false);
    c.validMembers.assign(p.size, false);
    // quorumPublicKey / quorumVvecHash / quorumSig / membersSig stay zero.
    return c;
}

/// dashcore GetMineableCommitmentsTx: nVersion=3, nType=6, empty vin/vout,
/// extra_payload = CFinalCommitmentTxPayload{version 1, nHeight, commitment}.
inline MutableTransaction build_qc_tx(uint32_t height,
                                      const vendor::CFinalCommitment& c)
{
    vendor::CFinalCommitmentTxPayload payload;
    payload.nVersion = vendor::CFinalCommitmentTxPayload::CURRENT_VERSION;
    payload.nHeight  = height;
    payload.commitment = c;
    auto stream = ::pack(payload);
    auto sp = stream.get_span();

    MutableTransaction tx;
    tx.version = 3;
    tx.type    = vendor::CFinalCommitmentTxPayload::SPECIALTX_TYPE;  // 6
    tx.locktime = 0;
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

// ── Mineable-commitment cache (Phase-L seam) ───────────────────────────────

/// Collects REAL finalized commitments off the coin-P2P `qfcommit` relay —
/// the exact stream dashd's own miner sources from. Admission is structural
/// (sizes, thresholds, non-null crypto fields, expected version); commitments
/// are only SERVED for mining once a BLS verifier is installed AND passes
/// (Phase L). Without one, verified_for() always returns nullopt and the
/// provider mines the consensus-valid null commitment instead. Mirrors
/// dashd's minableCommitments keep-best-by-CountSigners policy.
class MineableCommitmentCache {
public:
    using BlsVerifyFn = std::function<bool(const vendor::CFinalCommitment&)>;

    void set_bls_verify_fn(BlsVerifyFn fn) { m_bls_verify = std::move(fn); }
    bool has_bls_verifier() const { return static_cast<bool>(m_bls_verify); }

    /// Structural admission of a relayed commitment. Returns true when the
    /// commitment was cached (new, or better than the cached one).
    bool ingest(LlmqNetwork net, const vendor::CFinalCommitment& c)
    {
        const LlmqParamsView* p = nullptr;
        for (const auto& e : enabled_llmqs(net))
            if (e.type == c.llmqType) { p = &e; break; }
        if (p == nullptr) return false;
        // Version must be the post-V19 basic-scheme variant for the type's
        // rotation flag (dashcore CFinalCommitment::Verify version check).
        const uint16_t expected = p->use_rotation
            ? vendor::CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION
            : vendor::CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        if (c.nVersion != expected) return false;
        // VerifySizes.
        if (c.signers.size() != p->size || c.validMembers.size() != p->size)
            return false;
        // A REAL commitment: dashcore CFinalCommitment::Verify enforces the
        // count FLOOR at minSize, NOT threshold (VerifySizes/quorum count check:
        // CountValidMembers() >= minSize and CountSigners() >= minSize). A
        // colluding >=threshold-but-<minSize commitment passes the BLS math yet
        // is bad-qc-invalid to every dashd — admitting it (and, once member
        // sourcing lands, serving it) loses the block. Enforce minSize.
        if (c.CountValidMembers() < p->min_size) return false;
        if (c.CountSigners() < p->min_size) return false;
        auto all_zero = [](const auto& arr) {
            for (auto b : arr) if (b != 0) return false;
            return true;
        };
        if (all_zero(c.quorumPublicKey) || c.quorumVvecHash.IsNull()
            || all_zero(c.quorumSig) || all_zero(c.membersSig))
            return false;

        const Key k{c.llmqType, c.quorumHash};
        auto it = m_cache.find(k);
        if (it != m_cache.end()
            && it->second.CountSigners() >= c.CountSigners())
            return false;   // already hold an equal-or-better one
        m_cache[k] = c;
        return true;
    }

    /// The mineable commitment for a slot — ONLY once BLS-verified. The
    /// Phase-L blocker line: without a verifier this is always nullopt.
    std::optional<vendor::CFinalCommitment>
    verified_for(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        if (!m_bls_verify) return std::nullopt;
        auto it = m_cache.find(Key{llmq_type, quorum_hash});
        if (it == m_cache.end()) return std::nullopt;
        if (!m_bls_verify(it->second)) return std::nullopt;
        return it->second;
    }

    size_t size() const { return m_cache.size(); }
    void   clear() { m_cache.clear(); }

private:
    struct Key {
        uint8_t llmqType;
        uint256 quorumHash;
        bool operator<(const Key& r) const
        {
            if (llmqType != r.llmqType) return llmqType < r.llmqType;
            return std::memcmp(quorumHash.data(), r.quorumHash.data(), 32) < 0;
        }
    };
    std::map<Key, vendor::CFinalCommitment> m_cache;
    BlsVerifyFn m_bls_verify;   // unset until Phase L lands a BLS12-381 lib
};

// ── Daemonless provider (the piece main_dash wires in) ─────────────────────

/// The full mandatory type-6 set for block `next_height`, sourced without
/// dashd: real BLS-verified commitments from `cache` when available (Phase
/// L), the consensus-valid null commitment otherwise. std::nullopt => the
/// set cannot be derived safely; the embedded arm must fail closed.
inline std::optional<std::vector<vendor::CFinalCommitment>>
daemonless_qc_commitments(
    LlmqNetwork net, uint32_t next_height,
    const std::function<std::optional<uint256>(uint32_t)>& hash_at_height,
    const std::function<bool(uint8_t, const uint256&)>& has_mined,
    const MineableCommitmentCache* cache = nullptr)
{
    auto slots = compute_required_qc_slots(net, next_height,
                                           hash_at_height, has_mined);
    if (!slots) return std::nullopt;
    std::vector<vendor::CFinalCommitment> out;
    out.reserve(slots->size());
    for (const auto& s : *slots) {
        if (cache != nullptr) {
            if (auto real = cache->verified_for(s.params.type, s.quorum_hash)) {
                // quorumIndex is OUTSIDE BuildCommitmentHash (confirmed vs
                // dashcore v23.1.x) — neither BLS leg binds it, so a relay peer
                // can flip it on an otherwise-valid qfcommit. dashd enforces
                // base_height % dkgInterval == quorumIndex; the slot's
                // quorum_index IS that value by construction (base = cycleStart
                // + quorum_index). Serving a commitment whose quorumIndex does
                // not match this slot => bad-qc-invalid = lost block, so refuse
                // it and mine the consensus-valid null commitment instead
                // (reward-safe; the honest-copy DoS via keep-best dedup is the
                // flagged availability-only follow-up).
                if (real->quorumIndex == s.quorum_index) {
                    out.push_back(std::move(*real));
                    continue;
                }
            }
        }
        out.push_back(build_null_commitment(s.params, s.quorum_hash,
                                            s.quorum_index));
    }
    return out;
}

// ── merkleRootQuorums with block-local commitments ─────────────────────────

/// dashcore evo/cbtx.cpp CalcCbTxMerkleRootQuorums INCLUDING the candidate
/// block's own type-6 commitments (the piece compute_merkle_root_quorums —
/// proven at non-window heights — does not model):
///   * null commitments are SKIPPED (upstream: "having null commitments is
///     ok but we don't use them here") — so an all-null block reproduces
///     compute_merkle_root_quorums(qmgr) exactly;
///   * rotated types: the new leaf REPLACES the active leaf with the same
///     (llmqType, quorumIndex);
///   * non-rotated types: when the type is at signingActiveQuorumCount
///     capacity, the OLDEST-mined active leaf is evicted first. Mined order
///     within one type is monotone in the quorum base height (a cycle's
///     mining window closes before the next cycle starts), so "oldest
///     mined" == lowest base-block height, resolved via `height_of_hash`
///     (the header chain). std::nullopt when an eviction is needed but a
///     base height cannot be resolved — the caller must fail closed.
inline std::optional<uint256> compute_merkle_root_quorums_with_block(
    LlmqNetwork net,
    const QuorumManager& qmgr,
    const std::vector<vendor::CFinalCommitment>& block_qcs,
    const std::function<std::optional<uint32_t>(const uint256&)>& height_of_hash)
{
    struct Leaf {
        uint256 hash;         // SerializeHash(commitment)
        uint256 quorum_hash;  // for eviction ordering
        int16_t quorum_index; // for rotated replacement
    };
    std::map<uint8_t, std::vector<Leaf>> per_type;
    for (const auto& e : qmgr.active_entries()) {
        per_type[e.key.llmqType].push_back(
            Leaf{hash_commitment(e.commitment), e.key.quorumHash,
                 e.commitment.quorumIndex});
    }

    auto params_of = [&](uint8_t t) -> const LlmqParamsView* {
        for (const auto& p : enabled_llmqs(net))
            if (p.type == t) return &p;
        return nullptr;
    };

    for (const auto& qc : block_qcs) {
        // IsNull per dashcore: no signers/valid members and null crypto.
        if (qc.CountSigners() == 0 && qc.CountValidMembers() == 0)
            continue;   // null commitment — not folded into the root
        const LlmqParamsView* p = params_of(qc.llmqType);
        if (p == nullptr) return std::nullopt;
        auto& leaves = per_type[qc.llmqType];
        const Leaf nl{hash_commitment(qc), qc.quorumHash, qc.quorumIndex};
        if (p->use_rotation) {
            auto it = std::find_if(leaves.begin(), leaves.end(),
                [&](const Leaf& l) { return l.quorum_index == qc.quorumIndex; });
            if (it != leaves.end()) *it = nl; else leaves.push_back(nl);
        } else {
            if (leaves.size() >= p->signing_active_quorum_count) {
                // Evict the oldest-mined == lowest quorum-base-height leaf.
                size_t oldest = 0;
                std::optional<uint32_t> oldest_h;
                for (size_t i = 0; i < leaves.size(); ++i) {
                    auto h = height_of_hash(leaves[i].quorum_hash);
                    if (!h) return std::nullopt;   // cannot order — fail closed
                    if (!oldest_h || *h < *oldest_h) { oldest_h = *h; oldest = i; }
                }
                leaves.erase(leaves.begin() + static_cast<long>(oldest));
            }
            leaves.push_back(nl);
        }
        if (leaves.size() > p->signing_active_quorum_count)
            return std::nullopt;   // excess-quorums — fail closed
    }

    std::vector<uint256> vec_hashes_final;
    for (const auto& [t, leaves] : per_type)
        for (const auto& l : leaves) vec_hashes_final.push_back(l.hash);
    std::sort(vec_hashes_final.begin(), vec_hashes_final.end(),
        [](const uint256& a, const uint256& b) {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        });
    return compute_merkle_root_local(std::move(vec_hashes_final));
}

// ── The per-height plan NodeCoinState consumes ─────────────────────────────

/// Everything the embedded template needs at one height: the ordered
/// mandatory type-6 commitment set (empty off-window / all-mined) plus the
/// merkleRootQuorums INCLUDING those commitments. While the set is all-null
/// (the pre-Phase-L posture) the root equals the PROVEN
/// compute_merkle_root_quorums(qmgr) by construction.
struct QcBlockPlan {
    std::vector<vendor::CFinalCommitment> commitments;
    uint256 merkle_root_quorums;
};

/// Compose the full daemonless plan. std::nullopt => cannot be derived
/// safely at this height; the embedded arm must fail closed to the dashd
/// fallback (exactly the PHASE-1 refusal, but now only when genuinely
/// unable rather than for the whole window).
inline std::optional<QcBlockPlan> build_daemonless_qc_plan(
    LlmqNetwork net, uint32_t next_height,
    const QuorumManager& qmgr,
    const std::function<std::optional<uint256>(uint32_t)>& hash_at_height,
    const std::function<std::optional<uint32_t>(const uint256&)>& height_of_hash,
    const MineableCommitmentCache* cache = nullptr)
{
    auto has_mined = [&qmgr](uint8_t t, const uint256& qh) {
        return qmgr.find(t, qh).has_value();
    };
    auto commitments = daemonless_qc_commitments(
        net, next_height, hash_at_height, has_mined, cache);
    if (!commitments) return std::nullopt;
    auto root = compute_merkle_root_quorums_with_block(
        net, qmgr, *commitments, height_of_hash);
    if (!root) return std::nullopt;
    return QcBlockPlan{std::move(*commitments), *root};
}

} // namespace coin
} // namespace dash

