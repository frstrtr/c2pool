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
/// malicious peer could hand us a bad-qc-invalid block).
///
/// HEIGHT COMPLETENESS (fail-closed, definitive-soak block 1520106): the
/// merkleRootQuorums fold is PER-HEIGHT, so the serve decision must be
/// per-height ALL-OR-NOTHING, never per-slot. A null commitment is
/// consensus-VALID for any slot (CheckLLMQCommitment VerifyNull), but it
/// is only CANONICAL — only reproduces the root the network's dashd
/// miners commit — when that quorum's DKG genuinely failed and dashd's
/// own commitment is ALSO null. Serving null for a slot whose DKG
/// SUCCEEDED (rotated-unsupported, member-set-unsourced, relay gap,
/// verify-fail) skips a leaf every dashd folds in, diverging the whole
/// merkleRootQuorums = bad-cbtx verdict. At 1520106 (first height of the
/// rotated LLMQ_60_75 window) all 32 mandatory rotated slots null-served
/// while dashd mined 29 REAL rotated commitments: the served root was
/// byte-identical to block 1520105's (folded nothing) vs dashd's
/// with-block root. THE RULE: a slot with no BLS-verified real
/// commitment may be served null ONLY on positive evidence that dashd's
/// commitment for that quorum is also null (DkgNullEvidenceFn); absence
/// of a relayed qfcommit is NOT that evidence (absence != vote — the
/// 07-14 ratchet lesson). Otherwise the WHOLE height is underivable:
/// return nullopt so the embedded arm fails closed to the dashd
/// fallback. Until rotated (DIP-24) member sourcing lands, any height
/// whose mandatory set includes a rotated slot therefore falls back
/// unless every rotated slot has attested-null evidence.
///
/// COLD-START HOLE — WHY THERE IS NO BACK-FILL (prior art, settled against
/// dashpay/dash v21.1.0, 2026-08-03; mainnet incident h=2515381 type=1 qi=0):
///
/// A mandatory slot's commitment is NOT in any block yet — `has_mined` is
/// false by construction, so it lives only in every full node's in-memory
/// `minableCommitments` map. Upstream, that map is filled from exactly two
/// places (llmq/blockprocessor.cpp):
///   * `ProcessMessage`/`ProcessCommitment` on a relayed `qfcommit`, and
///   * `UndoBlock` (re-mineable after a reorg),
/// and `AddMineableCommitment` announces it ONCE — `RelayInv(CInv(
/// MSG_QUORUM_FINAL_COMMITMENT, ::SerializeHash(fqc)))` — at DKG finalize
/// (dkgsessionhandler.cpp HandleDKGRound tail). It is served on getdata BY
/// COMMITMENT HASH only (`GetMineableCommitmentByHash`). There is NO
/// request keyed by (llmqType, quorumHash), and the hash is a digest of the
/// full commitment (signers bitset + BLS sigs), so it is not derivable from
/// anything a cold node holds. The light-client messages do not close it
/// either: `mnlistdiff.newQuorums` and `qrinfo.lastCommitmentPerIndex` both
/// carry MINED commitments only — i.e. exactly the ones for which the slot
/// no longer exists.
///
/// So a commitment relayed before this process connected CANNOT be pulled.
/// Dash Core does not solve this; it has the identical hole and resolves it
/// by MINING NULL: `GetMineableCommitments` is documented "Will return a
/// null commitment if no mineable commitment is known and none was mined
/// yet" and takes the `// null commitment required` arm whenever
/// `minableCommitmentsByQuorum` has no entry for the quorum. c2pool
/// deliberately does NOT copy that arm — see HEIGHT COMPLETENESS above: at
/// block 1520106 null-serving a SUCCEEDED DKG diverged merkleRootQuorums.
/// The refusal is therefore correct and stays; what this module owes the
/// operator is a refusal that NAMES which of the several distinct causes
/// fired and BOUNDS the wait (QcSlotGap + qc_window_bound below). The wait
/// ends when any other miner mines the commitment (the slot then reads
/// already-mined off the mnlistdiff-fed QuorumManager) or when the DKG
/// mining window closes — both are bounded by cycleStart +
/// dkgMiningWindowEnd, which is why the incident self-healed in 4 blocks.
///
/// MAINTENANCE: the params table + V19 floors below are copied VERBATIM
/// from dashcore llmq/params.h + chainparams.cpp @ cfad414. The ENABLED
/// SETS are NOT a copy of anything — they are DERIVED (see enabled_llmqs
/// below) by evaluating dashd's runtime IsQuorumTypeEnabled predicate at
/// our serve floor, because that predicate, not the chainparams AddLLMQ
/// list, is what ProcessBlock requires. RE-DERIVE on every
/// vendored-dashcore pin bump (same rule as dkg_window.hpp) — a params
/// OR predicate change silently mis-shapes the mandatory set at window
/// heights, and a type we require that the chain does not mine fails
/// every window height closed forever. LlmqTypeReconciler
/// (llmq_type_reconciler.hpp) is the runtime backstop for exactly that.

#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <atomic>
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

/// Enabled LLMQ types per network, in dashd's enumeration order.
///
/// ⚠ THE ENABLED SET IS *NOT* THE chainparams AddLLMQ LIST. That was the bug
/// this table shipped with (mainnet, fixed 2026-08-03; see LLMQ_50_60 below).
/// dashd's consensus requirement is driven by
/// `GetEnabledQuorumParams(chainman, pindexPrev)` (llmq/options.cpp), which
/// FILTERS the chainparams list through
/// `ChainstateManager::IsQuorumTypeEnabled` (validation.cpp) — a RUNTIME,
/// HEIGHT- AND NETWORK-dependent predicate. `CQuorumBlockProcessor::ProcessBlock`
/// iterates that filtered list, so a chainparams type the predicate rejects is
/// NOT required (and must NOT be emitted: bad-qc-not-allowed). The filter
/// preserves chainparams order, so the byte-parity ordering argument is
/// unchanged: the miner emits qc txs in this enumeration order
/// (node/miner.cpp CreateNewBlock).
///
/// The predicate, verbatim (dashpay/dash v23.1.7 validation.cpp
/// ChainstateManager::IsQuorumTypeEnabled), for the types we carry:
///
///   LLMQ_50_60  : !fDIP0024IsActive || !fHaveDIP0024Quorums
///                 || network == testnet || network == devnet
///   LLMQ_60_75  : fDIP0024IsActive
///   LLMQ_400_60 : true
///   LLMQ_400_85 : true
///   LLMQ_100_67 : DeploymentActiveAfter(DIP0020)
///   LLMQ_25_67  : height >= 847000        (testnet-only type)
///
/// where fDIP0024IsActive = DeploymentActiveAfter(pindexPrev, DIP0024) and
/// fHaveDIP0024Quorums = pindexPrev->nHeight >= consensus.DIP0024QuorumsHeight.
///
/// Evaluated at (and only at) the heights this table is ever consulted — i.e.
/// at or above qc_serve_floor(), which is V19Height on both networks
/// (compute_required_qc_slots refuses below it):
///
///   MAINNET, floor 1899072 (chainparams.cpp: DIP0020Height 1516032,
///   DIP0024Height 1737792, DIP0024QuorumsHeight 1738698, V19Height 1899072).
///     * LLMQ_50_60 is DISABLED: at every height >= 1738698 both DIP0024 legs
///       are true and mainnet is neither testnet nor devnet, so the predicate
///       returns false — PERMANENTLY, 160374 blocks BELOW our serve floor.
///       Requiring it emitted a mandatory type-1 slot that can never be
///       satisfied (has_mined is false forever, no commitment is ever
///       relayed), failing the WHOLE height closed at every height in the
///       interval-24 window [10,18] — a structural 9-in-24 outage.
///       CORROBORATED against a live Dash Core 23.1.7 mainnet node at height
///       2515629: `quorum list` returns exactly the four keys below, in this
///       order, and `quorum info 1 <hash>` returns "quorum not found" where
///       type 4 on the same hash returns a full quorum. (Note `quorum info`
///       says "invalid LLMQ type" only for types absent from CHAINPARAMS —
///       type 1 IS in mainnet chainparams; it is the runtime predicate that
///       disables it. Absence from `quorum list` is the enabled-set evidence,
///       because quorum_list enumerates GetEnabledQuorumTypes.)
///     * The other four are all enabled at/above the floor. => 4 types.
///
///   TESTNET, floor 850100 (DIP0020Height 414100, DIP0024Height 769700,
///   DIP0024QuorumsHeight 770730, V19Height 850100).
///     * LLMQ_50_60 STAYS. The predicate's third disjunct
///       (`NetworkIDString() == TESTNET`) is unconditional and height-
///       independent, so LLMQ_50_60 is enabled on testnet FOREVER — it is
///       also testnet's llmqTypeChainLocks and llmqTypeMnhf. Removing it here
///       would be a NEW defect, symmetric-looking and wrong.
///     * LLMQ_25_67 is enabled from height 847000 < 850100. => 6 types.
///
/// RE-DERIVE THIS on every vendored-dashcore pin bump, from the PREDICATE, not
/// from the AddLLMQ list. `LlmqTypeReconciler` (llmq_type_reconciler.hpp) is
/// the runtime backstop that names a type we require here but that the chain
/// never actually mines — and the reverse.
inline const std::vector<LlmqParamsView>& enabled_llmqs(LlmqNetwork net)
{
    static const std::vector<LlmqParamsView> kMainnet{
        kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67};
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

/// WHY one mandatory slot could not be satisfied. The pre-fix gate collapsed
/// every one of these into "no verified real commitment", which is the same
/// sentence for a cold-start relay hole (wait, bounded), a missing verifier
/// (build defect), an unsourced member set (in flight), a failed signature
/// (hostile/corrupt peer) and an index-flipped copy (relay DoS) — five
/// different operator responses. `Unevaluated` is the honest value for a
/// field/branch never reached, and prints `n/a`, never a fabricated 0.
/// There is deliberately NO `None` value: nothing in this module can produce
/// one. `diagnose()` is defined only AFTER verified_for has already failed
/// (it re-runs no BLS math, so it cannot observe success), and a satisfied
/// slot is reported by the plan existing, not by a gap code. A `None` here
/// would be a value no code path can ever set — the kind of field that
/// silently reads as "fine" when it simply was not measured.
enum class QcSlotGap : uint8_t {
    Unevaluated = 0,       // no gap was recorded on this path
    NoCommitmentCached,    // nothing admitted for (llmqType, quorumHash)
    VerifierAbsent,        // cached, but no BLS verifier is installed
    MemberSetUnsourced,    // cached + verifier, member set not ready yet
    BlsVerifyFailed,       // cached + members ready, signature check FAILED
    QuorumIndexMismatch,   // verified, but quorumIndex != this slot's index
};

inline const char* qc_slot_gap_name(QcSlotGap g)
{
    switch (g) {
        case QcSlotGap::Unevaluated:        return "n/a";
        case QcSlotGap::NoCommitmentCached: return "no-commitment-cached";
        case QcSlotGap::VerifierAbsent:     return "bls-verifier-absent";
        case QcSlotGap::MemberSetUnsourced: return "member-set-unsourced";
        case QcSlotGap::BlsVerifyFailed:    return "bls-verify-failed";
        case QcSlotGap::QuorumIndexMismatch:return "quorum-index-mismatch";
    }
    return "n/a";
}

struct RequiredQcSlot {
    LlmqParamsView params;
    int16_t        quorum_index{0};
    uint256        quorum_hash;      // base block hash at cycleStart+index
    // Observability only — never consulted by the serve decision. Populated
    // ONLY on the fail-closed path (`first_gap`); slots returned in the
    // mandatory-set vector leave them at their unevaluated defaults.
    QcSlotGap      gap{QcSlotGap::Unevaluated};
    int32_t        cached_signers{-1};   // -1 == not evaluated -> prints n/a
};

/// The bound on a refusal: the DKG mining window this slot belongs to. A
/// mandatory slot cannot outlive its window — at cycleStart+miningWindowEnd
/// the slot stops being required (dashcore IsMiningPhase), and in practice it
/// disappears earlier, the moment any miner mines the commitment. So the
/// worst-case outage IS `heights_remaining`, and it is printable.
struct QcWindowBound {
    uint32_t cycle_start{0};
    uint32_t first_height{0};       // cycleStart + dkgMiningWindowStart
    uint32_t last_height{0};        // cycleStart + dkgMiningWindowEnd (incl.)
    uint32_t heights_remaining{0};  // incl. next_height; 0 once past the window
};

inline QcWindowBound qc_window_bound(const LlmqParamsView& p, uint32_t next_height)
{
    QcWindowBound b;
    b.cycle_start  = next_height - (next_height % p.dkg_interval);
    b.first_height = b.cycle_start + p.mining_window_start;
    b.last_height  = b.cycle_start + p.mining_window_end;
    b.heights_remaining = (next_height <= b.last_height)
        ? (b.last_height - next_height + 1u) : 0u;
    return b;
}

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

// ── PoSe interaction of REAL commitments (the #1083 landmine, enforced) ────

/// dashcore's IsNull predicate over a commitment, exactly as the
/// merkleRootQuorums fold applies it (CFinalCommitment::IsNull:
/// CountSigners()==0 && CountValidMembers()==0). Null commitments take the
/// IsNull() exempt path in dashd's verifier (specialtxman.cpp:427-432), so
/// they can never trigger a PoSe punishment.
inline bool qc_commitment_is_null(const vendor::CFinalCommitment& c)
{
    return c.CountSigners() == 0 && c.CountValidMembers() == 0;
}

/// Is the verifier's PoSe pass over this commitment PROVABLY a no-op?
///
/// dashd's verifier PoSe-punishes every quorum member the commitment marks
/// invalid when a NON-NULL commitment is in a block — specialtxman.cpp:159-174
/// HandleQuorumCommitment: for i over members.size(), `if (!qc.validMembers[i])
/// ... mnList.PoSePunish(members[i]->proTxHash, mnList.CalcPenalty(66))` — and
/// a punishment that crosses the ban threshold flips that MN's validity IN THE
/// SAME BLOCK's MN list, changing the merkleRootMNList the same coinbase
/// commits. c2pool does not fold that pass into its committed root (the full
/// fold mirrors the confirmedHash rollover projection and is not built), and
/// penalty-crossing cannot be computed daemonlessly at all: PoSe penalty state
/// is not in the SML, so it must never be guessed.
///
/// The INTERIM serve predicate is therefore the provable no-op: every LISTED
/// member — index < member_count, where member_count is the size of the
/// deterministic member list dashd indexes validMembers with
/// (GetAllQuorumMembers; daemonlessly the QuorumMemberSource set the BLS
/// verify already required) — is marked valid, so the punish loop touches
/// nothing and the committed MN root is exact. validMembers bits at
/// index >= member_count are DKG padding up to params.size (dashcore's own
/// Verify requires them unset) and prove nothing either way.
///
/// Fail-closed: a member_count of 0 or one exceeding the bitset cannot prove
/// the no-op (nothing to index the bitset against), so the answer is false —
/// the caller must refuse, never serve. Null commitments are exempt by the
/// same IsNull predicate the fold and dashd's verifier use.
inline bool qc_pose_pass_provably_noop(const vendor::CFinalCommitment& c,
                                       size_t member_count)
{
    if (qc_commitment_is_null(c)) return true;   // IsNull() exempt path
    if (member_count == 0 || member_count > c.validMembers.size())
        return false;                            // cannot prove — fail closed
    for (size_t i = 0; i < member_count; ++i)
        if (!c.validMembers[i]) return false;    // dashd would PoSePunish members[i]
    return true;
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
    /// OBSERVABILITY ONLY (never gates a serve): is the deterministic member
    /// set for (llmqType, quorumHash) already sourced? Lets a refusal
    /// distinguish "the member-set fetch is still in flight" (wait) from "the
    /// signature genuinely did not verify" (hostile or corrupt peer). Unset =>
    /// the distinction is UNEVALUATED and prints n/a — it is never guessed.
    using MembersReadyFn = std::function<bool(uint8_t, const uint256&)>;

    /// Installing (or swapping) the verifier RETIRES every memoised verdict:
    /// a "verified" latch is only ever a proof UNDER THE VERIFIER THAT
    /// PRODUCED IT, so a verdict must never outlive its prover.
    void set_bls_verify_fn(BlsVerifyFn fn)
    {
        m_bls_verify = std::move(fn);
        for (auto& e : m_cache)
            e.second.verified.store(false, std::memory_order_relaxed);
    }
    bool has_bls_verifier() const { return static_cast<bool>(m_bls_verify); }
    void set_members_ready_fn(MembersReadyFn fn) { m_members_ready = std::move(fn); }
    bool has_members_ready_fn() const { return static_cast<bool>(m_members_ready); }

    /// Member-set readiness for the slot, or std::nullopt when no probe is
    /// installed — the caller MUST print n/a for nullopt, never a guessed bool.
    std::optional<bool> members_ready(uint8_t llmq_type,
                                      const uint256& quorum_hash) const
    {
        if (!m_members_ready) return std::nullopt;
        return m_members_ready(llmq_type, quorum_hash);
    }

    /// Is ANY commitment admitted for this slot key (regardless of verify)?
    bool has_commitment(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        return m_cache.count(Key{llmq_type, quorum_hash}) != 0;
    }

    /// CountSigners of the admitted commitment, or -1 when none is held
    /// (-1 prints n/a; a real 0 is impossible past the minSize admission).
    int32_t cached_signers(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        auto it = m_cache.find(Key{llmq_type, quorum_hash});
        if (it == m_cache.end()) return -1;
        return static_cast<int32_t>(it->second.c.CountSigners());
    }

    /// Classify why `verified_for` withheld this slot. Callers MUST have just
    /// had verified_for fail — this re-runs NO BLS math (the hot path already
    /// paid for it), it only reads the cheap state that discriminates the
    /// causes, so it is safe on the per-template plan path.
    QcSlotGap diagnose(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        if (!has_commitment(llmq_type, quorum_hash))
            return QcSlotGap::NoCommitmentCached;
        if (!m_bls_verify) return QcSlotGap::VerifierAbsent;
        if (m_members_ready && !m_members_ready(llmq_type, quorum_hash))
            return QcSlotGap::MemberSetUnsourced;
        return QcSlotGap::BlsVerifyFailed;
    }

    /// Why a relayed commitment was (not) admitted. A rejected qfcommit used
    /// to vanish without a trace — `ingest` returned bare false and the only
    /// log line was on the ACCEPT path, so an operator staring at a
    /// no-commitment-cached refusal could not tell "never arrived on the
    /// wire" from "arrived and was dropped here", which are opposite
    /// diagnoses. Every rejection now has a name.
    enum class Admission : uint8_t {
        Accepted = 0,
        UnknownType,          // llmqType not enabled on this network
        WrongVersion,         // not the post-V19 basic-scheme variant
        BitsetSizeMismatch,   // signers/validMembers not params.size
        ValidMembersBelowMin, // CountValidMembers < params.minSize
        SignersBelowMin,      // CountSigners < params.minSize
        NullCryptoFields,     // zero pubkey / vvec / quorumSig / membersSig
        NotBetterThanCached,  // keep-best-by-CountSigners, same as dashd
    };

    static const char* admission_name(Admission a)
    {
        switch (a) {
            case Admission::Accepted:             return "accepted";
            case Admission::UnknownType:          return "unknown-llmq-type";
            case Admission::WrongVersion:         return "wrong-version";
            case Admission::BitsetSizeMismatch:   return "bitset-size-mismatch";
            case Admission::ValidMembersBelowMin: return "valid-members-below-minsize";
            case Admission::SignersBelowMin:      return "signers-below-minsize";
            case Admission::NullCryptoFields:     return "null-crypto-fields";
            case Admission::NotBetterThanCached:  return "not-better-than-cached";
        }
        return "n/a";
    }

    /// Structural admission of a relayed commitment. Returns true when the
    /// commitment was cached (new, or better than the cached one).
    bool ingest(LlmqNetwork net, const vendor::CFinalCommitment& c)
    {
        return ingest_ex(net, c) == Admission::Accepted;
    }

    /// Same admission, but SAYING WHY on every rejection.
    Admission ingest_ex(LlmqNetwork net, const vendor::CFinalCommitment& c)
    {
        const LlmqParamsView* p = nullptr;
        for (const auto& e : enabled_llmqs(net))
            if (e.type == c.llmqType) { p = &e; break; }
        if (p == nullptr) return Admission::UnknownType;
        // Version must be the post-V19 basic-scheme variant for the type's
        // rotation flag (dashcore CFinalCommitment::Verify version check).
        const uint16_t expected = p->use_rotation
            ? vendor::CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION
            : vendor::CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        if (c.nVersion != expected) return Admission::WrongVersion;
        // VerifySizes.
        if (c.signers.size() != p->size || c.validMembers.size() != p->size)
            return Admission::BitsetSizeMismatch;
        // A REAL commitment: dashcore CFinalCommitment::Verify enforces the
        // count FLOOR at minSize, NOT threshold (VerifySizes/quorum count check:
        // CountValidMembers() >= minSize and CountSigners() >= minSize). A
        // colluding >=threshold-but-<minSize commitment passes the BLS math yet
        // is bad-qc-invalid to every dashd — admitting it (and, once member
        // sourcing lands, serving it) loses the block. Enforce minSize.
        if (c.CountValidMembers() < p->min_size)
            return Admission::ValidMembersBelowMin;
        if (c.CountSigners() < p->min_size) return Admission::SignersBelowMin;
        auto all_zero = [](const auto& arr) {
            for (auto b : arr) if (b != 0) return false;
            return true;
        };
        if (all_zero(c.quorumPublicKey) || c.quorumVvecHash.IsNull()
            || all_zero(c.quorumSig) || all_zero(c.membersSig))
            return Admission::NullCryptoFields;

        const Key k{c.llmqType, c.quorumHash};
        auto it = m_cache.find(k);
        if (it != m_cache.end()
            && it->second.c.CountSigners() >= c.CountSigners())
            return Admission::NotBetterThanCached;   // hold an equal-or-better one
        // Replacement builds a FRESH entry, so the incoming commitment is
        // UNLATCHED by construction — a verdict proven for the superseded
        // bytes can never be served for these ones. ERASE-then-default-
        // construct rather than assign: Entry holds a std::atomic latch and is
        // therefore neither copyable nor movable, and that is deliberate — the
        // only way to obtain an entry is to build a fresh, unlatched one.
        m_cache.erase(k);
        m_cache[k].c = c;
        return Admission::Accepted;
    }

    /// The mineable commitment for a slot — ONLY once BLS-verified. The
    /// Phase-L blocker line: without a verifier this is always nullopt.
    ///
    /// THE AGGREGATE VERIFY IS PAID ONCE PER COMMITMENT, NOT ONCE PER READ.
    /// This is a SERVE-PATH hot function: the pre-emit consensus gate re-runs
    /// INLINE on the io thread for every read of a cached EMBEDDED template
    /// (work_source.cpp:852-853), the gate re-derives the mandatory qc plan on
    /// every call (node_coin_state.hpp:889-893), the plan walks
    /// daemonless_qc_commitments (:741 below) into here, and notify_all fans
    /// send_notify_work out SERIALLY per session (stratum_server.cpp:379-384).
    /// Re-proving a 391-signer LLMQ_400_60 aggregate signature on each of
    /// those was the 2026-08-07 tip freeze: one send_notify_work measured
    /// 0.3 ms -> 733 ms, the io thread saturated in userspace, and the tip
    /// stopped advancing — which is self-sustaining, because the expensive
    /// slot only retires when the tip advances (:415/:425 below).
    ///
    /// The memo is a POSITIVE-ONLY latch carried ON the cache entry, so its
    /// staleness argument is by construction, not by discipline:
    ///   * the verifier's inputs are the commitment BYTES and the member set
    ///     for (llmqType, quorumHash) (bls_verify.hpp);
    ///   * the bytes cannot change under a live latch: entry replacement is
    ///     the ONLY mutation (keep-best, ingest_ex above) and it builds a
    ///     FRESH, unlatched entry;
    ///   * quorumHash IS the quorum base block hash (:421-426 below), so a
    ///     reorg gives a DIFFERENT key — never a same-key different member
    ///     set;
    ///   * FALSE is never latched, so every recovery path (member set
    ///     arrives, better commitment lands, verifier installed) is unchanged,
    ///     as is diagnose()'s classification;
    ///   * set_bls_verify_fn retires every latch, so a verdict is never served
    ///     under a verifier that did not produce it.
    /// A latched TRUE is therefore a retained mathematical proof about
    /// immutable bytes against a chain-determined member set: it cannot become
    /// false, and nothing the pre-emit gate CHECKS is checked less often —
    /// only this leaf predicate's pairing math is reused.
    ///
    /// THREADING: the latch is `mutable std::atomic<bool>` read/written
    /// RELAXED under the cache's existing no-lock discipline. The only
    /// production caller is the single coin-state-owning thread
    /// (work_source.cpp:823-827), so the atomic is not load-bearing TODAY —
    /// it is there so that the safety of this line stops depending on that
    /// staying true. Relaxed is the right (and sufficient) order: the latch
    /// publishes nothing — the bytes it guards are immutable for the entry's
    /// lifetime — so the only race a second reader can lose is a redundant
    /// re-verify of the same commitment to the same verdict.
    ///
    /// BEHAVIOUR CHANGE, ON RECORD (the one thing this is not free): a latched
    /// slot no longer calls the BLS verifier, and the verifier is what sources
    /// the member key set (bls_verify.hpp make_commitment_bls_verifier). If
    /// the member set is EVICTED after a successful verify, the refusal MOVES
    /// DOWNSTREAM: it used to surface here as nullopt -> underivable plan ->
    /// cause=qc-plan-underivable (node_coin_state.hpp:892), and now surfaces
    /// at the PoSe-noop gate, which sources the SAME member set
    /// (main_dash.cpp:4160-4169) -> cause=emit-qc-real-pose-unfolded
    /// (node_coin_state.hpp:930). SAME OUTCOME — fail closed, no template
    /// served, no bytes changed — but a DIFFERENT decline cause string, which
    /// this project ranks serve-gate episodes by (ServeGateJournal,
    /// work_source.cpp:749-789). Pinned by
    /// DashQcVerifyMemoDeclineCause.EvictedMemberSetDeclinesAsPoseUnfolded
    /// (test_dash_node_coin_state.cpp).
    std::optional<vendor::CFinalCommitment>
    verified_for(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        if (!m_bls_verify) return std::nullopt;
        auto it = m_cache.find(Key{llmq_type, quorum_hash});
        if (it == m_cache.end()) return std::nullopt;
        if (!it->second.verified.load(std::memory_order_relaxed)) {
            if (!m_bls_verify(it->second.c)) return std::nullopt;
            // Latched ONLY on success. RELAXED is sufficient and is the WHOLE
            // safety argument: the latch publishes no data — the commitment
            // bytes it guards are immutable for the entry's whole lifetime
            // (replacement builds a fresh entry), so there is nothing for an
            // acquire/release pair to order. A relaxed atomic gives the one
            // property a plain `bool` did not: reads and writes cannot tear or
            // race (no UB), so the worst case of a concurrent reader is a
            // REDUNDANT re-verify of the same bytes to the same verdict.
            it->second.verified.store(true, std::memory_order_relaxed);
        }
        return it->second.c;
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
    /// The admitted commitment plus its memoised BLS verdict. `verified` is
    /// the POSITIVE-ONLY latch verified_for() sets (see there for why it can
    /// never go stale); it is `mutable` so the const serve-path read can
    /// record the proof it just paid for, and it dies with the entry — a
    /// replacement commitment is unlatched by construction.
    ///
    /// The latch is std::atomic<bool>, accessed RELAXED, not a plain bool. The
    /// production caller is the single coin-state-owning thread
    /// (work_source.cpp:823-827), so a plain bool would be provably safe BY
    /// READING THE CODE — which is exactly the argument that preceded the
    /// 2026-08-05 heap corruption on this same money path
    /// (oracle_shadow_worker racing lockless coin state). A relaxed atomic
    /// costs nothing on x86-64 (a plain mov either way) and converts "no
    /// second thread reaches this today" from an invariant someone must keep
    /// into one the type enforces: a future off-io reader gets a redundant
    /// re-verify, never a data race.
    ///
    /// Consequence, and it is deliberate: Entry is neither copyable nor
    /// movable, so an entry can only ever be DEFAULT-CONSTRUCTED (unlatched)
    /// and then filled — a latched verdict cannot be copied onto other bytes.
    struct Entry {
        vendor::CFinalCommitment c;
        mutable std::atomic<bool> verified{false};
    };
    std::map<Key, Entry> m_cache;
    BlsVerifyFn m_bls_verify;   // unset until Phase L lands a BLS12-381 lib
    MembersReadyFn m_members_ready;   // observability only; unset => n/a
};

// ── Daemonless provider (the piece main_dash wires in) ─────────────────────

/// Positive attestation that the DKG for (llmq_type, quorum_hash) genuinely
/// FAILED — i.e. dashd's own miner mines the NULL commitment for that slot,
/// so serving null is canonical (reproduces the network root). This must be
/// EVIDENCE of the failure, never inference from the absence of a relayed
/// qfcommit (a relay gap looks identical and null-serving through it is the
/// exact 1520106 divergence). No production source is wired yet: until one
/// exists (e.g. DKG-phase observation), an unsatisfiable slot fails the
/// whole height closed. Tests/harness inject attested vectors.
using DkgNullEvidenceFn =
    std::function<bool(uint8_t llmq_type, const uint256& quorum_hash)>;

/// The full mandatory type-6 set for block `next_height`, sourced without
/// dashd — per-height ALL-OR-NOTHING (see HEIGHT COMPLETENESS above). Every
/// slot must carry either a BLS-verified REAL commitment from `cache` or an
/// attested-null (null_evidence): std::nullopt => at least one mandatory
/// slot is unsatisfiable (or the slot set itself cannot be derived) and the
/// embedded arm must fail closed for the WHOLE height. `first_gap`, when
/// non-null, receives the first unsatisfiable slot INCLUDING its classified
/// `gap` reason and the measured `cached_signers` (observability only — it
/// is left untouched when the slot set itself was underivable, so a null
/// `quorum_hash` still discriminates that case).
inline std::optional<std::vector<vendor::CFinalCommitment>>
daemonless_qc_commitments(
    LlmqNetwork net, uint32_t next_height,
    const std::function<std::optional<uint256>(uint32_t)>& hash_at_height,
    const std::function<bool(uint8_t, const uint256&)>& has_mined,
    const MineableCommitmentCache* cache = nullptr,
    const DkgNullEvidenceFn& null_evidence = nullptr,
    RequiredQcSlot* first_gap = nullptr)
{
    auto slots = compute_required_qc_slots(net, next_height,
                                           hash_at_height, has_mined);
    if (!slots) return std::nullopt;
    std::vector<vendor::CFinalCommitment> out;
    out.reserve(slots->size());
    for (const auto& s : *slots) {
        // Recorded ONLY if this slot ends up being the fail-closed gap; it
        // never influences the serve decision.
        QcSlotGap gap_reason = cache != nullptr ? QcSlotGap::Unevaluated
                                                : QcSlotGap::NoCommitmentCached;
        if (cache != nullptr) {
            if (auto real = cache->verified_for(s.params.type, s.quorum_hash)) {
                // quorumIndex is OUTSIDE BuildCommitmentHash (confirmed vs
                // dashcore v23.1.x) — neither BLS leg binds it, so a relay peer
                // can flip it on an otherwise-valid qfcommit. dashd enforces
                // base_height % dkgInterval == quorumIndex; the slot's
                // quorum_index IS that value by construction (base = cycleStart
                // + quorum_index). Serving a commitment whose quorumIndex does
                // not match this slot => bad-qc-invalid = lost block, so treat
                // the slot as unsatisfiable (the honest-copy DoS via keep-best
                // dedup is the flagged availability-only follow-up).
                if (real->quorumIndex == s.quorum_index) {
                    out.push_back(std::move(*real));
                    continue;
                }
                gap_reason = QcSlotGap::QuorumIndexMismatch;
            } else {
                gap_reason = cache->diagnose(s.params.type, s.quorum_hash);
            }
        }
        // No verified real commitment for this mandatory slot. Null is
        // canonical ONLY on positive failed-DKG evidence; otherwise the
        // whole height is unservable (completeness gate — the 1520106 fix).
        if (null_evidence && null_evidence(s.params.type, s.quorum_hash)) {
            out.push_back(build_null_commitment(s.params, s.quorum_hash,
                                                s.quorum_index));
            continue;
        }
        if (first_gap != nullptr) {
            *first_gap = s;
            first_gap->gap = gap_reason;
            first_gap->cached_signers = cache != nullptr
                ? cache->cached_signers(s.params.type, s.quorum_hash) : -1;
        }
        return std::nullopt;
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
/// merkleRootQuorums INCLUDING those commitments. Every commitment in the
/// set is either BLS-verified real or attested-null (the completeness gate
/// in daemonless_qc_commitments) — a partially-sourced height never
/// produces a plan.
struct QcBlockPlan {
    std::vector<vendor::CFinalCommitment> commitments;
    uint256 merkle_root_quorums;
};

/// Compose the full daemonless plan. std::nullopt => cannot be derived
/// safely at this height — slot set underivable, root fold underivable, or
/// ANY mandatory slot lacking a verified real / attested-null commitment
/// (per-height all-or-nothing) — and the embedded arm must fail closed to
/// the dashd fallback (exactly the PHASE-1 refusal, but now only when
/// genuinely unable rather than for the whole window).
/// `also_has_mined` is the PR-2 forward seam (mined_commitment_index.hpp): a
/// SECOND source for "this quorum's commitment is already on the chain",
/// derived from our own block replay instead of from an mnlistdiff/qrinfo
/// round trip. It is OR'd into the QuorumManager answer, so it can only ever
/// make FEWER slots mandatory — never more, and never a different commitment.
///
/// ⚠ MONEY PATH. A slot dropped from the mandatory set is a type-6 tx the
/// served template no longer carries. That is byte-visible, so the source must
/// be a mined record that a reorg cannot invalidate — which is exactly why
/// MinedCommitmentIndex refuses to arm on a live-tip node until dashd's
/// UndoBlock half (v23.1.7 llmq/blockprocessor.cpp:383-408) is ported.
/// Defaulted null: every pre-existing caller keeps byte-identical behaviour.
inline std::optional<QcBlockPlan> build_daemonless_qc_plan(
    LlmqNetwork net, uint32_t next_height,
    const QuorumManager& qmgr,
    const std::function<std::optional<uint256>(uint32_t)>& hash_at_height,
    const std::function<std::optional<uint32_t>(const uint256&)>& height_of_hash,
    const MineableCommitmentCache* cache = nullptr,
    const DkgNullEvidenceFn& null_evidence = nullptr,
    RequiredQcSlot* first_gap = nullptr,
    const std::function<bool(uint8_t, const uint256&)>& also_has_mined = nullptr)
{
    auto has_mined = [&qmgr, &also_has_mined](uint8_t t, const uint256& qh) {
        if (qmgr.find(t, qh).has_value()) return true;
        return also_has_mined ? also_has_mined(t, qh) : false;
    };
    auto commitments = daemonless_qc_commitments(
        net, next_height, hash_at_height, has_mined, cache,
        null_evidence, first_gap);
    if (!commitments) return std::nullopt;
    auto root = compute_merkle_root_quorums_with_block(
        net, qmgr, *commitments, height_of_hash);
    if (!root) return std::nullopt;
    return QcBlockPlan{std::move(*commitments), *root};
}

} // namespace coin
} // namespace dash

