// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L — daemonless sourcing of the deterministic quorum MEMBER SET, the
/// input #812's verify_final_commitment needs to serve a REAL commitment.
///
/// verify_final_commitment(commitment, members) needs the ordered operator-key
/// set of the quorum's members. That set is ComputeQuorumMembers over the SML
/// AS OF the WORK block = quorumBase - WORK_DIFF_DEPTH(8) (#814 review R2:
/// dashcore v23.1.7 GetAllQuorumMembers non-rotated post-V20 feeds
/// GetListForBlock(pWorkBlockIndex), NOT the base-block list) — but the
/// embedded SML (E3) tracks the TIP, not arbitrary historical heights. This
/// module sources the historical input off the SAME coin-P2P client the E3 SML
/// sync already uses, computes the member set, and caches it for the
/// synchronous MemberKeysProvider lookup.
///
/// ONE request per quorum (R2 collapse): getmnlistd(ZERO, workHash) yields a
/// full snapshot whose SML is the work-block list AND whose embedded cbTx
/// carries the work block's bestCLSignature — both member-selection inputs in
/// one reply. Requests are DEDUPED BY BLOCK HASH (#814 review R1): on mainnet
/// the non-rotated types share quorum bases every cycle (50_60 + 100_67 every
/// 24 boundary; all four align at 576), so several (type, quorumHash) keys
/// ride ONE outstanding getmnlistd — a duplicate request would draw a second
/// reply that no longer matches an await and would leak past the demux into
/// the tip-SML maintainer (the R1 block-losing corruption; the maintainer is
/// additionally hardened against exactly that, see coin_state_maintainer.hpp).
///
/// AUTHENTICATION (#814 review R3 — the one serve-a-bad path without it): a
/// historical snapshot is the ROOT OF TRUST for the BLS member-set verify (a
/// lying peer could otherwise serve attacker keys plus a qfcommit that
/// legitimately BLS-verifies against them -> bad-qc -> lost block). So before
/// a snapshot is believed it must pass DIP-4 client verification:
///   (a) its embedded cbTx parses (type-5 CCbTx) and cbTx.nHeight == the
///       expected work height;
///   (b) cbTxMerkleTree proves the cbTx hash into the WORK block header's
///       hashMerkleRoot (header already PoW-verified by the header chain) at
///       tx index 0 (the coinbase);
///   (c) the snapshot SML's computed merkle root == cbTx.merkleRootMNList.
/// Any failure -> the pending quorums for that hash FAIL CLOSED: their member
/// set stays unsourced, so no commitment can be BLS-verified for those slots.
/// That is a REFUSAL, not a null serve — the slot is unsatisfiable and the
/// whole height falls back to dashd (cause=qc-plan-underivable). c2pool never
/// mines a null commitment to fill the shortfall (dkg_commitments.hpp HEIGHT
/// COMPLETENESS: doing so diverged merkleRootQuorums at block 1520106).
///
/// MODIFIER (#814 review R5): the coinbase ChainLock input is the work block's
/// OWN cbTx bestCLSignature — v23.1.7 GetNonNullCoinbaseChainlock does NOT
/// walk back. A null CL there means the upstream fallback modifier
/// SerializeHash((llmqType, workBlockHash)); no re-requests, no walk-back.
///
/// ASYNC by necessity: the provider is called synchronously while building a
/// template and MUST NOT block on I/O, so it only READS this cache. Population
/// is driven off relayed qfcommits (request() is kicked when a commitment for a
/// quorum is admitted) and completes when the getmnlistd reply lands. Until
/// then lookup() returns std::nullopt -> the verifier fails closed -> the slot
/// mines the consensus-valid null commitment (reward-safe), exactly the
/// pre-Phase-L posture.
///
/// DEMUX (reward-critical): historical getmnlistd replies must NOT reach the
/// E3 tip-SML maintainer — a full snapshot at an OLD base block would overwrite
/// the tip SML. on_mnlistdiff() returns TRUE when the reply matches an
/// outstanding await (whether or not it then verifies); main_dash routes such
/// replies here and skips the tip feed. Only STRICT matches consume: the diff
/// must be a full snapshot (baseBlockHash null) at an awaited block hash.
///
/// ROTATED (DIP-24) — NOW SERVED, one qrinfo per CYCLE fills 32 slots:
/// request() derives the cycle base from the quorum's own base height
/// (quorumIndex = baseHeight % dkgInterval, cycleBase = baseHeight -
/// quorumIndex — dashcore utils.cpp GetAllQuorumMembers), emits ONE getqrinfo
/// for that cycle base, and on_qrinfo() DIP-4 authenticates all four cycle
/// mnlistdiffs (each bound to the height the cycle geometry demands), runs
/// vendor::compute_quorum_members_by_quarter_rotation, and inserts ALL 32
/// resulting member sets into the SAME m_ready map the non-rotated path uses.
///
/// WHY (type, quorumHash) STAYS THE KEY: every one of the 32 rotated quorums
/// in a cycle has its OWN quorumHash — the block at cycleBase + quorumIndex
/// (DIP-0024; dashcore stores them as {cycleBaseHash, quorumIndex} internally
/// but the COMMITMENT carries the per-index base block hash). So no key,
/// provider signature or commitment-cache change was needed: one authenticated
/// reply simply populates 32 distinct keys at once. A slot whose base header
/// is not held when the reply finalizes is published LATE instead of lost:
/// the cycle's computed sets are retained (FIFO-bounded) and request()
/// republishes the slot the moment a qfcommit kick proves its header exists
/// (see the qi=11 wedge note at finalize_rotated / try_republish_rotated_slot).
///
/// DELIBERATE REVERSAL (was: "issue no getqrinfo"): the previous slice left
/// request() silent for rotated types on the reasoning that a live request
/// whose reply could not yet produce a member set is traffic on a money path
/// for no gain. Now that the reply DOES produce the member set, that reasoning
/// inverts and the branch emits. The request is still bounded exactly like the
/// non-rotated one (one outstanding per cycle base, deduped, FIFO-reaped) and
/// is only made for a cycle whose geometry validates locally first.
///
/// OBSERVABILITY ON THE ROTATED LANE (the defect this discipline exists for):
/// three live soaks cached 32 type-5 (LLMQ_60_75) qfcommits and produced ZERO
/// "[QC-MEMBERS] READY type=5", and NOTHING in the logs could distinguish
///   (a) the getqrinfo was never sent,
///   (b) it was sent and no reply came,
///   (c) a reply came and was dropped.
/// It was (c): message_qrinfo was missing from the p2p::Handler type list, so
/// every reply died in the "unhandled command" catch at DEBUG level and
/// on_qrinfo() was never called. Both the registry gap and the silence are
/// fixed. Every terminal state of this lane is now a RotatedOutcome that names
/// itself in the log with the cause=/value=/threshold= discipline the serve
/// gate uses, and an unanswered getqrinfo TIMES OUT by name — which also stops
/// one lost reply from wedging its cycle forever behind the dedup branch.
///
/// FAIL-CLOSED throughout: pre-V20 work block, base not dkgInterval-aligned,
/// header gap, unknown type, snapshot authentication failure, member
/// computation ambiguous (score tie / short quarter / zero operator key)
/// -> the quorum simply never becomes ready and the verifier serves null.
///
/// Threading: all entry points run on the single coin ioc thread (same
/// assumption as QuorumManager) — no internal locking.

#include <impl/dash/coin/historical_sml.hpp>       // authenticate_historical_snapshot (shared R3)
#include <impl/dash/coin/dkg_commitments.hpp>          // LlmqNetwork, enabled_llmqs
#include <impl/dash/coin/utxo_adapter.hpp>             // dash_txid
#include <impl/dash/coin/vendor/quorum_members.hpp>    // compute_quorum_members
#include <impl/dash/coin/vendor/quorum_members_rotated.hpp>  // DIP-24 quarter rotation
#include <impl/dash/coin/vendor/smldiff.hpp>           // CSimplifiedMNListDiff, apply_diff, ExtractMatches
#include <impl/dash/coin/vendor/cbtx.hpp>              // CCbTx, parse_cbtx
#include <impl/dash/coin/vendor/simplifiedmns.hpp>     // CSimplifiedMNList
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>  // DIP-24 CQuorumRotationInfo / CQuorumSnapshot

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <set>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// Every terminal outcome of the DIP-24 ROTATED lane, so the lane can never
/// again fail without saying which of them happened.
///
/// WHY THIS EXISTS: three live soaks cached 32 type-5 (LLMQ_60_75) qfcommits
/// and produced zero READY, and the logs could not distinguish "the request
/// was never sent" from "it was sent and no reply came" from "a reply came and
/// was dropped". Each rotated exit below now names itself with the same
/// cause=/value=/threshold= discipline the serve gate uses.
enum class RotatedOutcome {
    kNone = 0,
    // request() / request_rotated() — the SEND side
    kRequestSent,
    kRequestDeduped,             // a getqrinfo for this cycle is already out
    kRequestAlreadyReady,        // the cycle is served; no traffic needed
    kRefusedUnknownType,
    kRefusedNotRotated,
    kRefusedNoSendSeam,          // set_send_getqrinfo() never called
    kRefusedIntervalZero,
    kRefusedBaseHeaderMissing,   // header chain does not hold the quorum base
    kRefusedIndexOutOfRange,     // quorumIndex >= signingActiveQuorumCount
    kRefusedCycleHeaderGap,      // cycle-base header not held
    kRefusedBaseUnaligned,       // cycle base not on a dkgInterval boundary
    kRefusedCycleSpanTooShallow, // chain shorter than base-8-3C
    kRefusedPreV20,
    // on_qrinfo() — the REPLY side
    kReplyNoCbTx,
    kReplyUnsolicited,           // matched no outstanding request
    kReplyTypeVanished,
    kReplyNotFullList,
    kReplyAuthFailed,
    // finalize_rotated() — the COMPUTE side
    kComputeAmbiguous,
    kNoSlotHeaders,
    kReady,
    // request() — a slot published LATE from the retained cycle compute
    // (its base header was not held when the qrinfo was finalized)
    kSlotRepublished,
    // expire_rotated_requests()
    kTimedOut,                   // getqrinfo sent, no reply inside the window
};

inline const char* rotated_outcome_name(RotatedOutcome o)
{
    switch (o) {
    case RotatedOutcome::kNone:                     return "none";
    case RotatedOutcome::kRequestSent:              return "request_sent";
    case RotatedOutcome::kRequestDeduped:           return "request_deduped";
    case RotatedOutcome::kRequestAlreadyReady:      return "already_ready";
    case RotatedOutcome::kRefusedUnknownType:       return "unknown_llmq_type";
    case RotatedOutcome::kRefusedNotRotated:        return "type_not_rotated";
    case RotatedOutcome::kRefusedNoSendSeam:        return "no_send_seam";
    case RotatedOutcome::kRefusedIntervalZero:      return "dkg_interval_zero";
    case RotatedOutcome::kRefusedBaseHeaderMissing: return "base_header_not_held";
    case RotatedOutcome::kRefusedIndexOutOfRange:   return "quorum_index_out_of_range";
    case RotatedOutcome::kRefusedCycleHeaderGap:    return "cycle_base_header_not_held";
    case RotatedOutcome::kRefusedBaseUnaligned:     return "cycle_base_unaligned";
    case RotatedOutcome::kRefusedCycleSpanTooShallow: return "cycle_span_too_shallow";
    case RotatedOutcome::kRefusedPreV20:            return "pre_v20_work_block";
    case RotatedOutcome::kReplyNoCbTx:              return "reply_no_type5_cbtx";
    case RotatedOutcome::kReplyUnsolicited:         return "reply_unsolicited";
    case RotatedOutcome::kReplyTypeVanished:        return "reply_type_vanished";
    case RotatedOutcome::kReplyNotFullList:         return "reply_not_full_list";
    case RotatedOutcome::kReplyAuthFailed:          return "reply_dip4_auth_failed";
    case RotatedOutcome::kComputeAmbiguous:         return "member_compute_ambiguous";
    case RotatedOutcome::kNoSlotHeaders:            return "no_slot_base_headers";
    case RotatedOutcome::kReady:                    return "ready";
    case RotatedOutcome::kSlotRepublished:          return "slot_republished_from_cycle";
    case RotatedOutcome::kTimedOut:                 return "request_timed_out";
    }
    return "unnamed";   // unreachable; a new enumerator without a name is a bug
}

class QuorumMemberSource {
public:
    using HashAtHeight = std::function<std::optional<uint256>(uint32_t)>;
    using HeightOfHash = std::function<std::optional<uint32_t>(const uint256&)>;
    // The PoW-verified header's hashMerkleRoot for a held block hash (the
    // DIP-4 trust anchor); std::nullopt when the header is not held.
    using MerkleRootOfHash = std::function<std::optional<uint256>(const uint256&)>;
    using SendGetMnListd = std::function<void(const uint256& base, const uint256& target)>;

    // Soft cap on cached member sets (each ~ size*49 bytes); FIFO eviction.
    static constexpr size_t kReadyCap = 1024;
    // Reap bound on outstanding requests (review nit: pendings must not
    // accumulate forever when a peer never replies); FIFO eviction.
    static constexpr size_t kPendingCap = 64;

    QuorumMemberSource(LlmqNetwork net, HashAtHeight hash_at_height,
                       HeightOfHash height_of_hash,
                       MerkleRootOfHash merkle_root_of_hash, SendGetMnListd send)
        : m_net(net), m_hash_at_height(std::move(hash_at_height))
        , m_height_of_hash(std::move(height_of_hash))
        , m_merkle_root_of_hash(std::move(merkle_root_of_hash))
        , m_send(std::move(send))
    {}

    /// The MemberKeysProvider seam: ready member set for (llmqType, quorumHash),
    /// or std::nullopt (fail closed). Never blocks / never issues I/O.
    std::optional<std::vector<vendor::MemberOperatorKey>>
    lookup(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        auto it = m_ready.find(Key{llmq_type, quorum_hash});
        if (it == m_ready.end()) return std::nullopt;
        return it->second;
    }

    /// Kick sourcing for a quorum (idempotent). Called when a qfcommit for the
    /// quorum is admitted, so the member set is ready by the DKG-window height.
    /// #108 — PREFETCH the member sets a DKG cycle will need, BEFORE the
    /// commitments that need them arrive.
    ///
    /// MEASURED (fully-daemonless soak, 2026-08-06/07): 48 of the embedded
    /// arm's decline events were cause=qc-plan-underivable, and they are not
    /// scattered — every one sits at a height h where (h % dkgInterval) equals
    /// the type's mining_window_start, and each clears in 1-7 minutes. That is
    /// one getmnlistd/getqrinfo round trip, paid at the exact moment the plan
    /// first needs the answer.
    ///
    /// The inputs, however, are available much earlier: a non-rotated quorum's
    /// member set derives from the WORK block (quorumBase - 8), and the cycle
    /// base is known the moment the tip crosses it — typically ten blocks and
    /// ~25 minutes before the mining window opens. So the round trip is not
    /// unavoidable latency; it is latency we chose by asking late.
    ///
    /// This asks early. It calls the SAME request paths with the SAME key, so
    /// every invariant they carry is untouched: DIP-4 authentication of the
    /// snapshot, dedupe-by-block-hash, one outstanding request per base, FIFO
    /// reaping, and the demux that keeps historical replies away from the tip
    /// SML. The qfcommit kick stays exactly as it was — this only changes WHEN
    /// the first attempt happens, never whether the answer is trusted.
    ///
    /// Silent no-ops are deliberate: a header we do not hold yet, a pre-V20
    /// height, a type whose params we do not know. Prefetch is an optimisation
    /// and must never fail a template; the qfcommit kick remains the fallback
    /// for every case this skips.
    void prefetch_cycle(uint32_t tip_height)
    {
        if (tip_height == 0) return;
        // #1176 SLOT-AWARE READINESS. Before walking the prefetch memo, honour
        // reorgs: a rotated cycle is memoised by (type, cycleBase) and never
        // re-walked, so a reorg that swaps a TOP-slot header (cycleBase+qi for a
        // high qi) after the cycle was prefetched would strand that slot — its
        // m_ready entry is keyed by a block hash no longer on the chain, and the
        // memo suppresses any re-derivation. The serve gate fails CLOSED there
        // (qc-plan-underivable, never a bad block), but the SLOT is lost for its
        // whole mining window. reconcile_rotated_slots() detects the swap by the
        // header each published slot was derived under and re-derives the
        // changed slot from the retained cycle compute — the SAME republish path
        // the qi=11 late-slot wedge uses, reached by reorg-detection instead of a
        // qfcommit kick. It runs on EVERY tip (including catch-up), because a
        // reorg is exactly the event the catch-up gate below would skip.
        reconcile_rotated_slots();
        // CATCH-UP GATE. The tip callback fires once per headers MESSAGE, and
        // add_headers coalesces up to 2000 headers into one — so during a cold
        // start or a long resync each call arrives ~2000 blocks above the last.
        // Every such call is a memo miss for every type (2000 > any mainnet
        // dkgInterval), and each miss asks for a cycle whose mining window is
        // long past: measured shape is ~215 requests / ~100 MB of full MN
        // snapshots from a checkpointed cold start, all of it riding the ONE
        // ordered stream to the primary coin-P2P peer that the cold-start path
        // (#1162/#1151) just spent effort making fast. Prefetch is an
        // optimisation for the LIVE tip; while we are catching up the qfcommit
        // kick remains the correct and sufficient mechanism.
        const uint32_t prev = m_last_prefetch_tip;
        m_last_prefetch_tip = tip_height;
        if (prev != 0 && tip_height > prev + kMaxDkgInterval)
            return;   // jumped a whole cycle or more => still catching up
        for (const auto& p : enabled_llmqs(m_net)) {
            if (p.dkg_interval == 0) continue;
            // The cycle whose mining window this tip is approaching: the most
            // recent boundary at or below the tip.
            const uint32_t cycle_base = tip_height - (tip_height % p.dkg_interval);
            if (cycle_base == 0) continue;
            // ROTATED TYPES (DIP-24): DO NOT ask at the cycle boundary.
            //
            // A rotated reply publishes one member set per slot, keyed by the
            // header at cycleBase + quorumIndex (finalize_rotated). At the tip
            // that CROSSES the boundary only cycleBase itself exists, so 31 of
            // 32 slots would be skipped for want of a header. Skipped slots
            // now recover via the retained-cycle republish in request() (the
            // qi=11 wedge fix), so this is no longer a permanent-wedge hazard
            // — but asking before the slot headers exist still buys nothing:
            // every skipped slot waits for its header anyway, exactly what
            // waiting here achieves without spending a 600 kB reply early.
            //
            // So wait until the last slot's base header is in the chain. With
            // signing_active_quorum_count=32 and mining_window_start=42 the
            // prefetch still lands ~10 blocks (~25 min) before the window
            // opens, which is the entire point of this change.
            //
            // The memo is inserted AFTER this check on purpose: memoising a
            // cycle we deliberately skipped would burn the only chance to
            // prefetch it at all.
            if (p.use_rotation) {
                const uint32_t last_slot_h =
                    cycle_base + (p.signing_active_quorum_count > 0
                                      ? p.signing_active_quorum_count - 1
                                      : 0);
                if (tip_height < last_slot_h) continue;   // retry on a later tip
            }
            // Only act once per (type, cycle) — repeated tips inside the same
            // cycle must not re-walk the request path.
            // Resolve the header BEFORE memoising. A header gap is a
            // "not yet", not a "done": memoising it would spend the cycle's
            // only prefetch on a lookup that failed.
            auto base_hash = m_hash_at_height(cycle_base);
            if (!base_hash || base_hash->IsNull()) continue;  // retry next tip
            const uint64_t seen_key =
                (static_cast<uint64_t>(p.type) << 32) | cycle_base;
            if (!m_prefetched_cycles.insert(seen_key).second) continue;
            // Lead time is measured from the tip we are ON, not from the
            // window offset: a rotated type waits for its slot headers, so it
            // asks LATER than a non-rotated one and the honest number is the
            // difference. (An earlier version printed mining_window_start,
            // which overstated the rotated lane by 4x.)
            const uint32_t window_open_h = cycle_base + p.mining_window_start;
            const long lead = static_cast<long>(window_open_h)
                            - static_cast<long>(tip_height);
            LOG_INFO << "[QC-PREFETCH] cycle_base=" << cycle_base
                     << " type=" << static_cast<int>(p.type)
                     << " hash=" << base_hash->GetHex().substr(0, 8)
                     << " tip=" << tip_height
                     << " rotated=" << (p.use_rotation ? 1 : 0)
                     << " lead=" << lead
                     << " blocks before the mining window opens at h="
                     << window_open_h;
            request(p.type, *base_hash);
        }
        // Bound the memo: a cycle far behind the tip can never be asked for
        // again, and an unbounded set would grow for the life of the node.
        if (m_prefetched_cycles.size() > kPrefetchMemoMax)
            m_prefetched_cycles.clear();
    }

    void request(uint8_t llmq_type, const uint256& quorum_hash)
    {
        // request() is kicked on every admitted qfcommit, which makes it the
        // one reliable heartbeat this class has. Use it to retire rotated
        // requests that were sent and never answered — otherwise a single
        // unanswered getqrinfo wedges its cycle FOREVER (every later slot of
        // that cycle dedupes against the stuck pending and sends nothing).
        // That is precisely what a dropped reply produced in the soaks.
        expire_rotated_requests();

        const Key key{llmq_type, quorum_hash};
        if (m_ready.count(key) || m_pending.count(key)) return;

        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr) {                             // unknown type => fail closed
            note_rotated(RotatedOutcome::kRefusedUnknownType,
                         "type=" + std::to_string(static_cast<int>(llmq_type)));
            return;
        }
        if (p->use_rotation) {
            // ── ROTATED (DIP-24, e.g. llmq_60_75) ───────────────────────────
            // A rotated quorum's member set is NOT derivable from a single
            // work-block snapshot: dashcore ComputeQuorumMembersByQuarterRotation
            // (llmq/utils.cpp) assembles it from the three QUARTER-ROTATION
            // snapshots plus the four cycle work-block lists, which only the
            // qrinfo message carries. Sourcing is therefore per CYCLE, not per
            // quorum — and ONE reply yields all signingActiveQuorumCount sets.
            //
            // Derive the cycle base exactly as upstream GetAllQuorumMembers
            // does: quorumIndex = baseHeight % dkgInterval, and the cycle base
            // is baseHeight - quorumIndex. Upstream also REFUSES an index at or
            // beyond signingActiveQuorumCount (`return {}`), so do we.
            const std::string who =
                "type=" + std::to_string(static_cast<int>(llmq_type))
                + " quorum=" + quorum_hash.GetHex().substr(0, 16);
            auto rot_base_h = m_height_of_hash(quorum_hash);
            if (!rot_base_h) {                          // base header not held
                note_rotated(RotatedOutcome::kRefusedBaseHeaderMissing, who);
                return;
            }
            if (p->dkg_interval == 0) {
                note_rotated(RotatedOutcome::kRefusedIntervalZero, who);
                return;
            }
            const uint32_t quorum_index = *rot_base_h % p->dkg_interval;
            if (quorum_index >= p->signing_active_quorum_count) {
                note_rotated(RotatedOutcome::kRefusedIndexOutOfRange,
                             who + " value=" + std::to_string(quorum_index)
                             + " threshold=" + std::to_string(p->signing_active_quorum_count));
                return;
            }
            const uint32_t cycle_h = *rot_base_h - quorum_index;
            auto cycle_hash = m_hash_at_height(cycle_h);
            if (!cycle_hash || cycle_hash->IsNull()) {   // header gap
                note_rotated(RotatedOutcome::kRefusedCycleHeaderGap,
                             who + " cycle_base_h=" + std::to_string(cycle_h));
                return;
            }
            // LATE-SLOT REPUBLISH (the qi=11 member-set-unsourced wedge).
            // finalize_rotated() publishes each slot under the header at
            // cycleBase+qi and SKIPS a slot whose header is not held yet. If
            // index 0 published, the cycle key was in m_ready, and the old
            // code short-circuited every later request of the SAME cycle as
            // "already ready" — so a slot skipped at finalize time could never
            // become ready, ever: the refusal persisted through its entire
            // mining window (measured live: type=5 qi=11, whole window
            // [2517450,2517458], qfcommit cached with 59 signers).
            //
            // dashd has no such state: GetAllQuorumMembers (utils.cpp:569)
            // recomputes any missed quorum from its local evoDB stores on
            // cache miss. Our inputs are transient qrinfo replies, so the
            // structural equivalent is retaining the cycle's COMPUTED sets
            // and publishing a late slot from them here — same computation,
            // same bytes, just published when the slot's header (which this
            // request's own quorum_hash proves we now hold) has arrived.
            // (request() already returned above when this slot key is ready,
            // so reaching here means the slot is genuinely unsourced.)
            if (try_republish_rotated_slot(key, llmq_type, *cycle_hash,
                                           cycle_h, quorum_index))
                return;
            request_rotated(llmq_type, *cycle_hash);
            return;
        }

        auto base_h = m_height_of_hash(quorum_hash);
        if (!base_h) return;                            // base header not held yet
        // Upstream refusal (utils.cpp ComputeQuorumMembers): a non-rotated
        // quorum base MUST sit on a dkgInterval boundary. Also bounds
        // peer-driven request amplification via bogus quorumHashes.
        if (*base_h % p->dkg_interval != 0) return;
        if (*base_h < kWorkDiffDepth) return;           // no work block
        const uint32_t work_h = *base_h - kWorkDiffDepth;
        if (work_h < quorum_members_v20_floor()) return; // pre-V20 => fail closed
        auto work_hash = m_hash_at_height(work_h);
        if (!work_hash || work_hash->IsNull()) return;   // work header gap

        reap_if_needed();

        Pending pend;
        pend.type        = llmq_type;
        pend.quorum_hash = quorum_hash;
        pend.work_height = work_h;
        pend.work_hash   = *work_hash;
        m_pending.emplace(key, std::move(pend));
        m_pending_fifo.push_back(key);

        // ONE full snapshot at the WORK block carries BOTH member-selection
        // inputs (SML + cbTx bestCLSignature). Dedup outstanding requests BY
        // HASH (R1): if an await for this block already exists (a sibling type
        // sharing the cycle base), ride it — do NOT draw a second reply.
        auto& waiters = m_await[*work_hash];
        waiters.push_back(key);
        if (waiters.size() == 1) {
            m_send(uint256::ZERO, *work_hash);
            LOG_INFO << "[QC-MEMBERS] sourcing work-block snapshot "
                     << work_hash->GetHex().substr(0, 16) << " (work_h=" << work_h
                     << ") for type=" << static_cast<int>(llmq_type)
                     << " quorum=" << quorum_hash.GetHex().substr(0, 16)
                     << " base_h=" << *base_h;
        } else {
            LOG_INFO << "[QC-MEMBERS] type=" << static_cast<int>(llmq_type)
                     << " quorum=" << quorum_hash.GetHex().substr(0, 16)
                     << " rides outstanding snapshot request for work block "
                     << work_hash->GetHex().substr(0, 16)
                     << " (" << waiters.size() << " waiters)";
        }
    }

    /// True iff a mnlistdiff for `block_hash` is one this source requested.
    bool awaiting(const uint256& block_hash) const
    {
        return m_await.count(block_hash) != 0;
    }

    // ═══ DIP-24 ROTATED SOURCING + SERVING ═════════════════════════════════
    // Wire + authenticated decode + the quarter-rotation member computation.
    // on_qrinfo() ends by inserting all signingActiveQuorumCount member sets
    // into m_ready, so lookup() serves rotated commitments for real.
    // Everything below is exercised by the real-vector KAT.

    using SendGetQrInfo = std::function<void(const std::vector<uint256>& bases,
                                            const uint256& request_hash,
                                            bool extra_share)>;

    /// Optional (not a constructor arg, so no existing call site changes).
    void set_send_getqrinfo(SendGetQrInfo f) { m_send_qrinfo = std::move(f); }

    /// The four cycle SMLs a rotated member computation consumes, each already
    /// DIP-4 authenticated and bound to its expected height.
    struct RotatedInputs {
        uint8_t  llmq_type{0};
        uint256  quorum_hash;
        uint32_t cycle_base_height{0};
        // heights: H = base-8, then -C, -2C, -3C
        std::array<uint32_t, 4>                      heights{};
        std::array<vendor::CSimplifiedMNList, 4>     smls{};
        // GetHashModifier for each of the four CYCLE BASES (not the work
        // blocks): post-V20 that is SHA256d(type, workHeight, bestCLSignature)
        // taken from each cycle work block's OWN cbTx, with the
        // SHA256d(type, workBlockHash) fallback when that CL is null.
        std::array<uint256, 4>                       modifiers{};
        std::array<vendor::CQuorumSnapshot, 3>       snapshots{};  // H-C, H-2C, H-3C
        std::vector<vendor::CFinalCommitment>        last_commitment_per_index;
    };

    /// Ask a peer for the rotation info backing `quorum_hash`. Returns false
    /// (and sends nothing) when the request cannot be validated locally —
    /// unknown/non-rotated type, unaligned base, missing header, pre-V20.
    /// EMPTY baseBlockHashes on purpose: it makes the peer answer with FULL
    /// (from-genesis) lists, and only a full list is self-authenticating
    /// against its own cbTx.merkleRootMNList.
    /// `quorum_hash` is the CYCLE BASE block hash (dkgInterval-aligned) — the
    /// per-index entry point is request(), which derives it.
    bool request_rotated(uint8_t llmq_type, const uint256& quorum_hash)
    {
        const std::string who =
            "type=" + std::to_string(static_cast<int>(llmq_type))
            + " cycle_base=" + quorum_hash.GetHex().substr(0, 16);

        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr)
            return note_rotated_false(RotatedOutcome::kRefusedUnknownType, who);
        if (!p->use_rotation)
            return note_rotated_false(RotatedOutcome::kRefusedNotRotated, who);
        // The one refusal that is a WIRING fault, not a data fault: with no
        // send seam the lane emits nothing at all and every rotated quorum
        // stays unsourced forever (its slots refuse; they are NOT null-served
        // -- see the 1520106 incident). It must never be silent again.
        if (!m_send_qrinfo)
            return note_rotated_false(RotatedOutcome::kRefusedNoSendSeam, who);

        auto base_h = m_height_of_hash(quorum_hash);
        if (!base_h)
            return note_rotated_false(RotatedOutcome::kRefusedBaseHeaderMissing, who);
        if (p->dkg_interval == 0)
            return note_rotated_false(RotatedOutcome::kRefusedIntervalZero, who);
        if (*base_h % p->dkg_interval != 0)
            return note_rotated_false(
                RotatedOutcome::kRefusedBaseUnaligned,
                who + " value=" + std::to_string(*base_h)
                + " threshold=dkg_interval:" + std::to_string(p->dkg_interval));
        // Need H-3C to exist: base - 8 - 3*C.
        const uint64_t span = static_cast<uint64_t>(kWorkDiffDepth)
                            + 3ull * p->dkg_interval;
        if (*base_h < span)
            return note_rotated_false(
                RotatedOutcome::kRefusedCycleSpanTooShallow,
                who + " value=" + std::to_string(*base_h)
                + " threshold=" + std::to_string(span));
        if (*base_h - kWorkDiffDepth < quorum_members_v20_floor())
            return note_rotated_false(
                RotatedOutcome::kRefusedPreV20,
                who + " value=" + std::to_string(*base_h - kWorkDiffDepth)
                + " threshold=" + std::to_string(quorum_members_v20_floor()));

        const Key ckey{llmq_type, quorum_hash};
        // ONE outstanding getqrinfo per cycle base: the 32 slots of a cycle all
        // resolve to this same request, and a duplicate would draw a second
        // 600 kB reply that no await matches (the R1 hazard, per-cycle form).
        if (m_rotated_pending.count(ckey)) {
            m_last_rotated = RotatedOutcome::kRequestDeduped;
            return true;
        }
        // A cycle whose COMPUTED sets are retained needs no traffic: every
        // slot whose base header is held republishes from them in request()
        // before this function is reached, and a slot whose header is missing
        // cannot be helped by a fresh 600 kB reply either (finalize would
        // skip it again for the same missing header).
        if (m_rotated_cycles.count(ckey)) {
            m_last_rotated = RotatedOutcome::kRequestAlreadyReady;
            return true;
        }
        // Cycle key ready in m_ready but its retained compute is GONE
        // (FIFO-evicted). The pre-fix code returned "already ready" here on
        // the cycle key alone — the wedge: request() only reaches this point
        // for a slot that is NOT ready, and short-circuiting on index 0's key
        // meant that slot could never be sourced again. Fall through and
        // re-request; the traffic is bounded exactly like a first request
        // (one outstanding per cycle, timeout, FIFO reap).
        if (m_ready.count(ckey)) {
            LOG_INFO << "[QC-MEMBERS] rotated cycle " << who
                     << " is served at index 0 but a later slot is unsourced "
                        "and the retained cycle compute was evicted — "
                        "re-requesting qrinfo";
        }
        reap_rotated_if_needed();

        m_rotated_pending[ckey] = RotatedPending{*base_h, m_now()};
        m_rotated_fifo.push_back(ckey);
        m_send_qrinfo(std::vector<uint256>{}, quorum_hash, /*extra_share=*/false);
        m_last_rotated = RotatedOutcome::kRequestSent;
        LOG_INFO << "[QC-MEMBERS] rotated getqrinfo SENT outcome="
                 << rotated_outcome_name(RotatedOutcome::kRequestSent)
                 << " " << who << " cycle_base_h=" << *base_h
                 << " timeout=" << kRotatedRequestTimeoutSec << "s"
                 << " (awaiting a qrinfo RECEIVED line; if none appears a "
                    "TIMED OUT line will)";
        return true;
    }

    /// Consume a qrinfo reply. DIP-4 authenticates EVERY cycle mnlistdiff with
    /// the same discipline as the non-rotated path, binding each to the height
    /// the cycle geometry says it must be — a peer cannot answer with another
    /// block's genuine snapshot. Returns the authenticated inputs, or nullopt
    /// (fail closed) if anything does not check out.
    std::optional<RotatedInputs>
    on_qrinfo(const vendor::CQuorumRotationInfo& info)
    {
        // Which outstanding rotated request is this? Bind by the H diff's
        // height: H must be (cycle_base - 8) for exactly one pending.
        // Named ARRIVAL: this is the line whose absence made "no reply came"
        // and "a reply came and was dropped" indistinguishable in the soaks.
        LOG_INFO << "[QC-MEMBERS] qrinfo ARRIVED at member source: "
                 << "lastCommitmentPerIndex=" << info.lastCommitmentPerIndex.size()
                 << " outstanding=" << m_rotated_pending.size();

        vendor::CCbTx probe_cbtx;
        if (info.mnListDiffH.cbTx.type != 5
            || !vendor::parse_cbtx(info.mnListDiffH.cbTx.extra_payload, probe_cbtx)
            || probe_cbtx.nHeight < 0) {
            note_rotated(RotatedOutcome::kReplyNoCbTx,
                         "mnListDiffH carries no usable type-5 cbTx");
            return std::nullopt;
        }
        const uint64_t h_height = static_cast<uint64_t>(probe_cbtx.nHeight);

        const Key* match = nullptr;
        uint32_t   base_h = 0;
        for (const auto& [key, pend] : m_rotated_pending) {
            if (static_cast<uint64_t>(pend.cycle_base_height)
                == h_height + kWorkDiffDepth) {
                match = &key;
                base_h = pend.cycle_base_height;
                break;
            }
        }
        if (match == nullptr) {
            note_rotated(RotatedOutcome::kReplyUnsolicited,
                         "value=H:" + std::to_string(h_height)
                         + " threshold=outstanding:"
                         + std::to_string(m_rotated_pending.size()));
            return std::nullopt;
        }
        const Key key = *match;

        const LlmqParamsView* p = params_for(key.llmqType);
        if (p == nullptr || !p->use_rotation || p->dkg_interval == 0) {
            erase_rotated_pending(key);
            note_rotated(RotatedOutcome::kReplyTypeVanished,
                         "type=" + std::to_string(static_cast<int>(key.llmqType)));
            return std::nullopt;
        }
        const uint32_t C = p->dkg_interval;

        RotatedInputs out;
        out.llmq_type        = key.llmqType;
        out.quorum_hash      = key.quorumHash;
        out.cycle_base_height = base_h;

        const vendor::CSimplifiedMNListDiff* diffs[4] = {
            &info.mnListDiffH,
            &info.mnListDiffAtHMinusC,
            &info.mnListDiffAtHMinus2C,
            &info.mnListDiffAtHMinus3C,
        };
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t expect_h =
                base_h - kWorkDiffDepth - static_cast<uint32_t>(i) * C;
            out.heights[i] = expect_h;

            // A qrinfo cycle diff MUST be a FULL list: authentication applies
            // it onto an EMPTY list, so an incremental diff would authenticate
            // a list that is not the one at that height.
            //
            // ⚠ NOT the same test as the getmnlistd path's baseBlockHash.IsNull().
            // Observed from a real dashd: when the request carries an EMPTY
            // baseBlockHashes, the qrinfo diffs come back with baseBlockHash =
            // the GENESIS hash, not ZERO. So "full" is signalled here by having
            // nothing to delete (from genesis there is nothing to delete), and
            // the actual GUARANTEE is leg (c) of the authentication below: the
            // applied-onto-empty SML root must equal cbTx.merkleRootMNList, which
            // an incremental diff cannot satisfy.
            if (!diffs[i]->deletedMNs.empty()) {
                erase_rotated_pending(key);
                note_rotated(RotatedOutcome::kReplyNotFullList,
                             "cycle_diff=" + std::to_string(i)
                             + " value=deletedMNs:"
                             + std::to_string(diffs[i]->deletedMNs.size())
                             + " threshold=0 — whole reply fails closed");
                return std::nullopt;
            }
            vendor::CCbTx cbtx;
            auto sml = authenticate_historical_snapshot(
                *diffs[i], expect_h, m_merkle_root_of_hash, cbtx, "QC-MEMBERS");
            if (!sml) {
                erase_rotated_pending(key);
                note_rotated(RotatedOutcome::kReplyAuthFailed,
                             "cycle_diff=" + std::to_string(i)
                             + " expected_h=" + std::to_string(expect_h)
                             + " — whole reply fails closed");
                return std::nullopt;
            }
            out.smls[i] = std::move(*sml);

            // GetHashModifier for cycle base (base - i*C): post-V20 it hashes
            // the WORK block's height + its OWN cbTx bestCLSignature (R5 — no
            // walk-back), else falls back to (type, workBlockHash). The
            // work-block hash is the diff's own blockHash, which leg (b) of the
            // authentication above has just tied to a PoW-verified header.
            std::optional<std::array<uint8_t, vendor::CFinalCommitment::BLS_SIG_SIZE>> clsig;
            if (cbtx.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
                && cbtx.has_best_cl_signature()) {
                clsig = cbtx.bestCLSignature;
            }
            out.modifiers[i] = vendor::compute_quorum_modifier(
                key.llmqType, expect_h, clsig, diffs[i]->blockHash);
        }

        out.snapshots[0] = info.quorumSnapshotAtHMinusC;
        out.snapshots[1] = info.quorumSnapshotAtHMinus2C;
        out.snapshots[2] = info.quorumSnapshotAtHMinus3C;
        out.last_commitment_per_index = info.lastCommitmentPerIndex;

        erase_rotated_pending(key);
        LOG_INFO << "[QC-MEMBERS] qrinfo AUTHENTICATED for rotated type="
                 << static_cast<int>(key.llmqType) << " cycle_base="
                 << key.quorumHash.GetHex().substr(0, 16)
                 << " cycle_base_h=" << base_h
                 << " (H=" << out.heights[0] << ")";

        // ITEM 4: the authenticated inputs go straight into the SAME m_ready
        // map the non-rotated path fills, so lookup() serves these quorums.
        finalize_rotated(out);
        return out;
    }

    /// Run the quarter rotation over already-authenticated inputs and publish
    /// every resulting member set. Separated from on_qrinfo() so the compute
    /// can be gated in isolation. Returns the number of slots published.
    size_t finalize_rotated(const RotatedInputs& in)
    {
        const LlmqParamsView* p = params_for(in.llmq_type);
        if (p == nullptr || !p->use_rotation) return 0;

        vendor::RotatedQuorumParams rp{p->type, p->size,
                                       p->signing_active_quorum_count};
        std::array<vendor::RotatedCycleInput, 4> cycles{};
        for (size_t i = 0; i < 4; ++i) {
            cycles[i].sml      = &in.smls[i];
            cycles[i].modifier = in.modifiers[i];
        }
        const std::array<const vendor::CQuorumSnapshot*, 3> snaps{
            &in.snapshots[0], &in.snapshots[1], &in.snapshots[2]};

        auto sets = vendor::compute_quorum_members_by_quarter_rotation(
            rp, cycles, snaps);
        if (!sets) {
            note_rotated(RotatedOutcome::kComputeAmbiguous,
                         "type=" + std::to_string(static_cast<int>(in.llmq_type))
                         + " cycle_base_h=" + std::to_string(in.cycle_base_height)
                         + " -> fail closed (whole cycle stays unsourced; its "
                           "slots refuse, they are NOT null-served)");
            return 0;
        }

        // Each of the 32 quorums in the cycle carries its OWN quorumHash: the
        // block at cycleBase + quorumIndex (DIP-0024). A slot whose header we
        // do not hold YET is skipped here — and recovered later: the cycle's
        // computed sets are RETAINED below, and request() republishes a
        // skipped slot from them the moment a qfcommit kick arrives with that
        // slot's now-held header. (The previous comment claimed a skipped
        // slot "will be re-requested"; it could not be — index 0's key IS the
        // cycle key, so once index 0 published, the re-request path
        // short-circuited on "cycle already ready" and the skipped slot
        // stayed unsourced for its whole mining window. That was the live
        // type=5 qi=11 member-set-unsourced wedge.)
        size_t published = 0;
        const size_t computed = sets->size();   // read BEFORE the move below
        for (size_t qi = 0; qi < computed; ++qi) {
            auto qh = m_hash_at_height(in.cycle_base_height
                                       + static_cast<uint32_t>(qi));
            if (!qh || qh->IsNull()) continue;
            insert_ready(Key{in.llmq_type, *qh},
                         std::vector<vendor::MemberOperatorKey>((*sets)[qi]));
            // #1176: remember the header this slot was derived under, so a later
            // reorg that swaps it is detectable in reconcile_rotated_slots().
            record_slot_derivation(in.llmq_type, in.cycle_base_height,
                                   static_cast<uint32_t>(qi), *qh);
            ++published;
        }
        retain_cycle(Key{in.llmq_type, in.quorum_hash}, std::move(*sets));
        if (published == 0) {
            note_rotated(RotatedOutcome::kNoSlotHeaders,
                         "type=" + std::to_string(static_cast<int>(in.llmq_type))
                         + " cycle_base_h=" + std::to_string(in.cycle_base_height)
                         + " value=published:0 threshold=computed:"
                         + std::to_string(computed)
                         + " -- no slot base-block header held; nothing published "
                           "yet, but the cycle compute is retained and slots "
                           "republish as their headers arrive");
        } else {
            m_last_rotated = RotatedOutcome::kReady;
            // Mirrors the non-rotated "[QC-MEMBERS] READY type=" token so a
            // single grep answers "did ANY type reach ready?" for both lanes.
            LOG_INFO << "[QC-MEMBERS] READY type="
                     << static_cast<int>(in.llmq_type)
                     << " members=" << p->size
                     << " outcome=" << rotated_outcome_name(RotatedOutcome::kReady)
                     << " lane=ROTATED cycle_base_h=" << in.cycle_base_height
                     << " slots=" << published << "/" << computed
                     << " (real-commitment serving ENABLED for this cycle)";
        }
        return published;
    }

    size_t rotated_pending_count() const { return m_rotated_pending.size(); }

    /// Cycles whose computed member sets are retained for late-slot republish.
    size_t retained_cycle_count() const { return m_rotated_cycles.size(); }

    /// Test seam ONLY (like set_clock): shrink the retention bound so the
    /// evicted-retention re-request path is reachable in a KAT without
    /// fabricating eight more authenticated cycles. Production keeps the
    /// default; 0 disables retention entirely.
    void set_retained_cycles_cap(size_t cap) { m_retained_cycles_cap = cap; }

    /// The most recent named outcome of the rotated lane. Exists so a test can
    /// assert that a failure NAMED ITSELF, not merely that it failed — the
    /// property the soaks could not check.
    RotatedOutcome last_rotated_outcome() const { return m_last_rotated; }

    /// Monotonic clock seam (seconds). Defaults to steady_clock; tests inject.
    using NowSeconds = std::function<int64_t()>;
    void set_clock(NowSeconds f) { if (f) m_now = std::move(f); }

    /// A getqrinfo the peer never answered must EXPIRE, for two reasons that
    /// the soaks demonstrated together:
    ///   (1) DIAGNOSTIC — "sent, never answered" is otherwise indistinguishable
    ///       from "sent, answered, dropped"; only one of them is a peer problem;
    ///   (2) LIVENESS — a stuck pending makes every later slot of that cycle
    ///       take the dedup branch and send nothing, so ONE lost reply wedges
    ///       the cycle permanently. Expiry re-opens it for the next qfcommit.
    /// Returns the number expired. Driven off request() (the qfcommit kick).
    size_t expire_rotated_requests()
    {
        const int64_t now = m_now();
        std::vector<Key> dead;
        for (const auto& [key, pend] : m_rotated_pending) {
            if (now - pend.sent_at >= kRotatedRequestTimeoutSec)
                dead.push_back(key);
        }
        for (const auto& key : dead) {
            const auto it = m_rotated_pending.find(key);
            const uint32_t base_h = it->second.cycle_base_height;
            const int64_t  age    = now - it->second.sent_at;
            erase_rotated_pending(key);
            note_rotated(RotatedOutcome::kTimedOut,
                         "type=" + std::to_string(static_cast<int>(key.llmqType))
                         + " cycle_base=" + key.quorumHash.GetHex().substr(0, 16)
                         + " cycle_base_h=" + std::to_string(base_h)
                         + " value=age_s:" + std::to_string(age)
                         + " threshold=" + std::to_string(kRotatedRequestTimeoutSec)
                         + " — NO qrinfo reply reached the member source; cycle "
                           "re-opened for re-request");
        }
        return dead.size();
    }

    /// Consume a historical work-block snapshot. Returns TRUE iff the diff
    /// matched an outstanding await (so the caller must NOT also feed the
    /// tip-SML maintainer) — including when it then FAILS authentication (the
    /// pendings fail closed; the reply still must not leak to the tip path).
    /// STRICT match (R1): only a FULL snapshot (baseBlockHash null) at an
    /// awaited block hash matches; anything else is not ours.
    bool on_mnlistdiff(const vendor::CSimplifiedMNListDiff& diff)
    {
        if (!diff.baseBlockHash.IsNull()) return false;   // not a full snapshot
        auto ai = m_await.find(diff.blockHash);
        if (ai == m_await.end()) return false;
        const std::vector<Key> keys = ai->second;
        m_await.erase(ai);

        // ── R3: DIP-4 client verification — authenticate BEFORE believing ──
        vendor::CCbTx cbtx;
        std::optional<vendor::CSimplifiedMNList> sml =
            authenticate_snapshot(diff, keys, cbtx);
        if (!sml) {
            for (const auto& key : keys) erase_pending(key);
            return true;   // consumed (matched an await) — but failed closed
        }

        // ── finalize every waiter off the ONE verified snapshot ────────────
        for (const auto& key : keys) {
            auto pi = m_pending.find(key);
            if (pi == m_pending.end()) continue;
            finalize(pi->second, *sml, cbtx);
            erase_pending(key);
        }
        return true;
    }

    size_t ready_count() const { return m_ready.size(); }
    size_t pending_count() const { return m_pending.size(); }

private:
    // llmq/snapshot.h @ v23.1.7: WORK_DIFF_DEPTH = 8.
    static constexpr uint32_t kWorkDiffDepth = 8;

    /// How long a getqrinfo may stay outstanding before it is declared dead.
    /// Sized well above a normal round trip for a ~600 kB reply while staying
    /// far under DASH's 2.5-minute block time, so a wedged cycle re-opens
    /// within the same block it was requested in.
    static constexpr int64_t kRotatedRequestTimeoutSec = 120;

    /// Record + LOG a named rotated outcome. EVERY exit of the rotated lane
    /// goes through here (or sets m_last_rotated directly for the two
    /// non-events, dedup and already-ready), so no rotated path can end
    /// without saying which outcome it was.
    void note_rotated(RotatedOutcome o, const std::string& detail)
    {
        m_last_rotated = o;
        LOG_WARNING << "[QC-MEMBERS] rotated lane cause="
                    << rotated_outcome_name(o) << " " << detail;
    }
    bool note_rotated_false(RotatedOutcome o, const std::string& detail)
    {
        note_rotated(o, detail);
        return false;
    }

    struct Key {
        uint8_t llmqType;
        uint256 quorumHash;
        bool operator<(const Key& r) const
        {
            if (llmqType != r.llmqType) return llmqType < r.llmqType;
            return std::memcmp(quorumHash.data(), r.quorumHash.data(), 32) < 0;
        }
        bool operator==(const Key& r) const
        {
            return llmqType == r.llmqType && quorumHash == r.quorumHash;
        }
    };
    struct Pending {
        uint8_t  type{0};
        uint256  quorum_hash;
        uint32_t work_height{0};
        uint256  work_hash;
    };
    /// An outstanding getqrinfo. `sent_at` is what makes "no reply came" a
    /// NAMED, TIMED outcome instead of an entry that sits there forever.
    struct RotatedPending {
        uint32_t cycle_base_height{0};
        int64_t  sent_at{0};
    };

    // #108 prefetch memo: (type<<32 | cycle_base) already walked. Cleared
    // wholesale when it grows past the bound — re-walking a live cycle costs
    // one deduped request(), which the pending/ready maps then absorb.
    static constexpr size_t kPrefetchMemoMax = 4096;
    // Largest mainnet dkgInterval (LLMQ_400_85 = 576). A tip advance larger
    // than this cannot be live-chain progress; it is a headers batch.
    static constexpr uint32_t kMaxDkgInterval = 576;
    std::set<uint64_t> m_prefetched_cycles;
    uint32_t           m_last_prefetch_tip{0};

    // #1176 SLOT-AWARE READINESS memo: the block hash each published rotated
    // slot was derived under, so reconcile_rotated_slots() can detect a reorg
    // that swaps a top-slot header and re-derive instead of stranding it.
    // Bounded by wholesale clear past the cap (128 cycles x 32 slots), the same
    // discipline as m_prefetched_cycles.
    static constexpr size_t kSlotDeriveMemoMax = 4096;
    struct SlotDeriveKey {
        uint8_t  llmqType;
        uint32_t cycle_base_height;
        uint32_t quorum_index;
        bool operator<(const SlotDeriveKey& r) const
        {
            if (llmqType != r.llmqType) return llmqType < r.llmqType;
            if (cycle_base_height != r.cycle_base_height)
                return cycle_base_height < r.cycle_base_height;
            return quorum_index < r.quorum_index;
        }
    };
    std::map<SlotDeriveKey, uint256> m_slot_derived_from;

    const LlmqParamsView* params_for(uint8_t type) const
    {
        for (const auto& p : enabled_llmqs(m_net))
            if (p.type == type) return &p;
        return nullptr;
    }

    uint32_t quorum_members_v20_floor() const
    {
        return m_net == LlmqNetwork::Mainnet ? vendor::kV20FloorMainnet
                                             : vendor::kV20FloorTestnet;
    }

    uint8_t llmq_type_platform() const
    {
        return m_net == LlmqNetwork::Mainnet
            ? vendor::kLlmqTypePlatformMainnet
            : vendor::kLlmqTypePlatformTestnet;
    }

    /// R3 — DIP-4 client verification of a historical full snapshot:
    ///   (a) embedded cbTx is a type-5 CCbTx at the expected work height;
    ///   (b) cbTxMerkleTree proves that cbTx into the PoW-verified work-block
    ///       header's hashMerkleRoot at tx index 0;
    ///   (c) applied-SML merkle root == cbTx.merkleRootMNList.
    /// Returns the verified SML (and fills `cbtx_out`), or std::nullopt.
    std::optional<vendor::CSimplifiedMNList> authenticate_snapshot(
        const vendor::CSimplifiedMNListDiff& diff,
        const std::vector<Key>& keys, vendor::CCbTx& cbtx_out) const
    {
        // Shared with the daemonless MN-set bridge — see historical_sml.hpp.
        // Both consumers authenticate a peer-supplied historical list on the
        // reward path and must do it identically; two copies would be two
        // places for it to rot.
        const uint32_t expect_h =
            keys.empty() ? 0 : expected_work_height(keys.front());
        auto sml = authenticate_historical_snapshot(
            diff, expect_h, m_merkle_root_of_hash, cbtx_out, "QC-MEMBERS");
        if (!sml) {
            LOG_WARNING << "[QC-MEMBERS] " << keys.size()
                        << " quorum(s) fail closed (member set unsourced -> "
                           "those slots refuse, they are NOT null-served)";
        }
        return sml;
    }

    uint32_t expected_work_height(const Key& key) const
    {
        auto pi = m_pending.find(key);
        return pi == m_pending.end() ? 0 : pi->second.work_height;
    }

    void finalize(const Pending& pend, const vendor::CSimplifiedMNList& sml,
                  const vendor::CCbTx& cbtx)
    {
        const LlmqParamsView* p = params_for(pend.type);
        if (p == nullptr) return;

        // R5: the work block's OWN cbTx CL, or the upstream fallback modifier
        // when it is null — GetNonNullCoinbaseChainlock does not walk back.
        std::optional<std::array<uint8_t, vendor::CFinalCommitment::BLS_SIG_SIZE>> clsig;
        if (cbtx.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
            && cbtx.has_best_cl_signature()) {
            clsig = cbtx.bestCLSignature;
        }
        const uint256 modifier = vendor::compute_quorum_modifier(
            pend.type, pend.work_height, clsig, pend.work_hash);

        vendor::QuorumMemberParams qp{p->type, p->size, p->use_rotation,
                                      /*evo_only=*/p->type == llmq_type_platform()};
        auto members = vendor::compute_quorum_members(qp, modifier, sml);
        if (members) {
            insert_ready(Key{pend.type, pend.quorum_hash}, std::move(*members));
            LOG_INFO << "[QC-MEMBERS] READY type=" << static_cast<int>(pend.type)
                     << " quorum=" << pend.quorum_hash.GetHex().substr(0, 16)
                     << " members=" << p->size
                     << (clsig ? "" : " (null-CL fallback modifier)")
                     << " (real-commitment serving ENABLED for this quorum)";
        } else {
            LOG_WARNING << "[QC-MEMBERS] member computation ambiguous for quorum "
                        << pend.quorum_hash.GetHex().substr(0, 16)
                        << " -> fail closed (member set unsourced -> this slot "
                           "refuses, it is NOT null-served)";
        }
    }

    /// Publish ONE slot of an already-computed cycle from the retained sets.
    /// Returns false when the cycle is not retained (never computed, or
    /// FIFO-evicted) — the caller then falls through to request_rotated().
    /// The published bytes are the SAME compute_quorum_members_by_quarter_
    /// rotation output finalize_rotated() published for the other slots; only
    /// the publish TIME differs (the slot's base header arrived later).
    bool try_republish_rotated_slot(const Key& slot_key, uint8_t llmq_type,
                                    const uint256& cycle_hash,
                                    uint32_t cycle_base_height,
                                    uint32_t quorum_index)
    {
        auto it = m_rotated_cycles.find(Key{llmq_type, cycle_hash});
        if (it == m_rotated_cycles.end()) return false;
        // Unreachable in practice: request() bounds quorum_index by
        // signingActiveQuorumCount and the retained vector is exactly that
        // wide — but an out-of-range read on the money path is worth a guard.
        if (quorum_index >= it->second.size()) return false;
        insert_ready(slot_key, std::vector<vendor::MemberOperatorKey>(
                                   it->second[quorum_index]));
        // #1176: this slot is now published under slot_key.quorumHash — record
        // that header so a subsequent reorg of THIS slot is detected too.
        record_slot_derivation(llmq_type, cycle_base_height, quorum_index,
                               slot_key.quorumHash);
        m_last_rotated = RotatedOutcome::kSlotRepublished;
        // Same READY token as finalize_rotated so one grep finds both lanes.
        LOG_INFO << "[QC-MEMBERS] READY type="
                 << static_cast<int>(llmq_type)
                 << " quorum=" << slot_key.quorumHash.GetHex().substr(0, 16)
                 << " members=" << it->second[quorum_index].size()
                 << " outcome="
                 << rotated_outcome_name(RotatedOutcome::kSlotRepublished)
                 << " lane=ROTATED slot=" << quorum_index
                 << " cycle_base=" << cycle_hash.GetHex().substr(0, 16)
                 << " (slot header was not held when the cycle finalized; "
                    "published now from the retained cycle compute)";
        return true;
    }

    /// #1176: record the header a rotated slot was derived under.
    /// FIFO-unbounded but wholesale-cleared past a generous cap, exactly like
    /// m_prefetched_cycles — a slot old enough to fall out can never be reorged
    /// (its cycle is long past any feasible reorg depth), so losing its record
    /// only forgoes reorg-detection that could never have fired.
    void record_slot_derivation(uint8_t type, uint32_t cycle_base_h,
                                uint32_t quorum_index, const uint256& hash)
    {
        const SlotDeriveKey sk{type, cycle_base_h, quorum_index};
        if (m_slot_derived_from.size() >= kSlotDeriveMemoMax
            && m_slot_derived_from.find(sk) == m_slot_derived_from.end())
            m_slot_derived_from.clear();
        m_slot_derived_from[sk] = hash;
    }

    /// #1176 SLOT-AWARE READINESS — the reorg half of the qi=11 wedge fix.
    ///
    /// A rotated slot's MEMBERS are computed from the cycle work blocks
    /// (cycleBase-8, -C-8, …), not from the header at cycleBase+qi — that header
    /// only NAMES the quorum (its quorumHash / m_ready key). So a reorg that
    /// swaps a top-slot header does not change the member set; it changes the
    /// KEY the set must be served under. finalize_rotated() published the set
    /// under the OLD header and memoised the cycle, and no qfcommit for the new
    /// quorum need arrive before its mining window — so the slot strands.
    ///
    /// This walks the per-slot derivation record, and for any slot whose header
    /// on the current chain differs from the one it was published under,
    /// re-publishes the set under the NEW header from the RETAINED cycle compute
    /// — the same bytes finalize_rotated produced, re-keyed. When the retained
    /// compute is gone (FIFO-evicted) it drops the cycle from the prefetch memo
    /// so the qrinfo is re-requested; meanwhile the slot fails closed (refuses),
    /// never serving a set under a hash the chain no longer carries.
    void reconcile_rotated_slots()
    {
        if (m_slot_derived_from.empty()) return;
        // Collect first — the republish mutates m_slot_derived_from.
        std::vector<std::pair<SlotDeriveKey, uint256>> swapped;
        for (const auto& [sk, derived_hash] : m_slot_derived_from) {
            auto cur = m_hash_at_height(sk.cycle_base_height + sk.quorum_index);
            if (!cur || cur->IsNull()) continue;   // header gap: a "not yet"
            if (*cur == derived_hash)     continue;   // unchanged
            swapped.emplace_back(sk, *cur);
        }
        for (const auto& [sk, new_hash] : swapped) {
            const uint64_t cyc_key =
                (static_cast<uint64_t>(sk.llmqType) << 32) | sk.cycle_base_height;
            auto cycle_hash = m_hash_at_height(sk.cycle_base_height);
            if (!cycle_hash || cycle_hash->IsNull()) {
                // The cycle BASE itself moved (a reorg deeper than a top slot):
                // the retained compute is keyed by the old base hash and can no
                // longer be trusted. Re-open the whole cycle for a fresh qrinfo.
                m_prefetched_cycles.erase(cyc_key);
                m_slot_derived_from.erase(sk);
                continue;
            }
            const Key new_slot_key{sk.llmqType, new_hash};
            if (m_ready.count(new_slot_key)) {   // already re-keyed elsewhere
                m_slot_derived_from[sk] = new_hash;
                continue;
            }
            LOG_INFO << "[QC-PREFETCH] reorg swapped a rotated slot header type="
                     << static_cast<int>(sk.llmqType)
                     << " cycle_base_h=" << sk.cycle_base_height
                     << " slot=" << sk.quorum_index
                     << " new=" << new_hash.GetHex().substr(0, 8)
                     << " — re-deriving from the retained cycle compute instead "
                        "of stranding the slot";
            if (!try_republish_rotated_slot(new_slot_key, sk.llmqType,
                                            *cycle_hash, sk.cycle_base_height,
                                            sk.quorum_index)) {
                // Retained compute evicted: re-request the qrinfo. The slot
                // fails closed until the reply lands — never null-served.
                m_prefetched_cycles.erase(cyc_key);
                m_slot_derived_from.erase(sk);
            }
            // On success try_republish_rotated_slot re-recorded the slot under
            // new_hash, so the next reorg of the same slot is detected too.
        }
    }

    /// Retain a cycle's computed member sets (FIFO-bounded). For type 5 one
    /// cycle is 32 sets x 60 members x 49 bytes ~ 94 kB; the default cap of
    /// 8 cycles bounds this under 1 MB across all rotated types.
    void retain_cycle(const Key& ckey,
                      std::vector<std::vector<vendor::MemberOperatorKey>>&& sets)
    {
        if (m_retained_cycles_cap == 0) return;
        if (m_rotated_cycles.find(ckey) == m_rotated_cycles.end()) {
            while (m_rotated_cycles_fifo.size() >= m_retained_cycles_cap) {
                m_rotated_cycles.erase(m_rotated_cycles_fifo.front());
                m_rotated_cycles_fifo.pop_front();
            }
            m_rotated_cycles_fifo.push_back(ckey);
        }
        m_rotated_cycles[ckey] = std::move(sets);
    }

    void erase_rotated_pending(const Key& key)
    {
        m_rotated_pending.erase(key);
        for (auto it = m_rotated_fifo.begin(); it != m_rotated_fifo.end(); ++it) {
            if (*it == key) { m_rotated_fifo.erase(it); break; }
        }
    }

    // Same bound + rationale as reap_if_needed(), for the qrinfo lane. A
    // rotated cycle is 32 slots wide, so far fewer outstanding requests are
    // ever legitimate; an evicted cycle simply stays unsourced, so its slots
    // refuse (fail-safe) — they are never null-served.
    static constexpr size_t kRotatedPendingCap = 8;
    void reap_rotated_if_needed()
    {
        while (m_rotated_pending.size() >= kRotatedPendingCap
               && !m_rotated_fifo.empty()) {
            const Key victim = m_rotated_fifo.front();
            auto it = m_rotated_pending.find(victim);
            if (it != m_rotated_pending.end()) {
                LOG_WARNING << "[QC-MEMBERS] rotated lane cause=pending_cap_evicted"
                            << " type=" << static_cast<int>(victim.llmqType)
                            << " cycle_base_h=" << it->second.cycle_base_height
                            << " value=" << m_rotated_pending.size()
                            << " threshold=" << kRotatedPendingCap
                            << " — oldest outstanding getqrinfo dropped, that "
                               "cycle stays null-serve until re-requested";
                m_rotated_pending.erase(it);
            }
            m_rotated_fifo.pop_front();
        }
    }

    void erase_pending(const Key& key)
    {
        m_pending.erase(key);
        for (auto it = m_pending_fifo.begin(); it != m_pending_fifo.end(); ++it) {
            if (*it == key) { m_pending_fifo.erase(it); break; }
        }
    }

    // Bound outstanding requests: evict the OLDEST pending (and its await
    // membership) once the cap is hit — a dead peer must not grow state
    // forever, and an evicted quorum simply stays unsourced, so its slot
    // refuses (fail-safe) — it is never null-served.
    void reap_if_needed()
    {
        while (m_pending.size() >= kPendingCap && !m_pending_fifo.empty()) {
            const Key victim = m_pending_fifo.front();
            auto pi = m_pending.find(victim);
            if (pi != m_pending.end()) {
                auto ai = m_await.find(pi->second.work_hash);
                if (ai != m_await.end()) {
                    auto& v = ai->second;
                    for (auto it = v.begin(); it != v.end(); ++it) {
                        if (*it == victim) { v.erase(it); break; }
                    }
                    if (v.empty()) m_await.erase(ai);
                }
                m_pending.erase(pi);
            }
            m_pending_fifo.pop_front();
        }
    }

    void insert_ready(const Key& key, std::vector<vendor::MemberOperatorKey>&& v)
    {
        if (m_ready.find(key) == m_ready.end()) {
            m_ready_fifo.push_back(key);
            if (m_ready_fifo.size() > kReadyCap) {
                m_ready.erase(m_ready_fifo.front());
                m_ready_fifo.pop_front();
            }
        }
        m_ready[key] = std::move(v);
    }

    LlmqNetwork      m_net;
    HashAtHeight     m_hash_at_height;
    HeightOfHash     m_height_of_hash;
    MerkleRootOfHash m_merkle_root_of_hash;
    SendGetMnListd   m_send;

    std::map<Key, std::vector<vendor::MemberOperatorKey>> m_ready;
    std::deque<Key> m_ready_fifo;
    std::map<Key, Pending> m_pending;
    std::deque<Key> m_pending_fifo;
    std::map<uint256, std::vector<Key>> m_await;   // work-block hash -> waiters

    SendGetQrInfo                  m_send_qrinfo;
    std::map<Key, RotatedPending>  m_rotated_pending;  // cycle-base key -> when/where
    std::deque<Key>                m_rotated_fifo;
    // Computed member sets of finalized cycles, kept so a slot whose base
    // header arrived AFTER the qrinfo finalized can still be published (the
    // qi=11 wedge fix). dashd needs no such store — utils.cpp:569
    // GetAllQuorumMembers recomputes any quorum from evoDB on cache miss; our
    // compute inputs are transient wire replies, so we retain the OUTPUT.
    static constexpr size_t kRetainedCyclesCapDefault = 8;
    size_t                         m_retained_cycles_cap{kRetainedCyclesCapDefault};
    std::map<Key, std::vector<std::vector<vendor::MemberOperatorKey>>>
                                   m_rotated_cycles;   // cycle-base key -> 32 sets
    std::deque<Key>                m_rotated_cycles_fifo;
    RotatedOutcome                 m_last_rotated{RotatedOutcome::kNone};
    NowSeconds                     m_now{[] {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    }};
};

} // namespace coin
} // namespace dash
