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
/// Any failure -> the pending quorums for that hash FAIL CLOSED (null-serve).
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
/// reply simply populates 32 distinct keys at once.
///
/// DELIBERATE REVERSAL (was: "issue no getqrinfo"): the previous slice left
/// request() silent for rotated types on the reasoning that a live request
/// whose reply could not yet produce a member set is traffic on a money path
/// for no gain. Now that the reply DOES produce the member set, that reasoning
/// inverts and the branch emits. The request is still bounded exactly like the
/// non-rotated one (one outstanding per cycle base, deduped, FIFO-reaped) and
/// is only made for a cycle whose geometry validates locally first.
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
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace dash {
namespace coin {

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
    void request(uint8_t llmq_type, const uint256& quorum_hash)
    {
        const Key key{llmq_type, quorum_hash};
        if (m_ready.count(key) || m_pending.count(key)) return;

        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr) return;                       // unknown type => fail closed
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
            auto rot_base_h = m_height_of_hash(quorum_hash);
            if (!rot_base_h) return;                    // base header not held
            if (p->dkg_interval == 0) return;
            const uint32_t quorum_index = *rot_base_h % p->dkg_interval;
            if (quorum_index >= p->signing_active_quorum_count) return;
            const uint32_t cycle_h = *rot_base_h - quorum_index;
            auto cycle_hash = m_hash_at_height(cycle_h);
            if (!cycle_hash || cycle_hash->IsNull()) return;   // header gap
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
        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr || !p->use_rotation) return false;
        if (!m_send_qrinfo) return false;

        auto base_h = m_height_of_hash(quorum_hash);
        if (!base_h) return false;
        if (p->dkg_interval == 0 || *base_h % p->dkg_interval != 0) return false;
        // Need H-3C to exist: base - 8 - 3*C.
        const uint64_t span = static_cast<uint64_t>(kWorkDiffDepth)
                            + 3ull * p->dkg_interval;
        if (*base_h < span) return false;
        if (*base_h - kWorkDiffDepth < quorum_members_v20_floor()) return false;

        const Key ckey{llmq_type, quorum_hash};
        // ONE outstanding getqrinfo per cycle base: the 32 slots of a cycle all
        // resolve to this same request, and a duplicate would draw a second
        // 600 kB reply that no await matches (the R1 hazard, per-cycle form).
        if (m_rotated_pending.count(ckey)) return true;
        // The cycle's index-0 quorum hash IS the cycle base hash, so a ready
        // cycle needs no re-request.
        if (m_ready.count(ckey)) return true;
        reap_rotated_if_needed();

        m_rotated_pending[ckey] = *base_h;
        m_rotated_fifo.push_back(ckey);
        m_send_qrinfo(std::vector<uint256>{}, quorum_hash, /*extra_share=*/false);
        LOG_INFO << "[QC-MEMBERS] sourcing qrinfo for ROTATED type="
                 << static_cast<int>(llmq_type) << " quorum="
                 << quorum_hash.GetHex().substr(0, 16)
                 << " cycle_base_h=" << *base_h;
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
        vendor::CCbTx probe_cbtx;
        if (info.mnListDiffH.cbTx.type != 5
            || !vendor::parse_cbtx(info.mnListDiffH.cbTx.extra_payload, probe_cbtx)
            || probe_cbtx.nHeight < 0) {
            LOG_WARNING << "[QC-MEMBERS] qrinfo: mnListDiffH carries no usable "
                           "type-5 cbTx — fail closed";
            return std::nullopt;
        }
        const uint64_t h_height = static_cast<uint64_t>(probe_cbtx.nHeight);

        const Key* match = nullptr;
        uint32_t   base_h = 0;
        for (const auto& [key, base] : m_rotated_pending) {
            if (static_cast<uint64_t>(base) == h_height + kWorkDiffDepth) {
                match = &key;
                base_h = base;
                break;
            }
        }
        if (match == nullptr) {
            LOG_WARNING << "[QC-MEMBERS] qrinfo at H=" << h_height
                        << " matches no outstanding rotated request — dropped";
            return std::nullopt;
        }
        const Key key = *match;

        const LlmqParamsView* p = params_for(key.llmqType);
        if (p == nullptr || !p->use_rotation || p->dkg_interval == 0) {
            erase_rotated_pending(key);
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
                LOG_WARNING << "[QC-MEMBERS] qrinfo cycle diff " << i
                            << " deletes " << diffs[i]->deletedMNs.size()
                            << " entries — not a FULL list, fail closed";
                erase_rotated_pending(key);
                return std::nullopt;
            }
            vendor::CCbTx cbtx;
            auto sml = authenticate_historical_snapshot(
                *diffs[i], expect_h, m_merkle_root_of_hash, cbtx, "QC-MEMBERS");
            if (!sml) {
                LOG_WARNING << "[QC-MEMBERS] qrinfo cycle diff " << i
                            << " failed DIP-4 authentication at expected h="
                            << expect_h << " — whole reply fails closed";
                erase_rotated_pending(key);
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
            LOG_WARNING << "[QC-MEMBERS] rotated member computation AMBIGUOUS "
                           "for cycle_base_h=" << in.cycle_base_height
                        << " type=" << static_cast<int>(in.llmq_type)
                        << " -> fail closed (null-serve for the whole cycle)";
            return 0;
        }

        // Each of the 32 quorums in the cycle carries its OWN quorumHash: the
        // block at cycleBase + quorumIndex (DIP-0024). A slot whose header we
        // do not hold yet is simply skipped — it will be re-requested and the
        // ride-the-outstanding dedup will not fire once the cycle is ready,
        // because index 0's key IS the cycle key.
        size_t published = 0;
        for (size_t qi = 0; qi < sets->size(); ++qi) {
            auto qh = m_hash_at_height(in.cycle_base_height
                                       + static_cast<uint32_t>(qi));
            if (!qh || qh->IsNull()) continue;
            insert_ready(Key{in.llmq_type, *qh}, std::move((*sets)[qi]));
            ++published;
        }
        if (published == 0) {
            LOG_WARNING << "[QC-MEMBERS] rotated cycle_base_h="
                        << in.cycle_base_height << " type="
                        << static_cast<int>(in.llmq_type)
                        << " computed " << sets->size() << " member sets but NO "
                           "slot base-block header is held -> nothing published, "
                           "cycle stays null-serve";
        } else {
            LOG_INFO << "[QC-MEMBERS] ROTATED READY type="
                     << static_cast<int>(in.llmq_type) << " cycle_base_h="
                     << in.cycle_base_height << " slots=" << published << "/"
                     << sets->size() << " members=" << p->size
                     << " (real-commitment serving ENABLED for this cycle)";
        }
        return published;
    }

    size_t rotated_pending_count() const { return m_rotated_pending.size(); }

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
                        << " quorum(s) fail closed (null-serve)";
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
                        << " -> fail closed (null-serve)";
        }
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
    // ever legitimate; an evicted cycle simply stays null-serve.
    static constexpr size_t kRotatedPendingCap = 8;
    void reap_rotated_if_needed()
    {
        while (m_rotated_pending.size() >= kRotatedPendingCap
               && !m_rotated_fifo.empty()) {
            m_rotated_pending.erase(m_rotated_fifo.front());
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
    // forever, and an evicted quorum simply stays null-serve (fail-safe).
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

    SendGetQrInfo             m_send_qrinfo;
    std::map<Key, uint32_t>   m_rotated_pending;   // cycle-base key -> cycle base h
    std::deque<Key>           m_rotated_fifo;
};

} // namespace coin
} // namespace dash
