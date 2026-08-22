// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// ───────────────────────────────────────────────────────────────────────────
/// PR-2 FORWARD — the MINED-COMMITMENT store, ported from dashd v23.1.7.
/// ───────────────────────────────────────────────────────────────────────────
///
/// WHAT DASHD DOES THAT WE DID NOT
///
/// dashd learns that an LLMQ commitment has been MINED at the instant it
/// CONNECTS the block that carries the qfcommit tx. `CQuorumBlockProcessor::
/// ProcessBlock` (llmq/blockprocessor.cpp:165) pulls the block's type-6
/// payloads via `GetCommitmentsFromBlock` (:423) and `ProcessCommitment`
/// (:267) writes two records per non-null commitment (:359-368):
///
///     DB_MINED_COMMITMENT                   (llmqType, quorumHash) -> (qc, blockHash)
///     DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT(llmqType, minedHeight) -> quorumBaseHeight
///     …_Q_INDEXED                           (llmqType, qIdx, minedHeight) -> quorumBaseHeight
///
/// Those three are read by `HasMinedCommitment` (:502), `GetMinedCommitment`
/// (:517), `GetMinedCommitmentsUntilBlock` (:529),
/// `GetLastMinedCommitmentsByQuorumIndexUntilBlock` (:571) and
/// `GetMinedAndActiveCommitmentsUntilBlock` (:660) — and, through
/// `GetNumCommitmentsRequired` (:455), they are what decides WHICH type-6
/// commitments a block MUST carry.
///
/// c2pool had no equivalent. `compute_required_qc_slots`
/// (dkg_commitments.hpp:407) answers `has_mined` from the QuorumManager, and
/// the QuorumManager is fed ONLY from mnlistdiff `newQuorums` / qrinfo
/// `lastCommitmentPerIndex` (quorum_manager.hpp:6-21) — a REQUEST/RESPONSE
/// round trip that lands some time after the block did. Until it lands, a
/// slot another miner has already filled still reads "not mined", the slot
/// stays mandatory, we have no verified commitment for it, and the WHOLE
/// height refuses with cause=qc-plan-underivable (node_coin_state.hpp:1314).
///
/// That refusal was 84.3% of the steady-state non-serves on the 12-hour
/// daemonless soak and the only cause with a fat tail (episodes of 512, 302,
/// 283, 249, 194 s). The block that ended each of those episodes had ALREADY
/// been folded by this node — the fact just never reached the gate.
///
/// This file is the missing store. It is fed from OUR OWN block replay: the
/// same parsed bodies the DML fold, the credit pool and the payee queue
/// already consume.
///
/// ───────────────────────────────────────────────────────────────────────────
/// BOTH HALVES — AND THE CODE ENFORCES THE SYMMETRY
/// ───────────────────────────────────────────────────────────────────────────
///
/// `UndoBlock` (llmq/blockprocessor.cpp:383-408) IS now ported — `undo_input`,
/// `undo_block` and `handle_reorg` below. It erases the same records the
/// forward half wrote and gives the slot back to whoever mines next when a
/// block is DISCONNECTED. Without it a reorg would leave a phantom mined
/// record, `has_mined` would answer true for a commitment the new chain never
/// mined, the slot would drop out of the mandatory set, and the template we
/// serve would be short one type-6 tx — `bad-qc-missing`
/// (blockprocessor.cpp:198), i.e. a LOST BLOCK. This is not hypothetical on
/// this fleet: the hotel primary lost 2508008 to a stale payee and orphaned
/// 2517855.
///
/// Because add and remove are now symmetric, the index MAY arm on a live tip —
/// but ONLY when the caller declares it has wired a disconnect handler that
/// drives the undo (`TipPosture.reorg_undo_wired`, `arm()` below). A live tip
/// with no such wiring still gets a named refusal, not a silent gamble: the
/// undo half existing in this file is not the same as a caller actually
/// CALLING it on every reorg, and the guard demands the latter.
/// A second, independent guard runs per block — `process_block()` refuses any
/// height it did not expect next, so the forward store is built by a strictly
/// contiguous walk, and undo unwinds that walk in strict LIFO (dashd
/// DisconnectTip order).
///
/// ───────────────────────────────────────────────────────────────────────────
/// TRUST BOUNDARY
/// ───────────────────────────────────────────────────────────────────────────
///
/// dashd processes commitments from blocks that have already passed full
/// consensus validation, including `CFinalCommitment::Verify` with the real
/// member sets. We are an SPV-shaped node: the equivalent available proof is
/// that the body folds to the PoW-verified header's committed merkle root.
/// `process_block()` re-asserts that itself (`block_body_binds_to_header`,
/// block_producer.hpp:95) instead of trusting its caller — the same
/// defence-in-depth `on_block_connected_impl` applies
/// (coin_state_maintainer.hpp:1120-1129). What this store therefore asserts is
/// "the chain we followed mined this commitment at this height", which is
/// exactly the question `GetNumCommitmentsRequired` asks. It does NOT assert
/// that the commitment's BLS signatures verify: that is
/// `MineableCommitmentCache::verified_for`'s job and it is unchanged, because
/// a commitment we SERVE must be verified, while a commitment that merely
/// makes a slot non-mandatory need only have been mined.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>   // block_body_binds_to_header
#include <impl/dash/coin/dkg_commitments.hpp>  // LlmqParamsView, is_mining_phase
#include <impl/dash/coin/quorum_root.hpp>      // hash_commitment
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// ═══════════════════════════════════════════════════════════════════════════
// Configuration + the arm guard
// ═══════════════════════════════════════════════════════════════════════════

struct MinedCommitmentIndexConfig {
    /// THE FLAG. Default OFF. A default-constructed config refuses to arm, so
    /// nothing reaches this store unless an operator asked for it by name.
    bool        enabled{false};
    LlmqNetwork network{LlmqNetwork::Mainnet};
    /// Retention for the inversed-height indices, in MULTIPLES OF THE ACTIVE
    /// QUOTA per key — never in blocks. dashd keeps them forever in evoDB; we
    /// are in-memory, and every reader takes at most signingActiveQuorumCount
    /// entries per type (per quorumIndex for rotated types), so keeping a few
    /// multiples of that is lossless and bounded. See prune() for why a
    /// height window is the wrong shape here: mainnet's LLMQ_50_60 active
    /// commitments are 775k blocks old and never leave the active set.
    uint16_t    keep_cycles{4};
    /// How many of the most-recently-ingested heights keep a rollback journal
    /// entry (see UndoEntry / handle_reorg). This is the DEPTH the reorg-undo
    /// path can roll back EXACTLY, and it is the same shape as the replay UTXO
    /// fold's undo window (replay_utxo_fold.hpp ships 100): a reorg deeper than
    /// this cannot be rolled back commitment-for-commitment and fails closed
    /// into a cold rebuild. dashd reorgs are 1-2 blocks in practice; 100 is a
    /// wide margin bounded to a few hundred journal entries.
    uint32_t    undo_window{100};
};

/// What the caller declares about the chain position it is feeding from.
/// `live` means: this node follows the network tip, so a DISCONNECT can
/// happen and the missing `UndoBlock` half would matter.
///
/// The field is a DECLARATION, not a guess. Production derives it from
/// structure (is a live-tip lane feeding this consumer?), never from a
/// heuristic like "the tip looks old".
struct TipPosture {
    bool        live{true};
    /// Set only when the caller has wired dashd's UndoBlock half — a
    /// disconnect handler that calls handle_reorg() (or undo_input/undo_block)
    /// so a branch switch rolls the store back exactly. This is what makes a
    /// LIVE tip safe to arm: without it a disconnected block would leave a
    /// phantom mined record. It is a DECLARATION about the wiring, read off
    /// structure (is a reorg handler installed for this store?), never guessed.
    bool        reorg_undo_wired{false};
    /// Names WHO declared it. Reproduced verbatim in the refusal so the
    /// operator can see which wiring decided, not just that something did.
    std::string declared_by{"unspecified"};
};

struct MinedIndexArmVerdict {
    bool        armed{false};
    std::string reason;   // always populated, on success too
};

/// Per-block outcome. Every non-Applied value NAMES a dashd rejection code
/// where one exists, so a refusal here reads the same as the one the daemon
/// would have produced.
enum class MinedIngestResult : uint8_t {
    Applied = 0,
    NotArmed,            // arm() was never called, or refused
    NonContiguous,       // forward-only walk violated
    BodyNotBound,        // body merkle root != header commitment
    BadQcPayload,        // dashd "bad-qc-payload"          (:434)
    BadQcCommitmentType, // dashd "bad-qc-commitment-type"  (:440)
    BadQcDupInBlock,     // dashd "bad-qc-dup"              (:448)
    BadQcDupMined,       // dashd "bad-qc-dup"              (:322)
    BadQcHeight,         // dashd "bad-qc-height"           (:327)
    BadQcBlock,          // dashd "bad-qc-block"            (:303/:311)
    BaseUnresolvable,    // LookupBlockIndex(qc.quorumHash) == nullptr (:333)
};

inline const char* mined_ingest_result_name(MinedIngestResult r)
{
    switch (r) {
        case MinedIngestResult::Applied:             return "applied";
        case MinedIngestResult::NotArmed:            return "not-armed";
        case MinedIngestResult::NonContiguous:       return "non-contiguous";
        case MinedIngestResult::BodyNotBound:        return "body-not-bound";
        case MinedIngestResult::BadQcPayload:        return "bad-qc-payload";
        case MinedIngestResult::BadQcCommitmentType: return "bad-qc-commitment-type";
        case MinedIngestResult::BadQcDupInBlock:     return "bad-qc-dup";
        case MinedIngestResult::BadQcDupMined:       return "bad-qc-dup";
        case MinedIngestResult::BadQcHeight:         return "bad-qc-height";
        case MinedIngestResult::BadQcBlock:          return "bad-qc-block";
        case MinedIngestResult::BaseUnresolvable:    return "quorum-base-unresolvable";
    }
    return "n/a";
}

/// Per-disconnect outcome for the UndoBlock port (undo_input / undo_block /
/// handle_reorg). Every non-Undone value NAMES why the rollback could not be
/// applied, so a refusal here is as legible as a forward refusal.
enum class MinedUndoResult : uint8_t {
    Undone = 0,
    NotArmed,             // arm() was never called, or refused
    NotTip,               // dashd disconnects the TIP only (DisconnectTip)
    BeyondUndoWindow,     // reorg deeper than the retained journal => cold rebuild
    BodyNotBound,         // undo_block: body merkle root != header commitment
    BadQcPayload,         // undo_block: type-6 payload unparseable
    BadQcCommitmentType,  // llmqType not in this network's chainparams llmq list
};

inline const char* mined_undo_result_name(MinedUndoResult r)
{
    switch (r) {
        case MinedUndoResult::Undone:              return "undone";
        case MinedUndoResult::NotArmed:            return "not-armed";
        case MinedUndoResult::NotTip:              return "not-tip";
        case MinedUndoResult::BeyondUndoWindow:    return "beyond-undo-window";
        case MinedUndoResult::BodyNotBound:        return "body-not-bound";
        case MinedUndoResult::BadQcPayload:        return "bad-qc-payload";
        case MinedUndoResult::BadQcCommitmentType: return "bad-qc-commitment-type";
    }
    return "n/a";
}

/// One DB_MINED_COMMITMENT record + the two inversed-height values.
struct MinedCommitmentRecord {
    vendor::CFinalCommitment commitment;
    uint256  mined_block_hash;      // dashd DB value .second
    uint32_t mined_height{0};
    uint32_t quorum_base_height{0}; // dashd inversed-height value
    int16_t  quorum_index{0};
};

/// Parsed per-block input — the same shape QuorumReplayEngine's
/// QuorumBlockInput has, and for the same reason: KATs and lanes that have
/// ALREADY bound the body to its header feed the parsed form, while
/// `process_block()` is the BODY entry point that does the binding check
/// itself. Whoever calls `process_input()` owns that proof.
struct MinedBlockInput {
    uint32_t height{0};
    uint256  block_hash;
    /// The block's type-6 payloads in tx order, nulls INCLUDED — the store
    /// applies dashd's IsNull skip itself, because "the DKG failed here" and
    /// "nothing was mined here" must not be conflated.
    std::vector<vendor::CFinalCommitment> commitments;
};

// ═══════════════════════════════════════════════════════════════════════════
// The store
// ═══════════════════════════════════════════════════════════════════════════

class MinedCommitmentIndex
{
public:
    /// height -> block hash of OUR chain (the `GetBlockHash(active_chain, …)`
    /// GetQuorumBlockHash reads, blockprocessor.cpp:487).
    using HashAtHeightFn = std::function<std::optional<uint256>(uint32_t)>;

    explicit MinedCommitmentIndex(MinedCommitmentIndexConfig cfg)
        : m_cfg(std::move(cfg)) {}

    // ── Arming ───────────────────────────────────────────────────────────

    /// THE GUARD. Refuses when the flag is off, and refuses when the node's
    /// tip is LIVE — because the forward half alone is only self-consistent
    /// on a chain that never disconnects a block.
    MinedIndexArmVerdict arm(const TipPosture& posture)
    {
        MinedIndexArmVerdict v;
        if (!m_cfg.enabled) {
            v.reason =
                "mined-commitment index NOT armed: the feature flag is off "
                "(MinedCommitmentIndexConfig.enabled). Default-OFF is the "
                "money-path posture — arming it changes which type-6 "
                "commitments a served template is required to carry.";
            m_armed = false;
            m_arm_reason = v.reason;
            return v;
        }
        if (posture.live && !posture.reorg_undo_wired) {
            v.reason =
                "mined-commitment index REFUSED TO ARM: the node's tip is "
                "LIVE (declared by " + posture.declared_by + ") and NO "
                "reorg-undo handler is wired. dashd's UndoBlock "
                "(v23.1.7 llmq/blockprocessor.cpp:383-408) is ported here "
                "(undo_input/undo_block + handle_reorg), but the CALLER must "
                "install a disconnect handler that drives it and declare "
                "TipPosture.reorg_undo_wired. Until then a disconnected block "
                "would leave a phantom mined record; has_mined_commitment() "
                "would answer true for a commitment the new chain never mined, "
                "the slot would drop out of the mandatory set, and the served "
                "template would be short one qfcommit => bad-qc-missing "
                "(blockprocessor.cpp:198) => LOST BLOCK. Arm this on a "
                "replay/backfill consumer, or wire the undo handler first.";
            m_armed = false;
            m_arm_reason = v.reason;
            return v;
        }
        v.armed  = true;
        v.reason = posture.live
            ? ("mined-commitment index ARMED on a LIVE tip: dashd's UndoBlock "
               "(v23.1.7 llmq/blockprocessor.cpp:383-408) is ported "
               "(undo_input/undo_block + handle_reorg), so a disconnected "
               "block is rolled back exactly. Reorg-undo declared wired by "
               + posture.declared_by + ".")
            : ("mined-commitment index ARMED (forward-only; tip declared NOT "
               "live by " + posture.declared_by + ")");
        m_armed = true;
        m_arm_reason = v.reason;
        return v;
    }

    bool               armed() const      { return m_armed; }
    const std::string& arm_reason() const { return m_arm_reason; }

    /// Declare the cursor: the store is AT `height`; the next observable
    /// block is height+1. Mirrors the replay engines' seed_cursor().
    void seed_cursor(uint32_t height)
    {
        m_height = height;
        m_seeded = true;
    }

    uint32_t height() const { return m_height; }
    bool     seeded() const { return m_seeded; }

    // ── ProcessBlock — the forward port ──────────────────────────────────

    /// Port of `CQuorumBlockProcessor::ProcessBlock`'s STORE half
    /// (blockprocessor.cpp:165) — `GetCommitmentsFromBlock` (:423) followed by
    /// `ProcessCommitment`'s DB writes (:359-368) — with dashd's own
    /// rejections in dashd's own order. NOT ported here, deliberately:
    ///   * the BLS aggregate `qc.Verify` (:339) — see the TRUST BOUNDARY note;
    ///   * the `GetNumCommitmentsRequired` completeness checks (:194-201),
    ///     which are the VALIDATOR's job and are already modelled on the serve
    ///     side by compute_required_qc_slots;
    ///   * `PreComputeQuorumMembers` (:175), a cache warm-up with no store
    ///     effect.
    ///
    /// `err`, when non-null, receives a sentence naming the height, the
    /// offending commitment and the dashd code — a refusal that leaves no
    /// trace is indistinguishable from a block that carried nothing.
    MinedIngestResult process_block(uint32_t height, const uint256& block_hash,
                                    const BlockType& block,
                                    const HashAtHeightFn& hash_at_height,
                                    std::string* err = nullptr)
    {
        auto fail = [&](MinedIngestResult r, const std::string& why) {
            if (err)
                *err = "h=" + std::to_string(height) + " "
                     + mined_ingest_result_name(r) + ": " + why;
            ++m_stats.blocks_refused;
            return r;
        };
        // Trust boundary (see header note): the BODY entry point asserts the
        // binding itself rather than trusting its caller.
        if (!block_body_binds_to_header(block))
            return fail(MinedIngestResult::BodyNotBound,
                        "body merkle root != header commitment — a forged or "
                        "mutated body must never write a mined record");

        // ── GetCommitmentsFromBlock (blockprocessor.cpp:423-459) ─────────
        MinedBlockInput in;
        in.height     = height;
        in.block_hash = block_hash;
        std::map<uint8_t, size_t> per_type_count;
        for (size_t i = 0; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.type != vendor::CFinalCommitmentTxPayload::SPECIALTX_TYPE)
                continue;   // upstream: `tx->nType == TRANSACTION_QUORUM_COMMITMENT`
            vendor::CFinalCommitmentTxPayload payload;
            if (!vendor::parse_qfcommit_payload(tx.extra_payload, payload))
                return fail(MinedIngestResult::BadQcPayload,
                            "tx[" + std::to_string(i) + "] type-6 payload is "
                            "unparseable (upstream GetTxPayload failure)");
            const LlmqParamsView* p =
                params_for(payload.commitment.llmqType);
            if (p == nullptr)
                return fail(MinedIngestResult::BadQcCommitmentType,
                            "tx[" + std::to_string(i) + "] names llmqType "
                            + std::to_string(int(payload.commitment.llmqType))
                            + ", which is not in this network's chainparams "
                              "llmq list");
            // "only allow one commitment per type and per block (This was
            // changed with rotation)" — blockprocessor.cpp:445-450.
            if (!p->use_rotation && ++per_type_count[p->type] > 1)
                return fail(MinedIngestResult::BadQcDupInBlock,
                            "a second non-rotated type-"
                            + std::to_string(int(p->type))
                            + " commitment in one block");
            in.commitments.push_back(std::move(payload.commitment));
        }
        return process_input(in, hash_at_height, err);
    }

    /// The PARSED entry point. Same store writes, same dashd rejections; the
    /// body↔header binding is the CALLER's proof here (see MinedBlockInput).
    MinedIngestResult process_input(const MinedBlockInput& in,
                                    const HashAtHeightFn& hash_at_height,
                                    std::string* err = nullptr)
    {
        const uint32_t height = in.height;
        auto fail = [&](MinedIngestResult r, const std::string& why) {
            if (err)
                *err = "h=" + std::to_string(height) + " "
                     + mined_ingest_result_name(r) + ": " + why;
            ++m_stats.blocks_refused;
            return r;
        };
        if (!m_armed)
            return fail(MinedIngestResult::NotArmed, m_arm_reason);
        if (!m_seeded || height != m_height + 1)
            return fail(MinedIngestResult::NonContiguous,
                        "the store is at h=" + std::to_string(m_height)
                        + (m_seeded ? "" : " (NO seeded cursor)")
                        + " and this port is forward-only — only h="
                        + std::to_string(m_height + 1) + " is ingestible. "
                        "The reorg-undo half rolls the TIP back (handle_reorg); "
                        "it never fills a forward gap, so a skipped height must "
                        "be refused, not silently absorbed.");
        // Re-assert the per-block dup rule on the parsed path too: a caller
        // that assembled the input itself must not be able to smuggle two
        // non-rotated commitments of one type past bad-qc-dup.
        {
            std::map<uint8_t, size_t> per_type_count;
            for (const auto& qc : in.commitments) {
                const LlmqParamsView* p = params_for(qc.llmqType);
                if (p == nullptr)
                    return fail(MinedIngestResult::BadQcCommitmentType,
                                "llmqType " + std::to_string(int(qc.llmqType))
                                + " is not in this network's chainparams llmq"
                                  " list");
                if (!p->use_rotation && ++per_type_count[p->type] > 1)
                    return fail(MinedIngestResult::BadQcDupInBlock,
                                "a second non-rotated type-"
                                + std::to_string(int(p->type))
                                + " commitment in one block");
            }
        }
        const auto& qcs = in.commitments;
        const uint256& block_hash = in.block_hash;

        // ── ProcessCommitment, per commitment (blockprocessor.cpp:267) ────
        // Staged: nothing is written until EVERY commitment in the block has
        // passed. dashd gets atomicity from the evoDB transaction that
        // ConnectBlock rolls back on failure; a half-written block here would
        // be exactly the phantom record the missing undo half cannot repair.
        std::vector<MinedCommitmentRecord> staged;
        for (const auto& qc : qcs) {
            const LlmqParamsView* p = params_for(qc.llmqType);
            // GetQuorumBlockHash (:487): base = nHeight − nHeight%dkgInterval
            //                                    + quorumIndex
            const uint32_t base_h = height - (height % p->dkg_interval)
                                  + static_cast<uint32_t>(qc.quorumIndex);
            auto base_hash = hash_at_height ? hash_at_height(base_h)
                                            : std::nullopt;
            if (!base_hash || base_hash->IsNull())
                // Upstream returns uint256() here and ProcessCommitment then
                // rejects bad-qc-block (:303).
                return fail(MinedIngestResult::BadQcBlock,
                            "quorum base height " + std::to_string(base_h)
                            + " has no known block hash on our chain");
            if (*base_hash != qc.quorumHash)
                // blockprocessor.cpp:311 — quorumHash != qc.quorumHash.
                return fail(MinedIngestResult::BadQcBlock,
                            "commitment names quorumHash "
                            + qc.quorumHash.GetHex().substr(0, 16)
                            + "... but our chain has "
                            + base_hash->GetHex().substr(0, 16)
                            + "... at base height " + std::to_string(base_h));
            // blockprocessor.cpp:310-320: a NULL commitment is accepted and
            // written NOWHERE. Not folding it is the whole reason
            // has_mined_commitment() can be trusted: a null means the DKG
            // failed, the quorum does NOT exist, and the slot must stay
            // mandatory for whoever mines next.
            if (is_null_commitment(qc)) {
                ++m_stats.commitments_null;
                continue;
            }
            // blockprocessor.cpp:322 — bad-qc-dup.
            if (has_mined_commitment(qc.llmqType, qc.quorumHash))
                return fail(MinedIngestResult::BadQcDupMined,
                            "type=" + std::to_string(int(qc.llmqType))
                            + " quorum "
                            + qc.quorumHash.GetHex().substr(0, 16)
                            + "... is already recorded as mined at h="
                            + std::to_string(
                                  m_mined.at(key_of(qc.llmqType, qc.quorumHash))
                                      .mined_height));
            // blockprocessor.cpp:327 — bad-qc-height.
            if (!is_mining_phase(*p, height))
                return fail(MinedIngestResult::BadQcHeight,
                            "h=" + std::to_string(height) + " is outside the "
                            "type-" + std::to_string(int(p->type))
                            + " DKG mining window ["
                            + std::to_string(p->mining_window_start) + ","
                            + std::to_string(p->mining_window_end)
                            + "] of interval "
                            + std::to_string(p->dkg_interval));

            MinedCommitmentRecord rec;
            rec.commitment        = qc;
            rec.mined_block_hash  = block_hash;
            rec.mined_height      = height;
            rec.quorum_base_height = base_h;
            rec.quorum_index      = qc.quorumIndex;
            staged.push_back(std::move(rec));
        }

        // ── The two writes (blockprocessor.cpp:359-368) ──────────────────
        // The rollback journal records, per height, EXACTLY the keys these
        // writes touched, so handle_reorg can erase them without re-supplying
        // the body — dashd re-parses the disconnected CBlock in UndoBlock; we
        // keep a compact per-height journal instead, the same shape the replay
        // UTXO fold keeps a BlockUndo (replay_utxo_fold.hpp).
        UndoEntry undo;
        undo.block_hash = block_hash;
        undo.writes.reserve(staged.size());
        for (auto& rec : staged) {
            const LlmqParamsView* p = params_for(rec.commitment.llmqType);
            const uint8_t t = rec.commitment.llmqType;
            const IndexValue v{rec.quorum_base_height,
                               rec.commitment.quorumHash};
            if (p->use_rotation)
                m_by_height_indexed[t][rec.quorum_index][rec.mined_height] = v;
            else
                m_by_height[t][rec.mined_height] = v;
            m_mined[key_of(t, rec.commitment.quorumHash)] = rec;
            undo.writes.push_back(UndoWrite{t, rec.commitment.quorumHash,
                                            rec.quorum_index, p->use_rotation});
            ++m_stats.commitments_mined;
        }
        m_undo_journal[height] = std::move(undo);
        trim_undo_journal();

        m_height = height;
        ++m_stats.blocks_ingested;
        prune(height);
        if (err) err->clear();
        return MinedIngestResult::Applied;
    }

    // ── UndoBlock — the symmetric reorg port ─────────────────────────────

    /// Port of `CQuorumBlockProcessor::UndoBlock`'s STORE half
    /// (v23.1.7 llmq/blockprocessor.cpp:383-408). dashd, on DisconnectBlock,
    /// re-reads the disconnected block's commitments via GetCommitmentsFromBlock
    /// (:391), skips nulls (:394), and for every non-null one ERASES the two
    /// records ProcessCommitment wrote — DB_MINED_COMMITMENT by (llmqType,
    /// quorumHash) (:399) and the inversed-height key at THIS block's height
    /// (:402-406) — then re-offers the commitment as mineable (:408). This is
    /// the exact inverse of process_input's two writes.
    ///
    /// NOT ported here, symmetrically to the forward half:
    ///   * AddMineableCommitment (:408) — re-offering a disconnected commitment
    ///     as mineable is MineableCommitmentCache's job, unchanged; this store
    ///     only owns the MINED question. Erasing the mined record is already
    ///     enough for compute_required_qc_slots to re-mandate the slot.
    ///   * PreComputeQuorumMembers (:387) — a cache warm-up with no store effect.
    ///
    /// dashd only ever disconnects the TIP (DisconnectTip walks the active
    /// chain back one block at a time), so undo is LIFO: `in.height` must be the
    /// current cursor. That is the same invariant that makes the forward walk
    /// contiguous, run backwards.
    MinedUndoResult undo_input(const MinedBlockInput& in, std::string* err = nullptr)
    {
        auto fail = [&](MinedUndoResult r, const std::string& why) {
            if (err)
                *err = "h=" + std::to_string(in.height) + " "
                     + mined_undo_result_name(r) + ": " + why;
            ++m_stats.blocks_undo_refused;
            return r;
        };
        if (!m_armed)
            return fail(MinedUndoResult::NotArmed, m_arm_reason);
        if (!m_seeded || in.height != m_height)
            return fail(MinedUndoResult::NotTip,
                        "UndoBlock disconnects the TIP only (dashd "
                        "DisconnectTip). The store cursor is at h="
                        + std::to_string(m_height)
                        + (m_seeded ? "" : " (NO seeded cursor)")
                        + " — only that height is disconnectable.");
        // GetCommitmentsFromBlock + the null skip (blockprocessor.cpp:391-394):
        // build the erase list from the body, exactly as the forward path built
        // the write list.
        std::vector<UndoWrite> writes;
        for (const auto& qc : in.commitments) {
            const LlmqParamsView* p = params_for(qc.llmqType);
            if (p == nullptr)
                return fail(MinedUndoResult::BadQcCommitmentType,
                            "llmqType " + std::to_string(int(qc.llmqType))
                            + " is not in this network's chainparams llmq list");
            if (is_null_commitment(qc))
                continue;   // dashd: `if (qc.IsNull()) continue;` (:394)
            writes.push_back(UndoWrite{qc.llmqType, qc.quorumHash,
                                       qc.quorumIndex, p->use_rotation});
        }
        erase_writes_at(in.height, writes);
        m_undo_journal.erase(in.height);
        m_height = in.height - 1;
        ++m_stats.blocks_disconnected;
        if (err) err->clear();
        return MinedUndoResult::Undone;
    }

    /// The BODY entry point for undo — mirror of process_block. Re-parses the
    /// disconnected block's type-6 payloads (the GetCommitmentsFromBlock half
    /// of dashd's UndoBlock) and asserts the body binds to its header, then
    /// hands the parsed commitments to undo_input. Whoever has the disconnected
    /// body uses this; the live reorg path, which does not retain bodies, uses
    /// handle_reorg (journal-driven) instead.
    MinedUndoResult undo_block(uint32_t height, const uint256& block_hash,
                               const BlockType& block, std::string* err = nullptr)
    {
        auto fail = [&](MinedUndoResult r, const std::string& why) {
            if (err)
                *err = "h=" + std::to_string(height) + " "
                     + mined_undo_result_name(r) + ": " + why;
            ++m_stats.blocks_undo_refused;
            return r;
        };
        if (!block_body_binds_to_header(block))
            return fail(MinedUndoResult::BodyNotBound,
                        "body merkle root != header commitment — a forged or "
                        "mutated body must never drive an erase either");
        MinedBlockInput in;
        in.height     = height;
        in.block_hash = block_hash;
        for (size_t i = 0; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.type != vendor::CFinalCommitmentTxPayload::SPECIALTX_TYPE)
                continue;
            vendor::CFinalCommitmentTxPayload payload;
            if (!vendor::parse_qfcommit_payload(tx.extra_payload, payload))
                return fail(MinedUndoResult::BadQcPayload,
                            "tx[" + std::to_string(i) + "] type-6 payload is "
                            "unparseable");
            in.commitments.push_back(std::move(payload.commitment));
        }
        return undo_input(in, err);
    }

    /// The LIVE reorg driver. A branch switch disconnects every tip block that
    /// is no longer on the (already-switched) chain. This walks the cursor
    /// DOWN, and at each height compares the journal's recorded block hash
    /// against `hash_at_height` (the new chain): the FIRST height that still
    /// matches is the fork point, and everything above it is rolled back from
    /// the journal — no disconnected body needed. It is the exact analogue of
    /// the credit-pool axis's fork-point search (coin_state_maintainer.hpp), and
    /// dashd's per-block DisconnectTip loop expressed over the retained journal.
    ///
    /// A reorg deeper than the retained undo window cannot be rolled back
    /// exactly; this refuses BeyondUndoWindow and the caller must
    /// clear_for_cold_rebuild() (mirrors on_sml_reorg's cold-resync) — the
    /// fail-CLOSED direction: an empty store over-mandates slots, it never
    /// serves a phantom.
    MinedUndoResult handle_reorg(const HashAtHeightFn& hash_at_height,
                                 std::string* err = nullptr)
    {
        auto fail = [&](MinedUndoResult r, const std::string& why) {
            if (err)
                *err = mined_undo_result_name(r) + std::string(": ") + why;
            ++m_stats.blocks_undo_refused;
            return r;
        };
        if (!m_armed)
            return fail(MinedUndoResult::NotArmed, m_arm_reason);
        while (m_seeded && m_height > 0) {
            auto jit = m_undo_journal.find(m_height);
            if (jit == m_undo_journal.end())
                return fail(MinedUndoResult::BeyondUndoWindow,
                            "reorg is deeper than the retained undo window ("
                            + std::to_string(m_cfg.undo_window)
                            + " blocks): no journal entry for tip h="
                            + std::to_string(m_height)
                            + ". The store cannot roll back exactly and must be "
                              "cold-rebuilt (clear_for_cold_rebuild + re-seed).");
            auto on_chain = hash_at_height ? hash_at_height(m_height)
                                           : std::nullopt;
            if (on_chain && !on_chain->IsNull()
                && *on_chain == jit->second.block_hash)
                break;   // fork point: this tip block is still on the new chain
            erase_writes_at(m_height, jit->second.writes);
            m_undo_journal.erase(jit);
            --m_height;
            ++m_stats.blocks_disconnected;
        }
        if (err) err->clear();
        return MinedUndoResult::Undone;
    }

    /// Fail-closed reset for a reorg beyond the undo window (or any axis that
    /// invalidated the store). Empties every record and drops the cursor, so
    /// process_input refuses until the caller re-seeds and re-seeds the cursor —
    /// the same cold-resync contract on_sml_reorg gives the SML axis. The arm
    /// verdict and config are kept.
    void clear_for_cold_rebuild()
    {
        m_mined.clear();
        m_by_height.clear();
        m_by_height_indexed.clear();
        m_undo_journal.clear();
        m_seeded = false;
        m_height = 0;
        ++m_stats.cold_rebuilds;
    }

    // ── Readers ──────────────────────────────────────────────────────────

    /// `CQuorumBlockProcessor::HasMinedCommitment` (blockprocessor.cpp:502).
    bool has_mined_commitment(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        return m_mined.count(key_of(llmq_type, quorum_hash)) != 0;
    }

    /// `CQuorumBlockProcessor::GetMinedCommitment` (blockprocessor.cpp:517).
    /// nullopt where upstream returns the default-constructed pair.
    std::optional<MinedCommitmentRecord>
    get_mined_commitment(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        auto it = m_mined.find(key_of(llmq_type, quorum_hash));
        if (it == m_mined.end()) return std::nullopt;
        return it->second;
    }

    /// `CQuorumBlockProcessor::GetMinedCommitmentsUntilBlock`
    /// (blockprocessor.cpp:529). Upstream seeks the INVERSED-height key so a
    /// forward LevelDB scan walks mined heights DESCENDING; an ordered map
    /// walked in reverse is the same traversal. Returns QUORUM BASE HEIGHTS,
    /// most-recently-mined first — upstream returns the CBlockIndex* of that
    /// base, which we have no equivalent of.
    std::vector<uint32_t> mined_commitments_until_block(uint8_t llmq_type,
                                                        uint32_t height,
                                                        size_t max_count) const
    {
        std::vector<uint32_t> ret;
        for (const auto* r : mined_records_until_block(llmq_type, height,
                                                       max_count))
            ret.push_back(r->quorum_base_height);
        return ret;
    }

    /// The same walk, returning the RECORDS. Upstream hands back
    /// CBlockIndex* and lets the caller re-read the commitment from evoDB;
    /// we have no block index, and every consumer that wants the base height
    /// also wants the commitment (merkleRootQuorums is a fold over
    /// commitments), so the walk yields records and
    /// mined_commitments_until_block projects the base height out of them.
    std::vector<const MinedCommitmentRecord*>
    mined_records_until_block(uint8_t llmq_type, uint32_t height,
                              size_t max_count) const
    {
        std::vector<const MinedCommitmentRecord*> ret;
        auto tit = m_by_height.find(llmq_type);
        if (tit == m_by_height.end()) return ret;
        ret.reserve(max_count);
        const auto& by_h = tit->second;
        // upper_bound(height) then walk backwards == "the greatest mined
        // height <= height, descending" == upstream's inversed-key forward
        // scan.
        for (auto it = by_h.upper_bound(height);
             it != by_h.begin() && ret.size() < max_count;) {
            --it;
            if (const auto* r = record_for(llmq_type, it->second.quorum_hash))
                ret.push_back(r);
        }
        return ret;
    }

    /// `CQuorumBlockProcessor::GetLastMinedCommitmentsByQuorumIndexUntilBlock`
    /// (blockprocessor.cpp:571). `cycle` counts backwards from the most
    /// recently mined commitment for that quorumIndex (0 = the latest).
    std::optional<uint32_t> last_mined_commitment_by_quorum_index_until_block(
        uint8_t llmq_type, uint32_t height, int16_t quorum_index,
        size_t cycle) const
    {
        if (const auto* r = last_mined_record_by_quorum_index_until_block(
                llmq_type, height, quorum_index, cycle))
            return r->quorum_base_height;
        return std::nullopt;
    }

    const MinedCommitmentRecord* last_mined_record_by_quorum_index_until_block(
        uint8_t llmq_type, uint32_t height, int16_t quorum_index,
        size_t cycle) const
    {
        auto tit = m_by_height_indexed.find(llmq_type);
        if (tit == m_by_height_indexed.end()) return nullptr;
        auto iit = tit->second.find(quorum_index);
        if (iit == tit->second.end()) return nullptr;
        const auto& by_h = iit->second;
        size_t current = 0;
        for (auto it = by_h.upper_bound(height); it != by_h.begin();) {
            --it;
            if (current == cycle)
                return record_for(llmq_type, it->second.quorum_hash);
            ++current;
        }
        return nullptr;
    }

    /// `CQuorumBlockProcessor::GetLastMinedCommitmentsPerQuorumIndexUntilBlock`
    /// (blockprocessor.cpp:620). Upstream SKIPS indices with no commitment
    /// (`if (q.has_value())`), so the result can be shorter than
    /// signingActiveQuorumCount — reproduced, because a shorter active set is
    /// exactly what a partially-mined cycle looks like.
    std::vector<uint32_t> last_mined_commitments_per_quorum_index_until_block(
        uint8_t llmq_type, uint32_t height, size_t cycle) const
    {
        std::vector<uint32_t> ret;
        for (const auto* r : last_mined_records_per_quorum_index_until_block(
                 llmq_type, height, cycle))
            ret.push_back(r->quorum_base_height);
        return ret;
    }

    std::vector<const MinedCommitmentRecord*>
    last_mined_records_per_quorum_index_until_block(uint8_t llmq_type,
                                                    uint32_t height,
                                                    size_t cycle) const
    {
        std::vector<const MinedCommitmentRecord*> ret;
        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr) return ret;
        for (uint16_t qi = 0; qi < p->signing_active_quorum_count; ++qi) {
            if (const auto* r = last_mined_record_by_quorum_index_until_block(
                    llmq_type, height, static_cast<int16_t>(qi), cycle))
                ret.push_back(r);
        }
        return ret;
    }

    /// `CQuorumBlockProcessor::GetMinedAndActiveCommitmentsUntilBlock`
    /// (blockprocessor.cpp:660) — THE ACTIVE SET, per chainparams llmq type.
    /// Rotated types take the latest commitment PER quorumIndex (cycle 0),
    /// non-rotated types the last `signingActiveQuorumCount` mined. Values are
    /// quorum base heights.
    std::map<uint8_t, std::vector<uint32_t>>
    mined_and_active_commitments_until_block(uint32_t height) const
    {
        std::map<uint8_t, std::vector<uint32_t>> ret;
        for (const auto& p : chainparams_llmqs()) {
            ret[p.type] = p.use_rotation
                ? last_mined_commitments_per_quorum_index_until_block(
                      p.type, height, /*cycle=*/0)
                : mined_commitments_until_block(
                      p.type, height, p.signing_active_quorum_count);
        }
        return ret;
    }

    /// The same active set as RECORDS, flattened across types. This is what
    /// evo/cbtx.cpp CalcCbTxMerkleRootQuorums folds: every active
    /// commitment's SerializeHash, sorted, SHA256d-merkled. The KATs use it
    /// to re-derive real mainnet blocks' committed merkleRootQuorums from
    /// this store alone.
    std::vector<const MinedCommitmentRecord*>
    active_records_until_block(uint32_t height) const
    {
        std::vector<const MinedCommitmentRecord*> ret;
        for (const auto& p : chainparams_llmqs()) {
            auto part = p.use_rotation
                ? last_mined_records_per_quorum_index_until_block(
                      p.type, height, /*cycle=*/0)
                : mined_records_until_block(p.type, height,
                                            p.signing_active_quorum_count);
            ret.insert(ret.end(), part.begin(), part.end());
        }
        return ret;
    }

    /// Anchor seed for the PRE-replay active set (the Phase-1 trust class the
    /// replay design already defines). A forward replay starting at a modern
    /// anchor cannot observe commitments mined before it — on mainnet that
    /// includes LLMQ_50_60's last 24, frozen since DIP0024 and still in
    /// dashd's active set forever. Ordering among seeded entries uses the
    /// QUORUM BASE height as the mined-height proxy: within one llmq type a
    /// cycle's mining window closes before the next cycle starts, so mined
    /// order is monotone in base height (the same argument
    /// dkg_commitments.hpp's oldest-leaf eviction rests on). Seeded entries
    /// are given mined heights BELOW the cursor so any genuinely replayed
    /// commitment always outranks them.
    ///
    /// Returns false (and touches nothing) when the type is not in this
    /// network's chainparams list, or the commitment is null — a null was
    /// never a mined quorum and must not become one by way of a seed.
    bool seed_mined_commitment(uint32_t quorum_base_height,
                               const vendor::CFinalCommitment& c,
                               std::string& err)
    {
        const LlmqParamsView* p = params_for(c.llmqType);
        if (p == nullptr) {
            err = "seed names llmqType " + std::to_string(int(c.llmqType))
                + ", not in this network's chainparams llmq list";
            return false;
        }
        if (is_null_commitment(c)) {
            err = "seed is a NULL commitment — a failed DKG is not a mined "
                  "quorum";
            return false;
        }
        MinedCommitmentRecord rec;
        rec.commitment         = c;
        rec.quorum_base_height = quorum_base_height;
        rec.quorum_index       = c.quorumIndex;
        // Below every replayable height, order-preserving in base height.
        rec.mined_height       = quorum_base_height;
        const IndexValue v{quorum_base_height, c.quorumHash};
        if (p->use_rotation)
            m_by_height_indexed[c.llmqType][c.quorumIndex][rec.mined_height] = v;
        else
            m_by_height[c.llmqType][rec.mined_height] = v;
        m_mined[key_of(c.llmqType, c.quorumHash)] = std::move(rec);
        ++m_stats.commitments_seeded;
        return true;
    }

    // ── Observability ────────────────────────────────────────────────────

    struct Stats {
        uint64_t blocks_ingested{0};
        uint64_t blocks_refused{0};
        uint64_t commitments_mined{0};
        uint64_t commitments_null{0};
        uint64_t commitments_seeded{0};
        uint64_t blocks_disconnected{0};   // UndoBlock port: heights rolled back
        uint64_t commitments_erased{0};    // mined records removed by undo
        uint64_t blocks_undo_refused{0};   // undo/reorg refusals
        uint64_t cold_rebuilds{0};         // clear_for_cold_rebuild() calls
    };
    const Stats& stats() const { return m_stats; }
    size_t       size() const  { return m_mined.size(); }

    /// How far each chainparams type is from the FULL active quota at
    /// `height` — the criterion that decides whether a set reconstructed by a
    /// forward scan IS dashd's set. Empty => complete.
    ///
    /// This is the honest half of issue #90: on mainnet LLMQ_50_60 stopped
    /// being mined at DIP0024 (~h 1738698) yet its last 24 commitments stay in
    /// dashd's active set FOREVER (upstream walks the CHAINPARAMS list, not
    /// the enabled one — replay_quorum_engine.hpp SCOPE GATES). A forward
    /// replay seeded at a modern anchor can NEVER observe them from blocks, so
    /// this method will report type 1 short by 24 forever unless those
    /// commitments are seeded from elsewhere. A counter that cannot become
    /// complete must SAY it cannot, not read zero in silence.
    std::vector<std::pair<uint8_t, size_t>>
    active_set_shortfall(uint32_t height) const
    {
        std::vector<std::pair<uint8_t, size_t>> out;
        const auto active = mined_and_active_commitments_until_block(height);
        for (const auto& p : chainparams_llmqs()) {
            const size_t have = active.at(p.type).size();
            if (have < p.signing_active_quorum_count)
                out.emplace_back(p.type,
                                 p.signing_active_quorum_count - have);
        }
        return out;
    }

    /// One sentence an operator can read: armed?, cursor, store size, and the
    /// per-type shortfall by name.
    std::string summary() const
    {
        std::string s = "[QC-MINED-INDEX] armed="
                      + std::string(m_armed ? "1" : "0")
                      + " cursor_h=" + std::to_string(m_height)
                      + " mined=" + std::to_string(m_mined.size())
                      + " blocks=" + std::to_string(m_stats.blocks_ingested)
                      + " refused=" + std::to_string(m_stats.blocks_refused)
                      + " nulls=" + std::to_string(m_stats.commitments_null)
                      + " disconnected="
                      + std::to_string(m_stats.blocks_disconnected);
        if (!m_armed) return s + " reason=\"" + m_arm_reason + "\"";
        const auto miss = active_set_shortfall(m_height);
        if (miss.empty()) return s + " active_set=COMPLETE";
        s += " active_set=INCOMPLETE short=";
        for (size_t i = 0; i < miss.size(); ++i) {
            if (i) s += ",";
            s += "type" + std::to_string(int(miss[i].first)) + ":"
               + std::to_string(miss[i].second);
        }
        return s;
    }

    /// dashd `CFinalCommitment::IsNull` (llmq/commitment.cpp): no signers and
    /// no valid members. Exposed because the same predicate decides whether a
    /// commitment is folded into merkleRootQuorums
    /// (dkg_commitments.hpp compute_merkle_root_quorums_with_block).
    static bool is_null_commitment(const vendor::CFinalCommitment& c)
    {
        return c.CountSigners() == 0 && c.CountValidMembers() == 0;
    }

private:
    /// One erased key for the rollback journal — enough to invert the two
    /// writes without the disconnected body: which map (rotation) and which
    /// keys (type, quorumHash, quorumIndex). The mined height is the journal
    /// key itself.
    struct UndoWrite {
        uint8_t  llmq_type{0};
        uint256  quorum_hash;
        int16_t  quorum_index{0};
        bool     rotation{false};
    };
    /// Per-height rollback record: the block hash this height ingested (the
    /// fork-point discriminator handle_reorg compares against the new chain)
    /// plus every mined record written at it.
    struct UndoEntry {
        uint256                block_hash;
        std::vector<UndoWrite> writes;
    };

    const std::vector<LlmqParamsView>& chainparams_llmqs() const
    {
        // The CHAINPARAMS list, not the runtime-enabled one: upstream's
        // GetMinedAndActiveCommitmentsUntilBlock iterates
        // Params().GetConsensus().llmqs (blockprocessor.cpp:664). Mainnet
        // therefore includes LLMQ_50_60 even though it is no longer mineable.
        static const std::vector<LlmqParamsView> kMainnet{
            kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67};
        static const std::vector<LlmqParamsView> kTestnet{
            kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67,
            kLlmq25_67};
        return m_cfg.network == LlmqNetwork::Mainnet ? kMainnet : kTestnet;
    }

    const LlmqParamsView* params_for(uint8_t type) const
    {
        for (const auto& p : chainparams_llmqs())
            if (p.type == type) return &p;
        return nullptr;
    }

    static std::string key_of(uint8_t type, const uint256& qh)
    {
        std::string k;
        k.push_back(static_cast<char>(type));
        k.append(reinterpret_cast<const char*>(qh.data()), 32);
        return k;
    }

    const MinedCommitmentRecord* record_for(uint8_t type,
                                            const uint256& qh) const
    {
        auto it = m_mined.find(key_of(type, qh));
        return it == m_mined.end() ? nullptr : &it->second;
    }

    /// The inverse of process_input's two writes, for one height. Removes the
    /// DB_MINED_COMMITMENT record by (type, quorumHash) and the inversed-height
    /// entry at `height` — exactly what dashd's UndoBlock erases. Erasing a key
    /// prune() already dropped is a harmless no-op, which is why undo is
    /// prune-independent: the journal, not the count-bounded inversed indices,
    /// is the authority on what a height wrote.
    void erase_writes_at(uint32_t height, const std::vector<UndoWrite>& writes)
    {
        for (const auto& w : writes) {
            m_mined.erase(key_of(w.llmq_type, w.quorum_hash));
            if (w.rotation) {
                auto it = m_by_height_indexed.find(w.llmq_type);
                if (it != m_by_height_indexed.end()) {
                    auto qit = it->second.find(w.quorum_index);
                    if (qit != it->second.end()) qit->second.erase(height);
                }
            } else {
                auto it = m_by_height.find(w.llmq_type);
                if (it != m_by_height.end()) it->second.erase(height);
            }
            ++m_stats.commitments_erased;
        }
    }

    /// Keep only the last `undo_window` heights of rollback journal. Bounds the
    /// journal exactly as prune() bounds the inversed indices — the reorg depth
    /// beyond this is fail-closed in handle_reorg, never silently unrepairable.
    void trim_undo_journal()
    {
        while (m_undo_journal.size() > m_cfg.undo_window)
            m_undo_journal.erase(m_undo_journal.begin());
    }

    /// Bound the in-memory inversed-height indices BY COUNT, never by height.
    ///
    /// This was a height-based window first, and it was WRONG in a way the
    /// 3101-block mainnet KAT caught immediately: mainnet's LLMQ_50_60 active
    /// commitments were mined around h≈1738xxx and are STILL in dashd's active
    /// set at h≈2513686 — 775k blocks later, forever, because the type stopped
    /// being mined at DIP0024 but GetMinedAndActiveCommitmentsUntilBlock keeps
    /// walking the chainparams list (blockprocessor.cpp:664). Any height window
    /// short enough to be worth having drops them, and the derived
    /// merkleRootQuorums silently loses 24 leaves.
    ///
    /// Age is not the bound; RANK is. Every reader takes at most
    /// signingActiveQuorumCount entries per type (per quorumIndex for rotated
    /// types), so keeping a multiple of that per key is lossless for them and
    /// still bounded — a few hundred entries on mainnet.
    ///
    /// The DB_MINED_COMMITMENT map itself is NEVER pruned: has_mined_commitment
    /// must stay true for the life of the run (dashd erases it only in
    /// UndoBlock), and it is bounded by the number of quorums the chain mines.
    void prune(uint32_t)
    {
        auto trim = [](std::map<uint32_t, IndexValue>& by_h, size_t keep) {
            while (by_h.size() > keep) by_h.erase(by_h.begin());
        };
        for (auto& [t, by_h] : m_by_height) {
            const LlmqParamsView* p = params_for(t);
            if (p == nullptr) continue;
            trim(by_h, keep_per_key(p->signing_active_quorum_count));
        }
        for (auto& [t, by_idx] : m_by_height_indexed) {
            const LlmqParamsView* p = params_for(t);
            if (p == nullptr) continue;
            for (auto& [qi, by_h] : by_idx)
                trim(by_h, keep_per_key(1));
        }
    }

    size_t keep_per_key(size_t quota) const
    {
        const size_t k = static_cast<size_t>(m_cfg.keep_cycles) * quota;
        return k < quota ? quota : k;
    }

    /// The inversed-height index VALUE. dashd stores just the quorum base
    /// height (blockprocessor.cpp:363-367) and re-reads the commitment from
    /// DB_MINED_COMMITMENT via the block index; we have no block index, so
    /// the quorumHash rides along as the key back into m_mined. The base
    /// height is still the value every ported reader returns.
    struct IndexValue {
        uint32_t base_height{0};
        uint256  quorum_hash;
    };

    MinedCommitmentIndexConfig m_cfg;
    bool        m_armed{false};
    std::string m_arm_reason{"arm() has not been called"};
    bool        m_seeded{false};
    uint32_t    m_height{0};
    Stats       m_stats;

    // DB_MINED_COMMITMENT: (llmqType, quorumHash) -> record
    std::map<std::string, MinedCommitmentRecord> m_mined;
    // DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT: type -> minedHeight -> value
    std::map<uint8_t, std::map<uint32_t, IndexValue>> m_by_height;
    // …_Q_INDEXED: type -> quorumIndex -> minedHeight -> value
    std::map<uint8_t, std::map<int16_t, std::map<uint32_t, IndexValue>>>
        m_by_height_indexed;
    // Rollback journal for the UndoBlock port: minedHeight -> UndoEntry,
    // bounded to the last undo_window heights (trim_undo_journal).
    std::map<uint32_t, UndoEntry> m_undo_journal;
};

} // namespace coin
} // namespace dash
