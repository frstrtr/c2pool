// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ── W5 INTEGRATION SEAM: W2's block lane drives W1's DML fold ──────────────
//
// W2 (replay_bulk_fetch.hpp) fetches bodies across the peer pool, verifies
// each against the PoW-pinned header hash and the committed hashMerkleRoot,
// delivers them IN ORDER through IReplayBlockConsumer, and PRUNES them. W1
// (replay_fold_engine.hpp) folds a block into the deterministic masternode
// list and self-checks the result against that block's own committed cbTx
// merkleRootMNList. This class is the seam between them: it is the thing
// that makes a bulk fetch actually PROVE something.
//
// THE PROOF, per block, with no trusted input other than the anchor:
//
//     computed merkleRootMNList  ==  cbTx.merkleRootMNList
//
// The right-hand side is committed by miners inside the block we just
// verified binds to its own header; the left-hand side is folded from our
// own replayed state. A run of N consecutive byte-exact matches is N
// consecutive independent confirmations that our DML equals dashd's — which
// is the entire daemonless-DASH claim.
//
// ── Failure discipline ────────────────────────────────────────────────────
//
// A root mismatch POISONS the fold engine (W1's rule: serving from a state
// that has already diverged is the one unforgivable outcome). This consumer
// keeps that stickiness and adds the reporting the run needs: the FIRST
// divergence height, its computed/committed pair, and the fold counters at
// that block. A divergence is a FINDING to be reported precisely, not a
// crash — so on_replay_block returns false to stop the lane advancing rather
// than aborting the process, and everything measured up to that point stays
// readable.
//
// ── Optional lanes ────────────────────────────────────────────────────────
//
//   * W4 (replay_quorum_engine.hpp) is wired through the MembersFn seam that
//     W1 already exposes, so qfcommit PoSe punishes are attributed from
//     REPLAYED quorum membership rather than captured fixtures. Absent, W1
//     fails closed at the first non-null commitment (by design).
//   * W3 (replay_utxo_fold.hpp) is a Tier-B decoration: the same block is
//     handed to the UTXO fold when one is installed. Its gate is a
//     hash_serialized_2 match at a chosen height, which is independent of
//     the DML root chain and must never be able to fail the Tier-A proof.

#include <impl/dash/coin/replay_bulk_fetch.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>

#include <core/log.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <string>

namespace dash {
namespace coin {
namespace replay {

/// Live counters for the run report — read while the lane is running.
struct FoldConsumerStats
{
    uint64_t blocks_folded{0};      // folds that completed without error
    uint64_t roots_matched{0};      // THE proof counter
    uint64_t blocks_skipped{0};     // below the anchor, already folded
    uint32_t first_height{0};       // first height actually folded
    uint32_t last_height{0};        // highest height folded

    // The merkleRootMNList of the LAST block whose self-check passed — the
    // root the folded list hashed to at `last_height`, as committed by that
    // block's own cbTx. Retained so a downstream consumer of the folded list
    // can RE-DERIVE the root from the state it is about to use and compare it
    // against the chain's answer key, rather than trusting the counters above.
    // Null until the first match.
    uint256 last_matched_root;

    // Aggregated transition counters (diagnostics, not consensus).
    uint64_t registered{0};
    uint64_t updated{0};
    uint64_t revoked{0};
    uint64_t revived{0};
    uint64_t punished{0};
    uint64_t banned{0};
    uint64_t collateral_spent{0};

    // The W4 seam (replay_quorum_bridge.hpp), when installed.
    uint64_t    quorum_lane_refusals{0};
    uint32_t    first_quorum_refusal_height{0};
    std::string first_quorum_refusal;

    // The finding, if any.
    bool        diverged{false};
    uint32_t    divergence_height{0};
    std::string computed_root;      // display hex
    std::string committed_root;     // display hex
    std::string divergence_reason;  // the fold's own sentence, verbatim
};

/// Folds every block the bulk lane delivers and self-checks its root.
class FoldReplayConsumer : public IReplayBlockConsumer
{
public:
    /// `engine` must already be SEEDED at the anchor (see replay_prestate.hpp
    /// seed_engine_from_prestate, which re-verifies the anchor root) — this
    /// class never seeds, so it can never paper over a bad anchor.
    /// `utxo_sink` is the optional Tier-B decoration.
    using UtxoSink = std::function<bool(uint32_t, const uint256&,
                                        const BlockType&)>;

    explicit FoldReplayConsumer(DmlFoldEngine& engine,
                                UtxoSink utxo_sink = {},
                                uint32_t progress_every = 100)
        : m_engine(engine)
        , m_utxo_sink(std::move(utxo_sink))
        , m_progress_every(progress_every ? progress_every : 100)
        , m_started(std::chrono::steady_clock::now())
    {}

    /// ── The W4 seam (replay_quorum_bridge.hpp) ───────────────────────────
    /// `pre_fold` runs BEFORE the DML fold of the same block: that is where
    /// the quorum lane observes the block and derives any member cycle whose
    /// base is this height, so the fold's punish pass can resolve members
    /// from REPLAYED state. `post_fold` runs after a successful fold, where
    /// the just-folded list is retained for work-block lookups.
    ///
    /// A pre_fold refusal is NOT a divergence and must never be reported as
    /// one: it means the quorum lane could not observe this block, so the
    /// fold loses its member sets and will fail closed on its own terms at
    /// the first commitment that actually needs them — with ITS name for the
    /// blocking condition, not ours. It is recorded and logged; the fold
    /// still runs.
    using BlockHook = std::function<std::string(uint32_t, const uint256&,
                                                const BlockType&)>;
    void set_pre_fold(BlockHook h)  { m_pre_fold = std::move(h); }
    void set_post_fold(std::function<void(uint32_t)> h)
    {
        m_post_fold = std::move(h);
    }

    bool on_replay_block(uint32_t height, const uint256& hash,
                         const BlockType& block) override
    {
        // Already-folded / pre-anchor deliveries are a NO-OP, not an error:
        // the lane's resumable cursor and the anchor seed are independent,
        // so a restart legitimately re-offers blocks the engine has passed.
        if (height <= m_engine.height()) {
            ++m_stats.blocks_skipped;
            return true;
        }
        if (m_stats.diverged) return false;   // sticky, never fold past it

        if (m_pre_fold) {
            const std::string qerr = m_pre_fold(height, hash, block);
            if (!qerr.empty()) {
                ++m_stats.quorum_lane_refusals;
                if (m_stats.first_quorum_refusal.empty()) {
                    m_stats.first_quorum_refusal_height = height;
                    m_stats.first_quorum_refusal = qerr;
                }
                LOG_WARNING << "[REPLAY-FOLD] quorum lane refused h=" << height
                            << ": " << qerr
                            << " — the DML fold continues and will fail "
                               "closed at the first commitment that needs a "
                               "member set";
            }
        }

        const auto r = m_engine.fold_block(block, height);
        if (!r.ok) {
            // The fold names its own blocking condition; keep it VERBATIM.
            m_stats.diverged          = true;
            m_stats.divergence_height = height;
            m_stats.divergence_reason = r.error;
            m_stats.computed_root     = r.computed_root.GetHex();
            m_stats.committed_root    = r.committed_root.GetHex();
            LOG_ERROR << "[REPLAY-FOLD] ✗ h=" << height << " block "
                      << hash.GetHex().substr(0, 16) << " — " << r.error;
            LOG_ERROR << "[REPLAY-FOLD]   computed  merkleRootMNList = "
                      << m_stats.computed_root;
            LOG_ERROR << "[REPLAY-FOLD]   committed merkleRootMNList = "
                      << m_stats.committed_root;
            LOG_ERROR << "[REPLAY-FOLD]   FIRST DIVERGENCE after "
                      << m_stats.roots_matched
                      << " consecutive byte-exact root checks (h="
                      << m_stats.first_height << ".." << m_stats.last_height
                      << ")";
            return false;
        }

        // fold_block only returns ok when the self-check passed, but the
        // proof counter is incremented on the OBSERVED equality, never on a
        // flag someone could flip: the whole point is the byte comparison.
        if (r.computed_root != r.committed_root) {
            m_stats.diverged          = true;
            m_stats.divergence_height = height;
            m_stats.divergence_reason =
                "fold reported ok but computed root != committed root "
                "(W1 self-check invariant violated)";
            m_stats.computed_root  = r.computed_root.GetHex();
            m_stats.committed_root = r.committed_root.GetHex();
            LOG_ERROR << "[REPLAY-FOLD] ✗ h=" << height << " "
                      << m_stats.divergence_reason;
            return false;
        }

        if (m_stats.blocks_folded == 0) m_stats.first_height = height;
        ++m_stats.blocks_folded;
        ++m_stats.roots_matched;
        m_stats.last_height       = height;
        // Recorded from the OBSERVED equality above, so it is the block's own
        // committed root and our own computed root at once.
        m_stats.last_matched_root = r.committed_root;
        m_stats.registered       += r.registered;
        m_stats.updated          += r.updated;
        m_stats.revoked          += r.revoked;
        m_stats.revived          += r.revived;
        m_stats.punished         += r.punished;
        m_stats.banned           += r.banned;
        m_stats.collateral_spent += r.collateral_spent;

        if (m_post_fold) m_post_fold(height);

        if (m_utxo_sink && !m_utxo_sink(height, hash, block)) {
            // Tier-B is a DECORATION: its failure is reported but must never
            // invalidate the Tier-A root chain that already passed here.
            LOG_WARNING << "[REPLAY-FOLD] Tier-B UTXO sink refused h="
                        << height << " — DML root chain is unaffected";
        }

        if (height % m_progress_every == 0) {
            const auto secs = elapsed_seconds();
            LOG_INFO << "[REPLAY-FOLD] h=" << height
                     << " roots-matched=" << m_stats.roots_matched
                     << " mns=" << m_engine.size()
                     << " reg=" << m_stats.registered
                     << " ban=" << m_stats.banned
                     << " punish=" << m_stats.punished
                     << " spent=" << m_stats.collateral_spent
                     << " (" << secs << "s, "
                     << (secs > 0
                            ? static_cast<double>(m_stats.blocks_folded) / secs
                            : 0.0)
                     << " blk/s)";
        }
        return true;
    }

    const FoldConsumerStats& stats() const { return m_stats; }
    const DmlFoldEngine&     engine() const { return m_engine; }

    uint64_t elapsed_seconds() const
    {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - m_started).count());
    }

    /// One-line, greppable run summary — the deliverable of a replay.
    std::string summary() const
    {
        const auto secs = elapsed_seconds();
        std::string s =
            "[REPLAY-FOLD SUMMARY] folded=" + std::to_string(m_stats.blocks_folded)
            + " roots_matched=" + std::to_string(m_stats.roots_matched)
            + " range=" + std::to_string(m_stats.first_height) + ".."
            + std::to_string(m_stats.last_height)
            + " mns=" + std::to_string(m_engine.size())
            + " wall=" + std::to_string(secs) + "s"
            + " reg=" + std::to_string(m_stats.registered)
            + " upd=" + std::to_string(m_stats.updated)
            + " rev=" + std::to_string(m_stats.revoked)
            + " revive=" + std::to_string(m_stats.revived)
            + " punish=" + std::to_string(m_stats.punished)
            + " ban=" + std::to_string(m_stats.banned)
            + " spent=" + std::to_string(m_stats.collateral_spent);
        if (m_stats.quorum_lane_refusals)
            s += " quorum_lane_refusals="
               + std::to_string(m_stats.quorum_lane_refusals)
               + " first_at=" + std::to_string(m_stats.first_quorum_refusal_height);
        if (m_stats.diverged)
            s += " DIVERGED_AT=" + std::to_string(m_stats.divergence_height)
               + " computed=" + m_stats.computed_root
               + " committed=" + m_stats.committed_root
               + " reason=\"" + m_stats.divergence_reason + "\"";
        else
            s += " DIVERGED=none";
        return s;
    }

private:
    DmlFoldEngine&    m_engine;
    UtxoSink          m_utxo_sink;
    BlockHook         m_pre_fold;
    std::function<void(uint32_t)> m_post_fold;
    uint32_t          m_progress_every;
    FoldConsumerStats m_stats;
    std::chrono::steady_clock::time_point m_started;
};

/// ── THE LAST MILE: live tip blocks finish what the bulk lane started ──────
///
/// FOUND BY THE FIRST LIVE SEAM RUN. The W2 bulk lane fetches the heights its
/// peers announced when it planned, delivers them, and goes idle:
///
///     [BULK] delivered=2516911/2516911 rate=0blk/s inflight=0 hdr=joined
///
/// while our own PoW-validated header chain had moved on to h=2516923. The
/// fold therefore parked 12 blocks short of the tip — permanently — and any
/// consumer with a currency requirement could never be satisfied.
///
/// The node already HAS those blocks: the tip lane connects each one and fires
/// block_connected. The only thing missing was contiguity in time — a live
/// block for h=2516915 arrives while the fold is still down at h=2515000, and
/// the forward-contiguous fold cannot take it *yet*. So hold it, and drain the
/// moment the fold catches up.
///
/// Deliberately NOT a fetcher: it never asks the network for anything, it only
/// keeps what the node was already handed. A block it does not receive is a
/// gap it reports rather than papers over — the fold stays behind, and
/// whatever guards currency keeps refusing.
class FoldLiveTail
{
public:
    /// `cap` bounds the hold. Overflow drops the HIGHEST buffered height, not
    /// the lowest: the lowest is the one the fold needs next, and dropping it
    /// would break the contiguity that makes the drain safe. A fold far enough
    /// behind to overflow is a fold that must keep failing its currency check
    /// anyway — that is the honest outcome, not a reason to skip blocks.
    /// `bulk_floor` is an EXCLUSIVE floor: the highest height the bulk lane
    /// still owns (its delivered high-water and its fetch ceiling, whichever
    /// is greater). The tail touches NOTHING at or below it.
    ///
    /// That floor is not politeness, it is correctness. The first attempt had
    /// no floor and folded whatever arrived on block_connected — which also
    /// carries the checkpoint bridge's own historical replay. The fold then
    /// advanced through heights the bulk lane had not delivered, the W4 quorum
    /// lane lost the cycles it derives from the bulk ordering, and the run
    /// died at h=2512821 with "quorum-member resolver has no member set".
    /// The tail exists to close the gap the bulk lane LEAVES, never to race it.
    using HeightFn = std::function<uint32_t()>;

    FoldLiveTail(FoldReplayConsumer& consumer, const DmlFoldEngine& engine,
                 HeightFn bulk_floor, size_t cap = 512)
        : m_consumer(consumer)
        , m_engine(engine)
        , m_bulk_floor(std::move(bulk_floor))
        , m_cap(cap ? cap : 512)
    {}

    /// Offer a connected block. Heights at or below the fold cursor are a
    /// no-op (the bulk lane already folded them); higher ones are held and the
    /// buffer is drained contiguously.
    void offer(uint32_t height, const BlockType& block)
    {
        if (height <= m_engine.height()) return;
        if (height <= floor()) return;      // the bulk lane still owns it
        ++m_offered;
        auto [it, inserted] = m_held.emplace(height, block);
        if (!inserted) return;                       // already holding it
        if (m_held.size() > m_cap) {
            m_held.erase(std::prev(m_held.end()));   // drop the HIGHEST
            ++m_dropped;
        }
        drain();
    }

    /// Fold every held block the engine can take, in order. Also called after
    /// the bulk lane advances the cursor, so a hold that became contiguous
    /// without a new arrival still lands.
    void drain()
    {
        for (;;) {
            // Discard anything the bulk lane folded while we held it.
            while (!m_held.empty() && m_held.begin()->first <= m_engine.height())
                m_held.erase(m_held.begin());
            if (m_held.empty()) return;
            const uint32_t want = m_engine.height() + 1;
            // Never fold a height the bulk lane is still going to deliver:
            // its ordering is what the W4 quorum lane derives membership from.
            if (want <= floor()) return;
            auto it = m_held.find(want);
            if (it == m_held.end()) return;          // still a gap; wait
            // The REAL block hash, not a placeholder: the quorum lane keys
            // derived member cycles by it.
            const bool ok = m_consumer.on_replay_block(
                want, DmlFoldEngine::block_header_hash(it->second), it->second);
            m_held.erase(it);
            ++m_folded_live;
            if (!ok) {
                // A live block that fails the fold is exactly as fatal as a
                // replayed one — the consumer has already recorded the
                // divergence and the engine is poisoned. Stop; do not try the
                // next height on top of a poisoned state.
                LOG_ERROR << "[REPLAY-TAIL] live block h=" << want
                          << " FAILED the fold — the fold is now poisoned and"
                             " no further block will be folded from either lane";
                return;
            }
        }
    }

    uint32_t bulk_floor()  const { return floor(); }
    size_t   held()        const { return m_held.size(); }
    uint64_t folded_live() const { return m_folded_live; }
    uint64_t offered()     const { return m_offered; }
    uint64_t dropped()     const { return m_dropped; }
    uint32_t lowest_held() const
    {
        return m_held.empty() ? 0u : m_held.begin()->first;
    }

private:
    uint32_t floor() const { return m_bulk_floor ? m_bulk_floor() : 0u; }

    FoldReplayConsumer&               m_consumer;
    const DmlFoldEngine&              m_engine;
    HeightFn                          m_bulk_floor;
    size_t                            m_cap;
    std::map<uint32_t, BlockType>     m_held;
    uint64_t m_folded_live{0};
    uint64_t m_offered{0};
    uint64_t m_dropped{0};
};

} // namespace replay
} // namespace coin
} // namespace dash
