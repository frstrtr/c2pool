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

    // Aggregated transition counters (diagnostics, not consensus).
    uint64_t registered{0};
    uint64_t updated{0};
    uint64_t revoked{0};
    uint64_t revived{0};
    uint64_t punished{0};
    uint64_t banned{0};
    uint64_t collateral_spent{0};

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
        m_stats.last_height = height;
        m_stats.registered       += r.registered;
        m_stats.updated          += r.updated;
        m_stats.revoked          += r.revoked;
        m_stats.revived          += r.revived;
        m_stats.punished         += r.punished;
        m_stats.banned           += r.banned;
        m_stats.collateral_spent += r.collateral_spent;

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
    uint32_t          m_progress_every;
    FoldConsumerStats m_stats;
    std::chrono::steady_clock::time_point m_started;
};

} // namespace replay
} // namespace coin
} // namespace dash
