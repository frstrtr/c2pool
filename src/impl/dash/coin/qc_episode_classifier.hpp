// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// [QC-EPISODE] — terminal-event classifier for `qc-plan-underivable`
/// episodes (docs/DASH_NULL_COMMITMENT_ARM_DESIGN.md §8, recommendation 1).
///
/// Every qc-plan-underivable episode — a contiguous run of DKG-window heights
/// refused because a mandatory type-6 slot has no BLS-verified real
/// commitment — ends in exactly one of three ways:
///
///   * `real-arrived`      — the qfcommit flood delivered the real commitment
///                           (the MineableCommitmentCache gained it and the
///                           slot is served real);
///   * `real-mined`        — another miner mined it (`has_mined` flipped: the
///                           mnlistdiff-fed QuorumManager now holds the
///                           quorum, so the slot left the mandatory set);
///   * `window-closed-null`— the DKG mining window closed with NO real
///                           commitment ever seen — the network mined null to
///                           the end. This is the ONLY case dashd's
///                           null-commitment arm would have recovered.
///
/// The class-3 wall-clock total is the standing measurement that decides
/// whether the null arm (deferred by the design's §8 benefit accounting:
/// measured benefit today is zero) is ever worth building. Pure logging
/// policy: no I/O, no clock of its own (the caller passes monotonic
/// seconds), no coin state — the terminal class is derived from facts the
/// caches already hold at RESUME time, queried by the caller. Header-only so
/// it folds into the already-allowlisted dash test targets.
///
/// SCOPE: only slot-shaped refusals (a named gap slot) start an episode.
/// A plan that is underivable for structural reasons — header gap, below the
/// serve floor — is not a commitment wait and neither starts nor ends one.
/// An episode may progress across slots (slot A resolves, slot B still
/// blocks): the blocking slot is updated on every underivable observation
/// and the terminal event is classified against the LAST blocker — the slot
/// whose fact-flip actually ended the episode.

#include <core/uint256.hpp>

#include <cstdint>
#include <optional>

namespace dash {
namespace coin {

class QcEpisodeClassifier {
public:
    enum class Terminal : uint8_t {
        RealArrived,       ///< flood delivered: the cache gained the commitment
        RealMined,         ///< another miner mined it: has_mined flipped
        WindowClosedNull,  ///< window closed, no real commitment ever seen
        /// The honest name for a resolution none of the three facts explains
        /// (e.g. a reorg re-keyed the slot's base hash mid-window). Never
        /// silently mapped onto a real class — state says its own name.
        Unclassified,
    };

    static const char* terminal_name(Terminal t)
    {
        switch (t) {
            case Terminal::RealArrived:      return "real-arrived";
            case Terminal::RealMined:        return "real-mined";
            case Terminal::WindowClosedNull: return "window-closed-null";
            case Terminal::Unclassified:     return "unclassified";
        }
        return "unclassified";
    }

    /// The slot currently blocking the active episode — what the caller must
    /// query its caches about before calling observe_derivable().
    struct PendingSlot {
        uint8_t  llmq_type{0};
        int16_t  quorum_index{0};
        uint256  quorum_hash;
        uint32_t window_last_height{0};  ///< cycleStart + dkgMiningWindowEnd
    };

    /// One finished episode — everything the [QC-EPISODE] line prints.
    struct Ended {
        Terminal terminal{Terminal::Unclassified};
        int64_t  duration_sec{0};
        uint8_t  llmq_type{0};
        int16_t  quorum_index{0};
        uint256  quorum_hash;
        uint32_t first_height{0};    ///< first refused height of the episode
        uint32_t resumed_height{0};  ///< the height whose plan derived
    };

    /// Feed one underivable observation with its classified gap slot. Starts
    /// an episode if none is active; otherwise updates the blocking slot to
    /// the CURRENT one (see SCOPE note above). Cheap enough for the
    /// per-template plan path.
    void observe_underivable(uint32_t next_h, uint8_t llmq_type,
                             int16_t quorum_index, const uint256& quorum_hash,
                             uint32_t window_last_height, int64_t now_sec)
    {
        if (!m_active) {
            m_active       = true;
            m_started_sec  = now_sec;
            m_first_height = next_h;
        }
        m_slot.llmq_type          = llmq_type;
        m_slot.quorum_index       = quorum_index;
        m_slot.quorum_hash        = quorum_hash;
        m_slot.window_last_height = window_last_height;
    }

    bool active() const { return m_active; }

    /// The slot to interrogate the caches about, or std::nullopt when no
    /// episode is active.
    std::optional<PendingSlot> pending() const
    {
        if (!m_active) return std::nullopt;
        return m_slot;
    }

    /// Feed one derivable observation (the plan derived — the episode, if
    /// any, RESUMEs here). The two facts are queried BY THE CALLER for the
    /// pending() slot at resume time:
    ///   cache_has_commitment : MineableCommitmentCache holds a commitment
    ///                          for the slot (the flood delivered it);
    ///   has_mined            : the QuorumManager holds the quorum (another
    ///                          miner mined the commitment).
    /// Classification, in order: cache_has_commitment => real-arrived (the
    /// arrival lane worked, even if the network also mined it meanwhile —
    /// the split between the first two classes is diagnostic; only
    /// window-closed-null argues FOR the null arm); else has_mined =>
    /// real-mined; else past the window's last height => window-closed-null;
    /// else the honest `unclassified`. Returns the finished episode exactly
    /// once; std::nullopt when no episode was active.
    std::optional<Ended> observe_derivable(uint32_t next_h,
                                           bool cache_has_commitment,
                                           bool has_mined, int64_t now_sec)
    {
        if (!m_active) return std::nullopt;
        Ended e;
        if (cache_has_commitment)
            e.terminal = Terminal::RealArrived;
        else if (has_mined)
            e.terminal = Terminal::RealMined;
        else if (next_h > m_slot.window_last_height)
            e.terminal = Terminal::WindowClosedNull;
        else
            e.terminal = Terminal::Unclassified;
        e.duration_sec   = now_sec - m_started_sec;
        e.llmq_type      = m_slot.llmq_type;
        e.quorum_index   = m_slot.quorum_index;
        e.quorum_hash    = m_slot.quorum_hash;
        e.first_height   = m_first_height;
        e.resumed_height = next_h;
        m_active = false;
        m_slot   = PendingSlot{};
        return e;
    }

private:
    bool        m_active{false};
    PendingSlot m_slot;
    int64_t     m_started_sec{0};
    uint32_t    m_first_height{0};
};

}  // namespace coin
}  // namespace dash
