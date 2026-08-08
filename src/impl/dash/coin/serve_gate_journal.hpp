// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DEFECT-3 (daemonless soak, 2026-08-03): the DASH embedded serve gate
/// refused SILENTLY.
///
/// Measured on the contabo daemonless soak: the bridge completed, 2071
/// masternodes published, and the embedded arm served three templates whose MN
/// payee was byte-identical to a real dashd getblocktemplate at the same
/// height. It then flipped to the fallback arm and stayed there, and the ONLY
/// trace was
///
///     [DASH-STRATUM-GBT] template sourced: arm=dashd-fallback h=0 mn_payee=(none)
///
/// with no reason line of any kind. NodeCoinState::classify_decline() already
/// knew the answer, but it is reachable ONLY from EmbeddedOracleShadow, which
/// (a) requires --embedded-oracle-shadow and (b) returns at its first line when
/// no dashd oracle is bound -- i.e. it can never run on a daemonless node, the
/// only node where the question is asked. A gate that refuses in silence is
/// indistinguishable from a broken node.
///
/// ServeGateJournal is the rate policy for putting that answer on the live
/// serve path without flooding it (the path runs per template re-source):
///
///   * the EMBEDDED -> fallback TRANSITION always logs, even when the cause is
///     identical to a previous decline -- that edge is the event an operator
///     cares about and suppressing it is how the defect stayed invisible;
///   * a CHANGE of cause always logs (a different first-unmet condition is a
///     different fault);
///   * an unchanged cause logs on a slow HEARTBEAT so a stuck arm still names
///     itself in any window of the journal, not only at the moment it broke;
///   * everything else is suppressed and COUNTED, so the next emitted line can
///     say how many it stood for.
///
/// Pure policy: no I/O, no clock of its own (the caller passes monotonic
/// seconds), no coin state. Header-only so it folds into the already
/// allowlisted dash test targets.

#include <cstdint>
#include <string>

namespace dash {
namespace coin {

class ServeGateJournal {
public:
    /// Why this observation is being emitted. Rendered into the log line so a
    /// grep can separate "it just broke" from "it is still broken".
    enum class Trigger {
        None,        ///< suppressed
        First,       ///< first observation ever, and it is a decline
        Transition,  ///< EMBEDDED -> fallback: always emitted
        CauseChange, ///< still declining, but a DIFFERENT first-unmet condition
        Heartbeat,   ///< still declining, same cause, heartbeat interval elapsed
        Resumed      ///< fallback -> EMBEDDED: the arm is serving again
    };

    struct Decision {
        Trigger  trigger{Trigger::None};
        /// Declines suppressed since the previous emitted line (0 on the
        /// emitted line itself unless some were folded into it).
        uint64_t suppressed{0};
        /// The cause the previous emitted decline named ("" if none). Lets the
        /// Resumed / CauseChange lines say what they replaced.
        std::string previous_cause;
        /// Seconds the arm has been continuously OFF the embedded template, as
        /// of this decision. -1 when not applicable (the arm was already
        /// serving) or not yet measurable.
        ///
        /// WHY THIS FIELD EXISTS — the COUNT of decline lines is the wrong
        /// metric and it actively misleads. Measured on the hotel node over
        /// 5h33m (2026-08-06): 109 `dmn-stale` episodes vs 3
        /// `qc-plan-underivable`, so BY COUNT dmn-stale looks like 97% of the
        /// problem. BY TIME ACTUALLY SPENT ON THE FALLBACK ARM, 104 of those
        /// 109 dmn-stale episodes lasted under one second (~54 ms each — the
        /// ordinary tip-change -> getmnlistd round trip, 5.6 s in total) while
        /// the 3 qc-plan episodes cost 351 s. Eight episodes out of 116 carried
        /// 99.4% of the loss, and the prioritisation flips completely depending
        /// on which number you read.
        ///
        /// A journal that emits only counts cannot express that, so the episode
        /// duration rides the line that closes the episode.
        int64_t episode_sec{-1};

        bool emit() const { return trigger != Trigger::None; }
    };

    explicit ServeGateJournal(int64_t heartbeat_sec = 300)
        : m_heartbeat_sec(heartbeat_sec) {}

    /// Feed ONE arm-selection outcome. `cause` is ignored when
    /// `served_embedded` is true. `now_sec` is monotonic seconds.
    Decision observe(bool served_embedded, const std::string& cause, int64_t now_sec) {
        Decision d;
        d.previous_cause = m_last_cause;

        if (served_embedded) {
            const bool was_declining = (m_arm == Arm::Declining);
            m_arm = Arm::Embedded;
            m_last_cause.clear();
            if (was_declining) {
                d.trigger    = Trigger::Resumed;
                d.suppressed = m_suppressed;
                // How long this episode actually cost us. Measured from the
                // FIRST decline of the episode, not from the last emitted line,
                // so a cause-change mid-episode cannot shorten the number.
                d.episode_sec = (m_episode_start_sec >= 0)
                                    ? now_sec - m_episode_start_sec : -1;
                m_episode_start_sec = -1;
                m_suppressed = 0;
                m_last_emit_sec = now_sec;
                m_have_emitted  = true;
            }
            return d;
        }

        const Arm prev_arm = m_arm;
        m_arm = Arm::Declining;
        // Episode clock starts at the first decline after serving (or at the
        // very first observation) and survives cause changes.
        if (m_episode_start_sec < 0) m_episode_start_sec = now_sec;

        if (prev_arm == Arm::Embedded)
            d.trigger = Trigger::Transition;
        else if (prev_arm == Arm::Unknown)
            d.trigger = Trigger::First;
        else if (cause != m_last_cause)
            d.trigger = Trigger::CauseChange;
        else if (!m_have_emitted || now_sec - m_last_emit_sec >= m_heartbeat_sec)
            d.trigger = Trigger::Heartbeat;

        m_last_cause = cause;

        if (d.trigger == Trigger::None) {
            ++m_suppressed;
            return d;
        }
        d.suppressed    = m_suppressed;
        // Also carried on the DECLINE lines: a heartbeat that says how long the
        // arm has already been down is the difference between "the usual
        // sub-second round trip" and "we have been off the embedded arm for
        // four minutes", which read identically before.
        d.episode_sec   = (m_episode_start_sec >= 0)
                              ? now_sec - m_episode_start_sec : -1;
        m_suppressed    = 0;
        m_last_emit_sec = now_sec;
        m_have_emitted  = true;
        return d;
    }

    /// Human name for a trigger, for the log line.
    static const char* trigger_name(Trigger t) {
        switch (t) {
            case Trigger::First:       return "first";
            case Trigger::Transition:  return "transition";
            case Trigger::CauseChange: return "cause-change";
            case Trigger::Heartbeat:   return "heartbeat";
            case Trigger::Resumed:     return "resumed";
            case Trigger::None:        break;
        }
        return "none";
    }

    /// The cause of the most recent decline ("" while the arm is serving or
    /// before the first observation). This is what the operator-facing web
    /// surface publishes.
    const std::string& last_cause() const { return m_last_cause; }
    bool serving() const { return m_arm == Arm::Embedded; }
    bool observed() const { return m_arm != Arm::Unknown; }
    uint64_t suppressed_since_emit() const { return m_suppressed; }

private:
    enum class Arm { Unknown, Embedded, Declining };

    int64_t     m_heartbeat_sec;
    Arm         m_arm{Arm::Unknown};
    std::string m_last_cause;
    int64_t     m_last_emit_sec{0};
    /// Start of the CURRENT continuous off-embedded episode; -1 = arm serving.
    int64_t     m_episode_start_sec{-1};
    bool        m_have_emitted{false};
    uint64_t    m_suppressed{0};
};

}  // namespace coin
}  // namespace dash
