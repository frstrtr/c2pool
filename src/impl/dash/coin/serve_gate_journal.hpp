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

    /// The THREE serve dispositions, so the journal stops collapsing the third
    /// (neither arm produced a mineable template) into the dashd-fallback arm.
    ///   Embedded  -- the embedded arm served a mineable template;
    ///   Fallback  -- a real dashd getblocktemplate was served instead;
    ///   NoWork    -- SET-GAP: m_bits==0 || previous_block.IsNull(); an honest
    ///                absence, nothing was served (the caller drops the cache).
    /// Fallback and NoWork are both "off embedded" and time IDENTICALLY.
    enum class Served { Embedded, Fallback, NoWork };

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
        /// Seconds the cause named on THIS line has been the first-unmet
        /// condition, as of this decision. -1 when there is no active cause
        /// (Resumed lines, or the arm was already serving).
        ///
        /// WHY THIS FIELD EXISTS — episode_sec is deliberately whole-episode
        /// (measured from the FIRST decline, surviving cause changes, see
        /// above), which means a cause-change line attributes the WHOLE
        /// episode's duration to the cause it happens to name. Measured at
        /// h=2518004 (hotel, 2026-08-07): a cause-change line naming
        /// emit-bestcl-null-committed carried dur=512s, of which that cause
        /// owned 0.89 s — the 512 s belonged to the PRECEDING
        /// qc-plan-underivable segment. Every per-cause TIME histogram built
        /// from episode_sec alone is therefore wrong; by count
        /// emit-bestcl-null-committed read as 29% of the gap, by time it is
        /// 0.065% of wall clock while qc-plan-underivable is 87% of decline
        /// time. cause_sec restores the per-cause clock WITHOUT redefining
        /// episode_sec: it is 0 on the line that starts a cause segment and
        /// grows on heartbeats of the same cause.
        int64_t cause_sec{-1};
        /// Seconds the PREVIOUS cause (the `previous_cause` field) ran, on the
        /// lines that CLOSE a cause segment: CauseChange (the old cause's
        /// segment ends as the new one is named) and Resumed (the episode's
        /// final segment ends). -1 on every other line. Summing this field by
        /// `previous_cause` over a journal window yields the CORRECT per-cause
        /// time histogram; episode_sec cannot, by design.
        int64_t prev_cause_sec{-1};

        bool emit() const { return trigger != Trigger::None; }
    };

    explicit ServeGateJournal(int64_t heartbeat_sec = 300)
        : m_heartbeat_sec(heartbeat_sec) {}

    /// Feed ONE arm-selection outcome (LEGACY bool). Retained verbatim for the
    /// existing serve-path caller and the four timing KATs. false maps to
    /// Served::Fallback: Fallback and NoWork are BOTH "off the embedded arm"
    /// and share identical episode/partition timing, so every invariant and
    /// every existing test stays green. `cause` is ignored when
    /// `served_embedded` is true. `now_sec` is monotonic seconds.
    Decision observe(bool served_embedded, const std::string& cause, int64_t now_sec) {
        return observe(served_embedded ? Served::Embedded : Served::Fallback,
                       cause, now_sec);
    }

    /// Feed ONE arm-selection outcome, THREE-VALUED. Served::Embedded takes the
    /// serving path; Served::Fallback and Served::NoWork take the SAME decline
    /// path (identical timing) but record a distinct disposition so the arm can
    /// name the third state -- neither arm produced a mineable template
    /// (set-gap / no-work) -- instead of mis-reporting it as a dashd-fallback
    /// serve. `cause` is ignored for Served::Embedded. `now_sec` is monotonic.
    Decision observe(Served served, const std::string& cause, int64_t now_sec) {
        Decision d;
        d.previous_cause = m_last_cause;

        if (served == Served::Embedded) {
            const bool was_declining = (m_arm == Arm::Declining);
            m_arm = Arm::Embedded;
            m_disposition = Disposition::Serving;
            m_last_cause.clear();
            if (was_declining) {
                d.trigger    = Trigger::Resumed;
                d.suppressed = m_suppressed;
                // How long this episode actually cost us. Measured from the
                // FIRST decline of the episode, not from the last emitted line,
                // so a cause-change mid-episode cannot shorten the number.
                d.episode_sec = (m_episode_start_sec >= 0)
                                    ? now_sec - m_episode_start_sec : -1;
                // The episode's FINAL cause segment closes here; attribute its
                // duration to the cause it names (d.previous_cause).
                d.prev_cause_sec = (m_cause_start_sec >= 0)
                                       ? now_sec - m_cause_start_sec : -1;
                m_cause_start_sec   = -1;
                m_episode_start_sec = -1;
                m_suppressed = 0;
                m_last_emit_sec = now_sec;
                m_have_emitted  = true;
            }
            return d;
        }

        const Arm prev_arm = m_arm;
        m_arm = Arm::Declining;
        // The third arm state rides HERE: Fallback vs NoWork share this decline
        // path's timing exactly, and differ only in the disposition the arm
        // name renders. Recorded every decline so a cause-stable set-gap is
        // never mis-named a dashd-fallback serve on a later heartbeat.
        m_disposition = (served == Served::NoWork) ? Disposition::NoWork
                                                   : Disposition::Fallback;
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

        // Per-cause segment clock. Unlike the episode clock above, it does NOT
        // survive cause changes: a change of the first-unmet condition closes
        // the old cause's segment (attributed via prev_cause_sec — this line
        // always emits, it is a CauseChange) and starts the new cause's clock
        // at ZERO. This is what keeps a cause-change line from attributing the
        // whole episode to the cause it names (the h=2518004 trap).
        if (prev_arm == Arm::Declining && cause != m_last_cause &&
            m_cause_start_sec >= 0)
            d.prev_cause_sec = now_sec - m_cause_start_sec;
        if (prev_arm != Arm::Declining || cause != m_last_cause)
            m_cause_start_sec = now_sec;

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
        d.cause_sec     = (m_cause_start_sec >= 0)
                              ? now_sec - m_cause_start_sec : -1;
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

    /// True iff the arm is off the embedded template because NEITHER arm
    /// produced a mineable template (set-gap / no-work) -- the third state,
    /// distinct from a genuine dashd-fallback serve. False while serving.
    bool no_work() const { return m_disposition == Disposition::NoWork; }

    /// Three-valued arm name for the serve journal and the operator surface.
    const char* arm_name() const {
        if (m_arm == Arm::Unknown)  return "unknown";
        if (m_arm == Arm::Embedded) return "embedded";
        return m_disposition == Disposition::NoWork ? "none(set-gap/no-work)"
                                                    : "dashd-fallback";
    }

private:
    enum class Arm { Unknown, Embedded, Declining };
    /// Which off-embedded disposition the current decline is (Serving while the
    /// embedded arm is up). This is the state that makes arm_name() three-valued.
    enum class Disposition { Serving, Fallback, NoWork };

    int64_t     m_heartbeat_sec;
    Arm         m_arm{Arm::Unknown};
    Disposition m_disposition{Disposition::Serving};
    std::string m_last_cause;
    int64_t     m_last_emit_sec{0};
    /// Start of the CURRENT continuous off-embedded episode; -1 = arm serving.
    int64_t     m_episode_start_sec{-1};
    /// Start of the CURRENT cause segment WITHIN the episode; -1 = no active
    /// cause. Resets on every cause change; m_episode_start_sec does not.
    int64_t     m_cause_start_sec{-1};
    bool        m_have_emitted{false};
    uint64_t    m_suppressed{0};
};

}  // namespace coin
}  // namespace dash
