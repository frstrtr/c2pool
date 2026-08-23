// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// ServeGateLedger — the CUMULATIVE, CROSS-RESTART companion to
/// ServeGateJournal.
///
/// THE DEFECT THIS CLOSES (critic, 2026-08-23): the EMBED-GATE roll-up and
/// every ServeGateJournal counter live entirely in-process. `m_cause_totals`,
/// `m_first_observed_sec`, `m_episode_start_sec` are member state fed a
/// std::chrono::steady_clock (PROCESS-MONOTONIC) clock — so the whole roll-up
/// WIPES on every restart and the program-level "% embedded / never-a-reject"
/// figure is per-process, not standing. The dashd-cut acceptance gate is a
/// CUMULATIVE never-a-reject claim spanning >=3 restarts ("the null-arm covered
/// the 4.51% DKG floor, 0 rejects over N heights"), which the journal cannot
/// express: a claim you cannot carry across a restart is not a soak claim.
///
/// ServeGateLedger is the persisted aggregator. Design constraints, copied
/// verbatim from ServeGateJournal's discipline because the two must never
/// disagree:
///
///   * PURE POLICY — no I/O, no clock of its own, no JSON. The caller passes
///     monotonic seconds; a companion header (serve_gate_ledger_json.hpp) owns
///     serialize/deserialize + the atomic tmp+rename file. Header-only so it
///     folds into the allowlisted dash test targets exactly like the journal.
///
///   * ONLY DURATIONS/DELTAS CROSS PROCESSES. The steady_clock second is
///     process-monotonic, so a raw `now_sec` can never be persisted/restored.
///     observed_sec accumulates as (now - last_seen) DELTAS banked per serve;
///     off_embedded_sec / per_cause bank the journal's OWN closed-segment
///     durations (Decision.prev_cause_sec) — the exact quantity the journal
///     folds into m_cause_totals, so ledger and journal cannot diverge.
///
///   * CRASH LOSES <=1 FLUSH, NEVER DOUBLE-COUNTS. Closed segments are banked
///     into cumulative totals as they close. The currently-OPEN segment's
///     partial is written to a REPLACED (never accumulated) carry field and
///     folded exactly once on the next clean load — approximating the segment
///     the crashed process never got to close, without ever re-banking a
///     segment the new process's fresh journal will bank itself.
///
///   * MEASUREMENT-WITHOUT-COMMIT RULE. The persisted blob carries a schema
///     version, an epochs counter (++ on every load), and the writing binary's
///     commit sha, so a cumulative figure is never read without knowing which
///     code produced it.
///
/// NULL-ARM IS FIRST CLASS. A null-arm serve is journaled as plain
/// Served::Embedded and logs arm=EMBEDDED — indistinguishable from a
/// real-quorum serve (the 08-23 grep-case trap). The ledger splits Embedded
/// into EmbeddedReal / EmbeddedNull so "null-arm served the 4.51% floor" is a
/// first-class counter, and cross-checks that a null was served ONLY when no
/// real quorum was available (real_quorum_available_but_null_served MUST stay
/// 0 — that would be a null served where dashd had a real committed quorum).

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>

#include <impl/dash/coin/serve_gate_journal.hpp>

namespace dash {
namespace coin {

class ServeGateLedger {
public:
    static constexpr uint32_t kSchemaVersion = 1;

    /// Which arm produced a serve / won a block. Mirrors ServeGateJournal's
    /// three-valued disposition but SPLITS Embedded so the null arm is
    /// countable on its own axis.
    ///   EmbeddedReal — embedded template built on a real committed quorum;
    ///   EmbeddedNull — embedded template served coinbase-only over the DKG
    ///                  floor with the SAME null quorum commitment dashd uses
    ///                  (#127 parity), NOT a real quorum;
    ///   Fallback     — a real dashd getblocktemplate was served instead;
    ///   NoWork       — SET-GAP: neither arm produced a mineable template.
    enum class Arm : uint8_t {
        Unknown      = 0,
        EmbeddedReal = 1,
        EmbeddedNull = 2,
        Fallback     = 3,
        NoWork       = 4,
    };

    static const char* arm_name(Arm a) {
        switch (a) {
            case Arm::EmbeddedReal: return "embedded_real";
            case Arm::EmbeddedNull: return "embedded_null";
            case Arm::Fallback:     return "fallback";
            case Arm::NoWork:       return "no_work";
            case Arm::Unknown:      break;
        }
        return "unknown";
    }

    static bool is_embedded(Arm a) {
        return a == Arm::EmbeddedReal || a == Arm::EmbeddedNull;
    }

    /// The entire persisted state. A plain aggregate so the JSON companion can
    /// serialize/deserialize field-by-field and the KAT can compare two
    /// ledgers with ==. Every field is a cumulative TOTAL or a DELTA-safe
    /// duration — no raw process-monotonic clock value ever lands here.
    struct Totals {
        // ── provenance (measurement-without-commit rule) ──────────────────
        uint32_t    schema_version{kSchemaVersion};
        uint64_t    epochs{0};            ///< ++ on every load (restart count+1)
        std::string last_writer_commit;   ///< git sha of the writing binary

        // ── wall clock (delta-accumulated; safe across processes) ─────────
        int64_t observed_sec{0};          ///< cumulative wall clock observed
        int64_t off_embedded_sec{0};      ///< cumulative seconds off embedded
        std::map<std::string, int64_t> per_cause_sec;  ///< closed segments only

        // ── serve dispositions (per template re-source) ───────────────────
        uint64_t serves_embedded_real{0};
        uint64_t serves_embedded_null{0};
        uint64_t serves_fallback{0};
        uint64_t serves_no_work{0};

        // ── blocks ────────────────────────────────────────────────────────
        uint64_t blocks_won_embedded_real{0};
        uint64_t blocks_won_embedded_null{0};
        uint64_t blocks_won_fallback{0};
        uint64_t blocks_submitted{0};
        uint64_t blocks_confirmed{0};
        uint64_t blocks_orphaned{0};
        uint64_t local_payee_guard_rejects{0};

        // ── the never-a-reject numerators (hard gate: embedded == 0) ──────
        uint64_t rpc_rejected_embedded_real{0};
        uint64_t rpc_rejected_embedded_null{0};
        uint64_t rpc_rejected_fallback{0};
        uint64_t orphaned_embedded_real{0};   ///< validity-attributable
        uint64_t orphaned_embedded_null{0};   ///< validity-attributable
        std::map<std::string, uint64_t> rpc_reject_reasons;

        // ── null-arm first class ──────────────────────────────────────────
        /// A null was served on a DKG-floor tip where NO real quorum existed
        /// (the correct, dashd-parity case).
        uint64_t null_dkg_floor_tips_served{0};
        /// A null was served where a real committed quorum WAS available. This
        /// MUST stay 0 — a non-zero value means the null arm fired when it
        /// should not have, and stops the cut.
        uint64_t null_real_quorum_available_but_null_served{0};

        // ── rolling never-a-reject height span ────────────────────────────
        /// First / last parent-chain height in the CURRENT clean (0-reject)
        /// span. start==0 means the span is empty (just reset by a reject).
        uint64_t nr_span_start_height{0};
        uint64_t nr_span_last_height{0};
        /// Cumulative count of rejects (any arm) that broke a span, and the
        /// height of the most recent one (0 = never rejected).
        uint64_t nr_total_rejects{0};
        uint64_t nr_last_reject_height{0};

        // ── open-segment carry (REPLACED each flush; folded once on load) ──
        /// The partial duration of the segment currently in progress at flush
        /// time. NOT part of off_embedded_sec/per_cause until folded on the
        /// next load — that fold is the only place it is ever added, and it is
        /// cleared immediately after, so it can never be folded twice.
        std::string carry_cause;
        int64_t     carry_sec{0};

        bool operator==(const Totals& o) const {
            return schema_version == o.schema_version && epochs == o.epochs &&
                   last_writer_commit == o.last_writer_commit &&
                   observed_sec == o.observed_sec &&
                   off_embedded_sec == o.off_embedded_sec &&
                   per_cause_sec == o.per_cause_sec &&
                   serves_embedded_real == o.serves_embedded_real &&
                   serves_embedded_null == o.serves_embedded_null &&
                   serves_fallback == o.serves_fallback &&
                   serves_no_work == o.serves_no_work &&
                   blocks_won_embedded_real == o.blocks_won_embedded_real &&
                   blocks_won_embedded_null == o.blocks_won_embedded_null &&
                   blocks_won_fallback == o.blocks_won_fallback &&
                   blocks_submitted == o.blocks_submitted &&
                   blocks_confirmed == o.blocks_confirmed &&
                   blocks_orphaned == o.blocks_orphaned &&
                   local_payee_guard_rejects == o.local_payee_guard_rejects &&
                   rpc_rejected_embedded_real == o.rpc_rejected_embedded_real &&
                   rpc_rejected_embedded_null == o.rpc_rejected_embedded_null &&
                   rpc_rejected_fallback == o.rpc_rejected_fallback &&
                   orphaned_embedded_real == o.orphaned_embedded_real &&
                   orphaned_embedded_null == o.orphaned_embedded_null &&
                   rpc_reject_reasons == o.rpc_reject_reasons &&
                   null_dkg_floor_tips_served == o.null_dkg_floor_tips_served &&
                   null_real_quorum_available_but_null_served ==
                       o.null_real_quorum_available_but_null_served &&
                   nr_span_start_height == o.nr_span_start_height &&
                   nr_span_last_height == o.nr_span_last_height &&
                   nr_total_rejects == o.nr_total_rejects &&
                   nr_last_reject_height == o.nr_last_reject_height &&
                   carry_cause == o.carry_cause && carry_sec == o.carry_sec;
        }
        bool operator!=(const Totals& o) const { return !(*this == o); }
    };

    ServeGateLedger() = default;

    /// Restore from a persisted blob and count this as one more epoch. This is
    /// the ONLY place carry is folded: the crashed/previous process's open
    /// segment is banked into the cumulative totals exactly once, then cleared
    /// so it can never be folded again. epochs is bumped so the on-disk figure
    /// always names how many process lifetimes it spans.
    void load(const Totals& persisted) {
        m_t = persisted;
        // Fold the previous process's open-segment partial exactly once.
        if (m_t.carry_sec > 0 && !m_t.carry_cause.empty()) {
            m_t.off_embedded_sec += m_t.carry_sec;
            m_t.per_cause_sec[m_t.carry_cause] += m_t.carry_sec;
        }
        m_t.carry_sec = 0;
        m_t.carry_cause.clear();
        m_t.epochs += 1;
        m_t.schema_version = kSchemaVersion;
        // A new process: no last-seen clock yet, and no open segment carried in
        // memory (the fold above already accounted for the previous one).
        m_have_last_seen = false;
        m_open_cause.clear();
        m_open_start_sec = -1;
    }

    /// Stamp the writing binary's commit into the blob about to be flushed.
    void set_writer_commit(const std::string& sha) { m_t.last_writer_commit = sha; }

    /// HOOK h1 — bank ONE serve decision. Call once per template re-source,
    /// under the SAME serve_gate_mutex_ the journal observe() ran under, with:
    ///   arm            — resolved disposition (EmbeddedReal/EmbeddedNull/...);
    ///   current_cause  — the live first-unmet condition (why.cause) when off
    ///                    embedded; ignored (and cleared) when serving. Passed
    ///                    explicitly because Decision does not echo the current
    ///                    cause on suppressed lines (only prev_cause on the
    ///                    lines that CLOSE a segment);
    ///   d              — the SAME ServeGateJournal::Decision observe() just
    ///                    returned (its prev_cause_sec is exactly what the
    ///                    journal banks into m_cause_totals, so ledger and
    ///                    journal cannot disagree on closed segments);
    ///   now_sec        — monotonic seconds (process clock; only its DELTA and
    ///                    within-process open-segment span are used, never the
    ///                    absolute value — that is why totals cross restarts);
    ///   real_quorum_available — for EmbeddedNull only: was a real committed
    ///                    quorum available at this tip? true here is a defect (a
    ///                    null served where dashd had a real quorum), counted so.
    void bank_serve(Arm arm, const std::string& current_cause,
                    const ServeGateJournal::Decision& d, int64_t now_sec,
                    bool real_quorum_available = false) {
        // observed_sec grows by the DELTA since the last banked serve. First
        // call in a process contributes 0 (no prior sample) — this is why only
        // deltas cross restarts: the absolute clock is never persisted.
        if (m_have_last_seen && now_sec >= m_last_seen_sec)
            m_t.observed_sec += (now_sec - m_last_seen_sec);
        m_last_seen_sec  = now_sec;
        m_have_last_seen = true;

        // Bank the closed segment this decision reported, mirroring the
        // journal's m_cause_totals fold EXACTLY (same field, same guard).
        if (d.prev_cause_sec >= 0 && !d.previous_cause.empty()) {
            m_t.off_embedded_sec += d.prev_cause_sec;
            m_t.per_cause_sec[d.previous_cause] += d.prev_cause_sec;
        }

        // Track the currently-OPEN segment with the ledger's own segment clock,
        // exactly as the journal tracks m_cause_start_sec — Decision cannot
        // supply the open partial on suppressed lines (cause_sec is -1 there),
        // so the ledger measures it itself. A NEW segment (transition into
        // decline, or a cause change) restarts the clock at now_sec; a flush
        // then snapshots (last_seen - open_start) as carry.
        if (is_embedded(arm)) {
            m_open_cause.clear();
            m_open_start_sec = -1;
        } else {
            if (m_open_cause != current_cause || m_open_start_sec < 0) {
                m_open_cause     = current_cause;
                m_open_start_sec = now_sec;
            }
        }

        switch (arm) {
            case Arm::EmbeddedReal: ++m_t.serves_embedded_real; break;
            case Arm::EmbeddedNull:
                ++m_t.serves_embedded_null;
                if (real_quorum_available)
                    ++m_t.null_real_quorum_available_but_null_served;
                else
                    ++m_t.null_dkg_floor_tips_served;
                break;
            case Arm::Fallback: ++m_t.serves_fallback; break;
            case Arm::NoWork:   ++m_t.serves_no_work;  break;
            case Arm::Unknown:  break;
        }
    }

    /// HOOK h3 — snapshot the open segment into the REPLACED carry field, ready
    /// to be persisted. Idempotent; call immediately before every flush. Does
    /// NOT touch the cumulative totals (carry is folded only on load). The
    /// partial is (last banked serve - open-segment start), a within-process
    /// duration — never an absolute clock value.
    void snapshot_carry_for_flush() {
        if (!m_open_cause.empty() && m_open_start_sec >= 0 &&
            m_have_last_seen && m_last_seen_sec > m_open_start_sec) {
            m_t.carry_cause = m_open_cause;
            m_t.carry_sec   = m_last_seen_sec - m_open_start_sec;
        } else {
            m_t.carry_cause.clear();
            m_t.carry_sec = 0;
        }
    }

    // ── block / verdict hooks (h-blocks) ──────────────────────────────────

    /// A block was won and submitted on `arm` at parent-chain `height`. The
    /// clean span is extended optimistically; a later reject/validity-orphan
    /// breaks it.
    void record_block_won(Arm arm, uint64_t height) {
        switch (arm) {
            case Arm::EmbeddedReal: ++m_t.blocks_won_embedded_real; break;
            case Arm::EmbeddedNull: ++m_t.blocks_won_embedded_null; break;
            case Arm::Fallback:     ++m_t.blocks_won_fallback;      break;
            default: break;
        }
        ++m_t.blocks_submitted;
        extend_clean_span(height);
    }

    /// submitblock (or the daemonless header verdict) resolved. accepted=true
    /// when the RPC returned null / the header chain adopted the block;
    /// accepted=false with a reason string is a REJECT — it increments the
    /// per-arm reject counter and BREAKS the never-a-reject span.
    void record_rpc_verdict(Arm arm, uint64_t height, bool accepted,
                            const std::string& reject_reason) {
        if (accepted) return;
        switch (arm) {
            case Arm::EmbeddedReal: ++m_t.rpc_rejected_embedded_real; break;
            case Arm::EmbeddedNull: ++m_t.rpc_rejected_embedded_null; break;
            case Arm::Fallback:     ++m_t.rpc_rejected_fallback;      break;
            default: break;
        }
        if (!reject_reason.empty()) ++m_t.rpc_reject_reasons[reject_reason];
        break_clean_span(height);
    }

    /// The post-broadcast confirm/orphan lane resolved a verdict. A
    /// validity-attributable orphan on an embedded arm breaks the span (it is a
    /// silent reject); a race orphan (validity_attributable=false) does not.
    void record_confirm(Arm /*arm*/, uint64_t /*height*/) { ++m_t.blocks_confirmed; }
    void record_orphan(Arm arm, uint64_t height, bool validity_attributable) {
        ++m_t.blocks_orphaned;
        if (validity_attributable) {
            if (arm == Arm::EmbeddedReal) ++m_t.orphaned_embedded_real;
            else if (arm == Arm::EmbeddedNull) ++m_t.orphaned_embedded_null;
            if (is_embedded(arm)) break_clean_span(height);
        }
    }

    /// The pre-broadcast payee guard refused to submit locally. Counted, but it
    /// prevented a submit rather than being rejected by the network, so it does
    /// NOT break the never-a-reject span (nothing reached the chain).
    void record_payee_guard_reject(uint64_t /*height*/) {
        ++m_t.local_payee_guard_rejects;
    }

    // ── queries ───────────────────────────────────────────────────────────

    const Totals& totals() const { return m_t; }

    /// The cumulative never-a-reject claim: no embedded block was rejected by
    /// RPC and no embedded block was orphaned for a validity reason, over every
    /// epoch. This is the hard cut gate.
    bool never_a_reject() const {
        return m_t.rpc_rejected_embedded_real == 0 &&
               m_t.rpc_rejected_embedded_null == 0 &&
               m_t.orphaned_embedded_real == 0 &&
               m_t.orphaned_embedded_null == 0;
    }

    /// Length of the current clean span in heights (inclusive), 0 when empty.
    uint64_t clean_span_heights() const {
        if (m_t.nr_span_start_height == 0) return 0;
        return m_t.nr_span_last_height - m_t.nr_span_start_height + 1;
    }

    uint64_t serves_total() const {
        return m_t.serves_embedded_real + m_t.serves_embedded_null +
               m_t.serves_fallback + m_t.serves_no_work;
    }
    uint64_t serves_embedded_total() const {
        return m_t.serves_embedded_real + m_t.serves_embedded_null;
    }

private:
    void extend_clean_span(uint64_t height) {
        if (height == 0) return;
        if (m_t.nr_span_start_height == 0 || height < m_t.nr_span_start_height)
            m_t.nr_span_start_height = height;
        if (height > m_t.nr_span_last_height)
            m_t.nr_span_last_height = height;
    }
    void break_clean_span(uint64_t height) {
        ++m_t.nr_total_rejects;
        m_t.nr_last_reject_height = height;
        m_t.nr_span_start_height  = 0;
        m_t.nr_span_last_height   = 0;
    }

    Totals m_t;

    // In-memory-only tracking of the open segment + last-seen clock. NONE of
    // this is persisted directly: observed_sec banks deltas, and the open
    // segment is snapshotted into Totals::carry only at flush time.
    bool        m_have_last_seen{false};
    int64_t     m_last_seen_sec{0};
    std::string m_open_cause;
    /// Start of the currently-open off-embedded segment (process-monotonic);
    /// -1 while the embedded arm is serving. The flush snapshots
    /// (m_last_seen_sec - m_open_start_sec) as carry.
    int64_t     m_open_start_sec{-1};
};

}  // namespace coin
}  // namespace dash
