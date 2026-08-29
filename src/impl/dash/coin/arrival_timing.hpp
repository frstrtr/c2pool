// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// PR-0 ARRIVAL INSTRUMENTATION (dashd-cut coin-P2P foundation, task #154 line).
///
/// This header is the SCHEMA the coin-P2P racing/selection PRs (PR-1..PR-4)
/// build on. It is pure policy: NO I/O, NO clock of its own (every caller
/// passes monotonic milliseconds), NO coin state, header-only so it folds into
/// the allowlisted dash test targets exactly like serve_gate_journal.hpp.
///
/// It answers two questions that the existing serve-gate journal cannot,
/// because the journal times in WHOLE SECONDS on the serve path and cannot see
/// WHY a window was long:
///
///   (1) When the embedded arm falls off its template into an off-embedded
///       window (a fold / re-seed round trip), how much of that window was
///       spent WAITING FOR THE DATUM ON THE WIRE (arrival) versus DERIVING it
///       once it arrived (fold)?  A 4-second window that was 3.9 s of network
///       silence and 0.1 s of fold is a peer-selection problem; the same 4 s
///       that was 0.1 s wire and 3.9 s fold is a derivation problem. The
///       count- and second-only journal reads them identically — the same
///       class of trap the #119 per-cause-TIME work already fought.
///
///       OffEmbeddedWindow stamps the four boundary timestamps
///       t_open / t_data_arrived / t_fold_complete / t_resumed and partitions
///       the window into EXACTLY two spans that sum to the whole:
///           arrival_ms = t_data_arrived - t_open      (wire wait)
///           fold_ms    = t_resumed      - t_data_arrived (derive + resume)
///       so arrival_ms + fold_ms == window_ms by construction. t_fold_complete
///       is an intermediate marker WITHIN fold_ms (derivation done, before the
///       serve path resumed) carried for the finer 3-way view; it never breaks
///       the 2-way invariant.
///
///   (2) Per PEER and per DATUM CLASS (tip body / mnlistdiff / qrinfo), what is
///       the delivery latency between the request we sent and the reply we got,
///       smoothed so one slow round trip does not dominate?  DeliveryLatencyEwma
///       is a classic RTT-style exponential moving average (alpha = 1/8), the
///       measurement a later PR's peer scorer would consult to prefer the
///       carrier that actually answers fastest.
///
/// REWARD SAFETY. Nothing here selects a peer, fetches, or derives anything. It
/// records timestamps and computes moving averages. The emit of these fields on
/// the live log is gated behind a default-OFF flag (arrival_instr_enabled()) so
/// an unflagged binary is byte-identical to master. Worst case with the flag ON
/// is extra log fields; the values never gate a decision in this PR.

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace dash {
namespace coin {

// ─── Datum classes whose per-peer delivery latency the coin-P2P lane measures ─
// Ordinals are STABLE (they index PeerDeliveryLatency::by_class); append only.
enum class DatumClass : uint8_t {
    TipBody    = 0,   // block body fetched by getdata (the live-tip serve input)
    MnListDiff = 1,   // getmnlistd -> mnlistdiff (the fold snapshot)
    QrInfo     = 2,   // getqrinfo -> qrinfo (rotated-quorum bootstrap)
    Count      = 3
};

inline const char* datum_class_name(DatumClass c) {
    switch (c) {
        case DatumClass::TipBody:    return "tip_body";
        case DatumClass::MnListDiff: return "mnlistdiff";
        case DatumClass::QrInfo:     return "qrinfo";
        default:                     return "?";
    }
}

// ─── The default-OFF instrumentation emit flag ───────────────────────────────
// Gates ONLY the NEW log fields these instruments feed. OFF => byte-identical
// to master. Recording (the timestamp/EWMA member writes) is invisible and
// always runs; only the emit is flagged. A process-wide relaxed atomic — set
// once at startup from a CLI flag, read on the serve/dispatch threads.
inline std::atomic<bool>& arrival_instr_flag() {
    static std::atomic<bool> g{false};
    return g;
}
inline bool arrival_instr_enabled() {
    return arrival_instr_flag().load(std::memory_order_relaxed);
}
inline void set_arrival_instr_enabled(bool on) {
    arrival_instr_flag().store(on, std::memory_order_relaxed);
}

// ─── One off-embedded window's four boundary timestamps + the arrival/fold split
// All times are monotonic milliseconds supplied by the caller. -1 = unstamped.
struct OffEmbeddedWindow {
    int64_t t_open{-1};          // arm fell off the embedded template / ask sent
    int64_t t_data_arrived{-1};  // the datum (reply) arrived on the wire
    int64_t t_fold_complete{-1}; // derivation from the datum finished
    int64_t t_resumed{-1};       // the arm resumed serving the embedded template

    void reset() { t_open = t_data_arrived = t_fold_complete = t_resumed = -1; }

    // Idempotent-ish stampers: open() starts a fresh window; the later marks
    // record the FIRST time they are reached within the window and are ignored
    // out of order, so a duplicate reply or a spurious resume cannot rewrite a
    // boundary already banked.
    void open(int64_t now)          { reset(); t_open = now; }
    void data_arrived(int64_t now)  { if (t_open >= 0 && t_data_arrived < 0)  t_data_arrived  = now; }
    void fold_complete(int64_t now) { if (t_data_arrived >= 0 && t_fold_complete < 0) t_fold_complete = now; }
    void resumed(int64_t now)       { if (t_open >= 0 && t_resumed < 0)       t_resumed       = now; }

    bool open_pending() const { return t_open >= 0 && t_resumed < 0; }
    bool complete()     const { return t_open >= 0 && t_data_arrived >= 0 && t_resumed >= 0; }

    // Wire-wait span: open -> data arrived. -1 until the datum has arrived.
    int64_t arrival_ms() const {
        return (t_open >= 0 && t_data_arrived >= 0) ? t_data_arrived - t_open : -1;
    }
    // Derive+resume span: data arrived -> resumed. -1 until resumed.
    int64_t fold_ms() const {
        return (t_data_arrived >= 0 && t_resumed >= 0) ? t_resumed - t_data_arrived : -1;
    }
    // Derivation sub-span WITHIN fold_ms: data arrived -> fold complete.
    int64_t derive_ms() const {
        return (t_data_arrived >= 0 && t_fold_complete >= 0) ? t_fold_complete - t_data_arrived : -1;
    }
    // Full window: open -> resumed. -1 until resumed.
    int64_t window_ms() const {
        return (t_open >= 0 && t_resumed >= 0) ? t_resumed - t_open : -1;
    }
    // The invariant the KAT locks and the emit relies on: on a complete window
    // the two spans partition the whole with no gap and no overlap.
    bool split_consistent() const {
        return complete() && (arrival_ms() + fold_ms() == window_ms());
    }
};

// ─── Per-peer, per-datum-class delivery-latency EWMA ─────────────────────────
// Classic RTT smoother: seed on the first sample, then
//     ewma <- ewma + (sample - ewma) / kInvAlpha      (alpha = 1/kInvAlpha)
// Integer division truncates toward zero (deterministic; the KAT asserts the
// exact sequence). Negative samples (an unmatched reply / missing request
// stamp) are ignored so a bogus latency never poisons the average.
class DeliveryLatencyEwma {
public:
    static constexpr int64_t kInvAlpha = 8;  // alpha = 1/8

    void observe(int64_t sample_ms) {
        if (sample_ms < 0) return;
        m_last_ms = sample_ms;
        ++m_samples;
        if (m_ewma_ms < 0) { m_ewma_ms = sample_ms; return; }  // seed exactly
        m_ewma_ms += (sample_ms - m_ewma_ms) / kInvAlpha;
    }

    int64_t  ewma_ms()   const { return m_ewma_ms; }  // -1 before any sample
    int64_t  last_ms()   const { return m_last_ms; }  // -1 before any sample
    uint64_t samples()   const { return m_samples; }
    bool     has_sample() const { return m_samples > 0; }

private:
    int64_t  m_ewma_ms{-1};
    int64_t  m_last_ms{-1};
    uint64_t m_samples{0};
};

// A peer holds one EWMA per datum class. Embedded in the peer/session object;
// pure recording, zero behaviour.
struct PeerDeliveryLatency {
    std::array<DeliveryLatencyEwma, static_cast<size_t>(DatumClass::Count)> by_class{};

    void observe(DatumClass c, int64_t sample_ms) {
        const size_t i = static_cast<size_t>(c);
        if (i < by_class.size()) by_class[i].observe(sample_ms);
    }
    const DeliveryLatencyEwma& get(DatumClass c) const {
        return by_class[static_cast<size_t>(c)];
    }
    int64_t ewma_ms(DatumClass c) const { return get(c).ewma_ms(); }
    int64_t last_ms(DatumClass c) const { return get(c).last_ms(); }
    bool    has_any() const {
        for (const auto& e : by_class) if (e.has_sample()) return true;
        return false;
    }
};

}  // namespace coin
}  // namespace dash
