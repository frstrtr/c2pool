// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #157 M3 — GLOBAL (node-wide) inject rate limiter: count + volume per window.
//
// WHY A SECOND LIMITER
// --------------------
// M2 gave each PEER a sliding-window count cap (dash::PeerInjectGuard, in
// tx_inject_relay.hpp). That bounds ONE peer, but two gaps remain:
//   * AGGREGATE peer flood — N peers each just under their per-peer cap still
//     sum to N * cap injects/min hitting the (script-verifying) submit gate.
//   * LOCAL flood — the --embedded-tx-inject-hex loader and any future local
//     submit path never pass through a peer guard at all.
// Both funnel through the SINGLE gate every inject crosses:
// NodeCoinState::submit_inject. So this limiter lives THERE, node-wide, and
// bounds the total inject work the node performs per window regardless of
// origin — the "global cap" half of the per-peer-AND-global requirement.
//
// SHAPE: a sliding-window token bucket over TWO budgets at once — a COUNT
// budget (max injects/window) and a BYTE budget (max serialized bytes/window).
// A flood of many small txs is bounded by count; a flood of few large txs is
// bounded by bytes. try_consume() prunes the window to `now`, admits iff BOTH
// budgets have room, and (only then) records the event — so a refused attempt
// costs nothing and leaves the window untouched, letting a throttled source
// recover as its old events age out.
//
// CHARGED ON ATTEMPT, NOT ON SUCCESS: the gate consumes a token for every
// attempt that passes the rate check, BEFORE the validity/script work — so a
// flood of INVALID injects is throttled too (each still costs the interpreter
// otherwise). This is the DoS-correct placement.
//
// MONEY-SAFETY: a rate ceiling in front of the validity gate. It only REFUSES;
// it never admits, never loosens a consensus check, and touches no coinbase /
// subsidy / PPLNS / payee / fee state. It reads a byte count and a clock.
//
// PURE + HEADER-ONLY, IO-thread-confined (same discipline as the M2 relay
// guard / NodeImpl::m_known_txs) — no internal locking. Drivable from a
// rig-free KAT by passing an explicit `now`.

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <deque>

namespace dash {
namespace coin {

struct InjectRateLimiter {
    // Node-wide ceilings per window. An inject is a rare operator/miner action;
    // these are generous for a human-driven or scripted operator batch yet bound
    // a hostile aggregate to a low steady rate. Sized above the single-peer cap
    // (PeerInjectGuard::kMaxInjectsPerPeerPerWindow = 30) so a lone well-behaved
    // peer never trips the global limiter, while an aggregate flood does.
    static constexpr std::size_t kMaxInjectsPerWindow = 200;
    // Byte volume ceiling per window. 8 MB/min bounds memory/bandwidth churn
    // while clearing ~80 max-size (100 KB) injects — far beyond any real batch.
    static constexpr uint64_t    kMaxBytesPerWindow   = 8u * 1024u * 1024u;
    static constexpr std::time_t kWindowSeconds       = 60;

    // Named outcome so the caller logs cause/value/threshold in the repo's
    // convention (DEF3 — no silent drops).
    enum class Verdict : uint8_t {
        Ok = 0,
        CountExceeded,   // count budget full for this window
        BytesExceeded,   // byte budget would overflow for this window
    };
    static const char* verdict_name(Verdict v) {
        switch (v) {
            case Verdict::Ok:            return "ok";
            case Verdict::CountExceeded: return "inject-rate-limited-count";
            case Verdict::BytesExceeded: return "inject-rate-limited-bytes";
        }
        return "inject-rate-limited-unknown";
    }
    struct Result {
        Verdict  verdict{Verdict::Ok};
        uint64_t value{0};       // observed count-in-window or bytes-in-window
        uint64_t threshold{0};   // the cap it would breach
        bool ok() const { return verdict == Verdict::Ok; }
        const char* name() const { return verdict_name(verdict); }
    };

    std::deque<std::time_t> ts;      // event timestamps inside the window
    std::deque<uint64_t>    sz;      // parallel per-event byte sizes
    uint64_t bytes_in_window{0};     // running sum of sz (kept in step)

    // Drop events older than the window ending at `now`.
    void prune(std::time_t now) {
        while (!ts.empty() && ts.front() + kWindowSeconds <= now) {
            bytes_in_window -= sz.front();
            ts.pop_front();
            sz.pop_front();
        }
    }

    // Prune to `now`, then admit iff BOTH budgets have room for one more event
    // of `byte_size`. Records the event only on admit; a refusal mutates nothing
    // beyond the prune. Count is checked before bytes (cheapest signal first).
    Result try_consume(uint64_t byte_size, std::time_t now) {
        prune(now);
        Result r;
        if (ts.size() >= kMaxInjectsPerWindow) {
            r.verdict = Verdict::CountExceeded;
            r.value = ts.size(); r.threshold = kMaxInjectsPerWindow;
            return r;
        }
        if (bytes_in_window + byte_size > kMaxBytesPerWindow) {
            r.verdict = Verdict::BytesExceeded;
            r.value = bytes_in_window + byte_size; r.threshold = kMaxBytesPerWindow;
            return r;
        }
        ts.push_back(now);
        sz.push_back(byte_size);
        bytes_in_window += byte_size;
        return r;  // Ok — token consumed
    }

    std::size_t count_in_window() const { return ts.size(); }
};

} // namespace coin
} // namespace dash
