// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/inject/xmr_inject_rate_limiter.hpp
//
// PROVENANCE: this is a re-namespaced copy of the Dash inject rate limiter
// (src/impl/dash/coin/inject_rate_limiter.hpp, #157 M3), logic byte-identical.
// Hoisting the Dash struct into src/core/ so both lines share ONE definition is
// the clean end state, but that touches the Dash tree; it is a follow-up, not
// this PR. Until then this copy carries the same behaviour and the same named
// causes so the XMR gate throttles injects exactly as the Dash gate does.
//
// SHAPE: a sliding-window token bucket over TWO budgets at once -- a COUNT
// budget (max injects/window) and a BYTE budget (max serialized bytes/window).
// A flood of many small txs is bounded by count; a flood of few large txs by
// bytes. try_consume() prunes the window to `now`, admits iff BOTH budgets have
// room, and only then records the event -- so a refused attempt costs nothing.
//
// CHARGED ON ATTEMPT, NOT ON SUCCESS: the gate consumes a token for every
// attempt that passes the rate check, BEFORE the validity/verify work, so a
// flood of INVALID injects is throttled too. DoS-correct placement.
//
// Scope::{Local, Peers} -- a node runs TWO instances so a peer flood exhausts
// only the peer budget and can NEVER starve the operator's own inject. XMR has
// no sharechain tx-inject transport yet (Scope::Peers is reserved for when a
// relay path is added); the Local budget is what the operator submit path uses.
//
// PURE + HEADER-ONLY, no internal locking (the gate serialises access). Drivable
// from a rig-free KAT by passing an explicit `now`.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <deque>

namespace c2pool::xmr::native {

struct InjectRateLimiter {
    // Node-wide ceilings per window (Dash parity). Generous for a human-driven
    // or scripted operator batch, yet bound a hostile aggregate to a low rate.
    static constexpr std::size_t kMaxInjectsPerWindow = 200;
    static constexpr std::uint64_t kMaxBytesPerWindow = 8u * 1024u * 1024u;
    static constexpr std::time_t  kWindowSeconds      = 60;

    enum class Scope : std::uint8_t { Local, Peers };
    Scope scope{Scope::Local};

    InjectRateLimiter() = default;
    explicit InjectRateLimiter(Scope s) : scope(s) {}

    enum class Verdict : std::uint8_t {
        Ok = 0,
        CountExceeded,
        BytesExceeded,
    };
    static const char* verdict_name(Verdict v) {
        switch (v) {
            case Verdict::Ok:            return "ok";
            case Verdict::CountExceeded: return "inject-rate-limited-count";
            case Verdict::BytesExceeded: return "inject-rate-limited-bytes";
        }
        return "inject-rate-limited-unknown";
    }
    const char* scoped_name(Verdict v) const {
        if (scope == Scope::Peers) {
            switch (v) {
                case Verdict::Ok:            return "ok";
                case Verdict::CountExceeded: return "inject-rate-limited-peers-count";
                case Verdict::BytesExceeded: return "inject-rate-limited-peers-bytes";
            }
            return "inject-rate-limited-peers-unknown";
        }
        return verdict_name(v);
    }
    struct Result {
        Verdict     verdict{Verdict::Ok};
        std::uint64_t value{0};
        std::uint64_t threshold{0};
        const char* cause_name{"ok"};
        bool ok() const { return verdict == Verdict::Ok; }
        const char* name() const { return cause_name; }
    };

    std::deque<std::time_t> ts;
    std::deque<std::uint64_t> sz;
    std::uint64_t bytes_in_window{0};

    void prune(std::time_t now) {
        while (!ts.empty() && ts.front() + kWindowSeconds <= now) {
            bytes_in_window -= sz.front();
            ts.pop_front();
            sz.pop_front();
        }
    }

    Result try_consume(std::uint64_t byte_size, std::time_t now) {
        prune(now);
        Result r;
        if (ts.size() >= kMaxInjectsPerWindow) {
            r.verdict = Verdict::CountExceeded;
            r.value = ts.size(); r.threshold = kMaxInjectsPerWindow;
            r.cause_name = scoped_name(r.verdict);
            return r;
        }
        if (bytes_in_window + byte_size > kMaxBytesPerWindow) {
            r.verdict = Verdict::BytesExceeded;
            r.value = bytes_in_window + byte_size; r.threshold = kMaxBytesPerWindow;
            r.cause_name = scoped_name(r.verdict);
            return r;
        }
        ts.push_back(now);
        sz.push_back(byte_size);
        bytes_in_window += byte_size;
        return r;
    }

    std::size_t count_in_window() const { return ts.size(); }
};

} // namespace c2pool::xmr::native
