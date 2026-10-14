// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_timers.hpp
// Path B node policy timers (the node glue; time is the caller's, in
// seconds; nothing here reads a clock):
//   AbandonTimers   P-53 (--pathb-abandon-timeout, default 11 s), per
//                   request: the wait for the next frame of its reply,
//                   started when the request is sent and restarted at each
//                   frame (a prefix reply has no end mark). An expiry is
//                   non-service: no alarm, no token, no exclusion.
//   BucketWindow    the FC_BUCKETS bytes received from a peer in that peer's
//                   current window: the window starts at the first
//                   FC_GETBUCKETS sent to the peer after the previous window
//                   ended and ends one minute (P-42's unit) after the first
//                   frame of that request's reply arrived; a request is sent
//                   only while at least one frame (P-39) of the default P-42
//                   is left in the window, else after the window (the wait is
//                   not non-service).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_bucket_wire.hpp"  // BucketWirePolicy, kSecondsPerMinute

namespace c2pool::xmr::pathb {

// P-53 (policy, ruling 23): ceil(RTT_p99 + max(1 s, 3 x RTT_p99) + 60 s x P-39 / P-42).
inline constexpr std::uint64_t kAbandonTimeoutDefault = 11;
inline constexpr std::string_view kAbandonTimeoutFlag = "--pathb-abandon-timeout";

// One timer per open request, keyed by the caller's request key.
template <class Key>
class AbandonTimers {
public:
    explicit AbandonTimers(std::uint64_t timeout_s) : timeout_(timeout_s) {}

    std::uint64_t timeout() const noexcept { return timeout_; }
    // The request was sent at now_s.
    void sent(const Key& k, std::uint64_t now_s) { last_[k] = now_s; }
    // A frame of its reply arrived at now_s: the timer restarts.
    bool frame(const Key& k, std::uint64_t now_s) {
        const auto it = last_.find(k);
        if (it == last_.end()) return false;
        it->second = now_s;
        return true;
    }
    // The request is done (complete, refused or abandoned by its owner).
    void done(const Key& k) { last_.erase(k); }
    bool open(const Key& k) const { return last_.count(k) != 0; }
    // The requests whose next frame did not arrive within the timeout at now_s
    // (each returned once; their timers end).
    std::vector<Key> expired(std::uint64_t now_s) {
        std::vector<Key> out;
        for (auto it = last_.begin(); it != last_.end();) {
            if (now_s > it->second && now_s - it->second > timeout_) {
                out.push_back(it->first);
                it = last_.erase(it);
            } else {
                ++it;
            }
        }
        return out;
    }

private:
    std::uint64_t timeout_;
    std::map<Key, std::uint64_t> last_;
};

// The FC_BUCKETS bytes a peer sent in its current window (FIX-1).
class BucketWindow {
public:
    explicit BucketWindow(const BucketWirePolicy& defaults) : p_(defaults) {}

    // May an FC_GETBUCKETS go to `peer` at now_s?
    bool may_request(std::uint64_t peer, std::uint64_t now_s) {
        Peer& s = peers_[peer];
        roll(s, now_s);
        if (!s.open) return true;  // the next request opens a window
        return s.bytes + p_.frame_bytes <= p_.bytes_per_minute;
    }
    // A request was sent to `peer` at now_s.
    void requested(std::uint64_t peer, std::uint64_t now_s) {
        Peer& s = peers_[peer];
        roll(s, now_s);
        if (!s.open) {
            s.open = true;
            s.first_frame.reset();
            s.bytes = 0;
        }
    }
    // A frame of `bytes` arrived from `peer` at now_s.
    void received(std::uint64_t peer, std::uint64_t bytes, std::uint64_t now_s) {
        Peer& s = peers_[peer];
        roll(s, now_s);
        if (!s.open) return;
        if (!s.first_frame) s.first_frame = now_s;
        s.bytes = bytes > UINT64_MAX - s.bytes ? UINT64_MAX : s.bytes + bytes;
    }
    std::uint64_t bytes(std::uint64_t peer) const {
        const auto it = peers_.find(peer);
        return it == peers_.end() ? 0 : it->second.bytes;
    }
    // When the window of `peer` ends (nullopt: no reply frame yet, or no window).
    std::optional<std::uint64_t> window_end(std::uint64_t peer) const {
        const auto it = peers_.find(peer);
        if (it == peers_.end() || !it->second.open || !it->second.first_frame) return std::nullopt;
        return *it->second.first_frame + kSecondsPerMinute;
    }
    void forget(std::uint64_t peer) { peers_.erase(peer); }

private:
    struct Peer {
        bool open = false;
        std::optional<std::uint64_t> first_frame;
        std::uint64_t bytes = 0;
    };
    static void roll(Peer& s, std::uint64_t now_s) {
        if (s.open && s.first_frame && now_s >= *s.first_frame + kSecondsPerMinute) {
            s.open = false;
            s.first_frame.reset();
            s.bytes = 0;
        }
    }
    BucketWirePolicy p_;
    std::map<std::uint64_t, Peer> peers_;
};

}  // namespace c2pool::xmr::pathb
