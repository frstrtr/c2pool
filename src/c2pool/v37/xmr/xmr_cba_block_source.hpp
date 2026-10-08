// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_cba_block_source.hpp   (D6a)
//
// WHERE THE COINBASE-AUTHORITY BOOKING READS A LANE BLOCK FROM.
//
// The booking decodes the coinbase of every block the chain view reports
// (main_v37_xmr.cpp, fetch_decode). Until D6a it always asked monerod for the
// block blob (get_block by hash), even in --arm-order p2p-first where the chain
// view itself is the embedded native node -- one RPC per booking attempt, and a
// held block retried it every tick.
//
// With a native source bound (p2p-first + --xmr-template-source native) the
// blob is read from the native chain index's retained bodies instead:
//
//   * native HIT  -> that blob is THE input. A block id is the hash of its
//     blob, so the bytes are the ones monerod's get_block would return and the
//     booking is byte-identical to the monerod-backed path.
//   * native MISS -> HOLD. The block is older than the retained bodies, pruned,
//     or not connected yet. The caller gets a "native-hold:" reason, which
//     FinalizeConnect retries (and past its bound HOLDS, never drops), and the
//     miss is counted. There is NO silent monerod fallback: it only happens
//     with the explicit `rpc_fallback` option, and is then counted too.
//   * `compare_monerod` (default OFF) turns monerod into a compare-only
//     ORACLE: on a native hit it fetches the same block and counts equal /
//     mismatch / unavailable. It never decides -- the native blob is booked
//     either way.
//
// Without a native source (daemon-first, or monerod templates) the legacy
// monerod path runs unchanged, including its "get_block..." reasons.
//
// COLD-BOOT safety net (set_refetch): a native MISS on a block the index
// CONNECTED but no longer holds the body of (a fresh boot from an anchor older
// than the entry cache evicts the oldest post-anchor bodies before the first
// booking) asks the native node to fetch that body again over levin (bounded:
// `refetch_bound` requests per block) instead of holding it forever. The reason
// keeps the "native-hold:" prefix, so FinalizeConnect's retry/HOLD
// classification is unchanged; the next attempt books from the restored body,
// which is byte-identical (the id is the hash of the blob). Past the bound the
// block HOLDS exactly as before (loud alarm). Still never monerod.
//
// SCOPE FENCE: the booking fetch only. The tip/finalize feed, relay repair
// context and seed/ZMQ are separate (D6b-d).
// ===========================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace c2pool::v37n::xmr::o2 {

// The reason prefix of a native miss. FinalizeConnect classifies it as a
// TRANSIENT fetch failure (retry, then HOLD past the retry bound).
inline constexpr const char* kNativeHoldPrefix = "native-hold:";

struct CbaBlockSourceOptions {
    bool compare_monerod = false;   // --cba-monerod-compare: compare-only oracle (never decides)
    bool rpc_fallback    = false;   // --cba-monerod-fallback: a native miss asks monerod (explicit only)
};

struct CbaBlockSourceStats {
    std::uint64_t native_hits         = 0;   // blobs served by the native index
    std::uint64_t native_hold         = 0;   // native misses HELD (retried natively)
    std::uint64_t rpc_calls           = 0;   // monerod get_block calls made by this source (any reason)
    std::uint64_t rpc_failed          = 0;   // of those, transport/JSON/blob failures
    std::uint64_t compare_equal       = 0;   // oracle: monerod blob == native blob
    std::uint64_t compare_mismatch    = 0;   // oracle: monerod blob != native blob (native still booked)
    std::uint64_t compare_unavailable = 0;   // oracle: monerod could not answer
    std::uint64_t fallback_used       = 0;   // native misses answered by monerod (explicit fallback)
    std::uint64_t refetch_requested   = 0;   // COLD-BOOT: native misses that asked the node to refetch the body (levin)
    std::uint64_t refetch_restored    = 0;   // COLD-BOOT: blocks that booked from a body restored after a refetch
    std::uint64_t refetch_exhausted   = 0;   // COLD-BOOT: blocks past refetch_bound (HOLD, as before)
};

class CbaBlockSource {
public:
    // true + blob when the native index holds the block's body.
    using NativeFn = std::function<bool(const std::string& bid_hex, std::vector<std::uint8_t>& blob)>;
    // true + blob, or false + a complete reason ("get_block(...): ...").
    using RpcFn    = std::function<bool(const std::string& bid_hex, std::vector<std::uint8_t>& blob, std::string& why)>;
    using LogFn    = std::function<void(const std::string&)>;
    // COLD-BOOT: ask the native node to fetch this block's body again (levin).
    using RefetchFn = std::function<void(const std::string& bid_hex)>;

    CbaBlockSource(NativeFn native, RpcFn rpc, CbaBlockSourceOptions opts = {}, LogFn log = {})
        : native_(std::move(native)), rpc_(std::move(rpc)), opts_(opts), log_(std::move(log)) {}

    bool native_mode() const noexcept { return static_cast<bool>(native_); }
    const CbaBlockSourceOptions& options() const noexcept { return opts_; }
    const CbaBlockSourceStats&   stats()   const noexcept { return st_; }
    std::size_t holding_now() const noexcept { return hold_n_.size(); }

    // COLD-BOOT: arm the refetch safety net (native mode only; bound 0 = off).
    void set_refetch(RefetchFn fn, std::uint64_t bound) { refetch_ = std::move(fn); refetch_bound_ = bound; }
    bool refetch_armed() const noexcept { return static_cast<bool>(refetch_) && refetch_bound_ > 0; }

    // The one fetch. false + `why` is a transient failure (the caller retries).
    bool fetch(const std::string& bid_hex, std::vector<std::uint8_t>& blob, std::string& why) {
        if (!native_mode()) return rpc_fetch_(bid_hex, blob, why);   // legacy: monerod decides
        blob.clear();
        if (native_(bid_hex, blob) && !blob.empty()) {
            ++st_.native_hits;
            if (refetch_n_.erase(bid_hex)) {
                ++st_.refetch_restored;
                say_("cba-native: block " + bid_hex.substr(0, 12) + "… body RESTORED by refetch -> booked from the native index");
            }
            if (hold_n_.erase(bid_hex)) say_("cba-native: block " + bid_hex.substr(0, 12) + "… now held by the native index -> HOLD resolved");
            if (opts_.compare_monerod) compare_(bid_hex, blob);
            return true;
        }
        blob.clear();
        if (opts_.rpc_fallback) {
            ++st_.fallback_used;
            say_("cba-native: block " + bid_hex.substr(0, 12) + "… NOT in the native index -> explicit monerod fallback (--cba-monerod-fallback)");
            return rpc_fetch_(bid_hex, blob, why);
        }
        ++st_.native_hold;
        const std::uint64_t n = ++hold_n_[bid_hex];
        if (refetch_armed()) {
            std::uint64_t& r = refetch_n_[bid_hex];
            if (r < refetch_bound_) {
                ++r; ++st_.refetch_requested;
                refetch_(bid_hex);
                why = std::string(kNativeHoldPrefix) + " block " + bid_hex.substr(0, 12) +
                      " body is not held by the native chain index (evicted before booking, or not connected yet)"
                      " -- REFETCH requested over levin (" + std::to_string(r) + "/" + std::to_string(refetch_bound_) +
                      "), retried natively (no monerod fallback)";
                if (r == 1 || r % 20 == 0)
                    say_("cba-native refetch: block " + bid_hex.substr(0, 12) + "… not in the native chain index -> body refetch requested (" +
                         std::to_string(r) + "/" + std::to_string(refetch_bound_) + ", refetches total=" +
                         std::to_string(st_.refetch_requested) + ")");
                while (refetch_n_.size() > 4096) refetch_n_.erase(refetch_n_.begin());
                while (hold_n_.size() > 4096) hold_n_.erase(hold_n_.begin());
                return false;
            }
            if (r == refetch_bound_) {
                ++r; ++st_.refetch_exhausted;
                say_("cba-ALARM refetch_exhausted: block " + bid_hex.substr(0, 12) + "… body still not restored after " +
                     std::to_string(refetch_bound_) + " refetch requests -- HELD and retried natively");
            }
        }
        why = std::string(kNativeHoldPrefix) + " block " + bid_hex.substr(0, 12) +
              " is not held by the native chain index (older than its retained bodies, pruned, or not connected yet)"
              " -- HELD, retried natively (no monerod fallback)";
        if (n == 1 || n % 100 == 0)
            say_("cba-ALARM native_hold: block " + bid_hex.substr(0, 12) + "… attempt #" + std::to_string(n) +
                 " is not in the native chain index -- HELD and retried natively, never read from monerod (holds total=" +
                 std::to_string(st_.native_hold) + ")");
        while (hold_n_.size() > 4096) hold_n_.erase(hold_n_.begin());
        return false;
    }

private:
    bool rpc_fetch_(const std::string& bid_hex, std::vector<std::uint8_t>& blob, std::string& why) {
        ++st_.rpc_calls;
        if (!rpc_) { ++st_.rpc_failed; why = "get_block(" + bid_hex.substr(0, 12) + "): no monerod transport"; return false; }
        if (!rpc_(bid_hex, blob, why)) { ++st_.rpc_failed; blob.clear(); return false; }
        return true;
    }

    void compare_(const std::string& bid_hex, const std::vector<std::uint8_t>& native_blob) {
        std::vector<std::uint8_t> theirs;
        std::string why;
        if (!rpc_fetch_(bid_hex, theirs, why)) {
            ++st_.compare_unavailable;
            return;
        }
        if (theirs == native_blob) { ++st_.compare_equal; return; }
        ++st_.compare_mismatch;
        say_("cba-ALARM compare_mismatch: block " + bid_hex.substr(0, 12) + "… native blob (" + std::to_string(native_blob.size()) +
             " B) != monerod get_block blob (" + std::to_string(theirs.size()) + " B) -- the NATIVE blob is booked (monerod is compare-only)");
    }

    void say_(const std::string& s) { if (log_) log_(s); }

    NativeFn              native_;
    RpcFn                 rpc_;
    CbaBlockSourceOptions opts_;
    LogFn                 log_;
    CbaBlockSourceStats   st_;
    std::map<std::string, std::uint64_t> hold_n_;   // bid -> consecutive native misses (cleared on hit)
    RefetchFn             refetch_;                  // COLD-BOOT (unset = master's HOLD-only behaviour)
    std::uint64_t         refetch_bound_ = 0;
    std::map<std::string, std::uint64_t> refetch_n_; // bid -> refetch requests made (cleared on hit)
};

} // namespace c2pool::v37n::xmr::o2
