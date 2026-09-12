// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/xmr_p2p_dos.hpp
//
// Wave 1, component C1c: the per-peer DoS budget -- token buckets on the
// inbound message classes, the fail score, and the ban policy.
//
// WHAT THIS DEFENDS, precisely. C1a already refuses a frame whose declared body
// exceeds the per-command cap, before a byte of body is read (levin_codec.hpp
// max_body_bytes). That stops one huge message. It does not stop a peer that
// sends ten thousand PERFECTLY LEGAL small ones, and the cost of those is not
// bandwidth -- it is the work each class forces downstream:
//
//   * NOTIFY_NEW_FLUFFY_BLOCK (2008) / NEW_BLOCK (2001). Honest rate is about
//     one per 120 s per peer, plus orphans. Each unknown-parent block costs the
//     index a parse and, if it survives the cheap gates, a RandomX hash at
//     ~10-25 ms. An attacker mints unknown-parent blocks for free. THE BUCKET
//     IS THE RATE LIMIT ON THE CHEAP GATES; the RandomX grant itself is a
//     second, separate token (wire/xmr_carrier_dos_budget.hpp) that C2 spends,
//     and a completed hash below target is a 24 h ban on its own -- the only
//     fault in the table that reaches the threshold in one step, because an
//     unmet target on a finished hash is incontrovertible.
//   * NOTIFY_NEW_TRANSACTIONS (2002). Counted in TRANSACTIONS, not frames: a
//     peer that batches 500 txs into one frame has spent 500 tokens, which is
//     what a frame-counting bucket would have missed entirely.
//   * Byte rate, across everything. 2 MiB/s sustained per peer with a 16 MiB
//     burst -- above any honest sync, far below monerod's own 32 MB/s aggregate
//     down-limit, and the thing that bounds a slow-drip flood no single class
//     bucket would notice.
//   * SERVING requests (2003 / 2006 / 2009 / 2010) from the peer. These cost US
//     index reads and outbound bytes. A peer is entitled to sync from us; it is
//     not entitled to re-sync continuously.
//
// TOKENS ARE REUSED, NOT REINVENTED. The bucket is
// c2pool::xmr::TokenBucket from wire/xmr_carrier_dos_budget.hpp -- the same
// monotone-injected-clock leaky bucket the W3 carrier lane already meters
// RandomX with. A second implementation of the same arithmetic is a divergence
// waiting to happen. It takes nanoseconds; this layer speaks milliseconds, so
// the conversion happens once, at the boundary, in ms_to_ns().
//
// EXHAUSTION IS A DEFER, NOT A CRIME -- with one exception. Running a bucket dry
// means "you are going faster than I will follow"; the frame is DROPPED and the
// peer is scored a single soft point. That distinction matters: a peer on a
// fast link legitimately outruns us during a sync burst, and banning it would
// cost us our best peer. What DOES ban is the fault table below --
// structurally impossible input, a lie, or a proven-bad PoW.
//
// THE FAULT TABLE is monerod's own shape (P2P_IP_FAILS_BEFORE_BLOCK = 10 points
// to a ban, P2P_IP_BLOCKTIME = 24 h) with the points assigned by how
// unambiguous the fault is:
//
//     fault                                   points   why
//     ------------------------------------   ------   -----------------------
//     BadPow (completed hash below target)        10   incontrovertible
//     WrongNetwork / signature mismatch           10   cannot be an accident
//     Malformed body on a command we own          10   ditto
//     Unsolicited response / 2004 / 2007           5   protocol violation
//     BadChainEntry (ids that do not link)         5   a lie or a bug
//     Oversize peerlist (> 250)                    5   ignores the wire cap
//     Duplicate tx blob inside one batch           2   sloppy or probing
//     Unknown-parent block spam                    1   free for both sides
//     Bucket exhaustion (any class)                1   a defer, see above
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record.
//
// Header-only, STL plus the existing wire token bucket.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>

#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/levin_codec.hpp"
#include "impl/xmr/native/p2p/levin_invoke_queue.hpp"   // Millis
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"     // TokenBucket, nanos_t

namespace c2pool::xmr::native::p2p {

using levin::Millis;
using ::c2pool::xmr::TokenBucket;
using nanos_t = ::c2pool::xmr::nanos_t;

// TokenBucket uses `last == 0` as its "not yet primed" sentinel and swallows
// the advance that carries it. Our millisecond clocks are PER-OBJECT EPOCHS
// that start at zero (LevinLink::now_ms, XmrPeerPool::now_ms), so a naive
// ms * 1e6 would hand the bucket a literal 0 on the first frame, leave it
// unprimed, and then refill from a stale origin -- a peer's budget would never
// actually recover. Offsetting the whole clock by one second puts the sentinel
// out of reach without changing any rate: only differences are ever used.
inline constexpr nanos_t DOS_CLOCK_ORIGIN_NS = 1'000'000'000;

inline constexpr nanos_t ms_to_ns(Millis ms) noexcept {
    return DOS_CLOCK_ORIGIN_NS + static_cast<nanos_t>(ms) * 1'000'000;
}

// TokenBucket grants ONE token per try_take(). Byte and transaction budgets are
// charged in bulk, so this is the multi-token form, written against the same
// public fields rather than as a second bucket type.
inline bool bucket_take(TokenBucket& b, double n, nanos_t now) {
    b.advance(now);
    if (b.tokens + 1e-9 >= n) { b.tokens -= n; return true; }
    return false;
}

// ---------------------------------------------------------------------------
// The faults, and what each one costs.
// ---------------------------------------------------------------------------
enum class DosFault : std::uint8_t {
    None = 0,
    BucketExhausted,      // 1  -- a defer
    UnknownParentBlock,   // 1
    DuplicateTxInBatch,   // 2
    OversizePeerlist,     // 5
    BadChainEntry,        // 5
    Unsolicited,          // 5
    MalformedBody,        // 10
    WrongNetwork,         // 10
    BadPow,               // 10
};

inline const char* to_string(DosFault f) noexcept {
    switch (f) {
        case DosFault::None:               return "none";
        case DosFault::BucketExhausted:    return "bucket-exhausted";
        case DosFault::UnknownParentBlock: return "unknown-parent-block";
        case DosFault::DuplicateTxInBatch: return "duplicate-tx-in-batch";
        case DosFault::OversizePeerlist:   return "oversize-peerlist";
        case DosFault::BadChainEntry:      return "bad-chain-entry";
        case DosFault::Unsolicited:        return "unsolicited";
        case DosFault::MalformedBody:      return "malformed-body";
        case DosFault::WrongNetwork:       return "wrong-network";
        case DosFault::BadPow:             return "bad-pow";
    }
    return "?";
}

inline constexpr std::uint32_t fault_points(DosFault f) noexcept {
    switch (f) {
        case DosFault::None:               return 0;
        case DosFault::BucketExhausted:    return 1;
        case DosFault::UnknownParentBlock: return 1;
        case DosFault::DuplicateTxInBatch: return 2;
        case DosFault::OversizePeerlist:   return 5;
        case DosFault::BadChainEntry:      return 5;
        case DosFault::Unsolicited:        return 5;
        case DosFault::MalformedBody:      return 10;
        case DosFault::WrongNetwork:       return 10;
        case DosFault::BadPow:             return 10;
    }
    return 0;
}

// Which faults cost the CONNECTION even below the ban line: the ones after
// which the peer has nothing useful left to say on this socket -- a body we
// cannot parse, a network id that is not ours, a response nobody asked for, a
// chain span whose ids do not link, a peerlist over the wire cap.
//
// The cheap, RECOVERABLE faults are deliberately not on this list. A duplicate
// blob inside one relay batch, a block whose parent we do not know, and an
// exhausted bucket are all things an honest peer does: the offending frame is
// dropped and the points are recorded, and the connection lives. Closing on
// them would mean one sloppy batch costs us a working peer -- and at the pool's
// scale, losing peers is the failure mode that starves the node, not the one
// that protects it.
inline constexpr bool fault_closes_connection(DosFault f) noexcept {
    switch (f) {
        case DosFault::MalformedBody:
        case DosFault::WrongNetwork:
        case DosFault::BadPow:
        case DosFault::Unsolicited:
        case DosFault::BadChainEntry:
        case DosFault::OversizePeerlist:
            return true;
        case DosFault::None:
        case DosFault::BucketExhausted:
        case DosFault::UnknownParentBlock:
        case DosFault::DuplicateTxInBatch:
            return false;
    }
    return false;
}

// The C2/C3-facing PeerFault maps onto the table above, so a penalize() call
// from the verify thread and a fault raised on the io thread cost the same.
inline constexpr DosFault fault_of(PeerFault f) noexcept {
    switch (f) {
        case PeerFault::BadPow:          return DosFault::BadPow;
        case PeerFault::BadData:         return DosFault::MalformedBody;
        case PeerFault::BadChainEntry:   return DosFault::BadChainEntry;
        case PeerFault::Unresponsive:    return DosFault::Unsolicited;
        case PeerFault::VersionMismatch: return DosFault::WrongNetwork;
    }
    return DosFault::None;
}

// What the caller must do with the frame.
enum class DosAction : std::uint8_t {
    Accept = 0,   // pass it upward
    Drop,         // discard this frame, keep the connection
    Disconnect,   // close, but the address stays dialable
    Ban,          // close and block the address (and its /16) for ban_ms
};

inline const char* to_string(DosAction a) noexcept {
    switch (a) {
        case DosAction::Accept:     return "accept";
        case DosAction::Drop:       return "drop";
        case DosAction::Disconnect: return "disconnect";
        case DosAction::Ban:        return "ban";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Budget sizing. Every number is a per-instance knob; the defaults are the C1
// design lens §6.2 table.
// ---------------------------------------------------------------------------
struct DosConfig {
    // Bytes, all inbound frames.
    double bytes_capacity = 16.0 * 1024 * 1024;   // burst
    double bytes_refill   =  2.0 * 1024 * 1024;   // per second, sustained

    // Block pushes (2001 / 2008). Honest: ~1 per 120 s.
    double block_capacity = 8.0;
    double block_refill   = 0.1;

    // Transactions (2002), counted per TRANSACTION.
    double tx_capacity = 512.0;
    double tx_refill   = 64.0;

    // Requests the peer makes OF US (2003 / 2006 / 2009 / 2010).
    double serve_capacity = 16.0;
    double serve_refill   = 0.5;

    std::uint32_t fails_before_ban = P2P_FAILS_BEFORE_BAN_DEFAULT;
    Millis        ban_ms           = 86'400'000;   // P2P_IP_BLOCKTIME
    Millis        score_forget_ms  = 3'600'000;    // P2P_FAILED_ADDR_FORGET_SECONDS

    // Below this the peer is closed rather than merely drained -- a peer that
    // has been exhausting its budget for a whole forget window is not a fast
    // link, it is a flood.
    std::uint32_t exhaustions_before_disconnect = 64;

    static constexpr std::uint32_t P2P_FAILS_BEFORE_BAN_DEFAULT = 10;
};

// ---------------------------------------------------------------------------
// One peer's budget. Lives on the io thread beside its link.
// ---------------------------------------------------------------------------
class PeerDosGuard {
public:
    PeerDosGuard() : PeerDosGuard(DosConfig{}) {}

    explicit PeerDosGuard(const DosConfig& cfg)
        : cfg_(cfg)
        , bytes_(cfg.bytes_capacity, cfg.bytes_refill)
        , blocks_(cfg.block_capacity, cfg.block_refill)
        , txs_(cfg.tx_capacity, cfg.tx_refill)
        , serves_(cfg.serve_capacity, cfg.serve_refill) {}

    const DosConfig& config() const noexcept { return cfg_; }

    // -----------------------------------------------------------------------
    // Charge a frame. `units` is what the command's own bucket counts: the
    // number of transactions for 2002, and 1 for everything else. Bytes are
    // charged on EVERY command, including the ones that have no class bucket.
    //
    // Order matters and is deliberate: the byte bucket is charged first, so a
    // flood of oversized-but-legal frames is caught even when its command class
    // has budget left.
    // -----------------------------------------------------------------------
    DosAction on_frame(std::uint32_t cmd, std::size_t body_bytes, std::size_t units,
                       Millis now, DosFault& fault_out) {
        const nanos_t t = ms_to_ns(now);
        fault_out = DosFault::None;

        if (!bucket_take(bytes_, static_cast<double>(body_bytes), t))
            return exhausted(fault_out, now);

        switch (cmd) {
            case levin::CMD_NEW_BLOCK:
            case levin::CMD_NEW_FLUFFY_BLOCK:
                if (!bucket_take(blocks_, 1.0, t)) return exhausted(fault_out, now);
                break;
            case levin::CMD_NEW_TRANSACTIONS:
                if (!bucket_take(txs_, static_cast<double>(units == 0 ? 1 : units), t))
                    return exhausted(fault_out, now);
                break;
            case levin::CMD_REQUEST_GET_OBJECTS:
            case levin::CMD_REQUEST_CHAIN:
            case levin::CMD_REQUEST_FLUFFY_MISSING_TX:
            case levin::CMD_GET_TXPOOL_COMPLEMENT:
                if (!bucket_take(serves_, 1.0, t)) return exhausted(fault_out, now);
                break;
            default:
                break;   // handshake, timed sync, ping: the byte bucket is enough
        }
        ++accepted_;
        return DosAction::Accept;
    }

    // -----------------------------------------------------------------------
    // Raise a fault. Returns what to do with the connection.
    // -----------------------------------------------------------------------
    DosAction on_fault(DosFault f, Millis now) {
        forget_stale(now);
        const std::uint32_t pts = fault_points(f);
        if (pts == 0) return DosAction::Accept;
        score_ += pts;
        last_fault_ms_ = now;
        ++faults_;
        if (score_ >= cfg_.fails_before_ban) return DosAction::Ban;
        if (fault_closes_connection(f)) return DosAction::Disconnect;
        return DosAction::Drop;
    }

    // --- observation --------------------------------------------------------
    std::uint32_t score() const noexcept { return score_; }
    std::uint64_t faults() const noexcept { return faults_; }
    std::uint64_t accepted() const noexcept { return accepted_; }
    std::uint32_t exhaustions() const noexcept { return exhaustions_; }

    double bytes_level(Millis now)  { return bytes_.level(ms_to_ns(now)); }
    double blocks_level(Millis now) { return blocks_.level(ms_to_ns(now)); }
    double txs_level(Millis now)    { return txs_.level(ms_to_ns(now)); }
    double serves_level(Millis now) { return serves_.level(ms_to_ns(now)); }

private:
    DosAction exhausted(DosFault& fault_out, Millis now) {
        fault_out = DosFault::BucketExhausted;
        ++exhaustions_;
        const DosAction a = on_fault(DosFault::BucketExhausted, now);
        if (a == DosAction::Drop && exhaustions_ >= cfg_.exhaustions_before_disconnect)
            return DosAction::Disconnect;
        return a;
    }

    // `score_ == 0` already means "nothing to forget", so last_fault_ms_ needs
    // no second sentinel -- and must not have one, or a fault raised at
    // millisecond zero of this connection's epoch would never decay.
    void forget_stale(Millis now) {
        if (score_ == 0) return;
        if (now >= last_fault_ms_ + cfg_.score_forget_ms) {
            score_ = 0;
            exhaustions_ = 0;
        }
    }

    DosConfig   cfg_;
    TokenBucket bytes_, blocks_, txs_, serves_;
    std::uint32_t score_ = 0;
    std::uint32_t exhaustions_ = 0;
    std::uint64_t faults_ = 0;
    std::uint64_t accepted_ = 0;
    Millis        last_fault_ms_ = 0;
};

} // namespace c2pool::xmr::native::p2p
