// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_freshness.hpp
//
// ABSENCE IS NOT ZERO. The per-chain staleness clock, and the seven words the
// monitor is allowed to use to describe a source.
//
// ---------------------------------------------------------------------------
// THE FAILURE THIS FILE EXISTS TO PREVENT
// ---------------------------------------------------------------------------
// A dashboard that reads a counter and prints it has one catastrophic failure
// mode, and it is silent: the source dies, the counter stops moving, the panel
// keeps printing the last number (or a zero) in the same font as a live one,
// and the reader believes it. Nothing crashes. Nothing logs. The screen simply
// lies, and it lies most convincingly about the number that matters most --
// "peers 0, blocks 0" on a chain that is fine but which WE are no longer
// connected to is indistinguishable, on an ordinary dashboard, from "the chain
// is quiet".
//
// Those two readings must never share a rendering, so every number the monitor
// prints carries one of two things beside it:
//
//   * a LIVENESS word plus an AGE -- how long ago the fact was established, or
//   * a literal `--`, meaning WE HAVE NO BASIS for a number here.
//
// Zero is reserved for a measurement that came out zero. It is never used for
// "we did not measure".
//
// ---------------------------------------------------------------------------
// THE SEVEN STATES, AND WHY THEY ARE SEVEN
// ---------------------------------------------------------------------------
// Four of them (DARK / DIAL / WARM / LIVE) already existed as the monitor's
// ChainStatus and described the WARM-UP of a connection. They cannot describe a
// connection that was healthy and stopped being healthy, which is the case a
// long run actually meets, so three more are added and the enum is renamed to
// what it now measures:
//
//   DARK   never connected, nothing in flight. Age = time since this session
//          started. Distinct from DOWN on purpose: a chain we never reached may
//          be a bad seed list; a chain we lost is a network event.
//   DIAL   sockets in flight or addresses queued, no handshake yet.
//   DOWN   we HAD peers on this chain and now have none. The numbers on the
//          panel are last-known, not current, and are marked as such.
//   WARM   handshaken and receiving, but fewer than two live heights -- the
//          read model refuses to time the chain and so does the panel.
//   QUIET  handshaken, but the tip has not moved for longer than ordinary
//          variance explains. Not yet an error; worth a colour.
//   STALE  handshaken, and the tip has not moved for so long that the panel's
//          numbers should not be read as current.
//   LIVE   handshaken, timing the chain, tip moving inside expectation.
//
// QUIET and STALE are thresholds on the SAME clock, not two clocks. The clock
// is `tip_advanced_at_ms`: the last instant the sidechain tip height actually
// increased. Receiving a duplicate, a backfilled parent or a peer-list does not
// touch it, because none of those is evidence that the chain is advancing.
//
// ---------------------------------------------------------------------------
// WHY THE THRESHOLDS ARE MULTIPLES WITH A FLOOR
// ---------------------------------------------------------------------------
// A sidechain block arrival is close to Poisson, so the gap between heights has
// a long tail: on a 10-second chain, a 30-second gap happens roughly one time
// in twenty and means nothing at all. A fixed 30-second "stale" threshold would
// therefore cry wolf several times an hour, and a dashboard that cries wolf is
// a dashboard whose warnings get ignored -- which is the same failure as not
// warning at all, arrived at politely.
//
// So the thresholds are multiples of the chain's OWN target block time (nano
// targets 30 s and must not be called quiet at 45 s), with a floor so that a
// fast chain is not called quiet inside ordinary variance either. At the
// defaults below, a 10 s chain goes QUIET at 60 s (P(no block) ~ 0.25%) and
// STALE at 180 s (~ 1 in 400 000); a 30 s chain at 120 s and 360 s.
//
// ---------------------------------------------------------------------------
// NO CLOCK, NO SOCKET, NO SYSCALL
// ---------------------------------------------------------------------------
// The tracker is fed `now` and never reads it, exactly like the renderer, which
// is what lets a KAT drive a chain through all seven states in fixed
// milliseconds with no sleeping and no network. STL only, deliberately
// POSIX-free: this header is compiled by the offline render KAT.
//
// The `now` it is fed is WALL-CLOCK (p2p::wall_ms()), for the reason set out on
// FreshnessView below: these instants outlive the process that recorded them.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstddef>

namespace c2pool::xmr::p2pool {

// ---------------------------------------------------------------------------
// The seven words.
// ---------------------------------------------------------------------------
enum class Liveness : std::uint8_t {
    Dark = 0,     // never connected, nothing in flight
    Dialling,     // sockets in flight, no handshake yet
    Down,         // was connected, now has no peers
    Warming,      // handshaken and receiving, too few live heights to time
    Quiet,        // handshaken, tip has not moved for longer than usual
    Stale,        // handshaken, tip has not moved for far longer than usual
    Live,         // handshaken, timing the chain, tip moving
};

inline const char* to_string(Liveness s) noexcept {
    switch (s) {
        case Liveness::Dark:     return "DARK";
        case Liveness::Dialling: return "DIAL";
        case Liveness::Down:     return "DOWN";
        case Liveness::Warming:  return "WARM";
        case Liveness::Quiet:    return "QUIET";
        case Liveness::Stale:    return "STALE";
        case Liveness::Live:     return "LIVE";
    }
    return "?";
}

// True when the panel's chain numbers are NOT to be read as current. Used by
// the renderer to decide whether a figure gets an "as of" age beside it, and by
// the aggregation to decide whether a chain counts as reporting.
inline bool is_degraded(Liveness s) noexcept {
    return s != Liveness::Live && s != Liveness::Warming;
}

// ---------------------------------------------------------------------------
// Thresholds. Multiples of the chain's own target, with a floor; see the header.
// ---------------------------------------------------------------------------
struct FreshnessThresholds {
    std::uint64_t quiet_mult      = 4;
    std::uint64_t stale_mult      = 12;
    std::uint64_t quiet_floor_ms  = 60000;
    std::uint64_t stale_floor_ms  = 180000;

    std::uint64_t quiet_ms(std::uint64_t target_s) const noexcept {
        const std::uint64_t m = quiet_mult * target_s * 1000ull;
        return m > quiet_floor_ms ? m : quiet_floor_ms;
    }
    std::uint64_t stale_ms(std::uint64_t target_s) const noexcept {
        const std::uint64_t m = stale_mult * target_s * 1000ull;
        return m > stale_floor_ms ? m : stale_floor_ms;
    }
};

// ---------------------------------------------------------------------------
// One chain's freshness facts, as absolute instants. Plain data: it is what the
// tracker hands the renderer, what goes into the state file, and what comes
// back out of it, so a restored chain is classified by exactly the code that
// classifies a live one -- against the CURRENT clock, which is what makes a
// week-old file render as STALE rather than as a healthy chain.
//
// EVERY INSTANT HERE IS WALL-CLOCK MILLISECONDS SINCE THE UNIX EPOCH --
// p2p::wall_ms(), never p2p::steady_ms(). That is not a stylistic choice: these
// five numbers are written to the state file by one process and subtracted from
// another process's clock, on another boot and sometimes on another machine, so
// the only clock that can carry them is the one both processes agree on. A
// monotonic ms-since-boot instant makes the subtraction meaningless across a
// reboot and renders a stale chain as "LIVE as of 0s"; see the two-clock note
// at the top of p2pool_observer.hpp for the full account of that failure.
//
// The durations this file compares them against -- the QUIET and STALE
// thresholds -- are elapsed times and belong to neither clock: a threshold of
// 180 000 ms is 180 000 ms on both.
// ---------------------------------------------------------------------------
struct FreshnessView {
    bool          known          = false;  // false: no freshness was recorded at all
    bool          have_data      = false;  // at least one sidechain block is held
    bool          ever_connected = false;  // a handshake completed at some point
    std::uint64_t started_at_ms  = 0;      // wall: chain started being watched
    std::uint64_t tip_at_ms      = 0;      // wall: the tip HEIGHT last increased
    std::uint64_t rx_at_ms       = 0;      // wall: a new distinct block last arrived
    std::uint64_t up_since_ms    = 0;      // wall; 0 when no peers are up
    std::uint64_t down_since_ms  = 0;      // wall; 0 while peers are up

    // Age helpers. Clamped at zero: a state file written by a machine whose
    // clock is ahead of ours must produce "0s", never a 500-million-second age
    // from an unsigned subtraction that wrapped.
    static std::uint64_t age(std::uint64_t now, std::uint64_t then) noexcept {
        return (then && now > then) ? now - then : 0;
    }

    // THE CLAMP IS NOT ENOUGH ON ITS OWN. Wall time steps backwards for two
    // ordinary reasons -- an NTP correction on this host, and a file written by
    // a host whose clock is ahead of it -- and in both cases age() above returns
    // a perfectly confident 0, which reads on the panel as "this happened just
    // now". That is the same class of lie as the one the clock split fixes, in
    // miniature. So a recorded instant that lies in OUR FUTURE is reported as
    // such, and the renderer marks the age it clamped with a `+` rather than
    // printing a bare "0s".
    static bool ahead(std::uint64_t now, std::uint64_t then) noexcept {
        return then != 0 && then > now;
    }
    // True when ANY instant this view holds is in the future of `now`.
    bool clock_ahead(std::uint64_t now) const noexcept {
        return ahead(now, started_at_ms) || ahead(now, tip_at_ms) || ahead(now, rx_at_ms)
            || ahead(now, up_since_ms)   || ahead(now, down_since_ms);
    }

    std::uint64_t tip_age_ms(std::uint64_t now) const noexcept { return age(now, tip_at_ms); }
    std::uint64_t rx_age_ms(std::uint64_t now)  const noexcept { return age(now, rx_at_ms); }
    std::uint64_t up_ms(std::uint64_t now)      const noexcept { return age(now, up_since_ms); }
    std::uint64_t down_ms(std::uint64_t now)    const noexcept { return age(now, down_since_ms); }
};

// ---------------------------------------------------------------------------
// THE CLASSIFIER. One function, no state, so the same seven-way decision is
// made for a live chain, for a chain restored from the state file, and for the
// KAT's synthetic fixtures.
//
// ORDER MATTERS, and the order is "what does the reader most need to know":
// having no peers outranks any statement about the tip, because a tip age
// computed while disconnected measures our own outage and not the chain. And
// STALE outranks a computable cadence: a cadence figure derived from blocks
// that all arrived four minutes ago is arithmetically fine and editorially a
// lie.
// ---------------------------------------------------------------------------
inline Liveness classify(const FreshnessView& f, std::size_t peers_up, std::size_t sockets,
                         std::size_t queued, bool cadence_ok, std::uint64_t target_s,
                         std::uint64_t now, const FreshnessThresholds& th = {}) {
    if (peers_up == 0) {
        if (f.known && f.ever_connected) return Liveness::Down;
        if (sockets > 0 || queued > 0)   return Liveness::Dialling;
        return Liveness::Dark;
    }
    if (!f.known)      return cadence_ok ? Liveness::Live : Liveness::Warming;
    if (!f.have_data)  return Liveness::Warming;

    const std::uint64_t age = f.tip_age_ms(now);
    if (age >= th.stale_ms(target_s)) return Liveness::Stale;
    if (age >= th.quiet_ms(target_s)) return Liveness::Quiet;
    return cadence_ok ? Liveness::Live : Liveness::Warming;
}

// ---------------------------------------------------------------------------
// THE TRACKER. Polled rather than hooked.
//
// It is fed a sample of the read model on every turn of the shared loop instead
// of being called back from inside the observer. That is deliberate: a callback
// would have to be threaded through Observer, PeerSession and the block sink
// for a fact -- "did the tip height go up" -- that is already visible from
// outside, and every one of those hooks is a place for a chain's clock to be
// updated by another chain's event. Sampling at the loop rate (four times a
// second) resolves a threshold measured in tens of seconds with room to spare.
// ---------------------------------------------------------------------------
class FreshnessTracker {
public:
    // Called once when the chain starts being watched. Seeds both clocks to
    // `now` -- WALL time, as everywhere in this file -- so a chain that never
    // receives anything reports "nothing has moved for 3m10s" rather than an
    // age measured from the epoch.
    void start(std::uint64_t now) {
        v_.known         = true;
        v_.started_at_ms = now;
        v_.tip_at_ms     = now;
        v_.rx_at_ms      = now;
        v_.down_since_ms = now;        // not up yet; DARK vs DOWN is ever_connected
    }

    // One observation of the live model. Everything it needs is a query the
    // read model and the observer already expose.
    //
    // THE FRONTIER RULE, inherited from the read model and for the same reason.
    // The FIRST tip we learn was FETCHED, not watched arriving: treating it as
    // an advance would restart the staleness clock at start-up and hide a chain
    // that has been frozen for an hour behind a fresh-looking "tip as of 0s".
    // So the first height seen only sets the baseline, and the clock keeps
    // running from when this chain started being watched until a height
    // genuinely arrives above it. The error is one-sided on purpose: this can
    // make a chain look older than it is, never younger.
    void sample(std::uint64_t tip_height, std::size_t distinct, std::size_t peers_up,
                std::size_t sockets, std::size_t queued, std::uint64_t now) {
        if (!v_.known) start(now);

        if (distinct > last_distinct_) {
            last_distinct_ = distinct;
            v_.rx_at_ms    = now;
            v_.have_data   = true;
            if (!baseline_) { baseline_ = true; last_tip_ = tip_height; }
        }
        if (baseline_ && tip_height > last_tip_) { last_tip_ = tip_height; v_.tip_at_ms = now; }
        if (peers_up > 0) {
            if (!v_.up_since_ms) v_.up_since_ms = now;
            v_.down_since_ms  = 0;
            v_.ever_connected = true;
        } else {
            if (!v_.down_since_ms) v_.down_since_ms = now;
            v_.up_since_ms = 0;
        }
        peers_up_ = peers_up;
        sockets_  = sockets;
        queued_   = queued;
    }

    const FreshnessView& view() const noexcept { return v_; }

    std::size_t peers_up() const noexcept { return peers_up_; }
    std::size_t sockets()  const noexcept { return sockets_; }
    std::size_t queued()   const noexcept { return queued_; }

    // Carry the previous session's clock in, from the state file.
    //
    // EXACTLY ONE THING SURVIVES A RESTART: when the chain's tip last moved.
    // That is a fact about the CHAIN and stays true across our own restart, and
    // carrying it is what stops a monitor restarted onto a frozen chain from
    // reporting "tip as of 0s" for the first two minutes of its life.
    //
    // `have_data` deliberately does NOT survive. It is the flag that decides
    // whether the panel prints a number or a `--`, and the new session's read
    // model is empty: carrying it would make an empty model render as a tip
    // height of zero -- manufacturing the precise lie this file prevents. What
    // the previous session knew is shown separately, on the carry row, labelled
    // with its age. Peer state does not survive either: a restarted process has
    // no peers, and that is a fact, not a gap.
    //
    // The carried instant is taken as the EARLIER of the two, never the later.
    // start() has just seeded both clocks to `now`, and "the tip last moved
    // when this process happened to start" is an assertion nobody measured;
    // the previous session's instant is one somebody did. Taking the earlier
    // value can only ever make a chain look staler than it is, which is the
    // side of this trade-off a monitor is allowed to be wrong on.
    void carry_in(const FreshnessView& prev) {
        if (!prev.known) return;
        if (prev.tip_at_ms && prev.tip_at_ms < v_.tip_at_ms) v_.tip_at_ms = prev.tip_at_ms;
        if (prev.rx_at_ms  && prev.rx_at_ms  < v_.rx_at_ms)  v_.rx_at_ms  = prev.rx_at_ms;
    }

private:
    FreshnessView v_;
    bool          baseline_      = false;
    std::uint64_t last_tip_      = 0;
    std::size_t   last_distinct_ = 0;
    std::size_t   peers_up_      = 0;
    std::size_t   sockets_       = 0;
    std::size_t   queued_        = 0;
};

} // namespace c2pool::xmr::p2pool
