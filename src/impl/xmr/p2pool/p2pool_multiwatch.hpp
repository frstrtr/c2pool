// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_multiwatch.hpp
//
// THREE SIDECHAINS, ONE poll(). And the terminal, which is the other half of
// "all-in-one" and the half that is easy to get wrong.
//
// ---------------------------------------------------------------------------
// WHY NOT THREE OBSERVERS, THREE LOOPS
// ---------------------------------------------------------------------------
// An Observer is one sidechain by construction: one consensus id, one peer set,
// one read model, one byte ledger. That is the right shape and it is not
// changed here -- the monitor holds THREE of them. What cannot be had three
// times is the event loop: three ::poll() calls in sequence means each one
// blocks the other two for its timeout, so a quiet main chain would stall the
// mini panel for half a second at a time, and the 5-second tip-poll rule (which
// is what keeps a pulling observer from being banned) would start to slip under
// load. Threads would fix the stall and bring a mutex around every read model
// for a workload that is three sockets' worth of traffic.
//
// So the observer's loop was split into three phases it already contained
// (begin_tick / collect / dispatch, see p2pool_observer.hpp) and this file
// drives all three chains through ONE ::poll():
//
//     for each chain: begin_tick()                      dial, reap
//     for each chain: begins[i] = pfds.size(); collect() append its sockets
//     append the tty                                    so a keypress wakes us
//     ::poll(pfds, timeout)                             the only blocking call
//     for each chain: dispatch(pfds+begins[i], n_i)     its own slice, only
//
// THE RANGE IS THE TAG. A chain's sockets occupy a contiguous slice of the
// shared array, so there is no per-fd chain map to be built, looked up or left
// stale -- and a chain can never be handed another chain's revents, because it
// is handed a pointer and a length and nothing else.
//
// Per-connection timers need no change for this: next_tip_poll_ms_ lives inside
// PeerSession and is already per connection, so the "< 10 s" rule holds
// independently on each socket of each chain.
//
// ---------------------------------------------------------------------------
// THE RE-DIAL PROBLEM, which only appears when a run is long
// ---------------------------------------------------------------------------
// The observer never re-dials an endpoint: for a 300-second harness that is
// exactly right. Run the same code for six hours and every peer that ever hung
// up is permanently excluded, the dial queue drains, and the panel goes quiet
// while the chain is fine. The monitor therefore sets ObserverConfig's
// redial_after_ms, and reseeds a chain that has gone completely idle. Both are
// the caller's choice; run() still defaults to the harness behaviour.
//
// ---------------------------------------------------------------------------
// THE TERMINAL, AND PUTTING IT BACK
// ---------------------------------------------------------------------------
// No ncurses. Raw mode is four termios flags, the alternate screen and the
// cursor are two escapes each, and the size comes from TIOCGWINSZ -- that is
// the entire dependency, and it is POSIX.
//
// What actually matters is the restore path, because a monitor that dies in raw
// mode leaves the user with a shell that does not echo. So the restore is
// installed three ways over: the loop checks a quit flag set by SIGINT/SIGTERM
// and exits normally, TerminalUi's destructor restores, and an atexit hook
// restores whatever the exit path was. Restoring twice is harmless; restoring
// zero times costs someone a `reset`.
//
// SIGWINCH sets a flag and nothing else. Re-measuring the window inside a
// signal handler would mean calling ioctl() from one, and the frame is redrawn
// within the refresh interval anyway.
//
// POSIX + STL. No ncurses, no boost, no asio, no threads.
// ---------------------------------------------------------------------------
#pragma once

#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_freshness.hpp"
#include "impl/xmr/p2pool/p2pool_observer.hpp"
#include "impl/xmr/p2pool/p2pool_state.hpp"
#include "impl/xmr/p2pool/p2pool_tui.hpp"

namespace c2pool::xmr::p2pool {

// ---------------------------------------------------------------------------
// Signal flags. Written by handlers, read by the loop; nothing else.
// ---------------------------------------------------------------------------
inline volatile std::sig_atomic_t g_tui_quit    = 0;
inline volatile std::sig_atomic_t g_tui_resized = 1;   // measure once at start

inline void tui_on_quit(int)   { g_tui_quit = 1; }
inline void tui_on_winch(int)  { g_tui_resized = 1; }

// ---------------------------------------------------------------------------
// The multiplexer.
// ---------------------------------------------------------------------------
struct MonitorConfig {
    std::vector<Sidechain> chains{Sidechain::Main, Sidechain::Mini, Sidechain::Nano};
    std::size_t   peers_per_chain  = 4;
    std::uint64_t run_ms           = 0;         // 0 = until the user quits
    std::uint64_t refresh_ms       = 1000;
    std::uint64_t redial_after_ms  = 300000;    // 5 minutes; see the header note
    // How often a chain with no peers AND nothing queued retries its DNS seeds.
    // Short on purpose: a dark chain has no gossip, so the seeds are its only
    // way back, and a live run has already shown a chain losing four minutes to
    // two seed lookups that failed in the first second.
    std::uint64_t reseed_idle_ms   = 20000;
    std::uint64_t seed             = 0;
    bool          verbose          = false;
    // Chains that must NOT use the DNS seed list -- neither at start-up nor on
    // the idle reseed. They dial only what `--peer` gave them, which is how a
    // source is deliberately taken away from the monitor to prove that the
    // panel says so instead of showing zeros, and that the other chains carry
    // on. Without this, a chain pointed at a dead port is quietly rescued by
    // the seeds twenty seconds later and the case under test disappears.
    std::vector<Sidechain> seedless;
    // How stale is stale. Exposed so an operator watching a chain with a very
    // different cadence can move the bands without a rebuild.
    FreshnessThresholds freshness;
};

class MultiWatch {
public:
    explicit MultiWatch(const MonitorConfig& mc) : cfg_(mc) {
        for (std::size_t i = 0; i < cfg_.chains.size(); ++i) {
            ObserverConfig oc;
            oc.chain           = cfg_.chains[i];
            oc.max_peers       = cfg_.peers_per_chain;
            oc.redial_after_ms = cfg_.redial_after_ms;
            oc.verbose         = cfg_.verbose;
            // Each chain gets its own deterministic sub-seed when a seed was
            // given, so a seeded run is reproducible per chain rather than
            // depending on the order three observers happened to draw from one
            // generator.
            oc.seed = cfg_.seed ? (cfg_.seed + 1013904223ull * (i + 1)) : 0;
            oc.run_ms = 0;                      // this class owns the loop
            Slot sl;
            sl.obs   = std::make_unique<Observer>(oc);
            sl.seeds = true;
            for (const Sidechain c : cfg_.seedless)
                if (c == cfg_.chains[i]) sl.seeds = false;
            slots_.push_back(std::move(sl));
        }
    }

    std::size_t size() const noexcept { return slots_.size(); }
    Observer&       observer(std::size_t i)       { return *slots_[i].obs; }
    const Observer& observer(std::size_t i) const { return *slots_[i].obs; }
    Sidechain chain(std::size_t i) const noexcept { return cfg_.chains[i]; }

    void set_log(LogSink s) { for (Slot& sl : slots_) sl.obs->set_log(s); }

    void seed_all() {
        for (Slot& sl : slots_) if (sl.seeds) sl.obs->add_default_seeds();
    }

    // Dial this endpoint first on the named chain; the DNS seeds still follow
    // unless the chain is seedless. The endpoint is remembered, because a
    // seedless chain has nothing else to retry when its only peer goes away.
    void add_peer(Sidechain c, const std::string& host, std::uint16_t port) {
        for (std::size_t i = 0; i < slots_.size(); ++i)
            if (cfg_.chains[i] == c) {
                slots_[i].obs->add_seed(host, port);
                slots_[i].pinned.push_back({host, port});
            }
    }

    // CONTINUITY. The previous session's state, read off disk before the first
    // packet. Two things come across, and deliberately only two: the freshness
    // clock (see FreshnessTracker::carry_in) and the lifetime high-water marks.
    // Everything else on a panel is a live reading or a `--`.
    void set_carry(const state::MonitorState& prev) {
        carry_         = prev;
        carry_loaded_  = true;
        carry_applied_ = false;
    }

    bool          carried() const noexcept { return carry_loaded_; }
    std::uint64_t loop_stall_max_ms() const noexcept { return loop_stall_max_ms_; }

    // ONE turn of the shared loop. `extra_fd` (the tty, or -1) is polled beside
    // the sockets and its revents are returned, so a keypress wakes the loop
    // without a second poll and without a timeout race.
    short poll_once(int extra_fd, short extra_events, int timeout_ms) {
        // STEADY. Everything this turn measures -- the gap since the previous
        // turn, the per-chain reseed cool-off -- is a duration inside this
        // process, and a wall clock that an NTP step moved backwards would
        // report a negative loop stall or freeze a reseed timer for hours.
        const std::uint64_t t = steady_ms();

        // THE LOOP-STALL WATCH. One dead source must not stall the other two,
        // and "must not" is worth measuring rather than asserting: every turn
        // records the gap since the previous turn, and the worst gap of the
        // session is rendered on the header row and written into the state
        // file. A blocking getaddrinfo() on a chain whose seeds have gone away
        // shows up here as a multi-second spike, and it shows up whether or not
        // anybody was watching at the time.
        if (last_turn_ms_) {
            const std::uint64_t gap = t > last_turn_ms_ ? t - last_turn_ms_ : 0;
            if (gap > loop_stall_max_ms_) loop_stall_max_ms_ = gap;
        }
        last_turn_ms_ = t;

        for (Slot& sl : slots_) {
            sl.obs->begin_tick();
            if (sl.obs->idle() && t >= sl.next_reseed_ms) {
                // A seedless chain retries exactly what it was given. It must
                // not fall back to the DNS seeds: a chain deliberately pointed
                // at a dead endpoint that quietly reconnects to the real
                // network is a monitor that cannot be tested.
                if (sl.seeds) sl.obs->reseed();
                else for (const auto& p : sl.pinned) sl.obs->add_seed(p.first, p.second);
                sl.next_reseed_ms = t + cfg_.reseed_idle_ms;
            }
        }

        pfds_.clear();
        live_.clear();
        begins_.clear();
        begins_.reserve(slots_.size() + 1);
        for (Slot& sl : slots_) {
            begins_.push_back(pfds_.size());
            sl.obs->collect(pfds_, live_);
        }
        begins_.push_back(pfds_.size());        // end of the last chain's slice

        const std::size_t sockets = pfds_.size();
        if (extra_fd >= 0) {
            pollfd p{};
            p.fd     = extra_fd;
            p.events = extra_events;
            pfds_.push_back(p);
        }

        short extra_revents = 0;
        if (pfds_.empty()) {
            // NOTHING OPEN AT ALL. Wait out the timeout -- but take the
            // freshness sample first.
            //
            // This early return used to skip it, and the case it skipped is
            // exactly the worst one: a monitor whose chains are ALL dark never
            // started a single clock, so the panels said "DARK never connected"
            // with no age beside it, on the one run where how long it had been
            // dark was the whole question. Caught by running the binary with
            // every chain seedless; the three-chain case hid it, because one
            // live chain's sockets are enough to make this array non-empty and
            // sample all three.
            sample_freshness();
            ::poll(nullptr, 0, timeout_ms);
            return 0;
        }
        const int rc = ::poll(pfds_.data(), pfds_.size(), timeout_ms);
        if (rc < 0) {
            if (errno != EINTR) return 0;       // EINTR: a signal, handled by the caller
        } else if (extra_fd >= 0) {
            extra_revents = pfds_[sockets].revents;
        }

        // Each chain sees ITS OWN slice and nothing else.
        for (std::size_t i = 0; i < slots_.size(); ++i) {
            const std::size_t b = begins_[i];
            const std::size_t n = begins_[i + 1] - b;
            slots_[i].obs->dispatch(pfds_.data() + b, live_.data() + b, n);
        }

        // Taken AFTER dispatch so a block that arrived on this turn counts on
        // this turn.
        sample_freshness();
        return extra_revents;
    }

    void close_all() { for (Slot& sl : slots_) sl.obs->close_all("monitor stopped"); }

    // The frame, taken at one instant across all three chains. This is also
    // exactly what gets written to the state file: the file is built from the
    // frame, so the two cannot disagree (see p2pool_state.hpp).
    tui::MonitorFrame frame(std::uint64_t elapsed_ms, bool interactive,
                            const tui::PersistView& persist = tui::PersistView{}) const {
        tui::MonitorFrame f;
        f.elapsed_ms  = elapsed_ms;
        f.interactive = interactive;
        f.persist     = persist;
        f.persist.loop_stall_max_ms = loop_stall_max_ms_;
        // BOTH CLOCKS, read once each so every panel in this frame is resolved
        // at one instant: steady for the per-session feed ages, wall for the
        // freshness instants and for the age of the state the last session left.
        const std::uint64_t t = steady_ms();
        const std::uint64_t w = wall_ms();
        for (const Slot& sl : slots_) {
            tui::EmitCounts ec;
            const OutboundLedger& led = sl.obs->ledger();
            for (std::size_t i = 0; i < kControlMessageCount; ++i) {
                ec.messages[i] = led.messages[i];
                ec.bytes[i]    = led.bytes[i];
            }
            tui::ChainView v = tui::view_of(sl.obs->model(), ec, sl.obs->live_sessions(),
                                            sl.obs->pending_dials(), t, w, sl.fresh.view(),
                                            cfg_.freshness);

            // What the previous session left behind, on its own row, with its
            // age. The lifetime maxima are carried forward monotonically so a
            // restart cannot un-see a height.
            if (carry_loaded_) {
                if (const state::ChainState* prev = carry_.find(to_string(sl.obs->model().chain()))) {
                    v.carried             = true;
                    v.carry_written_at_ms = carry_.written_at_ms;
                    v.carry_age_ms        = FreshnessView::age(w, carry_.written_at_ms);
                    v.carry_tip_height    = prev->tip_height;
                    v.carry_tip_id8       = prev->tip_id.size() >= 8 ? prev->tip_id.substr(0, 8)
                                                                     : std::string();
                    v.lifetime_tip_max    = prev->lifetime.tip_height_max;
                    v.lifetime_monero_max = prev->lifetime.monero_tpl_max;
                }
            }
            if (v.tip_height > v.lifetime_tip_max)   v.lifetime_tip_max = v.tip_height;
            if (v.monero_high > v.lifetime_monero_max) v.lifetime_monero_max = v.monero_high;
            f.chains.push_back(std::move(v));
        }
        return f;
    }

private:
    // THE FRESHNESS SAMPLE, once per turn, per chain, from outside. Polling
    // rather than hooking the observer keeps every chain's clock driven by that
    // chain's own numbers and nothing else -- see the note on
    // FreshnessTracker::sample. Called on EVERY path out of poll_once(),
    // including the one where no socket exists yet.
    void sample_freshness() {
        // WALL. Every instant the tracker records from this sample is written to
        // the state file and read back by a later process, on a later boot and
        // sometimes on another machine, so it has to be on the clock those two
        // processes share. This one line is the fix for the reboot bug described
        // at the top of p2pool_observer.hpp.
        const std::uint64_t t = wall_ms();
        for (Slot& sl : slots_) {
            sl.fresh.sample(sl.obs->model().tip_height(), sl.obs->model().distinct_blocks(),
                            sl.obs->model().connected_peers(), sl.obs->live_sessions(),
                            sl.obs->pending_dials(), t);
        }
        // The carried clock is applied once, after the trackers have started:
        // carry_in() takes the EARLIER instant, and start() has just seeded
        // them to `now`.
        if (carry_loaded_ && !carry_applied_) {
            carry_applied_ = true;
            for (std::size_t i = 0; i < slots_.size(); ++i) {
                const state::ChainState* prev = carry_.find(to_string(cfg_.chains[i]));
                if (!prev) continue;
                FreshnessView fv;
                fv.known     = true;
                fv.tip_at_ms = prev->tip_advanced_at_ms;
                fv.rx_at_ms  = prev->rx_at_ms;
                slots_[i].fresh.carry_in(fv);
            }
        }
    }

    struct Slot {
        std::unique_ptr<Observer> obs;
        std::uint64_t             next_reseed_ms = 0;
        bool                      seeds = true;
        std::vector<std::pair<std::string, std::uint16_t>> pinned;
        FreshnessTracker          fresh;
    };

    MonitorConfig            cfg_;
    std::vector<Slot>        slots_;
    std::vector<pollfd>      pfds_;
    std::vector<PeerSession*> live_;
    std::vector<std::size_t> begins_;

    state::MonitorState      carry_;
    bool                     carry_loaded_  = false;
    bool                     carry_applied_ = false;
    std::uint64_t            last_turn_ms_  = 0;
    std::uint64_t            loop_stall_max_ms_ = 0;
};

// ---------------------------------------------------------------------------
// The terminal.
// ---------------------------------------------------------------------------
class TerminalUi;
inline TerminalUi* g_tui_active = nullptr;
inline void tui_atexit_restore();

class TerminalUi {
public:
    ~TerminalUi() { end(); }

    bool is_tty() const { return ::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO); }

    // Raw mode, alternate screen, cursor hidden, signal handlers installed.
    // Returns false (changing nothing) when stdout is not a terminal.
    bool begin() {
        if (active_) return true;
        if (!is_tty()) return false;
        if (::tcgetattr(STDIN_FILENO, &saved_) != 0) return false;

        termios raw = saved_;
        // Canonical mode and echo off: keys arrive one at a time and are not
        // printed over the frame. ISIG is left ON so Ctrl-C still raises
        // SIGINT, which is what the quit handler below is for.
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
        raw.c_iflag &= static_cast<tcflag_t>(~(IXON));
        raw.c_cc[VMIN]  = 0;
        raw.c_cc[VTIME] = 0;
        if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return false;

        active_ = true;
        g_tui_active = this;
        std::atexit(&tui_atexit_restore);

        install(SIGINT,  &tui_on_quit);
        install(SIGTERM, &tui_on_quit);
        install(SIGHUP,  &tui_on_quit);
        install(SIGWINCH, &tui_on_winch);

        write_all("\x1b[?1049h");     // alternate screen
        write_all("\x1b[?25l");       // hide cursor
        write_all("\x1b[2J");         // clear it once; frames repaint in place
        return true;
    }

    // Put everything back. Safe to call twice, safe from atexit.
    void end() {
        if (!active_) return;
        active_ = false;
        write_all("\x1b[?25h");       // show cursor
        write_all("\x1b[?1049l");     // leave alternate screen
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
        if (g_tui_active == this) g_tui_active = nullptr;
    }

    bool size(std::size_t& cols, std::size_t& rows) const {
        winsize ws{};
        if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_col == 0 || ws.ws_row == 0)
            return false;
        cols = ws.ws_col;
        rows = ws.ws_row;
        return true;
    }

    // Home the cursor, write every line, erase anything below. No clear-screen
    // per frame: clearing first is what makes a hand-rolled TUI flicker.
    void paint(const std::vector<std::string>& lines) {
        std::string out = "\x1b[H";
        for (std::size_t i = 0; i < lines.size(); ++i) {
            out += lines[i];
            if (i + 1 < lines.size()) out += "\r\n";
        }
        out += "\x1b[J";
        write_all(out);
    }

private:
    static void install(int sig, void (*fn)(int)) {
        struct sigaction sa{};
        sa.sa_handler = fn;
        ::sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;              // no SA_RESTART: poll() must return EINTR
        ::sigaction(sig, &sa, nullptr);
    }

    static void write_all(const std::string& s) {
        std::size_t off = 0;
        while (off < s.size()) {
            const ssize_t n = ::write(STDOUT_FILENO, s.data() + off, s.size() - off);
            if (n <= 0) break;
            off += static_cast<std::size_t>(n);
        }
    }

    termios saved_{};
    bool    active_ = false;
};

inline void tui_atexit_restore() {
    if (g_tui_active) g_tui_active->end();
}

} // namespace c2pool::xmr::p2pool
