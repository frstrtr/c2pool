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

#include "impl/xmr/p2pool/p2pool_observer.hpp"
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
            slots_.push_back(Slot{std::make_unique<Observer>(oc), 0});
        }
    }

    std::size_t size() const noexcept { return slots_.size(); }
    Observer&       observer(std::size_t i)       { return *slots_[i].obs; }
    const Observer& observer(std::size_t i) const { return *slots_[i].obs; }
    Sidechain chain(std::size_t i) const noexcept { return cfg_.chains[i]; }

    void set_log(LogSink s) { for (Slot& sl : slots_) sl.obs->set_log(s); }

    void seed_all() { for (Slot& sl : slots_) sl.obs->add_default_seeds(); }

    // Dial this endpoint first on the named chain; the DNS seeds still follow.
    void add_peer(Sidechain c, const std::string& host, std::uint16_t port) {
        for (std::size_t i = 0; i < slots_.size(); ++i)
            if (cfg_.chains[i] == c) slots_[i].obs->add_seed(host, port);
    }

    // ONE turn of the shared loop. `extra_fd` (the tty, or -1) is polled beside
    // the sockets and its revents are returned, so a keypress wakes the loop
    // without a second poll and without a timeout race.
    short poll_once(int extra_fd, short extra_events, int timeout_ms) {
        const std::uint64_t t = now_ms();

        for (Slot& sl : slots_) {
            sl.obs->begin_tick();
            if (sl.obs->idle() && t >= sl.next_reseed_ms) {
                sl.obs->reseed();
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
            ::poll(nullptr, 0, timeout_ms);     // nothing open yet: just wait
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
        return extra_revents;
    }

    void close_all() { for (Slot& sl : slots_) sl.obs->close_all("monitor stopped"); }

    // The frame, taken at one instant across all three chains.
    tui::MonitorFrame frame(std::uint64_t elapsed_ms, bool interactive) const {
        tui::MonitorFrame f;
        f.elapsed_ms  = elapsed_ms;
        f.interactive = interactive;
        const std::uint64_t t = now_ms();
        for (const Slot& sl : slots_) {
            tui::EmitCounts ec;
            const OutboundLedger& led = sl.obs->ledger();
            for (std::size_t i = 0; i < kControlMessageCount; ++i) {
                ec.messages[i] = led.messages[i];
                ec.bytes[i]    = led.bytes[i];
            }
            f.chains.push_back(tui::view_of(sl.obs->model(), ec, sl.obs->live_sessions(),
                                            sl.obs->pending_dials(), t));
        }
        return f;
    }

private:
    struct Slot {
        std::unique_ptr<Observer> obs;
        std::uint64_t             next_reseed_ms = 0;
    };

    MonitorConfig            cfg_;
    std::vector<Slot>        slots_;
    std::vector<pollfd>      pfds_;
    std::vector<PeerSession*> live_;
    std::vector<std::size_t> begins_;
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
