// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/tools/p2pool_monitor_main.cpp
//
// `xmr_p2pool_monitor` -- watch all three P2Pool sidechains at once, read-only,
// in one process, on one screen, and keep what it saw.
//
//   xmr_p2pool_monitor                          full screen, all three chains
//   xmr_p2pool_monitor --chains mini,nano       two of them
//   xmr_p2pool_monitor --snapshot --seconds 90  one plain-text frame to stdout
//   xmr_p2pool_monitor --read                   render the SAVED state, no network
//
// TWO LIVE MODES, ONE RENDERER, AND A THIRD MODE THAT DIALS NOTHING. The
// fullscreen mode paints the frame from p2pool_tui.hpp into an alternate screen
// at about 1 Hz; `--snapshot` runs the same loop for a fixed window and prints
// ONE frame of the same layout as plain text; `--read` reconstructs a frame
// from the state file and prints it through the same renderer without opening a
// socket. That a saved state and a live one go through one renderer is what
// makes the file reviewable rather than merely archived.
//
// ---------------------------------------------------------------------------
// BOTH LIVE MODES PERSIST, AND THE HEADLESS ONE MATTERS MOST
// ---------------------------------------------------------------------------
// `--snapshot` prints its single frame at the END of the window. A run left
// going overnight and killed at hour six has, without a state file, produced
// nothing at all -- and the headless run is precisely the one nobody is
// watching when the interesting thing happens. So the state file is written on
// a timer in BOTH modes, atomically, and read back at start-up.
//
// The final save carries `"shutdown":"clean"`. Its ABSENCE is the useful half:
// a state file without it was left by a process that was killed, and that is
// exactly the file the restart is supposed to pick up.
//
// READ-ONLY, unchanged and unchangeable here: this tool adds no encoder. Every
// byte it can put on a socket comes from the four-value ControlMessage enum in
// p2pool_wire.hpp, and the footer of every frame prints that set as computed
// from the encoder itself. Persistence writes a LOCAL FILE; the emitted id set
// is written INTO that file so the read-only claim is auditable off-line.
//
// It is a HARNESS, like xmr_p2pool_observer. CI BUILDS it so it cannot bit-rot
// and never RUNS it: running it dials three public networks and the fullscreen
// mode wants a tty. It registers no ctest test, so the #1539 Not-Run rule does
// not apply to it. What CI runs is xmr_p2pool_monitor_kat (the renderer, the
// absence-vs-zero rules) and xmr_p2pool_persist_kat (the state file).
//
// SCOPE FENCE: everything under src/impl/xmr/. UNIX only.
// ---------------------------------------------------------------------------

#include <poll.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_multiwatch.hpp"
#include "impl/xmr/p2pool/p2pool_persist.hpp"

namespace p2p = c2pool::xmr::p2pool;
namespace tui = c2pool::xmr::p2pool::tui;
namespace st  = c2pool::xmr::p2pool::state;

namespace {

bool parse_chain(const std::string& s, p2p::Sidechain& out) {
    if (s == "main") { out = p2p::Sidechain::Main; return true; }
    if (s == "mini") { out = p2p::Sidechain::Mini; return true; }
    if (s == "nano") { out = p2p::Sidechain::Nano; return true; }
    return false;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (const char c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

void usage() {
    std::cout <<
        "xmr_p2pool_monitor -- read-only monitor for all three P2Pool sidechains\n"
        "  --chains LIST        comma list of main,mini,nano (default all three)\n"
        "  --peers N            connections PER CHAIN (default 4)\n"
        "  --seconds N          run window; 0 = until q (default 0, or 60 with --snapshot)\n"
        "  --snapshot           headless: run the window, print ONE plain frame, exit\n"
        "  --read               print the SAVED state and exit; dials nothing\n"
        "  --width N            snapshot width in columns (default 100)\n"
        "  --refresh-ms N       fullscreen repaint interval (default 1000)\n"
        "  --peer CHAIN:HOST:PORT   dial this peer first on that chain (repeatable)\n"
        "  --no-seed CHAIN      that chain uses ONLY --peer, never the DNS seeds\n"
        "  --redial-ms N        re-dial cool-off per endpoint (default 300000)\n"
        "  --seed N             deterministic rng seed\n"
        "  --no-color           never emit colour, even on a tty\n"
        "  --log PATH           write the per-peer log there (never to the screen)\n"
        "\n"
        "State (durable, atomic, read back on start):\n"
        "  --state-dir PATH     default $HOME/p2pmon-state\n"
        "  --persist-ms N       how often the state file is rewritten (default 2000)\n"
        "  --no-persist         run with nothing written to disk\n"
        "\n"
        "Keys in fullscreen mode: q quit, r redraw.\n";
}

struct Options {
    p2p::MonitorConfig mc;
    bool        snapshot = false;
    bool        read_only = false;
    bool        no_color = false;
    bool        no_persist = false;
    std::size_t width    = 100;
    std::string log_path;
    std::string state_dir;
    std::uint64_t persist_ms = 2000;
    bool        seconds_set = false;
    std::vector<std::pair<p2p::Sidechain, std::pair<std::string, std::uint16_t>>> peers;
};

// The banner the header row renders, kept in one place so the ON and the OFF
// cases cannot drift apart.
tui::PersistView persist_view(const p2p::StateStore& store, bool asked_for,
                              std::uint64_t last_save_ms, std::uint64_t now,
                              bool restored, std::uint64_t restored_age_ms,
                              std::uint64_t sessions, std::uint64_t runtime_total_ms) {
    tui::PersistView p;
    p.enabled = store.enabled();
    p.dir     = store.dir();
    if (!p.enabled)
        p.off_reason = asked_for ? (store.off_reason().empty() ? std::string("(unavailable)")
                                                               : store.off_reason())
                                 : std::string("(--no-persist)");
    p.seq            = store.seq();
    p.ever_saved     = last_save_ms != 0;
    p.saved_age_ms   = p2p::FreshnessView::age(now, last_save_ms);
    p.errors         = store.errors();
    p.last_error     = store.last_error();
    p.journal_lines  = store.journal_lines();
    p.restored       = restored;
    p.restored_age_ms = restored_age_ms;
    p.sessions       = sessions;
    p.runtime_ms_total = runtime_total_ms;
    return p;
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    o.mc.run_ms = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::cerr << "missing value for " << what << "\n"; std::exit(2); }
            return argv[++i];
        };
        if (a == "--chains") {
            o.mc.chains.clear();
            for (const std::string& piece : split(next("--chains"), ',')) {
                p2p::Sidechain c{};
                if (!parse_chain(piece, c)) { std::cerr << "unknown chain " << piece << "\n"; return 2; }
                o.mc.chains.push_back(c);
            }
            if (o.mc.chains.empty()) { std::cerr << "--chains needs at least one chain\n"; return 2; }
        } else if (a == "--peers")      o.mc.peers_per_chain = static_cast<std::size_t>(std::stoul(next("--peers")));
        else if (a == "--seconds")      { o.mc.run_ms = std::stoull(next("--seconds")) * 1000ull; o.seconds_set = true; }
        else if (a == "--snapshot")     o.snapshot = true;
        else if (a == "--read")         o.read_only = true;
        else if (a == "--width")        o.width = static_cast<std::size_t>(std::stoul(next("--width")));
        else if (a == "--refresh-ms")   o.mc.refresh_ms = std::stoull(next("--refresh-ms"));
        else if (a == "--redial-ms")    o.mc.redial_after_ms = std::stoull(next("--redial-ms"));
        else if (a == "--seed")         o.mc.seed = std::stoull(next("--seed"));
        else if (a == "--no-color")     o.no_color = true;
        else if (a == "--verbose")      o.mc.verbose = true;
        else if (a == "--log")          o.log_path = next("--log");
        else if (a == "--state-dir")    o.state_dir = next("--state-dir");
        else if (a == "--persist-ms")   o.persist_ms = std::stoull(next("--persist-ms"));
        else if (a == "--no-persist")   o.no_persist = true;
        else if (a == "--no-seed") {
            p2p::Sidechain c{};
            const std::string v = next("--no-seed");
            if (!parse_chain(v, c)) { std::cerr << "unknown chain " << v << "\n"; return 2; }
            o.mc.seedless.push_back(c);
        } else if (a == "--peer") {
            const std::vector<std::string> parts = split(next("--peer"), ':');
            p2p::Sidechain c{};
            if (parts.size() != 3 || !parse_chain(parts[0], c)) {
                std::cerr << "--peer wants CHAIN:HOST:PORT\n";
                return 2;
            }
            o.peers.push_back({c, {parts[1], static_cast<std::uint16_t>(std::stoul(parts[2]))}});
        } else if (a == "--help" || a == "-h") { usage(); return 0; }
        else { std::cerr << "unknown argument " << a << "\n"; usage(); return 2; }
    }

    const std::string state_dir = o.state_dir.empty() ? p2p::StateStore::default_dir()
                                                      : o.state_dir;

    // -----------------------------------------------------------------------
    // READER: the state file, through the live renderer, with no network.
    // -----------------------------------------------------------------------
    if (o.read_only) {
        p2p::StateStore store;
        store.open_read_only(state_dir);
        st::MonitorState s;
        std::string why;
        if (!store.load(s, why)) {
            std::cerr << "cannot read state from " << (state_dir.empty() ? "(no HOME)" : state_dir)
                      << ": " << why << "\n";
            return 3;
        }
        tui::MonitorFrame f = st::frame_of(s, p2p::now_ms());
        f.persist.dir = store.dir();       // the file we read, named on the banner
        std::cout << tui::snapshot_text(f, o.width) << std::flush;
        return 0;
    }

    // A snapshot is a fixed window by definition; the fullscreen mode runs
    // until the user says otherwise.
    if (o.snapshot && !o.seconds_set) o.mc.run_ms = 60000;

    p2p::MultiWatch watch(o.mc);

    // Logging never goes to the screen: in fullscreen mode stdout belongs to
    // the frame, and a stray log line would shear the layout.
    FILE* logf = nullptr;
    if (!o.log_path.empty()) {
        logf = std::fopen(o.log_path.c_str(), "we");
        if (!logf) { std::cerr << "cannot open " << o.log_path << "\n"; return 2; }
        watch.set_log([logf](const std::string& m) {
            std::fprintf(logf, "%s\n", m.c_str());
            std::fflush(logf);
        });
    }

    // -----------------------------------------------------------------------
    // THE STATE DIRECTORY, and the continuity read.
    //
    // Nothing below is fatal. No HOME, a directory we cannot create, a disk
    // that is full, another monitor holding the lock -- each of those turns
    // persistence off and says so on the header row, and the monitor watches
    // three chains exactly as before. A telemetry file is not worth refusing to
    // do the job for.
    // -----------------------------------------------------------------------
    p2p::StateStore store;
    if (!o.no_persist) store.open(state_dir);

    st::MonitorState prev;
    bool          restored        = false;
    std::uint64_t restored_age_ms = 0;
    st::LifetimeState lifetime;
    lifetime.sessions = 1;

    const std::uint64_t t0  = p2p::now_ms();
    const std::uint64_t pid = static_cast<std::uint64_t>(::getpid());

    if (store.enabled()) {
        std::string why;
        if (store.load(prev, why)) {
            restored        = true;
            restored_age_ms = p2p::FreshnessView::age(t0, prev.written_at_ms);
            watch.set_carry(prev);
            lifetime.sessions            = prev.lifetime.sessions + 1;
            lifetime.first_started_at_ms = prev.lifetime.first_started_at_ms
                                         ? prev.lifetime.first_started_at_ms : t0;
            lifetime.runtime_ms_total    = prev.lifetime.runtime_ms_total;
            std::fprintf(stderr, "state: restored seq %llu from %s (%llus old, session %llu)%s\n",
                         static_cast<unsigned long long>(prev.seq), store.state_path().c_str(),
                         static_cast<unsigned long long>(restored_age_ms / 1000),
                         static_cast<unsigned long long>(lifetime.sessions),
                         prev.shutdown.empty() ? " -- previous session did not shut down cleanly"
                                               : "");
        } else {
            lifetime.first_started_at_ms = t0;
            std::fprintf(stderr, "state: starting fresh in %s (%s)\n",
                         store.dir().c_str(), why.c_str());
        }
    } else {
        lifetime.first_started_at_ms = t0;
        std::fprintf(stderr, "state: PERSIST OFF %s\n",
                     o.no_persist ? "(--no-persist)" : store.off_reason().c_str());
    }

    for (const auto& p : o.peers) watch.add_peer(p.first, p.second.first, p.second.second);
    watch.seed_all();

    const std::uint64_t t_end = o.mc.run_ms ? t0 + o.mc.run_ms : 0;
    const std::string   session_id = std::to_string(t0) + "-" + std::to_string(pid);
    const std::string   host = p2p::StateStore::hostname();

    std::uint64_t last_save_ms = 0;
    std::uint64_t next_save_ms = t0;          // save the first frame immediately

    // Build the frame at `now`, write it, and hand the same frame back so the
    // caller can print it. ONE frame object becomes both the file and the
    // screen, which is why the two can never disagree.
    auto capture = [&](std::uint64_t now, bool interactive,
                       const char* shutdown) -> tui::MonitorFrame {
        const tui::PersistView pv = persist_view(store, !o.no_persist, last_save_ms, now,
                                                 restored, restored_age_ms,
                                                 lifetime.sessions,
                                                 lifetime.runtime_ms_total + (now - t0));
        tui::MonitorFrame f = watch.frame(now - t0, interactive, pv);
        if (!store.enabled()) return f;

        st::SessionMeta meta;
        meta.written_at_ms = now;
        meta.seq  = store.seq() + 1;
        meta.pid  = pid;
        meta.host = host;
        meta.session_id            = session_id;
        meta.session_started_at_ms = t0;
        meta.shutdown              = shutdown ? shutdown : "";
        meta.persist.errors            = store.errors();
        meta.persist.last_error        = store.last_error();
        meta.persist.loop_stall_max_ms = watch.loop_stall_max_ms();
        meta.lifetime                  = lifetime;
        meta.lifetime.runtime_ms_total = lifetime.runtime_ms_total + (now - t0);

        const st::MonitorState s = st::state_of(f, meta);
        if (store.save_atomic(s)) {
            last_save_ms = now;
            store.journal(st::journal_line(s));
        }
        return f;
    };

    // -----------------------------------------------------------------------
    // HEADLESS: run the window, persist as it goes, print one frame at the end.
    // -----------------------------------------------------------------------
    if (o.snapshot) {
        std::uint64_t next_note = t0 + 15000;
        while (!p2p::g_tui_quit && (!t_end || p2p::now_ms() < t_end)) {
            watch.poll_once(-1, 0, 250);
            const std::uint64_t t = p2p::now_ms();
            if (t >= next_save_ms) {
                next_save_ms = t + o.persist_ms;
                capture(t, false, nullptr);
            }
            if (t >= next_note) {                     // a long window should not look hung
                next_note = t + 15000;
                const tui::MonitorFrame f = watch.frame(t - t0, false);
                const tui::MonitorTotals tot = tui::totals_of(f.chains);
                std::fprintf(stderr, "  .. %llus  peers %zu  blocks %zu  reporting %zu/%zu"
                                     "  saved seq %llu\n",
                             static_cast<unsigned long long>((t - t0) / 1000),
                             tot.peers_up, tot.blocks, tot.chains_reporting, tot.chains,
                             static_cast<unsigned long long>(store.seq()));
            }
        }
        // The frame is taken BEFORE the sockets are closed. Closing first would
        // print "4 peers up / 0 sockets", which is true of a process on its way
        // out and false of the window the frame is reporting on.
        const tui::MonitorFrame f = capture(p2p::now_ms(), false, "clean");
        watch.close_all();
        store.close_all();
        std::cout << tui::snapshot_text(f, o.width) << std::flush;
        if (logf) std::fclose(logf);
        // Non-vacuity, the same rule the observer harness applies: a run that
        // connected to nothing and parsed nothing is a failed run, and must not
        // green a pipeline by printing an empty frame. It is a per-RUN rule and
        // not a per-chain one on purpose: a deliberately dead chain beside two
        // live ones is the case this monitor is built to survive.
        return tui::totals_of(f.chains).blocks ? 0 : 1;
    }

    // -----------------------------------------------------------------------
    // FULLSCREEN.
    // -----------------------------------------------------------------------
    p2p::TerminalUi term;
    const bool tty = term.begin();
    if (!tty) {
        std::cerr << "stdout is not a terminal -- use --snapshot for a headless frame\n";
        if (logf) std::fclose(logf);
        return 2;
    }
    const bool color = !o.no_color;

    std::size_t cols = 100, rows = 30;
    std::uint64_t next_paint = 0;
    bool quit = false;

    while (!quit && !p2p::g_tui_quit && (!t_end || p2p::now_ms() < t_end)) {
        const short rev = watch.poll_once(STDIN_FILENO, POLLIN, 200);
        if (rev & POLLIN) {
            char keys[32];
            const ssize_t n = ::read(STDIN_FILENO, keys, sizeof(keys));
            for (ssize_t k = 0; k < n; ++k) {
                if (keys[k] == 'q' || keys[k] == 'Q' || keys[k] == 3 /* ^C */) quit = true;
                if (keys[k] == 'r' || keys[k] == 'R') next_paint = 0;
            }
        }
        const std::uint64_t t = p2p::now_ms();
        if (p2p::g_tui_resized) { p2p::g_tui_resized = 0; term.size(cols, rows); next_paint = 0; }
        if (t >= next_paint) {
            next_paint = t + o.mc.refresh_ms;
            // The repaint and the save share one frame whenever the save is due.
            const bool save_now = t >= next_save_ms;
            if (save_now) next_save_ms = t + o.persist_ms;
            const tui::MonitorFrame f = save_now
                ? capture(t, true, nullptr)
                : watch.frame(t - t0, true,
                              persist_view(store, !o.no_persist, last_save_ms, t, restored,
                                           restored_age_ms, lifetime.sessions,
                                           lifetime.runtime_ms_total + (t - t0)));
            term.paint(tui::render(f, cols, rows, color));
        }
    }

    const tui::MonitorFrame f = capture(p2p::now_ms(), false, "clean");   // before the sockets go
    watch.close_all();
    store.close_all();
    term.end();                       // back to the normal screen BEFORE printing
    if (logf) std::fclose(logf);

    // The alternate screen takes the frame with it when it goes, so the last
    // one is reprinted on the normal screen: a session that ends should leave
    // its numbers behind, not a blank prompt.
    std::cout << tui::snapshot_text(f, cols) << std::flush;
    return 0;
}
