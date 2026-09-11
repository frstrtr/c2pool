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
// in one process, on one screen.
//
//   xmr_p2pool_monitor                          full screen, all three chains
//   xmr_p2pool_monitor --chains mini,nano       two of them
//   xmr_p2pool_monitor --snapshot --seconds 90  one plain-text frame to stdout
//
// TWO MODES, ONE RENDERER. The fullscreen mode paints the frame from
// p2pool_tui.hpp into an alternate screen at about 1 Hz; `--snapshot` runs the
// same loop for a fixed window and prints ONE frame of the same layout as plain
// text with the escapes turned off. That is what makes the display reviewable:
// a snapshot can be pasted into a PR, diffed, or checked by a KAT, and it is
// not a second rendering path that could disagree with what the screen shows.
//
// It is a HARNESS, like xmr_p2pool_observer. CI BUILDS it so it cannot bit-rot
// and never RUNS it: running it dials three public networks and the fullscreen
// mode wants a tty. It registers no ctest test, so the #1539 Not-Run rule does
// not apply to it. What CI runs is xmr_p2pool_monitor_kat, which is offline and
// pins the renderer against a golden frame.
//
// READ-ONLY, unchanged and unchangeable here: this tool adds no encoder. Every
// byte it can put on a socket comes from the four-value ControlMessage enum in
// p2pool_wire.hpp, and the footer of every frame prints that set as computed
// from the encoder itself.
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

namespace p2p = c2pool::xmr::p2pool;
namespace tui = c2pool::xmr::p2pool::tui;

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
        "  --width N            snapshot width in columns (default 100)\n"
        "  --refresh-ms N       fullscreen repaint interval (default 1000)\n"
        "  --peer CHAIN:HOST:PORT   dial this peer first on that chain (repeatable)\n"
        "  --redial-ms N        re-dial cool-off per endpoint (default 300000)\n"
        "  --seed N             deterministic rng seed\n"
        "  --no-color           never emit colour, even on a tty\n"
        "  --log PATH           write the per-peer log there (never to the screen)\n"
        "\n"
        "Keys in fullscreen mode: q quit, r redraw.\n";
}

struct Options {
    p2p::MonitorConfig mc;
    bool        snapshot = false;
    bool        no_color = false;
    std::size_t width    = 100;
    std::string log_path;
    bool        seconds_set = false;
    std::vector<std::pair<p2p::Sidechain, std::pair<std::string, std::uint16_t>>> peers;
};

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
        else if (a == "--width")        o.width = static_cast<std::size_t>(std::stoul(next("--width")));
        else if (a == "--refresh-ms")   o.mc.refresh_ms = std::stoull(next("--refresh-ms"));
        else if (a == "--redial-ms")    o.mc.redial_after_ms = std::stoull(next("--redial-ms"));
        else if (a == "--seed")         o.mc.seed = std::stoull(next("--seed"));
        else if (a == "--no-color")     o.no_color = true;
        else if (a == "--verbose")      o.mc.verbose = true;
        else if (a == "--log")          o.log_path = next("--log");
        else if (a == "--peer") {
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

    for (const auto& p : o.peers) watch.add_peer(p.first, p.second.first, p.second.second);
    watch.seed_all();

    const std::uint64_t t0    = p2p::now_ms();
    const std::uint64_t t_end = o.mc.run_ms ? t0 + o.mc.run_ms : 0;

    // -----------------------------------------------------------------------
    // HEADLESS: run the window, print one frame.
    // -----------------------------------------------------------------------
    if (o.snapshot) {
        std::uint64_t next_note = t0 + 15000;
        while (!p2p::g_tui_quit && (!t_end || p2p::now_ms() < t_end)) {
            watch.poll_once(-1, 0, 250);
            const std::uint64_t t = p2p::now_ms();
            if (t >= next_note) {                     // a long window should not look hung
                next_note = t + 15000;
                const tui::MonitorFrame f = watch.frame(t - t0, false);
                const tui::MonitorTotals tot = tui::totals_of(f.chains);
                std::fprintf(stderr, "  .. %llus  peers %zu  blocks %zu\n",
                             static_cast<unsigned long long>((t - t0) / 1000),
                             tot.peers_up, tot.blocks);
            }
        }
        // The frame is taken BEFORE the sockets are closed. Closing first would
        // print "4 peers up / 0 sockets", which is true of a process on its way
        // out and false of the window the frame is reporting on.
        const std::uint64_t elapsed = p2p::now_ms() - t0;
        const tui::MonitorFrame f = watch.frame(elapsed, false);
        watch.close_all();
        std::cout << tui::snapshot_text(f, o.width) << std::flush;
        if (logf) std::fclose(logf);
        // Non-vacuity, the same rule the observer harness applies: a run that
        // connected to nothing and parsed nothing is a failed run, and must not
        // green a pipeline by printing an empty frame.
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
            const tui::MonitorFrame f = watch.frame(t - t0, true);
            term.paint(tui::render(f, cols, rows, color));
        }
    }

    const std::uint64_t elapsed = p2p::now_ms() - t0;
    const tui::MonitorFrame f = watch.frame(elapsed, false);   // before the sockets go
    watch.close_all();
    term.end();                       // back to the normal screen BEFORE printing
    if (logf) std::fclose(logf);

    // The alternate screen takes the frame with it when it goes, so the last
    // one is reprinted on the normal screen: a session that ends should leave
    // its numbers behind, not a blank prompt.
    std::cout << tui::snapshot_text(f, cols) << std::flush;
    return 0;
}
