// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_tui.hpp
//
// THE FRAME: three sidechain panels drawn as a pure function of three read
// models. No sockets, no terminal, no clock.
//
// ---------------------------------------------------------------------------
// WHY THE RENDERER HOLDS NOTHING
// ---------------------------------------------------------------------------
// A live dashboard is the easiest place in a codebase to hide an untested
// number, because the thing that would catch it -- looking at it -- is exactly
// what nobody does at three in the morning. So the rendering here is a total
// function
//
//     render(frame, cols, rows, color) -> exactly `rows` lines of `cols` columns
//
// over a `MonitorFrame` that is plain data: no pointer into a live model, no
// call to the clock, no access to a socket. Everything time-dependent -- ages,
// uptime -- is resolved by view_of() at ONE instant passed in by the caller.
// That is what lets a KAT pin the whole frame against a golden: feed a fixed
// read model and a fixed `now`, and the bytes are the same on every machine, on
// every run, forever. A renderer that reads the clock itself cannot be pinned,
// and a dashboard that cannot be pinned drifts silently.
//
// ---------------------------------------------------------------------------
// ONE BYTE IS ONE COLUMN
// ---------------------------------------------------------------------------
// Everything drawn is printable ASCII. The sparkline is `_.-=+*#`, the bars are
// `#` and `-`, the rules are `-`. That is not nostalgia: the moment a frame
// contains a multi-byte character, `std::string::size()` stops being the column
// count and every alignment in the file becomes a guess. The Line builder below
// tracks visible width as it appends, counts SGR escapes as zero-width, and
// clamps at `cols`, so a narrow terminal truncates instead of wrapping and
// shearing the layout.
//
// Colour is optional and strictly additive: render(color=false) and
// strip_ansi(render(color=true)) are the same bytes, which the KAT asserts.
// Snapshot mode is therefore not a second renderer, it is the same one with the
// escapes turned off.
//
// ---------------------------------------------------------------------------
// WHAT THE PANELS SAY, AND WHAT THEY REFUSE TO SAY
// ---------------------------------------------------------------------------
// The read model's rules carry through to the display rather than being
// softened for looks:
//
//   * Cadence is the LIVE-WINDOW figure only. Heights at or below the frontier
//     were backfilled by our own parent walk, and their spacing measures our
//     fetch rate. Below the two-sample threshold the panel prints "warming",
//     never a number with one sample behind it.
//   * The pulse line is the individual live gaps, newest on the right, because
//     an average of 10 s hides the difference between a steady beat and two
//     bursts around a stall.
//   * `monero tpl` is the highest Monero template height seen in a sidechain
//     coinbase. It is not a claim that P2Pool found a Monero block: deciding
//     that needs the Monero PoW target, which an observer holding no Monero
//     chain does not have.
//   * The `out` line is the byte ledger, and the footer prints the emitted
//     message-id set COMPUTED from the encoder (emitted_id_set(), which encodes
//     every ControlMessage and reads back the id byte) rather than a typed-in
//     list. If a fifth encoder ever appeared, the footer would start saying so
//     on screen and the KAT would fail in the same breath.
//
// ---------------------------------------------------------------------------
// ABSENCE IS NOT ZERO, AND IT IS ENFORCED HERE
// ---------------------------------------------------------------------------
// The refusals above are about numbers the read model declines to derive. The
// harder case is a number that does not EXIST because the source is gone, and
// it is harder because the wrong rendering is so natural: every counter on a
// panel is zero-initialised, so a chain we have heard nothing from draws itself
// as a complete set of confident zeros in exactly the shape a live chain uses.
//
// So every chain figure on a panel is gated on ChainView::have_data -- the read
// model actually HOLDING a block, not a counter being non-zero -- and a panel
// without data prints `--`, two columns that cannot be read as a value. Zero is
// reserved for a measurement that came out zero. Peer counts are the deliberate
// exception and are never dashed: "0 up" is a measurement, we looked at our own
// socket table, and it is paired with the status word that says what it means.
//
// Three things carry that rule up to the top of the frame:
//
//   * the STATUS WORD, now one of seven (p2pool_freshness.hpp) rather than
//     four, so DOWN, QUIET and STALE can be said at all, each with the age of
//     the event it is about;
//   * a `!` ROW above a degraded panel's figures, at kAlways priority, saying
//     in a sentence what stopped and how old the rest of the panel is -- a
//     status word alone makes the reader infer that, and at 4am readers infer
//     generously;
//   * a COVERAGE row beside the header totals. Summing three panels when one is
//     dark gives a figure that is arithmetically right and editorially false;
//     dropping the dead chain would hide it, so the header states how many
//     chains are actually behind the numbers, every frame.
//
// The PERSISTENCE banner is drawn every frame in both states for the same
// reason: whether these numbers will survive this process is not something an
// operator should have to discover by killing it.
//
// Header-only, STL only. Deliberately free of POSIX: this file is what the KAT
// compiles, and the KAT must not need a socket layer to check a layout.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_block.hpp"
#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_freshness.hpp"
#include "impl/xmr/p2pool/p2pool_read_model.hpp"
#include "impl/xmr/p2pool/p2pool_wire.hpp"

namespace c2pool::xmr::p2pool::tui {

// ---------------------------------------------------------------------------
// SGR codes. Every one of them is zero-width by construction; nothing else in
// this file emits an escape.
// ---------------------------------------------------------------------------
inline constexpr const char* kReset   = "\x1b[0m";
inline constexpr const char* kBold    = "\x1b[1m";
inline constexpr const char* kDim     = "\x1b[2m";
inline constexpr const char* kRed     = "\x1b[31m";
inline constexpr const char* kGreen   = "\x1b[32m";
inline constexpr const char* kYellow  = "\x1b[33m";
inline constexpr const char* kBlue    = "\x1b[34m";
inline constexpr const char* kMagenta = "\x1b[35m";
inline constexpr const char* kCyan    = "\x1b[36m";
inline constexpr const char* kWhite   = "\x1b[37m";

// Remove every CSI sequence. Used by the KAT to prove the colour build and the
// plain build differ by escapes alone.
inline std::string strip_ansi(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\x1b' && i + 1 < s.size() && s[i + 1] == '[') {
            i += 2;
            while (i < s.size() && !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z'))) ++i;
            continue;   // the final letter is consumed by the loop increment
        }
        out.push_back(s[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// One line, built left to right, clamped at `cols` visible columns.
// ---------------------------------------------------------------------------
class Line {
public:
    Line(std::size_t cols, bool color) : cols_(cols), color_(color) {}

    Line& put(const std::string& s) {
        for (const char c : s) {
            if (vis_ >= cols_) break;
            buf_.push_back(c);
            ++vis_;
        }
        return *this;
    }
    Line& put(const char* s) { return put(std::string(s)); }
    Line& put(char c) { if (vis_ < cols_) { buf_.push_back(c); ++vis_; } return *this; }
    Line& sgr(const char* code) { if (color_) buf_ += code; return *this; }
    Line& pad_to(std::size_t col) {
        while (vis_ < col && vis_ < cols_) { buf_.push_back(' '); ++vis_; }
        return *this;
    }
    Line& repeat(char c, std::size_t n) { for (std::size_t i = 0; i < n; ++i) put(c); return *this; }
    std::size_t visible() const noexcept { return vis_; }
    std::size_t room() const noexcept { return cols_ > vis_ ? cols_ - vis_ : 0; }

    // Close any colour and pad the rest of the row with plain spaces, so a
    // full-screen repaint overwrites whatever the previous frame left there.
    std::string take() {
        sgr(kReset);
        pad_to(cols_);
        return buf_;
    }

private:
    std::string buf_;
    std::size_t cols_;
    std::size_t vis_ = 0;
    bool        color_;
};

// ---------------------------------------------------------------------------
// Formatting. Integer maths wherever a rounding difference could show up in a
// golden; snprintf with an explicit precision everywhere else.
// ---------------------------------------------------------------------------
inline std::string fmt_fixed(long double v, int decimals) {
    char b[64];
    std::snprintf(b, sizeof(b), "%.*Lf", decimals, v);
    return std::string(b);
}

// 436060000 -> "436.06 M". Suffix appended by the caller ("H/s", "", ...).
inline std::string fmt_si(long double v, int decimals = 2) {
    static const char* kUnit[] = {"", "k", "M", "G", "T", "P", "E"};
    int u = 0;
    long double x = v < 0 ? -v : v;
    while (x >= 1000.0L && u < 6) { x /= 1000.0L; ++u; }
    return fmt_fixed(v < 0 ? -x : x, decimals) + " " + kUnit[u];
}

inline std::string fmt_bytes(std::uint64_t n) {
    static const char* kUnit[] = {"B", "KiB", "MiB", "GiB"};
    int u = 0;
    long double x = static_cast<long double>(n);
    while (x >= 1024.0L && u < 3) { x /= 1024.0L; ++u; }
    return fmt_fixed(x, u == 0 ? 0 : 1) + " " + kUnit[u];
}

inline std::string fmt_hms(std::uint64_t ms) {
    const std::uint64_t s = ms / 1000;
    char b[32];
    std::snprintf(b, sizeof(b), "%02llu:%02llu:%02llu",
                  static_cast<unsigned long long>(s / 3600),
                  static_cast<unsigned long long>((s / 60) % 60),
                  static_cast<unsigned long long>(s % 60));
    return std::string(b);
}

// Compact age: 7s, 2m11s, 1h04m, 3d.
inline std::string fmt_age(std::uint64_t ms) {
    const std::uint64_t s = ms / 1000;
    char b[32];
    if (s < 60)        std::snprintf(b, sizeof(b), "%llus", static_cast<unsigned long long>(s));
    else if (s < 3600) std::snprintf(b, sizeof(b), "%llum%02llus",
                                     static_cast<unsigned long long>(s / 60),
                                     static_cast<unsigned long long>(s % 60));
    else if (s < 86400) std::snprintf(b, sizeof(b), "%lluh%02llum",
                                      static_cast<unsigned long long>(s / 3600),
                                      static_cast<unsigned long long>((s / 60) % 60));
    else std::snprintf(b, sizeof(b), "%llud", static_cast<unsigned long long>(s / 86400));
    return std::string(b);
}

// The cadence bar. The scale runs 0 .. 2x target, so a chain exactly on target
// fills exactly half and stops at the `:` mark; slower chains overrun it,
// faster chains fall short of it. All integer maths -- a bar that rounds
// differently on another compiler would break the golden for no reason.
inline std::string cadence_bar(std::uint64_t observed_ms, std::uint64_t target_ms,
                               std::size_t width) {
    if (width < 3) width = 3;
    const std::size_t mark = width / 2;
    std::size_t n = 0;
    if (target_ms) {
        const std::uint64_t span = 2ull * target_ms;
        const std::uint64_t o = observed_ms > span ? span : observed_ms;
        n = static_cast<std::size_t>((o * width) / span);
    }
    std::string s(1, '[');
    for (std::size_t i = 0; i < width; ++i)
        s.push_back(i < n ? '#' : (i == mark ? ':' : '-'));
    s.push_back(']');
    return s;
}

// The pulse. One character per live inter-arrival gap, oldest left, newest
// right, scaled against 2x target so the target gap sits mid-ramp.
inline std::string sparkline(const std::vector<std::uint64_t>& gaps_ms,
                             std::uint64_t target_ms, std::size_t width) {
    static const char kRamp[] = "_.-=+*#";
    const std::size_t levels = sizeof(kRamp) - 2;      // 6 -> indices 0..6
    std::string s;
    if (gaps_ms.empty() || width == 0) return s;
    std::size_t begin = 0;
    if (gaps_ms.size() > width) begin = gaps_ms.size() - width;
    const std::uint64_t span = target_ms ? 2ull * target_ms : 1;
    for (std::size_t i = begin; i < gaps_ms.size(); ++i) {
        std::uint64_t g = gaps_ms[i];
        if (g > span) g = span;
        std::size_t lv = static_cast<std::size_t>((g * levels) / span);
        if (lv > levels) lv = levels;
        s.push_back(kRamp[lv]);
    }
    return s;
}

inline std::string upper(const std::string& s) {
    std::string o = s;
    for (char& c : o) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return o;
}

// ---------------------------------------------------------------------------
// THE EMITTED ID SET, computed rather than typed.
//
// Encodes every ControlMessage that exists and reads back the id byte. The
// footer prints what this returns, so the read-only claim on screen is derived
// from the encoder at run time; the KAT asserts it equals {0, 1, 3, 6}.
// ---------------------------------------------------------------------------
inline std::vector<int> emitted_id_set() {
    std::vector<int> ids;
    ControlArgs a{};
    for (std::size_t i = 0; i < kControlMessageCount; ++i) {
        const std::vector<std::uint8_t> bytes = encode(static_cast<ControlMessage>(i), a);
        if (bytes.empty()) continue;
        const int id = static_cast<int>(bytes[0]);
        if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    }
    std::sort(ids.begin(), ids.end());
    return ids;
}

inline std::string emitted_id_set_string() {
    const std::vector<int> ids = emitted_id_set();
    std::string s = "{";
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (i) s += ",";
        s += std::to_string(ids[i]);
    }
    return s + "}";
}

// ---------------------------------------------------------------------------
// THE FRAME'S INPUT. Plain data, one snapshot in time.
// ---------------------------------------------------------------------------

// The outbound byte ledger, copied out of the observer's. Copied rather than
// referenced so this header needs nothing from the socket layer.
struct EmitCounts {
    std::uint64_t messages[kControlMessageCount] = {0, 0, 0, 0};
    std::uint64_t bytes[kControlMessageCount]    = {0, 0, 0, 0};

    std::uint64_t total_messages() const noexcept {
        std::uint64_t t = 0;
        for (std::size_t i = 0; i < kControlMessageCount; ++i) t += messages[i];
        return t;
    }
    std::uint64_t total_bytes() const noexcept {
        std::uint64_t t = 0;
        for (std::size_t i = 0; i < kControlMessageCount; ++i) t += bytes[i];
        return t;
    }
};

struct FeedRow {
    std::uint64_t height   = 0;
    std::string   id8;                  // first 8 hex characters of the sidechain id
    std::uint64_t age_ms   = 0;
    std::size_t   shares   = 0;         // PPLNS payout lines in the coinbase
    std::size_t   uncles   = 0;
    bool          contested = false;    // another block already sits at this height
    bool          verified  = false;    // sidechain id recomputed and matched
};

// THE STATUS WORD now comes from p2pool_freshness.hpp, where it grew from four
// values to seven. The four it had (DARK / DIAL / WARM / LIVE) described the
// warm-up of a connection and could not say anything about a connection that
// was healthy and stopped being healthy -- the case a long run actually meets.
// DOWN, QUIET and STALE are that case. The alias is kept so every call site
// that says ChainStatus still reads correctly; they are the same type.
using ChainStatus = Liveness;

// What a number means when there is no number. Two ASCII columns, so it lines
// up under a figure and cannot be read as a value -- which is the whole point:
// `0` is a measurement that came out zero, `--` is the absence of one.
inline constexpr const char* kNoData = "--";

inline std::string or_dash(bool have, const std::string& s) {
    return have ? s : std::string(kNoData);
}

// Where a panel's numbers came from. A frame reconstructed from the state file
// is not a live reading and never renders as one.
enum class ChainSource : std::uint8_t { Live = 0, Restored = 1 };

inline const char* to_string(ChainSource s) noexcept {
    return s == ChainSource::Restored ? "restored" : "live";
}

struct ChainView {
    Sidechain     chain     = Sidechain::Main;
    std::uint16_t port      = 0;
    std::uint64_t target_s  = 0;
    ChainStatus   status    = ChainStatus::Dark;

    // ---- absence-vs-zero -------------------------------------------------
    // `have_data` gates EVERY chain figure below. False means the panel prints
    // `--` rather than the zero-initialised member, and it is false whenever
    // this monitor holds no sidechain block for the chain: not connected yet,
    // never connected, connected and told nothing. The read model's own
    // counters are not consulted for this, because a counter that was never
    // incremented and a counter that counted nothing are the same integer.
    bool          have_data      = false;
    ChainSource   source         = ChainSource::Live;
    FreshnessView fresh;                  // the absolute instants, for the file
    std::uint64_t status_age_ms  = 0;     // how long the status word has held
    bool          status_age_known = false;
    std::uint64_t tip_age_ms     = 0;     // since the tip HEIGHT last increased
    std::uint64_t rx_age_ms      = 0;     // since a new distinct block arrived
    std::uint64_t data_age_ms    = 0;     // Restored only: age of the file read

    // ---- continuity carried across a restart, from the state file --------
    bool          carried             = false;
    std::uint64_t carry_written_at_ms = 0;   // wall ms the carried state was saved
    std::uint64_t carry_age_ms        = 0;   // resolved against the frame's `now`
    std::uint64_t carry_tip_height    = 0;
    std::string   carry_tip_id8;
    std::uint64_t lifetime_tip_max    = 0;   // highest tip ever seen, any session
    std::uint64_t lifetime_monero_max = 0;

    std::uint64_t tip_height = 0;
    std::string   tip_id;                 // full 64 hex, for the state file
    std::string   tip_id8;
    std::string   difficulty;            // exact decimal
    std::string   cumulative;            // exact decimal, for the state file
    long double   difficulty_d = 0.0L;
    long double   cumulative_d = 0.0L;
    long double   hashrate     = 0.0L;   // H/s, implied by difficulty / target

    bool          cadence_ok = false;
    double        cadence_s  = 0.0;
    std::size_t   cadence_n  = 0;
    std::uint64_t frontier   = 0;
    std::vector<std::uint64_t> gaps_ms;  // live inter-arrival gaps, oldest first

    std::size_t   contested = 0;
    std::size_t   uncles_named = 0;
    std::size_t   uncles_resolved = 0;

    std::uint64_t monero_high = 0;
    std::size_t   monero_heights = 0;

    std::size_t   peers_up = 0;          // handshaken
    std::size_t   sockets  = 0;          // sockets alive, handshaken or not
    std::size_t   peers_known = 0;
    std::size_t   gossiped = 0;
    std::size_t   queued = 0;            // addresses waiting to be dialled

    std::size_t   distinct = 0;
    std::size_t   dupes = 0;
    std::size_t   parse_failures = 0;
    std::size_t   broadcasts = 0;

    std::vector<FeedRow> feed;           // newest first
    EmitCounts    out;
};

// ---------------------------------------------------------------------------
// THE PERSISTENCE BANNER. Everything the frame says about its own durability,
// resolved to plain data like everything else here, so the header row is a pure
// function and the KAT can pin it.
//
// It is drawn at kAlways priority and it is drawn even when persistence is OFF,
// with the REASON. A monitor whose numbers die with the session is a different
// tool from one whose numbers survive a kill, and which of the two is running
// must not be something the operator has to infer from the absence of a line.
// ---------------------------------------------------------------------------
struct PersistView {
    bool          enabled  = false;
    std::string   dir;                    // where the files are, when enabled
    std::string   off_reason;             // why not, when disabled
    std::uint64_t seq = 0;                // saves in this session
    std::uint64_t saved_age_ms = 0;       // since the last successful save
    bool          ever_saved = false;
    std::size_t   errors = 0;
    std::string   last_error;
    std::uint64_t journal_lines = 0;
    std::uint64_t loop_stall_max_ms = 0;  // worst gap between loop turns

    bool          restored = false;       // a previous state was read at start
    std::uint64_t restored_age_ms = 0;    // how old that state was
    std::uint64_t sessions = 1;           // this one included
    std::uint64_t runtime_ms_total = 0;   // across every session, this one included
};

struct MonitorFrame {
    std::uint64_t          elapsed_ms = 0;
    bool                   interactive = false;   // draws the key hints
    std::vector<ChainView> chains;
    PersistView            persist;
    // True when the whole frame was reconstructed from the state file rather
    // than from live read models: `--read`. Draws a banner, because a frame
    // that dialled nothing must not be mistaken for one that did.
    bool                   from_file = false;
    std::uint64_t          file_age_ms = 0;
};

struct MonitorTotals {
    std::size_t   chains = 0;
    std::size_t   chains_live = 0;        // LIVE or WARM: a source we are hearing
    std::size_t   chains_reporting = 0;   // have_data: a source we have numbers for
    std::size_t   chains_degraded = 0;    // QUIET / STALE / DOWN / DARK / DIAL
    std::size_t   chains_down = 0;        // DOWN or DARK: no peers at all
    std::size_t   chains_stale = 0;       // QUIET or STALE: peers, but nothing moving
    std::size_t   peers_up = 0;
    std::size_t   peers_known = 0;
    std::size_t   blocks = 0;
    std::size_t   contested = 0;
    std::size_t   parse_failures = 0;
    std::uint64_t messages_out = 0;
    std::uint64_t bytes_out = 0;
};

// The three-chain aggregation, in one place so the KAT can check it against the
// per-chain numbers rather than against the renderer's arithmetic.
//
// AN AGGREGATE OVER A DEAD SOURCE IS THE SECOND HALF OF THE ABSENCE-VS-ZERO
// PROBLEM. Summing three panels when one of them is dark produces a total that
// is arithmetically correct and editorially false: "blocks 15" reads as the
// three-chain figure, and it is a two-chain figure. Nothing here is fixed by
// dropping the dead chain from the sum -- that hides it. What is carried
// instead is the COVERAGE: how many of the configured chains actually have
// numbers behind them, which the header prints beside every total.
inline MonitorTotals totals_of(const std::vector<ChainView>& chains) {
    MonitorTotals t;
    t.chains = chains.size();
    for (const ChainView& c : chains) {
        if (c.status == ChainStatus::Live || c.status == ChainStatus::Warming) ++t.chains_live;
        if (c.have_data) ++t.chains_reporting;
        if (is_degraded(c.status)) ++t.chains_degraded;
        if (c.status == ChainStatus::Down || c.status == ChainStatus::Dark ||
            c.status == ChainStatus::Dialling) ++t.chains_down;
        if (c.status == ChainStatus::Quiet || c.status == ChainStatus::Stale) ++t.chains_stale;
        t.peers_up       += c.peers_up;
        t.peers_known    += c.peers_known;
        t.blocks         += c.distinct;
        t.contested      += c.contested;
        t.parse_failures += c.parse_failures;
        t.messages_out   += c.out.total_messages();
        t.bytes_out      += c.out.total_bytes();
    }
    return t;
}

// ---------------------------------------------------------------------------
// Turning one read model into one panel's worth of data, at one instant.
//
// `now_ms` is passed in rather than read, which is the whole reason a golden
// frame is possible. Everything else is a straight read of the model.
// ---------------------------------------------------------------------------
inline ChainView view_of(const ReadModel& m, const EmitCounts& out, std::size_t sockets,
                         std::size_t queued, std::uint64_t now_ms,
                         const FreshnessView& fresh = FreshnessView{},
                         const FreshnessThresholds& th = FreshnessThresholds{},
                         std::size_t feed_rows = 8, std::size_t pulse_width = 24) {
    ChainView v;
    v.chain    = m.chain();
    v.port     = default_port(m.chain());
    v.target_s = m.params().target_block_time;

    v.tip_height   = m.tip_height();
    v.tip_id       = m.tip_height() ? hex(m.tip_id()) : std::string();
    v.tip_id8      = m.tip_height() ? hex(m.tip_id()).substr(0, 8) : std::string("-");
    v.difficulty   = m.tip_difficulty().to_string();
    v.cumulative   = m.tip_cumulative_difficulty().to_string();
    v.difficulty_d = m.tip_difficulty().as_double();
    v.cumulative_d = m.tip_cumulative_difficulty().as_double();
    v.hashrate     = m.implied_hashrate();

    double cad = 0.0;
    std::size_t n = 0;
    v.cadence_ok = m.cadence_seconds(cad, n);
    v.cadence_s  = cad;
    v.cadence_n  = n;
    v.frontier   = m.frontier_height();
    v.gaps_ms    = m.live_arrival_gaps_ms(pulse_width);

    v.contested        = m.contested_heights();
    v.uncles_named     = m.uncles_seen();
    v.uncles_resolved  = m.uncles_resolved();
    v.monero_high      = m.monero_height_high();
    v.monero_heights   = m.monero_heights_crossed();

    v.peers_up    = m.connected_peers();
    v.sockets     = sockets;
    v.peers_known = m.known_peers();
    v.gossiped    = m.gossiped_addresses();
    v.queued      = queued;

    v.distinct       = m.distinct_blocks();
    v.dupes          = m.duplicate_receives();
    v.parse_failures = m.parse_failures();
    v.broadcasts     = m.broadcasts_seen();
    v.out            = out;

    // ---- absence, freshness, and the status word -------------------------
    // HAVE_DATA IS THE MODEL HOLDING A BLOCK, not a counter being non-zero.
    // distinct_blocks() counts ids the model actually stores, so it is zero
    // exactly when there is nothing to report and non-zero exactly when there
    // is -- which is what the `--` rendering needs and what no other counter
    // here can promise.
    v.have_data = m.distinct_blocks() > 0;
    v.fresh     = fresh;
    v.status    = classify(fresh, v.peers_up, v.sockets, v.queued, v.cadence_ok,
                           v.target_s, now_ms, th);
    v.tip_age_ms = fresh.tip_age_ms(now_ms);
    v.rx_age_ms  = fresh.rx_age_ms(now_ms);

    // WHICH CLOCK THE STATUS WORD IS SHOWING. Each word is about a different
    // event, so each one is timed from that event and not from a single "age"
    // that would mean something different in every row:
    //   DOWN            since the last peer went away
    //   DARK / DIAL     since this chain started being watched (we have never
    //                   been connected, so there is no outage to time)
    //   everything else since the tip last moved
    v.status_age_known = fresh.known;
    if (!fresh.known) {
        v.status_age_ms = 0;
    } else if (v.status == ChainStatus::Down) {
        v.status_age_ms = fresh.down_ms(now_ms);
    } else if (v.status == ChainStatus::Dark || v.status == ChainStatus::Dialling) {
        v.status_age_ms = FreshnessView::age(now_ms, fresh.started_at_ms);
    } else {
        v.status_age_ms = v.tip_age_ms;
    }

    // The feed is arrival order, newest first, deduplicated by construction:
    // arrival_order() holds one entry per DISTINCT id.
    const std::vector<Hash>& order = m.arrival_order();
    for (std::size_t i = order.size(); i-- > 0 && v.feed.size() < feed_rows;) {
        const ObservedBlock* b = m.find(order[i]);
        if (!b) continue;
        FeedRow r;
        r.height   = b->sidechain_height;
        r.id8      = hex(b->sidechain_id).substr(0, 8);
        r.age_ms   = now_ms >= b->first_seen_ms ? now_ms - b->first_seen_ms : 0;
        r.shares   = b->share_outputs;
        r.uncles   = b->uncles.size();
        r.verified = b->id_verified;
        const auto it = m.heights().find(b->sidechain_height);
        r.contested = (it != m.heights().end() && it->second.ids.size() > 1);
        v.feed.push_back(r);
    }
    return v;
}

// ---------------------------------------------------------------------------
// THE RENDERER
// ---------------------------------------------------------------------------
namespace detail {

// Line priority. Everything at kAlways is drawn whatever the terminal size;
// the rest is shed from the bottom of the list when the window is short, so a
// small terminal loses detail rather than losing a chain.
enum Level : int { kAlways = 0, kDetail = 2, kNetwork = 3, kFeed = 4 };

using Row = std::pair<int, std::string>;

inline const char* chain_color(Sidechain s) {
    switch (s) {
        case Sidechain::Main: return kCyan;
        case Sidechain::Mini: return kMagenta;
        case Sidechain::Nano: return kYellow;
    }
    return kWhite;
}

inline const char* status_color(ChainStatus s) {
    switch (s) {
        case ChainStatus::Live:     return kGreen;
        case ChainStatus::Warming:  return kYellow;
        case ChainStatus::Quiet:    return kYellow;
        case ChainStatus::Stale:    return kRed;
        case ChainStatus::Down:     return kRed;
        case ChainStatus::Dialling: return kBlue;
        case ChainStatus::Dark:     return kRed;
    }
    return kWhite;
}

// The status word with the age of the thing it is talking about, and a short
// sentence for the states a reader should not have to interpret. LIVE says
// nothing extra: it is the only state that needs no excuse.
inline std::string status_phrase(const ChainView& v) {
    std::string s = to_string(v.status);
    if (v.status_age_known && v.status != ChainStatus::Live)
        s += " " + fmt_age(v.status_age_ms);
    switch (v.status) {
        case ChainStatus::Dark:  s += " never connected"; break;
        case ChainStatus::Down:  s += " no peers";        break;
        case ChainStatus::Stale: s += " tip frozen";      break;
        default: break;
    }
    return s;
}

// Green inside 25% of target, yellow inside 60%, red outside. The chain's own
// variance is large, so the bands are wide on purpose: this flags "something is
// wrong with our view of the chain", not "a block was late".
inline const char* cadence_color(double observed_s, std::uint64_t target_s) {
    if (!target_s) return kWhite;
    const double r = observed_s / static_cast<double>(target_s);
    if (r >= 0.75 && r <= 1.25) return kGreen;
    if (r >= 0.40 && r <= 1.60) return kYellow;
    return kRed;
}

inline void label(Line& l, const char* text) {
    l.put("   ").sgr(kDim).put(text).sgr(kReset).pad_to(12);
}

inline void panel(const ChainView& v, std::size_t cols, bool color, std::vector<Row>& rows) {
    const bool have = v.have_data;
    {   // title
        Line l(cols, color);
        l.put(" ").sgr(kBold).sgr(chain_color(v.chain)).put(upper(to_string(v.chain)));
        l.sgr(kReset).put("  port ").put(std::to_string(v.port));
        l.put("  ").sgr(status_color(v.status)).put(status_phrase(v)).sgr(kReset);
        l.put("  ").sgr(kDim).put("target ").sgr(kReset).put(std::to_string(v.target_s)).put("s");
        if (v.source == ChainSource::Restored) {
            l.put("  ").sgr(kYellow).put("[FROM FILE ").put(fmt_age(v.data_age_ms))
             .put(" OLD]").sgr(kReset);
        }
        l.put(" ").sgr(kDim).repeat('-', l.room()).sgr(kReset);
        rows.emplace_back(kAlways, l.take());
    }
    if (is_degraded(v.status)) {
        // THE "WHY" ROW. A status word on its own makes the reader guess at
        // what it implies about the figures underneath, and at 4am a reader
        // guesses generously. So a degraded panel states, in a sentence, what
        // is missing and how old the rest of the panel is -- at kAlways
        // priority, so a short terminal sheds detail rows before it sheds the
        // reason the detail is not to be trusted.
        Line l(cols, color);
        label(l, "!");
        l.sgr(status_color(v.status)).sgr(kBold).put(to_string(v.status)).sgr(kReset).put("  ");
        const std::string age = v.status_age_known ? fmt_age(v.status_age_ms) : std::string("?");
        switch (v.status) {
            case ChainStatus::Down:
                l.sgr(kDim).put("no peers for ").sgr(kReset).put(age).sgr(kDim)
                 .put(have ? " -- the figures below are last known, not current"
                           : " -- nothing was ever received from this chain");
                break;
            case ChainStatus::Dark:
                l.sgr(kDim).put("never connected, ").sgr(kReset).put(age).sgr(kDim)
                 .put(" into this session -- nothing below was measured");
                break;
            case ChainStatus::Dialling:
                l.sgr(kDim).put("dialling for ").sgr(kReset).put(age).sgr(kDim)
                 .put(" -- no handshake yet, nothing below was measured");
                break;
            case ChainStatus::Stale:
                l.sgr(kDim).put("no new height for ").sgr(kReset).put(age);
                l.sgr(kDim).put(", last rx ").sgr(kReset).put(fmt_age(v.rx_age_ms));
                l.sgr(kDim).put(" -- the figures below are that old");
                break;
            case ChainStatus::Quiet:
                l.sgr(kDim).put("no new height for ").sgr(kReset).put(age);
                l.sgr(kDim).put(", last rx ").sgr(kReset).put(fmt_age(v.rx_age_ms));
                l.sgr(kDim).put(" -- long for this chain, not yet wrong");
                break;
            default:
                break;
        }
        rows.emplace_back(kAlways, l.take());
    }
    {   // tip
        //
        // THE `--` ROW. Every figure on this line is gated on have_data, and
        // all of them together: a chain we hold no block for has no tip height,
        // no id, no difficulty and no implied hashrate, and printing the
        // zero-initialised members would put "0" and "0.00 H/s" on screen in
        // the same shape a live chain uses. The age beside them says when the
        // numbers were last true, which is the other half of not lying.
        Line l(cols, color);
        label(l, "tip");
        if (!have) l.sgr(kDim);
        l.sgr(have ? kBold : kDim).put(or_dash(have, std::to_string(v.tip_height))).sgr(kReset);
        if (!have) l.sgr(kDim);
        l.put(" ").put(have ? v.tip_id8 : std::string(kNoData));
        l.put("  ").sgr(kDim).put("diff ").sgr(kReset).put(or_dash(have, fmt_si(v.difficulty_d)));
        l.put("  ").sgr(kDim).put("hash ").sgr(kReset)
         .put(have ? fmt_si(v.hashrate) + "H/s" : std::string(kNoData));
        l.put("  ").sgr(kDim).put("cum ").sgr(kReset).put(or_dash(have, fmt_si(v.cumulative_d)));
        if (have && v.status_age_known) {
            l.put("  ").sgr(is_degraded(v.status) ? kRed : kDim).put("as of ")
             .put(fmt_age(v.tip_age_ms)).sgr(kReset);
        }
        rows.emplace_back(kAlways, l.take());
    }
    {   // cadence
        Line l(cols, color);
        label(l, "cadence");
        if (!have) {
            l.sgr(kDim).put(kNoData).put("  no block held for this chain: nothing to time")
             .sgr(kReset);
        } else if (v.cadence_ok) {
            const std::uint64_t obs_ms = static_cast<std::uint64_t>(v.cadence_s * 1000.0 + 0.5);
            l.sgr(cadence_color(v.cadence_s, v.target_s));
            l.put(fmt_fixed(static_cast<long double>(v.cadence_s), 2)).put(" s");
            l.sgr(kReset).sgr(kDim).put(" / ").sgr(kReset).put(std::to_string(v.target_s)).put(" s  ");
            l.sgr(cadence_color(v.cadence_s, v.target_s));
            l.put(cadence_bar(obs_ms, v.target_s * 1000ull, 16));
            l.sgr(kReset);
            l.put("  ").sgr(kDim).put("over ").sgr(kReset).put(std::to_string(v.cadence_n));
            l.sgr(kDim).put(" live heights above ").sgr(kReset).put(std::to_string(v.frontier));
        } else {
            l.sgr(kDim).put("warming -- ").sgr(kReset).put(std::to_string(v.cadence_n));
            l.sgr(kDim).put(" live height(s) above frontier ").sgr(kReset)
             .put(std::to_string(v.frontier)).sgr(kDim).put("; two are needed to time the chain");
        }
        rows.emplace_back(kAlways, l.take());
    }
    {   // pulse
        Line l(cols, color);
        label(l, "pulse");
        const std::string sp = have ? sparkline(v.gaps_ms, v.target_s * 1000ull, 24) : std::string();
        if (!have)          l.sgr(kDim).put(kNoData).put("  (no data)").sgr(kReset);
        else if (sp.empty()) l.sgr(kDim).put("(no live gaps yet)");
        else {
            l.sgr(cadence_color(v.cadence_ok ? v.cadence_s : static_cast<double>(v.target_s),
                                v.target_s)).put(sp).sgr(kReset);
            l.put("  ").sgr(kDim).put("gaps, newest right (").sgr(kReset)
             .put(std::to_string(v.gaps_ms.size())).sgr(kDim).put(")");
        }
        rows.emplace_back(kDetail, l.take());
    }
    {   // races
        Line l(cols, color);
        label(l, "races");
        l.sgr(kDim).put("contested ").sgr(kReset).put(or_dash(have, std::to_string(v.contested)));
        l.sgr(kDim).put("  uncles named ").sgr(kReset)
         .put(or_dash(have, std::to_string(v.uncles_named)));
        l.sgr(kDim).put(" resolved ").sgr(kReset)
         .put(or_dash(have, std::to_string(v.uncles_resolved)));
        l.sgr(kDim).put("  monero tpl ").sgr(kReset)
         .put(or_dash(have, std::to_string(v.monero_high)));
        l.sgr(kDim).put(" over ").sgr(kReset).put(or_dash(have, std::to_string(v.monero_heights)));
        l.sgr(kDim).put(" heights");
        rows.emplace_back(kDetail, l.take());
    }
    if (v.carried) {
        // CONTINUITY. What the last session left in the state file, labelled
        // with its age and kept on its own row so it can never be mistaken for
        // a live reading. This row is the visible half of "the numbers survived
        // the kill": on a restart it is populated before a single packet has
        // been sent, and on a chain that is down it is the only chain figure on
        // the panel that is not a `--`.
        Line l(cols, color);
        label(l, "carry");
        l.sgr(kDim).put("prev tip ").sgr(kReset).put(std::to_string(v.carry_tip_height));
        if (!v.carry_tip_id8.empty()) l.put(" ").sgr(kDim).put(v.carry_tip_id8).sgr(kReset);
        l.sgr(kDim).put("  saved ").sgr(kReset).put(fmt_age(v.carry_age_ms))
         .sgr(kDim).put(" ago");
        l.sgr(kDim).put("  lifetime tip ").sgr(kReset).put(std::to_string(v.lifetime_tip_max));
        l.sgr(kDim).put("  monero tpl ").sgr(kReset).put(std::to_string(v.lifetime_monero_max));
        rows.emplace_back(kDetail, l.take());
    }
    {   // net
        Line l(cols, color);
        label(l, "net");
        l.sgr(v.peers_up ? kGreen : kRed).put(std::to_string(v.peers_up)).sgr(kReset);
        l.sgr(kDim).put(" up / ").sgr(kReset).put(std::to_string(v.sockets));
        l.sgr(kDim).put(" sock / ").sgr(kReset).put(std::to_string(v.peers_known));
        l.sgr(kDim).put(" known / ").sgr(kReset).put(std::to_string(v.gossiped));
        l.sgr(kDim).put(" gossip / ").sgr(kReset).put(std::to_string(v.queued));
        l.sgr(kDim).put(" queued");
        // PEER COUNTS ARE NEVER DASHED. "0 up" is a measurement -- we looked at
        // our own socket table and there were none -- and it is paired with the
        // status word that says what that means. The BLOCK counts beside them
        // are dashed, because a model holding nothing has not counted zero
        // duplicates, it has counted nothing.
        l.sgr(kDim).put("  blocks ").sgr(kReset).put(or_dash(have, std::to_string(v.distinct)));
        l.sgr(kDim).put(" (dup ").sgr(kReset).put(or_dash(have, std::to_string(v.dupes)));
        l.sgr(kDim).put(", bad ").sgr(kReset).put(or_dash(have, std::to_string(v.parse_failures)));
        l.sgr(kDim).put(", bc ").sgr(kReset).put(or_dash(have, std::to_string(v.broadcasts)));
        l.sgr(kDim).put(")");
        rows.emplace_back(kNetwork, l.take());
    }
    {   // out
        Line l(cols, color);
        label(l, "out");
        l.sgr(kDim).put("chal ").sgr(kReset).put(std::to_string(v.out.messages[0]));
        l.sgr(kDim).put("  sol ").sgr(kReset).put(std::to_string(v.out.messages[1]));
        l.sgr(kDim).put("  block_req ").sgr(kReset).put(std::to_string(v.out.messages[2]));
        l.sgr(kDim).put("  peer_req ").sgr(kReset).put(std::to_string(v.out.messages[3]));
        l.sgr(kDim).put("  = ").sgr(kReset).put(fmt_bytes(v.out.total_bytes()));
        l.sgr(kDim).put(" sent");
        rows.emplace_back(kNetwork, l.take());
    }
    {   // feed
        Line l(cols, color);
        label(l, "feed");
        // ARRIVAL order, newest first -- not height order. A backfilled parent
        // arrives after the tip that named it, and showing the order things
        // actually reached us is the point of a feed.
        if (v.feed.empty() && v.source == ChainSource::Restored)
            l.sgr(kDim).put("(the state file carries totals, not the arrival feed)");
        else if (v.feed.empty()) l.sgr(kDim).put("(nothing received yet)");
        for (const FeedRow& r : v.feed) {
            // Only start an entry that fits whole: a feed row cut in half looks
            // like a truncated block id, which is exactly the wrong thing for a
            // reader to wonder about.
            if (l.room() < 32) break;
            l.put(std::to_string(r.height)).put(" ");
            l.sgr(kDim).put(r.id8).sgr(kReset);
            l.sgr(kYellow).put(r.contested ? '*' : ' ').sgr(kReset);
            l.put(" ").put(fmt_age(r.age_ms));
            l.put(" ").put(std::to_string(r.shares)).sgr(kDim).put("sh").sgr(kReset);
            if (r.uncles) { l.sgr(kDim).put(" u").sgr(kReset).put(std::to_string(r.uncles)); }
            l.put("   ");
        }
        rows.emplace_back(kFeed, l.take());
    }
    rows.emplace_back(kFeed, Line(cols, color).take());   // breathing room
}

inline void header(const MonitorFrame& f, const MonitorTotals& t, std::size_t cols, bool color,
                   std::vector<Row>& rows) {
    {
        Line l(cols, color);
        l.put(" ").sgr(kBold).put("p2pool monitor").sgr(kReset);
        l.put("  ").sgr(kBold).sgr(kGreen).put("READ-ONLY").sgr(kReset);
        l.put("  ").sgr(kDim).put("chains ").sgr(kReset)
         .sgr(t.chains_live == t.chains ? kGreen : kYellow)
         .put(std::to_string(t.chains_live)).put("/").put(std::to_string(t.chains)).sgr(kReset);
        if (t.chains_down)  l.put("  ").sgr(kRed).put(std::to_string(t.chains_down))
                             .put(" down").sgr(kReset);
        if (t.chains_stale) l.put("  ").sgr(kRed).put(std::to_string(t.chains_stale))
                             .put(" stale").sgr(kReset);
        l.put("  ").sgr(kDim).put("up ").sgr(kReset).put(fmt_hms(f.elapsed_ms));
        l.put("  ").sgr(kDim).put("peers ").sgr(kReset).put(std::to_string(t.peers_up))
         .put("/").put(std::to_string(t.peers_known));
        l.put("  ").sgr(kDim).put("blocks ").sgr(kReset).put(std::to_string(t.blocks));
        l.put("  ").sgr(kDim).put("races ").sgr(kReset).put(std::to_string(t.contested));
        l.put("  ").sgr(kReset).put(fmt_bytes(t.bytes_out)).sgr(kDim).put(" out");
        rows.emplace_back(kAlways, l.take());
    }
    {
        // COVERAGE, stated in words on its own row and never inferred.
        //
        // The totals above are sums over the CONFIGURED chains, and when one of
        // them is dark that sum is a smaller-than-it-looks number wearing a
        // three-chain label. Dropping the dead chain from the total would hide
        // it; the fix is to print how many chains are actually behind the
        // figures, every frame, whether or not anything is wrong.
        Line l(cols, color);
        l.put(" ").sgr(kDim).put("coverage ").sgr(kReset);
        l.sgr(t.chains_reporting == t.chains ? kGreen : kYellow)
         .put(std::to_string(t.chains_reporting)).put("/")
         .put(std::to_string(t.chains)).sgr(kReset)
         .sgr(kDim).put(" reporting (the totals above cover those)").sgr(kReset);
        for (const ChainView& c : f.chains) {
            if (l.room() < 18) break;
            l.put("  ").sgr(chain_color(c.chain)).put(upper(to_string(c.chain))).sgr(kReset);
            l.put(" ").sgr(status_color(c.status)).put(to_string(c.status)).sgr(kReset);
        }
        rows.emplace_back(kAlways, l.take());
    }
    {
        // THE DURABILITY BANNER. Drawn every frame, in both states, because
        // "are these numbers going to survive this process" is not something an
        // operator should have to discover by killing it.
        const PersistView& p = f.persist;
        Line l(cols, color);
        l.put(" ").sgr(kDim).put("persist  ").sgr(kReset);
        if (!p.enabled) {
            l.sgr(kBold).sgr(kRed).put("OFF").sgr(kReset);
            l.put(" ").sgr(kRed).put(p.off_reason.empty() ? std::string("(no reason given)")
                                                          : p.off_reason).sgr(kReset);
            l.sgr(kDim).put("  -- every number here is in-process only and dies with the session");
        } else {
            l.sgr(p.errors ? kYellow : kGreen).put("ON").sgr(kReset);
            // WRITE ERRORS COME FIRST, before the path and the counters. This
            // row is the one that overflows a narrow terminal, and the field
            // that must never be the one truncated away is the one saying the
            // file is not being written.
            if (p.errors)
                l.put("  ").sgr(kRed).sgr(kBold).put("ERR ").put(std::to_string(p.errors))
                 .sgr(kReset).sgr(kRed).put(": ").put(p.last_error).sgr(kReset);
            l.put(" ").put(p.dir);
            l.sgr(kDim).put("  seq ").sgr(kReset).put(std::to_string(p.seq));
            l.sgr(kDim).put(" saved ").sgr(kReset)
             .put(p.ever_saved ? fmt_age(p.saved_age_ms) + " ago" : std::string("never"));
            l.sgr(kDim).put("  session ").sgr(kReset).put(std::to_string(p.sessions));
            if (p.restored)
                l.sgr(kDim).put(" from ").sgr(kReset).put(fmt_age(p.restored_age_ms))
                 .sgr(kDim).put("-old state");
            if (p.loop_stall_max_ms)
                l.sgr(kDim).put("  stall ").sgr(kReset)
                 .put(std::to_string(p.loop_stall_max_ms)).sgr(kDim).put(" ms");
            l.sgr(kDim).put("  total up ").sgr(kReset).put(fmt_hms(p.runtime_ms_total));
        }
        rows.emplace_back(kAlways, l.take());
    }
    if (f.from_file) {
        Line l(cols, color);
        l.put(" ").sgr(kBold).sgr(kYellow).put("RESTORED FRAME").sgr(kReset);
        l.sgr(kDim).put("  rendered from the state file, written ").sgr(kReset)
         .put(fmt_age(f.file_age_ms)).sgr(kDim)
         .put(" ago -- no network was dialled and no number below is current");
        rows.emplace_back(kAlways, l.take());
    }
    {
        Line l(cols, color);
        l.sgr(kDim).repeat('-', cols).sgr(kReset);
        rows.emplace_back(kAlways, l.take());
    }
}

inline void footer(const MonitorFrame& f, std::size_t cols, bool color, std::vector<Row>& rows) {
    {
        Line l(cols, color);
        l.sgr(kDim).repeat('-', cols).sgr(kReset);
        rows.emplace_back(kAlways, l.take());
    }
    {
        Line l(cols, color);
        l.put(" ").sgr(kDim).put("emitted ids ").sgr(kGreen).put(emitted_id_set_string())
         .sgr(kReset).sgr(kDim)
         .put("  CHALLENGE  SOLUTION  BLOCK_REQUEST  PEER_LIST_REQUEST");
        rows.emplace_back(kAlways, l.take());
    }
    {
        Line l(cols, color);
        l.put(" ").sgr(kDim).put("never emitted: LISTEN_PORT, BLOCK_RESPONSE, BLOCK_BROADCAST,"
                                 " BLOCK_NOTIFY -- no encoder exists");
        rows.emplace_back(kAlways, l.take());
    }
    if (f.interactive) {
        Line l(cols, color);
        l.put(" ").sgr(kBold).put("q").sgr(kReset).sgr(kDim).put(" quit   ").sgr(kReset);
        l.sgr(kBold).put("r").sgr(kReset).sgr(kDim).put(" redraw");
        rows.emplace_back(kAlways, l.take());
    }
}

inline std::vector<Row> build(const MonitorFrame& f, std::size_t cols, bool color) {
    std::vector<Row> rows;
    const MonitorTotals t = totals_of(f.chains);
    header(f, t, cols, color, rows);
    for (const ChainView& v : f.chains) panel(v, cols, color, rows);
    footer(f, cols, color, rows);
    return rows;
}

} // namespace detail

// Every line the frame wants, at this width.
inline std::size_t natural_rows(const MonitorFrame& f, std::size_t cols = 100) {
    return detail::build(f, cols, false).size();
}

// EXACTLY `rows` lines, each EXACTLY `cols` visible columns. Detail is shed
// from the bottom of the priority list when the window is short; a window
// shorter than the always-lines is truncated, never wrapped.
inline std::vector<std::string> render(const MonitorFrame& f, std::size_t cols, std::size_t rows,
                                       bool color) {
    if (cols < 40) cols = 40;
    std::vector<detail::Row> all = detail::build(f, cols, color);

    int cut = 5;                       // nothing shed
    for (;;) {
        std::size_t n = 0;
        for (const detail::Row& r : all) if (r.first < cut) ++n;
        if (n <= rows || cut <= detail::kAlways + 1) break;
        --cut;
    }

    std::vector<std::string> out;
    for (const detail::Row& r : all) {
        if (r.first >= cut) continue;
        if (out.size() >= rows) break;
        out.push_back(r.second);
    }
    const std::string blank = Line(cols, false).take();
    while (out.size() < rows) out.push_back(blank);
    return out;
}

// One plain-text frame: no escapes, no trailing blanks, one trailing newline.
// This is what --snapshot writes and what the KAT pins.
inline std::string snapshot_text(const MonitorFrame& f, std::size_t cols = 100) {
    const std::vector<std::string> lines = render(f, cols, natural_rows(f, cols), false);
    std::string s;
    for (const std::string& l : lines) {
        std::size_t end = l.size();
        while (end > 0 && l[end - 1] == ' ') --end;
        s.append(l, 0, end);
        s.push_back('\n');
    }
    return s;
}

} // namespace c2pool::xmr::p2pool::tui
