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
// ---------------------------------------------------------------------------
// TWO STATES PER CHAIN, AND WHY THE STATE IS NOT IN THE FRAME
// ---------------------------------------------------------------------------
// Each panel is drawn either EXPANDED -- the rows above plus the graphics
// described below -- or COLLAPSED: exactly one row, at kAlways priority, that
// replaces the whole panel. Three things about the collapsed row are
// deliberate, because a summary line is the easiest place to lose the honesty
// rules the panel spent so much effort keeping:
//
//   * it carries the FULL status phrase, so DOWN 1m35s no peers is said in the
//     one-liner and collapsing can never hide a degraded chain;
//   * every chain figure on it goes through or_dash(have_data), exactly as the
//     tip row does, so a chain with no data summarises as `--` and not as a
//     row of zeros; peer counts stay real numbers, for the same reason as ever;
//   * a restored panel keeps its [FROM FILE ... OLD] marker.
//
// WHICH CHAINS ARE OPEN IS A RENDER PARAMETER (`Layout`), not a field of
// MonitorFrame. That boundary is load-bearing twice over. The state file is
// built FROM the frame (p2pool_state.hpp), so a UI preference inside the frame
// would silently become part of p2pmon-state/1 -- the file records what the
// monitor KNOWS, never how somebody was looking at it. And the renderer stays a
// pure function of (frame, geometry, layout): the KAT can pin the collapsed
// frame and the expanded frame from ONE fixture, which is exactly the check
// that a summary line agrees with the panel it summarises.
//
// ---------------------------------------------------------------------------
// THE GRAPHICS, AND WHAT EACH ONE REFUSES TO DRAW
// ---------------------------------------------------------------------------
// Every widget is integer maths over a bounded series, drawn in printable
// ASCII, at two new priorities -- kGraph for one-row widgets, kGraphWide for
// the multi-row bar blocks -- so a short window sheds the pictures before it
// sheds a number, and sheds a number before it sheds a chain.
//
//   trend      the difficulty series over the heights this run advanced to,
//              normalised min..max. It is a SHAPE: the exact figure is on the
//              tip row, and the row prints the min and max it scaled against so
//              a flat-looking ramp cannot be mistaken for a flat chain.
//   buckets    the live gaps bucketed against the target -- a histogram. An
//              average hides the difference between a steady beat and two
//              bursts around a stall; the bucket counts do not.
//   heatmap    the same gaps as columns, four rows tall -- the wide pulse.
//   timeline   one character per height held, oldest left, `*` for a contested
//              height and `|` at the frontier, so the backfilled prefix is
//              visibly separated from what we actually watched arrive.
//   peers      up / sockets / known / gossiped as bars against the largest of
//              them. Never dashed: a peer count is our own socket table.
//   recent     the PPLNS payout-line count of each recent block, as columns.
//   pplns      how much of the chain's PPLNS window this observer actually
//              holds, as a gauge. This is a COVERAGE figure about us, not a
//              payout figure about the pool: the read model keeps no ledger,
//              and a gauge that implied one would be the exact lie that file
//              refuses to tell.
//   monero     the Monero template height per recent block, as columns, with
//              the highest seen. Still never a found-block claim.
//
// Every one of them is gated on have_data and draws `--` without a single
// digit when the chain has none, which the KAT walks row by row.
//
// Header-only, STL only. Deliberately free of POSIX: this file is what the KAT
// compiles, and the KAT must not need a socket layer to check a layout.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <map>
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

// The same age, with a marker when the instant it was computed from lies in the
// FUTURE of the clock we measured against -- an NTP step backwards, or a state
// file written by a host whose clock is ahead of this one. The age has been
// clamped to zero by FreshnessView::age(), and a bare "0s" would then read as
// "this happened a moment ago", which is a statement nobody measured. `0s+`
// reads as what it is: at least this old, by an amount this host cannot know.
//
// The marker is one character on purpose. It is appended to a figure inside a
// sentence, and a panel whose layout shifts when a clock steps is a panel that
// draws the eye to the wrong thing.
inline std::string fmt_age(std::uint64_t ms, bool clock_ahead) {
    return clock_ahead ? fmt_age(ms) + "+" : fmt_age(ms);
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

// ---------------------------------------------------------------------------
// THE GRAPHICS PRIMITIVES.
//
// All of them are integer maths over a bounded series and all of them return
// plain ASCII of a length the caller can predict, for the two reasons the rest
// of this file is written that way: a golden frame has to be reproducible on
// every compiler, and one byte has to stay one column.
//
// One shared rule worth stating once: A NON-ZERO MEASUREMENT NEVER DRAWS AS
// EMPTY. A bar whose value rounds below one cell is given one cell, so "a
// little" and "none" are different pictures. Zero draws empty, because an empty
// bar is exactly what zero looks like.
// ---------------------------------------------------------------------------

// `width` cells of '#' and '-', filled by value/span.
inline std::string bar_cells(std::uint64_t value, std::uint64_t span, std::size_t width) {
    std::string s;
    if (width == 0) return s;
    std::size_t n = 0;
    if (span) {
        const std::uint64_t v = value > span ? span : value;
        n = static_cast<std::size_t>((static_cast<unsigned __int128>(v) * width) / span);
    }
    if (n == 0 && value) n = 1;
    for (std::size_t i = 0; i < width; ++i) s.push_back(i < n ? '#' : '-');
    return s;
}

inline std::string gauge(std::uint64_t value, std::uint64_t span, std::size_t width) {
    return "[" + bar_cells(value, span, width) + "]";
}

// The gap histogram. Five buckets of half a target each, the last one open --
// which is the bucket that matters, because it is the one a stall lands in.
inline constexpr std::size_t kCadenceBuckets = 5;

inline const char* cadence_bucket_label(std::size_t i) {
    static const char* const kLabel[kCadenceBuckets] = {
        "0.0-0.5x", "0.5-1.0x", "1.0-1.5x", "1.5-2.0x", "  >2.0x "};
    return i < kCadenceBuckets ? kLabel[i] : "        ";
}

inline std::vector<std::size_t> cadence_histogram(const std::vector<std::uint64_t>& gaps_ms,
                                                  std::uint64_t target_ms) {
    std::vector<std::size_t> b(kCadenceBuckets, 0);
    if (!target_ms) return b;
    for (const std::uint64_t g : gaps_ms) {
        // Quarter-targets, so the bucket edges are exact integers rather than
        // a float comparison that lands differently on two compilers.
        const std::uint64_t q = (g * 4ull) / target_ms;
        std::size_t i = static_cast<std::size_t>(q / 2);
        if (i >= kCadenceBuckets) i = kCadenceBuckets - 1;
        ++b[i];
    }
    return b;
}

// A column chart: one column per value, `height` rows tall, newest on the
// right. `span` is the top of the scale, or 0 to scale against the window's own
// maximum. The bottom row draws `_` where a column is empty, so the baseline is
// visible and an all-zero window is a picture rather than a blank.
inline std::vector<std::string> column_bars(const std::vector<std::uint64_t>& values,
                                            std::uint64_t span, std::size_t height,
                                            std::size_t width) {
    std::vector<std::string> rows;
    if (height == 0 || width == 0 || values.empty()) return rows;
    const std::size_t begin = values.size() > width ? values.size() - width : 0;
    std::uint64_t top = span;
    if (!top) for (std::size_t i = begin; i < values.size(); ++i) top = std::max(top, values[i]);

    std::vector<std::size_t> level;
    level.reserve(values.size() - begin);
    for (std::size_t i = begin; i < values.size(); ++i) {
        std::uint64_t v = values[i];
        if (top && v > top) v = top;
        std::size_t l = top ? static_cast<std::size_t>(
                                  (static_cast<unsigned __int128>(v) * height) / top)
                            : 0;
        if (l == 0 && values[i]) l = 1;
        if (l > height) l = height;
        level.push_back(l);
    }

    rows.resize(height);
    for (std::size_t r = 0; r < height; ++r) {
        const std::size_t at = height - r;              // the top row is the tallest
        std::string s;
        s.reserve(level.size());
        for (const std::size_t l : level) s.push_back(l >= at ? '#' : (at == 1 ? '_' : ' '));
        rows[r] = s;
    }
    return rows;
}

// A min..max normalised ramp. Used for the difficulty trend, where the
// interesting thing is the SHAPE and the absolute value is on the tip row. A
// flat series draws flat and mid-ramp rather than at either end, because a
// series pinned to the bottom of the scale reads as a collapse.
inline std::string trend_spark(const std::vector<std::uint64_t>& series, std::size_t width) {
    static const char kRamp[] = "_.-=+*#";
    const std::size_t levels = sizeof(kRamp) - 2;      // 6 -> indices 0..6
    std::string s;
    if (series.empty() || width == 0) return s;
    const std::size_t begin = series.size() > width ? series.size() - width : 0;
    std::uint64_t lo = series[begin], hi = series[begin];
    for (std::size_t i = begin; i < series.size(); ++i) {
        lo = std::min(lo, series[i]);
        hi = std::max(hi, series[i]);
    }
    for (std::size_t i = begin; i < series.size(); ++i) {
        std::size_t l = levels / 2;
        if (hi > lo)
            l = static_cast<std::size_t>(
                (static_cast<unsigned __int128>(series[i] - lo) * levels) / (hi - lo));
        if (l > levels) l = levels;
        s.push_back(kRamp[l]);
    }
    return s;
}

// One height, as the timeline draws it.
struct HeightMark {
    std::uint64_t height    = 0;
    bool          contested = false;
    bool          live      = false;   // strictly above the frontier
};

// The height timeline: oldest left, `.` a height we hold, `*` a contested one,
// and a single `|` at the frontier -- everything left of it may have been
// backfilled by our own parent walk, everything right of it arrived while we
// were watching. Drawing those two as the same character is what makes a
// fetch rate look like a block rate, which is the mistake this whole component
// is written around.
inline std::string height_timeline(const std::vector<HeightMark>& marks, std::size_t width) {
    std::string s;
    if (marks.empty() || width == 0) return s;
    const std::size_t begin = marks.size() > width ? marks.size() - width : 0;
    for (std::size_t i = begin; i < marks.size(); ++i) {
        // The bar is drawn at the TRANSITION and nowhere else. A window that
        // starts inside the live region gets no bar at all, because the
        // frontier is then off the left edge and a bar at the first column
        // would claim it is right there.
        if (i > begin && marks[i].live && !marks[i - 1].live) s.push_back('|');
        s.push_back(marks[i].contested ? '*' : '.');
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
    FreshnessView fresh;                  // the absolute WALL instants, for the file
    std::uint64_t status_age_ms  = 0;     // how long the status word has held
    bool          status_age_known = false;
    std::uint64_t tip_age_ms     = 0;     // since the tip HEIGHT last increased
    std::uint64_t rx_age_ms      = 0;     // since a new distinct block arrived
    std::uint64_t data_age_ms    = 0;     // Restored only: age of the file read
    // One or more of this chain's recorded instants is in the FUTURE of the
    // clock the ages above were computed against, so every one of them was
    // clamped and none is a measurement. Marks the ages rather than hiding
    // them: see fmt_age(ms, clock_ahead).
    bool          clock_ahead    = false;

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

    // ---- the series the graphics are drawn from --------------------------
    // All bounded, all oldest-first, all copied straight out of the read
    // model's history ring at view_of() time. They are EMPTY on a frame
    // reconstructed from the state file, because p2pmon-state/1 carries what
    // the monitor knew and not a plot buffer; the widgets say so in words
    // rather than drawing a blank strip that reads as a flat chain.
    std::vector<std::uint64_t> diff_series;      // difficulty per advanced height
    bool                       diff_clamped = false;   // a 128-bit difficulty was clamped
    std::vector<std::uint64_t> share_series;     // PPLNS payout lines per block
    std::vector<std::uint64_t> monero_series;    // Monero template height per block
    std::vector<HeightMark>    marks;            // one per height held, oldest first
    std::uint64_t pplns_window = 0;              // the chain parameter, for the gauge
    std::size_t   heights_held = 0;              // distinct heights in the model
    std::size_t   tip_shares   = 0;              // payout lines in the tip coinbase
};

// ---------------------------------------------------------------------------
// THE LAYOUT -- which panels are open, and which one has the keyboard.
//
// A RENDER PARAMETER, not a frame field: see the note at the top of this file
// for why that boundary is the one thing about this struct that matters.
//
// An empty or short `expanded` vector means EXPANDED. The defensive default is
// deliberate: a Layout that has never been touched renders exactly the frame
// this file rendered before layouts existed, so every existing call site --
// the persistence KAT, the restored-state reader, snapshot_text(f, cols) --
// keeps its meaning without being edited to opt in.
// ---------------------------------------------------------------------------
struct Layout {
    std::vector<bool> expanded;
    std::size_t       focus = 0;
    bool              show_hints = false;

    static Layout all(std::size_t n, bool exp) {
        Layout l;
        l.expanded.assign(n, exp);
        return l;
    }
    bool is_expanded(std::size_t i) const {
        return i >= expanded.size() || expanded[i];
    }
    void set(std::size_t i, bool exp) {
        if (i >= expanded.size()) expanded.resize(i + 1, true);
        expanded[i] = exp;
    }
    void toggle(std::size_t i) { set(i, !is_expanded(i)); }
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
    bool          clock_ahead = false;    // that state was written in our future
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
    // The file's own write instant is in the future of the reading clock. Same
    // rule as ChainView::clock_ahead, one level up.
    bool                   clock_ahead = false;
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
// BOTH CLOCKS ARE PASSED IN rather than read, which is the whole reason a
// golden frame is possible. Everything else is a straight read of the model.
//
// `now_steady_ms` times things that happened INSIDE THIS PROCESS and is
// comparable only with this process's other steady readings: the feed's "this
// block arrived 7s ago" is measured against ObservedBlock::first_seen_ms, which
// the observer stamps with p2p::steady_ms().
//
// `now_wall_ms` times things that are RECORDED AND OUTLIVE THE PROCESS: every
// instant in FreshnessView, and therefore the status word, the tip age and the
// rx age. Those are the numbers that get written to the state file and read
// back after a restart or a reboot, and a monotonic clock cannot carry them --
// see the two-clock note at the top of p2pool_observer.hpp.
//
// Neither has a default. A caller that has only one number to offer has not yet
// worked out which of the two it is holding, and that is precisely the mistake
// the split was introduced to make impossible to write. The offline KATs pass
// one synthetic instant twice, deliberately and visibly.
// ---------------------------------------------------------------------------
inline ChainView view_of(const ReadModel& m, const EmitCounts& out, std::size_t sockets,
                         std::size_t queued, std::uint64_t now_steady_ms,
                         std::uint64_t now_wall_ms,
                         const FreshnessView& fresh = FreshnessView{},
                         const FreshnessThresholds& th = FreshnessThresholds{},
                         std::size_t feed_rows = 8, std::size_t pulse_width = 24,
                         std::size_t graph_width = 96) {
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
                           v.target_s, now_wall_ms, th);
    v.tip_age_ms = fresh.tip_age_ms(now_wall_ms);
    v.rx_age_ms  = fresh.rx_age_ms(now_wall_ms);
    v.clock_ahead = fresh.clock_ahead(now_wall_ms);

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
        v.status_age_ms = fresh.down_ms(now_wall_ms);
    } else if (v.status == ChainStatus::Dark || v.status == ChainStatus::Dialling) {
        v.status_age_ms = FreshnessView::age(now_wall_ms, fresh.started_at_ms);
    } else {
        v.status_age_ms = v.tip_age_ms;
    }

    // ---- the plot series -------------------------------------------------
    // Copied, bounded, and derived from nothing: `live` is decided HERE against
    // the frontier as it stands now, never stamped into the ring at insert
    // time, because the frontier is allowed to rise during the settle window.
    v.pplns_window = m.params().pplns_window;
    v.heights_held = m.heights_held();
    {
        const std::vector<TipSample>& hist = m.tip_history();
        const std::size_t begin = hist.size() > graph_width ? hist.size() - graph_width : 0;
        for (std::size_t i = begin; i < hist.size(); ++i) {
            v.diff_series.push_back(hist[i].difficulty);
            v.share_series.push_back(static_cast<std::uint64_t>(hist[i].shares));
            v.monero_series.push_back(hist[i].monero_height);
            if (hist[i].difficulty_clamped) v.diff_clamped = true;
        }
        const std::map<std::uint64_t, HeightContest>& hs = m.heights();
        std::size_t skip = hs.size() > graph_width ? hs.size() - graph_width : 0;
        for (const auto& kv : hs) {
            if (skip) { --skip; continue; }
            HeightMark mk;
            mk.height    = kv.first;
            mk.contested = kv.second.ids.size() > 1;
            mk.live      = kv.first > m.frontier_height();
            v.marks.push_back(mk);
        }
        if (const ObservedBlock* tip = m.tip_height() ? m.find(m.tip_id()) : nullptr)
            v.tip_shares = tip->share_outputs;
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
        // STEADY, not wall: first_seen_ms was stamped by this process from
        // p2p::steady_ms() and the feed is a this-session-only row.
        r.age_ms   = now_steady_ms >= b->first_seen_ms ? now_steady_ms - b->first_seen_ms : 0;
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
// kGraph and kGraphWide sit ABOVE the feed on purpose. The order a short
// window sheds in is therefore: multi-row bar blocks, then one-row graphs,
// then the feed, then the network rows, then the detail rows -- and a chain is
// never lost, because a collapsed summary and every expanded panel's first
// rows are kAlways.
enum Level : int {
    kAlways = 0, kDetail = 2, kNetwork = 3, kFeed = 4, kGraph = 5, kGraphWide = 6
};

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
        s += " " + fmt_age(v.status_age_ms, v.clock_ahead);
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

// A widget's second-level label, indented under its topic row.
inline void sublabel(Line& l, const char* text) {
    l.put("     ").sgr(kDim).put(text).sgr(kReset).pad_to(12);
}

// How wide a strip may be at this terminal width. Derived from `cols` inside
// the panel, so a narrower window SHORTENS a strip instead of having Line cut
// it mid-picture; 24 keeps a strip legible, 96 stops a very wide terminal from
// turning a pulse into wallpaper.
inline std::size_t strip_width(std::size_t cols) {
    std::size_t w = cols > 16 ? cols - 16 : 0;
    if (w < 24) w = 24;
    if (w > 96) w = 96;
    return w;
}

// The "this chain has nothing to plot" row, in the one shape every widget uses
// for it: the no-data marker and a sentence, and NOT ONE DIGIT -- a digit on a
// dead panel is the whole failure this component is written against, and the
// KAT walks these rows looking for one.
inline void no_plot(Line& l, const char* why) {
    l.sgr(kDim).put(kNoData).put("  ").put(why).sgr(kReset);
}

// ---------------------------------------------------------------------------
// THE COLLAPSED PANEL: one row that replaces all of it.
//
// The summary keeps the full status phrase, dashes every chain figure it
// cannot support, and keeps the restored marker -- so collapsing a panel can
// hide DETAIL and can never hide a PROBLEM. That is the entire design rule
// here, and the KAT asserts it against the dead-chain fixture.
// ---------------------------------------------------------------------------
inline void collapsed_row(const ChainView& v, std::size_t cols, bool color, bool interactive,
                          bool focused, std::vector<Row>& rows) {
    const bool have = v.have_data;
    Line l(cols, color);
    l.put(interactive && focused ? '>' : ' ');
    l.sgr(kBold).sgr(chain_color(v.chain)).put(upper(to_string(v.chain))).sgr(kReset);
    l.put("  port ").put(std::to_string(v.port));
    l.put("  ").sgr(status_color(v.status)).put(status_phrase(v)).sgr(kReset);
    // THE RESTORED MARKER COMES BEFORE THE FIGURES IT QUALIFIES, not after
    // them. One row has to hold everything a panel held, so it is the row most
    // likely to be truncated by a narrow terminal -- and the field that must
    // never be the one cut away is the one saying these numbers were read from
    // a file rather than measured. Its clamped-age marker travels with it,
    // exactly as on the title row.
    if (v.source == ChainSource::Restored) {
        l.put("  ").sgr(kYellow).put("[FROM FILE ").put(fmt_age(v.data_age_ms, v.clock_ahead))
         .put(" OLD]").sgr(kReset);
    }
    l.put("  ").sgr(kDim).put("tip ").sgr(kReset)
     .put(or_dash(have, std::to_string(v.tip_height)));
    l.put("  ");
    if (!have) {
        l.sgr(kDim).put("cadence ").sgr(kReset).put(kNoData);
    } else if (v.cadence_ok) {
        const std::uint64_t obs_ms = static_cast<std::uint64_t>(v.cadence_s * 1000.0 + 0.5);
        l.sgr(cadence_color(v.cadence_s, v.target_s));
        l.put(fmt_fixed(static_cast<long double>(v.cadence_s), 2)).put("s ");
        l.put(cadence_bar(obs_ms, v.target_s * 1000ull, 16)).sgr(kReset);
    } else {
        l.sgr(kDim).put("warming").sgr(kReset);
    }
    l.put("  ").sgr(v.peers_up ? kGreen : kRed).put(std::to_string(v.peers_up)).sgr(kReset)
     .sgr(kDim).put(" up").sgr(kReset);
    l.put("  ").sgr(kDim).put("blocks ").sgr(kReset).put(or_dash(have, std::to_string(v.distinct)));
    l.put("  ").sgr(kDim).put("races ").sgr(kReset).put(or_dash(have, std::to_string(v.contested)));
    if (interactive) l.put("  ").sgr(kDim).put("[+]").sgr(kReset);
    rows.emplace_back(kAlways, l.take());
}

inline void panel(const ChainView& v, std::size_t cols, bool color, bool interactive,
                  bool focused, std::vector<Row>& rows) {
    const bool have = v.have_data;
    const std::size_t sw = strip_width(cols);
    {   // title
        Line l(cols, color);
        l.put(interactive && focused ? '>' : ' ');
        l.sgr(kBold).sgr(chain_color(v.chain)).put(upper(to_string(v.chain)));
        l.sgr(kReset).put("  port ").put(std::to_string(v.port));
        l.put("  ").sgr(status_color(v.status)).put(status_phrase(v)).sgr(kReset);
        l.put("  ").sgr(kDim).put("target ").sgr(kReset).put(std::to_string(v.target_s)).put("s");
        if (v.source == ChainSource::Restored) {
            l.put("  ").sgr(kYellow).put("[FROM FILE ").put(fmt_age(v.data_age_ms, v.clock_ahead))
             .put(" OLD]").sgr(kReset);
        }
        if (interactive) l.put("  ").sgr(kDim).put("[-]").sgr(kReset);
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
        const std::string age = v.status_age_known ? fmt_age(v.status_age_ms, v.clock_ahead)
                                                  : std::string("?");
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
                l.sgr(kDim).put(", last rx ").sgr(kReset).put(fmt_age(v.rx_age_ms, v.clock_ahead));
                l.sgr(kDim).put(" -- the figures below are that old");
                break;
            case ChainStatus::Quiet:
                l.sgr(kDim).put("no new height for ").sgr(kReset).put(age);
                l.sgr(kDim).put(", last rx ").sgr(kReset).put(fmt_age(v.rx_age_ms, v.clock_ahead));
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
             .put(fmt_age(v.tip_age_ms, v.clock_ahead)).sgr(kReset);
        }
        rows.emplace_back(kAlways, l.take());
    }
    {   // trend -- the difficulty series, as a shape, with the scale it used
        Line l(cols, color);
        label(l, "trend");
        if (!have) {
            no_plot(l, "no block held for this chain: nothing to plot");
        } else if (v.diff_series.empty()) {
            l.sgr(kDim).put("(the state file carries the tip, not the difficulty series)");
        } else if (v.diff_clamped) {
            // A difficulty past 2^64 was clamped into the ring; the shape would
            // be a lie about a number we deliberately did not keep exactly.
            l.sgr(kDim).put("(a difficulty wider than 64 bits was clamped: trend not drawn)");
        } else {
            std::uint64_t lo = v.diff_series[0], hi = v.diff_series[0];
            for (const std::uint64_t d : v.diff_series) {
                lo = std::min(lo, d);
                hi = std::max(hi, d);
            }
            l.sgr(chain_color(v.chain)).put(trend_spark(v.diff_series, sw > 40 ? 40 : sw))
             .sgr(kReset);
            l.put("  ").sgr(kDim).put("diff ").sgr(kReset)
             .put(fmt_si(static_cast<long double>(lo)));
            l.sgr(kDim).put("..").sgr(kReset).put(fmt_si(static_cast<long double>(hi)));
            l.sgr(kDim).put(" over ").sgr(kReset).put(std::to_string(v.diff_series.size()));
            l.sgr(kDim).put(" heights");
        }
        rows.emplace_back(kGraph, l.take());
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
    {   // histogram -- the gaps bucketed against the target
        if (!have || v.gaps_ms.empty()) {
            Line l(cols, color);
            label(l, "buckets");
            if (!have) no_plot(l, "no block held for this chain: nothing to bucket");
            else       l.sgr(kDim).put("(no live gaps yet)");
            rows.emplace_back(kGraphWide, l.take());
        } else {
            const std::vector<std::size_t> h = cadence_histogram(v.gaps_ms,
                                                                 v.target_s * 1000ull);
            std::size_t top = 1;
            for (const std::size_t n : h) top = std::max(top, n);
            const std::size_t bw = sw > 32 ? 32 : sw;
            for (std::size_t i = 0; i < kCadenceBuckets; ++i) {
                Line l(cols, color);
                if (i == 0) label(l, "buckets");
                else        sublabel(l, "");
                l.sgr(kDim).put(cadence_bucket_label(i)).sgr(kReset).put(" ");
                // The overflow bucket is the one a stall lands in, so it is the
                // one that is coloured.
                l.sgr(i + 1 == kCadenceBuckets && h[i] ? kRed : chain_color(v.chain));
                l.put("[").put(bar_cells(static_cast<std::uint64_t>(h[i]),
                                         static_cast<std::uint64_t>(top), bw)).put("]");
                l.sgr(kReset).put(" ").put(std::to_string(h[i]));
                if (i + 1 == kCadenceBuckets)
                    l.put("  ").sgr(kDim).put("live gaps, bucketed against the target");
                rows.emplace_back(kGraphWide, l.take());
            }
        }
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
    {   // heatmap -- the same gaps, four rows tall: the wide pulse
        const std::vector<std::string> block =
            have ? column_bars(v.gaps_ms, v.target_s * 2000ull, 4, sw) : std::vector<std::string>();
        if (block.empty()) {
            Line l(cols, color);
            label(l, "heatmap");
            if (!have) no_plot(l, "no block held for this chain: nothing to plot");
            else       l.sgr(kDim).put("(no live gaps yet)");
            rows.emplace_back(kGraphWide, l.take());
        } else {
            static const char* const kScale[4] = {"2.0x", "1.5x", "1.0x", "0.5x"};
            for (std::size_t r = 0; r < block.size(); ++r) {
                Line l(cols, color);
                if (r == 0) label(l, "heatmap");
                else        sublabel(l, "");
                l.sgr(kDim).put(kScale[r]).sgr(kReset).put(" ");
                l.sgr(cadence_color(v.cadence_ok ? v.cadence_s
                                                 : static_cast<double>(v.target_s), v.target_s));
                l.put(block[r]).sgr(kReset);
                if (r + 1 == block.size())
                    l.put("  ").sgr(kDim).put("one column per live gap, newest right");
                rows.emplace_back(kGraphWide, l.take());
            }
        }
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
    {   // timeline -- one character per height, with the frontier marked
        Line l(cols, color);
        label(l, "timeline");
        if (!have) {
            no_plot(l, "no height held for this chain: nothing to lay out");
        } else if (v.marks.empty()) {
            l.sgr(kDim).put("(the state file carries totals, not the height timeline)");
        } else {
            std::size_t contested = 0;
            for (const HeightMark& mk : v.marks) if (mk.contested) ++contested;
            l.sgr(contested ? kYellow : chain_color(v.chain))
             .put(height_timeline(v.marks, sw > 48 ? 48 : sw)).sgr(kReset);
            l.put("  ").sgr(kDim).put("oldest left, ").sgr(kReset).put("|")
             .sgr(kDim).put(" frontier, ").sgr(kReset).put("*")
             .sgr(kDim).put(" contested");
        }
        rows.emplace_back(kGraph, l.take());
    }
    {   // monero -- the template height per recent block. Still not a claim
        // that a Monero block was found: that needs a PoW target we do not
        // hold, and no widget here is allowed to imply one.
        Line l(cols, color);
        label(l, "monero");
        if (!have) {
            no_plot(l, "no block held for this chain: no template to track");
        } else if (v.monero_series.empty()) {
            l.sgr(kDim).put("(the state file carries the highest template, not the series)");
        } else {
            const std::uint64_t base = v.monero_series.front();
            std::vector<std::uint64_t> rel;
            rel.reserve(v.monero_series.size());
            // Plotted as an OFFSET from the oldest template in the window: the
            // absolute heights differ by a few units over millions, and a bar
            // scaled against the absolute value would draw every chain flat.
            for (const std::uint64_t h : v.monero_series)
                rel.push_back(h >= base ? h - base : 0);
            l.sgr(chain_color(v.chain)).put(trend_spark(rel, sw > 40 ? 40 : sw)).sgr(kReset);
            l.put("  ").sgr(kDim).put("tpl ").sgr(kReset).put(std::to_string(v.monero_high));
            l.sgr(kDim).put(" spans ").sgr(kReset)
             .put(std::to_string(v.monero_series.back() >= base
                                 ? v.monero_series.back() - base + 1 : 1));
            l.sgr(kDim).put(" heights over ").sgr(kReset)
             .put(std::to_string(v.monero_series.size()));
            l.sgr(kDim).put(" blocks");
        }
        rows.emplace_back(kGraph, l.take());
    }
    {   // pplns -- OUR COVERAGE of the window, never a payout claim
        Line l(cols, color);
        label(l, "pplns");
        if (!have) {
            no_plot(l, "no height held for this chain: nothing to cover");
        } else if (!v.heights_held || !v.pplns_window) {
            // A RESTORED FRAME HAS NO HEIGHT SET. p2pmon-state/1 carries the
            // totals, not the model, so heights_held is zero here for the same
            // reason the series are empty -- and a gauge drawn anyway reads
            // "0/0 window held, tip pays 0 lines", which is three fabricated
            // zeros in the one row whose whole subject is coverage.
            l.sgr(kDim).put("(the state file carries totals, not the window coverage)");
        } else {
            l.sgr(chain_color(v.chain))
             .put(gauge(static_cast<std::uint64_t>(v.heights_held), v.pplns_window,
                        sw > 16 ? 16 : sw)).sgr(kReset);
            l.put(" ").put(std::to_string(v.heights_held)).sgr(kDim).put("/").sgr(kReset)
             .put(std::to_string(v.pplns_window));
            l.sgr(kDim).put(" window held").sgr(kReset);
            l.put("  ").sgr(kDim).put("tip pays ").sgr(kReset).put(std::to_string(v.tip_shares));
            l.sgr(kDim).put(" lines  (coverage, not a ledger)");
        }
        rows.emplace_back(kGraph, l.take());
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
        l.sgr(kDim).put("  saved ").sgr(kReset).put(fmt_age(v.carry_age_ms, v.clock_ahead))
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
    {   // peers -- four bars against the largest of them.
        //
        // NEVER DASHED, on the same rule as the net row: these are readings of
        // our own socket table, so zero is a measurement and draws as an empty
        // bar rather than as an absence.
        const std::uint64_t counts[4] = {
            static_cast<std::uint64_t>(v.peers_up), static_cast<std::uint64_t>(v.sockets),
            static_cast<std::uint64_t>(v.peers_known), static_cast<std::uint64_t>(v.gossiped)};
        static const char* const kName[4] = {"up    ", "sock  ", "known ", "gossip"};
        std::uint64_t top = 1;
        for (const std::uint64_t c : counts) top = std::max(top, c);
        const std::size_t bw = sw > 32 ? 32 : sw;
        for (std::size_t i = 0; i < 4; ++i) {
            Line l(cols, color);
            if (i == 0) label(l, "peers");
            else        sublabel(l, "");
            l.sgr(kDim).put(kName[i]).sgr(kReset).put(" ");
            l.sgr(i == 0 ? (v.peers_up ? kGreen : kRed) : chain_color(v.chain));
            l.put("[").put(bar_cells(counts[i], top, bw)).put("]").sgr(kReset);
            l.put(" ").put(std::to_string(counts[i]));
            rows.emplace_back(kGraphWide, l.take());
        }
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
    {   // recent -- the PPLNS payout-line count of each recent block, as columns
        const std::vector<std::string> block =
            have ? column_bars(v.share_series, 0, 3, sw) : std::vector<std::string>();
        if (block.empty()) {
            Line l(cols, color);
            label(l, "recent");
            if (!have) no_plot(l, "no block held for this chain: nothing to bar");
            else       l.sgr(kDim).put("(the state file carries totals, not the per-block series)");
            rows.emplace_back(kGraphWide, l.take());
        } else {
            std::uint64_t top = 0;
            for (const std::uint64_t s : v.share_series) top = std::max(top, s);
            for (std::size_t r = 0; r < block.size(); ++r) {
                Line l(cols, color);
                if (r == 0) label(l, "recent");
                else        sublabel(l, "");
                // The scale is stated on the top row, because a column chart
                // normalised to its own maximum says nothing on its own.
                if (r == 0) l.sgr(kDim).put("max ").sgr(kReset).put(std::to_string(top));
                l.sgr(kReset).pad_to(22);
                l.sgr(chain_color(v.chain)).put(block[r]).sgr(kReset);
                if (r + 1 == block.size())
                    l.put("  ").sgr(kDim).put("payout lines per block, newest right");
                rows.emplace_back(kGraphWide, l.take());
            }
        }
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
                l.sgr(kDim).put(" from ").sgr(kReset).put(fmt_age(p.restored_age_ms, p.clock_ahead))
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
         .put(fmt_age(f.file_age_ms, f.clock_ahead)).sgr(kDim)
         .put(" ago -- no network was dialled and no number below is current");
        rows.emplace_back(kAlways, l.take());
    }
    {
        // THE CLOCK-SKEW ROW. Drawn only when something recorded is dated in
        // this host's future, which happens for two ordinary reasons: the wall
        // clock stepped backwards (an NTP correction), or the file came from a
        // machine whose clock is ahead of this one. Every age computed from such
        // an instant has been clamped to zero and marked `+`, and a lone `+` in
        // the middle of a panel is not self-explanatory, so the frame says once,
        // in words, what the marker means. At kAlways priority: an unexplained
        // "0s" IS the failure this component exists to prevent.
        bool skew = f.clock_ahead || f.persist.clock_ahead;
        for (const ChainView& c : f.chains) skew = skew || c.clock_ahead;
        if (skew) {
            Line l(cols, color);
            l.put(" ").sgr(kBold).sgr(kYellow).put("CLOCK SKEW").sgr(kReset);
            l.sgr(kDim).put("  a recorded instant is AHEAD of this host's clock -- ages "
                            "marked ").sgr(kReset).put("+").sgr(kDim)
             .put(" are clamped to zero and are a lower bound, not a measurement");
            rows.emplace_back(kAlways, l.take());
        }
    }
    {
        Line l(cols, color);
        l.sgr(kDim).repeat('-', cols).sgr(kReset);
        rows.emplace_back(kAlways, l.take());
    }
}

inline void footer(const MonitorFrame& f, std::size_t cols, bool color, const Layout& lay,
                   std::vector<Row>& rows) {
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
        // THE KEY ROW NAMES THE CHAINS IT IS TALKING ABOUT. The digit keys
        // address the CONFIGURED order, so with `--chains nano,mini` the key 1
        // is NANO -- and an operator who has to work that out from a manual at
        // 4am will not, so the mapping is printed from the frame itself.
        Line l(cols, color);
        l.put(" ").sgr(kBold).put("q").sgr(kReset).sgr(kDim).put(" quit  ").sgr(kReset);
        l.sgr(kBold).put("r").sgr(kReset).sgr(kDim).put(" redraw  ").sgr(kReset);
        l.sgr(kBold).put("Tab").sgr(kReset).sgr(kDim).put(" focus  ").sgr(kReset);
        l.sgr(kBold).put("Space").sgr(kReset).sgr(kDim).put(" toggle  ").sgr(kReset);
        l.sgr(kBold).put("a").sgr(kReset).sgr(kDim).put("/").sgr(kReset)
         .sgr(kBold).put("c").sgr(kReset).sgr(kDim).put(" all/none").sgr(kReset);
        for (std::size_t i = 0; i < f.chains.size() && i < 9; ++i) {
            if (l.room() < 10) break;
            l.put("  ").sgr(kBold).put(std::to_string(i + 1)).sgr(kReset).put(" ")
             .sgr(chain_color(f.chains[i].chain)).put(upper(to_string(f.chains[i].chain)))
             .sgr(kReset);
        }
        l.put("  ").sgr(kBold).put("?").sgr(kReset).sgr(kDim).put(" keys");
        rows.emplace_back(kAlways, l.take());
    }
    if (f.interactive && lay.show_hints) {
        Line l(cols, color);
        l.put(" ").sgr(kDim).put("glyphs  ").sgr(kReset)
         .put("#").sgr(kDim).put(" bar   ").sgr(kReset)
         .put("_.-=+*#").sgr(kDim).put(" ramp, low to high   ").sgr(kReset)
         .put("*").sgr(kDim).put(" contested height   ").sgr(kReset)
         .put("|").sgr(kDim).put(" frontier   ").sgr(kReset)
         .put(kNoData).sgr(kDim).put(" no measurement");
        rows.emplace_back(kAlways, l.take());
        Line m(cols, color);
        m.put(" ").sgr(kDim).put("keys    ").sgr(kReset)
         .put("1..9").sgr(kDim).put(" toggle that chain   ").sgr(kReset)
         .put("Tab").sgr(kDim).put("/").sgr(kReset).put("j").sgr(kDim).put(" next   ").sgr(kReset)
         .put("k").sgr(kDim).put(" previous   ").sgr(kReset)
         .put("Enter").sgr(kDim).put(" toggle the focused chain   ").sgr(kReset)
         .put("?").sgr(kDim).put(" close this");
        rows.emplace_back(kAlways, m.take());
    }
}

inline std::vector<Row> build(const MonitorFrame& f, std::size_t cols, bool color,
                              const Layout& lay) {
    std::vector<Row> rows;
    const MonitorTotals t = totals_of(f.chains);
    header(f, t, cols, color, rows);
    for (std::size_t i = 0; i < f.chains.size(); ++i) {
        const bool focused = (i == lay.focus);
        if (lay.is_expanded(i)) panel(f.chains[i], cols, color, f.interactive, focused, rows);
        else collapsed_row(f.chains[i], cols, color, f.interactive, focused, rows);
    }
    footer(f, cols, color, lay, rows);
    return rows;
}

} // namespace detail

// Every line the frame wants, at this width and in this layout.
inline std::size_t natural_rows(const MonitorFrame& f, std::size_t cols = 100,
                                const Layout& lay = Layout{}) {
    return detail::build(f, cols, false, lay).size();
}

// EXACTLY `rows` lines, each EXACTLY `cols` visible columns. Detail is shed
// from the bottom of the priority list when the window is short; a window
// shorter than the always-lines is truncated, never wrapped.
inline std::vector<std::string> render(const MonitorFrame& f, std::size_t cols, std::size_t rows,
                                       bool color, const Layout& lay = Layout{}) {
    if (cols < 40) cols = 40;
    std::vector<detail::Row> all = detail::build(f, cols, color, lay);

    int cut = 7;                       // nothing shed
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
inline std::string snapshot_text(const MonitorFrame& f, std::size_t cols = 100,
                                 const Layout& lay = Layout{}) {
    const std::vector<std::string> lines = render(f, cols, natural_rows(f, cols, lay), false, lay);
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
