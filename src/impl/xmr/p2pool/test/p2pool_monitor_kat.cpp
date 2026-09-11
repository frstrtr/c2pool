// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/test/p2pool_monitor_kat.cpp
//
// THE MONITOR KAT. Offline, deterministic, no socket, no terminal.
//
// A dashboard is the easiest place in a codebase to hide a wrong number,
// because the only thing that would catch it is somebody looking at it. So this
// KAT pins the WHOLE FRAME: three read models are filled with fixed synthetic
// observations at fixed millisecond timestamps, rendered at a fixed width with
// a fixed `now`, and the resulting plain text is compared line by line against
// a golden embedded below. Any change to a label, a column, a unit or a
// rounding rule is a diff a reviewer must look at on purpose.
//
// Four things are checked, in the order they matter:
//
//   1. THE EMIT SET IS STILL {0, 1, 3, 6}. Re-asserted here, independently of
//      the parser KAT, because this component adds a second binary that dials
//      three networks at once and the read-only claim has to hold for it too.
//      The check is over the encoder itself (encode every ControlMessage, read
//      the id byte back), so a fifth encoder fails it rather than escaping it.
//   2. THE FRAME IS DETERMINISTIC and matches the golden byte for byte; colour
//      is additive only, so strip_ansi(coloured) == plain, line by line.
//   3. THE THREE-CHAIN AGGREGATION IS RIGHT: the header totals are the sums of
//      the panels, computed from the ChainViews rather than from the renderer.
//   4. THE HONESTY RULES SURVIVE THE DISPLAY: a model holding only backfilled
//      heights renders "warming", never a cadence figure -- the display must
//      not launder the artefact the read model refuses to report.
//
// Run with `--emit-golden` to print the frame the fixture produces; that is how
// the golden below was generated, and how it is regenerated on purpose.
//
// Offline, STL only: it includes no socket header, exactly like the parser KAT.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_read_model.hpp"
#include "impl/xmr/p2pool/p2pool_tui.hpp"
#include "impl/xmr/p2pool/p2pool_wire.hpp"

namespace p2p = c2pool::xmr::p2pool;
namespace tui = c2pool::xmr::p2pool::tui;

namespace {

int g_checks = 0;
int g_fail   = 0;

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { std::printf("FAIL: %s\n", what); ++g_fail; }
}

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* what) {
    ++g_checks;
    if (!(got == static_cast<A>(want))) {
        std::printf("FAIL: %s\n", what);
        ++g_fail;
    }
}

void check_str(const std::string& got, const std::string& want, const char* what) {
    ++g_checks;
    if (got != want) {
        std::printf("FAIL: %s\n  got  |%s|\n  want |%s|\n", what, got.c_str(), want.c_str());
        ++g_fail;
    }
}

// ---------------------------------------------------------------------------
// THE FIXTURE
//
// Three read models filled by hand. Every timestamp is explicit, so the frame
// is a pure function of the numbers below and of the `now` passed to view_of().
// The shape of each chain is chosen to exercise a different branch:
//
//   main  a live chain past the frontier, with a contested height whose loser
//         is carried as an uncle by the next block
//   mini  a live chain with a slow gap, to move the cadence bar off centre
//   nano  a chain that has handshaken and received its first blocks but has not
//         yet seen two live heights -- the "warming" branch, and the one that
//         must NOT print a cadence number
// ---------------------------------------------------------------------------

p2p::Hash mk_hash(std::uint8_t tag, std::uint8_t n) {
    p2p::Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<std::uint8_t>((tag * 61u + n * 17u + i * 7u) & 0xFFu);
    return h;
}

p2p::ObservedBlock mk_block(std::uint8_t tag, std::uint8_t n, std::uint64_t height,
                            std::uint64_t seen_ms, std::uint64_t diff_lo,
                            std::uint64_t monero_height, std::size_t shares) {
    p2p::ObservedBlock b;
    b.sidechain_id          = mk_hash(tag, n);
    b.sidechain_height      = height;
    b.difficulty.lo         = diff_lo;
    b.cumulative_difficulty.lo = diff_lo * 1000ull;
    b.parent                = mk_hash(tag, static_cast<std::uint8_t>(n - 1));
    b.monero_height         = monero_height;
    b.monero_timestamp      = 1757600000ull;
    b.share_outputs         = shares;
    b.total_reward          = 600000000000ull;
    b.tx_count              = 12;
    b.shape                 = p2p::BlobShape::Full;
    b.id_verified           = true;
    b.first_seen_ms         = seen_ms;
    b.from_peer             = "203.0.113.7:37889";
    return b;
}

// main: frontier 15200100, then four live heights, one of them contested.
p2p::ReadModel build_main() {
    p2p::ReadModel m(p2p::Sidechain::Main);
    const std::uint64_t d = 4360000000ull;

    m.observe(mk_block(1, 10, 15200100, 1000000, d, 3512000, 118));   // the frontier
    m.observe(mk_block(1,  9, 15200099, 1000100, d, 3512000, 117));   // backfilled parent
    m.observe(mk_block(1,  8, 15200098, 1000200, d, 3511999, 119));   // backfilled parent

    m.observe(mk_block(1, 11, 15200101, 1010000, d, 3512001, 120));
    m.observe(mk_block(1, 12, 15200102, 1019500, d, 3512001, 121));
    m.observe(mk_block(1, 13, 15200103, 1029000, d, 3512002, 121));
    m.observe(mk_block(1, 99, 15200103, 1029400, d, 3512002, 120));   // the race

    p2p::ObservedBlock win = mk_block(1, 14, 15200104, 1038000, d, 3512003, 122);
    win.uncles.push_back(mk_hash(1, 99));                             // loser carried
    m.observe(win);

    for (int i = 0; i < 4; ++i) m.note_connected("198.51.100." + std::to_string(i) + ":37889");
    for (int i = 0; i < 57; ++i) m.note_peer("198.51.100." + std::to_string(i) + ":37889");
    m.note_peer_gossip(48);
    m.note_broadcast_seen();
    return m;
}

// mini: live, with one long gap so the bar and the pulse are not flat.
p2p::ReadModel build_mini() {
    p2p::ReadModel m(p2p::Sidechain::Mini);
    const std::uint64_t d = 218000000ull;

    m.observe(mk_block(2, 10, 14757140, 1000000, d, 3512000, 44));    // frontier
    m.observe(mk_block(2,  9, 14757139, 1000300, d, 3512000, 43));    // backfilled

    m.observe(mk_block(2, 11, 14757141, 1006000, d, 3512001, 45));
    m.observe(mk_block(2, 12, 14757142, 1012500, d, 3512001, 45));
    m.observe(mk_block(2, 13, 14757143, 1031000, d, 3512002, 46));    // 18.5 s gap
    m.observe(mk_block(2, 14, 14757144, 1039500, d, 3512003, 46));

    for (int i = 0; i < 3; ++i) m.note_connected("198.51.100." + std::to_string(i) + ":37888");
    for (int i = 0; i < 31; ++i) m.note_peer("198.51.100." + std::to_string(i) + ":37888");
    m.note_peer_gossip(22);
    m.note_parse_failure();
    return m;
}

// nano: handshaken, one live height only -- the warming branch.
p2p::ReadModel build_nano() {
    p2p::ReadModel m(p2p::Sidechain::Nano);
    const std::uint64_t d = 9400000ull;

    m.observe(mk_block(3, 10, 2301884, 1005000, d, 3512001, 9));      // frontier
    m.observe(mk_block(3,  9, 2301883, 1005400, d, 3512000, 9));      // backfilled
    m.observe(mk_block(3, 11, 2301885, 1036000, d, 3512003, 10));     // one live height

    for (int i = 0; i < 2; ++i) m.note_connected("198.51.100." + std::to_string(i) + ":37890");
    for (int i = 0; i < 11; ++i) m.note_peer("198.51.100." + std::to_string(i) + ":37890");
    m.note_peer_gossip(6);
    return m;
}

tui::EmitCounts mk_emit(std::uint64_t chal, std::uint64_t sol, std::uint64_t breq,
                        std::uint64_t plreq) {
    tui::EmitCounts e;
    e.messages[0] = chal;  e.bytes[0] = chal  * 17;
    e.messages[1] = sol;   e.bytes[1] = sol   * 41;
    e.messages[2] = breq;  e.bytes[2] = breq  * 33;
    e.messages[3] = plreq; e.bytes[3] = plreq * 1;
    return e;
}

constexpr std::uint64_t kNow  = 1040000;   // the instant every view is taken at
constexpr std::size_t   kCols = 100;

tui::MonitorFrame build_frame() {
    static const p2p::ReadModel main_m = build_main();
    static const p2p::ReadModel mini_m = build_mini();
    static const p2p::ReadModel nano_m = build_nano();

    tui::MonitorFrame f;
    f.elapsed_ms  = 185000;      // 00:03:05
    f.interactive = false;
    f.chains.push_back(tui::view_of(main_m, mk_emit(6, 6, 141, 6), 4, 12, kNow));
    f.chains.push_back(tui::view_of(mini_m, mk_emit(5, 5, 118, 5), 3,  7, kNow));
    f.chains.push_back(tui::view_of(nano_m, mk_emit(3, 3,  64, 3), 2,  3, kNow));
    return f;
}

// ---------------------------------------------------------------------------
// THE GOLDEN FRAME. Regenerate with `xmr_p2pool_monitor_kat --emit-golden`.
// ---------------------------------------------------------------------------
const char* const kGolden[] = {
#include "p2pool_monitor_golden.inc"
};

// ---------------------------------------------------------------------------
// 1) The emit set, re-asserted for this binary.
// ---------------------------------------------------------------------------
void check_emit_set() {
    check_eq(p2p::kControlMessageCount, std::size_t(4), "exactly four control messages exist");

    const std::vector<int> ids = tui::emitted_id_set();
    check_eq(ids.size(), std::size_t(4), "four distinct outbound message ids");
    const int want[4] = {0, 1, 3, 6};
    for (std::size_t i = 0; i < ids.size() && i < 4; ++i)
        check_eq(ids[i], want[i], "outbound id set is exactly {0,1,3,6}");
    check_str(tui::emitted_id_set_string(), "{0,1,3,6}", "emit set prints as {0,1,3,6}");

    // Belt: the same statement made positionally over all twelve p2pool ids, so
    // a NEW encoder for LISTEN_PORT (2), BLOCK_RESPONSE (4), BLOCK_BROADCAST
    // (5), BLOCK_BROADCAST_COMPACT (8), BLOCK_NOTIFY (9), AUX_JOB_DONATION (10)
    // or MONERO_BLOCK_BROADCAST (11) fails here and not in review.
    bool emitted[12] = {false};
    p2p::ControlArgs a{};
    for (std::size_t i = 0; i < p2p::kControlMessageCount; ++i) {
        const std::vector<std::uint8_t> b = p2p::encode(static_cast<p2p::ControlMessage>(i), a);
        check(!b.empty(), "every control message encodes to bytes");
        if (!b.empty() && b[0] < 12) emitted[b[0]] = true;
        std::size_t framed = 0;
        check(p2p::frame_size(b.data(), b.size(), framed) == p2p::FrameStatus::Complete,
              "an encoded control message is a whole frame");
        check_eq(b.size(), framed, "encoded length is the wire length for its id");
    }
    const bool want_emitted[12] = {true, true, false, true, false, false,
                                   true, false, false, false, false, false};
    for (int i = 0; i < 12; ++i) {
        ++g_checks;
        if (emitted[i] != want_emitted[i]) {
            std::printf("FAIL: outbound id %d (%s) emitted=%d expected=%d\n", i,
                        p2p::to_string(static_cast<p2p::MessageId>(i)),
                        emitted[i] ? 1 : 0, want_emitted[i] ? 1 : 0);
            ++g_fail;
        }
    }

    // The monitor adds no encoder, so the lengths upstream reads are unchanged.
    check_eq(p2p::encode(p2p::ControlMessage::HandshakeChallenge, a).size(), std::size_t(17),
             "HANDSHAKE_CHALLENGE is 17 bytes");
    check_eq(p2p::encode(p2p::ControlMessage::HandshakeSolution, a).size(), std::size_t(41),
             "HANDSHAKE_SOLUTION is 41 bytes");
    check_eq(p2p::encode(p2p::ControlMessage::BlockRequest, a).size(), std::size_t(33),
             "BLOCK_REQUEST is 33 bytes");
    check_eq(p2p::encode(p2p::ControlMessage::PeerListRequest, a).size(), std::size_t(1),
             "PEER_LIST_REQUEST is 1 byte");

    // The footer states the set on screen; it must state THIS set.
    const std::string frame = tui::snapshot_text(build_frame(), kCols);
    check(frame.find("emitted ids {0,1,3,6}") != std::string::npos,
          "the frame footer prints the emitted id set");
    check(frame.find("LISTEN_PORT") != std::string::npos,
          "the frame footer names what is not emitted");
}

// ---------------------------------------------------------------------------
// 2) The frame: deterministic, golden-pinned, colour-additive.
// ---------------------------------------------------------------------------
void check_render() {
    const tui::MonitorFrame f = build_frame();

    const std::string a = tui::snapshot_text(f, kCols);
    const std::string b = tui::snapshot_text(build_frame(), kCols);
    check(a == b, "the same frame renders to the same bytes twice");

    // Against the golden, line by line so a failure names the line.
    std::vector<std::string> got;
    {
        std::string cur;
        for (const char c : a) {
            if (c == '\n') { got.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) got.push_back(cur);
    }
    const std::size_t want_n = sizeof(kGolden) / sizeof(kGolden[0]);
    check_eq(got.size(), want_n, "the frame has the golden number of lines");
    for (std::size_t i = 0; i < got.size() && i < want_n; ++i) {
        ++g_checks;
        if (got[i] != kGolden[i]) {
            std::printf("FAIL: frame line %zu\n  got  |%s|\n  want |%s|\n",
                        i, got[i].c_str(), kGolden[i]);
            ++g_fail;
        }
    }

    // Geometry: render() is total -- exactly `rows` lines of exactly `cols`
    // visible columns, at any size, padded so a repaint overwrites the last
    // frame rather than leaving its tail behind.
    for (std::size_t cols : {60u, 100u, 140u}) {
        for (std::size_t rows : {12u, 24u, 40u, 60u}) {
            const std::vector<std::string> plain = tui::render(f, cols, rows, false);
            check_eq(plain.size(), rows, "render returns exactly the rows asked for");
            bool width_ok = true;
            for (const std::string& l : plain) if (l.size() != cols) width_ok = false;
            check(width_ok, "every plain line is exactly cols wide");

            // Colour is additive and nothing else.
            const std::vector<std::string> col = tui::render(f, cols, rows, true);
            check_eq(col.size(), rows, "the coloured frame has the same row count");
            bool same = true;
            for (std::size_t i = 0; i < col.size(); ++i)
                if (tui::strip_ansi(col[i]) != plain[i]) same = false;
            check(same, "strip_ansi(coloured) == plain, line by line");
        }
    }

    // Shedding: a short window drops detail, never a chain.
    const std::vector<std::string> tight = tui::render(f, 100, 12, false);
    int titles = 0;
    for (const std::string& l : tight) {
        if (l.rfind(" MAIN ", 0) == 0 || l.rfind(" MINI ", 0) == 0 || l.rfind(" NANO ", 0) == 0)
            ++titles;
    }
    check_eq(titles, 3, "all three chains keep their panel in a 12-row window");

    // A narrow window truncates rather than wrapping and shearing the layout.
    const std::vector<std::string> narrow = tui::render(f, 60, 30, false);
    bool no_overflow = true;
    for (const std::string& l : narrow) if (l.size() != 60) no_overflow = false;
    check(no_overflow, "a 60-column window produces 60-column lines");
}

// ---------------------------------------------------------------------------
// 3) The three-chain aggregation.
// ---------------------------------------------------------------------------
void check_aggregation() {
    const tui::MonitorFrame f = build_frame();
    check_eq(f.chains.size(), std::size_t(3), "three chains in one frame");

    // Each panel is the chain it says it is: consensus port and target cadence
    // come from p2pool_consensus.hpp, not from the display.
    check_eq(f.chains[0].port, std::uint16_t(37889), "main panel is port 37889");
    check_eq(f.chains[1].port, std::uint16_t(37888), "mini panel is port 37888");
    check_eq(f.chains[2].port, std::uint16_t(37890), "nano panel is port 37890");
    check_eq(f.chains[0].target_s, std::uint64_t(10), "main targets 10 s");
    check_eq(f.chains[1].target_s, std::uint64_t(10), "mini targets 10 s");
    check_eq(f.chains[2].target_s, std::uint64_t(30), "nano targets 30 s");

    const tui::MonitorTotals t = tui::totals_of(f.chains);
    std::size_t peers_up = 0, known = 0, blocks = 0, contested = 0, bad = 0;
    std::uint64_t msgs = 0, bytes = 0;
    for (const tui::ChainView& c : f.chains) {
        peers_up  += c.peers_up;
        known     += c.peers_known;
        blocks    += c.distinct;
        contested += c.contested;
        bad       += c.parse_failures;
        msgs      += c.out.total_messages();
        bytes     += c.out.total_bytes();
    }
    check_eq(t.peers_up, peers_up, "header peers is the sum of the panels");
    check_eq(t.peers_known, known, "header known peers is the sum of the panels");
    check_eq(t.blocks, blocks, "header blocks is the sum of the panels");
    check_eq(t.contested, contested, "header races is the sum of the panels");
    check_eq(t.parse_failures, bad, "header parse failures is the sum of the panels");
    check_eq(t.messages_out, msgs, "header messages is the sum of the panels");
    check_eq(t.bytes_out, bytes, "header bytes is the sum of the panels");

    // The fixture's own arithmetic, so a silent change to it is visible.
    check_eq(peers_up, std::size_t(9), "fixture has 9 handshaken peers across three chains");
    check_eq(blocks, std::size_t(17), "fixture holds 17 distinct blocks across three chains");
    check_eq(t.chains_live, std::size_t(3), "all three fixture chains count as live-or-warming");
    check_eq(bytes, std::uint64_t(6 * 17 + 6 * 41 + 141 * 33 + 6
                                 + 5 * 17 + 5 * 41 + 118 * 33 + 5
                                 + 3 * 17 + 3 * 41 + 64 * 33 + 3),
             "header byte total is the three ledgers summed");

    // Chains are independent accumulators: mini's parse failure is mini's.
    check_eq(f.chains[0].parse_failures, std::size_t(0), "main saw no parse failure");
    check_eq(f.chains[1].parse_failures, std::size_t(1), "mini's parse failure stayed on mini");
    check_eq(f.chains[2].parse_failures, std::size_t(0), "nano saw no parse failure");
    check_eq(f.chains[0].contested, std::size_t(1), "main's contested height stayed on main");
    check_eq(f.chains[1].contested, std::size_t(0), "mini saw no contested height");
}

// ---------------------------------------------------------------------------
// 4) The honesty rules, checked through the display.
// ---------------------------------------------------------------------------
void check_honesty() {
    const tui::MonitorFrame f = build_frame();

    // main: cadence over the LIVE window only. Four live heights at
    // 1010.0, 1019.5, 1029.0, 1038.0 s -> 28.0 s / 3 = 9.33 s. The three
    // backfilled heights below the frontier (received 100 ms apart) are
    // excluded; including them would report about 5 s on a 10 s chain.
    check(f.chains[0].cadence_ok, "main reports a cadence");
    check_eq(f.chains[0].cadence_n, std::size_t(4), "main times four live heights");
    check_eq(f.chains[0].frontier, std::uint64_t(15200100), "main's frontier is the first tip seen");
    check_str(tui::fmt_fixed(static_cast<long double>(f.chains[0].cadence_s), 2), "9.33",
              "main's cadence is the live-window figure");
    check_eq(f.chains[0].distinct, std::size_t(8), "main holds eight distinct blocks");

    // nano: one live height. The model refuses to time it and so must the panel.
    check(!f.chains[2].cadence_ok, "nano refuses to report a cadence from one sample");
    check_eq(f.chains[2].status, tui::ChainStatus::Warming, "nano shows as warming");
    const std::string frame = tui::snapshot_text(f, kCols);
    const std::size_t nano_at = frame.find(" NANO ");
    check(nano_at != std::string::npos, "the nano panel is drawn");
    const std::size_t nano_end = frame.find(" MAIN ", nano_at) == std::string::npos
                               ? frame.size() : frame.find(" MAIN ", nano_at);
    const std::string nano_panel = frame.substr(nano_at, nano_end - nano_at);
    check(nano_panel.find("warming") != std::string::npos,
          "the nano panel says warming instead of printing a cadence");

    // A block whose height is contested is flagged in the feed, and the uncle
    // that carried the loser is counted as resolved.
    check_eq(f.chains[0].uncles_named, std::size_t(1), "main names one uncle");
    check_eq(f.chains[0].uncles_resolved, std::size_t(1), "main's uncle resolves to a block we hold");
    bool flagged = false;
    for (const tui::FeedRow& r : f.chains[0].feed)
        if (r.height == 15200103 && r.contested) flagged = true;
    check(flagged, "the contested height is flagged in the feed");

    // The Monero line is a template height, never a found-block claim.
    check_eq(f.chains[0].monero_high, std::uint64_t(3512003), "main's highest monero template");
    check(frame.find("monero tpl") != std::string::npos, "the monero template height is shown");
    check(frame.find("found") == std::string::npos,
          "the frame never claims a monero block was found");

    // An empty chain is DARK and says nothing it cannot support.
    p2p::ReadModel empty(p2p::Sidechain::Nano);
    const tui::ChainView dark = tui::view_of(empty, tui::EmitCounts{}, 0, 0, kNow);
    check_eq(dark.status, tui::ChainStatus::Dark, "a chain with nothing on it is dark");
    check_eq(dark.tip_id8, std::string("-"), "a dark chain shows no tip id");
    tui::MonitorFrame df;
    df.chains.push_back(dark);
    const std::string dark_frame = tui::snapshot_text(df, kCols);
    check(dark_frame.find("(nothing received yet)") != std::string::npos,
          "a dark chain says it has received nothing");
    check(dark_frame.find("(no live gaps yet)") != std::string::npos,
          "a dark chain draws no pulse it does not have");
}

// ---------------------------------------------------------------------------
// 5) The formatting primitives, pinned on their own so a golden diff is short.
// ---------------------------------------------------------------------------
void check_formatting() {
    check_str(tui::fmt_si(4360000000.0L), "4.36 G", "si: 4.36 G");
    check_str(tui::fmt_si(436000000.0L),  "436.00 M", "si: 436.00 M");
    check_str(tui::fmt_si(0.0L),          "0.00 ", "si: zero has no unit prefix");
    check_str(tui::fmt_bytes(0),          "0 B", "bytes: zero");
    check_str(tui::fmt_bytes(5222),       "5.1 KiB", "bytes: KiB");
    check_str(tui::fmt_hms(185000),       "00:03:05", "hms: 3m05s");
    check_str(tui::fmt_hms(3723000),      "01:02:03", "hms: 1h02m03s");
    check_str(tui::fmt_age(2000),         "2s", "age: seconds");
    check_str(tui::fmt_age(131000),       "2m11s", "age: minutes");
    check_str(tui::fmt_age(3900000),      "1h05m", "age: hours");

    // The bar's scale is 0..2x target, so on target is exactly half full and
    // stops at the `:` mark.
    check_str(tui::cadence_bar(10000, 10000, 16), "[########:-------]", "bar: on target");
    check_str(tui::cadence_bar(0, 10000, 16),     "[--------:-------]", "bar: no data");
    check_str(tui::cadence_bar(40000, 10000, 16), "[################]", "bar: clamped at 2x");
    check_str(tui::cadence_bar(5000, 10000, 16),  "[####----:-------]", "bar: twice as fast");

    // The pulse ramps over the same 0..2x scale; the newest gap is on the right.
    const std::vector<std::uint64_t> gaps = {0, 3400, 6700, 10000, 13400, 16700, 20000, 40000};
    check_str(tui::sparkline(gaps, 10000, 24), "_.-=+*##", "pulse: the full ramp");
    check_str(tui::sparkline(gaps, 10000, 3), "*##", "pulse: keeps the newest when it is narrow");
    check_str(tui::sparkline({}, 10000, 24), "", "pulse: empty when there is nothing live");

    // strip_ansi is the inverse of colouring, including adjacent escapes.
    check_str(tui::strip_ansi("\x1b[2mlabel\x1b[0m\x1b[1mvalue\x1b[0m"), "labelvalue",
              "strip_ansi removes every CSI sequence");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "--emit-golden") == 0) {
        // Prints the golden in the form p2pool_monitor_golden.inc holds it.
        const std::string frame = tui::snapshot_text(build_frame(), kCols);
        std::string cur;
        for (const char c : frame) {
            if (c == '\n') {
                std::string esc;
                for (const char k : cur) {
                    if (k == '\\' || k == '"') esc.push_back('\\');
                    esc.push_back(k);
                }
                std::printf("\"%s\",\n", esc.c_str());
                cur.clear();
            } else cur.push_back(c);
        }
        return 0;
    }
    if (argc > 1 && std::strcmp(argv[1], "--show") == 0) {
        std::printf("%s", tui::snapshot_text(build_frame(), kCols).c_str());
        return 0;
    }

    check_emit_set();
    check_render();
    check_aggregation();
    check_honesty();
    check_formatting();

    std::printf("checks=%d failures=%d\n", g_checks, g_fail);
    if (g_fail) { std::printf("KAT FAILED\n"); return 1; }
    std::printf("KAT OK\n");
    return 0;
}
