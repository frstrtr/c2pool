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
// Seven things are checked, in the order they matter:
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
//   5. ABSENCE IS NOT ZERO. A second fixture holds one LIVE chain, one STALE
//      chain and one DOWN chain that has never received a block, and the KAT
//      asserts that the dead chain's panel contains `--` where a live panel
//      holds a number and contains NO zero-valued figure at all -- because a
//      zero there is the one rendering that reads as a measurement and is not.
//      The two live chains are asserted to be unaffected in the same frame.
//   6. THE LIVENESS LADDER. classify() is driven through all seven states with
//      fixed inputs, so the thresholds and the precedence order (no peers
//      outranks tip age; STALE outranks a computable cadence) are pinned rather
//      than described.
//   7. THE STATE CODEC ROUND-TRIPS. A frame is turned into a MonitorState, that
//      into JSON, that back into a MonitorState, and every number is compared.
//      The FILESYSTEM half of persistence -- atomic rename, the lock, the
//      journal, surviving a kill -- is xmr_p2pool_persist_kat, because it needs
//      POSIX and this KAT deliberately does not.
//
// Run with `--emit-golden` to print the frame the fixture produces; that is how
// the golden below was generated, and how it is regenerated on purpose.
// `--show` prints the live fixture and `--show-degraded` the dead-chain one.
//
// Offline, STL only: it includes no socket header, exactly like the parser KAT.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_freshness.hpp"
#include "impl/xmr/p2pool/p2pool_read_model.hpp"
#include "impl/xmr/p2pool/p2pool_state.hpp"
#include "impl/xmr/p2pool/p2pool_tui.hpp"
#include "impl/xmr/p2pool/p2pool_wire.hpp"

namespace p2p = c2pool::xmr::p2pool;
namespace tui = c2pool::xmr::p2pool::tui;
namespace st  = c2pool::xmr::p2pool::state;

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

// The panel block for one chain, cut out of a rendered frame by its TITLE LINE.
//
// The title is matched with its "  port " suffix, not by the chain name alone.
// The header's coverage row also names all three chains, and matching the bare
// name cut the panels out of that row instead -- which is the sort of thing a
// test helper gets wrong silently, so it is worth the extra six characters.
std::string panel_of(const std::string& frame, const char* chain) {
    const std::string title = std::string(" ") + chain + "  port ";
    const std::size_t at = frame.find(title);
    if (at == std::string::npos) return std::string();
    std::size_t end = frame.size();
    for (const char* other : {"MAIN", "MINI", "NANO"}) {
        if (std::strcmp(other, chain) == 0) continue;
        const std::size_t o = frame.find(std::string(" ") + other + "  port ", at);
        if (o != std::string::npos && o < end) end = o;
    }
    return frame.substr(at, end - at);
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

// A freshness clock, by hand. Every instant is explicit for the same reason
// every block timestamp above is: the classifier reads no clock, so a fixture
// that states the instants states the whole input.
p2p::FreshnessView mk_fresh(bool have_data, bool ever_connected, std::uint64_t started,
                            std::uint64_t tip_at, std::uint64_t rx_at, std::uint64_t up_since,
                            std::uint64_t down_since) {
    p2p::FreshnessView f;
    f.known          = true;
    f.have_data      = have_data;
    f.ever_connected = ever_connected;
    f.started_at_ms  = started;
    f.tip_at_ms      = tip_at;
    f.rx_at_ms       = rx_at;
    f.up_since_ms    = up_since;
    f.down_since_ms  = down_since;
    return f;
}

// The persistence banner the golden frame carries. Fixed like everything else,
// so the durability row is pinned by the golden rather than merely present.
tui::PersistView mk_persist() {
    tui::PersistView p;
    p.enabled          = true;
    p.dir              = "/home/obs/p2pmon-state";
    p.seq              = 41;
    p.ever_saved       = true;
    p.saved_age_ms     = 1000;
    p.journal_lines    = 41;
    p.loop_stall_max_ms = 312;
    p.restored         = true;
    p.restored_age_ms  = 131000;
    p.sessions         = 2;
    p.runtime_ms_total = 3723000;
    return p;
}

tui::MonitorFrame build_frame() {
    static const p2p::ReadModel main_m = build_main();
    static const p2p::ReadModel mini_m = build_mini();
    static const p2p::ReadModel nano_m = build_nano();

    tui::MonitorFrame f;
    f.elapsed_ms  = 185000;      // 00:03:05
    f.interactive = false;
    f.persist     = mk_persist();
    f.chains.push_back(tui::view_of(main_m, mk_emit(6, 6, 141, 6), 4, 12, kNow,
                                    mk_fresh(true, true, 995000, 1038000, 1038000, 999000, 0)));
    f.chains.push_back(tui::view_of(mini_m, mk_emit(5, 5, 118, 5), 3,  7, kNow,
                                    mk_fresh(true, true, 995000, 1039500, 1039500, 999000, 0)));
    f.chains.push_back(tui::view_of(nano_m, mk_emit(3, 3,  64, 3), 2,  3, kNow,
                                    mk_fresh(true, true, 995000, 1036000, 1036000, 999000, 0)));
    // Continuity, as it looks on a restarted monitor: what the previous session
    // left, with its age, on its own row.
    f.chains[0].carried             = true;
    f.chains[0].carry_written_at_ms = kNow - 131000;
    f.chains[0].carry_age_ms        = 131000;
    f.chains[0].carry_tip_height    = 15200091;
    f.chains[0].carry_tip_id8       = "9a1c4b7e";
    f.chains[0].lifetime_tip_max    = 15200104;
    f.chains[0].lifetime_monero_max = 3512003;
    return f;
}

// ---------------------------------------------------------------------------
// THE DEGRADED FIXTURE: one chain LIVE, one STALE, one DOWN with no data.
//
// This is the shape a real overnight run takes, and the shape an ordinary
// dashboard renders as three panels of confident numbers, two of which are
// hours old and one of which is zeros. The whole of check_absence_vs_zero()
// below is about this frame.
// ---------------------------------------------------------------------------
tui::MonitorFrame build_degraded_frame() {
    static const p2p::ReadModel main_m = build_main();
    static const p2p::ReadModel mini_m = build_mini();
    static const p2p::ReadModel none_m = p2p::ReadModel(p2p::Sidechain::Nano);  // nothing at all

    tui::MonitorFrame f;
    f.elapsed_ms  = 3725000;     // 01:02:05
    f.interactive = false;
    f.persist     = mk_persist();

    // main: healthy, and it must STAY healthy in the same frame as the others.
    f.chains.push_back(tui::view_of(main_m, mk_emit(6, 6, 141, 6), 4, 12, kNow,
                                    mk_fresh(true, true, 700000, 1038000, 1038000, 720000, 0)));
    // mini: peers up, data held, but the tip has not moved for 6m40s. Its
    // cadence is still computable from the blocks it holds -- and must not be
    // reported as a current reading.
    f.chains.push_back(tui::view_of(mini_m, mk_emit(5, 5, 118, 5), 3, 7, kNow,
                                    mk_fresh(true, true, 700000, kNow - 400000, kNow - 400000,
                                             720000, 0)));
    // nano: was connected, lost every peer 1m35s ago, and never received a
    // single block. Everything about it is an absence.
    f.chains.push_back(tui::view_of(none_m, tui::EmitCounts{}, 0, 0, kNow,
                                    mk_fresh(false, true, 700000, 700000, 700000, 0,
                                             kNow - 95000)));
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
    const std::string nano_panel = panel_of(frame, "NANO");
    check(!nano_panel.empty(), "the nano panel is drawn");
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
    check(!dark.have_data, "a chain with nothing on it holds no data");
    check_eq(dark.tip_id8, std::string("-"), "a dark chain shows no tip id");
    tui::MonitorFrame df;
    df.chains.push_back(dark);
    const std::string dark_frame = tui::snapshot_text(df, kCols);
    check(dark_frame.find("(nothing received yet)") != std::string::npos,
          "a dark chain says it has received nothing");
    check(dark_frame.find("nothing to time") != std::string::npos,
          "a dark chain refuses to time a chain it has not seen");
    check(dark_frame.find("PERSIST") != std::string::npos ||
          dark_frame.find("persist  OFF") != std::string::npos,
          "a frame with no persistence says so rather than staying silent");
}

// ---------------------------------------------------------------------------
// 5) ABSENCE IS NOT ZERO -- the whole point of the degraded fixture.
// ---------------------------------------------------------------------------

// Is there a figure on this line that reads as a measurement? The test is
// deliberately crude and deliberately strict: any run of digits that is not
// part of the chain's own identity (its port, its target, an age) would be a
// number the panel is asserting about a chain it has heard nothing from.
bool has_value_digit(const std::string& line) {
    static const char* kIdentity[] = {"port 37889", "port 37888", "port 37890",
                                      "target 10s", "target 30s"};
    std::string s = line;
    for (const char* k : kIdentity) {
        for (std::size_t at = s.find(k); at != std::string::npos; at = s.find(k))
            s.erase(at, std::strlen(k));
    }
    // Ages are written as 41s / 2m11s / 1h04m / 3d and are the ONE numeric
    // thing a dead panel is allowed to say, because they measure our own
    // outage rather than the chain.
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] >= '0' && s[i] <= '9') {
            std::size_t j = i;
            while (j < s.size() && s[j] >= '0' && s[j] <= '9') ++j;
            const char unit = j < s.size() ? s[j] : ' ';
            if (unit == 's' || unit == 'm' || unit == 'h' || unit == 'd') { i = j; continue; }
            out.push_back('#');
            i = j - 1;
            continue;
        }
    }
    return !out.empty();
}

void check_absence_vs_zero() {
    const tui::MonitorFrame f = build_degraded_frame();
    check_eq(f.chains.size(), std::size_t(3), "the degraded fixture still has three chains");

    // The three states, from the same classifier the live path uses.
    check_eq(f.chains[0].status, tui::ChainStatus::Live,  "main is live in the degraded frame");
    check_eq(f.chains[1].status, tui::ChainStatus::Stale, "mini is stale: tip frozen 6m40s");
    check_eq(f.chains[2].status, tui::ChainStatus::Down,  "nano is down: peers lost 1m35s ago");
    check(f.chains[0].have_data,  "main holds data");
    check(f.chains[1].have_data,  "a stale chain still holds the data it did have");
    check(!f.chains[2].have_data, "a chain that never received a block holds none");

    // A DOWN chain and a DARK chain are different words for different facts.
    p2p::FreshnessView never = mk_fresh(false, false, 700000, 700000, 700000, 0, 700000);
    check_eq(p2p::classify(never, 0, 0, 0, false, 10, kNow), p2p::Liveness::Dark,
             "never connected is DARK, not DOWN");

    const std::string frame = tui::snapshot_text(f, kCols);
    const std::string nano  = panel_of(frame, "NANO");
    const std::string mini  = panel_of(frame, "MINI");
    const std::string main  = panel_of(frame, "MAIN");
    check(!nano.empty() && !mini.empty() && !main.empty(), "all three panels are drawn");

    // --- the dead chain ---------------------------------------------------
    check(nano.find("DOWN") != std::string::npos, "the dead chain is labelled DOWN");
    check(nano.find("1m35s") != std::string::npos, "the dead chain says how long it has been down");
    check(nano.find("no peers") != std::string::npos, "the dead chain says what DOWN means");
    check(nano.find(tui::kNoData) != std::string::npos, "the dead chain renders -- for its figures");

    // THE CENTRAL ASSERTION. Walk the dead panel's data rows and refuse any
    // digit that is not the chain's identity or an age. A regression that
    // reinstated the zero-initialised members would land exactly here.
    std::vector<std::string> lines;
    {
        std::string cur;
        for (const char c : nano) {
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) lines.push_back(cur);
    }
    int checked_rows = 0;
    for (const std::string& l : lines) {
        const bool data_row = l.find("   tip ") == 0 || l.find("   cadence ") == 0
                           || l.find("   pulse ") == 0 || l.find("   races ") == 0;
        if (!data_row) continue;
        ++checked_rows;
        ++g_checks;
        if (has_value_digit(l)) {
            std::printf("FAIL: a dead chain printed a figure: |%s|\n", l.c_str());
            ++g_fail;
        }
        ++g_checks;
        if (l.find(tui::kNoData) == std::string::npos) {
            std::printf("FAIL: a dead chain row has no -- marker: |%s|\n", l.c_str());
            ++g_fail;
        }
    }
    check_eq(checked_rows, 4, "four data rows on the dead panel were examined");
    check(nano.find("0 up / 0 sock") != std::string::npos,
          "peer counts stay real numbers: zero peers is a measurement");

    // --- the stale chain --------------------------------------------------
    check(mini.find("STALE") != std::string::npos, "the frozen chain is labelled STALE");
    check(mini.find("tip frozen") != std::string::npos, "the frozen chain says what STALE means");
    check(mini.find("as of 6m40s") != std::string::npos,
          "the frozen chain dates its tip instead of presenting it as current");
    check(mini.find("no new height for 6m40s") != std::string::npos,
          "the frozen chain spells out what has stopped, on its own row");
    check(mini.find("14757144") != std::string::npos,
          "a stale chain keeps the last number it knew rather than blanking it");

    // --- the live chain is untouched --------------------------------------
    check(main.find("LIVE") != std::string::npos, "the live chain is still live");
    check(main.find("15200104") != std::string::npos, "the live chain still shows its tip");
    // No `--` on a live panel's DATA rows. Three rows are drawn out of '-'
    // characters and are graphics rather than figures -- the title rule, the
    // pulse ramp and the cadence bar's empty cells -- so they are looked past
    // rather than being a reason to weaken the check on the rows that carry
    // the actual numbers.
    for (const char* row : {"   tip ", "   races ", "   net "}) {
        const std::size_t at = main.find(row);
        ++g_checks;
        if (at == std::string::npos) {
            std::printf("FAIL: the live panel is missing its %srow\n", row);
            ++g_fail;
            continue;
        }
        const std::size_t eol = main.find('\n', at);
        const std::string line = main.substr(at, eol - at);
        if (line.find(tui::kNoData) != std::string::npos) {
            std::printf("FAIL: a live panel row carries a no-data marker: |%s|\n", line.c_str());
            ++g_fail;
        }
    }

    // --- the aggregates do not launder the gap ----------------------------
    const tui::MonitorTotals t = tui::totals_of(f.chains);
    check_eq(t.chains, std::size_t(3), "three chains configured");
    check_eq(t.chains_live, std::size_t(1), "one chain is live");
    check_eq(t.chains_reporting, std::size_t(2), "two chains have numbers behind them");
    check_eq(t.chains_down, std::size_t(1), "one chain has no peers");
    check_eq(t.chains_stale, std::size_t(1), "one chain has peers and a frozen tip");
    check(frame.find("2/3 reporting") != std::string::npos,
          "the header states the coverage of its own totals");
    check(frame.find("1 down") != std::string::npos, "the header counts the dead chain");
    check(frame.find("1 stale") != std::string::npos, "the header counts the frozen chain");

    // The renderer stays total on a degraded frame -- a dead source must not
    // change the geometry any more than it may crash the loop.
    for (std::size_t cols : {60u, 100u, 140u}) {
        for (std::size_t rows : {12u, 30u}) {
            const std::vector<std::string> out = tui::render(f, cols, rows, false);
            check_eq(out.size(), rows, "a degraded frame renders the rows asked for");
            bool ok = true;
            for (const std::string& l : out) if (l.size() != cols) ok = false;
            check(ok, "a degraded frame renders full-width lines");
        }
    }
}

// ---------------------------------------------------------------------------
// 6) THE LIVENESS LADDER. All seven states, and the precedence between them.
// ---------------------------------------------------------------------------
void check_liveness_ladder() {
    const std::uint64_t now = 10'000'000;
    const p2p::FreshnessThresholds th;

    // The bands for a 10 s chain: quiet at 60 s (the floor beats 4x10), stale
    // at 180 s (the floor beats 12x10).
    check_eq(th.quiet_ms(10), std::uint64_t(60000),  "a 10 s chain goes quiet at 60 s");
    check_eq(th.stale_ms(10), std::uint64_t(180000), "a 10 s chain goes stale at 180 s");
    // ... and for a 30 s chain the multiple beats the floor, as intended.
    check_eq(th.quiet_ms(30), std::uint64_t(120000), "a 30 s chain goes quiet at 120 s");
    check_eq(th.stale_ms(30), std::uint64_t(360000), "a 30 s chain goes stale at 360 s");

    auto fresh_at = [&](std::uint64_t tip_age, bool have, bool ever) {
        return mk_fresh(have, ever, now - 600000, now - tip_age, now - tip_age,
                        ever ? now - 600000 : 0, 0);
    };

    check_eq(p2p::classify(fresh_at(1000, true, true), 4, 4, 0, true, 10, now),
             p2p::Liveness::Live, "peers, data, moving tip, timed -> LIVE");
    check_eq(p2p::classify(fresh_at(1000, true, true), 4, 4, 0, false, 10, now),
             p2p::Liveness::Warming, "peers and data but not timed yet -> WARM");
    check_eq(p2p::classify(fresh_at(1000, false, true), 4, 4, 0, false, 10, now),
             p2p::Liveness::Warming, "peers but nothing received -> WARM");
    check_eq(p2p::classify(fresh_at(90000, true, true), 4, 4, 0, true, 10, now),
             p2p::Liveness::Quiet, "90 s without a height on a 10 s chain -> QUIET");
    check_eq(p2p::classify(fresh_at(400000, true, true), 4, 4, 0, true, 10, now),
             p2p::Liveness::Stale, "400 s without a height -> STALE, cadence or not");
    check_eq(p2p::classify(fresh_at(1000, true, true), 0, 0, 0, true, 10, now),
             p2p::Liveness::Down, "no peers after having had some -> DOWN");
    check_eq(p2p::classify(fresh_at(1000, false, false), 0, 2, 3, false, 10, now),
             p2p::Liveness::Dialling, "sockets in flight, never handshaken -> DIAL");
    check_eq(p2p::classify(fresh_at(1000, false, false), 0, 0, 0, false, 10, now),
             p2p::Liveness::Dark, "nothing at all -> DARK");

    // PRECEDENCE, stated as tests because it is the part that is easy to get
    // subtly wrong: a fresh tip does not rescue a chain with no peers, and a
    // computable cadence does not rescue a frozen one.
    check_eq(p2p::classify(fresh_at(0, true, true), 0, 4, 0, true, 10, now),
             p2p::Liveness::Down, "a tip that moved this instant does not outrank losing the peers");
    check_eq(p2p::classify(fresh_at(400000, true, true), 4, 4, 0, true, 10, now),
             p2p::Liveness::Stale, "a computable cadence does not outrank a frozen tip");

    // is_degraded() is what the aggregation counts on.
    check(!p2p::is_degraded(p2p::Liveness::Live), "LIVE is not degraded");
    check(!p2p::is_degraded(p2p::Liveness::Warming), "WARM is not degraded");
    for (const p2p::Liveness s : {p2p::Liveness::Quiet, p2p::Liveness::Stale, p2p::Liveness::Down,
                                  p2p::Liveness::Dialling, p2p::Liveness::Dark})
        check(p2p::is_degraded(s), "every other state is degraded");

    // An age computed against a clock that is BEHIND the recorded instant --
    // which happens the moment a state file is copied between machines -- must
    // clamp at zero rather than wrap into a 584-million-year age.
    p2p::FreshnessView future = mk_fresh(true, true, now + 5000, now + 5000, now + 5000,
                                         now + 5000, 0);
    check_eq(future.tip_age_ms(now), std::uint64_t(0), "an age never runs backwards");
}

// ---------------------------------------------------------------------------
// 7) THE STATE CODEC. Frame -> state -> JSON -> state, number by number.
// ---------------------------------------------------------------------------
void check_state_codec() {
    const tui::MonitorFrame f = build_frame();

    st::SessionMeta meta;
    meta.written_at_ms = 1757620000123ull;
    meta.seq  = 42;
    meta.pid  = 4711;
    meta.host = "an \"odd\" host\\name";        // the escaping path, on purpose
    meta.session_id            = "1757619000000-4711";
    meta.session_started_at_ms = 1757619000000ull;
    meta.shutdown              = "clean";
    meta.persist.errors            = 2;
    meta.persist.last_error        = "write temp: No space left on device";
    meta.persist.loop_stall_max_ms = 312;
    meta.lifetime.sessions            = 7;
    meta.lifetime.first_started_at_ms = 1757000000000ull;
    meta.lifetime.runtime_ms_total    = 987654321ull;

    const st::MonitorState a = st::state_of(f, meta);
    const std::string json = st::to_json(a);
    check(json.size() > 1000 && json.size() < 16000, "one state file is a few KB");
    check(json.find("\"schema\":\"p2pmon-state/1\"") != std::string::npos,
          "the file names its schema first");
    check(json.find("\"emitted_ids\":[0,1,3,6]") != std::string::npos,
          "the read-only claim is written into the file");
    check(json.find("an \\\"odd\\\" host\\\\name") != std::string::npos,
          "strings with quotes and backslashes are escaped");
    // Non-finite values are not valid JSON. Matched as VALUES (":nan", ":inf")
    // rather than as substrings: the chain named "nano" contains "nan", and a
    // check that fires on a chain name is a check nobody will trust.
    check(json.find(":nan") == std::string::npos && json.find(":inf") == std::string::npos
          && json.find(":-inf") == std::string::npos,
          "no non-finite number reaches the file");

    st::MonitorState b;
    std::string why;
    check(st::from_json(json, b, why), "the file we just wrote parses");
    if (!why.empty()) std::printf("      (parse note: %s)\n", why.c_str());

    check_str(b.schema, a.schema, "schema round-trips");
    check_eq(b.written_at_ms, a.written_at_ms, "written_at_ms round-trips exactly");
    check_eq(b.seq, a.seq, "seq round-trips");
    check_eq(b.pid, a.pid, "pid round-trips");
    check_str(b.host, a.host, "an escaped host string round-trips");
    check_str(b.session_id, a.session_id, "session id round-trips");
    check_eq(b.session_started_at_ms, a.session_started_at_ms, "session start round-trips");
    check_eq(b.elapsed_ms, a.elapsed_ms, "elapsed round-trips");
    check_str(b.shutdown, a.shutdown, "the clean-shutdown marker round-trips");
    check_eq(b.emitted_ids.size(), a.emitted_ids.size(), "the emit set round-trips");
    for (std::size_t i = 0; i < b.emitted_ids.size() && i < a.emitted_ids.size(); ++i)
        check_eq(b.emitted_ids[i], a.emitted_ids[i], "each emitted id round-trips");
    check_eq(b.persist.errors, a.persist.errors, "persist error count round-trips");
    check_str(b.persist.last_error, a.persist.last_error, "the last error text round-trips");
    check_eq(b.persist.loop_stall_max_ms, a.persist.loop_stall_max_ms,
             "the worst loop stall round-trips");
    check_eq(b.lifetime.sessions, a.lifetime.sessions, "the session count round-trips");
    check_eq(b.lifetime.runtime_ms_total, a.lifetime.runtime_ms_total,
             "total runtime round-trips");
    check_eq(b.chains.size(), a.chains.size(), "every chain round-trips");

    for (std::size_t i = 0; i < b.chains.size() && i < a.chains.size(); ++i) {
        const st::ChainState& x = a.chains[i];
        const st::ChainState& y = b.chains[i];
        check_str(y.name, x.name, "chain name round-trips in order");
        check_eq(y.port, x.port, "port round-trips");
        check_eq(y.target_s, x.target_s, "target round-trips");
        check_str(y.liveness, x.liveness, "the status word round-trips");
        check_eq(y.have_data, x.have_data, "the absence flag round-trips");
        check_eq(y.ever_connected, x.ever_connected, "ever_connected round-trips");
        check_eq(y.tip_advanced_at_ms, x.tip_advanced_at_ms, "the staleness clock round-trips");
        check_eq(y.rx_at_ms, x.rx_at_ms, "the receive clock round-trips");
        check_eq(y.up_since_ms, x.up_since_ms, "up_since round-trips (null means zero)");
        check_eq(y.down_since_ms, x.down_since_ms, "down_since round-trips");
        check_eq(y.tip_height, x.tip_height, "tip height round-trips exactly");
        check_str(y.tip_id, x.tip_id, "the full 64-hex tip id round-trips");
        check_str(y.difficulty, x.difficulty, "difficulty round-trips as exact decimal");
        check_str(y.cumulative_difficulty, x.cumulative_difficulty,
                  "cumulative difficulty round-trips as exact decimal");
        check_eq(y.cadence_ok, x.cadence_ok, "the cadence flag round-trips");
        ++g_checks;
        if (y.cadence_s != x.cadence_s) {          // %.17g is exact for a double
            std::printf("FAIL: cadence %.17g != %.17g\n", y.cadence_s, x.cadence_s);
            ++g_fail;
        }
        check_eq(y.cadence_n, x.cadence_n, "the cadence sample count round-trips");
        check_eq(y.frontier, x.frontier, "the frontier round-trips");
        check_eq(y.gaps_ms.size(), x.gaps_ms.size(), "the pulse round-trips");
        for (std::size_t k = 0; k < y.gaps_ms.size() && k < x.gaps_ms.size(); ++k)
            check_eq(y.gaps_ms[k], x.gaps_ms[k], "each gap round-trips exactly");
        check_eq(y.contested, x.contested, "contested heights round-trip");
        check_eq(y.uncles_named, x.uncles_named, "named uncles round-trip");
        check_eq(y.uncles_resolved, x.uncles_resolved, "resolved uncles round-trip");
        check_eq(y.monero_tpl_high, x.monero_tpl_high, "the monero template height round-trips");
        check_eq(y.monero_heights, x.monero_heights, "the monero height count round-trips");
        check_eq(y.peers_up, x.peers_up, "peers up round-trips");
        check_eq(y.peers_known, x.peers_known, "known peers round-trip");
        check_eq(y.gossiped, x.gossiped, "gossiped addresses round-trip");
        check_eq(y.distinct, x.distinct, "distinct blocks round-trip");
        check_eq(y.dupes, x.dupes, "duplicates round-trip");
        check_eq(y.parse_failures, x.parse_failures, "parse failures round-trip");
        check_eq(y.broadcasts, x.broadcasts, "broadcasts round-trip");
        for (std::size_t k = 0; k < p2p::kControlMessageCount; ++k) {
            check_eq(y.out_messages[k], x.out_messages[k], "each emitted counter round-trips");
            check_eq(y.out_bytes[k], x.out_bytes[k], "each emitted byte count round-trips");
        }
        check_eq(y.lifetime.tip_height_max, x.lifetime.tip_height_max,
                 "the lifetime tip high-water mark round-trips");
    }

    // A 128-bit cumulative difficulty must survive, which is why it is text:
    // as a JSON double it would lose its low bits and come back plausible.
    st::MonitorState big = a;
    big.chains[0].cumulative_difficulty = "340282366920938463463374607431768211455";
    big.chains[0].difficulty            = "18446744073709551615";
    st::MonitorState back;
    check(st::from_json(st::to_json(big), back, why), "a 128-bit difficulty file parses");
    check_str(back.chains[0].cumulative_difficulty,
              "340282366920938463463374607431768211455", "2^128-1 survives the round trip");
    check_str(back.chains[0].difficulty, "18446744073709551615", "2^64-1 survives the round trip");
    std::uint64_t hi = 0, lo = 0;
    check(st::dec_to_u128("18446744073709551615", hi, lo), "2^64-1 parses as a 128-bit value");
    check_eq(hi, std::uint64_t(0), "2^64-1 has a zero high word");
    check_eq(lo, std::uint64_t(18446744073709551615ull), "2^64-1 keeps every bit");
    check(!st::dec_to_u128("1157920892373161954235709850086879078532699846656405640394575840079131296399361",
                           hi, lo), "an over-wide decimal is refused rather than wrapped");
    check(!st::dec_to_u128("12x4", hi, lo), "a non-decimal is refused");

    // A foreign or truncated file is a refusal, never a crash and never a
    // plausible-looking state.
    st::MonitorState junk;
    check(!st::from_json("", junk, why), "an empty file is refused");
    check(!st::from_json("{\"schema\":\"something-else/9\"}", junk, why),
          "a foreign schema is refused");
    check(!st::from_json(json.substr(0, json.size() / 2), junk, why),
          "a truncated file is refused");
    check(!st::from_json("{\"schema\":\"p2pmon-state/1\"}", junk, why),
          "a state with no write time is refused");

    // THE READ PATH. A saved state renders through the SAME renderer, and its
    // age is resolved against the reader's clock: a day later it is STALE.
    const tui::MonitorFrame day_later = st::frame_of(b, meta.written_at_ms + 86400000ull);
    check(day_later.from_file, "a restored frame knows it came from a file");
    check_eq(day_later.chains.size(), std::size_t(3), "a restored frame has every chain");
    for (const tui::ChainView& c : day_later.chains)
        check_eq(c.status, tui::ChainStatus::Stale, "a day-old state renders as stale");
    const std::string restored = tui::snapshot_text(day_later, kCols);
    check(restored.find("RESTORED FRAME") != std::string::npos,
          "a restored frame says so at the top");
    check(restored.find("no network was dialled") != std::string::npos,
          "a restored frame says it dialled nothing");
    check(restored.find("FROM FILE 1d OLD") != std::string::npos,
          "every restored panel carries the age of the file");
    check(restored.find("15200104") != std::string::npos,
          "a restored frame carries the numbers that were saved");

    // Read back one second later and the same file is a current reading, with
    // the same numbers -- the continuity property, in the renderer.
    const tui::MonitorFrame just_now = st::frame_of(b, meta.written_at_ms + 1000);
    check_eq(just_now.chains[0].tip_height, f.chains[0].tip_height,
             "the restored tip height is the saved tip height");
    check_str(just_now.chains[0].difficulty, f.chains[0].difficulty,
              "the restored difficulty is the saved difficulty");
    ++g_checks;
    if (just_now.chains[0].hashrate != f.chains[0].hashrate) {
        std::printf("FAIL: restored hashrate %.6Lf != live %.6Lf\n",
                    just_now.chains[0].hashrate, f.chains[0].hashrate);
        ++g_fail;
    }
    ++g_checks;
    if (just_now.chains[0].cumulative_d != f.chains[0].cumulative_d) {
        std::printf("FAIL: restored cumulative differs from live\n");
        ++g_fail;
    }
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
    if (argc > 1 && std::strcmp(argv[1], "--show-degraded") == 0) {
        std::printf("%s", tui::snapshot_text(build_degraded_frame(), kCols).c_str());
        return 0;
    }
    if (argc > 1 && std::strcmp(argv[1], "--show-state") == 0) {
        st::SessionMeta m;
        m.written_at_ms = 1757620000123ull;
        m.seq = 41;
        m.pid = 4711;
        m.host = "example";
        m.session_id = "1757619000000-4711";
        m.session_started_at_ms = 1757619000000ull;
        m.lifetime.sessions = 2;
        std::printf("%s", st::to_json(st::state_of(build_frame(), m)).c_str());
        return 0;
    }

    check_emit_set();
    check_render();
    check_aggregation();
    check_honesty();
    check_formatting();
    check_absence_vs_zero();
    check_liveness_ladder();
    check_state_codec();

    std::printf("checks=%d failures=%d\n", g_checks, g_fail);
    if (g_fail) { std::printf("KAT FAILED\n"); return 1; }
    std::printf("KAT OK\n");
    return 0;
}
