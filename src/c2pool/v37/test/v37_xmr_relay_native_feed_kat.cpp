// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_native_feed_kat (D6b): under --arm-order p2p-first the receipt
// relay's chain view is fed from the native chain index, not from monerod.
//
//   F1  window equivalence: the native feed notes EXACTLY what the daemon arm
//       (get_block_headers_range over the last 128 + get_block_header_by_height
//       for the seed) notes over the same chain -- same (prev_id -> height,
//       seed) map, same seed table -- across a RandomX epoch edge.
//   F2  once per new tip: an unchanged tip is not re-ingested; a new height is.
//   F3  a same-height reorg (tip ID change at the same height) re-notes the new
//       branch at once, so a receipt built on the reorg-in block resolves.
//   F4  a block the node never served a template on (a missed block) resolves.
//   F5  a seed or row the index does not hold is a counted skip, never a note.
//   F6  the compare-only oracle's window verdict (equal / mismatch / one-sided).
// Context blobs are not this feed's: RC-CTX's NativeCtxFeeder::serve is the one
// server (v37_xmr_relay_native_ctx_kat N1/N2).
#include <c2pool/v37/xmr/relay/xmr_relay_chain_feed.hpp>

#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <tuple>

using namespace c2pool::v37n::xmr::relay;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

static FeedId mk(std::uint64_t h, std::uint8_t branch = 0) {
    FeedId id{};
    for (int i = 0; i < 8; ++i) id[i] = static_cast<std::uint8_t>(h >> (8 * i));
    id[31] = static_cast<std::uint8_t>(0xA0 + branch);
    return id;
}

// A scripted best chain: height -> id, with a retained row window and seed
// anchors kept beyond it (what the native ChainIndex does).
struct Chain {
    std::map<std::uint64_t, FeedId> rows;
    std::map<std::uint64_t, FeedId> anchors;
    std::uint64_t tip_h = 0;
    NativeFeedSource source() {
        NativeFeedSource s;
        s.tip = [this]() -> std::optional<std::pair<std::uint64_t, FeedId>> {
            auto it = rows.find(tip_h);
            if (it == rows.end()) return std::nullopt;
            return std::make_pair(tip_h, it->second);
        };
        s.id_at = [this](std::uint64_t h) -> std::optional<FeedId> {
            auto it = rows.find(h);
            if (it == rows.end()) return std::nullopt;
            return it->second;
        };
        s.seed_for = [this](std::uint64_t h) -> std::optional<FeedId> {
            const std::uint64_t sh = ::xmr::coin::rx_seedheight(h);
            if (auto it = anchors.find(sh); it != anchors.end()) return it->second;
            if (auto it = rows.find(sh); it != rows.end()) return it->second;
            return std::nullopt;
        };
        return s;
    }
    // The monerod view of the same chain: every height answers (a daemon holds the
    // whole chain), so the reference arm never misses.
    std::optional<FeedId> monerod_at(std::uint64_t h) const {
        if (auto it = rows.find(h); it != rows.end()) return it->second;
        if (auto it = anchors.find(h); it != anchors.end()) return it->second;
        return std::nullopt;
    }
};

struct Recorder {
    std::map<FeedId, std::pair<std::uint64_t, FeedId>> notes;   // prev -> (height, seed)
    std::map<std::uint64_t, FeedId> seeds;
    FeedSink sink() {
        FeedSink k;
        k.note = [this](const FeedId& p, std::uint64_t h, const FeedId& s) { notes[p] = {h, s}; };
        k.note_seed = [this](std::uint64_t sh, const FeedId& s) { seeds[sh] = s; };
        return k;
    }
};

// The daemon arm's body (main_v37_xmr.cpp, !p2p_first), with the two RPCs
// replaced by the monerod view of the same chain: the reference the native feed
// must reproduce.
static void daemon_arm_reference(const Chain& c, std::uint64_t best, Recorder& r) {
    std::map<std::uint64_t, FeedId> hdr;
    const std::uint64_t lo = best > 128 ? best - 128 : 0;
    std::vector<std::pair<std::uint64_t, FeedId>> hdrs;
    for (std::uint64_t h = lo; h <= best; ++h) if (auto id = c.monerod_at(h)) hdrs.emplace_back(h, *id);
    for (const auto& [h, id] : hdrs) hdr[h] = id;
    for (const auto& [h, id] : hdrs) {
        const std::uint64_t sh = ::xmr::coin::rx_seedheight(h + 1);
        auto sit = hdr.find(sh);
        if (sit == hdr.end()) {
            if (auto s = c.monerod_at(sh)) hdr[sh] = *s;
            sit = hdr.find(sh);
            if (sit == hdr.end()) continue;
        }
        r.notes[id] = {h + 1, sit->second};
        r.seeds[sh] = sit->second;
    }
}

static Chain build(std::uint64_t lo, std::uint64_t tip) {
    Chain c;
    for (std::uint64_t h = lo; h <= tip; ++h) c.rows[h] = mk(h);
    for (std::uint64_t e = 0; e <= tip; e += 2048) c.anchors[e] = mk(e);   // epoch ids kept as seed anchors
    c.tip_h = tip;
    return c;
}

int main() {
    // F1: equivalence, straddling an epoch edge (seed switches at 2048+64+1).
    {
        Chain c = build(1800, 2150);   // rows only from 1800: the seed at 0 / 2048 comes from the anchors
        NativeRelayChainFeed f; Recorder nat, ref;
        const auto src = c.source();
        CHECK(f.tick(src, nat.sink()));
        daemon_arm_reference(c, 2150, ref);
        CHECK(nat.notes.size() == 129);
        CHECK(nat.notes == ref.notes);
        CHECK(nat.seeds == ref.seeds);
        CHECK(nat.seeds.size() == 2);   // seed heights 0 and 2048 both appear in this window
        CHECK(f.stats().headers == 129 && f.stats().seed_miss == 0 && f.stats().row_miss == 0);
        // walk the whole climb block by block: equal at every tip
        Chain d = build(0, 200);
        NativeRelayChainFeed g; Recorder n2, r2;
        auto s2 = d.source();
        for (std::uint64_t t = 1; t <= 200; ++t) {
            d.tip_h = t;
            CHECK(g.tick(s2, n2.sink()));
            daemon_arm_reference(d, t, r2);
        }
        CHECK(n2.notes == r2.notes);
        CHECK(n2.seeds == r2.seeds);
        CHECK(g.stats().tips == 200);
    }
    // F2: once per new tip.
    {
        Chain c = build(0, 50);
        NativeRelayChainFeed f; Recorder r;
        auto src = c.source();
        CHECK(f.tick(src, r.sink()));
        const auto h1 = f.stats().headers;
        CHECK(!f.tick(src, r.sink()));
        CHECK(f.stats().headers == h1 && f.stats().tips == 1);
        c.rows[51] = mk(51); c.tip_h = 51;
        CHECK(f.tick(src, r.sink()));
        CHECK(f.stats().tips == 2 && f.stats().reorg_tips == 0);
    }
    // F3: same-height reorg -- tip 100 replaced by a sibling branch (99', 100').
    {
        Chain c = build(0, 100);
        NativeRelayChainFeed f; Recorder r;
        auto src = c.source();
        CHECK(f.tick(src, r.sink()));
        c.rows[99] = mk(99, 1); c.rows[100] = mk(100, 1);
        CHECK(f.tick(src, r.sink()));   // the daemon arm (height-keyed) would wait for 101
        CHECK(f.stats().reorg_tips == 1);
        auto it = r.notes.find(mk(100, 1));
        CHECK(it != r.notes.end() && it->second.first == 101);   // a receipt on the reorg-in tip resolves
        auto it2 = r.notes.find(mk(99, 1));
        CHECK(it2 != r.notes.end() && it2->second.first == 100);
        // the retired branch stays noted (a note is additive, as on the daemon arm)
        CHECK(r.notes.count(mk(100)) == 1);
        // a reorg to a SHORTER best chain is also ingested
        c.rows.erase(100); c.rows[99] = mk(99, 2); c.tip_h = 99;
        CHECK(f.tick(src, r.sink()));
        CHECK(f.stats().reorg_tips == 2 && r.notes.count(mk(99, 2)) == 1);
    }
    // F4: a block this node never served a template on (missed while down).
    {
        Chain c = build(0, 400);
        NativeRelayChainFeed f; Recorder r;
        auto src = c.source();
        CHECK(f.tick(src, r.sink()));
        for (std::uint64_t h = 300; h < 400; ++h) {
            auto it = r.notes.find(mk(h));
            CHECK(it != r.notes.end() && it->second.first == h + 1 && it->second.second == mk(0));
        }
        CHECK(r.notes.count(mk(271)) == 0);   // below the 128 window: not noted (as on the daemon arm)
    }
    // F5: missing seed / row -> counted skip, never a note.
    {
        Chain c = build(2200, 2300);
        c.anchors.erase(2048);           // seed of every block here is 2048: not held
        NativeRelayChainFeed f; Recorder r;
        auto src = c.source();
        CHECK(f.tick(src, r.sink()));
        CHECK(r.notes.empty() && f.stats().seed_miss == 101 && f.stats().row_miss == 28);
        Chain d = build(0, 100); d.rows.erase(90);
        NativeRelayChainFeed g; Recorder r2;
        auto s2 = d.source();
        CHECK(g.tick(s2, r2.sink()));
        CHECK(g.stats().row_miss == 1 && g.stats().headers == 100 && r2.notes.count(mk(90)) == 0);
        NativeFeedSource empty;
        CHECK(!empty);
        CHECK(!g.tick(empty, r2.sink()));
    }
    // F6: compare-only oracle verdict.
    {
        std::map<std::uint64_t, FeedId> a{{1, mk(1)}, {2, mk(2)}, {3, mk(3)}}, b{{2, mk(2)}, {3, mk(3, 1)}, {4, mk(4)}};
        const FeedCompare v = compare_windows(a, b);
        CHECK(v.equal == 1 && v.mismatch == 1 && v.native_only == 1 && v.monerod_only == 1);
    }
    if (g_fail) { std::printf("v37_xmr_relay_native_feed_kat: %d FAILED\n", g_fail); return 1; }
    std::printf("v37_xmr_relay_native_feed_kat: ALL PASS\n");
    return 0;
}
