// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_coldboot_evq_kat.cpp   (COLD-BOOT-3)
//
// NativeNode::chain_events_ -- the queue the pool daemon drains for the tip
// feed (drain_mainchain_events) -- dropped its OLDEST events past 8192,
// silently: the pool never learned a block had been skipped. This KAT drives
// the REAL NativeNode (started, no peers, no daemon, no RandomX) with a burst
// of 9000 connected blocks while the consumer is not draining:
//
//   Q1  a catch-up DOWNLOAD burst (the index's chain-entry path, fed exactly
//       what refetch_wanted() hands out). Pre-fix 808 events are lost with no
//       counter anywhere. Fixed: the queue BACK-PRESSURES the bulk download
//       (the index hands out nothing above its tip while cap / 2 events are
//       undrained -- the verify thread is never blocked), so the queue never
//       overflows: 0 dropped, and the drained sequence is IDENTICAL to a
//       no-burst reference (every height once, in order, same ids).
//   Q2  a PUSH burst past the hard cap (pushes are not paced). Pre-fix 808
//       silent drops. Fixed: every drop is ALARMED and counted, and its height
//       is re-driven from the index on the next drain; what the index no longer
//       retains is counted as unrecoverable (loud) -- dropped == redriven +
//       unrecoverable, so 0 are silent.
//   Q3  the re-drive, with a cap inside the row retention (1024 / 1500 pushes):
//       the drained sequence is IDENTICAL to the no-burst reference.
//
// The same file builds against the pre-fix tree (the new surfaces are probed
// with `requires`), where Q1/Q2 FAIL. Network-free, RandomX-free.
// Nonzero exit on any failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "c2pool/v37/xmr/xmr_cba_block_source.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "impl/xmr/native/node/xmr_native_node.hpp"

namespace nat = c2pool::xmr::native;
namespace o2  = c2pool::v37n::xmr::o2;
using nat::BlockEntry;
using nat::ChainIndex;
using nat::ChainIndexOptions;
using nat::Hash;

namespace {

int g_fail = 0;
void check(const char* name, bool ok, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    if (!ok) ++g_fail;
}

// ---- the new surfaces, probed (absent on the pre-fix tree) --------------------
template <class O> concept HasWindow   = requires(O& o) { o.consumer_window = std::uint64_t{1}; };
template <class I> concept HasFrontier = requires(I& i) { i.set_consumer_frontier(std::uint64_t{1}); i.consumer_held(); };
template <class N> concept HasTipLook  = requires(N& n) { n.set_native_tip_lookup(std::function<std::uint64_t()>{}); };
template <class I> concept HasRefetch  = requires(I& i, const Hash& h) { i.want_body_for_booking(h, std::size_t{64}); };
template <class S> concept HasSrcRefetch = requires(S& s) { s.set_refetch(typename S::RefetchFn{}, std::uint64_t{1}); };

template <class O> void set_window(O& o, std::uint64_t w) { if constexpr (HasWindow<O>) o.consumer_window = w; else { (void)o; (void)w; } }
template <class I> void report_frontier(I& i, std::uint64_t h) { if constexpr (HasFrontier<I>) i.set_consumer_frontier(h); else { (void)i; (void)h; } }
template <class I> bool held(I& i) { if constexpr (HasFrontier<I>) return i.consumer_held(); else { (void)i; return false; } }
template <class N, class F> void set_tip_lookup(N& n, F f) { if constexpr (HasTipLook<N>) n.set_native_tip_lookup(std::function<std::uint64_t()>(std::move(f))); else { (void)n; (void)f; } }
template <class I> std::size_t want_back(I& idx, const Hash& id) {
    if constexpr (HasRefetch<I>) return idx.want_body_for_booking(id, 64);
    else { (void)idx; (void)id; return 0; }
}
template <class S, class F> void arm_refetch(S& s, F f) {
    if constexpr (HasSrcRefetch<S>) s.set_refetch(typename S::RefetchFn(std::move(f)), 120);
    else { (void)s; (void)f; }
}
template <class St> std::uint64_t replayed_of(const St& st) {
    if constexpr (requires { st.replayed_below_boot_cursor; }) return st.replayed_below_boot_cursor;
    else { (void)st; return 0; }
}
template <class G> std::uint64_t native_unknown_of(const G& g) {
    if constexpr (requires { g.native_unknown; }) return g.native_unknown;
    else { (void)g; return 0; }
}

// ---- blocks (the refetch KAT's shape) ------------------------------------------
Hash tag_id(std::uint64_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    h[31] = 0x5a;
    return h;
}
BlockEntry make_block(std::uint8_t major, std::uint64_t timestamp, const Hash& prev, std::uint32_t nonce,
                      std::uint64_t height, std::uint64_t reward) {
    std::vector<std::uint8_t> b;
    auto v = [&](std::uint64_t x) { nat::blob_write_varint(b, x); };
    v(major); v(major); v(timestamp);
    b.insert(b.end(), prev.begin(), prev.end());
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));
    v(2); v(height + 60); v(1); b.push_back(0xFF); v(height); v(1); v(reward);
    b.push_back(0x03);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x10 + ((i + height) & 0x3f)));
    b.push_back(static_cast<std::uint8_t>(height & 0xff));
    v(33); b.push_back(0x01);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x40 + i));
    b.push_back(0x00);
    v(0);
    BlockEntry e;
    e.block_blob = std::move(b);
    return e;
}
Hash id_of(const BlockEntry& e) {
    nat::EvaluatedBlock ev; std::string why;
    if (nat::evaluate_block(e, ev, why) != nat::EvalStatus::Ok) return Hash{};
    return ev.input.identity.id;
}
constexpr std::uint8_t  REG_MAJOR  = nat::MAX_IMPLEMENTED_HF_VERSION;
constexpr std::uint64_t GENESIS_TS = 1'700'000'000ull;
nat::U128 u128_of(std::uint64_t lo) { nat::U128 d; d.lo = lo; d.hi = 0; return d; }
nat::ChainRow genesis_row() {
    nat::ChainRow row;
    row.height = 0; row.id = tag_id(0); row.prev_id = Hash{}; row.timestamp = GENESIS_TS;
    row.major_version = 1; row.minor_version = 0; row.block_weight = 80; row.long_term_weight = 80;
    row.difficulty = u128_of(1); row.cumulative_difficulty = u128_of(1); row.already_generated_coins = 0;
    row.pow_verified = true;
    return row;
}
std::uint64_t base_at(std::uint64_t agc) {
    std::uint64_t base = 0;
    (void)nat::get_block_reward(300'000, 300, agc, nat::hf_rules_version(REG_MAJOR), base);
    return base;
}
class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };
    bool prefetch_epoch(const Hash&, const std::optional<Hash>&) { return true; }
    bool seed_resident(const Hash&) const { return true; }
    VerifyStatus verify(const std::uint8_t*, std::size_t, const Hash&, std::uint64_t, std::uint64_t, std::uint8_t out[32]) {
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }
};

constexpr std::uint64_t GAP    = 9000;   // a burst longer than the 8192-event queue
constexpr std::uint64_t WINDOW = 256;    // the shipped --native-catchup-window
constexpr std::uint64_t DCONF  = 3;

struct Chain {
    std::vector<BlockEntry> blocks;
    std::vector<Hash>       ids;
    std::map<Hash, std::size_t> by_id;
    Chain() {
        blocks.resize(GAP + 1); ids.resize(GAP + 1);
        ids[0] = genesis_row().id;
        std::uint64_t agc = 0;
        for (std::uint64_t h = 1; h <= GAP; ++h) {
            blocks[h] = make_block(REG_MAJOR, GENESIS_TS + 120 * h, ids[h - 1], static_cast<std::uint32_t>(h * 31), h, base_at(agc));
            agc = nat::accumulate_generated_coins(agc, base_at(agc));
            ids[h] = id_of(blocks[h]);
            by_id[ids[h]] = h;
        }
    }
};

std::string hex(const Hash& h) {
    static const char* k = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(k[b >> 4]); s.push_back(k[b & 0xf]); }
    return s;
}
bool id_of_hex(const std::string& x, Hash& out) {
    if (x.size() != 64) return false;
    auto nib = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nib(x[2 * i]), lo = nib(x[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

namespace rt = c2pool::xmr::native::rt;
using c2pool::xmr::node::MainchainEvent;
using c2pool::xmr::node::MainchainEventKind;

template <class C> concept HasBp  = requires(C& c) { c.chain_event_backpressure = true; c.chain_event_cap = std::size_t{1}; };
template <class N> concept HasQst = requires(const N& n) { n.chain_event_queue_stats(); };
struct Qs { std::uint64_t dropped = 0, redriven = 0, unrecoverable = 0, bp = 0; std::size_t high_water = 0; bool present = false; };
template <class N> Qs qstats(const N& n) {
    Qs q;
    if constexpr (HasQst<N>) {
        const auto s = n.chain_event_queue_stats();
        q.dropped = s.dropped; q.redriven = s.redriven; q.unrecoverable = s.unrecoverable; q.bp = s.backpressure_engaged;
        q.high_water = s.high_water; q.present = true;
    } else { (void)n; }
    return q;
}

template <class C> void set_bp(C& c, std::size_t cap) {
    if constexpr (HasBp<C>) { c.chain_event_backpressure = true; if (cap) c.chain_event_cap = cap; }
    else { (void)c; (void)cap; }
}

rt::NativeNodeConfig node_cfg(std::size_t cap) {
    rt::NativeNodeConfig c;
    c.net              = rt::NativeNet::Regtest;
    c.boot             = rt::BootMode::Genesis;
    c.snapshot_every_s = 0;
    c.parity           = false;
    c.use_seeds        = false;
    c.driver_tick_ms   = 100;
    c.allow_unverified_pow = true;   // no RandomX in this target
    set_bp(c, cap);
    return c;
}

struct Ev { int kind; std::uint64_t h; Hash id; bool operator==(const Ev&) const = default; };

struct Run {
    std::vector<Ev> got;
    std::uint64_t seen = 0, tip_after_burst = 0, tip = 0;
    Qs q;
};

struct Harness {
    rt::NativeNode node;
    const Chain& c;
    std::uint64_t net_tip;
    Harness(const Chain& ch, std::uint64_t nt, std::size_t cap) : node(node_cfg(cap)), c(ch), net_tip(nt) {
        std::string why;
        if (!node.start(why)) { check("rig: the NativeNode starts (no peers, no daemon)", false, why); return; }
        const nat::ChainRow g = genesis_row();
        node.index().seed_direct(g, {nat::DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                                 {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
    }
    ~Harness() { node.stop(); }
    std::uint64_t tip() const { const auto t = const_cast<rt::NativeNode&>(node).index().tip(); return t ? t->height : 0; }
    // One sync-driver round: a chain entry from our tip, then GET_OBJECTS for what the index hands out.
    std::size_t round() {
        auto& I = node.index();
        const std::uint64_t t = tip();
        if (t < net_tip) {
            nat::ChainEntry e;
            e.start_height = t; e.total_height = net_tip + 1;
            for (std::uint64_t h = t; h <= net_tip && e.ids.size() < 2000; ++h) e.ids.push_back(c.ids[h]);
            nat::PeerRef p; p.peer_id = 7; p.addr = "127.0.0.1:1";
            I.on_chain_entry(p, std::move(e));
        }
        std::size_t n = 0;
        for (const Hash& id : I.refetch_wanted()) {
            auto it = c.by_id.find(id);
            if (it == c.by_id.end() || it->second > net_tip) continue;
            (void)I.offer_block(nullptr, c.blocks[it->second], false);
            ++n;
        }
        return n;
    }
    void drain(Run& r) {
        for (const MainchainEvent& ev : node.drain_mainchain_events())
            r.got.push_back(Ev{static_cast<int>(ev.kind), ev.block.height, ev.kind == MainchainEventKind::Orphan ? ev.orphaned_id : ev.block.id});
    }
    void finish(Run& r) { drain(r); r.seen = node.mainchain_events_seen(); r.q = qstats(node); r.tip = tip(); }
};

Run download_run(const Chain& c, bool burst) {
    Run r; Harness H(c, GAP, 0);
    if (burst) {
        // The consumer is not draining (the serve loop is not up yet / stalled): the download runs as far as it is let.
        for (int i = 0; i < 400; ++i) if (H.round() == 0) break;
        r.tip_after_burst = H.tip();
    }
    for (int i = 0; i < 2000 && (H.tip() < GAP || i == 0); ++i) { H.drain(r); (void)H.round(); }
    H.finish(r);
    return r;
}

Run push_run(const Chain& c, std::uint64_t n, std::size_t cap, bool burst) {
    Run r; Harness H(c, n, cap);
    for (std::uint64_t h = 1; h <= n; ++h) {
        (void)H.node.index().offer_block(nullptr, c.blocks[h], false);   // a live push: never paced
        if (!burst) H.drain(r);
    }
    H.finish(r);
    return r;
}

std::vector<Ev> reference_seq(const Chain& c, std::uint64_t n) {
    std::vector<Ev> v;
    for (std::uint64_t h = 1; h <= n; ++h) v.push_back(Ev{static_cast<int>(MainchainEventKind::Extend), h, c.ids[h]});
    return v;
}

void print_run(const char* tag, const Run& r, std::size_t expect) {
    // silent = events the feed produced that were neither delivered nor alarmed as unrecoverable
    const std::uint64_t gone = r.seen > r.got.size() ? r.seen - r.got.size() : 0;
    const std::uint64_t silent = gone > r.q.unrecoverable ? gone - r.q.unrecoverable : 0;
    std::printf("  %-14s tip=%llu burst_tip=%llu seen=%llu delivered=%zu expected=%zu lost=%lld silent_drops=%llu | queue dropped=%llu redriven=%llu "
                "unrecoverable=%llu high_water=%zu backpressure_engaged=%llu%s\n",
                tag, (unsigned long long)r.tip, (unsigned long long)r.tip_after_burst, (unsigned long long)r.seen, r.got.size(), expect,
                (long long)expect - (long long)r.got.size(), (unsigned long long)silent, (unsigned long long)r.q.dropped,
                (unsigned long long)r.q.redriven, (unsigned long long)r.q.unrecoverable, r.q.high_water, (unsigned long long)r.q.bp,
                r.q.present ? "" : " (no queue stats on this tree)");
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::printf("== v37_xmr_coldboot_evq_kat ==\n");
    const Chain c;
    const std::vector<Ev> ref = reference_seq(c, GAP);

    std::printf("-- Q1: a %llu-block catch-up DOWNLOAD burst while the consumer is not draining --\n", (unsigned long long)GAP);
    const Run R  = download_run(c, false);
    const Run B  = download_run(c, true);
    print_run("reference", R, ref.size());
    print_run("burst", B, ref.size());
    check("Q0 rig: the no-burst reference drains every height 1..N once, in order, as Extend events",
          R.got == ref && R.tip == GAP, "delivered=" + std::to_string(R.got.size()));
    check("Q1 download burst: 0 events dropped (backpressure held the download below the cap)",
          B.q.present && B.q.dropped == 0 && B.seen == B.got.size() && B.q.high_water <= 8192,
          "seen=" + std::to_string(B.seen) + " delivered=" + std::to_string(B.got.size()) + " dropped=" + std::to_string(B.q.dropped));
    check("Q1b download burst: the drained sequence is IDENTICAL to the no-burst reference (booking input identical)",
          B.got == ref, "delivered=" + std::to_string(B.got.size()) + "/" + std::to_string(ref.size()));

    std::printf("-- Q2: a %llu-block PUSH burst past the hard cap (8192) while the consumer is not draining --\n", (unsigned long long)GAP);
    const Run P = push_run(c, GAP, 0, true);
    print_run("push-burst", P, ref.size());
    const std::uint64_t lost = P.seen > P.got.size() ? P.seen - P.got.size() : 0;
    check("Q2 push burst: NO silent drop -- every event that left the queue is counted and re-driven or alarmed unrecoverable",
          P.q.present && P.q.dropped > 0 && P.q.dropped == P.q.redriven + P.q.unrecoverable &&
              P.got.size() + P.q.unrecoverable == P.seen,
          "seen=" + std::to_string(P.seen) + " delivered=" + std::to_string(P.got.size()) + " lost=" + std::to_string(lost) +
          " counted_dropped=" + std::to_string(P.q.dropped));

    if constexpr (HasBp<rt::NativeNodeConfig>) {
        std::printf("-- Q3: the re-drive, cap 1024 inside the 2048-row retention, 1500 pushes --\n");
        const Run S = push_run(c, 1500, 1024, true);
        const std::vector<Ev> ref3 = reference_seq(c, 1500);
        print_run("push-cap1024", S, ref3.size());
        check("Q3 overflow re-driven from the index: dropped > 0, all re-driven, 0 unrecoverable, sequence IDENTICAL to the reference",
              S.q.dropped > 0 && S.q.redriven == S.q.dropped && S.q.unrecoverable == 0 && S.got == ref3,
              "dropped=" + std::to_string(S.q.dropped) + " redriven=" + std::to_string(S.q.redriven) + " delivered=" + std::to_string(S.got.size()));
    } else {
        check("Q3 overflow re-drive (the pre-fix tree has no configurable cap / re-drive)", false);
    }

    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
