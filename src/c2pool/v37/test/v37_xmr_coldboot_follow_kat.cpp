// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_coldboot_follow_kat.cpp   (COLD-BOOT-3)
//
// COLD-BOOT-2 paces the catch-up download at the settlement's finalize cursor
// + --native-catchup-window (256). The pacing applied to EVERY p2p-first
// anchor boot, including a snapshot resume, and never switched off: with the
// cursor HELD indefinitely (an undecidable lane block, a relay repair no peer
// can serve) and the tip more than the window past it, the chain-entry
// download stopped at the ceiling -- the node never reached synced again (no
// template arm, no jobs, snapshot tip frozen). This KAT pins the fix with the
// REAL ChainIndex at the SHIPPED bounds (2048 rows, 1024 bodies, window 256):
//
//   F1-F5  held cursor, the tip runs > 2 x window past it (F5: a missed-push
//          gap in the running process is fetched, the node stays synced), snapshot, restart
//          while the network moves on (missed pushes). Pre-fix the resumed
//          node's download is held at cursor + 256 below its own snapshot tip:
//          index tip frozen, synced=0, consumer_held=1. Fixed: the pacing is
//          lifted for the process (the resume is already past the ceiling),
//          the index follows the network tip and is synced; the cursor is
//          still HELD at the undecidable block (alarm kept), 0 late_unbooked,
//          0 heights at/below the cursor undecided (no silent drop).
//   P1-P3  a FRESH cold boot whose cursor is held from the start: pre-fix the
//          download stops at cursor + 256 forever. Fixed: after the shipped
//          stall bound (consumer_stall_reports) the pacing is lifted, the node
//          follows the network tip and is synced; the cursor stays held; 0 late,
//          0 undecided at/below it.
//   C1     the COLD-BOOT-2 guarantee is kept: a cold boot whose cursor is NOT
//          held is still paced (download never more than the window above the
//          cursor) until it is synced.
//
// The same file builds against the pre-fix tree (the new surfaces are probed
// with `requires`), where F1/F5/P1 FAIL. Network-free, RandomX-free.
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

constexpr std::uint64_t GAP    = 3000;   // post-anchor gap: longer than the 2048-row retention
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

// A REAL index behind a simulated sync driver: it is fed exactly what the index
// asks for (a chain entry from our tip, then GET_OBJECTS for refetch_wanted()
// and bodies_wanted()), never more.
struct Index {
    ModelVerifier mv;
    nat::LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions opts;
    std::unique_ptr<ChainIndex> idx;
    std::vector<c2pool::xmr::node::MainchainEvent> queue;   // the native node's event queue
    const Chain& c;
    std::uint64_t net_tip;
    Index(const Chain& ch, std::uint64_t network_tip, std::size_t rows, std::size_t cache, std::uint64_t window)
        : c(ch), net_tip(network_tip) {
        opts.net = nat::XmrNet::Regtest;
        opts.require_pow = false;
        opts.row_retention = rows;
        opts.entry_cache = cache;
        set_window(opts, window);
        idx = std::make_unique<ChainIndex>(opts, src);
        idx->subscribe([this](const c2pool::xmr::node::MainchainEvent& ev) { queue.push_back(ev); });
        const nat::ChainRow g = genesis_row();
        idx->seed_direct(g, {nat::DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                         {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
    }
    std::uint64_t tip() const { const auto t = idx->tip(); return t ? t->height : 0; }
    // One driver round. Returns the number of blocks offered.
    std::size_t sync_round() {
        std::size_t n = 0;
        const std::uint64_t t = tip();
        if (t < net_tip) {
            nat::ChainEntry e;
            e.start_height = t; e.total_height = net_tip + 1;
            for (std::uint64_t h = t; h <= net_tip && e.ids.size() < 2000; ++h) e.ids.push_back(c.ids[h]);
            nat::PeerRef p; p.peer_id = 7; p.addr = "127.0.0.1:1";
            idx->on_chain_entry(p, std::move(e));
        }
        for (const Hash& id : idx->refetch_wanted()) {
            auto it = c.by_id.find(id);
            if (it == c.by_id.end() || it->second > net_tip) continue;
            (void)idx->offer_block(nullptr, c.blocks[it->second], false);
            ++n;
        }
        std::size_t b = 0;
        for (const Hash& id : idx->bodies_wanted()) {   // the part-1 booking refetch (re-ask by id)
            auto it = c.by_id.find(id);
            if (it == c.by_id.end()) continue;
            (void)idx->offer_block(nullptr, c.blocks[it->second], false);
            if (++b >= 64) break;
        }
        return n + b;
    }
    std::vector<c2pool::xmr::node::MainchainEvent> drain() { std::vector<c2pool::xmr::node::MainchainEvent> o; o.swap(queue); return o; }
};

struct Out {
    std::string digest;
    std::set<std::string> settled;
    std::map<std::string, std::string> credits;
    std::vector<std::uint64_t> decided_order;   // heights decided (booked / not-lane), in decision order (all processes)
    std::uint64_t cursor = 0, late = 0, held = 0, refused = 0, rpc = 0, native_unknown = 0, dropped = 0, lane_dropped = 0;
    std::uint64_t max_lead = 0;                  // max (index tip - finalize cursor) seen while pumping
    std::uint64_t restart_cursor = 0, first_tick_cursor = 0, first_tick_undecided = 0, replayed = 0;
    bool order_ok = true;
};

// One settlement "process": XmrNode + FinalizeConnect over a store dir, bound to an Index.
struct Proc {
    c2pool::xmr::node::MockMonerodTransport mock;
    c2pool::v37n::xmr::XmrNodeConfig cfg;
    std::unique_ptr<c2pool::v37n::xmr::XmrNode> node;
    std::unique_ptr<o2::CbaBlockSource> src;
    o2::FoundBlockQueue q;
    std::unique_ptr<o2::FinalizeConnect> fc;
    std::uint64_t rpc = 0;
    Proc(Index& ix, const std::filesystem::path& dir, Out& out, std::map<std::uint64_t, int>& decided,
         const std::function<bool(std::uint64_t)>& hold) {
        using namespace c2pool::v37n::xmr;
        cfg.network = MoneroNetwork::Stagenet;
        cfg.lane_chain = 7;
        cfg.d_conf = DCONF;
        cfg.arm_order = ArmOrderMode::P2PFirst;
        cfg.settle_db_path = dir.string();
        std::filesystem::create_directories(dir);
        node = std::make_unique<XmrNode>(cfg, mock, &smoke::test_point_check);
        ChainIndex* I = ix.idx.get();
        node->set_native_chain_presence([I](std::uint64_t h, const std::string& bid) {
            const auto b = I->by_height(h);
            return b.has_value() && hex(b->id) == bid;
        });
        node->set_native_row_lookup([I](std::uint64_t h) -> std::optional<std::string> {
            const auto b = I->by_height(h);
            if (!b) return std::nullopt;
            return hex(b->id);
        });
        set_tip_lookup(*node, [I]() -> std::uint64_t { const auto t = I->tip(); return t ? t->height : 0; });
        node->bring_up();
        src = std::make_unique<o2::CbaBlockSource>(
            [I](const std::string& bid, std::vector<std::uint8_t>& blob) {
                Hash id{}; if (!id_of_hex(bid, id)) return false;
                return I->block_blob_of(id, blob);
            },
            [this](const std::string&, std::vector<std::uint8_t>&, std::string& why) { ++rpc; why = "get_block: test (must not be called)"; return false; });
        arm_refetch(*src, [I](const std::string& bid) { Hash id{}; if (id_of_hex(bid, id)) (void)want_back(*I, id); });
        o2::FinalizeConnectOptions o;
        o.out = nullptr;
        o.sidecar_path = (dir / "pfound.tsv").string();
        o.retry_bound = 40; o.held_retry_every = 5;
        o.book_from_chain_ex = [this, &out, &decided, hold](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) {
            if (hold && hold(h)) { bk.why = "native-hold: test (an undecidable block the operator has not cleared yet)"; return false; }
            std::vector<std::uint8_t> blob;
            if (!src->fetch(bid, blob, bk.why)) return false;
            if (!out.decided_order.empty() && h <= out.decided_order.back() && !decided.count(h)) out.order_ok = false;
            if (!decided.count(h)) out.decided_order.push_back(h);
            ++decided[h];
            if (h % 5 != 0) { bk.why = "not-lane: test"; return false; }
            std::uint64_t acc = 0; for (std::uint8_t x : blob) acc = acc * 131 + x;
            bk.credit.clear();
            bk.credit[smoke::key_of(static_cast<std::uint8_t>(1 + h % 3))] = static_cast<std::int64_t>(1'000'000'000ull + (acc % 1'000'000'000ull));
            bk.payout.clear();
            for (const auto& [k, a] : bk.credit) bk.payout[k] = a / 2;
            bk.total_pico = 0; for (const auto& [k, a] : bk.payout) { (void)k; bk.total_pico += static_cast<std::uint64_t>(a); }
            out.credits[bid] = std::to_string(bk.credit.begin()->second);
            return true;
        };
        fc = std::make_unique<o2::FinalizeConnect>(*node, cfg, q, o);
        (void)fc->reseed_after_bring_up();
    }
    std::uint64_t cursor() const { return node->finalize_driver().cursor_height(); }
    // main's serve-loop pass: report the frontier, pump the drained events, tick.
    void pass(Index& ix, Out& out) {
        const std::uint64_t t = ix.tip(), c = cursor();   // how far the DOWNLOAD ran ahead of the booking
        if (t > c && t - c > out.max_lead) out.max_lead = t - c;
        report_frontier(*ix.idx, cursor());
        (void)fc->tick();
        for (const auto& ev : ix.drain()) node->pump_mainchain_event(ev);
        report_frontier(*ix.idx, cursor());
    }
    void stop() { (void)fc->drain_before_stop(); fc.reset(); node->stop(); }
};

void finish(Index& ix, Proc& p, Out& out, const Chain& c, const std::map<std::uint64_t, int>& decided) {
    using namespace c2pool::v37n::xmr;
    out.cursor = p.cursor();
    out.late += p.fc->stats().late_unbooked;
    out.held += p.fc->stats().held_entered;
    out.refused += p.fc->stats().refused;
    out.rpc += p.rpc + p.src->stats().rpc_calls;
    out.native_unknown += native_unknown_of(p.node->gap_stats());
    out.replayed += replayed_of(p.fc->stats());
    out.digest = hex_of(p.node->ledger().owed_digest());
    for (std::uint64_t h = 5; h <= ix.net_tip; h += 5) if (p.node->ledger().is_settled(hex(c.ids[h]))) out.settled.insert(hex(c.ids[h]));
    out.dropped = out.lane_dropped = 0;
    for (std::uint64_t h = 1; h <= out.cursor; ++h)
        if (!decided.count(h)) { ++out.dropped; if (h % 5 == 0) ++out.lane_dropped; }
}

// ---- COLD-BOOT-3 probes ---------------------------------------------------------
template <class I> concept HasLifted = requires(const I& i) { i.consumer_pacing_lifted_why(); };
template <class I> std::string lifted_why(const I& i) {
    if constexpr (HasLifted<I>) return i.consumer_pacing_lifted_why();
    else { (void)i; return std::string(); }
}

void peer_sync(Index& ix) {
    nat::PeerRef p; p.peer_id = 7; p.addr = "127.0.0.1:1";
    nat::PeerSyncData d; d.current_height = ix.net_tip + 1; d.top_id = ix.c.ids[ix.net_tip]; d.top_version = 0;
    ix.idx->on_peer_sync_data(p, d);
}
// A live push of the network's new tip (fluffy/NOTIFY_NEW_BLOCK): never paced.
void push_tip(Index& ix) {
    nat::PeerRef p; p.peer_id = 7; p.addr = "127.0.0.1:1";
    ix.idx->on_new_block(p, BlockEntry(ix.c.blocks[ix.net_tip]), ix.net_tip + 1, false);
}
bool synced(const Index& ix) { return ix.idx->sync_state().synced; }

struct Follow {
    Out out;
    std::uint64_t tip_before = 0, net_before = 0;   // first process, at the stop
    std::uint64_t gap_tip = 0; bool gap_synced = false;   // first process, after a missed-push gap
    std::uint64_t tip = 0, net = 0, cursor = 0;     // after the restart / at the end
    bool synced_before = false, synced_end = false, held_end = false;
    std::uint64_t ceiling_end = 0, max_lead = 0;
    std::string lifted;
};

void print_follow(const char* tag, const Follow& f) {
    std::printf("  %-10s index_tip=%llu network_tip=%llu synced=%d consumer_held=%d ceiling=%llu cursor=%llu held_entered=%llu late=%llu "
                "undecided_at_or_below_cursor=%llu native_unknown=%llu max_lead=%llu lifted=\"%s\"\n",
                tag, (unsigned long long)f.tip, (unsigned long long)f.net, f.synced_end ? 1 : 0, f.held_end ? 1 : 0,
                (unsigned long long)f.ceiling_end, (unsigned long long)f.cursor, (unsigned long long)f.out.held,
                (unsigned long long)f.out.late, (unsigned long long)f.out.dropped, (unsigned long long)f.out.native_unknown,
                (unsigned long long)f.max_lead, f.lifted.c_str());
}

constexpr std::uint64_t X_HELD = 300;   // a lane block (300 % 5 == 0) that never becomes decidable

// F: held cursor, the tip runs past it, snapshot, restart while the network moves on.
Follow restart_follow(const Chain& c, const std::filesystem::path& dir) {
    Follow f; std::map<std::uint64_t, int> decided;
    auto hold = [](std::uint64_t h) { return h == X_HELD; };
    // NT1: pushes; NTG: a missed-push gap the first process must fetch (chain entry);
    // NT2: the network while the node is down (more than the window past the snapshot base).
    constexpr std::uint64_t NT0 = 400, NT1 = X_HELD + 2 * WINDOW + 300 /* 1112 */, NTG = NT1 + 60, NT2 = NTG + 400;
    auto ix = std::make_unique<Index>(c, NT0, 2048, 1024, WINDOW);
    peer_sync(*ix);
    for (int i = 0; i < 400 && ix->tip() < NT0 && !held(*ix->idx); ++i) if (ix->sync_round() == 0) break;
    std::vector<std::uint8_t> img;
    {
        Proc p(*ix, dir, f.out, decided, hold);
        for (int i = 0; i < 1500; ++i) {   // catch up to NT0; the cursor reaches the held block and stays
            (void)ix->sync_round(); peer_sync(*ix); p.pass(*ix, f.out);
            if (ix->tip() == NT0 && synced(*ix) && p.fc->stats().held_entered > 0) break;
        }
        while (ix->net_tip < NT1) {        // the network moves on, block by block (live pushes)
            ++ix->net_tip; push_tip(*ix); peer_sync(*ix); p.pass(*ix, f.out);
        }
        // a missed-push gap: the next 60 blocks are not pushed; the node must fetch them (chain entry)
        ix->net_tip = NTG; peer_sync(*ix);
        for (int i = 0; i < 60; ++i) { (void)ix->sync_round(); peer_sync(*ix); p.pass(*ix, f.out); }
        f.gap_tip = ix->tip(); f.gap_synced = synced(*ix);
        std::printf("  missed-push gap: index_tip=%llu network_tip=%llu synced=%d\n", (unsigned long long)f.gap_tip,
                    (unsigned long long)NTG, f.gap_synced ? 1 : 0);
        for (int i = 0; i < 20; ++i) p.pass(*ix, f.out);
        f.tip_before = ix->tip(); f.net_before = ix->net_tip; f.synced_before = synced(*ix);
        std::string why;
        if (!ix->idx->save_snapshot(img, why)) std::printf("  snapshot REFUSED: %s\n", why.c_str());
        f.out.late += p.fc->stats().late_unbooked;
        f.out.held += p.fc->stats().held_entered;
        std::printf("  first process stopped: cursor=%llu index_tip=%llu network_tip=%llu synced=%d (tip - cursor = %llu > 2 x window)\n",
                    (unsigned long long)p.cursor(), (unsigned long long)ix->tip(), (unsigned long long)ix->net_tip,
                    f.synced_before ? 1 : 0, (unsigned long long)(ix->tip() - p.cursor()));
        p.stop();
    }
    // restart from the snapshot; the network moved on while the node was down
    ix = std::make_unique<Index>(c, NT2, 2048, 1024, WINDOW);
    std::string why;
    if (!ix->idx->load_snapshot(img, why)) std::printf("  snapshot LOAD failed: %s\n", why.c_str());
    (void)ix->drain();
    std::printf("  restart: resumed index tip=%llu, network tip=%llu\n", (unsigned long long)ix->tip(), (unsigned long long)NT2);
    peer_sync(*ix);
    Proc p(*ix, dir, f.out, decided, hold);
    for (int i = 0; i < 1500; ++i) {
        (void)ix->sync_round(); peer_sync(*ix); p.pass(*ix, f.out);
        if (ix->tip() == NT2 && synced(*ix) && i > 200) break;
    }
    Out tmp; finish(*ix, p, tmp, c, decided);
    f.out.late += tmp.late; f.out.held += tmp.held; f.out.dropped = tmp.dropped; f.out.native_unknown = tmp.native_unknown;
    f.tip = ix->tip(); f.net = NT2; f.cursor = p.cursor(); f.synced_end = synced(*ix); f.held_end = held(*ix->idx);
    f.ceiling_end = ix->idx->consumer_ceiling(); f.lifted = lifted_why(*ix->idx);
    p.stop();
    return f;
}

// P: a fresh cold boot whose cursor is held from the start (or not: C1).
Follow fresh_follow(const Chain& c, bool hold_x, const std::filesystem::path& dir) {
    Follow f; std::map<std::uint64_t, int> decided;
    auto hold = [hold_x](std::uint64_t h) { return hold_x && h == X_HELD; };
    constexpr std::uint64_t NT = 1400;
    Index ix(c, NT, 2048, 1024, WINDOW);
    peer_sync(ix);
    for (int i = 0; i < 400 && ix.tip() < NT && !held(*ix.idx); ++i) if (ix.sync_round() == 0) break;
    Proc p(ix, dir, f.out, decided, hold);
    bool was_synced = false;
    for (int i = 0; i < 2500; ++i) {
        (void)ix.sync_round(); peer_sync(ix);
        if (!was_synced) { const std::uint64_t t = ix.tip(), cu = p.cursor(); if (t > cu && t - cu > f.max_lead) f.max_lead = t - cu; }
        p.pass(ix, f.out);
        if (synced(ix)) was_synced = true;
        if (ix.tip() == NT && synced(ix) && (hold_x ? p.fc->stats().held_entered > 0 : p.cursor() >= NT - DCONF)) break;
    }
    finish(ix, p, f.out, c, decided);
    f.tip = ix.tip(); f.net = NT; f.cursor = p.cursor(); f.synced_end = synced(ix); f.held_end = held(*ix.idx);
    f.ceiling_end = ix.idx->consumer_ceiling(); f.lifted = lifted_why(*ix.idx);
    p.stop();
    return f;
}

} // namespace

int main() {
    std::error_code ec;
    const std::filesystem::path base = std::filesystem::is_directory("/dev/shm", ec) && ::access("/dev/shm", W_OK) == 0
                                           ? std::filesystem::path("/dev/shm") : std::filesystem::temp_directory_path();
    std::filesystem::path tmp = base / ("v37-xmr-coldboot3-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::printf("== v37_xmr_coldboot_follow_kat ==\n");
    const Chain c;

    std::printf("-- F: cursor HELD at lane block %llu, tip runs > 2 x %llu past it (pushes, then a missed-push gap), snapshot, restart (network +400) --\n",
                (unsigned long long)X_HELD, (unsigned long long)WINDOW);
    const Follow F = restart_follow(c, tmp / "restart");
    print_follow("restart", F);
    const std::uint64_t HELD_CURSOR = X_HELD - DCONF - 1;
    check("F0 rig: the first process followed the pushed tip > 2 x window past the held cursor",
          F.tip_before >= X_HELD + 2 * WINDOW + 300 && F.tip_before > HELD_CURSOR + 2 * WINDOW,
          "tip=" + std::to_string(F.tip_before));
    check("F5 missed-push gap in the running process (cursor held): the node fetches the gap and stays synced",
          F.gap_tip == F.net_before && F.gap_synced && F.synced_before,
          "index_tip=" + std::to_string(F.gap_tip) + " network_tip=" + std::to_string(F.net_before) + " synced=" + std::to_string(F.gap_synced));
    check("F1 restart: the node KEEPS FOLLOWING -- index tip == network tip and the index is synced (template arm possible)",
          F.tip == F.net && F.synced_end && !F.held_end,
          "index_tip=" + std::to_string(F.tip) + " network_tip=" + std::to_string(F.net) + " synced=" + std::to_string(F.synced_end) +
          " consumer_held=" + std::to_string(F.held_end));
    check("F2 restart: the catch-up pacing is LIFTED for the process, with a reason (never a silent stall)",
          !F.lifted.empty() && F.ceiling_end == 0, "lifted=\"" + F.lifted + "\" ceiling=" + std::to_string(F.ceiling_end));
    check("F3 restart: the cursor is still HELD at the undecidable block (HOLD alarm kept), never walked over it",
          F.cursor == HELD_CURSOR && F.out.held > 0, "cursor=" + std::to_string(F.cursor) + " held_entered=" + std::to_string(F.out.held));
    check("F4 restart: 0 late_unbooked, 0 heights at/below the cursor left undecided (0 silent drops)",
          F.out.late == 0 && F.out.dropped == 0, "late=" + std::to_string(F.out.late) + " undecided=" + std::to_string(F.out.dropped));

    std::printf("-- P: a FRESH cold boot whose cursor is held from the start (network tip 1400) --\n");
    const Follow P = fresh_follow(c, true, tmp / "fresh-held");
    print_follow("fresh-held", P);
    check("P1 fresh boot, held cursor: after the stall bound the node follows the network tip and is synced",
          P.tip == P.net && P.synced_end && !P.lifted.empty(),
          "index_tip=" + std::to_string(P.tip) + " network_tip=" + std::to_string(P.net) + " synced=" + std::to_string(P.synced_end) +
          " lifted=\"" + P.lifted + "\"");
    check("P2 fresh boot, held cursor: the cursor stays HELD at the undecidable block (alarm), 0 late, 0 undecided at/below it",
          P.cursor == HELD_CURSOR && P.out.held > 0 && P.out.late == 0 && P.out.dropped == 0,
          "cursor=" + std::to_string(P.cursor) + " late=" + std::to_string(P.out.late) + " undecided=" + std::to_string(P.out.dropped));

    std::printf("-- C: the COLD-BOOT-2 pacing is kept for an ordinary catch-up (nothing held) --\n");
    const Follow C = fresh_follow(c, false, tmp / "fresh");
    print_follow("fresh", C);
    check("C1 unheld cold boot: paced until synced (download never > window + D_conf + 1 above the cursor), then books to the frontier, 0 late, 0 undecided",
          C.max_lead <= WINDOW + DCONF + 1 && C.synced_end && C.cursor >= C.net - DCONF && C.out.late == 0 && C.out.dropped == 0,
          "max_lead=" + std::to_string(C.max_lead) + " cursor=" + std::to_string(C.cursor) + " lifted=\"" + C.lifted + "\"");

    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
