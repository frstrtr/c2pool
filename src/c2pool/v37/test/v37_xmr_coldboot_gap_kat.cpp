// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_coldboot_gap_kat.cpp   (COLD-BOOT-2)
//
// COLD-BOOT part 1 made an EVICTED body come back (levin refetch). The verify
// of a fresh boot from an old anchor found three more ways the post-anchor gap
// is lost; this KAT pins all three with the REAL ChainIndex at the SHIPPED
// bounds (2048 rows, 1024 bodies) and a 3000-block gap:
//
//   G1-G4  D2, the gap is booked AS it downloads. A simulated sync driver feeds
//          the index exactly what refetch_wanted() hands out (chain entry ->
//          GET_OBJECTS), the node's mainchain events are pumped into
//          FinalizeConnect from the serve loop, and main's wiring reports the
//          finalize cursor to the index every pass. Pre-fix the whole gap was
//          downloaded first: rows older than tip - 2048 were trimmed, the
//          canonical test answered No and drain_bookings DROPPED the retried /
//          deferred blocks (lane blocks among them) silently. Fixed: 0 dropped,
//          every block decided once in ascending height, owed_digest / settled
//          set / credits identical to an uninterrupted reference, 0 late.
//   H1-H2  D2, the backstop. The same download-everything-first shape (pacing
//          off): a block whose row was trimmed before it was booked HOLDS
//          (Unknown, alarm counted) -- the cursor never walks over it and nothing
//          at or below the cursor is undecided. Pre-fix: silently dropped.
//   S0-S2  D4a, the snapshot after a cold boot. A burst of re-cached old bodies
//          (the part-1 booking refetch) used to evict every tip-side body, and
//          save_snapshot then refused ("the body of block N is not retained")
//          until 64 new blocks had connected. Fixed: the top snapshot_depth + 1
//          best-chain bodies are pinned, the save succeeds at full depth.
//   R1-R4  D4b, restart after a cold boot. A held lane block keeps the cursor
//          below the high-water; the node stops; a new process resumes the
//          store. Pre-fix the first tick re-advanced the cursor to hw - D_conf
//          (the in-memory deferred set died with the process) and every block
//          in between came back late_unbooked. Fixed, for both restart shapes
//          (re-walk from the anchor; snapshot resume, no re-delivered events):
//          the cursor continues from the recovered one, 0 late_unbooked, and
//          the final ledger equals an uninterrupted reference.
//
// The same file builds against the pre-fix tree (the new surfaces are probed
// with `requires`), where G1/G3/H1/S1/R2/R4 FAIL. Network-free, RandomX-free.
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

// The uninterrupted reference: bodies and rows never evicted, the whole chain
// downloaded, every event pumped in order, ticked to the frontier.
Out reference_run(const Chain& c, std::uint64_t net_tip, const std::filesystem::path& dir) {
    Out out; std::map<std::uint64_t, int> decided;
    Index ix(c, net_tip, 8192, 8192, 0);
    while (ix.tip() < net_tip) if (ix.sync_round() == 0) break;
    Proc p(ix, dir, out, decided, {});
    for (int i = 0; i < 4000 && p.cursor() < net_tip - DCONF; ++i) p.pass(ix, out);
    finish(ix, p, out, c, decided);
    p.stop();
    return out;
}

// A fresh cold boot at the SHIPPED bounds. `window` = the catch-up pacing (0 = off).
Out coldboot_run(const Chain& c, std::uint64_t window, const std::filesystem::path& dir) {
    Out out; std::map<std::uint64_t, int> decided;
    Index ix(c, GAP, 2048, 1024, window);
    // start_and_wait: download until synced -- or, with pacing, until the download is held at the ceiling.
    for (int i = 0; i < 400 && ix.tip() < GAP && !held(*ix.idx); ++i) if (ix.sync_round() == 0) break;
    Proc p(ix, dir, out, decided, {});
    std::uint64_t last = ~0ull; int still = 0;
    for (int i = 0; i < 4000 && p.cursor() < GAP - DCONF; ++i) {
        (void)ix.sync_round();
        p.pass(ix, out);
        if (p.cursor() == last && ix.tip() == GAP) { if (++still >= 150) break; }   // a held block: no progress possible
        else still = 0;
        last = p.cursor();
    }
    finish(ix, p, out, c, decided);
    p.stop();
    return out;
}

void print(const char* tag, const Out& o) {
    std::printf("  %-9s cursor=%llu decided=%zu dropped=%llu (lane %llu) order=%s late=%llu held=%llu refused=%llu native_unknown=%llu rpc=%llu max_lead=%llu replayed=%llu digest=%s\n",
                tag, (unsigned long long)o.cursor, o.decided_order.size(), (unsigned long long)o.dropped, (unsigned long long)o.lane_dropped,
                o.order_ok ? "ascending" : "OUT-OF-ORDER", (unsigned long long)o.late, (unsigned long long)o.held, (unsigned long long)o.refused,
                (unsigned long long)o.native_unknown, (unsigned long long)o.rpc, (unsigned long long)o.max_lead, (unsigned long long)o.replayed,
                o.digest.substr(0, 16).c_str());
}

void gap_cases(const Chain& c, const std::filesystem::path& tmp) {
    std::printf("-- G/H: a %llu-block post-anchor gap at the shipped bounds (2048 rows, 1024 bodies), D_conf=%llu --\n",
                (unsigned long long)GAP, (unsigned long long)DCONF);
    const Out R = reference_run(c, GAP, tmp / "ref");
    const Out P = coldboot_run(c, WINDOW, tmp / "paced");
    const Out L = coldboot_run(c, 0, tmp / "legacy");
    print("reference", R); print("paced", P); print("legacy", L);
    const std::uint64_t frontier = GAP - DCONF;
    check("G0 reference (never evicted, never trimmed): cursor at the frontier, every height decided in order, 0 late",
          R.cursor == frontier && R.dropped == 0 && R.order_ok && R.late == 0 && R.settled.size() == frontier / 5);
    check("G1 paced cold boot: 0 blocks dropped (0 lane blocks), every height 1..frontier decided, cursor at the frontier",
          P.cursor == frontier && P.dropped == 0 && P.lane_dropped == 0 && P.decided_order.size() >= frontier,
          "cursor=" + std::to_string(P.cursor) + " dropped=" + std::to_string(P.dropped) + " lane_dropped=" + std::to_string(P.lane_dropped));
    check("G2 paced: booked in ascending chain order, 0 late_unbooked, 0 held, 0 refused, 0 monerod calls",
          P.order_ok && P.late == 0 && P.held == 0 && P.refused == 0 && P.rpc == 0);
    check("G3 paced: owed_digest, settled set and per-block credits IDENTICAL to the uninterrupted reference",
          P.digest == R.digest && P.settled == R.settled && P.credits == R.credits,
          "digest " + P.digest.substr(0, 16) + " vs " + R.digest.substr(0, 16) + " settled " + std::to_string(P.settled.size()) + "/" + std::to_string(R.settled.size()));
    check("G4 paced: the download never ran further than the window above the finalize cursor (bounded batches)",
          P.max_lead <= WINDOW + DCONF + 1, "max_lead=" + std::to_string(P.max_lead));
    check("H1 legacy download-everything-first shape: NOTHING is dropped silently -- every height at/below the cursor was decided",
          L.dropped == 0 && L.lane_dropped == 0, "dropped=" + std::to_string(L.dropped) + " lane_dropped=" + std::to_string(L.lane_dropped));
    check("H2 legacy: a block whose row was trimmed before booking HOLDS (Unknown, alarm counted); the cursor stops below it; 0 late",
          L.native_unknown > 0 && L.cursor < frontier && L.late == 0,
          "native_unknown=" + std::to_string(L.native_unknown) + " cursor=" + std::to_string(L.cursor));
}

void snapshot_cases(const Chain& c) {
    std::printf("-- S: the snapshot after a cold-boot refetch burst (1024 bodies, snapshot_depth 64) --\n");
    Index ix(c, GAP, 4096, 1024, 0);
    while (ix.tip() < GAP) if (ix.sync_round() == 0) break;
    auto depth_of = [](const std::vector<std::uint8_t>& img) -> std::uint64_t {
        if (img.size() < 80) return ~0ull;
        std::uint64_t d = 0; for (int i = 0; i < 8; ++i) d |= std::uint64_t(img[72 + i]) << (8 * i);
        return d;
    };
    std::vector<std::uint8_t> img0; std::string why0;
    const bool ok0 = ix.idx->save_snapshot(img0, why0);
    check("S0 rig: before the burst the snapshot is written at full depth (64 bodies above its base)",
          ok0 && depth_of(img0) == 64, ok0 ? "depth=" + std::to_string(depth_of(img0)) : why0);
    // The part-1 booking refetch: the booking walks the gap from the anchor and
    // asks every evicted body back; each one re-enters the cache as its NEWEST entry.
    std::size_t restored = 0;
    for (std::uint64_t h = 1; h <= 1500; h += 64) {
        (void)want_back(*ix.idx, c.ids[h]);
        for (int r = 0; r < 2; ++r) restored += ix.sync_round();
    }
    std::vector<std::uint8_t> img1; std::string why1;
    const bool ok1 = ix.idx->save_snapshot(img1, why1);
    check("S1 after the refetch burst the snapshot is STILL written at full depth (tip-side bodies pinned)",
          ok1 && depth_of(img1) == 64, ok1 ? "depth=" + std::to_string(depth_of(img1)) + " restored=" + std::to_string(restored)
                                           : "REFUSED: " + why1 + " (restored=" + std::to_string(restored) + ")");
    std::vector<std::uint8_t> tipb;
    check("S2 the tip body is held and the old restored bodies are still served (bounded cache, nothing else lost)",
          ix.idx->block_blob_of(c.ids[GAP], tipb) && restored > 0);
}

// D4b: a held lane block keeps the cursor below the high-water; stop; restart.
Out restart_run(const Chain& c, std::uint64_t net_tip, bool rewalk, const std::filesystem::path& dir) {
    Out out; std::map<std::uint64_t, int> decided;
    const std::uint64_t X = 600;   // lane block (600 % 5 == 0) held in the first process
    bool holding = true;
    auto hold = [&](std::uint64_t h) { return holding && h == X; };
    auto ix = std::make_unique<Index>(c, net_tip, 2048, 1024, WINDOW);
    for (int i = 0; i < 400 && ix->tip() < net_tip && !held(*ix->idx); ++i) if (ix->sync_round() == 0) break;
    {
        Proc p(*ix, dir, out, decided, hold);
        for (int i = 0; i < 3000; ++i) {
            (void)ix->sync_round();
            p.pass(*ix, out);
            if (p.cursor() == X - DCONF - 1 && p.node->hw().hw_height >= X + 64) break;
        }
        out.restart_cursor = p.cursor();
        out.late += p.fc->stats().late_unbooked;
        std::printf("  first process stopped: cursor=%llu hw=%llu index_tip=%llu\n", (unsigned long long)p.cursor(),
                    (unsigned long long)p.node->hw().hw_height, (unsigned long long)ix->tip());
        p.stop();
    }
    holding = false;   // the operator cleared it (or the fix that decides it landed)
    if (rewalk) {
        ix = std::make_unique<Index>(c, net_tip, 2048, 1024, WINDOW);   // no snapshot: re-walk from the anchor
        for (int i = 0; i < 400 && ix->tip() < net_tip && !held(*ix->idx); ++i) if (ix->sync_round() == 0) break;
    } else {
        (void)ix->drain();   // snapshot resume: the index keeps its chain, re-raises NO event for it
    }
    Proc p(*ix, dir, out, decided, hold);
    p.pass(*ix, out);
    out.first_tick_cursor = p.cursor();
    for (std::uint64_t h = 1; h <= out.first_tick_cursor; ++h) if (!decided.count(h)) ++out.first_tick_undecided;
    for (int i = 0; i < 4000 && p.cursor() < net_tip - DCONF; ++i) { (void)ix->sync_round(); p.pass(*ix, out); }
    finish(*ix, p, out, c, decided);
    p.stop();
    return out;
}

void restart_cases(const Chain& c, const std::filesystem::path& tmp) {
    constexpr std::uint64_t NT = 1200;
    std::printf("-- R: restart after a cold boot (held lane block at 600, %llu-block chain) --\n", (unsigned long long)NT);
    const Out R  = reference_run(c, NT, tmp / "rref");
    const Out W  = restart_run(c, NT, /*rewalk=*/true,  tmp / "rewalk");
    const Out S  = restart_run(c, NT, /*rewalk=*/false, tmp / "resume");
    print("reference", R); print("re-walk", W); print("resume", S);
    std::printf("  re-walk: recovered cursor=%llu first-tick cursor=%llu | resume: recovered=%llu first-tick=%llu (undecided at/below: %llu / %llu)\n",
                (unsigned long long)W.restart_cursor, (unsigned long long)W.first_tick_cursor,
                (unsigned long long)S.restart_cursor, (unsigned long long)S.first_tick_cursor,
                (unsigned long long)W.first_tick_undecided, (unsigned long long)S.first_tick_undecided);
    check("R1 rig: the first process stopped with the cursor held below the lane block (600 - D_conf - 1) and the high-water above it",
          W.restart_cursor == 600 - DCONF - 1 && S.restart_cursor == 600 - DCONF - 1);
    check("R2 restart: the cursor CONTINUES from the recovered one -- after the first tick no height at/below it is undecided (no jump to hw - D_conf), both shapes",
          W.first_tick_undecided == 0 && S.first_tick_undecided == 0,
          "re-walk first tick=" + std::to_string(W.first_tick_cursor) + " undecided=" + std::to_string(W.first_tick_undecided) +
          " | resume first tick=" + std::to_string(S.first_tick_cursor) + " undecided=" + std::to_string(S.first_tick_undecided));
    check("R3 restart: 0 late_unbooked, 0 dropped, cursor at the frontier, 0 monerod calls, both shapes",
          W.late == 0 && S.late == 0 && W.dropped == 0 && S.dropped == 0 && W.cursor == NT - DCONF && S.cursor == NT - DCONF && W.rpc == 0 && S.rpc == 0,
          "late " + std::to_string(W.late) + "/" + std::to_string(S.late) + " dropped " + std::to_string(W.dropped) + "/" + std::to_string(S.dropped));
    check("R4 restart: owed_digest, settled set and credits IDENTICAL to the uninterrupted reference, both shapes",
          W.digest == R.digest && S.digest == R.digest && W.settled == R.settled && S.settled == R.settled &&
          W.credits == R.credits && S.credits == R.credits,
          "digest " + W.digest.substr(0, 16) + " / " + S.digest.substr(0, 16) + " vs " + R.digest.substr(0, 16));
}

} // namespace

int main() {
    std::error_code ec;
    const std::filesystem::path base = std::filesystem::is_directory("/dev/shm", ec) && ::access("/dev/shm", W_OK) == 0
                                           ? std::filesystem::path("/dev/shm") : std::filesystem::temp_directory_path();
    std::filesystem::path tmp = base / ("v37-xmr-coldboot2-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::printf("== v37_xmr_coldboot_gap_kat ==\n");
    const Chain c;
    gap_cases(c, tmp);
    snapshot_cases(c);
    restart_cases(c, tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
