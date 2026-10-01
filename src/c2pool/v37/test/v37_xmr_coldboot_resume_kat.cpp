// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_coldboot_resume_kat.cpp   (COLD-BOOT-4)
//
// The read-only mainnet dry run (09-25) found two cold-boot holes, COLD-BOOT-3's
// verify a third. Pinned with the REAL ChainIndex at the shipped bounds (2048
// rows, 1024 bodies, window 256) and the real XmrNode + FinalizeConnect:
//
//   B1-B2  the pinned default boot (output set, no --native-anchor) got NO
//          catch-up pacing (the predicate tested the anchor PATH). Fixed: one
//          predicate, the boot mode -- pinned and explicit anchor boots alike.
//   A0-A2  a restart whose finalize cursor lies below the f2 anchor (the span a
//          fresh boot seeds past; mainnet: cursor 3765808, anchor 3765865) could
//          never re-drive: row cursor + 1 is not held by any index booted from
//          that anchor -> "gap-redrive ALARM (native)" forever. Fixed: the resumed
//          scan starts at the anchor, as the fresh boot's did.
//   T0-T2  a restart whose cursor lags below the retained rows (held > 2048
//          blocks): the trimmed rows were gone. Fixed: the booking tail (ids of
//          trimmed, unbooked rows; bounded, loud past the bound) is kept and
//          snapshotted; the restart re-drives from its cursor.
//   R1-R3  (COLD-BOOT-3 verify R2) a resume whose cursor lags the snapshot tip
//          by > window lifted the pacing for the whole process. Fixed: it stays
//          paced until the cursor catches up, then lifts (synced).
//
// Builds on the pre-fix tree (new surfaces probed with `requires`), where B1,
// A1, T1 and R1-R2 FAIL. Network-free, RandomX-free. Nonzero exit on failure.
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
#include "c2pool/v37/xmr/xmr_native_template_backend.hpp"

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

constexpr std::uint64_t GAP    = 3000;
constexpr std::uint64_t WINDOW = 256;    // the shipped --native-catchup-window

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

// ---- COLD-BOOT-4 probes (absent on the pre-fix tree) -----------------------------
template <class I> concept HasTailId = requires(const I& i) { i.canonical_id_at(std::uint64_t{1}); };
template <class N> concept HasFloor  = requires(N& n) { n.floor_resumed_scan(std::uint64_t{1}); };
template <class I> std::optional<Hash> id_at(const I& ix, std::uint64_t h) {
    if constexpr (HasTailId<I>) return ix.canonical_id_at(h);
    else { const auto b = ix.by_height(h); if (!b) return std::nullopt; return b->id; }
}
template <class N> bool floor_scan(N& n, std::uint64_t a) {
    if constexpr (HasFloor<N>) return n.floor_resumed_scan(a);
    else { (void)n; (void)a; return false; }
}
template <class I> std::uint64_t tail_kept(const I& ix) {
    if constexpr (HasTailId<I>) return ix.booking_tail_stats().kept;
    else { (void)ix; return 0; }
}
template <class I> std::string lifted_why(const I& i) { return i.consumer_pacing_lifted_why(); }

// A REAL index behind a simulated sync driver (the follow KAT's shape), booted at
// genesis or from an ANCHOR row A > 0 (no rows below A, as an f2 anchor boot).
struct Index {
    ModelVerifier mv;
    nat::LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions opts;
    std::unique_ptr<ChainIndex> idx;
    std::vector<c2pool::xmr::node::MainchainEvent> queue;
    const Chain& c;
    std::uint64_t net_tip;
    Index(const Chain& ch, std::uint64_t network_tip, std::uint64_t anchor = 0) : c(ch), net_tip(network_tip) {
        opts.net = nat::XmrNet::Regtest;
        opts.require_pow = false;
        opts.row_retention = 2048;
        opts.entry_cache = 1024;
        opts.consumer_window = WINDOW;
        idx = std::make_unique<ChainIndex>(opts, src);
        idx->subscribe([this](const c2pool::xmr::node::MainchainEvent& ev) { queue.push_back(ev); });
        const nat::ChainRow g = genesis_row();
        if (anchor == 0) {
            idx->seed_direct(g, {nat::DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                             {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
            return;
        }
        // The anchor bundle's numbers, read off a scratch index that connected 0..A.
        ChainIndex tmp(opts, src);
        tmp.seed_direct(g, {nat::DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                        {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
        for (std::uint64_t h = 1; h <= anchor; ++h) (void)tmp.offer_block(nullptr, BlockEntry(c.blocks[h]), false);
        const auto& rows = tmp.view().state().rows();
        std::vector<nat::DifficultyRow> dw; std::vector<std::uint64_t> st, lt, ts;
        for (const auto& r : rows) { dw.push_back(nat::DifficultyRow{r.timestamp, r.cumulative_difficulty}); st.push_back(r.block_weight);
                                     lt.push_back(r.long_term_weight); ts.push_back(r.timestamp); }
        if (st.size() > 100) st.erase(st.begin(), st.end() - 100);
        if (ts.size() > 60) ts.erase(ts.begin(), ts.end() - 60);
        idx->seed_direct(*tmp.view().state().tip(), dw, st, lt, ts, {{0, g.id}});
    }
    std::uint64_t tip() const { const auto t = idx->tip(); return t ? t->height : 0; }
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
        for (const Hash& id : idx->bodies_wanted()) {   // the booking refetch (re-ask by id)
            auto it = c.by_id.find(id);
            if (it == c.by_id.end()) continue;
            (void)idx->offer_block(nullptr, c.blocks[it->second], false);
            if (++b >= 64) break;
        }
        return n + b;
    }
    std::vector<c2pool::xmr::node::MainchainEvent> drain() { std::vector<c2pool::xmr::node::MainchainEvent> o; o.swap(queue); return o; }
};

void peer_sync(Index& ix) {
    nat::PeerRef p; p.peer_id = 7; p.addr = "127.0.0.1:1";
    nat::PeerSyncData d; d.current_height = ix.net_tip + 1; d.top_id = ix.c.ids[ix.net_tip]; d.top_version = 0;
    ix.idx->on_peer_sync_data(p, d);
}
bool synced(const Index& ix) { return ix.idx->sync_state().synced; }

// One settlement process, main's order: bring_up -> the cold-boot block (fresh seed
// or, COLD-BOOT-4, the resumed pre-anchor floor) -> FinalizeConnect + reseed.
struct Proc {
    c2pool::xmr::node::MockMonerodTransport mock;
    c2pool::v37n::xmr::XmrNodeConfig cfg;
    std::unique_ptr<c2pool::v37n::xmr::XmrNode> node;
    std::unique_ptr<o2::CbaBlockSource> src;
    o2::FoundBlockQueue q;
    std::unique_ptr<o2::FinalizeConnect> fc;
    std::map<std::uint64_t, int>& decided;
    std::uint64_t rpc = 0;
    Proc(Index& ix, const std::filesystem::path& dir, std::uint64_t dconf, std::uint64_t anchor,
         std::map<std::uint64_t, int>& dec, const std::function<bool(std::uint64_t)>& hold) : decided(dec) {
        using namespace c2pool::v37n::xmr;
        cfg.network = MoneroNetwork::Stagenet;
        cfg.lane_chain = 7;
        cfg.d_conf = dconf;
        cfg.arm_order = ArmOrderMode::P2PFirst;
        cfg.settle_db_path = dir.string();
        std::filesystem::create_directories(dir);
        node = std::make_unique<XmrNode>(cfg, mock, &smoke::test_point_check);
        ChainIndex* I = ix.idx.get();
        // main's chain source: is_canonical / bid_at
        node->set_native_chain_presence([I](std::uint64_t h, const std::string& bid) {
            const auto id = id_at(*I, h); return id.has_value() && hex(*id) == bid; });
        node->set_native_row_lookup([I](std::uint64_t h) -> std::optional<std::string> {
            const auto id = id_at(*I, h); if (!id) return std::nullopt; return hex(*id); });
        node->set_native_tip_lookup([I]() -> std::uint64_t { const auto t = I->tip(); return t ? t->height : 0; });
        node->bring_up();
        if (anchor > dconf && !node->seed_fresh_cursor(anchor - dconf)) (void)floor_scan(*node, anchor);
        src = std::make_unique<o2::CbaBlockSource>(
            [I](const std::string& bid, std::vector<std::uint8_t>& blob) {
                Hash id{}; if (!id_of_hex(bid, id)) return false;
                return I->block_blob_of(id, blob);
            },
            [this](const std::string&, std::vector<std::uint8_t>&, std::string& why) { ++rpc; why = "get_block: test (must not be called)"; return false; });
        src->set_refetch([I](const std::string& bid) { Hash id{}; if (id_of_hex(bid, id)) (void)I->want_body_for_booking(id, 64); }, 120);
        o2::FinalizeConnectOptions o;
        o.out = nullptr;
        o.sidecar_path = (dir / "pfound.tsv").string();
        o.retry_bound = 40; o.held_retry_every = 5;
        o.book_from_chain_ex = [this, hold](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) {
            if (hold && hold(h)) { bk.why = "native-hold: test (an undecidable block the operator has not cleared yet)"; return false; }
            std::vector<std::uint8_t> blob;
            if (!src->fetch(bid, blob, bk.why)) return false;
            ++decided[h];
            if (h % 5 != 0) { bk.why = "not-lane: test"; return false; }
            std::uint64_t acc = 0; for (std::uint8_t x : blob) acc = acc * 131 + x;
            bk.credit.clear();
            bk.credit[smoke::key_of(static_cast<std::uint8_t>(1 + h % 3))] = static_cast<std::int64_t>(1'000'000'000ull + (acc % 1'000'000'000ull));
            bk.payout.clear();
            for (const auto& [k, a] : bk.credit) bk.payout[k] = a / 2;
            bk.total_pico = 0; for (const auto& [k, a] : bk.payout) { (void)k; bk.total_pico += static_cast<std::uint64_t>(a); }
            return true;
        };
        fc = std::make_unique<o2::FinalizeConnect>(*node, cfg, q, o);
        (void)fc->reseed_after_bring_up();
    }
    std::uint64_t cursor() const { return node->finalize_driver().cursor_height(); }
    void pass(Index& ix) {
        ix.idx->set_consumer_frontier(cursor());
        (void)fc->tick();
        for (const auto& ev : ix.drain()) node->pump_mainchain_event(ev);
        ix.idx->set_consumer_frontier(cursor());
    }
    void stop() { (void)fc->drain_before_stop(); fc.reset(); node->stop(); }
};

struct Run {
    std::uint64_t stop_cursor = 0, stop_tip = 0;              // first process, at the stop
    std::uint64_t resumed_tip = 0;                            // restart
    std::string   lifted_first; std::uint64_t ceiling_first = 0;   // restart, after the first report
    std::uint64_t unpaced = 0;          // restart: rounds that downloaded above max(resumed tip, cursor + window)
    std::uint64_t cursor = 0, tip = 0, net = 0, late = 0, fetch_failed = 0, undecided = 0, lane_undecided = 0, held_end = 0;
    std::string   lifted_end; bool synced_end = false;
    std::uint64_t tail_kept_at_stop = 0;
};

// Process 1 holds the cursor at `x_hold` (an undecidable block) until the pacing
// stall latch lets the tip run to `nt1`; clean stop + snapshot; process 2 resumes
// on the same store with the hold RELEASED while the network is at `nt2`.
Run restart(const Chain& c, const std::filesystem::path& dir, std::uint64_t anchor, std::uint64_t dconf,
            std::uint64_t x_hold, std::uint64_t nt1, std::uint64_t nt2) {
    Run R; std::map<std::uint64_t, int> decided;
    std::vector<std::uint8_t> img;
    {
        Index ix(c, nt1, anchor);
        peer_sync(ix);
        auto hold = [x_hold](std::uint64_t h) { return h == x_hold; };
        Proc p(ix, dir, dconf, anchor, decided, hold);
        for (int i = 0; i < 4000; ++i) {
            (void)ix.sync_round(); peer_sync(ix); p.pass(ix);
            if (ix.tip() == nt1 && synced(ix) && p.fc->stats().held_entered > 0) break;
        }
        for (int i = 0; i < 20; ++i) p.pass(ix);
        R.stop_cursor = p.cursor(); R.stop_tip = ix.tip();
        R.tail_kept_at_stop = tail_kept(*ix.idx);
        std::string why;
        if (!ix.idx->save_snapshot(img, why)) std::printf("  snapshot REFUSED: %s\n", why.c_str());
        R.late += p.fc->stats().late_unbooked;
        p.stop();
    }
    Index ix(c, nt2, anchor);
    std::string why;
    if (!ix.idx->load_snapshot(img, why)) std::printf("  snapshot LOAD failed: %s\n", why.c_str());
    (void)ix.drain();
    R.resumed_tip = ix.tip();
    peer_sync(ix);
    Proc p(ix, dir, dconf, anchor, decided, nullptr);
    ix.idx->set_consumer_frontier(p.cursor());
    R.lifted_first = lifted_why(*ix.idx); R.ceiling_first = ix.idx->consumer_ceiling();
    bool was_synced = false;
    for (int i = 0; i < 6000; ++i) {
        const std::uint64_t c0 = p.cursor();
        (void)ix.sync_round(); peer_sync(ix);
        if (!was_synced && ix.tip() > R.resumed_tip && ix.tip() > c0 + WINDOW) ++R.unpaced;
        if (synced(ix)) was_synced = true;
        p.pass(ix);
        if (ix.tip() == nt2 && synced(ix) && p.cursor() >= nt2 - dconf) break;
    }
    R.cursor = p.cursor(); R.tip = ix.tip(); R.net = nt2;
    R.late += p.fc->stats().late_unbooked;
    R.fetch_failed = p.node->gap_stats().fetch_failed;
    R.held_end = p.fc->stats().held_entered;
    R.lifted_end = lifted_why(*ix.idx); R.synced_end = synced(ix);
    for (std::uint64_t h = anchor + 1; h <= R.cursor; ++h)
        if (!decided.count(h)) { ++R.undecided; if (h % 5 == 0) ++R.lane_undecided; }
    p.stop();
    return R;
}

void print_run(const char* tag, const Run& r) {
    std::printf("  %-8s stop: cursor=%llu tip=%llu tail_kept=%llu | restart: resumed_tip=%llu first_report{lifted=\"%s\" ceiling=%llu} unpaced_rounds=%llu"
                " | end: cursor=%llu tip=%llu net=%llu synced=%d late_unbooked=%llu fetch_failed=%llu undecided=%llu (lane %llu) lifted=\"%s\"\n",
                tag, (unsigned long long)r.stop_cursor, (unsigned long long)r.stop_tip, (unsigned long long)r.tail_kept_at_stop,
                (unsigned long long)r.resumed_tip, r.lifted_first.c_str(), (unsigned long long)r.ceiling_first, (unsigned long long)r.unpaced,
                (unsigned long long)r.cursor, (unsigned long long)r.tip, (unsigned long long)r.net, r.synced_end ? 1 : 0,
                (unsigned long long)r.late, (unsigned long long)r.fetch_failed, (unsigned long long)r.undecided,
                (unsigned long long)r.lane_undecided, r.lifted_end.c_str());
}

} // namespace

int main() {
    std::error_code ec;
    const std::filesystem::path base = std::filesystem::is_directory("/dev/shm", ec) && ::access("/dev/shm", W_OK) == 0
                                           ? std::filesystem::path("/dev/shm") : std::filesystem::temp_directory_path();
    std::filesystem::path tmp = base / ("v37-xmr-coldboot4-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::printf("== v37_xmr_coldboot_resume_kat ==\n");

    // ---- B: one pacing predicate for every anchor boot -----------------------------
    {
        using namespace c2pool::v37n::xmr;
        auto mk = [](ArmOrderMode order, const std::string& anchor, const std::string& outset, bool solo) {
            XmrNodeConfig c;
            c.network = MoneroNetwork::Mainnet;
            c.coinbase = CoinbaseMode::V37Settlement;
            c.template_source = TemplateSourceMode::Native;
            c.arm_order = order;
            c.native_anchor_path = anchor;
            c.native_output_set_path = outset;
            c.native_solo = solo;
            return o2::native_template_config_of(c);
        };
        const auto pinned   = mk(ArmOrderMode::P2PFirst, "", "/f2/outset.bin", false);
        const auto explicit_ = mk(ArmOrderMode::P2PFirst, "/f2/anchor.inc", "/f2/outset.bin", false);
        const auto genesis  = mk(ArmOrderMode::P2PFirst, "", "", false);
        const auto daemon   = mk(ArmOrderMode::DaemonFirst, "/f2/anchor.inc", "/f2/outset.bin", false);
        const auto solo     = mk(ArmOrderMode::P2PFirst, "", "", true);
        std::printf("  consumer_window: pinned=%llu explicit=%llu genesis=%llu daemon-first=%llu solo=%llu\n",
                    (unsigned long long)pinned.consumer_window, (unsigned long long)explicit_.consumer_window,
                    (unsigned long long)genesis.consumer_window, (unsigned long long)daemon.consumer_window,
                    (unsigned long long)solo.consumer_window);
        check("B1 the PINNED default boot (output set, no --native-anchor) is paced like an explicit anchor boot",
              pinned.consumer_window == WINDOW && explicit_.consumer_window == WINDOW,
              "pinned=" + std::to_string(pinned.consumer_window) + " explicit=" + std::to_string(explicit_.consumer_window));
        check("B2 no pacing without an anchor boot (genesis, daemon-first, solo)",
              genesis.consumer_window == 0 && daemon.consumer_window == 0 && solo.consumer_window == 0);
    }

    const Chain c;

    // ---- A: resumed cursor in the pre-anchor span (the mainnet 3765808 case) ----------
    // f2 anchor A=100, D_conf=10: the fresh boot seeds the cursor at 90; the block at
    // 104 is undecidable, so the cursor HOLDS at 104 - 10 - 1 = 93 < A while the tip
    // runs > 256 past it; stop; restart with the block decidable.
    std::printf("-- A: anchor 100, D_conf 10, cursor held at 93 (< anchor), tip 700; restart (network 760) --\n");
    const Run A = restart(c, tmp / "pre-anchor", 100, 10, 104, 700, 760);
    print_run("A", A);
    check("A0 rig: the first process stopped with the cursor below the anchor and the tip > 256 past it",
          A.stop_cursor == 93 && A.stop_tip > A.stop_cursor + WINDOW, "cursor=" + std::to_string(A.stop_cursor) + " tip=" + std::to_string(A.stop_tip));
    check("A1 restart re-drives from its cursor: 0 unreachable rows (fetch_failed 0), the cursor books up to the network tip",
          A.fetch_failed == 0 && A.cursor >= A.net - 10,
          "fetch_failed=" + std::to_string(A.fetch_failed) + " cursor=" + std::to_string(A.cursor));
    check("A2 restart: late_unbooked 0, 0 post-anchor heights at/below the cursor undecided",
          A.late == 0 && A.undecided == 0, "late=" + std::to_string(A.late) + " undecided=" + std::to_string(A.undecided));

    // ---- T: resumed cursor below the retained rows (the booking tail) -------------------
    // genesis anchor, D_conf 3: the cursor HOLDS at 296 (block 300 undecidable) while the
    // tip runs to 2700 -- rows below 653 are trimmed (2048 retention); stop; restart with
    // the block decidable, network 2800.
    std::printf("-- T: cursor held at 296, tip 2700 (rows below 653 trimmed), restart (network 2800) --\n");
    const Run T = restart(c, tmp / "tail", 0, 3, 300, 2700, 2800);
    print_run("T", T);
    check("T0 rig: the first process stopped with the cursor > 2048 below the tip",
          T.stop_cursor == 296 && T.stop_tip >= T.stop_cursor + 2048, "cursor=" + std::to_string(T.stop_cursor) + " tip=" + std::to_string(T.stop_tip));
    check("T1 restart re-drives from its cursor through the trimmed rows: fetch_failed 0, the cursor books up to the network tip",
          T.fetch_failed == 0 && T.cursor >= T.net - 3,
          "fetch_failed=" + std::to_string(T.fetch_failed) + " cursor=" + std::to_string(T.cursor));
    check("T2 restart: late_unbooked 0, 0 heights at/below the cursor undecided (0 silent drops)",
          T.late == 0 && T.undecided == 0, "late=" + std::to_string(T.late) + " undecided=" + std::to_string(T.undecided));

    // ---- R2: a resume whose cursor lags the snapshot tip keeps pacing -------------------
    check("R1 resume with cursor + window < snapshot tip: pacing NOT lifted at the first report (ceiling = cursor + window)",
          T.lifted_first.empty() && T.ceiling_first == T.stop_cursor + WINDOW,
          "lifted=\"" + T.lifted_first + "\" ceiling=" + std::to_string(T.ceiling_first));
    check("R2 resume: nothing above max(snapshot tip, cursor + window) is downloaded before the cursor catches up",
          T.unpaced == 0, "unpaced_rounds=" + std::to_string(T.unpaced));
    check("R3 resume: once the cursor caught up the pacing lifts (synced), the index is synced",
          !T.lifted_end.empty() && T.synced_end, "lifted=\"" + T.lifted_end + "\" synced=" + std::to_string(T.synced_end));

    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
