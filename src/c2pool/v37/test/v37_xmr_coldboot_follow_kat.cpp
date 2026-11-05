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
// The catch-up download of a p2p-first anchor boot is paced at the CONSUMER's
// frontier + --native-catchup-window (256). Under Path B the consumer is the
// follower rows table: each serve-loop pass reports as the consumer frontier
// the height of the last row whose RowWeights record is written
// (PathbFollowerRows::frontier). Pinned with the REAL ChainIndex at the
// SHIPPED bounds (2048 rows, 1024 bodies, window 256):
//
//   C1     a fresh anchor boot 1400 rows behind the cohort: paced until synced
//          (each pass downloads at most the window above the reported
//          frontier), then the index follows the network tip, is synced, the
//          pacing is lifted by the synced latch, and the frontier is the
//          network tip with a RowWeights record for every main-chain row it
//          holds.
//
// Network-free, RandomX-free. Nonzero exit on any failure.
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
#include "c2pool/v37/xmr/pathb/pathb_follower_rows.hpp"

namespace nat = c2pool::xmr::native;
namespace pb  = c2pool::xmr::pathb;
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
        opts.consumer_window = window;
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

// The Path B consumer: the follower rows table over the index, and main's
// serve-loop pass (report the frontier, drain the events).
struct Consumer {
    pb::PathbFollowerRows rows;
    explicit Consumer(const std::string& table_path) : rows(table_path) {}
    void bind(Index& ix) {
        ix.idx->subscribe_rows([this](const nat::ConsensusState& st, const nat::ChainRow& row, bool seeded) {
            rows.on_row(st, row, seeded);
        });
        rows.bind(ix.idx.get());
    }
    std::optional<std::uint64_t> pass(Index& ix) {
        const std::optional<std::uint64_t> f = rows.frontier();
        if (f) ix.idx->set_consumer_frontier(*f);
        (void)ix.drain();
        return f;
    }
};

void peer_sync(Index& ix) {
    nat::PeerRef p; p.peer_id = 7; p.addr = "127.0.0.1:1";
    nat::PeerSyncData d; d.current_height = ix.net_tip + 1; d.top_id = ix.c.ids[ix.net_tip]; d.top_version = 0;
    ix.idx->on_peer_sync_data(p, d);
}
bool synced(const Index& ix) { return ix.idx->sync_state().synced; }

struct Follow {
    std::uint64_t tip = 0, net = 0, frontier = 0, ceiling_end = 0, max_step = 0, rows_missing = 0, passes = 0;
    bool synced_end = false, held_end = false;
    std::string lifted;
};

void print_follow(const char* tag, const Follow& f) {
    std::printf("  %-10s index_tip=%llu network_tip=%llu synced=%d consumer_held=%d ceiling=%llu frontier=%llu "
                "max_step=%llu rows_without_weights=%llu passes=%llu lifted=\"%s\"\n",
                tag, (unsigned long long)f.tip, (unsigned long long)f.net, f.synced_end ? 1 : 0, f.held_end ? 1 : 0,
                (unsigned long long)f.ceiling_end, (unsigned long long)f.frontier, (unsigned long long)f.max_step,
                (unsigned long long)f.rows_missing, (unsigned long long)f.passes, f.lifted.c_str());
}

// A fresh anchor boot NT rows behind the cohort, the Path B consumer reporting
// its frontier each pass.
Follow fresh_follow(const Chain& c, const std::filesystem::path& dir) {
    Follow f;
    constexpr std::uint64_t NT = 1400;
    Index ix(c, NT, 2048, 1024, WINDOW);
    Consumer k((dir / "row_weights").string());
    k.bind(ix);
    peer_sync(ix);
    std::uint64_t reported = 0;   // the frontier the download is paced at (the anchor until the first report)
    for (int i = 0; i < 2500; ++i) {
        (void)ix.sync_round(); peer_sync(ix);
        const std::uint64_t after = ix.tip();
        if (!synced(ix) && after > reported && after - reported > f.max_step) f.max_step = after - reported;
        if (const auto fr = k.pass(ix)) reported = *fr;
        ++f.passes;
        if (ix.tip() == NT && synced(ix)) break;
    }
    for (int i = 0; i < 5; ++i) (void)k.pass(ix);
    f.tip = ix.tip(); f.net = NT; f.synced_end = synced(ix); f.held_end = ix.idx->consumer_held();
    f.ceiling_end = ix.idx->consumer_ceiling(); f.lifted = ix.idx->consumer_pacing_lifted_why();
    if (const auto fr = k.rows.frontier()) f.frontier = *fr;
    for (std::uint64_t h = 1; h <= f.tip; ++h) {
        const auto b = ix.idx->by_height(h);
        if (b && !k.rows.weights(b->id)) ++f.rows_missing;
    }
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

    std::printf("-- C: a fresh p2p-first anchor boot 1400 rows behind, paced at the Path B consumer frontier --\n");
    const Follow C = fresh_follow(c, tmp / "fresh");
    print_follow("fresh", C);
    check("C1 anchor boot > window behind: paced until synced (each pass at most window + 1 above the reported frontier), then the index follows the network tip, is synced, the pacing lifted by the synced latch, the frontier is the network tip and every held main-chain row has its RowWeights record",
          C.max_step <= WINDOW + 1 && C.tip == C.net && C.synced_end && !C.held_end && C.lifted.rfind("synced", 0) == 0 &&
              C.frontier == C.net && C.rows_missing == 0,
          "max_step=" + std::to_string(C.max_step) + " index_tip=" + std::to_string(C.tip) + " synced=" + std::to_string(C.synced_end) +
          " frontier=" + std::to_string(C.frontier) + " rows_without_weights=" + std::to_string(C.rows_missing) +
          " lifted=\"" + C.lifted + "\"");

    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
