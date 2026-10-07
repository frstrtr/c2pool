// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_coldboot_refetch_kat.cpp   (COLD-BOOT)
//
// A node booted FRESH from an anchor far behind the tip downloads the whole
// post-anchor gap before its first booking. The chain index keeps only the
// newest `entry_cache` bodies, so the oldest post-anchor bodies are evicted
// before they are booked; pre-fix nothing fetched them again, the booking HELD
// forever, the finalize cursor stuck and the lane suspended on lag (stagenet
// capstone 09-25: H_a 2213803, 1390 blocks behind, cursor pinned at 2213793).
//
//   A1-A4  REAL ChainIndex (regtest, from genesis), 3000 blocks, entry cache
//          64: the old bodies are evicted (A1); the booking asks them back
//          (want_body_for_booking), the index lists them on the re-ask-by-id
//          path (bodies_wanted), and the answer re-caches them byte-identical
//          (A2), including a block below the retained rows (A3); the cache
//          bounds are the shipped ones (A4).
//   B1-B4  END TO END through FinalizeConnect in p2p-first shape (native
//          presence + pumped mainchain events, CbaBlockSource over the index):
//          run R with a cache that never evicts, run E with cache 64, every
//          event pumped AFTER the whole download (exactly the cold boot).
//          E books every block with 0 HELD, 0 late_unbooked, 0 monerod calls,
//          and its ledger (owed_digest, settled set, credits) is IDENTICAL to R.
//   C1-C2  the boot cursor seed: a fresh store is seeded (the anchor boot's
//          H_a - D_conf), a resumed store is never touched.
//
// The same file builds against the pre-fix tree (the new surfaces are probed
// with `requires`), where A2/A3/B1/B2/C1 FAIL: that is what makes it a pin.
// Network-free, RandomX-free. Nonzero exit on any failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
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
template <class I> concept HasBookingRefetch = requires(I& i, const Hash& h) { i.want_body_for_booking(h, std::size_t{64}); };
template <class S> concept HasSrcRefetch = requires(S& s) { s.set_refetch(typename S::RefetchFn{}, std::uint64_t{1}); };
template <class N> concept HasCursorSeed = requires(N& n) { n.seed_fresh_cursor(std::uint64_t{1}); };

// (templates, so the absent branch is never instantiated on the pre-fix tree)
template <class I> std::size_t want_back(I& idx, const Hash& id) {
    if constexpr (HasBookingRefetch<I>) return idx.want_body_for_booking(id, 64);
    else { (void)idx; (void)id; return 0; }   // pre-fix: nothing can ask a connected body back
}
template <class S, class F> void arm_refetch(S& s, F f) {
    if constexpr (HasSrcRefetch<S>) s.set_refetch(typename S::RefetchFn(std::move(f)), 120);
    else { (void)s; (void)f; }
}
template <class St> std::uint64_t restored_of(const St& st) {
    if constexpr (requires { st.refetch_restored; }) return st.refetch_restored;
    else { (void)st; return 0; }
}
template <class N> bool seed_cursor(N& n, std::uint64_t h) {
    if constexpr (HasCursorSeed<N>) return n.seed_fresh_cursor(h);
    else { (void)n; (void)h; return false; }
}

// ---- blocks: the dup-block / reorg-follow KAT shape ----------------------------
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

class ModelVerifier {   // PoW is not what this file tests (require_pow = false anyway)
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };
    bool prefetch_epoch(const Hash&, const std::optional<Hash>&) { return true; }
    bool seed_resident(const Hash&) const { return true; }
    VerifyStatus verify(const std::uint8_t*, std::size_t, const Hash&, std::uint64_t, std::uint64_t, std::uint8_t out[32]) {
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }
};

constexpr std::uint64_t GAP = 3000;           // post-anchor blocks downloaded before the first booking
constexpr std::size_t   SMALL_CACHE = 64;     // bodies kept (production: 1024 / 64 MiB)

// One chain, built once: blocks[h] for h = 1..GAP (index 0 unused).
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

// A real index that has downloaded the whole gap, with its mainchain events queued
// (the native node's queue: nothing is pumped until the download is done).
struct Node {
    ModelVerifier mv;
    nat::LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions opts;
    std::unique_ptr<ChainIndex> idx;
    std::vector<c2pool::xmr::node::MainchainEvent> events;
    std::uint64_t connected = 0;
    Node(const Chain& c, std::size_t cache) {
        opts.net = nat::XmrNet::Regtest;
        opts.require_pow = false;
        opts.entry_cache = cache;
        opts.row_retention = 4096;   // isolate the BODY eviction (the row window is a separate bound)
        idx = std::make_unique<ChainIndex>(opts, src);
        idx->subscribe([this](const c2pool::xmr::node::MainchainEvent& ev) { events.push_back(ev); });
        const nat::ChainRow g = genesis_row();
        idx->seed_direct(g, {nat::DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                         {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
        for (std::uint64_t h = 1; h <= GAP; ++h)
            if (idx->offer_block(nullptr, c.blocks[h], false).outcome == nat::OfferOutcome::Connected) ++connected;
    }
    bool has_body(const Hash& id, std::vector<std::uint8_t>* out = nullptr) const {
        std::vector<std::uint8_t> b;
        const bool ok = idx->block_blob_of(id, b);
        if (out) *out = b;
        return ok;
    }
    // The sync driver's re-ask-by-id round: answer what the index lists (one batch).
    std::size_t serve_wanted(const Chain& c) {
        std::size_t n = 0;
        for (const Hash& id : idx->bodies_wanted()) {
            auto it = c.by_id.find(id);
            if (it == c.by_id.end()) continue;
            (void)idx->offer_block(nullptr, c.blocks[it->second], false);
            if (++n >= 64) break;
        }
        return n;
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

void index_cases(const Chain& c) {
    std::printf("-- A: the chain index (cache %zu, gap %llu) --\n", SMALL_CACHE, (unsigned long long)GAP);
    Node n(c, SMALL_CACHE);
    check("A0 rig: the whole gap connected", n.connected == GAP, "connected=" + std::to_string(n.connected));
    const Hash old_id = c.ids[GAP - 500], deep_id = c.ids[100], new_id = c.ids[GAP - 5];
    check("A1 the oldest post-anchor bodies are EVICTED before any booking (only the newest 64 are held)",
          !n.has_body(old_id) && !n.has_body(deep_id) && n.has_body(new_id));
    const std::size_t asked = want_back(*n.idx, old_id);
    std::size_t served = 0;
    for (int round = 0; round < 3; ++round) served += n.serve_wanted(c);
    std::vector<std::uint8_t> got;
    const bool back = n.has_body(old_id, &got);
    std::vector<std::uint8_t> next;
    const bool back_next = n.has_body(c.ids[GAP - 500 + 40], &next);
    check("A2 the booking asks an evicted body back: listed for re-ask (+ the next 63 above it), re-cached byte-identical on arrival",
          asked == 64 && served >= 64 && back && got == c.blocks[GAP - 500].block_blob && back_next &&
          next == c.blocks[GAP - 500 + 40].block_blob,
          "asked=" + std::to_string(asked) + " served=" + std::to_string(served) + " back=" + std::to_string(back));
    (void)want_back(*n.idx, deep_id);
    (void)n.serve_wanted(c);
    std::vector<std::uint8_t> dgot;
    const bool dback = n.has_body(deep_id, &dgot);
    check("A3 the same for a body far below the cache (h=100 of 3000)", dback && dgot == c.blocks[100].block_blob);
    const ChainIndexOptions shipped{};
    check("A4 bounded memory: the shipped cache limits are unchanged (1024 bodies / 64 MiB), not raised to the gap",
          shipped.entry_cache == 1024 && shipped.entry_cache_bytes == 64ull * 1024 * 1024);
}

struct RunOut {
    std::string digest, empty_digest;
    std::set<std::string> settled;
    std::map<std::string, std::string> credits;
    std::uint64_t cursor = 0, booked = 0, held = 0, late = 0, refused = 0, rpc = 0, restored = 0, ticks = 0;
};

RunOut run_booking(const Chain& c, std::size_t cache, const std::filesystem::path& dir) {
    using namespace c2pool::v37n::xmr;
    RunOut out;
    Node n(c, cache);
    XmrNodeConfig cfg;
    cfg.network = MoneroNetwork::Stagenet;
    cfg.lane_chain = 7;
    cfg.d_conf = 3;
    cfg.arm_order = ArmOrderMode::P2PFirst;
    cfg.settle_db_path = dir.string();
    std::filesystem::create_directories(dir);
    c2pool::xmr::node::MockMonerodTransport mock;
    XmrNode node(cfg, mock, &smoke::test_point_check);
    node.set_native_chain_presence([&](std::uint64_t h, const std::string& bid) {
        const auto b = n.idx->by_height(h);
        return b.has_value() && hex(b->id) == bid;
    });
    node.set_native_row_lookup([&](std::uint64_t h) -> std::optional<std::string> {
        const auto b = n.idx->by_height(h);
        if (!b) return std::nullopt;
        return hex(b->id);
    });
    try { node.bring_up(); } catch (const std::exception& e) { check("B0 bring_up", false, e.what()); return out; }

    std::uint64_t rpc = 0;
    o2::CbaBlockSource src(
        [&](const std::string& bid, std::vector<std::uint8_t>& blob) {
            Hash id{}; if (!id_of_hex(bid, id)) return false;
            return n.idx->block_blob_of(id, blob);
        },
        [&](const std::string&, std::vector<std::uint8_t>&, std::string& why) { ++rpc; why = "get_block: test (must not be called)"; return false; });
    arm_refetch(src, [&](const std::string& bid) { Hash id{}; if (id_of_hex(bid, id)) (void)want_back(*n.idx, id); });

    o2::FinalizeConnectOptions o;
    o.out = nullptr;
    o.sidecar_path = (dir / "pfound.tsv").string();
    o.retry_bound = 40; o.held_retry_every = 5;
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) {
        std::vector<std::uint8_t> blob;
        if (!src.fetch(bid, blob, bk.why)) return false;       // exactly main's fetch_decode contract
        if (h % 5 != 0) { bk.why = "not-lane: test"; return false; }
        // the "decode": a pure function of the block bytes (a wrong / missing body cannot reproduce it)
        std::uint64_t acc = 0; for (std::uint8_t x : blob) acc = acc * 131 + x;
        bk.credit.clear();
        bk.credit[smoke::key_of(static_cast<std::uint8_t>(1 + h % 3))] = static_cast<std::int64_t>(1'000'000'000ull + (acc % 1'000'000'000ull));
        // the on-chain payout pays half of it, so the owed ledger (and its digest) carries the rest
        bk.payout.clear();
        for (const auto& [k, a] : bk.credit) bk.payout[k] = a / 2;
        bk.total_pico = 0; for (const auto& [k, a] : bk.payout) { (void)k; bk.total_pico += static_cast<std::uint64_t>(a); }
        out.credits[bid] = std::to_string(bk.credit.begin()->second);
        return true;
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, cfg, q, o);
    out.empty_digest = hex_of(node.ledger().owed_digest());
    // THE COLD BOOT: every event of the downloaded gap pumped in one go (main's pump_tip).
    for (const auto& ev : n.events) node.pump_mainchain_event(ev);
    const std::uint64_t frontier = GAP - cfg.d_conf;
    for (out.ticks = 0; out.ticks < 400 && node.finalize_driver().cursor_height() < frontier; ++out.ticks) {
        (void)fc.tick();
        (void)n.serve_wanted(c);   // the sync driver's GET_OBJECTS round (one batch per tick)
    }
    (void)fc.tick();
    out.cursor   = node.finalize_driver().cursor_height();
    out.booked   = fc.cba_chain_booked();
    out.held     = fc.stats().held_entered;
    out.late     = fc.stats().late_unbooked;
    out.refused  = fc.stats().refused;
    out.rpc      = rpc + src.stats().rpc_calls;
    out.restored = restored_of(src.stats());
    out.digest   = hex_of(node.ledger().owed_digest());
    for (std::uint64_t h = 5; h <= GAP; h += 5) if (node.ledger().is_settled(hex(c.ids[h]))) out.settled.insert(hex(c.ids[h]));
    (void)fc.drain_before_stop();
    return out;
}

void booking_cases(const Chain& c, const std::filesystem::path& tmp) {
    std::printf("-- B: end to end through FinalizeConnect (p2p-first shape, all %llu events pumped after the download) --\n",
                (unsigned long long)GAP);
    const RunOut R = run_booking(c, 8192, tmp / "ref");
    const RunOut E = run_booking(c, SMALL_CACHE, tmp / "evicted");
    const std::uint64_t frontier = GAP - 3, lane_settled = frontier / 5;
    std::printf("  ref:     cursor=%llu booked=%llu settled=%zu held=%llu late=%llu refused=%llu rpc=%llu ticks=%llu digest=%s\n",
                (unsigned long long)R.cursor, (unsigned long long)R.booked, R.settled.size(), (unsigned long long)R.held,
                (unsigned long long)R.late, (unsigned long long)R.refused, (unsigned long long)R.rpc, (unsigned long long)R.ticks, R.digest.substr(0, 16).c_str());
    std::printf("  evicted: cursor=%llu booked=%llu settled=%zu held=%llu late=%llu refused=%llu rpc=%llu ticks=%llu restored=%llu digest=%s\n",
                (unsigned long long)E.cursor, (unsigned long long)E.booked, E.settled.size(), (unsigned long long)E.held,
                (unsigned long long)E.late, (unsigned long long)E.refused, (unsigned long long)E.rpc, (unsigned long long)E.ticks,
                (unsigned long long)E.restored, E.digest.substr(0, 16).c_str());
    check("B0 reference run (bodies never evicted): cursor at the frontier, every lane block settled, 0 held / late / refused",
          R.cursor == frontier && R.settled.size() == lane_settled && R.held == 0 && R.late == 0 && R.refused == 0);
    check("B1 evicted run: the cursor reaches the finalize frontier (tip - D_conf), every lane block booked + settled",
          E.cursor == frontier && E.settled.size() == lane_settled && E.booked == R.booked,
          "cursor=" + std::to_string(E.cursor) + "/" + std::to_string(frontier) + " settled=" + std::to_string(E.settled.size()));
    check("B2 evicted run: 0 blocks HELD for a missing body, 0 late_unbooked, 0 refused; bodies were restored by refetch",
          E.held == 0 && E.late == 0 && E.refused == 0 && E.restored > 0,
          "held=" + std::to_string(E.held) + " restored=" + std::to_string(E.restored));
    check("B3 booking output IDENTICAL to the never-evicted run: owed_digest (non-empty ledger), settled set, per-block credits",
          E.digest == R.digest && E.digest != R.empty_digest && E.settled == R.settled && E.credits == R.credits,
          "digest " + E.digest.substr(0, 16) + " vs " + R.digest.substr(0, 16) + " (empty " + R.empty_digest.substr(0, 16) + ")");
    check("B4 0 monerod calls in both runs (the body comes back over the native path only)", E.rpc == 0 && R.rpc == 0);
}

void cursor_seed_cases(const std::filesystem::path& tmp) {
    std::printf("-- C: the boot cursor seed --\n");
    using namespace c2pool::v37n::xmr;
    XmrNodeConfig cfg;
    cfg.network = MoneroNetwork::Stagenet; cfg.lane_chain = 7; cfg.d_conf = 10;
    cfg.settle_db_path = (tmp / "seed").string();
    std::filesystem::create_directories(cfg.settle_db_path);
    const std::uint64_t HA = 2213803;
    {
        c2pool::xmr::node::MockMonerodTransport mock;
        XmrNode node(cfg, mock, &smoke::test_point_check);
        node.bring_up();
        bool seeded = false;
        seeded = seed_cursor(node, HA - cfg.d_conf);
        check("C1 fresh store: the finalize cursor is seeded at H_a - D_conf before any block is pumped (pre-fix: 0)",
              seeded && node.finalize_driver().cursor_height() == HA - cfg.d_conf,
              "cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        node.stop();
    }
    {
        c2pool::xmr::node::MockMonerodTransport mock;
        XmrNode node(cfg, mock, &smoke::test_point_check);
        node.bring_up();
        bool seeded = false;
        seeded = seed_cursor(node, 5);
        check("C2 resumed store (restart): the recovered cursor is kept, the seed refuses",
              !seeded && node.finalize_driver().cursor_height() == (HasCursorSeed<XmrNode> ? HA - cfg.d_conf : std::uint64_t{0}));
        node.stop();
    }
}

} // namespace

int main() {
    // the settle store fsyncs every cursor/high-water write (~6000 per booking run): on a tmpfs when one exists
    std::error_code ec;
    const std::filesystem::path base = std::filesystem::is_directory("/dev/shm", ec) && ::access("/dev/shm", W_OK) == 0
                                           ? std::filesystem::path("/dev/shm") : std::filesystem::temp_directory_path();
    std::filesystem::path tmp = base / ("v37-xmr-coldboot-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::printf("== v37_xmr_coldboot_refetch_kat ==\n");
    const Chain c;
    index_cases(c);
    booking_cases(c, tmp);
    cursor_seed_cases(tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
