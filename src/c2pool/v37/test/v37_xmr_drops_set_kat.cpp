// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_set_kat -- DROPS-SET-PIN (adversarial verify of 2da7c254, flip 1).
//
// THE DEFECT (regtest verify run vfix-m2). Lane block h=283 (P=594) was won by
// A, which composed its DROPS delta from the 8 raindrops of bin 257 it held at
// its booking. Node C was restarted mid-run; its post-restart range backfill
// (drops_sync: "hold everything every ready peer holds NOW") returned a 9th
// bin-257 raindrop that A/B had stored AFTER their compositions, so C composed
// 9 raindrops: 2 payees, sum 144217117774 vs the winner's 1 payee 127644960649
// -> drops-ALARM carry-mismatch, carried REFUSED, a latent owed-ledger split.
// The raindrop SET per committed range was node-local.
//
// THE FIX (DROPS-SET-PIN). The winner pins the receipt ids of exactly the
// raindrops it composed from (FB_BLOCK_WON v0x03 set trailer). Every node --
// the winner too -- composes the block's rows from exactly that set:
// never adds a raindrop it holds beyond it, never drops a member (HOLD and
// fetch it by id), and refuses an invalid set the same way on every node.
//
//   DS1  EXTRA: a receiver holding one more raindrop in the range composes the
//        winner's delta (base: its node-local set -> a different delta, RED).
//   DS2  FEWER: a receiver missing two members HOLDs (names them), and after
//        they arrive composes the winner's delta (base: composes short, RED).
//   DS3  RESTART: a restarted receiver (empty harvest) reloads the frame bytes,
//        fetches exactly the members by id from a peer over loopback TCP
//        (drops_fetch_ids: never an id outside the set) and books the winner's
//        delta.
//   DS4  WINNER SYMMETRY: the winner's pinned composition equals its full
//        composition; the set is sorted/unique; the v0x03 frame round-trips.
//   DS5  REFUSE: a set naming a raindrop outside the range, or a hash that is a
//        share, is refused with the same reason on every node (EMPTY delta);
//        a malformed set (unsorted / duplicate / over the bound) never decodes.
//   DS6  LEDGER: three lane blocks (winners W, R1, W) with extra and missing
//        raindrops on different nodes: owed_digest equal on every node after
//        every block, 0 lane_root_refused (base: split).
//   DS7  CAP: over the set bound the winner pins the smallest ids (flagged).
//   DS8  FLIP 0: a flip-0 decoder refuses v0x03 as "wrong length"; a frame
//        without a set still encodes as the v0x02 bytes.
//   DS9  source pins: the shell composes a receiver's rows from the carried
//        set only, HOLDs without it, fetches missing members by id, and never
//        runs the range backfill on the receiver route.
//
// RED on the base (2da7c254): no set exists, every node composes its own
// held raindrops; GREEN on the fix.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <c2pool/v37/v37_subthreshold_estimator.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
using namespace std::chrono_literals;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;
namespace rl = ::c2pool::v37n::xmr::relay;

static constexpr std::uint64_t kD = 10;
static constexpr std::uint64_t kShareDiff = 1024;
static constexpr std::uint32_t kPushes = 2;   // fee model: payee push + donation push per receipt
static const std::set<std::uint64_t> kLanes = {130, 170, 210};   // lane blocks on the canonical chain

struct HNode {   // the XmrNode seam shape
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester*) {}
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook*) {}
    void set_pre_harvest(std::function<void(std::uint64_t)>) {}
    void set_drops_price_fn(std::function<st::WorkPrice()>) {}
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
};
static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = static_cast<unsigned __int128>(n_shares);
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.valid = true;
    return dx::rescale_price(wp, 1);
}
static std::string slurp(const std::string& p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}
static bytes32 pid_of(std::uint64_t bin) { bytes32 b{}; b[0] = 0xEE; std::memcpy(b.data() + 8, &bin, 8); return b; }
static std::optional<std::uint64_t> bin_of_pid(const bytes32& pid) { std::uint64_t b = 0; std::memcpy(&b, pid.data() + 8, 8); return b; }
// the id a raindrop gets without a receipt (XmrDropsWiring::on_raindrop): the KAT names members by it
static bytes32 drop_id(const bytes32& payee, std::uint64_t bin, const bytes32& pow) {
    std::vector<std::uint8_t> b = {'V', '3', '7', 'D', 'R', 'O', 'P', 'I', 'D'};
    b.insert(b.end(), payee.begin(), payee.end());
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(bin >> (8 * i)));
    b.insert(b.end(), pow.begin(), pow.end());
    return ::v37::sha256d(b);
}

// One replicated stream: the lane order (receipt i at positions [2i, 2i+2)) +
// the raindrops (payee, bin, pow). Every node holds the same order.
struct Rcpt { bytes32 payee; std::uint64_t bin; std::uint16_t give; };
struct Drop { bytes32 payee; std::uint64_t bin; bytes32 pow; bytes32 id() const { return drop_id(payee, bin, pow); } };
static bytes32 rand_pow(std::mt19937_64& rng) {
    bytes32 pow{};
    for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(pow.data() + w * 8, &v, 8); }
    pow[31] = static_cast<std::uint8_t>(0x40 + (rng() % 0xC0));   // a raindrop, not a share
    return pow;
}
struct Stream { std::vector<Rcpt> order; std::vector<Drop> drops; };
static Stream make_stream(const std::vector<bytes32>& who, std::uint32_t K) {
    Stream s;
    std::mt19937_64 rng(0xD5E7D5E7ULL);
    const std::uint16_t give[4] = {0, 655, 6553, 0};
    const std::uint64_t from[4] = {101, 101, 115, 150};
    for (std::uint64_t bin = 101; bin <= 205; ++bin)
        for (int i = 0; i < 4; ++i) {
            if (bin < from[i]) continue;
            const int n = (i == 1 && bin % 3 == 0) ? 2 : 1;
            for (int j = 0; j < n; ++j) s.order.push_back({who[i], bin, give[i]});
            const std::uint32_t nd = (bin % 4 == 0) ? K - 1 : K + 1;   // some keys below K raindrops (share-weighted rows)
            for (std::uint32_t k = 0; k < nd; ++k) s.drops.push_back({who[i], bin, rand_pow(rng)});
        }
    return s;
}

struct NodeH {
    std::unique_ptr<dx::XmrDropsWiring> w;
    HNode node;
    ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    NodeH() {
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kShareDiff, 1);
        w->attach(node);
        w->attach_chain_order(node, kD);
        w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
            auto it = kLanes.lower_bound(h);
            if (it == kLanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
        w->observe_native_tip(100);
        w->set_enrol_mode(dx::EnrolMode::Auto);
    }
    void feed_order(const std::vector<Rcpt>& order) {
        std::uint64_t pos = 0;
        for (const auto& r : order) { w->on_share_lane(r.payee, r.bin, pos, kPushes, pid_of(r.bin), r.give); pos += kPushes; }
    }
    void feed(const std::vector<Drop>& ds, const std::set<bytes32>& skip = {}) {
        for (const auto& d : ds) if (!skip.count(d.id())) (void)w->on_raindrop(d.payee, d.bin, d.pow);
    }
    struct Out {
        bool ok = false;                          // composed (else HOLD)
        std::vector<bytes32> set, missing;        // the set composed from; members not held (HOLD)
        std::string refused;                      // the set is invalid for the range (EMPTY delta)
        std::size_t rows = 0; bytes32 digest{}; std::map<bytes32, long long> delta;
    };
    // THE booking of lane block h at cut P: pin == nullptr = this node is the
    // winner (it pins what it holds); else the winner's carried set.
    Out book(std::uint64_t h, std::uint64_t P, const std::vector<bytes32>* pin, const bytes32& don) {
        Out o;
        const auto rg = w->range_for(h);
        std::string why;
        const auto lp = w->own_prefix(P, bin_of_pid, &why);
        if (!rg || !lp) { o.refused = "undecidable: " + why; return o; }
        dx::XmrDropsWiring::LaneCompose lc;
#if defined(C2POOL_XMR_DROPS_SET_PIN)
        o.set = pin ? *pin : w->pinned_ids(rg->first, rg->second, rl::kBlockWonSetMaxIds);
        auto pc = w->compose_lane_pinned(rg->first, rg->second, *lp, o.set);
        o.missing = pc.missing; o.refused = pc.refused;
        if (!o.missing.empty()) return o;          // HOLD
        lc = pc.lc;
        if (!o.refused.empty()) lc.rows.clear();   // the carriage books EMPTY (every node alike)
#else
        (void)pin;   // BASE (2da7c254): the rows are whatever THIS node holds over the range
        lc = w->compose_lane(rg->first, rg->second, *lp);
#endif
        st::DropsCompose dctx; dctx.price = price_of(600000000000ULL, 1000);
        dctx.enrollment = &lc.book;
        auto carry = dx::compose_carry(params, lc.rows, dctx);
        dx::split_give_author(carry.delta, *lp, don);
        o.ok = true; o.rows = lc.rows.size(); o.digest = carry.enrollment_digest; o.delta = carry.delta;
        return o;
    }
};
static long long sum_of(const std::map<bytes32, long long>& d) { long long s = 0; for (const auto& [k, v] : d) s += v; return s; }

// ── DS3's relay side: two in-process XmrRelayNode over loopback TCP (fake
// RandomX: nonce >= kDropNonce hashes to a RAINDROP), as the backfill KAT ──
static constexpr u32 kChain = 7;
static constexpr u64 kRelayShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr std::uint32_t kDropNonce = 0x40000000u;
struct RNode {
    ChainView chain;
    std::atomic<u64> rx_calls{0};
    std::unique_ptr<XmrRelayNode> relay;
    std::vector<bytes32> drained;
    explicit RNode(RelayOptions ro) {
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [this](const std::vector<u8>& blob, const bytes32&, bytes32& pow) {
                ++rx_calls;
                u32 nonce = 0;
                ::v37::xmr::HashingBlob hb; hb.bytes = blob;
                ::v37::xmr::verify::ParsedBlob pb;
                if (::v37::xmr::verify::parse_hashing_blob(hb, pb))
                    for (int i = 0; i < 4; ++i) nonce |= static_cast<u32>(blob[pb.header_len - 4 + i]) << (8 * i);
                pow.fill(0);
                if (nonce >= kDropNonce) pow[31] = 0x02;
                return true;
            },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [](const std::string&) {});
    }
    ~RNode() { relay->stop(); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    void pump() { for (auto& a : relay->drain_drops()) drained.push_back(a.id); }
};
static RelayOptions ropts(bool listen, std::vector<u16> dial, u64 hello_bins) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kRelayShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kRelayShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = kFloorDiff;
    o.drops_hello_bins = hello_bins;
    o.drops_fetch_retry_ms = 300;
    return o;
}
template <class F>
static bool wait_for(F cond, std::vector<RNode*> pump, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
static Admitted drop_on(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, kChain, kRelayShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    a.pow.fill(0); a.pow[31] = 0x02;
    return a;
}


// The owed ledger of one node (V37Q digest of the forward map), as in the
// carry_suffix KAT: a root this node never passed through = lane_root_refused.
struct Ledger {
    std::map<bytes32, long long> fw;
    std::vector<bytes32> hist;
    std::uint64_t lane_root_refused = 0;
    bytes32 digest() const {
        std::map<std::array<std::uint8_t, 32>, long long> m;
        for (const auto& [k, v] : fw) { std::array<std::uint8_t, 32> a{}; std::memcpy(a.data(), k.data(), 32); m[a] = v; }
        const auto d = ::c2pool::v37::subthreshold::owed_digest(m, {});
        bytes32 b{}; std::memcpy(b.data(), d.data(), 32);
        return b;
    }
    Ledger() { hist.push_back(digest()); }
    void book(const bytes32& root, const std::map<bytes32, long long>& rows) {
        if (std::find(hist.begin(), hist.end(), root) == hist.end()) { ++lane_root_refused; return; }
        for (const auto& [k, v] : rows) fw[k] += v;
        hist.push_back(digest());
    }
};

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_set_kat (%s) ==\n",
#if defined(C2POOL_XMR_DROPS_SET_PIN)
                "fix tree: C2POOL_XMR_DROPS_SET_PIN");
#else
                "BASE tree: every node composes the raindrops it holds (2da7c254)");
#endif
    const std::vector<bytes32> who = {b32_of(0x41), b32_of(0x42), b32_of(0x43), b32_of(0x44)};
    const bytes32 DON = b32_of(0x77), XTRA = b32_of(0x58);
    const ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    const Stream s = make_stream(who, params.subthreshold.K);
    const auto pos_of_bin = [&](std::uint64_t b) { std::uint64_t n = 0; for (const auto& r : s.order) if (r.bin < b) ++n; return n * kPushes; };
    const std::uint64_t P1 = pos_of_bin(115), P2 = pos_of_bin(165), P3 = pos_of_bin(200);
    std::mt19937_64 rng(0xE7E7A5A5ULL);
    // the late raindrops (admitted somewhere AFTER the winner composed): the M2 shape
    const Drop late2a{who[3], 152, rand_pow(rng)}, late2b{XTRA, 157, rand_pow(rng)}, late1{who[0], 110, rand_pow(rng)};
    std::printf("stream: %zu receipts, %zu raindrops; cuts P=%llu/%llu/%llu; ranges h=130 [0,120) h=170 [120,160) h=210 [160,200)\n",
                s.order.size(), s.drops.size(), (unsigned long long)P1, (unsigned long long)P2, (unsigned long long)P3);

    // ── DS1 EXTRA + DS4 WINNER SYMMETRY ────────────────────────────────────
    std::printf("DS1: the receiver holds one more raindrop of the range than the winner composed (restart backfill / late flood)\n");
    NodeH W, R1;
    W.feed_order(s.order); R1.feed_order(s.order);
    W.feed(s.drops); R1.feed(s.drops);
    const auto w2 = W.book(170, P2, nullptr, DON);   // W wins h=170, composes, pins
    R1.feed({late2a, late2b});                         // arrives at R1 after W composed
    const auto r2 = R1.book(170, P2, &w2.set, DON);
    std::printf("  W  rows=%zu delta_payees=%zu sum=%lld set=%zu\n", w2.rows, w2.delta.size(), sum_of(w2.delta), w2.set.size());
    std::printf("  R1 rows=%zu delta_payees=%zu sum=%lld%s\n", r2.rows, r2.delta.size(), sum_of(r2.delta), r2.ok ? "" : " (HOLD)");
    C(w2.ok && !w2.delta.empty(), "DS1 the winner's composition of h=170 is non-trivial");
    C(r2.ok && r2.delta == w2.delta && r2.digest == w2.digest,
      "DS1 a receiver with 2 extra raindrops in [120,160) books EXACTLY the winner's delta (base: its own larger set -> RED)");
    C(r2.delta.count(XTRA) == 0, "DS1 the extra raindrop's payee is credited on no node for h=170");
#if defined(C2POOL_XMR_DROPS_SET_PIN)
    {
        const auto rg = W.w->range_for(170);
        std::string lwhy;
        const auto lp = W.w->own_prefix(P2, bin_of_pid, &lwhy);
        const auto full = W.w->compose_lane(rg->first, rg->second, *lp);
        const auto pin = W.w->compose_lane_pinned(rg->first, rg->second, *lp, w2.set);
        C(pin.ok() && pin.lc.rows.size() == full.rows.size() && pin.lc.inputs == full.inputs && pin.lc.digest == full.digest,
          "DS4 the winner's pinned composition == its full composition (same rows, inputs digest, book)");
        C(std::is_sorted(w2.set.begin(), w2.set.end()) && std::adjacent_find(w2.set.begin(), w2.set.end()) == w2.set.end(),
          "DS4 the pinned set is strictly ascending (the wire order)");
        rl::BlockWon bw; bw.chain_id = 7; bw.bid = b32_of(0x31); bw.h_b = 170; bw.cut_next_pos = P2;
        bw.drops = rl::BlockWon::Drops{w2.delta, w2.digest, w2.set};
        const auto f = rl::encode_block_won(bw);
        rl::BlockWon back; std::string why;
        C(!f.empty() && f[1] == rl::kFbBlockWonSetVersion &&
          f.size() == rl::kBlockWonDropsMinBytes + rl::kBlockWonDropsRowBytes * w2.delta.size() + 4 + 32 * w2.set.size(),
          "DS4 FB_BLOCK_WON v0x03 = 161 + 40 x rows + 4 + 32 x n_ids bytes (" + std::to_string(f.size()) + " B)");
        C(rl::decode_block_won(f, back, &why, true) && back == bw && back.drops->set == w2.set, "DS4 the v0x03 frame round-trips " + why);
    }
#else
    C(false, "DS4 no pinned composition on the base");
#endif

    // ── DS2 FEWER ───────────────────────────────────────────────────────────
    std::printf("DS2: the receiver lacks two members of the winner's set (a partial backfill)\n");
    {
        NodeH R2;
        R2.feed_order(s.order);
        std::set<bytes32> gone;
        for (const auto& d : s.drops) if (d.bin >= 120 && d.bin < 160 && gone.size() < 2 && d.payee == who[0]) gone.insert(d.id());
        R2.feed(s.drops, gone);
        const auto a = R2.book(170, P2, &w2.set, DON);
        std::printf("  R2 first attempt: %s missing=%zu\n", a.ok ? "COMPOSED" : "HOLD", a.missing.size());
        C(!a.ok && a.missing.size() == 2 && std::set<bytes32>(a.missing.begin(), a.missing.end()) == gone,
          "DS2 a receiver missing 2 members HOLDs and names exactly those 2 ids (base: composes a short set -> RED)");
        std::vector<Drop> back;
        for (const auto& d : s.drops) if (gone.count(d.id())) back.push_back(d);
        R2.feed(back);   // fetched by id
        const auto b = R2.book(170, P2, &w2.set, DON);
        C(b.ok && b.delta == w2.delta && b.digest == w2.digest, "DS2 once both members arrive the receiver books the winner's delta");
    }

    // ── DS5 REFUSE ──────────────────────────────────────────────────────────
    std::printf("DS5: an invalid set is refused alike on every node\n");
#if defined(C2POOL_XMR_DROPS_SET_PIN)
    {
        std::vector<bytes32> bad = w2.set;
        bytes32 outside{};
        for (const auto& d : s.drops) if (d.bin == 170) { outside = d.id(); break; }
        bad.push_back(outside); std::sort(bad.begin(), bad.end());
        const auto rw = W.book(170, P2, &bad, DON), rr = R1.book(170, P2, &bad, DON);
        std::printf("  W: %s | R1: %s\n", rw.refused.c_str(), rr.refused.c_str());
        C(rw.ok && rr.ok && !rw.refused.empty() && rw.refused == rr.refused && rw.delta.empty() && rr.delta.empty(),
          "DS5 a set naming a raindrop of bin 170 (outside [120,160)) is refused with the same reason on W and R1: EMPTY delta");
        bytes32 spow{}; spow[0] = 0x01;   // normalises to a SHARE (lz >= the drops floor): the harvester refuses it
        W.w->on_raindrop(who[2], 140, spow); R1.w->on_raindrop(who[2], 140, spow);
        std::vector<bytes32> bad2 = w2.set; bad2.push_back(drop_id(who[2], 140, spow)); std::sort(bad2.begin(), bad2.end());
        const auto sw = W.book(170, P2, &bad2, DON), sr = R1.book(170, P2, &bad2, DON);
        C(sw.ok && sr.ok && !sw.refused.empty() && sw.refused == sr.refused && sw.delta.empty(),
          "DS5 a set naming a share-grade hash is refused alike (" + sw.refused + ")");
        rl::BlockWon bw; bw.chain_id = 7; bw.bid = b32_of(0x32); bw.h_b = 170;
        bw.drops = rl::BlockWon::Drops{w2.delta, w2.digest, w2.set};
        auto f = rl::encode_block_won(bw);
        const std::size_t ids_at = f.size() - 32 * w2.set.size();
        rl::BlockWon x; std::string why;
        auto g = f; std::swap_ranges(g.begin() + ids_at, g.begin() + ids_at + 32, g.begin() + ids_at + 32);
        C(!rl::decode_block_won(g, x, &why, true) && why.find("not strictly ascending") != std::string::npos, "DS5 an unsorted set never decodes (" + why + ")");
        g = f; std::copy(g.begin() + ids_at, g.begin() + ids_at + 32, g.begin() + ids_at + 32);
        C(!rl::decode_block_won(g, x, &why, true) && why.find("not strictly ascending") != std::string::npos, "DS5 a duplicate id never decodes");
        g = f; const std::uint32_t over = static_cast<std::uint32_t>(rl::kBlockWonSetMaxIds + 1);
        for (int i = 0; i < 4; ++i) g[ids_at - 4 + i] = static_cast<std::uint8_t>(over >> (8 * i));
        C(!rl::decode_block_won(g, x, &why, true) && why.find("over the bound") != std::string::npos, "DS5 a set over kBlockWonSetMaxIds never decodes");
        std::vector<bytes32> unsorted = w2.set; std::swap(unsorted[0], unsorted[1]);
        bw.drops->set = unsorted;
        C(rl::encode_block_won(bw).empty(), "DS5 the encoder refuses a non-canonical set");
    }
#else
    C(false, "DS5 no set exists on the base: nothing to refuse");
#endif

    // ── DS7 CAP ─────────────────────────────────────────────────────────────
#if defined(C2POOL_XMR_DROPS_SET_PIN)
    {
        bool capped = false;
        const auto all = W.w->pinned_ids(120, 160, 1u << 20);
        const auto five = W.w->pinned_ids(120, 160, 5, &capped);
        C(capped && five.size() == 5 && std::equal(five.begin(), five.end(), all.begin()),
          "DS7 over the bound the winner pins the 5 SMALLEST ids (deterministic), flagged capped");
    }
#else
    C(false, "DS7 no set cap on the base");
#endif

    // ── DS8 FLIP 0 ──────────────────────────────────────────────────────────
#if defined(C2POOL_XMR_DROPS_SET_PIN)
    {
        rl::BlockWon bw; bw.chain_id = 7; bw.bid = b32_of(0x33); bw.h_b = 170;
        bw.drops = rl::BlockWon::Drops{w2.delta, w2.digest, std::nullopt};
        const auto f2 = rl::encode_block_won(bw);
        C(f2.size() == rl::kBlockWonDropsMinBytes + rl::kBlockWonDropsRowBytes * w2.delta.size() && f2[1] == rl::kFbBlockWonDropsVersion,
          "DS8 a frame without a set is still the v0x02 bytes (161 + 40 x rows)");
        bw.drops->set = w2.set;
        const auto f3 = rl::encode_block_won(bw);
        rl::BlockWon x; std::string why;
        C(!rl::decode_block_won(f3, x, &why, false) && why == "block_won: wrong length", "DS8 a flip-0 decoder refuses v0x03: " + why);
        C(rl::kBlockWonDropsLive == ::c2pool::v37n::kActivateConsensusV1 &&
          rl::kXmrPoolRulesVersion == (::c2pool::v37n::kActivateConsensusV1 ? 4u : 2u),
          "DS8 v0x03 only under the flip; pool rules v4 (flip 1) / v2 (flip 0, unchanged)");
    }
#else
    C(false, "DS8 no v0x03 on the base");
#endif

    // ── DS9 SOURCE PINS ─────────────────────────────────────────────────────
    {
        const std::string src = slurp(V37_XMR_SHELL_SRC);
        C(!src.empty(), std::string("DS9 the shell source is readable: ") + V37_XMR_SHELL_SRC);
        C(src.find("drops_have_set ? &*wire_cache[bid].drops_set : nullptr") != std::string::npos,
          "DS9 a receiver composes from the winner's carried set (wire_cache[bid].drops_set) only");
        C(src.find("if (!drops_winner_route && !drops_have_set)") != std::string::npos &&
          src.find("not carried yet") != std::string::npos && src.find("want_block_won") != std::string::npos,
          "DS9 without the winner's set a receiver HOLDs and asks FB_GETWON (never a node-local set)");
        C(src.find("if (drops_winner_route && rg.second > rg.first)") != std::string::npos,
          "DS9 the range backfill (drops_sync) runs on the winner route only");
        C(src.find("relay_node->drops_fetch_ids(pc.missing, relay_hint(bid), rgo->first, rgo->second)") != std::string::npos,
          "DS9 a missing member is fetched by id (the frame's sender first) and the booking HOLDs");
        C(src.find("drops->on_raindrop_id(a.id,") != std::string::npos && src.find("drops->on_raindrop(::v37") == std::string::npos,
          "DS9 every admitted raindrop enters the harvest with its receipt id");
        C(src.find("carry.enrollment_digest, drops_lane.set}") != std::string::npos,
          "DS9 the winner carries the set it composed from (FB_BLOCK_WON v0x03)");
    }

    // ── DS6 LEDGER ──────────────────────────────────────────────────────────
    std::printf("DS6: three lane blocks (winners W, R1, W); extra and missing raindrops on different nodes\n");
    {
        NodeH n[3];
        const char* names[3] = {"W", "R1", "R2"};
        const Drop ownR1{who[2], 141, rand_pow(rng)};   // R1's own raindrop, not yet flooded when R1 wins h=170
        std::set<bytes32> lackR2;
        for (const auto& d : s.drops) if (d.bin >= 160 && d.bin < 200 && d.payee == who[1] && lackR2.size() < 2) lackR2.insert(d.id());
        for (int i = 0; i < 3; ++i) n[i].feed_order(s.order);
        n[0].feed(s.drops);
        n[1].feed(s.drops); n[1].feed({late1, ownR1});   // late1: bin 110 of h=130's range, after W composed
        n[2].feed(s.drops, lackR2);
        std::map<bytes32, Drop> any;   // what the network can serve by id
        for (const auto& d : s.drops) any.emplace(d.id(), d);
        any.emplace(late1.id(), late1); any.emplace(ownR1.id(), ownR1);
        struct Blk { std::uint64_t h, P; int winner; };
        const std::vector<Blk> blocks = {{130, P1, 0}, {170, P2, 1}, {210, P3, 0}};
        Ledger L[3];
        std::uint64_t holds = 0, fetched = 0, split = 0, mismatch = 0;
        for (const auto& b : blocks) {
            const bytes32 root = L[b.winner].hist.back();
            const auto ow = n[b.winner].book(b.h, b.P, nullptr, DON);
            L[b.winner].book(root, ow.delta);
            for (int i = 0; i < 3; ++i) {
                if (i == b.winner) continue;
                auto o = n[i].book(b.h, b.P, &ow.set, DON);
                if (!o.ok && !o.missing.empty()) {   // HOLD -> fetch the members by id -> re-book
                    ++holds;
                    std::vector<Drop> got;
                    for (const auto& id : o.missing) if (any.count(id)) got.push_back(any.at(id));
                    fetched += got.size();
                    n[i].feed(got);
                    o = n[i].book(b.h, b.P, &ow.set, DON);
                }
                if (!o.ok || o.delta != ow.delta) ++mismatch;
                std::printf("  h=%llu %s set=%zu delta_payees=%zu sum=%lld | winner sum=%lld %s\n", (unsigned long long)b.h, names[i],
                            ow.set.size(), o.delta.size(), sum_of(o.delta), sum_of(ow.delta), o.delta == ow.delta ? "AGREES" : "REFUSED");
                if (o.ok) L[i].book(root, o.delta);
            }
            if (!(L[0].hist.back() == L[1].hist.back() && L[1].hist.back() == L[2].hist.back())) ++split;
            std::printf("  h=%llu owed_digest W=%s… R1=%s… R2=%s…\n", (unsigned long long)b.h, hex(L[0].hist.back()).substr(0, 12).c_str(),
                        hex(L[1].hist.back()).substr(0, 12).c_str(), hex(L[2].hist.back()).substr(0, 12).c_str());
        }
        const std::uint64_t refused = L[0].lane_root_refused + L[1].lane_root_refused + L[2].lane_root_refused;
        std::printf("  holds=%llu fetched=%llu carried-mismatch=%llu split_blocks=%llu lane_root_refused=%llu\n", (unsigned long long)holds,
                    (unsigned long long)fetched, (unsigned long long)mismatch, (unsigned long long)split, (unsigned long long)refused);
        C(mismatch == 0, "DS6 every receiver books every block's winner delta (0 carried mismatches; base: RED)");
        C(split == 0 && refused == 0, "DS6 owed_digest equal on W, R1, R2 after every block; 0 lane_root_refused");
        C(holds == 3 && fetched == 4, "DS6 exactly the members a node lacked were fetched: W and R2 lacked R1's own raindrop at h=170, R2 lacked 2 at h=210 (3 holds, 4 ids)");
    }

    // ── DS3 RESTART: members fetched by id over loopback ─────────────────────
    std::printf("DS3: a restarted receiver (empty store) fetches exactly the pinned members by id from a peer\n");
    {
        const ::v37::ScriptRef pA = payee_of("A");
        std::vector<bytes32> prev(8);
        for (int i = 0; i < 8; ++i) prev[i] = b32_of(static_cast<u8>(100 + i));
        std::string why;
        RNode A(ropts(true, {}, 64));
        C(A.relay->start(why), "DS3 A starts " + why);
        for (int i = 0; i < 8; ++i) A.note_bin(prev[i], 100 + i);
        std::vector<Admitted> dropsA;
        for (int b = 0; b < 3; ++b) {
            const SynthBlock blk = make_block(100 + b, prev[b], 1 + b, nullptr, 3, 10 + b);
            for (std::uint32_t k = 0; k < 2; ++k) dropsA.push_back(drop_on(blk, kDropNonce + 16 * b + k, pA));
        }
        for (auto& a : dropsA) A.relay->submit_own_drop(a);
        RNode B(ropts(true, {A.relay->listen_port()}, 0));   // hello_bins 0: no inventory pull of [100,103)
        for (int i = 0; i < 8; ++i) B.note_bin(prev[i], 100 + i);
        C(B.relay->start(why), "DS3 B (restarted: empty store, empty harvest) dials A " + why);
        C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, {&A, &B}),
          "DS3 HELLO: A-B up");
        std::vector<bytes32> pinned;   // the winner's set names 4 of A's 6 raindrops
        for (int i : {0, 1, 3, 4}) pinned.push_back(dropsA[static_cast<std::size_t>(i)].id);
        std::sort(pinned.begin(), pinned.end());
#if defined(C2POOL_XMR_DROPS_SET_PIN)
        const bool got = wait_for([&] {   // the shell's loop: ask only for the members the harvest still lacks
            std::set<bytes32> d(B.drained.begin(), B.drained.end());
            std::vector<bytes32> miss;
            for (const auto& x : pinned) if (!d.count(x)) miss.push_back(x);
            B.relay->drops_fetch_ids(miss, 0, 100, 103);
            return miss.empty();
        }, {&A, &B});
        std::this_thread::sleep_for(500ms); B.pump();
        std::set<bytes32> d(B.drained.begin(), B.drained.end());
        std::printf("    B drained %zu raindrop(s); asked 4; fetch ids=%llu backfilled=%llu rx=%llu\n", d.size(),
                    (unsigned long long)B.relay->stats().drops_pin_fetch_ids.load(),
                    (unsigned long long)B.relay->stats().drops_backfilled.load(), (unsigned long long)B.rx_calls.load());
        C(got && d == std::set<bytes32>(pinned.begin(), pinned.end()),
          "DS3 B holds EXACTLY the 4 pinned members (never A's 2 other raindrops of the same bins)");
        C(B.relay->stats().drops_backfilled.load() == 4 && B.rx_calls.load() == 4,
          "DS3 each member arrived solicited and was RandomX-verified once (admit_drop)");
        // a member the dedup set remembers but the caller lacks is fetched again (its bytes are needed)
        B.drained.clear();
        std::this_thread::sleep_for(350ms);
        const bool again = wait_for([&] {
            B.relay->drops_fetch_ids({pinned[0]}, 0, 100, 103);
            return std::find(B.drained.begin(), B.drained.end(), pinned[0]) != B.drained.end();
        }, {&A, &B}, 5000ms);
        C(again, "DS3 an id already seen here is re-admitted when the harvest asks for it (the dedup entry is forgotten)");
#else
        C(false, "DS3 no fetch by id on the base (drops_sync pulls whole range inventories: never exactly the pinned set)");
#endif
    }
    return C.done("v37_xmr_drops_set_kat");
}
