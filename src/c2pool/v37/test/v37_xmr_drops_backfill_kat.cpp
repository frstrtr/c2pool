// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_backfill_kat -- RAIN-BACKFILL (DROPS defect 3).
//
// With the DROPS flip at 1, XMR raindrops are flooded ONCE and never re-sent:
// a node that was partitioned, joined late or restarted harvests a different
// set, and because DropHarvester::take_buried() consumes in BOOKING order, a
// 1-deep reorg (own sibling booked, then the canonical block) composes the
// canonical block from an EMPTY harvest. Either way owed_digest forks.
//
// Two in-process XmrRelayNode instances over REAL loopback TCP (fake RandomX:
// nonce >= kDropNonce hashes to a RAINDROP -- above the drops floor, below
// share_diff) and the XmrDropsWiring harvest driven through the XmrNode seam
// shape:
//
//   B1  LATE JOIN: A floods 12 raindrops before B exists; B joins and, after
//       drops_sync over their intervals, holds exactly A's set (all 12
//       backfilled, RandomX-verified, solicited) -- base: B holds 0
//   B2  HOLD: a partitioned node's drops_sync is NOT complete (no ready peer)
//       -- the composition holds instead of composing a partial set
//   B3  PARTITION: both sides mint during a partition; after the heal
//       drops_sync on both leaves A and B with the SAME raindrop set
//   B4  FLIP 0: drops_floor_diff == 0 -> submit_own_drop is inert, drops_sync
//       is complete with no I/O, no FB_GETDROPS/FB_DROPINV is ever sent, and
//       a gate-OFF node that receives one counts it as an unknown Family-B
//       opcode and keeps the socket (master's behaviour)
//   H1  REORG: a node that books its own sibling Y at h and then the
//       canonical X at h composes X from the SAME rows (and the same credit) as
//       a node that only ever booked X -- base: the second booking is empty
//   H2  CHAIN ORDER: the rows of every canonical booking of a longer chain with
//       a 1-deep reorg in the middle equal those of a node that booked only the
//       canonical chain
//
// RED on the base (no drops_sync / no chain-ordered harvest: the base branch
// below exercises the base's only mechanisms -- flood + take_buried() -- and
// the checks fail); GREEN on the fix.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <sharechain/v37/v37_descriptor_xmr.hpp>

using namespace gap2test;
using namespace std::chrono_literals;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr std::uint32_t kDropNonce = 0x40000000u;

struct RNode {
    std::string name;
    ChainView chain;
    std::atomic<u64> rx_calls{0};
    std::unique_ptr<XmrRelayNode> relay;
    std::vector<std::string> logs;
    std::mutex log_mtx;
    RNode(std::string n, RelayOptions ro) : name(std::move(n)) {
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
                if (nonce >= kDropNonce) pow[31] = 0x02;   // 2^249: meets diff 10, fails diff 1000 -> a RAINDROP
                return true;
            },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(log_mtx); logs.push_back(l); });
    }
    ~RNode() { relay->stop(); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    std::vector<bytes32> drained;
    void pump() { for (auto& a : relay->drain_drops()) drained.push_back(a.id); }
};

static RelayOptions opts(bool listen, std::vector<u16> dial, u64 floor_diff) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = floor_diff;
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
    if (!mint_on(sb, nonce, payee, kChain, kShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    a.pow.fill(0); a.pow[31] = 0x02;
    return a;
}

#if defined(C2POOL_XMR_RAIN_BACKFILL)
static bool sync_until(RNode& n, u64 lo, u64 hi, std::vector<RNode*> pump, std::chrono::milliseconds limit = 15000ms) {
    return wait_for([&] { return n.relay->drops_sync(lo, hi).complete; }, std::move(pump), limit);
}
static std::vector<bytes32> held(RNode& n, u64 lo, u64 hi) { return n.relay->drops_held(lo, hi); }
static u64 backfilled(RNode& n) { return n.relay->stats().drops_backfilled.load(); }
static u64 served(RNode& n) { return n.relay->stats().drops_served.load(); }
static u64 new_frames_tx(RNode& n) {
    const auto& s = n.relay->stats();
    return s.drops_invreq_tx.load() + s.drops_inv_tx.load() + s.drops_fetch_tx.load() + s.drops_served.load();
}
#else
// BASE: no backfill exists; the only recovery is the flood itself.
static bool sync_until(RNode&, u64, u64, std::vector<RNode*> pump, std::chrono::milliseconds = 15000ms) {
    wait_for([] { return false; }, std::move(pump), 3000ms);
    return false;
}
static std::vector<bytes32> held(RNode& n, u64, u64) { auto v = n.drained; std::sort(v.begin(), v.end()); return v; }
static u64 backfilled(RNode&) { return 0; }
static u64 served(RNode&) { return 0; }
static u64 new_frames_tx(RNode&) { return 0; }
#endif

// ── the harvest side: the XmrNode seam shape (buried_harvest + compose) ─────
struct HNode {
    ::c2pool::v37n::DropHarvester* harvester = nullptr;
    const ::c2pool::v37n::EnrollmentBook* book = nullptr;
    std::function<void(std::uint64_t)> pre_harvest;
    std::function<st::WorkPrice()> price;
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester* h) { harvester = h; }
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook* b) { book = b; }
    void set_pre_harvest(std::function<void(std::uint64_t)> f) { pre_harvest = std::move(f); }
    void set_drops_price_fn(std::function<st::WorkPrice()> f) { price = std::move(f); }
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
    // XmrNode::on_network_block_won's DROPS body (buried_harvest), both arms
    std::vector<st::HarvestedReceipt> harvest(std::uint64_t won, std::uint64_t d_conf) {
        if (!harvester) return {};
        if (range) return range(won);
        const std::uint64_t frontier = won > d_conf ? won - d_conf : 0;
        if (pre_harvest) pre_harvest(frontier);
        return harvester->take_buried(frontier);
    }
};
static std::string rows_key(const std::vector<st::HarvestedReceipt>& rows, const std::map<::v37::bytes32, long long>& credit) {
    std::string s = std::to_string(rows.size()) + ":";
    for (const auto& r : rows) s += hex(r.payee).substr(0, 8) + "@" + std::to_string(r.interval) + ",";
    s += "|";
    for (const auto& [k, v] : credit) s += hex(k).substr(0, 8) + "=" + std::to_string(v) + ",";
    return s;
}
static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = static_cast<unsigned __int128>(n_shares);
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.valid = true;
    return wp;
}
struct Harness {
    std::unique_ptr<dx::XmrDropsWiring> w;
    HNode node;
    ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    static constexpr std::uint64_t kD = 10;
    Harness(const std::vector<bytes32>& enrol) {
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, 1024, 1);
        w->attach(node);
#if defined(C2POOL_XMR_RAIN_BACKFILL)
        w->attach_chain_order(node, kD);
#endif
#if defined(C2POOL_XMR_HARVEST_CHAIN_PURE)
        // RAIN-BACKFILL-2: the canonical chain of H1/H2 carries lane blocks at
        // 1030, 1033, 1034, 1038 (the shell answers this from the best chain)
        w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
            static const std::set<std::uint64_t> lanes = {1030, 1033, 1034, 1038};
            auto it = lanes.lower_bound(h);
            if (it == lanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
#endif
        w->observe_native_tip(1000);
        for (const auto& p : enrol) w->enroll_at_tip(p);
        w->arm_at_tip();
    }
    std::string book(std::uint64_t won) {
        w->set_cut_price(price_of(600000000000ULL, 1000));
        const auto rows = node.harvest(won, kD);
        st::DropsCompose dctx; dctx.price = node.price ? node.price() : st::WorkPrice{}; dctx.enrollment = node.book;
        return rows_key(rows, st::subthreshold_credit(params, rows, dctx));
    }
};

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_backfill_kat (RAIN-BACKFILL %s) ==\n",
#if defined(C2POOL_XMR_RAIN_BACKFILL)
                "present"
#else
                "ABSENT: base mechanisms only"
#endif
    );
    const ::v37::ScriptRef pA = payee_of("A"), pB = payee_of("B");
    std::vector<bytes32> prev(12);
    for (int i = 0; i < 12; ++i) prev[i] = b32_of(static_cast<u8>(100 + i));
    std::string why;

    // ── B1 LATE JOIN ────────────────────────────────────────────────────────
    RNode A("A", opts(true, {}, kFloorDiff));
    C(A.relay->start(why), "A starts (listen, drops floor " + std::to_string(kFloorDiff) + ") " + why);
    for (int i = 0; i < 8; ++i) A.note_bin(prev[i], 100 + i);
    std::vector<Admitted> dropsA;
    for (int b = 0; b < 4; ++b) {
        const SynthBlock blk = make_block(100 + b, prev[b], 1 + b, nullptr, 3, 10 + b);
        for (std::uint32_t k = 0; k < 3; ++k) dropsA.push_back(drop_on(blk, kDropNonce + 16 * b + k, pA));
    }
    for (auto& a : dropsA) A.relay->submit_own_drop(a);
    C(A.relay->stats().drops_own.load() == 12, "B1 A minted + flooded 12 raindrops over bins 100..103 (nobody listening)");
    const u16 portA = A.relay->listen_port();
    RNode B("B", opts(true, {portA}, kFloorDiff));
    for (int i = 0; i < 8; ++i) B.note_bin(prev[i], 100 + i);
    C(B.relay->start(why), "B1 B joins LATE, dials A " + why);
    C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, {&A, &B}),
      "B1 HELLO: A-B up");
    const bool b1 = sync_until(B, 100, 104, {&A, &B});
    std::vector<bytes32> idsA; for (auto& a : dropsA) idsA.push_back(a.id); std::sort(idsA.begin(), idsA.end());
    const auto hb = held(B, 100, 104);
    std::printf("    B holds %zu/12 of A's raindrops for [100,104); backfilled=%llu served_by_A=%llu B rx=%llu\n", hb.size(),
                (unsigned long long)backfilled(B), (unsigned long long)served(A), (unsigned long long)B.rx_calls.load());
    C(b1, "B1 drops_sync(100,104) at B completes");
    C(hb == idsA, "B1 ★ the late joiner holds EXACTLY A's raindrop set (12)");
    C(backfilled(B) == 12 && B.rx_calls.load() == 12,
      "B1 all 12 arrived as solicited backfill, each RandomX-verified once");
    { std::sort(B.drained.begin(), B.drained.end()); B.drained.erase(std::unique(B.drained.begin(), B.drained.end()), B.drained.end()); }
    C(B.drained.size() == 12, "B1 all 12 reached B's harvest queue (drain_drops)");

    // ── B2 HOLD while partitioned ───────────────────────────────────────────
    B.relay->partition_for(std::chrono::seconds(3));
    C(wait_for([&] { return B.relay->ready_peers().empty(); }, {&A, &B}, 5000ms), "B2 B partitioned (no ready peer)");
#if defined(C2POOL_XMR_RAIN_BACKFILL)
    {
        const auto ds = B.relay->drops_sync(100, 106);
        std::printf("    B partitioned: drops_sync complete=%d why=%s\n", (int)ds.complete, ds.why.c_str());
        C(!ds.complete && ds.why.find("no ready relay peer") != std::string::npos,
          "B2 ★ a partitioned node HOLDS (drops_sync incomplete: no ready relay peer), never composes a partial set");
    }
#else
    C(false, "B2 a partitioned node HOLDS (base: no drops_sync exists)");
#endif
    // ── B3 PARTITION: both mint while apart ────────────────────────────────
    std::vector<Admitted> pa, pb;
    {
        const SynthBlock blkA = make_block(104, prev[4], 9, nullptr, 3, 30);
        const SynthBlock blkB = make_block(104, prev[4], 10, nullptr, 3, 31);
        for (std::uint32_t k = 0; k < 5; ++k) pa.push_back(drop_on(blkA, kDropNonce + 0x1000 + k, pA));
        for (std::uint32_t k = 0; k < 4; ++k) pb.push_back(drop_on(blkB, kDropNonce + 0x2000 + k, pB));
    }
    for (auto& a : pa) A.relay->submit_own_drop(a);
    for (auto& a : pb) B.relay->submit_own_drop(a);
    C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, {&A, &B}, 20000ms),
      "B3 partition healed (B redials A)");
    const bool sa = sync_until(A, 100, 106, {&A, &B});
    const bool sb = sync_until(B, 100, 106, {&A, &B});
    const auto ha = held(A, 100, 106), hb2 = held(B, 100, 106);
    std::printf("    after heal: A holds %zu, B holds %zu (want 21 each); A backfilled=%llu B backfilled=%llu\n", ha.size(), hb2.size(),
                (unsigned long long)backfilled(A), (unsigned long long)backfilled(B));
    C(sa && sb, "B3 drops_sync(100,106) completes on BOTH sides after the heal");
    C(ha == hb2 && ha.size() == 21, "B3 ★ A and B hold the SAME raindrop set (12 + 5 + 4 = 21) after the partition");

    // ── B4 FLIP 0 ───────────────────────────────────────────────────────────
    {
        RNode Z0("Z0", opts(true, {}, 0));
        C(Z0.relay->start(why), "B4 Z0 (drops OFF) starts " + why);
        RNode Y0("Y0", opts(false, {Z0.relay->listen_port()}, 0));
        for (int i = 0; i < 8; ++i) { Z0.note_bin(prev[i], 100 + i); Y0.note_bin(prev[i], 100 + i); }
        C(Y0.relay->start(why), "B4 Y0 (drops OFF) dials Z0 " + why);
        C(wait_for([&] { return Z0.relay->ready_peers().size() == 1 && Y0.relay->ready_peers().size() == 1; }, {&Z0, &Y0}),
          "B4 HELLO: Z0-Y0 up");
        Y0.relay->submit_own_drop(dropsA[0]);
#if defined(C2POOL_XMR_RAIN_BACKFILL)
        const bool trivially = Y0.relay->drops_sync(100, 104).complete && Y0.relay->stats().drops_sync_calls.load() == 0;
#else
        const bool trivially = true;
#endif
        std::this_thread::sleep_for(500ms);
        const auto& zs = Z0.relay->stats(); const auto& ys = Y0.relay->stats();
        const u64 z_new = new_frames_tx(Z0), y_new = new_frames_tx(Y0);
        std::printf("    flip-0 pair: new-frame tx Z0=%llu Y0=%llu fb_unknown Z0=%llu Y0=%llu drops_own=%llu\n",
                    (unsigned long long)z_new, (unsigned long long)y_new, (unsigned long long)zs.fb_unknown.load(),
                    (unsigned long long)ys.fb_unknown.load(), (unsigned long long)ys.drops_own.load());
        C(trivially && z_new == 0 && y_new == 0 && zs.fb_unknown.load() == 0 && ys.fb_unknown.load() == 0 && ys.drops_own.load() == 0,
          "B4 flip 0: no FB_GETDROPS/FB_DROPINV sent or received, submit_own_drop inert, drops_sync complete with no I/O");
        // a gate-ON node dialing a gate-OFF node: Z0 counts the 0x45 as unknown, keeps the socket
        RNode W1("W1", opts(false, {Z0.relay->listen_port()}, kFloorDiff));
        for (int i = 0; i < 8; ++i) W1.note_bin(prev[i], 100 + i);
        C(W1.relay->start(why), "B4 W1 (drops ON) dials Z0 (drops OFF)");
        const bool unk = wait_for([&] { return Z0.relay->stats().fb_unknown.load() >= 1; }, {&Z0, &W1}, 5000ms);
        std::this_thread::sleep_for(300ms);
        C(unk && Z0.relay->ready_peers().size() == 2 && Z0.relay->stats().bans.load() == 0,
          "B4 a gate-OFF node counts FB_GETDROPS as an unknown Family-B opcode and keeps the socket (fb_unknown=" +
          std::to_string(Z0.relay->stats().fb_unknown.load()) + ")");
        W1.relay->set_dialing(false); Y0.relay->set_dialing(false);
    }

    // ── H1 / H2: consumption follows the chain ─────────────────────────────
    {
        const bytes32 P = ::v37::xmr::xmr_identity_key(pA), Q = ::v37::xmr::xmr_identity_key(pB);
        auto feed = [&](Harness& h) {
            std::mt19937_64 rng(0xBACF111ULL);
            for (std::uint64_t iv = 1002; iv < 1040; ++iv) {
                h.w->observe_native_tip(iv - 1);
                for (const bytes32& who : {P, Q}) {
                    for (int k = 0; k < 40; ++k) {
                        bytes32 hsh{};
                        for (int wd = 0; wd < 4; ++wd) { const std::uint64_t v = rng(); std::memcpy(hsh.data() + wd * 8, &v, 8); }
                        hsh[31] = static_cast<std::uint8_t>(1 + (hsh[31] % 15));   // H in [2^248, 2^252): a raindrop at share_diff 1024
                        h.w->on_raindrop(who, iv, hsh);
                    }
                    if ((iv + (who == P ? 0 : 1)) % 3 == 0) h.w->on_share_pushed(who, iv);
                }
            }
        };
        Harness X({P, Q}), Y({P, Q});
        feed(X); feed(Y);
        // X: books its own sibling at 1030, then (1-deep reorg) the canonical block at 1030
        const std::string x_sib = X.book(1030);
        const std::string x_can = X.book(1030);
        const std::string y_can = Y.book(1030);
        std::printf("    H1 node X sibling@1030 rows %s\n    H1 node X canonical@1030 rows %s\n    H1 node Y canonical@1030 rows %s\n",
                    x_sib.substr(0, 60).c_str(), x_can.substr(0, 60).c_str(), y_can.substr(0, 60).c_str());
        C(y_can.rfind("0:", 0) != 0, "H1 the canonical composition has harvest rows (non-trivial)");
        C(x_can == y_can, "H1 ★ after a 1-deep reorg the canonical block composes the SAME rows + credit as on a node that never saw the sibling");
        // H2: continue both chains; X also sees a sibling at 1034 that the chain replaces
        const std::string x1 = X.book(1033), y1 = Y.book(1033);
        (void)X.book(1034);
        const std::string x2 = X.book(1034), y2 = Y.book(1034);
        const std::string x3 = X.book(1038), y3 = Y.book(1038);
        C(x1 == y1 && x2 == y2 && x3 == y3,
          "H2 ★ every canonical booking of the longer chain (1033, 1034 after a reorg, 1038) composes identically on both nodes");
    }

    return C.done("v37_xmr_drops_backfill_kat");
}
