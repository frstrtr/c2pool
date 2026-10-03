// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_retain_kat -- DROPS-RETAIN (stagenet attempt 6, 2026-10-02).
//
// THE DEFECT. Node A found lane block h=2220425 and pinned 16384 raindrop ids
// of its range [2220334, 2220365) from its HARVEST. The range of a block is
// [prev_lane - D_conf, h - D_conf): with D_conf 60 every member was 112-160 min
// old at the find, while the servable relay store (a 65536-raindrop COUNT cap,
// ~73 min at 15 raindrops/s) had evicted all of them on every node, the finder
// included (raindrops_held=0, served=0). B and C, missing 6 and 4 members,
// could never fetch them: after 600 retries booking_stall_timeout REFUSED the
// block into node-local liability while A booked it -- an owed-ledger split.
//
// THE FIX (node-local; lane rules, the range, members_of and the wire unchanged):
//   L1  the store is bounded by BYTES (512 MiB) and a floor keyed to this node's
//       finalize cursor (frontier of the newest finalized lane block - 64), not
//       by a count; persisted as per-bin append-only segments, loaded newest
//       first up to the budget.
//   L2  the winner pins only what its store can serve; every pinned set is
//       retained (never evicted) until its block is decided here.
//   L3  "pinned raindrop(s) not held" / "not carried yet" HOLD, never a
//       retry-count refusal (v37_xmr_relay_repair_hold_kat K1/K1b).
//
//   R1  ATTEMPT-6 SHAPE (defaults, D_conf 60): 3 relay nodes over loopback; the
//       pool mines 66,000 raindrops past the range (today's store: 65536)
//       before the find; B
//       restarts (harvest rebuilt from its persisted store), C lost 2 members of
//       the flood. B and C book EXACTLY A's set and delta within the booking
//       retry bound; owed_digest equal on A/B/C (base: B and C cannot fetch a
//       single evicted member, served=0 -> refused -> split, RED).
//   R2  OVERFLOW SHAPE (a store too small for the window, same knob on both
//       trees): the winner pins only servable members (L2a) and every node
//       retains the set (L2b) while more raindrops arrive; B (restarted) and C
//       book identically (base: pinned members evicted -> refused -> split).
//   R3  L2a: harvest 12 / store 8 -> the pin is the 8 servable ids, skipped=4.
//   R4  L2b: a retained set survives 3 budgets of newer raindrops and is served
//       by id; after release its bins evict.
//   R5  L1: the floor evicts below it even under budget and keeps everything
//       above it; over the byte budget the oldest unretained bins go (counted);
//       a reload over budget keeps the NEWEST bins (base: a file over the count
//       bound was ignored whole).
//   R6  K6 backfill paging: a peer holding 20,000 ids of a range; every id is
//       fetched (base: inventory truncated at 16384 -> "complete", 3,616 never
//       asked).
//   R7  K7 segments: one changed bin = one segment appended (others untouched);
//       a torn tail keeps the valid prefix; another lane's segment is ignored.
//   R8  source pins: the shell wires L1/L2 (pin servable, retain at admission
//       and boot, release at forget, the floor at each finalize step, the knob).
//   R9-R12 ★ HOLD-ROUND-2 (C), the attempt-7 re-ask storm: R9 one bin of
//       20,000 raindrops is paged by cursor (base: 3,616 never asked); R10 a
//       fetched raindrop this node cannot admit counts as held (base: re-asked
//       forever); R11 the ask budget is per NODE and survives reconnects (base:
//       reset at every disconnect, never set aside); R12 the minter refuses a
//       raindrop on a job the chain passed (base: minted).
//
// RED on the base (ed360c4c), GREEN on the fix.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
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

static constexpr u32 kChain = 7;
static constexpr u64 kRelayShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr std::uint32_t kDropNonce = 0x40000000u;
static constexpr std::uint64_t kD = 60;            // D_conf: the #1894 floor off regtest, and mainnet's
static constexpr std::uint32_t kPushes = 2;
static constexpr std::uint64_t kRetryBound = 40;   // booking attempts before the base REFUSES (production: 600 x ~5 s)

static std::string slurp(const std::string& p) { std::ifstream f(p, std::ios::binary); std::stringstream ss; ss << f.rdbuf(); return ss.str(); }
static bytes32 pid_of(std::uint64_t bin) { bytes32 b{}; b[0] = 0xEE; std::memcpy(b.data() + 8, &bin, 8); return b; }
static std::optional<std::uint64_t> bin_of_pid(const bytes32& pid) { std::uint64_t b = 0; std::memcpy(&b, pid.data() + 8, 8); return b; }

struct HNode {   // the XmrNode seam shape (as the set KAT)
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester*) {}
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook*) {}
    void set_pre_harvest(std::function<void(std::uint64_t)>) {}
    void set_drops_price_fn(std::function<st::WorkPrice()>) {}
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
};
// fake RandomX: nonce >= kDropNonce hashes to a RAINDROP (difficulty ~128: over the floor 10, under the
// share 1000), bytes 24..27 = the nonce so every raindrop has its own (normalised) hash
static bool fake_rx(const std::vector<u8>& blob, bytes32& pow) {
    u32 nonce = 0;
    ::v37::xmr::HashingBlob hb; hb.bytes = blob;
    ::v37::xmr::verify::ParsedBlob pb;
    if (::v37::xmr::verify::parse_hashing_blob(hb, pb))
        for (int i = 0; i < 4; ++i) nonce |= static_cast<u32>(blob[pb.header_len - 4 + i]) << (8 * i);
    pow.fill(0);
    if (nonce >= kDropNonce) { pow[31] = 0x02; std::memcpy(pow.data() + 24, &nonce, 4); }   // high bytes: survive normalisation
    return true;
}

// One node: a relay (servable store, loopback TCP) + its harvest (the composition store),
// fed from drain_drops() exactly as the daemon does (on_raindrop_id: the receipt id).
static bytes32 prev_of(std::uint64_t bin) { bytes32 b{}; b[0] = 0xB1; b[1] = 0x75; std::memcpy(b.data() + 8, &bin, 8); return b; }
static std::set<std::uint64_t> g_lanes;   // lane blocks on the canonical chain (the prev_lane walk)
struct Node {
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<dx::XmrDropsWiring> w;
    HNode hn;
    ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    std::set<bytes32> lose;          // flood loss into the harvest: each id dropped ONCE (a later fetch is kept)
    std::size_t drained = 0;
    explicit Node(RelayOptions ro, std::uint64_t tip) {
        relay = std::make_unique<XmrRelayNode>(
            ro, chain, [](const std::vector<u8>& blob, const bytes32&, bytes32& pow) { return fake_rx(blob, pow); },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; }, [](const std::string&) {});
        for (std::uint64_t b = 90; b <= tip; ++b) chain.note(prev_of(b), b, bytes32{});
        chain.set_tip(tip);
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kRelayShareDiff, 1);
        w->attach(hn);
        w->attach_chain_order(hn, kD);
        w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
            auto it = g_lanes.lower_bound(h);
            if (it == g_lanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
        w->observe_native_tip(100);
        w->set_enrol_mode(dx::EnrolMode::Auto);
    }
    ~Node() { relay->stop(); }
    void tip(std::uint64_t t) { for (std::uint64_t b = 90; b <= t; ++b) chain.note(prev_of(b), b, bytes32{}); chain.set_tip(t); }
    void pump() {
        for (auto& a : relay->drain_drops()) {
            ++drained;
            if (lose.erase(a.id)) continue;
            (void)w->on_raindrop_id(a.id, a.r.payee, a.bin, a.pow);
        }
    }
    void feed_order(const std::vector<std::pair<bytes32, std::uint64_t>>& order) {   // (identity, bin): one lane receipt each
        std::uint64_t pos = 0;
        for (const auto& [who, bin] : order) { w->on_share_lane(who, bin, pos, kPushes, pid_of(bin), 0); pos += kPushes; }
    }
    struct Out { bool ok = false; std::vector<bytes32> set, missing; std::string refused; std::map<bytes32, long long> delta; std::size_t rows = 0; };
    // THE booking composition of lane block h at cut P (the daemon's drops_compose_lane):
    // pin == nullptr = this node is the winner; else the winner's carried set.
    Out compose(std::uint64_t h, std::uint64_t P, const std::vector<bytes32>* pin, const std::string& bid) {
        Out o;
        const auto rg = w->range_for(h);
        std::string why;
        const auto lp = w->own_prefix(P, bin_of_pid, &why);
        if (!rg || !lp) { o.refused = "undecidable: " + why; return o; }
        if (pin) o.set = *pin;
        else {
#if defined(C2POOL_XMR_DROPS_RETAIN)
            o.set = relay->drops_pin_servable(bid, w->pinned_ids(rg->first, rg->second, SIZE_MAX), rl::kBlockWonSetMaxIds);
#else
            (void)bid;   // BASE: the winner pins what its HARVEST holds, servable or not
            o.set = w->pinned_ids(rg->first, rg->second, rl::kBlockWonSetMaxIds);
#endif
        }
        auto pc = w->compose_lane_pinned(rg->first, rg->second, *lp, o.set);
        o.missing = pc.missing; o.refused = pc.refused;
        if (!o.missing.empty()) return o;   // HOLD (the caller fetches by id)
        st::WorkPrice wp; wp.reward = 600000000000ULL;
        wp.sum_weight.v[0] = static_cast<std::uint64_t>(static_cast<unsigned __int128>(1000) << 62);
        wp.sum_weight.v[1] = static_cast<std::uint64_t>(static_cast<unsigned __int128>(1000) >> 2);
        wp.valid = true;
        st::DropsCompose dctx; dctx.price = dx::rescale_price(wp, 1);
        dctx.enrollment = &pc.lc.book;
        if (!o.refused.empty()) pc.lc.rows.clear();
        const auto carry = dx::compose_carry(params, pc.lc.rows, dctx);
        o.ok = true; o.rows = pc.lc.rows.size(); o.delta = carry.delta;
        return o;
    }
};
// The owed ledger of one node: the V37Q owed digest of what it booked (a refusal books nothing:
// its payout is node-local liability, exactly the attempt-6 outcome).
struct Ledger {
    std::map<std::array<std::uint8_t, 32>, long long> fw;
    std::size_t booked = 0, refused = 0;
    void book(const std::map<bytes32, long long>& d) {
        for (const auto& [k, v] : d) { std::array<std::uint8_t, 32> a{}; std::memcpy(a.data(), k.data(), 32); fw[a] += v; }
        ++booked;
    }
    std::string digest() const {
        const auto d = ::c2pool::v37::subthreshold::owed_digest(fw, {});
        bytes32 b{}; std::memcpy(b.data(), d.data(), 32);
        return hex(b);
    }
};

static RelayOptions ropts(std::vector<u16> dial, const std::string& persist = "") {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kRelayShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kRelayShareDiff, BindMode::None);
    o.listen = true; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = kFloorDiff;
    o.drops_hello_bins = 0;            // no inventory pull: only floods and by-id fetches move raindrops
    o.drops_fetch_retry_ms = 100;
    o.drops_fetch_max_asks = 8;
    o.drops_fetch_slow_ms = 1000;
    o.drops_persist_path = persist;
    return o;
}
template <class F>
static bool wait_for(F cond, std::vector<Node*> pump, std::chrono::milliseconds limit = 20000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(10ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
// raindrop k of `bin` paid to `payee` (a receipt minted on that bin's synthetic block)
static Admitted drop_at(std::uint64_t bin, std::uint32_t k, const ::v37::ScriptRef& payee) {
    static std::map<std::uint64_t, SynthBlock> blocks;   // one synthetic block per bin (main thread only)
    auto bi = blocks.find(bin);
    if (bi == blocks.end())
        bi = blocks.emplace(bin, make_block(bin, prev_of(bin), 1 + static_cast<std::uint32_t>(bin), nullptr, 3, static_cast<u8>(bin))).first;
    const SynthBlock& sb = bi->second;
    Admitted a; std::string why;
    const std::uint32_t nonce = kDropNonce + k;
    if (!mint_on(sb, nonce, payee, kChain, kRelayShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = bin; a.own = true;
    fake_rx(with_nonce(sb, nonce), a.pow);
    return a;
}
static const ::v37::ScriptRef& payee_n(std::size_t i) {
    static const std::vector<::v37::ScriptRef> v = {payee_of("drA"), payee_of("drB"), payee_of("drC"), payee_of("drD")};
    return v[i % v.size()];
}
static bytes32 ident_n(std::size_t i) { return ::v37::xmr::xmr_identity_key(payee_n(i)); }
// the replicated lane order: every payee one receipt per bin in [100, 140) (enrolled by its first
// share); from bin 140 on only payees 2 and 3 find shares, so payees 0 and 1 are paid by their
// raindrops alone (S = 0: the sub-threshold work the DROPS delta exists to credit)
static bool in_order(std::uint64_t b, std::size_t i) { return b < 140 || i >= 2; }
static std::vector<std::pair<bytes32, std::uint64_t>> lane_order(std::uint64_t hi) {
    std::vector<std::pair<bytes32, std::uint64_t>> v;
    for (std::uint64_t b = 100; b < hi; ++b) for (std::size_t i = 0; i < 4; ++i) if (in_order(b, i)) v.emplace_back(ident_n(i), b);
    return v;
}
static std::uint64_t cut_at(std::uint64_t bin) {
    std::uint64_t n = 0;
    for (std::uint64_t b = 100; b < bin; ++b) for (std::size_t i = 0; i < 4; ++i) n += in_order(b, i);
    return n * kPushes;
}

// A 3-node mesh: A and C listen, B dials both, C dials A. Raindrops of a bin are submitted at
// node (payee % 3) and flooded; the caller waits until every store saw them.
struct Mesh {
    std::unique_ptr<Node> A, B, C;
    std::string bpath;
    RelayOptions base;
    bool up = false;
    Mesh(RelayOptions o, const std::string& persist_b, std::uint64_t tip) : bpath(persist_b), base(o) {
        std::string why;
        A = std::make_unique<Node>(o, tip);
        up = A->relay->start(why);
        auto oc = o; oc.peers.emplace_back("127.0.0.1", A->relay->listen_port());
        C = std::make_unique<Node>(oc, tip);
        up = up && C->relay->start(why);
        B = make_b(tip);
        up = up && B->relay->start(why) &&
             wait_for([&] { return A->relay->ready_peers().size() == 2 && B->relay->ready_peers().size() == 2 &&
                                   C->relay->ready_peers().size() == 2; }, {}, 10000ms);
    }
    std::unique_ptr<Node> make_b(std::uint64_t tip) {
        auto ob = base; ob.drops_persist_path = bpath;
        ob.peers.emplace_back("127.0.0.1", A->relay->listen_port());
        ob.peers.emplace_back("127.0.0.1", C->relay->listen_port());
        return std::make_unique<Node>(ob, tip);
    }
    std::vector<Node*> all() { return {A.get(), B.get(), C.get()}; }
    void tip(std::uint64_t t) { for (auto* n : all()) n->tip(t); }
    // submit + flood; true once every node admitted them (store or dedup)
    bool flood(const std::vector<Admitted>& v) {
        std::vector<u64> want;
        for (auto* n : all()) want.push_back(n->drained + v.size());
        std::size_t i = 0;
        for (const auto& a : v) { Node* at = all()[i++ % 3]; at->relay->submit_own_drop(a); }
        return wait_for([&] { for (std::size_t k = 0; k < 3; ++k) if (all()[k]->drained < want[k]) return false; return true; }, all(), 30000ms);
    }
};

// ── R1 / R2: the attempt-6 timeline ─────────────────────────────────────────
// range [100,170) of lane block h=230 (prev lane 160, D_conf 60): 4 raindrops per bin (one per payee);
// load1 = bins [170, l1_hi) x n1 BEFORE the find; load2 = bins [l1_hi, 230) x n2 after it; then B
// restarts (its harvest is rebuilt from its persisted store) and C (2 members lost in the flood)
// and B book A's carried set, each within kRetryBound attempts (fetching missing members by id).
struct Shape { const char* tag; RelayOptions o; std::uint64_t l1_hi; std::uint32_t n1; std::uint32_t n2; };
static void run_shape(Checker& C, const Shape& sh, const std::string& dir) {
    std::printf("%s: D_conf=%llu range [100,170) of h=230; load %u/bin over [170,%llu) before the find, %u/bin after; "
                "store count bound=%zu\n", sh.tag, (unsigned long long)kD, sh.n1, (unsigned long long)sh.l1_hi, sh.n2,
                sh.o.drops_store_max);
    g_lanes = {160, 230};
    const std::string bid = "a6" + std::string(62, '0') + sh.tag;
    Mesh m(sh.o, dir + "/" + sh.tag + "-lane7.drops", 101);
    C(m.up, std::string(sh.tag) + " the 3-node mesh is up (A, B, C over loopback)");
    if (!m.up) return;
    // the range's raindrops sit in bins [140,170): payees 0 and 1 mine K+1 = 5 per bin (estimator rows),
    // payees 2 and 3 one (share-weighted rows): 12 per bin, 360 in all
    std::vector<Admitted> range;
    for (std::uint64_t b = 140; b < 170; ++b)
        for (std::uint32_t i = 0; i < 4; ++i)
            for (std::uint32_t j = 0; j < (i < 2 ? 5u : 1u); ++j) range.push_back(drop_at(b, i * 8 + j, payee_n(i)));
    for (std::size_t i = 0; i < range.size(); ++i) if (range[i].bin == 160 && m.C->lose.size() < 2) m.C->lose.insert(range[i].id);
    bool flooded = true;
    for (std::uint64_t b = 100; b < 170; ++b) {
        m.tip(b + 1);
        std::vector<Admitted> v; for (const auto& a : range) if (a.bin == b) v.push_back(a);
        flooded = m.flood(v) && flooded;
    }
    auto load = [&](std::uint64_t lo, std::uint64_t hi, std::uint32_t n) {
        for (std::uint64_t b = lo; b < hi; ++b) {
            m.tip(b + 1);
            std::vector<Admitted> v; for (std::uint32_t k = 0; k < n; ++k) v.push_back(drop_at(b, 16 + k, payee_n(k)));
            flooded = m.flood(v) && flooded;
        }
    };
    load(170, sh.l1_hi, sh.n1);
    C(flooded, std::string(sh.tag) + " every raindrop reached every node (the flood; C's harvest lost 2 members of bin 160)");
    for (auto* n : m.all()) n->feed_order(lane_order(230));
    const std::uint64_t P = cut_at(200);
    // A finds h=230 and composes + pins (the winner route)
    m.A->pump();
    const std::size_t a_held = m.A->relay->drops_held(100, 170).size();
    const auto outA = m.A->compose(230, P, nullptr, bid);
    const std::vector<bytes32> S = outA.set;
    std::printf("  find: A store=%zu held %zu/360 of the range; pinned %zu; rows=%zu delta payees=%zu\n",
                m.A->relay->drops_store_size(), a_held, S.size(), outA.rows, outA.delta.size());
    C(outA.ok && !outA.delta.empty() && !S.empty(), std::string(sh.tag) + " A composes a non-trivial delta from its pinned set");
    Ledger LA, LB, LC;
    LA.book(outA.delta);
#if defined(C2POOL_XMR_DROPS_RETAIN)
    m.B->relay->drops_pin_retain(bid, S); m.C->relay->drops_pin_retain(bid, S);   // the shell: on admitting the carried set
#endif
    load(sh.l1_hi, 230, sh.n2);
    std::printf("  booking: A store=%zu holds %zu/%zu pinned members\n", m.A->relay->drops_store_size(),
                [&] { std::size_t k = 0; const auto h = m.A->relay->drops_held(100, 170); for (const auto& id : S) k += std::binary_search(h.begin(), h.end(), id); return k; }(),
                S.size());
    // B restarts: stop (persist) -> a fresh node on the same store file, its harvest rebuilt from it
    m.B.reset();
    m.B = m.make_b(230);
#if defined(C2POOL_XMR_DROPS_RETAIN)
    m.B->relay->drops_pin_retain(bid, S);   // the shell: journalled sets re-pinned BEFORE drops_load
#endif
    std::string why;
    const std::size_t loaded = m.B->relay->drops_load(&why);
    C(m.B->relay->start(why) && wait_for([&] { return m.B->relay->ready_peers().size() == 2; }, m.all(), 10000ms),
      std::string(sh.tag) + " B restarted (reloaded " + std::to_string(loaded) + " raindrops) and rejoined");
    for (auto* n : {m.B.get()}) n->feed_order(lane_order(230));
    auto book = [&](Node& X, Ledger& L, const char* name) {
        std::uint64_t n = 1;
        for (; n <= kRetryBound; ++n) {
            X.pump();
            const auto out = X.compose(230, P, &S, bid);
            if (out.ok) {
                if (out.delta == outA.delta) L.book(out.delta); else ++L.refused;   // a different delta = carry-mismatch REFUSED
                std::printf("  %s composed A's set at attempt %llu (delta %s)\n", name, (unsigned long long)n, out.delta == outA.delta ? "equal" : "DIFFERENT");
                return;
            }
            if (n == 1 || n == kRetryBound) std::printf("  %s attempt %llu: %zu/%zu pinned raindrop(s) not held (fetching by id)\n", name,
                                                        (unsigned long long)n, out.missing.size(), S.size());
            X.relay->drops_fetch_ids(out.missing, 0, 100, 170);
            std::this_thread::sleep_for(150ms);
        }
        ++L.refused;   // booking_stall_timeout at the bound: REFUSED -> node-local liability (attempt 6)
        std::printf("  %s: booking_stall_timeout after %llu attempts -> REFUSED (liability) while A booked\n", name, (unsigned long long)kRetryBound);
    };
    book(*m.B, LB, "B");
    book(*m.C, LC, "C");
    std::printf("  served: A=%llu B=%llu C=%llu | owed_digest A=%s… B=%s… C=%s…\n",
                (unsigned long long)m.A->relay->stats().drops_served.load(), (unsigned long long)m.B->relay->stats().drops_served.load(),
                (unsigned long long)m.C->relay->stats().drops_served.load(), LA.digest().substr(0, 12).c_str(),
                LB.digest().substr(0, 12).c_str(), LC.digest().substr(0, 12).c_str());
    C(LB.booked == 1 && LB.refused == 0, std::string(sh.tag) + " B (restarted) books A's set and delta within the retry bound (base: refused)");
    C(LC.booked == 1 && LC.refused == 0, std::string(sh.tag) + " C (2 members lost) books A's set and delta within the retry bound (base: refused)");
    C(LA.digest() == LB.digest() && LA.digest() == LC.digest(),
      std::string(sh.tag) + " owed_digest equal on A, B and C after h=230 (base: B/C refused -> an owed-ledger split)");
}

static std::vector<Admitted> drops_in(std::uint64_t b0, std::uint64_t b1, std::uint32_t per, std::uint32_t salt) {
    std::vector<Admitted> v;
    for (std::uint64_t b = b0; b < b1; ++b) for (std::uint32_t k = 0; k < per; ++k) v.push_back(drop_at(b, salt + k, payee_n(k)));
    return v;
}
static std::vector<bytes32> ids_of(const std::vector<Admitted>& v) {
    std::vector<bytes32> r; for (const auto& a : v) r.push_back(a.id); std::sort(r.begin(), r.end()); return r;
}
static bool holds_all(const XmrRelayNode& n, std::uint64_t lo, std::uint64_t hi, const std::vector<bytes32>& ids) {
    const auto h = n.drops_held(lo, hi);
    for (const auto& id : ids) if (!std::binary_search(h.begin(), h.end(), id)) return false;
    return true;
}

// ── R3 (L2a): the winner pins only what its store can serve ─────────────────
static void r3_servable(Checker& C) {
    std::printf("R3: harvest 12 raindrops over [100,103), store bounded to 8 -> the pin is the 8 servable ids\n");
    auto o = ropts({}); o.drops_store_max = 8;   // the same knob on both trees
    Node W(o, 103);
    std::string why;
    C(W.relay->start(why), "R3 W starts " + why);
    for (const auto& a : drops_in(100, 103, 4, 0)) W.relay->submit_own_drop(a);
    W.pump();
    const auto cand = W.w->pinned_ids(100, 103, SIZE_MAX);
    const auto held = W.relay->drops_held(100, 103);
#if defined(C2POOL_XMR_DROPS_RETAIN)
    std::size_t skipped = 0; bool capped = false;
    const auto pin = W.relay->drops_pin_servable("r3", cand, rl::kBlockWonSetMaxIds, &skipped, &capped);
    std::size_t s5 = 0; bool c5 = false;
    const auto five = W.relay->drops_pin_servable("r3b", cand, 5, &s5, &c5);
    C(c5 && five.size() == 5 && std::equal(five.begin(), five.end(), held.begin()),
      "R3 over the cap the pin is the 5 SMALLEST servable ids (deterministic), flagged capped");
#else
    std::size_t skipped = 0;
    const auto pin = W.w->pinned_ids(100, 103, rl::kBlockWonSetMaxIds);   // BASE: the harvest, servable or not
#endif
    std::printf("  harvest=%zu store=%zu pinned=%zu skipped=%zu\n", cand.size(), held.size(), pin.size(), skipped);
    C(cand.size() == 12 && held.size() == 8 && pin == held && skipped == 4,
      "R3 harvest 12 / store 8: the winner pins exactly the 8 ids it can serve, 4 skipped + counted (base: pins 12, 4 unservable)");
}

// ── R4 (L2b): a retained set survives newer raindrops, is served, then released ──
static void r4_retained(Checker& C) {
    std::printf("R4: a pinned set is retained while 3 budgets of newer raindrops arrive, served by id, then released\n");
    auto o = ropts({}); o.drops_store_max = 8;
    Node W(o, 102);
    std::string why;
    C(W.relay->start(why), "R4 W starts " + why);
    const auto mine = drops_in(100, 102, 3, 0);
    const auto pin = ids_of(mine);
    for (const auto& a : mine) W.relay->submit_own_drop(a);
#if defined(C2POOL_XMR_DROPS_RETAIN)
    W.relay->drops_pin_retain("blk", pin);
#endif
    W.tip(110);
    for (const auto& a : drops_in(102, 110, 3, 0)) W.relay->submit_own_drop(a);   // 24 = 3 store budgets
    C(holds_all(*W.relay, 100, 102, pin) && W.relay->drops_store_size() <= 8 + pin.size(),
      "R4 every pinned member is still servable after 3 budgets of newer raindrops (base: evicted with the next put)");
    Node R(ropts({W.relay->listen_port()}), 110);
    C(R.relay->start(why) && wait_for([&] { return R.relay->ready_peers().size() == 1; }, {&R, &W}), "R4 R dials W");
    const bool got = wait_for([&] {
        const auto h = R.relay->drops_held(100, 102);
        std::vector<bytes32> miss;
        for (const auto& id : pin) if (!std::binary_search(h.begin(), h.end(), id)) miss.push_back(id);
        if (!miss.empty()) R.relay->drops_fetch_ids(miss, 0, 100, 102);
        return miss.empty();
    }, {&R, &W}, 5000ms);
    C(got && W.relay->stats().drops_served.load() >= pin.size(), "R4 a peer fetches every pinned member by id from W (base: served=0)");
#if defined(C2POOL_XMR_DROPS_RETAIN)
    C(W.relay->stats().drops_evict_kept_pinned.load() > 0, "R4 evictions kept the pinned raindrops (drops_evict_kept_pinned > 0)");
    C(W.relay->drops_pin_release("blk") == pin.size(), "R4 release at the block's decision un-pins all 6 members");
    for (const auto& a : drops_in(110, 112, 4, 0)) W.relay->submit_own_drop(a);
    C(W.relay->drops_held(100, 102).empty() && W.relay->drops_store_size() <= 8,
      "R4 released members evict like any other raindrop (the next puts: the store is back under its bound)");
#endif
}

// ── R5 (L1): the floor, the byte budget, a reload over the budget ──────────
static void r5_floor_budget(Checker& C, const std::string& dir) {
    std::printf("R5: L1 -- the floor keyed to the finalize cursor, the byte budget, a reload keeps the newest bins\n");
    std::string why;
    {   // a reload over the bound keeps the NEWEST bins (same count knob on both trees)
        const std::string path = dir + "/r5-lane7.drops";
        auto o = ropts({}, path); o.drops_store_max = 40;
        {
            Node W(o, 110);
            C(W.relay->start(why), "R5 W starts " + why);
            for (const auto& a : drops_in(100, 110, 4, 0)) W.relay->submit_own_drop(a);   // 40 raindrops, bins 100..109
        }   // stop: persisted
        auto o2 = o; o2.drops_store_max = 20;   // the operator lowered the bound (or the pool outgrew it)
        Node W2(o2, 110);
        const std::size_t n = W2.relay->drops_load(&why);
        std::printf("  reload under a bound of 20: loaded=%zu held[100,105)=%zu held[105,110)=%zu (%s)\n", n,
                    W2.relay->drops_held(100, 105).size(), W2.relay->drops_held(105, 110).size(), why.c_str());
        C(n == 20 && W2.relay->drops_held(105, 110).size() == 20 && W2.relay->drops_held(100, 105).empty(),
          "R5 a store over the bound reloads its 20 NEWEST raindrops (bins 105..109) (base: the whole file ignored, loaded=0)");
    }
#if defined(C2POOL_XMR_DROPS_RETAIN)
    {   // the floor: evicts below it even under budget, keeps everything above it; monotone
        Node W(ropts({}), 100);
        C(W.relay->start(why), "R5 floor node starts " + why);
        W.tip(140);
        const auto v = drops_in(100, 140, 50, 0);   // 2000 raindrops over 40 bins: under the 512 MiB budget
        for (const auto& a : v) W.relay->submit_own_drop(a);
        C(W.relay->drops_store_size() == 2000 && !W.relay->drops_floor_set(),
          "R5 no floor yet (nothing finalized): 2000 raindrops / 40 bins kept, far past today's count of the window");
        const std::vector<bytes32> keep = ids_of(std::vector<Admitted>(v.begin(), v.begin() + 50));   // bin 100, pinned
        W.relay->drops_pin_retain("pending", keep);
        W.relay->set_drops_floor_bin(120);
        C(W.relay->drops_held(101, 120).empty() && W.relay->drops_held(120, 140).size() == 1000 && holds_all(*W.relay, 100, 101, keep),
          "R5 floor 120: every unpinned raindrop below it evicted even under budget, all 1000 above it kept, a pinned set below it kept");
        W.relay->set_drops_floor_bin(110);
        C(W.relay->drops_floor_bin() == 120, "R5 the floor is monotone (a lower push is ignored)");
        W.relay->drops_pin_release("pending");
        C(W.relay->drops_held(100, 120).empty(), "R5 released: the pinned bin below the floor evicts");
    }
    {   // the byte budget: the oldest unretained bins go, counted (overflow, loud)
        auto o = ropts({});
        Node probe(o, 101);
        C(probe.relay->start(why), "R5 probe starts " + why);
        probe.relay->submit_own_drop(drop_at(100, 0, payee_n(0)));
        const u64 per = probe.relay->drops_store_bytes();
        o.drops_store_bytes = per * 10 + per / 2;   // room for 10 raindrops
        Node W(o, 110);
        C(W.relay->start(why), "R5 budget node starts " + why);
        for (const auto& a : drops_in(100, 110, 2, 0)) W.relay->submit_own_drop(a);   // 20
        std::printf("  budget=%llu (%llu B per raindrop): store=%zu bytes=%llu overflow_bins=%llu\n", (unsigned long long)o.drops_store_bytes,
                    (unsigned long long)per, W.relay->drops_store_size(), (unsigned long long)W.relay->drops_store_bytes(),
                    (unsigned long long)W.relay->stats().drops_store_overflow_bins.load());
        C(W.relay->drops_store_size() == 10 && W.relay->drops_held(105, 110).size() == 10 && W.relay->drops_store_bytes() <= o.drops_store_bytes &&
          W.relay->stats().drops_store_overflow_bins.load() == 5,
          "R5 over the byte budget the 5 oldest bins are evicted (overflow_bins=5), the newest 10 raindrops kept");
    }
#else
    C(false, "R5 base: no floor and no byte budget -- a 65536-raindrop COUNT (~73 min at 15/s) bounds the store below any D_conf-60 range");
#endif
}

// ── R6 (K6): a backfill whose inventory overflows kDropsInvMaxIds is paged per bin ──
static void r6_paging(Checker& C) {
    std::printf("R6: a peer holds 20,000 raindrops of [100,110) (2000/bin); the inventory frame carries at most %zu ids\n", rl::kDropsInvMaxIds);
    std::string why;
    auto os = ropts({}); os.drops_fetch_retry_ms = 2000;   // the daemon's re-ask pace (a 20,000-id ask is not re-sent every 100 ms)
    Node S(os, 110);
    C(S.relay->start(why), "R6 S starts " + why);
    const auto v = drops_in(100, 110, 2000, 0);
    for (const auto& a : v) S.relay->submit_own_drop(a);   // S alone: nothing flooded
    C(S.relay->drops_held(100, 110).size() == 20000, "R6 S holds 20,000 raindrops of the range");
    auto orr = ropts({S.relay->listen_port()}); orr.drops_fetch_retry_ms = 2000;
    Node R(orr, 110);
    C(R.relay->start(why) && wait_for([&] { return R.relay->ready_peers().size() == 1; }, {&R, &S}), "R6 R dials S");
    bool complete = false;
    const auto dl = std::chrono::steady_clock::now() + 30s;
    while (!complete && std::chrono::steady_clock::now() < dl) {
        complete = R.relay->drops_sync(100, 110).complete;
        R.pump();
        if (!complete) std::this_thread::sleep_for(50ms);
    }
    const std::size_t got = R.relay->drops_held(100, 110).size();
    std::printf("  drops_sync complete=%d held=%zu/20000 inv_paged=%llu\n", complete ? 1 : 0, got,
#if defined(C2POOL_XMR_DROPS_RETAIN)
                (unsigned long long)R.relay->stats().drops_inv_paged.load()
#else
                0ull
#endif
    );
    C(complete && got == 20000, "R6 drops_sync answers complete only once all 20,000 are held (base: complete at 16,384, 3,616 never asked)");
}

// ── HOLD-ROUND-2 (C): the attempt-7 re-ask storm ────────────────────────────
// B asked 3.75M raindrop ids in 3 h: A's held template froze at h=2220689, its
// miners filled that ONE bin with ~130k raindrops; every HELLO (a ban loop:
// one per ~3 s) pulled the 16384 smallest ids, fetched them at once outside the
// ask budget, could never admit them (queue / horizon), never counted them held,
// and erased the per-peer ask counter at the disconnect.
static bool sync_until(XmrRelayNode& r, u64 lo, u64 hi, std::chrono::milliseconds limit, const std::function<void()>& tick = {}) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        if (r.drops_sync(lo, hi).complete) return true;
        if (tick) tick();
        std::this_thread::sleep_for(50ms);
    }
    return r.drops_sync(lo, hi).complete;
}
// R9 (C1): ONE bin over kDropsInvMaxIds is paged by cursor
static void r9_one_bin_paging(Checker& C) {
    std::printf("R9 (C1): a peer holds 20,000 raindrops of ONE bin; the inventory frame carries at most %zu ids\n", rl::kDropsInvMaxIds);
    std::string why;
    auto os = ropts({}); os.drops_fetch_retry_ms = 2000;
    Node S(os, 110);
    C(S.relay->start(why), "R9 S starts " + why);
    for (std::uint32_t k = 0; k < 20000; ++k) S.relay->submit_own_drop(drop_at(100, k, payee_n(k % 4)));
    C(S.relay->drops_held(100, 101).size() == 20000, "R9 S holds 20,000 raindrops of bin 100");
    auto orr = ropts({S.relay->listen_port()}); orr.drops_fetch_retry_ms = 2000;
    Node R(orr, 110);
    C(R.relay->start(why) && wait_for([&] { return R.relay->ready_peers().size() == 1; }, {&R, &S}), "R9 R dials S");
    const bool complete = sync_until(*R.relay, 100, 101, 40000ms, [&] { R.pump(); });
    const std::size_t got = R.relay->drops_held(100, 101).size();
#if defined(C2POOL_XMR_DROPS_PAGE)
    const unsigned long long pages = R.relay->stats().drops_inv_pages_rx.load(), served = S.relay->stats().drops_inv_pages_served.load();
#else
    const unsigned long long pages = 0, served = 0;
#endif
    std::printf("  drops_sync complete=%d held=%zu/20000 pages_rx=%llu pages_served=%llu\n", complete ? 1 : 0, got, pages, served);
    C(complete && got == 20000 && pages >= 1 && served >= 1,
      "R9 drops_sync of one bin is complete only once all 20,000 are held, via cursor pages (base: complete at 16,384, 3,616 never asked)");
}

// A bare relay node for R10/R11: its own ChainView (bins 90..tip) and a RandomX
// function the test controls (rx_ok = false: the engine never verifies).
struct RawNode {
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    RawNode(RelayOptions ro, std::uint64_t tip, bool rx_ok) {
        for (std::uint64_t b = 90; b <= tip; ++b) chain.note(prev_of(b), b, bytes32{});
        chain.set_tip(tip);
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [rx_ok](const std::vector<u8>& blob, const bytes32&, bytes32& pow) { return rx_ok && fake_rx(blob, pow); },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; }, [](const std::string&) {});
    }
    ~RawNode() { relay->stop(); }
};
// R10 (C2): a fetched raindrop this node cannot admit counts as held -- the sync
// completes and the id is not asked again, across forced reconnects.
static void r10_refused_held(Checker& C) {
    std::printf("R10 (C2): 40 raindrops of bin 115 whose Monero context neither node holds (inadmissible at R)\n");
    std::string why;
    auto os = ropts({}); os.drops_fetch_retry_ms = 100;
    Node S(os, 110);                      // S's chain stops at 110: it holds the raindrops, not their context
    C(S.relay->start(why), "R10 S starts " + why);
    for (std::uint32_t k = 0; k < 40; ++k) S.relay->submit_own_drop(drop_at(115, k, payee_n(k % 4)));
    C(S.relay->drops_held(115, 116).size() == 40, "R10 S holds the 40 raindrops of bin 115");
    auto orr = ropts({S.relay->listen_port()}); orr.drops_fetch_retry_ms = 100; orr.solicited_unresolved_patience_ms = 300;
    RawNode R(orr, 110, true);
    C(R.relay->start(why), "R10 R starts, dials S " + why);
    const auto t0 = std::chrono::steady_clock::now();
    while (R.relay->ready_peers().empty() && std::chrono::steady_clock::now() - t0 < 10s) std::this_thread::sleep_for(20ms);
    int reconnects = 0;
    auto last = std::chrono::steady_clock::now();
    bool complete = false;
    const auto dl = std::chrono::steady_clock::now() + 6s;
    while (std::chrono::steady_clock::now() < dl) {   // a forced reconnect every 600 ms (the attempt-7 ban loop, slowed)
        if (!complete) complete = R.relay->drops_sync(115, 116).complete;
        else (void)R.relay->drops_sync(115, 116);
        if (std::chrono::steady_clock::now() - last > 600ms) {
            for (auto p : R.relay->ready_peers()) { R.relay->drop_peer(p); ++reconnects; }
            last = std::chrono::steady_clock::now();
        }
        std::this_thread::sleep_for(50ms);
    }
    const auto& rs = R.relay->stats();
#if defined(C2POOL_XMR_DROPS_PAGE)
    const unsigned long long refused_held = rs.drops_refused_held.load();
#else
    const unsigned long long refused_held = 0;
#endif
    std::printf("  reconnects=%d complete=%d ids_asked=%llu unresolved_dropped=%llu refused_held=%llu set_aside=%llu\n", reconnects,
                complete ? 1 : 0, (unsigned long long)rs.drops_ids_asked.load(), (unsigned long long)rs.unresolved_dropped.load(),
                refused_held, (unsigned long long)rs.drops_peer_setaside.load());
    C(complete && refused_held > 0 && rs.drops_ids_asked.load() <= 8 * 40,
      "R10 the inadmissible ids count as held: drops_sync complete, ids_asked <= 8N (asks only until the first refusal) across " + std::to_string(reconnects) +
      " reconnects (base: never held, re-asked every 100 ms, ids_asked=" + std::to_string(rs.drops_ids_asked.load()) + ")");
}
// R11 (C3): the ask budget is per NODE and survives reconnects: a peer that never
// gets its inventory fetched is set aside after drops_fetch_max_asks asks in all.
static void r11_budget_by_node(Checker& C) {
    std::printf("R11 (C3): R can never verify (RandomX unavailable): every fetched raindrop is lost; reconnect every 700 ms\n");
    std::string why;
    auto os = ropts({}); os.drops_fetch_retry_ms = 100;
    Node S(os, 120);
    C(S.relay->start(why), "R11 S starts " + why);
    for (std::uint32_t k = 0; k < 40; ++k) S.relay->submit_own_drop(drop_at(115, 100 + k, payee_n(k % 4)));
    auto orr = ropts({S.relay->listen_port()}); orr.drops_fetch_retry_ms = 100;
    RawNode R(orr, 120, /*rx_ok=*/false);
    C(R.relay->start(why), "R11 R starts, dials S " + why);
    const auto t0 = std::chrono::steady_clock::now();
    while (R.relay->ready_peers().empty() && std::chrono::steady_clock::now() - t0 < 10s) std::this_thread::sleep_for(20ms);
    int reconnects = 0;
    auto last = std::chrono::steady_clock::now();
    const auto dl = std::chrono::steady_clock::now() + 7s;
    while (std::chrono::steady_clock::now() < dl) {
        (void)R.relay->drops_sync(115, 116);
        if (std::chrono::steady_clock::now() - last > 700ms) {
            for (auto p : R.relay->ready_peers()) { R.relay->drop_peer(p); ++reconnects; }
            last = std::chrono::steady_clock::now();
        }
        std::this_thread::sleep_for(50ms);
    }
    const auto& rs = R.relay->stats();
    std::printf("  reconnects=%d ids_asked=%llu set_aside=%llu rx_unavailable=%llu\n", reconnects,
                (unsigned long long)rs.drops_ids_asked.load(), (unsigned long long)rs.drops_peer_setaside.load(),
                (unsigned long long)rs.rx_unavailable.load());
    C(rs.drops_peer_setaside.load() >= 1 && rs.drops_ids_asked.load() <= 9 * 40,
      "R11 set aside after 8 asks IN ALL (node-keyed budget), ids_asked <= 9N across " + std::to_string(reconnects) +
      " reconnects (base: the budget reset at every disconnect, set_aside=" + std::to_string(rs.drops_peer_setaside.load()) +
      " ids_asked=" + std::to_string(rs.drops_ids_asked.load()) + ")");
}
// R12 (C4): never a raindrop on a job the chain has passed
static void r12_stale_mint(Checker& C) {
    std::printf("R12 (C4): the minter refuses raindrops on a stale job\n");
#if defined(C2POOL_XMR_DROPS_PAGE)
    C(rl::drop_mint_stale(2220689, 2220753) && !rl::drop_mint_stale(2220689, 2220689) && !rl::drop_mint_stale(2220689, 2220691) &&
      rl::drop_mint_stale(2220689, 2220692),
      "R12 job 2220689 at tip 2220753 (attempt 7's frozen template): STALE; at tip h..h+2: minted (one job late is honest work)");
    const std::string src = slurp(V37_XMR_SHELL_SRC);
    C(!src.empty() && src.find("relay::drop_mint_stale(acc.height, relay_chain.tip())") != std::string::npos &&
      src.find("++drops_mint_stale; return;") != std::string::npos && src.find("stale=%llu") != std::string::npos,
      "R12 the shell refuses a stale raindrop BEFORE minting it and counts it (mint drops ... stale=)");
#else
    C(false, "R12 the base mints raindrops on any job (attempt 7: ~130k into the frozen bin 2220689)");
#endif
}

// ── R7 (K7): per-bin append-only segments ───────────────────────────────────
static void r7_segments(Checker& C, const std::string& dir) {
    std::printf("R7: the store persisted as per-bin segments\n");
#if defined(C2POOL_XMR_DROPS_RETAIN)
    std::string why;
    const std::string path = dir + "/r7-lane7.drops";
    namespace fs = std::filesystem;
    auto snap = [&]() { std::map<std::string, std::uintmax_t> m; std::error_code ec;
        for (const auto& e : fs::directory_iterator(path + ".d", ec)) m[e.path().filename().string()] = fs::file_size(e.path(), ec);
        return m; };
    auto o = ropts({}, path);
    {
        Node W(o, 120);
        C(W.relay->start(why), "R7 W starts " + why);
        for (const auto& a : drops_in(100, 120, 2, 0)) W.relay->submit_own_drop(a);
        C(W.relay->drops_persist(), "R7 persist writes the changed bins");
        const auto s0 = snap();
        C(s0.size() == 20 && !fs::exists(path), "R7 20 bins = 20 segment files under <path>.d (no whole-store file)");
        const u64 ap0 = W.relay->stats().drops_seg_appends.load();
        W.relay->submit_own_drop(drop_at(110, 99, payee_n(1)));
        C(W.relay->drops_persist(), "R7 one more raindrop in bin 110 is persisted");
        const auto s1 = snap();
        std::size_t changed = 0;
        for (const auto& [f, sz] : s1) if (!s0.count(f) || s0.at(f) != sz) ++changed;
        C(changed == 1 && s1.at("110.seg") > s0.at("110.seg") && W.relay->stats().drops_seg_appends.load() == ap0 + 1,
          "R7 exactly one segment (110.seg) grew: an append, every other segment untouched (base: the whole store rewritten)");
        W.relay->set_drops_floor_bin(105);
        C(W.relay->drops_persist() && snap().size() == 15 && !fs::exists(path + ".d/104.seg"),
          "R7 bins below the floor evicted -> their segments unlinked (15 left)");
    }
    {   // a torn tail keeps the valid prefix; another lane's segment is ignored
        const std::string p115 = path + ".d/115.seg";
        fs::resize_file(p115, fs::file_size(p115) - 5);
        auto of = o; of.chain = kChain + 1;
        { Node F(of, 120); F.relay->submit_own_drop(drop_at(130, 0, payee_n(0))); F.relay->drops_persist(); }   // another lane's 130.seg in the same dir
        Node W2(o, 120);
        const std::size_t n = W2.relay->drops_load(&why);
        std::printf("  reload: loaded=%zu torn=%llu (%s)\n", n, (unsigned long long)W2.relay->stats().drops_seg_torn.load(), why.c_str());
        C(n == 30 && W2.relay->stats().drops_seg_torn.load() == 1 && W2.relay->drops_held(115, 116).size() == 1,
          "R7 a torn tail ends its segment: 115.seg keeps its valid first record, every other bin loads (31 - 1 = 30), "
          "another lane's segment is ignored");
    }
#else
    (void)dir;
    C(false, "R7 base: one whole-store file rewritten on every change (56 MB every ~2.4 s on stagenet, ~23 MB/s); a torn file drops everything");
#endif
}

// ── R8: the shell wires L1/L2 (source pins) ─────────────────────────────────
static void r8_source(Checker& C) {
    std::printf("R8: source pins -- the shell's wiring of DROPS-RETAIN\n");
    const std::string sh = slurp(V37_XMR_SHELL_SRC);
    C(!sh.empty(), std::string("R8 the shell source is readable: ") + V37_XMR_SHELL_SRC);
    auto has = [&](const char* s) { return sh.find(s) != std::string::npos; };
    C(has("ids = relay_node->drops_pin_servable(bid, drops->pinned_ids(rgo->first, rgo->second, SIZE_MAX), relay::kBlockWonSetMaxIds,"),
      "R8 L2a: the winner's own composition pins harvest ∩ servable store (drops_pin_servable)");
    C(has("if (relay_node && wc.drops_set) relay_node->drops_pin_retain(bid, *wc.drops_set);"),
      "R8 L2b: a carried set is retained when admitted into wire_cache");
    C(has("if (wc.drops_set) relay_node->drops_pin_retain(b, *wc.drops_set);   // ★ DROPS-RETAIN (L2b): before drops_load"),
      "R8 L2b: journalled sets are re-pinned at boot before the store is reloaded");
    C(has("if (relay_node) relay_node->drops_pin_release(it->first);"), "R8 L2b: released when wire_cache forgets the bid (decided here / evicted)");
    C(has("relay_node->set_drops_floor_bin(rg->first > kMargin ? rg->first - kMargin : 0);") && has("drops->range_for(cur)"),
      "R8 L1: the floor = frontier of the newest lane block below the finalize cursor - kReorgMargin, pushed on each finalize step");
    C(has("\"--drops-store-bytes\"") && has("ro.drops_store_bytes = g_drops_store_bytes;"), "R8 L1: --drops-store-bytes sets the byte budget");
    C(has("relay_node->describe_retain()"), "R8 the status line exports the store / floor / pins / overflow counters");
}

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_retain_kat (%s) ==\n",
#if defined(C2POOL_XMR_DROPS_RETAIN)
                "fix tree: C2POOL_XMR_DROPS_RETAIN");
#else
                "BASE tree: a 65536-count store; the winner pins its harvest (ed360c4c)");
#endif
    const std::string dir = std::filesystem::temp_directory_path().string() + "/v37_drops_retain_kat." + std::to_string(::getpid());
    std::filesystem::create_directories(dir);
    r3_servable(C);
    r4_retained(C);
    r5_floor_budget(C, dir);
    r6_paging(C);
    r9_one_bin_paging(C);    // HOLD-ROUND-2 (C1)
    r10_refused_held(C);     // HOLD-ROUND-2 (C2)
    r11_budget_by_node(C);   // HOLD-ROUND-2 (C3)
    r12_stale_mint(C);       // HOLD-ROUND-2 (C4)
    r7_segments(C, dir);
    {   // R2: a store too small for the window (the same count knob on both trees)
        auto o = ropts({}); o.drops_store_max = 600;
        run_shape(C, Shape{"R2", o, 210, 10, 30}, dir);
    }
    // R1: THE attempt-6 shape on today's defaults: 66,000 raindrops mined past the range before the find
    run_shape(C, Shape{"R1", ropts({}), 230, 1100, 0}, dir);
    r8_source(C);
    std::error_code ec; std::filesystem::remove_all(dir, ec);
    return C.done("v37_xmr_drops_retain_kat");
}
