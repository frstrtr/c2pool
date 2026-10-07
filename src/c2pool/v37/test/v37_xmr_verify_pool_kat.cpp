// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_verify_pool_kat -- DROPS-VERIFY-SCALE (capstone attempt 5 false start).
//
// With raindrops ON every node RandomX-verifies every raindrop of the pool
// (64x the receipt load) and the relay had ONE verify thread: a node fell
// behind, its FIFO dropped items (qdrop) and receipts verified after their bin
// closed were pushed 'late' in arrival order (node-local lane orders diverged).
// RelayOptions::verify_threads = N workers now run the same process().
//
// Three in-process XmrRelayNode instances over REAL loopback TCP in a TRIANGLE
// (B dials A, C dials A and B), each with its own V37Engine lane +
// XmrReceiptIngest (canonical order, bin_lag 1, grace 200 ms), DROPS gate ON.
// RandomX is a SLEEPING fake (kHashMs per hash, like a light hash on a busy
// host): nonce >= kDropNonce -> a raindrop (2^249: meets the floor 10, fails
// share_diff 1000), else a receipt. A and B mint receipts + raindrops per
// Monero "block" (one bin per tick); C verifies everything both of them send.
//
//   N1  overload (RED on base): 2 x kDropsPerTick raindrops/s offered to C,
//       capacity 1000/kHashMs per thread, verify_queue_max 256. One thread
//       (the base pipeline) -> queue drops and late receipts on C. The fix at
//       verify_threads = 4 -> qdrop 0, late <= 2%, every receipt in C's lane,
//       C's RxFn observed running on > 1 thread at once.
//   N2  determinism: the same deterministic script at a load one thread
//       sustains, N = 1 vs N = 8: identical accepted receipt id set, raindrop
//       id set, lane next_pos and lane digest on C (printed, so the base
//       build's run of this KAT can be diffed against the fix's).
//   N6  stop: stop() with 8 workers and a full queue joins within 2 s and no
//       RandomX call starts after stop() returns.
//   N7  rx-unavailable: a receipt whose first hash is refused (a seed being
//       keyed during a switch) is parked once and admitted on the retry
//       (base: dropped for good on this node).
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/v37_engine.hpp>
#if defined(V37_XMR_O2_WITH_RANDOMX)
#include <sys/resource.h>
#include "c2pool/v37/xmr/xmr_o2_randomx_verify.hpp"   // VP_LIVE: the REAL RandomX light cost per verify
namespace o2 = c2pool::v37n::xmr::o2;
#endif

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr std::uint32_t kDropNonce = 0x40000000u;

#if defined(C2POOL_XMR_RELAY_VERIFY_POOL)
static constexpr bool kFix = true;
#else
static constexpr bool kFix = false;   // BASE: one verify worker whatever is asked
#endif

// VP_LIVE (measurement mode, env-driven, RandomX builds only): every node owns a
// REAL O2RandomXVerifier (its own caches, like a separate process) and every
// verify pays a real light hash of the receipt's hashing blob (on the worker's
// own VM with the fix, on the single mutex-guarded VM on base); the verdict
// (receipt / raindrop) still comes from the nonce so the script stays exact.
static int g_grace_ms = 200;
static bool g_live = false;
static std::size_t g_live_workers = 1;

static u32 nonce_of(const std::vector<u8>& blob) {
    u32 nonce = 0;
    ::v37::xmr::HashingBlob hb; hb.bytes = blob;
    ::v37::xmr::verify::ParsedBlob pb;
    if (::v37::xmr::verify::parse_hashing_blob(hb, pb))
        for (int i = 0; i < 4; ++i) nonce |= static_cast<u32>(blob[pb.header_len - 4 + i]) << (8 * i);
    return nonce;
}

struct VNode {
    std::string name;
    ChainView chain;
    int hash_ms = 0;
    std::atomic<u64> rx_calls{0};
    std::atomic<int> rx_now{0}, rx_peak{0};           // concurrent RandomX calls (the pool at work)
    std::atomic<u32> fail_once{0};                    // N7: refuse the first hash of this nonce
    std::atomic<bool> failed{false};
#if defined(V37_XMR_O2_WITH_RANDOMX)
    std::unique_ptr<o2::O2RandomXVerifier> rx;        // VP_LIVE only
#endif
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    std::vector<bytes32> pushed_ids;                  // lane push order (main thread)
    std::set<bytes32> drop_ids;                       // raindrops drained (main thread)
    u64 template_height = 0;
    std::vector<std::string> logs;
    std::mutex log_mtx;

    VNode(std::string n, RelayOptions ro, int hms) : name(std::move(n)), hash_ms(hms) {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (g_live) {
            rx = std::make_unique<o2::O2RandomXVerifier>();
            o2::RandomXPolicy p; p.enabled = true; p.async_next_seed = false;
            if (!rx->init(p) || !rx->ensure_seeds(o2::Seed32{}, std::nullopt)) std::printf("    [%s] RandomX init FAILED\n", name.c_str());
#if defined(C2POOL_XMR_RELAY_VERIFY_POOL)
            rx->add_workers(g_live_workers);
#endif
        }
#endif
        engine = std::make_unique<c2pool::v37n::V37Engine>(4096);
        engine->start();
        engine->submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [this](const std::vector<u8>& blob, const bytes32&, bytes32& pow) {
                ++rx_calls;
                const int now = ++rx_now;
                int pk = rx_peak.load();
                while (now > pk && !rx_peak.compare_exchange_weak(pk, now)) {}
                const u32 nonce = nonce_of(blob);
                bool ok = true;
                if (fail_once.load() && nonce == fail_once.load() && !failed.exchange(true)) ok = false;
                if (ok && hash_ms) std::this_thread::sleep_for(std::chrono::milliseconds(hash_ms));
#if defined(V37_XMR_O2_WITH_RANDOMX)
                if (ok && rx) {   // VP_LIVE: pay the real light hash
                    o2::Hash32 h{};
#if defined(C2POOL_XMR_RELAY_VERIFY_POOL)
                    const int w = XmrRelayNode::verify_worker();
                    ok = w >= 0 ? rx->randomx_hash_on(static_cast<std::size_t>(w), blob.data(), blob.size(), o2::Seed32{}, h)
                                : rx->randomx_hash(blob.data(), blob.size(), 0, o2::Seed32{}, h);
#else
                    ok = rx->randomx_hash(blob.data(), blob.size(), 0, o2::Seed32{}, h);
#endif
                }
#endif
                pow.fill(0);
                if (nonce >= kDropNonce) pow[31] = 0x02;   // 2^249: meets diff 10, fails diff 1000 -> a RAINDROP
                --rx_now;
                return ok;
            },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(kChain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(log_mtx); logs.push_back(l); });
        XmrReceiptIngest::Options io; io.chain = kChain; io.order = XmrReceiptIngest::Order::Canonical;
        io.bin_lag = 1; io.grace_ms = static_cast<u32>(g_grace_ms);
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dig) {
                ::v37::PayoutDescriptor d; d.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(kChain, d, w, 0)).get().applied()) return false;
                auto s = engine->snapshot(kChain);
                next_after = s->next_pos; dig = s->digest;
                return true;
            },
            [this](const Admitted& a, u64 pos, u32 n_pushes, u64 next_after, const bytes32& dig) {
                pushed_ids.push_back(a.id);
                relay->on_pushed(a.id, pos, n_pushes, a.raw, next_after, dig);
            });
    }
    ~VNode() { relay->stop(); engine->stop(); }
    void pump() {
        for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a));
        for (auto& a : relay->drain_drops()) drop_ids.insert(a.id);
        ingest->tick(template_height);
    }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
    bytes32 digest() { auto s = engine->snapshot(kChain); return s ? s->digest : bytes32{}; }
    void dump_logs(std::size_t max = 20) {
        std::lock_guard<std::mutex> lk(log_mtx);
        for (std::size_t i = 0; i < logs.size() && i < max; ++i) std::printf("    [%s] %s\n", name.c_str(), logs[i].c_str());
        logs.clear();
    }
};

static RelayOptions opts(bool listen, std::vector<u16> dial, std::size_t threads, std::size_t qmax) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = kFloorDiff;
    o.verify_queue_max = qmax;
    o.reoffer_seconds = 0;
    o.dos.per_peer_capacity = 64; o.dos.global_capacity = 1024;   // valid PoW refunds; bursts only
#if defined(C2POOL_XMR_RELAY_VERIFY_POOL)
    o.verify_threads = threads;
#else
    (void)threads;
#endif
    return o;
}

template <class F>
static bool wait_for(F cond, std::vector<VNode*> pump, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}

struct Cfg {
    std::size_t threads = 1;
    int hash_ms = 25, ticks = 10, tick_ms = 1000, receipts_per_tick = 1, drops_per_tick = 10;
    std::size_t qmax = 4096;
    u32 fail_once = 0;       // N7
    bool stop_test = false;  // N6: stop C with its queue full instead of draining it
};
struct Result {
    bool ready = false;
    u64 qdrop = 0, late = 0, pushed = 0, rx_calls = 0, parked = 0, unavail = 0;
    std::size_t exp_receipts = 0, exp_drops = 0, lane_receipts = 0, drops_got = 0;
    int peak = 0;
    u64 next_pos = 0;
    bytes32 digest{};
    std::set<bytes32> receipt_ids;
    double secs = 0, stop_ms = 0;
    u64 calls_after_stop = 0;
    bool quiet_after_stop = false;
    u64 n_qdrop[3] = {0, 0, 0}, n_late[3] = {0, 0, 0}, n_pushed[3] = {0, 0, 0}, n_calls[3] = {0, 0, 0};
    std::size_t n_receipts[3] = {0, 0, 0}, n_drops[3] = {0, 0, 0};
    double max_lag_s = 0;   // longest verify backlog seen on C (queue depth / service rate proxy: items)
    std::size_t max_q = 0;
};

static constexpr u64 kH0 = 1000;

static Result run(const Cfg& c) {
    Result r;
    const auto t0 = std::chrono::steady_clock::now();
    VNode A("A", opts(true, {}, c.threads, c.qmax), c.hash_ms);
    std::string why;
    if (!A.relay->start(why)) { std::printf("    A start: %s\n", why.c_str()); return r; }
    VNode B("B", opts(true, {A.relay->listen_port()}, c.threads, c.qmax), c.hash_ms);
    if (!B.relay->start(why)) { std::printf("    B start: %s\n", why.c_str()); return r; }
    VNode C("C", opts(false, {A.relay->listen_port(), B.relay->listen_port()}, c.threads, c.qmax), c.hash_ms);
    C.fail_once = c.fail_once;
    if (!C.relay->start(why)) { std::printf("    C start: %s\n", why.c_str()); return r; }
    std::vector<VNode*> all{&A, &B, &C};
    r.ready = wait_for([&] { return A.relay->ready_peers().size() == 2 && B.relay->ready_peers().size() == 2 &&
                                    C.relay->ready_peers().size() == 2; }, all);
    if (!r.ready) { A.dump_logs(); C.dump_logs(); return r; }

    // the deterministic script: one synthetic Monero block per bin, receipts + raindrops per minter
    const ::v37::ScriptRef pay[2] = {payee_of("verify-pool-A"), payee_of("verify-pool-B")};
    std::vector<std::vector<std::pair<int, Admitted>>> rec(c.ticks), drp(c.ticks);
    std::set<bytes32> exp_rec, exp_drop;
    for (int h = 0; h < c.ticks; ++h) {
        const SynthBlock sb = make_block(kH0 + h, b32_of(static_cast<u8>(h + 1)), 7u + h, nullptr, 0, static_cast<u8>(h));
        for (auto* n : all) n->chain.note(sb.prev_id, sb.height, bytes32{});
        for (int m = 0; m < 2; ++m) {
            for (int i = 0; i < c.receipts_per_tick + c.drops_per_tick; ++i) {
                const bool drop = i >= c.receipts_per_tick;
                const u32 nonce = drop ? kDropNonce + (static_cast<u32>(m + 1) << 24) + (static_cast<u32>(h) << 12) + static_cast<u32>(i)
                                       : (static_cast<u32>(m + 1) << 20) + (static_cast<u32>(h) << 8) + static_cast<u32>(i);
                Admitted a; std::string w;
                if (!mint_on(sb, nonce, pay[m], kChain, kShareDiff, a.r, &w)) { std::printf("    mint failed: %s\n", w.c_str()); continue; }
                a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
                if (drop) { a.pow.fill(0); a.pow[31] = 0x02; exp_drop.insert(a.id); drp[h].emplace_back(m, std::move(a)); }
                else { exp_rec.insert(a.id); rec[h].emplace_back(m, std::move(a)); }
            }
        }
    }
    r.exp_receipts = exp_rec.size(); r.exp_drops = exp_drop.size();
    VNode* minter[2] = {&A, &B};
    for (int h = 0; h < c.ticks; ++h) {
        for (auto* n : all) { n->template_height = kH0 + h; n->chain.set_tip(kH0 + h); }
        for (auto& [m, a] : rec[h]) minter[m]->relay->submit_own(a);
        const int slices = std::max(10, c.tick_ms / 100);
        std::size_t k = 0;
        for (int s = 0; s < slices; ++s) {
            const std::size_t upto = drp[h].size() * static_cast<std::size_t>(s + 1) / slices;
            for (; k < upto; ++k) {
                minter[drp[h][k].first]->relay->submit_own_drop(drp[h][k].second);
            }
            for (auto* n : all) n->pump();
#if defined(C2POOL_XMR_RELAY_VERIFY_POOL)
            r.max_q = std::max(r.max_q, C.relay->verify_queue_size());
#endif
            std::this_thread::sleep_for(std::chrono::milliseconds(c.tick_ms / slices));
        }
    }
    if (c.stop_test) {   // N6: stop C while its queue is still full
        const auto s0 = std::chrono::steady_clock::now();
        C.relay->stop();
        r.stop_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - s0).count();
        r.calls_after_stop = C.rx_calls.load();
        std::this_thread::sleep_for(300ms);
        r.quiet_after_stop = (C.rx_calls.load() == r.calls_after_stop) && C.rx_now.load() == 0;
        r.qdrop = C.relay->stats().queue_dropped.load();
        return r;
    }
    // drain: the last bins close once every node's verify pipeline is quiet
    for (auto* n : all) { n->template_height = kH0 + c.ticks + 1; n->chain.set_tip(kH0 + c.ticks + 1); }
    {
        const auto dl = std::chrono::steady_clock::now() + 60s;
        u64 last = ~0ull; auto still = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() < dl) {
            for (auto* n : all) n->pump();
            const u64 now = A.rx_calls.load() + B.rx_calls.load() + C.rx_calls.load();
            if (now != last) { last = now; still = std::chrono::steady_clock::now(); }
            else if (std::chrono::steady_clock::now() - still > 1500ms) break;
            std::this_thread::sleep_for(20ms);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(std::max(400, g_grace_ms + 300)));   // > grace_ms: every bin closes
        for (auto* n : all) n->pump();
    }
    const auto& st = C.relay->stats();
    r.qdrop = st.queue_dropped.load();
    r.late = C.ingest->stats().late;
    r.pushed = C.ingest->stats().pushed;
    r.rx_calls = C.rx_calls.load();
    r.peak = C.rx_peak.load();
    r.unavail = st.rx_unavailable.load();
#if defined(C2POOL_XMR_RELAY_VERIFY_POOL)
    r.parked = st.rx_unavail_parked.load();
#endif
    for (const auto& id : C.pushed_ids) if (exp_rec.count(id)) { ++r.lane_receipts; r.receipt_ids.insert(id); }
    for (const auto& id : C.drop_ids) if (exp_drop.count(id)) ++r.drops_got;
    r.next_pos = C.next_pos();
    r.digest = C.digest();
    for (int i = 0; i < 3; ++i) {
        VNode& n = *all[i];
        r.n_qdrop[i] = n.relay->stats().queue_dropped.load();
        r.n_late[i] = n.ingest->stats().late; r.n_pushed[i] = n.ingest->stats().pushed; r.n_calls[i] = n.rx_calls.load();
        for (const auto& id : n.pushed_ids) if (exp_rec.count(id)) ++r.n_receipts[i];
        for (const auto& id : n.drop_ids) if (exp_drop.count(id)) ++r.n_drops[i];
    }
    r.secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("    run threads=%zu hash_ms=%d ticks=%d offered_to_C=%.0f/s: C qdrop=%llu late=%llu pushed=%llu "
                "lane_receipts=%zu/%zu drops=%zu/%zu rx_calls=%llu peak_concurrent=%d unavail=%llu parked=%llu "
                "next_pos=%llu digest=%s (%.1f s)\n",
                c.threads, c.hash_ms, c.ticks,
                2.0 * (c.receipts_per_tick + c.drops_per_tick) * 1000.0 / c.tick_ms,
                (unsigned long long)r.qdrop, (unsigned long long)r.late, (unsigned long long)r.pushed,
                r.lane_receipts, r.exp_receipts, r.drops_got, r.exp_drops, (unsigned long long)r.rx_calls, r.peak,
                (unsigned long long)r.unavail, (unsigned long long)r.parked,
                (unsigned long long)r.next_pos, hex(r.digest).substr(0, 16).c_str(), r.secs);
    std::fflush(stdout);
    return r;
}

static double cpu_s() {
#if defined(V37_XMR_O2_WITH_RANDOMX)
    rusage u{}; getrusage(RUSAGE_SELF, &u);
    return u.ru_utime.tv_sec + u.ru_stime.tv_sec + (u.ru_utime.tv_usec + u.ru_stime.tv_usec) / 1e6;
#else
    return 0;
#endif
}
static long rss_kb() {
    long kb = 0;
    if (std::FILE* f = std::fopen("/proc/self/status", "r")) {
        char line[256];
        while (std::fgets(line, sizeof line, f)) if (std::sscanf(line, "VmRSS: %ld kB", &kb) == 1) break;
        std::fclose(f);
    }
    return kb;
}

// VP_LIVE=1: the M2 measurement -- real RandomX light cost, the false-start
// offered load (VP_DROPS_PER_S per minter; 2 minters), bins of VP_TICK_MS with
// the daemon's grace (4000 ms), default verify queue (4096), VP_THREADS workers
// per node (0 = the daemon's auto rule clamp(cores/2, 2, 8)). Prints METRICS.
static int live_main() {
    auto env = [](const char* k, double d) { const char* v = std::getenv(k); return v ? std::atof(v) : d; };
    const double rate = env("VP_DROPS_PER_S", 21), secs = env("VP_SECS", 120);
    const int tick_ms = static_cast<int>(env("VP_TICK_MS", 10000));
    std::size_t thr = static_cast<std::size_t>(env("VP_THREADS", 0));
    if (thr == 0) thr = std::clamp<std::size_t>(std::max(1u, std::thread::hardware_concurrency()) / 2, 2, 8);
    g_live = true; g_grace_ms = static_cast<int>(env("VP_GRACE_MS", 4000)); g_live_workers = thr;
    Cfg c; c.threads = thr; c.hash_ms = 0; c.tick_ms = tick_ms; c.ticks = std::max(1, static_cast<int>(secs * 1000 / tick_ms));
    c.drops_per_tick = static_cast<int>(rate * tick_ms / 1000.0 + 0.5);
    c.receipts_per_tick = std::max(1, c.drops_per_tick / 64);
    c.qmax = static_cast<std::size_t>(env("VP_QMAX", 4096));
    const double cpu0 = cpu_s();
    const Result r = run(c);
    const double cpu = cpu_s() - cpu0;
    std::printf("METRICS build=%s threads=%zu offered_pool=%.1f/s ticks=%d tick_ms=%d secs=%.0f ready=%d "
                "A:qdrop=%llu,late=%llu/%llu,rx=%llu,receipts=%zu,drops=%zu "
                "B:qdrop=%llu,late=%llu/%llu,rx=%llu,receipts=%zu,drops=%zu "
                "C:qdrop=%llu,late=%llu/%llu,rx=%llu,receipts=%zu/%zu,drops=%zu/%zu max_q=%zu "
                "cpu_total=%.1fs cpu_per_s=%.2f cores rss=%.0fMiB digest=%s\n",
                kFix ? "fix" : "base", kFix ? thr : std::size_t{1}, 2.0 * c.drops_per_tick * 1000.0 / tick_ms, c.ticks, tick_ms, r.secs, r.ready ? 1 : 0,
                (unsigned long long)r.n_qdrop[0], (unsigned long long)r.n_late[0], (unsigned long long)r.n_pushed[0], (unsigned long long)r.n_calls[0], r.n_receipts[0], r.n_drops[0],
                (unsigned long long)r.n_qdrop[1], (unsigned long long)r.n_late[1], (unsigned long long)r.n_pushed[1], (unsigned long long)r.n_calls[1], r.n_receipts[1], r.n_drops[1],
                (unsigned long long)r.n_qdrop[2], (unsigned long long)r.n_late[2], (unsigned long long)r.n_pushed[2], (unsigned long long)r.n_calls[2],
                r.n_receipts[2], r.exp_receipts, r.n_drops[2], r.exp_drops, r.max_q,
                cpu, r.secs > 0 ? cpu / r.secs : 0.0, rss_kb() / 1024.0, hex(r.digest).substr(0, 16).c_str());
    return r.ready ? 0 : 1;
}

int main() {
    if (std::getenv("VP_LIVE")) return live_main();
    Checker C;
    std::printf("v37_xmr_verify_pool_kat (%s build)\n", kFix ? "DROPS-VERIFY-SCALE" : "BASE: one verify worker");
#if defined(V37_VERIFY_POOL_TSAN)
    const int kTicks = 5;   // TSan: same shape, shorter (the sanitizer slows the loopback path)
#else
    const int kTicks = 10;
#endif

    // N1: overload -- ~82 items/s offered to C, one worker verifies 40/s
    Cfg n1; n1.hash_ms = 25; n1.ticks = kTicks; n1.tick_ms = 1000; n1.receipts_per_tick = 1; n1.drops_per_tick = 40; n1.qmax = 256;
    std::printf("  N1 overload, 1 worker (the base pipeline):\n");
    Cfg n1b = n1; n1b.threads = 1;
    const Result b1 = run(n1b);
    C(b1.ready, "N1 triangle A-B-C up (1 worker)");
    C(b1.qdrop > 0 || b1.late > 0,
      "N1 one worker at ~2x its capacity REPRODUCES the false start: qdrop=" + std::to_string(b1.qdrop) +
      " late=" + std::to_string(b1.late) + " (reproduction, holds on base and fix)");
    std::printf("  N1 overload, 4 workers:\n");
    Cfg n1f = n1; n1f.threads = 4;
    const Result f1 = run(n1f);
    C(f1.ready, "N1 triangle A-B-C up (4 workers)");
    C(f1.qdrop == 0, "N1 4 workers: no verify-queue drop on C (qdrop=" + std::to_string(f1.qdrop) + ")");
    C(f1.pushed > 0 && f1.late * 50 <= f1.pushed,
      "N1 4 workers: late receipts <= 2% on C (late=" + std::to_string(f1.late) + " pushed=" + std::to_string(f1.pushed) + ")");
    C(f1.lane_receipts == f1.exp_receipts && f1.drops_got == f1.exp_drops,
      "N1 4 workers: every receipt in C's lane (" + std::to_string(f1.lane_receipts) + "/" + std::to_string(f1.exp_receipts) +
      ") and every raindrop drained (" + std::to_string(f1.drops_got) + "/" + std::to_string(f1.exp_drops) + ")");
    C(f1.peak > 1, "N1 4 workers: RandomX ran on " + std::to_string(f1.peak) + " threads at once on C");

    // N2: determinism at a load one worker sustains -- N = 1 vs N = 8
    Cfg n2; n2.hash_ms = 5; n2.ticks = kTicks / 2 + 1; n2.tick_ms = 500; n2.receipts_per_tick = 3; n2.drops_per_tick = 10;
    std::printf("  N2 determinism:\n");
    Cfg n2a = n2; n2a.threads = 1;
    Cfg n2b = n2; n2b.threads = 8;
    const Result d1 = run(n2a);
    const Result d8 = run(n2b);
    C(d1.ready && d8.ready && d1.late == 0 && d8.late == 0 && d1.qdrop == 0 && d8.qdrop == 0,
      "N2 both runs sustain the load (no late, no qdrop)");
    C(d1.receipt_ids == d8.receipt_ids && d1.lane_receipts == d1.exp_receipts,
      "N2 identical accepted receipt set for N=1 and N=8 (" + std::to_string(d1.receipt_ids.size()) + " receipts)");
    C(d1.drops_got == d8.drops_got && d1.drops_got == d1.exp_drops, "N2 identical raindrop set (" + std::to_string(d1.drops_got) + ")");
    C(d1.next_pos == d8.next_pos && d1.digest == d8.digest,
      "N2 identical lane next_pos + digest on C for N=1 and N=8");
    std::printf("  DETERMINISM next_pos=%llu digest=%s receipts=%zu drops=%zu\n",
                (unsigned long long)d1.next_pos, hex(d1.digest).c_str(), d1.receipt_ids.size(), d1.drops_got);

    // N6: stop() with 8 workers and a full queue
    Cfg n6; n6.threads = 8; n6.hash_ms = 50; n6.ticks = 2; n6.tick_ms = 200; n6.receipts_per_tick = 1; n6.drops_per_tick = 200;
    n6.stop_test = true;
    std::printf("  N6 stop:\n");
    const Result s6 = run(n6);
    C(s6.ready && s6.stop_ms < 2000.0 && s6.quiet_after_stop,
      "N6 stop() with a full queue joins in " + std::to_string(static_cast<int>(s6.stop_ms)) +
      " ms, no RandomX call after it returned");

    // N7: rx-unavailable -> parked once, admitted on the retry
    Cfg n7; n7.threads = 2; n7.hash_ms = 1; n7.ticks = 3; n7.tick_ms = 300; n7.receipts_per_tick = 2; n7.drops_per_tick = 2;
    n7.fail_once = (2u << 20) + (1u << 8);   // B's first receipt of bin 1
    std::printf("  N7 rx-unavailable:\n");
    const Result u7 = run(n7);
    C(u7.ready && u7.parked == 1 && u7.unavail == 0 && u7.lane_receipts == u7.exp_receipts,
      "N7 a refused hash is parked once (parked=" + std::to_string(u7.parked) + " unavail=" + std::to_string(u7.unavail) +
      ") and the receipt is admitted on the retry (" + std::to_string(u7.lane_receipts) + "/" + std::to_string(u7.exp_receipts) + ")");
    return C.done("v37_xmr_verify_pool_kat");
}
