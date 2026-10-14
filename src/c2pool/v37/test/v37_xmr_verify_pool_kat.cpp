// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_verify_pool_kat -- the verify pool of the Path B relay node
// (PathbRelayOptions::verify_threads).
//
// Three Path B relay nodes over REAL loopback TCP in a TRIANGLE (B dials A, C
// dials A and B), each with its own PathbNode. RandomX is a SLEEPING stub
// (hash_ms per hash). A plays a deterministic script, one Monero height per
// tick: jobs on its best tip, a carrier that moves the tip, then the jobs'
// shares (pending receipts on the tip it moved past); every carrier and receipt
// is flooded; B and C verify everything they receive.
//
//   N2  determinism: the same script at a load one worker sustains, N = 1 vs
//       N = 8 workers at every node: identical best tip, pending receipt set
//       and lane digest on C (printed, so runs can be diffed).
//   N6  stop: stop() with 8 workers and a full queue joins within 2 s and no
//       RandomX call starts after stop() returns.
//   N7  seed not held: a carrier whose seed C does not hold is parked once (a
//       seed DEFER) and admitted when the follower's main chain moves.
//   N8  RandomX throws three times at C on A's carrier (a node-internal
//       failure): every failure counted, one alarm line when it starts and
//       one when a hash is computed again; no strike, no ban; the frame
//       parked and run again: placed; a re-run is not counted in P-15.
//   N9  RandomX throws once at C on a receipt body A floods: no strike, no
//       ban; the receipt parked and run again: held at C; its re-run not
//       counted in P-15.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;

// A node and its sleeping RandomX stub.
struct VNode {
    std::unique_ptr<RNode> n;
    int hash_ms = 0;
    std::atomic<int> rx_now{0}, rx_peak{0};   // concurrent RandomX calls
    VNode(Rig& rig, std::string name, pb::PathbRelayOptions o, bool launch, int hms) : hash_ms(hms) {
        n = rig.make(std::move(name), std::move(o), launch);
        n->rx = [this](const pb::HashingBlob&, std::uint64_t, const pb::Hash32&) {
            const int now = ++rx_now;
            int pk = rx_peak.load();
            while (now > pk && !rx_peak.compare_exchange_weak(pk, now)) {}
            if (hash_ms) std::this_thread::sleep_for(std::chrono::milliseconds(hash_ms));
            --rx_now;
            return true;
        };
    }
    ~VNode() { n.reset(); }   // the relay stops before the stub's members go
    u64 rx_calls() const { return n->rx_calls.load(); }
    std::set<pb::Hash32> pending_ids() {
        return n->r().with_node([](pb::PathbNode& pn) {
            std::set<pb::Hash32> s;
            for (const pb::PendingReceipt* p : pn.pending().all()) s.insert(p->id);
            return s;
        });
    }
    std::string lane_digest() { return n->r().with_node([](pb::PathbNode& pn) { return pn.lane_digest(); }); }
};

static pb::PathbRelayOptions opts(bool listen, std::vector<u16> dial, std::size_t threads, std::size_t qmax) {
    pb::PathbRelayOptions o = Rig::opts(listen, dial);
    o.verify_threads = threads;
    o.verify_queue_max = qmax;
    ::c2pool::xmr::DosPolicy d;
    d.per_peer_capacity = 64;
    d.global_capacity = 1024;   // valid objects refund their token; bursts only
    o.dos = d;
    return o;
}

struct Cfg {
    std::size_t threads = 1;
    int hash_ms = 5, ticks = 6, tick_ms = 500, receipts_per_tick = 3;
    std::size_t qmax = 4096;
    bool stop_test = false;   // N6: stop C with its queue full instead of draining it
};
struct Result {
    bool ready = false, converged = false;
    u64 qdrop = 0, rx_calls = 0, workers = 0;
    int peak = 0;
    pb::Hash32 best{};
    u64 best_pos = 0;
    std::set<pb::Hash32> pending;
    std::string digest;
    double secs = 0, stop_ms = 0;
    bool quiet_after_stop = false;
    std::size_t queued_at_stop = 0;
};

static Result run(const Cfg& c) {
    Result r;
    const auto t0 = std::chrono::steady_clock::now();
    Rig rig;
    VNode A(rig, "A", opts(true, {}, c.threads, c.qmax), true, c.hash_ms);
    if (!A.n->start()) return r;
    VNode B(rig, "B", opts(true, {A.n->port()}, c.threads, c.qmax), false, c.hash_ms);
    if (!B.n->start()) return r;
    VNode C(rig, "C", opts(false, {A.n->port(), B.n->port()}, c.threads, c.qmax), false, c.hash_ms);
    if (!C.n->start()) return r;
    r.ready = wait_until([&] {
        return A.n->r().ready_peers().size() == 2 && B.n->r().ready_peers().size() == 2 && C.n->r().ready_peers().size() == 2;
    }, 15000ms);
    if (!r.ready) { A.n->dump_logs(); C.n->dump_logs(); return r; }
    r.workers = C.n->st().verify_threads.load();

    // the deterministic script, one Monero height per tick
    std::uint32_t nonce = 1;
    for (int h = 0; h < c.ticks; ++h) {
        rig.tick_monero();
        std::vector<std::pair<pb::PathbJob, std::uint32_t>> jobs;
        for (int i = 0; i < c.receipts_per_tick; ++i) {
            const std::optional<pb::PathbJob> j = rig.job(*A.n, static_cast<std::size_t>(i % 5), 1000 + static_cast<std::uint32_t>(h));
            if (j) jobs.emplace_back(*j, nonce++);
        }
        (void)rig.mine(*A.n, static_cast<std::size_t>(h % 5), nonce++);
        const int slices = std::max(1, std::min(c.receipts_per_tick, 10));
        std::size_t k = 0;
        for (int s = 0; s < slices; ++s) {
            const std::size_t upto = jobs.size() * static_cast<std::size_t>(s + 1) / static_cast<std::size_t>(slices);
            for (; k < upto; ++k) (void)rig.share(*A.n, jobs[k].first, jobs[k].second);
            std::this_thread::sleep_for(std::chrono::milliseconds(c.tick_ms / slices));
        }
    }
    if (c.stop_test) {   // N6: stop C while its queue is still full
        r.queued_at_stop = C.n->r().verify_queue_size() + C.n->r().parked_size();
        const auto s0 = std::chrono::steady_clock::now();
        C.n->r().stop();
        r.stop_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - s0).count();
        const u64 calls_after_stop = C.rx_calls();
        std::this_thread::sleep_for(300ms);
        r.quiet_after_stop = C.rx_calls() == calls_after_stop && C.rx_now.load() == 0;
        r.qdrop = C.n->st().queue_dropped.load();
        std::printf("    N6 C: %zu jobs queued at stop(), %llu RandomX calls; stop() took %.0f ms\n", r.queued_at_stop,
                    (unsigned long long)calls_after_stop, r.stop_ms);
        return r;
    }
    // drain: C has A's best tip and A's pending set once every node is quiet
    const pb::Hash32 a_best = A.n->best();
    const std::set<pb::Hash32> a_pending = A.pending_ids();
    r.converged = wait_until([&] { return C.n->best() == a_best && C.pending_ids() == a_pending; }, 60000ms, 50ms);
    {
        const auto dl = std::chrono::steady_clock::now() + 30s;
        u64 last = ~0ull;
        auto still = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() < dl) {
            const u64 now = A.rx_calls() + B.rx_calls() + C.rx_calls();
            if (now != last) { last = now; still = std::chrono::steady_clock::now(); }
            else if (std::chrono::steady_clock::now() - still > 1500ms) break;
            std::this_thread::sleep_for(20ms);
        }
    }
    r.qdrop = C.n->st().queue_dropped.load();
    r.rx_calls = C.rx_calls();
    r.peak = C.rx_peak.load();
    r.best = C.n->best();
    r.best_pos = C.n->best_pos();
    r.pending = C.pending_ids();
    r.digest = C.lane_digest();
    r.secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("    run threads=%zu (C workers %llu) hash_ms=%d ticks=%d: C qdrop=%llu rx_calls=%llu peak_concurrent=%d "
                "best_pos=%llu pending=%zu converged=%d digest=%s (%.1f s)\n",
                c.threads, (unsigned long long)r.workers, c.hash_ms, c.ticks, (unsigned long long)r.qdrop,
                (unsigned long long)r.rx_calls, r.peak, (unsigned long long)r.best_pos, r.pending.size(), r.converged ? 1 : 0,
                r.digest.substr(0, 32).c_str(), r.secs);
    std::fflush(stdout);
    return r;
}

// N7: C holds no seed when A's carrier arrives: parked once, admitted when the follower's chain moves.
static bool n7(std::string& note) {
    Rig rig;
    auto A = rig.make("A", opts(true, {}, 1, 4096), true);
    if (!A->start()) return false;
    auto Cn = rig.make("C", opts(false, {A->port()}, 1, 4096), false);
    Cn->seed_off = true;
    if (!Cn->start()) return false;
    if (!wait_until([&] { return A->r().ready_peers().size() == 1 && Cn->r().ready_peers().size() == 1; }, 5000ms)) return false;
    rig.tick_monero();
    if (rig.mine(*A, 0, 0x7000).action != pb::NodeAction::Placed) return false;
    const pb::Hash32 c = A->best();
    const bool parked = wait_until([&] { return Cn->r().parked_index_size() >= 1; }, 5000ms) && Cn->best() != c;
    Cn->seed_off = false;
    Cn->r().on_monero_tip();
    const bool placed = wait_until([&] { return Cn->best() == c; }, 5000ms);
    note = "parked " + std::to_string(parked) + ", re-runs " + std::to_string(Cn->st().parked_reruns.load()) +
           ", strikes " + std::to_string(Cn->st().strikes.load());
    return parked && placed && Cn->st().parked_reruns.load() >= 1 && Cn->st().strikes.load() == 0 && Cn->st().bans.load() == 0;
}

// N8: C's RandomX throws three times: the carrier parked and run again; no token; two alarm lines.
static bool n8(std::string& note) {
    Rig rig;
    auto A = rig.make("A", opts(true, {}, 1, 4096), true);
    if (!A->start()) return false;
    auto Cn = rig.make("C", opts(false, {A->port()}, 1, 4096), false);
    auto throws = std::make_shared<std::atomic<int>>(3);
    Cn->rx = [throws](const pb::HashingBlob&, std::uint64_t, const pb::Hash32&) -> bool {
        if (throws->fetch_sub(1) > 0) throw std::runtime_error("randomx: dataset");
        return true;
    };
    if (!Cn->start()) return false;
    if (!wait_until([&] { return A->r().ready_peers().size() == 1 && Cn->r().ready_peers().size() == 1; }, 5000ms)) return false;
    rig.tick_monero();
    if (rig.mine(*A, 0, 0x7100).action != pb::NodeAction::Placed) return false;
    const pb::Hash32 c = A->best();
    const bool placed = wait_until([&] { return Cn->best() == c; }, 10000ms);
    const bool again = wait_until([&] { return Cn->count_logs("RandomX hashes again") == 1; }, 3000ms);
    const std::size_t lines = Cn->count_logs("RandomX");
    note = "rx failures " + std::to_string(Cn->st().rx_failures.load()) + ", alarm lines " + std::to_string(lines) +
           ", strikes " + std::to_string(Cn->st().strikes.load()) + ", bans " + std::to_string(Cn->st().bans.load()) +
           ", P-15 counted " + std::to_string(Cn->st().p15_counted.load());
    return placed && again && Cn->st().rx_failures.load() == 3 && lines == 2 && Cn->st().p15_counted.load() == 0 &&
           Cn->count_logs("RandomX failing") == 1 && Cn->st().strikes.load() == 0 && Cn->st().bans.load() == 0 &&
           Cn->r().ready_peers().size() == 1;
}

// N9: C's RandomX throws once on a receipt body: the receipt parked and run again; no token.
static bool n9(std::string& note) {
    Rig rig;
    auto A = rig.make("A", opts(true, {}, 1, 4096), true);
    if (!A->start()) return false;
    auto Cn = rig.make("C", opts(false, {A->port()}, 1, 4096), false);
    auto throws = std::make_shared<std::atomic<int>>(0);
    Cn->rx = [throws](const pb::HashingBlob&, std::uint64_t, const pb::Hash32&) -> bool {
        if (throws->load() > 0 && throws->fetch_sub(1) > 0) throw std::runtime_error("randomx: dataset");
        return true;
    };
    if (!Cn->start()) return false;
    if (!wait_until([&] { return A->r().ready_peers().size() == 1 && Cn->r().ready_peers().size() == 1; }, 5000ms)) return false;
    rig.tick_monero();
    const std::optional<pb::PathbJob> j = rig.job(*A, 1, 0x91);
    if (!j || rig.mine(*A, 0, 0x7200).action != pb::NodeAction::Placed) return false;
    if (!wait_until([&] { return Cn->best() == A->best(); }, 5000ms)) return false;
    const std::uint64_t counted0 = Cn->st().p15_counted.load();
    throws->store(1);
    const pb::NodeEventResult r = rig.share(*A, *j, 0x7300);
    if (r.action != pb::NodeAction::Pending) return false;
    const pb::Hash32 id = r.admit.id;
    const auto held = [&] { return Cn->r().with_node([&](pb::PathbNode& n) { return n.pending().holds(id); }); };
    const bool ok = wait_until(held, 10000ms);
    const std::uint64_t counted = Cn->st().p15_counted.load() - counted0;
    note = "rx failures " + std::to_string(Cn->st().rx_failures.load()) + ", strikes " +
           std::to_string(Cn->st().strikes.load()) + ", bans " + std::to_string(Cn->st().bans.load()) +
           ", P-15 counted by the re-run " + std::to_string(counted);
    return ok && throws->load() <= 0 && Cn->st().rx_failures.load() == 1 && Cn->st().strikes.load() == 0 &&
           Cn->st().bans.load() == 0 && counted == 0;
}

int main() {
    Checker C;
    std::printf("v37_xmr_verify_pool_kat (the Path B relay node)\n");
#if defined(V37_VERIFY_POOL_TSAN)
    const int kTicks = 5;   // TSan: same shape, shorter (the sanitizer slows the loopback path)
#else
    const int kTicks = 10;
#endif

    // N2: determinism at a load one worker sustains -- N = 1 vs N = 8
    Cfg n2; n2.hash_ms = 5; n2.ticks = kTicks / 2 + 1; n2.tick_ms = 500; n2.receipts_per_tick = 3;
    std::printf("  N2 determinism:\n");
    Cfg n2a = n2; n2a.threads = 1;
    Cfg n2b = n2; n2b.threads = 8;
    const Result d1 = run(n2a);
    const Result d8 = run(n2b);
    C(d1.ready && d8.ready && d1.converged && d8.converged && d1.qdrop == 0 && d8.qdrop == 0 && d1.workers == 1 &&
      d8.workers == 8,
      "N2 both runs (1 and 8 verify workers) sustain the load: no queue drop, C reaches A's best tip and pending set");
    C(d1.pending == d8.pending && d1.best == d8.best && !d1.pending.empty(),
      "N2 identical accepted set on C for N=1 and N=8 (best tip and " + std::to_string(d1.pending.size()) + " pending receipts)");
    C(d1.best_pos == d8.best_pos && d1.digest == d8.digest && !d1.digest.empty(),
      "N2 identical best position + lane digest on C for N=1 and N=8");
    std::printf("  DETERMINISM best_pos=%llu digest=%s pending=%zu\n",
                (unsigned long long)d1.best_pos, d1.digest.c_str(), d1.pending.size());

    // N6: stop() with 8 workers and a full queue
    Cfg n6; n6.threads = 8; n6.hash_ms = 50; n6.ticks = 2; n6.tick_ms = 200; n6.receipts_per_tick = 200;
    n6.stop_test = true;
    std::printf("  N6 stop:\n");
    const Result s6 = run(n6);
    C(s6.ready && s6.stop_ms < 2000.0 && s6.quiet_after_stop,
      "N6 stop() with a full queue joins in " + std::to_string(static_cast<int>(s6.stop_ms)) +
      " ms, no RandomX call after it returned");
    // N7: a seed DEFER parked once and run again when the follower's chain moves
    std::string n7note;
    const bool n7ok = n7(n7note);
    C(n7ok, "N7 a carrier whose seed C does not hold is parked once and admitted when the follower's chain moves (" + n7note + ")");
    // N8: a RandomX exception is node-internal
    std::string n8note;
    const bool n8ok = n8(n8note);
    C(n8ok, "N8 RandomX throws three times at C: 3 failures, 2 alarm lines; no strike, no ban, the link kept; the carrier "
            "parked and placed (" + n8note + ")");
    std::string n9note;
    const bool n9ok = n9(n9note);
    C(n9ok, "N9 RandomX throws once at C on a receipt body: no strike, no ban; the receipt parked and held (" + n9note + ")");
    return C.done("v37_xmr_verify_pool_kat");
}
