// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xmr_cpu_miner.hpp — c2pool's OWN in-process RandomX CPU miner for the v37
// Work-Receipts "Family B: XMR lane".
//
// WHY THIS EXISTS
//   Until now the daemonless Monero node (src/impl/xmr/native/**, driven by
//   main_v37_xmr.cpp) built its own template, verified its own chain and
//   finalized its own wins — but the hashing itself came from an EXTERNAL
//   miner over stratum. That is one process too many for the M1 demo, for the
//   "phone-class node" story, and for a CI-shaped self-contained proof. This
//   header closes that last gap: one c2pool-v37-xmr process that builds the
//   template, hashes it, finds the block and books the payout.
//
//   It is an ADDITIVE worker. It produces nothing the node does not already
//   validate: every hit is handed back through the SAME (template_id, nonce,
//   extra_nonce) triple a stratum client would submit, and it is the node's
//   existing exact 128-bit RandomX gate that decides whether a block is real.
//   Nothing in src/sharechain/v37 is touched, read or re-derived here.
//
// PROVENANCE / LICENCE HYGIENE  (read this before editing)
//   This file is ORIGINAL c2pool code written against the PUBLIC C API of the
//   vendored tevador/RandomX library (BSD-3-Clause, src/impl/xmr/third_party/
//   randomx). It contains NO code from xmrig (GPL-3.0), NO code from p2pool
//   (GPL-3.0) and NO code from monerod. The RandomX algorithm is NOT
//   reimplemented here — every hash is produced by librandomx via
//   randomx_calculate_hash_first / _next / _last.
//
//   Two well-known TECHNIQUES are re-implemented from their primary sources
//   (a technique is not copyrightable; the expression below is ours):
//     * huge pages  — RANDOMX_FLAG_LARGE_PAGES, documented in randomx.h itself
//       (BSD-3). Graceful fallback is our own two-try allocator.
//     * thread affinity — sched_setaffinity(2), Linux man-pages. The
//       one-thread-per-PHYSICAL-core ordering is derived from sysfs topology
//       (/sys/devices/system/cpu/cpuN/topology), also our own.
//   MSR-boost (wrmsr on the prefetcher/MSR ranges) is deliberately NOT here:
//   it needs root, is per-microarchitecture, and is a later opt-in.
//
// SCOPE / NON-GOALS
//   * CPU ONLY. There is no GPU path and none is planned in this file.
//   * The miner never talks to a socket, a daemon or the sharechain. It takes
//     a MinerJob in and gives MinerHits out; the CALLER (main_v37_xmr.cpp)
//     owns every seam that has consequences.
//   * The miner's own target test is the cheap u64 one (top LE word <=
//     target), byte-identical to what xmr_stratum.cpp computes for a submit.
//     It is a SUPERSET of Monero's exact 128-bit rule, which is exactly what a
//     miner wants (it never misses a real block) — the exact decision stays
//     where it already is, in O2RandomXVerifier::verify_network_block.
//
// THREADING CONTRACT
//   * set_job() / stop() / pop_hit() / stats(): CALLER thread only (in
//     main_v37_xmr.cpp that is the main loop thread, the same thread that owns
//     the template provider).
//   * Worker threads only read the job snapshot and push hits. They never call
//     back into caller code, so there is no re-entrancy to reason about.
//   * A seed change quiesces every worker, re-keys the cache (and, in fast
//     mode, rebuilds the dataset) and restarts them. That costs a couple of
//     seconds once per Monero epoch (2048 blocks, ~2.8 days) and buys an
//     obviously-correct lifetime for randomx_cache*.
//   * Cache INITIALISATION is serialised process-wide against the node's own
//     verifier through randomx_init_lock.hpp — see that header for the SIGFPE
//     this prevents. The dataset build does not take that lock. The hot loop
//     never takes that lock.
//   * The keyer thread only builds. install_ready(), clear_job(), describe(),
//     running(), take_events() and the notes are CALLER thread only too; every
//     install, worker start and halt runs on the caller thread. A new seed is a
//     build request (seed, generation, the resources to release) in a slot only
//     the caller writes. The keyer releases those resources, keys the cache
//     (fast mode: builds the dataset), creates the VMs and publishes one result
//     (resources, seed, generation, outcome) in a slot only the keyer writes.
//     Resources change owner only through these two slots. The keyer abandons
//     a build when a newer request or stop() exists. A job is installed only
//     when its seed_hash equals the resources' seed; install_ready() installs
//     the posted job on the result of the newest request.

#ifndef C2POOL_XMR_CPU_MINER_HPP
#define C2POOL_XMR_CPU_MINER_HPP

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <random>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <sched.h>
#include <unistd.h>
#endif

#include "randomx.h"             // vendored BSD-3, third_party/randomx/randomx.h
#include "randomx_init_lock.hpp" // process-wide serialisation of cache/dataset init

namespace c2pool {
namespace xmr {
namespace miner {

inline constexpr std::size_t kHashSize  = 32;
inline constexpr std::size_t kSeedSize  = 32;
inline constexpr std::size_t kNonceSize = 4;

using HashBytes = std::array<std::uint8_t, kHashSize>;
using SeedBytes = std::array<std::uint8_t, kSeedSize>;

// ---------------------------------------------------------------------------
// Test-only: the points at which MinerOptions::test_hook is called.
//   keyer thread:  AfterConsume, BeforeAlloc, AfterCacheInit (the init lock is
//                  already dropped), BuildThreadStart (index = build thread),
//                  BeforePublish, AfterPublish;
//   caller thread: Requested (after the request is written), StopRequested
//                  (after stop() is written), WorkerStart (index = worker),
//                  KeyerStart (before the keyer thread is started).
// `gen` is the request generation. `cancelled` is the keyer's own predicate for
// that generation (always false at a caller-thread point).
// ---------------------------------------------------------------------------
enum class TestPoint : unsigned {
    AfterConsume,
    BeforeAlloc,
    AfterCacheInit,
    BuildThreadStart,
    BeforePublish,
    AfterPublish,
    Requested,
    StopRequested,
    WorkerStart,
    KeyerStart,
};
using TestHook = std::function<void(TestPoint, std::uint64_t gen, unsigned index,
                                    const std::function<bool()>& cancelled)>;

// ---------------------------------------------------------------------------
// Options. Everything here is a TUNING knob; none of it changes a hash.
// ---------------------------------------------------------------------------
struct MinerOptions {
    // 0 => auto: half of hardware_concurrency (one thread per physical core on
    // a 2-way SMT box), clamped to >= 1. RandomX gains little from SMT and a
    // node that eats every core is a bad neighbour to its own event loop.
    unsigned threads = 0;

    // false (DEFAULT) => LIGHT mode: a 256 MiB Argon2d cache, no dataset. Slow
    // per hash but ~8x less memory, starts in ~1 s, and is all a regtest /
    // demo / phone-class node needs.
    // true => FAST mode: RANDOMX_FLAG_FULL_MEM + a ~2080 MiB dataset. Opt-in
    // (--mine-fast), because the allocation and the multi-second init are not
    // something a node should do behind its operator's back.
    bool fast_mode = false;

    // Ask for RANDOMX_FLAG_LARGE_PAGES on the cache, the dataset and the VM
    // scratchpads. GRACEFUL: every allocation is retried without the flag, so
    // a host with no hugepages configured still mines (just slower). Report
    // what actually happened with large_pages_note().
    bool large_pages = true;

    // Pin each worker to one CPU, preferring one per physical core. RandomX is
    // a cache-resident workload; migration costs more than it looks.
    bool pin_threads = true;

    bool use_jit    = true;   // RANDOMX_FLAG_JIT
    bool secure_jit = false;  // RANDOMX_FLAG_SECURE (W^X JIT pages), opt-in

    // How many hits may sit in the outbound queue before the oldest is dropped.
    // A lane target set absurdly low is an operator error, not a reason to
    // grow without bound on a node's heap.
    std::size_t hit_queue_cap = 512;

    // After a NETWORK-target hit, stop hashing THAT template: a second winning
    // nonce on the same template is a second block at the same height, i.e. we
    // race ourselves and orphan one of our own wins. (Observed on the regtest
    // rig: 35 of 89 registered finds were same-height duplicates from a template
    // the workers kept grinding after the first hit.) Normal service resumes on
    // the next template.
    //
    // The timeout is the ANTI-STALL, and it is deliberately SHORT. A regtest run
    // with a 30 s window stalled outright: the 12th find was refused by the
    // daemon, so the tip never moved, the template never changed, and the miner
    // spent the rest of the run parked on work nobody was going to replace. The
    // suppression must therefore be worth much less than a block interval, not
    // more: at ~2 s it still covers the burst right after a find (which is where
    // the duplicates come from) while a chain that stops advancing costs two
    // seconds, not a run. 0 disables the suppression entirely.
    unsigned resume_after_find_ms = 2000;

    // Test-only. Empty by default.
    TestHook test_hook;
};

// ---------------------------------------------------------------------------
// A job: exactly what a stratum client is handed, minus the JSON.
// Built by the caller from strat::TemplateJob (see main_v37_xmr.cpp).
// ---------------------------------------------------------------------------
struct MinerJob {
    std::vector<std::uint8_t> blob;       // hashing blob, extra_nonce ALREADY baked in
    std::size_t   nonce_offset = 0;       // where the 4 nonce bytes live in blob
    std::uint32_t template_id  = 0;
    std::uint32_t extra_nonce  = 0;
    std::uint64_t height       = 0;
    SeedBytes     seed_hash{};
    std::uint64_t network_target = 0;     // 0 => this job can never be a block
    std::uint64_t lane_target    = 0;     // 0 => share reporting off (solo)

    bool valid() const noexcept {
        return !blob.empty() && nonce_offset + kNonceSize <= blob.size() &&
               (network_target != 0 || lane_target != 0);
    }
    // Two jobs are the SAME work iff the bytes we hash and the seed match.
    bool same_work_as(const MinerJob& o) const noexcept {
        return template_id == o.template_id && extra_nonce == o.extra_nonce &&
               nonce_offset == o.nonce_offset && seed_hash == o.seed_hash &&
               network_target == o.network_target && lane_target == o.lane_target &&
               blob == o.blob;
    }
};

// ---------------------------------------------------------------------------
// A hit. `network` and `share` are INDEPENDENT, exactly as in
// xmr_stratum.cpp handle_submit: a hash that clears the network target is a
// block AND (network target being the harder one) also clears the lane target.
// ---------------------------------------------------------------------------
struct MinerHit {
    std::uint32_t template_id = 0;
    std::uint32_t extra_nonce = 0;
    std::uint32_t nonce       = 0;
    std::uint64_t height      = 0;
    HashBytes     pow_hash{};
    std::uint64_t achieved_target = 0;   // top 64-bit LE word of pow_hash
    bool          network = false;       // cleared network_target
    bool          share   = false;       // cleared lane_target
};

struct MinerStats {
    std::uint64_t hashes        = 0;
    std::uint64_t shares        = 0;   // lane-target hits pushed
    std::uint64_t blocks        = 0;   // network-target hits pushed
    std::uint64_t job_switches  = 0;
    std::uint64_t seed_rekeys   = 0;
    std::uint64_t dropped_hits  = 0;   // queue cap reached
    double        hashrate      = 0.0; // H/s since the last install
    unsigned      threads       = 0;
    unsigned      pinned        = 0;   // workers that actually got an affinity mask
    std::uint64_t find_resumes  = 0;   // anti-stall resumes after a spent template
};

namespace detail {

inline std::uint64_t top_word_le(const HashBytes& h) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(h[kHashSize - 8 + i]) << (8 * i);
    return v;
}

// One CPU id per PHYSICAL core first (the lowest-numbered SMT sibling of each
// {package, core}), then the remaining siblings. Derived from sysfs; falls
// back to 0..n-1 wherever topology is unreadable. Linux-only; other platforms
// get the identity order and pinning is a no-op.
inline std::vector<int> preferred_cpu_order() {
    const unsigned n = std::max(1u, std::thread::hardware_concurrency());
    std::vector<int> firsts, rest;
#if defined(__linux__)
    std::map<std::pair<int, int>, int> first_of_core;
    bool any_topology = false;
    for (unsigned cpu = 0; cpu < n; ++cpu) {
        const std::string base =
            "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/";
        int core = -1, pkg = -1;
        {
            std::ifstream f(base + "core_id");
            if (f) f >> core;
        }
        {
            std::ifstream f(base + "physical_package_id");
            if (f) f >> pkg;
        }
        if (core < 0) { rest.push_back(static_cast<int>(cpu)); continue; }
        any_topology = true;
        const auto key = std::make_pair(pkg, core);
        if (first_of_core.emplace(key, static_cast<int>(cpu)).second)
            firsts.push_back(static_cast<int>(cpu));
        else
            rest.push_back(static_cast<int>(cpu));
    }
    if (!any_topology) { firsts.clear(); rest.clear(); }
#endif
    if (firsts.empty() && rest.empty())
        for (unsigned cpu = 0; cpu < n; ++cpu) firsts.push_back(static_cast<int>(cpu));
    firsts.insert(firsts.end(), rest.begin(), rest.end());
    return firsts;
}

// Pin the CALLING thread to one CPU. Returns false when unsupported or refused
// (a container cpuset, a non-Linux host) — never fatal, mining just migrates.
inline bool pin_this_thread(int cpu) {
#if defined(__linux__) && defined(CPU_SETSIZE)
    if (cpu < 0 || cpu >= CPU_SETSIZE) return false;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0;
#else
    (void)cpu;
    return false;
#endif
}

// HugePages_Total from /proc/meminfo, for the operator-facing note only.
// -1 means "could not tell" (not Linux, or /proc unreadable).
inline long hugepages_total() {
#if defined(__linux__)
    std::ifstream f("/proc/meminfo");
    std::string k;
    while (f >> k) {
        if (k == "HugePages_Total:") { long v = 0; f >> v; return v; }
        std::string rest;
        std::getline(f, rest);
    }
#endif
    return -1;
}

inline std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xF]; }
    return s;
}

} // namespace detail

// ===========================================================================
// CpuMiner
// ===========================================================================
class CpuMiner {
public:
    explicit CpuMiner(MinerOptions opts) : m_opt(opts) {
        m_threads_wanted = m_opt.threads;
        if (m_threads_wanted == 0) {
            const unsigned hc = std::max(1u, std::thread::hardware_concurrency());
            m_threads_wanted = std::max(1u, hc / 2);
        }
        m_k_items.reset(new ItemCounter[m_threads_wanted]);
    }
    ~CpuMiner() {
        stop();
        if (m_k_live || !m_workers.empty()) std::abort();
        m_res.reset();
    }

    CpuMiner(const CpuMiner&)            = delete;
    CpuMiner& operator=(const CpuMiner&) = delete;

    // ---- caller-thread API -------------------------------------------------

    // Hand the miner a job. A job whose seed is keyed is installed and the
    // workers run when this returns true. A job with another seed halts the
    // workers and requests a key on the keyer thread, or joins the one
    // outstanding for that seed; true then means the job is posted, and
    // install_ready() installs it once that key is ready unless a newer job or
    // clear_job() replaces it. false means the miner holds no job of it and
    // nothing was posted; *why says why. After a failed key of the job's seed,
    // false also requests one more key of that seed.
    bool set_job(const MinerJob& job, std::string* why = nullptr) {
        if (!job.valid()) {
            if (why) *why = "job has no blob / no target";
            return false;
        }
        if (m_job_valid && job.same_work_as(m_job_shadow)) return true;

        if (m_res && m_res->seed == job.seed_hash) {
            m_want = job;
            if (!install(job)) {
                m_want.reset();
                if (why) *why = "job seed is not the keyed seed";
                return false;
            }
            if (!spawn_workers(why)) {
                m_want.reset();
                return false;
            }
            return true;
        }
        if (pending() && m_rq_seed == job.seed_hash) {
            m_want = job;
            return true;
        }
        const bool retry = !pending() && m_fail && m_fail->seed == job.seed_hash;
        return post(job, retry, why);
    }

    // Once per pass of the caller's loop. Takes the keyer's result for the
    // newest request, if one is published: a failure is recorded; a ready set
    // is kept, and the posted job, if any, is installed on it and the workers
    // run. Returns true iff it installed a job.
    bool install_ready() {
        if (!pending()) return false;
        RxSetPtr      set;
        std::uint64_t gen = 0;
        bool          ok  = false;
        std::string   why;
        long long     ms  = 0;
        {
            std::lock_guard<std::mutex> lk(m_kx_mtx);
            if (!(m_rs_seq > m_c_taken && m_rs_gen == m_rq_gen.load(std::memory_order_relaxed)))
                return false;
            gen = m_rs_gen;
            ok  = m_rs_ok;
            set.reset(m_rs_set);
            why.swap(m_rs_why);
            ms  = m_rs_ms;
            m_c_taken = m_rs_seq;
            kx_notify();
        }
        m_answered_gen = gen;
        if (!ok) {
            take_failed(gen, std::move(why));
            return false;
        }
        if (!set || set->seed != m_rq_seed) std::abort();
        if (m_res || m_running.load(std::memory_order_relaxed) || !m_workers.empty()) std::abort();
        m_res = std::move(set);
        ++m_seed_rekeys;
        m_lp_note = m_res->lp_note;
        emit([&] { return "keyed seed=" + seed16(m_res->seed) + " in " + secs(ms) + " s"; });
        if (!m_want) return false;
        if (!install(*m_want)) return false;
        std::string w;
        if (!spawn_workers(&w)) {
            emit([&] { return "worker start failed seed=" + seed16(m_res->seed) + ": " + w; });
            return false;
        }
        return true;
    }

    // Drain one hit. Returns false when the queue is empty.
    bool pop_hit(MinerHit& out) {
        std::lock_guard<std::mutex> lk(m_hit_mtx);
        if (m_hits.empty()) return false;
        out = m_hits.front();
        m_hits.pop_front();
        return true;
    }

    // Halts the workers, withdraws the posted job and joins the keyer thread.
    // The installed set is kept; a later set_job() starts the keyer again.
    void stop() {
        halt_workers();
        m_want.reset();
        if (!m_k_live) return;
        {
            std::lock_guard<std::mutex> lk(m_kx_mtx);
            m_stop_req.store(true, std::memory_order_release);
            kx_notify();
        }
        try { hook_c(TestPoint::StopRequested); } catch (...) {}
        m_k.join();
        m_k_live = false;
        m_stop_req.store(false, std::memory_order_release);
        bool          failed = false;
        std::uint64_t gen = 0;
        std::string   why;
        {
            std::lock_guard<std::mutex> lk(m_kx_mtx);
            if (m_rs_seq > m_c_taken && m_rs_gen == m_rq_gen.load(std::memory_order_relaxed) && !m_rs_ok) {
                failed = true;
                gen = m_rs_gen;
                why.swap(m_rs_why);
                m_c_taken = m_rs_seq;
                kx_notify();
            }
        }
        if (failed) take_failed(gen, std::move(why));
        m_answered_gen = m_rq_gen.load(std::memory_order_relaxed);
    }

    // Withdraw the work: the node has no current job for the miner (its template
    // was withdrawn). The workers stop and the hits still queued are returned to
    // the caller (none is dropped here); the next set_job starts the workers again.
    std::vector<MinerHit> clear_job() {
        halt_workers();
        m_want.reset();
        std::lock_guard<std::mutex> lk(m_hit_mtx);
        std::vector<MinerHit> out(m_hits.begin(), m_hits.end());
        m_hits.clear();
        return out;
    }

    bool running() const noexcept { return m_running.load(std::memory_order_relaxed); }

    MinerStats stats() const {
        MinerStats s;
        s.hashes       = m_hashes.load(std::memory_order_relaxed);
        s.shares       = m_shares.load(std::memory_order_relaxed);
        s.blocks       = m_blocks.load(std::memory_order_relaxed);
        s.dropped_hits = m_dropped.load(std::memory_order_relaxed);
        s.job_switches = m_job_switches;
        s.seed_rekeys  = m_seed_rekeys;
        s.threads      = static_cast<unsigned>(m_workers.size());
        s.pinned       = m_pinned.load(std::memory_order_relaxed);
        s.find_resumes = m_resumed.load(std::memory_order_relaxed);
        const double dt = std::chrono::duration<double>(
                              std::chrono::steady_clock::now() - m_job_started).count();
        const std::uint64_t base = m_hashes_at_job.load(std::memory_order_relaxed);
        s.hashrate = (dt > 0.05 && s.hashes >= base)
                         ? static_cast<double>(s.hashes - base) / dt : 0.0;
        return s;
    }

    // One operator-facing line, safe to print on the status cadence.
    std::string describe() const {
        const MinerStats s = stats();
        const std::string lp = m_lp_note.empty() ? std::string() : (" " + m_lp_note);
        const bool keying = pending();
        const char* key = "none";
        std::string kseed = "-";
        if (keying)      { key = "keying"; kseed = seed16(m_rq_seed); }
        else if (m_res)  { key = "ready";  kseed = seed16(m_res->seed); }
        else if (m_fail) { key = "failed"; kseed = seed16(m_fail->seed); }
        unsigned long long items = 0;
        for (unsigned i = 0; i < m_threads_wanted; ++i)
            items += m_k_items[i].v.load(std::memory_order_relaxed);
        const unsigned long long total = m_opt.fast_mode ? randomx_dataset_item_count() : 0;
        const double key_s = m_rq_ms ? static_cast<double>(now_ms() - m_rq_ms) / 1000.0 : 0.0;
        char buf[896];
        std::snprintf(buf, sizeof(buf),
                      "cpu-miner: %s threads=%u pinned=%u mode=%s%s | hashes=%llu %.1f H/s | "
                      "shares=%llu blocks=%llu jobs=%llu rekeys=%llu dropped=%llu resumes=%llu "
                      "key=%s key_seed=%s key_items=%llu/%llu key_s=%.1f key_cancels=%llu",
                      m_running.load(std::memory_order_relaxed) ? "RUNNING" : (keying ? "keying" : "idle"),
                      s.threads, s.pinned,
                      m_opt.fast_mode ? "fast(dataset)" : "light(cache)", lp.c_str(),
                      static_cast<unsigned long long>(s.hashes), s.hashrate,
                      static_cast<unsigned long long>(s.shares),
                      static_cast<unsigned long long>(s.blocks),
                      static_cast<unsigned long long>(s.job_switches),
                      static_cast<unsigned long long>(s.seed_rekeys),
                      static_cast<unsigned long long>(s.dropped_hits),
                      static_cast<unsigned long long>(s.find_resumes),
                      key, kseed.c_str(), items, total, key_s,
                      static_cast<unsigned long long>(m_superseded));
        return buf;
    }

    // The event lines since the last call, oldest first.
    std::vector<std::string> take_events() {
        std::vector<std::string> out(std::make_move_iterator(m_events.begin()),
                                     std::make_move_iterator(m_events.end()));
        m_events.clear();
        return out;
    }

    // What the huge-page and pinning attempts actually achieved.
    const std::string& large_pages_note() const noexcept { return m_lp_note; }
    std::string pinning_note() const {
        if (!m_opt.pin_threads) return "pinning off";
        return "pinned " + std::to_string(m_pinned.load(std::memory_order_relaxed)) +
               "/" + std::to_string(m_workers.size()) + " workers to distinct CPUs";
    }
    unsigned threads_wanted() const noexcept { return m_threads_wanted; }
    bool     fast_mode()      const noexcept { return m_opt.fast_mode; }

    // ---- test-only (caller thread) ---------------------------------------
    struct BuildProgress {
        std::uint64_t request_gen  = 0;   // the newest request
        std::uint64_t consumed_gen = 0;   // the newest request the keyer consumed
        std::uint64_t result_seq   = 0;   // results published
        std::uint64_t result_gen   = 0;   // the request the last result answers
        bool          result_ok    = false;
        std::uint64_t abandoned    = 0;   // builds the keyer abandoned
        long long     sets_live    = 0;   // resource sets alive
    };
    BuildProgress build_progress() const {
        std::lock_guard<std::mutex> lk(m_kx_mtx);
        BuildProgress p;
        p.request_gen  = m_rq_gen.load(std::memory_order_relaxed);
        p.consumed_gen = m_k_taken;
        p.result_seq   = m_rs_seq;
        p.result_gen   = m_rs_gen;
        p.result_ok    = m_rs_ok;
        p.abandoned    = m_k_abandoned.load(std::memory_order_relaxed);
        p.sets_live    = m_sets_live.load(std::memory_order_relaxed);
        return p;
    }
    // True when a result for the newest request is published within d.
    template <class Rep, class Period>
    bool wait_result_for(const std::chrono::duration<Rep, Period>& d) {
        std::unique_lock<std::mutex> lk(m_kx_mtx);
        return m_kx_cv.wait_for(lk, d, [this] {
            return m_rs_seq != 0 && m_rs_gen == m_rq_gen.load(std::memory_order_relaxed);
        });
    }

private:
    // ---- a keyed resource set --------------------------------------------
    struct RxSet {
        randomx_cache*           cache   = nullptr;
        randomx_dataset*         dataset = nullptr;
        std::vector<randomx_vm*> vms;
        SeedBytes                seed{};
        std::string              lp_note;
        std::atomic<long long>*  live    = nullptr;   // m_sets_live, once allocated

        void release() noexcept {
            for (auto*& vm : vms) { if (vm) randomx_destroy_vm(vm); vm = nullptr; }
            vms.clear();
            if (dataset) { randomx_release_dataset(dataset); dataset = nullptr; }
            if (cache)   { randomx_release_cache(cache);     cache   = nullptr; }
            if (live)    { live->fetch_sub(1, std::memory_order_relaxed); live = nullptr; }
        }
    };
    struct RxSetRelease {
        void operator()(RxSet* s) const noexcept {
            if (s) { s->release(); delete s; }
        }
    };
    using RxSetPtr = std::unique_ptr<RxSet, RxSetRelease>;

    struct Fail {
        SeedBytes     seed{};
        std::uint64_t gen = 0;
        std::string   why;
    };
    struct alignas(64) ItemCounter {
        std::atomic<std::uint64_t> v{0};
    };
    enum class Built { Ready, Failed, Abandoned };

    // ---- the caller's side of the handoff ---------------------------------

    bool pending() const noexcept {
        return m_rq_gen.load(std::memory_order_relaxed) > m_answered_gen;
    }

    // sj-new / sj-retry: start the keyer if needed, halt, write the request.
    bool post(const MinerJob& job, bool retry, std::string* why) {
        std::vector<std::uint8_t> blob;
        std::optional<MinerJob>   want;
        std::string               rwhy;
        try {
            blob = job.blob;
            if (retry)
                rwhy = "key failed (seed " + seed16(job.seed_hash) + "): " + m_fail->why +
                       "; retry requested";
            else
                want = job;
        } catch (const std::bad_alloc&) {
            if (why) *why = "out of memory";
            return false;
        }
        const bool      was_pending = pending();
        const SeedBytes old_seed    = m_rq_seed;
        const long long old_ms      = m_rq_ms;

        if (!m_k_live) {
            try {
                hook_c(TestPoint::KeyerStart);
                m_k = std::thread([this] { keyer_main(); });
                m_k_live = true;
            } catch (const std::exception& e) {
                if (why) *why = std::string("keyer thread start failed: ") + e.what();
                return false;
            }
        }
        halt_workers();
        if (was_pending) ++m_superseded;
        request(job.seed_hash, blob);

        if (retry) m_want.reset();
        else       m_want = std::move(want);
        m_fail.reset();
        m_rq_ms = now_ms();
        if (was_pending)
            emit([&] {
                return "key cancelled seed=" + seed16(old_seed) + " after " + secs(m_rq_ms - old_ms) +
                       " s (newer seed " + seed16(job.seed_hash) + ")";
            });
        emit([&] {
            return "keying seed=" + seed16(job.seed_hash) + " mode=" +
                   (m_opt.fast_mode ? "fast" : "light") + " threads=" + std::to_string(m_threads_wanted);
        });
        if (retry) {
            if (why) *why = std::move(rwhy);
            return false;
        }
        return true;
    }

    // The request section: generation + 1, the seed, S-1's blob and the
    // installed set to release. Allocates nothing.
    void request(const SeedBytes& seed, std::vector<std::uint8_t>& blob) noexcept {
        {
            std::lock_guard<std::mutex> lk(m_kx_mtx);
            const std::uint64_t g = m_rq_gen.load(std::memory_order_relaxed) + 1;
            m_rq_blob.swap(blob);
            if (m_res) {
                if (m_running.load(std::memory_order_relaxed) || !m_workers.empty()) std::abort();
                m_rq_old     = m_res.release();
                m_rq_old_gen = g;
            }
            m_rq_seed = seed;
            m_rq_gen.store(g, std::memory_order_release);
            kx_notify();
        }
        try { hook_c(TestPoint::Requested); } catch (...) {}
    }

    // The one writer of m_job. Installs only on a set keyed to the job's seed.
    bool install(const MinerJob& job) {
        if (!(m_res && m_res->seed == job.seed_hash)) return false;
        {
            std::lock_guard<std::mutex> lk(m_job_mtx);
            m_job = job;
        }
        m_job_shadow = job;
        m_job_valid  = true;
        m_found_gen.store(0, std::memory_order_release);   // a new template is never spent
        m_job_gen.fetch_add(1, std::memory_order_release);
        ++m_job_switches;
        m_hashes_at_job.store(m_hashes.load(std::memory_order_relaxed),
                              std::memory_order_relaxed);
        m_job_started = std::chrono::steady_clock::now();
        return true;
    }

    void take_failed(std::uint64_t gen, std::string why) {
        m_fail = Fail{m_rq_seed, gen, std::move(why)};
        emit([&] { return "key failed seed=" + seed16(m_fail->seed) + ": " + m_fail->why; });
    }

    template <class F>
    void emit(F&& make) noexcept {
        try { m_events.push_back(make()); } catch (...) {}
    }
    static std::string seed16(const SeedBytes& s) { return detail::to_hex(s.data(), 8); }
    static std::string secs(long long ms) {
        char b[32];
        std::snprintf(b, sizeof(b), "%.1f", static_cast<double>(ms) / 1000.0);
        return b;
    }

    void kx_notify() noexcept { m_kx_cv.notify_all(); }

    bool kx_cancelled(std::uint64_t g) const noexcept {
        return m_rq_gen.load(std::memory_order_acquire) != g ||
               m_stop_req.load(std::memory_order_acquire);
    }

    void hook_k(TestPoint p, std::uint64_t g, unsigned i = 0) const {
        if (!m_opt.test_hook) return;
        const std::function<bool()> c = [this, g] { return kx_cancelled(g); };
        m_opt.test_hook(p, g, i, c);
    }
    void hook_c(TestPoint p, unsigned i = 0) const {
        if (!m_opt.test_hook) return;
        const std::function<bool()> c = [] { return false; };
        m_opt.test_hook(p, m_rq_gen.load(std::memory_order_relaxed), i, c);
    }

    // ---- the keyer's build ------------------------------------------------

    randomx_flags base_flags() const {
        randomx_flags f = randomx_get_flags();      // HARD_AES / ARGON2_* autodetect
        if (m_opt.use_jit) f = f | RANDOMX_FLAG_JIT;
        return f;
    }

    // Two-try allocator: with LARGE_PAGES, then without. `what` names the
    // allocation in the note so an operator can see which one fell back.
    template <class Alloc>
    auto try_large_then_small(Alloc alloc, randomx_flags flags, const char* what, std::string& note)
        -> decltype(alloc(flags)) {
        if (m_opt.large_pages) {
            auto* p = alloc(flags | RANDOMX_FLAG_LARGE_PAGES);
            if (p) { note_lp(note, what, true); return p; }
            note_lp(note, what, false);
        }
        return alloc(flags);
    }

    static void note_lp(std::string& note, const char* what, bool got) {
        if (!note.empty()) note += ",";
        note += what;
        note += got ? "=hugepages" : "=4k";
    }

    void keyer_main() noexcept {
        for (;;) {
            RxSetPtr                  old_set, stale;
            std::uint64_t             g = 0;
            SeedBytes                 seed{};
            std::vector<std::uint8_t> blob;
            bool                      stop_now = false, blob_ok = true;
            {
                std::unique_lock<std::mutex> lk(m_kx_mtx);
                m_kx_cv.wait(lk, [this] {
                    return m_stop_req.load(std::memory_order_acquire) ||
                           m_rq_gen.load(std::memory_order_acquire) > m_k_taken;
                });
                if (m_rq_old && m_rq_old_gen > m_k_taken) old_set.reset(m_rq_old);
                if (m_rs_seq > m_c_taken && m_rs_set) {
                    stale.reset(m_rs_set);
                    m_rs_set = nullptr;
                }
                g          = m_rq_gen.load(std::memory_order_acquire);
                m_k_taken  = g;
                seed       = m_rq_seed;
                stop_now   = m_stop_req.load(std::memory_order_acquire);
                try { blob = m_rq_blob; } catch (...) { blob_ok = false; }
                kx_notify();
            }
            const long long t0 = now_ms();
            RxSetPtr    built;
            Built       outcome = Built::Failed;
            std::string why;
            try {
                if (!stop_now) hook_k(TestPoint::AfterConsume, g);
                old_set.reset();
                stale.reset();
                if (stop_now) return;
                if (!blob_ok) why = "out of memory";
                else          outcome = build_set(g, seed, blob, built, why);
            } catch (const std::exception& e) {
                outcome = Built::Failed;
                try { why = e.what(); } catch (...) { why.clear(); }
            } catch (...) {
                outcome = Built::Failed;
                try { why = "unknown"; } catch (...) { why.clear(); }
            }
            if (outcome != Built::Ready) {
                m_b_abort.store(true, std::memory_order_relaxed);
                join_build_threads();
                built.reset();
            }
            old_set.reset();
            stale.reset();
            const long long ms = now_ms() - t0;
            bool published = false;
            if (outcome != Built::Abandoned) {
                std::lock_guard<std::mutex> lk(m_kx_mtx);
                if (!kx_cancelled(g)) {
                    ++m_rs_seq;
                    m_rs_gen  = g;
                    m_rs_ok   = outcome == Built::Ready;
                    m_rs_set  = built.release();
                    m_rs_why.swap(why);
                    m_rs_ms   = ms;
                    published = true;
                    kx_notify();
                }
            }
            if (!published) {
                built.reset();
                m_k_abandoned.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            try { hook_k(TestPoint::AfterPublish, g); } catch (...) {}
        }
    }

    // b3..b8 for request g: the cache, the Argon2d, the dataset (fast mode),
    // the VMs and the dataset parity check. `set` owns what is allocated.
    Built build_set(std::uint64_t g, const SeedBytes& seed, const std::vector<std::uint8_t>& blob,
                    RxSetPtr& set, std::string& why) {
        if (kx_cancelled(g)) return Built::Abandoned;
        hook_k(TestPoint::BeforeAlloc, g);
        set.reset(new RxSet);
        set->seed  = seed;
        set->cache = try_large_then_small(
            [](randomx_flags f) { return randomx_alloc_cache(f); }, base_flags(), "cache", set->lp_note);
        if (!set->cache) {
            why = "randomx_alloc_cache failed (out of memory?)";
            return Built::Failed;
        }
        set->live = &m_sets_live;
        m_sets_live.fetch_add(1, std::memory_order_relaxed);
        if (kx_cancelled(g)) return Built::Abandoned;
        {
            std::lock_guard<std::mutex> lk(c2pool::xmr::randomx_init_mutex());
            randomx_init_cache(set->cache, seed.data(), seed.size());
        }
        hook_k(TestPoint::AfterCacheInit, g);
        if (kx_cancelled(g)) return Built::Abandoned;

        if (m_opt.fast_mode) {
            set->dataset = try_large_then_small(
                [](randomx_flags f) { return randomx_alloc_dataset(f); },
                RANDOMX_FLAG_DEFAULT, "dataset", set->lp_note);
            if (!set->dataset) {
                why = "randomx_alloc_dataset failed (~2080 MiB needed for --mine-fast)";
                return Built::Failed;
            }
            if (kx_cancelled(g)) return Built::Abandoned;
            build_dataset(g, *set);
            if (kx_cancelled(g)) return Built::Abandoned;
        }

        randomx_flags vmf = base_flags();
        if (m_opt.secure_jit) vmf = vmf | RANDOMX_FLAG_SECURE;
        if (m_opt.fast_mode)  vmf = vmf | RANDOMX_FLAG_FULL_MEM;
        unsigned vm_large = 0;
        set->vms.reserve(m_threads_wanted);
        for (unsigned i = 0; i < m_threads_wanted; ++i) {
            randomx_cache*   c = m_opt.fast_mode ? nullptr : set->cache;
            randomx_dataset* d = m_opt.fast_mode ? set->dataset : nullptr;
            randomx_vm* vm = nullptr;
            if (m_opt.large_pages) {
                vm = randomx_create_vm(vmf | RANDOMX_FLAG_LARGE_PAGES, c, d);
                if (vm) ++vm_large;
            }
            if (!vm) vm = randomx_create_vm(vmf, c, d);
            if (!vm) {
                why = "randomx_create_vm failed for thread " + std::to_string(i);
                return Built::Failed;
            }
            set->vms.push_back(vm);
            if (kx_cancelled(g)) return Built::Abandoned;
        }
        if (m_opt.large_pages) {
            note_lp(set->lp_note, "scratchpads", vm_large == m_threads_wanted && m_threads_wanted != 0);
            if (set->lp_note.find("hugepages") == std::string::npos) {
                const long hp = detail::hugepages_total();
                set->lp_note += (hp == 0)
                    ? " (no hugepages configured: vm.nr_hugepages=0)"
                    : " (hugepage allocation refused)";
            }
        }

        if (m_opt.fast_mode && !parity_ok(*set, blob, why)) return Built::Failed;
        if (kx_cancelled(g)) return Built::Abandoned;
        hook_k(TestPoint::BeforePublish, g);
        return Built::Ready;
    }

    // The dataset over disjoint item ranges, one build thread per worker slot,
    // one item per call. Every build thread is joined on every exit.
    void build_dataset(std::uint64_t g, RxSet& set) {
        const unsigned long items = randomx_dataset_item_count();
        const unsigned n = std::max(1u, m_threads_wanted);
        const unsigned long per = items / n;
        randomx_dataset* ds    = set.dataset;
        randomx_cache*   cache = set.cache;
        m_b_abort.store(false, std::memory_order_relaxed);
        try {
            m_b_threads.reserve(n);
            for (unsigned i = 0; i < n; ++i) {
                const unsigned long start = per * i;
                const unsigned long count = (i + 1 == n) ? (items - start) : per;
                hook_k(TestPoint::BuildThreadStart, g, i);
                m_b_threads.emplace_back([this, ds, cache, start, count, i, g] {
                    std::atomic<std::uint64_t>& done = m_k_items[i].v;
                    done.store(0, std::memory_order_relaxed);
                    for (unsigned long k = 0; k < count; ++k) {
                        if (m_b_abort.load(std::memory_order_relaxed) || kx_cancelled(g)) return;
                        randomx_init_dataset(ds, cache, start + k, 1);
                        done.fetch_add(1, std::memory_order_relaxed);
                    }
                });
            }
        } catch (...) {
            m_b_abort.store(true, std::memory_order_relaxed);
            join_build_threads();
            throw;
        }
        join_build_threads();
    }

    void join_build_threads() noexcept {
        for (auto& t : m_b_threads) if (t.joinable()) t.join();
        m_b_threads.clear();
    }

    // One hash of the request's blob on vms[0] and one on a transient light VM
    // over the set's own cache; they must be equal.
    bool parity_ok(const RxSet& set, const std::vector<std::uint8_t>& blob, std::string& why) {
        if (set.vms.empty() || blob.empty()) {
            why = "dataset parity: no input";
            return false;
        }
        HashBytes full{}, light{};
        randomx_calculate_hash(set.vms[0], blob.data(), blob.size(), full.data());
        randomx_flags lf = base_flags();
        if (m_opt.secure_jit) lf = lf | RANDOMX_FLAG_SECURE;
        std::unique_ptr<randomx_vm, void (*)(randomx_vm*)> vm(
            randomx_create_vm(lf, set.cache, nullptr), &randomx_destroy_vm);
        if (!vm) {
            why = "randomx_create_vm failed for the dataset parity check";
            return false;
        }
        randomx_calculate_hash(vm.get(), blob.data(), blob.size(), light.data());
        vm.reset();
        if (full != light) {
            why = "dataset parity";
            return false;
        }
        return true;
    }

    // ---- workers ----------------------------------------------------------

    bool spawn_workers(std::string* why) {
        if (m_running.load(std::memory_order_relaxed)) return true;
        if (!m_res || m_res->vms.empty()) return true;
        m_stop.store(false, std::memory_order_relaxed);
        m_running.store(true, std::memory_order_relaxed);
        m_pinned.store(0, std::memory_order_relaxed);
        try {
            const std::vector<int> cpus = detail::preferred_cpu_order();
            std::random_device rd;
            const std::uint32_t nonce_base = static_cast<std::uint32_t>(rd());
            const unsigned n = static_cast<unsigned>(m_res->vms.size());
            m_workers.reserve(n);
            for (unsigned i = 0; i < n; ++i) {
                const int cpu = cpus.empty() ? -1 : cpus[i % cpus.size()];
                hook_c(TestPoint::WorkerStart, i);
                m_workers.emplace_back([this, i, cpu, nonce_base] {
                    if (m_opt.pin_threads && cpu >= 0 && detail::pin_this_thread(cpu))
                        m_pinned.fetch_add(1, std::memory_order_relaxed);
                    worker(i, nonce_base);
                });
            }
        } catch (const std::exception& e) {
            unwind_spawn();
            if (why) *why = std::string("worker start failed: ") + e.what();
            return false;
        } catch (...) {
            unwind_spawn();
            if (why) *why = "worker start failed: unknown";
            return false;
        }
        return true;
    }

    void unwind_spawn() noexcept {
        m_stop.store(true, std::memory_order_relaxed);
        for (auto& t : m_workers) if (t.joinable()) t.join();
        m_workers.clear();
        m_running.store(false, std::memory_order_relaxed);
        m_job_valid = false;
    }

    void halt_workers() {
        if (!m_running.load(std::memory_order_relaxed)) {
            for (auto& t : m_workers) if (t.joinable()) t.join();
            m_workers.clear();
            return;
        }
        m_stop.store(true, std::memory_order_relaxed);
        for (auto& t : m_workers) if (t.joinable()) t.join();
        m_workers.clear();
        m_running.store(false, std::memory_order_relaxed);
        m_job_valid = false;
    }

    static long long now_ms() noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    // True while `gen` is the job that already produced a network block AND the
    // anti-stall window has not expired. Expiry clears the marker so the next
    // caller falls straight through — no worker is ever parked indefinitely on
    // a template the node failed to replace.
    bool spent(std::uint64_t gen) noexcept {
        if (!m_opt.resume_after_find_ms) return false;
        std::uint64_t fg = m_found_gen.load(std::memory_order_acquire);
        if (fg != gen) return false;
        const long long age = now_ms() - m_found_at_ms.load(std::memory_order_relaxed);
        if (age >= static_cast<long long>(m_opt.resume_after_find_ms)) {
            m_found_gen.compare_exchange_strong(fg, 0, std::memory_order_acq_rel);
            m_resumed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        return true;
    }

    void push_hit(const MinerHit& h) {
        std::lock_guard<std::mutex> lk(m_hit_mtx);
        if (m_hits.size() >= m_opt.hit_queue_cap) {
            m_hits.pop_front();
            m_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        m_hits.push_back(h);
    }

    // The hot loop. ONE thread, ONE VM, its own nonce lane (base + i, stride
    // n) so two workers never test the same nonce for the same job.
    void worker(unsigned idx, std::uint32_t nonce_base) {
        randomx_vm* vm = m_res->vms[idx];
        const std::uint32_t stride = static_cast<std::uint32_t>(m_res->vms.size());
        MinerJob      job;
        std::uint64_t seen_gen = 0;
        bool          have_job = false;

        while (!m_stop.load(std::memory_order_relaxed)) {
            const std::uint64_t gen = m_job_gen.load(std::memory_order_acquire);
            if (gen != seen_gen) {
                std::lock_guard<std::mutex> lk(m_job_mtx);
                job = m_job;
                seen_gen = gen;
                have_job = job.valid();
            }
            if (!have_job) {
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                continue;
            }
            // This template already produced a block. Wait for a new one rather
            // than mining a competitor to our own win — but never wait forever.
            if (spent(seen_gen)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                continue;
            }

            std::vector<std::uint8_t> blob = job.blob;
            const std::size_t off = job.nonce_offset;
            std::uint32_t cur = nonce_base + idx;

            auto patch = [&](std::uint32_t n) {
                for (std::size_t i = 0; i < kNonceSize; ++i)
                    blob[off + i] = static_cast<std::uint8_t>(n >> (8 * i));
            };
            auto judge = [&](std::uint32_t nonce, const HashBytes& h) {
                const std::uint64_t top = detail::top_word_le(h);
                const bool net   = job.network_target && top <= job.network_target;
                const bool share = job.lane_target    && top <= job.lane_target;
                if (!net && !share) return;
                MinerHit hit;
                hit.template_id     = job.template_id;
                hit.extra_nonce     = job.extra_nonce;
                hit.nonce           = nonce;
                hit.height          = job.height;
                hit.pow_hash        = h;
                hit.achieved_target = top;
                hit.network         = net;
                hit.share           = share;
                if (net) {
                    m_blocks.fetch_add(1, std::memory_order_relaxed);
                    // Tell every worker this template is spent (see
                    // MinerOptions::resume_after_find_ms). First writer wins;
                    // the timestamp is what the anti-stall resume reads.
                    if (m_opt.resume_after_find_ms) {
                        m_found_at_ms.store(now_ms(), std::memory_order_relaxed);
                        m_found_gen.store(seen_gen, std::memory_order_release);
                    }
                }
                if (share) m_shares.fetch_add(1, std::memory_order_relaxed);
                push_hit(hit);
            };

            // randomx_calculate_hash_next returns the hash of the PREVIOUS
            // input, so `cur` always trails the nonce currently patched in.
            patch(cur);
            randomx_calculate_hash_first(vm, blob.data(), blob.size());
            HashBytes h{};
            while (true) {
                // Polled EVERY hash, not every N: a light-mode hash costs tens
                // of milliseconds and a fast-mode one still hundreds of
                // microseconds, so three relaxed atomic loads are free — while
                // a coarser poll leaves a window in which workers keep grinding
                // a template that is already spent or replaced, which is
                // exactly how a node orphans its own wins.
                if (m_stop.load(std::memory_order_relaxed) ||
                    m_job_gen.load(std::memory_order_acquire) != seen_gen ||
                    spent(seen_gen))
                    break;
                const std::uint32_t nxt = cur + stride;
                patch(nxt);
                randomx_calculate_hash_next(vm, blob.data(), blob.size(), h.data());
                judge(cur, h);
                m_hashes.fetch_add(1, std::memory_order_relaxed);
                cur = nxt;
            }
            // Close the pipeline so the VM is not left mid-calculation: this
            // yields the hash of the nonce currently loaded (`cur`), which has
            // not been judged yet.
            randomx_calculate_hash_last(vm, h.data());
            judge(cur, h);
            m_hashes.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ---- state ------------------------------------------------------------
    MinerOptions m_opt;
    unsigned     m_threads_wanted = 1;

    // The caller's. m_res is the installed set; no worker lives while it moves.
    RxSetPtr                   m_res;
    std::string                m_lp_note;     // the installed set's note

    mutable std::mutex         m_job_mtx;
    MinerJob                   m_job;         // guarded by m_job_mtx
    MinerJob                   m_job_shadow;  // caller-thread copy, no lock
    bool                       m_job_valid = false;
    std::atomic<std::uint64_t> m_job_gen{0};

    std::optional<MinerJob>    m_want;        // the posted job
    std::uint64_t              m_answered_gen = 0;
    std::optional<Fail>        m_fail;        // the last failed result taken
    long long                  m_rq_ms = 0;
    std::uint64_t              m_superseded = 0;
    std::deque<std::string>    m_events;
    std::thread                m_k;
    bool                       m_k_live = false;

    std::vector<std::thread>   m_workers;
    std::atomic<bool>          m_stop{false};
    std::atomic<bool>          m_running{false};

    mutable std::mutex         m_hit_mtx;
    std::deque<MinerHit>       m_hits;

    // Set to the job generation that already produced a network block, so no
    // worker mines a competitor to our own win; cleared by the anti-stall
    // resume in spent(). 0 => no template is spent.
    std::atomic<std::uint64_t> m_found_gen{0};
    std::atomic<long long>     m_found_at_ms{0};
    std::atomic<std::uint64_t> m_resumed{0};   // anti-stall resumes taken

    std::atomic<std::uint64_t> m_hashes{0}, m_shares{0}, m_blocks{0}, m_dropped{0};
    std::atomic<std::uint64_t> m_hashes_at_job{0};
    std::atomic<unsigned>      m_pinned{0};
    std::uint64_t              m_job_switches = 0, m_seed_rekeys = 0;
    std::chrono::steady_clock::time_point m_job_started = std::chrono::steady_clock::now();

    // The handoff, under m_kx_mtx. The request slot and m_c_taken: written by
    // the caller only. m_k_taken and the result slot: written by the keyer
    // only. m_rq_old and m_rs_set do not own; a set moves by generation.
    mutable std::mutex         m_kx_mtx;
    std::condition_variable    m_kx_cv;
    std::atomic<std::uint64_t> m_rq_gen{0};
    SeedBytes                  m_rq_seed{};
    std::vector<std::uint8_t>  m_rq_blob;
    RxSet*                     m_rq_old = nullptr;
    std::uint64_t              m_rq_old_gen = 0;
    std::atomic<bool>          m_stop_req{false};
    std::uint64_t              m_c_taken = 0;
    std::uint64_t              m_k_taken = 0;
    std::uint64_t              m_rs_seq = 0;
    std::uint64_t              m_rs_gen = 0;
    bool                       m_rs_ok = false;
    RxSet*                     m_rs_set = nullptr;
    std::string                m_rs_why;
    long long                  m_rs_ms = 0;

    // The keyer's.
    std::atomic<std::uint64_t>     m_k_abandoned{0};
    std::atomic<long long>         m_sets_live{0};
    std::vector<std::thread>       m_b_threads;
    std::atomic<bool>              m_b_abort{false};
    std::unique_ptr<ItemCounter[]> m_k_items;   // per build thread
};

} // namespace miner
} // namespace xmr
} // namespace c2pool

#endif // C2POOL_XMR_CPU_MINER_HPP
