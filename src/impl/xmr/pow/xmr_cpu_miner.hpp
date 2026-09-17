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
//   * Cache/dataset INITIALISATION is serialised process-wide against the
//     node's own verifier through randomx_init_lock.hpp — see that header for
//     the SIGFPE this prevents. The hot loop never takes that lock.

#ifndef C2POOL_XMR_CPU_MINER_HPP
#define C2POOL_XMR_CPU_MINER_HPP

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
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
    double        hashrate      = 0.0; // H/s since the last set_job()
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
    }
    ~CpuMiner() { stop(); release_resources(); }

    CpuMiner(const CpuMiner&)            = delete;
    CpuMiner& operator=(const CpuMiner&) = delete;

    // ---- caller-thread API -------------------------------------------------

    // Install (or replace) the work. Allocates/keys RandomX on the first call
    // and re-keys on a seed change; spawns the workers on the first valid job.
    // Returns false with *why set on an allocation/key failure — the miner then
    // stays idle and the node carries on doing everything else.
    bool set_job(const MinerJob& job, std::string* why = nullptr) {
        if (!job.valid()) {
            if (why) *why = "job has no blob / no target";
            return false;
        }
        if (m_seeded && m_job_valid && job.same_work_as(m_job_shadow)) return true;

        if (!m_seeded || job.seed_hash != m_seed) {
            halt_workers();
            if (!rekey(job.seed_hash, why)) return false;
            ++m_seed_rekeys;
        }
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
        spawn_workers();
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

    void stop() { halt_workers(); }

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
        char buf[640];
        std::snprintf(buf, sizeof(buf),
                      "cpu-miner: %s threads=%u pinned=%u mode=%s%s | hashes=%llu %.1f H/s | "
                      "shares=%llu blocks=%llu jobs=%llu rekeys=%llu dropped=%llu resumes=%llu",
                      m_running.load(std::memory_order_relaxed) ? "RUNNING" : "idle",
                      s.threads, s.pinned,
                      m_opt.fast_mode ? "fast(dataset)" : "light(cache)", lp.c_str(),
                      static_cast<unsigned long long>(s.hashes), s.hashrate,
                      static_cast<unsigned long long>(s.shares),
                      static_cast<unsigned long long>(s.blocks),
                      static_cast<unsigned long long>(s.job_switches),
                      static_cast<unsigned long long>(s.seed_rekeys),
                      static_cast<unsigned long long>(s.dropped_hits),
                      static_cast<unsigned long long>(s.find_resumes));
        return buf;
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

private:
    // ---- RandomX resource lifetime (caller thread, workers halted) ---------

    randomx_flags base_flags() const {
        randomx_flags f = randomx_get_flags();      // HARD_AES / ARGON2_* autodetect
        if (m_opt.use_jit) f = f | RANDOMX_FLAG_JIT;
        return f;
    }

    // Two-try allocator: with LARGE_PAGES, then without. `what` names the
    // allocation in the note so an operator can see which one fell back.
    template <class Alloc>
    auto try_large_then_small(Alloc alloc, randomx_flags flags, const char* what)
        -> decltype(alloc(flags)) {
        if (m_opt.large_pages) {
            auto* p = alloc(flags | RANDOMX_FLAG_LARGE_PAGES);
            if (p) { note_lp(what, true); return p; }
            note_lp(what, false);
        }
        return alloc(flags);
    }

    void note_lp(const char* what, bool got) {
        if (!m_lp_note.empty()) m_lp_note += ",";
        m_lp_note += what;
        m_lp_note += got ? "=hugepages" : "=4k";
    }

    bool rekey(const SeedBytes& seed, std::string* why) {
        release_resources();
        m_lp_note.clear();

        const randomx_flags cflags = base_flags();
        m_cache = try_large_then_small(
            [](randomx_flags f) { return randomx_alloc_cache(f); }, cflags, "cache");
        if (!m_cache) {
            if (why) *why = "randomx_alloc_cache failed (out of memory?)";
            return false;
        }
        {
            // Serialised against the node's verifier — see randomx_init_lock.hpp.
            // In FAST mode the dataset build is held under the SAME acquisition so
            // its worker threads never interleave with a verifier re-key either.
            std::lock_guard<std::mutex> lk(c2pool::xmr::randomx_init_mutex());
            randomx_init_cache(m_cache, seed.data(), seed.size());

            if (m_opt.fast_mode) {
                m_dataset = try_large_then_small(
                    [](randomx_flags f) { return randomx_alloc_dataset(f); },
                    RANDOMX_FLAG_DEFAULT, "dataset");
                if (!m_dataset) {
                    if (why) *why = "randomx_alloc_dataset failed (~2080 MiB needed for --mine-fast)";
                    // release_resources() touches no randomx *_init_* entry point,
                    // so calling it under the lock is safe.
                    release_resources();
                    return false;
                }
                init_dataset_parallel();
            }
        }

        randomx_flags vmf = base_flags();
        if (m_opt.secure_jit) vmf = vmf | RANDOMX_FLAG_SECURE;
        if (m_opt.fast_mode)  vmf = vmf | RANDOMX_FLAG_FULL_MEM;

        unsigned vm_large = 0;
        m_vms.assign(m_threads_wanted, nullptr);
        for (unsigned i = 0; i < m_threads_wanted; ++i) {
            randomx_cache*   c = m_opt.fast_mode ? nullptr : m_cache;
            randomx_dataset* d = m_opt.fast_mode ? m_dataset : nullptr;
            randomx_vm* vm = nullptr;
            if (m_opt.large_pages) {
                vm = randomx_create_vm(vmf | RANDOMX_FLAG_LARGE_PAGES, c, d);
                if (vm) ++vm_large;
            }
            if (!vm) vm = randomx_create_vm(vmf, c, d);
            if (!vm) {
                if (why) *why = "randomx_create_vm failed for thread " + std::to_string(i);
                release_resources();
                return false;
            }
            m_vms[i] = vm;
        }
        if (m_opt.large_pages) {
            note_lp("scratchpads", vm_large == m_threads_wanted && m_threads_wanted != 0);
            if (m_lp_note.find("hugepages") == std::string::npos) {
                const long hp = detail::hugepages_total();
                m_lp_note += (hp == 0)
                    ? " (no hugepages configured: vm.nr_hugepages=0)"
                    : " (hugepage allocation refused)";
            }
        }
        m_seed   = seed;
        m_seeded = true;
        return true;
    }

    // randomx_init_dataset over disjoint item ranges, one temporary thread per
    // worker slot. Single-threaded this is minutes; parallel it is seconds.
    // CALLED WITH randomx_init_mutex() HELD (see rekey).
    void init_dataset_parallel() {
        const unsigned long items = randomx_dataset_item_count();
        const unsigned n = std::max(1u, m_threads_wanted);
        std::vector<std::thread> tt;
        tt.reserve(n);
        const unsigned long per = items / n;
        for (unsigned i = 0; i < n; ++i) {
            const unsigned long start = per * i;
            const unsigned long count = (i + 1 == n) ? (items - start) : per;
            tt.emplace_back([this, start, count] {
                randomx_init_dataset(m_dataset, m_cache, start, count);
            });
        }
        for (auto& t : tt) t.join();
    }

    void release_resources() {
        for (auto*& vm : m_vms) { if (vm) randomx_destroy_vm(vm); vm = nullptr; }
        m_vms.clear();
        if (m_dataset) { randomx_release_dataset(m_dataset); m_dataset = nullptr; }
        if (m_cache)   { randomx_release_cache(m_cache);     m_cache   = nullptr; }
        m_seeded = false;
    }

    // ---- workers ----------------------------------------------------------

    void spawn_workers() {
        if (m_running.load(std::memory_order_relaxed)) return;
        if (m_vms.empty()) return;
        m_stop.store(false, std::memory_order_relaxed);
        m_running.store(true, std::memory_order_relaxed);
        m_pinned.store(0, std::memory_order_relaxed);

        const std::vector<int> cpus = detail::preferred_cpu_order();
        std::random_device rd;
        const std::uint32_t nonce_base = static_cast<std::uint32_t>(rd());

        m_workers.reserve(m_vms.size());
        for (unsigned i = 0; i < m_vms.size(); ++i) {
            const int cpu = cpus.empty() ? -1 : cpus[i % cpus.size()];
            m_workers.emplace_back([this, i, cpu, nonce_base] {
                if (m_opt.pin_threads && cpu >= 0 && detail::pin_this_thread(cpu))
                    m_pinned.fetch_add(1, std::memory_order_relaxed);
                worker(i, nonce_base);
            });
        }
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
        randomx_vm* vm = m_vms[idx];
        const std::uint32_t stride = static_cast<std::uint32_t>(m_vms.size());

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

    randomx_cache*             m_cache   = nullptr;
    randomx_dataset*           m_dataset = nullptr;
    std::vector<randomx_vm*>   m_vms;
    SeedBytes                  m_seed{};
    bool                       m_seeded = false;
    std::string                m_lp_note;

    mutable std::mutex         m_job_mtx;
    MinerJob                   m_job;         // guarded by m_job_mtx
    MinerJob                   m_job_shadow;  // caller-thread copy, no lock
    bool                       m_job_valid = false;
    std::atomic<std::uint64_t> m_job_gen{0};

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
};

} // namespace miner
} // namespace xmr
} // namespace c2pool

#endif // C2POOL_XMR_CPU_MINER_HPP
