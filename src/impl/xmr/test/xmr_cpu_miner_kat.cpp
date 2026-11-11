// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xmr_cpu_miner_kat.cpp — known-answer / property tests for the in-process
// RandomX CPU miner (src/impl/xmr/pow/xmr_cpu_miner.hpp).
//
// THE CLAIM UNDER TEST, in one sentence: the miner produces nothing the node
// does not already validate. Concretely:
//
//   K1  topology/pinning helpers are sane and never fatal;
//   K2  a LIGHT-mode miner finds a hit at an easy lane target, and EVERY hash
//       it reports is reproduced BIT-FOR-BIT by the production LightVerifier
//       (randomx_verify.hpp) over the same blob with the reported nonce
//       patched in — i.e. the miner is a client of librandomx, not a second
//       implementation of it;
//   K3  the reported achieved_target is exactly the top 64-bit LE word of the
//       hash, the same number xmr_stratum.cpp computes for a submit;
//   K4  no false positives: an impossible network target yields zero block
//       hits over thousands of hashes, while the easy lane target keeps
//       firing (so the negative is a real negative, not a dead miner);
//   K5  huge pages degrade gracefully: large_pages=true starts and mines on a
//       host with no hugepages configured, and says so;
//   K6  a new job takes over the workers, and — the invariant the node really
//       depends on — EVERY hit verifies against the blob of the template it
//       NAMES. (A hit for the previous template may still land after set_job()
//       returns: a worker notices the switch only every 64 hashes and then
//       closes its pipeline with one last hash. That is real work on a template
//       the provider still retains, not staleness to be suppressed.);
//   K7  SELF-CONTAINED FIND: at a *network* target a regtest node would set,
//       the miner produces `network`-flagged hits, and each one passes the
//       node's own exact 128-bit acceptance rule (meets_difficulty_128 from
//       randomx_verify.hpp) when re-hashed by the verifier. This is the
//       in-process, no-daemon, no-external-miner shape of the find proof;
//   K8  REGRESSION: a verifier re-key (prefetch_epoch, listener thread) racing
//       a miner re-key (the keyer thread) does not crash. Before
//       randomx_init_lock.hpp this pair died with SIGFPE inside
//       randomx_reciprocal() on a live regtest run;
//   V-*, R-*  the keyer thread and the caller-thread transitions: set_job()
//       never waits on a key; install_ready() installs the newest posted job
//       on the result of the newest request; a newer request or stop()
//       abandons a build; clear_job() and stop() withdraw; at most one
//       resource set is alive; a false set_job() posts nothing. Every step on
//       the keyer is reached through a test-hook latch or a published
//       generation, never by timing.
//
// Usage: xmr_cpu_miner_kat [--quick] [--only NAME[,NAME...]]   (default: all)
// Heavy: it allocates one 256 MiB Argon2d cache for the miner and two for the
// verifier. Gated behind XMR_BUILD_RANDOMX with the other RandomX targets.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <dirent.h>
#endif

#include "randomx_verify.hpp"
#include "xmr_cpu_miner.hpp"

namespace mn = c2pool::xmr::miner;

static int g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : " — ", detail.c_str());
    if (!ok) ++g_fail;
}

static std::uint64_t target_from_diff(std::uint64_t d) {
    return d ? (0xFFFFFFFFFFFFFFFFULL / d) : 0xFFFFFFFFFFFFFFFFULL;
}
static std::uint64_t top_word_le(const mn::HashBytes& h) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(h[mn::kHashSize - 8 + i]) << (8 * i);
    return v;
}

// A stand-in Monero v16 hashing blob: 76 bytes, nonce at offset 39. The exact
// bytes are irrelevant to RandomX (it hashes whatever it is given); what
// matters is that the miner and the verifier hash the SAME bytes.
static constexpr std::size_t kNonceOffset = 39;
static std::vector<std::uint8_t> make_blob() {
    std::vector<std::uint8_t> b(76, 0);
    for (std::size_t i = 0; i < b.size(); ++i)
        b[i] = static_cast<std::uint8_t>(0x10 + (i * 7) % 0xE0);
    b[0] = 16;  // major_version
    b[1] = 16;  // minor_version
    for (std::size_t i = 0; i < 4; ++i) b[kNonceOffset + i] = 0;
    return b;
}

static mn::SeedBytes make_seed(std::uint8_t tag) {
    mn::SeedBytes s{};
    for (std::size_t i = 0; i < s.size(); ++i)
        s[i] = static_cast<std::uint8_t>((i * 11 + tag) & 0xFF);
    return s;
}

static c2pool::xmr::SeedHash to_vseed(const mn::SeedBytes& s) {
    c2pool::xmr::SeedHash v{};
    std::memcpy(v.data(), s.data(), s.size());
    return v;
}

// A bound on a wait for a published result. It is a failure bound: every
// wait_result_for() below must return true, well inside it (R-F3: within a
// quarter of it).
static const std::chrono::seconds kWait{60};
static int    g_waits = 0, g_waits_late = 0;
static double g_wait_max_s = 0.0;
static bool wait_result(mn::CpuMiner& m) {
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = m.wait_result_for(kWait);
    const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    ++g_waits;
    g_wait_max_s = std::max(g_wait_max_s, s);
    if (!ok || s > static_cast<double>(kWait.count()) / 4.0) ++g_waits_late;
    return ok;
}

// ---------------------------------------------------------------------------
// The test hook: latches and signals at the miner's test points.
//   * A latch holds the thread that reaches (point, gen) until the test opens
//     it, or until the keyer's own cancel predicate is true (unless the latch
//     ignores it). The caller-thread points Requested / StopRequested wake
//     every held latch, so a newer request or stop() releases it at once.
//   * A watchdog opens a latch after kLatchBound and counts it; a count > 0
//     fails the case.
//   * Every point reached is recorded, so the test can wait for (point, gen).
// gen 0 in arm() / reached() matches any generation.
// ---------------------------------------------------------------------------
using TP = mn::TestPoint;
static const std::chrono::seconds kLatchBound{20};

struct HookCtl {
    struct Latch { TP p; std::uint64_t gen; bool ignore_cancel; bool open; };
    struct Mark  { TP p; std::uint64_t gen; unsigned idx; };

    std::mutex              mu;
    std::condition_variable cv;
    std::map<int, Latch>    latches;
    int                     next_id = 1;
    std::vector<Mark>       marks;
    int                     watchdog = 0;
    std::atomic<bool>       fail_after_cache{false};   // throw at AfterCacheInit
    std::atomic<int>        fail_worker_start{-1};     // throw at WorkerStart(i)
    std::atomic<int>        fail_build_start{-1};      // throw at BuildThreadStart(i)
    std::atomic<bool>       fail_keyer_start{false};   // throw at KeyerStart

    mn::TestHook hook() {
        return [this](TP p, std::uint64_t g, unsigned i, const std::function<bool()>& c) { on(p, g, i, c); };
    }

    void on(TP p, std::uint64_t g, unsigned i, const std::function<bool()>& cancelled) {
        const auto injected = [] {
            return std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again), "injected");
        };
        if (p == TP::KeyerStart && fail_keyer_start.load()) throw injected();
        if (p == TP::WorkerStart && fail_worker_start.load() == static_cast<int>(i)) throw injected();
        if (p == TP::BuildThreadStart && fail_build_start.load() == static_cast<int>(i)) throw injected();
        {
            std::unique_lock<std::mutex> lk(mu);
            marks.push_back({p, g, i});
            cv.notify_all();
            if (p != TP::Requested && p != TP::StopRequested) {
                for (auto& [id, l] : latches) {
                    if (l.open || l.p != p || (l.gen != 0 && l.gen != g)) continue;
                    Latch& L = l;
                    const bool ok = cv.wait_until(lk, std::chrono::steady_clock::now() + kLatchBound, [&] {
                        return L.open || (!L.ignore_cancel && cancelled());
                    });
                    if (!ok) ++watchdog;
                    L.open = true;
                    break;
                }
            }
        }
        if (p == TP::AfterCacheInit && fail_after_cache.load()) throw std::runtime_error("injected");
    }

    int arm(TP p, std::uint64_t gen, bool ignore_cancel = false) {
        std::lock_guard<std::mutex> lk(mu);
        const int id = next_id++;
        latches[id] = Latch{p, gen, ignore_cancel, false};
        return id;
    }
    void open(int id) {
        std::lock_guard<std::mutex> lk(mu);
        latches[id].open = true;
        cv.notify_all();
    }
    bool reached(TP p, std::uint64_t gen) {
        std::lock_guard<std::mutex> lk(mu);
        return reached_locked(p, gen);
    }
    bool wait_reached(TP p, std::uint64_t gen) {
        std::unique_lock<std::mutex> lk(mu);
        return cv.wait_for(lk, kLatchBound, [&] { return reached_locked(p, gen); });
    }
    int watchdogs() {
        std::lock_guard<std::mutex> lk(mu);
        return watchdog;
    }

private:
    bool reached_locked(TP p, std::uint64_t gen) const {
        for (const Mark& m : marks)
            if (m.p == p && (gen == 0 || m.gen == gen)) return true;
        return false;
    }
};

// Threads of this process (Linux), or -1 where /proc is not available.
static int count_tasks() {
#if defined(__linux__)
    int n = 0;
    if (DIR* d = opendir("/proc/self/task")) {
        while (dirent* e = readdir(d))
            if (e->d_name[0] != '.') ++n;
        closedir(d);
        return n;
    }
#endif
    return -1;
}
// The kernel removes an exited thread from /proc/self/task shortly after its
// join returns; give the listing that long to agree.
// This process's thread count with no miner alive: the least count seen over
// one second after a thread has been started and joined (a sanitizer runtime
// may start a thread of its own at the first thread start).
static int g_base_tasks = -1;
static void measure_base_tasks() {
    std::thread([] {}).join();
    int least = count_tasks();
    const auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < dl) {
        const int n = count_tasks();
        if (n >= 0 && n < least) least = n;
        std::this_thread::yield();
    }
    g_base_tasks = least;
}
static bool tasks_settle_to(int want) {
    if (want < 0) return true;
    const auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < dl) {
        if (count_tasks() == want) return true;
        std::this_thread::yield();
    }
    return count_tasks() == want;
}

static mn::MinerJob make_job(std::uint8_t seed_tag, std::uint32_t tid) {
    mn::MinerJob j;
    j.blob = make_blob();
    j.blob[8] ^= static_cast<std::uint8_t>(tid);
    j.blob[9] ^= static_cast<std::uint8_t>(tid >> 8);
    j.nonce_offset   = kNonceOffset;
    j.template_id    = tid;
    j.extra_nonce    = 0x99;
    j.height         = 1000 + tid;
    j.seed_hash      = make_seed(seed_tag);
    j.lane_target    = target_from_diff(16);
    j.network_target = 0;
    return j;
}

static mn::MinerOptions light_opts(HookCtl& ctl, unsigned threads = 1) {
    mn::MinerOptions o;
    o.threads     = threads;
    o.fast_mode   = false;
    o.large_pages = false;
    o.pin_threads = false;
    o.test_hook   = ctl.hook();
    return o;
}

// Every hit re-hashes bit-for-bit under the seed of the job it names.
struct Rehasher {
    c2pool::xmr::LightVerifier v;
    bool ok = false;
    Rehasher() { c2pool::xmr::VerifierOptions vo; ok = v.init(vo); }
    bool matches(const mn::MinerHit& h, const mn::MinerJob& j) {
        if (!ok) return false;
        const c2pool::xmr::SeedHash vs = to_vseed(j.seed_hash);
        if (!v.seed_resident(vs)) v.prefetch_epoch(vs, std::nullopt);
        std::vector<std::uint8_t> blob = j.blob;
        for (std::size_t i = 0; i < 4; ++i)
            blob[j.nonce_offset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
        std::uint8_t ref[32];
        return v.hash(blob.data(), blob.size(), vs, ref) && std::memcmp(ref, h.pow_hash.data(), 32) == 0;
    }
};

// Polls the hit queue (the workers' hashing, not the keyer) until `want` hits
// that name `tid` are in, or the bound passes. Every hit popped is returned.
static std::vector<mn::MinerHit> collect(mn::CpuMiner& m, std::uint32_t tid, int want, int bound_s = 120) {
    std::vector<mn::MinerHit> out;
    int got = 0;
    const auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(bound_s);
    while (got < want && std::chrono::steady_clock::now() < dl) {
        mn::MinerHit h;
        while (m.pop_hit(h)) {
            out.push_back(h);
            if (h.template_id == tid) ++got;
        }
        if (got < want) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return out;
}

static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }
static bool any_has(const std::vector<std::string>& v, const char* sub) {
    for (const std::string& s : v) if (has(s, sub)) return true;
    return false;
}
static std::string seed16(const mn::SeedBytes& s) { return mn::detail::to_hex(s.data(), 8); }
static std::uint64_t req_gen(const mn::CpuMiner& m) { return m.build_progress().request_gen; }

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    bool quick = false;
    std::set<std::string> only;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--quick") quick = true;
        if (a == "--only" && i + 1 < argc) {
            std::string list = argv[++i];
            for (std::size_t b = 0; b <= list.size();) {
                const std::size_t e = std::min(list.find(',', b), list.size());
                if (e > b) only.insert(list.substr(b, e - b));
                b = e + 1;
            }
        }
    }
    const auto sel = [&](const char* name) { return only.empty() || only.count(name) != 0; };

    std::printf("== xmr_cpu_miner_kat ==\n");
    measure_base_tasks();

    // ---- K1: topology + pinning helpers ----------------------------------
    if (sel("K")) {
        const std::vector<int> order = mn::detail::preferred_cpu_order();
        const std::set<int> uniq(order.begin(), order.end());
        check(!order.empty(), "K1.a preferred_cpu_order is non-empty",
              "n=" + std::to_string(order.size()));
        check(uniq.size() == order.size(), "K1.b preferred_cpu_order has no duplicates");
        bool in_range = true;
        for (int c : order) if (c < 0) in_range = false;
        check(in_range, "K1.c every cpu id is non-negative");
        // Pinning must never throw or abort; it may legitimately refuse.
        const bool pinned = mn::detail::pin_this_thread(order.front());
        check(true, "K1.d pin_this_thread is non-fatal",
              pinned ? "pinned cpu " + std::to_string(order.front())
                     : "refused (cpuset/container) — fallback path exercised");
        std::printf("       hugepages_total=%ld\n", mn::detail::hugepages_total());
        // Undo the pin: the rest of the KAT must be free to use every core.
        for (int c : order) (void)mn::detail::pin_this_thread(c);
    }

    // ---- shared setup: one verifier, one seed -----------------------------
    c2pool::xmr::LightVerifier verifier;
    c2pool::xmr::VerifierOptions vo;   // light, JIT on, no large pages
    if (!verifier.init(vo)) {
        std::printf("  [FAIL] verifier init (OOM?) — cannot check the miner's hashes\n");
        return 1;
    }
    const mn::SeedBytes seed = make_seed(0x5A);
    const c2pool::xmr::SeedHash vseed = to_vseed(seed);
    verifier.prefetch_epoch(vseed, std::nullopt);
    if (!verifier.seed_resident(vseed)) {
        std::printf("  [FAIL] verifier seed not resident after prefetch\n");
        return 1;
    }

    // ---- K2/K3/K4/K5/K6/K7: mine in LIGHT mode ----------------------------
    if (sel("K")) {
        mn::MinerOptions o;
        o.threads     = 2;            // keep CI memory and CPU modest
        o.fast_mode   = false;        // LIGHT is the default and what CI runs
        o.large_pages = true;         // K5: ask for them; must degrade, not die
        o.pin_threads = true;
        mn::CpuMiner miner(o);

        mn::MinerJob job;
        job.blob           = make_blob();
        job.nonce_offset   = kNonceOffset;
        job.template_id    = 0x1111;
        job.extra_nonce    = 0x2222;
        job.height         = 123456;
        job.seed_hash      = seed;
        job.lane_target    = target_from_diff(64);              // ~64 hashes per hit
        job.network_target = target_from_diff(1ULL << 40);      // effectively never

        std::string why;
        const auto t0 = std::chrono::steady_clock::now();
        const bool posted = miner.set_job(job, &why);
        const bool ok = posted && wait_result(miner) && miner.install_ready();
        check(ok, "K5.a miner starts with large_pages requested", ok ? miner.large_pages_note() : why);
        if (!ok) return 1;

        const int want_hits = quick ? 2 : 4;
        std::vector<mn::MinerHit> hits;
        const auto deadline = t0 + std::chrono::seconds(180);
        while (static_cast<int>(hits.size()) < want_hits &&
               std::chrono::steady_clock::now() < deadline) {
            mn::MinerHit h;
            while (miner.pop_hit(h)) hits.push_back(h);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const double secs = std::chrono::duration<double>(
                                std::chrono::steady_clock::now() - t0).count();
        const mn::MinerStats st = miner.stats();
        std::printf("       %s\n", miner.describe().c_str());
        std::printf("       LIGHT-mode: %llu hashes in %.1fs over %u threads => %.1f H/s "
                    "(%.1f H/s/thread)\n",
                    static_cast<unsigned long long>(st.hashes), secs, st.threads,
                    secs > 0 ? st.hashes / secs : 0.0,
                    (secs > 0 && st.threads) ? st.hashes / secs / st.threads : 0.0);
        std::printf("       %s\n", miner.pinning_note().c_str());

        check(static_cast<int>(hits.size()) >= want_hits,
              "K2.a miner finds lane-target hits",
              "got " + std::to_string(hits.size()) + "/" + std::to_string(want_hits));

        // K2.b/K3: every reported hash is a REAL RandomX hash of the exact blob
        // with the reported nonce, and achieved_target is its top LE word.
        int rehash_ok = 0, target_ok = 0, lane_ok = 0, wrong_tid = 0;
        for (const mn::MinerHit& h : hits) {
            std::vector<std::uint8_t> blob = job.blob;
            for (std::size_t i = 0; i < 4; ++i)
                blob[kNonceOffset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
            std::uint8_t ref[32];
            if (!verifier.hash(blob.data(), blob.size(), vseed, ref)) continue;
            if (std::memcmp(ref, h.pow_hash.data(), 32) == 0) ++rehash_ok;
            if (h.achieved_target == top_word_le(h.pow_hash)) ++target_ok;
            if (h.achieved_target <= job.lane_target) ++lane_ok;
            if (h.template_id != job.template_id || h.extra_nonce != job.extra_nonce)
                ++wrong_tid;
        }
        check(!hits.empty() && rehash_ok == static_cast<int>(hits.size()),
              "K2.b every mined hash re-computes byte-identically in LightVerifier",
              std::to_string(rehash_ok) + "/" + std::to_string(hits.size()));
        check(!hits.empty() && target_ok == static_cast<int>(hits.size()),
              "K3.a achieved_target == top 64-bit LE word of the hash");
        check(!hits.empty() && lane_ok == static_cast<int>(hits.size()),
              "K3.b every reported hit actually clears the lane target");
        check(wrong_tid == 0, "K3.c hits carry the job's (template_id, extra_nonce)");

        check(st.blocks == 0, "K4.a no false network-block hits at difficulty 2^40",
              "blocks=" + std::to_string(st.blocks) + " over " +
                  std::to_string(st.hashes) + " hashes");
        bool any_net = false;
        for (const mn::MinerHit& h : hits) if (h.network) any_net = true;
        check(!any_net, "K4.b no hit is flagged `network` at an impossible target");
        check(st.hashes > 0, "K4.c the negative is not a dead miner (hashes > 0)");

        // ---- K6: a new job displaces the old one --------------------------
        //
        // NOTE ON WHAT IS *NOT* ASSERTED HERE. A worker checks for a job change
        // every 64 hashes and then closes its RandomX pipeline with one final
        // hash of the nonce already loaded, so a hit for the PREVIOUS template
        // can legitimately land in the queue after set_job() returned. That is
        // not staleness to be suppressed: it is real work, it names the
        // template it was done on, and the provider keeps a 6-deep template ring
        // precisely so the node can still submit it. The invariant the node
        // actually depends on — and the one asserted below — is stronger and
        // simpler: EVERY hit verifies against the blob of the template it
        // NAMES, and the new template does take over.
        std::map<std::uint32_t, mn::MinerJob> issued;
        issued[job.template_id] = job;

        mn::MinerJob job2 = job;
        job2.template_id = 0x3333;
        job2.extra_nonce = 0x4444;
        job2.blob[8] ^= 0xFF;   // different work, same seed => no re-key
        std::string why2;
        const bool ok2 = miner.set_job(job2, &why2);
        check(ok2, "K6.a set_job replaces the work in place", ok2 ? "" : why2);
        issued[job2.template_id] = job2;
        { mn::MinerHit h; while (miner.pop_hit(h)) {} }   // drain what job 1 queued

        std::vector<mn::MinerHit> hits2;
        int new_tid = 0;
        const auto d2 = std::chrono::steady_clock::now() + std::chrono::seconds(120);
        while (new_tid < 2 && std::chrono::steady_clock::now() < d2) {
            mn::MinerHit h;
            while (miner.pop_hit(h)) {
                hits2.push_back(h);
                if (h.template_id == job2.template_id) ++new_tid;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        check(new_tid >= 2, "K6.b the new template takes over the workers",
              "new-template hits=" + std::to_string(new_tid) + " of " +
                  std::to_string(hits2.size()) + " total");

        int rehash2 = 0, unknown_tid = 0;
        for (const mn::MinerHit& h : hits2) {
            auto it = issued.find(h.template_id);
            if (it == issued.end()) { ++unknown_tid; continue; }
            std::vector<std::uint8_t> blob = it->second.blob;
            for (std::size_t i = 0; i < 4; ++i)
                blob[kNonceOffset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
            std::uint8_t ref[32];
            if (verifier.hash(blob.data(), blob.size(), vseed, ref) &&
                std::memcmp(ref, h.pow_hash.data(), 32) == 0)
                ++rehash2;
        }
        check(unknown_tid == 0, "K6.c no hit names a template that was never issued");
        check(!hits2.empty() && rehash2 == static_cast<int>(hits2.size()),
              "K6.d every hit verifies against the blob of the template it NAMES",
              std::to_string(rehash2) + "/" + std::to_string(hits2.size()));

        // ---- K7: SELF-CONTAINED FIND at a regtest network difficulty -------
        // The node's exact acceptance rule is meets_difficulty_128(hash, lo, hi)
        // — the SAME predicate O2RandomXVerifier::verify_network_block applies
        // before a block is published. Here the miner's cheap u64 pre-filter
        // proposes, and the node's exact rule disposes, entirely in-process.
        {
            const std::uint64_t regtest_diff = 500;     // monerod --fixed-difficulty class
            mn::MinerJob job3 = job2;
            job3.template_id    = 0x5555;
            job3.extra_nonce    = 0x6666;
            job3.blob[9] ^= 0x5A;
            job3.network_target = target_from_diff(regtest_diff);
            job3.lane_target    = 0;                    // solo: block hits only
            std::string why3;
            check(miner.set_job(job3, &why3), "K7.a miner takes a regtest network job",
                  why3);
            { mn::MinerHit h; while (miner.pop_hit(h)) {} }

            // Only hits that NAME job 3 are this test's subject; a trailing
            // job-2 share may still arrive (see the K6 note) and is ignored.
            std::vector<mn::MinerHit> found;
            const auto d3 = std::chrono::steady_clock::now() + std::chrono::seconds(240);
            while (found.empty() && std::chrono::steady_clock::now() < d3) {
                mn::MinerHit h;
                while (miner.pop_hit(h))
                    if (h.template_id == job3.template_id) found.push_back(h);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            check(!found.empty(), "K7.b miner finds a NETWORK-target hit",
                  "difficulty=" + std::to_string(regtest_diff) +
                      " n=" + std::to_string(found.size()));
            int net_flag = 0, exact_ok = 0, rehash3 = 0;
            for (const mn::MinerHit& h : found) {
                if (h.network) ++net_flag;
                std::vector<std::uint8_t> blob = job3.blob;
                for (std::size_t i = 0; i < 4; ++i)
                    blob[kNonceOffset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
                std::uint8_t ref[32];
                if (!verifier.hash(blob.data(), blob.size(), vseed, ref)) continue;
                if (std::memcmp(ref, h.pow_hash.data(), 32) == 0) ++rehash3;
                // the node's exact 128-bit gate, difficulty = (lo=regtest_diff, hi=0)
                if (c2pool::xmr::meets_difficulty_128(ref, regtest_diff, 0)) ++exact_ok;
            }
            check(!found.empty() && net_flag == static_cast<int>(found.size()),
                  "K7.c every job-3 hit is flagged `network`");
            check(!found.empty() && rehash3 == static_cast<int>(found.size()),
                  "K7.d the found hash re-computes byte-identically in LightVerifier",
                  std::to_string(rehash3) + "/" + std::to_string(found.size()));
            check(!found.empty() && exact_ok == static_cast<int>(found.size()),
                  "K7.e the found hash passes the node's EXACT 128-bit gate",
                  std::to_string(exact_ok) + "/" + std::to_string(found.size()));
        }

        miner.stop();
        check(!miner.running(), "K6.e stop() joins every worker");
    }

    // ---- K8: verifier re-key racing a miner re-key (SIGFPE regression) -----
    // The crash this reproduces needs both randomx_init_cache() calls to be in
    // flight at once. Both sides now take randomx_init_mutex(), so the loop
    // below simply has to survive; if the lock is removed it dies with SIGFPE
    // inside randomx_reciprocal() (observed 2026-09-17 on a regtest node).
    if (sel("K")) {
        mn::MinerOptions o;
        o.threads     = 1;
        o.large_pages = false;
        o.pin_threads = false;
        mn::CpuMiner miner(o);

        std::atomic<bool> go{false}, die{false};
        std::atomic<int>  rekeys{0};
        std::thread verifier_thread([&] {
            c2pool::xmr::LightVerifier lv;
            c2pool::xmr::VerifierOptions v2;
            if (!lv.init(v2)) return;
            while (!go.load()) std::this_thread::yield();
            for (int i = 0; i < 4 && !die.load(); ++i) {
                lv.prefetch_epoch(to_vseed(make_seed(static_cast<std::uint8_t>(0x80 + i))),
                                  std::nullopt);
                rekeys.fetch_add(1);
            }
        });

        mn::MinerJob j;
        j.blob         = make_blob();
        j.nonce_offset = kNonceOffset;
        j.template_id  = 0x7777;
        j.lane_target  = target_from_diff(1ULL << 30);   // never fires; we want the re-keys
        bool all_ok = true, any_failed = false;
        go.store(true);
        for (int i = 0; i < 4; ++i) {
            j.seed_hash   = make_seed(static_cast<std::uint8_t>(0xC0 + i));
            j.template_id = static_cast<std::uint32_t>(0x7777 + i);
            std::string w;
            if (!miner.set_job(j, &w)) { all_ok = false; std::printf("       set_job: %s\n", w.c_str()); }
            if (!wait_result(miner) || !miner.install_ready()) all_ok = false;
            for (const std::string& e : miner.take_events())
                if (e.find("key failed") != std::string::npos) any_failed = true;
        }
        die.store(true);
        verifier_thread.join();
        const std::uint64_t rk = miner.stats().seed_rekeys;
        miner.stop();
        check(all_ok, "K8.a 4 miner re-keys succeed while a verifier re-keys concurrently");
        check(rekeys.load() > 0, "K8.b the verifier side really ran",
              "prefetch_epoch x" + std::to_string(rekeys.load()));
        check(true, "K8.c no SIGFPE — randomx_init_mutex() held the two apart");
        check(rk == 4 && !any_failed, "V-h 4 posts, 4 keys installed, no key failed",
              "seed_rekeys=" + std::to_string(rk));
    }

    // =======================================================================
    // The keyer thread and the caller-thread transitions.
    // =======================================================================
    Rehasher rh;
    if (!rh.ok) {
        std::printf("  [FAIL] rehash verifier init (OOM?)\n");
        return 1;
    }

    // ---- V-a: the caller never waits on a key ------------------------------
    if (sel("V-a")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x11, 0xA001), A2 = make_job(0x11, 0xA002);
        const std::uint64_t gA = req_gen(m) + 1;
        const int l = ctl.arm(TP::AfterCacheInit, gA);
        std::string why;
        const bool posted = m.set_job(A, &why);
        const bool held = ctl.wait_reached(TP::AfterCacheInit, gA);
        const bool repost = m.set_job(A2, &why);
        mn::MinerHit h;
        const bool popped = m.pop_hit(h);
        const mn::MinerStats st = m.stats();
        const std::string d = m.describe();
        const std::vector<std::string> ev = m.take_events();
        const bool ir = m.install_ready();
        const bool run = m.running();
        const std::string notes = m.large_pages_note() + m.pinning_note();
        const bool still_held = !ctl.reached(TP::BeforePublish, gA) && ctl.watchdogs() == 0;
        check(posted && held && repost && still_held,
              "V-a.1 set_job (new seed, then the same seed) returns while the key is held");
        check(!popped && st.threads == 0 && !ir && !run && req_gen(m) == gA,
              "V-a.2 pop_hit / stats / install_ready / running return while held; nothing installed");
        check(has(d, "cpu-miner: keying") && has(d, "key=keying") && has(d, ("key_seed=" + seed16(A.seed_hash)).c_str()),
              "V-a.3 describe says keying while held", d);
        check(any_has(ev, "keying seed="), "V-a.4 take_events has the keying line");
        (void)notes;
        ctl.open(l);
        const bool wr = wait_result(m);
        const bool in = wr && m.install_ready();
        const std::string d2 = m.describe();
        check(wr && in && m.running() && has(d2, "cpu-miner: RUNNING") && has(d2, "key=ready"),
              "V-a.5 after the key: wait_result_for, install_ready installs, RUNNING", d2);
        const std::vector<mn::MinerHit> hits = collect(m, A2.template_id, 1);
        bool names_a2 = !hits.empty();
        for (const mn::MinerHit& x : hits) if (x.template_id != A2.template_id) names_a2 = false;
        check(names_a2, "V-a.6 the newest post (A2) is the job installed");
        check(ctl.watchdogs() == 0, "V-a.7 no watchdog fired");
    }

    // ---- V-b: the seed check in the install; release with no live user -----
    if (sel("V-b")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x21, 0xB001), B = make_job(0x22, 0xB002);
        std::string why;
        const bool a_ok = m.set_job(A, &why) && wait_result(m) && m.install_ready();
        std::vector<mn::MinerHit> ahits = collect(m, A.template_id, 1);
        const std::uint64_t gB = req_gen(m) + 1;
        const int l = ctl.arm(TP::BeforePublish, gB);
        const bool b_posted = m.set_job(B, &why);
        const bool halted = !m.running() && m.stats().threads == 0;
        const std::uint64_t h0 = m.stats().hashes;
        const bool held = ctl.wait_reached(TP::BeforePublish, gB);
        const std::uint64_t h1 = m.stats().hashes;
        mn::MinerHit h;
        bool drained_a = true;
        while (m.pop_hit(h)) {
            if (h.template_id != A.template_id) drained_a = false;
            ahits.push_back(h);
        }
        check(a_ok && b_posted && halted, "V-b.1 set_job(B, SB) returns with the workers halted",
              "running=" + std::to_string(m.running()));
        check(held && h0 == h1 && drained_a, "V-b.2 at BeforePublish: hashes unchanged, every drained hit names A");
        ctl.open(l);
        const bool in = wait_result(m) && m.install_ready();
        check(in && m.running(), "V-b.3 install_ready installs B");
        const std::vector<mn::MinerHit> bhits = collect(m, B.template_id, 2);
        int nb = 0, okb = 0, oka = 0, other = 0;
        for (const mn::MinerHit& x : bhits) {
            if (x.template_id == B.template_id) { ++nb; if (rh.matches(x, B)) ++okb; }
            else if (x.template_id == A.template_id) ahits.push_back(x);
            else ++other;
        }
        for (const mn::MinerHit& x : ahits) if (rh.matches(x, A)) ++oka;
        check(nb >= 2 && okb == nb && other == 0, "V-b.4 every B hit re-hashes bit-for-bit under SB",
              std::to_string(okb) + "/" + std::to_string(nb));
        check(!ahits.empty() && oka == static_cast<int>(ahits.size()), "V-b.5 every A hit re-hashes under SA",
              std::to_string(oka) + "/" + std::to_string(ahits.size()));
        check(ctl.watchdogs() == 0, "V-b.6 no watchdog fired");
    }

    // ---- V-c: newest wins; a newer seed cancels the build ------------------
    if (sel("V-c")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x31, 0xC001), B = make_job(0x32, 0xC002), B2 = make_job(0x32, 0xC003);
        const std::uint64_t gA = req_gen(m) + 1;
        ctl.arm(TP::AfterCacheInit, gA);
        std::string why;
        const bool pa = m.set_job(A, &why);
        const bool held = ctl.wait_reached(TP::AfterCacheInit, gA);
        const bool pb = m.set_job(B, &why);
        const std::uint64_t gB = req_gen(m);
        const bool pb2 = m.set_job(B2, &why);
        const bool no_new_request = req_gen(m) == gB;
        const bool in = wait_result(m) && m.install_ready();
        const mn::CpuMiner::BuildProgress bp = m.build_progress();
        check(pa && held && pb && pb2 && no_new_request && in, "V-c.1 A held, B then B' posted, B' installed");
        check(bp.abandoned == 1 && m.stats().seed_rekeys == 1 && bp.consumed_gen == gB,
              "V-c.2 abandoned == 1, seed_rekeys == 1, consumed == gB",
              "abandoned=" + std::to_string(bp.abandoned) + " rekeys=" + std::to_string(m.stats().seed_rekeys));
        const std::vector<mn::MinerHit> hits = collect(m, B2.template_id, 1);
        int okb = 0, wrong = 0;
        for (const mn::MinerHit& x : hits) {
            if (x.template_id != B2.template_id) { ++wrong; continue; }
            if (rh.matches(x, B2)) ++okb;
        }
        check(!hits.empty() && wrong == 0 && okb == static_cast<int>(hits.size()),
              "V-c.3 only B' is installed; its hits verify under SB", "wrong=" + std::to_string(wrong));
        check(ctl.watchdogs() == 0, "V-c.4 no watchdog fired");
    }

    // ---- V-d: stop() -------------------------------------------------------
    if (sel("V-d")) {
        const int base = g_base_tasks;
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x41, 0xD001);
        const std::uint64_t gA = req_gen(m) + 1;
        ctl.arm(TP::AfterCacheInit, gA);
        std::string why;
        const bool pa = m.set_job(A, &why);
        const bool held = ctl.wait_reached(TP::AfterCacheInit, gA);
        m.stop();
        const bool wd0 = ctl.watchdogs() == 0;
        const bool gone = tasks_settle_to(base);
        check(pa && held && wd0 && gone, "V-d.1 stop() during a held key returns before the watchdog; no thread remains",
              "tasks=" + std::to_string(count_tasks()) + " base=" + std::to_string(base));
        const bool again = m.set_job(A, &why);
        const bool in = again && wait_result(m) && m.install_ready();
        const std::vector<mn::MinerHit> hits = collect(m, A.template_id, 1);
        check(in && !hits.empty(), "V-d.2 the same job after stop(): K restarted, keyed, installed, hashing");
        m.stop();
        const bool resumed = m.set_job(A, &why);
        check(resumed && m.running(), "V-d.3 stop() while RUNNING, then the same job installs at once");
    }

    // ---- V-i: clear_job during a build -------------------------------------
    if (sel("V-i")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x51, 0xE001);
        const std::uint64_t gA = req_gen(m) + 1;
        const int l = ctl.arm(TP::BeforePublish, gA);
        std::string why;
        const bool pa = m.set_job(A, &why);
        const bool held = ctl.wait_reached(TP::BeforePublish, gA);
        const std::vector<mn::MinerHit> back = m.clear_job();
        const bool returned_held = !ctl.reached(TP::AfterPublish, gA);
        ctl.open(l);
        const bool wr = wait_result(m);
        const bool ir = m.install_ready();
        const std::string d = m.describe();
        check(pa && held && returned_held && back.empty(), "V-i.1 clear_job returns while the build is held");
        check(wr && !ir && !m.running() && has(d, "key=ready"),
              "V-i.2 the build's result is kept ready; nothing installed", d);
        const bool again = m.set_job(A, &why);
        check(again && m.running() && req_gen(m) == gA, "V-i.3 set_job(A) installs at once, no new request");
        check(ctl.watchdogs() == 0, "V-i.4 no watchdog fired");
    }

    // ---- V-k: the destructor mid-build, without stop() ---------------------
    if (sel("V-k")) {
        const int base = g_base_tasks;
        HookCtl ctl;
        {
            auto m = std::make_unique<mn::CpuMiner>(light_opts(ctl));
            const mn::MinerJob A = make_job(0x61, 0xF001);
            const std::uint64_t gA = req_gen(*m) + 1;
            ctl.arm(TP::AfterCacheInit, gA);
            std::string why;
            m->set_job(A, &why);
            check(ctl.wait_reached(TP::AfterCacheInit, gA), "V-k.1 the key is held");
            m.reset();
        }
        check(ctl.watchdogs() == 0 && tasks_settle_to(base),
              "V-k.2 the destructor returns before the watchdog; no thread remains");
    }

    // ---- V-l: a failed key and the retry ------------------------------------
    if (sel("V-l")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x71, 0x7101), A2 = make_job(0x71, 0x7102);
        std::string why;
        ctl.fail_after_cache = true;
        const bool pa = m.set_job(A, &why);
        const bool wr = wait_result(m);
        const bool ir = m.install_ready();
        const std::vector<std::string> ev = m.take_events();
        const std::string d = m.describe();
        check(pa && wr && !ir && any_has(ev, "key failed") && any_has(ev, "injected") && has(d, "key=failed"),
              "V-l.1 the failed key is taken: key failed ... injected, key=failed", d);
        ctl.fail_after_cache = false;
        const std::uint64_t g0 = req_gen(m);
        std::string w2;
        const bool r1 = m.set_job(A2, &w2);
        const std::uint64_t g1 = req_gen(m);
        check(!r1 && has(w2, "injected") && has(w2, "key failed (seed ") && g1 == g0 + 1,
              "V-l.2 set_job of that seed is false with the reason and requests one retry", w2);
        const bool r2 = m.set_job(A2, &w2);
        check(r2 && req_gen(m) == g1, "V-l.3 the re-offer is true and requests nothing");
        const bool in = wait_result(m) && m.install_ready();
        const std::vector<mn::MinerHit> hits = collect(m, A2.template_id, 1);
        check(in && !hits.empty(), "V-l.4 the retry keys, installs A2 and hashes");
    }

    // ---- V-l (2): a failed result untaken at stop() -------------------------
    if (sel("V-l2")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob J = make_job(0x72, 0x7201), J2 = make_job(0x72, 0x7202);
        std::string why;
        ctl.fail_after_cache = true;
        const std::uint64_t gJ = req_gen(m) + 1;
        const bool pj = m.set_job(J, &why);
        const bool pub = ctl.wait_reached(TP::AfterPublish, gJ);
        m.stop();
        ctl.fail_after_cache = false;
        const std::vector<std::string> ev = m.take_events();
        check(pj && pub && any_has(ev, ("key failed seed=" + seed16(J.seed_hash)).c_str()),
              "V-l2.1 stop() reports the failed result it finds after the join");
        std::string w2;
        const bool r = m.set_job(J2, &w2);
        check(!r && has(w2, "key failed (seed ") && has(w2, "injected"),
              "V-l2.2 after stop(), that seed's next job is the retry (false + reason)", w2);
    }

    // ---- V-o: at most one set; release before allocate; retraction ---------
    if (sel("V-o")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob A = make_job(0x81, 0x8101), B = make_job(0x82, 0x8102), C = make_job(0x83, 0x8103);
        std::string why;
        const bool a_ok = m.set_job(A, &why) && wait_result(m) && m.install_ready();
        const long long live_a = m.build_progress().sets_live;
        const std::uint64_t rk0 = m.stats().seed_rekeys;
        const std::uint64_t gB = req_gen(m) + 1;
        const int lb = ctl.arm(TP::BeforeAlloc, gB);
        const int lp = ctl.arm(TP::AfterPublish, gB, true);
        const bool pb = m.set_job(B, &why);
        const bool at_b = ctl.wait_reached(TP::BeforeAlloc, gB);
        const long long live_b = m.build_progress().sets_live;
        check(a_ok && live_a == 1 && pb && at_b && live_b == 0, "V-o.1 at BeforeAlloc(gB) no set is alive",
              "live_a=" + std::to_string(live_a) + " live_b=" + std::to_string(live_b));
        ctl.open(lb);
        const bool pub_b = ctl.wait_reached(TP::AfterPublish, gB);
        const bool pc = m.set_job(C, &why);
        const std::uint64_t gC = req_gen(m);
        const bool ir_stale = m.install_ready();
        check(pub_b && pc && gC == gB + 1 && !ir_stale, "V-o.2 the SB result is stale: install_ready takes nothing");
        const int lc = ctl.arm(TP::BeforeAlloc, gC);
        ctl.open(lp);
        const bool at_c = ctl.wait_reached(TP::BeforeAlloc, gC);
        const long long live_c = m.build_progress().sets_live;
        ctl.open(lc);
        check(at_c && live_c == 0, "V-o.3 at BeforeAlloc(gC) the retracted SB set is released",
              "live=" + std::to_string(live_c));
        const bool in = wait_result(m) && m.install_ready();
        const long long live_end = m.build_progress().sets_live;
        const std::uint64_t rk1 = m.stats().seed_rekeys;
        check(in && live_end == 1 && rk1 == rk0 + 1, "V-o.4 C installed; one set alive; one more rekey (SC only)",
              "live=" + std::to_string(live_end) + " rekeys " + std::to_string(rk0) + "->" + std::to_string(rk1));
        check(ctl.watchdogs() == 0, "V-o.5 no watchdog fired");
    }

    // ---- V-t: the caller's reads during repeated builds (TSan) -------------
    if (sel("V-t")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        int installed = 0;
        std::size_t chars = 0;
        for (int k = 0; k < 6; ++k) {
            const mn::MinerJob J = make_job(static_cast<std::uint8_t>(0x91 + (k % 2)), static_cast<std::uint32_t>(0x9100 + k));
            std::string why;
            if (!m.set_job(J, &why)) break;
            const auto dl = std::chrono::steady_clock::now() + kWait;
            bool in = false;
            while (!in && std::chrono::steady_clock::now() < dl) {
                chars += m.describe().size() + m.large_pages_note().size() + m.pinning_note().size();
                chars += static_cast<std::size_t>(m.stats().threads);
                for (const std::string& e : m.take_events()) chars += e.size();
                in = m.install_ready();
                std::this_thread::yield();
            }
            if (in && m.running()) ++installed;
        }
        check(installed == 6 && chars > 0, "V-t 6 alternating-seed builds installed while the caller reads in a loop",
              "installed=" + std::to_string(installed));
    }

    // ---- R-SH1: set_job then clear_job; clear_job during a build -----------
    if (sel("R-SH1")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob J0 = make_job(0xA1, 0xA100), J = make_job(0xA1, 0xA101), J2 = make_job(0xA2, 0xA102);
        std::string why;
        const bool ready = m.set_job(J0, &why) && wait_result(m) && m.install_ready();
        m.clear_job();
        const bool sj = m.set_job(J, &why);
        m.clear_job();
        const bool a_ok = ready && sj && !m.running() && m.stats().threads == 0 && !m.install_ready();
        check(a_ok, "R-SH1.a set_job then clear_job: halted, install_ready false");
        const std::uint64_t g = req_gen(m) + 1;
        const int l = ctl.arm(TP::BeforePublish, g);
        const bool p2 = m.set_job(J2, &why);
        const bool held = ctl.wait_reached(TP::BeforePublish, g);
        m.clear_job();
        ctl.open(l);
        const bool wr = wait_result(m);
        check(p2 && held && wr && !m.running() && !m.install_ready() && !m.running(),
              "R-SH1.b clear_job during the build: the withdrawn job is never installed");
        check(ctl.watchdogs() == 0, "R-SH1 no watchdog fired");
    }

    // ---- R-DV1: a same-seed install, then clear_job -------------------------
    if (sel("R-DV1")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob J1 = make_job(0xB1, 0xB101), J2 = make_job(0xB1, 0xB102);
        std::string why;
        const bool r1 = m.set_job(J1, &why) && wait_result(m) && m.install_ready();
        const bool r2 = m.set_job(J2, &why) && m.running();
        std::vector<mn::MinerHit> back = m.clear_job();
        const bool stopped = !m.running() && m.stats().threads == 0;
        mn::MinerHit h;
        while (m.pop_hit(h)) back.push_back(h);
        int foreign = 0;
        for (const mn::MinerHit& x : back)
            if (x.template_id != J1.template_id && x.template_id != J2.template_id) ++foreign;
        check(r1 && r2 && stopped && foreign == 0,
              "R-DV1 clear_job after a same-seed install: no worker alive at once; hits name J1/J2 only",
              "threads=" + std::to_string(m.stats().threads));
    }

    // ---- R-F2: a newer seed before the first allocation ---------------------
    if (sel("R-F2")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob S2 = make_job(0xC2, 0xC201), S3 = make_job(0xC3, 0xC301);
        const std::uint64_t g2 = req_gen(m) + 1;
        ctl.arm(TP::AfterConsume, g2);
        std::string why;
        const bool p2 = m.set_job(S2, &why);
        const bool held = ctl.wait_reached(TP::AfterConsume, g2);
        const bool p3 = m.set_job(S3, &why);
        const bool in = wait_result(m) && m.install_ready();
        const mn::CpuMiner::BuildProgress bp = m.build_progress();
        check(p2 && held && p3 && in && !ctl.reached(TP::AfterCacheInit, g2) && bp.abandoned == 1 &&
                  m.stats().seed_rekeys == 1 && has(m.describe(), ("key_seed=" + seed16(S3.seed_hash)).c_str()),
              "R-F2 S2 is never keyed (abandoned before its Argon2d); only S3 completes",
              "abandoned=" + std::to_string(bp.abandoned));
        check(ctl.watchdogs() == 0, "R-F2 no watchdog fired");
    }

    // ---- R-NI1: stop() right after the keyer consumed a request -------------
    if (sel("R-NI1")) {
        const int base = g_base_tasks;
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob S2 = make_job(0xD2, 0xD201);
        const std::uint64_t g2 = req_gen(m) + 1;
        ctl.arm(TP::AfterConsume, g2);
        std::string why;
        const bool p2 = m.set_job(S2, &why);
        const bool held = ctl.wait_reached(TP::AfterConsume, g2);
        m.stop();
        check(p2 && held && ctl.watchdogs() == 0 && !ctl.reached(TP::AfterCacheInit, g2) && tasks_settle_to(base),
              "R-NI1 stop() at AfterConsume returns before the watchdog; S2 never keyed; no thread remains");
    }

    // ---- R-NI2: a newer seed while the keyer is at AfterConsume -------------
    if (sel("R-NI2")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl));
        const mn::MinerJob S1 = make_job(0xE1, 0xE101), S2 = make_job(0xE2, 0xE201), S3 = make_job(0xE3, 0xE301);
        const std::uint64_t g1 = req_gen(m) + 1, g2 = g1 + 1;
        ctl.arm(TP::AfterCacheInit, g1);
        const int l2 = ctl.arm(TP::AfterConsume, g2);
        std::string why;
        const bool p1 = m.set_job(S1, &why);
        const bool h1 = ctl.wait_reached(TP::AfterCacheInit, g1);
        const bool p2 = m.set_job(S2, &why);
        const bool h2 = ctl.wait_reached(TP::AfterConsume, g2);
        const std::uint64_t ab1 = m.build_progress().abandoned;
        const bool p3 = m.set_job(S3, &why);
        const std::uint64_t g3 = req_gen(m);
        ctl.open(l2);
        const bool in = wait_result(m) && m.install_ready();
        const mn::CpuMiner::BuildProgress bp = m.build_progress();
        check(p1 && h1 && p2 && h2 && ab1 == 1 && p3 && in, "R-NI2.1 S1 held then cancelled; S2 consumed; S3 posted");
        check(bp.abandoned == 2 && ctl.reached(TP::AfterCacheInit, g1) && !ctl.reached(TP::AfterCacheInit, g2) &&
                  ctl.reached(TP::AfterCacheInit, g3) && m.stats().seed_rekeys == 1,
              "R-NI2.2 abandoned == 2; Argon2d for S1 and S3 only; only S3 completes",
              "abandoned=" + std::to_string(bp.abandoned));
        check(ctl.watchdogs() == 0, "R-NI2 no watchdog fired");
    }

    // ---- R-DV3 (a): a worker-start failure on the caller thread ------------
    if (sel("R-DV3")) {
        HookCtl ctl;
        mn::CpuMiner m(light_opts(ctl, 2));
        const mn::MinerJob A = make_job(0xF1, 0xF101), A2 = make_job(0xF1, 0xF102);
        std::string why;
        const bool r = m.set_job(A, &why) && wait_result(m) && m.install_ready();
        m.clear_job();
        const int base_k = g_base_tasks < 0 ? -1 : g_base_tasks + 1;   // + the keyer
        ctl.fail_worker_start = 1;
        std::string w2;
        const bool f = m.set_job(A2, &w2);
        const bool settled = tasks_settle_to(base_k);
        const bool lives = !f && has(w2, "injected") && m.stats().threads == 0 && !m.running() && settled;
        check(r && lives, "R-DV3.a worker 1 fails to start: false + reason, worker 0 joined, nothing runs",
              w2 + " | r=" + std::to_string(r) + " threads=" + std::to_string(m.stats().threads) +
                  " tasks=" + std::to_string(count_tasks()) + " base=" + std::to_string(base_k));
        ctl.fail_worker_start = -1;
        const bool again = m.set_job(A2, &w2);
        check(again && m.running() && m.stats().threads == 2, "R-DV3.a the re-offer installs and runs");
    }

    // ---- R-RETRY: a false set_job posts nothing ----------------------------
    if (sel("R-RETRY")) {
        // (a)
        {
            HookCtl ctl;
            mn::CpuMiner m(light_opts(ctl));
            const mn::MinerJob J1 = make_job(0x15, 0x1501), J2 = make_job(0x15, 0x1502);
            std::string why;
            ctl.fail_after_cache = true;
            const bool f1 = m.set_job(J1, &why) && wait_result(m) && !m.install_ready() &&
                            has(m.describe(), "key=failed");
            ctl.fail_after_cache = false;
            const std::uint64_t g0 = req_gen(m);
            std::string w;
            const bool r = m.set_job(J2, &w);
            const std::uint64_t g1 = req_gen(m);
            const bool wr = wait_result(m);
            const bool ir = m.install_ready();
            const std::string d = m.describe();
            check(f1 && !r && has(w, "key failed (seed ") && g1 == g0 + 1 && wr && !ir && !m.running() &&
                      m.stats().threads == 0 && has(d, "key=ready"),
                  "R-RETRY.a the retry's result is kept ready; the refused job is not installed", d);
            const bool re = m.set_job(J2, &w);
            check(re && req_gen(m) == g1 && m.running(), "R-RETRY.a the re-offer installs at once");
        }
        // (b)
        {
            HookCtl ctl;
            mn::CpuMiner m(light_opts(ctl));
            const mn::MinerJob J1 = make_job(0x16, 0x1601), J2 = make_job(0x16, 0x1602);
            std::string why;
            ctl.fail_after_cache = true;
            const bool f1 = m.set_job(J1, &why) && wait_result(m) && !m.install_ready();
            m.clear_job();
            ctl.fail_after_cache = false;
            const bool r = m.set_job(J2, &why);
            const bool wr = wait_result(m);
            const bool ir = m.install_ready();
            mn::MinerHit h;
            check(f1 && !r && wr && !ir && !m.running() && !m.pop_hit(h),
                  "R-RETRY.b withdraw, then a refused retry: nothing installed, no hit");
        }
        // (c)
        {
            HookCtl ctl;
            mn::CpuMiner m(light_opts(ctl));
            const mn::MinerJob J1 = make_job(0x17, 0x1701), J2 = make_job(0x17, 0x1702);
            std::string why;
            ctl.fail_after_cache = true;
            const bool f1 = m.set_job(J1, &why) && wait_result(m) && !m.install_ready();
            ctl.fail_after_cache = false;
            const bool r = m.set_job(J2, &why);
            const std::uint64_t g1 = req_gen(m);
            const bool re = m.set_job(J2, &why);
            const bool same = req_gen(m) == g1;
            const bool in = wait_result(m) && m.install_ready();
            const std::vector<mn::MinerHit> hits = collect(m, J2.template_id, 1);
            check(f1 && !r && re && same && in && !hits.empty(),
                  "R-RETRY.c the re-offer while the retry is outstanding requests nothing; it installs and hashes",
                  "request_gen " + std::to_string(g1) + "->" + std::to_string(req_gen(m)));
        }
        // (d)
        {
            HookCtl ctl;
            mn::CpuMiner m(light_opts(ctl));
            const mn::MinerJob J = make_job(0x18, 0x1801);
            ctl.fail_keyer_start = true;
            std::string w;
            const bool r = m.set_job(J, &w);
            const std::string d = m.describe();
            check(!r && has(w, "keyer thread start failed") && req_gen(m) == 0 && has(d, "cpu-miner: idle") &&
                      has(d, "key=none"),
                  "R-RETRY.d the keyer cannot start: false, nothing requested, idle", w + " | " + d);
            ctl.fail_keyer_start = false;
            const bool ok = m.set_job(J, &w) && wait_result(m) && m.install_ready();
            check(ok && m.running(), "R-RETRY.d the re-offer starts the keyer, keys and installs");
        }
    }

    check(g_waits > 0 && g_waits_late == 0,
          "R-F3 every wait_result_for returned true within a quarter of its bound",
          "waits=" + std::to_string(g_waits) + " late=" + std::to_string(g_waits_late) +
              " max=" + std::to_string(g_wait_max_s) + " s");
    std::printf("== %s ==\n", g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
