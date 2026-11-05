// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xmr_fast_mode_kat.cpp — --mine-fast (RANDOMX_FLAG_FULL_MEM + the ~2080 MiB
// dataset) produces the SAME hashes as the light path it replaces.
//
// WHY A SEPARATE TARGET. xmr_cpu_miner_kat covers the LIGHT miner and is cheap:
// one 256 MiB Argon2d cache. FAST mode is a different animal — it allocates a
// ~2080 MiB dataset and spends seconds initialising it — so it gets its own
// target, which a memory-starved host can leave out of a run without taking the
// light coverage with it.
//
// THE CLAIM UNDER TEST: fast mode is an OPTIMISATION, not a second algorithm.
//
//   F1  FIXED-INPUT PARITY at the VM level: one cache keyed with a fixed seed;
//       a LIGHT VM (cache, no FULL_MEM) and a FULL_MEM VM (dataset built from
//       that same cache) hash the same fixed blob, and the two 32-byte results
//       are BIT-IDENTICAL. Repeated over several fixed blobs, because a single
//       agreeing pair could be luck in a way a handful cannot;
//   F2  THE PRODUCTION PATH: a CpuMiner constructed with fast_mode = true
//       (i.e. exactly what --mine-fast builds, dataset split across threads and
//       all) mines at an easy lane target, and EVERY hash it reports is
//       reproduced byte-for-byte by the production LightVerifier over the same
//       blob with the reported nonce patched in. So the FULL_MEM VM the node
//       would ship is correct, not merely fast;
//   F3  informational: dataset init seconds and steady-state H/s for the fast
//       miner, printed for the record. Not asserted — a shared CI runner's
//       hashrate is not a property of this code;
//   V-f a verifier cache key on another thread completes while the miner's
//       real dataset build runs;
//   V-g the dataset parity check passes on a correct build;
//   V-c, V-d, V-k, R-DV3  a newer seed, stop(), the destructor and a build
//       thread that fails to start, each during a real dataset build: the
//       build is abandoned or failed promptly and every thread is joined.
//
// HONEST SKIP. If randomx_alloc_dataset() returns null (a host that cannot
// spare ~2 GiB) the fast half reports SKIP and the test still exits 0 — but it
// says so in as many words, and F1's light half has already run. A skip that
// hides is worse than no test; a skip that announces itself is a fact.
//
// PROVENANCE: original c2pool code over the PUBLIC librandomx C API (BSD-3,
// vendored tevador/RandomX). No xmrig, no p2pool, no monerod source.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <dirent.h>
#endif

#include "randomx.h"
#include "randomx_verify.hpp"
#include "xmr_cpu_miner.hpp"

namespace mn = c2pool::xmr::miner;

static int g_fail = 0;
static double g_full_build_s = 0.0;   // F2's build, set_job to install
static void check(bool ok, const char* name, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : " — ", detail.c_str());
    if (!ok) ++g_fail;
}

static std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xF]; }
    return s;
}

static std::uint64_t target_from_diff(std::uint64_t d) {
    return d ? (0xFFFFFFFFFFFFFFFFULL / d) : 0xFFFFFFFFFFFFFFFFULL;
}

static constexpr std::size_t kNonceOffset = 39;

static std::vector<std::uint8_t> make_blob(std::uint8_t tag) {
    std::vector<std::uint8_t> b(76, 0);
    for (std::size_t i = 0; i < b.size(); ++i)
        b[i] = static_cast<std::uint8_t>(0x10 + (i * 7 + tag * 31) % 0xE0);
    b[0] = 16;
    b[1] = 16;
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

// A failure bound on a fast-mode build (the dataset build dominates).
static const std::chrono::seconds kBuildWait{1200};

// Signals at the miner's test points, and an injected failure at
// BuildThreadStart(i). Every point reached is recorded with its time.
using TP = mn::TestPoint;
struct Signals {
    struct Mark { TP p; std::uint64_t gen; unsigned idx; std::chrono::steady_clock::time_point t; };
    std::mutex              mu;
    std::condition_variable cv;
    std::vector<Mark>       marks;
    std::atomic<int>        fail_build_start{-1};

    mn::TestHook hook() {
        return [this](TP p, std::uint64_t g, unsigned i, const std::function<bool()>&) {
            if (p == TP::BuildThreadStart && fail_build_start.load() == static_cast<int>(i))
                throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                        "injected");
            std::lock_guard<std::mutex> lk(mu);
            marks.push_back({p, g, i, std::chrono::steady_clock::now()});
            cv.notify_all();
        };
    }
    bool wait(TP p, std::uint64_t gen, std::chrono::seconds bound,
              std::chrono::steady_clock::time_point* at = nullptr) {
        std::unique_lock<std::mutex> lk(mu);
        const bool ok = cv.wait_for(lk, bound, [&] { return find(p, gen) != nullptr; });
        if (ok && at) *at = find(p, gen)->t;
        return ok;
    }
    bool reached(TP p, std::uint64_t gen) {
        std::lock_guard<std::mutex> lk(mu);
        return find(p, gen) != nullptr;
    }

private:
    const Mark* find(TP p, std::uint64_t gen) const {
        for (const Mark& m : marks)
            if (m.p == p && (gen == 0 || m.gen == gen)) return &m;
        return nullptr;
    }
};

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
static double secs_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}
static bool any_has(const std::vector<std::string>& v, const char* sub) {
    for (const std::string& s : v) if (s.find(sub) != std::string::npos) return true;
    return false;
}
// key_items=<done>/<total> from the miner's status line.
static bool key_items(const std::string& d, unsigned long long& done, unsigned long long& total) {
    const std::size_t at = d.find("key_items=");
    return at != std::string::npos && std::sscanf(d.c_str() + at, "key_items=%llu/%llu", &done, &total) == 2;
}

// Build the dataset over `threads` disjoint item ranges, the same split the
// miner's dataset build does. Returns seconds spent.
static double init_dataset_parallel(randomx_dataset* ds, randomx_cache* cache,
                                    unsigned threads) {
    const auto t0 = std::chrono::steady_clock::now();
    const unsigned long items = randomx_dataset_item_count();
    const unsigned n = std::max(1u, threads);
    const unsigned long per = items / n;
    std::vector<std::thread> tt;
    tt.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        const unsigned long start = per * i;
        const unsigned long count = (i + 1 == n) ? (items - start) : per;
        tt.emplace_back([ds, cache, start, count] {
            randomx_init_dataset(ds, cache, start, count);
        });
    }
    for (auto& t : tt) t.join();
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

// ---------------------------------------------------------------------------
int main() {
    std::printf("== xmr_fast_mode_kat: --mine-fast is an optimisation, not a second "
                "algorithm ==\n");
    measure_base_tasks();

    const unsigned hc = std::max(1u, std::thread::hardware_concurrency());
    const unsigned init_threads = std::min(4u, hc);
    std::printf("       hardware_concurrency=%u dataset_items=%lu init_threads=%u\n",
                hc, randomx_dataset_item_count(), init_threads);

    const mn::SeedBytes seed = make_seed(0x5A);

    // ---- F1: fixed-input parity at the VM level -----------------------------
    bool have_dataset = false;
    {
        randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_JIT;

        randomx_cache* cache = randomx_alloc_cache(flags);
        if (!cache) {
            std::printf("  [FAIL] F1 randomx_alloc_cache failed (256 MiB)\n");
            return 1;
        }
        randomx_init_cache(cache, seed.data(), seed.size());

        randomx_vm* light = randomx_create_vm(flags, cache, nullptr);
        if (!light) {
            std::printf("  [FAIL] F1 randomx_create_vm (light) failed\n");
            randomx_release_cache(cache);
            return 1;
        }

        // Light reference hashes first, so a dataset that cannot be allocated
        // costs us the comparison but not the run.
        std::vector<std::array<std::uint8_t, 32>> light_out;
        for (std::uint8_t tag = 0; tag < 4; ++tag) {
            const std::vector<std::uint8_t> blob = make_blob(tag);
            std::array<std::uint8_t, 32> h{};
            randomx_calculate_hash(light, blob.data(), blob.size(), h.data());
            light_out.push_back(h);
        }
        check(light_out.size() == 4, "F1.a light VM hashed the four fixed blobs",
              "first=" + hex(light_out[0].data(), 8) + "...");

        randomx_dataset* ds = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
        if (!ds) {
            std::printf("  [SKIP] F1.b/F2/F3 — randomx_alloc_dataset returned null: this "
                        "host cannot spare the ~2080 MiB --mine-fast needs. The FAST path "
                        "was NOT exercised on this run.\n");
        } else {
            have_dataset = true;
            const double init_s = init_dataset_parallel(ds, cache, init_threads);
            std::printf("       dataset init: %.2f s on %u threads\n", init_s, init_threads);

            randomx_vm* fast = randomx_create_vm(flags | RANDOMX_FLAG_FULL_MEM,
                                                nullptr, ds);
            if (!fast) {
                check(false, "F1.b randomx_create_vm (FULL_MEM) failed");
            } else {
                bool all_equal = true;
                std::string mismatch;
                for (std::uint8_t tag = 0; tag < 4; ++tag) {
                    const std::vector<std::uint8_t> blob = make_blob(tag);
                    std::array<std::uint8_t, 32> h{};
                    randomx_calculate_hash(fast, blob.data(), blob.size(), h.data());
                    if (h != light_out[tag]) {
                        all_equal = false;
                        mismatch = "blob " + std::to_string(tag) + ": light=" +
                                   hex(light_out[tag].data(), 32) + " fast=" +
                                   hex(h.data(), 32);
                        break;
                    }
                }
                check(all_equal,
                      "F1.b FULL_MEM VM hash == light VM hash, bit for bit, on 4 fixed blobs",
                      all_equal ? ("e.g. " + hex(light_out[0].data(), 16) + "...") : mismatch);
                randomx_destroy_vm(fast);
            }
            randomx_release_dataset(ds);
        }
        randomx_destroy_vm(light);
        randomx_release_cache(cache);
    }

    if (!have_dataset) {
        std::printf("== xmr_fast_mode_kat: %s (%d failure%s; FAST half SKIPPED for want of "
                    "memory) ==\n", g_fail ? "FAIL" : "PASS", g_fail,
                    g_fail == 1 ? "" : "s");
        return g_fail ? 1 : 0;
    }

    // ---- F2 / F3: the production miner in fast mode --------------------------
    // ONE dataset at a time: F1's is already released above, and this miner is
    // destroyed before the function returns.
    {
        c2pool::xmr::VerifierOptions vo;
        vo.large_pages = false;
        c2pool::xmr::LightVerifier verifier;
        if (!verifier.init(vo)) {
            check(false, "F2 LightVerifier init failed (out of memory?)");
        } else {
            const c2pool::xmr::SeedHash vseed = to_vseed(seed);
            verifier.prefetch_epoch(vseed, std::nullopt);

            mn::MinerOptions mo;
            mo.threads     = std::min(2u, hc);
            mo.fast_mode   = true;      // <-- exactly what --mine-fast sets
            mo.large_pages = true;      // graceful fallback to 4 KiB
            mo.pin_threads = true;
            Signals sig;
            mo.test_hook   = sig.hook();

            // V-f's reference: a fixed blob hashed on a cache keyed to another
            // seed, before the miner's build.
            const mn::SeedBytes other = make_seed(0x6B);
            const c2pool::xmr::SeedHash vother = to_vseed(other);
            const std::vector<std::uint8_t> vf_blob = make_blob(9);
            std::array<std::uint8_t, 32> vf_ref{};
            bool vf_ref_ok = false;
            {
                c2pool::xmr::CacheSlot ref(randomx_get_flags() | RANDOMX_FLAG_JIT);
                if (ref.rekey(vother)) {
                    randomx_vm* vm = randomx_create_vm(randomx_get_flags() | RANDOMX_FLAG_JIT, ref.raw(), nullptr);
                    if (vm) {
                        randomx_calculate_hash(vm, vf_blob.data(), vf_blob.size(), vf_ref.data());
                        randomx_destroy_vm(vm);
                        vf_ref_ok = true;
                    }
                }
            }

            mn::MinerJob job;
            job.blob           = make_blob(0);
            job.nonce_offset   = kNonceOffset;
            job.template_id    = 7;
            job.extra_nonce    = 3;
            job.height         = 123456;
            job.seed_hash      = seed;
            job.network_target = 0;                       // no block hits wanted here
            job.lane_target    = target_from_diff(256);   // easy: hits flow

            mn::CpuMiner miner(mo);
            std::string why;
            const auto t0 = std::chrono::steady_clock::now();
            const bool posted = miner.set_job(job, &why);

            // V-f: while the build runs, this thread keys a CacheSlot to
            // another seed; the key returns before the dataset build ends.
            {
                const bool building = posted && sig.wait(TP::BuildThreadStart, 0, kBuildWait);
                c2pool::xmr::CacheSlot slot(randomx_get_flags() | RANDOMX_FLAG_JIT);
                const auto k0 = std::chrono::steady_clock::now();
                const bool keyed = building && slot.rekey(vother);
                const double argon_s = secs_since(k0);
                unsigned long long done = 0, total = 0;
                const bool items = key_items(miner.describe(), done, total);
                std::array<std::uint8_t, 32> h{};
                bool same = false;
                if (keyed) {
                    randomx_vm* vm = randomx_create_vm(randomx_get_flags() | RANDOMX_FLAG_JIT, slot.raw(), nullptr);
                    if (vm) {
                        randomx_calculate_hash(vm, vf_blob.data(), vf_blob.size(), h.data());
                        randomx_destroy_vm(vm);
                        same = vf_ref_ok && h == vf_ref;
                    }
                }
                std::printf("       V-f: verifier cache key %.2f s; dataset items done %llu/%llu when it returned\n",
                            argon_s, done, total);
                check(keyed && items && total > 0 && done * 2 < total,
                      "V-f.1 a verifier cache key returns while the dataset build is under half done",
                      std::to_string(done) + "/" + std::to_string(total));
                check(same, "V-f.2 that key's hash of a fixed blob equals the reference");
            }

            const bool started = posted && miner.wait_result_for(kBuildWait) && miner.install_ready();
            const double init_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            check(started, "F2.a CpuMiner(fast_mode=true): set_job, the build, install_ready", why);
            if (started) g_full_build_s = init_s;
            const std::vector<std::string> ev = miner.take_events();
            check(started && !any_has(ev, "dataset parity") && miner.describe().find("key=ready") != std::string::npos,
                  "V-g the dataset parity check passed (key=ready)");

            if (started) {
                std::printf("       fast miner: threads=%u init=%.2f s %s\n",
                            miner.threads_wanted(), init_s,
                            miner.large_pages_note().c_str());
                check(miner.fast_mode(), "F2.b the miner reports fast mode");

                // Let it run long enough to produce a handful of hits.
                std::size_t verified = 0, mismatched = 0, seen = 0;
                const auto deadline =
                    std::chrono::steady_clock::now() + std::chrono::seconds(20);
                mn::MinerHit hit;
                while (std::chrono::steady_clock::now() < deadline && verified < 8) {
                    if (!miner.pop_hit(hit)) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        continue;
                    }
                    ++seen;
                    std::vector<std::uint8_t> blob = job.blob;
                    for (std::size_t i = 0; i < mn::kNonceSize; ++i)
                        blob[kNonceOffset + i] =
                            static_cast<std::uint8_t>(hit.nonce >> (8 * i));
                    std::uint8_t ref[32] = {0};
                    if (!verifier.hash(blob.data(), blob.size(), vseed, ref)) continue;
                    if (std::memcmp(ref, hit.pow_hash.data(), 32) == 0) ++verified;
                    else ++mismatched;
                }
                const mn::MinerStats st = miner.stats();
                std::printf("       %s\n", miner.describe().c_str());
                check(seen > 0, "F2.c the fast miner produced hits at diff 256",
                      "hits=" + std::to_string(seen) +
                          " hashes=" + std::to_string(st.hashes));
                check(mismatched == 0 && verified > 0,
                      "F2.d EVERY fast-mode hash re-computes byte-identically in the "
                      "production LightVerifier",
                      "verified=" + std::to_string(verified) +
                          " mismatched=" + std::to_string(mismatched));

                // F3 is informational only.
                const double hps = st.hashrate;
                std::printf("       F3 (informational) fast mode: %.1f H/s over %u thread(s) "
                            "= %.1f H/s/thread; dataset init %.2f s. A shared runner's "
                            "hashrate is not a property of this code, so nothing here is "
                            "asserted.\n",
                            hps, st.threads,
                            st.threads ? hps / st.threads : 0.0, init_s);
            }
            miner.stop();
        }
    }

    // ---- V-c, V-d, V-k, R-DV3 (b): during a real dataset build --------------
    // One dataset at a time: each miner below is destroyed before the next.
    // A full build's seconds (F2's) bound the prompt cases: each must end in
    // under a quarter of it.
    {
        const unsigned threads = std::min(2u, hc);
        auto fast_opts = [&](Signals& sig) {
            mn::MinerOptions mo;
            mo.threads     = threads;
            mo.fast_mode   = true;
            mo.large_pages = false;
            mo.pin_threads = false;
            mo.test_hook   = sig.hook();
            return mo;
        };
        auto fast_job = [&](std::uint8_t seed_tag, std::uint32_t tid) {
            mn::MinerJob j;
            j.blob           = make_blob(static_cast<std::uint8_t>(tid & 0xFF));
            j.nonce_offset   = kNonceOffset;
            j.template_id    = tid;
            j.extra_nonce    = 5;
            j.height         = 123457;
            j.seed_hash      = make_seed(seed_tag);
            j.network_target = 0;
            j.lane_target    = target_from_diff(256);
            return j;
        };
        // F2's whole build (set_job to install) on the same thread count.
        const double full_s = g_full_build_s > 0 ? g_full_build_s : 0.0;
        std::printf("       a full build here took %.2f s (F2)\n", full_s);

        // V-c: a newer seed during SA's real build is consumed promptly.
        {
            Signals sig;
            mn::CpuMiner m(fast_opts(sig));
            std::string why;
            const bool pa = m.set_job(fast_job(0x31, 31), &why);
            const bool building = pa && sig.wait(TP::BuildThreadStart, 0, kBuildWait);
            const auto t0 = std::chrono::steady_clock::now();
            const bool pb = m.set_job(fast_job(0x32, 32), &why);
            const std::uint64_t gB = m.build_progress().request_gen;
            std::chrono::steady_clock::time_point at{};
            const bool consumed = pb && sig.wait(TP::AfterConsume, gB, kBuildWait, &at);
            const double dt = consumed ? std::chrono::duration<double>(at - t0).count() : -1.0;
            const mn::CpuMiner::BuildProgress bp = m.build_progress();
            std::printf("       V-c: gB consumed %.2f s after the post\n", dt);
            check(building && consumed && full_s > 0 && dt < full_s / 4 && bp.abandoned == 1,
                  "V-c (fast) a newer seed during the real build is consumed in under a quarter build",
                  "abandoned=" + std::to_string(bp.abandoned));
        }

        // V-d: stop() during the real dataset build returns promptly.
        {
            const int base = g_base_tasks;
            Signals sig;
            mn::CpuMiner m(fast_opts(sig));
            std::string why;
            const bool pa = m.set_job(fast_job(0x41, 41), &why);
            const bool building = pa && sig.wait(TP::BuildThreadStart, 0, kBuildWait);
            const auto t0 = std::chrono::steady_clock::now();
            m.stop();
            const double dt = secs_since(t0);
            std::printf("       V-d: stop() during the build took %.2f s\n", dt);
            check(building && full_s > 0 && dt < full_s / 4 && tasks_settle_to(base),
                  "V-d (fast) stop() during the real build returns in under a quarter build; no thread remains");
        }

        // V-k: the destructor during the real build, without stop().
        {
            const int base = g_base_tasks;
            Signals sig;
            double dt = -1.0;
            bool building = false;
            {
                auto m = std::make_unique<mn::CpuMiner>(fast_opts(sig));
                std::string why;
                building = m->set_job(fast_job(0x61, 61), &why) && sig.wait(TP::BuildThreadStart, 0, kBuildWait);
                const auto t0 = std::chrono::steady_clock::now();
                m.reset();
                dt = secs_since(t0);
            }
            std::printf("       V-k: destruction during the build took %.2f s\n", dt);
            check(building && full_s > 0 && dt < full_s / 4 && tasks_settle_to(base),
                  "V-k (fast) the destructor during the real build returns promptly; no thread remains");
        }

        // R-DV3 (b): build thread 1 fails to start.
        {
            const int base = g_base_tasks;
            Signals sig;
            mn::CpuMiner m(fast_opts(sig));
            const mn::MinerJob A = fast_job(0x71, 71), A2 = fast_job(0x71, 72);
            std::string why;
            sig.fail_build_start = threads > 1 ? 1 : 0;
            const bool pa = m.set_job(A, &why);
            const bool wr = pa && m.wait_result_for(kBuildWait);
            const bool ir = m.install_ready();
            const std::vector<std::string> ev = m.take_events();
            const bool with_k = tasks_settle_to(base < 0 ? -1 : base + 1);
            check(wr && !ir && any_has(ev, "key failed") && any_has(ev, "injected") && with_k,
                  "R-DV3.b a build thread that fails to start: Failed(injected), every build thread joined");
            sig.fail_build_start = -1;
            std::string w2;
            const bool retry = m.set_job(A2, &w2);
            const bool reoffer = m.set_job(A2, &w2);
            const bool in = m.wait_result_for(kBuildWait) && m.install_ready();
            check(!retry && w2.find("injected") != std::string::npos && reoffer && in && m.running(),
                  "R-DV3.b the retry (false), the re-offer (true), then the build installs", w2);
        }
    }

    std::printf("== xmr_fast_mode_kat: %s (%d failure%s) ==\n",
                g_fail ? "FAIL" : "PASS", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
