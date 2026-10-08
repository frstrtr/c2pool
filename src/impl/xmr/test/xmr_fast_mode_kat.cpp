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
//       hashrate is not a property of this code.
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
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "randomx.h"
#include "randomx_verify.hpp"
#include "xmr_cpu_miner.hpp"

namespace mn = c2pool::xmr::miner;

static int g_fail = 0;
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

// Build the dataset over `threads` disjoint item ranges, the same split the
// miner's init_dataset_parallel() does. Returns seconds spent.
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
            const bool started = miner.set_job(job, &why);
            const double init_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            check(started, "F2.a CpuMiner(fast_mode=true).set_job() succeeded", why);

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

    std::printf("== xmr_fast_mode_kat: %s (%d failure%s) ==\n",
                g_fail ? "FAIL" : "PASS", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
