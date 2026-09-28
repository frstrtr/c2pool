// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_verify_pool_rx_kat -- DROPS-VERIFY-SCALE, the REAL RandomX half.
//
// The relay's verifier gives each verify worker its own light VM bound to the
// SHARED seed caches (O2RandomXVerifier::add_workers / randomx_hash_on): no
// 256 MiB cache is duplicated, a worker hash takes m_vm_mu SHARED, a slot swap
// takes it EXCLUSIVE and un-binds every worker VM.
//
//   A  identity: 8 workers hash 32 blobs each, concurrently; every hash equals
//      the listener VM's (single-VM) hash byte for byte.
//   B  seed switch under load: 8 workers hash continuously while the main
//      thread walks 4 epochs through ensure_seeds(e, e+1) (async next-seed
//      helper + adopt): every hash that returns equals a fresh single-verifier
//      reference of ITS seed; the workers re-bound after the swaps.
//   C  throughput (M1): 1 worker vs N = clamp(cores/2, 2, 8) workers for
//      RX_POOL_SECS (default 3) s each; aggregate hash/s, speedup and the RSS
//      cost per extra worker VM are printed. Gating only as "N workers are
//      faster than 1" (CI runners are small); the >= 3x verdict is printed.
//   D  lazy seed residency (D1): the daemon keys the relay verifier LAZILY
//      (no ensure_seeds). Walk 4 epochs E0..E3 through the WORKER path, then
//      alternate E2 (previous epoch, inside the horizon) / E3 (current):
//      0 re-keys, E2 + E3 resident, every hash == the reference. Worker hashes
//      never move LightVerifier's own MRU, so before the fix the 4th lazily
//      keyed seed evicted the current epoch and every alternating item re-keyed
//      Argon2d (~0.8 s each). Leg 2: the same with the last miss taken by the
//      listener lazy path (randomx_hash) after the workers hashed E2.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "c2pool/v37/xmr/xmr_o2_randomx_verify.hpp"

namespace o2 = c2pool::v37n::xmr::o2;
using Clock = std::chrono::steady_clock;

namespace {

int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
        std::fflush(stdout);                                   \
    } while (0)

o2::Seed32 seed_of(int e) {
    o2::Seed32 s{};
    for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(0x5A ^ (e * 41 + static_cast<int>(i) * 13));
    return s;
}
std::vector<std::uint8_t> blob_of(int e, int k) {
    std::vector<std::uint8_t> b(76);
    for (std::size_t i = 0; i < b.size(); ++i) b[i] = static_cast<std::uint8_t>(e * 29 + k * 7 + static_cast<int>(i) * 3);
    return b;
}
o2::RandomXPolicy policy(bool async_next) {
    o2::RandomXPolicy p;
    p.enabled = true;
    p.async_next_seed = async_next;
    return p;
}
bool ref_hash(const o2::Seed32& seed, const std::vector<std::uint8_t>& b, o2::Hash32& out) {
    o2::O2RandomXVerifier r;
    return r.init(policy(false)) && r.ensure_seeds(seed, std::nullopt) && r.randomx_hash(b.data(), b.size(), 0, seed, out);
}
long rss_kb() {
    long kb = 0;
    if (std::FILE* f = std::fopen("/proc/self/status", "r")) {
        char line[256];
        while (std::fgets(line, sizeof line, f)) if (std::sscanf(line, "VmRSS: %ld kB", &kb) == 1) break;
        std::fclose(f);
    }
    return kb;
}

void suite_identity() {
    std::printf("== A. 8 worker VMs on one shared cache == the single-VM hash ==\n");
    o2::O2RandomXVerifier v;
    CHECK(v.init(policy(false)) && v.ensure_seeds(seed_of(0), std::nullopt), "verifier init + seed keyed (%s)",
          o2::O2RandomXVerifier::to_string(v.mode()));
    const std::size_t nw = v.add_workers(8);
    CHECK(nw == 8 && v.workers() == 8, "add_workers(8) -> %zu worker VMs", nw);
    constexpr int kBlobs = 32;
    std::vector<o2::Hash32> ref(kBlobs);
    bool ref_ok = true;
    for (int k = 0; k < kBlobs; ++k) { const auto b = blob_of(0, k); ref_ok = v.randomx_hash(b.data(), b.size(), 0, seed_of(0), ref[k]) && ref_ok; }
    CHECK(ref_ok, "single-VM (listener) reference hashes of %d blobs", kBlobs);
    std::atomic<int> mism{0}, fails{0};
    std::vector<std::thread> th;
    for (std::size_t w = 0; w < nw; ++w)
        th.emplace_back([&, w] {
            for (int k = 0; k < kBlobs; ++k) {
                const int kk = (k + static_cast<int>(w) * 5) % kBlobs;   // different order per worker
                const auto b = blob_of(0, kk);
                o2::Hash32 h{};
                if (!v.randomx_hash_on(w, b.data(), b.size(), seed_of(0), h)) { fails.fetch_add(1); continue; }
                if (h != ref[kk]) mism.fetch_add(1);
            }
        });
    for (auto& t : th) t.join();
    CHECK(fails.load() == 0 && mism.load() == 0, "8 workers x %d concurrent hashes == reference (fails=%d mismatches=%d)",
          kBlobs, fails.load(), mism.load());
    o2::Hash32 h{};
    const auto b = blob_of(0, 3);
    CHECK(v.randomx_hash_on(99, b.data(), b.size(), seed_of(0), h) && h == ref[3],
          "an out-of-range worker index falls back to the listener VM (same hash)");
    std::printf("    %s\n", v.describe().c_str());
}

void suite_switch() {
    std::printf("== B. seed switches under 8 hashing workers ==\n");
    constexpr int kEpochs = 4, kBlobs = 4;
    std::map<std::pair<int, int>, o2::Hash32> ref;
    bool ref_ok = true;
    for (int e = 0; e < kEpochs; ++e)
        for (int k = 0; k < kBlobs; ++k) { o2::Hash32 h{}; ref_ok = ref_hash(seed_of(e), blob_of(e, k), h) && ref_ok; ref[{e, k}] = h; }
    CHECK(ref_ok, "fresh single-verifier references for %d epochs x %d blobs", kEpochs, kBlobs);
    o2::O2RandomXVerifier v;
    CHECK(v.init(policy(true)) && v.ensure_seeds(seed_of(0), seed_of(1)), "verifier init, epoch 0 keyed, next announced");
    const std::size_t nw = v.add_workers(8);
    std::atomic<int> epoch{0};
    std::atomic<bool> run{true};
    std::atomic<long> ok{0}, miss{0}, mism{0};
    std::vector<std::thread> th;
    for (std::size_t w = 0; w < nw; ++w)
        th.emplace_back([&, w] {
            int k = static_cast<int>(w) % kBlobs;
            while (run.load()) {
                const int e = epoch.load();
                const auto b = blob_of(e, k);
                o2::Hash32 h{};
                if (!v.randomx_hash_on(w, b.data(), b.size(), seed_of(e), h)) miss.fetch_add(1);
                else if (h != ref[{e, k}]) mism.fetch_add(1);
                else ok.fetch_add(1);
                k = (k + 1) % kBlobs;
            }
        });
    const auto binds0 = v.stats().worker_binds;
    for (int e = 1; e < kEpochs; ++e) {
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        const bool keyed = v.ensure_seeds(seed_of(e), e + 1 < kEpochs ? std::optional<o2::Seed32>(seed_of(e + 1)) : std::nullopt);
        epoch.store(e);
        CHECK(keyed, "switch to epoch %d while the workers hash (seed resident)", e);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    run.store(false);
    for (auto& t : th) t.join();
    const auto st = v.stats();
    CHECK(mism.load() == 0 && ok.load() > 0, "%ld worker hashes across %d switches, every one == the reference of its seed "
          "(mismatches=%ld, refused while not resident=%ld)", ok.load(), kEpochs - 1, mism.load(), miss.load());
    CHECK(st.worker_binds > binds0, "worker VMs re-bound after the swaps (binds %llu -> %llu, adopted=%llu)",
          (unsigned long long)binds0, (unsigned long long)st.worker_binds, (unsigned long long)st.next_adopted);
}

double rate(o2::O2RandomXVerifier& v, std::size_t n, double secs, long* rss_after) {
    std::atomic<bool> run{true};
    std::atomic<long> hashes{0};
    std::vector<std::thread> th;
    const auto t0 = Clock::now();
    for (std::size_t w = 0; w < n; ++w)
        th.emplace_back([&, w] {
            int k = 0;
            while (run.load()) {
                const auto b = blob_of(9, k++ + static_cast<int>(w) * 1000);
                o2::Hash32 h{};
                if (v.randomx_hash_on(w, b.data(), b.size(), seed_of(9), h)) hashes.fetch_add(1);
            }
        });
    std::this_thread::sleep_for(std::chrono::duration<double>(secs));
    if (rss_after) *rss_after = rss_kb();
    run.store(false);
    for (auto& t : th) t.join();
    return static_cast<double>(hashes.load()) / std::chrono::duration<double>(Clock::now() - t0).count();
}

void suite_throughput() {
    std::printf("== C. throughput: 1 worker vs N workers (M1) ==\n");
    const double secs = std::getenv("RX_POOL_SECS") ? std::atof(std::getenv("RX_POOL_SECS")) : 3.0;
    const unsigned hc = std::max(1u, std::thread::hardware_concurrency());
    std::size_t n = std::clamp<std::size_t>(hc / 2, 2, 8);
    if (const char* e = std::getenv("RX_POOL_N")) n = std::clamp<std::size_t>(std::strtoul(e, nullptr, 10), 1, 16);
    const long rss0 = rss_kb();
    o2::O2RandomXVerifier v;
    CHECK(v.init(policy(false)) && v.ensure_seeds(seed_of(9), std::nullopt), "verifier init + seed keyed");
    const long rss_cache = rss_kb();
    const std::size_t nw = v.add_workers(n);
    long rss1 = 0, rssn = 0;
    const double r1 = rate(v, 1, secs, &rss1);
    const double rn = rate(v, nw, secs, &rssn);
    const double sp = r1 > 0 ? rn / r1 : 0;
    const double per_vm = nw > 1 ? static_cast<double>(rssn - rss1) / 1024.0 / static_cast<double>(nw - 1) : 0;
    std::printf("    cores=%u workers=%zu: 1 worker %.1f hash/s (%.1f ms/hash) | %zu workers %.1f hash/s | speedup %.2fx %s\n",
                hc, nw, r1, r1 > 0 ? 1000.0 / r1 : 0.0, nw, rn, sp, sp >= 3.0 ? "(M1 >= 3x: MET)" : "(M1 >= 3x: not met here)");
    std::printf("    RSS: verifier (2 caches, 1 VM) +%.1f MiB | after 1 worker hashed %.1f MiB | after %zu workers hashed %.1f MiB "
                "=> +%.2f MiB per extra worker VM\n",
                (rss_cache - rss0) / 1024.0, rss1 / 1024.0, nw, rssn / 1024.0, per_vm);
    CHECK(nw == n, "add_workers(%zu) -> %zu", n, nw);
    CHECK(hc < 4 || sp > 1.2, "N workers out-hash one worker (%.2fx; gated only on >= 4 cores)", sp);
    CHECK(per_vm < 16.0, "an extra worker VM costs %.2f MiB RSS (< 16 MiB: no cache duplicated)", per_vm);
}

void lazy_leg(bool last_on_listener) {
    constexpr int kEpochs = 4, kAlt = 8;
    std::map<int, o2::Hash32> ref;
    bool ref_ok = true;
    for (int e = 0; e < kEpochs; ++e) { o2::Hash32 h{}; ref_ok = ref_hash(seed_of(e), blob_of(e, 0), h) && ref_ok; ref[e] = h; }
    o2::RandomXPolicy p = policy(true);
    p.lazy_prefetch_on_miss = true;   // the daemon's relay verifier: keyed only on a miss
    o2::O2RandomXVerifier v;
    const bool up = v.init(p);
    const std::size_t nw = up ? v.add_workers(2) : 0;
    CHECK(ref_ok && up && nw == 2, "lazy verifier up, no ensure_seeds, %zu worker VMs (%s)", nw,
          o2::O2RandomXVerifier::to_string(v.mode()));
    int mism = 0, fails = 0;
    auto hash = [&](int e, bool listener) {
        const auto b = blob_of(e, 0);
        o2::Hash32 h{};
        const bool ok = listener ? v.randomx_hash(b.data(), b.size(), 0, seed_of(e), h)
                                 : v.randomx_hash_on(0, b.data(), b.size(), seed_of(e), h);
        if (!ok) ++fails; else if (h != ref[e]) ++mism;
    };
    for (int e = 0; e < kEpochs; ++e) hash(e, last_on_listener && e == kEpochs - 1);
    const auto walk = v.stats().prefetches;
    const bool e2 = v.seed_resident(seed_of(2)), e3 = v.seed_resident(seed_of(3)), e1 = v.seed_resident(seed_of(1));
    CHECK(walk == kEpochs && e2 && e3 && !e1, "walk E0..E3: %llu lazy keys; resident E3=%d E2=%d E1=%d (0 = evicted)",
          (unsigned long long)walk, e3, e2, e1);
    const auto t0 = Clock::now();
    for (int i = 0; i < kAlt; ++i) hash(i % 2 ? 3 : 2, false);
    const double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count() / kAlt;
    const auto rekeys = v.stats().prefetches - walk;
    std::printf("    %d alternating E2/E3 worker items: %llu re-keys, %.1f ms/item\n", kAlt, (unsigned long long)rekeys, ms);
    CHECK(rekeys == 0 && v.seed_resident(seed_of(2)) && v.seed_resident(seed_of(3)),
          "alternating E2/E3: 0 re-keys (got %llu), E2 + E3 still resident", (unsigned long long)rekeys);
    CHECK(fails == 0 && mism == 0, "every hash == the reference of its seed (fails=%d mismatches=%d)", fails, mism);
}

void suite_lazy() {
    std::printf("== D. lazy keying: the workers' MRU seed stays resident (D1) ==\n");
    std::printf("  leg 1: every miss on the worker path\n");
    lazy_leg(false);
    std::printf("  leg 2: the 4th seed keyed by the listener lazy path\n");
    lazy_leg(true);
}

}  // namespace

int main() {
    std::printf("v37_xmr_verify_pool_rx_kat\n");
    suite_identity();
    suite_switch();
    suite_throughput();
    suite_lazy();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
