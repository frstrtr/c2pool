// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_rx_seed_race_kat -- SEED-RACE + NEXT-REORG (#1814 review)
//
// serve_and_run calls O2RandomXVerifier::on_template from the listener's
// template hook AND from pump_miner on the main thread, on ONE verifier; the
// NEXT-SEED helper state (the std::future, m_next_building) and the light VM
// (adopt / hash) were touched unlocked from both (a reviewer's two-thread
// harness: 3/3 segfaults, TSan heap-use-after-free in the future's state).
//   R  two threads, per epoch e = 0..N-1 (in step): ensure_seeds(e, e+1)
//      concurrently with randomx_hash(e) on the other thread; every call
//      keys `e`, every hash equals a single-threaded reference. Build this TU
//      with -fsanitize=thread for the TSan leg (RandomX itself may stay
//      Release): 0 reports on the fix.
//   G  NEXT-REORG: the announced next seed block is reorged while the helper
//      keys it. The next ensure_seeds (a different next) must NOT wait for
//      the rest of the stale build (it returns in << one cache build), the
//      new next is adopted, the orphan seed's cache is NEVER installed, and
//      the switch to the new seed keys nothing and hashes == reference.
// RED on 518066af (#1814): R crashes / TSan reports; G blocks ~one build and
// installs the orphan. GREEN on the fix. HEAVY: real RandomX light caches.
// ===========================================================================
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
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

o2::Seed32 seed_of(int e, std::uint8_t salt = 0) {
    o2::Seed32 s{};
    for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(0xC2 ^ (e * 37 + static_cast<int>(i) * 11 + salt * 101));
    return s;
}
std::vector<std::uint8_t> blob_of(int e, int k) {
    std::vector<std::uint8_t> b(76);
    for (std::size_t i = 0; i < b.size(); ++i) b[i] = static_cast<std::uint8_t>(e * 13 + k * 7 + static_cast<int>(i));
    return b;
}
std::string hx(const o2::Hash32& h) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (int i = 0; i < 8; ++i) { s += d[h[i] >> 4]; s += d[h[i] & 15]; }
    return s;
}
template <class S> std::uint64_t discarded_of(const S& s) {
    if constexpr (requires { s.next_discarded; }) return s.next_discarded; else return 0;
}
long long ms_since(Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count();
}
o2::RandomXPolicy policy() {
    o2::RandomXPolicy p;
    p.enabled = true;
    p.async_next_seed = true;
    return p;
}
// Reference: a fresh single-threaded verifier keyed with `seed` alone.
bool ref_hash(const o2::Seed32& seed, const std::vector<std::uint8_t>& b, o2::Hash32& out) {
    o2::O2RandomXVerifier r;
    o2::RandomXPolicy p = policy(); p.async_next_seed = false;
    return r.init(p) && r.ensure_seeds(seed, std::nullopt) && r.randomx_hash(b.data(), b.size(), 0, seed, out);
}

// A two-party step barrier (C++20 <barrier> kept out for older libstdc++).
struct Step {
    std::mutex mu; std::condition_variable cv; int n = 0, gen = 0;
    void arrive() {
        std::unique_lock<std::mutex> lk(mu);
        const int g = gen;
        if (++n == 2) { n = 0; ++gen; cv.notify_all(); return; }
        cv.wait(lk, [&] { return gen != g; });
    }
};

void suite_race(int epochs) {
    std::printf("== R. SEED-RACE: two threads, ensure_seeds(e, e+1) + randomx_hash(e), e = 0..%d ==\n", epochs - 1);
    o2::O2RandomXVerifier v;
    CHECK(v.init(policy()), "verifier init (%s)", o2::O2RandomXVerifier::to_string(v.mode()));
    if (!v.ready()) return;
    Step step;
    std::atomic<int> not_keyed{0}, hash_fail{0};
    std::vector<std::vector<o2::Hash32>> got(2, std::vector<o2::Hash32>(static_cast<std::size_t>(epochs)));
    const auto t0 = Clock::now();
    auto worker = [&](int t) {
        for (int e = 0; e < epochs; ++e) {
            step.arrive();                                   // both threads on epoch e
            if (!v.ensure_seeds(seed_of(e), seed_of(e + 1))) not_keyed.fetch_add(1);
            const auto b = blob_of(e, t);
            o2::Hash32 h{};
            bool ok = false;
            for (int k = 0; k < 4; ++k) ok = v.randomx_hash(b.data(), b.size(), 0, seed_of(e), h) || ok;   // hash while the other keys
            if (!ok) hash_fail.fetch_add(1);
            got[static_cast<std::size_t>(t)][static_cast<std::size_t>(e)] = h;
            (void)v.ensure_seeds(seed_of(e), seed_of(e + 1));   // adopt / re-check under contention
        }
    };
    std::thread a(worker, 0), b(worker, 1);
    a.join(); b.join();
    const auto st = v.stats();
    std::printf("    %d epochs in %lld ms | %s\n", epochs, ms_since(t0), v.describe().c_str());
    CHECK(not_keyed.load() == 0, "every ensure_seeds(e, e+1) left e resident (%d misses)", not_keyed.load());
    CHECK(hash_fail.load() == 0, "every thread hashed on its epoch (%d failures)", hash_fail.load());
    int mism = 0;
    for (int e = 0; e < epochs; ++e)
        for (int t = 0; t < 2; ++t) {
            o2::Hash32 r{};
            const auto b = blob_of(e, t);
            if (!ref_hash(seed_of(e), b, r) || r != got[static_cast<std::size_t>(t)][static_cast<std::size_t>(e)]) {
                ++mism;
                std::printf("    MISMATCH e=%d t=%d got=%s ref=%s\n", e, t, hx(got[static_cast<std::size_t>(t)][static_cast<std::size_t>(e)]).c_str(), hx(r).c_str());
            }
        }
    CHECK(mism == 0, "all %d concurrent hashes equal a single-threaded fresh-cache reference", 2 * epochs);
    CHECK(st.next_async >= static_cast<std::uint64_t>(epochs - 1), "the announced next epochs were keyed on the helper (next_async=%llu)",
          (unsigned long long)st.next_async);
}

void suite_reorg() {
    std::printf("== G. NEXT-REORG: the announced next seed block is reorged mid-build ==\n");
    const o2::Seed32 S0 = seed_of(100), S1 = seed_of(101), S1r = seed_of(101, 7), S2 = seed_of(102, 7);
    long long build_ms = 0;
    {
        o2::RandomXPolicy p = policy();
        o2::O2RandomXVerifier t;
        if (t.init(p)) {
            const auto t0 = Clock::now();
            (void)t.ensure_seeds(seed_of(99), std::nullopt);   // one synchronous cache build, timed
            build_ms = ms_since(t0);
        }
    }
    std::printf("    one light-cache build here: %lld ms\n", build_ms);
    o2::O2RandomXVerifier v;
    CHECK(v.init(policy()), "verifier init");
    if (!v.ready()) return;
    CHECK(v.ensure_seeds(S0, S1), "template 1: seed S0 keyed, next S1 announced (helper builds it)");
    const auto p0 = v.stats().prefetches;
    const auto t0 = Clock::now();
    const bool r2 = v.ensure_seeds(S0, S1r);    // the S1 block was reorged: the next is S1'
    const long long d = ms_since(t0);
    const bool orphan_now = v.seed_resident(S1);
    std::printf("    ensure_seeds(S0, S1') right after (S1 build in flight) took %lld ms\n", d);
    CHECK(r2 && d * 4 < build_ms, "a changed next does NOT wait for the stale build (%lld ms << one build %lld ms)", d, build_ms);
    CHECK(!orphan_now, "the changed-next call does not install the orphan seed S1's cache (S1 resident right after: %d)", orphan_now ? 1 : 0);
    const bool got_new = [&] {
        const auto dl = Clock::now() + std::chrono::seconds(120);
        while (Clock::now() < dl) {
            (void)v.ensure_seeds(S0, S1r);
            if (v.seed_resident(S1r)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return false;
    }();
    CHECK(got_new, "the new next S1' is keyed off the listener and adopted");
    std::this_thread::sleep_for(std::chrono::milliseconds(build_ms + 500));   // the stale S1 build has finished by now
    for (int i = 0; i < 3; ++i) (void)v.ensure_seeds(S0, S1r);
    CHECK(!v.seed_resident(S1) && v.seed_resident(S0) && v.seed_resident(S1r),
          "the orphan seed S1's cache is never installed (resident: S0 %d, S1' %d, S1 %d)", v.seed_resident(S0) ? 1 : 0,
          v.seed_resident(S1r) ? 1 : 0, v.seed_resident(S1) ? 1 : 0);
    CHECK(discarded_of(v.stats()) >= 1, "the stale build is counted as discarded (next_discarded=%llu)", (unsigned long long)discarded_of(v.stats()));
    const auto t1 = Clock::now();
    const bool sw = v.ensure_seeds(S1r, S2);
    const long long dsw = ms_since(t1);
    const auto b = blob_of(101, 0);
    o2::Hash32 h{}, r{};
    const bool hok = v.randomx_hash(b.data(), b.size(), 0, S1r, h);
    CHECK(sw && hok && ref_hash(S1r, b, r) && h == r && v.stats().prefetches == p0,
          "the switch to S1' keys nothing synchronously (%lld ms, prefetches %llu -> %llu) and hashes == reference (%s)", dsw,
          (unsigned long long)p0, (unsigned long long)v.stats().prefetches, hx(h).c_str());
    std::printf("    %s\n", v.describe().c_str());
}

}  // namespace

int main(int argc, char** argv) {
    const std::string only = argc > 1 ? argv[1] : "";
    const int epochs = std::getenv("RACE_EPOCHS") ? std::atoi(std::getenv("RACE_EPOCHS")) : 7;
    std::printf("v37_xmr_rx_seed_race_kat%s\n", only.empty() ? "" : (" (" + only + ")").c_str());
    if (only.empty() || only == "race") suite_race(epochs);
    if (only.empty() || only == "reorg") suite_reorg();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
