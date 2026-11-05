// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// xmr_wire_dos_check -- the RandomX DoS budget (impl/xmr/wire/xmr_carrier_dos_budget.hpp); no RandomX, no network:
//   T3  the per-peer token bucket grants its capacity then denies (deferred counted); refill; the global backstop
//       caps the aggregate across peers
//   T4  budget actions: a valid PoW refunds the tokens; a confirmed invalid PoW bans (one at the default policy) and
//       a banned peer gets no grant; an unconfirmed miss (re-verify disagrees: confirm_invalid false) drops without a
//       ban; a budget-starved peer is deferred with no penalty; cheap rejects ban only past the threshold
//   T5  the arithmetic the budget is sized to (~65 bogus evaluations/s saturate one light core)
//   T6  release: a source holding nothing is dropped, one with a spent bucket or a score is kept (at most retain_max)
//   T7  a flood of 2,000 grant requests from one peer inside one second gets the bucket's allowance only (capacity
//       plus at most one second of refill), the rest deferred with no penalty
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"

namespace cx = c2pool::xmr;

static int g_checks = 0;
#define CHECK(cond, msg) do { ++g_checks; if (!(cond)) { std::printf("FAIL: %s\n", msg); std::abort(); } } while (0)

static void t3_token_bucket() {
    cx::DosPolicy p;
    p.per_peer_capacity = 3; p.per_peer_refill = 0;
    p.global_capacity = 1000; p.global_refill = 0;
    cx::CarrierDosBudget dos(p);
    cx::nanos_t t = 1'000'000'000;
    int grants = 0;
    for (int i = 0; i < 10; ++i) if (dos.grant_randomx(42, t)) ++grants;
    CHECK(grants == 3, "T3 per-peer bucket grants exactly capacity then denies");
    CHECK(dos.state(42).deferred == 7, "T3 denied grants counted as deferred");

    p = cx::DosPolicy{}; p.per_peer_capacity = 2; p.per_peer_refill = 1;
    cx::CarrierDosBudget dos2(p);
    cx::nanos_t t0 = 5'000'000'000;
    CHECK(dos2.grant_randomx(1, t0), "T3 grant 1");
    CHECK(dos2.grant_randomx(1, t0), "T3 grant 2 (burst)");
    CHECK(!dos2.grant_randomx(1, t0), "T3 grant 3 denied at empty bucket");
    CHECK(dos2.grant_randomx(1, t0 + 2'000'000'000LL), "T3 grant recovers after 2 s refill");

    p = cx::DosPolicy{}; p.per_peer_capacity = 100; p.per_peer_refill = 100;
    p.global_capacity = 4; p.global_refill = 0;
    cx::CarrierDosBudget dos3(p);
    int gg = 0;
    for (int peer = 0; peer < 20; ++peer) if (dos3.grant_randomx(peer, t0)) ++gg;
    CHECK(gg == 4, "T3 global backstop caps aggregate grants across peers");
    std::printf("T3 token bucket OK (per-peer cap/refill, global backstop)\n");
}

static void t4_actions() {
    const cx::nanos_t t = 9'000'000'000;
    {   // valid PoW -> tokens refunded
        cx::CarrierDosBudget dos;
        const double before = dos.global_level(t);
        CHECK(dos.grant_randomx(11, t), "T4a a grant");
        dos.on_valid_pow(11, t);
        CHECK(!dos.banned(11), "T4a valid peer not banned");
        CHECK(std::fabs(dos.global_level(t) - before) < 1e-6, "T4a token refunded on valid PoW");
        CHECK(dos.state(11).granted == 1, "T4a one RandomX grant recorded");
    }
    {   // confirmed invalid -> ban; a banned peer gets no grant
        cx::CarrierDosBudget dos;
        CHECK(dos.grant_randomx(22, t), "T4b a grant");
        CHECK(dos.on_invalid_pow(22, true) == cx::Action::Ban, "T4b a confirmed invalid PoW bans (default policy)");
        CHECK(dos.banned(22) && dos.state(22).invalid_pow == 1, "T4b peer banned, invalid PoW counted");
        CHECK(!dos.grant_randomx(22, t + 10'000'000'000LL), "T4b a banned peer gets no grant");
    }
    {   // unconfirmed: the re-verify disagrees -> drop, no ban
        std::uint8_t a[32], b[32];
        std::memset(a, 0x7c, 32);
        std::memset(b, 0x00, 32);
        const bool confirmed = cx::confirm_invalid(a, b, true, false);
        CHECK(!confirmed, "T4d two different light-mode hashes: not confirmed");
        CHECK(cx::confirm_invalid(a, a, true, true), "T4d two equal hashes both below target: confirmed");
        cx::CarrierDosBudget dos;
        CHECK(dos.grant_randomx(44, t), "T4d a grant");
        CHECK(dos.on_invalid_pow(44, confirmed) == cx::Action::Drop && !dos.banned(44),
              "T4d an unconfirmed miss drops without a ban");
    }
    {   // budget-starved -> deferred, no penalty
        cx::DosPolicy p; p.per_peer_capacity = 0; p.per_peer_refill = 0;
        cx::CarrierDosBudget dos(p);
        CHECK(!dos.grant_randomx(33, t), "T4c no token: no grant");
        CHECK(!dos.banned(33) && dos.state(33).deferred == 1 && dos.state(33).score == 0,
              "T4c deferred, not penalised");
    }
    {   // cheap rejects: soft score; ban only at the threshold
        cx::DosPolicy p; p.ban_threshold = 5;
        cx::CarrierDosBudget dos(p);
        for (int i = 0; i < 4; ++i) CHECK(dos.on_cheap_reject(55) == cx::Action::Drop, "T4e a cheap reject below the threshold drops");
        CHECK(dos.on_cheap_reject(55) == cx::Action::Ban && dos.banned(55) && dos.state(55).structural == 5,
              "T4e the threshold-th cheap reject bans");
    }
    std::printf("T4 budget actions OK (refund / ban / unconfirmed / defer / cheap)\n");
}

static void t5_saturation_arithmetic() {
    const double ms_per_hash = 15.0;
    const double hashes_per_core_s = 1000.0 / ms_per_hash;
    CHECK(hashes_per_core_s > 60.0 && hashes_per_core_s < 70.0, "T5 ~65 (66.7) bogus evaluations/s saturate one light core");
    const double throttled_core_fraction = (1.0 * ms_per_hash) / 1000.0;
    CHECK(throttled_core_fraction < 0.02, "T5 throttled peer < 2% of one core");
    const double global_core_fraction = (16.0 * ms_per_hash) / 1000.0;
    CHECK(global_core_fraction < 0.30, "T5 global backstop <= ~25% of one core");
    std::printf("T5 arithmetic OK (%.1f hashes/core/s)\n", hashes_per_core_s);
}

static void t6_release() {
    cx::DosPolicy p; p.per_peer_capacity = 2; p.per_peer_refill = 0; p.retain_max = 1;
    cx::CarrierDosBudget dos(p);
    const cx::nanos_t t = 3'000'000'000LL;
    (void)dos.state(1);
    dos.release(1, t);
    CHECK(!dos.known(1), "T6 a source holding nothing is dropped at release");
    CHECK(dos.grant_randomx(2, t), "T6 source 2 spends a token");
    dos.release(2, t);
    CHECK(dos.known(2), "T6 a source with a spent bucket is kept at release");
    CHECK(dos.grant_randomx(3, t), "T6 source 3 spends a token");
    dos.release(3, t);
    CHECK(dos.known(3) && !dos.known(2), "T6 at most retain_max released sources kept (the oldest goes first)");
    std::printf("T6 release OK\n");
}

static void t7_flood_bounded() {
    cx::DosPolicy p;
    p.per_peer_capacity = 20; p.per_peer_refill = 1;
    p.global_capacity = 256; p.global_refill = 16;
    p.ban_threshold = 1'000'000'000u;
    cx::CarrierDosBudget dos(p);
    const int N = 2000;
    const cx::nanos_t t0 = 20'000'000'000LL, window = 1'000'000'000LL;
    const std::uint64_t peer = 0xBADu;
    int granted = 0;
    for (int i = 0; i < N; ++i) {
        const cx::nanos_t t = t0 + (cx::nanos_t)i * window / N;
        if (dos.grant_randomx(peer, t)) {
            ++granted;
            (void)dos.on_invalid_pow(peer, true);
        }
    }
    CHECK((std::uint64_t)granted == dos.state(peer).granted, "T7 grants recorded");
    CHECK(granted <= 22, "T7 RandomX evaluations capped at the token-bucket allowance");
    CHECK(granted >= 20, "T7 the bucket spent its burst");
    CHECK(granted < N / 20, "T7 <5% of the flood reaches the hasher");
    CHECK(dos.state(peer).deferred == (std::uint64_t)(N - granted), "T7 the rest deferred with no penalty");
    std::printf("T7 flood OK (N=%d requests/s -> %d evaluations)\n", N, granted);
}

int main() {
    t3_token_bucket();
    t4_actions();
    t5_saturation_arithmetic();
    t6_release();
    t7_flood_bounded();
    std::printf("ALL DOS-BUDGET CHECKS PASSED (%d assertions)\n", g_checks);
    return 0;
}
