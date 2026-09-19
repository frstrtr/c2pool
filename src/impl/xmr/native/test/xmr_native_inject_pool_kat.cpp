// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_inject_pool_kat.cpp
//
// The OPERATOR-INJECT DoS-LEDGER KAT. It exercises, purely (no node/rig), the
// three bounded-work guards that front the inject gate, mirroring the Dash
// inject KATs:
//
//   * OperatorInjectPool -- caps (entries, total bytes, per-tx size), duplicate,
//     expiry-by-height, forget, and the ordered() view (priority flag desc,
//     then submit FIFO) intersected against the C3 selectable set;
//   * InjectRateLimiter  -- count budget AND byte budget over a sliding window,
//     charged on attempt, with Local / Peers scopes so a peer flood can never
//     starve the operator's own inject budget;
//   * InjectSandbox      -- envelope bounds, oversize refused (charged-free)
//     BEFORE the limiter is charged, fail-closed by name.
//
// Every refusal is asserted BY NAME (the DEF3 discipline the Dash KATs use).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/inject/xmr_operator_inject_pool.hpp"
#include "impl/xmr/native/inject/xmr_inject_rate_limiter.hpp"
#include "impl/xmr/native/inject/xmr_inject_sandbox.hpp"

using namespace c2pool::xmr::native;
namespace node = c2pool::xmr::node;

static int g_checks = 0;
static int g_fail   = 0;
static void check(bool cond, const char* msg) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("  FAIL: %s\n", msg); }
}
static bool streq(const char* a, const char* b) { return std::strcmp(a, b) == 0; }

static Hash mkid(std::uint64_t tag) {
    Hash h{};
    for (int i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    return h;
}
static node::TxBacklogEntry mkbe(std::uint64_t tag, std::uint64_t weight, std::uint64_t fee) {
    node::TxBacklogEntry e;
    e.id = mkid(tag); e.weight = weight; e.blob_size = weight; e.fee = fee;
    return e;
}

int main() {
    std::printf("xmr_native_inject_pool_kat\n");

    // ===================== OperatorInjectPool ============================
    {
        OperatorInjectPool p;
        // admit one
        check(p.admit(mkid(1), InjectFlags::PriorityRequest, 1000, 1400, 1500, 0, 100) == OperatorInjectPool::Admit::Ok,
              "pool admits a fresh inject");
        check(p.size() == 1 && p.total_bytes() == 1400, "pool tracks size and bytes");
        check(p.contains(mkid(1)), "pool contains the admitted id");

        // duplicate -> named
        auto dup = p.admit(mkid(1), 0, 1000, 1400, 1500, 0, 101);
        check(dup == OperatorInjectPool::Admit::Duplicate, "duplicate refused");
        check(streq(OperatorInjectPool::admit_name(dup), "inject-pool-duplicate"), "duplicate named");

        // oversize -> named, charged-free (would_admit refuses before mutation)
        auto over = p.would_admit(mkid(2), OperatorInjectPool::kMaxInjectTxBytes + 1);
        check(over == OperatorInjectPool::Admit::TooLarge, "oversize refused");
        check(streq(OperatorInjectPool::admit_name(over), "inject-pool-oversize"), "oversize named");

        // forget
        check(p.forget(mkid(1)), "forget an admitted id");
        check(p.size() == 0 && p.total_bytes() == 0, "forget clears size/bytes");
        check(!p.forget(mkid(1)), "forget of an unknown id returns false");
    }

    // total-bytes cap -> named
    {
        OperatorInjectPool p;
        // fill to just under 4 MiB with big injects (each ~140 KB)
        std::uint64_t tag = 0;
        bool hit = false;
        for (int i = 0; i < 40; ++i) {
            auto v = p.admit(mkid(++tag), 0, 1000, 140000, 149400, 0, 1);
            if (v == OperatorInjectPool::Admit::TotalBytesExceeded) {
                check(streq(OperatorInjectPool::admit_name(v), "inject-pool-total-bytes-exceeded"),
                      "total-bytes cap named");
                hit = true; break;
            }
        }
        check(hit, "cumulative byte cap (4 MiB) eventually refuses");
        check(p.total_bytes() <= OperatorInjectPool::kMaxInjectTotalBytes, "total bytes never exceeds the cap");
    }

    // entries cap -> named (tiny injects so bytes never bind first)
    {
        OperatorInjectPool p;
        bool hit = false;
        for (std::uint64_t i = 1; i <= OperatorInjectPool::INJECT_POOL_MAX_ENTRIES + 5; ++i) {
            auto v = p.admit(mkid(i), 0, 1000, 100, 100, 0, 1);
            if (v == OperatorInjectPool::Admit::PoolFull) {
                check(streq(OperatorInjectPool::admit_name(v), "inject-pool-full"), "pool-full named");
                hit = true; break;
            }
        }
        check(hit, "entry cap (1024) eventually refuses");
        check(p.size() <= OperatorInjectPool::INJECT_POOL_MAX_ENTRIES, "entries never exceed the cap");
    }

    // expiry by height -> forgotten, dropped ids returned
    {
        OperatorInjectPool p;
        p.admit(mkid(1), 0, /*expiry*/ 100, 1400, 1500, 0, 1);
        p.admit(mkid(2), 0, /*expiry*/ 200, 1400, 1500, 0, 2);
        p.admit(mkid(3), 0, /*never*/   0,   1400, 1500, 0, 3);
        auto dropped = p.reap_expired(150);   // tip past 100, not 200
        check(dropped.size() == 1 && dropped[0] == mkid(1), "expiry drops exactly the expired id");
        check(!p.contains(mkid(1)) && p.contains(mkid(2)) && p.contains(mkid(3)),
              "reap keeps the unexpired and never-expiring injects");
    }

    // ordered(): priority flag first, then FIFO by submit seq, membership by C3
    {
        OperatorInjectPool p;
        // submit order 1,2,3,4; only 2 and 4 carry the priority flag.
        p.admit(mkid(1), 0,                            1000, 1400, 1500, 0, 10);
        p.admit(mkid(2), InjectFlags::PriorityRequest, 1000, 1400, 1500, 0, 11);
        p.admit(mkid(3), 0,                            1000, 1400, 1500, 0, 12);
        p.admit(mkid(4), InjectFlags::PriorityRequest, 1000, 1400, 1500, 0, 13);
        // C3 selectable set carries all four (plus an unrelated tx 99 that must
        // NOT appear -- it is not an inject).
        std::vector<node::TxBacklogEntry> pool_set{
            mkbe(1, 1400, 0), mkbe(2, 1400, 0), mkbe(3, 1400, 0), mkbe(4, 1400, 0), mkbe(99, 2000, 500) };
        auto ord = p.ordered(pool_set);
        check(ord.size() == 4, "ordered() returns only the injects still in the C3 set");
        // priority-flag injects first, in submit order: 2, 4 ; then non-priority 1, 3
        bool ok = ord[0].id == mkid(2) && ord[1].id == mkid(4)
               && ord[2].id == mkid(1) && ord[3].id == mkid(3);
        check(ok, "ordered() = priority-request first (FIFO), then non-priority (FIFO)");

        // an inject C3 has dropped (mined/conflicted) silently stops being offered
        std::vector<node::TxBacklogEntry> shrunk{ mkbe(1, 1400, 0), mkbe(3, 1400, 0) };
        auto ord2 = p.ordered(shrunk);
        check(ord2.size() == 2 && ord2[0].id == mkid(1) && ord2[1].id == mkid(3),
              "ordered() intersects against the C3 selectable set (membership by id)");
    }

    // ===================== InjectRateLimiter =============================
    {
        InjectRateLimiter lim(InjectRateLimiter::Scope::Local);
        // COUNT budget: 200/window. 200 tiny injects pass, the 201st is refused.
        std::time_t now = 1000;
        bool count_hit = false;
        for (std::size_t i = 0; i < InjectRateLimiter::kMaxInjectsPerWindow + 1; ++i) {
            auto r = lim.try_consume(10, now);
            if (!r.ok()) {
                check(r.verdict == InjectRateLimiter::Verdict::CountExceeded, "count budget refuses");
                check(streq(r.name(), "inject-rate-limited-count"), "count refusal named (local)");
                count_hit = true; break;
            }
        }
        check(count_hit, "count budget (200/window) eventually refuses");
        // after the window slides, the budget refills.
        auto r2 = lim.try_consume(10, now + InjectRateLimiter::kWindowSeconds + 1);
        check(r2.ok(), "count budget refills after the window slides");
    }
    {
        InjectRateLimiter lim(InjectRateLimiter::Scope::Local);
        // BYTE budget: 8 MiB/window. A few big injects exhaust bytes before count.
        std::time_t now = 2000;
        bool byte_hit = false;
        for (int i = 0; i < 100; ++i) {
            auto r = lim.try_consume(200000, now);   // 200 KB each
            if (!r.ok()) {
                check(r.verdict == InjectRateLimiter::Verdict::BytesExceeded, "byte budget refuses");
                check(streq(r.name(), "inject-rate-limited-bytes"), "byte refusal named (local)");
                byte_hit = true; break;
            }
        }
        check(byte_hit, "byte budget (8 MiB/window) eventually refuses");
    }
    {
        // SCOPE split: a peer flood exhausts ONLY the peer budget; the local
        // budget is untouched, so the operator's own inject is never starved.
        InjectRateLimiter local(InjectRateLimiter::Scope::Local);
        InjectRateLimiter peers(InjectRateLimiter::Scope::Peers);
        std::time_t now = 3000;
        for (std::size_t i = 0; i < InjectRateLimiter::kMaxInjectsPerWindow + 50; ++i)
            peers.try_consume(10, now);   // flood the peer budget
        auto pv = peers.try_consume(10, now);
        check(!pv.ok() && streq(pv.name(), "inject-rate-limited-peers-count"),
              "peer flood exhausts the peer budget, named with -peers-");
        auto lv = local.try_consume(10, now);
        check(lv.ok(), "the operator's Local budget is UNTOUCHED by a peer flood (no starvation)");
    }

    // ===================== InjectSandbox ================================
    {
        auto mkw = [](std::uint64_t blob, std::uint8_t rct, std::size_t nin,
                      std::size_t nout, std::size_t extra) {
            TxWeightInfo w;
            w.blob_size = blob; w.rct_type = rct; w.n_inputs = nin;
            w.n_outputs = nout; w.extra_size = extra;
            return w;
        };
        const std::uint8_t BPP = RCT_TYPE_BULLETPROOF_PLUS;

        // a realistic operator inject passes untouched
        check(InjectSandbox::vet(mkw(2000, BPP, 2, 2, 44)).ok(), "a normal BP+ inject passes the sandbox");

        // oversize refused FIRST (charged-free, before anything else)
        auto over = InjectSandbox::vet(mkw(InjectSandbox::kMaxBlobBytes + 1, BPP, 2, 2, 44));
        check(over.verdict == InjectSandbox::Verdict::Oversize, "oversize refused");
        check(streq(over.name(), "inject-sandbox-oversize"), "oversize named");

        // not bulletproof-plus
        auto notbpp = InjectSandbox::vet(mkw(2000, 5 /*CLSAG*/, 2, 2, 44));
        check(notbpp.verdict == InjectSandbox::Verdict::NotBulletproofPlus, "non-BP+ refused");
        check(streq(notbpp.name(), "inject-sandbox-not-bulletproof-plus"), "non-BP+ named");

        // too many outputs (> 16)
        auto outs = InjectSandbox::vet(mkw(2000, BPP, 2, 17, 44));
        check(outs.verdict == InjectSandbox::Verdict::TooManyOutputs, "too-many-outputs refused");
        check(streq(outs.name(), "inject-sandbox-too-many-outputs"), "too-many-outputs named");

        // extra too large (> 1060)
        auto extra = InjectSandbox::vet(mkw(2000, BPP, 2, 2, 1061));
        check(extra.verdict == InjectSandbox::Verdict::ExtraTooLarge, "extra-too-large refused");
        check(streq(extra.name(), "inject-sandbox-extra-too-large"), "extra-too-large named");

        // too many inputs (> 256)
        auto ins = InjectSandbox::vet(mkw(2000, BPP, 257, 2, 44));
        check(ins.verdict == InjectSandbox::Verdict::TooManyInputs, "too-many-inputs refused");
        check(streq(ins.name(), "inject-sandbox-too-many-inputs"), "too-many-inputs named");
    }

    std::printf("%s: %d checks, %d failures\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
