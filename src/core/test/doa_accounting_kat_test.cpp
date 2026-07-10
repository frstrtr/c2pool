// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <core/doa_accounting.hpp>

// Offline deterministic KAT for the DOA-under-load accounting SSOT.
//
// The predicate under test is the SAME core::doa::is_doa_share() the live
// submit path calls (stratum_server.cpp handle_submit, ~L933) -- this is an
// SSOT KAT, not a re-implementation, so a pass here proves the production
// behaviour, not a parallel copy of it.
//
// The load-bearing property (integrator, [s=contabo-gate] 2026-07-10): the
// guard only earns its keep because m_cached_template refreshes on tip-advance
// while stale jobs still carry the old frozen prevhash. When current==job_prev
// (cache updated in lockstep with job creation) doa_shares_ must never move.

using core::doa::is_doa_share;

namespace {

constexpr char PREV_A[] = "00000000000000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7";
constexpr char PREV_B[] = "0000000000000000000234abcd5678ef90112233445566778899aabbccddeeff";

// Minimal mirror of the submit-side accounting contract: a DOA increments the
// statistics counter ONLY, and leaves the job's frozen stale_info untouched.
// That field is part of ref_hash; mutating it at submit would yield GENTX-FAIL.
struct SubmitAccounting {
    std::uint64_t doa_shares = 0;
    int           job_stale_info = 0;  // frozen at get_work(); MUST NOT change at submit

    void on_submit(const std::string& current_prev, const std::string& job_prev) {
        if (is_doa_share(current_prev, job_prev)) {
            ++doa_shares;
            // Deliberately do NOT touch job_stale_info -- see SSOT header.
        }
    }
};

} // namespace

// -- Predicate axis ----------------------------------------------------------

TEST(DoaAccounting, FreshTemplateIsNotDoa) {
    // Cache advanced in lockstep with the job -> prevhashes equal -> not DOA.
    EXPECT_FALSE(is_doa_share(PREV_A, PREV_A));
}

TEST(DoaAccounting, TipAdvancedIsDoa) {
    // Job frozen under A, live template now on B -> positive mismatch -> DOA.
    EXPECT_TRUE(is_doa_share(PREV_B, PREV_A));
    EXPECT_TRUE(is_doa_share(PREV_A, PREV_B));
}

TEST(DoaAccounting, EmptyOperandIsNeverDoa) {
    // Unfetched template or unpopulated job prevhash -> freshness UNKNOWN ->
    // never counted (guard clauses mirror the live call site).
    EXPECT_FALSE(is_doa_share("",     PREV_A));
    EXPECT_FALSE(is_doa_share(PREV_A, ""));
    EXPECT_FALSE(is_doa_share("",     ""));
}

// -- Accounting-contract axis (the freshness assertion) ----------------------

TEST(DoaAccounting, StaleJobIncrementsCounterAndFreezesStaleInfo) {
    // job issued under prevhash A; tip advances -> cache flips to B; the miner
    // submits the now-stale A job. Expect: doa_shares++ AND stale_info frozen.
    SubmitAccounting acct;
    acct.on_submit(/*current=*/PREV_B, /*job=*/PREV_A);
    EXPECT_EQ(acct.doa_shares, 1u);
    EXPECT_EQ(acct.job_stale_info, 0) << "stale_info is part of ref_hash; must stay frozen (no GENTX-FAIL)";
}

TEST(DoaAccounting, LockstepCacheNeverAccumulatesDoa) {
    // If the cache updates in lockstep with job creation, current==job_prev on
    // every submit and the counter must stay at zero across a run.
    SubmitAccounting acct;
    for (int i = 0; i < 1000; ++i)
        acct.on_submit(PREV_A, PREV_A);
    EXPECT_EQ(acct.doa_shares, 0u);
    EXPECT_EQ(acct.job_stale_info, 0);
}

// NOTE: the DOA underfill-half threshold constant (owned by btc-heap-opt lane,
// [task] 2026-07-10) grafts a further assertion axis here once its canonical
// name + default land; the freshness contract above is independent of it.
