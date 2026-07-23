// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT pinning the think() Phase-4 head-score key construction
// (think_p4_head_keys.hpp) against the p2pool data.py think() Phase-4 oracle:
// selection key (adjusted_work, -reason, -time_seen) with a one-share punishment
// deduction iff naughty, and traditional key (work_score, -time_seen, -reason).
//
// Includes a NON-CIRCULAR reference anchor: an independent verbatim reproduction
// of the share_tracker.hpp inline arithmetic, asserted equal to the SSOT across a
// matrix — so the test would FAIL if the SSOT drifted from the pre-delegation
// inline code, not merely re-derive the SSOT from itself.

#include <gtest/gtest.h>
#include <cstdint>
#include <tuple>
#include "../think_p4_head_keys.hpp"

using dgb::think_p4_head_score_keys;
using Work = int64_t;

// ---- direct field pins vs the oracle --------------------------------------

TEST(ThinkP4HeadKeys, HonestHeadNoDeduction) {
    // reason == 0 => no punishment: adjusted == raw work_score, neg_reason == 0.
    auto k = think_p4_head_score_keys<Work>(1000, 7, /*reason=*/0, /*ts=*/42);
    EXPECT_EQ(k.adjusted_work, 1000);
    EXPECT_EQ(k.work_score, 1000);
    EXPECT_EQ(k.neg_reason, 0);
    EXPECT_EQ(k.neg_time_seen, -42);
}

TEST(ThinkP4HeadKeys, NaughtyHeadDeductsOneShareWork) {
    // reason > 0 => deduct EXACTLY one share's work from the selection key.
    auto k = think_p4_head_score_keys<Work>(1000, 7, /*reason=*/1, /*ts=*/42);
    EXPECT_EQ(k.adjusted_work, 993);     // 1000 - 7
    EXPECT_EQ(k.work_score, 1000);       // traditional key keeps raw work
    EXPECT_EQ(k.neg_reason, -1);
    EXPECT_EQ(k.neg_time_seen, -42);
}

TEST(ThinkP4HeadKeys, PunishmentIsMinPunishOne) {
    // p2pool min(punish,1): a large naughty count deducts the SAME single
    // share's work as naughty==1 — never a multiple.
    auto k1 = think_p4_head_score_keys<Work>(1000, 7, /*reason=*/1, /*ts=*/42);
    auto k9 = think_p4_head_score_keys<Work>(1000, 7, /*reason=*/9, /*ts=*/42);
    EXPECT_EQ(k1.adjusted_work, 993);
    EXPECT_EQ(k9.adjusted_work, 993);    // identical deduction, not 1000-9*7
    EXPECT_EQ(k9.neg_reason, -9);        // reason magnitude only affects key1
}

// ---- selection ordering (std::sort ascending, best == back()) -------------

namespace {
// Mirror DecoratedData<HeadScore> ordering on the selection key triple.
auto sel_key(const dgb::ThinkP4HeadKeys<Work>& k) {
    return std::make_tuple(k.adjusted_work, k.neg_reason, k.neg_time_seen);
}
}

TEST(ThinkP4HeadKeys, HonestBeatsEqualRawWorkNaughty) {
    // Two heads, equal raw work & time: the naughty one sorts LOWER (loses the
    // back()-is-best pick) purely via the work deduction.
    auto honest = think_p4_head_score_keys<Work>(1000, 7, 0, 100);
    auto naughty = think_p4_head_score_keys<Work>(1000, 7, 3, 100);
    EXPECT_GT(sel_key(honest), sel_key(naughty));
}

TEST(ThinkP4HeadKeys, EarlierSeenWinsOnFullTie) {
    // Equal work & honesty => earlier time_seen (larger -ts) wins.
    auto early = think_p4_head_score_keys<Work>(1000, 7, 0, 50);
    auto late  = think_p4_head_score_keys<Work>(1000, 7, 0, 80);
    EXPECT_GT(sel_key(early), sel_key(late));
}

// ---- non-circular anchor: verbatim inline reproduction --------------------

namespace {
// Independent restatement of the share_tracker.hpp think() Phase-4 inline
// arithmetic, written WITHOUT calling the SSOT.
struct InlineKeys { Work adjusted; Work raw; int32_t neg_reason; int64_t neg_ts; };
InlineKeys inline_phase4(Work work_score, Work head_share_work,
                         int32_t reason, int64_t time_seen) {
    Work adjusted_work = work_score;        // p2pool: work - min(punish,1)*ata
    if (reason > 0)
        adjusted_work = adjusted_work - head_share_work;
    return InlineKeys{adjusted_work, work_score, -reason, -time_seen};
}
}

TEST(ThinkP4HeadKeys, DelegationMatchesPreDelegationInlineArithmetic) {
    const Work works[]   = {0, 1, 7, 1000, 1'000'000};
    const Work shares[]  = {1, 7, 50, 999};
    const int32_t reas[] = {0, 1, 2, 9};
    const int64_t tss[]  = {0, 42, 100, 9'999'999};
    for (Work w : works)
      for (Work s : shares)
        for (int32_t r : reas)
          for (int64_t t : tss) {
            auto ssot = think_p4_head_score_keys<Work>(w, s, r, t);
            auto ref  = inline_phase4(w, s, r, t);
            EXPECT_EQ(ssot.adjusted_work, ref.adjusted)
                << "w=" << w << " s=" << s << " r=" << r << " t=" << t;
            EXPECT_EQ(ssot.work_score, ref.raw);
            EXPECT_EQ(ssot.neg_reason, ref.neg_reason);
            EXPECT_EQ(ssot.neg_time_seen, ref.neg_ts);
          }
}