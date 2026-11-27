// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Reviving a dormant DGB sharechain (rides dgb_work_source_test).
//
// dgb.voidbind held 2940 shares last extended 2026-08-27, both heads shallower
// than CHAIN_LENGTH (2880): think-P1 asked for the tails' parents, and think-P6
// dropped every request older than the no-best cutoff (now - 24 h, p2pool
// data.py:2360-2374), so the node never fetched them, never verified a head
// and never served work. The operator's decision (2026-11-27): revive the old
// chain. While no head has ever verified, the dropped parents are still
// requested, bounded per think and in total, and the revive ends for good once
// a best share exists.
// Pinned: the real think() on an aged unrooted chain requests the missing
// parent (RED before: nothing); the budget; one request per think; a valid best
// ends it and the cutoff applies again.
// ---------------------------------------------------------------------------

#include <impl/dgb/share.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/think_p6_desired_cutoff.hpp>

#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <vector>

namespace {

// An unrooted chain of `n` V36 shares whose oldest share's parent is missing,
// all `age_days` old: what voidbind stored.
struct AgedChain {
    dgb::ShareTracker tracker;
    uint256 missing_parent{std::vector<unsigned char>(32, 0x99)};
    uint256 tip;
    AgedChain(int n, uint32_t age_days)
    {
        const uint32_t t0 = static_cast<uint32_t>(std::time(nullptr)) - age_days * 86400u;
        uint256 prev = missing_parent;
        for (int i = 0; i < n; ++i) {
            auto* s = new dgb::MergedMiningShare();
            s->m_hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0x10 + i)));
            s->m_prev_hash = prev;
            s->m_pubkey_hash = uint160(base_uint<160>(std::vector<unsigned char>(20, 0xa1)));
            s->m_desired_version = 36;
            s->m_bits = 0x1e0fffff;
            s->m_max_bits = 0x1e0fffff;
            s->m_timestamp = t0 + 15u * static_cast<uint32_t>(i);
            s->m_min_header.m_bits = 0x1b0404cb;
            s->m_absheight = 100000u + static_cast<uint32_t>(i);
            prev = s->m_hash;
            tip = s->m_hash;
            dgb::ShareType st;
            st = s;
            tracker.add(st);
        }
    }
    dgb::TrackerThinkResult think()
    {
        return tracker.think([](uint256) { return 0; }, uint256(), 0x1b0404cb);
    }
};

bool requests(const dgb::TrackerThinkResult& r, const uint256& h)
{
    for (const auto& [peer, hash] : r.desired)
        if (hash == h)
            return true;
    return false;
}

} // namespace

TEST(DgbDormantChainRevive, AgedChainRequestsTheMissingParent)
{
    AgedChain c(10, 90);
    const auto r = c.think();
    EXPECT_TRUE(r.best.IsNull());
    EXPECT_TRUE(requests(r, c.missing_parent))
        << "the dormant chain's missing parent is never requested: the chain can never be revived";
}

TEST(DgbDormantChainRevive, FreshChainIsUnchanged)
{
    // A chain inside the cutoff is requested as before, without spending the
    // revive budget.
    AgedChain c(10, 0);
    const auto r = c.think();
    EXPECT_TRUE(requests(r, c.missing_parent));
    EXPECT_EQ(c.tracker.revive_state().requests_left, dgb::kReviveMaxRequests);
}

TEST(DgbDormantChainRevive, BudgetIsSpentOnePerThinkAndThenStops)
{
    AgedChain c(10, 90);
    for (int i = 0; i < dgb::kReviveMaxRequests; ++i) {
        const auto r = c.think();
        ASSERT_TRUE(requests(r, c.missing_parent)) << "think " << i;
        EXPECT_EQ(c.tracker.revive_state().requests_left, dgb::kReviveMaxRequests - 1 - i);
    }
    const auto r = c.think();
    EXPECT_FALSE(requests(r, c.missing_parent)) << "the revive budget is not enforced";
}

TEST(DgbDormantChainRevive, PolicyRules)
{
    // One per think.
    dgb::ReviveState st;
    int taken = 0;
    bool armed = dgb::think_p6_revive_armed(st, /*best_valid=*/false, /*verified=*/0);
    ASSERT_TRUE(armed);
    EXPECT_TRUE(dgb::think_p6_revive_take(st, armed, taken));
    EXPECT_FALSE(dgb::think_p6_revive_take(st, armed, taken)) << "two revive requests in one think";
    EXPECT_EQ(st.requests_left, dgb::kReviveMaxRequests - 1);

    // A verified chain (even without a best yet) does not revive.
    dgb::ReviveState v;
    EXPECT_FALSE(dgb::think_p6_revive_armed(v, false, 5));

    // A valid best ends it for good, and the cutoff applies again.
    dgb::ReviveState b;
    EXPECT_FALSE(dgb::think_p6_revive_armed(b, /*best_valid=*/true, 0));
    EXPECT_TRUE(b.done);
    EXPECT_FALSE(dgb::think_p6_revive_armed(b, /*best_valid=*/false, 0)) << "the revive restarted after a best";
    taken = 0;
    EXPECT_FALSE(dgb::think_p6_revive_take(b, false, taken));

    // An exhausted budget never takes.
    dgb::ReviveState e;
    e.requests_left = 0;
    EXPECT_FALSE(dgb::think_p6_revive_armed(e, false, 0));
}
