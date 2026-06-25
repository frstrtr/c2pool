/// Phase v36-migration-std — DASH Component A persisted activation LATCH KATs.
///
/// Exercises src/impl/dash/version_activation_latch.hpp — the persisted
/// VOTING -> ACTIVATED -> CONFIRMED state machine the migration standard
/// requires and that DASH lacked (version_negotiation.hpp computed the
/// v36-active verdict LIVE every call, so an unsupervised restart could flap).
///
/// The latch is fed the already-computed v36_active boolean (decoupled from the
/// chain) so these KATs are pure + socket-free. They prove:
///
///   (1) StartsVoting              — fresh latch is VOTING, not confirmed.
///   (2) ActivatesOnFirstActive    — first active=true -> ACTIVATED + height.
///   (3) ConfirmsAfterFullSpan     — active sustained for 2*CHAIN_LENGTH -> CONFIRMED.
///   (4) DoesNotConfirmEarly       — active for < span stays ACTIVATED.
///   (5) RevertsWhenActivationLost — active drops before confirm -> back to VOTING.
///   (6) ConfirmedIsIrreversible   — once CONFIRMED, active=false never reverts.
///   (7) JsonRoundTrips            — to_json()/from_json() identity across states.
///   (8) DefaultSpanIsTwoChainLen  — default confirm_span == 2*CHAIN_LENGTH.

#include <gtest/gtest.h>

#include <impl/dash/version_activation_latch.hpp>
#include <impl/dash/config_pool.hpp>

using dash::version_activation_latch::ActivationLatch;
using dash::version_activation_latch::LatchState;

namespace {

// short span so a KAT need not walk a 4320-deep chain; the span is a field.
ActivationLatch make_short(uint64_t span)
{
    ActivationLatch l;
    l.confirm_span = span;
    return l;
}

} // namespace

TEST(DashVersionActivationLatch, StartsVoting)
{
    ActivationLatch l;
    EXPECT_EQ(l.state, LatchState::Voting);
    EXPECT_FALSE(l.is_confirmed());
}

TEST(DashVersionActivationLatch, ActivatesOnFirstActive)
{
    auto l = make_short(100);
    l.observe(true, 1000);
    EXPECT_EQ(l.state, LatchState::Activated);
    EXPECT_EQ(l.activated_height, 1000u);
    EXPECT_FALSE(l.is_confirmed());
}

TEST(DashVersionActivationLatch, ConfirmsAfterFullSpan)
{
    auto l = make_short(100);
    l.observe(true, 1000);            // ACTIVATED at 1000
    l.observe(true, 1099);            // span-1 -> still ACTIVATED
    EXPECT_EQ(l.state, LatchState::Activated);
    l.observe(true, 1100);            // exactly span -> CONFIRMED
    EXPECT_EQ(l.state, LatchState::Confirmed);
    EXPECT_TRUE(l.is_confirmed());
}

TEST(DashVersionActivationLatch, DoesNotConfirmEarly)
{
    auto l = make_short(100);
    l.observe(true, 1000);
    l.observe(true, 1050);            // halfway
    EXPECT_EQ(l.state, LatchState::Activated);
    EXPECT_FALSE(l.is_confirmed());
}

TEST(DashVersionActivationLatch, RevertsWhenActivationLost)
{
    auto l = make_short(100);
    l.observe(true, 1000);            // ACTIVATED
    l.observe(false, 1040);           // dip below 95% before confirm -> revert
    EXPECT_EQ(l.state, LatchState::Voting);
    EXPECT_EQ(l.activated_height, 0u);
}

TEST(DashVersionActivationLatch, ConfirmedIsIrreversible)
{
    auto l = make_short(100);
    l.observe(true, 1000);
    l.observe(true, 1100);            // CONFIRMED
    ASSERT_TRUE(l.is_confirmed());
    l.observe(false, 1200);           // a later dip must NOT un-confirm
    l.observe(false, 5000);
    EXPECT_EQ(l.state, LatchState::Confirmed);
    EXPECT_TRUE(l.is_confirmed());
}

TEST(DashVersionActivationLatch, JsonRoundTrips)
{
    for (LatchState st : {LatchState::Voting, LatchState::Activated, LatchState::Confirmed}) {
        ActivationLatch l;
        l.state = st;
        l.version = 36;
        l.activated_height = (st == LatchState::Voting) ? 0u : 4242u;
        l.confirm_span = 777u;
        ActivationLatch r = ActivationLatch::from_json(l.to_json());
        EXPECT_EQ(r.state, l.state);
        EXPECT_EQ(r.version, l.version);
        EXPECT_EQ(r.activated_height, l.activated_height);
        EXPECT_EQ(r.confirm_span, l.confirm_span);
    }
}

TEST(DashVersionActivationLatch, DefaultSpanIsTwoChainLen)
{
    ActivationLatch l;
    EXPECT_EQ(l.confirm_span, 2ull * dash::PoolConfig::CHAIN_LENGTH);
}
