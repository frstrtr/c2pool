// SPDX-License-Identifier: AGPL-3.0-or-later
/// C-startup-invariant KATs — gapless MN-list follower / daemonless re-seed.
///
/// Exercises src/impl/dash/coin/embedded_startup_invariant.hpp:
/// require_body_first_when_fresh_gated(), the startup coupling wired in
/// src/c2pool/main_dash.cpp right after set_body_first_serve_tip(true).
///
/// The money-path freshness gates (require_fresh_credit_pool /
/// require_fresh_mn_payee) are only reward-safe when the serve tip is promoted
/// BODY-FIRST — a header-tip serve publishes a payee / creditPool off a fold
/// not yet current at the serve tip (bad-cb-payee / bad-cbtx-assetlocked =
/// lost block). The invariant makes a FUTURE embedded wiring that adds an arm
/// with a freshness gate but forgets set_body_first_serve_tip(true) fail LOUD
/// at startup. It TIGHTENS only: it never trips when body-first is on, and
/// never trips off the daemonless arm today (which sets body-first
/// unconditionally).
///
/// A throw (std::logic_error), not assert(), so it also fires in release/NDEBUG
/// — the money path must never depend on assertions being compiled in.

#include <gtest/gtest.h>

#include <stdexcept>

#include <impl/dash/coin/embedded_startup_invariant.hpp>

using dash::coin::require_body_first_when_fresh_gated;

namespace {

// ── THE DEATH-TEST (regression pin) ────────────────────────────────────────
// The exact future-regression the invariant exists to catch: an embedded arm
// with a money-path freshness gate ON but body_first_serve_tip left unset.
// Must throw at startup rather than silently serving publish-at-header-tip.
TEST(DashEmbeddedStartupInvariant, EmbeddedFreshGateWithoutBodyFirstThrows)
{
    // credit-pool gate on, body-first OFF -> violation
    EXPECT_THROW(
        require_body_first_when_fresh_gated(
            /*embedded_arm_enabled=*/true,
            /*require_fresh_credit_pool=*/true,
            /*require_fresh_mn_payee=*/false,
            /*body_first_serve_tip=*/false),
        std::logic_error);

    // mn-payee gate on, body-first OFF -> violation
    EXPECT_THROW(
        require_body_first_when_fresh_gated(
            true, /*cp=*/false, /*payee=*/true, /*body_first=*/false),
        std::logic_error);

    // BOTH gates on, body-first OFF -> violation
    EXPECT_THROW(
        require_body_first_when_fresh_gated(true, true, true, false),
        std::logic_error);
}

// ── The compliant daemonless arm (today) — body-first ON, never trips. ──────
TEST(DashEmbeddedStartupInvariant, EmbeddedFreshGateWithBodyFirstOk)
{
    EXPECT_NO_THROW(
        require_body_first_when_fresh_gated(true, true, false, true));
    EXPECT_NO_THROW(
        require_body_first_when_fresh_gated(true, false, true, true));
    EXPECT_NO_THROW(
        require_body_first_when_fresh_gated(true, true, true, true));
}

// ── No freshness gate armed -> body-first is irrelevant, never trips. ───────
TEST(DashEmbeddedStartupInvariant, EmbeddedWithoutAnyFreshGateOk)
{
    EXPECT_NO_THROW(
        require_body_first_when_fresh_gated(
            /*embedded=*/true, /*cp=*/false, /*payee=*/false,
            /*body_first=*/false));
}

// ── Non-embedded arm -> the invariant does not apply, never trips even with
//    both gate flags set and body-first off. Relaxes nothing on the embedded
//    path; only scopes the requirement to the embedded arm.
TEST(DashEmbeddedStartupInvariant, NonEmbeddedArmNeverTrips)
{
    EXPECT_NO_THROW(
        require_body_first_when_fresh_gated(
            /*embedded=*/false, /*cp=*/true, /*payee=*/true,
            /*body_first=*/false));
}

} // namespace
