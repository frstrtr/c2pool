// C-startup-invariant (gapless MN-list follower / daemonless re-seed).
//
// The embedded DASH arm projects a coinbase MN payee and a DIP-0027
// creditPoolBalance off an incrementally-folded deterministic MN list. Both
// freshness gates on the money path —
//   NodeCoinState::set_require_fresh_credit_pool  (bad-cbtx-assetlocked-amount)
//   NodeCoinState::set_require_fresh_mn_payee      (bad-cb-payee)
// — are only reward-safe when the serve tip is promoted BODY-FIRST
// (CoinStateMaintainer::set_body_first_serve_tip(true)). A header-tip serve
// publishes the tip before the fold is current at the block the template
// builds on — exactly the per-tip ordering window (#1154) these gates exist to
// close — so a payee / credit-pool derived at header-tip can be one block stale
// and serve a bad coinbase = lost block.
//
// The daemonless arm sets body-first UNCONDITIONALLY at its wiring site, so
// this invariant cannot false-trip today. Its job is to make a FUTURE embedded
// wiring that adds an arm but forgets set_body_first_serve_tip(true) fail LOUD
// at startup instead of silently regressing to publish-at-header-tip.
//
// It only TIGHTENS: it relaxes no guard and, on violation, refuses to start
// (the safe posture) rather than serving. A deliberate std::logic_error (not
// assert()) so the invariant also fires in release/NDEBUG builds — the money
// path must never depend on assertions being compiled in.

#pragma once

#include <stdexcept>
#include <string>

namespace dash {
namespace coin {

/// Startup coupling: an embedded arm running ANY money-path freshness gate
/// MUST promote its serve tip body-first. Throws std::logic_error on
/// violation; returns normally otherwise. Pure predicate over the four
/// already-resolved startup booleans so it is directly unit-testable.
inline void require_body_first_when_fresh_gated(
    bool embedded_arm_enabled,
    bool require_fresh_credit_pool,
    bool require_fresh_mn_payee,
    bool body_first_serve_tip)
{
    if (embedded_arm_enabled
        && (require_fresh_credit_pool || require_fresh_mn_payee)
        && !body_first_serve_tip) {
        throw std::logic_error(
            "[EMB-DASH] startup invariant violated: the embedded arm has a "
            "money-path freshness gate enabled (require_fresh_credit_pool || "
            "require_fresh_mn_payee) but body_first_serve_tip is OFF. A "
            "header-tip serve would publish a coinbase payee / creditPool off "
            "a fold that is not yet current at the serve tip "
            "(bad-cb-payee / bad-cbtx-assetlocked-amount = lost block). Wire "
            "CoinStateMaintainer::set_body_first_serve_tip(true).");
    }
}

} // namespace coin
} // namespace dash
