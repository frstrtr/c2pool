// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The causes only the inject dry run answers (POST /api/tx-inject/validate,
/// NodeCoinState::validate_inject), after everything a submit would answer.
/// /api/tx-inject/submit never returns them, so they are kept out of the
/// submit-path headers (node_coin_state.hpp, mempool.hpp, tx_inject_pool.hpp,
/// inject_rate_limiter.hpp, inject_sandbox.hpp) whose "inject-*" strings the
/// companion's submit vocabulary mirrors string for string (its test_sched
/// K9d drift check). A companion that wires the dry run maps these three in a
/// vocabulary of its own and extends that check to this header.

namespace dash {
namespace coin {
namespace inject_dry_run_cause {

/// The node has no tip yet, so input maturity cannot be judged. Transient:
/// ask again once the node follows the chain.
inline constexpr const char* kTipUnknown = "inject-tip-unknown";

/// A coinbase input is below 100 confirmations at the next height; the
/// template build would drop the tx silently. Wait: retry at the input's
/// spendable_from_height. (The companion's reserved name.)
inline constexpr const char* kImmatureCoinbaseInput = "inject-immature-coinbase-input";

/// Another pool tx already spends an input (the reply's conflicts[] names it;
/// the selector would keep one of the two). Not retryable as is: the
/// operator resolves the conflict (it confirms, it expires, or the plan is
/// rebuilt without that input).
inline constexpr const char* kInputSpentInMempool = "inject-input-spent-in-mempool";

} // namespace inject_dry_run_cause
} // namespace coin
} // namespace dash
