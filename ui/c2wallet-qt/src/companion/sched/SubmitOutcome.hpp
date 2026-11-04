// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the outcome map: one POST /api/tx-inject/submit reply
// (transport result, HTTP status, the node's named `cause`) -> the item's next
// state and retry class (design §6). Pure: no I/O, no clock.
//
// The cause vocabulary extends c2w::artifact::inject_cause (which lists only the
// M1 names) with every name the master node emits (node_coin_state.hpp
// submit_inject, mempool.hpp add_inject, tx_inject_pool.hpp, inject_sandbox.hpp,
// inject_rate_limiter.hpp), plus the reserved runtime-submit oracle names, so a
// future node never lands in "unknown". An unknown cause never loops: it
// blocks the item until the operator looks.

#include "InjectQueue.hpp"
#include "NodeApi.hpp"

#include <optional>
#include <string>

namespace c2w::companion::sched {

// Every name below is copied string-for-string from master c7a3bd0cd:
//   node_coin_state.hpp:715,719          inject-disabled, inject-type-unsupported
//   mempool.hpp:728-740                  inject_gate_name()
//   tx_inject_pool.hpp:76-82             admit_name()
//   inject_rate_limiter.hpp:83-98        verdict_name() / scoped_name()
//   inject_sandbox.hpp:91-97             the sandbox verdict names
// The `*-unknown` names are the node's own unreachable switch defaults.
namespace cause {
inline constexpr const char* Ok = "ok";
// node_coin_state.hpp
inline constexpr const char* Disabled = "inject-disabled";
inline constexpr const char* TypeUnsupported = "inject-type-unsupported";
// mempool.hpp add_inject gate
inline constexpr const char* Oversize = "inject-oversize";
inline constexpr const char* ScriptCheckUnarmed = "inject-script-check-unarmed";
inline constexpr const char* AlreadyKnown = "inject-already-known";
inline constexpr const char* AlreadyConfirmed = "inject-already-confirmed";
inline constexpr const char* Unpriceable = "inject-unpriceable";
inline constexpr const char* Bip68Unsupported = "inject-bip68-unsupported";
inline constexpr const char* BadVoutRange = "inject-bad-txns-vout-range";
inline constexpr const char* BadVersionOrType = "inject-bad-txns-version-or-type";
inline constexpr const char* FeeAboveMax = "inject-fee-above-max";
inline constexpr const char* ScriptInvalid = "inject-script-invalid";
inline constexpr const char* SpentShapedOutput = "inject-spent-shaped-output";
inline constexpr const char* GateUnknown = "inject-unknown";
// tx_inject_pool.hpp
inline constexpr const char* PoolDuplicate = "inject-pool-duplicate";
inline constexpr const char* PoolFull = "inject-pool-full";
inline constexpr const char* PoolTotalBytes = "inject-pool-total-bytes-exceeded";
inline constexpr const char* PoolOversize = "inject-pool-oversize";
inline constexpr const char* PoolUnknown = "inject-pool-unknown";
// inject_rate_limiter.hpp (local, then aggregate-peer scope)
inline constexpr const char* RateLimitedCount = "inject-rate-limited-count";
inline constexpr const char* RateLimitedBytes = "inject-rate-limited-bytes";
inline constexpr const char* RateLimitedUnknown = "inject-rate-limited-unknown";
inline constexpr const char* RateLimitedPeersCount = "inject-rate-limited-peers-count";
inline constexpr const char* RateLimitedPeersBytes = "inject-rate-limited-peers-bytes";
inline constexpr const char* RateLimitedPeersUnknown = "inject-rate-limited-peers-unknown";
// inject_sandbox.hpp
inline constexpr const char* SandboxTooManyInputs = "inject-sandbox-too-many-inputs";
inline constexpr const char* SandboxTooManyOutputs = "inject-sandbox-too-many-outputs";
inline constexpr const char* SandboxScriptsigTooLarge = "inject-sandbox-scriptsig-too-large";
inline constexpr const char* SandboxTotalScriptsigTooLarge = "inject-sandbox-total-scriptsig-too-large";
inline constexpr const char* SandboxTooManySigops = "inject-sandbox-too-many-sigops";
inline constexpr const char* SandboxUnknown = "inject-sandbox-unknown";
// Reserved (runtime-submit design; not on master):
inline constexpr const char* ImmatureCoinbaseInput = "inject-immature-coinbase-input";
inline constexpr const char* PrevoutPrefix = "inject-prevout-";
inline constexpr const char* OraclePrefix = "inject-oracle-";
// The submit route's own 403 body cause.
inline constexpr const char* BadToken = "missing or invalid control token";
} // namespace cause

// Every cause name the master node can put in a submit reply (the list above,
// without the reserved prefixes), for the KAT drift check.
const char* const* node_cause_names(size_t& count);

struct Outcome {
    State next = State::Ready;
    RetryClass retry = RetryClass::None;
    std::string cause;           // node cause, or a transport / HTTP label
    std::string why;             // operator-facing text
    bool alert = false;          // raise an operator alert
    bool scheduler_bug = false;  // should be unreachable after the local pre-flight
    std::optional<std::string> txid_echo;
    std::optional<bool> armed;
    int http = 0;                // 0 = transport error
    bool recognized = true;      // false: a cause outside the node vocabulary
};

// Classify a named cause as carried by a 200/409/422 reply body.
Outcome classify_cause(const std::string& cause, int http_status);

// Classify a whole reply. `our_txid` is compared with the node's txid on a 200
// ok (a mismatch refuses the item: the node accepted a different tx).
Outcome classify_submit(const HttpReply& r, const std::string& our_txid);

// Seconds to wait before the next attempt. `count` is the 1-based number of
// consecutive failures of that class (Backoff: 30, 60, 120, 300, 300...);
// `window_sec` is the node's rate-limit window (RateWindow: window + 15).
int64_t backoff_seconds(RetryClass c, int64_t count, int64_t window_sec = 60);

// The unpriceable retry budget: retries 1..3 wait 600 s, the 4th refuses.
inline constexpr int64_t kUnpriceableRetries = 3;

} // namespace c2w::companion::sched
