// SPDX-License-Identifier: AGPL-3.0-or-later
//
// src/core/config_endpoint.hpp
//
// Control-plane M1 (SAFE half): read-only serialization of the resolved launch
// config + the param catalog schema over the existing web server, plus DORMANT
// scaffolding for the write path.
//
// Qt-free, boost-free (nlohmann::json like the rest of the web layer). This
// module is the node-side surface behind:
//
//   GET  /api/config          -> resolved_config_json()   (loopback-only)
//   GET  /api/config/schema   -> catalog_schema_json()    (loopback-only)
//   POST /api/config/apply     -> 503 {"armed":false}     (INERT this pass)
//
// SAFETY POSTURE (M1 safe/additive split):
//   * The two GET endpoints are pure reads of compiled-in / startup-resolved
//     data. No locks, no node-state coupling. They report the L0..L2 launch
//     resolution ONLY — NOT live node state (a documented M1b follow-up; see
//     resolved_config_json()).
//   * validate_apply_batch() below is a PURE function, unit-tested, and NOT
//     exposed over HTTP. It exists so the reviewed apply oracle can be armed in
//     the money/write pass without redesign. It NEVER mutates a running node.
//   * ParamApplier is declared but NOTHING is registered and it is NEVER
//     invoked this pass.
//   * The POST route answers an unconditional HTTP 503 (see http_session.cpp).
//     Arming live runtime mutation is an OPERATOR-TAP change that must land the
//     control-token + two-phase nonce + server-side AddressValidator together
//     (plan: "the endpoint is never live without the gate").
#ifndef C2POOL_CORE_CONFIG_ENDPOINT_HPP
#define C2POOL_CORE_CONFIG_ENDPOINT_HPP

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "param_catalog.hpp"
#include "settings_file.hpp"

namespace c2pool::config_endpoint {

// Schema version of the /api/config[/schema] response shapes. Bump only on a
// breaking wire change so an old qt can detect skew (plan risk 10).
inline constexpr int kSchemaVersion = 1;

// ---------------------------------------------------------------------------
// Published launch-config snapshot (process-global, immutable after publish).
//
// Each main lifts its block-local ResolvedConfig into a shared_ptr<const ...>
// and calls publish_resolved() AFTER wire_settings succeeds (and after the
// --dump-resolved-config early-exit, so the dump lane never reaches it). Web
// threads only READ the snapshot; because it is const and never mutated in
// place, no lock is needed.
//
// M1b REQUIREMENT (write path): the future runtime-apply path MUST swap in a
// new shared_ptr snapshot atomically — it must NEVER mutate the published
// ResolvedConfig in place, or web readers would race a half-written map.
void publish_resolved(std::shared_ptr<const settings::ResolvedConfig> snapshot,
                      catalog::CoinBit coin,
                      std::string settings_path);

// True once a snapshot has been published. A main that never publishes leaves
// the endpoint unwired -> the HTTP layer answers 404 (harmless fail-safe).
bool is_published();

// ---------------------------------------------------------------------------
// Serializers (pure reads).
//
// resolved_config_json(): the full resolved LAUNCH config, one entry per
// catalog row applicable to the published coin's mask. Fields per key mirror
// the plan (§3): value/tri, type, section, source layer, mutability class,
// money flag, pending_restart. This is the L0..L2 startup resolution, NOT live
// node state; tri-state posture levers report their honest Unset/True/False
// (never a posture-resolved effective value -- that is a documented M1b
// follow-up). `pending_restart` is always false this pass (nothing is staged).
//
// Returns an {"error":...} object if called before publish (defensive; the
// HTTP layer gates on is_published() first).
nlohmann::json resolved_config_json();

// catalog_schema_json(): the FULL param catalog table (all_params(), every
// coin) as JSON, so one implementation serves every coin; qt filters by mask in
// M2. Pure compiled constants -- callable even before publish.
nlohmann::json catalog_schema_json();

// ---------------------------------------------------------------------------
// DORMANT write-path scaffolding (reviewed-but-inert this pass).
//
// validate_apply_batch() is the core-level apply oracle. It is a PURE function
// over (requested changes, coin, current resolved config): it validates the
// whole batch atomically and partitions it, but APPLIES NOTHING. It is NOT
// reachable over HTTP this pass. When the money/write pass arms the POST route,
// it wires THIS function in (behind the control-token + two-phase nonce +
// AddressValidator), and the referee invariant below is its single source.
enum class BatchVerdict {
    Ok,                   // every key valid; partitioned into live/restart/money
    RejectUnknownKey,     // canon not in catalog, or not applicable to the coin
    RejectReadonly,       // a compile_time_readonly row cannot be written
    RejectPairRequired,   // a pair(path,hex) half arrived without its partner
    RejectRefereeDisarm,  // serving ON while the self-validation referee is OFF
    RejectValidator,      // a per-key catalog validator rejected the value
};

const char* batch_verdict_name(BatchVerdict v);

struct BatchResult {
    BatchVerdict verdict = BatchVerdict::Ok;
    std::string  message;         // human-readable reason (empty on Ok)
    std::string  offending_key;   // the key that failed (empty on Ok)
    // Partition of the batch (meaningful only when verdict == Ok). MONEY keys
    // are separated OUT for the two-phase nonce flow -- never applied inline.
    std::vector<std::string> live_keys;
    std::vector<std::string> restart_keys;
    std::vector<std::string> money_keys;
    // ALWAYS false this pass: the oracle validates + partitions but the write
    // path is not armed. Pinned by the KAT so arming is a reviewed change.
    bool applied = false;

    bool ok() const { return verdict == BatchVerdict::Ok; }
};

// Validate + partition a batch of {canonical_name -> value} changes against the
// catalog and the cross-param referee invariant, using `current` as the base
// resolution (so a pair half already set in the file/CLI satisfies its
// partner). One invalid key rejects the WHOLE batch (atomicity). Applies
// nothing. `coin` selects the applicability mask.
BatchResult validate_apply_batch(const std::map<std::string, std::string>& changes,
                                 catalog::CoinBit coin,
                                 const settings::ResolvedConfig& current);

// ParamApplier: the runtime setter registry interface. DECLARED ONLY -- nothing
// is registered and nothing invokes it this pass. The money/write pass seeds it
// from the existing process-global setters (set_peer_latency_score_enabled,
// set_fresh_datum_race_enabled/_k, set_embedded_getmnlistd_tracker_enabled) +
// the stratum/log/ops/tx-lever setters.
class ParamApplier {
public:
    using Setter = std::function<bool(const std::string& value)>;
    // Register a live setter for a canonical key. (Unused this pass.)
    void register_setter(const std::string& canon, Setter fn);
    bool has(const std::string& canon) const;
private:
    std::map<std::string, Setter> setters_;
};

} // namespace c2pool::config_endpoint

#endif // C2POOL_CORE_CONFIG_ENDPOINT_HPP
