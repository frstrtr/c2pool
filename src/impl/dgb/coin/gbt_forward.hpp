#pragma once

// dgb::coin::select_work_template — Stage 4b/4c work-template selector SSOT.
//
// Two sources can produce the stratum work template served by
// DGBWorkSource::get_current_work_template():
//
//   1. The EMBEDDED Scrypt-only path (build_work_template): truthful for the
//      fields a Scrypt-only header walk can derive (coinbasevalue via the #207
//      subsidy SSOT, curtime, mintime, conditional previousblockhash), but it
//      deliberately HOLDS BACK bits (MultiShield V4 is a global 5-algo window a
//      Scrypt-only walk cannot reconstruct == V37) and pins version to the
//      Scrypt lane. It fabricates nothing.
//
//   2. The external DIGIBYTED getblocktemplate result (RPC-connected isolated
//      testnet / mainnet path). This IS the authoritative consensus template:
//      real bits, version, previousblockhash and transactions[]. The DGB plan
//      keeps the digibyted RPC path as a first-class source that MUST PERSIST.
//
// When a daemon GBT is present it is authoritative and forwarded verbatim,
// EXCEPT coinbasevalue: that is re-resolved through the ONE #207
// resolve_coinbase_value SSOT (the daemon value passed as the gbt override, so
// it is returned authoritative) — this guarantees the embedded subsidy schedule
// and the daemon reward can never SILENTLY diverge (a mismatch is observable at
// one choke point, not two independent derivations). When absent (nullopt), the
// embedded template passes through UNCHANGED — byte-identical to the pre-wire
// path, so an operator running without an RPC sink sees no behavioural change.

#include <optional>
#include <cstdint>

#include <nlohmann/json.hpp>

#include <core/pow.hpp>                            // core::SubsidyFunc
#include <impl/dgb/coin/embedded_coinbase_value.hpp>  // resolve_coinbase_value (#207 SSOT)

namespace dgb::coin {

inline nlohmann::json select_work_template(
    const core::SubsidyFunc&             subsidy_func,
    uint32_t                             next_height,
    nlohmann::json                       embedded_template,
    const std::optional<nlohmann::json>& daemon_gbt)
{
    // No external RPC sink wired -> embedded Scrypt-only template unchanged.
    if (!daemon_gbt.has_value())
        return embedded_template;

    // Daemon GBT is the authoritative template on the RPC-connected path.
    nlohmann::json out = *daemon_gbt;

    // Reconcile the reward through the single #207 SSOT. A present daemon
    // coinbasevalue is authoritative and returned verbatim, but routing it
    // through resolve_coinbase_value keeps ONE definition of the reward for
    // both paths. A malformed/absent field falls back to the embedded subsidy
    // derivation (never fabricates from a bad daemon value).
    std::optional<uint64_t> daemon_coinbasevalue;
    if (auto it = out.find("coinbasevalue");
        it != out.end() && it->is_number_unsigned())
        daemon_coinbasevalue = it->get<uint64_t>();

    out["coinbasevalue"] = resolve_coinbase_value(
        subsidy_func, next_height, /*total_fees=*/0, daemon_coinbasevalue);

    return out;
}

} // namespace dgb::coin
