#pragma once

#include <nlohmann/json.hpp>

#include <set>
#include <string>

namespace dgb::coin {

/**
 * Populate `out` with all softfork names found in a single getblockchaininfo
 * field value (either the "softforks" or "bip9_softforks" entry).
 *
 * Handles three formats produced by different digibyted versions:
 *   - Array of objects:  [{"id":"segwit",...}, ...]         (modern digibyted)
 *   - Array of strings:  ["segwit", "taproot", ...]         (compact form)
 *   - Object with keys:  {"segwit":{...}, "taproot":{...}}  (BIP9 style)
 */
inline void collect_softfork_names(const nlohmann::json& value,
                                   std::set<std::string>& out)
{
    if (value.is_array())
    {
        for (const auto& item : value)
        {
            if (item.is_object() && item.contains("id") && item["id"].is_string())
                out.insert(item["id"].get<std::string>());
            else if (item.is_string())
                out.insert(item.get<std::string>());
        }
    }
    else if (value.is_object())
    {
        for (auto it = value.begin(); it != value.end(); ++it)
            out.insert(it.key());
    }
}

/**
 * Populate `out` with deployment names from a getdeploymentinfo RPC result.
 *
 * DigiByte Core 8.26.2 (Bitcoin Core 26 base) no longer reports softfork
 * status under getblockchaininfo["softforks"]; that data moved to the
 * dedicated getdeploymentinfo RPC, whose "deployments" field is an object
 * keyed by deployment name, e.g.:
 *   {"deployments":{"csv":{...},"segwit":{...},"reservealgo":{...}, ...}}
 *
 * This reuses the object-keyed branch of collect_softfork_names so the
 * readiness gate observes identical name semantics across the Core-22 ->
 * Core-26 RPC drift (a name present here means the daemon knows that
 * deployment, exactly as a key under the legacy "softforks" object did).
 * No-op if the result lacks a "deployments" object (older daemons, or an
 * error result), so it is always safe to call as a fallback.
 */
inline void collect_deployment_names(const nlohmann::json& getdeploymentinfo_result,
                                     std::set<std::string>& out)
{
    if (getdeploymentinfo_result.is_object()
        && getdeploymentinfo_result.contains("deployments"))
    {
        collect_softfork_names(getdeploymentinfo_result["deployments"], out);
    }
}

/**
 * Algo deployments that a regtest digibyted legitimately never signals
 * (reservealgo, odo are DigiByte-unique) plus nversionbips. These are the only
 * names the readiness gate is ever permitted to drop from its required set.
 */
inline const std::set<std::string>& relaxable_algo_softforks()
{
    static const std::set<std::string> kRelaxable = {
        "reservealgo", "odo", "nversionbips"};
    return kRelaxable;
}

/**
 * Effective required-softfork set for NodeRPC::check(), given the connected
 * chain and an EXPLICIT, off-by-default developer relaxation flag.
 *
 *   - regtest           : always drops the relaxable algo deployments — a
 *                         regtest daemon cannot carry them and gating on them
 *                         would make the regtest won-block path unstartable.
 *   - non-main, non-regtest (e.g. an isolated tuned testnet):
 *                         drops the relaxable deployments ONLY when
 *                         dev_relax_algo_softforks is explicitly set. This is a
 *                         development boot-aid; it is off by default, so a real
 *                         testnet crossing-soak (which never sets it) keeps the
 *                         full SSOT requirement set and still demands active
 *                         forks.
 *   - main              : NEVER relaxed under any flag value. The dev flag
 *                         cannot weaken the readiness gate on mainnet.
 *
 * Pure (no I/O, no consensus surface) so it is exhaustively unit-testable
 * without a live daemon.
 */
inline std::set<std::string> compute_required_softforks(
    const std::set<std::string>& base,
    const std::string& chain,
    bool dev_relax_algo_softforks)
{
    std::set<std::string> required = base;
    // Hard floor: mainnet is never relaxed, regardless of the dev flag.
    if (chain == "main")
        return required;
    const bool relax = (chain == "regtest") || dev_relax_algo_softforks;
    if (relax)
        for (const auto& name : relaxable_algo_softforks())
            required.erase(name);
    return required;
}

} // namespace dgb::coin
