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

} // namespace dgb::coin
