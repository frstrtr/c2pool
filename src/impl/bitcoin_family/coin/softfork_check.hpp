#pragma once

#include <nlohmann/json.hpp>

#include <set>
#include <string>

namespace bitcoin_family::coin {

/**
 * Populate `out` with all softfork names found in a single getblockchaininfo
 * field value (either the "softforks" or "bip9_softforks" entry).
 *
 * Handles three formats produced by different litecoind / bitcoind versions:
 *   - Array of objects:  [{"id":"segwit",...}, ...]         (modern litecoind)
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

} // namespace bitcoin_family::coin
