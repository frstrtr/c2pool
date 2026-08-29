// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <nlohmann/json.hpp>

#include <set>
#include <string>

// ---------------------------------------------------------------------------
// bch::coin::collect_softfork_names -- ported from src/impl/btc/coin/softfork_check.hpp.
//
// >>> BCH NOTE: the softfork gate is informational/vacuous on BCH <<<
// bch::PoolConfig::SOFTFORKS_REQUIRED is EMPTY (BCH activations are MTP-based,
// not BIP9/GBT-signalled), so the missing-fork check in rpc.cpp always passes.
// This collector is kept for parity + diagnostics: BCHN's getblockchaininfo
// still reports a "softforks" object, and harvesting its names is harmless.
//
// Handles the formats BCHN/bitcoind variants produce:
//   - Array of objects:  [{"id":"csv",...}, ...]
//   - Array of strings:  ["csv", ...]
//   - Object with keys:  {"csv":{...}, ...}   (BCHN getblockchaininfo style)
// ---------------------------------------------------------------------------

namespace bch::coin {

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

} // namespace bch::coin