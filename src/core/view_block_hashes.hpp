// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The full hashes of found blocks whose shares are in a sharechain view.
//
// /sharechain/window and /sharechain/delta carry `block_hashes`, the full
// share hashes the explorer marks a cell by (a 16-hex short hash cannot tell
// DASH or BTC shares apart: their share hash is a PoW hash with leading
// zeros). The found-block ledger is uncapped and grows for the life of the
// node, so a view sends only the ledger entries whose shares it carries: the
// window its own, a delta the new shares since the client's cursor.

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_set>

namespace core {

/// The entries of `found` (full share hashes, ledger order) whose shares are
/// rows of `shares` (a view's share rows, each with its full hash "H").
template <typename FoundHashes>
inline nlohmann::json found_block_hashes_in(const nlohmann::json& shares, const FoundHashes& found)
{
    std::unordered_set<std::string> in_view;
    if (shares.is_array()) {
        for (const auto& s : shares) {
            const auto it = s.find("H");
            if (it != s.end() && it->is_string())
                in_view.insert(it->template get<std::string>());
        }
    }
    nlohmann::json out = nlohmann::json::array();
    if (in_view.empty())
        return out;
    for (const auto& h : found) {
        const std::string hs(h);
        if (in_view.count(hs) != 0)
            out.push_back(hs);
    }
    return out;
}

} // namespace core
