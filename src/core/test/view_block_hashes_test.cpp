// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::found_block_hashes_in: the `block_hashes` of a sharechain view are the
// found blocks whose shares the view carries, matched on the full hash. The
// found-block ledger is uncapped; a view never resends it whole, and a share
// that only shares a block's 16-hex short hash is not one of them.

#include <gtest/gtest.h>

#include <core/view_block_hashes.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>


TEST(ViewBlockHashes, OnlyTheFoundBlocksWhoseSharesTheViewCarries)
{
    const std::string a = std::string(14, '0') + "21" + std::string(48, 'a');
    const std::string b = std::string(14, '0') + "21" + std::string(48, 'b');   // a's 16-hex prefix
    const std::string c = std::string(14, '0') + "35" + std::string(48, 'c');
    nlohmann::json rows = nlohmann::json::array();
    for (const auto& h : {b, c})
        rows.push_back({{"h", h.substr(0, 16)}, {"H", h}});
    const std::vector<std::string> ledger{a, c};
    EXPECT_EQ(core::found_block_hashes_in(rows, ledger), nlohmann::json::array({c}))
        << "a is not in the view, though b shares its short hash";
    EXPECT_TRUE(core::found_block_hashes_in(nlohmann::json::array(), ledger).empty());
    EXPECT_TRUE(core::found_block_hashes_in(rows, std::vector<std::string>{}).empty());
}
