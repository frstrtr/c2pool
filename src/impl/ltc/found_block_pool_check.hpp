// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_pool_check.hpp -- is an LTC block a POOL block? The check behind
// core::found_block_import::Source::pays_pool (--import-found-blocks). Display
// only.
//
// Every p2pool coinbase carries the donation output, even at a value of 0
// (p2pool data.py generate_transaction keeps DONATION_SCRIPT in the outputs
// whatever its amount); no other coinbase pays that script. A block found
// before the V36 switch pays the pre-V36 DONATION_SCRIPT, one found after it
// the V36 COMBINED_DONATION_SCRIPT: both are the pool's.
//
// The block's body is at hand only in the explorer's raw-block store, for the
// last explorer_depth_ltc blocks; for anything older the answer is "not
// known" (nullopt) and the import trusts its source on this.

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/config_pool.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ltc {
namespace found_block {

/// Does the block's coinbase pay p2pool's donation script (either one)?
/// nullopt: the block holds no transaction.
inline std::optional<bool> coinbase_pays_donation(const coin::BlockType& block)
{
    if (block.m_txs.empty())
        return std::nullopt;
    auto is = [](const std::vector<unsigned char>& s, const auto& script) {
        return s.size() == script.size() && std::equal(s.begin(), s.end(), script.begin());
    };
    for (const auto& out : block.m_txs.front().vout) {
        const auto& s = out.scriptPubKey.m_data;
        if (is(s, PoolConfig::COMBINED_DONATION_SCRIPT) || is(s, PoolConfig::DONATION_SCRIPT))
            return true;
    }
    return false;
}

/// Source::pays_pool over a raw-block store keyed by height (the explorer's
/// UTXOViewDB::get_raw_block). The body stored at the height counts only if
/// it is the block's: the merkle root of the header chain's entry for the
/// hash. Both pointers must outlive the function.
template <class HeaderChainT, class RawBlockDbT>
std::function<std::optional<bool>(const std::string&, uint64_t)>
raw_block_pool_check(const HeaderChainT* hc, RawBlockDbT* db)
{
    return [hc, db](const std::string& hash_hex, uint64_t height) -> std::optional<bool> {
        if (!hc || !db || height == 0 || height > UINT32_MAX)
            return std::nullopt;
        uint256 h;
        h.SetHex(hash_hex);
        const auto entry = hc->get_header(h);
        if (!entry)
            return std::nullopt;
        const auto raw = db->get_raw_block(static_cast<uint32_t>(height));
        if (!raw)
            return std::nullopt;
        coin::BlockType block;
        try {
            PackStream ps(*raw);
            ps >> block;
        } catch (...) {
            return std::nullopt;
        }
        if (block.m_merkle_root != entry->header.m_merkle_root)
            return std::nullopt;   // another block's body (a reorg): cannot tell
        return coinbase_pays_donation(block);
    };
}

} // namespace found_block
} // namespace ltc
