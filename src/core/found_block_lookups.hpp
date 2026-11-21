// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_lookups.hpp -- a found block's own difficulty and time, by its
// hash, off an embedded header chain. Display only.
//
// A block's network difficulty is what its header's nBits say. The found-block
// ledger used to store the node's reading of the live template at RECORD time
// instead, which is the difficulty of another moment for any block recorded
// after the fact (a sharechain replay, a win learned from a peer) and nothing
// at all when no template was cached yet. LTC and DASH wired a by-hash header
// lookup into MiningInterface::set_block_field_lookups; this is the same pair
// of lookups for every lane whose header chain answers get_header(hash) with
// an entry carrying `header.m_bits`, `header.m_timestamp` and `height`.

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace core {

/// (difficulty by block hash, header time by block hash); each returns 0 for
/// a block the chain does not hold. `hc` must outlive the lookups.
template <class HeaderChainT>
inline std::pair<std::function<double(const std::string&)>,
                 std::function<uint32_t(const std::string&)>>
header_chain_block_lookups(const HeaderChainT* hc)
{
    auto difficulty = [hc](const std::string& block_hash_hex) -> double {
        if (!hc) return 0.0;
        uint256 h;
        h.SetHex(block_hash_hex);
        auto e = hc->get_header(h);
        if (!e) return 0.0;
        return chain::target_to_difficulty(chain::bits_to_target(e->header.m_bits));
    };
    auto time = [hc](const std::string& block_hash_hex) -> uint32_t {
        if (!hc) return 0;
        uint256 h;
        h.SetHex(block_hash_hex);
        auto e = hc->get_header(h);
        return e ? static_cast<uint32_t>(e->header.m_timestamp) : 0;
    };
    return {std::move(difficulty), std::move(time)};
}

/// The height of a block by its hash (MiningInterface::set_block_height_lookup);
/// 0 for a block the chain does not hold. `hc` must outlive the lookup.
template <class HeaderChainT>
inline std::function<uint64_t(const std::string&)>
header_chain_height_lookup(const HeaderChainT* hc)
{
    return [hc](const std::string& block_hash_hex) -> uint64_t {
        if (!hc) return 0;
        uint256 h;
        h.SetHex(block_hash_hex);
        auto e = hc->get_header(h);
        return e ? static_cast<uint64_t>(e->height) : 0;
    };
}

} // namespace core
