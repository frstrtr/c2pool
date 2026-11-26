// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bip110::coin::SideBodies -- block bodies the own-UTXO view could not connect
// when they arrived: a competing block at the view's height, one of a branch
// the header chain does not follow yet, one above a gap. main_bip110.cpp keeps
// the last few and, after each connect and after the tip-changed handler rolls
// the view back to a fork, connects those that are now the active chain's next
// block. Without it a reorg onto a branch whose blocks were already received
// would stop the view at the fork: the coin peer pool asks for a body once and
// does not ask again for one it received (it only holds a child for its
// parent), and the connect takes only the active chain's contiguous next block.
// IO thread only.

#include "block.hpp"
#include "header_chain.hpp"   // block_hash

#include <core/uint256.hpp>

#include <cstddef>
#include <deque>
#include <utility>

namespace bip110::coin {

class SideBodies {
public:
    explicit SideBodies(size_t max = 8) : m_max(max) {}

    /// Keep `block`, newest last; a block already kept is not kept twice; at
    /// the bound the oldest is dropped.
    void keep(const BlockType& block)
    {
        const uint256 id = block_hash(block);
        for (const auto& kept : m_bodies)
            if (kept.first == id)
                return;
        if (m_max == 0)
            return;
        if (m_bodies.size() >= m_max)
            m_bodies.pop_front();
        m_bodies.emplace_back(id, block);
    }

    /// Offer the kept bodies to `try_connect` (bool(const BlockType&): true if
    /// it connected the block) until none connects; a connected one is
    /// dropped. Returns the number connected.
    template <typename TryConnect>
    size_t connect_ready(const TryConnect& try_connect)
    {
        size_t connected = 0;
        for (bool progress = true; progress;) {
            progress = false;
            for (auto it = m_bodies.begin(); it != m_bodies.end(); ++it) {
                if (try_connect(it->second)) {
                    m_bodies.erase(it);
                    ++connected;
                    progress = true;
                    break;
                }
            }
        }
        return connected;
    }

    size_t size() const { return m_bodies.size(); }
    bool holds(const uint256& id) const
    {
        for (const auto& kept : m_bodies)
            if (kept.first == id)
                return true;
        return false;
    }

private:
    size_t m_max;
    std::deque<std::pair<uint256, BlockType>> m_bodies;
};

} // namespace bip110::coin
