// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Bounded, recency-preserving eviction for the node-level known-tx relay cache
// (m_known_txs) that backs share broadcast (remember_tx forwarding).
//
// Shared by the LTC / DGB / BCH / BTC node lanes. These coins populate
// m_known_txs ONLY from inbound peer remember_tx (they have no template-set
// registration), so the DASH template-window helper (known_txs_retention.hpp)
// does not apply. What they share is the bug: when the cache exceeds its cap a
// WHOLESALE clear() drops every forwardable tx byte at once, so a subsequent
// share relay referencing a just-dropped tx can no longer remember_tx-forward it
// and the receiving canonical peer disconnects with "referenced unknown
// transaction" (p2p.py:404) -> sharechain fragmentation / non-convergence.
//
// The fix replaces the wholesale clear() with oldest-first eviction down to the
// cap, preserving the most-recently-learned txs (the ones recent shares are most
// likely to reference). A parallel insertion-order deque records recency; the
// map holds the bytes.
//
// Reward-safety: tx-forwarding only. No consensus / subsidy / coinbase / payee
// state is touched, and the won-block and local-mint paths never read or write
// m_known_txs in these coins.

#pragma once

#include <cstddef>
#include <deque>

namespace core {

// Evict oldest known-txs until the map holds at most `cap` entries, preserving
// the most-recently-inserted (the entries most likely to be referenced by a
// recent share we may still have to relay). `order` is the insertion-order
// sidecar recorded at each new insert (front = oldest, back = newest).
//
// Desync-tolerant by construction: a key present in `order` but already absent
// from `known_txs` (evicted by some other path) erases as a harmless no-op and
// is still popped, so the loop makes progress on `order` shrinking even if the
// map size is unchanged. Leading stale entries are then pruned so `order` cannot
// accrete tombstones unbounded relative to the live map.
//
// cap == 0 degenerates to emptying the map (the old wholesale semantics),
// preserved so a zero cap is never a foot-gun.
template <typename Map, typename Key>
inline void evict_known_txs_to_cap(Map& known_txs, std::deque<Key>& order,
                                   std::size_t cap)
{
    while (known_txs.size() > cap && !order.empty()) {
        const Key oldest = order.front();
        order.pop_front();
        known_txs.erase(oldest); // no-op if already gone (desync tolerance)
    }
    // Bound deque slack: drop leading keys no longer in the map even when
    // already under cap, so `order` tracks the live set rather than tombstones.
    while (!order.empty() && known_txs.find(order.front()) == known_txs.end())
        order.pop_front();
}

} // namespace core
