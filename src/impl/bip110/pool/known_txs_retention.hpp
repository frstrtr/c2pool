// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure, unit-testable bookkeeping for the known-transaction pool that backs share
// broadcast (remember_tx forwarding) — bip110 lane copy of
// src/impl/btc/known_txs_retention.hpp (namespace-swapped btc -> bip110::pool).
// retain_template_txs() = rolling-window retention with template-identity dedup;
// all_txs_backable()/select_backable_shares()/partition_backable() = the canonical
// broadcast gate (a share is sent only when we hold every referenced new-tx so
// remember_tx can always forward them); broadcast_and_mark() = the F2 marking
// policy (mark only what a peer actually accepted). Tx-forwarding only — no
// consensus/mint state. See the BTC header for the full derivation.

#pragma once

#include <cstddef>
#include <deque>
#include <set>
#include <vector>

#include <core/uint256.hpp>

namespace bip110::pool {

// Retain the tx set of a newly-registered template in a rolling window of the last
// `cap` DISTINCT templates, inserting its tx bytes into `known_txs`. F1 dedup: if
// this template's tx set is already retained, its recency is refreshed (moved to
// back) and no new slot is consumed. A tx is erased from `known_txs` only once it
// has fallen out of EVERY retained set.
template <typename TxMap, typename Tx>
inline void retain_template_txs(std::deque<std::set<uint256>>& recent_sets,
                                TxMap& known_txs,
                                const std::vector<uint256>& hashes,
                                const std::vector<Tx>& txs,
                                std::size_t cap)
{
    if (cap == 0)
        return;

    std::set<uint256> new_set(hashes.begin(), hashes.end());

    for (auto it = recent_sets.begin(); it != recent_sets.end(); ++it) {
        if (*it == new_set) {
            if (std::next(it) != recent_sets.end()) {
                std::set<uint256> refreshed = std::move(*it);
                recent_sets.erase(it);
                recent_sets.push_back(std::move(refreshed));
            }
            return;
        }
    }

    const std::size_t n = std::min(hashes.size(), txs.size());
    for (std::size_t i = 0; i < n; ++i)
        known_txs.insert_or_assign(hashes[i], txs[i]);
    recent_sets.push_back(std::move(new_set));

    while (recent_sets.size() > cap) {
        const std::set<uint256> evicted = std::move(recent_sets.front());
        recent_sets.pop_front();
        for (const auto& h : evicted) {
            bool still_retained = false;
            for (const auto& s : recent_sets) {
                if (s.count(h)) { still_retained = true; break; }
            }
            if (!still_retained)
                known_txs.erase(h);
        }
    }
}

// True iff every hash in `tx_hashes` is present in `held` (the bytes we hold). The
// canonical broadcast gate: a share is backable only when we can forward every
// referenced tx.
template <typename Held>
inline bool all_txs_backable(const std::vector<uint256>& tx_hashes,
                             const Held& held)
{
    for (const auto& h : tx_hashes)
        if (held.find(h) == held.end())
            return false;
    return true;
}

// F3 send-gate over a batch: returns the indices of shares that are backable.
template <typename Held>
inline std::vector<std::size_t> select_backable_shares(
    const std::vector<std::vector<uint256>>& per_share_refs,
    const Held& held)
{
    std::vector<std::size_t> out;
    out.reserve(per_share_refs.size());
    for (std::size_t i = 0; i < per_share_refs.size(); ++i)
        if (all_txs_backable(per_share_refs[i], held))
            out.push_back(i);
    return out;
}

// Batch form of the F3 gate. Keeps in `shares` only entries every one of whose
// referenced new-tx hashes we hold, and returns how many were dropped.
template <typename Share, typename Held, typename HashesOf>
inline std::size_t partition_backable(std::vector<Share>& shares,
                                      const Held& held,
                                      HashesOf hashes_of)
{
    std::vector<Share> sendable;
    sendable.reserve(shares.size());
    std::size_t skipped = 0;
    for (auto& share : shares) {
        if (all_txs_backable(hashes_of(share), held))
            sendable.push_back(std::move(share));
        else
            ++skipped;
    }
    shares.swap(sendable);
    return skipped;
}

// F2 marking policy. Offers the batch to every peer via `send(peer)` — which
// returns the hashes it ACTUALLY wrote to that peer — and marks in `marked` only
// the hashes that reached at least one peer. Returns that count.
template <typename MarkedSet, typename Peers, typename SendFn>
inline std::size_t broadcast_and_mark(MarkedSet& marked, Peers& peers,
                                      const std::vector<uint256>& to_send,
                                      SendFn send)
{
    if (to_send.empty())
        return 0;

    std::set<uint256> actually_sent;
    for (auto& entry : peers) {
        const std::vector<uint256> sent = send(entry.second);
        actually_sent.insert(sent.begin(), sent.end());
    }
    for (const auto& h : actually_sent)
        marked.insert(h);
    return actually_sent.size();
}

} // namespace bip110::pool
