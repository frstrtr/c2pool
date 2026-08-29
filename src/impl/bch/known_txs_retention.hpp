// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure, unit-testable bookkeeping for the known-transaction pool that backs
// share broadcast (remember_tx forwarding). Ported to the BCH variant from
// src/impl/dash/known_txs_retention.hpp so the retention/eviction and
// broadcast-gate semantics can be exercised without a live node.
//
// Two concerns:
//   retain_template_txs() — the rolling-window retention with template-identity
//     dedup (code review F1): register_template_txs is invoked per producer-job
//     cache MISS, i.e. per (prev_share_hash, payout_script), NOT per template
//     rotation. A ~50-payout-script cluster therefore re-registers the SAME
//     template ~50 times on one tip; pushing each unconditionally collapses the
//     N-slot window to a single template within seconds. Dedup by the template's
//     tx-hash SET (its identity): a set already retained refreshes recency and
//     consumes NO new slot, so N re-registrations of one template use ONE slot
//     and the window holds N DISTINCT templates as intended.
//
//   all_txs_backable() — the canonical broadcast gate (F3): a share may be sent
//     only when we HOLD the bytes of every referenced new-tx (so remember_tx can
//     always forward them). This is what makes the "referenced unknown
//     transaction" disconnect unreachable by construction, and — paired with the
//     mint-time decline of shares whose txs are not retained — makes "every share
//     we mint/broadcast is backable" a by-construction invariant.
//
//   partition_backable() — the batch form of the gate, applied by send_shares()
//     to the shares it is about to write to one peer.
//
//   broadcast_and_mark() — the F2 marking policy: broadcast_share() may mark a
//     share "already shared" only AFTER a peer actually accepted it. Marking the
//     whole chain-walk up front (the pre-fix pattern) loses every share in a
//     batch that send_shares then abandons — the gate skipped it, the tracker
//     try_to_lock missed, or there were no peers — because the de-dup set then
//     breaks the walk forever and nothing re-pushes it.
//
// NOTE (de-dup): the same primitives now exist per-coin (btc/dgb/bch/dash) while
// the LTC lane hoists all_txs_backable into src/core/. Once both land, these
// per-coin headers should be collapsed onto that core hoist.

#pragma once

#include <cstddef>
#include <deque>
#include <set>
#include <vector>

#include <core/uint256.hpp>

namespace bch {

// Retain the tx set of a newly-registered template in a rolling window of the
// last `cap` DISTINCT templates, inserting its tx bytes into `known_txs`.
//
//   recent_sets : rolling history of distinct template tx-hash sets
//                 (front = oldest, back = newest).
//   known_txs   : uint256 -> tx map; needs insert_or_assign(k,v) and erase(k).
//   hashes/txs  : parallel arrays of the template's tx hashes and bytes.
//   cap         : number of DISTINCT templates to retain.
//
// A tx is erased from `known_txs` only once it has fallen out of EVERY retained
// set. F1 dedup: if this template's tx set is already retained, its recency is
// refreshed (moved to back) and no new slot is consumed.
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

    // F1 dedup by template identity (the tx-hash set). If this template is
    // already retained, refresh its recency (move to back) — no new slot, no
    // re-eviction. This is what stops ~50 payout-script re-registrations of one
    // template from evicting the rest of the window.
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

    // Distinct template: insert its tx bytes and consume a slot.
    const std::size_t n = std::min(hashes.size(), txs.size());
    for (std::size_t i = 0; i < n; ++i)
        known_txs.insert_or_assign(hashes[i], txs[i]);
    recent_sets.push_back(std::move(new_set));

    // Evict the oldest slots beyond `cap`; a tx is removed from `known_txs` only
    // once it is absent from EVERY remaining retained set.
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

// True iff every hash in `tx_hashes` is present in `held` (the bytes we hold,
// e.g. m_known_txs). The canonical broadcast gate: a share is backable — safe to
// send without risking the peer's "referenced unknown transaction" disconnect —
// only when we can forward every referenced tx.
template <typename Held>
inline bool all_txs_backable(const std::vector<uint256>& tx_hashes,
                             const Held& held)
{
    for (const auto& h : tx_hashes)
        if (held.find(h) == held.end())
            return false;
    return true;
}

// Batch form of the F3 gate. Keeps in `shares` only the entries every one of
// whose referenced new-tx hashes we hold, and returns how many were dropped.
// `hashes_of(share)` yields that share's referenced new-tx hashes.
//
// Skipping costs no propagation: a share we downloaded is by definition already
// on the network we fetched it from, and it will be re-offered on a later
// broadcast once its tx bytes arrive (F2 leaves it un-marked).
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
// returns the hashes it ACTUALLY wrote to that peer — and marks in `marked`
// only the hashes that reached at least one peer. Returns that count.
//
// The pre-fix code marked the whole chain-walk before calling send_shares, so a
// batch abandoned by every peer (gate skip, try_to_lock miss, empty peer set)
// stayed marked forever: the next broadcast_share walk breaks on the first
// marked hash and the share is never re-pushed. That is silent, permanent share
// loss with no retry path — a PPLNS-credit loss for whoever mined it.
template <typename MarkedSet, typename Peers, typename SendFn>
inline std::size_t broadcast_and_mark(MarkedSet& marked, Peers& peers,
                                      const std::vector<uint256>& to_send,
                                      SendFn send)
{
    if (to_send.empty())
        return 0;

    // NOTE: `to_send` is deliberately NOT what gets marked. Marking the offered
    // batch here is precisely the pre-fix bug this signature exists to make
    // un-writable by accident — only `send`'s report may be marked.
    std::set<uint256> actually_sent;
    for (auto& entry : peers) {
        const std::vector<uint256> sent = send(entry.second);
        actually_sent.insert(sent.begin(), sent.end());
    }
    for (const auto& h : actually_sent)
        marked.insert(h);
    return actually_sent.size();
}

} // namespace bch
