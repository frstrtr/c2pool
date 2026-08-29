// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure, unit-testable bookkeeping for the known-transaction pool that backs
// share broadcast (remember_tx forwarding). Factored out of NodeImpl so the
// retention/eviction semantics can be exercised without a live node.
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
//     It is coin-generic, so it now LIVES IN core/known_txs_backing.hpp and is
//     merely re-exported below; retain_template_txs() stays here because the
//     template-set registration it serves is DASH-only (the other lanes fill
//     m_known_txs from inbound peer remember_tx alone).

#pragma once

#include <cstddef>
#include <deque>
#include <set>
#include <vector>

#include <core/known_txs_backing.hpp>
#include <core/uint256.hpp>

namespace dash {

// all_txs_backable is coin-generic and now lives in core/known_txs_backing.hpp,
// so the LTC/DOGE, BTC, DGB and BCH lanes share ONE definition instead of each
// growing a copy. Re-exported here so every existing dash::all_txs_backable call
// site keeps resolving unchanged — same function, same semantics, one home.
using core::all_txs_backable;

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

// #950 STANDING remembered-set seed. Canonical p2pool keeps a per-peer standing
// remembered set — its dashboard "txpool" for us (web.py:673 remembered_txs_size)
// is fed ONLY by remember_tx BODIES, never by have_tx adverts — and seeds a
// freshly connected peer with the WHOLE current mining-tx set (p2p.py:269). It is
// bounded by max_remembered_txs_size = 2 500 000 bytes (p2p.py:30): a canonical
// peer DISCONNECTS if an inbound remember_tx pushes its remembered_txs_size over
// that bound (p2p.py:488), so the cap here is an interop-safety limit, not a
// nicety. c2pool held NO standing set — remember_tx went out only as a transient
// bracket inside sendShares (canonical-faithful, p2p.py:388) — so peers saw
// txpool == 0 (#950). This selects, from the txs we already hold, the prefix that
// fits under `cap` bytes to seed the peer. size_of(tx) MUST mirror canonical's
// `100 + packed_size(tx)` accounting so the running sum never overshoots the cap.
template <typename TxMap, typename SizeFn>
inline std::vector<typename TxMap::key_type>
select_standing_remember(const TxMap& known_txs, std::size_t cap, SizeFn size_of)
{
    std::vector<typename TxMap::key_type> chosen;
    std::size_t acc = 0;
    for (const auto& kv : known_txs) {
        const std::size_t sz = size_of(kv.second);
        if (acc + sz > cap)
            break;   // stop BEFORE the peer's cap — overshoot => it disconnects us
        acc += sz;
        chosen.push_back(kv.first);
    }
    return chosen;
}

} // namespace dash
