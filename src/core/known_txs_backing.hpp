// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Coin-generic tx-completeness gate for share broadcast ("F3"), hoisted out of
// impl/dash/known_txs_retention.hpp so every node lane consumes ONE definition.
//
// Canonical p2pool broadcasts a share together with the bytes of every new tx it
// references (remember_tx). A receiving canonical node that is handed a share
// referencing a transaction it does not hold DROPS THE CONNECTION
// ("referenced unknown transaction", p2p.py:404) -> sharechain isolation ->
// our shares orphan -> direct PPLNS loss.
//
// So a share may only be put on the wire when we HOLD the bytes of every
// referenced new tx (the node's m_known_txs relay cache), because that is the
// only way remember_tx can always forward them. Gating on the peer's have_tx
// advert instead is weaker than canonical: the advert can be stale (the peer may
// have dropped the tx), and sending hash-only for a tx the peer no longer holds
// is exactly the disconnect. The advert is therefore only good for choosing
// hash-vs-bytes encoding, never for deciding whether to send at all.
//
// Withholding costs no propagation: a share we could not back is by definition
// one we downloaded from the network (a sharereply carries no tx bytes), so the
// network already has it. What withholding buys is that we stay connected.
//
// Reward-safety: these helpers decide WHETHER a share is broadcast. They never
// touch share bytes, consensus, subsidy, coinbase, payee or minting state.

#pragma once

#include <cstddef>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

namespace core {

// True iff every hash in `tx_hashes` is present in `held` (the tx bytes we hold,
// i.e. the node's m_known_txs). An empty list is trivially backable — a share
// that references no new tx can never trigger the peer's unknown-tx disconnect.
//
// `held` needs only find()/end() (std::map, std::unordered_map, std::set...).
template <typename Held>
inline bool all_txs_backable(const std::vector<uint256>& tx_hashes,
                             const Held& held)
{
    for (const auto& h : tx_hashes)
        if (held.find(h) == held.end())
            return false;
    return true;
}

// F3 gate applied to a batch: drop from `shares` every entry we cannot back,
// preserving order. Returns the number dropped (for logging / accounting).
//
// `tx_hashes_of(share)` must return a pointer to that share's new-tx-hash vector,
// or nullptr when the share type carries no tx-hash list at all (then the share
// is trivially backable). A pointer — not a copy — so the hot broadcast path
// does no per-share allocation.
//
// The batch is filtered rather than rejected wholesale: one unbackable ancestor
// in a chain walk must not suppress the backable tip, which is the share our
// PPLNS credit actually depends on.
template <typename Share, typename TxHashesOf, typename Held>
inline std::size_t retain_backable_shares(std::vector<Share>& shares,
                                          TxHashesOf&& tx_hashes_of,
                                          const Held& held)
{
    std::vector<Share> keep;
    keep.reserve(shares.size());
    std::size_t dropped = 0;
    for (auto& share : shares) {
        const std::vector<uint256>* hashes = tx_hashes_of(share);
        if (hashes == nullptr || all_txs_backable(*hashes, held))
            keep.push_back(std::move(share));
        else
            ++dropped;
    }
    shares.swap(keep);
    return dropped;
}

// F2 companion: fold the per-peer "these hashes actually reached the wire"
// reports into the caller's already-broadcast de-dup set.
//
// The de-dup set must be advanced ONLY here, i.e. AFTER the peer loop. Marking a
// share at walk time (before the send) permanently retires a share the send then
// abandoned — a lock miss, an empty batch, zero peers connected, or the F3 gate
// above — and nothing ever re-pushes it, because the next walk breaks on the
// marked hash. That is a silently orphaned share and a direct PPLNS loss. An
// unmarked share simply gets retried by the next broadcast cycle.
template <typename MarkSet>
inline void commit_broadcast_marks(MarkSet& marked,
                                   const std::vector<uint256>& sent)
{
    for (const auto& h : sent)
        marked.insert(h);
}

} // namespace core
