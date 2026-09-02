// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Uniform access to a share's "new transaction hashes" list — bip110 lane copy of
// src/impl/btc/share_tx_refs.hpp (namespace-swapped btc -> bip110::pool). The
// v36-genesis chain carries the MergedMiningShare variant ONLY, which has neither
// m_tx_info nor m_new_transaction_hashes, so new_tx_hashes() resolves to the
// nullptr branch (correct: a v36 share carries no per-share new-tx list — jtoomim
// moved tx/fee validation to getblocktemplate for v34+). No consensus delta; the
// accessor exists so the node's F3 broadcast gate never silently no-ops on a
// member-name mismatch (the #880 class).

#pragma once

#include <vector>

#include <core/uint256.hpp>

namespace bip110::pool {

// Pointer to the share's new-transaction-hash list, or nullptr when this share
// variant carries none. A pointer (not a copy) so the broadcast hot path does no
// per-share allocation. Lifetime is the share object's.
template <typename ShareObj>
inline auto new_tx_hashes(ShareObj* obj)
{
    if constexpr (requires { obj->m_tx_info.m_new_transaction_hashes; })
        return &obj->m_tx_info.m_new_transaction_hashes;
    else if constexpr (requires { obj->m_new_transaction_hashes; })
        return &obj->m_new_transaction_hashes;
    else
        return static_cast<const std::vector<uint256>*>(nullptr);
}

// Compile-time pin: true iff the share variant exposes the list under the FLAT
// spelling the old probe assumed. Held false by the compile gate for the v36
// MergedMiningShare — if this ever becomes true, the flat branch handles it.
template <typename ShareObj>
inline constexpr bool has_flat_new_tx_hashes =
    requires(ShareObj* o) { o->m_new_transaction_hashes; };

// True iff the share variant nests the list inside m_tx_info.
template <typename ShareObj>
inline constexpr bool has_nested_new_tx_hashes =
    requires(ShareObj* o) { o->m_tx_info.m_new_transaction_hashes; };

} // namespace bip110::pool
