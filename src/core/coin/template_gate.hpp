// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin template gate: what a template on the tip may take from the
// mempool (#2136, #2137 S0).
//
// The selection prices the pool's txs against the UTXO view. A view behind
// the tip, beside it or above it cannot show that an input is still unspent
// at the tip: a tx the tip or one of its ancestors confirmed (cleaned once,
// then relayed again by a peer that had not seen the block) is priced
// against the older view and selected, and the block is one litecoind
// rejects (bad-txns-inputs-missingorspent). Likewise, before the tip's body
// ran through Mempool::remove_for_block the pool still holds the txs the tip
// confirmed. So the pool's txs enter a template only when
//   - the pool was cleaned for the tip, and
//   - the view's best block IS the tip (DOGE's utxo_view_prices for its
//     full set: complete at the tip).
// Otherwise the template carries none of them: coinbase (and HogEx) only on
// the tip, marked degraded under kTemplateDegradedKey and served. That block
// is valid whatever the view and the pool hold, so miners keep working on
// the tip instead of a held template on the old prev; only the fees wait for
// the view. A view without a best block (no set yet, a wiped set) prices
// nothing and is not gated, and neither is an empty pool.
// Header-only and pure so the KATs can pin it directly.
// ---------------------------------------------------------------------------

#include <core/uint256.hpp>

#include <cstdint>
#include <optional>

namespace core::coin {

/// Degraded codes (kTemplateDegradedKey) of a template that takes nothing
/// from the pool.
inline constexpr const char* kNotCleanedForTip = "mempool-not-cleaned-for-tip";
inline constexpr const char* kUtxoViewNotAtTip = "utxo-view-not-at-tip";

/// A block by height and hash.
struct BlockRef {
    uint32_t height{0};
    uint256  hash;
};

/// What a template on `tip` may take from the pool: nullptr = its priced
/// txs; else the degraded code (nothing from the pool). `view_best` is the
/// UTXO view's best block (nullopt: no view, or a view without a best block).
inline const char* template_pool_gate(bool pool_empty, bool cleaned_for_tip,
                                      const std::optional<BlockRef>& view_best,
                                      const BlockRef& tip)
{
    if (pool_empty)
        return nullptr;
    if (!cleaned_for_tip)
        return kNotCleanedForTip;
    if (view_best && (view_best->hash != tip.hash || view_best->height != tip.height))
        return kUtxoViewNotAtTip;
    return nullptr;
}

} // namespace core::coin
