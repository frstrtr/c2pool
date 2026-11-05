// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// A UTXO view for template tests that price their txs with
// Mempool::set_tx_fee. Selection needs a view (no view, no selection:
// Mempool::get_sorted_txs_with_fees), and a selected tx's inputs must be in
// the view or the pool. This one is in memory (no DB, no sync state: a
// partial view, as the accrual sets are) and holds every input of the
// pool's txs that no pool tx funds, as coins of `value`.

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <impl/ltc/coin/mempool.hpp>

#include <cstdint>

namespace ltc_test {

struct CoveringView {
    core::coin::UTXOViewCache view{nullptr};

    /// Cover the pool's current txs and install the view on the pool.
    void cover(ltc::coin::Mempool& pool, int64_t value = 100'000'000'000LL)
    {
        const auto txs = pool.all_txs_map();
        for (const auto& [id, tx] : txs) {
            for (const auto& in : tx.vin) {
                if (txs.count(in.prevout.hash))
                    continue;
                core::coin::Coin coin;
                coin.value = value;
                coin.scriptPubKey.m_data = {0x51};  // OP_TRUE
                coin.height = 1;
                view.add_coin(core::coin::Outpoint(in.prevout.hash, in.prevout.index), coin);
            }
        }
        pool.set_utxo(&view);
    }
};

} // namespace ltc_test
