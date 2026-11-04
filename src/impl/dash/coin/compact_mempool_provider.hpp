// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #968a slice 3: BIP 152 mempool short-id lookup for compact-block receive.
//
// Port of the mempool half of dashcore PartiallyDownloadedBlock::InitData:
// dashcore walks pool->vTxHashes under the mempool lock and matches each
// txid's SipHash short id against the cmpctblock. The vendored InitData
// keeps that loop and the SipHash (CBlockHeaderAndShortTxIDs::GetShortID),
// but asks a MempoolShortIdProvider for the (txid, tx) pairs instead of
// holding a CTxMemPool*. This header builds that provider over the DASH
// embedded Mempool.
//
//   - The snapshot is taken when InitData calls the provider, under the
//     Mempool's own lock (all_txs_map), so a tx admitted after the provider
//     was built is still found, and an evicted one is not.
//   - Keys are the Mempool's keys, which are dash_txid (Hash(pack(tx))).
//     That is the hash dashcore feeds GetShortID (no wtxid on Dash; we pin
//     CMPCTBLOCKS_VERSION 1).
//   - A null Mempool gives a null provider: every non-prefilled tx is then
//     fetched by getblocktxn, the pre-slice-3 behaviour.
//
// A tx that matches by short id but is the wrong tx is not caught here. The
// receiver's merkle bind catches it and fetches the full block (slice 1).
//
// LIFETIME: the provider holds `mp` by raw pointer. The Mempool must outlive
// every CompactBlockReceiver (and every parked PartiallyDownloadedBlock) the
// provider is installed into.

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/vendor/shim.hpp>

#include <core/uint256.hpp>

#include <memory>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

inline vendor::MempoolShortIdProvider make_mempool_short_id_provider(const Mempool* mp)
{
    if (!mp)
        return nullptr;
    return [mp] {
        auto txs = mp->all_txs_map();
        std::vector<std::pair<uint256, vendor::CTransactionRef>> snap;
        snap.reserve(txs.size());
        for (auto& [txid, tx] : txs)
            snap.emplace_back(txid, std::make_shared<const MutableTransaction>(std::move(tx)));
        return snap;
    };
}

} // namespace coin
} // namespace dash
