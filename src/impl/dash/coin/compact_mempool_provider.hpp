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
// LIFETIME: the provider holds `mp` by raw pointer. Only InitData calls it
// (vendor/blockencodings.cpp), and InitData runs inside on_cmpctblock, so a
// parked PartiallyDownloadedBlock's copy is never called again. The Mempool
// must outlive every receiver the provider is INSTALLED in. A client that
// can outlive the Mempool is bound through CompactMempoolBinding (below),
// which takes the provider out again before the Mempool goes.

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

// #968a slice 3b: installs a Mempool's provider into a coin-P2P client and
// takes it out again in the destructor.
//
// In run_node (main_dash.cpp) the client (coin_p2p) is declared before
// node_coin_state, which owns the Mempool, so at scope exit the Mempool is
// destroyed first. The client can also outlive the scope altogether:
// set_lifetime pins it with a strong ref per in-flight async op. Without this
// binding the client would be left holding a provider that points into a
// freed Mempool. Declare the binding AFTER the Mempool's owner. It is then
// destroyed BEFORE the owner, and the provider is gone from the client while
// the Mempool is still alive.
//
// The client is held weakly. If it is already gone, there is nothing to take
// out. Client needs set_compact_mempool_provider(MempoolShortIdProvider)
// (CoinClient, p2p_client.hpp). bind/unbind/destructor run on the client's io
// thread or after its io loop has stopped, the same rule as the setter.
template <class Client>
class CompactMempoolBinding
{
public:
    CompactMempoolBinding() = default;
    CompactMempoolBinding(const CompactMempoolBinding&) = delete;
    CompactMempoolBinding& operator=(const CompactMempoolBinding&) = delete;
    ~CompactMempoolBinding() { unbind(); }

    // A null client leaves the binding unbound. A second bind replaces the
    // first, after taking the first provider out.
    void bind(const std::shared_ptr<Client>& client, const Mempool& mp)
    {
        unbind();
        if (!client)
            return;
        client->set_compact_mempool_provider(make_mempool_short_id_provider(&mp));
        m_client = client;
    }

    void unbind()
    {
        if (auto c = m_client.lock())
            c->set_compact_mempool_provider(nullptr);
        m_client.reset();
    }

    bool bound() const { return !m_client.expired(); }

private:
    std::weak_ptr<Client> m_client;
};

} // namespace coin
} // namespace dash
