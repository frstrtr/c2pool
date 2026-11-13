// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #968a slice 3: BIP 152 mempool short-id lookup for compact-block receive.
//
// Port of the mempool half of dashcore PartiallyDownloadedBlock::InitData:
// dashcore takes LOCK(pool->cs) and walks pool->vTxHashes, matching each
// entry's SipHash short id against the cmpctblock. The vendored InitData keeps
// that loop and the SipHash (CBlockHeaderAndShortTxIDs::GetShortID) and asks a
// MempoolShortIdProvider to do the walk. This header builds that provider over
// the DASH embedded Mempool.
//
//   - The walk runs when InitData calls the provider, under the Mempool's own
//     lock (Mempool::for_each_tx_by_instance_hash), over the live pool: a tx
//     admitted after the provider was built is found, an evicted one is not.
//     Nothing is copied for the walk; InitData copies only a tx whose short id
//     matches.
//   - Keys are INSTANCE hashes, as in Dash Core v24 vTxHashes
//     (GetInstanceHash): the pool key dash_txid for every tx except a
//     version-2 asset unlock. Short ids in a v24 cmpctblock are over instance
//     hashes (blockencodings.cpp), so a re-signed v2 unlock that shares its
//     txid with the pooled one gets a different short id and is requested,
//     never spliced in.
//   - A null Mempool gives a null provider: every non-prefilled tx is then
//     fetched by getblocktxn.
//
// A tx that matches by short id but is the wrong tx is not caught here. The
// receiver's merkle bind catches it and fetches the full block.
//
// LIFETIME: the provider holds `mp` by raw pointer. Only InitData calls it
// (vendor/blockencodings.cpp), and InitData runs inside on_cmpctblock, so a
// parked PartiallyDownloadedBlock's copy is never called again. The Mempool
// must outlive every receiver the provider is INSTALLED in. A client that
// can outlive the Mempool is bound through CompactMempoolBinding (below),
// which takes the provider out again before the Mempool goes.
//
// The same holds for the header chain the cmpctblock gate reads
// (make_header_chain_compact_view / CompactChainViewBinding).

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/compact_block_receive.hpp>
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
    return [mp](const vendor::MempoolTxVisitor& visit) {
        mp->for_each_tx_by_instance_hash(
            [&visit](const uint256& instance_hash, const MutableTransaction& tx) {
                return visit(instance_hash, tx);
            });
    };
}

// The cmpctblock gate's view of a HeaderChain (compact_block_receive.hpp
// CompactChainView): lookups only, the compact path never adds a header.
// Holds `chain` by raw pointer: bind it through CompactChainViewBinding when
// the client can outlive the chain.
inline CompactChainView make_header_chain_compact_view(const HeaderChain* chain)
{
    CompactChainView v;
    if (!chain)
        return v;
    v.lookup = [chain](const uint256& h) -> std::optional<CompactChainEntry> {
        auto e = chain->get_header(h);
        if (!e) return std::nullopt;
        return CompactChainEntry{e->height, e->chain_work, e->prev_hash};
    };
    v.tip_hash = [chain]() -> uint256 {
        auto t = chain->tip();
        return t ? t->hash : uint256();
    };
    return v;
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

// #968a: the same teardown discipline for the header chain the cmpctblock gate
// reads. In run_node the HeaderChain (header_chain) is declared AFTER the
// mempool binding, so it needs its own binding declared after it. Client needs
// set_compact_chain_view(CompactChainView).
template <class Client>
class CompactChainViewBinding
{
public:
    CompactChainViewBinding() = default;
    CompactChainViewBinding(const CompactChainViewBinding&) = delete;
    CompactChainViewBinding& operator=(const CompactChainViewBinding&) = delete;
    ~CompactChainViewBinding() { unbind(); }

    void bind(const std::shared_ptr<Client>& client, const HeaderChain& chain)
    {
        unbind();
        if (!client)
            return;
        client->set_compact_chain_view(make_header_chain_compact_view(&chain));
        m_client = client;
    }

    void unbind()
    {
        if (auto c = m_client.lock())
            c->set_compact_chain_view(CompactChainView{});
        m_client.reset();
    }

    bool bound() const { return !m_client.expired(); }

private:
    std::weak_ptr<Client> m_client;
};

} // namespace coin
} // namespace dash
