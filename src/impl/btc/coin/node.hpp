// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <memory>

#include <boost/asio.hpp>

#include <btclibs/util/strencodings.h>          // HexStr

#include "rpc.hpp"
#include "p2p_node.hpp"
#include "node_interface.hpp"
#include "block_broadcast.hpp"

namespace btc
{

namespace coin
{

using p2p::NodeP2P; 

template <typename ConfigType>
class Node : public btc::interfaces::Node
{
    using config_t = ConfigType;

    boost::asio::io_context* m_context;
    config_t* m_config;

    std::unique_ptr<NodeRPC> m_rpc;
    std::unique_ptr<NodeP2P<config_t>> m_p2p;
    bool m_request_mempool_on_connect{false};  // BIP 35 pull on (re)connect

    void init_p2p()
    {
        m_p2p = std::make_unique<NodeP2P<config_t>>(m_context, this, m_config);
        m_p2p->connect(m_config->coin()->m_p2p.address);
    }

    void init_rpc()
    {
        // m_thread_rpc = std::thread
        // (
        //     [&]
        //     {
        //         auto* rpc_context = new boost::asio::io_context();
        //         m_rpc = std::make_unique<NodeRPC>(rpc_context, this, m_config->m_testnet);
        //         m_rpc->connect(m_config->m_rpc.address, m_config->m_rpc.userpass);
        //         // for test:
        //         boost::asio::post(*rpc_context, [&]{
        //             auto res = m_rpc->getwork();
        //             std::cout << res.m_data.dump() << std::endl;
        //         });
        //         rpc_context->run();
        //     }
        // );

        m_rpc = std::make_unique<NodeRPC>(m_context, this, m_config->m_testnet);
        m_rpc->connect(m_config->m_rpc.address, m_config->m_rpc.userpass);

        // work
        work.set(m_rpc->getwork());
        // work.set(m_rpc->getwork());
    }

public:
    
    Node(auto* context, auto* config) : m_context(context), m_config(config) 
    {
    }

    void run()
    {
        // RPC
        init_rpc();
    }

    /// Start P2P connection to coin daemon for fast block relay.
    /// Call after run() when P2P address is configured.
    void start_p2p(const NetService& addr)
    {
        m_p2p = std::make_unique<NodeP2P<config_t>>(m_context, this, m_config);
        if (m_request_mempool_on_connect)
            m_p2p->enable_mempool_request();
        m_p2p->connect(addr);
        LOG_INFO << "Coin P2P broadcaster connecting to " << addr.to_string();
    }

    /// Opt into the BIP 35 `mempool` request on (re)connect. Without this the
    /// embedded mempool only learns txs announced via `inv` AFTER we connect,
    /// so any tx already resident in the peer mempool at connect time is never
    /// pulled -> coinbase-only templates. Mirrors main_dgb. Idempotent; applies
    /// to the current peer immediately and to any peer start_p2p creates later.
    /// NOTE: the peer must advertise NODE_BLOOM (regtest: -peerbloomfilters=1)
    /// or NodeP2P skips the request to avoid a disconnect.
    void enable_mempool_request()
    {
        m_request_mempool_on_connect = true;
        if (m_p2p)
            m_p2p->enable_mempool_request();
    }

    /// Arm the submitblock RPC BACKUP leg (ARM B of the dual-path broadcaster)
    /// WITHOUT the getwork side effect init_rpc() carries. connect() runs the
    /// read-only liveness/softfork probe check() (getblockheader + getblockchaininfo
    /// + getnetworkinfo, results discarded by c2pool's own template path) but
    /// never getwork, so an external bitcoind we drive purely for submitblock
    /// arms cleanly and the embedded/daemonless template path is unperturbed.
    /// OPT-IN: main_btc calls
    /// this only when bitcoin.conf creds resolve (rpcpassword stays off the
    /// process table); otherwise m_rpc stays null, has_rpc()==false, and
    /// submit_block_hex returns false LOUDLY -- byte-identical to the daemonless
    /// default. Mirrors main_dgb's NodeRPC arming (the #82 reference). The
    /// embedded P2P relay (ARM A) remains the always-primary daemonless path.
    void arm_submit_rpc(const NetService& addr, const std::string& userpass)
    {
        m_rpc = std::make_unique<NodeRPC>(m_context, this, m_config->coin()->m_testnet);
        m_rpc->connect(addr, userpass);
        LOG_INFO << "[BTC] submitblock RPC backup ARMED: NodeRPC -> "
                 << addr.to_string() << " (creds from bitcoin.conf)";
    }

    /// True once arm_submit_rpc has bound the submitblock backup leg.
    bool has_rpc() const { return m_rpc != nullptr; }

    /// Submit a block via P2P directly (faster propagation than RPC).
    void submit_block_p2p(BlockType& block)
    {
        if (m_p2p)
            m_p2p->submit_block(block);
    }

    /// Submit a pre-serialized block via P2P. Used by the stratum work
    /// source which already has the full block bytes assembled from
    /// (header || tx_count || coinbase || tx_data) and doesn't need to
    /// round-trip through BlockType deserialization.
    /// Returns true iff the block was relayed to a connected peer.
    bool submit_block_p2p_raw(const std::vector<unsigned char>& block_bytes)
    {
        if (m_p2p)
            return m_p2p->submit_block_raw(block_bytes);
        return false;
    }

    /// Submit a pre-serialized block to bitcoind via the submitblock RPC.
    /// This is the FALLBACK sink (P2P relay is primary). Returns true iff
    /// the daemon accepted the block. ignore_failure is set so a rejection
    /// is logged but does not throw out of the won-block path.
    bool submit_block_hex(const std::vector<unsigned char>& block_bytes)
    {
        if (!m_rpc)
            return false;
        // MSVC: disambiguate HexStr overload (std::vector<unsigned char> is viable
        // for all span overloads). Feed the exact byte span the uint8_t overload wants.
        return m_rpc->submit_block_hex(
            HexStr(Span<const uint8_t>(block_bytes.data(), block_bytes.size())),
            /*ignore_failure=*/true);
    }

    /// Broadcast a WON block with FALLBACK semantics: P2P relay is primary,
    /// the submitblock RPC fires only if P2P is unavailable or the relay did
    /// not succeed (NOT always-both). Returns true iff the block reached at
    /// least one sink; a false return means it reached NEITHER and the caller
    /// MUST treat it as a lost subsidy.
    bool submit_block_with_fallback(const std::vector<unsigned char>& block_bytes)
    {
        return broadcast_block_with_fallback(
            [&]{ return submit_block_p2p_raw(block_bytes); },
            [&]{ return submit_block_hex(block_bytes); });
    }

    /// Broadcast a WON block for ACTUAL CONNECT (BTC lane). Unlike
    /// submit_block_with_fallback (P2P-primary, RPC only on relay-fail), the
    /// connect path fires the submitblock RPC UNCONDITIONALLY because a P2P
    /// cmpctblock announce-success does NOT guarantee the daemon connects the
    /// block (it requests the body via getblocktxn, which we do not serve).
    /// submitblock is connect-authoritative; P2P relay still fires for fast
    /// propagation. BTC-fenced - does not change the cross-coin fallback
    /// contract. Returns true iff the block reached at least one sink.
    bool submit_block_for_connect(const std::vector<unsigned char>& block_bytes)
    {
        return broadcast_block_for_connect(
            [&]{ return submit_block_p2p_raw(block_bytes); },
            [&]{ return submit_block_hex(block_bytes); });
    }

    bool has_p2p() const { return m_p2p != nullptr; }

    /// Send getheaders to drive header sync (BIP 31).
    /// Locator should be hashes from chain tip back to genesis (sparsely);
    /// for an empty chain pass {genesis_hash}. Stop = uint256::ZERO means
    /// "send up to 2000 headers from locator's first match forward".
    /// Per BTC protocol: the version field is the requester's protocol_version
    /// (we use 70016 to match B1's coin/p2p_node.hpp version handshake).
    void send_getheaders(uint32_t version,
                         const std::vector<uint256>& locator,
                         const uint256& stop)
    {
        if (m_p2p)
            m_p2p->send_getheaders(version, locator, stop);
    }

    /// True once the version+verack handshake completed with the peer.
    bool is_handshake_complete() const
    {
        return m_p2p && m_p2p->is_handshake_complete();
    }
};
    
} // namespace coin


} // namespace coin