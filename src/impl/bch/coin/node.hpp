#pragma once

// ---------------------------------------------------------------------------
// bch::coin::Node -- embedded coin-node front-end, ported from
// src/impl/btc/coin/node.hpp (M3 slice 13, last P2P-layer file).
//
// This is the site where bch's config.hpp FIRST resolves concretely: the
// class is template<ConfigType> and config binds only at the Node<Config>
// instantiation (binary entrypoint), exactly as the btc reference defers it.
// Until then nothing in the P2P layer is config-gated.
//
// Aggregates the embedded daemon front-ends landed in slices 1-12:
//   m_rpc : NodeRPC                 -- external coin-RPC client (work source)
//   m_p2p : p2p::NodeP2P<config_t>  -- embedded BCHN peer driver (fast relay)
// and derives from bch::interfaces::Node for the work/event surface.
//
// >>> BCH DIVERGENCE (standalone SHA256d parent, M1 4.x) <<<
//   - No MWEB / extension-block payload (LTC-specific); full_block carries
//     plain BlockType -- inherited from node_interface.hpp.
//   - No AuxPoW hooks (BCH is not merged-mined).
//   - Handshake protocol version is 70016, matching the btc reference and the
//     bch p2p_node.hpp version handshake; no NODE_WITNESS / wtxidrelay.
// ---------------------------------------------------------------------------

#include <memory>

#include <boost/asio.hpp>

#include "rpc.hpp"
#include "p2p_node.hpp"
#include "node_interface.hpp"

namespace bch
{

namespace coin
{

using p2p::NodeP2P;

template <typename ConfigType>
class Node : public bch::interfaces::Node
{
    using config_t = ConfigType;

    boost::asio::io_context* m_context;
    config_t* m_config;

    std::unique_ptr<NodeRPC> m_rpc;
    std::unique_ptr<NodeP2P<config_t>> m_p2p;

    void init_p2p()
    {
        m_p2p = std::make_unique<NodeP2P<config_t>>(m_context, this, m_config);
        m_p2p->connect(m_config->coin()->m_p2p.address);
    }

    void init_rpc()
    {
        m_rpc = std::make_unique<NodeRPC>(m_context, this, m_config->m_testnet);
        m_rpc->connect(m_config->m_rpc.address, m_config->m_rpc.userpass);

        // work
        work.set(m_rpc->getwork());
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
        m_p2p->connect(addr);
        LOG_INFO << "Coin P2P broadcaster connecting to " << addr.to_string();
    }

    /// Submit a block via P2P directly (faster propagation than RPC).
    void submit_block_p2p(BlockType& block)
    {
        if (m_p2p)
            m_p2p->submit_block(block);
    }

    /// Submit a pre-serialized block via P2P. Used by the stratum work
    /// source which already has the full block bytes assembled from
    /// (header || tx_count || coinbase || tx_data) and does not need to
    /// round-trip through BlockType deserialization.
    void submit_block_p2p_raw(const std::vector<unsigned char>& block_bytes)
    {
        if (m_p2p)
            m_p2p->submit_block_raw(block_bytes);
    }

    bool has_p2p() const { return m_p2p != nullptr; }

    /// Send getheaders to drive header sync.
    /// Locator should be hashes from chain tip back to genesis (sparsely);
    /// for an empty chain pass {genesis_hash}. Stop = uint256::ZERO means
    /// "send up to 2000 headers from locator first match forward".
    /// version is the requester protocol_version (70016, matching the
    /// bch p2p_node.hpp version handshake).
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

} // namespace bch
