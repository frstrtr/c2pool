// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <memory>
#include <cassert>      // dial-lifetime arm assert (UAF guard)

#include <boost/asio.hpp>

#include "rpc.hpp"
#include "p2p_node.hpp"
#include "node_interface.hpp"

namespace ltc
{

namespace coin
{

using p2p::NodeP2P; 

template <typename ConfigType>
class Node : public ltc::interfaces::Node
{
    using config_t = ConfigType;

    boost::asio::io_context* m_context;
    config_t* m_config;

    std::unique_ptr<NodeRPC> m_rpc;
    // shared_ptr-owned so core::Client can pin it with a strong ref for the dial
    // duration (set_lifetime below). A unique_ptr node leaves the core dial guard
    // a silent no-op -> make_socket()'s dynamic_cast can run on a freed NodeP2P on
    // a start_p2p() redial / teardown race (the #759-class dial-teardown UAF).
    std::shared_ptr<NodeP2P<config_t>> m_p2p;

    void init_p2p()
    {
        m_p2p = std::make_shared<NodeP2P<config_t>>(m_context, this, m_config);
        m_p2p->set_lifetime(m_p2p);
        assert(m_p2p->lifetime_armed() && "coin-P2P dial lifetime failed to arm");
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
        // Reassigning m_p2p frees the PRIOR NodeP2P; a still-in-flight resolve/
        // connect on it is kept alive by core::Client's captured strong ref
        // (set_lifetime) until its handler runs -- no freed-vtable make_socket.
        m_p2p = std::make_shared<NodeP2P<config_t>>(m_context, this, m_config);
        m_p2p->set_lifetime(m_p2p);
        assert(m_p2p->lifetime_armed() && "coin-P2P dial lifetime failed to arm");
        m_p2p->connect(addr);
        LOG_INFO << "Coin P2P broadcaster connecting to " << addr.to_string();
    }

    /// Submit a block via P2P directly (faster propagation than RPC).
    void submit_block_p2p(BlockType& block)
    {
        if (m_p2p)
            m_p2p->submit_block(block);
    }

    bool has_p2p() const { return m_p2p != nullptr; }
};
    
} // namespace coin


} // namespace coin