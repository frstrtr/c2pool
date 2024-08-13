#pragma once

#include <memory>

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
    std::unique_ptr<NodeP2P<config_t>> m_p2p;

    //TODO for async: std::thread m_thread_rpc;

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

        // P2P
        // init_p2p();
    }
};
    
} // namespace coin


} // namespace coin
