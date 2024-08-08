#pragma once

#include <memory>

#include <boost/asio.hpp>

#include "rpc.hpp"
#include "p2p_node.hpp"

namespace ltc
{

namespace coin
{

using p2p::NodeP2P; 

template <typename ConfigType>
class Node
{
    using config_t = ConfigType;

    boost::asio::io_context* m_context;
    config_t* m_config;

    std::unique_ptr<NodeRPC> m_rpc;
    std::unique_ptr<NodeP2P<config_t>> m_p2p;

public:
    
    Node(auto* context, auto* config) : m_context(context), m_config(config) 
    {
    }

    void run()
    {
        // P2P
        m_p2p = std::make_unique<NodeP2P<config_t>>(m_context, m_config);
        m_p2p->connect(m_config->coin()->m_p2p.address);

        // RPC
        m_rpc = std::make_unique<NodeRPC>(m_context, m_config->m_testnet);
        m_rpc->connect(m_config->m_rpc.address, m_config->m_rpc.userpass);
    }
};
    
} // namespace coin


} // namespace coin
