#pragma once

#include <memory>

#include <boost/asio.hpp>

#include "p2p_node.hpp"
#include "node_interface.hpp"

namespace dash
{
namespace coin
{

using p2p::NodeP2P;

template <typename ConfigType>
class Node : public dash::interfaces::Node
{
    using config_t = ConfigType;

    boost::asio::io_context* m_context;
    config_t* m_config;

    std::unique_ptr<NodeP2P<config_t>> m_p2p;

public:
    Node(auto* context, auto* config) : m_context(context), m_config(config) {}

    void start_p2p(const NetService& addr)
    {
        m_p2p = std::make_unique<NodeP2P<config_t>>(m_context, this, m_config);
        m_p2p->connect(addr);
        LOG_INFO << "[DashCoin] P2P connecting to " << addr.to_string();
    }

    void submit_block_p2p(BlockType& block)
    {
        if (m_p2p)
            m_p2p->submit_block(block);
    }

    void send_getheaders(uint32_t version, const std::vector<uint256>& locator, const uint256& stop)
    {
        if (m_p2p)
            m_p2p->send_getheaders(version, locator, stop);
    }

    bool has_p2p() const { return m_p2p != nullptr; }
};

} // namespace coin
} // namespace dash
