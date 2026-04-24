#pragma once

#include <memory>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

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

    // Bug 3 root-cause fix: NodeP2P inherits enable_shared_from_this so the
    // timer/connect/read async lambdas can capture self. shared_from_this()
    // requires the object be MANAGED by a shared_ptr at construction —
    // hence shared_ptr (not unique_ptr) here, and make_shared in start_p2p
    // below.
    std::shared_ptr<NodeP2P<config_t>> m_p2p;

public:
    Node(auto* context, auto* config) : m_context(context), m_config(config) {}

    void start_p2p(const NetService& addr)
    {
        LOG_INFO << "[DashCoin] Creating P2P node for " << addr.to_string();
        m_p2p = std::make_shared<NodeP2P<config_t>>(m_context, this, m_config);
        LOG_INFO << "[DashCoin] P2P node created, connecting...";
        m_p2p->connect(addr);
        LOG_INFO << "[DashCoin] P2P connecting to " << addr.to_string();
    }

    void submit_block_p2p(BlockType& block)
    {
        if (m_p2p)
            m_p2p->submit_block(block);
    }

    // Raw-bytes P2P broadcast. Pass-through for submit_block_raw — callers
    // that already have a packed block (e.g. from submit_validator) can
    // skip the deserialize/reserialize round-trip.
    void submit_block_raw(std::span<const unsigned char> block_bytes)
    {
        if (m_p2p)
            m_p2p->submit_block_raw(block_bytes);
    }

    void send_getheaders(uint32_t version, const std::vector<uint256>& locator, const uint256& stop)
    {
        if (m_p2p)
            m_p2p->send_getheaders(version, locator, stop);
    }

    bool has_p2p() const { return m_p2p != nullptr; }

    // Dashboard peer-info renderer: one-peer array (dashd SPV is always
    // exactly one connection) in the shape the web_server broadcaster
    // panel expects. Returns empty array before handshake completes so
    // the dashboard shows zero peers rather than partial/garbage state.
    nlohmann::json peer_info_json() const {
        auto arr = nlohmann::json::array();
        if (!m_p2p || !m_p2p->is_connected()) return arr;
        nlohmann::json p;
        p["addr"]           = m_p2p->target_addr().to_string();
        p["connected"]      = true;
        p["incoming"]       = false;
        p["subver"]         = m_p2p->peer_subver();
        p["version"]        = m_p2p->peer_version();
        p["startingheight"] = m_p2p->peer_start_height();
        // conntime in unix epoch seconds — dashboard computes uptime as
        // (now - conntime). Matches LTC peer_info shape.
        p["conntime"]       = m_p2p->connect_time_epoch();
        arr.push_back(std::move(p));
        return arr;
    }

    // SPV A1: true if a ChainLock has been received for this block hash.
    // Queried by main_dash.cpp submit handler after submitblock to mark
    // a FoundBlock as ChainLock-finalized (vs just dashd-accepted).
    bool is_chainlocked(const uint256& block_hash) const {
        return chainlocked_blocks.count(block_hash) > 0;
    }
};

} // namespace coin
} // namespace dash
