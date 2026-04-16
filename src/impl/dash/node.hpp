#pragma once

// DashNodeImpl: Dash p2pool node using BaseNode infrastructure.
// Handles v1700 protocol, v16 shares, X11 PoW validation.

#include "config.hpp"
#include "params.hpp"
#include "share.hpp"
#include "share_chain.hpp"
#include "share_tracker.hpp"
#include "peer.hpp"
#include "messages.hpp"

#include <core/coin_params.hpp>
#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>
#include <core/reply_matcher.hpp>

#include <random>

namespace dash
{

struct HandleSharesData;

class DashNodeImpl : public pool::BaseNode<dash::Config, dash::ShareChain, dash::Peer>
{
    using base_t = pool::BaseNode<dash::Config, dash::ShareChain, dash::Peer>;

protected:
    core::CoinParams m_coin_params;
    dash::Handler m_handler;
    ShareTracker m_tracker;

public:
    DashNodeImpl()
        : m_coin_params(dash::make_coin_params(false))
    {
        m_tracker.m_params = &m_coin_params;
    }

    DashNodeImpl(boost::asio::io_context* ctx, config_t* config, bool testnet = false)
        : m_coin_params(dash::make_coin_params(testnet)),
          base_t(ctx, config)
    {
        m_tracker.m_params = &m_coin_params;

        // Seed addr store with bootstrap peers
        m_addrs.load(config->pool()->m_bootstrap_addrs);

        // Random nonce
        std::mt19937_64 rng(std::random_device{}());
        m_nonce = rng();

        // Route chain pointer
        m_chain = &m_tracker.chain;
    }

    // INetwork
    void disconnect() override { }
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        auto addr = socket->get_addr();
        base_t::connected(socket);
        auto peer = m_connections[addr];
        send_version(peer);
    }

    // Send version message (protocol 1700)
    void send_version(peer_ptr peer)
    {
        auto rmsg = dash::message_version::make_raw(
            m_coin_params.minimum_protocol_version,
            0,                                    // services
            addr_t{0, peer->addr()},              // addr_to
            addr_t{0, NetService{"0.0.0.0", m_coin_params.p2p_port}},
            m_nonce,
            "/c2pool-dash:0.1/",
            1,                                    // mode
            best_share_hash()
        );
        peer->write(std::move(rmsg));
    }

    void send_ping(peer_ptr peer) override
    {
        auto rmsg = dash::message_ping::make_raw();
        peer->write(std::move(rmsg));
    }

    std::optional<pool::PeerConnectionType> handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override
    {
        auto msg = dash::message_version::make(rmsg->m_data);

        if (msg->m_version < m_coin_params.minimum_protocol_version)
        {
            LOG_WARNING << "[Dash] Peer protocol " << msg->m_version
                        << " < minimum " << m_coin_params.minimum_protocol_version;
            throw std::runtime_error("peer protocol too old");
        }

        peer->m_other_version = msg->m_version;
        peer->m_other_subversion = msg->m_subversion;
        peer->m_nonce = msg->m_nonce;

        LOG_INFO << "[Dash] Peer version=" << msg->m_version
                 << " subver=" << msg->m_subversion
                 << " best=" << msg->m_best_share.GetHex().substr(0, 16);

        return pool::PeerConnectionType::actual;
    }

    // Protocol message dispatch
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        auto peer_it = m_connections.find(service);
        if (peer_it == m_connections.end()) return;

        auto& peer = peer_it->second;
        peer->m_timeout->restart();

        // Version handshake (must be first message)
        // Command is 12-byte null-padded from wire; use prefix compare
        if (rmsg->m_command.compare(0, 7, "version") == 0)
        {
            auto type = handle_version(std::move(rmsg), peer);
            if (type.has_value()) {
                peer->stable(type.value(), PEER_TIMEOUT_TIME);
                LOG_INFO << "[Dash] Peer " << service.to_string() << " handshake OK";
            }
            return;
        }

        // Parse through message handler
        try {
            auto result = m_handler.parse(rmsg);
            std::visit([&](auto& msg) {
                using T = std::decay_t<decltype(msg)>;
                if constexpr (std::is_same_v<T, std::unique_ptr<dash::message_shares>>) {
                    if (msg) {
                        LOG_INFO << "[Dash] Received " << msg->m_shares.size() << " share(s)";
                        for (auto& raw_share : msg->m_shares) {
                            LOG_INFO << "[Dash] Share type=" << raw_share.type
                                     << " size=" << raw_share.contents.size();
                        }
                    }
                }
            }, result);
        } catch (const std::exception&) {
            // Unhandled messages (addrme, have_tx, etc.) — normal
        }
    }

    // Access
    ShareTracker& tracker() { return m_tracker; }
    const core::CoinParams& coin_params() const { return m_coin_params; }

    uint256 best_share_hash() const
    {
        // Return null until we have shares
        return uint256();
    }

    void error(const message_error_type& err, const NetService& service,
               const std::source_location where = std::source_location::current()) override
    {
        LOG_ERROR << "[Dash] P2P error from " << service.to_string() << ": " << err;
        base_t::error(err, service, where);
    }
};

} // namespace dash
