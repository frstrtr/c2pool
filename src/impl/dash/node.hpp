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
                        process_shares(msg->m_shares, service);
                    }
                }
            }, result);
        } catch (const std::exception&) {
            // Unhandled messages (addrme, have_tx, etc.) — normal
        }
    }

    // Process received shares: deserialize v16 → verify X11 PoW → add to tracker
    void process_shares(std::vector<chain::RawShare>& raw_shares, const NetService& from)
    {
        LOG_INFO << "[Dash] Processing " << raw_shares.size() << " share(s) from " << from.to_string();

        for (auto& raw_share : raw_shares)
        {
            if (raw_share.type != 16) {
                LOG_WARNING << "[Dash] Unknown share type " << raw_share.type << ", skipping";
                continue;
            }

            try {
                // Deserialize v16 share from wire
                auto stream = raw_share.contents.as_stream();
                auto share_var = dash::ShareType::load(raw_share.type, stream);

                // Extract share data for logging
                share_var.ACTION({
                    LOG_INFO << "[Dash] Share deserialized:"
                             << " prev=" << obj->m_prev_hash.GetHex().substr(0, 16)
                             << " height=" << obj->m_absheight
                             << " bits=0x" << std::hex << obj->m_bits << std::dec
                             << " subsidy=" << obj->m_subsidy
                             << " donation=" << obj->m_donation
                             << " payments=" << obj->m_packed_payments.size()
                             << " timestamp=" << obj->m_timestamp;

                    // Verify X11 PoW
                    try {
                        uint256 share_hash = dash::share_init_verify(*obj, m_coin_params, true);
                        obj->m_hash = share_hash;
                        LOG_INFO << "[Dash] Share VERIFIED: hash=" << share_hash.GetHex().substr(0, 16)
                                 << " X11 PoW valid!";

                        // Add to tracker
                        auto* heap_share = new dash::DashShare(*obj);
                        m_tracker.add(heap_share);
                        LOG_INFO << "[Dash] Share added to tracker (total: " << m_tracker.chain.size() << ")";
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[Dash] Share verification failed: " << e.what();
                    }
                });
            } catch (const std::exception& e) {
                LOG_WARNING << "[Dash] Share deserialization failed: " << e.what()
                            << " (type=" << raw_share.type << " size=" << raw_share.contents.size() << ")";
            }
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
