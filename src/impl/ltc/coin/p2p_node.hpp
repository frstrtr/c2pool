#pragma once

#include <impl/bitcoin_family/coin/p2p_messages.hpp>
#include <impl/bitcoin_family/coin/p2p_connection.hpp>
#include "node_interface.hpp"

#include <memory>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/random.hpp>
#include <core/factory.hpp>
#include <core/reply_matcher.hpp>
#include <core/timer.hpp>

namespace io = boost::asio;

#define ADD_P2P_HANDLER(name)\
    void handle(std::unique_ptr<bitcoin_family::coin::p2p::message_##name> msg)
namespace ltc
{
namespace coin
{

namespace p2p
{

// Namespace alias for coin daemon P2P types (avoids collision with pool-level messages)
namespace daemon = bitcoin_family::coin::p2p;

std::string parse_net_error(const boost::system::error_code& ec);

//-core::ICommmunicator:
// void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
// void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
// void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) = 0;
// const std::vector<std::byte>& get_prefix() const = 0;
//
//-core::INetwork:
// void connected(std::shared_ptr<core::Socket> socket) = 0;
// void disconnect() = 0;

template <typename ConfigType>
class NodeP2P : public core::ICommunicator, public core::INetwork, public core::Factory<core::Client>
{
    using config_t = ConfigType;

private:
    static constexpr time_t CONNECT_TIMEOUT_SEC = 10;
    static constexpr time_t IDLE_TIMEOUT_SEC = 100;
    static constexpr time_t PING_INTERVAL_SEC = 30;

    ltc::interfaces::Node* m_coin;
    io::io_context* m_context;
    config_t* m_config;
    daemon::Handler m_handler;

    std::unique_ptr<daemon::Connection> m_peer;
    std::unique_ptr<core::Timer> m_reconnect_timer;
    std::unique_ptr<core::Timer> m_ping_timer;
    std::unique_ptr<core::Timer> m_timeout_timer;
    NetService m_target_addr;
    bool m_reconnect_enabled = false;
    bool m_handshake_complete = false;

    // Callbacks for broadcaster integration
    using AddrCallback = std::function<void(const std::vector<NetService>&)>;
    AddrCallback m_addr_callback;

public:
    NodeP2P(io::io_context* context, ltc::interfaces::Node* coin, config_t* config) 
        : core::Factory<core::Client>(context, this), m_context(context), m_coin(coin), m_config(config) 
    {
        
    }

    /// Connect with automatic reconnection on failure/disconnect (30s interval).
    void connect(NetService addr)
    {
        m_target_addr = addr;
        m_reconnect_enabled = true;
        core::Factory<core::Client>::connect(addr);

        // Periodic reconnect check: if m_peer is null, try again
        m_reconnect_timer = std::make_unique<core::Timer>(m_context, true);
        m_reconnect_timer->start(30, [this]() {
            if (!m_peer && m_reconnect_enabled) {
                LOG_INFO << "P2P reconnecting to " << m_target_addr.to_string() << "...";
                core::Factory<core::Client>::connect(m_target_addr);
            }
        });
    }

    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_peer = std::make_unique<daemon::Connection>(m_context, socket);
        m_handshake_complete = false;
        LOG_INFO << "P2P connected to " << m_target_addr.to_string();

        // Require version/verack progress soon after connect.
        ensure_timeout_timer();
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [this]() {
            timeout("handshake timeout");
        });

        auto msg_version = daemon::message_version::make_raw(
            70017,
            1,
            core::timestamp(),
            addr_t{1, m_peer->get_addr()}, 
            addr_t{1, NetService{"192.168.0.1", 12024}},
            core::random::random_nonce(),
            "c2pool",
            0
        );

        m_peer->write(msg_version);
    }

    void disconnect() override
    {
        stop_ping_timer();
        stop_timeout_timer();
        m_handshake_complete = false;
        m_peer.reset();
    }

    // ICommmunicator
    void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        LOG_ERROR << "CoinNode <NetName>[" << service.to_string() << "]:";
        LOG_ERROR << "\terror: " << err;
        LOG_ERROR << "\twhere: " << where.function_name();
        if (m_peer)
        {
            m_peer.reset();
            // peer.mapped()->m_timeout->stop(); // for case: peer stored somewhere (or leak)
        }
        else
        {
            LOG_ERROR << "\tpeers not exist " << service.to_string();
        }

        stop_ping_timer();
        stop_timeout_timer();
        m_handshake_complete = false;
    }

    void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        error(parse_net_error(ec), service, where);
    }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        on_activity();

        daemon::Handler::result_t result;
        try 
        {
            result = m_handler.parse(rmsg);
        } catch (const std::runtime_error& ec)
        {
            LOG_ERROR << "NodeP2P handle: " << ec.what();
            // todo: error
            return;
        } catch (const std::out_of_range& ec)
        {
            LOG_ERROR << "NodeP2P: " << ec.what();
            return;
        }

        std::visit([&](auto& msg){ handle(std::move(msg)); }, result);
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_p2p.prefix;
    }

    void submit_block(BlockType& block)
    {
        if (m_peer)
        {
            auto rmsg = daemon::message_block::make_raw(block);
            m_peer->write(rmsg);
        } else
        {
            LOG_ERROR << "No bitcoind connection when block submittal attempted!";
            throw std::runtime_error("No bitcoind connection in submit_block");
        }
    }

    /// Set callback for received addr messages (peer discovery).
    void set_addr_callback(AddrCallback cb) { m_addr_callback = std::move(cb); }

    /// Send getaddr to request peer addresses.
    void send_getaddr()
    {
        if (m_peer) {
            auto msg = daemon::message_getaddr::make_raw();
            m_peer->write(msg);
        }
    }

    /// Send inv for a block hash (merged chain relay — announcement only).
    void send_block_inv(const uint256& block_hash)
    {
        if (m_peer) {
            auto msg = daemon::message_inv::make_raw({daemon::inventory_type(daemon::inventory_type::block, block_hash)});
            m_peer->write(msg);
        }
    }

    /// Relay a pre-serialized block (Bitcoin wire format) via P2P.
    /// Avoids BlockType deserialization which uses VarInt version.
    void submit_block_raw(const std::vector<unsigned char>& block_bytes)
    {
        if (m_peer)
        {
            PackStream ps(block_bytes);
            auto rmsg = std::make_unique<RawMessage>("block", std::move(ps));
            m_peer->write(rmsg);
            LOG_INFO << "Block relayed via P2P (raw, " << block_bytes.size() << " bytes)";
        } else
        {
            LOG_ERROR << "No bitcoind connection for P2P block relay";
        }
    }

    //[x][x][x] void handle_message_version(std::shared_ptr<coind::messages::message_version> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, CoindProtocol* protocol); // 
    //[x][x][x] void handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_block(std::shared_ptr<coind::messages::message_block> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, CoindProtocol* protocol); //

private:
    void ensure_timeout_timer()
    {
        if (!m_timeout_timer)
            m_timeout_timer = std::make_unique<core::Timer>(m_context, false);
    }

    void ensure_ping_timer()
    {
        if (!m_ping_timer)
            m_ping_timer = std::make_unique<core::Timer>(m_context, true);
    }

    void stop_timeout_timer()
    {
        if (m_timeout_timer)
            m_timeout_timer->stop();
    }

    void stop_ping_timer()
    {
        if (m_ping_timer)
            m_ping_timer->stop();
    }

    void on_activity()
    {
        if (!m_peer)
            return;

        ensure_timeout_timer();
        auto timeout = m_handshake_complete ? IDLE_TIMEOUT_SEC : CONNECT_TIMEOUT_SEC;
        m_timeout_timer->restart(timeout);
    }

    void timeout(const char* reason)
    {
        auto endpoint = m_peer ? m_peer->get_addr() : m_target_addr;
        error(std::string("peer timeout: ") + reason, endpoint);
    }

    void send_ping()
    {
        if (!m_peer || !m_handshake_complete)
            return;

        auto msg_ping = daemon::message_ping::make_raw(core::random::random_nonce());
        m_peer->write(msg_ping);
    }

    ADD_P2P_HANDLER(version)
    {
        LOG_INFO << "version is?: " << msg->m_command;
        auto verack_msg = daemon::message_verack::make_raw();
        m_peer->write(verack_msg);
    }

    ADD_P2P_HANDLER(verack)
    {
        m_peer->init_requests(
            [&](uint256 hash)
            {
                auto getdata_msg = daemon::message_getdata::make_raw({daemon::inventory_type(daemon::inventory_type::block, hash)});
                m_peer->write(getdata_msg);
            },
            [&](uint256 hash)
            {
                auto getheaders_msg = daemon::message_getheaders::make_raw(1, {}, hash);
                m_peer->write(getheaders_msg);
            }
        );

        m_handshake_complete = true;
        ensure_timeout_timer();
        m_timeout_timer->restart(IDLE_TIMEOUT_SEC);

        ensure_ping_timer();
        m_ping_timer->start(PING_INTERVAL_SEC, [this]() {
            send_ping();
        });
    }

    ADD_P2P_HANDLER(ping)
    {
        auto msg_pong = daemon::message_pong::make_raw(msg->m_nonce);
        m_peer->write(msg_pong);
    }
    
    ADD_P2P_HANDLER(pong)
    {
        // just handled pong
    }

    ADD_P2P_HANDLER(alert)
    {
        LOG_WARNING << "Handled message_alert signature: " << msg->m_signature;
    }

    ADD_P2P_HANDLER(inv)
    {
        std::vector<daemon::inventory_type> vinv;

        for (auto& inv : msg->m_invs)
        {
            switch (inv.m_type)
            {
            case daemon::inventory_type::tx:
                vinv.push_back(inv);
                break;
            case daemon::inventory_type::block:
                m_coin->new_block.happened(inv.m_hash);
                break;
            default:
                LOG_WARNING << "Unknown inv type " << (int)inv.m_type;
                break;
            }
        }

        if (!vinv.empty())
        {
            auto msg_getdata = daemon::message_getdata::make_raw(vinv);
            m_peer->write(msg_getdata);
        }
    }

    ADD_P2P_HANDLER(tx)
    {
        m_coin->new_tx.happened(Transaction(msg->m_tx));
    }

    ADD_P2P_HANDLER(block)
    {
        auto header = (BlockHeaderType) msg->m_block;
        auto packed_header = pack(header); // block_type -> block_header_type
        auto blockhash = Hash(packed_header.get_span());
        m_peer->get_block(blockhash, msg->m_block);
        m_peer->get_header(blockhash, header);
    }

    ADD_P2P_HANDLER(headers)
    {
        std::vector<BlockHeaderType> vheaders;

        for (auto block : msg->m_headers)
        {
            auto header = (BlockHeaderType)block;
            auto packed_header = pack(header);
            auto blockhash = Hash(packed_header.get_span());
            m_peer->get_header(blockhash, header);
        }

        m_coin->new_headers.happened(vheaders);
    }

    ADD_P2P_HANDLER(getaddr)
    {
        // We don't serve addresses — ignore
    }

    ADD_P2P_HANDLER(addr)
    {
        if (m_addr_callback && !msg->m_addrs.empty()) {
            std::vector<NetService> addrs;
            addrs.reserve(msg->m_addrs.size());
            for (auto& rec : msg->m_addrs) {
                addrs.push_back(rec.m_endpoint);
            }
            m_addr_callback(addrs);
        }
    }

    #undef ADD_P2P_HANDLER
};

} // namespace p2p

} // namespace node

} // namespace ltc
