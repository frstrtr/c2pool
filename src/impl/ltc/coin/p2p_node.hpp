#pragma once

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"

#include <memory>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/log.hpp>
#include <core/random.hpp>
#include <core/factory.hpp>
#include <core/reply_matcher.hpp>
#include <core/timer.hpp>

namespace io = boost::asio;

#define ADD_P2P_HANDLER(name)\
    void handle(std::unique_ptr<ltc::coin::p2p::message_##name> msg)
namespace ltc
{
namespace coin
{

namespace p2p
{

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
    p2p::Handler m_handler;

    std::unique_ptr<Connection> m_peer;
    std::unique_ptr<core::Timer> m_reconnect_timer;
    std::unique_ptr<core::Timer> m_ping_timer;
    std::unique_ptr<core::Timer> m_timeout_timer;
    NetService m_target_addr;
    bool m_reconnect_enabled = false;
    bool m_handshake_complete = false;

    // Callbacks for broadcaster integration
    using AddrCallback = std::function<void(const std::vector<NetService>&)>;
    AddrCallback m_addr_callback;
    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;

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
        m_peer = std::make_unique<Connection>(m_context, socket);
        m_handshake_complete = false;
        LOG_INFO << "P2P connected to " << m_target_addr.to_string();

        // Require version/verack progress soon after connect.
        ensure_timeout_timer();
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [this]() {
            timeout("handshake timeout");
        });

        auto msg_version = message_version::make_raw(
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

    /// Send a getheaders request to the connected peer.
    /// @param version  Protocol version (typically 70015 or 70017).
    /// @param locator  Block locator hashes (tip-to-genesis order).
    /// @param stop     Stop hash (uint256::ZERO to request up to tip).
    void send_getheaders(uint32_t version, const std::vector<uint256>& locator, const uint256& stop)
    {
        if (!m_peer) return;
        LOG_TRACE << "getheaders: locator_size=" << locator.size()
                  << (locator.empty() ? "" : " tip=" + locator.front().GetHex().substr(0, 16))
                  << " stop=" << (stop.IsNull() ? "0" : stop.GetHex().substr(0, 16));
        auto msg = message_getheaders::make_raw(version, locator, stop);
        m_peer->write(msg);
    }

    /// Whether the handshake with the peer is complete.
    bool is_handshake_complete() const { return m_handshake_complete; }

    /// Send BIP 35 mempool request — ask peer to announce all mempool txs via inv.
    void send_mempool() {
        if (!m_peer) return;
        auto msg = message_mempool::make_raw();
        m_peer->write(msg);
    }

    /// Send BIP 133 feefilter — advise peer of minimum feerate we accept (sat/kB).
    /// Pass 0 to request all transactions (no filtering).
    void send_feefilter(uint64_t min_feerate_sat_per_kb = 0) {
        if (!m_peer) return;
        auto msg = message_feefilter::make_raw(min_feerate_sat_per_kb);
        m_peer->write(msg);
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

        p2p::Handler::result_t result;
        try 
        {
            result = m_handler.parse(rmsg);
        } catch (const std::runtime_error& ec)
        {
            LOG_ERROR << "NodeP2P handle(" << rmsg->m_command << ", "
                      << rmsg->m_data.size() << " bytes): " << ec.what();
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
            auto rmsg = ltc::coin::p2p::message_block::make_raw(block);
            m_peer->write(rmsg);
        } else
        {
            LOG_ERROR << "No bitcoind connection when block submittal attempted!";
            throw std::runtime_error("No bitcoind connection in submit_block");
        }
    }

    /// Set callback for received addr messages (peer discovery).
    void set_addr_callback(AddrCallback cb) { m_addr_callback = std::move(cb); }
    /// Set callback for peer's reported chain height (from version message).
    void set_on_peer_height(PeerHeightCallback cb) { m_on_peer_height = std::move(cb); }

    /// Send getaddr to request peer addresses.
    void send_getaddr()
    {
        if (m_peer) {
            auto msg = message_getaddr::make_raw();
            m_peer->write(msg);
        }
    }

    /// Send inv for a block hash (merged chain relay — announcement only).
    void send_block_inv(const uint256& block_hash)
    {
        if (m_peer) {
            auto msg = message_inv::make_raw({inventory_type(inventory_type::block, block_hash)});
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
        }
        // Silent skip when peer not connected — the broadcaster logs the
        // aggregate count ("broadcast to N/M peers") which is sufficient.
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

        auto msg_ping = message_ping::make_raw(core::random::random_nonce());
        m_peer->write(msg_ping);
    }

    ADD_P2P_HANDLER(version)
    {
        LOG_INFO << "version is?: " << msg->m_command
                 << " start_height=" << msg->m_start_height;
        // Notify header chain of peer's tip height for fast-sync scrypt skip.
        if (m_on_peer_height && msg->m_start_height > 0)
            m_on_peer_height(msg->m_start_height);
        auto verack_msg = message_verack::make_raw();
        m_peer->write(verack_msg);
    }

    ADD_P2P_HANDLER(verack)
    {
        m_peer->init_requests(
            [&](uint256 hash)
            {
                auto getdata_msg = message_getdata::make_raw({inventory_type(inventory_type::block, hash)});
                m_peer->write(getdata_msg);
            },
            [&](uint256 hash)
            {
                auto getheaders_msg = message_getheaders::make_raw(1, {}, hash);
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

        // BIP 130: request header-first block announcements
        auto msg_sendheaders = message_sendheaders::make_raw();
        m_peer->write(msg_sendheaders);

        // BIP 133: advertise minimum feerate (0 = accept all transactions)
        send_feefilter(0);

        // NOTE: send_mempool() (BIP 35) is NOT called automatically here.
        // It requires NODE_BLOOM service flags on both sides or the daemon
        // may disconnect. Callers must invoke send_mempool() explicitly after
        // confirming the peer supports it.
    }

    ADD_P2P_HANDLER(ping)
    {
        auto msg_pong = message_pong::make_raw(msg->m_nonce);
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
        std::vector<inventory_type> vinv;
        
        for (auto& inv : msg->m_invs)
        {
            switch (inv.base_type())
            {
            case inventory_type::tx:
                vinv.push_back(inv);
                break;
            case inventory_type::block:
                m_coin->new_block.happened(inv.m_hash);
                break;
            case inventory_type::filtered_block:
            case inventory_type::cmpct_block:
                // Recognized but not requested — ignore
                break;
            default:
                LOG_WARNING << "Unknown inv type 0x" << std::hex
                            << static_cast<uint32_t>(inv.m_type) << std::dec;
                break;
            }
        }

        if (!vinv.empty())
        {
            auto msg_getdata = message_getdata::make_raw(vinv);
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
            // Feed to ReplyMatcher if there's a pending individual request;
            // ignore if not (batch headers from getheaders won't have one).
            try {
                m_peer->get_header(blockhash, header);
            } catch (const std::invalid_argument&) {
                // No pending request for this hash — expected for getheaders batches
            }
            vheaders.push_back(header);
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

    ADD_P2P_HANDLER(reject)
    {
        LOG_WARNING << "Peer rejected " << msg->m_message
                    << " (code=" << static_cast<int>(msg->m_ccode)
                    << "): " << msg->m_reason
                    << " hash=" << msg->m_data.GetHex();
    }

    ADD_P2P_HANDLER(sendheaders)
    {
        // Peer prefers header announcements — acknowledged
        LOG_DEBUG_COIND << "Peer supports sendheaders (BIP 130)";
    }

    ADD_P2P_HANDLER(notfound)
    {
        for (auto& inv : msg->m_invs)
        {
            switch (inv.base_type())
            {
            case inventory_type::block:
                // Complete the ReplyMatcher with a default (empty) response
                // so we don't wait for the 15s timeout.
                try {
                    m_peer->get_block(inv.m_hash, BlockType{});
                } catch (...) {}
                try {
                    m_peer->get_header(inv.m_hash, BlockHeaderType{});
                } catch (...) {}
                break;
            default:
                break;
            }
            LOG_DEBUG_COIND << "Peer does not have inv 0x" << std::hex
                            << static_cast<uint32_t>(inv.m_type) << std::dec
                            << " " << inv.m_hash.GetHex();
        }
    }

    ADD_P2P_HANDLER(feefilter)
    {
        LOG_DEBUG_COIND << "Peer feefilter: " << msg->m_feerate << " sat/kB";
    }

    ADD_P2P_HANDLER(mempool)
    {
        // We don't serve mempool — ignore incoming request
    }

    ADD_P2P_HANDLER(sendcmpct)
    {
        // BIP 152: Compact block negotiation — acknowledge but don't use yet
        LOG_DEBUG_COIND << "Peer sendcmpct: announce=" << msg->m_announce
                        << " version=" << msg->m_version;
    }

    ADD_P2P_HANDLER(wtxidrelay)
    {
        // BIP 339: Peer wants wtxid-based tx relay — acknowledged
        LOG_DEBUG_COIND << "Peer supports wtxidrelay (BIP 339)";
    }

    ADD_P2P_HANDLER(sendaddrv2)
    {
        // BIP 155: Peer wants addrv2 messages — acknowledged
        LOG_DEBUG_COIND << "Peer supports sendaddrv2 (BIP 155)";
    }

    ADD_P2P_HANDLER(getdata)
    {
        // Peer requesting data from us — we don't serve blocks/txs
        LOG_DEBUG_COIND << "Peer getdata with " << msg->m_requests.size() << " items (ignored)";
    }

    ADD_P2P_HANDLER(getblocks)
    {
        // Peer requesting block locator — we don't serve blocks
    }

    ADD_P2P_HANDLER(getheaders)
    {
        // Peer requesting headers — we don't serve headers
        LOG_DEBUG_COIND << "Peer getheaders (ignored, we don't serve headers)";
    }

    #undef ADD_P2P_HANDLER
};

} // namespace p2p

} // namespace node

} // namespace ltc
