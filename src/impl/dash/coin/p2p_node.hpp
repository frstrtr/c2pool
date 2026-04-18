#pragma once

// Dash coin daemon P2P node.
// Connects to dashd for header sync, block relay, mempool.
// Simplified from LTC: no MWEB, no segwit, no compact blocks.

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"

#include <memory>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/log.hpp>
#include <core/random.hpp>
#include <core/factory.hpp>
#include <core/timer.hpp>

#include <impl/dash/crypto/hash_x11.hpp>

namespace io = boost::asio;

namespace dash
{
namespace coin
{
namespace p2p
{

template <typename ConfigType>
class NodeP2P : public core::ICommunicator, public core::INetwork, public core::Factory<core::Client>
{
    using config_t = ConfigType;

    static constexpr time_t CONNECT_TIMEOUT_SEC = 10;
    static constexpr time_t IDLE_TIMEOUT_SEC = 100;
    static constexpr time_t PING_INTERVAL_SEC = 30;
    static constexpr uint64_t NODE_NETWORK = 1;
    // Dash Core v20+ protocol version
    static constexpr uint32_t DASH_PROTOCOL_VERSION = 70230;

    dash::interfaces::Node* m_coin;
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

    uint64_t m_peer_services{0};
    uint32_t m_peer_version{0};
    std::string m_peer_subver;
    uint32_t m_peer_start_height{0};

    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;

    void ensure_timeout_timer()
    {
        if (!m_timeout_timer)
            m_timeout_timer = std::make_unique<core::Timer>(m_context, true);
    }

    void stop_timeout_timer()
    {
        if (m_timeout_timer) m_timeout_timer->stop();
    }

    void ensure_ping_timer()
    {
        if (!m_ping_timer)
            m_ping_timer = std::make_unique<core::Timer>(m_context, true);
    }

    void stop_ping_timer()
    {
        if (m_ping_timer) m_ping_timer->stop();
    }

    void on_activity()
    {
        if (m_timeout_timer && m_handshake_complete)
            m_timeout_timer->restart(IDLE_TIMEOUT_SEC);
    }

    void timeout(const std::string& reason)
    {
        LOG_WARNING << "[DashP2P] Timeout: " << reason;
        disconnect();
    }

    void send_ping()
    {
        if (m_peer) {
            auto msg = message_ping::make_raw(core::random::random_nonce());
            m_peer->write(msg);
        }
    }

public:
    NodeP2P(io::io_context* context, dash::interfaces::Node* coin, config_t* config)
        : core::Factory<core::Client>(context, this, "DashP2P")
        , m_context(context), m_coin(coin), m_config(config)
    {}

    void connect(NetService addr)
    {
        m_target_addr = addr;
        m_reconnect_enabled = true;
        core::Factory<core::Client>::connect(addr);

        m_reconnect_timer = std::make_unique<core::Timer>(m_context, true);
        m_reconnect_timer->start(30, [this]() {
            if (!m_peer && m_reconnect_enabled) {
                LOG_INFO << "[DashP2P] Reconnecting to " << m_target_addr.to_string();
                core::Factory<core::Client>::connect(m_target_addr);
            }
        });
    }

    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_peer = std::make_unique<Connection>(m_context, socket);
        m_handshake_complete = false;
        LOG_INFO << "[DashP2P] Connected to " << m_target_addr.to_string();

        ensure_timeout_timer();
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [this]() {
            timeout("handshake timeout");
        });

        auto msg_version = message_version::make_raw(
            DASH_PROTOCOL_VERSION,
            NODE_NETWORK,
            core::timestamp(),
            addr_t{NODE_NETWORK, m_peer->get_addr()},
            addr_t{NODE_NETWORK, NetService{"192.168.0.1", 9999}},
            core::random::random_nonce(),
            "c2pool-dash",
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

    void send_getheaders(uint32_t version, const std::vector<uint256>& locator, const uint256& stop)
    {
        if (!m_peer) return;
        auto msg = message_getheaders::make_raw(version, locator, stop);
        m_peer->write(msg);
    }

    void set_on_peer_height(PeerHeightCallback cb) { m_on_peer_height = std::move(cb); }

    void submit_block(BlockType& block)
    {
        if (m_peer) {
            auto rmsg = message_block::make_raw(block);
            m_peer->write(rmsg);
        } else {
            throw std::runtime_error("No dashd connection in submit_block");
        }
    }

    // SPV A2 (parity audit): ship already-serialized block bytes to dashd
    // alongside the submitblock RPC, for fast P2P propagation on block-find.
    // Avoids a full BlockType round-trip deserialize just to re-serialize;
    // the submit validator built the exact bytes dashd expects (80-byte
    // header + VarInt tx count + coinbase + txs).
    void submit_block_raw(std::span<const unsigned char> block_bytes)
    {
        if (!m_peer) return;
        PackStream ps(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(block_bytes.data()),
            block_bytes.size()));
        auto rmsg = std::make_unique<RawMessage>("block", std::move(ps));
        m_peer->write(rmsg);
    }

    bool is_connected() const { return m_peer != nullptr && m_handshake_complete; }

    // ICommunicator — message dispatch
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        on_activity();

        // Trim null-padded command for clean logging
        std::string cmd = rmsg->m_command;
        while (!cmd.empty() && cmd.back() == '\0') cmd.pop_back();
        try {
            auto result = m_handler.parse(rmsg);
            std::visit([&](auto& msg) { handle_msg(std::move(msg)); }, result);
        } catch (const std::exception& e) {
            LOG_TRACE << "[DashP2P] unhandled: " << cmd;
        }
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_p2p.prefix;
    }

    void error(const message_error_type& err, const NetService& service,
               const std::source_location where = std::source_location::current()) override
    {
        LOG_WARNING << "[DashP2P] Error: " << err;
        disconnect();
    }

    void error(const boost::system::error_code& ec, const NetService& service,
               const std::source_location where = std::source_location::current()) override
    {
        LOG_WARNING << "[DashP2P] Error: " << ec.message();
        disconnect();
    }

private:
    // ── Message handlers ──

    template <typename T>
    void handle_msg(std::unique_ptr<T>) {}

    void handle_msg(std::unique_ptr<message_version> msg)
    {
        m_peer_services = msg->m_services;
        m_peer_version = msg->m_version;
        m_peer_subver = msg->m_subversion;
        m_peer_start_height = msg->m_start_height;
        LOG_INFO << "[DashP2P] version: height=" << msg->m_start_height
                 << " services=0x" << std::hex << msg->m_services << std::dec
                 << " subver=" << msg->m_subversion;

        if (m_on_peer_height && msg->m_start_height > 0)
            m_on_peer_height(msg->m_start_height);

        auto verack_msg = message_verack::make_raw();
        m_peer->write(verack_msg);
    }

    void handle_msg(std::unique_ptr<message_verack> msg)
    {
        m_peer->init_requests(
            [&](uint256 hash) {
                auto getdata = message_getdata::make_raw({inventory_type(inventory_type::block, hash)});
                m_peer->write(getdata);
            },
            [&](uint256 hash) {
                auto getheaders = message_getheaders::make_raw(1, {}, hash);
                m_peer->write(getheaders);
            }
        );

        m_handshake_complete = true;
        ensure_timeout_timer();
        m_timeout_timer->restart(IDLE_TIMEOUT_SEC);

        ensure_ping_timer();
        m_ping_timer->start(PING_INTERVAL_SEC, [this]() { send_ping(); });

        // BIP 130: request header-first announcements
        auto msg_sendheaders = message_sendheaders::make_raw();
        m_peer->write(msg_sendheaders);

        // SPV A4 (parity audit): ask peer for full mempool summary.
        // Peer replies with `inv` which our inv-handler already processes
        // → we learn about pending txs without waiting for new-tx pushes.
        // Closes the startup window where transactions sent during our
        // connection-setup gap would be invisible until they land in a block.
        auto msg_mempool = message_mempool::make_raw();
        m_peer->write(msg_mempool);

        LOG_INFO << "[DashP2P] Handshake complete with " << m_target_addr.to_string();
    }

    void handle_msg(std::unique_ptr<message_ping> msg)
    {
        auto pong = message_pong::make_raw(msg->m_nonce);
        m_peer->write(pong);
    }

    void handle_msg(std::unique_ptr<message_pong>) {}
    void handle_msg(std::unique_ptr<message_alert>) {}
    void handle_msg(std::unique_ptr<message_getaddr>) {}
    // SPV A3 (parity audit): log rejects instead of silently dropping.
    // Dashd sends these when our submitblock / getdata / etc. is malformed
    // or the message it references doesn't validate. Without the log a
    // submitblock failure leaves no diagnostic trail.
    void handle_msg(std::unique_ptr<message_reject> msg)
    {
        if (!msg) return;
        LOG_WARNING << "[DashP2P] reject from peer:"
                    << " msg=" << msg->m_message
                    << " ccode=0x" << std::hex << static_cast<int>(msg->m_ccode) << std::dec
                    << " reason='" << msg->m_reason << "'"
                    << " data=" << (msg->m_data.IsNull()
                                    ? std::string("-")
                                    : msg->m_data.GetHex().substr(0, 16));
    }
    void handle_msg(std::unique_ptr<message_notfound>) {}
    void handle_msg(std::unique_ptr<message_feefilter>) {}
    void handle_msg(std::unique_ptr<message_sendheaders>) {}
    void handle_msg(std::unique_ptr<message_sendcmpct>) {}
    void handle_msg(std::unique_ptr<message_sendaddrv2>) {}
    void handle_msg(std::unique_ptr<message_mempool>) {}

    void handle_msg(std::unique_ptr<message_inv> msg)
    {
        std::vector<inventory_type> requests;

        for (auto& inv : msg->m_invs)
        {
            auto btype = inv.base_type();
            switch (btype) {
            case inventory_type::tx:
                requests.push_back(inv);
                break;
            case inventory_type::block:
                m_coin->new_block.happened(inv.m_hash);
                requests.push_back(inv);
                break;
            default:
                break;
            }
        }

        if (!requests.empty()) {
            auto getdata = message_getdata::make_raw(requests);
            m_peer->write(getdata);
        }
    }

    void handle_msg(std::unique_ptr<message_tx> msg)
    {
        m_coin->new_tx.happened(Transaction(msg->m_tx));
    }

    void handle_msg(std::unique_ptr<message_block> msg)
    {
        auto header = static_cast<BlockHeaderType>(msg->m_block);
        auto packed_header = pack(header);
        // Dash uses X11 for block identity hash
        auto blockhash = dash::crypto::hash_x11(packed_header.get_span());
        try { m_peer->get_block(blockhash, msg->m_block); } catch (...) {}
        try { m_peer->get_header(blockhash, header); } catch (...) {}
        LOG_INFO << "[DashP2P] Block: " << blockhash.GetHex().substr(0, 16)
                 << " txs=" << msg->m_block.m_txs.size();
        m_coin->full_block.happened(msg->m_block);
    }

    void handle_msg(std::unique_ptr<message_headers> msg)
    {
        std::vector<BlockHeaderType> vheaders;

        for (auto& block : msg->m_headers)
        {
            auto header = static_cast<BlockHeaderType>(block);
            auto packed_header = pack(header);
            auto blockhash = dash::crypto::hash_x11(packed_header.get_span());
            try { m_peer->get_header(blockhash, header); } catch (const std::invalid_argument&) {}
            vheaders.push_back(header);
        }

        if (!vheaders.empty()) {
            m_coin->new_headers.happened(vheaders);

            // Small batch = new block announcement → request full block
            if (vheaders.size() <= 3 && m_peer) {
                for (auto& hdr : vheaders) {
                    auto packed = pack(hdr);
                    auto bhash = dash::crypto::hash_x11(packed.get_span());
                    auto getdata = message_getdata::make_raw(
                        {inventory_type(inventory_type::block, bhash)});
                    m_peer->write(getdata);
                    LOG_INFO << "[DashP2P] Requesting full block " << bhash.GetHex().substr(0, 16);
                }
            }
        }
    }

    void handle_msg(std::unique_ptr<message_addr> msg)
    {
        LOG_INFO << "[DashP2P] Received " << msg->m_addrs.size() << " addr entries";
    }
};

} // namespace p2p
} // namespace coin
} // namespace dash
