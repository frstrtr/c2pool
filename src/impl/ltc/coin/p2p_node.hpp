#pragma once

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"
#include "compact_blocks.hpp"
#include "mempool.hpp"

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
    std::string m_chain_label = "CoinP2P";
    // BIP 152 compact block state
    bool m_peer_supports_cmpct{false};
    uint64_t m_peer_cmpct_version{0};
    bool m_peer_wants_cmpct_announce{false};
    // BIP 339 wtxidrelay state
    bool m_peer_wtxidrelay{false};
    // Peer's advertised service flags (from version message)
    uint64_t m_peer_services{0};
    // BIP 35: request full mempool inventory after handshake
    bool m_request_mempool_on_connect{false};
    // Compact block reconstruction state: pending compact block awaiting blocktxn
    std::unique_ptr<CompactBlock> m_pending_cmpct;
    std::vector<uint32_t> m_pending_missing_indexes;
    // Last compact block we SENT — cached to serve getblocktxn requests
    BlockType m_sent_cmpct_block;
    uint256   m_sent_cmpct_hash;
    // External mempool for compact block tx matching
    Mempool* m_mempool{nullptr};

    // Callbacks for broadcaster integration
    using AddrCallback = std::function<void(const std::vector<NetService>&)>;
    AddrCallback m_addr_callback;
    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;
    // Raw headers parser: if set, called with raw payload data instead of
    // the standard 80+1 byte parser.  Used for DOGE AuxPoW extended headers.
    using RawHeadersParser = std::function<std::vector<BlockHeaderType>(const uint8_t*, size_t)>;
    RawHeadersParser m_raw_headers_parser;
    // Raw block parser: if set, re-parses DOGE AuxPoW full blocks from raw P2P bytes.
    using RawBlockParser = std::function<BlockType(const uint8_t*, size_t)>;
    RawBlockParser m_raw_block_parser;

public:
    NodeP2P(io::io_context* context, ltc::interfaces::Node* coin, config_t* config,
            const std::string& chain_label = "CoinP2P")
        : core::Factory<core::Client>(context, this, chain_label)
        , m_context(context), m_coin(coin), m_config(config)
        , m_chain_label(chain_label)
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
                LOG_INFO << "" << "[" << m_chain_label << "] Reconnecting to " << m_target_addr.to_string() << "...";
                core::Factory<core::Client>::connect(m_target_addr);
            }
        });
    }

    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_peer = std::make_unique<Connection>(m_context, socket);
        m_handshake_complete = false;
        LOG_INFO << "" << "[" << m_chain_label << "] Connected to " << m_target_addr.to_string();

        // Require version/verack progress soon after connect.
        ensure_timeout_timer();
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [this]() {
            timeout("handshake timeout");
        });

        // Service flags depend on chain type:
        // LTC: NODE_NETWORK | NODE_WITNESS | NODE_MWEB
        // DOGE: NODE_NETWORK only (no segwit, no MWEB)
        static constexpr uint64_t NODE_NETWORK = 1;
        static constexpr uint64_t NODE_WITNESS = (1 << 3);
        static constexpr uint64_t NODE_MWEB    = (1ULL << 24);
        bool is_doge = (m_chain_label == "DOGE" || m_chain_label == "doge");
        uint64_t our_services = NODE_NETWORK;
        if (!is_doge) our_services |= NODE_WITNESS | NODE_MWEB;
        uint32_t protocol_version = is_doge ? 70015 : 70017;

        auto msg_version = message_version::make_raw(
            protocol_version,
            our_services,
            core::timestamp(),
            addr_t{our_services, m_peer->get_addr()},
            addr_t{our_services, NetService{"192.168.0.1", 12024}},
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
        // Suppress per-request logging — Header sync progress indicator
        // in add_headers() provides the meaningful status update.
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
        // Copy — the NetService reference may dangle if the socket is already freed
        NetService svc_copy = service;
        LOG_WARNING << "[" << m_chain_label << "] Peer " << svc_copy.to_string()
                    << " disconnected: " << err;
        if (m_peer)
        {
            m_peer.reset();
        }
        // else: already disconnected (double-fire race) — safe to ignore

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
            auto rmsg = ltc::coin::p2p::message_block::make_raw(block, {});
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
    /// Set custom raw headers parser (for DOGE AuxPoW extended headers).
    void set_raw_headers_parser(RawHeadersParser p) { m_raw_headers_parser = std::move(p); }

    /// Set custom raw block parser (for DOGE AuxPoW full blocks).
    void set_raw_block_parser(RawBlockParser p) { m_raw_block_parser = std::move(p); }

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

    /// Request a full block via getdata.
    /// LTC: MSG_MWEB_BLOCK (0x60000002) for MWEB state extraction.
    /// DOGE: MSG_BLOCK (0x02) — no segwit/MWEB support.
    void request_full_block(const uint256& block_hash)
    {
        if (m_peer) {
            bool is_doge = (m_chain_label == "DOGE" || m_chain_label == "doge");
            auto inv = is_doge
                ? inventory_type::block  // MSG_BLOCK for DOGE
                : static_cast<inventory_type::inv_type>(0x60000002);  // MSG_MWEB_BLOCK for LTC
            auto msg = message_getdata::make_raw(
                {inventory_type(inv, block_hash)});
            m_peer->write(msg);
        }
    }

    /// Whether this peer supports compact blocks (BIP 152).
    bool supports_compact_blocks() const { return m_peer_supports_cmpct; }
    bool peer_wtxidrelay() const { return m_peer_wtxidrelay; }
    /// Peer's service flags from version message (for NODE_BLOOM check etc.)
    uint64_t peer_services() const { return m_peer_services; }
    /// Check if peer supports NODE_BLOOM (required for BIP 35 mempool).
    bool peer_has_bloom() const { return (m_peer_services & 4) != 0; }

    /// Set mempool reference for compact block reconstruction.
    void set_mempool(Mempool* mp) { m_mempool = mp; }

    /// Enable BIP 35 mempool request after handshake.
    /// Call after UTXO is initialized so incoming txs can have fees computed.
    void enable_mempool_request() { m_request_mempool_on_connect = true; }

    /// Relay a pre-serialized block via P2P.
    /// Uses compact block format (BIP 152 v2) for peers that support it,
    /// falling back to full block otherwise.
    void submit_block_raw(const std::vector<unsigned char>& block_bytes)
    {
        if (!m_peer) return;

        if (m_peer_supports_cmpct && m_peer_cmpct_version >= 2) {
            // Deserialize the block to build a compact representation
            try {
                PackStream ps(block_bytes);
                BlockType block;
                ps >> block;
                auto cb = BuildCompactBlock(
                    static_cast<BlockHeaderType&>(block), block.m_txs);
                auto rmsg = message_cmpctblock::make_raw(cb);
                m_peer->write(rmsg);

                auto packed_hdr = pack(static_cast<BlockHeaderType&>(block));
                auto blockhash = Hash(packed_hdr.get_span());

                // Cache the full block so we can serve getblocktxn requests.
                m_sent_cmpct_block = std::move(block);
                m_sent_cmpct_hash  = blockhash;

                LOG_INFO << "[" << m_chain_label << "] Sent compact block "
                         << blockhash.GetHex()
                         << " (" << cb.short_ids.size() << " short IDs, "
                         << cb.prefilled_txns.size() << " prefilled)";
                return;
            } catch (const std::exception& e) {
                LOG_WARNING << "[" << m_chain_label
                            << "] Compact block build failed (block_size=" << block_bytes.size()
                            << "), sending full block: " << e.what();
            }
        } else {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] Peer does not support compact blocks"
                     << " (cmpct=" << m_peer_supports_cmpct
                     << " ver=" << m_peer_cmpct_version
                     << "), sending full block (" << block_bytes.size() << " bytes)";
        }

        // Fallback: send full block
        submit_block_full(block_bytes);
    }

    /// Send a full block message (legacy relay).
    void submit_block_full(const std::vector<unsigned char>& block_bytes)
    {
        if (!m_peer) return;
        PackStream ps(block_bytes);
        auto rmsg = std::make_unique<RawMessage>("block", std::move(ps));
        m_peer->write(rmsg);
        LOG_INFO << "[" << m_chain_label << "] Sent full block message ("
                 << block_bytes.size() << " bytes) to " << m_target_addr.to_string();
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
        m_peer_services = msg->m_services;
        LOG_INFO << "[" << m_chain_label << "] version: " << msg->m_command
                 << " start_height=" << msg->m_start_height
                 << " services=0x" << std::hex << msg->m_services << std::dec
                 << " subver=" << msg->m_subversion;
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

        bool is_doge = (m_chain_label == "DOGE" || m_chain_label == "doge");

        // BIP 130: request header-first block announcements
        // DOGE Core may not fully support BIP 130 — skip to avoid misbehaving score
        if (!is_doge) {
            auto msg_sendheaders = message_sendheaders::make_raw();
            m_peer->write(msg_sendheaders);
        }
        // BIP 152: compact blocks — DOGE doesn't support segwit compact blocks (v2)
        if (!is_doge) {
            auto msg_cmpct = message_sendcmpct::make_raw(false, 2);
            m_peer->write(msg_cmpct);
        }

        // BIP 133: advertise minimum feerate (0 = accept all transactions)
        // DOGE Core may not support BIP 133 — skip to avoid disconnection
        if (!is_doge) {
            send_feefilter(0);
        }

        // BIP 35: Request mempool contents from peer.
        // CRITICAL: Peers without NODE_BLOOM (0x04) will DISCONNECT us if we
        // send the mempool message (litecoind net_processing.cpp:3918-3926).
        // Only send if peer advertises NODE_BLOOM in their version services.
        // Normal inv relay delivers NEW txs without BIP 35.
        static constexpr uint64_t SVC_NODE_BLOOM = 4;
        if (m_request_mempool_on_connect) {
            if (m_peer_services & SVC_NODE_BLOOM) {
                send_mempool();
                LOG_INFO << "[" << m_chain_label << "] Sent BIP 35 mempool request"
                         << " (peer has NODE_BLOOM)";
            } else {
                LOG_INFO << "[" << m_chain_label << "] Skipped BIP 35 mempool request"
                         << " — peer lacks NODE_BLOOM (0x" << std::hex << m_peer_services
                         << std::dec << "), would cause disconnect";
            }
        }
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
            auto btype = inv.base_type();
            // BIP 339: MSG_WTX (type 5) uses wtxid instead of txid.
            // Request via MSG_WITNESS_TX (0x40000001) since getdata doesn't accept MSG_WTX.
            // Reference: Bitcoin Core protocol.h line 447, net_processing.cpp line 3036
            if (inv.m_type == inventory_type::wtx) {
                vinv.push_back(inventory_type(inventory_type::witness_tx, inv.m_hash));
                continue;
            }

            switch (btype)
            {
            case inventory_type::tx:
                // Always request with witness (MSG_WITNESS_TX) so segwit
                // transactions arrive with their witness data intact.
                // Without this, P2WPKH/P2WSH spends arrive stripped and
                // fail CheckQueue when included in blocks.
                vinv.push_back(inventory_type(inventory_type::witness_tx, inv.m_hash));
                break;
            case inventory_type::block:
                m_coin->new_block.happened(inv.m_hash);
                // Request full block for MWEB state extraction
                vinv.push_back(inv);
                break;
            case inventory_type::filtered_block:
            case inventory_type::cmpct_block:
                // Recognized but not requested — ignore
                break;
            default:
                LOG_WARNING << "[" << m_chain_label << "] Unknown inv type 0x" << std::hex
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
        // When a raw block parser is set (DOGE AuxPoW), re-parse the block from
        // raw P2P bytes.  The standard BlockType deserialization misinterprets
        // AuxPoW data as transactions, producing garbage.
        BlockType block;
        if (m_raw_block_parser && !msg->m_raw_payload.empty()) {
            try {
                block = m_raw_block_parser(msg->m_raw_payload.data(),
                                           msg->m_raw_payload.size());
            } catch (const std::exception& e) {
                LOG_WARNING << "[" << m_chain_label << "] AuxPoW block parser failed: " << e.what()
                            << " — falling back to standard parse";
                block = msg->m_block;
            }
        } else {
            block = msg->m_block;
        }

        auto header = static_cast<BlockHeaderType>(block);
        auto packed_header = pack(header);
        auto blockhash = Hash(packed_header.get_span());
        // ReplyMatcher may throw if nobody registered a pending request for
        // this block (e.g., unsolicited block or getdata-triggered response).
        // Catch to ensure full_block event always fires for MWEB extraction.
        try { m_peer->get_block(blockhash, block); } catch (...) {}
        try { m_peer->get_header(blockhash, header); } catch (...) {}
        LOG_INFO << "[" << m_chain_label << "] Full block received: "
                 << blockhash.GetHex().substr(0, 16) << "..."
                 << " txs=" << block.m_txs.size()
                 << " mweb_raw=" << block.m_mweb_raw.size() << " bytes";
        // Fire full block event (carries MWEB data for state extraction)
        m_coin->full_block.happened(block);
    }

    ADD_P2P_HANDLER(headers)
    {
        std::vector<BlockHeaderType> vheaders;

        // When a raw parser is set (DOGE AuxPoW), always prefer it over the
        // standard parser.  The standard parser misinterprets AuxPoW data as
        // block transactions, producing a small number of garbage entries
        // instead of the full 2000-header batch.
        if (m_raw_headers_parser && !msg->m_raw_payload.empty()) {
            try {
                vheaders = m_raw_headers_parser(
                    msg->m_raw_payload.data(), msg->m_raw_payload.size());
                LOG_INFO << "[" << m_chain_label << "] AuxPoW parser: "
                         << vheaders.size() << " headers from "
                         << msg->m_raw_payload.size() << " bytes";
            } catch (const std::exception& e) {
                LOG_WARNING << "[" << m_chain_label << "] AuxPoW headers parser failed: " << e.what();
            }
        }

        if (vheaders.empty() && !msg->m_headers.empty()) {
            // Standard path: headers parsed as 80-byte BlockType (LTC, BTC)
            for (auto block : msg->m_headers)
            {
                auto header = (BlockHeaderType)block;
                auto packed_header = pack(header);
                auto blockhash = Hash(packed_header.get_span());
                try {
                    m_peer->get_header(blockhash, header);
                } catch (const std::invalid_argument&) {}
                vheaders.push_back(header);
            }
        }

        if (!vheaders.empty()) {
            m_coin->new_headers.happened(vheaders);

            // BIP 130: when receiving a small headers batch (new block announcement),
            // request the full block via getdata.
            // LTC: MSG_MWEB_BLOCK (0x60000002) for MWEB state extraction
            // DOGE: MSG_BLOCK (0x02) — no segwit/MWEB
            bool is_doge_chain = (m_chain_label == "DOGE" || m_chain_label == "doge");
            if (vheaders.size() <= 3 && m_peer) {
                for (auto& hdr : vheaders) {
                    auto packed = pack(hdr);
                    auto bhash = Hash(packed.get_span());
                    auto inv_type = is_doge_chain
                        ? inventory_type::block  // MSG_BLOCK for DOGE
                        : static_cast<inventory_type::inv_type>(0x60000002);  // MSG_MWEB_BLOCK
                    auto getdata_msg = message_getdata::make_raw(
                        {inventory_type(inv_type, bhash)});
                    m_peer->write(getdata_msg);
                    LOG_INFO << "[" << m_chain_label << "] Requesting full block "
                             << bhash.GetHex().substr(0, 16) << "...";
                }
            }
        }
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
        // BIP 152: Compact block negotiation — record peer capability
        m_peer_supports_cmpct = true;
        m_peer_cmpct_version = msg->m_version;
        m_peer_wants_cmpct_announce = msg->m_announce;
        LOG_INFO << "[" << m_chain_label << "] Peer supports compact blocks v"
                 << msg->m_version << " (announce=" << msg->m_announce << ")";
    }

    ADD_P2P_HANDLER(cmpctblock)
    {
        auto& cb = msg->m_compact_block;
        auto packed_hdr = pack(cb.header);
        auto blockhash = Hash(packed_hdr.get_span());

        LOG_INFO << "[" << m_chain_label << "] Received compact block "
                 << blockhash.GetHex()
                 << " (" << cb.short_ids.size() << " short IDs, "
                 << cb.prefilled_txns.size() << " prefilled)";

        // Always announce the new block to the node (header-based)
        m_coin->new_block.happened(blockhash);

        // Attempt reconstruction from mempool + known_txs
        // BIP 152 v2: short IDs are keyed by wtxid (witness txid).
        std::map<uint256, MutableTransaction> known;

        // Gather from node's known_txs (re-key by wtxid)
        for (const auto& [txid, tx] : m_coin->known_txs) {
            MutableTransaction mtx(tx);
            auto packed = pack(TX_WITH_WITNESS(mtx));
            uint256 wtxid = Hash(packed.get_span());
            known[wtxid] = std::move(mtx);
        }

        // Gather from mempool (wtxid-keyed)
        if (m_mempool) {
            auto mp_txs = m_mempool->all_txs_map_wtxid();
            known.merge(mp_txs);
        }

        auto result = ReconstructBlock(cb, known);

        if (result.complete) {
            LOG_INFO << "[" << m_chain_label << "] Compact block reconstructed: "
                     << blockhash.GetHex()
                     << " txs=" << result.block.m_txs.size()
                     << " mweb_raw=" << result.block.m_mweb_raw.size() << " bytes";
            // Deliver as a full block
            m_peer->get_block(blockhash, result.block);
            auto header = static_cast<BlockHeaderType>(result.block);
            m_peer->get_header(blockhash, header);
            // Fire full block event (carries MWEB data for state extraction)
            m_coin->full_block.happened(result.block);
        } else {
            LOG_INFO << "[" << m_chain_label << "] Compact block incomplete, "
                     << result.missing_indexes.size() << " txs missing — requesting via getblocktxn";
            // Save pending state and request missing transactions
            m_pending_cmpct = std::make_unique<CompactBlock>(cb);
            m_pending_missing_indexes = result.missing_indexes;

            BlockTransactionsRequest req;
            req.blockhash = blockhash;
            req.indexes = result.missing_indexes;
            auto req_msg = message_getblocktxn::make_raw(req);
            m_peer->write(req_msg);
        }
    }

    ADD_P2P_HANDLER(getblocktxn)
    {
        auto& req = msg->m_request;

        // Only serve our most recently sent compact block
        if (req.blockhash != m_sent_cmpct_hash || m_sent_cmpct_block.m_txs.empty()) {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] getblocktxn for unknown block "
                            << req.blockhash.GetHex() << " — ignoring";
            return;
        }

        BlockTransactionsResponse resp;
        resp.blockhash = req.blockhash;
        resp.txs.reserve(req.indexes.size());

        for (uint32_t idx : req.indexes) {
            if (idx >= m_sent_cmpct_block.m_txs.size()) {
                LOG_WARNING << "[" << m_chain_label << "] getblocktxn: index " << idx
                            << " out of range (block has " << m_sent_cmpct_block.m_txs.size() << " txs)";
                return;  // malformed request — drop
            }
            resp.txs.push_back(m_sent_cmpct_block.m_txs[idx]);
        }

        auto rmsg = message_blocktxn::make_raw(resp);
        m_peer->write(rmsg);
        LOG_INFO << "[" << m_chain_label << "] Served " << resp.txs.size()
                 << " txs via blocktxn for " << req.blockhash.GetHex();
    }

    ADD_P2P_HANDLER(blocktxn)
    {
        auto& resp = msg->m_response;

        if (!m_pending_cmpct || m_pending_missing_indexes.empty()) {
            LOG_WARNING << "[" << m_chain_label << "] Received blocktxn without pending compact block";
            return;
        }

        if (resp.txs.size() != m_pending_missing_indexes.size()) {
            LOG_WARNING << "[" << m_chain_label << "] blocktxn size mismatch: got "
                        << resp.txs.size() << ", expected " << m_pending_missing_indexes.size();
            m_pending_cmpct.reset();
            m_pending_missing_indexes.clear();
            return;
        }

        // Reconstruct the full block with the missing transactions
        auto& cb = *m_pending_cmpct;
        size_t total_txs = cb.short_ids.size() + cb.prefilled_txns.size();
        std::vector<MutableTransaction> txs(total_txs);
        std::vector<bool> filled(total_txs, false);

        // Place prefilled transactions
        for (const auto& pt : cb.prefilled_txns) {
            if (pt.index < total_txs) {
                txs[pt.index] = pt.tx;
                filled[pt.index] = true;
            }
        }

        // Re-match from mempool (same as cmpctblock handler)
        std::map<uint256, MutableTransaction> known;
        for (const auto& [txid, tx] : m_coin->known_txs)
            known[txid] = MutableTransaction(tx);
        if (m_mempool) {
            auto mp_txs = m_mempool->all_txs_map();
            known.merge(mp_txs);
        }

        uint64_t k0, k1;
        cb.GetSipHashKeys(k0, k1);
        std::map<uint64_t, const MutableTransaction*> sid_map;
        for (const auto& [txid, tx] : known) {
            ShortTxID sid = CompactBlock::GetShortID(k0, k1, txid);
            sid_map[sid.to_uint64()] = &tx;
        }

        size_t sid_idx = 0;
        for (size_t i = 0; i < total_txs; ++i) {
            if (filled[i]) continue;
            if (sid_idx < cb.short_ids.size()) {
                auto it = sid_map.find(cb.short_ids[sid_idx].to_uint64());
                if (it != sid_map.end() && it->second)
                    txs[i] = *(it->second);
                // else: will be filled from blocktxn response below
            }
            ++sid_idx;
        }

        // Fill in the missing transactions from blocktxn response
        for (size_t i = 0; i < m_pending_missing_indexes.size(); ++i) {
            uint32_t idx = m_pending_missing_indexes[i];
            if (idx < total_txs)
                txs[idx] = resp.txs[i];
        }

        // Build and deliver the full block
        auto packed_hdr = pack(cb.header);
        auto blockhash = Hash(packed_hdr.get_span());

        BlockType block;
        static_cast<BlockHeaderType&>(block) = cb.header;
        block.m_txs = std::move(txs);

        m_peer->get_block(blockhash, block);
        auto header = static_cast<BlockHeaderType>(block);
        m_peer->get_header(blockhash, header);

        LOG_INFO << "[" << m_chain_label << "] Compact block completed via blocktxn: "
                 << blockhash.GetHex();

        m_pending_cmpct.reset();
        m_pending_missing_indexes.clear();
    }

    ADD_P2P_HANDLER(wtxidrelay)
    {
        // BIP 339: Peer wants wtxid-based tx relay
        m_peer_wtxidrelay = true;
        LOG_DEBUG_COIND << "[" << m_chain_label << "] Peer supports wtxidrelay (BIP 339)";
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
