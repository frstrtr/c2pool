#pragma once

// Dash coin daemon P2P node.
// Connects to dashd for header sync, block relay, mempool.
// Simplified from LTC: no MWEB, no segwit, no compact blocks.

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"

#include <deque>
#include <memory>
#include <set>

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
    // Unix epoch seconds set when handshake completes; dashboard uses
    // (now - this) to render uptime for the dashd peer row.
    int64_t  m_connect_time_epoch{0};

    // SPV B2 (parity audit): per BIP 130, peer has asked us to announce
    // new blocks via `headers` rather than `inv`. We don't generate
    // unsolicited block announcements today (A2 broadcasts a full `block`
    // message directly), so this is bookkeeping only — the flag is
    // consulted by any future block-announcement path to stay in sync
    // with the peer's preference.
    bool m_peer_wants_headers = false;

    // SPV B3 (parity audit): dedup requested inv hashes so a flapping
    // peer doesn't make us issue duplicate getdata for the same block/tx.
    // Bounded ring of recent hashes — presence in this ring means we
    // already asked for the body. Sized for ~5 min of network noise at
    // mainnet rates (blocks every 2.5 min, txs a few per second).
    static constexpr size_t kSeenInvRingCap = 2048;
    std::set<uint256> m_seen_inv_hashes;
    std::deque<uint256> m_seen_inv_order;

    bool inv_already_requested(const uint256& h) const
    {
        return m_seen_inv_hashes.count(h) > 0;
    }

    void mark_inv_requested(const uint256& h)
    {
        if (m_seen_inv_hashes.insert(h).second) {
            m_seen_inv_order.push_back(h);
            while (m_seen_inv_order.size() > kSeenInvRingCap) {
                m_seen_inv_hashes.erase(m_seen_inv_order.front());
                m_seen_inv_order.pop_front();
            }
        }
    }

    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;
    std::function<void(const std::vector<NetService>&)> m_addr_callback;

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

    // LTC-surface parity methods (Phase 2 CoinBroadcaster port).
    // The templated CoinBroadcasterT expects these method names so the
    // same source calls into either LTC's NodeP2P or Dash's NodeP2P.

    bool is_handshake_complete() const { return m_handshake_complete; }

    // Dashd peer state accessors.
    const NetService& target_addr() const { return m_target_addr; }
    uint32_t           peer_version() const { return m_peer_version; }
    const std::string& peer_subver() const { return m_peer_subver; }
    uint32_t           peer_start_height() const { return m_peer_start_height; }
    int64_t            connect_time_epoch() const { return m_connect_time_epoch; }
    uint64_t           peer_services() const { return m_peer_services; }
    uint32_t           peer_uptime_sec() const {
        // Return epoch of connect, matching ltc::NodeP2P::peer_uptime_sec
        // (confusingly named — returns conntime epoch, not uptime).
        return static_cast<uint32_t>(m_connect_time_epoch);
    }

    // Bitcoin NODE_BLOOM (bit 2) — Dash v20+ doesn't advertise bloom by
    // default, so peer_has_bloom is informational; the broadcaster only
    // uses it to decide whether to send BIP 35 mempool (which Dash
    // doesn't need for its sharechain).
    bool peer_has_bloom() const { return (m_peer_services & 4) != 0; }

    // BIP 152 / BIP 339 — not used on Dash mainnet. Return false so the
    // broadcaster's compact-block / wtxid-relay paths remain inactive.
    bool supports_compact_blocks() const { return false; }
    bool peer_wtxidrelay() const { return false; }

    // Broadcaster fan-out entrypoints.
    void send_block_inv(const uint256& block_hash)
    {
        if (!m_peer) return;
        auto msg = message_inv::make_raw(
            std::vector<inventory_type>{
                inventory_type(inventory_type::block, block_hash)});
        m_peer->write(msg);
    }

    void request_full_block(const uint256& block_hash)
    {
        if (!m_peer) return;
        auto msg = message_getdata::make_raw(
            std::vector<inventory_type>{
                inventory_type(inventory_type::block, block_hash)});
        m_peer->write(msg);
    }

    void request_block(const uint256& block_hash) { request_full_block(block_hash); }

    void send_getaddr()
    {
        if (!m_peer) return;
        auto msg = message_getaddr::make_raw();
        m_peer->write(msg);
    }

    void send_mempool()
    {
        if (!m_peer) return;
        auto msg = message_mempool::make_raw();
        m_peer->write(msg);
    }

    // BIP 35 mempool request toggle — Dash doesn't use this (no bloom
    // filtering / sharechain fee tracking at the SPV layer), so this is
    // a no-op accepted for broadcaster surface parity.
    void enable_mempool_request() {}

    // Peer addr callback for broadcaster-driven peer discovery. Fires
    // whenever dashd sends us a message_addr (unsolicited or in response
    // to getaddr). Used by CoinPeerManager to learn about new dashd
    // endpoints without depending on RPC getpeerinfo.
    using AddrCallback = std::function<void(const std::vector<NetService>&)>;
    void set_addr_callback(AddrCallback cb) { m_addr_callback = std::move(cb); }

    // AuxPoW parsers — DOGE-only in the LTC tree. Dash has neither AuxPoW
    // nor MWEB so both are no-ops. Defined to satisfy the broadcaster
    // template surface.
    template <typename F> void set_raw_headers_parser(F&&) {}
    template <typename F> void set_raw_block_parser(F&&) {}

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

        // SPV C5 (parity audit): warn when dashd protocol is too old for
        // Dash v20+ features we depend on — DIP3 CBTX extra_payload,
        // ChainLocks, v16 share masternode payment fields. 70230 is the
        // minimum that carries all of these correctly; older dashd would
        // silently build mismatched coinbases at block-find time.
        constexpr uint32_t MIN_DASHD_PROTO = 70230;
        if (msg->m_version < MIN_DASHD_PROTO) {
            LOG_WARNING << "[DashP2P] dashd protocol " << msg->m_version
                        << " < minimum " << MIN_DASHD_PROTO
                        << " (v20+). Mining with this peer may produce "
                        << "invalid blocks (missing DIP3 payload, stale "
                        << "masternode fields). Upgrade dashd.";
        }

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
        m_connect_time_epoch = static_cast<int64_t>(std::time(nullptr));
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

        // Phase 2 peer discovery: ask the peer for its addr list so we
        // can seed the CoinPeerManager's candidate pool. Fires only when
        // a set_addr_callback is wired (DashCoinBroadcaster sets it).
        // Without this send, dashd returns nothing — addr messages are
        // push-only and a full getaddr is required to elicit the list
        // on-demand.
        if (m_addr_callback) {
            auto msg_getaddr = message_getaddr::make_raw();
            m_peer->write(msg_getaddr);
        }

        LOG_INFO << "[DashP2P] Handshake complete with " << m_target_addr.to_string();
    }

    void handle_msg(std::unique_ptr<message_ping> msg)
    {
        auto pong = message_pong::make_raw(msg->m_nonce);
        m_peer->write(pong);
    }

    void handle_msg(std::unique_ptr<message_pong>) {}
    void handle_msg(std::unique_ptr<message_alert>) {}
    // SPV B1 (parity audit): peer asked for our peer list. We're an SPV
    // client behind dashd, not a crawler — reply with an empty addr list
    // so the peer knows we responded. Silent drop would have dashd keep
    // re-asking and eventually mark us as a non-responding node.
    void handle_msg(std::unique_ptr<message_getaddr>)
    {
        auto reply = message_addr::make_raw({});
        m_peer->write(reply);
    }
    // SPV A1 (parity audit): Dash ChainLock message. Peer sends clsig
    // unsolicited (or via getdata) when an LLMQ has aggregated a
    // ChainLockSig for a block. Record it so the submit-handler /
    // record_found_block flow can mark the block as ChainLock-confirmed.
    // We trust dashd's network-level LLMQ validation and don't re-verify
    // the 96-byte BLS sig — that requires BLS + quorum state we don't
    // track. The fact that dashd forwarded the message IS the validation.
    void handle_msg(std::unique_ptr<message_clsig> msg)
    {
        if (!msg) return;
        auto bhash = msg->m_block_hash;
        auto h = msg->m_height;
        LOG_INFO << "[DashP2P] ChainLock: height=" << h
                 << " block=" << bhash.GetHex().substr(0, 16);
        m_coin->chainlocked_blocks[bhash] = h;
        m_coin->new_chainlock.happened({bhash, h});
    }

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
    // SPV B2 (parity audit): BIP 130 — peer prefers `headers` over `inv`
    // for new-block announcements. Record the preference. No behavior
    // change today (we don't announce blocks unsolicited), but a future
    // block-relay path can consult m_peer_wants_headers to stay in sync.
    void handle_msg(std::unique_ptr<message_sendheaders>)
    {
        m_peer_wants_headers = true;
    }
    void handle_msg(std::unique_ptr<message_sendcmpct>) {}
    void handle_msg(std::unique_ptr<message_sendaddrv2>) {}
    void handle_msg(std::unique_ptr<message_mempool>) {}

    void handle_msg(std::unique_ptr<message_inv> msg)
    {
        std::vector<inventory_type> requests;
        // MSG_CLSIG = 29 (dashcore/src/protocol.h:522). Not in our generic
        // inventory_type enum — compare raw uint32 value. SPV A1 path.
        static constexpr uint32_t DASH_MSG_CLSIG = 29;

        for (auto& inv : msg->m_invs)
        {
            auto btype = inv.base_type();
            switch (btype) {
            case inventory_type::tx:
                // SPV B3 (parity audit): skip invs we've already asked for.
                if (inv_already_requested(inv.m_hash)) continue;
                mark_inv_requested(inv.m_hash);
                requests.push_back(inv);
                break;
            case inventory_type::block:
                m_coin->new_block.happened(inv.m_hash);
                if (inv_already_requested(inv.m_hash)) continue;
                mark_inv_requested(inv.m_hash);
                requests.push_back(inv);
                break;
            default:
                if (static_cast<uint32_t>(btype) == DASH_MSG_CLSIG) {
                    // Request the clsig body. On receipt we'll record
                    // the ChainLock via handle_msg(message_clsig).
                    if (inv_already_requested(inv.m_hash)) continue;
                    mark_inv_requested(inv.m_hash);
                    requests.push_back(inv);
                }
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
        if (!m_addr_callback) return;
        std::vector<NetService> endpoints;
        endpoints.reserve(msg->m_addrs.size());
        for (const auto& rec : msg->m_addrs) {
            endpoints.push_back(rec.m_endpoint);
        }
        if (!endpoints.empty()) m_addr_callback(endpoints);
    }
};

} // namespace p2p
} // namespace coin
} // namespace dash
