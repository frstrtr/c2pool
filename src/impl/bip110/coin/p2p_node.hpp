// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"
#include "compact_blocks.hpp"
#include "mempool.hpp"
#include "idle_progress_gate.hpp"
#include "local_addr.hpp"        // LocalAddrTable, SelfNonceRegistry (self-advertise)

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
    void handle(std::unique_ptr<bip110::coin::p2p::message_##name> msg)
namespace bip110
{
namespace coin
{

namespace p2p
{

std::string parse_net_error(const boost::system::error_code& ec);

// BIP-110 fork service bit (NODE_BLAKE2B, bit 28), advertised by fork peers and
// enforced at BOTH the version gate and addr-ingest (Knots protocol.h
// SeedsServiceFlags 0x10000009).
inline constexpr uint64_t COIN_NODE_BLAKE2B = (uint64_t{1} << 28);

// Outgoing coin-p2p user agent (BIP14 free-text `/name:ver/` — display/identity
// ONLY, zero consensus). Fork-peer acceptance is gated on the NODE_BLAKE2B
// service bit (p2p_node.hpp version gate below), NEVER on this string, so the
// brand is safe to change: Knots/Core fork peers still accept the handshake.
// BOLD form (default) advertises c2pool to crawlers/bitnodes and any dialer.
// SAFE Knots-uacomment alternative (1-line flip, INTEGRATOR pick):
//   inline constexpr const char* BIP110_COIN_SUBVER = "/Satoshi:29.4.1/Knots:20260508(c2pool-bip110)/";
inline constexpr const char* BIP110_COIN_SUBVER = "/c2pool:0.1/bip110/frstrtr/";

// Fork-filtered addr ingest — the load-bearing half of the Knots addr handler
// (net_processing.cpp addr handling), BLAKE2b-adjusted. PURE + socket-free so
// KATs drive it directly. From gossiped `addr` records it keeps ONLY peers
// advertising NODE_BLAKE2B (a canonical-SHA256d peer would poison the fork
// addrman) and drops grossly FUTURE-dated records (>now+10min) as poison; every
// other record is forwarded (the bucketed addrman stamps its own nTime, so a
// clamp of an OLD timestamp into the past is already subsumed — see
// core/coin_addrman.hpp). `Rec` is any type exposing m_services / m_timestamp /
// m_endpoint (the wire btc_addr_record_t). Returns the survivors' endpoints.
template <typename Rec>
inline std::vector<NetService> filter_fork_addr_records(
    const std::vector<Rec>& recs, int64_t now,
    size_t* out_dropped_nonfork = nullptr, size_t* out_dropped_future = nullptr)
{
    std::vector<NetService> ok;
    ok.reserve(recs.size());
    size_t dropped_nonfork = 0, dropped_future = 0;
    for (const auto& rec : recs) {
        if (!(rec.m_services & COIN_NODE_BLAKE2B)) { ++dropped_nonfork; continue; }
        if (static_cast<int64_t>(rec.m_timestamp) > now + 10 * 60) { ++dropped_future; continue; }
        ok.push_back(rec.m_endpoint);
    }
    if (out_dropped_nonfork) *out_dropped_nonfork = dropped_nonfork;
    if (out_dropped_future)  *out_dropped_future  = dropped_future;
    return ok;
}

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

    // Guard-rail (integrator 2026-07-30, DGB): the idle-eviction window must be
    // >> the per-request timeout, so a genuinely long-running request is driven
    // by its OWN Connection::REQUEST_TIMEOUT_SEC and is never guillotined by the
    // coarse eviction backstop.
    static_assert(IDLE_TIMEOUT_SEC > Connection::REQUEST_TIMEOUT_SEC,
                  "idle-eviction window must exceed the per-request timeout");

    bip110::interfaces::Node* m_coin;
    io::io_context* m_context;
    config_t* m_config;
    p2p::Handler m_handler;

    std::unique_ptr<Connection> m_peer;
    std::unique_ptr<core::Timer> m_reconnect_timer;
    std::unique_ptr<core::Timer> m_ping_timer;
    std::unique_ptr<core::Timer> m_timeout_timer;
    // Idle-progress eviction: gate the stall window on FORWARD PROGRESS (a real
    // reply-matcher answer) rather than on any inbound byte.
    IdleProgressGate m_idle_gate;
    // Guard-rail (integrator 2026-07-30, BCH): single-peer coins running their own
    // block-download stall recovery disable this path so it never drops their only
    // connection. On by default for BTC/DGB.
    bool m_eviction_enabled{true};
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
    // Peer metadata from version message
    uint64_t m_peer_services{0};
    uint32_t m_peer_version{0};          // protocol version (e.g. 70016)
    std::string m_peer_subver;           // user agent (e.g. "/Satoshi:28.0.0/")
    uint32_t m_peer_start_height{0};     // chain height at connect time
    std::chrono::steady_clock::time_point m_connected_at{std::chrono::steady_clock::now()};
    // BIP 35: request full mempool inventory after handshake
    bool m_request_mempool_on_connect{false};
    // Compact block reconstruction state: pending compact block awaiting blocktxn
    std::unique_ptr<CompactBlock> m_pending_cmpct;
    std::vector<uint32_t> m_pending_missing_indexes;
    // Last compact block we SENT — cached to serve getblocktxn requests
    BlockType m_sent_cmpct_block;
    uint256   m_sent_cmpct_hash;
    // Last full block we RELAYED — cached raw bytes + hash to serve a
    // follow-up getdata(MSG_BLOCK / MSG_WITNESS_BLOCK) from our single peer.
    std::vector<unsigned char> m_served_block_bytes;
    uint256                    m_served_block_hash;
    // External mempool for compact block tx matching
    Mempool* m_mempool{nullptr};

    // BIP-110 fork service bit (NODE_BLAKE2B, bit 28). Advertised by fork peers;
    // enforced at BOTH the version gate AND at addr-ingest so only fork-capable
    // peers ever enter the addrman (Knots protocol.h SeedsServiceFlags 0x10000009).
    static constexpr uint64_t NODE_BLAKE2B = COIN_NODE_BLAKE2B;
    // The service set WE advertise everywhere (version, self-addr, getaddr-self):
    // truthful per Knots protocol.h SeedsServiceFlags 0x10000009 = NODE_NETWORK |
    // NODE_WITNESS | NODE_BLAKE2B. Same set the InboundListener advertises.
    static constexpr uint64_t SVC_NODE_NETWORK = 1;
    static constexpr uint64_t SVC_NODE_WITNESS = (uint64_t{1} << 3);
    static constexpr uint64_t OUR_SERVICES = SVC_NODE_NETWORK | SVC_NODE_WITNESS | NODE_BLAKE2B;

    // ── Self-address advertisement (Knots net.cpp GetLocalAddress / MaybeSendAddr)
    // Shared local-address table (peer-echo scored + --coin-externalip) answering
    // "what is OUR reachable address?" and the self-connect nonce guard. Both are
    // owned in main and shared across the primary + fan-out + inbound arms; null
    // when self-advertise is not wired (KATs / non-discovery mode) → every path
    // below is a no-op, so behaviour is byte-identical to before.
    std::shared_ptr<LocalAddrTable>    m_local_addr;
    std::shared_ptr<SelfNonceRegistry> m_self_nonce;
    // Self-announce cadence (Knots AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL is 24h;
    // a bootstrapping fork mesh re-announces faster so a newly-learned local addr
    // reaches peers within one interval — documented deviation).
    static constexpr time_t SELF_ADDR_INTERVAL_SEC = 30 * 60;
    bool m_self_addr_sent{false};
    std::chrono::steady_clock::time_point m_last_self_addr{};
    // addr-relay sink (Knots net_processing RelayAddress, 2-hop gossip): a fresh
    // gossip batch we banked is forwarded to a couple of OTHER fork slots. main
    // wires this to the inbound listener's session relay + addrman. Null → no
    // relay (still banks locally via m_addr_callback).
    using AddrRelaySink =
        std::function<void(const std::vector<btc_addr_record_t>&, const NetService& /*source*/)>;
    AddrRelaySink m_addr_relay_sink;

    // Callbacks for broadcaster integration.
    // Fork-filtered addr ingest sink: the NODE_BLAKE2B + sanity survivors, plus
    // the peer that gossiped them (source) so the addrman bucket-keys the banked
    // entries by source-group — dashd/Core keying that bounds how far one source
    // can spray the new table.
    using AddrCallback =
        std::function<void(const std::vector<NetService>&, const NetService& /*source*/)>;
    AddrCallback m_addr_callback;
    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;

    // ── Knots peer discovery (getaddr/addr crawl + scorer feedback) ───────────
    // getaddr-on-connect: Core sends GETADDR to outbound peers at verack so the
    // peer gossips its address set back (net_processing.cpp SetupAddressRelay).
    // Default OFF; main enables it on the discovery path. Guarded so exactly ONE
    // GETADDR goes out per connection (no spam).
    bool m_send_getaddr_on_connect{false};
    bool m_getaddr_sent{false};
    // Peer-lifecycle seams feeding the scored/bucketed peer manager:
    // handshake-complete -> notify_connected (addrman Good -> tried),
    // disconnect -> notify_disconnected, pre-socket dial failure ->
    // notify_dial_failed (#940 leg). NetService = the dialed key.
    using PeerLifecycleCallback = std::function<void(const NetService&)>;
    PeerLifecycleCallback m_on_peer_connected;
    PeerLifecycleCallback m_on_peer_disconnected;
    PeerLifecycleCallback m_on_dial_failed;
    // Raw headers parser: if set, called with raw payload data instead of
    // the standard 80+1 byte parser.  Used for DOGE AuxPoW extended headers.
    using RawHeadersParser = std::function<std::vector<BlockHeaderType>(const uint8_t*, size_t)>;
    RawHeadersParser m_raw_headers_parser;
    // Raw block parser: if set, re-parses DOGE AuxPoW full blocks from raw P2P bytes.
    using RawBlockParser = std::function<BlockType(const uint8_t*, size_t)>;
    RawBlockParser m_raw_block_parser;

public:
    NodeP2P(io::io_context* context, bip110::interfaces::Node* coin, config_t* config,
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
        m_getaddr_sent = false;   // fresh Connection -> re-arm the one-shot getaddr
        m_self_addr_sent = false; // fresh Connection -> re-announce our self-addr
        m_connected_at = std::chrono::steady_clock::now();  // stamp THIS connection
        m_idle_gate.reset();   // fresh Connection -> fresh progress high-water mark
        LOG_INFO << "" << "[" << m_chain_label << "] Connected to " << m_target_addr.to_string();

        // Require version/verack progress soon after connect.
        ensure_timeout_timer();
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [this]() {
            timeout("handshake timeout");
        });

        // BIP-110 service flags + protocol version:
        // NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B (bit 28). We advertise
        // NODE_BLAKE2B because this node enforces the BLAKE2b hard-fork rules —
        // truthful per Knots protocol.h:353-355 (SeedsServiceFlags=0x10000009).
        // Protocol 70016 = BIP 339 wtxidrelay activation point (Bitcoin Core 0.21+).
        uint64_t our_services = OUR_SERVICES;
        uint32_t protocol_version = 70016;

        // addr_from = our reachable IP:listen-port when we know it (Knots
        // GetLocalAddress). Previously a HARDCODED 192.168.0.1:8333 — an
        // untruthful RFC1918 literal that told every peer nothing usable. When we
        // do not yet know a routable local addr, send an unspecified endpoint
        // (Knots sends an empty CService and receivers ignore addr_from anyway;
        // the load-bearing advertisement is the self-addr push at verack below).
        NetService from_ep{"0.0.0.0", 0};
        if (m_local_addr) {
            if (auto best = m_local_addr->best_local())
                from_ep = *best;
        }

        // Self-connect guard (Knots CConnman nonce): record the nonce we send so
        // the version handler can drop a handshake whose nonce matches — i.e. we
        // dialed our own listener (only reachable once self-advertise lands).
        uint64_t nonce = core::random::random_nonce();
        if (m_self_nonce) m_self_nonce->record(nonce);

        auto msg_version = message_version::make_raw(
            protocol_version,
            our_services,
            core::timestamp(),
            addr_t{our_services, m_peer->get_addr()},
            addr_t{our_services, from_ep},
            nonce,
            BIP110_COIN_SUBVER,
            0
        );

        m_peer->write(msg_version);
    }

    void disconnect() override
    {
        // A handshaked peer going away is a live-link loss: report it to the
        // scorer so the addrman ages the entry (dashd Connected/attempt cadence).
        if (m_handshake_complete && m_on_peer_disconnected)
            m_on_peer_disconnected(m_target_addr);
        stop_ping_timer();
        stop_timeout_timer();
        m_handshake_complete = false;
        m_idle_gate.reset();
        m_peer.reset();
    }

    // INetwork: an outbound dial failed BEFORE the socket came up (ECONNREFUSED /
    // ETIMEDOUT / DNS-resolve). connected() never ran, so feed the dead target to
    // the peer scorer (#940 dial-failure leg: attempt++/backoff + score drop +
    // addrman Attempt) so the dial plan rotates off it. No redial issued here —
    // the driver/reconnect loop owns the actual retry (no retry-storm).
    void connect_failed(const NetService& addr) override
    {
        if (m_on_dial_failed)
            m_on_dial_failed(addr);
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

    /// Guard-rail (integrator 2026-07-30, BCH): disable idle-progress eviction for
    /// single-peer coins that run their own block-download stall recovery, so this
    /// path never drops their only connection. BTC/DGB leave it enabled (default).
    void set_idle_eviction_enabled(bool enabled) { m_eviction_enabled = enabled; }

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
        // Report a handshaked peer's loss to the scorer (see disconnect()).
        if (m_handshake_complete && m_on_peer_disconnected)
            m_on_peer_disconnected(m_target_addr);
        if (m_peer)
        {
            m_peer.reset();
        }
        // else: already disconnected (double-fire race) — safe to ignore

        stop_ping_timer();
        stop_timeout_timer();
        m_handshake_complete = false;
        m_idle_gate.reset();
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

        // Sample the idle-progress gate AFTER dispatch: got_response() runs during
        // dispatch, so pending/progress reflect this message before we (re)arm.
        sample_idle_gate();
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_p2p.prefix;
    }

    void submit_block(BlockType& block)
    {
        if (m_peer)
        {
            auto rmsg = bip110::coin::p2p::message_block::make_raw(block, {});
            m_peer->write(rmsg);
        } else
        {
            LOG_ERROR << "No bitcoind connection when block submittal attempted!";
            throw std::runtime_error("No bitcoind connection in submit_block");
        }
    }

    /// Set callback for received addr messages (peer discovery). The vector is
    /// already NODE_BLAKE2B-filtered + sanity-clamped by the addr handler; the
    /// second arg is the peer that gossiped them (addrman source-group key).
    void set_addr_callback(AddrCallback cb) { m_addr_callback = std::move(cb); }
    /// Peer-lifecycle seams (feed the scored/bucketed peer manager).
    void set_on_peer_connected(PeerLifecycleCallback cb) { m_on_peer_connected = std::move(cb); }
    void set_on_peer_disconnected(PeerLifecycleCallback cb) { m_on_peer_disconnected = std::move(cb); }
    void set_on_dial_failed(PeerLifecycleCallback cb) { m_on_dial_failed = std::move(cb); }
    /// Enable Knots getaddr-on-connect peer crawl (one GETADDR per connection).
    void enable_getaddr_discovery() { m_send_getaddr_on_connect = true; }
    /// Self-address advertisement seams (Knots net.cpp GetLocalAddress /
    /// SeenLocal / MaybeSendAddr). Shared with the inbound + fan-out arms.
    void set_local_addr_table(std::shared_ptr<LocalAddrTable> t) { m_local_addr = std::move(t); }
    void set_self_nonce_registry(std::shared_ptr<SelfNonceRegistry> r) { m_self_nonce = std::move(r); }
    /// addr-relay sink (Knots RelayAddress 2-hop gossip). Fresh banked batches are
    /// forwarded here for onward relay to other fork slots.
    void set_addr_relay_sink(AddrRelaySink cb) { m_addr_relay_sink = std::move(cb); }
    /// Whether getaddr-on-connect crawl is enabled (diagnostics / KATs).
    bool getaddr_discovery_enabled() const { return m_send_getaddr_on_connect; }
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

    /// Knots MaybeSendAddr self-announce: push a 1-record `addr` carrying OUR
    /// reachable IP:listen-port + NODE_BLAKE2B so this peer banks us and gossips
    /// us onward — the load-bearing half of the reachability fix (just listening
    /// is not enough; the fork network must LEARN our address). No-op until we
    /// know a routable local addr (best_local()), and rate-limited to
    /// SELF_ADDR_INTERVAL_SEC. Called at verack and on the ping tick so a
    /// later-learned local addr is announced on the next opportunity.
    void maybe_send_self_addr()
    {
        if (!m_peer || !m_handshake_complete || !m_local_addr)
            return;
        auto best = m_local_addr->best_local();
        if (!best)
            return;
        auto now = std::chrono::steady_clock::now();
        if (m_self_addr_sent &&
            now - m_last_self_addr < std::chrono::seconds(SELF_ADDR_INTERVAL_SEC))
            return;
        btc_addr_record_t rec;
        rec.m_services  = OUR_SERVICES;
        rec.m_endpoint  = *best;
        rec.m_timestamp = static_cast<uint32_t>(core::timestamp());
        auto msg = message_addr::make_raw(std::vector<btc_addr_record_t>{rec});
        m_peer->write(msg);
        m_self_addr_sent = true;
        m_last_self_addr = now;
        LOG_DEBUG_COIND << "[" << m_chain_label << "] self-addr announced "
                        << best->to_string() << " to " << m_target_addr.to_string();
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
    /// BTC: MSG_WITNESS_BLOCK (0x40000002) — BIP 144 witness-bearing block.
    /// (LTC used MSG_MWEB_BLOCK 0x60000002 for MWEB state extraction;
    /// bitcoind doesn't recognise that inv type and would peer-disconnect.)
    void request_full_block(const uint256& block_hash)
    {
        if (m_peer) {
            auto msg = message_getdata::make_raw(
                {inventory_type(inventory_type::witness_block, block_hash)});
            m_peer->write(msg);
        }
    }

    /// TIER-3 daemonless input pricing: request one or more parent txs via
    /// getdata(MSG_WITNESS_TX 0x40000001, BIP 144). A peer answers only from its
    /// mempool/relay set; an arriving tx flows through the normal message_tx ->
    /// new_tx path where the run loop prices it (self-authenticating txid).
    void request_tx(const std::vector<uint256>& txids)
    {
        if (!m_peer || txids.empty()) return;
        std::vector<inventory_type> vinv;
        vinv.reserve(txids.size());
        for (const auto& h : txids)
            vinv.emplace_back(inventory_type::witness_tx, h);
        auto msg = message_getdata::make_raw(vinv);
        m_peer->write(msg);
    }

    /// Request a block via plain MSG_BLOCK (0x02) getdata.
    /// Works for any block regardless of MWEB support.
    void request_block(const uint256& block_hash)
    {
        if (m_peer) {
            auto msg = message_getdata::make_raw(
                {inventory_type(inventory_type::block, block_hash)});
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

    /// Peer metadata accessors
    uint32_t peer_version() const { return m_peer_version; }
    const std::string& peer_subver() const { return m_peer_subver; }
    uint32_t peer_start_height() const { return m_peer_start_height; }
    int64_t peer_uptime_sec() const {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_connected_at).count();
    }
    /// Steady-clock stamp of the current connection (peer-discovery diagnostics).
    std::chrono::steady_clock::time_point connected_at() const { return m_connected_at; }
    /// The address this node was dialed at (the addrman/scorer key). Stable across
    /// the connection lifetime; used by the dashboard peer directory + tests.
    const NetService& target_addr() const { return m_target_addr; }
    const std::string& chain_label() const { return m_chain_label; }

    /// TEST-ONLY seam: stamp the version-message metadata the version handler
    /// would set on a live handshake, so network-free KATs can exercise the
    /// dashboard peer-detail read path (for_each_live_slot) without a socket.
    /// Not used by production code.
    void set_peer_metadata_for_test(uint32_t v, std::string subver, uint32_t h) {
        m_peer_version = v;
        m_peer_subver = std::move(subver);
        m_peer_start_height = h;
    }

    /// Set mempool reference for compact block reconstruction.
    void set_mempool(Mempool* mp) { m_mempool = mp; }

    /// Enable BIP 35 mempool request after handshake.
    /// Call after UTXO is initialized so incoming txs can have fees computed.
    void enable_mempool_request() { m_request_mempool_on_connect = true; }

    /// Relay a pre-serialized block via P2P.
    /// Uses compact block format (BIP 152 v2) for peers that support it,
    /// falling back to full block otherwise.
    bool submit_block_raw(const std::vector<unsigned char>& block_bytes)
    {
        if (!m_peer) return false;

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
                // Also cache raw bytes so a getdata(MSG_BLOCK) fallback (peer
                // failed compact reconstruction) can be served the full body.
                cache_served_block(block_bytes);

                LOG_INFO << "[" << m_chain_label << "] Sent compact block "
                         << blockhash.GetHex()
                         << " (" << cb.short_ids.size() << " short IDs, "
                         << cb.prefilled_txns.size() << " prefilled)";
                return true;
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
        return submit_block_full(block_bytes);
    }

    /// Send a full block message (legacy relay). Returns true iff a peer
    /// was connected and the block bytes were written to it.
    bool submit_block_full(const std::vector<unsigned char>& block_bytes)
    {
        if (!m_peer) return false;
        // Cache before relay so a follow-up getdata for the body can be served
        // (single-peer bitcoind drops the won block otherwise — no RPC path here).
        cache_served_block(block_bytes);
        PackStream ps(block_bytes);
        auto rmsg = std::make_unique<RawMessage>("block", std::move(ps));
        m_peer->write(rmsg);
        LOG_INFO << "[" << m_chain_label << "] Sent full block message ("
                 << block_bytes.size() << " bytes) to " << m_target_addr.to_string();
        return true;
    }

    /// Cache the raw bytes + hash of the block we just relayed, so the getdata
    /// handler can serve the body on a subsequent MSG_BLOCK / MSG_WITNESS_BLOCK
    /// request. Additive: no effect on the relay itself.
    void cache_served_block(const std::vector<unsigned char>& block_bytes)
    {
        m_served_block_bytes = block_bytes;
        m_served_block_hash  = uint256();
        try {
            PackStream hp(block_bytes);
            BlockHeaderType hdr;
            hp >> hdr;
            auto packed_hdr = pack(hdr);
            m_served_block_hash = Hash(packed_hdr.get_span());
        } catch (const std::exception& e) {
            LOG_WARNING << "[" << m_chain_label
                        << "] cache_served_block: header hash failed: " << e.what();
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

        // Post-handshake liveness is governed by the idle-progress gate
        // (sample_idle_gate) -- NOT by resetting a fixed window on every inbound
        // byte. That reset-on-any-byte was the bug: peer chatter kept a
        // non-progressing peer alive forever.
        if (m_handshake_complete)
            return;

        ensure_timeout_timer();
        m_timeout_timer->restart(CONNECT_TIMEOUT_SEC);
    }

    // Sample the idle-progress gate and arm/reset/keep/stop the eviction window.
    // Driven from handle() (post-dispatch) and the ping tick (so a totally-silent
    // non-progressing peer holding a pending request is still caught).
    void sample_idle_gate()
    {
        if (!m_peer || !m_handshake_complete)
            return;

        const bool     pending = m_peer->has_pending();
        const uint64_t epoch   = m_peer->progress_epoch();

        // Guard-rail (integrator 2026-07-30, BCH single-peer no-op): when
        // m_eviction_enabled is false the gate returns Stop unconditionally, so
        // the only connection is never dropped by this path.
        switch (m_idle_gate.evaluate(m_eviction_enabled, pending, epoch))
        {
            case IdleProgressGate::Action::Arm:
            case IdleProgressGate::Action::Reset:
                ensure_timeout_timer();
                m_timeout_timer->restart(IDLE_TIMEOUT_SEC);
                break;
            case IdleProgressGate::Action::Stop:
                stop_timeout_timer();   // synced/idle peer survives (zero pending)
                break;
            case IdleProgressGate::Action::KeepAsIs:
                break;                  // chatter must NOT reset a running window
        }
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
        // Self-connect guard (Knots CConnman: a version whose nonce equals one WE
        // sent means we dialed our own listener). Drop before anything else so our
        // own address never latches a slot or gets re-banked. Only reachable once
        // self-advertise is live (our routable addr is gossiped back + drawn by
        // the dial planner).
        if (m_self_nonce && m_self_nonce->is_self(msg->m_nonce)) {
            LOG_INFO << "[" << m_chain_label << "] REJECT peer — connected to self "
                     << "(version nonce match) at " << m_target_addr.to_string();
            timeout("connected to self");
            return;
        }

        m_peer_services = msg->m_services;
        m_peer_version = msg->m_version;
        m_peer_subver = msg->m_subversion;
        m_peer_start_height = msg->m_start_height;
        LOG_INFO << "[" << m_chain_label << "] version: " << msg->m_command
                 << " start_height=" << msg->m_start_height
                 << " services=0x" << std::hex << msg->m_services << std::dec
                 << " subver=" << msg->m_subversion;

        // Knots SeenLocal(): the peer echoed the address it saw us dial FROM in its
        // version.addr_to. On a no-NAT host that IP IS our reachable IP; score it
        // (the port is discarded — best_local() substitutes our real listen port).
        if (m_local_addr)
            m_local_addr->seen_local(msg->m_addr_to.m_endpoint.address());

        // BIP-110 fork-peer gate: only NODE_BLAKE2B (bit 28) peers follow the
        // BLAKE2b hard-fork chain. A canonical-SHA256d Bitcoin node would feed us
        // the foreign (higher-work) SHA256d chain, so drop it before verack and
        // let the standalone failover dialer walk to a fork peer.
        if (!(msg->m_services & NODE_BLAKE2B)) {
            LOG_INFO << "[" << m_chain_label << "] REJECT peer — no NODE_BLAKE2B (services=0x"
                     << std::hex << msg->m_services << std::dec << " subver=" << msg->m_subversion
                     << "); not a BIP-110 fork peer";
            timeout("peer lacks NODE_BLAKE2B");
            return;
        }
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
        m_idle_gate.reset();
        // The idle-progress gate now owns the eviction window. Nothing is pending
        // yet, so it stays disarmed (a synced/idle peer is never evicted); the
        // post-dispatch sample and the ping tick below arm it once we have an
        // outstanding request that stops making progress.
        stop_timeout_timer();

        ensure_ping_timer();
        m_ping_timer->start(PING_INTERVAL_SEC, [this]() {
            send_ping();
            sample_idle_gate();   // catch a silent, non-progressing peer
            maybe_send_self_addr();  // re-announce our reachable addr (Knots MaybeSendAddr)
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

        // Peer-lifecycle: a completed handshake is a live, answerable NODE_BLAKE2B
        // fork peer. Promote it in the scored/bucketed peer manager (addrman
        // Good() -> tried), so the tried set fills and the fan-out pool + serve
        // path have real dial candidates. m_target_addr is the dialed key.
        if (m_on_peer_connected)
            m_on_peer_connected(m_target_addr);

        // Self-authenticated fork-peer harvest into the shared addrman. We have
        // DIRECTLY observed this peer advertise NODE_BLAKE2B in its version (the
        // gate in handle(version) rejected non-fork peers BEFORE verack), so this
        // is a proven, live fork node — bank it as if it had been gossiped by
        // itself. This is the load-bearing growth path: Core/Knots answers getaddr
        // slowly (poisson ~30-120s), rate-limits it, and the reply is dominated by
        // canonical (non-NODE_BLAKE2B) addrs that the fork filter drops — so the
        // gossip crawl alone leaves the addrman latched at the seed (DATABASE=1).
        // Every fork peer we ACTUALLY connect to (explicit seed, primary, fan-out
        // probe) is a real dial candidate; banking it on handshake is what grows
        // the addrman past 1 with the reachable fork mesh. notify_connected above
        // only PROMOTES an already-present entry (addrman.good early-returns when
        // absent), so without this the connect never adds. Idempotent: a repeat
        // handshake just refreshes the entry. Source == self (the peer vouches for
        // its own address); m_addr_callback is the same NODE_BLAKE2B-only intake
        // wired for gossip, so a non-fork peer can never reach here (gated above).
        if (m_addr_callback)
            m_addr_callback({ m_target_addr }, m_target_addr);

        // Knots getaddr-on-connect (peer crawl). Core sends GETADDR to outbound
        // peers at verack (net_processing.cpp SetupAddressRelay); we ask this peer
        // once for its address set. A fork ORACLE answers with the reachable
        // NODE_BLAKE2B mesh, which the addr handler fork-filters + banks into the
        // addrman — this is what turns ONE oracle link into MANY dial candidates.
        if (m_send_getaddr_on_connect && !m_getaddr_sent) {
            m_getaddr_sent = true;
            send_getaddr();
            LOG_INFO << "[" << m_chain_label << "] Sent getaddr (peer crawl) to "
                     << m_target_addr.to_string();
        }

        // Knots MaybeSendAddr self-announce at handshake (the reachability fix):
        // tell this peer our reachable IP:8333 so it banks + gossips us onward.
        maybe_send_self_addr();
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
                // BTC advertises NODE_WITNESS — getdata for blocks must use
                // MSG_WITNESS_BLOCK (0x40000002) per BIP 144, otherwise the
                // peer drops witness data on the wire.
                vinv.push_back(inventory_type(
                    inventory_type::witness_block, inv.m_hash));
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
        // Catch to ensure full_block event always fires.
        try { m_peer->get_block(blockhash, block); } catch (...) {}
        try { m_peer->get_header(blockhash, header); } catch (...) {}
        LOG_INFO << "[" << m_chain_label << "] Full block received: "
                 << blockhash.GetHex().substr(0, 16) << "..."
                 << " txs=" << block.m_txs.size();
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

            // BIP 130: when receiving a small headers batch (new block
            // announcement), request the full block via getdata.
            // BTC: MSG_WITNESS_BLOCK (0x40000002) — BIP 144 witness-bearing.
            // LTC's MSG_MWEB_BLOCK (0x60000002) would be rejected by bitcoind.
            if (vheaders.size() <= 3 && m_peer) {
                for (auto& hdr : vheaders) {
                    auto packed = pack(hdr);
                    auto bhash = Hash(packed.get_span());
                    auto getdata_msg = message_getdata::make_raw(
                        {inventory_type(inventory_type::witness_block, bhash)});
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
        // Knots addr ingest (net_processing.cpp addr handling), fork-adjusted.
        // Every gossiped record is filtered HERE, where the wire services +
        // timestamp are still present, then the survivors are forwarded to the
        // bucketed addrman via m_addr_callback (the addrman intake is a NetService
        // + source-group, so the filter MUST happen upstream of it).
        if (!m_addr_callback || msg->m_addrs.empty())
            return;

        // Fork filter + future-poison drop (the SSOT lives in
        // filter_fork_addr_records above; the handler only wires the socket).
        const int64_t now = static_cast<int64_t>(core::timestamp());
        size_t dropped_nonfork = 0, dropped_future = 0;
        std::vector<NetService> ok = filter_fork_addr_records(
            msg->m_addrs, now, &dropped_nonfork, &dropped_future);
        const NetService source = m_peer ? m_peer->get_addr() : m_target_addr;
        if (!ok.empty()) {
            // source = the peer that gossiped these (addrman source-group key,
            // bounds how far one source can spray the new table).
            m_addr_callback(ok, source);
        }

        // Knots RelayAddress (2-hop gossip): forward a SMALL, FRESH batch of the
        // NODE_BLAKE2B survivors to other fork slots so a learned peer's
        // reachability spreads through us. Batch capped at 10 and only records
        // stamped within the last 10 min (Knots relays nTime <= 10 min old); the
        // sink (main) excludes the source and picks <=2 destinations.
        if (m_addr_relay_sink) {
            std::vector<btc_addr_record_t> fresh;
            for (const auto& rec : msg->m_addrs) {
                if (!(rec.m_services & NODE_BLAKE2B)) continue;
                const int64_t ts = static_cast<int64_t>(rec.m_timestamp);
                if (ts > now + 10 * 60 || ts < now - 10 * 60) continue;
                fresh.push_back(rec);
                if (fresh.size() >= 10) break;
            }
            if (!fresh.empty())
                m_addr_relay_sink(fresh, source);
        }
        LOG_DEBUG_COIND << "[" << m_chain_label << "] addr: " << msg->m_addrs.size()
                        << " received, " << ok.size() << " NODE_BLAKE2B kept ("
                        << dropped_nonfork << " non-fork, " << dropped_future
                        << " future-dated dropped)";
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
                     << " txs=" << result.block.m_txs.size();
            // Deliver as a full block
            m_peer->get_block(blockhash, result.block);
            auto header = static_cast<BlockHeaderType>(result.block);
            m_peer->get_header(blockhash, header);
            m_coin->full_block.happened(result.block);
        } else if (result.merkle_mismatch) {
            LOG_WARNING << "[" << m_chain_label << "] Compact block reconstruction merkle "
                        << "mismatch for " << blockhash.GetHex()
                        << " — discarding, requesting full block via getdata";
            request_full_block(blockhash);
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

        // Same merkle backstop as ReconstructBlock: even with the missing txns
        // now authoritative from blocktxn, a short-id-matched slot could carry a
        // 48-bit collision. Verify against the header commitment before delivering;
        // on mismatch discard and fall back to a full getdata.
        if (ReconstructedMerkleRoot(block.m_txs) != cb.header.m_merkle_root) {
            LOG_WARNING << "[" << m_chain_label << "] blocktxn-completed block merkle "
                        << "mismatch for " << blockhash.GetHex()
                        << " — discarding, requesting full block via getdata";
            request_full_block(blockhash);
            m_pending_cmpct.reset();
            m_pending_missing_indexes.clear();
            return;
        }

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
        // Serve the body of our most-recently-relayed block on demand. After
        // our inv/compact announcement bitcoind requests it via
        // getdata(MSG_BLOCK) or getdata(MSG_WITNESS_BLOCK); without serving it
        // the single c2pool peer never delivers the body and bitcoind drops the
        // won block ("Timeout downloading block, disconnecting"). Witness and
        // non-witness requests collapse via base_type(); the cached bytes are
        // the exact relayed block (hash-identical). Other inv kinds (tx, ...)
        // remain unserved.
        size_t served = 0;
        for (const auto& req : msg->m_requests) {
            if (req.base_type() != inventory_type::block) continue;
            if (m_served_block_bytes.empty() || req.m_hash != m_served_block_hash) {
                LOG_DEBUG_COIND << "[" << m_chain_label << "] getdata(block) for unknown "
                                << req.m_hash.GetHex() << " — ignoring";
                continue;
            }
            PackStream ps(m_served_block_bytes);
            auto rmsg = std::make_unique<RawMessage>("block", std::move(ps));
            m_peer->write(rmsg);
            ++served;
            LOG_INFO << "[" << m_chain_label << "] Served full block via getdata "
                     << req.m_hash.GetHex() << " (" << m_served_block_bytes.size()
                     << " bytes)";
        }
        if (served == 0)
            LOG_DEBUG_COIND << "[" << m_chain_label << "] Peer getdata with "
                            << msg->m_requests.size() << " items (none served)";
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

} // namespace bip110