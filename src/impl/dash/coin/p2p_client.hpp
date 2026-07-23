// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH embedded coin-network P2P client (E1: instantiate + outbound dial).
//
// Live-dial counterpart of the S8 socket-node skeleton (p2p_node.hpp). Where
// NodeP2P owns only the request/reply lifecycle over an already-attached
// socket, CoinClient owns the WHOLE outbound connection to a dashd peer:
//
//   * dial: core::Factory<core::Client> resolve/connect to a HOST:PORT target
//     (repeatable targets rotate round-robin on reconnect — DialPlan below);
//   * handshake: version/verack (HandshakeTracker below — the KAT'd state
//     machine), advertising protocol 70230, the SAME version the vendored
//     SML/clsig codecs assume (vendor/smldiff.hpp, vendor/quorum_tail.hpp);
//   * keep-alive: 30s ping cadence + idle/handshake timeout teardown;
//   * reconnect: 30s retry while disconnected, rotating the dial plan.
//
// Ported 1:1 from the PROVEN per-coin clients (src/impl/dgb/coin/p2p_node.hpp
// mirror lineage btc <- ltc), trimmed to the E1 scope: NO ingest legs. The
// tx/block/headers/inv/clsig/mnlistdiff handlers parse and FIRE the
// dash::interfaces::Node events (new_block / new_tx / full_block / new_headers
// / new_chainlock) — that event surface is the seam later slices (E2+) attach
// CoinStateMaintainer / HeaderChain / Mempool ingest to. With no subscribers
// (the E1 run_node wiring), every event is a no-op and NodeCoinState stays
// default-unpopulated, so get_work() keeps taking the retained dashd-RPC
// fallback — zero behavior change on the mining path.
//
// EXPLICITLY NOT HERE (later slices): getheaders sync driving (E2 — dash
// BlockType serialization is header-only, so multi-entry `headers` batches
// need a raw-payload parser first), getdata pulls, compact-block
// reconstruction, mnlistdiff-driven SML maintenance, fee pricing.
//
// Wire magic (pchMessageStart): mainnet bf0c6bbd / testnet cee2caff — supplied
// by run_node via config.coin()->m_p2p.prefix, never hard-coded here. The
// coin-network magic is DISTINCT from the sharechain PREFIX (pool peer
// isolation primitive): different layers, never conflated.
//
// Header-only to match the sibling dash coin leaves.

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"
#include "block.hpp"
#include "transaction.hpp"

#include <impl/dash/crypto/hash_x11.hpp>   // block identity on Dash = X11(header)
#include <impl/dash/coin/governance_object.hpp> // govobject_hash / govvote_signature_hash (dashcore-exact digests)

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/log.hpp>
#include <core/random.hpp>
#include <core/factory.hpp>
#include <core/timer.hpp>

namespace dash
{
namespace coin
{
namespace p2p
{

namespace io = boost::asio;

inline std::string parse_net_error(const boost::system::error_code& ec)
{
    switch (ec.value())
    {
    case boost::asio::error::eof:
        return "EOF, socket disconnected";
    default:
        return ec.message();
    }
}

// ── Handshake state machine (pure, KAT-able) ─────────────────────────────
//
// version/verack progress tracker, extracted from the client so the
// transition rules are unit-testable without sockets:
//
//   Idle --on_connected()--> Connected        (socket up, our version sent)
//   Connected --on_version()--> VersionReceived (peer version seen, verack sent)
//   VersionReceived --on_verack()--> Complete   (peer verack seen)
//
// verack-before-version is tolerated (Connected --on_verack()--> Complete;
// some implementations ack eagerly). Events received while Idle are ignored
// (a stray message must not fabricate a session). reset() returns to Idle on
// any disconnect/error.
class HandshakeTracker
{
public:
    enum class State { Idle, Connected, VersionReceived, Complete };

private:
    State m_state{State::Idle};

public:
    State state() const { return m_state; }
    bool complete() const { return m_state == State::Complete; }

    void on_connected() { m_state = State::Connected; }

    // Returns true if this version message is the handshake-advancing one
    // (i.e. we should reply verack); duplicates / pre-connect strays => false.
    bool on_version()
    {
        if (m_state != State::Connected)
            return false;
        m_state = State::VersionReceived;
        return true;
    }

    // Returns true if the handshake just completed.
    bool on_verack()
    {
        if (m_state != State::Connected && m_state != State::VersionReceived)
            return false;
        m_state = State::Complete;
        return true;
    }

    void reset() { m_state = State::Idle; }
};

// ── Dial plan (pure, KAT-able) ───────────────────────────────────────────
//
// Ordered outbound targets for --coin-p2p-connect (repeatable). current() is
// the target being dialed; advance() rotates round-robin so a dead first
// target does not wedge reconnection when alternates were supplied.
class DialPlan
{
    std::vector<NetService> m_targets;
    std::size_t m_index{0};

public:
    void set_targets(std::vector<NetService> targets)
    {
        m_targets = std::move(targets);
        m_index = 0;
    }

    bool empty() const { return m_targets.empty(); }
    std::size_t size() const { return m_targets.size(); }

    const NetService& current() const { return m_targets.at(m_index); }

    // Rotate to the next target (single-target plans stay put) and return it.
    const NetService& advance()
    {
        if (!m_targets.empty())
            m_index = (m_index + 1) % m_targets.size();
        return current();
    }
};

#define ADD_P2P_HANDLER(name)\
    void handle(std::unique_ptr<dash::coin::p2p::message_##name> msg)

// Outbound coin-network client: dial, handshake, keep-alive, reconnect.
// Concrete on dash::Config (per-coin isolation — no cross-coin template reuse).
template <typename ConfigType>
class CoinClient : public core::ICommunicator, public core::INetwork, public core::Factory<core::Client>
{
    using config_t = ConfigType;

private:
    static constexpr time_t CONNECT_TIMEOUT_SEC = 10;
    static constexpr time_t IDLE_TIMEOUT_SEC = 100;
    static constexpr time_t PING_INTERVAL_SEC = 30;
    static constexpr time_t RECONNECT_INTERVAL_SEC = 30;

    // Dash Core PROTOCOL_VERSION we advertise. MUST stay >= 70230: the
    // vendored mnlistdiff/clsig wire codecs (vendor/smldiff.hpp,
    // vendor/quorum_tail.hpp) parse the >=70230 layout.
    static constexpr uint32_t PROTOCOL_VERSION = 70230;
    static constexpr uint64_t NODE_NETWORK = 1;   // no segwit/witness on Dash
    static constexpr uint16_t MAINNET_P2P_PORT = 9999;

    dash::interfaces::Node* m_coin;
    io::io_context* m_context;
    config_t* m_config;
    p2p::Handler m_handler;

    std::unique_ptr<Connection> m_peer;
    std::unique_ptr<core::Timer> m_reconnect_timer;
    std::unique_ptr<core::Timer> m_ping_timer;
    std::unique_ptr<core::Timer> m_timeout_timer;
    DialPlan m_dial_plan;
    bool m_reconnect_enabled = false;
    HandshakeTracker m_handshake;
    std::string m_chain_label = "COIN-P2P";

    // Peer metadata from the version message
    uint64_t m_peer_services{0};
    uint32_t m_peer_version{0};
    std::string m_peer_subver;
    uint32_t m_peer_start_height{0};
    std::chrono::steady_clock::time_point m_connected_at{std::chrono::steady_clock::now()};

    // E2+ seams (callbacks, all optional)
    using AddrCallback = std::function<void(const std::vector<NetService>&)>;
    AddrCallback m_addr_callback;
    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;
    using HandshakeCallback = std::function<void()>;
    HandshakeCallback m_on_handshake_complete;

public:
    CoinClient(io::io_context* context, dash::interfaces::Node* coin, config_t* config,
               const std::string& chain_label = "COIN-P2P")
        : core::Factory<core::Client>(context, this, chain_label)
        , m_coin(coin), m_context(context), m_config(config)
        , m_chain_label(chain_label)
    {
    }

    ~CoinClient()
    {
        m_reconnect_enabled = false;
        if (m_reconnect_timer) m_reconnect_timer->stop();
        stop_ping_timer();
        stop_timeout_timer();
    }

    /// Dial the given targets with automatic reconnection (30s interval,
    /// round-robin over the target list on each retry).
    void connect(std::vector<NetService> targets)
    {
        if (targets.empty()) return;
        m_dial_plan.set_targets(std::move(targets));
        m_reconnect_enabled = true;
        LOG_INFO << "[" << m_chain_label << "] dialing "
                 << m_dial_plan.current().to_string()
                 << " (" << m_dial_plan.size() << " target[s] in plan)";
        core::Factory<core::Client>::connect(m_dial_plan.current());

        m_reconnect_timer = std::make_unique<core::Timer>(m_context, /*repeat=*/true);
        m_reconnect_timer->start(RECONNECT_INTERVAL_SEC, [this]() {
            if (!m_peer && m_reconnect_enabled) {
                const auto& target = m_dial_plan.advance();
                LOG_INFO << "[" << m_chain_label << "] reconnecting to "
                         << target.to_string() << "...";
                core::Factory<core::Client>::connect(target);
            }
        });
    }

    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_peer = std::make_unique<Connection>(m_context, socket);
        m_handshake.reset();
        m_handshake.on_connected();
        m_connected_at = std::chrono::steady_clock::now();
        LOG_INFO << "[" << m_chain_label << "] connected to "
                 << m_peer->get_addr().to_string() << " — sending version (proto "
                 << PROTOCOL_VERSION << ")";

        // Require version/verack progress soon after connect.
        ensure_timeout_timer();
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [this]() {
            timeout("handshake timeout");
        });

        auto msg_version = message_version::make_raw(
            PROTOCOL_VERSION,
            NODE_NETWORK,
            core::timestamp(),
            addr_t{NODE_NETWORK, m_peer->get_addr()},
            addr_t{NODE_NETWORK, NetService{"0.0.0.0", MAINNET_P2P_PORT}},
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
        m_handshake.reset();
        m_peer.reset();
    }

    /// Whether the version/verack handshake with the peer is complete.
    bool is_handshake_complete() const { return m_handshake.complete(); }
    bool is_connected() const { return m_peer != nullptr; }

    /// Peer metadata accessors (populated after the peer's version message).
    uint64_t peer_services() const { return m_peer_services; }
    uint32_t peer_version() const { return m_peer_version; }
    const std::string& peer_subver() const { return m_peer_subver; }
    /// Stable identity of the currently-connected peer (addr:port) — the R5
    /// govsync-completeness tracker keys peer coverage on this. Empty when no
    /// peer is connected.
    std::string peer_key() const {
        return m_peer ? m_peer->get_addr().to_string() : std::string();
    }
    uint32_t peer_start_height() const { return m_peer_start_height; }
    const std::string& chain_label() const { return m_chain_label; }
    int64_t peer_uptime_sec() const {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_connected_at).count();
    }

    // ── E2+ seams ────────────────────────────────────────────────────────
    /// addr-message peer discovery feed.
    void set_addr_callback(AddrCallback cb) { m_addr_callback = std::move(cb); }
    /// Peer's reported chain height (from its version message).
    void set_on_peer_height(PeerHeightCallback cb) { m_on_peer_height = std::move(cb); }
    /// Fired once per session when the version/verack handshake completes —
    /// the hook E2 uses to kick the initial getheaders/mnlistdiff sync.
    void set_on_handshake_complete(HandshakeCallback cb) { m_on_handshake_complete = std::move(cb); }

    /// Send a getheaders request (E2 sync driver seam; unused by E1 run_node).
    void send_getheaders(uint32_t version, const std::vector<uint256>& locator, const uint256& stop)
    {
        if (!m_peer) return;
        auto msg = message_getheaders::make_raw(version, locator, stop);
        m_peer->write(msg);
    }

    /// Send getaddr to request peer addresses (feeds set_addr_callback).
    void send_getaddr()
    {
        if (!m_peer) return;
        auto msg = message_getaddr::make_raw();
        m_peer->write(msg);
    }

    /// Request the peer's mempool inventory (E2a initial-sync seam). The peer
    /// replies with inv(MSG_TX,...) announcements; our inv handler currently
    /// only pulls block invs (tx pull is relay-driven), so this primes the
    /// relay feed — mempool contents are OPTIONAL for embedded-template
    /// viability (an empty mempool still yields a valid coinbase-only template),
    /// so this never gates populate; it only enriches the assembled template.
    void send_mempool()
    {
        if (!m_peer) return;
        auto msg = message_mempool::make_raw();
        m_peer->write(msg);
    }

    /// Request a full block via plain MSG_BLOCK getdata (E2 pull seam).
    void request_block(const uint256& block_hash)
    {
        if (!m_peer) return;
        auto msg = message_getdata::make_raw(
            {inventory_type(inventory_type::block, block_hash)});
        m_peer->write(msg);
    }

    /// Send a getmnlistd (SML diff request) — E2/E3 masternode-list sync seam.
    void send_getmnlistd(const uint256& base_block_hash, const uint256& block_hash)
    {
        if (!m_peer) return;
        auto msg = message_getmnlistd::make_raw(base_block_hash, block_hash);
        m_peer->write(msg);
    }

    /// Send a govsync (MNGOVERNANCESYNC) — E-SUPERBLOCK governance-object sync
    /// seam. A zero nProp with an EMPTY bloom filter requests ALL governance
    /// objects + votes; the peer streams them back as govobj / govobjvote
    /// messages, which the handlers above forward into the GovernanceStore.
    void send_govsync()
    {
        if (!m_peer) return;
        auto msg = message_govsync::make_raw(
            uint256::ZERO,               // nProp = 0 => request all
            std::vector<uint8_t>{},      // empty filter vData
            /*nHashFuncs=*/0u, /*nTweak=*/0u, /*nFlags=*/uint8_t{0});
        m_peer->write(msg);
    }

    /// Relay a pre-serialized won block as a `block` P2P message (the embedded
    /// P2P-relay arm of the dual-path broadcaster — dispatch wiring is a later
    /// slice; the method is here so the relay leg binds without a client edit).
    void submit_block_p2p_raw(const std::vector<unsigned char>& raw_block)
    {
        if (!m_peer)
        {
            LOG_ERROR << "[" << m_chain_label << "] no coin-network connection; "
                         "cannot relay won block over embedded P2P";
            return;
        }
        auto rmsg = std::make_unique<RawMessage>("block", PackStream(raw_block));
        m_peer->write(rmsg);
        LOG_INFO << "[" << m_chain_label << "] won-block relayed over embedded P2P ("
                 << raw_block.size() << " bytes)";
    }

    // ICommunicator
    void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        // Copy — the NetService reference may dangle once the socket is freed.
        NetService svc_copy = service;
        LOG_WARNING << "[" << m_chain_label << "] peer " << svc_copy.to_string()
                    << " disconnected: " << err
                    << (m_reconnect_enabled ? " (reconnect armed)" : "");
        if (m_peer)
            m_peer.reset();
        // else: already disconnected (double-fire race) — safe to ignore

        stop_ping_timer();
        stop_timeout_timer();
        m_handshake.reset();
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
            LOG_ERROR << "[" << m_chain_label << "] handle(" << rmsg->m_command
                      << ", " << rmsg->m_data.size() << " bytes): " << ec.what();
            return;
        } catch (const std::out_of_range&)
        {
            // Command outside our Handler set — dashd peers push spork/
            // governance/quorum traffic (spork, senddsq, qsendrecsigs, ...)
            // unsolicited; ignoring them is protocol-legal for a light client.
            LOG_DEBUG_COIND << "[" << m_chain_label << "] ignoring unhandled command '"
                            << rmsg->m_command << "' (" << rmsg->m_data.size() << " bytes)";
            return;
        }

        std::visit([&](auto& msg){ handle(std::move(msg)); }, result);
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_p2p.prefix;
    }

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
        auto timeout = m_handshake.complete() ? IDLE_TIMEOUT_SEC : CONNECT_TIMEOUT_SEC;
        m_timeout_timer->restart(timeout);
    }

    void timeout(const char* reason)
    {
        auto endpoint = m_peer ? m_peer->get_addr()
                               : (m_dial_plan.empty() ? NetService{} : m_dial_plan.current());
        error(std::string("peer timeout: ") + reason, endpoint);
    }

    void send_ping()
    {
        if (!m_peer || !m_handshake.complete())
            return;
        auto msg_ping = message_ping::make_raw(core::random::random_nonce());
        m_peer->write(msg_ping);
    }

    // ── handshake ────────────────────────────────────────────────────────

    ADD_P2P_HANDLER(version)
    {
        m_peer_services = msg->m_services;
        m_peer_version = msg->m_version;
        m_peer_subver = msg->m_subversion;
        m_peer_start_height = msg->m_start_height;
        LOG_INFO << "[" << m_chain_label << "] peer version: proto=" << msg->m_version
                 << " start_height=" << msg->m_start_height
                 << " services=0x" << std::hex << msg->m_services << std::dec
                 << " subver=" << msg->m_subversion;
        if (m_on_peer_height && msg->m_start_height > 0)
            m_on_peer_height(msg->m_start_height);
        if (!m_handshake.on_version())
            return;   // duplicate / stray version — do not re-ack
        auto verack_msg = message_verack::make_raw();
        m_peer->write(verack_msg);
    }

    ADD_P2P_HANDLER(verack)
    {
        if (!m_handshake.on_verack())
            return;   // stray verack outside a session

        // Arm the Connection request matchers (the E2 pull legs ride these).
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

        LOG_INFO << "[" << m_chain_label << "] handshake complete with "
                 << m_peer->get_addr().to_string()
                 << " (peer proto=" << m_peer_version
                 << " height=" << m_peer_start_height << ")";

        ensure_timeout_timer();
        m_timeout_timer->restart(IDLE_TIMEOUT_SEC);

        ensure_ping_timer();
        m_ping_timer->start(PING_INTERVAL_SEC, [this]() {
            send_ping();
        });

        if (m_on_handshake_complete)
            m_on_handshake_complete();
    }

    // ── keep-alive ───────────────────────────────────────────────────────

    ADD_P2P_HANDLER(ping)
    {
        auto msg_pong = message_pong::make_raw(msg->m_nonce);
        m_peer->write(msg_pong);
    }

    ADD_P2P_HANDLER(pong)
    {
        // liveness already refreshed by on_activity()
    }

    // ── E1 seam handlers: parse + fire interfaces::Node events, NO ingest ─

    ADD_P2P_HANDLER(inv)
    {
        // E1: announce-only. Block invs fire new_block (the E2 ingest seam);
        // NO getdata pulls yet — the ingest legs are later slices.
        for (auto& inv : msg->m_invs)
        {
            if (inv.base_type() == inventory_type::block)
            {
                LOG_INFO << "[" << m_chain_label << "] block inv "
                         << inv.m_hash.GetHex().substr(0, 16) << "...";
                m_coin->new_block.happened(inv.m_hash);
            }
        }
    }

    ADD_P2P_HANDLER(tx)
    {
        m_coin->new_tx.happened(Transaction(msg->m_tx));
    }

    ADD_P2P_HANDLER(block)
    {
        // E2a: BlockType now deserializes the full body (header + tx set), so
        // msg->m_block carries the transactions the ingest legs consume
        // (MnStateMachine::apply_block special txs, UTXO connect_block). The
        // full_block event below feeds the E2a live-feed bridge, which derives
        // the block height off the header chain and fires block_connected.
        auto header = static_cast<BlockHeaderType>(msg->m_block);
        auto packed_header = pack(header);
        auto blockhash = dash::crypto::hash_x11(packed_header.get_span());
        try { m_peer->get_block(blockhash, msg->m_block); } catch (...) {}
        try { m_peer->get_header(blockhash, header); } catch (...) {}
        LOG_INFO << "[" << m_chain_label << "] block received: "
                 << blockhash.GetHex().substr(0, 16) << "...";
        m_coin->full_block.happened(msg->m_block);
    }

    ADD_P2P_HANDLER(headers)
    {
        // E2a: BlockType now round-trips the wire `headers` layout (each entry
        // is an 80-byte header + CompactSize(0) tx-count), so multi-entry
        // getheaders-driven batches deserialize correctly. The new_headers event
        // feeds the E2a live-feed bridge -> HeaderChain::add_headers, which is
        // the tip authority driving the embedded template's next-work/MTP.
        std::vector<BlockHeaderType> vheaders;
        for (auto& block : msg->m_headers)
        {
            auto header = static_cast<BlockHeaderType>(block);
            auto packed_header = pack(header);
            auto blockhash = dash::crypto::hash_x11(packed_header.get_span());
            try { m_peer->get_header(blockhash, header); } catch (...) {}
            vheaders.push_back(header);
        }
        if (!vheaders.empty())
            m_coin->new_headers.happened(vheaders);
    }

    ADD_P2P_HANDLER(addr)
    {
        if (m_addr_callback && !msg->m_addrs.empty()) {
            std::vector<NetService> addrs;
            addrs.reserve(msg->m_addrs.size());
            for (auto& rec : msg->m_addrs)
                addrs.push_back(rec.m_endpoint);
            m_addr_callback(addrs);
        }
    }

    ADD_P2P_HANDLER(addrv2)
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] addrv2: "
                        << msg->m_addrs.size() << " record(s) (discovery seam is E2)";
    }

    ADD_P2P_HANDLER(clsig)
    {
        // ChainLock announcement — finalization signal. Fire the event seam;
        // recording into chainlocked_blocks is state population (E2+).
        LOG_INFO << "[" << m_chain_label << "] chainlock: height=" << msg->m_height
                 << " block=" << msg->m_block_hash.GetHex().substr(0, 16) << "...";
        m_coin->new_chainlock.happened({msg->m_block_hash, msg->m_height});
        // Daemonless CCbTx path: forward the recovered 96-byte threshold sig so
        // the maintainer can adopt this ChainLock as the coinbase bestCLSignature.
        // m_sig is decoded as a fixed 96-byte array (p2p_messages.hpp clsig);
        // guard the copy defensively in case a peer sent a short blob.
        if (msg->m_sig.size() == 96) {
            ::dash::interfaces::Node::ChainLockSigEvent ev;
            ev.height     = msg->m_height;
            ev.block_hash = msg->m_block_hash;
            std::copy(msg->m_sig.begin(), msg->m_sig.end(), ev.sig.begin());
            m_coin->new_chainlock_sig.happened(ev);
        }
    }

    ADD_P2P_HANDLER(mnlistdiff)
    {
        // SML/quorum snapshot. message_mnlistdiff already fully deserialized the
        // wire form into msg->m_diff (a vendor::CSimplifiedMNListDiff, see
        // p2p_messages.hpp) — apply_diff + the QuorumTail parser + the CCbTx
        // seed all consume it downstream. Fire the reception event so the
        // subscribed CoinStateMaintainer::on_mnlistdiff advances the local SML
        // (merkleRootMNList), the QuorumManager (merkleRootQuorums), and seeds
        // bestCL*/creditPool from the diff's embedded cbTx. With no subscriber
        // (E1 posture / coin-P2P off) this is a no-op and the node keeps taking
        // the retained dashd-RPC fallback — zero behavior change on that path.
        LOG_INFO << "[" << m_chain_label << "] mnlistdiff: base="
                 << msg->m_diff.baseBlockHash.GetHex().substr(0, 16)
                 << " tip=" << msg->m_diff.blockHash.GetHex().substr(0, 16)
                 << " +" << msg->m_diff.mnList.size() << "mn -"
                 << msg->m_diff.deletedMNs.size() << "del qtail="
                 << msg->m_diff.quorum_tail.size() << "B";
        m_coin->new_mnlistdiff.happened(msg->m_diff);
    }

    // ── E-SUPERBLOCK: governance objects + votes (daemonless superblock) ──

    ADD_P2P_HANDLER(govobj)
    {
        // MNGOVERNANCEOBJECT. Compute the dashcore object identity hash via
        // govobject_hash — the EXACT Governance::Object::GetHash() preimage
        // (governance/common.cpp), which dashcore itself notes "doesn't match
        // serialization": it EXCLUDES nCollateralHash and nObjectType,
        // hex-string-encodes vchData, and inserts legacy dummy bytes after
        // the outpoint. This hash is what votes carry as nParentHash, so a
        // wrong preimage silently detaches every vote from its trigger.
        // Pinned byte-exact against from-wire testnet objects in
        // test_dash_superblock.
        ::dash::interfaces::Node::GovObjectRecord rec;
        rec.object_hash = ::dash::coin::govobject_hash(
            msg->m_hash_parent, msg->m_revision, msg->m_time, msg->m_vch_data,
            msg->m_masternode_outpoint.hash, msg->m_masternode_outpoint.index,
            msg->m_vch_sig);
        rec.object_type = msg->m_object_type;
        rec.vch_data    = msg->m_vch_data;
        LOG_INFO << "[" << m_chain_label << "] govobj: hash="
                 << rec.object_hash.GetHex().substr(0, 16) << " type="
                 << rec.object_type << " data=" << rec.vch_data.size() << "B";
        m_coin->new_govobject.happened(rec);
    }

    ADD_P2P_HANDLER(govobjvote)
    {
        // MNGOVERNANCEOBJECTVOTE. Forward the vote for the maintainer to
        // VERIFY + TALLY. For TRIGGER funding votes — the only votes the
        // superblock tally consults — verification is BLS by the voting MN's
        // OPERATOR key (dashcore CGovernanceVote::IsValid with
        // useVotingKey=false -> CheckSignature(pubKeyOperator); the
        // ECDSA/keyIDVoting path applies ONLY to PROPOSAL funding votes).
        // vote_hash is govvote_signature_hash — the exact dashcore
        // GetSignatureHash preimage (outpoint, parent, outcome, signal, time;
        // vchSig excluded), i.e. the digest the operator key signed.
        ::dash::interfaces::Node::GovVoteRecord rec;
        rec.parent_hash      = msg->m_parent_hash;
        rec.mn_outpoint_hash = msg->m_masternode_outpoint.hash;
        rec.mn_outpoint_index= msg->m_masternode_outpoint.index;
        rec.mn_outpoint_key  = msg->m_masternode_outpoint.to_key();
        rec.outcome          = msg->m_vote_outcome;
        rec.signal           = msg->m_vote_signal;
        rec.time             = msg->m_time;
        rec.vch_sig          = msg->m_vch_sig;
        rec.vote_hash        = ::dash::coin::govvote_signature_hash(
            msg->m_masternode_outpoint.hash, msg->m_masternode_outpoint.index,
            msg->m_parent_hash, msg->m_vote_outcome, msg->m_vote_signal,
            msg->m_time);
        // DEBUG, not INFO: a mainnet governance sync streams tens of
        // thousands of votes (per-vote INFO would flood the journal).
        LOG_DEBUG_COIND << "[" << m_chain_label << "] govobjvote: parent="
                        << rec.parent_hash.GetHex().substr(0, 16) << " mn="
                        << rec.mn_outpoint_key.substr(0, 20) << " outcome="
                        << rec.outcome << " signal=" << rec.signal;
        m_coin->new_govvote.happened(rec);
    }

    ADD_P2P_HANDLER(govsync)   { /* inbound sync request — we don't serve governance */ }

    // ── tolerated / ignored peer traffic ─────────────────────────────────

    ADD_P2P_HANDLER(alert)
    {
        LOG_WARNING << "[" << m_chain_label << "] alert: " << msg->m_signature;
    }

    ADD_P2P_HANDLER(reject)
    {
        LOG_WARNING << "[" << m_chain_label << "] peer rejected " << msg->m_message
                    << " (code=" << static_cast<int>(msg->m_ccode)
                    << "): " << msg->m_reason
                    << " hash=" << msg->m_data.GetHex();
    }

    ADD_P2P_HANDLER(notfound)
    {
        for (auto& inv : msg->m_invs)
        {
            if (inv.base_type() == inventory_type::block)
            {
                // Complete the ReplyMatcher with an empty response so pending
                // requests don't wait out the 15s deferral timeout.
                try { m_peer->get_block(inv.m_hash, BlockType{}); } catch (...) {}
                try { m_peer->get_header(inv.m_hash, BlockHeaderType{}); } catch (...) {}
            }
        }
    }

    ADD_P2P_HANDLER(sendcmpct)
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] peer sendcmpct v"
                        << msg->m_version << " (compact-block lane is a later slice)";
    }

    ADD_P2P_HANDLER(feefilter)
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] peer feefilter: "
                        << msg->m_feerate << " duff/kB (fee pricing is a later slice)";
    }

    ADD_P2P_HANDLER(sendheaders)   { /* peer preference noted; we don't announce */ }
    ADD_P2P_HANDLER(sendaddrv2)    { /* acknowledged */ }
    ADD_P2P_HANDLER(mempool)       { /* we don't serve mempool */ }
    ADD_P2P_HANDLER(getaddr)       { /* we don't serve addresses */ }
    ADD_P2P_HANDLER(getdata)       { /* we don't serve blocks/txs */ }
    ADD_P2P_HANDLER(getblocks)     { /* we don't serve blocks */ }
    ADD_P2P_HANDLER(getheaders)    { /* we don't serve headers */ }
    ADD_P2P_HANDLER(getmnlistd)    { /* we don't serve SML diffs */ }
    ADD_P2P_HANDLER(cmpctblock)    { LOG_DEBUG_COIND << "[" << m_chain_label << "] cmpctblock ignored (E1)"; }
    ADD_P2P_HANDLER(getblocktxn)   { /* we never announce compact blocks */ }
    ADD_P2P_HANDLER(blocktxn)      { /* no pending compact block in E1 */ }

    #undef ADD_P2P_HANDLER
};

} // namespace p2p
} // namespace coin
} // namespace dash
