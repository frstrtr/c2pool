#pragma once

// Dash coin daemon P2P node.
// Connects to dashd for header sync, block relay, mempool.
// Simplified from LTC: no MWEB, no segwit, no compact blocks.

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"

#include <deque>
#include <iomanip>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>

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
class NodeP2P
    : public core::ICommunicator
    , public core::INetwork                              // inherits enable_shared_from_this<INetwork>
    , public core::Factory<core::Client>
{
    using config_t = ConfigType;
    using self_t   = NodeP2P<ConfigType>;
    // Bug 3 fix helper: get a NodeP2P-typed shared_ptr from the
    // INetwork-typed enable_shared_from_this base. We DON'T inherit
    // enable_shared_from_this<NodeP2P> too — that creates a diamond
    // (two enable_shared_from_this bases), which make_shared can't
    // resolve and leaves both weak_this empty → bad_weak_ptr at
    // first shared_from_this() call.
    std::shared_ptr<self_t> shared_self()
    {
        return std::static_pointer_cast<self_t>(this->shared_from_this());
    }

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

    // BIP 155 (Phase S1): set when the peer sends `sendaddrv2`. Governs
    // whether our getaddr reply uses `addrv2` (BIP 155) or classic `addr`.
    // We also send our own `sendaddrv2` unconditionally before verack so
    // peers send us addrv2 (with the broader address type set) going
    // forward — Dash protocol 70230+ always supports it.
    bool m_peer_supports_addrv2 = false;

    // BIP 152 (Phase S2) cmpctblock relay state. On inv(MSG_BLOCK) we
    // request the compact form via getdata(MSG_CMPCT_BLOCK); the peer
    // replies with `cmpctblock`, which we either reassemble immediately
    // (prefilled + mempool hits cover every index) or complete via a
    // getblocktxn → blocktxn round-trip. `m_pending_cmpctblocks` keeps
    // the partially-downloaded context keyed by blockhash until
    // blocktxn finishes it off; on failure we fall back to plain
    // getdata(MSG_BLOCK). Peer's `sendcmpct(announce)` preference and
    // version are recorded for future outbound-announce decisions.
    bool     m_peer_sendcmpct_announce = false;
    uint64_t m_peer_sendcmpct_version  = 0;
    std::map<uint256, std::unique_ptr<vendor::PartiallyDownloadedBlock>> m_pending_cmpctblocks;

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

    // Phase C-SML step 4: mnlistdiff arrival callback. Higher layer
    // (DashCoinBroadcaster) registers this to consume diffs and push
    // them through apply_diff + LevelDB persistence (steps 5-7).
    // Passing the diff by const-ref keeps a single copy live; the
    // handler synchronously runs the broadcaster-side dispatch.
    using MnListDiffCallback = std::function<void(
        const std::string& peer_key,
        const vendor::CSimplifiedMNListDiff& diff)>;
    MnListDiffCallback m_on_mnlistdiff;

    // Phase L step 3: ChainLock arrival callback. Higher layer (main_dash.cpp)
    // owns QuorumManager + HeaderChain and runs verify_chainlock; this
    // P2P-level handler just forwards the wire fields. Fired AFTER the
    // existing relay-trust record so the submit path stays unchanged
    // even if the verifier later proves the sig invalid (log-only at
    // MVP per the SML iteration plan).
    using ClsigCallback = std::function<void(
        const std::string& peer_key,
        int32_t height,
        const uint256& block_hash,
        const std::array<uint8_t, 96>& sig)>;
    ClsigCallback m_on_clsig;

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
        // Bug 3 root-cause fix: capture self via shared_from_this so the
        // timer handler keeps NodeP2P alive while it runs. Without this,
        // a peer destroy mid-firing UAFs on m_target_addr → garbage in
        // to_string() → boost::log codecvt crash.
        m_reconnect_timer->start(30, [self = shared_self()]() {
            if (!self->m_peer && self->m_reconnect_enabled) {
                LOG_INFO << "[DashP2P] Reconnecting to " << self->m_target_addr.to_string();
                self->core::Factory<core::Client>::connect(self->m_target_addr);
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
        // Bug 3 root-cause fix: self-capture so timeout() runs on a live NodeP2P.
        m_timeout_timer->start(CONNECT_TIMEOUT_SEC, [self = shared_self()]() {
            self->timeout("handshake timeout");
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

    // Phase C-SML step 4: ask this peer for the SML diff between two
    // blocks. base_block_hash = uint256::ZERO requests the full SML at
    // target_block_hash. Reply arrives async via handle_msg(mnlistdiff)
    // which fans out to m_on_mnlistdiff.
    void request_mnlistdiff(const uint256& base_block_hash,
                            const uint256& target_block_hash)
    {
        if (!m_peer) return;
        auto msg = message_getmnlistd::make_raw(
            base_block_hash, target_block_hash);
        m_peer->write(msg);
    }

    void set_on_mnlistdiff(MnListDiffCallback cb) { m_on_mnlistdiff = std::move(cb); }
    void set_on_clsig(ClsigCallback cb) { m_on_clsig = std::move(cb); }

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

        // BIP 155: signal addrv2 support before verack. Dashcore always
        // sends it in this position; peers that support BIP 155 will
        // reply with addrv2 instead of addr when relaying addresses.
        auto sendaddrv2_msg = message_sendaddrv2::make_raw();
        m_peer->write(sendaddrv2_msg);

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
        // Bug 3 root-cause fix: self-capture; send_ping touches m_peer + writes.
        m_ping_timer->start(PING_INTERVAL_SEC, [self = shared_self()]() { self->send_ping(); });

        // BIP 130: request header-first announcements
        auto msg_sendheaders = message_sendheaders::make_raw();
        m_peer->write(msg_sendheaders);

        // BIP 152 (Phase S2): negotiate compact-block relay.
        // Dashcore pins CMPCTBLOCKS_VERSION=1 (dashcore/src/net_processing.cpp)
        // — BIP 152 v2's wtxid short-IDs are meaningless on a segwit-free
        // chain, so v2 sendcmpct messages are silently dropped on the
        // receive side, leaving `m_provides_cmpctblocks=false` and
        // prompting the peer to ignore our later getdata(MSG_CMPCT_BLOCK).
        // announce=false keeps us in low-bandwidth mode: peers announce
        // tips via headers (BIP 130) as usual; we promote to
        // getdata(MSG_CMPCT_BLOCK) on arrival (see handle_msg(headers)).
        auto msg_sendcmpct = message_sendcmpct::make_raw(false, uint64_t{1});
        m_peer->write(msg_sendcmpct);

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
    // client behind dashd, not a crawler — reply with an empty list so
    // the peer knows we responded. Silent drop would have dashd keep
    // re-asking and eventually mark us as a non-responding node.
    // BIP 155: use `addrv2` if the peer signaled it via `sendaddrv2`,
    // else classic `addr`. Either way empty until we start crawling.
    void handle_msg(std::unique_ptr<message_getaddr>)
    {
        if (m_peer_supports_addrv2) {
            auto reply = message_addrv2::make_raw({});
            m_peer->write(reply);
        } else {
            auto reply = message_addr::make_raw({});
            m_peer->write(reply);
        }
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

        // Iteration-2 hardening: chainlocked_blocks write was MOVED to
        // the on_clsig callback in main_dash, gated on BLS verify
        // success. The eager relay-trust write here was spoofable —
        // any peer could send us a fake clsig blob and we'd record
        // their target block as ChainLock-finalized. Now we wait for
        // verify_chainlock() to confirm via real BLS + quorum lookup.
        //
        // new_chainlock event is also gated by the callback (no current
        // subscribers, but if one ever lands it should see the same
        // verify discipline).
        if (m_on_clsig && msg->m_sig.size() == 96) {
            std::array<uint8_t, 96> sig_arr{};
            std::memcpy(sig_arr.data(), msg->m_sig.data(), 96);
            m_on_clsig(m_target_addr.to_string(), h, bhash, sig_arr);
        }
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

    // Phase C-SML step 4: peer asks US for an SML diff. We don't serve
    // mnlistdiff (we're a consumer, not a full validator with SML build
    // state). Drop silently — same shape as our `handle_msg(mempool)`
    // no-op. Logging at debug only because honest peers don't ask us
    // for mnlistdiff except by mistake.
    void handle_msg(std::unique_ptr<message_getmnlistd> msg)
    {
        if (!msg) return;
        LOG_DEBUG_COIND << "[DashP2P] ignoring getmnlistd from peer "
                        << "(c2pool-dash is mnlistdiff consumer only)";
    }

    // Phase C-SML step 4: incoming SML diff (response to our
    // request_mnlistdiff). Forward to broadcaster via callback. The
    // broadcaster owns apply_diff + persistence + CBTX root verification
    // (steps 5-7).
    void handle_msg(std::unique_ptr<message_mnlistdiff> msg)
    {
        if (!msg) return;
        const auto& diff = msg->m_diff;
        LOG_INFO << "[DashP2P] mnlistdiff base="
                 << diff.baseBlockHash.GetHex().substr(0, 16)
                 << " block=" << diff.blockHash.GetHex().substr(0, 16)
                 << " mnList=" << diff.mnList.size()
                 << " deletedMNs=" << diff.deletedMNs.size()
                 << " quorum_tail=" << diff.quorum_tail.size() << "B";
        if (m_on_mnlistdiff) {
            m_on_mnlistdiff(m_target_addr.to_string(), diff);
        }
    }

    // SPV B2 (parity audit): BIP 130 — peer prefers `headers` over `inv`
    // for new-block announcements. Record the preference. No behavior
    // change today (we don't announce blocks unsolicited), but a future
    // block-relay path can consult m_peer_wants_headers to stay in sync.
    void handle_msg(std::unique_ptr<message_sendheaders>)
    {
        m_peer_wants_headers = true;
    }
    // BIP 152 sendcmpct (Phase S2): record the peer's announcement
    // preference and protocol version. announce=true would let peers
    // push cmpctblock unsolicited for tip-relay latency savings; we
    // don't honour that on our side yet (no cmpctblock push), but
    // peers that signal it will try pushing to us — the receive path
    // handles either.
    void handle_msg(std::unique_ptr<message_sendcmpct> msg)
    {
        if (!msg) return;
        m_peer_sendcmpct_announce = msg->m_announce;
        m_peer_sendcmpct_version  = msg->m_version;
        LOG_DEBUG_COIND << "[DashP2P] sendcmpct announce=" << (msg->m_announce ? 1 : 0)
                        << " version=" << msg->m_version
                        << " from " << m_target_addr.to_string();
    }

    // BIP 152 cmpctblock (Phase S2): peer is relaying a new tip via
    // header + short IDs + prefilled coinbase. Try to reassemble using
    // whatever transactions we can source locally (prefilled coinbase
    // always, mempool TBD in Phase M). If any index is still missing,
    // send `getblocktxn` for those indexes and stash the
    // PartiallyDownloadedBlock keyed by blockhash so the follow-up
    // `blocktxn` completes it. On reassembly failure, fall back to
    // plain getdata(MSG_BLOCK).
    void handle_msg(std::unique_ptr<message_cmpctblock> msg)
    {
        if (!msg) return;

        // Block hash: Dash uses X11 for both PoW and identity.
        auto packed_header = pack(msg->m_cmpct.header);
        auto blockhash = dash::crypto::hash_x11(packed_header.get_span());

        // Fire the inv-style notification so higher-level listeners
        // learn of the new tip immediately (same semantics as the
        // `inv(MSG_BLOCK)` → `new_block` path).
        m_coin->new_block.happened(blockhash);

        auto pdob = std::make_unique<vendor::PartiallyDownloadedBlock>(
            /*mempool_provider=*/nullptr,  // Phase M wires the real one
            /*max_block_tx_count=*/2000000 // Dash mainnet block_max_size
        );

        std::vector<std::pair<uint256, vendor::CTransactionRef>> extra_txn;
        auto status = pdob->InitData(msg->m_cmpct, extra_txn);
        if (status == vendor::READ_STATUS_INVALID
            || status == vendor::READ_STATUS_FAILED) {
            // Malformed or short-ID collision — fall back to full block.
            LOG_DEBUG_COIND << "[DashP2P] cmpctblock " << blockhash.GetHex().substr(0, 16)
                            << " InitData failed (status=" << status
                            << "), falling back to getdata(MSG_BLOCK)";
            auto getdata_full = message_getdata::make_raw(
                {inventory_type(inventory_type::block, blockhash)});
            m_peer->write(getdata_full);
            return;
        }

        // Count how many txs InitData couldn't fill — those are what we
        // need to fetch via getblocktxn.
        const size_t total = pdob->header.IsNull()
                                 ? 0
                                 : msg->m_cmpct.BlockTxCount();
        std::vector<uint16_t> missing_indexes;
        missing_indexes.reserve(total);
        for (size_t i = 0; i < total; ++i) {
            if (!pdob->IsTxAvailable(i))
                missing_indexes.push_back(static_cast<uint16_t>(i));
        }

        LOG_INFO << "[DashP2P] cmpctblock " << blockhash.GetHex().substr(0, 16)
                 << " total_txs=" << total
                 << " missing=" << missing_indexes.size();

        if (missing_indexes.empty()) {
            // Complete on arrival — reassemble and fire full_block.
            finalize_cmpctblock(blockhash, std::move(pdob), {});
            return;
        }

        // Send getblocktxn for the missing subset; stash the context.
        vendor::BlockTransactionsRequest req;
        req.blockhash = blockhash;
        req.indexes = std::move(missing_indexes);
        auto msg_getblocktxn = message_getblocktxn::make_raw(req);
        m_peer->write(msg_getblocktxn);
        m_pending_cmpctblocks[blockhash] = std::move(pdob);
    }

    // BIP 152 getblocktxn (Phase S2): peer is asking us for tx bodies
    // from a compact block we ostensibly announced. c2pool-dash neither
    // announces via cmpctblock nor caches block bodies locally, so
    // this should never happen. Log once at DEBUG level and drop —
    // peer will time out and fetch via inv/getdata from elsewhere.
    void handle_msg(std::unique_ptr<message_getblocktxn> msg)
    {
        if (!msg) return;
        LOG_DEBUG_COIND << "[DashP2P] unexpected getblocktxn (c2pool-dash does "
                        << "not serve block bodies) indexes="
                        << msg->m_req.indexes.size();
    }

    // BIP 152 blocktxn (Phase S2): peer's reply to our getblocktxn.
    // Look up the PartiallyDownloadedBlock we stashed at cmpctblock
    // time and complete it via FillBlock. On success emit full_block;
    // on failure fall back to plain getdata(MSG_BLOCK).
    void handle_msg(std::unique_ptr<message_blocktxn> msg)
    {
        if (!msg) return;
        auto it = m_pending_cmpctblocks.find(msg->m_txs.blockhash);
        if (it == m_pending_cmpctblocks.end()) {
            LOG_DEBUG_COIND << "[DashP2P] unmatched blocktxn for "
                            << msg->m_txs.blockhash.GetHex().substr(0, 16);
            return;
        }
        auto blockhash = msg->m_txs.blockhash;
        auto pdob = std::move(it->second);
        m_pending_cmpctblocks.erase(it);
        finalize_cmpctblock(blockhash, std::move(pdob), std::move(msg->m_txs.txn));
    }

private:
    void finalize_cmpctblock(const uint256& blockhash,
                             std::unique_ptr<vendor::PartiallyDownloadedBlock> pdob,
                             std::vector<vendor::CTransactionRef> vtx_missing)
    {
        BlockType block;
        auto status = pdob->FillBlock(block, vtx_missing);
        if (status != vendor::READ_STATUS_OK) {
            LOG_DEBUG_COIND << "[DashP2P] cmpctblock " << blockhash.GetHex().substr(0, 16)
                            << " FillBlock failed (status=" << status
                            << "), falling back to getdata(MSG_BLOCK)";
            auto getdata_full = message_getdata::make_raw(
                {inventory_type(inventory_type::block, blockhash)});
            m_peer->write(getdata_full);
            return;
        }

        // Reassembled. Plumb the block through the same entry points
        // handle_msg(message_block) uses so higher layers see the
        // reconstructed block identical to one that arrived as a full
        // `block` message.
        auto header = static_cast<BlockHeaderType>(block);
        try { m_peer->get_block(blockhash, block); } catch (...) {}
        try { m_peer->get_header(blockhash, header); } catch (...) {}
        LOG_INFO << "[DashP2P] cmpctblock reassembled " << blockhash.GetHex().substr(0, 16)
                 << " txs=" << block.m_txs.size();
        m_coin->full_block.happened(block);
    }

public:
    // BIP 155: peer wants to receive addrv2 from us (and is telling us
    // they understand BIP 155). Remember the preference so our reply to
    // any future getaddr from them uses addrv2.
    void handle_msg(std::unique_ptr<message_sendaddrv2>)
    {
        m_peer_supports_addrv2 = true;
    }
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
                // Plain MSG_BLOCK fetch — same model as LTC. BIP 152
                // negotiation + reassembly machinery is still present
                // for peers that push cmpctblock unsolicited
                // (announce=true path), but we don't actively upgrade
                // our own fetches: in practice the first peer that
                // announced the tip frequently drops the socket before
                // replying to getdata(MSG_CMPCT_BLOCK), and plain
                // MSG_BLOCK delivers reliably.
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

            // Small batch = new block announcement → plain getdata(MSG_BLOCK).
            // Same model as LTC's tip-fetch path. We keep the full BIP 152
            // reassembly plumbing in place for peers that choose to push
            // cmpctblock unsolicited via sendcmpct(announce=true), but the
            // explicit MSG_CMPCT_BLOCK getdata has proven too brittle on
            // Dash mainnet — the peer that delivers the headers
            // announcement often drops the connection before replying to
            // the compact request, starving new-tip delivery.
            if (vheaders.size() <= 3 && m_peer) {
                for (auto& hdr : vheaders) {
                    auto packed = pack(hdr);
                    auto bhash = dash::crypto::hash_x11(packed.get_span());
                    auto getdata = message_getdata::make_raw(
                        {inventory_type(inventory_type::block, bhash)});
                    m_peer->write(getdata);
                    LOG_INFO << "[DashP2P] Requesting full block "
                             << bhash.GetHex().substr(0, 16);
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

    // BIP 155 addrv2 receive path. Decodes networkID-tagged records back
    // into NetService endpoints for the peer-manager callback. IPv4 and
    // IPv6 are materialized; TORV3/I2P/CJDNS are logged but not dialed
    // (we don't speak those transports today); TORV2 is rejected per the
    // BIP 155 deprecation. Record count is capped at MAX_ADDRV2_RECORDS
    // (1000) per spec; per-record address length must match the networkID.
    void handle_msg(std::unique_ptr<message_addrv2> msg)
    {
        if (!msg) return;
        const size_t total = msg->m_addrs.size();
        if (total == 0) return;
        const size_t limit = std::min<size_t>(total, MAX_ADDRV2_RECORDS);
        if (total > MAX_ADDRV2_RECORDS) {
            LOG_WARNING << "[DashP2P] addrv2 record count " << total
                        << " exceeds BIP 155 cap " << MAX_ADDRV2_RECORDS
                        << ", truncating";
        }

        std::vector<NetService> endpoints;
        endpoints.reserve(limit);
        size_t ipv4 = 0, ipv6 = 0, torv3 = 0, i2p = 0, cjdns = 0, bad = 0;

        for (size_t i = 0; i < limit; ++i) {
            const auto& rec = msg->m_addrs[i];
            const size_t expected = bip155_address_size(rec.m_network_id);
            if (rec.m_network_id == static_cast<uint8_t>(BIP155Network::TORV2)) {
                ++bad;
                continue;
            }
            if (expected == 0 || rec.m_addr.size() != expected) {
                ++bad;
                continue;
            }

            switch (static_cast<BIP155Network>(rec.m_network_id)) {
                case BIP155Network::IPV4: {
                    const auto& a = rec.m_addr;
                    std::string ip =
                        std::to_string(a[0]) + "." + std::to_string(a[1]) + "." +
                        std::to_string(a[2]) + "." + std::to_string(a[3]);
                    endpoints.emplace_back(std::move(ip), rec.m_port);
                    ++ipv4;
                    break;
                }
                case BIP155Network::IPV6: {
                    const auto& a = rec.m_addr;
                    std::ostringstream oss;
                    for (int k = 0; k < 16; k += 2) {
                        if (k > 0) oss << ':';
                        oss << std::hex << std::setfill('0') << std::setw(2)
                            << static_cast<unsigned>(a[k]) << std::setw(2)
                            << static_cast<unsigned>(a[k + 1]);
                    }
                    endpoints.emplace_back(oss.str(), rec.m_port);
                    ++ipv6;
                    break;
                }
                case BIP155Network::TORV3: ++torv3; break;
                case BIP155Network::I2P:   ++i2p;   break;
                case BIP155Network::CJDNS: ++cjdns; break;
                default: ++bad; break;
            }
        }

        LOG_INFO << "[DashP2P] addrv2: " << total << " records"
                 << " (ipv4=" << ipv4
                 << " ipv6=" << ipv6
                 << " torv3=" << torv3
                 << " i2p=" << i2p
                 << " cjdns=" << cjdns
                 << " rejected=" << bad << ")";

        if (m_addr_callback && !endpoints.empty())
            m_addr_callback(endpoints);
    }
};

} // namespace p2p
} // namespace coin
} // namespace dash
