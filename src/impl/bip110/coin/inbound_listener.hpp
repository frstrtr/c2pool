// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// InboundListener — the BIP-110 coin-p2p INBOUND accept path (:8333).
//
// WHY A SEPARATE LISTENER (not the primary NodeP2P):
// The primary coin-p2p NodeP2P (p2p_node.hpp) is STRUCTURALLY SINGLE-CONNECTION:
// connected() does `m_peer = make_unique<Connection>(...)`, unconditionally sends
// OUR version first, and arms an OUTBOUND handshake-timeout against m_target_addr
// (initiator choreography). Routing an inbound accept through it would (a) CLOBBER
// the live outbound fork peer on the first inbound dial (header-sync/broadcast
// outage for all fork peers), and (b) use outbound-only choreography. So the
// primary NodeP2P stays Factory<Client>-only and BYTE-IDENTICAL. This is a NEW,
// small accept-only path that REUSES the existing UAF-safe infrastructure:
//
//   * core::Server accept + the eb60bf4c strong-ref-by-value UAF guard
//     (factory.hpp:83-117), armed by Factory::set_lifetime fan-out (:396-399).
//   * core::Socket framing + the m_node weak_ptr liveness guard (socket.cpp) —
//     the accepted socket is stamped connection_type::incoming and routes
//     handle()/error()/get_prefix() back to THIS listener (make_socket's
//     communicator == the node passed to the Server base). The listener DEMUXES
//     by remote addr to the owning per-connection session slot.
//   * The broadcaster.hpp per-slot session pattern: a std::map of make_shared
//     slots, prune_dead(), live_count().
//   * bip110::coin::p2p::Connection (direction-agnostic) for per-slot writes.
//   * core::Timer for the per-slot handshake timeout.
//   * The SAME NODE_BLAKE2B fork gate as the outbound version handler
//     (p2p_node.hpp:698-704) — a non-fork (canonical SHA256d) dialer is dropped.
//
// ACCEPTING-SIDE choreography (the inverse of NodeP2P::connected()):
//   accept -> arm handshake Timer -> WAIT the peer's version FIRST -> gate
//   NODE_BLAKE2B (missing bit -> drop) -> reply OUR branded version
//   (BIP110_COIN_SUBVER + NODE_NETWORK|NODE_WITNESS|NODE_BLAKE2B, proto 70016)
//   + verack -> WAIT their verack -> handshake complete -> serve ping->pong and
//   getaddr->addr (from the addrman supplier); everything else is ignored.
//
// SCOPE: network-identity/reachability ONLY. version/verack/ping/getaddr/addr are
// FREE p2p (no consensus/wire/params change). This makes /c2pool:0.1/bip110/
// frstrtr/ + NODE_BLAKE2B reachable by bitnodes/crawlers and any fork node that
// dials us. NO block/tx/headers serving here.
// ─────────────────────────────────────────────────────────────────────────────

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "p2p_node.hpp"          // COIN_NODE_BLAKE2B, BIP110_COIN_SUBVER (inline constexpr)

#include <map>
#include <string>
#include <memory>
#include <vector>
#include <functional>

#include <boost/asio.hpp>

#include <core/log.hpp>
#include <core/timer.hpp>
#include <core/random.hpp>
#include <core/core_util.hpp>
#include <core/factory.hpp>
#include <core/socket.hpp>
#include <core/inetwork.hpp>
#include <core/netaddress.hpp>

namespace io = boost::asio;

namespace bip110
{
namespace coin
{
namespace p2p
{

// One accepted inbound socket: owns its Connection (for writes) + a handshake
// Timer + the accepting-side handshake state. The LISTENER owns the protocol
// logic and demuxes parsed messages to this slot; the slot is a passive holder
// (mirrors the broadcaster's per-slot pattern). Liveness = !m_dead, so a dropped
// or timed-out slot is reaped by the listener's prune_dead() on the next accept.
class InboundSession : public std::enable_shared_from_this<InboundSession>
{
public:
    InboundSession(io::io_context* context, std::shared_ptr<core::Socket> socket, std::string remote_key)
        : m_context(context)
        , m_peer(std::make_unique<Connection>(context, socket))
        , m_remote_key(std::move(remote_key))
    {
    }

    // Arm the handshake timeout. NO version is sent here — the accepting side
    // WAITS for the peer's version first (inverse of NodeP2P::connected()).
    void arm_handshake_timeout(time_t seconds, std::function<void()> on_timeout)
    {
        m_handshake_timer = std::make_unique<core::Timer>(m_context, /*repeat=*/false);
        m_handshake_timer->start(seconds, [this, cb = std::move(on_timeout)]() {
            if (m_dead || m_handshake_complete)
                return;
            cb();
        });
    }

    // Cleanly tear the slot down. Marks dead + stops the timer + resets the
    // Connection (which cancels/closes the socket). The canceled read completes
    // with m_status==false, so the socket's read loop returns WITHOUT calling
    // error() — the dead slot is reaped by the listener's prune_dead(). No erase
    // from inside a timer callback (no reentrant map mutation).
    void drop(const char* reason)
    {
        if (m_dead)
            return;
        m_dead = true;
        LOG_INFO << "[BIP110-Inbound] dropping " << m_remote_key << ": " << reason;
        if (m_handshake_timer)
            m_handshake_timer->stop();
        m_peer.reset();
    }

    void write(std::unique_ptr<RawMessage>& rmsg)
    {
        if (m_peer)
            m_peer->write(rmsg);
    }

    void stop_handshake_timer()
    {
        if (m_handshake_timer)
            m_handshake_timer->stop();
    }

    bool dead()               const { return m_dead; }
    bool handshake_complete() const { return m_handshake_complete; }
    bool got_version()        const { return m_got_version; }
    bool getaddr_served()     const { return m_getaddr_served; }
    void mark_getaddr_served()      { m_getaddr_served = true; }
    const std::string& remote_key() const { return m_remote_key; }

    // Peer metadata captured from the version handshake (display/dashboard).
    uint64_t    peer_services()     const { return m_peer_services; }
    uint32_t    peer_version()      const { return m_peer_version; }
    const std::string& peer_subver() const { return m_peer_subver; }
    uint32_t    peer_start_height() const { return m_peer_start_height; }

    // ── listener-driven state transitions ─────────────────────────────────────
    void set_version(uint64_t services, uint32_t version, std::string subver, uint32_t start_height)
    {
        m_got_version       = true;
        m_peer_services     = services;
        m_peer_version      = version;
        m_peer_subver       = std::move(subver);
        m_peer_start_height = start_height;
    }
    void set_handshake_complete() { m_handshake_complete = true; }

private:
    io::io_context*               m_context;
    std::unique_ptr<Connection>   m_peer;             // reuse p2p_connection.hpp
    std::unique_ptr<core::Timer>  m_handshake_timer;  // reuse core/timer.hpp
    std::string                   m_remote_key;

    bool     m_dead{false};
    bool     m_got_version{false};
    bool     m_handshake_complete{false};
    bool     m_getaddr_served{false};   // Knots m_getaddr_recvd: answer getaddr once/conn

    uint64_t    m_peer_services{0};
    uint32_t    m_peer_version{0};
    std::string m_peer_subver;
    uint32_t    m_peer_start_height{0};
};

// The listener: core::Factory<core::Server> ONLY — it NEVER dials. It is the
// ICommunicator/INetwork the accepted sockets route to; it owns the per-remote
// session slots and runs the accepting-side handshake + minimal serve set.
template <typename ConfigType>
class InboundListener : public core::ICommunicator,
                        public core::INetwork,
                        public core::Factory<core::Server>
{
    using config_t = ConfigType;

public:
    // Address supplier for getaddr replies (fork-filtered tried peers). Returns
    // routable NODE_BLAKE2B peer endpoints; the listener stamps services+time.
    using AddrSupplier   = std::function<std::vector<NetService>()>;
    // Advertise-height supplier for our version reply (crawlers record UA+
    // services; height is cosmetic — header-chain tip if cheap, else 0).
    using HeightSupplier = std::function<uint32_t()>;

    static constexpr size_t MAX_INBOUND         = 8;   // cap; drop-on-overflow
    static constexpr time_t HANDSHAKE_TIMEOUT_SEC = 10;
    static constexpr size_t MAX_ADDR_REPLY      = 1000; // Bitcoin addr cap

    // Services WE advertise: truthful per Knots protocol.h SeedsServiceFlags
    // 0x10000009 = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B (bit 28). Same set
    // the outbound NodeP2P::connected() advertises (p2p_node.hpp:237-240).
    static constexpr uint64_t NODE_NETWORK  = 1;
    static constexpr uint64_t NODE_WITNESS  = (uint64_t{1} << 3);
    static constexpr uint64_t OUR_SERVICES  = NODE_NETWORK | NODE_WITNESS | COIN_NODE_BLAKE2B;
    static constexpr uint32_t PROTOCOL_VERSION = 70016;

    InboundListener(io::io_context* context, config_t* config,
                    const std::string& label = "BIP110-Inbound")
        : core::Factory<core::Server>(context, this, label)
        , m_context(context), m_config(config), m_label(label)
    {
    }

    // addr-ingest sink: NODE_BLAKE2B-filtered survivors from inbound `addr`
    // gossip, banked into the shared addrman (same signature as NodeP2P's
    // AddrCallback). Without this an inbound peer's gossip was dropped on the
    // floor (dispatch fallback), so a dialer could never grow our address DB.
    using AddrCallback =
        std::function<void(const std::vector<NetService>&, const NetService& /*source*/)>;

    void set_addr_supplier(AddrSupplier fn)     { m_addr_supplier = std::move(fn); }
    void set_height_supplier(HeightSupplier fn) { m_height_supplier = std::move(fn); }
    void set_addr_callback(AddrCallback fn)     { m_addr_callback = std::move(fn); }
    // Self-address advertisement seams (Knots GetLocalAddress / self-connect
    // nonce), shared with the outbound + fan-out arms.
    void set_local_addr_table(std::shared_ptr<LocalAddrTable> t) { m_local_addr = std::move(t); }
    void set_self_nonce_registry(std::shared_ptr<SelfNonceRegistry> r) { m_self_nonce = std::move(r); }

    // Knots RelayAddress destination: push a fresh gossip batch to up to `fanout`
    // handshaked inbound sessions other than `exclude`. Called by the outbound
    // arm's addr-relay sink (main) so a learned peer's reachability spreads to our
    // inbound peers too. Public so the outbound seam can reach it.
    void relay_addr(const std::vector<btc_addr_record_t>& recs,
                    const std::string& exclude_key, size_t fanout = 2)
    {
        if (recs.empty()) return;
        size_t sent = 0;
        for (auto& [key, s] : m_slots) {
            if (sent >= fanout) break;
            if (!s || s->dead() || !s->handshake_complete()) continue;
            if (key == exclude_key) continue;
            auto msg = message_addr::make_raw(recs);
            s->write(msg);
            ++sent;
        }
    }

    // ── INetwork ──────────────────────────────────────────────────────────────
    // Called by core::Server::accept for each accepted (incoming) socket, with
    // the node/lifetime already pinned by the eb60bf4c strong-ref guard. The
    // socket is already reading (Server::accept did socket->init()); on the
    // single io thread this connected() completes before any handle() arrives.
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        prune_dead();

        const std::string key = slot_key(socket->get_addr());

        if (live_count() >= MAX_INBOUND) {
            LOG_INFO << "[" << m_label << "] inbound cap reached (" << MAX_INBOUND
                     << ") — dropping " << key;
            socket->close();
            return;
        }

        // A re-accept from the same remote key: drop the stale slot first.
        if (auto it = m_slots.find(key); it != m_slots.end())
            m_slots.erase(it);

        auto session = std::make_shared<InboundSession>(m_context, socket, key);
        m_slots[key] = session;   // slot owns the session (broadcaster pattern)

        LOG_INFO << "[" << m_label << "] inbound accept " << key
                 << " (live=" << live_count() << "/" << MAX_INBOUND << ")";

        // Accepting side WAITS for the peer's version — arm a handshake timeout.
        std::weak_ptr<InboundSession> weak = session;
        session->arm_handshake_timeout(HANDSHAKE_TIMEOUT_SEC, [weak]() {
            if (auto s = weak.lock())
                s->drop("handshake timeout");
        });
    }

    void disconnect() override { /* accept-only node: nothing to dial/tear down */ }

    // ── ICommunicator ─────────────────────────────────────────────────────────
    // The accepted socket routes every parsed frame here, keyed by the remote
    // NetService (service). Demux to the owning slot, parse, dispatch.
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        auto it = m_slots.find(slot_key(service));
        if (it == m_slots.end() || !it->second || it->second->dead())
            return;   // unknown / already-dropped remote

        auto session = it->second;

        p2p::Handler::result_t result;
        try {
            result = m_handler.parse(rmsg);
        } catch (const std::exception& e) {
            LOG_DEBUG_OTHER << "[" << m_label << "] parse(" << rmsg->m_command
                            << ") from " << session->remote_key() << ": " << e.what();
            return;   // unknown/garbled command — ignore, keep the connection
        }

        std::visit([&](auto& msg) { dispatch(session, std::move(msg)); }, result);
    }

    void error(const message_error_type& err, const NetService& service,
               const std::source_location /*where*/ = std::source_location::current()) override
    {
        const std::string key = slot_key(service);
        auto it = m_slots.find(key);
        if (it != m_slots.end()) {
            LOG_INFO << "[" << m_label << "] inbound " << key << " closed: " << err;
            if (it->second)
                it->second->drop("peer closed");
            m_slots.erase(it);   // peer-initiated close: socket read loop is done
        }
    }

    void error(const boost::system::error_code& ec, const NetService& service,
               const std::source_location where = std::source_location::current()) override
    {
        error(std::string(ec.message()), service, where);
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_p2p.prefix;
    }

    // ── observers (dashboard / KAT) ────────────────────────────────────────────
    size_t slot_count() const { return m_slots.size(); }

    size_t live_count() const
    {
        size_t n = 0;
        for (const auto& [k, s] : m_slots)
            if (s && !s->dead()) ++n;
        return n;
    }

    size_t handshaked_count() const
    {
        size_t n = 0;
        for (const auto& [k, s] : m_slots)
            if (s && !s->dead() && s->handshake_complete()) ++n;
        return n;
    }

    // Read seam for per-peer dashboard rows (key + const session&). Read-only.
    void for_each_live_slot(
        const std::function<void(const std::string&, const InboundSession&)>& fn) const
    {
        for (const auto& [k, s] : m_slots)
            if (s && !s->dead()) fn(k, *s);
    }

    // Reap dead slots (dropped / timed-out). Returns count removed.
    size_t prune_dead()
    {
        size_t pruned = 0;
        for (auto it = m_slots.begin(); it != m_slots.end(); ) {
            if (!it->second || it->second->dead()) {
                it = m_slots.erase(it);
                ++pruned;
            } else {
                ++it;
            }
        }
        return pruned;
    }

private:
    static std::string slot_key(const NetService& addr)
    {
        return addr.address() + ":" + std::to_string(addr.port());
    }

    uint32_t advertise_height() const
    {
        return m_height_supplier ? m_height_supplier() : 0u;
    }

    // ── accepting-side dispatch ────────────────────────────────────────────────
    // Generic fallback: everything not explicitly served is ignored (no block/tx/
    // headers/inv serving on this identity-only path). Keeps a crawler-friendly
    // connection alive without touching consensus/serve paths.
    template <typename MsgT>
    void dispatch(std::shared_ptr<InboundSession>& /*session*/, std::unique_ptr<MsgT> /*msg*/)
    {
        // ignored (version/verack/ping/getaddr are handled by the overloads below)
    }

    // Peer's version FIRST (accepting side). Gate NODE_BLAKE2B, then reply our
    // branded version + verack. Clone of the outbound gate (p2p_node.hpp:698-704)
    // but with the reply choreography INVERTED (we send AFTER receiving).
    void dispatch(std::shared_ptr<InboundSession>& session, std::unique_ptr<message_version> msg)
    {
        // Self-connect guard (Knots CConnman): a dialer whose version nonce equals
        // one WE sent is us dialing our own listener. Drop before replying so we
        // never waste an inbound slot on ourselves (reachable once self-advertise
        // gossips our own routable addr back into the dial planner).
        if (m_self_nonce && m_self_nonce->is_self(msg->m_nonce)) {
            LOG_INFO << "[" << m_label << "] REJECT inbound " << session->remote_key()
                     << " — connected to self (version nonce match)";
            session->drop("connected to self");
            return;
        }

        session->set_version(msg->m_services, msg->m_version, msg->m_subversion, msg->m_start_height);

        LOG_INFO << "[" << m_label << "] inbound version from " << session->remote_key()
                 << " services=0x" << std::hex << msg->m_services << std::dec
                 << " subver=" << msg->m_subversion
                 << " start_height=" << msg->m_start_height;

        // Knots SeenLocal(): the dialer's version.addr_to is the address it dialed
        // us AT — i.e. OUR reachable IP as the network sees it. Strongest local-
        // address signal there is (no NAT ambiguity). Port discarded (best_local()
        // substitutes our listen port).
        if (m_local_addr)
            m_local_addr->seen_local(msg->m_addr_to.m_endpoint.address());

        // BIP-110 fork-peer gate — same rule as the outbound version handler: a
        // canonical SHA256d node (no NODE_BLAKE2B) does not follow the BLAKE2b
        // fork, so drop it before verack.
        if (!(msg->m_services & COIN_NODE_BLAKE2B)) {
            LOG_INFO << "[" << m_label << "] REJECT inbound " << session->remote_key()
                     << " — no NODE_BLAKE2B (services=0x" << std::hex << msg->m_services
                     << std::dec << " subver=" << msg->m_subversion << "); not a fork peer";
            session->drop("peer lacks NODE_BLAKE2B");
            return;
        }

        // addr_from = our reachable IP:listen-port when known (Knots
        // GetLocalAddress); else unspecified (Knots sends empty CService and
        // receivers ignore addr_from — the load-bearing advertise is the self-addr
        // push at handshake-complete below). Previously a hardcoded 0.0.0.0:8333.
        NetService from_ep{"0.0.0.0", 0};
        if (m_local_addr) {
            if (auto best = m_local_addr->best_local())
                from_ep = *best;
        }

        // Self-connect guard: record the nonce we send so our OWN dialer detects
        // the loopback at its version handler.
        uint64_t nonce = core::random::random_nonce();
        if (m_self_nonce) m_self_nonce->record(nonce);

        // Reply OUR branded version (accepting side sends AFTER the peer's).
        NetService peer_addr{session->remote_key()};
        auto version_reply = message_version::make_raw(
            PROTOCOL_VERSION,
            OUR_SERVICES,
            core::timestamp(),
            addr_t{OUR_SERVICES, peer_addr},                       // addr_to = the dialer
            addr_t{OUR_SERVICES, from_ep},                         // addr_from (our reachable addr)
            nonce,
            BIP110_COIN_SUBVER,                                    // /c2pool:0.1/bip110/frstrtr/
            advertise_height()
        );
        session->write(version_reply);

        auto verack = message_verack::make_raw();
        session->write(verack);
    }

    void dispatch(std::shared_ptr<InboundSession>& session, std::unique_ptr<message_verack> /*msg*/)
    {
        if (!session->got_version()) {
            // verack before version is a protocol violation — drop.
            session->drop("verack before version");
            return;
        }
        session->set_handshake_complete();
        session->stop_handshake_timer();
        LOG_INFO << "[" << m_label << "] inbound handshake complete " << session->remote_key()
                 << " subver=" << session->peer_subver();

        // Knots MaybeSendAddr self-announce: push our reachable IP:listen-port +
        // NODE_BLAKE2B so this dialer banks + gossips us onward. This is the
        // reachability keystone on the accept path (a crawler/fork node that
        // dialed us now RELAYS us into the fork addrman).
        maybe_send_self_addr(session);
    }

    void dispatch(std::shared_ptr<InboundSession>& session, std::unique_ptr<message_ping> msg)
    {
        auto pong = message_pong::make_raw(msg->m_nonce);
        session->write(pong);
    }

    void dispatch(std::shared_ptr<InboundSession>& /*session*/, std::unique_ptr<message_pong> /*msg*/)
    {
        // nothing to do
    }

    void dispatch(std::shared_ptr<InboundSession>& session, std::unique_ptr<message_getaddr> /*msg*/)
    {
        // Knots m_getaddr_recvd: answer getaddr AT MOST ONCE per connection; a
        // repeat is a fingerprinting probe and is ignored.
        if (session->getaddr_served()) {
            LOG_DEBUG_OTHER << "[" << m_label << "] ignoring repeat getaddr from "
                            << session->remote_key();
            return;
        }
        session->mark_getaddr_served();

        std::vector<btc_addr_record_t> records;
        const auto now = static_cast<uint32_t>(core::timestamp());

        // Our OWN reachable address FIRST (Knots includes the local addr in the
        // getaddr reply). Full service set — we truthfully offer all three bits.
        if (m_local_addr) {
            if (auto best = m_local_addr->best_local()) {
                btc_addr_record_t self;
                self.m_services  = OUR_SERVICES;   // NODE_NETWORK|NODE_WITNESS|NODE_BLAKE2B
                self.m_endpoint  = *best;
                self.m_timestamp = now;
                records.push_back(self);
            }
        }

        // Then the fork-filtered tried set from the supplier (Knots GetAddresses
        // 23%/1000; the supplier is drawn from addrman.get_addr, MAX_ADDR_REPLY
        // caps the reply). Services carry the full fork set (NODE_WITNESS was
        // previously dropped) — the addrman lacks a per-entry services field
        // (deferred G7 residual), so a uniform truthful fork-peer set is the
        // honest approximation (every banked non-seed entry passed the
        // NODE_BLAKE2B ingest gate).
        if (m_addr_supplier) {
            for (const auto& ns : m_addr_supplier()) {
                if (records.size() >= MAX_ADDR_REPLY)
                    break;
                btc_addr_record_t rec;
                rec.m_services  = OUR_SERVICES;
                rec.m_endpoint  = ns;
                rec.m_timestamp = now;
                records.push_back(rec);
            }
        }
        auto addr_msg = message_addr::make_raw(records);
        session->write(addr_msg);
        LOG_DEBUG_OTHER << "[" << m_label << "] served addr (" << records.size()
                        << ") to " << session->remote_key();
    }

    // Inbound `addr` gossip (Knots addr handler, fork-adjusted). Previously
    // DROPPED on the floor (generic fallback), so a dialer could never grow our
    // address DB. Fork-filter the records, bank the survivors into the addrman
    // (m_addr_callback), and RelayAddress a fresh subset to <=2 other inbound
    // sessions (2-hop gossip). Reuses the SSOT filter_fork_addr_records.
    void dispatch(std::shared_ptr<InboundSession>& session, std::unique_ptr<message_addr> msg)
    {
        if (msg->m_addrs.empty())
            return;
        const int64_t now = static_cast<int64_t>(core::timestamp());
        auto ok = filter_fork_addr_records(msg->m_addrs, now);
        if (!ok.empty() && m_addr_callback) {
            NetService source{session->remote_key()};
            m_addr_callback(ok, source);
        }
        // 2-hop relay: forward a fresh, small batch of NODE_BLAKE2B survivors to
        // other handshaked inbound sessions (Knots RelayAddress: nTime <= 10 min,
        // batch <= 10).
        std::vector<btc_addr_record_t> fresh;
        for (const auto& rec : msg->m_addrs) {
            if (!(rec.m_services & COIN_NODE_BLAKE2B)) continue;
            const int64_t ts = static_cast<int64_t>(rec.m_timestamp);
            if (ts > now + 10 * 60 || ts < now - 10 * 60) continue;
            fresh.push_back(rec);
            if (fresh.size() >= 10) break;
        }
        if (!fresh.empty())
            relay_addr(fresh, session->remote_key(), /*fanout=*/2);
        LOG_DEBUG_OTHER << "[" << m_label << "] inbound addr from " << session->remote_key()
                        << ": " << msg->m_addrs.size() << " recv, " << ok.size()
                        << " NODE_BLAKE2B banked, " << fresh.size() << " relayed";
    }

    // Knots MaybeSendAddr: push a 1-record `addr` with OUR reachable address to a
    // freshly-handshaked inbound dialer so it banks + gossips us onward. No-op
    // until we know a routable local addr (best_local()).
    void maybe_send_self_addr(std::shared_ptr<InboundSession>& session)
    {
        if (!m_local_addr) return;
        auto best = m_local_addr->best_local();
        if (!best) return;
        btc_addr_record_t rec;
        rec.m_services  = OUR_SERVICES;
        rec.m_endpoint  = *best;
        rec.m_timestamp = static_cast<uint32_t>(core::timestamp());
        auto msg = message_addr::make_raw(std::vector<btc_addr_record_t>{rec});
        session->write(msg);
        LOG_DEBUG_OTHER << "[" << m_label << "] self-addr announced " << best->to_string()
                        << " to " << session->remote_key();
    }

    io::io_context* m_context;
    config_t*       m_config;
    std::string     m_label;
    p2p::Handler    m_handler;

    AddrSupplier    m_addr_supplier;
    HeightSupplier  m_height_supplier;
    AddrCallback    m_addr_callback;                    // inbound addr -> addrman
    std::shared_ptr<LocalAddrTable>    m_local_addr;    // our reachable addr (self-advertise)
    std::shared_ptr<SelfNonceRegistry> m_self_nonce;    // self-connect guard

    std::map<std::string, std::shared_ptr<InboundSession>> m_slots;  // key = remote addr
};

} // namespace p2p
} // namespace coin
} // namespace bip110
