// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110_inbound_listener_kat — the coin-p2p INBOUND accept path (:8333) gate.
//
// WHY THIS KAT EXISTS
// -------------------
// The branded coin-p2p subver /c2pool:0.1/bip110/frstrtr/ was LIVE but the node
// was OUTBOUND-ONLY, so only the ~6 fork peers we dial ever saw it. A separate
// accept-only InboundListener on 0.0.0.0:8333 makes the brand + our node
// REACHABLE by bitnodes/crawlers and any fork node that dials us. This KAT drives
// the REAL InboundListener over a REAL loopback socket (reusing core::Server's
// accept path + core::Socket's framing on BOTH sides) and proves the three
// acceptance properties:
//
//   [A] LOOPBACK ACCEPT (crash-free, full accepting-side handshake). A fork
//       dialer (services incl NODE_BLAKE2B) connects to 127.0.0.1:<port>, sends
//       its version FIRST. The listener (accepting side) replies OUR branded
//       version (subver == BIP110_COIN_SUBVER, services has NODE_BLAKE2B bit 28)
//       + verack. The dialer sends verack + getaddr and receives an addr reply
//       from the addrman supplier. The listener reports the slot handshaked.
//   [B] NON-FORK DROP. A canonical dialer (services WITHOUT bit 28) sends its
//       version; the listener drops it BEFORE verack (same NODE_BLAKE2B gate as
//       the outbound arm). The dialer never receives a verack and its socket is
//       closed; the listener retains 0 handshaked slots.
//   [C] CAP + drop-on-overflow. MAX_INBOUND+1 fork dialers connect concurrently;
//       the listener accepts exactly MAX_INBOUND and drops the overflow at
//       accept time (socket closed pre-handshake).
//
// REUSE (no hand-rolled socket stack): the listener IS core::Factory<core::Server>
// (accept + eb60bf4c strong-ref UAF guard), armed by set_lifetime BEFORE listen();
// the dialer is a tiny core::Factory<core::Client>. Both frame via core::Socket +
// bip110::coin::p2p messages. Zero mocks of the wire.
//
// TRUE ACCEPTANCE GATE: this KAT is necessary, NOT sufficient. The real gate is a
// live 0.0.0.0:8333 deploy on contabo (ufw already open) where a real fork node /
// crawler dialing in records /c2pool:0.1/bip110/frstrtr/ + NODE_BLAKE2B, with the
// systemd restart counter holding at 0 and ZERO regression to the 6 outbound fork
// peers (the primary NodeP2P is untouched).
// ---------------------------------------------------------------------------

#include <cstdio>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <core/inetwork.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>
#include <core/factory.hpp>
#include <core/random.hpp>
#include <core/core_util.hpp>

#include "../inbound_listener.hpp"   // bip110::coin::p2p::InboundListener (REAL)
#include "../p2p_connection.hpp"     // bip110::coin::p2p::Connection
#include "../p2p_messages.hpp"

namespace bcp = bip110::coin::p2p;

namespace {

int g_fail = 0;
void expect(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

// Duck-typed config mirroring main_bip110's MiniConfig — the minimal shape both
// InboundListener<Cfg> and the dialer read (get_prefix() -> coin()->m_p2p.prefix).
struct KatCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
};
struct KatConfig {
    KatCoinCfg m_coin;
    bool m_testnet{false};
    KatCoinCfg* coin() { return &m_coin; }
};

using Listener = bcp::InboundListener<KatConfig>;

// Tiny outbound dialer: connects to the listener and drives the fork/non-fork
// handshake, collecting the listener's replies via core::Socket framing. It is
// the REAL client-factory + REAL messages — not a wire mock.
struct KatDialer : public core::ICommunicator,
                   public core::INetwork,
                   public core::Factory<core::Client>
{
    boost::asio::io_context* m_ctx;
    KatConfig*               m_cfg;
    uint64_t                 m_send_services;     // advertised services in our version
    bool                     m_reply_handshake;   // send verack + getaddr on receiving version

    std::unique_ptr<bcp::Connection> m_peer;
    bcp::Handler                     m_handler;

    // observed
    bool        got_version{false};
    bool        got_verack{false};
    bool        got_addr{false};
    bool        closed{false};
    std::string peer_subver;
    uint64_t    peer_services{0};
    size_t      addr_count{0};

    KatDialer(boost::asio::io_context* ctx, KatConfig* cfg, uint64_t services, bool reply)
        : core::Factory<core::Client>(ctx, this, "kat-dialer")
        , m_ctx(ctx), m_cfg(cfg), m_send_services(services), m_reply_handshake(reply)
    {}

    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_peer = std::make_unique<bcp::Connection>(m_ctx, socket);
        // OUTBOUND choreography: we (the dialer) send our version FIRST.
        auto v = bcp::message_version::make_raw(
            70016, m_send_services, core::timestamp(),
            addr_t{m_send_services, socket->get_addr()},
            addr_t{m_send_services, NetService{"0.0.0.0", 8333}},
            core::random::random_nonce(), "/kat-fork-dialer:1.0/", 100);
        m_peer->write(v);
    }

    void disconnect() override { closed = true; m_peer.reset(); }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& /*svc*/) override
    {
        bcp::Handler::result_t r;
        try { r = m_handler.parse(rmsg); } catch (...) { return; }
        std::visit([&](auto& m) { record(std::move(m)); }, r);
    }

    template <typename MsgT>
    void record(std::unique_ptr<MsgT> /*m*/) { /* uninteresting reply — ignore */ }

    void record(std::unique_ptr<bcp::message_version> m)
    {
        got_version   = true;
        peer_subver   = m->m_subversion;
        peer_services = m->m_services;
        if (m_reply_handshake && m_peer) {
            auto va = bcp::message_verack::make_raw();
            m_peer->write(va);
            auto ga = bcp::message_getaddr::make_raw();
            m_peer->write(ga);
        }
    }
    void record(std::unique_ptr<bcp::message_verack> /*m*/) { got_verack = true; }
    void record(std::unique_ptr<bcp::message_addr> m) { got_addr = true; addr_count = m->m_addrs.size(); }

    void error(const message_error_type& /*err*/, const NetService& /*svc*/,
               const std::source_location = std::source_location::current()) override
    { closed = true; m_peer.reset(); }
    void error(const boost::system::error_code& /*ec*/, const NetService& /*svc*/,
               const std::source_location = std::source_location::current()) override
    { closed = true; m_peer.reset(); }

    const std::vector<std::byte>& get_prefix() const override
    { return m_cfg->coin()->m_p2p.prefix; }
};

// Bitcoin mainnet magic — both sides must agree for core::Socket framing.
std::vector<std::byte> kat_prefix()
{
    return { std::byte{0xf9}, std::byte{0xbe}, std::byte{0xb4}, std::byte{0xd9} };
}

// Drive the shared io_context for a bounded wall-clock budget (loopback handshake
// is sub-ms; the 10s handshake timer never fires within this window).
void pump(boost::asio::io_context& ioc, int ms)
{
    ioc.restart();
    ioc.run_for(std::chrono::milliseconds(ms));
}

constexpr uint64_t NODE_NETWORK = 1;
constexpr uint64_t NODE_WITNESS = (uint64_t{1} << 3);
constexpr uint64_t FORK_SERVICES     = NODE_NETWORK | NODE_WITNESS | bcp::COIN_NODE_BLAKE2B;
constexpr uint64_t NONFORK_SERVICES  = NODE_NETWORK | NODE_WITNESS;   // no bit 28

std::shared_ptr<Listener> make_listener(boost::asio::io_context& ioc, KatConfig& cfg,
                                        uint16_t& out_port)
{
    auto L = std::make_shared<Listener>(&ioc, &cfg);
    L->set_lifetime(L);                     // ARM the accept-path UAF guard BEFORE listen()
    if (!L->lifetime_armed()) { std::printf("  [FAIL] listener lifetime failed to arm\n"); ++g_fail; }
    // Deterministic addr supplier: two routable fork endpoints for getaddr replies.
    L->set_addr_supplier([]() {
        return std::vector<NetService>{ NetService{"8.8.8.8", 8333}, NetService{"1.1.1.1", 8333} };
    });
    L->set_height_supplier([]() { return uint32_t{961640}; });
    L->core::Server::listen(uint16_t{0});   // ephemeral loopback-reachable port
    out_port = L->core::Server::listen_port();
    return L;
}

std::shared_ptr<KatDialer> dial(boost::asio::io_context& ioc, KatConfig& cfg,
                                uint16_t port, uint64_t services, bool reply)
{
    auto d = std::make_shared<KatDialer>(&ioc, &cfg, services, reply);
    d->set_lifetime(d);
    d->core::Factory<core::Client>::connect(NetService{"127.0.0.1", port});
    return d;
}

} // namespace

int main()
{
    std::printf("bip110_inbound_listener_kat: REAL coin-p2p inbound accept path (:8333)\n");

    // ── (A) LOOPBACK ACCEPT — full accepting-side handshake, crash-free ────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg; cfg.m_coin.m_p2p.prefix = kat_prefix();
        uint16_t port = 0;
        auto L = make_listener(ioc, cfg, port);
        expect("[A] listener bound an ephemeral port", port != 0);

        auto d = dial(ioc, cfg, port, FORK_SERVICES, /*reply=*/true);
        pump(ioc, 800);

        expect("[A] dialer received the listener's version reply", d->got_version);
        expect("[A] version reply carries the BRAND subver /c2pool:0.1/bip110/frstrtr/",
               d->peer_subver == std::string(bcp::BIP110_COIN_SUBVER));
        expect("[A] version reply advertises NODE_BLAKE2B (bit 28)",
               (d->peer_services & bcp::COIN_NODE_BLAKE2B) != 0);
        expect("[A] version reply advertises NODE_NETWORK|NODE_WITNESS",
               (d->peer_services & NODE_NETWORK) && (d->peer_services & NODE_WITNESS));
        expect("[A] dialer received verack (accepting side completed the handshake)",
               d->got_verack);
        expect("[A] listener reports exactly 1 handshaked inbound slot",
               L->handshaked_count() == 1 && L->live_count() == 1);
        expect("[A] getaddr served an addr reply from the addrman supplier",
               d->got_addr && d->addr_count == 2);
        expect("[A] dialer stayed connected (no crash / no drop)", !d->closed);
    }

    // ── (B) NON-FORK DROP — canonical peer refused at the NODE_BLAKE2B gate ────
    {
        boost::asio::io_context ioc;
        KatConfig cfg; cfg.m_coin.m_p2p.prefix = kat_prefix();
        uint16_t port = 0;
        auto L = make_listener(ioc, cfg, port);

        auto d = dial(ioc, cfg, port, NONFORK_SERVICES, /*reply=*/true);
        pump(ioc, 800);

        expect("[B] non-fork dialer NEVER received a verack (dropped pre-handshake)",
               !d->got_verack);
        expect("[B] listener retains 0 handshaked slots for the non-fork peer",
               L->handshaked_count() == 0);
        expect("[B] listener has 0 live slots after dropping the non-fork peer "
               "(prune reaps the dead slot on the next accept; here the drop closed it)",
               L->live_count() == 0);
    }

    // ── (C) CAP + drop-on-overflow ─────────────────────────────────────────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg; cfg.m_coin.m_p2p.prefix = kat_prefix();
        uint16_t port = 0;
        auto L = make_listener(ioc, cfg, port);

        const size_t N = Listener::MAX_INBOUND + 1;   // one over the cap
        std::vector<std::shared_ptr<KatDialer>> dialers;
        for (size_t i = 0; i < N; ++i)
            dialers.push_back(dial(ioc, cfg, port, FORK_SERVICES, /*reply=*/true));
        pump(ioc, 1200);

        expect("[C] listener accepted EXACTLY MAX_INBOUND live slots (cap enforced)",
               L->live_count() == Listener::MAX_INBOUND);
        expect("[C] listener handshaked EXACTLY MAX_INBOUND slots",
               L->handshaked_count() == Listener::MAX_INBOUND);

        size_t handshaked = 0, dropped = 0;
        for (auto& d : dialers) {
            if (d->got_verack) ++handshaked;
            else               ++dropped;
        }
        expect("[C] exactly MAX_INBOUND dialers completed the handshake",
               handshaked == Listener::MAX_INBOUND);
        expect("[C] the overflow dialer was dropped at accept (no verack)",
               dropped == 1);
    }

    if (g_fail == 0) {
        std::printf(
            "RESULT: PASS — the REAL InboundListener accepts fork dialers on loopback "
            "(branded version + NODE_BLAKE2B + verack + getaddr->addr), drops non-fork "
            "peers at the NODE_BLAKE2B gate, and enforces the MAX_INBOUND cap with "
            "drop-on-overflow. KAT is necessary, NOT sufficient — a live 0.0.0.0:8333 "
            "deploy where a real crawler/fork node records the brand, restart counter 0, "
            "and ZERO regression to the outbound fork peers is the acceptance gate.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
