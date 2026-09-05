// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_peer_info_snapshot_kat — the 'c2pool Nodes' card / /peer_list feed KAT.
//
// LIVE BUG (contabo + federation node2, 2026-09-03): under M3 flag-ON the
// sharechain :9337 had 2 ESTABLISHED TCP connections actively syncing shares,
// yet the dashboard 'c2pool Nodes' card showed CONNECTIONS '-' / 'No peers
// connected' / badge 0 and Node Topology showed '0 peers'. Root cause: the web
// MI's /peer_list is fed by MiningInterface::m_peer_info_fn, and main_bip110.cpp
// wired only the COIN feed (set_coin_peer_info_fn) — set_peer_info_fn (the
// SHARECHAIN peer feed) was left UNWIRED, so rest_peer_list() fell through to an
// empty array. The producer already existed on the sharechain node:
// NodeImpl::get_peer_info_json() (node.hpp) returns the lock-free snapshot built
// by publish_peer_info_snapshot() at every peer add/remove + the think IO-phase.
// The fix wires set_peer_info_fn -> get_peer_info_json in main_bip110.cpp.
//
// THIS KAT proves the underlying producer is sound — i.e. that once wired, the
// feed returns the connected sharechain peers when peers exist and is empty ONLY
// when there are genuinely none (never faked, never stuck-empty):
//   (a) a fresh node -> get_peer_info_json() == []  (empty, honest)
//   (b) inject 1 OUTBOUND + 1 INBOUND peer, publish_peer_info_snapshot() ->
//       2 entries with correct address / version / incoming (direction) /
//       uptime>=0 / downtime==0 / web_port==0 — the exact frontend field shape
//       (dashboard.html loadPeers: p.address, p.version, p.incoming, p.uptime).
//   (c) erase one + republish -> back to the remaining peer only; erase all +
//       republish -> [] again (empty only when genuinely none).
//
// direction: publish derives incoming = (m_outbound_addrs.find(addr) == end),
// so a peer whose addr is in m_outbound_addrs is OUTBOUND (incoming=false) and
// one absent is INBOUND (incoming=true) — the real dial-side bookkeeping.
//
// Read-only / display-only: get_peer_info_json is a const mutex-guarded copy of a
// display snapshot; the KAT never touches the tracker, PPLNS, rewards, or the
// wire. Same heavy node.cpp + protocol_actual.cpp link closure as
// bip110_persistence_roundtrip_kat (it drives a REAL Node). NOT a standalone
// unregistered add_executable in isolation — registered in CMakeLists +
// build.yml's target list (the #769 unregistered-KAT fake-green trap).

#include "../node.hpp"              // Node / NodeImpl / Config
#include "../config_pool.hpp"
#include "../peer.hpp"             // bip110::pool::Peer (PeerData)

#include <core/uint256.hpp>
#include <core/socket.hpp>         // core::Socket / core::ICommunicator
#include <core/netaddress.hpp>     // NetService
#include <core/filesystem.hpp>
#include <pool/peer.hpp>           // pool::Peer<Data>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace {

int g_fail = 0;
void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

using boost::asio::ip::tcp;

// Minimal ICommunicator: core::Socket::init() needs get_prefix() on the read
// path; the peer-info snapshot only ever reads Socket::get_addr(), so this stub
// is never actually driven. Empty weak_ptr<INetwork> + was_managed=false =>
// acquire_node() short-circuits and no INetwork is needed.
struct StubCommunicator : public core::ICommunicator
{
    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override
    {
        static const std::vector<std::byte> p{
            std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
        return p;
    }
};

// A real loopback TCP pair. The ACCEPTED (server) socket's remote endpoint is the
// client's distinct ephemeral 127.0.0.1:<port>, so two pairs give two distinct
// peer addresses — exactly what m_outbound_addrs membership keys on. The
// io_context is never run: init() posts an async_read that never fires (harmless),
// and get_addr() only needs the endpoint init() already captured.
struct LoopbackPair
{
    boost::asio::io_context ioc;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket>   client;   // kept alive so the connection holds
    std::unique_ptr<tcp::socket>   server;   // moved into the core::Socket

    LoopbackPair()
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor->listen();
        client = std::make_unique<tcp::socket>(ioc);
        client->connect(acceptor->local_endpoint());
        server = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

// Test subclass: injects display-only peers into the IO-owned maps and exposes
// the two production snapshot methods. Access to m_peers (pool::BaseNode) and
// m_outbound_addrs (bip110::pool::NodeImpl) is via protected inheritance — no
// production surface is widened.
struct TestNode : public bip110::pool::Node
{
    using PeerT = ::pool::Peer<bip110::pool::Peer>;

    TestNode(boost::asio::io_context* ctx, bip110::pool::Config* cfg)
        : bip110::pool::Node(ctx, cfg) {}

    // Build a peer over a real (init'd) socket; register it exactly as the IO
    // thread would (m_peers keyed by nonce; m_outbound_addrs holds outbound addrs).
    void inject(StubCommunicator* stub, LoopbackPair& pair, uint64_t nonce,
                const std::string& subver, long uptime_secs, bool outbound)
    {
        auto sock = std::make_shared<core::Socket>(
            std::move(pair.server),
            outbound ? core::outgoing : core::incoming,
            stub, std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();          // captures remote endpoint into m_addr
        sock->cancel();        // neutralize the pending async read (ioc never runs)

        auto peer = std::make_shared<PeerT>(sock);
        peer->m_nonce = nonce;
        peer->m_other_subversion = subver;
        peer->m_connected_at =
            std::chrono::steady_clock::now() - std::chrono::seconds(uptime_secs);

        this->m_peers[nonce] = peer;
        if (outbound)
            this->m_outbound_addrs.insert(peer->addr());
    }

    std::string addr_of(uint64_t nonce) const
    {
        auto it = this->m_peers.find(nonce);
        return it == this->m_peers.end() ? std::string{} : it->second->addr().to_string();
    }

    void erase_peer(uint64_t nonce)
    {
        auto it = this->m_peers.find(nonce);
        if (it == this->m_peers.end()) return;
        this->m_outbound_addrs.erase(it->second->addr());
        this->m_peers.erase(it);
    }

    using bip110::pool::NodeImpl::publish_peer_info_snapshot;
    using bip110::pool::NodeImpl::get_peer_info_json;
};

// Find the entry for a given address in the snapshot array; null json if absent.
nlohmann::json find_entry(const nlohmann::json& arr, const std::string& address)
{
    for (const auto& e : arr)
        if (e.contains("address") && e["address"].get<std::string>() == address)
            return e;
    return nlohmann::json();
}

} // namespace

int main()
{
    using namespace bip110::pool;

    std::printf("bip110_peer_info_snapshot_kat: /peer_list feed — live peers when "
                "connected, empty ONLY when genuinely none\n");

    // Isolated datadir so the real Node ctor (load_persisted_shares) never
    // touches a live c2pool datadir.
    auto tmp = std::filesystem::temp_directory_path()
             / ("bip110_peerinfo_kat_" + std::to_string(::getpid()));
    std::error_code ec;
    std::filesystem::remove_all(tmp, ec);
    std::filesystem::create_directories(tmp, ec);
    core::filesystem::set_data_dir(tmp);

    // Loopback pairs MUST outlive the node (the node owns the peers that own the
    // core::Sockets that own the moved boost sockets; the ioc lives here).
    LoopbackPair pairOut;   // -> OUTBOUND peer
    LoopbackPair pairIn;    // -> INBOUND peer
    StubCommunicator stub;

    boost::asio::io_context ioc;
    Config cfg;
    TestNode node(&ioc, &cfg);

    // (a) Fresh node: honest empty feed (the exact production symptom's correct
    //     baseline — empty because there really are no peers).
    {
        auto j = node.get_peer_info_json();
        expect_true("[a] fresh feed is a JSON array", j.is_array());
        expect_true("[a] fresh feed is EMPTY (no peers yet)", j.empty());
    }

    // (b) One outbound + one inbound peer, then publish.
    const std::string kOutVer = "/c2pool:0.1/bip110/nodeOUT/";
    const std::string kInVer  = "/c2pool:0.1/bip110/nodeIN/";
    node.inject(&stub, pairOut, /*nonce=*/1001, kOutVer, /*uptime=*/42, /*outbound=*/true);
    node.inject(&stub, pairIn,  /*nonce=*/2002, kInVer,  /*uptime=*/7,  /*outbound=*/false);

    const std::string addrOut = node.addr_of(1001);
    const std::string addrIn  = node.addr_of(2002);
    expect_true("[b] the two injected peers have distinct addresses",
                !addrOut.empty() && !addrIn.empty() && addrOut != addrIn);

    node.publish_peer_info_snapshot();
    {
        auto j = node.get_peer_info_json();
        std::printf("  [info] snapshot after 2 injects: %s\n", j.dump().c_str());
        expect_true("[b] feed is a JSON array", j.is_array());
        expect_true("[b] feed has exactly 2 peers", j.size() == 2);

        auto eOut = find_entry(j, addrOut);
        auto eIn  = find_entry(j, addrIn);
        expect_true("[b] outbound peer present by address", !eOut.is_null());
        expect_true("[b] inbound  peer present by address", !eIn.is_null());

        if (!eOut.is_null())
        {
            expect_true("[b] outbound version matches",
                        eOut.value("version", std::string{}) == kOutVer);
            expect_true("[b] outbound direction incoming==false",
                        eOut.value("incoming", true) == false);
            expect_true("[b] outbound uptime >= 0", eOut.value("uptime", -1) >= 0);
            expect_true("[b] outbound downtime == 0", eOut.value("downtime", -1) == 0);
            expect_true("[b] outbound web_port == 0", eOut.value("web_port", -1) == 0);
        }
        if (!eIn.is_null())
        {
            expect_true("[b] inbound version matches",
                        eIn.value("version", std::string{}) == kInVer);
            expect_true("[b] inbound direction incoming==true",
                        eIn.value("incoming", false) == true);
            expect_true("[b] inbound uptime >= 0", eIn.value("uptime", -1) >= 0);
        }
    }

    // (c) Erase the outbound peer + republish -> only the inbound remains.
    node.erase_peer(1001);
    node.publish_peer_info_snapshot();
    {
        auto j = node.get_peer_info_json();
        expect_true("[c] feed has exactly 1 peer after erase", j.size() == 1);
        auto eIn  = find_entry(j, addrIn);
        auto eOut = find_entry(j, addrOut);
        expect_true("[c] remaining peer is the inbound one", !eIn.is_null());
        expect_true("[c] erased outbound peer is GONE", eOut.is_null());
    }

    // (c) Erase the last peer + republish -> empty ONLY because genuinely none.
    node.erase_peer(2002);
    node.publish_peer_info_snapshot();
    {
        auto j = node.get_peer_info_json();
        expect_true("[c] feed is EMPTY again once all peers are gone", j.empty());
    }

    if (g_fail == 0) std::printf("RESULT: PASS — peer-info feed reflects live "
                                 "sharechain peers; empty only when genuinely none.\n");
    else             std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
