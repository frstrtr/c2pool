// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GAP5 step 2a: tx-tracking handler KATs on the ACTUAL arm.
//
// protocol_actual.cpp is the live handler set on the isolated-v36 profile from
// boot (pinned by DashV36E2E.AdmittedIsolatedPeerNegotiatesActualArm) and goes
// live on the public sharechain at the v36 crossing. Before this file nothing
// executed an Actual handler body; DashNodeDispatch only checks that the 13
// handlers are registered.
//
// Each case builds the wire message with make_raw, so the bytes go through the
// real dash::Handler::parse inside dash::Actual::handle_message. Then it asserts
// the per-peer state against canonical p2pool-dash p2p.py (9a0a609):
//
//   have_tx      p2p.py:430-434  remote_tx_hashes.update; pop while > 10000
//   losing_tx    p2p.py:438-440  remote_tx_hashes.difference_update
//   remember_tx  p2p.py:447-491  by-hash from known_txs; full txs keyed by
//                                hash256(tx_type.pack(tx)) and added to
//                                known_txs_var
//   forget_tx    p2p.py:493-497  del remembered_txs[tx_hash]
//
// CURRENT BEHAVIOUR, PINNED WHERE IT DIFFERS FROM CANONICAL. Legacy bodies are
// identical. Each case names the canonical line:
//   remember_tx duplicate or unknown hash   p2p.py:449-452, :463-465, :474-477
//     -> RememberTxDuplicateOrUnknownHashHandling
//   remember_tx stored size, limit 2500000  p2p.py:30, :470, :485-488
//     -> RememberTxStoredSizeHandling
//   forget_tx of an unremembered hash       p2p.py:495
//     -> ForgetTxUnrememberedHashHandling
//
// FOLDED into the EXISTING allowlisted test_dash_node target (#769 trap).

#include <gtest/gtest.h>

#include "dash_socket_harness.hpp"

#include <impl/dash/node.hpp>
#include <impl/dash/messages.hpp>
#include <impl/dash/coin/dash_txid.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

#include <core/addr_store.hpp>
#include <core/filesystem.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

using namespace dash_socket_harness;

// Keeps the probe node's AddrStore off the real ~/.c2pool. Virtual base listed
// first so it is built before NodeImpl (see test_dash_addrme.cpp IsolatedDataDir).
struct ActualKatDataDir
{
    std::filesystem::path prev = core::filesystem::data_dir_override();
    std::filesystem::path dir = std::filesystem::temp_directory_path()
        / ("c2pool-dash-actual-kat-" + std::to_string(::getpid()));

    ActualKatDataDir()
    {
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
        core::filesystem::set_data_dir(dir);
    }
    ~ActualKatDataDir()
    {
        core::filesystem::set_data_dir(prev);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

class ProbeActual : private virtual ActualKatDataDir, public dash::Actual
{
public:
    using dash::Actual::Actual;
    std::map<uint256, dash::coin::Transaction>& known_txs() { return m_known_txs; }
    core::AddrStore& addrs() { return m_addrs; }
    std::map<uint64_t, peer_ptr>& peers() { return m_peers; }
    std::map<NetService, peer_ptr>& connections() { return m_connections; }
};

dash::coin::MutableTransaction make_tx(std::uint32_t salt)
{
    dash::coin::MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    dash::coin::TxIn in;
    in.prevout.hash = uint256(salt);
    in.prevout.index = 0;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    dash::coin::TxOut out;
    out.value = 1000 + salt;
    tx.vout.push_back(out);
    return tx;
}

// Canonical key: hash256(tx_type.pack(tx)), p2p.py:472. Computed independently
// of coin::dash_txid so the test does not check the handler against itself.
uint256 canonical_hash(const dash::coin::MutableTransaction& tx)
{
    auto ps = ::pack(tx);
    return ::Hash(ps.get_span());
}

uint256 h(std::uint32_t n) { return uint256(n); }

struct Rig
{
    // bind_addr: 127.0.0.1 is the addrme self-probe host; any other 127/8
    // address (e.g. 127.0.0.2) is what the handler treats as a routable source.
    explicit Rig(const std::string& bind_addr = "127.0.0.1") : pair(bind_addr) {}

    StubCommunicator stub;
    LoopbackPair pair;
    ProbeActual node;
    // Built exactly as make_socket_peer does, but the socket handle is kept:
    // pool::Peer holds it protected, and the divergence pins below need to see
    // whether a handler closed the connection.
    std::shared_ptr<core::Socket> sock = [this] {
        auto s = std::make_shared<core::Socket>(
            std::move(pair.ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        s->init();
        return s;
    }();
    dash::NodeImpl::peer_ptr peer = std::make_shared<dash::NodeImpl::peer_t>(sock);

    bool open() const { return sock->status(); }
};

} // namespace

// have_tx then losing_tx: set union, then set difference. A losing_tx for a hash
// the peer never advertised is a no-op (difference_update), not an error.
TEST(DashActualHandlers, HaveTxThenLosingTxFollowCanonicalSetSemantics)
{
    Rig r;
    r.node.handle_message(
        dash::message_have_tx::make_raw(std::vector<uint256>{h(1), h(2), h(3)}), r.peer);
    EXPECT_EQ(r.peer->m_remote_txs, (std::set<uint256>{h(1), h(2), h(3)}));

    r.node.handle_message(
        dash::message_have_tx::make_raw(std::vector<uint256>{h(3), h(4)}), r.peer);
    EXPECT_EQ(r.peer->m_remote_txs, (std::set<uint256>{h(1), h(2), h(3), h(4)}))
        << "have_tx is a set update: a repeated hash is not double-counted";

    r.node.handle_message(
        dash::message_losing_tx::make_raw(std::vector<uint256>{h(2), h(99)}), r.peer);
    EXPECT_EQ(r.peer->m_remote_txs, (std::set<uint256>{h(1), h(3), h(4)}))
        << "losing_tx removes advertised hashes and ignores unknown ones";
}

// p2p.py:433-434: while len(remote_tx_hashes) > 10000: pop(). The set ends at
// exactly 10000. Which entries go is unspecified in canonical (set.pop), so only
// the size and the subset relation are asserted.
TEST(DashActualHandlers, HaveTxCapsRemoteSetAtTenThousand)
{
    // 10000 is the boundary: kept whole. 10001 is the first size the cap must
    // trim. 10005 checks that the trim lands on 10000, not just below the trigger.
    for (std::uint32_t n : {10000u, 10001u, 10005u}) {
        SCOPED_TRACE("advertised " + std::to_string(n));
        Rig r;
        std::vector<uint256> hashes;
        for (std::uint32_t i = 1; i <= n; ++i) hashes.push_back(h(i));
        r.node.handle_message(dash::message_have_tx::make_raw(hashes), r.peer);

        EXPECT_EQ(r.peer->m_remote_txs.size(), 10000u);
        const std::set<uint256> all(hashes.begin(), hashes.end());
        for (const auto& x : r.peer->m_remote_txs)
            ASSERT_TRUE(all.contains(x)) << "the cap may only evict, never invent";
    }
}

// remember_tx carries two lists. tx_hashes resolve from the node's known_txs;
// full txs are stored under hash256(pack(tx)) and are added to known_txs.
TEST(DashActualHandlers, RememberTxResolvesHashesAndStoresFullTxs)
{
    Rig r;
    const auto known = make_tx(0x11);
    const uint256 known_h = canonical_hash(known);
    r.node.known_txs().emplace(known_h, dash::coin::Transaction(known));

    const auto full = make_tx(0x22);
    const uint256 full_h = canonical_hash(full);
    ASSERT_FALSE(r.node.known_txs().contains(full_h));

    r.node.handle_message(
        dash::message_remember_tx::make_raw(
            std::vector<uint256>{known_h},
            std::vector<dash::coin::MutableTransaction>{full}),
        r.peer);

    ASSERT_EQ(r.peer->m_remembered_txs.size(), 2u);
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(known_h))
        << "a by-hash remember must resolve from known_txs (p2p.py:454-455)";
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(full_h))
        << "a full tx must be keyed by hash256(pack(tx)) (p2p.py:472)";
    EXPECT_TRUE(r.node.known_txs().contains(full_h))
        << "a full tx must be added to the node's known_txs (p2p.py:486)";
    EXPECT_EQ(dash::coin::dash_txid(full), full_h)
        << "type-0 tx: the lane txid must equal the canonical hash";
}

// forget_tx removes exactly the named entries from remembered_txs and leaves the
// node's known_txs alone (canonical touches only self.remembered_txs).
TEST(DashActualHandlers, ForgetTxDropsOnlyNamedRememberedEntries)
{
    Rig r;
    const auto a = make_tx(0x31);
    const auto b = make_tx(0x32);
    const uint256 ha = canonical_hash(a), hb = canonical_hash(b);

    r.node.handle_message(
        dash::message_remember_tx::make_raw(
            std::vector<uint256>{},
            std::vector<dash::coin::MutableTransaction>{a, b}),
        r.peer);
    ASSERT_EQ(r.peer->m_remembered_txs.size(), 2u);

    r.node.handle_message(dash::message_forget_tx::make_raw(std::vector<uint256>{ha}), r.peer);

    EXPECT_FALSE(r.peer->m_remembered_txs.contains(ha));
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(hb));
    EXPECT_TRUE(r.node.known_txs().contains(ha))
        << "forget_tx is per-peer; it must not evict from the node's known_txs";

    // The remote advertises a hash again after forgetting it: canonical accepts
    // a fresh remember (the twice-check is against the current remembered set).
    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{ha},
                                            std::vector<dash::coin::MutableTransaction>{}),
        r.peer);
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(ha));
}

// ---- Current behaviour, pinned where it differs from canonical (file header) ----
// Each case asserts the later entries of the same message, error_count and the
// socket state. Actual::handle_message catches handler exceptions
// (protocol_actual.cpp:38-46).

TEST(DashActualHandlers, RememberTxDuplicateOrUnknownHashHandling)
{
    Rig r;
    const auto a = make_tx(0x41), b = make_tx(0x42), c = make_tx(0x43);
    const uint256 ha = canonical_hash(a), hb = canonical_hash(b), hc = canonical_hash(c);
    r.node.known_txs().emplace(hb, dash::coin::Transaction(b));
    r.node.known_txs().emplace(hc, dash::coin::Transaction(c));

    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{},
                                            std::vector<dash::coin::MutableTransaction>{a}),
        r.peer);
    ASSERT_TRUE(r.peer->m_remembered_txs.contains(ha));

    // By-hash list: [already remembered, unknown, known]. Canonical p2p.py:449-452.
    const uint256 unknown = h(0xdead);
    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{ha, unknown, hb},
                                            std::vector<dash::coin::MutableTransaction>{}),
        r.peer);
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(hb))
        << "CURRENT: entries after a duplicate/unknown hash are processed "
           "(canonical p2p.py:449-452, :463-465)";
    EXPECT_FALSE(r.peer->m_remembered_txs.contains(unknown));

    // Full-tx list: [already remembered, new]. Canonical p2p.py:474-477.
    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{},
                                            std::vector<dash::coin::MutableTransaction>{a, c}),
        r.peer);
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(hc))
        << "CURRENT: a duplicate full tx is skipped (canonical p2p.py:474-477)";
    EXPECT_EQ(r.peer->m_remembered_txs.size(), 3u);
    EXPECT_EQ(r.stub.error_count.load(), 0) << "CURRENT: error_count 0";
    EXPECT_TRUE(r.open()) << "CURRENT: socket open";
}

TEST(DashActualHandlers, RememberTxStoredSizeHandling)
{
    Rig r;
    // Canonical accounting: 100 + packed_size per tx, limit 2500000
    // (p2p.py:30, :485-488). Script size 2500000.
    auto big = make_tx(0x51);
    std::vector<unsigned char> script(2500000, 0x51);
    big.vout[0].scriptPubKey = OPScript(script.data(), script.data() + script.size());
    const auto small = make_tx(0x52);
    const uint256 hbig = canonical_hash(big), hsmall = canonical_hash(small);

    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{},
                                            std::vector<dash::coin::MutableTransaction>{big}),
        r.peer);
    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{},
                                            std::vector<dash::coin::MutableTransaction>{small}),
        r.peer);
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(hbig));
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(hsmall))
        << "CURRENT: stored beyond 2500000 (canonical p2p.py:485-488)";
    EXPECT_EQ(r.stub.error_count.load(), 0);
    EXPECT_TRUE(r.open()) << "CURRENT: socket open";
}

TEST(DashActualHandlers, ForgetTxUnrememberedHashHandling)
{
    Rig r;
    const auto a = make_tx(0x61), b = make_tx(0x62);
    const uint256 ha = canonical_hash(a), hb = canonical_hash(b);
    r.node.handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{},
                                            std::vector<dash::coin::MutableTransaction>{a, b}),
        r.peer);
    ASSERT_EQ(r.peer->m_remembered_txs.size(), 2u);

    // [never remembered, a]. Canonical p2p.py:495.
    r.node.handle_message(
        dash::message_forget_tx::make_raw(std::vector<uint256>{h(0xbeef), ha}), r.peer);
    EXPECT_FALSE(r.peer->m_remembered_txs.contains(ha))
        << "CURRENT: an unremembered hash is skipped, later entries apply "
           "(canonical p2p.py:495)";
    EXPECT_TRUE(r.peer->m_remembered_txs.contains(hb));
    EXPECT_EQ(r.stub.error_count.load(), 0);
    EXPECT_TRUE(r.open()) << "CURRENT: socket open";
}

// =============================================================================
// GAP5 step 2b: ping / addrs / addrme / getaddrs / bestblock on the ACTUAL arm.
//
// Canonical (p2pool-dash 9a0a609):
//   ping      p2p.py:272-273   pass
//   addrme    p2p.py:278-302   127.0.0.1 source -> relay addrme to a random
//                              peer (0.8); else got_addr(host:port) and relay
//                              one addrs record to a random peer (0.8)
//   addrs     p2p.py:304-309   got_addr(min(now, ts)) per record; relay the
//                              record to a random node.peers entry (0.8)
//   getaddrs  p2p.py:313-325   count capped at 100; reply addrs from
//                              get_good_peers(count), services = store[0],
//                              timestamp = store[2] (last_seen)
//   got_addr  p2p.py:779-792   new -> (services, ts, ts) if < 10000 entries;
//                              known -> last_seen = max(old, ts)
//   bestblock p2p.py:423-424 -> node.py:81-84; no relay.
//                              BLOCKHASH_FUNC = POW_FUNC = X11
//                              (p2pool/dash/networks/dash.py:19-20).
//
// CURRENT BEHAVIOUR, PINNED WHERE IT DIFFERS FROM CANONICAL (as step 2a; Legacy
// bodies are identical; each case names the canonical line):
//   addrs relay target set and relayed timestamp   p2p.py:306-308
//     -> AddrsRelayTargetAndTimestamp
//   bestblock header handling                      node.py:81-84, dash.py:19-20
//     -> BestblockHeaderHandling
//
// Not a divergence: getaddrs skips entries is_wire_advertisable() rejects (#910,
// hard rule: never advertise an address we cannot render). Canonical resolves a
// bootstrap hostname before got_addr, so its store never holds one and the
// reply is the same.
// =============================================================================

namespace {

std::vector<dash_socket_harness::Frame> drain(Rig& r, std::chrono::milliseconds quiet)
{
    return dash_socket_harness::read_frames(*r.pair.theirs, quiet);
}

std::vector<addr_record_t> decode_addrs(const dash_socket_harness::Frame& f)
{
    PackStream ps{std::span<const std::byte>(f.payload)};
    return dash::message_addrs::make(ps)->m_addrs;
}

std::size_t count_frames(const std::vector<dash_socket_harness::Frame>& frames,
                         std::string_view command)
{
    std::size_t n = 0;
    for (const auto& f : frames)
        if (f.command == command) ++n;
    return n;
}

} // namespace

// p2p.py:272-273: ping does nothing. No reply, no state change, socket open.
TEST(DashActualHandlers, PingIsANoOp)
{
    Rig r;
    r.peer->m_nonce = 0x1001;
    r.node.peers()[r.peer->m_nonce] = r.peer;
    r.node.connections()[r.peer->addr()] = r.peer;
    const auto store_before = r.node.addrs().len();

    IoThread io(r.pair.ioc_node);
    for (int i = 0; i < 8; ++i)
        r.node.handle_message(dash::message_ping::make_raw(), r.peer);
    const auto frames = drain(r, std::chrono::milliseconds(200));
    io.stop(r.pair.ioc_node);

    EXPECT_TRUE(frames.empty()) << "ping must not be answered (p2p.py:273 pass)";
    EXPECT_EQ(r.node.addrs().len(), store_before);
    EXPECT_EQ(r.stub.error_count.load(), 0);
    EXPECT_TRUE(r.open());
}

// p2p.py:306 + got_addr p2p.py:787-792. The source peer is in no relay map, so
// only the store is exercised here.
TEST(DashActualHandlers, AddrsRecordsEntriesWithCanonicalTimestampRules)
{
    Rig r;
    const NetService past{std::string("10.1.2.3"), 8999};
    const NetService future{std::string("10.1.2.4"), 8999};
    constexpr std::uint64_t kSvcPast = 0x11, kSvcFuture = 0x22;

    const std::uint64_t before = core::timestamp();
    const std::uint64_t t_past = before - 1000;
    r.node.handle_message(
        dash::message_addrs::make_raw(std::vector<addr_record_t>{
            {kSvcPast, past, t_past},
            {kSvcFuture, future, before + 100000}}),
        r.peer);
    const std::uint64_t after = core::timestamp();

    ASSERT_TRUE(r.node.addrs().check(past));
    ASSERT_TRUE(r.node.addrs().check(future));
    const auto vp = r.node.addrs().get(past);
    EXPECT_EQ(vp.m_service, kSvcPast);
    EXPECT_EQ(vp.m_first_seen, t_past);
    EXPECT_EQ(vp.m_last_seen, t_past);
    const auto vf = r.node.addrs().get(future);
    EXPECT_EQ(vf.m_service, kSvcFuture);
    EXPECT_GE(vf.m_last_seen, before);
    EXPECT_LE(vf.m_last_seen, after)
        << "a future timestamp is stored as min(now, ts) (p2p.py:306)";

    // Known entry: last_seen = max(old, ts), first_seen kept, services replaced.
    r.node.handle_message(
        dash::message_addrs::make_raw(std::vector<addr_record_t>{{0x33, past, t_past - 500}}),
        r.peer);
    EXPECT_EQ(r.node.addrs().get(past).m_last_seen, t_past)
        << "an older timestamp must not move last_seen back (p2p.py:789 max)";
    EXPECT_EQ(r.node.addrs().get(past).m_service, 0x33u)
        << "services are replaced by the latest record (p2p.py:789)";

    r.node.handle_message(
        dash::message_addrs::make_raw(std::vector<addr_record_t>{{0x33, past, t_past + 10}}),
        r.peer);
    EXPECT_EQ(r.node.addrs().get(past).m_first_seen, t_past);
    EXPECT_EQ(r.node.addrs().get(past).m_last_seen, t_past + 10);
}

// Current behaviour (file header): relay target set and relayed timestamp.
TEST(DashActualHandlers, AddrsRelayTargetAndTimestamp)
{
    Rig r;
    // In m_connections, not in m_peers.
    r.node.connections()[r.peer->addr()] = r.peer;
    ASSERT_TRUE(r.node.peers().empty());

    const NetService rec{std::string("10.9.8.7"), 8999};
    constexpr std::uint64_t kSvc = 0xA5A5'0000'0000'0001ull;
    const std::uint64_t future = core::timestamp() + 100000;

    IoThread io(r.pair.ioc_node);
    for (int i = 0; i < 32; ++i)
        r.node.handle_message(
            dash::message_addrs::make_raw(std::vector<addr_record_t>{{kSvc, rec, future}}),
            r.peer);
    const auto frames = drain(r, std::chrono::milliseconds(300));
    io.stop(r.pair.ioc_node);

    const auto* f = find_frame(frames, "addrs");
    ASSERT_NE(f, nullptr)
        << "CURRENT: relay target drawn from m_connections "
           "(canonical p2p.py:307-308: node.peers)";
    const auto relayed = decode_addrs(*f);
    ASSERT_EQ(relayed.size(), 1u);
    EXPECT_EQ(relayed[0].m_endpoint.address(), "10.9.8.7");
    EXPECT_EQ(relayed[0].m_endpoint.port(), 8999);
    EXPECT_EQ(relayed[0].m_services, kSvc);
    EXPECT_LT(relayed[0].m_timestamp, future)
        << "CURRENT: relayed timestamp = clamped value (canonical p2p.py:308)";
}

// p2p.py:281-283: a 127.0.0.1 source takes the self-probe arm. The addrme is
// passed to a random peer with the same port and nothing is recorded.
TEST(DashActualHandlers, AddrmeFromLoopbackHostRelaysAddrmeAndRecordsNothing)
{
    constexpr std::uint16_t kPort = 41337;
    Rig r;
    ASSERT_EQ(r.peer->addr().address(), "127.0.0.1");
    r.peer->m_nonce = 0x2002;
    r.node.peers()[r.peer->m_nonce] = r.peer;
    const NetService loop{std::string("127.0.0.1"), kPort};

    IoThread io(r.pair.ioc_node);
    for (int i = 0; i < 32; ++i)
        r.node.handle_message(dash::message_addrme::make_raw(kPort), r.peer);
    const auto frames = drain(r, std::chrono::milliseconds(300));
    io.stop(r.pair.ioc_node);

    EXPECT_FALSE(r.node.addrs().check(loop)) << "the self-probe arm never calls got_addr";
    EXPECT_EQ(find_frame(frames, "addrs"), nullptr);
    const auto* f = find_frame(frames, "addrme");
    ASSERT_NE(f, nullptr) << "p2p.py:283 relays the addrme to a random peer";
    PackStream ps{std::span<const std::byte>(f->payload)};
    EXPECT_EQ(dash::message_addrme::make(ps)->m_port, kPort);
}

// p2p.py:284-302: any other source is recorded as host:port with the peer's
// services and relayed as ONE addrs record (never as addrme).
TEST(DashActualHandlers, AddrmeFromRoutableSourceRecordsAndRelaysOneAddrsRecord)
{
    constexpr std::uint16_t kPort = 8999;
    constexpr std::uint64_t kSvc = 0xA5A5'0000'1234'5678ull;
    Rig r("127.0.0.2");
    ASSERT_EQ(r.peer->addr().address(), "127.0.0.2");
    r.peer->m_other_services = kSvc;
    r.peer->m_nonce = 0x3003;
    r.node.peers()[r.peer->m_nonce] = r.peer;
    const NetService rec{std::string("127.0.0.2"), kPort};

    const std::uint64_t before = core::timestamp();
    IoThread io(r.pair.ioc_node);
    for (int i = 0; i < 32; ++i)
        r.node.handle_message(dash::message_addrme::make_raw(kPort), r.peer);
    const auto frames = drain(r, std::chrono::milliseconds(300));
    io.stop(r.pair.ioc_node);
    const std::uint64_t after = core::timestamp();

    ASSERT_TRUE(r.node.addrs().check(rec)) << "p2p.py:285 got_addr((host, port), ...)";
    EXPECT_EQ(r.node.addrs().get(rec).m_service, kSvc);
    EXPECT_GE(r.node.addrs().get(rec).m_last_seen, before);
    EXPECT_LE(r.node.addrs().get(rec).m_last_seen, after);

    EXPECT_EQ(find_frame(frames, "addrme"), nullptr);
    const auto* f = find_frame(frames, "addrs");
    ASSERT_NE(f, nullptr);
    const auto relayed = decode_addrs(*f);
    ASSERT_EQ(relayed.size(), 1u);
    EXPECT_EQ(relayed[0].m_endpoint.address(), "127.0.0.2");
    EXPECT_EQ(relayed[0].m_endpoint.port(), kPort);
    EXPECT_EQ(relayed[0].m_services, kSvc);
    EXPECT_GE(relayed[0].m_timestamp, before);
    EXPECT_LE(relayed[0].m_timestamp, after);
}

// p2p.py:313-325: count is capped at 100 and each record is served straight
// from the store (services = [0], timestamp = last_seen [2]). Count 0 still gets
// an (empty) addrs reply.
TEST(DashActualHandlers, GetaddrsCapsAtHundredAndServesStoreRecords)
{
    for (std::uint32_t asked : {0u, 3u, 100u, 500u}) {
        SCOPED_TRACE("getaddrs count " + std::to_string(asked));
        Rig r;
        const std::uint64_t now = core::timestamp();
        for (std::uint32_t i = 0; i < 150; ++i) {
            const NetService a{"10.0." + std::to_string(i / 200) + "." + std::to_string(i + 1),
                               static_cast<std::uint16_t>(9000 + i)};
            r.node.addrs().add(a, core::AddrValue{0x100u + i, now - 7200 - i, now - i});
        }

        IoThread io(r.pair.ioc_node);
        r.node.handle_message(dash::message_getaddrs::make_raw(asked), r.peer);
        const auto frames = drain(r, std::chrono::milliseconds(300));
        io.stop(r.pair.ioc_node);

        ASSERT_EQ(count_frames(frames, "addrs"), 1u) << "exactly one addrs reply";
        const auto reply = decode_addrs(*find_frame(frames, "addrs"));
        EXPECT_EQ(reply.size(), std::min<std::uint32_t>(asked, 100u));
        std::set<NetService> seen;
        for (const auto& rec : reply) {
            ASSERT_TRUE(r.node.addrs().check(rec.m_endpoint)) << "served only from the store";
            const auto v = r.node.addrs().get(rec.m_endpoint);
            EXPECT_EQ(rec.m_services, v.m_service) << "p2p.py:321 services = store[0]";
            EXPECT_EQ(rec.m_timestamp, v.m_last_seen) << "p2p.py:318 timestamp = store[2]";
            EXPECT_TRUE(seen.insert(rec.m_endpoint).second) << "no duplicate records";
        }
    }
}

// #910 / never-advertise rule: a store entry that cannot be rendered on the wire
// is left out of the reply, and the rest are still served.
TEST(DashActualHandlers, GetaddrsSkipsAnUnrenderableHost)
{
    Rig r;
    const std::uint64_t now = core::timestamp();
    const NetService named{std::string("dash-seed.example.invalid"), 8999};
    const NetService a{std::string("10.2.0.1"), 8999};
    const NetService b{std::string("10.2.0.2"), 8999};
    ASSERT_FALSE(named.is_wire_advertisable());
    r.node.addrs().add(named, core::AddrValue{1, now - 10, now});
    r.node.addrs().add(a, core::AddrValue{1, now - 10, now});
    r.node.addrs().add(b, core::AddrValue{1, now - 10, now});

    IoThread io(r.pair.ioc_node);
    r.node.handle_message(dash::message_getaddrs::make_raw(100u), r.peer);
    const auto frames = drain(r, std::chrono::milliseconds(300));
    io.stop(r.pair.ioc_node);

    ASSERT_NE(find_frame(frames, "addrs"), nullptr);
    const auto reply = decode_addrs(*find_frame(frames, "addrs"));
    std::set<std::string> hosts;
    for (const auto& rec : reply) hosts.insert(rec.m_endpoint.address());
    EXPECT_EQ(hosts, (std::set<std::string>{"10.2.0.1", "10.2.0.2"}))
        << "the hostname entry must be skipped and the numeric ones served";
}

// Current behaviour (file header). Header bits 0x03000001 (target 1).
TEST(DashActualHandlers, BestblockHeaderHandling)
{
    Rig r;
    r.peer->m_nonce = 0x4004;
    r.node.peers()[r.peer->m_nonce] = r.peer;   // a relay target exists
    r.node.connections()[r.peer->addr()] = r.peer;

    std::vector<uint256> hooked;
    r.node.set_on_bestblock([&](const uint256& h) { hooked.push_back(h); });

    dash::coin::BlockHeaderType header;
    header.m_version = 0x20000000;
    header.m_previous_block = uint256(0xabcdef);
    header.m_merkle_root = uint256(0x123456);
    header.m_timestamp = 1700000000;
    header.m_bits = 0x03000001;
    header.m_nonce = 42;

    auto ps = ::pack(header);
    const uint256 sha256d = ::Hash(ps.get_span());
    const uint256 x11 = dash::crypto::hash_x11(ps.get_span());
    ASSERT_EQ(ps.get_span().size(), 80u) << "a full block header is 80 bytes";
    ASSERT_NE(x11, uint256()) << "precondition: X11 hash > 1";
    ASSERT_NE(x11, uint256(1));
    ASSERT_NE(sha256d, x11);

    IoThread io(r.pair.ioc_node);
    r.node.handle_message(dash::message_bestblock::make_raw(header), r.peer);
    const auto frames = drain(r, std::chrono::milliseconds(200));
    io.stop(r.pair.ioc_node);

    EXPECT_EQ(find_frame(frames, "bestblock"), nullptr)
        << "bestblock is never relayed (canonical node.py:81-84)";
    ASSERT_EQ(hooked.size(), 1u);
    EXPECT_EQ(hooked[0], sha256d)
        << "CURRENT: hook value = SHA256d(header) "
           "(canonical BLOCKHASH_FUNC = X11, dash.py:19)";
    EXPECT_EQ(r.stub.error_count.load(), 0);
    EXPECT_TRUE(r.open())
        << "CURRENT: socket open (canonical node.py:82-83)";
}
