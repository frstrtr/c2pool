// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A parent share is asked of the peer that has it, not only of the peer that
// advertised it.
//
// THE incident (2026-11-13, LTC): two stalled nodes each held the share the
// other needed, and each kept asking only the peer that had advertised it,
// which answered empty every time. download_shares chose peers with
// FetchFailureMemory::choose: skip a peer that failed this hash within 90 s,
// else prefer the advertiser. DesiredRequestPacer spaced the retries 5, 10,
// 20 ... 300 s apart, so from about the sixth retry every failure had aged out
// and choose() went straight back to the advertiser. A holder that was not
// among the first few random picks was never asked again.
//
// Pinned here:
//   * the node (a REAL ltc::NodeImpl, its download_shares and reply callback,
//     peers on real loopback sockets; the only seam is the share-request
//     sender, which records who was asked): an empty reply from the
//     advertiser sends the request to the next peer AT ONCE, with no backoff;
//     the pacer backs off only once every connected peer has answered empty;
//     a peer that connects then is asked at once;
//   * the node, too: a peer that keeps reconnecting does not collapse the
//     backoff (only a host not seen for 10 min wakes it, at most every 30 s),
//     and a share that arrived another way is not asked for again;
//   * the policy (FetchPeerRotation and PeerWakeGate, the pure headers
//     node.cpp wires in): untried first, advertiser only while untried, a
//     30 min memory, rotation once every peer failed, a reconnected peer is
//     untried; and the incident replayed over simulated hours.
//
// RED on master: the two NodeImpl cases that use only master's API
// (EmptyReplyFromTheAdvertiserAsksTheNextPeerAtOnce,
// BackoffStartsOnlyOnceEveryConnectedPeerAnsweredEmpty) — master asks nobody
// after an empty reply and backs the hash off at once. The rest do not build
// on master (new API).
//
// Folded into the existing allowlisted `share_test` target (the #769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/desired_request_pacer.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_fetch_failover.hpp>

#include <core/netaddress.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

using boost::asio::ip::tcp;
using namespace std::chrono_literals;

const std::vector<std::byte>& test_prefix()
{
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

struct StubCommunicator : public core::ICommunicator
{
    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return test_prefix(); }
};

struct SocketPair
{
    boost::asio::io_context ioc;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    SocketPair()
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor->listen();
        ours = std::make_unique<tcp::socket>(ioc);
        ours->connect(acceptor->local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

// The node, with the share-request sender replaced by a recorder: every
// SHAREREQ download_shares sends is logged as (request id, peer asked).
struct FetchNode : public ltc::NodeImpl
{
    std::vector<std::pair<uint256, NetService>> asked;

    explicit FetchNode(boost::asio::io_context& ioc) : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_context = &ioc;
        m_share_getter = decltype(m_share_getter)(
            &ioc,
            [this](uint256 id, peer_ptr to, std::vector<uint256>, uint64_t, std::vector<uint256>) {
                asked.emplace_back(id, to->addr());
            },
            15);
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_desired_pacer;
    using ltc::NodeImpl::m_peers;
    using ltc::NodeImpl::m_tracker;

    peer_ptr attach_peer(SocketPair& pair, StubCommunicator& stub, uint64_t nonce)
    {
        auto sock = std::make_shared<core::Socket>(
            std::move(pair.ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();
        auto peer = std::make_shared<ltc::NodeImpl::peer_t>(sock);
        peer->m_other_version = ltc::PoolConfig::V3601_PROTOCOL_VERSION;
        peer->m_nonce = nonce;
        m_peers[nonce] = peer;
        return peer;
    }

    // The peer answers the last request: empty (it does not have the share,
    // or it timed out).
    void answer_last_empty() { got_share_reply(asked.back().first, ltc::ShareReplyData{}); }
};

double now_s() { return static_cast<double>(std::time(nullptr)); }

const uint256 kWanted = uint256(0x7a11);

} // namespace

// ---- the node ---------------------------------------------------------------

// The advertiser answers empty; the other peer (which holds the share) is
// asked at once — no think() cycle, no pacer backoff.
// Master: nobody is asked after the empty reply, and the hash is backed off.
TEST(LtcParentFetchRotation, EmptyReplyFromTheAdvertiserAsksTheNextPeerAtOnce)
{
    SocketPair pa, pb;
    StubCommunicator stub;
    FetchNode node(pa.ioc);
    auto advertiser = node.attach_peer(pa, stub, 0xa1);
    auto holder = node.attach_peer(pb, stub, 0xb2);

    node.download_shares(advertiser, kWanted);
    ASSERT_EQ(node.asked.size(), 1u);
    EXPECT_EQ(node.asked[0].second, advertiser->addr()) << "the advertiser is asked first";

    node.answer_last_empty();
    pa.ioc.run_for(300ms);   // the drain timer (50 ms) — not the pacer's 5 s
    ASSERT_EQ(node.asked.size(), 2u)
        << "after the advertiser's empty reply the next peer must be asked at once";
    EXPECT_EQ(node.asked[1].second, holder->addr());
    EXPECT_EQ(node.m_desired_pacer.attempts(kWanted), 0)
        << "no backoff while a connected peer has not been asked";
    EXPECT_TRUE(node.m_desired_pacer.eligible(kWanted, now_s()));
}

// Every connected peer answered empty: now, and only now, the pacer backs the
// hash off, and nobody else is asked.
TEST(LtcParentFetchRotation, BackoffStartsOnlyOnceEveryConnectedPeerAnsweredEmpty)
{
    SocketPair pa, pb, pc;
    StubCommunicator stub;
    FetchNode node(pa.ioc);
    auto advertiser = node.attach_peer(pa, stub, 0xa1);
    node.attach_peer(pb, stub, 0xb2);
    node.attach_peer(pc, stub, 0xc3);

    node.download_shares(advertiser, kWanted);
    for (int answered = 1; answered < 3; ++answered) {
        node.answer_last_empty();
        pa.ioc.run_for(300ms);
        ASSERT_EQ(node.asked.size(), static_cast<size_t>(answered + 1))
            << "peer " << answered + 1 << " of 3 is asked at once";
        EXPECT_EQ(node.m_desired_pacer.attempts(kWanted), 0);
    }
    std::set<NetService> distinct;
    for (const auto& [id, who] : node.asked)
        distinct.insert(who);
    EXPECT_EQ(distinct.size(), 3u) << "each peer asked once, none twice";

    node.answer_last_empty();   // the third and last peer
    pa.ioc.run_for(300ms);
    EXPECT_EQ(node.asked.size(), 3u) << "every peer failed it: no fourth request";
    EXPECT_EQ(node.m_desired_pacer.attempts(kWanted), 1) << "the backoff engages now";
    EXPECT_FALSE(node.m_desired_pacer.eligible(kWanted, now_s()));
}

// After every peer failed it (backed off), a peer that connects is asked at
// once, as soon as the hash is wanted again.
TEST(LtcParentFetchRotation, APeerThatConnectsIsAskedAtOnce)
{
    SocketPair pa, pb, pn;
    StubCommunicator stub;
    struct JoinNode : FetchNode {
        using FetchNode::FetchNode;
        using ltc::NodeImpl::m_pending_desired;
        using ltc::NodeImpl::note_fetch_peer_connected;
    } node(pa.ioc);
    auto advertiser = node.attach_peer(pa, stub, 0xa1);
    node.attach_peer(pb, stub, 0xb2);

    node.download_shares(advertiser, kWanted);
    node.answer_last_empty();
    pa.ioc.run_for(300ms);
    node.answer_last_empty();
    pa.ioc.run_for(300ms);
    ASSERT_EQ(node.asked.size(), 2u);
    ASSERT_FALSE(node.m_desired_pacer.eligible(kWanted, now_s())) << "backed off";

    auto newcomer = node.attach_peer(pn, stub, 0xd4);
    node.note_fetch_peer_connected(newcomer->addr());   // what the handshake calls
    EXPECT_TRUE(node.m_desired_pacer.eligible(kWanted, now_s()));

    // think() wants it again (as every cycle re-derives `desired`).
    node.m_pending_desired.push_back({advertiser->addr(), kWanted, 0});
    node.drain_pending_desired();
    ASSERT_EQ(node.asked.size(), 3u);
    EXPECT_EQ(node.asked[2].second, newcomer->addr()) << "the new peer is the untried one";
}

// A peer that keeps reconnecting (here: the same host again within minutes)
// does not collapse the backoff: only the first handshake of a host wakes the
// backed-off parents.
TEST(LtcParentFetchRotation, AFlappingPeerDoesNotCollapseTheBackoff)
{
    SocketPair pa, pb;
    StubCommunicator stub;
    struct JoinNode : FetchNode {
        using FetchNode::FetchNode;
        using ltc::NodeImpl::note_fetch_peer_connected;
    } node(pa.ioc);
    auto advertiser = node.attach_peer(pa, stub, 0xa1);
    auto other = node.attach_peer(pb, stub, 0xb2);
    node.note_fetch_peer_connected(advertiser->addr());   // both handshakes: hosts seen
    node.note_fetch_peer_connected(other->addr());

    node.download_shares(advertiser, kWanted);
    node.answer_last_empty();
    pa.ioc.run_for(300ms);
    node.answer_last_empty();
    pa.ioc.run_for(300ms);
    ASSERT_FALSE(node.m_desired_pacer.eligible(kWanted, now_s())) << "backed off";

    // The same host redials (a new source port), again and again.
    for (uint16_t port : {40001, 40002, 40003}) {
        node.note_fetch_peer_connected(NetService{other->addr().address(), port});
        EXPECT_FALSE(node.m_desired_pacer.eligible(kWanted, now_s()))
            << "a redial of a host seen minutes ago must not reset the backoff";
    }
}

// The advertiser answers empty, but meanwhile the share arrived another way:
// nobody is asked for it again.
TEST(LtcParentFetchRotation, AShareAlreadyHeldIsNotAskedAgain)
{
    SocketPair pa, pb;
    StubCommunicator stub;
    FetchNode node(pa.ioc);
    auto advertiser = node.attach_peer(pa, stub, 0xa1);
    node.attach_peer(pb, stub, 0xb2);

    node.download_shares(advertiser, kWanted);
    ASSERT_EQ(node.asked.size(), 1u);
    node.m_tracker.chain.add(new ltc::MergedMiningShare(kWanted, uint256()));
    node.answer_last_empty();
    pa.ioc.run_for(300ms);
    EXPECT_EQ(node.asked.size(), 1u) << "held: not asked of the other peer";
    EXPECT_EQ(node.m_desired_pacer.attempts(kWanted), 0);
}

// ---- the policy -------------------------------------------------------------

using Rotation = ltc::FetchPeerRotation<std::string, std::string>;
using Pacer = ltc::DesiredRequestPacer<std::string>;

namespace {
auto first = [](std::size_t) -> std::size_t { return 0; };
}

TEST(LtcParentFetchRotation, UntriedPeersFirstAdvertiserOnlyWhileUntried)
{
    Rotation r;
    const std::vector<std::string> peers{"A", "B", "C"};
    EXPECT_EQ(*r.choose("H", std::optional<std::string>{"B"}, peers, 0.0, first), "B");
    EXPECT_TRUE(r.record_failure("H", "B", peers, 0.0));
    // B (the advertiser) failed: an untried peer, not B.
    EXPECT_EQ(*r.choose("H", std::optional<std::string>{"B"}, peers, 1.0, first), "A");
    EXPECT_TRUE(r.record_failure("H", "A", peers, 1.0));
    EXPECT_EQ(*r.choose("H", std::optional<std::string>{"B"}, peers, 2.0, first), "C");
    EXPECT_FALSE(r.record_failure("H", "C", peers, 2.0)) << "nobody untried is left";
}

// The memory outlives the pacer's whole ladder (the 90 s one did not).
TEST(LtcParentFetchRotation, AFailureIsRememberedForThirtyMinutes)
{
    Rotation r;
    const std::vector<std::string> peers{"A", "B"};
    r.record_failure("H", "A", peers, 0.0);
    for (double t : {91.0, 300.0, 1200.0, 1800.0})
        EXPECT_EQ(*r.choose("H", std::optional<std::string>{"A"}, peers, t, first), "B") << t;
    EXPECT_EQ(*r.choose("H", std::optional<std::string>{"A"}, peers, 1801.0, first), "A")
        << "past the TTL the advertiser is untried again";
    r.prune(1801.0);
    EXPECT_EQ(r.tracked_hashes(), 0u);
}

// Every peer failed it: the one that failed longest ago, in turn — never
// "nobody" while a peer is connected (the pacer decides when, not this).
TEST(LtcParentFetchRotation, OnceEveryPeerFailedItRotatesOldestFirst)
{
    Rotation r;
    const std::vector<std::string> peers{"A", "B", "C"};
    r.record_failure("H", "B", peers, 10.0);
    r.record_failure("H", "C", peers, 20.0);
    r.record_failure("H", "A", peers, 30.0);
    std::vector<std::string> order;
    double t = 40.0;
    for (int i = 0; i < 6; ++i, t += 10.0) {
        const auto p = r.choose("H", std::optional<std::string>{"A"}, peers, t, first);
        ASSERT_TRUE(p.has_value());
        order.push_back(*p);
        r.record_failure("H", *p, peers, t);
    }
    EXPECT_EQ(order, (std::vector<std::string>{"B", "C", "A", "B", "C", "A"}));
    EXPECT_FALSE(r.choose("H", std::nullopt, {}, t, first).has_value());
}

TEST(LtcParentFetchRotation, AReconnectedPeerIsUntriedAndSuccessForgetsTheHash)
{
    Rotation r;
    const std::vector<std::string> peers{"A", "B"};
    r.record_failure("H", "A", peers, 0.0);
    r.record_failure("H", "B", peers, 0.0);
    r.record_failure("G", "B", peers, 0.0);
    r.forget_peer("B");
    EXPECT_EQ(*r.choose("H", std::optional<std::string>{"A"}, peers, 1.0, first), "B");
    EXPECT_EQ(*r.choose("G", std::nullopt, peers, 1.0, first), "A");
    r.clear_hash("H");
    EXPECT_EQ(*r.choose("H", std::optional<std::string>{"A"}, peers, 1.0, first), "A");
}

TEST(LtcParentFetchRotation, MakeAllEligibleKeepsTheExponent)
{
    Pacer pacer;
    pacer.record_empty("H", 0.0);
    pacer.record_empty("H", 10.0);   // 10 s backoff now
    ASSERT_FALSE(pacer.eligible("H", 11.0));
    pacer.make_all_eligible(11.0);
    EXPECT_TRUE(pacer.eligible("H", 11.0));
    EXPECT_EQ(pacer.attempts("H"), 2);
    pacer.record_empty("H", 11.0);
    EXPECT_FALSE(pacer.eligible("H", 11.0 + Pacer::kBaseBackoff * 4 - 1))
        << "the next backoff continues the ladder (20 s), not from the base";
}

// The incident, replayed through the policy exactly as node.cpp wires it, over
// simulated time: a think() cycle every 5 s re-asks a wanted hash the pacer
// allows; an empty reply goes on to the next untried peer at once; the pacer
// backs off only when none is left. Nine peers: the advertiser and seven
// others never have the share; the holder has it but its first answer is
// empty (its tracker was busy). The holder must be asked again, and the
// fetch must succeed, well within the hour.
TEST(LtcParentFetchRotation, TheHolderIsReachedEvenWhenItFirstAnswersEmpty)
{
    const std::vector<std::string> peers{"adv", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "holder"};
    Rotation rot;
    Pacer pacer;
    int holder_asked = 0;
    double served_at = -1.0;
    std::vector<std::string> log;

    for (double t = 0.0; t < 3600.0 && served_at < 0.0; t += 5.0) {   // think() cycles
        if (!pacer.eligible("H", t))
            continue;
        double now = t;
        while (true) {   // one think-originated request and its at-once follow-ups
            const auto who = rot.choose("H", std::optional<std::string>{"adv"}, peers, now, first);
            ASSERT_TRUE(who.has_value());
            log.push_back(*who);
            if (*who == "holder" && ++holder_asked > 1) {   // busy the first time only
                served_at = now;
                rot.clear_hash("H");
                pacer.record_success("H");
                break;
            }
            now += 1.0;   // the empty reply's round trip
            if (!rot.record_failure("H", *who, peers, now)) {
                pacer.record_empty("H", now);
                break;
            }
        }
    }
    ASSERT_GE(served_at, 0.0) << "the share was never fetched; asked in order: " << log.size();
    EXPECT_LT(served_at, 1800.0) << "fetched only after " << served_at << " s";
    EXPECT_EQ(holder_asked, 2);
}

// The field case (sg-ltc, 2026-11-13): wanting 4f235083a8268106, sg-ltc asked
// its advertiser 92.53.224.27 for it 27 times, every 5 min, and voidbind twice,
// while these connections were up (two each from 31.25 and 66.151 and 92.53,
// three from 102.115.16.20, one from voidbind). With every peer answering empty
// except one, the first round asks EVERY connection, at once — 102.115.16.20's
// and voidbind's included — before the pacer backs off at all, and the
// advertiser is asked exactly once in it.
TEST(LtcParentFetchRotation, TheFieldPeerSetIsAskedInFullBeforeAnyBackoff)
{
    const std::string adv = "92.53.224.27:40001";
    const std::vector<std::string> peers{
        "31.25.0.1:40001", "31.25.0.1:40002",
        "102.115.16.20:40001", "102.115.16.20:40002", "102.115.16.20:40003",
        "voidbind:9326",
        "66.151.0.1:40001", "66.151.0.1:40002",
        adv, "92.53.224.27:40002"};

    for (const std::string& holder : {std::string("102.115.16.20:40003"), std::string("voidbind:9326")}) {
        SCOPED_TRACE("held by " + holder);
        Rotation rot;
        Pacer pacer;
        std::vector<std::string> asked;
        double now = 0.0;
        bool served = false;
        while (!served) {   // one think-originated request and its at-once follow-ups
            ASSERT_TRUE(pacer.eligible("H", now)) << "backed off before the holder was asked";
            const auto who = rot.choose("H", std::optional<std::string>{adv}, peers, now, first);
            ASSERT_TRUE(who.has_value());
            asked.push_back(*who);
            if (*who == holder) {
                served = true;
                break;
            }
            now += 1.0;
            if (!rot.record_failure("H", *who, peers, now))
                pacer.record_empty("H", now);
        }
        EXPECT_EQ(asked.front(), adv) << "the advertiser first";
        EXPECT_EQ(std::count(asked.begin(), asked.end(), adv), 1) << "and only once";
        EXPECT_LE(asked.size(), peers.size()) << "within the first round";
        EXPECT_EQ(pacer.attempts("H"), 0) << "no backoff on the way";
        EXPECT_LT(now, 15.0) << "seconds, not the pacer's minutes";
    }
}

// The wake gate itself: a host wakes once per 10 min of absence, and wakes are
// at least 30 s apart overall.
TEST(LtcParentFetchRotation, TheWakeGateAdmitsNewHostsOnlyAndSpacesThem)
{
    ltc::PeerWakeGate<std::string> gate;
    EXPECT_TRUE(gate.admit("10.0.0.1", 0.0)) << "a new host wakes";
    EXPECT_FALSE(gate.admit("10.0.0.1", 5.0)) << "its redial does not";
    EXPECT_FALSE(gate.admit("10.0.0.2", 10.0)) << "a new host within 30 s of the last wake does not";
    EXPECT_TRUE(gate.admit("10.0.0.3", 31.0)) << "a new host after 30 s does";
    // Flapping keeps the host seen: every redial refreshes it.
    for (double t = 100.0; t < 2000.0; t += 300.0)
        EXPECT_FALSE(gate.admit("10.0.0.1", t)) << t;
    EXPECT_TRUE(gate.admit("10.0.0.1", 1900.0 + 601.0)) << "back after 10 min away: a new source again";
    gate.prune(1e6);
    EXPECT_EQ(gate.tracked_hosts(), 0u);
}

