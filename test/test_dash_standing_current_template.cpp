// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH standing remembered set == the CURRENT template — issue #950, ruling F1.
//
// Canonical p2pool-dash keeps, per peer, a STANDING remembered set that is
// exactly its current mining-tx set:
//
//   handshake   p2p.py:267-269  remember_tx(tx_hashes=[], txs=mining_txs)
//   transition  p2p.py:254-264  forget_tx(removed); remember_tx(added), by hash
//                               when the peer advertised it, else as a body (:263)
//   accounting  p2p.py:78/:259-268/:379-382/:390  remote_remembered_txs_size
//
// and the receiver enforces it (p2p.py:447-497): a hash remembered twice or a
// hash-only entry it cannot resolve disconnects (:448-451, :464, :473-476), a
// forget of a hash it does not hold is a KeyError (:495), and reaching
// max_remembered_txs_size = 2 500 000 (:30) raises PeerMisbehavingError (:488,
// `>=`). Before F1, c2pool seeded the set ONCE at handshake from the retained
// m_known_txs window (old templates + txs peers remembered to us) and never
// updated it, so it went stale by design, and it tracked no remote size at all.
//
// Each test drives the REAL dash::Node / NodeImpl (register_template_txs,
// handle_version, send_shares, and the REAL Legacy have_tx / remember_tx ingest
// handlers), a REAL dash::Peer over a REAL core::Socket on a loopback TCP pair,
// and decodes the exact frames the node put on the wire. The far end is
// `CanonicalPeer`: a byte-level model of the canonical RECEIVER above, fed those
// decoded frames, recording every condition on which canonical would disconnect
// or raise. That model, and the tx sizing it uses (100 + packed size, computed
// here from the bytes), are the only test-side stand-ins; nothing in the node is
// mocked. The only harness stub is the ICommunicator error sink core::Socket
// needs. Shares are hand-built (send_shares reads only m_new_transaction_hashes).
//
// FAILING-FIRST: this file deliberately compiles against the pre-F1 tree (the
// per-peer remote-size counter is read through a requires-probe, and the
// standing set only through count()/size()), so its red run on unfixed code is
// a real assertion failure, not a build break.
//
// FOLDED into the EXISTING allowlisted `test_dash_node` target (the #769 trap:
// a standalone add_executable is never built by CI and reports "Not Run").

#include "dash_socket_harness.hpp"

#include <impl/dash/node.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/messages.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace dash_socket_harness;
using namespace std::chrono_literals;
using MTx = dash::coin::MutableTransaction;

constexpr std::size_t kCap = 2500000;   // canonical max_remembered_txs_size, p2p.py:30

// ── txs ─────────────────────────────────────────────────────────────────────
MTx make_tx(std::uint32_t salt, std::size_t script_len = 0)
{
    MTx tx;
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
    out.scriptPubKey.m_data.assign(script_len, 0x6a);
    tx.vout.push_back(out);
    return tx;
}

uint256 txid(const MTx& tx)
{
    auto ps = ::pack(tx);
    return ::Hash(ps.get_span());
}

// Canonical per-entry charge, 100 + packed_size(tx) (sender p2p.py:259/:261/
// :267/:379, receiver :469/:485) — computed HERE from the serialized bytes,
// independently of the node's own sizer.
std::size_t charge(const MTx& tx)
{
    return 100 + ::pack(tx).get_span().size();
}

// A tx whose canonical charge is EXACTLY `target`.
MTx make_tx_charged(std::uint32_t salt, std::size_t target)
{
    std::size_t len = 0;
    for (int i = 0; i < 16; ++i) {
        MTx tx = make_tx(salt, len);
        const std::size_t c = charge(tx);
        if (c == target)
            return tx;
        if (c < target)
            len += target - c;
        else if (len > 0)
            len -= std::min(len, c - target);
        else
            break;
    }
    ADD_FAILURE() << "fixture: could not size tx " << salt << " to a charge of " << target;
    return make_tx(salt, len);
}

std::set<uint256> ids(const std::vector<MTx>& txs)
{
    std::set<uint256> out;
    for (const auto& t : txs)
        out.insert(txid(t));
    return out;
}

// ── wire decoding ───────────────────────────────────────────────────────────
struct RememberMsg {
    std::vector<uint256> hashes;
    std::vector<MTx> txs;
};

RememberMsg decode_remember(const Frame& f)
{
    PackStream ps(std::span<const std::byte>(f.payload.data(), f.payload.size()));
    auto m = dash::message_remember_tx::make(ps);
    return {m->m_tx_hashes, m->m_txs};
}

std::vector<uint256> decode_forget(const Frame& f)
{
    PackStream ps(std::span<const std::byte>(f.payload.data(), f.payload.size()));
    return dash::message_forget_tx::make(ps)->m_tx_hashes;
}

std::vector<const Frame*> frames_of(const std::vector<Frame>& fs, std::string_view cmd)
{
    std::vector<const Frame*> out;
    for (const auto& f : fs)
        if (f.command == cmd)
            out.push_back(&f);
    return out;
}

std::ptrdiff_t index_of(const std::vector<Frame>& fs, std::string_view cmd)
{
    for (std::size_t i = 0; i < fs.size(); ++i)
        if (fs[i].command == cmd)
            return static_cast<std::ptrdiff_t>(i);
    return -1;
}

// Reads the far end of the loopback pair until it has been quiet for `quiet`,
// then returns every COMPLETE frame. Unlike the shared read_frames(), a frame
// still in flight is carried over to the next drain instead of being dropped,
// so a ~2.5 MB seed cannot desynchronise the stream between test steps.
struct WireTap
{
    tcp::socket& s;
    std::vector<std::byte> buf;

    explicit WireTap(tcp::socket& sock) : s(sock) { s.non_blocking(true); }

    std::vector<Frame> drain(std::chrono::milliseconds quiet = 300ms,
                             std::chrono::milliseconds limit = 15s)
    {
        const auto start = std::chrono::steady_clock::now();
        auto last = start;
        std::array<std::byte, 65536> chunk{};
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            if (now - last >= quiet || now - start >= limit)
                break;
            boost::system::error_code ec;
            const std::size_t n = s.read_some(boost::asio::buffer(chunk), ec);
            if (n > 0) {
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
                last = std::chrono::steady_clock::now();
            } else if (ec == boost::asio::error::would_block ||
                       ec == boost::asio::error::try_again) {
                std::this_thread::sleep_for(2ms);
            } else if (ec) {
                break;
            }
        }

        std::vector<Frame> frames;
        const auto& prefix = test_prefix();
        const std::size_t header = prefix.size() + kCommandLen + kLengthLen + kChecksumLen;
        std::size_t off = 0;
        while (off + header <= buf.size()) {
            if (std::memcmp(buf.data() + off, prefix.data(), prefix.size()) != 0) {
                ADD_FAILURE() << "wire tap lost frame sync at offset " << off;
                buf.clear();
                return frames;
            }
            const auto* cmd = reinterpret_cast<const char*>(buf.data() + off + prefix.size());
            std::string command(cmd, kCommandLen);
            if (const auto z = command.find('\0'); z != std::string::npos)
                command.resize(z);
            std::uint32_t len = 0;
            std::memcpy(&len, buf.data() + off + prefix.size() + kCommandLen, kLengthLen);
            if (off + header + len > buf.size())
                break;   // in flight: keep for the next drain
            Frame f;
            f.command = std::move(command);
            f.payload.assign(buf.begin() + off + header, buf.begin() + off + header + len);
            frames.push_back(std::move(f));
            off += header + len;
        }
        buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(off));
        return frames;
    }
};

// ── the canonical receiver ──────────────────────────────────────────────────
// p2pool-dash p2p.py handle_remember_tx (:447-489) / handle_forget_tx (:493-497)
// for ONE connection, fed the frames our node wrote. Every point at which
// canonical would disconnect or raise is recorded as a violation instead.
struct CanonicalPeer
{
    std::map<uint256, std::size_t> known;       // its known_txs: resolves hash-only entries
    std::map<uint256, std::size_t> remembered;  // remembered_txs (this connection)
    std::size_t size = 0;                        // remembered_txs_size
    std::size_t peak = 0;
    std::vector<std::string> violations;

    void learn(const MTx& tx) { known[txid(tx)] = charge(tx); }

    void on_remember(const Frame& f)
    {
        const auto m = decode_remember(f);
        for (const auto& h : m.hashes) {
            if (remembered.count(h)) {
                violations.push_back("remember_tx hash referenced twice (p2p.py:448-451) " + h.GetHex());
                continue;
            }
            const auto k = known.find(h);
            if (k == known.end()) {
                violations.push_back("remember_tx hash of an unknown tx (p2p.py:464) " + h.GetHex());
                continue;
            }
            remembered.emplace(h, k->second);
            size += k->second;
        }
        for (const auto& tx : m.txs) {
            const uint256 h = txid(tx);
            const std::size_t c = charge(tx);
            if (remembered.count(h)) {
                violations.push_back("remember_tx body referenced twice (p2p.py:473-476) " + h.GetHex());
                continue;
            }
            remembered.emplace(h, c);
            size += c;
            known[h] = c;
        }
        peak = std::max(peak, size);
        if (size >= kCap)
            violations.push_back("too much transaction data stored: " + std::to_string(size) +
                                 " >= " + std::to_string(kCap) + " (p2p.py:488)");
    }

    void on_forget(const Frame& f)
    {
        for (const auto& h : decode_forget(f)) {
            const auto it = remembered.find(h);
            if (it == remembered.end()) {
                violations.push_back("forget_tx of a hash it does not hold: KeyError (p2p.py:495) " +
                                     h.GetHex());
                continue;
            }
            size -= it->second;
            remembered.erase(it);
        }
    }

    void consume(const std::vector<Frame>& frames)
    {
        for (const auto& f : frames) {
            if (f.command == "remember_tx")
                on_remember(f);
            else if (f.command == "forget_tx")
                on_forget(f);
        }
    }

    std::set<uint256> holds() const
    {
        std::set<uint256> out;
        for (const auto& [h, c] : remembered)
            out.insert(h);
        return out;
    }

    std::string report() const
    {
        std::string out;
        for (const auto& v : violations)
            out += "\n  " + v;
        return out.empty() ? std::string(" (none)") : out;
    }
};

// ── node-side probes ────────────────────────────────────────────────────────
// Per-peer tracked remote size (#950 F1, dash::Peer::m_remote_remembered_size),
// read through a requires-probe so this file also compiles against the pre-F1
// tree, where the member does not exist: there the probe is nullopt and the
// assertion that wants a value fails (that is the red run).
template <typename P>
std::optional<std::size_t> tracked_remote_size(const P& p)
{
    if constexpr (requires { p.m_remote_remembered_size; })
        return static_cast<std::size_t>(p.m_remote_remembered_size);
    else
        return std::nullopt;
}

// The standing set holds exactly `want` (count()/size() only, so it reads the
// pre-F1 std::set and the F1 std::map alike).
template <typename P>
::testing::AssertionResult standing_is(const P& p, const std::set<uint256>& want)
{
    for (const auto& h : want)
        if (!p.m_standing_remembered.count(h))
            return ::testing::AssertionFailure() << "standing set lacks " << h.GetHex();
    if (p.m_standing_remembered.size() != want.size())
        return ::testing::AssertionFailure()
               << "standing set holds " << p.m_standing_remembered.size()
               << " hash(es), want exactly " << want.size();
    return ::testing::AssertionSuccess();
}

struct StandingNode : dash::Node
{
    StandingNode(boost::asio::io_context* ctx, dash::Config* cfg)
        : dash::NodeImpl(ctx, cfg), dash::Node(ctx, cfg) {}
    dash::NodeImpl& impl() { return *this; }
    dash::Legacy& legacy() { return *this; }
};

struct Rig
{
    LoopbackPair pair;
    StubCommunicator stub;
    dash::Config cfg;
    std::unique_ptr<StandingNode> node;
    dash::NodeImpl::peer_ptr peer;
    std::unique_ptr<IoThread> io;
    std::unique_ptr<WireTap> tap;
    CanonicalPeer far;

    explicit Rig(const char* name) : cfg{name}
    {
        cfg.pool()->m_prefix = test_prefix();
        node = std::make_unique<StandingNode>(&pair.ioc_node, &cfg);
        peer = make_socket_peer(pair, stub);
        io = std::make_unique<IoThread>(pair.ioc_node);
        tap = std::make_unique<WireTap>(*pair.theirs);
    }
    ~Rig()
    {
        io->stop(pair.ioc_node);
        peer.reset();
        node.reset();
    }

    dash::NodeImpl& n() { return node->impl(); }

    void reg(const std::vector<MTx>& txs)
    {
        std::vector<dash::coin::Transaction> t;
        std::vector<uint256> h;
        for (const auto& x : txs) {
            t.emplace_back(x);
            h.push_back(txid(x));
        }
        n().register_template_txs(t, h);
    }

    bool handshake(std::uint64_t nonce)
    {
        return n().handle_version(make_version(nonce, "c2pool-dash-950-f1-kat"), peer).has_value();
    }

    uint256 add_share(std::uint64_t id, std::vector<uint256> refs)
    {
        auto* share = new dash::DashShare();
        share->m_hash = uint256(id);
        share->m_new_transaction_hashes = std::move(refs);
        dash::ShareType st;
        st = share;
        n().tracker().add(st);
        return uint256(id);
    }

    // Everything the node wrote since the last step, also fed to the receiver.
    std::vector<Frame> step()
    {
        auto f = tap->drain();
        far.consume(f);
        return f;
    }
};

} // namespace

// (a) Transition exactness. Canonical p2p.py:254-264: forget_tx exactly the
// hashes that LEFT, remember_tx the ones that ARRIVED — a HASH when the peer
// advertised the tx (have_tx -> remote_tx_hashes), a BODY otherwise (:263) — and
// nothing at all when the same template is registered again (Variable.set is a
// no-op on an equal value, util/variable.py:73-75; c2pool re-registers one
// template once per payout script).
TEST(DashStandingCurrentTemplate, TransitionForgetsLeaversAndRemembersArrivalsExactly)
{
    Rig rig("dash-950f1-transition-kat");
    const MTx a = make_tx(0xA1), b = make_tx(0xB2), c = make_tx(0xC3),
              d = make_tx(0xD4), e = make_tx(0xE5);

    rig.reg({a, b, c});
    ASSERT_TRUE(rig.handshake(0x950F'1A00'0000'0001ull));
    const auto seed = rig.step();
    ASSERT_EQ(frames_of(seed, "remember_tx").size(), 1u) << "handshake must emit ONE standing seed";
    EXPECT_EQ(ids(decode_remember(*frames_of(seed, "remember_tx")[0]).txs), ids({a, b, c}));

    // The peer advertises d through the REAL Legacy have_tx handler, i.e. it
    // already holds d in its own known_txs, so canonical sends d by hash.
    rig.far.learn(d);
    rig.node->legacy().handle_message(
        dash::message_have_tx::make_raw(std::vector<uint256>{txid(d)}), rig.peer);
    ASSERT_TRUE(rig.peer->m_remote_txs.count(txid(d))) << "harness sanity: have_tx ingest";
    rig.step();

    rig.reg({b, c, d, e});
    const auto t2 = rig.step();
    const auto forgets = frames_of(t2, "forget_tx");
    const auto remembers = frames_of(t2, "remember_tx");
    ASSERT_EQ(forgets.size(), 1u)
        << "#950 F1: a template transition must forget_tx the hashes that LEFT the "
           "template (canonical p2p.py:257-259); the standing set was never updated";
    ASSERT_EQ(remembers.size(), 1u)
        << "#950 F1: a template transition must remember_tx the ARRIVALS (p2p.py:260-263)";
    const auto fgot = decode_forget(*forgets[0]);
    EXPECT_EQ(std::set<uint256>(fgot.begin(), fgot.end()), std::set<uint256>{txid(a)})
        << "forget exactly the leaver, never a hash that stays";
    EXPECT_EQ(fgot.size(), 1u);
    const auto rem = decode_remember(*remembers[0]);
    EXPECT_EQ(std::set<uint256>(rem.hashes.begin(), rem.hashes.end()), std::set<uint256>{txid(d)})
        << "an arrival the peer advertised goes by HASH (p2p.py:263)";
    EXPECT_EQ(ids(rem.txs), ids({e})) << "an arrival the peer did not advertise goes as a BODY";
    EXPECT_LT(index_of(t2, "forget_tx"), index_of(t2, "remember_tx"))
        << "canonical order: forget the leavers, then remember the arrivals";

    EXPECT_TRUE(rig.far.violations.empty()) << "canonical receiver:" << rig.far.report();
    EXPECT_EQ(rig.far.holds(), ids({b, c, d, e}));
    EXPECT_TRUE(standing_is(*rig.peer, ids({b, c, d, e})));
    const auto tracked = tracked_remote_size(*rig.peer);
    ASSERT_TRUE(tracked.has_value()) << "#950 F1: no per-peer remote remembered-size accounting "
                                        "(canonical remote_remembered_txs_size, p2p.py:78)";
    EXPECT_EQ(*tracked, rig.far.size) << "tracked size must equal what the receiver counts";
    EXPECT_EQ(*tracked, charge(b) + charge(c) + charge(d) + charge(e));

    // Identical template again (same order, then permuted): no wire traffic.
    rig.reg({b, c, d, e});
    rig.reg({e, d, c, b});
    const auto again = rig.step();
    EXPECT_TRUE(frames_of(again, "remember_tx").empty() && frames_of(again, "forget_tx").empty())
        << "re-registering the identical template (identity = tx-hash set) must be a no-op";
    EXPECT_TRUE(standing_is(*rig.peer, ids({b, c, d, e})));
    EXPECT_TRUE(rig.far.violations.empty()) << "canonical receiver:" << rig.far.report();
}

// (b) Handshake seed = the CURRENT template only, all as bodies (canonical
// p2p.py:267-269, tx_hashes=[]). NOT an older template still retained in
// m_known_txs, and NOT a tx another peer remembered to us (real Legacy
// remember_tx ingest, protocol_legacy.cpp).
TEST(DashStandingCurrentTemplate, HandshakeSeedIsCurrentTemplateOnly)
{
    Rig rig("dash-950f1-seed-kat");
    const MTx old = make_tx(0x01D), cur1 = make_tx(0xC01), cur2 = make_tx(0xC02),
              inbound = make_tx(0x1B0);

    rig.reg({old});
    rig.reg({cur1, cur2});

    // A different peer remembers `inbound` to us: it lands in m_known_txs.
    LoopbackPair pair2;
    StubCommunicator stub2;
    auto other = make_socket_peer(pair2, stub2);
    rig.node->legacy().handle_message(
        dash::message_remember_tx::make_raw(std::vector<uint256>{}, std::vector<MTx>{inbound}),
        other);
    ASSERT_TRUE(other->m_remembered_txs.count(txid(inbound))) << "harness sanity: remember_tx ingest";

    ASSERT_TRUE(rig.handshake(0x950F'1B00'0000'0001ull));
    const auto hs = rig.step();
    const auto seeds = frames_of(hs, "remember_tx");
    ASSERT_EQ(seeds.size(), 1u) << "handshake must emit ONE standing seed";
    const auto seed = decode_remember(*seeds[0]);
    EXPECT_TRUE(seed.hashes.empty()) << "the seed is all bodies (p2p.py:269 tx_hashes=[])";
    EXPECT_EQ(ids(seed.txs), ids({cur1, cur2}))
        << "#950 F1: the standing seed must be the CURRENT template only — not the "
           "retained m_known_txs window (old template / inbound-remembered txs)";
    EXPECT_FALSE(ids(seed.txs).count(txid(old))) << "seeded a tx of an OLDER template";
    EXPECT_FALSE(ids(seed.txs).count(txid(inbound))) << "seeded a tx another PEER remembered to us";

    EXPECT_TRUE(rig.far.violations.empty()) << "canonical receiver:" << rig.far.report();
    EXPECT_TRUE(standing_is(*rig.peer, ids({cur1, cur2})));
    const auto tracked = tracked_remote_size(*rig.peer);
    ASSERT_TRUE(tracked.has_value()) << "#950 F1: no per-peer remote remembered-size accounting";
    EXPECT_EQ(*tracked, charge(cur1) + charge(cur2));
    EXPECT_EQ(*tracked, rig.far.size);

    // The retained window itself is untouched: the have_tx advert still offers
    // the old-template and inbound txs (canonical advertises known_txs, p2p.py:276).
    const auto adverts = frames_of(hs, "have_tx");
    ASSERT_FALSE(adverts.empty()) << "harness sanity: handshake have_tx advert";
    const auto advertises = [&](const uint256& h) {
        const auto* p = reinterpret_cast<const std::byte*>(h.data());
        return std::search(adverts[0]->payload.begin(), adverts[0]->payload.end(), p, p + 32) !=
               adverts[0]->payload.end();
    };
    EXPECT_TRUE(advertises(txid(old))) << "retained old-template tx must still be advertised";
    EXPECT_TRUE(advertises(txid(inbound))) << "inbound-remembered tx must still be advertised";
}

// (c1) Remote-size cap on the send_shares bracket (canonical sendShares
// p2p.py:379-382 refuses the whole batch). Seed the peer to 2 490 000 of
// 2 500 000, then: a bracket that would overshoot is refused; one that would land
// EXACTLY on the cap is refused too (receiver `>=`, p2p.py:488 — canonical's
// sender `>` at :380 would send it and be disconnected); one that fits goes out
// with its full bracket and the peer never reaches the cap.
TEST(DashStandingCurrentTemplate, BracketThatWouldReachPeerCapIsRefused)
{
    Rig rig("dash-950f1-cap-bracket-kat");

    std::vector<MTx> fillers;
    for (std::uint32_t i = 0; i < 24; ++i)
        fillers.push_back(make_tx_charged(0xF000 + i, 100000));
    fillers.push_back(make_tx_charged(0xF0FF, 90000));   // seed total 2 490 000
    const MTx over = make_tx_charged(0x0B16, 20000);     // 2 510 000 > cap
    const MTx edge = make_tx_charged(0x0ED6, 10000);     // 2 500 000 == cap
    const MTx fits = make_tx_charged(0x0F17, 5000);      // 2 495 000 < cap

    rig.reg(fillers);
    ASSERT_TRUE(rig.handshake(0x950F'1C00'0000'0001ull));
    const auto hs = rig.step();
    ASSERT_EQ(frames_of(hs, "remember_tx").size(), 1u);
    EXPECT_EQ(ids(decode_remember(*frames_of(hs, "remember_tx")[0]).txs), ids(fillers));
    ASSERT_EQ(rig.far.size, kCap - 10000) << "fixture: seed must leave exactly 10 000 B of room";

    // The template flaps to another set and back, so over/edge/fits end up in
    // the retained window (backable) but NOT current, and the peer again holds
    // exactly the fillers. (Registered after the handshake so the start state is
    // the same on the pre-F1 tree, whose seed drew on the whole retained window.)
    rig.reg({over, edge, fits});
    rig.reg(fillers);
    rig.step();
    EXPECT_TRUE(standing_is(*rig.peer, ids(fillers)));
    ASSERT_EQ(rig.far.size, kCap - 10000) << "fixture: back to exactly 10 000 B of room";
    const auto tracked0 = tracked_remote_size(*rig.peer);
    EXPECT_TRUE(tracked0.has_value()) << "#950 F1: no per-peer remote remembered-size accounting";
    if (tracked0)
        EXPECT_EQ(*tracked0, kCap - 10000);

    const uint256 s_over = rig.add_share(0x950F1C01u, {txid(over)});
    const uint256 s_edge = rig.add_share(0x950F1C02u, {txid(edge)});
    const uint256 s_fits = rig.add_share(0x950F1C03u, {txid(fits)});

    EXPECT_TRUE(rig.n().send_shares(rig.peer, {s_over}).empty())
        << "#950 F1: a bracket pushing the peer past its cap must be refused "
           "(canonical sendShares raises, p2p.py:380-381) and report no hash sent";
    const auto f_over = rig.step();
    EXPECT_TRUE(f_over.empty()) << "refused: NOTHING may reach the peer, got " << f_over.size()
                                << " frame(s)";

    EXPECT_TRUE(rig.n().send_shares(rig.peer, {s_edge}).empty())
        << "#950 F1: a bracket landing EXACTLY on the cap must be refused — the "
           "receiver raises at >= (p2p.py:488)";
    const auto f_edge = rig.step();
    EXPECT_TRUE(f_edge.empty()) << "refused: NOTHING may reach the peer, got " << f_edge.size()
                                << " frame(s)";

    const auto sent = rig.n().send_shares(rig.peer, {s_fits});
    EXPECT_EQ(sent, std::vector<uint256>{s_fits}) << "a bracket that fits must go out";
    const auto f_fits = rig.step();
    ASSERT_EQ(frames_of(f_fits, "remember_tx").size(), 1u);
    ASSERT_EQ(frames_of(f_fits, "forget_tx").size(), 1u);
    EXPECT_EQ(ids(decode_remember(*frames_of(f_fits, "remember_tx")[0]).txs), ids({fits}));
    EXPECT_EQ(decode_forget(*frames_of(f_fits, "forget_tx")[0]), std::vector<uint256>{txid(fits)});
    EXPECT_NE(index_of(f_fits, "shares"), -1);

    EXPECT_TRUE(rig.far.violations.empty()) << "canonical receiver:" << rig.far.report();
    EXPECT_LT(rig.far.peak, kCap) << "the peer must never reach its cap";
    EXPECT_EQ(rig.far.peak, kCap - 5000);
    EXPECT_EQ(rig.far.size, kCap - 10000) << "bracket fully forgotten again";
    const auto tracked = tracked_remote_size(*rig.peer);
    ASSERT_TRUE(tracked.has_value());
    EXPECT_EQ(*tracked, kCap - 10000);
    EXPECT_LT(*tracked, kCap);
}

// (c2) An arrival that does not fit under the cap is SKIPPED — kept out of the
// standing set, so a later transition never forgets it (forgetting a hash the
// peer does not hold is a KeyError, p2p.py:495). Canonical asserts instead
// (p2p.py:262); that is the documented divergence. Skip-and-continue: a smaller
// arrival behind it in template order still fits. A skipped tx is retried at the
// next transition once room frees up.
TEST(DashStandingCurrentTemplate, ArrivalOverCapIsSkippedAndNeverForgotten)
{
    Rig rig("dash-950f1-cap-arrival-kat");

    std::vector<MTx> fillers;
    for (std::uint32_t i = 0; i < 24; ++i)
        fillers.push_back(make_tx_charged(0xE000 + i, 100000));
    fillers.push_back(make_tx_charged(0xE0FF, 90000));   // 2 490 000
    const MTx huge = make_tx_charged(0x4A6E, 20000);
    const MTx small = make_tx_charged(0x5A11, 5000);

    rig.reg(fillers);
    ASSERT_TRUE(rig.handshake(0x950F'1D00'0000'0001ull));
    rig.step();
    ASSERT_EQ(rig.far.size, kCap - 10000) << "fixture: 10 000 B of room";

    auto t2 = fillers;
    t2.push_back(huge);    // first in template order, does not fit
    t2.push_back(small);   // fits behind it
    rig.reg(t2);
    const auto f2 = rig.step();
    EXPECT_TRUE(frames_of(f2, "forget_tx").empty()) << "nothing left the template";
    ASSERT_EQ(frames_of(f2, "remember_tx").size(), 1u)
        << "#950 F1: the arrival that fits must be remembered at the transition";
    const auto r2 = decode_remember(*frames_of(f2, "remember_tx")[0]);
    EXPECT_EQ(ids(r2.txs), ids({small})) << "remember the arrival that fits, skip the one that does not";
    EXPECT_TRUE(r2.hashes.empty());
    EXPECT_FALSE(rig.peer->m_standing_remembered.count(txid(huge)))
        << "a skipped arrival must stay OUT of the standing set";
    EXPECT_TRUE(rig.peer->m_standing_remembered.count(txid(small)));
    EXPECT_LT(rig.far.peak, kCap);

    rig.reg(fillers);   // huge and small both leave
    const auto f3 = rig.step();
    ASSERT_EQ(frames_of(f3, "forget_tx").size(), 1u) << "the standing arrival that left is forgotten";
    EXPECT_EQ(decode_forget(*frames_of(f3, "forget_tx")[0]), std::vector<uint256>{txid(small)})
        << "forget exactly what the peer holds — never the skipped tx";
    EXPECT_TRUE(frames_of(f3, "remember_tx").empty());
    EXPECT_TRUE(standing_is(*rig.peer, ids(fillers)));

    // Room frees up (a 100 000 B filler leaves): the skipped tx now fits.
    std::vector<MTx> t4(fillers.begin() + 1, fillers.end());
    t4.push_back(huge);
    rig.reg(t4);
    const auto f4 = rig.step();
    ASSERT_EQ(frames_of(f4, "forget_tx").size(), 1u);
    EXPECT_EQ(decode_forget(*frames_of(f4, "forget_tx")[0]), std::vector<uint256>{txid(fillers[0])});
    ASSERT_EQ(frames_of(f4, "remember_tx").size(), 1u);
    EXPECT_EQ(ids(decode_remember(*frames_of(f4, "remember_tx")[0]).txs), ids({huge}));

    EXPECT_TRUE(rig.far.violations.empty()) << "canonical receiver:" << rig.far.report();
    EXPECT_LT(rig.far.peak, kCap);
    const auto tracked = tracked_remote_size(*rig.peer);
    ASSERT_TRUE(tracked.has_value()) << "#950 F1: no per-peer remote remembered-size accounting";
    EXPECT_EQ(*tracked, rig.far.size);
    EXPECT_TRUE(standing_is(*rig.peer, ids(t4)));
}

// (d) The bracket's closing forget_tx never removes a standing hash, including
// when a template change lands BETWEEN two send_shares calls — in both
// directions: b ENTERS the standing set (must leave the bracket: re-remembering
// it is "referenced twice", p2p.py:473-476; forgetting it erases it) and a
// LEAVES it (must now be bracketed: the peer no longer holds it).
TEST(DashStandingCurrentTemplate, BracketNeverForgetsStandingAcrossTemplateChange)
{
    Rig rig("dash-950f1-bracket-transition-kat");
    const MTx a = make_tx(0xAA01), b = make_tx(0xBB02), x = make_tx(0xCC03);

    rig.reg({a, x});
    ASSERT_TRUE(rig.handshake(0x950F'1E00'0000'0001ull));
    rig.step();
    // Template flaps to {b} and back: b is retained (backable) but not current.
    // (After the handshake, so the start state is the same on the pre-F1 tree.)
    rig.reg({b});
    rig.reg({a, x});
    rig.step();
    ASSERT_TRUE(standing_is(*rig.peer, ids({a, x})));

    // Send 1: a standing, b not.
    const uint256 s1 = rig.add_share(0x950F1E01u, {txid(a), txid(b)});
    ASSERT_EQ(rig.n().send_shares(rig.peer, {s1}), std::vector<uint256>{s1});
    const auto f1 = rig.step();
    ASSERT_EQ(frames_of(f1, "forget_tx").size(), 1u);
    const auto fg1 = decode_forget(*frames_of(f1, "forget_tx")[0]);
    EXPECT_EQ(fg1, std::vector<uint256>{txid(b)});
    for (const auto& h : fg1)
        EXPECT_FALSE(rig.peer->m_standing_remembered.count(h)) << "send 1 forgot a STANDING hash";

    // Template change between the sends: a leaves, b enters. (Non-fatal checks,
    // so the send-2 property below is exercised even where this part fails.)
    rig.reg({b, x});
    const auto ft = rig.step();
    const auto ft_forget = frames_of(ft, "forget_tx");
    const auto ft_remember = frames_of(ft, "remember_tx");
    EXPECT_EQ(ft_forget.size(), 1u) << "#950 F1: the transition must forget the standing hash that left";
    if (!ft_forget.empty())
        EXPECT_EQ(decode_forget(*ft_forget[0]), std::vector<uint256>{txid(a)});
    EXPECT_EQ(ft_remember.size(), 1u) << "#950 F1: the transition must remember the arrival";
    if (!ft_remember.empty())
        EXPECT_EQ(ids(decode_remember(*ft_remember[0]).txs), ids({b}));
    EXPECT_TRUE(standing_is(*rig.peer, ids({b, x})));

    // Send 2: b is standing now, a is not.
    const uint256 s2 = rig.add_share(0x950F1E02u, {txid(a), txid(b)});
    ASSERT_EQ(rig.n().send_shares(rig.peer, {s2}), std::vector<uint256>{s2});
    const auto f2 = rig.step();
    ASSERT_EQ(frames_of(f2, "forget_tx").size(), 1u);
    const auto fg2 = decode_forget(*frames_of(f2, "forget_tx")[0]);
    EXPECT_EQ(fg2, std::vector<uint256>{txid(a)})
        << "#950 F1: after the transition the bracket must carry the LEAVER a and "
           "never the ENTRANT b";
    EXPECT_FALSE(std::count(fg2.begin(), fg2.end(), txid(b)))
        << "#950 F1: send 2's forget_tx removed b, which ENTERED the standing set "
           "between the sends — the peer loses a tx it should keep";
    for (const auto& h : fg2)
        EXPECT_FALSE(rig.peer->m_standing_remembered.count(h)) << "send 2 forgot a STANDING hash";
    ASSERT_EQ(frames_of(f2, "remember_tx").size(), 1u);
    EXPECT_EQ(ids(decode_remember(*frames_of(f2, "remember_tx")[0]).txs), ids({a}))
        << "the bracket must not re-remember the standing entrant b (p2p.py:473-476)";

    EXPECT_TRUE(rig.far.violations.empty()) << "canonical receiver:" << rig.far.report();
    EXPECT_EQ(rig.far.holds(), ids({b, x})) << "after both sends the peer holds the standing set only";
    const auto tracked = tracked_remote_size(*rig.peer);
    ASSERT_TRUE(tracked.has_value()) << "#950 F1: no per-peer remote remembered-size accounting";
    EXPECT_EQ(*tracked, rig.far.size);
}
