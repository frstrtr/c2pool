// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH incoming-share pre-checks (#1828): cheap caps and field checks that run
// BEFORE any hashing on the share receive path.
//
// What is pinned (every behavioural KAT counts X11 calls through a wrapped
// CoinParams::pow_func installed on the node's tracker, so "dropped before
// X11" is measured, not inferred):
//   1. The per-message caps run in all four receive handlers (Actual / Legacy
//      x 'shares' / 'sharereply') before a share is parsed: an oversize v36
//      share, a 'shares' message over the v36 count cap, a public 'shares'
//      message over the oracle 3145728-byte payload cap and a 'sharereply'
//      over the v36 count cap are dropped with zero X11 calls; the pending
//      share request of a dropped reply resolves EMPTY at once.
//   2. Honest-size traffic is untouched: 5 v36 shares in one 'shares', a
//      9-share 'sharereply', and a public v16 share through the Legacy
//      handler are all verified and inserted.
//   3. The no-hashing field checks in share_init_verify: merkle branch > 16
//      (data.py:318-319), broken transaction_hash_refs (data.py:335-340), v36
//      message_data > 561 bytes, v36 pubkey_type != 0 and non-empty merged
//      fields all throw with zero X11 calls; the v16 producer's own share and
//      an honest v36 share still pass.
//   4. Sender side: a 'sharereply' over the oracle payload cap is answered
//      'too long' by both sharereq handlers (p2pool/p2p.py:399-404 parity).
//   5. Pins: the minimal v16 RawShare size behind the public count cap, the
//      exact payload arithmetic, the profile numbers, the drop counters, and
//      no ban on a drop (graded bans are #1829).
//
// Red on the base revision: build this TU with DASH_PRECHECK_BASE_REVISION
// defined (it fences out the pins, which name new symbols); every behavioural
// KAT except the honest-traffic guards fails there.
//
// Folded into test_dash_node (needs dash::Node + c2pool_storage).

#include <gtest/gtest.h>

#include "dash_v36_mint_fixture.hpp"   // LiveNode idiom, mine_v16/mine_v36, LoopbackPair, ...

#ifndef DASH_PRECHECK_BASE_REVISION
#include <impl/dash/share_precheck.hpp>
#endif
#include <impl/dash/messages.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

// ── counting X11 ─────────────────────────────────────────────────────────────
struct PowCounter {
    std::shared_ptr<std::atomic<int>> calls = std::make_shared<std::atomic<int>>(0);
    core::CoinParams wrap(core::CoinParams p) const {
        auto inner = p.pow_func;
        auto c = calls;
        p.pow_func = [inner, c](std::span<const unsigned char> h) {
            c->fetch_add(1);
            return inner(h);
        };
        return p;
    }
    int n() const { return calls->load(); }
};

// ── a real dash::Node (Legacy + Actual dispatch) over its own LevelDB ─────────
struct BridgeProbe : dash::Node {
    BridgeProbe(boost::asio::io_context* ctx, dash::Config* cfg)
        : dash::NodeImpl(ctx, cfg), dash::Node(ctx, cfg) {}
    void hold_think_slot(bool hold) { m_think_running.store(hold); if (!hold) m_rethink_pending.store(false); }
};

struct Rig {
    boost::asio::io_context ioc;
    dash::Config cfg{"dash-precheck-kat"};
    LoopbackPair pair;
    StubCommunicator stub;
    PowCounter pow;
    std::unique_ptr<BridgeProbe> node;
    dash::NodeImpl::peer_ptr peer;

    Rig(const core::CoinParams& p, const std::string& sub)
    {
        node = std::make_unique<BridgeProbe>(&ioc, &cfg);
        node->tracker().m_coin_params = pow.wrap(p);
        fs::create_directories(core::filesystem::config_path() / sub);
        node->init_storage(sub);
        node->hold_think_slot(true);   // observe the receive path alone
        peer = make_socket_peer(pair, stub);
    }
    ~Rig()
    {
        node->join_compute_pools();
        node->hold_think_slot(false);
        node->shutdown_persistence();
        peer.reset();
        node.reset();
    }

    dash::Actual& actual() { return static_cast<dash::Actual&>(*node); }
    dash::Legacy& legacy() { return static_cast<dash::Legacy&>(*node); }

    // Run the io_context (verify-pool completions hop back here) for a while.
    void pump(int ms = 300)
    {
        const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < end) {
            ioc.restart();
            ioc.run_for(std::chrono::milliseconds(10));
        }
    }

    template <typename Pred>
    bool pump_until(Pred&& pred)
    {
        for (int i = 0; i < 400; ++i) {
            ioc.restart();
            ioc.run_for(std::chrono::milliseconds(20));
            auto g = node->read_tracker();
            if (g && pred(*g))
                return true;
        }
        return false;
    }

    bool has(const uint256& h)
    {
        for (int i = 0; i < 50; ++i) {
            auto g = node->read_tracker();
            if (g) return g->chain.contains(h);
            pump(10);
        }
        return false;
    }
};

chain::RawShare raw(uint64_t type, const Bytes& wire) { return chain::RawShare(type, PackStream(wire)); }

// The same wire with `pad` trailing bytes: still parses (the loader ignores
// trailing bytes), so only a size cap can refuse it before X11.
chain::RawShare padded(uint64_t type, Bytes wire, std::size_t pad)
{
    wire.resize(wire.size() + pad, 0x00);
    return raw(type, wire);
}

// A small honest v36 chain (genesis + children), mined on `p`.
std::vector<dash::producer::BuiltV36Share> v36_chain(const core::CoinParams& p, int n)
{
    dash::ShareChain scratch;
    std::vector<dash::producer::BuiltV36Share> out;
    uint256 prev;
    for (int i = 0; i < n; ++i) {
        auto b = mine_v36(scratch, p, info(prev, static_cast<uint32_t>(i + 1),
                                           static_cast<uint8_t>(0xa0 + i), 36));
        scratch.add(new dash::DashV36Share(b.share));
        prev = b.share.m_hash;
        out.push_back(b);
    }
    return out;
}

// Wire frames read off the peer end of a LoopbackPair (test_dash_addrme idiom).
struct Frame { std::string command; std::vector<std::byte> payload; };

std::vector<Frame> read_frames_for(boost::asio::ip::tcp::socket& s, std::chrono::milliseconds quiet_for)
{
    std::vector<std::byte> buf;
    s.non_blocking(true);
    auto deadline = std::chrono::steady_clock::now() + quiet_for;
    while (std::chrono::steady_clock::now() < deadline) {
        std::array<std::byte, 65536> chunk{};
        boost::system::error_code ec;
        const std::size_t n = s.read_some(boost::asio::buffer(chunk), ec);
        if (n > 0) {
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
            deadline = std::chrono::steady_clock::now() + quiet_for;   // still streaming
        } else if (ec == boost::asio::error::would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        } else if (ec) {
            break;
        }
    }
    std::vector<Frame> frames;
    const std::size_t pl = test_prefix().size();
    const std::size_t header = pl + 12 + 4 + 4;
    std::size_t off = 0;
    while (off + header <= buf.size()) {
        if (std::memcmp(buf.data() + off, test_prefix().data(), pl) != 0)
            break;
        std::string command(reinterpret_cast<const char*>(buf.data() + off + pl), 12);
        if (const auto z = command.find('\0'); z != std::string::npos)
            command.resize(z);
        uint32_t len = 0;
        std::memcpy(&len, buf.data() + off + pl + 12, 4);
        if (off + header + len > buf.size())
            break;
        Frame f;
        f.command = command;
        f.payload.assign(buf.begin() + off + header, buf.begin() + off + header + len);
        frames.push_back(std::move(f));
        off += header + len;
    }
    return frames;
}

// A v16 share with `n_tx` new transaction hashes (32 bytes each) and matching
// refs, linked to `prev`. Not mined: only served (handle_get_share), never
// verified.
dash::DashShare* fat_v16(uint8_t tag, const uint256& prev, std::size_t n_tx, uint32_t absheight)
{
    auto* s = new dash::DashShare();
    s->m_hash = tag_hash(tag);
    s->m_prev_hash = prev;
    s->m_coinbase = BaseScript(Bytes{0x01, 0x02});
    s->m_bits = EASY_BITS;
    s->m_max_bits = EASY_BITS;
    s->m_absheight = absheight;
    s->m_hash_link.m_state.m_data.assign(32, 0x00);
    s->m_hash_link.m_length = 0;
    s->m_new_transaction_hashes.resize(n_tx);
    for (std::size_t i = 0; i < n_tx; ++i) {
        Bytes h(32, 0x00);
        h[0] = tag;
        h[1] = static_cast<unsigned char>(i & 0xff);
        h[2] = static_cast<unsigned char>((i >> 8) & 0xff);
        s->m_new_transaction_hashes[i] = uint256(h);
        s->m_transaction_hash_refs.push_back(0);
        s->m_transaction_hash_refs.push_back(i);
    }
    return s;
}

// Serve a 9-share chain through `handler` ('sharereq', parents 8) and return
// the sharereply result byte the peer receives (0 good, 1 too long), or -1.
template <typename Handler>
int served_reply_result(Rig& rig, Handler&& handler, std::size_t n_tx, std::size_t* payload_len)
{
    uint256 prev;
    for (int i = 0; i < 9; ++i) {
        auto* s = fat_v16(static_cast<uint8_t>(0x10 + i), prev, n_tx, static_cast<uint32_t>(i + 1));
        prev = s->m_hash;
        rig.node->tracker().chain.add(s);
    }
    IoThread io(rig.pair.ioc_node);
    handler(dash::message_sharereq::make_raw(tag_hash(0xee), std::vector<uint256>{prev},
                                             uint64_t{8}, std::vector<uint256>{}));
    const auto frames = read_frames_for(*rig.pair.theirs, std::chrono::milliseconds(700));
    io.stop(rig.pair.ioc_node);
    for (const auto& f : frames) {
        if (f.command != "sharereply") continue;
        if (payload_len) *payload_len = f.payload.size();
        if (f.payload.size() < 33) return -1;
        return static_cast<int>(f.payload[32]);
    }
    return -1;
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// 1. Per-message caps, before any share is parsed or hashed
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashSharePrecheck, OversizeV36ShareDroppedBeforeX11)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_precheck_oversize");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    const Bytes w = wire_of(sh[0].share);

    Rig rig(p, SharechainConfig::data_subdir(false));
    // Parses on every revision: the padding is trailing bytes.
    rig.actual().handle_message(
        dash::message_shares::make_raw(std::vector<chain::RawShare>{padded(36, w, 65536)}), rig.peer);
    rig.pump();
    EXPECT_EQ(rig.pow.n(), 0) << "an oversize v36 share must be dropped before X11";
    EXPECT_FALSE(rig.has(sh[0].share.m_hash));
#ifndef DASH_PRECHECK_BASE_REVISION
    EXPECT_EQ(rig.node->precheck_dropped_messages(), 0u) << "per-share drop, not a whole-message drop";
    EXPECT_EQ(rig.node->precheck_dropped_shares(), 1u);
    EXPECT_FALSE(rig.node->is_banned(rig.peer->addr())) << "no ban here (#1829)";
#endif
}

TEST(DashSharePrecheck, TooManySharesMessageDroppedBeforeX11)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_precheck_count");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    const Bytes w = wire_of(sh[0].share);
    const std::vector<chain::RawShare> msg(65, raw(36, w));   // v36 cap: 64

    {
        Rig rig(p, SharechainConfig::data_subdir(false));
        rig.actual().handle_message(dash::message_shares::make_raw(msg), rig.peer);
        rig.pump();
        EXPECT_EQ(rig.pow.n(), 0) << "Actual: 65 shares in one 'shares' must be dropped before X11";
        EXPECT_FALSE(rig.has(sh[0].share.m_hash));
#ifndef DASH_PRECHECK_BASE_REVISION
        EXPECT_EQ(rig.node->precheck_dropped_messages(), 1u);
        EXPECT_EQ(rig.node->precheck_dropped_shares(), 65u);
        EXPECT_FALSE(rig.node->is_banned(rig.peer->addr()));
#endif
    }
    {
        Rig rig(p, SharechainConfig::data_subdir(false));
        rig.legacy().handle_message(dash::message_shares::make_raw(msg), rig.peer);
        rig.pump();
        EXPECT_EQ(rig.pow.n(), 0) << "Legacy: 65 shares in one 'shares' must be dropped before X11";
        EXPECT_FALSE(rig.has(sh[0].share.m_hash));
    }
}

TEST(DashSharePrecheck, OverPayloadSharesMessageDroppedOnPublicProfile)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_precheck_payload");
    const auto p = public_params();
    ASSERT_FALSE(SharechainConfig::isolated_v36());
    dash::ShareChain scratch;
    const auto b = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));
    const Bytes w = wire_of(b.share);

    // 3 parseable shares of ~1 MiB each: 3145728 + 1 payload bytes in total,
    // one byte over the oracle cap (p2pool/p2p.py:33). Each share alone is
    // under the public per-share cap, so only the payload cap refuses it.
    const std::size_t each = 1048576;
    std::vector<chain::RawShare> msg;
    for (int i = 0; i < 3; ++i)
        msg.push_back(padded(16, w, each - w.size()));
    // [VarInt 3] + 3 x ([VarInt 16][VarStr len 5 bytes][1048576]) = 3145747
    ASSERT_GT(dash::message_shares::make_raw(msg)->m_data.size(), 3145728u);

    Rig rig(p, SharechainConfig::data_subdir(false));
    rig.legacy().handle_message(dash::message_shares::make_raw(msg), rig.peer);
    rig.pump();
    EXPECT_EQ(rig.pow.n(), 0) << "a 'shares' payload over 3145728 bytes must be dropped before X11";
    EXPECT_FALSE(rig.has(b.share.m_hash));
#ifndef DASH_PRECHECK_BASE_REVISION
    EXPECT_EQ(rig.node->precheck_dropped_messages(), 1u);
    EXPECT_EQ(rig.node->precheck_dropped_shares(), 3u);
    EXPECT_FALSE(rig.node->is_banned(rig.peer->addr()));
#endif
}

TEST(DashSharePrecheck, SharereplyOverCountResolvesEmptyBeforeX11)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_precheck_reply");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    const Bytes w = wire_of(sh[0].share);
    const std::vector<chain::RawShare> shares(1002, raw(36, w));   // v36 cap: 1001

    for (int proto = 0; proto < 2; ++proto) {
        SCOPED_TRACE(proto == 0 ? "Actual" : "Legacy");
        Rig rig(p, SharechainConfig::data_subdir(false));
        const uint256 id = tag_hash(static_cast<uint8_t>(0x51 + proto));
        int fired = 0;
        std::size_t items = 0;
        // The download leg feeds a reply into processing_shares (node.cpp
        // download_shares); do the same, so X11 would be counted if it ran.
        rig.node->request_shares(id, rig.peer, {sh[0].share.m_hash}, 0, {},
            [&](dash::ShareReplyData d) {
                ++fired;
                items = d.m_items.size();
                dash::HandleSharesData hs;
                for (auto& s : d.m_items) hs.add(s, {});
                rig.node->processing_shares(hs, rig.peer->addr());
            });
        auto m = dash::message_sharereply::make_raw(id, dash::ShareReplyResult::good, shares);
        if (proto == 0) rig.actual().handle_message(std::move(m), rig.peer);
        else            rig.legacy().handle_message(std::move(m), rig.peer);
        rig.pump();
        EXPECT_EQ(fired, 1) << "the pending request resolves at once, not by timeout";
        EXPECT_EQ(items, 0u) << "a 'sharereply' over the count cap resolves EMPTY";
        EXPECT_EQ(rig.pow.n(), 0);
#ifndef DASH_PRECHECK_BASE_REVISION
        EXPECT_EQ(rig.node->precheck_dropped_messages(), 1u);
        EXPECT_EQ(rig.node->precheck_dropped_shares(), 1002u);
        EXPECT_FALSE(rig.node->is_banned(rig.peer->addr()));
#endif
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Honest-size traffic is untouched
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashSharePrecheck, HonestSizedMessagesStillAccepted)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_precheck_honest");
    {
        const auto p = iso_params(36);
        const auto sh = v36_chain(p, 9);
        // 5 shares in one 'shares' (the broadcast maximum), Actual.
        {
            Rig rig(p, SharechainConfig::data_subdir(false));
            std::vector<chain::RawShare> msg;
            for (int i = 0; i < 5; ++i) msg.push_back(raw(36, wire_of(sh[i].share)));
            rig.actual().handle_message(dash::message_shares::make_raw(msg), rig.peer);
            EXPECT_TRUE(rig.pump_until([&](dash::ShareTracker& t) {
                for (int i = 0; i < 5; ++i) if (!t.chain.contains(sh[i].share.m_hash)) return false;
                return true;
            })) << "5 honest v36 shares in one 'shares' must all be inserted";
            EXPECT_EQ(rig.pow.n(), 5);
#ifndef DASH_PRECHECK_BASE_REVISION
            EXPECT_EQ(rig.node->precheck_dropped_messages(), 0u);
            EXPECT_EQ(rig.node->precheck_dropped_shares(), 0u);
#endif
        }
        // A 9-share 'sharereply' (the c2pool serve maximum), Legacy.
        {
            Rig rig(p, SharechainConfig::data_subdir(false));
            std::vector<chain::RawShare> shares;
            for (int i = 0; i < 9; ++i) shares.push_back(raw(36, wire_of(sh[i].share)));
            const uint256 id = tag_hash(0x61);
            std::size_t items = 0;
            rig.node->request_shares(id, rig.peer, {sh[8].share.m_hash}, 8, {},
                [&](dash::ShareReplyData d) {
                    items = d.m_items.size();
                    dash::HandleSharesData hs;
                    for (auto& s : d.m_items) hs.add(s, {});
                    rig.node->processing_shares(hs, rig.peer->addr());
                });
            rig.legacy().handle_message(
                dash::message_sharereply::make_raw(id, dash::ShareReplyResult::good, shares), rig.peer);
            EXPECT_EQ(items, 9u);
            EXPECT_TRUE(rig.pump_until([&](dash::ShareTracker& t) {
                for (int i = 0; i < 9; ++i) if (!t.chain.contains(sh[i].share.m_hash)) return false;
                return true;
            })) << "a 9-share honest 'sharereply' must be fully inserted";
            EXPECT_EQ(rig.pow.n(), 9);
        }
    }
    // Public v16 through the Legacy handler (the p2pool-dash peer protocol).
    {
        const auto p = public_params();
        dash::ShareChain scratch;
        const auto b = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));
        Rig rig(p, SharechainConfig::data_subdir(false));
        rig.legacy().handle_message(
            dash::message_shares::make_raw(std::vector<chain::RawShare>{raw(16, wire_of(b.share))}), rig.peer);
        EXPECT_TRUE(rig.pump_until([&](dash::ShareTracker& t) { return t.chain.contains(b.share.m_hash); }))
            << "a public v16 share must still be accepted";
        EXPECT_EQ(rig.pow.n(), 1);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Field checks with no hashing (share_init_verify)
// ═════════════════════════════════════════════════════════════════════════════

namespace {
// share_init_verify(check_pow=false) outcome + X11 calls it made.
template <typename S>
std::pair<std::string, int> verify_counting(const S& s, const core::CoinParams& p)
{
    PowCounter c;
    const auto cp = c.wrap(p);
    const std::string err = invalid_arg_text([&] { (void)dash::share_init_verify(s, cp, false); });
    return {err, c.n()};
}
} // namespace

TEST(DashSharePrecheck, MerkleBranchOver16RejectedBeforeHashing)
{
    IdentityGuard guard;
    {
        const auto p = public_params();
        dash::ShareChain scratch;
        const auto b = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));
        auto ok = verify_counting(b.share, p);
        EXPECT_EQ(ok.first, "<no exception>");
        EXPECT_EQ(ok.second, 1);

        auto s = b.share;
        s.m_merkle_link.m_branch.assign(16, tag_hash(0x01));
        EXPECT_EQ(verify_counting(s, p).first, "<no exception>") << "16 is the oracle maximum";
        s.m_merkle_link.m_branch.assign(17, tag_hash(0x01));
        const auto r = verify_counting(s, p);
        EXPECT_EQ(r.first, "merkle branch too long");
        EXPECT_EQ(r.second, 0) << "rejected before X11";
    }
    {
        const auto p = iso_params(36);
        const auto sh = v36_chain(p, 1);
        auto s = sh[0].share;
        s.m_merkle_link.m_branch.assign(17, tag_hash(0x02));
        auto r = verify_counting(s, p);
        EXPECT_EQ(r.first, "merkle branch too long");
        EXPECT_EQ(r.second, 0);

        s = sh[0].share;
        s.m_ref_merkle_link.m_branch.assign(17, tag_hash(0x03));
        r = verify_counting(s, p);
        EXPECT_EQ(r.first, "merkle branch too long");
        EXPECT_EQ(r.second, 0);
    }
}

TEST(DashSharePrecheck, TxRefsInvariantRejectedBeforeHashing)
{
    IdentityGuard guard;
    const auto p = public_params();
    dash::ShareChain scratch;
    const auto b = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));

    struct Case { const char* name; std::vector<uint256> news; std::vector<uint64_t> refs; bool ok; };
    const std::vector<Case> cases = {
        {"empty",                  {},                           {},             true},
        {"one new, [0,0]",         {tag_hash(1)},                {0, 0},         true},
        {"old ref [109,3]",        {},                           {109, 3},       true},
        {"duplicate [0,0][0,0]",   {tag_hash(1)},                {0, 0, 0, 0},   true},
        {"share_count 110",        {},                           {110, 0},       false},
        {"tx_count past new list", {tag_hash(1)},                {0, 1},         false},
        {"new hash unreferenced",  {tag_hash(1), tag_hash(2)},   {0, 0},         false},
        {"new hash, no refs",      {tag_hash(1)},                {},             false},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        auto s = b.share;
        s.m_new_transaction_hashes = c.news;
        s.m_transaction_hash_refs = c.refs;
        const auto r = verify_counting(s, p);
        if (c.ok) {
            EXPECT_EQ(r.first, "<no exception>");
            EXPECT_EQ(r.second, 1);
        } else {
            EXPECT_EQ(r.first, "bad transaction_hash_refs");
            EXPECT_EQ(r.second, 0) << "rejected before X11";
        }
    }
}

TEST(DashSharePrecheck, V16ProducerShareWithTxRefsPasses)
{
    // The v16 producer's refs (share_producer.hpp assemble_tx_refs) satisfy
    // the oracle invariant: a parent carrying two new txs, a child that
    // re-references one and adds one.
    IdentityGuard guard;
    const auto p = public_params();
    dash::ShareChain chain;
    auto genesis = new dash::DashShare();
    genesis->m_hash = tag_hash(0x70);
    genesis->m_bits = EASY_BITS;
    genesis->m_max_bits = EASY_BITS;
    genesis->m_absheight = 1;
    chain.add(genesis);
    auto parent = new dash::DashShare();
    parent->m_hash = tag_hash(0x71);
    parent->m_prev_hash = tag_hash(0x70);
    parent->m_bits = EASY_BITS;
    parent->m_max_bits = EASY_BITS;
    parent->m_absheight = 2;
    parent->m_new_transaction_hashes = {tag_hash(0x81), tag_hash(0x82)};
    parent->m_transaction_hash_refs = {0, 0, 0, 1};
    chain.add(parent);
    const auto refs = dash::producer::assemble_tx_refs(chain, tag_hash(0x71),
                                                       {tag_hash(0x82), tag_hash(0x83)});
    ASSERT_EQ(refs.transaction_hash_refs, (std::vector<uint64_t>{1, 1, 0, 0}));
    ASSERT_EQ(refs.new_transaction_hashes, (std::vector<uint256>{tag_hash(0x83)}));

    auto i = info(tag_hash(0x71), 3, 0xbb, 16);
    i.new_transaction_hashes = refs.new_transaction_hashes;
    i.transaction_hash_refs = refs.transaction_hash_refs;
    const auto b = mine_v16(chain, p, i);   // the producer self-verifies with share_init_verify
    EXPECT_EQ(b.share.m_transaction_hash_refs, refs.transaction_hash_refs);
    EXPECT_EQ(verify_counting(b.share, p).first, "<no exception>");
}

TEST(DashSharePrecheck, V36FieldChecksRejectBeforeHashing)
{
    IdentityGuard guard;
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    {
        const auto r = verify_counting(sh[0].share, p);
        EXPECT_EQ(r.first, "<no exception>");
        EXPECT_EQ(r.second, 1);
    }
    struct Case { const char* name; std::function<void(dash::DashV36Share&)> edit; const char* err; };
    const std::vector<Case> cases = {
        {"message_data 562 bytes", [](dash::DashV36Share& s) {
             s.m_message_data = BaseScript(Bytes(562, 0x01)); },
         "share message_data exceeds MAX_TOTAL_MESSAGE_BYTES"},
        {"pubkey_type 1", [](dash::DashV36Share& s) { s.m_pubkey_type = 1; },
         "share pubkey_type must be 0 (P2PKH)"},
        {"merged_addresses", [](dash::DashV36Share& s) { s.m_merged_addresses.resize(1); },
         "share merged-mining fields must be empty"},
        {"merged_coinbase_info", [](dash::DashV36Share& s) { s.m_merged_coinbase_info.resize(1); },
         "share merged-mining fields must be empty"},
        {"merged_payout_hash", [](dash::DashV36Share& s) { s.m_merged_payout_hash = tag_hash(0x09); },
         "share merged-mining fields must be empty"},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        auto s = sh[0].share;
        c.edit(s);
        const auto r = verify_counting(s, p);
        EXPECT_EQ(r.first, c.err);
        EXPECT_EQ(r.second, 0) << "rejected before any hashing";
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Sender side: a reply over the oracle payload cap answers 'too long'
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashSharePrecheck, ShareReplyOverPayloadCapAnswersTooLong)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_precheck_send");
    const auto p = public_params();
    // 9 shares x 11000 new tx hashes x 32 bytes = ~3.17 MB > 3145728.
    for (int proto = 0; proto < 2; ++proto) {
        SCOPED_TRACE(proto == 0 ? "Actual" : "Legacy");
        Rig rig(p, SharechainConfig::data_subdir(false));
        std::size_t len = 0;
        const int result = served_reply_result(rig, [&](std::unique_ptr<RawMessage> m) {
            if (proto == 0) rig.actual().handle_message(std::move(m), rig.peer);
            else            rig.legacy().handle_message(std::move(m), rig.peer);
        }, 11000, &len);
        EXPECT_EQ(result, 1) << "the reply must be 'too long' (p2pool/p2p.py:399-404)";
        EXPECT_LE(len, 3145728u) << "nothing over the oracle cap goes on the wire";
    }
    // Honest-size replies are unchanged: 9 small shares answer 'good'.
    {
        Rig rig(p, SharechainConfig::data_subdir(false));
        std::size_t len = 0;
        const int result = served_reply_result(rig, [&](std::unique_ptr<RawMessage> m) {
            rig.actual().handle_message(std::move(m), rig.peer);
        }, 2, &len);
        EXPECT_EQ(result, 0);
        EXPECT_GT(len, 33u);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Pins (new symbols; fenced out of the base-revision build)
// ═════════════════════════════════════════════════════════════════════════════
#ifndef DASH_PRECHECK_BASE_REVISION

TEST(DashSharePrecheck, MinimalV16RawShareSize)
{
    // The smallest v16 share that can pass share_init_verify: 2-byte coinbase,
    // 1-byte VarInt header version, every list / VarStr empty.
    dash::DashShare s;
    s.m_coinbase = BaseScript(Bytes{0x01, 0x02});
    s.m_min_header.m_version = 0;
    s.m_desired_version = 16;
    s.m_hash_link.m_state.m_data.assign(32, 0x00);
    s.m_hash_link.m_length = 0;   // HashLinkType leaves it uninitialized
    const Bytes contents = wire_of(s);
    std::string hx;
    for (unsigned char c : contents) { static const char* d = "0123456789abcdef"; hx += d[c >> 4]; hx += d[c & 15]; }
    EXPECT_EQ(contents.size(), 237u) << hx;
    PackStream ps;
    ps << raw(16, contents);
    EXPECT_EQ(ps.size(), dash::precheck::MIN_V16_RAW_SHARE_WIRE_BYTES);
    EXPECT_EQ(dash::precheck::raw_share_wire_bytes(raw(16, contents)), ps.size());

    // The public count cap is the oracle byte cap re-expressed: 13162 minimal
    // shares fit one 3145728-byte payload, 13163 do not.
    using dash::precheck::MAX_P2P_PAYLOAD_BYTES;
    using dash::precheck::PUBLIC_MAX_SHARES_PER_MSG;
    EXPECT_EQ(PUBLIC_MAX_SHARES_PER_MSG, 13162u);
    const std::vector<chain::RawShare> fit(PUBLIC_MAX_SHARES_PER_MSG, raw(16, contents));
    const std::vector<chain::RawShare> over(PUBLIC_MAX_SHARES_PER_MSG + 1, raw(16, contents));
    EXPECT_LE(dash::message_shares::make_raw(fit)->m_data.size(), MAX_P2P_PAYLOAD_BYTES);
    EXPECT_GT(dash::message_shares::make_raw(over)->m_data.size(), MAX_P2P_PAYLOAD_BYTES);

    // Profiles.
    const auto& pub = SharechainConfig::PUBLIC_PROFILE;
    EXPECT_EQ(pub.max_shares_per_shares_msg, 13162u);
    EXPECT_EQ(pub.max_shares_per_sharereply, 13162u);
    EXPECT_EQ(pub.max_share_wire_bytes, 3145728u);
    const auto& v36 = SharechainConfig::ISOLATED_V36_PROFILE;
    EXPECT_EQ(v36.max_shares_per_shares_msg, 64u);
    EXPECT_EQ(v36.max_shares_per_sharereply, 1001u);
    EXPECT_EQ(v36.max_share_wire_bytes, 65536u);
    static_assert(dash::MAX_MESSAGE_DATA_WIRE_BYTES == 49 + 512);
}

TEST(DashSharePrecheck, PayloadArithmeticMatchesTheWireCodec)
{
    using dash::precheck::Kind;
    using dash::precheck::payload_bytes;
    for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{252}, std::size_t{253}, std::size_t{300}}) {
        for (std::size_t len : {std::size_t{0}, std::size_t{252}, std::size_t{253}, std::size_t{70000}}) {
            SCOPED_TRACE(std::to_string(n) + " x " + std::to_string(len));
            const std::vector<chain::RawShare> v(n, raw(n % 2 ? 36 : 16, Bytes(len, 0x5a)));
            EXPECT_EQ(payload_bytes(v, Kind::shares), dash::message_shares::make_raw(v)->m_data.size());
            EXPECT_EQ(payload_bytes(v, Kind::sharereply),
                      dash::message_sharereply::make_raw(tag_hash(1), dash::ShareReplyResult::good, v)->m_data.size());
        }
    }
    // sharereply_fits: the oracle sender rule.
    EXPECT_TRUE(dash::precheck::sharereply_fits(std::vector<chain::RawShare>(9, raw(16, Bytes(1000, 0)))));
    EXPECT_FALSE(dash::precheck::sharereply_fits(std::vector<chain::RawShare>(9, raw(16, Bytes(350000, 0)))));
}

TEST(DashSharePrecheck, RawPrecheckOrderAndProfiles)
{
    using dash::precheck::Kind;
    using dash::precheck::precheck_raw_shares;
    const auto& pub = SharechainConfig::PUBLIC_PROFILE;
    const auto& v36 = SharechainConfig::ISOLATED_V36_PROFILE;
    {   // v36: 64 pass, 65 drop the whole message; sharereply 1001 / 1002.
        std::vector<chain::RawShare> v(64, raw(36, Bytes(300, 1)));
        auto r = precheck_raw_shares(v, Kind::shares, v36);
        EXPECT_FALSE(r.message_dropped); EXPECT_EQ(r.shares_dropped, 0u); EXPECT_EQ(v.size(), 64u);
        v.push_back(raw(36, Bytes(300, 1)));
        r = precheck_raw_shares(v, Kind::shares, v36);
        EXPECT_TRUE(r.message_dropped); EXPECT_EQ(r.shares_dropped, 65u);
        std::vector<chain::RawShare> w(1001, raw(36, Bytes(300, 1)));
        EXPECT_FALSE(precheck_raw_shares(w, Kind::sharereply, v36).message_dropped);
        w.push_back(raw(36, Bytes(300, 1)));
        EXPECT_TRUE(precheck_raw_shares(w, Kind::sharereply, v36).message_dropped);
        // Public: 1002 in a sharereply is fine (the oracle enforces no count).
        EXPECT_FALSE(precheck_raw_shares(w, Kind::sharereply, pub).message_dropped);
    }
    {   // Per-share cap erases only the oversize item.
        std::vector<chain::RawShare> v = {raw(36, Bytes(65536, 1)), raw(36, Bytes(65537, 1)), raw(36, Bytes(10, 1))};
        auto r = precheck_raw_shares(v, Kind::shares, v36);
        EXPECT_FALSE(r.message_dropped);
        EXPECT_EQ(r.shares_dropped, 1u);
        ASSERT_EQ(v.size(), 2u);
        EXPECT_EQ(v[0].contents.m_data.size(), 65536u);
        EXPECT_EQ(v[1].contents.m_data.size(), 10u);
        // The same message on the public profile passes whole.
        std::vector<chain::RawShare> u = {raw(16, Bytes(65537, 1)), raw(16, Bytes(10, 1))};
        EXPECT_EQ(precheck_raw_shares(u, Kind::shares, pub).shares_dropped, 0u);
        EXPECT_EQ(u.size(), 2u);
    }
    {   // Exactly at the payload cap passes; one byte over drops.
        // [VarInt 1][VarInt 16][VarStr 5-byte length] + len = 3145728
        const std::size_t len = 3145728 - 1 - 1 - 5;
        std::vector<chain::RawShare> v = {raw(16, Bytes(len, 0))};
        ASSERT_EQ(dash::precheck::payload_bytes(v, Kind::shares), 3145728u);
        EXPECT_FALSE(precheck_raw_shares(v, Kind::shares, pub).message_dropped);
        std::vector<chain::RawShare> w = {raw(16, Bytes(len + 1, 0))};
        EXPECT_TRUE(precheck_raw_shares(w, Kind::shares, pub).message_dropped);
    }
}

#endif // DASH_PRECHECK_BASE_REVISION
