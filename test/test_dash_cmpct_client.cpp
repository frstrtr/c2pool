// SPDX-License-Identifier: AGPL-3.0-or-later
// #968a KAT: BIP 152 compact blocks THROUGH THE COINCLIENT HANDLERS.
//
// test_dash_compact_block_receive.cpp drives the pure receiver. This TU drives
// the real CoinClient<dash::Config>: raw messages in through handle() (the
// socket demux), every write out through the test write tap, the header chain
// as a fake CompactChainView fed by the client's own new_headers event, and a
// real Mempool behind make_mempool_short_id_provider. It pins:
//   * the request: a new tip body is asked for as getdata(MSG_CMPCT_BLOCK=20)
//     from the announcer once bodies are caught up, never before;
//   * header first: the cmpctblock header reaches the header chain before the
//     reassembled body is delivered (full_block);
//   * getblocktxn / blocktxn round trip, high-bandwidth selection
//     (sendcmpct 1) and push, credit only for asked-for bodies;
//   * the gate: parent unknown, bad PoW, refused header, held body,
//     unsolicited non-high-bandwidth push;
//   * hostile input: InitData INVALID, duplicate short ids, over-long
//     blocktxn, Misbehaving(100) -> disconnect, full-block fallback;
//   * the lost-body watchdog as the compact timeout;
//   * disconnect() clearing compact state, and minimal serving.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_client.hpp>
#include <impl/dash/coin/compact_mempool_provider.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHexBytes (wire-magic bytes)

#include <boost/asio.hpp>

#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

using dash::coin::p2p::CoinClient;
namespace p2p = dash::coin::p2p;
namespace v = dash::coin::vendor;
using dash::coin::BlockType;
using dash::coin::BlockHeaderType;
using dash::coin::MutableTransaction;

namespace {

constexpr uint32_t kEasyBits = 0x207fffff;   // ~half of all X11 hashes meet it
constexpr uint32_t kMsgBlock = 2;
constexpr uint32_t kMsgCmpctBlock = 20;      // Dash MSG_CMPCT_BLOCK

uint256 x11_of(const BlockHeaderType& h)
{
    auto ps = pack(h);
    return dash::crypto::hash_x11(ps.get_span());
}

MutableTransaction mk_tx(uint32_t tag)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = tag;
    return tx;
}

MutableTransaction mk_coinbase(uint32_t tag)
{
    MutableTransaction tx = mk_tx(tag);
    bitcoin_family::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    bitcoin_family::coin::TxOut out;
    out.value = 500000000;
    tx.vout.push_back(out);
    return tx;
}

// A block on `prev` with real (easy) PoW and a merkle root over its txs.
BlockType mk_block(const uint256& prev, uint32_t tag, size_t ntx,
                   uint32_t bits = kEasyBits, bool grind = true)
{
    BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_timestamp = 1'700'000'000u + tag;
    b.m_bits = bits;
    b.m_txs.push_back(mk_coinbase(tag));
    for (size_t i = 1; i < ntx; ++i)
        b.m_txs.push_back(mk_tx(tag * 1000 + static_cast<uint32_t>(i)));
    std::vector<uint256> ids;
    for (const auto& t : b.m_txs) ids.push_back(dash::coin::dash_txid(t));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
    for (uint32_t n = 0; grind; ++n) {
        b.m_nonce = n;
        if (dash::coin::header_pow_meets_bits(x11_of(b), b.m_bits)) break;
    }
    return b;
}

uint256 hash_of(const BlockType& b) { return x11_of(b); }

// The header chain the gate reads: accepts a header whose parent it holds and
// whose PoW meets its own bits (unless told to refuse everything).
struct FakeChain
{
    std::map<uint256, dash::coin::CompactChainEntry> idx;
    uint256 tip;
    bool refuse{false};

    void add_base(const BlockType& b, uint32_t height)
    {
        const uint256 h = hash_of(b);
        idx[h] = dash::coin::CompactChainEntry{height, uint256::ONE, b.m_previous_block};
        tip = h;
    }

    void on_headers(const std::vector<BlockHeaderType>& hs)
    {
        if (refuse) return;
        for (const auto& hdr : hs) {
            const uint256 h = x11_of(hdr);
            if (idx.count(h)) continue;
            auto prev = idx.find(hdr.m_previous_block);
            if (prev == idx.end()) continue;
            if (!dash::coin::header_pow_meets_bits(h, hdr.m_bits)) continue;
            dash::coin::CompactChainEntry e{prev->second.height + 1,
                                            prev->second.chain_work + uint256::ONE,
                                            hdr.m_previous_block};
            idx[h] = e;
            if (e.chain_work > idx[tip].chain_work) tip = h;
        }
    }

    dash::coin::CompactChainView view()
    {
        dash::coin::CompactChainView vw;
        vw.lookup = [this](const uint256& h) -> std::optional<dash::coin::CompactChainEntry> {
            auto it = idx.find(h);
            if (it == idx.end()) return std::nullopt;
            return it->second;
        };
        vw.tip_hash = [this] { return tip; };
        vw.locator = [this] { return std::vector<uint256>{tip}; };
        return vw;
    }
};

struct Sent
{
    std::string key;
    std::string cmd;
    std::vector<unsigned char> payload;
};

std::vector<unsigned char> bytes_of(PackStream ps)
{
    auto sp = ps.get_span();
    const auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    return std::vector<unsigned char>(p, p + sp.size());
}

// (type, hash) pairs of a getdata payload.
std::vector<std::pair<uint32_t, uint256>> getdata_invs(const Sent& s)
{
    PackStream ps(s.payload);
    const uint64_t n = ReadCompactSize(ps);
    std::vector<std::pair<uint32_t, uint256>> out;
    for (uint64_t i = 0; i < n; ++i) {
        uint32_t type = 0;
        uint256 h;
        ps >> type >> h;
        out.emplace_back(type, h);
    }
    return out;
}

struct CmpctRig
{
    boost::asio::io_context ioc;
    dash::interfaces::Node coin_state;
    dash::Config config;
    CoinClient<dash::Config> client;
    dash::coin::Mempool mempool;
    FakeChain chain;
    std::vector<Sent> sent;
    std::vector<uint256> delivered;
    std::vector<bool> header_known_at_delivery;
    bool emulate_main_dash{true};
    int64_t fake_now{1'000'000};
    BlockType b0;
    std::vector<std::shared_ptr<EventDisposable>> subs;

    explicit CmpctRig(bool wire_compact = true)
        : config("dash-cmpct-client-kat")
        , client(&ioc, &coin_state, &config, "COIN-P2P-CMPCT-KAT")
    {
        config.coin()->m_p2p.prefix = ParseHexBytes("cee2caff");
        client.set_now_fn([this] { return fake_now; });
        client.set_write_tap_for_test([this](const std::string& k, const RawMessage& m) {
            sent.push_back(Sent{k, m.m_command, bytes_of(m.m_data)});
        });
        subs.push_back(coin_state.new_headers.subscribe(
            [this](const std::vector<BlockHeaderType>& hs) { chain.on_headers(hs); }));
        subs.push_back(coin_state.full_block.subscribe([this](const BlockType& b) {
            const uint256 h = hash_of(b);
            delivered.push_back(h);
            header_known_at_delivery.push_back(chain.idx.count(h) != 0);
        }));
        // main_dash's new_block subscriber: getheaders + the TRACKED body pull.
        subs.push_back(coin_state.new_block.subscribe([this](const uint256& h) {
            if (emulate_main_dash) client.request_block_tracked(h);
        }));
        if (wire_compact) {
            client.set_compact_mempool_provider(dash::coin::make_mempool_short_id_provider(&mempool));
            client.set_compact_chain_view(chain.view());
        }
    }

    static NetService peer_addr(int n) { return NetService{"192.0.2." + std::to_string(n), 19999}; }
    static std::string key(int n) { return peer_addr(n).to_string(); }

    void deliver(int n, std::unique_ptr<RawMessage> m) { client.handle(std::move(m), peer_addr(n)); }

    // version / verack, then the peer's own sendcmpct(0, 1) as dashcore sends
    // it at VERACK (it provides compact blocks).
    void handshake(int n, bool peer_sends_sendcmpct = true)
    {
        client.attach_peer_for_test(peer_addr(n));
        deliver(n, p2p::message_version::make_raw(
            70230, /*services=*/1, 1234567890ull,
            addr_t{1, NetService{"127.0.0.1", 19999}},
            addr_t{1, NetService{"127.0.0.1", 19999}},
            0x1122334455667788ull, "/Dash Core:24.0.0/", 1000));
        deliver(n, p2p::message_verack::make_raw());
        if (peer_sends_sendcmpct)
            deliver(n, p2p::message_sendcmpct::make_raw(false, 1));
    }

    void inv_block(int n, const uint256& h)
    {
        deliver(n, p2p::message_inv::make_raw(
            {p2p::inventory_type(p2p::inventory_type::block, h)}));
    }

    // Cold start: the first tip body arrives whole (no body tip yet), from
    // peer n, which then becomes a high-bandwidth peer.
    void warm(int n)
    {
        b0 = mk_block(uint256(), 0, 2);
        chain.add_base(b0, 1000);
        inv_block(n, hash_of(b0));
        deliver(n, p2p::message_block::make_raw(b0));
    }

    std::vector<Sent> sent_to(int n, const std::string& cmd) const
    {
        std::vector<Sent> out;
        for (const auto& s : sent)
            if (s.key == key(n) && s.cmd == cmd) out.push_back(s);
        return out;
    }

    void run_seconds(int64_t s)
    {
        for (int64_t i = 0; i < s; ++i) { ++fake_now; client.tick_for_test(); }
    }

    void add_to_pool(const BlockType& b, std::vector<size_t> idx)
    {
        for (size_t i : idx) ASSERT_TRUE(mempool.add_tx(b.m_txs[i]));
    }
};

v::BlockTransactions answer(const v::BlockTransactionsRequest& req, const BlockType& b)
{
    v::BlockTransactions resp(req);
    for (size_t k = 0; k < req.indexes.size(); ++k)
        resp.txn[k] = v::MakeTransactionRef(b.m_txs[req.indexes[k]]);
    return resp;
}

// A cmpctblock straight from bytes (for the shapes the constructor refuses).
std::unique_ptr<RawMessage> raw_cmpct(const BlockHeaderType& h, const std::vector<uint64_t>& ids,
                                      const std::vector<std::pair<uint64_t, MutableTransaction>>& pre)
{
    PackStream ps;
    ps << h;
    ps << uint64_t{42};
    WriteCompactSize(ps, ids.size());
    for (uint64_t id : ids) {
        uint8_t b6[6];
        for (int i = 0; i < 6; ++i) b6[i] = static_cast<uint8_t>((id >> (8 * i)) & 0xff);
        ps.write(std::as_bytes(std::span{b6}));
    }
    WriteCompactSize(ps, pre.size());
    for (const auto& [idx, tx] : pre) {
        WriteCompactSize(ps, idx);
        ps << tx;
    }
    return std::make_unique<RawMessage>("cmpctblock", std::move(ps));
}

} // namespace

// ── the request: compact only for the next tip, from the announcer ─────────

TEST(DashCmpctClient, NoBlanketSendcmpctAtVerack)
{
    CmpctRig rig;
    rig.handshake(1);
    EXPECT_TRUE(rig.sent_to(1, "sendcmpct").empty())
        << "we serve compact blocks only for a handful of blocks: no blanket sendcmpct";
}

TEST(DashCmpctClient, ColdStartFetchesWholeThenAsksTheDelivererForHighBandwidth)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    auto gd = rig.sent_to(1, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0).first, kMsgBlock)
        << "no best body yet: the first body is a plain MSG_BLOCK";
    ASSERT_EQ(rig.delivered.size(), 1u);
    EXPECT_TRUE(rig.client.have_body_for_test(hash_of(rig.b0)));
    // dashcore BlockChecked -> MaybeSetPeerAsAnnouncingHeaderAndIDs.
    auto sc = rig.sent_to(1, "sendcmpct");
    ASSERT_EQ(sc.size(), 1u);
    EXPECT_EQ(sc[0].payload.at(0), 1u) << "sendcmpct(1, 1): push new blocks as cmpctblock";
    EXPECT_TRUE(rig.client.cmpct_high_bandwidth_for_test(CmpctRig::key(1)));
}

TEST(DashCmpctClient, NewTipIsRequestedCompactHeaderFirstBodyDelivered)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 4);
    const uint256 h1 = hash_of(b1);
    rig.add_to_pool(b1, {1, 2, 3});

    rig.inv_block(2, h1);   // peer 2 announces the new tip
    auto gd = rig.sent_to(2, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    const auto inv = getdata_invs(gd[0]).at(0);
    EXPECT_EQ(inv.first, kMsgCmpctBlock) << "the next tip is fetched as MSG_CMPCT_BLOCK";
    EXPECT_EQ(inv.second, h1);
    EXPECT_TRUE(rig.client.cmpct_requested_from_for_test(h1, CmpctRig::key(2)));
    EXPECT_FALSE(rig.chain.idx.count(h1)) << "header not known yet";

    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    ASSERT_EQ(rig.delivered.size(), 2u);
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_TRUE(rig.header_known_at_delivery.back())
        << "the cmpctblock header reached the header chain before the body";
    EXPECT_EQ(rig.client.cmpct_reconstructed(), 1u);
    EXPECT_EQ(rig.client.pending_body_count(), 0u);
    EXPECT_TRUE(rig.sent_to(2, "getblocktxn").empty()) << "the mempool held every tx";
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(2)), 1u)
        << "asked-for body: credited";
    EXPECT_TRUE(rig.client.cmpct_high_bandwidth_for_test(CmpctRig::key(2)));
}

TEST(DashCmpctClient, MissingTxsGoThroughGetblocktxn)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 4);
    const uint256 h1 = hash_of(b1);
    rig.add_to_pool(b1, {1});

    rig.inv_block(2, h1);
    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 1u);
    PackStream ps(gbt[0].payload);
    v::BlockTransactionsRequest req;
    ps >> req;
    EXPECT_EQ(req.blockhash, h1);
    EXPECT_EQ(req.indexes, (std::vector<uint16_t>{2, 3}));
    EXPECT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2)));
    EXPECT_EQ(rig.delivered.size(), 1u);

    rig.deliver(2, p2p::message_blocktxn::make_raw(answer(req, b1)));
    ASSERT_EQ(rig.delivered.size(), 2u);
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_FALSE(rig.client.cmpct_parked_for_test(CmpctRig::key(2)));
}

TEST(DashCmpctClient, NotCompactWhileAnotherBodyIsInFlight)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    const BlockType bx = mk_block(hash_of(rig.b0), 77, 2);
    rig.client.request_block_tracked(hash_of(bx));   // something else in flight
    rig.sent.clear();
    rig.inv_block(1, hash_of(b1));
    auto gd = rig.sent_to(1, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0).first, kMsgBlock)
        << "dashcore asks compact only for the single block in flight";
}

TEST(DashCmpctClient, CompactOffWithoutChainViewAndMempool)
{
    CmpctRig rig(/*wire_compact=*/false);
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    rig.sent.clear();
    rig.inv_block(1, hash_of(b1));
    EXPECT_EQ(getdata_invs(rig.sent_to(1, "getdata").at(0)).at(0).first, kMsgBlock);
    EXPECT_TRUE(rig.sent_to(1, "sendcmpct").empty());
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.client.cmpct_gate_dropped(), 1u);
}

// ── high-bandwidth push ─────────────────────────────────────────────────────

TEST(DashCmpctClient, HighBandwidthPushIsReconstructedButNotCredited)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    ASSERT_TRUE(rig.client.cmpct_high_bandwidth_for_test(CmpctRig::key(1)));
    const uint64_t credited_before = rig.client.peer_delivered_for_test(CmpctRig::key(1));
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.add_to_pool(b1, {1, 2});
    rig.sent.clear();

    // Pushed unasked, before any inv.
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    ASSERT_EQ(rig.delivered.size(), 2u);
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_TRUE(rig.header_known_at_delivery.back());
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(1)), credited_before)
        << "a push we did not ask for earns no delivery credit";
    // The block is handled: a later inv for it is a duplicate, not a fetch.
    rig.inv_block(2, h1);
    EXPECT_TRUE(rig.sent_to(2, "getdata").empty());
}

TEST(DashCmpctClient, UnsolicitedPushFromNonHighBandwidthPeerIsOnlyAnAnnouncement)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    ASSERT_FALSE(rig.client.cmpct_high_bandwidth_for_test(CmpctRig::key(2)));
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.add_to_pool(b1, {1, 2});
    rig.sent.clear();

    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.delivered.size(), 1u) << "no InitData for an unasked, non-hb push";
    EXPECT_TRUE(rig.chain.idx.count(h1)) << "but its header is processed (fRevertToHeaderProcessing)";
    // ... and it is fetched like an announced block: compact, from that peer.
    auto gd = rig.sent_to(2, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgCmpctBlock, h1));
    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    EXPECT_EQ(rig.delivered.size(), 2u);
}

// ── the gate ────────────────────────────────────────────────────────────────

TEST(DashCmpctClient, ParentUnknownAsksForHeadersOnly)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType orphan = mk_block(hash_of(mk_block(uint256(), 55, 1)), 2, 2);
    rig.sent.clear();
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(orphan)));
    EXPECT_EQ(rig.sent_to(1, "getheaders").size(), 1u);
    EXPECT_FALSE(rig.chain.idx.count(hash_of(orphan)));
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(orphan)));
    EXPECT_EQ(rig.sent_to(1, "getheaders").size(), 1u) << "MaybeSendGetHeaders spacing";
}

TEST(DashCmpctClient, BadPowIsMisbehaviourAndDisconnects)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType bad = mk_block(hash_of(rig.b0), 9, 2, /*bits=*/0x1d00ffff, /*grind=*/false);
    ASSERT_FALSE(dash::coin::header_pow_meets_bits(hash_of(bad), bad.m_bits));
    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(bad)));
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 100);
    EXPECT_TRUE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(2)));
    EXPECT_FALSE(rig.chain.idx.count(hash_of(bad))) << "never fed to the header chain";
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    // A flagged peer is not processed any further ...
    const size_t sent_before = rig.sent.size();
    rig.deliver(2, p2p::message_ping::make_raw(7));
    EXPECT_EQ(rig.sent.size(), sent_before) << "no pong to a flagged peer";
    // ... and the next pool tick disconnects it.
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.peer_session(CmpctRig::key(2)), nullptr);
    EXPECT_EQ(rig.client.misbehavior_disconnects(), 1u);
}

TEST(DashCmpctClient, HeaderRefusedByTheChainIsNotReconstructed)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    rig.chain.refuse = true;
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.delivered.size(), 1u);
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(1)), 0)
        << "a chain-context refusal is not punished";
}

TEST(DashCmpctClient, HeldBodyIsNotReconstructedAgain)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    rig.add_to_pool(b1, {1});
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    ASSERT_EQ(rig.delivered.size(), 2u);
    rig.deliver(1, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    EXPECT_EQ(rig.delivered.size(), 2u);
}

// ── hostile compact data ────────────────────────────────────────────────────

TEST(DashCmpctClient, InvalidCmpctblockMisbehavesAndFetchesFullFromAnotherPeer)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.inv_block(2, h1);
    ASSERT_TRUE(rig.client.cmpct_requested_from_for_test(h1, CmpctRig::key(2)));
    rig.sent.clear();
    // prefilled at absolute index 3 past 2 short ids + 0: READ_STATUS_INVALID.
    rig.deliver(2, raw_cmpct(b1, {1, 2}, {{3, b1.m_txs[0]}}));
    EXPECT_EQ(rig.client.cmpct_rejected(), 1u);
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 100);
    EXPECT_TRUE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(2)));
    auto gd = rig.sent_to(1, "getdata");
    ASSERT_EQ(gd.size(), 1u) << "the block still comes, from another peer";
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));
    rig.deliver(1, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
}

TEST(DashCmpctClient, DuplicateShortIdsFetchTheFullBlockFromTheSamePeer)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.inv_block(2, h1);
    rig.sent.clear();
    rig.deliver(2, raw_cmpct(b1, {0xabc, 0xabc}, {{0, b1.m_txs[0]}}));
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 0)
        << "READ_STATUS_FAILED is a collision, not misbehaviour";
    auto gd = rig.sent_to(2, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));
}

TEST(DashCmpctClient, OverLongBlocktxnMisbehavesAndFetchesFullElsewhere)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.inv_block(2, h1);
    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 1u);
    PackStream ps(gbt[0].payload);
    v::BlockTransactionsRequest req;
    ps >> req;
    auto resp = answer(req, b1);
    resp.txn.push_back(v::MakeTransactionRef(mk_tx(4242)));
    rig.sent.clear();
    rig.deliver(2, p2p::message_blocktxn::make_raw(resp));
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 100);
    auto gd = rig.sent_to(1, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));
    EXPECT_EQ(rig.delivered.size(), 1u);
}

TEST(DashCmpctClient, OversizedCmpctblockIsDroppedAtParse)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 1);
    std::vector<uint64_t> ids(65536);
    for (size_t i = 0; i < ids.size(); ++i) ids[i] = i + 1;
    rig.deliver(1, raw_cmpct(b1, ids, {}));   // > 0xffff entries: refused by the codec
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.delivered.size(), 1u);
    EXPECT_NE(rig.client.peer_session(CmpctRig::key(1)), nullptr) << "read loop preserved";
}

// ── the timeout is the lost-body watchdog ───────────────────────────────────

TEST(DashCmpctClient, StalledBlocktxnFallsBackToFullBlockFromAnotherPeer)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.inv_block(2, h1);
    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 1u);
    ASSERT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2)));
    ASSERT_EQ(rig.client.pending_body_count(), 1u);
    rig.sent.clear();

    rig.run_seconds(2);   // BODY_STALL_TIMEOUT_INIT
    EXPECT_FALSE(rig.client.cmpct_parked_for_test(CmpctRig::key(2)));
    EXPECT_GE(rig.client.cmpct_fallbacks(), 1u);
    auto gd = rig.sent_to(1, "getdata");
    ASSERT_EQ(gd.size(), 1u) << "full block from ANOTHER peer";
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));

    // The late blocktxn is now unrequested and ignored.
    PackStream ps(gbt[0].payload);
    v::BlockTransactionsRequest req;
    ps >> req;
    rig.deliver(2, p2p::message_blocktxn::make_raw(answer(req, b1)));
    EXPECT_EQ(rig.delivered.size(), 1u);
    rig.deliver(1, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.pending_body_count(), 0u);
}

// ── teardown and serving ────────────────────────────────────────────────────

TEST(DashCmpctClient, DisconnectClearsCompactState)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    rig.inv_block(2, hash_of(b1));
    rig.deliver(2, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b1)));
    ASSERT_EQ(rig.client.cmpct_parked_count_for_test(), 1u);
    ASSERT_EQ(rig.client.cmpct_high_bandwidth_count_for_test(), 1u);
    rig.client.disconnect();
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.client.cmpct_high_bandwidth_count_for_test(), 0u);
    EXPECT_FALSE(rig.client.cmpct_requested_from_for_test(hash_of(b1), CmpctRig::key(2)));
}

TEST(DashCmpctClient, ServesCmpctblockAndBlocktxnForHeldBlocks)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const uint256 h0 = hash_of(rig.b0);
    rig.sent.clear();
    // One answer per held block per message, however often it is repeated.
    rig.deliver(2, p2p::message_getdata::make_raw(
        {p2p::inventory_type(p2p::DASH_MSG_CMPCT_BLOCK, h0),
         p2p::inventory_type(p2p::DASH_MSG_CMPCT_BLOCK, h0),
         p2p::inventory_type(p2p::DASH_MSG_CMPCT_BLOCK, h0)}));
    auto cb = rig.sent_to(2, "cmpctblock");
    ASSERT_EQ(cb.size(), 1u);
    PackStream ps(cb[0].payload);
    v::CBlockHeaderAndShortTxIDs got;
    ps >> got;
    EXPECT_EQ(x11_of(got.header), h0);
    EXPECT_EQ(got.BlockTxCount(), rig.b0.m_txs.size());

    v::BlockTransactionsRequest req;
    req.blockhash = h0;
    req.indexes = {1};
    rig.deliver(2, p2p::message_getblocktxn::make_raw(req));
    auto bt = rig.sent_to(2, "blocktxn");
    ASSERT_EQ(bt.size(), 1u);
    PackStream ps2(bt[0].payload);
    v::BlockTransactions txn;
    ps2 >> txn;
    ASSERT_EQ(txn.txn.size(), 1u);
    EXPECT_EQ(dash::coin::dash_txid(*txn.txn[0]), dash::coin::dash_txid(rig.b0.m_txs[1]));

    // dashcore: an index past the block is Misbehaving(100).
    req.indexes = {9};
    rig.deliver(2, p2p::message_getblocktxn::make_raw(req));
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 100);
    // A block we do not hold is not served.
    rig.sent.clear();
    rig.deliver(1, p2p::message_getdata::make_raw(
        {p2p::inventory_type(p2p::DASH_MSG_CMPCT_BLOCK, uint256::ONE)}));
    EXPECT_TRUE(rig.sent_to(1, "cmpctblock").empty());
}
