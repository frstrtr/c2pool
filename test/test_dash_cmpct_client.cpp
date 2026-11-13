// SPDX-License-Identifier: AGPL-3.0-or-later
// #968a KAT: BIP 152 compact blocks THROUGH THE COINCLIENT HANDLERS.
//
// test_dash_compact_block_receive.cpp drives the pure receiver. This TU drives
// the real CoinClient<dash::Config>: raw messages in through handle() (the
// socket demux), every write out through the test write tap, the header chain
// as a fake CompactChainView fed ONLY by the client's headers handler (the
// normal getheaders path), and a real Mempool behind
// make_mempool_short_id_provider. It pins:
//   * the request: a new tip body is asked for as getdata(MSG_CMPCT_BLOCK=20)
//     from the announcer once bodies are caught up, never before, never while
//     another body is in flight, never with --embedded-compact-blocks=false;
//   * solicited only: a cmpctblock is processed only as the answer to our own
//     getdata to that peer, for a header already in the chain; nothing from a
//     cmpctblock ever reaches the header chain; we send no sendcmpct and
//     serve nothing;
//   * getblocktxn / blocktxn round trip, parks per (peer, block), a blocktxn
//     of the wrong size ignored (never punished);
//   * hostile input: InitData INVALID, duplicate short ids, Misbehaving(100)
//     -> disconnect, never for a protected peer or our last peer;
//   * bind first: a body that does not bind to its header touches nothing;
//   * credit only for the asked peer, and no peer takes another's ask;
//   * the lost-body watchdog as the compact timeout; disconnect().

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

bool pow_meets_bits(const uint256& h, uint32_t bits)
{
    bool neg = false, ovf = false;
    uint256 target;
    target.SetCompact(bits, &neg, &ovf);
    return !neg && !ovf && !target.IsNull() && h <= target;
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
BlockType mk_block(const uint256& prev, uint32_t tag, size_t ntx)
{
    BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_timestamp = 1'700'000'000u + tag;
    b.m_bits = kEasyBits;
    b.m_txs.push_back(mk_coinbase(tag));
    for (size_t i = 1; i < ntx; ++i)
        b.m_txs.push_back(mk_tx(tag * 1000 + static_cast<uint32_t>(i)));
    std::vector<uint256> ids;
    for (const auto& t : b.m_txs) ids.push_back(dash::coin::dash_txid(t));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
    for (uint32_t n = 0;; ++n) {
        b.m_nonce = n;
        if (pow_meets_bits(x11_of(b), b.m_bits)) break;
    }
    return b;
}

uint256 hash_of(const BlockType& b) { return x11_of(b); }

// The header chain the gate reads. Fed ONLY through the client's headers
// handler (the new_headers event); accepts a header whose parent it holds.
struct FakeChain
{
    std::map<uint256, dash::coin::CompactChainEntry> idx;
    uint256 tip;
    size_t headers_fed{0};

    void add_base(const BlockType& b, uint32_t height)
    {
        const uint256 h = hash_of(b);
        idx[h] = dash::coin::CompactChainEntry{height, uint256::ONE, b.m_previous_block};
        tip = h;
    }

    void on_headers(const std::vector<BlockHeaderType>& hs)
    {
        for (const auto& hdr : hs) {
            ++headers_fed;
            const uint256 h = x11_of(hdr);
            if (idx.count(h)) continue;
            auto prev = idx.find(hdr.m_previous_block);
            if (prev == idx.end()) continue;
            if (!pow_meets_bits(h, hdr.m_bits)) continue;
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

v::BlockTransactionsRequest getblocktxn_of(const Sent& s)
{
    PackStream ps(s.payload);
    v::BlockTransactionsRequest req;
    ps >> req;
    return req;
}

// Restores the process-wide --embedded-compact-blocks flag.
struct CompactSwitchGuard
{
    bool saved{dash::coin::embedded_compact_blocks_enabled()};
    ~CompactSwitchGuard() { dash::coin::set_embedded_compact_blocks_enabled(saved); }
};

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

    void deliver_from(const NetService& a, std::unique_ptr<RawMessage> m) { client.handle(std::move(m), a); }
    void deliver(int n, std::unique_ptr<RawMessage> m) { deliver_from(peer_addr(n), std::move(m)); }

    // version / verack, then the peer's own sendcmpct(0, 1) as dashcore sends
    // it at VERACK (it provides compact blocks).
    void handshake_at(const NetService& a, bool peer_sends_sendcmpct = true)
    {
        client.attach_peer_for_test(a);
        deliver_from(a, p2p::message_version::make_raw(
            70230, /*services=*/1, 1234567890ull,
            addr_t{1, NetService{"127.0.0.1", 19999}},
            addr_t{1, NetService{"127.0.0.1", 19999}},
            0x1122334455667788ull, "/Dash Core:24.0.0/", 1000));
        deliver_from(a, p2p::message_verack::make_raw());
        if (peer_sends_sendcmpct)
            deliver_from(a, p2p::message_sendcmpct::make_raw(false, 1));
    }
    void handshake(int n, bool peer_sends_sendcmpct = true) { handshake_at(peer_addr(n), peer_sends_sendcmpct); }

    void inv_block(int n, const uint256& h)
    {
        deliver(n, p2p::message_inv::make_raw(
            {p2p::inventory_type(p2p::inventory_type::block, h)}));
    }

    // The getheaders reply: the header reaches the chain the normal way.
    void headers_from(int n, const BlockType& b)
    {
        BlockType h = b;
        h.m_txs.clear();
        deliver(n, p2p::message_headers::make_raw(std::vector<BlockType>{h}));
    }

    // inv, then the header (the reply to the getheaders the inv triggers;
    // same stream, so it lands before the body reply).
    void announce(int n, const BlockType& b)
    {
        inv_block(n, hash_of(b));
        headers_from(n, b);
    }

    void cmpct(int n, const BlockType& b)
    {
        deliver(n, p2p::message_cmpctblock::make_raw(v::CBlockHeaderAndShortTxIDs(b)));
    }

    // Cold start: the first tip body arrives whole (no body tip yet).
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
    size_t sent_cmd(const std::string& cmd) const
    {
        size_t n = 0;
        for (const auto& s : sent) if (s.cmd == cmd) ++n;
        return n;
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

// ── we send nothing, we serve nothing ───────────────────────────────────────

TEST(DashCmpctClient, NoSendcmpctEverAndNothingServed)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    rig.add_to_pool(b1, {1, 2});
    rig.announce(2, b1);
    rig.cmpct(2, b1);
    ASSERT_EQ(rig.delivered.size(), 2u);
    EXPECT_EQ(rig.sent_cmd("sendcmpct"), 0u)
        << "no sendcmpct: receiving by getdata(MSG_CMPCT_BLOCK) needs none, and we serve none";
    // A peer asking us for a compact block or its txs gets nothing.
    rig.sent.clear();
    rig.deliver(2, p2p::message_getdata::make_raw(
        {p2p::inventory_type(p2p::DASH_MSG_CMPCT_BLOCK, hash_of(rig.b0))}));
    v::BlockTransactionsRequest req;
    req.blockhash = hash_of(rig.b0);
    req.indexes = {1};
    rig.deliver(2, p2p::message_getblocktxn::make_raw(req));
    EXPECT_TRUE(rig.sent.empty()) << "no serving: no cmpctblock, no blocktxn";
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 0);
}

// ── the request ─────────────────────────────────────────────────────────────

TEST(DashCmpctClient, ColdStartFetchesTheFirstBodyWhole)
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
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(1)), 1u);
}

TEST(DashCmpctClient, NewTipIsRequestedCompactAndDeliveredAfterItsHeader)
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
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgCmpctBlock, h1))
        << "the next tip is fetched as MSG_CMPCT_BLOCK, from the announcer";
    EXPECT_TRUE(rig.client.cmpct_requested_from_for_test(h1, CmpctRig::key(2)));

    rig.headers_from(2, b1);   // the getheaders reply, same stream, first
    const size_t fed = rig.chain.headers_fed;
    rig.cmpct(2, b1);
    EXPECT_EQ(rig.chain.headers_fed, fed) << "nothing from a cmpctblock reaches the header chain";
    ASSERT_EQ(rig.delivered.size(), 2u);
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_TRUE(rig.header_known_at_delivery.back());
    EXPECT_EQ(rig.client.cmpct_reconstructed(), 1u);
    EXPECT_EQ(rig.client.pending_body_count(), 0u);
    EXPECT_TRUE(rig.sent_to(2, "getblocktxn").empty()) << "the mempool held every tx";
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(2)), 1u)
        << "asked-for body: credited";
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

    rig.announce(2, b1);
    rig.cmpct(2, b1);
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 1u);
    const auto req = getblocktxn_of(gbt[0]);
    EXPECT_EQ(req.blockhash, h1);
    EXPECT_EQ(req.indexes, (std::vector<uint16_t>{2, 3}));
    EXPECT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2), h1));
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

TEST(DashCmpctClient, OffWithoutChainViewAndMempool)
{
    CmpctRig rig(/*wire_compact=*/false);
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    rig.sent.clear();
    rig.inv_block(1, hash_of(b1));
    EXPECT_EQ(getdata_invs(rig.sent_to(1, "getdata").at(0)).at(0).first, kMsgBlock);
    rig.cmpct(1, b1);
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.client.cmpct_unsolicited(), 1u);
}

// --embedded-compact-blocks=false: the canary kill switch, no rebuild.
TEST(DashCmpctClient, SwitchOffFetchesWholeAndDropsCmpctblock)
{
    CompactSwitchGuard guard;
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    ASSERT_TRUE(rig.client.compact_blocks_enabled());
    dash::coin::set_embedded_compact_blocks_enabled(false);
    EXPECT_FALSE(rig.client.compact_blocks_enabled());
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    const uint256 h1 = hash_of(b1);
    rig.add_to_pool(b1, {1});
    rig.sent.clear();
    rig.announce(2, b1);
    EXPECT_EQ(getdata_invs(rig.sent_to(2, "getdata").at(0)).at(0), std::make_pair(kMsgBlock, h1));
    rig.cmpct(2, b1);
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.delivered.size(), 1u) << "a cmpctblock is dropped while the switch is off";
    rig.deliver(2, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_NE(rig.client.compact_status().find("enabled=0"), std::string::npos);
}

// ── solicited only ──────────────────────────────────────────────────────────

TEST(DashCmpctClient, UnsolicitedCmpctblockIsDroppedAndNeverFedToTheChain)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);   // valid PoW, connects
    rig.add_to_pool(b1, {1, 2});
    rig.sent.clear();
    const size_t fed = rig.chain.headers_fed;
    rig.cmpct(1, b1);
    EXPECT_EQ(rig.client.cmpct_unsolicited(), 1u);
    EXPECT_EQ(rig.chain.headers_fed, fed);
    EXPECT_FALSE(rig.chain.idx.count(hash_of(b1))) << "the header never reaches the chain";
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_EQ(rig.delivered.size(), 1u);
    EXPECT_TRUE(rig.sent.empty()) << "no getheaders, no getdata, nothing";
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(1)), 0);
}

TEST(DashCmpctClient, CmpctblockFromAPeerWeDidNotAskIsDropped)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.add_to_pool(b1, {1, 2});
    rig.announce(2, b1);                 // we asked peer 2
    ASSERT_TRUE(rig.client.cmpct_requested_from_for_test(h1, CmpctRig::key(2)));
    rig.cmpct(1, b1);                    // peer 1 answers instead
    EXPECT_EQ(rig.client.cmpct_unsolicited(), 1u);
    EXPECT_EQ(rig.delivered.size(), 1u);
    rig.cmpct(2, b1);                    // the asked peer
    EXPECT_EQ(rig.delivered.size(), 2u);
}

TEST(DashCmpctClient, AnswerBeforeItsHeaderFetchesTheFullBlock)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.inv_block(2, h1);                // asked compact, header not in yet
    rig.sent.clear();
    rig.cmpct(2, b1);                    // the answer races ahead of the header
    EXPECT_FALSE(rig.chain.idx.count(h1)) << "never fed from the cmpctblock";
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    auto gd = rig.sent_to(2, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));
    rig.headers_from(2, b1);
    rig.deliver(2, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
}

TEST(DashCmpctClient, HeldBodyIsNotReconstructedAgain)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    rig.add_to_pool(b1, {1});
    rig.announce(1, b1);
    rig.cmpct(1, b1);
    ASSERT_EQ(rig.delivered.size(), 2u);
    rig.cmpct(1, b1);   // our ask is spent: a repeat is unsolicited
    EXPECT_EQ(rig.delivered.size(), 2u);
    EXPECT_EQ(rig.client.cmpct_unsolicited(), 1u);
}

// ── parks per (peer, block); blocktxn of the wrong size ─────────────────────

TEST(DashCmpctClient, OnePeerCanHaveTwoBlocksParked)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const BlockType b1x = mk_block(hash_of(rig.b0), 2, 3);   // a sibling
    rig.headers_from(2, b1);
    rig.headers_from(2, b1x);
    ASSERT_TRUE(rig.client.request_compact_from_for_test(CmpctRig::key(2), hash_of(b1)));
    ASSERT_TRUE(rig.client.request_compact_from_for_test(CmpctRig::key(2), hash_of(b1x)));
    rig.cmpct(2, b1);
    rig.cmpct(2, b1x);
    EXPECT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2), hash_of(b1)));
    EXPECT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2), hash_of(b1x)));
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 2u);
    rig.deliver(2, p2p::message_blocktxn::make_raw(answer(getblocktxn_of(gbt[0]), b1)));
    rig.deliver(2, p2p::message_blocktxn::make_raw(answer(getblocktxn_of(gbt[1]), b1x)));
    ASSERT_EQ(rig.delivered.size(), 3u);
    EXPECT_EQ(rig.delivered[1], hash_of(b1));
    EXPECT_EQ(rig.delivered[2], hash_of(b1x));
}

TEST(DashCmpctClient, BlocktxnOfTheWrongSizeIsIgnoredNeverPunished)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 4);
    const uint256 h1 = hash_of(b1);
    rig.announce(2, b1);
    rig.cmpct(2, b1);
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 1u);
    const auto req = getblocktxn_of(gbt[0]);
    auto longer = answer(req, b1);
    longer.txn.push_back(v::MakeTransactionRef(mk_tx(4242)));
    auto shorter = answer(req, b1);
    shorter.txn.pop_back();
    rig.deliver(2, p2p::message_blocktxn::make_raw(longer));
    rig.deliver(2, p2p::message_blocktxn::make_raw(shorter));
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 0);
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(2)));
    EXPECT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2), h1)) << "park kept";
    EXPECT_EQ(rig.delivered.size(), 1u);
    rig.deliver(2, p2p::message_blocktxn::make_raw(answer(req, b1)));   // the right one
    EXPECT_EQ(rig.delivered.back(), h1);
}

// ── hostile compact data and Misbehaving ────────────────────────────────────

TEST(DashCmpctClient, InvalidCmpctblockMisbehavesAndFetchesFullFromAnotherPeer)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.announce(2, b1);
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
    // A flagged peer is not processed any further ...
    const size_t before = rig.sent.size();
    rig.deliver(2, p2p::message_ping::make_raw(7));
    EXPECT_EQ(rig.sent.size(), before) << "no pong to a flagged peer";
    // ... the next pool tick disconnects it, and the block arrives.
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.peer_session(CmpctRig::key(2)), nullptr);
    EXPECT_EQ(rig.client.misbehavior_disconnects(), 1u);
    rig.deliver(1, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
}

TEST(DashCmpctClient, ProtectedPeerIsNeverDisconnected)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.client.set_protected_peer_keys({CmpctRig::key(2)});   // --coin-p2p-connect
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    rig.announce(2, b1);
    rig.deliver(2, raw_cmpct(b1, {1, 2}, {{3, b1.m_txs[0]}}));
    EXPECT_EQ(rig.client.cmpct_rejected(), 1u);
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(2)));
    EXPECT_EQ(rig.client.misbehavior_spared(), 1u);
    rig.run_seconds(1);
    EXPECT_NE(rig.client.peer_session(CmpctRig::key(2)), nullptr);
}

TEST(DashCmpctClient, LocalDashdIsNeverDisconnected)
{
    CmpctRig rig;
    const NetService local{"127.0.0.1", 19999};
    rig.handshake_at(local);
    rig.handshake(2);
    rig.client.misbehaving_for_test(local.to_string(), 100);
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(local.to_string()));
    const NetService lan{"10.1.2.3", 9999};
    rig.handshake_at(lan);
    rig.client.misbehaving_for_test(lan.to_string(), 100);
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(lan.to_string()));
    EXPECT_EQ(rig.client.misbehavior_spared(), 2u);
}

TEST(DashCmpctClient, LastPeerIsNeverDisconnected)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.client.misbehaving_for_test(CmpctRig::key(1), 100);
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(1)));
    EXPECT_EQ(rig.client.misbehavior_spared(), 1u);
    rig.handshake(2);
    rig.client.misbehaving_for_test(CmpctRig::key(2), 100);
    EXPECT_TRUE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(2)))
        << "with another peer up, a public peer is disconnected";
    // A peer on its way out is no alternative: peer 1 is spared again ...
    rig.client.misbehaving_for_test(CmpctRig::key(1), 10);
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(1)));
    // ... and cut on its next offence once a healthy peer is up.
    rig.handshake(3);
    rig.client.misbehaving_for_test(CmpctRig::key(1), 10);
    EXPECT_TRUE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(1)));
    EXPECT_EQ(rig.client.misbehavior_spared(), 2u);
}

TEST(DashCmpctClient, DuplicateShortIdsFetchTheFullBlockFromTheSamePeer)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.announce(2, b1);
    rig.sent.clear();
    rig.deliver(2, raw_cmpct(b1, {0xabc, 0xabc}, {{0, b1.m_txs[0]}}));
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 0)
        << "READ_STATUS_FAILED is a collision, not misbehaviour";
    auto gd = rig.sent_to(2, "getdata");
    ASSERT_EQ(gd.size(), 1u);
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));
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

// ── bind first, credit only the asked peer ──────────────────────────────────

TEST(DashCmpctClient, BodyThatDoesNotBindTouchesNothing)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    rig.client.request_block_tracked(hash_of(mk_block(hash_of(rig.b0), 9, 2)));  // body in flight -> full fetch
    rig.announce(2, b1);
    ASSERT_EQ(rig.client.pending_body_count(), 2u);
    const uint64_t credit = rig.client.peer_delivered_for_test(CmpctRig::key(2));
    BlockType forged = b1;               // b1's header, other txs
    forged.m_txs[1] = mk_tx(31337);
    ASSERT_EQ(hash_of(forged), h1);
    rig.deliver(2, p2p::message_block::make_raw(forged));
    EXPECT_EQ(rig.client.bodies_unbound(), 1u);
    EXPECT_EQ(rig.delivered.size(), 1u);
    EXPECT_FALSE(rig.client.have_body_for_test(h1));
    EXPECT_EQ(rig.client.pending_body_count(), 2u) << "the watchdog still wants it";
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(2)), credit) << "no credit";
    // The real body still credits the peer we asked (its ask was not consumed).
    rig.deliver(2, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(2)), credit + 1);
}

TEST(DashCmpctClient, UnaskedDeliveryDoesNotTakeAnotherPeersAsk)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const uint64_t c1 = rig.client.peer_delivered_for_test(CmpctRig::key(1));
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 2);
    rig.client.request_block_tracked(hash_of(mk_block(hash_of(rig.b0), 9, 2)));  // force MSG_BLOCK
    rig.announce(1, b1);                 // asked peer 1
    rig.deliver(2, p2p::message_block::make_raw(b1));   // peer 2 delivers, unasked
    EXPECT_EQ(rig.delivered.back(), hash_of(b1));
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(2)), 0u) << "unasked: no credit";
    rig.deliver(1, p2p::message_block::make_raw(b1));   // the asked peer, late
    EXPECT_EQ(rig.client.peer_delivered_for_test(CmpctRig::key(1)), c1 + 1)
        << "peer 1's ask survived peer 2's delivery";
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
    rig.announce(2, b1);
    rig.cmpct(2, b1);
    auto gbt = rig.sent_to(2, "getblocktxn");
    ASSERT_EQ(gbt.size(), 1u);
    ASSERT_TRUE(rig.client.cmpct_parked_for_test(CmpctRig::key(2), h1));
    ASSERT_EQ(rig.client.pending_body_count(), 1u);
    rig.sent.clear();

    rig.run_seconds(2);   // BODY_STALL_TIMEOUT_INIT
    EXPECT_FALSE(rig.client.cmpct_parked_for_test(CmpctRig::key(2)));
    EXPECT_GE(rig.client.cmpct_fallbacks(), 1u);
    auto gd = rig.sent_to(1, "getdata");
    ASSERT_EQ(gd.size(), 1u) << "full block from ANOTHER peer";
    EXPECT_EQ(getdata_invs(gd[0]).at(0), std::make_pair(kMsgBlock, h1));

    // The late blocktxn is now unrequested and ignored.
    rig.deliver(2, p2p::message_blocktxn::make_raw(answer(getblocktxn_of(gbt[0]), b1)));
    EXPECT_EQ(rig.delivered.size(), 1u);
    rig.deliver(1, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.pending_body_count(), 0u);
}

TEST(DashCmpctClient, DisconnectClearsCompactState)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.handshake(2);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    rig.announce(2, b1);
    rig.cmpct(2, b1);
    ASSERT_EQ(rig.client.cmpct_parked_count_for_test(), 1u);
    rig.client.disconnect();
    EXPECT_EQ(rig.client.cmpct_parked_count_for_test(), 0u);
    EXPECT_FALSE(rig.client.cmpct_requested_from_for_test(hash_of(b1), CmpctRig::key(2)));
}

// ── N1: a body that does not bind is an answer, not a stall ─────────────────

// The block every honest peer serves, whose header merkle root our txids do
// not reproduce: what a tx type we hash unlike Dash Core looks like from here.
static BlockType mk_unbindable_block(const uint256& prev, uint32_t tag, size_t ntx)
{
    BlockType b = mk_block(prev, tag, ntx);
    b.m_merkle_root.data()[0] ^= 0x01;
    for (uint32_t n = 0;; ++n) {
        b.m_nonce = n;
        if (pow_meets_bits(x11_of(b), b.m_bits)) break;
    }
    return b;
}

// Peer number of a rig key ("192.0.2.N:19999"), 0 when unknown.
static int peer_no(const std::string& key)
{
    for (int n = 1; n <= 16; ++n) if (CmpctRig::key(n) == key) return n;
    return 0;
}

// Answer every getdata for `h` sent since `seen` (MSG_BLOCK or
// MSG_CMPCT_BLOCK) at once, from the peer that was asked, with `body_of(n)` as
// a full block. Returns how many asks were answered.
// A re-ask loop would never drain `sent`; `max_answers` turns that into a
// failed bound instead of a hung test.
template <typename BodyOf>
static size_t answer_asks(CmpctRig& rig, size_t& seen, const uint256& h, BodyOf body_of,
                          size_t max_answers = 1000)
{
    size_t answered = 0;
    while (seen < rig.sent.size() && answered < max_answers) {
        const Sent s = rig.sent[seen++];   // copy: deliver() appends to sent
        if (s.cmd != "getdata") continue;
        for (const auto& [type, ih] : getdata_invs(s)) {
            if (ih != h || (type != kMsgBlock && type != kMsgCmpctBlock)) continue;
            const int n = peer_no(s.key);
            if (n == 0) continue;
            rig.deliver(n, p2p::message_block::make_raw(body_of(n)));
            ++answered;
        }
    }
    return answered;
}

TEST(DashCmpctClient, SelfBindFaultNeverEvictsHonestPeers)
{
    CmpctRig rig;
    for (int n = 1; n <= 4; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_unbindable_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    size_t seen = rig.sent.size();
    rig.announce(2, b1);
    auto honest = [&](int) { return b1; };
    size_t answers = answer_asks(rig, seen, h1, honest);
    EXPECT_TRUE(rig.client.self_bind_fault_for_test(h1))
        << "the first non-binding answer re-asks another peer at once; the second latches";
    for (int s = 0; s < 120; ++s) {
        rig.run_seconds(1);
        answers += answer_asks(rig, seen, h1, honest);
    }
    EXPECT_EQ(rig.client.self_bind_faults(), 1u);
    EXPECT_EQ(rig.client.self_bind_faults_active(), 1u);
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u) << "no honest peer evicted as a staller";
    EXPECT_EQ(rig.client.misbehavior_disconnects(), 0u);
    EXPECT_EQ(rig.client.unbound_blamed(), 0u);
    for (int n = 1; n <= 4; ++n)
        EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(n))) << n;
    EXPECT_EQ(rig.client.handshaked_peer_keys().size(), 4u);
    EXPECT_EQ(rig.delivered.size(), 1u) << "never ingested: the embedded arm stays fail-closed on it";
    EXPECT_FALSE(rig.client.have_body_for_test(h1));
    EXPECT_EQ(rig.client.pending_body_count(), 1u) << "still wanted";
    EXPECT_GE(answers, 4u) << "every peer is asked once before anyone is re-asked";
    EXPECT_LE(answers, 10u) << "then backed off by doubling to 64 s, not a request loop";
    EXPECT_NE(rig.client.compact_status().find("self_bind_faults=1 self_bind_active=1"),
              std::string::npos);
}

TEST(DashCmpctClient, OneForgedAnswerReasksAtOnceThenTheForgerIsBlamed)
{
    CmpctRig rig;
    for (int n = 1; n <= 3; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    BlockType forged = b1;                 // b1's header, other txs
    forged.m_txs[1] = mk_tx(31337);
    ASSERT_EQ(hash_of(forged), h1);
    rig.announce(2, b1);
    ASSERT_GE(rig.sent_to(2, "getdata").size(), 1u);
    const size_t seen = rig.sent.size();
    rig.deliver(2, p2p::message_block::make_raw(forged));
    EXPECT_EQ(rig.client.bodies_unbound(), 1u);
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(2)), 0) << "not blamed yet";
    EXPECT_FALSE(rig.client.self_bind_fault_for_test(h1));
    // Re-asked from another peer at once, without waiting out a stall window.
    int reasked = 0;
    for (size_t i = seen; i < rig.sent.size(); ++i)
        if (rig.sent[i].cmd == "getdata" && rig.sent[i].key != CmpctRig::key(2))
            for (const auto& [type, ih] : getdata_invs(rig.sent[i]))
                if (ih == h1 && type == kMsgBlock) reasked = peer_no(rig.sent[i].key);
    ASSERT_NE(reasked, 0);
    rig.deliver(reasked, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.pending_body_count(), 0u);
    EXPECT_EQ(rig.client.unbound_blamed(), 1u);
    EXPECT_TRUE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(2)))
        << "dashcore BLOCK_MUTATED, applied once the real body bound";
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(reasked)));
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u);
}

TEST(DashCmpctClient, ForgersLatchThenTheRealBodyClearsItWithoutPenalty)
{
    CmpctRig rig;
    for (int n = 1; n <= 4; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    std::vector<int> forgers;
    // Every peer forges except peer 4, which serves the real block.
    auto body_of = [&](int n) {
        if (n == 4) return b1;
        if (std::find(forgers.begin(), forgers.end(), n) == forgers.end()) forgers.push_back(n);
        BlockType f = b1;
        f.m_txs[1] = mk_tx(40000 + static_cast<uint32_t>(n));
        return f;
    };
    size_t seen = rig.sent.size();
    rig.announce(2, b1);
    answer_asks(rig, seen, h1, body_of);
    // Each forged answer re-asks a peer that has not answered yet, at once:
    // the real body lands without a single stall window.
    ASSERT_EQ(rig.client.pending_body_count(), 0u) << "the real body was fetched without waiting";
    EXPECT_EQ(rig.delivered.back(), h1);
    ASSERT_EQ(forgers.size(), 3u);
    EXPECT_EQ(rig.client.self_bind_faults(), 1u) << "two forgers do latch";
    EXPECT_EQ(rig.client.self_bind_faults_active(), 0u) << "cleared with the slot";
    // A latched slot means our own codec was in doubt: no deferred penalty.
    EXPECT_EQ(rig.client.unbound_blamed(), 0u);
    for (int n = 1; n <= 4; ++n)
        EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(n))) << n;
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u);
}

TEST(DashCmpctClient, SevenForgersOfEightCostOneRoundTripEach)
{
    CmpctRig rig;
    for (int n = 1; n <= 8; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    auto body_of = [&](int n) {
        if (n == 8) return b1;
        BlockType f = b1;
        f.m_txs[1] = mk_tx(40000 + static_cast<uint32_t>(n));
        return f;
    };
    size_t seen = rig.sent.size();
    rig.announce(2, b1);
    answer_asks(rig, seen, h1, body_of);
    EXPECT_EQ(rig.client.pending_body_count(), 0u) << "no stall window between forged answers";
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u);
}

TEST(DashCmpctClient, HolSlotNeverReasksAForgerWhileAnHonestPeerIsLeft)
{
    CmpctRig rig;
    for (int n = 1; n <= 4; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    // Peer 1 (the best deliverer, from warm()) and peer 2 forge; 3 and 4 are honest.
    auto body_of = [&](int n) {
        if (n >= 3) return b1;
        BlockType f = b1;
        f.m_txs[1] = mk_tx(40000 + static_cast<uint32_t>(n));
        return f;
    };
    size_t seen = rig.sent.size();
    ASSERT_TRUE(rig.client.request_head_of_line_for_test(h1));
    answer_asks(rig, seen, h1, body_of);
    int secs = 0;
    for (; secs < 600 && rig.client.pending_body_count() > 0; ++secs) {
        rig.run_seconds(1);
        answer_asks(rig, seen, h1, body_of);
    }
    EXPECT_EQ(rig.client.pending_body_count(), 0u) << "the fold cursor body was fetched";
    EXPECT_LE(secs, 4) << "from an honest peer, not after rounds of re-asking the forgers";
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.hol_disconnects(), 0u);
}

TEST(DashCmpctClient, HolSlotStillDisconnectsSilentStallersButNotTheAnswerer)
{
    CmpctRig rig;
    for (int n = 1; n <= 4; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_unbindable_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    size_t seen = rig.sent.size();
    ASSERT_TRUE(rig.client.request_head_of_line_for_test(h1));
    int answerer = 0;   // the first peer asked answers (non-binding); the rest stay silent
    auto step = [&] {
        while (seen < rig.sent.size()) {
            const Sent s = rig.sent[seen++];
            if (s.cmd != "getdata") continue;
            for (const auto& [type, ih] : getdata_invs(s)) {
                if (ih != h1) continue;
                const int n = peer_no(s.key);
                if (answerer == 0) answerer = n;
                if (n == answerer) rig.deliver(n, p2p::message_block::make_raw(b1));
            }
        }
    };
    step();
    ASSERT_NE(answerer, 0);
    for (int s = 0; s < 300; ++s) { rig.run_seconds(1); step(); }
    EXPECT_GE(rig.client.hol_disconnects(), 1u) << "a silent head-of-line carrier is still a staller";
    EXPECT_FALSE(rig.client.flagged_for_disconnect_for_test(CmpctRig::key(answerer)));
    const auto keys = rig.client.handshaked_peer_keys();
    EXPECT_NE(std::find(keys.begin(), keys.end(), CmpctRig::key(answerer)), keys.end())
        << "the peer that answered is never evicted for this body";
}

TEST(DashCmpctClient, MorePeersThanTheOldAnswererCapStillBackOff)
{
    // Verify R1: a pool larger than the recorded-answerer cap must not turn
    // two unrecorded answerers into a re-ask loop with no clock in it.
    CmpctRig rig;
    rig.client.set_max_peers(12);
    for (int n = 1; n <= 12; ++n) rig.handshake(n);
    ASSERT_EQ(rig.client.handshaked_peer_keys().size(), 12u);
    rig.warm(1);
    const BlockType b1 = mk_unbindable_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    size_t seen = rig.sent.size();
    rig.announce(2, b1);
    auto honest = [&](int) { return b1; };
    size_t answers = answer_asks(rig, seen, h1, honest);
    EXPECT_LE(answers, 12u) << "each peer once, then no immediate re-ask";
    for (int s = 0; s < 120; ++s) {
        rig.run_seconds(1);
        answers += answer_asks(rig, seen, h1, honest);
    }
    EXPECT_LE(answers, 20u) << "12 first answers, then a doubling backoff";
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u);
    EXPECT_EQ(rig.client.handshaked_peer_keys().size(), 12u);
    EXPECT_TRUE(rig.client.self_bind_fault_for_test(h1));
}

TEST(DashCmpctClient, SinglePeerPoolLatchesToo)
{
    CmpctRig rig;
    rig.handshake(1);
    rig.warm(1);
    const BlockType b1 = mk_unbindable_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    size_t seen = rig.sent.size();
    rig.announce(1, b1);
    auto honest = [&](int) { return b1; };
    size_t answers = answer_asks(rig, seen, h1, honest);
    for (int s = 0; s < 300; ++s) { rig.run_seconds(1); answers += answer_asks(rig, seen, h1, honest); }
    EXPECT_EQ(rig.client.self_bind_faults(), 1u) << "the whole pool answered: loud alert";
    EXPECT_TRUE(rig.client.self_bind_fault_for_test(h1));
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u);
    EXPECT_EQ(rig.client.handshaked_peer_keys().size(), 1u);
    EXPECT_LE(answers, 10u) << "backed off";
}

TEST(DashCmpctClient, UndecodableBlockIsAnAnswerNotAStall)
{
    CmpctRig rig;
    for (int n = 1; n <= 4; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    size_t seen = rig.sent.size();
    rig.announce(2, b1);
    // Every peer answers with a `block` whose last tx is cut short: our codec
    // throws, as it would on a tx shape we cannot decode.
    auto answer_truncated = [&] {
        while (seen < rig.sent.size()) {
            const Sent s = rig.sent[seen++];
            if (s.cmd != "getdata") continue;
            for (const auto& [type, ih] : getdata_invs(s)) {
                if (ih != h1 || (type != kMsgBlock && type != kMsgCmpctBlock)) continue;
                const int n = peer_no(s.key);
                if (!n) continue;
                auto raw = p2p::message_block::make_raw(b1);
                auto bytes = bytes_of(raw->m_data);
                bytes.resize(bytes.size() - 3);
                PackStream ps(bytes);
                rig.deliver(n, std::make_unique<RawMessage>("block", std::move(ps)));
            }
        }
    };
    answer_truncated();
    for (int s = 0; s < 120; ++s) { rig.run_seconds(1); answer_truncated(); }
    EXPECT_GE(rig.client.bodies_undecodable(), 4u);
    EXPECT_TRUE(rig.client.self_bind_fault_for_test(h1));
    EXPECT_EQ(rig.client.body_stall_evictions(), 0u) << "honest peers are not stallers";
    EXPECT_EQ(rig.client.handshaked_peer_keys().size(), 4u);
    EXPECT_EQ(rig.delivered.size(), 1u) << "never ingested";
}

TEST(DashCmpctClient, UnaskedNonBindingBodyIsOnlyDropped)
{
    CmpctRig rig;
    for (int n = 1; n <= 3; ++n) rig.handshake(n);
    rig.warm(1);
    const BlockType b1 = mk_block(hash_of(rig.b0), 1, 3);
    const uint256 h1 = hash_of(b1);
    BlockType forged = b1;
    forged.m_txs[1] = mk_tx(31337);
    rig.announce(2, b1);
    rig.deliver(3, p2p::message_block::make_raw(forged));   // peer 3 was not asked
    rig.deliver(1, p2p::message_block::make_raw(forged));   // nor was peer 1
    EXPECT_EQ(rig.client.bodies_unbound(), 2u);
    EXPECT_FALSE(rig.client.self_bind_fault_for_test(h1)) << "unasked bodies never latch";
    rig.deliver(2, p2p::message_block::make_raw(b1));
    EXPECT_EQ(rig.delivered.back(), h1);
    EXPECT_EQ(rig.client.unbound_blamed(), 0u) << "only asked answerers are remembered";
    EXPECT_EQ(rig.client.misbehavior_for_test(CmpctRig::key(3)), 0);
}
