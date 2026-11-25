// The pooled coin connection over NodeP2P (impl/btc/coin/coin_peer_pool_p2p.hpp)
// and the two NodeP2P hooks the pool uses (impl/btc/coin/p2p_node.hpp), plus a
// source check that main_btc.cpp wires the pool into both won-block arms, the
// caught-up flag and the block-body check.
#include <gtest/gtest.h>

#include <impl/btc/coin/coin_peer_pool_p2p.hpp>
#include <impl/btc/coin/p2p_node.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef BTC_MAIN_SRC
#error "BTC_MAIN_SRC must be defined by CMake to the path of src/c2pool/main_btc.cpp"
#endif

using namespace btc::coin;

namespace {

/// What NodeP2P reads from its config: the network magic.
struct KatP2PConfig {
    struct P2P {
        std::vector<std::byte> prefix{std::byte{0xf9}, std::byte{0xbe}, std::byte{0xb4},
                                      std::byte{0xd9}};
        NetService address;
    };
    struct Coin {
        P2P m_p2p;
    };
    Coin m_coin;
    Coin* coin() { return &m_coin; }
};

using KatNode = p2p::NodeP2P<KatP2PConfig>;

uint256 kat_hash(uint32_t n)
{
    BlockHeaderType h;
    h.m_nonce = n;
    h.m_bits = 0x1d00ffff;
    return pool_header_hash(h);
}

size_t standalone_pos(const std::string& src) { return src.find("if (bitcoind_host.empty()) {"); }

std::string main_src_code()
{
    std::ifstream in(BTC_MAIN_SRC);
    EXPECT_TRUE(in.good()) << "cannot open " << BTC_MAIN_SRC;
    std::stringstream ss;
    ss << in.rdbuf();
    // Drop // comments so a mention in a comment does not count as wiring.
    std::string out;
    std::istringstream lines(ss.str());
    std::string line;
    while (std::getline(lines, line)) {
        const auto c = line.find("//");
        out += (c == std::string::npos ? line : line.substr(0, c)) + "\n";
    }
    return out;
}

} // namespace

// Every headers message reaches the count callback, an empty one included
// (new_headers fires only for a non-empty one).
TEST(BtcCoinPeerPoolP2P, HeadersMessageCountIncludesAnEmptyOne)
{
    boost::asio::io_context ioc;
    KatP2PConfig cfg;
    btc::interfaces::Node sink;
    auto node = std::make_shared<KatNode>(&ioc, &sink, &cfg, "kat");
    std::vector<size_t> counts;
    int new_headers = 0;
    sink.new_headers.subscribe([&](const std::vector<BlockHeaderType>&) { ++new_headers; });
    node->set_on_headers_message([&](size_t n) { counts.push_back(n); });
    node->handle(std::make_unique<RawMessage>("headers", PackStream(std::vector<unsigned char>{0x00})),
                 NetService("127.0.0.1", 8333));
    EXPECT_EQ(counts, std::vector<size_t>{0});
    EXPECT_EQ(new_headers, 0);
}

// The fetch filter is asked about every announced block and transaction; a
// "no" sends no getdata (this driver has no connection: a getdata would have
// nowhere to go).
TEST(BtcCoinPeerPoolP2P, FetchFilterIsAskedForAnnouncedBlocksAndTransactions)
{
    boost::asio::io_context ioc;
    KatP2PConfig cfg;
    btc::interfaces::Node sink;
    auto node = std::make_shared<KatNode>(&ioc, &sink, &cfg, "kat");
    std::vector<std::pair<uint256, bool>> asked;
    node->set_fetch_filter([&](const uint256& h, bool is_block) {
        asked.emplace_back(h, is_block);
        return false;
    });
    std::vector<uint256> announced;
    sink.new_block.subscribe([&](const uint256& h) { announced.push_back(h); });
    const uint256 bh = kat_hash(1);
    const uint256 th = kat_hash(2);
    const uint256 wh = kat_hash(3);
    using p2p::inventory_type;
    node->handle(p2p::message_inv::make_raw({inventory_type(inventory_type::block, bh),
                                             inventory_type(inventory_type::tx, th),
                                             inventory_type(inventory_type::wtx, wh)}),
                 NetService("127.0.0.1", 8333));
    ASSERT_EQ(asked.size(), 3u);
    EXPECT_EQ(asked[0], std::make_pair(bh, true));
    EXPECT_EQ(asked[1], std::make_pair(th, false));
    EXPECT_EQ(asked[2], std::make_pair(wh, false));
    EXPECT_EQ(announced, std::vector<uint256>{bh});
}

// A pooled driver is owned by a real shared_ptr: its enable_shared_from_this
// is set, so the sockets it makes (core::make_socket) track its lifetime and a
// completion after the connection was dropped aborts instead of calling into
// it. Its log label names the peer.
TEST(BtcCoinPeerPoolP2P, PooledDriverLifetimeIsTracked)
{
    boost::asio::io_context ioc;
    KatP2PConfig cfg;
    int headers = 0;
    PoolPeerHooks hooks;
    hooks.headers_message = [&](size_t) { ++headers; };
    {
        NodeP2PPoolPeer<KatP2PConfig> peer(&ioc, &cfg, NetService("127.0.0.1", 1), hooks);
        EXPECT_TRUE(peer.lifetime_managed());
        EXPECT_EQ(peer.label(), "CoinP2P 127.0.0.1:1");
        EXPECT_FALSE(peer.handshaked());
    }
    // The connection is gone while its dial is pending: the dial completes
    // (refused) against a driver kept alive by the dial-lifetime handle, then
    // the driver is freed.
    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_EQ(headers, 0);
}

// main_btc.cpp: both won-block arms reach the pool, the empty-headers rule sets
// the caught-up flag, pooled bodies are checked against their header and kept
// in chain order, and the driver polls the pool.
TEST(BtcCoinPeerPoolP2P, MainBtcWiresThePool)
{
    const std::string src = main_src_code();
    // Stratum won block: the pool first, then the unchanged connect path.
    const auto stratum = src.find("auto stratum_submit_fn = [&coin_node, &coin_pool");
    ASSERT_NE(stratum, std::string::npos);
    const auto pool_relay = src.find("coin_pool->broadcast_block(block_bytes)", stratum);
    const auto connect = src.find("coin_node.submit_block_for_connect(block_bytes)", stratum);
    ASSERT_NE(pool_relay, std::string::npos);
    ASSERT_NE(connect, std::string::npos);
    EXPECT_LT(pool_relay, connect);
    // Share-chain won block (m_on_block_found's P2P relay arm).
    const auto relay = src.find("/*relay_p2p=*/[&ioc, coin = &coin_node, pool = &coin_pool]");
    ASSERT_NE(relay, std::string::npos);
    const auto relay_pool = src.find("(*pool)->broadcast_block(b)", relay);
    const auto relay_coin = src.find("coin->submit_block_p2p_raw(b)", relay);
    ASSERT_NE(relay_pool, std::string::npos);
    ASSERT_NE(relay_coin, std::string::npos);
    EXPECT_LT(relay_pool - relay, 600u);
    // The empty-headers rule feeds the same caught-up flag the driver reads.
    const auto empty = src.find("ph.on_empty_headers = [hdr_caught_up]");
    ASSERT_NE(empty, std::string::npos);
    EXPECT_NE(src.find("*hdr_caught_up = true;", empty), std::string::npos);
    EXPECT_LT(src.find("*hdr_caught_up = true;", empty) - empty, 400u);
    EXPECT_NE(src.find("ph.caught_up = [hdr_caught_up]() { return *hdr_caught_up; };"),
              std::string::npos);
    // Bodies: the header check and the UTXO set's best height.
    EXPECT_NE(src.find("return btc::coin::block_body_matches_header(b);"), std::string::npos);
    const auto best = src.find("ph.body_best_height = [&utxo_cache]");
    ASSERT_NE(best, std::string::npos);
    EXPECT_NE(src.find("utxo_cache.get_best()", best), std::string::npos);
    // The UTXO connect: the existing full_block subscriber with --bitcoind,
    // the pool's chain-ordered hook without it (and the subscriber then
    // leaves it to the pool).
    const auto connect_fn = src.find("auto utxo_connect_block =");
    ASSERT_NE(connect_fn, std::string::npos);
    const auto sub = src.find("[utxo_connect_block, utxo_connect_by_pool](const btc::coin::BlockType& block)",
                              connect_fn);
    ASSERT_NE(sub, std::string::npos);
    const auto skip = src.find("if (*utxo_connect_by_pool) return;", sub);
    ASSERT_NE(skip, std::string::npos);
    EXPECT_LT(skip - sub, 200u);
    EXPECT_NE(src.find("utxo_connect_block(block);", skip), std::string::npos);
    const auto by_pool = src.find("*utxo_connect_by_pool = true;");
    ASSERT_NE(by_pool, std::string::npos);
    EXPECT_LT(standalone_pos(src), by_pool);
    EXPECT_NE(src.find("ph.on_body_in_order = utxo_connect_block;", by_pool), std::string::npos);
    // Pool events into coin_node's existing subscribers.
    EXPECT_NE(src.find("coin_node.new_headers.happened(h);"), std::string::npos);
    EXPECT_NE(src.find("coin_node.full_block.happened(b);"), std::string::npos);
    EXPECT_NE(src.find("coin_node.new_tx.happened(tx);"), std::string::npos);
    // The driver: poll() every kCoinPoolPollSec; tip-reconcile asks every pooled peer.
    EXPECT_NE(src.find("pool_ptr->poll();"), std::string::npos);
    EXPECT_NE(src.find("static_cast<int>(btc::coin::kCoinPoolPollSec)"), std::string::npos);
    EXPECT_NE(src.find("coin_pool->ask_all(locator);"), std::string::npos);
    // Built only without --bitcoind.
    const auto standalone = src.find("if (bitcoind_host.empty()) {");
    const auto make_pool = src.find("coin_pool = std::make_unique<btc::coin::CoinPeerPool>");
    ASSERT_NE(standalone, std::string::npos);
    ASSERT_NE(make_pool, std::string::npos);
    EXPECT_LT(standalone, make_pool);
}
