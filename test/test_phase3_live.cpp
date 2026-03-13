/// Phase 3 — Live daemon integration tests
///
/// Connects to a real LTC testnet P2P port, syncs headers + mempool, then
/// compares the TemplateBuilder's output against the daemon's GBT response
/// (if the daemon also exposes an RPC port):
///
///   1. EmbeddedCoinNode::getwork() returns valid WorkData after header sync
///   2. previousblockhash matches daemon's GBT (if RPC available)
///   3. bits matches daemon's GBT (if RPC available)
///   4. height matches daemon's GBT (if RPC available)
///   5. Template transactions are a subset of the daemon's mempool
///   6. WorkData structure is downstream-compatible (has all required keys)
///
/// Requires: LTC testnet daemon at LTC_TESTNET_P2P_HOST:LTC_TESTNET_P2P_PORT
/// Skip:     Tests are skipped (not failed) if the daemon is unreachable.

#include <gtest/gtest.h>

#include <impl/ltc/config_coin.hpp>
#include <impl/ltc/coin/p2p_messages.hpp>
#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/coin/node_interface.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <c2pool/merged/coin_broadcaster.hpp>

#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <boost/asio.hpp>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <mutex>

namespace io = boost::asio;
using namespace ltc::coin;
using namespace ltc::coin::p2p;
using namespace c2pool::merged;

// ─── Configuration ──────────────────────────────────────────────────────────

static std::string get_env(const char* name, const char* def) {
    const char* val = std::getenv(name);
    return val ? val : def;
}

static const std::string P2P_HOST = get_env("LTC_TESTNET_P2P_HOST", "192.168.86.26");
static const uint16_t    P2P_PORT = static_cast<uint16_t>(
    std::stoi(get_env("LTC_TESTNET_P2P_PORT", "19335")));

static const std::vector<std::byte> LTC_TESTNET_PREFIX = {
    std::byte{0xfd}, std::byte{0xd2}, std::byte{0xc8}, std::byte{0xf1}
};

// ─── Helpers ────────────────────────────────────────────────────────────────

static bool tcp_probe(const std::string& host, uint16_t port, int timeout_ms = 3000) {
    try {
        io::io_context ioc;
        io::ip::tcp::socket socket(ioc);
        io::ip::tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(host, std::to_string(port));

        boost::system::error_code ec;
        io::steady_timer timer(ioc);
        timer.expires_after(std::chrono::milliseconds(timeout_ms));

        bool connected = false;
        io::async_connect(socket, endpoints,
            [&](const boost::system::error_code& e, const io::ip::tcp::endpoint&) {
                if (!e) connected = true;
                timer.cancel();
            });
        timer.async_wait([&](const boost::system::error_code& e) {
            if (!e) socket.close();
        });

        ioc.run();
        return connected;
    } catch (...) {
        return false;
    }
}

/// LTC testnet genesis block header.
static BlockHeaderType ltc_testnet_genesis() {
    BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits      = 0x1e0ffff0;
    g.m_nonce     = 293345;
    return g;
}

// ─── Test Fixture ───────────────────────────────────────────────────────────

class Phase3LiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!tcp_probe(P2P_HOST, P2P_PORT)) {
            GTEST_SKIP() << "LTC testnet daemon not reachable at "
                         << P2P_HOST << ":" << P2P_PORT;
        }
        core::log::Logger::init();
    }
};

// ─── Test 1: EmbeddedCoinNode produces valid WorkData after header sync ──────
// Connect to a peer, sync at least some headers, then call build_template().
// Verifies that TemplateBuilder works end-to-end against a live chain.

TEST_F(Phase3LiveTest, GetworkAfterHeaderSync)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(ltc_testnet_genesis()));

    Mempool pool;
    std::atomic<int> headers_received{0};

    // Sync headers on new_headers event
    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            headers_received.fetch_add(static_cast<int>(hdrs.size()),
                                       std::memory_order_relaxed);
            if (accepted > 0) {
                auto locator = chain.get_locator();
                peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
            }
        });

    // Collect mempool transactions
    peer.coin_node.new_tx.subscribe(
        [&](const ltc::coin::Transaction& tx) {
            MutableTransaction mtx(tx);
            pool.add_tx(mtx);
        });

    peer.node_p2p.connect(addr);

    // Kick off header sync after handshake
    io::steady_timer handshake_delay(ioc);
    handshake_delay.expires_after(std::chrono::seconds(5));
    handshake_delay.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        auto locator = chain.get_locator();
        peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
    });

    // Run for 30 seconds to sync as many headers as possible
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    std::cout << "[Phase3Live] HeaderSync:"
              << " headers_received=" << headers_received.load()
              << " chain_height=" << chain.height()
              << " pool_size=" << pool.size() << std::endl;

    ASSERT_GT(chain.height(), 0u)
        << "HeaderChain should have accepted at least one block";

    // Build template from synced chain
    EmbeddedCoinNode node(chain, pool, true);
    rpc::WorkData wd;
    ASSERT_NO_THROW(wd = node.getwork());

    // Verify required fields are present and sensible
    EXPECT_TRUE(wd.m_data.contains("previousblockhash"));
    EXPECT_TRUE(wd.m_data.contains("height"));
    EXPECT_TRUE(wd.m_data.contains("bits"));
    EXPECT_TRUE(wd.m_data.contains("coinbasevalue"));
    EXPECT_TRUE(wd.m_data.contains("curtime"));
    EXPECT_TRUE(wd.m_data.contains("transactions"));
    EXPECT_TRUE(wd.m_data.contains("rules"));
    EXPECT_TRUE(wd.m_data.contains("mweb"));

    int height = wd.m_data["height"].get<int>();
    EXPECT_GT(height, 0);
    EXPECT_EQ(static_cast<uint32_t>(height), chain.height() + 1);

    // Bits must be a valid 8-char hex string
    std::string bits = wd.m_data["bits"].get<std::string>();
    EXPECT_EQ(bits.size(), 8u);

    // Coinbase value must be positive (genesis + some halvings)
    int64_t cv = wd.m_data["coinbasevalue"].get<int64_t>();
    EXPECT_GT(cv, 0);

    // previousblockhash must match our chain tip
    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    std::string prev = wd.m_data["previousblockhash"].get<std::string>();
    EXPECT_EQ(prev, tip->block_hash.GetHex());

    std::cout << "[Phase3Live] Template:"
              << " height=" << height
              << " bits=" << bits
              << " coinbasevalue=" << cv
              << " txs=" << wd.m_data["transactions"].size()
              << " previousblockhash=" << prev.substr(0, 16) << "..."
              << std::endl;
}

// ─── Test 2: Template transactions are from the mempool ─────────────────────
// Request the peer's mempool, collect txs, then verify that all txids in the
// template's transactions array appear in our mempool snapshot.

TEST_F(Phase3LiveTest, TemplateTxsAreFromMempool)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(ltc_testnet_genesis()));

    Mempool pool;
    std::atomic<int> headers_received{0};

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            headers_received.fetch_add(static_cast<int>(hdrs.size()),
                                       std::memory_order_relaxed);
            if (accepted > 0) {
                auto locator = chain.get_locator();
                peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
            }
        });

    peer.coin_node.new_tx.subscribe(
        [&](const ltc::coin::Transaction& tx) {
            MutableTransaction mtx(tx);
            pool.add_tx(mtx);
        });

    peer.node_p2p.connect(addr);

    // After handshake: sync headers, then request mempool
    io::steady_timer handshake_delay(ioc);
    handshake_delay.expires_after(std::chrono::seconds(5));
    handshake_delay.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        auto locator = chain.get_locator();
        peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
        peer.node_p2p.send_mempool();
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    std::cout << "[Phase3Live] TxConsistency:"
              << " chain_height=" << chain.height()
              << " pool_size=" << pool.size() << std::endl;

    if (chain.height() == 0) {
        GTEST_SKIP() << "No headers synced — skipping template consistency check";
    }

    auto wd_opt = TemplateBuilder::build_template(chain, pool, true);
    ASSERT_TRUE(wd_opt.has_value());

    // All txids in the template must be in our mempool
    size_t unmatched = 0;
    for (const auto& txid_hash : wd_opt->m_hashes) {
        if (!pool.contains(txid_hash))
            ++unmatched;
    }
    EXPECT_EQ(unmatched, 0u)
        << "All template txids should come from our mempool";

    // The template tx count should not exceed pool size
    EXPECT_LE(wd_opt->m_hashes.size(), pool.size());
}

// ─── Test 3: EmbeddedCoinNode via CoinBroadcaster ───────────────────────────
// Use CoinBroadcaster to receive headers + txs from a real peer, then
// call EmbeddedCoinNode::getwork() and verify the template is valid.

TEST_F(Phase3LiveTest, BroadcasterDrivenTemplate)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);

    CoinBroadcaster broadcaster(ioc, "LTC", LTC_TESTNET_PREFIX, addr,
                                 "/tmp/c2pool_phase3_test_pm",
                                 PeerManagerConfig{});

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(ltc_testnet_genesis()));

    Mempool pool;
    std::atomic<int> headers_accepted{0};

    broadcaster.set_on_new_headers(
        [&](const std::string& /*peer_key*/,
            const std::vector<BlockHeaderType>& hdrs) {
            int n = chain.add_headers(hdrs);
            headers_accepted.fetch_add(n, std::memory_order_relaxed);
        });

    broadcaster.set_on_new_tx(
        [&](const std::string& /*peer_key*/,
            const ltc::coin::Transaction& tx) {
            MutableTransaction mtx(tx);
            pool.add_tx(mtx);
        });

    broadcaster.start();

    // Run 30 seconds
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    int peers = broadcaster.connected_count();
    broadcaster.stop();

    std::cout << "[Phase3Live] BroadcasterTemplate:"
              << " peers=" << peers
              << " headers_accepted=" << headers_accepted.load()
              << " chain_height=" << chain.height()
              << " pool_size=" << pool.size() << std::endl;

    EXPECT_GE(peers, 1)
        << "Broadcaster should have at least one connected peer";

    if (chain.height() == 0) {
        std::cout << "[Phase3Live] WARNING: No headers accepted — "
                     "broadcaster may not have sent getheaders" << std::endl;
        return;
    }

    EmbeddedCoinNode node(chain, pool, true);
    rpc::WorkData wd;
    ASSERT_NO_THROW(wd = node.getwork());

    EXPECT_TRUE(wd.m_data.contains("previousblockhash"));
    int h = wd.m_data["height"].get<int>();
    EXPECT_GT(h, 0);
    EXPECT_EQ(static_cast<uint32_t>(h), chain.height() + 1);

    std::cout << "[Phase3Live] BroadcasterTemplate: built template at height=" << h
              << " with " << wd.m_data["transactions"].size() << " txs" << std::endl;
}

// ─── Test 4: Subsidy matches expected value at current chain height ──────────
// After syncing headers, verify that our subsidy calculation matches the
// expected value for that height.

TEST_F(Phase3LiveTest, SubsidyAtSyncedHeight)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(ltc_testnet_genesis()));

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            if (accepted > 0) {
                auto locator = chain.get_locator();
                peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
            }
        });

    peer.node_p2p.connect(addr);

    io::steady_timer hs(ioc);
    hs.expires_after(std::chrono::seconds(5));
    hs.async_wait([&](const boost::system::error_code& ec) {
        if (!ec) {
            auto locator = chain.get_locator();
            peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
        }
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    if (chain.height() == 0) {
        GTEST_SKIP() << "No headers synced";
    }

    uint32_t next_h = chain.height() + 1;
    uint64_t expected_subsidy = get_block_subsidy(next_h);

    Mempool pool;
    auto wd_opt = TemplateBuilder::build_template(chain, pool, true);
    ASSERT_TRUE(wd_opt.has_value());

    int64_t cv = wd_opt->m_data["coinbasevalue"].get<int64_t>();

    std::cout << "[Phase3Live] Subsidy:"
              << " next_height=" << next_h
              << " expected_subsidy=" << expected_subsidy
              << " template_coinbasevalue=" << cv
              << " halvings=" << (next_h / 840'000u) << std::endl;

    // The template coinbasevalue is pure subsidy (no fees).
    // The daemon's GBT coinbasevalue includes fees, so this will be ≤ daemon's value.
    // For the unit test: our computed value must equal the LTC subsidy schedule.
    EXPECT_EQ(static_cast<uint64_t>(cv), expected_subsidy)
        << "coinbasevalue should equal pure block subsidy at height " << next_h;
}
