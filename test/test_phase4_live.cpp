/// Phase 4 — Live daemon-less integration tests
///
/// Verifies the full embedded-node pipeline end-to-end against a live LTC
/// testnet peer without a coin daemon:
///
///  1. EmbeddedCoinNode wired via CoinBroadcaster syncs headers from live peer
///  2. MiningInterface::refresh_work() with embedded node produces valid template
///  3. getblockchaininfo() reflects synced chain state
///  4. Template previousblockhash matches embedded chain tip after sync
///  5. block_rel_height via HeaderChain: depth of synced tip = 1
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
#include <core/web_server.hpp>
#include <core/address_validator.hpp>
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

class Phase4LiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!tcp_probe(P2P_HOST, P2P_PORT)) {
            GTEST_SKIP() << "LTC testnet daemon not reachable at "
                         << P2P_HOST << ":" << P2P_PORT;
        }
        core::log::Logger::init();
    }
};

// ─── Test 1: EmbeddedCoinNode syncs headers via CoinBroadcaster ─────────────
// Uses the CoinBroadcaster flow (as used in --embedded-ltc mode) to sync
// headers into the HeaderChain, then verifies EmbeddedCoinNode.getwork().

TEST_F(Phase4LiveTest, EmbeddedNodeSyncsViaDirectPeer)
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
    std::atomic<int> headers_accepted{0};

    // Sync headers on each new_headers event (mirrors embedded startup path)
    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            headers_accepted.fetch_add(accepted, std::memory_order_relaxed);
            if (accepted > 0) {
                auto locator = chain.get_locator();
                peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
            }
        });

    // Feed mempool
    peer.coin_node.new_tx.subscribe(
        [&](const ltc::coin::Transaction& tx) {
            MutableTransaction mtx(tx);
            pool.add_tx(mtx);
        });

    peer.node_p2p.connect(addr);

    // Kick off header sync after handshake
    io::steady_timer start_timer(ioc);
    start_timer.expires_after(std::chrono::seconds(5));
    start_timer.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        auto locator = chain.get_locator();
        peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });
    ioc.run();

    std::cout << "[Phase4Live] DirectPeerSync:"
              << " headers_accepted=" << headers_accepted.load()
              << " chain_height=" << chain.height()
              << " pool_size=" << pool.size() << "\n";

    ASSERT_GT(chain.height(), 0u) << "HeaderChain should have accepted at least one header";

    // Build EmbeddedCoinNode and verify getwork() succeeds
    EmbeddedCoinNode embedded(chain, pool, /*testnet=*/true);
    rpc::WorkData wd;
    ASSERT_NO_THROW(wd = embedded.getwork());

    EXPECT_EQ(wd.m_data["height"].get<uint32_t>(), chain.height() + 1);

    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(wd.m_data["previousblockhash"].get<std::string>(), tip->block_hash.GetHex());

    std::cout << "[Phase4Live] EmbeddedGetwork: height=" << wd.m_data["height"]
              << " prev=" << wd.m_data["previousblockhash"].get<std::string>().substr(0, 16) << "...\n";
}

// ─── Test 2: MiningInterface.refresh_work() with embedded node ───────────────
// Wires a synced EmbeddedCoinNode into a MiningInterface, calls refresh_work(),
// and verifies the cached template has correct fields.

TEST_F(Phase4LiveTest, MiningInterfaceRefreshWorkWithEmbeddedNode)
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

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
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

    io::steady_timer start_timer(ioc);
    start_timer.expires_after(std::chrono::seconds(5));
    start_timer.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });
    ioc.run();

    ASSERT_GT(chain.height(), 0u) << "HeaderChain should have accepted at least one header";

    // Wire embedded node into MiningInterface
    EmbeddedCoinNode embedded(chain, pool, true);
    core::MiningInterface mi(/*testnet=*/true, nullptr, c2pool::address::Blockchain::LITECOIN);
    mi.set_embedded_node(&embedded);

    EXPECT_NO_THROW(mi.refresh_work());

    auto tmpl = mi.get_current_work_template();
    EXPECT_FALSE(tmpl.is_null());
    EXPECT_TRUE(tmpl.contains("height"));
    EXPECT_TRUE(tmpl.contains("previousblockhash"));
    EXPECT_TRUE(tmpl.contains("bits"));
    EXPECT_TRUE(tmpl.contains("coinbasevalue"));

    uint32_t tmpl_height = tmpl["height"].get<uint32_t>();
    EXPECT_EQ(tmpl_height, chain.height() + 1);

    std::cout << "[Phase4Live] MiningInterface: height=" << tmpl_height
              << " coinbasevalue=" << tmpl.value("coinbasevalue", int64_t{0})
              << " txs=" << tmpl.value("transactions", nlohmann::json::array()).size() << "\n";
}

// ─── Test 3: getblockchaininfo after sync ───────────────────────────────────

TEST_F(Phase4LiveTest, GetblockchaininfoAfterSync)
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

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            if (accepted > 0)
                peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
        });

    peer.node_p2p.connect(addr);

    io::steady_timer t(ioc);
    t.expires_after(std::chrono::seconds(5));
    t.async_wait([&](const boost::system::error_code& ec) {
        if (!ec)
            peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });
    ioc.run();

    ASSERT_GT(chain.height(), 0u);

    EmbeddedCoinNode embedded(chain, pool, true);
    auto info = embedded.getblockchaininfo();

    EXPECT_EQ(info["chain"].get<std::string>(), "test");
    EXPECT_EQ(info["blocks"].get<uint32_t>(), chain.height());

    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(info["bestblockhash"].get<std::string>(), tip->block_hash.GetHex());

    std::cout << "[Phase4Live] Chaininfo: chain=" << info["chain"]
              << " blocks=" << info["blocks"]
              << " synced=" << info.value("synced", false) << "\n";
}

// ─── Test 4: block_rel_height via HeaderChain matches expected depth ─────────

TEST_F(Phase4LiveTest, BlockRelHeightViaSyncedChain)
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

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            if (accepted > 0)
                peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
        });

    peer.node_p2p.connect(addr);

    io::steady_timer t(ioc);
    t.expires_after(std::chrono::seconds(5));
    t.async_wait([&](const boost::system::error_code& ec) {
        if (!ec)
            peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });
    ioc.run();

    ASSERT_GT(chain.height(), 0u);

    // Simulate the block_rel_height_fn from c2pool_refactored.cpp embedded path
    auto block_rel_height = [&](uint256 block_hash) -> int32_t {
        if (block_hash.IsNull()) return 0;
        auto entry = chain.get_header(block_hash);
        if (!entry) return 0;
        int32_t tip_h   = static_cast<int32_t>(chain.height());
        int32_t entry_h = static_cast<int32_t>(entry->height);
        return tip_h - entry_h + 1;
    };

    // Tip should have depth 1
    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    int32_t depth = block_rel_height(tip->block_hash);
    EXPECT_EQ(depth, 1);
    std::cout << "[Phase4Live] TipDepth: chain_height=" << chain.height()
              << " tip_depth=" << depth << "\n";

    // Genesis should have depth = chain.height() + 1 (deepest block)
    auto genesis_entry = chain.get_header_by_height(0);
    if (genesis_entry) {
        int32_t genesis_depth = block_rel_height(genesis_entry->block_hash);
        EXPECT_EQ(genesis_depth, static_cast<int32_t>(chain.height()) + 1);
        std::cout << "[Phase4Live] GenesisDepth=" << genesis_depth << "\n";
    }

    // Unknown hash → 0
    uint256 unknown;
    unknown.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    EXPECT_EQ(block_rel_height(unknown), 0);
}
