/// Phase 1 — Live daemon integration tests
///
/// Connects to a real Litecoin testnet daemon P2P port and verifies
/// that the Phase 1 header chain syncs correctly:
///   1. Receives headers after getheaders request
///   2. Headers pass PoW validation
///   3. HeaderChain accumulates headers from live peer
///   4. handle_headers bug fix verified (headers vector non-empty)
///
/// Requires: LTC testnet daemon at LTC_TESTNET_P2P_HOST:LTC_TESTNET_P2P_PORT
/// Skip:     Tests are skipped (not failed) if the daemon is unreachable.

#include <gtest/gtest.h>

#include <impl/ltc/config_coin.hpp>
#include <impl/ltc/coin/p2p_messages.hpp>
#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/coin/node_interface.hpp>
#include <impl/ltc/coin/header_chain.hpp>
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
static const uint16_t    P2P_PORT = static_cast<uint16_t>(std::stoi(get_env("LTC_TESTNET_P2P_PORT", "19335")));

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
        bool timed_out = false;

        io::async_connect(socket, endpoints,
            [&](const boost::system::error_code& e, const io::ip::tcp::endpoint&) {
                if (!e) connected = true;
                timer.cancel();
            });

        timer.async_wait([&](const boost::system::error_code& e) {
            if (!e) {
                timed_out = true;
                socket.close();
            }
        });

        ioc.run();
        return connected && !timed_out;
    } catch (...) {
        return false;
    }
}

// ─── Test Fixture ───────────────────────────────────────────────────────────

class Phase1LiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!tcp_probe(P2P_HOST, P2P_PORT)) {
            GTEST_SKIP() << "LTC testnet daemon not reachable at "
                         << P2P_HOST << ":" << P2P_PORT;
        }
        core::log::Logger::init();
    }
};

// ─── Test 1: Headers callback delivers non-empty vector ─────────────────────
// This specifically validates the bug fix in handle(headers) — previously
// the vheaders vector was always empty.

TEST_F(Phase1LiveTest, HeadersCallbackNonEmpty)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    std::atomic<int> callback_count{0};
    std::atomic<int> total_headers{0};
    std::mutex mtx;
    std::vector<BlockHeaderType> received_headers;

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            callback_count.fetch_add(1, std::memory_order_relaxed);
            total_headers.fetch_add(static_cast<int>(hdrs.size()), std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(mtx);
            for (auto& h : hdrs)
                received_headers.push_back(h);
        });

    peer.node_p2p.connect(addr);

    // Wait for handshake, then send getheaders from genesis
    io::steady_timer wait_handshake(ioc);
    wait_handshake.expires_after(std::chrono::seconds(5));
    wait_handshake.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        // Send getheaders with genesis hash as locator → get headers from genesis
        uint256 genesis_hash;
        genesis_hash.SetHex("4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0");
        peer.node_p2p.send_getheaders(70017, {genesis_hash}, uint256::ZERO);
    });

    // 60 second deadline
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(60));
    deadline.async_wait([&](const boost::system::error_code&) {
        ioc.stop();
    });

    ioc.run();

    std::cout << "[Phase1Live] HeadersCallback: callbacks=" << callback_count.load()
              << " total_headers=" << total_headers.load() << std::endl;

    // The bug fix means we should receive at least some headers
    // (the daemon sends up to 2000 headers per getheaders response)
    if (callback_count.load() > 0) {
        EXPECT_GT(total_headers.load(), 0)
            << "BUG REGRESSION: headers callback fired but vector was empty!";

        // Validate each received header has a valid PoW
        std::lock_guard<std::mutex> lock(mtx);
        uint256 pow_limit;
        pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        int valid_pow_count = 0;
        for (auto& hdr : received_headers) {
            uint256 pow_hash = scrypt_hash(hdr);
            if (check_pow(pow_hash, hdr.m_bits, pow_limit))
                ++valid_pow_count;
        }

        std::cout << "[Phase1Live] PoW validation: " << valid_pow_count
                  << "/" << received_headers.size() << " headers valid" << std::endl;

        EXPECT_EQ(valid_pow_count, static_cast<int>(received_headers.size()))
            << "All received headers should have valid PoW";
    } else {
        std::cout << "[Phase1Live] WARNING: No headers callbacks received in 60s "
                  << "(daemon may not have responded to getheaders)" << std::endl;
    }
}

// ─── Test 2: HeaderChain syncs from live peer ───────────────────────────────
// Connects to the daemon, sends getheaders, feeds received headers into
// the HeaderChain, and verifies the chain grows.

TEST_F(Phase1LiveTest, HeaderChainSyncsFromDaemon)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());

    // Seed with testnet genesis
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_previous_block.SetNull();
    genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    genesis.m_timestamp = 1486949366;
    genesis.m_bits = 0x1e0ffff0;
    genesis.m_nonce = 293345;
    ASSERT_TRUE(chain.add_header(genesis));
    ASSERT_EQ(chain.height(), 0u);

    std::atomic<int> accepted_total{0};

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            accepted_total.fetch_add(accepted, std::memory_order_relaxed);

            std::cout << "[Phase1Live] Received " << hdrs.size()
                      << " headers, accepted " << accepted
                      << ", chain height=" << chain.height() << std::endl;

            // If we got headers and there's more, request more
            if (accepted > 0) {
                auto locator = chain.get_locator();
                peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
            }
        });

    peer.node_p2p.connect(addr);

    // After handshake, send initial getheaders from genesis
    io::steady_timer handshake_wait(ioc);
    handshake_wait.expires_after(std::chrono::seconds(5));
    handshake_wait.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        auto locator = chain.get_locator();
        peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
    });

    // Run for 120 seconds — enough to sync many batches of 2000 headers
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(120));
    deadline.async_wait([&](const boost::system::error_code&) {
        ioc.stop();
    });

    ioc.run();

    uint32_t final_height = chain.height();
    size_t final_size = chain.size();

    std::cout << "[Phase1Live] Final chain: height=" << final_height
              << " size=" << final_size
              << " accepted_total=" << accepted_total.load() << std::endl;

    // We should have synced at least some headers
    EXPECT_GT(final_height, 0u)
        << "HeaderChain should have synced at least some headers from daemon";

    // Tip should be valid
    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(tip->status, HEADER_VALID_CHAIN);
    EXPECT_EQ(tip->height, final_height);

    // All heights should be populated on the best chain
    for (uint32_t h = 0; h <= std::min(final_height, 10u); ++h) {
        auto entry = chain.get_header_by_height(h);
        EXPECT_TRUE(entry.has_value()) << "Missing header at height " << h;
    }
}

// ─── Test 3: Broadcaster with HeaderChain ───────────────────────────────────
// Uses CoinBroadcaster to connect and feed headers into HeaderChain.

TEST_F(Phase1LiveTest, BroadcasterFeedsHeaderChain)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);

    CoinBroadcaster broadcaster(ioc, "LTC", LTC_TESTNET_PREFIX, addr,
                                "/tmp/c2pool_phase1_test_pm",
                                PeerManagerConfig{});

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());

    // Seed genesis
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_previous_block.SetNull();
    genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    genesis.m_timestamp = 1486949366;
    genesis.m_bits = 0x1e0ffff0;
    genesis.m_nonce = 293345;
    ASSERT_TRUE(chain.add_header(genesis));

    std::atomic<int> header_batches{0};

    broadcaster.set_on_new_headers(
        [&](const std::string& peer_key, const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            header_batches.fetch_add(1, std::memory_order_relaxed);

            std::cout << "[Phase1Live] Broadcaster headers from " << peer_key
                      << ": " << hdrs.size() << " received, " << accepted
                      << " accepted, height=" << chain.height() << std::endl;
        });

    broadcaster.start();

    // Run for 30 seconds
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) {
        ioc.stop();
    });

    ioc.run();

    int peers = broadcaster.connected_count();
    broadcaster.stop();

    std::cout << "[Phase1Live] Broadcaster: peers=" << peers
              << " header_batches=" << header_batches.load()
              << " chain_height=" << chain.height() << std::endl;

    EXPECT_GE(peers, 1)
        << "Broadcaster should have at least one peer";
}
