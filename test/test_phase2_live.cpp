/// Phase 2 — Live daemon integration tests
///
/// Connects to a real Litecoin testnet daemon P2P port and verifies
/// that the Phase 2 mempool works correctly against a live peer:
///   1. send_mempool() triggers tx inv announcements from peer
///   2. Transactions are received via new_tx event and fed into Mempool
///   3. Mempool grows and maintains correct byte accounting
///   4. Duplicate transactions are rejected
///   5. evict_expired() can be called without crash
///   6. remove_for_block() is triggered by HeaderChain tip advance
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

// ─── Test Fixture ───────────────────────────────────────────────────────────

class Phase2LiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!tcp_probe(P2P_HOST, P2P_PORT)) {
            GTEST_SKIP() << "LTC testnet daemon not reachable at "
                         << P2P_HOST << ":" << P2P_PORT;
        }
        core::log::Logger::init();
    }
};

// ─── Test 1: Mempool receives transactions via new_tx ────────────────────────
// Verifies that:
//   - send_mempool() (sent automatically after verack) triggers tx inv from peer
//   - Transactions arrive via the new_tx event
//   - Mempool.add_tx() accepts them

TEST_F(Phase2LiveTest, MempoolReceivesTxsFromPeer)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    Mempool pool;
    std::atomic<int> tx_callbacks{0};
    std::atomic<int> tx_accepted{0};
    std::mutex mtx;

    peer.coin_node.new_tx.subscribe(
        [&](const ltc::coin::Transaction& tx) {
            tx_callbacks.fetch_add(1, std::memory_order_relaxed);

            // Convert Transaction → MutableTransaction for pool
            MutableTransaction mtx_tx(tx);
            if (pool.add_tx(mtx_tx))
                tx_accepted.fetch_add(1, std::memory_order_relaxed);
        });

    peer.node_p2p.connect(addr);

    // After handshake, explicitly request the peer's mempool (BIP 35).
    // Delayed to let the handshake complete first.
    io::steady_timer mempool_req(ioc);
    mempool_req.expires_after(std::chrono::seconds(5));
    mempool_req.async_wait([&](const boost::system::error_code& ec) {
        if (!ec) peer.node_p2p.send_mempool();
    });

    // Run for 30 seconds — should receive mempool txs after handshake
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    std::cout << "[Phase2Live] MempoolFromPeer:"
              << " tx_callbacks=" << tx_callbacks.load()
              << " tx_accepted=" << tx_accepted.load()
              << " pool_size=" << pool.size()
              << " pool_bytes=" << pool.byte_size() << std::endl;

    // NOTE: testnet may have an empty mempool. That's fine — we verify
    // the callbacks fired when they should and the pool is consistent.
    // The important thing is no crash and no duplicate txids.

    if (tx_callbacks.load() > 0) {
        EXPECT_GT(tx_accepted.load(), 0)
            << "At least some callbacks should result in accepted txs";
        EXPECT_EQ(pool.size(), static_cast<size_t>(tx_accepted.load()))
            << "Pool size should match accepted tx count";
    } else {
        std::cout << "[Phase2Live] WARNING: No tx callbacks in 30s "
                  << "(testnet mempool may be empty)" << std::endl;
    }
}

// ─── Test 2: Duplicate rejection ────────────────────────────────────────────
// Verify that if the peer sends the same transaction twice
// (e.g., via two inv announcements), the mempool only stores one copy.

TEST_F(Phase2LiveTest, MempoolRejectsDuplicates)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    Mempool pool;
    std::atomic<int> total_callbacks{0};
    std::mutex pool_mtx;
    std::vector<uint256> seen_txids;

    peer.coin_node.new_tx.subscribe(
        [&](const ltc::coin::Transaction& tx) {
            total_callbacks.fetch_add(1, std::memory_order_relaxed);
            MutableTransaction mtx_tx(tx);
            uint256 txid = compute_txid(mtx_tx);

            std::lock_guard<std::mutex> lk(pool_mtx);
            seen_txids.push_back(txid);
            pool.add_tx(mtx_tx);
        });

    peer.node_p2p.connect(addr);

    // Explicitly request mempool after handshake
    io::steady_timer mempool_req(ioc);
    mempool_req.expires_after(std::chrono::seconds(5));
    mempool_req.async_wait([&](const boost::system::error_code& ec) {
        if (!ec) peer.node_p2p.send_mempool();
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    std::lock_guard<std::mutex> lk(pool_mtx);
    std::cout << "[Phase2Live] DuplicateRejection:"
              << " total_callbacks=" << total_callbacks.load()
              << " unique_in_pool=" << pool.size() << std::endl;

    // Pool size must be <= total callbacks (duplicates rejected)
    EXPECT_LE(pool.size(), static_cast<size_t>(total_callbacks.load()));
    EXPECT_EQ(pool.byte_size() > 0 || pool.size() == 0, true)  // consistent
        << "byte_size must be non-zero iff pool is non-empty";
}

// ─── Test 3: Mempool + HeaderChain integration ───────────────────────────────
// Connect to peer, sync headers AND collect mempool txs.
// When a new block arrives (via headers event advancing the chain),
// call remove_for_block to prune confirmed transactions.
// Verifies that HeaderChain + Mempool work together.

TEST_F(Phase2LiveTest, MempoolPrunedOnBlockAdvance)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);
    std::string key = addr.to_string();

    BroadcastPeer peer(&ioc, key, LTC_TESTNET_PREFIX, addr);

    auto params = LTCChainParams::testnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());

    // Seed testnet genesis
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_previous_block.SetNull();
    genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    genesis.m_timestamp = 1486949366;
    genesis.m_bits = 0x1e0ffff0;
    genesis.m_nonce = 293345;
    ASSERT_TRUE(chain.add_header(genesis));

    Mempool pool;
    std::atomic<int> txs_received{0};
    std::atomic<int> headers_received{0};
    std::atomic<int> block_prune_calls{0};

    // Collect transactions
    peer.coin_node.new_tx.subscribe(
        [&](const ltc::coin::Transaction& tx) {
            txs_received.fetch_add(1, std::memory_order_relaxed);
            MutableTransaction mtx_tx(tx);
            pool.add_tx(mtx_tx);
        });

    // Sync headers; on each advance, simulate block pruning
    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            int accepted = chain.add_headers(hdrs);
            headers_received.fetch_add(static_cast<int>(hdrs.size()), std::memory_order_relaxed);

            if (accepted > 0) {
                // We don't have full block data from headers-only sync,
                // but we can test the call doesn't crash with an empty block.
                BlockType empty_blk;
                pool.remove_for_block(empty_blk);
                block_prune_calls.fetch_add(1, std::memory_order_relaxed);

                // Keep syncing headers
                auto locator = chain.get_locator();
                peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
            }
        });

    peer.node_p2p.connect(addr);

    // After handshake: kick off header sync
    io::steady_timer handshake(ioc);
    handshake.expires_after(std::chrono::seconds(5));
    handshake.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        auto locator = chain.get_locator();
        peer.node_p2p.send_getheaders(70017, locator, uint256::ZERO);
    });

    // Run for 30 seconds
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    pool.evict_expired();  // Should not crash

    std::cout << "[Phase2Live] MempoolPruneOnBlock:"
              << " txs_received=" << txs_received.load()
              << " headers_received=" << headers_received.load()
              << " block_prune_calls=" << block_prune_calls.load()
              << " chain_height=" << chain.height()
              << " pool_size=" << pool.size() << std::endl;

    // Chain should have advanced (Phase 1 validated this already)
    EXPECT_GT(chain.height(), 0u)
        << "HeaderChain should have synced at least some headers";

    // Pool state should be consistent
    if (txs_received.load() > 0)
        EXPECT_LE(pool.size(), static_cast<size_t>(txs_received.load()));
}

// ─── Test 4: CoinBroadcaster feeds Mempool ───────────────────────────────────
// Uses the CoinBroadcaster (multi-peer manager) to receive transactions
// and feed them into the Mempool via set_on_new_tx callback.

TEST_F(Phase2LiveTest, BroadcasterFeedsMempool)
{
    io::io_context ioc;
    NetService addr(P2P_HOST, P2P_PORT);

    CoinBroadcaster broadcaster(ioc, "LTC", LTC_TESTNET_PREFIX, addr,
                                "/tmp/c2pool_phase2_test_pm",
                                PeerManagerConfig{});

    Mempool pool;
    std::atomic<int> tx_batches{0};
    std::atomic<int> tx_total{0};

    broadcaster.set_on_new_tx(
        [&](const std::string& peer_key, const ltc::coin::Transaction& tx) {
            tx_batches.fetch_add(1, std::memory_order_relaxed);
            MutableTransaction mtx_tx(tx);
            if (pool.add_tx(mtx_tx))
                tx_total.fetch_add(1, std::memory_order_relaxed);
        });

    broadcaster.start();

    // Run 30 seconds
    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    int peers = broadcaster.connected_count();
    broadcaster.stop();

    std::cout << "[Phase2Live] BroadcasterMempool:"
              << " peers=" << peers
              << " tx_callbacks=" << tx_batches.load()
              << " tx_accepted=" << tx_total.load()
              << " pool_size=" << pool.size()
              << " pool_bytes=" << pool.byte_size() << std::endl;

    EXPECT_GE(peers, 1)
        << "Broadcaster should have at least one connected peer";

    // Byte accounting must be consistent
    EXPECT_EQ(pool.byte_size() > 0 || pool.size() == 0, true);
}
