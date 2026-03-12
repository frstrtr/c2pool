#include <gtest/gtest.h>

#include <impl/ltc/config_coin.hpp>
#include <c2pool/merged/coin_peer_manager.hpp>
#include <c2pool/merged/coin_broadcaster.hpp>

#include <boost/asio.hpp>
#include <set>
#include <vector>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <unistd.h>

using namespace c2pool::merged;

// ─── PeerInfo unit tests ─────────────────────────────────────────────────────

TEST(PeerInfo, DefaultConstruction)
{
    PeerInfo pi;
    EXPECT_EQ(pi.score, 0);
    EXPECT_EQ(pi.broadcast_successes, 0);
    EXPECT_EQ(pi.broadcast_failures, 0);
    EXPECT_EQ(pi.attempt_count, 0);
    EXPECT_EQ(pi.backoff_sec, 30);
    EXPECT_FALSE(pi.is_protected);
}

TEST(PeerInfo, RecordSuccess)
{
    PeerInfo pi;
    pi.record_success();
    EXPECT_EQ(pi.broadcast_successes, 1);
    EXPECT_EQ(pi.blocks_relayed, 1);
    EXPECT_EQ(pi.score, 10);
    
    pi.record_success();
    EXPECT_EQ(pi.broadcast_successes, 2);
    EXPECT_EQ(pi.blocks_relayed, 2);
    EXPECT_EQ(pi.score, 20);
}

TEST(PeerInfo, RecordFailure)
{
    PeerInfo pi;
    pi.score = 50;
    pi.record_failure();
    EXPECT_EQ(pi.broadcast_failures, 1);
    EXPECT_EQ(pi.score, 45);
}

TEST(PeerInfo, RecordConnected)
{
    PeerInfo pi;
    pi.backoff_sec = 120;
    pi.attempt_count = 3;
    pi.record_connected();
    EXPECT_EQ(pi.backoff_sec, 30);      // reset
    EXPECT_EQ(pi.attempt_count, 0);     // reset
    EXPECT_EQ(pi.connection_successes, 1);
    EXPECT_EQ(pi.score, 10);
}

TEST(PeerInfo, RecordDisconnected_RegularPeer)
{
    PeerInfo pi;
    pi.is_protected = false;
    pi.backoff_sec = 30;
    
    pi.record_disconnected();
    EXPECT_EQ(pi.attempt_count, 1);
    EXPECT_EQ(pi.backoff_sec, 60);      // doubled
    
    pi.record_disconnected();
    EXPECT_EQ(pi.attempt_count, 2);
    EXPECT_EQ(pi.backoff_sec, 120);     // doubled

    // Cap at 3600s for regular peers
    pi.backoff_sec = 2000;
    pi.record_disconnected();
    EXPECT_EQ(pi.backoff_sec, 3600);    // capped
}

TEST(PeerInfo, RecordDisconnected_ProtectedPeer)
{
    PeerInfo pi;
    pi.is_protected = true;
    pi.backoff_sec = 300;
    
    pi.record_disconnected();
    EXPECT_EQ(pi.backoff_sec, 600);     // capped at 600 for protected

    pi.record_disconnected();
    EXPECT_EQ(pi.backoff_sec, 600);     // stays at 600
}

TEST(PeerInfo, CanRetry_Protected)
{
    PeerInfo pi;
    pi.is_protected = true;
    pi.attempt_count = 999;
    pi.last_attempt = std::chrono::steady_clock::now() -
        std::chrono::seconds(1);
    // Protected peer can always retry
    EXPECT_TRUE(pi.can_retry());
}

TEST(PeerInfo, CanRetry_MaxAttempts)
{
    PeerInfo pi;
    pi.is_protected = false;
    pi.max_attempts = 10;
    pi.attempt_count = 10;
    EXPECT_FALSE(pi.can_retry());
}

TEST(PeerInfo, CanRetry_BackoffNotElapsed)
{
    PeerInfo pi;
    pi.is_protected = false;
    pi.max_attempts = 10;
    pi.attempt_count = 1;
    pi.backoff_sec = 60;
    pi.last_attempt = std::chrono::steady_clock::now();
    EXPECT_FALSE(pi.can_retry());
}

TEST(PeerInfo, ComputeScore_Protected)
{
    PeerInfo pi;
    pi.is_protected = true;
    EXPECT_EQ(pi.compute_score(), 999999);
}

TEST(PeerInfo, ComputeScore_AddrCrawlBonus)
{
    PeerInfo pi;
    pi.source = PeerInfo::Source::addr_crawl;
    pi.first_seen = std::chrono::steady_clock::now();
    int score = pi.compute_score();
    // Should include +50 for addr_crawl and +50 for age < 1h
    EXPECT_GE(score, 50);
}

TEST(PeerInfo, ComputeScore_CoindPenalty)
{
    PeerInfo pi;
    pi.source = PeerInfo::Source::coind;
    pi.first_seen = std::chrono::steady_clock::now();
    int score_coind = pi.compute_score();

    PeerInfo pi2;
    pi2.source = PeerInfo::Source::addr_crawl;
    pi2.first_seen = std::chrono::steady_clock::now();
    int score_addr = pi2.compute_score();

    // addr_crawl should score higher than coind
    EXPECT_GT(score_addr, score_coind);
}

TEST(PeerInfo, ComputeScore_BlockRelayActivity)
{
    PeerInfo pi;
    pi.first_seen = std::chrono::steady_clock::now();
    int base = pi.compute_score();

    pi.blocks_relayed = 11;
    int with_relay = pi.compute_score();
    EXPECT_GT(with_relay, base);
    // 11 blocks → +30
    EXPECT_EQ(with_relay - base, 30);
}

// ─── PeerManagerConfig tests ─────────────────────────────────────────────────

TEST(PeerManagerConfig, Defaults)
{
    PeerManagerConfig cfg;
    EXPECT_EQ(cfg.max_peers, 20);
    EXPECT_EQ(cfg.min_peers, 5);
    EXPECT_EQ(cfg.max_concurrent_connections, 3);
    EXPECT_EQ(cfg.max_connections_per_cycle, 5);
    EXPECT_EQ(cfg.base_backoff_sec, 30);
    EXPECT_EQ(cfg.max_backoff_sec, 3600);
    EXPECT_EQ(cfg.max_connection_attempts, 10);
    EXPECT_EQ(cfg.refresh_interval_sec, 1800);
    EXPECT_EQ(cfg.peer_db_save_interval_sec, 300);
    EXPECT_FALSE(cfg.is_merged);
    EXPECT_TRUE(cfg.valid_ports.empty());
}

TEST(PeerManagerConfig, MergedDefaults)
{
    PeerManagerConfig cfg;
    cfg.is_merged = true;
    cfg.min_peers = 4;
    cfg.max_connection_attempts = 5;
    cfg.refresh_interval_sec = 300;
    EXPECT_EQ(cfg.min_peers, 4);
    EXPECT_EQ(cfg.max_connection_attempts, 5);
    EXPECT_EQ(cfg.refresh_interval_sec, 300);
}

// ─── CoinPeerManager tests ──────────────────────────────────────────────────

TEST(CoinPeerManager, BasicLifecycle)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "TEST", "/tmp", cfg);
    
    EXPECT_EQ(pm.peer_count(), 0);
    EXPECT_EQ(pm.symbol(), "TEST");
    EXPECT_TRUE(pm.discovery_enabled());
}

TEST(CoinPeerManager, SetLocalNode)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.set_local_node(NetService("192.168.1.1", 19335));
    EXPECT_EQ(pm.peer_count(), 1);
}

TEST(CoinPeerManager, AddDiscoveredPeer)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.valid_ports = {9333, 19335};
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    // Valid port — should be added
    pm.add_discovered_peer(NetService("10.0.0.1", 19335));
    EXPECT_EQ(pm.peer_count(), 1);
    
    // Invalid port — should be rejected
    pm.add_discovered_peer(NetService("10.0.0.2", 54321));
    EXPECT_EQ(pm.peer_count(), 1);
    
    // Duplicate — should be skipped
    pm.add_discovered_peer(NetService("10.0.0.1", 19335));
    EXPECT_EQ(pm.peer_count(), 1);
}

TEST(CoinPeerManager, AddDiscoveredPeer_NoPortFilter)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    // Empty valid_ports → accept any port
    CoinPeerManager pm(ioc, "TEST", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 54321));
    EXPECT_EQ(pm.peer_count(), 1);
}

TEST(CoinPeerManager, GetPeersToConnect_Empty)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    std::set<std::string> connected;
    auto peers = pm.get_peers_to_connect(connected);
    EXPECT_TRUE(peers.empty());
}

TEST(CoinPeerManager, GetPeersToConnect_ReturnsAvailable)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_peers = 20;
    cfg.max_connections_per_cycle = 3;
    cfg.max_concurrent_connections = 5;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    // Add some peers
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    pm.add_discovered_peer(NetService("10.0.0.2", 9333));
    pm.add_discovered_peer(NetService("10.0.0.3", 9333));
    pm.add_discovered_peer(NetService("10.0.0.4", 9333));
    
    std::set<std::string> connected;
    auto peers = pm.get_peers_to_connect(connected);
    // Should return up to max_connections_per_cycle=3
    EXPECT_LE(peers.size(), 3u);
    EXPECT_GE(peers.size(), 1u);
}

TEST(CoinPeerManager, GetPeersToConnect_ExcludesConnected)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    
    std::set<std::string> connected = {"10.0.0.1:9333"};
    auto peers = pm.get_peers_to_connect(connected);
    EXPECT_TRUE(peers.empty());
}

TEST(CoinPeerManager, GetPeersToConnect_RespectMaxPeers)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_peers = 2;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    pm.add_discovered_peer(NetService("10.0.0.2", 9333));
    pm.add_discovered_peer(NetService("10.0.0.3", 9333));
    
    // Already at max_peers
    std::set<std::string> connected = {"10.0.0.5:9333", "10.0.0.6:9333"};
    auto peers = pm.get_peers_to_connect(connected);
    EXPECT_TRUE(peers.empty());
}

TEST(CoinPeerManager, NotifyConnected_ResetBackoff)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    pm.notify_connected("10.0.0.1:9333");
    // After connected notification, peer should be marked with reset backoff
    // (only verifiable through scoring, but should not throw)
}

TEST(CoinPeerManager, NotifyDisconnected)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    pm.notify_disconnected("10.0.0.1:9333");
    // Should not throw, just increment attempt count
}

TEST(CoinPeerManager, BroadcastRecording)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    pm.record_broadcast_success("10.0.0.1:9333");
    pm.record_broadcast_failure("10.0.0.1:9333");
    // Should not throw
}

TEST(CoinPeerManager, NeedsEmergencyRefresh)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.min_peers = 5;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    EXPECT_TRUE(pm.needs_emergency_refresh(3));
    EXPECT_FALSE(pm.needs_emergency_refresh(5));
    EXPECT_FALSE(pm.needs_emergency_refresh(10));
}

TEST(CoinPeerManager, DiscoveryEnabled_MaxPeers)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_peers = 2;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    EXPECT_TRUE(pm.discovery_enabled());
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    pm.add_discovered_peer(NetService("10.0.0.2", 9333));
    EXPECT_FALSE(pm.discovery_enabled()); // at max
    
    pm.add_discovered_peer(NetService("10.0.0.3", 9333)); // rejected
    EXPECT_EQ(pm.peer_count(), 2);
}

TEST(CoinPeerManager, PruneDead)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_connection_attempts = 3;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    // Simulate 3 disconnections to exhaust attempts
    pm.notify_disconnected("10.0.0.1:9333");
    pm.notify_disconnected("10.0.0.1:9333");
    pm.notify_disconnected("10.0.0.1:9333");
    
    pm.prune_dead_peers();
    EXPECT_EQ(pm.peer_count(), 0);
}

TEST(CoinPeerManager, PruneDead_ProtectsLocalNode)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_connection_attempts = 3;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.set_local_node(NetService("192.168.1.1", 19335));
    // Simulate many disconnections
    for (int i = 0; i < 20; ++i) {
        pm.notify_disconnected("192.168.1.1:19335");
    }
    
    pm.prune_dead_peers();
    EXPECT_EQ(pm.peer_count(), 1);  // local node not pruned
}

TEST(CoinPeerManager, GetPeerInfoBootstrap)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.valid_ports = {9333, 19335};
    // Use unique temp dir to avoid stale JSON from previous runs
    std::string tmp_dir = "/tmp/test_pm_bootstrap_" + std::to_string(::getpid());
    ::mkdir(tmp_dir.c_str(), 0755);
    CoinPeerManager pm(ioc, "LTC", tmp_dir, cfg);
    
    pm.set_getpeerinfo_fn([]() -> std::vector<NetService> {
        return {
            NetService("10.0.0.1", 19335),
            NetService("10.0.0.2", 19335),
            NetService("10.0.0.3", 54321),  // invalid port
        };
    });
    
    pm.start();
    // Should have peers from getpeerinfo (2 valid, 1 filtered) 
    EXPECT_EQ(pm.peer_count(), 2);
    pm.stop();
    // Cleanup
    std::string db = tmp_dir + "/broadcast_peers_LTC.json";
    ::unlink(db.c_str());
    ::rmdir(tmp_dir.c_str());
}

TEST(CoinPeerManager, ScoreSortedPriority)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_connections_per_cycle = 1;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    // Add local node (highest score)
    pm.set_local_node(NetService("192.168.1.1", 19335));
    
    // Add discovered peer (lower score)
    pm.add_discovered_peer(NetService("10.0.0.1", 9333));
    
    std::set<std::string> connected;
    auto peers = pm.get_peers_to_connect(connected);
    // Should return the protected local node first (score=999999)
    ASSERT_GE(peers.size(), 1u);
    EXPECT_EQ(peers[0].to_string(), "192.168.1.1:19335");
}

// ─── BroadcasterConfig tests ────────────────────────────────────────────────

TEST(BroadcasterConfig, Construction)
{
    std::vector<std::byte> prefix = {std::byte{0xfd}, std::byte{0xd2}, 
                                      std::byte{0xc8}, std::byte{0xf1}};
    NetService addr("192.168.1.1", 19335);
    BroadcasterConfig cfg(prefix, addr);
    
    EXPECT_EQ(cfg.coin()->m_p2p.prefix.size(), 4u);
    EXPECT_EQ(cfg.coin()->m_p2p.address.to_string(), "192.168.1.1:19335");
}

// ─── CoinBroadcaster construction tests ──────────────────────────────────────

TEST(CoinBroadcaster, ConstructionDefaults)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix = {std::byte{0xfd}, std::byte{0xd2}, 
                                      std::byte{0xc8}, std::byte{0xf1}};
    CoinBroadcaster bc(ioc, "LTC", prefix, NetService("192.168.1.1", 19335));
    
    EXPECT_EQ(bc.symbol(), "LTC");
    EXPECT_EQ(bc.connected_count(), 0);
}

TEST(CoinBroadcaster, ConstructionWithConfig)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix = {std::byte{0xd4}, std::byte{0xa1}, 
                                      std::byte{0xf4}, std::byte{0xa1}};
    PeerManagerConfig pm_cfg;
    pm_cfg.is_merged = true;
    pm_cfg.max_peers = 20;
    pm_cfg.min_peers = 4;
    pm_cfg.valid_ports = {22556, 44556};
    
    CoinBroadcaster bc(ioc, "DOGE", prefix,
                        NetService("192.168.86.27", 44556),
                        "/tmp", pm_cfg);
    
    EXPECT_EQ(bc.symbol(), "DOGE");
    EXPECT_EQ(bc.connected_count(), 0);
}

// ─── PeerManagerConfig valid_ports filtering ─────────────────────────────────

TEST(PeerManagerConfig, ValidPorts_DOGE)
{
    PeerManagerConfig cfg;
    cfg.valid_ports = {22556, 44556, 44557};
    
    EXPECT_TRUE(cfg.valid_ports.count(22556));
    EXPECT_TRUE(cfg.valid_ports.count(44556));
    EXPECT_TRUE(cfg.valid_ports.count(44557));
    EXPECT_FALSE(cfg.valid_ports.count(8333));
}

TEST(PeerManagerConfig, ValidPorts_LTC)
{
    PeerManagerConfig cfg;
    cfg.valid_ports = {9333, 19335};
    
    EXPECT_TRUE(cfg.valid_ports.count(9333));
    EXPECT_TRUE(cfg.valid_ports.count(19335));
    EXPECT_FALSE(cfg.valid_ports.count(22556));
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
