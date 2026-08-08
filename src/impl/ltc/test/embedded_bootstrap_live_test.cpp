// SPDX-License-Identifier: AGPL-3.0-or-later
/// LTC embedded-bootstrap live gate.
///
/// Proves the DEFAULT-ON embedded LTC bootstrap path end-to-end against the
/// REAL Litecoin P2P network, with NO operator-supplied peers and NO hardcoded
/// LAN daemon:
///
///   DNS-seed resolve  ->  TCP connect  ->  version/verack  ->  getheaders
///   ->  HeaderChain tip ADVANCES past genesis.
///
/// This is the coverage the five test/test_phase*_live.cpp harnesses do NOT
/// provide: they dial a hardcoded LAN testnet daemon (192.168.86.26), their
/// fixtures are named *LiveTest and are excluded by
/// `ctest --exclude-regex 'LiveTest\.'`. So the bootstrap that
/// main_ltc.cpp `bool embedded_ltc = true` turns on for every mainnet user had,
/// until this gate, ZERO CI coverage — and BTC/DGB/BCH/DASH copy this path as
/// "reuse", i.e. they copy UNPROVEN code.
///
/// Reachability contract (so a silent skip can never masquerade as green):
///   * DNS resolves zero peers          -> GTEST_SKIP naming the DNS failure.
///   * DNS ok but NO peer is TCP-reachable on the P2P port
///                                      -> GTEST_SKIP naming the egress failure.
///   * A peer IS reachable              -> NO skip. We ASSERT the tip advances.
///     A reachable network that fails to advance the tip is a real FAILURE of
///     the bootstrap path — exactly what this gate exists to catch.
///
/// Seed source: ltc_mainnet_dns_seeds() (the real public LTC DNS seeds) by
/// default, overridable to our own deterministic bootstrap host via the
/// LTC_BOOTSTRAP_DNS_SEED env var once
/// chain_seeds.hpp:ltc_embedded_bootstrap_seeds() is pinned. Either way the
/// seed is resolved THROUGH the DnsSeeder — never a hardcoded IP.

#include <gtest/gtest.h>

#include <impl/ltc/config_coin.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/chain_seeds.hpp>
#include <c2pool/merged/coin_broadcaster.hpp>

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <core/log.hpp>

#include <boost/asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace io = boost::asio;
using namespace ltc::coin;
using namespace c2pool::merged;

// LTC mainnet P2P message-start magic (pchMessageStart): fb c0 b6 db.
static const std::vector<std::byte> LTC_MAINNET_PREFIX = {
    std::byte{0xfb}, std::byte{0xc0}, std::byte{0xb6}, std::byte{0xdb}
};

static std::string get_env(const char* name, const char* def) {
    const char* v = std::getenv(name);
    return v ? v : def;
}

// Synchronous, bounded TCP reachability probe. Mirrors the harness helper.
static bool tcp_probe(const std::string& host, uint16_t port, int timeout_ms = 3000) {
    try {
        io::io_context ioc;
        io::ip::tcp::socket socket(ioc);
        io::ip::tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        io::steady_timer timer(ioc);
        timer.expires_after(std::chrono::milliseconds(timeout_ms));
        bool connected = false, timed_out = false;
        io::async_connect(socket, endpoints,
            [&](const boost::system::error_code& e, const io::ip::tcp::endpoint&) {
                if (!e) connected = true;
                timer.cancel();
            });
        timer.async_wait([&](const boost::system::error_code& e) {
            if (!e) { timed_out = true; socket.close(); }
        });
        ioc.run();
        return connected && !timed_out;
    } catch (...) { return false; }
}

// Resolve LTC mainnet DNS seeds THROUGH the DnsSeeder (never a hardcoded IP).
static std::vector<NetService> resolve_seeds() {
    io::io_context ioc;
    std::vector<c2pool::dns::DnsSeed> seeds;
    std::string override_host = get_env("LTC_BOOTSTRAP_DNS_SEED", "");
    if (!override_host.empty())
        seeds.push_back({override_host, 9333});
    else
        seeds = ltc_mainnet_dns_seeds();

    std::vector<NetService> out;
    c2pool::dns::DnsSeeder seeder(ioc, seeds);
    seeder.resolve_all([&](std::vector<NetService> peers) { out = std::move(peers); });
    ioc.run();
    return out;
}

TEST(EmbeddedBootstrapGate, DnsResolveHandshakeGetheadersTipAdvance)
{
    core::log::Logger::init();

    // ── Stage 1: DNS resolve through the seeder ──────────────────────────────
    auto peers = resolve_seeds();
    if (peers.empty()) {
        GTEST_SKIP() << "SKIP[dns-unreachable]: DnsSeeder resolved ZERO peers "
                        "from the LTC mainnet DNS seeds — DNS egress is blocked "
                        "on this runner. The bootstrap path was NOT exercised.";
    }
    std::cout << "[bootstrap-gate] DNS resolved " << peers.size()
              << " candidate peers" << std::endl;

    // ── Stage 2: find a TCP-reachable peer on the P2P port ───────────────────
    std::optional<NetService> reachable;
    int probed = 0;
    for (const auto& p : peers) {
        ++probed;
        if (tcp_probe(p.address(), p.port())) { reachable = p; break; }
        if (probed >= 12) break;   // bound the probe budget
    }
    if (!reachable.has_value()) {
        GTEST_SKIP() << "SKIP[p2p-egress-blocked]: DNS resolved " << peers.size()
                     << " peers but NONE accepted a TCP connection on the LTC "
                        "P2P port within the probe window — P2P egress is blocked "
                        "on this runner. Handshake was NOT exercised.";
    }
    std::cout << "[bootstrap-gate] TCP-reachable peer: "
              << reachable->to_string() << std::endl;

    // ── Stage 3: real handshake + getheaders against that peer ───────────────
    // Network is reachable from here on — NO further skips; we ASSERT.
    io::io_context ioc;
    NetService addr = *reachable;
    BroadcastPeer peer(&ioc, addr.to_string(), LTC_MAINNET_PREFIX, addr);

    auto params = make_ltc_chain_params_mainnet();
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());

    // Seed with the LTC mainnet genesis so received height-1 headers connect.
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_previous_block.SetNull();
    genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    genesis.m_timestamp = 1317972665;
    genesis.m_bits = 0x1e0ffff0;
    genesis.m_nonce = 2084524493;
    ASSERT_TRUE(chain.add_header(genesis));
    ASSERT_EQ(chain.height(), 0u);

    std::atomic<int> header_msgs{0};
    std::atomic<int> accepted_total{0};

    peer.coin_node.new_headers.subscribe(
        [&](const std::vector<BlockHeaderType>& hdrs) {
            header_msgs.fetch_add(1, std::memory_order_relaxed);
            int accepted = chain.add_headers(hdrs);
            accepted_total.fetch_add(accepted, std::memory_order_relaxed);
            std::cout << "[bootstrap-gate] headers msg: got " << hdrs.size()
                      << " accepted " << accepted
                      << " tip=" << chain.height() << std::endl;
            if (accepted > 0) {
                // Keep pulling to demonstrate a sustained advance.
                peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
            }
        });

    peer.node_p2p.connect(addr);

    // After version/verack settles, issue getheaders from genesis.
    io::steady_timer handshake_wait(ioc);
    handshake_wait.expires_after(std::chrono::seconds(5));
    handshake_wait.async_wait([&](const boost::system::error_code& ec) {
        if (ec) return;
        peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
    });

    io::steady_timer deadline(ioc);
    deadline.expires_after(std::chrono::seconds(90));
    deadline.async_wait([&](const boost::system::error_code&) { ioc.stop(); });

    ioc.run();

    const uint32_t final_height = chain.height();
    std::cout << "[bootstrap-gate] RESULT: header_msgs=" << header_msgs.load()
              << " accepted_total=" << accepted_total.load()
              << " tip_height=" << final_height << std::endl;

    // ── Assertions: the TIP ADVANCED (not merely "no crash") ─────────────────
    ASSERT_GT(header_msgs.load(), 0)
        << "Reachable peer completed TCP connect but delivered no headers "
           "message — the version/verack or getheaders path is BROKEN.";
    EXPECT_GT(final_height, 0u)
        << "TIP DID NOT ADVANCE past genesis after getheaders — the embedded "
           "bootstrap header-sync path is broken.";

    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(tip->status, HEADER_VALID_CHAIN);
    EXPECT_EQ(tip->height, final_height);
    for (uint32_t h = 0; h <= std::min(final_height, 10u); ++h) {
        EXPECT_TRUE(chain.get_header_by_height(h).has_value())
            << "gap on the best chain at height " << h;
    }

    std::cout << "[bootstrap-gate] PASS: tip advanced genesis(0) -> "
              << final_height << " via DNS-discovered peer "
              << addr.to_string() << std::endl;
}
