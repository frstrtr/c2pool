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
/// Peer rotation: public LTC nodes with full inbound slots evict a fresh,
/// zero-relay peer within seconds of verack (runs 39005660193 + 39010744011,
/// 2026-10-17: EOF 0.5-4.4s after connect, every reconnect). One unlucky pick
/// must not red the gate, so up to kMaxCandidates reachable peers are tried in
/// turn, and getheaders is sent on every completed handshake (including
/// reconnects) instead of once on a fixed timer. The gate still FAILS when
/// every candidate completes TCP connect and none delivers headers.
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
#include <functional>
#include <iostream>
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

    // ── Stage 2: collect TCP-reachable peers on the P2P port ─────────────────
    constexpr int kProbeBudget = 16;          // bound the probe time (3s each)
    constexpr size_t kMaxCandidates = 4;
    std::vector<NetService> reachable;
    int probed = 0;
    for (const auto& p : peers) {
        if (probed++ >= kProbeBudget || reachable.size() >= kMaxCandidates) break;
        if (tcp_probe(p.address(), p.port())) reachable.push_back(p);
    }
    if (reachable.empty()) {
        GTEST_SKIP() << "SKIP[p2p-egress-blocked]: DNS resolved " << peers.size()
                     << " peers but NONE accepted a TCP connection on the LTC "
                        "P2P port within the probe window — P2P egress is blocked "
                        "on this runner. Handshake was NOT exercised.";
    }
    std::cout << "[bootstrap-gate] TCP-reachable peers: " << reachable.size()
              << " of " << probed << " probed" << std::endl;

    // ── Stage 3: real handshake + getheaders, rotating across candidates ─────
    // Network is reachable from here on — NO further skips; we ASSERT.
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
    std::string served_by;
    size_t tried = 0;

    using clock = std::chrono::steady_clock;
    const auto stage3_deadline = clock::now() + std::chrono::seconds(120);
    constexpr auto kIdleWindow = std::chrono::seconds(30);   // no headers -> next peer

    for (const auto& addr : reachable) {
        if (clock::now() >= stage3_deadline) break;
        ++tried;
        std::cout << "[bootstrap-gate] candidate " << tried << "/" << reachable.size()
                  << ": " << addr.to_string() << std::endl;

        io::io_context ioc;
        BroadcastPeer peer(&ioc, addr.to_string(), LTC_MAINNET_PREFIX, addr);
        auto last_progress = clock::now();
        bool requested = false;

        peer.coin_node.new_headers.subscribe(
            [&](const std::vector<BlockHeaderType>& hdrs) {
                header_msgs.fetch_add(1, std::memory_order_relaxed);
                last_progress = clock::now();
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

        // Send getheaders once per completed handshake (verack), so a peer
        // that drops us and is reconnected gets asked again.
        io::steady_timer tick(ioc);
        std::function<void()> arm = [&]() {
            tick.expires_after(std::chrono::milliseconds(250));
            tick.async_wait([&](const boost::system::error_code& ec) {
                if (ec) return;
                const auto now = clock::now();
                if (now >= stage3_deadline || now - last_progress >= kIdleWindow) {
                    ioc.stop();
                    return;
                }
                if (!peer.node_p2p.is_handshake_complete()) {
                    requested = false;
                } else if (!requested) {
                    peer.node_p2p.send_getheaders(70017, chain.get_locator(), uint256::ZERO);
                    requested = true;
                }
                arm();
            });
        };
        arm();

        ioc.run();

        if (accepted_total.load() > 0) { served_by = addr.to_string(); break; }
        std::cout << "[bootstrap-gate] " << addr.to_string()
                  << " delivered no headers; rotating" << std::endl;
    }

    const uint32_t final_height = chain.height();
    std::cout << "[bootstrap-gate] RESULT: header_msgs=" << header_msgs.load()
              << " accepted_total=" << accepted_total.load()
              << " tip_height=" << final_height
              << " candidates_tried=" << tried << std::endl;

    // ── Assertions: the TIP ADVANCED (not merely "no crash") ─────────────────
    ASSERT_GT(header_msgs.load(), 0)
        << tried << " reachable peer(s) completed TCP connect but none delivered "
           "a headers message — the version/verack or getheaders path is BROKEN.";
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
              << served_by << std::endl;
}
