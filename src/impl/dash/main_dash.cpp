// c2pool-dash: Dash p2pool node
//
// Full node using BaseNode infrastructure with X11 PoW, v16 shares,
// protocol v1700. Connects to Dash p2pool peers and dashd daemon.
//
// Usage: c2pool-dash [--bootstrap HOST:PORT] [--dashd HOST:PORT] [--testnet]

#include <impl/dash/params.hpp>
#include <impl/dash/node.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/node.hpp>

#include <core/coin_params.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <iostream>
#include <string>
#include <thread>
#include <chrono>

namespace io = boost::asio;

int main(int argc, char* argv[])
{
    std::string bootstrap = "rov.p2p-spb.xyz";
    uint16_t port = 8999;
    std::string dashd_host;
    uint16_t dashd_port = 9999;
    bool testnet = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--testnet") { testnet = true; port = 18999; dashd_port = 19999; }
        else if (arg == "--bootstrap" && i + 1 < argc) {
            std::string addr = argv[++i];
            auto colon = addr.find(':');
            if (colon != std::string::npos) {
                bootstrap = addr.substr(0, colon);
                port = static_cast<uint16_t>(std::stoul(addr.substr(colon + 1)));
            } else {
                bootstrap = addr;
            }
        }
        else if (arg == "--dashd" && i + 1 < argc) {
            std::string addr = argv[++i];
            auto colon = addr.find(':');
            if (colon != std::string::npos) {
                dashd_host = addr.substr(0, colon);
                dashd_port = static_cast<uint16_t>(std::stoul(addr.substr(colon + 1)));
            } else {
                dashd_host = addr;
            }
        }
    }

    std::cout << "╔══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║           c2pool-dash — Dash p2pool node                ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;

    // X11 self-test
    {
        unsigned char zeros[80] = {};
        uint256 h = dash::crypto::hash_x11(zeros, 80);
        std::cout << "[X11] self-test: " << h.GetHex().substr(0, 16) << "... OK" << std::endl;
    }

    // Create params
    auto params = dash::make_coin_params(testnet);
    std::cout << "[INIT] " << params.symbol
              << " protocol=" << params.minimum_protocol_version
              << " share_period=" << params.share_period
              << " chain_length=" << params.chain_length
              << std::endl;

    // Create IO context
    io::io_context ioc;

    // Create config
    std::string coin_name = testnet ? "dash_testnet" : "dash";
    auto config = std::make_unique<dash::Config>(coin_name);

    // Set p2pool prefix bytes
    config->pool()->m_prefix.resize(8);
    auto prefix_hex = params.active_prefix_hex();
    for (size_t i = 0; i + 1 < prefix_hex.size(); i += 2) {
        config->pool()->m_prefix[i/2] = static_cast<std::byte>(
            std::stoul(prefix_hex.substr(i, 2), nullptr, 16));
    }

    // Set dashd wire prefix (pchMessageStart bytes in order)
    {
        config->coin()->m_p2p.prefix.resize(4);
        if (testnet) {
            config->coin()->m_p2p.prefix[0] = std::byte{0xce};
            config->coin()->m_p2p.prefix[1] = std::byte{0xe2};
            config->coin()->m_p2p.prefix[2] = std::byte{0xca};
            config->coin()->m_p2p.prefix[3] = std::byte{0xff};
        } else {
            config->coin()->m_p2p.prefix[0] = std::byte{0xbf};
            config->coin()->m_p2p.prefix[1] = std::byte{0x0c};
            config->coin()->m_p2p.prefix[2] = std::byte{0x6b};
            config->coin()->m_p2p.prefix[3] = std::byte{0xbd};
        }
    }

    // Add bootstrap
    config->pool()->m_bootstrap_addrs.emplace_back(bootstrap + ":" + std::to_string(port));
    config->coin()->m_testnet = testnet;

    // Verify p2pool prefix
    std::cout << "[CFG] p2pool prefix: ";
    for (auto b : config->pool()->m_prefix)
        printf("%02x", static_cast<unsigned char>(b));
    std::cout << std::endl;

    // Verify dashd prefix
    std::cout << "[CFG] dashd prefix: ";
    for (auto b : config->coin()->m_p2p.prefix)
        printf("%02x", static_cast<unsigned char>(b));
    std::cout << std::endl;

    // ── Header Chain (SPV) ──
    auto chain_params = testnet
        ? dash::coin::make_dash_chain_params_testnet()
        : dash::coin::make_dash_chain_params_mainnet();

    std::string header_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
        + "/.c2pool/" + coin_name + "/embedded_headers";
    dash::coin::HeaderChain header_chain(chain_params, header_db_path);
    if (!header_chain.init()) {
        std::cerr << "[ERROR] Failed to initialize header chain LevelDB" << std::endl;
        return 1;
    }
    std::cout << "[HEADERS] Initialized: height=" << header_chain.height()
              << " headers=" << header_chain.size() << std::endl;

    // ── Pool Node ──
    dash::DashNodeImpl node(&ioc, config.get(), testnet);
    std::cout << "[NODE] DashNodeImpl created" << std::endl;

    // ── Coin P2P Node (dashd connection) ──
    std::unique_ptr<dash::coin::Node<dash::Config>> coin_node;
    if (!dashd_host.empty()) {
        coin_node = std::make_unique<dash::coin::Node<dash::Config>>(&ioc, config.get());

        // Wire new_headers event → header chain
        coin_node->new_headers.subscribe([&](std::vector<dash::coin::BlockHeaderType> headers) {
            int accepted = header_chain.add_headers(headers);
            if (accepted > 0 && headers.size() >= 2000) {
                // More headers available — continue sync
                auto locator = header_chain.get_locator();
                coin_node->send_getheaders(70230, locator, uint256());
            }
        });

        // Wire new_block event → log
        coin_node->new_block.subscribe([&](uint256 hash) {
            LOG_INFO << "[DASH] New block announced: " << hash.GetHex().substr(0, 16);
        });

        // Wire full_block event → log
        coin_node->full_block.subscribe([&](dash::coin::BlockType block) {
            auto hdr = static_cast<dash::coin::BlockHeaderType>(block);
            auto bhash = dash::coin::x11_hash(hdr);
            LOG_INFO << "[DASH] Full block: " << bhash.GetHex().substr(0, 16)
                     << " txs=" << block.m_txs.size();
        });

        // Start dashd P2P after io_context starts
        config->coin()->m_p2p.address = NetService(dashd_host + ":" + std::to_string(dashd_port));
        io::post(ioc, [&]() {
            coin_node->start_p2p(config->coin()->m_p2p.address);

            // After short delay, send initial getheaders to start sync
            auto init_timer = std::make_shared<io::steady_timer>(ioc, std::chrono::seconds(3));
            init_timer->async_wait([&, init_timer](const boost::system::error_code& ec) {
                if (ec) return;
                auto locator = header_chain.get_locator();
                // If chain is empty, use genesis as locator
                if (locator.empty())
                    locator.push_back(chain_params.genesis_hash);
                coin_node->send_getheaders(70230, locator, uint256());
                LOG_INFO << "[DASH] Sent initial getheaders (locator=" << locator.size() << " entries)";
            });
        });

        std::cout << "[DASHD] Connecting to " << dashd_host << ":" << dashd_port << std::endl;
    } else {
        std::cout << "[DASHD] No --dashd specified, running without coin daemon P2P" << std::endl;
    }

    // ── Connect to p2pool peer ──
    std::cout << "[P2P] Connecting to " << bootstrap << ":" << port << "..." << std::endl;
    NetService peer_addr(bootstrap + ":" + std::to_string(port));
    io::post(ioc, [&]() {
        node.connect(peer_addr);
    });

    // Run IO context
    std::cout << "[P2P] Running event loop..." << std::endl;

    // Status timer
    io::steady_timer status(ioc, std::chrono::seconds(10));
    std::function<void(const boost::system::error_code&)> status_fn;
    status_fn = [&](const boost::system::error_code& ec) {
        if (ec) return;
        std::cout << "[STATUS] shares=" << node.tracker().chain.size()
                  << " headers=" << header_chain.height()
                  << "/" << header_chain.size()
                  << (header_chain.is_synced() ? " SYNCED" : " syncing")
                  << std::endl;
        status.expires_after(std::chrono::seconds(10));
        status.async_wait(status_fn);
    };
    status.async_wait(status_fn);

    try {
        ioc.run();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }

    std::cout << std::endl;
    std::cout << "[RESULT] Final state:" << std::endl;
    std::cout << "  Shares: " << node.tracker().chain.size() << std::endl;
    std::cout << "  Headers: " << header_chain.height() << "/" << header_chain.size() << std::endl;
    std::cout << "  Synced: " << (header_chain.is_synced() ? "YES" : "NO") << std::endl;

    return 0;
}
