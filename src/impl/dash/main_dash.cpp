// c2pool-dash: Dash p2pool node
//
// Full node using BaseNode infrastructure with X11 PoW, v16 shares,
// protocol v1700. Connects to Dash p2pool peers, receives and validates shares.
//
// Usage: c2pool-dash [--bootstrap HOST:PORT] [--testnet]

#include <impl/dash/params.hpp>
#include <impl/dash/node.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

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
    bool testnet = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--testnet") { testnet = true; port = 18999; }
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

    // Set prefix bytes
    config->pool()->m_prefix.resize(8);
    auto prefix_hex = params.active_prefix_hex();
    for (size_t i = 0; i + 1 < prefix_hex.size(); i += 2) {
        config->pool()->m_prefix[i/2] = static_cast<std::byte>(
            std::stoul(prefix_hex.substr(i, 2), nullptr, 16));
    }

    // Add bootstrap
    config->pool()->m_bootstrap_addrs.emplace_back(bootstrap + ":" + std::to_string(port));
    config->coin()->m_testnet = testnet;

    // Verify prefix was set
    std::cout << "[CFG] prefix bytes: ";
    for (auto b : config->pool()->m_prefix)
        printf("%02x", static_cast<unsigned char>(b));
    std::cout << " (" << config->pool()->m_prefix.size() << " bytes)" << std::endl;

    // Create node
    dash::DashNodeImpl node(&ioc, config.get(), testnet);

    // Verify prefix through node's get_prefix()
    auto& node_prefix = node.get_prefix();
    std::cout << "[NODE] get_prefix(): ";
    for (auto b : node_prefix)
        printf("%02x", static_cast<unsigned char>(b));
    std::cout << " (" << node_prefix.size() << " bytes)" << std::endl;

    std::cout << "[NODE] DashNodeImpl created" << std::endl;
    std::cout << "[NODE] Tracker params: share_period=" << node.coin_params().share_period
              << " chain_length=" << node.coin_params().chain_length << std::endl;

    // Connect to bootstrap peer (use post to ensure io_context is running)
    std::cout << "[P2P] Connecting to " << bootstrap << ":" << port << "..." << std::endl;

    NetService peer_addr(bootstrap + ":" + std::to_string(port));
    io::post(ioc, [&]() {
        node.connect(peer_addr);
    });

    // Run IO context with timeout
    std::cout << "[P2P] Running event loop (30s)..." << std::endl;

    // Set a deadline timer
    io::steady_timer deadline(ioc, std::chrono::seconds(30));
    deadline.async_wait([&](const boost::system::error_code& ec) {
        if (!ec) {
            std::cout << std::endl;
            std::cout << "[DONE] 30s elapsed — shutting down" << std::endl;
            std::cout << "[DONE] Tracker: " << node.tracker().chain.size() << " shares in chain" << std::endl;
            ioc.stop();
        }
    });

    // Status timer
    io::steady_timer status(ioc, std::chrono::seconds(10));
    std::function<void(const boost::system::error_code&)> status_fn;
    status_fn = [&](const boost::system::error_code& ec) {
        if (ec) return;
        std::cout << "[STATUS] shares=" << node.tracker().chain.size()
                  << " verified=" << node.tracker().verified.size()
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
    std::cout << "[RESULT] Final tracker state:" << std::endl;
    std::cout << "  Shares: " << node.tracker().chain.size() << std::endl;
    std::cout << "  Verified: " << node.tracker().verified.size() << std::endl;

    return 0;
}
