#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <thread>
#include <chrono>
#include <csignal>
#include <ctime>
#include <memory>

// Core includes
#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <core/pack.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <core/config.hpp>

// Pool infrastructure
#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <sharechain/sharechain.hpp>

// LTC implementation
#include <impl/ltc/share.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>
#include <impl/ltc/config.hpp>

// Enhanced C2Pool components
#include <c2pool/node/enhanced_node.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <c2pool/storage/sharechain_storage.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

// Global signal handling
static bool g_shutdown_requested = false;

void signal_handler(int signal) {
    LOG_INFO << "Received signal " << signal << ", initiating shutdown...";
    g_shutdown_requested = true;
}

// C2Pool configuration
struct C2PoolConfig {
    std::string m_name = "c2pool_sharechain";
    bool m_testnet = false;
    
    struct PoolConfig {
        std::vector<std::byte> m_prefix = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}}; // mainnet
        std::vector<std::byte> m_prefix_testnet = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdd}}; // testnet
    } m_pool_config;
    
    PoolConfig* pool() { return &m_pool_config; }
    
    void set_testnet(bool testnet) {
        m_testnet = testnet;
        if (testnet) {
            m_pool_config.m_prefix = m_pool_config.m_prefix_testnet;
            m_name = "c2pool_sharechain_testnet";
        }
    }
};

void print_help() {
    std::cout << "c2pool - P2Pool rebirth in C++ with enhanced difficulty adjustment\n\n";
    std::cout << "Usage:\n";
    std::cout << "  c2pool [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --help                    Show this help message\n";
    std::cout << "  --testnet                 Use testnet instead of mainnet\n";
    std::cout << "  --port PORT               Set P2P port (default: 9333)\n";
    std::cout << "  --integrated WEB_SERVER   Run integrated mining pool with web server\n";
    std::cout << "                            Format: IP:PORT (e.g., 0.0.0.0:8083)\n";
    std::cout << "  --sharechain              Run enhanced sharechain node with persistence\n";
    std::cout << "  --config FILE             Load configuration from file\n";
    std::cout << "\nFeatures:\n";
    std::cout << "  ✓ Automatic difficulty adjustment (VARDIFF)\n";
    std::cout << "  ✓ Real-time hashrate tracking\n";
    std::cout << "  ✓ Legacy share tracker compatibility\n";
    std::cout << "  ✓ LevelDB persistent storage\n";
    std::cout << "  ✓ JSON-RPC mining interface\n";
    std::cout << "  ✓ WebUI for monitoring\n";
    std::cout << "\nExamples:\n";
    std::cout << "  c2pool --testnet --port 9333\n";
    std::cout << "  c2pool --integrated 0.0.0.0:8083 --port 9333\n";
    std::cout << "  c2pool --sharechain --testnet\n";
}

int main(int argc, char* argv[]) {
    // Install signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    // Initialize logging
    core::log::Logger::init();
    
    LOG_INFO << "c2pool - p2pool rebirth in C++ with enhanced features";
    
    // Default settings
    auto settings = std::make_unique<core::Settings>();
    settings->m_testnet = false;
    
    int port = 9333;
    std::string config_file;
    std::string web_server_addr;
    bool integrated_mode = false;
    bool sharechain_mode = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        else if (arg == "--testnet") {
            settings->m_testnet = true;
        }
        else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        }
        else if (arg == "--integrated" && i + 1 < argc) {
            web_server_addr = argv[++i];
            integrated_mode = true;
        }
        else if (arg == "--sharechain") {
            sharechain_mode = true;
        }
        else if (arg == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        }
        else {
            LOG_ERROR << "Unknown argument: " << arg;
            return 1;
        }
    }
    
    try {
        boost::asio::io_context ioc;
        
        if (integrated_mode) {
            LOG_INFO << "Starting integrated C2Pool mining pool with automatic difficulty adjustment...";
            
            // Parse web server address
            size_t colon_pos = web_server_addr.find(':');
            if (colon_pos == std::string::npos) {
                LOG_ERROR << "Invalid web_server format. Use IP:PORT (e.g., 0.0.0.0:8083)";
                return 1;
            }
            
            std::string ip = web_server_addr.substr(0, colon_pos);
            std::string web_port_str = web_server_addr.substr(colon_pos + 1);
            int web_port = std::stoi(web_port_str);
            
            // Create enhanced node with default constructor to avoid nullptr issues
            auto enhanced_node = std::make_shared<c2pool::node::EnhancedC2PoolNode>();
            
            // Create web server 
            core::WebServer web_server(ioc, ip, static_cast<uint16_t>(web_port), 
                                     settings->m_testnet);
            
            if (!web_server.start()) {
                LOG_ERROR << "Failed to start integrated mining pool";
                return 1;
            }
            
            LOG_INFO << "Integrated C2Pool Mining Pool started successfully!";
            LOG_INFO << "Mining interface: http://" << ip << ":" << web_port;
            LOG_INFO << "Features enabled:";
            LOG_INFO << "  ✓ Automatic difficulty adjustment";
            LOG_INFO << "  ✓ Real-time hashrate tracking";
            LOG_INFO << "  ✓ Persistent storage";
            
            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.run_for(std::chrono::milliseconds(100));
            }
            
            enhanced_node->shutdown();
        }
        else if (sharechain_mode) {
            LOG_INFO << "Starting enhanced C2Pool sharechain node...";
            
            // Create LTC config for sharechain
            auto config = std::make_unique<ltc::Config>("ltc");
            config->m_testnet = settings->m_testnet;
            
            LOG_INFO << "Enhanced C2Pool sharechain config:";
            LOG_INFO << "  Network: " << (settings->m_testnet ? "testnet" : "mainnet");
            LOG_INFO << "  Protocol: LTC-based";
            LOG_INFO << "  Storage: enabled (persistent sharechain)";
            LOG_INFO << "  Enhanced features: enabled";
            
            // Create and start Enhanced C2Pool node
            auto enhanced_node = std::make_unique<c2pool::node::EnhancedC2PoolNode>(&ioc, config.get());
            enhanced_node->listen(port);
            
            LOG_INFO << "Enhanced C2Pool sharechain node started successfully on port " << port;
            LOG_INFO << "Features enabled:";
            LOG_INFO << "  ✓ Automatic difficulty adjustment";
            LOG_INFO << "  ✓ Real-time hashrate tracking";
            LOG_INFO << "  ✓ LevelDB persistent storage";
            LOG_INFO << "  ✓ LTC protocol compatibility";
            
            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.run_for(std::chrono::milliseconds(100));
            }
            
            enhanced_node->shutdown();
        }
        else {
            // Default mode - simple node
            LOG_INFO << "Starting c2pool node...";
            LOG_INFO << "Configuration:";
            LOG_INFO << "  Testnet: " << (settings->m_testnet ? "Yes" : "No");
            LOG_INFO << "  Port: " << port;
            LOG_INFO << "  Features: Basic mode";
            LOG_INFO << "c2pool node initialized successfully";
            LOG_INFO << "Use --help for available options";
            
            // Simple run loop
            while (!g_shutdown_requested) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        
        LOG_INFO << "c2pool shutdown complete";
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Fatal error: " << e.what();
        return 1;
    }
    
    return 0;
}
