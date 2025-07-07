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

// Bring the address validation types into scope
using Blockchain = c2pool::address::Blockchain;
using Network = c2pool::address::Network;

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
    std::cout << "  --p2p-port PORT           Set P2P port (default: 9333)\n";
    std::cout << "  --http-port PORT          Set HTTP/JSON-RPC API port (default: 8083)\n";
    std::cout << "  --stratum-port PORT       Set Stratum mining port (default: 8080)\n";
    std::cout << "  --http-host HOST          Set HTTP server host (default: 0.0.0.0)\n";
    std::cout << "  --integrated              Run integrated mining pool with web server\n";
    std::cout << "  --blockchain BLOCKCHAIN   Set blockchain type (ltc, btc, eth, xmr, zec, doge)\n";
    std::cout << "                            Default: ltc (Litecoin)\n";
    std::cout << "  --sharechain              Run enhanced sharechain node with persistence\n";
    std::cout << "  --config FILE             Load configuration from file\n";
    std::cout << "\nFeatures:\n";
    std::cout << "  ✓ Blockchain-specific address validation\n";
    std::cout << "  ✓ Automatic difficulty adjustment (VARDIFF)\n";
    std::cout << "  ✓ Real-time hashrate tracking\n";
    std::cout << "  ✓ Legacy share tracker compatibility\n";
    std::cout << "  ✓ LevelDB persistent storage\n";
    std::cout << "  ✓ JSON-RPC mining interface\n";
    std::cout << "  ✓ WebUI for monitoring\n";
    std::cout << "\nDefault Ports:\n";
    std::cout << "  P2P (sharechain):         9333\n";
    std::cout << "  HTTP API (JSON-RPC):      8083\n";
    std::cout << "  Stratum (mining):         8084 (configurable, standard is 8080)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  c2pool --testnet --p2p-port 9333\n";
    std::cout << "  c2pool --integrated --blockchain ltc --testnet\n";
    std::cout << "  c2pool --integrated --http-port 8083 --stratum-port 8084\n";
    std::cout << "  c2pool --sharechain --blockchain btc\n";
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
    
    // Port configuration with C2Pool standard defaults
    int p2p_port = 9333;           // P2P sharechain port
    int http_port = 8083;          // HTTP/JSON-RPC API port
    int stratum_port = 8084;       // Stratum mining port (temporarily 8084 for current miners)
    std::string http_host = "0.0.0.0";  // HTTP server host
    
    std::string config_file;
    bool integrated_mode = false;
    bool sharechain_mode = false;
    Blockchain blockchain = Blockchain::LITECOIN;  // Default to Litecoin
    
    // Helper function to parse blockchain string
    auto parse_blockchain = [](const std::string& blockchain_str) -> Blockchain {
        if (blockchain_str == "ltc" || blockchain_str == "litecoin") return Blockchain::LITECOIN;
        if (blockchain_str == "btc" || blockchain_str == "bitcoin") return Blockchain::BITCOIN;
        if (blockchain_str == "eth" || blockchain_str == "ethereum") return Blockchain::ETHEREUM;
        if (blockchain_str == "xmr" || blockchain_str == "monero") return Blockchain::MONERO;
        if (blockchain_str == "zec" || blockchain_str == "zcash") return Blockchain::ZCASH;
        if (blockchain_str == "doge" || blockchain_str == "dogecoin") return Blockchain::DOGECOIN;
        
        LOG_ERROR << "Unknown blockchain: " << blockchain_str;
        LOG_INFO << "Supported blockchains: ltc, btc, eth, xmr, zec, doge";
        throw std::invalid_argument("Unknown blockchain type");
    };
    
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
        else if (arg == "--p2p-port" && i + 1 < argc) {
            p2p_port = std::stoi(argv[++i]);
        }
        else if (arg == "--http-port" && i + 1 < argc) {
            http_port = std::stoi(argv[++i]);
        }
        else if (arg == "--stratum-port" && i + 1 < argc) {
            stratum_port = std::stoi(argv[++i]);
        }
        else if (arg == "--http-host" && i + 1 < argc) {
            http_host = argv[++i];
        }
        else if (arg == "--integrated") {
            integrated_mode = true;
        }
        else if (arg == "--sharechain") {
            sharechain_mode = true;
        }
        else if (arg == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        }
        else if (arg == "--blockchain" && i + 1 < argc) {
            blockchain = parse_blockchain(argv[++i]);
        }
        // Legacy support for old --port option (maps to p2p-port)
        else if (arg == "--port" && i + 1 < argc) {
            p2p_port = std::stoi(argv[++i]);
            LOG_WARNING << "--port is deprecated, use --p2p-port instead";
        }
        else {
            LOG_ERROR << "Unknown argument: " << arg;
            return 1;
        }
    }
    
    try {
        boost::asio::io_context ioc;
        
        if (integrated_mode) {
            std::string blockchain_name = "Unknown";
            switch (blockchain) {
                case Blockchain::LITECOIN: blockchain_name = "Litecoin"; break;
                case Blockchain::BITCOIN: blockchain_name = "Bitcoin"; break;
                case Blockchain::ETHEREUM: blockchain_name = "Ethereum"; break;
                case Blockchain::MONERO: blockchain_name = "Monero"; break;
                case Blockchain::ZCASH: blockchain_name = "Zcash"; break;
                case Blockchain::DOGECOIN: blockchain_name = "Dogecoin"; break;
            }
            
            LOG_INFO << "Starting integrated C2Pool mining pool for " << blockchain_name 
                    << " (" << (settings->m_testnet ? "testnet" : "mainnet") << ")";
            LOG_INFO << "Port configuration:";
            LOG_INFO << "  HTTP API (JSON-RPC): " << http_host << ":" << http_port;
            LOG_INFO << "  Stratum (mining):    " << http_host << ":" << stratum_port;
            LOG_INFO << "  P2P (sharechain):    " << p2p_port;
            LOG_INFO << "Features: automatic difficulty adjustment, blockchain-specific address validation";
            
            // Create enhanced node with default constructor to avoid nullptr issues
            auto enhanced_node = std::make_shared<c2pool::node::EnhancedC2PoolNode>();
            
            // Create web server with explicit port configuration
            core::WebServer web_server(ioc, http_host, static_cast<uint16_t>(http_port), 
                                     settings->m_testnet, nullptr, blockchain);
            
            // Set custom Stratum port if different from default
            web_server.set_stratum_port(static_cast<uint16_t>(stratum_port));
            
            if (!web_server.start()) {
                LOG_ERROR << "Failed to start integrated mining pool";
                return 1;
            }
            
            LOG_INFO << "Integrated C2Pool Mining Pool started successfully!";
            LOG_INFO << "Blockchain: " << blockchain_name << " (" << (settings->m_testnet ? "testnet" : "mainnet") << ")";
            LOG_INFO << "Mining interface: http://" << http_host << ":" << http_port;
            LOG_INFO << "Stratum interface: stratum+tcp://" << http_host << ":" << stratum_port;
            LOG_INFO << "Features enabled:";
            LOG_INFO << "  ✓ Blockchain-specific address validation";
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
            enhanced_node->listen(p2p_port);
            
            LOG_INFO << "Enhanced C2Pool sharechain node started successfully on port " << p2p_port;
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
            LOG_INFO << "  P2P Port: " << p2p_port;
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
