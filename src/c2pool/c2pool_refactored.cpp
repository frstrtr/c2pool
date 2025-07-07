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
#include <c2pool/payout/payout_manager.hpp>

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
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    C2Pool - P2Pool Rebirth in C++                           ║\n";
    std::cout << "║            A modern, high-performance decentralized mining pool             ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n\n";
    
    std::cout << "USAGE:\n";
    std::cout << "  c2pool [MODE] [OPTIONS]\n\n";
    
    std::cout << "OPERATION MODES:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    
    std::cout << "🏊 INTEGRATED MODE (--integrated) - RECOMMENDED FOR POOL OPERATORS\n";
    std::cout << "   Complete mining pool solution with all features enabled:\n";
    std::cout << "   ✅ HTTP/JSON-RPC API Server (monitoring & stats)\n";
    std::cout << "   ✅ Stratum Mining Server (miner connections)\n";
    std::cout << "   ✅ Enhanced Sharechain Processing (persistent storage)\n";
    std::cout << "   ✅ Real-time Payout Tracking & Management\n";
    std::cout << "   ✅ Variable Difficulty (VARDIFF) Adjustment\n";
    std::cout << "   ✅ Multi-blockchain Support (LTC, BTC, ETH, XMR, ZEC, DOGE)\n";
    std::cout << "   ✅ Web Interface for Pool Monitoring\n";
    std::cout << "   ✅ Per-miner Statistics & Contribution Tracking\n";
    std::cout << "   ✅ Address Validation for All Blockchain Types\n\n";
    
    std::cout << "🔗 SHARECHAIN MODE (--sharechain) - P2POOL NETWORK PARTICIPANT\n";
    std::cout << "   Dedicated P2P sharechain node for network participation:\n";
    std::cout << "   ✅ Enhanced Sharechain Processing\n";
    std::cout << "   ✅ LevelDB Persistent Storage\n";
    std::cout << "   ✅ P2P Network Communication\n";
    std::cout << "   ✅ Real-time Difficulty Tracking\n";
    std::cout << "   ✅ Protocol Compatibility (LTC-based)\n";
    std::cout << "   ✅ Share Validation & Network Consensus\n\n";
    
    std::cout << "⚡ SOLO MODE (default) - INDEPENDENT SOLO MINING\n";
    std::cout << "   Standalone mining node without P2P sharechain:\n";
    std::cout << "   ✅ Direct Blockchain Connection\n";
    std::cout << "   ✅ Solo Mining (100% block rewards)\n";
    std::cout << "   ✅ Stratum Mining Server\n";
    std::cout << "   ✅ Local Difficulty Management\n";
    std::cout << "   ✅ Block Template Generation\n";
    std::cout << "   ✅ No P2P Dependencies\n";
    std::cout << "   ✅ Lightweight Operation\n\n";
    
    std::cout << "COMMAND LINE OPTIONS:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  --help, -h                Show this help message and exit\n";
    std::cout << "  --testnet                 Use testnet instead of mainnet\n";
    std::cout << "  --integrated              Enable integrated mode (full mining pool)\n";
    std::cout << "  --sharechain              Enable sharechain mode (P2P node)\n";
    std::cout << "  --blockchain CHAIN        Blockchain type: ltc, btc, eth, xmr, zec, doge\n";
    std::cout << "                            (default: ltc - Litecoin)\n";
    std::cout << "  --config FILE             Load configuration from YAML file\n";
    std::cout << "  --solo-address ADDRESS    Solo mining payout address (for solo mode)\n\n";
    
    std::cout << "PAYOUT & FEE CONFIGURATION:\n";
    std::cout << "  --dev-donation PERCENT    Developer donation (0-50%, default: 0%)\n";
    std::cout << "                            Note: 0.5% attribution fee always included\n";
    std::cout << "  --node-owner-fee PERCENT  Node owner fee (0-50%, default: 0%)\n";
    std::cout << "  --node-owner-address ADDR Node owner payout address\n";
    std::cout << "  --auto-detect-wallet      Auto-detect wallet address from core client\n\n";
    
    std::cout << "PORT CONFIGURATION:\n";
    std::cout << "  --p2p-port PORT           P2P sharechain port (default: 9333)\n";
    std::cout << "  --http-port PORT          HTTP/JSON-RPC API port (default: 8083)\n";
    std::cout << "  --stratum-port PORT       Stratum mining port (default: 8084)\n";
    std::cout << "  --http-host HOST          HTTP server bind address (default: 0.0.0.0)\n\n";
    
    std::cout << "BLOCKCHAIN SUPPORT:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  Litecoin (LTC)    ✅ Full support with testnet\n";
    std::cout << "  Bitcoin (BTC)     ✅ Protocol compatibility\n";
    std::cout << "  Ethereum (ETH)    🔧 In development\n";
    std::cout << "  Monero (XMR)      🔧 In development\n";
    std::cout << "  Zcash (ZEC)       🔧 In development\n";
    std::cout << "  Dogecoin (DOGE)   🔧 In development\n\n";
    
    std::cout << "FEATURES & CAPABILITIES:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  ✅ Variable Difficulty (VARDIFF) - Automatic per-miner adjustment\n";
    std::cout << "  ✅ Real-time Hashrate Tracking - Live monitoring and statistics\n";
    std::cout << "  ✅ Payout Management System - Per-miner contribution tracking\n";
    std::cout << "  ✅ Address Validation - All address types (legacy, P2SH, bech32)\n";
    std::cout << "  ✅ LevelDB Storage - Persistent sharechain and miner data\n";
    std::cout << "  ✅ JSON-RPC API - Complete monitoring interface\n";
    std::cout << "  ✅ Stratum Protocol - Standard mining protocol support\n";
    std::cout << "  ✅ Multi-miner Support - Concurrent connections\n";
    std::cout << "  ✅ Web Interface - Real-time pool monitoring\n\n";
    
    std::cout << "DEFAULT NETWORK PORTS:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  P2P Sharechain:           9333  (for P2Pool network communication)\n";
    std::cout << "  HTTP API (JSON-RPC):      8083  (for monitoring and statistics)\n";
    std::cout << "  Stratum Mining:           8084  (for miner connections)\n\n";
    
    std::cout << "USAGE EXAMPLES:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  🏊 POOL OPERATOR (Integrated Mode):\n";
    std::cout << "     c2pool --integrated --blockchain ltc --testnet\n";
    std::cout << "     c2pool --integrated --http-port 8083 --stratum-port 8084\n";
    std::cout << "     c2pool --integrated --blockchain btc --http-host 127.0.0.1\n\n";
    
    std::cout << "  🔗 NETWORK PARTICIPANT (Sharechain Mode):\n";
    std::cout << "     c2pool --sharechain --blockchain ltc --testnet\n";
    std::cout << "     c2pool --sharechain --blockchain btc --p2p-port 9333\n";
    std::cout << "     c2pool --sharechain --config pool_config.yaml\n\n";
    
    std::cout << "  ⚡ SOLO MINING (Basic/Solo Mode):\n";
    std::cout << "     c2pool --testnet --blockchain ltc --stratum-port 8084\n";
    std::cout << "     c2pool --blockchain ltc --solo-address YOUR_ADDRESS\n";
    std::cout << "     c2pool --config solo_config.yaml\n";
    std::cout << "     c2pool --dev-donation 2.5 --node-owner-fee 1.0\n\n";
    
    std::cout << "API ENDPOINTS (Integrated Mode):\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  GET  /api/stats          Pool statistics and hashrate\n";
    std::cout << "  POST /api/getinfo        Pool information and status\n";
    std::cout << "  POST /api/getminerstats  Per-miner statistics\n";
    std::cout << "  POST /api/getpayoutinfo  Payout information and balances\n";
    std::cout << "  Stratum: stratum+tcp://HOST:PORT (for miners)\n\n";
    
    std::cout << "For detailed documentation, visit: https://github.com/frstrtr/c2pool\n";
    std::cout << "Report issues at: https://github.com/frstrtr/c2pool/issues\n";
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
    std::string solo_address;
    std::string node_owner_address;
    double dev_donation = 0.0;          // Developer donation percentage
    double node_owner_fee = 0.0;        // Node owner fee percentage
    bool auto_detect_wallet = true;     // Auto-detect wallet address
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
        else if (arg == "--solo-address" && i + 1 < argc) {
            solo_address = argv[++i];
        }
        else if (arg == "--dev-donation" && i + 1 < argc) {
            dev_donation = std::stod(argv[++i]);
        }
        else if (arg == "--node-owner-fee" && i + 1 < argc) {
            node_owner_fee = std::stod(argv[++i]);
        }
        else if (arg == "--node-owner-address" && i + 1 < argc) {
            node_owner_address = argv[++i];
        }
        else if (arg == "--auto-detect-wallet") {
            auto_detect_wallet = true;
        }
        else if (arg == "--no-auto-detect-wallet") {
            auto_detect_wallet = false;
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
        
        // Initialize payout manager for all modes
        auto network = settings->m_testnet ? Network::TESTNET : Network::MAINNET;
        auto payout_manager = std::make_unique<c2pool::payout::PayoutManager>(blockchain, network);
        
        // Configure payout system
        if (dev_donation > 0.0) {
            payout_manager->set_developer_donation(dev_donation);
        }
        
        if (node_owner_fee > 0.0) {
            payout_manager->set_node_owner_fee(node_owner_fee);
        }
        
        if (!node_owner_address.empty()) {
            payout_manager->set_node_owner_address(node_owner_address);
        }
        
        payout_manager->enable_auto_wallet_detection(auto_detect_wallet);
        
        // Validate payout configuration
        if (!payout_manager->validate_configuration()) {
            LOG_ERROR << "Invalid payout configuration:";
            for (const auto& error : payout_manager->get_validation_errors()) {
                LOG_ERROR << "  - " << error;
            }
            return 1;
        }
        
        // Log payout configuration
        LOG_INFO << "C2Pool Payout Configuration:";
        LOG_INFO << "  Developer fee: " << payout_manager->get_developer_config().get_total_developer_fee() << "%";
        LOG_INFO << "  Developer address: " << payout_manager->get_developer_address();
        if (payout_manager->has_node_owner_fee()) {
            LOG_INFO << "  Node owner fee: " << payout_manager->get_node_owner_config().fee_percent << "%";
            LOG_INFO << "  Node owner address: " << payout_manager->get_node_owner_address();
        }
        
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
            
            // Configure payout system for web server
            web_server.set_payout_manager(payout_manager.get());
            
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
            // Solo mining mode - independent mining without P2P sharechain
            LOG_INFO << "Starting C2Pool Solo Mining Mode...";
            
            std::string blockchain_name = "Unknown";
            switch (blockchain) {
                case Blockchain::LITECOIN: blockchain_name = "Litecoin"; break;
                case Blockchain::BITCOIN: blockchain_name = "Bitcoin"; break;
                case Blockchain::ETHEREUM: blockchain_name = "Ethereum"; break;
                case Blockchain::MONERO: blockchain_name = "Monero"; break;
                case Blockchain::ZCASH: blockchain_name = "Zcash"; break;
                case Blockchain::DOGECOIN: blockchain_name = "Dogecoin"; break;
            }
            
            LOG_INFO << "Solo Mining Configuration:";
            LOG_INFO << "  Blockchain: " << blockchain_name << " (" << (settings->m_testnet ? "testnet" : "mainnet") << ")";
            LOG_INFO << "  Mode: Solo Mining (100% block rewards)";
            LOG_INFO << "  Stratum Port: " << stratum_port;
            if (!solo_address.empty()) {
                LOG_INFO << "  Payout Address: " << solo_address;
            }
            LOG_INFO << "  P2P Disabled: No sharechain exchange";
            LOG_INFO << "  Dependencies: Direct blockchain connection only";
            
            // Create a minimal web server for solo mining (Stratum only)
            core::WebServer solo_server(ioc, http_host, 8083,  // Use default HTTP port since HTTP won't be used
                                       settings->m_testnet, nullptr, blockchain);
            
            // Configure payout system for solo server
            solo_server.set_payout_manager(payout_manager.get());
            
            // Configure for solo mining mode
            solo_server.set_solo_mode(true);
            solo_server.set_stratum_port(static_cast<uint16_t>(stratum_port));  // Set the correct Stratum port
            if (!solo_address.empty()) {
                solo_server.set_solo_address(solo_address);
            }
            
            // Start only Stratum server, no HTTP API or P2P
            if (!solo_server.start_solo()) {
                LOG_ERROR << "Failed to start solo mining server";
                return 1;
            }
            
            LOG_INFO << "C2Pool Solo Mining started successfully!";
            LOG_INFO << "Mining interface: stratum+tcp://" << http_host << ":" << stratum_port;
            LOG_INFO << "Features enabled:";
            LOG_INFO << "  ✓ Direct blockchain connection";
            LOG_INFO << "  ✓ Solo mining (100% rewards)";
            LOG_INFO << "  ✓ Local difficulty management";
            LOG_INFO << "  ✓ Block template generation";
            LOG_INFO << "  ✓ No P2P dependencies";
            LOG_INFO << "";
            LOG_INFO << "Connect your miners to: stratum+tcp://" << http_host << ":" << stratum_port;
            if (!solo_address.empty()) {
                LOG_INFO << "All rewards will be paid to: " << solo_address;
            } else {
                LOG_INFO << "Use your payout address as the username when connecting miners";
            }
            
            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.run_for(std::chrono::milliseconds(100));
            }
        }
        
        LOG_INFO << "c2pool shutdown complete";
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Fatal error: " << e.what();
        return 1;
    }
    
    return 0;
}
