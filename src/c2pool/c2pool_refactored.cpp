#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <thread>
#include <chrono>
#include <csignal>
#include <ctime>
#include <memory>
#include <sstream>

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
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>
#include <impl/ltc/config.hpp>

// Enhanced C2Pool components
#include <c2pool/node/enhanced_node.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <c2pool/storage/sharechain_storage.hpp>
#include <c2pool/payout/payout_manager.hpp>

// Integrated merged mining
#include <c2pool/merged/merged_mining.hpp>

// V36-compatible operational features
#include <impl/ltc/pool_monitor.hpp>
#include <impl/ltc/whale_departure.hpp>
#include <impl/ltc/redistribute.hpp>

// Coin daemon RPC
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

// Bring the address validation types into scope
using Blockchain = c2pool::address::Blockchain;
using Network = c2pool::address::Network;
using NodeOwnerAddressSource = c2pool::payout::NodeOwnerPayoutConfig::AddressSource;

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
    std::cout << "                            Note: When 0%, only 1 satoshi used for marking\n";
    std::cout << "  --node-owner-fee PERCENT  Node owner fee (0-50%, default: 0%)\n";
    std::cout << "  --node-owner-address ADDR Node owner payout address\n";
    std::cout << "  --node-owner-script HEX   Node owner P2SH script (generates address)\n";
    std::cout << "  --auto-detect-wallet      Auto-detect wallet address from core client\n";
    std::cout << "  --no-auto-detect-wallet   Disable wallet auto-detection\n";
    std::cout << "  --redistribute MODE       Redistribution for empty/broken miner addresses:\n";
    std::cout << "                            pplns (default), fee, boost, donate\n\n";
    
    std::cout << "PORT CONFIGURATION:\n";
    std::cout << "  --p2p-port PORT           P2P sharechain port (default: 9333)\n";
    std::cout << "  --http-port PORT          HTTP/JSON-RPC API port (default: 8083)\n";
    std::cout << "  --stratum-port PORT       Stratum mining port (default: 8084)\n";
    std::cout << "  --http-host HOST          HTTP server bind address (default: 0.0.0.0)\n\n";

    std::cout << "MERGED MINING:\n";
    std::cout << "  --merged SPEC             Add aux chain for merged mining. SPEC format:\n";
    std::cout << "                            SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS\n";
    std::cout << "                            Example: DOGE:98:127.0.0.1:22555:user:pass\n";
    std::cout << "                            Can be specified multiple times\n\n";
    std::cout << "COIN DAEMON RPC (for live block templates):\n";
    std::cout << "  --rpchost HOST            Coin daemon RPC host (default: 127.0.0.1)\n";
    std::cout << "  --rpcport PORT            Coin daemon RPC port (default: 19332 testnet / 9332 mainnet)\n";
    std::cout << "  --rpcuser USER            Coin daemon RPC username (default: user)\n";
    std::cout << "  --rpcpassword PASS        Coin daemon RPC password (default: password)\n\n";
    
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

    // Coin daemon RPC connection (used by integrated/solo modes for live block templates)
    std::string rpc_host = "127.0.0.1";
    int         rpc_port = 19332;       // LTC testnet default; mainnet = 9332
    std::string rpc_user = "user";
    std::string rpc_pass = "password";
    
    std::string config_file;
    std::string solo_address;
    std::string node_owner_address;
    std::string node_owner_script;         // Node owner script hex
    double dev_donation = 0.0;          // Developer donation percentage
    double node_owner_fee = 0.0;        // Node owner fee percentage
    bool auto_detect_wallet = true;     // Auto-detect wallet address
    bool integrated_mode = false;
    bool sharechain_mode = false;
    Blockchain blockchain = Blockchain::LITECOIN;  // Default to Litecoin

    // Merged mining (auxiliary chain) configuration
    // Multiple --merged flags can be given; each specifies:
    //   --merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS
    std::vector<std::string> merged_chain_specs;

    // Redistribute mode for shares from unnamed/broken miners
    std::string redistribute_mode_str = "pplns";

    // Track which options were explicitly set via CLI so that --config file
    // values only fill in gaps (CLI always wins).
    std::set<std::string> cli_explicit;
    
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
            cli_explicit.insert("testnet");
        }
        else if (arg == "--p2p-port" && i + 1 < argc) {
            p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("p2p_port");
        }
        else if (arg == "--http-port" && i + 1 < argc) {
            http_port = std::stoi(argv[++i]);
            cli_explicit.insert("http_port");
        }
        else if (arg == "--stratum-port" && i + 1 < argc) {
            stratum_port = std::stoi(argv[++i]);
            cli_explicit.insert("stratum_port");
        }
        else if (arg == "--http-host" && i + 1 < argc) {
            http_host = argv[++i];
            cli_explicit.insert("http_host");
        }
        else if (arg == "--integrated") {
            integrated_mode = true;
            cli_explicit.insert("integrated");
        }
        else if (arg == "--sharechain") {
            sharechain_mode = true;
            cli_explicit.insert("sharechain");
        }
        else if (arg == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        }
        else if (arg == "--blockchain" && i + 1 < argc) {
            blockchain = parse_blockchain(argv[++i]);
            cli_explicit.insert("blockchain");
        }
        else if (arg == "--solo-address" && i + 1 < argc) {
            solo_address = argv[++i];
            cli_explicit.insert("solo_address");
        }
        else if (arg == "--dev-donation" && i + 1 < argc) {
            dev_donation = std::stod(argv[++i]);
            cli_explicit.insert("dev_donation");
        }
        else if (arg == "--node-owner-fee" && i + 1 < argc) {
            node_owner_fee = std::stod(argv[++i]);
            cli_explicit.insert("node_owner_fee");
        }
        else if (arg == "--node-owner-address" && i + 1 < argc) {
            node_owner_address = argv[++i];
            cli_explicit.insert("node_owner_address");
        }
        else if (arg == "--node-owner-script" && i + 1 < argc) {
            node_owner_script = argv[++i];
            cli_explicit.insert("node_owner_script");
        }
        else if (arg == "--auto-detect-wallet") {
            auto_detect_wallet = true;
            cli_explicit.insert("auto_detect_wallet");
        }
        else if (arg == "--no-auto-detect-wallet") {
            auto_detect_wallet = false;
            cli_explicit.insert("auto_detect_wallet");
        }
        // Coin daemon RPC credentials
        else if (arg == "--rpchost" && i + 1 < argc) {
            rpc_host = argv[++i];
            cli_explicit.insert("rpc_host");
        }
        else if (arg == "--rpcport" && i + 1 < argc) {
            rpc_port = std::stoi(argv[++i]);
            cli_explicit.insert("rpc_port");
        }
        else if (arg == "--rpcuser" && i + 1 < argc) {
            rpc_user = argv[++i];
            cli_explicit.insert("rpc_user");
        }
        else if (arg == "--rpcpassword" && i + 1 < argc) {
            rpc_pass = argv[++i];
            cli_explicit.insert("rpc_pass");
        }
        // Merged mining: --merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS
        // e.g. --merged DOGE:98:127.0.0.1:22555:dogeuser:dogepass
        else if (arg == "--merged" && i + 1 < argc) {
            merged_chain_specs.push_back(argv[++i]);
            cli_explicit.insert("merged");
        }
        // Legacy support for old --port option (maps to p2p-port)
        else if (arg == "--port" && i + 1 < argc) {
            p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("p2p_port");
            LOG_WARNING << "--port is deprecated, use --p2p-port instead";
        }
        // Redistribute mode for empty/broken miner addresses
        else if (arg == "--redistribute" && i + 1 < argc) {
            redistribute_mode_str = argv[++i];
            cli_explicit.insert("redistribute");
        }
        else {
            LOG_ERROR << "Unknown argument: " << arg;
            return 1;
        }
    }

    // -----------------------------------------------------------------------
    // Load YAML config file if --config was specified.
    // Config file provides defaults; CLI arguments always take priority.
    // -----------------------------------------------------------------------
    if (!config_file.empty()) {
        try {
            YAML::Node cfg = YAML::LoadFile(config_file);
            LOG_INFO << "Loading config from " << config_file;

            // Network / mode
            if (!cli_explicit.count("testnet") && cfg["testnet"])
                settings->m_testnet = cfg["testnet"].as<bool>();
            if (!cli_explicit.count("integrated") && cfg["integrated"])
                integrated_mode = cfg["integrated"].as<bool>();
            if (!cli_explicit.count("sharechain") && cfg["sharechain"])
                sharechain_mode = cfg["sharechain"].as<bool>();
            if (!cli_explicit.count("blockchain") && cfg["blockchain"])
                blockchain = parse_blockchain(cfg["blockchain"].as<std::string>());

            // Ports
            if (!cli_explicit.count("p2p_port") && cfg["port"])
                p2p_port = cfg["port"].as<int>();
            if (!cli_explicit.count("stratum_port") && cfg["stratum_port"])
                stratum_port = cfg["stratum_port"].as<int>();
            if (!cli_explicit.count("http_port") && cfg["http_port"])
                http_port = cfg["http_port"].as<int>();
            if (!cli_explicit.count("http_host") && cfg["http_host"])
                http_host = cfg["http_host"].as<std::string>();

            // Coin daemon RPC
            if (!cli_explicit.count("rpc_host") && cfg["ltc_rpc_host"])
                rpc_host = cfg["ltc_rpc_host"].as<std::string>();
            if (!cli_explicit.count("rpc_port") && cfg["ltc_rpc_port"])
                rpc_port = cfg["ltc_rpc_port"].as<int>();
            if (!cli_explicit.count("rpc_user") && cfg["ltc_rpc_user"])
                rpc_user = cfg["ltc_rpc_user"].as<std::string>();
            if (!cli_explicit.count("rpc_pass") && cfg["ltc_rpc_password"])
                rpc_pass = cfg["ltc_rpc_password"].as<std::string>();

            // Mining / payout
            if (!cli_explicit.count("solo_address") && cfg["solo_address"])
                solo_address = cfg["solo_address"].as<std::string>();
            if (!cli_explicit.count("dev_donation") && cfg["donation_percentage"])
                dev_donation = cfg["donation_percentage"].as<double>();
            if (!cli_explicit.count("node_owner_fee") && cfg["node_owner_fee"])
                node_owner_fee = cfg["node_owner_fee"].as<double>();
            if (!cli_explicit.count("node_owner_address") && cfg["node_owner_address"])
                node_owner_address = cfg["node_owner_address"].as<std::string>();
            if (!cli_explicit.count("node_owner_script") && cfg["node_owner_script"])
                node_owner_script = cfg["node_owner_script"].as<std::string>();
            if (!cli_explicit.count("auto_detect_wallet") && cfg["auto_detect_wallet"])
                auto_detect_wallet = cfg["auto_detect_wallet"].as<bool>();

            // Merged mining chains (config appends; CLI replaces if specified)
            if (!cli_explicit.count("merged") && cfg["merged"] && cfg["merged"].IsSequence()) {
                for (const auto& item : cfg["merged"])
                    merged_chain_specs.push_back(item.as<std::string>());
            }

            // Redistribute mode
            if (!cli_explicit.count("redistribute") && cfg["redistribute"])
                redistribute_mode_str = cfg["redistribute"].as<std::string>();

        } catch (const YAML::Exception& e) {
            LOG_ERROR << "Failed to load config file '" << config_file << "': " << e.what();
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
        
        // Set node owner script if provided
        if (!node_owner_script.empty()) {
            payout_manager->set_node_owner_script(node_owner_script);
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
            const auto& node_config = payout_manager->get_node_owner_config();
            LOG_INFO << "  Node owner fee: " << node_config.fee_percent << "%";
            LOG_INFO << "  Node owner address: " << payout_manager->get_node_owner_address();
            
            // Show address source
            std::string source_description;
            switch (node_config.address_source) {
                case NodeOwnerAddressSource::CLI_ARGUMENT:
                    source_description = "CLI argument";
                    break;
                case NodeOwnerAddressSource::CONFIG_FILE:
                    source_description = "config file";
                    break;
                case NodeOwnerAddressSource::WALLET_RPC:
                    source_description = "wallet RPC";
                    break;
                case NodeOwnerAddressSource::GENERATED_NEW:
                    source_description = "newly generated";
                    break;
                case NodeOwnerAddressSource::SCRIPT_DERIVED:
                    source_description = "derived from script";
                    break;
                default:
                    source_description = "unknown";
                    break;
            }
            LOG_INFO << "  Address source: " << source_description;
            
            if (!node_config.payout_script_hex.empty()) {
                LOG_INFO << "  Script hex: " << node_config.payout_script_hex.substr(0, 32) << "...";
            }
        } else if (node_owner_fee > 0.0) {
            LOG_WARNING << "Node owner fee was set to " << node_owner_fee << "% but address resolution failed";
            LOG_WARNING << "Node owner payouts are disabled";
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
            
            // Set up coin daemon RPC for live block template generation.
            // The coin_node is kept alive for the duration of the integrated mode loop.
            ltc::interfaces::Node  coin_node;
            auto node_rpc = std::make_unique<ltc::coin::NodeRPC>(&ioc, &coin_node, settings->m_testnet);

            // Adjust default RPC port based on testnet flag when user didn't override
            if (rpc_port == 19332 && !settings->m_testnet)
                rpc_port = 9332; // mainnet LTC

            LOG_INFO << "Connecting to coin daemon RPC at " << rpc_host << ":" << rpc_port;
            node_rpc->connect(NetService(rpc_host, static_cast<uint16_t>(rpc_port)),
                              rpc_user + ":" + rpc_pass);

            // Create web server with explicit port configuration
            core::WebServer web_server(ioc, http_host, static_cast<uint16_t>(http_port), 
                                     settings->m_testnet, enhanced_node, blockchain);
            
            // Wire live coin-daemon RPC so getblocktemplate/submitblock use real data
            web_server.set_coin_rpc(node_rpc.get(), &coin_node);

            // Feed real network difficulty from block templates to the adjustment engine
            web_server.get_mining_interface()->set_on_network_difficulty(
                [engine = &enhanced_node->get_difficulty_engine()](double diff) {
                    engine->set_network_difficulty(diff);
                });
            
            // Start P2P sharechain node for broadcasting new best-blocks to peers
            auto ltc_p2p_config = std::make_unique<ltc::Config>("ltc");
            // Load/create ~/.c2pool/ltc/{pool,coin}.yaml so bootstrap_addrs are available.
            ltc_p2p_config->init();
            ltc_p2p_config->m_testnet = settings->m_testnet;
            auto p2p_node = std::make_unique<ltc::Node>(&ioc, ltc_p2p_config.get());
            p2p_node->core::Server::listen(static_cast<uint16_t>(p2p_port));
            LOG_INFO << "P2P sharechain node listening on port " << p2p_port;

            // Phase 1c: Whale departure detector (needs to be visible to ref_hash lambda)
            auto whale_detector = std::make_unique<ltc::WhaleDepartureDetector>();

            // Wire block_rel_height for chain scoring: queries coin daemon for block depth
            p2p_node->set_block_rel_height_fn(
                [rpc = node_rpc.get()](uint256 block_hash) -> int32_t {
                    if (!rpc || block_hash.IsNull()) return 0;
                    try {
                        auto reply = rpc->getblock(block_hash, 1);
                        if (reply.contains("confirmations"))
                            return reply["confirmations"].get<int32_t>();
                    } catch (...) {}
                    return 0; // RPC error or not found — safe default
                });

            // Begin actively connecting to outbound peers from bootstrap list / addr store
            p2p_node->start_outbound_connections();
            LOG_INFO << "Outbound peer connection loop started";

            // When a peer announces a new best block, refresh our mining template
            p2p_node->set_on_bestblock([&web_server]() {
                web_server.trigger_work_refresh();
                LOG_INFO << "bestblock received from P2P peer — work template refreshed";
            });

            // When a block submission is attempted, broadcast bestblock to all P2P peers
            // and record the found block for the /recent_blocks REST endpoint.
            // stale_info: 0=accepted, 253=orphan (stale prev), 254=doa (daemon rejected)
            web_server.set_on_block_submitted([&p2p_node, &web_server, &ioc, &node_rpc](const std::string& header_hex, int stale_info) {
                if (header_hex.size() < 160) return;
                // Parse the 80-byte Bitcoin wire-format block header
                auto hb = [&](int i) -> uint8_t {
                    auto d = [](char c) -> uint8_t {
                        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                        return static_cast<uint8_t>(c - 'A' + 10);
                    };
                    return static_cast<uint8_t>((d(header_hex[2*i]) << 4) | d(header_hex[2*i+1]));
                };
                auto le32 = [&](int off) -> uint32_t {
                    return hb(off) | (hb(off+1) << 8) | (hb(off+2) << 16) | (hb(off+3) << 24);
                };
                // Reverse 32 wire-format bytes into a display-order hex string for SetHex()
                auto wire32_to_hex = [&](int off) -> std::string {
                    std::string s; s.reserve(64);
                    static const char* hex_chars = "0123456789abcdef";
                    for (int b = 31; b >= 0; --b) {
                        uint8_t byte = hb(off + b);
                        s += hex_chars[byte >> 4];
                        s += hex_chars[byte & 0xf];
                    }
                    return s;
                };
                ltc::coin::BlockHeaderType hdr;
                hdr.m_version   = le32(0);
                hdr.m_previous_block.SetHex(wire32_to_hex(4));
                hdr.m_merkle_root.SetHex(wire32_to_hex(36));
                hdr.m_timestamp = le32(68);
                hdr.m_bits      = le32(72);
                hdr.m_nonce     = le32(76);

                // Only broadcast bestblock for accepted blocks
                if (stale_info == 0) {
                    p2p_node->broadcast_bestblock(hdr);
                }

                // Record found block for REST /recent_blocks
                uint256 block_hash = Hash(ParseHex(header_hex.substr(0, 160)));
                uint64_t height = 0;
                auto tmpl = web_server.get_mining_interface()->get_current_work_template();
                if (!tmpl.is_null() && tmpl.contains("height"))
                    height = tmpl["height"].get<uint64_t>();
                web_server.get_mining_interface()->record_found_block(height, block_hash);

                const char* stale_str = (stale_info == 253) ? " [ORPHAN]"
                                      : (stale_info == 254) ? " [DOA]"
                                      : "";
                LOG_INFO << "Block found! height=" << height
                         << " hash=" << block_hash.GetHex()
                         << stale_str
                         << " — broadcast bestblock to P2P peers";

                // Schedule post-submission orphan check at +30s and +120s
                if (stale_info == 0)
                {
                    auto check_block = [&ioc, &node_rpc, block_hash](int delay_sec) {
                        auto timer = std::make_shared<boost::asio::steady_timer>(ioc);
                        timer->expires_after(std::chrono::seconds(delay_sec));
                        timer->async_wait([timer, &node_rpc, block_hash, delay_sec](
                                              boost::system::error_code ec) {
                            if (ec) return;
                            try {
                                auto info = node_rpc->getblock(block_hash);
                                if (info.contains("confirmations")) {
                                    int confs = info["confirmations"].get<int>();
                                    if (confs < 0)
                                        LOG_WARNING << "Block " << block_hash.GetHex().substr(0, 16)
                                                    << "... ORPHANED (confirmations=" << confs
                                                    << ") after " << delay_sec << "s";
                                    else
                                        LOG_INFO << "Block " << block_hash.GetHex().substr(0, 16)
                                                 << "... confirmed (" << confs
                                                 << " confirmations) after " << delay_sec << "s";
                                }
                            } catch (const std::exception& e) {
                                LOG_WARNING << "Orphan check failed for "
                                            << block_hash.GetHex().substr(0, 16)
                                            << "...: " << e.what();
                            }
                        });
                    };
                    check_block(30);
                    check_block(120);
                }
            });
            
            // Configure payout system for web server (legacy — kept for REST stats)
            web_server.set_payout_manager(payout_manager.get());

            // V36-compatible node fee: probabilistic address replacement at share
            // creation time.  The node operator's address accumulates PPLNS weight
            // for ~fee% of shares, so all peers compute identical coinbase outputs.
            if (node_owner_fee > 0.0 && !node_owner_address.empty()) {
                web_server.get_mining_interface()->set_node_fee_from_address(
                    node_owner_fee, node_owner_address);
                LOG_INFO << "Node fee: " << node_owner_fee << "% → " << node_owner_address
                         << " (v36 probabilistic)";
            }

            // Donation script (protocol-level, goes to p2pool devs)
            if (payout_manager) {
                std::string dev_addr = payout_manager->get_developer_address();
                if (!dev_addr.empty()) {
                    web_server.get_mining_interface()->set_donation_script_from_address(dev_addr);
                }
            }

            // Wire the share tracker's best share hash into the mining interface
            // so that mining_submit can link new shares to the chain head.
            web_server.set_best_share_hash_fn([&p2p_node]() {
                return p2p_node->best_share_hash();
            });

            // Wire the PPLNS computation hook so refresh_work() builds
            // proportional coinbase outputs from the share tracker.
            web_server.set_pplns_fn([&p2p_node](
                    const uint256& best_hash, const uint256& block_target,
                    uint64_t subsidy, const std::vector<unsigned char>& donation_script) {
                return p2p_node->tracker().get_expected_payouts(
                    best_hash, block_target, subsidy, donation_script);
            });

            // Wire the ref_hash computation hook for per-connection coinbase generation.
            // This computes the p2pool ref_hash from share fields + tracker state.
            web_server.get_mining_interface()->set_ref_hash_fn(
                [&p2p_node, &whale_detector](
                    const std::vector<unsigned char>& coinbase_scriptSig,
                    const std::vector<unsigned char>& payout_script,
                    uint64_t subsidy, uint32_t bits, uint32_t timestamp,
                    bool segwit_active, const std::string& witness_commitment_hex,
                    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs)
                    -> std::pair<uint256, uint64_t>
                {
                    ltc::RefHashParams params;
                    params.prev_share = p2p_node->best_share_hash();
                    params.coinbase_scriptSig = coinbase_scriptSig;
                    params.share_nonce = 0;
                    params.subsidy = subsidy;
                    params.donation = 50; // 0.5%
                    params.desired_version = 36;

                    // Compute pool-level share target from tracker state
                    auto desired_target = chain::bits_to_target(bits);
                    // Phase 1c: whale departure override — mine at easiest allowed difficulty
                    if (whale_detector->is_active()) {
                        desired_target = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                    }
                    auto [share_max_bits, share_bits] = p2p_node->tracker().compute_share_target(
                        params.prev_share, timestamp, desired_target);
                    params.max_bits = share_max_bits;
                    params.bits = share_bits;
                    params.timestamp = timestamp;

                    // Extract pubkey_hash and type from payout_script
                    if (payout_script.size() == 25 &&
                        payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
                        payout_script[2] == 0x14) {
                        std::memcpy(params.pubkey_hash.data(), payout_script.data() + 3, 20);
                        params.pubkey_type = 0; // P2PKH
                    } else if (payout_script.size() >= 22 &&
                               payout_script[0] == 0x00 && payout_script[1] == 0x14) {
                        std::memcpy(params.pubkey_hash.data(), payout_script.data() + 2, 20);
                        params.pubkey_type = 1; // P2WPKH
                    } else if (payout_script.size() >= 20) {
                        std::memcpy(params.pubkey_hash.data(), payout_script.data(), 20);
                        params.pubkey_type = 0;
                    }

                    // Segwit data
                    if (segwit_active && !witness_commitment_hex.empty()) {
                        params.has_segwit = true;
                        ltc::SegwitData sd;
                        // wtxid_merkle_root from witness commitment
                        if (witness_commitment_hex.size() >= 76) {
                            sd.m_wtxid_merkle_root = uint256S(witness_commitment_hex.substr(12, 64));
                        }
                        params.segwit_data = sd;
                    }

                    // Merged addresses
                    for (const auto& [chain_id, script] : merged_addrs) {
                        ltc::MergedAddressEntry entry;
                        entry.m_chain_id = chain_id;
                        entry.m_script.m_data = script;
                        params.merged_addresses.push_back(std::move(entry));
                    }

                    // Chain position from tracker
                    auto& tracker = p2p_node->tracker();
                    if (!params.prev_share.IsNull() && tracker.chain.contains(params.prev_share)) {
                        tracker.chain.get(params.prev_share).share.invoke([&](auto* prev) {
                            params.absheight = prev->m_absheight + 1;
                            auto attempts = chain::target_to_average_attempts(
                                chain::bits_to_target(prev->m_bits));
                            params.abswork = prev->m_abswork + uint128(attempts.GetLow64());
                        });

                        // far_share_hash
                        auto prev_height = tracker.chain.get_height(params.prev_share);
                        auto far_dist = std::min(
                            static_cast<int32_t>(ltc::PoolConfig::REAL_CHAIN_LENGTH),
                            prev_height);
                        auto far_view = tracker.chain.get_chain(params.prev_share, static_cast<size_t>(far_dist));
                        uint256 last_hash = params.prev_share;
                        for (auto it = far_view.begin(); it != far_view.end(); ++it)
                            last_hash = (*it).first;
                        params.far_share_hash = last_hash;
                    }

                    return ltc::compute_ref_hash_for_work(params);
                });

            // Wire the share creation hook so mining_submit() creates a real
            // V36 share in the tracker and broadcasts it to peers.
            web_server.get_mining_interface()->set_create_share_fn(
                [&p2p_node](const core::MiningInterface::ShareCreationParams& p) {
                try {
                    // Build SmallBlockHeaderType from Stratum params
                    ltc::coin::SmallBlockHeaderType min_header;
                    min_header.m_version        = p.block_version;
                    min_header.m_previous_block  = p.prev_block_hash;
                    min_header.m_timestamp       = p.timestamp;
                    min_header.m_bits            = p.bits;
                    min_header.m_nonce           = p.nonce;

                    // Coinbase scriptSig (BIP34 height + pool identifier)
                    BaseScript coinbase;
                    coinbase.m_data = p.coinbase_scriptSig;

                    // Previous best share in the tracker
                    uint256 prev_share = p2p_node->best_share_hash();

                    // Convert merged_addresses map → vector<MergedAddressEntry>
                    std::vector<ltc::MergedAddressEntry> merged_addrs;
                    for (const auto& [chain_id, script] : p.merged_addresses) {
                        ltc::MergedAddressEntry entry;
                        entry.m_chain_id = chain_id;
                        entry.m_script.m_data = script;
                        merged_addrs.push_back(std::move(entry));
                    }

                    // Determine stale_info
                    ltc::StaleInfo stale = ltc::StaleInfo::none;
                    if (p.stale_info == 253)      stale = ltc::StaleInfo::orphan;
                    else if (p.stale_info == 254)  stale = ltc::StaleInfo::doa;

                    // Create the share and add it to the tracker
                    uint256 share_hash = ltc::create_local_share(
                        p2p_node->tracker(),
                        min_header,
                        coinbase,
                        p.subsidy,
                        prev_share,
                        p.merkle_branches,
                        p.payout_script,
                        50,  // donation = 0.5%
                        merged_addrs,
                        stale,
                        p.segwit_active,
                        p.witness_commitment_hex);

                    // Broadcast to all connected peers
                    p2p_node->broadcast_share(share_hash);

                    LOG_INFO << "Share created and broadcast: "
                             << share_hash.GetHex().substr(0, 16) << "..."
                             << " subsidy=" << p.subsidy
                             << " merged_chains=" << merged_addrs.size();
                } catch (const std::exception& e) {
                    LOG_ERROR << "create_share_fn failed: " << e.what();
                }
            });

            // --- Integrated Merged Mining ---
            // Parse --merged specs and set up the manager (replaces standalone mm-adapter)
            std::unique_ptr<c2pool::merged::MergedMiningManager> mm_manager;
            if (!merged_chain_specs.empty()) {
                mm_manager = std::make_unique<c2pool::merged::MergedMiningManager>(ioc);
                for (const auto& spec : merged_chain_specs) {
                    // Format: SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS
                    std::vector<std::string> parts;
                    std::string token;
                    std::istringstream ss(spec);
                    while (std::getline(ss, token, ':'))
                        parts.push_back(token);
                    if (parts.size() < 6) {
                        LOG_ERROR << "Invalid --merged spec (expected SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS): " << spec;
                        continue;
                    }
                    c2pool::merged::AuxChainConfig cfg;
                    cfg.symbol       = parts[0];
                    cfg.chain_id     = static_cast<uint32_t>(std::stoul(parts[1]));
                    cfg.rpc_host     = parts[2];
                    cfg.rpc_port     = static_cast<uint16_t>(std::stoul(parts[3]));
                    cfg.rpc_userpass = parts[4] + ":" + parts[5];
                    cfg.multiaddress = true;

                    mm_manager->add_chain(cfg);
                    LOG_INFO << "Merged mining: added " << cfg.symbol
                             << " (chain_id=" << cfg.chain_id << ") at "
                             << cfg.rpc_host << ":" << cfg.rpc_port;
                }
                web_server.set_merged_mining_manager(mm_manager.get());

                // Wire the merged payout provider so that aux chain block
                // construction uses per-chain PPLNS weights from the share tracker.
                auto* mi = web_server.get_mining_interface();
                mm_manager->set_payout_provider(
                    [&p2p_node, mi](
                        uint32_t chain_id, uint64_t coinbase_value)
                    -> std::vector<std::pair<std::vector<unsigned char>, uint64_t>>
                {
                    auto best = p2p_node->best_share_hash();
                    if (best.IsNull())
                        return {};

                    // Compute block_target from the share tracker's current tip
                    uint256 block_target;
                    p2p_node->tracker().chain.get(best).share.invoke([&](auto* s) {
                        block_target = chain::bits_to_target(s->m_bits);
                    });

                    auto& donation_script = mi->get_donation_script();
                    auto payouts_map = p2p_node->tracker().get_merged_expected_payouts(
                        best, block_target, coinbase_value, chain_id, donation_script);

                    // Convert map → sorted vector for coinbase construction
                    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> result;
                    result.reserve(payouts_map.size());
                    for (auto& [script, amount] : payouts_map) {
                        if (amount >= 1.0)
                            result.emplace_back(script, static_cast<uint64_t>(amount));
                    }
                    // Sort by script for deterministic coinbase ordering
                    std::sort(result.begin(), result.end());
                    return result;
                });

                mm_manager->start();
                LOG_INFO << "Merged mining manager started with " << mm_manager->chain_count() << " chain(s)";
            }

            // Set custom Stratum port if different from default
            web_server.set_stratum_port(static_cast<uint16_t>(stratum_port));

            // --- V36 operational features ---

            // Phase 3L: Pool monitor — periodic log-based diagnostics
            auto pool_monitor = std::make_unique<ltc::PoolMonitor>();

            // Redistribute mode for invalid/empty miner addresses
            auto redistribute_mode = ltc::parse_redistribute_mode(redistribute_mode_str);
            auto redistributor = std::make_unique<ltc::Redistributor>();
            redistributor->set_mode(redistribute_mode);
            LOG_INFO << "Redistribute mode: " << ltc::redistribute_mode_str(redistribute_mode);

            // Set operator identity for "fee" mode from node_owner_address
            // (uses same P2PKH extraction as payout_script handling)
            if (!node_owner_address.empty() && node_owner_fee > 0.0) {
                // The operator's pubkey_hash will be set when set_node_fee_from_address
                // was called earlier (which stores the scriptPubKey). For redistribute
                // we need the raw hash160. Extract from the stored fee script by reading
                // the MiningInterface's node fee data.
                // Since we can't access the private m_node_fee_script, use the COMBINED_DONATION
                // fallback for now; the operator identity gets wired below via lambda capture.
            }

            // Set donation identity for "donate" mode (V36 combined donation P2SH)
            {
                uint160 don_hash;
                std::memcpy(don_hash.data(),
                    ltc::PoolConfig::COMBINED_DONATION_SCRIPT.data() + 2, 20);
                redistributor->set_donation_identity(don_hash, 2); // P2SH
            }

            // Periodic monitoring timer (every 30 seconds)
            auto monitor_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            std::function<void(boost::system::error_code)> monitor_tick;
            monitor_tick = [&, monitor_timer](boost::system::error_code ec) {
                if (ec || g_shutdown_requested) return;
                try {
                    auto best = p2p_node->best_share_hash();
                    if (!best.IsNull()) {
                        pool_monitor->run_cycle(p2p_node->tracker(), best);
                        whale_detector->detect(p2p_node->tracker(), best, "timer");
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR << "[MONITOR] cycle error: " << e.what();
                }
                monitor_timer->expires_after(std::chrono::seconds(30));
                monitor_timer->async_wait(monitor_tick);
            };
            monitor_timer->expires_after(std::chrono::seconds(30));
            monitor_timer->async_wait(monitor_tick);
            
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
            
            // Coin daemon RPC for live block templates in solo mode
            ltc::interfaces::Node  solo_coin_node;
            auto solo_node_rpc = std::make_unique<ltc::coin::NodeRPC>(&ioc, &solo_coin_node, settings->m_testnet);
            if (rpc_port == 19332 && !settings->m_testnet) rpc_port = 9332;
            LOG_INFO << "Solo mode: connecting to coin daemon RPC at " << rpc_host << ":" << rpc_port;
            solo_node_rpc->connect(NetService(rpc_host, static_cast<uint16_t>(rpc_port)),
                                   rpc_user + ":" + rpc_pass);

            // Create a minimal web server for solo mining (Stratum only)
            core::WebServer solo_server(ioc, http_host, 8083,
                                       settings->m_testnet, nullptr, blockchain);

            // Wire coin daemon so solo Stratum gets live GBT + submitblock
            solo_server.set_coin_rpc(solo_node_rpc.get(), &solo_coin_node);

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
