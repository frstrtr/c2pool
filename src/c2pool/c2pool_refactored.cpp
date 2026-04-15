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
#include <impl/ltc/share_messages.hpp>
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
#include <c2pool/merged/coin_broadcaster.hpp>

// V36-compatible operational features
#include <impl/ltc/pool_monitor.hpp>
#include <impl/ltc/whale_departure.hpp>
#include <impl/ltc/redistribute.hpp>

// Coin daemon RPC
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>

// Qt-facing infrastructure
#include <core/runtime_config.hpp>
#include <core/cookie_auth.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <btclibs/util/strencodings.h>

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
    std::cout << "  --net CHAIN               Blockchain network: litecoin, bitcoin, dogecoin\n";
    std::cout << "                            (alias: --blockchain; default: litecoin)\n";
    std::cout << "  --config FILE             Load configuration from YAML file\n";
    std::cout << "  --address ADDRESS         Payout address (alias: --solo-address)\n\n";
    
    std::cout << "PAYOUT & FEE CONFIGURATION:\n";
    std::cout << "  --give-author PERCENT     Developer donation (alias: --dev-donation; default: 0%)\n";
    std::cout << "  -f / --fee PERCENT        Node owner fee (alias: --node-owner-fee; default: 0%)\n";
    std::cout << "  --node-owner-address ADDR Node owner payout address\n";
    std::cout << "  --redistribute MODE       Redistribution mode: pplns, fee, boost, donate\n\n";
    
    std::cout << "PORT CONFIGURATION:\n";
    std::cout << "  --p2pool-port PORT        P2P sharechain port (alias: --p2p-port; default: 9326)\n";
    std::cout << "  -w / --worker-port PORT   Stratum/worker port (alias: --stratum-port; default: 9327)\n";
    std::cout << "  --web-port PORT           Web dashboard / JSON-RPC API port (alias: --http-port; default: 8080)\n";
    std::cout << "  --http-host HOST          HTTP server bind address (default: 0.0.0.0)\n\n";

    std::cout << "PARENT COIN DAEMON:\n";
    std::cout << "  --coind-address HOST      RPC host (alias: --rpchost; default: 127.0.0.1)\n";
    std::cout << "  --coind-rpc-port PORT     RPC port (alias: --rpcport; auto-detected from chain)\n";
    std::cout << "  --coind-p2p-port PORT     P2P port (auto-detected; set 0 to disable)\n";
    std::cout << "  --coind-p2p-address HOST  P2P address (default: same as --coind-address)\n";
    std::cout << "  USER PASS                 RPC credentials as positional args (or use flags below)\n";
    std::cout << "  --rpcuser USER            RPC username\n";
    std::cout << "  --rpcpassword PASS        RPC password\n\n";

    std::cout << "MERGED MINING (p2pool-style individual flags):\n";
    std::cout << "  --merged-coind-address HOST      Merged coin RPC host\n";
    std::cout << "  --merged-coind-rpc-port PORT     Merged coin RPC port\n";
    std::cout << "  --merged-coind-rpc-user USER     Merged coin RPC username\n";
    std::cout << "  --merged-coind-rpc-password PASS Merged coin RPC password\n";
    std::cout << "  --merged-coind-p2p-port PORT     Merged coin P2P port\n";
    std::cout << "  --merged-coind-p2p-address HOST  Merged coin P2P address\n\n";

    std::cout << "MERGED MINING (c2pool spec format — alternative):\n";
    std::cout << "  --merged SPEC             SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]\n";
    std::cout << "                            Example: DOGE:98:192.168.86.29:22555:user:pass\n";
    std::cout << "                            Can be specified multiple times\n\n";

    std::cout << "NETWORK TUNING (accepted for p2pool compatibility):\n";
    std::cout << "  --max-conns N             Max outgoing P2P connections\n";
    std::cout << "  --outgoing-conns N        Alias for --max-conns\n";
    std::cout << "  --disable-upnp            Disable UPnP port forwarding\n\n";

    std::cout << "V36 SHARE MESSAGE BLOB (CLI operator control):\n";
    std::cout << "  --message-blob-hex HEX    Encrypted authority-signed message_data blob\n";
    std::cout << "                            to embed in locally created V36 shares\n\n";
    
    std::cout << "BLOCKCHAIN SUPPORT:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  Litecoin (LTC)    ✅ Full support with merged mining (parent)\n";
    std::cout << "  Dogecoin (DOGE)   ✅ Full support as merged-mined aux chain\n";
    std::cout << "  Bitcoin (BTC)     ✅ Protocol compatibility\n";
    std::cout << "  Digibyte (DGB)    🔧 In development\n\n";
    
    std::cout << "DEFAULT NETWORK PORTS:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  P2P Sharechain:           9326  (for P2Pool network communication)\n";
    std::cout << "  Stratum / HTTP API:       9327  (for miners and monitoring)\n\n";
    
    std::cout << "USAGE EXAMPLES:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  p2pool-compatible (LTC+DOGE merged mining):\n";
    std::cout << "     c2pool --integrated --net litecoin \\\n";
    std::cout << "       --coind-address 192.168.86.29 --coind-rpc-port 9332 \\\n";
    std::cout << "       --coind-p2p-port 9333 \\\n";
    std::cout << "       --merged-coind-address 192.168.86.29 \\\n";
    std::cout << "       --merged-coind-rpc-port 44556 --merged-coind-p2p-port 22556 \\\n";
    std::cout << "       --merged-coind-rpc-user dogerpc --merged-coind-rpc-password pass \\\n";
    std::cout << "       --address YOUR_LTC_ADDRESS --give-author 2 -f 0 \\\n";
    std::cout << "       litecoinrpc PASSWORD\n\n";
    
    std::cout << "  c2pool-style (spec format):\n";
    std::cout << "     c2pool --integrated --net litecoin \\\n";
    std::cout << "       --rpchost 192.168.86.29 --rpcport 9332 \\\n";
    std::cout << "       --rpcuser litecoinrpc --rpcpassword pass \\\n";
    std::cout << "       --merged DOGE:98:192.168.86.29:44556:dogerpc:pass\n\n";
    
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
    
    // Port configuration with p2pool-compatible defaults
    int p2p_port = 9326;           // P2Pool P2P sharechain port (p2pool default)
    int stratum_port = 9327;       // Stratum mining port (p2pool: -w / --worker-port)
    int http_port = 8080;          // Web dashboard / JSON-RPC API port
    std::string http_host = "0.0.0.0";  // HTTP server host

    // Coin daemon RPC connection (used by integrated/solo modes for live block templates)
    std::string rpc_host = "127.0.0.1";
    int         rpc_port = 0;           // 0 = auto-detect from chain+testnet
    std::string rpc_user;
    std::string rpc_pass;

    // Payout address (p2pool: --address)
    std::string payout_address;
    
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

    // Coin daemon P2P connection (for fast block relay alongside RPC)
    std::string coind_p2p_address;   // defaults to rpc_host (same machine as RPC)
    int         coind_p2p_port = -1; // -1 = auto-detect from chain; 0 = disabled

    // Merged mining (auxiliary chain) configuration
    // p2pool-style: --merged-coind-address, --merged-coind-rpc-port, etc.
    // c2pool-style: --merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]
    std::vector<std::string> merged_chain_specs;
    // p2pool-style merged chain flags (assembled into spec at the end)
    std::string merged_coind_address;
    int         merged_coind_rpc_port = 0;
    std::string merged_coind_rpc_user;
    std::string merged_coind_rpc_pass;
    int         merged_coind_p2p_port = 0;
    std::string merged_coind_p2p_address;

    // Seed nodes from -n flag (p2pool compat)
    std::vector<std::string> seed_nodes;
    int max_outgoing_conns = 0;
    bool max_outgoing_conns_set = false;

    // Redistribute mode for shares from unnamed/broken miners
    std::string redistribute_mode_str = "pplns";

    // Optional encrypted authority message_data blob for local V36 shares.
    std::string operator_message_blob_hex;

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

    // Well-known P2P ports for coin daemons (same machine as RPC by default)
    auto get_coin_p2p_port = [](const std::string& symbol, bool testnet) -> int {
        if (symbol == "LTC" || symbol == "ltc") return testnet ? 19335 : 9333;
        if (symbol == "DOGE" || symbol == "doge") return testnet ? 44556 : 22556;
        if (symbol == "BTC" || symbol == "btc") return testnet ? 18333 : 8333;
        if (symbol == "DGB" || symbol == "dgb") return testnet ? 12026 : 12024;
        return 0;  // unknown chain — caller must specify explicitly
    };
    auto blockchain_to_symbol = [](Blockchain b) -> std::string {
        switch (b) {
            case Blockchain::LITECOIN: return "LTC";
            case Blockchain::BITCOIN:  return "BTC";
            case Blockchain::DOGECOIN: return "DOGE";
            default: return "";
        }
    };
    // Known P2P magic prefixes for common chains
    auto get_chain_p2p_prefix = [](const std::string& symbol, bool testnet) -> std::vector<std::byte> {
        if (symbol == "DOGE" || symbol == "doge") {
            return testnet
                ? ParseHexBytes("d4a1f4a1")   // Dogecoin testnet4alpha
                : ParseHexBytes("c0c0c0c0");  // Dogecoin mainnet
        }
        if (symbol == "LTC" || symbol == "ltc") {
            return testnet
                ? ParseHexBytes("fdd2c8f1")   // Litecoin testnet
                : ParseHexBytes("fbc0b6db");  // Litecoin mainnet
        }
        if (symbol == "BTC" || symbol == "btc") {
            return testnet
                ? ParseHexBytes("0b110907")   // Bitcoin testnet
                : ParseHexBytes("f9beb4d9");  // Bitcoin mainnet
        }
        if (symbol == "DGB" || symbol == "dgb") {
            return testnet
                ? ParseHexBytes("fdc8bddd")   // DigiByte testnet
                : ParseHexBytes("fac3b6da");  // DigiByte mainnet
        }
        return {};  // unknown chain — P2P broadcast disabled
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
        // Network / blockchain selection (p2pool: --net)
        else if ((arg == "--net" || arg == "--blockchain") && i + 1 < argc) {
            blockchain = parse_blockchain(argv[++i]);
            cli_explicit.insert("blockchain");
        }
        // P2Pool P2P sharechain port (p2pool: --p2pool-port)
        else if ((arg == "--p2pool-port" || arg == "--p2p-port") && i + 1 < argc) {
            p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("p2p_port");
        }
        // Worker/Stratum port (p2pool: -w / --worker-port)
        else if ((arg == "--worker-port" || arg == "-w" || arg == "--stratum-port") && i + 1 < argc) {
            stratum_port = std::stoi(argv[++i]);
            cli_explicit.insert("stratum_port");
        }
        // Web dashboard / JSON-RPC API port
        else if ((arg == "--http-port" || arg == "--web-port") && i + 1 < argc) {
            http_port = std::stoi(argv[++i]);
            cli_explicit.insert("http_port");
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
        // Payout address (p2pool: --address)
        else if ((arg == "--address" || arg == "--solo-address") && i + 1 < argc) {
            payout_address = argv[++i];
            solo_address = payout_address;  // legacy compat
            cli_explicit.insert("solo_address");
            cli_explicit.insert("address");
        }
        // Donation (p2pool: --give-author)
        else if ((arg == "--give-author" || arg == "--dev-donation") && i + 1 < argc) {
            dev_donation = std::stod(argv[++i]);
            cli_explicit.insert("dev_donation");
        }
        // Node owner fee (p2pool: -f / --fee)
        else if ((arg == "-f" || arg == "--fee" || arg == "--node-owner-fee") && i + 1 < argc) {
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
        // Parent coin daemon RPC (p2pool: --coind-address, --coind-rpc-port)
        else if ((arg == "--coind-address" || arg == "--rpchost" || arg == "--bitcoind-address") && i + 1 < argc) {
            rpc_host = argv[++i];
            cli_explicit.insert("rpc_host");
        }
        else if ((arg == "--coind-rpc-port" || arg == "--rpcport" || arg == "--bitcoind-rpc-port") && i + 1 < argc) {
            rpc_port = std::stoi(argv[++i]);
            cli_explicit.insert("rpc_port");
        }
        else if ((arg == "--rpcuser") && i + 1 < argc) {
            rpc_user = argv[++i];
            cli_explicit.insert("rpc_user");
        }
        else if ((arg == "--rpcpassword") && i + 1 < argc) {
            rpc_pass = argv[++i];
            cli_explicit.insert("rpc_pass");
        }
        // c2pool-style merged (colon-separated spec)
        else if (arg == "--merged" && i + 1 < argc) {
            merged_chain_specs.push_back(argv[++i]);
            cli_explicit.insert("merged");
        }
        // p2pool-style merged chain flags
        else if (arg == "--merged-coind-address" && i + 1 < argc) {
            merged_coind_address = argv[++i];
            cli_explicit.insert("merged_coind_address");
        }
        else if (arg == "--merged-coind-rpc-port" && i + 1 < argc) {
            merged_coind_rpc_port = std::stoi(argv[++i]);
            cli_explicit.insert("merged_coind_rpc_port");
        }
        else if (arg == "--merged-coind-rpc-user" && i + 1 < argc) {
            merged_coind_rpc_user = argv[++i];
            cli_explicit.insert("merged_coind_rpc_user");
        }
        else if (arg == "--merged-coind-rpc-password" && i + 1 < argc) {
            merged_coind_rpc_pass = argv[++i];
            cli_explicit.insert("merged_coind_rpc_pass");
        }
        else if (arg == "--merged-coind-p2p-port" && i + 1 < argc) {
            merged_coind_p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("merged_coind_p2p_port");
        }
        else if (arg == "--merged-coind-p2p-address" && i + 1 < argc) {
            merged_coind_p2p_address = argv[++i];
            cli_explicit.insert("merged_coind_p2p_address");
        }
        // Parent coin daemon P2P (p2pool: --coind-p2p-port / --bitcoind-p2p-port)
        else if ((arg == "--coind-p2p-port" || arg == "--bitcoind-p2p-port") && i + 1 < argc) {
            coind_p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("coind_p2p_port");
        }
        else if (arg == "--coind-p2p-address" && i + 1 < argc) {
            coind_p2p_address = argv[++i];
            cli_explicit.insert("coind_p2p_address");
        }
        // Connection limits (p2pool: --max-conns, --outgoing-conns, --disable-upnp)
        else if (arg == "--max-conns" && i + 1 < argc) {
            max_outgoing_conns = std::stoi(argv[++i]);
            max_outgoing_conns_set = true;
        }
        else if (arg == "--outgoing-conns" && i + 1 < argc) {
            max_outgoing_conns = std::stoi(argv[++i]);
            max_outgoing_conns_set = true;
        }
        else if (arg == "--disable-upnp") {
            /* no-op, c2pool doesn't use UPnP */
        }
        else if (arg == "--message-blob-hex" && i + 1 < argc) {
            operator_message_blob_hex = argv[++i];
            cli_explicit.insert("message_blob_hex");
        }
        // Legacy support for old --port option
        else if (arg == "--port" && i + 1 < argc) {
            p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("p2p_port");
            LOG_WARNING << "--port is deprecated, use --p2pool-port instead";
        }
        // Redistribute mode for empty/broken miner addresses
        else if (arg == "--redistribute" && i + 1 < argc) {
            redistribute_mode_str = argv[++i];
            cli_explicit.insert("redistribute");
        }
        // Seed node: -n HOST:PORT (p2pool compat)
        else if (arg == "-n" && i + 1 < argc) {
            seed_nodes.push_back(argv[++i]);
        }
        // Flags accepted but ignored (p2pool compat)
        else if (arg == "--no-console") {
            // c2pool has no interactive console — silently accept
        }
        else if (arg[0] == '-') {
            LOG_ERROR << "Unknown argument: " << arg;
            return 1;
        }
        // Positional arguments: RPC username password (p2pool compat)
        else {
            if (rpc_user.empty()) {
                rpc_user = arg;
                cli_explicit.insert("rpc_user");
            } else if (rpc_pass.empty()) {
                rpc_pass = arg;
                cli_explicit.insert("rpc_pass");
            } else {
                LOG_ERROR << "Unexpected positional argument: " << arg;
                return 1;
            }
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
            if (!cli_explicit.count("http_port")) {
                if (cfg["web_port"])
                    http_port = cfg["web_port"].as<int>();
                else if (cfg["http_port"])
                    http_port = cfg["http_port"].as<int>();
            }
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

            // Coin daemon P2P broadcaster
            if (!cli_explicit.count("coind_p2p_port") && cfg["coind_p2p_port"])
                coind_p2p_port = cfg["coind_p2p_port"].as<int>();
            if (!cli_explicit.count("coind_p2p_address") && cfg["coind_p2p_address"])
                coind_p2p_address = cfg["coind_p2p_address"].as<std::string>();

            // Redistribute mode
            if (!cli_explicit.count("redistribute") && cfg["redistribute"])
                redistribute_mode_str = cfg["redistribute"].as<std::string>();

            // Optional operator-provided V36 message_data blob
            if (!cli_explicit.count("message_blob_hex") && cfg["message_blob_hex"])
                operator_message_blob_hex = cfg["message_blob_hex"].as<std::string>();

        } catch (const YAML::Exception& e) {
            LOG_ERROR << "Failed to load config file '" << config_file << "': " << e.what();
            return 1;
        }
    }

    // -----------------------------------------------------------------------
    // Post-parse: auto-detect defaults, assemble p2pool-style merged spec
    // -----------------------------------------------------------------------

    // Auto-detect RPC port from chain type if not set
    if (rpc_port == 0) {
        if (blockchain == Blockchain::LITECOIN)
            rpc_port = settings->m_testnet ? 19332 : 9332;
        else if (blockchain == Blockchain::BITCOIN)
            rpc_port = settings->m_testnet ? 18332 : 8332;
        else if (blockchain == Blockchain::DOGECOIN)
            rpc_port = settings->m_testnet ? 44555 : 22555;
        else
            rpc_port = 9332;  // fallback
    }

    // Auto-detect P2P and Stratum ports for testnet if not explicitly set
    if (settings->m_testnet) {
        if (!cli_explicit.count("p2p_port"))
            p2p_port = 19338;    // p2pool testnet convention (mainnet + 10012)
        if (!cli_explicit.count("stratum_port"))
            stratum_port = 19327; // p2pool testnet convention (mainnet + 10000)
    }

    // Assemble p2pool-style --merged-coind-* flags into a merged spec
    if (merged_coind_rpc_port > 0 && !merged_coind_address.empty()) {
        // p2pool uses a single merged chain; detect symbol from P2P port or default to DOGE
        std::string merged_symbol = "DOGE";
        uint32_t merged_chain_id = 98;  // Dogecoin default
        std::string spec = merged_symbol + ":" + std::to_string(merged_chain_id)
            + ":" + merged_coind_address + ":" + std::to_string(merged_coind_rpc_port)
            + ":" + merged_coind_rpc_user + ":" + merged_coind_rpc_pass;
        if (merged_coind_p2p_port > 0)
            spec += ":" + std::to_string(merged_coind_p2p_port);
        merged_chain_specs.push_back(spec);
        LOG_INFO << "Assembled merged spec from p2pool-style flags: " << spec;
    }

    // If --address was given without --node-owner-address, use it for node owner too
    if (!payout_address.empty() && node_owner_address.empty() && node_owner_fee > 0.0)
        node_owner_address = payout_address;

    // Guard against port conflicts between stratum and web dashboard
    if (stratum_port == http_port) {
        LOG_WARNING << "Stratum port " << stratum_port << " conflicts with web dashboard port"
                    << ", moving dashboard to " << (stratum_port + 1);
        http_port = stratum_port + 1;
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
            LOG_INFO << "  Stratum (mining):    " << http_host << ":" << stratum_port;
            LOG_INFO << "  Web dashboard/API:   " << http_host << ":" << http_port;
            LOG_INFO << "  P2P (sharechain):    " << p2p_port;
            LOG_INFO << "Features: automatic difficulty adjustment, blockchain-specific address validation";
            
            // Create enhanced node with default constructor to avoid nullptr issues
            auto enhanced_node = std::make_shared<c2pool::node::EnhancedC2PoolNode>(settings->m_testnet);
            
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

            // Populate RuntimeConfig for /config endpoint and Qt integration
            core::RuntimeConfig runtime_config;
            runtime_config.testnet = settings->m_testnet;
            runtime_config.integrated = integrated_mode;
            runtime_config.sharechain = sharechain_mode;
            runtime_config.blockchain = blockchain_to_symbol(blockchain);
            runtime_config.p2p_port = p2p_port;
            runtime_config.stratum_port = stratum_port;
            runtime_config.http_port = http_port;
            runtime_config.http_host = http_host;
            runtime_config.rpc_host = rpc_host;
            runtime_config.rpc_port = rpc_port;
            runtime_config.coind_p2p_address = coind_p2p_address;
            runtime_config.coind_p2p_port = coind_p2p_port;
            runtime_config.payout_address = payout_address.empty() ? solo_address : payout_address;
            runtime_config.node_owner_address = node_owner_address;
            runtime_config.node_owner_fee = node_owner_fee;
            runtime_config.dev_donation = dev_donation;
            runtime_config.redistribute_mode = redistribute_mode_str;
            runtime_config.seed_nodes = seed_nodes;
            runtime_config.max_outgoing_conns = max_outgoing_conns;
            runtime_config.merged_chain_specs = merged_chain_specs;
            runtime_config.auto_detect_wallet = auto_detect_wallet;

            // Generate cookie auth token for secure API access
            const auto datadir = core::filesystem::config_path();
            core::CookieAuth::generate(datadir);

            // Create web server with explicit port configuration
            core::WebServer web_server(ioc, http_host, static_cast<uint16_t>(http_port),
                                     settings->m_testnet, enhanced_node, blockchain);

            // Attach runtime config for /config endpoint
            web_server.get_mining_interface()->set_runtime_config(&runtime_config);

            // Wire live coin-daemon RPC so getblocktemplate/submitblock use real data
            web_server.set_coin_rpc(node_rpc.get(), &coin_node);

            // Feed real network difficulty from block templates to the adjustment engine
            web_server.get_mining_interface()->set_on_network_difficulty(
                [engine = &enhanced_node->get_difficulty_engine()](double diff) {
                    engine->set_network_difficulty(diff);
                });
            
            // Start P2P sharechain node for broadcasting new best-blocks to peers
            std::string p2p_config_dir = settings->m_testnet ? "ltc_testnet" : "ltc";
            auto ltc_p2p_config = std::make_unique<ltc::Config>(p2p_config_dir);
            // Load/create ~/.c2pool/{ltc,ltc_testnet}/{pool,coin}.yaml so bootstrap_addrs are available.
            ltc_p2p_config->init();
            ltc_p2p_config->m_testnet = settings->m_testnet;

            // Set testnet flag for runtime constant selection (SHARE_PERIOD, CHAIN_LENGTH, etc.)
            ltc::PoolConfig::is_testnet = settings->m_testnet;

            // Override P2P prefix for testnet (init() loads mainnet prefix from YAML)
            if (settings->m_testnet) {
                ltc_p2p_config->pool()->m_prefix = ParseHexBytes(ltc::PoolConfig::TESTNET_PREFIX_HEX);
                LOG_INFO << "P2P prefix set to testnet: " << ltc::PoolConfig::TESTNET_PREFIX_HEX;
            }

            // For testnet, discard hardcoded mainnet bootstrap peers before Node construction
            // (Node constructor copies bootstrap_addrs into its addr store)
            if (settings->m_testnet)
                ltc_p2p_config->pool()->m_bootstrap_addrs.clear();
            for (const auto& seed : seed_nodes) {
                ltc_p2p_config->pool()->m_bootstrap_addrs.emplace_back(seed);
                LOG_INFO << "Added seed node: " << seed;
            }

            auto p2p_node = std::make_unique<ltc::Node>(&ioc, ltc_p2p_config.get());
            if (max_outgoing_conns_set) {
                p2p_node->set_target_outbound_peers(static_cast<size_t>(max_outgoing_conns));
                LOG_INFO << "Configured outbound peer target: " << max_outgoing_conns;
            }
            p2p_node->core::Server::listen(static_cast<uint16_t>(p2p_port));
            LOG_INFO << "P2P sharechain node listening on port " << p2p_port;

            // --- Parent chain P2P broadcaster (fast block relay) ---
            // Auto-detect P2P port from chain type if not explicitly set.
            // P2P address defaults to the same host as RPC (coin daemon).
            if (coind_p2p_port == -1) {
                coind_p2p_port = get_coin_p2p_port(blockchain_to_symbol(blockchain), settings->m_testnet);
                if (coind_p2p_port > 0)
                    LOG_INFO << "Auto-detected parent coin P2P port: " << coind_p2p_port;
            }
            std::unique_ptr<ltc::coin::p2p::NodeP2P<ltc::Config>> coin_p2p;
            if (coind_p2p_port > 0) {
                std::string p2p_host = coind_p2p_address.empty() ? rpc_host : coind_p2p_address;
                // Override coin config P2P prefix + address with correct values
                auto parent_symbol = blockchain_to_symbol(blockchain);
                ltc_p2p_config->coin()->m_p2p.prefix = get_chain_p2p_prefix(parent_symbol, settings->m_testnet);
                ltc_p2p_config->coin()->m_p2p.address = NetService(p2p_host, static_cast<uint16_t>(coind_p2p_port));
                coin_p2p = std::make_unique<ltc::coin::p2p::NodeP2P<ltc::Config>>(
                    &ioc, &coin_node, ltc_p2p_config.get());
                coin_p2p->connect(NetService(p2p_host, static_cast<uint16_t>(coind_p2p_port)));
                LOG_INFO << "Parent coin P2P broadcaster connecting to " << p2p_host << ":" << coind_p2p_port;
            }

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
            
            // Wire P2P block relay for fast parent block propagation.
            // When a block is accepted by the daemon, also send it via P2P
            // for near-instant propagation to the coin network.
            if (coin_p2p) {
                web_server.set_on_block_relay([&coin_p2p](const std::string& full_block_hex) {
                    try {
                        auto block_bytes = ParseHex(full_block_hex);
                        coin_p2p->submit_block_raw(block_bytes);
                    } catch (const std::exception& e) {
                        LOG_WARNING << "P2P block relay failed: " << e.what();
                    }
                });
            }

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
            // Use the consensus donation script directly from PoolConfig (V36).
            {
                auto donation_script = ltc::PoolConfig::get_donation_script(36);
                web_server.get_mining_interface()->set_donation_script(donation_script);
                LOG_INFO << "Donation script set: V36 COMBINED_DONATION_SCRIPT ("
                         << donation_script.size() << " bytes)";
            }

            // Optional operator-provided encrypted authority message blob.
            // This blob is embedded in locally created V36 shares as message_data.
            if (!operator_message_blob_hex.empty()) {
                if (operator_message_blob_hex.size() % 2 != 0) {
                    LOG_ERROR << "--message-blob-hex must have even length";
                    return 1;
                }
                std::vector<unsigned char> blob;
                try {
                    blob = ParseHex(operator_message_blob_hex);
                } catch (const std::exception& e) {
                    LOG_ERROR << "Invalid --message-blob-hex: " << e.what();
                    return 1;
                }
                auto err = ltc::validate_message_data(blob);
                if (!err.empty()) {
                    LOG_ERROR << "Rejected --message-blob-hex: " << err;
                    return 1;
                }
                web_server.get_mining_interface()->set_operator_message_blob(blob);
                LOG_INFO << "Operator message blob configured (" << blob.size() << " bytes)";
            }

            // Wire the share tracker's best share hash into the mining interface
            // so that mining_submit can link new shares to the chain head.
            web_server.set_best_share_hash_fn([&p2p_node]() {
                return p2p_node->best_share_hash();
            });

            // Wire live sharechain statistics into the REST API.
            web_server.get_mining_interface()->set_sharechain_stats_fn([&p2p_node]() {
                nlohmann::json result;
                auto& chain = p2p_node->tracker().chain;

                // Use tallest chain head (not verified best) so stats stay current during sync
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }

                result["total_shares"]    = static_cast<int>(chain.size());
                result["fork_count"]      = static_cast<int>(chain.get_heads().size());
                result["chain_tip_hash"]  = best.IsNull() ? "" : best.GetHex();
                result["chain_height"]    = best.IsNull() ? 0 : chain.get_height(best);

                std::map<std::string, int> by_version;
                std::map<std::string, int> by_miner;
                double diff_sum = 0.0;
                int diff_count  = 0;

                // Timeline: 6 slots of 10 minutes each, ending at now
                auto now_ts = static_cast<uint32_t>(std::time(nullptr));
                constexpr int SLOTS = 6;
                constexpr uint32_t SLOT_SEC = 600;
                uint32_t window_start = now_ts - SLOTS * SLOT_SEC;
                struct Slot { uint32_t ts; int count; std::map<std::string, int> miners; };
                std::vector<Slot> slots(SLOTS);
                for (int i = 0; i < SLOTS; ++i)
                    slots[i].ts = window_start + (i + 1) * SLOT_SEC;

                // Walk up to 2000 shares from best head backwards
                if (!best.IsNull()) {
                    int height = chain.get_height(best);
                    int walk = std::min(height, 2000);
                    if (walk > 0) {
                        try {
                            auto view = chain.get_chain(best, walk);
                            for (auto& [hash, data] : view) {
                                data.share.invoke([&](auto* s) {
                                    // Version
                                    auto ver_key = std::to_string(s->version);
                                    by_version[ver_key]++;

                                    // Miner address (version-dependent)
                                    std::string miner;
                                    if constexpr (requires { s->m_address; })
                                        miner = HexStr(s->m_address.m_data);
                                    else if constexpr (requires { s->m_pubkey_hash; })
                                        miner = s->m_pubkey_hash.GetHex();
                                    if (!miner.empty())
                                        by_miner[miner]++;

                                    // Difficulty
                                    auto target = chain::bits_to_target(s->m_bits);
                                    double diff = chain::target_to_difficulty(target);
                                    diff_sum += diff;
                                    diff_count++;

                                    // Timeline bucketing
                                    if (s->m_timestamp >= window_start) {
                                        int idx = static_cast<int>((s->m_timestamp - window_start) / SLOT_SEC);
                                        if (idx >= SLOTS) idx = SLOTS - 1;
                                        slots[idx].count++;
                                        if (!miner.empty())
                                            slots[idx].miners[miner]++;
                                    }
                                });
                            }
                        } catch (...) {
                            // chain walk may throw if data is inconsistent; return partial results
                        }
                    }
                }

                result["shares_by_version"] = by_version;
                result["shares_by_miner"]   = by_miner;
                result["average_difficulty"] = diff_count > 0 ? diff_sum / diff_count : 1.0;
                result["heaviest_fork_weight"] = 0.0; // TODO: compute when multi-fork scoring is needed
                result["difficulty_trend"] = nlohmann::json::array();

                nlohmann::json tl = nlohmann::json::array();
                for (auto& sl : slots) {
                    tl.push_back({
                        {"timestamp",          sl.ts},
                        {"share_count",        sl.count},
                        {"miner_distribution", sl.miners}
                    });
                }
                result["timeline"] = tl;
                return result;
            });

            // Wire per-share window data for the defragmenter grid
            web_server.get_mining_interface()->set_sharechain_window_fn([&p2p_node]() {
                nlohmann::json result;
                auto& chain = p2p_node->tracker().chain;
                auto& verified = p2p_node->tracker().verified;

                // Use tallest chain head (not verified best) so the grid stays current during sync
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }

                result["best_hash"] = best.IsNull() ? "" : best.GetHex();
                result["chain_length"] = static_cast<int>(chain.size());

                nlohmann::json shares_arr = nlohmann::json::array();

                if (!best.IsNull()) {
                    int height = chain.get_height(best);
                    int walk = std::min(height, 2000);
                    if (walk > 0) {
                        try {
                            int pos = 0;
                            auto view = chain.get_chain(best, walk);
                            for (auto& [hash, data] : view) {
                                nlohmann::json s;
                                s["hash"] = hash.GetHex().substr(0, 16);
                                s["pos"] = pos++;
                                s["verified"] = verified.contains(hash);

                                data.share.invoke([&](auto* obj) {
                                    s["ts"] = obj->m_timestamp;
                                    s["ver"] = obj->version;
                                    s["stale"] = static_cast<int>(obj->m_stale_info);

                                    std::string miner;
                                    if constexpr (requires { obj->m_pubkey_hash; })
                                        miner = obj->m_pubkey_hash.GetHex();
                                    else if constexpr (requires { obj->m_address; })
                                        miner = HexStr(obj->m_address.m_data);
                                    s["miner"] = miner;
                                });

                                shares_arr.push_back(std::move(s));
                            }
                        } catch (...) {
                            // partial results on chain inconsistency
                        }
                    }
                }

                // heads and tails for fork marking
                nlohmann::json heads_arr = nlohmann::json::array();
                for (auto& [hh, _] : chain.get_heads()) {
                    heads_arr.push_back(hh.GetHex().substr(0, 16));
                }

                result["shares"] = std::move(shares_arr);
                result["heads"] = std::move(heads_arr);
                result["total"] = static_cast<int>(chain.size());
                return result;
            });

            // Expose decoded protocol messages from best share via API.
            web_server.get_mining_interface()->set_protocol_messages_fn([&p2p_node]() {
                nlohmann::json result = {
                    {"best_share_hash", ""},
                    {"message_data_hex", ""},
                    {"decrypted", false},
                    {"authority_pubkey_hex", ""},
                    {"messages", nlohmann::json::array()}
                };

                auto best = p2p_node->best_share_hash();
                if (best.IsNull())
                    return result;

                result["best_share_hash"] = best.GetHex();

                std::vector<unsigned char> blob;
                p2p_node->tracker().chain.get(best).share.invoke([&](auto* s) {
                    if constexpr (requires { s->m_message_data; })
                        blob = s->m_message_data.m_data;
                });

                if (blob.empty())
                    return result;

                result["message_data_hex"] = HexStr(blob);

                auto unpacked = ltc::unpack_share_messages(blob.data(), blob.size());
                result["decrypted"] = unpacked.decrypted;
                if (!unpacked.decrypted || unpacked.authority_pubkey == nullptr)
                    return result;

                result["authority_pubkey_hex"] = HexStr(*unpacked.authority_pubkey);
                nlohmann::json msgs = nlohmann::json::array();
                for (const auto& msg : unpacked.messages) {
                    msgs.push_back({
                        {"type", msg.msg_type},
                        {"flags", msg.flags},
                        {"timestamp", msg.timestamp},
                        {"payload_hex", HexStr(msg.payload)},
                        {"signature_hex", HexStr(msg.signature)},
                        {"protocol_authority", (msg.wire_flags & ltc::FLAG_PROTOCOL_AUTHORITY) != 0},
                        {"is_transition_signal", msg.msg_type == ltc::MSG_TRANSITION_SIGNAL}
                    });
                }
                result["messages"] = msgs;
                return result;
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
                    const uint256& frozen_prev_share,
                    const std::vector<unsigned char>& coinbase_scriptSig,
                    const std::vector<unsigned char>& payout_script,
                    uint64_t subsidy, uint32_t bits, uint32_t timestamp,
                    bool segwit_active, const std::string& witness_commitment_hex,
                    const uint256& witness_root,
                    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs,
                    const std::vector<uint256>& merkle_branches)
                    -> std::pair<uint256, uint64_t>
                {
                    ltc::RefHashParams params;
                    params.prev_share = frozen_prev_share;
                    params.coinbase_scriptSig = coinbase_scriptSig;
                    params.share_nonce = 0;
                    params.subsidy = subsidy;
                    params.donation = 50; // 0.5%
                    params.desired_version = 36;

                    // Compute pool-level share target from tracker state
                    auto desired_target = chain::bits_to_target(bits);
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

                    // Segwit data — txid_merkle_link must match create_local_share
                    if (segwit_active && !witness_commitment_hex.empty()) {
                        params.has_segwit = true;
                        ltc::SegwitData sd;
                        sd.m_txid_merkle_link.m_branch = merkle_branches;
                        sd.m_txid_merkle_link.m_index  = 0;
                        // Use raw wtxid merkle root (not the commitment hash)
                        if (!witness_root.IsNull()) {
                            sd.m_wtxid_merkle_root = witness_root;
                        } else if (witness_commitment_hex.size() >= 76) {
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
                        // Timestamp: clip to at least previous_share.timestamp + 1 (matches Python)
                        tracker.chain.get(params.prev_share).share.invoke([&](auto* prev) {
                            params.absheight = prev->m_absheight + 1;
                            if (params.timestamp <= prev->m_timestamp)
                                params.timestamp = prev->m_timestamp + 1;
                        });

                        // Recompute share target with the clipped timestamp
                        {
                            auto desired_target2 = chain::bits_to_target(bits);
                            auto [sm, sb] = tracker.compute_share_target(
                                params.prev_share, params.timestamp, desired_target2);
                            params.max_bits = sm;
                            params.bits = sb;
                        }

                        // abswork: prev_abswork + target_to_average_attempts(THIS share's bits)
                        tracker.chain.get(params.prev_share).share.invoke([&](auto* prev) {
                            auto attempts = chain::target_to_average_attempts(
                                chain::bits_to_target(params.bits));
                            params.abswork = prev->m_abswork + uint128(attempts.GetLow64());
                        });

                        // far_share_hash: 99th ancestor (matches Python: get_nth_parent_hash(prev, 99))
                        {
                            auto [prev_height, last] = tracker.chain.get_height_and_last(params.prev_share);
                            if (last.IsNull() && prev_height < 99) {
                                params.far_share_hash = uint256();
                            } else {
                                params.far_share_hash = tracker.chain.get_nth_parent_key(params.prev_share, 99);
                            }
                        }

                        // Merged payout hash: deterministic V36 PPLNS commitment.
                        // Must match what create_local_share computes at submit time.
                        params.merged_payout_hash = tracker.compute_merged_payout_hash(
                            params.prev_share, chain::bits_to_target(bits));
                    }

                    return ltc::compute_ref_hash_for_work(params);
                });

            // Wire the share creation hook so mining_submit() creates a real
            // V36 share in the tracker and broadcasts it to peers.
            web_server.get_mining_interface()->set_create_share_fn(
                [&p2p_node](const core::MiningInterface::ShareCreationParams& p) {
                try {
                    // Don't create shares before PPLNS is available.
                    // Without chain data, the coinbase won't have correct PPLNS outputs
                    // and Python peers will reject and ban us.
                    if (p.prev_share_hash.IsNull()) {
                        LOG_WARNING << "Skipping share creation: no prev_share (chain not ready)";
                        return;
                    }

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

                    // Always use the frozen share chain tip from job creation time.
                    // The ref_hash in the coinbase was computed with this prev_share,
                    // so create_local_share must use the same value (even if null).
                    uint256 prev_share = p.prev_share_hash;

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
                        p.witness_commitment_hex,
                        p.message_data,
                        p.full_coinbase_bytes,
                        p.witness_root);

                    // Only broadcast if self-validation passed (non-null hash)
                    if (share_hash.IsNull()) {
                        return;  // share failed PoW or validation; don't broadcast
                    }

                    // Broadcast to all connected peers
                    try {
                        p2p_node->broadcast_share(share_hash);
                    } catch (const std::exception& e) {
                        LOG_ERROR << "broadcast_share failed: " << e.what();
                    }

                    LOG_INFO << "Share created and broadcast: "
                             << share_hash.GetHex().substr(0, 16) << "..."
                             << " subsidy=" << p.subsidy
                             << " merged_chains=" << merged_addrs.size();
                } catch (const std::exception& e) {
                    LOG_ERROR << "create_share_fn failed (before broadcast): " << e.what();
                }
            });

            // --- Integrated Merged Mining ---
            // Parse --merged specs and set up the manager (replaces standalone mm-adapter)
            std::unique_ptr<c2pool::merged::MergedMiningManager> mm_manager;
            // Merged chain P2P broadcasters (one per chain with P2P configured)
            std::map<uint32_t, std::unique_ptr<c2pool::merged::CoinBroadcaster>> merged_broadcasters;

            if (!merged_chain_specs.empty()) {
                mm_manager = std::make_unique<c2pool::merged::MergedMiningManager>(ioc);
                for (const auto& spec : merged_chain_specs) {
                    // Format: SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]
                    std::vector<std::string> parts;
                    std::string token;
                    std::istringstream ss(spec);
                    while (std::getline(ss, token, ':'))
                        parts.push_back(token);
                    if (parts.size() < 6) {
                        LOG_ERROR << "Invalid --merged spec (expected SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]): " << spec;
                        continue;
                    }
                    c2pool::merged::AuxChainConfig cfg;
                    cfg.symbol       = parts[0];
                    cfg.chain_id     = static_cast<uint32_t>(std::stoul(parts[1]));
                    cfg.rpc_host     = parts[2];
                    cfg.rpc_port     = static_cast<uint16_t>(std::stoul(parts[3]));
                    cfg.rpc_userpass = parts[4] + ":" + parts[5];
                    cfg.multiaddress = false;  // Use createauxblock/submitauxblock for now

                    // DOGE testnet burn address (version 0x71, hash160 = zeros)
                    // Used as payout address for createauxblock RPC
                    if (cfg.symbol == "DOGE" && settings->m_testnet)
                        cfg.aux_payout_address = "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt";
                    else if (cfg.symbol == "DOGE")
                        cfg.aux_payout_address = "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr";  // mainnet burn

                    // P2P port: explicit (7th field) or auto-detected from symbol
                    if (parts.size() >= 7 && !parts[6].empty()) {
                        cfg.p2p_port = static_cast<uint16_t>(std::stoul(parts[6]));
                    } else {
                        int auto_port = get_coin_p2p_port(cfg.symbol, settings->m_testnet);
                        if (auto_port > 0) {
                            cfg.p2p_port = static_cast<uint16_t>(auto_port);
                            LOG_INFO << "Auto-detected P2P port for " << cfg.symbol << ": " << auto_port;
                        }
                    }
                    cfg.p2p_address = cfg.rpc_host;  // same host as RPC daemon

                    mm_manager->add_chain(cfg);
                    LOG_INFO << "Merged mining: added " << cfg.symbol
                             << " (chain_id=" << cfg.chain_id << ") at "
                             << cfg.rpc_host << ":" << cfg.rpc_port;

                    // Create multi-peer P2P broadcaster if P2P port is configured
                    if (cfg.p2p_port > 0) {
                        auto prefix = get_chain_p2p_prefix(cfg.symbol, settings->m_testnet);
                        if (!prefix.empty()) {
                            // Valid ports for this chain (main + testnet)
                            c2pool::merged::PeerManagerConfig pm_cfg;
                            pm_cfg.is_merged = true;
                            pm_cfg.max_peers = 20;
                            pm_cfg.min_peers = 4;
                            pm_cfg.max_connection_attempts = 5;
                            pm_cfg.refresh_interval_sec = 300; // 5 min for merged
                            // Populate valid ports for this chain
                            if (cfg.symbol == "DOGE" || cfg.symbol == "doge") {
                                pm_cfg.valid_ports = {22556, 44556, 44557};
                            } else if (cfg.symbol == "LTC" || cfg.symbol == "ltc") {
                                pm_cfg.valid_ports = {9333, 19335};
                            } else if (cfg.symbol == "BTC" || cfg.symbol == "btc") {
                                pm_cfg.valid_ports = {8333, 18333};
                            }
                            auto broadcaster = std::make_unique<c2pool::merged::CoinBroadcaster>(
                                ioc, cfg.symbol, prefix,
                                NetService(cfg.p2p_address, cfg.p2p_port),
                                ".", pm_cfg);
                            // Wire getpeerinfo bootstrap from the aux chain RPC
                            auto* rpc_ptr = mm_manager->get_chain_rpc(cfg.chain_id);
                            if (rpc_ptr) {
                                broadcaster->set_getpeerinfo_fn([rpc_ptr]() {
                                    return rpc_ptr->getpeerinfo();
                                });
                            }
                            broadcaster->start();
                            LOG_INFO << "Merged multi-peer broadcaster: " << cfg.symbol
                                     << " → " << cfg.p2p_address << ":" << cfg.p2p_port;
                            merged_broadcasters[cfg.chain_id] = std::move(broadcaster);
                        } else {
                            LOG_WARNING << "Unknown P2P prefix for " << cfg.symbol
                                        << " — P2P broadcaster disabled for this chain";
                        }
                    }
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

                // Wire merged P2P block relay: when a merged block is submitted
                // via RPC, also send it over P2P for fast network propagation.
                if (!merged_broadcasters.empty()) {
                    mm_manager->set_block_relay_fn(
                        [&merged_broadcasters](uint32_t chain_id, const std::string& block_hex) {
                            auto it = merged_broadcasters.find(chain_id);
                            if (it == merged_broadcasters.end()) return;
                            try {
                                auto block_bytes = ParseHex(block_hex);
                                it->second->submit_block_raw(block_bytes);
                            } catch (const std::exception& e) {
                                LOG_WARNING << "[" << it->second->symbol()
                                            << "] Merged P2P relay failed: " << e.what();
                            }
                        });
                }
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

            // Set operator identity for "fee" and "boost" modes.
            // get_node_fee_hash160() extracts the hash160 from the P2PKH fee scriptPubKey
            // that was set earlier via set_node_fee_from_address().
            {
                auto op_h160 = web_server.get_mining_interface()->get_node_fee_hash160();
                if (op_h160.size() == 40) {
                    uint160 op_hash;
                    for (int i = 0; i < 20; ++i)
                        op_hash.data()[i] = static_cast<uint8_t>(
                            std::stoul(op_h160.substr(i * 2, 2), nullptr, 16));
                    redistributor->set_operator_identity(op_hash, 0); // P2PKH
                }
            }

            // Set donation identity for "donate" mode (V36 combined donation P2SH)
            {
                uint160 don_hash;
                std::memcpy(don_hash.data(),
                    ltc::PoolConfig::COMBINED_DONATION_SCRIPT.data() + 2, 20);
                redistributor->set_donation_identity(don_hash, 2); // P2SH
            }

            // Wire Redistributor into MiningInterface as the address-fallback callback.
            // Called for Case 3: invalid/empty LTC address with no usable DOGE address.
            //
            // redistributor_ptr is a raw pointer — the unique_ptr is kept alive for the
            // duration of the pool (moved into redistributor_holder below).
            {
                auto* redistributor_ptr = redistributor.get();
                auto* node_ptr = p2p_node.get();
                web_server.get_mining_interface()->set_address_fallback_fn(
                    [redistributor_ptr, node_ptr](const std::string& /*bad_addr*/) -> std::string {
                        auto best = node_ptr->best_share_hash();
                        auto result = redistributor_ptr->pick(node_ptr->tracker(), best);
                        // Convert uint160 to 40-char hex string
                        static const char* HEX = "0123456789abcdef";
                        std::string h160;
                        h160.reserve(40);
                        const unsigned char* bytes = result.pubkey_hash.data();
                        for (int i = 0; i < 20; ++i) {
                            h160 += HEX[bytes[i] >> 4];
                            h160 += HEX[bytes[i] & 0x0f];
                        }
                        return h160;
                    });
            }
            // Keep redistributor alive for the lifetime of the pool
            auto redistributor_holder = std::move(redistributor);

            // Periodic run_think timer (every 15 seconds) — verify shares & manage peers
            auto think_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            std::function<void(boost::system::error_code)> think_tick;
            think_tick = [&, think_timer](boost::system::error_code ec) {
                if (ec || g_shutdown_requested) return;
                try {
                    p2p_node->run_think();
                } catch (const std::exception& e) {
                    LOG_ERROR << "[THINK] error: " << e.what();
                }
                think_timer->expires_after(std::chrono::seconds(15));
                think_timer->async_wait(think_tick);
            };
            think_timer->expires_after(std::chrono::seconds(15));
            think_timer->async_wait(think_tick);

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
            LOG_INFO << "Stratum interface: stratum+tcp://" << http_host << ":" << stratum_port;
            LOG_INFO << "Web dashboard:     http://" << http_host << ":" << http_port;
            LOG_INFO << "Features enabled:";
            LOG_INFO << "  ✓ Blockchain-specific address validation";
            LOG_INFO << "  ✓ Automatic difficulty adjustment";
            LOG_INFO << "  ✓ Real-time hashrate tracking";
            LOG_INFO << "  ✓ Persistent storage";
            
            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.restart();
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
                ioc.restart();
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
                ioc.restart();
                ioc.run_for(std::chrono::milliseconds(100));
            }
        }
        
        // Clean up auth cookie on shutdown
        core::CookieAuth::cleanup(core::filesystem::config_path());

        LOG_INFO << "c2pool shutdown complete";

    } catch (const std::exception& e) {
        LOG_ERROR << "Fatal error: " << e.what();
        return 1;
    }
    
    return 0;
}
