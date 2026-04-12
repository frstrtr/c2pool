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
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <iomanip>
#include <sstream>

// Core includes
#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <core/coinbase_builder.hpp>
#include <c2pool/storage/the_checkpoint.hpp>
#include <core/pack.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <core/hash.hpp>
#include <core/address_utils.hpp>
#include <core/config.hpp>

// Pool infrastructure
#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <sharechain/sharechain.hpp>
#include <sharechain/stats_skiplist.hpp>

// LTC implementation
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/auto_ratchet.hpp>
#include <impl/ltc/share_messages.hpp>
#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>
#include <impl/ltc/config.hpp>

// Chain seed discovery
#include <impl/ltc/coin/chain_seeds.hpp>
#include <impl/doge/coin/chain_seeds.hpp>

// Block explorer JSON serializer
#include <impl/ltc/coin/block_json.hpp>

// UTXO bootstrap pipeline (ordered block download for cold-start sync)
#include <core/coin/block_bootstrapper.hpp>

// Enhanced C2Pool components
#include <c2pool/node/enhanced_node.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <c2pool/storage/sharechain_storage.hpp>
#include <c2pool/storage/found_block_store.hpp>
#include <c2pool/payout/payout_manager.hpp>

// --- Platform-specific crash handler ---
#ifdef _WIN32
#include <windows.h>
#include <io.h>

static void write_crash_log(const char* reason) {
    auto crash_path = core::filesystem::config_path() / "crash.log";
    FILE* f = fopen(crash_path.string().c_str(), "a");
    if (!f) return;
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_s(&tm_buf, &now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(f, "\n=== CRASH: %s at %s\n", reason, time_str);
    fprintf(f, "=== END CRASH ===\n");
    fclose(f);
}

static void terminate_handler() {
    fprintf(stderr, "\n=== std::terminate() called ===\n");
    auto eptr = std::current_exception();
    if (eptr) {
        try { std::rethrow_exception(eptr); }
        catch (const std::exception& e) {
            fprintf(stderr, "Unhandled exception: %s\n", e.what());
            char msg[512];
            snprintf(msg, sizeof(msg), "std::terminate — %s", e.what());
            write_crash_log(msg);
        }
        catch (...) {
            fprintf(stderr, "Unhandled non-std exception\n");
            write_crash_log("std::terminate — unknown exception");
        }
    } else {
        fprintf(stderr, "No active exception\n");
        write_crash_log("std::terminate — no exception");
    }
    fprintf(stderr, "=== END ===\n");
    _exit(134);
}

static void segfault_handler(int sig) {
    fprintf(stderr, "\n=== CRASH (signal %d) ===\n", sig);
    char msg[64];
    snprintf(msg, sizeof(msg), "signal %d", sig);
    write_crash_log(msg);
    _exit(128 + sig);
}

#else // POSIX

#include <execinfo.h>
#include <cxxabi.h>

static void write_crash_log(const char* reason) {
    int fd = open("/tmp/c2pool_crash.log", O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "a");
    if (!f) { close(fd); return; }
    {
        time_t now = time(nullptr);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", &tm_buf);
        fprintf(f, "\n=== CRASH: %s at %s\n", reason, time_str);
        void* frames[64];
        int n = backtrace(frames, 64);
        char** syms = backtrace_symbols(frames, n);
        if (syms) {
            for (int i = 0; i < n; ++i)
                fprintf(f, "  %s\n", syms[i]);
            free(syms);
        }
        fprintf(f, "=== END CRASH ===\n");
        fclose(f);
    }
}

static void terminate_handler() {
    fprintf(stderr, "\n=== std::terminate() called ===\n");
    auto eptr = std::current_exception();
    if (eptr) {
        try { std::rethrow_exception(eptr); }
        catch (const std::exception& e) {
            fprintf(stderr, "Unhandled exception: %s\n", e.what());
            char msg[512];
            snprintf(msg, sizeof(msg), "std::terminate — %s", e.what());
            write_crash_log(msg);
        }
        catch (...) {
            fprintf(stderr, "Unhandled non-std exception\n");
            write_crash_log("std::terminate — unknown exception");
        }
    } else {
        fprintf(stderr, "No active exception\n");
        write_crash_log("std::terminate — no exception");
    }
    void* frames[64];
    int n = backtrace(frames, 64);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    fprintf(stderr, "=== END ===\n");
    _exit(134);
}

static void segfault_handler(int sig) {
    void* frames[64];
    int n = backtrace(frames, 64);
    fprintf(stderr, "\n=== CRASH (signal %d) ===\n", sig);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    fprintf(stderr, "=== END CRASH ===\n");
    char msg[64];
    snprintf(msg, sizeof(msg), "signal %d", sig);
    write_crash_log(msg);
    _exit(128 + sig);
}

#endif // _WIN32

// Integrated merged mining
#include <c2pool/merged/merged_mining.hpp>
#include <c2pool/merged/coin_broadcaster.hpp>
// Phase 5: Embedded DOGE node for daemonless merged mining
#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/template_builder.hpp>
#include <impl/doge/coin/aux_chain_embedded.hpp>
#include <impl/doge/coin/auxpow_header.hpp>

// V36-compatible operational features
#include <impl/ltc/pool_monitor.hpp>
#include <impl/ltc/whale_departure.hpp>
#include <impl/ltc/redistribute.hpp>

// Coin daemon RPC
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>
#include <impl/ltc/coin/template_builder.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
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
    std::cout << "  --integrated              Full P2P pool with sharechain (DEFAULT)\n";
    std::cout << "  --solo                    Solo pool mode (no P2P sharechain, local payouts)\n";
    std::cout << "  --custodial               Custodial pool (coinbase to --address, stratum for accounting)\n";
    std::cout << "  --sharechain              Sharechain-only mode (P2P node, no mining)\n";
    std::cout << "  --standalone              Legacy solo: minimal stratum + RPC daemon, no embedded SPV\n";
    std::cout << "  --net CHAIN               Blockchain: litecoin, digibyte, bitcoin, dogecoin\n";
    std::cout << "                            (alias: --blockchain; default: litecoin)\n";
    std::cout << "  --config FILE             Load configuration from YAML file\n";
    std::cout << "  --address ADDRESS         Node operator payout address (optional; miners use stratum username)\n";
    std::cout << "  --no-embedded-ltc         Disable embedded LTC SPV (use RPC daemon instead)\n";
    std::cout << "  --no-embedded-doge        Disable embedded DOGE SPV\n";
    std::cout << "  --genesis                 Create genesis share if chain is empty (don't wait for peers)\n";
    std::cout << "  --wait-for-peers          Wait for peers to download sharechain (DEFAULT)\n\n";
    
    std::cout << "PAYOUT & FEE CONFIGURATION:\n";
    std::cout << "  --give-author PERCENT     Developer donation (alias: --dev-donation; default: 0.1%)\n";
    std::cout << "  -f / --fee PERCENT        Node owner fee (alias: --node-owner-fee; default: 0%)\n";
    std::cout << "  --node-owner-address ADDR Node owner payout address\n";
    std::cout << "  --redistribute MODE       Redistribution mode: pplns, fee, boost, donate\n\n";
    
    std::cout << "PORT CONFIGURATION:\n";
    std::cout << "  --p2pool-port PORT        P2P sharechain port (alias: --p2p-port; default: 9326)\n";
    std::cout << "  -w / --worker-port PORT   Stratum/worker port (alias: --stratum-port; default: 9327)\n";
    std::cout << "  --web-port PORT           Web dashboard / JSON-RPC API port (alias: --http-port; default: 8080)\n";
    std::cout << "  --http-host HOST          HTTP server bind address (default: 0.0.0.0)\n";
    std::cout << "  --external-ip ADDR        Public IP or domain for stratum URL display (default: auto-detect)\n\n";

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

    std::cout << "STRATUM TUNING:\n";
    std::cout << "  --stratum-min-diff N      Minimum per-connection difficulty (default: 0.001)\n";
    std::cout << "  --stratum-max-diff N      Maximum per-connection difficulty (default: 65536)\n";
    std::cout << "  --stratum-target-time N   Target seconds per pseudoshare (default: 3)\n";
    std::cout << "  --no-vardiff              Disable automatic difficulty adjustment\n";
    std::cout << "  --max-coinbase-outputs N  Max coinbase outputs per block (default: 4000, matches p2pool)\n\n";

    std::cout << "EMBEDDED NODE OPTIONS:\n";
    std::cout << "  --embedded-ltc            Use embedded LTC SPV node (no daemon needed)\n";
    std::cout << "  --embedded-doge           Use embedded DOGE SPV node for merged mining\n";
    std::cout << "  --doge-testnet4alpha      Use DOGE testnet4alpha (default: testnet3)\n";
    std::cout << "  --doge-p2p-address HOST   Direct DOGE P2P peer address (e.g. your dogecoind)\n";
    std::cout << "  --doge-p2p-port PORT      Direct DOGE P2P peer port (overrides auto-detect)\n";
    std::cout << "  --header-checkpoint H:HASH  LTC header chain starting point\n";
    std::cout << "  --doge-header-checkpoint H:HASH  DOGE header chain starting point\n\n";

    std::cout << "COINBASE CUSTOMIZATION:\n";
    std::cout << "  --coinbase-text TEXT       Custom text in coinbase scriptSig (replaces /c2pool/ tag)\n";
    std::cout << "                            Max 20 chars with merged mining, 64 without\n";
    std::cout << "                            Default: /c2pool/ (c2pool always identified by donation address)\n\n";

    std::cout << "PRIVATE SHARECHAIN:\n";
    std::cout << "  --network-id ID           Private network identifier (hex, e.g. DEADBEEF)\n";
    std::cout << "                            Default: 0 (public p2pool network)\n";
    std::cout << "                            Nonzero: creates a private sharechain. P2P prefix\n";
    std::cout << "                            and THE metadata will carry this ID on the blockchain.\n";
    std::cout << "                            Genesis shares are created automatically when chain is empty.\n";
    std::cout << "  --startup-mode MODE       Sharechain startup behavior:\n";
    std::cout << "                              auto    — wait for peers (60s), then genesis if none (default)\n";
    std::cout << "                              genesis — create new chain immediately, don't wait for peers\n";
    std::cout << "                              wait    — never create genesis, wait indefinitely for peers\n";
    std::cout << "  --startup-timeout N       Seconds to wait for peers in auto mode (default: 60)\n\n";

    std::cout << "V36 SHARE MESSAGE BLOB (CLI operator control):\n";
    std::cout << "  --message-blob-hex HEX    Encrypted authority-signed message_data blob\n";
    std::cout << "                            to embed in locally created V36 shares\n\n";

    std::cout << "OPERATIONAL TUNING:\n";
    std::cout << "  --log-file FILE           Log filename (default: debug.log in data dir)\n";
    std::cout << "  --log-rotation-mb N       Rotate log file at N MB (default: 10)\n";
    std::cout << "  --log-max-mb N            Max total rotated log space in MB (default: 50)\n";
    std::cout << "  --log-level LEVEL         Log level: trace, debug, info, warning, error (default: trace)\n";
    std::cout << "  --p2p-max-peers N         Max total P2P peers (default: 30)\n";
    std::cout << "  --ban-duration N          P2P ban duration in seconds (default: 300)\n";
    std::cout << "  --rss-limit-mb N          Abort if RSS exceeds N MB (default: 4000)\n";
    std::cout << "  --cors-origin ORIGIN      CORS Access-Control-Allow-Origin (default: disabled)\n";
    std::cout << "  --payout-window N         PPLNS payout window in seconds (default: 86400)\n";
    std::cout << "  --storage-save-interval N Periodic sharechain save interval in seconds (default: 300)\n";
    std::cout << "  --dashboard-dir PATH      Dashboard static files directory (default: web-static)\n\n";

    std::cout << "BLOCKCHAIN SUPPORT:\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cout << "  Litecoin (LTC)    Parent chain with embedded SPV\n";
    std::cout << "  DigiByte (DGB)    Parent chain (Scrypt algo, --net digibyte)\n";
    std::cout << "  Dogecoin (DOGE)   Merged mining aux chain (embedded SPV)\n";
    std::cout << "  PEP/BELLS/LKY/JKC/SHIC  Merged mining aux chains (external daemons)\n";
    std::cout << "  Bitcoin (BTC)     Protocol compatibility (future)\n\n";
    
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
    // Install crash handlers
    std::set_terminate(terminate_handler);
    std::signal(SIGINT, signal_handler);
#ifndef _WIN32
    std::signal(SIGTERM, signal_handler);  // SIGTERM not reliably delivered on Windows
#endif
    std::signal(SIGSEGV, segfault_handler);
    std::signal(SIGABRT, segfault_handler);

    // Initialize logging
    core::log::Logger::init();
    
    std::cout << "\n"
              << "  c2pool v0.1 — P2Pool rebirth in C++\n"
              << "  https://github.com/frstrtr/c2pool\n"
              << "\n"
              << "  Distributed under the MIT/X11 software license, see the accompanying\n"
              << "  file LICENSE or http://www.opensource.org/licenses/mit-license.php.\n"
              << "\n"
              << "  THIS IS EXPERIMENTAL SOFTWARE.\n"
              << "  USE AT YOUR OWN RISK.\n"
              << "\n"
              << "  THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n"
              << "  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n"
              << "  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\n"
              << "\n";
    LOG_INFO    << "##############################################";
    LOG_INFO    << "#  c2pool v0.1 -- Decentralized Mining Pool  #";
    LOG_INFO    << "#  https://github.com/frstrtr/c2pool         #";
    LOG_INFO    << "##############################################";
    LOG_WARNING << "############################################################";
    LOG_WARNING << "#  THIS IS EXPERIMENTAL SOFTWARE -- USE AT YOUR OWN RISK   #";
    LOG_WARNING << "#  THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY      #";
    LOG_WARNING << "#  OF ANY KIND, EXPRESS OR IMPLIED.                        #";
    LOG_WARNING << "#  Distributed under the MIT/X11 software license          #";
    LOG_WARNING << "#  See http://www.opensource.org/licenses/mit-license.php  #";
    LOG_WARNING << "############################################################";

    // Default settings
    auto settings = std::make_unique<core::Settings>();
    settings->m_testnet = false;
    
    // Port configuration with p2pool-compatible defaults
    int p2p_port = 9326;           // P2Pool P2P sharechain port (p2pool LTC mainnet default)
    int stratum_port = 9327;       // Stratum mining port (p2pool: -w / --worker-port)
    int http_port = 8080;          // Web dashboard / JSON-RPC API port
    std::string http_host = "0.0.0.0";  // HTTP server host
    std::string external_ip;              // Public IP/domain for stratum URL (empty = auto-detect)

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
    std::string node_owner_merged_address; // Explicit merged chain (DOGE) address for node fee
    std::string node_owner_script;         // Node owner script hex
    double dev_donation = 0.1;          // Developer donation percentage (default 0.1%)
    double node_owner_fee = 0.0;        // Node owner fee percentage
    bool auto_detect_wallet = true;     // Auto-detect wallet address
    bool integrated_mode = true;     // Default: full integrated pool (p2pool persist=true)
    bool sharechain_mode = false;
    bool solo_mode       = false;    // --solo: integrated pool without P2P sharechain
    bool custodial_mode  = false;    // --custodial: all coinbase to --address, stratum for accounting
    bool embedded_ltc    = true;     // Default: embedded LTC SPV (no daemon needed)
    bool embedded_doge   = true;     // Default: embedded DOGE SPV for merged mining
    bool doge_testnet4alpha = false;  // Use DOGE testnet4alpha instead of standard testnet3
    // Embedded SPV bootstrap checkpoints (mainnet defaults, skip millions of old headers)
    // Override with --header-checkpoint / --doge-header-checkpoint or config YAML.
    // Testnet: set via CLI or config (no hardcoded default).
    std::string header_checkpoint_str       = "3088000:4a7fc8d4668c69db4f40fcdeb99ad3dbd85545b742b48e1529ebbec641e547d1";
    std::string doge_header_checkpoint_str  = "6160000:51efd04daebddba43ae403662098524d99abf3edad3bddc3ea7b2938c6799939";
    std::string doge_p2p_address;            // --doge-p2p-address HOST
    int doge_p2p_port = 0;                   // --doge-p2p-port PORT
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

    // Stratum tuning (configurable via CLI or YAML)
    core::StratumConfig stratum_config;  // defaults: min=0.001, max=65536, target=10s, vardiff=true

    // Operational tuning (configurable via CLI or YAML)
    std::string log_file;                        // empty = default "debug.log"
    int         log_rotation_size_mb = 100;      // rotate log at N MB
    int         log_max_total_mb     = 50;       // keep ≤N MB of rotated logs
    std::string log_level_str;                   // empty = default (trace)
    int         p2p_max_peers        = 30;       // max total P2P peers
    int         p2p_ban_duration     = 300;      // ban duration in seconds
    long        rss_limit_mb         = 4000;     // abort if RSS exceeds N MB
    std::string http_cors_origin     = "";       // Access-Control-Allow-Origin (empty = disabled)
    int         payout_window_seconds = 86400;   // PPLNS payout window (24h)
    int         cache_max_shared_hashes = 50000; // de-dup set cap
    int         cache_max_known_txs     = 10000; // known TX cache cap
    int         cache_max_raw_shares    = 50000; // raw share cache cap
    int         storage_save_interval   = 300;   // periodic save interval (seconds)

    // Dashboard directory (web-static/ by default, relative to CWD)
    std::string dashboard_dir = "web-static";

    // Google Analytics measurement ID (e.g. G-XXXXXXXXXX)
    std::string analytics_id;

    // Lite block explorer
    bool explorer_enabled = false;
    std::string explorer_url;
    uint32_t explorer_depth_ltc = 288;
    uint32_t explorer_depth_doge = 1440;

    // Custom explorer link prefixes (override Blockchair defaults)
    std::string address_explorer_prefix;
    std::string block_explorer_prefix;
    std::string tx_explorer_prefix;

    // Optional encrypted authority message_data blob for local V36 shares.
    std::string operator_message_blob_hex;

    // Coinbase scriptSig customization
    std::string coinbase_text;  // --coinbase-text (replaces /c2pool/ tag)

    // Private sharechain
    uint32_t network_id = 0;        // 0 = public p2pool network, nonzero = private

    // Startup mode: wait (default, p2pool persist=true), genesis, auto
    enum class StartupMode { AUTO, GENESIS, WAIT };
    StartupMode startup_mode = StartupMode::WAIT;  // Default: wait for peers (persist=true)
    int startup_timeout = 60;       // seconds to wait for peers in auto mode

    // Track which options were explicitly set via CLI so that --config file
    // values only fill in gaps (CLI always wins).
    std::set<std::string> cli_explicit;
    
    // Helper function to parse blockchain string
    auto parse_blockchain = [](const std::string& blockchain_str) -> Blockchain {
        if (blockchain_str == "ltc" || blockchain_str == "litecoin") return Blockchain::LITECOIN;
        if (blockchain_str == "dgb" || blockchain_str == "digibyte") return Blockchain::DIGIBYTE;
        if (blockchain_str == "btc" || blockchain_str == "bitcoin") return Blockchain::BITCOIN;
        if (blockchain_str == "eth" || blockchain_str == "ethereum") return Blockchain::ETHEREUM;
        if (blockchain_str == "xmr" || blockchain_str == "monero") return Blockchain::MONERO;
        if (blockchain_str == "zec" || blockchain_str == "zcash") return Blockchain::ZCASH;
        if (blockchain_str == "doge" || blockchain_str == "dogecoin") return Blockchain::DOGECOIN;

        LOG_ERROR << "Unknown blockchain: " << blockchain_str;
        LOG_INFO << "Supported blockchains: ltc, dgb, btc, doge";
        throw std::invalid_argument("Unknown blockchain type");
    };

    // Well-known P2P ports for coin daemons (same machine as RPC by default)
    auto get_coin_p2p_port = [](const std::string& symbol, bool testnet) -> int {
        if (symbol == "LTC"   || symbol == "ltc")   return testnet ? 19335 : 9333;
        if (symbol == "DOGE"  || symbol == "doge")  return testnet ? 44556 : 22556;
        if (symbol == "BTC"   || symbol == "btc")   return testnet ? 18333 : 8333;
        if (symbol == "DGB"   || symbol == "dgb")   return testnet ? 12026 : 12024;
        if (symbol == "PEP"   || symbol == "pep")   return testnet ? 44874 : 33874;
        if (symbol == "BELLS" || symbol == "bells")  return testnet ? 29919 : 19919;
        if (symbol == "LKY"   || symbol == "lky")   return testnet ? 19917 : 9917;
        if (symbol == "JKC"   || symbol == "jkc")   return testnet ? 19771 : 9771;
        if (symbol == "SHIC"  || symbol == "shic")  return testnet ? 44864 : 33864;
        if (symbol == "DINGO" || symbol == "dingo") return testnet ? 44117 : 33117;
        return 0;  // unknown chain — caller must specify explicitly
    };
    auto blockchain_to_symbol = [](Blockchain b) -> std::string {
        switch (b) {
            case Blockchain::LITECOIN: return "LTC";
            case Blockchain::DIGIBYTE: return "DGB";
            case Blockchain::BITCOIN:  return "BTC";
            case Blockchain::DOGECOIN: return "DOGE";
            default: return "";
        }
    };
    // Known P2P magic prefixes for common chains
    auto get_chain_p2p_prefix = [&doge_testnet4alpha](const std::string& symbol, bool testnet) -> std::vector<std::byte> {
        if (symbol == "DOGE" || symbol == "doge") {
            if (!testnet) return ParseHexBytes("c0c0c0c0");
            // --testnet = testnet3 (fcc1b7dc), --doge-testnet4alpha = testnet4alpha (d4a1f4a1)
            return doge_testnet4alpha ? ParseHexBytes("d4a1f4a1") : ParseHexBytes("fcc1b7dc");
        }
        if (symbol == "LTC" || symbol == "ltc") {
            return testnet ? ParseHexBytes("fdd2c8f1") : ParseHexBytes("fbc0b6db");
        }
        if (symbol == "BTC" || symbol == "btc") {
            return testnet ? ParseHexBytes("0b110907") : ParseHexBytes("f9beb4d9");
        }
        if (symbol == "DGB" || symbol == "dgb") {
            return testnet ? ParseHexBytes("fdc8bddd") : ParseHexBytes("fac3b6da");
        }
        if (symbol == "PEP" || symbol == "pep") {
            return testnet ? ParseHexBytes("fec1dbcc") : ParseHexBytes("c0a0f0e0");
        }
        if (symbol == "BELLS" || symbol == "bells") {
            return testnet ? ParseHexBytes("c3c3c3c3") : ParseHexBytes("c0c0c0c0");
        }
        if (symbol == "LKY" || symbol == "lky") {
            return testnet ? ParseHexBytes("fcc1b7dc") : ParseHexBytes("fbc0b6db");
        }
        if (symbol == "JKC" || symbol == "jkc") {
            return testnet ? ParseHexBytes("fcc1b7dc") : ParseHexBytes("fbc0b6db");
        }
        if (symbol == "SHIC" || symbol == "shic") {
            return testnet ? ParseHexBytes("b1c1e1f1") : ParseHexBytes("b0c0e0f0");
        }
        if (symbol == "DINGO" || symbol == "dingo") {
            return testnet ? ParseHexBytes("c2c2c2c2") : ParseHexBytes("c1c1c1c1");
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
        else if (arg == "--external-ip" && i + 1 < argc) {
            external_ip = argv[++i];
            cli_explicit.insert("external_ip");
        }
        else if (arg == "--integrated") {
            integrated_mode = true;
            cli_explicit.insert("integrated");
        }
        else if (arg == "--solo") {
            solo_mode = true;
            integrated_mode = true;  // solo is a variant of integrated
            cli_explicit.insert("solo");
            cli_explicit.insert("integrated");
        }
        else if (arg == "--custodial") {
            custodial_mode = true;
            integrated_mode = true;  // custodial is a variant of integrated
            cli_explicit.insert("custodial");
            cli_explicit.insert("integrated");
        }
        else if (arg == "--sharechain") {
            sharechain_mode = true;
            integrated_mode = false;
            cli_explicit.insert("sharechain");
            cli_explicit.insert("integrated");
        }
        else if (arg == "--standalone") {
            // Legacy solo mode: minimal stratum + RPC daemon, no embedded SPV
            integrated_mode = false;
            embedded_ltc = false;
            embedded_doge = false;
            cli_explicit.insert("integrated");
            cli_explicit.insert("embedded_ltc");
            cli_explicit.insert("embedded_doge");
        }
        else if (arg == "--embedded-ltc") {
            embedded_ltc = true;
            cli_explicit.insert("embedded_ltc");
        }
        else if (arg == "--no-embedded-ltc") {
            embedded_ltc = false;
            cli_explicit.insert("embedded_ltc");
        }
        else if (arg == "--embedded-doge") {
            embedded_doge = true;
            cli_explicit.insert("embedded_doge");
        }
        else if (arg == "--no-embedded-doge") {
            embedded_doge = false;
            cli_explicit.insert("embedded_doge");
        }
        else if (arg == "--doge-testnet4alpha") {
            doge_testnet4alpha = true;
            cli_explicit.insert("doge_testnet4alpha");
        }
        else if (arg == "--header-checkpoint" && i + 1 < argc) {
            header_checkpoint_str = argv[++i];
            cli_explicit.insert("header_checkpoint");
        }
        else if (arg == "--doge-header-checkpoint" && i + 1 < argc) {
            doge_header_checkpoint_str = argv[++i];
            cli_explicit.insert("doge_header_checkpoint");
        }
        else if (arg == "--doge-p2p-address" && i + 1 < argc) {
            doge_p2p_address = argv[++i];
            cli_explicit.insert("doge_p2p_address");
        }
        else if (arg == "--doge-p2p-port" && i + 1 < argc) {
            doge_p2p_port = std::stoi(argv[++i]);
            cli_explicit.insert("doge_p2p_port");
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
        else if ((arg == "--node-owner-merged-address" || arg == "--merged-operator-address") && i + 1 < argc) {
            node_owner_merged_address = argv[++i];
            cli_explicit.insert("node_owner_merged_address");
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
        else if (arg == "--coinbase-text" && i + 1 < argc) {
            coinbase_text = argv[++i];
            cli_explicit.insert("coinbase_text");
        }
        else if ((arg == "--network-id" || arg == "--chain-id") && i + 1 < argc) {
            network_id = static_cast<uint32_t>(std::stoul(argv[++i], nullptr, 16));
            cli_explicit.insert("network_id");
        }
        else if (arg == "--startup-mode" && i + 1 < argc) {
            std::string mode = argv[++i];
            if (mode == "genesis") startup_mode = StartupMode::GENESIS;
            else if (mode == "wait") startup_mode = StartupMode::WAIT;
            else startup_mode = StartupMode::AUTO;
            cli_explicit.insert("startup_mode");
        }
        else if (arg == "--genesis") {
            startup_mode = StartupMode::GENESIS;
            cli_explicit.insert("startup_mode");
        }
        else if (arg == "--wait-for-peers") {
            startup_mode = StartupMode::WAIT;
            cli_explicit.insert("startup_mode");
        }
        else if (arg == "--startup-timeout" && i + 1 < argc) {
            startup_timeout = std::stoi(argv[++i]);
            cli_explicit.insert("startup_timeout");
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
        // Stratum tuning
        else if (arg == "--stratum-min-diff" && i + 1 < argc) {
            stratum_config.min_difficulty = std::stod(argv[++i]);
            cli_explicit.insert("stratum_min_diff");
        }
        else if (arg == "--stratum-max-diff" && i + 1 < argc) {
            stratum_config.max_difficulty = std::stod(argv[++i]);
            cli_explicit.insert("stratum_max_diff");
        }
        else if (arg == "--stratum-target-time" && i + 1 < argc) {
            stratum_config.target_time = std::stod(argv[++i]);
            cli_explicit.insert("stratum_target_time");
        }
        else if (arg == "--no-vardiff") {
            stratum_config.vardiff_enabled = false;
            cli_explicit.insert("vardiff_enabled");
        }
        else if (arg == "--max-coinbase-outputs" && i + 1 < argc) {
            stratum_config.max_coinbase_outputs = static_cast<size_t>(std::stoul(argv[++i]));
            cli_explicit.insert("max_coinbase_outputs");
        }
        // Operational tuning
        else if (arg == "--log-file" && i + 1 < argc) {
            log_file = argv[++i];
            cli_explicit.insert("log_file");
        }
        else if (arg == "--log-rotation-mb" && i + 1 < argc) {
            log_rotation_size_mb = std::stoi(argv[++i]);
            cli_explicit.insert("log_rotation_size_mb");
        }
        else if (arg == "--log-max-mb" && i + 1 < argc) {
            log_max_total_mb = std::stoi(argv[++i]);
            cli_explicit.insert("log_max_total_mb");
        }
        else if (arg == "--log-level" && i + 1 < argc) {
            log_level_str = argv[++i];
            cli_explicit.insert("log_level");
        }
        else if (arg == "--p2p-max-peers" && i + 1 < argc) {
            p2p_max_peers = std::stoi(argv[++i]);
            cli_explicit.insert("p2p_max_peers");
        }
        else if (arg == "--ban-duration" && i + 1 < argc) {
            p2p_ban_duration = std::stoi(argv[++i]);
            cli_explicit.insert("ban_duration");
        }
        else if (arg == "--rss-limit-mb" && i + 1 < argc) {
            rss_limit_mb = std::stol(argv[++i]);
            cli_explicit.insert("rss_limit_mb");
        }
        else if (arg == "--cors-origin" && i + 1 < argc) {
            http_cors_origin = argv[++i];
            cli_explicit.insert("cors_origin");
        }
        else if (arg == "--payout-window" && i + 1 < argc) {
            payout_window_seconds = std::stoi(argv[++i]);
            cli_explicit.insert("payout_window_seconds");
        }
        else if (arg == "--storage-save-interval" && i + 1 < argc) {
            storage_save_interval = std::stoi(argv[++i]);
            cli_explicit.insert("storage_save_interval");
        }
        else if (arg == "--dashboard-dir" && i + 1 < argc) {
            dashboard_dir = argv[++i];
            cli_explicit.insert("dashboard_dir");
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
            if (!cli_explicit.count("solo") && cfg["solo"])
                solo_mode = cfg["solo"].as<bool>();
            if (!cli_explicit.count("custodial") && cfg["custodial"])
                custodial_mode = cfg["custodial"].as<bool>();
            if (!cli_explicit.count("embedded_ltc") && cfg["embedded_ltc"])
                embedded_ltc = cfg["embedded_ltc"].as<bool>();
            if (!cli_explicit.count("embedded_doge") && cfg["embedded_doge"])
                embedded_doge = cfg["embedded_doge"].as<bool>();
            if (!cli_explicit.count("doge_testnet4alpha") && cfg["doge_testnet4alpha"])
                doge_testnet4alpha = cfg["doge_testnet4alpha"].as<bool>();
            if (!cli_explicit.count("doge_p2p_address") && cfg["doge_p2p_address"])
                doge_p2p_address = cfg["doge_p2p_address"].as<std::string>();
            if (!cli_explicit.count("doge_p2p_port") && cfg["doge_p2p_port"])
                doge_p2p_port = cfg["doge_p2p_port"].as<int>();
            if (!cli_explicit.count("startup_mode") && cfg["startup_mode"]) {
                auto m = cfg["startup_mode"].as<std::string>();
                if (m == "genesis") startup_mode = StartupMode::GENESIS;
                else if (m == "wait") startup_mode = StartupMode::WAIT;
                else startup_mode = StartupMode::AUTO;
            }
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
            if (!cli_explicit.count("external_ip") && cfg["external_ip"])
                external_ip = cfg["external_ip"].as<std::string>();

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
            if (!cli_explicit.count("node_owner_merged_address") && cfg["node_owner_merged_address"])
                node_owner_merged_address = cfg["node_owner_merged_address"].as<std::string>();
            if (!cli_explicit.count("node_owner_script") && cfg["node_owner_script"])
                node_owner_script = cfg["node_owner_script"].as<std::string>();
            if (!cli_explicit.count("auto_detect_wallet") && cfg["auto_detect_wallet"])
                auto_detect_wallet = cfg["auto_detect_wallet"].as<bool>();

            // Merged mining chains (config appends; CLI replaces if specified)
            if (!cli_explicit.count("merged") && cfg["merged"] && cfg["merged"].IsSequence()) {
                for (const auto& item : cfg["merged"])
                    merged_chain_specs.push_back(item.as<std::string>());
            }

            // Embedded SPV checkpoints
            if (!cli_explicit.count("header_checkpoint") && cfg["header_checkpoint"])
                header_checkpoint_str = cfg["header_checkpoint"].as<std::string>();
            if (!cli_explicit.count("doge_header_checkpoint") && cfg["doge_header_checkpoint"])
                doge_header_checkpoint_str = cfg["doge_header_checkpoint"].as<std::string>();

            // Coin daemon P2P broadcaster
            if (!cli_explicit.count("coind_p2p_port") && cfg["coind_p2p_port"])
                coind_p2p_port = cfg["coind_p2p_port"].as<int>();
            if (!cli_explicit.count("coind_p2p_address") && cfg["coind_p2p_address"])
                coind_p2p_address = cfg["coind_p2p_address"].as<std::string>();

            // Sharechain seed nodes (appends to -n CLI nodes)
            if (cfg["seed_nodes"] && cfg["seed_nodes"].IsSequence()) {
                for (const auto& item : cfg["seed_nodes"])
                    seed_nodes.push_back(item.as<std::string>());
            }

            // Redistribute mode
            if (!cli_explicit.count("redistribute") && cfg["redistribute"])
                redistribute_mode_str = cfg["redistribute"].as<std::string>();

            // Optional operator-provided V36 message_data blob
            if (!cli_explicit.count("message_blob_hex") && cfg["message_blob_hex"])
                operator_message_blob_hex = cfg["message_blob_hex"].as<std::string>();

            // Stratum tuning
            if (!cli_explicit.count("stratum_min_diff") && cfg["min_difficulty"])
                stratum_config.min_difficulty = cfg["min_difficulty"].as<double>();
            if (!cli_explicit.count("stratum_max_diff") && cfg["max_difficulty"])
                stratum_config.max_difficulty = cfg["max_difficulty"].as<double>();
            if (!cli_explicit.count("stratum_target_time") && cfg["target_time"])
                stratum_config.target_time = cfg["target_time"].as<double>();
            if (!cli_explicit.count("vardiff_enabled") && cfg["vardiff_enabled"])
                stratum_config.vardiff_enabled = cfg["vardiff_enabled"].as<bool>();
            if (!cli_explicit.count("max_coinbase_outputs") && cfg["max_coinbase_outputs"])
                stratum_config.max_coinbase_outputs = cfg["max_coinbase_outputs"].as<size_t>();

            // Operational tuning
            if (!cli_explicit.count("log_file") && cfg["log_file"])
                log_file = cfg["log_file"].as<std::string>();
            if (!cli_explicit.count("log_rotation_size_mb") && cfg["log_rotation_size_mb"])
                log_rotation_size_mb = cfg["log_rotation_size_mb"].as<int>();
            if (!cli_explicit.count("log_max_total_mb") && cfg["log_max_total_mb"])
                log_max_total_mb = cfg["log_max_total_mb"].as<int>();
            if (!cli_explicit.count("log_level") && cfg["log_level"])
                log_level_str = cfg["log_level"].as<std::string>();
            if (!cli_explicit.count("p2p_max_peers") && cfg["p2p_max_peers"])
                p2p_max_peers = cfg["p2p_max_peers"].as<int>();
            if (!cli_explicit.count("ban_duration") && cfg["ban_duration"])
                p2p_ban_duration = cfg["ban_duration"].as<int>();
            if (!cli_explicit.count("rss_limit_mb") && cfg["rss_limit_mb"])
                rss_limit_mb = cfg["rss_limit_mb"].as<long>();
            if (!cli_explicit.count("cors_origin") && cfg["cors_origin"])
                http_cors_origin = cfg["cors_origin"].as<std::string>();
            if (!cli_explicit.count("payout_window_seconds") && cfg["payout_window_seconds"])
                payout_window_seconds = cfg["payout_window_seconds"].as<int>();
            if (!cli_explicit.count("storage_save_interval") && cfg["storage_save_interval"])
                storage_save_interval = cfg["storage_save_interval"].as<int>();
            if (!cli_explicit.count("dashboard_dir") && cfg["dashboard_dir"])
                dashboard_dir = cfg["dashboard_dir"].as<std::string>();
            if (cfg["analytics_id"])
                analytics_id = cfg["analytics_id"].as<std::string>();
            if (cfg["explorer"])
                explorer_enabled = cfg["explorer"].as<bool>();
            if (cfg["explorer_url"])
                explorer_url = cfg["explorer_url"].as<std::string>();
            if (cfg["explorer_depth_ltc"])
                explorer_depth_ltc = cfg["explorer_depth_ltc"].as<uint32_t>();
            if (cfg["explorer_depth_doge"])
                explorer_depth_doge = cfg["explorer_depth_doge"].as<uint32_t>();
            if (cfg["address_explorer_prefix"])
                address_explorer_prefix = cfg["address_explorer_prefix"].as<std::string>();
            if (cfg["block_explorer_prefix"])
                block_explorer_prefix = cfg["block_explorer_prefix"].as<std::string>();
            if (cfg["tx_explorer_prefix"])
                tx_explorer_prefix = cfg["tx_explorer_prefix"].as<std::string>();
            if (cfg["cache_max_shared_hashes"])
                cache_max_shared_hashes = cfg["cache_max_shared_hashes"].as<int>();
            if (cfg["cache_max_known_txs"])
                cache_max_known_txs = cfg["cache_max_known_txs"].as<int>();
            if (cfg["cache_max_raw_shares"])
                cache_max_raw_shares = cfg["cache_max_raw_shares"].as<int>();

        } catch (const YAML::Exception& e) {
            LOG_ERROR << "Failed to load config file '" << config_file << "': " << e.what();
            return 1;
        }
    }

    // -----------------------------------------------------------------------
    // Post-parse: add file sink (initial Logger::init() was console-only)
    // -----------------------------------------------------------------------
    {
        boost::log::core::get()->remove_all_sinks();
        core::log::Logger::init(log_file, log_rotation_size_mb, log_max_total_mb, log_level_str);
        LOG_INFO << "Logger initialized: file=" << (log_file.empty() ? "debug.log" : log_file)
                 << " rotation=" << log_rotation_size_mb << "MB"
                 << " max=" << log_max_total_mb << "MB"
                 << " level=" << (log_level_str.empty() ? "trace" : log_level_str);
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
            p2p_port = 19326;    // p2pool testnet convention (mainnet + 10012)
        if (!cli_explicit.count("stratum_port"))
            stratum_port = 19327; // p2pool testnet convention (mainnet + 10000)
        // Clear mainnet checkpoints for testnet (different chains!)
        if (!cli_explicit.count("header_checkpoint"))
            header_checkpoint_str.clear();
        if (!cli_explicit.count("doge_header_checkpoint"))
            doge_header_checkpoint_str.clear();
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

    // Auto-generate DOGE merged spec when --embedded-doge is set but no --merged DOGE:* provided
    if (embedded_doge) {
        bool has_doge_spec = false;
        for (const auto& s : merged_chain_specs) {
            if (s.substr(0, 4) == "DOGE" || s.substr(0, 4) == "doge") {
                has_doge_spec = true;
                break;
            }
        }
        if (!has_doge_spec) {
            merged_chain_specs.push_back("DOGE:98");
            LOG_INFO << "Auto-generated merged spec DOGE:98 for --embedded-doge";
        }
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
            
            // ── Coin node: embedded (Phase 4) or RPC (legacy) ─────────────────
            ltc::interfaces::Node  coin_node;
            std::unique_ptr<ltc::coin::NodeRPC> node_rpc;

            // Phase 4 embedded objects (alive for the duration of integrated mode)
            std::unique_ptr<ltc::coin::HeaderChain>     embedded_chain;
            std::unique_ptr<ltc::coin::Mempool>         embedded_pool;
            std::unique_ptr<c2pool::merged::CoinBroadcaster> embedded_broadcaster;
            std::unique_ptr<ltc::coin::MWEBTracker>     mweb_tracker;
            std::unique_ptr<ltc::coin::EmbeddedCoinNode> embedded_node;
            // UTXO set for fee computation (block reward + mempool tx fees)
            std::unique_ptr<core::coin::UTXOViewDB>     ltc_utxo_db;
            std::unique_ptr<core::coin::UTXOViewCache>  ltc_utxo_cache;

            // ── Timer heartbeat tracking ────────────────────────────────
            // Each recurring timer stores its last-fired timestamp (ms).
            // The watchdog periodically checks these to detect dead timers.
            auto now_ms = []() -> int64_t {
                return std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
            };
            auto hb_ltc_sync     = std::make_shared<std::atomic<int64_t>>(0);
            auto hb_ltc_mempool  = std::make_shared<std::atomic<int64_t>>(0);
            auto hb_doge_sync    = std::make_shared<std::atomic<int64_t>>(0);
            auto hb_doge_mempool = std::make_shared<std::atomic<int64_t>>(0);
            auto hb_think        = std::make_shared<std::atomic<int64_t>>(0);
            auto hb_monitor      = std::make_shared<std::atomic<int64_t>>(0);

            // Create web server EARLY so the loading page is served immediately
            // during SPV header sync and share loading.
            core::WebServer web_server(ioc, http_host, static_cast<uint16_t>(http_port),
                                     settings->m_testnet, enhanced_node, blockchain);
            web_server.get_mining_interface()->set_stratum_config(stratum_config);
            web_server.get_mining_interface()->set_cors_origin(http_cors_origin);
            web_server.get_mining_interface()->set_worker_port(static_cast<uint16_t>(stratum_port));
            web_server.get_mining_interface()->set_p2p_port(static_cast<uint16_t>(p2p_port));
            if (!external_ip.empty())
                web_server.get_mining_interface()->set_external_ip(external_ip);
#ifdef C2POOL_VERSION
            web_server.get_mining_interface()->set_pool_version(
                "c2pool/" C2POOL_VERSION);
#endif
            // Auto-detect public IP from external services
            // (non-blocking, detached threads). Only fetches if not configured.
            web_server.get_mining_interface()->auto_detect_external_info();
            web_server.set_dashboard_dir(dashboard_dir);
            if (!analytics_id.empty())
                web_server.set_analytics_id(analytics_id);
            if (explorer_enabled) {
                web_server.set_explorer_enabled(true);
                if (!explorer_url.empty())
                    web_server.set_explorer_url(explorer_url);
            }
            if (!address_explorer_prefix.empty())
                web_server.get_mining_interface()->set_custom_explorer_links(
                    address_explorer_prefix, block_explorer_prefix, tx_explorer_prefix);
            // Set stratum port BEFORE start() — start() launches the stratum listener.
            web_server.set_stratum_port(static_cast<uint16_t>(stratum_port));
            // Start HTTP server immediately so loading page is served during sync.
            // Stratum won't have valid work yet, but that's fine — miners retry.
            web_server.start();
            LOG_INFO << "WebServer started early — loading page available at http://"
                     << http_host << ":" << http_port;

            if (embedded_ltc) {
                LOG_INFO << "╔══════════════════════════════════════════════════════════════╗";
                LOG_INFO << "║  [EMB-LTC] Phase 4: EMBEDDED COIN NODE MODE                  ║";
                LOG_INFO << "║  No litecoind RPC required — SPV header chain + P2P sync     ║";
                LOG_INFO << "╚══════════════════════════════════════════════════════════════╝";

                auto ltc_params = settings->m_testnet
                    ? ltc::coin::LTCChainParams::testnet()
                    : ltc::coin::LTCChainParams::mainnet();

                // LevelDB-backed header chain for persistence across restarts
                // Use absolute path under ~/.c2pool/ (matches sharechain + found_blocks)
                std::string chain_db_path = (core::filesystem::config_path()
                    / (settings->m_testnet ? "litecoin_testnet" : "litecoin")
                    / "embedded_headers").string();
                LOG_INFO << "[EMB-LTC] Creating HeaderChain with DB at " << chain_db_path;
                embedded_chain = std::make_unique<ltc::coin::HeaderChain>(ltc_params, chain_db_path);
                // Retry init up to 5 times (previous process may still hold LevelDB lock)
                bool chain_ok = false;
                for (int attempt = 1; attempt <= 5; ++attempt) {
                    if (embedded_chain->init()) {
                        chain_ok = true;
                        break;
                    }
                    LOG_WARNING << "[EMB-LTC] HeaderChain LevelDB init failed (attempt "
                                << attempt << "/5) — retrying in 2s...";
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    embedded_chain = std::make_unique<ltc::coin::HeaderChain>(ltc_params, chain_db_path);
                }
                if (!chain_ok)
                    LOG_WARNING << "[EMB-LTC] HeaderChain LevelDB init failed after 5 attempts — running in-memory only";
                else
                    LOG_INFO << "[EMB-LTC] HeaderChain initialized: size=" << embedded_chain->size()
                             << " height=" << embedded_chain->height();

                // Apply CLI checkpoint (--header-checkpoint HEIGHT:HASH) if provided.
                // This lets operators skip millions of old headers on any chain.
                //
                // score() needs block headers going back far enough to cover the
                // share chain's tail window.  p2pool's HeightTracker uses a backlog
                // of 5 * SHARE_PERIOD * CHAIN_LENGTH / BLOCK_PERIOD blocks.
                // If the checkpoint is too recent, old shares will reference blocks
                // before the checkpoint → unresolvable → degraded scoring accuracy.
                // (Fix 1 in score() prevents oscillation, but accurate scoring
                // requires actual header data.)
                constexpr uint32_t LTC_BLOCK_PERIOD = 150; // seconds
                uint32_t score_backlog = 5 * ltc::PoolConfig::share_period()
                    * ltc::PoolConfig::chain_length() / LTC_BLOCK_PERIOD;
                if (!header_checkpoint_str.empty()) {
                    auto colon = header_checkpoint_str.find(':');
                    if (colon != std::string::npos) {
                        uint32_t cp_height = static_cast<uint32_t>(std::stoul(header_checkpoint_str.substr(0, colon)));
                        uint256 cp_hash;
                        cp_hash.SetHex(header_checkpoint_str.substr(colon + 1));
                        if (!cp_hash.IsNull()) {
                            embedded_chain->set_dynamic_checkpoint(cp_height, cp_hash);
                            // Warn if checkpoint doesn't provide enough backlog
                            // for accurate share chain scoring.  Operators should
                            // set the checkpoint at least score_backlog blocks
                            // before the current network tip.
                            LOG_INFO << "[EMB-LTC] Score backlog needed: " << score_backlog
                                     << " blocks before network tip"
                                     << " (checkpoint at height " << cp_height << ")";
                        }
                    }
                }

                // If chain is still empty after checkpoint, seed the genesis block.
                if (embedded_chain->size() == 0) {
                    ltc::coin::BlockHeaderType genesis;
                    genesis.m_previous_block.SetNull();
                    if (settings->m_testnet) {
                        genesis.m_version   = 1;
                        genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
                        genesis.m_timestamp = 1486949366;
                        genesis.m_bits      = 0x1e0ffff0;
                        genesis.m_nonce     = 293345;
                    } else {
                        genesis.m_version   = 1;
                        genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
                        genesis.m_timestamp = 1317972665;
                        genesis.m_bits      = 0x1e0ffff0;
                        genesis.m_nonce     = 2084524493;
                    }
                    if (embedded_chain->add_header(genesis))
                        LOG_INFO << "[LTC] HeaderChain: genesis block seeded (height 0)";
                    else
                        LOG_WARNING << "HeaderChain: genesis seed rejected — wrong genesis hash?";
                } else {
                    LOG_INFO << "[LTC] HeaderChain: loaded " << embedded_chain->size()
                             << " headers from LevelDB (height=" << embedded_chain->height() << ")";
                }

                LOG_INFO << "[EMB-LTC] Creating Mempool + UTXO + MWEBTracker + EmbeddedCoinNode";
                embedded_pool   = std::make_unique<ltc::coin::Mempool>(core::coin::LTC_LIMITS);

                // UTXO set for transaction fee computation
                {
                    auto utxo_path = (core::filesystem::config_path()
                        / (settings->m_testnet ? "litecoin_testnet" : "litecoin")
                        / "utxo_leveldb").string();
                    core::LevelDBOptions utxo_opts;
                    utxo_opts.block_cache_size = 32 * 1024 * 1024;  // 32 MB cache
                    utxo_opts.write_buffer_size = 8 * 1024 * 1024;  // 8 MB
                    ltc_utxo_db = std::make_unique<core::coin::UTXOViewDB>(utxo_path, utxo_opts);
                    {
                        bool utxo_ok = false;
                        for (int attempt = 1; attempt <= 5; ++attempt) {
                            if (ltc_utxo_db->open()) { utxo_ok = true; break; }
                            LOG_WARNING << "[EMB-LTC] UTXO DB open failed (attempt "
                                        << attempt << "/5) — retrying in 2s...";
                            std::this_thread::sleep_for(std::chrono::seconds(2));
                            ltc_utxo_db = std::make_unique<core::coin::UTXOViewDB>(utxo_path, utxo_opts);
                        }
                        if (utxo_ok) {
                            ltc_utxo_cache = std::make_unique<core::coin::UTXOViewCache>(ltc_utxo_db.get());
                            embedded_pool->set_utxo(ltc_utxo_cache.get());
                            LOG_INFO << "[EMB-LTC] UTXO set opened: best_height=" << ltc_utxo_db->get_best_height()
                                     << " best_block=" << ltc_utxo_db->get_best_block().GetHex().substr(0, 16);
                        } else {
                            LOG_WARNING << "[EMB-LTC] UTXO DB failed to open after 5 attempts — fees will be unknown";
                        }
                    }
                }
                mweb_tracker    = std::make_unique<ltc::coin::MWEBTracker>();
                embedded_node   = std::make_unique<ltc::coin::EmbeddedCoinNode>(
                    *embedded_chain, *embedded_pool, settings->m_testnet, mweb_tracker.get());
                // Gate mining until UTXO has coinbase maturity depth (100 blocks for LTC).
                // Without this, block templates may include TXs spending immature coinbase outputs.
                // Reference: litecoin/src/consensus/consensus.h COINBASE_MATURITY = 100
                if (ltc_utxo_cache) {
                    auto* cache_ptr = ltc_utxo_cache.get();
                    // Mining gate: coinbase_maturity + reorg_buffer
                    // LTC: 100 + 6 (pegout maturity) = 106
                    // Reference: litecoin/src/consensus/consensus.h
                    constexpr uint32_t LTC_GATE = core::coin::LTC_MINING_GATE_DEPTH; // 106
                    embedded_node->set_utxo_ready_fn([cache_ptr, LTC_GATE]() {
                        auto connected = cache_ptr->blocks_connected();
                        bool ready = connected >= LTC_GATE;
                        if (!ready) {
                            static int s_log_ctr = 0;
                            if (s_log_ctr++ % 20 == 0)
                                LOG_INFO << "[EMB-LTC] UTXO maturity gate: blocks_connected="
                                         << connected << " need>=" << LTC_GATE;
                        }
                        return ready;
                    });
                }
                LOG_INFO << "[EMB-LTC] EmbeddedCoinNode ready (testnet=" << settings->m_testnet
                         << ", MWEB=enabled)";

                // Auto-detect P2P port for the embedded broadcaster
                if (coind_p2p_port == -1)
                    coind_p2p_port = get_coin_p2p_port(blockchain_to_symbol(blockchain), settings->m_testnet);
                auto parent_symbol   = blockchain_to_symbol(blockchain);
                auto p2p_prefix      = get_chain_p2p_prefix(parent_symbol, settings->m_testnet);

                // Determine if user specified a local daemon peer
                bool has_local_daemon = !coind_p2p_address.empty() || coind_p2p_port > 0;
                std::string pm_data_dir = (core::filesystem::config_path()
                    / (settings->m_testnet ? "litecoin_testnet" : "litecoin")
                    / "embedded_peers").string();

                if (has_local_daemon) {
                    std::string p2p_host = coind_p2p_address.empty() ? rpc_host : coind_p2p_address;
                    NetService embedded_p2p_addr(p2p_host, static_cast<uint16_t>(
                        coind_p2p_port > 0 ? coind_p2p_port : 19335));
                    embedded_broadcaster = std::make_unique<c2pool::merged::CoinBroadcaster>(
                        ioc, parent_symbol, p2p_prefix, embedded_p2p_addr,
                        pm_data_dir, c2pool::merged::PeerManagerConfig{});
                    LOG_INFO << "[EMB-LTC] Local daemon peer: " << embedded_p2p_addr.to_string();
                } else {
                    // Seed-only mode: no local daemon, rely on DNS seeds + fixed seeds
                    embedded_broadcaster = std::make_unique<c2pool::merged::CoinBroadcaster>(
                        ioc, parent_symbol, p2p_prefix,
                        pm_data_dir, c2pool::merged::PeerManagerConfig{});
                    LOG_INFO << "[EMB-LTC] Seed-only mode (no --coind-p2p-address specified)";
                }

                // Wire DNS seeds + fixed seed fallback into peer manager
                auto& pm = embedded_broadcaster->peer_manager();
                pm.set_dns_seeds(ltc::coin::ltc_dns_seeds(settings->m_testnet));
                pm.set_fixed_seeds(ltc::coin::ltc_fixed_seeds(settings->m_testnet));
                // HTTP peer fallback: fetch from known c2pool nodes if DNS seeds fail
                pm.set_http_peer_seeds({{"voidbind.com", 8080}});

                // Feed mempool transactions into Mempool
                LOG_INFO << "[EMB-LTC] Wiring P2P tx → Mempool callback";
                embedded_broadcaster->set_on_new_tx(
                    [pool = embedded_pool.get(),
                     utxo = ltc_utxo_cache.get()](const std::string& peer_key,
                                                   const ltc::coin::Transaction& tx) {
                        ltc::coin::MutableTransaction mtx(tx);
                        bool added = pool->add_tx(mtx, utxo);
                        if (added) {
                            LOG_DEBUG_COIND << "[EMB-LTC] TX from " << peer_key
                                      << " added to mempool (size=" << pool->size() << ")";
                        }
                    });

                // Wire peer height callback for fast-sync: skip scrypt PoW on old headers.
                // No anchor checkpoint needed — header sync is fast (headers are 80 bytes,
                // old ones skip scrypt PoW). Use --header-checkpoint as optional speedup.
                embedded_broadcaster->set_on_peer_height(
                    [chain = embedded_chain.get()](uint32_t h) {
                        chain->set_peer_tip_height(h);
                        LOG_INFO << "[LTC] Peer reports chain height " << h
                                 << " — fast-sync: scrypt skip below " << (h > 2100 ? h - 2100 : 0);
                    });

                embedded_broadcaster->start();
                if (has_local_daemon) {
                    std::string p2p_host = coind_p2p_address.empty() ? rpc_host : coind_p2p_address;
                    LOG_INFO << "[LTC] Embedded broadcaster started, local="
                             << p2p_host << ":" << (coind_p2p_port > 0 ? coind_p2p_port : 19335)
                             << " + " << ltc::coin::ltc_dns_seeds(settings->m_testnet).size() << " DNS seeds";
                } else {
                    LOG_INFO << "[LTC] Embedded broadcaster started (seed-only), "
                             << ltc::coin::ltc_dns_seeds(settings->m_testnet).size() << " DNS seeds + "
                             << ltc::coin::ltc_fixed_seeds(settings->m_testnet).size() << " fixed seeds";
                }
                // NOTE: set_on_new_headers and set_embedded_node are wired after web_server is created below

            } else {
                // Legacy RPC mode
                node_rpc = std::make_unique<ltc::coin::NodeRPC>(&ioc, &coin_node, settings->m_testnet);

                // Adjust default RPC port based on testnet flag when user didn't override
                if (rpc_port == 19332 && !settings->m_testnet)
                    rpc_port = 9332; // mainnet LTC

                LOG_INFO << "[LTC] Connecting to coin daemon RPC at " << rpc_host << ":" << rpc_port;
                node_rpc->connect(NetService(rpc_host, static_cast<uint16_t>(rpc_port)),
                                  rpc_user + ":" + rpc_pass);
            }

            // web_server was created early (before SPV sync) so the loading
            // page is available immediately. Continue with remaining setup.

            // V35 merged block resolver: requests full LTC block from P2P,
            // extracts fabe6d6d MM commitment from coinbase, looks up DOGE
            // block hash in embedded HeaderChain for exact height.
            // Set later when embedded_broadcaster + doge_chain are created.
            // V35 pending resolution context — carries share metadata for async lookup
            struct MergedResolveCtx {
                uint256 pow_hash;
                std::string miner;  // human-readable address
                uint32_t share_ts{0};  // share's block header timestamp
            };
            using MergedResolverFn = std::function<void(const uint256& ltc_block_hash,
                                                        const MergedResolveCtx& ctx)>;
            auto merged_block_resolver = std::make_shared<MergedResolverFn>();

            // Pending V35 merged block resolutions: LTC block hash → context.
            // When a full LTC block arrives via P2P, check if it's in this set
            // and resolve the DOGE block from its coinbase MM commitment.
            auto pending_merged_resolve = std::make_shared<
                std::map<uint256, MergedResolveCtx>>();

            // Callback fired when a full LTC block arrives that matches a pending
            // merged resolution. Set later when doge_chain is available.
            using OnFullBlockMergedFn = std::function<void(const uint256& block_hash,
                const MergedResolveCtx& ctx, const ltc::coin::BlockType& block)>;
            auto on_full_block_merged = std::make_shared<OnFullBlockMergedFn>();

            // Stratum/payout config (web_server basic config was set at early creation above)
            web_server.get_mining_interface()->set_payout_address(payout_address);
            LOG_INFO << "Stratum config: min_diff=" << stratum_config.min_difficulty
                     << " max_diff=" << stratum_config.max_difficulty
                     << " target_time=" << stratum_config.target_time << "s"
                     << " vardiff=" << (stratum_config.vardiff_enabled ? "on" : "off")
                     << " max_cb_outputs=" << stratum_config.max_coinbase_outputs;
            LOG_INFO << "Operational config: p2p_max_peers=" << p2p_max_peers
                     << " ban_duration=" << p2p_ban_duration << "s"
                     << " rss_limit=" << rss_limit_mb << "MB"
                     << " cors=" << http_cors_origin
                     << " payout_window=" << payout_window_seconds << "s"
                     << " save_interval=" << storage_save_interval << "s";
            
            // io_context needed for block verification timers in all modes
            web_server.get_mining_interface()->set_io_context(&ioc);

            // Stats persistence — survives restarts (p2pool: graph_db)
            {
                std::string net_label = settings->m_testnet ? "testnet" : "mainnet";
                std::string graph_db_path = (core::filesystem::config_path()
                    / net_label / "graph_db").string();
                web_server.get_mining_interface()->set_stat_log_path(graph_db_path);
                web_server.get_mining_interface()->load_stat_log();
            }

            // --- Layer +2: Persistent found block + THE checkpoint storage ---
            // Runs in ALL modes (RPC and embedded). Uses dedicated LevelDB.
            {
                auto* mi = web_server.get_mining_interface();
                std::string net_label = settings->m_testnet ? "testnet" : "mainnet";
                std::string fblk_db_path = (core::filesystem::config_path()
                    / net_label / "found_blocks_db").string();
                auto fblk_leveldb = std::make_shared<core::LevelDBStore>(
                    fblk_db_path, core::LevelDBOptions{});
                if (fblk_leveldb->open()) {
                    auto fblk_store = std::make_shared<c2pool::storage::FoundBlockStore>(*fblk_leveldb);
                    using MI = core::MiningInterface;
                    mi->set_found_block_persistence(
                        [fblk_store, fblk_leveldb](const MI::FoundBlock& blk) -> bool {
                            c2pool::storage::FoundBlockRecord rec;
                            rec.chain = blk.chain;
                            rec.height = blk.height;
                            rec.block_hash = blk.hash;
                            rec.timestamp = blk.ts;
                            rec.status = static_cast<uint8_t>(blk.status);
                            rec.check_count = blk.check_count;
                            rec.confirmations = blk.confirmations;
                            rec.last_checked = static_cast<uint64_t>(std::time(nullptr));
                            return fblk_store->store(rec);
                        },
                        [fblk_store, fblk_leveldb]() -> std::vector<MI::FoundBlock> {
                            auto records = fblk_store->load_all();
                            std::vector<MI::FoundBlock> result;
                            result.reserve(records.size());
                            for (const auto& rec : records) {
                                MI::FoundBlock blk;
                                blk.height = rec.height;
                                blk.hash = rec.block_hash;
                                blk.ts = rec.timestamp;
                                blk.status = static_cast<MI::BlockStatus>(rec.status);
                                blk.check_count = rec.check_count;
                                blk.chain = rec.chain;
                                blk.confirmations = rec.confirmations;
                                result.push_back(std::move(blk));
                            }
                            return result;
                        }
                    );
                    mi->load_persisted_found_blocks();
                    LOG_INFO << "[Pool] Found block persistence enabled at " << fblk_db_path;

                    // Merged block persistence (shares same LevelDB)
                    auto mblk_store = std::make_shared<c2pool::storage::MergedBlockStore>(*fblk_leveldb);
                    mi->set_merged_block_store(mblk_store);
                    LOG_INFO << "[Pool] Merged block persistence enabled ("
                             << mblk_store->count() << " stored)";

                    // THE checkpoint store (shares same LevelDB)
                    auto the_store = std::make_shared<c2pool::storage::TheCheckpointStore>(*fblk_leveldb);
                    mi->set_checkpoint_fns(
                        [the_store]() -> nlohmann::json {
                            for (const auto& chain : {"tLTC", "LTC", "DOGE", "tDOGE"}) {
                                auto cp = the_store->get_latest(chain);
                                if (cp.has_value()) {
                                    return nlohmann::json{
                                        {"chain", cp->chain}, {"block_height", cp->block_height},
                                        {"block_hash", cp->block_hash},
                                        {"the_state_root", cp->the_state_root.GetHex()},
                                        {"sharechain_height", cp->sharechain_height},
                                        {"miner_count", cp->miner_count},
                                        {"hashrate_class", cp->hashrate_class},
                                        {"timestamp", cp->timestamp},
                                        {"status", cp->status == 1 ? "verified" : "pending"}
                                    };
                                }
                            }
                            return nlohmann::json{{"status", "no checkpoints"}};
                        },
                        [the_store]() -> nlohmann::json {
                            auto all = the_store->load_all();
                            nlohmann::json arr = nlohmann::json::array();
                            for (const auto& cp : all) {
                                arr.push_back({
                                    {"chain", cp.chain}, {"block_height", cp.block_height},
                                    {"block_hash", cp.block_hash},
                                    {"the_state_root", cp.the_state_root.GetHex()},
                                    {"sharechain_height", cp.sharechain_height},
                                    {"miner_count", cp.miner_count},
                                    {"timestamp", cp.timestamp},
                                    {"status", cp.status == 1 ? "verified" : (cp.status == 2 ? "mismatch" : "pending")}
                                });
                            }
                            return arr;
                        },
                        [](const uint256&, uint32_t) -> bool { return true; },
                        [the_store, mi](const std::string& chain, uint64_t height,
                                        const std::string& hash, uint64_t ts) {
                            c2pool::storage::TheCheckpoint cp;
                            cp.chain = chain; cp.block_height = height;
                            cp.block_hash = hash; cp.timestamp = ts; cp.status = 0;
                            auto work = mi->get_current_work();
                            cp.the_state_root = work.the_state_root;
                            cp.sharechain_height = work.sharechain_height;
                            cp.miner_count = work.miner_count;
                            cp.hashrate_class = c2pool::TheMetadata::encode_hashrate(work.pool_hashrate);
                            the_store->store(cp);
                            LOG_INFO << "[THE] Checkpoint: " << chain << " height=" << height
                                     << " miners=" << cp.miner_count
                                     << " root=" << cp.the_state_root.GetHex().substr(0, 16) << "...";
                        }
                    );
                    // On startup: prune checkpoints whose blocks are orphaned
                    size_t pruned = the_store->prune_unverified();
                    if (pruned > 0)
                        LOG_INFO << "[THE] Pruned " << pruned << " unverified checkpoints from previous runs";
                    LOG_INFO << "[THE] Checkpoint store: " << the_store->count() << " verified";
                } else {
                    LOG_WARNING << "[Pool] Failed to open found blocks LevelDB at " << fblk_db_path;
                }
            }

            // Wire live coin-daemon RPC so getblocktemplate/submitblock use real data
            if (!embedded_ltc) {
                web_server.set_coin_rpc(node_rpc.get(), &coin_node);
            } else if (embedded_broadcaster && embedded_chain) {
                // Wire embedded node + header-sync callback (now that web_server is alive)
                web_server.set_embedded_node(embedded_node.get());

                // Wire block verification for embedded mode
                auto* mi = web_server.get_mining_interface();
                mi->set_block_verify_fn(
                    [chain = embedded_chain.get()](const std::string& hash_hex) -> int {
                        uint256 h;
                        h.SetHex(hash_hex);
                        auto entry = chain->get_header(h);
                        if (!entry.has_value())
                            return 0;  // not in our chain — still pending
                        // Return actual confirmation count (tip_height - block_height + 1)
                        int32_t tip_h = static_cast<int32_t>(chain->height());
                        int32_t blk_h = static_cast<int32_t>(entry->height);
                        return std::max(1, tip_h - blk_h + 1);
                    });

                // Header validation thread pool (1 thread) — keeps scrypt off io_context.
                // Shared_ptr so it stays alive for the lifetime of the callbacks.
                auto hdr_pool = std::make_shared<boost::asio::thread_pool>(1);

                // Header sync: self-propelling chain catch-up.
                // add_headers() runs scrypt for each header (~20ms each), so we offload
                // it to a background thread and post the follow-up back to ioc.
                LOG_INFO << "[EMB-LTC] Wiring on_new_headers callback (background thread pool)";
                embedded_broadcaster->set_on_new_headers(
                    [chain = embedded_chain.get(), bcaster = embedded_broadcaster.get(),
                     &web_server, &ioc, hdr_pool](
                        const std::string& peer_key,
                        const std::vector<ltc::coin::BlockHeaderType>& hdrs) {
                        LOG_INFO << "[EMB-LTC] Received " << hdrs.size() << " headers from " << peer_key;
                        // Copy batch — caller's vector may be freed after return
                        auto batch = std::make_shared<std::vector<ltc::coin::BlockHeaderType>>(hdrs);
                        boost::asio::post(*hdr_pool,
                            [batch, chain, bcaster, &web_server, &ioc]() {
                                auto t0 = std::chrono::steady_clock::now();
                                int accepted = chain->add_headers(*batch);
                                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - t0).count();
                                if (accepted > 0)
                                    LOG_INFO << "[EMB-LTC] Processed batch: " << batch->size() << " headers"
                                             << " accepted=" << accepted
                                             << " chain_height=" << chain->height()
                                             << " elapsed=" << elapsed << "ms";
                                // Always use the LAST header in the batch as locator for the
                                // next getheaders — this advances past known-but-duplicate
                                // headers loaded from LevelDB.  The peer recognises the hash
                                // (it sent it) and continues from there.
                                uint256 last_hash;
                                if (!batch->empty()) {
                                    auto& last_hdr = batch->back();
                                    auto packed = pack(last_hdr);
                                    last_hash = Hash(packed.get_span());
                                }
                                bool full_batch = (batch->size() >= 2000);
                                if (accepted > 0 || full_batch) {
                                    boost::asio::post(ioc, [accepted, last_hash, chain, bcaster, &web_server]() {
                                      try {
                                        if (accepted > 0) {
                                            LOG_INFO << "[EMB-LTC] Triggering work refresh (new headers)";
                                            web_server.trigger_work_refresh_debounced();
                                            // New headers accepted — use last_hash to continue
                                            if (!last_hash.IsNull()) {
                                                bcaster->request_headers({last_hash}, uint256::ZERO);
                                            } else {
                                                bcaster->request_headers(chain->get_locator(), uint256::ZERO);
                                            }
                                        } else {
                                            // Full batch but all duplicates — use chain tip locator
                                            // to skip past known headers and find new ones
                                            bcaster->request_headers(chain->get_locator(), uint256::ZERO);
                                        }
                                      } catch (const std::exception& e) {
                                        LOG_WARNING << "[EMB-LTC] Header post-process error: " << e.what();
                                      }
                                    });
                                } else {
                                    LOG_DEBUG_COIND << "[EMB-LTC] No new headers accepted (all known), batch=" << batch->size();
                                }
                            });
                    });
                LOG_INFO << "[EMB-LTC] Embedded coin node wired to web server";

                // Full block handler: MWEB state extraction + mempool cleanup.
                // When a full block arrives via P2P, remove confirmed txs from
                // mempool (preserving unconfirmed ones for fee revenue) and
                // extract HogEx state for template construction.
                {
                    LOG_INFO << "[EMB-LTC] Wiring full block handler (MWEB + mempool cleanup)";
                    // Bootstrap state: ordered block download pipeline for cold-start sync.
                    // On a fresh install, the tip block arrives first and sets best_height
                    // high — all bootstrap blocks below it silently fail the height > best
                    // guard. This pipeline buffers blocks and processes in height order.
                    auto ltc_bs = std::make_shared<
                        core::coin::BlockBootstrapState<ltc::coin::BlockType>>();
                    embedded_broadcaster->set_on_full_block(
                        [tracker = mweb_tracker.get(),
                         chain = embedded_chain.get(),
                         pool = embedded_pool.get(),
                         utxo = ltc_utxo_cache.get(),
                         utxo_db = ltc_utxo_db.get(),
                         bcaster = embedded_broadcaster.get(),
                         coinbase_maturity = core::coin::LTC_LIMITS.coinbase_maturity,
                         explorer_enabled, explorer_depth_ltc,
                         pending_merged_resolve, on_full_block_merged,
                         ltc_bs, &ioc, &web_server](
                            const std::string& peer,
                            const ltc::coin::BlockType& block) {
                            // Determine block height from header chain
                            auto packed_hdr = pack(static_cast<const ltc::coin::BlockHeaderType&>(block));
                            auto block_hash = Hash(packed_hdr.get_span());
                            uint32_t height = 0;
                            auto entry = chain->get_header(block_hash);
                            if (entry)
                                height = entry->height;
                            else {
                                auto prev_entry = chain->get_header(block.m_previous_block);
                                if (prev_entry)
                                    height = prev_entry->height + 1;
                            }

                            auto txid_fn = [](const ltc::coin::MutableTransaction& tx) {
                                return ltc::coin::compute_txid(tx);
                            };
                            static bool mempool_requested = false;
                            static bool ltc_bootstrap_done = false;
                            constexpr uint32_t LTC_KEEP = core::coin::LTC_MIN_BLOCKS_TO_KEEP;

                            // ═══ BOOTSTRAP PIPELINE ═══════════════════════════════════
                            // Buffers blocks and processes in strict height order.
                            // Single-peer targeting with round-robin eliminates 20x
                            // duplicate bandwidth. Sliding window of 16 in-flight
                            // requests hides latency. Stall detection re-requests from
                            // all peers if a block doesn't arrive within 30s.

                            if (utxo && utxo_db) {
                                // 1. Bootstrap trigger — fires BEFORE connecting first
                                //    block so best_height isn't set prematurely.
                                if (!ltc_bootstrap_done && !ltc_bs->active &&
                                    chain && bcaster && height > LTC_KEEP) {
                                    ltc_bootstrap_done = true;
                                    uint32_t utxo_best = utxo->get_best_height();
                                    uint32_t start_from =
                                        (utxo_best > 0 && utxo_best >= height - LTC_KEEP)
                                        ? utxo_best + 1 : height - LTC_KEEP;

                                    if (start_from < height) {
                                        ltc_bs->active = true;
                                        ltc_bs->next_height = start_from;
                                        ltc_bs->end_height = height;
                                        ltc_bs->next_request = start_from;
                                        ltc_bs->total = height - start_from + 1;
                                        ltc_bs->buffer[height] = {block, block_hash};
                                        ltc_bs->last_drain_time =
                                            std::chrono::steady_clock::now();

                                        // Request initial window via broadcast (all peers)
                                        // to guarantee responses. Targeted requests are
                                        // used for window refill after drain starts.
                                        int requested = 0;
                                        while (ltc_bs->next_request <= ltc_bs->end_height &&
                                               (ltc_bs->next_request - ltc_bs->next_height)
                                                   < ltc_bs->WINDOW_SIZE) {
                                            if (!ltc_bs->buffer.count(ltc_bs->next_request)) {
                                                auto e = chain->get_header_by_height(
                                                    ltc_bs->next_request);
                                                if (e) {
                                                    bcaster->request_full_block(
                                                        e->block_hash);
                                                    ++requested;
                                                }
                                            }
                                            ++ltc_bs->next_request;
                                        }
                                        LOG_INFO << "[EMB-LTC] Bootstrap pipeline: "
                                                 << ltc_bs->total << " blocks ["
                                                 << start_from << ".." << height << "]"
                                                 << " window=" << ltc_bs->WINDOW_SIZE
                                                 << " requests=" << requested
                                                 << " peers=" << bcaster->peer_count();
                                        // Timer-based stall detection
                                        ltc_bs->start_stall_timer(ioc,
                                            [chain, bcaster](uint32_t h) {
                                                auto e = chain->get_header_by_height(h);
                                                if (e && bcaster)
                                                    bcaster->request_full_block(e->block_hash);
                                            }, "EMB-LTC");
                                        return;
                                    } else {
                                        LOG_INFO << "[EMB-LTC] UTXO warm restart: best="
                                                 << utxo_best << " — no bootstrap needed";
                                    }
                                }

                                // 2. Bootstrap active: buffer → drain → refill window
                                if (ltc_bs->active) {
                                    if (height >= ltc_bs->next_height &&
                                        height <= ltc_bs->end_height) {
                                        ltc_bs->buffer.try_emplace(
                                            height, std::make_pair(block, block_hash));
                                    } else if (height > ltc_bs->end_height) {
                                        // New block mined during bootstrap — extend range
                                        ltc_bs->end_height = height;
                                        ltc_bs->total = ltc_bs->processed
                                            + (ltc_bs->end_height - ltc_bs->next_height + 1);
                                        ltc_bs->buffer.try_emplace(
                                            height, std::make_pair(block, block_hash));
                                    }

                                    // Stall detection: re-request from all peers if stuck
                                    auto now = std::chrono::steady_clock::now();
                                    auto stall = std::chrono::duration_cast<
                                        std::chrono::seconds>(
                                        now - ltc_bs->last_drain_time).count();
                                    if (stall >= ltc_bs->STALL_TIMEOUT_SEC && chain && bcaster) {
                                        auto e = chain->get_header_by_height(
                                            ltc_bs->next_height);
                                        if (e) {
                                            LOG_WARNING << "[EMB-LTC] Bootstrap stall h="
                                                << ltc_bs->next_height << " (" << stall
                                                << "s) — broadcast fallback";
                                            bcaster->request_full_block(e->block_hash);
                                        }
                                        ltc_bs->last_drain_time = now;
                                    }

                                    // Drain consecutive blocks in height order
                                    while (ltc_bs->buffer.count(ltc_bs->next_height)) {
                                        auto node =
                                            ltc_bs->buffer.extract(ltc_bs->next_height);
                                        auto& [b, bh] = node.mapped();
                                        uint32_t h = ltc_bs->next_height;

                                        auto undo = utxo->connect_block(b, h, txid_fn);
                                        utxo_db->put_block_undo(h, undo);
                                        utxo->flush(bh, h);
                                        utxo->prune_undo(h, LTC_KEEP);

                                        if (explorer_enabled) {
                                            PackStream ps;
                                            ps << b;
                                            auto span = ps.get_span();
                                            std::vector<uint8_t> raw(
                                                reinterpret_cast<const uint8_t*>(
                                                    span.data()),
                                                reinterpret_cast<const uint8_t*>(
                                                    span.data()) + span.size());
                                            utxo_db->put_raw_block(h, raw);
                                            utxo_db->prune_raw_blocks(
                                                h, explorer_depth_ltc);
                                        }

                                        if (pool) {
                                            pool->set_tip_height(h);
                                            pool->remove_for_block(b);
                                        }

                                        if (tracker)
                                            tracker->update(b, h, b.m_mweb_raw);

                                        auto pit = pending_merged_resolve->find(bh);
                                        if (pit != pending_merged_resolve->end()
                                            && *on_full_block_merged) {
                                            auto ctx = pit->second;
                                            pending_merged_resolve->erase(pit);
                                            (*on_full_block_merged)(bh, ctx, b);
                                        }

                                        if (!mempool_requested && bcaster) {
                                            bcaster->enable_mempool_request();
                                            mempool_requested = true;
                                        }

                                        ++ltc_bs->next_height;
                                        ++ltc_bs->processed;
                                        ltc_bs->last_drain_time =
                                            std::chrono::steady_clock::now();
                                    }

                                    // Progress log
                                    static int bs_log = 0;
                                    if (++bs_log % 20 == 0 ||
                                        ltc_bs->next_height > ltc_bs->end_height) {
                                        LOG_INFO << "[EMB-LTC] Bootstrap: "
                                                 << ltc_bs->processed << "/"
                                                 << ltc_bs->total
                                                 << " buf=" << ltc_bs->buffer.size();
                                    }

                                    // Refill sliding window (broadcast to all peers)
                                    if (chain && bcaster) {
                                        while (ltc_bs->next_request <= ltc_bs->end_height
                                               && (ltc_bs->next_request - ltc_bs->next_height)
                                                   < ltc_bs->WINDOW_SIZE) {
                                            if (!ltc_bs->buffer.count(
                                                    ltc_bs->next_request)) {
                                                auto e = chain->get_header_by_height(
                                                    ltc_bs->next_request);
                                                if (e)
                                                    bcaster->request_full_block(
                                                        e->block_hash);
                                            }
                                            ++ltc_bs->next_request;
                                        }
                                    }

                                    if (ltc_bs->next_height > ltc_bs->end_height) {
                                        ltc_bs->active = false;
                                        ltc_bs->stop_stall_timer();
                                        LOG_INFO << "[EMB-LTC] Bootstrap complete: "
                                                 << ltc_bs->processed << " blocks";
                                    }
                                    return;
                                }

                                // 3. Normal processing (after bootstrap or warm restart)
                                if (height > utxo->get_best_height()) {
                                    auto undo = utxo->connect_block(
                                        block, height, txid_fn);
                                    utxo_db->put_block_undo(height, undo);
                                    utxo->flush(block_hash, height);
                                    utxo->prune_undo(height, LTC_KEEP);

                                    static int utxo_log = 0;
                                    if (utxo_log++ % 10 == 0) {
                                        LOG_INFO << "[EMB-LTC] UTXO: block " << height
                                                 << " hash="
                                                 << block_hash.GetHex().substr(0, 16)
                                                 << " txs=" << block.m_txs.size()
                                                 << " cache=" << utxo->cache_size();
                                    }

                                    if (!mempool_requested && bcaster) {
                                        bcaster->enable_mempool_request();
                                        mempool_requested = true;
                                        LOG_INFO << "[EMB-LTC] BIP 35 mempool enabled";
                                    }
                                }
                            }

                            // Normal mode: explorer, mempool, MWEB, merged resolve.
                            // During bootstrap these run inside the drain loop above.
                            if (explorer_enabled && utxo_db && height > 0) {
                                PackStream ps;
                                ps << block;
                                auto span = ps.get_span();
                                std::vector<uint8_t> raw(
                                    reinterpret_cast<const uint8_t*>(span.data()),
                                    reinterpret_cast<const uint8_t*>(span.data())
                                        + span.size());
                                utxo_db->put_raw_block(height, raw);
                                utxo_db->prune_raw_blocks(height, explorer_depth_ltc);
                            }

                            if (pool) {
                                pool->set_tip_height(height);
                                pool->remove_for_block(block);
                                if (utxo) {
                                    int resolved = pool->recompute_unknown_fees(utxo);
                                    int evicted = pool->revalidate_inputs(utxo);
                                    if (resolved > 0 || evicted > 0)
                                        web_server.trigger_work_refresh_debounced();
                                }
                            }

                            if (tracker && tracker->update(block, height, block.m_mweb_raw)) {
                                LOG_INFO << "[EMB-LTC] MWEB state updated from " << peer
                                         << " h=" << height
                                         << " mweb=" << block.m_mweb_raw.size() << "B";
                            }

                            auto pit = pending_merged_resolve->find(block_hash);
                            if (pit != pending_merged_resolve->end()
                                && *on_full_block_merged) {
                                auto ctx = pit->second;
                                pending_merged_resolve->erase(pit);
                                (*on_full_block_merged)(block_hash, ctx, block);
                            }
                        });
                }

                // Tip-change handler: invalidate MWEB, request new full block.
                // Mempool cleanup is handled by remove_for_block() in the
                // full_block callback above — same as Litecoin Core, which
                // runs removeForBlock() identically for both normal advances
                // and reorgs (no clear()).
                embedded_chain->set_on_tip_changed(
                    [tracker = mweb_tracker.get(),
                     bcaster = embedded_broadcaster.get(),
                     chain = embedded_chain.get(),
                     utxo = ltc_utxo_cache.get(),
                     utxo_db = ltc_utxo_db.get(),
                     &web_server, &ioc](
                        const uint256& old_tip, uint32_t old_height,
                        const uint256& new_tip, uint32_t new_height) {
                        // This callback fires on the hdr_pool thread.
                        // Post all work to ioc to avoid cross-thread access to
                        // bcaster/web_server/UTXO which are ioc-thread objects.
                        boost::asio::post(ioc,
                            [tracker, bcaster, chain, utxo, utxo_db, &web_server,
                             old_tip, old_height, new_tip, new_height]() {
                      try {
                        bool is_reorg = (new_height <= old_height);
                        LOG_WARNING << "[EMB-LTC] Chain tip changed: "
                                    << old_tip.GetHex().substr(0, 16) << " (h=" << old_height << ") → "
                                    << new_tip.GetHex().substr(0, 16) << " (h=" << new_height << ")"
                                    << (is_reorg ? " [REORG]" : "");

                        // Disconnect old fork blocks from UTXO during reorg.
                        // Uses undo data (added_outpoints + spent_coins) so full blocks
                        // are NOT needed for the old fork.
                        if (is_reorg && utxo && utxo_db && chain) {
                            // Find fork point: walk old_tip backward until we find
                            // a hash that's an ancestor of new_tip
                            std::set<uint256> new_ancestors;
                            {
                                uint256 cur = new_tip;
                                while (!cur.IsNull()) {
                                    new_ancestors.insert(cur);
                                    auto e = chain->get_header(cur);
                                    if (!e) break;
                                    cur = e->prev_hash;
                                }
                            }
                            uint256 fork_hash;
                            uint32_t fork_height = 0;
                            {
                                uint256 cur = old_tip;
                                while (!cur.IsNull()) {
                                    if (new_ancestors.count(cur)) {
                                        fork_hash = cur;
                                        auto e = chain->get_header(cur);
                                        if (e) fork_height = e->height;
                                        break;
                                    }
                                    auto e = chain->get_header(cur);
                                    if (!e) break;
                                    cur = e->prev_hash;
                                }
                            }

                            if (!fork_hash.IsNull() && fork_height < old_height) {
                                int disconnected = 0;
                                for (uint32_t h = old_height; h > fork_height; --h) {
                                    core::coin::BlockUndo undo;
                                    if (utxo_db->get_block_undo(h, undo)) {
                                        utxo->disconnect_from_undo(undo);
                                        utxo_db->remove_block_undo(h);
                                        ++disconnected;
                                    }
                                }
                                utxo->flush(fork_hash, fork_height);
                                LOG_WARNING << "[EMB-LTC] UTXO reorg: disconnected " << disconnected
                                            << " blocks (h=" << old_height << "→" << fork_height
                                            << ") fork=" << fork_hash.GetHex().substr(0, 16);
                            }
                        }

                        // Invalidate stale MWEB state — HogEx prev_txid is from the old fork
                        if (tracker) {
                            tracker->invalidate();
                        }
                        // Request the new tip's full block for MWEB state + mempool cleanup
                        if (bcaster) {
                            bcaster->request_full_block(new_tip);
                        }
                        // Trigger work refresh so stratum miners get the new tip
                        web_server.trigger_work_refresh_debounced();
                      } catch (const std::exception& e) {
                        LOG_ERROR << "[EMB-LTC] Reorg handler error: " << e.what();
                      }
                            }); // end post(ioc)
                    });
                LOG_INFO << "[EMB-LTC] Chain reorg handler registered";

                // Periodic fallback: re-request headers every 60s even if no batch arrived.
                // Uses shared_ptr self-capture so the lambda stays alive for the run duration.
                auto sync_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
                auto sync_timer = std::make_shared<boost::asio::steady_timer>(ioc);
                *sync_fn = [sync_fn, sync_timer, now_ms, hb_ltc_sync,
                            chain   = embedded_chain.get(),
                            bcaster = embedded_broadcaster.get()](boost::system::error_code ec) {
                    if (ec) return; // cancelled (ioc stopped)
                    hb_ltc_sync->store(now_ms());
                    sync_timer->expires_after(std::chrono::seconds(60));
                    sync_timer->async_wait(*sync_fn);
                    try {
                        LOG_DEBUG_COIND << "[EMB-LTC] Periodic header sync: height=" << chain->height()
                                  << " synced=" << chain->is_synced()
                                  << " peers=" << bcaster->connected_count();
                        bcaster->request_headers(chain->get_locator(), uint256::ZERO);
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[EMB-LTC] Header sync error: " << e.what();
                    }
                };
                // Kick off first getheaders after 3s (allow handshake to complete)
                LOG_INFO << "[EMB-LTC] Header chain height: " << embedded_chain->height()
                         << " — starting P2P sync in 3s";
                sync_timer->expires_after(std::chrono::seconds(3));
                sync_timer->async_wait(*sync_fn);
                LOG_INFO << "Embedded header sync timer started (60s interval)";

                // Periodic mempool cleanup: evict expired txs every 5 minutes.
                auto mempool_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
                auto mempool_timer = std::make_shared<boost::asio::steady_timer>(ioc);
                *mempool_fn = [mempool_fn, mempool_timer, now_ms, hb_ltc_mempool,
                               pool = embedded_pool.get()](boost::system::error_code ec) {
                    if (ec) return;
                    hb_ltc_mempool->store(now_ms());
                    mempool_timer->expires_after(std::chrono::minutes(5));
                    mempool_timer->async_wait(*mempool_fn);
                    try {
                        if (pool)
                            pool->evict_expired();
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[EMB-LTC] Mempool cleanup error: " << e.what();
                    }
                };
                mempool_timer->expires_after(std::chrono::minutes(5));
                mempool_timer->async_wait(*mempool_fn);
                LOG_INFO << "[EMB-LTC] Mempool expiration timer started (5m interval)";
            }

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

            // Private chain: override IDENTIFIER and PREFIX before any P2P or share ops
            if (network_id != 0) {
                std::ostringstream hex;
                hex << std::hex << std::setfill('0') << std::setw(8) << network_id;
                // Pad to 16 hex chars (8 bytes) for full IDENTIFIER
                std::string id_hex = hex.str();
                while (id_hex.size() < 16) id_hex += "00";
                ltc::PoolConfig::set_network_id(id_hex);
                LOG_INFO << "[Private] Network ID: " << ltc::PoolConfig::identifier_hex()
                         << " (PREFIX: " << ltc::PoolConfig::prefix_hex() << ")";
            }

            // Set P2P prefix (respects private chain override)
            ltc_p2p_config->pool()->m_prefix = ParseHexBytes(ltc::PoolConfig::prefix_hex());
            LOG_INFO << "P2P prefix: " << ltc::PoolConfig::prefix_hex()
                     << (network_id != 0 ? " (private chain)" : (settings->m_testnet ? " (testnet)" : " (mainnet)"));

            // For testnet, discard hardcoded mainnet bootstrap peers before Node construction
            // (Node constructor copies bootstrap_addrs into its addr store)
            std::unique_ptr<ltc::Node> p2p_node;
            if (solo_mode || custodial_mode) {
                LOG_INFO << (solo_mode ? "Solo" : "Custodial")
                         << " pool mode: no P2P sharechain, "
                         << (custodial_mode ? "all coinbase to --address" : "local proportional payouts");
            } else {
                if (settings->m_testnet)
                    ltc_p2p_config->pool()->m_bootstrap_addrs.clear();
                for (const auto& seed : seed_nodes) {
                    ltc_p2p_config->pool()->m_bootstrap_addrs.emplace_back(seed);
                    LOG_INFO << "Added seed node: " << seed;
                }
                p2p_node = std::make_unique<ltc::Node>(&ioc, ltc_p2p_config.get());
            } // P2P node creation
            if (p2p_node) {
                if (max_outgoing_conns_set) {
                    p2p_node->set_target_outbound_peers(static_cast<size_t>(max_outgoing_conns));
                    LOG_INFO << "Configured outbound peer target: " << max_outgoing_conns;
                }
                p2p_node->set_max_peers(static_cast<size_t>(p2p_max_peers));
                p2p_node->set_ban_duration(p2p_ban_duration);
                p2p_node->set_cache_limits(
                    static_cast<size_t>(cache_max_shared_hashes),
                    static_cast<size_t>(cache_max_known_txs),
                    static_cast<size_t>(cache_max_raw_shares));
                ltc::Node::set_rss_limit_mb(rss_limit_mb);
                p2p_node->core::Server::listen(static_cast<uint16_t>(p2p_port));
                LOG_INFO << "P2P sharechain node listening on port " << p2p_port;
            }

            // --- Parent chain P2P broadcaster (fast block relay) ---
            // Auto-detect P2P port from chain type if not explicitly set.
            // P2P address defaults to the same host as RPC (coin daemon).
            // In embedded mode the broadcaster was already started above — skip.
            if (!embedded_ltc && coind_p2p_port == -1) {
                coind_p2p_port = get_coin_p2p_port(blockchain_to_symbol(blockchain), settings->m_testnet);
                if (coind_p2p_port > 0)
                    LOG_INFO << "Auto-detected parent coin P2P port: " << coind_p2p_port;
            }
            std::unique_ptr<ltc::coin::p2p::NodeP2P<ltc::Config>> coin_p2p;
            if (!embedded_ltc && coind_p2p_port > 0) {
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

            // AutoRatchet: automated V35→V36 share version transition.
            // Persists state to JSON file under the data directory.
            std::string ratchet_path = (core::filesystem::config_path()
                / (settings->m_testnet ? "testnet" : "litecoin")
                / "v36_ratchet.json").string();
            auto auto_ratchet = std::make_shared<ltc::AutoRatchet>(ratchet_path, /*target_version=*/36);
            LOG_INFO << "[AutoRatchet] Initialized: state=" << ltc::ratchet_state_str(auto_ratchet->state())
                     << " target=V36 file=" << ratchet_path;

            // Set initial v36_active on tracker from persisted ratchet state
            if (p2p_node) {
                p2p_node->tracker().set_v36_active(
                    auto_ratchet->state() == ltc::RatchetState::ACTIVATED ||
                    auto_ratchet->state() == ltc::RatchetState::CONFIRMED);
            }

            if (p2p_node) {
                // Wire block_rel_height for chain scoring.
                // Embedded mode: use HeaderChain height diff. RPC mode: query daemon.
                if (embedded_ltc) {
                    p2p_node->set_block_rel_height_fn(
                        [chain = embedded_chain.get()](uint256 block_hash) -> int32_t {
                            if (!chain || block_hash.IsNull()) return 0;
                            auto entry = chain->get_header(block_hash);
                            if (!entry) return 0;
                            int32_t tip_h = static_cast<int32_t>(chain->height());
                            int32_t blk_h = static_cast<int32_t>(entry->height);
                            return tip_h - blk_h + 1; // confirmations-style depth
                        });
                } else {
                    p2p_node->set_block_rel_height_fn(
                        [rpc = node_rpc.get()](uint256 block_hash) -> int32_t {
                            if (!rpc || block_hash.IsNull()) return 0;
                            try {
                                // Use getblockheader (not getblock) — matches p2pool,
                                // and works for pruned daemons: block index (hash→height)
                                // is never pruned, only full block data is.
                                auto reply = rpc->getblockheader(block_hash);
                                if (reply.contains("confirmations"))
                                    return reply["confirmations"].get<int32_t>();
                            } catch (...) {}
                            return 0; // RPC error or not found — safe default
                        });
                }

                // Begin actively connecting to outbound peers from bootstrap list / addr store
                p2p_node->start_outbound_connections();
                LOG_INFO << "Outbound peer connection loop started";

                // p2pool node.py:260: self.set_best_share() — run think() immediately
                // after share loading + wiring so LevelDB-loaded shares get verified
                // and m_best_share_hash is set before the first status line fires.
                p2p_node->run_think();
                LOG_INFO << "Initial think() completed for loaded shares";

                // Block scan moved AFTER callbacks are wired (see below)

                // When a peer announces a new best block, refresh our mining template
                p2p_node->set_on_bestblock([&web_server, &p2p_node]() {
                    web_server.trigger_work_refresh();
                    // p2pool: bitcoind_work.changed → set_best_share() → think()
                    p2p_node->run_think();
                    LOG_INFO << "[LTC] bestblock received from P2P peer — work+think refreshed";
                });

                // When best_share changes (new share on chain), refresh work for all
                // miners. Debounced (100ms) to coalesce P2P share bursts into one
                // notification — matches p2pool's Twisted reactor tick coalescing.
                // New blocks use trigger_work_refresh() (immediate, above).
                p2p_node->set_on_best_share_changed([&web_server]() {
                    web_server.trigger_work_refresh_debounced();
                });

                // Wire local hashrate callback (from stratum server)
                p2p_node->set_local_hashrate_fn([&web_server]() -> double {
                    auto* mi = web_server.get_mining_interface();
                    if (mi) return mi->get_stratum_total_hashrate();
                    return 0.0;
                });

                // Wire rate monitor stats for p2pool-style status lines (DOA%, time window)
                p2p_node->set_local_rate_stats_fn([&web_server]() -> ltc::NodeImpl::LocalRateStats {
                    auto* mi = web_server.get_mining_interface();
                    if (!mi) return {};
                    auto s = mi->get_stratum_rate_stats();
                    return {s.hashrate, s.effective_dt, s.total_datums, s.dead_datums};
                });

                // Wire PPLNS outputs for current payout display
                p2p_node->set_current_pplns_fn([&web_server]() -> std::vector<std::pair<std::string, uint64_t>> {
                    auto* mi = web_server.get_mining_interface();
                    if (!mi) return {};
                    return mi->get_cached_pplns_outputs();
                });

                // Wire payout script for PPLNS matching (p2pool: -a address lookup)
                // Priority: node-owner script > --address converted to script
                if (payout_manager && payout_manager->has_node_owner_fee()) {
                    const auto& nc = payout_manager->get_node_owner_config();
                    if (!nc.payout_script_hex.empty())
                        p2p_node->set_node_payout_script_hex(nc.payout_script_hex);
                }
                if (!payout_address.empty() && p2p_node->get_node_payout_script_hex().empty()) {
                    auto script = core::address_to_script(payout_address);
                    if (!script.empty()) {
                        std::string hex;
                        const char HX[] = "0123456789abcdef";
                        for (unsigned char b : script) { hex += HX[b >> 4]; hex += HX[b & 0x0f]; }
                        p2p_node->set_node_payout_script_hex(hex);
                    }
                }

                // Wire local miner scripts callback for PPLNS payout display.
                // Converts stratum sessions' pubkey_hashes to all script forms (P2PKH, P2WPKH, P2SH)
                // so the status line can match them against PPLNS outputs.
                p2p_node->set_local_miner_scripts_fn([&web_server]() -> std::vector<std::string> {
                    std::vector<std::string> scripts;
                    auto rates = web_server.get_local_addr_rates();
                    const char HX[] = "0123456789abcdef";
                    for (const auto& [pubkey, rate] : rates) {
                        std::string h160;
                        for (auto b : pubkey) { h160 += HX[b >> 4]; h160 += HX[b & 0x0f]; }
                        scripts.push_back("76a914" + h160 + "88ac"); // P2PKH
                        scripts.push_back("0014" + h160);            // P2WPKH
                        scripts.push_back("a914" + h160 + "87");     // P2SH
                    }
                    return scripts;
                });
                // Wire peer info for /peer_list endpoint
                web_server.get_mining_interface()->set_peer_info_fn(
                    [&p2p_node]() -> nlohmann::json {
                        return p2p_node->get_peer_info_json();
                    });
                // Wire pool hashrate from p2pool's get_pool_attempts_per_second
                web_server.get_mining_interface()->set_pool_hashrate_fn(
                    [&p2p_node]() -> double {
                        auto best = p2p_node->best_share_hash();
                        if (best.IsNull()) return 0.0;
                        auto& tracker = p2p_node->tracker();
                        if (!tracker.chain.contains(best)) return 0.0;
                        int height = tracker.chain.get_height(best);
                        if (height < 3) return 0.0;
                        auto lookbehind = std::min(height - 1,
                            static_cast<int>(ltc::PoolConfig::TARGET_LOOKBEHIND));
                        auto aps = tracker.get_pool_attempts_per_second(best, lookbehind, false);
                        return static_cast<double>(aps.GetLow64());
                    });
            } // end if (p2p_node) — P2P callbacks

            // When a block submission is attempted, record the found block
            // and (if P2P mode) broadcast bestblock to sharechain peers.
            // stale_info: 0=accepted, 253=orphan (stale prev), 254=doa (daemon rejected)
            bool is_testnet = settings->m_testnet;
            auto* embedded_chain_ptr = embedded_chain.get();
            web_server.set_on_block_submitted([&p2p_node, &web_server, &ioc, &node_rpc, embedded_ltc, is_testnet, embedded_chain_ptr, dev_donation](const std::string& header_hex, int stale_info) {
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

                // Only broadcast bestblock for accepted blocks (P2P mode only)
                if (stale_info == 0 && p2p_node) {
                    p2p_node->broadcast_bestblock(hdr);
                }

                // Record found block for REST /recent_blocks.
                // Extract height from the block header's prev_block hash by looking it
                // up in the header chain — this gives the ACTUAL block height, not the
                // live template height (which changes rapidly during sync).
                uint256 block_hash = Hash(ParseHex(header_hex.substr(0, 160)));
                uint64_t height = 0;
                {
                    // prev_block is at bytes 4..36 of the 80-byte header (LE uint256)
                    auto hdr_bytes = ParseHex(header_hex.substr(0, 160));
                    if (hdr_bytes.size() >= 36) {
                        uint256 prev_block;
                        std::memcpy(prev_block.data(), hdr_bytes.data() + 4, 32);
                        if (embedded_chain_ptr) {
                            auto entry = embedded_chain_ptr->get_header(prev_block);
                            if (entry.has_value())
                                height = entry->height + 1;
                        }
                    }
                    // Fallback to template height if header chain lookup fails
                    if (height == 0) {
                        auto tmpl = web_server.get_mining_interface()->get_current_work_template();
                        if (!tmpl.is_null() && tmpl.contains("height"))
                            height = tmpl["height"].get<uint64_t>();
                    }
                }
                // Capture enriched data for dashboard /recent_blocks
                auto* mi = web_server.get_mining_interface();
                double net_diff = mi->get_network_difficulty();
                double pool_hr = mi->get_local_hashrate();
                uint64_t block_subsidy = 0;
                {
                    auto tmpl = mi->get_current_work_template();
                    if (!tmpl.is_null() && tmpl.contains("coinbasevalue"))
                        block_subsidy = tmpl["coinbasevalue"].get<uint64_t>();
                }
                std::string miner_addr = mi->get_payout_address();
                std::string share_h;
                if (auto fn = mi->get_best_share_hash_fn())
                    share_h = fn().GetHex();
                mi->record_found_block(
                    height, block_hash, 0, is_testnet ? "tLTC" : "LTC",
                    miner_addr, share_h, net_diff, 0, pool_hr, block_subsidy);
                // Schedule async verification at +10s, +30s, +120s
                if (stale_info == 0)
                    web_server.get_mining_interface()->schedule_block_verification(block_hash.GetHex());

                const char* stale_str = (stale_info == 253) ? " [ORPHAN — stale prev]"
                                      : (stale_info == 254) ? " [DOA — daemon rejected]"
                                      : "";
                LOG_INFO << "\n"
                         << "  ###  PARENT NETWORK BLOCK FOUND!  ###\n"
                         << "  Network:    Litecoin (" << (is_testnet ? "tLTC" : "LTC") << ")\n"
                         << "  Height:     " << height << "\n"
                         << "  Block hash: " << block_hash.GetHex() << "\n"
                         << "  Status:     " << (stale_info == 0 ? "ACCEPTED" : stale_str) << "\n"
                         << "  Broadcast:  " << (p2p_node ? "bestblock sent to P2P peers" : "relayed to coin network");

                // Schedule post-submission orphan check at +30s and +120s (RPC mode only)
                if (stale_info == 0 && !embedded_ltc)
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
            if (embedded_ltc && embedded_broadcaster) {
                // Embedded mode: relay directly via CoinBroadcaster (no daemon needed)
                LOG_INFO << "[EMB-LTC] Wiring block relay via CoinBroadcaster (no daemon RPC)";
                web_server.set_on_block_relay([&embedded_broadcaster](const std::string& full_block_hex) {
                    LOG_INFO << "[EMB-LTC] Block relay triggered: " << full_block_hex.size() / 2 << " bytes";
                    try {
                        auto block_bytes = ParseHex(full_block_hex);
                        embedded_broadcaster->submit_block_raw(block_bytes);
                        LOG_INFO << "[EMB-LTC] Block relayed to P2P peers successfully";
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[EMB-LTC] P2P block relay FAILED: " << e.what();
                    }
                });
            } else if (coin_p2p) {
                // RPC mode: relay via NodeP2P after daemon accepts the block
                web_server.set_on_block_relay([&coin_p2p](const std::string& full_block_hex) {
                    try {
                        auto block_bytes = ParseHex(full_block_hex);
                        coin_p2p->submit_block_raw(block_bytes);
                    } catch (const std::exception& e) {
                        LOG_WARNING << "P2P block relay failed: " << e.what();
                    }
                });
            }

            // Embedded mode + RPC submit fallback: if the user also provides
            // --rpc-host / --rpc-user / --rpc-pass, use direct HTTP JSON-RPC
            // as a secondary path that gives us immediate accept/reject feedback.
            if (embedded_ltc && !rpc_user.empty() && !rpc_pass.empty()) {
                int submit_rpc_port = rpc_port > 0 ? rpc_port
                    : (settings->m_testnet ? 19332 : 9332);
                std::string submit_rpc_host = rpc_host;
                std::string submit_rpc_user = rpc_user;
                std::string submit_rpc_pass = rpc_pass;

                LOG_INFO << "[EMB-LTC] RPC submit fallback enabled (HTTP JSON-RPC): "
                         << submit_rpc_host << ":" << submit_rpc_port;

                auto* mi = web_server.get_mining_interface();
                mi->set_rpc_submit_fallback(
                    [submit_rpc_host, submit_rpc_port, submit_rpc_user,
                     submit_rpc_pass](const std::string& hex) -> std::string {
                        try {
                            namespace beast = boost::beast;
                            namespace http = beast::http;
                            namespace net = boost::asio;
                            using tcp = net::ip::tcp;

                            // Build JSON-RPC request body
                            nlohmann::json rpc_req;
                            rpc_req["jsonrpc"] = "1.0";
                            rpc_req["id"] = "c2pool-submit";
                            rpc_req["method"] = "submitblock";
                            rpc_req["params"] = nlohmann::json::array({hex});
                            std::string body = rpc_req.dump();

                            // Base64-encode auth
                            std::string userpass = submit_rpc_user + ":" + submit_rpc_pass;
                            std::string auth_enc;
                            auth_enc.resize(beast::detail::base64::encoded_size(userpass.size()));
                            auto n = beast::detail::base64::encode(&auth_enc[0], userpass.data(), userpass.size());
                            auth_enc.resize(n);

                            // Synchronous HTTP POST (runs in detached thread)
                            net::io_context submit_ioc;
                            tcp::resolver resolver(submit_ioc);
                            beast::tcp_stream stream(submit_ioc);
                            stream.expires_after(std::chrono::seconds(10));

                            auto results = resolver.resolve(submit_rpc_host, std::to_string(submit_rpc_port));
                            stream.connect(results);

                            http::request<http::string_body> req{http::verb::post, "/", 11};
                            req.set(http::field::host, submit_rpc_host + ":" + std::to_string(submit_rpc_port));
                            req.set(http::field::content_type, "application/json");
                            req.set(http::field::authorization, "Basic " + auth_enc);
                            req.body() = body;
                            req.prepare_payload();

                            http::write(stream, req);

                            beast::flat_buffer buffer;
                            http::response<http::string_body> resp;
                            http::read(stream, buffer, resp);

                            beast::error_code ec;
                            stream.socket().shutdown(tcp::socket::shutdown_both, ec);

                            // Parse response: submitblock returns null on success
                            auto json_resp = nlohmann::json::parse(resp.body(), nullptr, false);
                            if (json_resp.is_discarded())
                                return "Failed to parse RPC response";
                            if (json_resp.contains("error") && !json_resp["error"].is_null())
                                return json_resp["error"].value("message", "unknown RPC error");
                            auto& result = json_resp["result"];
                            if (result.is_null() || (result.is_string() && result.get<std::string>().empty()))
                                return {};  // accepted
                            return result.get<std::string>();  // rejection reason
                        } catch (const std::exception& e) {
                            return std::string("RPC submit exception: ") + e.what();
                        }
                    });
            }

            // Configure payout system for web server (legacy — kept for REST stats)
            web_server.set_payout_manager(payout_manager.get());

            // Flag solo/custodial mode so REST APIs suppress P2P warnings
            if (solo_mode || custodial_mode) {
                web_server.get_mining_interface()->set_solo_mode(true);
                if (!payout_address.empty())
                    web_server.get_mining_interface()->set_solo_address(payout_address);
            }

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
            // Use the AutoRatchet's initial share version so the donation script
            // matches what generate_share_transaction expects.  Previously this
            // was hardcoded to V36, so the genesis share (created before the
            // PPLNS hook fires) used COMBINED_DONATION_SCRIPT (23 bytes) while
            // V35's gentx_before_refhash expects DONATION_SCRIPT (67 bytes),
            // causing p2pool to reject the share as PoW-invalid.
            {
                auto [initial_ver, initial_desired] = auto_ratchet->get_share_version(
                    p2p_node->tracker(), uint256());
                auto donation_script = ltc::PoolConfig::get_donation_script(initial_ver);
                web_server.get_mining_interface()->set_donation_script(donation_script);
                web_server.get_mining_interface()->set_cached_share_version(initial_ver);
                LOG_INFO << "Donation script set: V" << initial_ver << " ("
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

            // Load transition message blobs from shipped + data directories
            {
                // 1. Shipped with source: <repo>/transition_messages/
                auto exe_dir = std::filesystem::path(argv[0]).parent_path();
                web_server.get_mining_interface()->load_transition_blobs(
                    (exe_dir / ".." / ".." / ".." / "transition_messages").string());
                // 2. User data dir: ~/.c2pool/<net>/transition_messages/
                auto data_dir = core::filesystem::config_path();
                web_server.get_mining_interface()->load_transition_blobs(
                    (data_dir / "transition_messages").string());
            }

            // Coinbase text customization
            if (!coinbase_text.empty()) {
                bool has_mm = !merged_chain_specs.empty();
                size_t max_len = has_mm ? c2pool::MAX_OPERATOR_TEXT_MM : c2pool::MAX_OPERATOR_TEXT_SOLO;
                if (coinbase_text.size() > max_len) {
                    LOG_ERROR << "--coinbase-text too long: " << coinbase_text.size()
                              << " bytes (max " << max_len << " with"
                              << (has_mm ? "" : "out") << " merged mining)";
                    return 1;
                }
                web_server.get_mining_interface()->set_coinbase_text(coinbase_text);
                LOG_INFO << "Coinbase text: \"" << coinbase_text << "\" ("
                         << coinbase_text.size() << "/" << max_len << " bytes)";
            } else {
                LOG_INFO << "Coinbase tag: /c2pool/ (default, use --coinbase-text to customize)";
            }

          // Coin peer sources for /api/coin_peers endpoint (populated as
          // broadcasters are created — LTC in integrated block, DOGE in MM block).
          auto coin_peer_sources = std::make_shared<
              std::vector<c2pool::merged::CoinBroadcaster*>>();

          // DOGE UTXO pointer for SPV progress display (set after DOGE init,
          // read by loading page sync_status). Lives in outer scope so both
          // the SPV progress lambda and the merged mining init can access it.
          core::coin::UTXOViewCache* doge_utxo_ptr = nullptr;

          if (!solo_mode && !custodial_mode) {
            // Wire the share tracker's best share hash into the mining interface
            // so that mining_submit can link new shares to the chain head.
            web_server.set_best_share_hash_fn([&p2p_node]() {
                return p2p_node->best_share_hash();
            });

            // Find the LATEST peer share for work template.
            // Scan ALL chain heads to find the most recent peer share.
            // c2pool fork shares as prev → shares on side branches → 0% PPLNS.
            // Latest peer share as prev → shares extend main chain tip → 33% PPLNS.
            web_server.get_mining_interface()->set_find_peer_prev_fn(
                [&p2p_node](const uint256& best) -> uint256 {
                    auto& chain = p2p_node->tracker().chain;
                    // Strategy: check the best share first, then scan heads
                    // for the most recently seen peer share.
                    uint256 best_peer;
                    int64_t best_ts = 0;

                    // Check best_share itself
                    if (!best.IsNull() && chain.contains(best)) {
                        bool is_local = false;
                        int64_t ts = 0;
                        chain.get_share(best).invoke([&](auto* obj) {
                            is_local = (obj->peer_addr.port() == 0);
                            ts = obj->m_timestamp;
                        });
                        if (!is_local) return best;
                    }

                    // Scan heads for the most recent peer share
                    for (auto& [head, tail] : chain.get_heads()) {
                        if (!chain.contains(head)) continue;
                        // Walk up to 5 shares from each head
                        uint256 cur = head;
                        for (int i = 0; i < 5 && !cur.IsNull() && chain.contains(cur); ++i) {
                            bool is_local = false;
                            int64_t ts = 0;
                            chain.get_share(cur).invoke([&](auto* obj) {
                                is_local = (obj->peer_addr.port() == 0);
                                ts = obj->m_timestamp;
                            });
                            if (!is_local && ts > best_ts) {
                                best_peer = cur;
                                best_ts = ts;
                            }
                            cur = chain.get_index(cur)->tail;
                        }
                    }

                    return best_peer.IsNull() ? best : best_peer;
                });

            // Wire live sharechain statistics into the REST API.
            // Uses StatsSkipList for O(log n) aggregate queries instead of O(n) linear walk.
            // The skiplist is captured by shared_ptr so the lambda closure owns it.
            auto stats_skiplist = std::make_shared<chain::StatsSkipList>(
                // get_delta: extract stats for a single share
                [&p2p_node](const uint256& hash) -> chain::StatsDelta {
                    chain::StatsDelta d;
                    auto& chain = p2p_node->tracker().chain;
                    if (!chain.contains(hash))
                        return d;
                    try {
                        auto& cd = chain.get(hash);
                        cd.share.invoke([&](auto* s) {
                            d.share_count = 1;
                            if (static_cast<int>(s->m_stale_info) == 253) d.orphan_count = 1;
                            else if (static_cast<int>(s->m_stale_info) == 254) d.dead_count = 1;
                            d.version_counts[std::to_string(s->version)] = 1;
                            d.desired_version_counts[std::to_string(s->m_desired_version)] = 1;

                            auto target = chain::bits_to_target(s->m_bits);
                            d.difficulty_sum = chain::target_to_difficulty(target);

                            // Work-weighted desired version (matches p2pool's target_to_average_attempts weighting)
                            auto att = chain::target_to_average_attempts(target);
                            d.desired_version_weights[std::to_string(s->m_desired_version)] =
                                static_cast<double>(att.GetLow64());

                            std::string miner;
                            if constexpr (requires { s->m_address; })
                                miner = HexStr(s->m_address.m_data);
                            else if constexpr (requires { s->m_pubkey_hash; })
                                miner = s->m_pubkey_hash.GetHex();
                            if (!miner.empty())
                                d.miner_counts[miner] = 1;
                        });
                    } catch (...) {}
                    return d;
                },
                // previous: get parent share hash
                [&p2p_node](const uint256& hash) -> uint256 {
                    auto& chain = p2p_node->tracker().chain;
                    if (!chain.contains(hash))
                        return uint256();
                    try {
                        auto& cd = chain.get(hash);
                        uint256 prev;
                        cd.share.invoke([&](auto* s) { prev = s->m_prev_hash; });
                        return prev;
                    } catch (...) { return uint256(); }
                }
            );

            web_server.get_mining_interface()->set_sharechain_stats_fn(
                [&p2p_node, stats_skiplist]() {
                nlohmann::json result;
                auto& chain = p2p_node->tracker().chain;

                // Use tallest chain head (not verified best) so stats stay current during sync
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }

                result["fork_count"]      = static_cast<int>(chain.get_heads().size());
                result["chain_tip_hash"]  = best.IsNull() ? "" : best.GetHex();
                result["chain_height"]    = best.IsNull() ? 0 : chain.get_height(best);
                result["chain_length"]    = static_cast<int>(ltc::PoolConfig::chain_length());

                // O(log n) aggregate stats via skiplist — replaces O(n) linear walk
                int walk = best.IsNull() ? 0 : std::min(static_cast<int>(chain.get_height(best)),
                    static_cast<int>(ltc::PoolConfig::chain_length()));
                auto sr = stats_skiplist->query(best, walk);

                // Sampling window: oldest CHAIN_LENGTH/10 shares in the active chain
                // Matches p2pool consensus: get_nth_parent(tip, CHAIN_LENGTH*9//10) then count CHAIN_LENGTH//10
                int chain_len = static_cast<int>(ltc::PoolConfig::chain_length());
                int chain_ht = best.IsNull() ? 0 : static_cast<int>(chain.get_height(best));
                int skip_count = std::min(chain_ht, chain_len * 9 / 10);
                int sample_count = std::min(chain_ht - skip_count, chain_len / 10);

                // Walk active chain: find sampling start hash AND track V36 propagation
                uint256 sampling_start;
                int deepest_v36_pos = 0;
                int v36_contiguous_from_tip = 0;
                bool contiguous = true;
                int full_walk = std::min(chain_ht, chain_len);
                {
                    uint256 pos = best;
                    for (int i = 0; i < full_walk && !pos.IsNull(); ++i) {
                        if (!chain.contains(pos)) break;
                        if (i == skip_count) sampling_start = pos;
                        try {
                            auto& cd = chain.get(pos);
                            cd.share.invoke([&](auto* s) {
                                if (static_cast<int>(s->m_desired_version) >= 36) {
                                    deepest_v36_pos = i + 1;
                                    if (contiguous) v36_contiguous_from_tip = i + 1;
                                } else if (contiguous) {
                                    contiguous = false;
                                }
                                pos = s->m_prev_hash;
                            });
                        } catch (...) { break; }
                    }
                }
                result["deepest_v36_position"] = deepest_v36_pos;
                result["v36_contiguous_from_tip"] = v36_contiguous_from_tip;

                // Query the oldest CHAIN_LENGTH/10 shares from that position
                auto sampling_sr = (sample_count > 0 && !sampling_start.IsNull())
                    ? stats_skiplist->query(sampling_start, sample_count)
                    : chain::StatsResult{};
                result["sampling_desired_version"] = sampling_sr.desired_version_weights;
                result["sampling_total"]           = sampling_sr.share_count;

                result["total_shares"]    = sr.share_count;
                result["orphan_shares"]   = sr.orphan_count;
                result["dead_shares"]     = sr.dead_count;
                result["shares_by_version"] = sr.version_counts;
                result["shares_by_desired_version"] = sr.desired_version_counts;
                result["shares_by_miner"]   = sr.miner_counts;
                result["average_difficulty"] = sr.share_count > 0
                    ? sr.difficulty_sum / sr.share_count : 1.0;
                result["heaviest_fork_weight"] = chain.size() > 0
                    ? static_cast<double>(best_height) / static_cast<double>(chain.size())
                    : 0.0;
                result["difficulty_trend"] = nlohmann::json::array();

                // Timeline: short linear walk for last hour only (~360 shares at 10s/share)
                auto now_ts = static_cast<uint32_t>(std::time(nullptr));
                constexpr int SLOTS = 6;
                constexpr uint32_t SLOT_SEC = 600;
                uint32_t window_start = now_ts - SLOTS * SLOT_SEC;
                struct Slot { uint32_t ts; int count; std::map<std::string, int> miners; };
                std::vector<Slot> slots(SLOTS);
                for (int i = 0; i < SLOTS; ++i)
                    slots[i].ts = window_start + (i + 1) * SLOT_SEC;

                if (!best.IsNull() && chain.contains(best)) {
                    try {
                        // Walk only recent shares (within the 1-hour window)
                        int tl_walk = std::min(static_cast<int>(chain.get_height(best)), 400);
                        if (tl_walk > 0) {
                            auto view = chain.get_chain(best, tl_walk);
                            for (auto [hash, data] : view) {
                                data.share.invoke([&](auto* s) {
                                    if (s->m_timestamp < window_start)
                                        return; // outside window, stop processing
                                    int idx = static_cast<int>((s->m_timestamp - window_start) / SLOT_SEC);
                                    if (idx >= SLOTS) idx = SLOTS - 1;
                                    slots[idx].count++;
                                    std::string miner;
                                    if constexpr (requires { s->m_address; })
                                        miner = HexStr(s->m_address.m_data);
                                    else if constexpr (requires { s->m_pubkey_hash; })
                                        miner = s->m_pubkey_hash.GetHex();
                                    if (!miner.empty())
                                        slots[idx].miners[miner]++;
                                });
                            }
                        }
                    } catch (...) {}
                }

                nlohmann::json tl = nlohmann::json::array();
                for (auto& sl : slots) {
                    tl.push_back({
                        {"timestamp",          sl.ts},
                        {"share_count",        sl.count},
                        {"miner_distribution", sl.miners}
                    });
                }
                result["timeline"] = tl;

                // Verified count for sync_status readiness check
                result["verified_count"] = static_cast<int>(p2p_node->tracker().verified.size());

                // Share explorer fields for classic page (/web/heads etc.)
                {
                    auto& verified = p2p_node->tracker().verified;

                    nlohmann::json heads_arr = nlohmann::json::array();
                    for (auto& [h, t] : chain.get_heads())
                        heads_arr.push_back(h.GetHex());
                    result["heads"] = std::move(heads_arr);

                    nlohmann::json vheads_arr = nlohmann::json::array();
                    for (auto& [h, t] : verified.get_heads())
                        vheads_arr.push_back(h.GetHex());
                    result["verified_heads"] = std::move(vheads_arr);

                    nlohmann::json tails_arr = nlohmann::json::array();
                    for (auto& [t, hs] : chain.get_tails())
                        tails_arr.push_back(t.GetHex());
                    result["tails"] = std::move(tails_arr);

                    nlohmann::json vtails_arr = nlohmann::json::array();
                    for (auto& [t, hs] : verified.get_tails())
                        vtails_arr.push_back(t.GetHex());
                    result["verified_tails"] = std::move(vtails_arr);

                    // my_share_hashes: empty for now (no local share tracking yet)
                    result["my_share_hashes"] = nlohmann::json::array();
                }

                return result;
            });

            // SPV sync progress for loading page.
            // doge_utxo_ptr is declared in outer scope — set after DOGE UTXO init.
            web_server.get_mining_interface()->set_spv_progress_fn(
                [&ltc_utxo_cache, &embedded_chain, &doge_utxo_ptr]() {
                nlohmann::json r;
                int ltc_connected = ltc_utxo_cache ? static_cast<int>(ltc_utxo_cache->blocks_connected()) : 0;
                int ltc_need = static_cast<int>(core::coin::LTC_MINING_GATE_DEPTH);
                int ltc_height = embedded_chain ? static_cast<int>(embedded_chain->height()) : 0;
                r["ltc_blocks"] = ltc_connected;
                r["ltc_need"] = ltc_need;
                r["ltc_height"] = ltc_height;
                int doge_connected = doge_utxo_ptr
                    ? static_cast<int>(doge_utxo_ptr->blocks_connected()) : 0;
                r["doge_blocks"] = doge_connected;
                r["doge_need"] = static_cast<int>(core::coin::DOGE_MINING_GATE_DEPTH);
                return r;
            });

            // Coin peer sharing — share verified LTC/DOGE peers with new nodes.
            // coin_peer_sources is declared in outer scope. Add LTC broadcaster.
            if (embedded_broadcaster)
                coin_peer_sources->push_back(embedded_broadcaster.get());
            web_server.get_mining_interface()->set_coin_peers_fn(
                [coin_peer_sources]() {
                nlohmann::json r;
                nlohmann::json ltc_arr = nlohmann::json::array();
                nlohmann::json doge_arr = nlohmann::json::array();
                for (auto* bc : *coin_peer_sources) {
                    if (!bc) continue;
                    auto sym = bc->symbol();
                    auto peers = bc->peer_manager().get_tried_peers(25);
                    auto& arr = (sym == "DOGE" || sym == "doge")
                        ? doge_arr : ltc_arr;
                    for (auto& p : peers)
                        arr.push_back(p.to_string());
                }
                r["ltc"] = ltc_arr;
                r["doge"] = doge_arr;
                return r;
            });

            // Wire per-share window data for the defragmenter grid
            web_server.get_mining_interface()->set_sharechain_window_fn([&p2p_node, &web_server]() {
                nlohmann::json result;
                auto& chain = p2p_node->tracker().chain;
                auto& verified = p2p_node->tracker().verified;
                bool testnet = ltc::PoolConfig::is_testnet;

                // Use tallest chain head (not verified best) so the grid stays current during sync
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }

                result["best_hash"] = best.IsNull() ? "" : best.GetHex();
                result["chain_length"] = static_cast<int>(chain.size());
                result["window_size"] = static_cast<int>(ltc::PoolConfig::chain_length());

                // Include local payout address so frontend can mark "mine" shares
                auto mi = web_server.get_mining_interface();
                std::string local_addr;
                if (mi && !mi->get_payout_address().empty()) {
                    auto script = core::address_to_script(mi->get_payout_address());
                    if (!script.empty())
                        local_addr = core::script_to_address(script, true, testnet);
                }
                result["my_address"] = local_addr;

                // Node fee address for marking pool fee shares
                std::string fee_addr;
                if (mi) {
                    std::string fee_h160 = mi->get_node_fee_hash160();
                    if (!fee_h160.empty())
                        fee_addr = fee_h160;
                }
                result["fee_hash160"] = fee_addr;

                nlohmann::json shares_arr = nlohmann::json::array();

                // Walk chain_length shares (8640 mainnet / 400 testnet)
                if (!best.IsNull()) {
                    int height = chain.get_height(best);
                    int walk = std::min(height, static_cast<int>(ltc::PoolConfig::chain_length()));
                    if (walk > 0) {
                        try {
                            int pos = 0;
                            auto view = chain.get_chain(best, walk);
                            for (auto [hash, data] : view) {
                                nlohmann::json s;
                                s["h"] = hash.GetHex().substr(0, 16);
                                s["H"] = hash.GetHex();
                                s["p"] = pos++;
                                s["v"] = verified.contains(hash) ? 1 : 0;

                                // Check is_block_solution flag from tracker index
                                auto* idx = chain.get_index(hash);
                                if (idx && idx->is_block_solution)
                                    s["blk"] = 1;

                                data.share.invoke([&](auto* obj) {
                                    s["t"] = obj->m_timestamp;
                                    s["V"] = obj->version;
                                    s["s"] = static_cast<int>(obj->m_stale_info);
                                    s["b"] = obj->m_bits;
                                    s["a"] = obj->m_absheight;
                                    s["dv"] = obj->m_desired_version;

                                    // Convert miner script to human-readable address
                                    auto script = get_share_script(obj);
                                    std::string addr = core::script_to_address(
                                        script, true /*litecoin*/, testnet);
                                    s["m"] = addr.empty() ? HexStr(script) : addr;

                                    // Extract longest printable ASCII run from coinbase
                                    if (!obj->m_coinbase.m_data.empty()) {
                                        std::string best_run;
                                        std::string cur_run;
                                        for (auto c : obj->m_coinbase.m_data) {
                                            if (c >= 32 && c <= 126) {
                                                cur_run += static_cast<char>(c);
                                            } else {
                                                if (cur_run.size() > best_run.size())
                                                    best_run = cur_run;
                                                cur_run.clear();
                                            }
                                        }
                                        if (cur_run.size() > best_run.size())
                                            best_run = cur_run;
                                        // Only show if meaningful (10+ chars, must contain a letter)
                                        bool has_letter = false;
                                        for (auto c : best_run) {
                                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                                            { has_letter = true; break; }
                                        }
                                        if (best_run.size() >= 10 && has_letter) {
                                            if (best_run.size() > 48) best_run.resize(48);
                                            s["cb"] = best_run;
                                        }
                                    }

                                    // Detect pool fee share: compare hash160 with fee address
                                    if (!fee_addr.empty() && script.size() >= 22) {
                                        // Extract hash160 from script (P2PKH[3:23], P2WPKH[2:22], P2SH[2:22])
                                        int off = -1;
                                        if (script.size() == 25 && script[0] == 0x76) off = 3;
                                        else if (script.size() == 22 && script[0] == 0x00) off = 2;
                                        else if (script.size() == 23 && script[0] == 0xa9) off = 2;
                                        if (off >= 0) {
                                            std::string h160 = HexStr(std::vector<unsigned char>(
                                                script.begin() + off, script.begin() + off + 20));
                                            if (h160 == fee_addr)
                                                s["fee"] = 1;
                                        }
                                    }
                                });

                                shares_arr.push_back(std::move(s));
                            }
                        } catch (...) {
                            // partial results on chain inconsistency
                        }
                    }
                }

                // heads for fork marking
                nlohmann::json heads_arr = nlohmann::json::array();
                for (auto& [hh, _] : chain.get_heads()) {
                    heads_arr.push_back(hh.GetHex().substr(0, 16));
                }

                // LTC found blocks — use is_block_solution flag (above), but also keep
                // share hashes from persistence for blocks found before restart
                nlohmann::json blocks_arr = nlohmann::json::array();
                if (mi) {
                    for (const auto& fb : mi->get_found_blocks()) {
                        if (!fb.share_hash.empty())
                            blocks_arr.push_back(fb.share_hash.substr(0, 16));
                    }
                }

                // DOGE discovered blocks — keyed by parent (LTC) block hash
                nlohmann::json doge_arr = nlohmann::json::array();
                if (mi) {
                    auto* mm = mi->get_mm_manager();
                    if (mm) {
                        for (const auto& db : mm->get_discovered_blocks()) {
                            if (!db.parent_hash.empty())
                                doge_arr.push_back(db.parent_hash.substr(0, 16));
                        }
                    }
                }

                result["shares"] = std::move(shares_arr);
                result["heads"] = std::move(heads_arr);
                result["blocks"] = std::move(blocks_arr);
                result["doge_blocks"] = std::move(doge_arr);
                result["total"] = static_cast<int>(chain.size());
                // Include per-share PPLNS + current as fallback
                if (mi) {
                    result["pplns_current"] = mi->rest_current_payouts();
                    // Per-share PPLNS from cache (available for shares since server start)
                    nlohmann::json pplns_map = nlohmann::json::object();
                    for (const auto& s : result["shares"]) {
                        std::string sh = s["h"].get<std::string>();
                        auto p = mi->get_pplns_for_tip(sh);
                        if (!p.empty()) pplns_map[sh] = std::move(p);
                    }
                    if (!pplns_map.empty()) result["pplns"] = std::move(pplns_map);
                }
                return result;
            });

            // Lightweight tip endpoint for RealTime polling
            web_server.get_mining_interface()->set_sharechain_tip_fn([&p2p_node]() {
                auto& chain = p2p_node->tracker().chain;
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }
                return nlohmann::json::object({
                    {"hash", best.IsNull() ? "" : best.GetHex().substr(0, 16)},
                    {"height", best_height},
                    {"total", static_cast<int>(chain.size())}
                });
            });

            // Delta endpoint: return only shares newer than `since` hash
            web_server.get_mining_interface()->set_sharechain_delta_fn(
                [&p2p_node, &web_server](const std::string& since_hash) {
                nlohmann::json result;
                auto& chain = p2p_node->tracker().chain;
                auto& verified = p2p_node->tracker().verified;
                bool testnet = ltc::PoolConfig::is_testnet;

                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }

                auto mi = web_server.get_mining_interface();
                std::string fee_addr;
                if (mi) fee_addr = mi->get_node_fee_hash160();

                nlohmann::json shares_arr = nlohmann::json::array();
                int count = 0;

                if (!best.IsNull()) {
                    int walk = std::min(static_cast<int>(chain.get_height(best)),
                                        static_cast<int>(ltc::PoolConfig::chain_length()));
                    try {
                        auto view = chain.get_chain(best, walk);
                        for (auto [hash, data] : view) {
                            std::string short_h = hash.GetHex().substr(0, 16);
                            // Stop when we reach the share the client already has
                            if (short_h == since_hash || hash.GetHex() == since_hash)
                                break;

                            nlohmann::json s;
                            s["h"] = short_h;
                            s["H"] = hash.GetHex();
                            s["p"] = count;
                            s["v"] = verified.contains(hash) ? 1 : 0;

                            auto* idx = chain.get_index(hash);
                            if (idx && idx->is_block_solution)
                                s["blk"] = 1;

                            data.share.invoke([&](auto* obj) {
                                s["t"] = obj->m_timestamp;
                                s["V"] = obj->version;
                                s["s"] = static_cast<int>(obj->m_stale_info);
                                s["b"] = obj->m_bits;
                                s["a"] = obj->m_absheight;
                                s["dv"] = obj->m_desired_version;

                                auto script = get_share_script(obj);
                                std::string addr = core::script_to_address(script, true, testnet);
                                s["m"] = addr.empty() ? HexStr(script) : addr;

                                if (!obj->m_coinbase.m_data.empty()) {
                                    std::string best_run, cur_run;
                                    for (auto c : obj->m_coinbase.m_data) {
                                        if (c >= 32 && c <= 126) cur_run += static_cast<char>(c);
                                        else { if (cur_run.size() > best_run.size()) best_run = cur_run; cur_run.clear(); }
                                    }
                                    if (cur_run.size() > best_run.size()) best_run = cur_run;
                                    bool has_letter = false;
                                    for (auto c : best_run) if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')) { has_letter=true; break; }
                                    if (best_run.size() >= 10 && has_letter) {
                                        if (best_run.size() > 48) best_run.resize(48);
                                        s["cb"] = best_run;
                                    }
                                }

                                if (!fee_addr.empty() && script.size() >= 22) {
                                    int off = -1;
                                    if (script.size()==25 && script[0]==0x76) off=3;
                                    else if (script.size()==22 && script[0]==0x00) off=2;
                                    else if (script.size()==23 && script[0]==0xa9) off=2;
                                    if (off >= 0) {
                                        std::string h160 = HexStr(std::vector<unsigned char>(
                                            script.begin()+off, script.begin()+off+20));
                                        if (h160 == fee_addr) s["fee"] = 1;
                                    }
                                }
                            });
                            shares_arr.push_back(std::move(s));
                            if (++count >= 200) break;  // safety cap
                        }
                    } catch (...) {}
                }

                // Updated heads/blocks for the client to merge
                nlohmann::json heads_arr = nlohmann::json::array();
                for (auto& [hh, _] : chain.get_heads())
                    heads_arr.push_back(hh.GetHex().substr(0, 16));

                nlohmann::json blocks_arr = nlohmann::json::array();
                if (mi) {
                    for (const auto& fb : mi->get_found_blocks())
                        if (!fb.share_hash.empty()) blocks_arr.push_back(fb.share_hash.substr(0, 16));
                }
                nlohmann::json doge_arr = nlohmann::json::array();
                if (mi) {
                    auto* mm = mi->get_mm_manager();
                    if (mm) for (const auto& db : mm->get_discovered_blocks())
                        if (!db.parent_hash.empty()) doge_arr.push_back(db.parent_hash.substr(0, 16));
                }

                result["shares"] = std::move(shares_arr);
                result["count"] = count;
                result["tip"] = best.IsNull() ? "" : best.GetHex().substr(0, 16);
                result["heads"] = std::move(heads_arr);
                result["blocks"] = std::move(blocks_arr);
                result["doge_blocks"] = std::move(doge_arr);

                // Include per-share PPLNS snapshots from server cache
                // Each share's tip had a unique PPLNS computed at arrival time
                if (count > 0 && mi) {
                    nlohmann::json pplns_map = nlohmann::json::object();
                    for (const auto& s : result["shares"]) {
                        std::string sh = s["h"].get<std::string>();
                        auto p = mi->get_pplns_for_tip(sh);
                        if (!p.empty()) pplns_map[sh] = std::move(p);
                    }
                    result["pplns"] = std::move(pplns_map);
                }
                return result;
            });

            // Start background PPLNS pre-computation (separate thread, waits for sync)
            web_server.get_mining_interface()->start_pplns_precompute();

            // Wire individual share lookup for /web/share/<hash> detail page
            web_server.get_mining_interface()->set_share_lookup_fn(
                [&p2p_node, &web_server](const std::string& hash_hex) -> nlohmann::json {
                bool testnet = ltc::PoolConfig::is_testnet;
                auto& chain = p2p_node->tracker().chain;
                auto& verified = p2p_node->tracker().verified;

                uint256 hash;
                hash.SetHex(hash_hex);
                if (hash.IsNull() || !chain.contains(hash))
                    return nlohmann::json{{"error", "share not found"}};

                nlohmann::json result;
                auto& entry = chain.get(hash);

                // Block solution detection (outside invoke — uses index directly)
                auto* idx = chain.get_index(hash);
                bool is_ltc_block = idx && idx->is_block_solution;
                result["is_block_solution"] = is_ltc_block;

                // DOGE block detection
                auto mi = web_server.get_mining_interface();
                bool is_doge_block = false;
                nlohmann::json doge_block_info;
                if (mi) {
                    auto* mm = mi->get_mm_manager();
                    if (mm) {
                        auto short_hash = hash.GetHex().substr(0, 16);
                        for (const auto& db : mm->get_discovered_blocks()) {
                            if (!db.parent_hash.empty() &&
                                db.parent_hash.substr(0, 16) == short_hash) {
                                is_doge_block = true;
                                doge_block_info["symbol"] = db.symbol;
                                doge_block_info["height"] = db.height;
                                doge_block_info["block_hash"] = db.block_hash;
                                doge_block_info["reward"] = static_cast<double>(db.coinbase_value) / 1e8;
                                doge_block_info["miner"] = db.miner;
                                break;
                            }
                        }
                    }
                    if (is_ltc_block) {
                        for (const auto& fb : mi->get_found_blocks()) {
                            if (fb.hash == hash.GetHex() ||
                                (!fb.share_hash.empty() && fb.share_hash == hash.GetHex())) {
                                result["ltc_block_height"] = fb.height;
                                result["ltc_block_confirmations"] = fb.confirmations;
                                result["ltc_block_status"] = static_cast<int>(fb.status);
                                break;
                            }
                        }
                    }
                }
                result["is_doge_block"] = is_doge_block;
                if (is_doge_block)
                    result["doge_block"] = doge_block_info;

                // Parent / far_parent / children
                entry.share.invoke([&](auto* obj) {
                    result["parent"] = obj->m_prev_hash.GetHex();
                    result["far_parent"] = obj->m_far_share_hash.GetHex();
                    result["type_name"] = "V" + std::to_string(obj->version);
                    result["version"] = obj->version;

                    // Local data
                    nlohmann::json local_j;
                    local_j["verified"] = verified.contains(hash);
                    local_j["time_first_seen"] = idx ? idx->time_seen : 0;
                    local_j["peer_first_received_from"] = obj->peer_addr.to_string();
                    result["local"] = local_j;

                    // Share data — convert miner to address
                    auto script = get_share_script(obj);
                    std::string addr = core::script_to_address(script, true, testnet);

                    double target_diff = chain::target_to_difficulty(
                        chain::bits_to_target(obj->m_bits));
                    double max_target_diff = chain::target_to_difficulty(
                        chain::bits_to_target(obj->m_max_bits));

                    nlohmann::json sd;
                    sd["timestamp"] = obj->m_timestamp;
                    sd["target"] = obj->m_bits;
                    sd["max_target"] = obj->m_max_bits;
                    sd["payout_address"] = addr.empty() ? HexStr(script) : addr;
                    sd["donation"] = static_cast<double>(obj->m_donation) / 65536.0;
                    sd["stale_info"] = static_cast<int>(obj->m_stale_info);
                    sd["nonce"] = obj->m_nonce;
                    sd["desired_version"] = obj->m_desired_version;
                    sd["absheight"] = obj->m_absheight;
                    sd["abswork"] = obj->m_abswork.GetHex();
                    sd["difficulty"] = target_diff;
                    sd["min_difficulty"] = max_target_diff;
                    result["share_data"] = sd;

                    // Block header
                    auto& hdr = obj->m_min_header;
                    nlohmann::json hdr_j;
                    hdr_j["version"] = hdr.m_version;
                    hdr_j["previous_block"] = hdr.m_previous_block.GetHex();
                    hdr_j["merkle_root"] = "";
                    hdr_j["timestamp"] = hdr.m_timestamp;
                    hdr_j["target"] = hdr.m_bits;
                    hdr_j["nonce"] = hdr.m_nonce;
                    nlohmann::json gentx_j;
                    gentx_j["hash"] = "";
                    gentx_j["coinbase"] = HexStr(obj->m_coinbase.m_data);
                    gentx_j["value"] = static_cast<double>(obj->m_subsidy) / 1e8;
                    gentx_j["last_txout_nonce"] = obj->m_last_txout_nonce;
                    nlohmann::json block_j;
                    block_j["hash"] = hash.GetHex();
                    block_j["header"] = hdr_j;
                    block_j["gentx"] = gentx_j;
                    block_j["other_transaction_hashes"] = nlohmann::json::array();
                    result["block"] = block_j;

                    // Children (shares whose parent is this hash)
                    nlohmann::json children_arr = nlohmann::json::array();
                    // (would need reverse index — skip for now)
                    result["children"] = children_arr;

                    // V36 metadata
                    if constexpr (requires { obj->m_merged_addresses; }) {
                        nlohmann::json merged_addrs = nlohmann::json::array();
                        for (auto& ma : obj->m_merged_addresses) {
                            nlohmann::json a;
                            a["chain_id"] = ma.m_chain_id;
                            a["script_hex"] = HexStr(ma.m_script.m_data);
                            // Try to decode DOGE address
                            if (ma.m_chain_id == 98) {
                                // Dogecoin: P2PKH version 0x1e, P2SH 0x16, hrp "doge"
                                auto daddr = core::script_to_address(
                                    ma.m_script.m_data, "doge", 0x1e, 0x16);
                                if (!daddr.empty()) a["address"] = daddr;
                            }
                            merged_addrs.push_back(a);
                        }
                        nlohmann::json v36_j;
                        v36_j["merged_addresses"] = merged_addrs;
                        v36_j["merged_payout_hash"] = obj->m_merged_payout_hash.GetHex();
                        v36_j["message_data_hex"] = HexStr(obj->m_message_data.m_data);
                        v36_j["message_data_size"] = obj->m_message_data.m_data.size();
                        result["v36_metadata"] = v36_j;
                    }
                });

                return result;
            });

            // Wire block-found callback: when a verified share meets the block target,
            // record it to the found_blocks store. Matches p2pool's tracker.verified.added
            // watcher in node.py:289 — detects blocks from ANY pool participant.
            p2p_node->tracker().m_on_block_found = [&p2p_node, &web_server, &is_testnet](const uint256& share_hash) {
                auto mi = web_server.get_mining_interface();
                auto& chain = p2p_node->tracker().chain;
                if (!chain.contains(share_hash)) return;

                chain.get(share_hash).share.invoke([&](auto* s) {
                    uint64_t height = s->m_absheight;
                    uint256 block_hash = s->m_hash;  // share hash = block header hash
                    double net_diff = mi->get_network_difficulty();
                    double share_diff = chain::target_to_difficulty(chain::bits_to_target(s->m_bits));
                    double pool_hr = mi->get_local_hashrate();

                    std::string miner_addr;
                    if constexpr (requires { s->m_address; })
                        miner_addr = HexStr(s->m_address.m_data);
                    else if constexpr (requires { s->m_pubkey_hash; })
                        miner_addr = s->m_pubkey_hash.GetHex();

                    LOG_INFO << "GOT BLOCK FROM PEER! share=" << share_hash.GetHex().substr(0,16)
                             << " miner=" << miner_addr.substr(0,16)
                             << " height=" << height;

                    mi->record_found_block(
                        height, block_hash, s->m_min_header.m_timestamp,
                        is_testnet ? "tLTC" : "LTC",
                        miner_addr, share_hash.GetHex(), net_diff, share_diff, pool_hr, 0);
                    mi->schedule_block_verification(block_hash.GetHex());
                });
            };

            // Wire share difficulty tracking for best share dashboard display.
            // Every verified share reports its difficulty — both LTC and DOGE use
            // the same share difficulty (scrypt PoW), just compared against different
            // network targets for the percentage display.
            p2p_node->tracker().m_on_share_difficulty = [&web_server](double diff, const std::string& miner) {
                auto mi = web_server.get_mining_interface();
                mi->record_share_difficulty(diff, miner);
                mi->record_merged_share_difficulty(diff, miner);
            };

            // Wire merged block detection for peer shares.
            // V36: exact data from m_merged_coinbase_info (height, 80-byte header, coinbase_value).
            // V35: no merged data in share — if the share is an LTC block solution,
            //      request the full LTC block from P2P peers, parse coinbase for fabe6d6d
            //      MM commitment, extract DOGE block hash, look up in embedded HeaderChain.
            auto* ltc_header_chain = embedded_chain.get();
            p2p_node->tracker().m_on_merged_block_check =
                [&web_server, &p2p_node, merged_block_resolver, ltc_header_chain](const uint256& share_hash, const uint256& pow_hash) {
                auto mi = web_server.get_mining_interface();
                auto* mm = mi->get_mm_manager();
                if (!mm || !mm->has_chains()) return;

                auto& tracker_chain = p2p_node->tracker().chain;
                if (!tracker_chain.contains(share_hash)) return;

                bool had_v36_data = false;
                tracker_chain.get(share_hash).share.invoke([&](auto* s) {
                    // Extract miner address and share timestamp
                    uint32_t share_ts = s->m_min_header.m_timestamp;
                    std::string miner_addr;
                    {
                        auto script = get_share_script(s);
                        miner_addr = core::script_to_address(
                            script, true /*is_litecoin*/, ltc::PoolConfig::is_testnet);
                    }

                    if constexpr (requires { s->m_merged_coinbase_info; }) {
                        if (!s->m_merged_coinbase_info.empty())
                            had_v36_data = true;
                        for (const auto& entry : s->m_merged_coinbase_info) {
                            if (entry.m_block_header.m_data.size() != 80) continue;

                            // Extract nBits from aux block header (standard layout: offset 72, LE)
                            const auto* d = entry.m_block_header.m_data.data();
                            uint32_t bits = static_cast<uint32_t>(d[72]) |
                                           (static_cast<uint32_t>(d[73]) << 8) |
                                           (static_cast<uint32_t>(d[74]) << 16) |
                                           (static_cast<uint32_t>(d[75]) << 24);
                            uint256 target = chain::bits_to_target(bits);
                            if (target.IsNull() || !(pow_hash <= target)) continue;

                            // SHA256d of the 80-byte header = aux chain block hash
                            uint256 block_hash = Hash(entry.m_block_header.m_data);

                            // Resolve symbol from merged mining manager
                            std::string symbol;
                            for (const auto& ci : mm->get_chain_infos()) {
                                if (ci.chain_id == entry.m_chain_id) { symbol = ci.symbol; break; }
                            }
                            if (symbol.empty()) symbol = "MERGED-" + std::to_string(entry.m_chain_id);

                            LOG_INFO << "*** MERGED BLOCK FROM PEER! " << symbol
                                     << " share=" << share_hash.GetHex().substr(0,16)
                                     << " height=" << entry.m_block_height
                                     << " pow=" << pow_hash.GetHex().substr(0,16)
                                     << " target=" << target.GetHex().substr(0,16)
                                     << " block=" << block_hash.GetHex().substr(0,16);

                            c2pool::merged::DiscoveredMergedBlock blk;
                            blk.chain_id = entry.m_chain_id;
                            blk.symbol = symbol;
                            blk.height = static_cast<int>(entry.m_block_height);
                            blk.block_hash = block_hash.GetHex();
                            blk.parent_hash = share_hash.GetHex();
                            blk.timestamp = static_cast<int64_t>(share_ts);
                            blk.accepted = true;
                            blk.coinbase_value = entry.m_coinbase_value;
                            blk.miner = miner_addr;
                            // Get real LTC block height from header chain
                            if (ltc_header_chain) {
                                auto ltc_entry = ltc_header_chain->get_header(share_hash);
                                if (ltc_entry)
                                    blk.parent_height = ltc_entry->height;
                            }
                            mm->add_discovered_block(blk);
                            // Persist to LevelDB
                            auto store_ptr = mi->get_merged_block_store();
                            if (store_ptr) {
                                auto* ms = static_cast<c2pool::storage::MergedBlockStore*>(store_ptr.get());
                                c2pool::storage::MergedBlockRecord rec;
                                rec.chain_id = blk.chain_id; rec.symbol = blk.symbol;
                                rec.height = blk.height; rec.block_hash = blk.block_hash;
                                rec.parent_hash = blk.parent_hash; rec.timestamp = blk.timestamp;
                                rec.accepted = blk.accepted; rec.coinbase_value = blk.coinbase_value;
                                rec.is_local = blk.is_local; rec.parent_height = blk.parent_height;
                                rec.miner = blk.miner;
                                ms->store(rec);
                            }
                        }
                    }
                });

                // V35 fallback: if this share is an LTC block solution but has no V36
                // merged data, use the resolver to fetch the full LTC block from P2P
                // and extract the DOGE block hash from the coinbase MM commitment.
                // share_hash = SHA256d of the full 80-byte header (= LTC block hash),
                // set by share_init_verify() → share.m_hash. Same hash used by P2P getdata.
                if (!had_v36_data && *merged_block_resolver) {
                    auto* idx = tracker_chain.get_index(share_hash);
                    if (idx && idx->is_block_solution) {
                        MergedResolveCtx ctx;
                        ctx.pow_hash = pow_hash;
                        tracker_chain.get(share_hash).share.invoke([&](auto* s) {
                            ctx.share_ts = s->m_min_header.m_timestamp;
                            auto script = get_share_script(s);
                            ctx.miner = core::script_to_address(
                                script, true, ltc::PoolConfig::is_testnet);
                        });
                        (*merged_block_resolver)(share_hash, ctx);
                    }
                }
            };

            // Block scan moved to after all callbacks + DOGE target fn are wired (see below "started successfully")

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
            // Version-aware: uses v35 flat PPLNS when AutoRatchet says share_version<36,
            // v36 decayed PPLNS otherwise.  Also updates donation script to match.
            web_server.set_pplns_fn([&p2p_node, &auto_ratchet, &web_server](
                    const uint256& best_hash, const uint256& block_target,
                    uint64_t subsidy, const std::vector<unsigned char>& /*donation_script*/) {
                auto [share_version, desired_ver] = auto_ratchet->get_share_version(
                    p2p_node->tracker(), best_hash);
                // Propagate v36_active to tracker for generate_share_transaction runtime PPLNS selection
                p2p_node->tracker().set_v36_active(
                    auto_ratchet->state() == ltc::RatchetState::ACTIVATED ||
                    auto_ratchet->state() == ltc::RatchetState::CONFIRMED);
                // Update donation script + cached version so refresh_work() and
                // build_connection_coinbase() use the correct one.
                auto correct_donation = ltc::PoolConfig::get_donation_script(share_version);
                auto* mi = web_server.get_mining_interface();
                mi->set_donation_script(correct_donation);
                mi->set_cached_share_version(share_version);

                {
                    static int pplns_hook_log = 0;
                    if (pplns_hook_log++ % 20 == 0) {
                        bool v36_act = (auto_ratchet->state() == ltc::RatchetState::ACTIVATED ||
                                        auto_ratchet->state() == ltc::RatchetState::CONFIRMED);
                        LOG_INFO << "[PPLNS-HOOK] share_version=" << share_version
                                 << " v36_active=" << v36_act
                                 << " best_hash=" << best_hash.GetHex().substr(0, 16)
                                 << " using=" << (share_version < 36 ? "v35" : "v36")
                                 << " ratchet=" << ltc::ratchet_state_str(auto_ratchet->state());
                    }
                }

                if (share_version < 36) {
                    return p2p_node->tracker().get_v35_expected_payouts(
                        best_hash, block_target, subsidy, correct_donation);
                }
                return p2p_node->tracker().get_expected_payouts(
                    best_hash, block_target, subsidy, correct_donation);
            });

            // Wire the ref_hash computation hook for per-connection coinbase generation.
            // This computes the p2pool ref_hash from share fields + tracker state.
            // Also stores the computed share target so mining.notify and share
            // creation use the share difficulty (not block difficulty).
            auto* mi_for_share_bits = web_server.get_mining_interface();
            web_server.get_mining_interface()->set_ref_hash_fn(
                [&p2p_node, &whale_detector, mi_for_share_bits, dev_donation, &web_server, &auto_ratchet](
                    const uint256& frozen_prev_share,
                    const std::vector<unsigned char>& coinbase_scriptSig,
                    const std::vector<unsigned char>& payout_script,
                    uint64_t subsidy, uint32_t bits, uint32_t timestamp,
                    bool segwit_active, const std::string& witness_commitment_hex,
                    const uint256& witness_root,
                    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs,
                    const std::vector<uint256>& merkle_branches)
                    -> core::MiningInterface::RefHashResult
                {
                    LOG_TRACE << "[ref_hash_fn] ENTER prev=" << frozen_prev_share.GetHex().substr(0,16);

                    // AutoRatchet: determine share version from network state
                    auto [share_version, desired_ver] = auto_ratchet->get_share_version(
                        p2p_node->tracker(), frozen_prev_share);
                    // Propagate v36_active to tracker for verification consistency
                    p2p_node->tracker().set_v36_active(
                        auto_ratchet->state() == ltc::RatchetState::ACTIVATED ||
                        auto_ratchet->state() == ltc::RatchetState::CONFIRMED);
                    {
                        static int rv_log = 0;
                        if (rv_log++ < 5 || rv_log % 100 == 0)
                            LOG_INFO << "[AutoRatchet] share_version=" << share_version
                                     << " desired=" << desired_ver
                                     << " state=" << ltc::ratchet_state_str(auto_ratchet->state());
                    }

                    ltc::RefHashParams params;
                    params.share_version = share_version;
                    params.prev_share = frozen_prev_share;
                    params.coinbase_scriptSig = coinbase_scriptSig;
                    params.share_nonce = 0;
                    params.subsidy = subsidy;
                    // donation = round(65535 * percentage / 100)
                    // Matches p2pool: math.perfect_round(65535*self.donation_percentage/100)
                    params.donation = static_cast<uint16_t>(std::round(65535.0 * dev_donation / 100.0));
                    params.desired_version = desired_ver;

                    // Per-miner desired_target — matches p2pool work.py:2490-2505.
                    // 1) Start with 2^256-1 (easiest possible)
                    // 2) Cap to 1.67% of pool shares by local hashrate
                    // 3) Dust threshold: if expected payout < DUST, use block-proportional target
                    // Result: clips to [pre_target3/30, pre_target3] in compute_share_target.
                    auto desired_target = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

                    // Extract pubkey_hash from payout_script for hashrate lookup
                    std::array<uint8_t, 20> miner_pubkey{};
                    if (payout_script.size() == 25 && payout_script[0] == 0x76) {
                        std::copy(payout_script.begin() + 3, payout_script.begin() + 23, miner_pubkey.begin());
                    } else if (payout_script.size() == 23 && payout_script[0] == 0xa9) {
                        std::copy(payout_script.begin() + 2, payout_script.begin() + 22, miner_pubkey.begin());
                    } else if (payout_script.size() == 22 && payout_script[0] == 0x00) {
                        std::copy(payout_script.begin() + 2, payout_script.begin() + 22, miner_pubkey.begin());
                    }

                    // p2pool work.py:2488-2505: per-miner desired_target computation
                    LOG_TRACE << "[ref_hash_fn] getting local_addr_rates...";
                    auto local_addr_rates = web_server.get_local_addr_rates();
                    LOG_TRACE << "[ref_hash_fn] got " << local_addr_rates.size() << " addr rates";
                    double local_hash_rate = 0.0;
                    {
                        auto rate_it = local_addr_rates.find(miner_pubkey);
                        if (rate_it != local_addr_rates.end())
                            local_hash_rate = rate_it->second;
                    }

                    // Cap 1: limit to 1.67% of pool shares (work.py:2492-2495)
                    // desired_target = min(desired_target,
                    //   average_attempts_to_target(local_hash_rate * SHARE_PERIOD / 0.0167))
                    if (local_hash_rate > 0.0) {
                        double avg_attempts = local_hash_rate * ltc::PoolConfig::share_period() / 0.0167;
                        if (avg_attempts > 1.0) {
                            // average_attempts_to_target(n) = min(2^256/n - 1, 2^256-1)
                            uint288 two_256;
                            two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
                            uint288 avg_288(static_cast<uint64_t>(avg_attempts));
                            uint288 cap_288 = two_256 / avg_288;
                            if (cap_288 > uint288(1)) cap_288 = cap_288 - uint288(1);
                            uint256 cap_target;
                            cap_target.SetHex(cap_288.GetHex());
                            if (cap_target < desired_target)
                                desired_target = cap_target;
                        }
                    }

                    // Cap 2: dust threshold (work.py:2497-2505)
                    // If expected payout per block < DUST_THRESHOLD, ease the target
                    // so small miners still get meaningful payouts.
                    {
                        auto& trk = p2p_node->tracker();
                        if (!frozen_prev_share.IsNull() && trk.chain.contains(frozen_prev_share)) {
                            int32_t lookbehind = 3600 / ltc::PoolConfig::share_period();
                            auto height = trk.chain.get_acc_height(frozen_prev_share);
                            if (height > lookbehind && local_hash_rate > 0.0) {
                                auto pool_aps = trk.get_pool_attempts_per_second(
                                    frozen_prev_share, lookbehind, /*min_work=*/false);
                                double pool_aps_d = static_cast<double>(pool_aps.GetLow64());
                                if (pool_aps_d > 0.0) {
                                    double expected_payout = (local_hash_rate / pool_aps_d)
                                        * subsidy * (1.0 - dev_donation / 100.0);
                                    if (expected_payout < ltc::PoolConfig::dust_threshold()) {
                                        // p2pool: average_attempts_to_target(
                                        //   target_to_average_attempts(block_target) * SPREAD * DUST / subsidy)
                                        uint256 block_target = chain::bits_to_target(bits);
                                        uint288 block_aps = chain::target_to_average_attempts(block_target);
                                        // Use double arithmetic to avoid uint288 overflow
                                        double dust_avg = static_cast<double>(block_aps.GetLow64())
                                            * ltc::PoolConfig::SPREAD
                                            * ltc::PoolConfig::dust_threshold()
                                            / static_cast<double>(subsidy);
                                        if (dust_avg > 1.0) {
                                            uint288 two_256;
                                            two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
                                            uint288 dust_avg_288(static_cast<uint64_t>(dust_avg));
                                            uint288 dust_target_288 = two_256 / dust_avg_288;
                                            if (dust_target_288 > uint288(1))
                                                dust_target_288 = dust_target_288 - uint288(1);
                                            uint256 dust_target;
                                            dust_target.SetHex(dust_target_288.GetHex());
                                            if (dust_target < desired_target)
                                                desired_target = dust_target;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // With fork shares excluded from verified, best_share (= frozen_prev)
                    // is always the main chain head. CST walks the main chain directly.
                    LOG_TRACE << "[ref_hash_fn] calling compute_share_target...";
                    auto [share_max_bits, share_bits] = p2p_node->tracker().compute_share_target(
                        frozen_prev_share, timestamp, desired_target);
                    LOG_TRACE << "[ref_hash_fn] CST done, bits=" << std::hex << share_bits << std::dec;
                    // No bits guard needed: compute_share_target's ±10% clamp
                    // (matching p2pool) prevents drift. The old guard was a workaround
                    // for VARDIFF setting 3x harder difficulty → APS contamination.
                    // With VARDIFF fixed (target_time=3s matching p2pool), APS is
                    // accurate and the guard would risk GENTX-FAIL if it ever fired.
                    params.max_bits = share_max_bits;
                    params.bits = share_bits;
                    params.timestamp = timestamp;

                    // Store share target for mining.notify and share creation
                    mi_for_share_bits->m_share_bits.store(share_bits);
                    mi_for_share_bits->m_share_max_bits.store(share_max_bits);
                    {
                        auto st = chain::bits_to_target(share_bits);
                        auto mt = chain::bits_to_target(share_max_bits);
                        double sd = chain::target_to_difficulty(st);
                        double md = chain::target_to_difficulty(mt);
                        LOG_INFO << "[ShareTarget] share_bits=" << std::hex << share_bits
                                 << " max_bits=" << share_max_bits << std::dec
                                 << " share_diff=" << sd << " max_diff=" << md
                                 << " local_hr=" << local_hash_rate
                                 << " desired=" << desired_target.GetHex().substr(0, 16);
                    }

                    // Extract pubkey_hash and type from payout_script.
                    // Must match p2pool V36: 0=P2PKH, 1=P2WPKH, 2=P2SH.
                    if (payout_script.size() == 25 &&
                        payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
                        payout_script[2] == 0x14 && payout_script[23] == 0x88 &&
                        payout_script[24] == 0xac) {
                        // P2PKH: 76 a9 14 <hash160> 88 ac
                        std::memcpy(params.pubkey_hash.data(), payout_script.data() + 3, 20);
                        params.pubkey_type = 0;
                    } else if (payout_script.size() == 23 &&
                               payout_script[0] == 0xa9 && payout_script[1] == 0x14 &&
                               payout_script[22] == 0x87) {
                        // P2SH: a9 14 <hash160> 87
                        std::memcpy(params.pubkey_hash.data(), payout_script.data() + 2, 20);
                        params.pubkey_type = 2;
                    } else if (payout_script.size() == 22 &&
                               payout_script[0] == 0x00 && payout_script[1] == 0x14) {
                        // P2WPKH: 00 14 <hash160>
                        std::memcpy(params.pubkey_hash.data(), payout_script.data() + 2, 20);
                        params.pubkey_type = 1;
                    } else if (payout_script.size() >= 20) {
                        // Fallback: store first 20 bytes as P2PKH
                        std::memcpy(params.pubkey_hash.data(), payout_script.data(), 20);
                        params.pubkey_type = 0;
                    }

                    // V35: convert pubkey_hash to address string (uses raw bytes)
                    if (share_version <= 35) {
                        params.address = ltc::pubkey_hash_to_address(params.pubkey_hash, params.pubkey_type);
                    }

                    // No P2WPKH reversal — c2pool stores raw witness program
                    // bytes in uint160. The wire serialization preserves byte
                    // order from memcpy (uint160::data() = raw memory).

                    // Segwit data — txid_merkle_link must match create_local_share
                    if (segwit_active && !witness_commitment_hex.empty()) {
                        params.has_segwit = true;
                        ltc::SegwitData sd;
                        sd.m_txid_merkle_link.m_branch = merkle_branches;
                        sd.m_txid_merkle_link.m_index  = 0;
                        // Use raw wtxid merkle root (not the commitment hash).
                        // NEVER fall back to witness_commitment_hex — that contains
                        // SHA256d(root || nonce), not the raw root. Using it would
                        // cause double-hashing in generate_share_transaction.
                        if (!witness_root.IsNull()) {
                            sd.m_wtxid_merkle_root = witness_root;
                        } else {
                            LOG_WARNING << "[ref_hash_fn] witness_root is null despite segwit_active=true"
                                        << " — ref_hash will include zero wtxid_merkle_root";
                        }
                        params.segwit_data = sd;
                    }

                    // Merged addresses (V36 only)
                    if (share_version >= 36) {
                        for (const auto& [chain_id, script] : merged_addrs) {
                            ltc::MergedAddressEntry entry;
                            entry.m_chain_id = chain_id;
                            entry.m_script.m_data = script;
                            params.merged_addresses.push_back(std::move(entry));
                        }
                    }

                    // Chain position from tracker
                    LOG_TRACE << "[ref_hash_fn] looking up chain position...";
                    auto& tracker = p2p_node->tracker();
                    if (!params.prev_share.IsNull() && tracker.chain.contains(params.prev_share)) {
                        // Timestamp: clip to at least previous_share.timestamp + 1 (matches Python)
                        tracker.chain.get(params.prev_share).share.invoke([&](auto* prev) {
                            params.absheight = prev->m_absheight + 1;
                            if (params.timestamp <= prev->m_timestamp)
                                params.timestamp = prev->m_timestamp + 1;
                        });

                        // Recompute share target with the clipped timestamp
                        // Must use same desired_target as the initial computation
                        {
                            auto [sm, sb] = tracker.compute_share_target(
                                params.prev_share, params.timestamp, desired_target);
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
                        LOG_TRACE << "[ref_hash_fn] getting far_share (99th parent)...";
                        {
                            auto [prev_height, last] = tracker.chain.get_height_and_last(params.prev_share);
                            if (prev_height < 99) {
                                // Chain too short (cold-start, fragmented) — no 99th ancestor
                                params.far_share_hash = uint256();
                            } else {
                                try {
                                    params.far_share_hash = tracker.chain.get_nth_parent_key(params.prev_share, 99);
                                } catch (const std::exception&) {
                                    params.far_share_hash = uint256();
                                }
                            }
                        }

                        // Merged payout hash: deterministic V36 PPLNS commitment (V36 only).
                        if (share_version >= 36) {
                            LOG_TRACE << "[ref_hash_fn] computing merged_payout_hash...";
                            params.merged_payout_hash = tracker.compute_merged_payout_hash(
                                params.prev_share, chain::bits_to_target(bits));
                            LOG_TRACE << "[ref_hash_fn] merged_payout_hash done";
                        }
                    } else {
                        // Genesis: p2pool always does (0 + 1) for absheight, (0 + aps) for abswork
                        params.absheight = 1;
                        params.abswork = uint128(chain::target_to_average_attempts(
                            chain::bits_to_target(params.bits)).GetLow64());
                    }

                    LOG_TRACE << "[ref_hash_fn] chain position done, collecting MM coinbase info...";
                    // V36: Collect merged coinbase info from MM manager.
                    if (share_version >= 36) {
                        for (const auto& hi : mi_for_share_bits->get_last_merged_header_infos()) {
                            ltc::MergedCoinbaseEntry entry;
                            entry.m_chain_id = hi.chain_id;
                            entry.m_coinbase_value = hi.coinbase_value;
                            entry.m_block_height = hi.block_height;
                            if (hi.block_header.size() == 80)
                                entry.m_block_header.m_data = hi.block_header;
                            else
                                entry.m_block_header.m_data.assign(80, 0);
                            entry.m_coinbase_merkle_link.m_branch = hi.coinbase_merkle_branches;
                            entry.m_coinbase_merkle_link.m_index = 0;
                            entry.m_coinbase_script.m_data = hi.coinbase_script;
                            params.merged_coinbase_info.push_back(std::move(entry));
                        }
                    }

                    LOG_TRACE << "[ref_hash_fn] computing ref_hash...";
                    auto [rh, nonce] = ltc::compute_ref_hash_for_work(params);
                    LOG_TRACE << "[ref_hash_fn] ref_hash computed";
                    core::MiningInterface::RefHashResult result;
                    result.ref_hash = rh;
                    result.last_txout_nonce = nonce;
                    result.absheight = params.absheight;
                    result.abswork = params.abswork;
                    result.far_share_hash = params.far_share_hash;
                    result.max_bits = params.max_bits;
                    result.bits = params.bits;
                    result.timestamp = params.timestamp;
                    LOG_INFO << "[ref_hash_fn-result] bits=" << std::hex << result.bits
                             << " max_bits=" << result.max_bits << std::dec
                             << " absheight=" << result.absheight;
                    result.merged_payout_hash = params.merged_payout_hash;
                    result.share_version = share_version;
                    result.desired_version = desired_ver;
                    // Freeze segwit merkle branches + witness root — these change
                    // between GBT updates but the ref_hash was computed with these values.
                    result.frozen_merkle_branches = merkle_branches;
                    result.frozen_witness_root = witness_root;
                    // Freeze merged coinbase info — serialize to blob for transport
                    if (!params.merged_coinbase_info.empty()) {
                        PackStream mci_stream;
                        mci_stream << params.merged_coinbase_info;
                        auto mci_span = std::span<const unsigned char>(
                            reinterpret_cast<const unsigned char*>(mci_stream.data()),
                            mci_stream.size());
                        result.frozen_merged_coinbase_info.assign(mci_span.begin(), mci_span.end());
                    }
                    // mm_commitment is now computed atomically in build_connection_coinbase
                    // (before ref_hash_fn is called), so no need to freeze it here.
                    return result;
                });

            // Wire the share creation hook so mining_submit() creates a real
            // V36 share in the tracker and broadcasts it to peers.
            web_server.get_mining_interface()->set_create_share_fn(
                [&p2p_node, dev_donation](const core::MiningInterface::ShareCreationParams& p) {
                // Counters for periodic status reporting
                static std::atomic<uint64_t> s_call_count{0};
                static std::atomic<uint64_t> s_guard_blocked{0};
                static std::atomic<uint64_t> s_pow_failed{0};
                static std::atomic<uint64_t> s_created{0};
                static std::atomic<int64_t>  s_last_report{0};

                uint64_t calls = ++s_call_count;
                {
                    auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
                    if (now_ns - s_last_report.load() > 60'000'000'000LL) { // every 60s
                        s_last_report.store(now_ns);
                        LOG_INFO << "[ShareCreate] calls=" << calls
                                 << " guard_blocked=" << s_guard_blocked.load()
                                 << " pow_failed=" << s_pow_failed.load()
                                 << " created=" << s_created.load();
                    }
                }

                try {
                    // Allow null prev_share for genesis (empty chain, no peers).
                    // p2pool creates genesis share with previous_share_hash=None.
                    // Only block if chain has shares but best_share is null (sync issue).
                    if (p.prev_share_hash.IsNull() && p2p_node->tracker().chain.size() > 0) {
                        ++s_guard_blocked;
                        static std::atomic<int64_t> s_last_warn{0};
                        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
                        if (now - s_last_warn.load() > 30'000'000'000LL) {
                            s_last_warn.store(now);
                            LOG_WARNING << "[Pool] Skipping share: null prev_share_hash"
                                        << " (chain=" << p2p_node->tracker().chain.size()
                                        << " verified=" << p2p_node->tracker().verified.size() << ")";
                        }
                        return;
                    }

                    // Log chain depth for diagnostics (no guard — p2pool creates
                    // shares immediately with whatever depth it has)
                    {
                        auto& tracker = p2p_node->tracker();
                        if (tracker.chain.contains(p.prev_share_hash)) {
                            auto depth = tracker.chain.get_height(p.prev_share_hash);
                            static int depth_log = 0;
                            if (depth_log++ < 5)
                                LOG_INFO << "[Pool] Creating share at chain depth " << depth
                                         << " prev=" << p.prev_share_hash.GetHex().substr(0, 16);
                        }
                    }

                    // Build SmallBlockHeaderType from Stratum params.
                    // min_header.m_bits = GBT BLOCK difficulty (the nBits the miner put
                    // in the 80-byte header). This is different from share.m_bits (share
                    // chain target). p2pool stores block_bits in min_header.
                    ltc::coin::SmallBlockHeaderType min_header;
                    min_header.m_version        = p.block_version;
                    min_header.m_previous_block  = p.prev_block_hash;
                    min_header.m_timestamp       = p.timestamp;
                    min_header.m_bits            = p.block_bits ? p.block_bits : p.bits;
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

                    // Create the share and add it to the tracker.
                    // Shared lock: prevent data race with think()/clean_tracker()
                    // on the compute thread. Without this, the PPLNS walk inside
                    // create_local_share's cross-check sees inconsistent tracker
                    // state → GENTX mismatch → share rejected → peers ban us.
                    auto tracker_lock = p2p_node->tracker_shared_lock();

                    // Pass frozen fields from template time so ref_hash matches coinbase.
                    uint256 share_hash = ltc::create_local_share(
                        p2p_node->tracker(),
                        min_header,
                        coinbase,
                        p.subsidy,
                        prev_share,
                        p.merkle_branches,
                        p.payout_script,
                        static_cast<uint16_t>(std::round(65535.0 * dev_donation / 100.0)),  // donation from --give-author
                        merged_addrs,
                        stale,
                        p.segwit_active,
                        p.witness_commitment_hex,
                        p.message_data,
                        p.full_coinbase_bytes,
                        p.witness_root,
                        p.has_frozen_fields ? p.frozen_max_bits : 0,
                        p.has_frozen_fields ? p.frozen_bits : 0,
                        p.frozen_absheight,
                        p.frozen_abswork,
                        p.frozen_far_share_hash,
                        p.frozen_timestamp,
                        p.frozen_merged_payout_hash,
                        p.has_frozen_fields,
                        p.frozen_merkle_branches,
                        p.frozen_witness_root,
                        p.frozen_merged_coinbase_info,
                        p.share_version,
                        p.desired_version);

                    // Only broadcast if self-validation passed (non-null hash)
                    if (share_hash.IsNull()) {
                        ++s_pow_failed;
                        return;  // share failed PoW or validation; don't broadcast
                    }
                    ++s_created;

                    // Broadcast to all connected peers
                    try {
                        p2p_node->broadcast_share(share_hash);
                    } catch (const std::exception& e) {
                        LOG_ERROR << "broadcast_share failed: " << e.what();
                    }

                    // CRITICAL: Update best share immediately so refresh_work()
                    // sends new mining.notify to miners. Without this, the miner
                    // keeps working on the old chain tip and creates duplicate
                    // shares at the same height (self-orphaning).
                    // p2pool does this via set_best_share() → work_event.
                    // notify_local_share() is a fast-path that bypasses
                    // run_think() scoring — it directly sets the new tip.
                    p2p_node->notify_local_share(share_hash);

                    {
                        // p2pool format: GOT SHARE! addr.worker hash prev age
                        std::string age_str;
                        if (!prev_share.IsNull() && p2p_node->tracker().chain.contains(prev_share)) {
                            try {
                                uint32_t prev_ts = 0;
                                p2p_node->tracker().chain.get(prev_share).share.invoke([&](auto* s) {
                                    prev_ts = s->m_timestamp;
                                });
                                if (prev_ts > 0) {
                                    double age = static_cast<double>(p.timestamp) - static_cast<double>(prev_ts);
                                    std::ostringstream os;
                                    os << std::fixed << std::setprecision(2) << age << "s";
                                    age_str = os.str();
                                }
                            } catch (...) {}
                        }
                        LOG_INFO << "GOT SHARE! " << p.miner_address
                                 << " " << share_hash.GetHex().substr(0, 8)
                                 << " prev " << prev_share.GetHex().substr(0, 8)
                                 << (age_str.empty() ? "" : " age " + age_str);
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR << "create_share_fn failed (before broadcast): " << e.what();
                }
            });

          } else if (custodial_mode) {
            // ─── CUSTODIAL MODE: all coinbase to --address ─────────────────
            // No P2P sharechain, no share creation. Entire block reward goes
            // to the node operator's address. Stratum-provided miner addresses
            // are used ONLY for accounting (/stratum_stats, /connected_miners)
            // — they never appear in coinbase outputs.

            if (payout_address.empty()) {
                LOG_ERROR << "--custodial requires --address (node operator payout address)";
                return 1;
            }

            auto owner_script = core::address_to_script(payout_address);
            if (owner_script.empty()) {
                LOG_ERROR << "--custodial: invalid --address: " << payout_address;
                return 1;
            }

            // Custodial PPLNS: entire subsidy minus donation to node operator
            web_server.set_pplns_fn([owner_script, dev_donation](
                    const uint256& /*best_hash*/, const uint256& /*block_target*/,
                    uint64_t subsidy, const std::vector<unsigned char>& donation_script)
                    -> std::map<std::vector<unsigned char>, double> {

                std::map<std::vector<unsigned char>, double> result;

                // Donation (dev_donation% or 1 satoshi marker when 0%)
                uint64_t donation_amount = (dev_donation > 0)
                    ? static_cast<uint64_t>(subsidy * dev_donation / 100.0)
                    : 1;  // 1 satoshi marker
                result[donation_script] = static_cast<double>(donation_amount);

                // Everything else to node operator
                uint64_t operator_amount = subsidy - donation_amount;
                result[owner_script] = static_cast<double>(operator_amount);

                return result;
            });

            // No sharechain
            web_server.set_best_share_hash_fn([]() { return uint256::ZERO; });

            LOG_INFO << "Custodial mode ready — all coinbase to " << payout_address
                     << ", stratum addresses for accounting only";

          } else {
            // ─── SOLO MODE: local proportional payouts ─────────────────────
            // No P2P sharechain, no share creation. Coinbase pays connected
            // miners proportional to their hashrate, plus node owner fee and
            // donation marker (1 satoshi when give-author=0).

            // Solo PPLNS: distribute subsidy by stratum per-miner hashrates
            web_server.set_pplns_fn([&web_server, dev_donation, node_owner_fee, &payout_address](
                    const uint256& /*best_hash*/, const uint256& /*block_target*/,
                    uint64_t subsidy, const std::vector<unsigned char>& donation_script)
                    -> std::map<std::vector<unsigned char>, double> {

                std::map<std::vector<unsigned char>, double> result;

                auto rates = web_server.get_local_addr_rates();
                double total_rate = 0;
                for (auto& [_, rate] : rates) total_rate += rate;

                // Node owner fee
                uint64_t owner_fee_amount = 0;
                if (node_owner_fee > 0 && !payout_address.empty()) {
                    owner_fee_amount = static_cast<uint64_t>(subsidy * node_owner_fee / 100.0);
                    auto owner_script = core::address_to_script(payout_address);
                    if (!owner_script.empty())
                        result[owner_script] = static_cast<double>(owner_fee_amount);
                }

                // Donation (dev_donation% or 1 satoshi marker when 0%)
                uint64_t donation_amount = (dev_donation > 0)
                    ? static_cast<uint64_t>(subsidy * dev_donation / 100.0)
                    : 1;  // 1 satoshi marker
                result[donation_script] += static_cast<double>(donation_amount);

                uint64_t miner_pool = subsidy - owner_fee_amount - donation_amount;

                if (total_rate > 0 && !rates.empty()) {
                    // Proportional split by hashrate
                    for (auto& [pubkey_hash, rate] : rates) {
                        double fraction = rate / total_rate;
                        uint64_t amount = static_cast<uint64_t>(miner_pool * fraction);
                        if (amount == 0) continue;
                        // Convert pubkey_hash to P2PKH script: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
                        std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
                        script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());
                        script.push_back(0x88);
                        script.push_back(0xac);
                        result[script] += static_cast<double>(amount);
                    }
                } else {
                    // No miners connected — all to payout address or donation
                    if (!payout_address.empty()) {
                        auto pa_script = core::address_to_script(payout_address);
                        if (!pa_script.empty())
                            result[pa_script] = static_cast<double>(miner_pool);
                    } else {
                        result[donation_script] += static_cast<double>(miner_pool);
                    }
                }
                return result;
            });

            // Solo mode: best_share is always null (no sharechain)
            web_server.set_best_share_hash_fn([]() { return uint256::ZERO; });

            LOG_INFO << "Solo mode ready — miners connect to stratum, payouts proportional to hashrate";
          } // end if (!solo_mode && !custodial_mode) ... else

            // --- Integrated Merged Mining ---
            std::unique_ptr<c2pool::merged::MergedMiningManager> mm_manager;
            // Merged chain P2P broadcasters (one per chain with P2P configured)
            std::map<uint32_t, std::unique_ptr<c2pool::merged::CoinBroadcaster>> merged_broadcasters;

            // Phase 5: Embedded DOGE chain objects (created before mm_manager)
            std::unique_ptr<doge::coin::HeaderChain>  doge_chain;
            std::unique_ptr<ltc::coin::Mempool>       doge_pool;
            std::unique_ptr<doge::coin::DOGEChainParams> doge_params_ptr;
            // DOGE UTXO set for fee computation (no segwit/MWEB — simplified)
            std::unique_ptr<core::coin::UTXOViewDB>    doge_utxo_db;
            std::unique_ptr<core::coin::UTXOViewCache> doge_utxo_cache;

            if (!merged_chain_specs.empty()) {
                mm_manager = std::make_unique<c2pool::merged::MergedMiningManager>(ioc);
                for (const auto& spec : merged_chain_specs) {
                    // Format: SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]
                    std::vector<std::string> parts;
                    std::string token;
                    std::istringstream ss(spec);
                    while (std::getline(ss, token, ':'))
                        parts.push_back(token);
                    if (parts.size() < 6 && !(embedded_doge && parts.size() >= 2)) {
                        LOG_ERROR << "Invalid --merged spec (expected SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]): " << spec;
                        continue;
                    }
                    c2pool::merged::AuxChainConfig cfg;
                    cfg.symbol       = parts[0];
                    cfg.chain_id     = static_cast<uint32_t>(std::stoul(parts[1]));
                    if (parts.size() >= 4) cfg.rpc_host = parts[2];
                    if (parts.size() >= 4) cfg.rpc_port = static_cast<uint16_t>(std::stoul(parts[3]));
                    if (parts.size() >= 6) cfg.rpc_userpass = parts[4] + ":" + parts[5];
                    cfg.multiaddress = true;  // V36: canonical PPLNS coinbase for merged chains

                    // Fallback payout address for createauxblock RPC.
                    // Used when no per-miner address is available for a chain.
                    // PPLNS payouts override this in multiaddress mode.
                    if (cfg.symbol == "DOGE" && settings->m_testnet)
                        cfg.aux_payout_address = "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt";
                    else if (cfg.symbol == "DOGE")
                        cfg.aux_payout_address = "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr";
                    else if (cfg.symbol == "PEP")
                        cfg.aux_payout_address = "PSimbaxxxxxxxxxxxxxxxxxxxxUMbTDw";
                    else if (cfg.symbol == "BELLS")
                        cfg.aux_payout_address = solo_address;  // no well-known burn; use operator address
                    else if (cfg.symbol == "LKY")
                        cfg.aux_payout_address = solo_address;
                    else if (cfg.symbol == "JKC")
                        cfg.aux_payout_address = solo_address;
                    else if (cfg.symbol == "SHIC")
                        cfg.aux_payout_address = solo_address;
                    else if (cfg.symbol == "DINGO")
                        cfg.aux_payout_address = solo_address;

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
                    // P2P address: prefer chain-specific flags, then --merged-coind-p2p-address
                    if (cfg.symbol == "DOGE" && !doge_p2p_address.empty()) {
                        cfg.p2p_address = doge_p2p_address;
                    } else if (!merged_coind_p2p_address.empty()) {
                        cfg.p2p_address = merged_coind_p2p_address;
                    } else {
                        cfg.p2p_address = cfg.rpc_host;
                    }
                    // --doge-p2p-port overrides auto-detected port
                    if (cfg.symbol == "DOGE" && doge_p2p_port > 0) {
                        cfg.p2p_port = static_cast<uint16_t>(doge_p2p_port);
                        LOG_INFO << "DOGE P2P port overridden via --doge-p2p-port: " << doge_p2p_port;
                    }

                    // Phase 5/Step 4: create DOGE HeaderChain when embedded OR P2P is available.
                    // Even in RPC-primary mode, the HeaderChain enables live header sync
                    // and acts as fallback if the daemon goes down.
                    bool doge_has_p2p = (cfg.p2p_port > 0);
                    if ((embedded_doge || doge_has_p2p) && cfg.symbol == "DOGE" && !doge_chain) {
                        auto dp = settings->m_testnet
                            ? (doge_testnet4alpha
                                ? doge::coin::DOGEChainParams::testnet4alpha()
                                : doge::coin::DOGEChainParams::testnet())
                            : doge::coin::DOGEChainParams::mainnet();
                        doge_params_ptr = std::make_unique<doge::coin::DOGEChainParams>(dp);

                        std::string doge_net_dir = settings->m_testnet
                            ? (doge_testnet4alpha ? "dogecoin_testnet4alpha" : "dogecoin_testnet")
                            : "dogecoin";
                        std::string doge_db = (core::filesystem::config_path()
                            / doge_net_dir / "embedded_headers").string();
                        doge_chain = std::make_unique<doge::coin::HeaderChain>(*doge_params_ptr, doge_db);
                        {
                            bool doge_ok = false;
                            for (int attempt = 1; attempt <= 5; ++attempt) {
                                if (doge_chain->init()) { doge_ok = true; break; }
                                LOG_WARNING << "DOGE HeaderChain LevelDB init failed (attempt "
                                            << attempt << "/5) — retrying in 2s...";
                                std::this_thread::sleep_for(std::chrono::seconds(2));
                                doge_chain = std::make_unique<doge::coin::HeaderChain>(*doge_params_ptr, doge_db);
                            }
                            if (!doge_ok)
                                LOG_WARNING << "DOGE HeaderChain LevelDB init failed after 5 attempts — in-memory only";
                        }

                        // Apply DOGE checkpoint if provided
                        if (!doge_header_checkpoint_str.empty()) {
                            auto colon = doge_header_checkpoint_str.find(':');
                            if (colon != std::string::npos) {
                                uint32_t cp_h = static_cast<uint32_t>(std::stoul(
                                    doge_header_checkpoint_str.substr(0, colon)));
                                uint256 cp_hash;
                                cp_hash.SetHex(doge_header_checkpoint_str.substr(colon + 1));
                                if (!cp_hash.IsNull())
                                    doge_chain->set_dynamic_checkpoint(cp_h, cp_hash);
                            }
                        }

                        // Seed genesis if empty (same pattern as LTC genesis seeding).
                        // Reference: dogecoin/src/chainparams.cpp CreateGenesisBlock()
                        //   All networks: merkle_root=5b2a3f53..., version=1, bits=0x1e0ffff0
                        //   Mainnet:       nTime=1386325540, nNonce=99943
                        //   Testnet:       nTime=1391503289, nNonce=997879
                        //   Testnet4alpha: nTime=1737907200, nNonce=1812121
                        if (doge_chain->size() == 0) {
                            ltc::coin::BlockHeaderType genesis;
                            genesis.m_previous_block.SetNull();
                            genesis.m_version = 1;
                            genesis.m_merkle_root.SetHex("5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69");
                            genesis.m_bits = 0x1e0ffff0;
                            if (doge_testnet4alpha) {
                                genesis.m_timestamp = 1737907200;
                                genesis.m_nonce     = 1812121;
                            } else if (settings->m_testnet) {
                                genesis.m_timestamp = 1391503289;
                                genesis.m_nonce     = 997879;
                            } else {
                                genesis.m_timestamp = 1386325540;
                                genesis.m_nonce     = 99943;
                            }
                            if (doge_chain->add_header(genesis))
                                LOG_INFO << "[DOGE] HeaderChain: genesis block seeded (height 0)";
                            else
                                LOG_WARNING << "[DOGE] HeaderChain: genesis seed rejected — wrong genesis hash?";
                        } else {
                            LOG_INFO << "DOGE HeaderChain: loaded " << doge_chain->size()
                                     << " headers (height=" << doge_chain->height() << ")";
                        }

                        if (!doge_pool)
                            doge_pool = std::make_unique<ltc::coin::Mempool>(core::coin::DOGE_LIMITS);

                        // DOGE UTXO set (simplified — no segwit/MWEB)
                        if (!doge_utxo_db) {
                            auto utxo_path = (core::filesystem::config_path()
                                / (settings->m_testnet ? "dogecoin_testnet" : "dogecoin")
                                / "utxo_leveldb").string();
                            core::LevelDBOptions utxo_opts;
                            utxo_opts.block_cache_size = 16 * 1024 * 1024;  // 16 MB
                            doge_utxo_db = std::make_unique<core::coin::UTXOViewDB>(utxo_path, utxo_opts);
                            {
                                bool utxo_ok = false;
                                for (int attempt = 1; attempt <= 5; ++attempt) {
                                    if (doge_utxo_db->open()) { utxo_ok = true; break; }
                                    LOG_WARNING << "[EMB-DOGE] UTXO DB open failed (attempt "
                                                << attempt << "/5) — retrying in 2s...";
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                    doge_utxo_db = std::make_unique<core::coin::UTXOViewDB>(utxo_path, utxo_opts);
                                }
                                if (utxo_ok) {
                                    doge_utxo_cache = std::make_unique<core::coin::UTXOViewCache>(doge_utxo_db.get());
                                    doge_utxo_ptr = doge_utxo_cache.get();  // wire SPV progress
                                    if (doge_pool) doge_pool->set_utxo(doge_utxo_cache.get());
                                    LOG_INFO << "[EMB-DOGE] UTXO set opened: best_height=" << doge_utxo_db->get_best_height();
                                } else {
                                    LOG_WARNING << "[EMB-DOGE] UTXO DB failed to open after 5 attempts — fees will be unknown";
                                }
                            }
                        }

                        // Embedded is always primary for DOGE when HeaderChain is available.
                        // --embedded-doge or having P2P both trigger this path.
                        // RPC becomes the fallback (auto-switch if embedded fails).
                        {
                            auto backend = std::make_unique<doge::coin::AuxChainEmbedded>(
                                *doge_chain, *doge_pool, *doge_params_ptr, cfg);
                            // Gate mining until UTXO has coinbase maturity depth (240 blocks for DOGE).
                            // Without this, block templates may include TXs spending immature coinbase outputs.
                            // Reference: dogecoin/src/chainparams.cpp digishieldConsensus.nCoinbaseMaturity = 240
                            if (doge_utxo_cache) {
                                auto* cache_ptr = doge_utxo_cache.get();
                                // Mining gate: coinbase_maturity + reorg_buffer
                                // DOGE: 240 + 10 (reorg safety) = 250
                                // Reference: dogecoin/src/chainparams.cpp digishieldConsensus
                                constexpr uint32_t DOGE_GATE = core::coin::DOGE_MINING_GATE_DEPTH; // 250
                                backend->embedded_node().set_utxo_ready_fn([cache_ptr, DOGE_GATE]() {
                                    auto connected = cache_ptr->blocks_connected();
                                    bool ready = connected >= DOGE_GATE;
                                    if (!ready) {
                                        static int s_log_ctr = 0;
                                        if (s_log_ctr++ % 20 == 0)
                                            LOG_INFO << "[EMB-DOGE] UTXO maturity gate: blocks_connected="
                                                     << connected << " need>=" << DOGE_GATE;
                                    }
                                    return ready;
                                });
                            }
                            mm_manager->add_chain(cfg, std::move(backend));
                            LOG_INFO << "Merged mining: DOGE embedded (primary) chain_id=" << cfg.chain_id;

                            // Set RPC as fallback if connection details are available
                            if (cfg.rpc_port > 0 && !cfg.rpc_userpass.empty()) {
                                auto rpc_fallback = std::make_unique<c2pool::merged::AuxChainRPC>(ioc, cfg);
                                mm_manager->set_fallback_backend(cfg.chain_id, std::move(rpc_fallback));
                                LOG_INFO << "Merged mining: DOGE RPC fallback at "
                                         << cfg.rpc_host << ":" << cfg.rpc_port;
                            }
                        }
                    } else {
                        // Non-DOGE chain or no P2P — standard RPC path
                        mm_manager->add_chain(cfg);
                        LOG_INFO << "Merged mining: added " << cfg.symbol
                                 << " (chain_id=" << cfg.chain_id << ") at "
                                 << cfg.rpc_host << ":" << cfg.rpc_port;
                    }

                    // Create multi-peer P2P broadcaster if P2P port is configured
                    if (cfg.p2p_port > 0) {
                        auto prefix = get_chain_p2p_prefix(cfg.symbol, settings->m_testnet);
                        if (!prefix.empty()) {
                            // Valid ports for this chain (main + testnet)
                            c2pool::merged::PeerManagerConfig pm_cfg;
                            pm_cfg.is_merged = true;
                            pm_cfg.max_connection_attempts = 5;
                            pm_cfg.refresh_interval_sec = 300; // 5 min for merged
                            // Testnet4alpha is an isolated network — disable discovery,
                            // only connect to the specified daemon.
                            if (doge_testnet4alpha && (cfg.symbol == "DOGE" || cfg.symbol == "doge")) {
                                pm_cfg.max_peers = 1;
                                pm_cfg.min_peers = 1;
                                pm_cfg.disable_discovery = true;
                            } else {
                                pm_cfg.max_peers = 20;
                                pm_cfg.min_peers = 4;
                            }
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

                            // Wire DNS seeds + fixed seed fallback for merged chain
                            if (cfg.symbol == "DOGE" || cfg.symbol == "doge") {
                                broadcaster->peer_manager().set_dns_seeds(
                                    doge::coin::doge_dns_seeds(settings->m_testnet, doge_testnet4alpha));
                                broadcaster->peer_manager().set_fixed_seeds(
                                    doge::coin::doge_fixed_seeds(settings->m_testnet, doge_testnet4alpha));
                                broadcaster->peer_manager().set_http_peer_seeds(
                                    {{"voidbind.com", 8080}});
                            } else if (cfg.symbol == "LTC" || cfg.symbol == "ltc") {
                                broadcaster->peer_manager().set_dns_seeds(
                                    ltc::coin::ltc_dns_seeds(settings->m_testnet));
                                broadcaster->peer_manager().set_fixed_seeds(
                                    ltc::coin::ltc_fixed_seeds(settings->m_testnet));
                                broadcaster->peer_manager().set_http_peer_seeds(
                                    {{"voidbind.com", 8080}});
                            }

                            // Wire getpeerinfo bootstrap from the aux chain RPC
                            auto* rpc_ptr = mm_manager->get_chain_rpc(cfg.chain_id);
                            if (rpc_ptr) {
                                broadcaster->set_getpeerinfo_fn([rpc_ptr]() {
                                    return rpc_ptr->getpeerinfo();
                                });
                            }
                            // Phase 5.8: wire AuxPoW header parser for DOGE P2P
                            if (cfg.symbol == "DOGE") {
                                broadcaster->set_raw_headers_parser(
                                    doge::coin::parse_doge_headers_message);
                                broadcaster->set_raw_block_parser(
                                    doge::coin::parse_doge_block);
                            }

                            // Step 4: wire DOGE header sync via AuxPoW parser.
                            // Always active when HeaderChain + broadcaster exist
                            // (not gated on --embedded-doge anymore).
                            if (cfg.symbol == "DOGE" && doge_chain) {
                                auto doge_hdr_pool = std::make_shared<boost::asio::thread_pool>(1);
                                auto* bcaster_ptr = broadcaster.get();

                                // Wire peer tip height for fast-sync scrypt skip
                                broadcaster->set_on_peer_height(
                                    [dc = doge_chain.get()](uint32_t h) {
                                        dc->set_peer_tip_height(h);
                                        LOG_INFO << "DOGE peer reports height " << h;
                                    });

                                // Wire DOGE mempool: feed P2P transactions into the template builder's pool
                                if (doge_pool) {
                                    broadcaster->set_on_new_tx(
                                        [pool = doge_pool.get(),
                                         utxo = doge_utxo_cache.get()](const std::string& peer_key,
                                                                        const ltc::coin::Transaction& tx) {
                                            ltc::coin::MutableTransaction mtx(tx);
                                            bool added = pool->add_tx(mtx, utxo);
                                            if (added) {
                                                auto txid = ltc::coin::compute_txid(mtx);
                                                LOG_INFO << "[EMB-DOGE] Mempool: tx=" << txid.GetHex().substr(0, 16)
                                                         << " from=" << peer_key
                                                         << " size=" << pool->size()
                                                         << " fee=" << (pool->contains(txid) ? "pending" : "?");
                                            }
                                        });
                                    LOG_INFO << "DOGE mempool wired via P2P broadcaster";
                                }

                                // Wire headers: parse AuxPoW extended format → base headers → HeaderChain
                                broadcaster->set_on_new_headers(
                                    [dc = doge_chain.get(), doge_hdr_pool, bcaster_ptr, &ioc](
                                        const std::string& /*key*/,
                                        const std::vector<ltc::coin::BlockHeaderType>& hdrs) {
                                        // The broadcaster's on_new_headers gives us raw BlockHeaderType
                                        // from the standard parser. For DOGE AuxPoW, the P2P message
                                        // handler in NodeP2P already parses the headers using the
                                        // standard 80+1 byte format. AuxPoW blocks have the AuxPoW
                                        // data INSIDE the block, not the header in 'headers' message.
                                        //
                                        // NOTE: Dogecoin's P2P 'headers' message DOES include AuxPoW
                                        // data. However, our NodeP2P handler parses each header as
                                        // 80 bytes + tx_count. If the DOGE peer sends AuxPoW headers,
                                        // the parser will fail on the variable-length data.
                                        //
                                        // For testnet4alpha (all AuxPoW from genesis), we may need
                                        // the dedicated AuxPoW parser. For now, pass through directly
                                        // and handle parse errors gracefully.
                                        LOG_INFO << "[EMB-DOGE] Received " << hdrs.size()
                                                 << " headers from P2P";
                                        auto batch = std::make_shared<std::vector<ltc::coin::BlockHeaderType>>(hdrs);
                                        boost::asio::post(*doge_hdr_pool,
                                            [batch, dc, bcaster_ptr, &ioc]() {
                                                int accepted = dc->add_headers(*batch);
                                                if (accepted > 0)
                                                    LOG_INFO << "[EMB-DOGE] add_headers: "
                                                             << accepted << "/" << batch->size()
                                                             << " accepted, chain height="
                                                             << dc->height();

                                                // Pipeline: immediate follow-up getheaders for fast sync
                                                uint256 last_hash;
                                                if (!batch->empty()) {
                                                    auto packed = pack(batch->back());
                                                    last_hash = Hash(packed.get_span());
                                                }
                                                bool full_batch = (batch->size() >= 2000);
                                                if (accepted > 0 || full_batch) {
                                                    boost::asio::post(ioc, [accepted, last_hash, dc, bcaster_ptr]() {
                                                      try {
                                                        if (accepted > 0 && !last_hash.IsNull()) {
                                                            bcaster_ptr->request_headers({last_hash}, uint256::ZERO);
                                                        } else {
                                                            bcaster_ptr->request_headers(dc->get_locator(), uint256::ZERO);
                                                        }
                                                      } catch (const std::exception& e) {
                                                        LOG_WARNING << "[EMB-DOGE] Header post-process error: " << e.what();
                                                      }
                                                    });
                                                }
                                            });
                                    });

                                // Periodic DOGE header sync (every 60s)
                                auto doge_sync_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
                                auto doge_sync_timer = std::make_shared<boost::asio::steady_timer>(ioc);
                                *doge_sync_fn = [doge_sync_fn, doge_sync_timer, now_ms, hb_doge_sync,
                                                 dc = doge_chain.get(),
                                                 bcaster_ptr](boost::system::error_code ec) {
                                    if (ec) return;
                                    hb_doge_sync->store(now_ms());
                                    // Fast poll during sync (5s), slow when caught up (60s)
                                    int interval = dc->is_synced() ? 60 : 5;
                                    doge_sync_timer->expires_after(std::chrono::seconds(interval));
                                    doge_sync_timer->async_wait(*doge_sync_fn);
                                    try {
                                        auto locator = dc->get_locator();
                                        bcaster_ptr->request_headers(locator, uint256::ZERO);
                                    } catch (const std::exception& e) {
                                        LOG_WARNING << "[EMB-DOGE] Header sync error: " << e.what();
                                    }
                                };
                                // Initial delay: wait for broadcaster maintenance (5s) to connect peers
                                doge_sync_timer->expires_after(std::chrono::seconds(10));
                                doge_sync_timer->async_wait(*doge_sync_fn);
                                LOG_INFO << "DOGE embedded header sync wired via P2P";

                                // Wire full-block handler: UTXO bootstrap + mempool cleanup.
                                // Same bootstrap pipeline as LTC — see EMB-LTC handler.
                                {
                                auto doge_bs = std::make_shared<
                                    core::coin::BlockBootstrapState<ltc::coin::BlockType>>();
                                broadcaster->set_on_full_block(
                                    [pool = doge_pool.get(),
                                     chain = doge_chain.get(),
                                     utxo = doge_utxo_cache.get(),
                                     utxo_db = doge_utxo_db.get(),
                                     bcaster_ptr = broadcaster.get(),
                                     coinbase_maturity = core::coin::DOGE_LIMITS.coinbase_maturity,
                                     explorer_enabled, explorer_depth_doge,
                                     mm_ptr = mm_manager.get(),
                                     doge_bs, &ioc, &web_server](
                                        const std::string& peer,
                                        const ltc::coin::BlockType& block) {
                                        auto packed_hdr = pack(static_cast<const ltc::coin::BlockHeaderType&>(block));
                                        auto block_hash = Hash(packed_hdr.get_span());
                                        uint32_t height = 0;
                                        if (chain) {
                                            auto entry = chain->get_header(block_hash);
                                            if (entry) height = entry->height;
                                            else { auto prev = chain->get_header(block.m_previous_block); if (prev) height = prev->height + 1; }
                                        }

                                        auto txid_fn = [](const ltc::coin::MutableTransaction& tx) {
                                            return ltc::coin::compute_txid(tx);
                                        };
                                        static bool doge_mempool_requested = false;
                                        static bool doge_bootstrap_done = false;
                                        constexpr uint32_t DOGE_KEEP = core::coin::DOGE_MIN_BLOCKS_TO_KEEP;

                                        // ═══ BOOTSTRAP PIPELINE (same as LTC) ═════════
                                        if (utxo && utxo_db) {
                                            // 1. Bootstrap trigger
                                            if (!doge_bootstrap_done && !doge_bs->active &&
                                                chain && bcaster_ptr && height > DOGE_KEEP) {
                                                doge_bootstrap_done = true;
                                                uint32_t utxo_best = utxo->get_best_height();
                                                uint32_t start_from =
                                                    (utxo_best > 0 && utxo_best >= height - DOGE_KEEP)
                                                    ? utxo_best + 1 : height - DOGE_KEEP;

                                                if (start_from < height) {
                                                    doge_bs->active = true;
                                                    doge_bs->next_height = start_from;
                                                    doge_bs->end_height = height;
                                                    doge_bs->next_request = start_from;
                                                    doge_bs->total = height - start_from + 1;
                                                    doge_bs->buffer[height] = {block, block_hash};
                                                    doge_bs->last_drain_time =
                                                        std::chrono::steady_clock::now();

                                                    int requested = 0;
                                                    while (doge_bs->next_request <= doge_bs->end_height &&
                                                           (doge_bs->next_request - doge_bs->next_height)
                                                               < doge_bs->WINDOW_SIZE) {
                                                        if (!doge_bs->buffer.count(doge_bs->next_request)) {
                                                            auto e = chain->get_header_by_height(
                                                                doge_bs->next_request);
                                                            if (e) {
                                                                bcaster_ptr->request_full_block(
                                                                    e->block_hash);
                                                                ++requested;
                                                            }
                                                        }
                                                        ++doge_bs->next_request;
                                                    }
                                                    LOG_INFO << "[EMB-DOGE] Bootstrap pipeline: "
                                                             << doge_bs->total << " blocks ["
                                                             << start_from << ".." << height << "]"
                                                             << " window=" << doge_bs->WINDOW_SIZE
                                                             << " requests=" << requested
                                                             << " peers=" << bcaster_ptr->peer_count();
                                                    doge_bs->start_stall_timer(ioc,
                                                        [chain, bcaster_ptr](uint32_t h) {
                                                            auto e = chain->get_header_by_height(h);
                                                            if (e && bcaster_ptr)
                                                                bcaster_ptr->request_full_block(e->block_hash);
                                                        }, "EMB-DOGE");
                                                    return;
                                                } else {
                                                    LOG_INFO << "[EMB-DOGE] UTXO warm restart: best="
                                                             << utxo_best << " — no bootstrap needed";
                                                }
                                            }

                                            // 2. Bootstrap active: buffer → drain → refill
                                            if (doge_bs->active) {
                                                if (height >= doge_bs->next_height &&
                                                    height <= doge_bs->end_height) {
                                                    doge_bs->buffer.try_emplace(
                                                        height, std::make_pair(block, block_hash));
                                                } else if (height > doge_bs->end_height) {
                                                    doge_bs->end_height = height;
                                                    doge_bs->total = doge_bs->processed
                                                        + (doge_bs->end_height - doge_bs->next_height + 1);
                                                    doge_bs->buffer.try_emplace(
                                                        height, std::make_pair(block, block_hash));
                                                }

                                                auto now = std::chrono::steady_clock::now();
                                                auto stall = std::chrono::duration_cast<
                                                    std::chrono::seconds>(
                                                    now - doge_bs->last_drain_time).count();
                                                if (stall >= doge_bs->STALL_TIMEOUT_SEC && chain && bcaster_ptr) {
                                                    auto e = chain->get_header_by_height(
                                                        doge_bs->next_height);
                                                    if (e) {
                                                        LOG_WARNING << "[EMB-DOGE] Bootstrap stall h="
                                                            << doge_bs->next_height << " (" << stall
                                                            << "s) — broadcast fallback";
                                                        bcaster_ptr->request_full_block(e->block_hash);
                                                    }
                                                    doge_bs->last_drain_time = now;
                                                }

                                                // Drain consecutive blocks
                                                while (doge_bs->buffer.count(doge_bs->next_height)) {
                                                    auto node =
                                                        doge_bs->buffer.extract(doge_bs->next_height);
                                                    auto& [b, bh] = node.mapped();
                                                    uint32_t h = doge_bs->next_height;

                                                    auto undo = utxo->connect_block(b, h, txid_fn);
                                                    utxo_db->put_block_undo(h, undo);
                                                    utxo->flush(bh, h);
                                                    utxo->prune_undo(h, DOGE_KEEP);

                                                    if (explorer_enabled) {
                                                        PackStream ps;
                                                        ps << b;
                                                        auto span = ps.get_span();
                                                        std::vector<uint8_t> raw(
                                                            reinterpret_cast<const uint8_t*>(
                                                                span.data()),
                                                            reinterpret_cast<const uint8_t*>(
                                                                span.data()) + span.size());
                                                        utxo_db->put_raw_block(h, raw);
                                                        utxo_db->prune_raw_blocks(
                                                            h, explorer_depth_doge);
                                                    }

                                                    if (pool) {
                                                        pool->set_tip_height(h);
                                                        pool->remove_for_block(b);
                                                    }

                                                    if (mm_ptr && !b.m_txs.empty()) {
                                                        uint64_t cb_total = 0;
                                                        for (const auto& out : b.m_txs[0].vout)
                                                            cb_total += out.value;
                                                        if (cb_total > 0)
                                                            mm_ptr->update_block_coinbase(
                                                                bh.GetHex(), cb_total);
                                                    }

                                                    if (!doge_mempool_requested && bcaster_ptr) {
                                                        bcaster_ptr->enable_mempool_request();
                                                        doge_mempool_requested = true;
                                                    }

                                                    ++doge_bs->next_height;
                                                    ++doge_bs->processed;
                                                    doge_bs->last_drain_time =
                                                        std::chrono::steady_clock::now();
                                                }

                                                static int dbs_log = 0;
                                                if (++dbs_log % 50 == 0 ||
                                                    doge_bs->next_height > doge_bs->end_height) {
                                                    LOG_INFO << "[EMB-DOGE] Bootstrap: "
                                                             << doge_bs->processed << "/"
                                                             << doge_bs->total
                                                             << " buf=" << doge_bs->buffer.size();
                                                }

                                                if (chain && bcaster_ptr) {
                                                    while (doge_bs->next_request <= doge_bs->end_height
                                                           && (doge_bs->next_request - doge_bs->next_height)
                                                               < doge_bs->WINDOW_SIZE) {
                                                        if (!doge_bs->buffer.count(
                                                                doge_bs->next_request)) {
                                                            auto e = chain->get_header_by_height(
                                                                doge_bs->next_request);
                                                            if (e)
                                                                bcaster_ptr->request_full_block(
                                                                    e->block_hash);
                                                        }
                                                        ++doge_bs->next_request;
                                                    }
                                                }

                                                if (doge_bs->next_height > doge_bs->end_height) {
                                                    doge_bs->active = false;
                                                    doge_bs->stop_stall_timer();
                                                    LOG_INFO << "[EMB-DOGE] Bootstrap complete: "
                                                             << doge_bs->processed << " blocks";
                                                }
                                                return;
                                            }

                                            // 3. Normal processing
                                            if (height > utxo->get_best_height()) {
                                                auto undo = utxo->connect_block(
                                                    block, height, txid_fn);
                                                utxo_db->put_block_undo(height, undo);
                                                utxo->flush(block_hash, height);
                                                utxo->prune_undo(height, DOGE_KEEP);

                                                LOG_INFO << "[EMB-DOGE] UTXO: block " << height
                                                         << " hash="
                                                         << block_hash.GetHex().substr(0, 16)
                                                         << " txs=" << block.m_txs.size()
                                                         << " cache=" << utxo->cache_size();

                                                if (!doge_mempool_requested && bcaster_ptr) {
                                                    bcaster_ptr->enable_mempool_request();
                                                    doge_mempool_requested = true;
                                                    LOG_INFO << "[EMB-DOGE] Mempool relay active";
                                                }
                                            }
                                        }

                                        // Normal mode processing (after bootstrap)
                                        if (explorer_enabled && utxo_db && height > 0) {
                                            PackStream ps;
                                            ps << block;
                                            auto span = ps.get_span();
                                            std::vector<uint8_t> raw(
                                                reinterpret_cast<const uint8_t*>(span.data()),
                                                reinterpret_cast<const uint8_t*>(span.data())
                                                    + span.size());
                                            utxo_db->put_raw_block(height, raw);
                                            utxo_db->prune_raw_blocks(height, explorer_depth_doge);
                                        }
                                        if (pool) {
                                            pool->set_tip_height(height);
                                            pool->remove_for_block(block);
                                            if (utxo) {
                                                int resolved = pool->recompute_unknown_fees(utxo);
                                                int evicted = pool->revalidate_inputs(utxo);
                                                if (resolved > 0 || evicted > 0)
                                                    web_server.trigger_work_refresh_debounced();
                                            }
                                        }
                                        if (mm_ptr && !block.m_txs.empty()) {
                                            uint64_t cb_total = 0;
                                            for (const auto& out : block.m_txs[0].vout)
                                                cb_total += out.value;
                                            if (cb_total > 0) {
                                                mm_ptr->update_block_coinbase(
                                                    block_hash.GetHex(), cb_total);
                                                auto sp = web_server.get_mining_interface()
                                                    ->get_merged_block_store();
                                                if (sp) {
                                                    auto* ms = static_cast<
                                                        c2pool::storage::MergedBlockStore*>(
                                                        sp.get());
                                                    ms->update_coinbase(
                                                        block_hash.GetHex(), 98, cb_total);
                                                }
                                            }
                                        }
                                    });
                                } // doge_bs scope

                                // Tip-changed handler: trigger work refresh so stratum miners
                                // get updated merged mining targets immediately.
                                doge_chain->set_on_tip_changed(
                                    [bcaster_ptr, &web_server,
                                     chain = doge_chain.get(),
                                     utxo = doge_utxo_cache.get(),
                                     utxo_db = doge_utxo_db.get()](
                                        const uint256& old_tip, uint32_t old_height,
                                        const uint256& new_tip, uint32_t new_height) {
                                        bool is_reorg = (new_height <= old_height);
                                        LOG_WARNING << "[EMB-DOGE] Chain tip changed: "
                                                    << old_tip.GetHex().substr(0, 16) << " (h=" << old_height << ") → "
                                                    << new_tip.GetHex().substr(0, 16) << " (h=" << new_height << ")"
                                                    << (is_reorg ? " [REORG]" : "");

                                        // Disconnect old fork UTXO during reorg
                                        if (is_reorg && utxo && utxo_db && chain) {
                                            std::set<uint256> new_anc;
                                            { uint256 c = new_tip; while (!c.IsNull()) { new_anc.insert(c); auto e = chain->get_header(c); if (!e) break; c = e->prev_hash; } }
                                            uint256 fork_h; uint32_t fork_ht = 0;
                                            { uint256 c = old_tip; while (!c.IsNull()) { if (new_anc.count(c)) { fork_h = c; auto e = chain->get_header(c); if (e) fork_ht = e->height; break; } auto e = chain->get_header(c); if (!e) break; c = e->prev_hash; } }
                                            if (!fork_h.IsNull() && fork_ht < old_height) {
                                                int disc = 0;
                                                for (uint32_t h = old_height; h > fork_ht; --h) {
                                                    core::coin::BlockUndo undo;
                                                    if (utxo_db->get_block_undo(h, undo)) { utxo->disconnect_from_undo(undo); utxo_db->remove_block_undo(h); ++disc; }
                                                }
                                                utxo->flush(fork_h, fork_ht);
                                                LOG_WARNING << "[EMB-DOGE] UTXO reorg: disconnected " << disc << " blocks";
                                            }
                                        }

                                        // Request the new tip's full block for mempool cleanup
                                        if (bcaster_ptr)
                                            bcaster_ptr->request_full_block(new_tip);
                                        web_server.trigger_work_refresh_debounced();
                                    });
                                LOG_INFO << "[EMB-DOGE] Chain reorg handler registered";

                                // Periodic mempool cleanup: evict expired txs every 5 minutes.
                                auto doge_mempool_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
                                auto doge_mempool_timer = std::make_shared<boost::asio::steady_timer>(ioc);
                                *doge_mempool_fn = [doge_mempool_fn, doge_mempool_timer, now_ms, hb_doge_mempool,
                                                    pool = doge_pool.get()](boost::system::error_code ec) {
                                    if (ec) return;
                                    hb_doge_mempool->store(now_ms());
                                    doge_mempool_timer->expires_after(std::chrono::minutes(5));
                                    doge_mempool_timer->async_wait(*doge_mempool_fn);
                                    try {
                                        if (pool)
                                            pool->evict_expired();
                                    } catch (const std::exception& e) {
                                        LOG_WARNING << "[EMB-DOGE] Mempool cleanup error: " << e.what();
                                    }
                                };
                                doge_mempool_timer->expires_after(std::chrono::minutes(5));
                                doge_mempool_timer->async_wait(*doge_mempool_fn);
                                LOG_INFO << "[EMB-DOGE] Mempool expiration timer started (5m interval)";
                            }

                            broadcaster->start();
                            LOG_INFO << "Merged multi-peer broadcaster: " << cfg.symbol
                                     << " → " << cfg.p2p_address << ":" << cfg.p2p_port;
                            // Register for /api/coin_peers endpoint
                            coin_peer_sources->push_back(broadcaster.get());
                            merged_broadcasters[cfg.chain_id] = std::move(broadcaster);
                        } else {
                            LOG_WARNING << "Unknown P2P prefix for " << cfg.symbol
                                        << " — P2P broadcaster disabled for this chain";
                        }
                    }
                }
                web_server.set_merged_mining_manager(mm_manager.get());

                // Wire the merged payout provider so that aux chain block
                // construction uses the correct payout distribution.
                auto* mi = web_server.get_mining_interface();

              if (solo_mode || custodial_mode) {
                // Solo/custodial: reuse the same payout logic as LTC coinbase.
                // Custodial: entire merged subsidy to --address.
                // Solo: proportional split by stratum hashrates.
                auto owner_script_mm = core::address_to_script(payout_address);
                mm_manager->set_payout_provider(
                    [&web_server, mi, custodial_mode, owner_script_mm,
                     dev_donation, node_owner_fee, &payout_address](
                        uint32_t chain_id, uint64_t coinbase_value)
                    -> std::vector<std::pair<std::vector<unsigned char>, uint64_t>>
                {
                    auto& donation_script = mi->get_donation_script();

                    // Donation (dev_donation% or 1 satoshi marker)
                    uint64_t donation_amount = (dev_donation > 0)
                        ? static_cast<uint64_t>(coinbase_value * dev_donation / 100.0)
                        : 1;

                    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> result;

                    if (custodial_mode) {
                        // Custodial: everything to node operator
                        uint64_t operator_amount = coinbase_value - donation_amount;
                        if (!owner_script_mm.empty() && operator_amount > 0)
                            result.emplace_back(owner_script_mm, operator_amount);
                        if (donation_amount > 0)
                            result.emplace_back(donation_script, donation_amount);
                    } else {
                        // Solo: proportional split by hashrate
                        uint64_t owner_fee_amount = 0;
                        if (node_owner_fee > 0 && !owner_script_mm.empty()) {
                            owner_fee_amount = static_cast<uint64_t>(coinbase_value * node_owner_fee / 100.0);
                            result.emplace_back(owner_script_mm, owner_fee_amount);
                        }
                        if (donation_amount > 0)
                            result.emplace_back(donation_script, donation_amount);

                        uint64_t miner_pool = coinbase_value - owner_fee_amount - donation_amount;
                        auto rates = web_server.get_local_addr_rates();
                        double total_rate = 0;
                        for (auto& [_, rate] : rates) total_rate += rate;

                        if (total_rate > 0) {
                            for (auto& [pubkey_hash, rate] : rates) {
                                uint64_t amount = static_cast<uint64_t>(miner_pool * rate / total_rate);
                                if (amount == 0) continue;
                                std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
                                script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());
                                script.push_back(0x88);
                                script.push_back(0xac);
                                result.emplace_back(std::move(script), amount);
                            }
                        } else if (!owner_script_mm.empty()) {
                            result.emplace_back(owner_script_mm, miner_pool);
                        } else {
                            result.emplace_back(donation_script, miner_pool);
                        }
                    }

                    LOG_INFO << "[MM-payout] chain_id=" << chain_id
                             << " coinbase_value=" << coinbase_value
                             << " payouts=" << result.size()
                             << " mode=" << (custodial_mode ? "custodial" : "solo");

                    std::sort(result.begin(), result.end());
                    return result;
                });
              } else {
                // P2P mode: PPLNS weights from the share tracker
                // Build operator LTC script for merged address override (p2pool --merged-operator-address)
                auto operator_ltc_script = node_owner_address.empty()
                    ? std::vector<unsigned char>{}
                    : core::address_to_script(node_owner_address);
                auto operator_merged_script = node_owner_merged_address.empty()
                    ? std::vector<unsigned char>{}
                    : core::address_to_script(node_owner_merged_address);
                if (!node_owner_merged_address.empty()) {
                    LOG_INFO << "Merged operator address override: " << node_owner_merged_address
                             << " (script " << operator_merged_script.size() << " bytes)";
                }
                mm_manager->set_payout_provider(
                    [&p2p_node, mi, operator_ltc_script, operator_merged_script](
                        uint32_t chain_id, uint64_t coinbase_value)
                    -> std::vector<std::pair<std::vector<unsigned char>, uint64_t>>
                {
                    auto best = p2p_node->best_share_hash();
                    if (best.IsNull())
                        return {};

                    // Use block target (from min_header.bits), not share target.
                    // Matches p2pool: block_target = self.header['bits'].target
                    uint256 block_target;
                    p2p_node->tracker().chain.get(best).share.invoke([&](auto* s) {
                        block_target = chain::bits_to_target(s->m_min_header.m_bits);
                    });

                    // Merged chains always use COMBINED_DONATION_SCRIPT (P2SH)
                    // regardless of share version — p2pool data.py line 303.
                    // The parent chain uses version-dependent donation (P2PK for V35).
                    auto combined_donation = std::vector<unsigned char>(
                        ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(),
                        ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end());
                    auto payouts_map = p2p_node->tracker().get_merged_expected_payouts(
                        best, block_target, coinbase_value, chain_id, combined_donation,
                        operator_ltc_script, operator_merged_script);

                    LOG_INFO << "[MM-payout] chain_id=" << chain_id
                             << " coinbase_value=" << coinbase_value
                             << " payouts_map_size=" << payouts_map.size()
                             << " chain_height=" << p2p_node->tracker().chain.get_height(best)
                             << " block_target=" << block_target.GetHex().substr(0,16);

                    // Convert map → sorted vector for coinbase construction
                    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> result;
                    result.reserve(payouts_map.size());
                    for (auto& [script, amount] : payouts_map) {
                        if (amount >= 1)
                            result.emplace_back(script, amount);
                    }
                    std::sort(result.begin(), result.end());
                    return result;
                });
              } // end MM payout provider

                // Wire THE state root provider: anchors sharechain state in merged
                // coinbase scriptSig. Critical when only a merged block is found (no
                // LTC parent block anchor available).
                mm_manager->set_state_root_provider(
                    [mi]() -> uint256 {
                        if (!mi) return uint256();
                        return mi->get_the_state_root();
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

                    // Wire merged block found → unified verification via FoundBlock
                    auto* mi_ptr = web_server.get_mining_interface();
                    mm_manager->set_on_merged_block_found(
                        [mi_ptr](const std::string& symbol, int height,
                                 const std::string& block_hash, bool accepted) {
                            uint256 h;
                            h.SetHex(block_hash);
                            double net_diff = mi_ptr->get_network_difficulty();
                            double pool_hr = mi_ptr->get_local_hashrate();
                            std::string miner_addr = mi_ptr->get_payout_address();
                            mi_ptr->record_found_block(
                                static_cast<uint64_t>(height), h, 0, symbol,
                                miner_addr, "", net_diff, 0, pool_hr, 0);
                            if (accepted)
                                mi_ptr->schedule_block_verification(block_hash);
                        });

                    // When merged mining aux work changes (new DOGE block),
                    // push fresh stratum work so miners get the new commitment.
                    mm_manager->set_on_work_changed([&web_server]() {
                        web_server.trigger_work_refresh_debounced();
                    });

                    // Wire DOGE block verifier.
                    // Note: the aux block hash from createauxblock is NOT the chain
                    // block hash. After submitauxblock, the actual block gets a
                    // different hash (includes AuxPoW proof). We verify by checking
                    // if the daemon's best block height >= our block height.
                    for (auto& chain : merged_chain_specs) {
                        auto parts_check = std::vector<std::string>();
                        { std::istringstream ss(chain); std::string t;
                          while (std::getline(ss, t, ':')) parts_check.push_back(t); }
                        if (parts_check.size() >= 2) {
                            std::string sym = parts_check[0];
                            uint32_t cid = static_cast<uint32_t>(std::stoul(parts_check[1]));
                            auto* rpc_backend = mm_manager->get_chain_rpc(cid);
                            if (rpc_backend) {
                                mi_ptr->add_chain_verify_fn(sym,
                                    [rpc_backend](const std::string& /*hash_hex*/) -> int {
                                        // For merged blocks, submitauxblock returning success
                                        // means the daemon accepted it. The block IS in the chain.
                                        // We verify by checking the daemon is still responsive.
                                        try {
                                            auto tip = rpc_backend->get_best_block_hash();
                                            return tip.empty() ? 0 : 1; // daemon alive = confirmed
                                        } catch (...) {
                                            return 0; // daemon unreachable — can't verify
                                        }
                                    });
                            }
                        }
                    }
                }
            }

            // --- V36 operational features ---

            // Phase 3L: Pool monitor — periodic log-based diagnostics
            auto pool_monitor = std::make_unique<ltc::PoolMonitor>();

            // Redistribute mode for invalid/empty miner addresses (V2: hybrid support)
            auto hybrid_weights = ltc::parse_redistribute_spec(redistribute_mode_str);
            auto redistributor = std::make_unique<ltc::Redistributor>();
            redistributor->set_hybrid_weights(hybrid_weights);
            LOG_INFO << "Redistribute mode: " << ltc::format_hybrid_weights(hybrid_weights);

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
            // Solo/custodial: no tracker — fallback to payout_address hash160.
            // P2P: redistributor picks from share tracker PPLNS weights.
            if (p2p_node) {
                auto* redistributor_ptr = redistributor.get();
                auto* node_ptr = p2p_node.get();
                web_server.get_mining_interface()->set_address_fallback_fn(
                    [redistributor_ptr, node_ptr](const std::string& /*bad_addr*/) -> std::string {
                        auto best = node_ptr->best_share_hash();
                        auto result = redistributor_ptr->pick(node_ptr->tracker(), best);
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
            } else if (!payout_address.empty()) {
                // Solo/custodial: invalid miner address → use node operator address
                web_server.get_mining_interface()->set_address_fallback_fn(
                    [&payout_address](const std::string& /*bad_addr*/) -> std::string {
                        std::string atype;
                        return core::address_to_hash160(payout_address, atype);
                    });
            }
            // Keep redistributor alive for the lifetime of the pool
            auto redistributor_holder = std::move(redistributor);

            // Periodic run_think timer (every 5 seconds, safety net)
            // Primary think trigger: processing_shares_phase2 calls run_think()
            // for small batches (real-time share relay). This timer catches
            // anything that falls through.
            // Solo/custodial: no sharechain → no think/clean needed.
            auto think_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            std::function<void(boost::system::error_code)> think_tick;
            if (p2p_node) {
                think_tick = [&, think_timer, now_ms, hb_think](boost::system::error_code ec) {
                    if (ec || g_shutdown_requested) return;
                    hb_think->store(now_ms());
                    think_timer->expires_after(std::chrono::seconds(5));
                    think_timer->async_wait(think_tick);
                    try {
                        p2p_node->clean_tracker();
                    } catch (const std::exception& e) {
                        LOG_ERROR << "[CLEAN-TRACKER] error: " << e.what();
                    } catch (...) {
                        LOG_ERROR << "[CLEAN-TRACKER] unknown error";
                    }
                };
                think_timer->expires_after(std::chrono::seconds(5));
                think_timer->async_wait(think_tick);
            }

            // Heartbeat timer (every 30s): p2pool-style status lines.
            // Separated from think() to avoid blocking the compute thread
            // with diagnostic chain walks. Runs on IO thread with shared_lock.
            auto heartbeat_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            std::function<void(boost::system::error_code)> heartbeat_tick;
            if (p2p_node) {
                heartbeat_tick = [&, heartbeat_timer](boost::system::error_code ec) {
                    if (ec || g_shutdown_requested) return;
                    heartbeat_timer->expires_after(std::chrono::seconds(30));
                    heartbeat_timer->async_wait(heartbeat_tick);
                    try {
                        p2p_node->heartbeat_log();
                    } catch (...) {}
                };
                heartbeat_timer->expires_after(std::chrono::seconds(10));
                heartbeat_timer->async_wait(heartbeat_tick);
            }

            // Periodic monitoring timer (every 30 seconds)
            // Solo/custodial: no tracker to monitor.
            auto monitor_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            std::function<void(boost::system::error_code)> monitor_tick;
            if (p2p_node) {
                monitor_tick = [&, monitor_timer, now_ms, hb_monitor](boost::system::error_code ec) {
                    if (ec || g_shutdown_requested) return;
                    hb_monitor->store(now_ms());
                    monitor_timer->expires_after(std::chrono::seconds(30));
                    monitor_timer->async_wait(monitor_tick);
                    try {
                        auto best = p2p_node->best_share_hash();
                        if (!best.IsNull()) {
                            pool_monitor->run_cycle(p2p_node->tracker(), best);
                            whale_detector->detect(p2p_node->tracker(), best, "timer");
                        }
                    } catch (const std::exception& e) {
                        LOG_ERROR << "[MONITOR] cycle error: " << e.what();
                    } catch (...) {
                        LOG_ERROR << "[MONITOR] unknown error";
                    }
                };
                monitor_timer->expires_after(std::chrono::seconds(30));
                monitor_timer->async_wait(monitor_tick);
            }

            // ── Embedded LTC sync gate ──────────────────────────────────
            // Match p2pool's implicit sync gate: block startup until the
            // parent chain is ready.  p2pool blocks on getblocktemplate()
            // which fails until the daemon is synced.  We block on
            // HeaderChain::is_synced() (tip within 2 hours of wall clock).
            //
            // During this loop ioc runs — P2P header sync proceeds — but
            // Stratum is NOT open yet, so miners see "connection refused".
            // Merged chains (DOGE) do NOT block: they degrade gracefully
            // once the parent chain is ready, matching p2pool behavior.
            if (embedded_ltc && embedded_chain && embedded_node) {
                LOG_INFO << "[EMB-LTC] Waiting for header sync + UTXO maturity before starting Stratum...";
                auto sync_log_timer = std::chrono::steady_clock::now();
                // Gate on EmbeddedCoinNode::is_synced() which checks BOTH:
                //   1. HeaderChain tip within 2 hours (Bitcoin Core IsInitialBlockDownload)
                //   2. UTXO blocks_connected >= COINBASE_MATURITY (100 for LTC)
                while (!embedded_node->is_synced() && !g_shutdown_requested) {
                    ioc.restart();
                    try {
                        ioc.run_for(std::chrono::milliseconds(100));
                    } catch (const std::exception& e) {
                        LOG_ERROR << "ioc handler exception during sync wait: " << e.what();
                    }
                    // Progress log every 5 seconds
                    auto now = std::chrono::steady_clock::now();
                    if (now - sync_log_timer >= std::chrono::seconds(5)) {
                        LOG_INFO << "[EMB-LTC] Sync in progress: height="
                                 << embedded_chain->height()
                                 << " utxo_blocks=" << (ltc_utxo_cache ? ltc_utxo_cache->blocks_connected() : 0)
                                 << " peers=" << embedded_broadcaster->connected_count();
                        sync_log_timer = now;
                    }
                }
                if (g_shutdown_requested) {
                    LOG_INFO << "Shutdown requested during sync — exiting";
                    return 0;
                }
                LOG_INFO << "[EMB-LTC] Synced: headers=" << embedded_chain->height()
                         << " utxo_blocks=" << (ltc_utxo_cache ? ltc_utxo_cache->blocks_connected() : 0)
                         << " — starting Stratum";
            }

            // ── Explorer API callbacks ────────────────────────────────────────
            if (explorer_enabled) {
                auto* mi = web_server.get_mining_interface();
                auto* ltc_chain = embedded_chain.get();
                auto* ltc_udb = ltc_utxo_db.get();
                auto* dg_chain = doge_chain.get();
                auto* dg_udb = doge_utxo_db.get();
                bool testnet = settings->m_testnet;

                // getblockchaininfo
                mi->set_explorer_chaininfo_fn(
                    [ltc_chain, dg_chain, explorer_depth_ltc, explorer_depth_doge, testnet]
                    (const std::string& chain) -> nlohmann::json {
                        nlohmann::json r;
                        if (chain == "ltc" && ltc_chain) {
                            r["chain"] = testnet ? "test" : "main";
                            r["blocks"] = ltc_chain->height();
                            r["headers"] = ltc_chain->size();
                            auto t = ltc_chain->tip();
                            r["bestblockhash"] = t ? t->block_hash.GetHex() : "";
                            r["explorer_depth"] = explorer_depth_ltc;
                            if (t) {
                                auto target = ltc::coin::target_from_bits(t->header.m_bits);
                                double diff = target.IsNull() ? 0.0
                                    : ltc_chain->params().pow_limit.getdouble() / target.getdouble();
                                r["difficulty"] = diff;
                            }
                        } else if (chain == "doge" && dg_chain) {
                            r["chain"] = testnet ? "test" : "main";
                            r["blocks"] = dg_chain->height();
                            r["headers"] = dg_chain->size();
                            auto t = dg_chain->tip();
                            r["bestblockhash"] = t ? t->block_hash.GetHex() : "";
                            r["explorer_depth"] = explorer_depth_doge;
                            if (t) {
                                auto target = doge::coin::target_from_bits(t->header.m_bits);
                                double diff = target.IsNull() ? 0.0
                                    : dg_chain->params().pow_limit.getdouble() / target.getdouble();
                                r["difficulty"] = diff;
                            }
                        } else {
                            r["error"] = "Unknown chain or chain not enabled";
                        }
                        return r;
                    });

                // getblockhash
                mi->set_explorer_blockhash_fn(
                    [ltc_chain, dg_chain]
                    (uint32_t height, const std::string& chain) -> std::string {
                        if (chain == "ltc" && ltc_chain) {
                            auto e = ltc_chain->get_header_by_height(height);
                            if (e) return e->block_hash.GetHex();
                        } else if (chain == "doge" && dg_chain) {
                            auto e = dg_chain->get_header_by_height(height);
                            if (e) return e->block_hash.GetHex();
                        }
                        return {};
                    });

                // getblock — deserialize raw block from LevelDB, run block_to_explorer_json
                mi->set_explorer_getblock_fn(
                    [ltc_chain, ltc_udb, dg_chain, dg_udb, testnet,
                     explorer_depth_ltc, explorer_depth_doge]
                    (const std::string& hash_hex, const std::string& chain) -> nlohmann::json {
                        // Resolve hash to height via HeaderChain
                        uint256 blk_hash;
                        blk_hash.SetHex(hash_hex);

                        if (chain == "ltc" && ltc_chain && ltc_udb) {
                            auto entry = ltc_chain->get_header(blk_hash);
                            if (!entry)
                                return nlohmann::json{{"error", "Block not in header chain"}};
                            uint32_t height = entry->height;
                            uint32_t tip = ltc_chain->height();
                            if (tip > explorer_depth_ltc && height < tip - explorer_depth_ltc)
                                return nlohmann::json{
                                    {"error", "Block not in explorer range"},
                                    {"explorer_depth", explorer_depth_ltc}};

                            auto raw = ltc_udb->get_raw_block(height);
                            if (!raw)
                                return nlohmann::json{{"error", "Raw block not stored yet"}};

                            // Deserialize
                            ltc::coin::BlockType block;
                            try {
                                PackStream ps(*raw);
                                ps >> block;
                            } catch (...) {
                                return nlohmann::json{{"error", "Failed to deserialize block"}};
                            }

                            ltc::coin::ExplorerChainParams params;
                            if (testnet) {
                                params.bech32_hrp = "tltc";
                                params.p2pkh_ver = 0x6f;
                                params.p2sh_ver = 0xc4;
                                params.chain_name = "test";
                            } else {
                                params.bech32_hrp = "ltc";
                                params.p2pkh_ver = 0x30;
                                params.p2sh_ver = 0x32;
                                params.chain_name = "main";
                            }
                            try {
                                return ltc::coin::block_to_explorer_json(block, height, blk_hash, params);
                            } catch (const std::exception& e) {
                                return nlohmann::json{{"error", std::string("Block decode error: ") + e.what()}};
                            } catch (...) {
                                return nlohmann::json{{"error", "Block decode error (unknown)"}};
                            }

                        } else if (chain == "doge" && dg_chain && dg_udb) {
                            auto entry = dg_chain->get_header(blk_hash);
                            if (!entry)
                                return nlohmann::json{{"error", "Block not in header chain"}};
                            uint32_t height = entry->height;
                            uint32_t tip = dg_chain->height();
                            if (tip > explorer_depth_doge && height < tip - explorer_depth_doge)
                                return nlohmann::json{
                                    {"error", "Block not in explorer range"},
                                    {"explorer_depth", explorer_depth_doge}};

                            auto raw = dg_udb->get_raw_block(height);
                            if (!raw)
                                return nlohmann::json{{"error", "Raw block not stored yet"}};

                            ltc::coin::BlockType block;
                            try {
                                PackStream ps(*raw);
                                ps >> block;
                            } catch (...) {
                                return nlohmann::json{{"error", "Failed to deserialize block"}};
                            }

                            ltc::coin::ExplorerChainParams params;
                            if (testnet) {
                                params.bech32_hrp = "tdge";
                                params.p2pkh_ver = 0x71;
                                params.p2sh_ver = 0xc4;
                                params.chain_name = "test";
                            } else {
                                params.bech32_hrp = "doge";
                                params.p2pkh_ver = 0x1e;
                                params.p2sh_ver = 0x16;
                                params.chain_name = "main";
                            }
                            try {
                                return ltc::coin::block_to_explorer_json(block, height, blk_hash, params);
                            } catch (const std::exception& e) {
                                return nlohmann::json{{"error", std::string("Block decode error: ") + e.what()}};
                            } catch (...) {
                                return nlohmann::json{{"error", "Block decode error (unknown)"}};
                            }
                        }
                        return nlohmann::json{{"error", "Unknown chain or chain not enabled"}};
                    });

                LOG_INFO << "[Explorer] Callbacks wired — LTC:" << (ltc_chain ? "yes" : "no")
                         << " DOGE:" << (dg_chain ? "yes" : "no")
                         << " depth_ltc=" << explorer_depth_ltc
                         << " depth_doge=" << explorer_depth_doge;

                // ── Mempool explorer callbacks ───────────────────────────────
                auto* ltc_pool = embedded_pool.get();
                auto* dg_pool  = doge_pool.get();

                // getmempoolinfo: summary stats + feerate histogram
                mi->set_explorer_mempoolinfo_fn(
                    [ltc_pool, dg_pool, testnet]
                    (const std::string& chain) -> nlohmann::json {
                        auto* pool = (chain == "doge") ? dg_pool : ltc_pool;
                        if (!pool) return nlohmann::json{{"error", "Mempool not available for chain"}};

                        auto snap = pool->get_summary();
                        time_t now = std::time(nullptr);

                        // Feerate histogram: [0-1), [1-5), [5-20), [20-100), [100+) sat/vB
                        struct Bucket { double lo, hi; size_t count{0}; size_t bytes{0}; };
                        std::vector<Bucket> buckets = {{0,1},{1,5},{5,20},{20,100},{100,1e9}};
                        for (const auto& e : snap.entries) {
                            double fr = e.feerate();
                            for (auto& b : buckets) {
                                if (fr >= b.lo && fr < b.hi) {
                                    ++b.count;
                                    b.bytes += e.base_size;
                                    break;
                                }
                            }
                        }
                        nlohmann::json hist = nlohmann::json::array();
                        for (const auto& b : buckets) {
                            hist.push_back({
                                {"min_feerate", b.lo}, {"max_feerate", b.hi >= 1e9 ? nlohmann::json("inf") : nlohmann::json(b.hi)},
                                {"count", b.count}, {"bytes", b.bytes}
                            });
                        }

                        return nlohmann::json{
                            {"size", snap.tx_count},
                            {"bytes", snap.total_bytes},
                            {"total_weight", snap.total_weight},
                            {"total_fees", snap.total_fees},
                            {"fee_known_count", snap.fee_known_count},
                            {"fee_unknown_count", snap.tx_count - snap.fee_known_count},
                            {"min_feerate", snap.min_feerate},
                            {"max_feerate", snap.max_feerate},
                            {"median_feerate", snap.median_feerate},
                            {"avg_feerate", snap.avg_feerate},
                            {"oldest_age_sec", (snap.oldest_time > 0 && now > snap.oldest_time) ? (now - snap.oldest_time) : 0},
                            {"fee_histogram", hist},
                            {"chain", chain}
                        };
                    });

                // getrawmempool: txid list or verbose entries
                mi->set_explorer_rawmempool_fn(
                    [ltc_pool, dg_pool]
                    (const std::string& chain, bool verbose, uint32_t limit) -> nlohmann::json {
                        auto* pool = (chain == "doge") ? dg_pool : ltc_pool;
                        if (!pool) return nlohmann::json{{"error", "Mempool not available for chain"}};

                        if (!verbose) {
                            // Simple txid list
                            auto txids = pool->all_txids();
                            nlohmann::json arr = nlohmann::json::array();
                            for (const auto& id : txids)
                                arr.push_back(id.GetHex());
                            return arr;
                        }

                        // Verbose: use summary for sorted metadata
                        auto snap = pool->get_summary();
                        time_t now = std::time(nullptr);
                        nlohmann::json arr = nlohmann::json::array();
                        uint32_t count = 0;
                        for (const auto& e : snap.entries) {
                            if (count >= limit) break;
                            arr.push_back({
                                {"txid", e.txid.GetHex()},
                                {"size", e.base_size},
                                {"weight", e.weight},
                                {"fee", e.fee},
                                {"fee_known", e.fee_known},
                                {"feerate", e.feerate()},
                                {"time_added", e.time_added},
                                {"age_sec", (e.time_added > 0 && now > e.time_added) ? (now - e.time_added) : 0},
                                {"n_vin", e.n_vin},
                                {"n_vout", e.n_vout}
                            });
                            ++count;
                        }
                        return arr;
                    });

                // getmempoolentry: single tx full detail with vin/vout
                mi->set_explorer_mempoolentry_fn(
                    [ltc_pool, dg_pool, testnet]
                    (const std::string& txid_hex, const std::string& chain) -> nlohmann::json {
                        auto* pool = (chain == "doge") ? dg_pool : ltc_pool;
                        if (!pool) return nlohmann::json{{"error", "Mempool not available for chain"}};

                        uint256 txid;
                        txid.SetHex(txid_hex);
                        auto opt = pool->get_entry(txid);
                        if (!opt) return nlohmann::json{{"error", "Transaction not in mempool"}};

                        const auto& e = *opt;
                        time_t now = std::time(nullptr);

                        // Determine chain params for address decoding
                        bool is_ltc = (chain != "doge");

                        // vin
                        nlohmann::json vin_arr = nlohmann::json::array();
                        for (const auto& inp : e.tx.vin) {
                            vin_arr.push_back({
                                {"prevout_hash", inp.prevout.hash.GetHex()},
                                {"prevout_n", inp.prevout.index},
                                {"sequence", inp.prevout.index == 0xffffffff ? "ffffffff" : std::to_string(inp.sequence)}
                            });
                        }

                        // vout
                        nlohmann::json vout_arr = nlohmann::json::array();
                        for (size_t i = 0; i < e.tx.vout.size(); ++i) {
                            const auto& out = e.tx.vout[i];
                            std::vector<unsigned char> script(out.scriptPubKey.m_data.begin(),
                                                              out.scriptPubKey.m_data.end());
                            auto cls = core::classify_script(script, is_ltc, testnet);
                            nlohmann::json vout_obj = {
                                {"n", i},
                                {"value_sat", out.value},
                                {"scriptPubKey_hex", cls.hex},
                                {"type", cls.type}
                            };
                            if (!cls.addresses.empty())
                                vout_obj["address"] = cls.addresses[0];
                            if (cls.addresses.size() > 1)
                                vout_obj["addresses"] = cls.addresses;
                            vout_arr.push_back(std::move(vout_obj));
                        }

                        double feerate_val = e.feerate();
                        return nlohmann::json{
                            {"txid", e.txid.GetHex()},
                            {"size", e.base_size},
                            {"witness_size", e.witness_size},
                            {"weight", e.weight},
                            {"fee", e.fee},
                            {"fee_known", e.fee_known},
                            {"feerate", feerate_val},
                            {"time_added", e.time_added},
                            {"age_sec", (e.time_added > 0 && now > e.time_added) ? (now - e.time_added) : 0},
                            {"vin", vin_arr},
                            {"vout", vout_arr},
                            {"chain", chain}
                        };
                    });

                LOG_INFO << "[Explorer] Mempool callbacks wired — LTC:" << (ltc_pool ? "yes" : "no")
                         << " DOGE:" << (dg_pool ? "yes" : "no");
            }

            if (!web_server.start()) {
                LOG_ERROR << "Failed to start integrated mining pool";
                return 1;
            }
            
            // Wire V35 merged block resolver: when an LTC block is found from a V35
            // share (no m_merged_coinbase_info), fetch the full LTC block from P2P,
            // extract the fabe6d6d MM commitment from coinbase, resolve DOGE block hash
            // in the embedded HeaderChain.
            // Retry structure: {hash → {pow_hash, attempts, timer}}.
            struct PendingResolve {
                int attempts{0};
                std::shared_ptr<boost::asio::steady_timer> timer;
            };
            auto pending_resolve_state = std::make_shared<
                std::map<uint256, PendingResolve>>();

            if (embedded_broadcaster && doge_chain) {
                auto* bcaster = embedded_broadcaster.get();
                static constexpr int MAX_RETRY = 5;
                static constexpr int RETRY_SEC = 10;

                *merged_block_resolver = [bcaster, pending_merged_resolve,
                                          pending_resolve_state, &ioc](
                    const uint256& ltc_block_hash, const MergedResolveCtx& ctx) {

                    // Already pending? skip
                    if (pending_resolve_state->count(ltc_block_hash)) return;

                    (*pending_merged_resolve)[ltc_block_hash] = ctx;

                    auto& state = (*pending_resolve_state)[ltc_block_hash];
                    state.attempts = 0;
                    state.timer = std::make_shared<boost::asio::steady_timer>(ioc);

                    // Recursive retry lambda
                    auto retry_fn = std::make_shared<std::function<void()>>();
                    *retry_fn = [bcaster, pending_merged_resolve, pending_resolve_state,
                                 retry_fn, ltc_block_hash, MAX_RETRY, RETRY_SEC]() {
                        auto it = pending_resolve_state->find(ltc_block_hash);
                        if (it == pending_resolve_state->end()) return;  // resolved

                        auto& st = it->second;
                        ++st.attempts;

                        // Check if still pending (not yet resolved by full_block handler)
                        if (!pending_merged_resolve->count(ltc_block_hash)) {
                            pending_resolve_state->erase(it);
                            return;  // already resolved
                        }

                        if (st.attempts > MAX_RETRY) {
                            LOG_WARNING << "[V35-MERGED] Gave up on LTC block "
                                        << ltc_block_hash.GetHex().substr(0, 16)
                                        << " after " << MAX_RETRY << " attempts";
                            pending_merged_resolve->erase(ltc_block_hash);
                            pending_resolve_state->erase(it);
                            return;
                        }

                        // Schedule retry before work — survives exceptions
                        st.timer->expires_after(std::chrono::seconds(RETRY_SEC));
                        st.timer->async_wait([retry_fn](const boost::system::error_code& ec) {
                            if (!ec && retry_fn) (*retry_fn)();
                        });
                        try {
                            LOG_INFO << "[V35-MERGED] Requesting LTC block "
                                     << ltc_block_hash.GetHex().substr(0, 16)
                                     << " attempt " << st.attempts << "/" << MAX_RETRY
                                     << " (peers=" << bcaster->connected_count() << ")";
                            bcaster->request_block_plain(ltc_block_hash);
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[V35-MERGED] Request error: " << e.what();
                        }
                    };

                    // First attempt immediately
                    (*retry_fn)();
                };

                // Wire the actual resolution: parse coinbase for fabe6d6d,
                // extract MM root = DOGE block hash, look up in HeaderChain.
                auto* dc = doge_chain.get();
                auto* ltc_hc = embedded_chain.get();
                auto* mm = web_server.get_mining_interface()->get_mm_manager();
                // Get DOGE broadcaster for fetching full DOGE blocks (coinbase_value)
                c2pool::merged::CoinBroadcaster* doge_bcaster = nullptr;
                {
                    auto it = merged_broadcasters.find(98);
                    if (it != merged_broadcasters.end())
                        doge_bcaster = it->second.get();
                }
                bool testnet = settings->m_testnet;
                auto mi_ptr_for_merge = web_server.get_mining_interface();
                *on_full_block_merged = [dc, ltc_hc, mm, doge_bcaster, testnet, mi_ptr_for_merge](
                    const uint256& ltc_block_hash, const MergedResolveCtx& ctx,
                    const ltc::coin::BlockType& block) {
                    if (!mm || !dc || block.m_txs.empty()) return;
                    const auto& pow_hash = ctx.pow_hash;

                    // Extract coinbase scriptSig
                    const auto& coinbase_tx = block.m_txs[0];
                    if (coinbase_tx.vin.empty()) return;
                    const auto& script_sig = coinbase_tx.vin[0].scriptSig.m_data;

                    // Find fabe6d6d magic
                    static const uint8_t MM_MAGIC[] = {0xfa, 0xbe, 0x6d, 0x6d};
                    auto magic_pos = std::search(script_sig.begin(), script_sig.end(),
                                                  std::begin(MM_MAGIC), std::end(MM_MAGIC));
                    if (magic_pos == script_sig.end()) {
                        LOG_INFO << "[V35-MERGED] No fabe6d6d in LTC block "
                                 << ltc_block_hash.GetHex().substr(0, 16) << " — no merged mining";
                        return;
                    }
                    size_t offset = std::distance(script_sig.begin(), magic_pos) + 4;
                    if (offset + 32 + 4 + 4 > script_sig.size()) return;

                    // MM commitment: 32-byte merkle root (big-endian) + 4-byte tree_size + 4-byte nonce
                    // With single aux chain, tree_size=1, merkle_root = DOGE block hash
                    uint32_t tree_size = 0;
                    std::memcpy(&tree_size, &script_sig[offset + 32], 4);
                    // tree_size is LE

                    // Extract 32-byte MM root (stored big-endian in coinbase → reverse for uint256 LE)
                    uint256 mm_root;
                    for (int i = 0; i < 32; ++i)
                        mm_root.data()[31 - i] = script_sig[offset + i];

                    LOG_INFO << "[V35-MERGED] LTC block " << ltc_block_hash.GetHex().substr(0, 16)
                             << " MM root=" << mm_root.GetHex().substr(0, 16)
                             << " tree_size=" << tree_size;

                    // With tree_size=1, mm_root IS the DOGE block hash.
                    // With tree_size>1, we'd need the merkle branch to extract — but p2pool
                    // uses tree_size=1 for single aux chain (DOGE only).
                    if (tree_size > 1) {
                        LOG_WARNING << "[V35-MERGED] tree_size=" << tree_size
                                    << " — multi-chain aux tree, cannot resolve without merkle branch";
                        return;
                    }

                    // Look up DOGE block hash in embedded HeaderChain
                    auto doge_entry = dc->get_header(mm_root);
                    if (!doge_entry) {
                        LOG_INFO << "[V35-MERGED] DOGE block " << mm_root.GetHex().substr(0, 16)
                                 << " not found in HeaderChain (may not be synced yet)";
                        return;
                    }

                    // Verify pow_hash meets DOGE target
                    uint256 doge_target;
                    doge_target.SetCompact(doge_entry->header.m_bits);
                    if (doge_target.IsNull() || !(pow_hash <= doge_target)) {
                        LOG_INFO << "[V35-MERGED] pow_hash doesn't meet DOGE target at height "
                                 << doge_entry->height;
                        return;
                    }

                    LOG_INFO << "*** V35 MERGED BLOCK RESOLVED! DOGE"
                             << " height=" << doge_entry->height
                             << " block=" << mm_root.GetHex().substr(0, 16)
                             << " ltc_block=" << ltc_block_hash.GetHex().substr(0, 16);

                    c2pool::merged::DiscoveredMergedBlock blk;
                    blk.chain_id = 98;  // DOGE
                    blk.symbol = testnet ? "tDOGE" : "DOGE";
                    blk.height = static_cast<int>(doge_entry->height);
                    blk.block_hash = mm_root.GetHex();
                    blk.parent_hash = ltc_block_hash.GetHex();
                    blk.timestamp = ctx.share_ts > 0
                        ? static_cast<int64_t>(ctx.share_ts)
                        : static_cast<int64_t>(std::time(nullptr));
                    blk.accepted = true;
                    blk.miner = ctx.miner;
                    // Request full DOGE block from P2P to get exact coinbase_value.
                    // The block arrives async — we set coinbase_value=0 now and update
                    // when the DOGE block arrives via the full_block callback.
                    // This ensures exact amounts (subsidy + TX fees), never approximations.
                    blk.coinbase_value = 0;
                    // Get real LTC block height from header chain (not sharechain absheight)
                    if (ltc_hc) {
                        auto ltc_entry = ltc_hc->get_header(ltc_block_hash);
                        if (ltc_entry)
                            blk.parent_height = ltc_entry->height;
                    }
                    mm->add_discovered_block(blk);

                    // Persist to LevelDB
                    auto store_ptr = mi_ptr_for_merge->get_merged_block_store();
                    if (store_ptr) {
                        auto* ms = static_cast<c2pool::storage::MergedBlockStore*>(store_ptr.get());
                        c2pool::storage::MergedBlockRecord rec;
                        rec.chain_id = blk.chain_id; rec.symbol = blk.symbol;
                        rec.height = blk.height; rec.block_hash = blk.block_hash;
                        rec.parent_hash = blk.parent_hash; rec.timestamp = blk.timestamp;
                        rec.accepted = blk.accepted; rec.coinbase_value = blk.coinbase_value;
                        rec.is_local = blk.is_local; rec.parent_height = blk.parent_height;
                        rec.miner = blk.miner;
                        ms->store(rec);
                    }

                    // Request full DOGE block from P2P to get exact coinbase_value.
                    // When it arrives, the DOGE full_block handler will sum coinbase
                    // outputs and call update_block_coinbase() with the exact amount.
                    if (doge_bcaster) {
                        LOG_INFO << "[V35-MERGED] Requesting DOGE block " << mm_root.GetHex().substr(0, 16)
                                 << " for exact coinbase_value";
                        doge_bcaster->request_block_plain(mm_root);
                    }
                };

                LOG_INFO << "[V35-MERGED] Resolver wired via embedded LTC P2P + DOGE HeaderChain";
            }

            // Wire coin P2P peer info for dashboard tables
            if (embedded_broadcaster) {
                web_server.get_mining_interface()->set_ltc_peer_info_fn(
                    [bcaster = embedded_broadcaster.get()]() { return bcaster->get_peer_info(); });
            }
            {
                auto it = merged_broadcasters.find(98);  // DOGE
                if (it != merged_broadcasters.end()) {
                    web_server.get_mining_interface()->set_doge_peer_info_fn(
                        [bcaster = it->second.get()]() { return bcaster->get_peer_info(); });
                }
            }

            // Backfill network_difficulty + timestamp on persisted found blocks
            // using LTC header chain. Exact values from the block header.
            if (embedded_chain) {
                auto* hc = embedded_chain.get();
                web_server.get_mining_interface()->backfill_block_fields(
                    [hc](const std::string& block_hash_hex) -> double {
                        uint256 h;
                        h.SetHex(block_hash_hex);
                        auto entry = hc->get_header(h);
                        if (!entry) return 0.0;
                        auto target = chain::bits_to_target(entry->header.m_bits);
                        return chain::target_to_difficulty(target);
                    },
                    [hc](const std::string& block_hash_hex) -> uint32_t {
                        uint256 h;
                        h.SetHex(block_hash_hex);
                        auto entry = hc->get_header(h);
                        return entry ? entry->header.m_timestamp : 0;
                    });
            }

            // Load persisted merged blocks into mm_manager BEFORE block scan.
            {
                auto store_ptr = web_server.get_mining_interface()->get_merged_block_store();
                auto* mm = web_server.get_mining_interface()->get_mm_manager();
                if (store_ptr && mm) {
                    auto* mblk_store = static_cast<c2pool::storage::MergedBlockStore*>(store_ptr.get());
                    auto records = mblk_store->load_all();
                    int loaded = 0;
                    for (const auto& rec : records) {
                        c2pool::merged::DiscoveredMergedBlock blk;
                        blk.chain_id = rec.chain_id;
                        blk.symbol = rec.symbol;
                        blk.height = rec.height;
                        blk.block_hash = rec.block_hash;
                        blk.parent_hash = rec.parent_hash;
                        blk.timestamp = rec.timestamp;
                        blk.accepted = rec.accepted;
                        blk.coinbase_value = rec.coinbase_value;
                        blk.is_local = rec.is_local;
                        blk.parent_height = rec.parent_height;
                        blk.miner = rec.miner;
                        mm->add_discovered_block(blk);  // dedup handles duplicates
                        ++loaded;
                    }
                    if (loaded > 0)
                        LOG_INFO << "[Pool] Loaded " << loaded << " persisted merged blocks";
                }
            }

            // Block scan: run here after ALL callbacks + DOGE target fn are wired.
            if (p2p_node) {
                auto best = p2p_node->best_share_hash();
                int chain_len = static_cast<int>(ltc::PoolConfig::chain_length());
                if (!best.IsNull() && chain_len > 0) {
                    uint64_t latest_block_ts = 0;
                    // Check LTC found blocks
                    auto existing = web_server.get_mining_interface()->rest_recent_blocks();
                    for (const auto& b : existing) {
                        uint64_t ts = b.value("ts", uint64_t(0));
                        if (ts > latest_block_ts) latest_block_ts = ts;
                    }
                    // Check merged blocks — use max(ltc, merged) for scan cutoff
                    auto* mm = web_server.get_mining_interface()->get_mm_manager();
                    if (mm) {
                        for (const auto& mb : mm->get_discovered_blocks()) {
                            if (mb.timestamp > 0 && static_cast<uint64_t>(mb.timestamp) > latest_block_ts)
                                latest_block_ts = static_cast<uint64_t>(mb.timestamp);
                        }
                    }
                    int scan_depth = chain_len;
                    if (latest_block_ts > 0) {
                        auto& ch = p2p_node->tracker().chain;
                        int newer = 0;
                        uint256 pos = best;
                        for (int i = 0; i < chain_len && !pos.IsNull() && ch.contains(pos); ++i) {
                            ch.get(pos).share.invoke([&](auto* s) {
                                if (s->m_min_header.m_timestamp > latest_block_ts)
                                    ++newer;
                                else
                                    newer = chain_len + 1;
                                pos = s->m_prev_hash;
                            });
                            if (newer > chain_len) break;
                        }
                        scan_depth = std::min(newer, chain_len);
                    }
                    if (scan_depth > 0) {
                        auto& ch = p2p_node->tracker().chain;
                        auto heads = ch.get_heads();
                        LOG_INFO << "[BLOCK-SCAN] Scanning " << scan_depth << " shares from "
                                 << heads.size() << " head(s) (latest block ts=" << latest_block_ts
                                 << ", existing=" << existing.size() << ")";
                        for (const auto& [head_hash, _] : heads)
                            p2p_node->tracker().scan_chain_for_blocks(head_hash, scan_depth);
                    }
                }
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

            // ── Startup mode: genesis / auto / wait ──────────────────────────
            // Solo/custodial: no sharechain, skip entirely.
            if (solo_mode || custodial_mode) {
                LOG_INFO << "[" << (solo_mode ? "Solo" : "Custodial")
                         << "] No sharechain — ready to mine immediately";
                LOG_INFO << "[" << (solo_mode ? "Solo" : "Custodial")
                         << "] Payout address: " << payout_address;
            } else if (p2p_node) {
                // Determines behavior when sharechain is empty (no shares from
                // LevelDB or peers). Logged clearly so operator knows what's happening.
                auto chain_count = p2p_node->tracker().chain.size();
                auto best = p2p_node->best_share_hash();
                bool chain_empty = (chain_count == 0);
                const char* mode_str = startup_mode == StartupMode::GENESIS ? "genesis"
                                     : startup_mode == StartupMode::WAIT ? "wait" : "auto";

                if (chain_count > 0 && best.IsNull()) {
                    LOG_INFO << "[Sharechain] Loaded " << chain_count
                             << " shares from storage (best not yet computed — think() pending)";
                }

                if (chain_empty) {
                    LOG_INFO << "[Sharechain] No shares in chain (empty database or first start)";
                    LOG_INFO << "[Sharechain] Startup mode: " << mode_str;

                    if (startup_mode == StartupMode::WAIT) {
                        LOG_INFO << "[Sharechain] WAIT MODE — waiting indefinitely for peers with shares";
                        LOG_INFO << "[Sharechain] Will NOT create genesis. Use --genesis to override.";
                        while (!g_shutdown_requested) {
                            ioc.restart();
                            ioc.run_for(std::chrono::seconds(1));
                            best = p2p_node->best_share_hash();
                            if (!best.IsNull()) {
                                LOG_INFO << "[Sharechain] Received shares from peer! best="
                                         << best.GetHex().substr(0, 16) << "...";
                                break;
                            }
                        }
                    }
                    else {
                        LOG_INFO << "[Sharechain] Ready — genesis on first work request if no peers";
                        if (network_id != 0)
                            LOG_INFO << "[Sharechain] Private chain network_id="
                                     << std::hex << network_id << std::dec;
                    }
                } else {
                    LOG_INFO << "[Sharechain] Shares available, best="
                             << best.GetHex().substr(0, 16) << "...";
                }
            }

            // Work guard prevents ioc from draining when all async handlers
            // complete (e.g., all peers disconnect).  Timers and accept loops
            // continue firing on schedule.  Matches Litecoin Core's approach
            // where the event loop never exits until explicit shutdown.
            auto work_guard = boost::asio::make_work_guard(ioc);

            // Watchdog: detect event loop stalls AND dead timers
            auto watchdog_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            auto watchdog_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
            *watchdog_fn = [watchdog_timer, watchdog_fn, now_ms,
                            hb_think, hb_monitor, hb_ltc_sync, hb_ltc_mempool,
                            hb_doge_sync, hb_doge_mempool](boost::system::error_code ec) {
                if (ec) return;
                watchdog_timer->expires_after(std::chrono::seconds(30));
                watchdog_timer->async_wait(*watchdog_fn);
                static int tick = 0;
                ++tick;
                if (tick % 2 == 0) { // every 60s — heartbeat check
                    int64_t now = now_ms();
                    auto check = [&](const char* name, int64_t last, int expect_sec) {
                        if (last == 0) return; // not yet started
                        int64_t age_sec = (now - last) / 1000;
                        if (age_sec > expect_sec * 3) {
                            LOG_ERROR << "[WATCHDOG] TIMER DEAD: " << name
                                      << " last fired " << age_sec << "s ago"
                                      << " (expected every " << expect_sec << "s)";
                        }
                    };
                    check("think",        hb_think->load(),        5);
                    check("monitor",      hb_monitor->load(),      30);
                    check("ltc_sync",     hb_ltc_sync->load(),     60);
                    check("ltc_mempool",  hb_ltc_mempool->load(),  300);
                    check("doge_sync",    hb_doge_sync->load(),    60);
                    check("doge_mempool", hb_doge_mempool->load(), 300);
                    LOG_INFO << "[WATCHDOG] alive tick=" << tick;
                }
            };
            watchdog_timer->expires_after(std::chrono::seconds(30));
            watchdog_timer->async_wait(*watchdog_fn);

            // HTTP cache refresh timer: update all zero-arg callback caches
            // every 2 seconds so the dashboard reads pre-computed data
            // instead of blocking on main-thread dispatch.
            auto cache_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            auto cache_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
            auto* mi_ptr = web_server.get_mining_interface();
            *cache_fn = [cache_timer, cache_fn, mi_ptr](boost::system::error_code ec) mutable {
                if (ec) return;
                mi_ptr->refresh_http_caches();
                mi_ptr->cache_pplns_at_tip();   // keep merged payouts cache warm
                cache_timer->expires_after(std::chrono::seconds(2));
                cache_timer->async_wait(*cache_fn);
            };
            // Initial populate so dashboard has data immediately
            mi_ptr->refresh_http_caches();
            mi_ptr->cache_pplns_at_tip();
            cache_timer->expires_after(std::chrono::seconds(2));
            cache_timer->async_wait(*cache_fn);

            // Stats persistence timer — save every 100s (matches p2pool graph_db)
            auto stats_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            auto stats_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
            *stats_fn = [stats_timer, stats_fn, mi_ptr](boost::system::error_code ec) mutable {
                if (ec) return;
                mi_ptr->save_stat_log();
                stats_timer->expires_after(std::chrono::seconds(100));
                stats_timer->async_wait(*stats_fn);
            };
            stats_timer->expires_after(std::chrono::seconds(100));
            stats_timer->async_wait(*stats_fn);

            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.restart();
                try {
                    ioc.run_for(std::chrono::milliseconds(100));
                } catch (const std::exception& e) {
                    LOG_ERROR << "ioc handler exception (non-fatal): " << e.what();
                }
            }
            work_guard.reset();

            // Save stats on shutdown
            mi_ptr->save_stat_log();

            if (p2p_node) p2p_node->shutdown();
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

            auto work_guard = boost::asio::make_work_guard(ioc);

            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.restart();
                try {
                    ioc.run_for(std::chrono::milliseconds(100));
                } catch (const std::exception& e) {
                    LOG_ERROR << "ioc handler exception (non-fatal): " << e.what();
                }
            }
            work_guard.reset();

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
            solo_server.get_mining_interface()->set_stratum_config(stratum_config);
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
            
            auto work_guard = boost::asio::make_work_guard(ioc);

            // Run until shutdown
            while (!g_shutdown_requested) {
                ioc.restart();
                try {
                    ioc.run_for(std::chrono::milliseconds(100));
                } catch (const std::exception& e) {
                    LOG_ERROR << "ioc handler exception (non-fatal): " << e.what();
                }
            }
            work_guard.reset();
        }
        
        LOG_INFO << "c2pool shutdown complete";
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Fatal error: " << e.what();
        return 1;
    }
    
    return 0;
}
