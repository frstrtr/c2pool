// c2pool-btc — Bitcoin embedded SPV p2pool node.
//
// PR-B2-net (focused header-sync entry point).
//
// Wires `btc::coin::HeaderChain` to a single `btc::coin::Node` connection
// against a known bitcoind P2P endpoint. No sharechain, stratum, mempool,
// template builder, broadcaster, or web dashboard — those land in B3+.
//
// This main is small on purpose: it's the smoke-test target for verifying
// that the BTC port (jtoomim/SPB v35 + protocol 3502 + SHA256d PoW + BTC
// genesis + DAA) actually handshakes with bitcoind, sends getheaders,
// receives the response, and ingests headers into HeaderChain.
//
// Usage:
//   c2pool-btc --bitcoind HOST:PORT [--testnet | --testnet4]
//
// Examples:
//   c2pool-btc --testnet4 --bitcoind 127.0.0.1:48333
//   c2pool-btc --testnet  --bitcoind 127.0.0.1:18333
//   c2pool-btc           --bitcoind 127.0.0.1:8333
//
// Reference port from src/c2pool/c2pool_refactored.cpp lines 1500-1900
// (LTC's HeaderChain + EmbeddedCoinNode wiring), pruned to a single-peer
// non-broadcaster shape suitable for B2-net smoke testing.

#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/coin/node.hpp>
#include <impl/btc/coin/node_interface.hpp>
#include <impl/btc/config.hpp>

#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/asio.hpp>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace io = boost::asio;

static std::atomic<bool> g_should_stop{false};
static io::io_context*   g_ioc = nullptr;

static void handle_signal(int /*sig*/)
{
    g_should_stop.store(true);
    if (g_ioc) g_ioc->stop();
}

static void print_usage()
{
    std::cerr <<
        "Usage: c2pool-btc [--testnet | --testnet4] --bitcoind HOST:PORT\n"
        "\n"
        "  --testnet       BTC testnet3 chain (genesis 000000000933ea01...)\n"
        "  --testnet4      BTC testnet4 chain (genesis 00000000da84f2ba...)\n"
        "                  default: mainnet\n"
        "  --bitcoind H:P  bitcoind P2P endpoint host:port\n"
        "                  e.g. 127.0.0.1:8333  (mainnet)\n"
        "                       127.0.0.1:18333 (testnet3)\n"
        "                       127.0.0.1:48333 (testnet4)\n";
}

/// BTC wire-protocol magic bytes per network (pchMessageStart).
/// Source: ref/bitcoin/src/kernel/chainparams.cpp.
static std::vector<std::byte> btc_magic_bytes(bool testnet, bool testnet4)
{
    std::string hex;
    if (testnet4)      hex = "1c163f28";   // testnet4 (line 335-338)
    else if (testnet)  hex = "0b110907";   // testnet3 (line 235-238)
    else               hex = "f9beb4d9";   // mainnet  (line 117-120)
    return ParseHexBytes(hex);
}

int main(int argc, char* argv[])
{
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    core::log::Logger::init();

    bool        testnet       = false;
    bool        testnet4      = false;
    std::string bitcoind_host;
    uint16_t    bitcoind_port = 0;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help")
        {
            print_usage();
            return 0;
        }
        else if (arg == "--testnet")
        {
            testnet = true;
        }
        else if (arg == "--testnet4")
        {
            testnet  = true;
            testnet4 = true;
        }
        else if (arg == "--bitcoind" && i + 1 < argc)
        {
            std::string ep = argv[++i];
            auto colon = ep.find(':');
            if (colon == std::string::npos)
            {
                std::cerr << "--bitcoind requires HOST:PORT\n";
                return 1;
            }
            bitcoind_host = ep.substr(0, colon);
            bitcoind_port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
        }
        else
        {
            std::cerr << "unknown arg: " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    if (bitcoind_host.empty() || bitcoind_port == 0)
    {
        print_usage();
        return 1;
    }

    btc::PoolConfig::is_testnet = testnet;

    auto chain_params = testnet4
        ? btc::coin::BTCChainParams::testnet4()
        : (testnet ? btc::coin::BTCChainParams::testnet()
                   : btc::coin::BTCChainParams::mainnet());

    const std::string net_subdir = testnet4 ? "bitcoin_testnet4"
                                : (testnet  ? "bitcoin_testnet"
                                            : "bitcoin");

    const std::filesystem::path net_dir = core::filesystem::config_path() / net_subdir;
    std::error_code ec;
    std::filesystem::create_directories(net_dir, ec);  // best effort

    const std::string chain_db_path = (net_dir / "embedded_headers").string();

    LOG_INFO << "[BTC] c2pool-btc starting — net="
             << (testnet4 ? "testnet4" : (testnet ? "testnet3" : "mainnet"));
    LOG_INFO << "[BTC] HeaderChain DB: " << chain_db_path;
    LOG_INFO << "[BTC] Genesis:        " << chain_params.genesis_hash.GetHex();
    LOG_INFO << "[BTC] bitcoind P2P:   " << bitcoind_host << ":" << bitcoind_port;

    btc::coin::HeaderChain header_chain(chain_params, chain_db_path);
    if (!header_chain.init())
    {
        LOG_WARNING << "[BTC] HeaderChain init failed — running in-memory only";
    }
    else
    {
        LOG_INFO << "[BTC] HeaderChain initialized: size=" << header_chain.size()
                 << " height=" << header_chain.height();
    }

    io::io_context ioc;
    g_ioc = &ioc;

    // btc::Config = core::Config<PoolConfig, CoinConfig> — composite holds
    // both the c2pool sharechain identity (PoolConfig: prefix/identifier
    // from B1) AND the bitcoind wire-protocol identity (CoinConfig::m_p2p:
    // BTC magic bytes per network). NodeP2P reads m_config->coin()->m_p2p.prefix
    // to frame outbound bitcoind messages — getting this wrong = peer
    // disconnect.
    btc::Config config(net_subdir);
    // Skip Config::init() — it would try to load pool.yaml + coin.yaml
    // from disk; for B2-net smoke we set fields directly from chainparams.
    config.coin()->m_p2p.prefix  = btc_magic_bytes(testnet, testnet4);
    config.coin()->m_p2p.address = NetService(bitcoind_host, bitcoind_port);
    config.coin()->m_testnet     = testnet;
    config.coin()->m_symbol      = "BTC";

    btc::coin::Node<btc::Config> coin_node(&ioc, &config);

    // Constants for getheaders driver: protocol version sent in the message
    // (matches what we advertised in version handshake — see B1 coin/p2p_node.hpp).
    constexpr uint32_t BTC_PROTOCOL_VERSION = 70016;

    // Hash a BlockHeaderType into its canonical block-id (SHA256d of the
    // 80-byte serialized header). BTC unifies pow_hash and block_hash via
    // SHA256d; LTC distinguishes them (scrypt vs SHA256d). Used to compute
    // the locator for the next getheaders.
    auto header_block_hash = [](const btc::coin::BlockHeaderType& hdr) {
        auto packed = pack(hdr);
        return Hash(packed.get_span());
    };

    // Forward bitcoind's headers batches into HeaderChain AND chain the
    // getheaders locator forward to drive sync to peer's tip. LTC dispatches
    // this off-thread (scrypt CPU cost); BTC's PoW is SHA256d so inline is
    // fine for testnet (and for mainnet IBD too, given SHA256d is ~us/header).
    coin_node.new_headers.subscribe(
        [&header_chain, &coin_node, header_block_hash, &chain_params]
        (const std::vector<btc::coin::BlockHeaderType>& headers)
        {
            if (headers.empty()) return;
            int accepted = header_chain.add_headers(headers);
            uint256 last_hash = header_block_hash(headers.back());
            LOG_INFO << "[BTC] new_headers: received=" << headers.size()
                     << " accepted=" << accepted
                     << " chain_height=" << header_chain.height()
                     << " last=" << last_hash.GetHex().substr(0, 16);
            // Continue header sync if peer likely has more (full 2000-header
            // batch); otherwise we're caught up and bitcoind will push new
            // tips via inv/sendheaders.
            if (headers.size() >= 2000) {
                coin_node.send_getheaders(
                    BTC_PROTOCOL_VERSION, {last_hash}, uint256::ZERO);
            } else {
                LOG_INFO << "[BTC] Header sync caught up (last batch=" << headers.size()
                         << " < 2000). Waiting on inv announcements.";
            }
            (void)chain_params;  // captured for genesis fallback if needed later
        });

    coin_node.new_block.subscribe(
        [](const uint256& block_hash)
        {
            LOG_INFO << "[BTC] new_block: " << block_hash.GetHex().substr(0, 32) << "...";
        });

    LOG_INFO << "[BTC] Connecting to bitcoind...";
    coin_node.start_p2p(NetService(bitcoind_host, bitcoind_port));

    // Drive initial header sync. Per BTC protocol, NodeP2P's verack handler
    // sends sendheaders/sendcmpct/feefilter but NOT getheaders — header sync
    // is the consumer's responsibility (LTC drives this from the broadcaster).
    // Wait 3s for handshake to complete, then send getheaders([genesis], 0)
    // to start streaming headers from genesis. The new_headers callback above
    // chains the locator forward for the next batch.
    boost::asio::steady_timer initial_getheaders(ioc);
    initial_getheaders.expires_after(std::chrono::seconds(3));
    initial_getheaders.async_wait(
        [&coin_node, &header_chain, &chain_params, header_block_hash]
        (const boost::system::error_code& ec)
        {
            if (ec) return;
            if (!coin_node.has_p2p()) {
                LOG_WARNING << "[BTC] initial getheaders: no P2P connection yet";
                return;
            }
            if (!coin_node.is_handshake_complete()) {
                LOG_WARNING << "[BTC] initial getheaders: handshake not complete (peer slow?)";
                // Fire anyway — at worst the peer ignores and we retry later.
            }
            // Locator: if HeaderChain has any tip, use it; else genesis.
            // For a fresh DB the chain is empty so locator = [genesis].
            uint256 locator = (header_chain.height() > 0)
                ? uint256::ZERO  // header_chain.tip_hash() if exposed; placeholder
                : chain_params.genesis_hash;
            LOG_INFO << "[BTC] Sending initial getheaders, locator="
                     << locator.GetHex().substr(0, 16)
                     << " (chain_height=" << header_chain.height() << ")";
            coin_node.send_getheaders(
                BTC_PROTOCOL_VERSION, {locator}, uint256::ZERO);
        });

    LOG_INFO << "[BTC] io_context running. Ctrl-C to stop.";
    ioc.run();
    LOG_INFO << "[BTC] Shutting down.";
    return 0;
}
