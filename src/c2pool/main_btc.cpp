// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <impl/btc/coin/tip_reconcile_gate.hpp> // B5b: TipReconcileGate SSOT (10s re-poll cadence + fire predicate) shared with tip_reconcile_test.cpp
#include <impl/btc/coin/mempool.hpp>
#include <impl/btc/coin/node.hpp>
#include <impl/btc/coin/coin_peer_manager.hpp> // btc::coin::BtcCoinPeerManager -- BTC-ISOLATED scored/diverse coin-network peer discovery (--coin-p2p-discover)
#include <impl/btc/coin/chain_seeds.hpp>        // btc::coin::btc_dns_seeds / btc_fixed_seeds
#include <impl/btc/coin/node_interface.hpp>
#include <impl/btc/coin/transaction.hpp>
#include <impl/btc/config.hpp>
#include <impl/btc/config_pool.hpp>
#include <impl/btc/coin/rpc_conf.hpp>   // bitcoin.conf creds for the submitblock RPC backup (ARM B, #82/#744)
#include <impl/btc/node.hpp>
#include <impl/btc/auto_ratchet.hpp>     // AutoRatchet V35->V36 forward-version-voting
#include <impl/btc/share_check.hpp>      // RefHashParams + compute_ref_hash_for_work
#include <impl/btc/share_tracker.hpp>    // get_v35_expected_payouts
#include <impl/btc/stratum/work_source.hpp>
#include <impl/btc/coin/template_capture.hpp>     // per-share template retain -> won-block reconstruct (slice 7/7)
#include <impl/btc/coin/template_other_txs.hpp>    // make_template_other_txs_fn bridge (#840)
#include <impl/btc/coin/reconstruct_won_block.hpp> // make_reconstruct_closure — faithful won-block body (#839)
#include <impl/btc/coin/won_block_dispatch.hpp>    // make_on_block_found — dual-path won-block dispatch (#744)
#include <impl/btc/coin/block_confirm.hpp>       // #995/#1155 found-block confirm/orphan resolver
#include <impl/btc/coin/merged_spec.hpp>          // parse --merged SPEC -> AuxChainConfig (NMC PE host-wire slice 3)
#include <impl/btc/coin/merged_backend.hpp>       // build aux backends + merged_addr payout seam (NMC PE host-wire slice 4)
// PA/PB: embedded NMC SPV aux backend (daemonless --merged NMC) — mirrors the
// #1387 main_ltc wiring: AuxChainEmbedded primary + AuxChainRPC fallback +
// NMC coin-P2P header-feed (seeds + AuxPoW-preserving raw-headers sink).
#include <impl/nmc/coin/aux_chain_embedded.hpp>   // nmc::coin::AuxChainEmbedded + HeaderChain + Mempool
#include <impl/nmc/coin/chain_seeds.hpp>          // nmc_dns_seeds / nmc_fixed_seeds (#980)
#include <impl/nmc/coin/headers_wire.hpp>         // parse_nmc_headers_message (AuxPoW intact)
#include <impl/ltc/config_coin.hpp>               // ltc::config::P2PData/RPCData — BroadcasterConfig adapter dep (coin_broadcaster.hpp; main_ltc pulls it via config.hpp)
#include <c2pool/merged/coin_broadcaster.hpp>     // CoinBroadcaster (NMC coin-P2P header-feed)

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/stratum_server.hpp>
#include <core/web_server.hpp>          // H-STATS.944: operator dashboard + graph_db persist
#include <btclibs/util/strencodings.h>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>            // #1155 found-block record timestamp
#include <limits>           // #1155 found-block RPC-fallback sentinel
#include <optional>         // #1155 found-block winner_at oracle
#include <cstdio>           // [MEM] periodic logger reads /proc/self/status
#if defined(__GLIBC__)
#include <malloc.h>         // [MEM] periodic malloc_trim(0) bounds glibc pool fragmentation (glibc-only)
#endif
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace io = boost::asio;

static void print_usage()
{
    std::cerr <<
        "Usage: c2pool-btc [--testnet | --testnet4 | --regtest] --bitcoind HOST:PORT\n"
        "                  [--p2pool HOST:PORT]\n"
        "\n"
        "  --testnet       BTC testnet3 chain (genesis 000000000933ea01...)\n"
        "  --testnet4      BTC testnet4 chain (genesis 00000000da84f2ba...)\n"
        "  --regtest       BTC regtest chain (genesis 0f9188f13cb7b2c7...)\n"
        "                  default: mainnet\n"
        "  --data-dir PATH root all per-instance state here (default ~/.c2pool).\n"
        "                  Isolates co-located instances so they don't contend\n"
        "                  the LevelDB LOCK.\n"
        "  --bitcoind H:P  bitcoind P2P endpoint host:port\n"
        "                  e.g. 127.0.0.1:8333  (mainnet)\n"
        "                       127.0.0.1:18333 (testnet3)\n"
        "                       127.0.0.1:48333 (testnet4)\n"
        "                       127.0.0.1:18443 (regtest)\n"
        "  --p2pool H:P    BTC p2pool peer (jtoomim/SPB v35 + protocol 3502)\n"
        "                  e.g. p2p-spb.xyz:9333\n"
        "  --stratum [H:]P stratum TCP listener for miners (B4-stratum)\n"
        "                  e.g. --stratum 9332           (binds 0.0.0.0:9332)\n"
        "                       --stratum 127.0.0.1:9332 (loopback only)\n"
        "                  Omit to disable stratum listener.\n"
        "  --sharechain-port P  bind the sharechain (pool P2P) listener on\n"
        "                  port P instead of the default 9333, so a SECOND\n"
        "                  isolated c2pool-btc instance can run on one host\n"
        "                  (e.g. G3b tuned-net A->B crossing). Omit to keep\n"
        "                  the default PoolConfig::P2P_PORT.\n"
        "  --network-id ID c2pool sharechain IDENTIFIER (hex, <=8 bytes) for a\n"
        "                  private/custom p2pool network. Omit for public BTC.\n"
        "  --prefix HEX    c2pool sharechain PREFIX (hex, <=8 bytes), an\n"
        "                  INDEPENDENT per-network constant (no algebraic tie to\n"
        "                  IDENTIFIER). Supply with --network-id to join a custom\n"
        "                  p2pool chain; omit to use the compiled default prefix.\n"
        "  --coin-rpc H:P  submitblock RPC backup (ARM B) endpoint override.\n"
        "                  Endpoint only (no secret); creds come from bitcoin.conf.\n"
        "  --coin-rpc-auth PATH  bitcoin.conf-style file with rpcuser/rpcpassword\n"
        "                  for the submitblock backup (default ~/.bitcoin/\n"
        "                  bitcoin.conf; keeps rpcpassword off the process table).\n"
        "                  Omit both to run daemonless (embedded P2P relay only).\n"
        "  --coin-p2p-discover  arm BTC-isolated coin-network peer discovery\n"
        "                  (scored/group-diverse; DNS+fixed+HTTP-seed fallback).\n"
        "  --merged SPEC   embedded merged-mined aux chain (NMC under BTC),\n"
        "                  colon spec SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]\n"
        "                  e.g. NMC:1:127.0.0.1:8336:nmcrpc:pass  (Namecoin)\n"
        "                  Omit for a single SHA256d BTC parent (no aux).\n";
}

/// BTC wire-protocol magic bytes per network (pchMessageStart).
/// Source: ref/bitcoin/src/kernel/chainparams.cpp.
static std::vector<std::byte> btc_magic_bytes(bool testnet, bool testnet4, bool regtest)
{
    std::string hex;
    if (regtest)       hex = "fabfb5da";   // regtest  (CRegTestParams)
    else if (testnet4) hex = "1c163f28";   // testnet4 (line 335-338)
    else if (testnet)  hex = "0b110907";   // testnet3 (line 235-238)
    else               hex = "f9beb4d9";   // mainnet  (line 117-120)
    return ParseHexBytes(hex);
}

int main(int argc, char* argv[])
{
    core::log::Logger::init();

    bool        testnet       = false;
    bool        testnet4      = false;
    bool        regtest       = false;
    bool        coin_p2p_discover = false;  // --coin-p2p-discover: BTC-isolated scored/diverse coin-network peer discovery (network-standalone arm; independent of external bitcoind)
    std::string bitcoind_host;
    uint16_t    bitcoind_port = 0;
    std::string p2pool_host;
    uint16_t    p2pool_port   = 0;
    std::string stratum_addr  = "0.0.0.0";  // listen all interfaces by default
    uint16_t    stratum_port  = 0;          // 0 disables stratum; --stratum sets it
    std::string http_addr     = "0.0.0.0";  // dashboard bind; --http sets it (H-STATS.944)
    uint16_t    http_port     = 0;          // 0 disables dashboard; --http sets it (H-STATS.944)
    uint16_t    sharechain_port = 0;        // 0 = default P2P_PORT (9333); --sharechain-port overrides (opt-in isolation)
    std::string network_id_hex;             // --network-id: c2pool IDENTIFIER override (empty = public net)
    std::string prefix_hex;                 // --prefix: c2pool PREFIX override (empty = compiled default)
    std::string rpc_endpoint;               // --coin-rpc HOST:PORT: submitblock backup endpoint override (no secret)
    std::string rpc_conf_path;              // --coin-rpc-auth PATH: bitcoin.conf creds (default ~/.bitcoin/bitcoin.conf)
    std::vector<std::string> merged_chain_specs; // --merged SPEC entries (embedded NMC aux; consumed in later PE slices)

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help")
        {
            print_usage();
            return 0;
        }
        else if (arg == "--data-dir")
        {
            // Isolate per-instance on-disk state (LevelDB sharechain, addr
            // store, logs, ...) under PATH. Default keeps ~/.c2pool. See #722.
            if (i + 1 >= argc || argv[i + 1][0] == '\0' || argv[i + 1][0] == '-') {
                std::cerr << "error: --data-dir requires a PATH argument\n";
                return 1;
            }
            core::filesystem::set_data_dir(argv[++i]);
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
        else if (arg == "--regtest")
        {
            regtest = true;
        }
        else if (arg == "--coin-p2p-discover")
        {
            coin_p2p_discover = true;
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
        else if (arg == "--p2pool" && i + 1 < argc)
        {
            std::string ep = argv[++i];
            auto colon = ep.find(':');
            if (colon == std::string::npos)
            {
                std::cerr << "--p2pool requires HOST:PORT\n";
                return 1;
            }
            p2pool_host = ep.substr(0, colon);
            p2pool_port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
        }
        else if (arg == "--stratum" && i + 1 < argc)
        {
            // --stratum [HOST:]PORT — bind a stratum TCP listener for miners.
            // HOST defaults to 0.0.0.0 (all interfaces). When omitted entirely,
            // stratum is disabled.
            std::string ep = argv[++i];
            auto colon = ep.find(':');
            if (colon == std::string::npos) {
                stratum_port = static_cast<uint16_t>(std::stoi(ep));
            } else {
                stratum_addr = ep.substr(0, colon);
                stratum_port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
            }
        }
        else if (arg == "--http" && i + 1 < argc)
        {
            // --http [HOST:]PORT — bind the H-STATS.944 operator dashboard.
            // HOST defaults to 0.0.0.0. When omitted entirely, the dashboard
            // is disabled (mirrors --stratum).
            std::string ep = argv[++i];
            auto colon = ep.find(':');
            if (colon == std::string::npos) {
                http_port = static_cast<uint16_t>(std::stoi(ep));
            } else {
                http_addr = ep.substr(0, colon);
                http_port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
            }
        }
        else if (arg == "--sharechain-port" && i + 1 < argc)
        {
            // --sharechain-port PORT - bind the sharechain (pool P2P) listener
            // on a non-default port so a SECOND isolated c2pool-btc instance can
            // run on a host where 9333 is already taken (e.g. G3b tuned-net A->B
            // crossing). Default STAYS 9333 (PoolConfig::P2P_PORT) when omitted,
            // preserving G0/G1 oracle byte-parity + btc_share_test pins. BTC-fenced
            // opt-in; no shared-base / PoolConfig constant touch.
            sharechain_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
        else if (arg == "--network-id" && i + 1 < argc)
        {
            network_id_hex = argv[++i];
        }
        else if (arg == "--prefix" && i + 1 < argc)
        {
            prefix_hex = argv[++i];
        }
        else if (arg == "--coin-rpc" && i + 1 < argc)
        {
            // --coin-rpc HOST:PORT — endpoint override for the submitblock RPC
            // backup (ARM B). Endpoint ONLY (no secret) so it is safe on argv;
            // rpcuser/rpcpassword come from bitcoin.conf (--coin-rpc-auth).
            rpc_endpoint = argv[++i];
        }
        else if (arg == "--coin-rpc-auth" && i + 1 < argc)
        {
            // --coin-rpc-auth PATH — bitcoin.conf-style file carrying
            // rpcuser/rpcpassword for the submitblock RPC backup. Keeps the
            // rpcpassword OFF the process table (default ~/.bitcoin/bitcoin.conf).
            rpc_conf_path = argv[++i];
        }
        else if (arg == "--merged" && i + 1 < argc)
        {
            // --merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]
            // Register an embedded merged-mined aux chain (NMC under the BTC
            // SHA256d parent). Collected here; the embedded-NMC backend is
            // constructed and its aux-merkle payout fed to merged_addrs in the
            // following PE slices. Absent == BTC v35 byte-for-byte.
            merged_chain_specs.push_back(argv[++i]);
        }
        else
        {
            std::cerr << "unknown arg: " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    // The external-bitcoind endpoint is only mandatory when NOT running the
    // network-standalone arm. --coin-p2p-discover stands up an embedded
    // BtcCoinPeerManager (DNS/fixed/HTTP-seeded coin-network peer discovery)
    // that streams headers with no external bitcoind, so exempt it from the
    // usage-exit. When neither is supplied the binary has no coin source and
    // must still print usage and exit.
    if (!coin_p2p_discover && (bitcoind_host.empty() || bitcoind_port == 0))
    {
        print_usage();
        return 1;
    }

    btc::PoolConfig::is_testnet = testnet;

    // B2-net: apply optional private-chain overrides. IDENTIFIER and PREFIX are
    // two INDEPENDENT per-network constants — set_network_id never derives one
    // from the other (commit 9034b59d). A bare --network-id keeps the compiled
    // network-default prefix; supply --prefix to join a custom p2pool chain.
    if (!prefix_hex.empty() && network_id_hex.empty())
        std::cerr << "[BTC] warning: --prefix ignored without --network-id\n";
    btc::PoolConfig::set_network_id(network_id_hex, prefix_hex);

    // ── NMC PE host-wire slice 3: parse --merged SPECs into typed configs ──
    // #997 (slices 1-2) collected raw --merged strings into merged_chain_specs
    // but consumed nothing. Turn each into a validated AuxChainConfig here;
    // slice 4 builds the embedded-NMC backend from these and feeds its
    // aux-merkle payout into the merged_addrs seam at the create_local_share
    // call site. An invalid aux spec is logged and skipped -- it must never
    // abort the parent BTC pool. Absent --merged this vector is empty and the
    // host path stays v35 byte-for-byte.
    std::vector<c2pool::merged::AuxChainConfig> merged_configs;
    for (const auto& spec : merged_chain_specs) {
        c2pool::merged::AuxChainConfig cfg;
        std::string merged_err;
        if (!btc::parse_merged_spec(spec, cfg, merged_err)) {
            LOG_ERROR << "[NMC-MM] ignoring invalid --merged spec (" << merged_err << "): " << spec;
            continue;
        }
        // PA/PB: the embedded NMC follower is P2P-driven, so default the NMC
        // coin-P2P port when the optional 7th SPEC field is absent (SSOT:
        // src/impl/nmc/coin/chain_seeds.hpp — namecoind mainnet 8334 /
        // testnet3 18334; mirrors main_ltc's get_coin_p2p_port auto-detect).
        if (cfg.symbol == "NMC" && cfg.p2p_port == 0)
            cfg.p2p_port = testnet ? 18334 : 8334;
        LOG_INFO << "[NMC-MM] aux chain configured: " << cfg.symbol
                 << " chain_id=" << cfg.chain_id
                 << " rpc=" << cfg.rpc_host << ":" << cfg.rpc_port
                 << (cfg.p2p_port ? (" p2p=" + std::to_string(cfg.p2p_port))
                                  : std::string(" p2p=off"));
        merged_configs.push_back(std::move(cfg));
    }
    if (!merged_configs.empty())
        LOG_INFO << "[NMC-MM] " << merged_configs.size()
                 << " embedded merged-mined aux chain(s) parsed -- backend wiring pending (PE slice 4)";

    auto chain_params = regtest
        ? btc::coin::BTCChainParams::regtest()
        : (testnet4
            ? btc::coin::BTCChainParams::testnet4()
            : (testnet ? btc::coin::BTCChainParams::testnet()
                       : btc::coin::BTCChainParams::mainnet()));

    const std::string net_subdir = regtest ? "bitcoin_regtest"
                                : (testnet4 ? "bitcoin_testnet4"
                                : (testnet  ? "bitcoin_testnet"
                                            : "bitcoin"));

    const std::filesystem::path net_dir = core::filesystem::config_path() / net_subdir;
    std::error_code ec;
    std::filesystem::create_directories(net_dir, ec);  // best effort

    const std::string chain_db_path = (net_dir / "embedded_headers").string();
    const std::string utxo_db_path  = (net_dir / "utxo_view_db").string();

    LOG_INFO << "[BTC] c2pool-btc starting — net="
             << (regtest ? "regtest" : (testnet4 ? "testnet4" : (testnet ? "testnet3" : "mainnet")));
    LOG_INFO << "[BTC] HeaderChain DB: " << chain_db_path;
    LOG_INFO << "[BTC] UTXO DB:        " << utxo_db_path;
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

    // BTC reuses LTC_LIMITS — both chains share max_money≤2.1e15<8.4e15 (so
    // LTC's bound never falsely rejects a BTC value) and 100-block coinbase
    // maturity. pegout_maturity=6 is moot for BTC (no MWEB → no pegouts).
    // KEEP_DEPTH=288 matches Bitcoin Core MIN_BLOCKS_TO_KEEP exactly.
    core::coin::UTXOViewDB utxo_db(utxo_db_path);
    if (!utxo_db.open())
    {
        LOG_WARNING << "[BTC] UTXOViewDB open failed — running without UTXO persistence";
    }
    core::coin::UTXOViewCache utxo_cache(&utxo_db);
    LOG_INFO << "[BTC] UTXO loaded: best_height=" << utxo_cache.get_best_height()
             << " best_block=" << utxo_cache.get_best_block().GetHex().substr(0, 16);
    constexpr uint32_t BTC_KEEP_DEPTH = core::coin::LTC_MIN_BLOCKS_TO_KEEP;

    io::io_context ioc;

    // ── NMC PE host-wire slice 4 + PA/PB: aux backends from merged_configs ──
    // One AuxChainRPC (external-daemon fallback) per parsed aux chain — the
    // fallback route that MUST always exist (never removed). PA/PB below
    // registers the embedded-NMC SPV backend (nmc::coin::AuxChainEmbedded) as
    // PRIMARY alongside it, mirroring the #1387 NMC block in main_ltc
    // (~L5471-5524 + the L6132-6215 header-feed). Construction is inert — no
    // connect() here, so an unreachable aux daemon never blocks BTC startup.
    auto aux_backends = btc::build_aux_backends(ioc, merged_configs);
    if (!aux_backends.empty())
        LOG_INFO << "[NMC-MM] " << aux_backends.size()
                 << " aux chain RPC backend(s) constructed (fallback path)";

    // PA/PB state — all inert (null) absent --merged; declared AFTER ioc so
    // destruction runs before ioc's (broadcaster timers/sockets + the manager
    // poll thread stop first). Mirrors main_ltc declaration order (:5235-5246).
    std::unique_ptr<c2pool::merged::MergedMiningManager> mm_manager;
    std::map<uint32_t, std::unique_ptr<c2pool::merged::CoinBroadcaster>> merged_broadcasters;
    std::unique_ptr<nmc::coin::HeaderChain>    nmc_chain;
    std::unique_ptr<nmc::coin::Mempool>        nmc_pool;
    std::unique_ptr<nmc::coin::NMCChainParams> nmc_params_ptr;

    if (!merged_configs.empty()) {
        mm_manager = std::make_unique<c2pool::merged::MergedMiningManager>(ioc);
        for (size_t ci = 0; ci < merged_configs.size(); ++ci) {
            auto& cfg = merged_configs[ci];
            if (cfg.symbol == "NMC") {
                // Embedded NMC merged-mining under the BTC parent — faithful
                // port of the main_ltc NMC block (#1387, :5471-5524). NMC is
                // aux-only: no UTXO maturity gate; embedded HeaderChain +
                // Mempool + P2P header-feed is the authoritative route.
                if (!nmc_chain) {
                    auto np = testnet
                        ? nmc::coin::NMCChainParams::testnet()
                        : nmc::coin::NMCChainParams::mainnet();
                    nmc_params_ptr = std::make_unique<nmc::coin::NMCChainParams>(np);
                    std::string nmc_net_dir = testnet ? "namecoin_testnet" : "namecoin";
                    std::string nmc_db = (core::filesystem::config_path()
                        / nmc_net_dir / "embedded_headers").string();
                    nmc_chain = std::make_unique<nmc::coin::HeaderChain>(*nmc_params_ptr, nmc_db);
                    if (!nmc_chain->init())
                        LOG_WARNING << "[EMB-NMC] HeaderChain init failed - P2P sync will rebuild";
                    if (!testnet && nmc_chain->size() == 0) {
                        auto g = nmc::coin::NMCChainParams::mainnet_genesis_header();
                        if (nmc_chain->add_header(g))
                            LOG_INFO << "[EMB-NMC] seeded mainnet genesis header";
                    }
                }
                if (!nmc_pool) nmc_pool = std::make_unique<nmc::coin::Mempool>();
                {
                    auto backend = std::make_unique<nmc::coin::AuxChainEmbedded>(
                        *nmc_chain, *nmc_pool, *nmc_params_ptr, cfg, testnet);
                    // Embedded P2P relay sink — looked up lazily in
                    // merged_broadcasters (registered below), mirroring the
                    // manager-level set_block_relay_fn. submit_block_raw
                    // returns the relayed peer count.
                    uint32_t nmc_chain_id = cfg.chain_id;
                    auto* mbs = &merged_broadcasters;
                    backend->set_block_relay(
                        [mbs, nmc_chain_id](const std::string& block_hex) -> size_t {
                            auto it = mbs->find(nmc_chain_id);
                            if (it == mbs->end()) return 0;
                            try {
                                return it->second->submit_block_raw(ParseHex(block_hex));
                            } catch (const std::exception& e) {
                                LOG_WARNING << "[MM:NMC] embedded P2P relay failed: " << e.what();
                                return 0;
                            }
                        });
                    mm_manager->add_chain(cfg, std::move(backend));
                    LOG_INFO << "Merged mining: NMC embedded (primary) chain_id=" << cfg.chain_id;
                    // AuxChainRPC fallback (slice-4 backend, index-parallel to
                    // merged_configs) — the never-removed external-daemon path.
                    if (cfg.rpc_port > 0 && !cfg.rpc_userpass.empty() && aux_backends[ci]) {
                        mm_manager->set_fallback_backend(cfg.chain_id, std::move(aux_backends[ci]));
                        LOG_INFO << "Merged mining: NMC RPC fallback at "
                                 << cfg.rpc_host << ":" << cfg.rpc_port;
                    }
                }
            } else {
                // Non-NMC aux chain — standard RPC-primary path (slice-4 backend).
                mm_manager->add_chain(cfg, std::move(aux_backends[ci]));
                LOG_INFO << "Merged mining: added " << cfg.symbol
                         << " (chain_id=" << cfg.chain_id << ") via RPC at "
                         << cfg.rpc_host << ":" << cfg.rpc_port;
            }

            // ── NMC coin-P2P broadcaster + AuxPoW header-feed (#980 L1/L2) ──
            if (cfg.symbol == "NMC" && cfg.p2p_port > 0 && nmc_chain) {
                // SSOT: NMCChainParams::p2p_magic (header_chain.hpp; KAT
                // auxpow_wire_test.cpp) — mainnet f9beb4fe / testnet3 fabfb5fe.
                auto prefix = testnet ? ParseHexBytes("fabfb5fe")
                                      : ParseHexBytes("f9beb4fe");
                c2pool::merged::PeerManagerConfig pm_cfg;
                pm_cfg.is_merged = true;
                pm_cfg.max_connection_attempts = 5;
                pm_cfg.refresh_interval_sec = 300;
                pm_cfg.max_peers = 20;
                pm_cfg.min_peers = 4;
                pm_cfg.valid_ports = {8334, 18334};
                // Validate the P2P address via PeerEndpoint. In embedded mode
                // with a placeholder RPC host, a dead endpoint is scored out by
                // the peer manager; DNS/fixed seeds carry discovery.
                auto local_daemon = PeerEndpoint::from(cfg.p2p_address, cfg.p2p_port);
                if (!local_daemon) {
                    LOG_INFO << "[NMC] No valid local daemon P2P address"
                             << " ('" << cfg.p2p_address << ":" << cfg.p2p_port << "')"
                             << " — broadcaster will use seed-only mode";
                }
                auto broadcaster = std::make_unique<c2pool::merged::CoinBroadcaster>(
                    ioc, cfg.symbol, prefix,
                    std::move(local_daemon),
                    ".", pm_cfg);

                // #980: NMC DNS seeds are dead — live dialing works via
                // nmc_fixed_seeds (handshake-verified). No HTTP seeds.
                broadcaster->peer_manager().set_dns_seeds(
                    nmc::coin::nmc_dns_seeds(testnet));
                broadcaster->peer_manager().set_fixed_seeds(
                    nmc::coin::nmc_fixed_seeds(testnet));

                // getpeerinfo bootstrap from the aux chain backend (RPC arm).
                auto* rpc_ptr = mm_manager->get_chain_rpc(cfg.chain_id);
                if (rpc_ptr) {
                    broadcaster->set_getpeerinfo_fn([rpc_ptr]() {
                        return rpc_ptr->getpeerinfo();
                    });
                }

                // #980: NMC embedded header sync via P2P AuxPoW feed. The join
                // point is set_raw_headers_sink — NOT set_raw_headers_parser
                // (80-byte-only, drops the AuxPoW proof; structurally
                // insufficient for a chain that has been AuxPoW since 2014).
                auto nmc_hdr_pool = std::make_shared<boost::asio::thread_pool>(1);
                auto* bcaster_ptr = broadcaster.get();
                auto* nc = nmc_chain.get();

                // Peer-height (sync-progress logging only, no consensus)
                broadcaster->set_on_peer_height(
                    [nc](uint32_t h) {
                        nc->set_peer_tip_height(h);
                        LOG_INFO << "NMC peer reports height " << h;
                    });

                // The AuxPoW-carrying join point: parse the raw 'headers'
                // payload to (header, optional<AuxPow>) and admit via
                // add_auxpow_header (proof-verified) / add_header (own-PoW).
                // Serialized on a 1-thread pool (mirror DOGE/LTC-side NMC).
                broadcaster->set_raw_headers_sink(
                    [nc, nmc_hdr_pool, bcaster_ptr, &ioc](
                        const std::string& /*peer*/,
                        const uint8_t* d, size_t n) {
                        auto payload = std::make_shared<std::vector<uint8_t>>(d, d + n);
                        boost::asio::post(*nmc_hdr_pool,
                            [payload, nc, bcaster_ptr, &ioc]() {
                                auto parsed = nmc::coin::parse_nmc_headers_message(
                                    payload->data(), payload->size());
                                int acc = 0;
                                uint256 last_hash;
                                for (auto& wh : parsed) {
                                    bool ok = wh.auxpow
                                        ? nc->add_auxpow_header(wh.header, *wh.auxpow)
                                        : nc->add_header(wh.header);
                                    if (ok) ++acc;
                                    last_hash = nmc::coin::block_hash(wh.header);
                                }
                                if (acc > 0)
                                    LOG_INFO << "[EMB-NMC] admitted " << acc << "/"
                                             << parsed.size() << " headers, height="
                                             << nc->height();
                                bool full_batch = (parsed.size() >= 2000);
                                if (acc > 0 || full_batch) {
                                    boost::asio::post(ioc,
                                        [acc, last_hash, nc, bcaster_ptr]() {
                                          try {
                                            if (acc > 0 && !last_hash.IsNull())
                                                bcaster_ptr->request_headers({last_hash}, uint256::ZERO);
                                            else
                                                bcaster_ptr->request_headers(nc->get_locator(), uint256::ZERO);
                                          } catch (const std::exception& e) {
                                            LOG_WARNING << "[EMB-NMC] post-process: " << e.what();
                                          }
                                        });
                                }
                            });
                    });

                // Periodic getheaders sync timer (5s unsynced / 60s synced)
                auto nmc_sync_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
                auto nmc_sync_timer = std::make_shared<boost::asio::steady_timer>(ioc);
                *nmc_sync_fn = [nmc_sync_fn, nmc_sync_timer,
                                nc, bcaster_ptr](boost::system::error_code ec) {
                    if (ec) return;
                    int interval = nc->is_synced() ? 60 : 5;
                    nmc_sync_timer->expires_after(std::chrono::seconds(interval));
                    nmc_sync_timer->async_wait(*nmc_sync_fn);
                    try {
                        bcaster_ptr->request_headers(nc->get_locator(), uint256::ZERO);
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[EMB-NMC] Header sync error: " << e.what();
                    }
                };
                nmc_sync_timer->expires_after(std::chrono::seconds(10));
                nmc_sync_timer->async_wait(*nmc_sync_fn);
                LOG_INFO << "NMC embedded header sync wired via P2P (AuxPoW admission)";

                broadcaster->start();
                merged_broadcasters[cfg.chain_id] = std::move(broadcaster);
            }
        }

        // Manager-level merged P2P block relay (mirror main_ltc :6463-6476).
        if (!merged_broadcasters.empty()) {
            mm_manager->set_block_relay_fn(
                [&merged_broadcasters](uint32_t chain_id, const std::string& block_hex) {
                    auto it = merged_broadcasters.find(chain_id);
                    if (it == merged_broadcasters.end()) return;
                    try {
                        auto block_bytes = ParseHex(block_hex);
                        it->second->submit_block_raw(block_bytes);
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[MM] P2P block relay failed: " << e.what();
                    }
                });
        }

        mm_manager->start();
        LOG_INFO << "Merged mining manager started with "
                 << mm_manager->chain_count() << " chain(s)"
                 << " — embedded-NMC primary, RPC fallback retained";
    }

    // ── Graceful shutdown via boost::asio::signal_set ─────────────────────
    //
    // Why not std::signal? Two reasons:
    //   1. std::signal handlers run in the signal-delivery context, which
    //      is async-signal-safe-only. boost::asio::io_context::stop is
    //      thread-safe but not documented as signal-safe — calling it from
    //      a signal handler is undefined-behaviour-adjacent.
    //   2. Even if we get past UB, the queued asio handlers (pending reads,
    //      timer callbacks) hold shared_ptrs to sessions; stopping ioc
    //      drops the queue but leaves those captures alive until ioc itself
    //      is destroyed — by which time other subsystems have started their
    //      own RAII teardown, producing destruction-order races.
    //
    // signal_set runs its handler on the io_context thread, in an ordinary
    // async callback. We use it to drive an EXPLICIT graceful shutdown:
    // stop the stratum acceptor + close every active session FIRST (so
    // their pending async ops are cancelled cleanly via cancel_timers),
    // THEN call ioc.stop() to drain the rest. By the time ioc is destroyed
    // at end-of-main, all async operations have completed via cancellation
    // and there are no stale captures referencing torn-down state.
    //
    // The shutdown lambda captures by reference variables that are
    // declared further down in this function (stratum_server, work_source,
    // etc.) — those references resolve at *invocation* time (i.e., when
    // SIGINT/SIGTERM arrives), by which point the variables exist. If a
    // signal arrives before the variables are constructed (e.g., during
    // HeaderChain::init), the signal handler will see them as nullptr/
    // empty and the `if` guards below short-circuit safely.
    std::shared_ptr<btc::stratum::BTCWorkSource> work_source_for_shutdown;  // populated later
    std::unique_ptr<core::StratumServer>         stratum_server_for_shutdown;  // populated later
    bool                                         shutdown_initiated = false;

    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc, &stratum_server_for_shutdown, &shutdown_initiated]
        (const boost::system::error_code& ec, int signo) {
            if (ec) return;
            if (shutdown_initiated) return;
            shutdown_initiated = true;

            LOG_INFO << "[BTC] received signal " << signo
                     << " — initiating graceful shutdown";

            // 1) Stop stratum BEFORE ioc.stop() so sessions close cleanly:
            //    StratumServer::stop() cancels the acceptor + iterates
            //    session set, calling shutdown() on each (cancels the
            //    work_push_timer + closes the socket). The pending
            //    async_read_some on each session then fails with
            //    operation_aborted, the read-error path runs, the session
            //    self-removes from the workers map. By the time we call
            //    ioc.stop(), no session-bound async op is left.
            if (stratum_server_for_shutdown) {
                stratum_server_for_shutdown->stop();
            }

            // 2) Stop the io_context. Other subsystems (sharechain peer
            //    btc::Node, bitcoind P2P btc::coin::Node) handle their own
            //    teardown via RAII when main() exits. They don't have
            //    queued state that depends on this ioc (their timers/
            //    sockets are owned by THEIR objects, destroyed in reverse
            //    construction order before ioc itself).
            ioc.stop();
        });

    // btc::Config = core::Config<PoolConfig, CoinConfig> — composite holds
    // both the c2pool sharechain identity (PoolConfig: prefix/identifier
    // from B1) AND the bitcoind wire-protocol identity (CoinConfig::m_p2p:
    // BTC magic bytes per network). NodeP2P reads m_config->coin()->m_p2p.prefix
    // to frame outbound bitcoind messages — getting this wrong = peer
    // disconnect.
    btc::Config config(net_subdir);
    // Skip Config::init() — it would try to load pool.yaml + coin.yaml
    // from disk; for B2-net smoke we set fields directly from chainparams.
    config.coin()->m_p2p.prefix  = btc_magic_bytes(testnet, testnet4, regtest);
    config.coin()->m_p2p.address = NetService(bitcoind_host, bitcoind_port);
    config.coin()->m_testnet     = testnet || regtest;
    config.coin()->m_regtest     = regtest;
    config.coin()->m_symbol      = "BTC";

    btc::coin::Node<btc::Config> coin_node(&ioc, &config);

    // ── #82/#744 submitblock RPC BACKUP arm (ARM B of the dual-path
    // broadcaster) ── The embedded coin-net P2P relay (submit_block_for_connect
    // -> submit_block_p2p_raw) is the always-primary daemonless path; this arms
    // the OPT-IN submitblock backup so a won block ALSO reaches a locally-run
    // bitcoind if the operator provisions one. Creds come from bitcoin.conf
    // (default ~/.bitcoin/bitcoin.conf, overridable with --coin-rpc-auth PATH)
    // so the rpcpassword NEVER touches argv; --coin-rpc HOST:PORT overrides only
    // the endpoint. No creds => arm stays UNARMED (has_rpc()==false) and
    // submit_block_hex returns false LOUDLY -- byte-identical to the daemonless
    // default. Mirrors main_dgb's NodeRPC arming (the #82 reference).
    {
        btc::coin::RpcConf rpc_conf;
        std::string conf_path = rpc_conf_path;
        if (conf_path.empty()) {
            const char* home = std::getenv("HOME");
            conf_path = std::string(home ? home : ".") + "/.bitcoin/bitcoin.conf";
        }
        if (btc::coin::load_rpc_conf(conf_path, rpc_conf)) {
            if (rpc_conf.port == 0) {
                // Bitcoin Core RPC defaults: mainnet 8332, testnet3 18332,
                // testnet4 48332, regtest 18443.
                rpc_conf.port = regtest ? 18443
                              : (testnet4 ? 48332
                                          : (testnet ? 18332 : 8332));
            }
            btc::coin::apply_endpoint_override(rpc_endpoint, rpc_conf);
        } else {
            // No conf creds; --coin-rpc alone still lets an operator point the
            // endpoint, but without user/pass the arm cannot fire.
            btc::coin::apply_endpoint_override(rpc_endpoint, rpc_conf);
        }
        if (rpc_conf.armed()) {
            coin_node.arm_submit_rpc(NetService(rpc_conf.host, rpc_conf.port),
                                     rpc_conf.userpass());
        } else {
            LOG_INFO << "[BTC] submitblock RPC backup UNARMED "
                        "(no bitcoin.conf creds; embedded P2P relay is the only "
                        "broadcast arm)";
        }
    }

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

    // ─────────────────────────────────────────────────────────────────────────
    // B5: P2P submit + roundtrip tracking infrastructure.
    //
    // submit_block() is the public entry point for future found-block
    // producers (stratum, debug hook, etc.). It broadcasts the block to
    // bitcoind via MSG_BLOCK and records the hash in pending_submits.
    //
    // Confirmation strategy: bitcoind does NOT echo MSG_BLOCK back to its
    // sender (it tracks per-peer m_inv_known_blocks), so on_full_block won't
    // fire for our own submission. Instead we observe arrival in HeaderChain
    // via new_headers — bitcoind announces the new tip via headers relay,
    // which our locator-driven getheaders captures naturally. A 30s scan
    // timer warns on submits unconfirmed for >60s — typically a sign of
    // bitcoind rejecting (consensus failure) or mempool/network hiccup.
    //
    // shared_ptr captures: pending state outlives any single callback; the
    // new_headers subscriber, the warn timer, and submit_block all need it.
    // ─────────────────────────────────────────────────────────────────────────
    struct PendingSubmit {
        std::chrono::steady_clock::time_point submitted_at;
        uint32_t height;
    };
    auto pending_mu      = std::make_shared<std::mutex>();
    // std::map (not unordered_map): uint256 has operator< from base_uint::CompareTo
    // but no std::hash<uint256> specialization in this codebase.
    auto pending_submits = std::make_shared<std::map<uint256, PendingSubmit>>();

    [[maybe_unused]]
    auto submit_block = [&coin_node, pending_mu, pending_submits]
        (btc::coin::BlockType& block, uint32_t height)
    {
        auto packed_hdr = pack(static_cast<const btc::coin::BlockHeaderType&>(block));
        uint256 block_hash = Hash(packed_hdr.get_span());
        {
            std::lock_guard<std::mutex> lk(*pending_mu);
            (*pending_submits)[block_hash] = { std::chrono::steady_clock::now(), height };
        }
        LOG_INFO << "[BTC-SUBMIT] sending block " << block_hash.GetHex().substr(0, 16)
                 << " height=" << height;
        coin_node.submit_block_p2p(block);
    };

    // Header-sync caught-up flag (single-threaded ioc, so a bare shared bool is
    // race-free): set true once a peer answers getheaders with a < 2000 batch
    // (== nothing more after our tip on that peer), false while full 2000-batches
    // are still streaming. The standalone header-sync driver below reads it to
    // stop re-issuing getheaders and to suspend peer failover once synced, so a
    // correctly caught-up node emits zero getheaders churn and never rotates
    // peers on the natural header-gap between blocks. Untouched by the external
    // arm (that arm does not read it). Starts false so the driver actively
    // pushes sync from genesis.
    auto hdr_caught_up = std::make_shared<bool>(false);

    // Forward bitcoind's headers batches into HeaderChain AND chain the
    // getheaders locator forward to drive sync to peer's tip. LTC dispatches
    // this off-thread (scrypt CPU cost); BTC's PoW is SHA256d so inline is
    // fine for testnet (and for mainnet IBD too, given SHA256d is ~us/header).
    coin_node.new_headers.subscribe(
        [&header_chain, &coin_node, header_block_hash, &chain_params,
         pending_mu, pending_submits, hdr_caught_up]
        (const std::vector<btc::coin::BlockHeaderType>& headers)
        {
            if (headers.empty()) return;
            int accepted = header_chain.add_headers(headers);
            uint256 last_hash = header_block_hash(headers.back());
            LOG_INFO << "[BTC] new_headers: received=" << headers.size()
                     << " accepted=" << accepted
                     << " chain_height=" << header_chain.height()
                     << " last=" << last_hash.GetHex().substr(0, 16);

            // B5 roundtrip detection: any header in this batch matching a
            // pending submit means bitcoind accepted our block and built on it.
            if (!pending_submits->empty()) {
                std::lock_guard<std::mutex> lk(*pending_mu);
                for (const auto& hdr : headers) {
                    uint256 h = header_block_hash(hdr);
                    auto it = pending_submits->find(h);
                    if (it != pending_submits->end()) {
                        auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - it->second.submitted_at).count();
                        LOG_INFO << "[BTC-SUBMIT] roundtrip CONFIRMED: block "
                                 << h.GetHex().substr(0, 16)
                                 << " height=" << it->second.height
                                 << " latency=" << age_ms << "ms";
                        pending_submits->erase(it);
                    }
                }
            }

            // Continue header sync if peer likely has more (full 2000-header
            // batch); otherwise we're caught up and bitcoind will push new
            // tips via inv/sendheaders.
            if (headers.size() >= 2000) {
                *hdr_caught_up = false;
                coin_node.send_getheaders(
                    BTC_PROTOCOL_VERSION, {last_hash}, uint256::ZERO);
            } else {
                *hdr_caught_up = true;
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

    // BTC txid: SHA256d of the non-witness serialization (BIP 144). Witness
    // bytes change wtxid only — txid stays stable. UTXO indexing must use
    // txid since vin.prevout.hash references parents by txid.
    auto btc_txid = [](const btc::coin::MutableTransaction& tx) {
        auto packed = pack(btc::coin::TX_NO_WITNESS(tx));
        return Hash(packed.get_span());
    };

    // Subscribe to full_block events to maintain UTXO. The p2p_node
    // auto-requests every inv'd block (request_full_block uses
    // MSG_WITNESS_BLOCK 0x40000002) so witness data arrives intact —
    // txid (non-witness) is what UTXO keys on, but the wire path needs
    // witness or peer drops us for advertising NODE_WITNESS yet not honoring it.
    coin_node.full_block.subscribe(
        [&header_chain, &utxo_cache, &utxo_db, btc_txid]
        (const btc::coin::BlockType& block)
        {
            auto packed_hdr = pack(static_cast<const btc::coin::BlockHeaderType&>(block));
            uint256 block_hash = Hash(packed_hdr.get_span());

            auto entry = header_chain.get_header(block_hash);
            if (!entry) {
                LOG_WARNING << "[BTC] full_block: header unknown for "
                            << block_hash.GetHex().substr(0, 16)
                            << " — dropping (header sync lagging?)";
                return;
            }
            uint32_t height = entry->height;

            // Skip already-processed heights (warm restart, duplicate inv,
            // or replayed block). UTXO is monotonic on this single-peer path.
            if (height <= utxo_cache.get_best_height()) {
                LOG_INFO << "[BTC] full_block: skip duplicate h=" << height
                         << " best_height=" << utxo_cache.get_best_height();
                return;
            }

            try {
                auto undo = utxo_cache.connect_block(block, height, btc_txid);
                utxo_db.put_block_undo(height, undo);
                utxo_cache.flush(block_hash, height);
                utxo_cache.prune_undo(height, BTC_KEEP_DEPTH);

                LOG_INFO << "[BTC] UTXO connect: h=" << height
                         << " txs=" << block.m_txs.size()
                         << " undo_added=" << undo.added_outpoints.size()
                         << " undo_spent=" << undo.tx_undos.size()
                         << " best_height=" << utxo_cache.get_best_height();
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC] UTXO connect_block failed h=" << height
                            << " hash=" << block_hash.GetHex().substr(0, 16)
                            << ": " << e.what();
            }
        });

    // ── External-bitcoind P2P arm ────────────────────────────────────────────
    // Dials the operator-supplied bitcoind and drives header sync + block relay
    // through it. GUARDED on a non-empty --bitcoind: when running purely via
    // --coin-p2p-discover (network-standalone, no external bitcoind) this arm is
    // skipped and the embedded coin-network peer source below becomes the header
    // origin. Behaviour is byte-identical to before this guard when --bitcoind
    // is supplied (with or without --coin-p2p-discover also armed).
    if (!bitcoind_host.empty())
    {
        LOG_INFO << "[BTC] Connecting to bitcoind...";
        coin_node.start_p2p(NetService(bitcoind_host, bitcoind_port));

        // Phase 10c: pull the peer mempool on connect (BIP 35) so TemplateBuilder
        // produces POPULATED blocks. Without this the new_tx subscription above only
        // sees txs announced via inv AFTER connect; txs already resident in the
        // bitcoind mempool at connect time (e.g. a seeded regtest mempool) are never
        // requested, leaving coinbase-only templates. Mirrors main_dgb. Peer must
        // advertise NODE_BLOOM (regtest: -peerbloomfilters=1) or the request is
        // skipped (logged) to avoid a disconnect; normal inv relay still applies.
        coin_node.enable_mempool_request();
    }

    // ── BTC coin-network peer discovery (--coin-p2p-discover) ────────────────
    // BTC-ISOLATED, self-contained peer manager (per-coin isolation fence; a
    // faithful copy of the sibling coin CoinPeerManager under src/impl/btc).
    // OFF by default -> the external bitcoind P2P arm above is unchanged.
    // Declared at main scope so it outlives ioc.run(); destroyed at main exit.
    std::unique_ptr<btc::coin::BtcCoinPeerManager> coin_peer_mgr;
    // Keep the standalone header-sync driver's self-rescheduling closure alive
    // for the whole process lifetime. Its weak_ptr self-ref (mirroring the B5
    // warn/reconcile/mem timers) needs ONE strong owner that outlives the
    // nested --coin-p2p-discover / empty-bitcoind block that builds it — those
    // sibling timers get theirs from a main-scope shared_ptr, so this driver
    // needs the same or its first tick would run once and never reschedule.
    std::shared_ptr<std::function<void()>> standalone_driver_keepalive;
    if (coin_p2p_discover) {
        // BTC network default ports: 8333 mainnet / 18333 testnet3 /
        // 48333 testnet4 / 18444 regtest. Distinct from the stratum/P2P pool port.
        const uint16_t coin_port = regtest ? 18444
                                 : (testnet4 ? 48333
                                 : (testnet  ? 18333 : 8333));
        btc::coin::BtcPeerManagerConfig pm_cfg;
        pm_cfg.valid_ports = { coin_port };
        const std::string pm_data_dir = (net_dir / "btc_embedded_peers").string();
        coin_peer_mgr = std::make_unique<btc::coin::BtcCoinPeerManager>(
            ioc, "BTC", pm_data_dir, pm_cfg);
        // testnet4 currently reuses the testnet3 seed set (btc_*_seeds take a
        // single bool); the port above is still testnet4-correct. Refine when a
        // testnet4-specific seed accessor is wired.
        coin_peer_mgr->set_dns_seeds(btc::coin::btc_dns_seeds(testnet));
        coin_peer_mgr->set_fixed_seeds(btc::coin::btc_fixed_seeds(testnet));
        // Tier 3 (last-resort) HTTP bootstrap: the shared c2pool seed aggregator.
        // Fires only when DNS + fixed seeds both fail to yield min_peers within
        // 90s (schedule_http_peer_fallback). Coin selection is by the "btc" JSON
        // key inside http_fetch_coin_peers, not the host, so the shared
        // aggregator serves BTC peers without a BTC-specific endpoint. No-op if
        // the list is empty. KNOWN LIMITATION (inherited, not introduced here):
        // this fallback is one-shot and does not re-arm (see dgb-rearm-0801).
        coin_peer_mgr->set_http_peer_seeds({{"voidbind.com", 8080}});
        coin_peer_mgr->start();
        const auto pm_stats = coin_peer_mgr->peer_stats();
        LOG_INFO << "[BTC] coin-network peer discovery ARMED (--coin-p2p-discover): "
                 << "port=" << coin_port
                 << " peers=" << pm_stats.total
                 << " groups=" << pm_stats.unique_groups;

        // ── Network-standalone header source ────────────────────────────────
        // With no external bitcoind, the coin-network peer manager is the ONLY
        // header origin. It banks scored peer ADDRESSES but does not itself hold
        // a header-streaming connection, so dial one discovered peer through the
        // same NodeP2P broadcaster the external arm uses: the initial-getheaders
        // timer and new_headers callback (both keyed on coin_node) are then fed
        // by this peer exactly as they would be by an external bitcoind, and the
        // header tip advances from genesis. A self-rescheduling failover timer
        // re-dials a fresh candidate while the version/verack handshake has not
        // completed (or has since dropped), so a dead first pick — or a peer
        // that later disconnects — does not wedge header sync. When --bitcoind
        // is ALSO supplied the external arm already owns coin_node, so this
        // standalone dial is skipped and behaviour is unchanged.
        if (bitcoind_host.empty()) {
            // NOTE: deliberately do NOT enable_mempool_request() on the
            // standalone arm. This is header-only sync against random public
            // mainnet peers: a BIP 35 `mempool` request to a peer that has not
            // granted us bloom/permission is exactly what Bitcoin Core drops
            // peers for (the recurring ~60s EOF disconnects observed here), and
            // a header-only node has no use for the peer's full mempool anyway.
            // The mempool pull stays armed ONLY on the external-bitcoind arm
            // above (operator-controlled peer) and the submit arm — byte-
            // identical there.
            // Peers already dialed/attempted this run — passed to
            // get_peers_to_connect() as the "connected" exclusion set so each
            // failover draws the NEXT best-scored peer instead of re-picking a
            // dead one; cleared to re-sweep once the banked set is exhausted.
            auto standalone_tried = std::make_shared<std::set<std::string>>();
            auto dial_standalone_peer =
                [&coin_node, &coin_peer_mgr, standalone_tried]() -> bool {
                    auto cands = coin_peer_mgr->get_peers_to_connect(*standalone_tried);
                    if (cands.empty()) {
                        standalone_tried->clear();
                        cands = coin_peer_mgr->get_peers_to_connect(*standalone_tried);
                    }
                    if (cands.empty()) {
                        LOG_WARNING << "[BTC] standalone header source: no coin peers to dial yet";
                        return false;
                    }
                    const auto& ep = cands.front();
                    standalone_tried->insert(ep.to_string());
                    LOG_INFO << "[BTC] standalone header source: dialing coin peer "
                             << ep.to_string() << " (no external bitcoind)";
                    coin_node.start_p2p(ep.to_net_service());
                    return true;
                };
            // Initial dial now so the 3s initial-getheaders timer finds a peer.
            dial_standalone_peer();

            // ── Standalone header-sync driver ───────────────────────────────
            // On the external-bitcoind arm header re-requests come for free:
            // new_headers chains the next getheaders on every 2000-batch, and
            // the B5b tip-reconcile poll re-issues while a submit is pending. A
            // header-only standalone node MINES NOTHING, so pending_submits is
            // ALWAYS empty and B5b never fires; and the single 3s initial
            // getheaders is easily lost (sent before/at handshake, or on the
            // first peer that then EOFs), after which nothing re-requests headers
            // and the coin header chain wedges at genesis. This self-rescheduling
            // timer closes that gap, entirely on this standalone arm:
            //   (2) re-sends getheaders(locator=current tip) whenever a peer is
            //       handshaked, we are NOT caught up, and the tip did NOT advance
            //       since the last tick — kickstart at genesis + stall recovery;
            //       silent during healthy IBD (new_headers already chains the
            //       next batch) and silent once caught up (zero churn);
            //   (3) re-sends getheaders immediately on a fresh handshake, so a
            //       (re)connect — the 60s EOF auto-reconnect OR a failover dial —
            //       always re-requests headers on the new connection;
            //   (4) fails over to the NEXT best-scored candidate when the header
            //       tip has made NO progress for kNoProgressFailoverSec while not
            //       caught up, regardless of handshake state — a handshaked-but-
            //       silent peer no longer wedges sync forever. Suspended once
            //       caught up so the natural inter-block header gap never churns
            //       peers. Weak self-ref avoids a shared_ptr cycle (mirrors the
            //       B5 warn timer below).
            constexpr int kDriverTickSec         = 12;
            constexpr int kNoProgressFailoverSec = 40;
            auto hdr_last_height    = std::make_shared<uint32_t>(header_chain.height());
            auto hdr_last_progress  = std::make_shared<std::chrono::steady_clock::time_point>(
                std::chrono::steady_clock::now());
            auto hdr_was_handshaked = std::make_shared<bool>(false);
            auto standalone_dial_timer =
                std::make_shared<boost::asio::steady_timer>(ioc);
            auto schedule_standalone_dial = std::make_shared<std::function<void()>>();
            // Anchor the strong owner at main scope (see declaration above) so
            // the closure survives this block's exit and keeps rescheduling.
            standalone_driver_keepalive = schedule_standalone_dial;
            std::weak_ptr<std::function<void()>> weak_dial = schedule_standalone_dial;
            *schedule_standalone_dial =
                [standalone_dial_timer, weak_dial, &coin_node, &header_chain,
                 &chain_params, dial_standalone_peer, hdr_caught_up,
                 hdr_last_height, hdr_last_progress, hdr_was_handshaked,
                 kDriverTickSec, kNoProgressFailoverSec]() {
                    standalone_dial_timer->expires_after(std::chrono::seconds(kDriverTickSec));
                    standalone_dial_timer->async_wait(
                        [standalone_dial_timer, weak_dial, &coin_node, &header_chain,
                         &chain_params, dial_standalone_peer, hdr_caught_up,
                         hdr_last_height, hdr_last_progress, hdr_was_handshaked,
                         kNoProgressFailoverSec]
                        (const boost::system::error_code& ec) {
                            if (ec) return;
                            constexpr uint32_t GETHEADERS_VERSION = 70016;
                            const uint32_t h          = header_chain.height();
                            const bool     handshaked  = coin_node.is_handshake_complete();
                            const bool     caught_up   = *hdr_caught_up;
                            const auto     now         = std::chrono::steady_clock::now();
                            const bool     advanced    = (h > *hdr_last_height);
                            if (advanced) {
                                *hdr_last_height   = h;
                                *hdr_last_progress = now;
                            }

                            auto send_locator_getheaders = [&]() {
                                uint256 locator;
                                if (auto tip = header_chain.tip(); tip)
                                    locator = tip->block_hash;
                                else
                                    locator = chain_params.genesis_hash;
                                LOG_INFO << "[BTC] standalone header-sync getheaders locator="
                                         << locator.GetHex().substr(0, 16)
                                         << " chain_height=" << h;
                                coin_node.send_getheaders(
                                    GETHEADERS_VERSION, {locator}, uint256::ZERO);
                            };

                            if (handshaked && !caught_up) {
                                if (!*hdr_was_handshaked)      // fresh (re)connect
                                    send_locator_getheaders();
                                else if (!advanced)            // stalled / at genesis
                                    send_locator_getheaders();
                            }
                            *hdr_was_handshaked = handshaked;

                            if (!caught_up &&
                                now - *hdr_last_progress >=
                                    std::chrono::seconds(kNoProgressFailoverSec)) {
                                LOG_INFO << "[BTC] standalone header source: no header "
                                            "progress for " << kNoProgressFailoverSec
                                         << "s (chain_height=" << h << ", handshaked="
                                         << handshaked << ") — failing over to next candidate";
                                dial_standalone_peer();
                                *hdr_last_progress  = now;    // grace window for the new peer
                                *hdr_was_handshaked = false;  // force getheaders on its handshake
                            }
                            if (auto self = weak_dial.lock()) (*self)();
                        });
                };
            (*schedule_standalone_dial)();
        }
    }

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
            // Locator: if HeaderChain has any tip, use its hash; else genesis.
            // For a fresh DB the chain is empty so locator = [genesis].
            uint256 locator;
            if (auto tip = header_chain.tip(); tip)
                locator = tip->block_hash;
            else
                locator = chain_params.genesis_hash;
            LOG_INFO << "[BTC] Sending initial getheaders, locator="
                     << locator.GetHex().substr(0, 16)
                     << " (chain_height=" << header_chain.height() << ")";
            coin_node.send_getheaders(
                BTC_PROTOCOL_VERSION, {locator}, uint256::ZERO);
        });

    // B5: stale-submit warning timer. Every 30s, scan pending_submits for
    // entries older than 60s and log [BTC-SUBMIT] STALE — typically means
    // bitcoind rejected the block (consensus failure / dup hash / wrong
    // chain) since an accepted submission should appear in HeaderChain
    // within seconds. The recursive scheduler uses weak_ptr to itself to
    // avoid a self-referencing shared_ptr cycle.
    auto warn_timer    = std::make_shared<boost::asio::steady_timer>(ioc);
    auto schedule_warn = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak_warn = schedule_warn;
    *schedule_warn = [warn_timer, pending_mu, pending_submits, weak_warn]() {
        warn_timer->expires_after(std::chrono::seconds(30));
        warn_timer->async_wait([warn_timer, pending_mu, pending_submits, weak_warn]
                               (const boost::system::error_code& ec) {
            if (ec) return;
            {
                std::lock_guard<std::mutex> lk(*pending_mu);
                auto now = std::chrono::steady_clock::now();
                for (auto it = pending_submits->begin(); it != pending_submits->end(); ) {
                    auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
                        now - it->second.submitted_at).count();
                    if (age_s >= 60) {
                        LOG_WARNING << "[BTC-SUBMIT] STALE: block "
                                    << it->first.GetHex().substr(0, 16)
                                    << " height=" << it->second.height
                                    << " pending " << age_s
                                    << "s — bitcoind likely rejected";
                        it = pending_submits->erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            if (auto self = weak_warn.lock()) (*self)();
        });
    };
    (*schedule_warn)();

    // B5b: tip-reconcile poll. When a submitted block is still pending
    // roundtrip confirmation, bitcoind may have connected it (or a
    // competing block at the same height) as its active tip WITHOUT
    // re-announcing an inv/sendheaders over our P2P leg -- Core does not
    // reliably re-announce a block to the path it was learned from. The
    // initial getheaders sync then never re-fires, so HeaderChain stalls
    // one block behind bitcoind's real tip, every new template re-mines
    // the SAME height, and each won block returns submitblock
    // "inconclusive" -> STALE (self-collision livelock; observed on the
    // vm130 G3b regtest rig 2026-08-16, tip pinned at 604 while bitcoind
    // was at 605). Fix: while ANY submit is pending, actively re-issue
    // getheaders(locator = current tip) every 10s so HeaderChain pulls
    // the connected tip and either CONFIRMS the roundtrip or advances
    // past it, unwedging template production. Gated on pending_submits so
    // there is zero getheaders churn on an idle, caught-up node.
    auto reconcile_timer    = std::make_shared<boost::asio::steady_timer>(ioc);
    auto schedule_reconcile = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak_reconcile = schedule_reconcile;
    *schedule_reconcile = [reconcile_timer, &coin_node, &header_chain,
                           &chain_params, pending_mu, pending_submits,
                           weak_reconcile, BTC_PROTOCOL_VERSION]() {
        reconcile_timer->expires_after(btc::coin::TipReconcileGate::kPollInterval);
        reconcile_timer->async_wait(
            [reconcile_timer, &coin_node, &header_chain, &chain_params,
             pending_mu, pending_submits, weak_reconcile, BTC_PROTOCOL_VERSION]
            (const boost::system::error_code& ec) {
                if (ec) return;
                bool have_pending;
                {
                    std::lock_guard<std::mutex> lk(*pending_mu);
                    have_pending = !pending_submits->empty();
                }
                if (btc::coin::TipReconcileGate::evaluate(
                        have_pending, coin_node.has_p2p(),
                        coin_node.is_handshake_complete())
                    == btc::coin::TipReconcileGate::Action::Poll) {
                    uint256 locator;
                    if (auto tip = header_chain.tip(); tip)
                        locator = tip->block_hash;
                    else
                        locator = chain_params.genesis_hash;
                    LOG_INFO << "[BTC-SUBMIT] tip-reconcile getheaders locator="
                             << locator.GetHex().substr(0, 16)
                             << " chain_height=" << header_chain.height();
                    coin_node.send_getheaders(
                        BTC_PROTOCOL_VERSION, {locator}, uint256::ZERO);
                }
                if (auto self = weak_reconcile.lock()) (*self)();
            });
    };
    (*schedule_reconcile)();

    // [MEM] periodic memory logger: every 60s, log VmRSS / VmSize from
    // /proc/self/status. Catches slow leaks invisible from in-process
    // state alone — boost::asio handler queues, leveldb caches, fragmented
    // allocator pools, etc. Lightweight (~50µs per fire). Pair with a
    // MemoryMax cgroup cap so any runaway is caught at the systemd layer.
    // Other component sizes (mempool, chain) are already logged elsewhere
    // by their own subsystems; this timer adds the OS-level RSS/VSZ that
    // was previously visible only via external `ps` polling.
    auto mem_timer    = std::make_shared<boost::asio::steady_timer>(ioc);
    auto schedule_mem = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak_mem = schedule_mem;
    *schedule_mem = [mem_timer, weak_mem]() {
        mem_timer->expires_after(std::chrono::seconds(60));
        mem_timer->async_wait([mem_timer, weak_mem]
                               (const boost::system::error_code& ec) {
            if (ec) return;
            long vm_rss_kb = 0, vm_size_kb = 0, vm_data_kb = 0;
            if (FILE* f = std::fopen("/proc/self/status", "r")) {
                char line[256];
                while (std::fgets(line, sizeof(line), f)) {
                    long v;
                    if (std::sscanf(line, "VmRSS: %ld kB",  &v) == 1) { vm_rss_kb  = v; continue; }
                    if (std::sscanf(line, "VmSize: %ld kB", &v) == 1) { vm_size_kb = v; continue; }
                    if (std::sscanf(line, "VmData: %ld kB", &v) == 1) { vm_data_kb = v; continue; }
                }
                std::fclose(f);
            }
            // Hand glibc-resident-but-freed pages back to the kernel. Heaptrack
            // v4 (post Phase 1A+1B+1C) showed peak heap at 182 MB but RSS still
            // grew ~140 MB/h — confirmed glibc malloc-pool fragmentation, not a
            // true heap leak. malloc_trim(0) walks the top chunk of every arena
            // and madvise(MADV_DONTNEED)s pages that are free. Cheap (~ms) on
            // typical heap sizes, returns 1 if it actually released memory.
#if defined(__GLIBC__)
            int trimmed = ::malloc_trim(0);
#else
            int trimmed = 0;   // malloc_trim is a glibc extension; no-op on macOS/MSVC
#endif
            LOG_INFO << "[MEM] vmrss=" << vm_rss_kb << "kB"
                     << " vmsize=" << vm_size_kb << "kB"
                     << " vmdata=" << vm_data_kb << "kB"
                     << " malloc_trim=" << trimmed;
            if (auto self = weak_mem.lock()) (*self)();
        });
    };
    (*schedule_mem)();

    // ── B4-net: c2pool sharechain peer ───────────────────────────────────
    // pool::NodeBridge<NodeImpl, Legacy, Actual> from src/impl/btc/node.{hpp,cpp}.
    // Speaks the jtoomim/SPB BTC p2pool wire protocol (proto 3502, share v35
    // PaddingBugfixShare). NodeImpl ctor opens ~/.c2pool/<net>/sharechain_leveldb
    // for share persistence and seeds the addr store from m_bootstrap_addrs;
    // we set those + m_prefix BEFORE constructing the node.
    config.pool()->m_prefix = ParseHexBytes(btc::PoolConfig::prefix_hex());
    config.m_testnet        = testnet;

    if (!p2pool_host.empty() && p2pool_port != 0)
    {
        // Single explicit target — clear defaults so we dial only the named peer.
        config.pool()->m_bootstrap_addrs.clear();
        config.pool()->m_bootstrap_addrs.emplace_back(p2pool_host, p2pool_port);

        // AddrStore ctor reads addrs.json from disk if present, MERGING any
        // saved-from-prior-runs peers with our bootstrap_addrs. Saved peers
        // can outrank our just-added explicit target (get_good_peers scores
        // by first_seen/last_seen). When --p2pool is given the user has
        // explicitly chosen this peer — reset addr store so it actually wins.
        const auto addrs_path = net_dir / "addrs.json";
        std::error_code rm_ec;
        std::filesystem::remove(addrs_path, rm_ec);  // best-effort

        LOG_INFO << "[BTC] Sharechain bootstrap: explicit --p2pool "
                 << p2pool_host << ":" << p2pool_port
                 << " (addrs.json reset to enforce exclusive target)";
    }
    else if (regtest)
    {
        // Isolated regtest standup: NEVER dial the public mainnet p2pool seeds
        // (DEFAULT_BOOTSTRAP_HOSTS). Leaving the addr store empty keeps the
        // sharechain solo/local so a won block is never relayed to real peers.
        // Supply --p2pool HOST:PORT to dial an explicit isolated tuned-net peer.
        LOG_INFO << "[BTC] Sharechain bootstrap: regtest — 0 public seeds (isolated)";
    }
    else
    {
        // Default seed list (PoolConfig::DEFAULT_BOOTSTRAP_HOSTS, port 9333).
        for (const auto& host : btc::PoolConfig::DEFAULT_BOOTSTRAP_HOSTS)
        {
            // Some entries already include ":port" — preserve, else append.
            std::string addr = host.find(':') == std::string::npos
                ? host + ":" + std::to_string(btc::PoolConfig::P2P_PORT)
                : host;
            config.pool()->m_bootstrap_addrs.emplace_back(addr);
        }
        LOG_INFO << "[BTC] Sharechain bootstrap: "
                 << config.pool()->m_bootstrap_addrs.size()
                 << " default seeds";
    }

    auto p2p_node = std::make_unique<btc::Node>(&ioc, &config);
    p2p_node->set_target_outbound_peers(p2pool_host.empty() ? 4 : 1);
    // Default sharechain P2P port is 9333 (oracle byte-parity); --sharechain-port
    // overrides it for an isolated second instance (G3b tuned-net) without
    // touching the default or any shared-base constant.
    const uint16_t effective_p2p_port =
        sharechain_port ? sharechain_port : btc::PoolConfig::P2P_PORT;
    p2p_node->core::Server::listen(effective_p2p_port);
    LOG_INFO << "[BTC] Sharechain peer listening on port "
             << effective_p2p_port
             << (sharechain_port ? " (--sharechain-port override; default 9333)" : "")
             << " — proto adv=" << btc::PoolConfig::ADVERTISED_PROTOCOL_VERSION
             << " min=" << btc::PoolConfig::MINIMUM_PROTOCOL_VERSION
             << " share=v35 prefix=" << btc::PoolConfig::prefix_hex();
    p2p_node->start_outbound_connections();
    LOG_INFO << "[BTC] Outbound peer dialing started ("
             << config.pool()->m_bootstrap_addrs.size() << " bootstrap addrs)";

    // ── B7-stratum: stratum server + BTCWorkSource (miner-facing TCP) ────
    //
    // Mempool is constructed unwired for the MVP — TemplateBuilder still
    // produces valid coinbase-only templates from chain_.tip() + subsidy.
    // Wiring bitcoind P2P inv_tx → mempool.add_tx is a follow-up phase
    // (current LTC integration uses RPC getrawmempool which we deliberately
    // don't have in embedded mode).
    btc::coin::Mempool mempool;
    mempool.set_utxo(&utxo_cache);

    // ── Mempool wiring (Phase 10c) ────────────────────────────────────────
    //
    // Feed the local mempool from bitcoind's P2P inv stream so TemplateBuilder
    // produces real fee-bearing templates instead of coinbase-only ones.
    // bitcoind announces new mempool txs via `inv` of MSG_TX, NodeP2P
    // requests them via getdata, and on receipt fires coin_node.new_tx with
    // the parsed Transaction. We add to mempool; a later [BTC] full_block
    // subscriber removes confirmed txs.
    //
    // Mempool::add_tx without UTXO context cannot compute the fee — fees
    // start at sentinel UNKNOWN.  Subsequent block connects bring new
    // UTXOs into view, so fees of previously-unknown txs become resolvable.
    // The full_block hook below drives this revalidation each tip change.
    coin_node.new_tx.subscribe(
        [&mempool, &utxo_cache](const btc::coin::Transaction& tx) {
            // The Transaction → MutableTransaction round-trip is required
            // because Mempool::add_tx takes the mutable variant (matches the
            // pattern used by btc::coin::TemplateBuilder).
            btc::coin::MutableTransaction mtx(tx);
            (void)mempool.add_tx(mtx, &utxo_cache);
        });

    // remove_for_block on every full block we receive — connecting txs are
    // no longer mempool-eligible. Keeps the mempool honest after each new
    // tip without us having to track individual confirmations.
    //
    // After remove, also drive two UTXO-dependent maintenance passes:
    //   1. revalidate_inputs: evict txs whose inputs the new block spent
    //      out from under us (catches the case where remove_for_block's
    //      conflict detection didn't see the spend — e.g., the spending
    //      tx wasn't tracked in m_spent_outputs, parent-of-CPFP, etc).
    //   2. recompute_unknown_fees: re-attempt fee computation for txs
    //      that came in via new_tx before their inputs were visible.
    //      Without this, txs with unresolved inputs stay fee=? forever
    //      and are skipped by TemplateBuilder's fee-sorted include path
    //      → blocks miss legitimate fees that were just one tip behind.
    //
    // Subscriber-call order: this lambda registers AFTER the UTXO
    // connect_block subscriber at line 434, so by the time we run the
    // UTXO has the new block already applied. revalidate_inputs and
    // recompute_unknown_fees both operate on the post-connect snapshot.
    coin_node.full_block.subscribe(
        [&mempool, &utxo_cache](const btc::coin::BlockType& block) {
            mempool.remove_for_block(block);
            int evicted   = mempool.revalidate_inputs(&utxo_cache);
            int resolved  = mempool.recompute_unknown_fees(&utxo_cache);
            if (evicted > 0 || resolved > 0) {
                LOG_INFO << "[EMB] post-tip mempool maintenance: evicted="
                         << evicted << " resolved_fees=" << resolved;
            }
        });

    // submit_block_fn: bridges BTCWorkSource → coin_node.submit_block_p2p_raw
    // + adds to B5's pending_submits map for roundtrip tracking. Lambda
    // captures by reference so it reuses the existing B5 infrastructure
    // instead of duplicating it.
    auto stratum_submit_fn = [&coin_node, pending_mu, pending_submits]
        (const std::vector<unsigned char>& block_bytes, uint32_t height) -> bool
    {
        // Compute block_hash for pending_submits tracking. BTC block_hash =
        // SHA256d of the first 80 bytes (the header).
        if (block_bytes.size() < 80) {
            LOG_WARNING << "[BTC-STRATUM-BLOCK] block bytes too short ("
                        << block_bytes.size() << " < 80) — not submitting";
            return false;
        }
        uint256 block_hash = Hash(std::span<const unsigned char>(block_bytes.data(), 80));
        {
            std::lock_guard<std::mutex> lk(*pending_mu);
            (*pending_submits)[block_hash] = {
                std::chrono::steady_clock::now(), height
            };
        }
        LOG_INFO << "[BTC-SUBMIT] sending block " << block_hash.GetHex().substr(0, 16)
                 << " height=" << height << " (via stratum)";
        // CONNECT-AUTHORITATIVE: P2P relay (fast propagation) + submitblock RPC
        // fired UNCONDITIONALLY so the won block actually connects. A P2P
        // cmpctblock announce-success alone does NOT connect the tip (daemon
        // requests the body via getblocktxn, which we do not serve) - the
        // silent-loss this path closes. BTC-fenced; cross-coin fallback intact.
        return coin_node.submit_block_for_connect(block_bytes);
    };

    // Per-share template retention for the won-block reconstructor (slice 7/7).
    // create_share_fn seeds it (keyed by the freshly-minted share_hash) with the
    // template's non-coinbase tx set; a won share replays that EXACT set so the
    // reconstructed block body is merkle-consistent with the share-committed
    // header. Declared BEFORE work_source so it OUTLIVES the create_share_fn that
    // captures it and the m_on_block_found closure that reads its provider().
    btc::coin::TemplateCapture template_capture;

    // Construct the work source. Holds non-owning refs to chain + mempool;
    // both outlive it (stack-scoped main() lifetime).
    auto work_source = std::make_shared<btc::stratum::BTCWorkSource>(
        header_chain, mempool, testnet, std::move(stratum_submit_fn));
    work_source_for_shutdown = work_source;  // expose to signal handler

    // PA/PB: hand the merged-mining manager to the work source (PR-2a seam,
    // work_source.hpp set_merged_mining_manager). null absent --merged =>
    // has_merged_chain() false, plain-BTC path byte-identical.
    if (mm_manager)
        work_source->set_merged_mining_manager(mm_manager.get());

    // ── PPLNS + ref_hash callbacks (Phase 8d) ────────────────────────────
    //
    // These wire the BTCWorkSource's coinbase builder to the live BTC
    // sharechain via btc::ShareTracker. The pplns lambda is the real
    // deal — calls get_v35_expected_payouts under read_tracker() guard.
    // The ref_hash lambda is a SOPHISTICATED STUB: it calls
    // compute_ref_hash_for_work with sane defaults for tracker-derived
    // fields (absheight, abswork, far_share_hash). Until those are
    // properly walked from the tracker, the resulting ref_hash will not
    // match what live SPB peers expect — c2pool-btc-built shares get
    // produced locally but won't be accepted by the wider sharechain.
    // That's the next concrete TODO; the wiring + payouts are now real.

    auto* p2p_node_raw = p2p_node.get();  // captured by reference into lambdas

    // Pillar 1 (forward-version-voting): AutoRatchet drives btc's autonomous
    // V35->V36 share-version transition for its OWN modern sharechain.
    // target_version=36 — votes toward + activates V36; the machine is
    // v37-generic (bump target later). State persists under the net dir.
    const std::string ratchet_path = (net_dir / "v36_ratchet.json").string();
    auto auto_ratchet = std::make_shared<btc::AutoRatchet>(ratchet_path, /*target_version=*/36);
    LOG_INFO << "[AutoRatchet] Initialized: state="
             << btc::ratchet_state_str(auto_ratchet->state())
             << " target=V36 file=" << ratchet_path;

    // Wire best-share lookup: BTCWorkSource asks via this fn to determine
    // prev_share_hash for new jobs. Returns the sharechain tip the local
    // node has built up to. Empty (uint256::ZERO) on cold start; the
    // ref_hash callback then falls into its genesis branch — that ref_hash
    // won't match peers, but it's the right answer pre-bootstrap.
    work_source->set_best_share_hash_fn(
        [p2p_node_raw]() -> uint256 {
            if (!p2p_node_raw) return uint256::ZERO;
            return p2p_node_raw->best_share_hash();
        });

    {
        // Initial donation script must match the genesis share's version
        // (created before the first PPLNS-hook refresh). AutoRatchet bootstrap
        // returns V35 until the chain votes in V36, so P2PK DONATION_SCRIPT is
        // used pre-transition and COMBINED P2SH after — matching gentx.
        int64_t initial_ver = 35;
        if (p2p_node_raw) {
            auto [iv, idv] = auto_ratchet->get_share_version(
                p2p_node_raw->tracker(), uint256::ZERO);
            initial_ver = iv;
        }
        work_source->set_donation_script(
            btc::PoolConfig::get_donation_script(initial_ver));
        LOG_INFO << "[AutoRatchet] initial donation script V" << initial_ver;
    }

    work_source->set_pplns_fn(
        [p2p_node_raw, auto_ratchet, ws = work_source.get()](
                       const uint256& best_share_hash,
                       const uint256& block_target,
                       uint64_t subsidy,
                       const std::vector<unsigned char>& /*donation_script*/)
        -> std::map<std::vector<unsigned char>, double>
        {
            if (!p2p_node_raw) return {};
            auto guard = p2p_node_raw->read_tracker();
            if (!guard) {
                // Tracker busy with compute thread — return empty so the
                // coinbase falls back to single-output mode for THIS work
                // refresh. Next refresh will likely succeed.
                return {};
            }
            // Pillar 1: AutoRatchet picks the live share version from chain
            // vote state. Donation script + PPLNS formula must BOTH match it
            // (v35 flat PPLNS + P2PK donation, v36 decayed PPLNS + P2SH).
            auto [share_version, desired_ver] =
                auto_ratchet->get_share_version(*guard, best_share_hash);
            auto correct_donation = btc::PoolConfig::get_donation_script(share_version);
            ws->set_donation_script(correct_donation);
            try {
                if (share_version < 36)
                    return guard->get_v35_expected_payouts(
                        best_share_hash, block_target, subsidy, correct_donation);
                return guard->get_expected_payouts(
                    best_share_hash, block_target, subsidy, correct_donation);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-STRATUM] get_expected_payouts threw: " << e.what();
                return {};
            }
        });

    work_source->set_ref_hash_fn(
        [p2p_node_raw, auto_ratchet](const uint256& prev_share_hash,
                       const std::vector<unsigned char>& scriptSig,
                       const std::vector<unsigned char>& payout_script,
                       uint64_t subsidy, uint32_t block_bits, uint32_t timestamp)
        -> core::stratum::RefHashResult
        {
            // Phase 12 contract: produce both the ref_hash AND the full
            // chain-walked snapshot needed to populate snap.frozen_ref —
            // bits / max_bits (from tracker.compute_share_target),
            // absheight / abswork / far_share_hash (from prev walk),
            // timestamp_clipped (>= prev->m_timestamp + 1).
            //
            // The block_bits parameter is the BTC mainnet GBT block target;
            // we feed it as desired_target into compute_share_target to
            // get the actual sharechain target the network is currently
            // running. Pre-Phase-12 we used `bits` (block bits) directly
            // as p.bits — that produced ref_hashes peers couldn't verify
            // (ref_hash includes share_bits, not block_bits).
            core::stratum::RefHashResult result;
            result.share_version   = 35;
            result.desired_version = 35;
            result.timestamp       = timestamp;  // overwritten below if clipped

            btc::RefHashParams p;
            p.share_version       = 35;
            p.prev_share          = prev_share_hash;
            p.coinbase_scriptSig  = scriptSig;
            p.share_nonce         = 0;             // matches LTC line 4281
            p.subsidy             = subsidy;
            p.donation            = 50;            // 0.5% (matches finder fee)
            p.stale_info          = 0;
            p.desired_version     = 35;
            p.has_segwit          = false;         // TODO Phase 8c+: detect from rules
            p.timestamp           = timestamp;
            // p.bits / p.max_bits set below from compute_share_target

            // Heuristic v35 pubkey extract: P2PKH is 0x76 0xa9 0x14 + 20B + 0x88 0xac.
            if (payout_script.size() == 25 && payout_script[0] == 0x76 &&
                payout_script[1] == 0xa9 && payout_script[2] == 0x14 &&
                payout_script[23] == 0x88 && payout_script[24] == 0xac)
            {
                std::memcpy(p.pubkey_hash.begin(), payout_script.data() + 3, 20);
                p.pubkey_type = 0;
            }
            // Bech32 P2WSH/P2WPKH: leave pubkey_hash zeroed for now (TODO).

            // Defaults if tracker access fails — fall back to block bits so
            // we still emit *some* ref_hash. These won't validate against
            // peers but at least produce a well-formed coinbase OP_RETURN.
            auto set_block_bits_fallback = [&] {
                p.bits         = block_bits;
                p.max_bits     = block_bits;
                result.bits    = block_bits;
                result.max_bits = block_bits;
            };

            // ── Walk the share tracker for chain-position fields + share_target ──
            //
            // All values below are deterministically derived from the share
            // chain — every node walking the same chain MUST produce the
            // same values, otherwise ref_hash diverges and peers reject.
            if (p2p_node_raw) {
                auto guard = p2p_node_raw->read_tracker();
                if (guard) {
                    auto& tracker = *guard;

                    // Pillar 1: AutoRatchet sets the live share version from
                    // network vote state, overriding the V35 genesis defaults
                    // above once a chain exists. Done before compute_share
                    // _target so p.share_version is consistent with the rest.
                    {
                        auto [sv, dv] = auto_ratchet->get_share_version(
                            tracker, prev_share_hash);
                        result.share_version   = sv;
                        result.desired_version = dv;
                        p.share_version        = sv;
                        p.desired_version      = dv;
                    }

                    // Step 1 (must run before compute_share_target): clip
                    // timestamp + walk for absheight + far_share_hash.
                    // create_local_share_v35 (share_check.hpp:2126-2134)
                    // clips share.m_timestamp BEFORE calling compute_share
                    // _target with that clipped value — we must match that
                    // ordering so the (max_bits, bits) we report equal the
                    // values peers will compute on the same prev_share.
                    if (!prev_share_hash.IsNull() && tracker.chain.contains(prev_share_hash)) {
                        tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                            p.absheight = prev->m_absheight + 1;
                            if (p.timestamp <= prev->m_timestamp)
                                p.timestamp = prev->m_timestamp + 1;
                        });

                        auto [prev_height, _last] = tracker.chain.get_height_and_last(prev_share_hash);
                        if (prev_height >= 99) {
                            try {
                                p.far_share_hash = tracker.chain.get_nth_parent_key(prev_share_hash, 99);
                            } catch (const std::exception&) {
                                p.far_share_hash = uint256::ZERO;
                            }
                        } else {
                            p.far_share_hash = uint256::ZERO;
                        }
                    } else {
                        p.absheight      = 1;  // genesis
                        p.far_share_hash = uint256::ZERO;
                    }

                    // Step 2: share_target via compute_share_target with
                    // the *clipped* timestamp — same call create_local
                    // _share_v35 makes (share_check.hpp:2138).
                    auto desired_target = chain::bits_to_target(block_bits);
                    try {
                        auto st = tracker.compute_share_target(
                            prev_share_hash, p.timestamp, desired_target);
                        p.bits          = st.bits;
                        p.max_bits      = st.max_bits;
                        result.bits     = st.bits;
                        result.max_bits = st.max_bits;
                    } catch (const std::exception&) {
                        set_block_bits_fallback();
                    }

                    // Step 3: abswork = prev_abswork + work-of-this-share-at-bits
                    if (!prev_share_hash.IsNull() && tracker.chain.contains(prev_share_hash)) {
                        tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                            auto attempts = chain::target_to_average_attempts(
                                chain::bits_to_target(p.bits));
                            p.abswork = prev->m_abswork + uint128(attempts.GetLow64());
                        });
                    } else {
                        // Genesis case (cold-start or unknown prev)
                        p.absheight      = 1;
                        p.abswork        = uint128(chain::target_to_average_attempts(
                            chain::bits_to_target(p.bits)).GetLow64());
                        p.far_share_hash = uint256::ZERO;
                    }
                } else {
                    // Tracker busy — fallback values, ref_hash won't match peers
                    set_block_bits_fallback();
                    p.absheight      = 1;
                    p.abswork        = uint128(chain::target_to_average_attempts(
                        chain::bits_to_target(p.bits)).GetLow64());
                    p.far_share_hash = uint256::ZERO;
                }
            } else {
                set_block_bits_fallback();
                p.absheight      = 1;
                p.abswork        = uint128(chain::target_to_average_attempts(
                    chain::bits_to_target(p.bits)).GetLow64());
                p.far_share_hash = uint256::ZERO;
            }

            // Mirror the walked values into the result for snap.frozen_ref
            result.absheight      = p.absheight;
            result.abswork        = p.abswork;
            result.far_share_hash = p.far_share_hash;
            result.timestamp      = p.timestamp;

            try {
                auto [rh, nn] = btc::compute_ref_hash_for_work(p);
                result.ref_hash         = rh;
                result.last_txout_nonce = nn;
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-STRATUM] compute_ref_hash_for_work threw: " << e.what();
                // result.ref_hash stays default (zero) — caller emits no OP_RETURN
            }
            return result;
        });

    LOG_INFO << "[BTC-STRATUM] PPLNS + ref_hash callbacks wired"
             << " (donation_script=" << btc::PoolConfig::get_donation_script(35).size()
             << "B P2PK; ref_hash walks share tracker for share_target/absheight/abswork/far_share)";

    // ── Sharechain WRITE path (Phase 11) ──────────────────────────────────
    //
    // mining_submit calls this when a stratum submission's PoW meets the
    // sharechain target. The lambda:
    //   1. Parses 80-byte header → SmallBlockHeaderType (the v35 share's
    //      "min_header" field — a trimmed block header that omits the
    //      merkle_root since that's reconstructible from the share's
    //      coinbase + frozen branches).
    //   2. Wraps full_coinbase in a BaseScript.
    //   3. Converts string-hex merkle_branches → vector<uint256>.
    //   4. Acquires EXCLUSIVE tracker lock via try_to_lock — non-blocking;
    //      defer to next miner submission if compute thread is mid-think.
    //   5. Calls btc::create_local_share<TrackerT>(...) which builds a
    //      v35 PaddingBugfixShare, runs PoW recheck, and tracker.add()s
    //      it. Returns share_hash on success, uint256::ZERO on failure.
    //   6. On success: broadcast_share + notify_local_share so peers learn
    //      our new tip and miners get fresh work.
    //
    // create_local_share INTERNAL behavior (relevant to debug):
    //   - validates PoW against bits-derived target
    //   - reconstructs ref_hash from frozen fields and verifies it matches
    //     what the coinbase OP_RETURN claims
    //   - calls tracker.add(share) — attempt_verify runs later in think()
    work_source->set_create_share_fn(
        [p2p_node_raw, auto_ratchet, &template_capture, &merged_configs](const std::vector<unsigned char>& full_coinbase,
                       const std::vector<uint8_t>&        header_80b,
                       const core::stratum::JobSnapshot&  job,
                       const std::vector<unsigned char>& payout_script)
        -> uint256
        {
            if (!p2p_node_raw || header_80b.size() != 80) {
                LOG_WARNING << "[BTC-CREATE-SHARE] precondition fail: p2p_node="
                            << (p2p_node_raw ? "ok" : "null")
                            << " header_size=" << header_80b.size();
                return uint256::ZERO;
            }

            // ── Parse 80B BTC block header ──
            auto read_le32 = [](const uint8_t* p) -> uint32_t {
                return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                     | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
            };

            btc::coin::SmallBlockHeaderType min_header;
            min_header.m_version   = read_le32(header_80b.data() + 0);
            std::memcpy(min_header.m_previous_block.data(),
                        header_80b.data() + 4, 32);
            // bytes 36..67 are merkle_root — not stored in min_header
            min_header.m_timestamp = read_le32(header_80b.data() + 68);
            min_header.m_bits      = read_le32(header_80b.data() + 72);
            min_header.m_nonce     = read_le32(header_80b.data() + 76);

            // ── Wrap coinbase + convert merkle branches ──
            BaseScript coinbase_bs(std::vector<unsigned char>(
                full_coinbase.begin(), full_coinbase.end()));

            // Wire format for stratum branches is hex of LE-internal bytes
            // (see get_stratum_merkle_branches).  Parse via ParseHex+memcpy
            // — SetHex would reverse, producing uint256s that don't match
            // the bytes the miner already used to build their merkle root.
            std::vector<uint256> merkle_branches;
            merkle_branches.reserve(job.merkle_branches.size());
            for (const auto& bhex : job.merkle_branches) {
                uint256 b;
                auto bb = ParseHex(bhex);
                if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
                merkle_branches.push_back(b);
            }

            // ── Acquire EXCLUSIVE tracker lock (try, non-blocking) ──
            std::unique_lock<std::shared_mutex> lk(
                p2p_node_raw->tracker_mutex(), std::try_to_lock);
            if (!lk.owns_lock()) {
                LOG_INFO << "[BTC-CREATE-SHARE] tracker busy — share deferred";
                return uint256::ZERO;
            }

            // ── Call into btc::create_local_share ──
            // v35 path: dispatches internally based on share_version arg.
            // No merged_addrs (BTC v35 has no merged mining).
            // Pillar 1: live share version from AutoRatchet (the EXCLUSIVE
            // tracker lock is already held above). create_local_share
            // dispatches on this: <=35 -> V35 gentx path, >=36 -> V36 path
            // (P2SH donation + decayed PPLNS). This is how v36_active reaches
            // generate_share_transaction for locally created shares.
            auto [voted_ver, voted_desired] = auto_ratchet->get_share_version(
                p2p_node_raw->tracker(), job.prev_share_hash);

            uint256 share_hash;
            // P1 PE anchor (nmc/pe-main-btc-host-wire): merged_addrs is the
            // seam the embedded NMC aux backend feeds — next slices add the
            // --merged parse -> embedded-NMC register -> aux-merkle payout.
            // Empty here == v35 behavior byte-for-byte until the backend is
            // wired, so this commit is a no-op at runtime.
            // NMC PE host-wire slice 4: commit one aux payout entry per parsed
            // --merged chain. Empty absent --merged (v35 byte-for-byte). Until
            // PC freezes per-share PPLNS aux scripts into the template, this
            // feeds the parent payout_script under each aux chain_id — the
            // --merged path is wire-only and not yet consensus-consistent with
            // the frozen ref, so it stays behind that opt-in flag.
            std::vector<btc::MergedAddressEntry> merged_addrs =
                btc::merged_addr_entries(merged_configs, payout_script);
            try {
                share_hash = btc::create_local_share(
                    p2p_node_raw->tracker(),
                    min_header,
                    coinbase_bs,
                    /* subsidy */               job.subsidy,
                    /* prev_share */            job.prev_share_hash,
                    merkle_branches,
                    payout_script,
                    /* donation */              50,         // 0.5%
                    /* merged_addrs */          merged_addrs,
                    /* stale_info */            btc::StaleInfo::none,
                    /* segwit_active */         job.segwit_active,
                    /* witness_commitment */    job.witness_commitment_hex,
                    /* message_data */          {},
                    /* actual_coinbase_bytes */ std::vector<unsigned char>(
                                                    full_coinbase.begin(),
                                                    full_coinbase.end()),
                    /* witness_root */          job.witness_root,
                    /* override_max_bits */     job.frozen_ref.max_bits,
                    /* override_bits */         job.frozen_ref.bits,
                    /* frozen_absheight */      job.frozen_ref.absheight,
                    /* frozen_abswork */        job.frozen_ref.abswork,
                    /* frozen_far_share_hash */ job.frozen_ref.far_share_hash,
                    /* frozen_timestamp */      job.frozen_ref.timestamp,
                    /* frozen_merged_payout */  job.frozen_ref.merged_payout_hash,
                    // Phase 12: frozen_ref is now fully populated by
                    // build_connection_coinbase from the ref_hash_fn result
                    // (which walks the tracker for share_target + absheight
                    // + abswork + far_share_hash + clipped timestamp). The
                    // override values match what create_local_share_v35 would
                    // compute itself — but using the FROZEN values avoids
                    // races between template-build time and submit time
                    // (best_share could move under us mid-submit otherwise).
                    /* has_frozen */            true,
                    /* frozen_merkle_branches*/ job.frozen_ref.frozen_merkle_branches,
                    /* frozen_witness_root */   job.frozen_ref.frozen_witness_root,
                    /* frozen_merged_cb_info */ job.frozen_ref.frozen_merged_coinbase_info,
                    /* share_version */         voted_ver,
                    /* desired_version */       voted_desired);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-CREATE-SHARE] threw: " << e.what();
                return uint256::ZERO;
            }

            // Lock release order: drop the unique_lock BEFORE calling
            // broadcast_share / notify_local_share — those acquire their
            // own locks (or post to io_context) and we don't want to hold
            // exclusive while they run.
            lk.unlock();

            if (!share_hash.IsNull()) {
                // Retain the template's non-coinbase tx set keyed by THIS share's
                // hash for the won-block reconstructor (#840 decode contract:
                // [{"data": <raw-tx-hex>}, ...] in template order). A capture MISS
                // at won time decodes to empty -> a valid coinbase-only block.
                nlohmann::json tmpl_txs = nlohmann::json::array();
                if (job.tx_data)
                    for (const auto& tx_hex : *job.tx_data)
                        tmpl_txs.push_back(nlohmann::json::object({{"data", tx_hex}}));
                // F3: hand the template's tx set to the node (which owns
                // m_known_txs and takes its own lock) so every tx this share's
                // template committed to is forwardable and the share is backable
                // BEFORE we broadcast it. Must precede the capture move.
                p2p_node_raw->register_template_txs(share_hash, tmpl_txs);

                template_capture.capture(share_hash, std::move(tmpl_txs));

                p2p_node_raw->broadcast_share(share_hash);
                p2p_node_raw->notify_local_share(share_hash);
                LOG_INFO << "[BTC-CREATE-SHARE] OK + broadcast: hash="
                         << share_hash.GetHex().substr(0, 16);
            }
            return share_hash;
        });

    LOG_INFO << "[BTC-STRATUM] sharechain write path wired (mining_submit"
             << " → create_local_share → broadcast_share + notify_local_share)";

    // ── #995/#1155 BTC found-block reporter slot ──────────────────────────
    // Bound BELOW under --http once the MiningInterface exists; the won-block
    // dispatch (make_on_block_found, wired just below) forwards every
    // reconstructed win through this shared slot to record_found_block +
    // schedule_block_verification. Empty until then (or with the dashboard
    // off): a won block still broadcasts, it is simply not recorded. TELEMETRY
    // ONLY -- never on any broadcast/mint/target/payout path.
    auto found_block_report = std::make_shared<
        std::function<void(const uint256&, const std::vector<unsigned char>&,
                           const std::string&)>>();

    // ── #744 won-block DISPATCH wire (reconstructor slice 7/7 — FINAL) ─────
    //
    // Un-stub tracker.m_on_block_found. A share that clears the PARENT target
    // (share_init_verify flags g_last_init_is_block; attempt_verify fires the
    // callback, share_tracker.hpp:536) now reconstructs the FULL parent block
    // from live tracker state + the captured template txs and dispatches it on
    // the connect-authoritative dual path — closing the silent won-block DROP.
    //
    // THREADING: m_on_block_found fires on the COMPUTE thread (think()'s single
    // m_think_pool thread) while it holds m_tracker_mutex EXCLUSIVELY, so the
    // field/gentx providers read tracker().chain DIRECTLY and must NOT take
    // read_tracker() (self-deadlock). The two network sinks (NodeP2P relay,
    // NodeRPC submitblock) are single-thread-confined to the io_context, so each
    // io::post's its write onto ioc; make_on_block_found's dual-path audit then
    // reflects arm AVAILABILITY (has_p2p/has_rpc — a "reached NEITHER" only when
    // BOTH arms are absent = a genuine lost subsidy), while the real daemon
    // verdict is logged by submit_block_hex (#752) + pending_submits on ioc.
    {
        auto reconstruct = btc::coin::make_reconstruct_closure(
            /*share_fields_fn=*/
            [p2p_node_raw](const uint256& h)
                -> btc::coin::WonShareReconstructFields {
                btc::coin::WonShareReconstructFields f;
                bool found = false;
                p2p_node_raw->tracker().chain.get_share(h).invoke([&](auto* obj) {
                    f.small_header  = obj->m_min_header;
                    f.share_version = std::decay_t<decltype(*obj)>::version;
                    f.merkle_link   = obj->m_merkle_link;
                    if constexpr (requires { obj->m_segwit_data; }) {
                        if (obj->m_segwit_data.has_value())
                            f.txid_merkle_link =
                                obj->m_segwit_data->m_txid_merkle_link;
                    }
                    found = true;
                });
                if (!found)
                    throw std::runtime_error(
                        "won-share fields: share absent from chain");
                return f;
            },
            /*gentx_bytes_fn=*/
            [p2p_node_raw](const uint256& h) -> std::vector<unsigned char> {
                std::vector<unsigned char> bytes;
                bool found = false;
                auto& tracker = p2p_node_raw->tracker();
                tracker.chain.get_share(h).invoke([&](auto* obj) {
                    // Regenerate the share's SSOT gentx byte-for-byte. GST derives
                    // use_v36_pplns = v36_active || is_v36_active(ShareT::version),
                    // so passing v36_active=false is IDENTICAL to the verify-path
                    // call (share_check.hpp:1807, which uses the share's OWN
                    // compile-time version) -> the bytes hash to the committed
                    // txid, merkle-consistent.
                    (void)btc::generate_share_transaction(
                        *obj, tracker, /*dump_diag=*/false,
                        /*v36_active=*/false, /*out_gentx_bytes=*/&bytes);
                    found = true;
                });
                if (!found || bytes.empty())
                    throw std::runtime_error(
                        "won-share gentx regen: share absent / empty gentx");
                return bytes;
            },
            /*template_other_txs_fn=*/
            btc::coin::make_template_other_txs_fn(template_capture.provider()));

        p2p_node_raw->tracker().m_on_block_found = btc::coin::make_on_block_found(
            /*reconstruct=*/std::move(reconstruct),
            /*relay_p2p=*/[&ioc, coin = &coin_node](
                              const std::vector<unsigned char>& block_bytes)
                              -> bool {
                // NodeP2P is single-thread-confined to ioc — post the relay write.
                io::post(ioc, [coin, b = block_bytes]() {
                    coin->submit_block_p2p_raw(b);
                });
                return coin->has_p2p();   // arm available => not a lost subsidy
            },
            /*submit_rpc=*/[&ioc, coin = &coin_node](const std::string& block_hex)
                               -> bool {
                // NodeRPC shares ioc's stream — post the submitblock write.
                io::post(ioc, [coin, hex = block_hex]() {
                    coin->submit_block_hex_str(hex);
                });
                return coin->has_rpc();
            },
            /*on_found=*/[found_block_report](const uint256& sh,
                                              const std::vector<unsigned char>& bytes,
                                              const std::string& hex) {
                // Forward to the dashboard/verdict producer once it is bound
                // (below, under --http). No-op while unbound. Telemetry only.
                if (*found_block_report) (*found_block_report)(sh, bytes, hex);
            });
    }
    LOG_INFO << "[BTC] won-block dispatch WIRED: m_on_block_found -> faithful"
             << " reconstruct (share fields + SSOT gentx + captured template txs)"
             << " -> dual-path (P2P relay + submitblock RPC) — reconstructor 7/7";

    // Share-target: leave at 0 → frozen_ref.bits=0 / frozen_ref.max_bits=0
    // → override_bits=0 in create_local_share_v35 → share.m_bits is taken
    // from tracker.compute_share_target(prev_share, ...), the REAL network
    // sharechain target. Without this, a hardcoded diff-1 trivially passes
    // the internal PoW check, we add+broadcast invalid shares, and peers
    // promptly RST/ban us (verified empirically 2026-05-02 on .122 oracle:
    // disconnect 14ms after first broadcast).
    //
    // Stratum-side mining_submit's share_target check falls back to diff-1
    // when share_bits==0 (work_source.cpp:711), so pseudoshares are still
    // accepted for PPLNS bookkeeping. The chain WRITE path is reached only
    // when a bitaxe genuinely finds a hash meeting network sharechain
    // difficulty (~2e8) — that's the correct gate.
    LOG_INFO << "[BTC-STRATUM] share target left at 0 — create_local_share_v35"
             << " will use tracker.compute_share_target (real network target)";

    // Bump work-generation counter on every chain tip change. The stratum
    // server uses this to detect stale work between job-push timer firings
    // without snapshotting full template state.
    coin_node.new_headers.subscribe(
        [work_source](const std::vector<btc::coin::BlockHeaderType>&)
        { work_source->bump_work_generation(); });
    coin_node.full_block.subscribe(
        [work_source](const btc::coin::BlockType&)
        { work_source->bump_work_generation(); });

    std::unique_ptr<core::StratumServer> stratum_server;
    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_addr, stratum_port, work_source);
        if (stratum_server->start()) {
            LOG_INFO << "[BTC-STRATUM] listening on " << stratum_addr << ":" << stratum_port
                     << " (work source: BTCWorkSource, share v35, full c2pool stack:"
                     << " PPLNS + ref_hash + segwit_commit + sharechain write)";
        } else {
            LOG_WARNING << "[BTC-STRATUM] failed to bind " << stratum_addr << ":" << stratum_port
                        << " — stratum disabled";
            stratum_server.reset();
        }
    } else {
        LOG_INFO << "[BTC-STRATUM] disabled (no --stratum flag)";
    }
    // Expose to the signal handler for graceful shutdown. Note: signal_set
    // can fire as soon as we registered the async_wait, which means
    // theoretically the handler could see an empty stratum_server_for_shutdown
    // if a signal arrived during early init. That's fine — the `if` guard in
    // the lambda handles it.
    stratum_server_for_shutdown = std::move(stratum_server);

    // ââ Operator dashboard + graph_db stats persistence (H-STATS.944) ââ
    // Mirror of bch standup_pool_run (PR #1040 "stand up core::WebServer + graph_db
    // persist", commit 2b9fc26c; integrator 2026-08-03 "copy the shape"). main_btc
    // has no factored standup_pool_run, so the SAME core::WebServer standup lives
    // inline here, right after the stratum block, held at main scope so it and its
    // stats timer outlive the run-loop. ISOLATION: constructs existing core classes
    // only â ZERO src/core edits â so this stays OFF the four-coin smoke gate. node
    // == nullptr: BTC coin_node does not implement core::IMiningNode; the dashboard +
    // graph_db stat-log path does not require it (a live adapter is a follow-up
    // slice). Blockchain::BITCOIN selects the SHA256d graph_db constant pairing.
    std::unique_ptr<core::WebServer> web_server;
    std::shared_ptr<boost::asio::steady_timer> stats_timer;
    if (http_port != 0) {
        const bool web_is_testnet = testnet || testnet4 || regtest;
        // No-silent-ctor bracket (integrator req #2, per-lane port of bch #1050
        // "name the WebServer standup per-lane" / ltc #1041): name THIS lane's
        // dashboard standup on the way IN and OUT so a ctor that throws mid-standup
        // shows as an unmatched "standing up" with no "constructed" follow-up, and
        // guard a null MiningInterface before use. src/c2pool/main_btc.cpp only.
        LOG_INFO << "[BTC-POOL] standing up core::WebServer + MiningInterface (http bind "
                 << http_addr << ":" << http_port << ") ...";
        web_server = std::make_unique<core::WebServer>(
            ioc, http_addr, http_port, web_is_testnet,
            std::shared_ptr<core::IMiningNode>{},          // no IMiningNode adapter yet
            c2pool::address::Blockchain::BITCOIN);         // SHA256d graph_db pairing
        auto* mi = web_server->get_mining_interface();
        if (mi == nullptr) {
            LOG_ERROR << "[BTC-POOL] core::WebServer constructed but MiningInterface is"
                      << " NULL -- dashboard disabled, run-loop continues.";
            web_server.reset();
        }
        if (mi != nullptr) {
        LOG_INFO << "[BTC-POOL] core::WebServer + MiningInterface constructed (coin=BTC, "
                 << "http " << http_addr << ":" << http_port << "); MiningInterface alive.";
#ifdef C2POOL_VERSION
        mi->set_coin_label("BTC");
        mi->set_pool_version("c2pool/" C2POOL_VERSION);
#endif
        mi->set_io_context(&ioc);
        web_server->set_stratum_port(stratum_port);

        // PA/PB: surface the merged-mining manager on the dashboard /merged
        // endpoints (mirror main_ltc :6251). null absent --merged.
        if (mm_manager)
            web_server->set_merged_mining_manager(mm_manager.get());

        // Cross-coin dashboard parity: serve the shared refined web-static
        // dashboard over --http (btc.voidbind, same UI as LTC/DASH). This lane
        // passes a NULL IMiningNode, so refresh_work() never fills
        // m_cached_template and the readiness gate (http_session.cpp) would
        // redirect every .html to loading.html forever; mark the dashboard
        // always-ready (mirror main_dash.cpp) and point static serving at
        // web-static so "/" resolves. Display-only — no share/reward/consensus.
        mi->set_dashboard_always_ready(true);
        web_server->set_dashboard_dir("web-static");

        // D-BTC dashboard feeds (integrator 2026-08-03): mirror of D-BCH
        // (PR #1055) into the live MiningInterface the H-STATS.944 seam already
        // stood up with a NULL IMiningNode + zero feeds (so /api rendered empty).
        // BTC has no coin/embedded_daemon.hpp dashboard_topology() -- its embedded
        // transport is coin_node (BTC P2P) + an optional submitblock RPC fallback
        // -- so node_topology is synthesized inline from header_chain + coin_node,
        // and the sharechain feeds read the p2p_node NodeBridge accessors exactly
        // like the proven LTC feeders (main_ltc.cpp:2861/3378). Reuses the generic
        // core/web_server.hpp setters -- ZERO src/core edit. All captured objects
        // are declared above at main scope and outlive ioc.run(); all reads are
        // display-only (lock-free snapshots/atomics).
        mi->set_peer_info_fn([p2p_node_raw]() -> nlohmann::json {
            return p2p_node_raw->get_peer_info_json();
        });
        mi->set_pool_hashrate_fn([p2p_node_raw]() -> double {
            return p2p_node_raw->get_tracker_snapshot().pool_hashrate;
        });
        mi->set_sharechain_stats_fn([p2p_node_raw]() {
            auto s = p2p_node_raw->get_tracker_snapshot();
            return nlohmann::json{
                {"chain_count", s.chain_count},
                {"verified_count", s.verified_count},
                {"head_count", s.head_count},
                {"pool_hashrate", s.pool_hashrate},
            };
        });
        mi->set_node_topology_fn([&header_chain, &coin_node]() {
            const uint32_t synced   = header_chain.height();
            const uint32_t peer_tip = header_chain.peer_tip_height();
            const bool     emb_p2p  = coin_node.has_p2p();
            const bool     ext_rpc  = coin_node.has_rpc();
            return nlohmann::json{
                {"coin", "BTC"},
                {"embedded", true},
                {"has_rpc", ext_rpc},
                {"synced_height", synced},
                {"peer_tip_height", peer_tip},
                {"sync_pct", (peer_tip > 0 ? 100.0 * synced / peer_tip : 0.0)},
                {"embedded_peers", emb_p2p ? 1 : 0},
                {"broadcast_route", emb_p2p ? "p2p" : (ext_rpc ? "rpc" : "none")},
            };
        });

        // ── #995/#1155 BTC found-block record + chain-sourced confirm/orphan ─
        // Wire the won-block reporter slot (declared above, fired by
        // make_on_block_found AFTER both broadcast arms) to record_found_block +
        // schedule_block_verification, and install the verdict fn that resolves a
        // recorded block against the live chain. Mirrors the DASH/BCH call-site
        // shape (record sites + set_block_verify_fn) -- SHAPE reference only, no
        // cross-coin code copied. Isolation: constructs core classes / calls core
        // MI methods, ZERO src/core edits. Both halves TELEMETRY-ONLY and strictly
        // downstream of the block submit -- neither gates broadcast, mint, target
        // or payout.
        //
        // PRODUCER. The reconstructed parent block bytes carry the 80-byte header
        // first; the block IDENTITY hash is SHA256d(header) -- the same key the
        // embedded HeaderChain and bitcoind getblockheader answer on.
        *found_block_report =
            [mi, &header_chain](const uint256& /*share_hash*/,
                                const std::vector<unsigned char>& block_bytes,
                                const std::string& /*block_hex*/) {
                if (block_bytes.size() < 80) return;   // no header -> nothing to key on
                std::vector<unsigned char> hdr(block_bytes.begin(),
                                               block_bytes.begin() + 80);
                uint256 block_hash = Hash(hdr);        // SHA256d(80-byte header)
                // Height of the block we just won == the pool tip + 1.
                uint64_t height = static_cast<uint64_t>(header_chain.height()) + 1;
                mi->record_found_block(
                    height, block_hash, static_cast<uint64_t>(std::time(nullptr)),
                    /*chain=*/"BTC", /*miner=*/"", /*share_hash=*/block_hash.GetHex(),
                    mi->get_network_difficulty(), /*share_difficulty=*/0.0,
                    mi->get_local_hashrate(), /*subsidy=*/0);
                mi->schedule_block_verification(block_hash.GetHex());
                LOG_INFO << "[BTC] recorded found block hash="
                         << block_hash.GetHex().substr(0, 16)
                         << " -- confirm/orphan poller armed";
            };

        // VERDICT. Resolve a recorded found block against the chain: >0 accepted
        // (best-chain depth), <0 orphaned (off the active chain), 0 pending (not
        // yet buried, or the chain cannot answer). DAEMONLESS-FIRST off the
        // embedded HeaderChain (authoritative best branch -- BTC feeds it live,
        // unlike DGB), with the external bitcoind getblockheader confirmations as
        // the always-retained fallback when the header chain has not reached the
        // height. Mirrors the BCH set_block_verify_fn shape (per-coin isolated).
        mi->set_block_verify_fn(
            [mi, &header_chain, &coin_node](const std::string& hash_hex) -> int {
                uint256 h; h.SetHex(hash_hex);

                // found_height: authoritative from our own found-block record
                // (survives an orphan whose header peers never relayed to us);
                // else recovered from the embedded header chain.
                uint32_t found_height = 0;
                bool     have_height  = false;
                for (const auto& b : mi->get_found_blocks()) {
                    if (b.hash == hash_hex) {
                        found_height = static_cast<uint32_t>(b.height);
                        have_height  = true;
                        break;
                    }
                }
                if (!have_height) {
                    if (auto e = header_chain.get_header(h)) {
                        found_height = e->height;
                        have_height  = true;
                    }
                }

                if (have_height) {
                    auto winner_at = [&header_chain](uint32_t hh)
                        -> std::optional<uint256> {
                        if (auto e = header_chain.get_header_by_height(hh))
                            return e->block_hash;
                        return std::nullopt;
                    };
                    int v = btc::coin::block_confirm::resolve_status(
                        winner_at, header_chain.height(), h, found_height);
                    // Daemonless-first: trust a definite confirmed/orphaned
                    // verdict. A 0 (pending) with the header chain ALREADY past
                    // found_height is a genuine shallow-pending; only fall through
                    // to RPC when the header chain has not yet reached the height.
                    if (v != 0) return v;
                    if (header_chain.height() >= found_height) return 0;
                }

                // Fallback arm (header chain absent or behind): external bitcoind
                // getblockheader confirmations. c < 0 => off the best chain.
                int c = coin_node.rpc_block_confirmations(h);
                if (c != std::numeric_limits<int>::min()) {
                    if (c < 0) return -1;
                    if (c >= static_cast<int>(
                            btc::coin::block_confirm::kDefaultConfirmDepth))
                        return c;
                }
                return 0;  // still pending
            });
        LOG_INFO << "[BTC-POOL] found-block confirm/orphan lane ARMED "
                 << "(embedded HeaderChain verdict; bitcoind getblockheader fallback)";

        // graph_db stats persistence â survives restarts (LTC-parity site 2/3,
        // mirrors main_ltc.cpp:1967-1973). BTC-namespaced sub-dir keeps the per-coin
        // stat log isolated under the shared config path.
        {
            std::string net_label = web_is_testnet ? "testnet" : "mainnet";
            std::string graph_db_path = (core::filesystem::config_path()
                / net_label / "btc" / "graph_db").string();
            // #1040 gap (STATS.944 restart proof, 2026-08-03): the graph_db parent
            // dir (config_path()/<net>/btc/) was never created, so save_stat_log's
            // tmp-write + rename failed every 100s and NO stats survived restart.
            // Mirror the main_btc.cpp:358 / main_dgb.cpp:196 create_directories(net_dir)
            // best-effort pattern, targeting the actual stat-log parent.
            std::error_code graph_db_mkdir_ec;
            std::filesystem::create_directories(
                std::filesystem::path(graph_db_path).parent_path(), graph_db_mkdir_ec);
            mi->set_stat_log_path(graph_db_path);
            mi->load_stat_log();
            LOG_INFO << "[BTC-POOL] graph_db stats persistence -> " << graph_db_path;
        }

        if (web_server->start()) {
            // LTC-parity site 3/3: periodic save_stat_log every 100s (matches p2pool
            // graph_db + main_ltc.cpp:7429). Self-rescheduling steady_timer on the SAME
            // ioc the run-loop drives; captured by shared_ptr so it outlives each
            // async_wait continuation.
            stats_timer = std::make_shared<boost::asio::steady_timer>(ioc);
            auto save_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
            *save_fn = [stats_timer, save_fn, mi](boost::system::error_code ec) {
                if (ec) return;
                mi->save_stat_log();
                stats_timer->expires_after(std::chrono::seconds(100));
                stats_timer->async_wait(*save_fn);
            };
            stats_timer->expires_after(std::chrono::seconds(100));
            stats_timer->async_wait(*save_fn);
            LOG_INFO << "[BTC-POOL] dashboard live on http://" << http_addr << ":"
                     << http_port << " (graph_db persist every 100s).";
        } else {
            LOG_ERROR << "[BTC-POOL] WebServer FAILED to bind " << http_addr << ":"
                      << http_port << " â dashboard disabled, run-loop continues.";
            web_server.reset();
        }
        } // if (mi != nullptr)
    } else {
        LOG_INFO << "[BTC-POOL] dashboard disabled (no --http bind given).";
    }

    LOG_INFO << "[BTC] io_context running. Ctrl-C to stop.";

    // Diagnostic [IOC-LAT]: when a single run_for slice takes far longer
    // than its 100ms target, log it loud — boost::asio doesn't preempt
    // handlers so any handler blocking for N seconds shows up here. Same
    // signal as LTC's c2pool freeze-diag instrumentation
    // (c2pool_refactored.cpp:7065). The original blocking ioc.run() can't
    // emit per-slice diagnostics; switching to a 100ms-slice loop with
    // the signal-set handler still calling ioc.stop() preserves graceful
    // shutdown — once stop() is requested, run_for returns promptly and
    // g_shutdown_requested terminates the loop.
    while (!shutdown_initiated) {
        ioc.restart();
        auto loop_t0 = std::chrono::steady_clock::now();
        try {
            ioc.run_for(std::chrono::milliseconds(100));
        } catch (const std::exception& e) {
            LOG_ERROR << "ioc handler exception (non-fatal): " << e.what();
        }
        auto loop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - loop_t0).count();
        if (loop_ms > 2000) {
            LOG_WARNING << "[IOC-LAT] iteration took " << loop_ms
                        << "ms (target 100ms)";
        }
    }

    // LTC-parity site 3/3 (the TRUE third, missing until now): save the stat
    // log on clean shutdown. load-on-start (:1722) + periodic-100s (:1735) only
    // persist at tick boundaries, so without this every restart drops whatever
    // accumulated since the last 100s tick. Mirrors main_ltc.cpp:7456-7457
    // ("Save stats on shutdown"). web_server (and thus its MiningInterface) is
    // still alive here — the reset()s below run after. Display-only stat log;
    // p2pool-merged-v36 surface: NONE.
    if (web_server) {
        if (auto* mi = web_server->get_mining_interface())
            mi->save_stat_log();
    }

    // ── Graceful shutdown — explicit teardown order ──────────────────────
    //
    // ioc.run() returned because the signal handler called ioc.stop(). Now
    // we tear down in a controlled order BEFORE letting RAII at end-of-main
    // do the rest:
    //
    //   1. StratumServer is already stopped by the signal handler — sessions
    //      cancelled, acceptor closed. Reset the unique_ptr to invoke the
    //      destructor early so its sessions_ set is freed before anything
    //      else runs.
    //   2. work_source: drop our ref via the expose-shutdown variable. The
    //      coin_node subscribers still hold shared_ptrs to it, so it stays
    //      alive until coin_node's destructors clear those subscribers
    //      (which happens automatically at end-of-scope below). Important
    //      that work_source outlives any in-flight stratum-handler that
    //      might call into it.
    //   3. p2p_node (sharechain peer): explicit reset so its NodeP2P
    //      destructor closes peer connections before coin_node tears down
    //      its subordinate state.
    //   4. coin_node (bitcoind P2P) + ioc + the rest: regular RAII at end
    //      of scope.
    LOG_INFO << "[BTC] Shutting down...";
    // #995/#1155: unbind the found-block reporter before mi/web_server die.
    if (found_block_report) *found_block_report = nullptr;
    stratum_server_for_shutdown.reset();
    work_source_for_shutdown.reset();
    p2p_node.reset();
    LOG_INFO << "[BTC] Shutdown complete.";
    return 0;
}