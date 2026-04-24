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
#include <impl/dash/coin/rpc.hpp>
#include <impl/dash/coin/chain_seeds.hpp>
// Phase U step 1: UTXO adapter layer. Inclusion here is intentional —
// the adapter is a compile-time shape shim right now (no live
// UtxoViewCache instance constructed yet), so including it from
// main_dash.cpp guarantees the static_asserts + type aliases are
// exercised on every build of c2pool-dash, even before later Phase U
// steps start consuming the types at runtime.
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>
#include <impl/dash/coin/sml_db.hpp>
#include <impl/dash/coin/quorum_db.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/bls_verify.hpp>
#include <impl/dash/coin/chainlock_verify.hpp>

// Phase L static asserts: tie the upstream dashbls element sizes to
// the std::array byte counts in vendor/llmq_commitment.hpp. If these
// fire, upstream changed the wire format and we have to revisit
// CFinalCommitment's opaque pubkey/sig storage.
static_assert(bls::G1Element::SIZE == 48,
              "BLS G1 element (pubkey) size changed — update vendor");
static_assert(bls::G2Element::SIZE == 96,
              "BLS G2 element (signature) size changed — update vendor");
#include <core/coin/block_bootstrapper.hpp>
#include <impl/dash/broadcaster.hpp>
#include <impl/dash/broadcaster_full.hpp>
#include <impl/dash/enhanced_node.hpp>
#include <impl/dash/stratum.hpp>
#include <impl/dash/coinbase_builder.hpp>
#include <impl/dash/submit_validator.hpp>
#include <impl/dash/pplns.hpp>
#include <impl/dash/share_builder.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/messages.hpp>

#include <unordered_map>
#include <deque>
#include <mutex>
#include <set>

#include <core/coin_params.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <core/address_validator.hpp>

#include <boost/asio.hpp>

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <core/filesystem.hpp>
#include <string>
#include <thread>
#include <chrono>

namespace io = boost::asio;

// D3 (parity audit): latest miner-value (subsidy - masternode/superblock
// payments) published from the JOB cycle. Background PPLNS precomputer
// reads this so dashboard tooltip amounts match real network subsidy.
static std::atomic<uint64_t> g_latest_miner_value{0};

int main(int argc, char* argv[])
{
    std::string bootstrap = "rov.p2p-spb.xyz";
    uint16_t port = 8999;
    std::string dashd_host;
    uint16_t dashd_port = 9999;
    std::string dashd_rpc_host;
    uint16_t    dashd_rpc_port = 9998;
    std::string dashd_rpc_userpass;
    uint16_t    stratum_port   = 0;       // 0 = disabled; canonical Dash p2pool stratum port is 7903
    std::string mining_address;           // required when stratum+rpc are wired
    double      share_difficulty_default = 0.001;  // vardiff lands later
    double      donation_percentage = 1.0;  // p2pool-dash default (main.py:1110)
    bool        pplns_enabled   = true;   // default: PPLNS payouts across chain contributors
    size_t      pplns_window    = 0;      // 0 → use params.chain_length
    bool testnet = false;
    std::string http_host       = "127.0.0.1";   // dashboard bind host
    uint16_t    http_port       = 0;             // 0 = disable dashboard; e.g. 7904
    std::string dashboard_dir;                   // static files for web dashboard
    std::string http_cors_origin;
    bool        explorer_enabled = false;
    std::string explorer_url;                    // override for Explorer nav link
    // p2pool-dash/p2p.py:704 defaults desired_outgoing_conns=10. Matching
    // that here: 4 was below the bootstrap count (we have 4 bootstrap hosts)
    // so try_connect_more_peers never expanded past the initial connects.
    // With 10 the tick fills from addr_store until we reach 10 active peers.
    size_t      target_outbound_peers = 10;
    int         peer_ban_duration_sec = 300;     // C3 (parity audit): ban len
    std::string header_checkpoint_str;            // empty → use params.fast_start_checkpoint default
    // DashBroadcaster pool size — matches p2pool-dash DashNetworkBroadcaster
    // max_peers=20 (broadcaster.py:118). The primary dashd connection
    // counts as 1; the broadcaster pool fills the other 19.
    size_t      dashd_max_peers = 20;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--testnet") { testnet = true; port = 18999; dashd_port = 19999; dashd_rpc_port = 19998; }
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
        else if (arg == "--stratum-port" && i + 1 < argc) {
            stratum_port = static_cast<uint16_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--mining-address" && i + 1 < argc) {
            mining_address = argv[++i];
        }
        else if (arg == "--share-difficulty" && i + 1 < argc) {
            share_difficulty_default = std::stod(argv[++i]);
        }
        else if (arg == "--no-pplns") {
            pplns_enabled = false;          // pay 100% of miner reward to --mining-address
        }
        else if (arg == "--pplns-window" && i + 1 < argc) {
            pplns_window = static_cast<size_t>(std::stoul(argv[++i]));
        }
        else if ((arg == "--donation-percentage" || arg == "--donation")
                 && i + 1 < argc) {
            donation_percentage = std::stod(argv[++i]);
            if (donation_percentage < 0.0)   donation_percentage = 0.0;
            if (donation_percentage > 100.0) donation_percentage = 100.0;
        }
        else if (arg == "--http-port" && i + 1 < argc) {
            http_port = static_cast<uint16_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--http-host" && i + 1 < argc) {
            http_host = argv[++i];
        }
        else if (arg == "--dashboard-dir" && i + 1 < argc) {
            dashboard_dir = argv[++i];
        }
        else if (arg == "--cors-origin" && i + 1 < argc) {
            http_cors_origin = argv[++i];
        }
        else if (arg == "--explorer") {
            explorer_enabled = true;
        }
        else if (arg == "--explorer-url" && i + 1 < argc) {
            explorer_enabled = true;
            explorer_url = argv[++i];
        }
        else if (arg == "--target-peers" && i + 1 < argc) {
            target_outbound_peers = static_cast<size_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--ban-duration" && i + 1 < argc) {
            peer_ban_duration_sec = std::stoi(argv[++i]);
        }
        else if (arg == "--dash-header-checkpoint" && i + 1 < argc) {
            // Format: HEIGHT:HASH   e.g. 2450000:000000000000001b...
            // Empty string disables the hardcoded mainnet default
            // (starts from genesis).
            header_checkpoint_str = argv[++i];
        }
        else if (arg == "--dashd-max-peers" && i + 1 < argc) {
            dashd_max_peers = static_cast<size_t>(std::stoul(argv[++i]));
        }
        // --dashd-rpc host:port:user:pass  (or host:port if anon test)
        else if (arg == "--dashd-rpc" && i + 1 < argc) {
            std::string s = argv[++i];
            // Split by ':' into at most 4 parts: host, port, user, pass
            // (pass may itself contain ':' — everything after the third ':' is pass).
            auto a = s.find(':');
            if (a == std::string::npos) { dashd_rpc_host = s; continue; }
            dashd_rpc_host = s.substr(0, a);
            auto b = s.find(':', a + 1);
            if (b == std::string::npos) {
                dashd_rpc_port = static_cast<uint16_t>(std::stoul(s.substr(a + 1)));
            } else {
                dashd_rpc_port = static_cast<uint16_t>(std::stoul(s.substr(a + 1, b - (a + 1))));
                auto c = s.find(':', b + 1);
                if (c == std::string::npos) {
                    // host:port:userpass  (treat remainder as already-formatted user:pass,
                    // though typically this variant means just user with empty pass).
                    dashd_rpc_userpass = s.substr(b + 1);
                } else {
                    dashd_rpc_userpass = s.substr(b + 1, c - (b + 1)) + ":" + s.substr(c + 1);
                }
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

    // Phase L step 1: BLS verifier self-test. Generates a deterministic
    // keypair, signs + verifies (positive case), and verifies a bit-
    // flipped message fails (negative case). Catches: dashbls failed
    // to link, relic_conf.h built for wrong arch, relic init failure,
    // BasicSchemeMPL Verify silently broken. Hard-aborts on failure
    // because Phase L's clsig verification is consensus-critical —
    // running with a broken BLS verifier would silently accept
    // invalid ChainLocks.
    if (!dash::coin::bls_self_test_basic()) {
        std::cerr << "[BLS] self-test FAILED — aborting. Check that "
                     "dashbls linked correctly (libdashbls.a) and "
                     "relic_conf.h was generated for this arch."
                  << std::endl;
        return 1;
    }
    std::cout << "[BLS] self-test: BasicSchemeMPL sign+verify OK" << std::endl;

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

    // Add bootstrap(s). Start with user-supplied --bootstrap, then fold in the
    // coin_params defaults so the addr store is seeded with multiple live
    // Dash p2pool hosts. Without this the upstream bootstrap's relayed list
    // is almost entirely stale and peer expansion stays stuck at 1.
    config->pool()->m_bootstrap_addrs.emplace_back(bootstrap + ":" + std::to_string(port));
    {
        auto params = dash::make_coin_params(testnet);
        for (const auto& host : params.bootstrap_addrs) {
            std::string hp = host + ":" + std::to_string(port);
            NetService svc(hp);
            // Dedup against --bootstrap
            bool already = false;
            for (const auto& existing : config->pool()->m_bootstrap_addrs) {
                if (existing == svc) { already = true; break; }
            }
            if (!already) config->pool()->m_bootstrap_addrs.push_back(svc);
        }
    }
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

    // CLI override for the fast-start checkpoint. Format: HEIGHT:HASH.
    // Empty string / "off" / "genesis" disables the hardcoded default
    // and starts from the Dash genesis block.
    if (!header_checkpoint_str.empty()) {
        if (header_checkpoint_str == "off" || header_checkpoint_str == "genesis") {
            chain_params.fast_start_checkpoint.reset();
            std::cout << "[HEADERS] checkpoint disabled — starting from genesis"
                      << std::endl;
        } else {
            auto colon = header_checkpoint_str.find(':');
            if (colon != std::string::npos) {
                uint32_t cp_h = static_cast<uint32_t>(
                    std::stoul(header_checkpoint_str.substr(0, colon)));
                uint256 cp_hash;
                cp_hash.SetHex(header_checkpoint_str.substr(colon + 1));
                if (!cp_hash.IsNull()) {
                    chain_params.fast_start_checkpoint =
                        dash::coin::DashChainParams::Checkpoint{cp_h, cp_hash};
                    std::cout << "[HEADERS] CLI checkpoint override: height="
                              << cp_h << " hash="
                              << cp_hash.GetHex().substr(0, 16) << std::endl;
                } else {
                    std::cerr << "[HEADERS] invalid --dash-header-checkpoint hash"
                              << std::endl;
                    return 1;
                }
            }
        }
    } else if (chain_params.fast_start_checkpoint.has_value()) {
        std::cout << "[HEADERS] using default checkpoint: height="
                  << chain_params.fast_start_checkpoint->height
                  << " hash="
                  << chain_params.fast_start_checkpoint->hash.GetHex().substr(0, 16)
                  << " (override with --dash-header-checkpoint HEIGHT:HASH, "
                     "disable with --dash-header-checkpoint off)"
                  << std::endl;
    }

    std::string header_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
        + "/.c2pool/" + coin_name + "/embedded_headers";
    dash::coin::HeaderChain header_chain(chain_params, header_db_path);
    if (!header_chain.init()) {
        std::cerr << "[ERROR] Failed to initialize header chain LevelDB" << std::endl;
        return 1;
    }
    std::cout << "[HEADERS] Initialized: height=" << header_chain.height()
              << " headers=" << header_chain.size() << std::endl;

    // ── Phase U: UTXOViewCache + LevelDB persistence ─────────────────────
    // Step 2 wired an in-memory cache on full_block arrival; step 3
    // attaches LevelDB so the set survives restarts. Cache still hydrates
    // block-by-block from live full_block events — step 4 (bootstrap)
    // will fill the historical gap.
    //
    // Height tracking: the generic connect_block template wants an
    // explicit height per block. header_chain.height() is the authoritative
    // tip height once headers have synced, and full_block events arrive
    // AFTER the corresponding header (dashd sends headers-first per BIP
    // 130 and our own getdata is header-triggered), so height() at event
    // time equals the block's own height — no separate lookup needed.
    std::string utxo_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
        + "/.c2pool/" + coin_name + "/utxo_view_db";
    dash::coin::UtxoViewDB utxo_db(utxo_db_path);
    if (!utxo_db.open()) {
        std::cerr << "[WARN] Failed to open UTXO LevelDB at " << utxo_db_path
                  << " — running with in-memory UTXO cache only" << std::endl;
    }
    dash::coin::UtxoViewCache utxo_cache(
        utxo_db.is_open() ? &utxo_db : nullptr);
    std::cout << "[UTXO] initialized: db=" << (utxo_db.is_open() ? "open" : "memory-only")
              << " path=" << utxo_db_path
              << " best_height=" << utxo_cache.get_best_height()
              << std::endl;

    // ── Phase C-SML steps 5+6: SMLDb + in-memory CSimplifiedMNList ──
    // The persistent SML lives in `~/.c2pool/<coin>/sml_db/`. On startup
    // we load it into memory; on every accepted mnlistdiff (step 6) we
    // apply_diff + write_sml + verify CBTX root (step 7). Last-known
    // best_hash is used as the next getmnlistd's baseBlockHash; null
    // (cold start) means we ask from `uint256::ZERO` per dashcore's
    // protocol convention.
    std::string sml_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
        + "/.c2pool/" + coin_name + "/sml_db";
    auto sml_db = std::make_shared<dash::coin::SMLDb>(sml_db_path);
    if (!sml_db->open()) {
        std::cerr << "[WARN] Failed to open SML LevelDB at " << sml_db_path
                  << " — SML sync will run cold-start every restart"
                  << std::endl;
    }
    auto sml = std::make_shared<dash::coin::vendor::CSimplifiedMNList>();
    sml_db->load_sml(*sml);
    // Tracks the most recently seen CBTX merkleRootMNList from the
    // full_block path (Phase C-SML step 1's parser populates this).
    // Step 7 compares our SML's merkle root against this on every diff
    // application; mismatch → log-only at MVP.
    auto last_cbtx_mnlist_root = std::make_shared<uint256>();
    auto last_cbtx_block_height = std::make_shared<uint32_t>(0);
    std::cout << "[SML] initialized: entries=" << sml->size()
              << " best_height=" << sml_db->get_best_height()
              << " best_hash=" << sml_db->get_best_hash().GetHex().substr(0, 16)
              << std::endl;

    // ── Phase C-QUO step 3 + persistence: LLMQ quorum tracker + QuorumDb ──
    // QuorumDb persists the active quorum set so a restart between two
    // mnlistdiffs doesn't leave QuorumManager empty. Without it,
    // ChainLock verify returns NO_POOL after every restart in steady
    // state (incremental diffs don't refill the active set; a full
    // cold-start would require base=ZERO, which we only ask for when
    // SMLDb is empty).
    //
    // Consistency: QuorumDb's BEST sentinel must match SMLDb's. If
    // they diverge (crash mid-flush, manual db edit, schema upgrade)
    // we wipe BOTH and force cold-start. Cheap (~400 KB once) and
    // simpler than partial-write recovery.
    std::string quorum_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
        + "/.c2pool/" + coin_name + "/quorum_db";
    auto quorum_db = std::make_shared<dash::coin::QuorumDb>(quorum_db_path);
    if (!quorum_db->open()) {
        std::cerr << "[WARN] Failed to open Quorum LevelDB at " << quorum_db_path
                  << " — quorum tracker will run cold-start every restart"
                  << std::endl;
    }
    auto quorums = std::make_shared<dash::coin::QuorumManager>();
    if (quorum_db->is_open()) {
        // Cross-check the two BEST sentinels. If they don't agree, the
        // stored quorum state is stale relative to the SML; wipe both
        // for a clean cold-start.
        if (sml_db->is_open()
            && quorum_db->get_best_hash() != sml_db->get_best_hash()) {
            LOG_WARNING << "[QUO-DB] best_hash divergence vs SMLDb "
                        << "(quo=" << quorum_db->get_best_hash().GetHex().substr(0, 16)
                        << " sml=" << sml_db->get_best_hash().GetHex().substr(0, 16)
                        << ") — wiping both for cold-start";
            quorum_db->clear();
            sml_db->clear();
            sml->mnList.clear();
        } else {
            quorum_db->load_into(*quorums);
        }
    }
    std::cout << "[QUO] initialized: active=" << quorums->active_count()
              << " best_height=" << quorum_db->get_best_height()
              << " best_hash=" << quorum_db->get_best_hash().GetHex().substr(0, 16)
              << std::endl;

    // ── Phase L step 4: shared ChainLock-blocks set ──
    // Updated by the on_clsig callback (relay-trust at MVP) and read
    // by the tip-changed reorg handler to refuse reorgs that would
    // disconnect a CL'd block. Iteration 2 hardening will gate writes
    // on verify-success only.
    auto chainlocked_blocks =
        std::make_shared<std::map<uint256, int32_t>>();

    // ── Pool Node ──
    dash::DashNodeImpl node(&ioc, config.get(), testnet);
    std::cout << "[NODE] DashNodeImpl created" << std::endl;

    // ── Enhanced Node (vardiff, hashrate tracking, mining interface) ──
    // Template-instantiated for Dash via impl/dash/enhanced_node.hpp.
    // Storage is null (like LTC path); chain persistence belongs to DashNodeImpl.
    auto enhanced_node = std::make_shared<dash::EnhancedNode>(testnet);
    // IMiningNode overrides sourced from DashNodeImpl so /api/mining/stats
    // shows real peer + share counts (the base template's defaults read
    // m_chain/m_connections which are null in the default constructor).
    enhanced_node->set_total_shares_fn(
        [&node]() -> uint64_t { return node.tracker().chain.size(); });
    enhanced_node->set_connected_peers_fn(
        [&node]() -> size_t { return node.peer_count(); });
    std::cout << "[ENHANCED] dash::EnhancedNode created (vardiff + hashrate)" << std::endl;

    // ── Web dashboard (optional; enabled when --http-port > 0) ──────────
    // Coin-agnostic path: constructor takes IMiningNode (our EnhancedNode)
    // and Blockchain::DASH. We do NOT call set_coin_rpc() — that signature
    // is hardcoded to ltc::coin::NodeRPC* and would require ICoinRPC
    // extraction. Our GBT/submitblock path stays in the existing stratum
    // handler. The dashboard serves mining stats via IMiningNode only.
    // set_stratum_port(0) prevents WebServer from launching its own
    // StratumServer (we run dash::stratum::Server ourselves).
    std::unique_ptr<core::WebServer> web_server;
    if (http_port != 0) {
        web_server = std::make_unique<core::WebServer>(
            ioc, http_host, http_port, testnet,
            std::static_pointer_cast<core::IMiningNode>(enhanced_node),
            Blockchain::DASH);
        web_server->set_stratum_port(0);  // we own stratum; don't auto-launch
        auto* mi = web_server->get_mining_interface();
        if (!http_cors_origin.empty()) mi->set_cors_origin(http_cors_origin);
        if (stratum_port != 0)         mi->set_worker_port(stratum_port);
        if (!dashboard_dir.empty())    web_server->set_dashboard_dir(dashboard_dir);
        if (explorer_enabled) {
            web_server->set_explorer_enabled(true);
            if (!explorer_url.empty())
                web_server->set_explorer_url(explorer_url);
        }
#ifdef C2POOL_VERSION
        mi->set_pool_version("c2pool-dash/" C2POOL_VERSION);
#endif
        // Dash drives its own work pipeline (GBT via coin_rpc, stratum via
        // dash::stratum::Server) — bypass WebServer's internal has_work /
        // is_node_ready gate so the loading page doesn't stall / force
        // everyone into a redirect loop to loading.html.
        mi->set_dashboard_always_ready(true);
        // Sharechain stats for the dashboard (chain height + verified count).
        // HTTP-thread callback — D1/D2 (parity audit): reads from the
        // atomically-published TrackerSnapshot so we don't contend with
        // share-arrival writers on the main tracker mutex. The snapshot
        // is refreshed after every tracker mutation (process_shares,
        // sharereply, add_local_share, prune, LevelDB load). Matches
        // LTC's TrackerSnapshot path (c2pool_refactored.cpp:3206).
        mi->set_sharechain_stats_fn([&node]() {
            auto snap = node.get_tracker_snapshot();
            nlohmann::json j;
            j["chain_height"]   = snap.chain_count;
            j["verified_count"] = snap.verified_count;
            j["total_shares"]   = snap.chain_count;
            j["fork_count"]     = snap.fork_count;
            // §5.5 — head_count is the number of disconnected chain heads
            // currently tracked. Cheap O(heads) under shared_lock.
            {
                std::shared_lock lock(node.tracker_mutex());
                j["head_count"] = static_cast<int>(
                    node.tracker().chain.get_heads().size());
            }
            return j;
        });
        // Best share hash for the dashboard's head indicator.
        mi->set_best_share_hash_fn([&node]() { return node.best_share_hash(); });

        // On every new share ingest: invalidate the window cache, refresh
        // the per-tip PPLNS snapshot, precompute the window-delta for the
        // incoming since= parameter, and push an SSE event to RealTime
        // dashboard clients. Mirrors LTC's trigger_work_refresh_debounced
        // (web_server.cpp:7596-7625) on every share arrival — without this
        // the /sharechain/stream endpoint stays idle and the explorer
        // doesn't auto-refresh per-share PPLNS.
        {
            std::string prev_hash_buf;  // captured by lambda (main-thread only)
            node.m_on_new_share = [mi_ptr = web_server->get_mining_interface(),
                                   prev_hash_buf = std::string()]
                                  (const uint256& new_tip) mutable {
                mi_ptr->invalidate_window_cache();
                mi_ptr->cache_pplns_at_tip();
                mi_ptr->precompute_delta(prev_hash_buf);
                prev_hash_buf = new_tip.GetHex();
                if (mi_ptr->sse_subscriber_count() > 0) {
                    auto tip = mi_ptr->rest_sharechain_tip();
                    mi_ptr->sse_push(tip.dump());
                }
            };
        }
        // Peer list for /peer_list and /local_stats — real address + version.
        mi->set_peer_info_fn([&node]() -> nlohmann::json {
            return node.peer_info_json();
        });
        // Pool hashrate from sharechain attempts-per-second (p2pool formula).
        mi->set_pool_hashrate_fn([&node]() -> double {
            return node.pool_hashrate();
        });
        // Sharechain window for /sharechain/window (Transparency Explorer).
        // Walk up to CHAIN_LENGTH shares from the best head and serialize
        // each with the fields the dashboard JS expects (h, H, p, v, t, b,
        // a, dv, m).
        mi->set_sharechain_window_fn([&node, &params, testnet, mi_ptr = web_server->get_mining_interface()]() -> nlohmann::json {
            // HTTP-thread callback. Hold shared_lock across the whole chain
            // walk so writers on the main ioc thread block until we're done
            // iterating. The walk is bounded by chain_length (4320) and
            // returns 500 KB JSON — a few ms under lock is acceptable.
            std::shared_lock lock(node.tracker_mutex());
            nlohmann::json result;
            auto& chain = node.tracker().chain;
            auto& verified = node.tracker().verified;

            uint256 best = node.best_share_hash_nolock();  // shared best-head picker
            int32_t best_height = best.IsNull() ? 0 : chain.get_height(best);
            result["best_hash"]    = best.IsNull() ? "" : best.GetHex();
            result["chain_length"] = static_cast<int>(chain.size());
            result["window_size"]  = static_cast<int>(params.chain_length);
            result["my_address"]   = "";
            result["fee_hash160"]  = "";

            nlohmann::json shares_arr = nlohmann::json::array();
            const uint8_t p2pkh_ver = testnet ? 140 : 76;
            const uint8_t p2sh_ver  = testnet ?  19 : 16;
            if (!best.IsNull()) {
                int height = chain.get_height(best);
                int walk = std::min(height, static_cast<int>(params.chain_length));
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
                            data.share.invoke([&](auto* obj) {
                                using S = std::remove_pointer_t<decltype(obj)>;
                                if constexpr (std::is_same_v<S, dash::DashShare>) {
                                    s["t"]  = obj->m_timestamp;
                                    s["V"]  = S::version;       // 16 for Dash v16
                                    s["s"]  = static_cast<int>(obj->m_stale_info);
                                    s["b"]  = obj->m_bits;
                                    s["a"]  = obj->m_absheight;
                                    s["dv"] = obj->m_desired_version;
                                    auto script = dash::pubkey_hash_to_script2(obj->m_pubkey_hash);
                                    std::string addr = core::script_to_address(
                                        script, "" /*no bech32*/, p2pkh_ver, p2sh_ver);
                                    s["m"] = addr.empty() ? HexStr(script) : addr;
                                }
                            });
                            shares_arr.push_back(std::move(s));
                        }
                    } catch (...) {}
                }
            }
            result["shares"] = shares_arr;
            result["total"]  = static_cast<int>(shares_arr.size());

            // §5.1 — heads / blocks / doge_blocks overlays.
            // heads = short hashes of all tracked chain heads (for
            // the "Verified Heads" row + head-ring marker).
            // blocks = short hashes of shares that solved a DASH block
            // on the parent chain (gold border overlay).
            // doge_blocks = always empty on Dash (no merged mining);
            // present to match the coin-agnostic contract.
            nlohmann::json heads_arr = nlohmann::json::array();
            for (auto& [hh, _] : chain.get_heads())
                heads_arr.push_back(hh.GetHex().substr(0, 16));
            result["heads"]       = std::move(heads_arr);
            result["blocks"]      = nlohmann::json::array();  // TODO: populate from found_blocks_db
            result["doge_blocks"] = nlohmann::json::array();  // N/A for Dash

            // Per-share PPLNS zoom tooltip on the Sharechain Explorer reads
            // pplns_current (fallback for all shares) and pplns (per-share
            // map). Without pplns_current the zoom panel hides.
            if (mi_ptr) {
                result["pplns_current"] = mi_ptr->rest_current_payouts();
                // Per-share map — EXACT match only. get_pplns_for_tip() returns
                // a fallback entry on miss, which would flood the map with the
                // same payouts for every share. The hover-zoom JS falls back
                // to pplns_current on its own for uncached shares.
                nlohmann::json pplns_map = nlohmann::json::object();
                for (const auto& s : result["shares"]) {
                    std::string sh = s["h"].get<std::string>();
                    auto p = mi_ptr->get_pplns_for_tip_exact(sh);
                    if (!p.empty()) pplns_map[sh] = std::move(p);
                }
                if (!pplns_map.empty()) result["pplns"] = std::move(pplns_map);
            }
            return result;
        });
        // Sharechain tip for readiness checks.
        mi->set_sharechain_tip_fn([&node]() -> nlohmann::json {
            // HTTP-thread callback. All sharechain endpoints (tip, window,
            // delta) agree on best-head selection by delegating to
            // best_share_hash_nolock() — highest cumulative abswork, not
            // arbitrary map order. When two forks exist the head with
            // more work is "best"; without this the client's _rtTipHash
            // could track a stale head while new shares grew a different
            // fork and SSE pushes never reached the client.
            std::shared_lock lock(node.tracker_mutex());
            auto& chain = node.tracker().chain;
            uint256 best = node.best_share_hash_nolock();
            int32_t height = best.IsNull() ? 0 : chain.get_height(best);
            nlohmann::json t;
            t["hash"]   = best.IsNull() ? "" : best.GetHex().substr(0, 16);
            t["height"] = height;
            t["total"]  = static_cast<int>(chain.size());  // §5.2 informational
            return t;
        });
        // Sharechain delta endpoint — returns shares newer than `since`
        // so the dashboard's RealTime mode can incrementally prepend
        // shares on SSE tip notifications without refetching the full
        // 4320-share window. Without this the client receives the SSE
        // event but the delta fetch returns an empty array, so nothing
        // animates. Ports LTC's set_sharechain_delta_fn wiring
        // (c2pool_refactored.cpp:3613-3738) adapted to DashShare.
        mi->set_sharechain_delta_fn(
            [&node, &params, testnet,
             p2pkh_ver = (testnet ? 140 : 76),
             p2sh_ver  = (testnet ? 19 : 16),
             mi_ptr = web_server->get_mining_interface()]
            (const std::string& since_hash) -> nlohmann::json {
                std::shared_lock lock(node.tracker_mutex());
                auto& chain = node.tracker().chain;
                auto& verified = node.tracker().verified;

                uint256 best = node.best_share_hash_nolock();  // shared picker

                nlohmann::json shares_arr = nlohmann::json::array();
                int count = 0;
                if (!best.IsNull()) {
                    int walk = std::min(static_cast<int>(chain.get_height(best)),
                                        static_cast<int>(params.chain_length));
                    try {
                        auto view = chain.get_chain(best, walk);
                        for (auto [hash, data] : view) {
                            std::string short_h = hash.GetHex().substr(0, 16);
                            if (short_h == since_hash || hash.GetHex() == since_hash)
                                break;
                            nlohmann::json s;
                            s["h"] = short_h;
                            s["H"] = hash.GetHex();
                            s["p"] = count;
                            s["v"] = verified.contains(hash) ? 1 : 0;
                            data.share.invoke([&](auto* obj) {
                                using S = std::remove_pointer_t<decltype(obj)>;
                                if constexpr (std::is_same_v<S, dash::DashShare>) {
                                    s["t"]  = obj->m_timestamp;
                                    s["V"]  = S::version;
                                    s["s"]  = static_cast<int>(obj->m_stale_info);
                                    s["b"]  = obj->m_bits;
                                    s["a"]  = obj->m_absheight;
                                    s["dv"] = obj->m_desired_version;
                                    auto script = dash::pubkey_hash_to_script2(obj->m_pubkey_hash);
                                    std::string addr = core::script_to_address(
                                        script, "" /*no bech32*/, p2pkh_ver, p2sh_ver);
                                    s["m"] = addr.empty() ? HexStr(script) : addr;
                                }
                            });
                            shares_arr.push_back(std::move(s));
                            if (++count >= 200) break;  // safety cap
                        }
                    } catch (...) {}
                }

                nlohmann::json heads_arr = nlohmann::json::array();
                for (auto& [hh, _] : chain.get_heads())
                    heads_arr.push_back(hh.GetHex().substr(0, 16));

                nlohmann::json result;
                result["shares"] = std::move(shares_arr);
                result["count"]  = count;
                result["tip"]    = best.IsNull() ? "" : best.GetHex().substr(0, 16);
                result["heads"]       = std::move(heads_arr);
                result["blocks"]      = nlohmann::json::array();  // no parent-chain block solutions
                result["doge_blocks"] = nlohmann::json::array();  // §5.3 — N/A for Dash
                // Include chain_length so the dashboard's 'Chain Length'
                // stat stays populated on SSE deltas (it would blank out
                // to '-' otherwise since _rtFetchDelta calls updateStats
                // with only the delta fields).
                result["chain_length"] = static_cast<int>(chain.size());
                result["window_size"]  = static_cast<int>(params.chain_length);

                // Per-share PPLNS for the zoom-tooltip panel on the new shares.
                if (count > 0 && mi_ptr) {
                    nlohmann::json pplns_map = nlohmann::json::object();
                    for (const auto& sj : result["shares"]) {
                        std::string sh = sj["h"].get<std::string>();
                        auto p = mi_ptr->get_pplns_for_tip_exact(sh);
                        if (!p.empty()) pplns_map[sh] = std::move(p);
                    }
                    if (!pplns_map.empty())
                        result["pplns"] = std::move(pplns_map);
                }
                return result;
            });

        // Individual share lookup for /web/share/<hash> (share.html).
        // Returns the full share-detail JSON the dashboard's share page
        // expects (share_data, block header+gentx, local metadata).
        // Without this wiring /web/share returns "share not found" so
        // clicking any share on the Explorer grid shows a blank page.
        mi->set_share_lookup_fn(
            [&node, testnet, p2pkh_ver = (testnet ? 140 : 76),
             p2sh_ver = (testnet ? 19 : 16)]
            (const std::string& hash_hex) -> nlohmann::json {
                uint256 hash;
                hash.SetHex(hash_hex);
                if (hash.IsNull())
                    return nlohmann::json{{"error", "share not found"}};

                std::shared_lock lock(node.tracker_mutex());
                auto& chain = node.tracker().chain;
                auto& verified = node.tracker().verified;
                if (!chain.contains(hash))
                    return nlohmann::json{{"error", "share not found"}};

                nlohmann::json result;
                auto& entry = chain.get(hash);
                auto* idx = chain.get_index(hash);
                // Dash doesn't tag shares as block-solutions in the chain
                // index the way LTC does; block-found is driven separately
                // through the found_blocks store. Leave the client's
                // is_block_solution flag false here.
                result["is_block_solution"] = false;
                result["is_doge_block"] = false;  // Dash doesn't merge-mine

                entry.share.invoke([&](auto* obj) {
                    using S = std::remove_pointer_t<decltype(obj)>;
                    if constexpr (!std::is_same_v<S, dash::DashShare>) return;
                    result["parent"] = obj->m_prev_hash.GetHex();
                    result["far_parent"] = obj->m_far_share_hash.GetHex();
                    result["type_name"] = "V" + std::to_string(S::version);
                    result["version"] = S::version;

                    nlohmann::json local_j;
                    local_j["verified"] = verified.contains(hash);
                    local_j["time_first_seen"] = idx ? idx->time_seen : 0;
                    local_j["peer_first_received_from"] = obj->peer_addr.to_string();
                    result["local"] = local_j;

                    auto script = dash::pubkey_hash_to_script2(obj->m_pubkey_hash);
                    std::string addr = core::script_to_address(
                        script, "" /*no bech32*/, p2pkh_ver, p2sh_ver);

                    double target_diff = chain::target_to_difficulty(
                        chain::bits_to_target(obj->m_bits));
                    double max_target_diff = chain::target_to_difficulty(
                        chain::bits_to_target(obj->m_max_bits));

                    nlohmann::json sd;
                    sd["timestamp"]       = obj->m_timestamp;
                    sd["target"]          = obj->m_bits;
                    sd["max_target"]      = obj->m_max_bits;
                    sd["payout_address"]  = addr.empty() ? HexStr(script) : addr;
                    sd["donation"]        = static_cast<double>(obj->m_donation) / 65536.0;
                    sd["stale_info"]      = static_cast<int>(obj->m_stale_info);
                    sd["nonce"]           = obj->m_nonce;
                    sd["desired_version"] = obj->m_desired_version;
                    sd["absheight"]       = obj->m_absheight;
                    sd["abswork"]         = obj->m_abswork.GetHex();
                    sd["difficulty"]      = target_diff;
                    sd["min_difficulty"]  = max_target_diff;
                    sd["subsidy"]         = static_cast<double>(obj->m_subsidy) / 1e8;
                    sd["payment_amount"]  = static_cast<double>(obj->m_payment_amount) / 1e8;
                    result["share_data"] = sd;

                    auto& hdr = obj->m_min_header;
                    nlohmann::json hdr_j;
                    hdr_j["version"]        = hdr.m_version;
                    hdr_j["previous_block"] = hdr.m_previous_block.GetHex();
                    hdr_j["merkle_root"]    = "";
                    hdr_j["timestamp"]      = hdr.m_timestamp;
                    hdr_j["target"]         = hdr.m_bits;
                    hdr_j["nonce"]          = hdr.m_nonce;

                    nlohmann::json gentx_j;
                    gentx_j["hash"]             = "";
                    gentx_j["coinbase"]         = HexStr(obj->m_coinbase.m_data);
                    gentx_j["value"]            = static_cast<double>(obj->m_subsidy) / 1e8;
                    gentx_j["last_txout_nonce"] = obj->m_last_txout_nonce;

                    nlohmann::json block_j;
                    block_j["hash"]                     = hash.GetHex();
                    block_j["header"]                   = hdr_j;
                    block_j["gentx"]                    = gentx_j;
                    block_j["other_transaction_hashes"] = nlohmann::json::array();
                    result["block"] = block_j;

                    result["children"] = nlohmann::json::array();
                });
                return result;
            });

        // Dash p2pool uses protocol 1700 (not LTC's 3600).
        mi->set_protocol_version(1700);
        // Canonical Dash p2pool ports for node_info (dashboard miner URL).
        mi->set_p2p_port(port);
        if (stratum_port == 0) mi->set_worker_port(7903);


        // C2 (parity audit): operator stats history for dashboard graphs.
        // WebServer already runs update_stat_log every 60s on its own
        // timer; we just need to tell MiningInterface where to persist
        // samples and load any existing history. Timer below writes to
        // disk every 100s matching LTC / p2pool graph_db cadence.
        {
            std::string net_label = testnet ? "dash_testnet" : "dash";
            std::filesystem::path graph_db = core::filesystem::config_path()
                                           / net_label / "graph_db";
            mi->set_stat_log_path(graph_db.string());
            try { mi->load_stat_log(); }
            catch (const std::exception& e) {
                LOG_WARNING << "[Dash] load_stat_log: " << e.what();
            }
        }

        web_server->start();
        std::cout << "[WEB] dashboard listening on " << http_host << ":"
                  << http_port << std::endl;

        // C2: persistent save timer (every 100s). Graph_db rolls a 31-day
        // window via update_stat_log eviction so the file stays bounded.
        //
        // Wrapping the self-rescheduling std::function in shared_ptr avoids
        // the dangling-capture corner case where `[&stats_fn]` holds a
        // pointer to a stack local whose value the std::function_handler
        // chain can see as moved-from once asio has copied it into the
        // operation queue. Using a heap-owned std::function and capturing
        // the shared_ptr by value gives the lambda a stable, live handle
        // to itself across every async_wait iteration. Same pattern used
        // by c2pool-ltc's long-lived self-rescheduling timers.
        auto stat_save_timer = std::make_shared<io::steady_timer>(ioc);
        auto stat_save_fn = std::make_shared<
            std::function<void(const boost::system::error_code&)>>();
        *stat_save_fn = [mi, stat_save_timer, stat_save_fn]
                        (const boost::system::error_code& ec) {
            if (ec) return;
            try { mi->save_stat_log(); }
            catch (const std::exception& e) {
                LOG_WARNING << "[Dash] save_stat_log: " << e.what();
            }
            stat_save_timer->expires_after(std::chrono::seconds(100));
            stat_save_timer->async_wait(*stat_save_fn);
        };
        stat_save_timer->expires_after(std::chrono::seconds(100));
        stat_save_timer->async_wait(*stat_save_fn);

        // Background per-share PPLNS precomputer for the Sharechain Explorer.
        // Mirrors LTC's start_pplns_precompute(): walk the window, compute
        // PPLNS from each share's perspective, store under the share's short
        // hash so the hover-zoom treemap shows the distribution as it was at
        // that share's tip — not the current tip for every share.
        std::thread([&node, &params, testnet, mi]() {
            const uint8_t p2pkh_ver = testnet ? 140 : 76;
            const uint8_t p2sh_ver  = testnet ?  19 : 16;
            std::vector<unsigned char> dummy = {0x76,0xa9,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x88,0xac};
            auto& chain = node.tracker().chain;
            // D3 (parity audit): use the real miner-value from the latest
            // GBT so tooltip amounts reflect actual Dash subsidy (~1.77 DASH
            // post-halving) rather than a fixed 1e8 stand-in. Percentages
            // don't change either way — but absolute amounts become truthful.
            // g_latest_miner_value is published from the JOB cycle below.
            auto current_subsidy = [&]() -> uint64_t {
                uint64_t v = g_latest_miner_value.load();
                return v > 0 ? v : 100'000'000ULL;
            };

            // Single PPLNS computation. Must be called with a shared_lock on
            // node.tracker_mutex() already held by the caller — compute_payouts
            // walks the chain internally and we cannot let writers modify
            // m_shares mid-walk. The store_pplns_for_tip call itself uses its
            // own mutex (m_pplns_cache_mutex) and does not need the tracker
            // lock, so callers may release before storing if they want to
            // shorten the critical section.
            auto compute_one_locked = [&](const uint256& h) -> std::optional<nlohmann::json> {
                try {
                    auto r = dash::pplns::compute_payouts(
                        chain, h, params.chain_length, current_subsidy(), dummy);
                    if (r.used_fallback || r.payouts.empty()) return std::nullopt;
                    nlohmann::json pplns_json = nlohmann::json::object();
                    for (const auto& p : r.payouts) {
                        std::string addr = core::script_to_address(
                            p.script, "" /*no bech32*/, p2pkh_ver, p2sh_ver);
                        if (addr.empty()) addr = HexStr(p.script);
                        pplns_json[addr] = p.amount / 1e8;
                    }
                    return pplns_json;
                } catch (...) { return std::nullopt; }
            };

            // Wait for the chain to reach full depth before the first pass.
            // chain.size() is a read — protect with shared_lock each check.
            for (int i = 0; i < 300; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                size_t sz;
                {
                    std::shared_lock lock(node.tracker_mutex());
                    sz = node.tracker().chain.size();
                }
                if (sz >= static_cast<size_t>(params.chain_length)) break;
            }

            {
                std::shared_lock lock(node.tracker_mutex());
                LOG_INFO << "[PPLNS-Precompute] starting (chain.size="
                         << node.tracker().chain.size() << ")";
            }

            // Main loop. Two-phase per pass:
            //   Phase 1 — snapshot the window's share hashes under a brief
            //             shared_lock, release. Hashes are value types, safe
            //             to iterate unlocked.
            //   Phase 2 — for each uncached hash, take the shared_lock and
            //             run compute_payouts while holding it. Release
            //             between shares so writers get windows to run.
            // This gives us predictable 2-8ms lock durations per share
            // instead of one 8-9 second monolithic read lock.
            while (true) {
                std::vector<uint256> hashes;
                {
                    std::shared_lock lock(node.tracker_mutex());
                    auto heads = chain.get_heads();
                    if (heads.empty()) goto sleep_and_retry;
                    uint256 best = heads.begin()->first;
                    if (best.IsNull()) goto sleep_and_retry;
                    int32_t height = chain.get_height(best);
                    int32_t walk = std::min(height, static_cast<int32_t>(params.chain_length));
                    hashes.reserve(walk);
                    try {
                        for (auto&& [h, data] : chain.get_chain(best, walk))
                            hashes.push_back(h);
                    } catch (...) { goto sleep_and_retry; }
                }

                {
                    int scanned = 0, computed = 0;
                    for (const auto& h : hashes) {
                        ++scanned;
                        std::string sh = h.GetHex().substr(0, 16);
                        if (!mi->get_pplns_for_tip_exact(sh).empty()) continue;

                        std::optional<nlohmann::json> result;
                        {
                            std::shared_lock lock(node.tracker_mutex());
                            // Share might have been pruned between phase 1
                            // and here. Skip if it's no longer in the chain.
                            if (!chain.contains(h)) continue;
                            result = compute_one_locked(h);
                        }
                        if (result) {
                            mi->store_pplns_for_tip(sh, std::move(*result));
                            ++computed;
                        }
                        // Yield between shares so writers can progress.
                        std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    }
                    if (computed > 0) {
                        LOG_INFO << "[PPLNS-Precompute] pass: scanned=" << scanned
                                 << " new_cached=" << computed;
                    }
                }

            sleep_and_retry:
                std::this_thread::sleep_for(std::chrono::seconds(20));
            }
        }).detach();
    }

    // ── Coin P2P Node (dashd connection) ──
    std::unique_ptr<dash::coin::Node<dash::Config>> coin_node;
    // Phase 2 port of c2pool-ltc CoinBroadcaster: multi-peer pool with
    // Wilson-score reputation, exponential backoff, anchor persistence,
    // group limits, and addr-crawl peer discovery (all via CoinPeerManager,
    // which is chain-agnostic). Declared in main() scope so the web_server
    // peer_info_fn lambda + submit handler both see the same unique_ptr.
    std::unique_ptr<dash::DashCoinBroadcaster> broadcaster;
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

        // Lightweight arrival log on the primary dashd connection. UTXO
        // bookkeeping moves to the broadcaster callback below so every
        // peer's full blocks feed the same pipeline and we don't
        // double-connect the LAN dashd's block (it appears both as the
        // primary coin_node AND as a broadcaster peer slot).
        coin_node->full_block.subscribe([&](dash::coin::BlockType block) {
            auto hdr = static_cast<dash::coin::BlockHeaderType>(block);
            auto bhash = dash::coin::x11_hash(hdr);
            LOG_INFO << "[DASH] Full block: " << bhash.GetHex().substr(0, 16)
                     << " txs=" << block.m_txs.size();
        });

        // SPV C1 (parity audit): expose dashd header-sync progress to the
        // dashboard so the parent-chain panel shows height/target instead
        // of "Height: -". Coin-agnostic — the dashboard already reads
        // data.spv keys when present.
        if (web_server) {
            auto* mi3 = web_server->get_mining_interface();
            mi3->set_spv_progress_fn([&header_chain, &coin_node]() -> nlohmann::json {
                nlohmann::json r;
                r["dash_height"] = static_cast<int>(header_chain.height());
                r["dash_tip_count"] = static_cast<int>(header_chain.size());
                r["dash_synced"] = header_chain.is_synced();
                // Connection status to local dashd
                r["dashd_connected"] = coin_node && coin_node->has_p2p();
                return r;
            });
            // Wire the dashd P2P peers (primary + broadcaster pool) into the
            // "Parent Chain Peers" panel. broadcaster_status consumes this
            // when m_mm_manager is null (Dash has no merged mining) so the
            // dashboard shows ALL dashd connections — primary SPV + pool
            // slots dialed via getpeerinfo discovery — with addr, subver,
            // height, uptime. Matches p2pool-dash dashboard parity
            // (max_peers=20).
            mi3->set_coin_peer_info_fn([&coin_node, &broadcaster]() -> nlohmann::json {
                nlohmann::json primary = nlohmann::json::array();
                if (coin_node) primary = coin_node->peer_info_json();
                if (!broadcaster) return primary;
                // Concatenate primary SPV connection + broadcaster pool
                // (CoinPeerManager-driven slots). The broadcaster's own
                // get_peer_info includes its local_daemon slot — but we
                // surface the SPV coin_node's row first so the dashboard
                // lists the primary connection at the top.
                nlohmann::json pool = broadcaster->get_peer_info();
                if (!pool.is_array()) return primary;
                for (auto& p : pool) {
                    if (!p.is_object()) continue;
                    // Skip the broadcaster's own local_daemon row to
                    // avoid duplicating the primary SPV connection.
                    std::string addr = p.value("addr", "");
                    bool dup = false;
                    for (const auto& prim : primary) {
                        if (prim.value("addr", "") == addr) { dup = true; break; }
                    }
                    if (dup) continue;
                    primary.push_back(std::move(p));
                }
                return primary;
            });
        }

        // SPV A1 (parity audit): wire ChainLock-aware block verifier now
        // that coin_node exists. record_found_block schedules
        // verify_found_block at 30s/150s/300s/… intervals; this callback
        // returns 1 when dashd's LLMQ-aggregated ChainLock for our block
        // has arrived, promoting the FoundBlock status pending → confirmed.
        // clsig handler in p2p_node.hpp populates coin_node's chainlocked
        // map; this callback just queries it.
        if (web_server) {
            auto* mi2 = web_server->get_mining_interface();
            mi2->add_chain_verify_fn("DASH", [&coin_node](const std::string& hash_hex) -> int {
                if (!coin_node) return 0;
                try {
                    uint256 h;
                    h.SetHex(hash_hex);
                    return coin_node->is_chainlocked(h) ? 1 : 0;
                } catch (...) { return 0; }
            });
        }

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

    // ── Coin RPC (dashd JSON-RPC for GBT + submitblock) ──
    dash::interfaces::Node coin_iface;
    std::unique_ptr<dash::coin::NodeRPC> coin_rpc;
    if (!dashd_rpc_host.empty()) {
        coin_rpc = std::make_unique<dash::coin::NodeRPC>(&ioc, &coin_iface, testnet);
        io::post(ioc, [&]() {
            NetService rpc_addr(dashd_rpc_host + ":" + std::to_string(dashd_rpc_port));
            coin_rpc->connect(rpc_addr, dashd_rpc_userpass);
        });

        // After a short delay (to let RPC handshake complete), do a first GBT
        // call to exercise the pipeline end-to-end and print a summary.
        auto gbt_timer = std::make_shared<io::steady_timer>(ioc, std::chrono::seconds(5));
        gbt_timer->async_wait([&, gbt_timer](const boost::system::error_code& ec) {
            if (ec || !coin_rpc || !coin_rpc->is_connected()) return;
            try {
                auto work = coin_rpc->getwork();
                LOG_INFO << "[DashRPC] GBT: height=" << work.m_height
                         << " coinbasevalue=" << work.m_coinbase_value
                         << " payment_amount=" << work.m_payment_amount
                         << " txs=" << work.m_tx_hashes.size()
                         << " payments=" << work.m_packed_payments.size()
                         << " payload_bytes=" << work.m_coinbase_payload.size()
                         << " bits=0x" << std::hex << work.m_bits << std::dec;
                for (const auto& p : work.m_packed_payments) {
                    LOG_INFO << "[DashRPC]   payment: "
                             << p.payee.substr(0, std::min<size_t>(p.payee.size(), 40))
                             << (p.payee.size() > 40 ? "..." : "")
                             << " amount=" << p.amount;
                }
            } catch (const std::exception& e) {
                LOG_WARNING << "[DashRPC] getwork() failed: " << e.what();
            }
        });

        std::cout << "[DASHD-RPC] Connecting to " << dashd_rpc_host << ":" << dashd_rpc_port
                  << (dashd_rpc_userpass.empty() ? " (no auth)" : " (basic auth)") << std::endl;
    } else {
        std::cout << "[DASHD-RPC] No --dashd-rpc specified, running without RPC (mining disabled)" << std::endl;
    }

    // ── Phase 2 DashCoinBroadcaster (full CoinBroadcaster port) ──
    // Built on top of CoinPeerManager (chain-agnostic) — inherits its
    // Wilson-score reputation, exponential backoff, anchor persistence,
    // /16 group limits. Block propagation fans out to all connected
    // slots; peer discovery happens via BOTH RPC getpeerinfo (used to
    // seed initial candidates) AND addr-message crawl (CoinBroadcaster's
    // default per-peer addr callback feeds new endpoints into the peer
    // manager). Matches p2pool-dash DashNetworkBroadcaster max_peers=20.
    if (!dashd_host.empty() && dashd_max_peers > 1) {
        NetService primary_addr(dashd_host + ":" + std::to_string(dashd_port));

        ::c2pool::merged::PeerManagerConfig pm_config;
        pm_config.max_peers = static_cast<int>(dashd_max_peers);
        pm_config.min_peers = std::max<int>(3, pm_config.max_peers / 4);
        pm_config.max_connections_per_cycle = 5;
        pm_config.max_concurrent_connections = 3;
        pm_config.is_merged = false;      // Dash is the parent chain
        pm_config.valid_ports.insert(dashd_port);  // mainnet 9999 only
        // Re-bootstrap from getpeerinfo every 2 min so a cold start (RPC
        // not yet connected when broadcaster->start() fires) gets a
        // second chance. Upstream default is 30 min, which is too slow
        // for fresh starts.
        pm_config.refresh_interval_sec = 120;

        std::string data_dir =
            std::string(getenv("HOME") ? getenv("HOME") : ".")
            + "/.c2pool/" + coin_name;

        broadcaster = std::make_unique<dash::DashCoinBroadcaster>(
            ioc,
            config->coin()->m_p2p.prefix,
            primary_addr,
            data_dir,
            pm_config);

        // Phase S1 (dash-spv-embedded): wire DNS seeds + fixed-seed fallback
        // into the CoinPeerManager. Dashcore publishes `dnsseed.dash.org` /
        // `testnet-seed.dashdot.io`; fixed seeds come from dashcore's
        // autogenerated chainparamsseeds.h (IPv4 entries). This gives the
        // broadcaster a permissionless way to discover mainnet peers —
        // no dependence on --dashd-rpc getpeerinfo for bootstrap. The
        // getpeerinfo seed below still runs when RPC is configured and
        // augments the candidate pool; the DNS path is always available.
        broadcaster->peer_manager().set_dns_seeds(
            dash::coin::dash_dns_seeds(testnet));
        broadcaster->peer_manager().set_fixed_seeds(
            dash::coin::dash_fixed_seeds(testnet));

        // ── Phase U step 4: rolling-288-block UTXO bootstrap pipeline ──
        // Port of LTC's `c2pool_refactored.cpp:2055..2240` pattern.
        // Target range is [max(utxo_best+1, tip - DASH_MIN_BLOCKS_TO_KEEP), tip]
        // — NOT a genesis replay, NOT an assumeUTXO snapshot; just the
        // last 288 blocks of reorg-safe coverage, matching the same
        // anchoring LTC/DOGE already use in production. Template
        // construction + fee computation in later phases consumes the
        // rolling window; deeper UTXO lookups fall through to the
        // still-trusted dashd RPC until it gets removed.
        auto dash_bs = std::make_shared<
            core::coin::BlockBootstrapState<dash::coin::BlockType>>();

        broadcaster->set_on_full_block(
            [utxo = &utxo_cache,
             utxo_db_ptr = &utxo_db,
             chain = &header_chain,
             bcaster = broadcaster.get(),
             dash_bs,
             cbtx_root = last_cbtx_mnlist_root,
             cbtx_height = last_cbtx_block_height,
             &ioc](
                const std::string& /*peer_key*/,
                const dash::coin::BlockType& block) {
                auto packed_hdr = pack(
                    static_cast<const dash::coin::BlockHeaderType&>(block));
                auto block_hash = dash::crypto::hash_x11(
                    packed_hdr.get_span());

                uint32_t height = 0;
                auto entry = chain->get_header(block_hash);
                if (entry) {
                    height = entry->height;
                } else {
                    auto prev_entry = chain->get_header(block.m_previous_block);
                    if (prev_entry) height = prev_entry->height + 1;
                }
                if (height == 0) {
                    // Header race — block arrived ahead of its own header.
                    // Drop silently; bootstrap will catch it on the next
                    // tip or via stall-timer fallback.
                    return;
                }

                // Phase C-SML step 1 smoke test: parse the coinbase's CCbTx
                // extra payload and log a one-line summary. Every Dash
                // block since DIP-0008 carries a type-5 coinbase with the
                // SML merkle root we'll later verify against. Throttled
                // to every 64th block during bootstrap (would otherwise
                // emit 288 lines on first cold start) and every steady-
                // state tip, so production logs stay readable.
                if (!block.m_txs.empty()) {
                    const auto& cb = block.m_txs[0];
                    if (cb.type == 5 && !cb.extra_payload.empty()) {
                        static uint32_t s_cbtx_seen = 0;
                        ++s_cbtx_seen;
                        bool log_this = (s_cbtx_seen <= 3)
                                     || (s_cbtx_seen % 64 == 0);
                        dash::coin::vendor::CCbTx cbtx;
                        if (dash::coin::vendor::parse_cbtx(cb.extra_payload, cbtx)) {
                            if (log_this) {
                                LOG_INFO << "[CBTX] block_h=" << height
                                         << " " << cbtx.short_str();
                            }
                            // Phase C-SML step 7: stash the latest CBTX
                            // mnlist root so the SML verifier can compare
                            // against it on the next applied diff. We
                            // overwrite unconditionally; mismatches are
                            // surfaced when the diff handler reads it.
                            *cbtx_root = cbtx.merkleRootMNList;
                            *cbtx_height = height;
                        }
                    }
                }

                constexpr uint32_t DASH_KEEP = dash::coin::DASH_MIN_BLOCKS_TO_KEEP;
                static bool dash_bootstrap_done = false;

                // ── 1. Bootstrap trigger ────────────────────────────────
                if (!dash_bootstrap_done && !dash_bs->active
                    && chain && bcaster && height > DASH_KEEP) {
                    dash_bootstrap_done = true;
                    uint32_t utxo_best = utxo->get_best_height();
                    uint32_t start_from =
                        (utxo_best > 0 && utxo_best >= height - DASH_KEEP)
                        ? utxo_best + 1
                        : height - DASH_KEEP;

                    if (start_from < height) {
                        dash_bs->active = true;
                        dash_bs->next_height = start_from;
                        dash_bs->end_height = height;
                        dash_bs->next_request = start_from;
                        dash_bs->total = height - start_from + 1;
                        dash_bs->buffer[height] =
                            std::make_pair(block, block_hash);
                        dash_bs->last_drain_time =
                            std::chrono::steady_clock::now();

                        // Broadcast initial window across all connected
                        // peers so at least one responds even if the
                        // peer that delivered the tip is slow.
                        int requested = 0;
                        while (dash_bs->next_request <= dash_bs->end_height
                               && (dash_bs->next_request - dash_bs->next_height)
                                      < dash_bs->WINDOW_SIZE) {
                            if (!dash_bs->buffer.count(dash_bs->next_request)) {
                                auto e = chain->get_header_by_height(
                                    dash_bs->next_request);
                                if (e) {
                                    bcaster->request_full_block(e->hash);
                                    ++requested;
                                }
                            }
                            ++dash_bs->next_request;
                        }
                        LOG_INFO << "[EMB-DASH] Bootstrap pipeline: "
                                 << dash_bs->total << " blocks ["
                                 << start_from << ".." << height << "]"
                                 << " window=" << dash_bs->WINDOW_SIZE
                                 << " requests=" << requested
                                 << " peers=" << bcaster->peer_count();
                        dash_bs->start_stall_timer(ioc,
                            [chain, bcaster](uint32_t h) {
                                auto e = chain->get_header_by_height(h);
                                if (e && bcaster)
                                    bcaster->request_full_block(e->hash);
                            }, "EMB-DASH");
                        return;
                    } else {
                        LOG_INFO << "[EMB-DASH] UTXO warm restart: best="
                                 << utxo_best << " — no bootstrap needed";
                    }
                }

                // ── 2. Bootstrap active: buffer → drain → refill ─────
                if (dash_bs->active) {
                    if (height >= dash_bs->next_height
                        && height <= dash_bs->end_height) {
                        dash_bs->buffer.try_emplace(
                            height, std::make_pair(block, block_hash));
                    } else if (height > dash_bs->end_height) {
                        // New block mined mid-bootstrap — extend range.
                        dash_bs->end_height = height;
                        dash_bs->total = dash_bs->processed
                            + (dash_bs->end_height - dash_bs->next_height + 1);
                        dash_bs->buffer.try_emplace(
                            height, std::make_pair(block, block_hash));
                    }

                    // Stall fallback: if nothing drained for 30 s, re-ask
                    // the stuck height from all peers.
                    auto now = std::chrono::steady_clock::now();
                    auto stall = std::chrono::duration_cast<std::chrono::seconds>(
                        now - dash_bs->last_drain_time).count();
                    if (stall >= dash_bs->STALL_TIMEOUT_SEC && chain && bcaster) {
                        auto e = chain->get_header_by_height(dash_bs->next_height);
                        if (e) {
                            LOG_WARNING << "[EMB-DASH] Bootstrap stall h="
                                        << dash_bs->next_height << " ("
                                        << stall << "s) — broadcast fallback";
                            bcaster->request_full_block(e->hash);
                        }
                        dash_bs->last_drain_time = now;
                    }

                    while (dash_bs->buffer.count(dash_bs->next_height)) {
                        auto node_ex = dash_bs->buffer.extract(dash_bs->next_height);
                        auto& [b, bh] = node_ex.mapped();
                        uint32_t h = dash_bs->next_height;

                        try {
                            auto undo = utxo->connect_block(
                                b, h, &dash::coin::dash_txid);
                            utxo_db_ptr->put_block_undo(h, undo);
                            utxo->flush(bh, h);
                            utxo->prune_undo(h, DASH_KEEP);
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[EMB-DASH] connect_block failed at h="
                                        << h << ": " << e.what();
                        }

                        ++dash_bs->next_height;
                        ++dash_bs->processed;
                        dash_bs->last_drain_time =
                            std::chrono::steady_clock::now();

                        // Refill window via round-robin target.
                        if (dash_bs->next_request <= dash_bs->end_height) {
                            auto e = chain->get_header_by_height(dash_bs->next_request);
                            if (e) {
                                bcaster->request_full_block_targeted(
                                    e->hash, dash_bs->peer_rotation++);
                            }
                            ++dash_bs->next_request;
                        }

                        if (dash_bs->next_height > dash_bs->end_height) {
                            LOG_INFO << "[EMB-DASH] Bootstrap complete: "
                                     << dash_bs->processed << " blocks processed"
                                     << " utxo_best=" << utxo->get_best_height();
                            dash_bs->active = false;
                            dash_bs->stop_stall_timer();
                            dash_bs->buffer.clear();
                            return;
                        }
                    }
                    return;  // while bootstrap active, skip steady-state path
                }

                // ── 3. Steady state: single connect per new tip ────────
                try {
                    auto undo = utxo->connect_block(
                        block, height, &dash::coin::dash_txid);
                    utxo_db_ptr->put_block_undo(height, undo);
                    utxo->flush(block_hash, height);
                    utxo->prune_undo(height, DASH_KEEP);
                    LOG_INFO << "[UTXO] connected "
                             << block_hash.GetHex().substr(0, 16)
                             << " height=" << height
                             << " txs=" << block.m_txs.size()
                             << " added_ops=" << undo.added_outpoints.size();
                } catch (const std::exception& e) {
                    LOG_WARNING << "[UTXO] connect_block failed for "
                                << block_hash.GetHex().substr(0, 16)
                                << ": " << e.what();
                }
            });

        // ── Phase U polish: tip-changed handler (reorg + sync nudge) ──
        // Port of LTC's c2pool_refactored.cpp:2354 pattern. Two roles:
        //   1. Reorg disconnect_block: when the new tip is at lower-or-
        //      equal height, walk both chains backward to a common
        //      ancestor and `disconnect_from_undo` every old-fork block
        //      whose undo we still hold (rolling 288 window). ChainLocks
        //      make deep reorgs vanishingly rare on Dash, but 1-2-block
        //      tip flutter between network halves seeing different
        //      cmpctblock pushes is plausible — without this, the UTXO
        //      retains stale outputs from the abandoned fork.
        //   2. Header-sync-complete trigger: after every tip advance,
        //      nudge peers for the new tip's full block. This removes
        //      the 0–5 min latency between header sync finishing and
        //      the first unsolicited full_block arrival that would
        //      otherwise trigger the bootstrap pipeline. Skipped while
        //      bootstrap is already draining (would just queue duplicate
        //      getdata for the same hash).
        header_chain.set_on_tip_changed(
            [bcaster = broadcaster.get(),
             chain = &header_chain,
             utxo = &utxo_cache,
             utxo_db_ptr = &utxo_db,
             chainlocked_blocks,
             dash_bs, &ioc](
                const uint256& old_tip, uint32_t old_height,
                const uint256& new_tip, uint32_t new_height) {
                // Callback fires on whichever thread persisted the
                // header (header-sync worker or message handler). Post
                // to ioc so bcaster/UTXO access stays single-threaded.
                io::post(ioc,
                    [bcaster, chain, utxo, utxo_db_ptr,
                     chainlocked_blocks, dash_bs,
                     old_tip, old_height, new_tip, new_height]() {
                  try {
                    bool is_reorg = (new_height <= old_height);
                    LOG_WARNING << "[EMB-DASH] Chain tip changed: "
                                << old_tip.GetHex().substr(0, 16)
                                << " (h=" << old_height << ") → "
                                << new_tip.GetHex().substr(0, 16)
                                << " (h=" << new_height << ")"
                                << (is_reorg ? " [REORG]" : "");

                    // ── Phase L step 4: CL-aware reorg refusal ──
                    // Walk old fork backward from old_tip; if any
                    // block is in chainlocked_blocks AND would be
                    // disconnected by this reorg, refuse outright.
                    // (We need to know fork_height first; do a quick
                    // ancestor walk to find the common point, then
                    // re-walk old_tip → fork checking for CLs.)
                    if (is_reorg && chainlocked_blocks
                        && !chainlocked_blocks->empty() && chain) {
                        // Find fork height by walking new_tip ancestors
                        // into a set, then walking old_tip until we
                        // hit one. Capped at 32 hops — anything deeper
                        // shouldn't happen on Dash mainnet given
                        // ChainLocks finalize within seconds.
                        std::set<uint256> new_anc;
                        {
                            uint256 cur = new_tip;
                            for (int i = 0; i < 32 && !cur.IsNull(); ++i) {
                                new_anc.insert(cur);
                                auto e = chain->get_header(cur);
                                if (!e) break;
                                cur = e->prev_hash;
                            }
                        }
                        uint256 cur = old_tip;
                        for (int i = 0; i < 32 && !cur.IsNull(); ++i) {
                            if (new_anc.count(cur)) break;  // hit fork
                            auto cl_it = chainlocked_blocks->find(cur);
                            if (cl_it != chainlocked_blocks->end()) {
                                LOG_WARNING << "[EMB-DASH] reorg blocked by "
                                               "ChainLock at h=" << cl_it->second
                                            << " block=" << cur.GetHex().substr(0, 16)
                                            << " — refusing to disconnect "
                                               "(old_tip=" << old_tip.GetHex().substr(0, 16)
                                            << " h=" << old_height
                                            << " → new_tip=" << new_tip.GetHex().substr(0, 16)
                                            << " h=" << new_height << ")";
                                return;  // refuse: skip disconnect_block walk
                            }
                            auto e = chain->get_header(cur);
                            if (!e) break;
                            cur = e->prev_hash;
                        }
                    }

                    if (is_reorg && utxo && utxo_db_ptr && chain) {
                        // Walk new chain backward to collect ancestors.
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
                        // Walk old chain backward until we hit an
                        // ancestor of the new chain — that's the fork.
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
                                if (utxo_db_ptr->get_block_undo(h, undo)) {
                                    utxo->disconnect_from_undo(undo);
                                    utxo_db_ptr->remove_block_undo(h);
                                    ++disconnected;
                                }
                            }
                            utxo->flush(fork_hash, fork_height);
                            LOG_WARNING << "[EMB-DASH] UTXO reorg: disconnected "
                                        << disconnected << " blocks (h="
                                        << old_height << "→" << fork_height
                                        << ") fork="
                                        << fork_hash.GetHex().substr(0, 16);
                        }
                    }

                    // Header-sync nudge: ask peers for new tip block so
                    // bootstrap pipeline / steady-state connect_block
                    // doesn't wait on an unsolicited announce. Skip
                    // while bootstrap is draining (already in-flight).
                    if (bcaster && (!dash_bs || !dash_bs->active)) {
                        bcaster->request_full_block(new_tip);
                    }
                  } catch (const std::exception& e) {
                    LOG_ERROR << "[EMB-DASH] Tip-changed handler error: "
                              << e.what();
                  }
                });
            });
        LOG_INFO << "[EMB-DASH] Chain tip-changed handler registered "
                    "(reorg disconnect_block + header-sync nudge)";

        // ── Phase C-SML steps 6+7: SML diff consumer + CBTX root check ──
        // Receives mnlistdiffs from broadcaster fan-out (any peer that
        // replies to a getmnlistd we sent). Applies + persists + verifies
        // root against the most-recent CBTX merkleRootMNList. Mismatch
        // policy at MVP: LOG-ONLY, apply anyway. Hardening to
        // Misbehaving(100) + per-peer ban comes in iteration 2 after we
        // confirm CalcHash() is bit-exact correct.
        broadcaster->set_on_mnlistdiff(
            [sml, sml_db, quorums, quorum_db,
             cbtx_root = last_cbtx_mnlist_root,
             cbtx_height = last_cbtx_block_height, &ioc](
                const std::string& peer_key,
                const dash::coin::vendor::CSimplifiedMNListDiff& diff) {
                io::post(ioc,
                    [sml, sml_db, quorums, quorum_db,
                     cbtx_root, cbtx_height, peer_key, diff]() {
                  try {
                    // Validate base. Cold start: base == ZERO is fine.
                    // Steady state: base must match our current best.
                    uint256 expected_base = sml_db->get_best_hash();
                    if (diff.baseBlockHash != expected_base) {
                        LOG_WARNING << "[SML] diff base mismatch from "
                                    << peer_key
                                    << ": got=" << diff.baseBlockHash.GetHex().substr(0, 16)
                                    << " want=" << expected_base.GetHex().substr(0, 16)
                                    << " — dropping (race or stale request)";
                        return;
                    }

                    auto before_size = sml->size();
                    auto result = dash::coin::vendor::apply_diff(*sml, diff);
                    sml_db->write_sml(*sml, diff.blockHash, *cbtx_height);

                    LOG_INFO << "[SML] applied: +"
                             << result.added_or_updated << "/-"
                             << result.deleted
                             << " size " << before_size << "→" << sml->size()
                             << " best=" << diff.blockHash.GetHex().substr(0, 16)
                             << " peer=" << peer_key;

                    // Phase C-SML step 7: verify against the CBTX
                    // EMBEDDED IN THIS DIFF. The diff carries diff.cbTx
                    // which is the actual coinbase tx of diff.blockHash
                    // — guaranteed to be for the same block whose SML
                    // state we just applied. Using the cbTx from the
                    // diff itself (rather than a cached cbtx_root from
                    // some prior on_full_block arrival) eliminates a
                    // state-coordination race where the cached root was
                    // for a different height than the SML's current
                    // best_block, producing spurious mismatches.
                    auto computed = sml->CalcMerkleRoot();
                    dash::coin::vendor::CCbTx diff_cbtx;
                    if (!dash::coin::vendor::parse_cbtx(
                            diff.cbTx.extra_payload, diff_cbtx)) {
                        LOG_WARNING << "[SML] could not parse CBTX from "
                                       "mnlistdiff (CCbTx payload "
                                       << diff.cbTx.extra_payload.size()
                                       << " B) — root verification skipped";
                    } else if (computed == diff_cbtx.merkleRootMNList) {
                        LOG_INFO << "[SML] root MATCH "
                                 << computed.GetHex().substr(0, 16)
                                 << " (vs diff.cbTx@h=" << diff_cbtx.nHeight
                                 << " block=" << diff.blockHash.GetHex().substr(0, 16) << ")";
                    } else {
                        LOG_WARNING << "[SML] root MISMATCH"
                                    << " computed=" << computed.GetHex().substr(0, 16)
                                    << " cbtx="     << diff_cbtx.merkleRootMNList.GetHex().substr(0, 16)
                                    << " (vs diff.cbTx@h=" << diff_cbtx.nHeight
                                    << " block=" << diff.blockHash.GetHex().substr(0, 16) << ")"
                                    << " — log-only at MVP, applied anyway";
                    }

                    // ── Phase C-QUO step 3: structured tail → quorums ─
                    // Runs AFTER SML application. Failure here logs a
                    // warning and continues — SML sync stays alive
                    // (the MVP correctness gate). This is the optional,
                    // fail-safe layer over the opaque tail in
                    // smldiff.hpp; once we've observed N consecutive
                    // clean parses against mainnet we can promote the
                    // tail to first-class structured fields.
                    dash::coin::vendor::QuorumTail qtail;
                    if (dash::coin::vendor::parse_quorum_tail(
                            diff.quorum_tail, qtail)) {
                        auto qr = quorums->apply(qtail);
                        // Flush to QuorumDb on the same beat as SMLDb's
                        // write_sml above. Keeps the two stores' BEST
                        // sentinels aligned so the startup divergence
                        // check stays meaningful. Failure here is
                        // logged but non-fatal — in-memory state is
                        // still correct for THIS session; the next
                        // restart would just cold-start.
                        bool persisted = false;
                        if (quorum_db->is_open()) {
                            persisted = quorum_db->write_state(
                                *quorums, diff.blockHash, *cbtx_height);
                        }
                        LOG_INFO << "[QUO] applied: +"
                                 << qr.added_or_updated << "/-"
                                 << qr.deleted
                                 << " active=" << qr.active_after
                                 << " cl_sigs=" << qr.cl_sigs_cached
                                 << " (tail=" << diff.quorum_tail.size() << "B"
                                 << " persisted=" << (persisted ? "yes" : "no") << ")";
                    } else {
                        LOG_WARNING << "[QUO] tail parse failed — "
                                       "quorum tracking skipped for this "
                                       "diff (SML sync unaffected)";
                    }
                  } catch (const std::exception& e) {
                    LOG_ERROR << "[SML] diff handler error: " << e.what();
                  }
                });
            });
        LOG_INFO << "[EMB-DASH] SML diff handler registered "
                    "(apply_diff + LevelDB flush + CBTX root verification "
                    "+ structured quorum tail)";

        // ── Phase L step 3: ChainLock verifier wiring ──
        // Receives clsigs from broadcaster fan-out (any peer that
        // pushes one). Runs the full verify recipe (request_id →
        // signing-pool → selected-quorum → sign_hash → BLS Verify) via
        // chainlock_verify.hpp. Mismatch policy at MVP: LOG-ONLY,
        // chainlocked_blocks already updated by p2p_node.hpp's relay-
        // trust path. Iteration 2 (after N clean MATCH blocks) gates
        // the chainlocked_blocks update on verify success.
        broadcaster->set_on_clsig(
            [quorums, chain = &header_chain, chainlocked_blocks, &ioc](
                const std::string& peer_key,
                int32_t height,
                const uint256& bhash,
                const std::array<uint8_t, 96>& sig) {
                io::post(ioc,
                    [quorums, chain, chainlocked_blocks,
                     peer_key, height, bhash, sig]() {
                  try {
                    // Relay-trust record (MVP). Iteration 2 will gate
                    // this write on verify-success below.
                    (*chainlocked_blocks)[bhash] = height;

                    auto r = dash::coin::verify_chainlock(
                        height, bhash, sig, *quorums, *chain);
                    using S = dash::coin::ChainLockVerifyResult::Status;
                    switch (r.status) {
                    case S::VALID:
                        LOG_INFO << "[CLSIG] verified height=" << height
                                 << " block=" << bhash.GetHex().substr(0, 16)
                                 << " quorum=" << r.selected_quorum_hash.GetHex().substr(0, 16)
                                 << " pool=" << r.pool_size
                                 << " qver=" << r.quorum_nversion
                                 << " scheme=" << (r.scheme_legacy ? "legacy" : "basic")
                                 << " peer=" << peer_key;
                        break;
                    case S::INVALID_SIG:
                        LOG_WARNING << "[CLSIG] verify FAILED (bad sig) height=" << height
                                    << " block=" << bhash.GetHex().substr(0, 16)
                                    << " selected_quorum=" << r.selected_quorum_hash.GetHex().substr(0, 16)
                                    << " pool=" << r.pool_size
                                    << " qver=" << r.quorum_nversion
                                    << " scheme=" << (r.scheme_legacy ? "legacy" : "basic")
                                    << " peer=" << peer_key
                                    << " — log-only at MVP, relay-trust "
                                       "record retained";
                        break;
                    case S::NO_POOL:
                        LOG_WARNING << "[CLSIG] no signing pool height=" << height
                                    << " (anchor h=" << (height - dash::coin::clsig_detail::CHAINLOCKS_SIGN_OFFSET)
                                    << " has no LLMQ_400_60 quorums in our active set) "
                                       "— SML/QUO sync not yet primed";
                        break;
                    case S::NO_SELECTED:
                        LOG_WARNING << "[CLSIG] pool exists but no quorum selected "
                                       "(unexpected) height=" << height;
                        break;
                    }
                  } catch (const std::exception& e) {
                    LOG_ERROR << "[CLSIG] verify exception: " << e.what();
                  }
                });
            });
        LOG_INFO << "[EMB-DASH] ChainLock verifier registered "
                    "(BLS verify against derived signing quorum, "
                    "log-only mismatch at MVP)";

        // ── Phase C-SML step 6: tip-changed → request_mnlistdiff ──
        // Augment the existing tip-changed handler with an SML sync
        // trigger. On every tip advance: send getmnlistd(prev_best,
        // new_tip) to a single peer (round-robin via static counter).
        // Cold start (no prev_best): use uint256::ZERO. Reorg handling
        // lives in the same handler — drop SML + clear DB + cold-start.
        // We register this as a *second* tip-changed callback by
        // chaining off the existing one's outer scope; HeaderChain only
        // supports one callback so we have to wrap.
        //
        // Implementation: HeaderChain.set_on_tip_changed REPLACES, so
        // we re-set with a wrapper that runs the previous logic AND the
        // SML trigger. Re-fetching `header_chain.set_on_tip_changed`
        // below would clobber the Phase U handler — instead we add the
        // SML logic INSIDE that handler. So below, we re-register a
        // single combined handler that does both.
        //
        // For implementation simplicity at this step, we just add a
        // separate timer-based poll: every 30s, if (sml_best_height <
        // header_chain.height()), send getmnlistd. This avoids touching
        // the Phase U handler and gives us a working sync without race
        // conditions on first-tip arrival timing.
        // Chained-timer pattern: the persistent std::function is held
        // via shared_ptr on the heap and is NEVER passed directly to
        // async_wait. Each schedule() call hands async_wait a fresh
        // wrapper lambda that captures `tick` by value and invokes
        // (*tick)(ec) when fired. Direct passing of the persistent
        // std::function caused boost::asio's perfect-forwarding to
        // move-from the lvalue on first dispatch, leaving the function
        // empty; the second fire then crashed dereferencing an empty
        // std::function (apport core 03:55 / Thread 1 SIGSEGV).
        auto sml_sync_timer = std::make_shared<io::steady_timer>(ioc);
        auto sml_sync_tick =
            std::make_shared<std::function<void(const boost::system::error_code&)>>();
        auto sml_schedule = [sml_sync_timer, sml_sync_tick]() {
            sml_sync_timer->expires_after(std::chrono::seconds(30));
            sml_sync_timer->async_wait(
                [sml_sync_tick](const boost::system::error_code& ec) {
                    if (*sml_sync_tick) (*sml_sync_tick)(ec);
                });
        };
        *sml_sync_tick = [sml_sync_timer, sml, sml_db,
                          bcaster = broadcaster.get(),
                          chain = &header_chain,
                          sml_schedule](
            const boost::system::error_code& ec) {
            if (ec || !bcaster) return;
            try {
                uint32_t hdr_height = chain->height();
                uint32_t sml_height = sml_db->get_best_height();
                uint256  hdr_tip = chain->tip() ? chain->tip()->hash
                                                : uint256{};
                if (!hdr_tip.IsNull()
                    && (hdr_height > sml_height || sml_height == 0)
                    && bcaster->peer_count() > 0) {
                    static size_t s_peer_rot = 0;
                    auto base = sml_db->get_best_hash();
                    auto picked = bcaster->request_mnlistdiff_targeted(
                        base, hdr_tip, s_peer_rot++);
                    LOG_INFO << "[SML] sync request: base="
                             << base.GetHex().substr(0, 16)
                             << " target=" << hdr_tip.GetHex().substr(0, 16)
                             << " peer=" << (picked.empty() ? "(none)" : picked)
                             << " hdr_h=" << hdr_height
                             << " sml_h=" << sml_height;
                }
            } catch (const std::exception& e) {
                LOG_WARNING << "[SML] sync tick error: " << e.what();
            }
            sml_schedule();
        };
        sml_schedule();
        LOG_INFO << "[EMB-DASH] SML sync timer armed (30s interval, "
                    "fires once header chain advances ahead of SML)";

        // Seed initial candidates via dashd RPC getpeerinfo — the same
        // flow the Phase 1 broadcaster used. After seed, addr-crawl via
        // message_addr from any connected peer keeps the candidate pool
        // fresh (no RPC dependency after startup).
        if (coin_rpc) {
            broadcaster->set_getpeerinfo_fn(
                [&coin_rpc, dashd_port]() -> std::vector<NetService> {
                    std::vector<NetService> out;
                    if (!coin_rpc || !coin_rpc->is_connected()) return out;
                    try {
                        auto j = coin_rpc->getpeerinfo();
                        if (!j.is_array()) return out;
                        for (const auto& p : j) {
                            if (!p.is_object() || !p.contains("addr")) continue;
                            std::string raw = p.value("addr", "");
                            if (raw.empty()) continue;
                            // dashd reports [::ffff:1.2.3.4]:9999 for v4-mapped
                            // v6 and plain ip:port for IPv4-only listeners.
                            if (raw.front() == '[') {
                                auto rb = raw.find(']');
                                if (rb == std::string::npos) continue;
                                std::string host = raw.substr(1, rb - 1);
                                if (rb + 1 >= raw.size() || raw[rb + 1] != ':') continue;
                                int port = 0;
                                try { port = std::stoi(raw.substr(rb + 2)); }
                                catch (...) { continue; }
                                const std::string v4 = "::ffff:";
                                if (host.rfind(v4, 0) == 0) host = host.substr(v4.size());
                                if (port == dashd_port)
                                    out.emplace_back(host, static_cast<uint16_t>(port));
                            } else {
                                auto cln = raw.rfind(':');
                                if (cln == std::string::npos) continue;
                                int port = 0;
                                try { port = std::stoi(raw.substr(cln + 1)); }
                                catch (...) { continue; }
                                if (port == dashd_port)
                                    out.emplace_back(raw.substr(0, cln),
                                                     static_cast<uint16_t>(port));
                            }
                        }
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[DASH] getpeerinfo seed failed: " << e.what();
                    }
                    return out;
                });
        }

        // Defer start() so the dashd RPC has time to finish its initial
        // handshake. Otherwise the first getpeerinfo seed call fires against
        // a not-yet-connected RPC and returns zero candidates — the pool
        // would then only refill on the 120s refresh tick.
        auto bc_start_timer = std::make_shared<io::steady_timer>(
            ioc, std::chrono::seconds(7));
        bc_start_timer->async_wait(
            [bc_start_timer, &broadcaster, dashd_max_peers]
            (const boost::system::error_code& ec) {
                if (ec || !broadcaster) return;
                broadcaster->start();
                LOG_INFO << "[DASHD-POOL] DashCoinBroadcaster started — target="
                         << dashd_max_peers
                         << " peers (CoinPeerManager: Wilson-score + /16 "
                            "group cap + anchor persistence + addr-crawl)";
            });
        std::cout << "[DASHD-POOL] DashCoinBroadcaster armed — target="
                  << dashd_max_peers << " peers (delayed 7s for RPC handshake)"
                  << std::endl;
    } else {
        std::cout << "[DASHD-POOL] Broadcaster disabled "
                  << "(--dashd-max-peers=" << dashd_max_peers
                  << ", need --dashd + >=2 peers)" << std::endl;
    }

    // ── Connect to p2pool peer(s) ──
    // Dial every bootstrap addr up front so we never wait on the 30s outbound
    // timer to randomly pick a live one. On a sparse network like Dash's, the
    // upstream bootstrap's relayed addr list is mostly stale — immediate
    // parallel dials to all known-good operators give us fast multi-peer
    // convergence.
    for (const auto& b : config->pool()->m_bootstrap_addrs) {
        std::cout << "[P2P] Connecting to " << b.to_string() << "..." << std::endl;
        io::post(ioc, [&, addr = b]() { node.connect(addr); });
    }

    // ── Periodic outbound peer expansion ─────────────────────────────
    // Every 30s, if we're below the target outbound count, dial one more
    // peer from the addr store (populated via message_addrs responses from
    // handshaked peers). Mirrors p2pool-dash/p2p.py:667 ClientFactory.think
    // and LTC's NodeImpl::start_outbound_connections — dial multiple per
    // tick until target reached.
    //
    // C3 (parity audit): outbound-peer target now comes from --target-peers
    // CLI flag (default 10, matching p2pool-dash/p2p.py:704
    // desired_outgoing_conns). --ban-duration tunes the peer-ban expiry.
    //
    // First-fire at 5s (was 15s) so expansion beyond the bootstrap set
    // starts promptly — previously a 15s delay + target=4 meant the tick
    // never dialed after bootstrap filled target.
    const size_t TARGET_OUTBOUND_PEERS = target_outbound_peers;
    node.set_ban_duration(peer_ban_duration_sec);
    auto outbound_timer = std::make_shared<io::steady_timer>(ioc);
    std::function<void(const boost::system::error_code&)> outbound_fn;
    outbound_fn = [&, outbound_timer](const boost::system::error_code& ec) {
        if (ec) return;
        // B3: sweep expired ban entries before dialing so recovered peers
        // can re-enter the candidate pool.
        try { node.expire_bans(); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Dash] expire_bans threw: " << e.what();
        }
        try { node.try_connect_more_peers(TARGET_OUTBOUND_PEERS); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Dash] outbound dial failed: " << e.what();
        }
        outbound_timer->expires_after(std::chrono::seconds(15));
        outbound_timer->async_wait(outbound_fn);
    };
    outbound_timer->expires_after(std::chrono::seconds(5));
    outbound_timer->async_wait(outbound_fn);

    // ── Ancestor backfill (periodic sharereq for shallow heads) ──────
    // When a head's walkable depth is < chain_length, this tick finds
    // its tail and requests the missing parent. Without it, heads that
    // appear during a network blip stay stuck at their initial depth
    // (handshake/bestblock events triggered one download which failed,
    // and nothing retries). Runs every 30 s.
    auto backfill_timer = std::make_shared<io::steady_timer>(ioc);
    std::function<void(const boost::system::error_code&)> backfill_fn;
    backfill_fn = [&, backfill_timer](const boost::system::error_code& ec) {
        if (ec) return;
        try { node.backfill_ancestors(); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Dash] backfill_ancestors threw: " << e.what();
        }
        backfill_timer->expires_after(std::chrono::seconds(30));
        backfill_timer->async_wait(backfill_fn);
    };
    backfill_timer->expires_after(std::chrono::seconds(20));
    backfill_timer->async_wait(backfill_fn);

    // ── Tracker pruning (B2 from parity audit) ───────────────────────
    // p2pool-style tail-drop keeps the chain at 2*CL+10 = ~8650 shares.
    // Without this, live tracker grew to 10k+ within minutes — unbounded
    // leak. Fires every 60s; node.prune_shares() does up to 1000
    // removals per call (~350 in practice on first pass, ~1 per share
    // arrival steady-state). Separate timer so it never blocks the JOB
    // cycle or share-arrival path.
    auto prune_timer = std::make_shared<io::steady_timer>(ioc);
    std::function<void(const boost::system::error_code&)> prune_fn;
    prune_fn = [&, prune_timer](const boost::system::error_code& ec) {
        if (ec) return;
        try { node.prune_shares(); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Dash] prune_shares threw: " << e.what();
        }
        prune_timer->expires_after(std::chrono::seconds(60));
        prune_timer->async_wait(prune_fn);
    };
    // First prune 90s in — gives the initial sharechain download time to
    // complete before we start evicting.
    prune_timer->expires_after(std::chrono::seconds(90));
    prune_timer->async_wait(prune_fn);

    // ── Stratum server + job push (M6 Phase 4a: outbound work only) ──
    std::unique_ptr<dash::stratum::Server> stratum_server;
    if (stratum_port != 0) {
        try {
            stratum_server = std::make_unique<dash::stratum::Server>(ioc, stratum_port);
            // Per-session vardiff tuned to p2pool-dash mainnet (10s share
            // rate, 8-share trigger, quickup 2/3, 0.5/2.0 clip). Initial
            // difficulty comes from --share-difficulty (default 0.001 =
            // p2pool-dash MIN_DIFFICULTY_FLOOR). Bounds are set wide enough
            // that real ASIC hashrates can push diff to thousands.
            stratum_server->set_vardiff_config(
                params.vardiff,
                /*min_difficulty=*/0.001,
                /*max_difficulty=*/1e12,
                /*initial_difficulty=*/share_difficulty_default);
            stratum_server->start();
            std::cout << "[STRATUM] listening on 0.0.0.0:" << stratum_port
                      << " (vardiff: share_rate=" << params.vardiff.target_share_rate
                      << "s trigger=" << params.vardiff.shares_trigger
                      << " clip=" << params.vardiff.min_adjust
                      << "/" << params.vardiff.max_adjust << ")"
                      << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[STRATUM] failed to open port " << stratum_port
                      << ": " << e.what() << std::endl;
        }
    } else {
        std::cout << "[STRATUM] disabled (pass --stratum-port 7903 to enable)" << std::endl;
    }

    // Resolve miner payout script once (from --mining-address). Also extract
    // the 20-byte pubkey_hash — it goes into every share we create as
    // m_pubkey_hash, which is what Dash's PPLNS pays out to.
    std::vector<unsigned char> miner_script;
    uint160 miner_pubkey_hash;
    if (!mining_address.empty()) {
        miner_script = dash::decode_payee_script(
            mining_address, params.address_version, params.address_p2sh_version);
        std::vector<unsigned char> decoded;
        if (DecodeBase58Check(mining_address, decoded, 21) && decoded.size() == 21) {
            std::memcpy(miner_pubkey_hash.data(), decoded.data() + 1, 20);
        }
        if (miner_script.empty()) {
            std::cerr << "[MINING] --mining-address '" << mining_address
                      << "' could not be decoded for this network" << std::endl;
        } else {
            std::cout << "[MINING] payout address: " << mining_address
                      << " (script=" << miner_script.size() << "B"
                      << " pubkey_hash=" << miner_pubkey_hash.GetHex().substr(0, 16) << "...)"
                      << std::endl;
        }
    }

    // Side-map of job_id → (share template, tx bodies). Bounded history,
    // matches stratum::Server's MAX_JOB_HISTORY. Populated from the job-
    // refresh closure; consumed by the submit handler so it can pair a
    // newly-created share with the exact tx set it references in
    // new_transaction_hashes (needed for message_remember_tx).
    struct TemplateEntry {
        dash::DashShare share;
        std::vector<dash::coin::MutableTransaction> tx_bodies;
    };
    std::unordered_map<std::string, TemplateEntry> share_templates;
    std::deque<std::string> share_template_order;
    std::mutex share_templates_mtx;
    constexpr size_t MAX_TEMPLATE_HISTORY = 16;

    auto store_template = [&](const std::string& job_id,
                              dash::DashShare tmpl,
                              std::vector<dash::coin::MutableTransaction> tx_bodies) {
        std::lock_guard<std::mutex> lock(share_templates_mtx);
        share_templates[job_id] = TemplateEntry{std::move(tmpl), std::move(tx_bodies)};
        share_template_order.push_back(job_id);
        while (share_template_order.size() > MAX_TEMPLATE_HISTORY) {
            share_templates.erase(share_template_order.front());
            share_template_order.pop_front();
        }
    };
    auto fetch_template = [&](const std::string& job_id) -> std::optional<TemplateEntry> {
        std::lock_guard<std::mutex> lock(share_templates_mtx);
        auto it = share_templates.find(job_id);
        if (it == share_templates.end()) return std::nullopt;
        return it->second;
    };

    // Submit handler: validate reconstructed block header, forward blocks.
    if (stratum_server) {
        stratum_server->set_submit_handler(
            [&](const dash::stratum::SubmittedShare& s,
                const dash::stratum::JobContext* ctx,
                std::string& reject) -> bool {
                if (!ctx) {
                    reject = "stale job";
                    return false;
                }
                auto r = dash::submit::validate(s, *ctx);
                if (!r.valid_share) {
                    LOG_INFO << "[SUBMIT] rejected worker=" << s.worker_name
                             << " job=" << s.job_id
                             << " hash=" << r.x11_hash.GetHex().substr(0, 16)
                             << " reason=" << r.reject_reason;
                    reject = r.reject_reason;
                    return false;
                }
                LOG_INFO << "[SUBMIT] accepted worker=" << s.worker_name
                         << " job=" << s.job_id
                         << " hash=" << r.x11_hash.GetHex().substr(0, 16)
                         << (r.is_block ? " *** BLOCK ***"
                             : r.valid_real_share ? " real_share"
                             : " pseudoshare");
                // Feed hashrate tracker so per-worker estimates update.
                enhanced_node->track_mining_share_submission(
                    s.worker_name, ctx->share_difficulty);
                if (r.is_block && coin_rpc && coin_rpc->is_connected()) {
                    // SPV A2 (parity audit): broadcast via dashd P2P BEFORE
                    // the RPC call so the network sees our block ~1-2s
                    // earlier. Fire-and-forget; RPC is the authoritative
                    // acceptance signal.
                    if (coin_node && coin_node->has_p2p()) {
                        try {
                            auto bytes = ParseHex(r.block_hex);
                            std::span<const unsigned char> span(
                                bytes.data(), bytes.size());
                            coin_node->submit_block_raw(span);
                            LOG_INFO << "[SUBMIT] P2P block broadcast sent (bytes="
                                     << bytes.size() << ")";
                            // Fan-out via DashCoinBroadcaster pool so the
                            // block reaches 20 dashd peers in parallel
                            // rather than just the single primary SPV.
                            // Matches p2pool-dash broadcaster behavior.
                            if (broadcaster)
                                broadcaster->submit_block_raw(span);
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[SUBMIT] P2P block broadcast threw: " << e.what();
                        }
                    }
                    bool rpc_accepted = false;
                    try {
                        rpc_accepted = coin_rpc->submit_block_hex(r.block_hex);
                        LOG_INFO << "[SUBMIT] submitblock result="
                                 << (rpc_accepted ? "ACCEPTED" : "rejected")
                                 << " height=" << ctx->height;
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[SUBMIT] submitblock threw: " << e.what();
                    }
                    // C1 (parity audit): record the block find so
                    // /recent_blocks exposes it to the dashboard. Only
                    // record on RPC-ACCEPTED — the P2P pre-broadcast is
                    // best-effort and dashd rejection of the block (bad
                    // coinbase, missing ChainLock, etc.) should not surface
                    // as a "found" entry.
                    if (rpc_accepted) {
                        try {
                            auto* mi = web_server ? web_server->get_mining_interface() : nullptr;
                            if (mi) {
                                // X11 of header == the block's identifier on
                                // Dash mainnet.
                                mi->record_found_block(
                                    ctx->height,
                                    r.x11_hash,
                                    static_cast<uint64_t>(std::time(nullptr)),
                                    "DASH",
                                    s.worker_name,
                                    /*share_hash=*/"",
                                    chain::target_to_difficulty(
                                        chain::bits_to_target(ctx->nbits)),
                                    ctx->share_difficulty,
                                    /*pool_hashrate=*/0.0, // filled by impl
                                    /*subsidy=*/0);         // filled by impl
                            }
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[SUBMIT] record_found_block: " << e.what();
                        }
                    }
                }

                // Promote this submit into a real v16 share ONLY if the hash
                // meets the pool's real_share_target (≤ MAX_TARGET). Shares
                // that only meet the miner's stratum target are pseudoshares:
                // they count for stratum stats (already tracked above) and
                // local PPLNS credit, but broadcasting them would produce
                // protocol-invalid shares (share.target > MAX_TARGET) that
                // peers reject as PeerMisbehavingError('share target invalid').
                // See p2pool-dash data.py:356-358.
                if (!r.valid_real_share) {
                    // Accepted as a pseudoshare; nothing to broadcast.
                    return true;
                }
                try {
                    auto tmpl_opt = fetch_template(s.job_id);
                    if (!tmpl_opt) {
                        LOG_WARNING << "[SHARE] template missing for job="
                                    << s.job_id;
                    } else {
                        auto en2 = ParseHex(s.extranonce2_hex);
                        uint32_t miner_ntime = 0, miner_nonce = 0;
                        dash::submit::parse_be_u32_hex(s.ntime_hex, miner_ntime);
                        dash::submit::parse_be_u32_hex(s.nonce_hex, miner_nonce);
                        auto finalized = dash::share_builder::finalize_from_submit(
                            tmpl_opt->share, miner_ntime, miner_nonce,
                            std::span<const unsigned char>(en2.data(), en2.size()),
                            params);
                        auto h = node.add_local_share(finalized);
                        node.broadcast_share(finalized, tmpl_opt->tx_bodies);
                        LOG_INFO << "[SHARE] created hash="
                                 << h.GetHex().substr(0, 16)
                                 << " absheight=" << finalized.m_absheight
                                 << " tx_refs=" << tmpl_opt->tx_bodies.size()
                                 << " broadcast OK";
                    }
                } catch (const std::exception& e) {
                    LOG_WARNING << "[SHARE] creation failed: " << e.what();
                }
                return true;
            });
    }

    // Periodic GBT → PPLNS split → job → notify.
    auto job_timer = std::make_shared<io::steady_timer>(ioc);
    const std::string pool_tag = "/c2pool-dash:0.1/";
    const size_t eff_window = pplns_window != 0 ? pplns_window : params.chain_length;
    std::function<void(const boost::system::error_code&)> job_fn;
    job_fn = [&, job_timer](const boost::system::error_code& ec) {
        if (ec) return;
        if (coin_rpc && coin_rpc->is_connected() && !miner_script.empty()) {
            try {
                auto work = coin_rpc->getwork();

                // Feed network difficulty from GBT to the adjustment engine.
                {
                    auto net_target = chain::bits_to_target(work.m_bits);
                    double net_diff = chain::target_to_difficulty(net_target);
                    enhanced_node->get_difficulty_engine()
                        .set_network_difficulty(net_diff);
                }

                // Miner value = block reward minus masternode/treasury.
                uint64_t miner_value = (work.m_coinbase_value > work.m_payment_amount)
                    ? work.m_coinbase_value - work.m_payment_amount : 0;
                // D3: publish the current miner-value so the background
                // PPLNS precomputer uses a real subsidy for tooltip amounts.
                g_latest_miner_value.store(miner_value);

                // Compute PPLNS payout distribution (or single-miner fallback).
                std::vector<dash::coinbase::MinerPayout> payouts;
                dash::pplns::Result pplns{};
                if (pplns_enabled) {
                    pplns = dash::pplns::compute_payouts(
                        node.tracker().chain,
                        node.best_share_hash(),
                        eff_window,
                        miner_value,
                        miner_script);
                    for (auto& p : pplns.payouts)
                        payouts.push_back({p.script, p.amount});
                } else {
                    payouts.push_back({miner_script, miner_value});
                }

                // Pick a share target bits from our configured share_difficulty.
                // (target_from_difficulty matches submit_validator's math.)
                uint32_t share_bits = 0;
                {
                    uint256 st = dash::submit::target_from_difficulty(share_difficulty_default);
                    share_bits = chain::target_to_bits_upper_bound(st);
                    if (share_bits == 0) share_bits = 0x1f00ffff;
                }

                uint16_t donation_bps = static_cast<uint16_t>(std::min(
                    65535.0, std::max(0.0, 65535.0 * donation_percentage / 100.0)));
                auto built = dash::share_builder::build(
                    work, node.tracker(), miner_pubkey_hash, payouts, pool_tag, params,
                    share_bits, share_difficulty_default, donation_bps);

                // Publish the coinbase's mineable tx_outs to /current_payouts.
                // Driven off built.tx_outs_mineable (worker_tx || donation_tx,
                // masternode/platform entries excluded) so the dashboard's
                // "Current Payouts" only surfaces payouts a miner can earn
                // a share of. Masternode + platform payments come from
                // dashd's GBT and are consensus-fixed — they don't belong in
                // the pool's payout view.
                if (web_server) {
                    std::vector<std::pair<std::string,uint64_t>> pplns_cache;
                    pplns_cache.reserve(built.tx_outs_mineable.size());
                    for (const auto& o : built.tx_outs_mineable) {
                        if (o.amount == 0) continue;  // drop zero entries
                        pplns_cache.emplace_back(HexStr(o.script), o.amount);
                    }
                    auto* mi = web_server->get_mining_interface();
                    mi->set_cached_pplns_outputs(std::move(pplns_cache));
                    // /current_merged_payouts + /sharechain/window are both
                    // keyed on the sharechain tip. The JOB cycle fires every
                    // 10 s but the tip only changes when a new share lands
                    // (~20 s on Dash). Gate invalidations on an actual tip
                    // change — P3(b) from the next-session plan. Matches LTC
                    // (trigger_work_refresh_debounced is called only on
                    // share arrivals, not on a timer).
                    static uint256 s_last_cached_tip;
                    uint256 cur_tip = node.best_share_hash();
                    if (cur_tip != s_last_cached_tip) {
                        s_last_cached_tip = cur_tip;
                        mi->cache_pplns_at_tip();
                        mi->invalidate_window_cache();
                    }
                }

                size_t miner_count = 0;
                if (stratum_server) {
                    // Do NOT call set_difficulty_all() here — each Session's
                    // HashrateTracker holds its own per-miner vardiff target
                    // and pushes its own mining.set_difficulty after every
                    // accepted share (matches p2pool-dash's per-session
                    // vardiff). A pool-wide broadcast would stomp on that.
                    stratum_server->notify_all(built.job, built.context);
                    store_template(built.job.job_id, built.share_template, built.tx_bodies);
                    miner_count = stratum_server->session_count();
                }

                LOG_INFO << "[JOB] id=" << built.job.job_id
                         << " height=" << work.m_height
                         << " miners=" << miner_count
                         << " coinb_bytes=" << built.coinbase.bytes.size()
                         << " ref_off=" << built.coinbase.ref_hash_offset
                         << " n64_off=" << built.coinbase.nonce64_offset
                         << " branches=" << built.job.merkle_branches_hex.size()
                         << " txs=" << built.context.tx_data_hex.size()
                         << " pplns_mode="
                         << (!pplns_enabled ? "disabled"
                             : pplns.used_fallback ? "fallback_solo" : "active")
                         << " payouts=" << payouts.size()
                         << " shares_used=" << pplns.shares_used
                         // p2pool-dash-parity walk (WeightsSkipList port):
                         << " parity_walked=" << built.pplns_walked
                         << " parity_scripts=" << built.pplns_scripts
                         << " ref_hash=" << built.ref_hash.GetHex().substr(0, 16);
            } catch (const std::exception& e) {
                LOG_WARNING << "[JOB] build failed: " << e.what();
            }
        }
        job_timer->expires_after(std::chrono::seconds(10));
        job_timer->async_wait(job_fn);
    };
    // Kick off after initial RPC handshake delay.
    job_timer->expires_after(std::chrono::seconds(8));
    job_timer->async_wait(job_fn);

    // Run IO context
    std::cout << "[P2P] Running event loop..." << std::endl;

    // B5 (parity audit): heartbeat with peers + hashrate + verified count
    // so operator sees ongoing state at a glance. LTC has `heartbeat_log`
    // with similar fields; Dash's existing [STATUS] line only covered
    // shares / headers / miners.
    io::steady_timer status(ioc, std::chrono::seconds(10));
    std::function<void(const boost::system::error_code&)> status_fn;
    status_fn = [&](const boost::system::error_code& ec) {
        if (ec) return;
        std::cout << "[STATUS] shares=" << node.tracker().chain.size()
                  << " verified=" << node.tracker().verified.size()
                  << " peers=" << node.peer_count()
                  << " headers=" << header_chain.height()
                  << "/" << header_chain.size()
                  << (header_chain.is_synced() ? " SYNCED" : " syncing");
        if (stratum_server)
            std::cout << " miners=" << stratum_server->session_count();
        // Pool hashrate (X11 H/s from sharechain attempts-per-second).
        try {
            double hps = node.pool_hashrate();
            if (hps > 0) {
                const char* unit = "H/s";
                double v = hps;
                if (v > 1e9) { v /= 1e9; unit = "GH/s"; }
                else if (v > 1e6) { v /= 1e6; unit = "MH/s"; }
                else if (v > 1e3) { v /= 1e3; unit = "KH/s"; }
                std::cout << " hash=" << std::fixed
                          << std::setprecision(2) << v << unit;
            }
        } catch (...) {}
        std::cout << std::endl;
        status.expires_after(std::chrono::seconds(10));
        status.async_wait(status_fn);
    };
    status.async_wait(status_fn);

    // Enhanced-node stats timer (every 60s): hashrate, vardiff, share counts.
    io::steady_timer enh_stats(ioc, std::chrono::seconds(60));
    std::function<void(const boost::system::error_code&)> enh_stats_fn;
    enh_stats_fn = [&](const boost::system::error_code& ec) {
        if (ec) return;
        enhanced_node->log_sharechain_stats();
        enh_stats.expires_after(std::chrono::seconds(60));
        enh_stats.async_wait(enh_stats_fn);
    };
    enh_stats.async_wait(enh_stats_fn);

    // B4 (parity audit): graceful shutdown on SIGINT/SIGTERM. Uses asio
    // signal_set which runs the handler on the io_context thread — clean
    // interleave with every other asio timer. Handler flushes the LevelDB
    // persistence buffers (verified + removals) so we don't lose state on
    // exit, then calls ioc.stop() so the ioc.run() below returns.
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& ec, int sig) {
        if (ec) return;
        std::cout << "\n[Dash] Received signal " << sig
                  << ", flushing state + shutting down..." << std::endl;
        try { node.shutdown_storage(); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Dash] shutdown_storage: " << e.what();
        }
        // C2: final graph_db save so we don't lose recent samples.
        if (web_server) {
            try { web_server->get_mining_interface()->save_stat_log(); }
            catch (const std::exception& e) {
                LOG_WARNING << "[Dash] save_stat_log on shutdown: " << e.what();
            }
        }
        ioc.stop();
    });

    try {
        ioc.run();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }

    if (web_server) web_server->stop();
    enhanced_node->shutdown();
    // Safety net: flush buffers again in case we exited without hitting
    // the signal handler (uncaught exception from ioc.run()).
    try { node.shutdown_storage(); } catch (...) {}

    std::cout << std::endl;
    std::cout << "[RESULT] Final state:" << std::endl;
    std::cout << "  Shares: " << node.tracker().chain.size() << std::endl;
    std::cout << "  Headers: " << header_chain.height() << "/" << header_chain.size() << std::endl;
    std::cout << "  Synced: " << (header_chain.is_synced() ? "YES" : "NO") << std::endl;

    return 0;
}
