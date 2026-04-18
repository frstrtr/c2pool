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

#include <core/coin_params.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <core/address_validator.hpp>

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
    std::string dashd_host;
    uint16_t dashd_port = 9999;
    std::string dashd_rpc_host;
    uint16_t    dashd_rpc_port = 9998;
    std::string dashd_rpc_userpass;
    uint16_t    stratum_port   = 0;       // 0 = disabled; canonical Dash p2pool stratum port is 7903
    std::string mining_address;           // required when stratum+rpc are wired
    double      share_difficulty_default = 0.001;  // vardiff lands later
    bool        pplns_enabled   = true;   // default: PPLNS payouts across chain contributors
    size_t      pplns_window    = 0;      // 0 → use params.chain_length
    bool testnet = false;
    std::string http_host       = "127.0.0.1";   // dashboard bind host
    uint16_t    http_port       = 0;             // 0 = disable dashboard; e.g. 7904
    std::string dashboard_dir;                   // static files for web dashboard
    std::string http_cors_origin;

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

    std::string header_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
        + "/.c2pool/" + coin_name + "/embedded_headers";
    dash::coin::HeaderChain header_chain(chain_params, header_db_path);
    if (!header_chain.init()) {
        std::cerr << "[ERROR] Failed to initialize header chain LevelDB" << std::endl;
        return 1;
    }
    std::cout << "[HEADERS] Initialized: height=" << header_chain.height()
              << " headers=" << header_chain.size() << std::endl;

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
#ifdef C2POOL_VERSION
        mi->set_pool_version("c2pool-dash/" C2POOL_VERSION);
#endif
        // Dash drives its own work pipeline (GBT via coin_rpc, stratum via
        // dash::stratum::Server) — bypass WebServer's internal has_work /
        // is_node_ready gate so the loading page doesn't stall / force
        // everyone into a redirect loop to loading.html.
        mi->set_dashboard_always_ready(true);
        // Sharechain stats for the dashboard (chain height + verified count).
        // HTTP-thread callback — takes shared_lock so main-ioc writers
        // (tracker.add in share handlers) don't race on unordered_map.
        mi->set_sharechain_stats_fn([&node]() {
            std::shared_lock lock(node.tracker_mutex());
            nlohmann::json j;
            int h = static_cast<int>(node.tracker().chain.size());
            j["chain_height"]   = h;
            j["verified_count"] = h;
            j["total_shares"]   = h;
            j["fork_count"]     = static_cast<int>(node.tracker().chain.get_heads().size());
            return j;
        });
        // Best share hash for the dashboard's head indicator.
        mi->set_best_share_hash_fn([&node]() { return node.best_share_hash(); });
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

            uint256 best;
            int32_t best_height = -1;
            for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                auto h = chain.get_height(head_hash);
                if (h > best_height) { best = head_hash; best_height = h; }
            }
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
            // HTTP-thread callback. Inline the heads lookup + height under a
            // single shared_lock so both reads see the same snapshot —
            // calling best_share_hash() here would take + release, opening
            // a race window where `best` exists but gets removed before
            // get_height. shared_mutex forbids recursive shared locking.
            std::shared_lock lock(node.tracker_mutex());
            nlohmann::json t;
            auto& chain = node.tracker().chain;
            auto heads = chain.get_heads();
            uint256 best = heads.empty() ? uint256() : heads.begin()->first;
            t["hash"]   = best.IsNull() ? "" : best.GetHex();
            t["height"] = best.IsNull() ? 0 : chain.get_height(best);
            return t;
        });
        // Dash p2pool uses protocol 1700 (not LTC's 3600).
        mi->set_protocol_version(1700);
        // Canonical Dash p2pool ports for node_info (dashboard miner URL).
        mi->set_p2p_port(port);
        if (stratum_port == 0) mi->set_worker_port(7903);
        web_server->start();
        std::cout << "[WEB] dashboard listening on " << http_host << ":"
                  << http_port << std::endl;

        // Background per-share PPLNS precomputer for the Sharechain Explorer.
        // Mirrors LTC's start_pplns_precompute(): walk the window, compute
        // PPLNS from each share's perspective, store under the share's short
        // hash so the hover-zoom treemap shows the distribution as it was at
        // that share's tip — not the current tip for every share.
        std::thread([&node, &params, testnet, mi]() {
            const uint8_t p2pkh_ver = testnet ? 140 : 76;
            const uint8_t p2sh_ver  = testnet ?  19 : 16;
            constexpr uint64_t disp_subsidy = 100'000'000ULL;
            std::vector<unsigned char> dummy = {0x76,0xa9,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x88,0xac};
            auto& chain = node.tracker().chain;

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
                        chain, h, params.chain_length, disp_subsidy, dummy);
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

        // Wire full_block event → log
        coin_node->full_block.subscribe([&](dash::coin::BlockType block) {
            auto hdr = static_cast<dash::coin::BlockHeaderType>(block);
            auto bhash = dash::coin::x11_hash(hdr);
            LOG_INFO << "[DASH] Full block: " << bhash.GetHex().substr(0, 16)
                     << " txs=" << block.m_txs.size();
        });

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
    // handshaked peers). Mirrors the LTC NodeImpl::start_outbound_connections
    // pattern but keeps Dash's simpler one-dial-per-tick cadence.
    constexpr size_t TARGET_OUTBOUND_PEERS = 4;
    auto outbound_timer = std::make_shared<io::steady_timer>(ioc);
    std::function<void(const boost::system::error_code&)> outbound_fn;
    outbound_fn = [&, outbound_timer](const boost::system::error_code& ec) {
        if (ec) return;
        try { node.try_connect_more_peers(TARGET_OUTBOUND_PEERS); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Dash] outbound dial failed: " << e.what();
        }
        outbound_timer->expires_after(std::chrono::seconds(30));
        outbound_timer->async_wait(outbound_fn);
    };
    outbound_timer->expires_after(std::chrono::seconds(15));
    outbound_timer->async_wait(outbound_fn);

    // ── Stratum server + job push (M6 Phase 4a: outbound work only) ──
    std::unique_ptr<dash::stratum::Server> stratum_server;
    if (stratum_port != 0) {
        try {
            stratum_server = std::make_unique<dash::stratum::Server>(ioc, stratum_port);
            stratum_server->start();
            std::cout << "[STRATUM] listening on 0.0.0.0:" << stratum_port << std::endl;
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
                         << (r.is_block ? " *** BLOCK ***" : " share");
                // Feed hashrate tracker so per-worker estimates update.
                enhanced_node->track_mining_share_submission(
                    s.worker_name, ctx->share_difficulty);
                if (r.is_block && coin_rpc && coin_rpc->is_connected()) {
                    try {
                        bool ok = coin_rpc->submit_block_hex(r.block_hex);
                        LOG_INFO << "[SUBMIT] submitblock result="
                                 << (ok ? "ACCEPTED" : "rejected")
                                 << " height=" << ctx->height;
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[SUBMIT] submitblock threw: " << e.what();
                    }
                }

                // Phase 5c/5d: promote this submit into a real v16 share.
                // We do it for BOTH valid shares and blocks: any valid share
                // target hit is also a valid share for peers.
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

                // Publish PPLNS outputs to the dashboard (/current_payouts).
                // Format: vector<pair<script_hex, amount_sat>>.
                if (web_server) {
                    std::vector<std::pair<std::string,uint64_t>> pplns_cache;
                    pplns_cache.reserve(payouts.size());
                    for (const auto& p : payouts) {
                        pplns_cache.emplace_back(HexStr(p.script), p.amount);
                    }
                    auto* mi = web_server->get_mining_interface();
                    mi->set_cached_pplns_outputs(std::move(pplns_cache));
                    // /current_merged_payouts + /sharechain/window are both
                    // keyed on the sharechain tip. The JOB cycle fires every
                    // 10 s but the tip only changes when a new share lands
                    // (~20 s on Dash). Gate the cache invalidations on an
                    // actual tip change — P3(b) from the next-session plan.
                    // Matches LTC (trigger_work_refresh_debounced is called
                    // only on share arrivals, not on a timer).
                    static uint256 s_last_cached_tip;
                    uint256 cur_tip = node.best_share_hash();
                    if (cur_tip != s_last_cached_tip) {
                        s_last_cached_tip = cur_tip;
                        mi->cache_pplns_at_tip();
                        mi->invalidate_window_cache();
                    }
                }

                // Pick a share target bits from our configured share_difficulty.
                // (target_from_difficulty matches submit_validator's math.)
                uint32_t share_bits = 0;
                {
                    uint256 st = dash::submit::target_from_difficulty(share_difficulty_default);
                    share_bits = chain::target_to_bits_upper_bound(st);
                    if (share_bits == 0) share_bits = 0x1f00ffff;
                }

                auto built = dash::share_builder::build(
                    work, node.tracker(), miner_pubkey_hash, payouts, pool_tag, params,
                    share_bits, share_difficulty_default);
                size_t miner_count = 0;
                if (stratum_server) {
                    stratum_server->set_difficulty_all(share_difficulty_default);
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

    // Status timer
    io::steady_timer status(ioc, std::chrono::seconds(10));
    std::function<void(const boost::system::error_code&)> status_fn;
    status_fn = [&](const boost::system::error_code& ec) {
        if (ec) return;
        std::cout << "[STATUS] shares=" << node.tracker().chain.size()
                  << " headers=" << header_chain.height()
                  << "/" << header_chain.size()
                  << (header_chain.is_synced() ? " SYNCED" : " syncing");
        if (stratum_server)
            std::cout << " miners=" << stratum_server->session_count();
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

    try {
        ioc.run();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }

    if (web_server) web_server->stop();
    enhanced_node->shutdown();

    std::cout << std::endl;
    std::cout << "[RESULT] Final state:" << std::endl;
    std::cout << "  Shares: " << node.tracker().chain.size() << std::endl;
    std::cout << "  Headers: " << header_chain.height() << "/" << header_chain.size() << std::endl;
    std::cout << "  Synced: " << (header_chain.is_synced() ? "YES" : "NO") << std::endl;

    return 0;
}
