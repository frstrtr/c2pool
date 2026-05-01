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
#include <impl/btc/coin/mempool.hpp>
#include <impl/btc/coin/node.hpp>
#include <impl/btc/coin/node_interface.hpp>
#include <impl/btc/coin/transaction.hpp>
#include <impl/btc/config.hpp>
#include <impl/btc/config_pool.hpp>
#include <impl/btc/node.hpp>
#include <impl/btc/share_check.hpp>      // RefHashParams + compute_ref_hash_for_work
#include <impl/btc/share_tracker.hpp>    // get_v35_expected_payouts
#include <impl/btc/stratum/work_source.hpp>

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/stratum_server.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace io = boost::asio;

static void print_usage()
{
    std::cerr <<
        "Usage: c2pool-btc [--testnet | --testnet4] --bitcoind HOST:PORT\n"
        "                  [--p2pool HOST:PORT]\n"
        "\n"
        "  --testnet       BTC testnet3 chain (genesis 000000000933ea01...)\n"
        "  --testnet4      BTC testnet4 chain (genesis 00000000da84f2ba...)\n"
        "                  default: mainnet\n"
        "  --bitcoind H:P  bitcoind P2P endpoint host:port\n"
        "                  e.g. 127.0.0.1:8333  (mainnet)\n"
        "                       127.0.0.1:18333 (testnet3)\n"
        "                       127.0.0.1:48333 (testnet4)\n"
        "  --p2pool H:P    BTC p2pool peer (jtoomim/SPB v35 + protocol 3502)\n"
        "                  e.g. p2p-spb.xyz:9333\n"
        "  --stratum [H:]P stratum TCP listener for miners (B4-stratum)\n"
        "                  e.g. --stratum 9332           (binds 0.0.0.0:9332)\n"
        "                       --stratum 127.0.0.1:9332 (loopback only)\n"
        "                  Omit to disable stratum listener.\n";
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
    core::log::Logger::init();

    bool        testnet       = false;
    bool        testnet4      = false;
    std::string bitcoind_host;
    uint16_t    bitcoind_port = 0;
    std::string p2pool_host;
    uint16_t    p2pool_port   = 0;
    std::string stratum_addr  = "0.0.0.0";  // listen all interfaces by default
    uint16_t    stratum_port  = 0;          // 0 disables stratum; --stratum sets it

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
    const std::string utxo_db_path  = (net_dir / "utxo_view_db").string();

    LOG_INFO << "[BTC] c2pool-btc starting — net="
             << (testnet4 ? "testnet4" : (testnet ? "testnet3" : "mainnet"));
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

    // Forward bitcoind's headers batches into HeaderChain AND chain the
    // getheaders locator forward to drive sync to peer's tip. LTC dispatches
    // this off-thread (scrypt CPU cost); BTC's PoW is SHA256d so inline is
    // fine for testnet (and for mainnet IBD too, given SHA256d is ~us/header).
    coin_node.new_headers.subscribe(
        [&header_chain, &coin_node, header_block_hash, &chain_params,
         pending_mu, pending_submits]
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
    p2p_node->core::Server::listen(btc::PoolConfig::P2P_PORT);
    LOG_INFO << "[BTC] Sharechain peer listening on port "
             << btc::PoolConfig::P2P_PORT
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

    // submit_block_fn: bridges BTCWorkSource → coin_node.submit_block_p2p_raw
    // + adds to B5's pending_submits map for roundtrip tracking. Lambda
    // captures by reference so it reuses the existing B5 infrastructure
    // instead of duplicating it.
    auto stratum_submit_fn = [&coin_node, pending_mu, pending_submits]
        (const std::vector<unsigned char>& block_bytes, uint32_t height)
    {
        // Compute block_hash for pending_submits tracking. BTC block_hash =
        // SHA256d of the first 80 bytes (the header).
        if (block_bytes.size() < 80) {
            LOG_WARNING << "[BTC-STRATUM-BLOCK] block bytes too short ("
                        << block_bytes.size() << " < 80) — not submitting";
            return;
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
        coin_node.submit_block_p2p_raw(block_bytes);
    };

    // Construct the work source. Holds non-owning refs to chain + mempool;
    // both outlive it (stack-scoped main() lifetime).
    auto work_source = std::make_shared<btc::stratum::BTCWorkSource>(
        header_chain, mempool, testnet, std::move(stratum_submit_fn));
    work_source_for_shutdown = work_source;  // expose to signal handler

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

    work_source->set_donation_script(
        btc::PoolConfig::get_donation_script(/*share_version*/ 35));

    work_source->set_pplns_fn(
        [p2p_node_raw](const uint256& best_share_hash,
                       const uint256& block_target,
                       uint64_t subsidy,
                       const std::vector<unsigned char>& donation_script)
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
            try {
                return guard->get_v35_expected_payouts(
                    best_share_hash, block_target, subsidy, donation_script);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-STRATUM] get_v35_expected_payouts threw: " << e.what();
                return {};
            }
        });

    work_source->set_ref_hash_fn(
        [p2p_node_raw](const uint256& prev_share_hash,
                       const std::vector<unsigned char>& scriptSig,
                       const std::vector<unsigned char>& payout_script,
                       uint64_t subsidy, uint32_t bits, uint32_t timestamp)
        -> std::pair<uint256, uint64_t>
        {
            // RefHashParams for v35 with tracker-walked share-chain fields.
            // Mirrors LTC's c2pool_refactored.cpp:4460-4520 logic, simplified
            // for v35 (no merged_addresses / merged_payout_hash / desired
            // _target vardiff dance — we use the bits passed in by the work
            // source which derives them from the GBT template).
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
            p.bits                = bits;
            p.timestamp           = timestamp;
            p.max_bits            = bits;          // v35 stub: same as bits

            // Heuristic v35 pubkey extract: P2PKH is 0x76 0xa9 0x14 + 20B + 0x88 0xac.
            if (payout_script.size() == 25 && payout_script[0] == 0x76 &&
                payout_script[1] == 0xa9 && payout_script[2] == 0x14 &&
                payout_script[23] == 0x88 && payout_script[24] == 0xac)
            {
                std::memcpy(p.pubkey_hash.begin(), payout_script.data() + 3, 20);
                p.pubkey_type = 0;
            }
            // Bech32 P2WSH/P2WPKH: leave pubkey_hash zeroed for now (TODO).

            // ── Walk the share tracker for chain-position fields ──────────
            //
            // This is the critical path from "ref_hash never matches network
            // expectations" → "ref_hash matches IF prev_share is one our peers
            // also have". The 4 fields below (timestamp clip, absheight,
            // abswork, far_share_hash) are deterministically derived from the
            // chain — every node walking the same share chain MUST produce
            // the same values, otherwise their ref_hash diverges and shares
            // get rejected as invalid.
            if (p2p_node_raw && !prev_share_hash.IsNull()) {
                auto guard = p2p_node_raw->read_tracker();
                if (guard && guard->chain.contains(prev_share_hash)) {
                    auto& tracker = *guard;

                    // 1. absheight + timestamp clip (must be > prev's timestamp)
                    tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                        p.absheight = prev->m_absheight + 1;
                        if (p.timestamp <= prev->m_timestamp)
                            p.timestamp = prev->m_timestamp + 1;
                    });

                    // 2. abswork = prev_abswork + work-of-this-share-at-bits
                    tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                        auto attempts = chain::target_to_average_attempts(
                            chain::bits_to_target(p.bits));
                        p.abswork = prev->m_abswork + uint128(attempts.GetLow64());
                    });

                    // 3. far_share_hash = 99th ancestor of prev_share (matches
                    //    p2pool data.py get_nth_parent_hash(prev, 99))
                    auto [prev_height, _last] = tracker.chain.get_height_and_last(prev_share_hash);
                    if (prev_height >= 99) {
                        try {
                            p.far_share_hash = tracker.chain.get_nth_parent_key(prev_share_hash, 99);
                        } catch (const std::exception&) {
                            p.far_share_hash = uint256::ZERO;
                        }
                    } else {
                        // Chain too short (cold-start, fragmented) — no 99th ancestor.
                        // Matches LTC reference at c2pool_refactored.cpp:4498.
                        p.far_share_hash = uint256::ZERO;
                    }
                } else {
                    // Tracker busy OR prev_share unknown to us — we'll still
                    // compute a ref_hash, but it'll be a "genesis-like" walk
                    // that almost certainly won't match peers. The work source
                    // logs this separately; here we just fall through with
                    // genesis defaults below.
                    p.absheight       = 1;
                    p.abswork         = uint128(chain::target_to_average_attempts(
                        chain::bits_to_target(p.bits)).GetLow64());
                    p.far_share_hash  = uint256::ZERO;
                }
            } else {
                // No prev_share (genesis case) — matches LTC line 4516-4519.
                p.absheight       = 1;
                p.abswork         = uint128(chain::target_to_average_attempts(
                    chain::bits_to_target(p.bits)).GetLow64());
                p.far_share_hash  = uint256::ZERO;
            }

            try {
                return btc::compute_ref_hash_for_work(p);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-STRATUM] compute_ref_hash_for_work threw: " << e.what();
                return { uint256::ZERO, 0 };
            }
        });

    LOG_INFO << "[BTC-STRATUM] PPLNS + ref_hash callbacks wired"
             << " (donation_script=" << btc::PoolConfig::get_donation_script(35).size()
             << "B P2PK; ref_hash walks share tracker for absheight/abswork/far_share)";

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
                     << " (work source: BTCWorkSource, share v35, MVP — c2pool"
                     << " sharechain payouts deferred)";
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

    LOG_INFO << "[BTC] io_context running. Ctrl-C to stop.";
    ioc.run();

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
    stratum_server_for_shutdown.reset();
    work_source_for_shutdown.reset();
    p2p_node.reset();
    LOG_INFO << "[BTC] Shutdown complete.";
    return 0;
}
