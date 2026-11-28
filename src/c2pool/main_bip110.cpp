// SPDX-License-Identifier: AGPL-3.0-or-later
// c2pool-bip110 — Bitcoin Knots BLAKE2b hard fork (BIP-110) node entry.
//
// M1 = EMBEDDED daemonless SPV header-follower. With --run --coin-p2p-discover
// this binary dials NODE_BLAKE2B (bit 28) fork peers, downloads v2 (164-byte)
// headers, applies the BLAKE2b PoW at/after Blake2bHeight=961640 (SHA256d below,
// shared prefix), and FOLLOWS the BLAKE2b fork chain — rejecting the canonical
// SHA256d chain past the fork despite its higher work — with NO Knots/bitcoind
// daemon, exactly as btc.voidbind runs embedded today. --selftest keeps the
// live BLAKE2b block-hash KAT arm. Mining (164-byte template assembly / the
// Knots-GBT backend) is M2+; this milestone proves fork-following header sync.
//
// PER-COIN ISOLATION: src/impl/bip110 lane + the lane-local BLAKE2b primitive.
// No SHA256d/scrypt/X11 lane is touched.

#include <cassert>   // sharechain dial/accept lifetime arm assertion
#include <impl/bip110/params.hpp>
#include <impl/bip110/pow.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/btc/coin/header_source_step.hpp>   // header-sync driver tick rule (shared with c2pool-btc)
#include <impl/bip110/coin/template_builder.hpp>  // get_block_subsidy (dashboard block-value projection)
#include <impl/bip110/coin/node.hpp>
#include <impl/bip110/coin/node_interface.hpp>
#include <impl/bip110/coin/coin_peer_manager.hpp>
#include <impl/bip110/coin/coin_peer_pool.hpp>     // bip110::coin::CoinPeerPool -- the pool of fork peers (shared with c2pool-btc)
#include <impl/bip110/coin/coin_peer_pool_p2p.hpp> // bip110::coin::make_pool_peer -- one pooled fork-peer connection
#include <impl/bip110/coin/block_body_check.hpp>   // bip110::coin::block_body_matches_header -- pooled bodies vs their header + BIP-110 block rules
#include <impl/bip110/coin/broadcaster.hpp>        // M3 PR-C2 NODE_BLAKE2B fan-out pool
#include <impl/bip110/coin/broadcaster_full.hpp>   // M3 PR-C2 found-block keystone
#include <impl/bip110/coin/inbound_listener.hpp>   // coin-p2p INBOUND accept path (:8333)
#include <impl/bip110/coin/chain_seeds.hpp>
#include <impl/bip110/coin/mempool.hpp>            // M3 daemonless tx-serving
#include <impl/bip110/coin/block_json.hpp>         // explorer getblock verbosity=2 JSON
#include <impl/bip110/coin/explorer_getblock.hpp>  // explorer getblock full-then-partial decision (SSOT for the KAT)
#include <impl/bip110/coin/explorer_retention.hpp> // raw-block retention seam (SSOT for the retention KAT)
#include <impl/bip110/coin/block_confirm.hpp>      // found-block confirm/orphan resolver (B2 telemetry)
#include <impl/bip110/coin/parent_tx_resolver.hpp> // M3 tier-3 input pricing
#include <impl/bip110/coin/utxo_reorg.hpp>         // GAP4 reorg-blindness fix
#include <impl/bip110/coin/utxo_follow.hpp>        // UtxoFollower: the UTXO view on the active chain (keep, catch up, re-anchor)
#include <impl/bip110/stratum/work_source.hpp>

// ── M3 sharechain MINT lane (behind --bip110-sharechain; default OFF) ────────
#include <impl/bip110/pool/node.hpp>               // bip110::pool::Node / Config
#include <impl/bip110/pool/config_pool.hpp>        // PoolConfig SSOT (P2P_PORT 9337, STALE_SHARES)
#include <impl/bip110/pool/share_check.hpp>        // bip110::pool::create_local_share (MINT)
#include <impl/bip110/pool/current_payouts_report.hpp> // /current_payouts dashboard PPLNS split (read-only)
#include <impl/bip110/pool/sharechain_window_report.hpp> // /sharechain/window explorer + V36? column (read-only)
#include <impl/bip110/pool/share_detail_report.hpp>   // /web/share rich detail (DASH parity, read-only)

#include <core/view_block_hashes.hpp>   // core::found_block_hashes_in (block_hashes of a view)
#include <core/coin/utxo_view_db.hpp>              // M3 own-UTXO view (T2 pricing)
#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>
#include <core/found_block_lookups.hpp>
#include <core/address_utils.hpp>
#include <core/netaddress.hpp>
#include <core/stratum_server.hpp>
#include <core/web_server.hpp>              // shared coin-generic dashboard + /node_info
#include <core/analytics_tag.hpp>           // --analytics-id
#include <core/filesystem.hpp>             // config_path() for graph_db stats persistence
#include <core/log.hpp>
#include <core/param_catalog.hpp>           // M0b catalog: C_BIP110 / BIN_BIP110
#include <core/settings_file.hpp>           // M0b resolved-config (give_author / fee L0)
#include <impl/bip110/catalog_defaults.hpp> // M0b L0 compiled defaults (author 0.1%)

#include <boost/asio.hpp>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>
#include <core/sha256_init.hpp>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace io = boost::asio;

namespace {

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

void print_banner(const char* argv0)
{
    std::printf(
        "c2pool-bip110 %s — Bitcoin Knots BLAKE2b hard fork (BIP-110)\n\n"
        "Usage: %s [--version] [--help] [--selftest]\n"
        "       %s --run [--coin-p2p-discover] [--peer IP:PORT ...]\n"
        "                 [--fork-checkpoint] [--http [HOST:]PORT]\n\n"
        "  --run                embedded daemonless SPV header-follower\n"
        "  --coin-p2p-discover  discover NODE_BLAKE2B fork peers (DNS + fixed seeds)\n"
        "  --peer IP:PORT       add an explicit fork peer (repeatable)\n"
        "  --fork-checkpoint    seed the Knots 961640 checkpoint for a fast proof\n"
        "  --http [HOST:]PORT   serve the shared coin-generic dashboard (HTML at\n"
        "                       \"/\", JSON /node_info for health probes)\n"
        "  --analytics-id ID    Google Analytics (GA4) measurement ID, G-XXXXXXXXXX;\n"
        "                       off by default. Every HTML page --http serves then shows\n"
        "                       a consent bar; only after a visitor accepts are GA4\n"
        "                       page views sent, with addresses and query strings\n"
        "                       stripped. You are responsible for your own privacy notice.\n"
        "  --stratum-http[=true|false|auto]  also answer the web API (GET/HEAD,\n"
        "                       read-only) on the stratum port, as python p2pool did\n"
        "                       on its worker port; default false; auto = on when\n"
        "                       --http binds ::, binds 0.0.0.0 and --stratum is\n"
        "                       IPv4, or binds the --stratum address (not loopback)\n"
        "  --stratum-http-budget N  HTTP requests in progress on the stratum port at\n"
        "                       once: at most N and at most max_stratum_connections\n"
        "                       - 1; others are answered 503 (default 16; 0 = every\n"
        "                       HTTP request on the stratum port is answered 503)\n"
        "  --stratum-http-per-ip N  HTTP requests in progress on the stratum port at\n"
        "                       once from one address, one /64 for IPv6: at most N;\n"
        "                       others are answered 503 (default 6; 0 = no limit\n"
        "                       below --stratum-http-budget)\n"
        "  --stratum-tls [HOST:]PORT  a second stratum listener that speaks TLS\n"
        "                       (stratum+ssl://), so miners can verify the pool's\n"
        "                       certificate; PORT alone binds the --stratum host.\n"
        "                       Same sessions, limits and miner list as the plain\n"
        "                       port; TLS 1.2+, no client certificates (default off)\n"
        "  --stratum-tls-cert FILE  PEM certificate chain (leaf first) for\n"
        "                       --stratum-tls; re-read with the key when either\n"
        "                       file changes, and on SIGHUP\n"
        "  --stratum-tls-key FILE  PEM private key for --stratum-tls (no passphrase)\n"
        "  --stratum-tls-rate-per-ip R / --stratum-tls-burst-per-ip N  TLS accepts a\n"
        "                       second from one address (IPv6: one /64) and how many\n"
        "                       back to back (default 5 and 20; 0 = no limit)\n"
        "  --stratum-tls-handshakes N / --stratum-tls-handshakes-per-ip N  TLS\n"
        "                       handshakes in progress at once, in total and from one\n"
        "                       address (default 32 and 8; 0 = no limit)\n"
        "  --node-owner-address ADDR  subsidy fallback / donation payout when a\n"
        "                       miner has no resolvable payout address (base58/bech32)\n"
        "  --bip110-sharechain  ARM the M3 v36 sharechain MINT (DEFAULT OFF): start\n"
        "                       the sharechain node on :9337, mint local shares, and\n"
        "                       dial the fresh federation sharechain. IRREVERSIBLE\n"
        "                       first-outbound — gated by the operator wire-genesis\n"
        "                       params-freeze checkpoint. Absent => M2 header-follower.\n"
        "  --sharechain-addnode HOST:PORT  override the default sharechain bootstrap\n"
        "                       beacon list with explicit :9337 peer(s) (repeatable;\n"
        "                       unified TOML key sharechain.addnodes). Default dials\n"
        "                       our-fork beacon(s) so the sharechain can form.\n\n"
        "PoW: BLAKE2b commitment pipeline (bip110::pow); block hash == PoW hash.\n"
        "Fork: Blake2bHeight=%u; RDTS weight cap=%u WU; network==Bitcoin mainnet\n"
        "      (magic f9beb4d9, default port %u).\n",
        C2POOL_VERSION, argv0, argv0,
        bip110::BLAKE2B_HEIGHT, bip110::RDTS_MAX_BLOCK_WEIGHT, bip110::COIN_P2P_PORT);
}

// Drive the LIVE CoinParams-bound BLAKE2b block-hash path against real block
// 961640 (the first BLAKE2b block; also a Knots checkpoint).
int run_selftest()
{
    core::CoinParams params = bip110::make_coin_params(/*testnet=*/false);

    const std::string header_hex =
        "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000";
    const std::string canonical =
        "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
    const uint32_t nbits = 0x1a008d4f;

    std::vector<unsigned char> header = from_hex(header_hex);
    uint256 got = params.block_hash_func(std::span<const unsigned char>(header.data(), header.size()));
    uint256 pow = params.pow_func(std::span<const unsigned char>(header.data(), header.size()));
    uint256 target = chain::bits_to_target(nbits);

    const bool hash_ok = (got.GetHex() == canonical);
    const bool pow_bound = (pow.GetHex() == canonical);  // pow == block hash for BIP-110
    const bool pow_ok = (pow <= target);

    std::printf("[selftest] coin=%s  pow == block_hash (BLAKE2b) bound\n", params.symbol.c_str());
    std::printf("[selftest]   block 961640 hash   = %s\n", got.GetHex().c_str());
    std::printf("[selftest]   canonical (chain)   = %s  match=%s\n",
                canonical.c_str(), hash_ok ? "yes" : "NO");
    std::printf("[selftest]   pow == block_hash   = %s\n", pow_bound ? "yes" : "NO");
    std::printf("[selftest]   PoW <= target(0x%08x) = %s\n", nbits, pow_ok ? "yes" : "NO");
    std::printf("[selftest]   RDTS weight cap     = %u WU\n", params.block_max_weight);

    if (hash_ok && pow_bound && pow_ok) {
        std::printf("[selftest] PASS — CoinParams BLAKE2b reproduces the real chain block hash.\n");
        return 0;
    }
    std::printf("[selftest] FAIL — BLAKE2b block hash did not match the chain.\n");
    return 1;
}

// ── Minimal duck-typed config for the coin NodeP2P template ──────────────────
// btc::coin::Node<ConfigType> / NodeP2P<ConfigType> only read
// config->coin()->m_p2p.prefix (the network magic used to frame messages). The
// pool-side btc::Config carries a lot more (sharechain identity etc.) that a
// header-only follower never uses, so we hand a lean composite here rather than
// clone the pool-side config surface into the lane.
struct MiniCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
};
struct MiniConfig {
    MiniCoinCfg m_coin;
    bool m_testnet{false};
    MiniCoinCfg* coin() { return &m_coin; }
};

// The old bespoke StatusHttp JSON-on-every-path endpoint has been replaced by
// the shared coin-generic core::WebServer dashboard (see run_embedded --http):
// the WebServer serves the version-coupled web-static frontend at "/" and keeps
// the /node_info JSON (routed BEFORE static files in http_session.cpp). The
// header_height/blake2b_height/on_blake2b_chain fields the old endpoint carried
// now ride /api/node_topology (node_topology_fn) + /broadcaster_status.

int run_embedded(bool coin_p2p_discover,
                 const std::vector<NetService>& explicit_peers,
                 bool fork_checkpoint,
                 const std::string& http_host, uint16_t http_port,
                 const std::string& stratum_addr, uint16_t stratum_port,
                 const std::string& donation_address,
                 double give_author_pct,
                 double node_owner_fee_pct,
                 bool serve_mempool_txs,
                 bool sharechain_enabled,
                 const std::vector<std::pair<std::string, uint16_t>>& sharechain_addnodes,
                 bool explorer_enabled = true,
                 const std::string& coin_externalip = std::string())
{
    core::log::Logger::init();

    LOG_INFO << "[EMB-BIP110] c2pool-bip110 " << C2POOL_VERSION
             << " starting — EMBEDDED daemonless BLAKE2b fork follower (mainnet)";

    auto chain_params = bip110::coin::BTCChainParams::mainnet();
    if (fork_checkpoint) {
        // Seed the Knots consensus checkpoint at the first BLAKE2b block so the
        // node follows the fork from 961640 without a full genesis IBD. All
        // pre-fork (SHA256d) history is implicitly trusted; the fork gate then
        // requires every subsequent header to be v2 BLAKE2b.
        bip110::coin::BTCChainParams::Checkpoint cp;
        cp.height = bip110::BLAKE2B_HEIGHT;  // 961640
        cp.hash.SetHex("0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb");
        chain_params.fast_start_checkpoint = cp;
        LOG_INFO << "[EMB-BIP110] fork checkpoint seeded: height=" << cp.height
                 << " hash=" << cp.hash.GetHex();
    }

    const std::string db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
                              + "/.c2pool/bip110/embedded_headers";
    bip110::coin::HeaderChain header_chain(chain_params, db_path);
    if (!header_chain.init())
        LOG_WARNING << "[EMB-BIP110] HeaderChain init failed — running in-memory only";
    LOG_INFO << "[EMB-BIP110] HeaderChain ready: height=" << header_chain.height()
             << " genesis=" << chain_params.genesis_hash.GetHex().substr(0, 16)
             << " blake2b_height=" << chain_params.blake2b_height;

    io::io_context ioc;

    MiniConfig config;
    config.coin()->m_p2p.prefix = { std::byte{0xf9}, std::byte{0xbe}, std::byte{0xb4}, std::byte{0xd9} };

    bip110::coin::Node<MiniConfig> coin_node(&ioc, &config);

    // The NODE_BLAKE2B peer manager (--coin-p2p-discover; built below). Declared
    // before the fan-out broadcaster and the coin peer pool, whose hooks hold a
    // raw pointer to it, so both are destroyed first.
    std::unique_ptr<bip110::coin::BtcCoinPeerManager> coin_peer_mgr;

    // ── M3 PR-C2 addrman-backed FOUND-BLOCK fan-out (behind --bip110-sharechain;
    // DEFAULT OFF) ───────────────────────────────────────────────────────────
    // Declared at run_embedded scope so they outlive work_source / the stratum
    // server / ioc.run(). Constructed ONLY on the flag-ON path, AFTER coin_peer_mgr
    // exists (the NODE_BLAKE2B addrman that feeds the fan-out slot set). With the
    // flag OFF both stay null and stratum_submit_fn calls
    // coin_node.submit_block_with_fallback directly — byte-identical to M2.
    // With the coin peer pool the fan-out slots report into fanout_sink, which
    // nothing reads (they relay won blocks and crawl the fork mesh only).
    bip110::interfaces::Node fanout_sink;
    std::unique_ptr<bip110::coin::Bip110Broadcaster<MiniConfig>>     coin_broadcaster;
    std::unique_ptr<bip110::coin::Bip110BroadcasterFull<MiniConfig>> coin_broadcaster_full;

    // ── M3 DAEMONLESS MEMPOOL SERVING: own UTXO view + mempool + T3 resolver ──
    // BIP-110 has NO coin daemon, so there is no getblocktemplate to hand us txs
    // or fees. We do the daemon's job ourselves: ingest the fork mempool over
    // P2P, maintain a post-anchor UTXO view for input pricing (T2), fetch missing
    // parents over P2P (T3), and select txs Bitcoin-BlockAssembler-style. All
    // fail-closed: an unprice-able tx is EXCLUDED, never guessed.
    const std::string utxo_db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
                                   + "/.c2pool/bip110/utxo_view_db";
    core::coin::UTXOViewDB utxo_db(utxo_db_path);
    if (!utxo_db.open())
        LOG_WARNING << "[EMB-BIP110] UTXOViewDB open failed — running without UTXO persistence";
    core::coin::UTXOViewCache utxo_cache(&utxo_db);
    bip110::coin::Mempool mempool;
    mempool.set_utxo(&utxo_cache);
    mempool.set_tip_height(header_chain.height());
    // BIP-110 keeps txid over the NON-witness serialization (segwit-invariant).
    auto bip110_txid = [](const bip110::coin::MutableTransaction& tx) {
        auto packed = pack(bip110::coin::TX_NO_WITNESS(tx));
        return Hash(packed.get_span());
    };
    constexpr uint32_t BIP110_KEEP_DEPTH = core::coin::LTC_MIN_BLOCKS_TO_KEEP;

    // ── Coin peer pool: the fork-network connections ─────────────────────────
    // Up to kCoinPoolTargetPeers outbound NODE_BLAKE2B peers (bip110::coin::
    // CoinPeerPool, the pool c2pool-btc runs standalone), built below once the
    // peer sources exist. Headers, announcements, transactions and checked block
    // bodies from any pooled peer feed coin_node's events; a won block goes to
    // every pooled peer. coin_node itself then holds no connection. Declared
    // here, after the UTXO view and the mempool its hooks use (so it is destroyed
    // first) and before the won-block relay below that reaches it. Null when no
    // peer source is configured (neither --peer nor --coin-p2p-discover).
    std::unique_ptr<bip110::coin::CoinPeerPool> coin_pool;
    // The primary won-block relay: every pooled fork peer with a completed
    // handshake, then coin_node's own arm (P2P relay + optional submitblock RPC
    // backup). True iff the block reached at least one of them.
    auto primary_relay = [&coin_node, &coin_pool](const std::vector<unsigned char>& block_bytes) -> bool {
        bool pool_relayed = false;
        if (coin_pool) {
            try {
                pool_relayed = coin_pool->broadcast_block(block_bytes) > 0;
            } catch (const std::exception& e) {
                LOG_WARNING << "[EMB-BIP110] pooled fork peer relay failed: " << e.what();
            }
        }
        const bool reached = coin_node.submit_block_with_fallback(block_bytes);
        return reached || pool_relayed;
    };

    // Explorer raw-block retention window (heights kept for /api/explorer
    // getblock body lookups). 288 ≈ 2 days at 10-min blocks — matches the LTC
    // lane default (main_ltc.cpp explorer_depth_ltc). Retention is flag-gated on
    // explorer_enabled: storage only, never a consensus/reward path.
    constexpr uint32_t EXPLORER_DEPTH = 288;

    // ── M2 MINING: stratum server + BLAKE2b Sv1 work source (miner-facing) ──
    // submit_block_fn relays a won 164-byte v2 block to the FORK peers over the
    // coin P2P (submit_block_with_fallback: P2P relay + optional submitblock RPC
    // backup). The work source serves coinbase-only jobs, validates shares with
    // an independent BLAKE2b recompute, and dispatches block-target hits here.
    // ── #995-shape found-block PRODUCER slot (dashboard telemetry) ──────────
    // Fired from stratum_submit_fn right after a won block is dispatched, this
    // records the block into the MiningInterface for the /recent_blocks card +
    // the confirm/orphan verdict lane (set_block_verify_fn below). Declared here
    // so the stratum submit path can fire it; BOUND later inside the web-server
    // wiring where the MiningInterface (mi) is live. Empty until bound and when
    // the dashboard is off → a no-op. TELEMETRY ONLY: strictly downstream of the
    // block submit, never gates broadcast/mint/target/payout, zero consensus.
    auto found_block_report =
        std::make_shared<std::function<
            void(const std::vector<unsigned char>&, uint32_t)>>();

    auto stratum_submit_fn =
        [primary_relay, &coin_broadcaster_full, found_block_report](
            const std::vector<unsigned char>& block_bytes, uint32_t height) -> bool {
            LOG_INFO << "[EMB-BIP110] submitting won block height=" << height
                     << " bytes=" << block_bytes.size();
            // FLAG-ON: route through the found-block keystone — ARM A fans the
            // block to every live NODE_BLAKE2B fan-out peer, ARM B is the
            // primary relay (the coin peer pool, then coin_node's
            // submit_block_with_fallback: primary relay + optional RPC).
            // FLAG-OFF: coin_broadcaster_full is null -> the primary relay alone.
            const bool reached = coin_broadcaster_full
                ? coin_broadcaster_full->on_block_found(block_bytes).reached_network()
                : primary_relay(block_bytes);
            // TELEMETRY (dashboard only, downstream of submit): record the won
            // block so the found-blocks card + confirm/orphan lane observe it.
            // The block met block target (independent BLAKE2b recompute upstream)
            // → it is a real found block; the verdict poller resolves whether it
            // actually buried on-chain. Never gates the submit above.
            if (found_block_report && *found_block_report)
                (*found_block_report)(block_bytes, height);
            return reached;
        };
    auto work_source = std::make_shared<bip110::stratum::Bip110WorkSource>(
        header_chain, /*is_testnet=*/false, std::move(stratum_submit_fn));

    // Wire the embedded mempool into the work source. serve gated on the header
    // chain being caught up (never serve mid-sync) AND the fork gate — each tx is
    // still independently fail-closed on pricing, so this only avoids churning
    // templates before we are following the fork tip. The work source READS the
    // mempool only.
    // GAP4 — serve gate also requires the UTXO view to be CONSISTENT with the
    // active chain. On a reorg the tip-changed handler flips this false while it
    // rolls the view back to the fork (and permanently on an unrecoverable
    // rollback), so templates are NEVER built from a diverged ledger — the
    // work source falls back to coinbase-only (never a wrong fee).
    // The serve gate also requires the view to be AT the header tip
    // (UtxoFollower::fresh, kServeMaxLag 0): until the tip block's body is
    // connected the mempool still holds the transactions it confirmed, and a
    // view left behind (bodies not received, the view not yet anchored) prices
    // nothing it should. The follower is built with the UTXO connect below.
    std::atomic<bool> utxo_consistent{true};
    std::shared_ptr<bip110::coin::UtxoFollower> utxo_follower;
    work_source->set_mempool(&mempool, serve_mempool_txs,
        [&header_chain, &utxo_consistent, &utxo_follower]() {
            return utxo_consistent.load(std::memory_order_relaxed)
                && header_chain.height() >= header_chain.params().blake2b_height
                && utxo_follower && utxo_follower->fresh();
        });
    LOG_INFO << "[EMB-BIP110] mempool tx-serving "
             << (serve_mempool_txs ? "ENABLED" : "DISABLED (coinbase-only)")
             << " — daemonless ingest+price+select+xcheck";

    // #961 cross-lane (B4): publish BIP-110's REGISTRY-SOURCED own-coin payout-
    // address acceptance into the StratumConfig the core StratumServer reads, so
    // the SAME decide_payout_address() door-reject (mining.authorize) + no-empty-
    // payout guard (send_notify_work) LTC runs also apply on this lane — a foreign-
    // unconfigured payout is rejected at the door instead of redirected. The
    // Knots-GBT parent runs mainnet (is_testnet=false above); own-coin addresses
    // stay accepted byte-identically.
    {
        const auto acc = bip110::address_acceptance(
            bip110::pool::PoolConfig::is_testnet, /*regtest=*/false);
        work_source->set_payout_acceptance(acc.p2pkh_versions, acc.p2sh_versions,
                                           acc.bech32_hrps);
    }

    // ── DEFECT 2: node-owner / donation address (OPERATOR-PROVIDED, never hard-
    // coded). When a miner authorizes with a resolvable payout address it is paid
    // the subsidy; if the miner address fails to resolve, the subsidy falls back
    // to this donation script. If NEITHER resolves the work source REFUSES to
    // serve (burn guard) rather than emit all-zero-value work. Accepts any
    // Bitcoin base58/bech32 address (address_to_script). ──
    if (!donation_address.empty()) {
        auto donation_script = core::address_to_script(donation_address);
        if (donation_script.empty()) {
            LOG_ERROR << "[EMB-BIP110] --node-owner-address '" << donation_address
                      << "' did not decode to a scriptPubKey — REFUSING to start "
                         "(would fall through to the burn guard). Fix the address.";
            return 2;
        }
        work_source->set_donation_script(donation_script);
        LOG_INFO << "[EMB-BIP110] node-owner/donation address set: " << donation_address
                 << " (script " << donation_script.size() << " B) — subsidy fallback armed";
    } else {
        LOG_WARNING << "[EMB-BIP110] no --node-owner-address configured: only miners "
                       "with a resolvable payout address get work; unresolved payout + "
                       "no donation => work is REFUSED (burn guard), never zero-value.";
    }

    // ── REWARD SPLIT: author/dev donation (give_author_pct, default 0.1%) +
    // node-owner fee (node_owner_fee_pct, default 0). Percent -> parts-per-million
    // (integer): 0.1% = 1000 ppm, 1% = 10000 ppm. llround keeps the ppm exact for
    // typical human inputs; the split itself is integer FLOOR division and the
    // miner absorbs every remainder. The node-owner address == the donation
    // address here (single key), so a non-zero fee CONSOLIDATES with the donation
    // into ONE coinbase output (see work_source.cpp build_connection_coinbase). ──
    const uint64_t give_author_ppm = static_cast<uint64_t>(
        std::llround(std::max(0.0, give_author_pct) * 10000.0));
    const uint64_t node_owner_fee_ppm = static_cast<uint64_t>(
        std::llround(std::max(0.0, node_owner_fee_pct) * 10000.0));
    work_source->set_give_author_ppm(give_author_ppm);
    work_source->set_node_owner_fee_ppm(node_owner_fee_ppm);
    LOG_INFO << "[EMB-BIP110] reward split: give-author=" << give_author_pct << "% ("
             << give_author_ppm << " ppm) node-owner-fee=" << node_owner_fee_pct << "% ("
             << node_owner_fee_ppm << " ppm) — integer floor split, miner absorbs remainder"
             << (node_owner_fee_ppm > 0 ? "; owner+donation consolidated (single key)" : "");

    // ── M3 SHARECHAIN MINT (behind --bip110-sharechain; DEFAULT OFF) ─────────
    // With the flag OFF this block is skipped ENTIRELY: no bip110::pool::Node is
    // constructed, no :9337 listen, set_create_share_fn is never called (so
    // work_source's create_share_fn_ stays null and mining_submit's share arm is
    // a no-op — byte-identical to the M2 header-follower), and the IRREVERSIBLE
    // first-outbound to the fresh federation sharechain never runs. The C++ v36
    // wiring precedent is main_btc.cpp (node ctor + set_create_share_fn +
    // start_outbound_connections). Lifetime: sharechain_cfg + sharechain_node are
    // declared at run_embedded scope so they outlive work_source, the stratum
    // server, and ioc.run() (the lambda captures the raw node pointer; the
    // io_context drives its peers). WIRE-GENESIS FREEZE: params live in
    // params.hpp / config_pool.hpp (9337 / 8640 / SPREAD 3 / proto 3600 /
    // donation u16 66) — DO NOT change them here and DO NOT default the flag ON;
    // the operator performs the explicit params-freeze checkpoint before enabling
    // it in production.
    std::unique_ptr<bip110::pool::Config> sharechain_cfg;
    // ROBUST dial-teardown UAF fix (successor to e527abfe): hold the sharechain
    // node as a shared_ptr and register its OWNING control block with the node's
    // core::Client + core::Server bases via set_lifetime() below. core::Client/
    // Server pin the node with a STRONG ref for each async resolve/connect/accept,
    // so make_socket()'s dynamic_cast can never run on a freed node. Critically
    // this does NOT rely on node->weak_from_this(): the pool Node is a virtual-
    // inheritance diamond (public virtual NodeImpl → … → core::INetwork) whose
    // enable_shared_from_this base is not enrolled through the owning control
    // block, so weak_from_this() returns EMPTY — exactly the silent no-op that
    // made the e527abfe guard inert. Flag-ON exercises this hard (beacon :9337
    // self-dial + coin-P2P + ioc.stop() mid-resolve). All .get() sites unchanged.
    std::shared_ptr<bip110::pool::Node>   sharechain_node;
    if (sharechain_enabled) {
        sharechain_cfg  = std::make_unique<bip110::pool::Config>();          // (1) lifetime >= node

        // SHARECHAIN BOOTSTRAP SEED — populate m_bootstrap_addrs BEFORE the Node
        // ctor (node.hpp:237 m_addrs.load(config->pool()->m_bootstrap_addrs)), so
        // the node dials the beacon on start_outbound_connections. Mirrors
        // main_btc.cpp:1536-1618. Precedence: explicit --sharechain-addnode >
        // regtest > OurBeacon (default seed list). This whole block is INSIDE the
        // flag-ON guard: flag-OFF constructs no sharechain node and never dials.
        using PC = bip110::pool::PoolConfig;
        const auto sc_mode = PC::select_bootstrap_mode(
            /*has_explicit_peers=*/!sharechain_addnodes.empty(), /*regtest=*/false);
        auto& sc_addrs = sharechain_cfg->pool()->m_bootstrap_addrs;
        switch (sc_mode) {
        case PC::BootstrapMode::ExplicitPeers:
            for (const auto& [h, p] : sharechain_addnodes) sc_addrs.emplace_back(h, p);
            LOG_INFO << "[EMB-BIP110] sharechain bootstrap: " << sc_addrs.size()
                     << " explicit --sharechain-addnode peer(s) (OurBeacon suppressed)";
            break;
        case PC::BootstrapMode::OurBeacon:
            for (const auto& host : PC::default_bootstrap_hosts()) {
                std::string a = host.find(':') == std::string::npos
                    ? host + ":" + std::to_string(PC::P2P_PORT) : host;   // btc:1609 guard
                sc_addrs.emplace_back(a);
            }
            LOG_INFO << "[EMB-BIP110] sharechain bootstrap: OurBeacon — " << sc_addrs.size()
                     << " default seed(s) (prefix=" << PC::prefix_hex() << " :9337)";
            break;
        case PC::BootstrapMode::RegtestIsolated:
            LOG_INFO << "[EMB-BIP110] sharechain bootstrap: regtest — 0 seeds (isolated)";
            break;
        }

        sharechain_node = std::make_shared<bip110::pool::Node>(&ioc, sharechain_cfg.get());
        auto* node_raw  = sharechain_node.get();

        // ROBUST dial-teardown UAF fix (successor to e527abfe): register the
        // OWNING control block with the pool node's core::Client + core::Server
        // bases so their async resolve/connect/accept handlers pin the node with a
        // strong ref for the op's duration. This does NOT depend on the
        // enable_shared_from_this diamond enrollment (public virtual NodeImpl → …
        // → core::INetwork), which silently yields an empty weak_from_this() —
        // exactly why e527abfe's guard no-opped. Must precede listen()/outbound.
        sharechain_node->set_lifetime(sharechain_node);
        assert(sharechain_node->lifetime_armed() &&
               "sharechain node dial/accept lifetime failed to arm");

        node_raw->set_target_outbound_peers(
            sharechain_addnodes.empty() ? 4 : std::max<size_t>(1, sharechain_addnodes.size()));
        node_raw->set_seed_escalation_enabled(false);                        // (4) federation/fresh — fail-safe
        node_raw->core::Server::listen(bip110::pool::PoolConfig::P2P_PORT);   // 9337

        // M3 PR-C2 (job 2 — WON-SHARE robustness): wire the p2pool
        // best_share_var.changed.watch(broadcast_share) RE-SPREAD trigger
        // (p2pool/node.py:150). The per-peer fan-out already exists
        // (broadcast_share -> broadcast_and_mark over the WHOLE m_peers set);
        // the missing robustness was re-spreading when think() adopts a new best
        // (a downloaded/re-evaluated tip), not just on the local mint. Fires on
        // the IO thread with NO tracker lock held (node.cpp ASYNC-THINK IO-phase),
        // and broadcast_share takes its OWN shared try-lock, so this respects the
        // lock-drop-before-fan-out invariant. Set ONLY on the flag-ON path.
        node_raw->set_on_best_share_changed([node_raw, ws = work_source.get()]() {
            if (!node_raw) return;
            node_raw->broadcast_share(node_raw->best_share_hash());
            ws->bump_work_generation();   // refresh miner jobs: new prev_share_hash (LTC-shape main_ltc.cpp:2943-2947)
        });

        // (2) MINT on the stratum submit path. Mirrors main_btc.cpp:2215-2411,
        // adapted to bip110 (164B v2 header; BLAKE2b compute_share_hash inside
        // create_local_share). Drops the EXCLUSIVE tracker lock BEFORE broadcast.
        work_source->set_create_share_fn(
            [node_raw](const std::vector<unsigned char>& full_coinbase,
                       const std::vector<unsigned char>& header_164b,
                       const core::stratum::JobSnapshot&  job,
                       const std::vector<unsigned char>& payout_script) -> uint256
            {
                if (!node_raw || header_164b.size() != 164) return uint256::ZERO;

                // Parse the 164B v2 header into a full coin::BlockHeaderType.
                bip110::coin::BlockHeaderType full_hdr;
                try {
                    PackStream ps(std::vector<std::byte>(
                        reinterpret_cast<const std::byte*>(header_164b.data()),
                        reinterpret_cast<const std::byte*>(header_164b.data()) + 164));
                    ps >> full_hdr;
                } catch (const std::exception& e) {
                    LOG_WARNING << "[BIP110-CREATE-SHARE] header parse failed: " << e.what();
                    return uint256::ZERO;
                }

                // Coinbase scriptSig (share.m_coinbase is the scriptSig, 2..100B).
                BaseScript coinbase_bs(
                    bip110::stratum::extract_coinbase_scriptsig(full_coinbase));

                // Stratum merkle branches: hex of LE-internal bytes (ParseHex+memcpy,
                // NOT SetHex — SetHex would reverse and break the miner's root).
                std::vector<uint256> merkle_branches;
                merkle_branches.reserve(job.merkle_branches.size());
                for (const auto& bhex : job.merkle_branches) {
                    uint256 b;
                    auto bb = ParseHex(bhex);
                    if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
                    merkle_branches.push_back(b);
                }

                // EXCLUSIVE tracker lock (try, non-blocking) — decline if the
                // compute thread is mid-think, exactly like btc.
                std::unique_lock<std::shared_mutex> lk(
                    node_raw->tracker_mutex(), std::try_to_lock);
                if (!lk.owns_lock()) {
                    LOG_INFO << "[BIP110-CREATE-SHARE] tracker busy — share deferred";
                    return uint256::ZERO;
                }

                // (5) Caller-side mint-freshness gate — PoolConfig::STALE_SHARES
                // (=30). Refuse to extend a stale verified tip (a private low-diff
                // fork peers would reject). Genesis / unknown prev is exempt so the
                // first shares can still form. BTC C1 precedent (main_btc.cpp:2287).
                {
                    auto& tk = node_raw->tracker();
                    int32_t raw_h = -1;
                    for (const auto& [hh, th] : tk.chain.get_heads()) {
                        (void)th;
                        auto h = tk.chain.get_height(hh);
                        if (h > raw_h) raw_h = h;
                    }
                    int32_t v_h = (!job.prev_share_hash.IsNull()
                                   && tk.chain.contains(job.prev_share_hash))
                        ? tk.chain.get_height(job.prev_share_hash) : -1;
                    if (raw_h >= 0 && v_h >= 0 &&
                        (raw_h - v_h) > (int32_t)bip110::pool::PoolConfig::STALE_SHARES) {
                        static int stale_log = 0;
                        if (stale_log++ % 20 == 0)
                            LOG_WARNING << "[BIP110-CREATE-SHARE] refused: verified tip stale"
                                        << " (v_h=" << v_h << " raw_h=" << raw_h
                                        << " gap=" << (raw_h - v_h) << " > "
                                        << bip110::pool::PoolConfig::STALE_SHARES << ")";
                        return uint256::ZERO;
                    }
                }

                uint256 share_hash;
                try {
                    // PR-C: build_connection_coinbase now FREEZES the sharechain ref
                    // fields into JobSnapshot.frozen_ref (populated by ref_hash_fn)
                    // and stamps job.prev_share_hash from best_share_hash_fn, so
                    // has_frozen=TRUE — create_local_share reproduces the EXACT
                    // ref_hash the coinbase committed (extend-off-real-tip), instead
                    // of re-deriving from the tracker and taking the genesis branch.
                    // The abswork %2^64 wrap (NIT-2) is applied inside create_local_share.
                    share_hash = bip110::pool::create_local_share(
                        node_raw->tracker(),
                        full_hdr,
                        coinbase_bs,
                        /* subsidy */               job.subsidy,
                        /* prev_share */            job.prev_share_hash,
                        merkle_branches,
                        payout_script,
                        /* donation */              66,   // WIRE-GENESIS FREEZE (0.1%)
                        /* merged_addrs */          {},   // no merged mining on bip110
                        /* stale_info */            bip110::pool::StaleInfo::none,
                        /* segwit_active */         job.segwit_active,
                        /* witness_commitment */    job.witness_commitment_hex,
                        /* message_data */          {},
                        /* actual_coinbase_bytes */ full_coinbase,
                        /* witness_root */          job.witness_root,
                        /* override_max_bits */     job.frozen_ref.max_bits,
                        /* override_bits */         job.frozen_ref.bits,
                        /* frozen_absheight */      job.frozen_ref.absheight,
                        /* frozen_abswork */        job.frozen_ref.abswork,
                        /* frozen_far_share_hash */ job.frozen_ref.far_share_hash,
                        /* frozen_timestamp */      job.frozen_ref.timestamp,
                        /* frozen_merged_payout */  job.frozen_ref.merged_payout_hash,
                        /* has_frozen */            true,
                        /* frozen_merkle_branches*/ job.frozen_ref.frozen_merkle_branches,
                        /* frozen_witness_root */   job.frozen_ref.frozen_witness_root,
                        /* frozen_merged_cb_info */ job.frozen_ref.frozen_merged_coinbase_info,
                        /* share_version */         36,
                        /* desired_version */       36);
                } catch (const std::exception& e) {
                    LOG_WARNING << "[BIP110-CREATE-SHARE] threw: " << e.what();
                    return uint256::ZERO;
                }

                // FINDING A/#941 — mark the OWN minted share verified + persist
                // its body, WHILE the exclusive lock is still held (no re-lock,
                // no IO-thread stall). Without this the share only ever landed in
                // the RAW chain: verified_size / has_shares stayed 0 (the operator
                // "no bip110 shares" symptom) and the body was never written to
                // LevelDB (local mint never goes through handle_shares), so it did
                // not survive a restart. Own share is trivially valid — the gentx
                // cross-check above already passed — so we mark it verified
                // DIRECTLY, never through the crash-prone peer attempt_verify path.
                if (!share_hash.IsNull())
                    node_raw->verify_and_persist_local_share_locked(share_hash);

                // Drop the EXCLUSIVE lock BEFORE broadcast (lock-discipline
                // invariant — a held-lock broadcast is the serve-dead/deadlock
                // class; broadcast_share/notify_local_share take their own locks).
                lk.unlock();

                if (!share_hash.IsNull()) {
                    // (3) F3: hand the template tx set to the node BEFORE broadcast
                    // so the share is backable ([{"data": <raw-tx-hex>}, ...]).
                    nlohmann::json tmpl_txs = nlohmann::json::array();
                    if (job.tx_data)
                        for (const auto& tx_hex : *job.tx_data)
                            tmpl_txs.push_back(nlohmann::json::object({{"data", tx_hex}}));
                    node_raw->register_template_txs(share_hash, tmpl_txs);

                    node_raw->broadcast_share(share_hash);
                    node_raw->notify_local_share(share_hash);
                    LOG_INFO << "[BIP110-CREATE-SHARE] OK + broadcast: hash="
                             << share_hash.GetHex().substr(0, 16);
                }
                return share_hash;
            });

        // (6b) M3 PR-C: the coinbase's donation output (p2pool-canonical SECOND-
        // TO-LAST, immediately before the OP_RETURN ref) MUST carry the canonical
        // p2pool donation script — compute_gentx_before_refhash(36) (share_check.hpp)
        // hardcodes it as the hash_link const-ending, so a peer reconstructing the
        // gentx from the share's hash_link re-supplies exactly those bytes. Any
        // other donation script (e.g. the operator node-owner address set at M2
        // startup) makes the peer's reconstruction diverge -> the share is rejected.
        // Mirrors main_btc.cpp:1829 (set_donation_script(PoolConfig::get_donation_
        // script(ver))). Overrides the M2 node-owner donation ONLY on the flag-ON
        // path; the OFF path keeps the operator address (byte-identical M2).
        work_source->set_donation_script(bip110::pool::PoolConfig::get_donation_script(36));
        LOG_INFO << "[EMB-BIP110] M3 PR-C donation output -> canonical p2pool script "
                    "(hash_link const-ending parity; overrides M2 node-owner donation)";

        // (7) M3 PR-C: feed the sharechain tip into JobSnapshot.prev_share_hash.
        // The generic stratum_server seam (stratum_server.cpp:1607) calls this to
        // freeze the tip ONCE per job and stores it on the job (:1807) — the SAME
        // value build_connection_coinbase's ref walk uses. Cold start / empty chain
        // => uint256::ZERO, and the ref walk then takes the genesis branch (correct
        // pre-bootstrap). Mirrors main_btc.cpp:1812-1816.
        work_source->set_best_share_hash_fn(
            [node_raw]() -> uint256 {
                if (!node_raw) return uint256::ZERO;
                return node_raw->best_share_hash();
            });

        // (7b) M3 PR-C F1b: the PPLNS-distributed coinbase producer. Under
        // read_tracker() (non-blocking; refuses the refresh if the compute thread
        // holds the exclusive lock), calls ShareTracker::get_expected_payouts —
        // the SSOT that returns the {scriptPubKey -> amount} map for the ENTIRE
        // decayed PPLNS window, folding the residual into the donation script.
        // build_connection_coinbase emits those outputs (sorted/capped, donation
        // second-to-last) so the minted coinbase == generate_share_transaction
        // byte-for-byte and peers ACCEPT the share. Mirrors main_btc.cpp
        // set_pplns_fn; no AutoRatchet (v36 always), no v35 branch, no merged
        // mining. Empty map (tracker busy) => build_connection_coinbase refuses the
        // sharechain job (fail-closed). Set ONLY inside this flag-ON block, so its
        // presence is the exact --bip110-sharechain predicate.
        work_source->set_pplns_fn(
            [node_raw](const uint256& prev, const uint256& block_target,
                       uint64_t subsidy, const std::vector<unsigned char>& donation_script)
                -> std::map<std::vector<unsigned char>, double> {
                if (!node_raw) return {};
                auto guard = node_raw->read_tracker();
                if (!guard) return {};                 // tracker busy -> refuse this refresh
                try {
                    return guard->get_expected_payouts(prev, block_target, subsidy, donation_script);
                } catch (const std::exception&) {
                    return {};
                }
            });

        // (8) M3 PR-C: the coinbase ref-commitment producer. Walks the share
        // tracker off prev_share_hash for the deterministic chain-position fields
        // (absheight/abswork/far_share_hash) + the share target (compute_share_
        // target), then computes the p2pool ref_hash via the lane SSOT
        // bip110::pool::compute_ref_hash_for_work. build_connection_coinbase embeds
        // the returned ref_hash in the coinbase OP_RETURN and freezes these fields
        // into JobSnapshot.frozen_ref; create_local_share (has_frozen=TRUE) then
        // reproduces the EXACT ref_hash, so the commitment the coinbase carries ==
        // what a peer recomputes off the minted share (mint==verify, peers accept).
        //
        // Near-verbatim port of main_btc.cpp:1869-2125 with the bip110 v36 deltas:
        //   • share_version = desired_version = 36 (no AutoRatchet — v36 always)
        //   • donation u16 = 66 (WIRE-GENESIS freeze, 0.1%; NOT btc's 50)
        //   • no merged mining (merged_addresses / merged_coinbase_info empty)
        //   • segwit_data = a REAL SegwitData with the coinbase-only witness merkle
        //     root ZERO (merkle([0]), python v36 data.py:1090) — NOT the 0xff None-
        //     sentinel. create_local_share stores this same ZERO root for a segwit-
        //     active coinbase-only share, so the ref MUST serialize ZERO too
        //     (has_segwit=true path) or the ref_hash diverges. This is also what the
        //     found-block coinbase witness commitment is computed over, so a won
        //     block passes segwit's witness-commitment consensus check.
        //   • timestamp clipped to prev->m_timestamp+1 BEFORE compute_share_target,
        //     matching create_local_share's ordering (share_check.hpp:2256-2269) so
        //     the (bits,max_bits) the ref commits equal what peers derive.
        work_source->set_ref_hash_fn(
            [node_raw](const uint256& prev_share_hash,
                       const std::vector<unsigned char>& scriptSig,
                       const std::vector<unsigned char>& payout_script,
                       uint64_t subsidy, uint32_t block_bits, uint32_t timestamp)
            -> core::stratum::RefHashResult
            {
                core::stratum::RefHashResult result;
                result.share_version   = 36;
                result.desired_version = 36;
                result.timestamp       = timestamp;   // overwritten below if clipped

                bip110::pool::RefHashParams p;
                p.share_version   = 36;
                p.desired_version = 36;
                p.prev_share      = prev_share_hash;
                p.coinbase_scriptSig = scriptSig;
                p.share_nonce     = 0;                // share commitment nonce (== m_nonce)
                p.subsidy         = subsidy;          // BLOCK subsidy (== job.subsidy)
                p.donation        = 66;               // WIRE-GENESIS freeze (0.1%)
                p.stale_info      = 0;
                p.timestamp       = timestamp;

                // Pubkey extract — MUST mirror create_local_share (share_check.hpp:
                // 2296-2316) so the payout identity the ref commits == the minted
                // share's. P2PKH(25)/P2SH(23)/P2WPKH(22).
                if (payout_script.size() >= 20) {
                    if (payout_script.size() == 25 &&
                        payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
                        payout_script[2] == 0x14 && payout_script[23] == 0x88 &&
                        payout_script[24] == 0xac) {
                        std::memcpy(p.pubkey_hash.data(), payout_script.data() + 3, 20);
                        p.pubkey_type = 0;
                    } else if (payout_script.size() == 23 &&
                               payout_script[0] == 0xa9 && payout_script[1] == 0x14 &&
                               payout_script[22] == 0x87) {
                        std::memcpy(p.pubkey_hash.data(), payout_script.data() + 2, 20);
                        p.pubkey_type = 2;
                    } else if (payout_script.size() == 22 &&
                               payout_script[0] == 0x00 && payout_script[1] == 0x14) {
                        std::memcpy(p.pubkey_hash.data(), payout_script.data() + 2, 20);
                        p.pubkey_type = 1;
                    } else {
                        std::memcpy(p.pubkey_hash.data(), payout_script.data(), 20);
                        p.pubkey_type = 0;
                    }
                }

                // Segwit (coinbase-only): match create_local_share's segwit-active
                // coinbase-only SegwitData — empty txid_merkle_link branch + the REAL
                // witness merkle root ZERO (merkle([0]), python v36 data.py:1090), NOT
                // the 0xff None-sentinel. MUST be the has_segwit=TRUE path so this
                // exact root is serialized into the ref_hash. The found-block coinbase
                // witness commitment is computed over this same ZERO root, so a won
                // block passes segwit's witness-commitment consensus check.
                p.has_segwit  = true;
                {
                    bip110::pool::SegwitData sd = bip110::pool::SegwitDataDefault::get();
                    sd.m_wtxid_merkle_root = uint256::ZERO;   // coinbase-only real root
                    p.segwit_data = sd;
                }

                // Genesis / tracker-busy fallbacks (ref_hash won't match a live tip,
                // but that IS the right answer pre-bootstrap / when prev unknown).
                auto set_genesis = [&] {
                    p.absheight = 1;
                    p.far_share_hash = uint256::ZERO;
                    p.abswork = uint128(chain::target_to_average_attempts(
                        chain::bits_to_target(p.bits)).GetLow64());
                };
                auto set_block_bits_fallback = [&] {
                    p.bits = block_bits; p.max_bits = block_bits;
                    result.bits = block_bits; result.max_bits = block_bits;
                };

                if (node_raw) {
                    auto guard = node_raw->read_tracker();
                    if (guard) {
                        auto& tracker = *guard;
                        // Step 1: clip timestamp + absheight + far_share_hash off prev
                        // (BEFORE compute_share_target — share_check.hpp ordering).
                        if (!prev_share_hash.IsNull() && tracker.chain.contains(prev_share_hash)) {
                            tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                                p.absheight = prev->m_absheight + 1;
                                if (p.timestamp <= prev->m_timestamp)
                                    p.timestamp = prev->m_timestamp + 1;
                            });
                            auto [prev_height, _last] =
                                tracker.chain.get_height_and_last(prev_share_hash);
                            if (prev_height >= 99) {
                                try {
                                    p.far_share_hash =
                                        tracker.chain.get_nth_parent_key(prev_share_hash, 99);
                                } catch (const std::exception&) {
                                    p.far_share_hash = uint256::ZERO;
                                }
                            } else {
                                p.far_share_hash = uint256::ZERO;
                            }
                            // Step 2: share_target with the CLIPPED timestamp.
                            try {
                                auto st = tracker.compute_share_target(
                                    prev_share_hash, p.timestamp,
                                    chain::bits_to_target(block_bits));
                                p.bits = st.bits; p.max_bits = st.max_bits;
                                result.bits = st.bits; result.max_bits = st.max_bits;
                            } catch (const std::exception&) {
                                set_block_bits_fallback();
                            }
                            // Step 3: abswork = prev_abswork + aps(this-share-bits).
                            tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                                auto attempts = chain::target_to_average_attempts(
                                    chain::bits_to_target(p.bits));
                                p.abswork = uint128(
                                    (prev->m_abswork + uint128(attempts.GetLow64())).GetLow64());
                            });
                            // Step 4: merged_payout_hash — computed on THIS guard (no
                            // re-lock). Verify recomputes with the BLOCK target
                            // (share.m_min_header.m_bits), so use block_bits here.
                            try {
                                p.merged_payout_hash = tracker.compute_merged_payout_hash(
                                    prev_share_hash, chain::bits_to_target(block_bits));
                            } catch (const std::exception&) {
                                p.merged_payout_hash = uint256();
                            }
                        } else {
                            // prev unknown / genesis: derive share_target off null prev
                            // (compute_share_target returns the floor), then genesis.
                            try {
                                auto st = tracker.compute_share_target(
                                    prev_share_hash, p.timestamp,
                                    chain::bits_to_target(block_bits));
                                p.bits = st.bits; p.max_bits = st.max_bits;
                                result.bits = st.bits; result.max_bits = st.max_bits;
                            } catch (const std::exception&) {
                                set_block_bits_fallback();
                            }
                            set_genesis();
                        }
                    } else {
                        // Tracker busy — fallback (ref_hash won't match peers).
                        set_block_bits_fallback();
                        set_genesis();
                    }
                } else {
                    set_block_bits_fallback();
                    set_genesis();
                }

                // Mirror the walked values into the result for snap.frozen_ref.
                result.absheight      = p.absheight;
                result.abswork        = p.abswork;
                result.far_share_hash = p.far_share_hash;
                result.timestamp      = p.timestamp;
                result.merged_payout_hash = p.merged_payout_hash;

                try {
                    auto [rh, nn] = bip110::pool::compute_ref_hash_for_work(p);
                    result.ref_hash         = rh;
                    result.last_txout_nonce = nn;
                } catch (const std::exception& e) {
                    LOG_WARNING << "[BIP110-STRATUM] compute_ref_hash_for_work threw: "
                                << e.what();
                    // result.ref_hash stays null -> build_connection_coinbase refuses.
                }
                return result;
            });

        LOG_INFO << "[EMB-BIP110] M3 PR-C ref-commitment wired (best_share + ref_hash;"
                    " coinbase carries the v36 ref_hash, mint has_frozen=TRUE)";

        // FINDING C — arm the standalone periodic verified-flush timer so a
        // low-share-rate / idle node persists recent verified shares on a fixed
        // cadence, independent of think() events and the >=50 fast path. Flag-ON
        // only. The graceful-shutdown flush is wired at the signal handler below.
        node_raw->arm_flush_timer();

        // (6) IRREVERSIBLE first-outbound to the fresh federation sharechain.
        // Stays INSIDE the flag-ON block so it never runs by default.
        node_raw->start_outbound_connections();
        LOG_INFO << "[EMB-BIP110] M3 sharechain MINT wired + node LIVE on :"
                 << bip110::pool::PoolConfig::P2P_PORT
                 << " (--bip110-sharechain; prefix=" << bip110::pool::PoolConfig::prefix_hex()
                 << " proto=" << bip110::pool::PoolConfig::ADVERTISED_PROTOCOL_VERSION
                 << " share=v36) — outbound dialing started";
    } else {
        LOG_INFO << "[EMB-BIP110] M3 sharechain DISABLED (M2 header-follower; pass "
                    "--bip110-sharechain to arm the mint) — nothing minted, no sharechain node";
    }

    std::unique_ptr<core::StratumServer> stratum_server;
    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_addr, stratum_port, work_source);
        if (stratum_server->start())
            LOG_INFO << "[EMB-BIP110] stratum server LIVE on :" << stratum_port
                     << " (BLAKE2b Sv1 work source, coinbase-only M2)";
        else
            LOG_WARNING << "[EMB-BIP110] stratum server failed to bind :" << stratum_port;
    }

    auto header_block_hash = [](const bip110::coin::BlockHeaderType& hdr) {
        return bip110::coin::block_hash(hdr);
    };

    auto hdr_caught_up = std::make_shared<bool>(false);

    // ── M3 UTXO maintenance: connect every full block into the own-UTXO view ──
    // The p2p_node auto-requests every inv'd block via getdata(MSG_WITNESS_BLOCK),
    // so witness data arrives intact. Registration order matters: UTXO connect
    // FIRST (so the post-tip mempool passes see the applied block), mirroring
    // main_btc.cpp. This deepens the T2 pricing view one block at a time.
    // bip110::coin::UtxoFollower (utxo_follow.hpp) keeps the view on the active
    // chain: a block is connected only as the active chain's block right after
    // the view's best (the first one anchors an empty view), found in the header
    // chain by its BIP-110 identity (bip110::coin::block_hash: BLAKE2b at/after
    // the v2 fork -- SHA256d(header) never matches past the fork); a body that
    // cannot connect yet is kept and offered again after every body, on every
    // tip change and on each catch-up step; the catch-up step (the pool driver)
    // fetches the active chain's next blocks while the view is behind the tip,
    // and re-anchors a view too far behind or off the active chain.
    // Coin peer pool: the pool runs this UTXO connect itself, in chain order
    // (on_body_in_order), after its body check, and sets utxo_connect_by_pool;
    // the full_block subscriber below then leaves the connect to the pool.
    auto utxo_connect_by_pool = std::make_shared<bool>(false);
    {
        bip110::coin::UtxoFollowHost fh;
        fh.view = [&utxo_cache]() { return utxo_cache.get_best(); };
        fh.tip_height = [&header_chain]() { return header_chain.height(); };
        fh.active_at = [&header_chain](uint32_t h) -> std::optional<uint256> {
            auto e = header_chain.get_header_by_height(h);
            if (!e) return std::nullopt;
            return e->block_hash;
        };
        fh.height_of = [&header_chain](const uint256& id) -> std::optional<uint32_t> {
            auto e = header_chain.get_header(id);
            if (!e) return std::nullopt;
            return e->height;
        };
        // The connect itself (the follower checked utxo_connect_gate):
        // utxo_connect_and_flush drops the block's changes if the flush or the
        // connect fails (the view stays at its best; connected again later).
        fh.connect = [&utxo_cache, &utxo_db, &mempool, bip110_txid, BIP110_KEEP_DEPTH]
                     (const bip110::coin::BlockType& block, uint32_t height) -> bool {
            const uint256 block_hash =
                bip110::coin::block_hash(static_cast<const bip110::coin::BlockHeaderType&>(block));
            if (!bip110::coin::utxo_connect_and_flush(utxo_cache, utxo_db, block, height, bip110_txid,
                                                      block_hash, BIP110_KEEP_DEPTH))
                return false;
            // (Explorer raw-block retention hoisted OUT of this connect gate to
            // the top of the full_block subscriber — DASH/LTC parity — so it
            // persists every received body regardless of connect contiguity.)
            mempool.set_tip_height(height);
            LOG_INFO << "[EMB-BIP110] UTXO connect: h=" << height
                     << " txs=" << block.m_txs.size()
                     << " best_height=" << utxo_cache.get_best_height();
            return true;
        };
        // Kept bodies connected (their full_block pass ran when they came): the
        // UTXO-based mempool passes on the connected view.
        fh.after_kept = [&mempool, &utxo_cache]() {
            mempool.revalidate_inputs(&utxo_cache);
            mempool.recompute_unknown_fees(&utxo_cache);
        };
        // A connect made the view fresh (the serve gate opens): bump the work
        // generation, so stratum pushes populated work; the tip header's own
        // bump came while the gate was still shut (coinbase-only work).
        std::weak_ptr<bip110::stratum::Bip110WorkSource> fresh_ws = work_source;
        fh.on_fresh = [fresh_ws]() {
            if (auto ws = fresh_ws.lock())
                ws->bump_work_generation();
        };
        // ── GAP4 UTXO-view reorg handling ────────────────────────────────────
        // The view is on an abandoned branch: flag it inconsistent (serve
        // coinbase-only), roll the view back to the common ancestor via undo data
        // (removing rolled-back coins, restoring the coins they spent;
        // fail-closed on missing/legacy/too-deep undo or a record of another
        // block), requarantine + re-price the mempool against the reconciled
        // view, then clear the flag. A rolled-back coin can NEVER be
        // priced/included afterwards (GAP2's inclusion rule is the 2nd wall). On
        // failure the disconnects already made are dropped
        // (reorg_disconnect_or_discard): the view is the DB's again, at its old
        // best, never half-undone; the flag stays set and the follower
        // suspends the view (no connect) and re-anchors it at once.
        fh.rollback = [&utxo_cache, &utxo_db, &header_chain, &mempool, &utxo_consistent,
                       BIP110_KEEP_DEPTH]() -> bool {
            const uint32_t old_h = utxo_cache.get_best_height();
            utxo_consistent.store(false, std::memory_order_relaxed);
            const auto tip = header_chain.tip();
            auto res = bip110::coin::reorg_disconnect_or_discard(
                utxo_cache, utxo_db, header_chain, tip ? tip->block_hash : uint256(),
                BIP110_KEEP_DEPTH);
            if (res != bip110::coin::ReorgResult::OK) {
                LOG_ERROR << "[EMB-BIP110] UTXO reorg FAILED ("
                          << bip110::coin::reorg_result_name(res) << ") view_h=" << old_h
                          << " tip_h=" << header_chain.height() << " — partial rollback dropped;"
                             " serving coinbase-only until the view is re-anchored (fail closed,"
                             " never a wrong ledger)";
                return false;
            }
            mempool.requarantine_all();
            mempool.set_tip_height(utxo_cache.get_best_height());
            mempool.recompute_unknown_fees(&utxo_cache);
            mempool.revalidate_inputs(&utxo_cache);
            utxo_consistent.store(true, std::memory_order_relaxed);
            LOG_INFO << "[EMB-BIP110] UTXO reorg reconciled to fork h="
                     << utxo_cache.get_best_height() << " (from h=" << old_h << ", tip h="
                     << header_chain.height() << ")";
            return true;
        };
        // Wipe the view; the next connected block anchors it, as the first
        // anchor. Every mempool price came from the old view. The wipe
        // (UTXOViewCache::reanchor -> UTXOViewDB::reset) also drops the
        // explorer's retained block bodies (the 'F' records in the same DB):
        // getblock serves header partials for older heights until new bodies
        // refill the EXPLORER_DEPTH window.
        fh.reanchor = [&utxo_cache, &mempool, &utxo_consistent]() -> bool {
            if (!utxo_cache.reanchor())
                return false;
            mempool.requarantine_all();
            mempool.recompute_unknown_fees(&utxo_cache);
            utxo_consistent.store(true, std::memory_order_relaxed);
            LOG_WARNING << "[EMB-BIP110] UTXO view wiped for a re-anchor: its coins, undo"
                           " records and the explorer's retained block bodies (these refill"
                           " from new blocks)";
            return true;
        };
        // The bodies come through the coin peer pool (built below).
        fh.fetch = [&coin_pool](const std::vector<uint256>& ids) {
            if (coin_pool)
                coin_pool->fetch_bodies(ids);
        };
        utxo_follower = std::make_shared<bip110::coin::UtxoFollower>(std::move(fh));
    }
    auto utxo_connect_block = [utxo_follower](const bip110::coin::BlockType& block) {
        utxo_follower->on_body(block);
    };
    coin_node.full_block.subscribe(
        [&header_chain, &utxo_db, explorer_enabled, EXPLORER_DEPTH,
         utxo_connect_block, utxo_connect_by_pool]
        (const bip110::coin::BlockType& block)
        {
            // ── Explorer raw-block retention — persist EVERY received full block ─
            // DASH/LTC parity (main_ltc.cpp:2588, main_dash.cpp:2976): retention
            // lives OUTSIDE the UTXO-connect gate, so a reorg / non-contiguous /
            // already-seen body is still stored and served. bip110::coin::
            // retain_full_block resolves the block IDENTITY (BLAKE2b at/after the
            // v2 fork, SHA256d below) against the header chain — the SAME key the
            // chain is indexed by — NOT SHA256d(header), which never matches the
            // BLAKE2b key past the fork (why retention never fired live while it
            // used Hash()). STORAGE / SERVE ONLY — no consensus /
            // share / reward / coinbase / gentx / wire path is touched here.
            if (explorer_enabled) {
                auto stored = bip110::coin::retain_full_block(
                    [&header_chain](const uint256& id) -> std::optional<uint32_t> {
                        auto e = header_chain.get_header(id);
                        if (!e) return std::nullopt;
                        return e->height;
                    },
                    utxo_db, block, EXPLORER_DEPTH);
                if (stored)
                    LOG_INFO << "[EMB-BIP110] explorer retain: h=" << *stored;
            }

            if (*utxo_connect_by_pool) return;
            utxo_connect_block(block);
        });

    // On a fork-chain reorg the header chain fires on_tip_changed: the follower
    // offers its kept bodies first (a branch that just became active may extend
    // the view: a plain extension rolls nothing back), then, if the view's best
    // left the active chain, rolls the view back to the fork (fh.rollback) and
    // offers them again; if the rollback fails it suspends the view and
    // re-anchors it before returning (no connect in between).
    header_chain.set_on_tip_changed(
        [utxo_follower](const uint256& /*old_tip*/, uint32_t old_h, const uint256& /*new_tip*/,
                        uint32_t new_h)
        {
            if (utxo_follower->on_tip_changed() == bip110::coin::UtxoFollower::TipChange::RollbackFailed)
                LOG_WARNING << "[EMB-BIP110] UTXO view could not follow the reorg (old_h=" << old_h
                            << " new_h=" << new_h << "): "
                            << (utxo_follower->suspended() ? "suspended, re-anchor retried"
                                                           : "re-anchored");
        });

    // ── M3 mempool tx ingest ──────────────────────────────────────────────
    // new_tx fires for every tx relayed via inv->getdata(MSG_WITNESS_TX). We
    // add it to the mempool (priced from the UTXO view where possible) AND feed
    // its output values to the tier-3 priced-parent side table (self-authenticating
    // — a fetched parent that a child spends is priced from THESE bytes).
    coin_node.new_tx.subscribe(
        [&mempool, &utxo_cache](const bip110::coin::Transaction& tx) {
            bip110::coin::MutableTransaction mtx(tx);
            mempool.add_parent_priced(mtx);         // T3: record output values
            (void)mempool.add_tx(mtx, &utxo_cache);  // T1/T2: admit + price
        });

    // Post-tip mempool maintenance (after the UTXO connect above): drop confirmed
    // + conflicting txs, evict stale-input txs, re-price previously-unknown fees.
    coin_node.full_block.subscribe(
        [&mempool, &utxo_cache](const bip110::coin::BlockType& block) {
            mempool.remove_for_block(block);
            int evicted  = mempool.revalidate_inputs(&utxo_cache);
            int resolved = mempool.recompute_unknown_fees(&utxo_cache);
            mempool.evict_expired();
            mempool.evict_expired_parents();
            if (evicted > 0 || resolved > 0)
                LOG_INFO << "[EMB-BIP110] post-tip mempool: evicted=" << evicted
                         << " resolved_fees=" << resolved << " size=" << mempool.size();
        });

    // ── TIER-3 parent-tx resolver (daemonless input pricing driver) ──────────
    // Coin peer pool: the getdata goes to one pooled fork peer (the next one
    // each call); coin_node then holds no connection.
    auto parent_resolver = std::make_shared<bip110::coin::ParentTxResolver>(
        mempool, [&coin_node, &coin_pool](const std::vector<uint256>& txids) {
            if (coin_pool)
                coin_pool->request_txs(txids);
            else
                coin_node.request_tx(txids);
        });

    // Ingest header batches, drive the peer's start_height into the fast-sync
    // gate, and chain the next getheaders forward until caught up. Bump the work
    // generation on every fork-tip move so stratum sessions re-push fresh work.
    coin_node.new_headers.subscribe(
        [&header_chain, &coin_node, header_block_hash, hdr_caught_up, work_source]
        (const std::vector<bip110::coin::BlockHeaderType>& headers)
        {
            if (headers.empty()) return;
            int accepted = header_chain.add_headers(headers);
            if (accepted > 0) work_source->bump_work_generation();
            uint256 last_hash = header_block_hash(headers.back());
            const auto& lh = headers.back();
            LOG_INFO << "[EMB-BIP110] new_headers: received=" << headers.size()
                     << " accepted=" << accepted
                     << " height=" << header_chain.height()
                     << " last=" << last_hash.GetHex().substr(0, 16)
                     << " v2=" << (lh.is_v2() ? 1 : 0)
                     << " committed_height=" << lh.m_height;
            if (headers.size() >= 2000) {
                *hdr_caught_up = false;
                coin_node.send_getheaders(70016, {last_hash}, uint256::ZERO);
            } else {
                *hdr_caught_up = true;
            }
        });

    // Peer discovery (the scored NODE_BLAKE2B peer manager; declared above).
    const std::string pm_dir = std::string(getenv("HOME") ? getenv("HOME") : ".")
                             + "/.c2pool/bip110/peers";
    if (coin_p2p_discover) {
        bip110::coin::BtcPeerManagerConfig pm_cfg;
        pm_cfg.valid_ports = { 8333, 9333 };  // two of the fixed fork peers listen on 9333
        coin_peer_mgr = std::make_unique<bip110::coin::BtcCoinPeerManager>(
            ioc, "BIP110", pm_dir, pm_cfg);
        coin_peer_mgr->set_dns_seeds(bip110::coin::btc_dns_seeds(false));
        coin_peer_mgr->set_fixed_seeds(bip110::coin::btc_fixed_seeds(false));
        coin_peer_mgr->start();
        const auto st = coin_peer_mgr->peer_stats();
        LOG_INFO << "[EMB-BIP110] NODE_BLAKE2B peer discovery ARMED: peers=" << st.total
                 << " groups=" << st.unique_groups;
    }

    // ── SELF-ADDRESS ADVERTISEMENT primitives (Knots net.cpp GetLocalAddress /
    // SeenLocal / self-connect nonce). Shared by the primary NodeP2P, every
    // fan-out slot, and the InboundListener so a reachable-address vote learned on
    // ANY arm advertises on ALL. This is the reachability keystone: just listening
    // on :8333 is not enough — the fork network must LEARN our address, which
    // happens when we self-announce it and peers gossip it onward. Declared at
    // run_embedded scope so the shared_ptrs outlive ioc.run(). ──────────────────
    auto local_addr =
        std::make_shared<bip110::coin::p2p::LocalAddrTable>(uint16_t{8333});
    if (!coin_externalip.empty()) {
        local_addr->set_external(coin_externalip);
        LOG_INFO << "[EMB-BIP110] self-advertise external IP pinned: "
                 << coin_externalip << ":8333 (--coin-externalip)";
    } else {
        LOG_INFO << "[EMB-BIP110] self-advertise: no --coin-externalip; will learn "
                    "our reachable IP from fork-peer version echoes (Knots SeenLocal)";
    }
    auto self_nonce = std::make_shared<bip110::coin::p2p::SelfNonceRegistry>();

    // ── COIN-P2P INBOUND LISTENER (:8333) ─────────────────────────────────────
    // Make the branded coin-p2p node (/c2pool:0.1/bip110/frstrtr/ + NODE_BLAKE2B)
    // REACHABLE: the outbound arms (the coin peer pool, the fan-out) only dial,
    // so only the fork peers we dial ever see our UA. A separate accept-only
    // InboundListener on 0.0.0.0:8333 lets bitnodes/crawlers and any fork node
    // DIAL US and record our brand + services. It REUSES core::Server's accept
    // path (the same eb60bf4c strong-ref UAF guard as the outbound arm) via
    // set_lifetime BEFORE listen(), the broadcaster per-slot session pattern, and
    // the addrman getaddr supplier. The outbound connections stay UNTOUCHED —
    // zero regression to the outbound fork peers. Network-identity only:
    // version/verack/ping/getaddr are FREE p2p (no consensus/wire/params change).
    // Always-on whenever coin p2p is armed (not sharechain-flag-gated). Declared
    // at run_embedded scope so it outlives ioc.run().
    std::shared_ptr<bip110::coin::p2p::InboundListener<MiniConfig>> inbound_listener;
    if (coin_p2p_discover) {
        inbound_listener =
            std::make_shared<bip110::coin::p2p::InboundListener<MiniConfig>>(&ioc, &config);
        // ARM the accept-path UAF guard BEFORE listen(): register the listener's
        // own control block as its INetwork lifetime so core::Server::accept's
        // async_accept completion pins it by a strong ref (factory.hpp:83-117).
        inbound_listener->set_lifetime(inbound_listener);
        assert(inbound_listener->lifetime_armed() && "inbound listener lifetime failed to arm");
        // Self-address advertisement on the accept path: version addr_from + the
        // self-addr push at handshake + the self record in getaddr replies all
        // read our reachable addr from here; the self-connect nonce guard drops a
        // loopback dial. Shared with the outbound arms.
        inbound_listener->set_local_addr_table(local_addr);
        inbound_listener->set_self_nonce_registry(self_nonce);
        // getaddr replies come from the SAME fork-filtered, routable tried set the
        // fan-out broadcaster draws from (mutex-guarded, read-only, io-safe). A
        // large cap (Knots serves up to 1000) so a crawler learns the whole mesh.
        if (coin_peer_mgr) {
            auto* mgr = coin_peer_mgr.get();
            inbound_listener->set_addr_supplier([mgr]() {
                std::vector<NetService> out;
                for (const auto& ep : mgr->get_tried_peers(/*max_count=*/1000))
                    out.push_back(ep.to_net_service());
                return out;
            });
            // Inbound `addr` gossip → the shared addrman (was dropped on the floor):
            // a dialer's address set now grows our DB just like the outbound crawl.
            inbound_listener->set_addr_callback(
                [mgr](const std::vector<NetService>& addrs, const NetService& source) {
                    for (const auto& a : addrs)
                        mgr->add_discovered_peer(a, source.address());
                });
        }
        // Advertise our header-chain tip in the version reply (cosmetic; crawlers
        // only record UA + services).
        inbound_listener->set_height_supplier([&header_chain]() {
            return static_cast<uint32_t>(header_chain.height());
        });
        inbound_listener->core::Server::listen(uint16_t{8333});   // 0.0.0.0:8333
        LOG_INFO << "[EMB-BIP110] coin-p2p INBOUND listener ARMED on 0.0.0.0:8333 "
                    "(subver=" << bip110::coin::p2p::BIP110_COIN_SUBVER
                 << ", services=NODE_NETWORK|NODE_WITNESS|NODE_BLAKE2B, cap="
                 << bip110::coin::p2p::InboundListener<MiniConfig>::MAX_INBOUND << ")";
    }

    // ── Coin peer pool (the fork-network connections) ─────────────────────────
    // kCoinPoolTargetPeers outbound connections (bip110::coin::CoinPeerPool, the
    // pool c2pool-btc runs without --bitcoind), each a bip110 NodeP2P with its own
    // event sink. It replaces the single primary connection (and its 10 s
    // header-sync driver): headers, block announcements, transactions and block
    // bodies from any pooled peer feed coin_node's events (the new_headers /
    // new_tx / full_block subscribers above); a won block goes to every pooled
    // peer (primary_relay).
    //
    // Who is dialed: the explicit fork peers (--peer) first, then the peer
    // manager's candidates (--coin-p2p-discover; the NODE_BLAKE2B addrman,
    // scored, /16-diverse, backed off), never a key a fan-out slot already holds.
    // Each pooled peer is the same driver the primary was, so it keeps the BIP-110
    // peer rules (coin_peer_pool_p2p.hpp): the NODE_BLAKE2B version gate (a peer
    // without it is dropped before verack, then the slot as a failed dial), our
    // NODE_BLAKE2B services and branded user agent, the BIP-110 block identity
    // for its getdata / served-block paths; and, with the peer manager, what the
    // primary arm had (Knots net/net_processing): getaddr on connect, the
    // NODE_BLAKE2B addr intake into the addrman (and the self-authenticated add
    // of the peer itself at verack), self-advertisement (addr_from / SeenLocal /
    // self-addr push, the self-connect nonce) and the addr relay to inbound
    // sessions; the BIP 35 mempool request when serving mempool transactions.
    // The peer manager hears a handshake as connected and a dropped slot as a
    // disconnect or a failed dial from the pool (once per slot).
    //
    // Headers go through the header chain, which follows only the BIP-110 chain
    // (v2 BLAKE2b headers at and after the fork, the committed height); a peer
    // whose headers do not move the tip is the pool's failover victim. A block
    // body reaches the mempool and the UTXO view only if it was asked for, its
    // header is in the chain and it passes block_body_matches_header: the
    // c2pool-btc checks plus the v2 committed transaction count and the RDTS
    // weight cap (block_body_check.hpp).
    auto explicit_list = std::make_shared<std::vector<NetService>>(explicit_peers);
    std::shared_ptr<std::function<void()>> keepalive;   // the pool driver
    std::shared_ptr<std::function<void(NetService, int)>> resolve_keepalive;   // host-name --peer
    if (!explicit_peers.empty() || coin_peer_mgr) {
        // An explicit peer given by host name is resolved (async, the asio
        // resolver the dial path uses); its addresses take its place among the
        // explicit peers (the pool dials addresses only), so the next free slot
        // goes to them first (pool_candidates puts the explicit peers first). A
        // failed resolve is tried again after peer_resolve_backoff_sec (30 s,
        // doubling, at most 30 min).
        auto resolve_peer = std::make_shared<std::function<void(NetService, int)>>();
        std::weak_ptr<std::function<void(NetService, int)>> weak_resolve = resolve_peer;
        *resolve_peer = [&ioc, explicit_list, weak_resolve](NetService ns, int failures) {
            auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(ioc);
            resolver->async_resolve(
                ns.address(), std::to_string(ns.port()),
                [&ioc, resolver, explicit_list, weak_resolve, ns, failures](
                    const boost::system::error_code& ec,
                    boost::asio::ip::tcp::resolver::results_type results) {
                    if (ec) {
                        const int64_t wait = bip110::coin::peer_resolve_backoff_sec(failures);
                        LOG_WARNING << "[EMB-BIP110] explicit fork peer " << ns.to_string()
                                    << " not resolved (" << ec.message() << "): tried again in "
                                    << wait << "s";
                        auto timer = std::make_shared<io::steady_timer>(ioc, std::chrono::seconds(wait));
                        timer->async_wait([timer, weak_resolve, ns, failures](const boost::system::error_code& e) {
                            if (e) return;
                            if (auto again = weak_resolve.lock())
                                (*again)(ns, failures + 1);
                        });
                        return;
                    }
                    std::vector<NetService> addrs;
                    for (const auto& r : results)
                        addrs.emplace_back(r.endpoint().address().to_string(), r.endpoint().port());
                    const size_t n = bip110::coin::add_resolved_peers(*explicit_list, ns, addrs);
                    LOG_INFO << "[EMB-BIP110] explicit fork peer " << ns.to_string()
                             << " resolved: " << n << " address(es) added";
                });
        };
        resolve_keepalive = resolve_peer;
        for (const auto& ns : explicit_peers) {
            if (!bip110::coin::is_peer_hostname(ns))
                continue;
            LOG_WARNING << "[EMB-BIP110] explicit fork peer " << ns.to_string()
                        << " is a host name: resolving it (the coin peer pool dials addresses)";
            (*resolve_peer)(ns, 0);
        }
        auto* mgr = coin_peer_mgr.get();
        std::weak_ptr<bip110::coin::p2p::InboundListener<MiniConfig>> weak_il = inbound_listener;
        bip110::coin::CoinPeerPoolHost ph;
        ph.dial = [&ioc, &config, mgr, local_addr, self_nonce, weak_il, serve_mempool_txs]
                  (const NetService& addr, bip110::coin::PoolPeerHooks hooks)
                  -> std::unique_ptr<bip110::coin::PoolPeer> {
            return bip110::coin::make_pool_peer<MiniConfig>(
                &ioc, &config, addr, std::move(hooks),
                [mgr, local_addr, self_nonce, weak_il, serve_mempool_txs]
                (bip110::coin::p2p::NodeP2P<MiniConfig>& peer) {
                    if (mgr) {
                        peer.enable_getaddr_discovery();
                        peer.set_addr_callback(
                            [mgr](const std::vector<NetService>& addrs, const NetService& source) {
                                for (const auto& a : addrs)
                                    mgr->add_discovered_peer(a, source.address());
                            });
                        peer.set_local_addr_table(local_addr);
                        peer.set_self_nonce_registry(self_nonce);
                        if (!weak_il.expired())
                            peer.set_addr_relay_sink(
                                [weak_il](const std::vector<bip110::coin::p2p::btc_addr_record_t>& recs,
                                          const NetService& source) {
                                    if (auto il = weak_il.lock())
                                        il->relay_addr(recs, source.to_string(), /*fanout=*/2);
                                });
                    }
                    if (serve_mempool_txs)
                        peer.enable_mempool_request();   // BIP35 pull (skipped if peer !NODE_BLOOM)
                });
        };
        ph.candidates = [explicit_list, mgr, &coin_broadcaster]
                        (const std::set<std::string>& exclude) {
            return bip110::coin::pool_candidates(
                *explicit_list, exclude,
                coin_broadcaster ? coin_broadcaster->slot_keys() : std::vector<std::string>{},
                mgr ? std::function<std::vector<PeerEndpoint>(const std::set<std::string>&)>(
                          [mgr](const std::set<std::string>& taken) {
                              return mgr->get_peers_to_connect(taken);
                          })
                    : nullptr);
        };
        if (mgr) {
            ph.connected    = [mgr](const std::string& k) { mgr->notify_connected(k); };
            ph.disconnected = [mgr](const std::string& k) { mgr->notify_disconnected(k); };
            ph.dial_failed  = [mgr](const std::string& k) { mgr->notify_dial_failed(k); };
        }
        ph.has_header = [&header_chain](const uint256& h) { return header_chain.has_header(h); };
        // A full block locator (tip, then exponentially back to genesis): a peer
        // that does not hold our tip answers from the fork point.
        ph.locator = [&header_chain, &chain_params]() {
            auto loc = header_chain.get_locator();
            if (loc.empty())
                loc.push_back(chain_params.genesis_hash);
            return loc;
        };
        ph.height = [&header_chain]() { return header_chain.height(); };
        ph.header_height = [&header_chain](const uint256& h) -> std::optional<uint32_t> {
            auto e = header_chain.get_header(h);
            if (!e) return std::nullopt;
            return e->height;
        };
        ph.tip = [&header_chain]() {
            auto tip = header_chain.tip();
            return tip ? tip->block_hash : uint256();
        };
        ph.caught_up = [hdr_caught_up]() { return *hdr_caught_up; };
        ph.on_empty_headers = [hdr_caught_up]() {
            if (!*hdr_caught_up)
                LOG_INFO << "[EMB-BIP110] Header sync caught up (a fork peer has no headers"
                            " after our tip). Waiting on announcements.";
            *hdr_caught_up = true;
        };
        ph.on_headers = [&coin_node](const std::vector<bip110::coin::BlockHeaderType>& h) {
            coin_node.new_headers.happened(h);
        };
        ph.on_block_announced = [&coin_node](const uint256& h) { coin_node.new_block.happened(h); };
        ph.on_tx = [&coin_node](const bip110::coin::Transaction& tx) { coin_node.new_tx.happened(tx); };
        // A pooled block body goes on only if it was asked for, its header is in
        // the chain and it matches that header and the BIP-110 block rules; the
        // RDTS weight cap by the parent's median time past (header chain).
        auto rdts_cap_for = [&header_chain](const bip110::coin::BlockType& b) {
            const auto mtp = bip110::coin::parent_median_time_past(
                b.m_previous_block,
                [&header_chain](const uint256& h) -> std::optional<bip110::coin::BlockHeaderType> {
                    auto e = header_chain.get_header(h);
                    if (!e) return std::nullopt;
                    return e->header;
                });
            return bip110::coin::rdts_weight_cap_applies(b, mtp);
        };
        ph.body_valid = [rdts_cap_for](const bip110::coin::BlockType& b) {
            return bip110::coin::block_body_matches_header(b, rdts_cap_for(b));
        };
        // Bodies from two or more peers that pass every c2pool-btc check and
        // fail only a BIP-110 rule (the committed transaction count, the RDTS
        // weight cap): an ERROR naming the rule (BodyRuleAlarm: once per block,
        // at most every 10 min), so a rule of ours the fork network does not
        // share shows at once.
        auto rule_alarm = std::make_shared<bip110::coin::BodyRuleAlarm>();
        ph.on_bad_body = [rdts_cap_for, rule_alarm](const bip110::coin::BlockType& b, size_t peers) {
            if (peers < 2)
                return;
            const auto rule = bip110::coin::block_body_rule(b, rdts_cap_for(b));
            const uint256 id = bip110::coin::block_hash(
                static_cast<const bip110::coin::BlockHeaderType&>(b));
            if (rule_alarm->should_log(id, rule, peers, std::chrono::steady_clock::now()))
                LOG_ERROR << "[EMB-BIP110] block " << id.GetHex().substr(0, 16) << ": bodies from "
                          << peers << " fork peers pass every Bitcoin check and fail only the"
                             " BIP-110 " << bip110::coin::body_rule_name(rule) << " rule -- if"
                             " the fork network accepts this block, that rule does not match"
                             " the network's";
        };
        ph.body_best_height = [&utxo_cache]() -> std::optional<uint32_t> {
            if (utxo_cache.get_best_block().IsNull()) return std::nullopt;
            return utxo_cache.get_best_height();
        };
        // The UTXO connect in chain order; coin_node's full_block path (explorer
        // retention, mempool cleanup) on arrival, after the connect when the body
        // is not held for its parent.
        *utxo_connect_by_pool = true;
        ph.on_body_in_order = utxo_connect_block;
        // After a held body's UTXO connect (its full_block pass ran on arrival,
        // before the connect): the UTXO-based mempool passes on the connected
        // view and the work bump.
        std::weak_ptr<bip110::stratum::Bip110WorkSource> weak_ws = work_source;
        ph.after_late_connect = [&mempool, &utxo_cache, weak_ws](const bip110::coin::BlockType&) {
            const int evicted  = mempool.revalidate_inputs(&utxo_cache);
            const int resolved = mempool.recompute_unknown_fees(&utxo_cache);
            if (evicted > 0 || resolved > 0)
                LOG_INFO << "[EMB-BIP110] post-connect mempool maintenance (held block): evicted="
                         << evicted << " resolved_fees=" << resolved;
            if (auto ws = weak_ws.lock())
                ws->bump_work_generation();
        };
        ph.on_full_block = [&coin_node](const bip110::coin::BlockType& b) {
            coin_node.full_block.happened(b);
        };
        coin_pool = std::make_unique<bip110::coin::CoinPeerPool>(
            std::move(ph), bip110::coin::kCoinPoolTargetPeers, "[EMB-BIP110]");
        LOG_INFO << "[EMB-BIP110] coin peer pool: target " << coin_pool->target()
                 << " outbound NODE_BLAKE2B fork peers (explicit=" << explicit_list->size()
                 << ", discovery=" << (mgr ? "on" : "off") << ")";
        // First dials now (before the fan-out's first discovery pass below).
        coin_pool->tick();

        // ── Pool driver ─────────────────────────────────────────────────────
        // Every kCoinPoolPollSec the pool's poll(): block-body retries and the
        // chain-order hold; every kCoinPoolTickSec its full tick: slot upkeep +
        // refill, and the header-source step over the whole pool
        // (header_source_step: progress = the header tip, from any peer). Then,
        // once header sync is caught up, the UTXO view's catch-up step
        // (UtxoFollower::catch_up: the next bodies while the view is behind the
        // tip, a re-anchor when it is too far behind or off the active chain).
        // Weak self-ref avoids a shared_ptr cycle; `keepalive` holds it.
        auto pool_timer = std::make_shared<io::steady_timer>(ioc);
        auto schedule_pool = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak_pool = schedule_pool;
        auto* pool_ptr = coin_pool.get();
        *schedule_pool = [pool_timer, weak_pool, pool_ptr, utxo_follower, hdr_caught_up]() {
            pool_timer->expires_after(
                std::chrono::seconds(static_cast<int>(bip110::coin::kCoinPoolPollSec)));
            pool_timer->async_wait([weak_pool, pool_ptr, utxo_follower, hdr_caught_up]
                                   (const boost::system::error_code& ec) {
                if (ec) return;
                try {
                    pool_ptr->poll();
                    utxo_follower->on_tick(*hdr_caught_up);
                } catch (const std::exception& e) {
                    LOG_WARNING << "[EMB-BIP110] coin peer pool tick error: " << e.what();
                }
                if (auto self = weak_pool.lock()) (*self)();
            });
        };
        keepalive = schedule_pool;
        (*schedule_pool)();
    } else {
        LOG_WARNING << "[EMB-BIP110] no fork peer source (pass --peer IP:PORT or "
                       "--coin-p2p-discover): no coin-network connection";
    }

    // ── M3 PR-C2: construct the addrman-backed FOUND-BLOCK fan-out pool + the
    // found-block keystone (flag-ON only). Placed AFTER coin_peer_mgr (the
    // NODE_BLAKE2B addrman) and the coin peer pool (its first dials are out).
    // With the flag OFF this whole block is skipped: coin_broadcaster* stay null
    // and stratum_submit_fn keeps calling the primary relay alone. ─────────────
    // With the coin peer pool, fan-out slots relay won blocks (ARM A) and crawl
    // the fork mesh only: their events go to fanout_sink (not coin_node), they
    // fetch no announced block or transaction (bodies reach the mempool and the
    // UTXO view only through the pool's body check), and they serve a relayed
    // block by the BIP-110 block identity.
    std::shared_ptr<io::steady_timer> broadcaster_timer;
    if (sharechain_enabled) {
        constexpr size_t kFanoutMaxPeers = 8;
        coin_broadcaster = std::make_unique<bip110::coin::Bip110Broadcaster<MiniConfig>>(
            &ioc,
            coin_pool ? &fanout_sink : static_cast<bip110::interfaces::Node*>(&coin_node),
            &config,
            kFanoutMaxPeers);
        coin_broadcaster_full =
            std::make_unique<bip110::coin::Bip110BroadcasterFull<MiniConfig>>(
                coin_broadcaster.get());
        // ARM B — the standing primary sink: the primary relay (the coin peer
        // pool, then coin_node's P2P relay + optional submitblock RPC backup).
        // Never masked by ARM A.
        coin_broadcaster_full->set_primary_submit(primary_relay);
        // Wire the SAME Knots peer-discovery seams onto every fan-out slot, so a
        // fan-out peer's addr gossip ALSO grows the shared addrman + tried set
        // (not just the pooled peers). Only when the scored peer manager exists.
        const bool fanout_relay_only = static_cast<bool>(coin_pool);
        if (coin_peer_mgr || fanout_relay_only) {
            auto* mgr = coin_peer_mgr.get();
            std::weak_ptr<bip110::coin::p2p::InboundListener<MiniConfig>> weak_il = inbound_listener;
            coin_broadcaster->set_slot_configurator(
                [mgr, local_addr, self_nonce, weak_il, fanout_relay_only]
                (bip110::coin::p2p::NodeP2P<MiniConfig>& slot) {
                    if (fanout_relay_only) {
                        slot.set_fetch_filter([](const uint256&, bool) { return false; });
                        slot.set_header_hash_fn([](const bip110::coin::BlockHeaderType& h) {
                            return bip110::coin::block_hash(h);
                        });
                    }
                    if (!mgr)
                        return;
                    slot.enable_getaddr_discovery();
                    slot.set_addr_callback(
                        [mgr](const std::vector<NetService>& addrs, const NetService& source) {
                            for (const auto& a : addrs)
                                mgr->add_discovered_peer(a, source.address());
                        });
                    slot.set_on_peer_connected(
                        [mgr](const NetService& s) { mgr->notify_connected(s.to_string()); });
                    slot.set_on_peer_disconnected(
                        [mgr](const NetService& s) { mgr->notify_disconnected(s.to_string()); });
                    slot.set_on_dial_failed(
                        [mgr](const NetService& s) { mgr->notify_dial_failed(s.to_string()); });
                    // Same self-advertise seams on every fan-out slot so a peer
                    // echo / self-addr learned on any link advertises on all.
                    slot.set_local_addr_table(local_addr);
                    slot.set_self_nonce_registry(self_nonce);
                    slot.set_addr_relay_sink(
                        [weak_il](const std::vector<bip110::coin::p2p::btc_addr_record_t>& recs,
                                  const NetService& source) {
                            if (auto il = weak_il.lock())
                                il->relay_addr(recs, source.to_string(), /*fanout=*/2);
                        });
                });
        }
        LOG_INFO << "[EMB-BIP110] M3 PR-C2 found-block fan-out ARMED (max_peers="
                 << kFanoutMaxPeers << ") — ARM A embedded NODE_BLAKE2B fan-out + "
                    "ARM B primary relay/RPC";

        // Self-rescheduling discovery tick: grow the fan-out pool from the
        // addrman tried set + explicit fork peers, and prune dead slots. The
        // pool stays warm so a found block fans to many peers immediately.
        broadcaster_timer = std::make_shared<io::steady_timer>(ioc);
        auto bc_tick = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak_bc_tick = bc_tick;
        *bc_tick = [broadcaster_timer, weak_bc_tick, &coin_broadcaster, &coin_peer_mgr,
                    explicit_list, &coin_pool]() {
            // The fork peers the coin peer pool holds (dialing or live): never a
            // fan-out target, so a slot is never spent dueling the pool for the
            // same peer (the redundant-inbound EOF) and each fan-out probe dials
            // a DISTINCT fork peer.
            std::set<std::string> pooled;
            if (coin_pool)
                for (const auto& k : coin_pool->slot_keys())
                    pooled.insert(k);
            std::vector<NetService> targets;
            // Explicit fork peers first (the operator's pinned NODE_BLAKE2B set);
            // with the pool, a host-name entry by its resolved addresses only.
            for (const auto& ep : *explicit_list)
                if (!coin_pool || !bip110::coin::is_peer_hostname(ep))
                    targets.push_back(ep);
            // Then the addrman tried set (NODE_BLAKE2B-filtered, scored).
            if (coin_peer_mgr)
                for (const auto& ep : coin_peer_mgr->get_tried_peers(/*max_count=*/16))
                    targets.push_back(ep.to_net_service());
            // GAP-6 (raise the fan-out target off 1): ALSO draw NEW, learned-but-
            // not-yet-tried fork peers straight from the bucketed addrman via the
            // scored dial planner (group diversity + backoff + feeler enforced in
            // get_peers_to_connect). Without this the fan-out could only redial
            // the tried set, so a freshly-crawled oracle mesh was never dialed and
            // the pool stayed pinned at the explicit/primary peer.
            if (coin_peer_mgr) {
                for (const auto& ep : coin_peer_mgr->get_peers_to_connect(pooled))
                    targets.push_back(ep.to_net_service());
            }
            targets.erase(std::remove_if(targets.begin(), targets.end(),
                                         [&pooled](const NetService& t) {
                                             return pooled.count(t.to_string()) != 0;
                                         }),
                          targets.end());
            if (coin_broadcaster) {
                coin_broadcaster->prune_dead();
                coin_broadcaster->discover(targets);
            }
            if (auto self = weak_bc_tick.lock()) {
                broadcaster_timer->expires_after(std::chrono::seconds(30));
                broadcaster_timer->async_wait(
                    [self](const boost::system::error_code& ec) { if (!ec) (*self)(); });
            }
        };
        (*bc_tick)();
    }

    // ── Shared coin-generic dashboard (--http) ───────────────────────────────
    // Serve the SAME refined web-static dashboard the BTC/DGB/DASH lanes serve
    // (btc.voidbind parity), rendered per-coin from the runtime coin LABEL. This
    // replaces the old bespoke StatusHttp JSON-on-every-path endpoint: the shared
    // core::WebServer routes REST endpoints (incl /node_info) BEFORE static files
    // in http_session.cpp, so "/" now resolves to the HTML dashboard while
    // /node_info stays JSON (caddy's health_uri probe keeps its 200). This lane
    // passes a NULL IMiningNode (proven BTC/DGB/DASH pattern — the Blockchain
    // enum only selects graph_db constants + address validation), so refresh_work
    // never fills m_cached_template; set_dashboard_always_ready(true) is MANDATORY
    // or http_session's readiness gate 307-redirects every .html to loading.html
    // forever. All feeds below are display-only lambdas over already-published
    // header/peer state — no share/reward/consensus/PoW path is touched.
    std::unique_ptr<core::WebServer> web_server;
    std::shared_ptr<io::steady_timer> stats_timer;
    if (http_port != 0) {
        LOG_INFO << "[EMB-BIP110] standing up core::WebServer + MiningInterface (http bind "
                 << http_host << ":" << http_port << ") ...";
        web_server = std::make_unique<core::WebServer>(
            ioc, http_host, http_port, /*testnet=*/false,
            std::shared_ptr<core::IMiningNode>{},            // NULL IMiningNode (BTC/DGB pattern)
            c2pool::address::Blockchain::BITCOIN);           // SHA256d graph_db pairing
        auto* mi = web_server->get_mining_interface();
        if (mi == nullptr) {
            LOG_ERROR << "[EMB-BIP110] core::WebServer constructed but MiningInterface is"
                      << " NULL -- dashboard disabled, run-loop continues.";
            web_server.reset();
        }
        if (mi != nullptr) {
        LOG_INFO << "[EMB-BIP110] core::WebServer + MiningInterface constructed (coin=BIP110, "
                 << "http " << http_host << ":" << http_port << ").";
        // Coin identity — the whole UI renders from the LABEL (registry row +
        // rest_web_currency_info "BIP110" branch brand it; the BITCOIN enum alone
        // would render as Bitcoin).
        mi->set_coin_label("BIP110");

        // ── Explorer API callbacks (loopback-only, read-only) ─────────────────
        // Enable the node /api/explorer surface that explorer.py --c2pool
        // consumes. This is the ONLY caller of set_explorer_enabled on this lane
        // (main_ltc.cpp is the reference); without it http_session's gate answers
        // {"error":"Explorer not enabled"}. All feeds are display-only reads over
        // the header chain / retained raw blocks / mempool snapshot — no
        // consensus/reward/share/coinbase/wire path is touched. #99 SPV bounds:
        // fields the node cannot serve are named-refused, never faked.
        //
        // Chain-key trap: explorer.py always sends ?chain=bip110, but the node's
        // own primary_chain_key() returns "btc" on a BITCOIN-enum lane (the
        // default when ?chain= is absent). Accept "bip110", "btc", and "" — this
        // is a single-chain node, so any of them means the bip110 chain.
        if (explorer_enabled) {
            mi->set_explorer_enabled(true);
            auto chain_ok = [](const std::string& c) {
                return c.empty() || c == "bip110" || c == "btc";
            };
            auto* hc  = &header_chain;
            auto* udb = &utxo_db;
            auto* mp  = &mempool;

            // getblockchaininfo — header-chain derived (always servable).
            mi->set_explorer_chaininfo_fn(
                [hc, chain_ok, EXPLORER_DEPTH](const std::string& chain) -> nlohmann::json {
                    if (!chain_ok(chain))
                        return nlohmann::json{{"error", "Unknown chain or chain not enabled"}};
                    nlohmann::json r;
                    r["chain"]   = "main";
                    r["blocks"]  = hc->height();
                    r["headers"] = static_cast<uint64_t>(hc->size());
                    r["explorer_depth"] = EXPLORER_DEPTH;
                    auto t = hc->tip();
                    r["bestblockhash"] = t ? t->block_hash.GetHex() : "";
                    if (t) {
                        auto target = bip110::coin::target_from_bits(t->header.m_bits);
                        double diff = target.IsNull() ? 0.0
                            : hc->params().pow_limit.getdouble() / target.getdouble();
                        r["difficulty"] = diff;
                    }
                    return r;
                });

            // getblockhash — header-chain derived (always servable within chain).
            mi->set_explorer_blockhash_fn(
                [hc, chain_ok](uint32_t height, const std::string& chain) -> std::string {
                    if (!chain_ok(chain)) return {};
                    auto e = hc->get_header_by_height(height);
                    if (e) return e->block_hash.GetHex();
                    return {};
                });

            // getblock — deserialize retained raw block, run block_to_explorer_json.
            // #99: below the retention depth OR body not yet stored → named refusal.
            mi->set_explorer_getblock_fn(
                [hc, udb, chain_ok, EXPLORER_DEPTH](const std::string& hash_hex,
                                    const std::string& chain) -> nlohmann::json {
                    if (!chain_ok(chain))
                        return nlohmann::json{{"error", "Unknown chain or chain not enabled"}};
                    uint256 blk_hash;
                    blk_hash.SetHex(hash_hex);
                    auto entry = hc->get_header(blk_hash);
                    if (!entry)
                        return nlohmann::json{{"error", "Block not in header chain"}};

                    // DASH-shape (#1460/#99) full-then-partial getblock. Every
                    // indexed header answers; bodies stay honestly absent below the
                    // 288-block retention window (never tx: [], never fabricated
                    // sizes, never an "error" key so the row still renders). The
                    // decision + header-partial builder are hoisted verbatim into
                    // bip110::coin::explorer_getblock_body so the getblock KAT binds
                    // the EXACT shipped logic. Mirrors main_dash.cpp:4496-4563.
                    uint32_t tip = hc->height();
                    std::optional<uint256> next_block_hash;
                    if (auto nxt = hc->get_header_by_height(entry->height + 1))
                        next_block_hash = nxt->block_hash;
                    bip110::coin::ExplorerChainParams params;
                    params.bech32_hrp = "bc";
                    params.p2pkh_ver  = 0x00;
                    params.p2sh_ver   = 0x05;
                    params.chain_name = "main";
                    return bip110::coin::explorer_getblock_body(
                        *entry, blk_hash, tip, next_block_hash,
                        hc->params().pow_limit, *udb, EXPLORER_DEPTH, params);
                });

            // getmempoolinfo — summary stats + feerate histogram.
            mi->set_explorer_mempoolinfo_fn(
                [mp, chain_ok](const std::string& chain) -> nlohmann::json {
                    if (!chain_ok(chain))
                        return nlohmann::json{{"error", "Mempool not available for chain"}};
                    auto snap = mp->get_summary();
                    time_t now = std::time(nullptr);
                    struct Bucket { double lo, hi; size_t count{0}; size_t bytes{0}; };
                    std::vector<Bucket> buckets = {{0,1},{1,5},{5,20},{20,100},{100,1e9}};
                    for (const auto& e : snap.entries) {
                        double fr = e.feerate();
                        for (auto& b : buckets) {
                            if (fr >= b.lo && fr < b.hi) { ++b.count; b.bytes += e.base_size; break; }
                        }
                    }
                    nlohmann::json hist = nlohmann::json::array();
                    for (const auto& b : buckets) {
                        hist.push_back({
                            {"min_feerate", b.lo},
                            {"max_feerate", b.hi >= 1e9 ? nlohmann::json("inf") : nlohmann::json(b.hi)},
                            {"count", b.count}, {"bytes", b.bytes}});
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
                        {"oldest_age_sec", (snap.oldest_time > 0 && now > snap.oldest_time)
                                              ? (now - snap.oldest_time) : 0},
                        {"fee_histogram", hist},
                        {"chain", "bip110"}};
                });

            // getrawmempool — txid list or verbose entries.
            mi->set_explorer_rawmempool_fn(
                [mp, chain_ok](const std::string& chain, bool verbose, uint32_t limit) -> nlohmann::json {
                    if (!chain_ok(chain))
                        return nlohmann::json{{"error", "Mempool not available for chain"}};
                    if (!verbose) {
                        auto txids = mp->all_txids();
                        nlohmann::json arr = nlohmann::json::array();
                        for (const auto& id : txids) arr.push_back(id.GetHex());
                        return arr;
                    }
                    auto snap = mp->get_summary();
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
                            {"n_vout", e.n_vout}});
                        ++count;
                    }
                    return arr;
                });

            // getmempoolentry — single tx full detail with vin/vout.
            mi->set_explorer_mempoolentry_fn(
                [mp, chain_ok](const std::string& txid_hex, const std::string& chain) -> nlohmann::json {
                    if (!chain_ok(chain))
                        return nlohmann::json{{"error", "Mempool not available for chain"}};
                    uint256 txid;
                    txid.SetHex(txid_hex);
                    auto opt = mp->get_entry(txid);
                    if (!opt) return nlohmann::json{{"error", "Transaction not in mempool"}};
                    const auto& e = *opt;
                    time_t now = std::time(nullptr);
                    nlohmann::json vin_arr = nlohmann::json::array();
                    for (const auto& inp : e.tx.vin) {
                        vin_arr.push_back({
                            {"prevout_hash", inp.prevout.hash.GetHex()},
                            {"prevout_n", inp.prevout.index},
                            {"sequence", inp.prevout.index == 0xffffffff
                                            ? "ffffffff" : std::to_string(inp.sequence)}});
                    }
                    nlohmann::json vout_arr = nlohmann::json::array();
                    for (size_t i = 0; i < e.tx.vout.size(); ++i) {
                        const auto& out = e.tx.vout[i];
                        std::vector<unsigned char> script(out.scriptPubKey.m_data.begin(),
                                                          out.scriptPubKey.m_data.end());
                        auto cls = core::classify_script(script, "bc", 0x00, 0x05);
                        nlohmann::json vout_obj = {
                            {"n", i},
                            {"value_sat", out.value},
                            {"scriptPubKey_hex", cls.hex},
                            {"type", cls.type}};
                        if (!cls.addresses.empty()) vout_obj["address"] = cls.addresses[0];
                        if (cls.addresses.size() > 1) vout_obj["addresses"] = cls.addresses;
                        vout_arr.push_back(std::move(vout_obj));
                    }
                    return nlohmann::json{
                        {"txid", e.txid.GetHex()},
                        {"size", e.base_size},
                        {"witness_size", e.witness_size},
                        {"weight", e.weight},
                        {"fee", e.fee},
                        {"fee_known", e.fee_known},
                        {"feerate", e.feerate()},
                        {"time_added", e.time_added},
                        {"age_sec", (e.time_added > 0 && now > e.time_added) ? (now - e.time_added) : 0},
                        {"vin", vin_arr},
                        {"vout", vout_arr},
                        {"chain", "bip110"}};
                });

            LOG_INFO << "[EMB-BIP110] Explorer API wired (loopback-only): header browse + "
                        "found-block coinbase + mempool, retention depth=" << EXPLORER_DEPTH;
        }

        // F2 — currency_info share_version. The MI default is 35 (the V35/V36
        // ratchet cross default for the LTC family); bip110 never runs the
        // AutoRatchet and its mint is hardwired v36 (see the v36 header/share
        // construction below), so the honest static answer is 36. Without this
        // the explorer misclassifies live v36 share cells as v35.
        mi->set_cached_share_version(36);
        // F2b — native share-version declaration (display-only). bip110's genesis
        // share-version already EQUALS the target (v36) with no lower predecessor,
        // so there is no crossing and no voting. This makes /v36_status report
        // state='native' instead of fabricating a 'voting' / V36->V36 crossing
        // (the Share-Version Crossing card lied ACTIVE+VOTING on a chain that
        // never crossed). Consensus/mint untouched -- purely the ratchet widget.
        mi->set_native_share_version(true);
        // F3 — currency_info + node_topology "embedded" flag. This lane is fully
        // daemonless (no external node RPC) but runs on a NULL IMiningNode with
        // no m_coin_node (bip110::coin::Node is NOT a core::coin::ICoinNode), so
        // the default (m_coin_node && is_embedded()) reads false and contradicts
        // /api/node_topology embedded:true. Display-only override; does NOT arm
        // any coin-node submit/refresh path (m_coin_node stays null).
        mi->set_embedded_display(true);
#ifdef C2POOL_VERSION
        mi->set_pool_version("c2pool/" C2POOL_VERSION);
#endif
        mi->set_io_context(&ioc);
        mi->set_dashboard_always_ready(true);   // load-bearing on a NULL IMiningNode
        // Advertise real runtime ports on /node_info. Under M3 flag-ON the
        // sharechain node binds a REAL inbound listener on PoolConfig::P2P_PORT
        // (node_raw->core::Server::listen(9337)), so p2p_port is the live
        // sharechain peer port — mirrors LTC semantics (main_ltc.cpp:1776 passes
        // the sharechain p2p_port to /node_info). Flag-OFF (M2, no sharechain
        // node) keeps 0 since nothing listens. The stratum bind is the worker
        // port (set_worker_port below), independent of this.
        //
        // DELIBERATE: set_stratum_port(0), NOT stratum_port. This lane already
        // binds its OWN core::StratumServer on stratum_port above (fed by the
        // BLAKE2b Sv1 work_source). A nonzero value here would make
        // WebServer::start() construct a SECOND core::StratumServer on the same
        // port via start_stratum_server(), whose bind throws EADDRINUSE ("bind:
        // Address already in use") and serves miners from the wrong work source
        // if the first ever failed. This is the exact hazard main_dash.cpp
        // documents (main_dash.cpp:1289-1297,1539-1542) and opts out of the same
        // way. The call MUST remain (not be deleted): the WebServer ctor DEFAULTS
        // stratum_port_ to http_port+10 (web_server.cpp:9514), so omitting it
        // would auto-bind a stray listener on http_port+10. The dashboard's
        // displayed worker port comes from MiningInterface::set_worker_port()
        // below (fully independent of WebServer::stratum_port_).
        web_server->set_stratum_port(0);
        mi->set_worker_port(stratum_port);
        // Sharechain peer port (LTC semantics): the live :9337 inbound listener
        // when the sharechain node exists, else 0 (M2 has no listener).
        mi->set_p2p_port(sharechain_enabled
                             ? bip110::pool::PoolConfig::P2P_PORT : 0);
        // Self-advertised public IP for the miner-config URL + peer endpoint.
        // Without this /node_info emits external_ip "0.0.0.0" (the miner-config
        // card then shows 0.0.0.0:port). The operator-supplied --coin-externalip
        // (the reachable public IP of this host, e.g. 203.0.113.10) is the same
        // address the sharechain :9337 + coin-p2p :8333 listeners bind on; surface
        // it. Auto-detect from peer echoes still fills it later when unset. LTC
        // ref main_ltc.cpp:1778.
        if (!coin_externalip.empty())
            mi->set_external_ip(coin_externalip);
        // Payout/owner address for the dashboard: powers the sharechain-window
        // "mine" highlight (my_address), the Node-Fee card's own-entitlement line
        // (/payout_addrs ∩ /current_merged_payouts) and the explorer's fee-share
        // marking. LTC ref main_ltc.cpp:2071. Display-only: the consensus donation
        // script is set separately on the work_source above.
        if (!donation_address.empty())
            mi->set_payout_address(donation_address);
        // Point static serving at the on-disk frontend (CWD-relative, same as
        // btc/dgb): "/" -> web-static/dashboard.html. The deploy pairs a
        // web-static copied from THIS commit next to the binary/CWD.
        web_server->set_dashboard_dir("web-static");
        web_server->set_analytics_id(core::analytics_id_setting());   // --analytics-id (default off)
        // Node fee card — configured node-owner fee percent.
        mi->set_pool_fee_percent(node_owner_fee_pct);

        // Node topology card: embedded SPV follower state + the old StatusHttp
        // fork fields (blake2b_height / on_blake2b_chain) find their honest new
        // home here. Mirror of main_btc.cpp node_topology_fn.
        mi->set_node_topology_fn([&header_chain, &coin_node, &chain_params,
                                  &coin_broadcaster, &coin_pool]() {
            const uint32_t synced   = header_chain.height();
            const uint32_t peer_tip = header_chain.peer_tip_height();
            const bool     emb_p2p  = coin_node.has_p2p();
            const bool     ext_rpc  = coin_node.has_rpc();
            // Count ALL live NODE_BLAKE2B fork links, not just "a primary object
            // exists": the handshaked primary (1) PLUS every handshake-complete
            // fan-out slot (Bip110Broadcaster::live_count). The old `emb_p2p ? 1 : 0`
            // reported 1 even while the node was connected to 6+ fork nodes (the
            // fan-out arm was never counted) — and 1 even before the primary had
            // handshaked. Gate the primary on the completed handshake so the number
            // reflects real, answerable links.
            int embedded_peers = coin_node.is_handshake_complete() ? 1 : 0;
            // Every pooled fork peer with a completed handshake (coin_node then
            // holds no connection).
            const size_t pool_live = coin_pool ? coin_pool->live_count() : 0;
            embedded_peers += static_cast<int>(pool_live);
            if (coin_broadcaster)
                embedded_peers += static_cast<int>(coin_broadcaster->live_count());
            return nlohmann::json{
                {"coin", "BIP110"},
                {"embedded", true},
                {"has_rpc", ext_rpc},
                {"synced_height", synced},
                {"peer_tip_height", peer_tip},
                {"sync_pct", (peer_tip > 0 ? 100.0 * synced / peer_tip : 0.0)},
                {"embedded_peers", embedded_peers},
                // Node-topology "peers" key (renderNodeTopology c.peers,
                // dashboard.html:3266): LTC/DGB emit the coin-P2P connected
                // count here (main_ltc.cpp:3854 e["peers"]=bc->connected_count),
                // and the auto-detect fallback fills it too (web_server.cpp:5617).
                // bip110 previously emitted only "embedded_peers" with NO "peers"
                // key, so the topology row read the 0 default and always showed
                // "0 peers"/faulted while genuinely connected to fork nodes.
                // Mirror LTC semantics: topology "peers" = coin-P2P links (NOT
                // sharechain peers — the c2pool-Nodes card gets those via
                // set_peer_info_fn below). Keep "embedded_peers" for compat.
                {"peers", embedded_peers},
                {"broadcast_route", (emb_p2p || pool_live > 0) ? "p2p" : (ext_rpc ? "rpc" : "none")},
                {"blake2b_height", chain_params.blake2b_height},
                {"on_blake2b_chain", synced >= chain_params.blake2b_height},
            };
        });

        // Coin sync-status cards: feed /broadcaster_status header_height/
        // target_height + the single embedded fork peer's version-advertised
        // tip so the sync cards render the REAL BIP-110 header tip. Mirror of
        // main_btc.cpp coin_sync_status_fn.
        mi->set_coin_sync_status_fn([&header_chain, &coin_node, &coin_broadcaster, &coin_pool]()
                                        -> nlohmann::json {
            nlohmann::json s = nlohmann::json::object();
            const uint32_t hh = header_chain.height();
            uint32_t th = header_chain.peer_tip_height();
            nlohmann::json peers = nlohmann::json::array();
            std::set<std::string> seen;
            auto* p2p = coin_node.p2p();
            if (p2p != nullptr && p2p->peer_version() > 0) {
                const uint32_t sh = p2p->peer_start_height();
                if (sh > th) th = sh;
                seen.insert(p2p->target_addr().to_string());
                peers.push_back({
                    {"subver", p2p->peer_subver()},
                    {"startingheight", sh},
                    {"conntime", p2p->peer_uptime_sec()},
                    {"connected", true},
                });
            }
            // Every pooled fork peer with a completed handshake.
            if (coin_pool) {
                for (const auto& r : coin_pool->rows()) {
                    if (!seen.insert(r.addr).second) continue;
                    if (r.start_height > th) th = r.start_height;
                    peers.push_back({
                        {"subver", r.subver},
                        {"startingheight", r.start_height},
                        {"conntime", r.conntime},
                        {"connected", true},
                    });
                }
            }
            // Fold EVERY live fork peer into the sync cards, not just the
            // primary — so target_height is honest over the whole NODE_BLAKE2B
            // mesh and the peers array counts all connected forks. Deduped
            // against the primary by dialed address.
            if (coin_broadcaster) {
                coin_broadcaster->for_each_live_slot(
                    [&](const std::string& key, const auto& n) {
                        if (!seen.insert(key).second) return;
                        const uint32_t sh = n.peer_start_height();
                        if (sh > th) th = sh;
                        peers.push_back({
                            {"subver", n.peer_subver()},
                            {"startingheight", sh},
                            {"conntime", n.peer_uptime_sec()},
                            {"connected", true},
                        });
                    });
            }
            s["header_height"] = hh;
            s["target_height"] = th;
            s["peers"] = std::move(peers);
            return s;
        });

        // Fork-peer directory card (/broadcaster_status "peers"): the honest set of
        // NODE_BLAKE2B links + learned fork mesh. Drives the dashboard CONNECTIONS
        // (entries with connected==true) and DATABASE (total entries) counters.
        // Previously UNWIRED, so rest_broadcaster_status fell through to the header-
        // sync provider whose peers array is JUST the primary — hence the stuck
        // "CONNECTIONS 1 / DATABASE 1" while the node was connected to 6+ fork
        // nodes. Composed from: (1) the primary coin-P2P arm (rich subver/height),
        // (2) every live fan-out slot (redundant NODE_BLAKE2B header/broadcast
        // peers), (3) the peer manager's routable directory (the learned breadth,
        // grown by the self-authenticated handshake add + addr crawl + seeds).
        // Deduped by addr; the primary/live entries win their richer fields.
        mi->set_coin_peer_info_fn([&coin_node, &coin_broadcaster, &coin_peer_mgr, &coin_pool]()
                                      -> nlohmann::json {
            nlohmann::json arr = nlohmann::json::array();
            std::set<std::string> seen;
            // (1) Primary coin-P2P arm.
            if (auto* p = coin_node.p2p(); p != nullptr) {
                const std::string key = p->target_addr().to_string();
                if (!key.empty() && seen.insert(key).second) {
                    arr.push_back({
                        {"addr", key},
                        {"connected", p->is_handshake_complete()},
                        {"subver", p->peer_subver()},
                        {"startingheight", p->peer_start_height()},
                        {"conntime", p->peer_uptime_sec()},
                        {"role", "primary"},
                    });
                }
            }
            // (1b) Pooled fork peers with a completed handshake (the coin peer
            // pool: header source, bodies, transactions, won-block relay).
            if (coin_pool) {
                for (const auto& r : coin_pool->rows()) {
                    if (!seen.insert(r.addr).second) continue;
                    arr.push_back({
                        {"addr", r.addr},
                        {"connected", true},
                        {"subver", r.subver},
                        {"startingheight", r.start_height},
                        {"conntime", r.conntime},
                        {"role", "pool"},
                    });
                }
            }
            // (2) Live fan-out slots (handshake-complete NODE_BLAKE2B peers).
            // Surface the slot OBJECT (not just its key) so each fork peer's
            // version-advertised subver/height/uptime render — the same rich
            // fields the primary already shows. The version handler stamps this
            // per slot; for_each_live_slot only reads it (no dial, no mutation).
            if (coin_broadcaster) {
                coin_broadcaster->for_each_live_slot(
                    [&](const std::string& key, const auto& n) {
                        if (!seen.insert(key).second) return;
                        arr.push_back({
                            {"addr", key},
                            {"connected", true},
                            {"subver", n.peer_subver()},
                            {"startingheight", n.peer_start_height()},
                            {"conntime", n.peer_uptime_sec()},
                            {"role", "fanout"},
                        });
                    });
            }
            // (3) Learned fork-mesh breadth (banked, not-currently-primary/fanout).
            if (coin_peer_mgr) {
                for (const auto& [ns, connected] : coin_peer_mgr->peer_directory()) {
                    const std::string key = ns.to_string();
                    if (!seen.insert(key).second) continue;
                    arr.push_back({
                        {"addr", key},
                        {"connected", connected},
                        {"subver", ""},
                        {"startingheight", 0},
                        {"conntime", 0},
                        {"role", "database"},
                    });
                }
            }
            return arr;
        });

        // Miners-Block-Value / Node-Fee cards: daemonless zero-rig projection of
        // the next block's subsidy from the header-follower tip + the ported BTC
        // subsidy formula (same math template_builder.hpp uses). BIP-110 (like
        // BTC) has no treasury / MN split / burn: the whole subsidy is the
        // miners' gross block value. Projection excludes tx fees, flagged
        // block_value_basis="projected" (template_age_sec=-1). NON-fetching read
        // of already-published header state.
        mi->set_coin_work_fn(
            [&header_chain, halving = chain_params.subsidy_halving_interval]()
                -> core::MiningInterface::CoinWorkInfo {
                core::MiningInterface::CoinWorkInfo info;
                const uint32_t tip = header_chain.height();
                if (tip == 0) return info;   // header follower not yet synced
                const uint32_t height = tip + 1;
                info.valid              = true;
                info.projected          = true;
                info.height             = height;
                info.coinbase_value_sat = bip110::coin::get_block_subsidy(height, halving);
                info.payment_amount_sat = 0;
                info.payments_total_sat = 0;
                info.burn_sat           = 0;
                // Coin network difficulty from the chain tip's nBits.
                if (auto t = header_chain.tip())
                    info.network_difficulty =
                        chain::target_to_difficulty(chain::bits_to_target(t->header.m_bits));
                info.template_age_sec = -1;   // projected, no sourced template
                return info;
            });

        // Local hashrate graph + miners/workers table: bridge the stratum worker
        // registry (rigs register on the Bip110WorkSource). Honestly zero until
        // rigs connect. Coin-generic per #1141.
        mi->set_stratum_workers_fn([ws = work_source.get()]() {
            return ws ? ws->snapshot_stratum_workers()
                      : std::map<std::string, core::stratum::WorkerInfo>{};
        });
        mi->set_stratum_hashrate_fn([ws = work_source.get()]() -> double {
            if (!ws) return 0.0;
            double total = 0.0;
            for (auto& [id, w] : ws->snapshot_stratum_workers()) total += w.hashrate;
            return total;
        });

        // FINDING A1 — dashboard sharechain feeds. Under M3 flag-ON the
        // sharechain node EXISTS (sharechain_node != null), so wire the two
        // callbacks rest_sync_status() reads. When they are absent, that handler
        // leaves chain_size / verified_size / has_shares / has_best_share at their
        // 0/false DEFAULTS regardless of the real tracker state — which is exactly
        // the operator's "no bip110 shares even though it is live" symptom (the
        // tracker had grown to height 29 but /web/sync_status reported all zero).
        // Both callbacks read the LOCK-FREE published snapshot (get_tracker_snapshot,
        // set by think() under the exclusive lock) — never the tracker lock and
        // never an off-lock chain walk, so no kr1z1s prune-vs-read UAF. This
        // mirrors main_btc.cpp (chain_height = raw chain_count, not verified), so
        // a single mint flips has_shares=true even before the verified tip settles.
        if (sharechain_node) {
            auto* scn = sharechain_node.get();
            mi->set_sharechain_stats_fn([scn]() -> nlohmann::json {
                auto snap = scn->get_tracker_snapshot();
                nlohmann::json out;
                out["chain_height"]   = snap.chain_count;      // RAW chain size
                out["total_shares"]   = snap.chain_count;
                out["verified_count"] = snap.verified_count;
                out["fork_count"]     = snap.fork_count;
                out["orphan_shares"]  = snap.orphan_shares;
                out["dead_shares"]    = snap.dead_shares;
                // P6 — the LTC-family version tally the Shares-card version line
                // (#share_versions_line: "V36:N | want V36:N") and /version_signaling
                // read. bip110 is NATIVE v36 (every share, own or relayed, is format
                // v36 from genesis — create_local_share stamps share_version=36 and
                // the chain admits no lower version), so the whole raw chain is v36
                // with no walk needed. Emitting these makes all_target=true (correct);
                // it does NOT surface the crossing banner (higher_desired_signalled
                // needs dominant_desired > lowest_share_type, but both are 36) and the
                // V35 caveat stays suppressed by set_native_share_version(true) above.
                // Without these keys the version line rendered BLANK (reads broken).
                const int n = static_cast<int>(snap.chain_count);
                out["chain_length"] = static_cast<int>(
                    bip110::pool::PoolConfig::chain_length());
                out["shares_by_version"]         = nlohmann::json{{"36", n}};
                out["shares_by_desired_version"] = nlohmann::json{{"36", n}};
                return out;
            });
            mi->set_best_share_hash_fn([scn]() -> uint256 {
                return scn->get_tracker_snapshot().best_share;
            });
            // FINDING F1 — reported pool hashrate (dashboard CURRENT/AVERAGE/PEAK,
            // the "Good" graph series, /global_stats.pool_hash_rate, and the CI
            // footer's "reported" value all read m_pool_hashrate_fn via
            // update_stat_log → pool_rates.good). The producer already exists:
            // publish_snapshot() computes TrackerSnapshot.pool_hashrate with the
            // p2pool-exact get_pool_attempts_per_second over TARGET_LOOKBEHIND —
            // a WINDOWED attempts/sec, i.e. already smoothed, so the Good series
            // is a stable line and not per-interval spikes-to-0. It was simply
            // never handed to the web MI, so every sample read the default 0.0 →
            // summary 0 H/s while the node was really minting. Exact BTC/BCH shape
            // (main_btc.cpp:2653, bch/pool_entrypoint.hpp:726). Lock-free snapshot;
            // no tracker lock, no off-lock chain walk. Display/accounting only.
            mi->set_pool_hashrate_fn([scn]() -> double {
                return scn->get_tracker_snapshot().pool_hashrate;
            });
            // 'c2pool Nodes' card + /peer_list + /peer_versions + /pings +
            // /local_stats.connections all read MiningInterface::m_peer_info_fn
            // (web_server.cpp:5358 rest_peer_list, :2121 connections, :5340
            // peer_versions). Under M3 flag-ON the sharechain node has 2+ live
            // ESTABLISHED :9337 links, but the fn was UNWIRED, so /peer_list fell
            // through to nlohmann::json::array() -> the card showed "No peers
            // connected"/badge 0 while genuinely syncing shares. The producer
            // already exists on the sharechain node: get_peer_info_json()
            // (node.hpp:414) returns the IO-thread-published lock-free snapshot
            // (publish_peer_info_snapshot, node.hpp:389) with the exact frontend
            // shape {address,version,incoming,uptime,downtime,web_port}. Reads the
            // published snapshot under m_snapshot_mutex — never the live m_peers
            // map (DASH #828 UAF back-port), never the tracker lock. Byte-parallel
            // to main_dash.cpp:2159 / main_ltc.cpp:3004. Display-only; ZERO consensus.
            mi->set_peer_info_fn([scn]() -> nlohmann::json {
                return scn->get_peer_info_json();
            });
            LOG_INFO << "[EMB-BIP110] dashboard sharechain feeds wired "
                        "(set_sharechain_stats_fn + set_best_share_hash_fn + "
                        "set_pool_hashrate_fn + set_peer_info_fn; lock-free "
                        "snapshot) — chain_size/has_shares/pool_hashrate/peer_list "
                        "now reflect the mint";

            // FINDING P1 — the "Current Payouts" dashboard card. rest_current_
            // payouts() (web_server.cpp:2408) returned {} on bip110 because NONE of
            // its three sources is live on this lane: the #939 direct seam was wired
            // ONLY by DASH (main_dash.cpp:1882), MI stratum is OFF (set_stratum_port
            // (0) above) so MI's refresh_work() never fills the PPLNS cache, and no
            // PayoutManager is set. So the handler fell through all three -> {}, and
            // the card showed "0.0000 BIP110" over an empty ADDRESS/V36?/AMOUNT table
            // even with 196+ shares in the window. Wire the direct seam with the SAME
            // PPLNS SSOT that mints the coinbase — ShareTracker::get_expected_payouts,
            // the exact map the work_source pplns_fn_ (line ~638) already emits — so
            // the card previews the projected NEXT-BLOCK split (subsidy x each
            // address's decayed PPLNS weight, donation residual folded in).
            //
            // READ-ONLY: this REPORTS the split the node would pay; it never touches
            // share_check gentx, build_connection_coinbase, the donation consensus,
            // or any reward path (get_expected_payouts is a const window walk under
            // the read guard). The front-end loadPayouts actually fetches
            // /current_merged_payouts (NOT /current_payouts); that endpoint's
            // main-thread cache pump is dead on bip110, so a cold-cache fallback
            // in rest_current_merged_payouts (web_server.cpp) now wraps THIS seam
            // in the merged shape — see wrap_primary_payouts_as_merged.
            //
            // Nested-lock hazard: read the LOCK-FREE published snapshot best_share
            // BEFORE taking read_tracker() — re-acquiring the tracker's shared_mutex
            // from a thread that already holds it stops being harmless the moment a
            // writer queues (main_dash.cpp:1853-1858). Snapshot is set by think()
            // under the exclusive lock; no off-lock chain walk here.
            // The pool-wide projected PPLNS split — shared by /current_payouts,
            // the main-page treemap (via /current_merged_payouts) and the
            // sharechain window's own `pplns_current` overlay. Hoisted into a
            // named lambda (DASH pattern main_dash.cpp:1856) so the window fn
            // below reuses the EXACT same SSOT walk instead of re-deriving it.
            // Snapshot the LOCK-FREE published best BEFORE read_tracker() — the
            // documented nested shared-lock hazard (main_dash.cpp:1853-1858).
            auto current_pplns =
                [scn, &header_chain,
                 halving = chain_params.subsidy_halving_interval]() -> nlohmann::json {
                    const uint256 best = scn->get_tracker_snapshot().best_share;  // lock-free
                    if (best.IsNull()) return nlohmann::json::object();
                    const uint32_t tip = header_chain.height();
                    if (tip == 0) return nlohmann::json::object();  // header follower cold
                    // Same next-block subsidy projection the Miners-Block-Value card
                    // uses (set_coin_work_fn); bip110 (like BTC) has no treasury/burn,
                    // so the whole subsidy is the miners' gross block value.
                    const uint64_t subsidy = bip110::coin::get_block_subsidy(tip + 1, halving);
                    // v36 ignores block_target (work_source.cpp:345 "pass real"), but
                    // pass the real tip nBits target for correctness/parity.
                    uint256 block_target = uint256::ZERO;
                    if (auto t = header_chain.tip())
                        block_target = chain::bits_to_target(t->header.m_bits);
                    auto guard = scn->read_tracker();
                    if (!guard) return nlohmann::json::object();  // tracker busy -> honest empty
                    return bip110::pool::current_payouts_report(
                        *guard, best, block_target, subsidy,
                        bip110::pool::PoolConfig::get_donation_script(36),
                        bip110::pool::PoolConfig::is_testnet);
                };
            mi->set_current_payouts_fn(current_pplns);
            LOG_INFO << "[EMB-BIP110] /current_payouts seam wired "
                        "(get_expected_payouts projected next-block PPLNS split; "
                        "read-only preview) — 'Current Payouts' card now shows the "
                        "live window split instead of 0.0000/empty";

            // FINDING P2 — the sharechain-transparency EXPLORER and the V36?
            // column. GET /sharechain/window served the stub {shares:[]} because
            // m_sharechain_window_fn was unwired on bip110 (web_server.cpp
            // rest_sharechain_window). The explorer was therefore empty, and the
            // "Current Payouts" card's V36? column stayed blank — it is filled
            // ENTIRELY client-side by getMinerVersion(addr) scanning
            // defrag.shares (= this window) for s.m === addr (dashboard.html).
            // Wire it to the SAME PPLNS SSOT walk /current_payouts uses; the
            // report emits the address form for s.m (so it matches the payout
            // keys and the V36? column fills) and the native share version for
            // s.V. Read-only: a const window walk under the read guard.
            //
            // Nested-lock hazard: snapshot the LOCK-FREE best BEFORE read_tracker(),
            // and call current_pplns() (which takes + releases its OWN guard)
            // BEFORE taking this fn's guard — DASH ordering (main_dash.cpp:1886-1888).
            // The last window served: returned while the tracker is busy, so a
            // refresh that meets a locked tracker does not blank the explorer
            // until the next refresh.
            struct LastWindow { std::mutex m; nlohmann::json j = nlohmann::json::object(); };
            auto last_window = std::make_shared<LastWindow>();
            mi->set_sharechain_window_fn(
                [scn, mi, current_pplns, ws = work_source.get(), last_window]() -> nlohmann::json {
                    const uint256 best = scn->get_tracker_snapshot().best_share;  // lock-free
                    auto cur = current_pplns();          // takes + releases its own guard
                    // Found-block share hashes for the explorer's block marks
                    // (the ledger's own mutex, taken before the tracker guard).
                    std::vector<std::string> found;
                    if (mi)
                        for (const auto& fb : mi->get_found_blocks()) {
                            const std::string sh = mi->found_block_share_hash(fb);
                            if (!sh.empty()) found.push_back(sh);
                        }
                    auto guard = scn->read_tracker();
                    if (!guard) {   // tracker busy -> the last window served
                        std::lock_guard<std::mutex> l(last_window->m);
                        return last_window->j;
                    }
                    std::string fee_hash160 = mi ? mi->get_node_fee_hash160() : std::string{};
                    const bool testnet = bip110::pool::PoolConfig::is_testnet;
                    // "This node" self-identity for the explorer's blue highlight
                    // + This-Node count. The window fn previously left my_address
                    // EMPTY ("every miner authorizes with its own address, so
                    // there is no node-level 'my' address") — but this node's rigs
                    // ARE its local stratum workers, so every share they author IS
                    // this node's. Mark the node-owner/payout address AND every
                    // current stratum worker address blue. Each candidate is
                    // normalized through the SAME script->address encoder the
                    // report uses for s["m"] (address_to_script ->
                    // current_payouts_script_to_address) so the frontend string
                    // compare matches exactly. Display-only: no consensus/coinbase
                    // /PPLNS/wire state is read or written here. LTC ref
                    // main_ltc.cpp:3916-3924 (owner addr); the worker-set union is
                    // the bip110 correction (owner-only would still render 0 blue,
                    // since the window owners are the rig addresses).
                    auto normalize_addr =
                        [testnet](const std::string& a) -> std::string {
                            if (a.empty()) return {};
                            auto script = core::address_to_script(a);
                            if (script.empty()) return {};
                            return bip110::pool::current_payouts_script_to_address(
                                script, testnet);
                        };
                    std::string my_address =
                        normalize_addr(mi ? mi->get_payout_address() : std::string{});
                    nlohmann::json my_addrs = nlohmann::json::array();
                    std::set<std::string> seen;
                    auto add_addr = [&](const std::string& a) {
                        if (!a.empty() && seen.insert(a).second)
                            my_addrs.push_back(a);
                    };
                    add_addr(my_address);
                    if (ws) {
                        for (auto& [id, wi] : ws->snapshot_stratum_workers())
                            add_addr(normalize_addr(wi.username));
                    }
                    auto w = bip110::pool::sharechain_window_report(
                        *guard, best,
                        bip110::pool::PoolConfig::chain_length(),
                        my_address, fee_hash160,
                        testnet, found);
                    if (!my_addrs.empty())
                        w["my_addresses"] = std::move(my_addrs);
                    // Fold the projected split in as the explorer's per-share
                    // PPLNS overlay fallback (dashboard.html getPPLNSForShare
                    // reads window.pplns_current). bip110 has no per-tip PPLNS
                    // cache pump (that DASH path is dead here), so pplns_current
                    // is the overlay source. Read-only.
                    if (cur.is_object() && !cur.empty())
                        w["pplns_current"] = std::move(cur);
                    std::lock_guard<std::mutex> l(last_window->m);
                    last_window->j = w;
                    return w;
                });
            // bip110 has no share-tip refresh event (MI stratum off, no
            // fire_share_tip_refresh), so opt this cache into the periodic
            // fallback refresh (web_server mark_last_cache_tip_driven) — correct
            // cadence for a ~10 s share period.
            mi->mark_last_cache_tip_driven();

            // MI's own window-PPLNS overlay producer (pplns_fn_t). On bip110 its
            // consumers are inert (MI stratum off, no refresh trigger, no
            // m_cached_template), but wire it for LTC/BTC/DASH parity and so the
            // web_server precompute path (should it ever run) has the SSOT split.
            // BTC shape (main_btc.cpp set_pplns_fn) minus the v35/AutoRatchet
            // branch — bip110 is v36-always. Read-only: get_expected_payouts is a
            // const window walk; no coinbase/gentx/reward touched.
            mi->set_pplns_fn(
                [scn](const uint256& best_share_hash,
                      const uint256& block_target,
                      uint64_t subsidy,
                      const std::vector<unsigned char>& donation_script)
                -> std::map<std::vector<unsigned char>, double> {
                    auto guard = scn->read_tracker();
                    if (!guard) return {};
                    try {
                        return guard->get_expected_payouts(
                            best_share_hash, block_target, subsidy, donation_script);
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[EMB-BIP110] web pplns get_expected_payouts threw: "
                                    << e.what();
                        return {};
                    }
                });
            LOG_INFO << "[EMB-BIP110] /sharechain/window + pplns seams wired "
                        "(explorer window walk + V36? column feed + pplns overlay; "
                        "read-only) — explorer/PPLNS-view/V36? now reflect the mint";

            // P5 — hashrate ring + share stats. The tracker FIRES
            // m_on_share_difficulty for every verified share (share_tracker.hpp)
            // with (difficulty, miner). Set once at startup before think()
            // begins; the callback runs under the compute thread's exclusive
            // lock (same as the stats publish), touches no consensus/mint/
            // coinbase state. LTC ref main_ltc.cpp m_on_share_difficulty.
            // A verified share (any member, startup re-verify, catch-up sync)
            // carries its share target, not a hash this node found, so it
            // does not reach the Best Share legs (update_best=false).
            scn->tracker().m_on_share_difficulty =
                [mi](double diff, const std::string& miner) {
                    mi->record_share_difficulty(diff, miner, /*share_hash=*/"",
                                                /*update_best=*/false);
                };

            // P2-remainder — the seams the window+pplns commit left unwired:
            // /sharechain/tip (RealTime SSE poll), /sharechain/delta (incremental
            // stream) and /web/share/<hash> (explorer click-through). Without them
            // the RealTime toggle poll reads a null tip, the SSE never streams new
            // shares, and share.html 404s. Port the LTC feeders, BITCOIN-encoded
            // and native-v36; all walks run under the lock-free read_tracker()
            // guard. Read-only.

            // /sharechain/tip (LTC ref main_ltc.cpp:4082).
            mi->set_sharechain_tip_fn([scn]() -> std::optional<core::SharechainTip> {
                auto guard = scn->read_tracker();
                if (!guard) {
                    auto snap = scn->get_tracker_snapshot();
                    if (snap.chain_count == 0) return std::nullopt;
                    core::SharechainTip t;
                    t.hash   = "";
                    t.height = snap.verified_count > 0
                                   ? static_cast<int64_t>(snap.chain_count) : -1;
                    t.total  = static_cast<int32_t>(snap.chain_count);
                    return t;
                }
                auto& chain = guard->chain;
                uint256 best; int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    (void)tail_hash;
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }
                if (best.IsNull() && chain.size() == 0) return std::nullopt;
                core::SharechainTip t;
                t.hash   = best.IsNull() ? "" : best.GetHex().substr(0, 16);
                t.height = best_height;
                t.total  = static_cast<int>(chain.size());
                return t;
            });

            // /sharechain/delta (LTC ref main_ltc.cpp:4115), no merged arrays.
            mi->set_sharechain_delta_fn([scn, mi](const std::string& since_hash)
                                            -> nlohmann::json {
                auto guard = scn->read_tracker();
                if (!guard) return nlohmann::json::object();
                const bool testnet = bip110::pool::PoolConfig::is_testnet;
                auto& chain    = guard->chain;
                auto& verified = guard->verified;
                std::string fee_addr = mi ? mi->get_node_fee_hash160() : std::string{};

                uint256 best; int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    (void)tail_hash;
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }
                nlohmann::json shares_arr = nlohmann::json::array();
                int count = 0;
                if (!best.IsNull()) {
                    int walk = std::min(static_cast<int>(chain.get_height(best)),
                        static_cast<int>(bip110::pool::PoolConfig::chain_length()));
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
                            auto* idx = chain.get_index(hash);
                            if (idx && idx->is_block_solution) s["blk"] = 1;
                            data.share.invoke([&](auto* obj) {
                                s["t"]  = obj->m_timestamp;
                                s["V"]  = 36;
                                s["s"]  = static_cast<int>(obj->m_stale_info);
                                s["b"]  = obj->m_bits;
                                s["a"]  = obj->m_absheight;
                                s["dv"] = obj->m_desired_version;
                                auto script = bip110::pool::get_share_script(obj);
                                std::string addr =
                                    core::script_to_address(script, false, testnet);
                                s["m"] = addr.empty() ? HexStr(script) : addr;
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
                            if (++count >= 200) break;   // safety cap
                        }
                    } catch (...) {}
                }
                nlohmann::json heads_arr = nlohmann::json::array();
                for (auto& [hh, _] : chain.get_heads())
                    heads_arr.push_back(hh.GetHex().substr(0, 16));
                nlohmann::json blocks_arr = nlohmann::json::array();
                std::vector<std::string> found_full;
                if (mi) for (const auto& fb : mi->get_found_blocks())
                    if (!fb.share_hash.empty()) {
                        blocks_arr.push_back(fb.share_hash.substr(0, 16));
                        found_full.push_back(fb.share_hash);
                    }
                // Full hashes of the found blocks among this delta's new shares
                // (matched on H); omitted when there are none.
                nlohmann::json block_hashes_arr = core::found_block_hashes_in(shares_arr, found_full);

                nlohmann::json result;
                result["shares"] = std::move(shares_arr);
                result["count"]  = count;
                result["tip"]    = best.IsNull() ? "" : best.GetHex().substr(0, 16);
                result["heads"]  = std::move(heads_arr);
                result["blocks"] = std::move(blocks_arr);
                if (!block_hashes_arr.empty())
                    result["block_hashes"] = std::move(block_hashes_arr);
                return result;
            });

            // /web/share/<hash> — DASH-parity RICH detail document (parent/
            // far_parent/type_name/children + local/share_data/block/v36 +
            // pplns), built by bip110::pool::build_share_detail off the SAME
            // sharechain node. Was a reduced 12-key stub that hung share.html
            // (share.parent undefined -> renderShare TypeError -> stuck on
            // "Loading"). READ-ONLY: the builder does const tracker walks only;
            // the found-block enrichment reads MiningInterface::get_found_blocks().
            mi->set_share_lookup_fn([scn, mi](const std::string& hash_hex)
                                        -> nlohmann::json {
                auto guard = scn->read_tracker();
                if (!guard) return nlohmann::json{{"error", "tracker busy"}};
                const bool testnet = bip110::pool::PoolConfig::is_testnet;

                nlohmann::json result = bip110::pool::build_share_detail(
                    *guard, hash_hex,
                    bip110::pool::PoolConfig::get_donation_script(36), testnet);
                if (result.contains("error")) return result;

                if (result.value("is_block_solution", false) && mi) {
                    const std::string hh = result.value("hash", std::string{});
                    for (const auto& fb : mi->get_found_blocks()) {
                        if (fb.hash == hh ||
                            (!fb.share_hash.empty() && fb.share_hash == hh)) {
                            result["block_height"]        = fb.height;
                            result["block_confirmations"] = fb.confirmations;
                            result["block_status"]        = static_cast<int>(fb.status);
                            break;
                        }
                    }
                }
                return result;
            });

            LOG_INFO << "[EMB-BIP110] /sharechain/tip + /sharechain/delta + "
                        "/share/<hash> + best-share difficulty wired — RealTime SSE "
                        "poll, share.html click-through and the Best-Share card now live";
        }

        // All dashboard sharechain feeds are now wired on flag-ON:
        // set_sharechain_stats_fn, set_best_share_hash_fn, set_pool_hashrate_fn,
        // set_peer_info_fn, set_current_payouts_fn, set_sharechain_window_fn and
        // set_pplns_fn. Absent feeds (flag-OFF) render honestly empty — NEVER faked.

        // graph_db-persisted stats history (LTC/BTC parity): namespaced sub-dir.
        {
            std::string graph_db_path = (core::filesystem::config_path()
                / "mainnet" / "bip110" / "graph_db").string();
            std::error_code mkdir_ec;
            std::filesystem::create_directories(
                std::filesystem::path(graph_db_path).parent_path(), mkdir_ec);
            mi->set_stat_log_path(graph_db_path);
            mi->load_stat_log();
            LOG_INFO << "[EMB-BIP110] graph_db stats persistence -> " << graph_db_path;
        }

        // Found-block confirm/orphan telemetry (BTC-shape, main_btc.cpp:3100-3153).
        // TELEMETRY ONLY — the dashboard found-blocks card + /web/share/<hash>
        // (fb.confirmations/fb.status, :2318-2320) go from human-only to
        // instrumented. Isolated-orphan money-risk becomes visible. No consensus,
        // reward, share-validity or wire surface is touched.
        if (mi) {
            // PRODUCER (pairs with the VERDICT fn below): feed the found-block
            // record. Keyed on the BIP-110 block IDENTITY — bip110::coin::block_hash
            // (SHA256d below the fork, BLAKE2b v2 at/after), computed the SAME way
            // header_chain stores block_hash, so the verdict fn resolves this exact
            // row. Reading the leading header off the won block bytes yields the
            // identity. this_node: the stratum work source built + dispatched it.
            *found_block_report =
                [mi](const std::vector<unsigned char>& block_bytes, uint32_t height) {
                    bip110::coin::BlockHeaderType hdr;
                    try {
                        PackStream ps(block_bytes);
                        ps >> hdr;
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[EMB-BIP110] found-block record: header "
                                       "parse failed: " << e.what();
                        return;
                    }
                    const uint256 id = bip110::coin::block_hash(hdr);
                    if (id == uint256::ZERO) return;  // unsupported layout: no key
                    mi->record_found_block(
                        static_cast<uint64_t>(height), id,
                        static_cast<uint64_t>(std::time(nullptr)),
                        /*chain=*/"BIP110", /*miner=*/"",
                        /*share_hash=*/id.GetHex(),
                        mi->get_network_difficulty(), /*share_difficulty=*/0.0,
                        // Pool hashrate 0 -> record_found_block reads the
                        // sharechain pool estimator. This site passed
                        // get_local_hashrate(): this node's OWN stratum rate
                        // in a field named pool_hashrate_at_find, so a
                        // block's luck was measured against one node's
                        // miners, not the pool.
                        /*pool_hashrate=*/0.0, /*subsidy=*/0,
                        core::MiningInterface::BlockAuthorship::this_node);
                    mi->schedule_block_verification(id.GetHex());
                    LOG_INFO << "[EMB-BIP110] recorded found block h=" << height
                             << " id=" << id.GetHex().substr(0, 16)
                             << " -- confirm/orphan poller armed";
                };

            // The block's OWN difficulty and time, by its identity hash, off
            // the embedded header chain: a recorded block's network difficulty
            // is its header's nBits (the record above passes the live
            // template's reading, which record_found_block replaces as soon
            // as the header is held). Display only.
            {
                auto lookups = core::header_chain_block_lookups(&header_chain);
                mi->set_block_field_lookups(lookups.first, lookups.second);
                mi->set_block_height_lookup(core::header_chain_height_lookup(&header_chain));
            }

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
                        int v = bip110::coin::block_confirm::resolve_status(
                            winner_at, header_chain.height(), h, found_height);
                        // Daemonless-first: trust a definite confirmed/orphaned
                        // verdict. A 0 (pending) with the header chain ALREADY past
                        // found_height is a genuine shallow-pending; only fall
                        // through to RPC when the header chain has not yet reached
                        // the height.
                        if (v != 0) return v;
                        if (header_chain.height() >= found_height) return 0;
                    }

                    // Fallback arm (header chain absent or behind): external node
                    // getblockheader confirmations. Returns INT_MIN when no RPC is
                    // configured, so the daemonless arm falls through to pending.
                    int c = coin_node.rpc_block_confirmations(h);
                    if (c != std::numeric_limits<int>::min()) {
                        if (c < 0) return -1;
                        if (c >= static_cast<int>(
                                bip110::coin::block_confirm::kDefaultConfirmDepth))
                            return c;
                    }
                    return 0;  // still pending
                });
            LOG_INFO << "[EMB-BIP110] found-block confirm/orphan lane ARMED "
                     << "(embedded HeaderChain verdict; getblockheader fallback)";
        }

        if (web_server->start()) {
            // Periodic save every 100s on the SAME ioc the run-loop drives.
            stats_timer = std::make_shared<io::steady_timer>(ioc);
            auto save_fn = std::make_shared<std::function<void(boost::system::error_code)>>();
            *save_fn = [stats_timer, save_fn, mi](boost::system::error_code ec) {
                if (ec) return;
                mi->save_stat_log();
                stats_timer->expires_after(std::chrono::seconds(100));
                stats_timer->async_wait(*save_fn);
            };
            stats_timer->expires_after(std::chrono::seconds(100));
            stats_timer->async_wait(*save_fn);
            LOG_INFO << "[EMB-BIP110] dashboard live on http://" << http_host << ":"
                     << http_port << " (coin=BIP110, graph_db persist every 100s).";
        } else {
            LOG_ERROR << "[EMB-BIP110] WebServer FAILED to bind " << http_host << ":"
                      << http_port << " -- dashboard disabled, run-loop continues.";
        }
        } // if (mi != nullptr)
    }
    // HTTP on the stratum port (--stratum-http; auto follows the --http bind).
    if (stratum_server)
        core::configure_stratum_http(*stratum_server, web_server.get(),
                                     core::stratum_http_mode_setting(),
                                     core::stratum_http_limits_setting());
    // The TLS stratum listener (--stratum-tls), when set.
    core::configure_stratum_tls(stratum_server.get(), core::stratum_tls_setting());

    // Periodic tip log — the live-proof capture line.
    auto tip_timer = std::make_shared<io::steady_timer>(ioc);
    auto tip_log = std::make_shared<std::function<void()>>();
    auto tip_ka = tip_timer;
    std::weak_ptr<std::function<void()>> weak_tip = tip_log;
    *tip_log = [tip_timer, weak_tip, &header_chain, &chain_params]() {
        tip_timer->expires_after(std::chrono::seconds(15));
        tip_timer->async_wait([tip_timer, weak_tip, &header_chain, &chain_params]
                              (const boost::system::error_code& ec) {
            if (ec) return;
            auto tip = header_chain.tip();
            const uint32_t h = header_chain.height();
            LOG_INFO << "[EMB-BIP110][TIP] height=" << h
                     << " hash=" << (tip ? tip->block_hash.GetHex() : std::string("null"))
                     << " peer_tip=" << header_chain.peer_tip_height()
                     << " on_blake2b_chain=" << (h >= chain_params.blake2b_height ? "YES" : "no");
            if (auto self = weak_tip.lock()) (*self)();
        });
    };
    (*tip_log)();

    // ── M3: tier-3 resolver pump + mempool-epoch re-job cadence ──────────────
    // Every few seconds: request missing parents (T3), and if the mempool tx-set
    // changed, bump the work generation so stratum re-pushes a template reflecting
    // the new set (BIP-110 freezes the tx set per job — there is no miner-side
    // merkle fold, so a fresh set needs a fresh job).
    if (serve_mempool_txs) {
        // BIP35 pull (skipped if peer !NODE_BLOOM). Pooled fork peers opt in
        // when they are dialed (the coin peer pool's per-peer setup).
        coin_node.enable_mempool_request();
        auto mp_timer = std::make_shared<io::steady_timer>(ioc);
        auto mp_ka = mp_timer;
        auto last_epoch = std::make_shared<uint64_t>(mempool.epoch());
        auto mp_loop = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak_mp = mp_loop;
        *mp_loop = [mp_timer, weak_mp, &mempool, parent_resolver, work_source, last_epoch]() {
            mp_timer->expires_after(std::chrono::seconds(5));
            mp_timer->async_wait([mp_timer, weak_mp, &mempool, parent_resolver, work_source, last_epoch]
                                 (const boost::system::error_code& ec) {
                if (ec) return;
                parent_resolver->pump();
                uint64_t e = mempool.epoch();
                if (e != *last_epoch) { *last_epoch = e; work_source->bump_work_generation(); }
                if (auto self = weak_mp.lock()) (*self)();
            });
        };
        (*mp_loop)();
        // keep the loop alive for the io_context lifetime
        static std::shared_ptr<std::function<void()>> mp_keepalive;
        mp_keepalive = mp_loop;
        (void)mp_ka;
    }

    // ── M3: periodic think/clean tick (5s) + heartbeat (30s) ─────────────────
    // Port of main_ltc.cpp:6685-6723. The bip110 main NEVER scheduled these, so
    // clean_tracker() (stale-head eating, drop-tails pruning, re-score AND — since
    // the desired-republish fix — the parent-share download RE-ARM) simply never
    // ran. On the busy LTC/DASH chains run_think() fires on every share batch and
    // masks the absence; on the quiet bip110 federation nothing re-drove the
    // downloader between share events, so a cold-attach that hit one empty/timed-out
    // round-trip stalled for ~30 min until the next genuinely-new share (the
    // node2 `parents=145` → `parents=3` gap). With the tick wired, the download
    // walk is re-armed every 5s worst case (retry-on-empty covers the ~1s case),
    // and the tracker is finally pruned instead of growing unbounded.
    // Guarded on sharechain_node: flag-OFF (M2, no sharechain) stays a no-op.
    std::shared_ptr<io::steady_timer> think_timer;
    std::shared_ptr<io::steady_timer> hb_timer;
    if (sharechain_node) {
        auto* scn = sharechain_node.get();

        think_timer = std::make_shared<io::steady_timer>(ioc);
        auto think_loop = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak_think = think_loop;
        *think_loop = [think_timer, weak_think, scn]() {
            think_timer->expires_after(std::chrono::seconds(5));
            think_timer->async_wait([think_timer, weak_think, scn]
                                    (const boost::system::error_code& ec) {
                if (ec) return;
                try {
                    scn->clean_tracker();
                } catch (const std::exception& e) {
                    LOG_ERROR << "[EMB-BIP110][CLEAN-TRACKER] error: " << e.what();
                } catch (...) {
                    LOG_ERROR << "[EMB-BIP110][CLEAN-TRACKER] unknown error";
                }
                if (auto self = weak_think.lock()) (*self)();
            });
        };
        (*think_loop)();
        static std::shared_ptr<std::function<void()>> think_keepalive;
        think_keepalive = think_loop;

        hb_timer = std::make_shared<io::steady_timer>(ioc);
        auto hb_loop = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak_hb = hb_loop;
        *hb_loop = [hb_timer, weak_hb, scn]() {
            hb_timer->expires_after(std::chrono::seconds(30));
            hb_timer->async_wait([hb_timer, weak_hb, scn]
                                 (const boost::system::error_code& ec) {
                if (ec) return;
                try { scn->heartbeat_log(); } catch (...) {}
                if (auto self = weak_hb.lock()) (*self)();
            });
        };
        (*hb_loop)();
        static std::shared_ptr<std::function<void()>> hb_keepalive;
        hb_keepalive = hb_loop;

        LOG_INFO << "[EMB-BIP110] sharechain think/clean tick (5s) + heartbeat (30s) armed";
    }

    io::signal_set signals(ioc, SIGINT, SIGTERM);
    // FINDING C — graceful-shutdown flush. NodeImpl::shutdown() flushes the
    // pending verified/removal buffers to LevelDB (and cancels the periodic flush
    // timer). It existed but was NEVER called — the handler only did ioc.stop(),
    // so a clean SIGTERM lost every verified share minted since the last flush.
    // Flag-OFF: sharechain_node is null, so this is a no-op (M2 unchanged). The
    // capture keeps a shared_ptr copy so the node outlives the flush call.
    signals.async_wait([&ioc, sharechain_node](const boost::system::error_code&, int) {
        LOG_INFO << "[EMB-BIP110] shutdown signal — stopping";
        if (sharechain_node)
            sharechain_node->shutdown();
        ioc.stop();
    });

    LOG_INFO << "[EMB-BIP110] entering io loop";
    ioc.run();
    (void)keepalive; (void)tip_ka; (void)resolve_keepalive;
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    // SHA-256 implementation (SSE4 / AVX2 / SHA-NI when the CPU has them),
    // self-tested, before any thread starts: core/sha256_init.hpp.
    core::init_sha256();
    bool selftest = true;
    bool run = false;
    bool coin_p2p_discover = false;
    std::string coin_externalip;   // --coin-externalip: self-advertise override
    bool fork_checkpoint = false;
    std::string http_host = "0.0.0.0";
    uint16_t http_port = 0;
    uint16_t stratum_port = 9336;  // BIP-110 Stratum port (params.hpp worker_port)
    std::string stratum_addr = "0.0.0.0";  // listen all interfaces by default
    std::string donation_address;  // operator-provided node-owner/donation address
    std::vector<NetService> explicit_peers;
    // ── SHARECHAIN (pool-P2P, :9337) explicit peer override (--sharechain-addnode
    // HOST:PORT, repeatable). This is a DIFFERENT layer from --peer (coin-P2P fork
    // peers on 8333/9333): when non-empty it OVERRIDES the OurBeacon default seed
    // list (config_pool.hpp DEFAULT_BOOTSTRAP_HOSTS), dialing ONLY these hosts.
    // Unified TOML key: sharechain.addnodes (param_catalog.inc). Mirrors main_btc. ──
    std::vector<std::pair<std::string, uint16_t>> sharechain_addnodes;

    // ── REWARD SPLIT L0 (resolved config): author/dev donation percent and the
    // node-owner fee percent read from the settings catalog defaults (mirrors
    // main_ltc/main_dash). money.give_author_pct is a FROM_POOL_CONFIG row filled
    // by impl/bip110/catalog_defaults.hpp (0.1%); money.node_owner_fee_pct is the
    // LIT "0" catalog row seeded by seed_compiled_defaults. CLI flags below win. ──
    double give_author_pct   = 0.1;   // HARD RULE: author-fee default = 0.1%
    double node_owner_fee_pct = 0.0;  // node-owner fee default = 0
    // M3 good-citizen mandate: include REAL network txs by default (never mine
    // coinbase-only EMPTY blocks while the fork network has pending txs). Money
    // path — --no-serve-mempool-txs is the canary escape hatch back to M2.
    bool serve_mempool_txs = true;
    // ── M3 SHARECHAIN MINT arm (DEFAULT OFF). The mint/sharechain node only
    // starts with --bip110-sharechain; absent, the binary is the M2 header-
    // follower byte-for-byte. IRREVERSIBLE first-outbound is behind this flag. ──
    bool sharechain_enabled = false;
    // Explorer /api/explorer surface (default ON — loopback-only + read-only, so
    // exposing it is safe; --no-explorer disables both the gate and raw-block
    // retention). Consumed by explorer.py --coin bip110 --c2pool ...
    bool explorer_enabled = true;
    {
        namespace cs = c2pool::settings;
        cs::ResolvedConfig rc;
        rc.seed_compiled_defaults(c2pool::catalog::C_BIP110);
        c2pool::impl::bip110::register_catalog_defaults(rc);
        give_author_pct    = rc.get_double("money.give_author_pct").value_or(give_author_pct);
        node_owner_fee_pct = rc.get_double("money.node_owner_fee_pct").value_or(node_owner_fee_pct);
    }

    auto parse_hostport = [](const std::string& v, std::string& h, uint16_t& p) {
        auto c = v.rfind(':');
        if (c == std::string::npos) { p = static_cast<uint16_t>(std::stoi(v)); }
        else { h = v.substr(0, c); p = static_cast<uint16_t>(std::stoi(v.substr(c + 1))); }
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--version") {   // tls=: the TLS stratum listener is built in (on) or not
            std::printf("c2pool-bip110 %s tls=%s\n", C2POOL_VERSION, core::stratum_tls_supported() ? "on" : "off");
            return 0;
        }
        if (arg == "--help" || arg == "-h") { print_banner(argv[0]); return 0; }
        else if (arg == "--selftest") { selftest = true; run = false; }
        else if (arg == "--run") { run = true; selftest = false; }
        else if (arg == "--coin-p2p-discover") { coin_p2p_discover = true; }
        else if (arg == "--coin-externalip" && i + 1 < argc) {
            // Operator-pinned reachable IP for self-address advertisement (Knots
            // -externalip). Optional: peer-echo scoring auto-discovers it on a
            // no-NAT host; this override wins when set. Bare IP (no port — the
            // listen port 8333 is substituted).
            coin_externalip = argv[++i];
        }
        else if (arg == "--fork-checkpoint") { fork_checkpoint = true; }
        else if (arg == "--peer" && i + 1 < argc) {
            std::string host = "127.0.0.1"; uint16_t port = 8333;
            parse_hostport(argv[++i], host, port);
            explicit_peers.emplace_back(host, port);
        }
        else if (arg == "--http" && i + 1 < argc) {
            parse_hostport(argv[++i], http_host, http_port);
        }
        else if (arg == "--stratum" && i + 1 < argc) {
            // --stratum [HOST:]PORT — bind a stratum TCP listener for miners.
            // HOST defaults to 0.0.0.0 (all interfaces). Mirrors main_btc.cpp /
            // main_dgb.cpp so the standard `--stratum 0.0.0.0:9336` form parses
            // the port correctly (bare std::stoi stopped at the first '.',
            // yielding 0 and silently disabling the listener). A bare `--stratum
            // 9336` is still accepted.
            std::string ep = argv[++i];
            auto colon = ep.find(':');
            if (colon == std::string::npos) {
                stratum_port = static_cast<uint16_t>(std::stoi(ep));
            } else {
                stratum_addr = ep.substr(0, colon);
                stratum_port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
            }
        }
        else if (arg == "--no-stratum") { stratum_port = 0; }
        else if (arg == "--analytics-id" && i + 1 < argc) {
            if (!core::parse_analytics_id(argv[++i], core::analytics_id_setting())) {
                std::fprintf(stderr, "bad value: --analytics-id %s (expected a Google Analytics "
                                     "measurement ID, G-XXXXXXXXXX)\n", argv[i]);
                return 1;
            }
        }
        else if (arg == "--stratum-http" || arg.rfind("--stratum-http=", 0) == 0) {
            // the web API on the stratum port too (core/stratum_http.hpp)
            if (!core::parse_stratum_http_flag(arg, core::stratum_http_mode_setting())) {
                std::fprintf(stderr, "bad value: %s (expected --stratum-http=true, false or auto)\n",
                             arg.c_str());
                return 1;
            }
        }
        // --stratum-http-budget N / --stratum-http-per-ip N (core/stratum_http.hpp).
        else if (arg == "--stratum-http-budget" && i + 1 < argc) {
            if (!core::parse_stratum_http_count(argv[++i], core::stratum_http_limits_setting().budget)) {
                std::fprintf(stderr, "bad value: --stratum-http-budget %s (expected a count)\n", argv[i]);
                return 1;
            }
        }
        else if (arg == "--stratum-http-per-ip" && i + 1 < argc) {
            if (!core::parse_stratum_http_count(argv[++i], core::stratum_http_limits_setting().per_ip)) {
                std::fprintf(stderr, "bad value: --stratum-http-per-ip %s (expected a count)\n", argv[i]);
                return 1;
            }
        }
        // --stratum-tls [HOST:]PORT / --stratum-tls-cert FILE / --stratum-tls-key
        // FILE: the TLS stratum listener (core/stratum_tls.hpp); checked once
        // every flag is read (check_stratum_tls_settings).
        else if (arg == "--stratum-tls" && i + 1 < argc) {
            core::stratum_tls_setting().bind = argv[++i];
        }
        else if (arg == "--stratum-tls-cert" && i + 1 < argc) {
            core::stratum_tls_setting().cert = argv[++i];
        }
        else if (arg == "--stratum-tls-key" && i + 1 < argc) {
            core::stratum_tls_setting().key = argv[++i];
        }
        else if ((arg == "--stratum-tls-rate-per-ip" || arg == "--stratum-tls-burst-per-ip"
                  || arg == "--stratum-tls-handshakes" || arg == "--stratum-tls-handshakes-per-ip")
                 && i + 1 < argc) {
            std::string err;
            if (!core::parse_stratum_tls_limit_flag(arg, argv[++i], core::stratum_tls_setting(), err)) {
                std::fprintf(stderr, "c2pool-bip110: %s\n", err.c_str());
                return 1;
            }
        }
        else if ((arg == "--node-owner-address" || arg == "--donation") && i + 1 < argc) {
            donation_address = argv[++i];
        }
        // Money-class CLI flags (CLI wins over the catalog L0 defaults above).
        else if ((arg == "--give-author" || arg == "--dev-donation") && i + 1 < argc) {
            give_author_pct = std::stod(argv[++i]);
        }
        else if ((arg == "--fee" || arg == "-f") && i + 1 < argc) {
            node_owner_fee_pct = std::stod(argv[++i]);
        }
        else if (arg == "--serve-mempool-txs") { serve_mempool_txs = true; }
        else if (arg == "--no-serve-mempool-txs") { serve_mempool_txs = false; }
        else if (arg == "--bip110-sharechain") { sharechain_enabled = true; }
        else if (arg == "--explorer") { explorer_enabled = true; }
        else if (arg == "--no-explorer") { explorer_enabled = false; }
        else if (arg == "--sharechain-addnode" && i + 1 < argc) {
            // --sharechain-addnode HOST:PORT — repeatable. Explicit sharechain
            // (pool-P2P, :9337) peer override; overrides the OurBeacon default
            // seed list. Mirrors main_btc.cpp --sharechain-addnode.
            std::string ep = argv[++i];
            auto colon = ep.rfind(':');
            if (colon == std::string::npos) {
                std::fprintf(stderr, "--sharechain-addnode requires HOST:PORT\n");
                return 1;
            }
            sharechain_addnodes.emplace_back(
                ep.substr(0, colon),
                static_cast<uint16_t>(std::stoi(ep.substr(colon + 1))));
        }
    }

    // --stratum-tls / --stratum-tls-cert / --stratum-tls-key: a complete set
    // this build supports, whose certificate and key load; else refused here.
    if (auto why = core::check_stratum_tls_settings(core::stratum_tls_setting())) {
        std::fprintf(stderr, "c2pool-bip110: %s\n", why->c_str());
        return 1;
    }
    if (!run && core::stratum_tls_setting().any_set())
        std::fprintf(stderr, "c2pool-bip110: warning: --stratum-tls has no effect without --run (no stratum listener)\n");

    if (run) {
        if (!coin_p2p_discover && explicit_peers.empty()) {
            // Default to discovery so `--run` alone still finds fork peers.
            coin_p2p_discover = true;
        }
        return run_embedded(coin_p2p_discover, explicit_peers, fork_checkpoint, http_host, http_port, stratum_addr, stratum_port, donation_address, give_author_pct, node_owner_fee_pct, serve_mempool_txs, sharechain_enabled, sharechain_addnodes, explorer_enabled, coin_externalip);
    }

    print_banner(argv[0]);
    std::printf("\n");
    return run_selftest();
}
