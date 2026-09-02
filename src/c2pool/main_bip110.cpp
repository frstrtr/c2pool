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

#include <impl/bip110/params.hpp>
#include <impl/bip110/pow.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/template_builder.hpp>  // get_block_subsidy (dashboard block-value projection)
#include <impl/bip110/coin/node.hpp>
#include <impl/bip110/coin/node_interface.hpp>
#include <impl/bip110/coin/coin_peer_manager.hpp>
#include <impl/bip110/coin/broadcaster.hpp>        // M3 PR-C2 NODE_BLAKE2B fan-out pool
#include <impl/bip110/coin/broadcaster_full.hpp>   // M3 PR-C2 found-block keystone
#include <impl/bip110/coin/chain_seeds.hpp>
#include <impl/bip110/coin/mempool.hpp>            // M3 daemonless tx-serving
#include <impl/bip110/coin/parent_tx_resolver.hpp> // M3 tier-3 input pricing
#include <impl/bip110/coin/utxo_reorg.hpp>         // GAP4 reorg-blindness fix
#include <impl/bip110/stratum/work_source.hpp>

// ── M3 sharechain MINT lane (behind --bip110-sharechain; default OFF) ────────
#include <impl/bip110/pool/node.hpp>               // bip110::pool::Node / Config
#include <impl/bip110/pool/config_pool.hpp>        // PoolConfig SSOT (P2P_PORT 9337, STALE_SHARES)
#include <impl/bip110/pool/share_check.hpp>        // bip110::pool::create_local_share (MINT)

#include <core/coin/utxo_view_db.hpp>              // M3 own-UTXO view (T2 pricing)
#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>
#include <core/address_utils.hpp>
#include <core/netaddress.hpp>
#include <core/stratum_server.hpp>
#include <core/web_server.hpp>              // shared coin-generic dashboard + /node_info
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
#include <memory>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace io = boost::asio;

namespace {

// Standalone header-sync driver cadence (file-scope so the nested async lambdas
// use them as constant expressions without an explicit capture).
constexpr int kTickSec = 10;
constexpr int kNoProgressFailoverSec = 40;

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
                 const std::vector<std::pair<std::string, uint16_t>>& sharechain_addnodes)
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

    // ── M3 PR-C2 addrman-backed FOUND-BLOCK fan-out (behind --bip110-sharechain;
    // DEFAULT OFF) ───────────────────────────────────────────────────────────
    // Declared at run_embedded scope so they outlive work_source / the stratum
    // server / ioc.run(). Constructed ONLY on the flag-ON path, AFTER coin_peer_mgr
    // exists (the NODE_BLAKE2B addrman that feeds the fan-out slot set). With the
    // flag OFF both stay null and stratum_submit_fn calls
    // coin_node.submit_block_with_fallback directly — byte-identical to M2.
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

    // ── M2 MINING: stratum server + BLAKE2b Sv1 work source (miner-facing) ──
    // submit_block_fn relays a won 164-byte v2 block to the FORK peers over the
    // coin P2P (submit_block_with_fallback: P2P relay + optional submitblock RPC
    // backup). The work source serves coinbase-only jobs, validates shares with
    // an independent BLAKE2b recompute, and dispatches block-target hits here.
    auto stratum_submit_fn =
        [&coin_node, &coin_broadcaster_full](const std::vector<unsigned char>& block_bytes,
                                             uint32_t height) -> bool {
            LOG_INFO << "[EMB-BIP110] submitting won block height=" << height
                     << " bytes=" << block_bytes.size();
            // FLAG-ON: route through the found-block keystone — ARM A fans the
            // block to every live NODE_BLAKE2B fan-out peer, ARM B is the same
            // coin_node.submit_block_with_fallback (primary relay + optional RPC).
            // FLAG-OFF: coin_broadcaster_full is null -> the single M2 call,
            // byte-identical to today.
            if (coin_broadcaster_full)
                return coin_broadcaster_full->on_block_found(block_bytes).reached_network();
            return coin_node.submit_block_with_fallback(block_bytes);
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
    std::atomic<bool> utxo_consistent{true};
    work_source->set_mempool(&mempool, serve_mempool_txs,
        [&header_chain, &utxo_consistent]() {
            return utxo_consistent.load(std::memory_order_relaxed)
                && header_chain.height() >= header_chain.params().blake2b_height;
        });
    LOG_INFO << "[EMB-BIP110] mempool tx-serving "
             << (serve_mempool_txs ? "ENABLED" : "DISABLED (coinbase-only)")
             << " — daemonless ingest+price+select+xcheck";

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
    // FINDING B (core UAF, class of #759): hold the sharechain node as a
    // shared_ptr (NOT unique_ptr). core::Client::resolve()/connect_socket() guard
    // the async dial teardown race with node->weak_from_this() — but for an
    // UNMANAGED (unique_ptr) node weak_from_this() is empty, was_managed=false,
    // and the guard is a NO-OP, so make_socket() dynamic_casts a DANGLING node on
    // teardown → SEGV. make_shared enrolls the enable_shared_from_this control
    // block, so weak_from_this() is real and the guard fires (clean dial abort).
    // Flag-ON exercises this hard (beacon :9337 self-dial + coin-P2P + ioc.stop()
    // mid-resolve). All .get() call sites below are unchanged.
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

        sharechain_node = std::make_unique<bip110::pool::Node>(&ioc, sharechain_cfg.get());
        auto* node_raw  = sharechain_node.get();

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
        node_raw->set_on_best_share_changed([node_raw]() {
            if (!node_raw) return;
            node_raw->broadcast_share(node_raw->best_share_hash());
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
    coin_node.full_block.subscribe(
        [&header_chain, &utxo_cache, &utxo_db, &mempool, bip110_txid, BIP110_KEEP_DEPTH]
        (const bip110::coin::BlockType& block)
        {
            auto packed_hdr = pack(static_cast<const bip110::coin::BlockHeaderType&>(block));
            uint256 block_hash = Hash(packed_hdr.get_span());
            auto entry = header_chain.get_header(block_hash);
            if (!entry) return;                     // header sync lagging — drop
            uint32_t height = entry->height;
            if (height <= utxo_cache.get_best_height()) return;   // monotonic
            // GAP4 continuity gate: only connect a block that extends the current
            // view tip. A non-contiguous block means a reorg is pending — the
            // tip-changed handler rolls the view back to the fork first, then the
            // new branch re-connects contiguously from fork+1. Skip (named) here.
            {
                uint256 view_best = utxo_cache.get_best_block();
                if (!view_best.IsNull() && block.m_previous_block != view_best) {
                    LOG_WARNING << "[EMB-BIP110] utxo-connect skipped: non-contiguous "
                                   "(reorg pending) h=" << height
                                << " prev=" << block.m_previous_block.GetHex().substr(0, 16)
                                << " view_best=" << view_best.GetHex().substr(0, 16);
                    return;
                }
            }
            try {
                auto undo = utxo_cache.connect_block(block, height, bip110_txid);
                utxo_db.put_block_undo(height, undo);
                utxo_cache.flush(block_hash, height);
                utxo_cache.prune_undo(height, BIP110_KEEP_DEPTH);
                mempool.set_tip_height(height);
                LOG_INFO << "[EMB-BIP110] UTXO connect: h=" << height
                         << " txs=" << block.m_txs.size()
                         << " best_height=" << utxo_cache.get_best_height();
            } catch (const std::exception& e) {
                LOG_WARNING << "[EMB-BIP110] UTXO connect_block failed h=" << height
                            << ": " << e.what();
            }
        });

    // ── GAP4 UTXO-view reorg handling ───────────────────────────────────────
    // On a fork-chain reorg the header chain fires on_tip_changed. If the view's
    // best is already on the new chain this is a plain extension (no-op — the
    // connect handler applies the new blocks). Otherwise the view is on an
    // abandoned branch: flag it inconsistent (serve coinbase-only), roll the view
    // back to the common ancestor via undo data (removing rolled-back coins;
    // fail-closed on missing/too-deep undo), requarantine + re-price the mempool
    // against the reconciled view, then clear the flag. A rolled-back coin can
    // NEVER be priced/included afterwards (GAP2's inclusion rule is the 2nd wall).
    header_chain.set_on_tip_changed(
        [&utxo_cache, &utxo_db, &header_chain, &mempool, &utxo_consistent, BIP110_KEEP_DEPTH]
        (const uint256& /*old_tip*/, uint32_t old_h, const uint256& new_tip, uint32_t new_h)
        {
            uint256  view_best = utxo_cache.get_best_block();
            uint32_t view_h    = utxo_cache.get_best_height();
            if (view_best.IsNull()) return;    // nothing connected yet
            auto active_at = header_chain.get_header_by_height(view_h);
            if (active_at && active_at->block_hash == view_best)
                return;                        // view already on the new chain — plain extension

            utxo_consistent.store(false, std::memory_order_relaxed);
            auto res = bip110::coin::reorg_disconnect_to_fork(
                utxo_cache, utxo_db, header_chain, new_tip, BIP110_KEEP_DEPTH);
            if (res != bip110::coin::ReorgResult::OK) {
                LOG_ERROR << "[EMB-BIP110] UTXO reorg FAILED ("
                          << bip110::coin::reorg_result_name(res) << ") old_h=" << old_h
                          << " new_h=" << new_h << " — serving coinbase-only until view "
                             "rebuild (fail closed, never a wrong ledger)";
                return;   // leave utxo_consistent=false (until restart / rebuild)
            }
            mempool.requarantine_all();
            mempool.set_tip_height(utxo_cache.get_best_height());
            mempool.recompute_unknown_fees(&utxo_cache);
            mempool.revalidate_inputs(&utxo_cache);
            utxo_consistent.store(true, std::memory_order_relaxed);
            LOG_INFO << "[EMB-BIP110] UTXO reorg reconciled to fork h="
                     << utxo_cache.get_best_height() << " (new tip h=" << new_h << ")";
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
    auto parent_resolver = std::make_shared<bip110::coin::ParentTxResolver>(
        mempool, [&coin_node](const std::vector<uint256>& txids) {
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

    // Peer discovery + explicit peers -> a shared candidate dialer with failover.
    std::unique_ptr<bip110::coin::BtcCoinPeerManager> coin_peer_mgr;
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

    // ── Knots peer-discovery wiring (getaddr crawl + addr ingest + scorer
    // feedback), ported from Bitcoin Knots net/net_processing. The PRIMARY
    // coin-P2P arm now (1) sends getaddr on connect, (2) banks the NODE_BLAKE2B-
    // filtered addr gossip into the bucketed addrman (source-group keyed), and
    // (3) feeds connect / disconnect / dial-failure back to the scorer so the
    // tried table fills. Without this the embedded node latched at the single
    // oracle peer and never grew (dashboard "CONNECTIONS 1 Active/Target").
    // Stored on the coin Node and re-applied to every start_p2p() redial. ───────
    if (coin_peer_mgr) {
        auto* mgr = coin_peer_mgr.get();
        coin_node.enable_getaddr_discovery();
        coin_node.set_addr_callback(
            [mgr](const std::vector<NetService>& addrs, const NetService& source) {
                for (const auto& a : addrs)
                    mgr->add_discovered_peer(a, source.address());
            });
        coin_node.set_on_peer_connected(
            [mgr](const NetService& s) { mgr->notify_connected(s.to_string()); });
        coin_node.set_on_peer_disconnected(
            [mgr](const NetService& s) { mgr->notify_disconnected(s.to_string()); });
        coin_node.set_on_dial_failed(
            [mgr](const NetService& s) { mgr->notify_dial_failed(s.to_string()); });
        LOG_INFO << "[EMB-BIP110] Knots peer crawl wired (primary arm): "
                    "getaddr-on-connect + NODE_BLAKE2B addr ingest + scorer feedback";
    }

    // Round-robin dialer over explicit peers + the discovered set. Redials the
    // next candidate whenever the handshake is not complete (a non-fork peer is
    // dropped at the NODE_BLAKE2B version gate and we walk on).
    auto explicit_list = std::make_shared<std::vector<NetService>>(explicit_peers);
    auto explicit_idx  = std::make_shared<size_t>(0);
    auto tried = std::make_shared<std::set<std::string>>();
    auto dial_next = [&coin_node, &coin_peer_mgr, explicit_list, explicit_idx, tried]() -> bool {
        // Prefer explicit peers first (round-robin), then discovered candidates.
        if (!explicit_list->empty()) {
            NetService ep = (*explicit_list)[(*explicit_idx)++ % explicit_list->size()];
            LOG_INFO << "[EMB-BIP110] dialing explicit fork peer " << ep.to_string();
            coin_node.start_p2p(ep);
            return true;
        }
        if (coin_peer_mgr) {
            auto cands = coin_peer_mgr->get_peers_to_connect(*tried);
            if (cands.empty()) { tried->clear(); cands = coin_peer_mgr->get_peers_to_connect(*tried); }
            if (cands.empty()) {
                LOG_WARNING << "[EMB-BIP110] no fork peers to dial yet";
                return false;
            }
            const auto& ep = cands.front();
            tried->insert(ep.to_string());
            LOG_INFO << "[EMB-BIP110] dialing discovered fork peer " << ep.to_string();
            coin_node.start_p2p(ep.to_net_service());
            return true;
        }
        return false;
    };
    dial_next();

    // ── M3 PR-C2: construct the addrman-backed FOUND-BLOCK fan-out pool + the
    // found-block keystone (flag-ON only). Placed AFTER coin_peer_mgr (the
    // NODE_BLAKE2B addrman) and dial_next (the primary is now dialing). With the
    // flag OFF this whole block is skipped: coin_broadcaster* stay null and
    // stratum_submit_fn keeps calling coin_node.submit_block_with_fallback —
    // byte-identical to M2. ─────────────────────────────────────────────────────
    std::shared_ptr<io::steady_timer> broadcaster_timer;
    if (sharechain_enabled) {
        constexpr size_t kFanoutMaxPeers = 8;
        coin_broadcaster = std::make_unique<bip110::coin::Bip110Broadcaster<MiniConfig>>(
            &ioc,
            static_cast<bip110::interfaces::Node*>(&coin_node),
            &config,
            kFanoutMaxPeers);
        coin_broadcaster_full =
            std::make_unique<bip110::coin::Bip110BroadcasterFull<MiniConfig>>(
                coin_broadcaster.get());
        // ARM B — the standing primary sink (M2 path: primary coin-P2P relay +
        // optional submitblock RPC backup). Never masked by ARM A.
        coin_broadcaster_full->set_primary_submit(
            [&coin_node](const std::vector<unsigned char>& b) {
                return coin_node.submit_block_with_fallback(b);
            });
        // Wire the SAME Knots peer-discovery seams onto every fan-out slot, so a
        // fan-out peer's addr gossip ALSO grows the shared addrman + tried set
        // (not just the primary arm). Only when the scored peer manager exists.
        if (coin_peer_mgr) {
            auto* mgr = coin_peer_mgr.get();
            coin_broadcaster->set_slot_configurator(
                [mgr](bip110::coin::p2p::NodeP2P<MiniConfig>& slot) {
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
                    explicit_list]() {
            std::vector<NetService> targets;
            // Explicit fork peers first (the operator's pinned NODE_BLAKE2B set).
            for (const auto& ep : *explicit_list) targets.push_back(ep);
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
                std::set<std::string> none;
                for (const auto& ep : coin_peer_mgr->get_peers_to_connect(none))
                    targets.push_back(ep.to_net_service());
            }
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

    // Self-rescheduling driver: (re)issue getheaders on a fresh handshake or a
    // stall, and fail over to the next candidate after no header progress.
    auto last_height   = std::make_shared<uint32_t>(header_chain.height());
    auto last_progress = std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());
    auto was_handshaked = std::make_shared<bool>(false);
    auto timer = std::make_shared<io::steady_timer>(ioc);
    auto driver = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak_driver = driver;
    auto keepalive = driver;  // outlive this scope
    *driver = [timer, weak_driver, &coin_node, &header_chain, &chain_params,
               dial_next, hdr_caught_up, last_height, last_progress, was_handshaked]() {
        timer->expires_after(std::chrono::seconds(kTickSec));
        timer->async_wait([timer, weak_driver, &coin_node, &header_chain, &chain_params,
                           dial_next, hdr_caught_up, last_height, last_progress, was_handshaked]
                          (const boost::system::error_code& ec) {
            if (ec) return;
            const uint32_t h = header_chain.height();
            const bool handshaked = coin_node.is_handshake_complete();
            const bool caught_up = *hdr_caught_up;
            const auto now = std::chrono::steady_clock::now();
            const bool advanced = (h > *last_height);
            if (advanced) { *last_height = h; *last_progress = now; }

            auto send_locator = [&]() {
                uint256 loc;
                if (auto tip = header_chain.tip(); tip) loc = tip->block_hash;
                else loc = chain_params.genesis_hash;
                LOG_INFO << "[EMB-BIP110] getheaders locator=" << loc.GetHex().substr(0, 16)
                         << " height=" << h << (h >= chain_params.blake2b_height ? " [on BLAKE2b fork]" : "");
                coin_node.send_getheaders(70016, {loc}, uint256::ZERO);
            };
            if (handshaked && !caught_up) {
                if (!*was_handshaked || !advanced) send_locator();
            }
            *was_handshaked = handshaked;

            if (!caught_up && now - *last_progress >= std::chrono::seconds(kNoProgressFailoverSec)) {
                LOG_INFO << "[EMB-BIP110] no header progress for " << kNoProgressFailoverSec
                         << "s (height=" << h << ", handshaked=" << handshaked << ") — failover";
                dial_next();
                *last_progress = now;
                *was_handshaked = false;
            }
            if (auto self = weak_driver.lock()) (*self)();
        });
    };
    (*driver)();

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
#ifdef C2POOL_VERSION
        mi->set_pool_version("c2pool/" C2POOL_VERSION);
#endif
        mi->set_io_context(&ioc);
        mi->set_dashboard_always_ready(true);   // load-bearing on a NULL IMiningNode
        // Advertise real runtime ports on /node_info. BIP-110 has no inbound
        // sharechain P2P listener (fork peers are dialed outbound), so p2p_port
        // is honestly 0; the stratum bind is the worker port.
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
        mi->set_p2p_port(0);
        // Point static serving at the on-disk frontend (CWD-relative, same as
        // btc/dgb): "/" -> web-static/dashboard.html. The deploy pairs a
        // web-static copied from THIS commit next to the binary/CWD.
        web_server->set_dashboard_dir("web-static");
        // Node fee card — configured node-owner fee percent.
        mi->set_pool_fee_percent(node_owner_fee_pct);

        // Node topology card: embedded SPV follower state + the old StatusHttp
        // fork fields (blake2b_height / on_blake2b_chain) find their honest new
        // home here. Mirror of main_btc.cpp node_topology_fn.
        mi->set_node_topology_fn([&header_chain, &coin_node, &chain_params]() {
            const uint32_t synced   = header_chain.height();
            const uint32_t peer_tip = header_chain.peer_tip_height();
            const bool     emb_p2p  = coin_node.has_p2p();
            const bool     ext_rpc  = coin_node.has_rpc();
            return nlohmann::json{
                {"coin", "BIP110"},
                {"embedded", true},
                {"has_rpc", ext_rpc},
                {"synced_height", synced},
                {"peer_tip_height", peer_tip},
                {"sync_pct", (peer_tip > 0 ? 100.0 * synced / peer_tip : 0.0)},
                {"embedded_peers", emb_p2p ? 1 : 0},
                {"broadcast_route", emb_p2p ? "p2p" : (ext_rpc ? "rpc" : "none")},
                {"blake2b_height", chain_params.blake2b_height},
                {"on_blake2b_chain", synced >= chain_params.blake2b_height},
            };
        });

        // Coin sync-status cards: feed /broadcaster_status header_height/
        // target_height + the single embedded fork peer's version-advertised
        // tip so the sync cards render the REAL BIP-110 header tip. Mirror of
        // main_btc.cpp coin_sync_status_fn.
        mi->set_coin_sync_status_fn([&header_chain, &coin_node]() -> nlohmann::json {
            nlohmann::json s = nlohmann::json::object();
            const uint32_t hh = header_chain.height();
            uint32_t th = header_chain.peer_tip_height();
            nlohmann::json peers = nlohmann::json::array();
            auto* p2p = coin_node.p2p();
            if (p2p != nullptr && p2p->peer_version() > 0) {
                const uint32_t sh = p2p->peer_start_height();
                if (sh > th) th = sh;
                peers.push_back({
                    {"subver", p2p->peer_subver()},
                    {"startingheight", sh},
                    {"conntime", p2p->peer_uptime_sec()},
                    {"connected", true},
                });
            }
            s["header_height"] = hh;
            s["target_height"] = th;
            s["peers"] = std::move(peers);
            return s;
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
                return out;
            });
            mi->set_best_share_hash_fn([scn]() -> uint256 {
                return scn->get_tracker_snapshot().best_share;
            });
            LOG_INFO << "[EMB-BIP110] dashboard sharechain feeds wired "
                        "(set_sharechain_stats_fn + set_best_share_hash_fn; lock-free "
                        "snapshot) — chain_size/has_shares now reflect the mint";
        }

        // Still deliberately NOT installed even on flag-ON (no PPLNS/window/peer
        // producer wired for bip110 yet): set_pplns_fn, set_sharechain_window_fn,
        // set_peer_info_fn, set_pool_hashrate_fn. Absent feeds render honestly
        // empty — NEVER faked.

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
        coin_node.enable_mempool_request();   // BIP35 pull (skipped if peer !NODE_BLOOM)
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
    (void)keepalive; (void)tip_ka;
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool selftest = true;
    bool run = false;
    bool coin_p2p_discover = false;
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
        if (arg == "--version") { std::printf("c2pool-bip110 %s\n", C2POOL_VERSION); return 0; }
        if (arg == "--help" || arg == "-h") { print_banner(argv[0]); return 0; }
        else if (arg == "--selftest") { selftest = true; run = false; }
        else if (arg == "--run") { run = true; selftest = false; }
        else if (arg == "--coin-p2p-discover") { coin_p2p_discover = true; }
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

    if (run) {
        if (!coin_p2p_discover && explicit_peers.empty()) {
            // Default to discovery so `--run` alone still finds fork peers.
            coin_p2p_discover = true;
        }
        return run_embedded(coin_p2p_discover, explicit_peers, fork_checkpoint, http_host, http_port, stratum_addr, stratum_port, donation_address, give_author_pct, node_owner_fee_pct, serve_mempool_txs, sharechain_enabled, sharechain_addnodes);
    }

    print_banner(argv[0]);
    std::printf("\n");
    return run_selftest();
}
