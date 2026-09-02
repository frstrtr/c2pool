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
#include <impl/bip110/coin/node.hpp>
#include <impl/bip110/coin/node_interface.hpp>
#include <impl/bip110/coin/coin_peer_manager.hpp>
#include <impl/bip110/coin/chain_seeds.hpp>
#include <impl/bip110/coin/mempool.hpp>            // M3 daemonless tx-serving
#include <impl/bip110/coin/parent_tx_resolver.hpp> // M3 tier-3 input pricing
#include <impl/bip110/coin/utxo_reorg.hpp>         // GAP4 reorg-blindness fix
#include <impl/bip110/stratum/work_source.hpp>

#include <core/coin/utxo_view_db.hpp>              // M3 own-UTXO view (T2 pricing)
#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>
#include <core/address_utils.hpp>
#include <core/netaddress.hpp>
#include <core/stratum_server.hpp>
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
        "  --http [HOST:]PORT   serve a JSON sync-status endpoint\n"
        "  --node-owner-address ADDR  subsidy fallback / donation payout when a\n"
        "                       miner has no resolvable payout address (base58/bech32)\n\n"
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

// ── Minimal JSON status HTTP endpoint (live-proof surface) ───────────────────
// Serves one JSON body describing the header tip on any request, then closes.
class StatusHttp : public std::enable_shared_from_this<StatusHttp> {
public:
    StatusHttp(io::io_context& ioc, const std::string& host, uint16_t port,
               bip110::coin::HeaderChain& chain, uint32_t fork_height)
        : m_acceptor(ioc), m_chain(chain), m_fork_height(fork_height)
    {
        io::ip::tcp::endpoint ep(io::ip::make_address(host), port);
        m_acceptor.open(ep.protocol());
        m_acceptor.set_option(io::socket_base::reuse_address(true));
        m_acceptor.bind(ep);
        m_acceptor.listen();
    }
    void start() { do_accept(); }
private:
    void do_accept() {
        auto self = shared_from_this();
        m_acceptor.async_accept([self](const boost::system::error_code& ec, io::ip::tcp::socket sock) {
            if (!ec) self->serve(std::move(sock));
            self->do_accept();
        });
    }
    void serve(io::ip::tcp::socket sock) {
        auto s = std::make_shared<io::ip::tcp::socket>(std::move(sock));
        auto buf = std::make_shared<std::array<char, 1024>>();
        s->async_read_some(io::buffer(*buf), [this, s, buf](const boost::system::error_code&, std::size_t) {
            auto tip = m_chain.tip();
            const uint32_t h = m_chain.height();
            const std::string hash = tip ? tip->block_hash.GetHex() : std::string("null");
            const uint32_t peer_tip = m_chain.peer_tip_height();
            char body[512];
            std::snprintf(body, sizeof(body),
                "{\"coin\":\"BIP110\",\"header_height\":%u,\"header_tip\":\"%s\","
                "\"peer_tip\":%u,\"blake2b_height\":%u,\"on_blake2b_chain\":%s}\n",
                h, hash.c_str(), peer_tip, m_fork_height,
                (h >= m_fork_height ? "true" : "false"));
            auto resp = std::make_shared<std::string>();
            *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Connection: close\r\nContent-Length: " + std::to_string(std::strlen(body)) +
                    "\r\n\r\n" + std::string(body);
            io::async_write(*s, io::buffer(*resp),
                [s, resp](const boost::system::error_code&, std::size_t) {
                    boost::system::error_code ig; s->shutdown(io::ip::tcp::socket::shutdown_both, ig);
                });
        });
    }
    io::ip::tcp::acceptor m_acceptor;
    bip110::coin::HeaderChain& m_chain;
    uint32_t m_fork_height;
};

int run_embedded(bool coin_p2p_discover,
                 const std::vector<NetService>& explicit_peers,
                 bool fork_checkpoint,
                 const std::string& http_host, uint16_t http_port,
                 uint16_t stratum_port,
                 const std::string& donation_address,
                 double give_author_pct,
                 double node_owner_fee_pct,
                 bool serve_mempool_txs)
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
        [&coin_node](const std::vector<unsigned char>& block_bytes, uint32_t height) -> bool {
            LOG_INFO << "[EMB-BIP110] submitting won block height=" << height
                     << " bytes=" << block_bytes.size();
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

    std::unique_ptr<core::StratumServer> stratum_server;
    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, "0.0.0.0", stratum_port, work_source);
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

    // Optional JSON status endpoint.
    std::shared_ptr<StatusHttp> http;
    if (http_port != 0) {
        try {
            http = std::make_shared<StatusHttp>(ioc, http_host, http_port, header_chain, chain_params.blake2b_height);
            http->start();
            LOG_INFO << "[EMB-BIP110] status endpoint on " << http_host << ":" << http_port;
        } catch (const std::exception& e) {
            LOG_WARNING << "[EMB-BIP110] status endpoint bind failed: " << e.what();
        }
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
    signals.async_wait([&ioc](const boost::system::error_code&, int) {
        LOG_INFO << "[EMB-BIP110] shutdown signal — stopping";
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
    std::string donation_address;  // operator-provided node-owner/donation address
    std::vector<NetService> explicit_peers;

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
            stratum_port = static_cast<uint16_t>(std::stoi(argv[++i]));
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
    }

    if (run) {
        if (!coin_p2p_discover && explicit_peers.empty()) {
            // Default to discovery so `--run` alone still finds fork peers.
            coin_p2p_discover = true;
        }
        return run_embedded(coin_p2p_discover, explicit_peers, fork_checkpoint, http_host, http_port, stratum_port, donation_address, give_author_pct, node_owner_fee_pct, serve_mempool_txs);
    }

    print_banner(argv[0]);
    std::printf("\n");
    return run_selftest();
}
