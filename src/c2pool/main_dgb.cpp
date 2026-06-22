// c2pool-dgb — DigiByte Scrypt-only (V36) p2pool node entry point.
//
// Wires the real dgb sharechain/pool TU (pool pillars + score path, ported from
// LTC under impl/dgb/ across PRs #112/#113/#115/#121/#129/#131/#132/#134) into
// the c2pool-dgb executable. Two entry paths:
//
//   --selftest / bare : drive the LIVE dgb::ShareTracker::score() path so the
//                       coin smoke gate exercises real consensus code, then exit.
//   --run             : stand up the run-loop — io_context + graceful
//                       SIGINT/SIGTERM shutdown, the dgb::Node sharechain peer
//                       (P2P listener), and (this slice) the miner-facing
//                       Stratum work source. A won Scrypt block reaches the
//                       network via the #82 dual-path broadcaster: the
//                       submitblock-RPC arm (rpc.cpp:387 submit_block_hex, REAL)
//                       is wired here; the embedded P2P-relay arm
//                       (m_on_block_found -> reconstruct_won_block ->
//                       broadcast_won_block, PRs #163/#166/#167/#173/#174/#176/
//                       #177/#179) binds in the NEXT stacked slice once that
//                       reconstructor stack lands on this base.
//
// V36 scope: Scrypt blocks validated; the other 4 DGB algos (SHA256d, Skein,
// Qubit, Odocrypt) are accept-by-continuity / ignored — full 5-algo support is
// V37. Conformance oracle: frstrtr/p2pool-dgb-scrypt (DGB-Scrypt standalone
// parent; merged-v36 byte-compat WAIVED for DGB per operator 2026-06-17).
// CoinParams are oracle-sourced via dgb::make_coin_params (no hardcoded bytes).
// External digibyted RPC stays as a fallback alongside the embedded path.
// Mirrors src/c2pool/main_btc.cpp s target shape.

#include <impl/dgb/node.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/coin_node.hpp>
#include <impl/dgb/coin/embedded_coin_node.hpp>
#include <impl/dgb/coin/embedded_tx_select.hpp>   // make_mempool_tx_source (EmbeddedTxSource)
#include <impl/dgb/coin/won_block_dispatch.hpp>
#include <impl/dgb/coin/reconstruct_closure.hpp>  // make_reconstruct_closure_from_template (#280)
#include <impl/dgb/coin/template_capture.hpp>      // TemplateCapture per-job retain (#300/#271)
#include <impl/dgb/coin/template_other_txs.hpp>    // make_template_other_txs_fn bridge (#299)
#include <impl/dgb/coin/won_block_finalize.hpp>   // finalize_won_block_pow -- forced-won PoW grind JOINT (#82 gate)
#include <impl/dgb/coin/header_sample_build.hpp>  // c2pool::dgb::compact_to_target (nBits -> u256)
#include <impl/dgb/coin/won_share_inputs.hpp>      // won_share_inputs (#279)
#include <impl/dgb/coin/node_interface.hpp>
#include <impl/dgb/coin/header_ingest.hpp>
#include <impl/dgb/coin/mempool_ingest.hpp>
#include <impl/dgb/stratum/work_source.hpp>
#include <impl/dgb/run_loop_mint.hpp>   // Phase B: worker->mint run-loop bind (mint_local_share_locked)
#include <impl/dgb/coin/p2p_node.hpp>
#include <impl/dgb/coin/rpc.hpp>        // NodeRPC — external-daemon submitblock arm (#82)
#include <impl/dgb/coin/rpc_conf.hpp>   // digibyte.conf creds resolution (rpcpassword off argv)
#include <impl/dgb/config_coin.hpp>     // dgb::CoinParams::MAINNET_RPC_PORT default

#include <core/filesystem.hpp>
#include <core/stratum_server.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/asio.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <functional>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace io = boost::asio;

namespace {

// Live network summary sourced from the oracle-populated CoinParams
// (make_coin_params) — never a hardcoded string. These are the exact constants
// the sharechain score() consumes (block_period etc.).
std::string network_summary(const core::CoinParams& p)
{
    return "DigiByte (Scrypt-only) — identifier=" + p.active_identifier_hex()
        + " prefix=" + p.active_prefix_hex()
        + " block_period=" + std::to_string(p.block_period) + "s"
        + " share_period=" + std::to_string(p.share_period) + "s"
        + " chain_length=" + std::to_string(p.chain_length);
}

void print_banner(const char* argv0, const core::CoinParams& p)
{
    std::cout
        << "c2pool-dgb " << C2POOL_VERSION << " — DigiByte Scrypt-only (V36)\n\n"
        << "Usage: " << argv0
        << " [--version] [--help] [--selftest] [--run] [--stratum [H:]P]\n"
        << "       [--coin-daemon H:P] [--coin-magic HEX] [--regtest]\n"
        << "       [--regtest-force-won-share] [--no-p2p-relay]\n\n"
        << "Status: pool/sharechain pillars live (Phase B); run-loop up\n"
        << "        (--run: io_context + sharechain peer + Stratum standup).\n"
        << "        --stratum [HOST:]PORT binds a miner-facing TCP listener\n"
        << "        (e.g. --stratum 5022 or --stratum 127.0.0.1:5022); omit to\n"
        << "        disable. Embedded P2P won-block relay + external digibyted\n"
        << "        RPC fallback land in the next slices.\n"
        << "        --regtest-force-won-share (regtest-ONLY; requires\n"
        << "        --regtest AND --coin-daemon) drives ONE forced won\n"
        << "        share through the live dual-path broadcaster;\n"
        << "        --no-p2p-relay isolates the submitblock arm.\n"
        << "Network: " << network_summary(p) << "\n";
}

// Drive the LIVE chain-score path: dgb::ShareTracker::score() derives time_span
// from CoinParams::block_period (PR #132) and total_work from the verified
// chain. On an empty verified set score() takes its short-chain early-return,
// but the call EXECUTES the real score() body compiled from the #132/#134
// sharechain TU (not just links it) and reports the oracle block_period it
// consumes. The deep block_period multiply (time_span = confirmations *
// block_period) runs once a verified chain >= chain_length exists — exercised
// by the Phase B share fixtures, not standable-up in a startup smoke.
int run_selftest(const core::CoinParams& params)
{
    dgb::ShareTracker tracker;
    tracker.m_params = &params;  // wiring NodeImpl does at ctor time

    // No embedded daemon wired here → block height is "unknown" (0), which
    // routes score() through its 1e6-confirmation * block_period fallback.
    auto block_rel_height = [](uint256) -> std::int32_t { return 0; };

    auto s = tracker.score(uint256::ZERO, block_rel_height);
    std::cout << "[selftest] live dgb::ShareTracker constructed; score() driven\n"
              << "[selftest]   score(ZERO) -> chain_len=" << s.chain_len
              << " hashrate=" << (s.hashrate.IsNull() ? std::string("0")
                                                       : s.hashrate.GetHex()) << "\n"
              << "[selftest]   time_span basis block_period=" << params.block_period
              << "s (oracle PARENT.BLOCK_PERIOD, #132 SSOT)\n"
              << "[selftest] OK\n";
    return 0;
}

// Run-loop: sharechain peer bring-up + miner-facing Stratum standup. Stands up
// the io_context that every node subsystem hangs off, an explicit graceful
// shutdown driven from boost::asio::signal_set, the dgb::Node sharechain peer
// (P2P listener), and (this slice) the Stratum work source + acceptor so a
// won Scrypt block reaches the network.
//
// Why signal_set and not std::signal: std::signal handlers run in the
// async-signal-only delivery context; io_context::stop is thread-safe but not
// documented signal-safe. signal_set delivers SIGINT/SIGTERM as an ordinary
// async callback on the io_context thread, so the shutdown path can do real
// work (stop the stratum acceptor, close sessions) before ioc.stop() drains
// the rest — mirrors main_btc.cpp's teardown contract.
int run_node(const core::CoinParams& params, bool testnet,
             const std::string& stratum_addr, uint16_t stratum_port,
             const std::string& coin_daemon,
             const std::vector<std::byte>& coin_magic,
             const uint256& coin_genesis,
             const std::string& rpc_endpoint,
             const std::string& rpc_conf_path,
             bool regtest = false, bool force_won_share = false,
             bool no_p2p_relay = false)
{
    io::io_context ioc;

    // Per-coin config root: ~/.c2pool/<net>/ (sharechain LevelDB + addrs.json
    // open underneath). Bucket-1 isolation primitive: DGB never shares LTC's
    // net dir — keep the subdir per-coin in v36 AND v37.
    const std::string net_subdir = testnet ? "digibyte_testnet" : "digibyte";
    const std::filesystem::path net_dir =
        core::filesystem::config_path() / net_subdir;
    std::error_code mkdir_ec;
    std::filesystem::create_directories(net_dir, mkdir_ec);  // best effort

    // dgb::Config = core::Config<PoolConfig, CoinConfig>. Skip Config::init()
    // (it would load pool.yaml + coin.yaml from disk); set the sharechain
    // identity directly from the oracle-sourced constants instead — the same
    // contract main_btc.cpp uses for its net smoke. prefix/identifier come from
    // the p2pool-dgb-scrypt oracle (PREFIX 1c0553f2…, IDENTIFIER 4b62545b…).
    dgb::Config config(net_subdir);
    config.pool()->m_prefix = ParseHexBytes(dgb::PoolConfig::DEFAULT_PREFIX_HEX);
    config.m_testnet        = testnet;
    // DEFAULT_BOOTSTRAP_HOSTS is empty until DGB p2pool nodes come online, so
    // there are no outbound seeds to dial this slice — the node binds its
    // listener and waits for inbound sharechain peers.
    for (const auto& host : dgb::PoolConfig::DEFAULT_BOOTSTRAP_HOSTS) {
        const std::string addr = host.find(':') == std::string::npos
            ? host + ":" + std::to_string(dgb::PoolConfig::P2P_PORT)
            : host;
        config.pool()->m_bootstrap_addrs.emplace_back(addr);
    }

    // Stratum acceptor handle, declared BEFORE the signal_set so the shutdown
    // callback can stop it (cancel acceptor + close sessions) ahead of
    // ioc.stop(). Populated below once the work source is built.
    std::unique_ptr<core::StratumServer> stratum_server;

    bool shutdown_initiated = false;
    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc, &stratum_server, &shutdown_initiated]
        (const boost::system::error_code& ec, int signo) {
            if (ec) return;
            if (shutdown_initiated) return;
            shutdown_initiated = true;

            std::cout << "[DGB] received signal " << signo
                      << " — initiating graceful shutdown" << std::endl;
            // Stop stratum BEFORE ioc.stop() so the acceptor cancels and live
            // miner sessions close cleanly (their pending async ops unwind on
            // the io_context). The sharechain peer's sockets close when
            // p2p_node destructs at scope exit after ioc.run() returns.
            if (stratum_server)
                stratum_server->stop();
            ioc.stop();
        });

    // Sharechain peer node: pool::NodeBridge<NodeImpl, Legacy, Actual>. The
    // NodeImpl ctor opens ~/.c2pool/<net>/sharechain_leveldb and seeds the addr
    // store from m_bootstrap_addrs, so config must be populated BEFORE
    // construction (above).
    // §7b embedded chain — backs the in-process work source below and is
    // fed by the embedded P2P header ingest once that lands. Declared HERE
    // (ahead of coin_node) so EmbeddedCoinNode, which holds a HeaderChain&,
    // and coin_node, which holds the EmbeddedCoinNode*, both outlive the
    // tracker callback captured below. The DGBWorkSource further down holds
    // the same non-owning ref.
    c2pool::dgb::HeaderChain header_chain;

    // Embedded mempool — the in-process pool the work template selects from.
    // Declared HERE (ahead of embedded_coin) because the injected
    // EmbeddedTxSource below captures it by reference and MUST be outlived by
    // it; reverse-order destruction tears embedded_coin (and its source) down
    // before mempool. FEED: wire_mempool_ingest (coin/mempool_ingest.hpp, #245)
    // subscribes this pool to an ::dgb::interfaces::Node new_tx relay — but no
    // embedded coin-daemon P2P node is constructed in this run-loop yet (the M3
    // embedded port; header_chain is likewise still unfed), so nothing calls
    // add_tx and the pool stays empty until that node lands. The selection
    // below is therefore byte-identical to the subsidy-only #237 baseline today.
    dgb::coin::Mempool       mempool;

    // Embedded in-process work source: assembles GBT-compatible templates
    // ENTIRELY from embedded chain state + the coin subsidy schedule (no
    // external digibyted). coinbasevalue resolves through the #207 ->
    // subsidy_func SSOT; bits are held back truthfully until the next-target
    // source is plumbed. transactions[] + the fee total come from an injected
    // make_mempool_tx_source over the embedded mempool (#244 seam): fee-sorted
    // txs up to BLOCK_MAX_WEIGHT with their fees folded into coinbasevalue via
    // the #207 SSOT. The source returns an EMPTY selection while the mempool is
    // unfed (see above), so the served template stays at the #237 baseline
    // until live `tx` ingest lands.
    dgb::coin::EmbeddedCoinNode embedded_coin(
        header_chain, params.subsidy_func,
        dgb::coin::make_mempool_tx_source(mempool, dgb::PoolConfig::BLOCK_MAX_WEIGHT));

    // CoinNode seam — embedded-preferred work source (embedded_coin) with the
    // external-digibyted submitblock FALLBACK leg of the #82 dual-path
    // broadcaster. Shared by BOTH the sharechain m_on_block_found arm (just
    // below) and the miner-facing Stratum arm (further below). Declared
    // BEFORE p2p_node so it OUTLIVES the tracker callback that captures it.
    // rpc=nullptr => has_rpc()==false => submit_block_hex returns false
    // LOUDLY (the #163 seam guard: no silent drop, INDEPENDENT of the
    // embedded source). Point a real NodeRPC at external digibyted here to
    // light the submit sink up.
    // ── #82 external-daemon submitblock arm (RPC leg of the dual-path
    // broadcaster) ── Creds come from digibyte.conf (default
    // ~/.digibyte/digibyte.conf, overridable with --coin-rpc-auth PATH) so the
    // rpcpassword NEVER touches argv; --coin-rpc HOST:PORT overrides only the
    // endpoint. When no creds resolve (no daemon provisioned) the arm stays
    // UNARMED (rpc=nullptr) and submit_block_hex returns false LOUDLY (the #163
    // CoinNode seam guard) — byte-identical to today's daemon-less default
    // build, so --run still works without a digibyted. NodeRPC is declared
    // BEFORE coin_node so it OUTLIVES the tracker callback that captures it.
    dgb::coin::RpcConf rpc_conf;
    {
        std::string conf_path = rpc_conf_path;
        if (conf_path.empty()) {
            const char* home = std::getenv("HOME");
            conf_path = std::string(home ? home : ".") + "/.digibyte/digibyte.conf";
        }
        if (dgb::coin::load_rpc_conf(conf_path, rpc_conf)) {
            if (rpc_conf.port == 0)
                rpc_conf.port = testnet ? dgb::CoinParams::TESTNET_RPC_PORT
                                        : dgb::CoinParams::MAINNET_RPC_PORT;
            dgb::coin::apply_endpoint_override(rpc_endpoint, rpc_conf);
        }
    }
    std::unique_ptr<dgb::coin::NodeRPC> rpc;
    if (rpc_conf.armed()) {
        rpc = std::make_unique<dgb::coin::NodeRPC>(&ioc, /*coin=*/nullptr, testnet);
        rpc->connect(NetService(rpc_conf.host, rpc_conf.port), rpc_conf.userpass());
        std::cout << "[DGB] external-daemon submit arm ARMED: NodeRPC -> "
                  << rpc_conf.host << ":" << rpc_conf.port
                  << " (creds from digibyte.conf)" << std::endl;
    } else {
        std::cout << "[DGB] external-daemon submit arm UNARMED "
                     "(no digibyte.conf creds; embedded-only submit path)" << std::endl;
    }

    dgb::coin::CoinNode coin_node(/*embedded=*/&embedded_coin, /*rpc=*/rpc.get());

    dgb::Node p2p_node(&ioc, &config);
    p2p_node.set_target_outbound_peers(4);
    p2p_node.core::Server::listen(dgb::PoolConfig::P2P_PORT);
    std::cout << "[DGB] sharechain peer listening on port "
              << dgb::PoolConfig::P2P_PORT
              << " — proto adv=" << dgb::PoolConfig::ADVERTISED_PROTOCOL_VERSION
              << " min=" << dgb::PoolConfig::MINIMUM_PROTOCOL_VERSION
              << " prefix=" << dgb::PoolConfig::DEFAULT_PREFIX_HEX << std::endl;
    p2p_node.start_outbound_connections();  // no-op until seed hosts exist

    // ── #82 dual-path won-block CLOSER: sharechain (pool) arm ─────────────
    //
    // Bind the tracker's won-block callback to the #82 dispatcher. When a
    // sharechain share is ALSO a valid parent block, ShareTracker fires
    // m_on_block_found(share_hash) (share_tracker.hpp:380/531) — UNTIL NOW that
    // callback was never installed in the run-loop, so a pool-found block
    // SILENTLY DROPPED (the #82 root cause). make_on_block_found routes it
    // through broadcast_won_block's dual path: the P2P-primary relay (empty
    // here — the embedded NodeP2P submit_block_p2p_raw port binds it) plus the
    // live external-digibyted submitblock FALLBACK via the coin_node seam.
    //
    // The reconstruct closure is the documented interim (won_block_dispatch.hpp:
    // "until then a stub reconstructor + the external-RPC fallback"). A faithful
    // reconstruct_won_block needs the share's gentx reassembly + known-tx feed,
    // which lands with the embedded template builder (Phase B embedded). Until
    // then it returns nullopt with a LOUD log — a won share is announced and
    // audited rather than silently dropped, and NO malformed block is emitted.
    // Assigned at setup (single-threaded, pre-ioc.run) — the only safe point to
    // touch tracker() off the compute thread.
    // Declared ahead of the m_on_block_found binding so the won-block P2P-relay
    // sink below can capture it. Constructed later only when --coin-daemon is
    // supplied (stays null otherwise -> sink no-ops, RPC fallback still fires).
    std::unique_ptr<dgb::coin::p2p::NodeP2P<dgb::Config>> coin_p2p;

    // ── #82 FAITHFUL won-block reconstruct closure (replaces the interim
    // nullopt stub) ── make_reconstruct_closure_from_template (#280) composes
    // the three version-AGNOSTIC won-block inputs, bound here to the LIVE
    // sharechain tracker:
    //   won_share_fields_fn   -> share.m_min_header + m_merkle_link (#279, the
    //                            two inputs a won share carries verbatim)
    //   gentx_bytes_fn        -> generate_share_transaction(...).GentxCoinbase
    //                            .bytes (#173 SSOT). v36_active is re-derived
    //                            from the share's COMPILE-TIME version inside
    //                            GST (share_check.hpp:943), so passing false is
    //                            byte-identical to the verify-path invocation
    //                            (share_check.hpp:1728) -> the regenerated gentx
    //                            matches the one that passed verification.
    //   template_other_txs_fn -> the captured-GBT template's non-coinbase set
    //                            (#271). EMPTY today: no per-job template-
    //                            retention seam in the run-loop yet AND the
    //                            embedded mempool is unfed, so the served
    //                            template is coinbase-only => the won block's
    //                            non-coinbase set IS empty. Correct-and-empty (a
    //                            valid coinbase-only block), NOT fail-closed; it
    //                            fills with NO change to this seam once retention
    //                            + tx-selection land.
    //
    // FIRES on the COMPUTE thread already holding the tracker lock
    // (attempt_verify -> m_on_block_found, share_tracker.hpp:537), so the fns
    // read tracker().chain DIRECTLY and must NOT take read_tracker() (would
    // self-deadlock — the corrected consume-seam audit). Fail-closed end to
    // end: any error in a builder fn throws, is caught inside the closure ->
    // std::nullopt (announce + audit; the RPC submitblock fallback still fires).
    // #82 tx-bearing won block: retain each handed-out template's
    // transactions[] keyed by the resulting share_hash so the reconstructor
    // replays the EXACT non-coinbase set the share committed to (merkle-
    // consistent), replacing the interim coinbase-only stub. Plain local:
    // outlives every tracker callback the provider() is installed into
    // (all bound within this main scope, before ioc.run()).
    dgb::coin::TemplateCapture template_capture;

    auto& reconstruct_tracker = p2p_node.tracker();
    auto faithful_reconstruct = dgb::coin::make_reconstruct_closure_from_template(
        /*won_share_fields_fn=*/
        [&reconstruct_tracker](const uint256& h) -> dgb::coin::WonShareInputs {
            dgb::coin::WonShareInputs si{};
            bool found = false;
            reconstruct_tracker.chain.get_share(h).invoke([&](auto* obj) {
                si = dgb::coin::won_share_inputs(*obj);
                found = true;
            });
            if (!found)
                throw std::runtime_error("won_share_inputs: share absent from chain");
            return si;
        },
        /*gentx_bytes_fn=*/
        [&reconstruct_tracker, &params](const uint256& h)
            -> std::vector<unsigned char> {
            dgb::coin::GentxCoinbase gc;
            bool found = false;
            reconstruct_tracker.chain.get_share(h).invoke([&](auto* obj) {
                (void)dgb::generate_share_transaction(
                    *obj, reconstruct_tracker, params,
                    /*dump_diag=*/false, /*v36_active=*/false, &gc);
                found = true;
            });
            if (!found || gc.bytes.empty())
                throw std::runtime_error("gentx regen: share absent / empty gentx");
            return gc.bytes;
        },
        /*template_other_txs_fn=*/
        // #300/#299: replay the captured per-job template transactions[]
        // keyed by share_hash (TemplateCapture above feeds it at seed time);
        // a capture MISS decodes to an empty set -> valid coinbase-only block.
        dgb::coin::make_template_other_txs_fn(template_capture.provider()));

    // -- #82 forced-won PoW finalize -------------------------------------
    // A forced-won share (the regtest --regtest-force-won-share live seam)
    // carries no real Scrypt work, so the reconstructed block is daemon-rejected
    // high-hash (observed: ProcessNewBlock AcceptBlock FAILED, proof of work
    // failed). Grind the reconstructed header nonce to satisfy the block's OWN
    // declared nBits via the won_block_finalize JOINT (over the #286 scrypt_pow
    // SSOT) BEFORE dispatch, so the dual-path broadcaster relays a PoW-valid
    // block the peer ACCEPTs. Gated to the regtest forced-won path ONLY: a
    // genuine pool-won share already satisfies the parent target and is NEVER
    // reground -- zero production behaviour change.
    if (regtest && force_won_share) {
        auto inner = std::move(faithful_reconstruct);
        faithful_reconstruct =
            [inner = std::move(inner)](const uint256& share_hash)
            -> std::optional<std::pair<std::vector<unsigned char>, std::string>> {
            auto blk = inner(share_hash);
            if (!blk || blk->first.size() < 80) return blk;  // pass through / fail closed
            // nBits is header bytes [72..75], little-endian.
            const uint32_t nbits =
                  static_cast<uint32_t>(blk->first[72])
                | (static_cast<uint32_t>(blk->first[73]) << 8)
                | (static_cast<uint32_t>(blk->first[74]) << 16)
                | (static_cast<uint32_t>(blk->first[75]) << 24);
            const auto target = c2pool::dgb::compact_to_target(nbits);
            auto fin = dgb::coin::finalize_won_block_pow(blk->first, target);
            if (!fin) {
                std::cout << "[DGB-BLOCK] forced-won finalize: no satisfying nonce "
                             "for nBits=" << std::hex << nbits << std::dec
                          << " -- relaying UNGROUND (peer will reject high-hash)"
                          << std::endl;
                return blk;
            }
            std::cout << "[DGB-BLOCK] forced-won finalize: ground nonce="
                      << fin->grind.nonce << " after " << fin->grind.iters
                      << " iters (PoW now satisfies nBits=" << std::hex << nbits
                      << std::dec << ")" << std::endl;
            return std::make_pair(std::move(fin->bytes), std::move(fin->hex));
        };
    }

    p2p_node.tracker().m_on_block_found = dgb::coin::make_on_block_found(
        /*reconstruct=*/std::move(faithful_reconstruct),
        /*p2p_relay=*/[&ioc, &coin_p2p, no_p2p_relay](const std::vector<unsigned char>& block_bytes) {
            // #82 PRIMARY arm: relay the won block over the embedded coin-daemon
            // P2P producer. The sink fires from the compute thread, so post the
            // peer write onto the io thread (NodeP2P is single-thread-confined).
            // No-op when --coin-daemon is absent (coin_p2p null) — the RPC
            // fallback below still fires (dual-path rule).
            //
            // --no-p2p-relay (#82 ARM B isolation): suppress ONLY this embedded
            // P2P-relay arm and leave the external-digibyted submitblock seam
            // (fallback) live, so a regtest soak can prove the RPC fallback lands
            // the block ON ITS OWN — not masked by a silent or dead P2P relay
            // (the historical #82 gap). A real operator toggle, not a test seam.
            if (no_p2p_relay) {
                std::cout << "[DGB-BLOCK] --no-p2p-relay: embedded P2P-relay arm "
                             "SUPPRESSED; submitblock-RPC fallback remains live"
                          << std::endl;
                return;
            }
            if (!coin_p2p) return;
            io::post(ioc, [&coin_p2p, bytes = block_bytes]() {
                if (coin_p2p) coin_p2p->submit_block_p2p_raw(bytes);
            });
        },
        /*seam=*/&coin_node);                     // external-digibyted submitblock fallback

    // ── #82 dual-path won-block CLOSER: miner-facing Stratum standup ───────
    //
    // Stand the miner path up so a Scrypt block found by a connected miner
    // reaches the network. The embedded coin side is MVP-unwired this slice
    // (empty HeaderChain + Mempool): the DGBWorkSource 4a skeleton returns
    // default work and mining_submit low-diff-rejects before the broadcaster
    // (compute_share_difficulty's 0.0 sentinel), so NO garbage block is ever
    // emitted — the standup proves the StratumServer<->IWorkSource wiring
    // end-to-end. Real work-gen / Scrypt share-validation land in 4b/4c.
    // This mirrors btc::stratum standing its skeleton wiring up first.
    // header_chain AND mempool are both declared above coin_node now — mempool
    // backs the injected EmbeddedCoinNode tx source (declared there so it
    // outlives the capturing source).

    // ── Embedded coin-daemon ingest surface (Phase B P2P-node standup) ──
    //
    // dgb::interfaces::Node (coin/node_interface.hpp) is the shared-state
    // surface the embedded coin-daemon P2P node (coin/p2p_node.hpp, NodeP2P)
    // binds against: NodeP2P fires new_headers on each received `headers`
    // batch and new_tx on each relayed `tx`. Construct it here and subscribe
    // BOTH the HeaderChain and the Mempool to those feeds through the
    // wire_*_ingest SSOT connectors (coin/header_ingest.hpp,
    // coin/mempool_ingest.hpp), so a live header/tx feed flows into
    // HeaderChain::validate_and_append and Mempool::add_tx the moment the
    // NodeP2P is connected (NodeP2P construct + connect is the next slice).
    // Declared AFTER header_chain + mempool so coin_iface (and its event
    // subscriptions) destructs FIRST: the wire_*_ingest handlers capture
    // chain/pool by reference and must not outlive them. The returned
    // EventDisposable handles are held for the run-loop lifetime.
    //
    // No behavior change this slice: with no NodeP2P producer constructed yet,
    // new_headers/new_tx never fire, so the chain and mempool stay exactly as
    // before. This stands the CONSUMER seam up that the NodeP2P producer binds
    // to next — header+mempool ingest together, the unblock order integrator
    // directed (2026-06-20).
    dgb::interfaces::Node coin_iface;
    auto header_ingest_sub  = c2pool::dgb::wire_header_ingest(coin_iface, header_chain);
    auto mempool_ingest_sub = c2pool::dgb::wire_mempool_ingest(coin_iface, mempool);
    std::cout << "[DGB] embedded coin-daemon ingest surface up — header+tx "
                 "feeds wired (NodeP2P producer standup next)" << std::endl;

    // ── Embedded coin-daemon P2P PRODUCER standup (Phase B) ───────────────
    //
    // dgb::coin::p2p::NodeP2P<dgb::Config> (coin/p2p_node.hpp) is the producer that
    // binds against coin_iface: it dials the local digibyted, speaks the
    // DigiByte Core wire protocol (Scrypt-only consumer), and fires
    // coin_iface.new_headers on each `headers` batch / new_tx on each relayed
    // `tx`. The wire_*_ingest connectors above already route those onto
    // HeaderChain::validate_and_append and Mempool::add_tx, so a live feed now
    // flows end-to-end the moment the handshake completes.
    //
    // The coin-daemon wire MAGIC (coin_magic, the network pchMessageStart) is
    // DISTINCT from the sharechain PREFIX (PoolConfig::DEFAULT_PREFIX_HEX, the
    // p2pool peer-namespace isolation primitive): different layers, never
    // conflated. Both endpoint and magic are supplied by main() so the binary
    // can target mainnet (magic faf3b6da / port 12024) or a dev regtest daemon
    // (magic fabfb5da) without hard-coding either here.
    //
    // No behavior change when --coin-daemon is absent: coin_p2p stays null, the
    // consumer seam idles exactly as before this slice.
    io::steady_timer coin_getheaders_timer(ioc);
    if (!coin_daemon.empty()) {
        if (coin_magic.empty())
            std::cout << "[DGB] WARNING: --coin-daemon set without --coin-magic "
                         "— handshake will fail (wrong network magic)" << std::endl;
        config.coin()->m_p2p.prefix = coin_magic;
        const auto colon = coin_daemon.rfind(':');
        const std::string host = coin_daemon.substr(0, colon);
        const uint16_t port =
            static_cast<uint16_t>(std::stoi(coin_daemon.substr(colon + 1)));
        const NetService target(host, port);
        config.coin()->m_p2p.address = target;

        coin_p2p = std::make_unique<dgb::coin::p2p::NodeP2P<dgb::Config>>(
            &ioc, &coin_iface, &config, "DGB-CoinP2P");
        coin_p2p->enable_mempool_request();  // also exercise the tx ingest seam
        coin_p2p->connect(target);
        std::cout << "[DGB] embedded coin-daemon P2P producer dialing "
                  << target.to_string() << " magic=" << HexStr(coin_magic)
                  << " (proto adv per coin/p2p_node.hpp)" << std::endl;

        // After the version/verack handshake, drive an initial getheaders from
        // the genesis locator (or current tip) so the peer streams its header
        // chain into validate_and_append. 3s mirrors main_btc.cpp's driver.
        coin_getheaders_timer.expires_after(std::chrono::seconds(3));
        coin_getheaders_timer.async_wait(
            [&coin_p2p, coin_genesis]
            (const boost::system::error_code& ec) {
                if (ec) return;
                if (!coin_p2p->is_handshake_complete()) {
                    std::cout << "[DGB] coin-daemon handshake not complete yet "
                                 "(peer slow?) — reconnect/getheaders retry on "
                                 "the NodeP2P 30s timer" << std::endl;
                    return;
                }
                // Empty chain (fresh regtest) -> locator = [genesis]; one
                // getheaders batch (<=2000) covers a short regtest chain. Walk-
                // forward continuation for long chains is a follow-up slice.
                std::vector<uint256> locator;
                if (!coin_genesis.IsNull())
                    locator.push_back(coin_genesis);
                std::cout << "[DGB] coin-daemon handshake OK — sending initial "
                             "getheaders, locator="
                          << (locator.empty()
                                  ? std::string("<empty>")
                                  : locator.front().GetHex().substr(0, 16))
                          << std::endl;
                // 70019 == DigiByte Core PROTOCOL_VERSION (coin/p2p_node.hpp).
                coin_p2p->send_getheaders(70019, locator, uint256::ZERO);
            });
    }

    // submitblock-RPC arm of the #82 dual-path broadcaster, driven from the
    // miner-facing Stratum path. Reuses the SAME coin_node seam declared above
    // p2p_node (the sharechain arm shares it). rpc.cpp:387 submit_block_hex is
    // REAL, not a stub.
    auto stratum_submit_fn =
        [&coin_node](const std::vector<unsigned char>& block_bytes,
                     uint32_t height) -> bool {
            const std::string block_hex = HexStr(block_bytes);
            std::cout << "[DGB-STRATUM-BLOCK] won block height=" << height
                      << " bytes=" << block_bytes.size()
                      << " — dispatching via submitblock-RPC arm" << std::endl;
            // The sharechain P2P-relay arm (m_on_block_found ->
            // reconstruct_won_block -> broadcast_won_block) is bound above with
            // the FAITHFUL template-based reconstruct closure (#280, wired here):
            // share fields (#279) + regenerated gentx (#173) + the captured-GBT
            // template's non-coinbase set (#271, empty until the embedded feed
            // lands). That arm reconstructs + broadcasts a won pool block
            // INDEPENDENTLY of this Stratum submitblock fallback.
            const bool ok =
                coin_node.submit_block_hex(block_hex, /*ignore_failure=*/false);
            if (!ok)
                std::cout << "[DGB-STRATUM-BLOCK] submitblock arm reached NO sink "
                             "(no embedded backend / no digibyted RPC wired yet) "
                             "— sharechain P2P-relay arm reconstructs+broadcasts independently"
                          << std::endl;
            return ok;
        };

    // AutoRatchet mint-side state machine (base_version=35, target=36; oracle
    // frstrtr/p2pool-dgb-scrypt @22761e7). Declared BEFORE work_source so it
    // OUTLIVES the mint callback that captures it by reference. In-memory for
    // now (no state-file path wired -- a restart re-bootstraps to VOTING, which
    // is safe: it never regresses a crossed share; persistence is a follow-up).
    // Accessed ONLY from the mint closure below, and only while that closure
    // holds the tracker write-lock, so its state is serialized -- no extra mutex.
    dgb::AutoRatchet dgb_mint_ratchet = dgb::make_dgb_ratchet();

    // DGBWorkSource holds non-owning refs to chain + mempool; both outlive it
    // (declared just above, same scope). The StratumServer co-owns the work
    // source via shared_ptr.
    auto work_source = std::make_shared<dgb::stratum::DGBWorkSource>(
        header_chain, mempool, testnet, std::move(stratum_submit_fn),
        params.subsidy_func);

    // -- Phase B worker->mint run-loop bind --------------------------------
    // Complete the worker->mint path: when mining_submit classifies a Scrypt
    // submission as ShareAccept (meets the SHARE target but NOT the block
    // target), DGBWorkSource::try_mint_share invokes this. mint_local_share_
    // locked mints the found share into the LIVE sharechain tracker under the
    // tracker write-lock -- taken NON-BLOCKING on this Stratum-submission thread
    // (declined, never blocked, if think() holds the exclusive lock; the
    // ShareAccept handler logs minted-vs-no-credit off the returned hash) --
    // stamping the AutoRatchet-selected {mint=35, vote=36} version pair. This
    // replaces the unbound no-op (set_mint_share_fn previously never called).
    work_source->set_mint_share_fn(
        [&p2p_node, &params, &dgb_mint_ratchet](
            const dgb::stratum::DGBWorkSource::MintShareInputs& in) -> uint256 {
            return dgb::mint_local_share_locked(
                in, p2p_node, params, dgb_mint_ratchet);
        });

    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_addr, stratum_port, work_source);
        if (stratum_server->start()) {
            std::cout << "[DGB] stratum listening on " << stratum_addr << ":"
                      << stratum_port
                      << " (work source: DGBWorkSource 4a skeleton — Scrypt-only;"
                      << " work-gen/share-validation land in 4b/4c)" << std::endl;
        } else {
            std::cout << "[DGB] stratum FAILED to bind " << stratum_addr << ":"
                      << stratum_port << " — stratum disabled" << std::endl;
            stratum_server.reset();
        }
    } else {
        std::cout << "[DGB] stratum disabled (no --stratum flag)" << std::endl;
    }

    // ── #82 REGTEST-GATED forced-won-share LIVE seam (decision (a), 2026-06-21) ──
    //
    // Synthesize ONE won share, insert it into the LIVE dgb::ShareTracker chain,
    // and fire m_on_block_found(share_hash) AFTER both broadcast arms are bound
    // (above). This drives the REAL faithful reconstruct closure
    // (make_reconstruct_closure_from_template) + the REAL dual-path dispatch
    // (make_on_block_found) over a genuine tracker share — the live counterpart
    // of the dgb_forced_won_share_dualpath KAT, whose seams are synthetic.
    //
    // FAIL-CLOSED GATE: this seam is REACHABLE ONLY on a regtest run. There is
    // no regtest CoinParam (the run builds make_coin_params(testnet=false)), so
    // "regtest" is asserted conservatively as BOTH --regtest AND a --coin-daemon
    // target (a dev regtest digibyted, e.g. magic fabfb5da). If --regtest-force-
    // won-share is passed WITHOUT that, it is REFUSED (logged, not fired): it can
    // never run on a production/mainnet path. The share is posted on a short
    // timer so it fires after the producer handshake driver, on the io thread.
    io::steady_timer force_won_timer(ioc);
    if (force_won_share) {
        const bool gated_regtest = regtest && !coin_daemon.empty();
        if (!gated_regtest) {
            std::cout << "[DGB] REFUSED --regtest-force-won-share: not a regtest "
                         "run (requires BOTH --regtest AND --coin-daemon <regtest "
                         "digibyted>). Seam NOT fired — fail-closed." << std::endl;
        } else {
            // Build a v36 MergedMiningShare with a NULL parent so the PPLNS walk
            // is skipped entirely (no chain ancestry needed) — payouts empty,
            // donation == subsidy. The reconstruct closure reads this share via
            // chain.get_share(h): won_share_inputs(*obj) (m_min_header +
            // m_merkle_link, both default-constructed here) and
            // generate_share_transaction(*obj, ...) (the SSOT gentx regen). The
            // share is inserted under its m_hash so the get_share lookup hits.
            auto* forced = new dgb::MergedMiningShare();
            // Deterministic synthetic share hash (all-hex; no real PoW). The
            // tag "f02ced" marks it as the #82 forced-won-share seam in logs.
            forced->m_hash.SetHex(
                "00000000000000000000000000000000000000000000000000000000f02ced01");
            forced->m_prev_hash.SetNull();             // null parent => PPLNS skipped
            forced->m_coinbase.m_data =
                { 0x03, 0xa1, 0xb2, 0xc3, 0x04, 0x11, 0x22, 0x33, 0x44 };
            forced->m_nonce = 0x12345678;
            forced->m_pubkey_hash.SetNull();
            forced->m_pubkey_type = 0;
            forced->m_subsidy = 500000000ull;
            forced->m_donation = 0;
            forced->m_stale_info = dgb::none;
            forced->m_desired_version = 36;
            forced->m_segwit_data = std::nullopt;
            forced->m_far_share_hash.SetNull();
            forced->m_max_bits = 0x1e0fffff;
            forced->m_bits = 0x1e0fffff;
            forced->m_timestamp = 1718700000;
            forced->m_absheight = 1000;
            forced->m_merged_payout_hash.SetNull();
            forced->m_last_txout_nonce = 0x0001020304050607ull;
            // m_min_header / m_merkle_link / m_ref_merkle_link default-construct.
            const uint256 forced_hash = forced->m_hash;
            p2p_node.tracker().add(forced);            // chain indexes by m_hash

            // ── Fire AFTER work-template/UpdateTip-ready, not a blind one-shot ──
            //
            // The historical 0-shares/120s timeout had a SECOND cause behind the
            // stale port-5024 collision: a fixed 5s one-shot fired the won-share
            // BEFORE the embedded coin-daemon P2P producer finished its
            // version/verack handshake and before any header reached HeaderChain
            // (the first UpdateTip). A won block dispatched then cannot reach
            // node B by the P2P-relay arm (peer not yet connected) and races
            // ahead of node B's own sync, so neither path produced a
            // ProcessNewBlock ACCEPT and the soak grep saw "Final share count: 0".
            //
            // Gate the fire on a genuine readiness signal instead (integrator
            // 2026-06-21): poll until BOTH (a) the coin-daemon P2P handshake is
            // complete (node B reachable for the P2P-relay arm + the submitblock
            // RPC fallback) AND (b) HeaderChain::tip_hash() carries a tip (>=1
            // UpdateTip ingested -> a work template with a real
            // previousblockhash now exists). Latch-once. A bounded fallback fires
            // after the cap with a LOUD, attributable log so a slow/stuck peer
            // surfaces as a named blocker, not a silent no-fire. Regtest-only;
            // zero production-path behaviour change.
            auto fw_attempt = std::make_shared<int>(0);
            constexpr int FW_MAX_ATTEMPTS = 40;        // 40 * 1.5s = 60s cap
            auto fw_poll = std::make_shared<
                std::function<void(const boost::system::error_code&)>>();
            // -- #82 faithful seed: rebuild the synthetic won share header
            // from node B's LIVE getblocktemplate (integrator 2026-06-21) --
            // Bare prevhash seeding fixes only bad-prevblk; node B can still
            // reject on a wrong nBits (high-hash), a mismatched BIP34 height
            // (bad-cb-height) or an over-claimed coinbase (bad-cb-amount).
            // Pulling node B's OWN Scrypt-lane GBT (make_gbt_request pins
            // algo=scrypt) yields a fully connectable coinbase-only block in
            // one move: correct prev + bits + height + coinbasevalue. The
            // reconstruct closure frames it; --soak-regrind then grinds the
            // nonce to satisfy THIS bits. Regtest-only; coinbase-only =>
            // merkle root == gentx txid by construction (no bad-txnmrklroot).
            auto seed_forced_from_gbt = [forced, forced_hash, &rpc, &template_capture, &header_chain]() {
                if (!rpc) {
                    // Unreachable on the gated path (--regtest-force-won-share
                    // requires --coin-daemon, which arms rpc); without the GBT
                    // there is no authoritative bits/height anyway, so the block
                    // cannot connect. Surface, do not fabricate.
                    std::cout << "[DGB] #82 forced-won seed: no RPC arm - cannot "
                                 "pull node-B GBT; block will not connect"
                              << std::endl;
                    return;
                }
                try {
                    auto gbt = rpc->getblocktemplate({"segwit"});
                    // #82 tx-bearing: retain this template transactions[]
                    // under the forced share hash so the won-block
                    // reconstructor replays them (coinbasevalue already
                    // includes their fees -> subsidy/merkle consistent).
                    template_capture.capture(
                        forced_hash,
                        gbt.value("transactions", nlohmann::json::array()));
                    auto& mh = forced->m_min_header;
                    mh.m_version = gbt.at("version").get<uint64_t>();
                    mh.m_previous_block.SetHex(
                        gbt.at("previousblockhash").get<std::string>());
                    mh.m_bits = static_cast<uint32_t>(
                        std::stoul(gbt.at("bits").get<std::string>(), nullptr, 16));
                    mh.m_timestamp = gbt.at("curtime").get<uint32_t>();
                    forced->m_bits      = mh.m_bits;
                    forced->m_max_bits  = mh.m_bits;
                    forced->m_timestamp = mh.m_timestamp;
                    forced->m_absheight = gbt.at("height").get<uint32_t>();
                    forced->m_subsidy   = gbt.at("coinbasevalue").get<uint64_t>();
                    // BIP34: the coinbase scriptSig MUST begin with the
                    // serialized block height (minimal CScriptNum push) or
                    // node B rejects bad-cb-height. The synthetic
                    // m_coinbase.m_data is passed through verbatim by
                    // generate_share_transaction, so encode node B's GBT
                    // height here. height>0 always (won block is tip+1).
                    {
                        uint32_t h = forced->m_absheight;
                        std::vector<unsigned char> hb;
                        while (h) { hb.push_back(h & 0xff); h >>= 8; }
                        if (hb.empty()) hb.push_back(0);
                        if (hb.back() & 0x80) hb.push_back(0);
                        std::vector<unsigned char> cb;
                        cb.push_back(static_cast<unsigned char>(hb.size()));
                        cb.insert(cb.end(), hb.begin(), hb.end());
                        const unsigned char tail[] = {0x04, 0x11, 0x22, 0x33, 0x44};
                        cb.insert(cb.end(), std::begin(tail), std::end(tail));
                        forced->m_coinbase.m_data = cb;
                    }
                    std::cout << "[DGB] #82 forced-won seed from node-B GBT: height="
                              << forced->m_absheight << " prev="
                              << gbt.at("previousblockhash").get<std::string>().substr(0, 16)
                              << " bits=" << gbt.at("bits").get<std::string>()
                              << " coinbasevalue=" << forced->m_subsidy << std::endl;
                } catch (const std::exception& e) {
                    std::cout << "[DGB] #82 forced-won seed: getblocktemplate FAILED ("
                              << e.what()
                              << ") - NAMED BLOCKER, block will not connect"
                              << std::endl;
                }
            };
            auto fire_forced =
                [&p2p_node, forced_hash, no_p2p_relay, seed_forced_from_gbt](const char* why) {
                    seed_forced_from_gbt();   // node-B-faithful header before reconstruct
                    std::cout << "[DGB] #82 forced-won-share seam firing "
                              << "m_on_block_found("
                              << forced_hash.GetHex().substr(0, 16)
                              << ") — regtest, " << why << "; "
                              << (no_p2p_relay ? "ARM B (submitblock) ISOLATED "
                                                 "(--no-p2p-relay)"
                                               : "BOTH arms (P2P relay + submitblock)")
                              << std::endl;
                    auto& cb = p2p_node.tracker().m_on_block_found;
                    if (cb) cb(forced_hash);
                    else
                        std::cout << "[DGB] forced-won-share: m_on_block_found "
                                     "UNBOUND — nothing fired" << std::endl;
                };
            *fw_poll = [&force_won_timer, &coin_p2p, &header_chain, fw_poll,
                        fw_attempt, fire_forced]
                (const boost::system::error_code& ec) {
                if (ec) return;
                const bool handshake_ready =
                    coin_p2p && coin_p2p->is_handshake_complete();
                const bool tip_ready = header_chain.tip_hash().has_value();
                if (handshake_ready && tip_ready) {
                    fire_forced("work-template/UpdateTip-ready "
                                "(handshake complete + tip present)");
                    return;
                }
                if (++(*fw_attempt) >= FW_MAX_ATTEMPTS) {
                    std::cout << "[DGB] forced-won-share readiness TIMEOUT after "
                              << FW_MAX_ATTEMPTS << " polls — unmet: "
                              << (handshake_ready ? "" : "[handshake] ")
                              << (tip_ready ? "" : "[tip] ")
                              << "— firing anyway (last-resort; node B may reject)"
                              << std::endl;
                    fire_forced("readiness-TIMEOUT last-resort");
                    return;
                }
                force_won_timer.expires_after(std::chrono::milliseconds(1500));
                force_won_timer.async_wait(*fw_poll);
            };
            force_won_timer.expires_after(std::chrono::milliseconds(1500));
            force_won_timer.async_wait(*fw_poll);
        }
    }

    std::cout << "[DGB] run-loop up: " << network_summary(params) << "\n";
    std::cout << "[DGB] io_context running. Ctrl-C to stop." << std::endl;

    ioc.run();

    // Tear the acceptor + sessions down while the work source and the coin
    // objects it references (header_chain / mempool / coin_node) are still
    // alive — explicit reset keeps destruction order safe (stratum_server was
    // declared first, so it would otherwise outlive them).
    stratum_server.reset();

    std::cout << "[DGB] io_context stopped — clean exit" << std::endl;
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_selftest = false;
    bool want_run = false;
    std::string stratum_addr = "0.0.0.0";  // bind all interfaces by default
    uint16_t    stratum_port = 0;           // 0 disables stratum; --stratum sets it
    std::string coin_daemon;                // --coin-daemon HOST:PORT (embedded P2P producer target)
    std::vector<std::byte> coin_magic;      // --coin-magic HEX (network pchMessageStart)
    uint256 coin_genesis;                   // --coin-genesis HASH (initial getheaders locator base)
    std::string rpc_endpoint;               // --coin-rpc HOST:PORT (external digibyted submit arm)
    std::string rpc_conf_path;              // --coin-rpc-auth PATH to digibyte.conf (creds source)
    // ── #82 regtest-gated forced-won-share LIVE seam (decision (a), 2026-06-21) ──
    // --regtest-force-won-share synthesizes ONE won share into the live
    // ShareTracker and fires m_on_block_found AFTER both broadcast arms are
    // bound, driving the faithful reconstruct closure + dual-path dispatch live.
    // FAIL-CLOSED: it is REFUSED unless the run is regtest. There is no regtest
    // CoinParam yet (make_coin_params(testnet=false)), so 'regtest' here means an
    // explicit --regtest marker AND a --coin-daemon target (a dev regtest
    // digibyted). Absent either, the flag is logged-and-ignored — it can NEVER
    // fire on a production/mainnet run path. --no-p2p-relay isolates ARM B
    // (external submitblock) by suppressing the embedded P2P-relay sink.
    bool regtest        = false;            // --regtest (dev/regtest marker; gates the forced seam)
    bool force_won_share = false;           // --regtest-force-won-share (regtest-ONLY won-block live seam)
    bool no_p2p_relay   = false;            // --no-p2p-relay (suppress ARM A to isolate ARM B)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dgb " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0)     want_help = true;
        if (std::strcmp(argv[i], "--selftest") == 0) want_selftest = true;
        if (std::strcmp(argv[i], "--run") == 0)      want_run = true;
        if (std::strcmp(argv[i], "--stratum") == 0 && i + 1 < argc) {
            // --stratum [HOST:]PORT — bind a stratum TCP listener for miners.
            const std::string ep = argv[++i];
            const auto colon = ep.find(':');
            if (colon == std::string::npos) {
                stratum_port = static_cast<uint16_t>(std::stoi(ep));
            } else {
                stratum_addr = ep.substr(0, colon);
                stratum_port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));
            }
        }
        if (std::strcmp(argv[i], "--coin-daemon") == 0 && i + 1 < argc) {
            coin_daemon = argv[++i];               // embedded coin-daemon P2P endpoint
        }
        if (std::strcmp(argv[i], "--coin-magic") == 0 && i + 1 < argc) {
            coin_magic = ParseHexBytes(argv[++i]); // network magic (pchMessageStart)
        }
        if (std::strcmp(argv[i], "--coin-genesis") == 0 && i + 1 < argc) {
            coin_genesis = uint256S(argv[++i]);    // genesis hash for initial getheaders
        }
        if (std::strcmp(argv[i], "--coin-rpc") == 0 && i + 1 < argc) {
            rpc_endpoint = argv[++i];              // HOST:PORT endpoint override (no secret)
        }
        if (std::strcmp(argv[i], "--coin-rpc-auth") == 0 && i + 1 < argc) {
            rpc_conf_path = argv[++i];             // path to digibyte.conf (rpcpassword stays in-file)
        }
        if (std::strcmp(argv[i], "--regtest") == 0)  regtest = true;
        if (std::strcmp(argv[i], "--regtest-force-won-share") == 0)
            force_won_share = true;                 // gated below: regtest-ONLY
        if (std::strcmp(argv[i], "--no-p2p-relay") == 0) no_p2p_relay = true;
    }

    const core::CoinParams params = dgb::make_coin_params(/*testnet=*/false);
    print_banner(argv[0], params);

    if (want_help)
        return 0;

    // --run: stand up the run-loop (io_context + sharechain peer + stratum).
    if (want_run)
        return run_node(params, /*testnet=*/false, stratum_addr, stratum_port,
                        coin_daemon, coin_magic, coin_genesis,
                        rpc_endpoint, rpc_conf_path,
                        regtest, force_won_share, no_p2p_relay);

    // --selftest, or a bare invocation: drive the live score path so the
    // binary exercises real consensus code, then exit cleanly.
    (void)want_selftest;
    return run_selftest(params);
}
