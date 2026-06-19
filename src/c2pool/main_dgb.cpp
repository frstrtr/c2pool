// c2pool-dgb — DigiByte Scrypt-only (V36) p2pool node entry point.
//
// Wires the real dgb sharechain/pool TU (pool pillars + score path, ported from
// LTC under impl/dgb/ across PRs #112/#113/#115/#121/#129/#131/#132/#134) into
// the c2pool-dgb executable. Two entry paths:
//
//   --selftest / bare : drive the LIVE dgb::ShareTracker::score() path so the
//                       coin smoke gate exercises real consensus code, then exit.
//   --run             : stand up the run-loop SPINE (this slice) — io_context +
//                       graceful SIGINT/SIGTERM shutdown. The node/stratum/P2P
//                       subsystems and the won-block dispatch binding
//                       (m_on_block_found -> reconstruct_won_block ->
//                       broadcast_won_block, #82 connecting tissue landed across
//                       PRs #163/#166/#167/#173/#174/#176/#177/#179) bind onto
//                       this io_context in the NEXT stacked slice. Standing the
//                       spine up first gives those subsystems the lifecycle they
//                       hang off and keeps each increment build-verifiable.
//
// V36 scope: Scrypt blocks validated; the other 4 DGB algos (SHA256d, Skein,
// Qubit, Odocrypt) are accept-by-continuity / ignored — full 5-algo support is
// V37. Conformance oracle: frstrtr/p2pool-dgb-scrypt (DGB-Scrypt standalone
// parent; merged-v36 byte-compat WAIVED for DGB per operator 2026-06-17).
// CoinParams are oracle-sourced via dgb::make_coin_params (no hardcoded bytes).
// External digibyted RPC stays as a fallback alongside the embedded path.
// Mirrors src/c2pool/main_btc.cpp s target shape.

#include <impl/dgb/node.hpp>

#include <core/filesystem.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/asio.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>

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
        << "Usage: " << argv0 << " [--version] [--help] [--selftest] [--run]\n\n"
        << "Status: pool/sharechain pillars live (Phase B); run-loop spine up\n"
        << "        (--run: io_context + graceful shutdown). Node/stratum/P2P +\n"
        << "        won-block dispatch binding land in the next slice; external\n"
        << "        digibyted RPC stays as a fallback.\n"
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

// Run-loop SPINE + sharechain peer bring-up. Stands up the io_context that
// every node subsystem hangs off, an explicit graceful shutdown driven from
// boost::asio::signal_set, and (this slice) constructs the dgb::Config +
// dgb::Node sharechain peer and binds its P2P listener.
//
// Why signal_set and not std::signal: std::signal handlers run in the
// async-signal-only delivery context; io_context::stop is thread-safe but not
// documented signal-safe. signal_set delivers SIGINT/SIGTERM as an ordinary
// async callback on the io_context thread, so the shutdown path can do real
// work (stop the stratum acceptor, close sessions) before ioc.stop() drains
// the rest — mirrors main_btc.cpp's teardown contract.
//
// SEAM (next stacked slice): stand up the Stratum work source and bind
// make_on_block_found(reconstruct_won_block, p2p_sink) into m_on_block_found
// so a won share reaches the network (closes #82's embedded P2P relay path);
// the submitblock RPC fallback (rpc.cpp:387, already real — NOT a stub) is the
// second arm of the dual-path broadcaster gate.
int run_node(const core::CoinParams& params, bool testnet)
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

    bool shutdown_initiated = false;
    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc, &shutdown_initiated](const boost::system::error_code& ec, int signo) {
            if (ec) return;
            if (shutdown_initiated) return;
            shutdown_initiated = true;

            std::cout << "[DGB] received signal " << signo
                      << " — initiating graceful shutdown" << std::endl;
            // Next slice: stop stratum acceptor + close sessions here BEFORE
            // ioc.stop(), so their pending async ops cancel cleanly. The
            // sharechain peer's sockets close when p2p_node destructs at scope
            // exit after ioc.run() returns.
            ioc.stop();
        });

    // Sharechain peer node: pool::NodeBridge<NodeImpl, Legacy, Actual>. The
    // NodeImpl ctor opens ~/.c2pool/<net>/sharechain_leveldb and seeds the addr
    // store from m_bootstrap_addrs, so config must be populated BEFORE
    // construction (above).
    dgb::Node p2p_node(&ioc, &config);
    p2p_node.set_target_outbound_peers(4);
    p2p_node.core::Server::listen(dgb::PoolConfig::P2P_PORT);
    std::cout << "[DGB] sharechain peer listening on port "
              << dgb::PoolConfig::P2P_PORT
              << " — proto adv=" << dgb::PoolConfig::ADVERTISED_PROTOCOL_VERSION
              << " min=" << dgb::PoolConfig::MINIMUM_PROTOCOL_VERSION
              << " prefix=" << dgb::PoolConfig::DEFAULT_PREFIX_HEX << std::endl;
    p2p_node.start_outbound_connections();  // no-op until seed hosts exist

    std::cout << "[DGB] run-loop up: " << network_summary(params) << "\n";
    std::cout << "[DGB] io_context running. Ctrl-C to stop. "
              << "(Stratum work source + won-block dispatch bind in the next slice)"
              << std::endl;

    ioc.run();

    std::cout << "[DGB] io_context stopped — clean exit" << std::endl;
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_selftest = false;
    bool want_run = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dgb " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0)     want_help = true;
        if (std::strcmp(argv[i], "--selftest") == 0) want_selftest = true;
        if (std::strcmp(argv[i], "--run") == 0)      want_run = true;
    }

    const core::CoinParams params = dgb::make_coin_params(/*testnet=*/false);
    print_banner(argv[0], params);

    if (want_help)
        return 0;

    // --run: stand up the run-loop spine (io_context + graceful shutdown).
    if (want_run)
        return run_node(params, /*testnet=*/false);

    // --selftest, or a bare invocation: drive the live score path so the
    // binary exercises real consensus code, then exit cleanly.
    (void)want_selftest;
    return run_selftest(params);
}
