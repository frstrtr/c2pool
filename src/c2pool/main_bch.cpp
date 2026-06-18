// c2pool-bch — Bitcoin Cash (BCH, SHA256d standalone parent, V36) p2pool node
// entry point.
//
// EXE-WIRE slice (integrator 2026-06-18) closed the "no runnable c2pool-bch
// entrypoint" gap. This slice adds the --ibd RUN-LOOP: a read-only headers-first
// initial-block-download harness that stands up the embedded daemon over its
// P2P front-end against VM300 bchn-bch (192.168.86.110:8333) and reports the
// live sync evidence the M5 size loop rests on:
//   - synced height advancing PAST the init() checkpoint  (chain-ingest works)
//   - false_evict_count                                   (0 == clean sync)
//   - in_flight / reissue_count                           (download-window health)
//
// TWO MODES:
//   --selftest (default) : drive the LIVE ABLA template-budget path
//       (coin/abla.hpp, 1:1 BCHN consensus/abla.cpp port) std-only, proving the
//       GROWTH and FLOOR invariants. Network-free, no core runtime.
//   --ibd [opts]         : stand up EmbeddedDaemon::start_ibd over the P2P
//       front-end and run a bounded io_context loop, logging the evidence tuple
//       each tick until caught up or the deadline. Read-only: a P2P peer
//       connection issues no qm/control op, so VM300 stays read-only. This is
//       the evidence harness, NOT the production daemon — start_ibd skips
//       init_rpc(); run() still owns the external BCHN-RPC fallback.
//
// PER-COIN ISOLATION: src/impl/bch headers only; the --ibd path links the core
// OBJECT-lib (NodeP2P/HeaderChain/Timer) — a SAFE-ADDITIVE link-line addition
// on this target only (integrator 2026-06-18), no shared-base/core source edit.
// p2pool-merged-v36 surface: NONE — ABLA + SPV header state carry no share/
// coinbase/PPLNS/PoW bytes. Conformance oracle: frstrtr/p2poolBCH (kr1z1sBCH);
// BCH = SHA256d standalone parent (NOT merged-mined).

#include <impl/bch/coin/abla.hpp>
#include <impl/bch/config.hpp>
#include <impl/bch/coin/embedded_daemon.hpp>

#include <core/netaddress.hpp>
#include <core/timer.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

using bch::coin::abla::Config;
using bch::coin::abla::State;
using bch::coin::abla::DEFAULT_CONSENSUS_BLOCK_SIZE;
using bch::coin::abla::ONE_MEGABYTE;
using bch::coin::EmbeddedDaemon;

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-bch " << C2POOL_VERSION << " — Bitcoin Cash (SHA256d, V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n"
        << "       " << argv0 << " --ibd [--testnet] [--peer HOST:PORT] [--max-seconds N]\n\n"
        << "Status: M5 pool/sharechain + embedded-daemon assembly live.\n"
        << "        The embedded daemon (coin/embedded_daemon.hpp) is the primary\n"
        << "        work source; external BCHN-RPC stays as the fallback.\n"
        << "Consensus: ABLA floor budget = "
        << (DEFAULT_CONSENSUS_BLOCK_SIZE / ONE_MEGABYTE) << " MB; ASERT DAA; CTOR;\n"
        << "        CashTokens transparent; standalone SHA256d parent.\n";
}

// Drive the LIVE ABLA template-budget path (coin/abla.hpp, 1:1 BCHN port).
//   (1) GROWTH  — sustained full blocks raise the limit above the floor.
//   (2) FLOOR   — empty/small blocks never undercut the 32 MB activation floor.
int run_selftest()
{
    const Config config = Config::MakeDefault();         // 32 MB floor default
    const uint64_t floor_limit = State(config, 0).GetBlockSizeLimit();

    State grow(config, DEFAULT_CONSENSUS_BLOCK_SIZE);
    for (int i = 0; i < 5000; ++i)
        grow = grow.NextBlockState(config, grow.GetBlockSizeLimit());
    const uint64_t grown_limit = grow.GetBlockSizeLimit();

    State hold(config, DEFAULT_CONSENSUS_BLOCK_SIZE);
    for (int i = 0; i < 5000; ++i)
        hold = hold.NextBlockState(config, 0);
    const uint64_t held_limit = hold.GetBlockSizeLimit();

    std::cout
        << "[selftest] live bch::coin::abla::State replayed (BCHN consensus/abla port)\n"
        << "[selftest]   floor  limit = " << floor_limit
        << " (" << (floor_limit / ONE_MEGABYTE) << " MB)\n"
        << "[selftest]   grown  limit = " << grown_limit
        << " (" << (grown_limit / ONE_MEGABYTE) << " MB) after 5000 full blocks\n"
        << "[selftest]   held   limit = " << held_limit
        << " (" << (held_limit / ONE_MEGABYTE) << " MB) after 5000 empty blocks\n";

    const bool grew = grown_limit > floor_limit;
    const bool held = held_limit >= floor_limit;
    if (!grew || !held) {
        std::cout << "[selftest] FAIL — ABLA invariant violated"
                  << " (grew=" << grew << " held=" << held << ")\n";
        return 1;
    }
    std::cout << "[selftest]   GROWTH ok (grown > floor); FLOOR ok (held >= floor)\n"
              << "[selftest] OK\n";
    return 0;
}

// Read-only headers-first IBD harness. Stands up the embedded daemon over the
// P2P front-end pointed at one BCHN peer, kicks the first getheaders once the
// handshake is up, and logs the evidence tuple every TICK seconds until the
// chain catches the peer tip (with no in-flight blocks) or the deadline fires.
int run_ibd(const std::string& host, uint16_t port, bool testnet, uint32_t max_seconds)
{
    boost::asio::io_context ctx;

    // Construct config WITHOUT a file load: Config(coin_name) only stores paths
    // (Fileconfig ctor reads nothing until init()), so we skip init() and set
    // by hand only the two fields the IBD harness touches — the testnet flag and
    // the single BCHN P2P peer. No pool.yaml/coin.yaml is read or written.
    bch::Config cfg("bch-ibd");
    cfg.m_testnet = testnet;
    const NetService peer(host, port);
    cfg.coin()->m_p2p.address = peer;

    EmbeddedDaemon<bch::Config> daemon(&ctx, &cfg, /*anchor_height=*/0);
    daemon.start_ibd(peer);

    const uint32_t init_height = daemon.ibd_synced_height();
    std::cout << "[ibd] read-only sync vs " << host << ":" << port
              << (testnet ? " (testnet)" : " (mainnet)")
              << " — init checkpoint=" << init_height
              << ", deadline=" << max_seconds << "s\n";

    bool kicked = false;
    uint32_t elapsed = 0;
    const uint32_t TICK = 5;

    core::Timer tick(&ctx, /*repeat=*/true);
    tick.start(TICK, [&]() {
        elapsed += TICK;
        if (!kicked && daemon.ibd_handshake_ready()) {
            daemon.ibd_kick_sync();
            kicked = true;
            std::cout << "[ibd] handshake up; getheaders kicked from height "
                      << daemon.ibd_synced_height() << "\n";
        }
        const uint32_t h   = daemon.ibd_synced_height();
        const uint32_t tip = daemon.ibd_peer_tip();
        std::cout << "[ibd] t=" << elapsed << "s synced=" << h
                  << " peer_tip=" << tip
                  << " in_flight=" << daemon.ibd_in_flight()
                  << " reissue=" << daemon.ibd_reissue_count()
                  << " false_evict=" << daemon.ibd_false_evict_count() << "\n";

        const bool advanced  = h > init_height;
        const bool caught_up = kicked && tip > 0 && h >= tip && daemon.ibd_in_flight() == 0;
        if (caught_up || elapsed >= max_seconds) {
            std::cout << "[ibd] " << (caught_up ? "SYNCED" : "DEADLINE")
                      << " — final synced=" << h
                      << " (init checkpoint=" << init_height
                      << ", advanced=" << (advanced ? "yes" : "NO") << ")"
                      << " false_evict=" << daemon.ibd_false_evict_count()
                      << " reissue=" << daemon.ibd_reissue_count() << "\n";
            tick.stop();
            ctx.stop();
        }
    });

    ctx.run();
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_ibd = false;
    bool testnet = false;
    std::string host = "192.168.86.110";   // VM300 bchn-bch
    uint16_t port = 8333;
    uint32_t max_seconds = 600;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-bch " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0)     want_help = true;
        if (std::strcmp(argv[i], "--ibd") == 0)      want_ibd = true;
        if (std::strcmp(argv[i], "--testnet") == 0) { testnet = true; port = 18333; }
        if (std::strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
            std::string hp = argv[++i];
            const auto c = hp.rfind(char(58));  // ASCII colon
            if (c != std::string::npos) {
                host = hp.substr(0, c);
                port = static_cast<uint16_t>(std::stoi(hp.substr(c + 1)));
            } else {
                host = hp;
            }
        }
        if (std::strcmp(argv[i], "--max-seconds") == 0 && i + 1 < argc)
            max_seconds = static_cast<uint32_t>(std::stoul(argv[++i]));
    }

    print_banner(argv[0]);
    if (want_help)
        return 0;

    if (want_ibd)
        return run_ibd(host, port, testnet, max_seconds);

    // Default / --selftest: drive the live ABLA budget path, then exit.
    return run_selftest();
}
