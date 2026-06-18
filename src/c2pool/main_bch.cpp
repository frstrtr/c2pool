// c2pool-bch — Bitcoin Cash (BCH, SHA256d standalone parent, V36) p2pool node
// entry point.
//
// This is the EXE-WIRE slice that closes the "no runnable c2pool-bch
// entrypoint" gap (integrator 2026-06-18): the M5 lane was pure state-machine +
// ctest with no main_bch.cpp, so nothing could be stood up to drive a live
// daemon path. This target gives c2pool-bch a real entrypoint that builds +
// links off the branch and drives a LIVE BCH consensus path at startup, so the
// coin smoke exercises real consensus code rather than merely linking it.
//
// LIVE PATH = ABLA (CHIP-2023-01, May 2024 adaptive blocksize limit). The
// embedded daemon (coin/embedded_daemon.hpp) owns AblaRuntime, which feeds live
// block sizes from VM300 bchn-bch into the dynamic template budget; the budget
// floor invariant (folding live sizes forward can only RAISE the budget, never
// undercut the 32 MB activation/floor) is the safety property the whole M4/M5
// size loop rests on. We drive that exact code here: bch::coin::abla::State
// replayed forward via NextBlockState (1:1 BCHN consensus/abla.cpp port), proven
// to grow on full blocks and hold the floor on empty ones. abla.hpp is
// std-only (no core/yaml/uint256/leveldb), so — like the c2pool-dgb skeleton —
// this target links NOTHING beyond the standard runtime and never drags in the
// core OBJECT-lib web_server/stratum tangle. Per-coin isolation: src/impl/bch
// headers only; zero p2pool-merged-v36 surface (ABLA carries no share/coinbase/
// PPLNS/PoW bytes — it is local template-budget consensus only).
//
// NOT YET WIRED HERE: the P2P IBD run-loop (coin/p2p_node.cpp + coin_node.cpp
// read-only sync to 192.168.86.110:8333) and its synced-height / false-eviction
// / reissue_count() live numbers. That is the NEXT slice (a --ibd mode that
// stands up EmbeddedDaemon::run over the P2P front-end); it pulls the network
// TUs and is kept separate so this entrypoint lands additive and clean. The
// embedded work source stays primary; external BCHN-RPC remains the fallback.
//
// Conformance oracle: frstrtr/p2poolBCH (kr1z1sBCH); BCH = SHA256d standalone
// parent (NOT merged-mined). Mirrors src/c2pool/main_dgb.cpp target shape.

#include <impl/bch/coin/abla.hpp>

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

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-bch " << C2POOL_VERSION << " — Bitcoin Cash (SHA256d, V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n\n"
        << "Status: M5 pool/sharechain + embedded-daemon assembly live (header).\n"
        << "        The embedded daemon (coin/embedded_daemon.hpp) is the primary\n"
        << "        work source; external BCHN-RPC stays as the fallback. The P2P\n"
        << "        IBD run-loop (read-only sync vs VM300 bchn-bch .110:8333)\n"
        << "        lands in the next --ibd slice.\n"
        << "Consensus: ABLA floor budget = "
        << (DEFAULT_CONSENSUS_BLOCK_SIZE / ONE_MEGABYTE) << " MB; ASERT DAA; CTOR;\n"
        << "        CashTokens transparent; standalone SHA256d parent.\n";
}

// Drive the LIVE ABLA template-budget path (coin/abla.hpp, 1:1 BCHN port). This
// is the exact code AblaRuntime replays when full_block sizes arrive from the
// embedded daemon. We prove the two properties the M4/M5 size loop depends on:
//   (1) GROWTH  — sustained full blocks raise the limit above the floor.
//   (2) FLOOR   — empty/small blocks never undercut the 32 MB activation floor.
int run_selftest()
{
    const Config config = Config::MakeDefault();         // 32 MB floor default
    const uint64_t floor_limit = State(config, 0).GetBlockSizeLimit();

    // (1) Replay 5000 FULL blocks (each at the current limit): budget grows.
    State grow(config, DEFAULT_CONSENSUS_BLOCK_SIZE);
    for (int i = 0; i < 5000; ++i)
        grow = grow.NextBlockState(config, grow.GetBlockSizeLimit());
    const uint64_t grown_limit = grow.GetBlockSizeLimit();

    // (2) Replay 5000 EMPTY blocks from the same anchor: budget holds the floor.
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

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_selftest = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-bch " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0)     want_help = true;
        if (std::strcmp(argv[i], "--selftest") == 0) want_selftest = true;
    }

    print_banner(argv[0]);
    if (want_help)
        return 0;

    // --selftest, or a bare invocation (no run-loop yet): drive the live ABLA
    // budget path so the binary exercises real consensus code, then exit.
    (void)want_selftest;
    return run_selftest();
}
