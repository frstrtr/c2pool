// c2pool-dgb — DigiByte Scrypt-only (V36) p2pool node entry point.
//
// SLICE #4 (Option B): genuinely minimal COMPILING SKELETON. This wires the
// CMake c2pool-dgb target so the binary builds + links off master; it does
// NOT yet run a node. The embedded-daemon + pool/sharechain body is M3 /
// Phase B (DGB = PORT-not-activation; Phase A p2p+mempool already landed under
// impl/dgb/coin/). When the pool-pillars node.cpp lands it replaces the
// skeleton via a clean dgb-only re-cut off master.
//
// V36 scope: Scrypt blocks validated; the other 4 DGB algos (SHA256d, Skein,
// Qubit, Odocrypt) are accept-by-continuity / ignored — full 5-algo support
// is V37. Compatibility target: frstrtr/p2pool-merged-v36 (share format,
// sharechain rules, PPLNS, Stratum, block submission). See
// c2pool-dgb-embedded-impl-plan.md (frstrtr/the docs/v36).
//
// Mirrors src/c2pool/main_btc.cpp's target shape, pruned to a stub entry.

#include <impl/dgb/node.hpp>

#include <cstring>
#include <iostream>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-dgb " << C2POOL_VERSION << " — DigiByte Scrypt-only (V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help]\n\n"
        << "Status: skeleton (slice #4). The node run-loop (embedded daemon +\n"
        << "        pool pillars) lands in M3 / Phase B.\n"
        << "Network: " << dgb::network_summary() << "\n";
}

} // namespace

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dgb " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0) {
            print_banner(argv[0]);
            return 0;
        }
    }

    print_banner(argv[0]);
    return dgb::run_skeleton();
}
