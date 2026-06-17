// c2pool-dgb — DigiByte Scrypt-only (V36) p2pool node entry point.
//
// Wires the real dgb sharechain/pool TU (pool pillars + score path, ported from
// LTC under impl/dgb/ across PRs #112/#113/#115/#121/#129/#131/#132/#134) into
// the c2pool-dgb executable. This is the exe-wire slice: it replaces the
// slice-#4 skeleton entry (dgb::run_skeleton/network_summary, removed when #134
// dropped the real node.cpp in) and drives the LIVE chain-score path at
// startup, so the coin smoke gate exercises share_tracker::score() rather than
// merely linking it. node.cpp (the concrete dgb::NodeImpl) is compiled into the
// target so the real node TU links; its full run-loop (NodeBridge over the
// embedded digibyted P2P + Stratum) is a later Phase B slice — dgb::NodeImpl is
// abstract (ICommunicator::handle is supplied by the NodeBridge wrapper), so a
// bare node is not stood up here. The score path lives on dgb::ShareTracker,
// which we drive directly (header-only, no network / no LevelDB).
//
// V36 scope: Scrypt blocks validated; the other 4 DGB algos (SHA256d, Skein,
// Qubit, Odocrypt) are accept-by-continuity / ignored — full 5-algo support is
// V37. Conformance oracle: frstrtr/p2pool-dgb-scrypt (DGB-Scrypt standalone
// parent; merged-v36 byte-compat WAIVED for DGB per operator 2026-06-17).
// CoinParams are oracle-sourced via dgb::make_coin_params (no hardcoded bytes).
// Mirrors src/c2pool/main_btc.cpp's target shape.

#include <impl/dgb/node.hpp>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

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
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n\n"
        << "Status: pool/sharechain pillars live (Phase B). The embedded-daemon\n"
        << "        run-loop (digibyted P2P + Stratum) lands in a later slice;\n"
        << "        external digibyted RPC stays as a fallback.\n"
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

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_selftest = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dgb " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0)     want_help = true;
        if (std::strcmp(argv[i], "--selftest") == 0) want_selftest = true;
    }

    const core::CoinParams params = dgb::make_coin_params(/*testnet=*/false);
    print_banner(argv[0], params);

    if (want_help)
        return 0;

    // --selftest, or a bare invocation (no run-loop yet): drive the live score
    // path so the binary exercises real consensus code, then exit cleanly.
    (void)want_selftest;
    return run_selftest(params);
}
