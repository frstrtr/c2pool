#include "node.hpp"

#include <string>

// c2pool-dgb node skeleton (slice #4, Option B).
//
// COMPILING SKELETON ONLY. The real embedded-daemon + pool/sharechain body
// (DensePPLNSWindow / PPLNS, p2p run-loop, template builder, broadcaster) is
// M3 / Phase B per the embedded-daemon roadmap: DGB is PORT-not-activation —
// Phase A p2p + mempool already landed under impl/dgb/coin/, and Phase B
// brings the pool pillars. When the pool-pillars node.cpp lands it REPLACES
// this file via a clean dgb-only re-cut off master; see
// c2pool-dgb-embedded-impl-plan.md (frstrtr/the docs/v36).
//
// Deliberately free of pool logic so c2pool-dgb LINKS today without dragging
// Phase B forward, instantiating the Fileconfig-derived config classes (whose
// load()/get_default() bodies are Phase B), or touching the shared
// bitcoin_family / DOGE-aux surface.

namespace dgb
{

// One-line summary of the DGB-Scrypt network this binary targets. Reads the
// compile-time constants from config_{coin,pool}.hpp (header-only) — no
// Fileconfig instantiation.
std::string network_summary()
{
    return std::string("DigiByte Scrypt-only (V36) — ")
        + "pool_p2p_port=" + std::to_string(PoolConfig::P2P_PORT)
        + " coin_p2p_port=" + std::to_string(CoinParams::MAINNET_P2P_PORT)
        + " block_period=" + std::to_string(CoinParams::BLOCK_PERIOD) + "s"
        + " gbt_algo=" + std::string(CoinParams::GBT_ALGO);
}

// Skeleton entry point. Phase B replaces this with the real node run-loop.
int run_skeleton()
{
    return 0;
}

} // namespace dgb
