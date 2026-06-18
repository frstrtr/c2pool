#pragma once

// BCH pool-node won-block sink standup -- broadcaster-gate leg C, pool-entrypoint
// (integrator 2026-06-18, entrypoint-standup slice, ordered BEFORE gentx).
//
// THE single startup wiring call. The pool node (NodeImpl) stays coin-daemon-
// agnostic: its tracker().m_on_block_found lambda fires the instant a verified
// share meets the BCH block target, but only down a sink the binary entrypoint
// supplies via set_block_broadcaster(). This helper IS that one call -- it binds
// the sink to the embedded daemon dual-path broadcast_won_block (embedded P2P
// PRIMARY + external BCHN submitblock FALLBACK, both fired per the dual-path
// gate rule). Construct NodeImpl + EmbeddedDaemon, call this once before the
// run-loop; idempotent (set_block_broadcaster replaces).
//
// The sink being live is NECESSARY but NOT SUFFICIENT to close the gate to
// verified: reconstruct_won_block() still returns nullopt until gentx (coinbase)
// full-body reconstruction lands (share_check.hpp:472) and leg C is exercised
// against VM300 (192.168.86.110:8333). Until then the lambda has a live sink yet
// emits nothing -- the gate stays honestly GAP and no partial block is relayed.
//
// PER-COIN ISOLATION: src/impl/bch only. Zero p2pool-merged-v36 surface -- block
// dispatch, NOT share/PPLNS/coinbase bytes. BCH = SHA256d standalone parent.

#include "node.hpp"
#include "coin/embedded_daemon.hpp"

#include <string>
#include <vector>

namespace bch
{

// Bind the pool node won-block sink to the embedded daemon dual-path broadcaster.
// Capture by reference: both objects are owned by the binary entrypoint and
// outlive the pool run-loop, so the lambda never dangles. Call once at startup.
inline void wire_won_block_sink(NodeImpl& node, coin::EmbeddedDaemon<Config>& daemon)
{
    node.set_block_broadcaster(
        [&daemon](const std::vector<unsigned char>& block_bytes,
                  const std::string& block_hex)
        {
            daemon.broadcast_won_block(block_bytes, block_hex);
        });
}

} // namespace bch
