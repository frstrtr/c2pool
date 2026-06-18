#pragma once

// BCH pool run-loop ENTRYPOINT standup -- broadcaster-gate leg C, pool side
// (integrator 2026-06-18: "NodeImpl + EmbeddedDaemon constructed,
// bch::wire_won_block_sink called live").
//
// This is the single production call site the c2pool-bch binary main invokes to
// bring the pool node up WITH its embedded coin daemon and the won-block sink
// already bound. It owns both objects for the lifetime of the run-loop (they
// outlive io_context.run(), so the wire_won_block_sink lambda -- which captures
// the daemon by reference -- never dangles) and enforces the structural half of
// broadcaster-gate criterion C: the won-block sink MUST be live before the
// run-loop accepts shares, or a verified block-meeting share would fire
// m_on_block_found into a null sink and the win would be silently dropped.
//
// Construction + wiring order (matches EmbeddedDaemon::run() contract):
//   1. EmbeddedDaemon(ctx, config, anchor) -- cold-start floor-anchored ABLA.
//   2. daemon.run() -- external BCHN-RPC fallback (init_rpc) + assemble() +
//      ABLA loop + operator-approved cold-start anchor pin. Embedded-primary
//      work source live, external fallback retained (external_fallback law).
//   3. NodeImpl(ctx, config) -- the pool node (sharechain, storage, P2P).
//   4. wire_won_block_sink(node, daemon) -- bind tracker().m_on_block_found ->
//      daemon.broadcast_won_block (dual path: embedded P2P PRIMARY + external
//      BCHN submitblock FALLBACK).
//   5. ASSERT node.has_block_broadcaster() -- the sink is LIVE. This is the
//      structural criterion-C check; throwing here is correct (a missing sink
//      at the production entrypoint is a wiring bug, not a runtime condition).
//
// The sink being live is NECESSARY but NOT SUFFICIENT to declare BCH
// block-viable: reconstruct_won_block() still gates on full gentx (coinbase)
// reconstruction, and the dual paths must be proven to FIRE+ACCEPT against the
// live VM300 bchn-bch peer (192.168.86.110:8333) -- the behavioural half of
// criterion C, a separate read-only e2e slice (code-exists != fires).
//
// PER-COIN ISOLATION: src/impl/bch only. p2pool-merged-v36 surface: NONE
// (block dispatch + run-loop bring-up, not share/PPLNS/coinbase/AuxPoW bytes).
// BCH = SHA256d standalone parent.

#include "node.hpp"
#include "pool_standup.hpp"
#include "coin/embedded_daemon.hpp"

#include <core/log.hpp>

#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <stdexcept>

namespace bch
{

// Stand up the BCH pool node + embedded coin daemon on a shared io_context,
// bind the won-block sink, assert it is live, then drive the run-loop.
// `config` and `ioc` outlive this call (owned by the binary entrypoint); the
// daemon and node are owned here for the run-loop lifetime. `anchor_height` is
// the cold-start ABLA floor anchor (operator-approved VM300 record, floor-
// equivalent). Returns when the io_context stops.
inline void standup_pool_run(boost::asio::io_context& ioc,
                             Config& config,
                             uint32_t anchor_height)
{
    // 1+2: embedded daemon up first -- it owns the work source + RPC fallback
    // the pool node consumes, and is the broadcast sink the node wires into.
    coin::EmbeddedDaemon<Config> daemon(&ioc, &config, anchor_height);
    daemon.run();

    // 3: the pool node (sharechain, LevelDB, P2P, Stratum).
    NodeImpl node(&ioc, &config);

    // 4: bind the in-operation won-block fire path to the dual-path broadcaster.
    wire_won_block_sink(node, daemon);

    // 5: structural criterion-C gate -- refuse to run shares without a live sink.
    if (!node.has_block_broadcaster()) {
        LOG_FATAL << "[BCH-POOL] won-block sink NOT live after wire_won_block_sink"
                  << " -- refusing to start run-loop (a won block would be dropped).";
        throw std::runtime_error("bch::standup_pool_run: won-block broadcaster sink not wired");
    }

    LOG_INFO << "[BCH-POOL] pool run-loop standup complete: embedded daemon up,"
             << " won-block sink LIVE (dual-path: embedded P2P primary + BCHN"
             << " submitblock fallback). Structural broadcaster-gate criterion-C"
             << " satisfied; live VM300 e2e is the behavioural half.";

    // Drive the shared io_context: pool node + embedded daemon run together.
    ioc.run();
}

} // namespace bch
