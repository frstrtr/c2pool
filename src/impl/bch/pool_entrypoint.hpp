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
// G3-slice-b (integrator 2026-06-27): this entrypoint now also stands up the
// miner-facing IWorkSource + Stratum front-end, closing the M5 "no BCH
// IWorkSource served" gap. BCHWorkSource bridges the coin-agnostic
// core::StratumServer to BCH work generation off the embedded daemon's
// HeaderChain + Mempool, and routes a mainnet-hit (share-author) block down the
// SAME dual-path broadcaster the won-block sink uses (embedded P2P primary +
// BCHN submitblock fallback). So the coinbase a genuine share assembles is what
// reaches the network -- not a synthetic solo-cb leg-C block (the slice-a
// caveat). standup_pool_run is the production caller the work_source.hpp Stage-a
// TODO names ("wire StratumServer into standup_pool_run + main_bch.cpp --pool").
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
//   6. BCHWorkSource + core::StratumServer -- miner-facing front-end; a hit
//      block routes through the SAME daemon.broadcast_won_block dual path.
//
// The sink being live is NECESSARY but NOT SUFFICIENT to declare BCH
// block-viable: reconstruct_won_block() still gates on full gentx (coinbase)
// reconstruction, and the dual paths must be proven to FIRE+ACCEPT against a
// live BCHN peer -- the behavioural half of criterion C, a separate e2e slice
// (code-exists != fires).
//
// PER-COIN ISOLATION: src/impl/bch only. p2pool-merged-v36 surface: NONE
// (block dispatch + run-loop bring-up, not share/PPLNS/coinbase/AuxPoW bytes).
// BCH = SHA256d standalone parent.

#include "node.hpp"
#include "pool_standup.hpp"
#include "coin/embedded_daemon.hpp"
#include "stratum/work_source.hpp"

#include <core/log.hpp>
#include <core/stratum_server.hpp>

#include <btclibs/util/strencodings.h>   // HexStr

#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace bch
{

// Stand up the BCH pool node + embedded coin daemon on a shared io_context,
// bind the won-block sink, assert it is live, stand up the miner-facing
// IWorkSource + Stratum front-end, then drive the run-loop.
// `config` and `ioc` outlive this call (owned by the binary entrypoint); the
// daemon, node, work source and stratum server are owned here for the run-loop
// lifetime. `anchor_height` is the cold-start ABLA floor anchor (operator-
// approved VM300 record, floor-equivalent). `stratum_addr`/`stratum_port` are
// the miner-facing bind (port 0 == stratum disabled); `is_testnet` selects the
// BCH network params the work source stamps onto generated work. Returns when
// the io_context stops.
inline void standup_pool_run(boost::asio::io_context& ioc,
                             Config& config,
                             uint32_t anchor_height,
                             const std::string& stratum_addr = "0.0.0.0",
                             uint16_t stratum_port = 0,
                             bool is_testnet = false,
                             bool is_regtest = false)
{
    // 1+2: embedded daemon up first -- it owns the work source + RPC fallback
    // the pool node consumes, and is the broadcast sink the node wires into.
    coin::EmbeddedDaemon<Config> daemon(&ioc, &config, anchor_height, is_regtest);
    daemon.run();

    // 3: the pool node (sharechain, LevelDB, P2P, Stratum).
    Node node(&ioc, &config);  // concrete NodeBridge<NodeImpl,Legacy,Actual> -- NodeImpl alone is abstract (ICommunicator::handle lives in NodeBridge)

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

    // 6: miner-facing IWorkSource + Stratum front-end. BCHWorkSource generates
    // work off the embedded daemon's HeaderChain + Mempool (SHA256d, no-segwit,
    // CashTokens transparent-carry), and routes a mainnet-hit block through the
    // SAME dual-path broadcaster (embedded P2P primary + BCHN submitblock
    // fallback) the won-block sink uses -- so the share-author coinbase reaches
    // the network down both legs. Held here so the shared_ptr + server outlive
    // ioc.run() alongside the daemon they reference.
    auto work_source = std::make_shared<stratum::BCHWorkSource>(
        daemon.chain(),
        daemon.mempool(),
        is_testnet,
        [&daemon](const std::vector<unsigned char>& block_bytes,
                  uint32_t /*height*/) -> bool {
            // Genuine share-author block -> dual-path broadcaster. block_hex for
            // the BCHN submitblock fallback is HexStr(block_bytes). True iff at
            // least one sink accepted (embedded P2P relay OR external RPC).
            coin::BlockBroadcast r =
                daemon.broadcast_won_block(block_bytes, HexStr(block_bytes));
            return r.any();
        });

    std::unique_ptr<core::StratumServer> stratum_server;
    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_addr, stratum_port, work_source);
        if (stratum_server->start()) {
            LOG_INFO << "[BCH-POOL] stratum listening on " << stratum_addr << ":"
                     << stratum_port << " (BCHWorkSource: SHA256d, no-segwit,"
                     << " CashTokens transparent-carry; hit block routes the"
                     << " dual-path broadcaster).";
        } else {
            LOG_ERROR << "[BCH-POOL] stratum FAILED to bind " << stratum_addr << ":"
                      << stratum_port << " -- stratum disabled, daemon run-loop continues.";
            stratum_server.reset();
        }
    } else {
        LOG_INFO << "[BCH-POOL] stratum disabled (no --stratum bind given);"
                 << " embedded daemon run-loop only.";
    }

    // Drive the shared io_context: pool node + embedded daemon + stratum run together.
    ioc.run();
}

} // namespace bch
