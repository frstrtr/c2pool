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
#include "config_pool.hpp"      // bch::PoolConfig::get_donation_script
#include "share_check.hpp"      // bch::create_local_share (transitive via node.hpp)
#include "share_types.hpp"      // bch::StaleInfo
#include "coin/block.hpp"       // bch::coin::SmallBlockHeaderType

#include <core/pack_types.hpp>    // BaseScript

#include <core/log.hpp>
#include <core/stratum_server.hpp>

#include <btclibs/util/strencodings.h>   // HexStr

#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <cstring>
#include <shared_mutex>
#include <type_traits>
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

    // ── Sharechain WRITE path: local-share author wiring ─────────────────
    // Without these callbacks BCHWorkSource accepts miner submissions that
    // clear the sharechain target but DROPS them ("accepted (no-tracker)",
    // work_source.cpp:686) because create_share_fn_ is null -- c2pool-bch runs
    // as a bare stratum proxy and Stored shares stay stuck at 0. This block
    // closes that gap (mirrors main_btc.cpp:863/1118), wiring the three
    // callbacks the local-author path needs:
    //   - best_share_hash_fn : new-job prev_share = our sharechain tip
    //   - donation_script    : version-gated coinbase residual recipient
    //   - create_share_fn    : mining_submit -> bch::create_local_share ->
    //                          tracker.add -> broadcast_share + notify_local_share
    // BCH is a STANDALONE SHA256d parent: no segwit, no merged/aux dimension
    // (merged_addrs = {}, segwit_active=false, witness_* empty). ref_hash_fn /
    // pplns_fn are a FOLLOW-UP slice -- they gate peer-verifiable ref_hash +
    // PPLNS payout distribution, NOT local Stored accumulation; until wired,
    // build_connection_coinbase falls back to a single-output coinbase and
    // create_local_share computes its own share target via
    // tracker.compute_share_target (has_frozen=false).
    work_source->set_best_share_hash_fn(
        [&node]() -> uint256 { return node.best_share_hash(); });

    // Initial donation matches the cold-start create version (35 -> P2PK). A
    // ratchet-driven refresh to the COMBINED P2SH on v36 activation is the same
    // follow-up slice as pplns_fn/ref_hash_fn.
    work_source->set_donation_script(PoolConfig::get_donation_script(35));

    work_source->set_create_share_fn(
        [&node](const std::vector<unsigned char>& full_coinbase,
                const std::vector<uint8_t>&        header_80b,
                const core::stratum::JobSnapshot&  job,
                const std::vector<unsigned char>& payout_script) -> uint256
        {
            if (header_80b.size() != 80) {
                LOG_WARNING << "[BCH-CREATE-SHARE] bad header size=" << header_80b.size();
                return uint256::ZERO;
            }

            // Parse the 80-byte BCH block header -> SmallBlockHeaderType. The
            // merkle_root (bytes 36..67) is reconstructible from coinbase +
            // frozen branches, so it is not stored in min_header.
            auto read_le32 = [](const uint8_t* p) -> uint32_t {
                return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                     | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
            };
            coin::SmallBlockHeaderType min_header;
            min_header.m_version = read_le32(header_80b.data() + 0);
            std::memcpy(min_header.m_previous_block.data(), header_80b.data() + 4, 32);
            min_header.m_timestamp = read_le32(header_80b.data() + 68);
            min_header.m_bits      = read_le32(header_80b.data() + 72);
            min_header.m_nonce     = read_le32(header_80b.data() + 76);

            BaseScript coinbase_bs(std::vector<unsigned char>(
                full_coinbase.begin(), full_coinbase.end()));

            // Stratum branches are hex of LE-internal bytes -> ParseHex+memcpy
            // (SetHex would byte-reverse and break the merkle root the miner used).
            std::vector<uint256> merkle_branches;
            merkle_branches.reserve(job.merkle_branches.size());
            for (const auto& bhex : job.merkle_branches) {
                uint256 b;
                auto bb = ParseHex(bhex);
                if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
                merkle_branches.push_back(b);
            }

            // Exclusive tracker lock (non-blocking): defer to the next submit if
            // the compute thread is mid-think rather than freezing the io_context.
            std::unique_lock<std::shared_mutex> lk(node.tracker_mutex(), std::try_to_lock);
            if (!lk.owns_lock()) {
                LOG_INFO << "[BCH-CREATE-SHARE] tracker busy -- share deferred";
                return uint256::ZERO;
            }

            // Author at the current tip's version (35 on an empty chain), voting
            // desired=36. Same-version authoring never trips the 60%-by-work
            // accept gate; the ratchet-driven upgrade to v36 is a follow-up slice.
            int64_t create_ver = 35;
            if (!job.prev_share_hash.IsNull() &&
                node.tracker().chain.contains(job.prev_share_hash)) {
                node.tracker().chain.get_share(job.prev_share_hash).invoke(
                    [&](auto* s) {
                        using ST = std::remove_pointer_t<decltype(s)>;
                        create_ver = ST::version;
                    });
            }

            uint256 share_hash;
            try {
                share_hash = bch::create_local_share(
                    node.tracker(), min_header, coinbase_bs,
                    /* subsidy */               job.subsidy,
                    /* prev_share */            job.prev_share_hash,
                    merkle_branches, payout_script,
                    /* donation bps */          50,
                    /* merged_addrs */          {},
                    /* stale_info */            StaleInfo::none,
                    /* segwit_active */         false,        // BCH: no segwit
                    /* witness_commitment */    {},
                    /* message_data */          {},
                    /* actual_coinbase_bytes */ full_coinbase,
                    /* witness_root */          uint256(),
                    /* override_max_bits */     job.share_max_bits,  // pin share target to
                    /* override_bits */         job.share_bits,      // what the miner was issued
                    /* frozen_absheight */      0,
                    /* frozen_abswork */        uint128(),
                    /* frozen_far_share_hash */ uint256(),
                    /* frozen_timestamp */      0,
                    /* frozen_merged_payout */  uint256(),
                    /* has_frozen */            false,
                    /* frozen_merkle_branches*/ {},
                    /* frozen_witness_root */   uint256(),
                    /* frozen_merged_cb_info */ {},
                    /* share_version */         create_ver,
                    /* desired_version */       36);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BCH-CREATE-SHARE] threw: " << e.what();
                return uint256::ZERO;
            }

            // Drop the exclusive lock BEFORE broadcast/notify (they take their
            // own locks / post to the io_context).
            lk.unlock();
            if (!share_hash.IsNull()) {
                node.broadcast_share(share_hash);
                node.notify_local_share(share_hash);
                LOG_INFO << "[BCH-CREATE-SHARE] OK + broadcast v" << create_ver
                         << " hash=" << share_hash.GetHex().substr(0, 16);
            }
            return share_hash;
        });

    LOG_INFO << "[BCH-POOL] sharechain WRITE path wired (mining_submit ->"
             << " create_local_share -> broadcast_share + notify_local_share);"
             << " ref_hash/pplns are a follow-up slice.";

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
