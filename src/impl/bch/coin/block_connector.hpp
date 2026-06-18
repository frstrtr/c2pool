#pragma once
// ---------------------------------------------------------------------------
// bch::coin::BlockConnector -- M5 full-block body, slice 1: BLOCK-CONNECT.
//
// AblaBlockFeed (slice prior) wired full_block --> ABLA size budget, but the
// block-connect path itself was never closed: Mempool::remove_for_block() was
// DEFINED yet had ZERO call sites, and nothing tied a received best-chain block
// to the header index or to a mempool reconciliation. This object is that tie.
//
// It subscribes to interfaces::Node::full_block (the single sink all three P2P
// delivery paths -- direct `block`, `cmpctblock`, `blocktxn` -- already funnel
// into, p2p_node.hpp:emit_full_block) and, for each block, performs the
// block-connect sequence the integrator scoped (block-connect -> mempool
// reconciliation -> BIP130 ordering):
//
//   1. BLOCK-CONNECT. Hand the block's 80-byte header to HeaderChain::add_header
//      (idempotent: returns false for an already-known header). Under BIP130
//      headers-first the header is normally already synced, so this is a no-op
//      on the common path; on direct-block delivery (e.g. a block we mined, or
//      a peer sending `block` with no prior header) it indexes the connect.
//
//   2. BIP130 BEST-CHAIN GATE. Only a block that IS the current best tip
//      reconciles the mempool. A side / stale / not-yet-connected block (its
//      header didn't become the tip) leaves the mempool untouched -- its txs
//      are NOT confirmed on our best chain, so removing them would be wrong.
//      The gate is "this block's hash == best-chain tip hash", read back from
//      the header index after the connect, never guessed.
//
//   3. MEMPOOL RECONCILIATION to the new tip:
//        a. set_tip_height(tip.height)   -- coinbase-maturity / staleness base.
//        b. remove_for_block(block)      -- Phase 1 confirmed-by-txid, Phase 2
//                                           same-outpoint conflicts, Phase 3
//                                           orphaned children (all txid/spent-
//                                           outpoint based; no UTXO needed).
//        c. revalidate_inputs(utxo)      -- Phase 4 stale-input sweep; a no-op
//                                           when no UTXO view is wired (cold
//                                           start / headers-only), which is the
//                                           correct contract until the full
//                                           UTXO connect layer lands.
//
// THREADING: single-threaded use from the daemon's block-processing context,
// same contract as AblaBlockFeed and the header chain's advance path.
//
// p2pool-merged-v36 SURFACE: NONE. Pure local block-connect + mempool hygiene;
// no PoW hash, share format, coinbase commitment, AuxPoW, or PPLNS math is
// touched. PER-COIN ISOLATION: src/impl/bch/coin/ only; every type is bch-owned.
// Build-INERT / source-only header (bch stays skip-green; don't race ci-steward).
// ---------------------------------------------------------------------------

#include "block.hpp"
#include "header_chain.hpp"     // bch::coin::block_hash(), HeaderChain
#include "mempool.hpp"          // Mempool, core::coin::UTXOViewCache
#include "node_interface.hpp"   // bch::interfaces::Node (full_block event)

#include <core/events.hpp>      // EventDisposable
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <memory>

namespace bch {
namespace coin {

/// Closes the block-connect path: full_block --> header index connect -->
/// best-chain-gated mempool reconciliation. Daemon-owned; the chain and pool
/// it references must outlive it.
class BlockConnector {
public:
    /// @param chain  best-chain header index (connect target + tip authority).
    /// @param pool   mempool to reconcile against each connected best-chain block.
    BlockConnector(HeaderChain& chain, Mempool& pool)
        : m_chain(chain), m_pool(pool) {}

    BlockConnector(const BlockConnector&) = delete;
    BlockConnector& operator=(const BlockConnector&) = delete;

    /// Optional UTXO view for the Phase-4 stale-input sweep. Until a UTXO
    /// connect layer is wired this stays null and revalidate_inputs() is a
    /// no-op -- Phases 1-3 (txid + spent-outpoint based) still run fully.
    void set_utxo(core::coin::UTXOViewCache* u) { m_utxo = u; }

    /// Wire to a node's full_block event. Retained internally, torn down on
    /// destruction (or detach()). Call once, after node + chain + pool exist.
    void attach(bch::interfaces::Node& node) {
        m_sub = node.full_block.subscribe(
            [this](const BlockType& block) { on_full_block(block); });
    }

    /// Drop the subscription early (idempotent). Destruction does this anyway.
    void detach() {
        if (m_sub) {
            m_sub->dispose();
            m_sub.reset();
        }
    }

    /// Connect one received full block. Public so the out-of-tree harness can
    /// drive it without a live Event/socket; in production it is invoked only
    /// by the full_block subscription.
    void on_full_block(const BlockType& block) {
        const uint256 hash =
            block_hash(static_cast<const BlockHeaderType&>(block));

        // 1. Block-connect: index the header if new (idempotent on the common
        //    headers-first path where it is already synced).
        m_chain.add_header(static_cast<const BlockHeaderType&>(block));

        // 2. BIP130 best-chain gate: reconcile ONLY when this block is the tip.
        const auto tip = m_chain.tip();
        if (!tip || tip->block_hash != hash) {
            LOG_DEBUG_COIND << "[EMB-BCH] block-connect: " << hash.GetHex().substr(0, 16)
                            << "... not best tip -- mempool NOT reconciled (side/stale/unconnected)";
            return;
        }

        // 3. Mempool reconciliation to the new tip.
        m_pool.set_tip_height(tip->height);
        m_pool.remove_for_block(block);          // Phase 1 + 2 + 3
        const int evicted = m_pool.revalidate_inputs(m_utxo);  // Phase 4 (no-op if null)

        LOG_DEBUG_COIND << "[EMB-BCH] block-connect: tip=" << hash.GetHex().substr(0, 16)
                        << "... height=" << tip->height
                        << " mempool reconciled (size=" << m_pool.size()
                        << " phase4_evicted=" << evicted << ")";
    }

    bool is_attached() const { return static_cast<bool>(m_sub); }

    ~BlockConnector() { detach(); }

private:
    HeaderChain&                 m_chain;
    Mempool&                     m_pool;
    core::coin::UTXOViewCache*   m_utxo {nullptr};   // optional Phase-4 view
    std::shared_ptr<EventDisposable> m_sub;
};

} // namespace coin
} // namespace bch
