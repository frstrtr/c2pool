#pragma once
// ---------------------------------------------------------------------------
// bch::coin::EmbeddedDaemon<Config> -- M5: the embedded-daemon ENTRYPOINT
// assembly. After AblaRuntime (9f5050f2) closed the size loop, four front-ends
// existed but nothing OWNED them as one running daemon instance:
//   HeaderChain        -- SPV header store + tip (M3); height source
//   Mempool            -- tx acceptance pool (M4); template input
//   EmbeddedCoinNode   -- in-process getwork() work source (template builder)
//   coin::Node<Config> -- P2P + external-RPC front-end; the full_block source
//                         (derives bch::interfaces::Node) AND the retained
//                         external BCHN-RPC fallback path (init_rpc / m_rpc)
//   AblaRuntime        -- owns AblaTracker + AblaBlockFeed; wires full_block
//                         --> feed --> tracker --> EmbeddedCoinNode budget
//
// This object is that owner: one daemon = one EmbeddedDaemon. It constructs the
// members in the lifetime order the wiring demands, runs the node, and closes
// the ABLA loop via AblaRuntime::wire(). It is the site coin::Node<Config>
// instantiates concretely (config binds here, per node.hpp's deferral note).
//
// EMBEDDED-PRIMARY, EXTERNAL-FALLBACK (v36-master-plan, REQUIRED for every coin)
//   The embedded work source (EmbeddedCoinNode::getwork) is the DEFAULT. The
//   external BCHN-RPC path stays alongside it -- coin::Node::init_rpc() is NOT
//   removed; m_node keeps its NodeRPC. The CoinNode seam (node_iface.hpp) is
//   built embedded-primary with the RPC as the live fallback. Removing the
//   external path would violate the per-coin external_fallback invariant.
//
// COLD START = FLOOR ANCHOR (VM300 pin is the NEXT, operator-gated step).
//   Absent a BCHN-pinned {height,State} captured from VM300 bchn-bch, the ABLA
//   runtime anchors at the activation/floor State -- folding live block sizes
//   forward can only RAISE the budget, never undercut the 32 MB floor. The
//   BCHN pin is a later reanchor() passthrough (AblaRuntime::reanchor), NOT a
//   reconstruction; capturing it touches VM300 read-only and is surfaced to the
//   operator as a [decision-needed] before any read. This assembly is complete
//   and correct WITHOUT the pin; the pin only sharpens the cold-start budget.
//
// LIFETIME (members declared in this exact order so refs bind to live objects):
//   m_chain  before m_embedded (EmbeddedCoinNode HeaderChain&) and m_abla
//            (AblaBlockFeed HeaderChain&) -- both bind to a constructed chain.
//   m_pool   before m_embedded (EmbeddedCoinNode Mempool&).
//   m_embedded, m_node before wire() hands their addresses to m_abla; m_abla's
//            AblaTracker outlives the EmbeddedCoinNode raw pointer it sinks into
//            (the daemon owns all of them for its whole run).
//
// p2pool-merged-v36 SURFACE: NONE. Pure local daemon assembly -- no PoW hash,
// share format, coinbase commitment, AuxPoW, or PPLNS math is touched; getwork
// emits the same coin-agnostic WorkData the sweep already pinned conformant.
// PER-COIN ISOLATION: src/impl/bch/coin/ only; every type is bch-owned.
// Build-INERT / source-only: header-only, no impl_bch CMake registration
// (bch stays skip-green; don't race ci-steward).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <memory>

#include "header_chain.hpp"     // HeaderChain
#include "mempool.hpp"          // Mempool
#include "template_builder.hpp" // EmbeddedCoinNode
#include "node.hpp"             // coin::Node<Config> (interfaces::Node source)
#include "coin_node.hpp"        // CoinNode (core::coin::ICoinNode seam)
#include "abla_runtime.hpp"     // AblaRuntime (owns tracker + feed)
#include "bchn_anchor_record.hpp" // BchnAnchorRecord (cold-start anchor)

#include <core/log.hpp>

namespace bch {
namespace coin {

/// Owns and wires one embedded BCH daemon instance. Single-threaded
/// construction from the binary entrypoint; run() then drives the node.
template <typename ConfigType>
class EmbeddedDaemon {
public:
    using config_t = ConfigType;

    /// Cold-start ctor: floor-anchored ABLA at `anchor_height` (safe default
    /// when no VM300 BCHN pin is available yet). `context`/`config` outlive the
    /// daemon (owned by the binary entrypoint, same contract as coin::Node).
    EmbeddedDaemon(auto* context, config_t* config, uint32_t anchor_height)
        : m_config(config),
          m_chain(),
          m_pool(),
          m_embedded(m_chain, m_pool, config->m_testnet),
          m_node(context, config),
          m_abla(config->m_testnet, anchor_height, m_chain) {}

    EmbeddedDaemon(const EmbeddedDaemon&) = delete;
    EmbeddedDaemon& operator=(const EmbeddedDaemon&) = delete;

    /// Bring the daemon up: start the node front-end (external RPC fallback +
    /// P2P relay) and close the ABLA size loop. After this, full_block events
    /// flow node --> feed --> tracker --> EmbeddedCoinNode dynamic budget, and
    /// EmbeddedCoinNode::getwork() is the live in-process work source.
    void run() {
        m_node.run();                 // init_rpc(): external BCHN-RPC fallback retained
        m_abla.wire(m_node, m_embedded);
        // Build the CoinNode seam NOW (not in the ctor): m_node.rpc() is only
        // live after run()/init_rpc(). Embedded work source = primary, the
        // external BCHN-RPC = retained fallback (v36 external_fallback law).
        m_coin_node = std::make_unique<CoinNode>(&m_embedded, m_node.rpc());
        LOG_INFO << "[EMB-BCH] embedded daemon up: embedded-primary work source,"
                 << " external BCHN-RPC fallback retained, ABLA loop closed"
                 << " (cold-start floor anchor; VM300 pin pending operator).";
    }

    /// Apply a BCHN-pinned {height, State} captured from VM300 bchn-bch. This
    /// is the operator-gated reanchor step -- call ONLY after the read is
    /// approved; until then the floor anchor is correct and never-undercut.
    void apply_bchn_anchor(uint32_t height, abla::State state) {
        m_abla.reanchor(height, state);
    }

    /// DRY RUN of the cold-start reanchor: read the STATIC VM300 anchor record
    /// (BchnAnchorRecord -- captured once, read-only; the live VM is never
    /// touched here) and LOG exactly what apply_bchn_anchor() WOULD pin, with
    /// no mutation of the running ABLA state. This is the cold-start path
    /// wiring: origin is the recorded {height,hash,chainwork,time} anchor, NOT
    /// genesis; the AblaRuntime replay stays pinned to the 32 MB safe floor
    /// whenever the recorded control state is still at floor (the 955700
    /// capture is). The real reanchor stays operator-gated -- this only proves
    /// the wiring and surfaces a non-floor budget the moment a capture shows one.
    void dry_run_bchn_anchor() const {
        using Rec = BchnAnchorRecord;
        const abla::State rec_state = Rec::state(m_config->m_testnet);
        const uint64_t rec_limit = rec_state.GetBlockSizeLimit();
        LOG_INFO << "[EMB-BCH] cold-start anchor DRY RUN (record-only, VM300 untouched):"
                 << " height=" << Rec::height
                 << " hash=" << Rec::hash
                 << " chainwork=" << Rec::chainwork
                 << " time=" << Rec::time
                 << " -> ABLA limit=" << rec_limit
                 << " (control=" << rec_state.GetControlBlockSize()
                 << " elastic=" << rec_state.GetElasticBufferSize() << ").";
        if (Rec::is_floor()) {
            LOG_INFO << "[EMB-BCH] recorded ABLA control state == 32 MB floor;"
                     << " pinning is a no-op vs cold-start floor (provenance only)."
                     << " apply_bchn_anchor() remains operator-gated.";
        } else {
            LOG_WARNING << "[EMB-BCH] recorded ABLA control state is ABOVE floor"
                        << " (limit=" << rec_limit << "); apply_bchn_anchor("
                        << Rec::height << ", state) would RAISE the cold-start"
                        << " budget. Operator gate required before pinning.";
        }
    }

    // Accessors for the CoinNode seam cluster (embedded-primary + RPC fallback)
    // and for tests; the daemon retains ownership.
    EmbeddedCoinNode&   embedded()       { return m_embedded; }
    Node<config_t>&     node()           { return m_node; }
    /// The CoinNode seam handed to the pool/web_server (core::coin::ICoinNode).
    /// Valid only after run() has built it. Embedded-primary + external-RPC
    /// fallback; the daemon owns it for its whole run.
    CoinNode&           coin_node()      { return *m_coin_node; }
    bool                seam_ready() const { return m_coin_node != nullptr; }
    AblaRuntime&        abla()           { return m_abla; }
    HeaderChain&        chain()          { return m_chain; }
    Mempool&            mempool()        { return m_pool; }
    bool                is_wired() const { return m_abla.is_wired(); }

private:
    config_t*        m_config;   // not owned (binary entrypoint owns it)
    HeaderChain      m_chain;    // before m_embedded + m_abla: their refs bind here
    Mempool          m_pool;     // before m_embedded
    EmbeddedCoinNode m_embedded; // in-process work source
    Node<config_t>   m_node;     // P2P + external-RPC fallback; full_block source
    AblaRuntime      m_abla;     // owns tracker + feed; wired in run()
    // Built in run() once m_node.rpc() is live; binds raw ptrs to m_embedded
    // (primary) + m_node's NodeRPC (fallback), both outlive it (daemon-owned).
    std::unique_ptr<CoinNode> m_coin_node;
};

} // namespace coin
} // namespace bch
