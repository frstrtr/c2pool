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
#include <core/events.hpp>   // EventDisposable (new_headers subscription handle)

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
          m_chain(config->m_testnet ? BCHChainParams::testnet()
                                    : BCHChainParams::mainnet()),
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
        m_chain.init();               // load genesis / fast-start checkpoint (network-free)
        m_node.run();                 // init_rpc(): external BCHN-RPC fallback retained
        assemble();                   // network-free seam + ABLA wiring (see below)
        wire_chain_ingest();          // new_headers --> HeaderChain (advances synced height)
        pin_cold_start_anchor();      // operator-APPROVED VM300 anchor (decisions@ 2026-06-18); floor-equivalent
        LOG_INFO << "[EMB-BCH] embedded daemon up: embedded-primary work source,"
                 << " external BCHN-RPC fallback retained, ABLA loop closed"
                 << " (cold-start anchor pinned @" << BchnAnchorRecord::height << ").";
    }

    /// NETWORK-FREE assembly of the in-process daemon graph: close the ABLA
    /// size loop (full_block --> feed --> tracker --> EmbeddedCoinNode budget)
    /// and build the CoinNode seam (core::coin::ICoinNode) embedded-primary.
    /// Split out of run() so the embedded cluster can be assembled and verified
    /// against the REAL EmbeddedCoinNode without bringing up the external
    /// BCHN-RPC / P2P front-end (run() = m_node.run() THEN assemble()).
    ///
    /// The seam binds &m_embedded (always-live, primary) + m_node.rpc() (the
    /// external FALLBACK sink). When assemble() runs BEFORE run(), m_node.rpc()
    /// is still null -> the seam is embedded-primary with the fallback absent,
    /// which is the correct offline contract; run() calls assemble() AFTER
    /// init_rpc() so production binds the live RPC fallback. Idempotent: guarded
    /// on m_coin_node so a second call (e.g. assemble()-then-run()) is a no-op.
    /// p2pool-merged-v36 surface: NONE -- pure local wiring, no PoW/share/
    /// coinbase/PPLNS/WorkData-shape change.
    void assemble() {
        if (m_coin_node)
            return;                   // already assembled; idempotent no-op
        m_abla.wire(m_node, m_embedded);
        m_coin_node = std::make_unique<CoinNode>(&m_embedded, m_node.rpc());
    }

    /// Drive the authoritative HeaderChain from the live P2P header stream.
    /// The P2P front-end (NodeP2P) parses `headers` messages and fires
    /// new_headers; until this subscription existed NOTHING advanced m_chain
    /// during a sync (the handler only queued block-body downloads), so the
    /// synced height stayed pinned at the init() checkpoint. Here we feed every
    /// received batch into m_chain.add_headers() -- headers-first IBD: the tip
    /// tracks the peer as batches stream, block bodies backfill via the
    /// block-download window. The peer's advertised tip is propagated first so
    /// add_headers() picks its fast-sync batch size. Idempotent (guarded).
    /// p2pool-merged-v36 surface: NONE -- local SPV header state only (no
    /// PoW/share/coinbase/PPLNS/WorkData-shape change).
    void wire_chain_ingest() {
        if (m_headers_sub)
            return;                   // already wired; idempotent no-op
        m_headers_sub = m_node.new_headers.subscribe(
            [this](const std::vector<BlockHeaderType>& headers) {
                if (auto* p2p = m_node.p2p()) {
                    const uint32_t peer_tip = p2p->peer_start_height();
                    if (peer_tip > 0)
                        m_chain.set_peer_tip_height(peer_tip);
                }
                m_chain.add_headers(headers);
            });
    }

    // Read-only IBD evidence for the --ibd run-loop: synced height vs the peer's
    // advertised tip, plus the block-download window stall counters. All derived
    // from live members; valid once run()/start_p2p() has connected a peer.
    uint32_t ibd_synced_height() { return m_chain.height(); }
    uint32_t ibd_peer_tip() {
        return m_node.has_p2p() ? m_node.p2p()->peer_start_height() : 0;
    }
    std::size_t ibd_reissue_count() {
        return m_node.has_p2p() ? m_node.p2p()->ibd_reissue_count() : 0;
    }
    std::size_t ibd_false_evict_count() {
        return m_node.has_p2p() ? m_node.p2p()->ibd_false_evict_count() : 0;
    }
    std::size_t ibd_in_flight() {
        return m_node.has_p2p() ? m_node.p2p()->ibd_in_flight() : 0;
    }

    /// Apply a BCHN-pinned {height, State} captured from VM300 bchn-bch. This
    /// is the operator-gated reanchor step -- call ONLY after the read is
    /// approved; until then the floor anchor is correct and never-undercut.
    void apply_bchn_anchor(uint32_t height, abla::State state) {
        m_abla.reanchor(height, state);
    }

    /// Pin the operator-APPROVED VM300 BCHN cold-start anchor. decisions@
    /// 2026-06-18 flipped this dry-run -> live (floor-equivalent): the recorded
    /// control state @955700 is still at the 32 MB floor, so pinning changes NO
    /// ABLA budget vs the cold-start floor -- it only fixes the height/chainwork
    /// origin so a future SPV cold-start can trust the recorded header instead
    /// of climbing from genesis. The moment a future capture is ABOVE floor this
    /// path RAISES the budget to the real recorded limit (never undercuts). The
    /// static record is read here; VM300 stays read-only (no qm op). Zero
    /// p2pool-merged-v36 surface (ABLA is BCH embedded-internal).
    void pin_cold_start_anchor() {
        using Rec = BchnAnchorRecord;
        apply_bchn_anchor(Rec::height, Rec::state(m_config->m_testnet));
        const uint64_t pinned = m_abla.tracker().budget_for_tip(Rec::height);
        if (Rec::is_floor())
            LOG_INFO << "[EMB-BCH] cold-start anchor PINNED (operator-approved):"
                     << " height=" << Rec::height << " budget=" << pinned
                     << " (32 MB floor-equivalent; provenance hash=" << Rec::hash << ").";
        else
            LOG_WARNING << "[EMB-BCH] cold-start anchor PINNED above floor:"
                        << " height=" << Rec::height << " budget=" << pinned << ".";
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
    // new_headers -> m_chain.add_headers() subscription (headers-first IBD).
    std::shared_ptr<EventDisposable> m_headers_sub;
    // Built in run() once m_node.rpc() is live; binds raw ptrs to m_embedded
    // (primary) + m_node's NodeRPC (fallback), both outlive it (daemon-owned).
    std::unique_ptr<CoinNode> m_coin_node;
};

} // namespace coin
} // namespace bch
