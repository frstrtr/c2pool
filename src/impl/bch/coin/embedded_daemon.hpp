// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <optional>
#include <limits>       // std::numeric_limits (found-block RPC-fallback sentinel)
#include <string>
#include <vector>

#include "header_chain.hpp"     // HeaderChain
#include "mempool.hpp"          // Mempool
#include "block_connector.hpp" // BlockConnector (full-block UTXO/mempool reorg path)
#include "template_builder.hpp" // EmbeddedCoinNode
#include "node.hpp"             // coin::Node<Config> (interfaces::Node source)
#include "coin_node.hpp"        // CoinNode (core::coin::ICoinNode seam)
#include "block_broadcast_guard.hpp" // guarded_dual_broadcast + BlockBroadcast
#include "abla_runtime.hpp"     // AblaRuntime (owns tracker + feed)
#include "bchn_anchor_record.hpp" // BchnAnchorRecord (cold-start anchor)
#include "seed_tier.hpp"        // SeedTier (Option-A embedded peer discovery ladder)
#include "chain_seeds.hpp"      // bch_dns_seeds / bch_fixed_seeds (tier 1 + 2 data)

#include <core/log.hpp>
#include <core/timer.hpp>    // core::Timer (dedicated emergency re-arm timer)
#include <core/events.hpp>   // EventDisposable (new_headers subscription handle)
#include <core/uint256.hpp> // uint256S (near-tip checkpoint seed)   // EventDisposable (new_headers subscription handle)

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
    EmbeddedDaemon(auto* context, config_t* config, uint32_t anchor_height,
                   bool is_regtest = false)
        : m_context(context),
          m_config(config),
          m_chain(is_regtest ? BCHChainParams::regtest()
                             : (config->m_testnet4 ? BCHChainParams::testnet4()
                                : (config->m_testnet ? BCHChainParams::testnet()
                                                     : BCHChainParams::mainnet()))),
          m_pool(),
          m_embedded(m_chain, m_pool, config->m_testnet),
          m_node(context, config),
          m_abla(config->m_testnet, anchor_height, m_chain),
          m_connector(m_chain, m_pool) { m_regtest = is_regtest; }

    EmbeddedDaemon(const EmbeddedDaemon&) = delete;
    EmbeddedDaemon& operator=(const EmbeddedDaemon&) = delete;

    /// SHUTDOWN (re-arm spec 2.3): the daemon is a stack object owned by the
    /// binary entrypoint, so teardown IS destruction. Clear the running flag and
    /// cancel the emergency re-arm timer so a pending backed-off ladder
    /// re-resolve cannot fire against a half-destroyed daemon. Without this the
    /// m_running guards in arm_emergency_fallbacks() / the timer handler are
    /// dead code -- the flag would never become false.
    ~EmbeddedDaemon() { stop(); }

    /// Idempotent shutdown: stop arming new emergency re-arms and cancel any
    /// pending one. Safe to call more than once and safe to call before run().
    void stop() {
        m_running = false;
        if (m_emergency_timer)
            m_emergency_timer->stop();
    }

    /// Bring the daemon up: start the node front-end (external RPC fallback +
    /// P2P relay) and close the ABLA size loop. After this, full_block events
    /// flow node --> feed --> tracker --> EmbeddedCoinNode dynamic budget, and
    /// EmbeddedCoinNode::getwork() is the live in-process work source.
    void run() {
        m_chain.init();               // load genesis / fast-start checkpoint (network-free)
        m_node.run(/*embedded_primary=*/true); // init_rpc(): eager external GBT non-fatal (embedded-primary); RPC fallback retained
        assemble();                   // network-free seam + ABLA wiring (see below)
        wire_chain_ingest();          // new_headers --> HeaderChain (advances synced height)
        pin_cold_start_anchor();      // operator-APPROVED VM300 anchor (decisions@ 2026-06-18); floor-equivalent
        configure_seed_tier();        // populate the tier-1/2/3 seed ladder BEFORE maybe_start_p2p consults it (no network here -- data only)
        const bool p2p_up = maybe_start_p2p(); // arm won-block P2P relay leg + connector re-request sink (gated on configured peer)
        sync_mempool_from_rpc();      // RPC-fallback: BCHN loose-mempool txs never reach embedded P2P -> fill m_pool so populated templates (nTx>1) are built
        LOG_INFO << "[EMB-BCH] embedded daemon up: embedded-primary work source,"
                 << " external BCHN-RPC fallback retained, ABLA loop closed"
                 << " (cold-start anchor pinned @" << BchnAnchorRecord::height << "),"
                 << " P2P relay leg " << (p2p_up ? "LIVE" : "OFF (no peer configured -> RPC-only)") << ".";
    }

    /// Populate the embedded mempool from the external BCHN GBT (RPC-fallback
    /// path). On regtest -- and any RPC-primary deploy -- loose transactions
    /// live in BCHN's mempool and never reach the embedded P2P relay, so the
    /// template builder selects from an empty m_pool and every won block is
    /// coinbase-only (nTx=1). BCHN GBT already returns the CTOR-ordered,
    /// fee-annotated, consensus-valid tx set -- the SAME set NodeRPC::getwork()
    /// consumes for the external-RPC work path -- so we hand those to m_pool and
    /// build_template selects them unchanged. No-op when no external RPC is bound
    /// (a pure embedded-P2P deploy keeps its own relayed mempool).
    /// KNOWN LIMITATION: one-shot at run()-startup; per-tip/periodic refresh is a
    /// tracked production-standup follow-up (fenced, non-blocking for G3a).
    /// p2pool-merged-v36 surface: NONE -- local mempool population only.
    std::size_t sync_mempool_from_rpc() {
        auto* r = m_node.rpc();
        if (!r) return 0;             // pure embedded-P2P deploy -> no RPC fill
        std::size_t added = 0;
        try {
            auto wd = r->getwork();   // GBT-derived; m_txs unpacked, witness-free
            const auto& jtx = (wd.m_data.is_object() && wd.m_data.contains("transactions")
                               && wd.m_data["transactions"].is_array())
                                  ? wd.m_data["transactions"]
                                  : nlohmann::json::array();
            for (std::size_t i = 0; i < wd.m_txs.size(); ++i) {
                MutableTransaction mtx(wd.m_txs[i]);
                bool ok = false;
                if (i < jtx.size() && jtx[i].is_object()
                        && jtx[i].contains("fee") && jtx[i]["fee"].is_number()) {
                    // Authoritative per-tx fee from BCHN GBT -> fee_known=true so
                    // get_sorted_txs_with_fees() selects it into the template.
                    ok = m_pool.add_tx_with_known_fee(
                             mtx, static_cast<uint64_t>(jtx[i]["fee"].template get<int64_t>()));
                } else {
                    ok = m_pool.add_tx(mtx);  // no fee field -> UTXO/feeless fallback
                }
                if (ok) ++added;
            }
            LOG_INFO << "[EMB-BCH] mempool RPC-sync: +" << added
                     << " txs from BCHN GBT (m_pool size=" << m_pool.size() << ")";
        } catch (const std::exception& e) {
            LOG_WARNING << "[EMB-BCH] mempool RPC-sync skipped (RPC fallback): "
                        << e.what();
        }
        return added;
    }

    /// READ-ONLY IBD evidence harness entry (drives the --ibd run-loop in
    /// main_bch.cpp). Brings up ONLY the network-free chain + the P2P front-end
    /// pointed at a single BCHN peer (VM300 bchn-bch .110:8333), with the
    /// headers-first ingest subscription (wire_chain_ingest) live, so a REAL
    /// sync advances m_chain past its init() checkpoint and the block-download
    /// window accrues the in_flight / reissue / false_evict counters the harness
    /// reports. Deliberately does NOT call init_rpc(): this is a read-only
    /// header/block pull for evidence, NOT the production daemon -- run() still
    /// owns the external BCHN-RPC fallback (external_fallback invariant intact).
    /// A P2P peer connection issues NO qm/control op, so VM300 stays read-only.
    /// p2pool-merged-v36 surface: NONE (local SPV header state only).
    void start_ibd(const NetService& peer) {
        m_chain.init();               // genesis/checkpoint origin (network-free)
        assemble();                   // ABLA loop + CoinNode seam (network-free)
        wire_chain_ingest();          // new_headers --> HeaderChain (height advance)
        pin_cold_start_anchor();      // operator-approved floor-equivalent anchor
        m_node.start_p2p(peer);       // read-only P2P connect to the BCHN peer
        bind_locator_provider();      // ContinueSync uses HeaderChain back-off locator
    }

    /// NEAR-TIP variant of the read-only IBD harness (UID 1375 follow-up). The
    /// plain --ibd cold-start CANNOT exercise AblaBlockFeed advancement: by
    /// construction the ABLA cursor only moves when full blocks arrive
    /// CONTIGUOUSLY from the anchor (height == cursor+1), and the anchor sits at
    /// BchnAnchorRecord::height (955700) -- only ~100+ blocks below the live
    /// VM300 tip. A genesis-origin sync reaches at most a few ten-thousand
    /// headers in a harness window, all far below the anchor, so every
    /// downloaded block is height <= cursor -> idempotently ignored -> the
    /// cursor never moves (exactly the pre-tip state UID 1375 confirmed).
    ///
    /// This variant seeds the header chain's dynamic checkpoint AT the
    /// operator-approved anchor {height,hash} BEFORE connecting, so the locator
    /// anchors at 955700 and the peer streams ONLY the last handful of headers
    /// to its tip. Their block bodies backfill through the download window and
    /// fold into AblaTracker as REAL serialized sizes -- advancing the cursor
    /// 955700 -> tip, the proof that full_block --> AblaBlockFeed --> AblaTracker
    /// is live on live-network data (UID 1369 acceptance (a): real, not
    /// synthetic). Still strictly read-only: a seeded checkpoint + P2P
    /// header/block pull issues NO qm/control op, VM300 stays read-only. NO
    /// init_rpc() -- the external BCHN-RPC fallback path is run()'s, untouched.
    /// The anchor hash is the SAME static record run() pins (no new VM read).
    /// p2pool-merged-v36 surface: NONE (local SPV + ABLA budget only).
    void start_ibd_near_tip(const NetService& peer) {
        m_chain.init();               // genesis/checkpoint origin (network-free)
        // Seed the header origin at the operator-approved BCHN anchor so the
        // sync covers only anchor -> tip (a handful of blocks), letting the ABLA
        // feed actually fold real block sizes within one harness run.
        m_chain.set_dynamic_checkpoint(
            BchnAnchorRecord::height,
            uint256S(std::string(BchnAnchorRecord::hash)));
        assemble();                   // ABLA loop + CoinNode seam (network-free)
        wire_chain_ingest();          // new_headers --> HeaderChain (height advance)
        pin_cold_start_anchor();      // ABLA anchor @ the SAME height as the seed
        m_node.start_p2p(peer);       // read-only P2P connect to the BCHN peer
        bind_locator_provider();      // ContinueSync uses HeaderChain back-off locator
    }

    /// True once the BCHN peer handshake (version/verack) has completed, so the
    /// first locator-anchored getheaders can be issued.
    bool ibd_handshake_ready() {
        return m_node.has_p2p() && m_node.p2p()->is_handshake_complete();
    }

    /// Kick the first headers-first getheaders from our current locator
    /// (genesis/checkpoint). The peer streams its chain forward and the
    /// p2p_node ContinueSync follow-up self-drives the rest of IBD; block
    /// bodies backfill through the bounded download window. Caller issues this
    /// once, after ibd_handshake_ready() turns true.
    void ibd_kick_sync() {
        m_node.send_getheaders(70016, m_chain.get_locator(), uint256::ZERO);
    }

    /// Arm the handshake-gated header-sync self-start on the harness P2P node
    /// (the same enable as the production maybe_start_p2p path). With this set,
    /// the verack handler self-issues the initial getheaders -- the --ibd
    /// harness needs NO ibd_kick_sync() poll. Call after start_ibd*/start_p2p.
    void arm_auto_getheaders() {
        if (auto* p2p = m_node.p2p())
            p2p->enable_auto_getheaders();
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

        // Drive the full-block UTXO/mempool reorg-reconciliation path and wire its
        // deep-reorg re-request sink to the P2P block-download window: a reorg
        // deeper than the connector's remembered-block ring re-getdata's the
        // missing new-branch bodies through the bounded/deduping IBD window
        // instead of stranding the UTXO view at the fork. m_node.p2p() is null
        // until start_p2p(), so the sink no-ops safely when assemble() runs
        // network-free. attach() subscribes the connector to full_block (the
        // m_coin_node guard above makes this run exactly once).
        m_connector.set_block_requester(
            [this](const std::vector<uint256>& hashes) {
                if (auto* p2p = m_node.p2p())
                    p2p->request_block_downloads(hashes);
            });
        m_connector.attach(m_node);
    }

    /// Wire NodeP2P's IBD getheaders continuation to the authoritative
    /// HeaderChain locator (exponential back-off from the tip). Without this the
    /// ContinueSync follow-up falls back to a single-hash locator anchored at
    /// the last learned header, which a peer cannot anchor if that header is on
    /// a minority fork -- IBD then stalls silently. m_chain has already ingested
    /// each batch (wire_chain_ingest) before ContinueSync fires, so get_locator()
    /// reflects the just-learned tip. Call AFTER start_p2p (the p2p object must
    /// exist). p2pool-merged-v36 surface: NONE (local SPV wire-sync only).
    void bind_locator_provider() {
        if (auto* p2p = m_node.p2p())
            p2p->set_locator_provider([this]{ return m_chain.get_locator(); });
    }

    /// Bring up the embedded BCH P2P transport against the configured peer
    /// (coin()->m_p2p.address) when one is set, then bind the HeaderChain
    /// locator provider so any IBD continuation anchors at the learned tip.
    /// Returns true if the transport was started, false when no peer is
    /// configured (port == 0) -- in which case the daemon stays strictly
    /// RPC-only (offline/no-peer contract preserved).
    ///
    /// Closes the won-block P2P-leg gap: broadcast_won_block submit_block_p2p*
    /// calls no-op while m_node.p2p() is null, so EVERY won block degraded to
    /// the RPC-only submitblock leg; likewise the BlockConnector
    /// request_block_downloads re-request sink (wired in assemble) stayed
    /// dormant with no download window to issue getdata on. Both go live the
    /// instant the transport exists. The external BCHN-RPC fallback (init_rpc,
    /// already brought up by run) is untouched -- this only ADDS the P2P leg.
    /// A P2P connect issues no qm/control op, so VM300 bchn-bch stays read-only.
    /// p2pool-merged-v36 surface: NONE (transport wiring only -- no PoW/share/
    /// coinbase/PPLNS/WorkData-shape change).
    bool maybe_start_p2p() {
        const auto& peer = m_config->coin()->m_p2p.address;
        if (peer.port() == 0) {
            // No EXPLICIT peer configured. ADDITIVE Option-A discovery: consult
            // the SeedTier ladder (DNS tier-1 -> fixed tier-2 -> HTTP-peer
            // tier-3) ONLY under should_run_ladder() -- i.e. only when no
            // explicit peer is set AND at least one tier is populated (run()
            // populates them via configure_seed_tier(); an offline caller that
            // never configured seeds keeps has_seeds()==false, so this stays the
            // exact no-op RPC-only path it was before). The explicit-peer arm
            // below ALWAYS bypasses this gate, so the reward-safe configured-peer
            // default is bit-for-bit unchanged.
            if (!SeedTier::should_run_ladder(peer.port(), m_seed_tier.has_seeds()))
                return false;             // no seeds -> RPC-only, exactly as before
            if (!m_context)
                return false;             // no io_context to resolve on -> RPC-only
            m_seed_tier.resolve_candidates(*m_context,
                [this](std::vector<NetService> candidates) {
                    if (candidates.empty()) {
                        LOG_WARNING << "[EMB-BCH] SeedTier ladder resolved 0 "
                                       "candidates -> staying RPC-only.";
                        return;
                    }
                    // resolve_candidates() already ran build_ladder() to order +
                    // dedup the tiers ([dns-or-fixed] then http). Seed the walk
                    // cursor with the ORDERED list, dial the front, then install
                    // the tail-walk provider so peer loss advances to the next
                    // candidate (and re-arms when the ladder is exhausted) instead
                    // of re-dialing the dead front forever.
                    m_walk.rearm(candidates);
                    bool wrapped = false;
                    const NetService dial = m_walk.next(wrapped);
                    start_discovered_p2p(dial);
                    if (auto* p2p = m_node.p2p()) {
                        p2p->set_next_target_provider(
                            [this]() { return next_discovery_target(); });
                        // Recovery signal (spec 2.3): a connected peer resets the
                        // emergency backoff so the next drop escalates from base.
                        p2p->set_peer_connected_callback(
                            [this]() { clear_emergency_state(); });
                    }
                    LOG_INFO << "[EMB-BCH] SeedTier ladder dial -> "
                             << dial.to_string() << " (" << candidates.size()
                             << " candidate(s), tail-walk + emergency re-arm armed)";
                });
            return true;                  // ladder armed (async dial on resolution)
        }
        m_node.start_p2p(peer);           // embedded BCHN P2P relay/IBD transport (EXPLICIT peer -- unchanged)
        bind_locator_provider();          // HeaderChain back-off locator for ContinueSync
        if (auto* p2p = m_node.p2p())     // self-start IBD: kick getheaders at handshake
            p2p->enable_auto_getheaders();
        return true;
    }

    /// PRODUCTION-FIDELITY read-only arming for the --with-peer-verify harness.
    /// Runs run()'s EXACT bring-up sequence MINUS m_node.run() (init_rpc): the
    /// external BCHN-RPC fallback is deliberately NOT brought up so the harness
    /// exercises ONLY the embedded P2P leg #231 wired, and drives the REAL
    /// maybe_start_p2p() through its configured-peer gate -- the method under
    /// test. Returns what maybe_start_p2p() returned (true => the won-block P2P
    /// relay leg + the BlockConnector deep-reorg re-request sink are both LIVE).
    /// After this returns true broadcast_route() reports "p2p": the won-block
    /// dispatcher now takes the embedded P2P relay, not the RPC-only
    /// degradation #231 closed. Strictly read-only vs VM300 (start_p2p connects
    /// + getheaders; no qm/control op, no init_rpc). The caller must have set
    /// the configured peer (config->coin()->m_p2p.address) BEFORE calling, just
    /// as a YAML load would for the production run(). p2pool-merged-v36 surface:
    /// NONE (transport wiring only -- no PoW/share/coinbase/PPLNS change).
    bool arm_p2p_no_rpc() {
        m_chain.init();               // genesis/checkpoint origin (network-free)
        assemble();                   // ABLA loop + CoinNode seam + connector sink
        wire_chain_ingest();          // new_headers --> HeaderChain (height advance)
        pin_cold_start_anchor();      // operator-approved floor-equivalent anchor
        return maybe_start_p2p();     // the #231 method under test (configured-peer gate)
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

    /// Live ABLA size-feed evidence for the --ibd harness: the dynamic block-size
    /// budget the feed has folded from the REAL blocks streamed off the peer
    /// (VM300 bchn-bch), anchored at the cursor the feed has advanced to. The
    /// budget sits at the 32 MB safe floor until the feed has folded blocks
    /// CONTIGUOUSLY from the cursor; the cursor trails ibd_synced_height by design
    /// (headers-first: headers race ahead, block bodies backfill through the
    /// download window, and ONLY a folded full block advances this cursor). A
    /// moving cursor here is the proof that full_block --> AblaBlockFeed -->
    /// AblaTracker is live on real network data, not merely the cold-start anchor.
    /// Read-only; no p2pool-merged-v36 surface (local ABLA budget only).
    uint64_t ibd_abla_budget() {
        return m_abla.tracker().budget_for_tip(m_abla.tracker().cursor_height());
    }
    uint32_t ibd_abla_cursor() { return m_abla.tracker().cursor_height(); }

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
        if (m_regtest) {
            // Regtest has no mainnet/testnet BCHN anchor; the @955700 record is
            // meaningless here. ABLA stays at its floor anchor; the chain syncs
            // from the regtest genesis. Skipping the pin keeps regtest correct.
            LOG_INFO << "[EMB-BCH] cold-start anchor SKIPPED (regtest: floor ABLA, genesis-rooted chain).";
            return;
        }
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
    BlockConnector&     connector()      { return m_connector; }
    HeaderChain&        chain()          { return m_chain; }
    Mempool&            mempool()        { return m_pool; }
    bool                is_wired() const { return m_abla.is_wired(); }

    /// Found-block confirmation depth via the external BCHN-RPC fallback
    /// (getblockheader "confirmations"). Returns INT_MIN when no external RPC is
    /// live (embedded-only arm) so the caller falls through to the header-chain
    /// verdict. TELEMETRY ONLY -- the dashboard found-block verifier's fallback
    /// arm (#995 BCH arm); never a consensus or broadcast gate. Read-only vs
    /// VM300 (a getblockheader query issues no qm/control op).
    int rpc_block_confirmations(const uint256& block_hash)
    {
        NodeRPC* r = m_node.rpc();
        if (!r) return std::numeric_limits<int>::min();
        try {
            nlohmann::json j = r->getblockheader(block_hash, /*verbose=*/true);
            if (j.contains("confirmations") && j["confirmations"].is_number())
                return j["confirmations"].get<int>();
        } catch (...) { /* unreachable / unknown -> pending */ }
        return std::numeric_limits<int>::min();
    }

    // BlockBroadcast result type + the guarded dual-path dispatch live in
    // block_broadcast_guard.hpp (shared single source of guard truth; the
    // throw-injection KATs exercise the same helper).

    /// Fire a won block down BOTH broadcast paths. `block_bytes` is the
    /// pre-serialized (header || tx_count || coinbase || tx_data) blob the
    /// embedded P2P broadcaster relays; `block_hex` is the same block hex for
    /// the external submitblock fallback. BCH is SHA256d standalone parent --
    /// no merged-coinbase leg. Read-only vs VM300 (a block relay/submit issues
    /// no qm/control op). Zero p2pool-merged-v36 surface (block dispatch, not
    /// share/PPLNS/coinbase bytes). This is the sink the pool node wires its
    /// tracker().m_on_block_found to so an in-operation win emits immediately.
    BlockBroadcast broadcast_won_block(const std::vector<unsigned char>& block_bytes,
                                       const std::string& block_hex)
    {
        // Each leg is independently guarded via guarded_dual_broadcast so a
        // throwing embedded-P2P relay can never propagate out and skip the
        // always-fire submitblock fallback (silent won-block drop + runtime
        // removal of the external-daemon fallback). A throwing RPC submit =
        // no-ack that never masks a P2P win. Same contract as NMC #468.
        BlockBroadcast r = guarded_dual_broadcast(
            m_node.has_p2p(),
            [&] {
                m_node.submit_block_p2p_raw(block_bytes);
                LOG_INFO << "[EMB-BCH] won-block P2P relay issued (" << block_bytes.size()
                         << " bytes) -- primary path.";
            },
            (m_coin_node && m_coin_node->has_rpc()),
            [&] {
                bool ok = m_coin_node->submit_block_hex(block_hex, /*ignore_failure=*/true);
                if (ok) {
                    LOG_INFO << "[EMB-BCH] won-block submitblock RPC fallback ok/duplicate.";
                } else {
                    // A wired fallback channel that does not acknowledge a WON
                    // BLOCK is a potential lost subsidy, not routine noise. It
                    // is an error even though the P2P primary may have carried
                    // the block -- the whole point of the dual path is that we
                    // never have to assume that.
                    LOG_ERROR << "[EMB-BCH] won-block submitblock RPC fallback NO-ACK -- the "
                                 "external daemon did not confirm the block down this path.";
                }
                return ok;
            });

        if (m_node.has_p2p() && !r.p2p_sent)
            LOG_WARNING << "[EMB-BCH] won-block: P2P leg present but did not send (threw) -- "
                           "relied on RPC fallback.";
        else if (!m_node.has_p2p())
            LOG_WARNING << "[EMB-BCH] won-block: no embedded P2P sink; relying on RPC fallback.";
        if (!(m_coin_node && m_coin_node->has_rpc()))
            LOG_WARNING << "[EMB-BCH] won-block: no external BCHN-RPC fallback sink wired.";

        if (!r.any())
            LOG_ERROR << "[EMB-BCH] won-block had NEITHER broadcast sink (or both threw) -- block NOT relayed!";
        else
            LOG_INFO << "[EMB-BCH] won-block broadcast: p2p=" << (r.p2p_sent ? "sent" : "off")
                     << " rpc=" << (r.rpc_ok ? "ok" : "off")
                     << " landed_first=" << r.landed_first << ".";
        return r;
    }

    /// Read-only routing decision mirroring broadcast_won_block's sink-selection
    /// guards WITHOUT transmitting: reports which leg a won block WOULD take
    /// given the currently-armed sinks -- "p2p" once the embedded P2P transport
    /// is live (maybe_start_p2p armed it), "rpc" if only the external BCHN-RPC
    /// fallback is up, "none" offline. Lets the --with-peer-verify harness
    /// assert the P2P leg is SELECTED post-arm WITHOUT relaying a block onto the
    /// live network, so VM300 stays strictly read-only. Selection order matches
    /// broadcast_won_block exactly: embedded P2P is PRIMARY (checked first), the
    /// external BCHN-RPC submitblock is the FALLBACK.
    const char* broadcast_route() {
        if (m_node.has_p2p()) return "p2p";
        if (m_coin_node && m_coin_node->has_rpc()) return "rpc";
        return "none";
    }

    /// D-BCH dashboard feed: per-coin embedded-daemon topology surfaced at
    /// core::WebServer /api/node_topology (MiningInterface::set_node_topology_fn).
    /// Display-only -- reads live daemon state, mutates no serving/consensus
    /// path. Each datum is named TRUTHFULLY: BCH embedded transport is
    /// SINGLE-PEER (one explicit BCHN peer or the RPC fallback, no
    /// coin_peer_mgr), so `embedded_peers` is 0-or-1 alongside `broadcast_route`,
    /// NOT a multi-peer getpeerinfo table (acceptance #2: name the datum the
    /// lane cannot supply rather than render a placeholder). p2pool-merged-v36
    /// surface: NONE (dashboard reporting, not share/PPLNS/coinbase bytes).
    nlohmann::json dashboard_topology() {
        const bool     emb_p2p  = m_node.has_p2p();
        const bool     ext_rpc  = (m_coin_node && m_coin_node->has_rpc());
        const uint32_t synced   = ibd_synced_height();
        const uint32_t peer_tip = m_chain.peer_tip_height();
        return nlohmann::json{
            {"coin", "BCH"},
            {"embedded", true},
            {"has_rpc", ext_rpc},
            {"synced_height", synced},
            {"peer_tip_height", peer_tip},
            {"sync_pct", (peer_tip > 0 ? 100.0 * synced / peer_tip : 0.0)},
            {"embedded_peers", emb_p2p ? 1 : 0},   // single-peer embedded transport
            {"broadcast_route", broadcast_route()},
        };
    }

    /// Embedded coin header-sync snapshot for the core::WebServer
    /// /broadcaster_status merge (MiningInterface::set_coin_sync_status_fn).
    /// Display-only, same read set as dashboard_topology(): header_height =
    /// the embedded BCH HeaderChain tip (never the sharechain height),
    /// target_height = the peer-advertised tip raised by the single embedded
    /// peer's startingheight, peers = that peer's version metadata (BCH's
    /// embedded transport is single-peer -- 0-or-1 rows, never a fabricated
    /// getpeerinfo table).
    nlohmann::json sync_status() {
        const uint32_t hh = ibd_synced_height();
        uint32_t th = m_chain.peer_tip_height();
        nlohmann::json peers = nlohmann::json::array();
        auto* p2p = m_node.p2p();
        if (p2p != nullptr && p2p->peer_version() > 0) {
            const uint32_t sh = p2p->peer_start_height();
            if (sh > th) th = sh;
            peers.push_back({
                {"subver", p2p->peer_subver()},
                {"startingheight", sh},
                {"conntime", p2p->peer_uptime_sec()},
                {"connected", true},
            });
        }
        nlohmann::json s = nlohmann::json::object();
        s["header_height"] = hh;
        s["target_height"] = th;
        s["peers"] = std::move(peers);
        return s;
    }

private:
    /// Populate the three converged seed tiers (idempotent). Mirrors the DGB
    /// tier-3 wire (main_dgb.cpp): DNS (tier 1) + fixed (tier 2) from
    /// chain_seeds.hpp, then the c2pool HTTP seed aggregator as the last-resort
    /// tier 3. No network here -- pure data population; the ladder is only
    /// walked (and only when no explicit peer is set) inside maybe_start_p2p().
    void configure_seed_tier() {
        if (m_seed_tier.has_seeds())
            return;                        // populate once (idempotent)
        const bool testnet = m_config->m_testnet;
        m_seed_tier.set_dns_seeds(bch_dns_seeds(testnet));     // tier 1: DNS
        m_seed_tier.set_fixed_seeds(bch_fixed_seeds(testnet)); // tier 2: fixed
        // Tier 3 (last-resort) bootstrap: the c2pool HTTP seed aggregator.
        // Fires only when the DNS + fixed tiers both resolve nothing, so a BCH
        // lane that loses its DNS and fixed seeds still has a recovery path.
        // Coin selection is by the "bch" JSON key inside http_fetch_coin_peers,
        // not the host, so the shared aggregator serves BCH peers without a
        // BCH-specific endpoint. Shaped after the DGB tier-3 wire. No-op if the
        // list is empty.
        m_seed_tier.set_http_peer_seeds({{"voidbind.com", 8080}});
    }

    /// Dial a discovery-resolved candidate through the SAME transport arm the
    /// explicit-peer path uses (start_p2p + locator provider + auto-getheaders),
    /// so a ladder-discovered peer and an explicitly-configured one bring the
    /// won-block P2P relay leg + IBD self-start up identically.
    void start_discovered_p2p(const NetService& dial) {
        m_node.start_p2p(dial);
        bind_locator_provider();
        if (auto* p2p = m_node.p2p())
            p2p->enable_auto_getheaders();
    }

    /// Discovery tail-walk provider body: hand the transport the NEXT resolved
    /// candidate on peer loss. On the tick that wraps past the last candidate the
    /// ladder is exhausted -> kick an async re-resolve (re-entry-guarded) to
    /// rebuild it; the wrapped candidate is returned meanwhile so the transport
    /// keeps trying. Returns nullopt only when the walk is empty (nothing to
    /// rotate to -> transport keeps its current target).
    std::optional<NetService> next_discovery_target() {
        if (m_walk.empty())
            return std::nullopt;
        bool wrapped = false;
        NetService nxt = m_walk.next(wrapped);
        // A wrap past the last candidate == starvation observed on this reconnect
        // tick (the whole resolved ladder was walked with no live peer). Feed it
        // to the emergency re-arm state machine; the latch there collapses many
        // wraps into ONE backed-off re-resolve. The wrapped candidate is still
        // returned so the transport keeps trying while the re-resolve is pending.
        if (wrapped)
            arm_emergency_fallbacks();
        return nxt;
    }

    /// Emergency re-arm entry point (spec section 2.4), BCH single-peer locus: the
    /// re-arm CYCLE is the ladder RE-RESOLVE (resolve_candidates rebuilds DNS +
    /// fixed + HTTP tiers in one call -- BCH has no separate per-tier timers).
    /// Idempotent under the latch (2.2): a starved tick while a re-arm is pending
    /// is a no-op, so N starved reconnect ticks schedule EXACTLY ONE re-resolve.
    /// Backoff (2.1): the dedicated one-shot timer fires after delay(n) =
    /// min(60<<n, 3600)s, the saturating exponential; n increments per arm.
    void arm_emergency_fallbacks() {
        if (!m_context || !m_running)
            return;
        auto delay = m_emergency.on_starved_tick();   // 2.2 re-entry guard
        if (!delay)
            return;                                    // latched -> no timer storm
        if (!m_emergency_timer)
            m_emergency_timer = std::make_unique<core::Timer>(m_context, /*repeat=*/false);
        LOG_INFO << "[EMB-BCH] emergency ladder re-resolve armed in " << *delay
                 << "s (attempt " << m_emergency.attempt << ")";
        m_emergency_timer->start(static_cast<time_t>(*delay), [this]() {
            m_emergency.on_timer_fire();               // 2.2 release latch at TOP
            if (!m_running)                            // 2.3 SHUTDOWN early-return
                return;
            // Re-arm cycle: rebuild the ladder (DNS re-resolve + fixed + HTTP
            // tier). Tier throws are caught inside resolve_candidates' detached
            // HTTP thread, so a bad tier cannot kill the io_context or the cycle.
            m_seed_tier.resolve_candidates(*m_context,
                [this](std::vector<NetService> fresh) {
                    if (!fresh.empty())
                        m_walk.rearm(std::move(fresh));
                });
        });
    }

    /// Recovery reset (spec section 2.3): a connected peer clears the backoff so
    /// the NEXT drop starts a fresh escalation from base, not the ceiling. Cancels
    /// any pending re-arm. Wired to NodeP2P's peer-connected callback on the
    /// discovered path (the explicit-peer / RPC-only default never installs it).
    void clear_emergency_state() {
        bool was_armed = m_emergency.active || m_emergency.attempt != 0;
        m_emergency.clear();
        if (m_emergency_timer)
            m_emergency_timer->stop();
        if (was_armed)
            LOG_INFO << "[EMB-BCH] peer recovered -> emergency re-arm state reset";
    }

    boost::asio::io_context* m_context; // not owned (binary entrypoint owns it); SeedTier async resolve target
    bool             m_regtest = false; // regtest 3rd-net: skip mainnet/testnet anchor + drive RPC mempool sync
    config_t*        m_config;   // not owned (binary entrypoint owns it)
    HeaderChain      m_chain;    // before m_embedded + m_abla: their refs bind here
    Mempool          m_pool;     // before m_embedded
    EmbeddedCoinNode m_embedded; // in-process work source
    Node<config_t>   m_node;     // P2P + external-RPC fallback; full_block source
    AblaRuntime      m_abla;     // owns tracker + feed; wired in run()
    // full_block -> header connect -> best-chain-gated UTXO/mempool reconcile;
    // attached in assemble(). Declared after m_node so its full_block
    // subscription tears down (dtor detach) before the event source m_node dies.
    BlockConnector   m_connector;
    // new_headers -> m_chain.add_headers() subscription (headers-first IBD).
    std::shared_ptr<EventDisposable> m_headers_sub;
    // Built in run() once m_node.rpc() is live; binds raw ptrs to m_embedded
    // (primary) + m_node's NodeRPC (fallback), both outlive it (daemon-owned).
    std::unique_ptr<CoinNode> m_coin_node;
    // Option-A embedded peer-discovery ladder (DNS -> fixed -> HTTP tier-3).
    // Populated by configure_seed_tier() in run(); consulted by maybe_start_p2p()
    // ONLY when no explicit peer is configured (should_run_ladder gate).
    SeedTier         m_seed_tier;
    // Ordered discovery candidate cursor (SSOT for the peer-loss tail walk).
    // Drives the Option-A discovered path only; the explicit-peer / RPC-only
    // default never touches it.
    SeedTier::CandidateWalk m_walk;
    // Emergency re-arm state machine (backoff counter + re-entry latch) per the
    // fleet-canonical never-re-arm spec (the/docs/coin-peer-manager-rearm.md
    // sections 2.1-2.4), BCH single-peer locus = the ladder re-resolve. Pure /
    // network-free (KAT-pinned). The dedicated one-shot timer owns the backed-off
    // re-resolve, independent of the reconnect tick; cancelled on recovery and
    // torn down on destruction (the core::Timer dtor cancels a pending wait).
    SeedTier::EmergencyReArm     m_emergency;
    std::unique_ptr<core::Timer> m_emergency_timer;
    bool             m_running = true;   // cleared by stop()/~EmbeddedDaemon: timer handlers early-return
};

} // namespace coin
} // namespace bch