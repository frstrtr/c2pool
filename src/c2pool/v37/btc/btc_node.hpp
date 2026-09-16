// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/btc_node.hpp   (Track A2 / Milestone A-BTC — the lifecycle)
//
// XbtcNode — the live v37 node lifecycle for the BITCOIN FAMILY. It wires the
// coin-agnostic, MERGED v37 engine (V37Engine, W4 OwedLedger, W5 native
// coinbase) to the MATURE v36 coin plumbing (the coin adapter behind
// ICoinBackend, and the v36 core::StratumServer / IWorkSource front-end).
//
// SIBLING of src/c2pool/v37/xmr/ (Milestone A-XMR): identical engine + F1 driver
// + W6 shape; the coin backend differs (v36 Bitcoin/DASH adapter instead of
// monerod, and the W5 NATIVE coinbase instead of the CARROT-fenced XMR one).
//
// ── THE CONSTRUCTION ORDER (donor lifecycle; open() then start()) ───────────
//   1. open() — DURABLE side, BEFORE the engine spins:
//        a. build the ISettleStore (File/LevelDB in prod, Mem in the smoke);
//        b. RecoveryDriver::recover() rebuilds the OwedLedger + SettleHW +
//           finalize cursor from the store — F2 fail-closed: a torn store
//           returns false and the daemon REFUSES to start;
//        c. construct the BtcFinalizeDriver seeded with the recovered cursor +
//           event seq, its CanonicalFn bound to the coin backend's is_canonical.
//   2. start() — LIVE side:
//        d. V37Engine::start() (spawns the single executor thread);
//        e. AddLane(lane_chain, lane_params) — the one BTC-family lane, seeded
//           through the engine so its digest is the executor's, not ours;
//        f. hand the v36 work source to a core::StratumServer bound to
//           stratum_bind — miners connect; IWorkSource::mining_submit classifies
//           PoW; a block-winning share fires on_block_won();
//        g. run the height-watch: poll ICoinBackend::best_tip() and feed each
//           advance to BtcFinalizeDriver::advance_to_tip() (the F1 contract).
//   3. stop() — teardown in donor order: stop the stratum/network first, then
//      V37Engine::stop() drains-and-joins (no callback can submit post-stop).
//
// ── HARD SAFETY MAPPING ─────────────────────────────────────────────────────
//   (1) no consensus-DIGEST change — every digest comes from the merged
//       V37Engine/OwedLedger/W5; XbtcNode only SEQUENCES calls. See the
//       drift-guard KAT (btc_digest_drift_kat.cpp).
//   (2) F1 — the finalize driver is the sole live caller of on_block_finalized,
//       one coin-height step at a time, bin_height = high-water AT the step.
//   (3) NATIVE canon — W5 assemble() is the native BTC-family coinbase; no
//       XMR/P-1 code is reachable from here.
//   (4) DASH-regtest DEFAULT; mainnet refused without i_understand_mainnet.
//   (5) v36 reuse — the coin logic lives behind ICoinBackend / IWorkSource; we
//       wire, never rewrite.
//   (6) local smoke uses MockCoinBackend + MemSettleStore (no heavy libs).
//
// Header-only, STL-only. The stratum server object itself (Boost.Asio) is NOT
// constructed here — XbtcNode exposes on_block_won() as the callback the v36
// work source invokes on a block-winning share, so the lifecycle is unit-
// testable with no network. main_v37_btc.cpp binds the real core::StratumServer.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>            // V37Engine (merged)
#include <c2pool/v37/w4_settlement.hpp>         // OwedLedger, SettleHW (merged)
#include <c2pool/v37/w5_coinbase.hpp>           // native BTC-family coinbase (merged)
#include <c2pool/v37/btc/btc_node_config.hpp>
#include <c2pool/v37/btc/btc_settle_store.hpp>
#include <c2pool/v37/btc/btc_finalize_driver.hpp>
#include <c2pool/v37/btc/btc_coin_backend.hpp>
#include <c2pool/v37/v37_drop_harvest.hpp>      // ★ DROPS T3: DropHarvester
#include <c2pool/v37/v37_drops_enrollment.hpp>  // ★ R-SYBIL: EnrollmentBook
#include <sharechain/v37/v37_roundabout.hpp>    // ::v37::LaneRecord, LaneParams

namespace c2pool::v37n::btc {

namespace cb     = ::c2pool::v37n::coinbase;
namespace settle = ::c2pool::v37n::settle;

// Resolve a canonical OWED key to its payout ScriptRef. In production this is
// W4's OI-W4-1 identity view (SettlementView::identities); the smoke supplies a
// P2PKH resolver. Injected so the lifecycle never bakes an identity policy.
using PayOfFn = std::function<::v37::ScriptRef(const ::v37::bytes32& key)>;

// ── S-1: the E_b fold at a win's lane cut, with its own witness ─────────────
// One block win folds the ENTITLEMENT E_b (§4.3) out of the lane snapshot the
// engine has published at that instant, and records the cut it read at. The
// cut witness is diagnostic — the CONSENSUS quantity is `lane_digest`, the
// snapshot's canonical lane commitment: two nodes that fold at the same lane
// digest fold the same E_b, so this is the value the cross-node convergence
// assertion is made against.
//
// NOT the coinbase. `credit` is what the ledger OWES the payees after this
// block; the coinbase `payout` is the K_fair proposal the block actually
// broadcast. They are different maps on purpose (§4.4): credit - payout is the
// carried-forward owed balance, and it is exactly the difference the owed
// digest commits to. Conflating them nets finalW to zero and leaves the digest
// at the empty anchor forever — the S-1 defect this fold replaces.
struct EbCut {
    Amounts        credit;                   // E_b, canonical-key keyed
    bool           folded    = false;        // fold_eb returned a value
    bool           valueless = false;        // folded, but worth nothing (see `refusal`)
    ::v37::bytes32 lane_digest{};            // ★ the cut witness (consensus commitment)
    std::uint64_t  lane_version = 0;         // per-lane monotone publication version
    std::uint64_t  lane_incarnation = 0;     // node-monotone AddLane incarnation (F2/ABA)
    std::uint64_t  next_pos = 0;             // the prefix P the fold read at
    std::size_t    unresolved = 0;           // OI-W4-1 broken-invariant counter
    const char*    source = "none";          // eb_source_name(): live-only / live+carry
    std::string    refusal;                  // non-empty => the loud reason
    // ★ S-1c: the reward THIS fold consumed. E_b is a function of (reward,
    // payout, identities); a peer must fold with the SAME reward, and the
    // coin backend cannot be asked for it later (block_reward is fail-closed
    // on a moved template cache). Recorded here so the value that actually
    // entered the fold — not a second, possibly different read — is what the
    // v0x02 cut descriptor carries.
    std::uint64_t  reward = 0;
    // ── ★ DROPS-R1: the conversion this cut prices work at ────────────────
    // (reward, SUM weight) read through the SAME project() call the fold ran, so
    // an estimated hash and a real hash at this cut are worth the same satoshi.
    settle::WorkPrice price{};
    // ── ★ DROPS-R3: the COMPOSED DROPS delta map at this cut ──────────────
    // On an OWN win: composed once, here, from our buried harvest — credited to
    // our own ledger AND put on the v0x03 wire, so the two are the same bytes.
    // On a PEER win: the map read off the wire, folded exactly as received.
    Amounts        drops_delta;
    ::v37::bytes32 enrollment_digest{};   // R-SYBIL witness at the cut
    bool           drops_saturated = false;  // R1 clamp fired (never on a live cut)
};

// The disposition of a block-winning share the v36 work source handed us.
struct WonBlockOutcome {
    bool                  emitted = false;   // W5 buried-gate decided to pay
    std::size_t           outputs = 0;       // K_fair outputs assembled
    ::v37::bytes32        state_root{};       // §13 root committed in the coinbase
    SubmitResult          submit;            // coin-backend submit disposition
    std::string           bid;               // the block hash we submitted under
    EbCut                 cut;               // ★ S-1: the E_b fold this win credited
};

// S-1 refusal counters (diagnostics only — never consensus). A live node that
// registers wins with no credit is BROKEN, and these are how an operator sees
// it without reading the log.
struct S1FoldStats {
    std::uint64_t folds      = 0;   // wins whose E_b fold produced a credit map
    std::uint64_t no_view    = 0;   // wins with no published lane snapshot
    std::uint64_t refused    = 0;   // wins fold_eb REFUSED (geometry not ratified)
    std::uint64_t valueless  = 0;   // wins registered with an EMPTY credit (reward 0 / empty lane)
    std::uint64_t unresolved = 0;   // total OI-W4-1 unresolved payout keys seen
};

// ═══════════════════════════════════════════════════════════════════════════
// ★ S-1c — A PEER'S BLOCK WIN, as the flat cut descriptor delivers it.
//
// THE DEFECT S-1c CLOSES. After S-1, the node that MINED a block credits E_b
// and its owed_digest leaves the empty anchor. Its peers do not: they account
// the block-winning carrier as an ordinary share and know nothing of the block,
// so their finalW never moves. Two peered nodes that have ingested the byte-
// identical carrier stream therefore emit DIFFERENT owed_digests — A != B —
// which is a settlement fork, not a cosmetic gap.
//
// THE FIX. The winner names its fold on the wire (w3_relay.hpp CutDescriptor,
// carrier wire v0x02) and every receiver re-runs THE SAME fold against its OWN
// engine at THE SAME prefix, then drives its OWN ledger through the EXISTING
// on_block_found / on_block_finalized API. Nothing about the fold, the ledger
// or the owed commitment is re-implemented here: this is a second CALLER of
// settle::fold_eb, not a second fold.
//
// THE CUT RULE (the whole correctness argument). E_b = fold_eb(reward, view@P)
// is a pure function of (reward, view.payout, view.identities) at ONE lane
// prefix P (w4_settlement.hpp S8). A receiver that folded at ITS OWN TIP would
// fold at a strictly later prefix — its tip already includes the block-winning
// carrier it just admitted — and would credit a DIFFERENT E_b. So the receiver
// folds at the winner's (next_pos, spine_digest), read back out of its own ring
// (V37Engine::settlement_view_by_cut), and REFUSES if it cannot find that exact
// prefix with that exact commitment. Refusing is the honest failure: it leaves
// A != B visible and counted, where folding-at-the-wrong-cut would hide a fork
// behind a plausible number.
struct PeerWin {
    std::string    bid;                  // the OwedLedger key (hex, from the wire)
    std::uint64_t  h_b = 0;              // the block's OWN height (D8)
    std::uint64_t  cut_next_pos = 0;     // P — the prefix the WINNER folded at
    ::v37::bytes32 cut_spine_digest{};   // the lane commitment at P
    std::uint64_t  reward = 0;           // the winner's block_reward(H_b)
    bool           payout_emitted = false;      // winner's W5 assembly emitted outputs
    ::v37::bytes32 owed_digest_at_win{};        // VERIFY field (diagnostics only)
    // ── ★ DROPS-R3: the WINNER'S composed DROPS credit map, off wire v0x03 ──
    // `has_drops` false means the winner carried no map at all — a DROPS-dormant
    // winner — and an EMPTY map is exactly what it credited itself, so folding
    // nothing here converges with it. A raindrop is a node-local observation, so
    // this map is the one part of the settlement a receiver cannot recompute:
    // it is taken as the winner told it, and the local harvest plays no part.
    bool                              has_drops = false;
    std::map<::v37::bytes32, long long> drops_credit;
    ::v37::bytes32                    enrollment_digest{};   // winner's book digest
};

struct PeerWinOutcome {
    bool  registered = false;      // the FOUND entered our ledger + F1 driver
    EbCut cut;                     // the fold we ran (credit / witness / refusal)
    // the refusal shapes, each its own bit so an operator never has to guess
    bool  cut_miss = false;             // P is not a prefix THIS node published
    bool  cut_digest_mismatch = false;  // P published here with a DIFFERENT digest
    bool  refused_payout_emitted = false;  // winner already paid a coinbase (unreproducible)
    bool  refused_too_late = false;        // H_b already below our finalize cursor
    bool  already_known = false;           // our own win, or a duplicate descriptor
    // the VERIFY field: did our owed commitment agree with the winner's at the
    // instant of the win? A `false` here means the two nodes had ALREADY
    // diverged before this block — the earliest point at which that is visible.
    bool  owed_at_win_agreed = false;
    ::v37::bytes32 owed_here_at_receipt{};
    // ★ DROPS-R3 diagnostics: how many rows of the WINNER'S map we folded, and
    // how many of OUR OWN buried harvest rows we consumed and threw away so the
    // two nodes' harvesters stay at the same frontier.
    std::size_t drops_carried_rows = 0;
    std::size_t drops_local_discarded = 0;
};

// S-1c receive-side counters (diagnostics only — never consensus).
struct S1PeerStats {
    std::uint64_t seen        = 0;   // peer block-winner descriptors offered
    std::uint64_t credited    = 0;   // folded at the carried cut and REGISTERED
    std::uint64_t valueless   = 0;   // registered with an EMPTY credit (reward 0 / empty lane)
    std::uint64_t cut_miss    = 0;   // P not published here (ring evicted / coalesced through)
    std::uint64_t cut_mismatch = 0;  // P published here with a DIFFERENT lane digest (!)
    std::uint64_t refused_fold = 0;  // fold_eb REFUSED (geometry not ratified)
    std::uint64_t refused_payout = 0;// winner had already emitted a coinbase
    std::uint64_t refused_late = 0;  // H_b at or below our finalize cursor
    std::uint64_t already_known = 0; // our own win, or a duplicate
    std::uint64_t owed_diverged = 0; // owed_digest_at_win != ours at receipt
};

class XbtcNode {
public:
    XbtcNode(BtcNodeConfig cfg, std::unique_ptr<ISettleStore> store,
             std::shared_ptr<ICoinBackend> coin, PayOfFn pay_of)
        : m_cfg(std::move(cfg)), m_store(std::move(store)),
          m_coin(std::move(coin)), m_pay_of(std::move(pay_of)) {}

    // ── STEP 1: open() — durable side, BEFORE the engine starts ──────────────
    // Rebuild the OWED ledger from the store (F2 fail-closed). Returns false iff
    // the store is torn (the daemon must then refuse to start). Also enforces
    // the mainnet fence (HARD SAFETY 4).
    bool open() {
        if (m_cfg.network == BtcNetwork::Mainnet && !m_cfg.i_understand_mainnet)
            return false;   // loud mainnet refusal

        m_ledger = std::make_unique<OwedLedger>(m_cfg.lane_chain);

        RecoveryDriver rec(*m_store, m_cfg.lane_chain);
        bool ok = false;
        RecoveredState st = rec.recover(*m_ledger, ok);
        if (!ok) return false;                 // F2: torn store → refuse to start
        m_hw = st.hw;

        // The F1 driver, seeded with the recovered cursor + event seq, its
        // canonicality predicate bound to the coin backend (the reorg oracle).
        auto is_canon = [this](std::uint64_t h, const std::string& bid) {
            return m_coin->is_canonical(h, bid);
        };
        m_fin = std::make_unique<BtcFinalizeDriver>(
            *m_ledger, m_hw, *m_store, m_cfg.lane_chain, m_cfg.d_conf,
            st.finalize_cursor_height, st.max_event_seq, is_canon);
        m_opened = true;
        return true;
    }

    // ── STEP 2: start() — live side ──────────────────────────────────────────
    // Spin the engine and seed the single BTC-family lane THROUGH it (so its
    // digest is the executor's). The stratum server + height-watch are driven
    // externally (main binds core::StratumServer; a poll loop calls on_tip()).
    bool start() {
        if (!m_opened) return false;
        m_engine = std::make_unique<V37Engine>();
        m_engine->start();
        ::v37::SubmitResult r =
            m_engine->submit_tracked(
                        ::v37::LaneRecord::add_lane(m_cfg.lane_chain, m_cfg.lane_params))
                .get();
        if (!r.applied()) return false;
        m_started = true;
        return true;
    }

    // ── STEP 2g: the F1 height-watch tick ───────────────────────────────────
    // Called on every observed coin-tip advance (the main poll loop reads
    // ICoinBackend::best_tip() and passes it here). Delegates to the F1 driver,
    // which steps ONE coin-height at a time — never jumps to the tip.
    std::vector<FinalizeStep> on_tip(const CoinTip& tip) {
        if (!m_started) return {};
        return m_fin->advance_to_tip(tip.height, tip.id);
    }
    // Convenience: read the backend's tip and tick.
    std::vector<FinalizeStep> poll_tip() { return on_tip(m_coin->best_tip()); }

    // ── STEP 2f: on_block_won() — a block-winning share arrived ──────────────
    // The v36 work source's mining_submit found PoW ≤ block target. Build the
    // W5 NATIVE coinbase from the finality-gated OWED ledger (oldest-owed-first
    // K_fair, §13 state-root) under the buried gate, then submit the block to
    // the coin network via the backend. `bid` is the winning block's hash; the
    // real block hex is assembled by the v36 reconstructor from these outputs
    // (dash::coin::reconstruct_won_block) — here we pass the coinbase summary
    // through to the backend, which in production feeds the reconstructor.
    //
    // The buried gate here is the block's OWN-chain depth at win time (a fresh
    // win is depth 0, so a live win emits nothing until it matures — exactly the
    // W5/§4.7 rule); the STANDING settlement is what the F1 driver finalizes as
    // blocks bury. So on_block_won primarily REGISTERS the found block with the
    // F1 driver (write-ahead + pending) and assembles the coinbase the block
    // will carry; emission of PRIOR owed balances rides the buried gate.
    WonBlockOutcome on_block_won(const std::string& bid, std::uint64_t won_height,
                                 std::uint64_t confirmations) {
        WonBlockOutcome out;
        out.bid = bid;
        if (!m_started) return out;

        const std::uint64_t reward = m_coin->block_reward(won_height);

        // ── ★ S-1 (live fold-wiring): the ENTITLEMENT this win creates ───────
        // Fold E_b out of the lane cut the engine has published RIGHT NOW, and
        // keep the witness of which cut that was. This is the live path that
        // was missing: before it, the only live FOUND sites handed the ledger a
        // credit built from the W5 assembly, which a fresh win (confirmations
        // == 0) WITHHOLDS — so credit was empty, finalW never moved, and
        // owed_digest stayed at the empty "V37O" anchor forever.
        out.cut = fold_entitlement_at_cut(reward, bid, won_height);

        // R1: the ratified defaults are UNBOUNDED output-count C and byte budget
        // K_max (spec §4.6) — pay every eligible owed balance the reward covers.
        // slot_budget_C == 0 / max_payout_bytes == 0 BOTH mean UNBOUNDED (the two
        // caps are symmetric and honored in OwedLedger::propose_coinbase / the W5
        // assemble byte loop), NOT "emit nothing". k_floor > 0 ARMS the byte-
        // denominated no-dust floor (coinbase-prioritization Rule 0):
        // h_min(P2PKH) = 34 sat, so no sub-floor dust output is ever emitted (a
        // below-floor balance carries forward, owed unchanged). All three caps
        // are consensus-fixed and identical fleet-wide (shipped defaults).
        cb::CoinbaseBudget budget;
        budget.slot_budget_C    = 0;   // unbounded output-count C (ratified default)
        budget.max_payout_bytes = 0;   // unbounded byte budget K_max (ratified default)
        budget.k_floor          = 1;   // real byte floor -> h_min > 0 (no dust emitted)

        auto pay_of = [this](const ::v37::bytes32& k) { return m_pay_of(k); };

        cb::BurialGate gate;
        gate.d_conf        = m_cfg.d_conf;
        gate.canonical     = m_coin->is_canonical(won_height, bid);
        gate.confirmations = confirmations;

        // W5 native coinbase from the OWED ledger, buried-gated (§13 state root).
        cb::CoinbaseAssembly asm_ =
            cb::assemble_if_buried(*m_ledger, reward, budget, gate, pay_of);
        out.emitted    = asm_.emitted;
        out.outputs    = asm_.outputs.size();
        out.state_root = asm_.state_root;

        // Register the found block with the F1 driver: write-ahead FOUND + enter
        // the merged ledger's pending set, so as the block buries D_conf deep the
        // height-watch finalizes it IN ORDER (the F1 contract).
        //
        // ★ S-1: credit and payout are DIFFERENT maps and must stay so.
        //   credit = E_b, the entitlement this block creates over the lane cut
        //            above (what the pool now OWES its payees).
        //   payout = the coinbase outputs this block ACTUALLY BROADCAST — the
        //            K_fair proposal the buried gate admitted. A fresh win
        //            (confirmations == 0) emits nothing, so this is EMPTY here
        //            and the whole entitlement carries forward as owed; that
        //            carry is precisely what owed_digest commits to.
        // FINALIZE does finalW += credit; finalW -= payout (Settlement.tla G).
        // Registering credit == payout nets every block to zero and is the
        // defect; registering the assembly as the CREDIT loses the entitlement
        // entirely. Both are replaced here.
        FoundBlock fb;
        fb.bid    = bid;
        fb.height = won_height;
        fb.credit = out.cut.credit;
        for (const auto& o : asm_.outputs)
            fb.payout[o.key] = static_cast<long long>(o.amount);
        // ★ DROPS T3 (own win), now composed EXACTLY ONCE, here.
        //
        // The node builds the DROPS delta map itself instead of handing the
        // driver a harvest to compose later, for one reason: under DROPS-R3 the
        // winner also BROADCASTS that map, and the map it broadcasts and the map
        // it credits itself must be the same bytes. Composing in two places
        // would make that a hope; composing once makes it a fact.
        //   R1  dctx.price denominates BOTH sides of the replace through the
        //       ordinary share -> E_b conversion this very fold just read.
        //   R-SYBIL  dctx.enrollment credits only identities that committed to
        //       DROPS before the interval; everyone else keeps its S*T path.
        settle::DropsCompose dctx;
        dctx.price      = out.cut.price;
        dctx.enrollment = m_enroll;
        const auto harvest = buried_harvest(won_height);
        bool drops_sat = false;
        out.cut.drops_delta =
            settle::subthreshold_credit(m_cfg.lane_params, harvest, dctx, &drops_sat);
        out.cut.drops_saturated   = drops_sat;
        out.cut.enrollment_digest = dctx.enrollment_digest();
        m_last_cut = out.cut;          // so last_cut() and last_won().cut agree
        fb.params            = m_cfg.lane_params;
        fb.drops             = dctx;
        fb.has_carried_drops = true;            // the map above IS the map
        fb.carried_drops     = out.cut.drops_delta;
        m_fin->on_block_found(fb);

        // Submit the block to the coin network (ARM A embedded P2P + ARM B
        // submitblock RPC, behind the backend). block_hex is produced by the v36
        // reconstructor in production; the smoke's MockCoinBackend accepts a
        // non-empty placeholder. Fail-closed: if PoW verify is off, we never
        // reach here (the work source rejected the share as a network block).
        out.submit = m_coin->submit_block(reconstruct_block_hex(bid, asm_));
        m_last_won = out;   // S-1c: the send side reads `emitted`/`outputs` from here
        return out;
    }

    // ── ★ S-1c: on_peer_block_won() — a PEER's block win, from the wire ──────
    // Credit OUR ledger with the SAME E_b the winner credited, at the SAME lane
    // prefix, and register the FOUND so OUR height-watch finalizes it at the
    // SAME bin_height (FinalizeStep::bin_height == H_b + d_conf, and d_conf is
    // fleet-identical, so equal H_b => equal bin). No submit, no coin-backend
    // probe, no template read: this path touches the network not at all.
    //
    // REFUSE, DO NOT GUESS. Unlike on_block_won (our own block, where the FOUND
    // must be registered even if the fold gives nothing — the coinbase we paid
    // still has to be deducted), every failure below REFUSES the registration
    // outright and says why. A peer's block that we cannot credit correctly is
    // one we must not credit at all: registering it with a fabricated or empty
    // credit would put a DIFFERENT number into our finalW than the winner put
    // into theirs, which is exactly the divergence this path exists to remove.
    PeerWinOutcome on_peer_block_won(const PeerWin& w) {
        PeerWinOutcome out;
        if (!m_started) return out;
        ++m_s1p.seen;

        out.owed_here_at_receipt = m_ledger->owed_digest();
        out.owed_at_win_agreed   = (out.owed_here_at_receipt == w.owed_digest_at_win);
        if (!out.owed_at_win_agreed) {
            ++m_s1p.owed_diverged;
            say_s1c(w, "VERIFY MISMATCH: the winner's owed_digest at the win differs from ours "
                       "at receipt — these two nodes had ALREADY diverged before this block "
                       "(this is a report, not a refusal: the fold below still runs)");
        }

        // (a) ours already, or a duplicate descriptor: the ledger is idempotent
        //     per bid, but say so rather than letting it look like a credit.
        if (m_ledger->is_pending(w.bid) || m_ledger->is_settled(w.bid)) {
            ++m_s1p.already_known;
            out.already_known = true;
            return out;
        }
        // (b) the winner had already broadcast a coinbase. Its payout map is NOT
        //     on the wire (unbounded), and we cannot reproduce it — fail closed.
        //     A FRESH win is at depth 0 so the W5 burial gate withholds, which is
        //     why this is the one shape v0x02 refuses rather than carries.
        if (w.payout_emitted) {
            ++m_s1p.refused_payout;
            out.refused_payout_emitted = true;
            say_s1c(w, "REFUSED: the winner's coinbase had already EMITTED outputs, and the "
                       "payout map is not on the wire — we cannot reproduce it, so we credit "
                       "nothing rather than credit something different");
            return out;
        }
        // (c) too late: H_b is at or below our finalize cursor, so advance_to_tip
        //     will never step that height again and the FOUND would sit pending
        //     forever (deducting nothing, finalizing never).
        if (w.h_b == 0 || w.h_b <= m_fin->cursor_height()) {
            ++m_s1p.refused_late;
            out.refused_too_late = true;
            say_s1c(w, "REFUSED: H_b is at or below our finalize cursor — this block can never "
                       "be stepped at maturity here (the descriptor arrived after we had already "
                       "buried past it)");
            return out;
        }

        // (d) THE CUT RULE: fold at the WINNER'S prefix, read back from OUR ring.
        bool mismatch = false;
        std::shared_ptr<const SettlementView> view =
            m_engine->settlement_view_by_cut(m_cfg.lane_chain, w.cut_next_pos,
                                             w.cut_spine_digest, &mismatch);
        if (!view) {
            out.cut_miss = !mismatch;
            out.cut_digest_mismatch = mismatch;
            if (mismatch) {
                ++m_s1p.cut_mismatch;
                say_s1c(w, "REFUSED: we published the winner's prefix P with a DIFFERENT lane "
                           "digest — the two nodes folded different records into the same prefix. "
                           "This is a SHARECHAIN divergence, not a settlement one; the owed ledger "
                           "cannot repair it");
            } else {
                ++m_s1p.cut_miss;
                say_s1c(w, "REFUSED: the winner's prefix P is not a version THIS node published "
                           "(older than the settlement ring, or the executor coalesced through "
                           "it) — we will not fold at a neighbouring prefix (O2.3)");
            }
            return out;
        }

        // (e) the fold — settle::fold_eb, the SAME single entry point the winner
        //     used, over the SAME (reward, payout, identities) triple.
        EbCut c;
        c.lane_digest      = view->digest;
        c.lane_version     = view->version;       // OUR version number for that prefix
        c.lane_incarnation = view->incarnation;   // OUR incarnation (node-local, never on the wire)
        std::optional<settle::EbFold> f = settle::fold_eb(w.reward, *view, /*strict=*/true);
        if (!f) {
            ++m_s1p.refused_fold;
            c.valueless = true;
            c.next_pos  = view->next_pos;
            c.refusal   = "fold_eb REFUSED at the peer's cut: this lane's geometry is NOT "
                          "ratified (settle::geometry_is_ratified == false)";
            out.cut = c;
            say_s1c(w, c.refusal);
            return out;
        }
        c.folded     = true;
        c.next_pos   = f->next_pos;
        c.unresolved = f->unresolved;
        c.source     = settle::eb_source_name(f->source);
        c.price      = settle::work_price_at(w.reward, *view);   // ★ R1
        for (const auto& [k, v] : f->credit) c.credit[k] = static_cast<long long>(v);
        m_s1.unresolved += f->unresolved;
        if (w.reward == 0 || c.credit.empty()) {
            c.valueless = true;
            c.refusal   = (w.reward == 0)
                ? "the winner carried reward == 0 — it registered a VALUELESS win and so do we "
                  "(both nodes credit nobody, which still CONVERGES)"
                : "E_b is EMPTY at the carried cut — the lane had no accounted weight at P "
                  "(both nodes credit nobody, which still CONVERGES)";
        }
        out.cut = c;

        // (f) the payout leg. The winner's coinbase outputs are not on the wire;
        //     payout_emitted == false (checked in (b)) says the winner's W5
        //     burial gate WITHHELD, so its payout map was EMPTY. We mirror that
        //     gate exactly — a freshly relayed win is at depth 0 and is not yet
        //     canonical here — so assemble_if_buried withholds for us too and
        //     the two payout maps are equal BY CONSTRUCTION, not by luck.
        cb::CoinbaseBudget budget;
        budget.slot_budget_C    = 0;   // unbounded (ratified default, mirrors on_block_won)
        budget.max_payout_bytes = 0;   // unbounded (ratified default)
        budget.k_floor          = 1;   // byte-denominated no-dust floor
        cb::BurialGate gate;
        gate.d_conf        = m_cfg.d_conf;
        gate.canonical     = false;    // a peer's fresh win is never canonical to us yet
        gate.confirmations = 0;        // depth 0: the W5 gate withholds
        auto pay_of = [this](const ::v37::bytes32& k) { return m_pay_of(k); };
        cb::CoinbaseAssembly asm_ =
            cb::assemble_if_buried(*m_ledger, w.reward, budget, gate, pay_of);

        FoundBlock fb;
        fb.bid    = w.bid;
        fb.height = w.h_b;
        fb.credit = c.credit;
        for (const auto& o : asm_.outputs)
            fb.payout[o.key] = static_cast<long long>(o.amount);
        // ★★ DROPS-R3 (S-1c PEER win) — RULED, AND THIS IS THE FIX.
        //
        // THE DEFECT. This path used to add THIS node's buried harvest to the
        // locally re-folded E_b. E_b is recomputable (it is a pure function of
        // reward, payout and identities, all of which the peer holds) — but a
        // RAINDROP IS NOT. It is a below-target work event one node happened to
        // see on its own wire; two nodes observe different sets by construction.
        // So with harvesters attached, two nodes credited DIFFERENT numbers for
        // the SAME peer win and their owed_digests parted at the first block.
        // That is the S-1c fork wearing a new hat, and unlike the canonical
        // coinbase case there is no recompute available: the evidence never
        // reached the peer.
        //
        // THE RULE. THE WINNER'S VIEW IS AUTHORITATIVE. We fold the map the
        // winner composed and put on the wire, verbatim — never our own harvest,
        // which has no standing on someone else's block. An absent map (a
        // DROPS-dormant winner) folds as EMPTY, which is exactly what that
        // winner credited itself, so the two still converge.
        //
        // AND WE STILL ADVANCE OUR OWN HARVESTER. The local buried rows are
        // consumed and DISCARDED at the same frontier. If they were left open
        // they would be folded into THIS node's next own win, for intervals the
        // fleet had already settled — the same divergence, one block later.
        fb.params            = m_cfg.lane_params;
        out.drops_local_discarded = discard_local_harvest(w.h_b);
        fb.has_carried_drops = true;
        for (const auto& [k, v] : w.drops_credit)
            if (v != 0) fb.carried_drops[k] += v;
        out.drops_carried_rows = fb.carried_drops.size();
        c.drops_delta          = fb.carried_drops;
        c.enrollment_digest    = w.enrollment_digest;
        out.cut                = c;    // re-publish the cut with the carried map
        m_fin->on_block_found(fb);     // write-ahead FOUND + pending + maturity map

        out.registered = true;
        if (c.valueless) ++m_s1p.valueless; else ++m_s1p.credited;
        m_last_peer_cut = c;
        say_s1c(w, c.refusal.empty() ? "credited" : c.refusal);
        return out;
    }

    // A reorg dropped a block we found — dispose via the F1 driver (O3.5).
    void on_block_orphaned(const std::string& bid) {
        if (m_started) m_fin->on_block_orphaned(bid);
    }

    // ── STEP 3: stop() — donor teardown order ────────────────────────────────
    void stop() {
        if (m_engine) m_engine->stop();     // drain-and-join (network already down)
        m_started = false;
    }

    // ── read seams (any thread) ──────────────────────────────────────────────
    OwedLedger&       ledger()        { return *m_ledger; }
    V37Engine&        engine()        { return *m_engine; }
    BtcFinalizeDriver& finalizer()    { return *m_fin; }
    const BtcNodeConfig& config() const { return m_cfg; }
    std::shared_ptr<const ::v37::LaneSnapshot> lane_snapshot() const {
        return m_engine ? m_engine->snapshot(m_cfg.lane_chain) : nullptr;
    }
    // S-1 diagnostics: the refusal counters and the cut the last win folded at.
    const S1FoldStats& s1_stats() const { return m_s1; }
    const EbCut&       last_cut() const { return m_last_cut; }
    // S-1c diagnostics: the receive-side counters and the last peer cut folded.
    const WonBlockOutcome& last_won()   const { return m_last_won; }
    const S1PeerStats& s1c_stats()     const { return m_s1p; }
    const EbCut&       last_peer_cut() const { return m_last_peer_cut; }

    // ── ★ DROPS T3: attach the node-local sub-threshold harvest ──────────────
    // `h` is the DropHarvester the W2 admitter's DropSink feeds
    // (v37_drop_harvest.hpp). NOT attached by default: with no harvester every
    // FOUND carries an empty harvest, compose_credit_replace() returns E_b
    // unchanged, and the node settles exactly as master does. Attach it only on
    // a node whose lane_params carry the SubthresholdGate ON — a harvest folded
    // into a gated-off settlement credits nothing and only costs memory.
    //
    // The node does not own the harvester's lifetime; the caller that owns the
    // admitter owns it, because that is who feeds it.
    void set_drop_harvester(DropHarvester* h) { m_drops = h; }
    DropHarvester* drop_harvester() const { return m_drops; }

    // ── ★ R-SYBIL: attach the EX-ANTE ENROLMENT BOOK ─────────────────────
    // NOT attached by default, and that default is the safe one: with no book,
    // NOBODY is enrolled, so the composition credits nothing at all and the node
    // settles exactly as master does even with the gate on and a full harvest.
    // The node does not own the book's lifetime.
    void set_enrollment_book(const EnrollmentBook* b) { m_enroll = b; }
    const EnrollmentBook* enrollment_book() const { return m_enroll; }

    // ── ★ the SHARE-COUNT DECLARE hook ───────────────────────────────────
    // Called with the burial frontier immediately BEFORE the harvest is taken
    // (and before it is discarded on a peer win, so two nodes prune their
    // counters at the same frontiers). The owner of the admitter wires this to
    // ShareCountBook::declare_into(harvester, frontier, lz_of, enrollment) —
    // which is what makes DropHarvester's fail-closed declare_shares() rule a
    // live path instead of an API nobody drives.
    using PreHarvestFn = std::function<void(std::uint64_t bury_before)>;
    void set_pre_harvest(PreHarvestFn f) { m_pre_harvest = std::move(f); }
    // How many harvest rows the last FOUND folded (diagnostic; 0 when detached).
    std::size_t last_harvest_rows() const { return m_last_harvest_rows; }

private:
    // ── ★ DROPS T3: the buried harvest for a win at coin height H_b ──────────
    // F1: only intervals strictly BELOW the burial frontier may be shown to the
    // estimator, and take_buried() consumes them so the same interval can never
    // be folded into two blocks. The frontier is the same D_conf the finalize
    // driver gates on: an interval is eligible once it is as buried as the block
    // that would settle it. A node with no harvester attached returns {} and the
    // whole seam is inert.
    std::vector<settle::HarvestedReceipt> buried_harvest(std::uint64_t won_height) {
        if (!m_drops) { m_last_harvest_rows = 0; return {}; }
        const std::uint64_t frontier =
            won_height > m_cfg.d_conf ? won_height - m_cfg.d_conf : 0;
        if (m_pre_harvest) m_pre_harvest(frontier);   // ★ declare S before release
        auto rows = m_drops->take_buried(frontier);
        m_last_harvest_rows = rows.size();
        return rows;
    }

    // ★ DROPS-R3: consume our own buried harvest on a PEER win and throw it
    // away. Nothing of ours is credited on someone else's block, but the
    // frontier must still move or those intervals would be credited later, on
    // our own next win, for a cut the fleet has already settled.
    std::size_t discard_local_harvest(std::uint64_t h_b) {
        if (!m_drops) return 0;
        const std::uint64_t frontier = h_b > m_cfg.d_conf ? h_b - m_cfg.d_conf : 0;
        if (m_pre_harvest) m_pre_harvest(frontier);
        return m_drops->discard_buried(frontier);
    }

    // ── ★ S-1: fold E_b at the lane cut published NOW ────────────────────────
    // The ONE credit-path entry point is settle::fold_eb — it does the ratified-
    // geometry refusal AND the fold in one call (the S8 seam), so a settlement
    // over a non-ratified geometry cannot reach the ledger through here. strict
    // == true is the production setting; a HARD refusal is never retried.
    //
    // REFUSE LOUD, REGISTER ANYWAY. A real block we mined is a real block: the
    // FOUND registration must happen even when the fold gives us nothing, or the
    // block is lost to the F1 driver and the coinbase it paid is never deducted.
    // So every failure path below stamps the record VALUELESS, screams on
    // stderr, bumps a counter — and returns an empty credit that is still
    // registered by the caller.
    EbCut fold_entitlement_at_cut(std::uint64_t reward, const std::string& bid,
                                  std::uint64_t won_height) {
        EbCut c;
        c.reward = reward;   // S-1c: the exact value this fold consumed
        std::shared_ptr<const ::v37::LaneSnapshot> view =
            m_engine ? m_engine->snapshot(m_cfg.lane_chain) : nullptr;
        if (!view) {
            ++m_s1.no_view;
            c.valueless = true;
            c.refusal = "no lane snapshot published for chain " +
                        std::to_string(static_cast<unsigned long long>(m_cfg.lane_chain));
            say_s1(bid, won_height, reward, c);
            m_last_cut = c;
            return c;
        }
        c.lane_digest      = view->digest;
        c.lane_version     = view->version;
        c.lane_incarnation = view->incarnation;

        std::optional<settle::EbFold> f = settle::fold_eb(reward, *view, /*strict=*/true);
        if (!f) {
            ++m_s1.refused;
            c.valueless = true;
            c.next_pos  = view->next_pos;
            c.refusal   = "fold_eb REFUSED: this lane's geometry is NOT ratified "
                          "(settle::geometry_is_ratified == false) — the settlement "
                          "boundary will not credit over it";
            say_s1(bid, won_height, reward, c);
            m_last_cut = c;
            return c;
        }
        c.folded     = true;
        c.next_pos   = f->next_pos;
        c.unresolved = f->unresolved;
        c.source     = settle::eb_source_name(f->source);
        // ★ DROPS-R1: the conversion this cut prices work at, read through the
        // SAME project() the fold just ran — (reward, SUM weight), nothing new.
        c.price      = settle::work_price_at(reward, *view);
        for (const auto& [k, v] : f->credit)
            c.credit[k] = static_cast<long long>(v);
        m_s1.unresolved += f->unresolved;

        if (reward == 0) {
            c.valueless = true;
            c.refusal   = "reward == 0 at H_b — the coin backend answered "
                          "fail-closed (cached template height != H_b?); the win is "
                          "registered VALUELESS and credits nobody";
        } else if (c.credit.empty()) {
            c.valueless = true;
            c.refusal   = "E_b is EMPTY at this cut — the lane has no accounted "
                          "weight (no shares ingested: is the carrier relay up?); "
                          "the win is registered VALUELESS and credits nobody";
        }
        if (c.valueless) ++m_s1.valueless; else ++m_s1.folds;
        say_s1(bid, won_height, reward, c);
        m_last_cut = c;
        return c;
    }

    // The cut witness on one line. STL-only (this header links no logger): the
    // daemon mirrors it through LOG_* from WonBlockOutcome::cut.
    static void say_s1(const std::string& bid, std::uint64_t h, std::uint64_t reward,
                       const EbCut& c) {
        auto hex32 = [](const ::v37::bytes32& d) {
            static const char* H = "0123456789abcdef";
            std::string s;
            for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; }
            return s;
        };
        std::fprintf(c.valueless ? stderr : stdout,
                     "[v37-s1] %s FOUND %s h=%llu reward=%llu E_b=%zu keys "
                     "cut{lane_digest=%s version=%llu incarnation=%llu next_pos=%llu "
                     "source=%s unresolved=%zu}%s%s\n",
                     c.valueless ? "VALUELESS" : "credit", bid.c_str(),
                     static_cast<unsigned long long>(h),
                     static_cast<unsigned long long>(reward), c.credit.size(),
                     hex32(c.lane_digest).c_str(),
                     static_cast<unsigned long long>(c.lane_version),
                     static_cast<unsigned long long>(c.lane_incarnation),
                     static_cast<unsigned long long>(c.next_pos), c.source,
                     c.unresolved, c.refusal.empty() ? "" : " — ",
                     c.refusal.c_str());
    }

    // The S-1c receive-side line. Same STL-only shape as say_s1: the daemon
    // mirrors it through LOG_* from the PeerWinOutcome.
    void say_s1c(const PeerWin& w, const std::string& note) const {
        auto hex32 = [](const ::v37::bytes32& d) {
            static const char* H = "0123456789abcdef";
            std::string s;
            for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; }
            return s;
        };
        std::fprintf(stdout,
                     "[v37-s1c] PEER WIN %s h=%llu reward=%llu cut{P=%llu spine=%s} "
                     "payout_emitted=%d owed_at_win=%s — %s\n",
                     w.bid.c_str(), static_cast<unsigned long long>(w.h_b),
                     static_cast<unsigned long long>(w.reward),
                     static_cast<unsigned long long>(w.cut_next_pos),
                     hex32(w.cut_spine_digest).c_str(), w.payout_emitted ? 1 : 0,
                     hex32(w.owed_digest_at_win).c_str(), note.c_str());
    }

    // Placeholder for the v36 reconstruct_won_block(share_hash, coinbase, ...)
    // full-block-hex assembly. Kept out of the lifecycle proper (it needs the
    // known-tx bodies + the coin's block header codec, which live in the v36
    // coin lib). The DashCoinBackend fills this via reconstruct_won_block; the
    // smoke returns a non-empty marker so submit() exercises the wire.
    static std::string reconstruct_block_hex(const std::string& bid,
                                             const cb::CoinbaseAssembly& a) {
        // GAP: real path is dash::coin::reconstruct_won_block(...) -> .hex.
        return "v37blk:" + bid + ":" + std::to_string(a.outputs.size());
    }

    BtcNodeConfig                  m_cfg;
    std::unique_ptr<ISettleStore>  m_store;
    std::shared_ptr<ICoinBackend>  m_coin;
    PayOfFn                        m_pay_of;

    std::unique_ptr<OwedLedger>        m_ledger;
    SettleHW                           m_hw;
    std::unique_ptr<BtcFinalizeDriver> m_fin;
    std::unique_ptr<V37Engine>         m_engine;
    // ★ DROPS T3: non-owning, DEFAULT NULL => the whole seam is inert.
    DropHarvester*                     m_drops = nullptr;
    const EnrollmentBook*              m_enroll = nullptr;
    PreHarvestFn                       m_pre_harvest{};
    std::size_t                        m_last_harvest_rows = 0;

    S1FoldStats m_s1;        // S-1 fold counters (diagnostics)
    EbCut       m_last_cut;  // the cut the last win folded at (diagnostics)
    WonBlockOutcome m_last_won;  // the last OWN win's disposition (diagnostics)
    S1PeerStats m_s1p;           // S-1c receive-side counters (diagnostics)
    EbCut       m_last_peer_cut; // the cut the last PEER win folded at (diagnostics)

    bool m_opened = false;
    bool m_started = false;
};

// ── a P2PKH pay_of for the smoke / any all-P2PKH deployment ─────────────────
// Maps a canonical key's first 20 bytes to a P2PKH ScriptRef. Production wires
// PayOfFn to the W4 OI-W4-1 identity view instead.
inline PayOfFn p2pkh_pay_of() {
    return [](const ::v37::bytes32& k) {
        ::v37::ScriptRef r;
        r.kind = ::v37::ScriptKind::P2PKH;
        r.payload.assign(k.begin(), k.begin() + 20);
        return r;
    };
}

} // namespace c2pool::v37n::btc
