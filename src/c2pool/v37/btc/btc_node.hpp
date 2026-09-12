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
        m_fin->on_block_found(fb);

        // Submit the block to the coin network (ARM A embedded P2P + ARM B
        // submitblock RPC, behind the backend). block_hex is produced by the v36
        // reconstructor in production; the smoke's MockCoinBackend accepts a
        // non-empty placeholder. Fail-closed: if PoW verify is off, we never
        // reach here (the work source rejected the share as a network block).
        out.submit = m_coin->submit_block(reconstruct_block_hex(bid, asm_));
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

private:
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

    S1FoldStats m_s1;        // S-1 fold counters (diagnostics)
    EbCut       m_last_cut;  // the cut the last win folded at (diagnostics)

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
