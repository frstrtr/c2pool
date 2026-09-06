// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
#pragma once
// ===========================================================================
// settle_finalize_driver.hpp  —  the F1-CORRECT production settlement finalize
// driver.  ONE COIN-AGNOSTIC DRIVER (Milestone A live-node lifecycle).
//
// COIN-AGNOSTIC — THIS IS THE SAME DRIVER AS A-XMR
// ------------------------------------------------
// This is byte-for-byte the same logic as the A-XMR lane's
// xmr_finalize_driver.hpp; the only differences are this file's name and its
// comments (which speak of "the coin adapter's height" instead of "monerod").
// The driver touches NOTHING coin-specific: it is a pure sequencer over the
// merged w4 types (OwedLedger + SettleHW), driven by a monotone coin-height
// integer that the caller feeds from whatever mainchain view it owns —
//   * BTC family: the v36 coin daemon adapter (DASH devnet/regtest embedded-SPV
//     or daemon; LTC testnet4) best-height (SHA-256d / Scrypt PoW),
//   * XMR family: the monerod ZMQ tip height (RandomX PoW).
// Neither PoW, coinbase shape, nor ScriptKind enters here. There should be ONE
// such file in-tree; the A-XMR xmr_finalize_driver.hpp should become an include
// alias of (or be replaced by) this coin-neutral header. Kept as a distinct
// file here only because this build leg writes to a scratch directory.
//
// WHY THIS FILE EXISTS (the F1 audit's HIGH obligation)
// -----------------------------------------------------
// OwedLedger::on_block_finalized(bid, bin_height) (w4_settlement.hpp) stamps
// first_eligible for every key whose EffectiveOwed just went positive AT
// bin_height (rearm_first_eligible), and owed_digest() COMMITS first_eligible
// per finalized key. Therefore the value passed as bin_height is CONSENSUS: two
// nodes that finalize the same block at a different bin_height compute a
// DIFFERENT owed_digest — an owed_digest FORK.
//
// The correct bin_height is "the coin high-water AT THE HEIGHT STEP where the
// block first becomes buried >= D_conf", i.e. found_height + D_conf. A node that
// was behind (or received a burst of heights from the coin adapter in one
// Extend that jumps best_height by >1) MUST replay the settlement path PER
// COIN-HEIGHT STEP IN ORDER and stamp each block at its own step's high-water.
// It must NEVER jump straight to the live coin tip and finalize every buried
// block at the tip height — that stamps a LATE first_eligible and is the exact
// F1 fork.
//
// The w4 test harness's reconcile()-at-current-tip shape is a TEST convenience
// (it drives finalize at one height because the test constructs one height); it
// is NOT the live-driver contract. This driver is the live contract: per-height,
// in-order, high-water-at-the-step. Do NOT copy reconcile() into a live caller.
//
// SAFETY / DIGEST-NEUTRALITY
// --------------------------
// This driver is a pure CALLER of the merged w4 API (OwedLedger + SettleHW). It
// redefines NO consensus quantity: not owed_digest, not first_eligible, not the
// K_fair clock. It only sequences the existing on_block_finalized / on_tip /
// on_block_orphaned calls so the argument they already consume (bin_height) is
// the spec-correct value on every path (real-time, catch-up, burst, restart).
//
// stdlib-only + header-only: builds on an OOM-pressured host and is exercised by
// f1_finalize_kat_btc.cpp against the real merged w4 types with no engine link.
// ===========================================================================

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>   // OwedLedger, SettleHW (merged w4 types)

namespace c2pool::v37n::settle {

// A pool-found block awaiting its finalize gate. Recorded at FOUND time with the
// per-key entitlement E_b (credit) and the coinbase outputs it broadcast
// (payout) — the exact two maps OwedLedger::on_block_found already consumes.
struct FinalizeCandidate {
    std::string          bid;            // block id (ledger key)
    std::uint64_t        found_height{}; // coin height at which the pool found it
    OwedLedger::Amounts  credit;         // E_b at the burial-gated prefix
    OwedLedger::Amounts  payout;         // coinbase outputs broadcast in the block
};

// ===========================================================================
// FinalizeDriver — sequences OwedLedger + SettleHW off the coin adapter's
// height progression, honoring the F1 contract on every path.
//
// USAGE (live daemon): construct with (ledger, hw, chain, D_conf). On each pool
// block found, call register_found(). On the coin adapter's height progression
// (Extend/Reorg events off the DASH/LTC mainchain view), call
// advance_to(new_best_height, tip): the driver replays every unseen height in
// order, advancing the O5.5 high-water and finalizing exactly the candidates
// that reach D_conf at each step, stamping bin_height = that step's high-water.
// On an Orphan event, call on_orphaned().
// ===========================================================================
class FinalizeDriver {
public:
    // tip_of_height(h) -> the 32-byte coin block id at height h (for SettleHW's
    // hw_tip leg). In the live daemon this reads the coin adapter's
    // by_height(h) (DASH/LTC block hash); in KATs it is a deterministic stub.
    // May return {} if unknown.
    using TipOfHeight = std::function<::v37::bytes32(std::uint64_t)>;

    // is_canonical(bid) -> is this found block still on the best chain? Guards
    // finalize against a block that was orphaned between FOUND and its gate. In
    // the live daemon this consults the coin adapter's mainchain view; default
    // = always true.
    using IsCanonical = std::function<bool(const std::string& bid)>;

    FinalizeDriver(OwedLedger& ledger, SettleHW& hw, ::v37::ChainId chain,
                   std::uint64_t d_conf)
        : m_ledger(ledger), m_hw(hw), m_chain(chain), m_dconf(d_conf) {}

    void set_tip_of_height(TipOfHeight f) { m_tip_of = std::move(f); }
    void set_is_canonical(IsCanonical f) { m_is_canonical = std::move(f); }

    // Restart bring-up: adopt the persisted O5.5 high-water as the last-driven
    // height so a restarted node does not re-drive (and re-stamp) settled heights.
    // Call AFTER the W6 RecoveryDriver has rehydrated the OwedLedger + SettleHW.
    void resume_from_persisted() { m_last_driven = m_hw.hw_height; }

    ::v37::ChainId chain() const { return m_chain; }
    std::uint64_t d_conf() const { return m_dconf; }
    std::uint64_t last_driven_height() const { return m_last_driven; }

    // FOUND(b). Records the candidate and credits the ledger (idempotent per bid
    // via OwedLedger::on_block_found). finalize_height = found_height + D_conf is
    // the coin height at which b first becomes buried >= D_conf.
    void register_found(const FinalizeCandidate& c) {
        m_ledger.on_block_found(c.bid, c.credit, c.payout);
        const std::uint64_t fin_h = c.found_height + m_dconf;
        m_by_finalize_height[fin_h].push_back(c.bid);      // sorted map → in-order
        m_found_height[c.bid] = c.found_height;
    }

    // The height progression. Advance the driver to `new_best_height` (the coin
    // adapter's best tip), replaying EVERY height step from
    // last_driven+1 .. new_best_height IN ORDER. This is the F1 core:
    //   * a single Extend that jumps best_height by many blocks (a coin adapter
    //     catch-up burst) is replayed per-height here — never collapsed to one
    //     finalize at the tip;
    //   * each step advances the O5.5 high-water (SettleHW) then finalizes the
    //     candidates whose gate lands on THAT step, stamping bin_height = that
    //     step's high-water (== the step height), NOT new_best_height.
    // Returns the number of blocks finalized across the replay (diagnostic).
    std::size_t advance_to(std::uint64_t new_best_height) {
        std::size_t finalized = 0;
        // O5.5 gate: a target strictly below the persisted high-water is a
        // shorter branch — not adopted, settlement never re-evaluated lower.
        if (!m_hw.admit_candidate_height(new_best_height)) return 0;
        for (std::uint64_t h = m_last_driven + 1; h <= new_best_height; ++h)
            finalized += drive_one_height(h);
        m_last_driven = new_best_height;
        return finalized;
    }

    // ORPHAN(b): a pool-found block left the best chain. Forward to the ledger
    // (pre-SETTLED → pending keys removed and re-mint from the spine; post-SETTLED
    // → O3.5 priced residual). The O5.5 high-water is NEVER lowered here.
    void on_orphaned(const std::string& bid,
                     const OwedLedger::Amounts& settled_payout) {
        m_ledger.on_block_orphaned(bid, settled_payout);
        // If it was still awaiting its gate, forget the pending candidate so a
        // later replay does not attempt to finalize a dead block.
        m_orphaned.insert(bid);
    }

private:
    // Drive exactly one coin-height step h, in order. NEVER called with a batch.
    std::size_t drive_one_height(std::uint64_t h) {
        // (1) on_tip_advanced(chain, h, tip): move the O5.5 high-water to h.
        //     admit_candidate_height already re-checked by advance_to's loop
        //     invariant (h strictly increases and h > previous high-water on the
        //     forward path); advance() itself refuses a decrease defensively.
        ::v37::bytes32 tip = m_tip_of ? m_tip_of(h) : ::v37::bytes32{};
        m_hw.advance(h, tip);                      // high-water AT this step := h

        // (2) finalize every candidate whose gate (found_height + D_conf) is at
        //     or below this step and is still pending — stamping bin_height =
        //     m_hw.hw_height, which is EXACTLY h (this step's high-water), the
        //     spec-correct value. Because advance_to replays per-height, a gate
        //     is reached at its own height, so hw.hw_height == finalize_height.
        std::size_t n = 0;
        auto it = m_by_finalize_height.begin();
        while (it != m_by_finalize_height.end() && it->first <= h) {
            std::vector<std::string> bids = it->second;
            std::sort(bids.begin(), bids.end());   // deterministic intra-step order
            for (const auto& bid : bids) {
                if (m_orphaned.count(bid)) continue;
                if (m_is_canonical && !m_is_canonical(bid)) continue;
                if (!m_ledger.is_pending(bid)) continue;
                // bin_height := this step's coin high-water. On the forward
                // per-height path hw.hw_height == h == it->first (the gate). We
                // pass hw.hw_height (the honest high-water read) rather than the
                // live tip — that difference IS the F1 fix.
                m_ledger.on_block_finalized(bid, m_hw.hw_height);
                ++n;
            }
            it = m_by_finalize_height.erase(it);
        }
        return n;
    }

    OwedLedger&    m_ledger;
    SettleHW&      m_hw;
    ::v37::ChainId m_chain;
    std::uint64_t  m_dconf;
    std::uint64_t  m_last_driven = 0;

    // finalize_height -> bids gated at that height (std::map keeps height order).
    std::map<std::uint64_t, std::vector<std::string>> m_by_finalize_height;
    std::map<std::string, std::uint64_t>              m_found_height;
    std::set<std::string>                             m_orphaned;

    TipOfHeight m_tip_of;
    IsCanonical m_is_canonical;
};

}  // namespace c2pool::v37n::settle
