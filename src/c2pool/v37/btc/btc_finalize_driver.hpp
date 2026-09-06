// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/btc_finalize_driver.hpp  (Track A2 / Milestone A-BTC — F1)
//
// THE PRODUCTION SETTLEMENT FINALIZE DRIVER for the BITCOIN FAMILY — the piece
// the F1 audit found had no live caller (OwedLedger::on_block_finalized was only
// ever reached by the w4 test harness's reconcile()). This is the live driver,
// written to the F1 CONTRACT verbatim:
//
//   on_block_finalized() is called ONCE PER COIN-HEIGHT STEP, IN ORDER, with
//   bin_height = the best-chain HIGH-WATER AT THAT STEP — NEVER the live coin
//   daemon tip. The stepping is driven off the coin adapter's mainchain height
//   progression (dash::coin::chain_rpc / HeaderChain for DASH, the daemon RPC
//   tip for LTC testnet4), one height at a time.
//
// COIN-AGNOSTIC BY CONSTRUCTION: this is BYTE-FOR-BYTE the same sequencing logic
// as src/c2pool/v37/xmr/xmr_finalize_driver.hpp (Milestone A-XMR). The only
// inputs are `bid` (a block-id string — a BTC-family block HASH hex here, a
// Monero block id there), `height`, credit/payout Amounts, a ChainId, d_conf,
// an ISettleStore and a caller-supplied canonicality predicate. It does NOT
// name a coin. The XMR and BTC nodes feed it from different backends; the driver
// is identical. (The two files could be one v37/finalize_driver.hpp; kept
// parallel to let each milestone land independently.)
//
// WHY THIS SHAPE (the bug it avoids): OwedLedger::rearm_first_eligible(bin_height)
// stamps first_eligible (the K_fair age clock) for every newly-owed key at
// `bin_height`. If a node that has fallen behind finalized a backlog of matured
// blocks all at the LIVE TIP height (the reconcile() shape), every key those
// blocks newly owe would be stamped with a single, far-future age — over-aging
// them relative to a node that stayed in sync, so the two nodes would compute
// DIFFERENT K_fair orderings and DIFFERENT coinbases: a consensus split. The
// contract removes that: a block mined at coin height H_b finalizes with
// bin_height = H_b + D_conf (the high-water at the moment H_b became buried
// D_conf deep), replayed in strict ascending order regardless of how far ahead
// the live tip has run. Deterministic in the coin height progression alone.
//
// SCOPE: single lane (one BTC-family parent). Header-only, STL-only,
// unit-testable with no coin adapter/engine (canonicality is a caller-supplied
// predicate; the smoke feeds a scripted MockCoinBackend). Consensus-DIGEST-
// NEUTRAL: it only SEQUENCES calls into the merged OwedLedger.
// ===========================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>          // OwedLedger, SettleHW (merged)
#include <c2pool/v37/btc/btc_settle_store.hpp>   // ISettleStore, SettleEvent, codec

namespace c2pool::v37n::btc {

// A settlement-carrying block WE found and broadcast, awaiting D_conf burial.
struct FoundBlock {
    std::string   bid;          // BTC-family block hash (hex) — the OwedLedger key
    std::uint64_t height = 0;   // the coin height it was mined at
    Amounts       credit;       // per-key entitlement E_b at b's burial-gated prefix
    Amounts       payout;       // the coinbase outputs broadcast in b (K_fair)
    bool          canonical = true;
};

// Result of one advance, for the smoke/KAT to assert the F1 discipline.
struct FinalizeStep {
    std::string   bid;
    std::uint64_t coin_height = 0;   // H_b, the height the block was mined at
    std::uint64_t bin_height  = 0;   // the high-water at the finalize step (== H_b + D_conf)
};

class BtcFinalizeDriver {
public:
    // `is_canonical(height, bid)` returns true iff the best chain still carries
    // block `bid` at `height`. For DASH this is answered from the embedded-SPV
    // HeaderChain (dash::coin::chain_rpc getblockhash <h> == bid); for LTC from
    // the daemon getblockhash RPC. The MockCoinBackend answers it from its
    // scripted chain (reorg-injectable).
    using CanonicalFn = std::function<bool(std::uint64_t height, const std::string& bid)>;

    BtcFinalizeDriver(OwedLedger& ledger, SettleHW& hw, ISettleStore& store,
                      ::v37::ChainId chain, std::uint64_t d_conf,
                      std::uint64_t recovered_cursor_height,
                      std::uint64_t recovered_event_seq, CanonicalFn is_canonical)
        : m_ledger(ledger), m_hw(hw), m_store(store), m_chain(chain),
          m_d_conf(d_conf), m_cursor_h(recovered_cursor_height),
          m_seq(recovered_event_seq), m_is_canonical(std::move(is_canonical)) {}

    // Register a settlement-carrying block we just found. Write-ahead the FOUND
    // event (durable BEFORE the block is announced, W6 §5.2), enter the merged
    // ledger's pending set, and remember it for maturity. Idempotent per bid.
    void on_block_found(const FoundBlock& b) {
        if (m_found.count(b.bid)) return;
        SettleEvent ev;
        ev.kind = SettleEvKind::Found;
        ev.bid = b.bid;
        ev.credit = b.credit;
        ev.payout = b.payout;
        write_event(ev);
        m_ledger.on_block_found(b.bid, b.credit, b.payout);
        m_found.emplace(b.bid, b);
        m_by_height[b.height].push_back(b.bid);
    }

    // A block left the best chain (an Orphan / a Reorg that dropped it). Dispose
    // per the merged ledger's O3.5 rule (pre-SETTLED: pure removal; post-SETTLED:
    // priced residual). Write-ahead the ORPHAN event.
    void on_block_orphaned(const std::string& bid) {
        auto it = m_found.find(bid);
        Amounts payout = (it != m_found.end()) ? it->second.payout : Amounts{};
        SettleEvent ev;
        ev.kind = SettleEvKind::Orphan;
        ev.bid = bid;
        ev.payout = payout;
        write_event(ev);
        m_ledger.on_block_orphaned(bid, payout);
        if (it != m_found.end()) it->second.canonical = false;
    }

    // ── THE F1 DRIVER ──────────────────────────────────────────────────────
    // Advance settlement to reflect that the best chain now stands at
    // (best_height, best_id). Steps the finalize cursor ONE coin-height at a
    // time from cursor+1 up to the newly-buried frontier (best_height - D_conf),
    // finalizing each matured found block IN ORDER with the per-step high-water.
    // Returns the steps taken (for assertions); empty when nothing matured.
    //
    // O5.5: a candidate best_height BELOW the persisted high-water is REFUSED
    // (settlement is never advanced or re-evaluated against a lower height); the
    // driver returns empty without touching the ledger. A reorg that LOWERS the
    // tip is handled by on_block_orphaned on the dropped blocks, not here.
    std::vector<FinalizeStep> advance_to_tip(std::uint64_t best_height,
                                             const ::v37::bytes32& best_id) {
        std::vector<FinalizeStep> steps;

        // O5.5 gate (MD-3 ruling A): refuse a shorter candidate outright.
        if (!m_hw.admit_candidate_height(best_height)) {
            persist_hw();                        // record the refusal count
            return steps;
        }
        m_hw.advance(best_height, best_id);      // monotone high-water

        // Newly-buried frontier. Guard unsigned underflow when the chain is
        // shallower than D_conf (early regtest/devnet).
        const std::uint64_t frontier =
            (best_height >= m_d_conf) ? best_height - m_d_conf : 0;

        // Step per coin-height, IN ORDER. For each height h that just crossed
        // the D_conf burial threshold, the high-water at that step is h + D_conf
        // (NOT best_height): that is the value the K_fair clock must see, so a
        // node catching up replays the SAME per-height clock a synced node saw.
        for (std::uint64_t h = m_cursor_h + 1; h <= frontier; ++h) {
            const std::uint64_t bin_height = h + m_d_conf;   // high-water at this step

            auto bit = m_by_height.find(h);
            if (bit != m_by_height.end()) {
                for (const std::string& bid : bit->second) {
                    auto fit = m_found.find(bid);
                    if (fit == m_found.end()) continue;
                    if (!fit->second.canonical) continue;             // already orphaned
                    if (m_is_canonical && !m_is_canonical(h, bid)) {  // orphaned at maturity
                        on_block_orphaned(bid);
                        continue;
                    }
                    if (!m_ledger.is_pending(bid)) continue;          // idempotent / already settled

                    // FINALIZE — write-ahead THEN mutate the ledger (crash-safe
                    // ordering), with the per-step bin_height. This is the sole
                    // live caller of OwedLedger::on_block_finalized.
                    SettleEvent ev;
                    ev.kind = SettleEvKind::Finalize;
                    ev.bid = bid;
                    ev.bin_height = bin_height;
                    write_event(ev);
                    m_ledger.on_block_finalized(bid, bin_height);
                    steps.push_back(FinalizeStep{bid, h, bin_height});
                }
            }
            m_cursor_h = h;
            persist_cursor();
        }
        persist_hw();
        return steps;
    }

    std::uint64_t cursor_height() const { return m_cursor_h; }
    std::uint64_t event_seq()     const { return m_seq; }

private:
    void write_event(const SettleEvent& ev) {
        auto b = m_store.batch();
        b->put(store_codec::k_evt(m_chain, ++m_seq), ev.serialize());
        b->commit_sync();
    }
    void persist_cursor() {
        std::string v;
        store_codec::put_u64(v, m_cursor_h);
        auto b = m_store.batch();
        b->put(store_codec::k_cursor(m_chain), v);
        b->commit_sync();
    }
    void persist_hw() {
        m_hw.ledger_seq = m_ledger.ledger_seq();
        auto b = m_store.batch();
        b->put(store_codec::k_hw(m_chain), m_hw.serialize());
        b->commit_sync();
    }

    OwedLedger&    m_ledger;
    SettleHW&      m_hw;
    ISettleStore&  m_store;
    ::v37::ChainId m_chain;
    std::uint64_t  m_d_conf;
    std::uint64_t  m_cursor_h;   // highest coin height already processed for burial
    std::uint64_t  m_seq;        // write-ahead event sequence
    CanonicalFn    m_is_canonical;

    std::map<std::string, FoundBlock>                 m_found;      // bid -> block
    std::map<std::uint64_t, std::vector<std::string>> m_by_height;  // mined height -> bids
};

} // namespace c2pool::v37n::btc
