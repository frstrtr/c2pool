// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/block_event_driver.hpp   (Track A2 follow-on / PR-1 — the
//                                              shared BLOCK-EVENT DRIVER)
//
// BlockEventDriver — the piece main_v37_btc.cpp (master 89325e91) never had: a
// live sequencer that turns the three block events of a BTC-family node
//
//     FOUND      (a block-winning share)            → XbtcNode::on_block_won
//     FINALIZED  (D_conf burial, one height a step) → XbtcNode::on_tip
//     ORPHANED   (left the best chain)              → XbtcNode::on_block_orphaned
//
// into node calls in the right order, and — the point of it — makes the
// PENDING-FOUND set survive a restart (★ verify-round fix 3 / D10):
//
// THE MASTER DEFECT IT CLOSES. XbtcNode::open() (btc_node.hpp:104-126)
// constructs an EMPTY BtcFinalizeDriver. RecoveryDriver (btc_settle_store.hpp:
// 319-357) replays FOUND events into the OwedLedger's pending set, but
// SettleEvent::Found persists NO HEIGHT (:162-193) and the driver's
// m_found/m_by_height (btc_finalize_driver.hpp:222-223) are never rebuilt. A
// block found before a restart and not yet buried D_conf deep is therefore
// invisible afterwards: advance_to_tip() (:156-185) steps only m_by_height, so
// it is never FINALIZED and never ORPHANED, while its payout stays deducted
// from effective_owed() forever (w4_settlement.hpp:533-542) — the owed_digest
// of this node diverges from a node that stayed up. Runbook A8 would be a
// hollow pass without this.
//
// THE FIX, ADDITIVE ONLY (no SettleEvent schema change, RecoveryDriver untouched):
//   1. A write-ahead PENDING-FOUND SIDECAR in the same ISettleStore:
//        key   "v37s:pfound:<chain>:<bid>"     value  u8 ver=1 ‖ u64 height (LE)
//      written BEFORE the FOUND event (order: sidecar → FOUND event → announce),
//      removed when the bid leaves the pending set (FINALIZE step / ORPHAN /
//      reconcile). Crash windows are all benign:
//        sidecar ∧ ¬FOUND-event : ledger not pending at boot → sidecar dropped, logged
//        FOUND-event ∧ ¬sidecar : impossible with this order; a store written by a
//                                 pre-driver binary (pure master) shows it →
//                                 "UNRECOVERABLE PENDING" loud log, never silent.
//      credit/payout for the re-drive are read from the FOUND event itself (the
//      single source of truth — the same event-log prefix RecoveryDriver replays).
//   2. reseed_after_open(): after XbtcNode::open() re-enters every sidecar bid the
//      ledger still holds pending into the fresh BtcFinalizeDriver through ONE
//      consumer-tree seam, BtcFinalizeDriver::reseed_found(const FoundBlock&)
//      (consumer_tree_edits.patch, +12 lines in btc_finalize_driver.hpp): no
//      second FOUND event, no ledger mutation — the original event is already in
//      the log and OwedLedger::on_block_found is idempotent per bid
//      (w4_settlement.hpp:450-458) but the audit log must not carry duplicates.
//   3. ONE mutex serializes the stratum io_context thread (on_block_found) against
//      the height-watch (on_tip / recheck_pending) — XbtcNode is not thread-safe
//      (GAP-7); main no longer has to remember its own lock.
//
// D11 (poll-side reorg re-check): recheck_pending(probe) asks a TRI-STATE
// canonicality probe for every pending (bid, H_b) and disposes `No` at once via
// on_block_orphaned; `Unknown` waits (never a guess). main calls it when the tip
// lowered or the previous tip left the active chain. Pre-SETTLED only — a reorg
// deeper than D_conf after FINALIZE (O3.5 priced residual) is NOT driven here
// (seam S-9: ledger side, w4 territory, operator's hands).
//
// Coin-agnostic and header-only (STL + the btc/ consumer headers; no Boost, no
// coin lib): usable from the Threads-only leg and unit-testable with the
// MockCoinBackend + MemSettleStore. Nothing here is consensus code — it only
// SEQUENCES calls into the merged OwedLedger through XbtcNode/BtcFinalizeDriver
// (HARD SAFETY 1). No file under src/sharechain/v37 and no w4_settlement.hpp
// change is needed.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/btc/btc_node.hpp>             // XbtcNode, FoundBlock, FinalizeStep, CoinTip
#include <c2pool/v37/btc/btc_settle_store.hpp>     // ISettleStore, store_codec, SettleEvent

namespace c2pool::v37n::btc {

// Tri-state canonicality — the honest shape of "is `bid` still the best-chain
// block at `height`?" (the bool CanonicalFn of btc_finalize_driver.hpp:84
// cannot say Unknown; seam S-3 is the driver-side follow-on).
enum class Canon : std::uint8_t { Yes = 0, No = 1, Unknown = 2 };
using CanonProbeFn = std::function<Canon(std::uint64_t height, const std::string& bid)>;

namespace store_codec {
// The sidecar key: one record per pending FOUND, keyed by bid (idempotent put).
inline std::string k_pfound(::v37::ChainId c, const std::string& bid) {
    return "v37s:pfound:" + chain_fmt(c) + ":" + bid;
}
inline std::string k_pfound_prefix(::v37::ChainId c) { return "v37s:pfound:" + chain_fmt(c) + ":"; }
constexpr std::uint8_t PFOUND_VER = 1;
} // namespace store_codec

class BlockEventDriver {
public:
    struct RegisterResult {
        bool        registered = false;
        std::string reason;                // set when !registered
    };
    struct BootReport {
        std::size_t reseeded      = 0;     // pending FOUNDs re-driven into the finalize driver
        std::size_t stale_dropped = 0;     // sidecars whose bid the ledger no longer holds pending
        std::size_t unrecoverable = 0;     // ledger-pending bids WITHOUT a sidecar (pre-driver store)
    };

    // `store` is the SAME ISettleStore XbtcNode owns (main keeps a raw reference
    // before std::move-ing the unique_ptr into the node; lifetime == the node's).
    BlockEventDriver(XbtcNode& node, ISettleStore& store, ::v37::ChainId chain)
        : m_node(node), m_store(store), m_chain(chain) {}

    // ── boot: call AFTER XbtcNode::open() (the finalize driver exists) and
    //    BEFORE the stratum server / height-watch run. Throws std::runtime_error
    //    on a torn sidecar record (F2 posture: main maps it to the torn-store
    //    exit, never resumes from a truncated pending set).
    BootReport reseed_after_open() {
        std::lock_guard<std::mutex> g(m_mu);
        BootReport rep;

        // (1) every sidecar (bid -> H_b)
        std::map<std::string, std::uint64_t> sidecars;
        const std::string prefix = store_codec::k_pfound_prefix(m_chain);
        m_store.for_each_prefix(prefix, [&](const std::string& k, const std::string& v) {
            store_codec::Reader r(v);
            const std::uint8_t ver = r.u8();
            if (ver > store_codec::PFOUND_VER)
                throw std::runtime_error("settle-store: pfound record schema newer than reader");
            const std::uint64_t h = r.u64();
            r.expect_end();
            sidecars[k.substr(prefix.size())] = h;
            return true;
        });

        // (2) the FOUND events (credit/payout) + the log-derived pending set, read
        //     through the same prefix RecoveryDriver replays (btc_settle_store.hpp:337-351).
        struct FoundRec { Amounts credit, payout; };
        std::map<std::string, FoundRec> found;
        std::set<std::string> left;   // finalized or orphaned in the log
        m_store.for_each_prefix(store_codec::k_evt_prefix(m_chain),
            [&](const std::string&, const std::string& v) {
                SettleEvent e = SettleEvent::deserialize(v);
                switch (e.kind) {
                    case SettleEvKind::Found:    found[e.bid] = FoundRec{e.credit, e.payout}; break;
                    case SettleEvKind::Finalize: left.insert(e.bid); break;
                    case SettleEvKind::Orphan:   left.insert(e.bid); break;
                }
                return true;
            });

        // (3) re-drive: sidecar ∧ ledger-pending → reseed; sidecar ∧ ¬pending → stale.
        for (const auto& [bid, h] : sidecars) {
            if (!m_node.ledger().is_pending(bid)) {
                del_sidecar_locked(bid);
                ++rep.stale_dropped;
                std::fprintf(stderr, "[v37-bed] boot: dropped stale pending-FOUND sidecar %s (ledger not pending)\n", bid.c_str());
                continue;
            }
            FoundBlock fb;
            fb.bid = bid;
            fb.height = h;
            auto fit = found.find(bid);
            if (fit != found.end()) { fb.credit = fit->second.credit; fb.payout = fit->second.payout; }
            fb.canonical = true;
            if (!m_node.finalizer().reseed_found(fb)) {          // consumer-tree seam (patch)
                del_sidecar_locked(bid);
                ++rep.stale_dropped;
                continue;
            }
            m_pending[bid] = h;
            ++rep.reseeded;
            std::fprintf(stderr, "[v37-bed] boot: re-drove pending FOUND %s h=%llu\n", bid.c_str(),
                         static_cast<unsigned long long>(h));
        }

        // (4) the loud, never-silent case: pending in the ledger, no height on disk.
        for (const auto& [bid, rec] : found) {
            (void)rec;
            if (left.count(bid) || sidecars.count(bid)) continue;
            if (!m_node.ledger().is_pending(bid)) continue;
            ++rep.unrecoverable;
            std::fprintf(stderr, "[v37-bed] boot: UNRECOVERABLE PENDING %s — FOUND in the log without a "
                                 "pending-FOUND sidecar (store written by a pre-driver binary?); it will "
                                 "never be stepped at maturity: operator must re-register by hand\n",
                         bid.c_str());
        }
        return rep;
    }

    // ── FOUND: write-ahead the sidecar (H_b), then register with the node
    //    (XbtcNode::on_block_won writes the FOUND event, enters the ledger's
    //    pending set and the finalize driver's maps). `height` MUST be the
    //    block's OWN height H_b (D8) — never the template height, never 0.
    //    Idempotent per bid. Never throws (a throw from on_block_won — e.g. the
    //    coin backend's OracleUnavailable from the win-time canonicality probe,
    //    btc_node.hpp:185 — is reported, the sidecar is rolled back, and the
    //    caller may retry after the submit).
    RegisterResult on_block_found(const std::string& bid, std::uint64_t height,
                                  std::uint64_t confirmations) {
        std::lock_guard<std::mutex> g(m_mu);
        if (m_pending.count(bid)) return RegisterResult{true, ""};
        if (height == 0) return RegisterResult{false, "refusing H_b == 0 (unknown height is not a height)"};
        if (!put_sidecar_locked(bid, height))
            return RegisterResult{false, "pending-FOUND sidecar write failed (store commit)"};
        try {
            (void)m_node.on_block_won(bid, height, confirmations);   // FOUND event + pending + driver maps
        } catch (const std::exception& e) {
            del_sidecar_locked(bid);
            return RegisterResult{false, std::string("on_block_won threw before registering: ") + e.what()};
        }
        if (!m_node.ledger().is_pending(bid)) {
            del_sidecar_locked(bid);
            return RegisterResult{false, "ledger did not admit the FOUND (bid already SETTLED?)"};
        }
        m_pending[bid] = height;
        return RegisterResult{true, ""};
    }

    // ── FINALIZED: the F1 tick. Delegates to XbtcNode::on_tip (one height a
    //    step, never jumps to tip) and retires the sidecar of every finalized
    //    bid. A bid the driver orphaned AT MATURITY inside advance_to_tip
    //    (btc_finalize_driver.hpp:165-168) is not in `steps`; reconcile() catches
    //    it (the ledger no longer holds it pending). Propagates the backend's
    //    OracleUnavailable after reconciling — the finalize driver is
    //    write-ahead-per-bid, so what it persisted before the throw is durable
    //    and the sidecars of those bids are retired here or at the next boot.
    std::vector<FinalizeStep> on_tip(const CoinTip& tip) {
        std::lock_guard<std::mutex> g(m_mu);
        std::vector<FinalizeStep> steps;
        try {
            steps = m_node.on_tip(tip);
        } catch (...) {
            reconcile_locked();
            throw;
        }
        for (const auto& s : steps) on_block_finalized_locked(s);
        reconcile_locked();
        return steps;
    }

    // ── ORPHANED: dispose via the node (O3.5 through the finalize driver) and
    //    retire the sidecar.
    void on_block_orphaned(const std::string& bid) {
        std::lock_guard<std::mutex> g(m_mu);
        m_node.on_block_orphaned(bid);
        m_pending.erase(bid);
        del_sidecar_locked(bid);
    }

    // ── D11: re-check every pending FOUND against a tri-state probe. `No` is
    //    disposed at once; `Yes`/`Unknown` wait for maturity (never a guess).
    //    Returns the number orphaned.
    std::size_t recheck_pending(const CanonProbeFn& probe) {
        std::lock_guard<std::mutex> g(m_mu);
        std::size_t orphaned = 0;
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            if (probe(it->second, it->first) == Canon::No) {
                m_node.on_block_orphaned(it->first);
                del_sidecar_locked(it->first);
                it = m_pending.erase(it);
                ++orphaned;
            } else {
                ++it;
            }
        }
        return orphaned;
    }

    // ── read seams ───────────────────────────────────────────────────────────
    std::map<std::string, std::uint64_t> pending() const {   // bid -> H_b (snapshot)
        std::lock_guard<std::mutex> g(m_mu);
        return m_pending;
    }
    std::size_t pending_count() const {
        std::lock_guard<std::mutex> g(m_mu);
        return m_pending.size();
    }
    // Same read, but the CALLER already holds mutex() (m_mu is non-recursive):
    // used by main's boot/stop observability blocks, which hold the lock across
    // the whole scope. Calling the locking pending_count() there self-deadlocks.
    std::size_t pending_count_locked() const { return m_pending.size(); }
    // The one lock. main takes it around XbtcNode::stop() and the boot/stop
    // observability reads so no second caller can forget GAP-7.
    std::mutex& mutex() const { return m_mu; }

private:
    bool put_sidecar_locked(const std::string& bid, std::uint64_t h) {
        std::string v;
        v.push_back(static_cast<char>(store_codec::PFOUND_VER));
        store_codec::put_u64(v, h);
        auto b = m_store.batch();
        b->put(store_codec::k_pfound(m_chain, bid), v);
        return b->commit_sync();
    }
    void del_sidecar_locked(const std::string& bid) {
        auto b = m_store.batch();
        b->remove(store_codec::k_pfound(m_chain, bid));
        (void)b->commit_sync();   // a failed delete leaves a stale sidecar → dropped at the next boot
    }
    void on_block_finalized_locked(const FinalizeStep& s) {
        m_pending.erase(s.bid);
        del_sidecar_locked(s.bid);   // AFTER the FINALIZE event (already durable, write-ahead)
    }
    // Any pending bid the ledger no longer holds (orphaned at maturity inside
    // advance_to_tip, or finalized in a tick that threw before returning its
    // steps) is retired here.
    void reconcile_locked() {
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            if (!m_node.ledger().is_pending(it->first)) {
                del_sidecar_locked(it->first);
                it = m_pending.erase(it);
            } else {
                ++it;
            }
        }
    }

    XbtcNode&      m_node;
    ISettleStore&  m_store;
    ::v37::ChainId m_chain;
    mutable std::mutex m_mu;
    std::map<std::string, std::uint64_t> m_pending;   // bid -> H_b, mirrors the sidecars
};

} // namespace c2pool::v37n::btc
