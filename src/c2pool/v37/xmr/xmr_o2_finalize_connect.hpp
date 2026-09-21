// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_o2_finalize_connect.hpp   (X9 / O-2 wire 4 —
//                                                    FINALIZE CONNECT)
//
// FinalizeConnect — the MAIN-THREAD glue that routes an XMR network-block WIN
// (the stratum share sink's submit_block "OK", produced on the listener thread)
// into the F1 finalize driver through the ONE existing seam,
//
//     XmrNode::on_network_block_won(height, block_id, credit, payout)
//                                                     (xmr_node.hpp:182-199)
//
// so that FOUND -> FINALIZE runs at D_conf burial off the adapter's
// Extend/Reorg/Orphan stream (xmr_node.hpp:228-249 -> XmrFinalizeDriver::
// advance_to_tip, xmr_finalize_driver.hpp:121-191). Nothing here touches the
// driver, the ledger or the store directly: it only SEQUENCES calls into the
// node (HARD SAFETY 1 — no consensus digest is defined or altered).
//
// WHAT IT ADDS ON TOP OF THE BARE HOOK
//   (1) FoundBlockQueue — the single cross-thread object of the O-2 assembly
//       for this wire: the listener thread pushes a FoundBlockEvent (height,
//       monerod's block_id, reward, payee key, worker/address) right after
//       submit_block returned "OK"; the main loop drains it in tick().
//       Replaces the WIP FoundEvent/FoundQueue (xmr_o2_serve.hpp:338-358),
//       which carried only a height.
//   (2) Amount-honest credit/payout for the option-A (monerod-template) block:
//       credit == payout == { identity_key(payout XMR_STD ref) : reward }, so
//       finalW nets to 0 at FINALIZE and the FOUND/FINALIZE audit trail carries
//       the real amount. Without a payee key the degenerate {}/{} record is
//       used (the ledger still bumps; the block is recorded as valueless).
//   (3) The LATE-FOUND guard: XmrFinalizeDriver::advance_to_tip steps only
//       heights ABOVE its cursor (:155). A FOUND registered at a height the
//       cursor already passed would sit pending FOREVER (its payout deducted
//       from effective_owed for good). Such a win is REFUSED, loudly, instead
//       of being poisoned into the ledger.
//   (4) O-3 observability: XmrNode logs "win:" / "finalize: ... SETTLED at
//       bin_height=" only into construction_log(), which main prints ONCE
//       after bring_up. tick() echoes every new line to stdout and prints
//       burial progress (h + D_conf - hw) for each pending FOUND.
//   (5) A pending-FOUND SIDECAR (optional, one small text file next to
//       settle.img) so a restart inside the D_conf window does not lose the
//       pending FOUND — the same D10 defect the BTC side closed with
//       block_event_driver.hpp:35-52. RecoveryDriver replays FOUND events into
//       the OwedLedger but NOT into XmrFinalizeDriver::m_found/m_by_height
//       (SettleEvent::Found carries no height), so without this the block is
//       never finalized after a restart. The re-drive goes through the same
//       on_network_block_won seam (no XmrFinalizeDriver::reseed_found seam
//       exists yet): OwedLedger::on_block_found is idempotent per bid
//       (w4_settlement.hpp:452), so the ledger and ledger_seq are untouched;
//       ONE duplicate FOUND event lands in the write-ahead log. That duplicate
//       is harmless on replay — it always precedes the bid's terminal
//       FINALIZE/ORPHAN event, and the ledger ignores a FOUND for a bid it
//       already holds pending. When the reseed_found seam lands (follow-on,
//       consumer-tree edit), swap re_drive() to it and the duplicate goes away.
//
// KNOWN O-2 ORDERING DEVIATION (stated, not hidden): W6 §5.2 wants FOUND
// durable BEFORE the block is announced. Under option A the announce IS
// monerod's submit_block on the listener thread; the FOUND becomes durable on
// the main thread's next tick. The crash window is [submit OK, next tick].
// A block lost in that window still pays its payee on-chain (the template
// coinbase pays the wallet directly) — only the v37 ledger record is missing.
//
// THREADING: FoundBlockQueue is thread-safe (one mutex). EVERYTHING ELSE in
// this header is main-thread only — XmrNode, MonerodAdapter/MainchainIndex,
// XmrFinalizeDriver and OwedLedger are single-threaded (no locks).
//
// Header-only, STL + POSIX file I/O (for the fsync'd sidecar). Includes only
// consumer-tree headers already pulled in by main_v37_xmr.cpp.
// ===========================================================================
#pragma once

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_descriptor_xmr.hpp>   // make_xmr_std/make_xmr_sub, xmr_identity_key, xmr_ref_valid
#include <sharechain/v37/v37_hash.hpp>             // ::v37::bytes32

#include "impl/xmr/node/xmr_node_types.hpp"        // c2pool::xmr::node::Hash
#include "xmr_node.hpp"                            // XmrNode, hex_of, Amounts (via xmr_settle_store.hpp)
#include "xmr_node_config.hpp"                     // XmrNodeConfig, MoneroNetwork
#include "xmr_same_height_race.hpp"                // SameHeightRaceLedger (c2pool#1551)

namespace c2pool::v37n::xmr::o2 {

// ── hex helpers (the inverse of hex_of, xmr_node.hpp:64) ────────────────────
inline int fc_hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 64 hex chars (either case) -> 32 bytes. Works for c2pool::xmr::node::Hash and
// ::v37::bytes32 alike (both are std::array<std::uint8_t, 32>).
inline bool hash_from_hex(std::string_view hex, std::array<std::uint8_t, 32>& out) noexcept {
    if (hex.size() != 64) return false;
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = fc_hex_nibble(hex[2 * i]);
        const int lo = fc_hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

inline std::string lower_hex(std::string_view s) {
    std::string o(s);
    for (char& c : o) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    return o;
}

// ── payee identity: the address boundary's OUTPUT, never an address string ──
// The stratum listener (wire 1) decodes the miner's login address into raw
// keys; this turns them into the ledger key the FOUND/FINALIZE record is
// keyed by (sharechain/v37/v37_descriptor_xmr.hpp make_xmr_std :243 /
// make_xmr_sub :252 / identity_key :289-302). Returns nullopt when the ref does
// not validate under the installed ed25519 point-check backend — a key that
// xmr_ref_valid() rejects must never become a ledger key (fail-closed).
struct PayeeKeys {
    std::array<std::uint8_t, 32> spend{};   // B (XMR_STD) or D_i (XMR_SUB)
    std::array<std::uint8_t, 32> view{};    // A (main view key)
    bool subaddress = false;                // false = XMR_STD, true = XMR_SUB
};

inline std::optional<::v37::bytes32> payee_identity_key(const PayeeKeys& k) {
    ::v37::ScriptRef ref = k.subaddress ? ::v37::xmr::make_xmr_sub(k.spend, k.view)
                                        : ::v37::xmr::make_xmr_std(k.spend, k.view);
    if (!::v37::xmr::xmr_ref_valid(ref)) return std::nullopt;
    return ::v37::xmr::xmr_identity_key(ref);
}

// ── the FOUND record crossing listener thread -> main thread ────────────────
struct FoundBlockEvent {
    std::uint64_t height = 0;             // H_b — the block's OWN height (template height); never 0
    std::string   block_id_hex;           // monerod's block hash (submit_block result.block_id),
                                          // 64 hex — REQUIRED: is_canonical (xmr_node.hpp:146-149)
                                          // compares hex_of(index.by_height(H).id) == bid
    std::string   prev_id_hex;            // template prev_hash (informational; cross-check only)
    std::uint64_t reward_piconero = 0;    // get_block_template.expected_reward (or chain_main.reward)
    std::optional<::v37::bytes32> payee;  // identity_key of the payout descriptor (payee_identity_key)
    std::uint32_t template_id = 0;        // stratum bookkeeping (logged only)
    std::uint32_t nonce = 0;
    std::uint32_t extra_nonce = 0;
    std::string   worker;                 // from the login string (logged only)
    std::string   address;                // raw base58 (logged only — never a ledger key)
    std::uint64_t found_unix_s = 0;       // 0 = stamp at push()
};

class FoundBlockQueue {
public:
    // Listener thread. Never blocks on anything but the mutex.
    void push(FoundBlockEvent e) {
        if (e.found_unix_s == 0)
            e.found_unix_s = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
        std::lock_guard<std::mutex> lk(m_mtx);
        m_q.push_back(std::move(e));
        ++m_pushed;
    }
    // Main thread. Appends everything queued so far to `out`; returns the count.
    std::size_t drain(std::vector<FoundBlockEvent>& out) {
        std::lock_guard<std::mutex> lk(m_mtx);
        const std::size_t n = m_q.size();
        for (auto& e : m_q) out.push_back(std::move(e));
        m_q.clear();
        return n;
    }
    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_q.size();
    }
    std::uint64_t pushed_total() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_pushed;
    }
private:
    mutable std::mutex          m_mtx;
    std::deque<FoundBlockEvent> m_q;
    std::uint64_t               m_pushed = 0;
};

// ── options ─────────────────────────────────────────────────────────────────
struct FinalizeConnectOptions {
    // Pending-FOUND sidecar file. Empty = disabled (restart inside the D_conf
    // window then loses the pending FOUND — the D10 defect). Recommended:
    //   cfg.resolved_settle_db_path() + "/pfound.tsv"   (next to settle.img)
    std::string sidecar_path;
    bool        echo_node_log = true;   // print construction_log() deltas each tick (O-3)
    bool        progress      = true;   // print burial progress whenever hw advances
    std::FILE*  out           = stdout; // nullptr = silent (the self-check uses this)
    std::string tag           = "[v37-xmr-fc]";

    // ── c2pool#1551 ────────────────────────────────────────────────────────
    // Per-height verdict journal, appended on every verdict TRANSITION. Empty =
    // no journal. Two nodes that watched the same race must agree on every
    // height either of them credited; this file is what makes that a diff.
    std::string race_journal_path;

    // Lever (2): re-announce our nominated block on a contested, unburied
    // height. Bounded by SameHeightPolicy::max_renotify. Unset = no re-announce
    // (the observe-side posture, and what the self-check runs).
    std::function<bool(std::uint64_t height, const std::string& bid_hex)> renotify;
    //  COINBASE AUTHORITY: (height, bid) -> credit/payout read from the block's on-chain
    // coinbase. false + why. why starting with "not-lane:" = a stranger's block (ignored).
    std::function<bool(std::uint64_t, const std::string&, Amounts&, Amounts&, std::string&)> book_from_chain;
    // recon(A+B credit): our OWN win was submitted OK and its booking deferred to the
    // chain — the moment the S-1c v0x02 cut descriptor (the FAST PATH) leaves.
    // (template_id, extra_nonce) name the candidate we SUBMITTED, so the recompute
    // cross-check can fetch our own assembled bytes back off the provider ring.
    std::function<void(std::uint64_t height, const std::string& bid_hex,
                       std::uint32_t template_id, std::uint32_t extra_nonce)> on_own_win_deferred;
};

// ── the glue ────────────────────────────────────────────────────────────────
class FinalizeConnect {
public:
    struct PendingRec {
        std::uint64_t height = 0;
        std::optional<::v37::bytes32> payee;
        std::uint64_t reward = 0;
        std::string   prev_id_hex;
        std::uint64_t found_unix_s = 0;
    };
    struct RegisterResult {
        bool        registered = false;
        bool        duplicate  = false;   // already pending here (idempotent)
        std::string reason;               // set when !registered
    };
    struct BootReport {
        bool        sidecar_present = false;
        std::size_t reseeded      = 0;   // ledger-pending bids re-driven into the fresh driver
        std::size_t reregistered  = 0;   // sidecar without a FOUND event (crash in the window) -> registered now
        std::size_t stale_dropped = 0;   // already SETTLED / already stepped past
        std::size_t unrecoverable = 0;   // ledger-pending but height <= cursor: will never be stepped
        std::size_t malformed     = 0;
    };
    struct TickReport {
        std::size_t drained = 0, registered = 0, refused = 0, settled = 0, orphaned = 0;
    };
    struct Stats {
        std::uint64_t registered = 0, refused = 0, late_refused = 0, settled = 0,
                      orphaned = 0, sidecar_write_failures = 0;
        // c2pool#1551. `r7_violations` is the one that must stay at zero: it
        // counts settlements the race gate did NOT authorise, which is the only
        // way a double-credit or an orphan-credit could reach the ledger.
        std::uint64_t race_credited = 0, race_refused_orphaned = 0,
                      race_refused_other_only = 0, race_deferred = 0,
                      race_renotified = 0, r7_violations = 0;
        // R4 (chain-ordered booking). `late_unbooked` must stay 0 with the gate
        // armed (it fires only after a bounded-stall release or a boot cursor
        // mismatch); `booking_stall_timeout` counts booking-pending lane blocks
        // that exhausted their retry bound while still canonical (the LOUD
        // release that replaces the old silent LATE fork).
        //
        // `late_unbooked` covers BOTH sub-classes of "FINALIZE already consumed a
        // high-water >= h without this block in the pending set":
        //   (a) h <= cursor            : unbookable, dropped (the original alarm);
        //   (b) cursor < h <= cursor+D : bookable, but FINALIZE(cursor) already ran
        //                                at hw = cursor + D_conf and read the pending
        //                                set without it -> the two nodes' ledgers
        //                                have diverged at that finalize (the
        //                                cursor-31 R4-bound fork class). Counted in
        //                                `late_booked_post_finalize` as well. The
        //                                old gate bound (hh <= h) let (b) through
        //                                silently: the alarm read 0 on a real fork.
        std::uint64_t late_unbooked = 0, booking_stall_timeout = 0;
        std::uint64_t late_booked_post_finalize = 0;
        // R5: lane blocks whose 03 root matched no candidate digest, kept in the
        // retry set (never memoized) and re-decoded as the candidate ring advances;
        // `lane_root_unknown_resolved` = later booked; `lane_root_unknown_terminal`
        // = exhausted the retry bound still unknown (LOUD; a real other-lane block
        // or a ring that never reached the winner's state).
        std::uint64_t lane_root_unknown_retries = 0, lane_root_unknown_resolved = 0,
                      lane_root_unknown_terminal = 0;
    };

    // Construct AFTER node.bring_up() (the finalize driver exists) and AFTER
    // main has printed construction_log() — the echo cursor starts at "now" so
    // nothing is printed twice.
    FinalizeConnect(XmrNode& node, const XmrNodeConfig& cfg, FoundBlockQueue& queue,
                    FinalizeConnectOptions opts = {})
        : m_node(node), m_cfg(cfg), m_q(queue), m_o(std::move(opts)),
          m_log_cursor(node.construction_log().size()),
          m_race(cfg.same_height_policy()) {
        // c2pool#1551: take the node's single chain-observation seam. Both arm
        // orders route through it, so the race book sees the same blocks the
        // finalize driver does, in the same order, in either mode.
        m_node.set_chain_observer(
            [this](std::uint64_t h, const std::string& bid) { observe_chain_block(h, bid); });
        m_node.set_chain_extend_observer(
            [this](std::uint64_t h, const std::string& bid) { book_chain_block(h, bid); });   //
        // R4: chain-ordered booking gate. The finalize cursor may not step onto
        // a coin-height that still carries a canonical, booking-pending lane
        // block (one in the retry set): booking must land BEFORE FINALIZE so
        // rearm_first_eligible sees the same pending set on every node.
        m_node.finalize_driver().set_booking_gate(
            [this](std::uint64_t h) { return booking_gate(h); });
    }

    FinalizeConnect(const FinalizeConnect&) = delete;
    FinalizeConnect& operator=(const FinalizeConnect&) = delete;

    // ── boot: re-drive the sidecar's pending FOUNDs into the fresh driver.
    //    Call BEFORE the stratum listener starts and BEFORE the first pump_poll
    //    (so the driver's maps are rebuilt before any Extend can step past H_b).
    BootReport reseed_after_bring_up() {
        BootReport rep;
        if (m_o.sidecar_path.empty()) return rep;

        std::ifstream in(m_o.sidecar_path);
        if (!in) {
            say("boot: no pending-FOUND sidecar at " + m_o.sidecar_path + " (fresh)");
            return rep;
        }
        rep.sidecar_present = true;

        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        std::vector<std::pair<std::string, PendingRec>> recs;
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            std::string bid; PendingRec rec;
            if (!parse_sidecar_line(line, bid, rec)) {
                ++rep.malformed;
                say("boot: MALFORMED sidecar line dropped: " + line);
                continue;
            }
            recs.emplace_back(std::move(bid), std::move(rec));
        }

        for (auto& [bid, rec] : recs) {
            c2pool::xmr::node::Hash id{};
            (void)hash_from_hex(bid, id);   // validated by parse_sidecar_line
            if (m_node.ledger().is_settled(bid)) {
                ++rep.stale_dropped;
                say("boot: dropped stale sidecar " + short_bid(bid) + " (already SETTLED)");
                continue;
            }
            const bool pending = m_node.ledger().is_pending(bid);
            if (rec.height <= cursor) {
                if (pending) {
                    // The driver's cursor is past H_b: advance_to_tip will never
                    // step it. Keep it in the sidecar so this warning repeats at
                    // every boot until an operator disposes of it.
                    ++rep.unrecoverable;
                    m_unrecoverable[bid] = rec;
                    say("boot: UNRECOVERABLE PENDING " + bid + " h=" + std::to_string(rec.height) +
                        " — the finalize cursor (" + std::to_string(cursor) + ") is already past its "
                        "height (store written by a run without the sidecar?); it will never be "
                        "stepped at maturity and its payout stays deducted from effective_owed: "
                        "operator must dispose of it by hand");
                } else {
                    ++rep.stale_dropped;
                    say("boot: dropped stale sidecar " + short_bid(bid) + " (not pending, cursor past h=" +
                        std::to_string(rec.height) + ")");
                }
                continue;
            }
            // Re-drive through the one seam. `pending` == true: the ledger already
            // holds it (RecoveryDriver replayed the FOUND) -> ledger no-op, driver
            // maps rebuilt, one duplicate FOUND event (idempotent on replay).
            // `pending` == false: the sidecar was written but the crash hit before
            // the FOUND write-ahead -> this IS the registration (monerod had
            // accepted the block before the sidecar was written).
            Amounts credit = amounts_from(rec.payee, rec.reward, nullptr);
            Amounts payout = credit;
            const bool ok = m_node.on_network_block_won(rec.height, id, credit, payout);
            if (!ok || !m_node.ledger().is_pending(bid)) {
                ++rep.stale_dropped;
                say("boot: sidecar " + short_bid(bid) + " not admitted by the node/ledger; dropped");
                continue;
            }
            m_pending[bid] = rec;
            m_race.observe_own(rec.height, bid, rec.found_unix_s);
            if (pending) ++rep.reseeded; else ++rep.reregistered;
            say(std::string("boot: ") + (pending ? "re-drove pending FOUND " : "RE-REGISTERED lost FOUND ") +
                short_bid(bid) + " h=" + std::to_string(rec.height) +
                " (finalizes when hw >= " + std::to_string(rec.height + m_cfg.d_conf) + ")");
        }
        (void)sidecar_flush();
        echo_node_log();
        return rep;
    }

    // ── the main-loop tick. Call it right BEFORE transport.pump_poll() so a win
    //    queued during the sleep is registered before the tip can advance past
    //    it (the late-FOUND guard below is the backstop, not the plan).
    TickReport tick() {
        TickReport t;
        echo_node_log();                       // finalize: / win: lines since the last tick
        if (!m_retry.empty()) {                //  fix 4: retry transient chain-fetch failures
            // R4: retry in CHAIN ORDER (ascending height), so booking lands
            // oldest-first and deterministically across nodes — the same order
            // FINALIZE will consume them in.
            std::vector<std::pair<std::uint64_t, std::string>> again;   // (height, bid)
            for (const auto& [bid, h] : m_retry) again.emplace_back(h, bid);
            std::sort(again.begin(), again.end());
            m_retry.clear();
            for (const auto& [h, bid] : again)
                if (m_node.chain_carries(h, bid)) book_chain_block(h, bid);   // still canonical -> try again; else drop (an orphan)
        }

        std::vector<FoundBlockEvent> evs;
        t.drained = m_q.drain(evs);
        for (const auto& ev : evs) {
            RegisterResult r = register_found(ev);
            if (r.registered && !r.duplicate) ++t.registered;
            else if (!r.registered)            ++t.refused;
        }
        reconcile(t);
        race_gate(t);                          // c2pool#1551 -- after reconcile, so a
                                               // credit the driver just took is already
                                               // recorded when the gate cross-checks it
        echo_node_log();                       // the node's own "win: FOUND ..." lines
        progress();
        return t;
    }

    // ── c2pool#1551: observation ───────────────────────────────────────────
    // A block the node's chain told us about, at `height`. Ours (it will have
    // been registered as a FOUND, or will be in a moment -- the race book
    // promotes either way) or a stranger's. Installed as XmrNode's chain
    // observer by the constructor; also callable directly by a consumer that
    // learns of a same-height block from somewhere else.
    void observe_chain_block(std::uint64_t height, const std::string& bid_hex) {
        const std::string bid = lower_hex(bid_hex);
        if (bid.size() != 64) return;
        if (m_race.holds_own(height, bid)) { m_race.observe_own(height, bid); return; }
        if (m_pending.count(bid) || m_unrecoverable.count(bid)) {
            m_race.observe_own(height, bid);     // ours, seen through the chain
            return;
        }
        m_race.observe_other(height, bid);
    }

    // Candidate blocks the node is HOLDING but has not adopted (the alt pool).
    // Without them the race book is blind in exactly the branch that matters: if
    // our own block stays best, the rival never becomes a mainchain event, and
    // an accounting layer fed only by the event stream would report the height
    // uncontested and credit as if we had run unopposed.
    struct AltObservation {
        std::uint64_t height = 0;
        std::string   bid_hex;
        bool          own_mined = false;
    };
    std::size_t observe_alt_tips(const std::vector<AltObservation>& alts) {
        std::size_t n = 0;
        for (const AltObservation& a : alts) {
            const std::string bid = lower_hex(a.bid_hex);
            if (bid.size() != 64 || a.height == 0) continue;
            if (a.own_mined || m_race.holds_own(a.height, bid) || m_pending.count(bid))
                n += m_race.observe_own(a.height, bid) ? 1 : 0;
            else
                n += m_race.observe_other(a.height, bid) ? 1 : 0;
        }
        return n;
    }

    const SameHeightRaceLedger& race() const noexcept { return m_race; }
    SameHeightRaceLedger&       race()       noexcept { return m_race; }

    // ── shutdown: one last drain so a win that landed after the final tick has
    //    its FOUND written before node.stop(). Order: listener.stop() ->
    //    fc.drain_before_stop() -> node.stop().
    TickReport drain_before_stop() { return tick(); }

    //  a block joined the best chain at h. If it is a LANE block (its coinbase carries our
    // 0x03 tag and maps under deterministic r), book it FOUND with the ON-CHAIN amounts — whoever
    // mined it. Provisional (pending) until D_conf burial; an Orphan event disposes it (pre-SETTLED
    // pure removal), a later block on the new chain is booked the same way at ITS burial.
    void book_chain_block(std::uint64_t h, const std::string& bid_hex) {
        if (!m_o.book_from_chain) return;
        const std::string bid = lower_hex(bid_hex);
        if (bid.size() != 64 || h == 0) return;
        //  fix 2: dedup on CURRENT ledger state, not on "ever seen" -- an orphaned block that
        // becomes canonical again (branch flip-flop) must be re-booked.
        if (m_pending.count(bid) || m_unrecoverable.count(bid)) return;
        if (m_node.ledger().is_settled(bid) || m_node.ledger().is_pending(bid)) return;
        if (m_chain_seen.count(bid)) return;   //  fix 3b: memo of NON-booked outcomes only (not-lane / late / refused)
        if (m_chain_booked_once.count(bid)) say("cba: chain block " + short_bid(bid) + " h=" + std::to_string(h) + " is canonical AGAIN after an orphan -> re-booking");
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        if (h <= cursor) {
            // R4: with the booking gate armed the cursor cannot step past a
            // canonical unbooked lane block, so this is no longer a SILENT fork.
            // It can fire only after a bounded-stall release or a boot cursor
            // mismatch — a LOUD alarm, never a quiet drop.
            m_chain_seen[bid] = true; ++m_stats.late_unbooked;
            say("cba-ALARM late_unbooked: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) +
                " is at/below the finalize cursor " + std::to_string(cursor) +
                " — its credit can no longer be booked (would pend forever). With R4 this means a "
                "booking-stall timeout released the gate or the cursor was recovered ahead of it; "
                "this height needs an operator's eyes (credit divergence risk)");
            return;
        }
        // R4-bound alarm (sub-class (b), the cursor-31 fork class): the finalize
        // cursor ADVANCED while this block was awaiting booking (first seen at
        // cursor c0, now at cursor > c0) and one of those steps ran at hw = h' +
        // D_conf >= h -- so the OwedLedger read the WHOLE pending set WITHOUT this
        // block while a node that booked it in time had it in. That is exactly what
        // the booking_gate bound (hh <= h + D_conf) forbids; it can fire only after
        // a bounded-stall release or a boot cursor mismatch. Still booked (the
        // driver will step h), but LOUDLY: it must read 0 in a converged run.
        // (Not "h <= cursor + D_conf" alone: after a pop the regrown blocks sit
        // within D_conf above a cursor that stepped BEFORE they existed -- no
        // finalize ever read a pending set they should have been in.)
        auto fc_it = m_first_cursor.find(bid);
        if (fc_it == m_first_cursor.end()) fc_it = m_first_cursor.emplace(bid, cursor).first;
        const bool late_post_finalize = (cursor > fc_it->second) && (h <= cursor + m_cfg.d_conf);
        Amounts credit, payout; std::string why;
        if (!m_o.book_from_chain(h, bid, credit, payout, why)) {
            const bool root_unknown = (why.rfind("lane-root-unknown:", 0) == 0);   // R5
            if (why.rfind("get_block", 0) == 0 || why.find("does not parse") != std::string::npos ||
                why.rfind("cut-pending:", 0) == 0 || root_unknown) {   //  fix 4: transient (recon(A+B credit): + receiver's lane not yet at P; R5: + ring not yet at the winner's state)
                if (++m_retry_n[bid] <= 600) {
                    m_retry[bid] = h;
                    if (root_unknown) {
                        ++m_stats.lane_root_unknown_retries; m_root_unknown_bids.insert(bid);
                        if (m_retry_n[bid] == 1 || m_retry_n[bid] % 50 == 0)
                            say("cba: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " lane-root-unknown (" + why + ") -> kept, RETRY #" + std::to_string(m_retry_n[bid]) + " as the candidate ring advances (holds the R4 gate)");
                    } else {
                        say("cba: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " fetch failed (" + why + ") -> RETRY #" + std::to_string(m_retry_n[bid]));
                    }
                    return;
                }
            }
            m_chain_seen[bid] = true; m_first_cursor.erase(bid);
            if (why.rfind("not-lane:", 0) == 0) return;   // a stranger's block: nothing to book
            if (why.rfind("cut-pending:", 0) == 0) {      // R4: the receiver's lane never reached P within the retry bound
                ++m_stats.booking_stall_timeout;
                say("cba-ALARM booking_stall_timeout: chain lane block " + short_bid(bid) + " h=" +
                    std::to_string(h) + " exhausted its booking retry bound still cut-pending (" + why +
                    ") — releasing the finalize gate; credit for this height may diverge");
            }
            if (root_unknown) {                           // R5: the ring never reached the winner's state within the bound
                ++m_stats.booking_stall_timeout; ++m_stats.lane_root_unknown_terminal;
                say("cba-ALARM booking_stall_timeout(lane_root_unknown): chain lane block " + short_bid(bid) + " h=" +
                    std::to_string(h) + " exhausted its retry bound with its 03 root still matching no candidate digest (" + why +
                    ") — releasing the finalize gate; another lane's block, or this ledger never passed through the winner's state (credit divergence risk)");
            }
            ++m_stats.refused;
            say("cba: REFUSED chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + ": " + why);
            return;
        }
        if (m_root_unknown_bids.erase(bid)) {   // R5: a lane-root-unknown block resolved once the ring caught up
            ++m_stats.lane_root_unknown_resolved;
            say("cba: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " lane-root-unknown RESOLVED after " +
                std::to_string(m_retry_n[bid]) + " retries (the candidate ring reached the winner's ledger state)");
        }
        if (late_post_finalize) {
            ++m_stats.late_unbooked; ++m_stats.late_booked_post_finalize;
            say("cba-ALARM late_unbooked(post-finalize): chain lane block " + short_bid(bid) + " h=" + std::to_string(h) +
                " is being booked with the finalize cursor at " + std::to_string(cursor) + " (hw already reached " +
                std::to_string(cursor + m_cfg.d_conf) + " >= h): FINALIZE(" + std::to_string(cursor) +
                ") read the pending set WITHOUT this block — this node's ledger has diverged from a node that booked it in time "
                "(R4 gate released by a stall timeout, or a boot cursor mismatch); booking it anyway, operator's eyes needed");
        }
        c2pool::xmr::node::Hash id{}; (void)hash_from_hex(bid, id);
        PendingRec rec; rec.height = h; rec.reward = 0; for (const auto& [k, v] : payout) { (void)k; rec.reward += static_cast<std::uint64_t>(v); }
        m_pending[bid] = rec; (void)sidecar_flush();
        if (!m_node.on_network_block_won(h, id, credit, payout) || !m_node.ledger().is_pending(bid)) {
            m_pending.erase(bid); (void)sidecar_flush();
            say("cba: node/ledger did not admit chain lane block " + short_bid(bid)); return;
        }
        ++m_stats.registered; ++m_cba_chain_booked; m_chain_booked_once[bid] = true; m_retry.erase(bid); m_first_cursor.erase(bid);
        m_race.observe_own(h, bid);   // a LANE block is 'own' for the race book (multi-node: own == lane)
        say("cba: CHAIN FOUND booked " + short_bid(bid) + " h=" + std::to_string(h) + " payout_keys=" + std::to_string(payout.size()) + " total=" + std::to_string(rec.reward) + " -> finalizes when hw >= " + std::to_string(h + m_cfg.d_conf));
    }
    std::uint64_t cba_chain_booked() const { return m_cba_chain_booked; }

    // ── the FOUND path (also usable directly on the main thread, e.g. by a
    //    --replay-found operator tool). Idempotent per bid. Never throws.
    RegisterResult register_found(const FoundBlockEvent& ev) {
        RegisterResult r;
        const std::string bid = lower_hex(ev.block_id_hex);
        c2pool::xmr::node::Hash id{};
        if (!hash_from_hex(bid, id)) {
            return refuse(r, bid, "malformed block id (need monerod's 64-hex block hash — "
                                  "submit_block result.block_id)");
        }
        if (c2pool::xmr::node::is_zero(id))
            return refuse(r, bid, "block id UNKNOWN (all-zero): is_canonical could never match it — "
                                  "the submitter must supply monerod's block_id (or the local keccak / "
                                  "get_block_header_by_height cross-check)");
        if (ev.height == 0)
            return refuse(r, bid, "refusing H_b == 0 (unknown height is not a height)");
        if (m_pending.count(bid)) { r.registered = true; r.duplicate = true; return r; }
        if (m_node.ledger().is_settled(bid))
            return refuse(r, bid, "already SETTLED");
        if (m_cfg.network == MoneroNetwork::Mainnet && !m_cfg.i_understand_mainnet)
            return refuse(r, bid, "MAINNET block without --i-understand-mainnet (prototype fence)");

        // LATE-FOUND guard: advance_to_tip steps only heights > cursor.
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        if (ev.height <= cursor) {
            ++m_stats.late_refused;
            return refuse(r, bid, "LATE FOUND: finalize cursor (" + std::to_string(cursor) +
                                  ") is already past h=" + std::to_string(ev.height) +
                                  " — the driver would never step it (pending forever); "
                                  "drain the found queue BEFORE pump_poll / lower --poll-ms");
        }

        std::string why_valueless;
        Amounts credit = amounts_from(ev.payee, ev.reward_piconero, &why_valueless);
        Amounts payout = credit;
        if (m_o.book_from_chain) {   //  (part 2): an OWN win is NOT booked on submit-OK — monerod also says OK
            // for an ALTERNATIVE block. It is booked by book_chain_block when OUR chain view carries it: the
            // single booking path for every lane block, so every node holds the same pending set.
            m_race.observe_own(ev.height, bid, ev.found_unix_s);
            say("own win " + short_bid(bid) + " h=" + std::to_string(ev.height) +
                " submitted OK -> booking DEFERRED to the chain view (coinbase authority)");
            if (m_o.on_own_win_deferred) m_o.on_own_win_deferred(ev.height, bid, ev.template_id, ev.extra_nonce);   // recon(A+B credit): v0x02 fast path leaves here (+ recompute capture)
            r.registered = true; r.duplicate = true; r.reason = "deferred-to-chain";
            return r;
        }

        PendingRec rec;
        rec.height = ev.height;
        rec.payee = ev.payee;
        rec.reward = ev.reward_piconero;
        rec.prev_id_hex = lower_hex(ev.prev_id_hex);
        rec.found_unix_s = ev.found_unix_s;

        // write-ahead the sidecar, then the FOUND event (inside on_network_block_won)
        m_pending[bid] = rec;
        if (!sidecar_flush()) {
            // The block is ALREADY on the chain (monerod accepted it): losing the
            // FOUND registration is strictly worse than losing restart-hardening.
            ++m_stats.sidecar_write_failures;
            say("WARN: pending-FOUND sidecar write FAILED for " + short_bid(bid) +
                " (" + std::string(std::strerror(errno)) + "); registering anyway — a restart "
                "inside the D_conf window will lose this pending FOUND");
        }
        const bool ok = m_node.on_network_block_won(ev.height, id, credit, payout);
        if (!ok) {
            m_pending.erase(bid);
            (void)sidecar_flush();
            return refuse(r, bid, "node refused the win (mainnet fence)");
        }
        if (!m_node.ledger().is_pending(bid)) {
            m_pending.erase(bid);
            (void)sidecar_flush();
            return refuse(r, bid, "ledger did not admit the FOUND (bid already known?)");
        }
        ++m_stats.registered;
        // c2pool#1551: the block enters the race book at the same instant it
        // enters the ledger's pending set, so no window exists in which a rival
        // at the same height could be judged against an empty book.
        m_race.observe_own(ev.height, bid, ev.found_unix_s);
        say("FOUND registered " + short_bid(bid) + " h=" + std::to_string(ev.height) +
            " reward=" + std::to_string(ev.reward_piconero) + " piconero payee=" +
            (ev.payee ? hex_of(*ev.payee).substr(0, 12) + "…" : std::string("-")) +
            (why_valueless.empty() ? "" : " [VALUELESS record: " + why_valueless + "]") +
            (ev.worker.empty() ? "" : " worker=" + ev.worker) +
            " tid=" + std::to_string(ev.template_id) + " nonce=" + std::to_string(ev.nonce) +
            " -> finalizes when hw >= " + std::to_string(ev.height + m_cfg.d_conf) +
            " (D_conf=" + std::to_string(m_cfg.d_conf) + ")");
        r.registered = true;
        return r;
    }

    // credit == payout == { payee : reward } (amount-honest, nets to 0 at
    // FINALIZE); {} when no payee / zero reward (the degenerate valueless record).
    static Amounts amounts_from(const std::optional<::v37::bytes32>& payee, std::uint64_t reward,
                                std::string* why_valueless) {
        Amounts a;
        auto because = [&](const char* s) { if (why_valueless) *why_valueless = s; };
        if (!payee)   { because("no payee identity key (address boundary not decoded)"); return a; }
        if (reward == 0) { because("zero reward"); return a; }
        if (reward > static_cast<std::uint64_t>(LLONG_MAX)) { because("reward exceeds long long"); return a; }
        a[*payee] = static_cast<long long>(reward);
        return a;
    }

    // ── read seams (main thread) ────────────────────────────────────────────
    const std::map<std::string, PendingRec>& pending()       const { return m_pending; }
    const std::map<std::string, PendingRec>& unrecoverable() const { return m_unrecoverable; }
    const Stats& stats() const { return m_stats; }

private:
    // R4: the booking gate the finalize driver consults before stepping onto a
    // coin-height. false => STALL: a still-canonical lane block at height <= h is
    // booking-pending (in the retry set). Bounded by the retry cap in
    // book_chain_block — once a bid exhausts its retries it leaves m_retry (with
    // a booking_stall_timeout alarm), so the gate always releases; it is never an
    // unbounded stall. This is what makes booking land BEFORE FINALIZE, so
    // rearm_first_eligible sees the same pending set on every node.
    //
    // BOUND (the cursor-31 fork fix): FINALIZE(h) runs at high-water hw = h + D_conf
    // and OwedLedger::on_block_finalized -> rearm_first_eligible reads the WHOLE
    // pending set (every booked lane block, whatever its height), so a canonical
    // booking-pending lane block ANYWHERE at height <= hw must hold the cursor,
    // not only one at height <= h. With the old bound (hh <= h) a cut-pending lane
    // block in (h, h+D_conf] let FINALIZE(h) run on one node with that block booked
    // and on the other without it: two pending sets, two ledgers, a permanent
    // owed_digest fork (seen at cursor 31 in the recon-final rig).
    bool booking_gate(std::uint64_t h) {
        const std::uint64_t hw = h + m_cfg.d_conf;
        for (const auto& [bid, hh] : m_retry)
            if (hh <= hw && m_node.chain_carries(hh, bid)) return false;
        return true;
    }

    RegisterResult& refuse(RegisterResult& r, const std::string& bid, std::string reason) {
        ++m_stats.refused;
        r.registered = false;
        r.reason = std::move(reason);
        say("REFUSED win " + short_bid(bid) + ": " + r.reason);
        return r;
    }

    // Retire every pending bid the ledger no longer holds pending: SETTLED (the
    // driver finalized it at bin_height = H_b + D_conf) or gone (orphaned —
    // an Orphan event, or the canonical predicate at maturity).
    void reconcile(TickReport& t) {
        bool changed = false;
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            const std::string& bid = it->first;
            const PendingRec&  rec = it->second;
            if (m_node.ledger().is_settled(bid)) {
                ++t.settled; ++m_stats.settled;
                race_confirm_credit(bid, rec.height);
                say("FINALIZED " + short_bid(bid) + " h=" + std::to_string(rec.height) +
                    " SETTLED at bin_height=" + std::to_string(rec.height + m_cfg.d_conf) +
                    (rec.payee ? " effective_owed(payee)=" +
                                 std::to_string(m_node.ledger().effective_owed(*rec.payee))
                               : std::string("")) +
                    " ledger_seq=" + std::to_string(m_node.ledger().ledger_seq()));
                it = m_pending.erase(it); changed = true;
            } else if (!m_node.ledger().is_pending(bid)) {
                ++t.orphaned; ++m_stats.orphaned;
                say("ORPHANED " + short_bid(bid) + " h=" + std::to_string(rec.height) +
                    " left the pending set (pre-SETTLED removal, O3.5)");
                it = m_pending.erase(it); changed = true;
            } else {
                ++it;
            }
        }
        // an unrecoverable bid the ledger finally dropped (operator disposed of it)
        for (auto it = m_unrecoverable.begin(); it != m_unrecoverable.end();) {
            if (!m_node.ledger().is_pending(it->first)) { it = m_unrecoverable.erase(it); changed = true; }
            else ++it;
        }
        if (changed) (void)sidecar_flush();
    }

    // ── c2pool#1551: THE GATE ──────────────────────────────────────────────
    // Walk the heights that are actually races, decide each against the SAME
    // chain the finalize driver asks, journal the transitions, and spend the
    // bounded re-announce budget on a contested height whose nominee is ours.
    //
    // Nothing here credits anything. The credit belongs to the F1 finalize
    // driver; this gate's job is to have an INDEPENDENT verdict ready so that
    // race_confirm_credit() can check the driver's answer against it. A gate
    // that also did the crediting would agree with itself by construction and
    // would prove nothing.
    void race_gate(TickReport& t) {
        (void)t;
        const std::uint64_t hw = m_node.hw().hw_height;
        auto canonical = [this](std::uint64_t h, const std::string& b) {
            return m_node.chain_carries(h, b);
        };

        for (const std::uint64_t h : m_race.heights_of_interest()) {
            const RaceDecision d = m_race.decide(h, hw, canonical);

            const auto lv = m_last_verdict.find(h);
            if (lv == m_last_verdict.end() || lv->second != d.verdict) {
                m_last_verdict[h] = d.verdict;
                m_race.account(d);
                switch (d.verdict) {
                    case RaceVerdict::DeferUnburied:   ++m_stats.race_deferred; break;
                    case RaceVerdict::RefuseOrphaned:  ++m_stats.race_refused_orphaned; break;
                    case RaceVerdict::OtherOnly:       ++m_stats.race_refused_other_only; break;
                    default: break;
                }
                journal_race(d, hw);
                say("race h=" + std::to_string(h) + " " + to_string(d.verdict) +
                    " [own=" + std::to_string(d.own_candidates) +
                    " other=" + std::to_string(d.other_candidates) +
                    (d.own_vs_other ? " OWN-vs-OTHER" : (d.contested ? " own-vs-own" : "")) +
                    "] hw=" + std::to_string(hw) + " need=" + std::to_string(d.need_hw) +
                    " nominated=" + (d.nomination.bid.empty() ? std::string("-")
                                                              : short_bid(d.nomination.bid)) +
                    (d.nomination.is_own ? " (ours)" : " (theirs)") +
                    (d.credit_bid.empty() ? "" : " credit=" + short_bid(d.credit_bid)) +
                    " :: " + d.nomination.why);
            }

            // Lever (2). take_renotify() is what enforces the bound: it fires
            // only on a contested, unburied height whose nominee is ours and is
            // not already the block the chain carries, and at most
            // max_renotify times per height.
            if (m_o.renotify && m_race.take_renotify(h, d, canonical)) {
                const bool sent = m_o.renotify(h, d.nomination.bid);
                if (sent) ++m_stats.race_renotified;
                say(std::string("race h=") + std::to_string(h) + " prefer-own RE-ANNOUNCE " +
                    short_bid(d.nomination.bid) + (sent ? " pushed" : " NOT pushed (relay declined)"));
            }
        }

        // Bound the book. The gate keeps a few D_conf windows of candidates and
        // a full retention window of credit records -- long enough that any
        // reorg the index itself could follow still finds its R-7 answer here.
        const std::uint64_t keep = m_cfg.d_conf * 4 + 64;
        if (hw > keep) {
            const std::uint64_t floor = hw - keep;
            m_race.prune_below(floor, m_cfg.index_retain_recent);
            for (auto it = m_last_verdict.begin(); it != m_last_verdict.end();) {
                if (it->first < floor) it = m_last_verdict.erase(it); else break;
            }
        }
    }

    // The finalize driver has just SETTLED `bid`, mined at `height`. The race
    // gate now has to agree, independently, that this exact block at this exact
    // height was creditable -- buried D_conf deep, carried by the best chain,
    // and the FIRST credit at that height. A disagreement is not a warning to
    // shrug at: a double-credit and an orphan-credit have no other shape.
    void race_confirm_credit(const std::string& bid, std::uint64_t height) {
        const std::uint64_t hw = m_node.hw().hw_height;
        const RaceDecision d = m_race.decide(height, hw,
            [this](std::uint64_t h, const std::string& b) { return m_node.chain_carries(h, b); });

        const bool authorised = (d.verdict == RaceVerdict::CreditOwn) && (d.credit_bid == bid);
        const bool first      = authorised && m_race.note_credited(height, bid);
        if (first) {
            ++m_stats.race_credited;
            m_last_verdict[height] = RaceVerdict::AlreadyCredited;
            RaceDecision rec = d;
            rec.verdict = RaceVerdict::AlreadyCredited;
            journal_race(rec, hw);
            return;
        }
        ++m_stats.r7_violations;
        const std::string* already = m_race.credited_at(height);
        say("R-7 VIOLATION: the finalize driver SETTLED " + short_bid(bid) + " at h=" +
            std::to_string(height) + " but the same-height gate says " + to_string(d.verdict) +
            " (own=" + std::to_string(d.own_candidates) + " other=" + std::to_string(d.other_candidates) +
            " hw=" + std::to_string(hw) + " need=" + std::to_string(d.need_hw) +
            (already ? " already-credited=" + short_bid(*already) : std::string()) +
            "). This is the shape an orphan-credit or a double-credit takes -- "
            "the settlement store and this height need an operator's eyes.");
        journal_race(d, hw);
    }

    void journal_race(const RaceDecision& d, std::uint64_t hw) {
        if (m_o.race_journal_path.empty()) return;
        std::ofstream f(m_o.race_journal_path, std::ios::app);
        if (!f) return;
        f << static_cast<unsigned long long>(
                 std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch()).count())
          << ' ' << race_journal_line(d, hw) << '\n';
    }

    void progress() {
        if (!m_o.progress || m_pending.empty()) return;
        const std::uint64_t hw = m_node.hw().hw_height;
        if (hw == m_last_hw_printed) return;
        m_last_hw_printed = hw;
        for (const auto& [bid, rec] : m_pending) {
            const std::uint64_t need = rec.height + m_cfg.d_conf;
            const std::uint64_t left = need > hw ? need - hw : 0;
            say("pending " + short_bid(bid) + " h=" + std::to_string(rec.height) + " hw=" +
                std::to_string(hw) + " — finalizes at hw>=" + std::to_string(need) + " (" +
                std::to_string(left) + " to go)");
        }
    }

    void echo_node_log() {
        if (!m_o.echo_node_log) return;
        const auto& L = m_node.construction_log();
        for (; m_log_cursor < L.size(); ++m_log_cursor) say("node: " + L[m_log_cursor]);
    }

    void say(const std::string& s) const {
        if (!m_o.out) return;
        std::fprintf(m_o.out, "%s %s\n", m_o.tag.c_str(), s.c_str());
        std::fflush(m_o.out);
    }
    static std::string short_bid(const std::string& bid) {
        return bid.size() > 12 ? bid.substr(0, 12) + "…" : bid;
    }

    // ── sidecar codec: one record per line, space-separated, no escaping needed
    //    (bids/keys are hex; '-' = absent):
    //    1 <bid64> <height> <payee64|-> <reward> <prev64|-> <found_unix_s>
    static std::string sidecar_line(const std::string& bid, const PendingRec& r) {
        std::string s = "1 " + bid + " " + std::to_string(r.height) + " " +
                        (r.payee ? hex_of(*r.payee) : std::string("-")) + " " +
                        std::to_string(r.reward) + " " +
                        (r.prev_id_hex.size() == 64 ? r.prev_id_hex : std::string("-")) + " " +
                        std::to_string(r.found_unix_s) + "\n";
        return s;
    }
    static bool parse_sidecar_line(const std::string& line, std::string& bid, PendingRec& r) {
        std::istringstream is(line);
        std::string ver, payee, prev;
        unsigned long long h = 0, reward = 0, ts = 0;
        if (!(is >> ver >> bid >> h >> payee >> reward >> prev >> ts)) return false;
        if (ver != "1") return false;
        std::array<std::uint8_t, 32> tmp{};
        bid = lower_hex(bid);
        if (!hash_from_hex(bid, tmp)) return false;
        if (c2pool::xmr::node::is_zero(tmp)) return false;   // a zero bid can never finalize
        if (h == 0) return false;
        r.height = h;
        r.reward = reward;
        r.found_unix_s = ts;
        if (payee != "-") {
            ::v37::bytes32 k{};
            if (!hash_from_hex(lower_hex(payee), k)) return false;
            r.payee = k;
        }
        if (prev != "-") {
            prev = lower_hex(prev);
            if (!hash_from_hex(prev, tmp)) return false;
            r.prev_id_hex = prev;
        }
        return true;
    }

    bool sidecar_flush() {
        if (m_o.sidecar_path.empty()) return true;
        std::string body;
        for (const auto& [bid, rec] : m_pending)       body += sidecar_line(bid, rec);
        for (const auto& [bid, rec] : m_unrecoverable) body += sidecar_line(bid, rec);
        return atomic_write(m_o.sidecar_path, body);
    }

    // tmp -> fsync -> rename -> fsync(dir): the file is either the old or the new
    // whole image, never a torn one.
    static bool atomic_write(const std::string& path, const std::string& body) {
        const std::string tmp = path + ".tmp";
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        std::size_t off = 0;
        while (off < body.size()) {
            const ssize_t n = ::write(fd, body.data() + off, body.size() - off);
            if (n < 0) { if (errno == EINTR) continue; ::close(fd); return false; }
            if (n == 0) { ::close(fd); return false; }
            off += static_cast<std::size_t>(n);
        }
        if (::fsync(fd) != 0) { ::close(fd); return false; }
        ::close(fd);
        if (::rename(tmp.c_str(), path.c_str()) != 0) return false;
        const std::string dir = std::filesystem::path(path).parent_path().string();
        int dfd = ::open(dir.empty() ? "." : dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) { (void)::fsync(dfd); ::close(dfd); }
        return true;
    }

    XmrNode&               m_node;
    const XmrNodeConfig&   m_cfg;
    FoundBlockQueue&       m_q;
    FinalizeConnectOptions m_o;

    std::map<std::string, PendingRec> m_pending;        // bid -> rec, mirrors the sidecar
    std::map<std::string, bool>       m_chain_seen;     //  bids classified not-lane / late / refused (never re-attempted)
    std::map<std::string, bool>       m_chain_booked_once;   //  bids booked at least once (re-bookable after an orphan)
    std::map<std::string, std::uint64_t> m_retry;            //  fix 4: bid -> height, transient fetch failures to retry
    std::map<std::string, int>        m_retry_n;
    std::set<std::string>             m_root_unknown_bids;   //  R5: bids currently retrying as lane-root-unknown
    std::map<std::string, std::uint64_t> m_first_cursor;     //  R4 alarm: finalize cursor when a chain lane block was first seen
    std::uint64_t                     m_cba_chain_booked = 0;
    std::map<std::string, PendingRec> m_unrecoverable;  // kept in the sidecar so the boot warning repeats
    Stats         m_stats;
    std::size_t   m_log_cursor = 0;
    std::uint64_t m_last_hw_printed = ~std::uint64_t{0};

    // c2pool#1551: the race book and the last verdict reported per height (so a
    // quiet loop stays quiet and the journal records transitions, not ticks).
    SameHeightRaceLedger                    m_race;
    std::map<std::uint64_t, RaceVerdict>    m_last_verdict;
};

} // namespace c2pool::v37n::xmr::o2

// ===========================================================================
// SELF-CHECK — network-free, RandomX-free, against the monerod STUB; the same
// shape as xmr_node_smoke.hpp so it can run under `--mock-smoke` / the CI
// smoke target. Proves: queued win -> FOUND (amount-honest) -> restart inside
// the D_conf window -> sidecar re-drive -> FINALIZE at bin_height = H_b+D_conf
// -> finalW nets to 0 -> sidecar retired; plus the late-FOUND and malformed
// refusals, the valueless record, idempotence, and the orphan disposition.
// ===========================================================================
#include "xmr_node_smoke.hpp"   // smoke::Report, apply_row, blk_id, key_of, test_point_check
#include "impl/xmr/node/monerod_transport.hpp"   // MockMonerodTransport

namespace c2pool::v37n::xmr::o2 {

inline smoke::Report finalize_connect_selfcheck(const std::filesystem::path& tmp_root) {
    using c2pool::xmr::node::MockMonerodTransport;
    smoke::Report rep;
    const ::v37::ChainId CHAIN = 7;
    const std::uint64_t  D_CONF = 3;
    const std::uint64_t  REWARD = 600000000000ull;   // 0.6 XMR in piconero

    XmrNodeConfig cfg;
    cfg.network = MoneroNetwork::Stagenet;
    cfg.lane_chain = CHAIN;
    cfg.d_conf = D_CONF;
    cfg.settle_db_path = (tmp_root / "store").string();
    std::filesystem::create_directories(cfg.settle_db_path);

    FinalizeConnectOptions o;
    o.sidecar_path = (std::filesystem::path(cfg.settle_db_path) / "pfound.tsv").string();
    o.out = nullptr;   // silent

    const ::v37::bytes32 payee = smoke::key_of(0xC3);
    const std::string bid5 = hex_of(smoke::blk_id(5));
    const std::string bid8 = hex_of(smoke::blk_id(8));
    const std::string bid11 = hex_of(smoke::blk_id(11));
    FoundBlockQueue q;

    auto count_lines = [&](const std::string& p) {
        std::ifstream f(p); std::string l; std::size_t n = 0;
        while (std::getline(f, l)) if (!l.empty()) ++n;
        return n;
    };
    auto chain = [&](XmrNode& node, std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h)
            smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)),
                             smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    };

    // ── phase 1: node A — win at 5, buried 2 (< D_conf), then "crash" ────────
    {
        MockMonerodTransport mock;
        XmrNode node(cfg, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) {
            rep.add("FC0 bring_up (node A)", false, e.what()); return rep;
        }
        chain(node, 1, 5);
        FinalizeConnect fc(node, cfg, q, o);
        auto boot = fc.reseed_after_bring_up();
        rep.add("FC1 fresh boot: no sidecar, nothing reseeded",
                !boot.sidecar_present && boot.reseeded == 0 && boot.reregistered == 0);

        FoundBlockEvent ev;
        ev.height = 5; ev.block_id_hex = bid5; ev.prev_id_hex = hex_of(smoke::blk_id(4));
        ev.reward_piconero = REWARD; ev.payee = payee; ev.worker = "rig0"; ev.template_id = 42;
        q.push(ev); q.push(ev);                       // duplicate push (idempotent per bid)
        auto t = fc.tick();
        rep.add("FC2 queued win -> on_network_block_won: ledger pending, idempotent per bid",
                t.drained == 2 && t.registered == 1 && t.refused == 0 &&
                fc.pending().size() == 1 && node.ledger().is_pending(bid5),
                "drained=" + std::to_string(t.drained) + " registered=" + std::to_string(t.registered));
        rep.add("FC3 amount-honest: effective_owed(payee) == -reward while pending",
                node.ledger().effective_owed(payee) == -static_cast<long long>(REWARD));
        rep.add("FC4 pending-FOUND sidecar written (write-ahead, 1 record)",
                count_lines(o.sidecar_path) == 1);

        chain(node, 6, 7);                            // hw=7 < 5+3
        t = fc.tick();
        rep.add("FC5 not yet buried D_conf (hw=7 < 8): still pending, no finalize",
                t.settled == 0 && t.orphaned == 0 && fc.pending().size() == 1 &&
                node.ledger().is_pending(bid5),
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()));

        // late FOUND: cursor is 7-3=4, a win claimed at h=3 can never be stepped
        FoundBlockEvent late = ev; late.height = 3; late.block_id_hex = hex_of(smoke::blk_id(3));
        q.push(late);
        t = fc.tick();
        rep.add("FC6 late FOUND (height <= finalize cursor) refused, not poisoned into the ledger",
                t.refused == 1 && fc.stats().late_refused == 1 &&
                !node.ledger().is_pending(hex_of(smoke::blk_id(3))));

        FoundBlockEvent bad = ev; bad.block_id_hex = "not-a-block-id";
        q.push(bad);
        t = fc.tick();
        rep.add("FC7 malformed block id refused", t.refused == 1 && fc.pending().size() == 1);

        FoundBlockEvent zero = ev; zero.block_id_hex = std::string(64, '0');
        q.push(zero);
        t = fc.tick();
        rep.add("FC7b all-zero (unknown) block id refused — never a FOUND that cannot be canonical",
                t.refused == 1 && fc.pending().size() == 1 &&
                !node.ledger().is_pending(std::string(64, '0')));
        // node A is destroyed here: a restart inside the D_conf window
    }

    // ── phase 2: node B on the same store — reseed, bury, FINALIZE ───────────
    {
        MockMonerodTransport mock;
        XmrNode node(cfg, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) {
            rep.add("FC0 bring_up (node B)", false, e.what()); return rep;
        }
        const bool recovered_pending = node.ledger().is_pending(bid5);
        FinalizeConnect fc(node, cfg, q, o);
        auto boot = fc.reseed_after_bring_up();
        rep.add("FC8 restart: sidecar re-drives the pending FOUND into the fresh driver",
                recovered_pending && boot.sidecar_present && boot.reseeded == 1 &&
                boot.reregistered == 0 && boot.unrecoverable == 0 && fc.pending().size() == 1,
                "reseeded=" + std::to_string(boot.reseeded) + " unrec=" + std::to_string(boot.unrecoverable) +
                " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        const auto seq_before = node.ledger().ledger_seq();
        rep.add("FC8b re-drive left the ledger untouched (ledger_seq unchanged, still pending)",
                node.ledger().ledger_seq() == seq_before && node.ledger().is_pending(bid5));

        chain(node, 5, 8);                            // index rebuilt from 5; hw -> 8 = 5+3
        auto t = fc.tick();
        rep.add("FC9 FOUND -> FINALIZE at D_conf burial after restart (bin_height = 5+3 = 8)",
                t.settled == 1 && node.ledger().is_settled(bid5) && fc.pending().empty(),
                "settled=" + std::to_string(t.settled));
        rep.add("FC10 finalW nets to 0 for the payee (credit == payout)",
                node.ledger().effective_owed(payee) == 0);
        rep.add("FC11 sidecar retired after FINALIZE", count_lines(o.sidecar_path) == 0);
        bool logged = false;
        for (const auto& l : node.construction_log())
            if (l.find("SETTLED at bin_height=8") != std::string::npos) logged = true;
        rep.add("FC12 the node logged the FINALIZE step with the per-height bin_height (echoed by tick)", logged);

        // valueless win (no payee decoded) still records the block
        FoundBlockEvent v; v.height = 8; v.block_id_hex = bid8;
        q.push(v);
        t = fc.tick();
        rep.add("FC13 valueless win (no payee) still registers (degenerate {}/{})",
                t.registered == 1 && node.ledger().is_pending(bid8));
        chain(node, 9, 11);
        t = fc.tick();
        rep.add("FC14 valueless win finalizes at 8+3=11", t.settled == 1 && node.ledger().is_settled(bid8));

        // orphan disposition: win at 11, then a competing 11 wins the chain
        FoundBlockEvent w; w.height = 11; w.block_id_hex = bid11; w.payee = payee; w.reward_piconero = REWARD;
        q.push(w);
        t = fc.tick();
        const bool reg11 = t.registered == 1 && node.ledger().is_pending(bid11);
        smoke::apply_row(node, 11, smoke::blk_id(99), smoke::blk_id(10));   // reorg at 11
        chain(node, 12, 14);                          // bury the competitor: 11+3 = 14
        t = fc.tick();
        // the Orphan event or the canonical predicate at maturity disposed it
        rep.add("FC15 orphaned win leaves the pending set (never SETTLED) and the sidecar",
                reg11 && !node.ledger().is_pending(bid11) && !node.ledger().is_settled(bid11) &&
                fc.pending().empty() && count_lines(o.sidecar_path) == 0 && fc.stats().orphaned == 1,
                "orphaned=" + std::to_string(fc.stats().orphaned));
        rep.add("FC16 orphan: payee's effective_owed back to 0 (pure pending removal)",
                node.ledger().effective_owed(payee) == 0);
        (void)fc.drain_before_stop();
    }
    return rep;
}

} // namespace c2pool::v37n::xmr::o2
