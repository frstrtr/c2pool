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
//   (2) R-7 RECONCILIATION (2026-09-10) — the FOUND record books what the
//       COINBASE ACTUALLY PAID, against the SAME OwedLedger the coinbase drew
//       EffectiveOwed from (XmrNode::ledger()).
//         payout := the emitted CoinbaseOutput::Role::Owed set of the block's
//                   own coinbase, { identity : amount }, carried across the
//                   listener->main thread boundary in FoundBlockEvent (filled
//                   at the submit seam from the very snapshot whose bytes were
//                   submitted). NEVER Role::Fixed / Role::Sink — those keys were
//                   never credited, so booking them would drive their finalW
//                   permanently negative. NEVER a re-run of project_w4_owed —
//                   X6 may legitimately emit fewer rows than W4 proposed.
//         credit := {} — E_b, the per-key entitlement from the fold over b's
//                   burial-gated prefix, requires an XMR sharechain emission
//                   that does NOT exist yet (Track A2 S-1). The empty map is
//                   the honest value; when S-1 lands it fills
//                   FoundBlockEvent::credit and nothing else here changes.
//       This replaces the previous "amount-honest" record credit == payout ==
//       { --payee-* identity : FULL block reward }. That record was FICTIONAL
//       under option B: the operator's --payee key is not a payee of the v37
//       coinbase at all (the coinbase pays the K_fair owed rows plus the
//       residual sink), and it produced TWO empirically confirmed defects —
//         (a) effective_owed(payee) = finalW(0) - SUM_pending payout went
//             NEGATIVE by one full reward per concurrent pending FOUND;
//         (b) the settlement ledger the coinbase read was a DIFFERENT object
//             from the node ledger FINALIZE booked into, so it was never
//             decremented and re-proposed the SAME owed row at its full
//             EffectiveOwed on EVERY block — a no-double-pay violation of the
//             whitepaper section 9 / OI-W4-5 credit-at-finality contract.
//       Under option A (monerod get_block_template, --payout-address) the block
//       is not a v37 settlement at all and both maps are EMPTY: the ledger still
//       registers the block, its ledger_seq still bumps, no key is created.
//       INVARIANTS this restores (w4_settlement.hpp:531-542 / :485-500):
//         INV-1  effective_owed(k) >= 0 at every step, FOUND and FINALIZE alike;
//         INV-2  on_block_finalized moves effective_owed(k) by EXACTLY
//                +credit[k] (it removes the same payout from the pending term
//                that it subtracts from finalW) — invariant when credit == {},
//                never decreasing. effective_owed legitimately DROPS at FOUND:
//                that is the pending-payout deduction the coinbase drew on.
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
    std::optional<::v37::bytes32> payee;  // identity_key of the --payee-* descriptor.
                                          // INFORMATIONAL ONLY since R-7: it is the
                                          // operator's own wallet, NOT a coinbase payee
                                          // under option B, and is never booked.

    // ── R-7: what the block's coinbase ACTUALLY paid / credited ─────────────
    // coinbase_owed: the emitted CoinbaseOutput::Role::Owed outputs of THIS
    //   block, { identity_key : piconero }. Filled at the submit seam from the
    //   snapshot whose bytes were submitted (submit::BlockCandidate::
    //   coinbase_owed). EMPTY under option A and for a sink-only block.
    // credit: E_b, the per-key entitlement over b's burial-gated prefix.
    //   ALWAYS EMPTY today — there is no XMR sharechain fold yet (Track A2 S-1).
    //   The field exists so the S-1 landing is a fill, not a re-wiring.
    Amounts       coinbase_owed;
    Amounts       credit;
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
};

// ── the glue ────────────────────────────────────────────────────────────────
class FinalizeConnect {
public:
    struct PendingRec {
        std::uint64_t height = 0;
        std::optional<::v37::bytes32> payee;   // informational (see FoundBlockEvent::payee)
        std::uint64_t reward = 0;              // informational
        std::string   prev_id_hex;
        std::uint64_t found_unix_s = 0;
        // R-7: the MAPS THAT WERE BOOKED must survive a restart inside the
        // D_conf window. Before R-7 the sidecar carried only payee+reward and
        // the re-drive reconstructed a payout from them — so a restart could
        // re-drive a DIFFERENT payout than the block paid. Persisted since
        // sidecar schema v2.
        Amounts       coinbase_owed;           // the booked `payout` term
        Amounts       credit;                  // the booked `credit` term ({} until S-1)
        // A v1 (pre-R-7) sidecar line carries no maps. Such a record is
        // re-driven with EMPTY maps (the fail-safe direction: owed is never
        // over-decremented) and says so, loudly, once per boot.
        bool          legacy_v1 = false;
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
        long long     owed_booked = 0;   // R-7: Σ piconero of owed the FOUNDs extinguish
        std::uint64_t split_brain_refused = 0;   // payout > effective_owed (INV-1 precheck)
    };

    // Construct AFTER node.bring_up() (the finalize driver exists) and AFTER
    // main has printed construction_log() — the echo cursor starts at "now" so
    // nothing is printed twice.
    FinalizeConnect(XmrNode& node, const XmrNodeConfig& cfg, FoundBlockQueue& queue,
                    FinalizeConnectOptions opts = {})
        : m_node(node), m_cfg(cfg), m_q(queue), m_o(std::move(opts)),
          m_log_cursor(node.construction_log().size()) {}

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
            // R-7: re-drive the SAME maps the original FOUND booked, read back
            // from the sidecar — never re-derived from payee/reward.
            if (rec.legacy_v1)
                say("boot: PRE-R-7 (schema v1) sidecar record " + short_bid(bid) +
                    " carries no coinbase-owed map; re-driving with EMPTY credit/payout. "
                    "If the ledger already holds this bid pending (store replay) its booked "
                    "payout is unchanged (on_block_found is idempotent per bid); otherwise the "
                    "owed this block paid stays owed and will be paid again by a later block — "
                    "operator must reconcile by hand");
            const bool ok = m_node.on_network_block_won(rec.height, id, rec.credit, rec.coinbase_owed);
            if (!ok || !m_node.ledger().is_pending(bid)) {
                ++rep.stale_dropped;
                say("boot: sidecar " + short_bid(bid) + " not admitted by the node/ledger; dropped");
                continue;
            }
            m_pending[bid] = rec;
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

        std::vector<FoundBlockEvent> evs;
        t.drained = m_q.drain(evs);
        for (const auto& ev : evs) {
            RegisterResult r = register_found(ev);
            if (r.registered && !r.duplicate) ++t.registered;
            else if (!r.registered)            ++t.refused;
        }
        reconcile(t);
        echo_node_log();                       // the node's own "win: FOUND ..." lines
        progress();
        return t;
    }

    // ── shutdown: one last drain so a win that landed after the final tick has
    //    its FOUND written before node.stop(). Order: listener.stop() ->
    //    fc.drain_before_stop() -> node.stop().
    TickReport drain_before_stop() { return tick(); }

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

        // ── R-7: book what the coinbase ACTUALLY paid ───────────────────────
        // payout := the emitted Role::Owed set (empty under option A / for a
        //           sink-only block); credit := E_b ({} until Track A2 S-1).
        // A payout key must be one the ledger CREDITED (w4_settlement.hpp:
        // 485-500 subtracts the payout term from finalW), so a row whose amount
        // is <= 0 is dropped rather than booked — a defensive fail-closed, the
        // emitted set never carries one.
        Amounts payout;
        for (const auto& [k, v] : ev.coinbase_owed) if (v > 0) payout[k] = v;
        Amounts credit;
        for (const auto& [k, v] : ev.credit) if (v != 0) credit[k] = v;

        // NON-NEGATIVITY PRECHECK (INV-1, fail-closed). propose_coinbase caps
        // each take at EffectiveOwed, so a well-formed payout can never push a
        // key negative; a payout that WOULD is proof that the coinbase was built
        // against a different ledger than this one — exactly the split-brain R-7
        // closes. Refuse loudly rather than poison the ledger. (The block is
        // already on-chain either way; refusing costs the v37 record, booking a
        // negative costs every future K_fair proposal.)
        for (const auto& [k, v] : payout) {
            const long long eo = m_node.ledger().effective_owed(k);
            if (v > eo) {
                ++m_stats.split_brain_refused;
                return refuse(r, bid,
                    "R-7 REFUSED: coinbase pays " + std::to_string(v) + " to key " +
                    hex_of(k).substr(0, 12) + "… but its effective_owed is only " +
                    std::to_string(eo) + " — the coinbase was built against a DIFFERENT "
                    "ledger than the finalize driver writes (split-brain); not booking a "
                    "negative owed");
            }
        }

        std::string why_valueless;
        if (payout.empty() && credit.empty())
            why_valueless = ev.coinbase_owed.empty()
                ? "no K_fair owed outputs in this coinbase (option A, or the whole reward "
                  "went to the residual sink) and no E_b credit yet (Track A2 S-1 pending)"
                : "every coinbase owed row was non-positive";

        PendingRec rec;
        rec.height = ev.height;
        rec.payee = ev.payee;
        rec.reward = ev.reward_piconero;
        rec.prev_id_hex = lower_hex(ev.prev_id_hex);
        rec.found_unix_s = ev.found_unix_s;
        rec.coinbase_owed = payout;
        rec.credit = credit;

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
        long long owed_paid = 0;
        for (const auto& [k, v] : payout) { (void)k; owed_paid += v; }
        m_stats.owed_booked += owed_paid;
        say("FOUND registered " + short_bid(bid) + " h=" + std::to_string(ev.height) +
            " reward=" + std::to_string(ev.reward_piconero) + " piconero" +
            " owed_rows=" + std::to_string(payout.size()) +
            " owed_paid=" + std::to_string(owed_paid) +
            " credit_rows=" + std::to_string(credit.size()) +
            " (operator payee=" +
            (ev.payee ? hex_of(*ev.payee).substr(0, 12) + "…" : std::string("-")) +
            ", informational)" +
            (why_valueless.empty() ? "" : " [VALUELESS record: " + why_valueless + "]") +
            (ev.worker.empty() ? "" : " worker=" + ev.worker) +
            " tid=" + std::to_string(ev.template_id) + " nonce=" + std::to_string(ev.nonce) +
            " -> finalizes when hw >= " + std::to_string(ev.height + m_cfg.d_conf) +
            " (D_conf=" + std::to_string(m_cfg.d_conf) + ")");
        r.registered = true;
        return r;
    }

    // (R-7, 2026-09-10) The former `amounts_from(payee, reward)` helper — which
    // synthesised credit == payout == { --payee-* identity : FULL block reward }
    // — is GONE. It booked a record no coinbase ever paid; see the banner. The
    // FOUND maps now come from the block's own emitted outputs, carried in
    // FoundBlockEvent, and option A books the degenerate {}/{} directly.

    // ── read seams (main thread) ────────────────────────────────────────────
    const std::map<std::string, PendingRec>& pending()       const { return m_pending; }
    const std::map<std::string, PendingRec>& unrecoverable() const { return m_unrecoverable; }
    const Stats& stats() const { return m_stats; }

    // R-7 acceptance probe: min over effective_owed_all(). Must be >= 0 at every
    // point of a healthy run, INCLUDING while blocks are pending. 0 on an empty
    // ledger. This is the number the regtest re-proof records.
    long long min_effective_owed() const {
        long long m = 0;
        for (const auto& [k, v] : m_node.ledger().effective_owed_all()) { (void)k; if (v < m) m = v; }
        return m;
    }

private:
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
                // R-7 observability: effective_owed of the keys THIS block paid
                // (the operator's --payee-* key is not one of them under option
                // B), plus the ledger-wide minimum. Both must stay >= 0 for the
                // whole run — that is the acceptance criterion the split-ledger
                // wiring violated by one full reward per pending FOUND.
                std::string per_key;
                for (const auto& [k, v] : rec.coinbase_owed) {
                    (void)v;
                    per_key += " effective_owed(" + hex_of(k).substr(0, 12) + "…)=" +
                               std::to_string(m_node.ledger().effective_owed(k));
                }
                say("FINALIZED " + short_bid(bid) + " h=" + std::to_string(rec.height) +
                    " SETTLED at bin_height=" + std::to_string(rec.height + m_cfg.d_conf) +
                    per_key +
                    " min_effective_owed=" + std::to_string(min_effective_owed()) +
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

public:
    // ── sidecar codec: one record per line, space-separated, no escaping needed
    //    (bids/keys are hex; '-' = absent).
    //    PUBLIC since R-7 so the self-check can pin the schema-v2 round trip and
    //    the v1 legacy path directly, without standing up a live node.
    //
    //    SCHEMA v2 (R-7, 2026-09-10) — the BOOKED MAPS are persisted, because a
    //    restart inside the D_conf window must re-drive the SAME payout the block
    //    paid, not one re-derived from payee/reward:
    //      2 <bid64> <height> <payee64|-> <reward> <prev64|-> <found_unix_s>
    //        <n_owed> [<key64>:<amount> ...] <n_credit> [<key64>:<amount> ...]
    //
    //    SCHEMA v1 (pre-R-7) is still PARSED, so a node that crashed under the
    //    old build still finds its pending FOUNDs at boot. A v1 record carries no
    //    maps: it is flagged legacy_v1 and re-driven with EMPTY credit/payout
    //    (the fail-safe direction — owed is never over-decremented — and loudly
    //    reported). v1 is never WRITTEN again.
    static std::string amounts_field(const Amounts& a) {
        std::string s = std::to_string(a.size());
        for (const auto& [k, v] : a) s += " " + hex_of(k) + ":" + std::to_string(v);
        return s;
    }
    static bool parse_amounts_field(std::istringstream& is, Amounts& out) {
        out.clear();
        unsigned long long n = 0;
        if (!(is >> n)) return false;
        if (n > 100000) return false;              // sanity bound: a coinbase has far fewer outputs
        for (unsigned long long i = 0; i < n; ++i) {
            std::string tok;
            if (!(is >> tok)) return false;
            const std::size_t colon = tok.find(':');
            if (colon != 64) return false;         // exactly a 64-hex key then ':'
            ::v37::bytes32 k{};
            if (!hash_from_hex(lower_hex(tok.substr(0, 64)), k)) return false;
            long long v = 0;
            try { v = std::stoll(tok.substr(colon + 1)); } catch (...) { return false; }
            out[k] = v;
        }
        return true;
    }

    static std::string sidecar_line(const std::string& bid, const PendingRec& r) {
        std::string s = "2 " + bid + " " + std::to_string(r.height) + " " +
                        (r.payee ? hex_of(*r.payee) : std::string("-")) + " " +
                        std::to_string(r.reward) + " " +
                        (r.prev_id_hex.size() == 64 ? r.prev_id_hex : std::string("-")) + " " +
                        std::to_string(r.found_unix_s) + " " +
                        amounts_field(r.coinbase_owed) + " " +
                        amounts_field(r.credit) + "\n";
        return s;
    }
    static bool parse_sidecar_line(const std::string& line, std::string& bid, PendingRec& r) {
        std::istringstream is(line);
        std::string ver, payee, prev;
        unsigned long long h = 0, reward = 0, ts = 0;
        if (!(is >> ver >> bid >> h >> payee >> reward >> prev >> ts)) return false;
        if (ver != "1" && ver != "2") return false;
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
        if (ver == "1") {                 // pre-R-7 record: no maps on the wire
            r.legacy_v1 = true;
            r.coinbase_owed.clear();
            r.credit.clear();
            return true;
        }
        if (!parse_amounts_field(is, r.coinbase_owed)) return false;
        if (!parse_amounts_field(is, r.credit)) return false;
        return true;
    }

private:
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
    std::map<std::string, PendingRec> m_unrecoverable;  // kept in the sidecar so the boot warning repeats
    Stats         m_stats;
    std::size_t   m_log_cursor = 0;
    std::uint64_t m_last_hw_printed = ~std::uint64_t{0};
};

} // namespace c2pool::v37n::xmr::o2

// ===========================================================================
// SELF-CHECK — network-free, RandomX-free, against the monerod STUB; the same
// shape as xmr_node_smoke.hpp so it can run under `--mock-smoke` / the CI
// smoke target.
//
// RE-PINNED for R-7 (2026-09-10). The old FC3/FC10/FC16 asserted the FICTIONAL
// record (credit == payout == { --payee-* : FULL reward }, effective_owed ==
// -reward while pending). They ENCODED the defect. They now assert the
// reconciled contract:
//   INV-1  effective_owed(k) >= 0 at EVERY step (FOUND and FINALIZE alike);
//   INV-2  a FINALIZE moves effective_owed(k) by EXACTLY +credit[k] — invariant
//          when credit == {}, never decreasing. effective_owed legitimately
//          DROPS at FOUND: that is the pending-payout deduction the coinbase
//          drew on, and asserting monotonicity across FOUND would be wrong.
//
// Proves, end to end: an S-1-shaped credit block arms owed -> a settlement win
// whose coinbase pays part of that owed -> restart inside the D_conf window ->
// the schema-v2 sidecar re-drives the SAME payout map (never one re-derived
// from payee/reward) -> FINALIZE at bin_height = H_b + D_conf extinguishes the
// owed EXACTLY ONCE -> sidecar retired; plus the split-brain precheck, the
// late-FOUND / malformed / zero-bid refusals, the valueless (option-A) record,
// idempotence, the v1 legacy-sidecar path, and the orphan disposition.
// ===========================================================================
#include "xmr_node_smoke.hpp"   // smoke::Report, apply_row, blk_id, key_of, test_point_check
#include "impl/xmr/node/monerod_transport.hpp"   // MockMonerodTransport

namespace c2pool::v37n::xmr::o2 {

inline smoke::Report finalize_connect_selfcheck(const std::filesystem::path& tmp_root) {
    using c2pool::xmr::node::MockMonerodTransport;
    smoke::Report rep;
    const ::v37::ChainId CHAIN = 7;
    const std::uint64_t  D_CONF = 3;
    const std::uint64_t  REWARD = 600000000000ull;    // 0.6 XMR in piconero (block reward)
    // The K_fair owed this lane holds, and what two coinbases pay out of it.
    const long long SEED  = 600000000000ll;           // E_b credit that ARMS the owed
    const long long TAKE  = 100000000000ll;           // block 5's Role::Owed output
    const long long TAKE2 =  50000000000ll;           // block 11's (orphaned) output

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
    const std::string bid2  = hex_of(smoke::blk_id(2));
    const std::string bid5  = hex_of(smoke::blk_id(5));
    const std::string bid8  = hex_of(smoke::blk_id(8));
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
    // One owed row: { payee : amount }. The SHAPE of an emitted Role::Owed set.
    auto owed_of = [&](long long amount) {
        Amounts a;
        if (amount != 0) a[payee] = amount;
        return a;
    };

    // ── phase 1: node A — arm owed, win at 5, bury 2 (< D_conf), then "crash" ─
    {
        MockMonerodTransport mock;
        XmrNode node(cfg, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) {
            rep.add("FC0 bring_up (node A)", false, e.what()); return rep;
        }
        FinalizeConnect fc(node, cfg, q, o);
        auto boot = fc.reseed_after_bring_up();
        rep.add("FC1 fresh boot: no sidecar, nothing reseeded",
                !boot.sidecar_present && boot.reseeded == 0 && boot.reregistered == 0);

        // ── ARM the owed through the DURABLE path (a FOUND carrying an
        //    S-1-shaped E_b credit and no coinbase owed outputs), so the credit
        //    is in the settle-store write-ahead log and survives the restart.
        chain(node, 1, 2);
        FoundBlockEvent seed_ev;
        seed_ev.height = 2; seed_ev.block_id_hex = bid2;
        seed_ev.prev_id_hex = hex_of(smoke::blk_id(1));
        seed_ev.reward_piconero = REWARD; seed_ev.payee = payee;
        seed_ev.credit = owed_of(SEED);              // E_b (Track A2 S-1 shape)
        q.push(seed_ev);
        auto t = fc.tick();
        const long long eo_before_credit_finalize = node.ledger().effective_owed(payee);
        rep.add("FC-A0 a credit-only FOUND registers and leaves effective_owed UNCHANGED "
                "(credit lands at FINALITY, not at FOUND — OI-W4-5)",
                t.registered == 1 && node.ledger().is_pending(bid2) &&
                eo_before_credit_finalize == 0,
                "eo=" + std::to_string(eo_before_credit_finalize));

        chain(node, 3, 5);                            // hw=5 => bin_height 2 => FINALIZE bid2
        t = fc.tick();
        rep.add("FC-A1 INV-2: FINALIZE raised effective_owed by EXACTLY credit[k]",
                t.settled == 1 && node.ledger().is_settled(bid2) &&
                node.ledger().effective_owed(payee) == eo_before_credit_finalize + SEED,
                "eo=" + std::to_string(node.ledger().effective_owed(payee)));

        // ── the settlement win: its coinbase pays TAKE of the armed owed ──────
        FoundBlockEvent ev;
        ev.height = 5; ev.block_id_hex = bid5; ev.prev_id_hex = hex_of(smoke::blk_id(4));
        ev.reward_piconero = REWARD; ev.payee = payee; ev.worker = "rig0"; ev.template_id = 42;
        ev.coinbase_owed = owed_of(TAKE);             // the EMITTED Role::Owed set
        q.push(ev); q.push(ev);                       // duplicate push (idempotent per bid)
        t = fc.tick();
        rep.add("FC2 queued win -> on_network_block_won: ledger pending, idempotent per bid",
                t.drained == 2 && t.registered == 1 && t.refused == 0 &&
                fc.pending().size() == 1 && node.ledger().is_pending(bid5),
                "drained=" + std::to_string(t.drained) + " registered=" + std::to_string(t.registered));
        rep.add("FC3 R-7 INV-1: effective_owed(payee) == seeded - take and is NON-NEGATIVE "
                "while the block is pending (never -reward)",
                node.ledger().effective_owed(payee) == SEED - TAKE &&
                node.ledger().effective_owed(payee) >= 0 && fc.min_effective_owed() == 0,
                "eo=" + std::to_string(node.ledger().effective_owed(payee)) +
                " min=" + std::to_string(fc.min_effective_owed()));
        rep.add("FC3b the FOUND booked EXACTLY the coinbase-paid owed set",
                fc.pending().count(bid5) == 1 &&
                fc.pending().at(bid5).coinbase_owed == owed_of(TAKE) &&
                fc.pending().at(bid5).credit.empty() &&
                fc.stats().owed_booked == TAKE);

        // FC3c SPLIT-BRAIN PRECHECK: a coinbase claiming to pay more owed than
        // this ledger holds is proof it was built against a DIFFERENT ledger.
        // Refused loudly instead of poisoning effective_owed negative.
        {
            FoundBlockEvent over = ev;
            over.block_id_hex = hex_of(smoke::blk_id(6));
            over.height = 6;
            over.coinbase_owed = owed_of(SEED * 4);
            q.push(over);
            const auto before = node.ledger().effective_owed(payee);
            t = fc.tick();
            rep.add("FC3c split-brain payout (> effective_owed) is REFUSED, ledger untouched",
                    t.refused == 1 && fc.stats().split_brain_refused == 1 &&
                    !node.ledger().is_pending(hex_of(smoke::blk_id(6))) &&
                    node.ledger().effective_owed(payee) == before);
        }

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
        late.coinbase_owed.clear();
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
        rep.add("FC8a the store replay restored the ARMED owed and the pending payout "
                "(effective_owed == seeded - take across the restart)",
                node.ledger().effective_owed(payee) == SEED - TAKE,
                "eo=" + std::to_string(node.ledger().effective_owed(payee)));

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
        // R-7: the SCHEMA-v2 sidecar round-trips the booked payout map BYTE-FOR-
        // BYTE. Before the schema bump the re-drive rebuilt a payout out of
        // payee+reward — a DIFFERENT map from the one the block paid.
        rep.add("FC8c sidecar v2 round-trip: the re-driven payout map is byte-equal to the "
                "map the block paid (not re-derived from payee/reward)",
                fc.pending().count(bid5) == 1 &&
                fc.pending().at(bid5).coinbase_owed.size() == 1 &&
                fc.pending().at(bid5).coinbase_owed.count(payee) == 1 &&
                fc.pending().at(bid5).coinbase_owed.at(payee) == TAKE &&
                !fc.pending().at(bid5).legacy_v1);

        chain(node, 5, 8);                            // index rebuilt from 5; hw -> 8 = 5+3
        const long long eo_before = node.ledger().effective_owed(payee);
        auto t = fc.tick();
        rep.add("FC9 FOUND -> FINALIZE at D_conf burial after restart (bin_height = 5+3 = 8)",
                t.settled == 1 && node.ledger().is_settled(bid5) && fc.pending().empty(),
                "settled=" + std::to_string(t.settled));
        rep.add("FC10 R-7 INV-2: FINALIZE with credit == {} leaves effective_owed UNCHANGED "
                "(the take was extinguished exactly ONCE, at FOUND)",
                node.ledger().effective_owed(payee) == eo_before &&
                node.ledger().effective_owed(payee) == SEED - TAKE,
                "eo=" + std::to_string(node.ledger().effective_owed(payee)));
        rep.add("FC10b INV-1 holds across the whole run: no ledger row is negative",
                fc.min_effective_owed() == 0);
        rep.add("FC11 sidecar retired after FINALIZE", count_lines(o.sidecar_path) == 0);
        bool logged = false;
        for (const auto& l : node.construction_log())
            if (l.find("SETTLED at bin_height=8") != std::string::npos) logged = true;
        rep.add("FC12 the node logged the FINALIZE step with the per-height bin_height (echoed by tick)", logged);

        // OPTION-A / valueless win: monerod's own template pays no v37 owed, so
        // the record is the degenerate {}/{} — the ledger registers the block and
        // its ledger_seq bumps, but NO key is created and NO owed moves.
        const long long eo_pre_a = node.ledger().effective_owed(payee);
        const std::size_t keys_pre_a = node.ledger().effective_owed_all().size();
        FoundBlockEvent v; v.height = 8; v.block_id_hex = bid8;
        q.push(v);
        t = fc.tick();
        rep.add("FC13 option-A / valueless win registers as the degenerate {}/{} record",
                t.registered == 1 && node.ledger().is_pending(bid8) &&
                fc.pending().at(bid8).coinbase_owed.empty() &&
                fc.pending().at(bid8).credit.empty() &&
                node.ledger().effective_owed(payee) == eo_pre_a &&
                node.ledger().effective_owed_all().size() == keys_pre_a);
        chain(node, 9, 11);
        t = fc.tick();
        rep.add("FC14 valueless win finalizes at 8+3=11 and moves no owed",
                t.settled == 1 && node.ledger().is_settled(bid8) &&
                node.ledger().effective_owed(payee) == eo_pre_a);

        // orphan disposition: win at 11 paying TAKE2, then a competing 11 wins
        FoundBlockEvent w; w.height = 11; w.block_id_hex = bid11; w.payee = payee;
        w.reward_piconero = REWARD; w.coinbase_owed = owed_of(TAKE2);
        q.push(w);
        t = fc.tick();
        const bool reg11 = t.registered == 1 && node.ledger().is_pending(bid11);
        const bool owed_dropped_at_found =
            node.ledger().effective_owed(payee) == SEED - TAKE - TAKE2;
        smoke::apply_row(node, 11, smoke::blk_id(99), smoke::blk_id(10));   // reorg at 11
        chain(node, 12, 14);                          // bury the competitor: 11+3 = 14
        t = fc.tick();
        // the Orphan event or the canonical predicate at maturity disposed it
        rep.add("FC15 orphaned win leaves the pending set (never SETTLED) and the sidecar",
                reg11 && owed_dropped_at_found &&
                !node.ledger().is_pending(bid11) && !node.ledger().is_settled(bid11) &&
                fc.pending().empty() && count_lines(o.sidecar_path) == 0 && fc.stats().orphaned == 1,
                "orphaned=" + std::to_string(fc.stats().orphaned));
        rep.add("FC16 orphan: the pending payout is returned — effective_owed back to "
                "seeded - take (pure pending removal, never a clawback)",
                node.ledger().effective_owed(payee) == SEED - TAKE &&
                fc.min_effective_owed() == 0,
                "eo=" + std::to_string(node.ledger().effective_owed(payee)));
        (void)fc.drain_before_stop();
    }

    // ── phase 3: the sidecar CODEC itself (schema v2 + the v1 legacy path) ────
    {
        FinalizeConnect::PendingRec r;
        r.height = 4242;
        r.payee = payee;
        r.reward = REWARD;
        r.prev_id_hex = hex_of(smoke::blk_id(4));
        r.found_unix_s = 1700000000ull;
        r.coinbase_owed[payee] = TAKE;
        r.coinbase_owed[smoke::key_of(0xA1)] = TAKE2;
        r.credit[smoke::key_of(0xB2)] = SEED;

        const std::string line = FinalizeConnect::sidecar_line(bid5, r);
        std::string bid_out;
        FinalizeConnect::PendingRec back;
        const bool ok = FinalizeConnect::parse_sidecar_line(line, bid_out, back);
        rep.add("FC17 sidecar v2 codec round-trips both maps exactly",
                ok && bid_out == bid5 && back.height == r.height &&
                back.coinbase_owed == r.coinbase_owed && back.credit == r.credit &&
                !back.legacy_v1);

        // A pre-R-7 (v1) line still parses, carries no maps, and says so.
        const std::string v1 = "1 " + bid5 + " 4242 " + hex_of(payee) + " " +
                               std::to_string(REWARD) + " " + hex_of(smoke::blk_id(4)) +
                               " 1700000000";
        FinalizeConnect::PendingRec legacy;
        std::string legacy_bid;
        const bool ok1 = FinalizeConnect::parse_sidecar_line(v1, legacy_bid, legacy);
        rep.add("FC18 a pre-R-7 (schema v1) sidecar line still parses, with EMPTY maps and the "
                "legacy flag set (fail-safe: owed is never over-decremented)",
                ok1 && legacy.legacy_v1 && legacy.coinbase_owed.empty() && legacy.credit.empty() &&
                legacy.height == 4242);

        FinalizeConnect::PendingRec junk;
        std::string junk_bid;
        rep.add("FC19 a truncated v2 line is REFUSED (never a half-parsed payout map)",
                !FinalizeConnect::parse_sidecar_line(
                    "2 " + bid5 + " 4242 - 0 - 0 2 " + hex_of(payee) + ":1", junk_bid, junk));
    }
    return rep;
}

} // namespace c2pool::v37n::xmr::o2
