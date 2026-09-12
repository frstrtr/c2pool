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
//   (2) ★ S-1b — THE E_b FOLD. This step USED to register
//         credit == payout == { identity_key(payout ref) : reward },
//       which made FINALIZE do finalW += credit; finalW -= payout and net
//       EXACTLY to zero: owed_digest never left the empty sha256d("V37O")
//       anchor b4db1ded… and the option-B tx_extra 0x03 merge-mining leaf was a
//       constant. It now folds the real ENTITLEMENT out of the lane cut the
//       engine has published — settle::fold_eb (xmr_s1_fold.hpp), the SAME
//       single credit-path entry point XbtcNode::on_block_won uses — and
//       registers credit = E_b with an EMPTY payout, because a freshly found
//       Monero block broadcasts no settled-owed output keyed to a lane identity
//       (option A pays monerod's own --payout-address; option B's K_fair
//       coinbase is assembled before burial). The whole entitlement therefore
//       carries forward as owed, and that carry is what owed_digest commits to.
//       Refuse-LOUD, register anyway: a block we mined is a real block, so a
//       no-view / non-ratified-geometry / reward==0 / empty-E_b fold is stamped
//       VALUELESS, counted and narrated — and still registered.
//   (2a) ★ R-7 — THE PAYOUT LEG (the option-B deadlock). S-1b registered
//       `payout = {}` on the premise that a freshly found XMR block broadcasts
//       no settled-owed output. That is true of option A and FALSE of option B,
//       whose whole purpose is a coinbase that pays owed balances. Left empty,
//       the balances the block just paid stay owed, the next template proposes
//       them AGAIN (double-pay), and owed climbs by a whole E_b per block until
//       owed >= budget — at which point K_fair takes the entire reward, the
//       mandated residual sink drops out of the coinbase, the §13 shape gate
//       (xmr_settlement_coinbase_shape.hpp) refuses EVERY template, the miners
//       are parked on a stale height and the daemon books duplicate FOUNDs at
//       it. `payout` is now the block's OWED-ROLE coinbase outputs, carried
//       from the template snapshot its bytes were built from (fixed + residual
//       sink excluded — neither is credited to a ledger key, so neither may be
//       deducted from one) and PERSISTED in the sidecar so a restart re-drives
//       the same deduction. FINALIZE then does finalW += credit; finalW -=
//       payout with two DIFFERENT maps, which is the merged DASH R-7 shape
//       (btc_node.hpp on_block_won). Registering credit == payout nets every
//       block to zero — the S-1b defect; registering payout == {} strands the
//       pool — this one.
//   (2b) ★ S-1c — A PEER'S WIN. offer_peer_win() takes the flat cut descriptor
//       a peer's block-winning carrier carried (wire v0x02) and re-runs the
//       SAME fold at the WINNER'S prefix, read back out of OUR own settlement
//       ring, then drives OUR ledger through the EXISTING on_block_found /
//       on_block_finalized API. Without it a peer accounts the block-winning
//       carrier as an ordinary share, never credits E_b, and the two nodes
//       commit to different owed ledgers while both look healthy.
//   (2c) ★ canonical_coinbase_matches = (a) — A SETTLING PEER WIN. S-1c alone
//       converges only until the first block whose option-B coinbase actually
//       PAYS owed: from there the winner deducts a payout map the receiver does
//       not have (it is unbounded and deliberately off the frozen v0x02 wire),
//       and the receiver's only honest move was to refuse the block, forking
//       the ledgers. Under ruling (a) the receiver RECOMPUTES that map from its
//       OWN K_fair run for the same height — OwedLedger::propose_coinbase, the
//       same deterministic §4.6 selection the node already performs for its own
//       template — and books it as the payout leg. The recompute is a pure
//       lookup in xmr_peer_payout_recompute.hpp, admitted only when our
//       owed_digest at that build equals the winner's at the win; every other
//       shape keeps the loud fail-closed refusal. A second CALLER of K_fair,
//       never a second K_fair.
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
#include <functional>
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
#include "xmr_peer_payout_recompute.hpp"           // ★ (a) peer-recompute: XmrPeerPayoutOutcome
#include "xmr_s1_fold.hpp"                         // ★ S-1b: fold_at_tip / fold_at_peer_cut (settle::fold_eb)
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

// Σ of an amount map, for the one-line human account of a payout leg. Signed,
// because OwedLedger::Amounts is signed and a negative row is a real (if loud)
// state this must be able to print rather than wrap.
inline long long amounts_sum(const Amounts& a) {
    long long s = 0;
    for (const auto& [k, v] : a) { (void)k; s += v; }
    return s;
}

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

    // ── ★ R-7 PAYOUT LEG: what this block's coinbase ACTUALLY PAID the ledger ─
    // The OWED-ROLE outputs of the coinbase that was broadcast, {identity_key :
    // piconero}, EXCLUDING the fixed outputs and the residual sink (neither is
    // ever credited to a ledger key, so neither may be deducted from one).
    //
    // Option A leaves this EMPTY and `payout_known` false: monerod's own
    // template pays a single output to --payout-address, which is not a v37
    // ledger identity, so the block settles nothing and the whole entitlement
    // carries. Option B fills it from the assembled K_fair template it was mined
    // on — that coinbase pays owed balances DIRECTLY, and a block that paid them
    // must decrement them or the next template pays the same balances again.
    //
    // `payout_known` is the fail-closed discriminator and is NOT the same as
    // "payout is empty": an option-B win whose template can no longer be
    // resolved (evicted from the retain ring) has an UNKNOWN payout, and
    // registering that as an empty one would book a credit for a coinbase that
    // has already paid it out. Such a win is REFUSED, loudly.
    Amounts payout;
    bool    payout_known = false;
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

    // ── ★ R-7: is this node serving a coinbase that PAYS THE OWED LEDGER? ────
    // ON for option B bound to the node's own ledger — every found block's
    // coinbase settles owed balances, so a FOUND whose payout map cannot be
    // named is REFUSED rather than booked as "paid nobody".
    // OFF for option A (monerod's template pays --payout-address, never a
    // ledger key) and for an option-B run whose template is built from a
    // SEPARATE proof ledger (--owed-demo-amount): there the coinbase's owed
    // outputs belong to a different ledger than the one FOUND/FINALIZE move, so
    // deducting them HERE would settle balances this ledger never credited.
    bool require_payout = false;
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
        // ★ S-1b: the CUT this win's E_b fold read at. Persisted (sidecar v2) so
        // a restart inside the D_conf window re-drives the FOUND at the SAME
        // prefix rather than re-folding at whatever the lane has become since —
        // which would credit a different E_b for the same block.
        std::uint64_t  cut_next_pos = 0;
        ::v37::bytes32 cut_spine_digest{};
        bool           cut_folded = false;
        // ★ R-7: the payout leg this FOUND was BOOKED with — the owed-role
        // coinbase outputs the block broadcast. Persisted (sidecar v3) because
        // a restart must re-drive the SAME deduction: the block is on the chain
        // and has already paid these keys, and a re-drive that booked an empty
        // payout would restore balances the coinbase already settled and pay
        // them a second time.
        Amounts payout;
    };
    struct RegisterResult {
        bool        registered = false;
        bool        duplicate  = false;   // already pending here (idempotent)
        std::string reason;               // set when !registered
        XmrEbCut    cut;                  // ★ S-1b: the fold this win credited
    };
    struct BootReport {
        bool        sidecar_present = false;
        std::size_t reseeded      = 0;   // ledger-pending bids re-driven into the fresh driver
        std::size_t reregistered  = 0;   // sidecar without a FOUND event (crash in the window) -> registered now
        std::size_t stale_dropped = 0;   // already SETTLED / already stepped past
        std::size_t unrecoverable = 0;   // ledger-pending but height <= cursor: will never be stepped
        std::size_t malformed     = 0;
        // ★ S-1b: sidecar records RE-REGISTERED after a crash that lost the FOUND
        // write-ahead. Their E_b cannot be reproduced — the fresh engine has an
        // empty settlement ring, so the winner's prefix P is not retained — so
        // the block is registered with an EMPTY credit and this counter is the
        // only honest account of the entitlement that was lost.
        std::size_t eb_irrecoverable = 0;
        // ★ R-7: sidecar records re-driven WITH a non-empty payout leg. Unlike
        // E_b, the payout IS recoverable — it was written down, not recomputed.
        std::size_t payout_redriven = 0;
    };
    struct TickReport {
        std::size_t drained = 0, registered = 0, refused = 0, settled = 0, orphaned = 0;
        // ★ S-1c
        std::size_t peer_drained = 0, peer_credited = 0, peer_refused = 0, peer_deferred = 0;
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
        // ★ R-7 payout leg. `payout_booked` counts wins registered with a
        // NON-EMPTY payout map (an option-B coinbase that actually settled owed
        // balances); `payout_unknown` counts option-B wins REFUSED because the
        // block's owed-role outputs could not be named. A live option-B pool
        // whose payout_booked stays at 0 while owed grows is NOT settling —
        // that is the defect this leg closes, visible without reading a log.
        std::uint64_t payout_booked = 0, payout_unknown = 0;
        // The RUNNING MINIMUM of EffectiveOwed over every key, sampled on every
        // tick rather than only when a status line happens to print. It is the
        // one number that falsifies "no double-pay": EffectiveOwed = finalW -
        // Σ_pending payout, so it can only go below zero if more was PAID than
        // was ever OWED. A dip is fail-safe in the moment (a template with
        // nothing to propose pays the residual sink, and the owed CARRIES) but
        // it is still a pool paying out money it had not booked as owed, and
        // sampling it at 20-second status intervals would hide it.
        long long min_effective_owed = 0;
        // The RUNNING MINIMUM of the FINALIZED partition, finalW, over every
        // key. This is the SOLVENCY floor, and it is the one that must never go
        // below zero.
        //
        // The two are different claims and only this one is an error when it
        // dips. EffectiveOwed = finalW - Σ_pending payout is a RESERVATION:
        // every in-flight coinbase that MIGHT land has its owed outputs held
        // back so no later template can propose them again. On a height with
        // rival own blocks (three were observed on one regtest height, all mined
        // on the same template) every rival reserves the same proposal, so the
        // reservation floor legitimately goes negative — "all of the owed is
        // currently spoken for" — and recovers as the losers are ORPHANED and
        // their reservations released. Under-proposing for a few blocks is the
        // safe direction; it delays a payee, it never overpays one.
        //
        // finalW moves only at FINALIZE, by credit - payout, and only for the
        // ONE block per height that the chain actually kept. If it ever went
        // negative the pool would have finalized more coinbase payouts than
        // entitlements — money paid that was never owed. That is the real
        // double-pay, and it has stayed at zero.
        long long min_final_owed = 0;
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
            //
            // ★ S-1b: the credit passed here is IGNORED in the `pending` case —
            // OwedLedger::on_block_found is idempotent per bid and the ledger
            // already holds the E_b the original fold produced (RecoveryDriver
            // replayed the FOUND from the store). In the `!pending` case it is
            // NOT ignored, and it cannot be reproduced: this process has a fresh
            // engine whose settlement ring does not retain the winner's prefix P,
            // and folding at the current (empty) lane instead would credit a
            // DIFFERENT number for the same block. So the block is registered
            // with an EMPTY credit — its record exists, the F1 driver can still
            // settle or dispose it — and the lost entitlement is counted and
            // named rather than papered over with a plausible figure.
            Amounts credit;   // see above: never re-folded at a foreign cut
            // ★ R-7: the payout leg IS reproducible, because it was persisted
            // (sidecar v3) rather than recomputed. The block is on the chain and
            // its coinbase has already paid these keys; re-driving it with an
            // empty payout would restore balances the chain already settled and
            // let the next template pay them a second time. This is the half of
            // the record that must survive a restart even when E_b cannot.
            Amounts payout = rec.payout;
            if (!pending) {
                ++rep.eb_irrecoverable;
                say("boot: E_b IRRECOVERABLE for RE-REGISTERED " + short_bid(bid) + " h=" +
                    std::to_string(rec.height) + " (cut P=" + std::to_string(rec.cut_next_pos) +
                    (rec.cut_folded ? " spine=" + hex_of(rec.cut_spine_digest)
                                    : " [sidecar v1: no cut recorded]") +
                    ") — this process's settlement ring does not retain that prefix, so the "
                    "block is registered with an EMPTY credit: its entitlement is LOST and the "
                    "owed ledger is short by exactly that block's E_b");
            }
            const bool ok = m_node.on_network_block_won(rec.height, id, credit, payout);
            if (!ok || !m_node.ledger().is_pending(bid)) {
                ++rep.stale_dropped;
                say("boot: sidecar " + short_bid(bid) + " not admitted by the node/ledger; dropped");
                continue;
            }
            m_pending[bid] = rec;
            note_known(rec.height, bid);
            m_race.observe_own(rec.height, bid, rec.found_unix_s);
            if (pending) ++rep.reseeded; else ++rep.reregistered;
            if (!payout.empty()) ++rep.payout_redriven;
            say(std::string("boot: ") + (pending ? "re-drove pending FOUND " : "RE-REGISTERED lost FOUND ") +
                short_bid(bid) + " h=" + std::to_string(rec.height) +
                " payout=" + std::to_string(payout.size()) + " keys/" +
                std::to_string(amounts_sum(payout)) + " pico" +
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
        drain_peer_wins(t);                    // ★ S-1c, BEFORE reconcile so a peer
                                               // FOUND registered this tick can still
                                               // be settled by it at maturity
        reconcile(t);
        race_gate(t);                          // c2pool#1551 -- after reconcile, so a
                                               // credit the driver just took is already
                                               // recorded when the gate cross-checks it
        sample_min_effective_owed();           // ★ R-7: every tick, not every status line
        echo_node_log();                       // the node's own "win: FOUND ..." lines
        progress();
        return t;
    }

    // Self-check seam: the sidecar codec, so a KAT can assert that what was
    // written to disk is what comes back off it (a payout leg that round-trips
    // only through the object it came from proves nothing about a restart).
    static bool parse_sidecar_line_for_test(const std::string& line, std::string& bid,
                                            PendingRec& r) {
        return parse_sidecar_line(line, bid, r);
    }

    // Undrained work: a FOUND that has been queued but not yet booked. A
    // template built while this is non-zero would be proposing balances a block
    // the pool has ALREADY MINED has already paid — the double-pay this leg
    // exists to prevent, re-entering through the back door. The serve loop uses
    // it to hold the rebuild for one iteration.
    std::size_t unbooked_found() const { return m_q.size(); }

    // ★ (a): peer wins that have ARRIVED but have not been looked at yet. The
    // R-7 reason `unbooked_found()` exists applies verbatim to them: a template
    // built while one is in flight proposes over a reservation set that is
    // MISSING that block's payout, and a receiver whose reservation set is
    // smaller than the winner's proposes a different K_fair map. Retries
    // (attempts > 0) are excluded on purpose — a cut-miss is already waiting on
    // the engine and must not park the miners for its whole retry budget.
    std::size_t unbooked_peer_wins() const {
        std::lock_guard<std::mutex> lk(m_peer_mtx);
        std::size_t n = 0;
        for (const PeerPending& p : m_peer_q) if (p.attempts == 0) ++n;
        return n;
    }

    // ★ (a): heights in (cursor, tip] for which we know of NO block at all —
    // i.e. a block the chain has but whose block-winner descriptor has not
    // reached (or not yet been drained by) this node.
    //
    // WHY THIS MUST HOLD THE TEMPLATE REBUILD. K_fair draws on EffectiveOwed,
    // which nets the payouts of the blocks a node holds PENDING. The winner
    // books its own block BEFORE it builds the next height (the R-7 hold), so
    // its reservation set always contains it. A receiver's tip moves from the
    // CHAIN — a poll away — while the descriptor is a poll plus a relay hop
    // away, so without this the receiver routinely builds h+1 with the block at
    // h missing from its reservation, proposes a LARGER K_fair set than the
    // winner did, and the equal owed_digest (the finalized half only) cannot
    // tell the difference. The caller holds the rebuild while this is non-zero,
    // BOUNDED, so a descriptor that never arrives parks nobody: the recompute's
    // reservation witness then refuses that height, loudly.
    //
    // Returns 0 when the window is implausibly wide (initial catch-up), where a
    // hold would be pointless and every height is unknown by construction.
    std::size_t unbooked_chain_heights(std::uint64_t max_window = 32) const {
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        const std::uint64_t tip    = m_node.best_height();
        if (tip <= cursor || tip - cursor > max_window) return 0;
        std::size_t n = 0;
        for (std::uint64_t h = cursor + 1; h <= tip; ++h)
            if (!m_known_by_height.count(h)) ++n;
        return n;
    }

    // ★ (a): how many blocks this node KNOWS OF with lo < height < hi. Monotone
    // (a block is never un-learned; an orphan stays known), counted over every
    // own FOUND and every peer descriptor ever offered — which is exactly the
    // population that can sit in a K_fair reservation. The recompute witnesses
    // this at template-build time and re-asks here, so a record built before a
    // block in its window was known is REFUSED instead of booked.
    std::size_t known_blocks_in(std::uint64_t lo_exclusive,
                                std::uint64_t hi_exclusive) const {
        std::size_t n = 0;
        for (auto it = m_known_by_height.upper_bound(lo_exclusive);
             it != m_known_by_height.end() && it->first < hi_exclusive; ++it)
            n += it->second.size();
        return n;
    }

    // ★ R-7: the two owed floors, taken on every tick rather than whenever a
    // status line happens to print. See Stats for why they are different claims.
    void sample_min_effective_owed() {
        for (const auto& [k, v] : m_node.ledger().effective_owed_all()) {
            (void)k;
            if (v < m_stats.min_effective_owed) m_stats.min_effective_owed = v;
        }
        for (const auto& [k, v] : m_node.ledger().finalW()) {
            (void)k;
            if (v < m_stats.min_final_owed) m_stats.min_final_owed = v;
        }
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

        // ── ★ R-7: THE PAYOUT LEG, BEFORE ANYTHING IS BOOKED ────────────────
        // `payout` is what the coinbase of THIS block ACTUALLY PAID owed keys.
        // It is a DIFFERENT map from `credit` and must stay so: FINALIZE does
        // finalW += credit; finalW -= payout (Settlement.tla G), and while the
        // block is pending EffectiveOwed already reads finalW - Σ_pending payout
        // (w4_settlement.hpp), so booking it is what stops the NEXT template
        // from proposing the very balances this block just settled.
        //
        // Option A pays a single output to monerod's --payout-address, which is
        // no v37 identity: nothing is settled, the map is empty, `require_payout`
        // is off and the whole entitlement carries. Option B's K_fair coinbase
        // pays owed balances DIRECTLY, so its map is the block's owed-role
        // outputs (fixed + residual sink excluded — see BlockCandidate).
        //
        // FAIL-CLOSED: with `require_payout` on, an UNKNOWN map is refused. An
        // unknown map is not an empty one; booking it as empty would credit E_b
        // for a coinbase that has already paid it out, which is the double-pay
        // this leg exists to prevent.
        if (m_o.require_payout && !ev.payout_known) {
            ++m_stats.payout_unknown;
            return refuse(r, bid, "PAYOUT MAP UNKNOWN for an option-B win (template " +
                                  std::to_string(ev.template_id) + " could not be resolved to its "
                                  "owed-role outputs). The K_fair coinbase in this block has "
                                  "ALREADY paid owed balances; registering it with an empty payout "
                                  "leg would leave those balances owed and pay them again");
        }

        // ── ★ S-1b: THE FOLD ────────────────────────────────────────────────
        // credit = E_b, folded out of the lane cut the engine has published
        // RIGHT NOW through settle::fold_eb — what the pool NOW OWES because of
        // this block. Registering credit == payout nets every block to zero
        // (the S-1b defect); registering the coinbase as the CREDIT loses the
        // entitlement. Both are replaced here.
        XmrEbCut cut = fold_at_tip(m_node.engine(), m_cfg.lane_chain,
                                   ev.reward_piconero, m_s1);
        m_last_cut = cut;
        say(describe_cut("FOUND", bid, ev.height, cut));
        if (!cut.refusal.empty())
            say("S-1 fold gave " + short_bid(bid) + " NO CREDIT: " + cut.refusal);
        Amounts credit = cut.credit;
        Amounts payout = ev.payout;   // the R-7 leg — never `= credit`
        if (!payout.empty()) ++m_stats.payout_booked;

        PendingRec rec;
        rec.height = ev.height;
        rec.payee = ev.payee;
        rec.reward = ev.reward_piconero;
        rec.prev_id_hex = lower_hex(ev.prev_id_hex);
        rec.found_unix_s = ev.found_unix_s;
        rec.cut_next_pos     = cut.next_pos;
        rec.cut_spine_digest = cut.lane_digest;
        rec.cut_folded       = cut.folded;
        rec.payout           = payout;

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
        note_known(ev.height, bid);
        // c2pool#1551: the block enters the race book at the same instant it
        // enters the ledger's pending set, so no window exists in which a rival
        // at the same height could be judged against an empty book.
        m_race.observe_own(ev.height, bid, ev.found_unix_s);
        say("FOUND registered " + short_bid(bid) + " h=" + std::to_string(ev.height) +
            " reward=" + std::to_string(ev.reward_piconero) + " piconero payee=" +
            (ev.payee ? hex_of(*ev.payee).substr(0, 12) + "…" : std::string("-")) +
            " E_b=" + std::to_string(credit.size()) + " keys" +
            " payout=" + std::to_string(payout.size()) + " keys/" +
            std::to_string(amounts_sum(payout)) + " pico" +
            (ev.payout_known ? "" : " [payout UNKNOWN: option-A coinbase pays no ledger key]") +
            (cut.valueless ? " [VALUELESS record]" : "") +
            (ev.worker.empty() ? "" : " worker=" + ev.worker) +
            " tid=" + std::to_string(ev.template_id) + " nonce=" + std::to_string(ev.nonce) +
            " owed_digest=" + hex_of(m_node.ledger().owed_digest()) +
            " -> finalizes when hw >= " + std::to_string(ev.height + m_cfg.d_conf) +
            " (D_conf=" + std::to_string(m_cfg.d_conf) + ")");
        r.registered = true;
        r.cut = cut;
        note_own_win(bid);                       // S-1c: the double-drive guard
        if (m_on_registered) m_on_registered(bid, rec, cut);
        return r;
    }

    // ── ★ S-1c: a PEER's block win, offered from ANY thread ─────────────────
    //
    // The carrier reader thread learns of a peer's win when an ADMITTED carrier
    // carries a v0x02 cut descriptor. FinalizeConnect, the node, the driver and
    // the ledger are all MAIN-THREAD-ONLY, so the win is queued here and drained
    // in tick(). That queue is also what gives the CUT-MISS retry its shape:
    // CarrierIngest's admit is fire-and-forget into the engine's MPSC mailbox,
    // so the winner's prefix P may not be published HERE for a few milliseconds
    // after the carrier that produced it was admitted. A bounded number of ticks
    // is spent waiting for that publication before the win is refused — and the
    // refusal still happens, because an executor that COALESCED through P never
    // publishes it at all and no amount of waiting will conjure it.
    void offer_peer_win(const XmrPeerWin& w) {
        if (w.bid.size() != 64 || w.h_b == 0) return;
        std::lock_guard<std::mutex> lk(m_peer_mtx);
        m_peer_q.push_back(PeerPending{w, 0});
    }

    // Our own wins, by bid: a descriptor for a block WE mined comes back on the
    // flood and must never be re-driven (we credited it at the win). Registered
    // automatically for every own FOUND; exposed so the daemon can also mark a
    // win it registered by some other route.
    void note_own_win(const std::string& bid) {
        std::lock_guard<std::mutex> lk(m_peer_mtx);
        m_own_wins.insert(lower_hex(bid));
    }

    // ── read seams (main thread) ────────────────────────────────────────────
    const std::map<std::string, PendingRec>& pending()       const { return m_pending; }
    const std::map<std::string, PendingRec>& unrecoverable() const { return m_unrecoverable; }
    const Stats& stats() const { return m_stats; }
    // ★ S-1b/S-1c diagnostics: the fold counters and the last cuts folded at.
    const XmrS1FoldStats& s1_stats()      const { return m_s1; }
    const XmrS1PeerStats& s1c_stats()     const { return m_s1p; }
    const XmrEbCut&       last_cut()      const { return m_last_cut; }
    const XmrEbCut&       last_peer_cut() const { return m_last_peer_cut; }
    ::v37::bytes32        owed_digest()   const { return m_node.ledger().owed_digest(); }

    // Called on the MAIN thread right after an own FOUND is registered, with the
    // cut its fold read at. The daemon binds this to mint the BLOCK-WINNING
    // carrier that NAMES this fold to its peers (wire v0x02). It is a callback
    // rather than a return value because the win arrives asynchronously, on the
    // found queue, and the carrier must not be minted before the fold exists.
    using OnRegisteredFoundFn =
        std::function<void(const std::string& bid, const PendingRec& rec, const XmrEbCut& cut)>;
    void set_on_registered_found(OnRegisteredFoundFn f) { m_on_registered = std::move(f); }

    // ── ★ canonical_coinbase_matches = (a): the K_fair peer-recompute seam ───
    // Bound by the daemon ONLY in the mode where it is meaningful: option B with
    // the coinbase committing to THIS node's own ledger. Unbound (option A, or
    // --owed-demo-amount, whose coinbase settles a separate proof ledger) leaves
    // the pre-(a) behaviour exactly as it was — a settling peer win is refused,
    // loudly. The daemon binds it to xmr_peer_payout_recompute.hpp's pure
    // decision over its per-height K_fair cache; nothing about the fold, the
    // ledger or the owed commitment is re-implemented behind it.
    using PeerPayoutRecomputeFn = std::function<XmrPeerPayoutOutcome(const XmrPeerWin&)>;
    void set_peer_payout_recompute(PeerPayoutRecomputeFn f) { m_recompute = std::move(f); }
    bool peer_payout_recompute_armed() const { return static_cast<bool>(m_recompute); }

private:
    // ── ★ S-1c: drain the peer-win queue on the MAIN thread ─────────────────
    //
    // REFUSE, DO NOT GUESS. Unlike an own win — where the FOUND must be
    // registered even if the fold gives nothing, because the block is real and
    // the F1 driver has to be able to settle or dispose it — every failure here
    // refuses the registration outright and says why. Crediting a peer's block
    // with a number we invented is exactly the divergence this path exists to
    // remove.
    void drain_peer_wins(TickReport& t) {
        std::deque<PeerPending> batch;
        {
            std::lock_guard<std::mutex> lk(m_peer_mtx);
            batch.swap(m_peer_q);
        }
        t.peer_drained = batch.size();
        std::deque<PeerPending> keep;

        for (PeerPending& pw : batch) {
            const XmrPeerWin& w = pw.win;
            const std::string bid = lower_hex(w.bid);
            const bool first_look = (pw.attempts == 0);
            if (first_look) {
                ++m_s1p.seen;
                // ★ (a): a descriptor is proof the WINNER registered this block,
                // so it joins the known population whatever we go on to do with
                // it — including refuse it. The reservation witness counts
                // blocks that can be reserved, not blocks we credited.
                note_known(w.h_b, bid);
            }

            // (a) ours, or a duplicate descriptor. The flood echoes our own
            //     block-winning carrier straight back at us; re-driving it would
            //     double-register a block we credited at the win.
            {
                bool mine = false;
                { std::lock_guard<std::mutex> lk(m_peer_mtx); mine = m_own_wins.count(bid) != 0; }
                if (mine || m_pending.count(bid) || m_node.ledger().is_pending(bid) ||
                    m_node.ledger().is_settled(bid)) {
                    if (first_look) {
                        ++m_s1p.already_known;
                        say("S-1c: descriptor for a block we already hold (" + short_bid(bid) +
                            (mine ? ", OUR OWN win" : "") + ") — not re-driven");
                    }
                    continue;
                }
            }
            // (b0) c2pool#1627's DROPS credit map rode the same v0x03 frame and
            //      this build has no DROPS ledger leg to apply it with. Crediting
            //      E_b while dropping a credit the winner applied is exactly the
            //      divergence the sections exist to close, so the block is
            //      refused, loudly, rather than half-accounted. (Reconciled at
            //      the wire-integration merge — see w3_relay.hpp's banner.)
            if (w.drops_carried) {
                ++m_s1p.refused_payout;
                ++t.peer_refused;
                say("S-1c REFUSED " + short_bid(bid) + " h=" + std::to_string(w.h_b) +
                    ": the carrier brought a v0x03 DROPS credit map (c2pool#1627) and this "
                    "build has no DROPS ledger leg to fold it with — crediting E_b while "
                    "ignoring a credit the winner applied would fork the two ledgers");
                continue;
            }
            // (b) ★★ WIRE-CARRY (c2pool#1625). The winner broadcast a SETTLING
            //     coinbase: its option-B K_fair outputs paid owed balances, so at
            //     FINALIZE the winner does finalW -= payout and a peer that
            //     deducts nothing has forked from that block on.
            //
            //     WHAT THIS REPLACES, AND WHY. The first answer was to RECOMPUTE
            //     the map — K_fair is OwedLedger::propose_coinbase, deterministic
            //     over ledger state, and this node runs it for its own template
            //     at the same height. It converged BYTE-EQUAL for the first four
            //     settling blocks of a 2-node regtest and forked terminally at
            //     the fifth, refusing every settling block after it. The maps are
            //     byte-exact where the two states match; the defect is that
            //     nothing makes them match. Two daemons sample their ledgers on
            //     independent clocks, so "both nodes build h=H_b when their tip is
            //     H_b-1" is a tendency, not an invariant, and the first skew is
            //     unrecoverable: the guards correctly refuse, the peer books
            //     nothing, and the ledgers never rejoin.
            //
            //     So the map is CARRIED instead. The winner knows it exactly —
            //     it is the Owed-role output set of the template it mined, the
            //     very map its own ledger booked (PendingRec::payout) — and puts
            //     it on the v0x03 trailer. Here it is FOLDED VERBATIM: no
            //     recompute, no template build to compare against, no
            //     same-instant requirement anywhere. The two-clock dependency is
            //     gone, which is why this converges THROUGH every settling block
            //     instead of until the first skew.
            //
            //     FAIL-CLOSED, and only on the things that stay wrong under
            //     retry: a missing section (the winner could not tell us), a row
            //     the ledger cannot key, or a total the frame's own reward cannot
            //     cover. A TIMING SKEW IS NEVER A REFUSAL HERE — that is the
            //     whole point of the switch.
            Amounts carried;
            if (w.payout_emitted) {
                if (!w.payout_carried) {
                    ++m_s1p.refused_payout;
                    ++m_s1p.payout_absent;
                    ++t.peer_refused;
                    say("S-1c REFUSED " + short_bid(bid) + " h=" + std::to_string(w.h_b) +
                        ": the winner's descriptor says its coinbase SETTLED owed balances but "
                        "carried no v0x03 K_fair section (a pre-v0x03 peer, or a winner that "
                        "could not state its own map) — we credit nothing rather than credit "
                        "something different");
                    continue;
                }
                // Shape, re-asked at the fold. The codec already enforced the
                // wire rules (bounded, strictly ascending, every amount > 0,
                // Sum <= reward); this is the LEDGER's half of the same question,
                // and it is asked here so a map that cannot be booked is refused
                // before anything is registered rather than after.
                std::uint64_t sum = 0;
                bool shape_ok = !w.payout.empty();
                for (const auto& [k, v] : w.payout) {
                    (void)k;
                    // Ordered so the accumulator can never wrap: each row is
                    // compared to the budget before it is added, so `reward - sum`
                    // is the remaining budget and is never a borrow.
                    if (v <= 0) { shape_ok = false; break; }
                    const std::uint64_t amt = static_cast<std::uint64_t>(v);
                    if (amt > w.reward || sum > w.reward - amt) { shape_ok = false; break; }
                    sum += amt;
                }
                if (!shape_ok) {
                    ++m_s1p.refused_payout;
                    ++m_s1p.payout_shape;
                    ++t.peer_refused;
                    say("S-1c REFUSED " + short_bid(bid) + " h=" + std::to_string(w.h_b) +
                        ": the carried K_fair map is not a bookable shape (" +
                        std::to_string(w.payout.size()) + " row(s), Sum=" + std::to_string(sum) +
                        " against reward " + std::to_string(w.reward) + ")");
                    continue;
                }
                carried = w.payout;
                if (first_look) {
                    say("S-1c WIRE-CARRY " + short_bid(bid) + " h=" + std::to_string(w.h_b) +
                        ": folding the WINNER'S K_fair map, " + std::to_string(carried.size()) +
                        " owed key(s)/" + std::to_string(sum) + " pico of reward " +
                        std::to_string(w.reward) + " — no recompute, no same-instant requirement");
                }
                // The old recompute, demoted to a NON-AUTHORITATIVE cross-check.
                // It can only ever say "our own K_fair run for this height agreed
                // with the winner's"; a disagreement is a diagnostic about the
                // two template clocks, NOT a reason to refuse a map the winner
                // already spent. Nothing below reads its verdict.
                if (m_recompute && first_look) {
                    const XmrPeerPayoutOutcome ro = m_recompute(w);
                    if (!ro.ok) {
                        ++m_s1p.xcheck_absent;
                        say("S-1c xcheck [" + std::string(ro.code) + "] " + short_bid(bid) +
                            ": the local recompute had no comparable map (" + ro.refusal +
                            ") — NOT a refusal; the carried map stands");
                    } else if (ro.payout == carried) {
                        ++m_s1p.xcheck_agree;
                        say("S-1c xcheck AGREE " + short_bid(bid) + " h=" +
                            std::to_string(w.h_b) + ": our own K_fair run produced the SAME map");
                    } else {
                        ++m_s1p.xcheck_differ;
                        say("S-1c xcheck DIFFER " + short_bid(bid) + " h=" +
                            std::to_string(w.h_b) + ": our own K_fair run proposed " +
                            std::to_string(ro.payout.size()) + " key(s)/" +
                            std::to_string(ro.sum) + " pico where the winner paid " +
                            std::to_string(carried.size()) + " key(s)/" + std::to_string(sum) +
                            " pico — the two template clocks were apart at this height. This is "
                            "EXACTLY the skew the recompute path could not survive and is NOT a "
                            "refusal: the winner's map is what its coinbase spent");
                    }
                }
            } else if (w.payout_carried) {
                // A map on a descriptor that denies settling. The codec refuses
                // this shape outright, so reaching it means the wire and this
                // consumer disagree about the frozen rule — refuse, loudly.
                ++m_s1p.refused_payout;
                ++m_s1p.payout_shape;
                ++t.peer_refused;
                say("S-1c REFUSED " + short_bid(bid) + ": a K_fair map arrived on a descriptor "
                    "whose payout_emitted is 0 — the frame contradicts itself");
                continue;
            }
            // (c) too late: advance_to_tip steps only heights ABOVE the cursor,
            //     so the FOUND would sit pending forever.
            const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
            if (w.h_b <= cursor) {
                ++m_s1p.refused_late;
                ++t.peer_refused;
                say("S-1c REFUSED " + short_bid(bid) + ": H_b=" + std::to_string(w.h_b) +
                    " is at or below our finalize cursor (" + std::to_string(cursor) +
                    ") — this block can never be stepped at maturity here");
                continue;
            }
            // (d) the VERIFY field, stated honestly. owed_digest_at_win is the
            //     winner's §4.5 commitment at ITS win; ours is read HERE, at
            //     receipt, which is a strictly LATER instant — this node learns
            //     of H_b from the chain a poll away while the descriptor is a
            //     poll plus a relay hop away, so its finalize cursor has
            //     routinely stepped a bin the winner had not. A skew is
            //     therefore normal and is NOT by itself a divergence; it is a
            //     REPORT either way, never a refusal. The same-instant
            //     comparison is the K_fair recompute's, below.
            if (first_look) {
                const ::v37::bytes32 here = m_node.ledger().owed_digest();
                if (!(here == w.owed_digest_at_win)) {
                    ++m_s1p.owed_skew;
                    say("S-1c VERIFY SKEW on " + short_bid(bid) + ": winner's owed_digest at "
                        "the win " + hex_of(w.owed_digest_at_win) + " != ours at receipt " +
                        hex_of(here) + " — our receipt instant is LATER than the winner's win "
                        "instant, so this alone is not a divergence. The same-instant check is "
                        "the K_fair recompute (our owed_digest at OUR build of h=" +
                        std::to_string(w.h_b) + " against this field); a real divergence shows "
                        "up there as refused[payout], and in the per-cursor owed_digest");
                }
            }

            // (e) THE CUT RULE: fold at the WINNER'S prefix, out of OUR ring.
            XmrPeerFoldOutcome f =
                fold_at_peer_cut(m_node.engine(), m_cfg.lane_chain, w, m_s1p);
            if (!f.ok) {
                // A cut MISS can be a race: CarrierIngest's admit is
                // fire-and-forget into the engine's MPSC mailbox, so the prefix
                // the winner named may be published here a few milliseconds from
                // now. Give it a bounded number of ticks, then refuse. A DIGEST
                // MISMATCH is never a race and is refused immediately.
                if (f.cut_miss && pw.attempts + 1 < kPeerCutRetryTicks) {
                    --m_s1p.cut_miss;              // not a verdict yet
                    ++pw.attempts;
                    ++t.peer_deferred;
                    keep.push_back(pw);
                    continue;
                }
                ++t.peer_refused;
                m_last_peer_cut = f.cut;
                say("S-1c REFUSED " + short_bid(bid) + " h=" + std::to_string(w.h_b) + ": " +
                    f.cut.refusal + " — our owed_digest will NOT converge with the winner's "
                    "for this block");
                continue;
            }

            m_last_peer_cut = f.cut;
            Amounts credit = f.cut.credit;
            // ★★ WIRE-CARRY: the payout leg. EMPTY for a non-settling win (the
            // winner's coinbase paid no ledger key, so there is nothing to deduct
            // and the whole entitlement carries); the winner's OWN K_fair map,
            // off the v0x03 trailer, for a settling one — so this ledger deducts
            // exactly what the winner's did at FINALIZE (finalW -= payout) and
            // the next template here cannot re-propose what that block paid.
            Amounts payout = carried;

            c2pool::xmr::node::Hash id{};
            if (!hash_from_hex(bid, id) || c2pool::xmr::node::is_zero(id)) {
                ++t.peer_refused;
                say("S-1c REFUSED " + short_bid(bid) + ": malformed block id on the wire");
                continue;
            }
            if (!m_node.on_network_block_won(w.h_b, id, credit, payout) ||
                !m_node.ledger().is_pending(bid)) {
                ++t.peer_refused;
                say("S-1c REFUSED " + short_bid(bid) + ": the node/ledger did not admit the FOUND");
                continue;
            }
            PendingRec rec;
            rec.height           = w.h_b;
            rec.reward           = w.reward;
            rec.cut_next_pos     = w.cut_next_pos;
            rec.cut_spine_digest = w.cut_spine_digest;
            rec.cut_folded       = f.cut.folded;
            // ★ R-7 / (a): persist the recomputed leg (sidecar v3) for the SAME
            // reason an own win persists its own — the block is on the chain and
            // has already paid these keys, so a restart inside the D_conf window
            // that re-drove it with an empty payout would restore balances the
            // coinbase already settled and let the next template pay them twice.
            rec.payout           = payout;
            m_pending[bid] = rec;
            (void)sidecar_flush();
            ++m_stats.registered;
            if (!payout.empty()) ++m_stats.payout_booked;
            // observe_OWN, deliberately. The same-height book's "own" means "a
            // block THIS LEDGER will credit", not "a block this process mined":
            // it exists to stop an orphan-credit and a double-credit, and after
            // S-1c a peer's block is credited here exactly as our own is. Filing
            // it as "other" would make the gate declare an R-7 violation against
            // the finalize driver every time a peer's block matured — the gate
            // and the driver disagreeing about a settlement that is correct.
            m_race.observe_own(w.h_b, bid);
            if (f.cut.valueless) ++m_s1p.valueless; else ++m_s1p.credited;
            // Counted at REGISTRATION, once per block: a cut-miss retry re-drives
            // the (pure) fold, and counting there would report a multiple of the
            // number of blocks actually settled from a peer.
            if (w.payout_emitted) ++m_s1p.payout_carried;
            ++t.peer_credited;
            say(describe_cut("PEER WIN", bid, w.h_b, f.cut));
            say("S-1c PEER FOUND registered " + short_bid(bid) + " h=" + std::to_string(w.h_b) +
                " E_b=" + std::to_string(credit.size()) + " keys payout=" +
                std::to_string(payout.size()) + " keys/" + std::to_string(amounts_sum(payout)) +
                " pico" + (w.payout_emitted ? " [WIRE-CARRIED K_fair]" : "") +
                " at the winner's cut P=" +
                std::to_string(w.cut_next_pos) + " (our lane version " +
                std::to_string(f.cut.lane_version) + ") owed_digest=" +
                hex_of(m_node.ledger().owed_digest()) + " -> finalizes when hw >= " +
                std::to_string(w.h_b + m_cfg.d_conf));
        }

        if (!keep.empty()) {
            std::lock_guard<std::mutex> lk(m_peer_mtx);
            for (auto& p : keep) m_peer_q.push_back(std::move(p));
        }
    }

    // ★ (a): the known population, bounded to the heights that can still matter
    // (anything at or below the finalize cursor is settled or gone and can no
    // longer sit in a reservation).
    void note_known(std::uint64_t height, const std::string& bid) {
        if (height == 0) return;
        m_known_by_height[height].insert(bid);
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        const std::uint64_t keep_from = cursor > kKnownKeepDepth ? cursor - kKnownKeepDepth : 0;
        while (!m_known_by_height.empty() && m_known_by_height.begin()->first < keep_from)
            m_known_by_height.erase(m_known_by_height.begin());
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
    //    2 <bid64> <height> <payee64|-> <reward> <prev64|-> <found_unix_s>
    //      <cut_next_pos> <cut_spine64|-> <folded 0|1>       ★ S-1b
    //    3 ... as 2, then                                    ★ R-7 payout leg
    //      <n_payout> [<key64> <amount>] * n_payout
    // Versions 1 and 2 are still PARSED (a store written by an older run
    // reseeds). A v1 line reads back with cut_folded == false, and v1/v2 lines
    // read back with an EMPTY payout — which is exactly right for them: they
    // were written by a build that booked no payout leg, so the ledger they
    // belong to never deducted one either.
    static std::string sidecar_line(const std::string& bid, const PendingRec& r) {
        std::string s = "3 " + bid + " " + std::to_string(r.height) + " " +
                        (r.payee ? hex_of(*r.payee) : std::string("-")) + " " +
                        std::to_string(r.reward) + " " +
                        (r.prev_id_hex.size() == 64 ? r.prev_id_hex : std::string("-")) + " " +
                        std::to_string(r.found_unix_s) + " " +
                        std::to_string(r.cut_next_pos) + " " +
                        (r.cut_folded ? hex_of(r.cut_spine_digest) : std::string("-")) + " " +
                        (r.cut_folded ? "1" : "0") + " " +
                        std::to_string(r.payout.size());
        for (const auto& [k, v] : r.payout)
            s += " " + hex_of(k) + " " + std::to_string(v);
        s += "\n";
        return s;
    }
    static bool parse_sidecar_line(const std::string& line, std::string& bid, PendingRec& r) {
        std::istringstream is(line);
        std::string ver, payee, prev;
        unsigned long long h = 0, reward = 0, ts = 0;
        if (!(is >> ver >> bid >> h >> payee >> reward >> prev >> ts)) return false;
        if (ver != "1" && ver != "2" && ver != "3") return false;
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
        if (ver == "2" || ver == "3") {
            unsigned long long p = 0, folded = 0;
            std::string spine;
            if (!(is >> p >> spine >> folded)) return false;
            r.cut_next_pos = p;
            r.cut_folded   = (folded != 0);
            if (spine != "-") {
                ::v37::bytes32 d{};
                if (!hash_from_hex(lower_hex(spine), d)) return false;
                r.cut_spine_digest = d;
            } else if (r.cut_folded) {
                return false;   // "folded" without a commitment is not a cut
            }
        }
        if (ver == "3") {
            // ★ R-7 payout leg. A TRUNCATED or malformed payout list makes the
            // whole line malformed rather than a record with a short payout:
            // silently dropping a key here would restore a balance the block
            // already paid, which is the double-pay this leg exists to stop.
            unsigned long long n = 0;
            if (!(is >> n)) return false;
            for (unsigned long long i = 0; i < n; ++i) {
                std::string kh;
                long long amt = 0;
                if (!(is >> kh >> amt)) return false;
                ::v37::bytes32 k{};
                if (!hash_from_hex(lower_hex(kh), k)) return false;
                r.payout[k] = amt;
            }
            if (r.payout.size() != static_cast<std::size_t>(n)) return false;   // duplicate keys
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
    std::map<std::string, PendingRec> m_unrecoverable;  // kept in the sidecar so the boot warning repeats
    Stats         m_stats;
    std::size_t   m_log_cursor = 0;
    std::uint64_t m_last_hw_printed = ~std::uint64_t{0};

    // c2pool#1551: the race book and the last verdict reported per height (so a
    // quiet loop stays quiet and the journal records transitions, not ticks).
    SameHeightRaceLedger                    m_race;
    std::map<std::uint64_t, RaceVerdict>    m_last_verdict;

    // ── ★ S-1b / S-1c state ────────────────────────────────────────────────
    // How many ticks a cut MISS is given before it becomes a refusal. At the
    // daemon's default --poll-ms this is a couple of seconds, which covers the
    // engine's MPSC publication latency by orders of magnitude and still ends.
    static constexpr unsigned kPeerCutRetryTicks = 20;
    // How far below the finalize cursor the known-block map is retained. It only
    // has to outlive the K_fair cache's own window, and the cache is bounded to
    // the most recent heights, so a couple of hundred is generous.
    static constexpr std::uint64_t kKnownKeepDepth = 256;
    struct PeerPending { XmrPeerWin win; unsigned attempts = 0; };
    // ★ (a): height -> the bids at that height this node has learned of (own
    // FOUNDs and peer descriptors alike). See known_blocks_in().
    std::map<std::uint64_t, std::set<std::string>> m_known_by_height;

    XmrS1FoldStats m_s1;             // own-win fold counters
    XmrS1PeerStats m_s1p;            // receive-side counters
    XmrEbCut       m_last_cut;       // the cut the last own win folded at
    XmrEbCut       m_last_peer_cut;  // the cut the last peer win folded at
    OnRegisteredFoundFn m_on_registered;
    // ★ (a) peer-recompute. Main thread only (drain_peer_wins). Unbound => the
    // pre-(a) fail-closed refusal for a settling peer win.
    PeerPayoutRecomputeFn m_recompute;

    mutable std::mutex       m_peer_mtx;   // guards the two members below
    std::deque<PeerPending>  m_peer_q;     // offered from the carrier reader thread
    std::set<std::string>    m_own_wins;   // the double-drive guard
};

} // namespace c2pool::v37n::xmr::o2

// ===========================================================================
// SELF-CHECK — network-free, RandomX-free, against the monerod STUB; the same
// shape as xmr_node_smoke.hpp so it can run under `--mock-smoke` / the CI
// smoke target. Proves: lane work pushed -> queued win -> FOUND credits the
// FOLDED E_b -> restart inside the D_conf window -> sidecar re-drive -> FINALIZE
// at bin_height = H_b+D_conf -> ★ owed_digest LEAVES the empty anchor and
// effective_owed carries the whole entitlement -> sidecar retired; plus the
// late-FOUND and malformed refusals, the EMPTY-lane refusal (the X2 tripwire),
// idempotence, and the orphan disposition.
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

    // ── ★ X2 stand-in: put WORK in the lane ─────────────────────────────────
    // The daemon gets here through XmrLaneShareSink -> CarrierSendQueue ->
    // CarrierRelay -> CarrierIngest, which ends in exactly this call —
    // V37Engine::submit(LaneRecord::push(...)), the ONE producer seam. The smoke
    // drives that seam directly so it stays network-free and crypto-free while
    // still folding over a lane that has real weight. A P2PKH descriptor is used
    // rather than an XMR one precisely so this check needs no ed25519 backend;
    // the identity KIND is irrelevant to the fold, which reads weights and keys.
    ::v37::PayoutDescriptor lane_desc;
    {
        ::v37::ScriptRef r;
        r.kind = ::v37::ScriptKind::P2PKH;
        r.payload.assign(20, 0x5A);
        lane_desc.pay = r;
    }
    const ::v37::bytes32 lane_key = lane_desc.identity_key();
    auto seed_lane = [&](XmrNode& node, std::uint64_t w) {
        return node.engine()
            .submit_tracked(::v37::LaneRecord::push(CHAIN, lane_desc, w, 0))
            .get()
            .applied();
    };
    const ::v37::bytes32 empty_anchor = OwedLedger(CHAIN).owed_digest();

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

        // X2: put real work in the lane (what the share sink does live).
        const bool seeded = seed_lane(node, 1000) && seed_lane(node, 3000);
        rep.add("FC1d lane accrued work through the ONE producer seam (X2 stand-in)", seeded);

        FoundBlockEvent ev;
        ev.height = 5; ev.block_id_hex = bid5; ev.prev_id_hex = hex_of(smoke::blk_id(4));
        ev.reward_piconero = REWARD; ev.payee = payee; ev.worker = "rig0"; ev.template_id = 42;
        q.push(ev); q.push(ev);                       // duplicate push (idempotent per bid)
        auto t = fc.tick();
        rep.add("FC2 queued win -> on_network_block_won: ledger pending, idempotent per bid",
                t.drained == 2 && t.registered == 1 && t.refused == 0 &&
                fc.pending().size() == 1 && node.ledger().is_pending(bid5),
                "drained=" + std::to_string(t.drained) + " registered=" + std::to_string(t.registered));
        rep.add("FC3 ★ S-1b: the win credited the FOLDED E_b (non-empty, lane-keyed) and did "
                "NOT net credit against payout",
                fc.last_cut().folded && !fc.last_cut().valueless &&
                fc.last_cut().credit.size() == 1 &&
                fc.last_cut().credit.count(lane_key) == 1 &&
                fc.last_cut().credit.at(lane_key) == static_cast<long long>(REWARD) &&
                fc.s1_stats().folds == 1,
                "E_b keys=" + std::to_string(fc.last_cut().credit.size()) +
                " raw_total=" + std::to_string(fc.last_cut().raw_total));
        rep.add("FC3b this win carried NO payout map (the option-A shape: monerod's coinbase "
                "pays no ledger key), so effective_owed is untouched while pending "
                "(the pre-S-1b code deducted the whole reward here)",
                fc.pending().at(bid5).payout.empty() &&
                node.ledger().effective_owed(lane_key) == 0 &&
                node.ledger().effective_owed(payee) == 0);
        rep.add("FC4 pending-FOUND sidecar written (write-ahead, 1 record) and it carries the "
                "CUT (v2), so a re-drive cannot re-fold at a foreign prefix",
                count_lines(o.sidecar_path) == 1 && fc.pending().count(bid5) &&
                fc.pending().at(bid5).cut_folded &&
                fc.pending().at(bid5).cut_spine_digest == fc.last_cut().lane_digest);

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
        // ★★ THE S-1b CLAIM. Pre-S-1b this read `effective_owed == 0` because
        // credit and payout were the same map and FINALIZE netted them to zero.
        rep.add("FC10 ★ S-1b: FINALIZE carried the whole entitlement into finalW — the pool "
                "now OWES its lane payee the block reward (pre-S-1b this netted to 0)",
                node.ledger().effective_owed(lane_key) == static_cast<long long>(REWARD),
                "effective_owed(lane_key)=" +
                    std::to_string(node.ledger().effective_owed(lane_key)));
        rep.add("FC10b ★ S-1b: owed_digest LEFT the empty sha256d(\"V37O\") anchor",
                !(node.ledger().owed_digest() == empty_anchor),
                "owed=" + hex_of(node.ledger().owed_digest()) +
                    " anchor=" + hex_of(empty_anchor));
        rep.add("FC11 sidecar retired after FINALIZE", count_lines(o.sidecar_path) == 0);
        bool logged = false;
        for (const auto& l : node.construction_log())
            if (l.find("SETTLED at bin_height=8") != std::string::npos) logged = true;
        rep.add("FC12 the node logged the FINALIZE step with the per-height bin_height (echoed by tick)", logged);

        // ── ★ S-1b tripwire: a win over an EMPTY lane refuses LOUDLY ────────
        // This process's engine is fresh, so its lane carries no work yet: the
        // exact shape the pre-X2 daemon was in permanently. The win must still
        // be REGISTERED (a block we mined is a real block) but stamped VALUELESS
        // with a reason that names the cause, rather than booking a plausible
        // number.
        const ::v37::bytes32 owed_before_dry = node.ledger().owed_digest();
        FoundBlockEvent v; v.height = 8; v.block_id_hex = bid8;
        v.reward_piconero = REWARD; v.payee = payee;
        q.push(v);
        t = fc.tick();
        rep.add("FC13 ★ EMPTY lane: the win REGISTERS but is VALUELESS and says why "
                "(E_b is EMPTY — no share reached the lane)",
                t.registered == 1 && node.ledger().is_pending(bid8) &&
                fc.last_cut().valueless && fc.last_cut().credit.empty() &&
                fc.last_cut().refusal.find("E_b is EMPTY") != std::string::npos,
                "refusal=" + fc.last_cut().refusal);
        chain(node, 9, 11);
        t = fc.tick();
        rep.add("FC14 the valueless win finalizes at 8+3=11 and moves owed_digest NOT AT ALL "
                "(crediting nobody is a real answer, not a silent one)",
                t.settled == 1 && node.ledger().is_settled(bid8) &&
                node.ledger().owed_digest() == owed_before_dry);

        // orphan disposition: work in the lane, win at 11, competing 11 wins
        (void)seed_lane(node, 4096);
        const ::v37::bytes32 owed_before_orphan = node.ledger().owed_digest();
        FoundBlockEvent w; w.height = 11; w.block_id_hex = bid11; w.payee = payee; w.reward_piconero = REWARD;
        q.push(w);
        t = fc.tick();
        const bool reg11 = t.registered == 1 && node.ledger().is_pending(bid11) &&
                           !fc.last_cut().credit.empty();
        smoke::apply_row(node, 11, smoke::blk_id(99), smoke::blk_id(10));   // reorg at 11
        chain(node, 12, 14);                          // bury the competitor: 11+3 = 14
        t = fc.tick();
        // the Orphan event or the canonical predicate at maturity disposed it
        rep.add("FC15 orphaned win leaves the pending set (never SETTLED) and the sidecar",
                reg11 && !node.ledger().is_pending(bid11) && !node.ledger().is_settled(bid11) &&
                fc.pending().empty() && count_lines(o.sidecar_path) == 0 && fc.stats().orphaned == 1,
                "orphaned=" + std::to_string(fc.stats().orphaned));
        rep.add("FC16 orphan: the folded E_b NEVER reached finalW — owed_digest is byte-identical "
                "to before the win (credit is applied at FINALIZE, not at FOUND)",
                node.ledger().owed_digest() == owed_before_orphan);
        rep.add("FC16b ★ R-7: nothing in this leg drove EffectiveOwed OR finalW below zero",
                fc.stats().min_effective_owed == 0 && fc.stats().min_final_owed == 0,
                "eff_min=" + std::to_string(fc.stats().min_effective_owed) +
                " final_min=" + std::to_string(fc.stats().min_final_owed));
        (void)fc.drain_before_stop();
    }

    // ═══ ★ R-7: THE PAYOUT LEG ═══════════════════════════════════════════════
    // Everything above drives the option-A shape, where the coinbase pays no
    // ledger key and the payout map is empty. This section drives the option-B
    // shape: a coinbase that SETTLED owed balances, which is what made the old
    // `payout = {}` a deadlock. A fresh store so the ledger starts clean.
    {
        XmrNodeConfig c2 = cfg;
        c2.settle_db_path = (tmp_root / "store_r7").string();
        std::filesystem::create_directories(c2.settle_db_path);
        FinalizeConnectOptions o2;
        o2.sidecar_path  = (std::filesystem::path(c2.settle_db_path) / "pfound.tsv").string();
        o2.out           = nullptr;
        o2.require_payout = true;             // the option-B posture

        const std::string bidA = hex_of(smoke::blk_id(5));
        const std::string bidB = hex_of(smoke::blk_id(9));
        const std::string bidC = hex_of(smoke::blk_id(13));
        FoundBlockQueue q2;
        ::v37::bytes32 sidecar_digest{};
        long long owed_after_first = 0;

        {
            MockMonerodTransport mt;
            XmrNode node(c2, mt);
            node.bring_up();
            FinalizeConnect fc(node, c2, q2, o2);
            (void)fc.reseed_after_bring_up();
            (void)seed_lane(node, 4096);

            // ── (1) an UNKNOWN payout map is REFUSED, never booked as empty ──
            FoundBlockEvent bad;
            bad.height = 5; bad.block_id_hex = bidA; bad.reward_piconero = REWARD;
            bad.payee = payee; bad.payout_known = false;       // template unresolvable
            q2.push(bad);
            auto t2 = fc.tick();
            rep.add("FC17 ★ R-7: an option-B win whose payout map is UNKNOWN is REFUSED, not "
                    "booked as 'paid nobody' (booking it would credit E_b for a coinbase that "
                    "has already paid it out)",
                    t2.registered == 0 && t2.refused == 1 &&
                    !node.ledger().is_pending(bidA) && fc.stats().payout_unknown == 1,
                    "registered=" + std::to_string(t2.registered) +
                    " unknown=" + std::to_string(fc.stats().payout_unknown));

            // ── (2) the FIRST block, in the real order ───────────────────────
            // Its coinbase was assembled over an EMPTY ledger, so K_fair had
            // nothing to propose and the whole reward went to the residual sink:
            // a KNOWN, EMPTY payout map. That is a different fact from FC17's
            // unknown one, and the leg has to tell them apart.
            FoundBlockEvent good = bad;
            good.payout_known = true;                          // known, and empty
            q2.push(good);
            t2 = fc.tick();
            rep.add("FC18 ★ R-7: a KNOWN but EMPTY payout map registers normally (an option-B "
                    "coinbase over an empty ledger really does pay only the residual sink) — "
                    "'unknown' and 'paid nobody' are not the same answer",
                    t2.registered == 1 && node.ledger().is_pending(bidA) &&
                    fc.pending().at(bidA).payout.empty() && fc.stats().payout_booked == 0,
                    "booked=" + std::to_string(fc.stats().payout_booked));

            chain(node, 5, 8);                                 // h=5 canonical, hw = 5 + 3
            t2 = fc.tick();
            const long long owed_now = node.ledger().effective_owed(lane_key);
            rep.add("FC19 ★ S-1b: that block's E_b landed in finalW at FINALIZE — the pool now "
                    "OWES the lane a reward, which is what the NEXT coinbase will settle",
                    t2.settled == 1 && owed_now == static_cast<long long>(REWARD),
                    "eo=" + std::to_string(owed_now));

            // ── (3) the SECOND block: a coinbase that actually SETTLES ───────
            // Its payout can only ever be what K_fair was allowed to propose,
            // which is bounded by EffectiveOwed — so a partial settle here.
            // EffectiveOwed = finalW - Σ_pending payout, so the deduction lands
            // at FOUND, not at FINALIZE. That is precisely what stops the next
            // template proposing the balances this coinbase just settled.
            const long long PAY = 250000000000ll;              // < REWARD: a partial settle
            (void)seed_lane(node, 4096);
            FoundBlockEvent settle_ev;
            settle_ev.height = 9; settle_ev.block_id_hex = bidB;
            settle_ev.reward_piconero = REWARD; settle_ev.payee = payee;
            settle_ev.payout_known = true;
            settle_ev.payout[lane_key] = PAY;
            q2.push(settle_ev);
            t2 = fc.tick();
            rep.add("FC20 ★ R-7: with a NON-EMPTY map the win registers AND books the payout leg",
                    t2.registered == 1 && node.ledger().is_pending(bidB) &&
                    fc.stats().payout_booked == 1 &&
                    fc.pending().at(bidB).payout.size() == 1 &&
                    fc.pending().at(bidB).payout.at(lane_key) == PAY,
                    "booked=" + std::to_string(fc.stats().payout_booked));
            rep.add("FC21 ★ R-7: a FOUND with a booked payout moves EffectiveOwed DOWN by exactly "
                    "the payout WHILE STILL PENDING (an empty leg leaves it untouched — FC3b — "
                    "and that is the double-pay: the next template re-proposes the same balance)",
                    node.ledger().effective_owed(lane_key) == owed_now - PAY,
                    "eo=" + std::to_string(node.ledger().effective_owed(lane_key)) +
                    " expected=" + std::to_string(owed_now - PAY));

            // ── (4) sidecar v3 carries the map ───────────────────────────────
            rep.add("FC22 ★ R-7: the pending-FOUND sidecar persists the payout map (v3), so a "
                    "restart re-drives the SAME deduction instead of restoring balances the "
                    "block already paid",
                    count_lines(o2.sidecar_path) == 1 &&
                    [&] {
                        std::ifstream f(o2.sidecar_path);
                        std::string line; std::getline(f, line);
                        std::string b; FinalizeConnect::PendingRec r;
                        return FinalizeConnect::parse_sidecar_line_for_test(line, b, r) &&
                               b == bidB && r.payout.size() == 1 && r.payout.at(lane_key) == PAY;
                    }());
            owed_after_first = owed_now - PAY;
            sidecar_digest   = node.ledger().owed_digest();
            rep.add("FC23 ★ R-7: neither floor went below zero across the whole leg — finalW "
                    "(SOLVENCY: finalized entitlements minus finalized payouts) is the one that "
                    "must not, and EffectiveOwed (the RESERVATION of in-flight coinbases) did "
                    "not either here",
                    fc.stats().min_final_owed == 0 && fc.stats().min_effective_owed == 0 &&
                    owed_after_first >= 0,
                    "eff_min=" + std::to_string(fc.stats().min_effective_owed) +
                    " final_min=" + std::to_string(fc.stats().min_final_owed));
        }

        // ── (6) RESTART with that second win still pending ──────────────────
        {
            MockMonerodTransport mt;
            XmrNode node(c2, mt);
            node.bring_up();
            FinalizeConnect fc(node, c2, q2, o2);
            const FinalizeConnect::BootReport boot = fc.reseed_after_bring_up();
            rep.add("FC24 ★ R-7: the restart re-drove the pending FOUND WITH its payout leg, so "
                    "the deduction survived the crash window (E_b may be irrecoverable; the "
                    "payout is not, because it was written down rather than recomputed)",
                    boot.reseeded + boot.reregistered == 1 && boot.payout_redriven == 1 &&
                    fc.pending().count(bidB) == 1 &&
                    fc.pending().at(bidB).payout.size() == 1,
                    "reseeded=" + std::to_string(boot.reseeded) +
                    " redriven=" + std::to_string(boot.payout_redriven));
            rep.add("FC25 ★ R-7: and EffectiveOwed after the restart is what it was before it, "
                    "not the un-deducted balance the block had already paid",
                    node.ledger().effective_owed(lane_key) == owed_after_first &&
                    node.ledger().owed_digest() == sidecar_digest,
                    "eo=" + std::to_string(node.ledger().effective_owed(lane_key)) +
                    " expected=" + std::to_string(owed_after_first));
            (void)bidC;
            (void)fc.drain_before_stop();
        }
    }
    return rep;
}

} // namespace c2pool::v37n::xmr::o2
