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
// R6 — TWO-SIDED CHAIN-ORDERED BOOKING + THE DIVERGENCE CAP (recon-final):
//   The R4 gate (booking_gate) is ONE-SIDED: it keeps the cursor from stepping
//   past an UNBOOKED lane block at height <= h + D_conf, but it lets a node
//   whose cursor is held (feed lag, cut-pending) BOOK chain blocks far ABOVE
//   cursor + 1 + D_conf as they arrive -- earlier, relative to the cursor, than
//   the synced node booked them (the synced node books h with its cursor at
//   h - 1 - D_conf, because book(h) precedes advance(h) -> FINALIZE(h-D_conf)).
//   FINALIZE(h) then reads a LARGER pending set on the lagging node, and
//   OwedLedger::rearm_first_eligible (w4_settlement.hpp) stamps a different eo
//   sign / first_eligible -> owed_digest forks with identical settled sets and
//   amounts (the RUN3 cursor-7 fork: {5,6,7,8} vs {5,6,7} at FINALIZE(4)).
//   The other side: book_chain_block DEFERS any chain block at height h >
//   cursor + 1 + D_conf (m_deferred; it holds the gate exactly like a retry),
//   and tick() books deferred blocks in ascending height as the cursor reaches
//   h - 1 - D_conf, re-advancing the driver between bookings. Every node now
//   books in the SAME chain order and FINALIZE(h) sees the SAME pending set
//   (h, h + D_conf] -- whatever its lag, whatever its poll cadence.
//   DIVERGENCE CAP: a reorg of depth >= D_conf is the documented finality
//   boundary (SETTLED is terminal; docs/xmr-lane/finality-boundary.md). After
//   one, every peer lane block is lane-root-unknown here and the cursor would
//   fall behind the tip without bound. divergence_check() declares HELD-LAG
//   (R-C rework-2: loud, counted, NON-terminal; it used to be a terminal
//   DIVERGED that dropped every later chain block) once the cursor is more
//   than divergence_cap_heights behind the buried frontier with a root-unknown
//   / HELD lane block for divergence_cap_ticks consecutive ticks.
//
// R-C REWORK-2 (docs/xmr-lane/r-c-rework-2.md):
//   * (rework-3 replaces rework-2's debit-on-refuse, which forked honest
//     refusers) a refused lane block's on-chain payout is NODE-LOCAL LIABILITY
//     -- never a ledger mutation (docs/xmr-lane/r-c-rework-3.md);
//   * HELD -- a transient failure past retry_bound is held, never dropped;
//   * the LINEAGE VOTE (CONVERGED / CONTESTED / ISOLATED) replaces the M=3 /
//     2-distinct-roots run: refused blocks alone never halt; ISOLATED needs a
//     VERIFIED counter-lineage and is non-terminal;
//   * sidecar v2 carries the booking kind + exact maps (boot re-drive);
//   * the tri-state carry (Unknown holds, never a false orphan) and the F2 gap
//     re-drive live in XmrNode; this class consults chain_carries3.
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
#include <ctime>
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
#include "xmr_minority_converge.hpp"               // D2: detection rule, refold, marker

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

    // ── R6: TWO-SIDED chain-ordered booking + the divergence cap ─────────────
    // book_deferral: a chain block at height h > cursor + 1 + D_conf is NOT booked
    // when it arrives; it is held (still holding the R4 gate) and booked when the
    // cursor reaches h - 1 - D_conf, so every node books in the SAME chain order
    // and FINALIZE(h) reads the SAME pending set (h, h + D_conf] everywhere. OFF
    // only for an A/B comparison (it reintroduces the RUN3 lagging-receiver fork).
    bool          book_deferral = true;
    // Divergence cap: 0 = default (2 * D_conf heights). The cursor may fall this
    // many heights behind the buried frontier (hw - D_conf) while a lane block is
    // lane-root-unknown / HELD, for at most divergence_cap_ticks consecutive
    // ticks, before the lane is declared HELD-LAG (R-C rework-2: loud, counted,
    // NON-terminal -- the cursor stays held by the held block itself, main's
    // lag-gate suspends the builder, and it clears the moment the held block
    // resolves). divergence_cap_terminal is RETIRED (no retry bound exhausts
    // into a drop any more; kept so the CLI flag still parses).
    std::uint64_t divergence_cap_heights  = 0;
    std::uint64_t divergence_cap_ticks    = 20;
    std::uint64_t divergence_cap_terminal = 2;

    // ── R-C rework-2: the RICH booking callback (rework-3: the payout of a
    //    refused block feeds the node-local LIABILITY, never the ledger) ─────
    // Same contract as book_from_chain, plus what the money path needs when the
    // CREDIT side is refused: the block's on-chain PAYOUT map (sink excluded) when
    // it is decodable, and the owed-output amount that could NOT be attributed to
    // a payee identity. When set it is used instead of book_from_chain.
    struct ChainBooking {
        Amounts       credit, payout;       // payout: filled whenever payout_decoded (also on a false return)
        std::string   why;
        bool          payout_decoded = false;   // payout is the COMPLETE attributed owed-output map of the block
        std::uint64_t unattributed_pico = 0;    // on-chain value this node cannot attribute to a key (root unknown:
                                                // the whole reward incl. sink; unmapped outputs: their sum)
        std::uint64_t total_pico = 0;           // the block's coinbase total (diagnostics)
        std::string   onchain_root_hex;         // 0x03 root, when parsed
        // D2 (minority converges to majority): the builder datum and the lineage
        // point of a matched commitment, for the minority-detection observation.
        bool          has_extra_nonce = false;  // the 0x02 extra-nonce payload was parsed
        std::uint32_t extra_nonce = 0;          // its first 4 bytes, LE (builder_key = >> 20)
        bool          has_matched_since = false;// the 0x03 root matched a ring state ...
        std::uint64_t matched_since = 0;        // ... that became current at this coin height
    };
    std::function<bool(std::uint64_t, const std::string&, ChainBooking&)> book_from_chain_ex;

    // ── R-C rework-2: the transient-retry bound and the HELD state ───────────
    // A transient booking failure (root-unknown while not yet decidable, block
    // fetch / parse failure) is retried every tick up to retry_bound attempts.
    // Past the bound the block is HELD -- never silently dropped (the pre-rework
    // cap fell into booking_stall_timeout -> REFUSED, m_chain_seen, credit gone):
    // it stays in the retry set (so it keeps holding the R4 gate), is re-tried
    // every held_retry_every ticks (so a decidable reclassification or a
    // recovered fetch still lands), raises a cba-ALARM HELD each retry, and is
    // counted (held_now / held_entered / held_resolved).
    std::uint64_t retry_bound       = 600;
    std::uint64_t held_retry_every  = 50;

    // ── R-C rework-2: the LINEAGE VOTE (replaces the M=3/2-distinct run) ─────
    // A refused-count can never be a halt trigger: a single live diverged builder
    // commits a NEW root at every own FINALIZE (so "3 consecutive, 2 distinct" is
    // trivially met by ONE forker), consecutive runs are a coin-flip test on one
    // hashrate share, and any Monero miner can append a random 03 21 00 tail.
    // Three states per node:
    //   CONVERGED  refused fraction over the last vote_obs_window frontier lane
    //              blocks < contest (num/den). Normal.
    //   CONTESTED  refused fraction >= contest with >= vote_obs_min observations
    //              and no VERIFIED counter-lineage outvoting us. LOUD (state
    //              alarm + per-block alarm), keeps refusing-not-crediting
    //              (payout -> node-local liability) and KEEPS BUILDING (ruled
    //              default: contested_suspends=false). With contested_suspends
    //              =true (operator opt-in) lane template production is
    //              SUSPENDED until CONVERGED. Never halts the node:
    //              without a verifiable counter-lineage refusals are
    //              indistinguishable from outsider tags.
    //   ISOLATED   a VERIFIED counter-lineage L' (register_counter_lineage --
    //              produced by the W6 verified-resync verifier; no production
    //              caller yet) holds >= vote_k_min AND >= iso (num/den) of the
    //              attributed lane blocks since its fork height. The node's lane
    //              production is suspended (on_isolation hook -> main), booking
    //              continues (the vote stays live), NOT terminal: it returns to
    //              CONTESTED when L' drops below iso for vote_exit_hold further
    //              attributed blocks, or exits via adoption (W6) + restart.
    std::size_t   vote_obs_window  = 24;
    std::size_t   vote_obs_min     = 6;
    std::uint32_t vote_contest_num = 1, vote_contest_den = 3;
    std::size_t   vote_window      = 32;   // attributed blocks since the fork height considered by the vote
    std::size_t   vote_k_min       = 8;
    std::uint32_t vote_iso_num     = 2, vote_iso_den = 3;
    std::size_t   vote_exit_hold   = 16;   // attributed blocks below iso before ISOLATED -> CONTESTED
    std::uint64_t vote_stale_s     = 48 * 3600;   // observations older than this are dropped (0 = never)

    // ── R-C rework-3: RULED DEFAULTS ────────────────────────────────────────
    // (b) REFUSE-SIDE MONEY IS NODE-LOCAL (operator ruling: (b)). A refused lane block's on-chain
    // reward is recorded in a node-local LIABILITY ledger (per payee when the
    // payout decodes from the on-chain bytes + this node's own ring alone, else
    // the whole reward), with a loud alarm and counters. It NEVER mutates eo /
    // finalW / owed_digest: two honest nodes that refuse the same block stay
    // byte-identical whatever they knew about it and whenever they knew it
    // (rework-2's debit-on-refuse was attribution-dependent, attribution was
    // wire-timing-dependent, and three honest nodes ended on three digests).
    // The only value; the long-term fixes are consensus-side
    // (docs/xmr-lane/r-c-rework-3.md §5):
    //   (a) the lane_commitment preimage in-band in the coinbase (every node
    //       derives r for every lane block; "refused" stops being a money event);
    //   (c) a consensus carrier for refuse events through the GAP-2 relay.
    enum class RefuseMoney : int { NodeLocalLiability = 0 };
    RefuseMoney   refuse_money       = RefuseMoney::NodeLocalLiability;
    // CONTESTED -> suspend lane template production. OPERATOR RULING: default
    // OFF. CONTESTED is a loud alarm (cba-ALARM CONTESTED + contested_entered)
    // and the node KEEPS BUILDING. Evidence (r-c-rework-3.md §3): under a
    // 64-height forker + 60 s wire skew the honest owed_digests stayed
    // byte-equal at every shared cursor, while contested-suspend DEADLOCKED the
    // honest lane once the forker stopped (all honest builders suspended, the
    // window could only refill with blocks nobody was building). true = the
    // operator opt-in (--contested-suspend on): the contested hook
    // (set_contested_hook) fires synchronously inside the tick that decided it
    // and auto-releases when the vote returns to CONVERGED.
    bool          contested_suspends = false;
    // D3: the vote's observation window survives a restart (<sidecar>.obs,
    // append-only, compacted). Needs sidecar_path.
    bool          persist_vote_obs   = true;

    // ── D2 (operator ruling D2 = A, 2026-09-24): MINORITY CONVERGES TO MAJORITY ─
    // docs/xmr-lane/d2-minority-converge.md. Every canonical lane block this
    // node decides is one OBSERVATION (matched / unmatched / undecided, own or
    // foreign, the builder key off its 0x02 extra-nonce). M consecutive
    // UNMATCHED foreign blocks from >= B_min distinct builders = this node is
    // the MINORITY (a single foreign block, or M from one builder, is refuse +
    // alarm only -- never a halt). Then: CONVERGING (lane production suspended),
    // re-derive the ledger with this node's own unverifiable blocks on the
    // refuse/liability path, CHECK that the re-derived owed_digest history
    // reproduces the majority's commitments; adopt it (store rewritten, ledger
    // re-lineaged, ring re-seeded, production resumed) or HALT (DIVERGED: lane
    // production withdrawn, loud, nothing mutated, never a guess).
    //   Off      -- today's behaviour exactly (refuse + alarm; no detection)
    //   On       -- detect, converge or halt (default)
    //   HaltOnly -- detect -> DIVERGED; never adopts (observe-only posture)
    enum class MinorityMode : int { Off = 0, On = 1, HaltOnly = 2 };
    MinorityMode  minority_mode        = MinorityMode::On;
    std::size_t   minority_run         = 3;     // M
    std::size_t   minority_builders    = 2;     // B_min
    std::uint64_t converge_retry_bound = 600;   // undecidable attempts (one per tick) before DIVERGED
    std::uint64_t converge_retry_every = 50;    // DIVERGED: re-attempt cadence (ticks) + banner repeat
    std::uint64_t converge_max_depth   = 0;     // 0 = 4 * D_conf: a fork deeper than this is never re-derived (W6)
    std::uint64_t converge_hold_ticks  = 0;     // TEST knob: ticks CONVERGING holds before the first attempt
    int           converge_crash_after = 0;     // TEST (KAT) failpoint: stop after phase 1 'proposed' / 2 'applied'
    // The re-derivation's decoder: book (h, bid) against the SCRATCH candidate
    // ring (cands/superseded as ReconRing::candidates() yields them). Same
    // contract as book_from_chain_ex; root_only = the caller already holds the
    // block's booked maps, only the 0x03 root match (age-bounded) is asked.
    struct ScratchQuery {
        const std::vector<::v37::bytes32>* cands = nullptr;
        const std::vector<std::uint64_t>*  superseded = nullptr;
        bool root_only = false;
    };
    std::function<bool(std::uint64_t, const std::string&, const ScratchQuery&, ChainBooking&)> book_scratch;
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
        // R-C rework-2 (sidecar v2): WHICH booking this is and its exact maps, so
        // the boot re-drive re-registers the SAME FOUND (the v1 re-drive rebuilt
        // {payee: reward} for every record -- wrong for a coinbase-authority
        // booking and for a debit-only one).
        //   'a' option-A own win  (credit == payout == {payee: reward})
        //   'c' coinbase-authority CREDITED booking (credit, payout as booked)
        //   'd' DEBIT-ONLY booking of a refused block (credit = {}, payout) --
        //       rework-2 LEGACY: rework-3 never writes one (refuse-side money is
        //       node-local); a v2 sidecar that still carries one is re-driven as
        //       it was booked (the ledger already holds it from the replay)
        char          kind = 'a';
        Amounts       credit, payout;
    };
    // R-C rework-3 (ruled (b)): the NODE-LOCAL LIABILITY record of one refused
    // lane block. `payout` = the per-payee part decoded from the on-chain bytes
    // alone (this node's own ring; never a wire descriptor), `unattributed_pico`
    // = what could not be attributed (root unknown -> the whole reward incl. the
    // sink; unmapped outputs -> their sum). Persisted in <sidecar>.liability,
    // reloaded at boot. NEVER a ledger key, never an eo/finalW/owed_digest input.
    struct LiabilityRec {
        std::uint64_t height = 0;
        std::string   bid, root_hex, why;
        Amounts       payout;                 // attributed per payee (on-chain bytes only)
        std::uint64_t unattributed_pico = 0;
        std::uint64_t total_pico = 0;         // the block's coinbase total (0 = unknown)
        std::uint64_t attributed_pico() const {
            std::uint64_t a = 0; for (const auto& [k, v] : payout) { (void)k; if (v > 0) a += static_cast<std::uint64_t>(v); }
            return a;
        }
    };
    enum class VoteState : int { Converged = 0, Contested = 1, Isolated = 2 };
    static const char* vote_state_name(VoteState s) {
        switch (s) { case VoteState::Converged: return "CONVERGED"; case VoteState::Contested: return "CONTESTED";
                     case VoteState::Isolated: return "ISOLATED"; }
        return "?";
    }
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
        // the subset of booking_stall_timeout whose cut-pending was a GAP-2 relay
        // REPAIR still in flight (the winner-side order / its receipts / their
        // Monero context never completed): a relay-repair STALL, named as one --
        // never an anonymous "cut-pending" refusal of an honest block.
        std::uint64_t relay_repair_stall_timeout = 0;
        std::uint64_t late_booked_post_finalize = 0;
        // R5: lane blocks whose 03 root matched no candidate digest, kept in the
        // retry set (never memoized) and re-decoded as the candidate ring advances;
        // `lane_root_unknown_resolved` = later booked; `lane_root_unknown_terminal`
        // = exhausted the retry bound still unknown (LOUD; a real other-lane block
        // or a ring that never reached the winner's state).
        std::uint64_t lane_root_unknown_retries = 0, lane_root_unknown_resolved = 0,
                      lane_root_unknown_terminal = 0;
        // R6 (TWO-SIDED chain-ordered booking): chain blocks that arrived at a
        // height ABOVE cursor + 1 + D_conf and were held back (not booked) until
        // the cursor reached them. `booking_deferred` counts deferral events
        // (one per block per arrival); `booked_after_deferral` the deferred
        // blocks whose booking was then ATTEMPTED in chain order (a not-lane or
        // transient outcome counts: the point is the order). Normal on a node that is
        // catching up or whose R4 gate is held; late_unbooked MUST still be 0.
        std::uint64_t booking_deferred = 0, booked_after_deferral = 0;
        // R6 DIVERGENCE CAP -> R-C rework-2. `diverged` is 1 WHILE the node is
        // ISOLATED by the lineage vote (non-terminal; it drops back to 0 when the
        // vote flips). `divergence_ticks` / `divergence_lag_max` feed HELD-LAG.
        // `divergence_dropped` stays 0: no path drops a chain block any more.
        // `divergence_alarms` counts ISOLATED + HELD-LAG entry banners.
        std::uint64_t diverged = 0, divergence_alarms = 0, divergence_dropped = 0,
                      divergence_lag_max = 0, divergence_ticks = 0;
        // R-C: `refused_not_credited` = SYNCED-but-unmatched lane blocks refused-
        // not-credited (loud alarm, gate released, NEVER a halt by itself).
        std::uint64_t refused_not_credited = 0;
        // R-C rework-3 (ruled (b)): the NODE-LOCAL LIABILITY of refused lane
        // blocks. `liability_blocks` refused blocks recorded; `_attributed_pico`
        // the per-payee part (on-chain bytes only), `_unattributed_pico` the rest
        // (whole reward when the root is unknown), `liability_pico` their sum --
        // the over-statement of owed(k) this node carries until a consensus
        // carrier ((a)/(c)) exists. `ledger_mutations_on_refuse` MUST read 0.
        // `legacy_debit_records` = rework-2 'd' sidecar records re-driven at boot.
        std::uint64_t liability_blocks = 0, liability_pico = 0, liability_attributed_pico = 0,
                      liability_unattributed_pico = 0, liability_alarms = 0, liability_payees = 0,
                      ledger_mutations_on_refuse = 0, legacy_debit_records = 0;
        // R-C rework-2 (HOLD cap): transient failures past retry_bound are HELD
        // (never dropped). held_now = currently held bids.
        std::uint64_t held_entered = 0, held_resolved = 0, held_alarms = 0, held_now = 0;
        // R-C rework-2: HELD-LAG (the non-terminal replacement of the R6 cap).
        std::uint64_t held_lag = 0, held_lag_entered = 0, held_lag_cleared = 0;
        // R-C rework-2: the LINEAGE VOTE. vote_state = 0/1/2 (CONVERGED/CONTESTED/
        // ISOLATED); obs_* over the last vote_obs_window frontier lane blocks;
        // votes_* over the attributed window since the counter-lineage fork.
        std::uint64_t vote_state = 0, contested_entered = 0, isolated_entered = 0, isolated_exited = 0,
                      obs_n = 0, obs_refused = 0, obs_unattributed = 0,
                      votes_me = 0, votes_counter = 0, counter_lineages = 0;
        // R-C rework-3: CONTESTED -> lane suspend (hook edges), and D3: the vote's
        // observation window restored from <sidecar>.obs at boot.
        std::uint64_t contested_suspend_edges = 0, contested_resume_edges = 0,
                      obs_restored = 0, obs_persist_failures = 0;
        // D2 (minority converges to majority). minority_state = 0/1/2
        // (CONVERGED/CONVERGING/DIVERGED); run_len/run_builders = the current
        // unmatched-foreign run; converged = adoptions; diverged_halts = entries
        // into the halt; own_refused_on_converge = own blocks moved to the
        // refuse/liability path by an adoption; liability_released = refused
        // majority blocks credited by an adoption.
        std::uint64_t minority_state = 0, minority_run_len = 0, minority_run_builders = 0, minority_runs_detected = 0,
                      converged = 0, diverged_halts = 0, diverged_cleared = 0, own_refused_on_converge = 0,
                      liability_released = 0, converge_attempts = 0, converge_undecidable = 0, converge_failed = 0,
                      isolated_marked = 0, mobs_n = 0, mobs_restored = 0, converge_boot_finished = 0,
                      converge_boot_dropped = 0, converge_check_mismatch = 0;
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
        // R-C rework-2: installed through the node, which composes it with its
        // own F2 gap gate (never step onto h while h + D_conf is unscanned).
        m_node.set_booking_gate(
            [this](std::uint64_t h) { return booking_gate(h); });
        // R6 evidence: the AUTHORITATIVE pending set at every FINALIZE(h), printed
        // synchronously from inside the driver's walk (not reconstructed from log
        // order). Two converged nodes print identical cba-finalize: lines.
        m_node.finalize_driver().set_finalize_observer(
            [this](const std::string& bid, std::uint64_t h, std::uint64_t bin) { on_finalize_step(bid, h, bin); });
    }

    FinalizeConnect(const FinalizeConnect&) = delete;
    FinalizeConnect& operator=(const FinalizeConnect&) = delete;

    // ── boot: re-drive the sidecar's pending FOUNDs into the fresh driver.
    //    Call BEFORE the stratum listener starts and BEFORE the first pump_poll
    //    (so the driver's maps are rebuilt before any Extend can step past H_b).
    BootReport reseed_after_bring_up() {
        const bool finish = converge_boot_pre();   // D2: a marker left by an adoption (before the sidecar is read)
        BootReport rep = reseed_sidecar();
        load_liability();
        load_obs();   // R-C rework-3 (D3): the vote window survives a restart
        if (finish) converge_boot_post();          // D2: an 'applied' adoption is finished here
        load_isolated();                           // D2: isolation marks survive a restart
        load_mobs();                               // D2: the minority observations survive a restart (re-detects)
        // R-C rework-2 (F2): the boot GAP RE-DRIVE (every canonical height between
        // the recovered finalize cursor and the tip -- the boot tip initial_sync
        // applied before our observers existed, every lane block mined while this
        // node was down, deferred-but-unbooked blocks that died with the previous
        // process) runs from the FIRST tick(), not here: the consumer's booking
        // callback may not be fully bound yet (main binds the settlement ledger
        // after this call). Until then the node's gap gate holds the finalize walk
        // at the recovered cursor. No-op unless enable_gap_redrive() was armed.
        if (m_node.gap_redrive_enabled() && m_node.scan_height())
            say("boot: gap re-drive armed from the recovered cursor " + std::to_string(m_node.scan_height()) +
                " (runs on the first tick; the finalize walk is held there until then)");
        echo_node_log();
        return rep;
    }

private:
    BootReport reseed_sidecar() {
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
            // R-C rework-2 (M4): re-register the SAME FOUND the record was booked
            // with -- option-A {payee: reward}, or the exact coinbase-authority /
            // debit-only maps carried by a v2 sidecar line.
            Amounts credit, payout;
            if (rec.kind == 'a') { credit = amounts_from(rec.payee, rec.reward, nullptr); payout = credit; }
            else                 { credit = rec.credit; payout = rec.payout; }
            const bool ok = m_node.on_network_block_won(rec.height, id, credit, payout);
            if (!ok || !m_node.ledger().is_pending(bid)) {
                ++rep.stale_dropped;
                say("boot: sidecar " + short_bid(bid) + " not admitted by the node/ledger; dropped");
                continue;
            }
            m_pending[bid] = rec;
            if (rec.kind == 'c') m_chain_booked_once[bid] = true;
            if (rec.kind == 'd') {
                ++m_stats.legacy_debit_records;
                say("boot: LEGACY rework-2 debit-only record " + short_bid(bid) + " re-driven as booked (the ledger already "
                    "holds it from the replay); rework-3 never writes one -- refuse-side money is node-local liability");
            }
            if (rec.kind != 'd') m_race.observe_own(rec.height, bid, rec.found_unix_s);   // a debit is not an own/credited block
            if (pending) ++rep.reseeded; else ++rep.reregistered;
            say(std::string("boot: ") + (pending ? "re-drove pending FOUND " : "RE-REGISTERED lost FOUND ") +
                short_bid(bid) + " h=" + std::to_string(rec.height) + " kind=" + std::string(1, rec.kind) +
                " (finalizes when hw >= " + std::to_string(rec.height + m_cfg.d_conf) + ")");
        }
        (void)sidecar_flush();
        echo_node_log();
        return rep;
    }

public:

    // ── the main-loop tick. Call it right BEFORE transport.pump_poll() so a win
    //    queued during the sleep is registered before the tip can advance past
    //    it (the late-FOUND guard below is the backstop, not the plan).
    TickReport tick() {
        TickReport t;
        echo_node_log();                       // finalize: / win: lines since the last tick
        // R6: book in CHAIN ORDER and interleave with the finalize walk. One
        // pass = (a) retry the transient failures + book every DEFERRED block the
        // cursor has reached, ascending height; (b) re-advance the finalize
        // driver at the unchanged high-water so the cursor steps onto the next
        // height (its R4 gate releases once the block at cursor+1+D_conf is
        // booked); repeat while either side made progress. A node catching up
        // therefore replays exactly the synced node's sequence:
        //   book(h+D_conf) -> FINALIZE(h) -> book(h+1+D_conf) -> FINALIZE(h+1) ...
        // Bounded: every pass books at least one block or moves the cursor, and
        // the loop cap covers a full retention window.
        // The RETRY set is attempted once per tick (first pass only): a transient
        // failure must not burn its retry bound inside one tick. Later passes
        // attempt only DEFERRED blocks the moved cursor has just reached.
        ++m_tick;
        // R-C rework-2 (F2): a gap re-drive that stopped on a header-fetch failure
        // (or a scan that lags the tip for any reason) is retried every tick.
        (void)m_node.redrive_gap_to_tip();
        // R-C rework-2: a walk held on an UNKNOWN carry answer (header fetch
        // failed) or by the gap gate resumes here without waiting for the next
        // Extend. Safe: the high-water is unchanged and every gate still applies.
        // Only when the cursor actually trails the buried frontier (the walk
        // persists hw/cursor, so a no-op re-advance every tick would be an fsync
        // per poll for nothing).
        if (m_node.finalize_driver().cursor_height() + m_cfg.d_conf < m_node.hw().hw_height)
            (void)m_node.readvance_settlement();
        for (std::uint64_t pass = 0; pass < m_cfg.d_conf * 4 + 64; ++pass) {
            const std::uint64_t c0 = m_node.finalize_driver().cursor_height();
            const std::size_t reached = drain_bookings(/*with_retries=*/pass == 0);
            if (reached == 0 && m_deferred.empty()) break;   // nothing reached, nothing waits on the cursor
            (void)m_node.readvance_settlement();
            echo_node_log();
            if (reached == 0 && m_node.finalize_driver().cursor_height() == c0) break;   // the gate holds: no progress this tick
        }
        divergence_check();
        evaluate_vote();
        converge_tick();   // D2: CONVERGING -> attempt / DIVERGED -> banner + retry
        if (!m_liability.empty() && (m_tick % 50 == 1)) {
            ++m_stats.liability_alarms;
            say("cba-ALARM LIABILITY: " + std::to_string(m_stats.liability_blocks) + " refused lane block(s) paid " +
                std::to_string(m_stats.liability_pico) + " piconero on-chain (" + std::to_string(m_stats.liability_attributed_pico) +
                " attributed to " + std::to_string(m_stats.liability_payees) + " payee(s), " +
                std::to_string(m_stats.liability_unattributed_pico) + " unattributed) that this node's owed ledger does NOT "
                "net out: owed(k) is over-stated by up to this much, so a later K_fair coinbase may pay those payees again. "
                "NODE-LOCAL by design (ruled (b)): the ledger never moves on a refusal, so honest refusers stay identical. "
                "Fix = consensus carrier ((a) in-band lane_commitment preimage / (c) GAP-2 relay), operator's hand.");
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
        if (!m_o.book_from_chain && !m_o.book_from_chain_ex) return;
        const std::string bid = lower_hex(bid_hex);
        if (bid.size() != 64 || h == 0) return;
        //  fix 2: dedup on CURRENT ledger state, not on "ever seen" -- an orphaned block that
        // becomes canonical again (branch flip-flop) must be re-booked.
        if (m_pending.count(bid) || m_unrecoverable.count(bid)) return;
        if (m_node.ledger().is_settled(bid) || m_node.ledger().is_pending(bid)) return;
        if (m_chain_seen.count(bid)) return;   //  fix 3b: memo of NON-booked outcomes only (not-lane / late / refused)
        if (m_chain_booked_once.count(bid)) say("cba: chain block " + short_bid(bid) + " h=" + std::to_string(h) + " is canonical AGAIN after an orphan -> re-booking");
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        // R6 (TWO-SIDED chain-ordered booking): a chain block ABOVE cursor + 1 +
        // D_conf is not booked yet. The synced node books h exactly when its
        // cursor stands at h - 1 - D_conf (book(h) precedes advance(h), which
        // finalizes h - D_conf); a lagging node whose gate holds the cursor
        // lower would otherwise book h EARLY and FINALIZE(cursor+1) with a
        // larger pending set -> rearm_first_eligible forks (the RUN3 cursor-7
        // fork: pending {5,6,7,8} vs {5,6,7} at FINALIZE(4)). Held here, in the
        // deferred set (which the booking gate also honours), and booked from
        // tick() in ascending height once the cursor reaches h - 1 - D_conf.
        // (R-C rework-2: there is no terminal DIVERGED drop any more -- an
        // ISOLATED node keeps booking so the lineage vote stays live.)
        if (m_o.book_deferral && h > cursor + 1 + m_cfg.d_conf) {
            const bool fresh = !m_deferred.count(bid);
            m_deferred[bid] = h; m_retry.erase(bid);
            if (fresh) {
                ++m_stats.booking_deferred;
                say("cba: chain block " + short_bid(bid) + " h=" + std::to_string(h) + " DEFERRED (h > cursor " +
                    std::to_string(cursor) + " + 1 + D_conf " + std::to_string(m_cfg.d_conf) +
                    "): booked in chain order when the cursor reaches " + std::to_string(h - 1 - m_cfg.d_conf));
            }
            return;
        }
        m_deferred.erase(bid);   // reached (drain_bookings) or re-fed by the extend observer: either way it is attempted now
        if (h <= cursor) {
            // R4: with the booking gate armed the cursor cannot step past a
            // canonical unbooked lane block, so this is no longer a SILENT fork.
            // It can fire only after a boot cursor mismatch or a TRUNCATED gap
            // re-drive (R-C rework-2: the retry bound no longer releases the gate)
            // -- a LOUD alarm, never a quiet drop. Its payout (if it is a lane
            // block at all) is NOT decoded here: a late DEBIT would need a
            // chain-ordered point the cursor already passed (design note M3,
            // docs/xmr-lane/money-path-debit-on-refuse.md). Must read 0.
            m_chain_seen[bid] = true; ++m_stats.late_unbooked;
            say("cba-ALARM late_unbooked: chain block " + short_bid(bid) + " h=" + std::to_string(h) +
                " is at/below the finalize cursor " + std::to_string(cursor) +
                " — if it is a lane block its credit AND its payout debit can no longer be booked at their chain-ordered "
                "point (would pend forever). With R4 + the F2 gap re-drive this means a boot cursor mismatch or a "
                "truncated gap; this height needs an operator's eyes (credit divergence risk)");
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
        auto fc_it = m_first_cursor.find(bid);
        if (fc_it == m_first_cursor.end()) fc_it = m_first_cursor.emplace(bid, cursor).first;
        const bool late_post_finalize = (cursor > fc_it->second) && (h <= cursor + m_cfg.d_conf);
        FinalizeConnectOptions::ChainBooking bk;
        if (!call_book(h, bid, bk)) {
            const std::string& why = bk.why;
            // R-C: main reclassifies a SYNCED receiver's unmatched-root block
            // "lane-root-unknown:" -> "lane-root-refused:<roothex>:". REFUSED-not-
            // credited (loud alarm, the R4 gate RELEASED for this height), its
            // on-chain payout recorded as NODE-LOCAL LIABILITY (rework-3 (b)), and
            // one OBSERVATION for the lineage vote -- never by itself a halt.
            if (why.rfind("lane-root-refused:", 0) == 0) { note_refused_frontier(h, bid, bk); return; }
            const bool root_unknown = (why.rfind("lane-root-unknown:", 0) == 0);   // R5
            const bool fetch_fail   = (why.rfind("get_block", 0) == 0 || why.find("does not parse") != std::string::npos);
            const bool cut_pend     = (why.rfind("cut-pending:", 0) == 0);
            if (fetch_fail || cut_pend || root_unknown) {   //  fix 4: transient (recon(A+B credit): + receiver's lane not yet at P; R5: + ring not yet at the winner's state)
                const std::uint64_t n = static_cast<std::uint64_t>(++m_retry_n[bid]);
                if (n <= m_o.retry_bound) {
                    m_retry[bid] = h;
                    if (root_unknown) {
                        ++m_stats.lane_root_unknown_retries; m_root_unknown_bids.insert(bid);
                        if (n == 1 || n % 50 == 0)
                            say("cba: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " lane-root-unknown (" + why + ") -> kept, RETRY #" + std::to_string(n) + " as the candidate ring advances (holds the R4 gate)");
                    } else {
                        say("cba: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " booking failed (" + why + ") -> RETRY #" + std::to_string(n));
                    }
                    return;
                }
                // R-C rework-2 (HOLD cap): root-unknown (not yet decidable) and
                // fetch/parse failures are HELD past the bound -- never dropped,
                // never credited-around. The pre-rework code fell into
                // booking_stall_timeout(lane_root_unknown) -> REFUSED + memoized,
                // which silently dropped the credit and released the gate.
                if (root_unknown || fetch_fail) { enter_held(h, bid, why, root_unknown); return; }
                // cut-pending past the bound: the loud release below (its payout is
                // decoded, so it is DEBITED -- conservation-neutral on the payout side).
            }
            m_chain_seen[bid] = true; m_first_cursor.erase(bid);
            if (m_held.erase(bid)) { ++m_stats.held_resolved; m_stats.held_now = m_held.size(); }
            if (why.rfind("not-lane:", 0) == 0) return;   // a stranger's block: nothing to book
            if (cut_pend) {      // R4: the receiver's lane never reached P within the retry bound
                ++m_stats.booking_stall_timeout;
                if (why.find("relay repair of P=") != std::string::npos) {
                    // GAP-2: the view at the winner's cut was being REPAIRED over the
                    // relay and the repair did not complete. Refusing here is a
                    // RELAY-REPAIR STALL of THIS node (its stuck stage is in `why`),
                    // not evidence that the winner's block is dishonest.
                    ++m_stats.relay_repair_stall_timeout;
                    say("cba-ALARM relay_repair_stall_timeout: chain lane block " + short_bid(bid) + " h=" +
                        std::to_string(h) + " -- the GAP-2 relay REPAIR of the winner's cut did NOT complete within the booking retry bound (" +
                        std::to_string(m_o.retry_bound) + " attempts): " + why +
                        " — this is a RELAY-REPAIR STALL on this node, NOT a lane divergence or a dishonest winner; releasing the finalize gate; "
                        "credit for this height is REFUSED (payout -> node-local LIABILITY); operator's eyes needed on the relay");
                } else {
                    say("cba-ALARM booking_stall_timeout: chain lane block " + short_bid(bid) + " h=" +
                        std::to_string(h) + " exhausted its booking retry bound still cut-pending (" + why +
                        ") — releasing the finalize gate; credit for this height is REFUSED (payout -> node-local LIABILITY)");
                }
            }
            m_root_unknown_bids.erase(bid);
            ++m_stats.refused;
            say("cba: REFUSED chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + ": " + why);
            refuse_money(h, bid, bk, why);
            observe_frontier(h, bid, bk.onchain_root_hex, /*booked=*/false);
            // D2: the 0x03 root matched this node's ring (refused for a non-root
            // reason: cut stall, unmapped output, donation rule, cut mismatch):
            // the block is on OUR lineage.
            if (!bk.onchain_root_hex.empty()) observe_d2(h, bid, bk, minority::Verdict::Matched);
            return;
        }
        if (m_root_unknown_bids.erase(bid)) {   // R5: a lane-root-unknown block resolved once the ring caught up
            ++m_stats.lane_root_unknown_resolved;
            say("cba: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " lane-root-unknown RESOLVED after " +
                std::to_string(m_retry_n[bid]) + " retries (the candidate ring reached the winner's ledger state)");
        }
        if (m_held.erase(bid)) { ++m_stats.held_resolved; m_stats.held_now = m_held.size(); say("cba: HELD lane block " + short_bid(bid) + " h=" + std::to_string(h) + " RESOLVED -> booked"); }
        if (late_post_finalize) {
            ++m_stats.late_unbooked; ++m_stats.late_booked_post_finalize;
            say("cba-ALARM late_unbooked(post-finalize): chain lane block " + short_bid(bid) + " h=" + std::to_string(h) +
                " is being booked with the finalize cursor at " + std::to_string(cursor) + " (hw already reached " +
                std::to_string(cursor + m_cfg.d_conf) + " >= h): FINALIZE(" + std::to_string(cursor) +
                ") read the pending set WITHOUT this block — this node's ledger has diverged from a node that booked it in time "
                "(R4 gate released by a stall timeout, or a boot cursor mismatch); booking it anyway, operator's eyes needed");
        }
        c2pool::xmr::node::Hash id{}; (void)hash_from_hex(bid, id);
        PendingRec rec; rec.height = h; rec.kind = 'c'; rec.credit = bk.credit; rec.payout = bk.payout;
        rec.reward = 0; for (const auto& [k, v] : bk.payout) { (void)k; rec.reward += static_cast<std::uint64_t>(v); }
        m_pending[bid] = rec; (void)sidecar_flush();
        if (!m_node.on_network_block_won(h, id, bk.credit, bk.payout) || !m_node.ledger().is_pending(bid)) {
            m_pending.erase(bid); (void)sidecar_flush();
            say("cba: node/ledger did not admit chain lane block " + short_bid(bid)); return;
        }
        ++m_stats.registered; ++m_cba_chain_booked; m_chain_booked_once[bid] = true; m_retry.erase(bid); m_first_cursor.erase(bid);
        // R-C rework-2: one BOOKED observation for the lineage vote (attributed to
        // this node's own lineage). Nothing is "reset": the vote is a window
        // fraction, so a forker's own booked blocks cannot launder its refusals.
        observe_frontier(h, bid, bk.onchain_root_hex, /*booked=*/true);
        m_race.observe_own(h, bid);   // a LANE block is 'own' for the race book (multi-node: own == lane)
        observe_d2(h, bid, bk, minority::Verdict::Matched);   // D2: our lineage (own or foreign)
        say("cba: CHAIN FOUND booked " + short_bid(bid) + " h=" + std::to_string(h) + " payout_keys=" + std::to_string(bk.payout.size()) + " total=" + std::to_string(rec.reward) + " -> finalizes when hw >= " + std::to_string(h + m_cfg.d_conf));
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
        // D2: this node mined it (own for the minority rule); published while the
        // publisher had no relay peer -> isolation-marked (the R1 candidate set).
        m_own_bids.insert(bid);
        if (m_isolated_probe && m_isolated_probe(bid))
            mark_isolated_own(bid, ev.height, "published while no relay peer (parked, late re-announce)");
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
        if (m_o.book_from_chain || m_o.book_from_chain_ex) {   //  (part 2): an OWN win is NOT booked on submit-OK — monerod also says OK
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
    const FinalizeConnectOptions& options() const { return m_o; }
    std::size_t deferred_now() const { return m_deferred.size(); }   // R6: chain blocks awaiting the cursor
    // R-C rework-2: `diverged()` == ISOLATED by the lineage vote (NON-terminal).
    bool        diverged()     const { return m_vote == VoteState::Isolated; }
    bool        isolated()     const { return m_vote == VoteState::Isolated; }
    bool        held_lag()     const { return m_held_lag; }
    VoteState   vote_state()   const { return m_vote; }
    const std::map<std::string, std::uint64_t>& held() const { return m_held; }
    const std::vector<LiabilityRec>& liability() const { return m_liability; }
    const std::map<::v37::bytes32, long long>& liability_by_payee() const { return m_liability_by_payee; }

    // R-C rework-2: the ISOLATED edge hook (main: suspend lane production, stop
    // the in-process miner, withdraw the stratum job -- synchronously, inside
    // the tick that decided it, so no share/hit can slip between the decision
    // and the suspension). Called with (true, why) on entry, (false, why) on exit.
    void set_isolation_hook(std::function<void(bool, const std::string&)> f) { m_iso_hook = std::move(f); }
    // R-C rework-3: the CONTESTED edge hook (opt-in, --contested-suspend on:
    // CONTESTED suspends lane template production; default off). (true, why) when the vote enters CONTESTED,
    // (false, why) when it leaves it -- synchronously, inside the tick that
    // decided it. Only fired when options().contested_suspends.
    void set_contested_hook(std::function<void(bool, const std::string&)> f) { m_contested_hook = std::move(f); }
    bool contested() const { return m_vote == VoteState::Contested; }

    // ── D2 (minority converges to majority): the public seams ───────────────
    enum class ConvergeState : int { Converged = 0, Converging = 1, Diverged = 2 };
    static const char* converge_state_name(ConvergeState s) {
        switch (s) { case ConvergeState::Converged: return "CONVERGED"; case ConvergeState::Converging: return "CONVERGING";
                     case ConvergeState::Diverged: return "DIVERGED"; }
        return "?";
    }
    ConvergeState converge_state() const { return m_cstate; }
    bool converging()    const { return m_cstate == ConvergeState::Converging; }
    bool diverged_halt() const { return m_cstate == ConvergeState::Diverged; }
    // (true, why) the moment the node enters CONVERGING or DIVERGED (main: suspend
    // lane production synchronously, like the isolation hook), (false, why) when
    // it is CONVERGED again (main releases through apply_suspension).
    void set_converge_hook(std::function<void(bool, const std::string&)> f) { m_converge_hook = std::move(f); }
    // Fired synchronously right after an adoption re-lineaged the node (main:
    // re-seed the RECON candidate ring from boot_digest_history(), forget its
    // root-unknown alarm memo, force a template rebuild).
    void set_relineage_hook(std::function<void()> f) { m_relineage_hook = std::move(f); }
    std::uint64_t relineage_seq() const { return m_relineage_seq; }
    // This node's own builder keys (builder_key of the GAP-2 extra-nonce base and
    // of the in-process miner's slot): a lane block carrying one is OWN.
    void set_own_builder_keys(std::set<std::uint32_t> k) { m_own_keys = std::move(k); }
    // "Was this own block published while the publisher had no relay peer"
    // (P2pBlockPublisher: parked for re-announce). Asked when the own win is
    // registered; a yes is persisted in <sidecar>.isolated.
    void set_isolated_probe(std::function<bool(const std::string&)> f) { m_isolated_probe = std::move(f); }
    void mark_isolated_own(const std::string& bid_hex, std::uint64_t h, const std::string& why) {
        const std::string bid = lower_hex(bid_hex);
        if (bid.size() != 64 || m_isolated.count(bid)) return;
        m_isolated[bid] = h; ++m_stats.isolated_marked;
        if (!m_o.sidecar_path.empty()) {
            std::ofstream f(m_o.sidecar_path + ".isolated", std::ios::app);
            std::string w = why.substr(0, 60); for (char& c : w) if (c == ' ' || c == '\t' || c == '\n') c = '_';
            if (f) f << "1 " << bid << ' ' << h << ' ' << now_unix() << ' ' << (w.empty() ? "-" : w) << '\n';
        }
        say("minority: own block " + short_bid(bid) + " h=" + std::to_string(h) + " ISOLATION-MARKED (" + why +
            "): if the majority cannot reproduce its credit cut it is the first candidate for the refuse/liability path");
    }
    const std::vector<minority::Observation>& minority_observations() const { return m_mobs; }
    const minority::RunStatus& minority_run_status() const { return m_last_run; }
    const std::map<std::string, std::uint64_t>& isolated_own() const { return m_isolated; }

    // R-C rework-2: register a VERIFIED counter-lineage L' (the set of 0x03
    // roots its verified snapshot can produce, and the height of its fork point
    // F with this node's lineage). CONTRACT: the caller has VERIFIED it against
    // on-chain lane commitments (W6 verified resync, docs/xmr-lane/
    // finality-boundary.md §W6-verified); an unverified lineage must never be
    // registered -- that is the whole difference between evidence and a vote.
    // No production caller exists yet: until the W6 verifier lands, ISOLATED is
    // unreachable in production and the node can only be CONVERGED/CONTESTED.
    void register_counter_lineage(const std::set<std::string>& roots_hex, std::uint64_t fork_height,
                                  const std::string& source) {
        for (const auto& r : roots_hex) m_counter_roots.insert(lower_hex(r));
        m_counter_fork_h = fork_height;
        ++m_stats.counter_lineages;
        say("cba: VERIFIED counter-lineage registered from " + source + ": " + std::to_string(roots_hex.size()) +
            " root(s), fork height " + std::to_string(fork_height) + " -- lineage vote armed");
        evaluate_vote();
    }

private:
    // One booking attempt through whichever callback is installed.
    bool call_book(std::uint64_t h, const std::string& bid, FinalizeConnectOptions::ChainBooking& bk) {
        if (m_o.book_from_chain_ex) return m_o.book_from_chain_ex(h, bid, bk);
        const bool ok = m_o.book_from_chain(h, bid, bk.credit, bk.payout, bk.why);
        if (!ok) bk.payout.clear();   // the legacy callback carries no payout attribution on a refusal
        return ok;
    }

    // R-C rework-3 (ruled (b)): the payout side of a REFUSED lane block. The
    // block paid its coinbase on-chain whatever this node thinks of its credit;
    // that value is recorded as NODE-LOCAL LIABILITY and NOTHING ELSE. No FOUND,
    // no debit, no eo/finalW/owed_digest mutation: whether this node could
    // attribute the payout (and when it learned enough to) is node-local
    // knowledge -- rework-2 turned it into a ledger input and forked three honest
    // refusers (verify D1). The ledger_seq guard below makes that a counted,
    // loud invariant rather than a comment.
    void refuse_money(std::uint64_t h, const std::string& bid, const FinalizeConnectOptions::ChainBooking& bk,
                      const std::string& why) {
        const std::uint64_t seq0 = m_node.ledger().ledger_seq();
        const ::v37::bytes32 dg0 = m_node.ledger().owed_digest();
        LiabilityRec r;
        r.height = h; r.bid = bid; r.root_hex = lower_hex(bk.onchain_root_hex); r.total_pico = bk.total_pico;
        if (bk.payout_decoded) {
            for (const auto& [k, v] : bk.payout) if (v > 0) r.payout[k] = v;
            r.unattributed_pico = bk.unattributed_pico;
        } else {
            r.unattributed_pico = bk.unattributed_pico ? bk.unattributed_pico : bk.total_pico;
        }
        add_liability(r, why, /*persist=*/true);
        if (m_node.ledger().ledger_seq() != seq0 || !(m_node.ledger().owed_digest() == dg0)) {
            ++m_stats.ledger_mutations_on_refuse;
            say("cba-ALARM INVARIANT: the refuse path of " + short_bid(bid) + " mutated the owed ledger (ledger_seq " +
                std::to_string(seq0) + " -> " + std::to_string(m_node.ledger().ledger_seq()) + ") -- must never happen");
        }
    }

    void add_liability(const LiabilityRec& r0, const std::string& why, bool persist) {
        for (const auto& x : m_liability) if (x.bid == r0.bid) return;   // once per block
        LiabilityRec r = r0;
        r.why = why.substr(0, 60);
        for (char& c : r.why) if (c == ' ' || c == '\t' || c == '\n') c = '_';
        if (r.why.empty()) r.why = "-";
        if (r.payout.empty() && r.unattributed_pico == 0) {
            // Either the payout decoded COMPLETELY and pays no ledger key (the whole
            // reward went to the residual sink: no owed over-statement), or the
            // block's total is unknown. Neither is a liability.
            say("cba: refused block " + short_bid(r.bid) + " h=" + std::to_string(r.height) +
                (r.total_pico ? " pays no owed key (payout fully decoded; the reward went to the residual sink) -- no liability"
                              : " carries no decodable on-chain value (total unknown) -- nothing to record as liability"));
            return;
        }
        m_liability.push_back(r);
        ++m_stats.liability_blocks;
        const std::uint64_t att = r.attributed_pico();
        m_stats.liability_attributed_pico += att;
        m_stats.liability_unattributed_pico += r.unattributed_pico;
        m_stats.liability_pico += att + r.unattributed_pico;
        for (const auto& [k, v] : r.payout) m_liability_by_payee[k] += v;
        m_stats.liability_payees = m_liability_by_payee.size();
        if (persist && !m_o.sidecar_path.empty()) {
            std::ofstream f(m_o.sidecar_path + ".liability", std::ios::app);
            if (f) f << liability_line(r);
        }
        if (!persist) return;
        std::string pm;
        for (const auto& [k, v] : r.payout) pm += " " + hex_of(k).substr(0, 8) + "=" + std::to_string(v);
        say("cba-ALARM LIABILITY: h=" + std::to_string(r.height) + " bid=" + short_bid(r.bid) + " refused lane block paid " +
            std::to_string(att + r.unattributed_pico) + " piconero on-chain -> NODE-LOCAL liability (attributed{" + pm +
            " } unattributed=" + std::to_string(r.unattributed_pico) + ") [" + why.substr(0, 60) + "]. The owed ledger is "
            "NOT touched (eo/finalW/owed_digest unchanged): honest refusers stay byte-identical. Totals: blocks=" +
            std::to_string(m_stats.liability_blocks) + " pico=" + std::to_string(m_stats.liability_pico));
    }

    // Reload the liability tally (v2 lines) plus the rework-2 suspense file (v1:
    // unattributed only), so a restart keeps the count and the alarm.
    void load_liability() {
        if (m_o.sidecar_path.empty()) return;
        std::size_t n0 = m_liability.size();
        {
            std::ifstream in(m_o.sidecar_path + ".liability");
            std::string line;
            while (std::getline(in, line)) {
                std::istringstream is(line);
                std::string ver, bid, root, pm, why; unsigned long long h = 0, tot = 0, un = 0;
                if (!(is >> ver >> bid >> h >> root >> tot >> un >> pm >> why) || ver != "2") continue;
                LiabilityRec r; r.height = h; r.bid = bid; r.root_hex = root == "-" ? "" : root;
                r.total_pico = tot; r.unattributed_pico = un;
                if (!map_parse(pm, r.payout)) continue;
                add_liability(r, why, /*persist=*/false);
            }
        }
        {
            std::ifstream in(m_o.sidecar_path + ".suspense");   // rework-2 legacy
            std::string line;
            while (std::getline(in, line)) {
                std::istringstream is(line);
                std::string ver, bid, root, why; unsigned long long h = 0, amt = 0;
                if (!(is >> ver >> bid >> h >> root >> amt >> why) || ver != "1") continue;
                LiabilityRec r; r.height = h; r.bid = bid; r.root_hex = root == "-" ? "" : root; r.unattributed_pico = amt;
                add_liability(r, why, /*persist=*/false);
            }
        }
        if (m_liability.size() > n0)
            say("boot: LIABILITY reloaded: " + std::to_string(m_liability.size()) + " refused block(s), " +
                std::to_string(m_stats.liability_pico) + " piconero (" + std::to_string(m_stats.liability_attributed_pico) +
                " attributed, " + std::to_string(m_stats.liability_unattributed_pico) + " unattributed)");
    }

    void enter_held(std::uint64_t h, const std::string& bid, const std::string& why, bool root_unknown) {
        m_retry[bid] = h;   // stays in the retry set: keeps holding the R4 gate
        if (root_unknown) m_root_unknown_bids.insert(bid);
        const bool fresh = !m_held.count(bid);
        m_held[bid] = h;
        m_stats.held_now = m_held.size();
        if (fresh) ++m_stats.held_entered;
        ++m_stats.held_alarms;
        if (fresh || m_stats.held_alarms % 10 == 0)
            say("cba-ALARM HELD: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) + " is still " +
                (root_unknown ? "lane-root-unknown (this node is not yet decidable for it)" : "unfetchable/unparseable") +
                " after " + std::to_string(m_retry_n[bid]) + " attempts (" + why.substr(0, 80) + "). HELD, NOT dropped: "
                "it keeps holding the finalize gate, is re-tried every " + std::to_string(m_o.held_retry_every) +
                " ticks, and books / is refused (liability) the moment it resolves. held_now=" + std::to_string(m_held.size()));
    }
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
    //
    // R6 (two-sided): a DEFERRED chain block (arrived above cursor+1+D_conf,
    // not yet classified lane / not-lane) holds the gate the same way -- it may
    // be a lane block, and the synced node had it booked before FINALIZE(h) ran.
    // By construction a deferred block sits at hh > cursor + 1 + D_conf, so it
    // never holds h = cursor + 1: the driver steps ONE height, stalls on the
    // next, tick() books the block the new cursor reached, re-advances -- the
    // chain-ordered interleave. A DIVERGED lane holds the gate for good.
    bool booking_gate(std::uint64_t h) {
        const std::uint64_t hw = h + m_cfg.d_conf;
        // R-C rework-2: an UNKNOWN carry answer (header fetch failed) HOLDS, like
        // a carried block -- only a positive "No" (a different block / above the
        // tip) releases a retry/deferred entry here.
        for (const auto& [bid, hh] : m_retry)
            if (hh <= hw && m_node.chain_carries3(hh, bid) != XmrNode::Carry::No) return false;
        for (const auto& [bid, hh] : m_deferred)
            if (hh <= hw && m_node.chain_carries3(hh, bid) != XmrNode::Carry::No) return false;
        return true;
    }

    // R6 evidence line. `pending{...}` = the coin heights of every OTHER lane
    // block the ledger holds pending at the instant FINALIZE(h) reads the set
    // (h:bid12 pairs, ascending) -- what rearm_first_eligible sees. Diffing
    // these lines across nodes per (h, bid) is the direct test of the
    // chain-ordered booking invariant; pendset.py consumes them.
    void on_finalize_step(const std::string& bid, std::uint64_t h, std::uint64_t bin) {
        std::vector<std::pair<std::uint64_t, std::string>> pend;
        for (const auto& [b, rec] : m_pending)
            if (b != bid && m_node.ledger().is_pending(b)) pend.emplace_back(rec.height, b.substr(0, 12));
        std::sort(pend.begin(), pend.end());
        std::string s;
        for (const auto& [hh, b] : pend) s += (s.empty() ? "" : " ") + std::to_string(hh) + ":" + b;
        say("cba-finalize: h=" + std::to_string(h) + " bid=" + short_bid(bid) + " bin_height=" + std::to_string(bin) +
            " cursor=" + std::to_string(m_node.finalize_driver().cursor_height()) + " pending{" + s + "}");
    }

    // R6: one chain-ordered booking pass. Retries (transient fetch failures /
    // cut-pending / lane-root-unknown) and the deferred blocks the cursor has
    // reached (hh <= cursor + 1 + D_conf), merged and booked in ASCENDING height
    // so booking lands oldest-first and identically on every node. A block the
    // chain POSITIVELY no longer carries is dropped (an orphan; re-fed by the
    // extend observer if it ever becomes canonical again); an UNKNOWN carry
    // answer keeps it (R-C rework-2). HELD bids are attempted only every
    // held_retry_every ticks (they stay in the retry set meanwhile).
    // Returns the number of DEFERRED blocks the cursor has reached this pass
    // (attempted whatever their outcome) -- the tick loop's progress signal.
    std::size_t drain_bookings(bool with_retries) {
        if ((!with_retries || m_retry.empty()) && m_deferred.empty()) return 0;
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        const std::uint64_t reach  = cursor + 1 + m_cfg.d_conf;
        std::vector<std::pair<std::uint64_t, std::string>> again;   // (height, bid)
        if (with_retries) {
            const bool held_slot = m_o.held_retry_every == 0 || (m_tick % m_o.held_retry_every) == 0;
            for (auto it = m_retry.begin(); it != m_retry.end();) {
                if (m_held.count(it->first) && !held_slot) { ++it; continue; }   // HELD: kept, not attempted this tick
                again.emplace_back(it->second, it->first);
                it = m_retry.erase(it);
            }
        }
        std::size_t reached = 0;
        for (auto it = m_deferred.begin(); it != m_deferred.end();) {
            const bool is_reached = it->second <= reach;
            if (is_reached || m_node.chain_carries3(it->second, it->first) == XmrNode::Carry::No) {
                if (is_reached) { again.emplace_back(it->second, it->first); ++reached; ++m_stats.booked_after_deferral; }
                it = m_deferred.erase(it);   // orphaned-while-deferred: dropped, no attempt
            } else ++it;
        }
        std::sort(again.begin(), again.end());
        for (const auto& [h, bid] : again) {
            const auto c = m_node.chain_carries3(h, bid);
            if (c == XmrNode::Carry::Yes) book_chain_block(h, bid);   // still canonical -> attempt
            else if (c == XmrNode::Carry::Unknown) m_retry[bid] = h;  // UNKNOWN: keep (holds the gate), retry next tick
            else {                                                    // an orphan: drop
                m_root_unknown_bids.erase(bid); m_first_cursor.erase(bid);
                if (m_held.erase(bid)) { ++m_stats.held_resolved; m_stats.held_now = m_held.size(); }
            }
        }
        return reached;
    }

    // ── R-C (rework-2): a SYNCED receiver's unmatched-root lane block ────────
    // main tagged it "lane-root-refused:<roothex>:". REFUSE-not-credit it -- do
    // NOT book its credit, do NOT hold the finalize gate for it (the cursor is
    // never held hostage by one participant), raise a LOUD alarm, record its
    // on-chain payout as NODE-LOCAL LIABILITY (rework-3 (b): never a ledger
    // mutation), and record ONE observation for the lineage vote.
    void note_refused_frontier(std::uint64_t h, const std::string& bid, const FinalizeConnectOptions::ChainBooking& bk) {
        const std::string& why = bk.why;
        std::string roothex = bk.onchain_root_hex;
        if (roothex.empty()) {   // parse "lane-root-refused:<roothex>:<rest>"
            const std::size_t p0 = std::string("lane-root-refused:").size();
            const std::size_t p1 = why.find(':', p0);
            roothex = (p1 == std::string::npos) ? why.substr(p0) : why.substr(p0, p1 - p0);
        }
        roothex = lower_hex(roothex);
        m_retry.erase(bid); m_retry_n.erase(bid); m_deferred.erase(bid);
        m_root_unknown_bids.erase(bid); m_first_cursor.erase(bid);
        if (m_held.erase(bid)) { ++m_stats.held_resolved; m_stats.held_now = m_held.size(); }
        m_chain_seen[bid] = true;
        ++m_stats.refused_not_credited;
        say("cba-ALARM lane-root-refused: chain lane block " + short_bid(bid) + " h=" + std::to_string(h) +
            " root=" + roothex.substr(0, 12) + " is SYNCED-but-unmatched -> REFUSED (not credited), gate released, "
            "payout -> node-local LIABILITY (" + std::string(bk.payout_decoded && !bk.payout.empty() ? "per payee" : "whole reward") +
            ", ledger untouched); lineage vote state " + vote_state_name(m_vote) + ".");
        refuse_money(h, bid, bk, why);
        observe_frontier(h, bid, roothex, /*booked=*/false);
        // D2: a D7 stale root is a HISTORICAL state of our own lineage (matched);
        // anything else is a commitment this node's history cannot reproduce.
        observe_d2(h, bid, bk, why.find(":stale-root:") != std::string::npos ? minority::Verdict::Matched
                                                                             : minority::Verdict::Unmatched);
    }

    // ── R-C rework-2: THE LINEAGE VOTE ──────────────────────────────────────
    // R-C rework-3 (D3): `t` is WALL-CLOCK unix seconds (persisted in
    // <sidecar>.obs; a steady_clock point does not survive a restart).
    struct Obs { std::uint64_t h = 0; std::string bid, root; bool booked = false; std::uint64_t t = 0; };
    static std::uint64_t now_unix() {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
    char attribute(const Obs& o) const {
        if (o.booked) return 'm';
        if (!o.root.empty() && m_counter_roots.count(o.root)) return 'p';
        return 'u';
    }
    void observe_frontier(std::uint64_t h, const std::string& bid, const std::string& roothex, bool booked) {
        for (const auto& o : m_obs) if (o.bid == bid) return;   // once per block (re-entry across ticks)
        Obs o; o.h = h; o.bid = bid; o.root = lower_hex(roothex); o.booked = booked; o.t = now_unix();
        const bool attributed = attribute(o) != 'u';
        persist_obs(o);
        m_obs.push_back(std::move(o));
        while (m_obs.size() > obs_cap()) m_obs.pop_front();
        evaluate_vote(attributed);
    }
    std::size_t obs_cap() const { return 4 * std::max(m_o.vote_obs_window, m_o.vote_window) + 64; }

    // ── R-C rework-3 (D3): the observation window survives a restart ────────
    // rework-2 kept the window in memory only: a node rebooted into "CONVERGED
    // (0 observations)" while its peers -- and it -- were forked, and warmed up
    // from scratch. Now every observation is appended to <sidecar>.obs
    // ("1 h bid root|- booked t_unix") before it counts; the file is rewritten
    // (tmp+fsync+rename) once it holds more than 2x the in-memory cap; boot
    // reloads it (stale entries dropped by vote_stale_s) and re-evaluates the
    // vote, so the state -- and its suspension -- is restored, not re-warmed.
    std::string obs_path() const { return m_o.sidecar_path.empty() ? std::string() : m_o.sidecar_path + ".obs"; }
    static std::string obs_line(const Obs& o) {
        return "1 " + std::to_string(o.h) + " " + o.bid + " " + (o.root.empty() ? std::string("-") : o.root) + " " +
               (o.booked ? "1" : "0") + " " + std::to_string(o.t) + "\n";
    }
    void persist_obs(const Obs& o) {
        if (!m_o.persist_vote_obs || obs_path().empty()) return;
        if (m_obs_file_lines + 1 > 2 * obs_cap()) {   // compact: current window + this one
            std::string body;
            for (const auto& x : m_obs) body += obs_line(x);
            body += obs_line(o);
            if (atomic_write(obs_path(), body)) { m_obs_file_lines = m_obs.size() + 1; return; }
            ++m_stats.obs_persist_failures;
            return;
        }
        std::ofstream f(obs_path(), std::ios::app);
        if (!f) { ++m_stats.obs_persist_failures; return; }
        f << obs_line(o);
        f.flush();
        if (!f) { ++m_stats.obs_persist_failures; return; }
        ++m_obs_file_lines;
    }
    void load_obs() {
        if (!m_o.persist_vote_obs || obs_path().empty()) return;
        std::ifstream in(obs_path());
        if (!in) return;
        std::string line;
        std::size_t n = 0;
        while (std::getline(in, line)) {
            std::istringstream is(line);
            std::string ver, bid, root; unsigned long long h = 0, t = 0; int booked = 0;
            if (!(is >> ver >> h >> bid >> root >> booked >> t) || ver != "1") continue;
            ++n;
            bool dup = false; for (const auto& x : m_obs) if (x.bid == bid) { dup = true; break; }
            if (dup) continue;
            Obs o; o.h = h; o.bid = bid; o.root = root == "-" ? "" : root; o.booked = booked != 0; o.t = t;
            m_obs.push_back(std::move(o));
            while (m_obs.size() > obs_cap()) m_obs.pop_front();
        }
        m_obs_file_lines = n;
        m_stats.obs_restored = m_obs.size();
        if (m_obs.empty()) return;
        evaluate_vote();
        say("boot: lineage-vote window RESTORED from " + obs_path() + ": " + std::to_string(m_obs.size()) +
            " observation(s) -> vote " + vote_state_name(m_vote) + " (window " + std::to_string(m_stats.obs_refused) + "/" +
            std::to_string(m_stats.obs_n) + " refused) -- not re-warmed from zero");
    }
    void evaluate_vote(bool new_attributed_obs = false) {
        if (m_o.vote_stale_s) {
            const std::uint64_t now = now_unix();
            while (!m_obs.empty() && m_obs.front().t + m_o.vote_stale_s < now) m_obs.pop_front();
        }
        // (a) the observation window: refused fraction over the last W_obs frontier lane blocks.
        std::size_t n = 0, refused = 0, unattr = 0;
        for (auto it = m_obs.rbegin(); it != m_obs.rend() && n < m_o.vote_obs_window; ++it, ++n) {
            const char a = attribute(*it);
            if (a != 'm') ++refused;
            if (a == 'u') ++unattr;
        }
        m_stats.obs_n = n; m_stats.obs_refused = refused; m_stats.obs_unattributed = unattr;
        const bool contested = n >= m_o.vote_obs_min &&
                               static_cast<std::uint64_t>(refused) * m_o.vote_contest_den >=
                               static_cast<std::uint64_t>(n) * m_o.vote_contest_num;
        // (b) the vote: attributed blocks (mine / verified counter-lineage) above the fork height.
        std::size_t am = 0, ap = 0, na = 0;
        if (!m_counter_roots.empty()) {
            for (auto it = m_obs.rbegin(); it != m_obs.rend() && na < m_o.vote_window; ++it) {
                if (it->h <= m_counter_fork_h) continue;
                const char a = attribute(*it);
                if (a == 'u') continue;   // outsider tags / third lineages never vote
                ++na; if (a == 'm') ++am; else ++ap;
            }
        }
        m_stats.votes_me = am; m_stats.votes_counter = ap;
        const bool iso_now = !m_counter_roots.empty() && ap >= m_o.vote_k_min &&
                             static_cast<std::uint64_t>(ap) * m_o.vote_iso_den >= static_cast<std::uint64_t>(na) * m_o.vote_iso_num;
        const VoteState prev = m_vote;
        if (m_vote == VoteState::Isolated) {
            if (iso_now) m_iso_below = 0;
            else if (new_attributed_obs) ++m_iso_below;   // hysteresis: count NEW attributed blocks below iso
            if (!iso_now && m_iso_below >= m_o.vote_exit_hold) {
                m_vote = contested ? VoteState::Contested : VoteState::Converged;
                ++m_stats.isolated_exited;
            }
        } else if (iso_now) {
            m_vote = VoteState::Isolated; m_iso_below = 0;
            ++m_stats.isolated_entered; ++m_stats.divergence_alarms;
        } else {
            m_vote = contested ? VoteState::Contested : VoteState::Converged;
        }
        m_stats.vote_state = static_cast<std::uint64_t>(m_vote);
        m_stats.diverged = (m_vote == VoteState::Isolated) ? 1 : 0;
        if (m_vote == prev) return;
        const std::string tally = "window " + std::to_string(refused) + "/" + std::to_string(n) + " refused (" +
                                  std::to_string(unattr) + " unattributed), vote me=" + std::to_string(am) +
                                  " counter=" + std::to_string(ap) + " (k_min " + std::to_string(m_o.vote_k_min) + ", iso " +
                                  std::to_string(m_o.vote_iso_num) + "/" + std::to_string(m_o.vote_iso_den) + ")";
        // R-C rework-3: CONTESTED -> lane-suspend edge (opt-in; default off), fired
        // synchronously before this tick returns. Leaving CONTESTED (to CONVERGED,
        // or to ISOLATED -- whose own hook then holds the suspension) releases it.
        const bool was_c = (prev == VoteState::Contested), now_c = (m_vote == VoteState::Contested);
        if (m_o.contested_suspends && was_c != now_c) {
            if (now_c) ++m_stats.contested_suspend_edges; else ++m_stats.contested_resume_edges;
            if (m_contested_hook)
                m_contested_hook(now_c, now_c ? "CONTESTED (" + tally + ")"
                                              : std::string("left CONTESTED -> ") + vote_state_name(m_vote) + " (" + tally + ")");
        }
        if (m_vote == VoteState::Contested && prev == VoteState::Converged) {
            ++m_stats.contested_entered;
            say("cba-ALARM CONTESTED: " + tally + " -- " +
                (m_o.contested_suspends
                     ? std::string("lane template production SUSPENDED (cause=contested; operator opt-in --contested-suspend on) "
                                   "until the vote returns to CONVERGED; booking and refusing-not-crediting continue")
                     : std::string("contested-suspend off (default): this node KEEPS BUILDING; booking and "
                                   "refusing-not-crediting continue")) +
                ". Refused blocks without a VERIFIED counter-lineage are indistinguishable from outsider tags: never a "
                "halt. Operator: compare peers' owed_digest; W6 verified resync supplies the evidence.");
        } else if (m_vote == VoteState::Converged && prev == VoteState::Contested) {
            say("cba: lineage vote CONTESTED -> CONVERGED (" + tally + ")" +
                (m_o.contested_suspends ? std::string(" -- the contested lane suspension is released") : std::string()));
        } else if (m_vote == VoteState::Isolated) {
            const std::string banner = "cba-ALARM ISOLATED (lineage vote, NON-terminal): a VERIFIED counter-lineage holds " + tally +
                " of the attributed lane blocks since its fork height " + std::to_string(m_counter_fork_h) +
                " -- this node is the minority. Lane production SUSPENDED (no stale-root block, stratum job withdrawn, "
                "in-process miner stopped); booking continues so the vote stays live. Exit: W6 verified adoption + restart, "
                "or the counter-lineage loses the vote.";
            say(banner);
            if (m_o.out) { std::fprintf(stderr, "%s [stderr copy] %s\n", m_o.tag.c_str(), banner.c_str()); std::fflush(stderr); }
            if (m_iso_hook) m_iso_hook(true, banner);
        } else if (prev == VoteState::Isolated) {
            const std::string msg = std::string("cba: ISOLATED -> ") + vote_state_name(m_vote) + " (" + tally +
                                    "): the counter-lineage lost the vote; lane production may resume";
            say(msg);
            if (m_iso_hook) m_iso_hook(false, msg);
        } else {
            say(std::string("cba: lineage vote ") + vote_state_name(prev) + " -> " + vote_state_name(m_vote) + " (" + tally + ")");
        }
    }

    // R6 DIVERGENCE CAP -> R-C rework-2 HELD-LAG. A reorg of depth >= D_conf
    // (the documented finality boundary), or a peer lineage this node never
    // passed through while it is not yet decidable, leaves a canonical lane
    // block root-unknown / HELD that holds the cursor while the tip runs on.
    // Bound the SILENCE, not the block: after `cap_ticks` consecutive ticks with
    // the cursor more than `cap_heights` behind the buried frontier and a
    // root-unknown/HELD block pending, declare HELD-LAG -- one LOUD banner,
    // counted, main's lag-gate suspends the builder -- and keep holding (nothing
    // is dropped, nothing is credited around the held block). It CLEARS the
    // moment the held block resolves (books, or is refused (liability) once
    // decidable). Recovery for a real finality-boundary split: W6 verified resync.
    void divergence_check() {
        const std::uint64_t d = m_cfg.d_conf;
        const std::uint64_t hw = m_node.hw().hw_height;
        const std::uint64_t cursor = m_node.finalize_driver().cursor_height();
        const std::uint64_t frontier = hw >= d ? hw - d : 0;
        const std::uint64_t lag = frontier > cursor ? frontier - cursor : 0;
        const std::uint64_t cap_h = m_o.divergence_cap_heights ? m_o.divergence_cap_heights : 2 * d;
        if (lag > m_stats.divergence_lag_max) m_stats.divergence_lag_max = lag;
        const bool unknown_pending = !m_root_unknown_bids.empty() || !m_held.empty();
        if (unknown_pending && lag > cap_h) ++m_stats.divergence_ticks; else m_stats.divergence_ticks = 0;
        const bool over = m_stats.divergence_ticks >= m_o.divergence_cap_ticks;
        if (over && !m_held_lag) {
            m_held_lag = true; m_stats.held_lag = 1; ++m_stats.held_lag_entered; ++m_stats.divergence_alarms;
            std::string held;
            for (const auto& b : m_root_unknown_bids) held += " " + short_bid(b) + "@h" + std::to_string(m_retry.count(b) ? m_retry.at(b) : 0);
            for (const auto& [b, hh] : m_held) if (!m_root_unknown_bids.count(b)) held += " " + short_bid(b) + "@h" + std::to_string(hh);
            const std::string banner =
                "cba-ALARM HELD-LAG (non-terminal): finalize cursor " + std::to_string(cursor) + " is " + std::to_string(lag) +
                " heights behind the buried frontier " + std::to_string(frontier) + " (cap " + std::to_string(cap_h) +
                ") for " + std::to_string(m_stats.divergence_ticks) + " ticks with undecided lane block(s):" +
                (held.empty() ? std::string(" -") : held) +
                ". NOTHING is dropped or credited around them: the cursor stays held, the builder lag-gate suspends lane "
                "production, the alarm repeats. Cause class: this node's ledger history does not contain the winner's state "
                "(a reorg of depth >= D_conf -- the finality boundary -- or a lineage split). Recovery: W6 verified resync.";
            say(banner);
            if (m_o.out) { std::fprintf(stderr, "%s [stderr copy] %s\n", m_o.tag.c_str(), banner.c_str()); std::fflush(stderr); }
        } else if (!unknown_pending && m_held_lag) {
            m_held_lag = false; m_stats.held_lag = 0; ++m_stats.held_lag_cleared;
            say("cba: HELD-LAG CLEARED -- the held lane block(s) resolved; the cursor walks again");
        } else if (m_held_lag && m_tick % 50 == 0) {
            say("cba-ALARM HELD-LAG persists: cursor " + std::to_string(cursor) + " lag " + std::to_string(lag) +
                " held=" + std::to_string(m_held.size()) + " root_unknown=" + std::to_string(m_root_unknown_bids.size()));
        }
    }


    // ════════════════════════════════════════════════════════════════════════
    // D2 -- MINORITY CONVERGES TO MAJORITY (docs/xmr-lane/d2-minority-converge.md)
    // ════════════════════════════════════════════════════════════════════════
    static std::string liability_line(const LiabilityRec& r) {
        return "2 " + r.bid + " " + std::to_string(r.height) + " " + (r.root_hex.empty() ? std::string("-") : r.root_hex) + " " +
               std::to_string(r.total_pico) + " " + std::to_string(r.unattributed_pico) + " " + map_str(r.payout) + " " +
               (r.why.empty() ? std::string("-") : r.why) + "\n";
    }
    static std::string sanitize_why(const std::string& w0) {
        std::string w = w0.substr(0, 60);
        for (char& c : w) if (c == ' ' || c == '\t' || c == '\n') c = '_';
        return w.empty() ? std::string("-") : w;
    }
    static std::string utc_stamp() {
        const std::time_t t = std::time(nullptr);
        std::tm g{};
        ::gmtime_r(&t, &g);
        char b[32]; std::strftime(b, sizeof b, "%Y%m%dT%H%M%SZ", &g);
        return b;
    }
    bool d2_on() const { return m_o.minority_mode != FinalizeConnectOptions::MinorityMode::Off; }
    std::string mobs_path()   const { return m_o.sidecar_path.empty() ? std::string() : m_o.sidecar_path + ".mobs"; }
    std::string marker_path() const { return m_o.sidecar_path.empty() ? std::string() : m_o.sidecar_path + ".converge"; }

    bool is_own_block(const std::string& bid, const FinalizeConnectOptions::ChainBooking& bk) const {
        if (m_own_bids.count(bid) || m_isolated.count(bid)) return true;
        return bk.has_extra_nonce && m_own_keys.count(minority::builder_key(bk.extra_nonce)) != 0;
    }

    // One observation per decided canonical lane block (booked / refused), chain
    // order via the R6 booking order; persisted append-only in <sidecar>.mobs.
    void observe_d2(std::uint64_t h, const std::string& bid, const FinalizeConnectOptions::ChainBooking& bk, minority::Verdict v) {
        if (!d2_on()) return;
        for (const auto& o : m_mobs) if (o.bid == bid) return;   // once per block
        minority::Observation o;
        o.h = h; o.bid = bid; o.root = lower_hex(bk.onchain_root_hex); o.own = is_own_block(bid, bk);
        o.has_builder = bk.has_extra_nonce; o.builder = bk.has_extra_nonce ? minority::builder_key(bk.extra_nonce) : 0;
        o.verdict = v; o.has_matched_since = bk.has_matched_since; o.matched_since = bk.matched_since; o.t = now_unix();
        if (!mobs_path().empty()) { std::ofstream f(mobs_path(), std::ios::app); if (f) f << minority::obs_line(o); }
        m_mobs.push_back(o);
        if (m_mobs.size() > 512) m_mobs.erase(m_mobs.begin(), m_mobs.begin() + static_cast<std::ptrdiff_t>(m_mobs.size() - 512));
        m_stats.mobs_n = m_mobs.size();
        evaluate_minority(v == minority::Verdict::Unmatched && !o.own);
    }

    std::string run_text(const minority::RunStatus& st) const {
        std::string roots, hs;
        for (const auto& o : st.run) {
            roots += (roots.empty() ? "" : ",") + (o.root.empty() ? std::string("?") : o.root.substr(0, 12));
            hs += (hs.empty() ? "" : ",") + std::to_string(o.h) + (o.has_builder ? "/b" + std::to_string(o.builder) : std::string("/b?"));
        }
        return "run k=" + std::to_string(st.run.size()) + "/" + std::to_string(m_o.minority_run) + " builders=" +
               std::to_string(st.builders) + "/" + std::to_string(m_o.minority_builders) + " heights=[" + hs + "] roots=[" + roots + "]";
    }

    void evaluate_minority(bool new_unmatched_foreign) {
        if (!d2_on()) return;
        if (m_o.vote_stale_s) {
            const std::uint64_t now = now_unix();
            m_mobs.erase(std::remove_if(m_mobs.begin(), m_mobs.end(),
                                        [&](const minority::Observation& o) { return o.t + m_o.vote_stale_s < now; }), m_mobs.end());
        }
        m_last_run = minority::evaluate_run(m_mobs, m_o.minority_run, m_o.minority_builders, m_floor_h);
        m_stats.minority_run_len = m_last_run.run.size();
        m_stats.minority_run_builders = m_last_run.builders;
        m_stats.mobs_n = m_mobs.size();
        if (m_cstate == ConvergeState::Converged) {
            if (m_last_run.detected) enter_converging();
        } else if (m_cstate == ConvergeState::Diverged) {
            if (new_unmatched_foreign) m_converge_retry_now = true;
            if (m_last_run.trailing_clear)
                leave_to_converged(false, "cba: minority DIVERGED -> CLEARED: " + std::to_string(m_last_run.trailing_matched) +
                                          " matched foreign lane blocks from " + std::to_string(m_last_run.trailing_matched_builders) +
                                          " builders since the last unmatched one -- the majority is demonstrably on this node's "
                                          "lineage; nothing was mutated; lane production may resume");
        }
    }

    void enter_converging() {
        ++m_stats.minority_runs_detected;
        const std::string rt = run_text(m_last_run);
        if (m_o.minority_mode == FinalizeConnectOptions::MinorityMode::HaltOnly) {
            say("cba-ALARM MINORITY DETECTED: " + rt + " (--minority-converge halt-only: never adopts)");
            enter_diverged("--minority-converge halt-only: the minority is detected and the node halts; the re-derivation is never adopted (" + rt + ")");
            return;
        }
        m_cstate = ConvergeState::Converging; m_stats.minority_state = 1;
        m_converge_attempts_run = 0; m_hold = m_o.converge_hold_ticks;
        const std::string msg = "cba-ALARM MINORITY DETECTED: " + rt + " -- M consecutive foreign lane blocks from >= " +
            std::to_string(m_o.minority_builders) + " distinct builders commit roots this node's ledger history cannot reproduce: "
            "this node is the MINORITY. Lane production SUSPENDED (cause=converging); re-deriving the ledger with this node's own "
            "unverifiable blocks on the refuse/liability path (ruling D2 = A)";
        say(msg);
        if (m_o.out) { std::fprintf(stderr, "%s [stderr copy] %s\n", m_o.tag.c_str(), msg.c_str()); std::fflush(stderr); }
        if (m_converge_hook) m_converge_hook(true, msg);
    }

    void enter_diverged(const std::string& why) {
        const bool fresh = m_cstate != ConvergeState::Diverged;
        const bool was_serving = m_cstate == ConvergeState::Converged;   // CONVERGING already suspended the lane
        m_cstate = ConvergeState::Diverged; m_stats.minority_state = 2;
        m_last_diverged_why = why;
        if (!fresh) { say("cba-ALARM DIVERGED (halt) persists: " + why); return; }
        ++m_stats.diverged_halts;
        const std::string banner = "cba-ALARM DIVERGED (halt): " + why + " -- lane production HALTED, stratum WITHDRAWN, "
            "in-process miner stopped; booking/refusing continue; NOTHING guessed, NOTHING mutated. Exits: a later re-derivation "
            "that reproduces the majority, >= " + std::to_string(m_o.minority_run) + " matched foreign lane blocks from >= " +
            std::to_string(m_o.minority_builders) + " builders, or the operator (W6 verified adoption + restart).";
        say(banner);
        if (m_o.out) { std::fprintf(stderr, "%s [stderr copy] %s\n", m_o.tag.c_str(), banner.c_str()); std::fflush(stderr); }
        if (was_serving && m_converge_hook) m_converge_hook(true, banner);
    }

    void leave_to_converged(bool adopted, const std::string& msg) {
        const bool was_diverged = m_cstate == ConvergeState::Diverged;
        m_cstate = ConvergeState::Converged; m_stats.minority_state = 0;
        if (!adopted && was_diverged) ++m_stats.diverged_cleared;
        say(msg);
        if (m_converge_hook) m_converge_hook(false, msg);
    }

    void converge_tick() {
        if (!d2_on() || m_converge_crashed) return;
        if (m_cstate == ConvergeState::Converging) {
            if (m_hold) { --m_hold; return; }
            converge_attempt();
        } else if (m_cstate == ConvergeState::Diverged) {
            const std::uint64_t every = m_o.converge_retry_every ? m_o.converge_retry_every : 50;
            const bool slot = (m_tick % every) == 0;
            if (slot) {
                const std::string b = "cba-ALARM DIVERGED (halt) persists: " + m_last_diverged_why;
                say(b);
                if (m_o.out) { std::fprintf(stderr, "%s [stderr copy] %s\n", m_o.tag.c_str(), b.c_str()); std::fflush(stderr); }
            }
            if (m_o.minority_mode == FinalizeConnectOptions::MinorityMode::On && (m_converge_retry_now || slot)) {
                m_converge_retry_now = false;
                converge_attempt();
            }
        }
    }

    minority::DecodeResult scratch_decode(std::uint64_t h, const std::string& bid, const std::vector<::v37::bytes32>& cands,
                                          const std::vector<std::uint64_t>& sup, bool root_only) {
        minority::DecodeResult r;
        FinalizeConnectOptions::ChainBooking bk;
        FinalizeConnectOptions::ScratchQuery q; q.cands = &cands; q.superseded = &sup; q.root_only = root_only;
        const bool ok = m_o.book_scratch(h, bid, q, bk);
        r.credit = bk.credit; r.payout = bk.payout; r.why = bk.why; r.payout_decoded = bk.payout_decoded;
        r.unattributed_pico = bk.unattributed_pico; r.total_pico = bk.total_pico; r.root_hex = lower_hex(bk.onchain_root_hex);
        if (ok) r.outcome = minority::DecodeOutcome::Booked;
        else if (bk.why.rfind("not-lane:", 0) == 0) r.outcome = minority::DecodeOutcome::NotLane;
        else if (bk.why.rfind("cut-pending:", 0) == 0 || bk.why.rfind("get_block", 0) == 0 ||
                 bk.why.find("does not parse") != std::string::npos) r.outcome = minority::DecodeOutcome::Undecidable;
        else r.outcome = minority::DecodeOutcome::Refused;
        return r;
    }

    // One re-derivation attempt (CONVERGING every tick; DIVERGED on a new
    // unmatched foreign block and every converge_retry_every ticks).
    void converge_attempt() {
        ++m_stats.converge_attempts; ++m_converge_attempts_run;
        const minority::RunStatus st = minority::evaluate_run(m_mobs, m_o.minority_run, m_o.minority_builders, m_floor_h);
        if (!st.detected) {
            if (m_cstate == ConvergeState::Converging)
                leave_to_converged(false, "cba: minority run no longer stands (a matched foreign block arrived) -> CONVERGED "
                                          "without adoption; lane production may resume");
            return;
        }
        const std::uint64_t D = m_cfg.d_conf ? m_cfg.d_conf : 1;
        const std::uint64_t c = m_node.finalize_driver().cursor_height();
        std::uint64_t F = c >= 4 * D ? c - 4 * D : 0;
        std::string f_src = "no matched foreign block before the run: cursor - 4*D_conf";
        if (st.last_matched_before && st.last_matched_before->has_matched_since) {
            F = st.last_matched_before->matched_since;
            f_src = "the since-height of the state the last matched foreign block (h=" + std::to_string(st.last_matched_before->h) +
                    ") committed";
        }
        if (F > c) F = c;
        const std::uint64_t bcut0 = recon::builder_cut(st.run.front().h, D);
        const std::uint64_t depth = bcut0 > F ? bcut0 - F : 0;
        const std::uint64_t maxd = m_o.converge_max_depth ? m_o.converge_max_depth : 4 * D;
        if (depth > maxd) {
            ++m_stats.converge_failed;
            enter_diverged("the fork point F=" + std::to_string(F) + " lies " + std::to_string(depth) + " heights below the run's first "
                           "builder cut " + std::to_string(bcut0) + " (bound " + std::to_string(maxd) + " = the RECON root-age bound): "
                           "not re-derived (W6 verified resync territory)");
            return;
        }
        if (!m_o.book_scratch) { ++m_stats.converge_failed; enter_diverged("no re-derivation decoder is installed (book_scratch)"); return; }
        minority::RefoldInput in;
        in.chain = m_cfg.lane_chain; in.d_conf = D; in.fork_h = F; in.cursor = c;
        try {
            m_node.store().for_each_prefix(store_codec::k_evt_prefix(m_cfg.lane_chain), [&](const std::string&, const std::string& v) {
                in.events.push_back(SettleEvent::deserialize(v)); return true; });
        } catch (const std::exception& e) {
            ++m_stats.converge_failed; enter_diverged(std::string("the event log does not read back: ") + e.what()); return;
        }
        const std::uint64_t top = c + 1 + D, tip = m_node.best_height();
        for (std::uint64_t h = F + 1; h <= top && h <= tip; ++h) {
            const auto b = m_node.chain_bid_at(h);
            if (!b) { converge_undecidable("the chain row at h=" + std::to_string(h) + " is not available yet"); return; }
            in.chain_blocks[h] = *b;
        }
        std::set<std::string> r1, r2;
        for (const auto& [b, hh] : m_isolated) if (hh > F) r1.insert(b);
        for (const auto& o : m_mobs) if (o.own && o.h > F) r2.insert(o.bid);
        for (const auto& [h, b] : in.chain_blocks) if (m_own_bids.count(b)) r2.insert(b);
        for (const auto& b : r1) r2.insert(b);
        std::vector<std::pair<std::string, std::set<std::string>>> tries;
        if (!r1.empty()) tries.emplace_back("R1 (isolation-marked own blocks)", r1);
        if (!r2.empty() && r2 != r1) tries.emplace_back("R2 (every own block since F)", r2);
        if (tries.empty()) tries.emplace_back("R0 (no own block since F)", std::set<std::string>{});
        // Then every other subset of the own blocks since F (bounded: <= 6 own
        // blocks, smallest first). Not a guess: the CHECK below is exact -- a
        // candidate is adopted only if its re-derived history reproduces every one
        // of the majority's M on-chain commitments (sha256d digests), which only
        // the majority's actual refuse set can do.
        if (r2.size() <= 6) {
            const std::vector<std::string> own(r2.begin(), r2.end());
            std::vector<std::set<std::string>> subs;
            for (std::uint32_t m = 1; m + 1 < (1u << own.size()); ++m) {
                std::set<std::string> sub;
                for (std::size_t i = 0; i < own.size(); ++i) if (m & (1u << i)) sub.insert(own[i]);
                if (sub != r1) subs.push_back(std::move(sub));
            }
            std::stable_sort(subs.begin(), subs.end(), [](const auto& a, const auto& b) { return a.size() < b.size(); });
            if (!r2.empty()) tries.emplace_back("R0 (no own block forced)", std::set<std::string>{});
            for (auto& sub : subs) tries.emplace_back("Rs (own subset)", std::move(sub));
        }
        auto decode = [this](std::uint64_t h, const std::string& bid, const std::vector<::v37::bytes32>& cands,
                             const std::vector<std::uint64_t>& sup, bool root_only) {
            return scratch_decode(h, bid, cands, sup, root_only);
        };
        std::string tried;
        std::size_t idx = 0;
        for (const auto& [name, R] : tries) {
            in.refuse = R;
            minority::RefoldResult res = minority::refold(in, decode);
            if (res.undecidable) { converge_undecidable(res.why); return; }
            const std::size_t k = minority::reproduced(res, st.run);
            if (idx++ < 3) tried += " " + name + " reproduced " + std::to_string(k) + "/" + std::to_string(st.run.size()) + ";";
            if (idx > 3 && k != st.run.size()) continue;   // the subset search logs only its hit
            say("minority: re-derivation with " + name + " {" + [&] { std::string x; for (const auto& b : R) x += " " + short_bid(b); return x; }() +
                " } F=" + std::to_string(F) + " (" + f_src + ") cursor=" + std::to_string(c) + ": reproduces " + std::to_string(k) + "/" +
                std::to_string(st.run.size()) + " of the run's commitments (" + std::to_string(res.finalized) + " FINALIZE re-derived, " +
                std::to_string(res.booked.size()) + " booked, " + std::to_string(res.refused.size()) + " refused, " +
                std::to_string(res.reused_maps) + " booked maps reused, digest " + hex_of(res.digest).substr(0, 12) + ")");
            if (res.ok && k == st.run.size()) { adopt(res, in, name, st); return; }
        }
        ++m_stats.converge_failed;
        if (tries.size() > 3) tried += " +" + std::to_string(tries.size() - 3) + " own-block subset(s) reproduced fewer;";
        enter_diverged(std::to_string(st.run.size()) + " unmatched from " + std::to_string(st.builders) + " builders; re-derivation with" +
                       tried + " -- this ledger can NOT be brought onto the majority lineage by refusing its own blocks");
    }

    void converge_undecidable(const std::string& why) {
        ++m_stats.converge_undecidable;
        if (m_converge_attempts_run == 1 || m_converge_attempts_run % 50 == 0)
            say("minority: re-derivation UNDECIDABLE (" + why + ") -- attempt #" + std::to_string(m_converge_attempts_run) +
                ", retried (bound " + std::to_string(m_o.converge_retry_bound) + "); nothing adopted, nothing guessed");
        if (m_cstate == ConvergeState::Converging && m_o.converge_retry_bound && m_converge_attempts_run >= m_o.converge_retry_bound)
            enter_diverged("the re-derivation stayed UNDECIDABLE for " + std::to_string(m_converge_attempts_run) + " attempts: " + why);
    }

    void reset_liability_state() {
        m_liability.clear(); m_liability_by_payee.clear();
        m_stats.liability_blocks = m_stats.liability_pico = m_stats.liability_attributed_pico = 0;
        m_stats.liability_unattributed_pico = m_stats.liability_payees = 0;
    }
    void clean_booking_state(const std::string& bid) {
        m_retry.erase(bid); m_retry_n.erase(bid); m_deferred.erase(bid); m_root_unknown_bids.erase(bid); m_first_cursor.erase(bid);
        if (m_held.erase(bid)) { ++m_stats.held_resolved; m_stats.held_now = m_held.size(); }
    }
    void archive_for_converge(const std::string& utc) {
        std::vector<std::string> files = { m_node.store_dir() + "/settle.img" };
        if (!m_o.sidecar_path.empty())
            for (const char* sfx : {"", ".liability", ".obs", ".mobs", ".isolated"}) files.push_back(m_o.sidecar_path + sfx);
        for (const auto& f : files) {
            std::error_code ec;
            if (!std::filesystem::exists(f, ec)) continue;
            std::filesystem::copy_file(f, f + ".pre-converge-" + utc, std::filesystem::copy_options::skip_existing, ec);
        }
    }

    // THE ADOPTION (docs §3.4). Every step is ordered for restart safety: the
    // new sidecar + liability bodies and the marker ('proposed') are durable
    // BEFORE the store is touched; the store rewrite is ONE atomic image
    // replace (old or new, never torn); 'applied' is written after it; a boot
    // that finds 'proposed' + the OLD store drops the marker (nothing mutated),
    // 'applied' (or 'proposed' + the NEW store) finishes the in-memory steps.
    void adopt(const minority::RefoldResult& res, const minority::RefoldInput& in, const std::string& cand,
               const minority::RunStatus& st) {
        const std::string utc = utc_stamp();
        std::map<std::string, PendingRec> newp;
        for (const auto& p : res.pending) {
            PendingRec r; r.height = p.h; r.kind = 'c'; r.credit = p.credit; r.payout = p.payout; r.found_unix_s = now_unix();
            for (const auto& [k, v] : p.payout) { (void)k; if (v > 0) r.reward += static_cast<std::uint64_t>(v); }
            newp[p.bid] = r;
        }
        std::string pbody;
        for (const auto& [b, r] : newp) pbody += sidecar_line(b, r);
        for (const auto& [b, r] : m_unrecoverable) pbody += sidecar_line(b, r);
        std::vector<LiabilityRec> newl;
        std::vector<std::string> released, refused_all, forced;
        for (const auto& x : m_liability) { if (res.booked.count(x.bid)) released.push_back(x.bid); else newl.push_back(x); }
        for (const auto& rb : res.refused) {
            refused_all.push_back(rb.bid);
            if (rb.forced) forced.push_back(rb.bid);
            bool have = false; for (const auto& x : newl) if (x.bid == rb.bid) { have = true; break; }
            if (have) continue;
            LiabilityRec L; L.height = rb.h; L.bid = rb.bid;
            if (rb.forced || (rb.had_old && !rb.r.payout_decoded && rb.r.unattributed_pico == 0 && rb.r.total_pico == 0)) {
                for (const auto& [k, v] : rb.old_payout) if (v > 0) L.payout[k] = v;
                L.why = sanitize_why(rb.forced ? "converge:own-block-refused(majority-cannot-reproduce)" : "converge:refused");
            } else {
                L.root_hex = rb.r.root_hex; L.total_pico = rb.r.total_pico;
                if (rb.r.payout_decoded) { for (const auto& [k, v] : rb.r.payout) if (v > 0) L.payout[k] = v; L.unattributed_pico = rb.r.unattributed_pico; }
                else L.unattributed_pico = rb.r.unattributed_pico ? rb.r.unattributed_pico : rb.r.total_pico;
                L.why = sanitize_why(rb.r.why);
            }
            if (L.payout.empty() && L.unattributed_pico == 0) continue;
            newl.push_back(L);
        }
        std::string lbody; for (const auto& x : newl) lbody += liability_line(x);
        std::uint64_t floor_h = m_floor_h;
        for (const auto& o : m_mobs) floor_h = std::max(floor_h, o.h);
        minority::Marker mk;
        mk.phase = "proposed"; mk.fork_h = in.fork_h; mk.cursor = in.cursor; mk.new_seq = res.ledger_seq;
        mk.new_events = res.events.size(); mk.old_events = in.events.size(); mk.floor_h = floor_h;
        mk.new_digest_hex = hex_of(res.digest); mk.utc = utc; mk.candidate = cand.substr(0, 2);
        mk.forced = forced; mk.refused = refused_all; mk.released = released;
        const std::string sc = m_o.sidecar_path;
        if (!sc.empty() && (!atomic_write(sc + ".converge.pfound", pbody) || !atomic_write(sc + ".converge.liab", lbody) ||
                            !atomic_write(marker_path(), minority::marker_str(mk)))) {
            ++m_stats.converge_failed;
            enter_diverged("the adoption files could not be written (" + std::string(std::strerror(errno)) + "); nothing was mutated");
            return;
        }
        say("converge: " + cand + " reproduces " + std::to_string(st.run.size()) + "/" + std::to_string(st.run.size()) +
            " of the majority's commitments -> ADOPTING (F=" + std::to_string(in.fork_h) + ", cursor=" + std::to_string(in.cursor) +
            ", new digest " + hex_of(res.digest).substr(0, 12) + ", marker 'proposed')");
        if (m_o.converge_crash_after == 1) { m_converge_crashed = true; say("TEST failpoint: stopped after phase 'proposed'"); return; }
        archive_for_converge(utc);
        {
            std::vector<std::string> keys;
            m_node.store().for_each_prefix(store_codec::k_evt_prefix(m_cfg.lane_chain),
                                           [&](const std::string& k, const std::string&) { keys.push_back(k); return true; });
            auto b = m_node.store().batch();
            for (const auto& k : keys) b->remove(k);
            std::uint64_t seq = 0;
            for (const auto& e : res.events) b->put(store_codec::k_evt(m_cfg.lane_chain, ++seq), e.serialize());
            if (!b->commit_sync()) {
                ++m_stats.converge_failed;
                enter_diverged("the store rewrite FAILED (atomic image replace): the old store stands; marker left 'proposed' (a boot drops it)");
                return;
            }
        }
        say("converge: store rewritten (" + std::to_string(in.events.size()) + " events -> " + std::to_string(res.events.size()) +
            "), archived *.pre-converge-" + utc);
        mk.phase = "applied";
        if (!sc.empty()) (void)atomic_write(marker_path(), minority::marker_str(mk));
        if (m_o.converge_crash_after == 2) { m_converge_crashed = true; say("TEST failpoint: stopped after phase 'applied'"); return; }
        std::set<std::string> own_now(m_own_bids.begin(), m_own_bids.end());
        for (const auto& [b, hh] : m_isolated) { (void)hh; own_now.insert(b); }
        for (const auto& o : m_mobs) if (o.own) own_now.insert(o.bid);
        for (const auto& b : forced) own_now.insert(b);
        if (!finish_applied(mk, /*live=*/true)) return;
        for (const auto& rb : res.refused) {
            const bool own = own_now.count(rb.bid) != 0;
            if (!own && !rb.had_old) continue;
            std::string pm; for (const auto& [k, v] : (rb.forced || !rb.r.payout_decoded ? rb.old_payout : rb.r.payout)) pm += " " + hex_of(k).substr(0, 8) + "=" + std::to_string(v);
            if (own) ++m_stats.own_refused_on_converge;
            say("converge: " + std::string(own ? "own" : "previously credited") + " block " + short_bid(rb.bid) + " h=" + std::to_string(rb.h) +
                " moved to refuse/LIABILITY (payout {" + pm + " }" + (rb.forced ? ", " + cand.substr(0, 2) : std::string(", ") + rb.r.why.substr(0, 60)) +
                "); the receipts its miners minted while this node was isolated receive NO lane credit through it -- they did not reach the "
                "majority through the relay within the booking window (they are credited only if a later majority cut carries them)");
        }
        for (const auto& b : released) {
            ++m_stats.liability_released;
            say("converge: majority block " + short_bid(b) + " h=" + std::to_string(res.booked.count(b) ? res.booked.at(b) : 0) +
                " now CREDITED (liability released)");
        }
        ++m_stats.converged;
        leave_to_converged(true, "converge: DONE ring=" + std::to_string(m_node.boot_digest_history().size()) + " cursor=" +
                                 std::to_string(m_node.finalize_driver().cursor_height()) + " digest=" +
                                 hex_of(m_node.ledger().owed_digest()).substr(0, 16) + " ledger_seq=" +
                                 std::to_string(m_node.ledger().ledger_seq()) + "; lane production resumes");
    }

    // The in-memory half of an adoption (live, right after the store rewrite) or
    // of a boot that found an 'applied' marker (the boot replay already used the
    // rewritten store; the sidecar/liability were renamed in converge_boot_pre).
    bool finish_applied(minority::Marker mk, bool live) {
        const std::string sc = m_o.sidecar_path;
        if (!sc.empty()) {
            std::error_code ec;
            if (std::filesystem::exists(sc + ".converge.pfound", ec)) std::filesystem::rename(sc + ".converge.pfound", sc, ec);
            if (std::filesystem::exists(sc + ".converge.liab", ec)) std::filesystem::rename(sc + ".converge.liab", sc + ".liability", ec);
        }
        if (live) {
            std::string why;
            if (!m_node.relineage(&why)) {
                ++m_stats.converge_failed;
                enter_diverged("the in-process relineage FAILED (" + why + "); the store IS rewritten (marker 'applied'): restart the node to finish");
                return false;
            }
            m_pending.clear();
            reset_liability_state();
            if (!sc.empty()) { (void)reseed_sidecar(); load_liability(); }
        }
        const std::set<std::string> refused(mk.refused.begin(), mk.refused.end()), released(mk.released.begin(), mk.released.end());
        for (const auto& b : refused)  { m_chain_seen[b] = true; clean_booking_state(b); m_pending.erase(b); }
        for (const auto& b : released) { m_chain_seen.erase(b); clean_booking_state(b); }
        for (const auto& [b, r] : m_pending) { (void)r; m_chain_seen.erase(b); clean_booking_state(b); }
        // the lineage vote window follows the adopted lineage
        bool obs_changed = false;
        for (auto& o : m_obs) {
            const bool now_booked = !refused.count(o.bid) && (released.count(o.bid) || m_pending.count(o.bid) || m_node.ledger().is_settled(o.bid));
            if (o.booked != now_booked) { o.booked = now_booked; obs_changed = true; }
        }
        if (obs_changed && m_o.persist_vote_obs && !obs_path().empty()) {
            std::string body; for (const auto& x : m_obs) body += obs_line(x);
            if (atomic_write(obs_path(), body)) m_obs_file_lines = m_obs.size();
        }
        if (obs_changed) evaluate_vote();
        // the D2 observations up to the adoption are consumed
        m_floor_h = std::max(m_floor_h, mk.floor_h);
        m_mobs.clear(); m_last_run = minority::RunStatus{};
        m_stats.mobs_n = 0; m_stats.minority_run_len = 0; m_stats.minority_run_builders = 0;
        if (!mobs_path().empty()) (void)atomic_write(mobs_path(), "");
        ++m_relineage_seq;
        if (m_relineage_hook) m_relineage_hook();
        const bool digest_ok = mk.new_digest_hex.empty() || hex_of(m_node.ledger().owed_digest()) == mk.new_digest_hex;
        if (!digest_ok) {
            ++m_stats.converge_check_mismatch;
            say("cba-ALARM converge: the replayed ledger digest " + hex_of(m_node.ledger().owed_digest()).substr(0, 16) +
                " != the re-derived " + mk.new_digest_hex.substr(0, 16) + " -- must never happen; operator's eyes needed");
        }
        mk.phase = "done";
        if (!sc.empty()) (void)atomic_write(marker_path(), minority::marker_str(mk));
        echo_node_log();
        return true;
    }

    // Boot, BEFORE the sidecar is read: act on a marker left by an adoption.
    // Returns true when an 'applied' adoption must be finished after the
    // sidecar/liability/vote loads (converge_boot_post).
    bool converge_boot_pre() {
        m_boot_marker.reset();
        if (marker_path().empty()) return false;
        std::ifstream in(marker_path());
        if (!in) return false;
        const std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        minority::Marker mk;
        if (!minority::marker_parse(body, mk)) { say("boot: MALFORMED converge marker at " + marker_path() + " ignored"); return false; }
        if (mk.phase == "done") {
            m_floor_h = std::max(m_floor_h, mk.floor_h);
            say("boot: this node CONVERGED to the majority lineage at " + mk.utc + " (F=" + std::to_string(mk.fork_h) + ", " +
                std::to_string(mk.forced.size()) + " own block(s) forced to liability, " + std::to_string(mk.released.size()) +
                " majority block(s) released) -- informational");
            return false;
        }
        const bool store_is_new = hex_of(m_node.ledger().owed_digest()) == mk.new_digest_hex &&
                                  m_node.recovered().max_event_seq == mk.new_events;
        if (mk.phase == "proposed" && !store_is_new) {
            ++m_stats.converge_boot_dropped;
            std::error_code ec;
            const std::string sc = m_o.sidecar_path;
            std::filesystem::rename(marker_path(), marker_path() + ".dropped-" + utc_stamp(), ec);
            std::filesystem::remove(sc + ".converge.pfound", ec);
            std::filesystem::remove(sc + ".converge.liab", ec);
            say("boot: converge marker 'proposed' found with the OLD store (nothing was mutated) -> dropped; live detection runs again");
            return false;
        }
        m_floor_h = std::max(m_floor_h, mk.floor_h);
        mk.phase = "applied";
        const std::string sc = m_o.sidecar_path;
        std::error_code ec;
        if (std::filesystem::exists(sc + ".converge.pfound", ec)) std::filesystem::rename(sc + ".converge.pfound", sc, ec);
        if (std::filesystem::exists(sc + ".converge.liab", ec)) std::filesystem::rename(sc + ".converge.liab", sc + ".liability", ec);
        m_boot_marker = mk;
        say("boot: converge marker 'applied' (the store is the re-derived lineage: digest " + mk.new_digest_hex.substr(0, 16) +
            ", " + std::to_string(mk.new_events) + " events) -> finishing the adoption");
        return true;
    }
    void converge_boot_post() {
        if (!m_boot_marker) return;
        ++m_stats.converge_boot_finished;
        (void)finish_applied(*m_boot_marker, /*live=*/false);
        m_boot_marker.reset();
    }
    void load_isolated() {
        if (m_o.sidecar_path.empty()) return;
        std::ifstream in(m_o.sidecar_path + ".isolated");
        std::string line;
        while (std::getline(in, line)) {
            std::istringstream is(line); std::string ver, bid; unsigned long long h = 0;
            if (!(is >> ver >> bid >> h) || ver != "1" || bid.size() != 64) continue;
            m_isolated[lower_hex(bid)] = h; m_own_bids.insert(lower_hex(bid));
        }
    }
    void load_mobs() {
        if (!d2_on() || mobs_path().empty()) return;
        std::ifstream in(mobs_path());
        std::string line;
        std::size_t n = 0;
        while (std::getline(in, line)) {
            minority::Observation o;
            if (!minority::obs_parse(line, o)) continue;
            bool dup = false; for (const auto& x : m_mobs) if (x.bid == o.bid) { dup = true; break; }
            if (dup) continue;
            if (o.own) m_own_bids.insert(o.bid);
            m_mobs.push_back(o); ++n;
        }
        if (m_mobs.size() > 512) m_mobs.erase(m_mobs.begin(), m_mobs.begin() + static_cast<std::ptrdiff_t>(m_mobs.size() - 512));
        m_stats.mobs_restored = n;
        if (n) {
            say("boot: minority observations RESTORED from " + mobs_path() + ": " + std::to_string(n));
            evaluate_minority(false);
        }
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
                // R-C rework-2: a DEBIT-ONLY record is not a credit -- the race
                // gate's credit authorisation (R-7) does not apply to it.
                if (rec.kind != 'd') race_confirm_credit(bid, rec.height);
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
    //    v1 (read only):  1 <bid64> <height> <payee64|-> <reward> <prev64|-> <found_unix_s>
    //    v2 (R-C rework-2, written): the v1 fields, then
    //                     <kind a|c|d> <credit-map|-> <payout-map|->
    //    map = key64=amount[,key64=amount...] (signed decimal amounts)
    static std::string map_str(const Amounts& m) {
        if (m.empty()) return "-";
        std::string s;
        for (const auto& [k, v] : m) { if (!s.empty()) s += ","; s += hex_of(k) + "=" + std::to_string(v); }
        return s;
    }
    static bool map_parse(const std::string& s, Amounts& out) {
        out.clear();
        if (s == "-") return true;
        std::size_t p = 0;
        while (p < s.size()) {
            std::size_t c = s.find(',', p); if (c == std::string::npos) c = s.size();
            const std::string item = s.substr(p, c - p);
            const std::size_t eq = item.find('=');
            if (eq != 64) return false;
            ::v37::bytes32 k{};
            if (!hash_from_hex(lower_hex(item.substr(0, 64)), k)) return false;
            try { out[k] = std::stoll(item.substr(65)); } catch (...) { return false; }
            p = c + 1;
        }
        return true;
    }
    static std::string sidecar_line(const std::string& bid, const PendingRec& r) {
        std::string s = "2 " + bid + " " + std::to_string(r.height) + " " +
                        (r.payee ? hex_of(*r.payee) : std::string("-")) + " " +
                        std::to_string(r.reward) + " " +
                        (r.prev_id_hex.size() == 64 ? r.prev_id_hex : std::string("-")) + " " +
                        std::to_string(r.found_unix_s) + " " + std::string(1, r.kind) + " " +
                        map_str(r.credit) + " " + map_str(r.payout) + "\n";
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
        r.kind = 'a';
        if (ver == "2") {
            std::string kind, cm, pm;
            if (!(is >> kind >> cm >> pm)) return false;
            if (kind.size() != 1 || (kind[0] != 'a' && kind[0] != 'c' && kind[0] != 'd')) return false;
            r.kind = kind[0];
            if (!map_parse(cm, r.credit) || !map_parse(pm, r.payout)) return false;
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
    std::map<std::string, std::uint64_t> m_deferred;         //  R6: bid -> height, chain blocks above cursor+1+D_conf awaiting the cursor
    // R-C rework-2
    std::map<std::string, std::uint64_t> m_held;             //  bid -> height: transient failures past the retry bound (HELD, never dropped)
    std::vector<LiabilityRec>         m_liability;           //  rework-3 (b): refused blocks' on-chain value (node-local)
    std::map<::v37::bytes32, long long> m_liability_by_payee; //  rework-3 (b): attributed liability per payee
    std::size_t                       m_obs_file_lines = 0;  //  rework-3 (D3): lines in <sidecar>.obs
    std::deque<Obs>                   m_obs;                 //  lineage vote: frontier lane block observations (bounded)
    std::set<std::string>             m_counter_roots;       //  lineage vote: VERIFIED counter-lineage roots (hex)
    std::uint64_t                     m_counter_fork_h = 0;  //  lineage vote: fork height F
    VoteState                         m_vote = VoteState::Converged;
    std::size_t                       m_iso_below = 0;       //  ISOLATED exit hysteresis
    bool                              m_held_lag = false;    //  HELD-LAG (non-terminal)
    std::function<void(bool, const std::string&)> m_iso_hook;
    std::function<void(bool, const std::string&)> m_contested_hook;   // rework-3: CONTESTED -> lane suspend
    std::uint64_t                     m_tick = 0;
    std::uint64_t                     m_cba_chain_booked = 0;
    std::map<std::string, PendingRec> m_unrecoverable;  // kept in the sidecar so the boot warning repeats
    Stats         m_stats;
    std::size_t   m_log_cursor = 0;
    std::uint64_t m_last_hw_printed = ~std::uint64_t{0};

    // c2pool#1551: the race book and the last verdict reported per height (so a
    // quiet loop stays quiet and the journal records transitions, not ticks).
    SameHeightRaceLedger                    m_race;
    std::map<std::uint64_t, RaceVerdict>    m_last_verdict;

    // D2 (minority converges to majority)
    ConvergeState                           m_cstate = ConvergeState::Converged;
    std::vector<minority::Observation>      m_mobs;                 // decided lane-block observations (bounded)
    minority::RunStatus                     m_last_run;
    std::uint64_t                           m_floor_h = 0;          // observations at/below it were consumed by an adoption
    std::set<std::string>                   m_own_bids;             // mined by this node
    std::map<std::string, std::uint64_t>    m_isolated;             // own bid -> h, published with no relay peer
    std::set<std::uint32_t>                 m_own_keys;             // this node's builder keys
    std::function<bool(const std::string&)> m_isolated_probe;
    std::function<void(bool, const std::string&)> m_converge_hook;
    std::function<void()>                   m_relineage_hook;
    std::uint64_t                           m_relineage_seq = 0, m_converge_attempts_run = 0, m_hold = 0;
    bool                                    m_converge_retry_now = false, m_converge_crashed = false;
    std::string                             m_last_diverged_why;
    std::optional<minority::Marker>         m_boot_marker;
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
#include "xmr_recon_ring.hpp"                     // R-C rework-3 (D7): FC29

namespace c2pool::v37n::xmr::o2 {

inline void minority_fc_selfcheck(smoke::Report& rep, const std::filesystem::path& tmp_root);   // D2 phases (below)

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

    // ── phase 3: R6 TWO-SIDED chain-ordered booking (coinbase-authority path) ─
    // A lane block at 5 stays cut-pending (the receiver's feed is behind), so the
    // R4 gate holds the cursor at 1 while the chain runs on to 12. Pre-R6 the
    // node booked 6..12 as they arrived (ahead of the synced node's order);
    // with R6 they are DEFERRED and booked one by one as the cursor reaches
    // h - 1 - D_conf, interleaved with the finalize walk inside ONE tick.
    {
        XmrNodeConfig c3 = cfg;
        c3.settle_db_path = (tmp_root / "store-r6").string();
        std::filesystem::create_directories(c3.settle_db_path);
        FinalizeConnectOptions o3;
        o3.out = nullptr;
        o3.sidecar_path = (std::filesystem::path(c3.settle_db_path) / "pfound.tsv").string();
        MockMonerodTransport mock;
        XmrNode node(c3, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) {
            rep.add("FC17 bring_up (node R6)", false, e.what()); return rep;
        }
        const std::set<std::uint64_t> lane = {5, 8, 11, 14};
        std::map<std::uint64_t, std::uint64_t> booked_at;   // lane h -> finalize cursor at the successful booking
        std::vector<std::uint64_t> order;
        bool hold5 = true;
        XmrNode* np = &node;
        o3.book_from_chain = [&](std::uint64_t h, const std::string&, Amounts& credit, Amounts& payout, std::string& why) {
            if (!lane.count(h)) { why = "not-lane: test"; return false; }
            if (h == 5 && hold5) { why = "cut-pending: test feed behind"; return false; }
            credit.clear(); credit[payee] = static_cast<long long>(REWARD); payout = credit;
            booked_at[h] = np->finalize_driver().cursor_height(); order.push_back(h);
            return true;
        };
        FoundBlockQueue q3;
        FinalizeConnect fc(node, c3, q3, o3);
        chain(node, 1, 4);
        (void)fc.tick();
        rep.add("FC17a chain 1..4: cursor at 1 (= 4 - D_conf), nothing lane yet",
                node.finalize_driver().cursor_height() == 1 && order.empty(),
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        chain(node, 5, 12);                          // 5 = lane, held cut-pending; 6..12 arrive while the gate holds
        rep.add("FC17b lane block 5 cut-pending holds the R4 gate at cursor 1; 6..12 (> cursor+1+D_conf = 5) are DEFERRED, not booked",
                node.finalize_driver().cursor_height() == 1 && fc.stats().booking_deferred == 7 &&
                order.empty() && fc.stats().late_unbooked == 0,
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()) +
                " deferred=" + std::to_string(fc.stats().booking_deferred) + " booked=" + std::to_string(order.size()));
        hold5 = false;
        auto t = fc.tick();                          // ONE tick: 5 books, then the chain-ordered interleave runs to the frontier
        bool ordered = !booked_at.empty();
        for (const auto& [h, c] : booked_at) if (c + 1 + D_CONF != h) ordered = false;
        rep.add("FC17c one tick after the feed catches up: every lane booking landed with cursor == h - 1 - D_conf (5@1, 8@4, 11@7) -- the synced node's order",
                ordered && order == std::vector<std::uint64_t>{5, 8, 11},
                "order=" + std::to_string(order.size()) + " 5@" + std::to_string(booked_at.count(5) ? booked_at[5] : 99) +
                " 8@" + std::to_string(booked_at.count(8) ? booked_at[8] : 99) + " 11@" + std::to_string(booked_at.count(11) ? booked_at[11] : 99));
        rep.add("FC17d the cursor walked to the frontier (9 = 12 - D_conf) inside that tick: 5 and 8 SETTLED, 11 pending, deferred set drained, late_unbooked = 0",
                node.finalize_driver().cursor_height() == 9 && t.settled == 2 &&
                node.ledger().is_settled(hex_of(smoke::blk_id(5))) && node.ledger().is_settled(hex_of(smoke::blk_id(8))) &&
                node.ledger().is_pending(hex_of(smoke::blk_id(11))) && fc.stats().booked_after_deferral == 7 &&
                fc.stats().late_unbooked == 0 && fc.stats().late_booked_post_finalize == 0,
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()) + " settled=" + std::to_string(t.settled) +
                " attempted_after_deferral=" + std::to_string(fc.stats().booked_after_deferral));
        chain(node, 13, 14);                         // the synced shape: 13 and 14 arrive with the cursor one below -> booked at once
        (void)fc.tick();
        rep.add("FC17e a synced arrival (h == cursor + 1 + D_conf) is booked immediately, not deferred: 14@10",
                booked_at.count(14) && booked_at[14] == 10 && fc.stats().booking_deferred == 7 &&
                node.finalize_driver().cursor_height() == 11 && node.ledger().is_settled(hex_of(smoke::blk_id(11))),
                "14@" + std::to_string(booked_at.count(14) ? booked_at[14] : 99) + " deferred=" + std::to_string(fc.stats().booking_deferred));
        (void)fc.drain_before_stop();
    }

    // ── shared helpers for the R-C rework-2 phases ──────────────────────────
    auto roothex_of = [](std::uint64_t h) {   // a distinct 64-hex root per height
        static const char* hx = "0123456789abcdef";
        std::string s(64, '0');
        for (int i = 0; i < 16; ++i) { s[63 - i] = hx[(h >> (4 * i)) & 0xF]; }
        return s;
    };
    // A monerod header responder over a canonical chain id_of(h) (prev = id_of(h-1)).
    // mode: 0 = serve, 1 = transport-fail every header fetch.
    auto header_responder = [](std::function<c2pool::xmr::node::Hash(std::uint64_t)> id_of, const int* mode) {
        return [id_of, mode](const std::string& method, const std::string& body) {
            c2pool::xmr::node::RpcResponse r;
            if (method != "get_block_header_by_height" || (mode && *mode == 1)) { r.error = "mock: header fetch failed"; return r; }
            const std::size_t p = body.find("\"height\":");
            if (p == std::string::npos) { r.error = "mock: no height"; return r; }
            const std::uint64_t h = std::stoull(body.substr(p + 9));
            const std::string js = std::string("{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"result\":{\"status\":\"OK\",\"block_header\":{\"height\":") +
                std::to_string(h) + ",\"hash\":\"" + hex_of(id_of(h)) + "\",\"prev_hash\":\"" + hex_of(id_of(h ? h - 1 : 0)) +
                "\",\"timestamp\":0,\"reward\":0}}}";
            r.body.assign(js.begin(), js.end());
            return r;
        };
    };
    auto store_of = [&](const char* name) {
        XmrNodeConfig c = cfg;
        c.settle_db_path = (tmp_root / name).string();
        std::filesystem::create_directories(c.settle_db_path);
        return c;
    };
    auto opts_for = [](const XmrNodeConfig& c) {
        FinalizeConnectOptions o; o.out = nullptr;
        o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
        return o;
    };
    using CB = FinalizeConnectOptions::ChainBooking;
    const ::v37::bytes32 kA = smoke::key_of(0xA1), kB = smoke::key_of(0xB2), kC = smoke::key_of(0xC4);

    // ── phase 4: HELD + HELD-LAG (R-C rework-2: the HOLD cap never drops) ───
    // A lane block whose 03 root stays UNKNOWN while the node is not decidable
    // holds the gate. Past the retry bound it is HELD (never booking_stall_
    // timeout -> REFUSED -> credit dropped, the pre-rework defect); after the
    // persistence window the lane is HELD-LAG (loud, NON-terminal). Once main can
    // decide (lane-root-refused) it is refused-not-credited and the cursor walks.
    {
        XmrNodeConfig c4 = store_of("store-held");
        FinalizeConnectOptions o4 = opts_for(c4);
        o4.divergence_cap_ticks = 20;                // cap_heights default = 2 * D_conf = 6
        o4.retry_bound = 30; o4.held_retry_every = 5;
        MockMonerodTransport mock;
        XmrNode node(c4, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) {
            rep.add("FC18 bring_up (node HELD)", false, e.what()); return rep;
        }
        bool decidable5 = false;
        o4.book_from_chain = [&](std::uint64_t h, const std::string&, Amounts&, Amounts&, std::string& why) {
            if (h == 5) why = decidable5 ? "lane-root-refused:" + roothex_of(5) + ": now decidable (test)"
                                         : "lane-root-unknown: 03 root matches none (test)";
            else why = "not-lane: test";
            return false;
        };
        FoundBlockQueue q4;
        FinalizeConnect fc(node, c4, q4, o4);
        chain(node, 1, 4); (void)fc.tick();
        chain(node, 5, 20);                          // 5 root-unknown holds the gate at cursor 1; frontier 17 -> lag 16 > cap 6
        for (int i = 0; i < 19; ++i) (void)fc.tick();
        rep.add("FC18a bounded window: 19 ticks over the cap -> no HELD-LAG yet (cursor held at 1, root-unknown retried, lag 16 > cap 6)",
                fc.stats().held_lag == 0 && node.finalize_driver().cursor_height() == 1 &&
                fc.stats().lane_root_unknown_retries >= 19 && fc.stats().divergence_ticks == 19 && fc.stats().divergence_lag_max == 16,
                "ticks=" + std::to_string(fc.stats().divergence_ticks) + " lag_max=" + std::to_string(fc.stats().divergence_lag_max));
        (void)fc.tick();
        rep.add("FC18b the 20th tick declares HELD-LAG: loud, counted, NON-terminal (not diverged/isolated), cursor held at 1",
                fc.stats().held_lag == 1 && fc.stats().held_lag_entered == 1 && !fc.diverged() && fc.stats().diverged == 0 &&
                node.finalize_driver().cursor_height() == 1);
        for (int i = 0; i < 40; ++i) (void)fc.tick();
        chain(node, 21, 24);
        for (int i = 0; i < 5; ++i) (void)fc.tick();
        rep.add("FC18c past the retry bound the block is HELD, NEVER dropped: held_now=1, booking_stall_timeout=0, terminal=0, still holding the gate, no chain block dropped",
                fc.stats().held_entered == 1 && fc.stats().held_now == 1 && fc.held().count(hex_of(smoke::blk_id(5))) &&
                fc.stats().booking_stall_timeout == 0 && fc.stats().lane_root_unknown_terminal == 0 &&
                fc.stats().refused == 0 && fc.stats().divergence_dropped == 0 && node.finalize_driver().cursor_height() == 1 &&
                fc.deferred_now() > 0,
                "held_now=" + std::to_string(fc.stats().held_now) + " stall=" + std::to_string(fc.stats().booking_stall_timeout) +
                " cursor=" + std::to_string(node.finalize_driver().cursor_height()) + " deferred=" + std::to_string(fc.deferred_now()));
        decidable5 = true;
        for (int i = 0; i < 6; ++i) (void)fc.tick();
        rep.add("FC18d once decidable the HELD block is REFUSED-not-credited (not dropped silently): held resolved, gate released, cursor walks to the frontier (21), HELD-LAG cleared",
                fc.stats().held_resolved == 1 && fc.stats().held_now == 0 && fc.stats().refused_not_credited == 1 &&
                node.finalize_driver().cursor_height() == 21 && fc.stats().held_lag == 0 && fc.stats().held_lag_cleared == 1,
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()) + " resolved=" + std::to_string(fc.stats().held_resolved));
        (void)fc.drain_before_stop();
    }

    // ── phase 5: the LINEAGE VOTE (replaces the M=3 / 2-distinct run) ───────
    // 5A: every frontier block refused with a fresh root (outsider tags / a
    // forker the node cannot verify): CONTESTED, loud -- NEVER a halt.
    {
        XmrNodeConfig c5 = store_of("store-vote-tags");
        FinalizeConnectOptions o5 = opts_for(c5);
        MockMonerodTransport mock;
        XmrNode node(c5, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC19 bring_up (node VOTE-A)", false, e.what()); return rep; }
        o5.book_from_chain = [&](std::uint64_t h, const std::string&, Amounts&, Amounts&, std::string& why) {
            if (h >= 5) { why = "lane-root-refused:" + roothex_of(h) + ": synced-but-unmatched (test)"; return false; }
            why = "not-lane: test"; return false;
        };
        FoundBlockQueue q5; FinalizeConnect fc(node, c5, q5, o5);
        chain(node, 1, 4); (void)fc.tick();
        chain(node, 5, 20);
        for (int i = 0; i < 25; ++i) (void)fc.tick();
        rep.add("FC19a every block refused with a distinct root (the shape that tripped the old M=3 halt on every honest node): CONTESTED, NOT diverged/isolated, all 16 refused-not-credited, vote never ran (no verified counter-lineage)",
                fc.vote_state() == FinalizeConnect::VoteState::Contested && !fc.diverged() && fc.stats().diverged == 0 &&
                fc.stats().isolated_entered == 0 && fc.stats().contested_entered == 1 && fc.stats().refused_not_credited == 16 &&
                fc.stats().obs_unattributed == 16,
                "state=" + std::string(FinalizeConnect::vote_state_name(fc.vote_state())) + " refused=" + std::to_string(fc.stats().refused_not_credited));
        rep.add("FC19b the refuse path RELEASED the finalize gate (the cursor walked to the frontier 17)",
                node.finalize_driver().cursor_height() == 17,
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        (void)fc.drain_before_stop();
    }
    // 5B: a lone forker holding ~25% of the lane blocks (fresh root at every one
    // of its blocks -- the shape that DID satisfy "3 consecutive, 2 distinct"):
    // the honest node stays CONVERGED, never contested, never halts.
    {
        XmrNodeConfig c6 = store_of("store-vote-forker");
        FinalizeConnectOptions o6 = opts_for(c6);
        MockMonerodTransport mock;
        XmrNode node(c6, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC19 bring_up (node VOTE-B)", false, e.what()); return rep; }
        o6.book_from_chain = [&](std::uint64_t h, const std::string&, Amounts& credit, Amounts& payout, std::string& why) {
            if (h < 5) { why = "not-lane: test"; return false; }
            if (h % 4 == 0) { why = "lane-root-refused:" + roothex_of(h) + ": forker block (test)"; return false; }
            credit.clear(); credit[payee] = 1000; payout = credit; return true;
        };
        FoundBlockQueue q6; FinalizeConnect fc(node, c6, q6, o6);
        chain(node, 1, 4); (void)fc.tick();
        for (std::uint64_t h = 5; h <= 44; ++h) { chain(node, h, h); (void)fc.tick(); }
        rep.add("FC19c lone forker at 25% share (fresh root at each of its blocks; its own booked blocks never 'reset' anything): honest node CONVERGED throughout -- never contested, never isolated, never halted",
                fc.vote_state() == FinalizeConnect::VoteState::Converged && fc.stats().contested_entered == 0 &&
                fc.stats().isolated_entered == 0 && !fc.diverged() && fc.stats().refused_not_credited == 10 &&
                node.finalize_driver().cursor_height() == 41,
                "state=" + std::string(FinalizeConnect::vote_state_name(fc.vote_state())) + " refused=" + std::to_string(fc.stats().refused_not_credited) +
                " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        (void)fc.drain_before_stop();
    }
    // 5C/5D: a VERIFIED counter-lineage (test seam: register_counter_lineage).
    //  C: 3 of 4 blocks are its -> ISOLATED at k_min=8 (hook fires synchronously),
    //     cursor NOT frozen; then it stops producing -> back out after exit_hold.
    //  D: 1 of 2 blocks are its -> the dead zone: CONTESTED, never ISOLATED.
    for (int variant = 0; variant < 2; ++variant) {
        XmrNodeConfig c7 = store_of(variant == 0 ? "store-vote-iso" : "store-vote-dead");
        FinalizeConnectOptions o7 = opts_for(c7);
        MockMonerodTransport mock;
        XmrNode node(c7, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC19 bring_up (node VOTE-C)", false, e.what()); return rep; }
        bool counter_active = true;
        auto theirs = [&](std::uint64_t h) { return counter_active && (variant == 0 ? (h % 4 != 0) : (h % 2 == 1)); };
        o7.book_from_chain = [&](std::uint64_t h, const std::string&, Amounts& credit, Amounts& payout, std::string& why) {
            if (h < 5) { why = "not-lane: test"; return false; }
            if (theirs(h)) { why = "lane-root-refused:" + roothex_of(1000 + h) + ": counter-lineage block (test)"; return false; }
            credit.clear(); credit[payee] = 1000; payout = credit; return true;
        };
        FoundBlockQueue q7; FinalizeConnect fc(node, c7, q7, o7);
        int hook_on = 0, hook_off = 0;
        fc.set_isolation_hook([&](bool on, const std::string&) { if (on) ++hook_on; else ++hook_off; });
        std::set<std::string> lp; for (std::uint64_t h = 1; h < 200; ++h) lp.insert(roothex_of(1000 + h));
        fc.register_counter_lineage(lp, 4, "test-verified-snapshot");
        chain(node, 1, 4); (void)fc.tick();
        std::uint64_t iso_at = 0;
        for (std::uint64_t h = 5; h <= 24; ++h) { chain(node, h, h); (void)fc.tick(); if (!iso_at && fc.isolated()) iso_at = h; }
        if (variant == 0) {
            rep.add("FC19d VERIFIED counter-lineage with 3/4 of the attributed work: ISOLATED once it has k_min=8 blocks (h=14), isolation hook fired once, cursor NOT frozen (keeps booking)",
                    iso_at == 14 && fc.isolated() && fc.diverged() && hook_on == 1 && fc.stats().isolated_entered == 1 &&
                    node.finalize_driver().cursor_height() == 21,
                    "iso_at=" + std::to_string(iso_at) + " hook_on=" + std::to_string(hook_on) + " votes me/counter=" +
                    std::to_string(fc.stats().votes_me) + "/" + std::to_string(fc.stats().votes_counter) +
                    " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
            counter_active = false;   // the counter-lineage ran out of hashrate
            for (std::uint64_t h = 25; h <= 64; ++h) { chain(node, h, h); (void)fc.tick(); }
            rep.add("FC19e the counter-lineage stops producing: after exit_hold attributed blocks below 2/3 the node leaves ISOLATED (hook off fired), non-terminal",
                    !fc.isolated() && fc.stats().isolated_exited == 1 && hook_off == 1 && fc.stats().diverged == 0,
                    "state=" + std::string(FinalizeConnect::vote_state_name(fc.vote_state())) + " votes me/counter=" +
                    std::to_string(fc.stats().votes_me) + "/" + std::to_string(fc.stats().votes_counter));
        } else {
            rep.add("FC19f dead zone: a verified counter-lineage with 1/2 of the attributed work -> CONTESTED, NEVER ISOLATED (neither side halts near 50/50)",
                    iso_at == 0 && fc.stats().isolated_entered == 0 && hook_on == 0 &&
                    fc.vote_state() == FinalizeConnect::VoteState::Contested,
                    "state=" + std::string(FinalizeConnect::vote_state_name(fc.vote_state())) + " votes me/counter=" +
                    std::to_string(fc.stats().votes_me) + "/" + std::to_string(fc.stats().votes_counter));
        }
        (void)fc.drain_before_stop();
    }

    // ── phase 6: rework-3 (b) -- REFUSE-SIDE MONEY IS NODE-LOCAL LIABILITY ──
    // Seeded owed: B = 2000 (through the EVENT LOG -- F1). Chain lane blocks:
    //   5  credited      credit {A:1000}  payout {A:1000}
    //   6  lane-root-refused, payout decoded {B:700} (total 5700)
    //   7  refused cut_absent (credit unreproducible), payout decoded {C:300}
    //   8  lane-root-refused, payout NOT attributable, total 5000
    // The refused blocks NEVER touch the ledger (no FOUND, no debit): they are
    // recorded as node-local LIABILITY (per payee when decoded, else the whole
    // reward). Restart: the liability tally reloads, the ledger is unchanged.
    {
        XmrNodeConfig c8 = store_of("store-liability");
        auto cb8 = [&](std::uint64_t h, const std::string&, CB& bk) -> bool {
            if (h == 5) { bk.credit[kA] = 1000; bk.payout[kA] = 1000; bk.payout_decoded = true; return true; }
            if (h == 6) { bk.why = "lane-root-refused:" + roothex_of(6) + ": unmatched (test)"; bk.payout[kB] = 700;
                          bk.payout_decoded = true; bk.total_pico = 5700; bk.onchain_root_hex = roothex_of(6); return false; }
            if (h == 7) { bk.why = "no on-chain credit cut (0x02 V37C tail) -- E_b unreproducible (fail-closed)";
                          bk.payout[kC] = 300; bk.payout_decoded = true; bk.total_pico = 5300; return false; }
            if (h == 8) { bk.why = "lane-root-refused:" + roothex_of(8) + ": unmatched (test)"; bk.total_pico = 5000;
                          bk.onchain_root_hex = roothex_of(8); return false; }
            bk.why = "not-lane: test"; return false;
        };
        long long eoB_after6 = 0, eoB_before6 = 0;
        std::uint64_t seq_before6 = 0, seq_after6 = 0;
        std::size_t dlines = 0, llines = 0;
        bool seeded_fresh = false;
        {
            MockMonerodTransport mock;
            XmrNode node(c8, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC20 bring_up (node LIABILITY)", false, e.what()); return rep; }
            Amounts sB; sB[kB] = 2000;
            seeded_fresh = node.seed_settled_owed("fixture-seed-0", sB, 1);
            FinalizeConnectOptions o8 = opts_for(c8); o8.book_from_chain_ex = cb8;
            FoundBlockQueue q8; FinalizeConnect fc(node, c8, q8, o8);
            (void)fc.reseed_after_bring_up();
            // an OWN win reported by the submit path with the coinbase-authority
            // callback armed: NOT booked on submit-OK -- deferred to the chain view.
            FoundBlockEvent own; own.height = 5; own.block_id_hex = hex_of(smoke::blk_id(5)); own.payee = payee; own.reward_piconero = REWARD;
            q8.push(own); (void)fc.tick();
            const bool own_deferred = fc.pending().empty() && !node.ledger().is_pending(hex_of(smoke::blk_id(5)));
            chain(node, 1, 5); (void)fc.tick();
            const auto p5 = fc.pending().find(hex_of(smoke::blk_id(5)));
            rep.add("FC20e with the RICH callback armed an own win is deferred to the chain (not booked {payee: reward} on submit-OK), then booked from the chain as kind=c with the on-chain maps",
                    own_deferred && p5 != fc.pending().end() && p5->second.kind == 'c' && p5->second.credit.count(kA) &&
                    !p5->second.payout.count(payee), "own_deferred=" + std::to_string(own_deferred));
            eoB_before6 = node.ledger().effective_owed(kB); seq_before6 = node.ledger().ledger_seq();
            chain(node, 6, 6); (void)fc.tick();
            eoB_after6 = node.ledger().effective_owed(kB); seq_after6 = node.ledger().ledger_seq();
            chain(node, 7, 8); (void)fc.tick();
            {
                std::ifstream f(o8.sidecar_path); std::string l;
                while (std::getline(f, l)) if (l.rfind("2 ", 0) == 0 && l.find(" d ") != std::string::npos) ++dlines;
            }
            llines = count_lines(o8.sidecar_path + ".liability");
            rep.add("FC20a rework-3 (b): a refused block with a decoded payout does NOT touch the ledger: eo(B) stays 2000, ledger_seq unchanged, no FOUND/pending for 6 or 7, invariant counter ledger_mutations_on_refuse = 0",
                    seeded_fresh && eoB_before6 == 2000 && eoB_after6 == 2000 && seq_after6 == seq_before6 &&
                    !node.ledger().is_pending(hex_of(smoke::blk_id(6))) && !node.ledger().is_pending(hex_of(smoke::blk_id(7))) &&
                    !node.ledger().is_settled(hex_of(smoke::blk_id(6))) && fc.stats().ledger_mutations_on_refuse == 0,
                    "eoB " + std::to_string(eoB_before6) + "->" + std::to_string(eoB_after6) + " seq " + std::to_string(seq_before6) +
                    "->" + std::to_string(seq_after6));
            const auto& by = fc.liability_by_payee();
            auto byv = [&](const ::v37::bytes32& k) { auto it = by.find(k); return it == by.end() ? 0LL : it->second; };
            rep.add("FC20b the refused blocks are NODE-LOCAL LIABILITY: 3 blocks, attributed {B:700, C:300} (per payee, on-chain decode), unattributed 5000 (whole reward, undecodable), persisted (3 lines), no debit record (kind=d) in the sidecar",
                    fc.stats().liability_blocks == 3 && fc.stats().liability_attributed_pico == 1000 &&
                    fc.stats().liability_unattributed_pico == 5000 && fc.stats().liability_pico == 6000 &&
                    byv(kB) == 700 && byv(kC) == 300 && fc.stats().liability_payees == 2 && llines == 3 && dlines == 0,
                    "blocks=" + std::to_string(fc.stats().liability_blocks) + " att=" + std::to_string(fc.stats().liability_attributed_pico) +
                    " unatt=" + std::to_string(fc.stats().liability_unattributed_pico) + " lines=" + std::to_string(llines) +
                    " dlines=" + std::to_string(dlines));
            (void)fc.drain_before_stop();
        }
        {   // restart: 5 settled at hw 8; nothing of 6/7/8 is in the ledger
            MockMonerodTransport mock;
            const int serve = 0;
            mock.set_responder(header_responder([](std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(h)); }, &serve));
            XmrNode node(c8, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC20 bring_up (node LIABILITY restart)", false, e.what()); return rep; }
            Amounts sB; sB[kB] = 2000;
            const bool reseeded_again = node.seed_settled_owed("fixture-seed-0", sB, 1);
            FinalizeConnectOptions o8 = opts_for(c8); o8.book_from_chain_ex = cb8;
            FoundBlockQueue q8; FinalizeConnect fc(node, c8, q8, o8);
            const auto boot = fc.reseed_after_bring_up();
            rep.add("FC20c restart: the seed is NOT re-applied, no pending record to re-drive (refusals never booked), the LIABILITY tally reloads (3 blocks, 6000), eo(B) still 2000",
                    !reseeded_again && boot.reseeded == 0 && fc.pending().empty() && fc.stats().liability_blocks == 3 &&
                    fc.stats().liability_pico == 6000 && node.ledger().effective_owed(kB) == 2000,
                    "reseeded=" + std::to_string(boot.reseeded) + " liab=" + std::to_string(fc.stats().liability_pico) +
                    " eoB=" + std::to_string(node.ledger().effective_owed(kB)));
            chain(node, 9, 11); (void)fc.tick();
            const auto& fw = node.ledger().finalW();
            auto fwv = [&](const ::v37::bytes32& k) { auto it = fw.find(k); return it == fw.end() ? 0LL : it->second; };
            rep.add("FC20d the ledger holds ONLY the credited block: finalW(A) nets 0, finalW(B) = 2000 (NOT debited by the refused payout), finalW(C) = 0 (no negative finalW from a refusal)",
                    node.ledger().is_settled(hex_of(smoke::blk_id(5))) && !node.ledger().is_settled(hex_of(smoke::blk_id(6))) &&
                    !node.ledger().is_settled(hex_of(smoke::blk_id(7))) && fwv(kA) == 0 && fwv(kB) == 2000 && fwv(kC) == 0,
                    "finalW A/B/C=" + std::to_string(fwv(kA)) + "/" + std::to_string(fwv(kB)) + "/" + std::to_string(fwv(kC)));
            // I1': finalW(k) = C(k) - P(k) over SETTLED (credited) blocks only.
            // I2': on-chain owed outputs over the canonical lane blocks == P(settled) + LIABILITY (nothing unrecorded).
            const long long C_A = 1000, C_B = 2000, P_A = 1000;
            const bool i1 = fwv(kA) == C_A - P_A && fwv(kB) == C_B && fwv(kC) == 0 &&
                            node.ledger().effective_owed(kA) == fwv(kA) && node.ledger().effective_owed(kB) == fwv(kB);
            const long long onchain_owed = 1000 + 700 + 300 + 5000;   // block 8 undecodable: its whole total bounds it
            const long long covered = P_A + static_cast<long long>(fc.stats().liability_pico);
            rep.add("FC21 conservation: I1' finalW(k) == C(k) - P(k) over the SETTLED blocks; I2' on-chain owed outputs == P(settled) + node-local LIABILITY exactly (every refused piconero is on the liability tally, none in the ledger)",
                    i1 && onchain_owed == covered, "onchain=" + std::to_string(onchain_owed) + " covered=" + std::to_string(covered));
            (void)fc.drain_before_stop();
        }
    }

    // ── phase 7: D1 -- two honest nodes refuse the SAME block with DIFFERENT
    // wire-arrival order / attribution, and end BYTE-IDENTICAL ───────────────
    // Both nodes: seed B=2000; 5 credited {A:1000}/{A:600}; 6 the forker's
    // block (refused by both); 9 credited {A:200}/{B:50}. X attributes 6's payout at once
    // (the shape of "the wire descriptor arrived before booking" in rework-2);
    // Y sees 6 root-UNKNOWN for its first 3 attempts (holding its finalize gate),
    // then refuses it with NO attribution (whole reward). rework-2 debited on X
    // and suspended on Y -> two digests. rework-3: identical digest sequence at
    // every ledger event, identical ledger_seq / finalW / settled set; the only
    // difference is the node-local liability's granularity.
    {
        struct Out { std::vector<std::pair<std::uint64_t, ::v37::bytes32>> seq; ::v37::bytes32 fin{}; std::uint64_t lseq = 0;
                     std::map<::v37::bytes32, long long> fw; bool r6_pending = true; std::uint64_t att = 0, unatt = 0, mut = 1, ref = 0, unk = 0; };
        Out out[2];
        for (int side = 0; side < 2; ++side) {
            XmrNodeConfig c9 = store_of(side == 0 ? "store-d1-X" : "store-d1-Y");
            MockMonerodTransport mock;
            XmrNode node(c9, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC22 bring_up", false, e.what()); return rep; }
            Out& O = out[side];
            node.finalize_driver().set_ledger_event_observer([&]() {
                const auto d = node.ledger().owed_digest();
                if (O.seq.empty() || !(O.seq.back().second == d)) O.seq.emplace_back(node.finalize_driver().digest_since(), d);
            });
            Amounts sB; sB[kB] = 2000; (void)node.seed_settled_owed("fixture-seed-0", sB, 1);
            FinalizeConnectOptions o9 = opts_for(c9);
            int y_attempts = 0;
            o9.book_from_chain_ex = [&, side](std::uint64_t h, const std::string&, CB& bk) -> bool {
                // credit != payout so every FINALIZE moves the digest (the sequence has content)
                if (h == 5) { bk.credit[kA] = 1000; bk.payout[kA] = 600; bk.payout_decoded = true; return true; }
                if (h == 9) { bk.credit[kA] = 200; bk.payout[kB] = 50; bk.payout_decoded = true; return true; }
                if (h != 6) { bk.why = "not-lane: test"; return false; }
                bk.total_pico = 5700; bk.onchain_root_hex = roothex_of(606);
                if (side == 0) {   // X: attributed at once
                    bk.why = "lane-root-refused:" + roothex_of(606) + ": forker (test, attributed)";
                    bk.payout[kB] = 700; bk.payout_decoded = true; return false;
                }
                if (++y_attempts <= 3) { bk.why = "lane-root-unknown: 03 root matches none (test: Y not yet decidable)"; return false; }
                bk.why = "lane-root-refused:" + roothex_of(606) + ": forker (test, unattributed)";
                return false;
            };
            FoundBlockQueue q9; FinalizeConnect fc(node, c9, q9, o9);
            for (std::uint64_t h = 1; h <= 14; ++h) { chain(node, h, h); (void)fc.tick(); if (side == 1 && h >= 6) (void)fc.tick(); }
            for (int i = 0; i < 4; ++i) (void)fc.tick();
            O.fin = node.ledger().owed_digest(); O.lseq = node.ledger().ledger_seq(); O.fw = node.ledger().finalW();
            O.r6_pending = node.ledger().is_pending(hex_of(smoke::blk_id(6))) || node.ledger().is_settled(hex_of(smoke::blk_id(6)));
            O.att = fc.stats().liability_attributed_pico; O.unatt = fc.stats().liability_unattributed_pico;
            O.mut = fc.stats().ledger_mutations_on_refuse; O.ref = fc.stats().refused_not_credited;
            O.unk = fc.stats().lane_root_unknown_retries;
            (void)fc.drain_before_stop();
        }
        const bool same = out[0].seq == out[1].seq && out[0].fin == out[1].fin && out[0].lseq == out[1].lseq && out[0].fw == out[1].fw;
        rep.add("FC22 D1: X (payout attributed at once) and Y (root-unknown x3, holding its gate, then refused UNATTRIBUTED) refuse the same block and end BYTE-IDENTICAL -- same owed_digest at every ledger event (" +
                std::to_string(out[0].seq.size()) + " states, with since-heights), same final digest, ledger_seq and finalW",
                same && out[0].seq.size() >= 4 && !out[0].r6_pending && !out[1].r6_pending && out[0].ref == 1 && out[1].ref == 1 &&
                out[0].mut == 0 && out[1].mut == 0 && out[0].unk == 0 && out[1].unk == 3,
                "Y root-unknown retries=" + std::to_string(out[1].unk) + " states X/Y=" + std::to_string(out[0].seq.size()) + "/" + std::to_string(out[1].seq.size()) + " lseq X/Y=" +
                std::to_string(out[0].lseq) + "/" + std::to_string(out[1].lseq) + " digest " + hex_of(out[0].fin).substr(0, 12) + "/" +
                hex_of(out[1].fin).substr(0, 12));
        rep.add("FC22b the ONLY difference is node-local: X's liability is per payee {B:700}, Y's is the whole reward 5700 unattributed",
                out[0].att == 700 && out[0].unatt == 0 && out[1].att == 0 && out[1].unatt == 5700,
                "X att/unatt=" + std::to_string(out[0].att) + "/" + std::to_string(out[0].unatt) + " Y=" +
                std::to_string(out[1].att) + "/" + std::to_string(out[1].unatt));
    }

    // ── phase 8: F1 -- restart digest-history diff KAT ──────────────────────
    // The live owed_digest sequence a node lives through must EQUAL the
    // boot_digest_history() RecoveryDriver replays after a restart (that history
    // seeds the RECON ring; a gap in it refuses honest pre-restart roots). Seeds
    // routed through the event log pass; the old out-of-log seed is the control.
    for (int logged = 1; logged >= 0; --logged) {
        XmrNodeConfig c10 = store_of(logged ? "store-f1-logged" : "store-f1-bypass");
        std::vector<::v37::bytes32> live;
        auto push = [&](const ::v37::bytes32& d) { if (live.empty() || !(live.back() == d)) live.push_back(d); };
        {
            MockMonerodTransport mock;
            XmrNode node(c10, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC24 bring_up", false, e.what()); return rep; }
            push(node.ledger().owed_digest());
            node.finalize_driver().set_ledger_event_observer([&]() { push(node.ledger().owed_digest()); });
            for (int i = 0; i < 3; ++i) {
                Amounts s; s[smoke::key_of(static_cast<std::uint8_t>(0x50 + i))] = 1000 * (i + 1);
                const std::string bid = "fixture-seed-" + std::to_string(i);
                if (logged) (void)node.seed_settled_owed(bid, s, static_cast<std::uint64_t>(i + 1));
                else { node.ledger().on_block_found(bid, s, {}); node.ledger().on_block_finalized(bid, static_cast<std::uint64_t>(i + 1));
                       push(node.ledger().owed_digest()); }
            }
            chain(node, 1, 5);
            Amounts cr; cr[kA] = 400; Amounts po; po[smoke::key_of(0x51)] = 250;
            node.on_network_block_won(5, smoke::blk_id(5), cr, po);
            chain(node, 6, 9);   // FINALIZE(5) at hw 8
        }
        MockMonerodTransport mock;
        XmrNode node(c10, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC24 bring_up (restart)", false, e.what()); return rep; }
        const auto& boot = node.boot_digest_history();
        const bool equal = boot == live;
        if (logged)
            rep.add("FC24 F1: every ledger mutation goes through the event log -> the restarted node's boot_digest_history() EQUALS the live digest sequence it lived through (" +
                    std::to_string(live.size()) + " states)", equal && live.size() >= 5,
                    "live=" + std::to_string(live.size()) + " boot=" + std::to_string(boot.size()));
        else
            rep.add("FC24n control (the pre-fix out-of-log seed): the replayed history MISSES the lived states -- the restart-liveness root cause is real and is what FC24 closes",
                    !equal, "live=" + std::to_string(live.size()) + " boot=" + std::to_string(boot.size()));
    }

    // ── phase 9: TRI-STATE carry -- a header-fetch failure is UNKNOWN (hold) ─
    // Found blocks at 5 (stays canonical) and 6 (replaced by a rival); restart
    // with an empty mirror. Fetch failing -> UNKNOWN -> the walk HOLDS (no false
    // orphan); fetch serving -> 5 finalizes, 6 is a real orphan.
    {
        XmrNodeConfig c11 = store_of("store-tri");
        auto id_of = [](std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(h == 6 ? 99 : h)); };
        {
            MockMonerodTransport mock;
            XmrNode node(c11, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC25 bring_up", false, e.what()); return rep; }
            FinalizeConnectOptions o = opts_for(c11);
            FoundBlockQueue q; FinalizeConnect fc(node, c11, q, o);
            chain(node, 1, 6);
            FoundBlockEvent e5; e5.height = 5; e5.block_id_hex = hex_of(smoke::blk_id(5)); e5.payee = payee; e5.reward_piconero = 100;
            FoundBlockEvent e6; e6.height = 6; e6.block_id_hex = hex_of(smoke::blk_id(6)); e6.payee = payee; e6.reward_piconero = 100;
            q.push(e5); q.push(e6); (void)fc.tick();
            (void)fc.drain_before_stop();
        }
        MockMonerodTransport mock;
        int mode = 1;   // header fetch FAILS
        mock.set_responder(header_responder(id_of, &mode));
        XmrNode node(c11, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC25 bring_up (restart)", false, e.what()); return rep; }
        FinalizeConnectOptions o = opts_for(c11);
        FoundBlockQueue q; FinalizeConnect fc(node, c11, q, o);
        (void)fc.reseed_after_bring_up();
        smoke::apply_row(node, 12, id_of(12), id_of(11));   // empty mirror: only the tip row; frontier 9
        (void)fc.tick();
        const bool held = node.finalize_driver().cursor_height() == 4 && node.ledger().is_pending(hex_of(smoke::blk_id(5))) &&
                          node.ledger().is_pending(hex_of(smoke::blk_id(6))) && fc.stats().orphaned == 0 &&
                          node.finalize_driver().carry_unknown_holds() >= 1;
        rep.add("FC25a header fetch FAILED -> carry UNKNOWN -> the walk HOLDS at 4 (no ORPHAN event, both blocks still pending) -- never the old false orphan",
                held, "cursor=" + std::to_string(node.finalize_driver().cursor_height()) + " orphaned=" + std::to_string(fc.stats().orphaned));
        mode = 0;   // daemon answers again
        (void)fc.tick();
        rep.add("FC25b fetch serving again: 5 is carried (Yes) -> FINALIZED at 8; 6 is carried by a DIFFERENT block (No) -> a REAL orphan; cursor at the frontier 9",
                node.ledger().is_settled(hex_of(smoke::blk_id(5))) && !node.ledger().is_pending(hex_of(smoke::blk_id(6))) &&
                !node.ledger().is_settled(hex_of(smoke::blk_id(6))) && node.finalize_driver().cursor_height() == 9,
                "cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        (void)fc.drain_before_stop();
    }

    // ── phase 10: F2 -- lane blocks mined while the node was DOWN / across a
    // ZMQ gap are re-driven and BOOKED (Extend was the only booking trigger).
    for (int armed = 1; armed >= 0; --armed) {
        XmrNodeConfig c12 = store_of(armed ? "store-gap" : "store-gap-ctl");
        std::set<std::uint64_t> lane = {5, 8, 12, 14, 17, 25};
        auto cb12 = [&](std::uint64_t h, const std::string&, CB& bk) -> bool {
            if (!lane.count(h)) { bk.why = "not-lane: test"; return false; }
            bk.credit[kA] = 100; bk.payout[kA] = 100; bk.payout_decoded = true; return true;
        };
        auto id_of = [](std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(h)); };
        const int serve = 0;
        {
            MockMonerodTransport mock; mock.set_responder(header_responder(id_of, &serve));
            XmrNode node(c12, mock, &smoke::test_point_check);
            node.enable_gap_redrive(armed != 0);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC26 bring_up", false, e.what()); return rep; }
            FinalizeConnectOptions o = opts_for(c12); o.book_from_chain_ex = cb12;
            FoundBlockQueue q; FinalizeConnect fc(node, c12, q, o);
            (void)fc.reseed_after_bring_up();
            for (std::uint64_t h = 1; h <= 9; ++h) { chain(node, h, h); (void)fc.tick(); }
            (void)fc.drain_before_stop();
        }
        // DOWN while 10..20 were mined (12, 14, 17 are lane blocks).
        MockMonerodTransport mock; mock.set_responder(header_responder(id_of, &serve));
        XmrNode node(c12, mock, &smoke::test_point_check);
        node.enable_gap_redrive(armed != 0);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC26 bring_up (restart)", false, e.what()); return rep; }
        smoke::apply_row(node, 20, id_of(20), id_of(19));   // the boot tip lands BEFORE the booking observer exists (initial_sync shape)
        const std::uint64_t cursor_pre = node.finalize_driver().cursor_height();
        FinalizeConnectOptions o = opts_for(c12); o.book_from_chain_ex = cb12;
        FoundBlockQueue q; FinalizeConnect fc(node, c12, q, o);
        (void)fc.reseed_after_bring_up();
        for (int i = 0; i < 3; ++i) (void)fc.tick();
        const auto settled = [&](std::uint64_t h) { return node.ledger().is_settled(hex_of(id_of(h))); };
        if (armed) {
            rep.add("FC26a boot: the tip applied before the observer existed does NOT walk the cursor past the unscanned gap (held at the recovered cursor 6)",
                    cursor_pre == 6, "cursor_pre=" + std::to_string(cursor_pre));
            rep.add("FC26b boot gap re-drive: lane blocks 12, 14, 17 mined while the node was DOWN are BOOKED and SETTLED in chain order (cursor 17), late_unbooked = 0",
                    settled(8) && settled(12) && settled(14) && settled(17) && node.finalize_driver().cursor_height() == 17 &&
                    fc.stats().late_unbooked == 0 && fc.stats().late_booked_post_finalize == 0 && node.gap_stats().redriven_heights >= 14,
                    "cursor=" + std::to_string(node.finalize_driver().cursor_height()) + " redriven=" +
                    std::to_string(node.gap_stats().redriven_heights) + " late=" + std::to_string(fc.stats().late_unbooked));
            smoke::apply_row(node, 30, id_of(30), id_of(29));   // a live ZMQ gap wider than any reconcile walk: 21..29 unseen
            for (int i = 0; i < 3; ++i) (void)fc.tick();
            rep.add("FC26c live gap: lane block 25 inside a missed 21..29 stretch is re-driven, booked and SETTLED (cursor 27), late_unbooked = 0",
                    settled(25) && node.finalize_driver().cursor_height() == 27 && fc.stats().late_unbooked == 0,
                    "cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        } else {
            rep.add("FC26n control (re-drive OFF, the pre-fix behaviour): the lane blocks mined while the node was down are NEVER booked",
                    !settled(12) && !settled(14) && !settled(17) && !node.ledger().is_pending(hex_of(id_of(12))),
                    "cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        }
        (void)fc.drain_before_stop();
    }

    // ── phase 11: D3 -- the vote's observation window survives a restart ────
    // rework-2 verify: B rebooted into "CONVERGED" while forked (the window was
    // memory-only). Refuse 8 frontier blocks -> CONTESTED; restart on the same
    // store: the vote is CONTESTED straight out of reseed_after_bring_up (no
    // tick, no new block). FC27n = the rework-2 behaviour (persistence off).
    for (int persisted = 1; persisted >= 0; --persisted) {
        XmrNodeConfig c13 = store_of(persisted ? "store-obs" : "store-obs-ctl");
        auto cb13 = [&](std::uint64_t h, const std::string&, CB& bk) -> bool {
            if (h >= 5) { bk.why = "lane-root-refused:" + roothex_of(700 + h) + ": unmatched (test)"; bk.total_pico = 100;
                          bk.onchain_root_hex = roothex_of(700 + h); return false; }
            bk.why = "not-lane: test"; return false;
        };
        std::uint64_t n_before = 0; FinalizeConnect::VoteState st_before = FinalizeConnect::VoteState::Converged;
        {
            MockMonerodTransport mock;
            XmrNode node(c13, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC27 bring_up", false, e.what()); return rep; }
            FinalizeConnectOptions o = opts_for(c13); o.book_from_chain_ex = cb13; o.persist_vote_obs = persisted != 0;
            FoundBlockQueue q; FinalizeConnect fc(node, c13, q, o);
            (void)fc.reseed_after_bring_up();
            for (std::uint64_t h = 1; h <= 12; ++h) { chain(node, h, h); (void)fc.tick(); }
            n_before = fc.stats().obs_n; st_before = fc.vote_state();
            (void)fc.drain_before_stop();
        }
        MockMonerodTransport mock;
        XmrNode node(c13, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC27 bring_up (restart)", false, e.what()); return rep; }
        FinalizeConnectOptions o = opts_for(c13); o.book_from_chain_ex = cb13; o.persist_vote_obs = persisted != 0;
        o.contested_suspends = true;   // opt-in (default is off, FC28d): pins that a RESTORED CONTESTED re-arms the suspension at boot
        FoundBlockQueue q; FinalizeConnect fc(node, c13, q, o);
        int hook_on = 0; fc.set_contested_hook([&](bool on, const std::string&) { if (on) ++hook_on; });
        (void)fc.reseed_after_bring_up();
        if (persisted)
            rep.add("FC27 D3: after a restart the lineage-vote window is RESTORED from <sidecar>.obs -- CONTESTED (8/8 refused) straight out of the boot, not re-warmed from zero (with --contested-suspend on, the restored CONTESTED re-fires the suspend hook)",
                    st_before == FinalizeConnect::VoteState::Contested && n_before == 8 &&
                    fc.vote_state() == FinalizeConnect::VoteState::Contested && fc.stats().obs_n == 8 &&
                    fc.stats().obs_restored == 8 && hook_on == 1,
                    "before=" + std::string(FinalizeConnect::vote_state_name(st_before)) + "/" + std::to_string(n_before) +
                    " after=" + FinalizeConnect::vote_state_name(fc.vote_state()) + "/" + std::to_string(fc.stats().obs_n) +
                    " hook_on=" + std::to_string(hook_on));
        else
            rep.add("FC27n control (window NOT persisted, the rework-2 behaviour): the restarted node reports CONVERGED with 0 observations while nothing changed on-chain",
                    st_before == FinalizeConnect::VoteState::Contested &&
                    fc.vote_state() == FinalizeConnect::VoteState::Converged && fc.stats().obs_n == 0,
                    "after=" + std::string(FinalizeConnect::vote_state_name(fc.vote_state())));
        (void)fc.drain_before_stop();
    }

    // ── phase 12: CONTESTED -> lane suspend (opt-in), auto-resume ───────────
    // FC28d pins the RULED default: suspension is OFF unless an operator asks.
    rep.add("FC28d contested_suspends defaults to false (operator ruling: CONTESTED = loud alarm + counters, keep building; --contested-suspend on opts in)",
            FinalizeConnectOptions{}.contested_suspends == false);
    // 6 refused frontier blocks -> CONTESTED: the contested hook fires ONCE,
    // synchronously inside that tick. Then honest (booked) blocks until the
    // refused fraction over the 24-block window drops below 1/3 -> CONVERGED:
    // the hook fires (false) ONCE. With contested_suspends=false it never fires.
    for (int armed = 1; armed >= 0; --armed) {
        XmrNodeConfig c14 = store_of(armed ? "store-contested" : "store-contested-off");
        FinalizeConnectOptions o = opts_for(c14); o.contested_suspends = armed != 0;
        o.book_from_chain_ex = [&](std::uint64_t h, const std::string&, CB& bk) -> bool {
            if (h >= 5 && h <= 10) { bk.why = "lane-root-refused:" + roothex_of(800 + h) + ": forker (test)"; bk.total_pico = 100;
                                     bk.onchain_root_hex = roothex_of(800 + h); return false; }
            if (h > 10) { bk.credit[kA] = 10; bk.payout[kA] = 10; bk.payout_decoded = true; return true; }
            bk.why = "not-lane: test"; return false;
        };
        MockMonerodTransport mock;
        XmrNode node(c14, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC28 bring_up", false, e.what()); return rep; }
        FoundBlockQueue q; FinalizeConnect fc(node, c14, q, o);
        int on = 0, off = 0; std::uint64_t on_at = 0, off_at = 0; std::uint64_t cur_h = 0;
        fc.set_contested_hook([&](bool v, const std::string&) { if (v) { ++on; on_at = cur_h; } else { ++off; off_at = cur_h; } });
        for (std::uint64_t h = 1; h <= 40; ++h) { cur_h = h; chain(node, h, h); (void)fc.tick(); }
        if (armed)
            rep.add("FC28 CONTESTED -> lane suspend: the contested hook fires once (h=10, the 6th refused frontier block, inside that tick) and releases once when the window returns below 1/3 -> CONVERGED (auto-resume); no halt, the cursor walked to the frontier",
                    on == 1 && off == 1 && on_at == 10 && off_at > 10 && fc.vote_state() == FinalizeConnect::VoteState::Converged &&
                    fc.stats().contested_suspend_edges == 1 && fc.stats().contested_resume_edges == 1 &&
                    node.finalize_driver().cursor_height() == 37,
                    "on=" + std::to_string(on) + "@" + std::to_string(on_at) + " off=" + std::to_string(off) + "@" + std::to_string(off_at) +
                    " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        else
            rep.add("FC28n --contested-suspend off (the default): the vote still goes CONTESTED -> CONVERGED (loud, counted) but the hook never fires (keep building)",
                    on == 0 && off == 0 && fc.stats().contested_entered == 1, "on=" + std::to_string(on));
        (void)fc.drain_before_stop();
    }

    // ── phase 13: D7 -- the RECON root-age bound ────────────────────────────
    // (a) the ring's since-heights are the same live and after a restart (the
    //     boot replay derives them from the Finalize events' bin_height);
    // (b) a block committing a HISTORICAL root older than 4*D_conf (relative to
    //     its builder cut) is refused -- the forker-commits-the-genesis-seed-state
    //     shape -- while an honest builder at the lag-suspend bound, a recent
    //     stale root and a long-idle CURRENT root are all accepted.
    {
        namespace rc = c2pool::v37n::xmr::recon;
        XmrNodeConfig c15 = store_of("store-recon-age");
        std::vector<std::pair<::v37::bytes32, std::uint64_t>> live;
        {
            MockMonerodTransport mock;
            XmrNode node(c15, mock, &smoke::test_point_check);
            try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC29 bring_up", false, e.what()); return rep; }
            live.emplace_back(node.ledger().owed_digest(), node.finalize_driver().digest_since());
            node.finalize_driver().set_ledger_event_observer([&]() {
                const auto d = node.ledger().owed_digest();
                if (!(live.back().first == d)) live.emplace_back(d, node.finalize_driver().digest_since());
            });
            Amounts s0; s0[kB] = 5000; (void)node.seed_settled_owed("fixture-seed-0", s0, 1);   // the genesis-seed state
            for (std::uint64_t h = 1; h <= 30; ++h) {
                chain(node, h, h);
                if (h == 10 || h == 14 || h == 17 || h == 20) {
                    Amounts cr; cr[kA] = static_cast<long long>(100 + h);   // credit only: every FINALIZE moves finalW(A)
                    node.on_network_block_won(h, smoke::blk_id(static_cast<std::uint8_t>(h)), cr, Amounts{});
                }
            }
        }
        MockMonerodTransport mock;
        XmrNode node(c15, mock, &smoke::test_point_check);
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC29 bring_up (restart)", false, e.what()); return rep; }
        const auto& bd = node.boot_digest_history(); const auto& bs = node.boot_digest_since();
        bool eq = bd.size() == live.size() && bs.size() == live.size();
        for (std::size_t i = 0; eq && i < live.size(); ++i) eq = bd[i] == live[i].first && bs[i] == live[i].second;
        std::string sinces; for (auto v : bs) sinces += std::to_string(v) + ",";
        auto last_with = [&](std::uint64_t since) -> long {
            long r = -1; for (std::size_t i = 0; i < bs.size(); ++i) if (bs[i] == since) r = static_cast<long>(i); return r; };
        rep.add("FC29a D7: the (digest, since-height) pairs a node lives through EQUAL the boot replay's after a restart (seed at 0, FINALIZE(h) at h: 10,14,17,20)",
                eq && live.size() >= 6 && last_with(10) > 0 && last_with(14) > last_with(10) && last_with(17) > last_with(14) &&
                last_with(20) == static_cast<long>(bs.size()) - 1 && node.finalize_driver().digest_since() == 20,
                "live=" + std::to_string(live.size()) + " boot=" + std::to_string(bd.size()) + " since=" + sinces);
        rc::ReconRing ring; ring.seed(bd, bs);
        std::vector<::v37::bytes32> cands; std::vector<std::uint64_t> sup;
        ring.candidates(node.ledger().owed_digest(), cands, sup);
        const std::uint64_t D = D_CONF, maxage = rc::default_max_root_age(D);
        auto age_of = [&](const ::v37::bytes32& d, std::uint64_t h) -> std::uint64_t {
            for (std::size_t i = 0; i < cands.size(); ++i) if (cands[i] == d) return rc::root_age(sup[i], rc::builder_cut(h, D));
            return ~std::uint64_t{0};
        };
        if (!eq || last_with(0) < 1 || last_with(14) < 0 || last_with(17) < 0) { rep.add("FC29b precondition (ring layout)", false, sinces); return rep; }
        const ::v37::bytes32 seed_state = bd[static_cast<std::size_t>(last_with(0))], st14 = bd[static_cast<std::size_t>(last_with(14))],
                             st17 = bd[static_cast<std::size_t>(last_with(17))], cur = bd.back();
        // the forker, freshly booted with the same genesis seed, builds at h=40 (bcut 36): seed state superseded at 10 -> age 26 > 12
        const std::uint64_t a_forker = age_of(seed_state, 40);
        // an honest builder at the lag-suspend bound (cursor = bcut - 2*D_conf) commits the state current at that cursor
        const std::uint64_t a_honest_lag = age_of(st17, 20 + 1 + D + 2 * D);        // st17 superseded at 20, bcut = 26 -> age 6
        const std::uint64_t a_recent = age_of(st14, 24);                             // superseded at 17, bcut 20 -> age 3
        const std::uint64_t a_idle   = age_of(cur, 5000);                            // still CURRENT: age 0 however old
        const std::uint64_t a_seed_early = age_of(seed_state, 22);                   // bcut 18, superseded 10 -> age 8 (within 12)
        rep.add("FC29b D7 bound = 4*D_conf = 12: a block at h=40 committing the GENESIS-SEED state (superseded at h=10) has age 26 -> REFUSED as stale (the rework-2 credit), while an honest builder at the 2*D_conf lag bound (age 6), a recent stale root (3), the seed state while still young (8) and a long-idle CURRENT root (0) are all accepted",
                maxage == 12 && a_forker == 26 && a_forker > maxage && a_honest_lag == 6 && a_honest_lag <= maxage &&
                a_recent == 3 && a_idle == 0 && a_seed_early == 8 && a_seed_early <= maxage,
                "forker=" + std::to_string(a_forker) + " honest_lag=" + std::to_string(a_honest_lag) + " recent=" +
                std::to_string(a_recent) + " idle=" + std::to_string(a_idle) + " seed_early=" + std::to_string(a_seed_early));
    }

    // ── phase 14: D2-0 -- a Reorg's re-applied blocks reach the booking observer ─
    // p2p-first (the evidence arm): the native index emits Orphan(s) + ONE Reorg
    // carrying only the new tip. shape 0 (fix2 evidence): this node's own block
    // at 9 is replaced by the peer's 9 and 10 -- the peer's 9 must be BOOKED and
    // SETTLED here exactly as on the node that followed the peer directly.
    // shape 1 (base evidence): the peer's 9 is booked, replaced by our own 9,
    // then re-established under the peer's 10 -- it must be RE-BOOKED
    // ("canonical AGAIN") and settled; our own 9 never settles.
    for (int shape = 0; shape < 2; ++shape) {
        using c2pool::xmr::node::MainchainEvent;
        using c2pool::xmr::node::MainchainEventKind;
        XmrNodeConfig c16 = store_of(shape == 0 ? "store-d20-fix2" : "store-d20-base");
        c16.arm_order = ArmOrderMode::P2PFirst;
        std::map<std::uint64_t, c2pool::xmr::node::Hash> canon;
        MockMonerodTransport mock;
        XmrNode node(c16, mock, &smoke::test_point_check);
        node.set_native_chain_presence([&](std::uint64_t h, const std::string& bid) {
            const auto it = canon.find(h); return it != canon.end() && hex_of(it->second) == bid; });
        node.set_native_row_lookup([&](std::uint64_t h) -> std::optional<std::string> {
            const auto it = canon.find(h); if (it == canon.end()) return std::nullopt; return hex_of(it->second); });
        try { node.bring_up(); } catch (const std::exception& e) { rep.add("FC30 bring_up", false, e.what()); return rep; }
        FinalizeConnectOptions o = opts_for(c16);
        o.book_from_chain_ex = [&](std::uint64_t h, const std::string&, CB& bk) -> bool {
            if (h < 5) { bk.why = "not-lane: test"; return false; }
            bk.credit[kA] = static_cast<long long>(100 + h); bk.payout_decoded = true; return true;
        };
        FoundBlockQueue q; FinalizeConnect fc(node, c16, q, o);
        (void)fc.reseed_after_bring_up();
        auto own  = [](std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(h)); };
        auto peer = [](std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(100 + h)); };
        auto send = [&](MainchainEventKind k, std::uint64_t h, const c2pool::xmr::node::Hash& id, std::uint64_t depth,
                        const c2pool::xmr::node::Hash& orphaned) {
            MainchainEvent ev; ev.kind = k; ev.block.height = h; ev.block.id = id; ev.depth = depth; ev.orphaned_id = orphaned;
            node.pump_mainchain_event(ev);
        };
        auto extend = [&](std::uint64_t h, const c2pool::xmr::node::Hash& id) {
            canon[h] = id; send(MainchainEventKind::Extend, h, id, 0, {}); (void)fc.tick();
        };
        for (std::uint64_t h = 1; h <= 8; ++h) extend(h, own(h));
        if (shape == 0) {
            extend(9, own(9));                                   // our own 9 (the stale-template find), booked
            canon[9] = peer(9); canon[10] = peer(10);            // the peer's branch 9, 10 arrives
            send(MainchainEventKind::Orphan, 9, own(9), 0, own(9));
            send(MainchainEventKind::Reorg, 10, peer(10), 1, {});
            (void)fc.tick();
        } else {
            extend(9, peer(9));                                  // the peer's 9 arrives first: booked
            canon[9] = own(9);                                   // our own 9 on a stale template replaces it
            send(MainchainEventKind::Orphan, 9, peer(9), 0, peer(9));
            send(MainchainEventKind::Reorg, 9, own(9), 1, {});
            (void)fc.tick();
            canon[9] = peer(9); canon[10] = peer(10);            // the peer's 10 (built on its 9) re-establishes it
            send(MainchainEventKind::Orphan, 9, own(9), 0, own(9));
            send(MainchainEventKind::Reorg, 10, peer(10), 1, {});
            (void)fc.tick();
        }
        for (std::uint64_t h = 11; h <= 16; ++h) extend(h, peer(h));
        for (int i = 0; i < 3; ++i) (void)fc.tick();
        const bool p9 = node.ledger().is_settled(hex_of(peer(9))), o9 = node.ledger().is_settled(hex_of(own(9))) ||
                                                                         node.ledger().is_pending(hex_of(own(9)));
        rep.add(shape == 0
                    ? "FC30 D2-0 (fix2 shape): our own 9 replaced by the peer's 9+10 in ONE Reorg -> the re-applied peer 9 is delivered to the booking observer before the tip, BOOKED and SETTLED (not left unattempted); our 9 never settles; late_unbooked = 0"
                    : "FC30b D2-0 (base shape): the peer's 9 booked, orphaned by our stale 9, re-established under the peer's 10 -> RE-BOOKED (canonical again) and SETTLED; our 9 never settles; late_unbooked = 0",
                p9 && !o9 && node.reorg_redelivered() >= 1 && fc.stats().late_unbooked == 0 &&
                node.finalize_driver().cursor_height() == 13,
                "peer9_settled=" + std::to_string(p9) + " own9=" + std::to_string(o9) + " redelivered=" +
                std::to_string(node.reorg_redelivered()) + " late=" + std::to_string(fc.stats().late_unbooked) +
                " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
        (void)fc.drain_before_stop();
    }

    minority_fc_selfcheck(rep, tmp_root);
    return rep;
}

// ===========================================================================
// D2 KATs (FC31..FC35): N FinalizeConnect nodes in LOCKSTEP over one mock chain.
// Every lane block carries the owed_digest its builder held at its builder cut
// (the "0x03 root", here the digest itself) and the builder's extra-nonce; each
// node decodes it against its OWN candidate ring exactly like main's
// book_from_chain_ex (unmatched + synced = lane-root-refused, D7 omitted), and
// the scratch decoder (book_scratch) against the ring the re-derivation hands it.
// ===========================================================================
struct D2Rig {
    using CB = FinalizeConnectOptions::ChainBooking;
    using Hash = c2pool::xmr::node::Hash;
    struct Blk {
        std::string bid; char who = 'B'; ::v37::bytes32 commit{}; Amounts credit, payout; std::uint32_t en = 0;
        bool stall_majority = false;   // the majority cannot reproduce its credit cut (relay-repair stall)
    };
    struct Node {
        std::string name; bool majority = false; char who = 'B';
        XmrNodeConfig cfg; FinalizeConnectOptions base_opts;
        std::unique_ptr<c2pool::xmr::node::MockMonerodTransport> mock;
        std::unique_ptr<XmrNode> node; std::unique_ptr<FoundBlockQueue> q; std::unique_ptr<FinalizeConnect> fc;
        recon::ReconRing ring{4096};
        int hook_on = 0, hook_off = 0; std::uint64_t scratch_calls = 0;
        std::set<std::uint64_t> not_lane_h;          // control nodes: heights they treat as strangers' blocks
        std::vector<::v37::bytes32> dseq;            // distinct digest states lived through
        std::string boot_error;
    };
    std::uint64_t D = 3;
    std::map<std::uint64_t, Blk> spec;
    std::deque<Node> nodes;
    std::uint64_t top = 0;

    static std::uint32_t en_of(char who) {
        switch (who) { case 'A': return 0x01100000u; case 'B': return 0x02200000u; case 'C': return 0x03300000u; default: return 0x04400000u; }
    }
    static Hash id(std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(h)); }

    Node& add(const std::string& name, bool majority, char who, const XmrNodeConfig& cfg, FinalizeConnectOptions o) {
        nodes.emplace_back();
        Node& n = nodes.back();
        n.name = name; n.majority = majority; n.who = who; n.cfg = cfg; n.base_opts = std::move(o);
        return n;
    }
    bool boot(Node& n) {
        n.mock = std::make_unique<c2pool::xmr::node::MockMonerodTransport>();
        n.node = std::make_unique<XmrNode>(n.cfg, *n.mock, &smoke::test_point_check);
        try { n.node->bring_up(); } catch (const std::exception& e) { n.boot_error = e.what(); return false; }
        for (std::uint64_t h = 1; h <= top; ++h) smoke::apply_row(*n.node, h, id(h), id(h - 1));   // before the observers exist
        n.ring = recon::ReconRing(4096);
        n.ring.seed(n.node->boot_digest_history(), n.node->boot_digest_since());
        Node* np = &n;
        n.node->finalize_driver().set_ledger_event_observer([np] {
            const auto d = np->node->ledger().owed_digest();
            np->ring.push(d, np->node->finalize_driver().digest_since());
            if (np->dseq.empty() || !(np->dseq.back() == d)) np->dseq.push_back(d);
        });
        FinalizeConnectOptions o = n.base_opts;
        o.book_from_chain_ex = [this, np](std::uint64_t h, const std::string& bid, CB& bk) { return book(*np, h, bid, bk, nullptr); };
        o.book_scratch = [this, np](std::uint64_t h, const std::string& bid, const FinalizeConnectOptions::ScratchQuery& q, CB& bk) {
            ++np->scratch_calls; return book(*np, h, bid, bk, &q); };
        n.q = std::make_unique<FoundBlockQueue>();
        n.fc = std::make_unique<FinalizeConnect>(*n.node, n.cfg, *n.q, o);
        n.fc->set_own_builder_keys({minority::builder_key(en_of(n.who))});
        n.fc->set_converge_hook([np](bool on, const std::string&) { if (on) ++np->hook_on; else ++np->hook_off; });
        n.fc->set_relineage_hook([np] {
            np->ring = recon::ReconRing(4096);
            np->ring.seed(np->node->boot_digest_history(), np->node->boot_digest_since());
        });
        (void)n.fc->reseed_after_bring_up();
        const auto d = n.node->ledger().owed_digest();
        if (n.dseq.empty() || !(n.dseq.back() == d)) n.dseq.push_back(d);
        return true;
    }
    void shutdown(Node& n, bool drain = true) {   // drain = false: a simulated crash (nothing more is written)
        if (n.fc && drain) (void)n.fc->drain_before_stop();
        n.fc.reset(); n.q.reset(); n.node.reset(); n.mock.reset();
    }
    // The block at h, built by `who` on `builder`'s ledger (its owed_digest now,
    // i.e. at the builder cut h - 1 - D of a lockstep node); garbage = a root no
    // honest ledger ever held (a forker's commitment).
    void mine(std::uint64_t h, char who, Node* builder, bool garbage = false, bool stall = false) {
        Blk b; b.bid = hex_of(id(h)); b.who = who; b.en = en_of(who) + static_cast<std::uint32_t>(h);
        b.credit[smoke::key_of(static_cast<std::uint8_t>(0x40 + (who - 'A')))] = static_cast<long long>(1000 + 17 * h);
        b.payout[smoke::key_of(static_cast<std::uint8_t>(0x60 + h % 3))] = static_cast<long long>(200 + h);
        if (garbage) { b.commit = smoke::key_of(static_cast<std::uint8_t>(0xE0 + h)); b.commit[7] = 0x77; }
        else b.commit = builder->node->ledger().owed_digest();
        b.stall_majority = stall;
        spec[h] = b;
    }
    void apply(std::uint64_t h) {
        top = std::max(top, h);
        for (auto& n : nodes) if (n.node) smoke::apply_row(*n.node, h, id(h), id(h - 1));
        for (int i = 0; i < 2; ++i) for (auto& n : nodes) if (n.fc) (void)n.fc->tick();
    }
    bool book(Node& n, std::uint64_t h, const std::string& bid, CB& bk, const FinalizeConnectOptions::ScratchQuery* q) {
        const auto it = spec.find(h);
        if (it == spec.end() || it->second.bid != bid || n.not_lane_h.count(h)) { bk.why = "not-lane: test"; return false; }
        const Blk& b = it->second;
        bk.has_extra_nonce = true; bk.extra_nonce = b.en; bk.onchain_root_hex = hex_of(b.commit);
        std::uint64_t tot = 1000; for (const auto& [k, v] : b.payout) { (void)k; tot += static_cast<std::uint64_t>(v); }
        bk.total_pico = tot;
        std::vector<::v37::bytes32> cands; std::vector<std::uint64_t> sup;
        if (q) { cands = *q->cands; sup = *q->superseded; }
        else n.ring.candidates(n.node->ledger().owed_digest(), cands, sup);
        bool m = false; for (const auto& d : cands) if (d == b.commit) { m = true; break; }
        if (!m) {
            const bool decidable = q || n.node->finalize_driver().cursor_height() >= recon::builder_cut(h, D);
            bk.why = decidable ? "lane-root-refused:" + bk.onchain_root_hex + ": unmatched (test)" : "lane-root-unknown: not yet decidable (test)";
            bk.unattributed_pico = tot;
            return false;
        }
        if (!q) {
            bk.has_matched_since = true;
            const auto s = n.ring.since_of(b.commit);
            bk.matched_since = s ? *s : n.node->finalize_driver().digest_since();
        }
        if (q && q->root_only) { bk.why = "root-ok"; return true; }
        bk.payout = b.payout; bk.payout_decoded = true;
        if (!q && n.majority && b.stall_majority) {
            bk.why = "cut-pending: relay repair of P=1 spine=000000000000 in flight (test: the winner's isolated receipts never reached this node)";
            return false;
        }
        bk.credit = b.credit;
        return true;
    }
    // FINALIZED-set equality over every lane block of the chain.
    static bool same_settled(D2Rig& R, Node& a, Node& b) {
        for (const auto& [h, blk] : R.spec) { (void)h; if (a.node->ledger().is_settled(blk.bid) != b.node->ledger().is_settled(blk.bid)) return false; }
        return true;
    }
    static bool same_liability(Node& a, Node& b) {
        const auto& sa = a.fc->stats(); const auto& sb = b.fc->stats();
        std::set<std::string> ba, bb;
        for (const auto& x : a.fc->liability()) ba.insert(x.bid);
        for (const auto& x : b.fc->liability()) bb.insert(x.bid);
        return ba == bb && a.fc->liability_by_payee() == b.fc->liability_by_payee() &&
               sa.liability_attributed_pico == sb.liability_attributed_pico && sa.liability_unattributed_pico == sb.liability_unattributed_pico;
    }
};

inline void minority_fc_selfcheck(smoke::Report& rep, const std::filesystem::path& tmp_root) {
    using Node = D2Rig::Node;
    const ::v37::ChainId CHAIN = 7;
    auto cfg_of = [&](const std::string& name) {
        XmrNodeConfig c; c.network = MoneroNetwork::Stagenet; c.lane_chain = CHAIN; c.d_conf = 3;
        c.settle_db_path = (tmp_root / name).string();
        std::filesystem::create_directories(c.settle_db_path);
        return c;
    };
    auto opts_of = [&](const XmrNodeConfig& c, bool majority) {
        FinalizeConnectOptions o; o.out = nullptr;
        o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
        if (majority) o.retry_bound = 1;   // the relay-repair stall on X resolves inside one tick pair
        return o;
    };
    auto archived = [](const XmrNodeConfig& c) {
        for (const auto& e : std::filesystem::directory_iterator(c.settle_db_path))
            if (e.path().filename().string().rfind("settle.img.pre-converge-", 0) == 0) return true;
        return false;
    };
    auto marker_of = [](const XmrNodeConfig& c) {
        std::ifstream in((std::filesystem::path(c.settle_db_path) / "pfound.tsv.converge").string());
        std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        minority::Marker m; if (!minority::marker_parse(body, m)) m.phase = "-";
        return m;
    };
    auto hx = [](const ::v37::bytes32& d) { return hex_of(d).substr(0, 12); };
    const std::string X = hex_of(D2Rig::id(8)), W = hex_of(D2Rig::id(11)), Y = hex_of(D2Rig::id(13));

    // The FC31 layout. Heights 1..4: no lane block. 5..7: majority (B, C
    // alternating). 8 = X, the minority A's own ISOLATED find: A credits it,
    // the majority stalls on its credit cut (relay repair) and refuses it
    // (liability). 9, 10, 12: majority. 11 = W (with_w): A's own block built on
    // the SHARED state -> credited everywhere. 13 = Y: A's own block on the
    // minority lineage (commits a digest containing X) -> refused by the
    // majority as lane-root-refused. 14..: majority, committing states A's
    // history cannot hold -> A refuses them; 14, 15, 16 from builders B and C
    // complete the run on A.
    auto layout = [&](D2Rig& R, Node& A, Node& B, bool mark, bool with_w, std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h) {
            if (h <= 4) { R.apply(h); continue; }
            if (h == 8) {
                R.mine(8, 'A', &A, false, /*stall=*/true);
                if (mark && A.fc) A.fc->mark_isolated_own(X, 8, "test: parked, no relay peer");
            } else if (h == 11 && with_w) R.mine(11, 'A', &A);
            else if (h == 13) R.mine(13, 'A', &A);
            else R.mine(h, (h % 2) ? 'B' : 'C', &B);
            R.apply(h);
        }
    };

    // ── FC31 / FC33 / FC31n: the D2 case end to end ─────────────────────────
    for (int mode = 1; mode >= 0; --mode) {
        D2Rig R;
        auto cA = cfg_of(mode ? "d2-fc31-A" : "d2-fc31n-A"), cB = cfg_of(mode ? "d2-fc31-B" : "d2-fc31n-B"),
             cB2 = cfg_of(mode ? "d2-fc31-B2" : "d2-fc31n-B2");
        FinalizeConnectOptions oA = opts_of(cA, false);
        if (!mode) oA.minority_mode = FinalizeConnectOptions::MinorityMode::Off;   // today's behaviour exactly
        Node& A = R.add("A", false, 'A', cA, oA);
        Node& B = R.add("B", true, 'B', cB, opts_of(cB, true));
        Node& B2 = R.add("B2", true, 'B', cB2, opts_of(cB2, true));   // FC33 control: A's X and Y are strangers' blocks to it
        B2.not_lane_h = {8, 13};
        if (!R.boot(A) || !R.boot(B) || !R.boot(B2)) { rep.add("FC31 boot", false, A.boot_error + B.boot_error + B2.boot_error); return; }
        layout(R, A, B, true, true, 1, 16);
        const auto st16 = A.fc->stats();
        const bool eq16 = A.node->ledger().owed_digest() == B.node->ledger().owed_digest();
        bool eq_after = eq16;
        for (std::uint64_t h = 17; h <= 22; ++h) { layout(R, A, B, true, true, h, h); eq_after = eq_after && A.node->ledger().owed_digest() == B.node->ledger().owed_digest(); }
        const auto& sa = A.fc->stats(); const auto& sb = B.fc->stats();
        if (mode) {
            rep.add("FC31 D2 end to end: A's own isolated X credited by A, refused by the majority (relay-repair stall); 3 majority blocks from 2 builders then commit roots A cannot reproduce -> MINORITY DETECTED (hook on), R1 = {X} reproduces 3/3, store rewritten + archived, A re-lineaged INSIDE the same step: owed_digest == the majority's from that step on (and at every later step), FINALIZED sets equal, hook off, cursor unchanged",
                    st16.minority_runs_detected == 1 && st16.converged == 1 && A.hook_on == 1 && A.hook_off == 1 && eq16 && eq_after &&
                    A.fc->converge_state() == FinalizeConnect::ConvergeState::Converged && archived(cA) && marker_of(cA).phase == "done" &&
                    marker_of(cA).candidate == "R1" && D2Rig::same_settled(R, A, B) && !A.node->ledger().is_settled(X) &&
                    A.node->ledger().is_settled(W) && A.node->finalize_driver().cursor_height() == B.node->finalize_driver().cursor_height() &&
                    A.node->relineages() == 1,
                    "detected=" + std::to_string(st16.minority_runs_detected) + " converged=" + std::to_string(st16.converged) +
                    " hooks=" + std::to_string(A.hook_on) + "/" + std::to_string(A.hook_off) + " eq16=" + std::to_string(eq16) +
                    " eq_after=" + std::to_string(eq_after) + " A=" + hx(A.node->ledger().owed_digest()) + " B=" + hx(B.node->ledger().owed_digest()) +
                    " marker=" + marker_of(cA).phase + "/" + marker_of(cA).candidate);
            rep.add("FC31c liability after the adoption is IDENTICAL on A and the majority: X per payee (on A from its booked payout, on B from the stalled decode), Y whole reward unattributed; A released its 3 refusals of the run blocks (now credited); the refuse path never mutated a ledger; late_unbooked = 0",
                    D2Rig::same_liability(A, B) && sa.liability_released == 3 && sa.own_refused_on_converge == 2 &&
                    sa.ledger_mutations_on_refuse == 0 && sb.ledger_mutations_on_refuse == 0 && sa.late_unbooked == 0 && sb.late_unbooked == 0 &&
                    sb.relay_repair_stall_timeout == 1,
                    "liab A/B blocks=" + std::to_string(sa.liability_blocks) + "/" + std::to_string(sb.liability_blocks) + " att=" +
                    std::to_string(sa.liability_attributed_pico) + "/" + std::to_string(sb.liability_attributed_pico) + " unatt=" +
                    std::to_string(sa.liability_unattributed_pico) + "/" + std::to_string(sb.liability_unattributed_pico) +
                    " released=" + std::to_string(sa.liability_released) + " own_refused=" + std::to_string(sa.own_refused_on_converge));
            rep.add("FC33 the MAJORITY is unaffected: B saw A's X (refused, stall), W (matched) and Y (unmatched, ONE builder) -> never detects, never suspends, and its digest sequence EQUALS a control that never saw X / Y as lane blocks; ledger_mutations_on_refuse = 0",
                    sb.minority_runs_detected == 0 && B.hook_on == 0 && B.fc->converge_state() == FinalizeConnect::ConvergeState::Converged &&
                    B.dseq == B2.dseq && B.node->ledger().owed_digest() == B2.node->ledger().owed_digest() && sb.refused_not_credited == 1,
                    "B states=" + std::to_string(B.dseq.size()) + " control=" + std::to_string(B2.dseq.size()) +
                    " B run=" + std::to_string(sb.minority_run_len));
        } else {
            rep.add("FC31n control (--minority-converge off == the base behaviour): the same partition leaves A and the majority FORKED for good (A credits X, refuses every majority block after it; no detection, no convergence)",
                    !eq_after && sa.minority_runs_detected == 0 && sa.converged == 0 && A.node->ledger().is_settled(X) &&
                    !D2Rig::same_settled(R, A, B),
                    "A=" + hx(A.node->ledger().owed_digest()) + " B=" + hx(B.node->ledger().owed_digest()));
        }
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── FC31b: no isolation mark -> R1 empty -> R2 (every own block since F) ─
    {
        D2Rig R;
        auto cA = cfg_of("d2-fc31b-A"), cB = cfg_of("d2-fc31b-B");
        Node& A = R.add("A", false, 'A', cA, opts_of(cA, false));
        Node& B = R.add("B", true, 'B', cB, opts_of(cB, true));
        if (!R.boot(A) || !R.boot(B)) { rep.add("FC31b boot", false, A.boot_error + B.boot_error); return; }
        layout(R, A, B, /*mark=*/false, /*with_w=*/false, 1, 20);
        rep.add("FC31b without an isolation mark R1 is empty: R2 = every own block since F ({X, Y}) reproduces the run -> converged; digests and FINALIZED sets equal",
                A.fc->stats().converged == 1 && marker_of(cA).candidate == "R2" &&
                A.node->ledger().owed_digest() == B.node->ledger().owed_digest() && D2Rig::same_settled(R, A, B),
                "converged=" + std::to_string(A.fc->stats().converged) + " candidate=" + marker_of(cA).candidate);
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── FC31d: the forced refuse set is neither R1 nor R2 -> the bounded own-subset search ─
    // X1 (8, isolation-marked) is credited by the majority, X2 (9, NOT marked) is
    // refused by it (credit-cut stall), W (11) is credited everywhere. F = 8 (the
    // last matched foreign block commits D(8)), so R1 = {} and R2 = {X2, W}
    // (fails: W was credited), R0 = {} fails (X2 was refused); the subset {X2}
    // reproduces the majority's commitments exactly.
    {
        D2Rig R;
        auto cA = cfg_of("d2-fc31d-A"), cB = cfg_of("d2-fc31d-B");
        Node& A = R.add("A", false, 'A', cA, opts_of(cA, false));
        Node& B = R.add("B", true, 'B', cB, opts_of(cB, true));
        if (!R.boot(A) || !R.boot(B)) { rep.add("FC31d boot", false, A.boot_error + B.boot_error); return; }
        for (std::uint64_t h = 1; h <= 22; ++h) {
            if (h >= 5) {
                if (h == 8) { R.mine(8, 'A', &A); A.fc->mark_isolated_own(X, 8, "test: parked, no relay peer"); }
                else if (h == 9) R.mine(9, 'A', &A, false, /*stall=*/true);
                else if (h == 11) R.mine(11, 'A', &A);
                else R.mine(h, (h % 2) ? 'B' : 'C', &B);
            }
            R.apply(h);
        }
        const std::string X2 = hex_of(D2Rig::id(9));
        rep.add("FC31d the refuse set is neither R1 nor R2 (X1 isolated but credited by the majority, X2 unmarked but refused, W credited): the bounded own-subset search finds {X2} -- adopted only because it reproduces every run commitment; digests and FINALIZED sets equal",
                A.fc->stats().converged == 1 && marker_of(cA).candidate == "Rs" && marker_of(cA).forced == std::vector<std::string>{X2} &&
                A.node->ledger().owed_digest() == B.node->ledger().owed_digest() && D2Rig::same_settled(R, A, B) &&
                A.node->ledger().is_settled(X) && !A.node->ledger().is_settled(X2),
                "converged=" + std::to_string(A.fc->stats().converged) + " candidate=" + marker_of(cA).candidate + " forced=" +
                std::to_string(marker_of(cA).forced.size()));
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── FC32 / FC32b: a run nothing reproduces -> HALT (DIVERGED), then cleared ─
    for (int deep = 0; deep < 2; ++deep) {
        D2Rig R;
        auto cA = cfg_of(deep ? "d2-fc32b-A" : "d2-fc32-A");
        FinalizeConnectOptions oA = opts_of(cA, false);
        if (deep) oA.converge_max_depth = 2;
        Node& A = R.add("A", false, 'A', cA, oA);
        if (!R.boot(A)) { rep.add("FC32 boot", false, A.boot_error); return; }
        std::uint64_t events_before = 0; ::v37::bytes32 dg_before{};
        for (std::uint64_t h = 1; h <= 18; ++h) {
            if (h >= 5 && !(deep && h >= 10 && h <= 12)) {
                const bool forker = h >= 13 && h <= 15;   // a forker PAIR (two builder keys) committing roots no ledger holds
                R.mine(h, (h % 2) ? 'B' : 'C', &A, forker);
            }
            if (h == 13) { events_before = A.node->finalize_driver().event_seq(); dg_before = A.node->ledger().owed_digest(); }
            R.apply(h);
            if (h == 15) break;
        }
        const auto s15 = A.fc->stats();
        const std::string state15 = FinalizeConnect::converge_state_name(A.fc->converge_state());
        const bool halted = A.fc->converge_state() == FinalizeConnect::ConvergeState::Diverged && A.hook_on == 1;
        const bool untouched = !archived(cA) && marker_of(cA).phase == "-" && A.node->relineages() == 0 && s15.converged == 0;
        if (!deep) {
            for (std::uint64_t h = 16; h <= 18; ++h) { R.mine(h, (h % 2) ? 'B' : 'C', &A); R.apply(h); }
            rep.add("FC32 3 unmatched foreign blocks from 2 builders whose roots NO candidate refuse set reproduces (R0 reproduced 0/3) -> DIVERGED (halt): hook on, nothing mutated (no archive, no marker, no relineage), booking continued",
                    halted && untouched && s15.diverged_halts == 1 && s15.converge_failed >= 1 && A.scratch_calls > 0 &&
                    A.node->finalize_driver().event_seq() >= events_before,
                    "state@15=" + state15 + " halts=" +
                    std::to_string(s15.diverged_halts) + " failed=" + std::to_string(s15.converge_failed) + " scratch_calls=" + std::to_string(A.scratch_calls));
            rep.add("FC32c then 3 MATCHED foreign blocks from 2 builders -> DIVERGED CLEARED (the majority is demonstrably on this lineage): hook off, state CONVERGED, still no mutation",
                    A.fc->converge_state() == FinalizeConnect::ConvergeState::Converged && A.hook_off == 1 &&
                    A.fc->stats().diverged_cleared == 1 && A.node->relineages() == 0 && !archived(cA),
                    "state=" + std::string(FinalizeConnect::converge_state_name(A.fc->converge_state())) + " cleared=" + std::to_string(A.fc->stats().diverged_cleared));
        } else {
            rep.add("FC32b a fork point deeper than the bound (F from h=9's commitment, 4 heights below the run's builder cut; bound 2) -> DIVERGED WITHOUT a re-derivation (no scratch decode), nothing mutated (W6 territory)",
                    halted && untouched && A.scratch_calls == 0 && s15.converge_failed == 1,
                    "state=" + std::string(FinalizeConnect::converge_state_name(A.fc->converge_state())) + " scratch_calls=" + std::to_string(A.scratch_calls));
        }
        (void)dg_before;
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── FC34: restarts during and after the convergence ─────────────────────
    for (int variant = 0; variant < 3; ++variant) {   // 0: crash after 'proposed', 1: after 'applied', 2: restart after 'done'
        D2Rig R;
        const std::string sfx = variant == 0 ? "a" : variant == 1 ? "b" : "c";
        auto cA = cfg_of("d2-fc34" + sfx + "-A"), cB = cfg_of("d2-fc34" + sfx + "-B");
        FinalizeConnectOptions oA = opts_of(cA, false);
        oA.converge_crash_after = variant < 2 ? variant + 1 : 0;
        Node& A = R.add("A", false, 'A', cA, oA);
        Node& B = R.add("B", true, 'B', cB, opts_of(cB, true));
        if (!R.boot(A) || !R.boot(B)) { rep.add("FC34 boot", false, A.boot_error + B.boot_error); return; }
        layout(R, A, B, true, true, 1, 16);
        const std::string phase_at_crash = marker_of(cA).phase;
        const auto hist_before = A.node->boot_digest_history();
        const auto dg_before = A.node->ledger().owed_digest();
        R.shutdown(A, /*drain=*/variant == 2);
        A.base_opts.converge_crash_after = 0;
        A.hook_on = A.hook_off = 0;
        if (!R.boot(A)) { rep.add("FC34 reboot", false, A.boot_error); return; }
        const auto sb = A.fc->stats();
        const auto dg_boot = A.node->ledger().owed_digest();
        const bool eq_boot = dg_boot == B.node->ledger().owed_digest();
        std::vector<::v37::bytes32> b_ring; std::vector<std::uint64_t> b_since;
        for (const auto& e : B.ring.entries()) { b_ring.push_back(e.digest); b_since.push_back(e.since); }
        for (std::uint64_t h = 17; h <= 20; ++h) layout(R, A, B, true, true, h, h);
        const bool eq_end = A.node->ledger().owed_digest() == B.node->ledger().owed_digest() && D2Rig::same_settled(R, A, B);
        if (variant == 0)
            rep.add("FC34a crash right after the 'proposed' marker (old store): the boot DROPS the marker (nothing was mutated), the restored observations re-detect, the next tick converges: digest == the majority's, FINALIZED sets equal",
                    phase_at_crash == "proposed" && sb.converge_boot_dropped == 1 && !eq_boot && A.fc->stats().converged == 1 && eq_end &&
                    A.fc->stats().late_unbooked == 0,
                    "phase=" + phase_at_crash + " dropped=" + std::to_string(sb.converge_boot_dropped) + " converged=" + std::to_string(A.fc->stats().converged));
        else if (variant == 1)
            rep.add("FC34b crash right after the store rewrite ('applied'): the boot replays the REWRITTEN store and finishes the adoption from the marker: digest == the majority's straight out of the boot, boot_digest_history() (digest, since) == the majority's lived sequence, liability identical, no re-detection",
                    phase_at_crash == "applied" && sb.converge_boot_finished == 1 && eq_boot && eq_end &&
                    A.node->boot_digest_history() == b_ring && A.node->boot_digest_since() == b_since && D2Rig::same_liability(A, B) &&
                    A.fc->stats().minority_runs_detected == 0 && marker_of(cA).phase == "done",
                    "phase=" + phase_at_crash + " finished=" + std::to_string(sb.converge_boot_finished) + " eq_boot=" + std::to_string(eq_boot) +
                    " hist=" + std::to_string(A.node->boot_digest_history().size()) + "/" + std::to_string(b_ring.size()));
        else
            rep.add("FC34c restart AFTER the adoption ('done'): the F1 replay is identical (same digest, same boot history as before the restart), the pending set is re-driven, no re-detection; the chain then runs on with digests equal and late_unbooked = 0",
                    phase_at_crash == "done" && A.node->boot_digest_history() == hist_before && eq_boot && dg_before == dg_boot &&
                    A.fc->stats().minority_runs_detected == 0 && A.fc->converge_state() == FinalizeConnect::ConvergeState::Converged &&
                    A.fc->pending().size() == B.fc->pending().size() && eq_end && A.fc->stats().late_unbooked == 0,
                    "phase=" + phase_at_crash + " pending A/B=" + std::to_string(A.fc->pending().size()) + "/" + std::to_string(B.fc->pending().size()) +
                    " hist=" + std::to_string(A.node->boot_digest_history() == hist_before) + " eq_boot=" + std::to_string(eq_boot) +
                    " dg=" + std::to_string(dg_before == dg_boot) + " det=" + std::to_string(A.fc->stats().minority_runs_detected) +
                    " state=" + FinalizeConnect::converge_state_name(A.fc->converge_state()) + " eq_end=" + std::to_string(eq_end) +
                    " late=" + std::to_string(A.fc->stats().late_unbooked));
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── FC35: --minority-converge halt-only ─────────────────────────────────
    {
        D2Rig R;
        auto cA = cfg_of("d2-fc35-A"), cB = cfg_of("d2-fc35-B");
        FinalizeConnectOptions oA = opts_of(cA, false);
        oA.minority_mode = FinalizeConnectOptions::MinorityMode::HaltOnly;
        Node& A = R.add("A", false, 'A', cA, oA);
        Node& B = R.add("B", true, 'B', cB, opts_of(cB, true));
        if (!R.boot(A) || !R.boot(B)) { rep.add("FC35 boot", false, A.boot_error + B.boot_error); return; }
        layout(R, A, B, true, true, 1, 20);
        const auto& s = A.fc->stats();
        rep.add("FC35 --minority-converge halt-only: the same detection -> DIVERGED (halt, hook on), NEVER adopts (no attempt, no archive, no marker, the ledger keeps its own lineage)",
                s.minority_runs_detected == 1 && A.fc->converge_state() == FinalizeConnect::ConvergeState::Diverged && A.hook_on == 1 &&
                s.converge_attempts == 0 && s.converged == 0 && !archived(cA) && marker_of(cA).phase == "-" && A.node->ledger().is_settled(X),
                "state=" + std::string(FinalizeConnect::converge_state_name(A.fc->converge_state())) + " attempts=" + std::to_string(s.converge_attempts));
        for (auto& n : R.nodes) R.shutdown(n);
    }
}

} // namespace c2pool::v37n::xmr::o2
