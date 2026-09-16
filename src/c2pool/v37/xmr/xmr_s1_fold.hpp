// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_s1_fold.hpp   (S-1b — the Monero-family E_b fold)
//
// THE DEFECT THIS CLOSES. xmr_o2_finalize_connect.hpp registered every XMR
// block win with
//
//     credit == payout == { payee : reward }
//
// so FINALIZE did finalW += credit; finalW -= payout and netted EXACTLY to
// zero. m_finalW therefore never gained a row, OwedLedger::owed_digest() never
// left the empty sha256d("V37O") anchor b4db1ded…, and the option-B coinbase's
// tx_extra 0x03 merge-mining leaf — which serialises that very digest — was a
// constant. A pool that has mined blocks and owes its miners nothing is not an
// accounting model; it is an accounting hole.
//
// THE FIX, AND WHAT IT IS NOT. E_b is folded out of the lane cut the engine has
// published, through settle::fold_eb — the ONE credit-path entry point (W4 S8),
// the SAME function XbtcNode::on_block_won calls on the merged DASH side. This
// header is a second CALLER of that fold, never a second fold: no arithmetic
// from w4_settlement.hpp is restated here, src/sharechain/v37 is untouched, and
// the owed_digest() body is not read except through the ledger's own accessor.
//
// THE TWO ARMS, AND WHY THEY ARE THE SAME CODE
//   fold_at_tip()      our OWN win. Folds at the lane snapshot published RIGHT
//                      NOW and records the cut witness (P, the lane digest at
//                      P, the reward consumed) so the win can NAME its fold to
//                      peers on the carrier wire (w3_relay.hpp CutDescriptor,
//                      wire v0x02).
//   fold_at_peer_cut() a PEER's win, as that descriptor delivers it. THE CUT
//                      RULE: fold at the WINNER'S prefix read back out of OUR
//                      own ring (V37Engine::settlement_view_by_cut), never at
//                      our own tip — our tip already includes the block-winning
//                      carrier we just admitted, so folding there would credit
//                      a DIFFERENT E_b and the two nodes would commit to
//                      different owed ledgers while both looked healthy.
//
// REFUSE LOUD. Every failure — no published lane view, a non-ratified geometry,
// reward == 0, an EMPTY E_b, a prefix this node never published, a prefix
// published here under a DIFFERENT commitment — is stamped, counted and
// narrated. An own win is still REGISTERED after a refusal (a block we mined is
// a real block and its record must exist); a PEER's win is REFUSED outright,
// because crediting a peer's block with a number we invented is precisely the
// divergence the cut rule exists to prevent.
//
// THE PAYOUT LEG — AND THE CLAIM THAT WAS WRONG ABOUT IT. On the DASH side
// `payout` is the W5 native coinbase the block actually broadcast, which the
// burial gate WITHHOLDS at depth 0, so a fresh win's payout map is empty by
// construction. This header used to assert the same of Monero "either way",
// reasoning that option A pays monerod's own --payout-address (never a v37
// ledger key) and that option B's K_fair coinbase is assembled BEFORE the block
// is buried.
//
// Half of that is true and half of it is the reverse of the truth. Option A
// really does settle nothing. Option B's coinbase is not burial-gated at all —
// it is the K_fair SETTLEMENT coinbase, and paying owed balances is the entire
// reason it exists. Registering such a win with an empty payout leg leaves
// every balance it just paid still owed, so the NEXT template proposes them
// again: a double-pay. It also drives owed up by a whole E_b per block until
// owed >= budget, at which point K_fair takes the whole reward, the mandated
// residual sink disappears from the coinbase, the §13 shape gate refuses every
// template, and the miners are parked on a stale height while the chain moves
// on and the daemon books duplicate FOUNDs. That is the option-B deadlock.
//
// So the leg is per-coinbase, not per-family, and it is booked at the FOUND
// site (xmr_o2_finalize_connect.hpp) from the owed-role outputs of the very
// template the block was mined on — the R-7 pattern the merged DASH side uses,
// where `payout` is what the block ACTUALLY BROADCAST to ledger keys and
// `credit` stays E_b. The fixed outputs and the residual sink are excluded:
// neither is ever credited to a ledger key, so neither may be deducted from
// one. What the coinbase did NOT cover carries forward as owed, and that carry
// is what owed_digest commits to.
//
// SCOPE FENCE: consumer tree, header-only, STL only. No consensus digest is
// defined here; no fold body, no settle_block arithmetic, no ledger internals.
// ===========================================================================
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include <c2pool/v37/v37_engine.hpp>        // V37Engine, SettlementView
#include <c2pool/v37/w4_settlement.hpp>     // settle::fold_eb, OwedLedger, Amounts
#include <sharechain/v37/v37_hash.hpp>      // ::v37::bytes32
#include <sharechain/v37/v37_roundabout.hpp>

#include "xmr_cut_projector.hpp"            // ★ R-A: project the view at a peer's P

namespace c2pool::v37n::xmr::o2 {

namespace settle = ::c2pool::v37n::settle;

// Lowercase hex of any 32-byte array (bytes32 / Hash alike). Local so this
// header pulls in nothing for one format call.
inline std::string s1_hex32(const std::array<std::uint8_t, 32>& d) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : d) { s.push_back(k[b >> 4]); s.push_back(k[b & 0x0f]); }
    return s;
}

// ── the fold, and its witness ───────────────────────────────────────────────
// `credit` is E_b: what the pool now OWES its payees because of this block. It
// is NOT the coinbase. The consensus quantity here is `lane_digest` — the
// snapshot's canonical commitment at the prefix the fold read — because two
// nodes that fold at the same lane digest fold the same E_b, and that is the
// assertion cross-node convergence is made against.
struct XmrEbCut {
    settle::OwedLedger::Amounts credit;      // E_b, canonical-key keyed
    bool           folded    = false;        // fold_eb returned a value
    bool           valueless = false;        // folded, but worth nothing (see `refusal`)
    ::v37::bytes32 lane_digest{};            // the cut witness (the consensus commitment)
    std::uint64_t  lane_version = 0;         // per-lane monotone publication version (node-local)
    std::uint64_t  lane_incarnation = 0;     // node-monotone AddLane incarnation (F2/ABA)
    std::uint64_t  next_pos = 0;             // the prefix P the fold read at
    std::uint64_t  raw_total = 0;            // lane weight at P (diagnostics: is X2 alive?)
    std::size_t    unresolved = 0;           // OI-W4-1 broken-invariant counter
    const char*    source = "none";          // settle::eb_source_name()
    std::uint64_t  reward = 0;               // the reward THIS fold consumed
    // ★ R-A (c2pool#1625): this cut was read from the RECEIVE-SIDE PROJECTION
    // (xmr_cut_projector.hpp) rather than from the engine's own publication
    // ring, because the executor coalesced through the winner's prefix here.
    // The credit is identical either way — the projection is accepted ONLY at a
    // matching lane digest — but an auditor should be able to see which answer
    // served the fold, so it is stamped rather than inferred.
    bool           projected = false;
    std::string    refusal;                  // non-empty => the loud reason
};

// Own-win fold counters (diagnostics only — never consensus). A live node that
// registers wins with no credit is BROKEN, and these are how that is visible
// without reading a log.
struct XmrS1FoldStats {
    std::uint64_t folds      = 0;   // wins whose E_b fold produced a credit map
    std::uint64_t no_view    = 0;   // wins with no published lane snapshot
    std::uint64_t refused    = 0;   // fold_eb REFUSED (geometry not ratified)
    std::uint64_t valueless  = 0;   // registered with an EMPTY credit (reward 0 / empty lane)
    std::uint64_t unresolved = 0;   // total OI-W4-1 unresolved payout keys seen
};

// ── a PEER's block win, as the flat v0x02 cut descriptor delivers it ────────
struct XmrPeerWin {
    std::string    bid;                  // the OwedLedger key (64 lowercase hex)
    std::uint64_t  h_b = 0;              // the block's OWN height (D8)
    std::uint64_t  cut_next_pos = 0;     // P — the prefix the WINNER folded at
    ::v37::bytes32 cut_spine_digest{};   // the lane commitment at P
    std::uint64_t  reward = 0;           // the reward the winner's fold consumed
    bool           payout_emitted = false;      // winner's coinbase emitted owed outputs
    ::v37::bytes32 owed_digest_at_win{};        // VERIFY field (diagnostics only)
    // ★★ WIRE-CARRY (wire v0x03 section 2, c2pool#1625). The winner's OWN K_fair
    // owed-deduction map: {owed identity -> piconero its coinbase paid that
    // identity}, taken from the Owed-role outputs of the template it mined
    // (Fixed and residual-Sink outputs are not ledger keys and never enter it).
    // This REPLACES the peer-side recompute: the receiver folds what the winner
    // sent instead of re-deriving it from a ledger state it can only match by
    // luck, so there is no same-instant requirement left anywhere on this path.
    //
    // `payout_carried` is the presence bit, kept separate from `payout.empty()`
    // on purpose. An EMPTY carried map and NO carried map are different claims:
    // the first says "my coinbase settled nothing", the second says "I could not
    // tell you", and only the first may be folded. A pre-v0x03 winner, and a
    // v0x03 winner whose descriptor carried no section, both land here as false.
    bool payout_carried = false;
    settle::OwedLedger::Amounts payout;
    // v0x03 section 1 (c2pool#1627) rode the same frame. This build has no DROPS
    // ledger leg, so a set flag is a REFUSAL, never an ignored field: crediting
    // E_b while dropping a credit map the winner applied is the divergence both
    // sections exist to close.
    bool drops_carried = false;
};

// Receive-side counters (diagnostics only — never consensus).
struct XmrS1PeerStats {
    std::uint64_t seen          = 0;   // peer block-winner descriptors offered
    std::uint64_t credited      = 0;   // folded at the carried cut and REGISTERED
    std::uint64_t valueless     = 0;   // registered with an EMPTY credit
    std::uint64_t cut_miss      = 0;   // P not published here (ring evicted / coalesced through)
    std::uint64_t cut_mismatch  = 0;   // P published here with a DIFFERENT lane digest (!)
    std::uint64_t refused_fold  = 0;   // fold_eb REFUSED (geometry not ratified)
    std::uint64_t refused_payout = 0;  // winner emitted owed outputs we could NOT fold
    // ★★ WIRE-CARRY (c2pool#1625). A settling peer win — one whose option-B
    // coinbase actually paid owed balances — is no longer refused outright, and
    // is no longer RECOMPUTED either: the winner's own K_fair deduction map
    // rides the v0x03 trailer and is folded verbatim, so the peer deducts
    // exactly what the winner deducted with no same-instant requirement between
    // the two nodes. `payout_carried` counts the settling peer blocks REGISTERED
    // that way (once per block, at registration, never per retry);
    // `refused_payout` above counts only the ones that could NOT be folded,
    // which stay fail-closed. `payout_absent` is the fail-closed half: the
    // descriptor said the coinbase settled, but no section came with it (a
    // pre-v0x03 peer, or a winner that could not name its own map) — refused,
    // never guessed. `payout_shape` counts a carried map this node would not
    // fold (a row the ledger cannot key, or a total the frame's own reward
    // cannot cover).
    std::uint64_t payout_carried  = 0;
    std::uint64_t payout_absent   = 0;
    std::uint64_t payout_shape    = 0;
    // The non-authoritative LOCAL CROSS-CHECK, kept because it is now free
    // diagnostics rather than the mechanism: when the old K_fair recompute is
    // armed AND produced a map for this height, does it agree with the one the
    // winner sent? Disagreement is REPORTED and never refuses — the whole point
    // of the switch is that the recompute's agreement is not required.
    std::uint64_t xcheck_agree    = 0;
    std::uint64_t xcheck_differ   = 0;
    std::uint64_t xcheck_absent   = 0;
    // ★ R-A (c2pool#1625). The engine publishes ONE SettlementView per coalesced
    // executor burst, so the exact prefix a winner names is frequently never
    // published here — which the receive seam used to read as a permanent
    // cut_miss and a permanent refusal. The prefix is still WELL-DEFINED (a
    // snapshot's content is a pure function of the committed record prefix), so
    // it is PROJECTED on demand from the retained record log and accepted ONLY
    // at a matching lane digest. `cut_projected` counts the folds the projection
    // served; `cut_project_miss` the asks it could not answer (the records have
    // not arrived yet, or the log no longer reaches back that far) — those fall
    // through to the ordinary cut_miss retry and refusal, unchanged;
    // `cut_project_mismatch` is the projection reaching P and committing to a
    // DIFFERENT digest, which is a sharechain divergence and is refused like the
    // ring's own mismatch.
    std::uint64_t cut_projected       = 0;
    std::uint64_t cut_project_miss    = 0;
    std::uint64_t cut_project_mismatch = 0;
    std::uint64_t refused_late  = 0;   // H_b at or below our finalize cursor
    std::uint64_t already_known = 0;   // our own win, or a duplicate
    // The VERIFY field, and what it is NOT. owed_digest_at_win is the winner's
    // §4.5 commitment at the instant of ITS win; ours is read at RECEIPT, which
    // is a strictly LATER instant — a receiver learns of H_b from the chain a
    // poll away while the descriptor is a poll plus a relay hop away, so its
    // finalize cursor has routinely stepped a bin the winner had not. A skew
    // here is therefore NORMAL on a live rig and is not by itself a divergence.
    // The SAME-INSTANT comparison is the K_fair recompute's, which pins our
    // owed_digest AT OUR BUILD of that height against this very field
    // (xmr_peer_payout_recompute.hpp); a real divergence surfaces there as
    // refused[payout], and in the per-cursor owed_digest an auditor diffs.
    std::uint64_t owed_skew = 0;       // owed_digest_at_win != ours at receipt
};

// Why a peer fold was refused, each its own bit so an operator never guesses.
struct XmrPeerFoldOutcome {
    XmrEbCut cut;
    bool ok = false;                     // the fold ran and the credit may be registered
    bool cut_miss = false;               // P is not a prefix THIS node published
    bool cut_digest_mismatch = false;    // P published here with a DIFFERENT digest
};

// ═══════════════════════════════════════════════════════════════════════════
// fold_at_tip — our OWN win.
//
// `engine` may be mid-publication; a nullptr snapshot is the honest "we have
// nothing to fold over yet" and is counted, never guessed around. strict ==
// true is the production setting: a HARD refusal is never retried.
// ═══════════════════════════════════════════════════════════════════════════
inline XmrEbCut fold_at_tip(V37Engine& engine, ::v37::ChainId chain,
                            std::uint64_t reward, XmrS1FoldStats& st,
                            bool strict = true) {
    XmrEbCut c;
    c.reward = reward;

    std::shared_ptr<const ::v37::LaneSnapshot> view = engine.snapshot(chain);
    if (!view) {
        ++st.no_view;
        c.valueless = true;
        c.refusal = "no lane snapshot published for chain " +
                    std::to_string(static_cast<unsigned long long>(chain)) +
                    " — the engine has not published a version yet (AddLane not "
                    "committed, or the executor is still draining)";
        ++st.valueless;
        return c;
    }
    c.lane_digest      = view->digest;
    c.lane_version     = view->version;
    c.lane_incarnation = view->incarnation;
    c.raw_total        = static_cast<std::uint64_t>(view->raw_total);

    std::optional<settle::EbFold> f = settle::fold_eb(reward, *view, strict);
    if (!f) {
        ++st.refused;
        c.valueless = true;
        c.next_pos  = view->next_pos;
        c.refusal   = "fold_eb REFUSED: this lane's geometry is NOT ratified "
                      "(settle::geometry_is_ratified == false) — the settlement "
                      "boundary will not credit over it";
        ++st.valueless;
        return c;
    }
    c.folded     = true;
    c.next_pos   = f->next_pos;
    c.unresolved = f->unresolved;
    c.source     = settle::eb_source_name(f->source);
    for (const auto& [k, v] : f->credit) c.credit[k] = static_cast<long long>(v);
    st.unresolved += f->unresolved;

    if (reward == 0) {
        c.valueless = true;
        c.refusal   = "reward == 0 at H_b — the template/miner-data answered "
                      "fail-closed (cached template height != H_b?); the win is "
                      "registered VALUELESS and credits nobody";
    } else if (c.credit.empty()) {
        c.valueless = true;
        c.refusal   = "E_b is EMPTY at this cut — the lane has NO accounted weight "
                      "(raw_total=" + std::to_string(c.raw_total) +
                      "): no miner share reached the lane accumulator. Is the X2 "
                      "share-push wired and is the carrier relay up?";
    }
    if (c.valueless) ++st.valueless; else ++st.folds;
    return c;
}

// ═══════════════════════════════════════════════════════════════════════════
// fold_at_peer_cut — a PEER's win, at the WINNER'S prefix, out of OUR ring.
//
// Returns ok == false on every refusal shape; the caller must then NOT register
// the FOUND. Refusing is the honest failure: it leaves A != B visible and
// counted, where folding at a neighbouring prefix would hide a settlement fork
// behind a plausible number (O2.3).
// ═══════════════════════════════════════════════════════════════════════════
inline XmrPeerFoldOutcome fold_at_peer_cut(V37Engine& engine, ::v37::ChainId chain,
                                           const XmrPeerWin& w, XmrS1PeerStats& st,
                                           bool strict = true,
                                           XmrCutProjector* projector = nullptr) {
    XmrPeerFoldOutcome out;
    out.cut.reward = w.reward;

    bool mismatch = false;
    std::shared_ptr<const SettlementView> view =
        engine.settlement_view_by_cut(chain, w.cut_next_pos, w.cut_spine_digest, &mismatch);

    // ★ R-A: the ring said "never published here". That is NOT the same claim as
    // "the prefix does not exist": the engine publishes once per COALESCED burst
    // (v37_engine.hpp kCoalesceBurst), while a snapshot's content is a pure
    // function of the committed record prefix. So the view at P is projected on
    // demand from the record log, and — this is the whole safety case — it is
    // accepted ONLY when the projection's own lane digest equals the one the
    // winner committed to. A faithful replica therefore turns this refusal into
    // the correct credit; an unfaithful one cannot turn it into a WRONG credit,
    // it can only leave the refusal standing.
    //
    // A ring DIGEST MISMATCH is not routed here. It means this node published
    // that prefix under a different commitment, which is a sharechain divergence
    // the settlement layer must keep reporting loudly, not something to re-ask.
    std::string project_why;
    if (!view && !mismatch && projector) {
        bool pmis = false;
        view = projector->project(w.cut_next_pos, w.cut_spine_digest, &pmis, &project_why);
        if (view) {
            out.cut.projected = true;
            ++st.cut_projected;
        } else if (pmis) {
            mismatch = true;
            ++st.cut_project_mismatch;
        } else {
            ++st.cut_project_miss;
        }
    }

    if (!view) {
        out.cut_miss = !mismatch;
        out.cut_digest_mismatch = mismatch;
        if (mismatch) {
            ++st.cut_mismatch;
            out.cut.refusal =
                "REFUSED: the winner's prefix P=" + std::to_string(w.cut_next_pos) +
                " resolves here under a DIFFERENT lane digest — the two nodes folded "
                "different records into the same prefix. This is a SHARECHAIN divergence, "
                "not a settlement one; the owed ledger cannot repair it" +
                (project_why.empty() ? std::string() : " [" + project_why + "]");
        } else {
            ++st.cut_miss;
            out.cut.refusal =
                "REFUSED: the winner's prefix P=" + std::to_string(w.cut_next_pos) +
                " is neither a version THIS node published nor one the record log can be "
                "replayed to — we will not fold at a neighbouring prefix (O2.3)" +
                (project_why.empty() ? std::string() : " [" + project_why + "]");
        }
        return out;
    }

    out.cut.lane_digest      = view->digest;
    out.cut.lane_version     = view->version;       // OUR version number for that prefix
    out.cut.lane_incarnation = view->incarnation;   // OUR incarnation (never on the wire)
    out.cut.raw_total        = static_cast<std::uint64_t>(view->raw_total);

    std::optional<settle::EbFold> f = settle::fold_eb(w.reward, *view, strict);
    if (!f) {
        ++st.refused_fold;
        out.cut.valueless = true;
        out.cut.next_pos  = view->next_pos;
        out.cut.refusal   = "fold_eb REFUSED at the peer's cut: this lane's geometry is NOT "
                            "ratified (settle::geometry_is_ratified == false)";
        return out;
    }
    out.cut.folded     = true;
    out.cut.next_pos   = f->next_pos;
    out.cut.unresolved = f->unresolved;
    out.cut.source     = settle::eb_source_name(f->source);
    for (const auto& [k, v] : f->credit) out.cut.credit[k] = static_cast<long long>(v);

    if (w.reward == 0) {
        out.cut.valueless = true;
        out.cut.refusal = "the winner carried reward == 0 — it registered a VALUELESS win and "
                          "so do we (both nodes credit nobody, which still CONVERGES)";
    } else if (out.cut.credit.empty()) {
        out.cut.valueless = true;
        out.cut.refusal = "E_b is EMPTY at the carried cut — the lane had no accounted weight "
                          "at P (both nodes credit nobody, which still CONVERGES)";
    }
    out.ok = true;
    return out;
}

// One-line narration of a fold, for the daemon log and the KAT alike.
inline std::string describe_cut(const char* what, const std::string& bid,
                                std::uint64_t h, const XmrEbCut& c) {
    std::string s = std::string("[v37-xmr-s1] ") + what + " " +
                    (c.valueless ? "VALUELESS" : "credit") + " " +
                    (bid.size() > 12 ? bid.substr(0, 12) + "…" : bid) +
                    " h=" + std::to_string(h) +
                    " reward=" + std::to_string(c.reward) +
                    " E_b=" + std::to_string(c.credit.size()) + " keys" +
                    " cut{lane_digest=" + s1_hex32(c.lane_digest) +
                    " v=" + std::to_string(c.lane_version) +
                    " inc=" + std::to_string(c.lane_incarnation) +
                    " P=" + std::to_string(c.next_pos) +
                    " raw_total=" + std::to_string(c.raw_total) +
                    " src=" + c.source +
                    " unresolved=" + std::to_string(c.unresolved) + "}" +
                    (c.projected ? " [PROJECTED at P: the executor coalesced through this "
                                   "prefix here, so the view was replayed from the record "
                                   "log and accepted at a MATCHING lane digest]"
                                 : "");
    if (!c.refusal.empty()) s += " — " + c.refusal;
    return s;
}

} // namespace c2pool::v37n::xmr::o2
