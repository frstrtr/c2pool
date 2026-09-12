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
// THE PAYOUT LEG (stated, not hidden). On the DASH side `payout` is the W5
// native coinbase the block actually broadcast, which the burial gate WITHHOLDS
// at depth 0 — so a fresh win's payout map is empty by construction. On Monero
// the same depth-0 fact holds for a different reason: the option-A coinbase
// pays monerod's own --payout-address (never a v37 ledger key), and the
// option-B K_fair coinbase is assembled BEFORE the block is buried. Either way
// a freshly found XMR block broadcasts NO settled-owed output keyed to a lane
// identity, so the payout leg is EMPTY and the whole entitlement carries
// forward as owed. That carry is exactly what owed_digest commits to.
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
};

// Receive-side counters (diagnostics only — never consensus).
struct XmrS1PeerStats {
    std::uint64_t seen          = 0;   // peer block-winner descriptors offered
    std::uint64_t credited      = 0;   // folded at the carried cut and REGISTERED
    std::uint64_t valueless     = 0;   // registered with an EMPTY credit
    std::uint64_t cut_miss      = 0;   // P not published here (ring evicted / coalesced through)
    std::uint64_t cut_mismatch  = 0;   // P published here with a DIFFERENT lane digest (!)
    std::uint64_t refused_fold  = 0;   // fold_eb REFUSED (geometry not ratified)
    std::uint64_t refused_payout = 0;  // winner had already emitted an owed coinbase
    std::uint64_t refused_late  = 0;   // H_b at or below our finalize cursor
    std::uint64_t already_known = 0;   // our own win, or a duplicate
    std::uint64_t owed_diverged = 0;   // owed_digest_at_win != ours at receipt
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
                                           bool strict = true) {
    XmrPeerFoldOutcome out;
    out.cut.reward = w.reward;

    bool mismatch = false;
    std::shared_ptr<const SettlementView> view =
        engine.settlement_view_by_cut(chain, w.cut_next_pos, w.cut_spine_digest, &mismatch);
    if (!view) {
        out.cut_miss = !mismatch;
        out.cut_digest_mismatch = mismatch;
        if (mismatch) {
            ++st.cut_mismatch;
            out.cut.refusal =
                "REFUSED: we published the winner's prefix P=" +
                std::to_string(w.cut_next_pos) + " with a DIFFERENT lane digest — the two "
                "nodes folded different records into the same prefix. This is a SHARECHAIN "
                "divergence, not a settlement one; the owed ledger cannot repair it";
        } else {
            ++st.cut_miss;
            out.cut.refusal =
                "REFUSED: the winner's prefix P=" + std::to_string(w.cut_next_pos) +
                " is not a version THIS node published (older than the settlement ring, or "
                "the executor coalesced through it) — we will not fold at a neighbouring "
                "prefix (O2.3)";
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
                    " unresolved=" + std::to_string(c.unresolved) + "}";
    if (!c.refusal.empty()) s += " — " + c.refusal;
    return s;
}

} // namespace c2pool::v37n::xmr::o2
