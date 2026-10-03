// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_cut_admission.hpp
//
// RULES RATCHET R1, RECEIPT ADMISSION -- F3, THE EMPTY-CUT RULE (operator
// ruling 2026-10-03; lane rule `empty_cut`, OwedLedgerRules::empty_cut).
//
// Under the anchor rule a canonical lane block's money never reads its own
// credit cut: credit and the recompute read the ANCHOR. The block's own cut
// (P, spine) matters for one thing: it becomes the ledger's anchor when the
// block finalizes (w4_settlement.hpp). This header decides that one field.
//
//   VALID      the view at the cut is reproducible here from receipts this
//              node admitted (verdict 1): book as before, cut = (P, spine).
//   EMPTY-CUT  the cut is DECIDED bad: the winner-side order that reaches the
//              committed spine carries a receipt this node refused under the
//              committed receipt test (xmr_share_verdict.hpp), and no ready
//              peer serves an order for that spine without one. The block's
//              money is booked exactly as decided (canonical, debit-only or
//              O-2 as before) with NO cut: its FINALIZE leaves the anchor where
//              it is. No DROPS deposit, window or enrolment is composed from
//              that cut, the CUT-FLOOR is not raised, and the DROPS harvest
//              range of the next decided lane block reaches back over it.
//   PENDING    not decided yet (data still arriving, or withheld): HELD, as
//              before. A cut whose order no connected peer serves is counted as
//              `withheld` (FinalizeConnect withheld_cut_held): undecided, never
//              refused on a timeout.
//
// WHAT THE SPINE BINDS. The lane digest at P folds the per-miner accumulators
// (identity keys and weights), not receipt ids: a served order is
// authenticated in its payee/weight sequence. Hence:
//   * an order that breaks the order rule or repeats an id only sets its
//     serving peer aside (pending), never decides the cut;
//   * a served order with a refused receipt sets its peer aside first; the cut
//     is decided bad only once every ready peer was asked and none served an
//     order for the spine without a refused receipt.
// A cut-level commitment of the receipt ids (the v37.1 set digest) is what
// would bind the ids themselves.
//
// Pure functions only; main_v37_xmr.cpp wires them (relay_view, own_cut_decide)
// and the KATs drive them directly.
// ===========================================================================
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>   // settle::AnchorCut
#include "xmr_credit_cut.hpp"     // credit::CreditCut

namespace c2pool::v37n::xmr::cutadm {

#define C2POOL_XMR_EMPTY_CUT 1

// A decided-bad own cut reports this prefix (never "cut-pending:").
inline constexpr const char* kCutBadPrefix = "cut-bad:";
// The undecided reason of a cut whose winner-side order no connected peer
// serves carries this marker (class 3: withheld; still "cut-pending:").
inline constexpr const char* kWithheldMarker = "withheld:";

inline bool is_cut_bad(const std::string& why) { return why.rfind(kCutBadPrefix, 0) == 0; }
inline bool is_pending(const std::string& why) { return why.rfind("cut-pending:", 0) == 0; }
inline bool is_withheld(const std::string& why) { return is_pending(why) && why.find(kWithheldMarker) != std::string::npos; }

// ── the served order ─────────────────────────────────────────────────────────
// One served receipt as this node sees it: admitted (verified cache), refused
// (the relay's refused memo: decided under the committed test), or missing
// (not here yet: in verify, parked, or never served).
enum class Served : std::uint8_t { Admitted, Refused, Missing };
enum class OrderVerdict : std::uint8_t { Valid, Bad, Pending };

struct OrderInput {
    std::vector<Served> receipts;   // the served positions [a0, P)
    bool spine_reproduced = false;  // the replay of [0, a0) + the served pushes reached the committed spine
    bool every_peer_tried = false;  // the repair asked every ready peer (Exhausted) since this variant
};

// Valid: every served receipt admitted and the spine reproduced. Bad: the
// spine reproduced, a served receipt refused, every ready peer tried. Pending
// otherwise (a missing receipt, a spine not reproduced -- the serving peer is
// set aside --, or a refused variant while other peers are still to be asked).
inline OrderVerdict classify_served_order(const OrderInput& in, std::string* why = nullptr) {
    std::size_t refused = 0, missing = 0;
    for (const auto s : in.receipts) {
        if (s == Served::Refused) ++refused;
        else if (s == Served::Missing) ++missing;
    }
    if (missing) {
        if (why) *why = std::to_string(missing) + " served receipt(s) not here yet";
        return OrderVerdict::Pending;
    }
    if (!in.spine_reproduced) {
        if (why) *why = "the served order does not reproduce the committed spine (serving peer set aside)";
        return OrderVerdict::Pending;
    }
    if (!refused) return OrderVerdict::Valid;
    if (!in.every_peer_tried) {
        if (why) *why = std::to_string(refused) + " served receipt(s) refused here; asking the other ready peers for the same spine";
        return OrderVerdict::Pending;
    }
    if (why) *why = std::to_string(refused) + " of " + std::to_string(in.receipts.size()) +
                    " served receipt(s) refused under the committed receipt test, and no ready peer serves the spine without them";
    return OrderVerdict::Bad;
}

// ── the own cut of a booking ─────────────────────────────────────────────────
enum class OwnCut : std::uint8_t { Valid, EmptyCut, Pending, Refused };

inline const char* to_string(OwnCut c) {
    switch (c) {
        case OwnCut::Valid:    return "valid";
        case OwnCut::EmptyCut: return "empty-cut";
        case OwnCut::Pending:  return "pending";
        case OwnCut::Refused:  return "refused";
    }
    return "?";
}

// The decision from the view lookup at the block's own cut: `view_ok` = the
// view at (P, spine) is reproducible here; otherwise `why` says why not.
// anchor rule off: Valid (the cut is not an anchor). empty_cut off: a bad cut
// is pending (the pre-R1 HOLD).
inline OwnCut classify_own_cut(bool anchor_cut, bool empty_cut, bool view_ok, const std::string& why) {
    if (!anchor_cut || view_ok) return OwnCut::Valid;
    if (is_cut_bad(why)) return empty_cut ? OwnCut::EmptyCut : OwnCut::Pending;
    if (is_pending(why)) return OwnCut::Pending;
    return OwnCut::Refused;
}

// The cut the booking passes (ChainBooking::cut): the block's own on-chain cut
// when VALID under the anchor rule, none for EMPTY-CUT (the anchor stays).
inline std::optional<::c2pool::v37n::settle::AnchorCut> booking_cut(OwnCut c, bool anchor_cut,
                                                                     const ::c2pool::v37n::xmr::credit::CreditCut& cc) {
    if (!anchor_cut || c != OwnCut::Valid) return std::nullopt;
    ::c2pool::v37n::settle::AnchorCut a;
    a.next_pos = cc.next_pos;
    a.spine = cc.spine_digest;
    return a;
}

}  // namespace c2pool::v37n::xmr::cutadm
