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
//   PENDING    not decided yet: HELD, as before. That includes data still
//              arriving, an order no connected peer serves (counted as
//              `withheld`, FinalizeConnect withheld_cut_held), and -- after the
//              review of 2026-10-04 -- a served order that reaches the spine but
//              carries a receipt this node refused: its serving peer is set
//              aside and the cut stays HELD. Never a ban, never a strike.
//   EMPTY-CUT  RESERVED. The booking branch (money as decided, NO cut, the
//              anchor stays, no DROPS composed, CUT-FLOOR not raised) is kept,
//              but nothing reaches it: a cut is never decided bad from what a
//              peer served (below). Lane-rules field 30 stays present for the
//              rule that will let a later lane block attest the previous
//              block's cut (a committed receipt-id digest, or none).
//
// WHY A SERVED ORDER NEVER DECIDES A CUT. The lane digest at P folds the
// per-miner accumulators (identity keys and weights), not receipt ids: a served
// order is authenticated only in its payee/weight sequence, so another receipt
// of the same payee and weight can stand in for an honest one and still reach
// the spine, and which peers hold the order at a given moment is node-local.
// So an order that breaks the order rule, repeats an id, or carries a receipt
// refused here only sets its serving peer aside; the cut stays HELD until an
// order of admitted receipts reproduces the spine. A cut-level commitment of
// the receipt ids (the v37.1 set digest, or the cut attestation above) is what
// would make "this cut holds a refused receipt" a property of the chain.

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
// review 2026-10-04 (D1/D2): a refused receipt in a served order sets its peer
// aside and keeps the cut HELD; no served order is ever decided bad.
#define C2POOL_XMR_CUT_HELD_ON_REFUSED 1

// A decided-bad own cut would report this prefix (never "cut-pending:").
// RESERVED: no caller produces it (a served order never decides a cut).
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
enum class OrderVerdict : std::uint8_t { Valid, Bad, Pending };   // Bad: RESERVED, never returned

struct OrderInput {
    std::vector<Served> receipts;   // the served positions [a0, P)
    bool spine_reproduced = false;  // the replay of [0, a0) + the served pushes reached the committed spine
    bool every_peer_tried = false;  // the repair asked every ready peer (Exhausted); does not decide anything
};

// Valid: every served receipt admitted and the spine reproduced. Pending
// otherwise: a missing receipt, a spine not reproduced, or a served receipt
// refused here -- in the last two cases the serving peer is set aside and the
// cut stays HELD, whatever the other peers answered (`every_peer_tried` is
// informational only). Never Bad: the spine does not bind receipt ids.
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
    if (why) *why = std::to_string(refused) + " of " + std::to_string(in.receipts.size()) +
                    " served receipt(s) refused here: the serving peer is set aside and the cut stays HELD" +
                    (in.every_peer_tried ? " (every ready peer tried; asked again on the next round)" : " (asking the other ready peers)");
    return OrderVerdict::Pending;
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
