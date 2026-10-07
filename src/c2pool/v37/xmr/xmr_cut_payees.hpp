// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// REJOIN-PAYEE: resolve a lane coinbase's outputs against the payees of ITS OWN
// on-chain credit cut before refusing it.
//
// decode_lane_coinbase() maps every output to a payee identity by deriving the
// one-time key for each identity the CALLER knows (owed ledger keys + the
// payee resolver's learned refs) and fails closed on an output none of them
// derives. The resolver learns a payee's ScriptRef only when THIS node pushes
// that payee's receipt into its own lane (live ingest or the durable reload).
// SAME-BLOCK PAY-NOW pays a block's miners out of that block's E_b: its outputs
// pay the projected payees of the view at the block's on-chain credit cut --
// consensus data every node folds identically -- whether or not this node has
// pushed their receipts yet. A node that joins late or restarts after a
// downtime folds those views by relay repair / replay (scratch engines) that
// never taught its resolver the refs, so it REFUSED canonical lane blocks of
// its downtime ("output N maps to no known payee") and booked them as a
// NODE-LOCAL liability while every other node booked them.
//
// The rule here: an output-unmapped lane block whose credit cut is readable is
// resolved against the payees projected from the view at THAT cut:
//   * view not available yet (lane behind P / relay repair in flight): the
//     block is UNDECIDED -> the caller answers cut-pending (retried, HELD past
//     the bound like every relay repair), never refused on a timing accident;
//   * view available: every XMR payee it projects is learned, the coinbase is
//     decoded again; an output that still maps to nobody is a genuine unknown
//     payee and stays fail-closed (refused, liability) exactly as before;
//   * the cut does not reproduce (a decided mismatch): refused as before.
// Learning a ref can only make an output MAPPABLE when the derived one-time
// key equals the on-chain key (derive_output is the proof), so no output is
// ever attributed to a payee that was not paid; the payee set comes from the
// on-chain cut, so every node resolves the same outputs.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "xmr_coinbase_authority.hpp"
#include <c2pool/v37/w4_settlement.hpp>   // settle::WeightedPayee (the projected payees at a cut)

namespace c2pool::v37n::xmr::authority {

enum class CutPayeeStatus {
    NotNeeded,   // decoded (or not an output-unmapped lane block): nothing to resolve
    Learned,     // the cut's payees taught >= 1 new ref; the returned booking is the re-decode
    Pending,     // the view at the cut is not available here yet: UNDECIDED (caller: cut-pending)
    Refused,     // the cut resolves nothing new / does not reproduce: the fail-closed booking stands
};

inline const char* to_string(CutPayeeStatus s) {
    switch (s) {
        case CutPayeeStatus::NotNeeded: return "not-needed";
        case CutPayeeStatus::Learned:   return "learned";
        case CutPayeeStatus::Pending:   return "pending";
        case CutPayeeStatus::Refused:   return "refused";
    }
    return "?";
}

struct CutPayeeResult {
    CutPayeeStatus status = CutPayeeStatus::NotNeeded;
    std::size_t    projected = 0;   // payees the view at the cut projects
    std::size_t    learned = 0;     // of them, refs this call taught the resolver
    std::string    why;             // Pending: the view source's reason (starts "cut-pending:"); Refused: its reason
};

// decode()                                   -> CoinbaseBooking   (decodes with the resolver's CURRENT refs)
// payees_at(cut, out, why)                   -> int  1 = view read (out = its projected payees),
//                                                    0 = not available yet (why = "cut-pending: ..."),
//                                                   -1 = decided: the cut does not reproduce here (why)
// learn(ScriptRef)                           -> bool (true = a ref the resolver did not hold)
template <class Decode, class PayeesAt, class Learn>
inline CoinbaseBooking decode_resolving_cut_payees(Decode&& decode, PayeesAt&& payees_at, Learn&& learn,
                                                   CutPayeeResult* res = nullptr) {
    CutPayeeResult local;
    CutPayeeResult& r = res ? *res : local;
    r = CutPayeeResult{};
    CoinbaseBooking bk = decode();
    if (bk.ok || !bk.is_lane || !bk.payout_partial || !bk.has_credit_cut) return bk;
    std::vector<::c2pool::v37n::settle::WeightedPayee> ps;
    std::string w;
    const int got = payees_at(bk.credit_cut, ps, w);
    r.projected = ps.size();
    if (got == 0) { r.status = CutPayeeStatus::Pending; r.why = std::move(w); return bk; }
    if (got < 0)  { r.status = CutPayeeStatus::Refused; r.why = std::move(w); return bk; }
    for (const auto& p : ps)
        if (::v37::xmr::is_xmr_kind(p.pay.kind) && learn(p.pay)) ++r.learned;
    if (r.learned == 0) {
        r.status = CutPayeeStatus::Refused;
        r.why = "the view at the on-chain credit cut projects no payee this node did not already resolve";
        return bk;
    }
    r.status = CutPayeeStatus::Learned;
    return decode();
}

} // namespace c2pool::v37n::xmr::authority
