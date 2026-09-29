// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_share_verdict.hpp
//
// SHARE-LEVEL CANONICAL COINBASE, the relay side (P2Pool's share rule: a share
// is a block candidate, so its coinbase must be the canonical one).
//
// Under the ANCHOR rule (OwedLedgerRules::anchor_cut, ruling A 2026-09-29)
// every input of a lane coinbase is finalized state: the ledger at the
// booking point and the view at its anchor. The main thread publishes, per
// ledger state (keyed by the 0x03 root that state commits), a frozen copy of
// the ledger, the payees at its anchor, the booked refs and the lane config
// (ShareStateStore). A relay verify worker then decides a receipt alone:
//
//    1  canonical                -> admit
//   -1  not the canonical coinbase (or no lane root / no V37R / a broken
//       opening)                 -> refuse
//    0  this node does not hold that state (yet), or the view at its anchor
//       is not readable yet      -> park; the relay decides what to do past
//                                   its patience (xmr_relay_node.hpp)
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "impl/xmr/receipt/xmr_receipt_verify.hpp"   // resume_prefix_hash, ParsedBlob
#include "xmr_relay_wire.hpp"                          // FbReceipt
#include "../xmr_coinbase_recompute.hpp"               // verify_share_coinbase, mm_root_of

namespace c2pool::v37n::xmr::relay {

struct ShareStateEntry {
    ::v37::bytes32 digest{};                        // owed_digest of the state
    ::v37::bytes32 root{};                          // mm_commitment_root(chain, digest): the receipt's 0x03 key
    std::shared_ptr<const ::c2pool::v37n::settle::OwedLedger> ledger;   // frozen, memo warmed
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;                     // booked refs (the owed pass's resolver)
    ::c2pool::v37n::xmr::recompute::LaneInputs lane;
    bool has_view = false;                          // the payees at the anchor are known
    bool view_ratified = false;                     // ... and its geometry is ratified
    std::vector<::c2pool::v37n::settle::WeightedPayee> payees;
};

struct ShareStateStore {
    std::mutex mu;
    std::deque<std::shared_ptr<const ShareStateEntry>> ring;   // newest last, bounded by the publisher
    std::shared_ptr<const ShareStateEntry> find_root(const ::v37::bytes32& root) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto it = ring.rbegin(); it != ring.rend(); ++it)
            if ((*it)->root == root) return *it;
        return nullptr;
    }
};

inline int share_verdict(ShareStateStore& store, const FbReceipt& r, const ::v37::xmr::verify::ParsedBlob& pb,
                         std::uint64_t coinbase_height, std::string& why) {
    namespace rc = ::c2pool::v37n::xmr::recompute;
    const auto& op = r.receipt.coinbase_opening;
    const auto root = rc::mm_root_of(op.tx_extra);
    if (!root) { why = "tx_extra does not end in the lane 0x03 root"; return -1; }
    const auto e = store.find_root(*root);
    if (!e) { why = "the ledger state its 0x03 root commits is not held here"; return 0; }
    if (!e->has_view) { why = "the view at that state's anchor is not readable here yet"; return 0; }
    ::v37::bytes32 hp{};
    if (!::v37::xmr::verify::resume_prefix_hash(op, hp)) { why = "the coinbase opening does not resume"; return -1; }
    auto refs = e->refs;
    const ::c2pool::v37n::xmr::o2::PayOfFn pay_of = [refs](const ::v37::bytes32& k) {
        auto it = refs.find(k);
        if (it != refs.end()) return it->second;
        ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
    };
    rc::CutInputs ci;
    ci.has_view = e->view_ratified;
    ci.payees = e->payees;
    const rc::Result res = rc::verify_share_coinbase(op.tx_extra, hp, static_cast<std::uint8_t>(pb.major), coinbase_height,
                                                    pb.prev_id, *e->ledger, pay_of, e->lane, ci);
    why = res.why;
    if (res.verdict == rc::Verdict::Canonical) return 1;
    if (res.verdict == rc::Verdict::Mismatch) return -1;
    return 0;
}

}  // namespace c2pool::v37n::xmr::relay
