// SPDX-License-Identifier: (see repository LICENSE)
// ---------------------------------------------------------------------------
// xmr_recon_ring.hpp — RECON Phase-1: the post-finalize owed-ledger snapshot
// ring (payout-side convergence, twin of the ruled variant-A credit side).
//
// WHY THIS EXISTS. A settling peer win names an on-chain coinbase whose K_fair
// deduction map is a pure function of the WINNER's owed-ledger STATE at the
// instant it built the block — the finalize cursor it evaluated at, and the
// pending reservation set. Neither is on the frozen v0x02 wire. The winner's
// commitment (§4.5 owed_digest_at_win) IS on the wire, so a receiver can pick
// the moment its OWN ledger carried the same commitment and RECONSTRUCT the map
// from there. That moment is a post-finalize snapshot; this ring holds a bounded
// history of them, keyed by the finalize cursor, looked up by owed_digest.
//
// ATOMIC-IN-FINALIZE. Production takes the snapshot INSIDE the finalize step
// (XmrFinalizeDriver step-hook), never on a poll tick — a multi-height
// advance_to_tip batch would otherwise lose the intermediate cursors the winner
// may have evaluated at. `observe()` is therefore called from the finalize
// thread, once per touched height, before the next height is stepped.
//
// This is a CONSUMER-TREE module: no consensus body, no owed_digest()/fold_eb
// edit. The ledger is copied by value (OwedLedger is copyable), so a snapshot
// is a frozen scratch the reconstructor can replay pending onto without
// touching the live ledger.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <utility>

#include "xmr_s1_fold.hpp"   // settle = ::c2pool::v37n::settle; OwedLedger

namespace c2pool::v37n::xmr::o2 {

class XmrReconRing {
public:
    explicit XmrReconRing(std::size_t cap = 24) : m_cap(cap ? cap : 1) {}

    // Called ATOMICALLY inside the finalize step, keyed by the finalize cursor
    // the ledger has just reached. If that cursor is already held (a touched
    // snapshot re-taken within the same step), update it in place; otherwise
    // append and evict the oldest to keep the ring bounded.
    void observe(std::uint64_t cursor, const settle::OwedLedger& led) {
        for (auto& e : m_ring)
            if (e.first == cursor) { e.second = led; return; }
        m_ring.emplace_back(cursor, led);
        while (m_ring.size() > m_cap) m_ring.pop_front();
    }

    // Newest-first search for the snapshot whose owed_digest equals `d` (the
    // winner's owed_digest_at_win). Returns nullptr and leaves cursor_out
    // untouched when no snapshot carries that commitment — the "no-state"
    // (PARK / behind) verdict of the reconstructor.
    const settle::OwedLedger* find_by_digest(const ::v37::bytes32& d,
                                             std::uint64_t& cursor_out) const {
        for (auto it = m_ring.rbegin(); it != m_ring.rend(); ++it)
            if (it->second.owed_digest() == d) { cursor_out = it->first; return &it->second; }
        return nullptr;
    }

    std::size_t   size()         const { return m_ring.size(); }
    bool          empty()        const { return m_ring.empty(); }
    std::uint64_t oldest_cursor() const { return m_ring.empty() ? 0 : m_ring.front().first; }
    std::uint64_t newest_cursor() const { return m_ring.empty() ? 0 : m_ring.back().first; }

private:
    std::size_t m_cap;
    std::deque<std::pair<std::uint64_t, settle::OwedLedger>> m_ring;
};

}  // namespace c2pool::v37n::xmr::o2
