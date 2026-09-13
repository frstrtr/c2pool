// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_peer_payout_recompute.hpp
//     canonical_coinbase_matches = (a) PEER-RECOMPUTE — the receive-side K_fair
//     payout leg for a SETTLING peer block.
//
// THE DEFECT THIS CLOSES. After S-1b/S-1c a peer credits E_b for a block it did
// not mine, and two nodes fed the same carrier stream emit the byte-identical
// owed_digest — until the first block whose OPTION-B coinbase actually SETTLES
// owed. From that block on the winner deducts a real payout map at FINALIZE
// (finalW -= payout) while the peer deducts nothing, because the payout map is
// NOT on the frozen v0x02 carrier wire (w3_wire_freeze.hpp excludes it on
// purpose: it is unbounded). The peer's only honest move was to REFUSE the
// block outright — loudly, with refused[payout] climbing — and from the first
// settling block the two owed ledgers were forked.
//
// THE RULING, AND WHAT THIS IS. The operator ruled (a): the peer RECOMPUTES the
// winner's K_fair payout from its OWN owed ledger. K_fair is
// OwedLedger::propose_coinbase — oldest-owed-first over EffectiveOwed, taken
// O(K) off the incremental EffectiveOwedIndex ordered view (w4_settlement.hpp
// §4.6 / w4_owed_incremental.hpp) — and it is DETERMINISTIC: two ledgers in the
// same state, asked for the same budget under the same caps, return the same
// key set in the same order with the same amounts.
//
// So this header does not compute a payout. It REMEMBERS one. The node already
// runs propose_coinbase once per height, for its OWN option-B template
// (xmr_o2_settlement_source.hpp KFairSource::W4Propose ->
// OwedLedger::propose_coinbase -> x6::build_coinbase), and the Owed-role
// outputs of that assembled template ARE the K_fair payout this node would have
// broadcast had it won that height. XmrKFairPayoutCache records that map, per
// height, at the instant it was built; recompute_peer_payout() hands it back
// when a peer's win for that height arrives. A SECOND CALLER of the node's own
// K_fair run — never a second K_fair rule, never a second fold, and no edit to
// src/sharechain/v37, to the owed_digest() body, to fold_eb or to settle_block.
//
// ── WHY THE CACHED HEIGHT, AND NOT A FRESH CALL AT RECEIPT ─────────────────
// propose_coinbase is a pure function of the ledger STATE, and the two nodes
// are at the same state only at one instant per height. The winner's coinbase
// for H_b was proposed when ITS tip was H_b-1: after the finalize of bin
// H_b-1, before the finalize of bin H_b. A receiver that called
// propose_coinbase when the descriptor lands would call it at whatever state it
// had reached by then — and on a live rig that is routinely ONE FINALIZE
// AHEAD, because the receiver learns of H_b from the chain (a poll away) while
// the winner's descriptor is a poll plus a relay hop away. FINALIZE moves
// EffectiveOwed by +credit and re-arms first_eligible, so a fresh call one
// finalize late returns a DIFFERENT map: the same silent divergence, wearing a
// plausible number. This was not hypothetical — it is visible as the
// per-cursor owed_digest diff of the 2-node run that motivated the ruling.
//
// The cached map is taken at exactly the winner's instant because BOTH nodes
// build their template for H_b when their tip is H_b-1. That is a chain-
// anchored, node-independent clock, which is why the two maps agree.
//
// ── THE GUARD (fail-closed; a refusal is never a silent credit) ─────────────
// The wire carries the winner's owed_digest AT THE WIN (w3_relay.hpp
// CutDescriptor::owed_digest_at_win) and the winner's reward. The winner samples
// that digest after registering its FOUND, and on_block_found does not move
// finalW, so it is the digest of the SAME finalized partition its template was
// proposed over. The cache stores OUR digest at OUR build of that height. Equal
// digests therefore mean the two ledgers agreed, over the §4.5 commitment, at
// the one instant that determines the map. Every guard below REFUSES on failure
// and the caller keeps the existing loud fail-closed path:
//
//   no-record      we never built a template for H_b (not serving, the rebuild
//                  was held for an unbooked FOUND, the ring aged out)
//   ambiguous      we built MORE THAN ONE distinct map for H_b (a rebuild on a
//                  different parent); which one the winner used is unknowable
//   reward         our template's reward != the winner's -> different parent,
//                  different fees, different budget, different selection
//   digest         our owed_digest at build != the winner's at the win -> the
//                  ledgers had ALREADY diverged; reproducing is impossible
//   empty          the winner EMITTED owed outputs and our K_fair proposed NONE
//                  -> the identity set or the payability resolution differs
//   shape          a non-positive amount, or Σ payout > reward
//
// ── THE RESERVATION HALF, AND WHY owed_digest ALONE IS NOT ENOUGH ──────────
// K_fair draws on EffectiveOwed = finalW - Σ_pending payout, and owed_digest
// (§4.5) commits to the FINALIZED half ONLY. Two nodes can therefore hold the
// SAME owed_digest and still propose different maps, because one of them has
// more blocks reserved. This is not theoretical: on the 2-node regtest the
// winner mined two rival blocks at one height and reserved BOTH, while the
// receiver had drained only the first of the two descriptors when it built the
// next height — equal digests, and a proposal 47x larger. Booking that would
// have been a silent divergence, which is the one outcome this path must never
// produce.
//
// So each record also witnesses its RESERVATION: the finalize cursor at the
// build, and how many blocks this node knew of in (cursor, height) at that
// moment. `known_now(lo, hi)` re-asks at lookup. If the count has GROWN, the
// build reserved less than the winner's did and the record is refused
// [reservation]. The count is monotone (a block is never un-learned), so an
// orphan cannot make it drop and produce a false pass; an orphan that arrives
// after the build makes it grow, and refusing there is the safe direction.
//
// What is STILL not pinned, said out loud: the count is a cardinality, not a
// set-equality against the winner's, and it says nothing about the two nodes'
// K_fair CAPS (output_cap / h_min / sink_min / the fixed-output set), which are
// config and are assumed fleet-identical. A winner holding a rival THIS node
// never hears of at all (its descriptor lost, or a third node's block) would
// not move our count, and `empty` / `shape` are all that stand between that and
// a wrong map. Closing that last gap needs one more bit from the winner — a
// commitment to its payout map on the wire (a v0x03 trailer), or the receiver
// reading the winner's coinbase amounts off the chain it already follows. Both
// are outside ruling (a) as written and are named for the operator rather than
// invented here.
//
// SCOPE FENCE: consumer tree, header-only, STL only. Defines no consensus
// digest, no fold, no ledger arithmetic; touches no wire.
// ===========================================================================
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <utility>

#include <c2pool/v37/w4_settlement.hpp>     // OwedLedger::Amounts
#include <c2pool/v37/xmr/xmr_s1_fold.hpp>   // XmrPeerWin, s1_hex32, settle alias
#include <sharechain/v37/v37_hash.hpp>      // ::v37::bytes32

namespace c2pool::v37n::xmr::o2 {

// ── one height's K_fair snapshot, as THIS node proposed it ──────────────────
struct XmrKFairRecord {
    std::uint64_t  height      = 0;
    std::uint64_t  reward      = 0;    // the template's reward (Σ coinbase outputs)
    std::uint32_t  template_id = 0;    // last template id seen for this height
    ::v37::bytes32 owed_digest{};      // ledger.owed_digest() at the FIRST build
    settle::OwedLedger::Amounts owed_payout;   // the Owed-role outputs, identity-keyed
    std::uint32_t  builds    = 0;      // templates built for this height
    bool           ambiguous = false;  // a rebuild produced a DIFFERENT map/reward
    // ── THE RESERVATION WITNESS (see the banner's RESERVATION section) ───────
    // K_fair draws on EffectiveOwed = finalW - Σ_pending payout, and
    // owed_digest commits to the FINALIZED half ONLY. The reserved half is the
    // set of blocks this node held pending when it built — every block it knows
    // of in (cursor_at_build, height). If we later learn of ANOTHER block in
    // that window, our build reserved less than the winner's did, our
    // EffectiveOwed was higher, and the map we proposed is NOT the winner's
    // even though the two digests agree. That is the one shape that could book
    // a wrong payout silently, so the count is witnessed here and re-checked at
    // lookup.
    std::uint64_t  cursor_at_build = 0;   // finalize cursor when this was built
    std::size_t    known_blocks    = 0;   // blocks known in (cursor_at_build, height)
};

// Receive-side recompute counters (diagnostics only — never consensus).
struct XmrRecomputeStats {
    std::uint64_t observed        = 0;  // templates recorded into the cache
    std::uint64_t heights         = 0;  // distinct heights recorded
    std::uint64_t asked           = 0;  // settling peer wins offered to the recompute
    std::uint64_t applied         = 0;  // recomputed maps handed back and APPLIED
    std::uint64_t no_record       = 0;  // no template of ours for that height
    std::uint64_t ambiguous       = 0;  // more than one distinct map for that height
    std::uint64_t reward_mismatch = 0;
    std::uint64_t digest_mismatch = 0;  // our ledger != the winner's at the cut
    std::uint64_t empty_map       = 0;  // winner emitted; our K_fair proposed nothing
    std::uint64_t bad_shape       = 0;  // non-positive amount / Σ > reward
    std::uint64_t reservation     = 0;  // we learned of another block in the window AFTER the build
};

// ── the per-height cache ────────────────────────────────────────────────────
// Bounded: a fixed number of the most recent heights, so a long-running daemon
// cannot grow it without limit. A height that has aged out is a `no_record`
// refusal, which is the correct answer — not a guess at a stale map.
class XmrKFairPayoutCache {
public:
    explicit XmrKFairPayoutCache(std::size_t depth = 256)
        : m_depth(depth ? depth : 1) {}

    // Record the K_fair payout of a template THIS node just built.
    //
    // `owed_digest` MUST be read at the same instant the template was built —
    // the caller passes ledger.owed_digest() immediately after the refresh that
    // produced this template, with nothing in between that can move finalW. A
    // repeat call for the same (height, template_id) is a no-op, so a caller may
    // drive this from a per-loop hook without re-stamping the digest with a
    // later one.
    void observe(std::uint64_t height, std::uint64_t reward, std::uint32_t template_id,
                 const ::v37::bytes32& owed_digest,
                 const settle::OwedLedger::Amounts& owed_payout,
                 std::uint64_t cursor_at_build, std::size_t known_blocks,
                 XmrRecomputeStats* st = nullptr) {
        if (height == 0) return;
        auto it = m_by_height.find(height);
        if (it == m_by_height.end()) {
            XmrKFairRecord r;
            r.height      = height;
            r.reward      = reward;
            r.template_id = template_id;
            r.owed_digest = owed_digest;
            r.owed_payout = owed_payout;
            r.builds      = 1;
            r.cursor_at_build = cursor_at_build;
            r.known_blocks    = known_blocks;
            m_by_height.emplace(height, std::move(r));
            m_order.push_back(height);
            evict();
            if (st) { ++st->observed; ++st->heights; }
            return;
        }
        XmrKFairRecord& r = it->second;
        if (r.template_id == template_id) return;      // the same template, re-offered
        r.template_id = template_id;
        ++r.builds;
        if (st) ++st->observed;
        // A rebuild at the SAME height. If it proposes the same map at the same
        // reward it is harmless (the tip was re-announced); if it differs, we can
        // no longer say which one the winner mined, and every later lookup for
        // this height must refuse.
        if (r.reward != reward || r.owed_payout != owed_payout) r.ambiguous = true;
    }

    const XmrKFairRecord* find(std::uint64_t height) const {
        auto it = m_by_height.find(height);
        return it == m_by_height.end() ? nullptr : &it->second;
    }
    std::size_t size() const { return m_by_height.size(); }
    std::uint64_t oldest_height() const { return m_order.empty() ? 0 : m_order.front(); }
    std::uint64_t newest_height() const { return m_order.empty() ? 0 : m_order.back(); }

private:
    void evict() {
        while (m_order.size() > m_depth) {
            m_by_height.erase(m_order.front());
            m_order.pop_front();
        }
    }
    std::size_t                              m_depth;
    std::map<std::uint64_t, XmrKFairRecord>  m_by_height;
    std::deque<std::uint64_t>                m_order;
};

// ── the verdict ─────────────────────────────────────────────────────────────
struct XmrPeerPayoutOutcome {
    bool        ok = false;                 // `payout` may be booked for this win
    settle::OwedLedger::Amounts payout;     // the recomputed K_fair map
    const char* code = "not-armed";         // stable machine tag for the counter
    std::string refusal;                    // the loud human reason (empty iff ok)
    std::uint32_t template_id = 0;          // ours, for the log
    std::uint64_t sum = 0;                  // Σ payout (piconero)
};

// Σ of a map, as an unsigned piconero total. Amounts are signed because the
// ledger nets over-credit forward; a negative row here is a refusal, not a sum.
inline bool recompute_sum(const settle::OwedLedger::Amounts& a, std::uint64_t& out) {
    unsigned long long s = 0;
    for (const auto& [k, v] : a) {
        (void)k;
        if (v <= 0) return false;
        s += static_cast<unsigned long long>(v);
    }
    out = static_cast<std::uint64_t>(s);
    return true;
}

// The whole rule, in one pure function, so the KAT and the daemon run the SAME
// decision. `w` is the peer's win as the v0x02 descriptor delivered it.
// `known_now(lo, hi)` answers how many blocks this node knows of with
// lo < height < hi RIGHT NOW. It is the reservation witness's second half: if it
// has grown since the build, the build reserved less than the winner did.
template <typename KnownNowFn>
inline XmrPeerPayoutOutcome recompute_peer_payout(const XmrKFairPayoutCache& cache,
                                                  const XmrPeerWin& w,
                                                  XmrRecomputeStats& st,
                                                  KnownNowFn&& known_now) {
    XmrPeerPayoutOutcome out;
    ++st.asked;

    const XmrKFairRecord* r = cache.find(w.h_b);
    if (!r) {
        ++st.no_record;
        out.code = "no-record";
        out.refusal =
            "REFUSED: this node built NO option-B template for h=" + std::to_string(w.h_b) +
            " (not serving, the rebuild was held for an unbooked FOUND, or the height aged out "
            "of the K_fair cache [" + std::to_string(cache.oldest_height()) + ".." +
            std::to_string(cache.newest_height()) + "]) — there is no K_fair run of ours to "
            "reproduce the winner's payout from, and we will not invent one";
        return out;
    }
    out.template_id = r->template_id;
    if (r->ambiguous) {
        ++st.ambiguous;
        out.code = "ambiguous";
        out.refusal =
            "REFUSED: we built " + std::to_string(r->builds) + " DIFFERENT templates for h=" +
            std::to_string(w.h_b) + " (a rebuild on another parent / another ledger state) — "
            "which one the winner mined is unknowable from the wire, so no map may be booked";
        return out;
    }
    if (r->reward != w.reward) {
        ++st.reward_mismatch;
        out.code = "reward";
        out.refusal =
            "REFUSED: our template for h=" + std::to_string(w.h_b) + " had reward " +
            std::to_string(r->reward) + " but the winner carried " + std::to_string(w.reward) +
            " — different parent or different fees, so the K_fair budget and therefore the "
            "selection differ";
        return out;
    }
    if (!(r->owed_digest == w.owed_digest_at_win)) {
        ++st.digest_mismatch;
        out.code = "digest";
        out.refusal =
            "REFUSED: our owed_digest when we built h=" + std::to_string(w.h_b) + " was " +
            s1_hex32(r->owed_digest) + " but the winner's at the win was " +
            s1_hex32(w.owed_digest_at_win) + " — the two ledgers had ALREADY diverged at the "
            "instant that decides K_fair, so the winner's payout cannot be reproduced here";
        return out;
    }
    if (r->owed_payout.empty()) {
        ++st.empty_map;
        out.code = "empty";
        out.refusal =
            "REFUSED: the winner's coinbase EMITTED owed outputs but our own K_fair proposal at "
            "h=" + std::to_string(w.h_b) + " selected NONE — the identity set or the payout-ref "
            "resolution differs between the two nodes; booking an empty map would leave settled "
            "balances owed here and pay them again";
        return out;
    }
    std::uint64_t sum = 0;
    if (!recompute_sum(r->owed_payout, sum) || sum > r->reward) {
        ++st.bad_shape;
        out.code = "shape";
        out.refusal =
            "REFUSED: our K_fair map for h=" + std::to_string(w.h_b) + " is not a payable shape "
            "(a non-positive amount, or Σ=" + std::to_string(sum) + " above the reward " +
            std::to_string(r->reward) + ")";
        return out;
    }

    const std::size_t known_now_n = known_now(r->cursor_at_build, w.h_b);
    if (known_now_n != r->known_blocks) {
        ++st.reservation;
        out.code = "reservation";
        out.refusal =
            "REFUSED: when we built h=" + std::to_string(w.h_b) + " we knew of " +
            std::to_string(r->known_blocks) + " block(s) in (" +
            std::to_string(r->cursor_at_build) + ", " + std::to_string(w.h_b) +
            ") but we know of " + std::to_string(known_now_n) + " now — our K_fair drew on a "
            "SMALLER pending reservation than the winner's, so the two proposals differ even "
            "though the two owed_digests (the FINALIZED half only) agree";
        return out;
    }

    out.ok     = true;
    out.code   = "recomputed";
    out.payout = r->owed_payout;
    out.sum    = sum;
    ++st.applied;
    return out;
}

// One-line narration for the daemon log and the KAT alike.
inline std::string describe_recompute(const std::string& bid, const XmrPeerWin& w,
                                      const XmrPeerPayoutOutcome& o) {
    const std::string sb = bid.size() > 12 ? bid.substr(0, 12) + "…" : bid;
    if (!o.ok)
        return "S-1c K_fair RECOMPUTE [" + std::string(o.code) + "] " + sb + " h=" +
               std::to_string(w.h_b) + ": " + o.refusal;
    return "S-1c K_fair RECOMPUTED " + sb + " h=" + std::to_string(w.h_b) + ": " +
           std::to_string(o.payout.size()) + " owed key(s)/" + std::to_string(o.sum) +
           " pico from OUR template " + std::to_string(o.template_id) +
           " (owed_digest agreed at the cut: " + s1_hex32(w.owed_digest_at_win) + ")";
}

} // namespace c2pool::v37n::xmr::o2
