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
//    ★ HOLD-ROUND-2 (B) lane-prefix SKEW (xmr_relay_wire.hpp kShareVerdict*):
//    2  AHEAD  the committed owed takes are the drain Delta at a SMALLER dh'
//              than ours: the sender's ledger holds a lane block at h - dh'
//              above our prev_lane_height() -> parked until our state
//              advances, never a strike
//    3  BEHIND the take is the Delta at a LARGER dh': the sender has not
//              booked a lane block we hold -> dropped, never a strike
//    (V2) the F-capped forms count too: an under-take is always AHEAD (the
//         sender's float is smaller), an over-take is BEHIND when took >= our F
//         or our pass under-fills Delta; -1 only for a take no ledger with this
//         owed_digest builds (rc::classify_take_skew)
//    4  LATE   a lane block at or above the share's height is booked here
//              (our dh is 0 -> the cap) -> dropped, never a strike
//    Stagenet attempt 7: the finder's post-FOUND shares (dh 4) were judged on
//    the receivers' older prefix (dh 14) -> "under-take" -> -1 -> a strike each
//    -> the finder banned every ~3 s -> the repair of its block never finished.
//
// ★ RULES RATCHET R1, RECEIPT ADMISSION (F1-F3, operator ruling 2026-10-03):
//   * only verdict 1 admits (xmr_relay_node.hpp); 0 and every skew code park
//     and are re-judged, never admitted, never a strike;
//   * F2 retention: every (digest, seq) state whose digest was superseded less
//     than kLateTailBins + 1 + A heights (A = the root-age bound) behind the
//     finalize cursor is kept, so a synced node can evaluate every receipt the
//     lane order can still admit; retention never decides anything;
//   * THE COMMITTED RECEIPT TEST (CommittedHistory, published by the daemon):
//     b = the receipt's bin (its coinbase height), bcut = b - 1 - D_conf (the
//     builder cut of that bin, the block-level D7 rule). Once this node's
//     finalize cursor is >= bcut, the receipt's 0x03 root must be the root of
//     a state in this node's canonical digest history that was current within
//     A heights of bcut, else the verdict is FOREIGN (decided, refused, no
//     strike). Before the cursor gets there an unmatched root is 0 (not yet).
//     A function of the receipt bytes and the chain: every node on the same
//     ledger lineage answers alike, whatever it retained.
//   * a recompute -1 against retained states is decided only when this node
//     holds the digest COMPLETE from the moment it became current (it was
//     running then and evicted none of its states); otherwise 0.
// ===========================================================================
#pragma once

#include <cstdint>
#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"                 // tx_prefix_hash
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"   // resume_prefix_hash, ParsedBlob
#include "xmr_relay_wire.hpp"                          // FbReceipt
#include "xmr_order_rule.hpp"                          // kLateTailBins (F2 retention span)
#include "../xmr_coinbase_recompute.hpp"               // verify_share_coinbase, mm_root_of
#include "../xmr_recon_ring.hpp"                       // builder_cut, root_age (the committed test)

namespace c2pool::v37n::xmr::relay {

// PER-TEMPLATE CACHE. Every share of one template has the same canonical
// outputs: they depend on the state (this entry), the parent, the height and
// the 0x02 tail from V37R on (total, finder, base, owed_in, pool tag, cut),
// never on the worker head (extra-nonce, rbind, padding). So the first
// canonical share of a template stores the canonical prefix; a later share
// with the same key splices its own 0x02 payload into it (same length) and
// compares one Keccak instead of rebuilding the coinbase. A refused share is
// never cached, so a thief cannot seed an entry.
struct ShareTemplateCache {
    struct Item {
        std::vector<std::uint8_t> key;
        std::vector<unsigned char> prefix;   // the canonical miner_tx prefix
        std::size_t payload_at = 0;          // where its 0x02 payload starts
        std::size_t payload_len = 0;
    };
    std::mutex mu;
    std::deque<Item> items;                  // FIFO, bounded
    std::uint64_t hits = 0, misses = 0;
    static constexpr std::size_t kMax = 64;
};

struct ShareStateEntry {
    ::v37::bytes32 digest{};                        // owed_digest of the state
    std::uint64_t ledger_seq = 0;                   // the ledger's event sequence: the key is (digest, ledger_seq)
    ::v37::bytes32 root{};                          // mm_commitment_root(chain, digest): the receipt's 0x03 key
    std::shared_ptr<const ::c2pool::v37n::settle::OwedLedger> ledger;   // frozen, memo warmed
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;                     // booked refs (the owed pass's resolver)
    ::c2pool::v37n::xmr::recompute::LaneInputs lane;
    bool has_view = false;                          // the payees at the anchor are known
    bool view_ratified = false;                     // ... and its geometry is ratified
    std::vector<::c2pool::v37n::settle::WeightedPayee> payees;
    std::shared_ptr<ShareTemplateCache> cache = std::make_shared<ShareTemplateCache>();
    // ★ R1 ADMISSION (F2): the coin height the digest became current at (the
    // finalize driver's digest_since), and whether this node published the
    // digest's FIRST state live (it was running when the digest became
    // current): only then does it hold every (digest, seq) of that digest.
    std::uint64_t since = 0;
    bool from_birth = false;
};

// ★ R1 ADMISSION: THE COMMITTED RECEIPT TEST's inputs, published by the daemon
// (main thread) from its canonical digest history (the RECON ring, seeded from
// the boot replay, so a restarted node holds the same (digest, since) pairs as
// a node that never stopped) and its finalize cursor. Immutable once published.
struct CommittedHistory {
    struct Entry {
        ::v37::bytes32 digest{};
        ::v37::bytes32 root{};             // mm_commitment_root(chain, digest)
        std::uint64_t  since = 0;          // the coin height it became current at
        std::uint64_t  superseded = ::c2pool::v37n::xmr::recon::kSupersededNever;   // the next state's since
    };
    std::vector<Entry> entries;            // oldest first; the live digest last (superseded = never)
    std::uint64_t cursor = 0;              // this node's finalize cursor height
    std::uint64_t d_conf = 0;
    std::uint64_t max_root_age = 0;        // the root-age bound A (0 = unbounded, the lane rule's knob)
    bool warm = false;                     // the history is complete enough to decide (boot-seeded or past warm-up)
};

// ★ review 2026-10-04 (O3): does the history reach back over every canonical
// state admissible for a bin whose builder cut is `bcut`? Admissible = a state
// superseded at or after bcut - A (A = max_root_age; 0 = unbounded, so every
// state back to the lane's first). The entries are contiguous (each one's
// superseded is the next one's since), so it suffices that the oldest entry is
// the lane's first state (since 0) or became current before bcut - A.
#define C2POOL_XMR_HISTORY_REACH 1
inline bool committed_history_reaches(const CommittedHistory& h, std::uint64_t bcut) {
    if (h.entries.empty()) return false;
    const std::uint64_t f = h.entries.front().since;
    if (f == 0) return true;
    if (h.max_root_age == 0 || bcut <= h.max_root_age) return false;
    return f < bcut - h.max_root_age;
}
// `warm` (the daemon's publisher): the history reaches back over the whole span
// the lane order can still admit at this cursor -- the late tail, plus one bin,
// plus D_conf (the builder cut of the oldest admissible bin), plus A.
inline bool committed_history_warm(const CommittedHistory& h, std::uint64_t late_tail_bins) {
    if (h.entries.empty()) return false;
    if (h.entries.front().since == 0) return true;
    if (h.max_root_age == 0) return false;
    const std::uint64_t span = late_tail_bins + 1 + h.d_conf + h.max_root_age;
    return h.cursor > span && h.entries.front().since < h.cursor - span;
}

// The committed test alone (no recompute): 1 = the root is an admissible
// canonical state for bin `coinbase_height`; -1 = decided not (FOREIGN);
// 0 = not decidable here yet (cursor before the builder cut, or not warm).
inline int committed_root_test(const CommittedHistory& h, const ::v37::bytes32& root, std::uint64_t coinbase_height,
                               std::string* why = nullptr) {
    namespace rr = ::c2pool::v37n::xmr::recon;
    const std::uint64_t bcut = rr::builder_cut(coinbase_height, h.d_conf);
    bool in_history = false;
    std::uint64_t best_age = ~std::uint64_t{0};
    for (const auto& e : h.entries) {
        if (e.root != root) continue;
        in_history = true;
        const std::uint64_t age = rr::root_age(e.superseded, bcut);
        if (age < best_age) best_age = age;
        if (h.max_root_age == 0 || age <= h.max_root_age) return 1;
    }
    // ★ review 2026-10-04 (O3): FOREIGN only when the history held here reaches
    // back over EVERY state admissible for this bin: from the lane's first state
    // (since 0), or from a state that became current before bcut - A. A history
    // that starts later (a boot seed from a later point, an evicted ring front)
    // cannot tell an old admissible root from a foreign one: undecided (0).
    if (!committed_history_reaches(h, bcut)) {
        if (why) *why = "not yet: the canonical history held here starts at since " +
                        std::to_string(h.entries.empty() ? 0 : h.entries.front().since) +
                        ", after the oldest state admissible for bin " + std::to_string(coinbase_height) + " (builder cut " +
                        std::to_string(bcut) + ", bound " + std::to_string(h.max_root_age) + ")";
        return 0;
    }
    if (!h.warm || h.cursor < bcut) {
        if (why) *why = "not yet: this node's finalize cursor " + std::to_string(h.cursor) + " has not reached the builder cut " +
                        std::to_string(bcut) + " of bin " + std::to_string(coinbase_height) + (h.warm ? "" : " (history warming up)");
        return 0;
    }
    if (why) {
        *why = in_history ? "foreign: the 0x03 root is a canonical state superseded " + std::to_string(best_age) + " heights before the builder cut " +
                                std::to_string(bcut) + " of bin " + std::to_string(coinbase_height) + " (bound " + std::to_string(h.max_root_age) + ")"
                          : "foreign: the 0x03 root is no state of this node's canonical history (" + std::to_string(h.entries.size()) +
                                " states) and the cursor " + std::to_string(h.cursor) + " has passed the builder cut " + std::to_string(bcut) +
                                " of bin " + std::to_string(coinbase_height);
    }
    return -1;
}

// STATE KEY = (owed_digest, ledger_seq). A sibling FOUND bumps ledger_seq
// without changing owed_digest (the digest covers the settled rows, not the
// pending ones), yet the builder then reads the new pending rows (A5: avail =
// due - SUM(pending claims)). Keyed by the digest alone, the publisher kept
// the first state of a digest, so a share built after the FOUND was rebuilt
// on the old ledger and refused. Both states commit the same 0x03 root, so
// the verdict tries every held entry with that root: a share is canonical if
// it is the canonical coinbase of ANY held state it commits (handoff gap 1).
// ★ R1 ADMISSION (F2) RETENTION: put(e, cursor, span) keeps every state whose
// digest is current or was superseded at a height >= cursor - span (the
// daemon passes span = kLateTailBins + 1 + A); kMaxStates is a hard memory
// cap above that (oldest evicted first; an evicted digest is no longer
// complete, so it never yields a decided -1). put(e) alone = the cap only.
#define C2POOL_XMR_SHARE_STATE_BY_SEQ 1
#define C2POOL_XMR_SHARE_STATE_RETENTION 1
struct ShareStateStore {
    static constexpr std::size_t kMaxStates = 1024;
    std::mutex mu;
    std::deque<std::shared_ptr<const ShareStateEntry>> ring;   // newest last, bounded (span, then kMaxStates)
    std::map<::v37::bytes32, std::uint64_t> superseded_at;     // digest -> the since of the digest that replaced it
    std::set<::v37::bytes32> broken;                           // digests with an evicted state (not complete any more)
    std::shared_ptr<const CommittedHistory> history;           // null = no committed test (the pre-R1 answers)
    void set_history(std::shared_ptr<const CommittedHistory> h) {
        std::lock_guard<std::mutex> lk(mu);
        history = std::move(h);
    }
    std::shared_ptr<const CommittedHistory> history_now() {
        std::lock_guard<std::mutex> lk(mu);
        return history;
    }
    // every retained state of `digest` is held, from its first one on
    bool complete(const ::v37::bytes32& digest) {
        std::lock_guard<std::mutex> lk(mu);
        if (broken.count(digest)) return false;
        for (const auto& x : ring) if (x->digest == digest && x->from_birth) return true;
        return false;
    }
    std::shared_ptr<const ShareStateEntry> find_root(const ::v37::bytes32& root) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto it = ring.rbegin(); it != ring.rend(); ++it)
            if ((*it)->root == root) return *it;
        return nullptr;
    }
    // Every held entry whose state commits `root`, newest first.
    std::vector<std::shared_ptr<const ShareStateEntry>> find_all_root(const ::v37::bytes32& root) {
        std::vector<std::shared_ptr<const ShareStateEntry>> out;
        std::lock_guard<std::mutex> lk(mu);
        for (auto it = ring.rbegin(); it != ring.rend(); ++it)
            if ((*it)->root == root) out.push_back(*it);
        return out;
    }
    std::shared_ptr<const ShareStateEntry> find_state(const ::v37::bytes32& digest, std::uint64_t seq) {
        std::lock_guard<std::mutex> lk(mu);
        for (const auto& x : ring)
            if (x->digest == digest && x->ledger_seq == seq) return x;
        return nullptr;
    }
    // Replace the entry with the same (digest, ledger_seq); else append. Then
    // evict: (F2) every state of a digest superseded below cursor - span (when
    // span != 0), and the oldest past kMaxStates (that digest is no longer
    // complete here).
    void put(std::shared_ptr<const ShareStateEntry> e, std::uint64_t cursor = 0, std::uint64_t span = 0) {
        std::lock_guard<std::mutex> lk(mu);
        bool replaced = false;
        for (auto& x : ring)
            if (x->digest == e->digest && x->ledger_seq == e->ledger_seq) { x = e; replaced = true; break; }
        if (!replaced) {
            if (!ring.empty() && ring.back()->digest != e->digest && !superseded_at.count(ring.back()->digest))
                superseded_at[ring.back()->digest] = e->since;   // the newest digest was replaced by this one
            ring.push_back(e);
        }
        if (span) {
            while (!ring.empty()) {
                const auto& f = ring.front();
                const auto s = superseded_at.find(f->digest);
                if (f->digest == ring.back()->digest || s == superseded_at.end() || s->second + span >= cursor) break;
                ring.pop_front();
            }
        }
        while (ring.size() > kMaxStates) {
            broken.insert(ring.front()->digest);
            ring.pop_front();
        }
        // forget the bookkeeping of digests no longer held
        for (auto it = superseded_at.begin(); it != superseded_at.end();) {
            bool held = false;
            for (const auto& x : ring) if (x->digest == it->first) { held = true; break; }
            it = held ? std::next(it) : superseded_at.erase(it);
        }
        for (auto it = broken.begin(); it != broken.end();) {
            bool held = false;
            for (const auto& x : ring) if (x->digest == *it) { held = true; break; }
            it = held ? std::next(it) : broken.erase(it);
        }
    }
};

// ★ review 2026-10-04 (O2): a restarted node rebuilds, from its boot replay
// (XmrNode::boot_share_states), every state of each digest the lane order can
// still need, oldest first, and publishes them before its live state. Each such
// digest is held complete here (every one of its states, from its first), so a
// receipt built on a state current before the restart is judged 1 / -1 exactly
// as on a node that never stopped (O1: a recompute -1 is decided alike).
// The boot states REPLACE whatever the store held (a live state published
// before them would otherwise sit in front of older digests and corrupt the
// superseded-at order); the caller re-publishes its live state right after.
// The committed history is kept.
#define C2POOL_XMR_BOOT_SHARE_STATES 1
inline std::size_t put_boot_states(ShareStateStore& store, const std::vector<std::shared_ptr<ShareStateEntry>>& states,
                                   std::uint64_t cursor, std::uint64_t span) {
    if (states.empty()) return 0;
    {
        std::lock_guard<std::mutex> lk(store.mu);
        store.ring.clear(); store.superseded_at.clear(); store.broken.clear();
    }
    for (const auto& e : states) { e->from_birth = true; store.put(e, cursor, span); }
    return states.size();
}

// The verdict of one held state `e` (1 / -1 / 0, as share_verdict).
inline int share_verdict_one(const std::shared_ptr<const ShareStateEntry>& e, const FbReceipt& r,
                             const ::v37::xmr::verify::ParsedBlob& pb, std::uint64_t coinbase_height,
                             const ::v37::bytes32& hp, std::string& why) {
    namespace rc = ::c2pool::v37n::xmr::recompute;
    const auto& op = r.receipt.coinbase_opening;
    if (!e->has_view) { why = "the view at that state's anchor is not readable here yet"; return 0; }

    // PER-TEMPLATE CACHE: key = parent | height | major | the 0x02 tail from V37R on
    const auto payload = ::c2pool::v37n::xmr::credit::extra_nonce_field(op.tx_extra);
    std::vector<std::uint8_t> key;
    if (payload) {
        const std::size_t end = ::c2pool::v37n::xmr::paynow::end_before_finder(*payload);
        if (end >= ::c2pool::v37n::xmr::paynow::kRewardTotalFieldBytes) {
            key.insert(key.end(), pb.prev_id.begin(), pb.prev_id.end());
            for (int i = 0; i < 8; ++i) key.push_back(static_cast<std::uint8_t>(coinbase_height >> (8 * i)));
            key.push_back(static_cast<std::uint8_t>(pb.major));
            key.insert(key.end(), payload->begin() + static_cast<std::ptrdiff_t>(end - ::c2pool::v37n::xmr::paynow::kRewardTotalFieldBytes),
                       payload->end());
        }
    }
    if (!key.empty() && e->cache) {
        std::vector<unsigned char> prefix;
        {
            std::lock_guard<std::mutex> lk(e->cache->mu);
            for (const auto& it : e->cache->items)
                if (it.key == key && it.payload_len == payload->size()) { prefix = it.prefix; std::copy(payload->begin(), payload->end(), prefix.begin() + static_cast<std::ptrdiff_t>(it.payload_at)); break; }
        }
        if (!prefix.empty()) {
            const auto h = ::xmr::coin::tx_prefix_hash(prefix);
            std::lock_guard<std::mutex> lk(e->cache->mu);
            if (std::memcmp(h.data(), hp.data(), 32) == 0) { ++e->cache->hits; why.clear(); return 1; }
            ++e->cache->hits;
            why = "share-mismatch: the coinbase prefix hash is not the canonical one of its template";
            return -1;
        }
    }
    auto refs = e->refs;
    const ::c2pool::v37n::xmr::o2::PayOfFn pay_of = [refs](const ::v37::bytes32& k) {
        auto it = refs.find(k);
        if (it != refs.end()) return it->second;
        ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
    };
    rc::CutInputs ci;
    ci.has_view = e->view_ratified;
    ci.payees = e->payees;
    ::v37::xmr::settle::BuiltCoinbase built;
    const rc::Result res = rc::verify_share_coinbase(op.tx_extra, hp, static_cast<std::uint8_t>(pb.major), coinbase_height,
                                                    pb.prev_id, *e->ledger, pay_of, e->lane, ci, &built);
    why = res.why;
    if (res.verdict == rc::Verdict::Canonical) {
        if (!key.empty() && e->cache && built.prefix.size() >= built.tx_extra.size()) {
            // the payload sits inside the canonical tx_extra, which ends the prefix
            const std::size_t xat = built.prefix.size() - built.tx_extra.size();
            const auto pos = std::search(built.tx_extra.begin(), built.tx_extra.end(), payload->begin(), payload->end());
            if (pos != built.tx_extra.end()) {
                ShareTemplateCache::Item it;
                it.key = std::move(key);
                it.prefix = built.prefix;
                it.payload_at = xat + static_cast<std::size_t>(pos - built.tx_extra.begin());
                it.payload_len = payload->size();
                std::lock_guard<std::mutex> lk(e->cache->mu);
                ++e->cache->misses;
                e->cache->items.push_back(std::move(it));
                while (e->cache->items.size() > ShareTemplateCache::kMax) e->cache->items.pop_front();
            }
        }
        return 1;
    }
    if (res.verdict == rc::Verdict::Mismatch) {
        // ★ HOLD-ROUND-2 (B): a drain take mismatch explained by the lane prefix
        if (res.take_mismatch && e->ledger) {
            const std::uint64_t prev = e->ledger->prev_lane_height();
            if (prev > 0 && coinbase_height <= prev) {
                why = "late: a lane block at height " + std::to_string(prev) + " >= this share's height " +
                      std::to_string(coinbase_height) + " is booked here (" + res.why + ")";
                return kShareVerdictLate;
            }
            // ★ HOLD-ROUND-2 V2: every drain regime, not only the dh one: an
            // F-capped take (either float) and both dh past H_cap are a skew too
            // (rc::classify_take_skew); only a take no ledger with this digest
            // builds is a strike.
            const rc::TakeSkewClass k = rc::classify_take_skew(res.took, res.took_canon, res.F, res.delta, res.R, res.dh,
                                                               res.drain_q, res.drain_h_cap);
            const std::string nums = "took " + std::to_string(res.took) + " vs ours " + std::to_string(res.took_canon) +
                                     "; ours dh " + std::to_string(res.dh) + " F " + std::to_string(res.F) + ", prev_lane " +
                                     std::to_string(prev);
            if (k.kind == rc::TakeSkew::Ahead) {
                why = k.dh ? "ahead: the take is the drain Delta at dh " + std::to_string(k.dh) + " (a lane block at " +
                                 std::to_string(coinbase_height - k.dh) + " not booked here; " + nums + ")"
                           : std::string("ahead: ") + k.regime + " (a pending lane block not booked here; " + nums + ")";
                return kShareVerdictAhead;
            }
            if (k.kind == rc::TakeSkew::Behind) {
                why = k.dh && k.dh > ((res.dh == 0 || res.dh > res.drain_h_cap) ? res.drain_h_cap : res.dh)
                    ? "behind: the take is the drain Delta at dh " + std::to_string(k.dh) + " (the sender has not booked "
                      "our lane block at " + std::to_string(prev) + "; " + nums + ")"
                    : std::string("behind: ") + k.regime + " (the sender has not booked a lane block we hold; " + nums + ")";
                return kShareVerdictBehind;
            }
            why = res.why + " -- outside every drain regime: " + k.regime + " (G(H_cap) " + std::to_string(k.g_max) + "; " + nums + ")";
        }
        // ★ HOLD-ROUND-3 (F4): the tails agree and the outputs do not, and the
        // share commits NO V37N base -- the drain take it embodies is not stated
        // anywhere, so the AHEAD / BEHIND regimes above had nothing to classify
        // and this was a -1. Stagenet attempt 8: every lineage split was born
        // here (receivers struck the finder's post-FOUND shares before pay-now
        // armed, admitted them later in the late tail). The share's state is the
        // same owed_digest as ours (else verdict 0), so it is a lane block ahead
        // of us, behind us, or garbage: LATE when a lane block at or above its
        // height is booked here (as the take form), else UNBASED -- parked like
        // AHEAD, re-judged when our state advances, dropped without a strike
        // after kShareUnbasedMaxRounds (xmr_relay_node.hpp). Never a strike.
        if (!res.take_mismatch && res.prefix_hash_mismatch && !res.has_paynow_base) {
            const std::uint64_t prev = e->ledger ? e->ledger->prev_lane_height() : res.prev_lane;
            if (prev > 0 && coinbase_height <= prev) {
                why = "late: a lane block at height " + std::to_string(prev) + " >= this share's height " +
                      std::to_string(coinbase_height) + " is booked here (no V37N base; " + res.why + ")";
                return kShareVerdictLate;
            }
            why = "unbased: the coinbase prefix hash is not the canonical one of this state and the share commits no V37N base "
                  "(pay-now not armed): the sender's prev lane block differs from ours (" + std::to_string(prev) +
                  ") or the template is not a lane template -- parked, re-judged on the next share state, never a strike";
            return kShareVerdictUnbased;
        }
        return -1;
    }
    return 0;
}

// Every held state with the share's 0x03 root is tried (newest first): 1 if
// the share is the canonical coinbase of any of them; else 0 if one of them
// could not decide (no view yet, or undecidable); else -1. The answer is a
// function of the SET of held states, never of their order.
// ★ R1 ADMISSION: with a published CommittedHistory the root is first put
// through the committed test (FOREIGN when decided not admissible), a root
// that is admissible but has no retained state answers 0 (F2: never trusted,
// never refused for what this node happened to retain), and a recompute -1
// stands only on a digest this node holds complete (else 0).
inline int share_verdict(ShareStateStore& store, const FbReceipt& r, const ::v37::xmr::verify::ParsedBlob& pb,
                         std::uint64_t coinbase_height, std::string& why) {
    namespace rc = ::c2pool::v37n::xmr::recompute;
    const auto& op = r.receipt.coinbase_opening;
    const auto root = rc::mm_root_of(op.tx_extra);
    if (!root) { why = "tx_extra does not end in the lane 0x03 root"; return -1; }
    const auto hist = store.history_now();
    if (hist) {
        std::string cw;
        const int c = committed_root_test(*hist, *root, coinbase_height, &cw);
        if (c < 0) { why = cw; return kShareVerdictForeign; }
    }
    const auto es = store.find_all_root(*root);
    if (es.empty()) {
        why = hist ? "the canonical ledger state its 0x03 root commits is not retained here (or not reached yet): undecided"
                   : "the ledger state its 0x03 root commits is not held here";
        return 0;
    }
    ::v37::bytes32 hp{};
    if (!::v37::xmr::verify::resume_prefix_hash(op, hp)) { why = "the coinbase opening does not resume"; return -1; }
    bool undecided = false;
    std::string first_why, undecided_why;
    int skew = 0; std::string skew_why;   // HOLD-ROUND-2 (B): AHEAD > BEHIND > LATE, any state
    for (const auto& e : es) {
        std::string w;
        const int v = share_verdict_one(e, r, pb, coinbase_height, hp, w);
        if (v == 1) { why.clear(); return 1; }
        if (v == 0 && !undecided) { undecided = true; undecided_why = w; }
        if (v >= kShareVerdictAhead) {   // AHEAD > UNBASED > BEHIND > LATE (HOLD-ROUND-3: UNBASED parks like AHEAD)
            auto rank_of = [](int c) { return c == kShareVerdictAhead ? 4 : c == kShareVerdictUnbased ? 3 : c == kShareVerdictBehind ? 2 : c == kShareVerdictLate ? 1 : 0; };
            if (rank_of(v) > rank_of(skew)) { skew = v; skew_why = w; }
        }
        if (first_why.empty()) first_why = w;
    }
    if (undecided) { why = undecided_why; return 0; }
    // a share some held state explains as lane-prefix skew is never a strike
    if (skew) { why = skew_why; return skew; }
    why = first_why;
    if (es.size() > 1) why += " (against each of the " + std::to_string(es.size()) + " held states with that root)";
    // ★ R1 ADMISSION: a -1 is decided only against the COMPLETE state set of
    // that digest (this node was running when it became current and evicted
    // none of its states); a node that holds part of it answers 0.
    if (hist && !store.complete(es.front()->digest)) {
        why = "undecided: not canonical for the " + std::to_string(es.size()) + " retained state(s) of its digest, which this node does not hold "
              "complete (" + why + ")";
        return 0;
    }
    return -1;
}

}  // namespace c2pool::v37n::xmr::relay
