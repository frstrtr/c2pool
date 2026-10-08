// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_fork_choice.hpp
// Path B carrier fork choice over a tree of carriers.
//
//   d(c)        = d_at(chain of c, pos(c))                     (pathb_retarget.hpp)
//   H(c)        = max(H(parent), h(c)); h(c) < H(parent): not a carrier
//   cum_work(c) = cum_work(parent) + d(c)                      (128 bit; genesis 0)
//   best tip    = the greatest cum_work among the carriers whose chain back
//                 to genesis is fully verified (header checks and PoW at d
//                 passed, bodies held); equal cum_work: the lower id (32
//                 bytes compared in order). Comparing cum_work is comparing
//                 the verified work after the branch point of two chains.
//   No reorg depth limit. A switch whose fork point the journal holds
//   rewinds (RewindVerdict::Rewound); a deeper one rebuilds
//   (RewindVerdict::RebuildRequired).
//   A carrier whose parent is not held waits (Deferred); a waiting entry is
//   the pair (id, claimed parent), so the same id naming another parent is
//   judged on its own. When a carrier is placed, its other waiting entries are
//   dropped and the carriers waiting on it are released
//   (PlaceOutcome::released): the caller admits each again on the parent's
//   view and places it. A carrier refused NotCarrier or FoldMismatch discards
//   the carriers waiting on it, and those waiting on them, except a carrier
//   that still waits under another claimed parent (PlaceOutcome::discarded).
//   receipts_root (S1.3 #10): a carrier's receipts_root must equal
//     sha256d("c2pool-v37-carry" || carried_root(ids) || rs_root(S(parent)))
//   over the ids of its carried list in list order (check_carried_fold,
//   pathb_receipt_admission.hpp; carried_root 0 when it carries nothing);
//   otherwise FoldMismatch (strike) in place(), after the parent and height
//   checks.
//   S(c) = rs_step_at(S(parent), pos(c), placements at pos(c), T)
//   (pathb_ratchet_activation.hpp): step (1) at H_act of the table T, then
//   step (2) over every placement at pos(c): each carried receipt at its
//   credited work, 0 when dead, then the carrier at d(c); the activation row
//   it returns is kept on the carrier node. Genesis S = epoch 0, rules_cur =
//   the genesis rules digest.
//   Headers-first: an announced side header weighs its retarget d on the
//   side chain; it fails on a parent link that does not continue the side
//   chain, a height below the record of its parent, or a failed PoW at that
//   d. A header carries no carried bodies: no fold and no S on this path.
//   decide_side_branch (pathb_headers_first.hpp) decides on the result.
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128, u128_add, u128_less, u128_greater

#include "pathb_headers_first.hpp"
#include "pathb_journal.hpp"
#include "pathb_params.hpp"
#include "pathb_ratchet_activation.hpp"  // EpochTable, ActivationRow, rs_step_at
#include "pathb_ratchet_state.hpp"
#include "pathb_receipt_admission.hpp"   // carrier_receipts_root_over, check_carried_fold
#include "pathb_retarget.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Fork-choice order
// ---------------------------------------------------------------------------
struct ChainTip {
    ::c2pool::xmr::native::U128 cum_work{};
    Hash32 id{};
};

// true when the fork choice takes a over b: greater cum_work, or equal
// cum_work and the lower id.
inline bool fork_choice_prefers(const ChainTip& a, const ChainTip& b) noexcept {
    if (::c2pool::xmr::native::u128_greater(a.cum_work, b.cum_work)) return true;
    if (::c2pool::xmr::native::u128_less(a.cum_work, b.cum_work)) return false;
    return a.id < b.id;
}

// ---------------------------------------------------------------------------
// Carrier tree
// ---------------------------------------------------------------------------
struct CarrierAnnounce {
    Hash32 id{};
    Hash32 parent{};
    std::uint64_t h = 0;       // template height
    Hash32 receipts_root{};    // side_data_v3 receipts_root
    std::uint16_t ballot = 0;  // side_data_v3 ballot
};

// A receipt of a carrier's carried list as placed at the carrier's position:
// its id, its credited work work(T_origin) (R-1, S2.3 #11), its ballot
// (side_data_v3) and its liveness at placement on the placing chain (S2.3
// #17, decided by the placement). A dead placement adds 0 to S.
struct CarriedPlacement {
    Hash32 id{};
    std::uint64_t work = 0;
    std::uint16_t ballot = 0;
    bool live = false;
};

struct CarrierNode {
    Hash32 id{};
    Hash32 parent{};
    std::uint64_t pos = 0;
    std::uint64_t h = 0;
    std::uint64_t H = 0;
    std::uint64_t d = 0;
    ::c2pool::xmr::native::U128 cum_work{};
    Hash32 receipts_root{};
    std::uint16_t ballot = 0;
    RatchetState rs{};                        // S after this position
    std::optional<ActivationRow> activation;  // the AR row of an activation at this position
    bool verified = false;                    // header checks and PoW at d passed
    bool bodies = false;                      // bodies held
    bool chain_valid = false;                 // verified and bodies on every carrier back to genesis
    std::size_t parent_index = 0;
    std::vector<std::size_t> children;
};

enum class PlaceVerdict : std::uint8_t { Placed, Deferred, Duplicate, NotCarrier, FoldMismatch };

struct PlaceOutcome {
    PlaceVerdict verdict = PlaceVerdict::Deferred;
    std::vector<Hash32> released;   // Placed: the carriers that waited on this one, in arrival order; each is
                                    // admitted again by the caller and placed
    std::vector<Hash32> discarded;  // NotCarrier / FoldMismatch: the waiting entries dropped (the carriers that
                                    // waited on this one, and on them while they have no other waiting entry)
};

struct SwitchPlan {
    Hash32 fork{};
    std::uint64_t fork_position = 0;
    std::uint64_t undo_depth = 0;  // positions above the fork point on the applied chain
    RewindVerdict verdict = RewindVerdict::Rewound;
    std::vector<Hash32> apply;     // fork point + 1 .. best tip
};

class CarrierTree {
public:
    // Genesis: position 0, record height genesis_height (at least the newest
    // inherited record), cum_work 0, verified, bodies held, S =
    // genesis_ratchet_state(genesis_rules_digest). `inherited`: the
    // predecessor's carriers, oldest first; the newest N_rt open the window
    // of position 1. `table`: the node's compiled epoch table T, read by
    // rs_step_at at every position (no default).
    // Preconditions: retarget_params_valid(p), ratchet_params_valid(rp).
    CarrierTree(const LaneParams& p, const Hash32& genesis_id, std::uint64_t genesis_height, const EpochTable& table,
                std::span<const RetargetEntry> inherited = {}, const RatchetParams& rp = kRuledRatchetParams,
                const Hash32& genesis_rules_digest = Hash32{})
        : p_(p), rp_(rp), table_(table) {
        const std::size_t keep =
                static_cast<std::size_t>(std::min<std::uint64_t>(inherited.size(), p.retarget_span));
        inherited_.assign(inherited.end() - static_cast<std::ptrdiff_t>(keep), inherited.end());
        CarrierNode g;
        g.id = genesis_id;
        g.parent = genesis_id;
        g.H = inherited_.empty() ? genesis_height : record_height(inherited_.back().H, genesis_height);
        g.h = genesis_height;
        g.rs = genesis_ratchet_state(genesis_rules_digest);
        g.verified = g.bodies = g.chain_valid = true;
        nodes_.push_back(std::move(g));
        index_.emplace(genesis_id, 0);
    }

    const LaneParams& params() const noexcept { return p_; }
    const RatchetParams& ratchet_params() const noexcept { return rp_; }
    const EpochTable& epoch_table() const noexcept { return table_; }
    std::size_t size() const noexcept { return index_.size(); }
    std::size_t waiting() const noexcept { return waiting_keys_.size(); }
    const CarrierNode& genesis() const noexcept { return nodes_[0]; }
    const CarrierNode& best() const noexcept { return nodes_[best_]; }

    const CarrierNode* find(const Hash32& id) const {
        const auto it = index_.find(id);
        return it == index_.end() ? nullptr : &nodes_[it->second];
    }

    // The retarget window of the carrier after `tip` (its newest N_rt
    // carriers, then inherited entries).
    std::optional<RetargetWindow> window_after(const Hash32& tip) const {
        const auto it = index_.find(tip);
        if (it == index_.end()) return std::nullopt;
        return window_after_index(it->second);
    }

    // d_at(chain of tip, pos(tip) + 1): the d of a carrier on top of `tip`
    // and the T_origin of every receipt whose tip is `tip`.
    std::optional<std::uint64_t> next_difficulty(const Hash32& tip) const {
        const std::optional<RetargetWindow> w = window_after(tip);
        if (!w) return std::nullopt;
        return w->next_difficulty();
    }

    // The receipts_root of a carrier on top of `tip` that carries `carried_ids`
    // (in list order): the fold of carried_root(carried_ids) with rs_root(S(tip)).
    std::optional<Hash32> next_receipts_root(const Hash32& tip, std::span<const Hash32> carried_ids) const {
        const auto it = index_.find(tip);
        if (it == index_.end()) return std::nullopt;
        return carrier_receipts_root_over(carried_ids, nodes_[it->second].rs);
    }

    // Places carrier c with its carried list (in list order). c.id held, or
    // (c.id, c.parent) already waiting: Duplicate. Parent not held: Deferred
    // (c waits on its parent). Then h(c) >= H(parent), else NotCarrier; then
    // the fold of S1.3 #10 over the carried ids against S(parent), else
    // FoldMismatch; then c is placed at pos(parent) + 1 and S advances by
    // rs_step_at over every placement there.
    // Preconditions of the caller:
    //   - with c.parent held, place() follows S1.3 #1a-#9 (the coinbase check
    //     binds side_data, and so the claimed parent, to c.id);
    //   - the carried bodies are held and S2.3 #14 passed; missing bodies are
    //     DEFERred before place() (place(c, {}) for a carrier that carries
    //     receipts is FoldMismatch);
    //   - `carried` is read on the placing chain (the branch through c.parent):
    //     the ids of the carried list in body order, work = the #11 t_origin,
    //     ballot = the side_data_v3 ballot, live = #17;
    //   - a FoldMismatch judges these bytes (the carrier and its carried
    //     list), not c.id: the tree keeps no refusal, and the same id with
    //     other bytes is judged again;
    //   - place() is not called at x >= H_hold (the hold is the caller's).
    PlaceOutcome place(const CarrierAnnounce& c, std::span<const CarriedPlacement> carried) {
        PlaceOutcome out;
        if (index_.count(c.id) != 0 || waiting_keys_.count(WaitKey{c.id, c.parent}) != 0) {
            out.verdict = PlaceVerdict::Duplicate;
            return out;
        }
        const auto pit = index_.find(c.parent);
        if (pit == index_.end()) {
            waiting_[c.parent].push_back(c.id);
            waiting_keys_.insert(WaitKey{c.id, c.parent});
            out.verdict = PlaceVerdict::Deferred;
            return out;
        }
        if (!carrier_height_admissible(nodes_[pit->second].H, c.h)) {
            out.verdict = PlaceVerdict::NotCarrier;
            out.discarded = discard_waiting(c.id);
            return out;
        }
        if (fold_verdict(nodes_[pit->second].rs, c, carried) != FoldVerdict::Match) {
            out.verdict = PlaceVerdict::FoldMismatch;
            out.discarded = discard_waiting(c.id);
            return out;
        }
        out.verdict = PlaceVerdict::Placed;
        place_under(pit->second, c, carried);
        drop_claims(c.id);
        out.released = release_waiting(c.id);
        return out;
    }

    bool mark_verified(const Hash32& id) { return mark(id, true, false); }
    bool mark_bodies(const Hash32& id) { return mark(id, false, true); }

    // Removes a carrier that is not chain-valid, with its descendants (none of
    // them is chain-valid, so the best tip does not change). Waiting carriers
    // never wait on a placed id.
    bool drop(const Hash32& id) {
        const auto it = index_.find(id);
        if (it == index_.end() || it->second == 0 || nodes_[it->second].chain_valid) return false;
        const std::size_t root = it->second;
        std::vector<std::size_t>& sib = nodes_[nodes_[root].parent_index].children;
        sib.erase(std::remove(sib.begin(), sib.end(), root), sib.end());
        std::vector<std::size_t> stack{root};
        while (!stack.empty()) {
            const std::size_t i = stack.back();
            stack.pop_back();
            index_.erase(nodes_[i].id);
            for (std::size_t ch : nodes_[i].children) stack.push_back(ch);
            nodes_[i].children.clear();
        }
        return true;
    }

    // The newest common ancestor of a and b.
    std::optional<Hash32> fork_point(const Hash32& a, const Hash32& b) const {
        const auto ia = index_.find(a), ib = index_.find(b);
        if (ia == index_.end() || ib == index_.end()) return std::nullopt;
        return nodes_[common_ancestor(ia->second, ib->second)].id;
    }

    // Carriers after `fork` up to `tip`, oldest first; nullopt when `fork` is
    // not an ancestor of `tip` (or either is not held).
    std::optional<std::vector<Hash32>> path(const Hash32& fork, const Hash32& tip) const {
        const auto fi = index_.find(fork), ti = index_.find(tip);
        if (fi == index_.end() || ti == index_.end()) return std::nullopt;
        std::vector<Hash32> out;
        std::size_t i = ti->second;
        while (nodes_[i].pos > nodes_[fi->second].pos) {
            out.push_back(nodes_[i].id);
            i = nodes_[i].parent_index;
        }
        if (i != fi->second) return std::nullopt;
        std::reverse(out.begin(), out.end());
        return out;
    }

    // cum_work(tip) - cum_work(fork) when `fork` is an ancestor of `tip`.
    std::optional<::c2pool::xmr::native::U128> work_after(const Hash32& fork, const Hash32& tip) const {
        if (!path(fork, tip)) return std::nullopt;
        return rt_wide::u128_sub(find(tip)->cum_work, find(fork)->cum_work);
    }

    // Headers-first: the side headers after `fork` (chain order) with their
    // retarget d as work. pow_ok(header, d) is the caller's PoW check. Headers
    // after the first failed one are marked failed. nullopt: fork not held.
    // A header carries no carried bodies: no receipts_root fold and no S here;
    // both are checked when the carrier is placed with its carried list.
    template <class PowCheck>
    std::optional<std::vector<SideHeader>> check_side_headers(const Hash32& fork,
                                                              std::span<const CarrierAnnounce> headers,
                                                              PowCheck&& pow_ok) const {
        const auto fi = index_.find(fork);
        if (fi == index_.end()) return std::nullopt;
        RetargetWindow w = window_after_index(fi->second);
        Hash32 prev = fork;
        std::uint64_t prev_record = nodes_[fi->second].H;
        bool failed = false;
        std::vector<SideHeader> out;
        out.reserve(headers.size());
        for (const CarrierAnnounce& hdr : headers) {
            SideHeader s;
            s.id = hdr.id;
            if (failed) {
                s.check = HeaderCheck::Failed;
                out.push_back(s);
                continue;
            }
            s.work = w.next_difficulty();
            if (hdr.parent != prev || !carrier_height_admissible(prev_record, hdr.h) || !pow_ok(hdr, s.work)) {
                s.check = HeaderCheck::Failed;
                failed = true;
            } else {
                prev_record = record_height(prev_record, hdr.h);
                w.push(RetargetEntry{s.work, prev_record});
                prev = hdr.id;
            }
            out.push_back(s);
        }
        return out;
    }

    // decide_side_branch against the best tip, for side headers after `fork`.
    template <class PowCheck>
    std::optional<SideBranchDecision> decide_headers(const Hash32& fork, std::span<const CarrierAnnounce> headers,
                                                     PowCheck&& pow_ok, std::uint64_t journal_depth) const {
        const std::optional<std::vector<SideHeader>> side =
                check_side_headers(fork, headers, std::forward<PowCheck>(pow_ok));
        if (!side) return std::nullopt;
        const std::size_t fi = index_.at(fork);
        const CarrierNode& b = best();
        const std::uint64_t fork_depth = b.pos - nodes_[common_ancestor(best_, fi)].pos;
        return decide_side_branch(b.cum_work, b.id, nodes_[fi].cum_work, *side, fork_depth, journal_depth);
    }

    // The switch from the applied tip (the journal's tip) to the best tip.
    template <class Record>
    std::optional<SwitchPlan> plan_switch(const Hash32& applied_tip, const RewindJournal<Record>& j) const {
        const auto ai = index_.find(applied_tip);
        if (ai == index_.end()) return std::nullopt;
        const std::size_t f = common_ancestor(ai->second, best_);
        SwitchPlan plan;
        plan.fork = nodes_[f].id;
        plan.fork_position = nodes_[f].pos;
        plan.undo_depth = nodes_[ai->second].pos - nodes_[f].pos;
        plan.verdict = j.verdict_for(plan.fork_position);
        plan.apply = *path(plan.fork, best().id);
        return plan;
    }

private:
    using WaitKey = std::pair<Hash32, Hash32>;  // (carrier id, claimed parent id)

    // S1.3 #10: receipts_root of c against carried_root(ids of `carried`) and S at its parent.
    static FoldVerdict fold_verdict(const RatchetState& parent_rs, const CarrierAnnounce& c,
                                    std::span<const CarriedPlacement> carried) {
        std::vector<Hash32> ids;
        ids.reserve(carried.size());
        for (const CarriedPlacement& r : carried) ids.push_back(r.id);
        return check_carried_fold(c.receipts_root, ids, parent_rs);
    }

    // The placements at c's position for rs_step step (2): the carried list in
    // its order, each at its credited work (0 when dead), then c at d(c).
    static std::vector<RatchetPlacement> placements_at(std::uint64_t d, const CarrierAnnounce& c,
                                                       std::span<const CarriedPlacement> carried) {
        std::vector<RatchetPlacement> out;
        out.reserve(carried.size() + 1);
        for (const CarriedPlacement& r : carried) out.push_back(RatchetPlacement{r.live ? r.work : 0, r.ballot});
        out.push_back(RatchetPlacement{d, c.ballot});
        return out;
    }

    RetargetWindow window_after_index(std::size_t i) const {
        std::vector<RetargetEntry> rev;
        while (i != 0 && rev.size() < p_.retarget_span) {
            rev.push_back(RetargetEntry{nodes_[i].d, nodes_[i].H});
            i = nodes_[i].parent_index;
        }
        for (auto it = inherited_.rbegin(); it != inherited_.rend() && rev.size() < p_.retarget_span; ++it) {
            rev.push_back(*it);
        }
        std::reverse(rev.begin(), rev.end());
        return RetargetWindow(p_, rev);
    }

    void place_under(std::size_t pi, const CarrierAnnounce& c, std::span<const CarriedPlacement> carried) {
        CarrierNode n;
        n.id = c.id;
        n.parent = c.parent;
        n.pos = nodes_[pi].pos + 1;
        n.h = c.h;
        n.H = record_height(nodes_[pi].H, c.h);
        n.d = window_after_index(pi).next_difficulty();
        n.cum_work = ::c2pool::xmr::native::u128_add(nodes_[pi].cum_work, ::c2pool::xmr::native::U128{n.d, 0});
        n.receipts_root = c.receipts_root;
        n.ballot = c.ballot;
        const std::vector<RatchetPlacement> placed = placements_at(n.d, c, carried);
        StepAt st = rs_step_at(rp_, nodes_[pi].rs, n.pos, placed, table_);
        n.rs = st.s;
        n.activation = st.row;
        n.parent_index = pi;
        const std::size_t idx = nodes_.size();
        nodes_.push_back(std::move(n));
        nodes_[pi].children.push_back(idx);
        index_.emplace(c.id, idx);
    }

    bool mark(const Hash32& id, bool verified, bool bodies) {
        const auto it = index_.find(id);
        if (it == index_.end()) return false;
        CarrierNode& n = nodes_[it->second];
        n.verified = n.verified || verified;
        n.bodies = n.bodies || bodies;
        // chain validity flows down from this carrier
        std::vector<std::size_t> stack{it->second};
        while (!stack.empty()) {
            const std::size_t i = stack.back();
            stack.pop_back();
            CarrierNode& c = nodes_[i];
            if (c.chain_valid || !c.verified || !c.bodies || !nodes_[c.parent_index].chain_valid) continue;
            c.chain_valid = true;
            if (fork_choice_prefers(ChainTip{c.cum_work, c.id}, ChainTip{nodes_[best_].cum_work, nodes_[best_].id})) {
                best_ = i;
            }
            for (std::size_t ch : c.children) stack.push_back(ch);
        }
        return true;
    }

    // true when `id` has a waiting entry under some claimed parent.
    bool waiting_on_any(const Hash32& id) const {
        const auto it = waiting_keys_.lower_bound(WaitKey{id, Hash32{}});
        return it != waiting_keys_.end() && it->first == id;
    }

    // Drops every waiting entry of `id` (its claims of other parents) once id is placed.
    void drop_claims(const Hash32& id) {
        auto it = waiting_keys_.lower_bound(WaitKey{id, Hash32{}});
        while (it != waiting_keys_.end() && it->first == id) {
            const auto wit = waiting_.find(it->second);
            if (wit != waiting_.end()) {
                std::vector<Hash32>& v = wit->second;
                v.erase(std::remove(v.begin(), v.end(), id), v.end());
                if (v.empty()) waiting_.erase(wit);
            }
            it = waiting_keys_.erase(it);
        }
    }

    // The carriers waiting on `parent` (arrival order), no longer waiting.
    std::vector<Hash32> release_waiting(const Hash32& parent) {
        const auto wit = waiting_.find(parent);
        if (wit == waiting_.end()) return {};
        std::vector<Hash32> out = std::move(wit->second);
        waiting_.erase(wit);
        for (const Hash32& id : out) waiting_keys_.erase(WaitKey{id, parent});
        return out;
    }

    // Discards the waiting entries under `parent` when `parent` has no waiting
    // entry of its own, and then those under each discarded carrier that has
    // no other waiting entry left.
    std::vector<Hash32> discard_waiting(const Hash32& parent) {
        std::vector<Hash32> out;
        std::vector<Hash32> stack;
        if (!waiting_on_any(parent)) stack.push_back(parent);
        while (!stack.empty()) {
            const Hash32 p = stack.back();
            stack.pop_back();
            const auto wit = waiting_.find(p);
            if (wit == waiting_.end()) continue;
            const std::vector<Hash32> ids = std::move(wit->second);
            waiting_.erase(wit);
            for (const Hash32& id : ids) {
                waiting_keys_.erase(WaitKey{id, p});
                out.push_back(id);
                if (!waiting_on_any(id)) stack.push_back(id);
            }
        }
        return out;
    }

    std::size_t common_ancestor(std::size_t a, std::size_t b) const {
        while (nodes_[a].pos > nodes_[b].pos) a = nodes_[a].parent_index;
        while (nodes_[b].pos > nodes_[a].pos) b = nodes_[b].parent_index;
        while (a != b) {
            a = nodes_[a].parent_index;
            b = nodes_[b].parent_index;
        }
        return a;
    }

    LaneParams p_;
    RatchetParams rp_;
    EpochTable table_;
    std::vector<RetargetEntry> inherited_;
    std::vector<CarrierNode> nodes_;           // index 0 = genesis; dropped carriers stay, unindexed
    std::map<Hash32, std::size_t> index_;
    std::map<Hash32, std::vector<Hash32>> waiting_;  // waiting carrier ids by claimed parent id
    std::set<WaitKey> waiting_keys_;                 // (carrier id, claimed parent id)
    std::size_t best_ = 0;
};

}  // namespace c2pool::xmr::pathb
