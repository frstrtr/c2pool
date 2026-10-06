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
//   A carrier whose parent is not held waits (Deferred) and is placed when
//   the parent is placed.
//   receipts_root: a carrier's receipts_root must equal
//     sha256d("c2pool-v37-carry" || carried_root || rs_root(S(parent)))
//   with carried_root 0 (a carrier here carries nothing); otherwise
//   FoldMismatch (strike) in place(), after the parent and height checks,
//   and a failed side header. S(c) = rs_step(S(parent), pos(c), {d(c), ballot(c)})
//   (pathb_ratchet_state.hpp); genesis S = epoch 0, rules_cur = the genesis
//   rules digest.
//   Headers-first: an announced side header weighs its retarget d on the
//   side chain; it fails on a parent link that does not continue the side
//   chain, a height below the record of its parent, a receipts_root that
//   does not fold over the side chain's S, or a failed PoW at that d.
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
#include "pathb_ratchet_state.hpp"
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
    RatchetState rs{};         // S after this position
    bool verified = false;     // header checks and PoW at d passed
    bool bodies = false;       // bodies held
    bool chain_valid = false;  // verified and bodies on every carrier back to genesis
    std::size_t parent_index = 0;
    std::vector<std::size_t> children;
};

enum class PlaceVerdict : std::uint8_t { Placed, Deferred, Duplicate, NotCarrier, FoldMismatch };

struct PlaceOutcome {
    PlaceVerdict verdict = PlaceVerdict::Deferred;
    std::vector<Hash32> placed;         // this carrier, then the waiting carriers placed behind it, in order
    std::vector<Hash32> not_carrier;    // waiting carriers with h < H(parent), discarded with their waiting descendants
    std::vector<Hash32> fold_mismatch;  // waiting carriers whose receipts_root does not fold (strike), discarded
                                        // with their waiting descendants
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
    // of position 1. Preconditions: retarget_params_valid(p),
    // ratchet_params_valid(rp).
    CarrierTree(const LaneParams& p, const Hash32& genesis_id, std::uint64_t genesis_height,
                std::span<const RetargetEntry> inherited = {}, const RatchetParams& rp = kRuledRatchetParams,
                const Hash32& genesis_rules_digest = Hash32{})
        : p_(p), rp_(rp) {
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
    std::size_t size() const noexcept { return index_.size(); }
    std::size_t waiting() const noexcept { return waiting_ids_.size(); }
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

    // The receipts_root of a carrier on top of `tip` (carried_root 0).
    std::optional<Hash32> next_receipts_root(const Hash32& tip) const {
        const auto it = index_.find(tip);
        if (it == index_.end()) return std::nullopt;
        return carrier_receipts_root(kNoCarriedRoot, nodes_[it->second].rs);
    }

    PlaceOutcome place(const CarrierAnnounce& c) {
        PlaceOutcome out;
        if (index_.count(c.id) != 0 || waiting_ids_.count(c.id) != 0) {
            out.verdict = PlaceVerdict::Duplicate;
            return out;
        }
        const auto pit = index_.find(c.parent);
        if (pit == index_.end()) {
            waiting_[c.parent].push_back(c);
            waiting_ids_.insert(c.id);
            out.verdict = PlaceVerdict::Deferred;
            return out;
        }
        if (!carrier_height_admissible(nodes_[pit->second].H, c.h)) {
            out.verdict = PlaceVerdict::NotCarrier;
            return out;
        }
        if (!fold_matches(nodes_[pit->second].rs, c)) {
            out.verdict = PlaceVerdict::FoldMismatch;
            return out;
        }
        out.verdict = PlaceVerdict::Placed;
        place_under(pit->second, c);
        out.placed.push_back(c.id);
        // Waiting carriers whose parent is now placed, breadth first.
        for (std::size_t q = 0; q < out.placed.size(); ++q) {
            const auto wit = waiting_.find(out.placed[q]);
            if (wit == waiting_.end()) continue;
            std::vector<CarrierAnnounce> ready = std::move(wit->second);
            waiting_.erase(wit);
            const std::size_t pi = index_.at(out.placed[q]);
            for (const CarrierAnnounce& w : ready) {
                waiting_ids_.erase(w.id);
                if (!carrier_height_admissible(nodes_[pi].H, w.h)) {
                    out.not_carrier.push_back(w.id);
                    discard_waiting(w.id);
                    continue;
                }
                if (!fold_matches(nodes_[pi].rs, w)) {
                    out.fold_mismatch.push_back(w.id);
                    discard_waiting(w.id);
                    continue;
                }
                place_under(pi, w);
                out.placed.push_back(w.id);
            }
        }
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
    template <class PowCheck>
    std::optional<std::vector<SideHeader>> check_side_headers(const Hash32& fork,
                                                              std::span<const CarrierAnnounce> headers,
                                                              PowCheck&& pow_ok) const {
        const auto fi = index_.find(fork);
        if (fi == index_.end()) return std::nullopt;
        RetargetWindow w = window_after_index(fi->second);
        Hash32 prev = fork;
        std::uint64_t prev_record = nodes_[fi->second].H;
        std::uint64_t pos = nodes_[fi->second].pos;
        RatchetState rs = nodes_[fi->second].rs;
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
            if (hdr.parent != prev || !carrier_height_admissible(prev_record, hdr.h) || !fold_matches(rs, hdr)
                || !pow_ok(hdr, s.work)) {
                s.check = HeaderCheck::Failed;
                failed = true;
            } else {
                prev_record = record_height(prev_record, hdr.h);
                w.push(RetargetEntry{s.work, prev_record});
                ++pos;
                const RatchetPlacement own{s.work, hdr.ballot};
                rs = rs_step(rp_, rs, pos, std::span<const RatchetPlacement>(&own, 1));
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
    // receipts_root of c against S at its parent (carried_root 0).
    static bool fold_matches(const RatchetState& parent_rs, const CarrierAnnounce& c) {
        return check_carrier_fold(c.receipts_root, kNoCarriedRoot, parent_rs) == FoldVerdict::Match;
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

    void place_under(std::size_t pi, const CarrierAnnounce& c) {
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
        const RatchetPlacement own{n.d, c.ballot};
        n.rs = rs_step(rp_, nodes_[pi].rs, n.pos, std::span<const RatchetPlacement>(&own, 1));
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

    // Discards the carriers waiting on `parent`, and those waiting on them.
    void discard_waiting(const Hash32& parent) {
        std::vector<Hash32> stack{parent};
        while (!stack.empty()) {
            const Hash32 p = stack.back();
            stack.pop_back();
            const auto wit = waiting_.find(p);
            if (wit == waiting_.end()) continue;
            for (const CarrierAnnounce& w : wit->second) {
                waiting_ids_.erase(w.id);
                stack.push_back(w.id);
            }
            waiting_.erase(wit);
        }
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
    std::vector<RetargetEntry> inherited_;
    std::vector<CarrierNode> nodes_;           // index 0 = genesis; dropped carriers stay, unindexed
    std::map<Hash32, std::size_t> index_;
    std::map<Hash32, std::vector<CarrierAnnounce>> waiting_;  // by parent id
    std::set<Hash32> waiting_ids_;
    std::size_t best_ = 0;
};

}  // namespace c2pool::xmr::pathb
