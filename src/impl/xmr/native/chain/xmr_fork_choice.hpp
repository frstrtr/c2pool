// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_fork_choice.hpp
//
// FORK CHOICE: the rule that picks a chain, and the bounded pool of candidate
// branches it picks from.
//
// THE RULE IS CUMULATIVE DIFFICULTY, RECOMPUTED. monerod switches iff the
// alternative's cumulative difficulty is STRICTLY greater than the main chain's
// (handle_alternative_block); equality keeps what we already have. This node
// applies the same rule to a number it computed itself: every candidate block's
// difficulty is derived from the 735-row window ON THAT BRANCH and summed onto
// its parent. The peer's `cumulative_difficulty_hint` and `weights_claimed_hint`
// are recorded for scheduling and for catching an obvious liar early -- they are
// never the input to this decision. That distinction is the whole reason a
// lightweight node can be trusted with a fork choice at all: work is the only
// thing an attacker cannot forge, and a claim about work is not work.
//
// THE ONE DELIBERATE DIVERGENCE (D-14 PREFER-OWN). At EQUAL cumulative
// difficulty at the same height, monerod keeps the block it saw first; this node
// prefers a block it mined itself. What is being chosen is which valid tip to
// BUILD ON, not what the network settles -- the network still decides that -- and
// building on our own tip is what makes our next block extend our own work
// instead of a stranger's. The honest cost is written down rather than hidden:
// if the network saw the rival first, our next block carries a real orphan risk,
// which is why fast block relay is the lever that makes prefer-own pay.
//
// THE POOL IS BOUNDED, ON PURPOSE. Alt branches are memory a stranger can ask us
// to spend, so the pool has a block cap AND a byte cap, and when it is full the
// lightest branch is evicted first: an attacker's cheap branch loses to a real
// one because the ordering is by accumulated work, not by arrival. A branch we
// cannot link to anything we know is not stored as a branch at all -- it is an
// orphan waiting for its parent, with its own smaller cap.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native {

// --- the decision ---------------------------------------------------------------
struct BranchTip {
    Hash          id{};
    std::uint64_t height = 0;
    U128          cumulative_difficulty{};
    bool          own_mined = false;
    std::uint64_t first_seen_seq = 0;   // monotone arrival counter, for first-seen
};

enum class ForkAction : std::uint8_t { Keep = 0, Switch = 1 };

struct ForkDecision {
    ForkAction  action = ForkAction::Keep;
    const char* reason = "";
};

// D-14 is a policy flag rather than a constant so that the tie-break can be
// turned off for a parity run against monerod, where first-seen is the behaviour
// being compared.
enum class TieBreak : std::uint8_t { FirstSeen = 0, PreferOwn = 1 };

inline ForkDecision fork_choice(const BranchTip& best, const BranchTip& candidate,
                                TieBreak tie = TieBreak::PreferOwn) noexcept {
    if (u128_greater(candidate.cumulative_difficulty, best.cumulative_difficulty))
        return ForkDecision{ForkAction::Switch, "candidate carries strictly more work"};

    if (u128_less(candidate.cumulative_difficulty, best.cumulative_difficulty))
        return ForkDecision{ForkAction::Keep, "candidate carries less work"};

    // Equal work from here on.
    if (tie == TieBreak::PreferOwn && candidate.own_mined && !best.own_mined)
        return ForkDecision{ForkAction::Switch, "equal work, D-14 prefer-own"};

    return ForkDecision{ForkAction::Keep, "equal work, first-seen kept"};
}

// --- a candidate block ------------------------------------------------------------
struct AltBlock {
    Hash          id{};
    Hash          prev_id{};
    std::uint64_t height = 0;

    // Recomputed on the branch, never a peer's claim. `resolved` says whether we
    // have been able to compute them yet (a block whose parent is still unknown
    // has a height and nothing else).
    U128 difficulty{};
    U128 cumulative_difficulty{};
    bool resolved = false;

    bool pow_verified = false;
    bool own_mined    = false;

    // Has this block passed the proof-of-work gate (or been explicitly exempted
    // by a run with PoW checking off)? A block that was parked before its
    // difficulty could be computed has NOT, and a branch containing one must not
    // be adopted while the node is fail-closed -- otherwise the cheapest attack
    // on this index would be to feed it a chain bottom-up and have the orphan
    // pool do the adopting.
    bool adoptable = false;

    // The bytes, kept so that adopting this branch needs no refetch, and so that
    // a branch we just left can be adopted again without one. Best effort: a
    // block restored from a snapshot has no entry, and a switch that needs one
    // it does not have is refused rather than guessed.
    BlockEntry entry{};
    bool       has_entry = false;

    // Who gave it to us, so a branch that turns out to be consensus-invalid can
    // be charged to the connection that proposed it rather than to whoever
    // happened to be talking when the switch was attempted.
    PeerRef source{};

    std::uint64_t first_seen_seq = 0;
    std::uint64_t bytes          = 0;

    BranchTip as_tip() const {
        BranchTip t;
        t.id                    = id;
        t.height                = height;
        t.cumulative_difficulty = cumulative_difficulty;
        t.own_mined             = own_mined;
        t.first_seen_seq        = first_seen_seq;
        return t;
    }
};

// --- the pool -----------------------------------------------------------------------
class AltPool {
public:
    void set_caps(std::size_t max_blocks, std::uint64_t max_bytes) {
        max_blocks_ = max_blocks;
        max_bytes_  = max_bytes;
        evict_();
    }

    void clear() {
        blocks_.clear();
        children_.clear();
        bytes_ = 0;
    }

    std::size_t   size()  const noexcept { return blocks_.size(); }
    std::uint64_t bytes() const noexcept { return bytes_; }

    bool contains(const Hash& id) const { return blocks_.count(key_(id)) != 0; }

    const AltBlock* find(const Hash& id) const {
        const auto it = blocks_.find(key_(id));
        return it == blocks_.end() ? nullptr : &it->second;
    }

    AltBlock* find_mut(const Hash& id) {
        const auto it = blocks_.find(key_(id));
        return it == blocks_.end() ? nullptr : &it->second;
    }

    // Insert or replace. Replacement matters: a block first seen as a bodiless
    // announcement is later completed, and a block parked with an unresolved
    // difficulty is resolved once its parent lands.
    bool insert(AltBlock b) {
        const Key k = key_(b.id);
        b.bytes = static_cast<std::uint64_t>(b.entry.block_blob.size());
        for (const TxBlobEntry& t : b.entry.txs) b.bytes += t.blob.size();

        const auto it = blocks_.find(k);
        if (it != blocks_.end()) {
            bytes_ -= it->second.bytes;
            it->second = std::move(b);
            bytes_ += it->second.bytes;
            return true;
        }
        bytes_ += b.bytes;
        children_[key_(b.prev_id)].push_back(k);
        blocks_.emplace(k, std::move(b));
        evict_();
        return blocks_.count(k) != 0;
    }

    void erase(const Hash& id) { erase_key_(key_(id)); }

    // Drop a block and everything descended from it: what a PoW failure or a
    // consensus refusal means for a branch is that the whole branch above the
    // bad block is worthless, and leaving the descendants behind would let the
    // same work be re-proposed forever.
    std::size_t erase_branch(const Hash& id) {
        std::size_t n = 0;
        std::vector<Key> stack{key_(id)};
        while (!stack.empty()) {
            const Key k = stack.back();
            stack.pop_back();
            const auto ch = children_.find(k);
            if (ch != children_.end())
                for (const Key& c : ch->second) stack.push_back(c);
            if (erase_key_(k)) ++n;
        }
        return n;
    }

    // Every candidate the pool is holding, in key order. The accounting layer
    // above needs this to see a same-height race in the branch where our own
    // block stays best: the rival never becomes a mainchain event there, so a
    // consumer fed only by the event stream would report the height uncontested.
    void for_each(const std::function<void(const AltBlock&)>& fn) const {
        for (const auto& kv : blocks_) fn(kv.second);
    }

    std::vector<const AltBlock*> children_of(const Hash& prev_id) const {
        std::vector<const AltBlock*> out;
        const auto it = children_.find(key_(prev_id));
        if (it == children_.end()) return out;
        for (const Key& k : it->second) {
            const auto b = blocks_.find(k);
            if (b != blocks_.end()) out.push_back(&b->second);
        }
        return out;
    }

    // The heaviest resolved candidate in the pool. Ties go to the block seen
    // first, so the pool's own answer is stable; D-14 is applied by the caller,
    // which is the only place that knows what the main chain is.
    const AltBlock* heaviest() const {
        const AltBlock* best = nullptr;
        for (const auto& kv : blocks_) {
            const AltBlock& b = kv.second;
            if (!b.resolved) continue;
            if (!best) { best = &b; continue; }
            if (u128_greater(b.cumulative_difficulty, best->cumulative_difficulty)) best = &b;
            else if (!u128_less(b.cumulative_difficulty, best->cumulative_difficulty)
                     && b.first_seen_seq < best->first_seen_seq) best = &b;
        }
        return best;
    }

    // Walk from `tip_id` down its prev-links until a block that `on_main` accepts
    // (the fork point's parent, which is on the best chain). Fills `out` oldest
    // first. Fails -- rather than returning a partial branch -- when the chain of
    // parents leaves the pool without reaching the main chain, or when it is
    // longer than `max_depth`.
    // Why a branch could not be assembled. The two failures are different
    // stories -- a gap in what we hold, versus a chain longer than we are
    // willing to reorganise -- and the journal reports them apart.
    enum class BranchWalk : std::uint8_t { Ok = 0, Broken, TooDeep };

    BranchWalk branch_to_main(const Hash& tip_id,
                              const std::function<bool(const Hash&)>& on_main,
                              std::size_t max_depth,
                              std::vector<const AltBlock*>& out,
                              Hash& fork_parent_id,
                              std::string& why) const {
        out.clear();
        why.clear();
        Hash cursor = tip_id;
        while (out.size() <= max_depth) {
            const AltBlock* b = find(cursor);
            if (!b) {
                why = "branch walk left the alt pool before reaching the best chain";
                out.clear();
                return BranchWalk::Broken;
            }
            out.push_back(b);
            if (on_main(b->prev_id)) {
                fork_parent_id = b->prev_id;
                std::reverse(out.begin(), out.end());
                return BranchWalk::Ok;
            }
            cursor = b->prev_id;
        }
        why = "branch is longer than the bounded reorg horizon of "
            + std::to_string(max_depth) + " blocks";
        out.clear();
        return BranchWalk::TooDeep;
    }

private:
    using Key = std::string;

    static Key key_(const Hash& h) {
        return Key(reinterpret_cast<const char*>(h.data()), h.size());
    }

    bool erase_key_(const Key& k) {
        const auto it = blocks_.find(k);
        if (it == blocks_.end()) return false;
        bytes_ -= it->second.bytes;
        const Key pk = key_(it->second.prev_id);
        const auto ch = children_.find(pk);
        if (ch != children_.end()) {
            for (std::size_t i = 0; i < ch->second.size(); ++i) {
                if (ch->second[i] == k) {
                    ch->second.erase(ch->second.begin() + static_cast<long>(i));
                    break;
                }
            }
            if (ch->second.empty()) children_.erase(ch);
        }
        blocks_.erase(it);
        children_.erase(k);
        return true;
    }

    // Evict the lightest branch first: an unresolved block (no work proven at
    // all) before any resolved one, then the smallest cumulative difficulty,
    // then the oldest arrival.
    void evict_() {
        while ((max_blocks_ && blocks_.size() > max_blocks_)
               || (max_bytes_ && bytes_ > max_bytes_)) {
            const AltBlock* victim = nullptr;
            for (const auto& kv : blocks_) {
                const AltBlock& b = kv.second;
                if (!victim) { victim = &b; continue; }
                if (victim->resolved && !b.resolved) { victim = &b; continue; }
                if (victim->resolved != b.resolved) continue;
                if (u128_less(b.cumulative_difficulty, victim->cumulative_difficulty))
                    victim = &b;
                else if (!u128_greater(b.cumulative_difficulty, victim->cumulative_difficulty)
                         && b.first_seen_seq < victim->first_seen_seq) victim = &b;
            }
            if (!victim) return;
            erase_key_(key_(victim->id));
        }
    }

    std::map<Key, AltBlock>            blocks_;
    std::map<Key, std::vector<Key>>    children_;
    std::uint64_t                      bytes_      = 0;
    std::size_t                        max_blocks_ = 512;
    std::uint64_t                      max_bytes_  = 32ull * 1024ull * 1024ull;
};

} // namespace c2pool::xmr::native
