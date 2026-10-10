// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_join.hpp
// Path B, slice S3b-4b: the joiner (S3.1a; C43; INV-31, INV-32).
//
//   A join attempt is one (candidate, server) pair: every request goes to the
//   attempt's server (JoinLink; the transport times each request by the
//   abandon timeout, P-53, given to the Joiner, no default here).
//     L          the server's best tip in its reply to the attempt's first
//                FC_GETHEADERS (with the claimed position of its first
//                header); A's bound-work profile is read in the same step.
//     scope      at a node with an adopted state A: the fork of L with A from
//                the header hash links before any body; L held by A, or a
//                fork above A's x1 and at or above A's base: the attempt ends,
//                the pair dropped.
//     span       span_bounds (pathb_joiner.hpp): x0, x1 at L'; the young
//                chain [1, L] from the genesis state, no claim.
//     fetch A    at = c_x0: the peaks at lc(H(x0 - 1)) and S_{x0-1}
//                (S_parent(c_x0), folded with c_x0's receipts_root); on demand
//                the buckets of bins below lc(H(x0 - 1)).
//     fetch B    at = c_L: the bins H(x0 - 1) - F < b <= min(H(L - 1) - F,
//                H(x0 - 1) + Fresh); no fetch at a child of L.
//     prefix     the claimed retarget prefix [x_pre, x0 - 1] (ruling 53,
//                E-99): x_pre = pre_start(x0) (pathb_joiner.hpp); its headers
//                hash-linked, no PoW; below x0 - N_rt asked one record at a time
//                (the record the formula reads next).
//     replay     x0 .. L through admit_carrier with the attempt's JoinClaims
//                (CarrierTree::joined at x0 - 1 with the retarget prefix as its
//                window and its nodes [x_pre, x0 - 2], BinStore::joined with the
//                adopt bound, AR seeded by the joiner row (S_{x0-1}.epoch_cur,
//                x0 - 1, S_{x0-1}.rules_cur)); every mmr_root of [x0, x1]
//                compared with the joined MMR. A walked branch forking at a
//                prefix node f (r's tip branch and the closure's) takes S(f)
//                and the claimed view at f from one FC_GETBUCKETS at its first
//                carrier (ruling 47, E-83; ruling 53, E-100); a bin sealed on
//                such a branch from a served bucket at its next carrier.
//   The attempt ends on: completion at L; an alarm on a claim (the server
//   excluded); the server not serving (a not-served reply, no reply within the
//   timeout, a short FC_HEADERS / FC_GETCARRIER reply; the pair to the end of
//   the queue); the server contradicting itself (excluded); a span carrier
//   that cannot be placed with nothing left to fetch (excluded).
//   Candidates (E-77 as ruling 45 amends it): the first completed attempt is
//   adopted; a completed candidate replaces the adopted chain when its work
//   bound by computed S1.3 #9 at the Monero heights from h_f up is greater
//   (equal: the lower tip id), h_f = the greater of the two bound parts'
//   lowest heights. The attempt order is a queue of (candidate, server)
//   pairs in the order of first offer (P-52).
//   Two states: the adopted state A and the state of the running attempt,
//   each with its own tree, store, AR, header index, window and key caches; an
//   attempt never changes A; an ended attempt leaves nothing.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128, u128_add, u128_less, u128_greater

#include "pathb_admit.hpp"
#include "pathb_bucket_wire.hpp"
#include "pathb_emission.hpp"  // kHf16
#include "pathb_joiner.hpp"

namespace c2pool::xmr::pathb {

using ::c2pool::xmr::native::U128;

// ---------------------------------------------------------------------------
// Bound work (E-77 as ruling 45 amends it): Monero height h(c) -> the sum of
// d of the carriers there whose S1.3 #9 this node computed (receipts never
// count). A sum of at most 2^64 - 1 terms of at most 2^64 - 1 each is below
// 2^128: no wrap.
// ---------------------------------------------------------------------------
static_assert(sizeof(std::uint64_t) * 2 == sizeof(U128::lo) + sizeof(U128::hi),
              "bound work: u64 terms summed in 128 bits");

struct BoundWork {
    std::map<std::uint64_t, U128> at;

    void add(std::uint64_t h, std::uint64_t d) { at[h] = ::c2pool::xmr::native::u128_add(at[h], U128{d, 0}); }
    std::optional<std::uint64_t> lowest() const {
        if (at.empty()) return std::nullopt;
        return at.begin()->first;
    }
    std::optional<std::uint64_t> highest() const {
        if (at.empty()) return std::nullopt;
        return at.rbegin()->first;
    }
    // The work at the heights from h_f up.
    U128 from(std::uint64_t h_f) const {
        U128 w{};
        for (auto it = at.lower_bound(h_f); it != at.end(); ++it) w = ::c2pool::xmr::native::u128_add(w, it->second);
        return w;
    }
};

// a - b where b is a part of the sum a (a term this profile added earlier): no borrow out of 128 bits.
inline constexpr U128 bound_work_minus(const U128& a, const U128& b) noexcept {
    return U128{a.lo - b.lo, a.hi - b.hi - (a.lo < b.lo ? std::uint64_t{1} : std::uint64_t{0})};
}

// Rule (4) of ruling 44 as ruling 45 reads it: a completed candidate C
// replaces the adopted chain A when C's bound work from h_f up is greater
// than A's from h_f up, h_f = the greater of the two bound parts' lowest
// heights; equal: the lower tip id. A bound part wholly below h_f has 0.
inline bool candidate_replaces(const BoundWork& c, const Hash32& c_tip, const BoundWork& a, const Hash32& a_tip) {
    const std::optional<std::uint64_t> lc = c.lowest(), la = a.lowest();
    if (!lc) return false;
    if (!la) return true;
    const std::uint64_t h_f = std::max(*lc, *la);
    const U128 wc = c.from(h_f), wa = a.from(h_f);
    if (::c2pool::xmr::native::u128_greater(wc, wa)) return true;
    if (::c2pool::xmr::native::u128_less(wc, wa)) return false;
    return c_tip < a_tip;
}

// ---------------------------------------------------------------------------
// The attempt's link to its server (S4w-a binds it to the family-C frames).
// Every request carries the abandon timeout; the transport ends a reply when
// no frame of it arrives within that time (the timer restarted per frame).
// ---------------------------------------------------------------------------
enum class LinkStatus : std::uint8_t {
    Served,     // the reply's frames
    NotServed,  // a not-served answer
    NoReply,    // no frame within the abandon timeout
};

// FC_HEADERS: the server's chain ending at the request's stop, oldest first,
// and the position of its first header as the server claims it.
struct ChainHeaders {
    LinkStatus status = LinkStatus::NoReply;
    std::uint64_t first_pos = 0;
    std::vector<CarrierHeader> headers;
};

// FC_CARRIER frames answering FC_GETCARRIER.
struct CarrierFrames {
    LinkStatus status = LinkStatus::NoReply;
    std::vector<CarrierBodyV3> bodies;
};

// FC_BUCKETS frames answering one FC_GETBUCKETS, in arrival order.
struct BucketFrames {
    LinkStatus status = LinkStatus::NoReply;
    std::vector<std::vector<std::uint8_t>> frames;
};

class JoinLink {
public:
    virtual ~JoinLink() = default;
    // The server (its peer id).
    virtual std::uint64_t peer() const = 0;
    // FC_GETHEADERS: the at most `max` headers of the server's chain ending at
    // `stop` (zero: the server's best tip).
    virtual ChainHeaders headers(const Hash32& stop, std::uint64_t max, std::uint64_t timeout_s) = 0;
    // FC_GETCARRIER: n <= 1 + R_MAX ids.
    virtual CarrierFrames carriers(const std::vector<Hash32>& ids, bool want_bodies, std::uint64_t timeout_s) = 0;
    // FC_GETBUCKETS.
    virtual BucketFrames buckets(const GetBuckets& q, std::uint64_t timeout_s) = 0;
};

// ---------------------------------------------------------------------------
// The serving side of a join (P-51, policy, the flags of S4w-a): what a
// server keeps for joins at its best tip L, and the floor it holds for an
// open join attempt.
// ---------------------------------------------------------------------------
struct JoinServeFloors {
    std::uint64_t bodies = 0;   // bodies, tree nodes, side headers and views from x0(L') - J_0 - 1
    std::uint64_t headers = 0;  // carrier headers from the claimed prefix start x_pre(L') (ruling 53, E-102), with the
                                // record that fixes it (pre_start's read_lo)
};

// The floors at the server's best tip L (rec: H on its best chain).
// b0 enables the serving note of ruling 47's record (P-51): while no bin is
// sealed at or before the body floor (lc(H(x0(L') - J_0 - 1)) = 0) the node
// keeps bodies and headers from position 1 (floors {0, 0}). That covers the
// young chain (lc(H(x0 - 1)) = 0, E-79) and the young path of a side branch
// with no sealed bin (E-83), so both are servable at the default retention.
// The header floor (ruling 53, E-102): the claimed prefix start x_pre(L')
// and the record below it that fixes it (pre_start's read_lo); 0 (position 1
// on) where x0 <= N_rt.
template <class Rec>
inline JoinServeFloors join_serve_floors(const LaneParams& p, std::uint64_t L, Rec&& rec, std::uint64_t b0 = 0) {
    const SpanResult s = span_bounds(p, L, rec, b0);
    if (s.status != SpanStatus::Ok || s.bounds.young) return JoinServeFloors{0, 0};
    const std::uint64_t j0 = journal_j0(p, kSealDepth);
    const std::uint64_t x0 = s.bounds.x0;
    const std::uint64_t nrt = join_n_rt(p);
    const std::uint64_t body = x0 > j0 + 1 ? x0 - j0 - 1 : 0;
    if (b0 != 0) {  // no bin sealed at or before the body floor: everything from position 1
        const std::optional<std::uint64_t> hf = rec(body);
        if (hf && bin_leaf_count(*hf, b0, p.open_bins) == 0) return JoinServeFloors{0, 0};
    }
    if (x0 <= nrt) return JoinServeFloors{body, 0};
    const PreStart ps = pre_start(p, x0, rec);
    return JoinServeFloors{body, ps.status == SpanStatus::Ok ? ps.read_lo : x0 - nrt};
}

// The hold of a serving node (P-51 as corrected): the floor taken at its best
// tip when it answered an attempt's first request is held while that
// attempt's requests continue; no request within the abandon timeout ends
// the hold; a request for an item the attempt was already served, or for one
// above the attempt's L, does not continue it; one hold per connection (its
// newest attempt's).
class JoinServeHold {
public:
    // The attempt's first request (FC_GETHEADERS of the server's best tip):
    // the hold starts with the floors at that tip.
    void first(std::uint64_t conn, std::uint64_t now_s, std::uint64_t L, const JoinServeFloors& f) {
        Hold h;
        h.floors = f;
        h.L = L;
        h.last_s = now_s;
        holds_[conn] = std::move(h);
    }

    // A later request of the attempt on `conn` for the item `item` at
    // position `pos`: the floors that apply (`current` when no hold is open).
    JoinServeFloors request(std::uint64_t conn, std::uint64_t now_s, const Hash32& item, std::uint64_t pos,
                            const JoinServeFloors& current, std::uint64_t timeout_s) {
        const auto it = holds_.find(conn);
        if (it == holds_.end()) return current;
        Hold& h = it->second;
        if (now_s > h.last_s && now_s - h.last_s > timeout_s) {  // no request within the timeout: the hold ended
            holds_.erase(it);
            return current;
        }
        const bool repeated = !h.served.insert(item).second;
        if (!repeated && pos <= h.L) h.last_s = now_s;  // continues the hold
        return h.floors;
    }

    bool holding(std::uint64_t conn) const { return holds_.count(conn) != 0; }
    void close(std::uint64_t conn) { holds_.erase(conn); }

private:
    struct Hold {
        JoinServeFloors floors;
        std::uint64_t L = 0;
        std::uint64_t last_s = 0;
        std::set<Hash32> served;
    };
    std::map<std::uint64_t, Hold> holds_;
};

// ---------------------------------------------------------------------------
// The inputs of every attempt: the pool identity, the tables and parameters,
// the follower view and the node's functors (S4w-a's). Nothing of the node's
// old store, pending set or tree.
// ---------------------------------------------------------------------------
struct JoinInputs {
    LaneParams p = kRuledLaneParams;
    RatchetParams rp = kRuledRatchetParams;
    EpochTable T;
    Hash32 pool_id{};
    std::uint64_t b0 = 0;                    // H(0) = b0
    Hash32 genesis_prev{};                   // P_0: the pool identity's Monero block
    Hash32 rules_g{};                        // G: S_0 = genesis_ratchet_state(G)
    std::uint64_t journal_depth = 0;         // P-01 of the joined store; the max of one FC_GETHEADERS
    const FollowerBranchView* monero = nullptr;
    XmrKeyRef author;
    RelayBuffers buffers{};                  // P-10, P-11
    std::uint64_t headers_frame_bytes = 0;   // what one FC_HEADERS frame holds (P-14, the caller's)
    std::uint64_t bucket_frame_bytes = 0;    // P-39
    std::uint32_t chain_id = 0;
    std::function<PrInfo(const Hash32& p_r)> resolve_pr;
    std::function<std::optional<Hash32>(const Hash32& p_r)> seed_of;
    std::function<bool(const HashingBlob&, std::uint64_t d, const Hash32& seed)> randomx;
    // FB_GETCTX of a Monero block from any peer into the follower within the
    // timeout (data any peer may serve); true: now held.
    std::function<bool(const Hash32& id, std::uint64_t timeout_s)> fetch_context;
};

// ---------------------------------------------------------------------------
// The open-bin placements of a store's best chain at its tip (the lost count
// of a switch by the joiner path: the abandoned chain's placements whose
// origin bin is open, none of them re-pended).
// ---------------------------------------------------------------------------
inline std::uint64_t open_bin_placements(const BinStore& store) {
    const LaneView v = store.view_at(store.best_tip());
    if (!v.ok()) return 0;
    std::uint64_t n = 0;
    const std::uint64_t H = v.record(v.pos());
    const std::uint64_t F = store.params().open_bins;
    for (std::uint64_t b = H > F ? H - F + 1 : store.b0(); b <= H + store.params().fresh_max; ++b)
        n += v.live_entries(b, v.pos()).size();
    return n;
}

// ---------------------------------------------------------------------------
// The adopted state A as an attempt sees it (3.3a (4), (6)).
// ---------------------------------------------------------------------------
class AdoptedChain {
public:
    virtual ~AdoptedChain() = default;
    // id is a node of A's tree (its best chain or a side branch)
    virtual bool holds(const Hash32& id) const = 0;
    // id lies on A's best chain (the fork of a candidate with A is its newest header there)
    virtual bool on_chain(const Hash32& id) const = 0;
    virtual std::optional<std::uint64_t> pos_of(const Hash32& id) const = 0;
    virtual std::optional<std::uint64_t> joined_x1() const = 0;  // a joined chain's x1; nullopt: a full node's own
    virtual std::uint64_t store_base() const = 0;                // the one depth measure (Part A 1.4)
    // A's bound-work profile; the instance is shared with its readers and never
    // changes after it is returned (A's later placements make a new one).
    virtual std::shared_ptr<const BoundWork> bound_work() const = 0;
    virtual Hash32 tip() const = 0;
    // the open-bin placements of A's best chain (the lost count when A is replaced)
    virtual std::uint64_t open_placements() const = 0;
};

class JoinedState;

// ---------------------------------------------------------------------------
// JoinClaims: the claim view of a joined state (the extension point of
// pathb_claim_view.hpp, answered for a join).
//   during the replay of [x0, L]:
//     Epoch, Fold, OriginBin, Dedup, Live  ClaimSpan for x <= x1 + 1 (the
//              span state, the AR row of S_{x0-1}, the records and placements
//              of the span carriers at x <= x1, bound by the first computed #9)
//     Retarget ClaimSpan for x <= x1 + N_rt (a d_at window holding the
//              retarget prefix or a span carrier at x <= x1)
//     Coinbase NotComputed for tips below x1; ClaimSpan at x1 and where the
//              window reads a leaf adopted at an at header (c_x0; c_L before L)
//     Roots    NotComputed for tips below x1; else ClaimSpan (c_x0's peaks)
//     Walk     Computed: a Boundary / Closure decided on the server's
//              variants ends the attempt as an unplaceable span carrier
//     a tip on a side branch forking at a prefix node below the root (ruling
//              53, E-100, E-101): ClaimSpan; Coinbase and Roots NotComputed
//              where the window at the tip reads a bin open at f (H(t) <
//              H(f) + F + Fresh) or a bin sealed at the tip that no carrier of
//              the branch serves (placements below x0 are claims, none held)
//   after L: Coinbase ClaimLeaf where the window reads an adopted leaf, Roots
//     ClaimLeaf (the mmr_root commits the adopted leaves), Computed otherwise.
//   The young chain: Computed everywhere.
//   judge_copy: during the replay the attempt's server only; after L every
//   peer. leaf_servable: no adopted leaf, nothing before the first computed
//   #9. at_servable: a carrier whose own #9 this node computed (above x1).
// ---------------------------------------------------------------------------
class JoinClaims final : public ClaimView {
public:
    enum class Phase : std::uint8_t { Replay, AfterL };

    explicit JoinClaims(JoinedState& st) : st_(&st) {}

    void set_phase(Phase p) noexcept { phase_ = p; }
    Phase phase() const noexcept { return phase_; }

    Basis basis(RowClass k, const Hash32& tip, std::uint64_t x) const override;
    Basis base_basis(RowClass k, const Hash32& tip, std::uint64_t x) const;
    Basis header_binding(const Hash32& id, const Hash32& header_digest) const override;
    bool judge_copy(std::uint64_t peer, const Hash32& object_digest) const override;
    bool leaf_servable(std::uint64_t bin) const override;
    bool at_servable(const Hash32& at_id, const Hash32& at_digest) const override;
    bool rests_on_claims() const override { return phase_ == Phase::Replay; }

private:
    JoinedState* st_;
    Phase phase_ = Phase::Replay;
};

// The at header a leaf was proved against (3.4: kept by id and digest).
struct AtHeader {
    Hash32 id{};
    Hash32 digest{};
    friend bool operator==(const AtHeader&, const AtHeader&) = default;
};

// ---------------------------------------------------------------------------
// JoinedState: the state of one attempt, and after its completion the
// adopted state A (3.3a). Each owns its tree, store, AR, header index, bodies,
// references and its own window and key cache instances.
// ---------------------------------------------------------------------------
class JoinedState final : public AdoptedChain {
public:
    JoinedState(const JoinInputs& in, std::uint64_t server) : in_(&in), server_(server), claims_(*this) {
        windows_ = &own_windows_;
        keys_ = &own_keys_;
    }
    JoinedState(const JoinedState&) = delete;
    JoinedState& operator=(const JoinedState&) = delete;

    // ---- the span ----
    bool young = false;
    std::uint64_t x0 = 1;
    std::uint64_t x1 = 1;
    std::uint64_t L = 0;
    Hash32 root_prev{};  // P_t of the root (the genesis node: P_0)

    std::optional<CarrierTree> tree;
    std::optional<BinStore> store;
    ActivationRecord ar;
    HeaderIndex headers;
    CarrierBodies bodies;
    std::map<Hash32, XmrKeyRef> refs;          // served references and the span bodies' references
    AlarmSink alarm;
    std::map<std::uint64_t, AtHeader> claimed;  // adopted (claimed) leaves: bin -> the at header it was proved against

    // counters (JoinResult)
    std::uint64_t full_bodies = 0;   // bodies whose every row ran (tips at or above x1)
    std::uint64_t span_claims = 0;   // bodies with a tip below x1 (D35)
    // The pending set of the result: EMPTY (a switch by the joiner path holds
    // no abandoned placement and re-pends none; ruling 40).
    std::vector<Placement> pending;

    std::uint64_t server() const noexcept { return server_; }
    const JoinInputs& inputs() const noexcept { return *in_; }
    JoinClaims& claims() noexcept { return claims_; }
    const JoinClaims& claims() const noexcept { return claims_; }
    WindowCache& windows() noexcept { return *windows_; }
    KeyCache& keys() noexcept { return *keys_; }
    // The cache instances this state uses (its own unless set otherwise).
    void use_caches(WindowCache& w, KeyCache& k) noexcept {
        windows_ = &w;
        keys_ = &k;
    }

    // P_t of a placed tip.
    std::optional<Hash32> prev_of(const Hash32& tip) const {
        if (tree && tip == tree->genesis().id) return root_prev;
        const CarrierBodyV3* b = bodies.get(tip);
        if (b == nullptr) return std::nullopt;
        return b->own.blob.prev_id;
    }

    AdmitEnv env() {
        return AdmitEnv{*tree,
                        *store,
                        headers,
                        bodies,
                        *in_->monero,
                        *windows_,
                        *keys_,
                        [this](const Hash32& id) -> std::optional<XmrKeyRef> {
                            const auto it = refs.find(id);
                            if (it == refs.end()) return std::nullopt;
                            return it->second;
                        },
                        in_->author,
                        in_->p,
                        in_->rp,
                        in_->T,
                        ar,
                        in_->pool_id,
                        admit_j0(in_->p),
                        in_->buffers,
                        root_prev,
                        in_->resolve_pr,
                        in_->seed_of,
                        in_->randomx,
                        alarm,
                        &claims_};
    }

    // The references a body brings (its payee and owner keys).
    void learn_refs(const ReceiptBodyV3& r) {
        refs.emplace(r.side.payee, r.payee);
        if (r.owner && !(r.side.owner == kZeroHash)) refs.emplace(r.side.owner, *r.owner);
    }

    // The window at a tip at hf 16 reads a leaf adopted from a served bucket.
    bool window_reads_claimed(const Hash32& tip) {
        if (!store || !tree || claimed.empty()) return false;
        const std::optional<Hash32> pt = prev_of(tip);
        if (!pt) return false;
        const Hash32 author_id = key_ref_identity(in_->author);
        const TipWindow tw = windows_->get(
                tip, kHf16, [&] { return evaluate_window_at(*store, tip, *pt, *in_->monero, kHf16, author_id); });
        if (!tw.ok() || tw.oldest_bin == 0) return false;
        return tw.oldest_bin <= claimed.rbegin()->first;
    }
    bool has_claimed_leaves() const noexcept { return !claimed.empty() || (store && store->first_leaf() > 0); }

    // ---- AdoptedChain ----
    bool holds(const Hash32& id) const override { return tree && tree->find(id) != nullptr; }
    bool on_chain(const Hash32& id) const override {
        const std::optional<std::uint64_t> p = pos_of(id);
        return p && store && store->best_at(*p) == id;
    }
    std::optional<std::uint64_t> pos_of(const Hash32& id) const override {
        if (!tree) return std::nullopt;
        const CarrierNode* n = tree->find(id);
        if (n == nullptr) return std::nullopt;
        return n->pos;
    }
    std::optional<std::uint64_t> joined_x1() const override { return young ? std::uint64_t{0} : x1; }
    std::uint64_t store_base() const override { return store ? store->base_pos() : 0; }
    Hash32 tip() const override { return store ? store->best_tip() : Hash32{}; }
    // The carriers whose S1.3 #9 this node computed: x1 + 1 .. its best tip
    // ([1, tip] on a young chain), each its d at h(c). Kept along the best
    // chain: a position is counted once, a switch recounts only the positions
    // above its fork, and an unchanged chain returns the same instance (a read
    // walks no part of the chain).
    std::shared_ptr<const BoundWork> bound_work() const override {
        sync_profile();
        return profile_;
    }

    // The open-bin placements of the best chain (the lost count of a switch by the joiner path).
    std::uint64_t open_placements() const override { return store ? open_bin_placements(*store) : 0; }

private:
    struct Counted {
        Hash32 id{};
        std::uint64_t h = 0;
        std::uint64_t d = 0;
    };
    // The profile instance to change (a new one while a reader holds it).
    BoundWork& profile_for_write() const {
        if (profile_.use_count() > 1) profile_ = std::make_shared<BoundWork>(*profile_);
        return *profile_;
    }
    void sync_profile() const {
        if (!tree || !store) return;
        const std::uint64_t lo = young ? 1 : x1 + 1;
        const std::uint64_t top = store->tip_pos();
        const std::size_t want = top >= lo ? static_cast<std::size_t>(top - lo + 1) : 0;
        // the counted positions still on the best chain (ids link: the newest match keeps every lower one)
        std::size_t keep = std::min(counted_.size(), want);
        while (keep > 0 && store->best_at(lo + keep - 1) != counted_[keep - 1].id) --keep;
        if (keep == counted_.size() && keep == want) return;
        BoundWork& w = profile_for_write();
        while (counted_.size() > keep) {
            const Counted c = counted_.back();
            counted_.pop_back();
            const auto n = counted_at_.find(c.h);
            if (n == counted_at_.end()) continue;
            if (--n->second == 0) {
                counted_at_.erase(n);
                w.at.erase(c.h);
            } else {
                w.at[c.h] = bound_work_minus(w.at[c.h], U128{c.d, 0});
            }
        }
        for (std::uint64_t x = lo + counted_.size(); x <= top; ++x) {
            const std::optional<Hash32> id = store->best_at(x);
            const CarrierNode* n = id ? tree->find(*id) : nullptr;
            if (n == nullptr) break;
            w.add(n->h, n->d);
            ++counted_at_[n->h];
            counted_.push_back(Counted{*id, n->h, n->d});
        }
    }

    const JoinInputs* in_;
    std::uint64_t server_;
    JoinClaims claims_;
    WindowCache own_windows_;
    KeyCache own_keys_;
    WindowCache* windows_ = nullptr;
    KeyCache* keys_ = nullptr;
    mutable std::vector<Counted> counted_;                       // the best chain's positions lo .. counted so far
    mutable std::map<std::uint64_t, std::uint64_t> counted_at_;  // carriers counted per Monero height
    mutable std::shared_ptr<BoundWork> profile_ = std::make_shared<BoundWork>();
};

inline Basis JoinClaims::basis(RowClass k, const Hash32& tip, std::uint64_t x) const {
    const JoinedState& s = *st_;
    if (s.young) return Basis::Computed;  // the young chain: no claim
    const bool replay = phase_ == Phase::Replay;
    // ruling 53 (E-100, E-101): a tip on a side branch forking at a prefix node below the root reads the claimed
    // view at f during the replay (a claim); its rows that read placements below x0 are not computed
    const CarrierNode* tn = replay && s.tree ? s.tree->find(tip) : nullptr;
    if (tn != nullptr && tn->below_root && !(s.store && s.store->best_at(tn->pos) == tip)) {
        const Basis b = base_basis(k, tip, x);
        if (b == Basis::NotComputed) return b;
        if (k == RowClass::Coinbase || k == RowClass::Roots) {
            const LaneParams& p = s.inputs().p;
            if (tn->H < tn->pre_fork_H + p.open_bins + p.fresh_max) return Basis::NotComputed;  // a bin open at f
            if (s.store && s.store->view_at(tip).pending_bin()) return Basis::NotComputed;     // a bin no carrier serves
        }
        return Basis::ClaimSpan;
    }
    return base_basis(k, tip, x);
}

inline Basis JoinClaims::base_basis(RowClass k, const Hash32& tip, std::uint64_t x) const {
    const JoinedState& s = *st_;
    const bool replay = phase_ == Phase::Replay;
    const std::uint64_t x1 = s.x1;
    switch (k) {
        case RowClass::Walk: return Basis::Computed;
        case RowClass::Epoch:
            // a tip below the root x0 - 1 is a claimed PRE node whose ratchet state the joiner does not hold (ruling 47,
            // E-84): its epoch / H_hold is a claim it does not compute
            if (replay && s.x0 > 1 && x <= s.x0 - 1) return Basis::NotComputed;
            return replay && x <= x1 + 1 ? Basis::ClaimSpan : Basis::Computed;
        case RowClass::Fold:
        case RowClass::OriginBin:
        case RowClass::Dedup:
        case RowClass::Live: return replay && x <= x1 + 1 ? Basis::ClaimSpan : Basis::Computed;
        case RowClass::Retarget:
            // a carried receipt whose tip lies below the root x0 - 1 (ruling 47, E-84): its d_at window lies below the
            // PRE the joiner holds, a claim it does not compute
            if (replay && s.x0 > 1 && x <= s.x0 - 1) return Basis::NotComputed;
            return replay && x <= x1 + s.inputs().p.retarget_span ? Basis::ClaimSpan : Basis::Computed;
        case RowClass::Coinbase:
            if (x <= x1) return Basis::NotComputed;  // a tip below x1 (D35)
            if (replay) return x == x1 + 1 || st_->window_reads_claimed(tip) ? Basis::ClaimSpan : Basis::Computed;
            return st_->window_reads_claimed(tip) ? Basis::ClaimLeaf : Basis::Computed;
        case RowClass::Roots:
            if (x <= x1) return Basis::NotComputed;
            if (replay) return Basis::ClaimSpan;
            return s.has_claimed_leaves() ? Basis::ClaimLeaf : Basis::Computed;
    }
    return Basis::Computed;
}

inline Basis JoinClaims::header_binding(const Hash32& id, const Hash32& header_digest) const {
    const JoinedState& s = *st_;
    if (s.young || !s.tree) return Basis::Computed;
    if (const CarrierNode* n = s.tree->find(id); n != nullptr) return n->pos <= s.x1 ? Basis::NotComputed : Basis::Computed;
    const HeaderVariant* y = s.headers.variant(id, header_digest);
    if (y == nullptr) return Basis::NotComputed;
    const CarrierNode* pn = s.tree->find(y->header.own.side.tip);
    return pn == nullptr || pn->pos < s.x1 ? Basis::NotComputed : Basis::Computed;  // a parent below x1 (or below x0 - 1)
}

inline bool JoinClaims::judge_copy(std::uint64_t peer, const Hash32&) const {
    if (phase_ == Phase::AfterL || st_->young) return true;
    return peer == st_->server();
}

inline bool JoinClaims::leaf_servable(std::uint64_t bin) const {
    const JoinedState& s = *st_;
    if (phase_ == Phase::Replay && !s.young) return false;  // nothing before the replay reached L
    if (s.claimed.count(bin) != 0) return false;            // an adopted leaf (a claim)
    if (s.store && bin >= s.store->b0() && bin - s.store->b0() < s.store->first_leaf()) return false;
    return true;
}

inline bool JoinClaims::at_servable(const Hash32& at_id, const Hash32& at_digest) const {
    const JoinedState& s = *st_;
    if (phase_ == Phase::Replay && !s.young) return false;
    if (!s.tree) return false;
    const CarrierNode* n = s.tree->find(at_id);
    if (n == nullptr || (!s.young && n->pos <= s.x1)) return false;  // its own #9 computed here: above x1
    const CarrierBodyV3* b = s.bodies.get(at_id);
    if (b == nullptr) return false;
    const std::optional<Hash32> dg = header_digest(header_of(*b));
    return dg && *dg == at_digest;
}

// ---------------------------------------------------------------------------
// JoinBuckets: the bucket fetches of a join (3.4). One BucketsAssembly per
// (peer, at); inside an attempt every fetch goes to the attempt's server and a
// prefix is continued there from the next bin. BW's refusals that compare a
// reply with a claimed at header (leaf_count, peaks, the MMR proof, the
// S_parent fold) are an alarm and end the attempt, no strike; the refusals of
// the server's own bytes keep their strike.
// ---------------------------------------------------------------------------
enum class BucketsEnd : std::uint8_t {
    Complete,   // every bin of the range received
    NotServed,  // a not-served answer, no reply, or a reply that brought nothing new
    AtClaim,    // a refusal against the claimed at header: alarm, the attempt ends, no strike
    Struck,     // a refusal of the server's own bytes: one strike
};

inline constexpr bool at_header_fault(BucketsFault f) noexcept {
    return f == BucketsFault::LeafCount || f == BucketsFault::Peaks || f == BucketsFault::Proof ||
           f == BucketsFault::SParent;
}

struct BucketsFetch {
    BucketsEnd end = BucketsEnd::NotServed;
    BucketsFault fault = BucketsFault::None;
    std::uint32_t strike = 0;
    std::map<std::uint64_t, ServedBin> bins;
    std::map<Hash32, XmrKeyRef> refs;
    std::optional<std::vector<Hash32>> peaks;  // the peaks of the first accepted frame
    std::uint64_t leaf_count = 0;
    std::optional<RatchetState> s_parent;      // S_parent(at), folded with at's receipts_root
};

class JoinBuckets {
public:
    JoinBuckets(std::uint64_t b0, std::uint64_t F, std::uint64_t frame_bytes, std::uint32_t chain_id)
        : b0_(b0), f_(F), frame_bytes_(frame_bytes), chain_id_(chain_id) {}

    // The bins [bin_lo, bin_hi] at `at` from the link's server.
    BucketsFetch fetch(JoinLink& link, const BucketsAnchor& anchor, const AtHeader& at, std::uint64_t bin_lo,
                       std::uint64_t bin_hi, std::uint64_t timeout_s) {
        BucketsFetch out;
        const std::uint64_t peer = link.peer();
        const Key key{peer, at.id};
        if (closed_.count(key) != 0) return out;  // a refused (peer, at): closed for the join
        std::uint64_t lo = bin_lo;
        while (lo <= bin_hi) {
            const GetBuckets q{chain_id_, at.id, lo, bin_hi};
            auto [it, fresh] = asm_.insert_or_assign(key, BucketsAssembly(q, b0_, f_, frame_bytes_));
            (void)fresh;
            BucketsAssembly& a = it->second;
            const BucketFrames r = link.buckets(q, timeout_s);
            if (r.status == LinkStatus::NotServed || r.frames.empty()) return out;
            bool accepted = false;
            for (const std::vector<std::uint8_t>& f : r.frames) {
                const FrameOutcome o = a.add_frame(peer, f, anchor);
                if (o.verdict == BucketsFrameVerdict::NotServed) return out;
                if (o.verdict == BucketsFrameVerdict::Drop) continue;
                if (o.verdict == BucketsFrameVerdict::Defer) return out;
                if (o.verdict == BucketsFrameVerdict::Refused) {
                    closed_.insert(key);
                    out.fault = o.fault;
                    if (at_header_fault(o.fault)) {
                        out.end = BucketsEnd::AtClaim;
                    } else {
                        out.end = BucketsEnd::Struck;
                        out.strike = o.strike;
                    }
                    return out;
                }
                if (!accepted && !out.peaks) {
                    BucketsFrameView v;
                    if (decode_buckets_view(f, chain_id_, v) == BucketsWireError::None) {
                        out.peaks = v.peaks;
                        out.leaf_count = v.leaf_count;
                    }
                }
                accepted = true;
            }
            if (!accepted) return out;
            const SResolution sr = a.resolve_s(anchor);
            if (!sr.struck.empty()) {  // the S_parent fold against the claimed at header
                closed_.insert(key);
                out.end = BucketsEnd::AtClaim;
                out.fault = BucketsFault::SParent;
                return out;
            }
            if (sr.adopted && !out.s_parent) out.s_parent = sr.adopted;
            for (const auto& [bin, sb] : a.bins()) out.bins.emplace(bin, sb);
            for (const auto& [id, k] : a.refs()) out.refs.emplace(id, k);
            const std::uint64_t got = a.complete_through();
            if (got == lo) return out;  // nothing new: not served
            lo = got;                   // a prefix: continued at the same server from the next bin
        }
        out.end = BucketsEnd::Complete;
        return out;
    }

    // Outside an attempt (a full node's MissingBucket, Part A 3.7a; the E-72
    // re-ask after a join): the peers in turn; NotServed or an ended prefix ->
    // the next peer (the earlier (peer, at) abandoned: its later frames DROP);
    // a refused (peer, at) stays closed. `served_by`: the peer whose reply
    // completed the range.
    BucketsFetch fetch_any(const std::vector<JoinLink*>& peers, const BucketsAnchor& anchor, const AtHeader& at,
                           std::uint64_t bin_lo, std::uint64_t bin_hi, std::uint64_t timeout_s,
                           std::optional<std::uint64_t>* served_by = nullptr) {
        BucketsFetch last;
        for (JoinLink* l : peers) {
            if (l == nullptr || closed(l->peer(), at.id)) continue;
            BucketsFetch f = fetch(*l, anchor, at, bin_lo, bin_hi, timeout_s);
            if (f.end == BucketsEnd::Complete) {
                if (served_by != nullptr) *served_by = l->peer();
                return f;
            }
            abandon(l->peer(), at.id);
            last = std::move(f);
        }
        return last;
    }

    // A late frame of `peer` for `at` (after its request ended): judged by the
    // (peer, at) assembly; a closed or abandoned one DROPs it.
    FrameOutcome late_frame(std::uint64_t peer, const Hash32& at, std::span<const std::uint8_t> frame,
                            const BucketsAnchor& anchor) {
        const auto it = asm_.find(Key{peer, at});
        if (it == asm_.end()) return FrameOutcome{BucketsFrameVerdict::Drop, BucketsFault::Unsolicited};
        return it->second.add_frame(peer, frame, anchor);
    }
    // A request whose reply ended: its later frames DROP.
    void abandon(std::uint64_t peer, const Hash32& at) {
        const auto it = asm_.find(Key{peer, at});
        if (it != asm_.end()) it->second.abandon(peer);
    }
    bool closed(std::uint64_t peer, const Hash32& at) const { return closed_.count(Key{peer, at}) != 0; }

    // ---- the claimed leaves (E-72) and the re-ask (3.4) ----
    // 'Those bins': the claimed leaves whose at header (id and digest) is not a
    // bound carrier of the heavier chain, and those a claim-leaf mismatch
    // entered; each asked at a carrier of that chain whose leaf_count(tip(at))
    // covers the bin (the first such carrier, by position).
    struct Reask {
        std::uint64_t bin = 0;
        Hash32 at{};
    };
    // claimed: bin -> the at header it was proved against; heavier_bound: the
    // carriers of the heavier chain this node has bound (id and digest);
    // heavier: that chain's carriers by position with leaf_count(tip(at)).
    static std::vector<Reask> reask_scope(const std::map<std::uint64_t, AtHeader>& claimed,
                                          const std::vector<AtHeader>& heavier_bound,
                                          const std::set<std::uint64_t>& mismatched,
                                          const std::vector<std::pair<Hash32, std::uint64_t>>& heavier, std::uint64_t b0) {
        std::vector<Reask> out;
        for (const auto& [bin, at] : claimed) {
            const bool bound = std::find(heavier_bound.begin(), heavier_bound.end(), at) != heavier_bound.end();
            if (bound && mismatched.count(bin) == 0) continue;
            for (const auto& [id, lc] : heavier)
                if (lc > bin - b0) {  // leaf_count(tip(at)) covers the bin
                    out.push_back(Reask{bin, id});
                    break;
                }
        }
        return out;
    }

private:
    using Key = std::pair<std::uint64_t, Hash32>;
    std::uint64_t b0_;
    std::uint64_t f_;
    std::uint64_t frame_bytes_;
    std::uint32_t chain_id_;
    std::map<Key, BucketsAssembly> asm_;
    std::set<Key> closed_;
};

// The replay of a claimed leaf's re-ask: the position before the bin's seal,
// and whether it lies below the journal base (then the joiner path).
struct ReaskReplay {
    std::uint64_t from = 0;
    bool joiner_path = false;
};
inline ReaskReplay reask_replay(std::uint64_t seal_pos, std::uint64_t base_pos) {
    const std::uint64_t from = seal_pos > 0 ? seal_pos - 1 : 0;
    return ReaskReplay{from, from < base_pos};
}

// ---------------------------------------------------------------------------
// P-52: the queue of (candidate, server) pairs, in the order of first offer.
// Each pair is attempted once; a non-service re-queues it at the end; an
// alarm, a contradiction or an unplaceable span carrier excludes the server
// with all its pairs in this join; a pair lives while its server is
// connected. Neither claimed work nor the tip id orders.
// ---------------------------------------------------------------------------
class AttemptQueue {
public:
    struct Pair {
        Hash32 candidate{};
        std::uint64_t server = 0;
        U128 claimed_work{};  // the HELLO claim (orders nothing)
        std::uint64_t seq = 0;
        bool young = false;   // the pair runs the young path (the ruling-47 fallback; not attempt state)
    };

    void offer(const Hash32& candidate, std::uint64_t server, const U128& claimed_work = {}) {
        if (excluded_.count(server) != 0) return;
        const Key k{candidate, server};
        if (known_.count(k) != 0) return;  // queued, or attempted once
        known_.insert(k);
        q_.push_back(Pair{candidate, server, claimed_work, ++seq_});
    }

    // The next pair (removed from the queue).
    std::optional<Pair> next() {
        if (q_.empty()) return std::nullopt;
        const auto pick = q_.begin();
        Pair p = *pick;
        q_.erase(pick);
        return p;
    }

    void requeue(const Pair& p) {
        if (excluded_.count(p.server) != 0) return;
        q_.push_back(p);
    }
    void exclude(std::uint64_t server) {
        excluded_.insert(server);
        drop_server(server);
    }
    void disconnect(std::uint64_t server) {
        drop_server(server);
        for (auto it = known_.begin(); it != known_.end();) it = it->second == server ? known_.erase(it) : std::next(it);
    }
    bool excluded(std::uint64_t server) const { return excluded_.count(server) != 0; }
    std::size_t size() const noexcept { return q_.size(); }
    const std::deque<Pair>& pairs() const noexcept { return q_; }

private:
    using Key = std::pair<Hash32, std::uint64_t>;
    void drop_server(std::uint64_t server) {
        q_.erase(std::remove_if(q_.begin(), q_.end(), [&](const Pair& p) { return p.server == server; }), q_.end());
    }
    std::deque<Pair> q_;
    std::set<Key> known_;
    std::set<std::uint64_t> excluded_;
    std::uint64_t seq_ = 0;
};

// ---------------------------------------------------------------------------
// One attempt.
// ---------------------------------------------------------------------------
enum class AttemptEnd : std::uint8_t {
    Completed,      // (i) completion at L
    Alarm,          // (ii) an alarm on a claim: the server excluded
    NotServed,      // (iii) not serving / no reply / a short reply / data any peer may serve not resolved: re-queued
    Contradiction,  // (iv) the server contradicted itself: excluded
    Unplaceable,    // (v) a span carrier that cannot be placed with nothing left to fetch: excluded
    Header,         // the header phase (header checks (4), (5)): the end, the server excluded with all its pairs, no token
    OutOfScope,     // 3.3 step 2a: L held by A, or forking above A's x1 and at or above its base: dropped
    Known,          // 3.3a (5): a completed candidate that did not replace A: dropped
};

inline constexpr bool attempt_excludes(AttemptEnd e) noexcept {
    return e == AttemptEnd::Alarm || e == AttemptEnd::Contradiction || e == AttemptEnd::Unplaceable ||
           e == AttemptEnd::Header;
}

struct AttemptReport {
    AttemptEnd end = AttemptEnd::NotServed;
    std::uint64_t server = 0;
    Hash32 candidate{};
    std::uint64_t L = 0;
    Hash32 tip{};
    std::uint64_t at = 0;                  // the position of the frame the attempt ended on (0: none)
    RowId row = RowId::None;
    std::optional<Missing> missing;
    AdmitVerdict verdict = AdmitVerdict::Defer;
    std::uint32_t strike = 0;              // tokens of computed rows on the server's own bytes
    std::uint64_t alarms = 0;              // local alarms raised (claims, node-internal)
    std::string what;                      // a short reason
    SpanBounds span;
    std::shared_ptr<const BoundWork> a_profile;  // A's bound work, read when the attempt took its L
    bool a_profile_read = false;
    bool force_young = false;              // ruling 47: the next attempt of this pair runs the young path
    std::unique_ptr<JoinedState> state;    // Completed: the attempt's state
};

// The FC_HEADERS 0x53 frame head at frame version 0x02 (ruling 48 JC-3L (a), E-86): FH (opcode, version, chain_id:
// 6 B) | u64 first_pos | u16 n, before the n headers.
inline constexpr std::uint64_t kJoinHeadersFrameHead = kFrameHeaderBytes + sizeof(std::uint64_t) + kU16Bytes;
static_assert(kJoinHeadersFrameHead == 6 + 8 + 2, "the FC_HEADERS v0x02 frame head: FH 6 + first_pos 8 + n 2");

namespace join_detail {

inline std::uint64_t height_of(const JoinInputs& in, const ReceiptBodyV3& r) {
    const PrInfo pr = in.resolve_pr ? in.resolve_pr(r.blob.prev_id) : PrInfo{};
    return pr.status == PrInfo::Status::Held ? pr.height + 1 : 0;
}

inline std::optional<Hash32> digest_of(const CarrierHeader& h) { return header_digest(h); }

// A header's own PoW at its claimed t_origin (the header path of a side variant).
inline bool header_path_ok(const JoinInputs& in, const CarrierHeader& h) {
    const std::optional<Hash32> seed = in.seed_of ? in.seed_of(h.own.blob.prev_id) : std::nullopt;
    return seed && in.randomx && in.randomx(h.own.blob, h.own.side.t_origin, *seed);
}

}  // namespace join_detail

class JoinAttempt {
public:
    JoinAttempt(const JoinInputs& in, JoinLink& link, std::uint64_t timeout_s, const AdoptedChain* adopted,
                std::function<void(JoinedState&, std::uint64_t)> on_step = {})
        : in_(in), link_(link), timeout_(timeout_s), a_(adopted), on_step_(std::move(on_step)),
          jb_(in.b0, in.p.open_bins, in.bucket_frame_bytes, in.chain_id) {}

    AttemptReport run(const Hash32& candidate) {
        rep_.server = link_.peer();
        rep_.candidate = candidate;
        st_ = std::make_unique<JoinedState>(in_, link_.peer());  // its own tree, store, AR, index and caches
        if (!fetch_top()) return finish();
        // 3.3 step 2a: L held by A ends the attempt before any further fetch (any node of A's tree)
        if (a_ != nullptr && rep_.L != 0 && a_->holds(rep_.tip)) return end(AttemptEnd::OutOfScope, "L held by A");
        if (known_ && known_(rep_.tip)) return end(AttemptEnd::Known, "a completed candidate not attempted again");
        if (!scope_on_page()) return finish();  // the fork of L with A's best chain, from the first reply on
        if (!bounds()) return finish();  // pages headers to the retarget-prefix start x0(L') - N_rt (the retarget-prefix floor)
        if (a_ != nullptr && !in_scope()) return finish();  // no candidate header on A's chain down to that floor
        if (!build()) return finish();
        if (!replay()) return finish();
        st_->claims().set_phase(JoinClaims::Phase::AfterL);
        rep_.end = AttemptEnd::Completed;
        rep_.state = std::move(st_);
        return std::move(rep_);
    }

    // The tips of completed candidates kept by tip id (3.3a (5)).
    void set_known(std::function<bool(const Hash32&)> f) { known_ = std::move(f); }
    // The pair's young mark (the ruling-47 fallback): the whole chain [1, L] in full, no claim.
    void set_force_young(bool y) noexcept { force_young_ = y; }

private:
    // ---- the result ----
    AttemptReport finish() { return std::move(rep_); }
    bool fail(AttemptEnd e, const std::string& what) {
        rep_.end = e;
        rep_.what = what;
        rep_.alarms = st_ ? st_->alarm.count() : 0;
        return false;
    }
    AttemptReport end(AttemptEnd e, const std::string& what) {
        fail(e, what);
        return finish();
    }

    // ---- headers (3.3 step 2a; the positions the server claims) ----
    // One FC_GETHEADERS page: at most N_rt headers, so no page asks below the
    // server's P-51 header floor x0(L') - N_rt (every position the span scan
    // needs lies at or above x0 - 1).
    std::uint64_t header_page() const {
        return std::min<std::uint64_t>(std::max<std::uint64_t>(1, in_.journal_depth), join_n_rt(in_.p));
    }
    // what one FC_HEADERS frame can carry: its head at frame version 0x02 is FH | u64 first_pos | u16 n (E-86)
    std::uint64_t frame_fit() const {
        const std::uint64_t max_header = 1 + in_.buffers.receipt + 1 + 2 * sizeof(std::uint64_t);
        const std::uint64_t room = in_.headers_frame_bytes > kJoinHeadersFrameHead
                                           ? in_.headers_frame_bytes - kJoinHeadersFrameHead
                                           : 0;
        return std::max<std::uint64_t>(1, room / max_header);
    }
    // A reply that carries less than the request could carry (ruling 46 S4wa-2 (a)).
    bool short_headers(const ChainHeaders& r, std::uint64_t max, std::uint64_t range) const {
        const std::uint64_t could = std::min({max, range, frame_fit()});
        return r.headers.size() < could;
    }

    // The header phase (RULED 47 (a), RULED 48 (a); E-81, E-87):
    // every FC_HEADERS header of the attempt is checked on arrival, (1)-(4)
    // before (5). A failed (4) or (5) ends the attempt and excludes the server
    // with all its pairs, no token (AttemptEnd::Header); a repeat (2) is a
    // contradiction; an unresolved P_r (3) is non-service. The PRE headers,
    // once x0 is known, stay hash-linked with no PoW (P-43): (5) is skipped for
    // positions below x0.
    bool pow_ok(const CarrierHeader& h) const {
        return h.own.side.t_origin >= in_.p.d_min && join_detail::header_path_ok(in_, h);
    }

    // Adds one reply's headers below what is held; false: the attempt ended.
    bool take_headers(const ChainHeaders& r, const std::optional<Hash32>& stop) {
        if (r.status != LinkStatus::Served || r.headers.empty()) return fail(AttemptEnd::NotServed, "headers not served");
        // (1) the reply must link and end at stop
        for (std::size_t i = 1; i < r.headers.size(); ++i)
            if (r.headers[i].own.side.tip != receipt_id(r.headers[i - 1].own))
                return fail(AttemptEnd::NotServed, "headers do not link");
        if (stop && receipt_id(r.headers.back().own) != *stop) return fail(AttemptEnd::NotServed, "headers do not end at stop");
        if (!hdr_.empty() && r.first_pos + r.headers.size() != lo_pos_)
            return fail(AttemptEnd::Contradiction, "claimed positions contradict");
        // (2)-(4) per header, oldest (lowest position) first; (5) is a separate pass (check_span_pow), run only on
        // the span [x0, L] so the PRE's hash-linked headers (no PoW, P-43) are not rejected before x0 is known.
        std::optional<std::uint64_t> prev_h;
        std::vector<std::uint64_t> page_h;  // h of the page's headers (check (3)): its records
        page_h.reserve(r.headers.size());
        for (std::size_t i = 0; i < r.headers.size(); ++i) {
            const CarrierHeader& h = r.headers[i];
            const Hash32 id = receipt_id(h.own);
            // (2) no id repeats within the attempt's header-phase sequence (the cycle of the review)
            if (!phase_ids_.insert(id).second) return fail(AttemptEnd::Contradiction, "a repeated header id in the header phase");
            // (3) its P_r resolves, else non-service after P-53
            const std::optional<std::uint64_t> hh = h_of(h.own);
            if (!hh) return fail(AttemptEnd::NotServed, "a header's P_r not resolved");
            // (4) h does not decrease along the chain (S1.3 #6)
            if (prev_h && *hh < *prev_h) return fail(AttemptEnd::Header, "h decreases along the header chain");
            prev_h = hh;
            page_h.push_back(*hh);
        }
        // (4) at the page boundary: the existing lowest held header's h >= this page's top h
        if (lo_h_ && prev_h && *lo_h_ < *prev_h) return fail(AttemptEnd::Header, "h decreases at a page boundary");
        lo_h_ = page_h.front();  // h at the new lowest position
        std::vector<CarrierHeader> merged = r.headers;
        merged.insert(merged.end(), hdr_.begin(), hdr_.end());
        hdr_ = std::move(merged);
        // the records, incremental: with (4) in the page and at its boundary every held record above is at least
        // the page's top h, so only the page's own records are new (the running max of h within it)
        std::vector<std::uint64_t> page_rec(page_h.size());
        std::uint64_t H = 0;
        for (std::size_t i = 0; i < page_h.size(); ++i) page_rec[i] = H = std::max(H, page_h[i]);
        records_.insert(records_.begin(), page_rec.begin(), page_rec.end());
        lo_pos_ = r.first_pos;
        return true;
    }

    // (5) RULED 47 (a): the blob's PoW at its own claimed t_origin >= d_min, for every held span header not yet
    // checked. `floor` is x0 once known (the PRE below it stays hash-linked, no PoW), else lo_pos_ (every held header
    // is a candidate until x0 is resolved, so a no-PoW server is caught at the top before paging without bound). A
    // failure ends the attempt, the server excluded with all its pairs, no token (AttemptEnd::Header).
    bool check_span_pow(std::uint64_t floor) {
        const std::uint64_t from = std::max(lo_pos_, floor);
        const std::uint64_t hi = pow_lo_ == 0 ? rep_.L + 1 : pow_lo_;  // [from, hi): held but not yet (5)-checked
        for (std::uint64_t p = hi; p-- > from;) {
            const CarrierHeader* h = header_at(p);
            if (h != nullptr && !pow_ok(*h)) return fail(AttemptEnd::Header, "a header's PoW at its own t_origin");
        }
        pow_lo_ = from;
        return true;
    }

    // The record H(x) on the candidate's chain (running max of h from the
    // lowest held header up; H(0) = b0), kept by take_headers page by page
    // (each held header's P_r resolved once, at its check (3)).
    std::optional<std::uint64_t> rec(std::uint64_t x) const {
        if (x == 0) return in_.b0;
        if (x < lo_pos_ || x > rep_.L || x - lo_pos_ >= records_.size()) return std::nullopt;
        return records_[x - lo_pos_];
    }
    // h(r) = the height of its P_r + 1. A P_r the follower does not hold is
    // fetched as at a full node (data any peer may serve, within the abandon
    // timeout); nullopt: not resolved (the attempt ends as non-service).
    std::optional<std::uint64_t> h_of(const ReceiptBodyV3& r) {
        std::uint64_t h = join_detail::height_of(in_, r);
        if (h == 0 && in_.fetch_context && in_.fetch_context(r.blob.prev_id, timeout_)) h = join_detail::height_of(in_, r);
        if (h == 0) return std::nullopt;
        return h;
    }
    const CarrierHeader* header_at(std::uint64_t x) const {
        if (x < lo_pos_ || x - lo_pos_ >= hdr_.size()) return nullptr;
        return &hdr_[x - lo_pos_];
    }

    // The next page below the lowest held header, down to `need_lo` at most.
    bool more_headers(std::uint64_t need_lo = 1) {
        const Hash32 stop = hdr_.front().own.side.tip;  // the parent of the lowest held header
        const std::uint64_t range = lo_pos_ > need_lo ? lo_pos_ - need_lo : 1;
        const std::uint64_t max = std::min(header_page(), range);
        const ChainHeaders r = link_.headers(stop, max, timeout_);
        if (r.status == LinkStatus::Served && short_headers(r, max, range))
            return fail(AttemptEnd::NotServed, "a short FC_HEADERS reply");
        return take_headers(r, stop);
    }

    bool fetch_top() {
        const std::uint64_t max = header_page();
        const ChainHeaders r = link_.headers(Hash32{}, max, timeout_);
        if (r.status != LinkStatus::Served) return fail(AttemptEnd::NotServed, "headers not served");
        if (r.headers.empty()) {  // the server's chain is position 0: L = 0
            rep_.L = 0;
            rep_.tip = in_.pool_id;
            lo_pos_ = 1;
            if (a_ != nullptr) {
                rep_.a_profile = a_->bound_work();
                rep_.a_profile_read = true;
            }
            return true;
        }
        rep_.L = r.first_pos + r.headers.size() - 1;
        rep_.tip = receipt_id(r.headers.back().own);
        // A's bound work in the step that records L
        if (a_ != nullptr) {
            rep_.a_profile = a_->bound_work();
            rep_.a_profile_read = true;
        }
        if (short_headers(r, max, rep_.L)) return fail(AttemptEnd::NotServed, "a short FC_HEADERS reply");
        if (r.first_pos == 0) return fail(AttemptEnd::NotServed, "a header at position 0");
        if (!take_headers(r, std::nullopt)) return false;
        // (5) on the top page: x0 is not known, so every held header is a candidate (a no-PoW server is caught here)
        return check_span_pow(lo_pos_);
    }

    // 3.3a (4) / ruling 47 (E-82): the fork of L with A's best chain, scanned
    // over each FC_HEADERS page of the header phase as it arrives (top down),
    // so the scope is decided at the first reply that shows the fork; never
    // below the held headers (the retarget-prefix start x0(L') - N_rt). "L held
    // by A" (any node) is tested first. The newest candidate header on A's best
    // chain is the fork: at or below A's x1, or below A's base -> deep, in
    // scope; above both -> out of scope. If no candidate header lies on A's
    // chain down to the floor, the fork is below it and the candidate is in
    // scope (rule (4) decides).
    bool scope_on_page() { return a_ == nullptr || scope_scan(); }
    bool scope_scan() {
        if (scope_done_ || rep_.L == 0) return true;  // decided, or an empty / position-0 candidate
        const std::uint64_t hi = scope_lo_ == 0 ? rep_.L + 1 : scope_lo_;
        const std::uint64_t lo = std::max(lo_pos_, scope_floor_);  // never below x0(L') - N_rt (E-82, E-104)
        for (std::uint64_t x = hi; x-- > lo;) {
            const Hash32 id = receipt_id(header_at(x)->own);
            if (!a_->on_chain(id)) continue;
            scope_done_ = true;
            const std::uint64_t f = a_->pos_of(id).value_or(x);
            const std::optional<std::uint64_t> ax1 = a_->joined_x1();
            const bool deep = (ax1 && f <= *ax1) || f < a_->store_base();
            return deep ? true : fail(AttemptEnd::OutOfScope, "the fork lies above A's x1 and at or above its base");
        }
        scope_lo_ = lo;
        return true;
    }
    bool in_scope() {
        if (!scope_scan()) return false;
        return true;  // ruling 47: the links reach x0(L') - N_rt without meeting A's chain; the fork lies below, in scope
    }

    // ---- span ----
    bool bounds() {
        if (force_young_) {  // the ruling-47 fallback: the whole chain [1, L] verified in full, no claim
            while (lo_pos_ > 1)  // (5) on arrival, page by page
                if (!more_headers(1) || !check_span_pow(lo_pos_) || !scope_on_page()) return false;
            if (!check_span_pow(1)) return false;
            rep_.span = SpanBounds{true, 0, 1, 1};
            return true;
        }
        for (;;) {
            const SpanResult s = span_bounds(in_.p, rep_.L, [this](std::uint64_t x) { return rec(x); }, in_.b0);
            std::uint64_t need_lo = 1;
            bool held = false;
            if (s.status == SpanStatus::Ok) {
                rep_.span = s.bounds;
                const std::uint64_t nrt = join_n_rt(in_.p);
                if (!s.bounds.young) {
                    x0_known_ = true;  // below x0 the PRE is hash-linked, no PoW (header check (5))
                    x0_ = s.bounds.x0;
                    scope_floor_ = x0_ > nrt ? x0_ - nrt : 1;  // the scope scan's floor x0(L') - N_rt (E-82, E-104)
                }
                const std::uint64_t want = s.bounds.young ? 1 : (s.bounds.x0 > nrt ? s.bounds.x0 - nrt : 1);
                need_lo = want;  // pages down to x0 - N_rt: no page asks below what the span reads
                if (s.bounds.young) {
                    held = lo_pos_ <= want;
                } else if (lo_pos_ <= want) {
                    // ruling 53 (E-99): the claimed prefix starts at x_pre; below x0 - N_rt the attempt asks exactly the
                    // record the formula reads next
                    const PreStart ps = pre_start(in_.p, s.bounds.x0, [this](std::uint64_t x) { return rec(x); });
                    if (ps.status == SpanStatus::Ok) {
                        x_pre_ = ps.x_pre;
                        held = true;
                    } else if (ps.need >= lo_pos_) {
                        return fail(AttemptEnd::NotServed, "the prefix start's record lies outside the chain");
                    } else {
                        need_lo = ps.need;
                    }
                }
            }
            // (5) on the span held so far (floor = x0 once known, else every held header): the PRE below x0 is exempt
            if (!check_span_pow(x0_known_ ? x0_ : lo_pos_)) return false;
            if (!scope_on_page()) return false;  // the scope over the page that arrived last
            if (held) return true;  // the span with its prefix (or the whole young chain) held
            if (lo_pos_ <= 1) return fail(AttemptEnd::NotServed, "the records do not reach the span");
            if (!more_headers(need_lo)) return false;
        }
    }

    // ---- bodies of the span ----
    bool fetch_bodies(std::uint64_t from, std::uint64_t to) {
        const std::uint64_t batch = 1 + in_.p.r_max;  // FC_GETCARRIER n <= 1 + R_MAX
        for (std::uint64_t x = from; x <= to;) {
            std::vector<Hash32> ids;
            for (std::uint64_t k = x; k <= to && ids.size() < batch; ++k) {
                const Hash32 id = receipt_id(header_at(k)->own);
                if (span_bodies_.count(id) == 0) ids.push_back(id);
            }
            x += batch;
            if (ids.empty()) continue;
            const CarrierFrames r = link_.carriers(ids, true, timeout_);
            if (r.status != LinkStatus::Served) return fail(AttemptEnd::NotServed, "bodies not served");
            if (r.bodies.size() < ids.size()) return fail(AttemptEnd::NotServed, "a short FC_GETCARRIER reply");
            for (const CarrierBodyV3& b : r.bodies) {
                const Hash32 id = receipt_id(b.own);
                if (std::find(ids.begin(), ids.end(), id) == ids.end()) continue;
                const auto [it, ins] = span_bodies_.emplace(id, b);
                if (!ins && !(it->second == b)) return fail(AttemptEnd::Contradiction, "a second body of a carrier");
            }
            for (const Hash32& id : ids)
                if (span_bodies_.count(id) == 0) return fail(AttemptEnd::NotServed, "a requested body not served");
        }
        return true;
    }
    const CarrierBodyV3* body(std::uint64_t x) const {
        const auto it = span_bodies_.find(receipt_id(header_at(x)->own));
        return it == span_bodies_.end() ? nullptr : &it->second;
    }
    // A body that is not its header: the server contradicts itself.
    bool body_matches_header(std::uint64_t x) const {
        const CarrierBodyV3* b = body(x);
        const CarrierHeader* h = header_at(x);
        return b != nullptr && h != nullptr && b->own == h->own && b->carried.size() == h->n_carried;
    }

    // ---- the joined state ----
    bool build() {
        JoinedState& s = *st_;
        const SpanBounds& sb = rep_.span;
        s.young = sb.young;
        s.x0 = sb.x0;
        s.x1 = sb.x1;
        s.L = rep_.L;
        if (sb.young) {
            s.tree.emplace(in_.p, in_.pool_id, in_.b0, in_.T, std::span<const RetargetEntry>{}, in_.rp, in_.rules_g);
            s.store.emplace(in_.p, in_.journal_depth, in_.pool_id, in_.b0, 0);
            s.root_prev = in_.genesis_prev;
            return true;  // AR: the genesis AR (no rows, no joiner flag)
        }
        const std::uint64_t x0 = sb.x0;
        const std::uint64_t nrt = join_n_rt(in_.p);
        if (!fetch_bodies(x0, x0) || !fetch_bodies(rep_.L, rep_.L)) return false;
        if (!body_matches_header(x0) || !body_matches_header(rep_.L))
            return fail(AttemptEnd::Contradiction, "a body is not its header");
        // the root (x0 - 1) and the claimed retarget prefix [x_pre, x0 - 1] (ruling 53, E-99; the tree's window keeps
        // its newest N_rt entries)
        const std::uint64_t pre_lo = x_pre_;
        if (pre_lo > (x0 > nrt ? x0 - nrt : 1)) return fail(AttemptEnd::NotServed, "the retarget prefix not held");
        std::vector<RetargetEntry> pre;
        std::vector<Hash32> pre_ids;
        std::vector<std::uint64_t> pre_rec;
        for (std::uint64_t x = pre_lo; x + 1 <= x0; ++x) {
            const CarrierHeader* h = header_at(x);
            if (h == nullptr) return fail(AttemptEnd::NotServed, "the retarget prefix not held");
            pre.push_back(RetargetEntry{h->own.side.t_origin, *rec(x)});
            pre_ids.push_back(receipt_id(h->own));
            pre_rec.push_back(*rec(x));
        }
        const CarrierBodyV3& cx0 = *body(x0);
        const CarrierBodyV3& cl = *body(rep_.L);
        Hash32 root_id{};
        std::uint64_t root_h = in_.b0;
        RatchetState root_s = genesis_ratchet_state(in_.rules_g);
        std::vector<Hash32> peaks;
        const std::uint64_t root_H = x0 == 1 ? in_.b0 : pre_rec.back();
        const std::uint64_t lc0 = bin_leaf_count(root_H, in_.b0, in_.p.open_bins);
        if (x0 == 1) {  // the root is position 0, from the identity
            root_id = in_.pool_id;
            s.root_prev = in_.genesis_prev;
            pre_ids.assign(1, in_.pool_id);
            pre_rec.assign(1, in_.b0);
        } else {
            const CarrierHeader* rh = header_at(x0 - 1);
            root_id = receipt_id(rh->own);
            const std::optional<std::uint64_t> rh_h = h_of(rh->own);
            if (!rh_h) return fail(AttemptEnd::NotServed, "a header's P_r not resolved");
            root_h = *rh_h;
            s.root_prev = rh->own.blob.prev_id;
        }
        if (root_id != cx0.own.side.tip) return fail(AttemptEnd::Contradiction, "c_x0 does not link to the root");
        // fetch A: the peaks at lc(H(x0 - 1)) and S_{x0-1}, at c_x0
        const AtHeader at_x0{receipt_id(cx0.own), join_detail::digest_of(header_of(cx0)).value_or(Hash32{})};
        at_x0_ = at_x0;
        anchor_x0_ = BucketsAnchor{true, root_H, cx0.own.side.mmr_root, cx0.own.side.receipts_root, ids_of(cx0)};
        if (x0 > 1) {
            const std::uint64_t bin = in_.b0 + (lc0 > 0 ? lc0 - 1 : 0);
            const BucketsFetch fa = jb_.fetch(link_, anchor_x0_, at_x0, bin, bin, timeout_);
            if (!take_fetch(fa, true)) return false;
            if (!fa.peaks || !fa.s_parent) return fail(AttemptEnd::NotServed, "fetch A: no peaks or S");
            peaks = *fa.peaks;
            root_s = *fa.s_parent;
        }
        // the prefix headers below the root [x_pre, x0 - 2] as claimed nodes of the joined tree (ruling 47, E-84;
        // ruling 53, E-99)
        std::vector<CarrierTree::PreNode> pre_nodes;
        if (x0 > 1) {
            for (std::uint64_t x = pre_lo; x + 1 < x0; ++x) {
                const CarrierHeader* hh = header_at(x);
                const std::optional<std::uint64_t> xh = h_of(hh->own);
                if (!xh) return fail(AttemptEnd::NotServed, "a retarget-prefix header's P_r not resolved");
                pre_nodes.push_back(CarrierTree::PreNode{receipt_id(hh->own), x, *xh, *rec(x), hh->own.side.t_origin});
            }
        }
        // the tree, the store, AR
        s.tree.emplace(CarrierTree::joined(in_.p, root_id, x0 - 1, root_h, root_s, in_.T, pre, in_.rp, pre_nodes));
        BinStore::JoinedStart js;
        js.b0 = in_.b0;
        js.first_pos = x0 == 1 ? 0 : pre_lo;
        js.pre_ids = pre_ids;
        js.pre_records = pre_rec;
        js.root_h = root_h;
        js.peaks = peaks;
        js.adopt_bound = root_H + in_.p.fresh_max;
        std::optional<BinStore> st = BinStore::joined(in_.p, in_.journal_depth, js);
        if (!st) return fail(AttemptEnd::Alarm, "the peaks of c_x0 do not number popcount(leaf_count)");
        s.store.emplace(std::move(*st));
        s.ar.seed_joiner(root_s, x0);
        // fetch B at c_L: the bins sealed inside the span that can hold a placement before x0
        const std::uint64_t F = in_.p.open_bins;
        const std::optional<std::uint64_t> hl1 = rec(rep_.L - 1);
        if (!hl1) return fail(AttemptEnd::NotServed, "the record of L - 1 not held");
        const std::uint64_t lo_b = root_H >= F ? root_H - F + 1 : in_.b0;
        const std::uint64_t hi_b = std::min(*hl1 >= F ? *hl1 - F : 0, root_H + in_.p.fresh_max);
        const std::uint64_t lo_bin = std::max(lo_b, in_.b0);
        if (lo_bin <= hi_b) {
            const AtHeader at_l{receipt_id(cl.own), join_detail::digest_of(header_of(cl)).value_or(Hash32{})};
            const BucketsAnchor anchor{true, *hl1, cl.own.side.mmr_root, cl.own.side.receipts_root, ids_of(cl)};
            const BucketsFetch fb = jb_.fetch(link_, anchor, at_l, lo_bin, hi_b, timeout_);
            if (!take_fetch(fb, false)) return false;
            for (const auto& [bin, sv] : fb.bins) {
                SealedBin sb2;
                sb2.bucket = sv.bucket;
                sb2.leaf = sv.leaf;
                sb2.refs = sv.refs;
                if (!s.store->adopt_served(sb2)) return fail(AttemptEnd::NotServed, "fetch B: a bin not adopted");
                s.claimed[bin] = at_l;
            }
        }
        return true;
    }

    static std::vector<Hash32> ids_of(const CarrierBodyV3& c) {
        std::vector<Hash32> out;
        for (const ReceiptBodyV3& r : c.carried) out.push_back(receipt_id(r));
        return out;
    }

    // A bucket fetch's end inside the attempt; false: the attempt ended.
    bool take_fetch(const BucketsFetch& f, bool fetch_a) {
        return take_fetch(f, fetch_a ? "fetch A not served" : "fetch B not served");
    }
    bool take_fetch(const BucketsFetch& f, const char* not_served) {
        for (const auto& [id, k] : f.refs) st_->refs.emplace(id, k);
        switch (f.end) {
            case BucketsEnd::Complete: return true;
            case BucketsEnd::NotServed: return fail(AttemptEnd::NotServed, not_served);
            case BucketsEnd::AtClaim:
                st_->alarm.raise(RowId::None, Basis::ClaimSpan, Hash32{}, Missing::ClaimAlarm);
                return fail(AttemptEnd::Alarm, "a bucket reply against a claimed at header");
            case BucketsEnd::Struck:
                rep_.strike += f.strike;
                return fail(AttemptEnd::NotServed, "a bucket frame refused (struck)");
        }
        return fail(AttemptEnd::NotServed, "fetch");
    }

    // ---- the replay ----
    bool replay() {
        JoinedState& s = *st_;
        const std::uint64_t from = s.young ? 1 : s.x0;
        if (rep_.L < from) return true;  // L = 0: position 0
        const std::uint64_t batch = 1 + in_.p.r_max;
        for (std::uint64_t x = from; x <= rep_.L; ++x) {
            if ((x - from) % batch == 0 && !fetch_bodies(x, std::min(rep_.L, x + batch - 1))) return false;
            if (!body_matches_header(x)) return fail(AttemptEnd::Contradiction, "a body is not its header");
            const CarrierBodyV3& c = *body(x);
            s.learn_refs(c.own);
            for (const ReceiptBodyV3& r : c.carried) s.learn_refs(r);
            if (!place(c, CarrierRole::Frame, x)) return false;
            for (const ReceiptBodyV3& r : c.carried) {
                const CarrierNode* t = s.tree->find(r.side.tip);
                if (t != nullptr && (s.young || t->pos >= s.x1))
                    ++s.full_bodies;
                else
                    ++s.span_claims;
            }
            if (s.young || x - 1 >= s.x1)
                ++s.full_bodies;
            else
                ++s.span_claims;
            if (on_step_) on_step_(s, x);
        }
        return true;
    }

    // ruling 47 (E-83), ruling 53 (E-100): a walked branch forking at a prefix
    // node f below x0 - 1 (r's tip branch, and every branch the walk entered:
    // the closure's) cannot be folded without S(f). The joiner fetches S(f)
    // from the attempt's server by FC_GETBUCKETS at = the branch's first
    // carrier, its fork that carrier's parent (B7), whose S_parent = S(f) and
    // whose peaks at lc(H(f)) are proved against its mmr_root; it sets the fork
    // node's claimed ratchet state and the store's claimed view at f, then
    // re-admits c. The fold runs over the first carrier's carried list: its
    // body set is fetched first.
    enum class SpanFold : std::uint8_t { None, Fetched, Young, Alarm, NotServed, Ended };
    // The first carrier of the walked branch through `t`: down its held header
    // variants to the carrier whose parent is a tree node (nullptr: not held).
    const HeaderVariant* first_carrier(const Hash32& t) const {
        const JoinedState& s = *st_;
        std::vector<const HeaderVariant*> vs = s.headers.variants(t);
        for (std::uint64_t k = 0; !vs.empty() && k <= admit_j0(in_.p) + 1; ++k) {
            const HeaderVariant* y = vs.front();
            if (s.tree->find(y->header.own.side.tip) != nullptr) return y;
            vs = s.headers.variants(y->header.own.side.tip);
        }
        return nullptr;
    }
    SpanFold try_span_fold(const CarrierBodyV3& c, const std::vector<Hash32>& walked) {
        JoinedState& s = *st_;
        if (s.young || !s.tree || !s.store) return SpanFold::None;
        const std::uint64_t root_pos = s.x0 > 0 ? s.x0 - 1 : 0;
        const std::uint64_t first_pos = s.store->first_record_pos();
        std::vector<Hash32> tips;
        for (const ReceiptBodyV3& r : c.carried) tips.push_back(r.side.tip);
        // the closure's branches (ruling 53, E-100): the top of every walked branch (a walked id no walked header names
        // as its parent), each followed down to its first carrier below
        std::set<Hash32> named;
        for (const Hash32& w : walked)
            for (const HeaderVariant* v : s.headers.variants(w)) named.insert(v->header.own.side.tip);
        for (const Hash32& w : walked)
            if (s.tree->find(w) == nullptr && named.count(w) == 0) tips.push_back(w);
        bool fetched = false;
        for (const Hash32& tip : tips) {
            if (s.tree->find(tip) != nullptr) continue;        // on the joined chain, or already placed
            const HeaderVariant* first = first_carrier(tip);
            if (first == nullptr) continue;                    // the side header is not held (the TipHeaders path fetches it)
            const Hash32 t = first->id;                        // the branch's first carrier (E-83)
            const CarrierHeader& y = first->header;
            const CarrierNode* fn = s.tree->find(y.own.side.tip);  // the fork: the first side carrier's parent
            if (fn == nullptr || fn->pos >= root_pos || fn->pos < first_pos) continue;  // not a PRE node below the root
            if (!span_s_done_.insert(t).second) continue;      // S(f) for this side branch already attempted
            const std::uint64_t lc = bin_leaf_count(fn->H, in_.b0, in_.p.open_bins);
            if (lc == 0) return SpanFold::Young;               // no bin sealed at or before f (ruling 47): the young path
            std::vector<Hash32> cids;
            if (y.n_carried > 0) {
                if (s.headers.body_sets(t).empty() && !fetch_body_set(t)) return SpanFold::Ended;  // the attempt ended
                const std::vector<const BodySet*> bs = s.headers.body_sets(t);
                if (!bs.empty())
                    for (const ReceiptBodyV3& b : bs.front()->bodies) cids.push_back(receipt_id(b));
            }
            const AtHeader at_t{t, join_detail::digest_of(y).value_or(Hash32{})};
            const BucketsAnchor anchor{true, fn->H, y.own.side.mmr_root, y.own.side.receipts_root, cids};
            const std::uint64_t bin = in_.b0 + lc - 1;
            const BucketsFetch f = jb_.fetch(link_, anchor, at_t, bin, bin, timeout_);
            for (const auto& [id, k] : f.refs) s.refs.emplace(id, k);
            if (f.end == BucketsEnd::AtClaim) {
                s.alarm.raise(RowId::None, Basis::ClaimSpan, Hash32{}, Missing::ClaimAlarm);
                return SpanFold::Alarm;
            }
            if (f.end == BucketsEnd::Struck) {
                rep_.strike += f.strike;
                return SpanFold::NotServed;
            }
            if (!f.s_parent || !f.peaks) return SpanFold::NotServed;
            // S(f) and the view at f, claims of ruling 42: two replies naming one prefix node must agree
            const auto [cs, fresh] = claimed_s_.emplace(fn->id, *f.s_parent);
            if ((!fresh && !(cs->second == *f.s_parent)) || !s.store->claim_fork(fn->id, fn->pos, *f.peaks)) {
                s.alarm.raise(RowId::None, Basis::ClaimSpan, Hash32{}, Missing::ClaimAlarm);
                return SpanFold::Alarm;
            }
            if (s.tree->set_claimed_rs(y.own.side.tip, *f.s_parent)) fetched = true;
        }
        return fetched ? SpanFold::Fetched : SpanFold::None;
    }

    // ruling 53 (E-100): the bins pending at a parent on a branch forking at a
    // claimed prefix node, taken from a served bucket at the carrier being
    // placed on it (a carrier of that branch whose leaf_count covers them).
    bool fill_side_seals(const CarrierNode& pn, const CarrierBodyV3& c) {
        JoinedState& s = *st_;
        const LaneDelta* d = s.store->delta(pn.id);
        if (d == nullptr || d->pending.empty()) return true;
        const std::vector<std::uint64_t> bins = d->pending;
        const AtHeader at{receipt_id(c.own), join_detail::digest_of(header_of(c)).value_or(Hash32{})};
        const BucketsAnchor anchor{true, pn.H, c.own.side.mmr_root, c.own.side.receipts_root, ids_of(c)};
        const BucketsFetch f = jb_.fetch(link_, anchor, at, bins.front(), bins.back(), timeout_);
        if (!take_fetch(f, "a side bin's bucket not served")) return false;
        for (const std::uint64_t bin : bins) {
            const auto it = f.bins.find(bin);
            if (it == f.bins.end()) return fail(AttemptEnd::NotServed, "a side bin's bucket not served");
            SealedBin sb;
            sb.bucket = it->second.bucket;
            sb.leaf = it->second.leaf;
            sb.refs = it->second.refs;
            if (!s.store->fill_side_seal(pn.id, sb)) return fail(AttemptEnd::NotServed, "a side bin not adopted");
        }
        return true;
    }

    // Admits and places one frame, fetching what its DEFERs name from the
    // attempt's server and placing the walked side carriers (claims) first.
    bool place(const CarrierBodyV3& c0, CarrierRole role0, std::uint64_t x) {
        JoinedState& s = *st_;
        struct Item {
            CarrierBodyV3 c;
            CarrierRole role;
        };
        std::vector<Item> stack{Item{c0, role0}};
        while (!stack.empty()) {
            const Item it = stack.back();
            const Hash32 id = receipt_id(it.c.own);
            if (s.tree->find(id) != nullptr) {
                stack.pop_back();
                continue;
            }
            const std::optional<std::vector<std::uint8_t>> frame = carrier_frame(it.c, in_.p.r_max);
            if (!frame) return fail(AttemptEnd::Unplaceable, "a frame that does not encode");
            AdmitEnv env = s.env();
            const AdmitResult r = admit_carrier(env, *frame, it.role);
            rep_.at = x;
            rep_.row = r.row;
            rep_.missing = r.missing;
            rep_.verdict = r.verdict;
            if (r.verdict == AdmitVerdict::AdmitCarrier) {
                // E-16: every mmr_root of the span (a carrier on a tip below x1 is not checked by the pipeline)
                const CarrierNode* pn = s.tree->find(it.c.own.side.tip);
                if (pn != nullptr && pn->below_root && !fill_side_seals(*pn, it.c)) return false;
                if (!s.young && pn != nullptr && pn->pos < s.x1) {
                    const LaneView pv = s.store->view_at(pn->id);
                    if (!pv.ok() || pv.pending_bin()) return fail(AttemptEnd::NotServed, "the parent's view not held");
                    if (pv.mmr_root() != it.c.own.side.mmr_root) {
                        s.alarm.raise(RowId::R10, Basis::ClaimSpan, id, Missing::ClaimAlarm);
                        return fail(AttemptEnd::Alarm, "an mmr_root of the span against the joined MMR");
                    }
                }
                const WriteResult w = place_admitted(*s.tree, *s.store, s.ar, s.bodies, r, &s.alarm);
                if (w.outcome == WriteOutcome::NodeInternal) return fail(AttemptEnd::NotServed, "a node-internal write");
                if (it.role == CarrierRole::Closure) s.headers.placed(id);
                stack.pop_back();
                continue;
            }
            if (r.verdict != AdmitVerdict::Defer) {
                rep_.strike += r.strike;
                return fail(AttemptEnd::Unplaceable, "a span carrier refused");
            }
            switch (*r.missing) {
                case Missing::ClaimAlarm: return fail(AttemptEnd::Alarm, "an alarm on a claim");
                case Missing::TipUnknown:
                case Missing::TipHeaders:
                    if (!fetch_side_headers(r.fetch)) return false;
                    break;
                case Missing::ClosureBodies:
                    if (!fetch_body_set(r.fetch)) return false;
                    break;
                case Missing::TipBodies: {
                    if (r.bind.empty()) return fail(AttemptEnd::Unplaceable, "a tip branch not held");
                    std::size_t pushed = 0;
                    for (auto b = r.bind.rbegin(); b != r.bind.rend(); ++b) {
                        if (s.tree->find(*b) != nullptr) continue;
                        const std::vector<const HeaderVariant*> vs = s.headers.variants(*b);
                        if (vs.empty()) return fail(AttemptEnd::Unplaceable, "a walked carrier without a header");
                        const HeaderVariant& y = *vs.front();
                        CarrierBodyV3 w;
                        w.own = y.header.own;
                        s.learn_refs(w.own);  // its payee / owner key references (placed from its header)
                        if (y.header.n_carried > 0) {
                            const std::vector<const BodySet*> sets = s.headers.body_sets(*b);
                            if (sets.empty()) {
                                if (!fetch_body_set(*b)) return false;
                                const std::vector<const BodySet*> again = s.headers.body_sets(*b);
                                if (again.empty()) return fail(AttemptEnd::Unplaceable, "a walked carrier's bodies");
                                w.carried = again.front()->bodies;
                            } else {
                                w.carried = sets.front()->bodies;
                            }
                        }
                        stack.push_back(Item{std::move(w), CarrierRole::Closure});
                        ++pushed;
                    }
                    if (pushed == 0) return fail(AttemptEnd::Unplaceable, "nothing to place");
                    break;
                }
                case Missing::Closure: {
                    // ruling 47: a side branch forking at a PRE node below x0 - 1 needs S(f) from the attempt's server
                    const SpanFold sf = try_span_fold(it.c, r.walked);
                    if (sf == SpanFold::Fetched) break;  // re-admit with the fork node's S(f) set
                    if (sf == SpanFold::Ended) return false;  // the side carrier's body set: the attempt ended there
                    if (sf == SpanFold::Young) {
                        rep_.force_young = true;
                        return fail(AttemptEnd::NotServed, "S(f) at a fork with no sealed bin: the young path");
                    }
                    if (sf == SpanFold::Alarm) return fail(AttemptEnd::Alarm, "the S(f) fold against the side carrier");
                    if (sf == SpanFold::NotServed) return fail(AttemptEnd::NotServed, "the S(f) fetch not served");
                    return fail(AttemptEnd::Unplaceable, "a span carrier deferred with nothing to fetch");
                }
                case Missing::Boundary:
                case Missing::EpochGrace: return fail(AttemptEnd::Unplaceable, "a span carrier deferred with nothing to fetch");
                case Missing::MoneroBlock:
                case Missing::Seed:
                case Missing::MissingBlock:
                case Missing::MissingWeights:
                    if (!in_.fetch_context || !in_.fetch_context(r.fetch, timeout_))
                        return fail(AttemptEnd::NotServed, "data any peer may serve, not resolved");
                    break;
                case Missing::MissingBucket:
                    if (!fetch_below(r.fetch_bin)) return false;
                    break;
                case Missing::Hold: return fail(AttemptEnd::NotServed, "an H_hold DEFER");
                default: return fail(AttemptEnd::NotServed, "a DEFER the attempt cannot resolve");
            }
        }
        return true;
    }
    // Side headers of a walked id from the server; one variant per id and attempt.
    bool fetch_side_headers(const Hash32& id) {
        JoinedState& s = *st_;
        const ChainHeaders r = link_.headers(id, header_page(), timeout_);
        if (r.status != LinkStatus::Served || r.headers.empty()) return fail(AttemptEnd::NotServed, "side headers not served");
        bool fresh = false;
        for (const CarrierHeader& h : r.headers) {
            const Hash32 hid = receipt_id(h.own);
            if (s.tree->find(hid) != nullptr) {  // placed: its header must be the placed body's
                const CarrierBodyV3* b = s.bodies.get(hid);
                if (b != nullptr && !(b->own == h.own && b->carried.size() == h.n_carried))
                    return fail(AttemptEnd::Contradiction, "a header that is not the placed carrier's");
                continue;
            }
            const std::optional<std::uint64_t> hh = h_of(h.own);
            if (!hh) return fail(AttemptEnd::NotServed, "a side header's P_r not resolved");
            const IndexAdd a = s.headers.add(s.server(), h, *hh, join_detail::header_path_ok(in_, h));
            if (a == IndexAdd::Replaced) return fail(AttemptEnd::Contradiction, "a second variant of an id");
            if (a == IndexAdd::Added) fresh = true;
        }
        if (!fresh) return fail(AttemptEnd::Unplaceable, "no new side header");
        return true;
    }

    // A walked carrier's carried bodies from the server; one body set per carrier and attempt.
    bool fetch_body_set(const Hash32& id) {
        JoinedState& s = *st_;
        const CarrierFrames r = link_.carriers({id}, true, timeout_);
        if (r.status != LinkStatus::Served) return fail(AttemptEnd::NotServed, "a walked body not served");
        if (r.bodies.empty()) return fail(AttemptEnd::NotServed, "a short FC_GETCARRIER reply");
        bool any = false;
        for (const CarrierBodyV3& b : r.bodies) {
            if (receipt_id(b.own) != id) continue;
            any = true;
            for (const ReceiptBodyV3& rr : b.carried) s.learn_refs(rr);
            s.learn_refs(b.own);
            const IndexAdd a = s.headers.add_body_set(s.server(), id, b.carried, header_digest(header_of(b)));
            if (a == IndexAdd::Replaced) return fail(AttemptEnd::Contradiction, "a second body set of a carrier");
            if (a != IndexAdd::Added && a != IndexAdd::Known) return fail(AttemptEnd::Unplaceable, "a body set not held");
        }
        if (!any) return fail(AttemptEnd::NotServed, "the walked body not served");
        return true;
    }

    // A bucket of a bin below lc(H(x0 - 1)) on demand: fetch A at c_x0.
    bool fetch_below(std::uint64_t bin) {
        JoinedState& s = *st_;
        if (s.young || bin < in_.b0 || bin - in_.b0 >= s.store->first_leaf())
            return fail(AttemptEnd::NotServed, "a bucket the join does not fetch");
        const BucketsFetch f = jb_.fetch(link_, anchor_x0_, at_x0_, bin, bin, timeout_);
        if (!take_fetch(f, true)) return false;
        const auto it = f.bins.find(bin);
        if (it == f.bins.end()) return fail(AttemptEnd::NotServed, "fetch A: the bin not served");
        SealedBin sb;
        sb.bucket = it->second.bucket;
        sb.leaf = it->second.leaf;
        sb.refs = it->second.refs;
        if (!s.store->adopt_below(sb)) return fail(AttemptEnd::NotServed, "fetch A: the bin not adopted");
        s.claimed[bin] = at_x0_;
        return true;
    }

    const JoinInputs& in_;
    JoinLink& link_;
    std::uint64_t timeout_;
    const AdoptedChain* a_;
    std::function<void(JoinedState&, std::uint64_t)> on_step_;
    std::function<bool(const Hash32&)> known_;
    JoinBuckets jb_;
    AttemptReport rep_;
    std::unique_ptr<JoinedState> st_;
    std::vector<CarrierHeader> hdr_;  // positions lo_pos_ .. L
    std::uint64_t lo_pos_ = 0;
    std::deque<std::uint64_t> records_;  // H(x) for x in lo_pos_ .. L (take_headers, page by page)
    std::set<Hash32> phase_ids_;  // ids seen in the header phase (header check (2))
    std::optional<std::uint64_t> lo_h_;  // h at the current lowest held header (header check (4) at a page boundary)
    bool x0_known_ = false;       // x0 fixed by bounds(): below it the PRE is hash-linked, no PoW (header check (5))
    std::uint64_t x0_ = 0;
    std::uint64_t pow_lo_ = 0;    // the lowest position (5)-checked so far (0 = none)
    bool force_young_ = false;    // the young path forced by the pair's mark (the ruling-47 fallback)
    bool scope_done_ = false;     // the fork with A's best chain met (in scope: deep)
    std::uint64_t scope_lo_ = 0;  // the lowest position the scope scan has read (0: none)
    std::uint64_t scope_floor_ = 0;  // x0(L') - N_rt once x0 is known: the scope scan reads nothing below it
    std::uint64_t x_pre_ = 1;     // the claimed prefix start (ruling 53, E-99)
    std::map<Hash32, RatchetState> claimed_s_;  // S(f) taken per prefix node (ruling 47, E-83)
    std::map<Hash32, CarrierBodyV3> span_bodies_;
    std::set<Hash32> span_s_done_;  // side carriers whose S(f) fetch was attempted (ruling 47)
    AtHeader at_x0_{};
    BucketsAnchor anchor_x0_{};
};

// ---------------------------------------------------------------------------
// A joined node's own switch to a branch forking at `fork` (ruling 44 item (2);
// E-75; 35 DC-3): at or below its x1 the joiner path whatever its P-01; below
// its journal base the joiner path; otherwise a rewind by its journal.
// ---------------------------------------------------------------------------
enum class SwitchPath : std::uint8_t { Rewind, Joiner };

inline SwitchPath own_switch_path(const JoinedState& a, std::uint64_t fork) {
    if (!a.young && fork <= a.x1) return SwitchPath::Joiner;
    if (fork < a.store_base()) return SwitchPath::Joiner;
    return SwitchPath::Rewind;
}

// ---------------------------------------------------------------------------
// The Joiner of a node: the queue of pairs, the adopted state A and the
// replacement test (3.3, 3.3a, 3.6). abandon_timeout_s: P-53 per request (no
// default here: the caller's flag).
// ---------------------------------------------------------------------------
struct SwitchReport {
    bool adopted = false;    // the first completed attempt adopted
    bool replaced = false;   // a completed candidate replaced A (a switch by the joiner path)
    std::uint64_t lost = 0;  // the replaced A's open-bin placements, a joined state or a full node's own chain
                             // (counted lost; nothing re-pended; the caller logs it)
};

class Joiner {
public:
    Joiner(const JoinInputs& in, std::uint64_t abandon_timeout_s) : in_(in), timeout_(abandon_timeout_s) {}

    // A server offers its best tip (HELLO; a trigger of 3.1): the pair is
    // queued in the order of first offer. A trigger never discards A.
    void offer(const Hash32& candidate, JoinLink& server, const U128& claimed_work = {}) {
        links_[server.peer()] = &server;
        queue_.offer(candidate, server.peer(), claimed_work);
    }
    void disconnect(std::uint64_t server) {
        links_.erase(server);
        queue_.disconnect(server);
    }

    // A full node's own chain as A (a deep switch); nullptr: none.
    void set_own_chain(const AdoptedChain* own) { own_ = own; }

    // The adopted state (a joined one), and A as the attempts see it.
    const JoinedState* adopted() const noexcept { return adopted_.get(); }
    JoinedState* adopted() noexcept { return adopted_.get(); }
    const AdoptedChain* a() const noexcept { return adopted_ ? static_cast<const AdoptedChain*>(adopted_.get()) : own_; }
    // 3.3a (2): A's answer; true only while the node has no adopted state.
    bool rests_on_claims() const noexcept { return a() == nullptr; }

    const AttemptQueue& queue() const noexcept { return queue_; }
    const SwitchReport& last_switch() const noexcept { return switch_; }

    // Observes the attempt state while it runs (the caller's work between
    // steps: A's templates, relays).
    void set_on_step(std::function<void(JoinedState&, std::uint64_t)> f) { on_step_ = std::move(f); }

    // Runs the next pair's attempt; nullopt: no pair queued.
    std::optional<AttemptReport> run_next() {
        const std::optional<AttemptQueue::Pair> p = queue_.next();
        if (!p) return std::nullopt;
        const auto li = links_.find(p->server);
        if (li == links_.end()) return run_next();
        JoinAttempt att(in_, *li->second, timeout_, a(), on_step_);
        att.set_known([this](const Hash32& tip) { return known_.count(tip) != 0; });
        att.set_force_young(p->young);
        AttemptReport rep = att.run(p->candidate);
        switch_ = SwitchReport{};
        switch (rep.end) {
            case AttemptEnd::Completed: complete(rep); break;
            case AttemptEnd::NotServed: {
                // ruling 47: the pair's next attempt runs the young path (the mark rides the queue)
                AttemptQueue::Pair q = *p;
                q.young = q.young || rep.force_young;
                queue_.requeue(q);
                break;
            }
            case AttemptEnd::Alarm:
            case AttemptEnd::Contradiction:
            case AttemptEnd::Unplaceable:
            case AttemptEnd::Header: queue_.exclude(p->server); break;
            case AttemptEnd::OutOfScope:
            case AttemptEnd::Known: break;
        }
        return rep;
    }

private:
    void complete(AttemptReport& rep) {
        if (a() == nullptr) {
            adopted_ = std::move(rep.state);
            switch_.adopted = true;
            known_.clear();
            return;
        }
        const std::shared_ptr<const BoundWork> c = rep.state->bound_work();
        const std::shared_ptr<const BoundWork> ap = rep.a_profile ? rep.a_profile : std::make_shared<const BoundWork>();
        const Hash32 a_tip = a()->tip();
        if (candidate_replaces(*c, rep.tip, *ap, a_tip)) {
            switch_.replaced = true;
            switch_.lost = a()->open_placements();  // A's (joined or the full node's own): counted lost, never re-pended
            adopted_ = std::move(rep.state);  // the old A is discarded with its store
            own_ = nullptr;
            known_.clear();
            return;
        }
        known_.insert(rep.tip);  // kept by the tip id of the attempt's L
    }

    const JoinInputs& in_;
    std::uint64_t timeout_;
    AttemptQueue queue_;
    std::map<std::uint64_t, JoinLink*> links_;
    std::unique_ptr<JoinedState> adopted_;
    const AdoptedChain* own_ = nullptr;
    std::set<Hash32> known_;
    SwitchReport switch_;
    std::function<void(JoinedState&, std::uint64_t)> on_step_;
};

// ---------------------------------------------------------------------------
// C-1 (0) for FB_RECEIPTS: with a claim view, a relayed receipt the view does
// not judge now is DEFERred (CopyDeferred), no row run.
// ---------------------------------------------------------------------------
inline AdmitResult admit_receipt_from(const AdmitEnv& env, std::uint64_t peer, std::span<const std::uint8_t> body) {
    if (env.claims != nullptr) {
        const Hash32 digest = ::v37::sha256d(std::vector<std::uint8_t>(body.begin(), body.end()));
        if (!env.claims->judge_copy(peer, digest)) {
            AdmitResult r = admit_detail::defer(Missing::CopyDeferred, RowId::None);
            r.digest = digest;
            return r;
        }
    }
    return admit_receipt(env, body, Role::Pending);
}

}  // namespace c2pool::xmr::pathb
