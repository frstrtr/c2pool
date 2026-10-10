// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_admit.hpp
// Path B, slice S3b-4a: the admission pipeline of a full node (S1.3 then
// S2.3, in SPEC order; C37, C41, C43, C44; INV-30).
//
//   admit_carrier(env, frame, role)   an FC_CARRIER frame (FH | carrier body):
//     #1a  frame <= the frame buffer (P-11)                     DROP
//     #1b  ver, n_carried <= R_MAX, field sums; every body (own and carried)
//          read within the receipt buffer (P-10), else the frame DROP; then
//          S2.3 #1b (ID-1) and #2 (pool_id, p + give_author_bp <= 10000) for
//          every body before any fetch                           STRIKE
//     #3   parent = tip held                                     DEFER ParentUnknown
//          role Frame: parent's fork with the store's best chain
//          (store.best_tip()) below base_pos                     DEFER OwnChainDeep
//     #2   rules_epoch (frame_verdict, epoch_at (i))             STRIKE / DEFER
//     #4   P_r                                                   DEFER / BAN the server
//     #5   0 <= h - h(tip) <= Fresh                              REFUSE
//     #6   h >= H(pos(tip))                                      else a receipt (PENDING)
//     #7   header fields, vote(minor) >= hf                      STRIKE
//     #8   t_origin == d_at(tip)                                 STRIKE
//     #9   canonical coinbase (+ #13 roots) on window(parent)    BAN / REFUSE / alarm + DEFER
//     carried bodies: S2.3 #3 (EP-4 walk, the deep-tip boundary pos(parent(c))
//          - f > J_0 and the closure, from headers and carried bodies before any
//          state of those branches is read), #4 (epoch_at (ii) / (iii)), #5,
//          #6; the canonical order; #7 (open bin on c's chain, h(r) <= h(c) +
//          Fresh), #8 (dedup on c's chain), #9, #11, #12, #13; the list
//          (check_carried_list; its fold = S1.3 #10)
//     RandomX once per body, last                                BAN / SeedMissing DEFER
//     #17 live on c's chain; the placements
//   admit_receipt(env, body, Pending)  an unsolicited receipt: S2.3 only.
//   place_admitted(...)                 the write step after the dry run.
//   ClaimView (pathb_claim_view.hpp): a claim basis turns a computed mismatch
//     into a local alarm + DEFER, no token; claims == nullptr is the full node.
//   No verdict reads a clock or the node's journal depth; J_0 =
//   journal_j0(p, D_fin).
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
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "pathb_bin_store.hpp"
#include "pathb_caps.hpp"
#include "pathb_claim_view.hpp"
#include "pathb_coinbase_split.hpp"
#include "pathb_fork_choice.hpp"
#include "pathb_header_index.hpp"
#include "pathb_header_rules.hpp"
#include "pathb_joiner.hpp"  // journal_j0
#include "pathb_params.hpp"
#include "pathb_ratchet_activation.hpp"
#include "pathb_receipt_admission.hpp"
#include "pathb_window_cache.hpp"
#include "pathb_window_chain.hpp"
#include "pathb_wire_v3.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Rows, roles, DEFER causes
// ---------------------------------------------------------------------------
// The rows of the admission table: 1-13 = S1.3 #1a .. #12, 14-31 = S2.3 #1a .. #17.
enum class RowId : std::uint8_t {
    None = 0,
    R1 = 1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13,
    R14, R15, R16, R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31
};

// Frame: judged for its own placement (the row-4 gate applies). Closure:
// placed as closure material for a judged carrier's walk.
enum class CarrierRole : std::uint8_t { Frame, Closure };

enum class Role : std::uint8_t { Pending };

enum class Missing : std::uint8_t {
    ParentUnknown,   // FC_GETCARRIER(tip); headers first
    OwnChainDeep,    // nothing; the node's own switch by headers first
    TipUnknown,      // FC_GETHEADERS of t's branch
    TipHeaders,      // FC_GETHEADERS of t's branch / of a branch the closure enters
    Boundary,        // nothing (ruling 40)
    ClosureBodies,   // FC_GETCARRIER(want_bodies 1) of a walked carrier
    Closure,         // nothing (ruling 41)
    EpochGrace,      // nothing (EP-4 (iii))
    Hold,            // the P-34 store
    MoneroBlock,     // FB_GETCTX
    Seed,            // the seed cache
    Bodies,          // FC_GETCARRIER(c, want_bodies 1)
    TipBodies,       // t's branch held in the store (bind and place the walked carriers)
    MissingBucket,   // FC_GETBUCKETS at a bound carrier on the best chain above the bin's seal
    MissingEntries,  // rebuild
    MissingWeights,  // the follower (A_t RowWeights)
    MissingBlock,    // the follower
    MissingRef,      // FC_GETBUCKETS references
    NodeInternal,    // nothing; local alarm (E-46)
    ClaimAlarm,      // nothing; local alarm (a claim basis)
    CopyDeferred,    // nothing here; the owner fetches its own copy
};

// Node-internal and claim outcomes: a local alarm with the row and the basis.
struct AlarmSink {
    struct Entry {
        RowId row = RowId::None;
        Basis basis = Basis::Computed;
        Hash32 id{};
        Missing cause = Missing::NodeInternal;
    };
    std::vector<Entry> entries;
    void raise(RowId row, Basis basis, const Hash32& id, Missing cause) { entries.push_back(Entry{row, basis, id, cause}); }
    std::size_t count() const noexcept { return entries.size(); }
};

struct AdmitResult {
    AdmitVerdict verdict = AdmitVerdict::Defer;
    RowId row = RowId::None;
    std::uint32_t strike = 0;
    bool randomx_called = false;
    std::optional<Missing> missing;              // DEFER: what to fetch / rebuild, or nothing
    std::vector<CarriedPlacement> placements;    // AdmitCarrier: the carried list's placements (body order)
    bool alarm = false;
    // detail
    std::size_t body = 0;                        // the deciding body: 0 = own, k = carried k - 1
    Hash32 fetch{};                              // the id to fetch (or the walked carrier / t)
    Hash32 fetch_from{};                         // TipHeaders: c's ancestor at pos(parent(c)) - J_0
    std::uint64_t fetch_bin = 0;                 // MissingBucket / MissingEntries
    bool claim_based = false;                    // Boundary / Closure on a path holding an unbound header
    std::vector<Hash32> walked;                  // ids a walk touched (re-walk triggers)
    std::vector<Hash32> bind;                    // TipBodies: the walked ids to bind, fork upward
    std::vector<std::pair<std::uint64_t, std::uint32_t>> peer_tokens;  // a walk's tokens by serving peer (none)
    std::vector<std::pair<std::uint64_t, Hash32>> refuted_sets;        // body sets a computed S1.3 #10 refutes
    // the frame, for place_admitted
    Hash32 id{};
    Hash32 digest{};                             // sha256d of the frame bytes
    std::optional<CarrierBodyV3> carrier;
    CarrierAnnounce announce{};
    std::vector<Placement> store_placements;     // the carried list (canonical order), then the own body
};

inline bool admitted(const AdmitResult& r) noexcept {
    return r.verdict == AdmitVerdict::AdmitCarrier || r.verdict == AdmitVerdict::AdmitPending;
}

// P_r of a receipt as the follower and the served context resolve it.
struct PrInfo {
    enum class Status : std::uint8_t { Held, Missing, BadServed } status = Status::Missing;
    std::uint64_t height = 0;  // height(P_r)
    HeaderInputs in{};         // the header inputs of P_r's branch for a child (hf, median60, Z, Z_lt)
};

struct AdmitEnv {
    const CarrierTree& tree;            // fork choice, S per node, waiting entries
    const BinStore& store;              // lane state per held branch, with the view horizon
    const HeaderIndex& headers;         // side-header variants and body sets
    const CarrierBodies& bodies;        // the bodies of placed carriers
    const FollowerBranchView& monero;   // blocks, weights, window inputs on any held branch
    WindowCache& windows;
    KeyCache& keys;
    RefLookup refs;
    XmrKeyRef author;                   // the network's author reference (K16)
    const LaneParams& p;
    const RatchetParams& rp;
    const EpochTable& T;                // the compiled table
    const ActivationRecord& ar;
    Hash32 pool_id{};
    std::uint64_t j0 = 0;               // journal_j0(p, D_fin)
    RelayBuffers buffers{};             // P-10, P-11
    Hash32 genesis_prev{};              // P_0 = the pool identity's Monero block H
    std::function<PrInfo(const Hash32& p_r)> resolve_pr;
    std::function<std::optional<Hash32>(const Hash32& p_r)> seed_of;
    std::function<bool(const HashingBlob&, std::uint64_t d, const Hash32& seed)> randomx;
    AlarmSink& alarm;
    const ClaimView* claims = nullptr;  // the claim extension point: nullptr = the full node
};

// ---------------------------------------------------------------------------
// Small checks
// ---------------------------------------------------------------------------
// S1.3 #2 / S2.3 #2: the body's pool_id is the lane's.
inline bool pool_id_ok(const SideDataV3& side, const Hash32& lane_pool_id) noexcept { return side.pool_id == lane_pool_id; }

// S1.3 #8 / S2.3 #11: t_origin == d_at(chain of tip, pos(tip) + 1).
inline bool origin_target_ok(std::uint64_t t_origin, std::uint64_t d_at_tip) noexcept { return t_origin == d_at_tip; }

// S2.3 #7 (ruling 31 P-11): a carried receipt h(r) <= h(c) + Fresh.
inline bool carried_upper_ok(std::uint64_t h_r, std::uint64_t h_c, std::uint64_t fresh) noexcept {
    return h_c <= UINT64_MAX - fresh ? h_r <= h_c + fresh : true;
}

// J_0 of the boundary: journal_j0(p, D_fin), the 3 h written in (K C-DTB);
// never journal_depth(p) (P-01 / P-02).
inline std::uint64_t admit_j0(const LaneParams& p) noexcept { return journal_j0(p, kSealDepth); }

// S2.3 #3 (ruling 40, K C-DTB): a tip forking at f from c's chain is DEFERRED
// when pos(parent(c)) - f > J_0.
inline bool deep_tip_deferred(std::uint64_t pos_parent_c, std::uint64_t f, std::uint64_t j0) noexcept {
    return pos_parent_c > f && pos_parent_c - f > j0;
}

// S2.3 #3, the closure (ruling 41 S3b4-2 (a)): a branch the judging reads,
// forking at f* from c's chain, with pos(parent(c)) - f* > J_0.
inline bool closure_fork_deferred(std::uint64_t pos_parent_c, std::uint64_t f_star, std::uint64_t j0) noexcept {
    return pos_parent_c > f_star && pos_parent_c - f_star > j0;
}

// S1.3 #1b / S2.3 #1a inside a frame: every body (own and carried) read within
// the receipt buffer P-10; the bytes read_receipt_body_v3 consumes for each.
// false: a body above the buffer (the frame is DROPPED). A body that does not
// parse ends the scan (the decode refuses it).
inline bool frame_body_within_buffer(std::span<const std::uint8_t> body, std::uint64_t receipt_buffer) {
    BlobReader r(body.data(), body.size());
    std::uint8_t ver = 0;
    if (!r.read_byte(ver)) return true;
    const auto one = [&]() -> std::optional<bool> {
        const std::size_t before = r.remaining();
        ReceiptBodyV3 b;
        if (read_receipt_body_v3(r, b) != WireError::None) return std::nullopt;
        return before - r.remaining() <= receipt_buffer;
    };
    const std::optional<bool> own = one();
    if (!own) return true;
    if (!*own) return false;
    std::uint8_t n = 0;
    if (!r.read_byte(n)) return true;
    for (std::uint8_t i = 0; i < n; ++i) {
        const std::optional<bool> k = one();
        if (!k) return true;
        if (!*k) return false;
    }
    return true;
}

// The bytes of each body of a carrier body, as read (own first).
inline std::vector<std::uint64_t> body_lengths(std::span<const std::uint8_t> body) {
    std::vector<std::uint64_t> out;
    BlobReader r(body.data(), body.size());
    std::uint8_t ver = 0;
    if (!r.read_byte(ver)) return out;
    const auto one = [&]() -> bool {
        const std::size_t before = r.remaining();
        ReceiptBodyV3 b;
        if (read_receipt_body_v3(r, b) != WireError::None) return false;
        out.push_back(before - r.remaining());
        return true;
    };
    if (!one()) return out;
    std::uint8_t n = 0;
    if (!r.read_byte(n)) return out;
    for (std::uint8_t i = 0; i < n; ++i)
        if (!one()) return out;
    return out;
}

inline std::uint64_t encoded_length(const ReceiptBodyV3& b) {
    std::vector<std::uint8_t> out;
    encode_receipt_body_v3(b, out);
    return out.size();
}

// S2.3 #12: the check is called with tip = side_data.tip, p_r = blob.prev_id
// and hf = hf_version(h(r)); otherwise node-internal.
inline bool coinbase_args_bound(const ReceiptBodyV3& r, const Hash32& tip, const Hash32& p_r, std::uint8_t hf,
                                std::uint8_t hf_of_h) noexcept {
    return tip == r.side.tip && p_r == r.blob.prev_id && hf == hf_of_h;
}

// S2.3 #8: the placed ids of c's chain at its parent among `ids` (a PlacedSet
// for check_carried_list read from view_at(parent(c))).
inline PlacedSet placed_set_on(const LaneView& v, std::span<const Hash32> ids) {
    PlacedSet out;
    for (const Hash32& id : ids)
        if (v.placed_open(id)) out.place(id);
    return out;
}

// The row-4 gate (role Frame): the frame's parent forks from the store's
// best chain (store.best_tip()) at or above base_pos. false: DEFER
// OwnChainDeep. A parent below base_pos answers false at once; otherwise the
// ancestor of the parent at base_pos is compared with the store's best-chain
// carrier there (both walks stop at base_pos). Precondition: parent held.
inline bool own_chain_judged(const CarrierTree& tree, const BinStore& store, const Hash32& parent) {
    const CarrierNode* n = tree.find(parent);
    if (n == nullptr) return false;
    const std::uint64_t base = store.base_pos();
    if (n->pos < base) return false;  // the fork lies at or below the parent
    const std::optional<Hash32> a = tree.ancestor_at(parent, base);
    const std::optional<Hash32> b = store.best_at(base);
    return a.has_value() && b.has_value() && *a == *b;
}

// ---------------------------------------------------------------------------
// The result helpers
// ---------------------------------------------------------------------------
namespace admit_detail {

inline AdmitResult verdict(AdmitVerdict v, RowId row, std::size_t body = 0) {
    AdmitResult r;
    r.verdict = v;
    r.row = row;
    r.strike = static_cast<std::uint32_t>(strike_tokens(v));
    r.body = body;
    return r;
}

inline AdmitResult defer(Missing m, RowId row, std::size_t body = 0, const Hash32& fetch = Hash32{}) {
    AdmitResult r;
    r.verdict = AdmitVerdict::Defer;
    r.row = row;
    r.missing = m;
    r.body = body;
    r.fetch = fetch;
    return r;
}

// ClaimAlarm: DEFER, a local alarm with the row and the basis, no token, no BAN.
inline AdmitResult claim_alarm(const AdmitEnv& env, RowId row, Basis b, const Hash32& id, std::size_t body = 0) {
    AdmitResult r = defer(Missing::ClaimAlarm, row, body);
    r.alarm = true;
    env.alarm.raise(row, b, id, Missing::ClaimAlarm);
    return r;
}

// A failing row's word on a basis: a claim basis is ClaimAlarm (DEFER, alarm,
// no token, no BAN); a computed basis keeps the row's word.
inline AdmitResult fail_row(const AdmitEnv& env, AdmitVerdict v, RowId row, Basis b, const Hash32& id,
                            std::size_t body = 0) {
    if (is_claim_basis(b)) return claim_alarm(env, row, b, id, body);
    return verdict(v, row, body);
}

inline AdmitResult node_internal(const AdmitEnv& env, RowId row, const Hash32& id, std::size_t body = 0) {
    AdmitResult r = defer(Missing::NodeInternal, row, body);
    r.alarm = true;
    env.alarm.raise(row, Basis::Computed, id, Missing::NodeInternal);
    return r;
}

}  // namespace admit_detail

// ---------------------------------------------------------------------------
// The judged frame's own chain: c's chain at and below parent(c).
// ---------------------------------------------------------------------------
class OwnChain {
public:
    OwnChain(const AdmitEnv& env, const Hash32& parent) : env_(env), parent_(parent) {
        const CarrierNode* n = env.tree.find(parent);
        if (n == nullptr) return;
        held_ = true;
        pos_ = n->pos;
        lo_ = pos_ > env.j0 ? pos_ - env.j0 : 0;
        // parent(c) on the store's best chain: c's chain at and below it is read from the store (best_at)
        if (const std::optional<Hash32> b = env.store.best_at(pos_); b.has_value() && *b == parent) {
            on_best_ = true;
            return;
        }
        // c's chain from parent(c) down to cache_lo; below it c's chain is the store's best chain
        const std::uint64_t base = env.store.base_pos();
        cache_lo_ = std::min(lo_, base > env.j0 ? base - env.j0 : 0);
        ids_.resize(pos_ - cache_lo_ + 1);
        const CarrierNode* x = n;
        for (std::uint64_t k = pos_ + 1; k-- > cache_lo_;) {
            ids_[k - cache_lo_] = x->id;
            if (k == cache_lo_ || x->pos == 0) break;
            x = env.tree.find(x->parent);
            if (x == nullptr) break;
        }
        const std::optional<Hash32> b = env.store.best_at(cache_lo_);
        below_is_best_ = b.has_value() && *b == ids_[0];
    }

    bool held() const noexcept { return held_; }
    // pos(parent(c)): the position the boundary and the closure count from.
    std::uint64_t pos() const noexcept { return pos_; }
    // pos(parent(c)) - J_0 (0 when the chain is shorter).
    std::uint64_t lo() const noexcept { return lo_; }

    // The carrier at position k on c's chain (k <= pos(parent(c))).
    std::optional<Hash32> at(std::uint64_t k) const {
        if (!held_ || k > pos_) return std::nullopt;
        if (on_best_) return env_.store.best_at(k);
        if (k >= cache_lo_) return ids_[k - cache_lo_];
        if (below_is_best_) return env_.store.best_at(k);
        return env_.tree.ancestor_at(parent_, k);
    }
    bool contains(const Hash32& id, std::uint64_t k) const {
        const std::optional<Hash32> a = at(k);
        return a.has_value() && *a == id;
    }
    // H(k) on c's chain.
    std::optional<std::uint64_t> record(std::uint64_t k) const {
        const std::optional<Hash32> a = at(k);
        if (!a) return std::nullopt;
        const CarrierNode* n = env_.tree.find(*a);
        if (n == nullptr) return std::nullopt;
        return n->H;
    }

private:
    const AdmitEnv& env_;
    Hash32 parent_{};
    bool held_ = false;
    std::uint64_t pos_ = 0;
    std::uint64_t lo_ = 0;
    std::uint64_t cache_lo_ = 0;
    bool on_best_ = false;
    bool below_is_best_ = false;
    std::vector<Hash32> ids_;
};

// ---------------------------------------------------------------------------
// The EP-4 walk, the ruling-40 boundary and the ruling-41 closure (S2.3 #3):
// from headers and carried bodies only, before any state of these branches
// is read. Existential over the held header variants and body sets, memoised
// by (id, header digest) for the frame; no token on any path.
// ---------------------------------------------------------------------------
enum class WalkVerdict : std::uint8_t {
    OnChain,      // t on c's chain: not touched
    Placed,       // a passing assignment, every walked carrier placed: judge on the bound branch
    Bind,         // a passing assignment that holds an unbound header: bind and place it first (TipBodies)
    Boundary,     // t's fork more than J_0 below parent(c) on every held path (ruling 40)
    Closure,      // every held assignment reads a branch forked more than J_0 below parent(c) (ruling 41)
    NeedHeaders,  // a walked header not held (TipHeaders)
    NeedBodies,   // a walked carrier's carried bodies not held (ClosureBodies)
};

struct WalkResult {
    WalkVerdict v = WalkVerdict::Boundary;
    std::uint64_t f = 0;      // the fork position of t's branch with c's chain
    std::uint64_t pos_t = 0;  // pos(t) on the passing path
    bool claim_based = false; // decided while an unbound header was walked
    Hash32 fetch{};
    std::vector<Hash32> walked;          // every id walked
    std::vector<Hash32> bind;            // Bind: the unbound ids of the passing assignment, fork upward
    std::vector<std::pair<std::uint64_t, Hash32>> refuted_sets;  // body sets a computed fold refutes: (peer, carrier)
    std::vector<std::uint64_t> tokens;   // peers a walk charged (none: a walk gives no token)
    std::uint64_t d_tip = 0;             // d_at(t's chain, pos(t) + 1) on the passing path (a claim before binding)
};

class ClosureWalk {
public:
    ClosureWalk(const AdmitEnv& env, const OwnChain& own) : env_(env), own_(own), closure_(true) {}

    // The walk of a carried receipt's tip t.
    // claim_based, walked and refuted_sets accumulate over the frame's tips.
    WalkResult walk_tip(const Hash32& t) {
        WalkResult out;
        const Res r = resolve_id(t);
        out.claim_based = claim_;
        out.walked.assign(walked_.begin(), walked_.end());
        out.refuted_sets = refuted_;
        out.tokens = tokens_;
        switch (r.kind) {
            case Kind::Pass:
                out.f = r.st->f;
                out.pos_t = r.st->pos;
                out.d_tip = d_after(r.st);
                if (r.st->on_chain) {
                    out.v = WalkVerdict::OnChain;
                    return out;
                }
                out.v = r.st->placed ? WalkVerdict::Placed : WalkVerdict::Bind;
                if (!r.st->placed) collect_bind(r.st, out.bind);
                return out;
            case Kind::Boundary: out.v = WalkVerdict::Boundary; return out;
            case Kind::NeedHeaders: out.v = WalkVerdict::NeedHeaders; out.fetch = r.fetch; return out;
            case Kind::NeedBodies: out.v = WalkVerdict::NeedBodies; out.fetch = r.fetch; return out;
            case Kind::Closure:
            case Kind::NoPass: out.v = WalkVerdict::Closure; return out;
        }
        return out;
    }

    std::uint64_t states() const noexcept { return states_.size(); }
    // The most frames the walk's stack held at once (the depth of the walked chains).
    std::size_t max_frames() const noexcept { return max_frames_; }

private:
    enum class Kind : std::uint8_t { Pass, Boundary, Closure, NeedHeaders, NeedBodies, NoPass };

    // The state after a walked node on one path.
    struct State {
        Hash32 id{};
        Hash32 digest{};                 // zero for a tree node
        bool tree = false;               // a placed carrier (bound)
        bool on_chain = false;           // on c's chain
        bool placed = true;              // every walked node of the path above f is placed
        const State* parent = nullptr;   // the walked node below (nullptr: the parent lies on c's chain)
        std::uint64_t pos = 0;
        std::uint64_t f = 0;             // the fork with c's chain
        std::uint64_t h = 0;
        std::uint64_t H = 0;
        std::uint64_t d = 0;
        RatchetState S{};
        std::vector<const State*> nested;  // the passing states of the branches its carried tips enter
        mutable std::optional<std::uint64_t> d_next;  // d_at after this node on its path (cached)
    };

    struct Res {
        Kind kind = Kind::NoPass;
        const State* st = nullptr;
        Hash32 fetch{};
    };

    static Res fail(Kind k, const Hash32& fetch = Hash32{}) { return Res{k, nullptr, fetch}; }

    // Order of the failure kinds when no option passes: a fetch first, then the depth.
    static Kind combine(Kind a, Kind b) {
        const auto rank = [](Kind k) {
            switch (k) {
                case Kind::NeedHeaders: return 5;
                case Kind::NeedBodies: return 4;
                case Kind::Closure: return 3;
                case Kind::Boundary: return 2;
                case Kind::NoPass: return 1;
                case Kind::Pass: return 6;
            }
            return 0;
        };
        return rank(a) >= rank(b) ? a : b;
    }

    // Every passing state of a walked id (a placed carrier, else each held
    // header variant, bound first), and the failure when none passes.
    struct Options {
        std::vector<const State*> pass;
        Res fail;
    };

    using Key = std::pair<Hash32, Hash32>;

    // The memo key of a header variant: (id, digest).
    static Key variant_key(const HeaderVariant& y) { return Key{y.id, y.digest}; }

    // ---- the walk's explicit stack ----
    // A frame stands for one call of the walk: Options (the passing states of
    // an id; IdFirst: its first passing state), Tree (a placed carrier), Variant
    // (a held header variant on each passing state of its claimed parent),
    // OnParent (the variant on one parent state, over its body sets), Nested (a
    // placed carrier's carried tips), Replay (a body set's tips with S replayed)
    // and Tip (one carried body's tip). A frame calls another by pushing it and
    // resumes at its next stage with the callee's result in ret_ (ret_opts_ for
    // Options); no frame calls the walk recursively.
    enum class Op : std::uint8_t { Options, IdFirst, Tree, Variant, OnParent, Nested, Replay, Tip };

    struct Frame {
        Op op = Op::Options;
        std::uint8_t stage = 0;
        Hash32 id{};                                         // Options, IdFirst
        const CarrierNode* node = nullptr;                   // Tree
        const HeaderVariant* y = nullptr;                    // Variant, OnParent
        const State* ps = nullptr;                           // OnParent, Replay: the parent state
        State* s = nullptr;                                  // Tree, OnParent, Nested, Replay, Tip
        const std::vector<ReceiptBodyV3>* bodies = nullptr;  // Nested, Replay
        const ReceiptBodyV3* b = nullptr;                    // Tip
        std::vector<const HeaderVariant*> vs;                // Options: the held variants
        std::vector<const BodySet*> tries;                   // OnParent: the body sets tried
        std::vector<RatchetPlacement> placed;                // Replay: the placements replayed
        Options opts;                                        // Options: the result; Variant: the parent's
        std::size_t i = 0;                                   // the next variant / parent state / set / body
        Kind worst = Kind::NoPass;
        Hash32 fetch{};
        std::uint64_t d = 0;                                 // OnParent: d after the parent state
        std::uint16_t ballot = 0;                            // Replay: the carrier's ballot
    };

    static Frame options_frame(const Hash32& id, Op op) {
        Frame f;
        f.op = op;
        f.id = id;
        return f;
    }
    static Frame tree_frame(const CarrierNode& n) {
        Frame f;
        f.op = Op::Tree;
        f.node = &n;
        return f;
    }
    static Frame variant_frame(const HeaderVariant& y) {
        Frame f;
        f.op = Op::Variant;
        f.y = &y;
        return f;
    }
    static Frame on_parent_frame(const HeaderVariant& y, const State& ps) {
        Frame f;
        f.op = Op::OnParent;
        f.y = &y;
        f.ps = &ps;
        return f;
    }
    static Frame nested_frame(State& s, const std::vector<ReceiptBodyV3>& carried) {
        Frame f;
        f.op = Op::Nested;
        f.s = &s;
        f.bodies = &carried;
        return f;
    }
    static Frame replay_frame(State& s, const State& ps, const std::vector<ReceiptBodyV3>& bodies, std::uint16_t ballot) {
        Frame f;
        f.op = Op::Replay;
        f.s = &s;
        f.ps = &ps;
        f.bodies = &bodies;
        f.ballot = ballot;
        return f;
    }
    static Frame tip_frame(State& s, const ReceiptBodyV3& b) {
        Frame f;
        f.op = Op::Tip;
        f.s = &s;
        f.b = &b;
        return f;
    }

    void call(Frame f) {
        stack_.push_back(std::move(f));
        max_frames_ = std::max(max_frames_, stack_.size());
    }
    void ret(const Res& r) {
        const Res out = r;
        stack_.pop_back();
        ret_ = out;
    }
    void ret_options(Options o) {
        stack_.pop_back();
        ret_opts_ = std::move(o);
    }

    // A walked id: its first passing state, else the failure.
    Res resolve_id(const Hash32& id) {
        stack_.clear();
        call(options_frame(id, Op::IdFirst));
        while (!stack_.empty()) {
            Frame& f = stack_.back();
            switch (f.op) {
                case Op::Options:
                case Op::IdFirst: step_options(f); break;
                case Op::Tree: step_tree(f); break;
                case Op::Variant: step_variant(f); break;
                case Op::OnParent: step_on_parent(f); break;
                case Op::Nested: step_nested(f); break;
                case Op::Replay: step_replay(f); break;
                case Op::Tip: step_tip(f); break;
            }
        }
        return ret_;
    }

    // Options / IdFirst: walked; a placed carrier, else every held variant.
    void step_options(Frame& f) {
        if (f.stage == 0) {
            walked_.insert(f.id);
            f.opts.fail = fail(Kind::NoPass);
            if (const CarrierNode* n = env_.tree.find(f.id)) {
                f.stage = 1;
                return call(tree_frame(*n));
            }
            f.vs = env_.headers.variants(f.id);
            if (f.vs.empty()) {
                f.opts.fail = fail(Kind::NeedHeaders, f.id);
                return finish_options(f);
            }
            f.stage = 2;
            return call(variant_frame(*f.vs[0]));
        }
        if (f.stage == 1) {  // the placed carrier's result
            if (ret_.kind == Kind::Pass)
                f.opts.pass.push_back(ret_.st);
            else
                f.opts.fail = ret_;
            return finish_options(f);
        }
        // stage 2: a variant's result
        const Res r = ret_;
        if (r.kind == Kind::Pass) {
            f.opts.pass.push_back(r.st);
        } else {
            if (combine(r.kind, f.opts.fail.kind) == r.kind && r.kind != f.opts.fail.kind) f.opts.fail.fetch = r.fetch;
            f.opts.fail.kind = combine(f.opts.fail.kind, r.kind);
        }
        if (++f.i < f.vs.size()) return call(variant_frame(*f.vs[f.i]));
        return finish_options(f);
    }

    void finish_options(Frame& f) {
        if (f.op == Op::IdFirst)
            return ret(!f.opts.pass.empty() ? Res{Kind::Pass, f.opts.pass.front(), {}} : f.opts.fail);
        return ret_options(std::move(f.opts));
    }

    // Tree: a placed carrier on c's chain, below the boundary, or on a branch
    // (its parent, then its carried tips).
    void step_tree(Frame& f) {
        const CarrierNode& n = *f.node;
        const Key key{n.id, Hash32{}};
        if (f.stage == 0) {
            if (const auto m = memo_.find(key); m != memo_.end()) return ret(m->second);
            if (own_.contains(n.id, n.pos)) {
                State& s = state(n.id, Hash32{});
                s.tree = true;
                s.on_chain = true;
                s.pos = n.pos;
                s.f = n.pos;
                s.h = n.h;
                s.H = n.H;
                s.d = n.d;
                s.S = n.rs;
                return done(key, Res{Kind::Pass, &s, {}});
            }
            if (n.pos < own_.lo() || n.pos == 0) return done(key, fail(Kind::Boundary));  // off c's chain below pos(parent(c)) - J_0
            memo_[key] = fail(Kind::NoPass);  // in progress
            const CarrierNode* pn = env_.tree.find(n.parent);
            f.stage = 1;
            if (pn == nullptr) {
                ret_ = fail(Kind::NoPass);
                return;
            }
            return call(tree_frame(*pn));
        }
        if (f.stage == 1) {  // the parent's result
            const Res pr = ret_;
            if (pr.kind != Kind::Pass) return done(key, fail(pr.kind == Kind::NoPass ? Kind::NoPass : pr.kind, pr.fetch));
            if (pr.st->on_chain && deep_tip_deferred(own_.pos(), pr.st->pos, env_.j0))
                return done(key, fail(Kind::Boundary));  // meets c's chain below pos(parent(c)) - J_0
            State& s = state(n.id, Hash32{});
            s.tree = true;
            s.parent = pr.st->on_chain ? nullptr : pr.st;
            s.pos = n.pos;
            s.f = pr.st->f;
            s.h = n.h;
            s.H = n.H;
            s.d = n.d;
            s.S = n.rs;
            s.placed = pr.st->placed;
            const CarrierBodyV3* body = env_.bodies.get(n.id);
            if (body == nullptr) return done(key, fail(Kind::NeedBodies, n.id));
            f.s = &s;
            f.stage = 2;
            return call(nested_frame(s, body->carried));
        }
        // stage 2: the carried tips' result
        const Res nr = ret_;
        return done(key, nr.kind == Kind::Pass ? Res{Kind::Pass, f.s, {}} : nr);
    }

    void done(const Key& key, const Res& out) {
        memo_[key] = out;
        ret(out);
    }

    // Variant: a held header variant, existential over the passing states of
    // its claimed parent; in progress it does not pass (a cycle).
    void step_variant(Frame& f) {
        const HeaderVariant& y = *f.y;
        const Key key = variant_key(y);
        if (f.stage == 0) {
            if (const auto m = memo_.find(key); m != memo_.end()) return ret(m->second);
            memo_[key] = fail(Kind::NoPass);  // in progress: a cycle does not pass
            if (!y.bound) claim_ = true;
            if (!y.path_ok) return done(key, fail(Kind::NoPass));
            // the third Boundary test: h(y) < H(pos(parent(c)) - J_0) on c's chain
            const std::optional<std::uint64_t> h_lo = own_.record(own_.lo());
            if (h_lo && y.height < *h_lo) return done(key, fail(Kind::Boundary));
            f.stage = 1;
            return call(options_frame(y.header.own.side.tip, Op::Options));
        }
        if (f.stage == 1) {  // the claimed parent's passing states
            f.opts = std::move(ret_opts_);
            if (f.opts.pass.empty()) return done(key, f.opts.fail);
            f.stage = 2;
            return call(on_parent_frame(y, *f.opts.pass[0]));
        }
        // stage 2: y on one passing state of its claimed parent
        const Res r = ret_;
        if (r.kind == Kind::Pass) return done(key, r);
        if (combine(r.kind, f.worst) == r.kind && r.kind != f.worst) f.fetch = r.fetch;
        f.worst = combine(f.worst, r.kind);
        if (++f.i < f.opts.pass.size()) return call(on_parent_frame(y, *f.opts.pass[f.i]));
        return done(key, fail(f.worst, f.fetch));
    }

    // OnParent: y on one passing state of its claimed parent, over its body sets.
    void step_on_parent(Frame& f) {
        const HeaderVariant& y = *f.y;
        const State& ps = *f.ps;
        const ReceiptBodyV3& own = y.header.own;
        if (f.stage == 0) {
            if (ps.on_chain && deep_tip_deferred(own_.pos(), ps.pos, env_.j0)) return ret(fail(Kind::Boundary));
            // the carrier at its position on the claimed path: monotone record, t_origin == d there
            if (!carrier_height_admissible(ps.H, y.height)) return ret(fail(Kind::NoPass));
            const std::uint64_t d = d_after(&ps);
            if (!origin_target_ok(own.side.t_origin, d)) return ret(fail(Kind::NoPass));  // d on this path is a claim: no token
            // its carried list: a body set that folds with its receipts_root over S at the parent
            const std::vector<const BodySet*> sets = env_.headers.body_sets(y.id);
            if (y.header.n_carried > 0 && sets.empty()) return ret(fail(Kind::NeedBodies, y.id));
            f.tries = sets;
            if (y.header.n_carried == 0) f.tries.assign(1, nullptr);
            f.d = d;
            f.stage = 1;
        } else if (f.stage == 2) {  // the nested tips' result for f.tries[f.i]
            const Res nr = ret_;
            if (nr.kind == Kind::Pass) return ret(Res{Kind::Pass, f.s, {}});
            if (combine(nr.kind, f.worst) == nr.kind && nr.kind != f.worst) f.fetch = nr.fetch;
            f.worst = combine(f.worst, nr.kind);
            ++f.i;
            f.stage = 1;
        }
        // stage 1: the next body set that folds
        for (; f.i < f.tries.size(); ++f.i) {
            const BodySet* bs = f.tries[f.i];
            const std::vector<ReceiptBodyV3>& bodies = bs ? bs->bodies : no_bodies_;
            if (bodies.size() != y.header.n_carried) continue;
            std::vector<Hash32> ids;
            for (const ReceiptBodyV3& b : bodies) ids.push_back(receipt_id(b));
            if (check_carried_fold(own.side.receipts_root, ids, ps.S) != FoldVerdict::Match) {
                // computed only at a placed parent with the bound header or the same reply's header
                const bool computed = ps.tree && bs != nullptr && (y.bound || bs->reply_header == y.digest);
                if (computed) refuted_.emplace_back(bs->peer, y.id);
                continue;  // on a claimed path: not a passing assignment, no token
            }
            State& s = state(y.id, y.digest);
            s.parent = ps.on_chain ? nullptr : &ps;
            s.pos = ps.pos + 1;
            s.f = ps.on_chain ? ps.pos : ps.f;
            s.h = y.height;
            s.H = record_height(ps.H, y.height);
            s.d = f.d;
            s.placed = false;
            s.nested.clear();
            f.s = &s;
            f.stage = 2;
            return call(replay_frame(s, ps, bodies, own.side.ballot));
        }
        return ret(fail(f.worst, f.fetch));
    }

    // Nested: the nested tips of a placed carrier's carried bodies (its S is bound).
    void step_nested(Frame& f) {
        if (f.stage == 1) {  // the tip's result for body f.i
            const Res r = ret_;
            if (r.kind != Kind::Pass) return ret(r);
            ++f.i;
        }
        if (f.i >= f.bodies->size()) return ret(Res{Kind::Pass, f.s, {}});
        f.stage = 1;
        return call(tip_frame(*f.s, (*f.bodies)[f.i]));
    }

    // Replay: the nested tips of a header variant's body set, with S replayed
    // by rs_step_at over its placements (work = d_at on each body's tip chain,
    // dead = 0 by #17 on the walked chain, then the carrier at its side d).
    void step_replay(Frame& f) {
        State& s = *f.s;
        const State& ps = *f.ps;
        if (f.stage == 0) {
            f.placed.reserve(f.bodies->size() + 1);
        } else {  // the tip's result for body f.i
            const Res r = ret_;
            if (r.kind != Kind::Pass) return ret(r);
            const ReceiptBodyV3& b = (*f.bodies)[f.i];
            if (r.st == nullptr) {
                f.placed.push_back(RatchetPlacement{b.side.t_origin, b.side.ballot});
            } else {
                const State& t = *r.st;
                const std::uint64_t d_tip = d_after(&t);
                if (!origin_target_ok(b.side.t_origin, d_tip)) return ret(fail(Kind::NoPass));
                // #17 on the walked chain: h(r) >= H(min(q - 1, p(r)))
                const std::uint64_t q = s.pos;
                const std::uint64_t thr = std::min(q - 1, t.pos + 1);
                const std::optional<std::uint64_t> h_thr = record_on(&ps, thr);
                if (!h_thr) return ret(fail(Kind::NoPass));
                // h(r) is the body's own Monero height: from P_r
                const PrInfo pr = env_.resolve_pr ? env_.resolve_pr(b.blob.prev_id) : PrInfo{};
                if (pr.status != PrInfo::Status::Held) return ret(fail(Kind::NoPass));
                const bool live = pr.height + 1 >= *h_thr;
                f.placed.push_back(RatchetPlacement{live ? b.side.t_origin : 0, b.side.ballot});
            }
            ++f.i;
        }
        if (f.i < f.bodies->size()) {
            f.stage = 1;
            return call(tip_frame(s, (*f.bodies)[f.i]));
        }
        f.placed.push_back(RatchetPlacement{s.d, f.ballot});
        s.S = rs_step_at(env_.rp, ps.S, s.pos, f.placed, env_.T).s;
        return ret(Res{Kind::Pass, &s, {}});
    }

    // Tip: a carried body's tip: on c's chain (not touched), on the walked
    // path, or a branch the closure enters (its fork more than J_0 below
    // parent(c): Closure).
    void step_tip(Frame& f) {
        if (f.stage == 0) {
            const Hash32& t = f.b->side.tip;
            if (!closure_) return ret(Res{Kind::Pass, nullptr, {}});
            for (const State* p = f.s->parent; p != nullptr; p = p->parent)
                if (p->id == t) return ret(Res{Kind::Pass, p, {}});  // a tip on the walked path: the same branch
            f.stage = 1;
            return call(options_frame(t, Op::IdFirst));
        }
        const Res r = ret_;
        if (r.kind == Kind::Boundary) return ret(fail(Kind::Closure));
        if (r.kind != Kind::Pass) return ret(r);
        if (r.st->on_chain) return ret(r);  // a tip on c's chain is not touched
        if (closure_fork_deferred(own_.pos(), r.st->f, env_.j0)) return ret(fail(Kind::Closure));
        f.s->nested.push_back(r.st);
        return ret(r);
    }

    // H at position k on the chain through `s` (walked nodes, then c's chain).
    std::optional<std::uint64_t> record_on(const State* s, std::uint64_t k) const {
        for (const State* x = s; x != nullptr; x = x->parent) {
            if (x->on_chain) break;
            if (x->pos == k) return x->H;
            if (x->pos < k) return std::nullopt;
        }
        return own_.record(k);
    }

    // d_at after a walked node on its path (a placed node: the tree's).
    std::uint64_t d_after(const State* s) const {
        if (!s->d_next) {
            s->d_next = s->on_chain || s->tree ? env_.tree.next_difficulty(s->id).value_or(0)
                                               : window_after(s).next_difficulty();
        }
        return *s->d_next;
    }

    // The retarget window after a walked node: the walked nodes' (d, H), then
    // the tree's window at the fork.
    RetargetWindow window_after(const State* s) const {
        std::vector<RetargetEntry> rev;
        const State* x = s;
        for (; x != nullptr && !x->on_chain && rev.size() < env_.p.retarget_span; x = x->parent)
            rev.push_back(RetargetEntry{x->d, x->H});
        Hash32 anchor{};
        if (x != nullptr && x->on_chain) {
            anchor = x->id;
        } else {
            const std::optional<Hash32> a = own_.at(s->f);
            anchor = a.value_or(Hash32{});
        }
        RetargetWindow w(env_.p);
        if (const std::optional<RetargetWindow> base = env_.tree.window_after(anchor)) w = *base;
        std::vector<RetargetEntry> entries(w.entries().begin(), w.entries().end());
        std::reverse(rev.begin(), rev.end());
        entries.insert(entries.end(), rev.begin(), rev.end());
        return RetargetWindow(env_.p, entries);
    }

    // The unbound ids of a passing assignment, fork upward: each walked path
    // from its lowest node up, the branches its nodes' carried tips enter
    // before the node itself; each state and each id once (an explicit stack).
    void collect_bind(const State* s, std::vector<Hash32>& out) const {
        std::set<const State*> seen;
        std::set<Hash32> listed(out.begin(), out.end());
        struct Level {
            std::vector<const State*> chain;  // the path from s down (s first)
            std::size_t ci = 0;               // the nodes of chain still to finish (from the lowest)
            std::size_t ni = 0;               // the next nested branch of chain[ci - 1]
        };
        const auto level = [&](const State* top) {
            Level l;
            for (const State* x = top; x != nullptr && !x->on_chain && seen.insert(x).second; x = x->parent) l.chain.push_back(x);
            l.ci = l.chain.size();
            return l;
        };
        std::vector<Level> st;
        st.push_back(level(s));
        while (!st.empty()) {
            Level& l = st.back();
            if (l.ci == 0) {
                st.pop_back();
                continue;
            }
            const State* x = l.chain[l.ci - 1];
            if (l.ni < x->nested.size()) {
                const State* n = x->nested[l.ni++];
                st.push_back(level(n));
                continue;
            }
            if (!x->tree && listed.insert(x->id).second) out.push_back(x->id);
            --l.ci;
            l.ni = 0;
        }
    }

    State& state(const Hash32& id, const Hash32& digest) {
        auto [it, ins] = states_.try_emplace(Key{id, digest});
        it->second.id = id;
        it->second.digest = digest;
        it->second.d_next.reset();
        return it->second;
    }

    const AdmitEnv& env_;
    const OwnChain& own_;
    std::map<Key, Res> memo_;
    std::map<Key, State> states_;  // node-stable storage (std::map)
    std::set<Hash32> walked_;
    std::vector<std::pair<std::uint64_t, Hash32>> refuted_;
    std::vector<std::uint64_t> tokens_;
    bool claim_ = false;
    bool closure_;
    std::deque<Frame> stack_;
    Res ret_;
    Options ret_opts_;
    std::size_t max_frames_ = 0;
    const std::vector<ReceiptBodyV3> no_bodies_;
};


// ---------------------------------------------------------------------------
// The rows
// ---------------------------------------------------------------------------
namespace admit_detail {

// One body under judgement.
struct Body {
    const ReceiptBodyV3* r = nullptr;
    std::uint64_t bytes = 0;  // its length as received
    Hash32 id{};
    std::uint64_t h = 0;      // h(r) = height(P_r) + 1
    HeaderInputs in{};        // P_r's branch for a child
    const CarrierNode* tip = nullptr;
    std::uint64_t f = 0;      // the tip's fork with the placing chain (row 17)
};

// P_t: the Monero parent t committed (C-7: position 0 = the pool identity's block).
inline std::optional<Hash32> tip_prev_id(const AdmitEnv& env, const Hash32& tip) {
    if (tip == env.tree.genesis().id) return env.genesis_prev;
    const CarrierBodyV3* b = env.bodies.get(tip);
    if (b == nullptr) return std::nullopt;
    return b->own.blob.prev_id;
}

// S1.3 #4 / S2.3 #5: P_r on a verified branch; h(r) = height(P_r) + 1.
inline std::optional<AdmitResult> pr_row(const AdmitEnv& env, Body& b, RowId row, std::size_t idx) {
    const PrInfo pr = env.resolve_pr ? env.resolve_pr(b.r->blob.prev_id) : PrInfo{};
    const Resolve res = pr.status == PrInfo::Status::Held      ? Resolve::Ready
                        : pr.status == PrInfo::Status::Missing ? Resolve::DeferUnknownPr
                                                               : Resolve::BanBadCtx;
    if (res != Resolve::Ready) {
        const AdmitVerdict v = admit_resolution(res);  // DEFER + fetch, or BAN the server
        return v == AdmitVerdict::Defer ? defer(Missing::MoneroBlock, row, idx, b.r->blob.prev_id) : verdict(v, row, idx);
    }
    b.h = pr.height + 1;
    b.in = pr.in;
    return std::nullopt;
}

// S1.3 #2 / S2.3 #4: rules_epoch per frame_verdict. held: S_{pos(t)} for (i);
// nullopt: (ii) fork-local (a carried receipt).
inline std::optional<AdmitResult> epoch_row(const AdmitEnv& env, const Body& b, const CarrierNode& tip,
                                            const std::optional<RatchetState>& held, RowId row, std::size_t idx) {
    const std::uint64_t x = tip.pos + 1;
    const Basis basis = basis_of(env.claims, RowClass::Epoch, tip.id, x);
    if (basis == Basis::NotComputed) return std::nullopt;
    const CarrierNode* best = env.tree.find(env.store.best_tip());
    if (best == nullptr) return node_internal(env, row, b.id, idx);
    // f: the tip's fork with the store's best chain (the tip itself when it lies on it; else the walk
    // from the tip stops at the first best-chain carrier)
    const std::optional<Hash32> fp = env.tree.newest_ancestor_where(tip.id, [&](const Hash32& id, std::uint64_t pos) {
        const std::optional<Hash32> on_best = env.store.best_at(pos);
        return on_best.has_value() && *on_best == id;
    });
    if (!fp) return node_internal(env, row, b.id, idx);
    const std::uint64_t f = env.tree.find(*fp)->pos;
    const EpochAt ea = epoch_at(env.rp, env.T, held, env.ar, best->pos, best->rs, f, x);
    const std::uint64_t hold_at = h_hold(env.rp, tip.rs, x, env.T);
    switch (frame_verdict(x, b.r->side.rules_epoch, hold_at, ea)) {
        case FrameVerdict::Judge: return std::nullopt;
        case FrameVerdict::Strike: return fail_row(env, AdmitVerdict::Strike, row, basis, b.id, idx);
        case FrameVerdict::Defer:
            return defer(ea.kind == EpochAtKind::Defer ? Missing::EpochGrace : Missing::Hold, row, idx);
    }
    return node_internal(env, row, b.id, idx);
}

// S1.3 #7 / S2.3 #9: header fields, the vote rule, the size rules and the cap.
inline std::optional<AdmitResult> header_row(const Body& b, RowId row, std::size_t idx) {
    if (header_fields_verdict(header_fields(*b.r, b.bytes, b.in))) return verdict(AdmitVerdict::Strike, row, idx);
    return std::nullopt;
}

// S1.3 #8 / S2.3 #11: t_origin == d_at(chain of tip, pos(tip) + 1).
inline std::optional<AdmitResult> retarget_row(const AdmitEnv& env, const Body& b, const CarrierNode& tip, RowId row,
                                               std::size_t idx) {
    const std::uint64_t x = tip.pos + 1;
    const Basis basis = basis_of(env.claims, RowClass::Retarget, tip.id, x);
    if (basis == Basis::NotComputed) return std::nullopt;
    const std::optional<std::uint64_t> d = env.tree.next_difficulty(tip.id);
    if (!d) return node_internal(env, row, b.id, idx);
    if (!origin_target_ok(b.r->side.t_origin, *d)) return fail_row(env, AdmitVerdict::Strike, row, basis, b.id, idx);
    return std::nullopt;
}

// A window DEFER: what to fetch, or node-internal.
inline AdmitResult window_defer(const AdmitEnv& env, const TipWindow& tw, const Body& b, RowId row, std::size_t idx) {
    switch (tw.defer) {
        case WindowDefer::TipNotHeld: return defer(Missing::TipBodies, row, idx, tw.tip);
        case WindowDefer::MissingBlock:
        case WindowDefer::Inconsistent: return defer(Missing::MissingBlock, row, idx, tw.missing_id);
        case WindowDefer::MissingWeights: return defer(Missing::MissingWeights, row, idx, tw.missing_id);
        case WindowDefer::MissingBucket: {
            // FC_GETBUCKETS at a bound carrier on the best chain above the bin's seal
            AdmitResult r = defer(Missing::MissingBucket, row, idx, env.store.best_tip());
            r.fetch_bin = tw.missing_bin;
            return r;
        }
        case WindowDefer::MissingEntries:
        case WindowDefer::SealedCut: {
            AdmitResult r = node_internal(env, row, b.id, idx);  // below the P-37 floor inside the horizon
            r.missing = Missing::MissingEntries;
            r.fetch_bin = tw.missing_bin;
            return r;
        }
        case WindowDefer::TipDeep:
        case WindowDefer::None: break;
    }
    return node_internal(env, row, b.id, idx);  // Deep reaching a row
}

// S1.3 #9 / S2.3 #12 with #13: the canonical coinbase of window(tip, v) and the
// roots at the tip. RandomX is not called here.
inline std::optional<AdmitResult> coinbase_row(const AdmitEnv& env, const Body& b, const Hash32& tip, std::uint64_t x,
                                               RowId row, RowId roots_row, std::size_t idx) {
    const Basis basis = basis_of(env.claims, RowClass::Coinbase, tip, x);
    if (basis == Basis::NotComputed) return std::nullopt;  // not run (D35)
    const std::uint8_t v = b.in.hf;
    if (amount_fork_fused(v)) return verdict(AdmitVerdict::Refuse, row, idx);  // FORK-FUSE: no token, no RandomX
    const std::optional<Hash32> p_t = tip_prev_id(env, tip);
    if (!p_t) return defer(Missing::TipBodies, row, idx, tip);
    const Hash32 author_id = key_ref_identity(env.author);
    const TipWindow tw = env.windows.get(
            tip, v, [&] { return evaluate_window_at(env.store, tip, *p_t, env.monero, v, author_id); });
    if (!tw.ok()) return window_defer(env, tw, b, row, idx);
    const WindowAt at = window_at(tw);
    if (!coinbase_args_bound(*b.r, tip, b.r->blob.prev_id, v, b.in.hf)) return node_internal(env, row, b.id, idx);
    const CoinbaseCheck cb =
            canonical_coinbase_check(*b.r, at, tip, b.r->blob.prev_id, b.h, v, env.keys, env.refs, env.author);
    const Basis roots_basis = basis_of(env.claims, RowClass::Roots, tip, x);
    const bool roots = roots_basis == Basis::NotComputed || roots_ok_at(b.r->side, at);
    const TailResult w = coinbase_roots_word(cb, roots);
    switch (w.verdict) {
        case AdmitVerdict::AdmitCarrier: return std::nullopt;
        case AdmitVerdict::Refuse: return verdict(AdmitVerdict::Refuse, row, idx);
        case AdmitVerdict::Defer:
            if (w.alarm) return node_internal(env, row, b.id, idx);
            return defer(Missing::MissingRef, row, idx);  // a window payee's reference
        case AdmitVerdict::Ban:
            if (cb == CoinbaseCheck::IdentityGuard) return verdict(AdmitVerdict::Ban, row, idx);
            if (cb == CoinbaseCheck::Match) return fail_row(env, AdmitVerdict::Ban, roots_row, roots_basis, b.id, idx);
            return fail_row(env, AdmitVerdict::Ban, row, basis, b.id, idx);
        default: break;
    }
    return node_internal(env, row, b.id, idx);
}

// S1.3 #11 / S2.3 #15: RandomX at d with the seed of P_r's branch.
inline std::optional<AdmitResult> randomx_row(const AdmitEnv& env, const Body& b, RowId row, std::size_t idx,
                                              bool& called) {
    const std::optional<Hash32> seed = env.seed_of ? env.seed_of(b.r->blob.prev_id) : std::nullopt;
    if (!seed) return defer(Missing::Seed, row, idx, b.r->blob.prev_id);
    called = true;
    if (!env.randomx || !env.randomx(b.r->blob, b.r->side.t_origin, *seed)) return verdict(AdmitVerdict::Ban, row, idx);
    return std::nullopt;
}

inline Placement placement_of(const ReceiptBodyV3& r, const Hash32& id, std::uint64_t h_r, std::uint64_t p_own) {
    Placement x;
    x.id = id;
    x.bin = h_r;
    x.p_own = p_own;
    x.payee = r.side.payee;
    x.owner = r.side.owner;
    x.p = r.side.fee_rate_bp;
    x.give_author_bp = r.side.give_author_bp;
    x.work = r.side.t_origin;
    x.payee_ref = r.payee;
    if (r.owner) x.owner_ref = *r.owner;
    return x;
}

// The S1.3 #3-#9 rows of a carrier's own body on its parent (rows 4-10).
struct OwnRows {
    const CarrierNode* parent = nullptr;
    Body body;
    bool not_carrier = false;  // S1.3 #6 failed: the body continues as a receipt
};

inline std::optional<AdmitResult> own_rows(const AdmitEnv& env, const ReceiptBodyV3& own, std::uint64_t own_bytes,
                                           const Hash32& own_id, CarrierRole role, OwnRows& out) {
    out.body.r = &own;
    out.body.bytes = own_bytes;
    out.body.id = own_id;
    // row 4 (S1.3 #3): parent = tip held and verified
    const Hash32& parent = own.side.tip;
    const CarrierNode* pn = env.tree.find(parent);
    if (pn == nullptr || !pn->verified) return defer(Missing::ParentUnknown, RowId::R4, 0, parent);
    out.parent = pn;
    out.body.tip = pn;
    // the row-4 gate: a frame judged for its own placement
    if (role == CarrierRole::Frame && !own_chain_judged(env.tree, env.store, parent))
        return defer(Missing::OwnChainDeep, RowId::R4);
    // row 3 (S1.3 #2): rules_epoch at x = pos(tip) + 1, (i) on the held parent
    if (auto r = epoch_row(env, out.body, *pn, std::optional<RatchetState>(pn->rs), RowId::R3, 0)) return r;
    // row 5 (S1.3 #4): P_r
    if (auto r = pr_row(env, out.body, RowId::R5, 0)) return r;
    // row 6 (S1.3 #5): freshness
    if (freshness(out.body.h, pn->h, env.p.fresh_max) == FreshVerdict::Refuse)
        return verdict(AdmitVerdict::Refuse, RowId::R6);
    // row 7 (S1.3 #6): monotone, else not a carrier
    if (!carrier_height_admissible(pn->H, out.body.h)) {
        out.not_carrier = true;
        return std::nullopt;
    }
    // row 8 (S1.3 #7): header fields and the vote rule
    if (auto r = header_row(out.body, RowId::R8, 0)) return r;
    // row 9 (S1.3 #8): t_origin == d_at(parent)
    if (auto r = retarget_row(env, out.body, *pn, RowId::R9, 0)) return r;
    // row 10 (S1.3 #9, the words of S2.3 #12; with #13): the canonical coinbase on window(parent, v)
    if (auto r = coinbase_row(env, out.body, parent, pn->pos + 1, RowId::R10, RowId::R10, 0)) return r;
    return std::nullopt;
}

inline Missing missing_of(WalkVerdict v, bool tip_itself) {
    switch (v) {
        case WalkVerdict::NeedHeaders: return tip_itself ? Missing::TipUnknown : Missing::TipHeaders;
        case WalkVerdict::NeedBodies: return Missing::ClosureBodies;
        case WalkVerdict::Boundary: return Missing::Boundary;
        case WalkVerdict::Closure: return Missing::Closure;
        case WalkVerdict::Bind: return Missing::TipBodies;
        case WalkVerdict::OnChain:
        case WalkVerdict::Placed: break;
    }
    return Missing::NodeInternal;
}

// S2.3 #3: the tip held on c's chain, or its branch (and the closure) within
// J_0 of parent(c) and placed. nullopt: judge on the placed branch.
inline std::optional<AdmitResult> walk_row(const AdmitEnv& env, ClosureWalk& walk, const OwnChain& own, Body& b,
                                           RowId row, std::size_t idx) {
    const Hash32& t = b.r->side.tip;
    const WalkResult w = walk.walk_tip(t);
    if (w.v == WalkVerdict::OnChain || w.v == WalkVerdict::Placed) {
        b.tip = env.tree.find(t);
        b.f = w.f;
        if (b.tip == nullptr) return node_internal(env, row, b.id, idx);
        return std::nullopt;
    }
    if (w.v == WalkVerdict::Boundary || w.v == WalkVerdict::Closure) {
        // the walk's values on a claim basis (C-8, row 17): ClaimAlarm
        const CarrierNode* tn = env.tree.find(t);
        const Basis bw = basis_of(env.claims, RowClass::Walk, t, tn != nullptr ? tn->pos + 1 : 0);
        if (is_claim_basis(bw)) {
            AdmitResult r = claim_alarm(env, row, bw, b.id, idx);
            r.claim_based = w.claim_based;
            r.walked = w.walked;
            return r;
        }
    }
    AdmitResult r = defer(missing_of(w.v, w.fetch == t && !env.tree.find(t)), row, idx, w.fetch);
    r.claim_based = w.claim_based;
    r.walked = w.walked;
    r.bind = w.bind;
    r.refuted_sets = w.refuted_sets;
    for (std::uint64_t peer : w.tokens) r.peer_tokens.emplace_back(peer, 1);
    if (w.v == WalkVerdict::NeedHeaders) r.fetch_from = own.at(own.lo()).value_or(Hash32{});
    if (w.v == WalkVerdict::Bind) r.fetch = t;
    return r;
}

}  // namespace admit_detail

// ---------------------------------------------------------------------------
// admit_carrier: an FC_CARRIER frame (FH | carrier body; FH is decoded by the
// relay). Reads the env; writes nothing but the window and key caches.
// ---------------------------------------------------------------------------
inline AdmitResult admit_receipt_decoded(const AdmitEnv& env, const ReceiptBodyV3& r, std::uint64_t bytes);

inline AdmitResult admit_carrier(const AdmitEnv& env, std::span<const std::uint8_t> frame, CarrierRole role) {
    using namespace admit_detail;
    // row 1 (S1.3 #1a): the frame buffer P-11, before parsing
    if (frame_size_verdict(frame.size(), env.buffers.frame, env.buffers.frame) == AdmitVerdict::Drop)
        return verdict(AdmitVerdict::Drop, RowId::R1);
    if (frame.size() < kFrameHeaderBytes) return verdict(AdmitVerdict::Strike, RowId::R2);
    const std::span<const std::uint8_t> body = frame.subspan(kFrameHeaderBytes);
    // row 2 (S1.3 #1b): every body within the receipt buffer P-10 as it is read, then the decode
    if (!frame_body_within_buffer(body, env.buffers.receipt)) return verdict(AdmitVerdict::Drop, RowId::R14);
    CarrierBodyV3 c;
    const WireError e = decode_carrier_body_v3(body.data(), body.size(), CarrierLimits{env.buffers.receipt, env.p.r_max}, c);
    if (const std::optional<AdmitVerdict> wv = wire_verdict(e)) {
        const RowId row = wire_row(e) == WireRow::Row1a ? RowId::R1
                          : wire_row(e) == WireRow::Row2 ? RowId::R16
                          : (e == WireError::Version || e == WireError::CarriedCount || e == WireError::Trailing)
                                  ? RowId::R2
                                  : RowId::R15;
        return verdict(*wv, row);
    }
    const std::vector<std::uint64_t> lens = body_lengths(body);
    if (lens.size() != c.carried.size() + 1) return node_internal(env, RowId::R2, Hash32{});
    // rows 14-16 for every body (own and carried), before any fetch: ID-1, pool_id (E-11 in the decode)
    for (std::size_t k = 0; k <= c.carried.size(); ++k) {
        const ReceiptBodyV3& r = k == 0 ? c.own : c.carried[k - 1];
        if (!identities_bound(r)) return verdict(AdmitVerdict::Strike, RowId::R15, k);
        if (!pool_id_ok(r.side, env.pool_id)) return verdict(AdmitVerdict::Strike, k == 0 ? RowId::R3 : RowId::R16, k);
    }
    const Hash32 own_id = receipt_id(c.own);
    // the own body's S1.3 #3-#9 (rows 4-10)
    OwnRows own;
    if (auto r = own_rows(env, c.own, lens[0], own_id, role, own)) return *r;
    if (own.not_carrier) {
        // row 7: not a carrier; the own body continues as a receipt (row 30: PENDING)
        AdmitResult r = admit_receipt_decoded(env, c.own, lens[0]);
        if (r.row == RowId::None) r.row = RowId::R7;
        return r;
    }
    const CarrierNode& P = *own.parent;
    const OwnChain chain(env, P.id);
    // carried bodies: rows 17-20, the order, rows 21-27
    std::vector<Body> bodies(c.carried.size());
    ClosureWalk walk(env, chain);
    for (std::size_t k = 0; k < c.carried.size(); ++k) {
        Body& b = bodies[k];
        b.r = &c.carried[k];
        b.bytes = lens[k + 1];
        b.id = receipt_id(*b.r);
        // row 17 (S2.3 #3): the EP-4 walk, the boundary and the closure, before any view of t's branch
        if (auto r = walk_row(env, walk, chain, b, RowId::R17, k + 1)) return *r;
        // row 18 (S2.3 #4): epoch_at (ii) / (iii) for a carried receipt
        if (auto r = epoch_row(env, b, *b.tip, std::nullopt, RowId::R18, k + 1)) return *r;
        // row 19 (S2.3 #5): P_r
        if (auto r = pr_row(env, b, RowId::R19, k + 1)) return *r;
        // row 20 (S2.3 #6): freshness, before any store call
        if (freshness(b.h, b.tip->h, env.p.fresh_max) == FreshVerdict::Refuse)
            return verdict(AdmitVerdict::Refuse, RowId::R20, k + 1);
    }
    {
        std::vector<CarriedKey> keys;
        for (const Body& b : bodies) keys.push_back(CarriedKey{b.h, b.id});
        if (!carried_order_ok(keys, P.id)) return verdict(AdmitVerdict::Strike, RowId::R28);
    }
    const LaneView pv = env.store.view_at(P.id);  // the placing chain
    if (!pv.ok()) return pv.status() == ViewStatus::Unknown ? defer(Missing::TipBodies, RowId::R21, 0, P.id)
                                                             : node_internal(env, RowId::R21, own_id);
    const std::uint64_t H_parent = pv.record(pv.pos());
    for (std::size_t k = 0; k < bodies.size(); ++k) {
        Body& b = bodies[k];
        const std::uint64_t x = b.tip->pos + 1;
        // row 21 (S2.3 #7): the origin bin open on c's chain at its parent; h(r) <= h(c) + Fresh
        const Basis bo = basis_of(env.claims, RowClass::OriginBin, b.tip->id, x);
        if (bo != Basis::NotComputed && (!open_at(H_parent, b.h, env.p.open_bins)
                                         || !carried_upper_ok(b.h, own.body.h, env.p.fresh_max)))
            return fail_row(env, AdmitVerdict::Strike, RowId::R21, bo, b.id, k + 1);
        // row 22 (S2.3 #8): not placed on c's chain in an open bin, not c itself
        const Basis bd = basis_of(env.claims, RowClass::Dedup, b.tip->id, x);
        if (bd != Basis::NotComputed && (b.id == own_id || pv.placed_open(b.id)))
            return fail_row(env, AdmitVerdict::Strike, RowId::R22, bd, b.id, k + 1);
        // row 23 (S2.3 #9): header fields
        if (auto r = header_row(b, RowId::R23, k + 1)) return *r;
        // row 25 (S2.3 #11): t_origin == d_at on the tip's (bound) branch
        if (auto r = retarget_row(env, b, *b.tip, RowId::R25, k + 1)) return *r;
        // rows 26, 27 (S2.3 #12, #13): the canonical coinbase on window(t, v), roots at t
        if (auto r = coinbase_row(env, b, b.tip->id, x, RowId::R26, RowId::R27, k + 1)) return *r;
    }
    // row 28 (S2.3 #14) with row 11 (S1.3 #10): the carried list and the one fold
    {
        std::vector<CarriedReceipt> list;
        std::vector<Hash32> ids;
        for (const Body& b : bodies) {
            list.push_back(CarriedReceipt{*b.r, b.h});
            ids.push_back(b.id);
        }
        const CarriedListResult cl =
                check_carried_list(c.own, H_parent, list, placed_set_on(pv, ids), P.rs, env.p);
        if (cl.verdict) {
            switch (cl.fault) {
                case CarriedFault::MissingBody: return defer(Missing::Bodies, RowId::R28, cl.index + 1, own_id);
                case CarriedFault::Fold:
                    return fail_row(env, AdmitVerdict::Strike, RowId::R11,
                                    basis_of(env.claims, RowClass::Fold, P.id, P.pos + 1), own_id);
                case CarriedFault::SealedBin: return verdict(AdmitVerdict::Strike, RowId::R21, cl.index + 1);
                case CarriedFault::Duplicate: return verdict(AdmitVerdict::Strike, RowId::R22, cl.index + 1);
                case CarriedFault::Count: return verdict(AdmitVerdict::Strike, RowId::R2);
                case CarriedFault::Order:
                case CarriedFault::None: return verdict(AdmitVerdict::Strike, RowId::R28);
            }
        }
    }
    // FRAME_CAP after every body's #9 (it cannot fail there)
    // rows 12, 29: RandomX once per body, last
    bool rx = false;
    if (auto r = randomx_row(env, own.body, RowId::R12, 0, rx)) {
        r->randomx_called = rx;
        return *r;
    }
    for (std::size_t k = 0; k < bodies.size(); ++k)
        if (auto r = randomx_row(env, bodies[k], RowId::R29, k + 1, rx)) {
            r->randomx_called = rx;
            return *r;
        }
    // rows 31, 30, 13: live on c's chain, the placements
    AdmitResult out;
    out.verdict = AdmitVerdict::AdmitCarrier;
    out.row = RowId::R13;
    out.randomx_called = rx;
    out.id = own_id;
    out.digest = ::v37::sha256d(std::vector<std::uint8_t>(frame.begin(), frame.end()));
    const std::uint64_t q = P.pos + 1;
    for (std::size_t k = 0; k < bodies.size(); ++k) {
        const Body& b = bodies[k];
        const std::uint64_t p_own = b.tip->pos + 1;  // p(r) = pos(t) + 1
        const bool is_live = live(b.h, q, p_own, [&](std::uint64_t x) { return pv.record(x); });
        // row 31 on a claim basis (C-8): a dead placement is ClaimAlarm
        const Basis bl = basis_of(env.claims, RowClass::Live, b.tip->id, p_own);
        if (!is_live && is_claim_basis(bl)) {
            AdmitResult r = claim_alarm(env, RowId::R31, bl, b.id, k + 1);
            r.randomx_called = rx;
            return r;
        }
        out.placements.push_back(CarriedPlacement{b.id, b.r->side.t_origin, b.r->side.ballot, is_live});
        out.store_placements.push_back(placement_of(*b.r, b.id, b.h, p_own));
    }
    out.store_placements.push_back(placement_of(c.own, own_id, own.body.h, q));
    out.announce = CarrierAnnounce{own_id, P.id, own.body.h, c.own.side.receipts_root, c.own.side.ballot};
    out.carrier = std::move(c);
    return out;
}

// ---------------------------------------------------------------------------
// admit_receipt: an unsolicited receipt (FB_RECEIPTS body), S2.3 only, the
// pending words of #7 / #8 / #16.
// ---------------------------------------------------------------------------
inline AdmitResult admit_receipt_decoded(const AdmitEnv& env, const ReceiptBodyV3& r, std::uint64_t bytes) {
    using namespace admit_detail;
    if (!identities_bound(r)) return verdict(AdmitVerdict::Strike, RowId::R15);
    if (!pool_id_ok(r.side, env.pool_id)) return verdict(AdmitVerdict::Strike, RowId::R16);
    Body b;
    b.r = &r;
    b.bytes = bytes;
    b.id = receipt_id(r);
    // row 17: the tip held; off the best chain, the boundary and the closure with parent(c) := the best tip
    // (the carrier this node would build; relay policy, no token)
    if (env.tree.find(r.side.tip) == nullptr && env.headers.variants(r.side.tip).empty())
        return defer(Missing::TipUnknown, RowId::R17, 0, r.side.tip);
    const Hash32 best = env.store.best_tip();
    const OwnChain chain(env, best);
    ClosureWalk walk(env, chain);
    if (auto rr = walk_row(env, walk, chain, b, RowId::R17, 0)) return *rr;
    // row 18: epoch_at (i) on the held tip
    if (auto rr = epoch_row(env, b, *b.tip, std::optional<RatchetState>(b.tip->rs), RowId::R18, 0)) return *rr;
    if (auto rr = pr_row(env, b, RowId::R19, 0)) return *rr;
    if (freshness(b.h, b.tip->h, env.p.fresh_max) == FreshVerdict::Refuse) return verdict(AdmitVerdict::Refuse, RowId::R20);
    // row 21: the origin bin open at H(L) of the best chain (local admission): REFUSE
    const LaneView bv = env.store.view_at(best);
    if (!bv.ok()) return node_internal(env, RowId::R21, b.id);
    const std::uint64_t x = b.tip->pos + 1;
    const Basis bo = basis_of(env.claims, RowClass::OriginBin, b.tip->id, x);
    if (bo != Basis::NotComputed && !open_at(bv.record(bv.pos()), b.h, env.p.open_bins))
        return fail_row(env, AdmitVerdict::Refuse, RowId::R21, bo, b.id);
    // row 22: DUPLICATE on the best chain
    const Basis bd = basis_of(env.claims, RowClass::Dedup, b.tip->id, x);
    if (bd != Basis::NotComputed && bv.placed_open(b.id)) return fail_row(env, AdmitVerdict::Duplicate, RowId::R22, bd, b.id);
    if (auto rr = header_row(b, RowId::R23, 0)) return *rr;
    if (auto rr = retarget_row(env, b, *b.tip, RowId::R25, 0)) return *rr;
    if (auto rr = coinbase_row(env, b, b.tip->id, x, RowId::R26, RowId::R27, 0)) return *rr;
    bool rx = false;
    if (auto rr = randomx_row(env, b, RowId::R29, 0, rx)) {
        rr->randomx_called = rx;
        return *rr;
    }
    AdmitResult out;
    out.verdict = AdmitVerdict::AdmitPending;
    out.row = RowId::R30;
    out.randomx_called = rx;
    out.id = b.id;
    out.store_placements.push_back(placement_of(r, b.id, b.h, b.tip->pos + 1));
    return out;
}

inline AdmitResult admit_receipt(const AdmitEnv& env, std::span<const std::uint8_t> body, Role) {
    using namespace admit_detail;
    ReceiptBodyV3 r;
    const WireError e = decode_receipt_body_v3(body.data(), body.size(), ReceiptLimits{env.buffers.receipt}, r);
    if (const std::optional<AdmitVerdict> wv = wire_verdict(e))
        return verdict(*wv, wire_row(e) == WireRow::Row1a ? RowId::R14
                            : wire_row(e) == WireRow::Row2 ? RowId::R16
                                                           : RowId::R15);
    AdmitResult out = admit_receipt_decoded(env, r, body.size());
    out.digest = ::v37::sha256d(std::vector<std::uint8_t>(body.begin(), body.end()));
    return out;
}

// C-1 (0): with a claim view, a copy the view does not judge now is DEFERred
// (CopyDeferred), no row run. `peer`: the arriving peer.
inline AdmitResult admit_frame_from(const AdmitEnv& env, std::uint64_t peer, std::span<const std::uint8_t> frame,
                                    CarrierRole role) {
    if (env.claims != nullptr) {
        const Hash32 digest = ::v37::sha256d(std::vector<std::uint8_t>(frame.begin(), frame.end()));
        if (!env.claims->judge_copy(peer, digest)) {
            AdmitResult r = admit_detail::defer(Missing::CopyDeferred, RowId::None);
            r.digest = digest;
            return r;
        }
    }
    return admit_carrier(env, frame, role);
}

// The frame bytes FH | carrier body of a carrier (FH: the relay's; zero here).
inline std::optional<std::vector<std::uint8_t>> carrier_frame(const CarrierBodyV3& c, std::uint64_t r_max) {
    std::vector<std::uint8_t> out(kFrameHeaderBytes, 0);
    if (encode_carrier_body_v3(c, r_max, out) != WireError::None) return std::nullopt;
    return out;
}

// ---------------------------------------------------------------------------
// place_admitted: the write step after the dry run (C-3).
//   tree.place(c, placements) (Placed, or Duplicate when a copy won the race);
//   on Placed: BinStore add_carrier, ingest of the carried list in canonical
//   order then of the own body, seal; then mark_verified and mark_bodies (a
//   node-internal store outcome leaves c placed but not chain-valid: its
//   partial delta is dropped (drop_side) and tree.drop removes it). When c's parent is the store's best tip and tree.best() is c
//   (an extension): store.switch_best(c) (the position's record batch), then
//   the activation row of c appended to AR. A node-internal outcome of either
//   is undone: the switch rewound to c's parent (out.batch holds both), c's
//   delta and body removed, the marks undone (unmark) and c dropped, so the
//   tree's and the store's best tip are c's parent again and AR is unchanged.
//   When tree.best() changed otherwise, the switch is the caller's
//   (SwitchToCaller).
// ---------------------------------------------------------------------------
enum class WriteOutcome : std::uint8_t { Extended, SideBranch, SwitchToCaller, Duplicate, NodeInternal };

struct WriteResult {
    WriteOutcome outcome = WriteOutcome::NodeInternal;
    PlaceOutcome place;
    std::optional<ActivationRow> ar_row;
    LaneBatch batch;
};

template <class Store>
inline WriteResult place_admitted(CarrierTree& tree, Store& store, ActivationRecord& ar, CarrierBodies& bodies,
                                  const AdmitResult& r, AlarmSink* alarm = nullptr) {
    WriteResult out;
    const auto internal = [&](RowId row) {
        if (alarm) alarm->raise(row, Basis::Computed, r.id, Missing::NodeInternal);
        out.outcome = WriteOutcome::NodeInternal;
        return out;
    };
    if (r.verdict != AdmitVerdict::AdmitCarrier || !r.carrier) return internal(RowId::R13);
    out.place = tree.place(r.announce, r.placements);
    if (out.place.verdict == PlaceVerdict::Duplicate) {
        out.outcome = WriteOutcome::Duplicate;
        return out;
    }
    if (out.place.verdict != PlaceVerdict::Placed) return internal(RowId::R13);
    const Hash32& id = r.announce.id;
    bool ok = store.add_carrier(id, r.announce.parent, r.announce.h) == AddVerdict::Added;
    for (std::size_t i = 0; ok && i < r.store_placements.size(); ++i) {
        const std::optional<Ingest> in = store.ingest(id, r.store_placements[i]);
        ok = in.has_value() && *in == Ingest::Accepted;
    }
    if (ok) {
        // guarantee 4: the store's #17 equals the placement handed to the tree
        const LaneDelta* d = store.delta(id);
        ok = d != nullptr && d->placed.size() == r.store_placements.size();
        for (std::size_t i = 0; ok && i < r.placements.size(); ++i) ok = d->placed[i].live == r.placements[i].live;
    }
    ok = ok && store.seal(id).has_value();
    if (!ok) {
        (void)store.drop_side(id);  // a store failure before the marks: c's partial delta goes with c
        tree.drop(id);
        return internal(RowId::R13);
    }
    tree.mark_verified(id);
    tree.mark_bodies(id);
    bodies.put(id, *r.carrier);
    // a node-internal outcome after the marks: the switch rewound, c's delta and body removed, the marks undone
    const auto undo = [&](bool switched) {
        if (switched) (void)store.switch_best(r.announce.parent, &out.batch);
        (void)store.drop_side(id);
        bodies.erase(id);
        tree.unmark(id);
        tree.drop(id);
        return internal(RowId::R13);
    };
    if (r.announce.parent == store.best_tip() && tree.best().id == id) {
        if (store.switch_best(id, &out.batch) != SwitchVerdict::Switched) return undo(false);
        const CarrierNode* n = tree.find(id);
        if (n != nullptr && n->activation) {
            if (!ar.append(*n->activation)) return undo(true);
            out.ar_row = n->activation;
        }
        out.outcome = WriteOutcome::Extended;
        return out;
    }
    out.outcome = tree.best().id == store.best_tip() ? WriteOutcome::SideBranch : WriteOutcome::SwitchToCaller;
    return out;
}

// ---------------------------------------------------------------------------
// DeferredCarriers: the deferred-frame store (P-47, policy; ruling 23).
//   One store keyed by the frame digest, with the arriving peer. A frame
//   DEFERred on an unknown parent is a waiting entry (id, claimed parent) of
//   the tree as well; a key holds the digests of every frame stored under it.
//   Frames parked by a non-retrying DEFER (the boundary, the closure, EP-4
//   (iii), node-internal, OwnChainDeep) are in the same store and cap.
//   Over the cap: the oldest frame of the peer holding the most frames is
//   dropped (DROP, no verdict, no token); the tree's entry is removed
//   (unwait) only when the last frame under its key leaves.
//   Re-walks (C-6): an arrival or a binding that touches a parked
//   claim-based frame's walked ids marks it for one pending re-walk.
// ---------------------------------------------------------------------------
inline std::uint64_t waiting_cap_default() { return journal_j0(kRuledLaneParams, kSealDepth); }
inline constexpr std::string_view kWaitingCapFlag = "--pathb-waiting-cap";

struct ParkedFrame {
    Hash32 digest{};
    Hash32 id{};
    Hash32 parent{};
    std::uint64_t peer = 0;
    std::vector<std::uint8_t> frame;
    Missing cause = Missing::NodeInternal;
    bool claim_based = false;
    std::vector<Hash32> walked;
    std::uint64_t seq = 0;
    bool rewalk = false;
    std::uint64_t walks = 0;
};

class DeferredCarriers {
public:
    explicit DeferredCarriers(std::uint64_t cap) : cap_(cap) {}

    std::uint64_t cap() const noexcept { return cap_; }
    std::size_t size() const noexcept { return frames_.size(); }
    std::size_t waiting_keys() const noexcept { return keys_.size(); }
    std::size_t held_by(std::uint64_t peer) const {
        std::size_t n = 0;
        for (const auto& [d, f] : frames_) n += f.peer == peer ? 1 : 0;
        return n;
    }
    const ParkedFrame* get(const Hash32& digest) const {
        const auto it = frames_.find(digest);
        return it == frames_.end() ? nullptr : &it->second;
    }
    bool holds(const Hash32& digest) const { return frames_.count(digest) != 0; }

    // Parks a DEFERred frame (by its digest). ParentUnknown: the waiting entry
    // (id, claimed parent) is registered in the tree. Returns false when the
    // digest is held already.
    bool park(CarrierTree& tree, ParkedFrame f) {
        if (frames_.count(f.digest) != 0) return false;
        f.seq = ++seq_;
        if (f.cause == Missing::ParentUnknown) {
            if (tree.find(f.id) != nullptr) return false;  // placed already
            const PlaceVerdict v = tree.place(CarrierAnnounce{f.id, f.parent, 0, Hash32{}, 0}, {}).verdict;
            if (v != PlaceVerdict::Deferred && v != PlaceVerdict::Duplicate) return false;
            keys_[WaitKey{f.id, f.parent}].insert(f.digest);
        }
        frames_.emplace(f.digest, std::move(f));
        while (frames_.size() > cap_) evict(tree);
        return true;
    }

    // The frames stored under (id, parent) for the ids the tree released on
    // parent's placement; their keys leave the store.
    std::vector<ParkedFrame> release(const Hash32& parent, const std::vector<Hash32>& released) {
        std::vector<ParkedFrame> out;
        for (const Hash32& id : released) {
            const auto k = keys_.find(WaitKey{id, parent});
            if (k == keys_.end()) continue;
            for (const Hash32& d : k->second) {
                const auto it = frames_.find(d);
                if (it == frames_.end()) continue;
                out.push_back(std::move(it->second));
                frames_.erase(it);
                forget(d);
            }
            keys_.erase(k);
        }
        std::sort(out.begin(), out.end(), [](const ParkedFrame& a, const ParkedFrame& b) { return a.seq < b.seq; });
        return out;
    }

    // c placed: every stored frame of c.id is purged (the tree dropped its other entries).
    void purge(const Hash32& id) {
        for (auto it = frames_.begin(); it != frames_.end();) {
            if (it->second.id == id) {
                erase_key_of(it->second);
                forget(it->first);
                it = frames_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // A frame leaves (re-admitted, dropped at its bin's seal, ...).
    std::optional<ParkedFrame> take(CarrierTree& tree, const Hash32& digest) {
        const auto it = frames_.find(digest);
        if (it == frames_.end()) return std::nullopt;
        ParkedFrame f = std::move(it->second);
        frames_.erase(it);
        forget(digest);
        leave_key(tree, f);
        return f;
    }

    // The tree discarded these waiting entries (PlaceOutcome::discarded); their frames are dropped.
    void discard(const std::vector<WaitKey>& keys) {
        for (const WaitKey& k : keys) {
            const auto it = keys_.find(k);
            if (it == keys_.end()) continue;
            for (const Hash32& d : it->second) {
                frames_.erase(d);
                forget(d);
            }
            keys_.erase(it);
        }
    }

    // C-6: data touching these ids arrived (a variant or body set in a reply to
    // the node's own request, or a binding): every parked claim-based frame
    // that walked one of them is marked for one pending re-walk.
    void touch(const std::vector<Hash32>& ids) {
        const std::set<Hash32> s(ids.begin(), ids.end());
        for (auto& [d, f] : frames_) {
            if (!f.claim_based || f.rewalk) continue;
            for (const Hash32& w : f.walked)
                if (s.count(w) != 0) {
                    f.rewalk = true;
                    break;
                }
        }
    }

    // The frames marked for a re-walk, each once (the marks are cleared).
    std::vector<Hash32> take_rewalks() {
        std::vector<std::pair<std::uint64_t, Hash32>> v;
        for (auto& [d, f] : frames_)
            if (f.rewalk) {
                f.rewalk = false;
                ++f.walks;
                v.emplace_back(f.seq, d);
            }
        std::sort(v.begin(), v.end());
        std::vector<Hash32> out;
        for (const auto& [s, d] : v) out.push_back(d);
        return out;
    }

    // C-6: the node asks a peer for a parked frame's walked headers or bodies at
    // most once while that peer holds its variants (until forget_peer). The
    // record of a frame leaves with the frame (take, eviction, purge, discard,
    // release): it is held for held frames only.
    bool may_ask(const Hash32& digest, std::uint64_t peer) {
        const auto it = frames_.find(digest);
        if (it == frames_.end()) return false;
        return asked_[digest].insert(peer).second;
    }
    void forget_peer(std::uint64_t peer) {
        for (auto& [d, peers] : asked_) peers.erase(peer);
    }
    // The frames with an ask record.
    std::size_t asked_frames() const noexcept { return asked_.size(); }

    // A re-walked frame's new outcome (still DEFERred).
    void update(const Hash32& digest, Missing cause, bool claim_based, const std::vector<Hash32>& walked) {
        const auto it = frames_.find(digest);
        if (it == frames_.end()) return;
        it->second.cause = cause;
        it->second.claim_based = claim_based;
        it->second.walked = walked;
    }

private:
    void forget(const Hash32& digest) { asked_.erase(digest); }

    void erase_key_of(const ParkedFrame& f) {
        if (f.cause != Missing::ParentUnknown) return;
        const auto k = keys_.find(WaitKey{f.id, f.parent});
        if (k == keys_.end()) return;
        k->second.erase(f.digest);
        if (k->second.empty()) keys_.erase(k);
    }

    void leave_key(CarrierTree& tree, const ParkedFrame& f) {
        if (f.cause != Missing::ParentUnknown) return;
        const WaitKey key{f.id, f.parent};
        const auto k = keys_.find(key);
        if (k == keys_.end()) return;
        k->second.erase(f.digest);
        if (k->second.empty()) {
            keys_.erase(k);
            tree.unwait(f.id, f.parent);  // the last frame under the key left
        }
    }

    // The oldest frame of the peer holding the most frames.
    void evict(CarrierTree& tree) {
        std::map<std::uint64_t, std::size_t> per;
        for (const auto& [d, f] : frames_) ++per[f.peer];
        std::size_t most = 0;
        for (const auto& [p, n] : per) most = std::max(most, n);
        const ParkedFrame* victim = nullptr;
        for (const auto& [d, f] : frames_)
            if (per[f.peer] == most && (victim == nullptr || f.seq < victim->seq)) victim = &f;
        if (victim == nullptr) return;
        const Hash32 dg = victim->digest;
        (void)take(tree, dg);
    }

    std::uint64_t cap_;
    std::uint64_t seq_ = 0;
    std::map<Hash32, ParkedFrame> frames_;
    std::map<WaitKey, std::set<Hash32>> keys_;
    std::map<Hash32, std::set<std::uint64_t>> asked_;
};

// ---------------------------------------------------------------------------
// P-50: the claim-leaf alarm budget per peer (policy; ruling 23). A token
// bucket with refill P-15 = (1 + R_MAX) / T alarms per second and burst
// 1 + R_MAX, counted on the frames a peer relays (a reply to the node's own
// request is not counted). An empty bucket: disconnect the peer (no ban, no
// token, never a verdict).
// ---------------------------------------------------------------------------
inline constexpr std::string_view kClaimAlarmRateFlag = "--pathb-claim-alarm-rate";

class ClaimAlarmBudget {
public:
    explicit ClaimAlarmBudget(const LaneParams& p)
        : per_s_(1 + p.r_max), unit_(p.carrier_interval_s), cap_((1 + p.r_max) * p.carrier_interval_s) {}

    // A ClaimLeaf alarm on a frame from `peer`. false: the bucket is empty, disconnect the peer.
    bool charge(std::uint64_t peer, std::uint64_t now_s, bool relayed) {
        if (!relayed) return true;
        Bucket& b = buckets_[peer];
        if (!b.started) {
            b.started = true;
            b.units = cap_;
            b.at = now_s;
        }
        if (now_s > b.at) {
            const std::uint64_t dt = now_s - b.at;
            b.units = dt > (cap_ - b.units) / per_s_ ? cap_ : std::min(cap_, b.units + dt * per_s_);
            b.at = now_s;
        }
        if (b.units < unit_) return false;
        b.units -= unit_;
        return true;
    }

private:
    struct Bucket {
        bool started = false;
        std::uint64_t units = 0;
        std::uint64_t at = 0;
    };
    std::uint64_t per_s_;
    std::uint64_t unit_;
    std::uint64_t cap_;
    std::map<std::uint64_t, Bucket> buckets_;
};

// ---------------------------------------------------------------------------
// Binding the walked branches (1.4a): every held variant of a walked id whose
// claimed parent is placed runs its own S1.3 #3-#9 from its header; a Match
// binds it, a computed Mismatch refutes it (its servers BANned); a bound
// carrier is placed as closure material once a body set passes S1.3 #10 and
// S2.3 #14 (admit_carrier, role Closure; place_admitted).
// ---------------------------------------------------------------------------
enum class HeaderBind : std::uint8_t { Match, Mismatch, Wait };

struct HeaderBindResult {
    HeaderBind bind = HeaderBind::Wait;
    AdmitVerdict word = AdmitVerdict::Defer;  // Mismatch: the computed word (BAN at #9, STRIKE at #2 / #7 / #8)
};

// A header variant's own S1.3 #3-#9 at this node (its claimed parent placed; role Closure).
inline HeaderBindResult bind_header(const AdmitEnv& env, const HeaderVariant& y) {
    if (env.claims != nullptr && env.claims->header_binding(y.id, y.digest) == Basis::NotComputed)
        return {};  // binds nothing at this node
    admit_detail::OwnRows own;
    const std::optional<AdmitResult> r =
            admit_detail::own_rows(env, y.header.own, encoded_length(y.header.own), y.id, CarrierRole::Closure, own);
    if (!r) return own.not_carrier ? HeaderBindResult{} : HeaderBindResult{HeaderBind::Match, AdmitVerdict::AdmitCarrier};
    if ((r->verdict == AdmitVerdict::Ban || r->verdict == AdmitVerdict::Strike) && r->row != RowId::R5)
        return HeaderBindResult{HeaderBind::Mismatch, r->verdict};
    return {};
}

struct NodeRefs {
    CarrierTree& tree;
    BinStore& store;
    ActivationRecord& ar;
    HeaderIndex& headers;
    CarrierBodies& bodies;
};

struct BindReport {
    std::vector<Hash32> placed;
    std::vector<std::uint64_t> banned;  // servers of refuted variants or body sets
    std::vector<std::uint64_t> struck;  // servers of body sets struck once
    std::vector<WriteOutcome> writes;
};

inline BindReport bind_walked(const AdmitEnv& env, NodeRefs n, const std::vector<Hash32>& ids) {
    BindReport out;
    for (bool progress = true; progress;) {
        progress = false;
        for (const Hash32& id : ids) {
            if (n.tree.find(id) != nullptr) continue;
            if (!n.headers.bound_digest(id)) {
                std::vector<Hash32> digests;
                for (const HeaderVariant* y : n.headers.variants(id)) digests.push_back(y->digest);
                for (const Hash32& dg : digests) {
                    const HeaderVariant* y = n.headers.variant(id, dg);
                    if (y == nullptr || y->bound || n.tree.find(y->header.own.side.tip) == nullptr) continue;
                    const HeaderBindResult hb = bind_header(env, *y);
                    if (hb.bind == HeaderBind::Match) {
                        n.headers.bind(id, dg);  // the other variants of id are dropped
                        progress = true;
                        break;
                    }
                    if (hb.bind == HeaderBind::Mismatch) {
                        std::vector<std::uint64_t>& to = hb.word == AdmitVerdict::Ban ? out.banned : out.struck;
                        to.insert(to.end(), y->peers.begin(), y->peers.end());
                        n.headers.refute(id, dg);
                        progress = true;
                    }
                }
            }
            const std::optional<Hash32> bd = n.headers.bound_digest(id);
            if (!bd) continue;
            const HeaderVariant* y = n.headers.variant(id, *bd);
            if (y == nullptr || n.tree.find(y->header.own.side.tip) == nullptr) continue;
            std::vector<const BodySet*> sets = n.headers.body_sets(id);
            const BodySet none_set{};
            if (y->header.n_carried == 0 && sets.empty()) sets.push_back(&none_set);
            for (const BodySet* bs : sets) {
                CarrierBodyV3 c;
                c.own = y->header.own;
                c.carried = bs->bodies;
                const std::optional<std::vector<std::uint8_t>> frame = carrier_frame(c, env.p.r_max);
                if (!frame) continue;
                const AdmitResult r = admit_carrier(env, *frame, CarrierRole::Closure);
                if (r.verdict == AdmitVerdict::AdmitCarrier) {
                    const WriteResult w = place_admitted(n.tree, n.store, n.ar, n.bodies, r, &env.alarm);
                    out.writes.push_back(w.outcome);
                    if (w.outcome != WriteOutcome::NodeInternal) {
                        n.headers.placed(id);
                        out.placed.push_back(id);
                        progress = true;
                    }
                    break;
                }
                if (bs != &none_set && (r.verdict == AdmitVerdict::Ban || r.verdict == AdmitVerdict::Strike)) {
                    // computed: the parent placed, the header bound
                    (r.verdict == AdmitVerdict::Ban ? out.banned : out.struck).push_back(bs->peer);
                    n.headers.drop_body_set(bs->peer, id);
                    progress = true;
                    break;
                }
            }
        }
    }
    return out;
}

}  // namespace c2pool::xmr::pathb
