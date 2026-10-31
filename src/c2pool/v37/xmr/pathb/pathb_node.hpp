// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_node.hpp
// PathbNode: the Path B modules bound into one node (slice S4w-a; unwired).
//
// One owner executor holds the carrier tree, the bin store, the journal, AR,
// the caches, the pending set and the deferred store; every event below runs
// on it. RandomX runs through the `verify` callback (the verify workers); a
// carrier's placement re-runs its cheap rows when the best chain changed while
// its RandomX ran (begin_carrier / complete_carrier); a body is hashed once
// (the verified-body memo). I/O and time are the caller's (callbacks and
// arguments); nothing here reads a clock.
//
//   on_hello          the Path B FB_HELLO (pathb_hello_receive); the peer's tail
//   on_carrier        FC_CARRIER: frame buffer, admit_frame_from (role Frame),
//                     place_admitted, a switch by the journal with the re-pend
//                     step, the deferred store, the requests a DEFER names
//   on_receipts       FB_RECEIPTS v3: admit_receipt_from; the pending set (P-09)
//   on_headers        FC_HEADERS (first_pos): the header path (cheap rows, then
//                     PoW at d; a variant enters the HeaderIndex only after its
//                     PoW, path_ok passed explicitly), then the side-branch
//                     decision; a fork below the journal base: the joiner path
//   on_buckets        FC_BUCKETS: one assembly per (peer, at); the abandon
//                     timer per frame; a refused or abandoned (peer, at)'s later
//                     frames DROP, 0 tokens
//   serve_*           FC_GETCARRIER (n <= 17), FC_GETHEADERS (a held from:
//                     serve_headers, at most min(max, P-01, a frame); from =
//                     the zero id: a join attempt's page ending at stop),
//                     FC_GETBUCKETS (serve_buckets with the requester's P-42
//                     bytes left, P-48); each names the request's token class
//                     (undecodable: STRIKE; above the buffer: DROP)
//   make_template     E2: hold, FORK-FUSE, catch-up P_r, the window at A_t, the
//                     reward inputs at P_r, the selection with the real coinbase
//                     size; R = Monero's reward for a child of P_r
//   make_job          E3: side_data_v3, the carried list (the honest default,
//                     the canonical order, the deep-tip boundary and the
//                     closure), the canonical miner tx, the tree root
//   on_own_share      E5: the node's own receipt with its own hash: a carrier
//                     on the best tip, else pending
//   hold_state        E13
//   tick              the abandon timers
//   poison            a store write failure (3.3): the latch first in every
//                     event (NodeInternal; nothing judged, pended, parked or
//                     flooded), the status alarm, the poison mark the next
//                     load reports
//   join              the joiner (E15; 3.3, 3.3a): one Joiner, one
//                     PathbJoinLink per accepted HELLO peer (alive to the end
//                     of an attempt that uses it); A = the full node's own
//                     chain (FullNodeA) or the adopted state; candidates from
//                     a HELLO tail after a load failure, a HELLO tip a joined
//                     node does not hold, and a header or body switch that
//                     takes the joiner path (an empty store at position 0
//                     catches up headers first); attempt_join (the join
//                     worker: the E-72 re-ask's fetches, the next pair's
//                     attempt) and apply_join (the owner executor: the
//                     outcome, the adoption batch into a cleared store); a
//                     load failure (LoadFailed) keeps the failed store
//                     untouched until an adoption replaces it; a joined node
//                     serves its claimed prefix headers; a full node that
//                     pruned also offers a HELLO tip it does not hold
//   relay glue        offer_empty_store_tip (a store whose catch-up from
//                     position 0 got no header: the peer's HELLO tip a join
//                     candidate), take_parked (a parked frame run again),
//                     take_repended (the receipts a switch re-pended, to
//                     relay), set_join_step (the join worker's step callback),
//                     may_ask / take_rewalk_frames (the re-walk of parked
//                     frames), on_body_set (a walked carrier's bodies from a
//                     reply to the node's own FC_GETCARRIER),
//                     bind_walked_branch (a TipBodies DEFER's walked branch
//                     bound and placed); the references of a served bucket
//                     taken back are learned
//   prune             the retention prune step (P-51): the floors
//                     of the P-51 flags or join_serve_floors, the open holds
//                     and the node's own horizon; the tree re-rooted, bodies
//                     and records below the floors dropped, the headers below
//                     the bodies kept as prefix headers; one store batch
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"         // tree_root, make_coinbase_branch
#include "impl/xmr/coin/xmr_check_hash.hpp"   // check_hash
#include "impl/xmr/pathb/pathb_admit.hpp"
#include "impl/xmr/pathb/pathb_block_reward.hpp"
#include "impl/xmr/pathb/pathb_bucket_wire.hpp"
#include "impl/xmr/pathb/pathb_catchup.hpp"
#include "impl/xmr/pathb/pathb_hello.hpp"
#include "impl/xmr/pathb/pathb_join.hpp"  // admit_receipt_from, the joiner
#include "impl/xmr/pathb/pathb_pool_identity.hpp"
#include "impl/xmr/pathb/pathb_relay_wire.hpp"
#include "impl/xmr/pathb/pathb_store.hpp"

#include "c2pool/v37/xmr/pathb/pathb_join_link.hpp"
#include "c2pool/v37/xmr/pathb/pathb_template_select.hpp"
#include "c2pool/v37/xmr/pathb/pathb_timers.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Configuration and I/O
// ---------------------------------------------------------------------------
inline constexpr std::string_view kPathbLaunchFlag = "--pathb-launch";
inline constexpr std::string_view kVoteFlag = "--vote";

struct PathbNodeConfig {
    PoolIdentity identity;            // network, chain_id, pool_id, H
    Hash32 genesis_prev{};            // P_0: the Monero block at H
    Hash32 rules_g{};                 // the compiled G (S_0 = genesis_ratchet_state(G))
    EpochTable T;
    LaneParams p = kRuledLaneParams;
    RatchetParams rp = kRuledRatchetParams;
    std::uint64_t journal_depth = 0;  // P-01 (floor J_0, journal_depth_refusal)
    RelayBuffers buffers{};           // P-10, P-11
    std::uint64_t headers_frame_bytes = 0;  // P-14: one FC_HEADERS frame
    BucketWirePolicy bucket_policy{};       // P-39, P-41, P-42
    std::uint64_t bucket_serve_cap = UINT64_MAX;  // P-48 lower fixed cap (default: the P-42 bytes left)
    std::uint64_t abandon_timeout_s = kAbandonTimeoutDefault;  // P-53
    std::uint64_t pending_cap = 0;          // P-09 (0: relay_horizons(p).pending_cap)
    std::uint64_t waiting_cap = 0;          // P-47 (0: waiting_cap_default())
    // P-51: positions kept through the best tip (absent: the P-51 default, join_serve_floors); a value below the
    // node's own horizon is raised to it
    std::optional<std::uint64_t> body_keep;    // --pathb-body-keep: carrier bodies, tree nodes
    std::optional<std::uint64_t> header_keep;  // --pathb-header-keep: carrier headers
    std::optional<std::uint64_t> side_keep;    // --pathb-side-keep: side headers, side views
    XmrKeyRef author;                       // K16 author reference
    std::uint16_t give_author_bp = kDonationBp;
    std::uint16_t owner_fee_bp = 0;         // node-owner fee B (p)
    std::optional<XmrKeyRef> owner;         // present iff owner_fee_bp > 0
    bool launch = false;                    // --pathb-launch
    bool penalty_fill = false;              // --pathb-penalty-fill
    bool vote_no = false;                   // --vote no
    std::uint32_t record_chain = 0;         // the store's record chain id
    std::size_t key_cache_bytes = kKeyCacheBytesDefault;  // P-36 (--pathb-key-cache-mb): the node's own key cache
};

struct PathbNodeIo {
    const FollowerBranchView* monero = nullptr;
    std::function<PrInfo(const Hash32& p_r)> resolve_pr;
    std::function<std::optional<Hash32>(const Hash32& p_r)> seed_of;
    // RandomX of a hashing blob at d with the seed (the verify workers): false = the hash computed does not meet d;
    // a hash not computed throws (RandomxFailure: verify_rx_at_d)
    std::function<bool(const HashingBlob&, std::uint64_t d, const Hash32& seed)> verify;
    // the follower's main chain: its tip height and the block at a height
    std::function<std::optional<std::uint64_t>()> monero_tip;
    std::function<std::optional<Hash32>(std::uint64_t height)> monero_block_at;
    // the template's candidate transactions, in the source's priority order
    std::function<std::vector<TemplateTx>()> tx_source;
    // a frame to one peer; a frame to every peer but `except` (relay policy)
    std::function<void(std::uint64_t peer, const std::vector<std::uint8_t>& frame)> send;
    std::function<void(const std::vector<std::uint8_t>& frame, std::optional<std::uint64_t> except)> flood;
    // FB_GETCTX of a Monero block from any peer into the follower within the timeout (a join attempt's context)
    std::function<bool(const Hash32& id, std::uint64_t timeout_s)> fetch_context;
};

// RandomX through a hash function `hash(bytes, seed, pow, why)`: true with the hash in `pow`, or false with `why`
// when it computed no hash (the verifier not ready, a seed whose cache cannot be keyed, a VM error). No hash computed
// is node-internal: it leaves as RandomxFailure with its reason, never as a PoW verdict.
template <class HashFn>
void rx_hash_or_fail(HashFn&& hash, const std::vector<std::uint8_t>& bytes, const Hash32& seed, Hash32& pow) {
    std::string why;
    if (!hash(bytes, seed, pow, why))
        throw RandomxFailure("RandomX computed no hash: " + (why.empty() ? std::string("no reason given") : why));
}
// PathbNodeIo::verify over such a hash function: the hash computed is judged at d (false: it does not meet d).
template <class HashFn>
bool verify_rx_at_d(HashFn&& hash, const HashingBlob& b, std::uint64_t d, const Hash32& seed) {
    std::vector<std::uint8_t> bytes;
    encode_hashing_blob(b, bytes);
    Hash32 pow{};
    rx_hash_or_fail(hash, bytes, seed, pow);
    unsigned char h[32];
    std::copy(pow.begin(), pow.end(), h);
    return ::xmr::coin::check_hash(h, d);
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------
enum class NodeAction : std::uint8_t {
    None,
    Placed,          // a carrier extended the best chain
    SideBranch,      // placed off the best chain
    Switched,        // a switch by the journal (re-pend done)
    JoinerPath,      // a fork below the journal base (or below AR's joiner seed): the joiner path
    Parked,          // DEFERred into the deferred store
    Pending,         // a receipt into the pending set
    Verdict,         // STRIKE / BAN / REFUSE / DUPLICATE / DROP (the relay node's tokens)
    NodeInternal,    // the store poisoned
};

struct NodeEventResult {
    NodeAction action = NodeAction::None;
    AdmitResult admit;
    std::optional<WriteOutcome> write;
    std::uint64_t repended = 0;  // the re-pend count of a switch
    std::uint64_t lost = 0;      // abandoned placements whose bin is sealed on the new branch
    std::uint64_t omitted = 0;   // a peer's placed carrier with room: the receipts this node holds pending in bins open
                                 // at its parent that it did not carry (relay policy, never a verdict)
    Hash32 object{};             // a STRIKE, REFUSE or BAN: the id of the body it names (zero: not decoded; logs only)
};

// A family C frame's token class for the relay node (it applies the token):
// None = handled; Drop = a frame above its buffer, unsolicited, or over the
// serve budget (no verdict, no token); Strike = refuse + 1 strike (a frame
// that does not decode).
enum class FrameToken : std::uint8_t { None, Drop, Strike };

// What a serve handler answers: the reply frames, and the token class of the
// request frame.
struct ServeResult {
    FrameToken token = FrameToken::None;
    std::vector<std::vector<std::uint8_t>> frames;
};

// An FC_BUCKETS frame at this node: NodeInternal (the store poisoned: nothing
// judged) or the assembly's outcome.
struct BucketsEventResult {
    NodeAction action = NodeAction::Verdict;
    FrameOutcome frame;
};

// One step of the joiner (PathbNode::run_join): the attempt's report, the
// switch it made (adopted / replaced, the lost count) and whether the node
// now runs on the adopted state.
struct JoinStep {
    std::optional<AttemptReport> report;
    SwitchReport sw;
    bool switched = false;       // the node's state is the adopted one from now on
    bool batch_written = false;  // the adoption batch committed into an empty store
    std::uint64_t reasked = 0;   // E-72: claimed leaves asked again at a carrier of the heavier chain
    bool reask_joiner = false;   // E-72: a re-asked leaf differed: the joiner path
    bool caught_up = false;      // a completed attempt that rule (4) did not take ended the store's K_NCU
    bool adopt_caught_up = false;  // the adoption ended the store's K_NCU (its drain done)
};

// The join worker's half of a step (PathbNode::attempt_join): the E-72
// re-ask's served leaves and the next pair's attempt; apply_join applies them
// on the owner executor.
struct JoinAttempted {
    struct Reasked {
        std::uint64_t bin = 0;
        AtHeader at{};
        Hash32 leaf{};
        std::uint64_t server = 0;
    };
    std::vector<Reasked> reask;
    std::optional<Joiner::Attempted> attempt;
};

// A frame's arrival at the caller's link, in link order: the caller's clock (ms) and its node lock's busy total then
// (ms). Unstamped: a frame run again, or one given to the node directly; it is no arrival (the template gate, E-194).
struct PathbArrival {
    std::uint64_t ms = 0;
    std::uint64_t busy_ms = 0;
    bool stamped = false;
};

enum class TemplateStatus : std::uint8_t {
    Ok,
    NoPathbPeer,  // an empty store with no Path B peer and no --pathb-launch; a store not caught up with no Path B peer
    CatchingUp,   // a store not caught up: its first catch-up round in flight, or verified heavier headers being fetched
    Poisoned,     // the store failed a write: no template until the joiner path at the next start
    RestsOnClaims,  // no adopted state (a load failure), or the adopted state still replayed to its L
    Hold,         // E13
    ForkFuse,     // hf >= 17 (O-01)
    Defer,        // a Monero input, a weight input or a bucket is missing (fetch)
    NoTemplate,   // no selection fits (keep the previous template; a status alarm)
};

struct PathbTemplate {
    TemplateStatus status = TemplateStatus::NoTemplate;
    Hash32 tip{};
    std::uint64_t x = 0;           // pos(tip) + 1
    Hash32 p_r{};
    std::uint64_t h = 0;           // height(P_r) + 1
    std::uint8_t hf = 0;
    std::uint64_t timestamp = 0;
    std::uint64_t d = 0;           // d_at(best chain, x)
    std::uint64_t base = 0;        // B(P_r)
    std::uint64_t median = 0;      // Z(P_r)
    std::uint64_t reward = 0;      // R
    std::uint64_t fees = 0;        // F
    std::uint64_t tx_weight = 0;   // T
    std::uint64_t coinbase = 0;    // c (the coinbase size at R)
    std::vector<TemplateTx> txs;
    TipWindow window;
    Hash32 fetch{};                // Defer: what to fetch
};

// A stratum session (or the in-process miner's): its payee and stated vote.
struct PathbSession {
    XmrKeyRef payee;
    std::optional<std::uint32_t> stated_vote;
    std::array<std::uint8_t, kExtraNonceBytes> extra_nonce{};
};

struct PathbJob {
    ReceiptBodyV3 body;                  // blob.nonce 0
    std::vector<ReceiptBodyV3> carried;  // canonical order
    std::uint64_t d = 0;
    std::uint64_t h = 0;
    Hash32 tip{};
    MinerTx miner_tx;
    BallotChoice ballot;
};

// ---------------------------------------------------------------------------
// The pending set (E8; P-09): admitted receipts not yet placed on the best chain.
// ---------------------------------------------------------------------------
struct PendingReceipt {
    Hash32 id{};
    ReceiptBodyV3 body;
    std::uint64_t h = 0;          // h(r), the origin bin
    std::uint64_t tip_pos = 0;    // pos(t) at admission
    std::uint64_t seq = 0;
};

class PendingSet {
public:
    explicit PendingSet(std::uint64_t cap) : cap_(cap) {}
    std::size_t size() const noexcept { return by_id_.size(); }
    std::uint64_t cap() const noexcept { return cap_; }
    bool holds(const Hash32& id) const { return by_id_.count(id) != 0; }
    const PendingReceipt* get(const Hash32& id) const {
        const auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &it->second;
    }
    // Adds r; over the cap the oldest origin bin goes first, then the lowest tip
    // position (then the lowest id). False: r was held already, or r itself went.
    bool add(PendingReceipt r) {
        if (holds(r.id)) return false;
        r.seq = ++seq_;
        const Hash32 id = r.id;
        order_.insert(Key{r.h, r.tip_pos, id});
        by_id_.emplace(id, std::move(r));
        bool kept = true;
        while (by_id_.size() > cap_) {
            const Key v = *order_.begin();
            order_.erase(order_.begin());
            by_id_.erase(std::get<2>(v));
            if (std::get<2>(v) == id) kept = false;
        }
        return kept;
    }
    void erase(const Hash32& id) {
        const auto it = by_id_.find(id);
        if (it == by_id_.end()) return;
        order_.erase(Key{it->second.h, it->second.tip_pos, id});
        by_id_.erase(it);
    }
    template <class Pred>
    void erase_if(Pred&& pred) {
        for (auto it = by_id_.begin(); it != by_id_.end();) {
            if (pred(it->second)) {
                order_.erase(Key{it->second.h, it->second.tip_pos, it->first});
                it = by_id_.erase(it);
            } else {
                ++it;
            }
        }
    }
    std::vector<const PendingReceipt*> all() const {
        std::vector<const PendingReceipt*> out;
        for (const auto& [id, r] : by_id_) out.push_back(&r);
        return out;
    }

private:
    using Key = std::tuple<std::uint64_t, std::uint64_t, Hash32>;  // (h, tip_pos, id): the eviction order
    std::uint64_t cap_;
    std::uint64_t seq_ = 0;
    std::map<Hash32, PendingReceipt> by_id_;
    std::set<Key> order_;
};

// ---------------------------------------------------------------------------
// Store write seam: the BinStore through which place_admitted writes (a test
// may fail one of its writes; the node treats any failure as node-internal).
// ---------------------------------------------------------------------------
struct StoreFaults {
    bool fail_seal = false;
    bool fail_switch = false;
};

struct NodeStore {
    BinStore& s;
    StoreFaults& f;
    AddVerdict add_carrier(const Hash32& id, const Hash32& parent, std::uint64_t h) { return s.add_carrier(id, parent, h); }
    std::optional<Ingest> ingest(const Hash32& c, Placement r) { return s.ingest(c, std::move(r)); }
    std::optional<std::uint64_t> seal(const Hash32& c) {
        if (f.fail_seal) {
            f.fail_seal = false;
            return std::nullopt;
        }
        return s.seal(c);
    }
    const LaneDelta* delta(const Hash32& id) const { return s.delta(id); }
    const Hash32& best_tip() const { return s.best_tip(); }
    SwitchVerdict switch_best(const Hash32& t, LaneBatch* b) {
        if (f.fail_switch) {
            f.fail_switch = false;
            return SwitchVerdict::NotSealed;
        }
        return s.switch_best(t, b);
    }
    bool drop_side(const Hash32& id) { return s.drop_side(id); }
};

// ---------------------------------------------------------------------------
// PathbNode
// ---------------------------------------------------------------------------
class PathbNode {
public:
    // An empty store: position 0 = (pool_id, H + 1); the store written from
    // its genesis batch when `kv` is given.
    PathbNode(const PathbNodeConfig& cfg, PathbNodeIo io, PathbKv* kv = nullptr) : PathbNode(cfg, std::move(io), kv, true) {}

    // A start after a load failure (E-38, the joiner path): the node starts at
    // position 0 in memory and rests on claims (no template, nothing relayed)
    // until an attempt is adopted; every Path B HELLO tail is a candidate. The
    // failed store is kept as it is (nothing written) until the adoption batch
    // replaces it, so a restart before that is a load failure again.
    struct LoadFailed {};
    PathbNode(const PathbNodeConfig& cfg, PathbNodeIo io, PathbKv* kv, LoadFailed) : PathbNode(cfg, std::move(io), kv, false) {
        load_failed_ = true;
        refresh_own_chain();
    }

private:
    PathbNode(const PathbNodeConfig& cfg, PathbNodeIo io, PathbKv* kv, bool write_genesis)
        : cfg_(cfg),
          io_(std::move(io)),
          own_tree_(std::in_place, cfg.p, cfg.identity.pool_id, cfg.identity.height + 1, cfg.T,
                    std::span<const RetargetEntry>{}, cfg.rp, cfg.rules_g),
          own_store_(std::in_place, cfg.p, cfg.journal_depth, cfg.identity.pool_id, cfg.identity.height + 1,
                     cfg.record_chain),
          pending_(cfg.pending_cap ? cfg.pending_cap : relay_horizons(cfg.p).pending_cap),
          deferred_(cfg.waiting_cap ? cfg.waiting_cap : waiting_cap_default()),
          timers_(cfg.abandon_timeout_s),
          window_(cfg.bucket_policy),
          budget_(cfg.bucket_policy),
          kv_(kv),
          started_empty_(true) {
        point_own();
        head_ = head_of(cfg);
        if (kv_ != nullptr && write_genesis) {
            // into an empty store: every key of the store's prefixes deleted in the same batch
            LaneBatch b;
            const bool cleared = clear_store_batch(*kv_, cfg_.record_chain, b);
            const LaneBatch g = genesis_batch(cfg_.record_chain, head_, *tree_, *store_);
            b.ops.insert(b.ops.end(), g.ops.begin(), g.ops.end());
            // a store that starts empty and is not launched here has not caught up (K_NCU, cleared when it does)
            if (!cfg_.launch) b.put(store_keys::ncu(cfg_.record_chain), encode_ncu());
            if (!cleared || !commit_lane_batch(*kv_, b)) poison(tree_->genesis().id);
            not_caught_up_ = !cfg_.launch;
            first_round_ = not_caught_up_;
        }
        init_join();
    }

public:
    // A node from its loaded store (pathb_load); a load failure is the caller's
    // joiner path.
    PathbNode(const PathbNodeConfig& cfg, PathbNodeIo io, LoadedState loaded, PathbKv* kv)
        : cfg_(cfg),
          io_(std::move(io)),
          own_tree_(std::move(loaded.tree)),
          own_store_(std::move(loaded.store)),
          own_ar_(std::move(loaded.ar)),
          own_bodies_(std::move(loaded.bodies)),
          pending_(cfg.pending_cap ? cfg.pending_cap : relay_horizons(cfg.p).pending_cap),
          deferred_(cfg.waiting_cap ? cfg.waiting_cap : waiting_cap_default()),
          timers_(cfg.abandon_timeout_s),
          window_(cfg.bucket_policy),
          budget_(cfg.bucket_policy),
          kv_(kv),
          started_empty_(false) {
        point_own();
        head_ = loaded.head;
        *refs_ = std::move(loaded.refs);
        own_prefix_ = std::move(loaded.prefix_headers);
        own_chain_.seed_below(std::move(loaded.bound_below), loaded.bound_lo);
        if (loaded.bound_lo > 0) {  // a joined store: its claim view after L, from x1 = K_BLO - 1, its claimed leaves
            resumed_x1_ = loaded.bound_lo - 1;
            for (const auto& [bin, c] : loaded.claimed) resumed_claimed_[bin] = AtHeader{c.at_id, c.at_digest};
            resumed_.set_x1(loaded.bound_lo - 1);
            claims_ = &resumed_;
        }
        not_caught_up_ = loaded.not_caught_up && !cfg_.launch;  // K_NCU: still not caught up after the restart
        first_round_ = not_caught_up_;
        init_join();
    }

    PathbNode(const PathbNode&) = delete;
    PathbNode& operator=(const PathbNode&) = delete;

    // ---- state ----
    const CarrierTree& tree() const noexcept { return *tree_; }
    const BinStore& store() const noexcept { return *store_; }
    const ActivationRecord& ar() const noexcept { return *ar_; }
    const CarrierBodies& bodies() const noexcept { return *bodies_; }
    const HeaderIndex& headers() const noexcept { return *headers_; }
    const PendingSet& pending() const noexcept { return pending_; }
    std::uint64_t pending_cap() const noexcept { return pending_.cap(); }  // P-09
    const DeferredCarriers& deferred() const noexcept { return deferred_; }
    const AlarmSink& alarms() const noexcept { return alarm_; }
    // A's bound-work profile (rule (4)): the joined state's in its session, else the node's own chain's.
    std::shared_ptr<const BoundWork> bound_work_a() const {
        return joined_ != nullptr ? joined_->bound_work() : own_chain_.bound_work();
    }
    const PathbNodeConfig& config() const noexcept { return cfg_; }
    // A receipt's origin height h(r) = height(P_r) + 1 when the follower holds its P_r.
    std::optional<std::uint64_t> receipt_origin(const ReceiptBodyV3& r) const {
        const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(r.blob.prev_id) : PrInfo{};
        if (pr.status != PrInfo::Status::Held) return std::nullopt;
        return pr.height + 1;
    }
    // H(L) of the best chain (the record at its tip), when its view is held.
    std::optional<std::uint64_t> best_record() const {
        const LaneView v = store_->view_at(store_->best_tip());
        if (!v.ok()) return std::nullopt;
        return v.record(v.pos());
    }
    bool poisoned() const noexcept { return poisoned_; }
    std::uint64_t verify_calls() const noexcept { return verify_calls_; }
    // The switches by the journal: their count, the re-pend and lost counts of the last one, and the totals; of the
    // re-pended receipts, those later carried on the best chain, those whose bin sealed while they were pending and
    // those the pending set evicted (P-09) while watched; the joiner-path switches (rule (4) replaced the running
    // state) and the placements they lost; the adoptions with no state before (a fresh start, a load failure). Of the
    // carried ones: H(q) - H_s by bucket 0 / 1 / 2 / 3 and above, and its maximum (q the placing position, H_s the
    // record at the new tip at the switch); the abandoned placements the re-pend step did not re-pend (P_r not held,
    // or evicted at once by the pending set) (logs only).
    struct SwitchCounts {
        std::uint64_t switches = 0;
        std::uint64_t last_repended = 0;
        std::uint64_t last_lost = 0;
        std::uint64_t repended = 0;
        std::uint64_t lost = 0;
        std::uint64_t carried = 0;
        std::uint64_t sealed_pending = 0;
        std::uint64_t evicted = 0;
        std::uint64_t joiner_switches = 0;
        std::uint64_t joiner_lost = 0;
        std::uint64_t joiner_adopted = 0;
        std::array<std::uint64_t, 4> carry_bins{};
        std::uint64_t carry_bins_max = 0;
        std::uint64_t repend_skipped = 0;
    };
    const SwitchCounts& switch_counts() const noexcept { return switches_; }
    // The windows evaluated since start (each once, the cache) and how many had the N rule drop bins, cut the newest bin
    // by position, or merge an owner or the author back (logs only).
    struct WindowFlagCounts {
        std::uint64_t evaluated = 0;
        std::uint64_t n_dropped_bins = 0;
        std::uint64_t n_cut_position = 0;
        std::uint64_t merged_back = 0;
    };
    const WindowFlagCounts& window_flags() const noexcept { return win_flags_; }
    // The re-pended receipts still pending (at most the pending cap): each leaves at its placement, its seal, its
    // eviction or an adoption (the joiner path).
    std::size_t repend_watch_size() const noexcept { return repend_watch_.size(); }
    // The admitted receipt bodies by (tip, P_r) while their origin bin is open at the best tip: the keys held, the keys
    // that saw two distinct R, the least and greatest R seen; the carried bodies whose payee is not their carrier's
    // payee, counted at the carrier's first placement (logs only; none noted while the state rests on claims).
    struct AmountCounts {
        std::uint64_t keys = 0;
        std::uint64_t multi_fee = 0;
        std::uint64_t r_min = 0;
        std::uint64_t r_max = 0;
        std::uint64_t foreign_carried = 0;
    };
    AmountCounts amount_counts() const noexcept {
        AmountCounts c = amount_counts_;
        c.keys = amounts_.size();
        return c;
    }
    // Own carriers placed on the best chain since start, and those orphaned (no longer best at their position). Each
    // is watched until it is below the journal base (confirmed) or orphaned, a joiner switch included: at most J
    // positions; the watch starts empty at every start.
    std::uint64_t own_carriers() const noexcept { return own_carriers_; }
    std::uint64_t own_orphaned() const noexcept { return own_orphaned_; }
    std::size_t own_watch_size() const noexcept { return own_watch_.size(); }
    // The open state at the best tip (S4.7): every placement held for the open bins, live and dead, and the v3 wire
    // bytes of their receipt bodies (each placing carrier's bodies encoded once).
    struct OpenState {
        std::uint64_t placements = 0;
        std::uint64_t bytes = 0;
    };
    // The liveness line at the best tip: the placements of the open bins, live and dead, and sha256d over (id, live)
    // in bin and id order (equal on nodes at the same tip).
    struct Liveness {
        std::uint64_t live = 0;
        std::uint64_t dead = 0;
        Hash32 hash{};
    };
    Liveness liveness() const {
        Liveness o;
        const LaneView v = store_->view_at(store_->best_tip());
        if (!v.ok()) return o;
        const std::uint64_t H = v.record(v.pos());
        const std::uint64_t F = cfg_.p.open_bins;
        std::vector<std::uint8_t> pre;
        for (std::uint64_t b = H > F ? H - F + 1 : store_->b0(); b <= H + cfg_.p.fresh_max; ++b) {
            std::vector<const Placement*> es = v.entries(b, v.pos());
            std::sort(es.begin(), es.end(), [](const Placement* x, const Placement* y) { return x->id < y->id; });
            for (const Placement* e : es) {
                ++(e->live ? o.live : o.dead);
                pre.insert(pre.end(), e->id.begin(), e->id.end());
                pre.push_back(e->live ? 1 : 0);
            }
        }
        o.hash = ::v37::sha256d(pre);
        return o;
    }
    OpenState open_state() const {
        ++open_state_calls_;
        OpenState o;
        const LaneView v = store_->view_at(store_->best_tip());
        if (!v.ok()) return o;
        const std::uint64_t H = v.record(v.pos());
        const std::uint64_t F = cfg_.p.open_bins;
        std::map<Hash32, std::set<Hash32>> placed_by;  // placing carrier -> the receipt ids it placed in the open bins
        for (std::uint64_t b = H > F ? H - F + 1 : store_->b0(); b <= H + cfg_.p.fresh_max; ++b)
            for (const Placement* e : v.entries(b, v.pos())) {
                ++o.placements;
                placed_by[e->carrier].insert(e->id);
            }
        std::vector<std::uint8_t> buf;
        for (const auto& [carrier, ids] : placed_by) {
            const CarrierBodyV3* c = bodies_->get(carrier);
            if (c == nullptr) continue;
            const auto add = [&](const ReceiptBodyV3& r) {
                if (ids.count(receipt_id(r)) == 0) return;
                buf.clear();
                if (encode_receipt_body_v3(r, buf) == WireError::None) o.bytes += buf.size();
            };
            add(c->own);
            for (const ReceiptBodyV3& r : c->carried) add(r);
        }
        return o;
    }
    // open_state() evaluations since start.
    std::uint64_t open_state_calls() const noexcept { return open_state_calls_; }
    // The open state and the liveness line of the daemon's status line, computed once per status period: a call
    // less than period_s after the last computation returns the kept values (period_s 0: no status line, none).
    struct StatusSample {
        OpenState open;
        Liveness liveness;
    };
    const StatusSample& status_sample(std::uint64_t now_s, std::uint64_t period_s) {
        if (period_s != 0 && (!sample_s_ || now_s >= *sample_s_ + period_s)) {
            sample_ = StatusSample{open_state(), liveness()};
            sample_s_ = now_s;
        }
        return sample_;
    }
    std::uint64_t best_changes() const noexcept { return generation_; }
    StoreFaults& faults() noexcept { return faults_; }
    WindowCache& windows() noexcept { return *windows_; }

    // ---- the joiner (E15; 3.3a) ----
    // The transport of the join attempts' requests (the relay node's, on the join worker).
    void set_join_transport(JoinTransport* t) { transport_ = t; }
    const Joiner& joiner() const noexcept { return *joiner_; }
    const JoinedState* joined() const noexcept { return joined_; }
    const PathbJoinLink* join_link(std::uint64_t peer) const {
        const auto it = links_.find(peer);
        return it == links_.end() ? nullptr : it->second.get();
    }
    // An attempt runs (3.3a: A keeps building templates, relaying and judging meanwhile).
    bool attempting() const noexcept { return attempting_; }
    // The pair of the attempt taken from the queue and not yet applied; nullopt: none.
    const std::optional<AttemptQueue::Pair>& open_attempt() const noexcept { return joiner_->running(); }
    // E-72: the claimed leaves wait to be asked again after a switch by the journal (a joined store, in its session or
    // after a restart).
    bool reask_pending() const noexcept { return reask_pending_; }
    // 3.3a (2): the state rests on claims: no adopted state after a load failure, or the adopted state still
    // replayed to its L (no template, nothing relayed).
    bool rests_on_claims() const noexcept {
        if (joined_ != nullptr) return joined_->claims().rests_on_claims();
        return load_failed_;
    }

    // One step of the joiner, in two halves (C-10). attempt_join runs on the
    // join worker: the E-72 re-ask's FC_GETBUCKETS after a switch by the
    // journal, then the next queued (candidate, server) pair's attempt, with
    // the JoinLink waits; it reads A (the scope, A's profile in the step that
    // records L) and changes nothing of the node. apply_join runs on the owner
    // executor: the re-asked leaves rebound or the joiner path, the attempt's
    // outcome (the queue; an adoption or a replacement makes the attempt's
    // state the node's, written into the store in one batch). The links an
    // attempt uses stay alive to its end; a server that disconnected meanwhile
    // answers nothing and its pairs go when the attempt is applied.
    // attempt: the queued pair's attempt runs (false: the re-ask only; P-40 not met).
    JoinAttempted attempt_join(bool attempt = true) {
        JoinAttempted out;
        if (poisoned_) return out;
        std::vector<std::shared_ptr<PathbJoinLink>> held;  // kept alive to the end of this call
        for (const auto& [peer, l] : links_) held.push_back(l);
        attempting_ = true;
        if (reask_pending_ && joined_store()) reask_fetch(out);
        if (attempt) out.attempt = joiner_->attempt_next();
        attempting_ = false;
        for (const std::shared_ptr<PathbJoinLink>& l : held) l->reset();  // what an attempt received is its own
        return out;
    }
    JoinStep apply_join(JoinAttempted&& t) {
        JoinStep out;
        if (poisoned_) return out;
        reask_apply(t, out);
        if (t.attempt) {
            out.report = joiner_->apply(std::move(*t.attempt));
            out.sw = joiner_->last_switch();
        }
        for (const std::uint64_t peer : left_) joiner_->disconnect(peer);  // re-queued pairs of a gone server
        left_.clear();
        const bool ncu_before = not_caught_up_;
        if (out.report && (out.sw.adopted || out.sw.replaced)) out.switched = adopt(out.batch_written);
        out.adopt_caught_up = out.switched && ncu_before && !not_caught_up_;
        if (out.switched) {
            if (out.sw.replaced) {
                ++switches_.joiner_switches;
                switches_.joiner_lost += out.sw.lost;
            } else {
                ++switches_.joiner_adopted;
            }
            watch_own_carriers();
        }
        // a completed attempt whose candidate rule (4) did not take: the node keeps its own chain, and a store not
        // caught up (K_NCU) is caught up (the record leaves the store) once its drain is done (E-193; else the
        // caller's finish_kept)
        if (out.report && out.report->end == AttemptEnd::Completed && !out.sw.adopted && !out.sw.replaced
            && not_caught_up_) {
            ncu_due_ = NcuDue::Kept;
            out.caught_up = finish_kept();
        }
        return out;
    }
    // Both halves in one call (the KATs' single-threaded form).
    JoinStep run_join() { return apply_join(attempt_join()); }

    // ---- HELLO (E10) ----
    PathbHello our_hello(std::uint64_t node_nonce, std::uint16_t listen_port) const {
        PathbHello h;
        h.network = static_cast<std::uint8_t>(cfg_.identity.network);
        h.chain_id = cfg_.identity.chain_id;
        h.pool_id = cfg_.identity.pool_id;
        h.node_nonce = node_nonce;
        h.listen_port = listen_port;
        const CarrierNode& b = tree_->best();
        const LaneView v = store_->view_at(b.id);
        // the rules list of the node's epoch_cur (the compiled table's; epoch 0: the network's list)
        PathbLaneRules rules = epoch0_lane_rules(cfg_.identity.network);
        for (const CompiledEpoch& c : cfg_.T.compiled)
            if (c.epoch_no == b.rs.epoch_cur && c.rules) rules = *c.rules;
        h.tail = make_hello_tail(rules, b.cum_work, b.id, b.h, v.ok() ? v.leaf_count() : 0);
        h.trailer = hello_trailer(cfg_.rp, b.rs, b.pos + 1, cfg_.T);
        return h;
    }

    // The caller (the relay node, S4w-bc) runs what follows an accepted HELLO:
    // headers first when the peer's HELLO tip is not held here, the pending re-offer.
    HelloCheck on_hello(std::uint64_t peer, std::span<const std::uint8_t> frame, const PathbHello& ours) {
        PathbHello theirs;
        const HelloCheck c = pathb_hello_receive(
                ours, frame,
                [this](const Hash32& tip) -> std::optional<std::uint64_t> {
                    // a best tip bound at this node: a carrier it placed (its own #9 matched); at a joined node never a
                    // claimed one (a prefix node, a span carrier at or below x1: its #9 not computed here)
                    const CarrierNode* n = tree_->find(tip);
                    if (n == nullptr) return std::nullopt;
                    if (claims_ != nullptr) {
                        const CarrierBodyV3* b = bodies_->get(tip);
                        const std::optional<Hash32> dg = b ? header_digest(header_of(*b)) : std::nullopt;
                        if (!dg || claims_->header_binding(tip, *dg) != Basis::Computed) return std::nullopt;
                    }
                    return n->H;
                },
                store_->b0(), cfg_.p.open_bins, &theirs);
        if (c.verdict == HelloVerdict::Accept) {
            const bool fresh = peers_.count(peer) == 0;
            peers_[peer] = theirs.tail;
            if (fresh) hf_round_.insert(peer);  // a new link: its next catch-up request is a round's first
            if (fresh) joiner_->release_waits(std::nullopt);  // a new Path B peer: the pairs waiting on a P_r are tried
            // the first catch-up round after the start opens at the first tail whose tip is not held here (the template
            // gate); the tail's best_cum_work is not read
            if (gate_applies() && first_round_ && !first_round_open_ && !holds_tip(theirs.tail.best_tip))
                first_round_open_ = true;
            if (transport_ != nullptr && links_.count(peer) == 0)
                links_[peer] = std::make_shared<PathbJoinLink>(peer, *transport_, cfg_.identity.chain_id, cfg_.p,
                                                               cfg_.buffers, frame_bytes_headers(), window_);
            // the candidates of a trigger: after a load failure (no A) every tail; with a joined A a tip it does not
            // hold (its fork may lie below what the node holds; the attempt's scope at the reply's L decides, 3.3a
            // (4), ruling 46 S4wa-1 (b)). An empty store at position 0 offers none: it catches up headers first
            // (ruling 39 P-S4w-6; the joiner path for a tip beyond what peers retain is S4w-bc's, with the prune step)
            // A full node that pruned (its tree no longer reaches position 0) offers a tip it does not hold in the same
            // way: a fork below what it holds has no header work its own records compute; the scope decides.
            const bool after_failure = load_failed_ && joiner_->a() == nullptr;
            const bool unheld = tree_->find(theirs.tail.best_tip) == nullptr;
            const bool pruned = joined_ == nullptr && !load_failed_ && tree_->genesis().pos > 0;
            if (theirs.tail.best_tip != cfg_.identity.pool_id
                && (after_failure || ((joined_ != nullptr || pruned) && unheld)))
                offer(theirs.tail.best_tip, peer, theirs.tail.best_cum_work);
        }
        return c;
    }
    bool has_pathb_peer() const noexcept { return !peers_.empty(); }
    // A HELLO tip this node holds: position 0 (the pool identity) or a carrier placed in its tree. The catch-up
    // trigger, its done test and the template gate read this, never a tail's best_cum_work.
    bool holds_tip(const Hash32& tip) const { return tip == cfg_.identity.pool_id || tree_->find(tip) != nullptr; }

    // ---- the relay node's glue (pathb_relay_node.hpp) ----
    // The caller's headers-first catch-up to `peer` got a reply with no header to a request from position 0 (the peer
    // serves none of this node's chain), or (a store not caught up, the caller's test) a catch-up step stayed deferred
    // on a P_r past its context's time. The peer's HELLO tip becomes a join candidate with that peer as its server (no
    // load failure, no adopted state, not poisoned; K_NCU not read) when the tip is not position 0 and not held here;
    // one pair per (tip, server) (P-52); rule (4) of the attempt decides whether it replaces the node's own chain.
    // True: the pair was queued.
    bool offer_empty_store_tip(std::uint64_t peer) {
        if (poisoned_ || load_failed_ || joined_ != nullptr) return false;
        const auto it = peers_.find(peer);
        if (it == peers_.end()) return false;
        const HelloTail& t = it->second;
        if (holds_tip(t.best_tip)) return false;
        const std::size_t before = joiner_->queue().size();
        offer(t.best_tip, peer, t.best_cum_work);
        return joiner_->queue().size() > before;
    }
    // P-52: the (tip, server) pair lives: queued, or the open attempt's (taken from the queue, not yet applied). The
    // caller's hand-over to the joiner is recorded, and holds, only while its pair lives (E-193).
    bool pair_lives(const Hash32& tip, std::uint64_t server) const {
        for (const AttemptQueue::Pair& q : joiner_->queue().pairs())
            if (q.candidate == tip && q.server == server) return true;
        const std::optional<AttemptQueue::Pair>& r = open_attempt();
        return r && r->candidate == tip && r->server == server;
    }
    // An attempt open with a server that left: K_NCU's end is not evaluated before the attempt's own end (E-193).
    bool attempt_server_gone() const {
        const std::optional<AttemptQueue::Pair>& r = open_attempt();
        return r && peers_.count(r->server) == 0;
    }
    // Caught up (node policy; K_NCU): a store that started empty and was not launched here is not caught up until
    // every catch-up the caller started from a HELLO ended (its tip held, or its reply's own decision), a join adopts,
    // or a join attempt completes and rule (4) keeps the node's chain; each also waits until the node holds no frame
    // it received and has not judged, and no parked frame whose parent it holds (E-193: drain_done).
    bool caught_up() const noexcept { return !not_caught_up_; }
    // The first catch-up round after the start is in flight (the template gate's first clause).
    bool first_round_open() const noexcept { return first_round_open_; }
    // The caller's catch-ups ended: the record leaves the store (one batch).
    void note_caught_up() {
        if (!not_caught_up_) return;
        not_caught_up_ = false;
        first_round_ = first_round_open_ = false;
        ncu_due_ = NcuDue::None;
        reset_delivery();
        if (kv_ == nullptr || poisoned_) return;
        LaneBatch b;
        b.del(store_keys::ncu(cfg_.record_chain));
        if (!commit_lane_batch(*kv_, b)) poison(tree_->best().id);
    }
    // E-193's second half: the node holds no frame it received and has not judged (the caller's inbound frames, the
    // released carriers not run yet, a RandomX failure's re-run) and no parked frame whose parent it holds.
    bool drain_done() const {
        if (!release_q_.empty() || !rx_failed_.empty()) return false;
        for (const auto& [parent, peers] : deferred_.waiting_parents())
            if (const CarrierNode* pn = tree_->find(parent); pn != nullptr && pn->verified) return false;
        return !inbound_idle_ || inbound_idle_();
    }
    // The caller's inbound frames: true when it holds none it received and has not given to the node (unset: none).
    void set_inbound_idle(std::function<bool()> f) { inbound_idle_ = std::move(f); }
    // The caller's catch-ups: one not ended toward a tip this node does not hold (the template gate's claim case).
    void set_catchup_claim(std::function<bool()> f) { catchup_claim_ = std::move(f); }
    // The template gate's final state (the KATs).
    bool gate_held() const { return gate_holds(); }
    // A completed join attempt that rule (4) did not take, or an adoption, at a store not caught up: K_NCU ends when
    // the drain is done (finish_kept, finish_adopted).
    bool kept_due() const noexcept { return ncu_due_ == NcuDue::Kept && not_caught_up_; }
    bool adopt_due() const noexcept { return ncu_due_ == NcuDue::Adopted && not_caught_up_; }
    bool finish_kept() {
        if (!kept_due() || !drain_done()) return false;
        note_caught_up();
        return true;
    }
    bool finish_adopted() {
        if (!adopt_due() || !drain_done()) return false;
        note_caught_up();
        return true;
    }
    // Not caught up, templates built: the gate open (gate_holds) with a HELLO tail's tip not held here (the caller logs
    // it).
    bool unverified_claims() const {
        if (!gate_applies() || gate_holds()) return false;
        for (const auto& [peer, t] : peers_)
            if (!holds_tip(t.best_tip)) return true;
        return false;
    }
    // The P_r ids queued join pairs wait on (a NotServed on an unresolved P_r), and their release: the id resolved,
    // or (nullopt) every id.
    std::vector<std::pair<Missing, Hash32>> join_waits() const { return joiner_->queue().waits(); }
    std::size_t release_join_waits(const std::optional<Hash32>& id, const std::optional<Missing>& cause = std::nullopt) {
        return joiner_->release_waits(id, cause);
    }

    // A frame this node parked, by its digest, taken out of the deferred store to be run again; nullopt: not held.
    std::optional<ParkedFrame> take_parked(const Hash32& digest) {
        if (poisoned_) return std::nullopt;
        return deferred_.take(*tree_, digest);
    }
    // The relay's re-run gate (node-local; no verdict reads it): the Monero input a DEFER names is held now:
    // MoneroBlock its P_r resolved, Seed its seed, MissingBlock the block, MissingWeights its weight inputs.
    bool monero_input_held(Missing m, const Hash32& id) const {
        switch (m) {
            case Missing::MoneroBlock: return io_.resolve_pr && io_.resolve_pr(id).status == PrInfo::Status::Held;
            case Missing::Seed: return io_.seed_of && io_.seed_of(id).has_value();
            case Missing::MissingBlock: return io_.monero != nullptr && io_.monero->block(id).has_value();
            case Missing::MissingWeights: return io_.monero != nullptr && io_.monero->weights_at(id).has_value();
            default: return false;
        }
    }
    // The follower holds the Monero block (with or without its weights).
    bool monero_block_held(const Hash32& id) const { return io_.monero != nullptr && io_.monero->block(id).has_value(); }
    // An object's origin height h = height(P_r) + 1 by its own P_r held with or without its weights (the seal sweep of
    // parked objects); nullopt: P_r not held.
    std::optional<std::uint64_t> held_origin(const Hash32& p_r) const {
        const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(p_r) : PrInfo{};
        if (pr.status == PrInfo::Status::Held) return pr.height + 1;
        if (io_.monero != nullptr)
            if (const std::optional<BranchBlock> b = io_.monero->block(p_r)) return b->height + 1;
        return std::nullopt;
    }
    // The deferred store holds a frame of this digest; its cap (J_0).
    bool parked_held(const Hash32& digest) const { return deferred_.holds(digest); }
    std::uint64_t deferred_cap() const noexcept { return deferred_.cap(); }
    // The digests of every frame the deferred store holds (the seal sweep of parked frames).
    std::vector<Hash32> parked_digests() const { return deferred_.digests(); }
    // The FC_GETCARRIER(parent) asks of ParentUnknown DEFERs sent since the start.
    std::uint64_t parent_asks() const noexcept { return parent_asks_; }
    // ... of them sent by reask_parents.
    std::uint64_t parent_reasks() const noexcept { return parent_reasks_; }
    // The relay's maintenance tick, after tick(now_s): the lowest frame of a parked chain (its parent neither held nor
    // parked) has FC_GETCARRIER(parent) sent while that parent is missing, once it was not asked within P-53 (an ask
    // lost or not served, an ancestor the deferred store evicted), whether or not the best tip moves, while headers first
    // is not live (headers_first_live); at most one ask
    // per parent id per P-53, none for a parent the header path asked within P-53. The first ask goes to the sender of
    // the chain's oldest frame while it is connected, else to another connected Path B peer (one that sent frames of that
    // chain first); each repeat goes to the next connected peer in turn. `room(peer)`: the asks that peer may take now
    // (the relay's asked-carrier record per peer); a peer without room is passed over, and with none left the ask waits
    // for a later pass. Bound: at most P-47 asks per P-53 per node (the waiting keys; about 105 per second at the
    // defaults), each a one-id FC_GETCARRIER to one peer.
    void reask_parents(const std::function<std::size_t(std::uint64_t peer)>& room = nullptr) {
        if (poisoned_ || deferred_.waiting_keys() == 0 || headers_first_live()) return;
        const std::set<Hash32> parked = deferred_.ids();
        std::set<Hash32> missing;
        for (const auto& [parent, senders] : deferred_.waiting_parents()) {
            if (tree_->find(parent) != nullptr || tree_->is_waiting(parent) || parked.count(parent) != 0) continue;
            missing.insert(parent);
            if (const auto a = parent_asked_.find(parent);
                a != parent_asked_.end() && clock_s_ < a->second + cfg_.abandon_timeout_s)
                continue;
            if (const auto b = bodies_asked_.find(parent);
                b != bodies_asked_.end() && clock_s_ < b->second + cfg_.abandon_timeout_s)
                continue;  // asked by a header page within P-53
            const std::optional<std::uint64_t> to = reask_target(parent, senders, room);
            if (!to) continue;
            parent_asked_[parent] = clock_s_;
            GetCarrier q;
            q.chain_id = cfg_.identity.chain_id;
            q.ids = {parent};
            q.want_bodies = true;
            ++parent_asks_;
            ++parent_reasks_;
            send(*to, *encode_fc_getcarrier(q, cfg_.p));
        }
        for (auto it = reask_round_.begin(); it != reask_round_.end();)  // the rounds of parents no longer missing go
            it = missing.count(it->first) == 0 ? reask_round_.erase(it) : std::next(it);
    }
    // A parked carrier frame's own P_r (its own receipt's), by digest; nullopt: no such frame held.
    std::optional<Hash32> parked_own_pr(const Hash32& digest) const {
        const ParkedFrame* f = deferred_.get(digest);
        if (f == nullptr || f->frame.size() <= kFrameHeaderBytes) return std::nullopt;
        CarrierBodyV3 c;
        if (decode_carrier_body_v3(f->frame.data() + kFrameHeaderBytes, f->frame.size() - kFrameHeaderBytes,
                                   CarrierLimits{cfg_.buffers.receipt, cfg_.p.r_max}, c) != WireError::None)
            return std::nullopt;
        return c.own.blob.prev_id;
    }
    // Called between the replay steps of a join attempt (on the join worker).
    void set_join_step(std::function<void()> f) {
        if (!f) {
            joiner_->set_on_step({});
            return;
        }
        joiner_->set_on_step([f = std::move(f)](JoinedState&, std::uint64_t) { f(); });
    }
    // A parked frame's walked headers or bodies are asked of `peer` at most once while that peer holds its variants.
    bool may_ask(const Hash32& digest, std::uint64_t peer) { return deferred_.may_ask(digest, peer); }
    // The parked frames marked for a re-walk (data they walked arrived), taken out of the deferred store.
    // The released carriers whose admission failed with a RandomX failure (drain_released): the caller runs them
    // again.
    std::vector<ParkedFrame> take_rx_failed() { return std::exchange(rx_failed_, {}); }
    // The unsolicited released carriers placed by a drain (their first placement): the sender and the objects to
    // count in P-15 (the carrier and its carried bodies not pending here).
    struct PlacedRelease {
        std::uint64_t peer = 0;
        std::uint64_t objects = 0;
    };
    std::vector<PlacedRelease> take_placed_released() { return std::exchange(placed_released_, {}); }
    // The outcomes of the carriers the node placed on its own, since the last call: the released carriers a drain ran
    // (drain_released; at most the release queue's length per drain) and the walked carriers a bind placed
    // (bind_walked_branch; at most the walked ids). The sender, the action, the row and verdict, the omissions and the
    // switch counts, for the relay's accounting of a received frame (the verdict by row, the omission log, the switch
    // line), and the strike tokens and the frame's id, for the relay's tokens and bans of a received frame.
    struct DrainedResult {
        std::uint64_t peer = 0;
        NodeAction action = NodeAction::None;
        RowId row = RowId::None;
        AdmitVerdict verdict = AdmitVerdict::Defer;
        std::uint64_t omitted = 0;
        std::uint64_t repended = 0;
        std::uint64_t lost = 0;
        std::uint32_t strike = 0;  // a STRIKE: its tokens
        Hash32 id{};               // the frame's id (a STRIKE or BAN line names it)
        Hash32 object{};  // a STRIKE or REFUSE: the id of the body it names (logs only)
    };
    std::vector<DrainedResult> take_drained() { return std::exchange(drained_, {}); }
    // The receipts the switches by the journal put back into the pending set (E11), in re-pend order, since the last
    // call: the caller relays them as FB_RECEIPTS v3 (a receipt no longer pending then is skipped there).
    std::vector<Hash32> take_repended() { return std::exchange(repended_out_, {}); }
    std::vector<ParkedFrame> take_rewalk_frames() {
        std::vector<ParkedFrame> out;
        if (poisoned_) return out;
        for (const Hash32& d : deferred_.take_rewalks())
            if (std::optional<ParkedFrame> f = deferred_.take(*tree_, d)) out.push_back(std::move(*f));
        return out;
    }
    // FC_CARRIER from `peer` in reply to this node's FC_GETCARRIER (want_bodies 1) for a walked carrier: its carried
    // bodies as that peer's body set of the carrier (its references learned). False: the frame does not decode.
    bool on_body_set(std::uint64_t peer, std::span<const std::uint8_t> frame) {
        if (poisoned_ || !check_fc_carrier(frame, cfg_.identity.chain_id, cfg_.buffers).ok()) return false;
        CarrierBodyV3 c;
        if (decode_carrier_body_v3(frame.data() + kFrameHeaderBytes, frame.size() - kFrameHeaderBytes,
                                   CarrierLimits{cfg_.buffers.receipt, cfg_.p.r_max}, c)
            != WireError::None)
            return false;
        const Hash32 id = receipt_id(c.own);
        for (const ReceiptBodyV3& b : c.carried) learn_refs(b);
        learn_refs(c.own);
        const IndexAdd a = headers_->add_body_set(peer, id, c.carried, header_digest(header_of(c)));
        if (a == IndexAdd::Added || a == IndexAdd::Replaced) deferred_.touch({id});
        return true;
    }
    // The walked branch a TipBodies DEFER names, fork upward: every held variant whose claimed parent is placed runs
    // bind_header; a Match binds it, a computed Mismatch refutes it (its servers BANned or
    // struck); a bound carrier with a body set (none needed when it carries nothing) is admitted in the role Closure
    // and placed through this node's placement (the store batch, a switch, the waiting carriers released).
    struct WalkBind {
        std::vector<Hash32> placed;
        std::vector<std::uint64_t> banned;
        std::vector<std::string> banned_why;  // one per entry of banned
        std::vector<std::uint64_t> struck;
        std::vector<Hash32> need_bodies;  // bound, carrying bodies, no body set held
        bool rx_failed = false;           // a Closure admission failed with RandomxFailure: the walk stopped there
    };
    WalkBind bind_walked_branch(const std::vector<Hash32>& ids) {
        WalkBind out;
        if (poisoned_) return out;
        for (bool progress = true; progress && !poisoned_ && !out.rx_failed;) {
            progress = false;
            out.need_bodies.clear();
            for (const Hash32& id : ids) {
                if (out.rx_failed) break;
                if (tree_->find(id) != nullptr) continue;
                if (!headers_->bound_digest(id)) {
                    std::vector<Hash32> digests;
                    for (const HeaderVariant* y : headers_->variants(id)) digests.push_back(y->digest);
                    for (const Hash32& dg : digests) {
                        const HeaderVariant* y = headers_->variant(id, dg);
                        if (y == nullptr || y->bound || tree_->find(y->header.own.side.tip) == nullptr) continue;
                        const HeaderBindResult hb = bind_header(env(), *y);
                        if (hb.bind == HeaderBind::Match) {
                            headers_->bind(id, dg);
                            progress = true;
                            break;
                        }
                        if (hb.bind == HeaderBind::Mismatch) {
                            std::vector<std::uint64_t>& to = hb.word == AdmitVerdict::Ban ? out.banned : out.struck;
                            to.insert(to.end(), y->peers.begin(), y->peers.end());
                            if (hb.word == AdmitVerdict::Ban)
                                out.banned_why.resize(out.banned.size(), "walked header " + hex32(id).substr(0, 16) +
                                                                                 ": bind mismatch at row R" +
                                                                                 std::to_string(static_cast<int>(hb.row)));
                            headers_->refute(id, dg);
                            progress = true;
                        }
                    }
                }
                const std::optional<Hash32> bd = headers_->bound_digest(id);
                if (!bd) continue;
                const HeaderVariant* y = headers_->variant(id, *bd);
                if (y == nullptr || tree_->find(y->header.own.side.tip) == nullptr) continue;
                std::vector<std::vector<ReceiptBodyV3>> sets;
                std::vector<std::uint64_t> servers;
                for (const BodySet* bs : headers_->body_sets(id)) {
                    sets.push_back(bs->bodies);
                    servers.push_back(bs->peer);
                }
                if (y->header.n_carried == 0 && sets.empty()) {  // carries nothing: no body set (its header's server)
                    sets.emplace_back();
                    servers.push_back(y->peers.empty() ? kOwnPeer : *y->peers.begin());
                }
                if (sets.empty()) out.need_bodies.push_back(id);
                const ReceiptBodyV3 own = y->header.own;
                for (std::size_t k = 0; k < sets.size(); ++k) {
                    CarrierBodyV3 c;
                    c.own = own;
                    c.carried = sets[k];
                    const std::optional<std::vector<std::uint8_t>> frame = encode_fc_carrier(cfg_.identity.chain_id, c, cfg_.p.r_max);
                    if (!frame) continue;
                    AdmitResult r;
                    try {
                        r = admit_frame_from(env(), servers[k], *frame, CarrierRole::Closure);
                    } catch (const RandomxFailure&) {  // node-internal: the walk stops; what it found so far stays
                        out.rx_failed = true;
                        break;
                    }
                    if (r.verdict == AdmitVerdict::AdmitCarrier) {
                        const NodeEventResult sr = settle_carrier(servers[k], *frame, r, false);
                        drained_.push_back(DrainedResult{servers[k], sr.action, sr.admit.row, sr.admit.verdict, sr.omitted,
                                                         sr.repended, sr.lost, sr.admit.strike, id});
                        if (tree_->find(id) != nullptr) {
                            out.placed.push_back(id);
                            progress = true;
                        }
                        break;
                    }
                    if (!sets[k].empty() && (r.verdict == AdmitVerdict::Ban || r.verdict == AdmitVerdict::Strike)) {
                        (r.verdict == AdmitVerdict::Ban ? out.banned : out.struck).push_back(servers[k]);
                        if (r.verdict == AdmitVerdict::Ban)
                            out.banned_why.resize(out.banned.size(), "walked carrier " + hex32(id).substr(0, 16) +
                                                                             ": body set refuted at row R" +
                                                                             std::to_string(static_cast<int>(r.row)));
                        headers_->drop_body_set(servers[k], id);
                        progress = true;
                        break;
                    }
                }
            }
        }
        if (!out.placed.empty()) drain_released();
        return out;
    }

    void disconnect(std::uint64_t peer) {
        peers_.erase(peer);
        hf_round_.erase(peer);
        if (hp_win_ && hp_win_peer_ == peer) hp_win_.reset();  // its verified headers released below
        hp_body_.erase(peer);
        headers_->release_peer(peer);
        deferred_.forget_peer(peer);
        header_req_.erase(peer);
        timers_.done(Req{peer, ReqKind::Headers, Hash32{}});
        for (auto it = assemblies_.begin(); it != assemblies_.end();) {
            if (it->first.first == peer) {
                timers_.done(Req{peer, ReqKind::Buckets, it->first.second});
                it = assemblies_.erase(it);
            } else {
                ++it;
            }
        }
        window_.forget(peer);
        hold_.close(peer);  // one hold per connection
        hold_conns_.erase(peer);
        joiner_->disconnect(peer);  // the peer's P-52 pairs
        if (const auto it = links_.find(peer); it != links_.end()) {
            it->second->close();  // an attempt or a re-ask using it holds it to its end; its requests have no reply
            links_.erase(it);
        }
        if (attempting_) left_.insert(peer);  // its pairs dropped again once the attempt is applied
        for (auto* keys : {&closed_, &abandoned_})
            for (auto it = keys->begin(); it != keys->end();) {
                if (it->first == peer)
                    it = keys->erase(it);
                else
                    ++it;
            }
    }

    // ---- FC_CARRIER (E7) ----
    using Arrival = PathbArrival;
    // The cheap rows and RandomX (on the verify workers), then the placement.
    struct CarrierTicket {
        std::uint64_t peer = 0;
        std::vector<std::uint8_t> frame;
        AdmitResult admit;
        std::uint64_t generation = 0;
        bool relayed = true;
        bool solicited = false;  // a reply to this node's own request (kept if it parks)
        Arrival arrival;         // its arrival (the template gate's delivery clock)
    };

    CarrierTicket begin_carrier(std::uint64_t peer, std::span<const std::uint8_t> frame, bool relayed = true,
                                bool solicited = false, Arrival arrival = {}) {
        CarrierTicket t;
        t.peer = peer;
        t.solicited = solicited;
        t.relayed = relayed;
        t.arrival = arrival;
        t.generation = generation_;
        if (poisoned_) return t;  // the latch: nothing judged after the poison
        t.frame.assign(frame.begin(), frame.end());
        const FrameDecode fh = check_fc_carrier(frame, cfg_.identity.chain_id, cfg_.buffers);
        if (!fh.ok()) {
            t.admit = admit_detail::verdict(fh.error == FrameWireError::OverBuffer ? AdmitVerdict::Drop : AdmitVerdict::Strike,
                                            fh.error == FrameWireError::OverBuffer ? RowId::R1 : RowId::R2);
            return t;
        }
        t.admit = admit_frame_from(env(), peer, frame, CarrierRole::Frame);
        return t;
    }

    // The placement on the owner executor: when the best chain changed since
    // the ticket's admission, its cheap rows run again (RandomX from the memo).
    NodeEventResult complete_carrier(CarrierTicket t) {
        if (poisoned_) return node_internal();
        note_body_arrival(t);
        if (t.generation != generation_ && admitted(t.admit))
            t.admit = admit_frame_from(env(), t.peer, t.frame, CarrierRole::Frame);
        NodeEventResult out = settle_carrier(t.peer, t.frame, t.admit, t.relayed, t.solicited);
        if (names_object(out.admit.verdict)) {  // the body the verdict names (logs only)
            CarrierBodyV3 c;
            if (out.admit.id != Hash32{})
                out.object = out.admit.id;
            else if (t.frame.size() > kFrameHeaderBytes
                     && decode_carrier_body_v3(t.frame.data() + kFrameHeaderBytes, t.frame.size() - kFrameHeaderBytes,
                                               CarrierLimits{cfg_.buffers.receipt, cfg_.p.r_max}, c)
                                == WireError::None)
                out.object = out.admit.body == 0 ? receipt_id(c.own)
                             : out.admit.body <= c.carried.size() ? receipt_id(c.carried[out.admit.body - 1])
                                                                  : Hash32{};
        }
        return out;
    }
    static bool names_object(AdmitVerdict v) noexcept {
        return v == AdmitVerdict::Strike || v == AdmitVerdict::Refuse || v == AdmitVerdict::Ban;
    }

    NodeEventResult on_carrier(std::uint64_t peer, std::span<const std::uint8_t> frame) {
        return complete_carrier(begin_carrier(peer, frame));
    }

    // ---- FB_RECEIPTS (E8) ----
    std::vector<NodeEventResult> on_receipts(std::uint64_t peer, std::span<const std::uint8_t> frame) {
        std::vector<NodeEventResult> out;
        if (poisoned_) {
            out.push_back(node_internal());
            return out;
        }
        ReceiptsFrame rf;
        const FrameDecode d = decode_fb_receipts(frame, cfg_.identity.chain_id, cfg_.buffers, cfg_.p, rf);
        if (!d.ok()) {
            NodeEventResult r;
            r.action = NodeAction::Verdict;
            r.admit = admit_detail::verdict(d.error == FrameWireError::OverBuffer ? AdmitVerdict::Drop : AdmitVerdict::Strike,
                                            RowId::R14);
            out.push_back(r);
            return out;
        }
        for (const std::vector<std::uint8_t>& body : rf.bodies) out.push_back(on_receipt_body(peer, body));
        return out;
    }

    // ---- HOLD (E13) ----
    struct HoldState {
        bool hold = false;
        std::uint16_t epoch_cur = 0;
        std::uint64_t h_hold = 0;
        std::uint64_t x = 0;
    };
    HoldState hold_state() const {
        const CarrierNode& b = tree_->best();
        HoldState s;
        s.x = b.pos + 1;
        s.epoch_cur = b.rs.epoch_cur;
        s.h_hold = h_hold(cfg_.rp, b.rs, s.x, cfg_.T);
        s.hold = hold(cfg_.rp, b.rs, b.pos, cfg_.T);
        return s;
    }

    // ---- the template (E2) ----
    PathbTemplate make_template(std::uint64_t now_ts) {
        PathbTemplate t;
        if (poisoned_) return status(t, TemplateStatus::Poisoned);
        if (rests_on_claims()) return status(t, TemplateStatus::RestsOnClaims);
        if (!cfg_.launch && peers_.empty() && ((started_empty_ && tree_->best().pos == 0) || not_caught_up_))
            return status(t, TemplateStatus::NoPathbPeer);
        // not caught up (K_NCU): the template gate (gate_holds)
        if (gate_holds()) return status(t, TemplateStatus::CatchingUp);
        const CarrierNode& tip = tree_->best();
        t.tip = tip.id;
        t.x = tip.pos + 1;
        if (hold(cfg_.rp, tip.rs, tip.pos, cfg_.T)) return status(t, TemplateStatus::Hold);
        const std::optional<std::uint64_t> m = io_.monero_tip ? io_.monero_tip() : std::nullopt;
        if (!m) return status(t, TemplateStatus::Defer);
        const CatchupDecision cd = catchup_template(tip.h, *m, cfg_.p);
        const std::optional<Hash32> p_t = prev_of(tip.id);
        if (!p_t) return status(t, TemplateStatus::Defer);
        const std::optional<Hash32> p_r =
                cd.parent == TemplateParent::TipParent ? p_t : (io_.monero_block_at ? io_.monero_block_at(cd.parent_height) : std::nullopt);
        if (!p_r) return status(t, TemplateStatus::Defer);
        t.p_r = *p_r;
        t.h = cd.template_height;
        const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(*p_r) : PrInfo{};
        if (pr.status != PrInfo::Status::Held || pr.height + 1 != t.h) {
            t.fetch = *p_r;
            return status(t, TemplateStatus::Defer);
        }
        t.hf = pr.in.hf;
        if (amount_fork_fused(t.hf)) return status(t, TemplateStatus::ForkFuse);
        t.timestamp = std::max(now_ts, pr.in.median60.value_or(0));
        const std::optional<std::uint64_t> d = tree_->next_difficulty(tip.id);
        if (!d) return status(t, TemplateStatus::NoTemplate);
        t.d = *d;
        // the window inputs at A_t (window only)
        t.window = window_of(tip.id, *p_t, t.hf);
        if (!t.window.ok()) {
            t.fetch = t.window.missing_id;
            return status(t, TemplateStatus::Defer);
        }
        // the reward inputs at P_r
        const std::optional<WeightInputs> wi = io_.monero ? io_.monero->weights_at(*p_r) : std::nullopt;
        if (!wi) {
            t.fetch = *p_r;
            return status(t, TemplateStatus::Defer);
        }
        t.base = wi->base_reward;
        t.median = wi->zone;
        // the selection with the real coinbase size
        const std::vector<TemplateTx> cands = io_.tx_source ? io_.tx_source() : std::vector<TemplateTx>{};
        const TxSelection sel =
                select_template(cands, t.base, t.median, t.hf, t.h, t.window.window.get(), cfg_.penalty_fill);
        if (!sel.ok) {
            alarm_.raise(RowId::None, Basis::Computed, tip.id, Missing::NodeInternal);
            return status(t, TemplateStatus::NoTemplate);
        }
        for (std::size_t i : sel.picked) t.txs.push_back(cands[i]);
        t.reward = sel.reward;
        t.fees = sel.F;
        t.tx_weight = sel.T;
        t.coinbase = sel.coinbase;
        t.status = TemplateStatus::Ok;
        return t;
    }

    // ---- the job (E3) ----
    std::optional<PathbJob> make_job(const PathbTemplate& t, const PathbSession& s) {
        if (t.status != TemplateStatus::Ok) return std::nullopt;
        const CarrierNode* tip = tree_->find(t.tip);
        if (tip == nullptr) return std::nullopt;
        PathbJob job;
        job.tip = t.tip;
        job.d = t.d;
        job.h = t.h;
        ReceiptBodyV3& r = job.body;
        r.blob.major = t.hf;
        r.blob.minor = kHf16;
        r.blob.timestamp = t.timestamp;
        r.blob.prev_id = t.p_r;
        r.blob.nonce = 0;
        r.extra_nonce = s.extra_nonce;
        r.payee = s.payee;
        r.side.pool_id = cfg_.identity.pool_id;
        const EpochAt ea = epoch_at(cfg_.rp, cfg_.T, std::optional<RatchetState>(tip->rs), *ar_, tip->pos, tip->rs,
                                    tip->pos, t.x);
        r.side.rules_epoch = ea.epoch;
        job.ballot = ballot_to_write(cfg_.rp, tip->rs, t.x, cfg_.T, s.stated_vote, cfg_.vote_no);
        r.side.ballot = job.ballot.ballot;
        r.side.payee = key_ref_identity(s.payee);
        r.side.t_origin = t.d;
        r.side.tip = t.tip;
        job.carried = carried_list(t.x, t.h);
        std::vector<Hash32> ids;
        for (const ReceiptBodyV3& c : job.carried) ids.push_back(receipt_id(c));
        const std::optional<Hash32> rr = tree_->next_receipts_root(t.tip, ids);
        if (!rr) return std::nullopt;
        r.side.receipts_root = *rr;
        r.side.window_root = t.window.window_root;
        r.side.mmr_root = t.window.mmr_root;
        r.side.fee_rate_bp = cfg_.owner_fee_bp;
        if (cfg_.owner_fee_bp > 0 && cfg_.owner) {
            r.side.owner = key_ref_identity(*cfg_.owner);
            r.owner = cfg_.owner;
        }
        r.side.give_author_bp = cfg_.give_author_bp;
        r.reward_total = t.reward;
        (*refs_)[r.side.payee] = s.payee;
        // the canonical miner tx of the receipt (the function every node checks it with)
        const CanonicalTx ct = canonical_miner_tx(r, window_at(t.window), t.tip, t.p_r, t.h, t.hf, *keys_, ref_lookup(),
                                                  cfg_.author);
        if (ct.stop != CoinbaseCheck::Match || !ct.tx) return std::nullopt;
        job.miner_tx = *ct.tx;
        std::vector<::xmr::coin::Hash256> hashes;
        hashes.push_back(to_coin(ct.tx->tx_hash));
        for (const TemplateTx& x : t.txs) hashes.push_back(to_coin(x.hash));
        ::xmr::coin::TreeBranch br;
        if (!::xmr::coin::make_coinbase_branch(hashes, br)) return std::nullopt;
        for (const ::xmr::coin::Hash256& b : br.branch) r.branch.push_back(from_coin(b));
        r.blob.tx_count = hashes.size();
        r.blob.tree_root = tree_root_fold(ct.tx->tx_hash, std::span<const Hash32>(r.branch));
        return job;
    }

    // ---- the node's own share (E5) ----
    NodeEventResult on_own_share(const PathbJob& job, std::uint32_t nonce, const Hash32& pow_hash) {
        ReceiptBodyV3 r = job.body;
        r.blob.nonce = nonce;
        const Hash32 own_id = receipt_id(r);
        own_pow_ = OwnPow{own_id, pow_hash};
        struct OwnPowReset {
            std::optional<OwnPow>& p;
            ~OwnPowReset() { p.reset(); }
        } own_pow_reset{own_pow_};  // on every exit, a RandomxFailure among them
        NodeEventResult out;
        const CarrierNode* tip = tree_->find(job.tip);
        if (tip != nullptr && job.tip == tree_->best().id && job.h >= tip->H) {
            CarrierBodyV3 c;
            c.own = r;
            c.carried = job.carried;
            const std::optional<std::vector<std::uint8_t>> f = encode_fc_carrier(cfg_.identity.chain_id, c, cfg_.p.r_max);
            if (f) out = complete_carrier(begin_carrier(kOwnPeer, *f, false));
            if (out.action == NodeAction::Placed || out.action == NodeAction::Switched)
                if (const CarrierNode* n = tree_->find(own_id); n != nullptr && store_->best_at(n->pos) == own_id) {
                    own_watch_[own_id] = n->pos;
                    ++own_carriers_;
                }
        } else {
            std::vector<std::uint8_t> body;
            encode_receipt_body_v3(r, body);
            out = on_receipt_body(kOwnPeer, body);
        }
        return out;
    }

    // ---- serving (E9) ----
    // A request frame above the frame buffer: DROP; one that does not decode:
    // refuse + 1 strike (the token is the relay node's).
    ServeResult serve_getcarrier(std::uint64_t peer, std::span<const std::uint8_t> frame, std::uint64_t now_s) {
        ServeResult out;
        if (frame.size() > cfg_.buffers.frame) return token(out, FrameToken::Drop);
        GetCarrier q;
        if (!decode_fc_getcarrier(frame, cfg_.identity.chain_id, cfg_.p, q).ok()) return token(out, FrameToken::Strike);
        for (const Hash32& id : q.ids) {  // n <= 17
            (void)join_request(peer, now_s, id);
            const std::optional<CarrierBodyV3> b = serve_carrier(*tree_, *bodies_, id, q.want_bodies);
            if (!b) continue;
            if (const std::optional<std::vector<std::uint8_t>> f = encode_fc_carrier(cfg_.identity.chain_id, *b, cfg_.p.r_max))
                out.frames.push_back(*f);
        }
        return out;
    }

    // FC_GETHEADERS. A held `from`: the headers after it (serve_headers), at most
    // min(max, P-01, a frame's worth). `from` = the zero id (a join attempt's
    // page, JoinLink::headers): the headers ending at stop (zero: the best tip),
    // n = min(max, pos(stop), what fits in one frame), chosen from stop down,
    // oldest first, first_pos the position of the first.
    ServeResult serve_getheaders(std::uint64_t peer, std::span<const std::uint8_t> frame, std::uint64_t now_s) {
        ServeResult out;
        if (frame.size() > cfg_.buffers.frame) return token(out, FrameToken::Drop);
        GetHeaders q;
        if (!decode_fc_getheaders(frame, cfg_.identity.chain_id, q).ok()) return token(out, FrameToken::Strike);
        HeadersReply r{cfg_.identity.chain_id, 0, {}};
        if (q.from == Hash32{}) {
            // its first request (stop zero) starts the peer's hold at the floors of this best tip; a later one
            // continues it
            if (q.stop == Hash32{}) {
                hold_.first(peer, now_s, store_->tip_pos(), serve_floors_now());
                hold_conns_.insert(peer);
            } else {
                (void)join_request(peer, now_s, q.stop);
            }
            r = joiner_page(q.stop, q.max);
        } else if (const CarrierNode* from = tree_->find(q.from)) {
            r.first_pos = from->pos + 1;
            const std::uint64_t cap = std::min<std::uint64_t>({q.max, cfg_.journal_depth, headers_frame_fit()});
            r.headers = serve_headers(*tree_, *store_, *bodies_, *headers_, q.from, q.stop, cap);
        }
        if (const std::optional<std::vector<std::uint8_t>> f = encode_fc_headers(r, frame_bytes_headers()))
            out.frames.push_back(*f);
        return out;
    }

    // FC_GETBUCKETS: the per-peer budget (P-41, P-42), max_bytes = the
    // requester's P-42 bytes left (P-48); serve_buckets packs while it collects.
    ServeResult serve_getbuckets(std::uint64_t peer, std::span<const std::uint8_t> frame, std::uint64_t now_s) {
        ServeResult out;
        if (frame.size() > cfg_.buffers.frame) return token(out, FrameToken::Drop);
        GetBuckets q;
        if (decode_getbuckets(frame, cfg_.identity.chain_id, q) != BucketsWireError::None)
            return token(out, FrameToken::Strike);
        if (!budget_.admit(peer, now_s)) return token(out, FrameToken::Drop);  // no verdict
        (void)join_request(peer, now_s, q.at);
        const std::uint64_t max_bytes = std::min(budget_.remaining(peer, now_s), cfg_.bucket_serve_cap);
        std::optional<RatchetStateBytes> s_parent;
        // above the tree's lowest node (position 0, or a joined or pruned tree's root, its parent not held)
        if (const CarrierNode* at = tree_->find(q.at); at != nullptr && at->pos > tree_->genesis().pos)
            if (const CarrierNode* par = tree_->find(at->parent)) s_parent = encode_ratchet_state(par->rs);
        out.frames = serve_buckets(*store_, q, s_parent, cfg_.bucket_policy.frame_bytes, max_bytes);
        std::uint64_t bytes = 0;
        for (const std::vector<std::uint8_t>& f : out.frames) bytes += f.size();
        budget_.sent(peer, bytes, now_s);
        budget_.done(peer);
        return out;
    }

    // ---- the serving side of a join (P-51 as corrected; join_serve_floors, JoinServeHold) ----
    // The floors at the best tip ({0, 0} while the span at the tip is the young chain); H from the best chain's
    // records the store holds.
    JoinServeFloors serve_floors_now() const {
        const LaneView v = store_->view_at(store_->best_tip());
        const std::uint64_t lo = store_->first_record_pos();
        const auto rec = [&](std::uint64_t x) -> std::optional<std::uint64_t> {
            if (!v.ok() || x < lo || x > v.pos()) return std::nullopt;
            return v.record(x);
        };
        return join_serve_floors(cfg_.p, store_->tip_pos(), rec, store_->b0());
    }
    // The floors that apply to a request of `peer` for `item` (an open hold's while its attempt continues); an item
    // the tree does not hold is placed by the store's best chain records (a prefix header).
    JoinServeFloors join_request(std::uint64_t peer, std::uint64_t now_s, const Hash32& item) {
        const CarrierNode* n = tree_->find(item);
        std::uint64_t pos = n ? n->pos : UINT64_MAX;
        if (n == nullptr && item != Hash32{})
            if (const LaneView v = store_->view_at(item); v.ok() && v.fork_pos() == v.pos()) pos = v.pos();
        const JoinServeFloors f = hold_.request(peer, now_s, item, pos, serve_floors_now(), cfg_.abandon_timeout_s);
        if (!hold_.holding(peer)) hold_conns_.erase(peer);
        return f;
    }
    bool join_holding(std::uint64_t peer) const { return hold_.holding(peer); }
    // The lowest floors the best tip and the open holds keep (P-51's formula; the prune step applies the flags and
    // the node's own horizon, prune_floors).
    JoinServeFloors retention_floors(std::uint64_t now_s) {
        JoinServeFloors out = serve_floors_now();
        if (const std::optional<JoinServeFloors> h = held_floors(now_s)) {
            out.bodies = std::min(out.bodies, h->bodies);
            out.headers = std::min(out.headers, h->headers);
        }
        return out;
    }

    // ---- retention (P-51, P-37, P-38): the prune step ----
    // The floors the prune keeps from at the best tip L: the P-51 flags, else
    // join_serve_floors at L (the bodies' floor also for side headers and
    // views; {0, 0}: everything from position 1 while no bin is sealed at or
    // before the body floor); lowered to the floors of the open join holds and
    // to the node's own horizon: bodies and tree nodes to min(s(L), L - P-04 +
    // 1) and to the view horizon base_pos - J_0, side headers and views to the
    // view horizon, carrier records (headers) to the bodies' floor and to the
    // retarget window of the tree's root (the N_rt positions through it).
    struct PruneFloors {
        std::uint64_t bodies = 0;   // carrier bodies, tree nodes (S, records)
        std::uint64_t records = 0;  // carrier records (headers)
        std::uint64_t sides = 0;    // side headers, side views
    };
    PruneFloors prune_floors(std::uint64_t now_s) {
        PruneFloors f;
        const std::uint64_t tip = store_->tip_pos();
        const JoinServeFloors p51 = serve_floors_now();
        const auto kept = [tip](const std::optional<std::uint64_t>& n, std::uint64_t dflt) -> std::uint64_t {
            if (!n) return dflt;
            return tip + 1 > *n ? tip + 1 - *n : 0;
        };
        f.bodies = kept(cfg_.body_keep, p51.bodies);
        f.records = kept(cfg_.header_keep, p51.headers);
        f.sides = kept(cfg_.side_keep, p51.bodies);
        if (const std::optional<JoinServeFloors> h = held_floors(now_s)) {
            f.bodies = std::min(f.bodies, h->bodies);
            f.records = std::min(f.records, h->headers);
            f.sides = std::min(f.sides, h->bodies);
        }
        const std::uint64_t base = store_->base_pos();
        const std::uint64_t j0 = store_->view_horizon_depth();
        const std::uint64_t view = base > j0 ? base - j0 : 0;
        f.bodies = std::min({f.bodies, own_body_horizon(), view});
        f.sides = std::min(f.sides, view);
        const std::uint64_t nrt = cfg_.p.retarget_span;
        f.records = std::min({f.records, f.bodies, f.bodies + 1 > nrt ? f.bodies + 1 - nrt : 0});
        return f;
    }

    // The prune step (the daemon's serve loop runs it): carrier bodies and
    // tree nodes kept from floors.bodies (the tree re-rooted there), carrier
    // records from floors.records (those below the bodies as header records,
    // served from the prefix headers), side branches forking at or above
    // floors.sides; one store batch (prune_batch; a failed commit poisons the
    // store). The MMR, K_BLHASH, K_BLEAF and K_AR are kept; A's bound-work
    // profile keeps the work it counted (its work below the floor in the same
    // batch, K_BWORK, loaded at a restart: a full node's, and a joined node's
    // from x1 + 1). Nothing while poisoned, after a load failure, or while a
    // join attempt runs (it reads A).
    struct PruneReport {
        PruneFloors floors;
        bool floors_set = false;   // the floors computed (none while poisoned, after a load failure, during an attempt)
        std::uint64_t root = 0;    // the tree's lowest position after the step
        std::uint64_t first = 0;   // the store's first record after the step
        bool written = false;      // the prune batch committed
    };
    // A joined node's prune: the work its computed #9 bound (positions x1 + 1 .. ; 1 .. on a young chain) at the
    // best chain's positions below `root` that no earlier prune moved, added by Monero height; the heights the store
    // does not hold yet returned (K_BWORK).
    std::map<std::uint64_t, U128> joined_below(std::uint64_t root) {
        const JoinedState& js = *joined_;
        const std::uint64_t lo = std::max<std::uint64_t>({js.young ? 1 : js.x1 + 1, tree_->genesis().pos, jbelow_done_});
        for (std::uint64_t x = lo; x < root; ++x) {
            const std::optional<Hash32> id = store_->best_at(x);
            const CarrierNode* c = id ? tree_->find(*id) : nullptr;
            if (c == nullptr) break;
            jbelow_[c->h] = ::c2pool::xmr::native::u128_add(jbelow_[c->h], U128{c->d, 0});
            jbelow_unwritten_.insert(c->h);
        }
        jbelow_done_ = std::max(jbelow_done_, root);
        std::map<std::uint64_t, U128> out;
        for (const std::uint64_t h : jbelow_unwritten_) out[h] = jbelow_.at(h);
        return out;
    }
    PruneReport prune(std::uint64_t now_s) {
        PruneReport out;
        out.root = tree_->genesis().pos;
        out.first = store_->first_record_pos();
        if (poisoned_ || load_failed_ || attempting_) return out;
        out.floors = prune_floors(now_s);
        out.floors_set = true;
        const std::uint64_t held_first = std::max(out.first, head_.first_pos);
        const std::uint64_t root = std::max(out.floors.bodies, out.root);
        const std::uint64_t first = std::min(std::max(out.floors.records, held_first), root);
        if (root == out.root && first == held_first) return out;
        // A's bound work counted before its positions leave the tree
        if (joined_ != nullptr)
            (void)joined_->bound_work();
        else
            own_chain_.forget_below(root);
        StoreHead head = head_;
        std::map<std::uint64_t, CarrierHeader>* pre = joined_ != nullptr ? &joined_->prefix_headers : &own_prefix_;
        const std::map<std::uint64_t, U128> below = joined_ == nullptr ? own_chain_.below_unwritten() : joined_below(root);
        const std::optional<LaneBatch> b =
                prune_batch(cfg_.record_chain, head, *tree_, *store_, *bodies_, first, root, pre, &below);
        if (!b) return out;
        if (PathbKv* kv = store_kv()) {
            if (!commit_lane_batch(*kv, *b)) {
                poison(store_->best_tip());
                return out;
            }
            out.written = true;
        }
        if (joined_ == nullptr)
            own_chain_.below_written();
        else
            jbelow_unwritten_.clear();
        head_ = head;
        // the headers of the positions whose bodies go, served from the prefix headers
        for (std::uint64_t x = std::max(first, out.root); x < root; ++x)
            if (const std::optional<Hash32> id = store_->best_at(x))
                if (const CarrierBodyV3* body = bodies_->get(*id)) (*pre)[x] = header_of(*body);
        pre->erase(pre->begin(), pre->lower_bound(first));
        std::set<Hash32> side_gone;  // K_PSIDE rows of the carriers the re-root drops
        if (root > out.root)
            if (const std::optional<std::vector<Hash32>> gone = tree_->reroot(root, out.floors.sides))
                for (const Hash32& id : *gone) {
                    bodies_->erase(id);
                    side_gone.insert(id);
                }
        if (PathbKv* kv = store_kv()) {  // K_PSIDE at floors.sides (a failed scan: none this step)
            LaneBatch sb;
            if (side_prune_batch(*kv, cfg_.record_chain, out.floors.sides, side_gone, sb) && !sb.ops.empty() &&
                !commit_lane_batch(*kv, sb)) {
                poison(store_->best_tip());
                return out;
            }
        }
        out.first = store_->drop_records_below(first);
        out.root = tree_->genesis().pos;
        if (const std::optional<Hash32> s = store_->best_at(std::max(out.floors.sides, out.first)))
            if (const CarrierNode* n = tree_->find(*s)) headers_->drop_below(n->H);
        return out;
    }

    // ---- headers first (E11; the header path) ----
    // The owner of a header request: the catch-up of the peer, or a tip-header want; a context re-ask and a
    // continuation page keep the owner of the request they continue. Only the owner acts on its outcome.
    enum class HeaderOwner : std::uint8_t { None, CatchUp, Tip };
    // A request FC_GETHEADERS(from, stop, max) to `peer`. One is in flight per peer, from its send until a frame of
    // its reply arrives or the link drops; one without a frame within P-53 is retired and still in flight (no new
    // request to the peer until its reply arrives, which then DROPs). Its continuations go to the same peer. `from`
    // is held: the fork.
    bool request_headers(std::uint64_t peer, const Hash32& from, const Hash32& stop, std::uint16_t max,
                         std::uint64_t now_s, HeaderOwner owner = HeaderOwner::CatchUp) {
        if (poisoned_ || header_req_.count(peer) != 0 || tree_->find(from) == nullptr) return false;
        HeaderRequest r;
        r.fork = from;
        r.from = from;
        r.stop = stop;
        r.max = max;
        r.owner = owner;
        r.first = owner == HeaderOwner::CatchUp && hf_round_.erase(peer) != 0;
        r.sent_s = now_s;
        header_req_[peer] = std::move(r);
        timers_.sent(Req{peer, ReqKind::Headers, Hash32{}}, now_s);
        send(peer, encode_fc_getheaders(GetHeaders{cfg_.identity.chain_id, from, stop, max}));
        return true;
    }
    // A frame answering this node's FC_GETHEADERS to `peer` arrived (the caller pairs by link order; its handling may
    // wait behind the node lock): the request is answered, its P-53 clock stops. A retired request stays retired.
    void headers_arrived(std::uint64_t peer) {
        const auto it = header_req_.find(peer);
        if (it == header_req_.end() || it->second.retired || it->second.arrived) return;
        it->second.arrived = true;
        timers_.done(Req{peer, ReqKind::Headers, Hash32{}});
    }
    // The header request in flight to `peer` (open or retired), if any.
    struct HeaderSlot {
        HeaderOwner owner = HeaderOwner::None;
        Hash32 from{};  // the request's fork
        Hash32 stop{};
        bool retired = false;
    };
    std::optional<HeaderSlot> header_slot(std::uint64_t peer) const {
        const auto it = header_req_.find(peer);
        if (it == header_req_.end()) return std::nullopt;
        return HeaderSlot{it->second.owner, it->second.fork, it->second.stop, it->second.retired};
    }

    struct HeadersOutcome {
        enum class Kind : std::uint8_t {
            Unsolicited,  // no request in flight, or a frame that does not start at the open request's from: DROP
            OverBuffer,   // above the FC_HEADERS frame buffer: DROP (no token; the request ends: one frame, one request)
            Undecodable,  // the frame does not decode: refuse + 1 strike (the request ends)
            NodeInternal, // the store poisoned: nothing judged
            Ban,          // a header failed its cheap rows or its PoW at d, or a P_r served bad: BAN the server
            Keep,         // indexed, not heavier
            Continue,     // a full page: the next page asked of the same server
            FetchBodies,  // heavier: FC_GETCARRIER of its bodies (same peer)
            JoinerPath,   // heavier, its fork below the journal base: the joiner path, no body fetched
            Defer,        // a P_r not resolved yet
            Strike,       // a header failed S1.3 #6, #7 or #8: refuse + 1 strike (the request ends)
            Retired,      // the reply to a request retired at P-53: DROP (no verdict, no token, nothing indexed)
        } kind = Kind::Unsolicited;
        // the request this frame answered: its owner, fork and stop (None: no request consumed)
        HeaderOwner owner = HeaderOwner::None;
        std::size_t indexed = 0;
        std::uint64_t fork_pos = 0;
        std::vector<Hash32> ids;
        // Defer on a P_r the node does not hold: that Monero block, and the request (from its fork to stop) to ask
        // again once it resolves
        Hash32 fetch{};
        Missing cause = Missing::MoneroBlock;  // the input the request waits for (MissingWeights: the floor reading)
        Hash32 from{};
        Hash32 stop{};
        Hash32 fetch_last{};  // FetchBodies: the last body asked (none asked: the page's tip)
        std::string why;  // the deciding check, for the relay's log line
    };

    // `arrival`: the frame's arrival at the caller's link (the template gate's delivery clock; unstamped: none).
    HeadersOutcome on_headers(std::uint64_t peer, std::span<const std::uint8_t> frame, std::uint64_t now_s,
                              Arrival arrival = {}) {
        HeadersOutcome out;
        clock_s_ = std::max(clock_s_, now_s);
        if (poisoned_) {
            out.kind = HeadersOutcome::Kind::NodeInternal;
            return out;
        }
        const auto it = header_req_.find(peer);
        if (it == header_req_.end()) return out;
        // the next FC_HEADERS of a peer answers the request in flight to it (one frame, one request)
        if (it->second.retired) {  // its reply, whatever it holds: DROP, nothing judged; the slot frees
            out.kind = HeadersOutcome::Kind::Retired;
            out.owner = it->second.owner;
            out.from = it->second.fork;
            out.stop = it->second.stop;
            out.why = "FC_HEADERS reply to a retired request (from " + hex32(it->second.from).substr(0, 16) +
                      ", no frame within P-53)";
            header_req_.erase(it);
            return out;
        }
        if (frame.size() > frame_bytes_headers()) {
            out.kind = HeadersOutcome::Kind::OverBuffer;
            out.owner = it->second.owner;
            out.from = it->second.fork;
            out.stop = it->second.stop;
            if (it->second.owner == HeaderOwner::CatchUp) end_first_round();
            header_req_.erase(it);
            timers_.done(Req{peer, ReqKind::Headers, Hash32{}});
            return out;
        }
        HeadersReply rep;
        const bool decoded = decode_fc_headers(frame, cfg_.identity.chain_id, frame_bytes_headers(), cfg_.p, rep).ok();
        // a reply whose first header's parent is not the open request's `from` answers no request of this node: DROP
        // (no verdict, no token); the open request and its P-53 clock stay
        if (decoded && !rep.headers.empty() && rep.headers.front().own.side.tip != it->second.from) {
            out.kind = HeadersOutcome::Kind::Unsolicited;
            out.why = "FC_HEADERS reply to another request (first header's parent " +
                      hex32(rep.headers.front().own.side.tip).substr(0, 16) + ", open request from " +
                      hex32(it->second.from).substr(0, 16) + ")";
            if (it->second.arrived) {  // the frame counted as its reply's arrival did not answer it: the clock again
                it->second.arrived = false;
                timers_.sent(Req{peer, ReqKind::Headers, Hash32{}}, it->second.sent_s);
            }
            return out;
        }
        HeaderRequest req = std::move(it->second);
        header_req_.erase(it);
        timers_.done(Req{peer, ReqKind::Headers, Hash32{}});
        out.owner = req.owner;
        out.from = req.fork;
        out.stop = req.stop;
        if (req.owner == HeaderOwner::CatchUp) end_first_round();  // the catch-up's reply ends its first round
        if (!decoded) {
            out.kind = HeadersOutcome::Kind::Undecodable;
            headers_->release_peer(peer);
            return out;
        }
        // positions follow the hash links from the held fork (first_pos is a claim the links decide)
        const CarrierNode* fork = tree_->find(req.fork);
        if (fork == nullptr) {
            out.kind = HeadersOutcome::Kind::Keep;
            return out;
        }
        const std::size_t before = req.got.size();
        for (const CarrierHeader& h : rep.headers) {
            const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(h.own.blob.prev_id) : PrInfo{};
            if (pr.status == PrInfo::Status::Missing) {
                out.kind = HeadersOutcome::Kind::Defer;
                out.fetch = h.own.blob.prev_id;
                out.from = req.fork;
                out.stop = req.stop;
                return out;
            }
            if (pr.status == PrInfo::Status::BadServed) {
                out.kind = HeadersOutcome::Kind::Ban;  // its earlier variants released as on every BAN
                out.why = "FC_HEADERS: S1.3 #4 P_r " + hex32(h.own.blob.prev_id).substr(0, 16) + " served failing its branch PoW";
                headers_->release_peer(peer);
                return out;
            }
            req.got.push_back(h);
            req.heights.push_back(pr.height + 1);
        }
        // the header path over the branch so far: link, monotone H, then pow_ok: #8 t_origin == d,
        // #7 header fields, then the PoW at d (last; a header hashed once, the memo)
        std::vector<CarrierAnnounce> ann;
        for (std::size_t i = 0; i < req.got.size(); ++i) {
            const CarrierHeader& h = req.got[i];
            ann.push_back(CarrierAnnounce{receipt_id(h.own), h.own.side.tip, req.heights[i], h.own.side.receipts_root,
                                          h.own.side.ballot});
        }
        std::size_t k = 0;
        // #8 at a position whose window reads a claim (the node's claim view): a mismatch is ClaimLeaf (alarm +
        // DEFER), never a BAN
        std::optional<std::size_t> claim_fail;
        Basis claim_basis = Basis::Computed;
        // a size rule the floor reading leaves undecided (P_r without its weights): DEFER on that P_r, never a BAN
        std::optional<std::size_t> size_undecided;
        // S1.3 #11 SeedMissing: DEFER (no token) until the seed is held, never a BAN
        std::optional<std::size_t> seed_missing;
        std::string pow_why;  // the check pow_ok refused on
        int pow_row = 0;      // its S1.3 row (7, 8 or 11)
        const auto pow_ok = [&](const CarrierAnnounce& a, std::uint64_t d) {
            const std::size_t i = k++;
            const CarrierHeader& h = req.got[i];
            if (h.own.side.t_origin != d) {
                const Basis b = basis_of(claims_, RowClass::Retarget, a.parent, fork->pos + 1 + i);
                if (is_claim_basis(b) && !claim_fail) {
                    claim_fail = i;
                    claim_basis = b;
                }
                pow_why = "S1.3 #8 t_origin " + std::to_string(h.own.side.t_origin) + " != d " + std::to_string(d);
                pow_row = 8;
                return false;
            }
            const PrInfo pr = io_.resolve_pr(h.own.blob.prev_id);
            const HeaderFault hf = header_fields(h.own, encoded_length(h.own), pr.in);
            if (hf == HeaderFault::SizeUndecided && !size_undecided) size_undecided = i;
            if (header_fields_verdict(hf)) {
                pow_why = "S1.3 #7 header fault " + std::to_string(static_cast<int>(hf));
                pow_row = 7;
                return false;
            }
            const std::optional<Hash32> seed = io_.seed_of ? io_.seed_of(h.own.blob.prev_id) : std::nullopt;
            if (!seed) {
                if (!seed_missing) seed_missing = i;
                pow_why = "S1.3 #11 no seed for P_r " + hex32(h.own.blob.prev_id).substr(0, 16);
                pow_row = 11;
                return false;
            }
            if (!verify_memo(h.own.blob, d, *seed)) {
                pow_why = "S1.3 #11 PoW below d " + std::to_string(d);
                pow_row = 11;
                return false;
            }
            return true;
        };
        const std::optional<std::vector<SideHeader>> side = tree_->check_side_headers(req.fork, ann, pow_ok);
        if (!side) {
            out.kind = HeadersOutcome::Kind::Keep;
            return out;
        }
        for (std::size_t i = 0; i < side->size(); ++i) {
            const SideHeader& sh = (*side)[i];
            if (sh.check != HeaderCheck::Passed) {
                if (claim_fail && *claim_fail == i) {  // #8 on a claim: alarm + DEFER, no token, nothing indexed
                    alarm_.raise(RowId::R9, claim_basis, sh.id, Missing::ClaimAlarm);
                    out.kind = HeadersOutcome::Kind::Defer;
                    return out;
                }
                if (size_undecided && *size_undecided == i) {  // the floor reading: DEFER until P_r's weights, no token
                    out.kind = HeadersOutcome::Kind::Defer;
                    out.fetch = req.got[i].own.blob.prev_id;
                    out.cause = Missing::MissingWeights;
                    out.from = req.fork;
                    out.stop = req.stop;
                    return out;
                }
                if (seed_missing && *seed_missing == i) {  // S1.3 #11 SeedMissing: DEFER, no token; asked again when held
                    out.kind = HeadersOutcome::Kind::Defer;
                    out.fetch = req.got[i].own.blob.prev_id;
                    out.cause = Missing::Seed;
                    out.from = req.fork;
                    out.stop = req.stop;
                    return out;
                }
                const Hash32 prev = i == 0 ? req.fork : ann[i - 1].id;
                const bool checked = ann[i].parent == prev && k == i + 1;  // pow_ok ran on this header
                const bool monotone = ann[i].parent == prev && k == i;     // h below the record H
                if (monotone) {
                    // #6 below the fork's record H alone (no header of the reply raised the record above h) where that
                    // record is a claim (a fork node at x <= x1 of a joined store): alarm + DEFER, no token, nothing
                    // indexed (per operator ruling); every other #6 failure STRIKE
                    std::uint64_t own = 0;
                    for (std::size_t j = 0; j < i; ++j) own = std::max(own, ann[j].h);
                    const Basis hb = basis_of(claims_, RowClass::ForkRecord, req.fork, fork->pos + 1);
                    if (ann[i].h >= own && is_claim_basis(hb)) {
                        alarm_.raise(RowId::R7, hb, sh.id, Missing::ClaimAlarm);
                        out.kind = HeadersOutcome::Kind::Defer;
                        return out;
                    }
                }
                // a link broken inside the reply (a header's parent not the id of the header before it): STRIKE (per
                // operator ruling); S1.3 #6 monotone h >= H: STRIKE (per operator ruling); #7 header fields (major ==
                // hf(h); timestamp >= median60(branch of P_r); the size verdict): "STRIKE"; #8 t_origin ==
                // d_at(chain, pos(tip) + 1): "STRIKE"; #11 RandomX meets d: "BAN"
                const bool link = ann[i].parent != prev;
                out.kind = link || monotone || (checked && (pow_row == 7 || pow_row == 8)) ? HeadersOutcome::Kind::Strike
                                                                                           : HeadersOutcome::Kind::Ban;
                const std::string cause = ann[i].parent != prev ? "link (parent " + hex32(ann[i].parent).substr(0, 16) + " != " +
                                                                          hex32(prev).substr(0, 16) + ")"
                                          : checked           ? pow_why
                                                              : "S1.3 #6 h " + std::to_string(ann[i].h) + " below H";
                out.why = "FC_HEADERS header " + std::to_string(i) + " (" + hex32(sh.id).substr(0, 16) + ", pos " +
                          std::to_string(fork->pos + 1 + i) + "): " + cause;
                headers_->release_peer(peer);  // no variant of the reply indexed, the server's earlier ones released
                return out;
            }
            out.ids.push_back(sh.id);
        }
        // N-7: a variant enters the index only after the cheap rows and the PoW at d of the whole reply passed on this
        // path (path_ok passed explicitly)
        std::size_t fresh = 0;  // variants this frame brought (a re-asked page's known ones are no delivery)
        for (std::size_t i = before; i < side->size(); ++i) {
            const IndexAdd a = headers_->add(peer, req.got[i], req.heights[i], /*path_ok=*/true);
            if (a == IndexAdd::Added || a == IndexAdd::Replaced) ++fresh;
            ++out.indexed;
        }
        deferred_.touch(out.ids);
        const CarrierNode& b = tree_->best();
        const SideBranchDecision dec =
                decide_side_branch(b.cum_work, b.id, fork->cum_work, *side, 0, std::numeric_limits<std::uint64_t>::max());
        out.fork_pos = fork->pos;
        if (dec.action == SideBranchAction::FetchBodies && gate_applies() && !out.ids.empty()) {
            // headers this node verified win against its best tip: a page or side-header delivery holds the template
            // gate toward their tip (E-194 (v)); a frame that brought no new header is no delivery
            hp_win_ = ChainTip{dec.claimed_work, out.ids.back()};
            hp_win_peer_ = peer;
            if (fresh > 0) note_delivery(hp_page_, arrival);
        }
        if (dec.action == SideBranchAction::FetchBodies) {
            // one depth measure: the journal base (never fork_depth against J); a joined node at or below its x1
            if (deep_switch(fork->pos)) {
                out.kind = HeadersOutcome::Kind::JoinerPath;
                offer(req.stop != Hash32{} ? req.stop : out.ids.back(), peer, U128{});  // the branch's tip with this server
                return out;
            }
            out.kind = HeadersOutcome::Kind::FetchBodies;
            // the bodies this node neither holds nor has parked, at most the deferred store's free room (its cap less
            // the parked frames and the bodies asked within P-53: an asked body is on its way to the store) and at least
            // the first of them; the rest with a later page
            for (auto a = bodies_asked_.begin(); a != bodies_asked_.end();)
                a = tree_->find(a->first) != nullptr || now_s >= a->second + cfg_.abandon_timeout_s ? bodies_asked_.erase(a)
                                                                                                   : std::next(a);
            const std::uint64_t used = deferred_.size() + bodies_asked_.size();
            std::uint64_t room = deferred_.cap() > used ? deferred_.cap() - used : 0;
            std::vector<Hash32> want;
            for (const Hash32& id : out.ids) {
                if (room == 0 && !want.empty()) break;
                if (tree_->find(id) != nullptr || tree_->is_waiting(id)) continue;
                want.push_back(id);
                bodies_asked_[id] = now_s;
                if (room > 0) --room;
            }
            out.fetch_last = want.empty() ? out.ids.back() : want.back();
            const std::size_t per = static_cast<std::size_t>(max_receipts_per_frame(cfg_.p.r_max));
            for (std::size_t i = 0; i < want.size(); i += per) {
                GetCarrier q;
                q.chain_id = cfg_.identity.chain_id;
                q.want_bodies = true;
                for (std::size_t j = i; j < want.size() && q.ids.size() < per; ++j) q.ids.push_back(want[j]);
                if (const std::optional<std::vector<std::uint8_t>> f = encode_fc_getcarrier(q, cfg_.p)) send(peer, *f);
            }
            return out;
        }
        // a page that ends before `stop`: the next page from its last header, at the same server, while the request's
        // max is not reached (the branch the request accumulates is at most max headers)
        if (!rep.headers.empty() && out.ids.back() != req.stop && req.got.size() < req.max) {
            out.kind = HeadersOutcome::Kind::Continue;
            req.from = out.ids.back();
            req.sent_s = now_s;
            req.arrived = false;
            req.first = false;
            const GetHeaders q{cfg_.identity.chain_id, req.from, req.stop, req.max};
            header_req_[peer] = std::move(req);
            timers_.sent(Req{peer, ReqKind::Headers, Hash32{}}, now_s);
            send(peer, encode_fc_getheaders(q));
            return out;
        }
        out.kind = HeadersOutcome::Kind::Keep;
        return out;
    }

    // ---- FC_BUCKETS (E9 receive; 3.7a) ----
    // An FC_GETBUCKETS to `peer` for `at` (one assembly per (peer, at)); false:
    // the peer is closed for `at`, or its window has no frame left (FIX-1).
    bool request_buckets(std::uint64_t peer, const Hash32& at, std::uint64_t bin_lo, std::uint64_t bin_hi,
                         std::uint64_t now_s) {
        if (poisoned_) return false;
        const std::pair<std::uint64_t, Hash32> key{peer, at};
        if (assemblies_.count(key) != 0 || closed_.count(key) != 0) return false;
        if (!window_.may_request(peer, now_s)) return false;
        GetBuckets q{cfg_.identity.chain_id, at, bin_lo, bin_hi};
        const std::optional<std::vector<std::uint8_t>> f = encode_getbuckets(q);
        if (!f) return false;
        assemblies_.emplace(key, BucketsAssembly(q, store_->b0(), cfg_.p.open_bins, cfg_.bucket_policy.frame_bytes));
        timers_.sent(Req{peer, ReqKind::Buckets, at}, now_s);
        window_.requested(peer, now_s);
        send(peer, *f);
        return true;
    }

    // A frame above the bucket frame buffer (P-39): DROP. A frame that does not
    // decode: from a peer with an open request, refuse + 1 strike and its open
    // requests close; from a peer with none, DROP. Else the frame goes to the
    // assembly of its (peer, at); none: DROP (unsolicited, late).
    BucketsEventResult on_buckets(std::uint64_t peer, std::span<const std::uint8_t> frame, std::uint64_t now_s) {
        BucketsEventResult out;
        if (poisoned_) {
            out.action = NodeAction::NodeInternal;
            out.frame = FrameOutcome{BucketsFrameVerdict::Drop, BucketsFault::Unsolicited};
            return out;
        }
        if (frame.size() > cfg_.bucket_policy.frame_bytes) {
            out.frame = FrameOutcome{BucketsFrameVerdict::Drop, BucketsFault::OverBuffer};
            return out;
        }
        BucketsFrameView v;
        const BucketsWireError we = decode_buckets_view(frame, cfg_.identity.chain_id, v);
        if (we != BucketsWireError::None) {
            bool open = false;
            for (auto it = assemblies_.begin(); it != assemblies_.end();) {
                if (it->first.first != peer) {
                    ++it;
                    continue;
                }
                open = true;
                timers_.done(Req{peer, ReqKind::Buckets, it->first.second});
                closed_.insert(it->first);
                it = assemblies_.erase(it);
            }
            if (!open) {
                out.frame = FrameOutcome{BucketsFrameVerdict::Drop, BucketsFault::Unsolicited};
                return out;
            }
            out.frame.verdict = BucketsFrameVerdict::Refused;
            out.frame.fault = BucketsFault::Wire;
            out.frame.wire = we;
            out.frame.strike = 1;
            return out;
        }
        const Hash32 at = v.at;
        const auto it = assemblies_.find(std::make_pair(peer, at));
        if (it == assemblies_.end()) {
            out.frame = FrameOutcome{BucketsFrameVerdict::Drop, BucketsFault::Unsolicited};
            return out;
        }
        timers_.frame(Req{peer, ReqKind::Buckets, at}, now_s);
        window_.received(peer, frame.size(), now_s);
        out.frame = it->second.add_frame(peer, frame, anchor_of(at));
        if (out.frame.verdict == BucketsFrameVerdict::Refused || out.frame.verdict == BucketsFrameVerdict::NotServed) {
            closed_.insert(it->first);
            timers_.done(Req{peer, ReqKind::Buckets, at});
            assemblies_.erase(it);
            return out;
        }
        for (const auto& [bin, sb] : it->second.bins()) {
            if (joined_store() && bin >= store_->b0() && bin - store_->b0() < store_->first_leaf()) {
                // below the joined MMR's start: adopted from the served bucket, a claim (3.7a; E-72)
                SealedBin a;
                a.bucket = sb.bucket;
                a.leaf = sb.leaf;
                a.refs = sb.refs;
                if (store_->adopt_below(a)) {
                    claim_leaf(bin, at_header(at));
                    learn_bucket_refs(sb.refs);
                }
                continue;
            }
            if (store_->restore_bucket(sb.bucket, sb.refs)) learn_bucket_refs(sb.refs);
        }
        if (it->second.complete()) {
            timers_.done(Req{peer, ReqKind::Buckets, at});
            assemblies_.erase(it);
        }
        return out;
    }
    std::size_t open_assemblies() const noexcept { return assemblies_.size(); }

    // ---- timers ----
    // The requests with no next frame within P-53: non-service (no alarm, no
    // token, no exclusion); a bucket request's server is abandoned for that at;
    // a header request is retired (still in flight until its reply arrives or
    // the link drops; the peer gets no new header request meanwhile).
    std::size_t tick(std::uint64_t now_s) {
        std::size_t n = 0;
        clock_s_ = std::max(clock_s_, now_s);
        for (auto a = parent_asked_.begin(); a != parent_asked_.end();)  // placed, or asked P-53 ago
            a = tree_->find(a->first) != nullptr || clock_s_ >= a->second + cfg_.abandon_timeout_s ? parent_asked_.erase(a)
                                                                                               : std::next(a);
        for (const Req& r : timers_.expired(now_s)) {
            ++n;
            if (r.kind == ReqKind::Headers) {
                const auto it = header_req_.find(r.peer);
                if (it == header_req_.end() || it->second.retired) continue;
                it->second.retired = true;
                it->second.got.clear();
                it->second.heights.clear();
                if (it->second.owner == HeaderOwner::CatchUp) end_first_round();  // its P-53 ends the first round
                continue;
            }
            const auto key = std::make_pair(r.peer, r.at);
            if (assemblies_.erase(key) != 0) abandoned_.insert(key);  // its later frames DROP (no assembly)
            closed_.insert(key);
        }
        catchup_gate_tick(now_s);
        return n;
    }

    // The template gate's clock (E-194): the caller's time (ms) and its node lock's busy total (ms), given before tick.
    void gate_clock(std::uint64_t now_ms, std::uint64_t busy_ms) {
        gate_now_ms_ = std::max(gate_now_ms_, now_ms);
        gate_busy_ms_ = std::max(gate_busy_ms_, busy_ms);
    }
    // The template gate's hold after the first round: the header path delivers (E-194).
    bool delivering() const { return delivery_hold(); }

    bool abandoned(std::uint64_t peer, const Hash32& at) const { return abandoned_.count(std::make_pair(peer, at)) != 0; }

    // ---- digests (status line, KATs) ----
    std::string lane_digest() {
        std::string s;
        const CarrierNode& b = tree_->best();
        s += hex32(b.id) + ":" + std::to_string(b.pos) + ":" + std::to_string(b.d) + ":" + std::to_string(b.cum_work.lo) + ";";
        const RatchetStateBytes rs = encode_ratchet_state(b.rs);
        s += pid_detail::hex(rs.data(), rs.size()) + ";";
        for (const ActivationRow& a : ar_->rows()) s += std::to_string(a.epoch) + "@" + std::to_string(a.h_act) + ",";
        const BmmrHead h = store_->head();
        s += std::to_string(h.leaf_count) + ":" + hex32(h.root) + ";";
        const std::optional<Hash32> pt = prev_of(b.id);
        if (pt) {
            const TipWindow w = window_of(b.id, *pt, kHf16);
            s += w.ok() ? hex32(w.window_root) + ":" + hex32(w.mmr_root) : std::string("nowin");
        }
        return s;
    }

    // The FC_HEADERS frame bytes (P-14; the caller's).
    std::uint64_t frame_bytes_headers() const noexcept {
        return cfg_.headers_frame_bytes ? cfg_.headers_frame_bytes : cfg_.buffers.frame;
    }

    static constexpr std::uint64_t kOwnPeer = UINT64_MAX;

private:
    friend struct PathbNodeTestAccess;  // the KATs' view of the private state

    enum class ReqKind : std::uint8_t { Headers, Buckets };
    struct Req {
        std::uint64_t peer = 0;
        ReqKind kind = ReqKind::Headers;
        Hash32 at{};
        friend bool operator<(const Req& a, const Req& b) {
            return std::tie(a.peer, a.kind, a.at) < std::tie(b.peer, b.kind, b.at);
        }
    };
    struct HeaderRequest {
        Hash32 fork{};  // the held carrier the branch forks from
        Hash32 from{};  // this page's from
        Hash32 stop{};
        std::uint16_t max = 0;
        HeaderOwner owner = HeaderOwner::CatchUp;
        std::uint64_t sent_s = 0;  // this page's send
        bool arrived = false;      // a frame of its reply arrived: its P-53 clock stopped
        bool retired = false;      // no frame within P-53: its reply DROPs when it arrives
        bool first = false;        // a catch-up round's first request (the first after a link's first HELLO)
        std::vector<CarrierHeader> got;      // the branch's headers so far, oldest first
        std::vector<std::uint64_t> heights;  // h(y) of each
    };
    struct OwnPow {
        Hash32 id{};
        Hash32 pow_hash{};
    };

    static std::string hex32(const Hash32& h) { return pid_detail::hex(h); }
    // The state pointers at the node's own state.
    void point_own() {
        tree_ = &*own_tree_;
        store_ = &*own_store_;
        ar_ = &own_ar_;
        bodies_ = &own_bodies_;
        headers_ = &own_headers_;
        windows_ = &own_windows_;
        keys_ = &own_keys_;
        refs_ = &own_refs_;
        claims_ = nullptr;
        prefix_ = &own_prefix_;
    }
    static ::xmr::coin::Hash256 to_coin(const Hash32& h) {
        ::xmr::coin::Hash256 o;
        std::memcpy(o.data(), h.data(), kHashBytes);
        return o;
    }
    static Hash32 from_coin(const ::xmr::coin::Hash256& h) {
        Hash32 o{};
        std::memcpy(o.data(), h.data(), kHashBytes);
        return o;
    }
    static PathbTemplate status(PathbTemplate t, TemplateStatus s) {
        t.status = s;
        return t;
    }

    static StoreHead head_of(const PathbNodeConfig& cfg) {
        StoreHead h;
        h.identity = cfg.identity;
        h.genesis_id = cfg.identity.pool_id;
        h.h0 = cfg.identity.height + 1;
        h.rules_g = cfg.rules_g;
        h.s_base = encode_ratchet_state(genesis_ratchet_state(cfg.rules_g));
        return h;
    }

    void send(std::uint64_t peer, const std::vector<std::uint8_t>& f) {
        if (io_.send) io_.send(peer, f);
    }
    // The store the node writes: none after a load failure until the adoption batch replaces the failed store.
    PathbKv* store_kv() const noexcept { return load_failed_ ? nullptr : kv_; }

    void flood(const std::vector<std::uint8_t>& f, std::optional<std::uint64_t> except) {
        if (io_.flood) io_.flood(f, except);
    }

    RefLookup ref_lookup() {
        return [this](const Hash32& id) -> std::optional<XmrKeyRef> {
            const auto it = refs_->find(id);
            if (it == refs_->end()) return std::nullopt;
            return it->second;
        };
    }

    void learn_refs(const ReceiptBodyV3& r) {
        (*refs_)[r.side.payee] = r.payee;
        if (r.owner) (*refs_)[r.side.owner] = *r.owner;
    }
    // The key references of a served bucket taken back into the store (each bound to its rows by the store).
    void learn_bucket_refs(const std::vector<XmrKeyRef>& refs) {
        for (const XmrKeyRef& k : refs) (*refs_)[key_ref_identity(k)] = k;
    }

    // RandomX through the verified-body memo (a body is hashed once); the
    // node's own share returns its own hash's result. An exception from
    // io.verify leaves as RandomxFailure (node-internal).
    bool verify_memo(const HashingBlob& blob, std::uint64_t d, const Hash32& seed) {
        const Hash32 id = receipt_id(blob);
        if (own_pow_ && own_pow_->id == id) {
            unsigned char h[32];
            std::copy(own_pow_->pow_hash.begin(), own_pow_->pow_hash.end(), h);
            return ::xmr::coin::check_hash(h, d);
        }
        const MemoKey k{id, d, seed};
        if (const auto it = memo_.find(k); it != memo_.end()) return it->second;
        ++verify_calls_;
        bool ok = false;
        try {
            ok = io_.verify && io_.verify(blob, d, seed);
        } catch (const RandomxFailure&) {
            throw;
        } catch (const std::exception& e) {
            throw RandomxFailure(e.what());
        } catch (...) {
            throw RandomxFailure("RandomX: unknown failure");
        }
        memo_.emplace(k, ok);
        memo_order_.push_back(k);
        while (memo_order_.size() > memo_cap()) {
            memo_.erase(memo_order_.front());
            memo_order_.pop_front();
        }
        return ok;
    }
    std::size_t memo_cap() const noexcept { return static_cast<std::size_t>(2 * relay_horizons(cfg_.p).pending_cap); }

    AdmitEnv env() {
        return AdmitEnv{*tree_,
                        *store_,
                        *headers_,
                        *bodies_,
                        *io_.monero,
                        *windows_,
                        *keys_,
                        ref_lookup(),
                        cfg_.author,
                        cfg_.p,
                        cfg_.rp,
                        cfg_.T,
                        *ar_,
                        cfg_.identity.pool_id,
                        admit_j0(cfg_.p),
                        cfg_.buffers,
                        root_prev(),
                        io_.resolve_pr,
                        io_.seed_of,
                        [this](const HashingBlob& b, std::uint64_t d, const Hash32& s) { return verify_memo(b, d, s); },
                        alarm_,
                        claims_};
    }

    // P_t of the tree's lowest node: P_0 at position 0; a pruned tree's root, its own body's.
    Hash32 root_prev() const {
        const CarrierNode& g = tree_->genesis();
        if (g.pos != 0)
            if (const CarrierBodyV3* b = bodies_->get(g.id)) return b->own.blob.prev_id;
        return cfg_.genesis_prev;
    }

    // The carried bodies of a carrier frame this node holds no pending copy of.
    std::uint64_t carried_not_pending(std::span<const std::uint8_t> f) const {
        if (f.size() < kFrameHeaderBytes) return 0;
        CarrierBodyV3 c;
        if (decode_carrier_body_v3(f.data() + kFrameHeaderBytes, f.size() - kFrameHeaderBytes,
                                   CarrierLimits{cfg_.buffers.receipt, cfg_.p.r_max}, c) != WireError::None)
            return 0;
        std::uint64_t n = 0;
        for (const ReceiptBodyV3& b : c.carried) n += pending_.holds(receipt_id(b)) ? 0 : 1;
        return n;
    }

    std::optional<Hash32> prev_of(const Hash32& tip) const {
        if (tip == tree_->genesis().id && tree_->genesis().pos == 0) return cfg_.genesis_prev;
        const CarrierBodyV3* b = bodies_->get(tip);
        if (b == nullptr) return std::nullopt;
        return b->own.blob.prev_id;
    }

    TipWindow window_of(const Hash32& tip, const Hash32& p_t, std::uint8_t v) {
        const Hash32 author_id = key_ref_identity(cfg_.author);
        return windows_->get(tip, v, [&] {
            TipWindow w = evaluate_window_at(*store_, tip, p_t, *io_.monero, v, author_id);
            if (w.ok()) {  // each window evaluated once (the cache): what fired
                ++win_flags_.evaluated;
                win_flags_.n_dropped_bins += w.n_dropped_bins ? 1 : 0;
                win_flags_.n_cut_position += w.n_cut_position ? 1 : 0;
                win_flags_.merged_back += w.merged_back ? 1 : 0;
            }
            return w;
        });
    }

    BucketsAnchor anchor_of(const Hash32& at) const {
        BucketsAnchor a;
        const CarrierNode* n = tree_->find(at);
        const CarrierBodyV3* b = bodies_->get(at);
        if (n == nullptr || b == nullptr || n->pos <= tree_->genesis().pos) return a;  // the tree's root: no parent
        const CarrierNode* par = tree_->find(n->parent);
        if (par == nullptr) return a;
        a.header_held = true;
        a.tip_record = par->H;
        a.mmr_root = b->own.side.mmr_root;
        a.receipts_root = b->own.side.receipts_root;
        std::vector<Hash32> ids;
        for (const ReceiptBodyV3& r : b->carried) ids.push_back(receipt_id(r));
        a.carried_ids = ids;
        return a;
    }

    // The lowest floors of the open join holds (an item above every L, the zero id, reads a hold and never continues
    // it); nullopt: none open.
    std::optional<JoinServeFloors> held_floors(std::uint64_t now_s) {
        std::optional<JoinServeFloors> out;
        const JoinServeFloors none{UINT64_MAX, UINT64_MAX};
        for (auto it = hold_conns_.begin(); it != hold_conns_.end();) {
            const JoinServeFloors f = hold_.request(*it, now_s, Hash32{}, UINT64_MAX, none, cfg_.abandon_timeout_s);
            if (!hold_.holding(*it)) {
                it = hold_conns_.erase(it);
                continue;
            }
            if (!out) out = f;
            out->bodies = std::min(out->bodies, f.bodies);
            out->headers = std::min(out->headers, f.headers);
            ++it;
        }
        return out;
    }

    // The node's own body horizon at the best tip L: min(s(L), L - P-04 + 1), s(L) the phase-1 start of a restart
    // replay (the first position above the tree's root with H(x) > H(q0 - 1) - F - Fresh, q0 = max(base_pos + 1,
    // L - J + 1)), P-04 = max(the backfill formula, J).
    std::uint64_t own_body_horizon() const {
        const std::uint64_t tip = store_->tip_pos();
        const std::uint64_t J = store_->journal_depth();
        const std::uint64_t p04 = std::max(relay_horizons(cfg_.p).backfill, J);
        const std::uint64_t back = tip + 1 > p04 ? tip + 1 - p04 : 0;
        const std::uint64_t q0 = std::max(head_.base_pos + 1, tip + 1 > J ? tip + 1 - J : 0);
        const LaneView v = store_->view_at(store_->best_tip());
        const std::uint64_t lo = std::max(tree_->genesis().pos + 1, store_->first_record_pos());
        if (!v.ok() || q0 == 0 || q0 - 1 > tip || q0 - 1 < lo) return std::min(back, q0 > 0 ? q0 - 1 : 0);
        const std::uint64_t span = cfg_.p.open_bins + cfg_.p.fresh_max;
        const std::uint64_t hq = v.record(q0 - 1);
        const std::uint64_t floor_h = hq > span ? hq - span : 0;
        // H is monotone along the chain: the first x in [lo, q0 - 1] with H(x) > floor_h
        std::uint64_t a = lo, b = q0 - 1;
        while (a < b) {
            const std::uint64_t m = a + (b - a) / 2;
            if (v.record(m) > floor_h)
                b = m;
            else
                a = m + 1;
        }
        return std::min(a, back);
    }

    static ServeResult token(ServeResult r, FrameToken t) {
        r.token = t;
        return r;
    }
    static NodeEventResult node_internal() {
        NodeEventResult r;
        r.action = NodeAction::NodeInternal;
        return r;
    }

    // A store write failed (3.3): the latch (nothing is judged after it), the
    // status alarm, and the poison mark (the next load is a load failure).
    void poison(const Hash32& at) {
        if (poisoned_) return;
        poisoned_ = true;
        alarm_.raise(RowId::None, Basis::Computed, at, Missing::NodeInternal);
        if (PathbKv* kv = store_kv()) (void)commit_lane_batch(*kv, poison_batch(cfg_.record_chain));
    }

    // An upper bound of the headers one FC_HEADERS frame holds (each header holds
    // at least its hashing blob).
    std::uint64_t headers_frame_fit() const {
        const std::uint64_t fb = frame_bytes_headers();
        return fb > kHeadersFrameHeadBytes ? (fb - kHeadersFrameHeadBytes) / kHashingBlobMinBytes : 0;
    }

    // A join attempt's page: the headers ending at x = stop (zero: the best
    // tip), chosen from x down while they are bound here and fit one frame, at
    // most max, never position 0; first_pos = pos(x) - n + 1 (n = 0: 0).
    // The prefix headers ending at position p (linked down by their tips), at most max and one frame.
    HeadersReply prefix_page(std::uint64_t p, std::uint64_t max) const {
        HeadersReply r{cfg_.identity.chain_id, 0, {}};
        const std::uint64_t fb = frame_bytes_headers();
        const std::uint64_t room = fb > kHeadersFrameHeadBytes ? fb - kHeadersFrameHeadBytes : 0;
        std::uint64_t bytes = 0;
        std::vector<CarrierHeader> page;  // newest first
        Hash32 want{};
        for (std::uint64_t x = p; x >= 1 && page.size() < max; --x) {
            const auto it = prefix_->find(x);
            if (it == prefix_->end() || (!page.empty() && receipt_id(it->second.own) != want)) break;
            const std::optional<std::vector<std::uint8_t>> hb = header_bytes(it->second);
            if (!hb || bytes + hb->size() > room) break;
            bytes += hb->size();
            page.push_back(it->second);
            want = it->second.own.side.tip;
        }
        if (page.empty()) return r;
        r.first_pos = p - page.size() + 1;
        r.headers.assign(page.rbegin(), page.rend());
        return r;
    }

    HeadersReply joiner_page(const Hash32& stop, std::uint64_t max) const {
        HeadersReply r{cfg_.identity.chain_id, 0, {}};
        const Hash32 x = stop == Hash32{} ? tree_->best().id : stop;
        // a stop below the joined tree's lowest node: the prefix headers from it down
        if (tree_->find(x) == nullptr && prefix_ != nullptr)
            for (auto it = prefix_->rbegin(); it != prefix_->rend(); ++it)
                if (receipt_id(it->second.own) == x) return prefix_page(it->first, max);
        std::vector<CarrierHeader> above;  // x's bound variants above the placed carriers, newest first
        Hash32 y = x;
        for (std::size_t guard = 0; tree_->find(y) == nullptr; ++guard) {
            const std::optional<Hash32> bd = headers_->bound_digest(y);
            const HeaderVariant* v = bd ? headers_->variant(y, *bd) : nullptr;
            if (v == nullptr || guard > headers_->size()) return r;  // x is not bound at this node
            above.push_back(v->header);
            y = v->header.own.side.tip;
        }
        const CarrierNode* n = tree_->find(y);
        const std::uint64_t top = n->pos + above.size();  // pos(x)
        const std::uint64_t fb = frame_bytes_headers();
        const std::uint64_t room = fb > kHeadersFrameHeadBytes ? fb - kHeadersFrameHeadBytes : 0;
        std::uint64_t bytes = 0;
        std::vector<CarrierHeader> page;  // newest first
        const auto take = [&](const CarrierHeader& h) {
            if (page.size() >= max) return false;
            const std::optional<std::vector<std::uint8_t>> hb = header_bytes(h);
            if (!hb || bytes + hb->size() > room) return false;
            bytes += hb->size();
            page.push_back(h);
            return true;
        };
        bool more = true;
        for (const CarrierHeader& h : above)
            if (!take(h)) {
                more = false;
                break;
            }
        // down the placed chain: a carrier's header from its body, a claimed prefix node's from the prefix headers
        // (a joined node), then the prefix headers below its lowest node (E-102's header floor)
        Hash32 want{};
        std::uint64_t pos = 0;
        for (const CarrierNode* c = n; more && c != nullptr && c->pos > 0;) {
            const CarrierBodyV3* b = bodies_->get(c->id);
            const CarrierHeader* ph = nullptr;
            if (b == nullptr && prefix_ != nullptr)
                if (const auto it = prefix_->find(c->pos); it != prefix_->end() && receipt_id(it->second.own) == c->id)
                    ph = &it->second;
            if (b == nullptr && ph == nullptr) {
                more = false;  // not held here
                break;
            }
            const CarrierHeader hdr = b != nullptr ? header_of(*b) : *ph;
            if (!take(hdr)) {
                more = false;  // the frame is full
                break;
            }
            want = hdr.own.side.tip;  // the header's own parent link
            pos = c->pos;
            const CarrierNode* below = tree_->find(want);
            c = below != nullptr && below->pos + 1 == pos ? below : nullptr;  // a joined tree's root has no node below
        }
        for (; more && prefix_ != nullptr && pos > 1; --pos) {
            const auto it = prefix_->find(pos - 1);
            if (it == prefix_->end() || receipt_id(it->second.own) != want || !take(it->second)) break;
            want = it->second.own.side.tip;
        }
        if (page.empty()) return r;
        r.first_pos = top - page.size() + 1;
        r.headers.assign(page.rbegin(), page.rend());
        return r;
    }

    // ---- the joiner's hookup ----
    // The full node's own chain as A (a deep switch; ruling 47 JC-6 (a)):
    // on_chain = A's best chain, never "held"; no x1; the journal base; the
    // bound work of positions 1 .. tip kept along the best chain (each position
    // counted once, a switch recounting above its fork; an unchanged chain the
    // same instance; a prune keeps the work counted below its floor, stored
    // in the prune batch; a tree loaded from a pruned store counts from its
    // root, the stored work below it loaded); the open-bin placements of the
    // best chain.
    class FullNodeA final : public AdoptedChain {
    public:
        explicit FullNodeA(const PathbNode& n) : n_(&n) {}
        bool holds(const Hash32& id) const override { return n_->tree_->find(id) != nullptr; }
        bool on_chain(const Hash32& id) const override {
            const CarrierNode* c = n_->tree_->find(id);
            return c != nullptr && n_->store_->best_at(c->pos) == id;
        }
        std::optional<std::uint64_t> pos_of(const Hash32& id) const override {
            const CarrierNode* c = n_->tree_->find(id);
            if (c == nullptr) return std::nullopt;
            return c->pos;
        }
        // a joined store restarted: its x1 (K_BLO - 1); a full node's own chain: none
        std::optional<std::uint64_t> joined_x1() const override {
            return lo_edge_ > 0 ? std::optional<std::uint64_t>(lo_edge_ - 1) : std::nullopt;
        }
        std::uint64_t store_base() const override { return n_->store_->base_pos(); }
        Hash32 tip() const override { return n_->store_->best_tip(); }
        std::uint64_t open_placements() const override { return open_bin_placements(*n_->store_); }
        std::shared_ptr<const BoundWork> bound_work() const override {
            sync();
            return profile_;
        }
        void reset() {
            counted_.clear();
            counted_at_.clear();
            below_.clear();
            unwritten_.clear();
            lo_edge_ = 0;
            profile_ = std::make_shared<BoundWork>();
        }
        // A loaded store: the bound work stored below its floor (K_BWORK), by height, and the lower edge of the
        // count (K_BLO: x1 + 1 of a joined store; 0: none, from the tree's root).
        void seed_below(std::map<std::uint64_t, U128> below, std::uint64_t lo_edge = 0) {
            reset();
            below_ = std::move(below);
            lo_edge_ = lo_edge;
            profile_->at = below_;
        }
        // A prune: the positions below `pos` leave the count's bookkeeping (counted first); their work stays in the
        // profile, held as the work below the floor (written with the prune batch).
        void forget_below(std::uint64_t pos) {
            sync();
            if (pos <= lo_) return;
            const std::size_t k = static_cast<std::size_t>(std::min<std::uint64_t>(counted_.size(), pos - lo_));
            for (std::size_t i = 0; i < k; ++i) {
                const Counted& c = counted_[i];
                below_[c.h] = ::c2pool::xmr::native::u128_add(below_[c.h], U128{c.d, 0});
                unwritten_.insert(c.h);
                if (const auto it = counted_at_.find(c.h); it != counted_at_.end() && --it->second == 0)
                    counted_at_.erase(it);
            }
            counted_.erase(counted_.begin(), counted_.begin() + static_cast<std::ptrdiff_t>(k));
            lo_ += k;
        }
        // The heights whose work below the floor the store does not hold yet.
        std::map<std::uint64_t, U128> below_unwritten() const {
            std::map<std::uint64_t, U128> out;
            for (const std::uint64_t h : unwritten_) out[h] = below_.at(h);
            return out;
        }
        void below_written() { unwritten_.clear(); }
        const std::map<std::uint64_t, U128>& below() const noexcept { return below_; }

    private:
        struct Counted {
            Hash32 id{};
            std::uint64_t h = 0;
            std::uint64_t d = 0;
        };
        BoundWork& for_write() const {
            if (profile_.use_count() > 1) profile_ = std::make_shared<BoundWork>(*profile_);
            return *profile_;
        }
        void sync() const {
            const BinStore& st = *n_->store_;
            // from position 1, or from the root of a tree loaded from a pruned store; a joined store's from its x1 + 1
            if (counted_.empty()) lo_ = std::max<std::uint64_t>({1, n_->tree_->genesis().pos, lo_edge_});
            const std::uint64_t lo = lo_;
            const std::uint64_t top = st.tip_pos();
            const std::size_t want = top >= lo ? static_cast<std::size_t>(top - lo + 1) : 0;
            std::size_t keep = std::min(counted_.size(), want);
            while (keep > 0 && st.best_at(lo + keep - 1) != counted_[keep - 1].id) --keep;
            if (keep == counted_.size() && keep == want) return;
            BoundWork& w = for_write();
            while (counted_.size() > keep) {
                const Counted c = counted_.back();
                counted_.pop_back();
                const auto it = counted_at_.find(c.h);
                if (it == counted_at_.end()) continue;
                if (--it->second == 0) {
                    counted_at_.erase(it);
                    // the work below the floor at this height stays
                    if (const auto bt = below_.find(c.h); bt != below_.end())
                        w.at[c.h] = bt->second;
                    else
                        w.at.erase(c.h);
                } else {
                    w.at[c.h] = bound_work_minus(w.at[c.h], U128{c.d, 0});
                }
            }
            for (std::uint64_t x = lo + counted_.size(); x <= top; ++x) {
                const std::optional<Hash32> id = st.best_at(x);
                const CarrierNode* c = id ? n_->tree_->find(*id) : nullptr;
                if (c == nullptr) break;
                w.add(c->h, c->d);
                ++counted_at_[c->h];
                counted_.push_back(Counted{*id, c->h, c->d});
            }
        }
        const PathbNode* n_;
        mutable std::uint64_t lo_ = 1;  // the position of counted_[0]
        mutable std::vector<Counted> counted_;
        mutable std::map<std::uint64_t, std::uint64_t> counted_at_;
        std::map<std::uint64_t, U128> below_;  // the work counted below the prune floor, by height
        std::uint64_t lo_edge_ = 0;            // the count's lower edge (K_BLO); 0: none
        std::set<std::uint64_t> unwritten_;    // its heights not yet in the store
        mutable std::shared_ptr<BoundWork> profile_ = std::make_shared<BoundWork>();
    };

    void init_join() {
        join_in_.p = cfg_.p;
        join_in_.rp = cfg_.rp;
        join_in_.T = cfg_.T;
        join_in_.pool_id = cfg_.identity.pool_id;
        join_in_.b0 = cfg_.identity.height + 1;
        join_in_.genesis_prev = cfg_.genesis_prev;
        join_in_.rules_g = cfg_.rules_g;
        join_in_.journal_depth = cfg_.journal_depth;
        join_in_.monero = io_.monero;
        join_in_.author = cfg_.author;
        join_in_.buffers = cfg_.buffers;
        join_in_.headers_frame_bytes = frame_bytes_headers();
        join_in_.bucket_frame_bytes = cfg_.bucket_policy.frame_bytes;
        join_in_.chain_id = cfg_.identity.chain_id;
        join_in_.key_cache_bytes = cfg_.key_cache_bytes;
        join_in_.resolve_pr = io_.resolve_pr;
        join_in_.seed_of = io_.seed_of;
        join_in_.randomx = [this](const HashingBlob& b, std::uint64_t d, const Hash32& seed) { return verify_memo(b, d, seed); };
        join_in_.fetch_context = io_.fetch_context;
        joiner_.emplace(join_in_, cfg_.abandon_timeout_s);
        refresh_own_chain();
    }

    // The node's own chain is A while it is a full node holding a chain of its
    // own (an empty store at position 0 and a load failure have none).
    void refresh_own_chain() {
        if (!joiner_ || joined_ != nullptr) return;
        const bool own = !load_failed_ && tree_->best().pos > 0;
        joiner_->set_own_chain(own ? &own_chain_ : nullptr);
    }

    // A joined store, in its session (the adopted state) or after a restart (K_BLO).
    bool joined_store() const noexcept { return joined_ != nullptr || resumed_x1_.has_value(); }
    // Its x1 (nullopt: not a joined store, or a young chain).
    std::optional<std::uint64_t> joined_x1_now() const {
        if (joined_ != nullptr) return joined_->young ? std::nullopt : std::optional<std::uint64_t>(joined_->x1);
        return resumed_x1_;
    }
    // Its claimed leaves: bin -> the at header the leaf was proved against (3.7a, E-72).
    std::map<std::uint64_t, AtHeader>& claimed_map() { return joined_ != nullptr ? joined_->claimed : resumed_claimed_; }
    const std::map<std::uint64_t, AtHeader>& claimed_map() const {
        return joined_ != nullptr ? joined_->claimed : resumed_claimed_;
    }
    // A leaf adopted as a claim, kept in the store (K_BCLAIM) so that a restart judges with it.
    void claim_leaf(std::uint64_t bin, const AtHeader& at) {
        claimed_map()[bin] = at;
        if (PathbKv* kv = store_kv()) {
            LaneBatch b;
            b.put(store_keys::bclaim(cfg_.record_chain, bin), encode_bclaim(BclaimRecord{bin, at.id, at.digest}));
            if (!commit_lane_batch(*kv, b)) poison(store_->best_tip());
        }
    }
    // The window at a tip at hf 16 reads a claimed leaf (JoinedState::window_reads_claimed, from the node's state).
    bool window_reads_claimed_now(const Hash32& tip) {
        const std::map<std::uint64_t, AtHeader>& claimed = claimed_map();
        if (claimed.empty()) return false;
        const std::optional<Hash32> pt = prev_of(tip);
        if (!pt) return false;
        const TipWindow tw = window_of(tip, *pt, kHf16);
        if (!tw.ok() || tw.oldest_bin == 0) return false;
        return tw.oldest_bin <= claimed.rbegin()->first;
    }

    // The claim view of a joined store after a restart (K_BLO): the joined state's view after L (JoinClaims, phase
    // AfterL) from what the store keeps: x1 = K_BLO - 1, the joined MMR's first leaf, the claimed leaves (K_BCLAIM).
    class ResumedClaims final : public ClaimView {
    public:
        explicit ResumedClaims(PathbNode& n) : n_(&n) {}
        void set_x1(std::uint64_t x1) { x1_ = x1; }
        Basis basis(RowClass k, const Hash32& tip, std::uint64_t x) const override {
            switch (k) {
                case RowClass::Retarget:  // a window that reads the claimed prefix or span
                    return x <= x1_ + n_->cfg_.p.retarget_span ? Basis::ClaimLeaf : Basis::Computed;
                case RowClass::ForkRecord:  // a fork node at x <= x1 (per operator ruling)
                    return x <= x1_ + 1 ? Basis::ClaimLeaf : Basis::Computed;
                case RowClass::Coinbase:
                    if (x <= x1_) return Basis::NotComputed;
                    return n_->window_reads_claimed_now(tip) ? Basis::ClaimLeaf : Basis::Computed;
                case RowClass::Roots:
                    if (x <= x1_) return Basis::NotComputed;
                    return n_->store_->first_leaf() > 0 ? Basis::ClaimLeaf : Basis::Computed;
                default: return Basis::Computed;
            }
        }
        Basis header_binding(const Hash32& id, const Hash32& header_digest) const override {
            if (const CarrierNode* c = n_->tree_->find(id); c != nullptr) return c->pos <= x1_ ? Basis::NotComputed : Basis::Computed;
            const HeaderVariant* y = n_->headers_->variant(id, header_digest);
            if (y == nullptr) return Basis::NotComputed;
            const CarrierNode* pn = n_->tree_->find(y->header.own.side.tip);
            return pn == nullptr || pn->pos < x1_ ? Basis::NotComputed : Basis::Computed;
        }
        bool judge_copy(std::uint64_t, const Hash32&) const override { return true; }
        bool leaf_servable(std::uint64_t bin) const override {
            const BinStore& st = *n_->store_;
            if (n_->resumed_claimed_.count(bin) != 0) return false;  // an adopted leaf (a claim)
            return !(bin >= st.b0() && bin - st.b0() < st.first_leaf());
        }
        bool at_servable(const Hash32& at_id, const Hash32& at_digest) const override {
            const CarrierNode* c = n_->tree_->find(at_id);
            if (c == nullptr || c->pos <= x1_) return false;
            const CarrierBodyV3* b = n_->bodies_->get(at_id);
            if (b == nullptr) return false;
            const std::optional<Hash32> dg = header_digest(header_of(*b));
            return dg && *dg == at_digest;
        }
        bool rests_on_claims() const override { return false; }

    private:
        PathbNode* n_;
        std::uint64_t x1_ = 0;
    };

    // The node's own switch at a fork position takes the joiner path: below the
    // journal base (one depth measure); a joined node also at or below its x1
    // (in its session, and after a restart from K_BLO).
    bool deep_switch(std::uint64_t fork) const {
        if (joined_ != nullptr) return own_switch_path(*joined_, fork) == SwitchPath::Joiner;
        if (const std::optional<std::uint64_t> x1 = own_chain_.joined_x1(); x1 && fork <= *x1) return true;
        return fork < store_->base_pos();
    }

    // A (candidate, server) pair for the joiner (P-52; the server's link).
    void offer(const Hash32& candidate, std::uint64_t peer, const U128& claimed) {
        const auto it = links_.find(peer);
        if (it == links_.end()) return;
        U128 work = claimed;
        if (const auto pt = peers_.find(peer); pt != peers_.end() && pt->second.best_tip == candidate && work.lo == 0 && work.hi == 0)
            work = pt->second.best_cum_work;  // the server's claimed work for its HELLO tip
        joiner_->offer(candidate, *it->second, work);
    }

    // The at header (id and digest) of a carrier this node placed.
    AtHeader at_header(const Hash32& at) const {
        const CarrierBodyV3* b = bodies_->get(at);
        return AtHeader{at, b ? header_digest(header_of(*b)).value_or(Hash32{}) : Hash32{}};
    }

    // The adopted state becomes the node's (3.3, 3.3a): its tree, store, AR,
    // header index, bodies, references, caches and claim view; the old state's
    // pending set, parked frames and requests go (the joiner path re-pends
    // nothing); the adoption batch into an EMPTY store (the poison mark cleared
    // with it). False: the batch was not committed (the store poisoned).
    bool adopt(bool& written) {
        written = false;
        JoinedState* js = joiner_->adopted();
        if (js == nullptr || !js->tree || !js->store) return false;
        const bool ncu = not_caught_up_;
        joined_ = js;
        prefix_ = &js->prefix_headers;
        tree_ = &*js->tree;
        store_ = &*js->store;
        ar_ = &js->ar;
        bodies_ = &js->bodies;
        headers_ = &js->headers;
        windows_ = &js->windows();
        keys_ = &js->keys();
        refs_ = &js->refs;
        claims_ = &js->claims();
        own_chain_.reset();
        // the node's own state before the adoption is gone (a replaced own chain, or the empty start)
        own_tree_.reset();
        own_store_.reset();
        own_ar_ = ActivationRecord{};
        own_bodies_ = CarrierBodies{};
        own_headers_ = HeaderIndex{};
        own_windows_ = WindowCache{};
        own_keys_ = KeyCache{cfg_.key_cache_bytes};
        own_refs_.clear();
        own_prefix_.clear();
        pending_ = PendingSet(cfg_.pending_cap ? cfg_.pending_cap : relay_horizons(cfg_.p).pending_cap);
        repend_watch_.clear();  // the re-pended receipts left with the pending set
        amounts_.clear();
        deferred_ = DeferredCarriers(cfg_.waiting_cap ? cfg_.waiting_cap : waiting_cap_default());
        parent_asked_.clear();
        reask_round_.clear();
        hf_placed_s_ = 0;
        for (auto& [p, r] : header_req_) {  // still in flight: retired (their replies DROP; no new request before them)
            r.retired = true;
            r.got.clear();
            r.heights.clear();
            timers_.done(Req{p, ReqKind::Headers, Hash32{}});
        }
        assemblies_.clear();
        abandoned_.clear();
        closed_.clear();
        release_q_.clear();
        rx_failed_.clear();
        placed_released_.clear();
        drained_.clear();
        resumed_x1_.reset();
        resumed_claimed_.clear();
        jbelow_.clear();
        jbelow_unwritten_.clear();
        jbelow_done_ = 0;
        load_failed_ = false;
        poisoned_ = false;
        reask_pending_ = false;
        // an adoption catches up once the drain is done (E-193); until then the adopted store keeps K_NCU
        // (finish_adopted)
        not_caught_up_ = ncu && !drain_done();
        ncu_due_ = not_caught_up_ ? NcuDue::Adopted : NcuDue::None;
        first_round_ = first_round_open_ = false;
        reset_delivery();
        ++generation_;
        if (kv_ == nullptr) return true;
        LaneBatch b;
        const bool cleared = clear_store_batch(*kv_, cfg_.record_chain, b);
        const std::optional<LaneBatch> ab = adoption_batch(cfg_.record_chain, head_, *tree_, *store_, *bodies_, *ar_,
                                                           js->young ? 0 : js->x0 - 1, &js->prefix_headers);
        if (ab) b.ops.insert(b.ops.end(), ab->ops.begin(), ab->ops.end());
        put_sides(b, cfg_.record_chain, *tree_, *store_, *bodies_);  // the adopted tree's side carriers (K_PSIDE)
        // the lower edge of A's bound work (x1 + 1), read at a restart (K_BLO)
        if (!js->young) b.put(store_keys::blo(cfg_.record_chain), encode_blo(js->x1 + 1));
        if (not_caught_up_) b.put(store_keys::ncu(cfg_.record_chain), encode_ncu());  // K_NCU until the drain
        for (const auto& [bin, at] : js->claimed)  // the leaves adopted as claims (K_BCLAIM)
            b.put(store_keys::bclaim(cfg_.record_chain, bin), encode_bclaim(BclaimRecord{bin, at.id, at.digest}));
        if (!cleared || !ab || !commit_lane_batch(*kv_, b)) {
            poison(store_->best_tip());
            return true;
        }
        written = true;
        return true;
    }

    // E-72 (addendum 3.4): after a switch by the journal at a joined node, the
    // claimed leaves whose at header is not a bound carrier of the new chain
    // are asked again at a carrier of that chain whose leaf_count(tip(at))
    // covers the bin (JoinBuckets::reask_scope, fetch_any over the peers'
    // links); a leaf proved against that carrier's own header equal to the
    // claimed one is kept, its claim now at that carrier; a different leaf:
    // the replay from the position before the bin's seal lies at or below x1,
    // so the joiner path (own_switch_path; reask_replay).
    void reask_fetch(JoinAttempted& t) {
        reask_pending_ = false;
        const std::map<std::uint64_t, AtHeader>& claimed = claimed_map();
        const std::optional<std::uint64_t> x1 = joined_x1_now();
        if (!x1 || claimed.empty()) return;  // a young chain: no claim
        std::vector<AtHeader> bound;
        std::vector<std::pair<Hash32, std::uint64_t>> heavier;
        for (std::uint64_t x = *x1 + 1; x <= store_->tip_pos(); ++x) {
            const std::optional<Hash32> id = store_->best_at(x);
            if (!id) continue;
            const CarrierNode* n = tree_->find(*id);
            if (n == nullptr) continue;
            bound.push_back(at_header(*id));
            const LaneView pv = store_->view_at(n->parent);
            if (pv.ok()) heavier.emplace_back(*id, pv.leaf_count());
        }
        const std::vector<JoinBuckets::Reask> rs =
                JoinBuckets::reask_scope(claimed, bound, mismatched_, heavier, store_->b0());
        std::vector<std::shared_ptr<PathbJoinLink>> held;  // alive to the end of the re-ask
        std::vector<JoinLink*> peers;
        for (const auto& [peer, l] : links_) {
            held.push_back(l);
            peers.push_back(l.get());
        }
        for (const JoinBuckets::Reask& r : rs) {
            const AtHeader at = at_header(r.at);
            std::optional<std::uint64_t> served_by;
            const BucketsFetch f = reask_jb_.fetch_any(peers, anchor_of(r.at), at, r.bin, r.bin, cfg_.abandon_timeout_s,
                                                       &served_by);
            if (f.end != BucketsEnd::Complete || !served_by) continue;
            const auto it = f.bins.find(r.bin);
            if (it == f.bins.end()) continue;
            t.reask.push_back(JoinAttempted::Reasked{r.bin, at, it->second.leaf, *served_by});
        }
    }
    void reask_apply(const JoinAttempted& t, JoinStep& out) {
        if (!joined_store()) return;
        for (const JoinAttempted::Reasked& r : t.reask) {
            ++out.reasked;
            // the at carrier still bound on the best chain (else the next switch asks again)
            const CarrierNode* an = tree_->find(r.at.id);
            if (an == nullptr || store_->best_at(an->pos) != r.at.id) {
                reask_pending_ = true;
                continue;
            }
            const std::optional<Hash32> held = store_->best_mmr().leaf(r.bin - store_->b0());
            if (held && *held == r.leaf) {
                claim_leaf(r.bin, r.at);  // the same leaf, now proved against a carrier of this chain
                mismatched_.erase(r.bin);
                continue;
            }
            // a different leaf: replay from the position before the bin's seal (at or below x1): the joiner path,
            // the server's best tip with it a candidate
            const ReaskReplay rr = reask_replay(seal_pos_of(r.bin), store_->base_pos());
            if (rr.joiner_path || deep_switch(rr.from)) {
                out.reask_joiner = true;
                const auto pt = peers_.find(r.server);
                if (pt != peers_.end()) offer(pt->second.best_tip, r.server, pt->second.best_cum_work);
            }
        }
    }

    // The position where a bin sealed on the best chain (the first x with lc(H(x)) > bin - b0).
    std::uint64_t seal_pos_of(std::uint64_t bin) const {
        const std::uint64_t want = bin - store_->b0() + 1;
        for (std::uint64_t x = store_->first_record_pos(); x <= store_->tip_pos(); ++x) {
            const std::optional<Hash32> id = store_->best_at(x);
            if (!id) continue;
            const LaneView v = store_->view_at(*id);
            if (v.ok() && v.leaf_count() >= want) return x;
        }
        return store_->tip_pos();
    }

    // ---- E3: the carried list ----
    // Every pending receipt a carrier at x may carry: its origin bin open on the
    // best chain at x - 1, h(r) <= h(c) + Fresh, not placed on the best chain,
    // and its tip's branch judged by the S3b-4a walk (the ruling-40 boundary
    // and the closure leave it out); the first R_MAX in the canonical order.
    std::vector<ReceiptBodyV3> carried_list(std::uint64_t x, std::uint64_t h_c) {
        std::vector<ReceiptBodyV3> out;
        const CarrierNode& best = tree_->best();
        const LaneView bv = store_->view_at(best.id);
        if (!bv.ok()) return out;
        const std::uint64_t H_parent = bv.record(bv.pos());
        const AdmitEnv e = env();
        const OwnChain chain(e, best.id);
        ClosureWalk walk(e, chain);
        std::vector<std::pair<CarriedKey, const PendingReceipt*>> ok;
        for (const PendingReceipt* r : pending_.all()) {
            if (!open_at(H_parent, r->h, cfg_.p.open_bins) || !carried_upper_ok(r->h, h_c, cfg_.p.fresh_max)) continue;
            if (bv.placed_open(r->id)) continue;
            const WalkResult w = walk.walk_tip(r->body.side.tip);
            if (w.v != WalkVerdict::OnChain && w.v != WalkVerdict::Placed) continue;  // Boundary, Closure, not held
            ok.emplace_back(CarriedKey{r->h, r->id}, r);
        }
        std::sort(ok.begin(), ok.end(),
                  [&](const auto& a, const auto& b) { return carried_key_less(a.first, b.first, best.id); });
        for (std::size_t i = 0; i < ok.size() && out.size() < cfg_.p.r_max; ++i) out.push_back(ok[i].second->body);
        (void)x;
        return out;
    }

    // ---- E8: one receipt body ----
    NodeEventResult on_receipt_body(std::uint64_t peer, const std::vector<std::uint8_t>& body) {
        if (poisoned_) return node_internal();
        NodeEventResult out;
        out.admit = admit_receipt_from(env(), peer, body);
        if (out.admit.verdict == AdmitVerdict::AdmitPending) {
            ReceiptBodyV3 r;
            decode_receipt_body_v3(body.data(), body.size(), ReceiptLimits{cfg_.buffers.receipt}, r);
            learn_refs(r);
            const CarrierNode* t = tree_->find(r.side.tip);
            PendingReceipt pr{out.admit.id, r, out.admit.store_placements.empty() ? 0 : out.admit.store_placements[0].bin,
                              t ? t->pos : 0, 0};
            note_amount(r, pr.h);
            if (!pending_.add(std::move(pr))) {  // evicted at once (P-09): not held, not relayed
                out.action = NodeAction::None;
                return out;
            }
            out.action = NodeAction::Pending;
            std::vector<ReceiptBodyV3> one{r};
            if (!rests_on_claims())
                if (const std::optional<std::vector<std::uint8_t>> f = encode_fb_receipts(cfg_.identity.chain_id, one, cfg_.p))
                    flood(*f, peer == kOwnPeer ? std::nullopt : std::optional<std::uint64_t>(peer));
            return out;
        }
        out.action = out.admit.verdict == AdmitVerdict::Defer ? NodeAction::Parked : NodeAction::Verdict;
        if (names_object(out.admit.verdict)) {  // the body the verdict names (logs only)
            ReceiptBodyV3 r;
            if (out.admit.id != Hash32{})
                out.object = out.admit.id;
            else if (decode_receipt_body_v3(body.data(), body.size(), ReceiptLimits{cfg_.buffers.receipt}, r) == WireError::None)
                out.object = receipt_id(r);
        }
        return out;
    }

    // An admitted receipt body's R under its (tip, P_r) while its origin bin h is open (logs only).
    void note_amount(const ReceiptBodyV3& r, std::uint64_t h) {
        if (rests_on_claims()) return;
        const std::uint64_t R = r.reward_total;
        const auto [it, fresh] = amounts_.try_emplace(std::make_pair(r.side.tip, r.blob.prev_id), AmountKey{h, R, false});
        if (!fresh && !it->second.multi && it->second.first != R) {
            it->second.multi = true;
            ++amount_counts_.multi_fee;
        }
        amount_counts_.r_min = amount_seen_ ? std::min(amount_counts_.r_min, R) : R;
        amount_counts_.r_max = amount_seen_ ? std::max(amount_counts_.r_max, R) : R;
        amount_seen_ = true;
    }

    // ---- E7: the placement and what follows it ----
    NodeEventResult settle_carrier(std::uint64_t peer, const std::vector<std::uint8_t>& frame, const AdmitResult& r,
                                   bool relayed, bool solicited = false) {
        ++settle_depth_;
        max_settle_depth_ = std::max(max_settle_depth_, settle_depth_);
        NodeEventResult out;
        try {
            out = settle_once(peer, frame, r, relayed, solicited);
        } catch (...) {
            --settle_depth_;
            throw;
        }
        --settle_depth_;
        drain_released();
        return out;
    }

    // The carriers released by a placement wait in a queue the outermost event
    // drains (one level of placement at a time, whatever the parked chain's length).
    // A released carrier whose admission fails with a RandomX failure keeps its
    // parked state in rx_failed_ (take_rx_failed); the rest continue.
    void drain_released() {
        if (draining_ || settle_depth_ != 0) return;
        draining_ = true;
        try {
            while (!release_q_.empty() && !poisoned_) {
                ParkedFrame f = std::move(release_q_.front());
                release_q_.pop_front();
                try {
                    const std::uint64_t fresh = f.solicited ? 0 : carried_not_pending(f.frame);
                    const NodeEventResult r = complete_carrier(begin_carrier(f.peer, f.frame, true, f.solicited));
                    drained_.push_back(DrainedResult{f.peer, r.action, r.admit.row, r.admit.verdict, r.omitted, r.repended,
                                                     r.lost, r.admit.strike, f.id, r.object});
                    if (!f.solicited && (r.action == NodeAction::Placed || r.action == NodeAction::SideBranch ||
                                         r.action == NodeAction::Switched || r.action == NodeAction::JoinerPath))
                        placed_released_.push_back(PlacedRelease{f.peer, 1 + fresh});  // its first placement (P-15)
                } catch (const RandomxFailure&) {
                    rx_failed_.push_back(std::move(f));
                }
            }
        } catch (...) {
            release_q_.clear();
            draining_ = false;
            throw;
        }
        release_q_.clear();
        draining_ = false;
    }

    NodeEventResult settle_once(std::uint64_t peer, const std::vector<std::uint8_t>& frame, const AdmitResult& r,
                                bool relayed, bool solicited = false) {
        NodeEventResult out;
        out.admit = r;
        if (r.verdict == AdmitVerdict::Defer) {
            out.action = NodeAction::Parked;
            park(peer, frame, r, solicited);
            return out;
        }
        if (r.verdict != AdmitVerdict::AdmitCarrier) {
            out.action = r.verdict == AdmitVerdict::AdmitPending ? NodeAction::Pending : NodeAction::Verdict;
            return out;
        }
        for (const ReceiptBodyV3& b : r.carrier->carried) learn_refs(b);
        learn_refs(r.carrier->own);
        if (r.store_placements.size() == r.carrier->carried.size() + 1) {  // the carried list, then the own body
            for (std::size_t k = 0; k < r.carrier->carried.size(); ++k)
                note_amount(r.carrier->carried[k], r.store_placements[k].bin);
            note_amount(r.carrier->own, r.store_placements.back().bin);
        }
        // a peer's carrier's omissions at its parent, counted at its first placement (a copy of a placed carrier: none)
        const std::uint64_t omitted = peer != kOwnPeer && tree_->find(r.id) == nullptr ? omissions_of(r) : 0;
        NodeStore ns{*store_, faults_};
        WriteResult w = place_admitted(*tree_, ns, *ar_, *bodies_, r, &alarm_);
        out.write = w.outcome;
        if (w.outcome != WriteOutcome::NodeInternal) out.omitted = omitted;
        switch (w.outcome) {
            case WriteOutcome::NodeInternal:
                // a store write failure of 3.3: the store poisoned, templates stop, the joiner path at the next start
                poison(r.id);
                out.action = NodeAction::NodeInternal;
                return out;
            case WriteOutcome::Duplicate: out.action = NodeAction::Verdict; return out;
            case WriteOutcome::SideBranch: {
                out.action = NodeAction::SideBranch;
                if (PathbKv* kv = store_kv()) {  // K_PSIDE: the side carrier kept across a restart
                    LaneBatch b;
                    if (put_side(b, cfg_.record_chain, *tree_, *store_, *bodies_, r.id) && !commit_lane_batch(*kv, b)) {
                        poison(r.id);
                        out.action = NodeAction::NodeInternal;
                        return out;
                    }
                }
                break;
            }
            case WriteOutcome::Extended: {
                out.action = NodeAction::Placed;
                ++generation_;
                if (PathbKv* kv = store_kv()) {
                    const LaneBatch b = extension_batch(cfg_.record_chain, head_, *tree_, *store_, *bodies_, r.id,
                                                        std::move(w.batch), w.ar_row);
                    if (!commit_lane_batch(*kv, b)) {
                        poison(r.id);
                        out.action = NodeAction::NodeInternal;
                        return out;
                    }
                }
                after_best_change();
                break;
            }
            case WriteOutcome::SwitchToCaller: {
                const SwitchResult sr = switch_to_best(peer);
                if (!sr.joiner && !sr.internal) {
                    ++switches_.switches;
                    switches_.last_repended = sr.repended;
                    switches_.last_lost = sr.lost;
                    switches_.repended += sr.repended;
                    switches_.lost += sr.lost;
                    switches_.repend_skipped += sr.skipped;
                }
                out.action = sr.joiner ? NodeAction::JoinerPath
                                       : (sr.internal ? NodeAction::NodeInternal : NodeAction::Switched);
                out.repended = sr.repended;
                out.lost = sr.lost;
                if (sr.internal || poisoned_) return out;  // nothing flooded or released after the poison
                break;
            }
        }
        if (!rests_on_claims())  // the carried bodies of other payees, at the carrier's first placement (logs only)
            for (const ReceiptBodyV3& b : r.carrier->carried)
                if (b.side.payee != r.carrier->own.side.payee) ++amount_counts_.foreign_carried;
        headers_->placed(r.id);
        deferred_.purge(r.id);
        parent_asked_.erase(r.id);
        if (bodies_asked_.count(r.id) != 0) hf_placed_s_ = clock_s_;
        if ((relayed || peer == kOwnPeer) && !rests_on_claims())
            flood(frame, peer == kOwnPeer ? std::nullopt : std::optional<std::uint64_t>(peer));
        // the carriers that waited on this one (placed by the outermost event, drain_released)
        for (ParkedFrame& f : deferred_.release(r.id, w.place.released)) release_q_.push_back(std::move(f));
        return out;
    }

    void park(std::uint64_t peer, const std::vector<std::uint8_t>& frame, const AdmitResult& r, bool solicited = false) {
        if (!r.missing || *r.missing == Missing::CopyDeferred) return;
        ParkedFrame f;
        f.digest = r.digest == Hash32{} ? ::v37::sha256d(frame) : r.digest;
        f.peer = peer;
        f.frame = frame;
        f.solicited = solicited;
        f.cause = *r.missing;
        f.claim_based = r.claim_based;
        f.walked = r.walked;
        if (r.carrier) {
            f.id = receipt_id(r.carrier->own);
            f.parent = r.carrier->own.side.tip;
        } else {
            CarrierBodyV3 c;
            if (frame.size() > kFrameHeaderBytes
                && decode_carrier_body_v3(frame.data() + kFrameHeaderBytes, frame.size() - kFrameHeaderBytes,
                                          CarrierLimits{cfg_.buffers.receipt, cfg_.p.r_max}, c)
                           == WireError::None) {
                f.id = receipt_id(c.own);
                f.parent = c.own.side.tip;
            }
        }
        if (placed_copy(f.id, frame)) return;  // a byte-identical copy of a placed carrier: not parked
        if (*r.missing == Missing::ParentUnknown) {
            // its parent was placed after this frame's admission: admitted again (drain_released), never dropped
            if (const CarrierNode* pn = tree_->find(f.parent); pn != nullptr && pn->verified) {
                release_q_.push_back(std::move(f));
                return;
            }
        }
        const bool stored = deferred_.park(*tree_, std::move(f));
        // FC_GETCARRIER(parent) for a frame parked now (a copy held already asks nothing), whose parent is neither held,
        // nor parked, nor asked within P-53, while headers first is not live
        if (*r.missing == Missing::ParentUnknown && peer != kOwnPeer && stored && !headers_first_live()
            && parent_ask_due(r.fetch)) {
            GetCarrier q;
            q.chain_id = cfg_.identity.chain_id;
            q.ids = {r.fetch};
            q.want_bodies = true;
            ++parent_asks_;
            send(peer, *encode_fc_getcarrier(q, cfg_.p));
        }
    }

    // reask_parents' target, in turn over the asks of one parent: the connected senders of the chain's frames (the
    // oldest frame's first; connected: a Path B peer past HELLO), then every other connected Path B peer; a peer
    // without room is passed over (none with room: no ask now).
    std::optional<std::uint64_t> reask_target(const Hash32& parent, const std::vector<std::uint64_t>& senders,
                                              const std::function<std::size_t(std::uint64_t)>& room) {
        std::vector<std::uint64_t> c;
        for (const std::uint64_t p : senders)
            if (peers_.count(p) != 0) c.push_back(p);
        for (const auto& [p, t] : peers_)
            if (std::find(c.begin(), c.end(), p) == c.end()) c.push_back(p);
        if (c.empty()) return std::nullopt;
        std::uint64_t& round = reask_round_[parent];
        for (std::size_t i = 0; i < c.size(); ++i) {
            const std::uint64_t p = c[(round + i) % c.size()];
            if (room && room(p) == 0) continue;
            round += i + 1;
            return p;
        }
        return std::nullopt;
    }

    // A copy of a carrier the tree holds whose body bytes are those of its stored body (a copy with other bytes, such as
    // another carried list, is parked and judged as any frame).
    bool placed_copy(const Hash32& id, const std::vector<std::uint8_t>& frame) const {
        if (frame.size() <= kFrameHeaderBytes || tree_->find(id) == nullptr) return false;
        const CarrierBodyV3* c = bodies_->get(id);
        if (c == nullptr) return false;
        const std::optional<std::vector<std::uint8_t>> held = carrier_frame(*c, cfg_.p.r_max);
        return held && held->size() == frame.size()
               && std::equal(frame.begin() + kFrameHeaderBytes, frame.end(), held->begin() + kFrameHeaderBytes);
    }

    // Headers first is live (no parent ask, first or repeated, goes out): (a) a catch-up round's first request is in
    // flight (sent, no frame of its reply arrived, not retired); or (b) while the deferred store is not full, a body a
    // header page asked is in flight within P-53, or one was placed within P-53.
    bool headers_first_live() const {
        for (const auto& [p, r] : header_req_)
            if (r.owner == HeaderOwner::CatchUp && r.first && !r.arrived && !r.retired) return true;
        if (deferred_.size() >= deferred_.cap()) return false;
        if (hf_placed_s_ != 0 && clock_s_ < hf_placed_s_ + cfg_.abandon_timeout_s) return true;
        for (const auto& [id, t] : bodies_asked_)
            if (clock_s_ < t + cfg_.abandon_timeout_s && tree_->find(id) == nullptr) return true;
        return false;
    }

    // The parent ask of a ParentUnknown DEFER is due: `id` is not held, not parked (a frame of it waiting on its own
    // parent or DEFERred on another cause), and not asked as a parent within P-53; the ask is recorded.
    bool parent_ask_due(const Hash32& id) {
        if (tree_->find(id) != nullptr || tree_->is_waiting(id) || deferred_.holds_id(id)) return false;
        const auto [a, fresh] = parent_asked_.try_emplace(id, clock_s_);
        if (!fresh) {
            if (clock_s_ < a->second + cfg_.abandon_timeout_s) return false;
            a->second = clock_s_;
        }
        return true;
    }

    // After every change of the store's best tip: variants below H(base_pos -
    // J_0) go; the pending set loses what the best chain placed and what
    // sealed; the per-tip caches stay valid (a tip's window is its own).
    void after_best_change() {
        refresh_own_chain();
        const std::uint64_t base = store_->base_pos();
        const std::uint64_t floor_pos = base > admit_j0(cfg_.p) ? base - admit_j0(cfg_.p) : 0;
        if (const std::optional<Hash32> f = store_->best_at(std::max(floor_pos, store_->first_record_pos())))
            if (const CarrierNode* n = tree_->find(*f)) headers_->drop_below(n->H);
        // the bucket requests closed or abandoned for an `at` the node holds no more, or below that floor
        for (auto* keys : {&closed_, &abandoned_})
            for (auto it = keys->begin(); it != keys->end();) {
                const CarrierNode* n = tree_->find(it->second);
                if (n == nullptr || n->pos < floor_pos)
                    it = keys->erase(it);
                else
                    ++it;
            }
        const LaneView v = store_->view_at(store_->best_tip());
        if (!v.ok()) return;
        const std::uint64_t H = v.record(v.pos());
        pending_.erase_if([&](const PendingReceipt& r) {
            const bool placed = v.placed_open(r.id);
            const bool gone = placed || !open_at(H, r.h, cfg_.p.open_bins);
            if (const auto wt = gone ? repend_watch_.find(r.id) : repend_watch_.end(); wt != repend_watch_.end()) {
                ++(placed ? switches_.carried : switches_.sealed_pending);
                if (placed) count_carry_bins(v, r, wt->second);
                repend_watch_.erase(wt);
            }
            return gone;
        });
        for (auto it = repend_watch_.begin(); it != repend_watch_.end();) {  // evicted from the pending set meanwhile
            if (pending_.holds(it->first)) {
                ++it;
                continue;
            }
            ++switches_.evicted;
            it = repend_watch_.erase(it);
        }
        for (auto it = amounts_.begin(); it != amounts_.end();)  // the keys whose origin bin sealed at the best tip
            it = open_at(H, it->second.bin, cfg_.p.open_bins) ? std::next(it) : amounts_.erase(it);
        watch_own_carriers();
    }

    // A watched re-pended receipt carried on the best chain: H(q) - H_s, q its placing position (the tip's position if
    // its placement is not found: an upper bound), H_s the record at the new tip at its switch (logs only).
    void count_carry_bins(const LaneView& v, const PendingReceipt& r, std::uint64_t H_s) {
        std::uint64_t q = v.pos();
        for (const Placement* e : v.entries(r.h, v.pos()))
            if (e->id == r.id) {
                q = e->q;
                break;
            }
        if (q < store_->first_record_pos()) q = v.pos();  // a record the store holds (the view throws below it)
        const std::uint64_t Hq = v.record(q);
        const std::uint64_t bins = Hq > H_s ? Hq - H_s : 0;
        const std::size_t last = switches_.carry_bins.size() - 1;
        ++switches_.carry_bins[bins < last ? static_cast<std::size_t>(bins) : last];
        switches_.carry_bins_max = std::max(switches_.carry_bins_max, bins);
    }

    // Each watched own carrier: orphaned when the best chain no longer holds it at its position; confirmed (no longer
    // watched) once it is below the journal base.
    void watch_own_carriers() {
        const std::uint64_t base = store_->base_pos();
        for (auto it = own_watch_.begin(); it != own_watch_.end();) {
            const std::optional<Hash32> at = store_->best_at(it->second);
            if (!at || *at != it->first) {
                ++own_orphaned_;
                it = own_watch_.erase(it);
            } else if (it->second < base) {
                it = own_watch_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // The receipts this node holds pending that a carrier with room for more (fewer than R_MAX carried) did not carry
    // although the honest carried list at its parent holds them (E3, carried_list's predicate at the carrier's parent):
    // the origin bin open there, h(r) <= h(c) + Fresh, not placed on the parent's chain, the tip's branch passing the
    // S3b-4a walk from it (on the chain, or placed within J_0); never a receipt whose tip is the carrier's parent: it
    // competes for the carrier's own position, so the carrier could not carry it; never the carrier's own receipt, also
    // when a copy with its id holds another tip (a joined node does not run #12 for a tip below x1, D35)
    // (carried_omissions; S2.3 #14).
    std::uint64_t omissions_of(const AdmitResult& a) {
        const CarrierBodyV3& c = *a.carrier;
        if (c.carried.size() >= cfg_.p.r_max) return 0;
        if (a.store_placements.empty()) return 0;
        const Hash32& parent = c.own.side.tip;
        const LaneView pv = store_->view_at(parent);
        if (!pv.ok()) return 0;
        const std::uint64_t H = pv.record(pv.pos());
        const std::uint64_t h_c = a.store_placements.back().bin;  // the own body's origin bin
        const Hash32 own = receipt_id(c.own);
        std::vector<Hash32> carried;
        for (const ReceiptBodyV3& b : c.carried) carried.push_back(receipt_id(b));
        const AdmitEnv e = env();
        std::optional<OwnChain> chain;  // the walk from the parent, built at the first receipt that needs it
        std::optional<ClosureWalk> walk;
        std::vector<Hash32> known;
        for (const PendingReceipt* p : pending_.all()) {
            if (p->body.side.tip == parent) continue;  // competes for the carrier's own position
            if (p->id == own) continue;
            if (!open_at(H, p->h, cfg_.p.open_bins)) continue;
            if (!carried_upper_ok(p->h, h_c, cfg_.p.fresh_max)) continue;
            if (pv.placed_open(p->id)) continue;
            if (!walk) {
                chain.emplace(e, parent);
                walk.emplace(e, *chain);
            }
            const WalkResult w = walk->walk_tip(p->body.side.tip);
            if (w.v != WalkVerdict::OnChain && w.v != WalkVerdict::Placed) continue;  // Boundary, Closure, not held
            known.push_back(p->id);
        }
        return carried_omissions(carried, known);
    }

    // ---- E11: a switch by the journal, with the re-pend step ----
    struct SwitchResult {
        bool joiner = false;
        bool internal = false;  // a store write failed: poisoned
        std::uint64_t repended = 0;
        std::uint64_t lost = 0;
        std::uint64_t skipped = 0;  // not re-pended: P_r not held, or evicted at once (logs only)
    };

    SwitchResult switch_to_best(std::uint64_t peer) {
        SwitchResult out;
        const Hash32 new_tip = tree_->best().id;
        const Hash32 old_tip = store_->best_tip();
        const std::optional<Hash32> fork_id = tree_->fork_point(old_tip, new_tip);
        if (!fork_id) return out;
        const std::uint64_t fork = tree_->find(*fork_id)->pos;
        // one depth measure: the journal base; a joined node at or below its x1 (own_switch_path)
        if (deep_switch(fork)) {
            out.joiner = true;
            if (peer != kOwnPeer) offer(new_tip, peer, U128{});
            return out;
        }
        // the undone positions (the losing branch), oldest first
        std::vector<Hash32> undone;
        for (const CarrierNode* n = tree_->find(old_tip); n != nullptr && n->pos > fork; n = tree_->find(n->parent))
            undone.push_back(n->id);
        std::reverse(undone.begin(), undone.end());
        const std::uint64_t old_pos = store_->tip_pos();
        const ActivationRecord ar_before = *ar_;
        LaneBatch lane;
        NodeStore ns{*store_, faults_};
        if (ns.switch_best(new_tip, &lane) != SwitchVerdict::Switched) {
            poison(new_tip);
            out.internal = true;
            return out;
        }
        if (ar_->rewind(fork) == ArRewind::BelowJoinerSeed) {
            out.joiner = true;  // fail closed: no restore below the joiner's seed
            poison(new_tip);
            return out;
        }
        std::vector<Hash32> added_ids;  // the new branch (K_PSIDE rows leave with the switch)
        {
            std::vector<const CarrierNode*> added;
            for (const CarrierNode* n = tree_->find(new_tip); n != nullptr && n->pos > fork; n = tree_->find(n->parent))
                added.push_back(n);
            for (const CarrierNode* a : added) added_ids.push_back(a->id);
            for (auto it = added.rbegin(); it != added.rend(); ++it)
                if ((*it)->activation && !ar_->append(*(*it)->activation)) {
                    poison(new_tip);  // nothing committed
                    out.internal = true;
                    return out;
                }
        }
        if (PathbKv* kv = store_kv()) {
            LaneBatch b = switch_batch(cfg_.record_chain, head_, *tree_, *store_, *bodies_, fork, old_pos, ar_before, *ar_,
                                       std::move(lane));
            side_moves(b, cfg_.record_chain, *tree_, *store_, *bodies_, undone, added_ids);  // the abandoned branch kept
            if (!commit_lane_batch(*kv, b)) {
                poison(new_tip);
                out.internal = true;
                return out;
            }
        }
        ++generation_;
        // the re-pend step: each undone position ascending, its carried list then its own receipt
        const LaneView nv = store_->view_at(new_tip);
        const std::uint64_t H_new = nv.record(nv.pos());
        for (const Hash32& id : undone) {
            const CarrierBodyV3* b = bodies_->get(id);
            if (b == nullptr) continue;
            std::vector<const ReceiptBodyV3*> rs;
            for (const ReceiptBodyV3& r : b->carried) rs.push_back(&r);
            rs.push_back(&b->own);
            for (std::size_t k = 0; k < rs.size(); ++k) {
                const ReceiptBodyV3& r = *rs[k];
                const Hash32 rid = receipt_id(r);
                if (nv.placed_open(rid) || pending_.holds(rid)) continue;
                const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(r.blob.prev_id) : PrInfo{};
                if (pr.status != PrInfo::Status::Held) {
                    ++out.skipped;
                    continue;
                }
                const std::uint64_t h_r = pr.height + 1;
                if (!open_at(H_new, h_r, cfg_.p.open_bins)) {
                    ++out.lost;  // its origin bin is sealed on the new branch: lost
                    continue;
                }
                const CarrierNode* t = tree_->find(r.side.tip);
                // the verified body: no second RandomX; one the pending set evicts at once is not counted
                if (pending_.add(PendingReceipt{rid, r, h_r, t ? t->pos : 0, 0})) {
                    ++out.repended;
                    repended_out_.push_back(rid);  // relayed as FB_RECEIPTS v3 (take_repended)
                    repend_watch_[rid] = H_new;
                } else {
                    ++out.skipped;
                }
            }
        }
        if (joined_store()) reask_pending_ = true;  // E-72: the claimed leaves asked again at the new chain
        after_best_change();
        return out;
    }

    PathbNodeConfig cfg_;
    PathbNodeIo io_;
    // The node's state: its own (a full node: launched here or loaded) or, after a join, the adopted state's.
    std::optional<CarrierTree> own_tree_;
    std::optional<BinStore> own_store_;
    ActivationRecord own_ar_;
    CarrierBodies own_bodies_;
    HeaderIndex own_headers_;
    WindowCache own_windows_;
    KeyCache own_keys_{cfg_.key_cache_bytes};
    SwitchCounts switches_;
    std::map<Hash32, XmrKeyRef> own_refs_;
    std::map<std::uint64_t, CarrierHeader> own_prefix_;  // the headers below the tree's root (joined, pruned)
    CarrierTree* tree_ = nullptr;
    BinStore* store_ = nullptr;
    ActivationRecord* ar_ = nullptr;
    CarrierBodies* bodies_ = nullptr;
    HeaderIndex* headers_ = nullptr;
    WindowCache* windows_ = nullptr;
    KeyCache* keys_ = nullptr;
    std::map<Hash32, XmrKeyRef>* refs_ = nullptr;
    const ClaimView* claims_ = nullptr;  // the adopted state's claim view (nullptr: a full node)
    const std::map<std::uint64_t, CarrierHeader>* prefix_ = nullptr;  // the claimed prefix headers served
    AlarmSink alarm_;
    PendingSet pending_;
    DeferredCarriers deferred_;
    AbandonTimers<Req> timers_;
    BucketWindow window_;
    BucketServeBudget budget_;
    PathbKv* kv_ = nullptr;
    StoreHead head_;
    // The template gate's state: not caught up (K_NCU), not launched here.
    bool gate_applies() const noexcept { return not_caught_up_ && !cfg_.launch; }
    // The first round ends at its reply or at its request's P-53.
    void end_first_round() {
        if (!first_round_open_) return;
        first_round_open_ = false;
        first_round_ = false;
    }
    // The template gate after the first round (E-194): the header path delivers toward a tip this node does not
    // hold. A delivery is a frame answering one of the node's own requests that arrived within P-53: a body it asked
    // by FetchBodies (toward any unheld tip: its headers were verified and won when it was asked), or a page or a
    // side header whose verified headers win against the best tip and that brought a header the index did not hold
    // (toward that tip only). The hold belongs to the catch-up, not to one page. P-53 is non-service as E-150 reads
    // it: time counts from the frame's arrival in link order and leaves out the node's own processing (the node lock
    // held, the caller's busy total); a re-ask is no delivery.
    struct Delivery {
        Arrival at;
        bool live = false;  // within P-53 of `at`, by the last gate clock
    };
    bool delivery_hold() const {
        if (!gate_applies()) return false;
        const bool win = win_open();
        if (hp_page_.live && win) return true;
        for (const auto& [peer, d] : hp_body_)  // a body delivery: toward its server's HELLO tip, or the verified win
            if (d.live && (win || peer_tip_unheld(peer))) return true;
        return false;
    }
    bool peer_tip_unheld(std::uint64_t peer) const {
        const auto it = peers_.find(peer);
        return it != peers_.end() && !holds_tip(it->second.best_tip);
    }
    // The template gate at a store not caught up (F-D2 as amended; E-194 (v), (vi); E-196): it holds in the first
    // round, while the header path delivers, while R-CU-1's drain clause is unmet (frames in hand), and, once R-CU-1's
    // first conjunct is met (every HELLO catch-up ended by its done test or its reply's own decision, a completed
    // attempt kept, or an adoption), until K_NCU ends. Before K_NCU ends it opens only where a claim alone opens it: a
    // HELLO catch-up still open toward a tip the node does not hold, nothing delivered and nothing in hand.
    bool gate_holds() const {
        if (!gate_applies()) return false;
        if (first_round_open_ || delivery_hold()) return true;
        if (!drain_done()) return true;             // frames in hand
        if (ncu_due_ != NcuDue::None) return true;  // a kept attempt or an adoption, until K_NCU ends
        return !claim_open();                       // until K_NCU ends, but for a claim-only open catch-up
    }
    // A HELLO catch-up not ended (open, or handed to the joiner) toward a tip the node does not hold: the caller's
    // catch-ups (unset: a HELLO tail's tip not held).
    bool claim_open() const { return catchup_claim_ ? catchup_claim_() : hello_unheld(); }
    // The verified winning headers' tip: not held, still winning against the best tip.
    bool win_open() const {
        if (!hp_win_) return false;
        const CarrierNode& b = tree_->best();
        return tree_->find(hp_win_->id) == nullptr && fork_choice_prefers(*hp_win_, ChainTip{b.cum_work, b.id});
    }
    bool hello_unheld() const {
        for (const auto& [peer, t] : peers_)
            if (!holds_tip(t.best_tip)) return true;
        return false;
    }
    void note_delivery(Delivery& d, const Arrival& a) {
        if (!a.stamped || !gate_applies()) return;
        if (!d.live || a.ms >= d.at.ms) d.at = a;
        d.live = true;
        expire(d);
    }
    // A body this node asked by FetchBodies arrived in reply (solicited, not held, not refuted at its cheap rows).
    void note_body_arrival(const CarrierTicket& t) {
        if (!t.solicited || !t.arrival.stamped || !gate_applies() || bodies_asked_.empty()) return;
        if (t.admit.verdict == AdmitVerdict::Strike || t.admit.verdict == AdmitVerdict::Ban
            || t.admit.verdict == AdmitVerdict::Drop)
            return;
        Hash32 id = t.admit.id;
        if (id == Hash32{}) {
            CarrierBodyV3 c;
            if (t.frame.size() <= kFrameHeaderBytes
                || decode_carrier_body_v3(t.frame.data() + kFrameHeaderBytes, t.frame.size() - kFrameHeaderBytes,
                                          CarrierLimits{cfg_.buffers.receipt, cfg_.p.r_max}, c)
                           != WireError::None)
                return;
            id = receipt_id(c.own);
        }
        if (bodies_asked_.count(id) != 0 && tree_->find(id) == nullptr) note_delivery(hp_body_[t.peer], t.arrival);
    }
    // P-53 on the server's time: the time since the arrival less the node lock's busy time since then.
    void expire(Delivery& d) const {
        if (!d.live) return;
        const std::uint64_t elapsed = gate_now_ms_ > d.at.ms ? gate_now_ms_ - d.at.ms : 0;
        const std::uint64_t busy = gate_busy_ms_ > d.at.busy_ms ? gate_busy_ms_ - d.at.busy_ms : 0;
        if (elapsed > busy && elapsed - busy >= cfg_.abandon_timeout_s * 1000) d.live = false;
    }
    void reset_delivery() {
        hp_page_ = Delivery{};
        hp_body_.clear();
        hp_win_.reset();
    }
    // An open catch-up request (not retired) to any peer.
    bool catchup_request_open() const {
        for (const auto& [p, r] : header_req_)
            if (r.owner == HeaderOwner::CatchUp && !r.retired) return true;
        return false;
    }
    // The template gate's timers (P-53): an open first round with no catch-up request in flight ends; a delivery's
    // hold ends at P-53 on the server's time.
    void catchup_gate_tick(std::uint64_t now_s) {
        if (first_round_open_ && !catchup_request_open()) {
            if (first_round_s_ == 0) first_round_s_ = now_s;
            if (now_s >= first_round_s_ + cfg_.abandon_timeout_s) end_first_round();
        } else {
            first_round_s_ = 0;
        }
        gate_now_ms_ = std::max(gate_now_ms_, now_s * 1000);
        expire(hp_page_);
        for (auto it = hp_body_.begin(); it != hp_body_.end();) {
            expire(it->second);
            it = it->second.live ? std::next(it) : hp_body_.erase(it);
        }
        if (hp_win_ && !win_open()) hp_win_.reset();
    }

    bool started_empty_ = false;
    bool not_caught_up_ = false;          // K_NCU
    bool first_round_ = false;            // the first catch-up round after the start not run yet
    bool first_round_open_ = false;       // ... and in flight (opened by a HELLO tail whose tip is not held)
    std::uint64_t first_round_s_ = 0;     // since when it is open with no request in flight
    enum class NcuDue : std::uint8_t { None, Kept, Adopted };
    NcuDue ncu_due_ = NcuDue::None;       // a kept attempt or an adoption; K_NCU ends at its drain (E-193)
    std::function<bool()> inbound_idle_;  // the caller's inbound frames all judged (E-193)
    std::function<bool()> catchup_claim_;  // the caller's catch-ups: one not ended toward an unheld tip
    std::optional<ChainTip> hp_win_;      // headers this node verified that win (their tip and work)
    std::uint64_t hp_win_peer_ = 0;
    Delivery hp_page_;                    // the last page or side-header delivery (E-194 (v))
    std::map<std::uint64_t, Delivery> hp_body_;  // the last delivery of a body asked by FetchBodies, per server
    std::uint64_t gate_now_ms_ = 0;       // the gate clock: the caller's time (ms)
    std::uint64_t gate_busy_ms_ = 0;      // ... and the node lock's busy total then (ms)
    bool poisoned_ = false;
    StoreFaults faults_;
    std::uint64_t generation_ = 0;
    std::uint64_t verify_calls_ = 0;
    std::map<std::uint64_t, HelloTail> peers_;
    std::map<std::uint64_t, HeaderRequest> header_req_;
    std::map<Hash32, std::uint64_t> bodies_asked_;  // FetchBodies ids not placed yet: their last ask time (s)
    std::map<Hash32, std::uint64_t> parent_asked_;  // parent asks of ParentUnknown DEFERs: their last ask time (s)
    std::uint64_t parent_asks_ = 0;                 // parent asks sent
    std::uint64_t parent_reasks_ = 0;               // ... of them by reask_parents
    std::map<Hash32, std::uint64_t> reask_round_;   // reask_parents: asks of a missing parent sent past its sender
    std::uint64_t clock_s_ = 0;                     // the latest time given to tick or on_headers (s)
    std::set<std::uint64_t> hf_round_;              // links whose next catch-up request opens a round (first HELLO)
    std::uint64_t hf_placed_s_ = 0;                 // the last placement of a body a header page asked (s)
    std::map<std::pair<std::uint64_t, Hash32>, BucketsAssembly> assemblies_;
    std::set<std::pair<std::uint64_t, Hash32>> abandoned_;
    std::set<std::pair<std::uint64_t, Hash32>> closed_;
    JoinServeHold hold_;
    std::set<std::uint64_t> hold_conns_;
    std::deque<ParkedFrame> release_q_;
    std::vector<ParkedFrame> rx_failed_;  // released carriers whose admission failed with a RandomX failure
    std::vector<PlacedRelease> placed_released_;  // unsolicited released carriers placed by a drain (P-15)
    std::vector<DrainedResult> drained_;          // the outcomes of the drained and walk-bound carriers (take_drained)
    std::vector<Hash32> repended_out_;  // re-pended by a switch, not yet taken for the relay (take_repended)
    std::map<Hash32, std::uint64_t> repend_watch_;  // re-pended by a switch and still pending (at most the pending cap)
                                                    // -> the record at the new tip at that switch
    struct AmountKey {
        std::uint64_t bin = 0;  // the origin bin
        std::uint64_t first = 0;
        bool multi = false;     // a second distinct R seen
    };
    std::map<std::pair<Hash32, Hash32>, AmountKey> amounts_;  // (tip, P_r) -> its admitted R (logs only)
    AmountCounts amount_counts_;
    bool amount_seen_ = false;
    std::map<Hash32, std::uint64_t> own_watch_;  // own carriers on the best chain at or above the journal base -> pos
    std::uint64_t own_carriers_ = 0;
    std::uint64_t own_orphaned_ = 0;
    WindowFlagCounts win_flags_;
    mutable std::uint64_t open_state_calls_ = 0;
    StatusSample sample_;                    // the status line's open state and liveness (status_sample)
    std::optional<std::uint64_t> sample_s_;  // when they were computed
    std::map<std::uint64_t, U128> jbelow_;      // a joined node: the bound work its prunes moved below the floor
    std::set<std::uint64_t> jbelow_unwritten_;  // its heights not yet in the store
    std::uint64_t jbelow_done_ = 0;             // the positions below this one are in jbelow_
    // the joiner (E15): its inputs, the queue and the adopted state, the full node's own chain as A, one link per
    // Path B peer over the relay's transport, the E-72 re-ask's buckets
    JoinInputs join_in_;
    std::optional<Joiner> joiner_;
    FullNodeA own_chain_{*this};
    ResumedClaims resumed_{*this};
    std::optional<std::uint64_t> resumed_x1_;           // a joined store after a restart: its x1 (K_BLO - 1)
    std::map<std::uint64_t, AtHeader> resumed_claimed_;  // and its claimed leaves (K_BCLAIM)
    JoinTransport* transport_ = nullptr;
    std::map<std::uint64_t, std::shared_ptr<PathbJoinLink>> links_;
    std::set<std::uint64_t> left_;  // servers that disconnected while an attempt ran
    JoinedState* joined_ = nullptr;
    bool load_failed_ = false;
    bool reask_pending_ = false;
    bool attempting_ = false;
    std::set<std::uint64_t> mismatched_;  // claimed bins a claim-leaf mismatch entered (E-72)
    JoinBuckets reask_jb_{cfg_.identity.height + 1, cfg_.p.open_bins, cfg_.bucket_policy.frame_bytes,
                          cfg_.identity.chain_id};
    bool draining_ = false;
    std::uint64_t settle_depth_ = 0;
    std::uint64_t max_settle_depth_ = 0;
    struct MemoKey {
        Hash32 id{};
        std::uint64_t d = 0;
        Hash32 seed{};
        friend bool operator<(const MemoKey& a, const MemoKey& b) { return std::tie(a.id, a.d, a.seed) < std::tie(b.id, b.d, b.seed); }
    };
    std::map<MemoKey, bool> memo_;
    std::deque<MemoKey> memo_order_;
    std::optional<OwnPow> own_pow_;
};

}  // namespace c2pool::xmr::pathb
