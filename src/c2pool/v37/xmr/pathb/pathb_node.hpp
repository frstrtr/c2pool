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
//   join              the joiner path: the hookup is a later commit
//
// Header-only. Not included by any running component; included by its KATs only.
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
#include "impl/xmr/pathb/pathb_join.hpp"  // admit_receipt_from (and the joiner, wired last)
#include "impl/xmr/pathb/pathb_pool_identity.hpp"
#include "impl/xmr/pathb/pathb_relay_wire.hpp"
#include "impl/xmr/pathb/pathb_store.hpp"

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
    XmrKeyRef author;                       // K16 author reference
    std::uint16_t give_author_bp = kDonationBp;
    std::uint16_t owner_fee_bp = 0;         // node-owner fee B (p)
    std::optional<XmrKeyRef> owner;         // present iff owner_fee_bp > 0
    bool launch = false;                    // --pathb-launch
    bool penalty_fill = false;              // --pathb-penalty-fill
    bool vote_no = false;                   // --vote no
    std::uint32_t record_chain = 0;         // the store's record chain id
};

// A candidate transaction of the template (the source's order): its hash,
// weight and fee read from its own bytes.
struct TemplateTx {
    Hash32 hash{};
    std::uint64_t weight = 0;
    std::uint64_t fee = 0;
};

struct PathbNodeIo {
    const FollowerBranchView* monero = nullptr;
    std::function<PrInfo(const Hash32& p_r)> resolve_pr;
    std::function<std::optional<Hash32>(const Hash32& p_r)> seed_of;
    // RandomX of a hashing blob at d with the seed (the verify workers)
    std::function<bool(const HashingBlob&, std::uint64_t d, const Hash32& seed)> verify;
    // the follower's main chain: its tip height and the block at a height
    std::function<std::optional<std::uint64_t>()> monero_tip;
    std::function<std::optional<Hash32>(std::uint64_t height)> monero_block_at;
    // the template's candidate transactions, in the source's priority order
    std::function<std::vector<TemplateTx>()> tx_source;
    // a frame to one peer; a frame to every peer but `except` (relay policy)
    std::function<void(std::uint64_t peer, const std::vector<std::uint8_t>& frame)> send;
    std::function<void(const std::vector<std::uint8_t>& frame, std::optional<std::uint64_t> except)> flood;
};

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

enum class TemplateStatus : std::uint8_t {
    Ok,
    NoPathbPeer,  // an empty store with no Path B peer and no --pathb-launch
    Poisoned,     // the store failed a write: no template until the joiner path at the next start
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
    PathbNode(const PathbNodeConfig& cfg, PathbNodeIo io, PathbKv* kv = nullptr)
        : cfg_(cfg),
          io_(std::move(io)),
          tree_(cfg.p, cfg.identity.pool_id, cfg.identity.height + 1, cfg.T, {}, cfg.rp, cfg.rules_g),
          store_(cfg.p, cfg.journal_depth, cfg.identity.pool_id, cfg.identity.height + 1, cfg.record_chain),
          pending_(cfg.pending_cap ? cfg.pending_cap : relay_horizons(cfg.p).pending_cap),
          deferred_(cfg.waiting_cap ? cfg.waiting_cap : waiting_cap_default()),
          timers_(cfg.abandon_timeout_s),
          window_(cfg.bucket_policy),
          budget_(cfg.bucket_policy),
          kv_(kv),
          started_empty_(true) {
        head_ = head_of(cfg);
        if (kv_ != nullptr) {
            // into an empty store: every key of the store's prefixes deleted in the same batch
            LaneBatch b;
            const bool cleared = clear_store_batch(*kv_, cfg_.record_chain, b);
            const LaneBatch g = genesis_batch(cfg_.record_chain, head_, tree_, store_);
            b.ops.insert(b.ops.end(), g.ops.begin(), g.ops.end());
            if (!cleared || !commit_lane_batch(*kv_, b)) poison(tree_.genesis().id);
        }
    }

    // A node from its loaded store (pathb_load); a load failure is the caller's
    // joiner path.
    PathbNode(const PathbNodeConfig& cfg, PathbNodeIo io, LoadedState loaded, PathbKv* kv)
        : cfg_(cfg),
          io_(std::move(io)),
          tree_(std::move(loaded.tree)),
          store_(std::move(loaded.store)),
          ar_(std::move(loaded.ar)),
          bodies_(std::move(loaded.bodies)),
          pending_(cfg.pending_cap ? cfg.pending_cap : relay_horizons(cfg.p).pending_cap),
          deferred_(cfg.waiting_cap ? cfg.waiting_cap : waiting_cap_default()),
          timers_(cfg.abandon_timeout_s),
          window_(cfg.bucket_policy),
          budget_(cfg.bucket_policy),
          kv_(kv),
          started_empty_(false) {
        head_ = loaded.head;
        refs_ = std::move(loaded.refs);
    }

    PathbNode(const PathbNode&) = delete;
    PathbNode& operator=(const PathbNode&) = delete;

    // ---- state ----
    const CarrierTree& tree() const noexcept { return tree_; }
    const BinStore& store() const noexcept { return store_; }
    const ActivationRecord& ar() const noexcept { return ar_; }
    const CarrierBodies& bodies() const noexcept { return bodies_; }
    const HeaderIndex& headers() const noexcept { return headers_; }
    const PendingSet& pending() const noexcept { return pending_; }
    const DeferredCarriers& deferred() const noexcept { return deferred_; }
    const AlarmSink& alarms() const noexcept { return alarm_; }
    const PathbNodeConfig& config() const noexcept { return cfg_; }
    bool poisoned() const noexcept { return poisoned_; }
    std::uint64_t verify_calls() const noexcept { return verify_calls_; }
    std::uint64_t best_changes() const noexcept { return generation_; }
    StoreFaults& faults() noexcept { return faults_; }
    WindowCache& windows() noexcept { return windows_; }

    // ---- HELLO (E10) ----
    PathbHello our_hello(std::uint64_t node_nonce, std::uint16_t listen_port) const {
        PathbHello h;
        h.network = static_cast<std::uint8_t>(cfg_.identity.network);
        h.chain_id = cfg_.identity.chain_id;
        h.pool_id = cfg_.identity.pool_id;
        h.node_nonce = node_nonce;
        h.listen_port = listen_port;
        const CarrierNode& b = tree_.best();
        const LaneView v = store_.view_at(b.id);
        // the rules list of the node's epoch_cur (the compiled table's; epoch 0: the network's list)
        PathbLaneRules rules = epoch0_lane_rules(cfg_.identity.network);
        for (const CompiledEpoch& c : cfg_.T.compiled)
            if (c.epoch_no == b.rs.epoch_cur && c.rules) rules = *c.rules;
        h.tail = make_hello_tail(rules, b.cum_work, b.id, b.h, v.ok() ? v.leaf_count() : 0);
        h.trailer = hello_trailer(cfg_.rp, b.rs, b.pos + 1, cfg_.T);
        return h;
    }

    // The caller (the relay node, S4w-bc) runs what follows an accepted HELLO:
    // headers first when the peer's best_cum_work wins, the pending re-offer.
    HelloCheck on_hello(std::uint64_t peer, std::span<const std::uint8_t> frame, const PathbHello& ours) {
        PathbHello theirs;
        const HelloCheck c = pathb_hello_receive(
                ours, frame,
                [this](const Hash32& tip) -> std::optional<std::uint64_t> {
                    // a best tip bound at this node: a carrier it placed (its own #9 matched)
                    const CarrierNode* n = tree_.find(tip);
                    if (n == nullptr) return std::nullopt;
                    return n->H;
                },
                store_.b0(), cfg_.p.open_bins, &theirs);
        if (c.verdict == HelloVerdict::Accept) peers_[peer] = theirs.tail;
        return c;
    }
    bool has_pathb_peer() const noexcept { return !peers_.empty(); }
    void disconnect(std::uint64_t peer) {
        peers_.erase(peer);
        headers_.release_peer(peer);
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
        for (auto* keys : {&closed_, &abandoned_})
            for (auto it = keys->begin(); it != keys->end();) {
                if (it->first == peer)
                    it = keys->erase(it);
                else
                    ++it;
            }
    }

    // ---- FC_CARRIER (E7) ----
    // The cheap rows and RandomX (on the verify workers), then the placement.
    struct CarrierTicket {
        std::uint64_t peer = 0;
        std::vector<std::uint8_t> frame;
        AdmitResult admit;
        std::uint64_t generation = 0;
        bool relayed = true;
    };

    CarrierTicket begin_carrier(std::uint64_t peer, std::span<const std::uint8_t> frame, bool relayed = true) {
        CarrierTicket t;
        t.peer = peer;
        t.relayed = relayed;
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
        if (t.generation != generation_ && admitted(t.admit))
            t.admit = admit_frame_from(env(), t.peer, t.frame, CarrierRole::Frame);
        return settle_carrier(t.peer, t.frame, t.admit, t.relayed);
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
        const CarrierNode& b = tree_.best();
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
        if (started_empty_ && !cfg_.launch && peers_.empty() && tree_.best().pos == 0)
            return status(t, TemplateStatus::NoPathbPeer);
        const CarrierNode& tip = tree_.best();
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
        const std::optional<std::uint64_t> d = tree_.next_difficulty(tip.id);
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
        std::vector<TxCandidate> tc;
        std::uint64_t f_all = 0;
        for (const TemplateTx& c : cands) {
            tc.push_back(TxCandidate{c.weight, c.fee});
            f_all = f_all > UINT64_MAX - c.fee ? UINT64_MAX : f_all + c.fee;
        }
        const Window& w = *t.window.window;
        const std::size_t n_out = w.empty_finder_only ? 1 : w.weight.size();
        const std::uint64_t r_up = t.base > UINT64_MAX - f_all ? UINT64_MAX : t.base + f_all;
        const std::uint64_t cw_up = coinbase_weight_hf16(t.h, std::vector<std::uint64_t>(n_out, r_up));
        const std::uint64_t h = t.h;
        const CoinbaseSize cw = [&w, h](std::uint64_t R) -> std::optional<std::uint64_t> {
            std::vector<std::uint64_t> a;
            if (w.empty_finder_only) {
                a.push_back(R);
            } else {
                for (const SplitOutput& o : hf16_outputs(R, w)) a.push_back(o.amount);
                if (a.empty()) return std::nullopt;
            }
            return coinbase_weight_hf16(h, a);
        };
        const TxSelection sel = cfg_.penalty_fill ? select_penalty_fill(tc, t.base, t.median, t.hf, cw_up, cw)
                                                  : select_no_penalty(tc, t.base, t.median, cw_up, cw);
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
        const CarrierNode* tip = tree_.find(t.tip);
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
        const EpochAt ea = epoch_at(cfg_.rp, cfg_.T, std::optional<RatchetState>(tip->rs), ar_, tip->pos, tip->rs,
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
        const std::optional<Hash32> rr = tree_.next_receipts_root(t.tip, ids);
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
        refs_[r.side.payee] = s.payee;
        // the canonical miner tx of the receipt (the function every node checks it with)
        const CanonicalTx ct = canonical_miner_tx(r, window_at(t.window), t.tip, t.p_r, t.h, t.hf, keys_, ref_lookup(),
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
        NodeEventResult out;
        const CarrierNode* tip = tree_.find(job.tip);
        if (tip != nullptr && job.tip == tree_.best().id && job.h >= tip->H) {
            CarrierBodyV3 c;
            c.own = r;
            c.carried = job.carried;
            const std::optional<std::vector<std::uint8_t>> f = encode_fc_carrier(cfg_.identity.chain_id, c, cfg_.p.r_max);
            if (f) out = complete_carrier(begin_carrier(kOwnPeer, *f, false));
        } else {
            std::vector<std::uint8_t> body;
            encode_receipt_body_v3(r, body);
            out = on_receipt_body(kOwnPeer, body);
        }
        own_pow_.reset();
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
            const std::optional<CarrierBodyV3> b = serve_carrier(tree_, bodies_, id, q.want_bodies);
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
                hold_.first(peer, now_s, store_.tip_pos(), serve_floors_now());
                hold_conns_.insert(peer);
            } else {
                (void)join_request(peer, now_s, q.stop);
            }
            r = joiner_page(q.stop, q.max);
        } else if (const CarrierNode* from = tree_.find(q.from)) {
            r.first_pos = from->pos + 1;
            const std::uint64_t cap = std::min<std::uint64_t>({q.max, cfg_.journal_depth, headers_frame_fit()});
            r.headers = serve_headers(tree_, store_, bodies_, headers_, q.from, q.stop, cap);
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
        if (const CarrierNode* at = tree_.find(q.at); at != nullptr && at->pos > 0)
            if (const CarrierNode* par = tree_.find(at->parent)) s_parent = encode_ratchet_state(par->rs);
        out.frames = serve_buckets(store_, q, s_parent, cfg_.bucket_policy.frame_bytes, max_bytes);
        std::uint64_t bytes = 0;
        for (const std::vector<std::uint8_t>& f : out.frames) bytes += f.size();
        budget_.sent(peer, bytes, now_s);
        budget_.done(peer);
        return out;
    }

    // ---- the serving side of a join (P-51 as corrected; join_serve_floors, JoinServeHold) ----
    // The floors at the best tip ({0, 0} while the span at the tip is the young chain).
    JoinServeFloors serve_floors_now() const {
        const auto rec = [&](std::uint64_t x) -> std::optional<std::uint64_t> {
            const std::optional<Hash32> id = store_.best_at(x);
            const CarrierNode* n = id ? tree_.find(*id) : nullptr;
            if (n == nullptr) return std::nullopt;
            return n->H;
        };
        return join_serve_floors(cfg_.p, store_.tip_pos(), rec, store_.b0());
    }
    // The floors that apply to a request of `peer` for `item` (an open hold's while its attempt continues).
    JoinServeFloors join_request(std::uint64_t peer, std::uint64_t now_s, const Hash32& item) {
        const CarrierNode* n = tree_.find(item);
        const JoinServeFloors f = hold_.request(peer, now_s, item, n ? n->pos : UINT64_MAX, serve_floors_now(),
                                                cfg_.abandon_timeout_s);
        if (!hold_.holding(peer)) hold_conns_.erase(peer);
        return f;
    }
    bool join_holding(std::uint64_t peer) const { return hold_.holding(peer); }
    // The lowest floors the best tip and the open holds keep (the prune step keeps from these; TODO(S4w-bc): the
    // prune step and the P-51 flags, none below the node's own horizon).
    JoinServeFloors retention_floors(std::uint64_t now_s) {
        const JoinServeFloors cur = serve_floors_now();
        JoinServeFloors out = cur;
        for (auto it = hold_conns_.begin(); it != hold_conns_.end();) {
            // an item above every L (zero id): reads the hold, never continues it
            const JoinServeFloors f = hold_.request(*it, now_s, Hash32{}, UINT64_MAX, cur, cfg_.abandon_timeout_s);
            if (!hold_.holding(*it)) {
                it = hold_conns_.erase(it);
                continue;
            }
            out.bodies = std::min(out.bodies, f.bodies);
            out.headers = std::min(out.headers, f.headers);
            ++it;
        }
        return out;
    }

    // ---- headers first (E11; the header path) ----
    // A request FC_GETHEADERS(from, stop, max) to `peer` (one in flight per
    // peer; its continuations go to the same peer). `from` is held: the fork.
    bool request_headers(std::uint64_t peer, const Hash32& from, const Hash32& stop, std::uint16_t max,
                         std::uint64_t now_s) {
        if (poisoned_ || header_req_.count(peer) != 0 || tree_.find(from) == nullptr) return false;
        HeaderRequest r;
        r.fork = from;
        r.from = from;
        r.stop = stop;
        r.max = max;
        header_req_[peer] = std::move(r);
        timers_.sent(Req{peer, ReqKind::Headers, Hash32{}}, now_s);
        send(peer, encode_fc_getheaders(GetHeaders{cfg_.identity.chain_id, from, stop, max}));
        return true;
    }

    struct HeadersOutcome {
        enum class Kind : std::uint8_t {
            Unsolicited,  // no request in flight: DROP
            OverBuffer,   // above the FC_HEADERS frame buffer: DROP (no token; the request stays open)
            Undecodable,  // the frame does not decode: refuse + 1 strike (the request ends)
            NodeInternal, // the store poisoned: nothing judged
            Ban,          // a header failed its cheap rows or its PoW at d, or a P_r served bad: BAN the server
            Keep,         // indexed, not heavier
            Continue,     // a full page: the next page asked of the same server
            FetchBodies,  // heavier: FC_GETCARRIER of its bodies (same peer)
            JoinerPath,   // heavier, its fork below the journal base: the joiner path, no body fetched
            Defer,        // a P_r not resolved yet
        } kind = Kind::Unsolicited;
        std::size_t indexed = 0;
        std::uint64_t fork_pos = 0;
        std::vector<Hash32> ids;
    };

    HeadersOutcome on_headers(std::uint64_t peer, std::span<const std::uint8_t> frame, std::uint64_t now_s) {
        HeadersOutcome out;
        if (poisoned_) {
            out.kind = HeadersOutcome::Kind::NodeInternal;
            return out;
        }
        const auto it = header_req_.find(peer);
        if (it == header_req_.end()) return out;
        if (frame.size() > frame_bytes_headers()) {
            out.kind = HeadersOutcome::Kind::OverBuffer;
            return out;
        }
        HeaderRequest req = std::move(it->second);
        header_req_.erase(it);
        timers_.done(Req{peer, ReqKind::Headers, Hash32{}});
        HeadersReply rep;
        if (!decode_fc_headers(frame, cfg_.identity.chain_id, frame_bytes_headers(), cfg_.p, rep).ok()) {
            out.kind = HeadersOutcome::Kind::Undecodable;
            headers_.release_peer(peer);
            return out;
        }
        // positions follow the hash links from the held fork (first_pos is a claim the links decide)
        const CarrierNode* fork = tree_.find(req.fork);
        if (fork == nullptr) {
            out.kind = HeadersOutcome::Kind::Keep;
            return out;
        }
        const std::size_t before = req.got.size();
        for (const CarrierHeader& h : rep.headers) {
            const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(h.own.blob.prev_id) : PrInfo{};
            if (pr.status == PrInfo::Status::Missing) {
                out.kind = HeadersOutcome::Kind::Defer;
                return out;
            }
            if (pr.status == PrInfo::Status::BadServed) {
                out.kind = HeadersOutcome::Kind::Ban;  // its earlier variants released as on every BAN
                headers_.release_peer(peer);
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
        const auto pow_ok = [&](const CarrierAnnounce&, std::uint64_t d) {
            const CarrierHeader& h = req.got[k++];
            if (h.own.side.t_origin != d) return false;
            const PrInfo pr = io_.resolve_pr(h.own.blob.prev_id);
            if (header_fields_verdict(header_fields(h.own, encoded_length(h.own), pr.in))) return false;
            const std::optional<Hash32> seed = io_.seed_of ? io_.seed_of(h.own.blob.prev_id) : std::nullopt;
            return seed.has_value() && verify_memo(h.own.blob, d, *seed);
        };
        const std::optional<std::vector<SideHeader>> side = tree_.check_side_headers(req.fork, ann, pow_ok);
        if (!side) {
            out.kind = HeadersOutcome::Kind::Keep;
            return out;
        }
        for (const SideHeader& sh : *side) {
            if (sh.check != HeaderCheck::Passed) {
                out.kind = HeadersOutcome::Kind::Ban;  // BAN the server; no variant of it indexed, its earlier ones released
                headers_.release_peer(peer);
                return out;
            }
            out.ids.push_back(sh.id);
        }
        // N-7: a variant enters the index only after the cheap rows and the PoW at d of the whole reply passed on this
        // path (path_ok passed explicitly)
        for (std::size_t i = before; i < side->size(); ++i) {
            headers_.add(peer, req.got[i], req.heights[i], /*path_ok=*/true);
            ++out.indexed;
        }
        deferred_.touch(out.ids);
        const CarrierNode& b = tree_.best();
        const SideBranchDecision dec =
                decide_side_branch(b.cum_work, b.id, fork->cum_work, *side, 0, std::numeric_limits<std::uint64_t>::max());
        out.fork_pos = fork->pos;
        if (dec.action == SideBranchAction::FetchBodies) {
            // one depth measure: the journal base (never fork_depth against J)
            if (fork->pos < store_.base_pos()) {
                out.kind = HeadersOutcome::Kind::JoinerPath;
                return out;
            }
            out.kind = HeadersOutcome::Kind::FetchBodies;
            const std::size_t per = static_cast<std::size_t>(max_receipts_per_frame(cfg_.p.r_max));
            for (std::size_t i = 0; i < out.ids.size(); i += per) {
                GetCarrier q;
                q.chain_id = cfg_.identity.chain_id;
                q.want_bodies = true;
                for (std::size_t j = i; j < out.ids.size() && q.ids.size() < per; ++j) q.ids.push_back(out.ids[j]);
                if (const std::optional<std::vector<std::uint8_t>> f = encode_fc_getcarrier(q, cfg_.p)) send(peer, *f);
            }
            return out;
        }
        // a page that ends before `stop`: the next page from its last header, at the same server, while the request's
        // max is not reached (the branch the request accumulates is at most max headers)
        if (!rep.headers.empty() && out.ids.back() != req.stop && req.got.size() < req.max) {
            out.kind = HeadersOutcome::Kind::Continue;
            req.from = out.ids.back();
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
        assemblies_.emplace(key, BucketsAssembly(q, store_.b0(), cfg_.p.open_bins, cfg_.bucket_policy.frame_bytes));
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
        for (const auto& [bin, sb] : it->second.bins()) (void)store_.restore_bucket(sb.bucket, sb.refs);
        if (it->second.complete()) {
            timers_.done(Req{peer, ReqKind::Buckets, at});
            assemblies_.erase(it);
        }
        return out;
    }
    std::size_t open_assemblies() const noexcept { return assemblies_.size(); }

    // ---- timers ----
    // The requests with no next frame within P-53: non-service (no alarm, no
    // token, no exclusion); a bucket request's server is abandoned for that at.
    std::size_t tick(std::uint64_t now_s) {
        std::size_t n = 0;
        for (const Req& r : timers_.expired(now_s)) {
            ++n;
            if (r.kind == ReqKind::Headers) {
                header_req_.erase(r.peer);
                continue;
            }
            const auto key = std::make_pair(r.peer, r.at);
            if (assemblies_.erase(key) != 0) abandoned_.insert(key);  // its later frames DROP (no assembly)
            closed_.insert(key);
        }
        return n;
    }

    bool abandoned(std::uint64_t peer, const Hash32& at) const { return abandoned_.count(std::make_pair(peer, at)) != 0; }

    // ---- digests (status line, KATs) ----
    std::string lane_digest() {
        std::string s;
        const CarrierNode& b = tree_.best();
        s += hex32(b.id) + ":" + std::to_string(b.pos) + ":" + std::to_string(b.d) + ":" + std::to_string(b.cum_work.lo) + ";";
        const RatchetStateBytes rs = encode_ratchet_state(b.rs);
        s += pid_detail::hex(rs.data(), rs.size()) + ";";
        for (const ActivationRow& a : ar_.rows()) s += std::to_string(a.epoch) + "@" + std::to_string(a.h_act) + ",";
        const BmmrHead h = store_.head();
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
        std::vector<CarrierHeader> got;      // the branch's headers so far, oldest first
        std::vector<std::uint64_t> heights;  // h(y) of each
    };
    struct OwnPow {
        Hash32 id{};
        Hash32 pow_hash{};
    };

    static std::string hex32(const Hash32& h) { return pid_detail::hex(h); }
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
    void flood(const std::vector<std::uint8_t>& f, std::optional<std::uint64_t> except) {
        if (io_.flood) io_.flood(f, except);
    }

    RefLookup ref_lookup() {
        return [this](const Hash32& id) -> std::optional<XmrKeyRef> {
            const auto it = refs_.find(id);
            if (it == refs_.end()) return std::nullopt;
            return it->second;
        };
    }

    void learn_refs(const ReceiptBodyV3& r) {
        refs_[r.side.payee] = r.payee;
        if (r.owner) refs_[r.side.owner] = *r.owner;
    }

    // RandomX through the verified-body memo (a body is hashed once); the
    // node's own share returns its own hash's result.
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
        const bool ok = io_.verify && io_.verify(blob, d, seed);
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
        return AdmitEnv{tree_,
                        store_,
                        headers_,
                        bodies_,
                        *io_.monero,
                        windows_,
                        keys_,
                        ref_lookup(),
                        cfg_.author,
                        cfg_.p,
                        cfg_.rp,
                        cfg_.T,
                        ar_,
                        cfg_.identity.pool_id,
                        admit_j0(cfg_.p),
                        cfg_.buffers,
                        cfg_.genesis_prev,
                        io_.resolve_pr,
                        io_.seed_of,
                        [this](const HashingBlob& b, std::uint64_t d, const Hash32& s) { return verify_memo(b, d, s); },
                        alarm_,
                        nullptr};
    }

    std::optional<Hash32> prev_of(const Hash32& tip) const {
        if (tip == tree_.genesis().id && tree_.genesis().pos == 0) return cfg_.genesis_prev;
        const CarrierBodyV3* b = bodies_.get(tip);
        if (b == nullptr) return std::nullopt;
        return b->own.blob.prev_id;
    }

    TipWindow window_of(const Hash32& tip, const Hash32& p_t, std::uint8_t v) {
        const Hash32 author_id = key_ref_identity(cfg_.author);
        return windows_.get(tip, v, [&] { return evaluate_window_at(store_, tip, p_t, *io_.monero, v, author_id); });
    }

    BucketsAnchor anchor_of(const Hash32& at) const {
        BucketsAnchor a;
        const CarrierNode* n = tree_.find(at);
        const CarrierBodyV3* b = bodies_.get(at);
        if (n == nullptr || b == nullptr || n->pos == 0) return a;
        const CarrierNode* par = tree_.find(n->parent);
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
        if (kv_ != nullptr) (void)commit_lane_batch(*kv_, poison_batch(cfg_.record_chain));
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
    HeadersReply joiner_page(const Hash32& stop, std::uint64_t max) const {
        HeadersReply r{cfg_.identity.chain_id, 0, {}};
        const Hash32 x = stop == Hash32{} ? tree_.best().id : stop;
        std::vector<CarrierHeader> above;  // x's bound variants above the placed carriers, newest first
        Hash32 y = x;
        for (std::size_t guard = 0; tree_.find(y) == nullptr; ++guard) {
            const std::optional<Hash32> bd = headers_.bound_digest(y);
            const HeaderVariant* v = bd ? headers_.variant(y, *bd) : nullptr;
            if (v == nullptr || guard > headers_.size()) return r;  // x is not bound at this node
            above.push_back(v->header);
            y = v->header.own.side.tip;
        }
        const CarrierNode* n = tree_.find(y);
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
        for (const CarrierNode* c = n; more && c != nullptr && c->pos > 0; c = tree_.find(c->parent)) {
            const CarrierBodyV3* b = bodies_.get(c->id);
            if (b == nullptr || !take(header_of(*b))) break;  // not held here, or the frame is full
        }
        if (page.empty()) return r;
        r.first_pos = top - page.size() + 1;
        r.headers.assign(page.rbegin(), page.rend());
        return r;
    }

    // ---- E3: the carried list ----
    // Every pending receipt a carrier at x may carry: its origin bin open on the
    // best chain at x - 1, h(r) <= h(c) + Fresh, not placed on the best chain,
    // and its tip's branch judged by the S3b-4a walk (the ruling-40 boundary
    // and the closure leave it out); the first R_MAX in the canonical order.
    std::vector<ReceiptBodyV3> carried_list(std::uint64_t x, std::uint64_t h_c) {
        std::vector<ReceiptBodyV3> out;
        const CarrierNode& best = tree_.best();
        const LaneView bv = store_.view_at(best.id);
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
            const CarrierNode* t = tree_.find(r.side.tip);
            PendingReceipt pr{out.admit.id, r, out.admit.store_placements.empty() ? 0 : out.admit.store_placements[0].bin,
                              t ? t->pos : 0, 0};
            pending_.add(std::move(pr));
            out.action = NodeAction::Pending;
            std::vector<ReceiptBodyV3> one{r};
            if (const std::optional<std::vector<std::uint8_t>> f = encode_fb_receipts(cfg_.identity.chain_id, one, cfg_.p))
                flood(*f, peer == kOwnPeer ? std::nullopt : std::optional<std::uint64_t>(peer));
            return out;
        }
        out.action = out.admit.verdict == AdmitVerdict::Defer ? NodeAction::Parked : NodeAction::Verdict;
        return out;
    }

    // ---- E7: the placement and what follows it ----
    NodeEventResult settle_carrier(std::uint64_t peer, const std::vector<std::uint8_t>& frame, const AdmitResult& r,
                                   bool relayed) {
        ++settle_depth_;
        max_settle_depth_ = std::max(max_settle_depth_, settle_depth_);
        NodeEventResult out = settle_once(peer, frame, r, relayed);
        --settle_depth_;
        drain_released();
        return out;
    }

    // The carriers released by a placement wait in a queue the outermost event
    // drains (one level of placement at a time, whatever the parked chain's length).
    void drain_released() {
        if (draining_ || settle_depth_ != 0) return;
        draining_ = true;
        while (!release_q_.empty() && !poisoned_) {
            ParkedFrame f = std::move(release_q_.front());
            release_q_.pop_front();
            (void)on_carrier(f.peer, f.frame);
        }
        release_q_.clear();
        draining_ = false;
    }

    NodeEventResult settle_once(std::uint64_t peer, const std::vector<std::uint8_t>& frame, const AdmitResult& r,
                                bool relayed) {
        NodeEventResult out;
        out.admit = r;
        if (r.verdict == AdmitVerdict::Defer) {
            out.action = NodeAction::Parked;
            park(peer, frame, r);
            return out;
        }
        if (r.verdict != AdmitVerdict::AdmitCarrier) {
            out.action = r.verdict == AdmitVerdict::AdmitPending ? NodeAction::Pending : NodeAction::Verdict;
            return out;
        }
        for (const ReceiptBodyV3& b : r.carrier->carried) learn_refs(b);
        learn_refs(r.carrier->own);
        NodeStore ns{store_, faults_};
        WriteResult w = place_admitted(tree_, ns, ar_, bodies_, r, &alarm_);
        out.write = w.outcome;
        switch (w.outcome) {
            case WriteOutcome::NodeInternal:
                // a store write failure of 3.3: the store poisoned, templates stop, the joiner path at the next start
                poison(r.id);
                out.action = NodeAction::NodeInternal;
                return out;
            case WriteOutcome::Duplicate: out.action = NodeAction::Verdict; return out;
            case WriteOutcome::SideBranch: out.action = NodeAction::SideBranch; break;
            case WriteOutcome::Extended: {
                out.action = NodeAction::Placed;
                ++generation_;
                if (kv_ != nullptr) {
                    const LaneBatch b = extension_batch(cfg_.record_chain, head_, tree_, store_, bodies_, r.id,
                                                        std::move(w.batch), w.ar_row);
                    if (!commit_lane_batch(*kv_, b)) {
                        poison(r.id);
                        out.action = NodeAction::NodeInternal;
                        return out;
                    }
                }
                after_best_change();
                break;
            }
            case WriteOutcome::SwitchToCaller: {
                const SwitchResult sr = switch_to_best();
                out.action = sr.joiner ? NodeAction::JoinerPath
                                       : (sr.internal ? NodeAction::NodeInternal : NodeAction::Switched);
                out.repended = sr.repended;
                out.lost = sr.lost;
                if (sr.internal) return out;
                break;
            }
        }
        headers_.placed(r.id);
        deferred_.purge(r.id);
        if (relayed || peer == kOwnPeer) flood(frame, peer == kOwnPeer ? std::nullopt : std::optional<std::uint64_t>(peer));
        // the carriers that waited on this one (placed by the outermost event, drain_released)
        for (ParkedFrame& f : deferred_.release(r.id, w.place.released)) release_q_.push_back(std::move(f));
        return out;
    }

    void park(std::uint64_t peer, const std::vector<std::uint8_t>& frame, const AdmitResult& r) {
        if (!r.missing || *r.missing == Missing::CopyDeferred) return;
        ParkedFrame f;
        f.digest = r.digest == Hash32{} ? ::v37::sha256d(frame) : r.digest;
        f.peer = peer;
        f.frame = frame;
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
        (void)deferred_.park(tree_, std::move(f));
        if (*r.missing == Missing::ParentUnknown && peer != kOwnPeer) {
            GetCarrier q;
            q.chain_id = cfg_.identity.chain_id;
            q.ids = {r.fetch};
            q.want_bodies = true;
            send(peer, *encode_fc_getcarrier(q, cfg_.p));
        }
    }

    // After every change of the store's best tip: variants below H(base_pos -
    // J_0) go; the pending set loses what the best chain placed and what
    // sealed; the per-tip caches stay valid (a tip's window is its own).
    void after_best_change() {
        const std::uint64_t base = store_.base_pos();
        const std::uint64_t floor_pos = base > admit_j0(cfg_.p) ? base - admit_j0(cfg_.p) : 0;
        if (const std::optional<Hash32> f = store_.best_at(std::max(floor_pos, store_.first_record_pos())))
            if (const CarrierNode* n = tree_.find(*f)) headers_.drop_below(n->H);
        // the bucket requests closed or abandoned for an `at` the node holds no more, or below that floor
        for (auto* keys : {&closed_, &abandoned_})
            for (auto it = keys->begin(); it != keys->end();) {
                const CarrierNode* n = tree_.find(it->second);
                if (n == nullptr || n->pos < floor_pos)
                    it = keys->erase(it);
                else
                    ++it;
            }
        const LaneView v = store_.view_at(store_.best_tip());
        if (!v.ok()) return;
        const std::uint64_t H = v.record(v.pos());
        pending_.erase_if([&](const PendingReceipt& r) { return v.placed_open(r.id) || !open_at(H, r.h, cfg_.p.open_bins); });
    }

    // ---- E11: a switch by the journal, with the re-pend step ----
    struct SwitchResult {
        bool joiner = false;
        bool internal = false;  // a store write failed: poisoned
        std::uint64_t repended = 0;
        std::uint64_t lost = 0;
    };

    SwitchResult switch_to_best() {
        SwitchResult out;
        const Hash32 new_tip = tree_.best().id;
        const Hash32 old_tip = store_.best_tip();
        const std::optional<Hash32> fork_id = tree_.fork_point(old_tip, new_tip);
        if (!fork_id) return out;
        const std::uint64_t fork = tree_.find(*fork_id)->pos;
        // one depth measure: the journal base
        if (fork < store_.base_pos()) {
            out.joiner = true;
            return out;
        }
        // the undone positions (the losing branch), oldest first
        std::vector<Hash32> undone;
        for (const CarrierNode* n = tree_.find(old_tip); n != nullptr && n->pos > fork; n = tree_.find(n->parent))
            undone.push_back(n->id);
        std::reverse(undone.begin(), undone.end());
        const std::uint64_t old_pos = store_.tip_pos();
        const ActivationRecord ar_before = ar_;
        LaneBatch lane;
        NodeStore ns{store_, faults_};
        if (ns.switch_best(new_tip, &lane) != SwitchVerdict::Switched) {
            poison(new_tip);
            out.internal = true;
            return out;
        }
        if (ar_.rewind(fork) == ArRewind::BelowJoinerSeed) {
            out.joiner = true;  // fail closed: no restore below the joiner's seed
            poison(new_tip);
            return out;
        }
        {
            std::vector<const CarrierNode*> added;
            for (const CarrierNode* n = tree_.find(new_tip); n != nullptr && n->pos > fork; n = tree_.find(n->parent))
                added.push_back(n);
            for (auto it = added.rbegin(); it != added.rend(); ++it)
                if ((*it)->activation && !ar_.append(*(*it)->activation)) {
                    poison(new_tip);  // nothing committed
                    out.internal = true;
                    return out;
                }
        }
        if (kv_ != nullptr) {
            const LaneBatch b = switch_batch(cfg_.record_chain, head_, tree_, store_, bodies_, fork, old_pos, ar_before,
                                             ar_, std::move(lane));
            if (!commit_lane_batch(*kv_, b)) {
                poison(new_tip);
                out.internal = true;
                return out;
            }
        }
        ++generation_;
        // the re-pend step: each undone position ascending, its carried list then its own receipt
        const LaneView nv = store_.view_at(new_tip);
        const std::uint64_t H_new = nv.record(nv.pos());
        for (const Hash32& id : undone) {
            const CarrierBodyV3* b = bodies_.get(id);
            if (b == nullptr) continue;
            std::vector<const ReceiptBodyV3*> rs;
            for (const ReceiptBodyV3& r : b->carried) rs.push_back(&r);
            rs.push_back(&b->own);
            for (std::size_t k = 0; k < rs.size(); ++k) {
                const ReceiptBodyV3& r = *rs[k];
                const Hash32 rid = receipt_id(r);
                if (nv.placed_open(rid) || pending_.holds(rid)) continue;
                const PrInfo pr = io_.resolve_pr ? io_.resolve_pr(r.blob.prev_id) : PrInfo{};
                if (pr.status != PrInfo::Status::Held) continue;
                const std::uint64_t h_r = pr.height + 1;
                if (!open_at(H_new, h_r, cfg_.p.open_bins)) {
                    ++out.lost;  // its origin bin is sealed on the new branch: lost
                    continue;
                }
                const CarrierNode* t = tree_.find(r.side.tip);
                pending_.add(PendingReceipt{rid, r, h_r, t ? t->pos : 0, 0});  // the verified body: no second RandomX
                ++out.repended;
            }
        }
        after_best_change();
        return out;
    }

    PathbNodeConfig cfg_;
    PathbNodeIo io_;
    CarrierTree tree_;
    BinStore store_;
    ActivationRecord ar_;
    CarrierBodies bodies_;
    HeaderIndex headers_;
    WindowCache windows_;
    KeyCache keys_;
    AlarmSink alarm_;
    PendingSet pending_;
    DeferredCarriers deferred_;
    AbandonTimers<Req> timers_;
    BucketWindow window_;
    BucketServeBudget budget_;
    PathbKv* kv_ = nullptr;
    StoreHead head_;
    bool started_empty_ = false;
    bool poisoned_ = false;
    StoreFaults faults_;
    std::uint64_t generation_ = 0;
    std::uint64_t verify_calls_ = 0;
    std::map<std::uint64_t, HelloTail> peers_;
    std::map<std::uint64_t, HeaderRequest> header_req_;
    std::map<std::pair<std::uint64_t, Hash32>, BucketsAssembly> assemblies_;
    std::set<std::pair<std::uint64_t, Hash32>> abandoned_;
    std::set<std::pair<std::uint64_t, Hash32>> closed_;
    std::map<Hash32, XmrKeyRef> refs_;
    JoinServeHold hold_;
    std::set<std::uint64_t> hold_conns_;
    std::deque<ParkedFrame> release_q_;
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
