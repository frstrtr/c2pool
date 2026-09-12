// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_chain_view.hpp
//
// ChainStateView -- the REAL IChainView over the consensus state, replacing the
// Wave 0 fake for every consumer that reads chain state (C4 template, C5 relay,
// C6 parity, the W4 finalize driver).
//
// WHAT IT IS: a single-branch view. It connects blocks on top of its tip,
// disconnects them exactly, answers every IChainView query from its own rows,
// keeps the RandomX seed anchors, and emits the MainchainEvent / BlockTxEvent
// streams the contracts pin.
//
// WHAT IT IS NOT, AND WHY THAT IS THE RIGHT LINE: it holds no alt branches and
// makes no fork choice. Choosing between two branches needs the peer graph, the
// span scheduler and the ban table -- C2c's, all of it -- and a class that owned
// both would be untestable without a network. So the reorg PRIMITIVE lives here
// (disconnect_to + connect, exactly reversible, proven by the KAT) and the
// POLICY that calls it lives in the index. D-14 PREFER-OWN is likewise C2c's
// tie-break; this class records which ids are ours (`is_own_block`) so the
// index can apply it without re-deriving anything.
//
// THREADING. The contract says cheap accessors should be nearly lock-free and
// the window snapshots may lock. This class is NOT internally synchronised: it
// is owned by the verify thread, exactly as the design pins, and C2c wraps it
// with the mutex it already needs for its own tables. Making it lock itself
// would buy nothing and hide where the real contention is.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_block_eval.hpp"
#include "impl/xmr/native/chain/xmr_consensus_state.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"

namespace c2pool::xmr::native {

class ChainStateView : public IChainView {
public:
    explicit ChainStateView(XmrNet net = XmrNet::Mainnet) : state_(net) {}

    // --- construction ---------------------------------------------------------
    ConsensusState&       state()       noexcept { return state_; }
    const ConsensusState& state() const noexcept { return state_; }

    // Seed from a verified anchor: the tip row, the windows, and the seed ids
    // the bundle carries for the first post-anchor epoch(s).
    void seed_from_anchor(const AnchorBundle& b,
                          const std::vector<std::uint64_t>& timestamps_60) {
        reset_tables_();
        state_.seed_from_anchor(b, timestamps_60);
        for (const auto& s : b.seed_ids) seed_ids_[s.first] = s.second;
        index_tip_();
    }

    void seed_direct(const ChainRow& tip,
                     const std::vector<DifficultyRow>& difficulty_window,
                     const std::vector<std::uint64_t>& short_term_weights,
                     const std::vector<std::uint64_t>& long_term_weights,
                     const std::vector<std::uint64_t>& timestamps_60,
                     const std::vector<std::pair<std::uint64_t, Hash>>& seed_ids = {}) {
        reset_tables_();
        state_.seed_direct(tip, difficulty_window, short_term_weights,
                           long_term_weights, timestamps_60);
        for (const auto& s : seed_ids) seed_ids_[s.first] = s.second;
        index_tip_();
    }

    void set_synced(bool v) noexcept { synced_ = v; }
    void set_randomx_mode(RandomXMode m) noexcept { randomx_mode_ = m; }

    // --- connecting / disconnecting --------------------------------------------
    // Evaluate a wire entry and connect it. `why` carries the reason on refusal;
    // `eval` and `connect_status` let the caller tell a peer fault from a retry.
    struct ConnectOutcome {
        EvalStatus    eval    = EvalStatus::Ok;
        ConnectStatus connect = ConnectStatus::Ok;
        bool          ok      = false;
        ChainRow      row{};
    };

    ConnectOutcome connect(const BlockEntry& entry, bool pow_verified,
                           std::uint64_t now, bool own_mined, std::string& why) {
        ConnectOutcome outcome;
        EvaluatedBlock ev;
        outcome.eval = evaluate_block(entry, ev, why);
        if (outcome.eval != EvalStatus::Ok) return outcome;
        ev.input.pow_verified = pow_verified;

        ChainRow    row;
        ConnectUndo undo;
        outcome.connect = state_.connect(ev.input, now, row, undo, why);
        if (outcome.connect != ConnectStatus::Ok) return outcome;

        undos_.push_back(undo);
        index_row_(row);
        if (own_mined) own_ids_.insert(key_(row.id));

        outcome.ok  = true;
        outcome.row = row;

        emit_extend_(row);
        emit_txs_connected_(row, ev);
        return outcome;
    }

    // Roll the tip back by one block, emitting Orphan for what leaves. The
    // caller supplies the bodies it wants returned to the pool, if it kept them
    // (BlockTxEvent::tx_blobs is best effort by contract).
    bool disconnect_tip(const std::vector<Hash>& tx_hashes,
                        std::vector<std::vector<std::uint8_t>> tx_blobs = {}) {
        const ChainRow* t = state_.tip();
        if (!t || undos_.empty()) return false;
        const ChainRow leaving = *t;

        if (!state_.disconnect(undos_.back())) return false;
        undos_.pop_back();
        unindex_row_(leaving);

        node::MainchainEvent ev;
        ev.kind        = node::MainchainEventKind::Orphan;
        ev.block       = leaving.to_chain_main_block();
        ev.orphaned_id = leaving.id;
        emit_(ev);

        BlockTxEvent tx;
        tx.kind               = BlockTxEvent::Kind::Disconnected;
        tx.height             = leaving.height;
        tx.block_id           = leaving.id;
        tx.tx_hashes          = tx_hashes;
        tx.tx_blobs           = std::move(tx_blobs);
        tx.tx_blobs_complete  = tx.tx_blobs.size() == tx.tx_hashes.size();
        emit_txs_(tx);
        return true;
    }

    // A reorg's first half: roll back to `height` (which must be at or above the
    // anchor). Returns how many blocks left the chain.
    std::uint64_t disconnect_to(std::uint64_t height) {
        std::uint64_t n = 0;
        while (state_.height() > height && disconnect_tip({})) ++n;
        return n;
    }

    // A reorg's second half: after disconnect_to + the connects, one Reorg
    // event tells the consumers what happened as a whole.
    void emit_reorg(std::uint64_t depth) {
        const ChainRow* t = state_.tip();
        if (!t) return;
        node::MainchainEvent ev;
        ev.kind  = node::MainchainEventKind::Reorg;
        ev.block = t->to_chain_main_block();
        ev.depth = depth;
        ++reorgs_;
        if (depth > deepest_reorg_) deepest_reorg_ = depth;
        emit_(ev);
    }

    bool is_own_block(const Hash& id) const { return own_ids_.count(key_(id)) != 0; }

    // --- IChainView -------------------------------------------------------------
    std::optional<node::ChainMainBlock> tip() const override {
        const ChainRow* t = state_.tip();
        if (!t) return std::nullopt;
        return t->to_chain_main_block();
    }

    std::optional<TemplateInputs> template_inputs() const override {
        if (!synced_ || !state_.allows(HfCapability::Template)) return std::nullopt;
        TemplateInputs t = state_.template_inputs_partial();
        const SeedPair p = seed_pair_for_height(t.height);
        const std::optional<Hash> cur = seed_hash_for_height(t.height);
        if (!cur) return std::nullopt;          // fail-closed: no seed, no template
        t.seed_hash = *cur;
        if (p.in_lag_window) {
            const auto nxt = seed_id_at_(p.next_seed_height);
            if (nxt) t.next_seed_hash = *nxt;
        }
        t.synced = true;
        return t;
    }

    std::uint64_t epoch_seq() const override { return state_.epoch_seq(); }

    std::optional<node::ChainMainBlock> by_id(const Hash& id) const override {
        const ChainRow* r = row_by_id_(id);
        if (!r) return std::nullopt;
        return r->to_chain_main_block();
    }

    std::optional<node::ChainMainBlock> by_height(std::uint64_t h) const override {
        const ChainRow* r = row_by_height_(h);
        if (!r) return std::nullopt;
        return r->to_chain_main_block();
    }

    std::optional<std::uint64_t> height_of(const Hash& id) const override {
        const auto it = id_to_height_.find(key_(id));
        if (it == id_to_height_.end()) return std::nullopt;
        return it->second;
    }

    std::uint64_t confirmation_depth(const Hash& id) const override {
        const auto it = id_to_height_.find(key_(id));
        if (it == id_to_height_.end()) return 0;
        const std::uint64_t h = state_.height();
        return h >= it->second ? (h - it->second + 1) : 0;
    }

    bool is_on_best_chain(const Hash& id) const override {
        return id_to_height_.find(key_(id)) != id_to_height_.end();
    }

    std::uint64_t anchor_height()     const override { return state_.anchor_height(); }
    std::uint64_t verified_frontier() const override { return state_.verified_frontier(); }

    // The RandomX seed for `height`: the id of the block at rx_seedheight(h).
    // Answered from the seed anchors, which are kept beyond the row retention
    // precisely so an epoch boundary 2048 blocks back is still reachable.
    std::optional<Hash> seed_hash_for_height(std::uint64_t height) const override {
        return seed_id_at_(rx_seedheight(height));
    }

    void subscribe(EventSink sink) override { sinks_.push_back(std::move(sink)); }
    void subscribe_txs(TxEventSink sink) override { tx_sinks_.push_back(std::move(sink)); }

    // C5's path: a block we assembled. Verified exactly like a peer's -- the
    // only difference is the own-mined mark that feeds D-14 in the index.
    bool submit_own_block(const BlockEntry& entry, std::string& why) override {
        const ConnectOutcome o = connect(entry, /*pow_verified=*/false, /*now=*/0,
                                         /*own_mined=*/true, why);
        return o.ok;
    }

    SyncState sync_state() const override {
        SyncState s;
        s.anchor_height     = state_.anchor_height();
        s.verified_frontier = state_.verified_frontier();
        s.header_frontier   = state_.height();
        s.cohort_height     = cohort_height_;
        const ChainRow* t   = state_.tip();
        if (t) s.best_cumulative_difficulty = t->cumulative_difficulty;
        s.rows         = static_cast<std::uint64_t>(state_.rows().size());
        s.reorgs       = reorgs_;
        s.pow_verified = pow_verified_count_;
        s.randomx_mode = randomx_mode_;
        s.synced       = synced_ && state_.allows(HfCapability::Template);
        return s;
    }

    void set_cohort_height(std::uint64_t h) noexcept { cohort_height_ = h; }

private:
    using Key = std::string;   // 32 raw bytes; std::array has no hash by default

    static Key key_(const Hash& h) {
        return Key(reinterpret_cast<const char*>(h.data()), h.size());
    }

    void reset_tables_() {
        id_to_height_.clear();
        id_order_.clear();
        seed_ids_.clear();
        own_ids_.clear();
        undos_.clear();
        reorgs_ = 0;
        deepest_reorg_ = 0;
        pow_verified_count_ = 0;
    }

    void index_tip_() {
        const ChainRow* t = state_.tip();
        if (t) index_row_(*t);
    }

    void index_row_(const ChainRow& r) {
        const Key k = key_(r.id);
        id_to_height_[k] = r.height;
        id_order_.push_back(std::make_pair(r.height, k));
        if (r.height % SEEDHASH_EPOCH_BLOCKS == 0) seed_ids_[r.height] = r.id;
        if (r.pow_verified) ++pow_verified_count_;
        // Rows fall out of the state's retention window; their id entries go
        // with them, or a query would report a height the state cannot serve.
        // The seed anchors deliberately do NOT: an epoch height 2048 blocks
        // back must stay reachable after its row is gone (D-15).
        const auto& rows = state_.rows();
        const std::uint64_t oldest = rows.empty() ? 0 : rows.front().height;
        while (!id_order_.empty() && id_order_.front().first < oldest) {
            id_to_height_.erase(id_order_.front().second);
            id_order_.pop_front();
        }
    }

    void unindex_row_(const ChainRow& r) {
        id_to_height_.erase(key_(r.id));
        if (!id_order_.empty() && id_order_.back().first == r.height) id_order_.pop_back();
        if (r.pow_verified && pow_verified_count_) --pow_verified_count_;
        // The seed anchor for a rolled-back epoch height must go too: a reorg
        // across an epoch edge re-resolves the seed on the new branch (D-15).
        if (r.height % SEEDHASH_EPOCH_BLOCKS == 0) seed_ids_.erase(r.height);
    }

    const ChainRow* row_by_height_(std::uint64_t h) const {
        const auto& rows = state_.rows();
        if (rows.empty()) return nullptr;
        const std::uint64_t lo = rows.front().height;
        const std::uint64_t hi = rows.back().height;
        if (h < lo || h > hi) return nullptr;
        return &rows[static_cast<std::size_t>(h - lo)];
    }

    const ChainRow* row_by_id_(const Hash& id) const {
        const auto it = id_to_height_.find(key_(id));
        if (it == id_to_height_.end()) return nullptr;
        return row_by_height_(it->second);
    }

    std::optional<Hash> seed_id_at_(std::uint64_t epoch_height) const {
        const auto it = seed_ids_.find(epoch_height);
        if (it != seed_ids_.end()) return it->second;
        const ChainRow* r = row_by_height_(epoch_height);
        if (r) return r->id;
        return std::nullopt;
    }

    void emit_(const node::MainchainEvent& ev) const {
        for (const auto& s : sinks_) s(ev);
    }
    void emit_txs_(const BlockTxEvent& ev) const {
        for (const auto& s : tx_sinks_) s(ev);
    }

    void emit_extend_(const ChainRow& row) const {
        node::MainchainEvent ev;
        ev.kind  = node::MainchainEventKind::Extend;
        ev.block = row.to_chain_main_block();
        emit_(ev);
    }

    void emit_txs_connected_(const ChainRow& row, const EvaluatedBlock& ev) const {
        if (tx_sinks_.empty()) return;
        BlockTxEvent t;
        t.kind     = BlockTxEvent::Kind::Connected;
        t.height   = row.height;
        t.block_id = row.id;
        t.tx_hashes = ev.input.parsed.tx_hashes;
        t.key_images = ev.key_images;
        emit_txs_(t);
    }

    ConsensusState                  state_;
    std::map<Key, std::uint64_t>    id_to_height_;
    std::deque<std::pair<std::uint64_t, Key>> id_order_;
    std::map<std::uint64_t, Hash>   seed_ids_;
    std::set<Key>                   own_ids_;
    std::vector<ConnectUndo>        undos_;
    std::vector<EventSink>          sinks_;
    std::vector<TxEventSink>        tx_sinks_;

    bool          synced_             = false;
    RandomXMode   randomx_mode_       = RandomXMode::Disabled;
    std::uint64_t cohort_height_      = 0;
    std::uint64_t reorgs_             = 0;
    std::uint64_t deepest_reorg_      = 0;
    std::uint64_t pow_verified_count_ = 0;
};

} // namespace c2pool::xmr::native
