// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/fakes/fake_chain.hpp
//
// Compiling fakes for the three C2 surfaces: IChainIndexInbound (the wire side),
// IChainView (the consumer side) and IChainServing (the io-thread read side).
//
// These are not mocks with expectations; they are canned, inspectable
// implementations. A wave-1 component under test drives one of these and then
// reads the recorded calls, so every component can be built and tested before
// the real index exists. Being able to instantiate all of them in one
// translation unit is itself the contracts KAT's main assertion.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "../chain_index.hpp"
#include "../serving.hpp"

namespace c2pool::xmr::native::fakes {

class FakeChain final : public IChainIndexInbound,
                        public IChainView,
                        public IChainServing {
public:
    // --- canned state, set by the test --------------------------------------
    std::vector<node::ChainMainBlock> rows;        // ascending by height
    std::optional<TemplateInputs>     inputs;
    std::uint64_t                     anchor = 0;
    std::uint64_t                     frontier = 0;
    SyncState                         state{};
    // Blocks this fake will hand back from get_block_entry().
    std::map<std::string, BlockEntry> served_blocks;
    bool                              accept_own_block = true;
    std::string                       reject_reason = "fake rejects";

    // --- recorded inbound calls ---------------------------------------------
    struct SyncDataCall  { PeerRef peer; PeerSyncData data; };
    struct ChainEntryCall{ PeerRef peer; ChainEntry entry; };
    struct ObjectsCall   { PeerRef peer; std::vector<BlockEntry> blocks;
                           std::vector<Hash> missed; std::uint64_t peer_height; };
    struct NewBlockCall  { PeerRef peer; BlockEntry block;
                           std::uint64_t peer_height; bool fluffy; };

    std::vector<SyncDataCall>   sync_data_calls;
    std::vector<ChainEntryCall> chain_entry_calls;
    std::vector<ObjectsCall>    objects_calls;
    std::vector<NewBlockCall>   new_block_calls;
    std::vector<PeerRef>        peer_gone_calls;
    std::vector<BlockEntry>     own_blocks;

    // --- IChainIndexInbound --------------------------------------------------
    void on_peer_sync_data(const PeerRef& p, const PeerSyncData& d) override {
        sync_data_calls.push_back({p, d});
    }
    void on_chain_entry(const PeerRef& p, ChainEntry&& e) override {
        chain_entry_calls.push_back({p, std::move(e)});
    }
    void on_objects(const PeerRef& p, std::vector<BlockEntry>&& blocks,
                    std::vector<Hash>&& missed, std::uint64_t peer_height) override {
        objects_calls.push_back({p, std::move(blocks), std::move(missed), peer_height});
    }
    void on_new_block(const PeerRef& p, BlockEntry&& b,
                      std::uint64_t peer_height, bool fluffy) override {
        new_block_calls.push_back({p, std::move(b), peer_height, fluffy});
    }
    void on_peer_gone(const PeerRef& p) override { peer_gone_calls.push_back(p); }

    // --- IChainView ----------------------------------------------------------
    std::optional<node::ChainMainBlock> tip() const override {
        if (rows.empty()) return std::nullopt;
        return rows.back();
    }
    std::optional<TemplateInputs> template_inputs() const override {
        if (!state.synced) return std::nullopt;   // fail-closed, like the real one
        return inputs;
    }
    std::uint64_t epoch_seq() const override { return epoch_seq_; }

    std::optional<node::ChainMainBlock> by_id(const Hash& id) const override {
        for (const auto& r : rows) if (r.id == id) return r;
        return std::nullopt;
    }
    std::optional<node::ChainMainBlock> by_height(std::uint64_t h) const override {
        for (const auto& r : rows) if (r.height == h) return r;
        return std::nullopt;
    }
    std::optional<std::uint64_t> height_of(const Hash& id) const override {
        for (const auto& r : rows) if (r.id == id) return r.height;
        return std::nullopt;
    }
    std::uint64_t confirmation_depth(const Hash& id) const override {
        const auto h = height_of(id);
        if (!h || rows.empty()) return 0;
        return rows.back().height >= *h ? rows.back().height - *h + 1 : 0;
    }
    bool is_on_best_chain(const Hash& id) const override { return height_of(id).has_value(); }

    std::uint64_t anchor_height() const override { return anchor; }
    std::uint64_t verified_frontier() const override { return frontier; }

    std::optional<Hash> seed_hash_for_height(std::uint64_t h) const override {
        const auto b = by_height(h);
        if (!b) return std::nullopt;
        return b->id;
    }

    void subscribe(EventSink s) override { event_sinks_.push_back(std::move(s)); }
    void subscribe_txs(TxEventSink s) override { tx_sinks_.push_back(std::move(s)); }

    bool submit_own_block(const BlockEntry& b, std::string& why) override {
        if (!accept_own_block) { why = reject_reason; return false; }
        own_blocks.push_back(b);
        return true;
    }

    SyncState sync_state() const override { return state; }

    // --- IChainServing -------------------------------------------------------
    PeerSyncData our_sync_data() const override {
        PeerSyncData d;
        if (!rows.empty()) {
            d.current_height = rows.back().height + 1;
            d.top_id         = rows.back().id;
            d.cumulative_difficulty = rows.back().difficulty;
        }
        d.top_version  = top_version;
        d.pruning_seed = 0;
        return d;
    }
    bool have_block(const Hash& id) const override { return by_id(id).has_value(); }

    std::vector<Hash> locator() const override {
        std::vector<Hash> out;
        for (auto it = rows.rbegin(); it != rows.rend(); ++it) out.push_back(it->id);
        return out;
    }

    std::optional<ChainEntry> find_supplement(const std::vector<Hash>& peer_locator) const override {
        for (const Hash& id : peer_locator) {
            const auto h = height_of(id);
            if (!h) continue;
            ChainEntry e;
            e.start_height = *h;
            e.total_height = rows.empty() ? 0 : rows.back().height + 1;
            for (const auto& r : rows) if (r.height >= *h) e.ids.push_back(r.id);
            return e;
        }
        return std::nullopt;   // no common id: caller closes the peer
    }

    std::optional<BlockEntry> get_block_entry(const Hash& id, bool prune) const override {
        const auto it = served_blocks.find(key_of(id));
        if (it == served_blocks.end()) return std::nullopt;
        BlockEntry e = it->second;
        e.pruned = prune;
        return e;
    }

    // --- test helpers --------------------------------------------------------
    std::uint8_t top_version = 16;

    void bump_epoch() { ++epoch_seq_; }

    void emit(const node::MainchainEvent& ev) {
        for (auto& s : event_sinks_) s(ev);
    }
    void emit_tx(const BlockTxEvent& ev) {
        for (auto& s : tx_sinks_) s(ev);
    }
    std::size_t event_sink_count() const { return event_sinks_.size(); }
    std::size_t tx_sink_count() const { return tx_sinks_.size(); }

    void serve(const Hash& id, BlockEntry e) { served_blocks[key_of(id)] = std::move(e); }

    static std::string key_of(const Hash& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    }

private:
    std::uint64_t              epoch_seq_ = 0;
    std::vector<EventSink>     event_sinks_;
    std::vector<TxEventSink>   tx_sinks_;
};

} // namespace c2pool::xmr::native::fakes
