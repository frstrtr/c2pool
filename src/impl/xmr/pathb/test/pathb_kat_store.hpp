// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_store.hpp
// Helpers for the store KATs: an in-memory PathbKv (a commit applies its batch
// whole, or fails whole, or tears: a prefix of its operations then a
// failure), a scaffold node that writes its store as a node does (one batch
// per position), and the digest of a node's lane state.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_store.hpp"
#include "pathb_kat_admit.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

class MemoryKv final : public pb::PathbKv {
public:
    pb::LaneKv data;
    int fail_next = 0;     // the next n commits fail whole
    bool tear_next = false; // the next commit applies half of its operations, then fails
    std::uint64_t commits = 0;
    std::vector<std::size_t> batch_sizes;

    class Batch final : public pb::PathbKvBatch {
    public:
        explicit Batch(MemoryKv* kv) : kv_(kv) {}
        void put(const std::string& k, const std::string& v) override { ops_.put(k, v); }
        void remove(const std::string& k) override { ops_.del(k); }
        bool commit_sync() override { return kv_->apply(ops_); }

    private:
        MemoryKv* kv_;
        pb::LaneBatch ops_;
    };

    std::unique_ptr<pb::PathbKvBatch> batch() override { return std::make_unique<Batch>(this); }
    std::optional<std::string> get(const std::string& k) override {
        const auto it = data.find(k);
        if (it == data.end()) return std::nullopt;
        return it->second;
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        for (auto it = data.lower_bound(prefix); it != data.end() && it->first.compare(0, prefix.size(), prefix) == 0;
             ++it)
            if (!fn(it->first, it->second)) break;
        return true;
    }

    bool apply(const pb::LaneBatch& b) {
        if (fail_next > 0) {
            --fail_next;
            return false;
        }
        if (tear_next) {
            tear_next = false;
            pb::LaneBatch half;
            for (std::size_t i = 0; i < b.ops.size() / 2; ++i) half.ops.push_back(b.ops[i]);
            pb::apply_batch(data, half);
            return false;
        }
        ++commits;
        batch_sizes.push_back(b.ops.size());
        pb::apply_batch(data, b);
        return true;
    }
};

// The head of a KatNet pool (the raw form at H = kPoolH; position 0 = (pool_id, kLaneB0)).
inline pb::StoreHead kat_head(const KatNet& net) {
    pb::StoreHead h;
    h.identity.network = pb::LaneNet::Regtest;
    h.identity.chain_id = 0;
    h.identity.form = pb::GenesisForm::Raw;
    h.identity.height = kPoolH;
    h.identity.pool_genesis = seq32(0x31);
    h.identity.pool_id = net.pool_id;
    h.genesis_id = net.pool_id;
    h.h0 = kLaneB0;
    h.rules_g = net.rules_g;
    return h;
}

// A node that writes its store as it places (one batch per position).
struct KatStoreNode {
    KatNode n;
    MemoryKv kv;
    pb::StoreHead head;
    std::uint32_t chain = 0;
    bool poisoned = false;

    KatStoreNode(const KatNet& net, std::uint64_t J) : n(net, J), head(kat_head(net)) {
        const pb::LaneBatch b = pb::genesis_batch(chain, head, n.tree, n.store);
        poisoned = !pb::commit_lane_batch(kv, b);
    }

    // place_direct, then the position's batch on an extension.
    pb::WriteResult place(const pb::CarrierBodyV3& c) {
        pb::WriteResult w = place_direct(n, c);
        if (w.outcome == pb::WriteOutcome::Extended) {
            const pb::LaneBatch b =
                    pb::extension_batch(chain, head, n.tree, n.store, n.bodies, pb::receipt_id(c.own), w.batch, w.ar_row);
            if (!pb::commit_lane_batch(kv, b)) poisoned = true;
        }
        return w;
    }
};

// A cheap receipt body on `tip` at h(r) (no coinbase commitment; the scaffold
// places without admission).
inline pb::ReceiptBodyV3 scaffold_receipt(const KatNode& n, const pb::Hash32& tip, std::uint64_t h_r, std::size_t payee,
                                          std::uint64_t k) {
    const KatNet& net = *n.net;
    pb::ReceiptBodyV3 r;
    r.blob.major = 16;
    r.blob.minor = 16;
    r.blob.timestamp = mon_ts(h_r - 1) + 1;
    r.blob.prev_id = mon_block(h_r - 1);
    r.blob.nonce = static_cast<std::uint32_t>(k);
    r.blob.tree_root[0] = 0xEE;
    for (int i = 0; i < 8; ++i) r.blob.tree_root[1 + i] = static_cast<std::uint8_t>(k >> (8 * i));
    r.blob.tx_count = 1;
    r.payee = net.refs[payee % net.refs.size()];
    r.side.pool_id = net.pool_id;
    r.side.payee = net.ids[payee % net.ids.size()];
    r.side.t_origin = n.tree.next_difficulty(tip).value_or(0);
    r.side.tip = tip;
    r.side.give_author_bp = 10;
    r.reward_total = kReward;
    return r;
}

// A scaffold carrier with its committed mmr_root (the root over lc(H(parent))
// leaves of the parent's chain).
inline pb::CarrierBodyV3 scaffold_carrier(const KatNode& n, const pb::Hash32& parent, std::uint64_t h, std::uint8_t tag,
                                          std::uint64_t k, std::size_t payee,
                                          const std::vector<pb::ReceiptBodyV3>& carried) {
    pb::CarrierBodyV3 c = scaffold_body(n, parent, h, tag, k, payee, carried);
    const pb::LaneView pv = n.store.view_at(parent);
    if (pv.ok()) c.own.side.mmr_root = pv.mmr_root_at(pv.pos());
    return c;
}

// A chain of `count` scaffold carriers on the best tip, each carrying up to
// `per` receipts on recent best-chain tips (their bins open at the parent),
// written to the node's store.
inline std::vector<pb::Hash32> store_chain(KatStoreNode& sn, std::uint64_t count, std::uint8_t tag, std::size_t per,
                                          std::uint64_t seed) {
    std::vector<pb::Hash32> out;
    KatNode& n = sn.n;
    Rng rng(seed);
    for (std::uint64_t i = 0; i < count; ++i) {
        const pb::CarrierNode& best = n.tree.best();
        const std::uint64_t x = best.pos + 1;
        std::vector<pb::ReceiptBodyV3> carried;
        for (std::size_t k = 0; k < per && best.pos >= 2; ++k) {
            const std::uint64_t back = 1 + rng.below(std::min<std::uint64_t>(best.pos - 1, 30));
            const std::optional<pb::Hash32> tip = n.store.best_at(best.pos - back);
            if (!tip) continue;
            const pb::CarrierNode* t = n.tree.find(*tip);
            const std::uint64_t h_r = t->h + rng.below(3);  // freshness: 0 .. 2
            if (h_r <= best.H - pb::kRuledLaneParams.open_bins || h_r > h_pos(x) + pb::kRuledLaneParams.fresh_max) continue;
            carried.push_back(scaffold_receipt(n, *tip, h_r, rng.below(20), (seed << 32) ^ (x << 8) ^ k));
        }
        canonical_sort(*n.net, carried, best.id);
        const pb::CarrierBodyV3 c = scaffold_carrier(n, best.id, h_pos(x), tag, x, rng.below(20), carried);
        const pb::WriteResult w = sn.place(c);
        if (w.outcome != pb::WriteOutcome::Extended) {
            check(false, "store_chain: carrier not placed at " + std::to_string(x));
            break;
        }
        out.push_back(pb::receipt_id(c.own));
    }
    return out;
}

// The lane state of a node at its best tip: tip, S, d, cum_work, AR, the MMR
// head, the window and roots of the best tip, every open-bin entry list and
// the placed ids of the open bins.
inline std::string lane_digest(KatNode& n) {
    std::string s;
    const pb::CarrierNode& b = n.tree.best();
    s += hex(b.id.data(), 32) + ":" + std::to_string(b.pos) + ":" + std::to_string(b.d) + ":" + std::to_string(b.H) + ":"
         + std::to_string(b.cum_work.lo) + ":" + std::to_string(b.cum_work.hi) + ";";
    const pb::RatchetStateBytes rs = pb::encode_ratchet_state(b.rs);
    s += hex(rs.data(), rs.size()) + ";";
    for (const pb::ActivationRow& a : n.ar.rows()) s += std::to_string(a.epoch) + "@" + std::to_string(a.h_act) + ",";
    const pb::BmmrHead h = n.store.head();
    s += std::to_string(h.leaf_count) + ":" + hex(h.root.data(), 32) + ":" + std::to_string(h.tip_pos) + ";";
    const pb::TipWindow tw = n.window(b.id);
    s += tw.ok() ? hex(tw.window_root.data(), 32) + ":" + hex(tw.mmr_root.data(), 32) : std::string("nowin");
    s += ";";
    const pb::LaneView v = n.store.view_at(b.id);
    const std::uint64_t H = v.record(v.pos());
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;
    for (std::uint64_t bin = H > F ? H - F + 1 : kLaneB0; bin <= H + pb::kRuledLaneParams.fresh_max; ++bin) {
        s += std::to_string(bin) + "[";
        for (const pb::Placement* x : v.live_entries(bin, v.pos()))
            s += hex(x->id.data(), 4) + "/" + std::to_string(x->q) + "/" + std::to_string(x->p_own) + ",";
        s += "]";
    }
    return s;
}

}  // namespace pathb_kat
