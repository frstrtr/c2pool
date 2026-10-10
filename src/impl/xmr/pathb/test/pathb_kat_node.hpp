// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_node.hpp
// Helpers for v37_xmr_pathb_node_kat: in-process PathbNodes over one scripted
// Monero chain (KatNet's rows; a moving main-chain tip), a RandomX stub, and a
// router that carries every frame between the nodes in order.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_node.hpp"
#include "pathb_kat_admit.hpp"
#include "pathb_kat_store.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

struct Msg {
    std::size_t from = 0;
    std::size_t to = 0;
    std::vector<std::uint8_t> frame;
};

struct Harness {
    const KatNet& net;
    std::uint64_t mon_tip = kPoolH + 1;   // the follower's main-chain tip height
    std::uint64_t now = 1000;              // seconds (the glue's clock)
    std::set<pb::Hash32> bad_pow;
    std::uint64_t rx_calls = 0;
    std::vector<pb::TemplateTx> txs;
    std::vector<std::unique_ptr<pb::FollowerBranchView>> views;
    std::vector<std::unique_ptr<pb::PathbNode>> nodes;
    std::vector<std::unique_ptr<MemoryKv>> kvs;
    std::deque<Msg> q;
    std::set<std::pair<std::size_t, std::size_t>> cut;  // links not delivered (from, to)
    std::uint64_t delivered = 0;
    std::optional<pb::BucketWirePolicy> bucket_policy;  // P-39, P-41, P-42 (default: the defaults)
    std::optional<std::uint64_t> headers_frame;         // P-14 (default: the frame buffer)
    std::uint64_t serve_cap = UINT64_MAX;               // P-48's lower fixed cap

    explicit Harness(const KatNet& n) : net(n) {}

    pb::PathbNodeConfig config(const pb::EpochTable& T, bool launch = false, std::uint64_t J = 1152) const {
        pb::PathbNodeConfig c;
        c.identity.network = pb::LaneNet::Regtest;
        c.identity.chain_id = 0;
        c.identity.form = pb::GenesisForm::Raw;
        c.identity.height = kPoolH;
        c.identity.pool_genesis = seq32(0x31);
        c.identity.pool_id = net.pool_id;
        c.genesis_prev = mon_block(kPoolH);
        c.rules_g = net.rules_g;
        c.T = T;
        c.journal_depth = J;
        c.buffers = pb::relay_buffers_default(16, 300000, c.p.r_max).value();
        c.headers_frame_bytes = headers_frame ? *headers_frame : c.buffers.frame;
        c.bucket_serve_cap = serve_cap;
        c.bucket_policy = bucket_policy ? *bucket_policy : pb::bucket_wire_policy_default(16, 300000).value();
        c.author = net.author;
        c.launch = launch;
        return c;
    }

    pb::PrInfo resolve(const pb::FollowerBranchView& mon, const pb::Hash32& p_r) const {
        pb::PrInfo out;
        const std::optional<pb::BranchBlock> b = mon.block(p_r);
        if (!b) return out;
        out.status = pb::PrInfo::Status::Held;
        out.height = b->height;
        std::optional<std::uint64_t> m;
        const pb::BranchStatus st = pb::timestamp_median_for_child(mon, p_r, m);
        out.in = pb::HeaderInputs{16, st.selected() ? m : std::nullopt, 300000, 300000};
        return out;
    }

    pb::PathbNodeIo io(std::size_t self) {
        views.push_back(std::make_unique<pb::FollowerBranchView>(net.rows));
        const pb::FollowerBranchView* mon = views.back().get();
        pb::PathbNodeIo o;
        o.monero = mon;
        o.resolve_pr = [this, mon](const pb::Hash32& p_r) { return resolve(*mon, p_r); };
        o.seed_of = [](const pb::Hash32&) -> std::optional<pb::Hash32> { return seq32(0x99); };
        o.verify = [this](const pb::HashingBlob& b, std::uint64_t, const pb::Hash32&) {
            ++rx_calls;
            return bad_pow.count(pb::receipt_id(b)) == 0;
        };
        o.monero_tip = [this]() -> std::optional<std::uint64_t> { return mon_tip; };
        o.monero_block_at = [](std::uint64_t h) -> std::optional<pb::Hash32> { return mon_block(h); };
        o.tx_source = [this]() { return txs; };
        o.send = [this, self](std::uint64_t peer, const std::vector<std::uint8_t>& f) {
            q.push_back(Msg{self, static_cast<std::size_t>(peer), f});
        };
        o.flood = [this, self](const std::vector<std::uint8_t>& f, std::optional<std::uint64_t> except) {
            for (std::size_t j = 0; j < nodes.size(); ++j)
                if (j != self && (!except || *except != j)) q.push_back(Msg{self, j, f});
        };
        return o;
    }

    std::size_t add(const pb::EpochTable& T, bool launch = false, std::uint64_t J = 1152, bool persist = false) {
        const std::size_t self = nodes.size();
        MemoryKv* kv = nullptr;
        if (persist) {
            kvs.push_back(std::make_unique<MemoryKv>());
            kv = kvs.back().get();
        }
        nodes.push_back(std::make_unique<pb::PathbNode>(config(T, launch, J), io(self), kv));
        return self;
    }

    pb::PathbNode& operator[](std::size_t i) { return *nodes[i]; }

    void dispatch(const Msg& m) {
        if (cut.count({m.from, m.to}) != 0 || m.to >= nodes.size() || nodes[m.to] == nullptr) return;
        ++delivered;
        pb::PathbNode& n = *nodes[m.to];
        const std::uint8_t op = m.frame.empty() ? 0 : m.frame[0];
        switch (op) {
            case pb::kOpFcCarrier: (void)n.on_carrier(m.from, m.frame); break;
            case pb::kOpFbReceipts: (void)n.on_receipts(m.from, m.frame); break;
            case pb::kOpFcGetCarrier:
                for (auto& f : n.serve_getcarrier(m.from, m.frame, now)) q.push_back(Msg{m.to, m.from, f});
                break;
            case pb::kOpFcGetHeaders:
                for (auto& f : n.serve_getheaders(m.from, m.frame, now)) q.push_back(Msg{m.to, m.from, f});
                break;
            case pb::kOpFcHeaders: (void)n.on_headers(m.from, m.frame, now); break;
            case pb::kOpFcGetBuckets:
                for (auto& f : n.serve_getbuckets(m.from, m.frame, now)) q.push_back(Msg{m.to, m.from, f});
                break;
            case pb::kOpFcBuckets: (void)n.on_buckets(m.from, m.frame, now); break;
            default: break;
        }
    }

    void pump(std::size_t limit = 1000000) {
        while (!q.empty() && limit-- > 0) {
            const Msg m = std::move(q.front());
            q.pop_front();
            dispatch(m);
        }
    }

    // A session of payee k (net.refs[k]).
    pb::PathbSession session(std::size_t k, std::uint32_t nonce = 0) const {
        pb::PathbSession s;
        s.payee = net.refs[k % net.refs.size()];
        for (int i = 0; i < 4; ++i) s.extra_nonce[i] = static_cast<std::uint8_t>(nonce >> (8 * i));
        return s;
    }

    std::optional<pb::PathbJob> job(std::size_t i, std::size_t payee, std::uint32_t en = 0) {
        const pb::PathbTemplate t = nodes[i]->make_template(now);
        if (t.status != pb::TemplateStatus::Ok) return std::nullopt;
        return nodes[i]->make_job(t, session(payee, en));
    }

    // Node i mines one share on its best tip (its own hash: zero meets any d).
    pb::NodeEventResult mine(std::size_t i, std::size_t payee, std::uint32_t nonce, bool deliver = true) {
        pb::NodeEventResult r;
        const std::optional<pb::PathbJob> j = job(i, payee, nonce);
        if (!j) return r;
        r = nodes[i]->on_own_share(*j, nonce, pb::Hash32{});
        if (deliver) pump();
        return r;
    }

    // Advance the follower's tip so the next template's P_r moves on.
    void tick_monero(std::uint64_t by = 1) { mon_tip = std::min<std::uint64_t>(mon_tip + by, kMonTop); }
};

// The canonical miner tx bytes a node builds for its best tip and session k.
inline std::vector<std::uint8_t> coinbase_bytes(Harness& h, std::size_t i, std::size_t k) {
    const std::optional<pb::PathbJob> j = h.job(i, k, 7);
    if (!j) return {};
    return j->miner_tx.prefix;
}

inline std::uint64_t vout_sum(const pb::MinerTx& tx) {
    std::uint64_t s = 0;
    for (const pb::MinerOut& o : tx.outs) s += o.amount;
    return s;
}

}  // namespace pathb_kat
