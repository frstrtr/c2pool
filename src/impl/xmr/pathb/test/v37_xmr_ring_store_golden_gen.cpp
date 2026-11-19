// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_store_golden_gen: the K = 1 store golden. Two persisted
// in-process nodes (the node KATs' Harness over MemoryKv), K = 1 only, with an
// activation (epoch 1 by a kind-2 descriptor; its list is the epoch-0 list
// with coverage + 1, K17 = 1):
//   extensions on A, followed by B, to the fork below the activation;
//   the links cut: A and B each extend across the activation; A's branch
//   delivered to B (side carriers there); B's branch, one position longer,
//   delivered to A: A switches across the activation;
//   extensions until A's view horizon passes the activation, then A's prune;
//   A restarted through pathb_load, and two extensions after it;
//   a third node with an empty persisted store joins B and adopts its chain.
// After each step: every MemoryKv key and value of each node, its batch
// sizes and commit count.
//   --out=FILE / --raw=FILE / --check=FILE as v37_xmr_ring_c1_golden_gen.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"

#include "pathb_kat_node.hpp"
#include "pathb_ratchet_sim.hpp"

#ifndef RING_STORE_GEN_SHA256
#define RING_STORE_GEN_SHA256 "unset"
#endif

namespace {

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

struct Bytes {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t x) { b.push_back(x); }
    void u64(std::uint64_t x) {
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
    }
    void str(const std::string& s) {
        u64(s.size());
        b.insert(b.end(), s.begin(), s.end());
    }
};

struct Recorder {
    struct Rec {
        std::string name;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<Rec> recs;
    void add(const std::string& name, Bytes&& o) { recs.push_back(Rec{name, std::move(o.b)}); }
};

// The journal depth of the persisted nodes (the node KATs' restart depth).
constexpr std::uint64_t kJ = 64;

// Every key and value of each persisted node's store, its batch sizes and its commit count; the facts of each node.
void snap(Recorder& rec, Harness& h, const std::string& step) {
    for (std::size_t k = 0; k < h.kvs.size(); ++k) {
        const MemoryKv& kv = *h.kvs[k];
        Bytes d;
        d.u64(kv.data.size());
        for (const auto& [key, value] : kv.data) {
            d.str(key);
            d.str(value);
        }
        rec.add("store/" + step + "/kv" + std::to_string(k), std::move(d));
        Bytes s;
        s.u64(kv.commits);
        s.u64(kv.batch_sizes.size());
        for (const std::size_t n : kv.batch_sizes) s.u64(n);
        rec.add("store/" + step + "/kv" + std::to_string(k) + "/batches", std::move(s));
    }
    Bytes f;
    for (const std::unique_ptr<pb::PathbNode>& n : h.nodes) {
        f.u64(n->tree().best().pos);
        f.u8(n->poisoned() ? 1 : 0);
        f.u64(n->ar().rows().size());
        for (const pb::ActivationRow& a : n->ar().rows()) {
            f.u64(a.epoch);
            f.u64(a.h_act);
        }
    }
    rec.add("store/" + step + "/facts", std::move(f));
}

// A persisted node of the harness with its own configuration.
std::size_t add_node(Harness& h, const pb::PathbNodeConfig& c) {
    const std::size_t self = h.nodes.size();
    h.kvs.push_back(std::make_unique<MemoryKv>());
    h.nodes.push_back(std::make_unique<pb::PathbNode>(c, h.io(self), h.kvs.back().get()));
    return self;
}

void scenario(Recorder& rec) {
    const KatNet net;
    // epoch 1's list: the epoch-0 list with coverage + 1 (K17 = 1), activated by a kind-2 descriptor at `fixed`
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    const pb::Hash32 d1 = pb::rules_digest(r1);
    const std::uint64_t fixed = 8;
    pb::EpochTable T = kat_table(net);
    T.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, fixed));
    T.compiled.push_back(pb::CompiledEpoch{1, d1, r1});
    Harness h(net);
    // A keeps the fewest bodies the flag allows to keep: its own horizon and the view horizon bind the prune
    pb::PathbNodeConfig ca = h.config(T, true, kJ);
    ca.body_keep = 1;
    const std::size_t a = add_node(h, ca);
    const std::size_t b = add_node(h, h.config(T, true, kJ));
    snap(rec, h, "genesis");
    std::uint32_t nonce = 100;
    std::uint64_t mined = 0;
    const auto mine = [&](std::size_t i) {
        if (mined++ % 2 == 0) h.tick_monero();
        h.mine(i, static_cast<std::size_t>(mined % 4), nonce++);
    };
    // the fork lies below h_act - 1: each branch holds its own H(h_act - 1) and its own activation row
    const std::uint64_t fork = fixed - 2;
    while (h[a].tree().best().pos < fork) {
        mine(a);
        snap(rec, h, "ext/" + std::to_string(h[a].tree().best().pos));
    }
    check(h[b].tree().best().id == h[a].tree().best().id, "B follows A to the fork");
    h.cut = {{a, b}, {b, a}};
    while (h[a].tree().best().pos < fixed + 1) {
        mine(a);
        snap(rec, h, "cut-a/" + std::to_string(h[a].tree().best().pos));
    }
    while (h[b].tree().best().pos < fixed + 2) {
        mine(b);
        snap(rec, h, "cut-b/" + std::to_string(h[b].tree().best().pos));
    }
    h.cut.clear();
    check(h[a].ar().rows().size() == 1 && h[a].ar().rows()[0].h_act == fixed && h[b].ar().rows().size() == 1 &&
                  h[b].ar().rows()[0].h_act == fixed && h[a].tree().best().id != h[b].tree().best().id,
          "both branches activate epoch 1 at its fixed position");
    // A's branch to B first (side carriers there: the receipts A re-pends at its switch rest on them)
    for (std::uint64_t x = fork + 1; x <= h[a].tree().best().pos; ++x) {
        const pb::Hash32 id = *h[a].store().best_at(x);
        (void)h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(id), pb::kRuledLaneParams.r_max));
        h.pump();
        snap(rec, h, "side/" + std::to_string(x));
    }
    bool switched = false;
    for (std::uint64_t x = fork + 1; x <= h[b].tree().best().pos; ++x) {
        const pb::Hash32 id = *h[b].store().best_at(x);
        const pb::NodeEventResult r =
                h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(id), pb::kRuledLaneParams.r_max));
        switched = switched || r.action == pb::NodeAction::Switched;
        h.pump();
        snap(rec, h, "switch/" + std::to_string(x));
    }
    check(switched && h[a].tree().best().id == h[b].tree().best().id && h[a].ar().rows() == h[b].ar().rows(),
          "A switches to B's branch across the activation");
    // the view horizon (base_pos - J_0) passes the activation by `fixed` positions
    const std::uint64_t L = kJ + pb::admit_j0(pb::kRuledLaneParams) + 2 * fixed;
    while (h[a].tree().best().pos < L) mine(a);
    check(h[b].tree().best().id == h[a].tree().best().id && !h[a].poisoned() && !h[b].poisoned(),
          "B follows A to L (A at " + std::to_string(h[a].tree().best().pos) + ", B at " + std::to_string(h[b].tree().best().pos)
                  + ", poisoned " + std::to_string(h[a].poisoned()) + std::to_string(h[b].poisoned()) + ")");
    snap(rec, h, "run/" + std::to_string(h[a].tree().best().pos));
    const pb::PathbNode::PruneReport pr = h[a].prune(h.now);
    check(pr.written && pr.root > fixed, "A's prune writes, its root above the activation");
    {
        Bytes o;
        o.u8(pr.written ? 1 : 0);
        o.u64(pr.root);
        o.u64(pr.first);
        o.u64(pr.floors.bodies);
        o.u64(pr.floors.records);
        o.u64(pr.floors.sides);
        rec.add("store/prune/report", std::move(o));
    }
    snap(rec, h, "prune");
    // A restarted through pathb_load
    const std::string before = h[a].lane_digest();
    pb::LoadInputs in;
    in.T = T;
    in.journal_depth = kJ;
    pb::LoadResult lr = pb::pathb_load(*h.kvs[a], net.pool_id, net.rules_g, in);
    {
        Bytes o;
        o.u8(static_cast<std::uint8_t>(lr.fault));
        o.u64(lr.at);
        o.u8(lr.check);
        rec.add("store/restart/load", std::move(o));
    }
    check(lr.fault == pb::StoreFault::None && lr.state.has_value(), "A's store loads");
    if (!lr.state) return;
    h.nodes[a] = std::make_unique<pb::PathbNode>(ca, h.io(a), std::move(*lr.state), h.kvs[a].get());
    check(h[a].lane_digest() == before, "the restarted A's lane digest equals");
    snap(rec, h, "restart");
    for (int i = 0; i < 2; ++i) {
        mine(a);
        snap(rec, h, "after-restart/" + std::to_string(h[a].tree().best().pos));
    }
    // a node with an empty persisted store joins B (a young chain, joined in full) and adopts it
    h.kvs.push_back(std::make_unique<MemoryKv>());
    const std::size_t j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(T, false, kJ), h.io(j), h.kvs.back().get(),
                                                      pb::PathbNode::LoadFailed{}));
    KatTransport tr(h, j);
    h[j].set_join_transport(&tr);
    h.hello(j, b);
    const pb::JoinStep st = h[j].run_join();
    check(st.switched && st.batch_written && h[j].joined() != nullptr && h[j].joined()->young &&
                  h[j].tree().best().id == h[b].tree().best().id && h[j].ar().rows() == h[b].ar().rows(),
          "the third node adopts B's chain (young, joined in full) and writes its adoption batch");
    snap(rec, h, "adopt");
}

std::string golden_text(const std::vector<std::string>& header, const Recorder& rec) {
    std::string out;
    for (const std::string& l : header) out += "# " + l + "\n";
    std::uint64_t total = 0;
    for (const Recorder::Rec& r : rec.recs) total += r.bytes.size();
    out += "# records " + std::to_string(rec.recs.size()) + " bytes " + std::to_string(total) + "\n";
    for (const Recorder::Rec& r : rec.recs) {
        const pb::Hash32 d = ::v37::sha256d(r.bytes);
        out += r.name + "\t" + std::to_string(r.bytes.size()) + "\t" + hex(d.data(), d.size()) + "\n";
    }
    return out;
}

std::vector<std::uint8_t> golden_raw(const Recorder& rec) {
    Bytes o;
    for (const Recorder::Rec& r : rec.recs) {
        o.str(r.name);
        o.u64(r.bytes.size());
        o.b.insert(o.b.end(), r.bytes.begin(), r.bytes.end());
    }
    return std::move(o.b);
}

std::string arg_of(int argc, char** argv, const std::string& key) {
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        if (s.rfind(key, 0) == 0) return s.substr(key.size());
    }
    return {};
}

}  // namespace

int main(int argc, char** argv) {
    Recorder rec;
    scenario(rec);
    const std::vector<std::string> header{
            "v37_xmr_ring_store_golden: the K = 1 store bytes (MemoryKv keys and values, batch sizes) of two persisted "
            "nodes and a joined one",
            "entry points: the node KATs' Harness (MemoryKv), PathbNode::on_carrier / make_template / make_job / "
            "on_own_share / prune / run_join, pathb_load",
            std::string("source-sha256 v37_xmr_ring_store_golden_gen.cpp ") + RING_STORE_GEN_SHA256,
    };
    const std::string text = golden_text(header, rec);
    const std::string out = arg_of(argc, argv, "--out="), raw = arg_of(argc, argv, "--raw="),
                      chk = arg_of(argc, argv, "--check=");
    if (!out.empty()) {
        std::ofstream f(out, std::ios::binary);
        f << text;
    }
    if (!raw.empty()) {
        const std::vector<std::uint8_t> r = golden_raw(rec);
        std::ofstream f(raw, std::ios::binary);
        f.write(reinterpret_cast<const char*>(r.data()), static_cast<std::streamsize>(r.size()));
    }
    bool ok = g_fail == 0;
    if (!chk.empty()) {
        std::ifstream f(chk, std::ios::binary);
        const std::string want((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (want != text) {
            std::istringstream g(text), w(want);
            std::string lg, lw;
            while (std::getline(g, lg) && std::getline(w, lw) && lg == lw) {
            }
            std::printf("  FAIL: differs from the golden at %s\n", lg.substr(0, lg.find('\t')).c_str());
            ok = false;
        }
    }
    std::printf("v37_xmr_ring_store_golden_gen: %s: %zu records, %d checks, %d failures\n", ok ? "PASS" : "FAIL",
                rec.recs.size(), g_checks, g_fail);
    return ok ? 0 : 1;
}
