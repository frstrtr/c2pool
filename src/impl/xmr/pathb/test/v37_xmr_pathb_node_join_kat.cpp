// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_node_join_kat.cpp
// The joiner wired into PathbNode (E15; 3.3, 3.3a): PathbNode servers built
// from honest chains, a joining PathbNode over the family-C frames
// (PathbJoinLink over a KAT transport).
//   loadfail   a store that fails to load (its poison mark) starts empty and
//              rests on claims (no template, nothing relayed); a server's HELLO
//              tail is a candidate; the attempt completes; the node runs on the
//              adopted state (templates from L + 1); the adoption batch into an
//              empty store reloads at its base with no re-join (F-5: base at
//              lc(H(x0 - 1)), its peaks), the poison mark and the old
//              records deleted; resting on claims nothing is relayed;
//   young      a young chain joined in full; its store (root 0, the genesis
//              AR) reloads;
//   scope      a joined node offered an unheld tip forking above its x1 and
//              at or above its base: OutOfScope at the first reply (R46B-3);
//   tokens     a disconnect drops the server's pairs; an undecodable
//              FC_HEADERS: 1 strike, NotServed; a short reply: NotServed;
//   fetchahead requests chained from the first reply (C-10) keep a pruning
//              server's hold while every RandomX check takes 2 x P-53;
//   deep       a full node's own chain as A (JC-6 / B-1): headers first from a
//              fork below the journal base -> the joiner path (D37); A builds
//              templates, judges and relays while the attempt runs (3.3a);
//              rule (4) replaces A, the lost count;
//   partition  a fork below the server's header floor (a server at its P-51
//              floors): in scope without a header below x0(L') - N_rt (E-82);
//   x1         a joined node: a fork at or below x1 (above the journal base)
//              takes the joiner path by a body and by headers;
//   reask      E-72: claimed leaves asked again after a switch by the
//              journal, rebound to a carrier of the new chain;
//   adoptbelow a bucket below the joined MMR adopted after L enters the
//              claimed leaves; on_hello compares no claimed node; a #13
//              mismatch above L is ClaimLeaf (alarm + DEFER), never BAN.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "pathb_kat_join.hpp"
#include "pathb_kat_node.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

constexpr std::uint64_t kJ = 1152;

double secs_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

// A PathbNode serving a KatNode's chain (its tree, store, AR and bodies).
std::unique_ptr<pb::PathbNode> server_from(Harness& h, const KatNode& n, std::uint64_t J, std::size_t self) {
    pb::LoadedState st{kat_head(*n.net), n.tree, n.store, n.ar, n.bodies, 0, 0, {}};
    for (const auto& [id, ref] : n.net->book.refs) st.refs[id] = ref;
    st.refs[n.net->author_id] = n.net->author;
    return std::make_unique<pb::PathbNode>(h.config(n.T, true, J), h.io(self), std::move(st), nullptr);
}

// A lane digest without its cum_work and AR fields (a joined tree counts work from its root; its AR starts at the
// joiner's seed row).
std::string digest_wo_work(const std::string& d) {
    std::vector<std::string> f;
    std::size_t a = 0;
    for (std::size_t b = d.find(';'); b != std::string::npos; a = b + 1, b = d.find(';', a)) f.push_back(d.substr(a, b - a));
    f.push_back(d.substr(a));
    if (f.empty()) return d;
    const std::size_t c3 = f[0].rfind(':');
    std::string out = c3 == std::string::npos ? f[0] : f[0].substr(0, c3);
    for (std::size_t i = 1; i < f.size(); ++i)
        if (i != 2) out += ";" + f[i];
    return out;
}

pb::LoadInputs load_inputs(const KatNet& net, std::uint64_t J) {
    pb::LoadInputs in;
    in.T = kat_table(net);
    in.journal_depth = J;
    return in;
}

// ---------------------------------------------------------------------------
void loadfail() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    const std::uint64_t L = 4704;  // a bin seals at L (12 positions per Monero height)
    KatNode a(net, kJ);
    grow(a, L);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    // the joining node's store: a written store with its poison mark -> the load fails
    h.kvs.push_back(std::make_unique<MemoryKv>());
    MemoryKv& kv = *h.kvs.back();
    kv.data[pb::store_keys::poison(0)] = std::string(1, '\x01');
    kv.data[pb::store_keys::pcarrier(0, 3)] = "stale";
    const pb::LoadResult lr = pb::pathb_load(kv, net.pool_id, net.rules_g, load_inputs(net, kJ));
    check(lr.fault == pb::StoreFault::Poisoned, "loadfail: the poison mark: a load failure");
    const std::size_t j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), false, kJ), h.io(j), &kv, pb::PathbNode::LoadFailed{}));
    KatTransport tr(h, j);
    h[j].set_join_transport(&tr);
    const pb::LaneKv failed = kv.data;
    check(h[j].rests_on_claims() && h[j].make_template(h.now).status == pb::TemplateStatus::RestsOnClaims
                  && kv.data == failed,
          "loadfail: started at position 0 in memory, resting on claims (no template); the failed store kept as it is");
    // resting on claims: a carrier placed and a receipt pending are not relayed (3.3a (2)); both from a peer that is
    // not the server, so a relay would reach the server
    h.q.clear();
    const std::uint64_t other = 77;
    const pb::NodeEventResult r1 =
            h[j].on_carrier(other, *pb::encode_fc_carrier(0, *a.bodies.get(at_pos(a, 1)), pb::kRuledLaneParams.r_max));
    const std::vector<pb::ReceiptBodyV3> one{body_on(a, at_pos(a, 1), h_pos(2), 2, 880001)};
    const std::vector<pb::NodeEventResult> rr = h[j].on_receipts(other, *pb::encode_fb_receipts(0, one, pb::kRuledLaneParams));
    bool relayed = false;
    for (const Msg& m : h.q) relayed = relayed || (m.from == j && m.to == s);
    h.q.clear();
    check(r1.action == pb::NodeAction::Placed && rr.size() == 1 && rr[0].action == pb::NodeAction::Pending && !relayed
                  && h[j].rests_on_claims(),
          "loadfail: resting on claims, a placed carrier and a pending receipt are not relayed (actions "
                  + std::to_string(static_cast<int>(r1.action)) + ", "
                  + std::to_string(static_cast<int>(rr.empty() ? pb::NodeAction::None : rr[0].action)) + ")");
    check(kv.data == failed, "loadfail: nothing written while the store is the failed one (a placement, a pending receipt)");
    // a record above L left in the store too: the adoption deletes it with the failed store
    kv.data[pb::store_keys::pcarrier(0, L + 7)] = "stale";
    const pb::HelloCheck hc = h.hello(j, s);
    check(hc.verdict == pb::HelloVerdict::Accept && h[j].joiner().queue().size() == 1,
          "loadfail: the server's HELLO accepted; its tail is a candidate (one pair queued)");
    const pb::JoinStep st = h[j].run_join();
    check(st.report && st.report->end == pb::AttemptEnd::Completed && st.sw.adopted && st.switched && st.batch_written,
          "loadfail: the attempt completes and is adopted; the adoption batch written" +
                  (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    if (!st.switched || h[j].joined() == nullptr) return;
    const pb::JoinedState& js = *h[j].joined();
    check(h[j].tree().best().id == at_pos(a, L) && !h[j].rests_on_claims() && digest_wo_work(h[j].lane_digest()) == digest_wo_work(h[s].lane_digest()),
          "loadfail: the node runs on the adopted state at L (lane digest == the server's, work from its root), no longer resting on claims");
    check(h[j].ar().rows().size() == 1 && h[j].ar().rows()[0].h_act == js.x0 - 1, "loadfail: AR = the joiner's seed row at x0 - 1");
    h.mon_tip = h_pos(L) + 1;
    check(h[j].make_template(h.now).status != pb::TemplateStatus::RestsOnClaims, "loadfail: templates from L + 1");
    // the store: reloads at its base (tip == base_pos = L) with no re-join (F-5)
    const std::uint64_t lc_x0 = pb::bin_leaf_count(a.node(at_pos(a, js.x0 - 1)).H, kLaneB0, pb::kRuledLaneParams.open_bins);
    const std::uint64_t lc_l1 = pb::bin_leaf_count(a.node(at_pos(a, L - 1)).H, kLaneB0, pb::kRuledLaneParams.open_bins);
    const std::uint64_t lc_l = pb::bin_leaf_count(a.node(at_pos(a, L)).H, kLaneB0, pb::kRuledLaneParams.open_bins);
    check(lc_l > lc_l1 && lc_x0 < lc_l1, "loadfail: a bin sealed at L (lc " + std::to_string(lc_x0) + " / " +
                                                 std::to_string(lc_l1) + " / " + std::to_string(lc_l) + ")");
    const pb::StoreHead hd = *pb::decode_phead(kv.data[pb::store_keys::phead(0)]);
    check(hd.base_pos == L && hd.root_pos == js.x0 - 1 && hd.base_leaf_count == lc_x0 && hd.first_pos == js.store->first_record_pos()
                  && !kv.data.count(pb::store_keys::poison(0)) && !kv.data.count(pb::store_keys::pcarrier(0, L + 7)),
          "loadfail: K_PHEAD base_pos = L, base_leaf_count = lc(H(x0 - 1)) = " + std::to_string(hd.base_leaf_count)
                  + ", root_pos = x0 - 1; no poison mark");
    pb::LoadResult rl = pb::pathb_load(kv, net.pool_id, net.rules_g, load_inputs(net, kJ));
    check(rl.fault == pb::StoreFault::None && rl.state && rl.state->tree.best().id == at_pos(a, L)
                  && rl.state->store.first_leaf() == lc_x0 && rl.state->store.head().root == js.store->head().root,
          "loadfail: the store reloads at its base with no re-join; first_leaf() == lc(H(x0 - 1)); the MMR head equal");
    if (rl.state) {
        const std::size_t r = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), false, kJ), h.io(r), std::move(*rl.state), nullptr));
        check(h[r].lane_digest() == h[j].lane_digest(), "loadfail: the reloaded node's lane digest == the adopted state's");
    }
    std::printf("  loadfail: %.1f s\n", secs_since(t0));
}

// A joining node after a load failure (persisted store), its transport, the server node index.
struct Joining {
    std::size_t j = 0;
    std::unique_ptr<KatTransport> tr;
};
Joining joining_node(Harness& h, const KatNet& net, std::uint64_t J) {
    Joining o;
    h.kvs.push_back(std::make_unique<MemoryKv>());
    o.j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), false, J), h.io(o.j), h.kvs.back().get(),
                                                      pb::PathbNode::LoadFailed{}));
    o.tr = std::make_unique<KatTransport>(h, o.j);
    h[o.j].set_join_transport(o.tr.get());
    return o;
}

// ---------------------------------------------------------------------------
// young: a young chain (L < N_rt + 1,176) joined in full; the adoption's store (root at 0, the genesis AR) reloads.
void young() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 600);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    Joining jn = joining_node(h, net, kJ);
    const std::size_t j = jn.j;
    h.hello(j, s);
    const pb::JoinStep st = h[j].run_join();
    check(st.switched && h[j].joined() && h[j].joined()->young && h[j].tree().best().id == at_pos(a, 600),
          "young: the young chain [1, L] joined in full" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    if (!st.switched) return;
    MemoryKv& kv = *h.kvs.back();
    const pb::StoreHead hd = *pb::decode_phead(kv.data[pb::store_keys::phead(0)]);
    const pb::LoadResult rl = pb::pathb_load(kv, net.pool_id, net.rules_g, load_inputs(net, kJ));
    check(hd.root_pos == 0 && hd.base_pos == 600 && hd.base_leaf_count == 0 && h[j].ar().rows().empty()
                  && rl.fault == pb::StoreFault::None && rl.state && rl.state->tree.best().id == at_pos(a, 600),
          "young: the young adoption's store (root 0, base L, no base leaves, the genesis AR) reloads with no re-join");
}

// ---------------------------------------------------------------------------
// scope: a joined node offered a tip it does not hold on a chain forking above its x1 and at or above its base: the
// attempt ends at its first reply (R46B-3), 0 tokens, the pair dropped; nothing of A changes.
void scope() {
    JoinNet net(900);
    const std::uint64_t L = 4704;
    KatNode a(net, kJ);
    grow(a, L);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    Joining jn = joining_node(h, net, kJ);
    const std::size_t j = jn.j;
    h.hello(j, s);
    const pb::JoinStep st = h[j].run_join();
    check(st.switched, "scope: joined at L");
    if (!st.switched) return;
    // the server's chain grows 5 more: its tip is not held by A, its fork with A is L (above x1, at or above the base)
    grow(a, 5);
    const std::size_t s2 = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s2));
    const std::string before = h[j].lane_digest();
    h.hello(j, s2);
    check(h[j].joiner().queue().size() == 1, "scope: the unheld tip of a peer is a candidate at a joined A");
    const std::size_t reqs0 = jn.tr->log.size();
    const pb::JoinStep o = h[j].run_join();
    check(o.report && o.report->end == pb::AttemptEnd::OutOfScope && o.report->strike == 0 && !o.switched
                  && h[j].join_link(s2)->strikes() == 0 && h[j].joiner().queue().size() == 0
                  && jn.tr->requests_of(pb::kOpFcGetHeaders) - 0 >= 1 && h[j].lane_digest() == before,
          "scope: OutOfScope at the first reply, 0 tokens, the pair dropped, A unchanged" +
                  (o.report ? std::string(": ") + rep_desc(*o.report) : std::string()));
    std::size_t carriers = 0;
    for (std::size_t k = reqs0; k < jn.tr->log.size(); ++k) carriers += jn.tr->log[k].op == pb::kOpFcGetCarrier ? 1 : 0;
    check(carriers == 0, "scope: no body fetched before the fork with A is known");
}

// ---------------------------------------------------------------------------
// tokens: an undecodable FC_HEADERS reply: 1 strike for the server, the attempt ends NotServed (re-queued);
// a short FC_HEADERS reply: NotServed (ruling 46 S4wa-2 (a)), 0 tokens.
void tokens() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 600);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    {
        // a disconnect drops the server's pairs and its link (Joiner::disconnect)
        Joining jn = joining_node(h, net, kJ);
        h.hello(jn.j, s);
        const std::size_t q0 = h[jn.j].joiner().queue().size();
        h[jn.j].disconnect(s);
        check(q0 == 1 && h[jn.j].joiner().queue().size() == 0 && h[jn.j].join_link(s) == nullptr,
              "tokens: a disconnect drops the server's queued pair and its link");
    }
    {
        Joining jn = joining_node(h, net, kJ);
        const std::size_t j = jn.j;
        bool done = false;
        jn.tr->edit = [&](std::uint64_t, std::uint8_t op, std::vector<std::vector<std::uint8_t>>& reply) {
            if (op != pb::kOpFcGetHeaders || done || reply.empty()) return;
            done = true;
            reply[0][2] ^= 0x01;  // another chain_id: the frame does not decode
        };
        h.hello(j, s);
        const pb::JoinStep o = h[j].run_join();
        check(o.report && o.report->end == pb::AttemptEnd::NotServed && h[j].join_link(s)->strikes() == 1
                      && h[j].joiner().queue().size() == 1,
              "tokens: an undecodable FC_HEADERS from the attempt's server: 1 strike, NotServed, the pair re-queued");
    }
    {
        Joining jn = joining_node(h, net, kJ);
        const std::size_t j = jn.j;
        jn.tr->edit = [&](std::uint64_t, std::uint8_t op, std::vector<std::vector<std::uint8_t>>& reply) {
            if (op != pb::kOpFcGetHeaders || reply.empty()) return;
            pb::HeadersReply rep;
            if (!pb::decode_fc_headers(reply[0], 0, 1u << 22, pb::kRuledLaneParams, rep).ok() || rep.headers.size() < 2) return;
            rep.first_pos += rep.headers.size() - 1;
            rep.headers.erase(rep.headers.begin(), rep.headers.end() - 1);  // one header per reply
            reply[0] = *pb::encode_fc_headers(rep, 1u << 22);
        };
        h.hello(j, s);
        const pb::JoinStep o = h[j].run_join();
        check(o.report && o.report->end == pb::AttemptEnd::NotServed && h[j].join_link(s)->strikes() == 0
                      && o.report->what.find("short") != std::string::npos,
              "tokens: one header per reply: the attempt ends at its first short reply, 0 tokens" +
                      (o.report ? std::string(": ") + o.report->what : std::string()));
    }
}

// ---------------------------------------------------------------------------
// fetchahead: one request outstanding while the attempt checks the reply it holds. Replies arrive 8 s after their
// request; a header page's checks take about 6 s; the server keeps only from its floors, ends a hold at P-53 and its
// tip moves on while it serves. The next page goes out before the page held is checked, so the gap between two
// requests is the latency, the server's hold stands and the attempt completes; the transport never holds more than one
// reply nobody asked for yet.
void fetchahead() {
    JoinNet net(900);
    const std::uint64_t L = 6000, moved = 24;  // a span whose floors are above position 1
    KatNode a(net, kJ);
    grow(a, L);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    const std::vector<pb::Hash32> more = grow(a, moved);  // the server's next carriers (its tip moves while it serves)
    // a header page's size at this server: its checks take about 6 s
    std::uint64_t page_n = 0;
    {
        const std::vector<std::vector<std::uint8_t>> top = h[s].serve_getheaders(
                9999, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, pb::Hash32{}, 1152}), h.now).frames;
        pb::HeadersReply rep;
        if (!top.empty() && pb::decode_fc_headers(top[0], 0, 1u << 22, pb::kRuledLaneParams, rep).ok()) page_n = rep.headers.size();
        h[s].disconnect(9999);
    }
    Joining jn = joining_node(h, net, kJ);
    const std::size_t j = jn.j;
    jn.tr->prune = true;
    jn.tr->rtt_s = 8;
    const pb::JoinServeFloors f_L = h[s].serve_floors_now();
    bool grown = false;
    jn.tr->on_request = [&]() {
        if (grown || jn.tr->log.size() != 2) return;
        grown = true;
        const std::uint64_t per = h.verify_per_s;
        h.verify_per_s = 0;
        h.mon_tip = h_pos(L + moved) + 1;
        for (const pb::Hash32& id : more)
            (void)h[s].on_carrier(99, *pb::encode_fc_carrier(0, *a.bodies.get(id), pb::kRuledLaneParams.r_max));
        h.q.clear();
        h.verify_per_s = per;
    };
    h.verify_per_s = std::max<std::uint64_t>(1, page_n / 6);
    h.hello(j, s);
    const std::uint64_t t0 = h.now;
    const pb::JoinStep st = h[j].run_join();
    const pb::JoinServeFloors f_now = h[s].serve_floors_now();
    check(page_n >= 10 && grown && h[s].tree().best().pos == L + moved && f_now.headers > f_L.headers,
          "fetchahead: the server's tip moved to L + 24 while it served (header floor " + std::to_string(f_L.headers) + " -> "
                  + std::to_string(f_now.headers) + "; pages of " + std::to_string(page_n) + " headers)");
    check(st.report && st.report->end == pb::AttemptEnd::Completed && st.switched && h[j].tree().best().id == at_pos(a, L),
          "fetchahead: the attempt completes at L against the pruning server (" + std::to_string(h.now - t0) + " s)"
                  + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    // the next FC_GETHEADERS went out before the page held was checked: two consecutive sends with no check between
    std::vector<std::uint64_t> hdr_rx;
    for (const KatTransport::Logged& l : jn.tr->log)
        if (l.op == pb::kOpFcGetHeaders) hdr_rx.push_back(l.rx);
    std::size_t unchecked = 0;
    for (std::size_t i = 2; i < hdr_rx.size(); ++i) unchecked += hdr_rx[i] == hdr_rx[i - 1] ? 1 : 0;
    check(hdr_rx.size() >= 3 && unchecked >= 1 && jn.tr->peak_pending <= 1,
          "fetchahead: a header page named ahead went out before the page held was checked (" + std::to_string(unchecked)
                  + " of " + std::to_string(hdr_rx.size()) + "); at most one reply outstanding (peak "
                  + std::to_string(jn.tr->peak_pending) + ")");
    const std::size_t car = jn.tr->requests_of(pb::kOpFcGetCarrier);
    const std::uint64_t named = h[j].join_link(s) != nullptr ? h[j].join_link(s)->ahead_carriers_taken() : 0;
    check(car >= 3 && named + 3 >= car,
          "fetchahead: every FC_GETCARRIER batch of the replay after the first named before the batch held was placed ("
                  + std::to_string(named) + " of " + std::to_string(car) + ")");
}

// Headers first at node `to` from server `from`: FC_GETHEADERS(from the held fork, stop) and the server's pages until
// the node decides.
pb::PathbNode::HeadersOutcome headers_first(Harness& h, std::size_t to, std::size_t from, const pb::Hash32& fork,
                                            const pb::Hash32& stop) {
    pb::PathbNode::HeadersOutcome o;
    h.q.clear();
    if (!h[to].request_headers(from, fork, stop, 8000, h.now)) return o;
    for (int page = 0; page < 1000 && !h.q.empty(); ++page) {
        const Msg req = h.q.front();
        h.q.pop_front();
        if (req.frame.empty() || req.frame[0] != pb::kOpFcGetHeaders) continue;
        const std::vector<std::vector<std::uint8_t>> r = h[from].serve_getheaders(to, req.frame, h.now).frames;
        if (r.empty()) break;
        o = h[to].on_headers(from, r.at(0), h.now);
        if (o.kind != pb::PathbNode::HeadersOutcome::Kind::Continue) break;
    }
    return o;
}

// ---------------------------------------------------------------------------
// deep (D37; JC-6 / B-1; 3.3a): a full node whose own chain is A. b forks from a at 3,000; a holds b's carriers to
// 3,560 as a side branch at or above its base, then a's base passes 3,000; b heavier. Headers first from b's server:
// the fork below the journal base -> the joiner path, b's tip with that server a candidate; the attempt runs while A
// builds templates, judges and relays a carrier; the fork with A's BEST chain (not the held side top) decides: in
// scope, rule (4) replaces A, the lost count = A's open-bin placements.
void deep() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    ChainShape sb;
    sb.nonce0 = 7000000;
    KatNode a(net, kJ);
    grow(a, 3000);
    const pb::Hash32 fork = at_pos(a, 3000);
    KatNode b(a);
    std::uint64_t placed = 0;
    for (int i = 0; i < 560; ++i) {
        grow(a, 2);
        const std::vector<pb::Hash32> ids = grow(b, 1, sb);
        if (!ids.empty() && admit_place(a, *b.bodies.get(ids.back())).placed) ++placed;
    }
    const pb::Hash32 q = b.store.best_tip();  // the held side top
    grow(a, 4200 - a.store.tip_pos());
    grow(b, 4700 - b.store.tip_pos(), sb);
    Harness h(net);
    const std::size_t fa = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, fa));
    const std::size_t fb = h.nodes.size();
    h.nodes.push_back(server_from(h, b, kJ, fb));
    const std::vector<pb::Hash32> a_next = grow(a, 1);  // a's next carrier, relayed to A while the attempt runs
    h.mon_tip = h_pos(4201) + 1;
    KatTransport tr(h, fa);
    h[fa].set_join_transport(&tr);
    const pb::CarrierNode* qn = h[fa].tree().find(q);
    const std::uint64_t base = h[fa].store().base_pos();
    check(placed == 560 && qn != nullptr && h[fa].store().best_at(qn->pos) != q && base > 3000 && qn->pos >= base,
          "deep: A holds b's carriers to " + std::to_string(qn ? qn->pos : 0) + " as a side branch at or above its base "
                  + std::to_string(base) + "; the fork 3,000 lies below it");
    const pb::HelloCheck hc = h.hello(fa, fb);
    check(hc.verdict == pb::HelloVerdict::Accept && h[fa].joiner().queue().size() == 0 && h[fa].join_link(fb) != nullptr,
          "deep: B's HELLO accepted; a full node offers no candidate on a HELLO (headers first decide)");
    const pb::PathbNode::HeadersOutcome o = headers_first(h, fa, fb, fork, b.store.best_tip());
    check(o.kind == pb::PathbNode::HeadersOutcome::Kind::JoinerPath && o.fork_pos == 3000 && h[fa].joiner().queue().size() == 1,
          "deep: heavier by its headers, forked below the journal base: the joiner path; b's tip with B a candidate "
          "(kind " + std::to_string(static_cast<int>(o.kind)) + ", queued " + std::to_string(h[fa].joiner().queue().size()) + ")");
    // 3.3a: while the attempt runs A builds templates, places a relayed carrier and floods it
    bool during = false, attempting = false, flooded = false;
    pb::TemplateStatus tst = pb::TemplateStatus::RestsOnClaims;
    pb::NodeAction placed_action = pb::NodeAction::None;
    std::uint64_t lost_expected = 0;
    tr.on_request = [&]() {
        if (during || tr.log.size() != 3) return;
        during = true;
        attempting = h[fa].attempting();
        tst = h[fa].make_template(h.now).status;
        h.q.clear();
        placed_action = h[fa].on_carrier(99, *pb::encode_fc_carrier(0, *a.bodies.get(a_next.at(0)), pb::kRuledLaneParams.r_max)).action;
        placed_action = h[fa].tree().best().id == a_next.at(0) ? placed_action : pb::NodeAction::None;
        for (const Msg& m : h.q) flooded = flooded || (m.from == fa && !m.frame.empty() && m.frame[0] == pb::kOpFcCarrier);
        h.q.clear();
        lost_expected = pb::open_bin_placements(h[fa].store());
    };
    const pb::JoinStep st = h[fa].run_join();
    check(during && attempting && tst == pb::TemplateStatus::Ok && placed_action == pb::NodeAction::Placed && flooded,
          "deep: while the attempt runs A builds a template, places a relayed carrier and relays it (template "
                  + std::to_string(static_cast<int>(tst)) + ", action " + std::to_string(static_cast<int>(placed_action)) + ")");
    check(st.report && st.report->end == pb::AttemptEnd::Completed && st.sw.replaced && st.switched,
          "deep: the fork with A's best chain, not the held side top, decides: below A's base, in scope; rule "
          "(4) replaces A" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    check(lost_expected > 0 && st.sw.lost == lost_expected,
          "deep: the lost count = the replaced own chain's open-bin placements (" + std::to_string(st.sw.lost) + " of "
                  + std::to_string(lost_expected) + ")");
    check(h[fa].joined() != nullptr && h[fa].tree().best().id == b.store.best_tip()
                  && digest_wo_work(h[fa].lane_digest()) == digest_wo_work(h[fb].lane_digest()) && !h[fa].attempting(),
          "deep: the node runs on the adopted state at b's tip (lane digest == B's, work from its root)");
    std::printf("  deep: %.1f s\n", secs_since(t0));
}

// ---------------------------------------------------------------------------
// partition (C-23; ruling 47 (a), E-82): the full node's own chain as A, a fork at 2,000 below A's base and below the
// server's header floor (a server keeping only from its P-51 floors). The scope scan asks no header below
// x0(L') - N_rt; the candidate is in scope and rule (4) replaces A.
void partition() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 2000);
    KatNode b(a);
    grow(a, 2000);
    ChainShape sb;
    sb.nonce0 = 6000000;
    grow(b, 7000, sb);
    Harness h(net);
    const std::size_t fa = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, fa));
    const std::size_t fb = h.nodes.size();
    h.nodes.push_back(server_from(h, b, kJ, fb));
    KatTransport tr(h, fa);
    tr.prune = true;
    h[fa].set_join_transport(&tr);
    h.mon_tip = h_pos(9000) + 1;
    (void)h.hello(fa, fb);
    const pb::JoinServeFloors f = h[fb].serve_floors_now();
    const std::uint64_t base = h[fa].store().base_pos();
    check(f.headers > base && base > 2000,
          "partition: the fork 2,000 lies below A's base " + std::to_string(base) + " and below the server's header floor "
                  + std::to_string(f.headers));
    const pb::PathbNode::HeadersOutcome o = headers_first(h, fa, fb, at_pos(a, 2000), b.store.best_tip());
    h.q.clear();
    const pb::JoinStep st = h[fa].run_join();
    check(o.kind == pb::PathbNode::HeadersOutcome::Kind::JoinerPath && st.report && st.report->end == pb::AttemptEnd::Completed
                  && st.sw.replaced && h[fa].tree().best().id == b.store.best_tip(),
          "partition: the scan asks no header below x0(L') - N_rt; the fork below it, in scope; rule (4) replaces A (kind "
                  + std::to_string(static_cast<int>(o.kind)) + ")"
                  + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string(": no attempt")));
    std::printf("  partition: %.1f s\n", secs_since(t0));
}

// A node joined at L from a server holding a's chain (J: the joining node's P-01).
struct Joined {
    std::size_t s = 0;  // the server
    Joining jn;
    bool ok = false;
};
Joined join_at(Harness& h, const JoinNet& net, KatNode& a, std::uint64_t J) {
    Joined o;
    o.s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, o.s));
    o.jn = joining_node(h, net, J);
    h.hello(o.jn.j, o.s);
    const pb::JoinStep st = h[o.jn.j].run_join();
    o.ok = st.switched && h[o.jn.j].joined() != nullptr && h[o.jn.j].tree().best().id == a.store.best_tip();
    return o;
}

// ---------------------------------------------------------------------------
// x1 (3.3a after a join): a joined node (P-01 4,000: its journal base below its x1) and a heavier branch forking at
// 2,400, at or below x1 and above the base: headers first take the joiner path, no body fetched; rule (4) replaces A.
void x1() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    const std::uint64_t L = 4704, f = 2400;
    ChainShape sb;
    sb.nonce0 = 7100000;
    KatNode a(net, kJ);
    grow(a, f);
    KatNode b(a);
    grow(a, L - f);
    grow(b, L + 120 - f, sb);
    Harness h(net);
    Joined jd = join_at(h, net, a, 4000);
    check(jd.ok, "x1: joined at L with P-01 4,000");
    if (!jd.ok) return;
    const std::size_t j = jd.jn.j;
    const pb::JoinedState& js = *h[j].joined();
    const std::uint64_t base = h[j].store().base_pos();
    check(!js.young && f <= js.x1 && base < f,
          "x1: the fork 2,400 at or below x1 " + std::to_string(js.x1) + " and above the journal base " + std::to_string(base));
    const std::size_t sb_ = h.nodes.size();
    h.nodes.push_back(server_from(h, b, kJ, sb_));
    (void)h.hello(j, sb_);
    const std::size_t q_hello = h[j].joiner().queue().size();  // b's tip with B (a tip A does not hold)
    const pb::PathbNode::HeadersOutcome o = headers_first(h, j, sb_, at_pos(a, f), b.store.best_tip());
    bool bodies = false;
    for (const Msg& m : h.q) bodies = bodies || (!m.frame.empty() && m.frame[0] == pb::kOpFcGetCarrier);
    check(o.kind == pb::PathbNode::HeadersOutcome::Kind::JoinerPath && o.fork_pos == f && !bodies && q_hello == 1 && h[j].joiner().queue().size() == 1,
          "x1: heavier by its headers, forked at or below x1: the joiner path whatever its P-01, no body fetched (kind "
                  + std::to_string(static_cast<int>(o.kind)) + ", fork " + std::to_string(o.fork_pos) + ", queued "
                  + std::to_string(q_hello) + " / " + std::to_string(h[j].joiner().queue().size()) + ")");
    // by its bodies: placed as a side branch until heavier, then the joiner path (b's tip there with B a candidate)
    h.mon_tip = h_pos(b.store.tip_pos()) + 1;
    pb::NodeAction act = pb::NodeAction::None;
    std::uint64_t sent = 0;
    for (std::uint64_t x = f + 1; x <= b.store.tip_pos(); ++x) {
        act = h[j].on_carrier(sb_, *pb::encode_fc_carrier(0, *b.bodies.get(at_pos(b, x)), pb::kRuledLaneParams.r_max)).action;
        ++sent;
        if (act != pb::NodeAction::SideBranch) break;
    }
    h.q.clear();
    check(act == pb::NodeAction::JoinerPath && h[j].joiner().queue().size() == 2
                  && h[j].store().best_tip() == at_pos(a, L),
          "x1: by its bodies (" + std::to_string(sent) + "), heavier with its fork at or below x1: the joiner path, its tip "
          "with B a candidate; the store kept (action " + std::to_string(static_cast<int>(act)) + ", queued "
                  + std::to_string(h[j].joiner().queue().size()) + ")");
    h.q.clear();
    const pb::JoinStep st = h[j].run_join();
    check(st.report && st.report->end == pb::AttemptEnd::Completed && st.sw.replaced && h[j].tree().best().id == b.store.best_tip(),
          "x1: in scope (the fork at or below x1); rule (4) replaces A" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    std::printf("  x1: %.1f s\n", secs_since(t0));
}

// ---------------------------------------------------------------------------
// reask (E-72, 3.4): a joined node switches by its journal to a branch forking at L - 1 (c_L off its best chain); its
// claimed leaves (at c_L and c_x0) are asked again at a carrier of the new chain and, equal, rebound to it.
void reask() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    const std::uint64_t L = 4704;
    ChainShape sb;
    sb.nonce0 = 7200000;
    KatNode a(net, kJ);
    grow(a, L - 1);
    KatNode b(a);
    grow(a, 1);
    const std::vector<pb::Hash32> bb = grow(b, 3, sb);
    Harness h(net);
    Joined jd = join_at(h, net, a, kJ);
    check(jd.ok, "reask: joined at L");
    if (!jd.ok) return;
    const std::size_t j = jd.jn.j;
    const pb::JoinedState& js = *h[j].joined();
    const std::size_t claimed = js.claimed.size();
    const pb::Hash32 cL = at_pos(a, L);
    std::size_t at_cl = 0;
    for (const auto& [bin, at] : js.claimed) at_cl += at.id == cL ? 1 : 0;
    h.mon_tip = h_pos(L + 2) + 1;
    bool switched = false;
    for (const pb::Hash32& id : bb)
        switched = h[j].on_carrier(77, *pb::encode_fc_carrier(0, *b.bodies.get(id), pb::kRuledLaneParams.r_max)).action
                           == pb::NodeAction::Switched
                   || switched;
    h.q.clear();
    check(claimed > 0 && at_cl > 0 && switched && h[j].store().best_tip() == bb.back(),
          "reask: a switch by the journal at L - 1 (c_L off the best chain; " + std::to_string(claimed) + " claimed leaves, "
                  + std::to_string(at_cl) + " at c_L)");
    const pb::JoinStep st = h[j].run_join();
    std::size_t rebound = 0;
    for (const auto& [bin, at] : js.claimed) {
        const pb::CarrierNode* n = h[j].tree().find(at.id);
        if (n != nullptr && n->pos > js.x1 && h[j].store().best_at(n->pos) == at.id) ++rebound;
    }
    check(st.reasked == claimed && rebound == claimed && !st.reask_joiner && js.claimed.size() == claimed,
          "reask: every claimed leaf asked again at a carrier of the new chain, equal, rebound to it (asked "
                  + std::to_string(st.reasked) + ", rebound " + std::to_string(rebound) + " of " + std::to_string(claimed) + ")");
    std::printf("  reask: %.1f s\n", secs_since(t0));
}

// ---------------------------------------------------------------------------
// adoptbelow (3.7a; RV87 N-7 (i)): a bucket below the joined MMR's start adopted after L outside an attempt enters
// the claimed leaves at its at header. claimleaf (C-23): a #13 mismatch (mmr_root) on a carrier above L at a joined
// node: ClaimLeaf, alarm + DEFER, 0 tokens, never BAN.
void adoptbelow() {
    JoinNet net(900);
    const std::uint64_t L = 4704;
    KatNode a(net, kJ);
    grow(a, L);
    Harness h(net);
    Joined jd = join_at(h, net, a, kJ);
    check(jd.ok, "adoptbelow: joined at L");
    if (!jd.ok) return;
    const std::size_t j = jd.jn.j;
    const pb::JoinedState& js = *h[j].joined();
    const std::uint64_t fl = h[j].store().first_leaf();
    const std::uint64_t bin = kLaneB0 + fl - 2;
    const pb::Hash32 cL = at_pos(a, L);
    check(fl >= 2 && js.claimed.count(bin) == 0, "adoptbelow: a bin below the joined MMR's start, not claimed");
    h.q.clear();
    const bool sent = h[j].request_buckets(jd.s, cL, bin, bin, h.now);
    h.pump();
    const auto it = js.claimed.find(bin);
    check(sent && it != js.claimed.end() && it->second.id == cL,
          "adoptbelow: the bucket adopted after L (FC_BUCKETS at c_L) enters the claimed leaves at c_L");
    // on_hello: a best tip that is a claimed node here (a prefix node below the root, a span carrier at or below x1) is
    // not bound: its leaf count is not compared; a carrier above x1 is
    {
        const pb::PathbHello ours = h[j].our_hello(1000 + j, 0);
        const auto hello_at = [&](const pb::Hash32& tip, std::uint64_t lc) {
            pb::PathbHello t = h[jd.s].our_hello(1000 + jd.s, 0);
            t.tail.best_tip = tip;
            t.tail.mmr_leaf_count = lc;
            return h[j].on_hello(jd.s, *pb::encode_pathb_hello(t), ours).verdict;
        };
        const auto lc_at = [&](std::uint64_t x) {
            return pb::bin_leaf_count(a.node(at_pos(a, x)).H, kLaneB0, pb::kRuledLaneParams.open_bins);
        };
        const pb::Hash32 pre = at_pos(a, js.x0 - 2), span = at_pos(a, js.x1), above = at_pos(a, js.x1 + 1);
        const bool held = h[j].tree().find(pre) != nullptr && h[j].tree().find(span) != nullptr;
        const pb::HelloVerdict v_pre = hello_at(pre, lc_at(js.x0 - 2) + 3);
        const pb::HelloVerdict v_span = hello_at(span, lc_at(js.x1) + 3);
        const pb::HelloVerdict v_above = hello_at(above, lc_at(js.x1 + 1) + 3);
        check(held && v_pre == pb::HelloVerdict::Accept && v_span == pb::HelloVerdict::Accept && v_above == pb::HelloVerdict::Close,
              "hello: a claimed prefix node and a span carrier at x1 are not bound (no leaf-count comparison); a carrier "
              "above x1 is (another leaf count: closed)");
    }
    // claimleaf
    h.mon_tip = h_pos(L + 1) + 1;
    const pb::CarrierBodyV3 c = carrier_on(a, cL, h_pos(L + 1), {}, 1, 4242, {},
                                           [](pb::ReceiptBodyV3& r) { r.side.mmr_root[0] ^= 1; });
    const pb::NodeEventResult r = h[j].on_carrier(jd.s, *pb::encode_fc_carrier(0, c, pb::kRuledLaneParams.r_max));
    check(r.admit.missing == pb::Missing::ClaimAlarm && r.admit.strike == 0 && r.admit.verdict != pb::AdmitVerdict::Ban
                  && r.action == pb::NodeAction::Parked && h[j].tree().best().id == cL,
          "claimleaf: a #13 mismatch above L at a joined node: ClaimLeaf, alarm + DEFER, 0 tokens, no BAN (action "
                  + std::to_string(static_cast<int>(r.action)) + ", strike " + std::to_string(r.admit.strike) + ")");
}

// ---------------------------------------------------------------------------
// e81: the header phase through PathbJoinLink against a server of our own (E-81, RULED 47 (a)): the checks on
// arrival end the attempt at the first bad page, with bounded requests and one reply outstanding; the honest pair
// queued behind completes. (5) flat unique blobs with no PoW at top position 10^12; (2) two alternating blobs (real
// PoW); flood: every FC_GETHEADERS answered with one real page, its first_pos claimed below the last, top at 10^12.
std::vector<pb::CarrierHeader> fake_chain(const KatNet& net, std::uint64_t n, int mode) {
    std::vector<pb::CarrierHeader> chain;
    pb::Hash32 parent = seq32(0x33);
    for (std::uint64_t k = 0; k < n; ++k) {
        pb::CarrierHeader h;
        pb::ReceiptBodyV3& r = h.own;
        r.blob.major = 16;
        r.blob.minor = 16;
        r.blob.timestamp = mon_ts(kAnchorH + 500) + 1;
        r.blob.prev_id = mon_block(kAnchorH + 500);
        const std::uint64_t b = mode == 1 ? k % 2 : k;
        r.blob.nonce = static_cast<std::uint32_t>(b);
        for (int i = 0; i < 8; ++i) r.blob.tree_root[i] = static_cast<std::uint8_t>(b >> (8 * i));
        r.payee = net.refs[0];
        r.side.pool_id = net.pool_id;
        r.side.payee = net.ids[0];
        r.side.t_origin = pb::kRuledLaneParams.d_min;
        r.side.tip = parent;
        r.side.give_author_bp = 10;
        r.reward_total = kReward;
        r.side.ballot = static_cast<std::uint16_t>(k);
        chain.push_back(h);
        parent = pb::receipt_id(r);
    }
    return chain;
}
struct FakeWire {
    std::vector<pb::CarrierHeader> chain;  // oldest first
    std::uint64_t top_pos = 1000000000000ull;
    std::uint64_t limit = 100;  // pages, then empty replies (a mutant without the checks ends, not at timeout)
    bool flood = false;         // every reply the top page, first_pos claimed lower each time
    std::uint64_t pages = 0;
    std::size_t served_lo = 0;
    std::uint64_t frame = 1u << 14;
    std::vector<std::vector<std::uint8_t>> answer(const std::vector<std::uint8_t>& req) {
        pb::GetHeaders q;
        if (req.empty() || req[0] != pb::kOpFcGetHeaders || !pb::decode_fc_getheaders(req, 0, q).ok()) return {};
        ++pages;
        pb::HeadersReply rep{0, 0, {}};
        if (pages <= limit) {
            std::size_t end = chain.size() - 1;
            if (!flood && q.stop != pb::Hash32{}) {
                if (served_lo == 0 || pb::receipt_id(chain[served_lo - 1].own) != q.stop) return {};
                end = served_lo - 1;
            }
            const std::size_t n = std::min<std::size_t>(q.max, end + 1);
            const std::size_t lo = end + 1 - n;
            for (std::size_t i = lo; i <= end; ++i) rep.headers.push_back(chain[i]);
            std::size_t packed = 0;
            (void)pb::encode_fc_headers(rep, frame, &packed);
            rep.headers.erase(rep.headers.begin(), rep.headers.end() - static_cast<std::ptrdiff_t>(packed));
            served_lo = end + 1 - packed;
            rep.first_pos = flood ? top_pos - pages * 1000 : top_pos - (chain.size() - 1 - served_lo);
        }
        return {*pb::encode_fc_headers(rep, frame)};
    }
};
void e81() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 600);
    struct Case {
        const char* name;
        int mode;
        bool flood;
        pb::AttemptEnd end;
    };
    for (const Case& c : {Case{"(5) no PoW", 0, false, pb::AttemptEnd::Header},
                          Case{"(2) alternating blobs", 1, false, pb::AttemptEnd::Contradiction},
                          Case{"flood", 2, true, pb::AttemptEnd::NotServed}}) {
        Harness h(net);
        const std::size_t s = h.nodes.size();
        h.nodes.push_back(server_from(h, a, kJ, s));
        Joining jn = joining_node(h, net, kJ);
        const std::size_t j = jn.j;
        const std::uint64_t fake_peer = 500;
        FakeWire fw;
        fw.frame = h.config(kat_table(net), false, kJ).headers_frame_bytes;
        if (c.flood) {
            for (std::uint64_t x = 600 - 40; x <= 600; ++x) fw.chain.push_back(pb::header_of(*a.bodies.get(at_pos(a, x))));
            fw.flood = true;
        } else {
            fw.chain = fake_chain(net, 600, c.mode);
            if (c.mode == 0)
                for (const pb::CarrierHeader& hd : fw.chain) h.bad_pow.insert(pb::receipt_id(hd.own));
        }
        std::uint64_t fake_requests = 0;
        jn.tr->fake = [&](std::uint64_t peer, const std::vector<std::uint8_t>& req) -> std::vector<std::vector<std::uint8_t>> {
            if (peer == fake_peer) {
                ++fake_requests;
                return fw.answer(req);
            }
            pb::PathbNode& sv = *h.nodes[peer];
            const std::uint8_t op = req.empty() ? 0 : req[0];
            if (op == pb::kOpFcGetHeaders) return sv.serve_getheaders(j, req, h.now).frames;
            if (op == pb::kOpFcGetCarrier) return sv.serve_getcarrier(j, req, h.now).frames;
            if (op == pb::kOpFcGetBuckets) return sv.serve_getbuckets(j, req, h.now).frames;
            return {};
        };
        // the fake server's HELLO (a server's HELLO from another peer id), then the honest server's
        const pb::PathbHello theirs = h[s].our_hello(4242, 0);
        (void)h[j].on_hello(fake_peer, *pb::encode_pathb_hello(theirs), h[j].our_hello(1000 + j, 0));
        (void)h.hello(j, s);
        const pb::JoinStep st = h[j].run_join();
        const std::string tag = std::string("e81 ") + c.name + ": ";
        check(st.report && st.report->server == fake_peer && st.report->end == c.end && st.report->strike == 0
                      && fake_requests <= 3 && jn.tr->peak_pending <= 1,
              tag + "the attempt ends at the first bad page with " + std::to_string(fake_requests)
                      + " requests and at most one reply outstanding" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
        pb::JoinStep st2 = h[j].run_join();
        if (st2.report && st2.report->server == fake_peer) st2 = h[j].run_join();  // a re-queued (non-service) pair first
        check(st2.switched && h[j].tree().best().id == at_pos(a, 600), tag + "the honest pair behind it completes");
    }
}

// ---------------------------------------------------------------------------
// caps: a reply carries what was asked: FC_GETCARRIER at most n frames read and only the asked ids kept; FC_HEADERS
// one frame.
void caps() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 120);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    const pb::PathbNodeConfig cfg = h.config(kat_table(net), false, kJ);
    KatTransport tr(h, 77);
    pb::BucketWindow window(cfg.bucket_policy);
    pb::PathbJoinLink link(s, tr, 0, cfg.p, cfg.buffers, cfg.headers_frame_bytes, window);
    const std::vector<pb::Hash32> ids{at_pos(a, 10), at_pos(a, 11), at_pos(a, 12)};
    tr.edit = [&](std::uint64_t, std::uint8_t op, std::vector<std::vector<std::uint8_t>>& reply) {
        if (op == pb::kOpFcGetCarrier) {
            // a body nobody asked for in place of the second frame, the asked one after it, then a garbage frame
            const std::vector<std::uint8_t> extra = *pb::encode_fc_carrier(0, *a.bodies.get(at_pos(a, 50)), pb::kRuledLaneParams.r_max);
            reply.insert(reply.begin() + 1, extra);
            reply.push_back(std::vector<std::uint8_t>{0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13});
        }
        if (op == pb::kOpFcGetHeaders) reply.push_back(std::vector<std::uint8_t>{0x53, 0x02, 0x00, 0x00, 0x00, 0x00, 0x13});
    };
    const pb::CarrierFrames cf = link.carriers(ids, true, 11);
    bool asked = true;
    for (const pb::CarrierBodyV3& b : cf.bodies) asked = asked && std::find(ids.begin(), ids.end(), pb::receipt_id(b.own)) != ids.end();
    check(cf.status == pb::LinkStatus::Served && cf.bodies.size() == 2 && asked && link.strikes() == 0,
          "caps: an FC_GETCARRIER of 3 ids answered with an unasked body among 4 frames and a garbage frame after them: 3 "
          "frames read, the unasked body not kept, nothing struck (" + std::to_string(cf.bodies.size()) + " kept)");
    const pb::ChainHeaders ch = link.headers(at_pos(a, 100), 20, 11);
    check(ch.status == pb::LinkStatus::Served && ch.headers.size() == 20 && link.strikes() == 0,
          "caps: an FC_HEADERS reply with a second (garbage) frame: the first read, nothing struck");
}

// ---------------------------------------------------------------------------
// disconnect: the attempt's server disconnects while the attempt runs (an owner event between its requests): the link
// stays alive to the attempt's end, answers nothing more, the attempt ends as non-service and the pair is dropped.
void disconnect() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 4704);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    Joining jn = joining_node(h, net, kJ);
    const std::size_t j = jn.j;
    bool gone = false;
    jn.tr->on_request = [&]() {
        if (gone || jn.tr->log.size() != 3) return;
        gone = true;
        h[j].disconnect(s);
    };
    h.hello(j, s);
    const pb::JoinStep st = h[j].run_join();
    check(gone && st.report && st.report->end == pb::AttemptEnd::NotServed && !st.switched && h[j].join_link(s) == nullptr
                  && h[j].joiner().queue().size() == 0 && jn.tr->log.size() <= 4,
          "disconnect: the server gone mid-attempt: its link answers nothing more, the attempt ends non-service, the "
          "pair dropped (" + std::to_string(jn.tr->log.size()) + " requests)" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
}

// ---------------------------------------------------------------------------
// floors: a server keeping only from its P-51 floors at L 6,000 / 6,010 / 6,020 / 6,030 (its floor page cut at its
// header floor): the attempt asks no header below its own prefix start and completes. archival: an archival server
// (nothing pruned): the lowest header asked is the prefix start's lowest read record; the header requests one per page.
void floors() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 6000);
    for (const std::uint64_t L : {6000ull, 6010ull, 6020ull, 6030ull}) {
        if (a.store.tip_pos() < L) grow(a, L - a.store.tip_pos());
        for (const bool prune : {true, false}) {
            Harness h(net);
            const std::size_t s = h.nodes.size();
            h.nodes.push_back(server_from(h, a, kJ, s));
            Joining jn = joining_node(h, net, kJ);
            jn.tr->prune = prune;
            std::uint64_t lowest = UINT64_MAX;
            std::uint64_t pages = 0;
            jn.tr->edit = [&](std::uint64_t, std::uint8_t op, std::vector<std::vector<std::uint8_t>>& reply) {
                if (op != pb::kOpFcGetHeaders || reply.empty()) return;
                pb::HeadersReply rep;
                if (pb::decode_fc_headers(reply[0], 0, 1u << 22, pb::kRuledLaneParams, rep).ok() && !rep.headers.empty()) {
                    lowest = std::min(lowest, rep.first_pos);
                    ++pages;
                }
            };
            h.hello(jn.j, s);
            const pb::JoinStep st = h[jn.j].run_join();
            const auto rec = [&](std::uint64_t x) -> std::optional<std::uint64_t> {
                const std::optional<pb::Hash32> id = a.store.best_at(x);
                if (!id) return std::nullopt;
                return a.node(*id).H;
            };
            const pb::SpanResult sp = pb::span_bounds(pb::kRuledLaneParams, L, rec, kLaneB0);
            const pb::PreStart ps = pb::pre_start(pb::kRuledLaneParams, sp.bounds.x0, rec);
            const std::string tag = std::string(prune ? "floors" : "archival") + " at L " + std::to_string(L) + ": ";
            check(st.report && st.report->end == pb::AttemptEnd::Completed && st.switched && lowest >= ps.read_lo,
                  tag + "completes; the lowest header asked " + std::to_string(lowest) + " >= the prefix start's lowest read "
                          "record " + std::to_string(ps.read_lo) + " (" + std::to_string(pages) + " pages)"
                          + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
        }
    }
}

// ---------------------------------------------------------------------------
// emptystore (ruling 39 P-S4w-6): an empty store at position 0 (no load failure) queues no pair on a HELLO; it
// catches up headers first from position 0 against a server that keeps everything.
void emptystore() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 600);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    const std::size_t e = h.add(kat_table(net), false, kJ);
    KatTransport tr(h, e);
    h[e].set_join_transport(&tr);
    const pb::HelloCheck hc = h.hello(e, s);
    const std::size_t queued = h[e].joiner().queue().size();
    h.mon_tip = h_pos(600) + 1;
    h.q.clear();
    // the relay node's catch-up (S4w-bc): headers first from the node's tip, the bodies of a heavier branch, again
    bool asked = true;
    for (int round = 0; round < 100 && asked && h[e].tree().best().id != a.store.best_tip(); ++round) {
        asked = h[e].request_headers(s, h[e].tree().best().id, a.store.best_tip(), 8000, h.now);
        h.pump();
    }
    check(hc.verdict == pb::HelloVerdict::Accept && queued == 0 && asked && h[e].tree().best().id == at_pos(a, 600)
                  && h[e].joiner().queue().size() == 0 && !h[e].rests_on_claims(),
          "emptystore: an empty store queues no pair on a HELLO and catches up headers first from position 0 to the "
          "server's tip (" + std::to_string(h[e].tree().best().pos) + ")");
}

// ---------------------------------------------------------------------------
// split (C-10): the attempt (attempt_join) changes nothing of the node; its outcome is applied by apply_join.
void split() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 600);
    Harness h(net);
    const std::size_t s = h.nodes.size();
    h.nodes.push_back(server_from(h, a, kJ, s));
    Joining jn = joining_node(h, net, kJ);
    const std::size_t j = jn.j;
    MemoryKv& kv = *h.kvs.back();
    const pb::LaneKv before = kv.data;
    h.hello(j, s);
    pb::JoinAttempted t = h[j].attempt_join();
    const bool unchanged = h[j].joined() == nullptr && h[j].rests_on_claims() && h[j].tree().best().pos == 0
                           && kv.data == before && t.attempt && t.attempt->report.end == pb::AttemptEnd::Completed;
    const pb::JoinStep st = h[j].apply_join(std::move(t));
    check(unchanged && st.switched && st.batch_written && h[j].joined() != nullptr && h[j].tree().best().id == at_pos(a, 600),
          "split: the completed attempt changes nothing of the node; apply_join adopts it and writes the batch");
}

// ---------------------------------------------------------------------------
// restart (E-38): a load failure survives a restart: the failed store is kept until an adoption, so a second start
// with --pathb-launch and no peer is a load failure again (no relaunch from genesis).
void restart() {
    JoinNet net(900);
    KatNode a(net, kJ);
    grow(a, 30);
    Harness h(net);
    for (const int failure : {0, 1}) {
        h.kvs.push_back(std::make_unique<MemoryKv>());
        MemoryKv& kv = *h.kvs.back();
        // a written store (genesis) with its failure: the poison mark, or an unreadable head
        {
            const std::size_t w = h.nodes.size();
            h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), true, kJ), h.io(w), &kv));
        }
        if (failure == 0) kv.data[pb::store_keys::poison(0)] = std::string(1, '\x01');
        else kv.read_error.insert(pb::store_keys::phead(0));
        const pb::StoreFault f1 = pb::pathb_load(kv, net.pool_id, net.rules_g, load_inputs(net, kJ)).fault;
        const std::size_t n1 = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), true, kJ), h.io(n1), &kv, pb::PathbNode::LoadFailed{}));
        h.mon_tip = h_pos(1) + 1;
        (void)h[n1].on_carrier(77, *pb::encode_fc_carrier(0, *a.bodies.get(at_pos(a, 1)), pb::kRuledLaneParams.r_max));
        h.q.clear();
        // the restart
        const pb::LoadResult l2 = pb::pathb_load(kv, net.pool_id, net.rules_g, load_inputs(net, kJ));
        const std::size_t n2 = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), true, kJ), h.io(n2), &kv, pb::PathbNode::LoadFailed{}));
        check(f1 != pb::StoreFault::None && f1 != pb::StoreFault::NoHead && l2.fault == f1
                      && h[n2].make_template(h.now).status == pb::TemplateStatus::RestsOnClaims,
              std::string("restart (") + (failure == 0 ? "the poison mark" : "an unreadable head")
                      + "): the second start is the same load failure; with --pathb-launch and no peer no template (no "
                        "relaunch from genesis)");
    }
}

// ---------------------------------------------------------------------------
// j2: a node that joined and followed its chain on serves a later join: its claimed prefix headers down to E-102's
// floor, its span bodies and buckets (from memory, and from its store after a restart).
void j2() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    const std::uint64_t L = 6000, more = 120;
    KatNode a(net, kJ);
    grow(a, L);
    Harness h(net);
    Joined jd = join_at(h, net, a, kJ);
    check(jd.ok, "j2: the first node joined at L");
    if (!jd.ok) return;
    const std::size_t j = jd.jn.j;
    const std::vector<pb::Hash32> next = grow(a, more);
    h.mon_tip = h_pos(L + more) + 1;
    for (const pb::Hash32& id : next)
        (void)h[j].on_carrier(jd.s, *pb::encode_fc_carrier(0, *a.bodies.get(id), pb::kRuledLaneParams.r_max));
    h.q.clear();
    check(h[j].tree().best().id == a.store.best_tip(), "j2: the joined node followed its chain to L + 120");
    Joining k = joining_node(h, net, kJ);
    h.hello(k.j, j);
    const pb::JoinStep st = h[k.j].run_join();
    check(st.report && st.report->end == pb::AttemptEnd::Completed && st.switched && h[k.j].tree().best().id == a.store.best_tip(),
          "j2: a second node joins from the joined node" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    // the joined node restarted from its store
    MemoryKv& kv = *h.kvs[h.kvs.size() - 2];
    pb::LoadResult rl = pb::pathb_load(kv, net.pool_id, net.rules_g, load_inputs(net, kJ));
    check(rl.fault == pb::StoreFault::None && rl.state && !rl.state->prefix_headers.empty(),
          "j2: the joined store reloads with its claimed prefix headers (" + std::to_string(rl.state ? rl.state->prefix_headers.size() : 0) + ")");
    if (!rl.state) return;
    const std::size_t r = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(net), false, kJ), h.io(r), std::move(*rl.state), nullptr));
    Joining k2 = joining_node(h, net, kJ);
    h.hello(k2.j, r);
    const pb::JoinStep st2 = h[k2.j].run_join();
    check(st2.report && st2.report->end == pb::AttemptEnd::Completed && st2.switched,
          "j2: a third node joins from the joined node restarted from its store" + (st2.report ? std::string(": ") + rep_desc(*st2.report) : std::string()));
    std::printf("  j2: %.1f s\n", secs_since(t0));
}

// ---------------------------------------------------------------------------
// below (RULED 46 S4wa-1 (b)): a joined node whose fork with a heavier chain lies below its first record (below what
// it holds): the peer's HELLO tip is a candidate, the attempt completes and rule (4) replaces A.
void below() {
    const auto t0 = std::chrono::steady_clock::now();
    JoinNet net(900);
    const std::uint64_t L = 6000, f = 200;
    ChainShape sb;
    sb.nonce0 = 7300000;
    KatNode a(net, kJ);
    grow(a, f);
    KatNode b(a);
    grow(a, L - f);
    grow(b, L + 200 - f, sb);
    Harness h(net);
    Joined jd = join_at(h, net, a, kJ);
    check(jd.ok, "below: joined at L");
    if (!jd.ok) return;
    const std::size_t j = jd.jn.j;
    const std::uint64_t first = h[j].store().first_record_pos();
    const std::size_t sb_ = h.nodes.size();
    h.nodes.push_back(server_from(h, b, kJ, sb_));
    (void)h.hello(j, sb_);
    h.mon_tip = h_pos(L + 200) + 1;
    const pb::JoinStep st = h[j].run_join();
    check(f < first && st.report && st.report->end == pb::AttemptEnd::Completed && st.sw.replaced
                  && h[j].tree().best().id == b.store.best_tip(),
          "below: the fork " + std::to_string(f) + " below the first record " + std::to_string(first)
                  + ": a candidate; rule (4) replaces A" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
    std::printf("  below: %.1f s\n", secs_since(t0));
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_node_join_kat\n");
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*fn)()) {
        if (only.empty() || only == name) run_part(name, fn);
    };
    run("loadfail", loadfail);
    run("young", young);
    run("scope", scope);
    run("tokens", tokens);
    run("fetchahead", fetchahead);
    run("deep", deep);
    run("partition", partition);
    run("x1", x1);
    run("reask", reask);
    run("adoptbelow", adoptbelow);
    run("e81", e81);
    run("caps", caps);
    run("disconnect", disconnect);
    run("floors", floors);
    run("emptystore", emptystore);
    run("split", split);
    run("restart", restart);
    run("j2", j2);
    run("below", below);
    return finish("v37_xmr_pathb_node_join_kat");
}
