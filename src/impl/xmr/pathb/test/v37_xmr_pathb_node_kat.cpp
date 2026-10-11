// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_node_kat.cpp
// PathbNode (c2pool/v37/xmr/pathb/pathb_node.hpp): three in-process nodes, a
// RandomX stub and a scripted Monero chain.
//   genesis      position 0 = (pool_id, H + 1) on every node; an empty store
//                with no Path B peer builds no template until --pathb-launch;
//                with a peer it builds;
//   relay        carriers mined on one node reach the others through
//                FC_CARRIER; every node builds the same coinbase bytes for every
//                tip; Sum(vout) == B(P_r) + F (C48, no penalty);
//   race         a sibling race: the losing node switches and re-pends its own
//                receipt; the next carriers carry it (no uncles; credited at
//                its origin bin);
//   carriage     17 carriable pending receipts: the first 16 in the canonical
//                order; a carriable receipt is carried by default (R2);
//   repend       a switch by the journal re-pends the abandoned placements
//                whose bin is open on the new branch, without a second hash;
//                one whose bin sealed on the new branch is lost (C49);
//   own          the node's own share is admitted with its own hash (no
//                verify call; carried bodies from the memo) (E5, E5b);
//   m23          a best switch between RandomX and placement re-runs the
//                cheap rows, RandomX not again;
//   restart      a node reloaded from its store has the live lane digest and
//                builds the same coinbase bytes;
//   n5           a store refusing switch_best after the marks: NodeInternal,
//                the tree's best at c's parent, the store poisoned, no
//                template (REVIEW-1976 N-5 after the merged undo);
//   hold         a kind-2 activation at its fixed height on the nodes whose
//                build implements it; a node whose build does not holds: no
//                template, its frames DEFERred, no strike;
//   c48          a non-tail chain (B(A_t) != B(P_r)): Sum(vout) == B(P_r) + F;
//                the penalty fill: R == reward_for_child(Z, T + c, B) + F;
//   rrfix3       one depth measure: a joined-shape node (its base above tip -
//                J) meets a heavier branch forked in [tip - J, base): the
//                joiner path, no body fetched;
//   joinserve    the serving side of a join: join_serve_floors at the best
//                tip ({0, 0} on the young chain); an attempt's first request
//                holds its floors while new items at or below its L follow
//                within P-53; a repeated item or one above L does not continue
//                it; a disconnect closes it;
//   n7b2         B-2 bounded serving (FC_GETHEADERS <= max; FC_GETBUCKETS <=
//                the P-48 cap); N-7: a header failing its PoW at d BANs its
//                server and indexes no variant (across pages: the server's
//                earlier variants released); the honest branch indexed after
//                its PoW, its bodies fetched, the switch by headers first;
//   startup      the start-up refusals in E1's order (the first failing
//                step refuses; a later failing input does not decide);
//   deep         (e) on BinStore + S + AR (D37): a fork at journal depth J
//                switches by the journal; at J + 1 (below the journal base)
//                its bodies DEFER (OwnChainDeep, 0 tokens) and its headers
//                take the joiner path, the store untouched;
//   poison       the store poisoned: the latch first in every event
//                (NodeInternal, nothing judged, pended or flooded), the status
//                alarm, the poison mark (the next load fails); the empty-store
//                start writes into an empty store;
//   joinpages    FC_GETHEADERS with from = the zero id: the at most
//                min(max, pos(stop), a frame) headers ending at stop, oldest
//                first, first_pos claimed; side parts; position 0 never;
//   tokens       family C token classes (undecodable STRIKE, above the buffer
//                DROP); FC_GETHEADERS at most P-01; the pending set's eviction;
//   receive      FC_BUCKETS undecodable from an asked server (refuse + 1
//                strike); closed / abandoned keys go with the peer; a parked
//                chain released iteratively; BadServed BAN releases; a request
//                accumulates at most its max;
//   hellobound   the HELLO leaf count compared on a placed best tip only;
//   base         the header path forked exactly at the journal base switches
//                by the journal; a refused switch_best on a reorg: NodeInternal;
//   boundary     the carried list leaves out a pending receipt whose tip
//                forks more than J_0 below the carrier's parent (ruling 40);
//   timers       P-53 per request restarted per frame, a timeout is
//                non-service; the FC_BUCKETS window (FIX-1);
//   buckets      a full node's FC_GETBUCKETS: one assembly per (peer, at), a
//                prefix assembled across frames P-53 - 1 s apart, a gap of
//                P-53 + 1 s ends it and the late frame DROPs, 0 tokens.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_startup.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_ratchet_sim.hpp"


namespace c2pool::xmr::pathb {
// The KATs' view of a node's private state.
struct PathbNodeTestAccess {
    static void add_pending(PathbNode& n, PendingReceipt r) { n.pending_.add(std::move(r)); }
    static std::vector<ReceiptBodyV3> carried(PathbNode& n, std::uint64_t x, std::uint64_t h) { return n.carried_list(x, h); }
    static const HeaderIndex& headers(const PathbNode& n) { return *n.headers_; }
    static std::uint64_t max_settle_depth(const PathbNode& n) { return n.max_settle_depth_; }
    static std::size_t closed(const PathbNode& n) { return n.closed_.size(); }
    static std::size_t abandoned(const PathbNode& n) { return n.abandoned_.size(); }
};
}  // namespace c2pool::xmr::pathb

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::EpochTable table0(const KatNet& net) { return kat_table(net); }

// ---------------------------------------------------------------------------
void genesis() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net)), b = h.add(table0(net)), c = h.add(table0(net), true);
    bool same = true;
    for (std::size_t i : {a, b, c})
        same = same && h[i].tree().genesis().id == net.pool_id && h[i].tree().genesis().H == kPoolH + 1
               && h[i].store().b0() == kPoolH + 1;
    check(same, "genesis: position 0 = (pool_id, H + 1) on every node; b0 = H(0)");
    check(h[a].make_template(h.now).status == pb::TemplateStatus::NoPathbPeer,
          "an empty store with no Path B peer builds no template");
    check(h[c].make_template(h.now).status == pb::TemplateStatus::Ok, "with --pathb-launch it builds");
    const pb::PathbHello hc = h[c].our_hello(11, 0);
    const std::vector<std::uint8_t> hf = *pb::encode_pathb_hello(hc);
    const pb::HelloCheck hk = h[a].on_hello(c, hf, h[a].our_hello(12, 0));
    check(hk.verdict == pb::HelloVerdict::Accept && h[a].has_pathb_peer(), "a HELLO from a Path B peer accepted");
    check(h[a].make_template(h.now).status == pb::TemplateStatus::Ok, "with a Path B peer it builds");
    (void)b;
}

// ---------------------------------------------------------------------------
void relay() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    h.add(table0(net));
    h.add(table0(net));
    h.txs = {{seq32(0xE1), 2000, 3000000}, {seq32(0xE2), 1500, 2000000}};
    bool placed = true, same_tip = true, same_cb = true, sum_ok = true;
    for (int i = 0; i < 30; ++i) {
        if (i % 3 == 0) h.tick_monero();
        const pb::NodeEventResult r = h.mine(a, static_cast<std::size_t>(i % 5), 100 + i);
        placed = placed && r.action == pb::NodeAction::Placed;
        same_tip = same_tip && h[0].tree().best().id == h[1].tree().best().id && h[1].tree().best().id == h[2].tree().best().id;
        const std::vector<std::uint8_t> c0 = coinbase_bytes(h, 0, 3), c1 = coinbase_bytes(h, 1, 3), c2 = coinbase_bytes(h, 2, 3);
        same_cb = same_cb && !c0.empty() && c0 == c1 && c1 == c2;
        const pb::PathbTemplate t = h[0].make_template(h.now);
        const std::optional<pb::PathbJob> j = h[0].make_job(t, h.session(3));
        sum_ok = sum_ok && j && vout_sum(j->miner_tx) == t.base + t.fees && t.reward == t.base + t.fees && t.fees == 5000000;
    }
    check(placed, "relay: 30 carriers mined by A are placed (extensions)");
    check(same_tip && h[0].tree().best().pos == 30, "relay: A, B and C reach the same best tip through FC_CARRIER");
    check(same_cb, "relay: the three nodes build the same coinbase bytes for every tip");
    check(sum_ok, "relay (C48): Sum(vout) == B(P_r) + F with no penalty");
    check(h.rx_calls > 0 && h[0].verify_calls() == 0, "relay: B and C hash every relayed carrier; A never hashes its own");
}

// ---------------------------------------------------------------------------
void race() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(a, 1, 10 + i);
    }
    // a sibling race on one tip: A and B each find a carrier, the links cut while they do
    h.cut = {{a, b}, {b, a}};
    h.mine(a, 2, 900);
    h.mine(b, 3, 901);
    const pb::Hash32 ca = h[a].tree().best().id, cb = h[b].tree().best().id;
    check(ca != cb && h[a].tree().best().pos == h[b].tree().best().pos, "race: two siblings at one position");
    h.cut.clear();
    // each node's carrier to the other
    const std::vector<std::uint8_t> fa = *pb::encode_fc_carrier(0, *h[a].bodies().get(ca), 16);
    const std::vector<std::uint8_t> fb = *pb::encode_fc_carrier(0, *h[b].bodies().get(cb), 16);
    const pb::NodeEventResult ra = h[a].on_carrier(b, fb);
    const pb::NodeEventResult rb = h[b].on_carrier(a, fa);
    h.pump();
    const pb::Hash32 winner = ca < cb ? ca : cb, loser = ca < cb ? cb : ca;
    const std::size_t lnode = ca < cb ? b : a;
    check(h[a].tree().best().id == winner && h[b].tree().best().id == winner, "race: equal work, the lower id wins on both");
    const pb::NodeEventResult& sw = lnode == a ? ra : rb;
    check(sw.action == pb::NodeAction::Switched && sw.repended >= 1, "race: the losing node switches and re-pends its own receipt");
    check(h[lnode].pending().holds(loser), "race: the losing carrier's receipt is pending again (no uncle)");
    // the next carrier carries it, credited at its origin bin
    h.tick_monero();
    const std::optional<pb::PathbJob> j = h.job(lnode, 4, 77);
    bool carried = false;
    for (const pb::ReceiptBodyV3& r : j ? j->carried : std::vector<pb::ReceiptBodyV3>{}) carried = carried || pb::receipt_id(r) == loser;
    check(carried, "race: the next job carries the losing receipt");
    h[lnode].on_own_share(*j, 77, pb::Hash32{});
    h.pump();
    const pb::LaneView v = h[a].store().view_at(h[a].tree().best().id);
    check(v.ok() && v.placed_open(loser) && h[a].tree().best().id == h[b].tree().best().id,
          "race: the losing receipt is placed on the best chain at both nodes (credited in its open origin bin)");
}

// ---------------------------------------------------------------------------
void carriage() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        h.mine(a, 1, 20 + i);
    }
    // 17 jobs on one tip; a new carrier moves the best tip; the 17 shares become pending receipts
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 17; ++k) jobs.push_back(*h.job(a, k + 2, 500 + k));
    h.mine(a, 1, 30);
    std::size_t pend = 0;
    for (std::uint32_t k = 0; k < 17; ++k) pend += h[a].on_own_share(jobs[k], 500 + k, pb::Hash32{}).action == pb::NodeAction::Pending ? 1 : 0;
    check(pend == 17 && h[a].pending().size() == 17, "carriage: 17 shares on a lost tip are pending receipts");
    const std::optional<pb::PathbJob> j = h.job(a, 1, 31);
    bool order = j.has_value() && j->carried.size() == 16;
    std::vector<pb::CarriedKey> keys;
    for (const pb::ReceiptBodyV3& r : j ? j->carried : std::vector<pb::ReceiptBodyV3>{})
        keys.push_back(pb::CarriedKey{h_of(net, r), pb::receipt_id(r)});
    order = order && pb::carried_order_ok(keys, h[a].tree().best().id);
    // the 17th is the last in the canonical order
    std::vector<std::pair<pb::CarriedKey, pb::Hash32>> all;
    for (const pb::PendingReceipt* p : h[a].pending().all()) all.emplace_back(pb::CarriedKey{p->h, p->id}, p->id);
    std::sort(all.begin(), all.end(), [&](const auto& x, const auto& y) { return pb::carried_key_less(x.first, y.first, h[a].tree().best().id); });
    bool first16 = order;
    for (std::size_t k = 0; first16 && k < 16; ++k) first16 = pb::receipt_id(j->carried[k]) == all[k].second;
    check(order && first16, "carriage: 17 carriable -> the first 16 in the canonical order");
    h[a].on_own_share(*j, 31, pb::Hash32{});
    const std::optional<pb::PathbJob> j2 = h.job(a, 1, 32);
    check(j2 && j2->carried.size() == 1 && pb::receipt_id(j2->carried[0]) == all[16].second,
          "carriage: the remaining carriable receipt is carried by the next job (no omission)");
}

// ---------------------------------------------------------------------------
void repend() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 5; ++i) {
        h.tick_monero();
        h.mine(a, 1, 40 + i);
    }
    // B alone: shares on a stale tip (pending), then a branch X carrying them (2 carriers)
    h.cut = {{a, b}, {b, a}};
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 3; ++k) jobs.push_back(*h.job(b, 5 + k, 600 + k));
    h.mine(b, 9, 610);
    for (std::uint32_t k = 0; k < 3; ++k) h[b].on_own_share(jobs[k], 600 + k, pb::Hash32{});
    h.mine(b, 9, 611);  // carries the three
    const std::uint64_t carried_x = h[b].bodies().get(h[b].tree().best().id)->carried.size();
    check(carried_x == 3, "repend: branch X carries the three receipts");
    // A alone: a heavier branch Y (3 carriers) from the same fork
    for (int i = 0; i < 3; ++i) h.mine(a, 2, 620 + i);
    h.cut.clear();
    const std::uint64_t rx_before = h.rx_calls;
    // Y reaches B: B switches by its journal
    std::vector<pb::NodeEventResult> rs;
    for (std::uint64_t x = 6; x <= 8; ++x) {
        const pb::Hash32 id = *h[a].store().best_at(x);
        rs.push_back(h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(id), 16)));
    }
    std::uint64_t repended = 0;
    bool switched = false;
    for (const pb::NodeEventResult& r : rs) {
        repended += r.repended;
        switched = switched || r.action == pb::NodeAction::Switched;
    }
    check(switched && h[b].tree().best().id == h[a].tree().best().id, "repend: B switches to Y by its journal");
    check(repended >= 5, "repend (C49): X's placements (2 carriers, 3 carried) are pending again on Y");
    check(h.rx_calls - rx_before == 3, "repend: the re-pended bodies are not hashed again (only Y's 3 carriers)");
    const std::optional<pb::PathbJob> j = h.job(b, 9, 640);
    check(j && j->carried.size() >= 5, "repend: the next job carries the re-pended receipts");
    h.pump();
    // a switch to a branch whose record passed an abandoned placement's origin bin: lost, not re-pended
    Harness g(net);
    const std::size_t c = g.add(table0(net), true), e = g.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        g.tick_monero();
        g.mine(c, 1, 40 + i);
    }
    std::vector<pb::PathbJob> old_jobs;
    for (std::uint32_t k = 0; k < 3; ++k) old_jobs.push_back(*g.job(e, 5 + k, 800 + k));
    const std::uint64_t h_r = old_jobs[0].h;
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;
    for (int i = 0; i < 400 && g[c].tree().best().H < h_r + F - 4; ++i) {
        g.tick_monero(2);
        g.mine(c, 1, 50 + i);
    }
    // the old shares: pending at E (their bin still open)
    std::size_t pend = 0;
    for (std::uint32_t k = 0; k < 3; ++k)
        if (g[e].on_own_share(old_jobs[k], 800 + k, pb::Hash32{}).action == pb::NodeAction::Pending) ++pend;
    g.pump();
    g.cut = {{c, e}, {e, c}};
    g.mine(e, 9, 900);  // X: one carrier carrying them
    const pb::CarrierBodyV3* xb = g[e].bodies().get(g[e].tree().best().id);
    const std::size_t x_carried = xb ? xb->carried.size() : 0;
    const std::uint64_t x_pos = g[e].tree().best().pos;
    for (int i = 0; i < 400 && (g[c].tree().best().pos < x_pos + 1 || g[c].tree().best().H < h_r + F); ++i) {
        g.tick_monero(2);
        g.mine(c, 2, 950 + i);
    }
    g.cut.clear();
    std::uint64_t lost = 0, rep = 0;
    bool sw = false;
    std::uint64_t H_sw = 0;
    for (std::uint64_t x = x_pos; x <= g[c].store().tip_pos(); ++x) {
        const pb::Hash32 id = *g[c].store().best_at(x);
        const pb::NodeEventResult r = g[e].on_carrier(c, *pb::encode_fc_carrier(0, *g[c].bodies().get(id), 16));
        lost += r.lost;
        rep += r.repended;
        if (r.action == pb::NodeAction::Switched) {
            sw = true;
            H_sw = g[e].tree().best().H;
        }
    }
    bool none_pending = true;
    for (std::uint32_t k = 0; k < 3; ++k) {
        pb::ReceiptBodyV3 rb = old_jobs[k].body;
        rb.blob.nonce = 800 + k;
        none_pending = none_pending && !g[e].pending().holds(pb::receipt_id(rb));
    }
    check(pend == 3 && x_carried == 3 && sw && H_sw >= h_r + F && lost == 3 && rep == 1 && none_pending,
          "repend (C49): the 3 carried receipts' origin bin " + std::to_string(h_r) + " sealed on the new branch (H "
                  + std::to_string(H_sw) + "): lost " + std::to_string(lost) + "; X's own receipt re-pended ("
                  + std::to_string(rep) + "); pending " + std::to_string(pend) + ", carried " + std::to_string(x_carried));
    g.pump();
}

// ---------------------------------------------------------------------------
// n-3: a receipt the pending set (P-09) evicts at once is neither relayed nor counted as re-pended.
void n3() {
    const KatNet net;
    {
        Harness h(net);
        h.pending_cap = 1;
        const std::size_t a = h.add(table0(net), true);
        (void)h.add(table0(net), true);
        for (int i = 0; i < 4; ++i) {
            h.tick_monero();
            h.mine(a, 1, 20 + i);
        }
        std::vector<pb::PathbJob> jobs;
        for (std::uint32_t k = 0; k < 2; ++k) jobs.push_back(*h.job(a, k + 2, 500 + k));
        h.mine(a, 1, 30);
        const auto rid = [&](std::size_t k) {
            pb::ReceiptBodyV3 r = jobs[k].body;
            r.blob.nonce = static_cast<std::uint32_t>(500 + k);
            return pb::receipt_id(r);
        };
        const std::size_t hi = rid(0) < rid(1) ? 1 : 0, lo = 1 - hi;  // one tip, one h: the lower id goes first
        const pb::NodeEventResult r_hi = h[a].on_own_share(jobs[hi], static_cast<std::uint32_t>(500 + hi), pb::Hash32{});
        h.q.clear();
        const pb::NodeEventResult r_lo = h[a].on_own_share(jobs[lo], static_cast<std::uint32_t>(500 + lo), pb::Hash32{});
        bool relayed = false;
        for (const Msg& m : h.q) relayed = relayed || (m.from == a && !m.frame.empty() && m.frame[0] == pb::kOpFbReceipts);
        h.q.clear();
        check(r_hi.action == pb::NodeAction::Pending && r_lo.action == pb::NodeAction::None && !relayed
                      && h[a].pending().size() == 1 && h[a].pending().holds(rid(hi)),
              "n3: with a pending cap of 1 a share the pending set evicts at once is not pending and not relayed (action "
                      + std::to_string(static_cast<int>(r_lo.action)) + ")");
    }
    {
        // B (P-09 = 1): X = 2 carriers; a share P on X1 at a later Monero height pending; a heavier Y from A: the
        // re-pend of X's own receipts (older origin bins, or P's bin and tip with a lower id) evicted at once
        Harness h(net);
        const std::size_t a = h.add(table0(net), true);
        h.pending_cap = 1;
        const std::size_t b = h.add(table0(net), true);
        for (int i = 0; i < 5; ++i) {
            h.tick_monero();
            h.mine(a, 1, 40 + i);
        }
        h.cut = {{a, b}, {b, a}};
        h.mine(b, 9, 610);
        const pb::Hash32 x1 = h[b].tree().best().id;
        h.tick_monero(2);
        const pb::PathbJob jp = *h.job(b, 7, 612);
        h.mine(b, 9, 611);
        const pb::Hash32 x2 = h[b].tree().best().id;
        const pb::NodeEventResult rp = h[b].on_own_share(jp, 612, pb::Hash32{});
        pb::ReceiptBodyV3 pr = jp.body;
        pr.blob.nonce = 612;
        const pb::Hash32 p_id = pb::receipt_id(pr);
        const pb::Hash32 x2_own = pb::receipt_id(h[b].bodies().get(x2)->own);
        for (int i = 0; i < 3; ++i) h.mine(a, 2, 620 + i);
        h.cut.clear();
        h.q.clear();
        std::uint64_t rep = 0;
        bool switched = false;
        for (std::uint64_t x = 6; x <= 8; ++x) {
            const pb::Hash32 id = *h[a].store().best_at(x);
            const pb::NodeEventResult r = h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(id), 16));
            rep += r.repended;
            switched = switched || r.action == pb::NodeAction::Switched;
        }
        h.q.clear();
        const std::uint64_t want = x2_own > p_id ? 1 : 0;  // X2's own receipt has P's bin and tip: the id orders
        check(rp.action == pb::NodeAction::Pending && x1 != x2 && switched && rep == want && h[b].pending().size() == 1,
              "n3: a re-pended receipt the pending set evicts at once is not counted (re-pended " + std::to_string(rep)
                      + ", expected " + std::to_string(want) + " of X's 2)");
    }
}

// ---------------------------------------------------------------------------
void own_share() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 50 + i);
    }
    // B's share relayed to A as a pending receipt (A hashes it once), then carried by A's own carrier
    h.cut = {{b, a}};
    const pb::PathbJob jb = *h.job(b, 6, 700);
    h.mine(b, 7, 701);
    h.cut.clear();
    const pb::NodeEventResult pr = h[b].on_own_share(jb, 700, pb::Hash32{});
    h.pump();
    check(pr.action == pb::NodeAction::Pending && h[a].pending().size() == 1, "own: B's late share is pending at A");
    const std::uint64_t calls = h[a].verify_calls();
    const std::optional<pb::PathbJob> ja = h.job(a, 1, 702);
    const pb::NodeEventResult r = h[a].on_own_share(*ja, 702, pb::Hash32{});
    check(ja->carried.size() == 1 && r.action == pb::NodeAction::Placed && h[a].verify_calls() == calls,
          "own (E5, E5b): A's own carrier is admitted with its own hash; its carried body from the memo (no verify call)");
    // a share whose hash does not meet d is refused (BAN at the own body's RandomX row)
    pb::Hash32 big{};
    big.fill(0xff);
    const std::optional<pb::PathbJob> j2 = h.job(a, 1, 703);
    const pb::NodeEventResult r2 = h[a].on_own_share(*j2, 703, big);
    check(r2.action == pb::NodeAction::Verdict && r2.admit.verdict == pb::AdmitVerdict::Ban, "own: a hash above the target is refused");
}

// ---------------------------------------------------------------------------
void m23() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true), c = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 60 + i);
    }
    // C builds a carrier on the tip; B builds a heavier branch of two from the same tip (cut from A)
    h.cut = {{b, a}, {c, a}, {b, c}, {c, b}};
    h.mine(c, 3, 800);
    const pb::Hash32 cc = h[c].tree().best().id;
    h.mine(b, 4, 801);
    h.mine(b, 4, 802);
    h.cut.clear();
    // A admits C's frame (cheap rows + RandomX), then B's branch switches A's best, then the placement
    const std::vector<std::uint8_t> fc = *pb::encode_fc_carrier(0, *h[c].bodies().get(cc), 16);
    pb::PathbNode::CarrierTicket t = h[a].begin_carrier(c, fc);
    const std::uint64_t rx_after_begin = h.rx_calls;
    for (std::uint64_t x = 4; x <= 5; ++x) {
        const pb::Hash32 id = *h[b].store().best_at(x);
        h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(id), 16));
    }
    const std::uint64_t gen = h[a].best_changes();
    const std::uint64_t rx_mid = h.rx_calls;
    const pb::NodeEventResult r = h[a].complete_carrier(std::move(t));
    check(t.generation != gen && h.rx_calls == rx_mid && rx_mid > rx_after_begin,
          "m23: the best changed between RandomX and the placement; the cheap rows re-ran, RandomX not again");
    check(r.action == pb::NodeAction::SideBranch && h[a].tree().find(cc) != nullptr && h[a].tree().best().id == *h[b].store().best_at(5),
          "m23: C's carrier is placed on its (now side) branch after the re-run");
    // the re-run decides: the best chain moved J + 2 past C's parent while RandomX ran; C's parent now lies below the
    // journal base and the re-run DEFERs (OwnChainDeep), where the stale verdict would place it
    const std::uint64_t J = 16;
    Harness g(net);
    const std::size_t a2 = g.add(table0(net), true, J), b2 = g.add(table0(net), true, J), c2 = g.add(table0(net), true, J);
    for (int i = 0; i < 3; ++i) {
        g.tick_monero();
        g.mine(a2, 1, 60 + i);
    }
    g.cut = {{b2, a2}, {c2, a2}, {b2, c2}, {c2, b2}};
    g.mine(c2, 3, 800);
    const pb::Hash32 cc2 = g[c2].tree().best().id;
    for (std::uint64_t i = 0; i < J + 2; ++i) g.mine(b2, 4, 801 + static_cast<std::uint32_t>(i));
    g.cut.clear();
    g.q.clear();
    pb::PathbNode::CarrierTicket t2 = g[a2].begin_carrier(c2, *pb::encode_fc_carrier(0, *g[c2].bodies().get(cc2), 16));
    const bool first_ok = t2.admit.verdict == pb::AdmitVerdict::AdmitCarrier;
    for (std::uint64_t x = 4; x <= 3 + J + 2; ++x) {
        const pb::Hash32 id = *g[b2].store().best_at(x);
        g[a2].on_carrier(b2, *pb::encode_fc_carrier(0, *g[b2].bodies().get(id), 16));
    }
    g.q.clear();
    const pb::NodeEventResult r2 = g[a2].complete_carrier(std::move(t2));
    check(first_ok && g[a2].store().base_pos() > 3 && r2.action == pb::NodeAction::Parked
                  && r2.admit.missing == pb::Missing::OwnChainDeep && !g[a2].poisoned(),
          "m23: the re-run against the moved best chain: C's parent below the journal base -> DEFER (action "
                  + std::to_string(static_cast<int>(r2.action)) + ")");
}

// ---------------------------------------------------------------------------
void restart() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true, 64, true);
    h.add(table0(net));
    for (int i = 0; i < 80; ++i) {
        if (i % 2 == 0) h.tick_monero();
        h.mine(a, static_cast<std::size_t>(i % 4), 70 + i);
    }
    check(!h[a].poisoned() && h.kvs[0]->commits == 81, "restart: one commit per position (genesis + 80)");
    pb::LoadInputs in;
    in.T = table0(net);
    in.journal_depth = 64;
    pb::LoadResult lr = pb::pathb_load(*h.kvs[0], net.pool_id, net.rules_g, in);
    check(lr.fault == pb::StoreFault::None, "restart: the store loads");
    if (!lr.state) return;
    const std::size_t r = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true, 64), h.io(r), std::move(*lr.state), nullptr));
    check(h[a].lane_digest() == h[r].lane_digest(), "restart: the reloaded node's lane digest (tip, S, AR, MMR, window) equals");
    check(coinbase_bytes(h, a, 2) == coinbase_bytes(h, r, 2), "restart: the reloaded node builds the same coinbase bytes");
}

// ---------------------------------------------------------------------------
void n5() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 80 + i);
    }
    const pb::Hash32 parent = h[b].tree().best().id;
    h.cut = {{a, b}};
    h.mine(a, 1, 90);
    h.cut.clear();
    const pb::Hash32 c = h[a].tree().best().id;
    h[b].faults().fail_switch = true;
    const pb::NodeEventResult r = h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(c), 16));
    check(r.action == pb::NodeAction::NodeInternal && r.write == pb::WriteOutcome::NodeInternal,
          "n5: switch_best refused after the marks: NodeInternal");
    check(h[b].tree().best().id == parent && h[b].store().best_tip() == parent && h[b].tree().find(c) == nullptr,
          "n5: the merged undo: the tree's and the store's best tip at c's parent, c dropped");
    check(h[b].poisoned() && h[b].make_template(h.now).status == pb::TemplateStatus::Poisoned,
          "n5: the store poisoned; no template on c (or after it)");
}

// ---------------------------------------------------------------------------
void hold_kind2() {
    const KatNet net;
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);  // epoch 1's list
    const pb::Hash32 d1 = pb::rules_digest(r1);
    const std::uint64_t fixed = 8;
    pb::EpochTable impl = table0(net);
    impl.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, fixed));
    impl.compiled.push_back(pb::CompiledEpoch{1, d1, r1});
    pb::EpochTable lack = table0(net);
    lack.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, fixed));
    Harness h(net);
    const std::size_t a = h.add(impl, true), b = h.add(impl), c = h.add(lack, true);
    std::uint64_t c_jobs = 0;
    for (int i = 0; i < 12; ++i) {
        h.tick_monero();
        h.mine(a, 1, 100 + i);
        if (h[c].make_template(h.now).status == pb::TemplateStatus::Ok) ++c_jobs;
    }
    check(h[a].ar().rows().size() == 1 && h[a].ar().rows()[0].epoch == 1 && h[a].ar().rows()[0].h_act == fixed
                  && h[a].tree().best().rs.epoch_cur == 1,
          "hold: the kind-2 activation at its fixed height (AR row (1, 8))");
    check(h[b].tree().best().id == h[a].tree().best().id && h[b].ar().rows() == h[a].ar().rows(),
          "hold: a node of the same build follows and activates");
    check(h[a].our_hello(1, 0).tail.rules == pb::rules_block(r1)
                  && h[c].our_hello(1, 0).tail.rules == pb::rules_block(pb::epoch0_lane_rules(pb::LaneNet::Regtest)),
          "hold: the HELLO tail carries the rules list of the node's epoch_cur (1 after the activation; 0 at the holder)");
    const pb::PathbNode::HoldState hs = h[c].hold_state();
    // templates for x = 2 .. 7 (tips 1 .. 6); the template for x = 8 = H_hold is not built
    check(hs.hold && hs.h_hold == fixed && h[c].make_template(h.now).status == pb::TemplateStatus::Hold && c_jobs == fixed - 2,
          "hold: the node whose build lacks the epoch holds from x = 8 (its job counter stops)");
    check(h[c].tree().best().pos == fixed - 1 && h[c].deferred().size() > 0 && h[c].alarms().count() == 0,
          "hold: its frames from H_hold are DEFERred (stored), never struck");
}

// ---------------------------------------------------------------------------
void c48() {
    KatNet net;
    // a non-tail emission: already_generated_coins grows with the height (B differs between A_t and P_r)
    for (auto& [id, w] : net.rows.w) {
        const std::optional<pb::BranchBlock> blk = net.rows.block(id);
        if (blk) w.agc_after = 1000000000000000000ull + blk->height * 1000000000000000ull;
    }
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    h.add(table0(net));
    h.txs = {{seq32(0xE3), 3000, 7000000}};
    for (int i = 0; i < 4; ++i) {
        h.tick_monero(2);
        h.mine(a, 1, 120 + i);
    }
    const pb::PathbTemplate t = h[a].make_template(h.now);
    const std::optional<pb::PathbJob> j = h[a].make_job(t, h.session(2));
    const pb::WeightInputs at_pr = *h.views[0]->weights_at(t.p_r);
    const pb::WeightInputs at_at = *h.views[0]->weights_at(t.window.inputs.a_t);
    check(j && at_pr.base_reward != at_at.base_reward, "c48: a non-tail chain: B(P_r) != B(A_t)");
    check(j && vout_sum(j->miner_tx) == at_pr.base_reward + 7000000 && t.reward == at_pr.base_reward + 7000000,
          "c48: Sum(vout) == B(P_r) + F (never B(A_t) + F)");
    // the penalty fill: a set above Z(P_r)
    Harness hp(net);
    const std::size_t p = hp.add(table0(net), true);
    pb::PathbNodeConfig cfg = hp.config(table0(net), true);
    (void)cfg;
    hp.nodes.pop_back();
    hp.views.pop_back();
    pb::PathbNodeConfig pc = hp.config(table0(net), true);
    pc.penalty_fill = true;
    hp.nodes.push_back(std::make_unique<pb::PathbNode>(pc, hp.io(p), nullptr));
    for (int i = 0; i < 3; ++i) hp.txs.push_back(pb::TemplateTx{seq32(static_cast<std::uint8_t>(0xF0 + i)), 120000, 900000000ull});
    const pb::PathbTemplate tp = hp[p].make_template(hp.now);
    const std::optional<std::uint64_t> rr = pb::reward_for_child(tp.median, tp.tx_weight + tp.coinbase, tp.base, 16);
    const std::optional<pb::PathbJob> jp = hp[p].make_job(tp, hp.session(2));
    check(tp.status == pb::TemplateStatus::Ok && tp.tx_weight + tp.coinbase > tp.median && rr && tp.reward == *rr + tp.fees
                  && jp && vout_sum(jp->miner_tx) == tp.reward && jp->miner_tx.prefix.size() + 1 == tp.coinbase,
          "c48: penalised: R == reward_for_child(Z, T + c, B) + F and w == T + the coinbase size");
}

// A PathbNode holding a KatNode's state (tree, store, AR, bodies) and the net's key references.
std::unique_ptr<pb::PathbNode> node_from(Harness& h, const KatNode& n, std::uint64_t J, std::size_t self) {
    pb::LoadedState st{kat_head(*n.net), n.tree, n.store, n.ar, n.bodies, 0, 0, {}};
    for (const auto& [id, ref] : n.net->book.refs) st.refs[id] = ref;
    st.refs[n.net->author_id] = n.net->author;
    return std::make_unique<pb::PathbNode>(h.config(n.T, true, J), h.io(self), std::move(st), nullptr);
}

// ---------------------------------------------------------------------------
void rrfix3() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 3700, 0x81, 1, 23);
    KatNode& n = sn.n;
    const std::uint64_t root = 2300, base = 3690, fork = 3650;
    MemoryKv kv = joined_shape(sn.kv, n, root, base);
    pb::LoadInputs in;
    in.T = n.T;
    in.journal_depth = 64;
    pb::LoadResult lr = pb::pathb_load(kv, net.pool_id, net.rules_g, in);
    check(lr.fault == pb::StoreFault::None, "rrfix3: the joined-shape store loads");
    if (!lr.state) return;
    Harness h(net);
    const std::size_t a = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(n.T, true, 64), h.io(a), std::move(*lr.state), nullptr));
    check(h[a].store().base_pos() == base && h[a].store().tip_pos() - 64 < base,
          "rrfix3: the node's journal base stands above tip - J (base 3690, tip 3700, J 64)");
    // a heavier side branch from 3650 (60 carriers), built on a copy of the scaffold node
    KatNode side(n);
    pb::Hash32 p = *n.store.best_at(fork);
    std::vector<pb::CarrierHeader> hdrs;
    for (std::uint64_t x = fork + 1; x <= fork + 60; ++x) {
        const pb::CarrierBodyV3 c = scaffold_carrier(side, p, h_pos(x), 0x83, 50000 + x, 2, {});
        const pb::WriteResult w = place_direct(side, c);
        if (w.outcome == pb::WriteOutcome::NodeInternal) break;
        p = pb::receipt_id(c.own);
        hdrs.push_back(pb::header_of(c));
    }
    check(hdrs.size() == 60, "rrfix3: the side branch of 60 carriers (tip at 3710)");
    const pb::Hash32 from = *n.store.best_at(fork);
    check(h[a].request_headers(7, from, p, 64, h.now), "rrfix3: FC_GETHEADERS(from 3650, stop, 64) sent");
    h.q.clear();
    // the server's pages (what fits one FC_HEADERS frame), each answering the node's next request
    pb::PathbNode::HeadersOutcome o;
    std::size_t sent = 0, pages = 0, indexed = 0;
    while (sent < hdrs.size() && pages < 10) {
        pb::HeadersReply rep{0, fork + 1 + sent, {}};
        rep.headers.assign(hdrs.begin() + static_cast<std::ptrdiff_t>(sent), hdrs.end());
        std::size_t packed = 0;
        const std::vector<std::uint8_t> f = *pb::encode_fc_headers(rep, h[a].frame_bytes_headers(), &packed);
        o = h[a].on_headers(7, f, h.now);
        sent += packed;
        indexed += o.indexed;
        ++pages;
        if (o.kind != pb::PathbNode::HeadersOutcome::Kind::Continue) break;
        h.q.clear();  // the continuation request
    }
    check(indexed == 60 && pages >= 2 && o.kind == pb::PathbNode::HeadersOutcome::Kind::JoinerPath && o.fork_pos == fork,
          "rrfix3: heavier by its headers (" + std::to_string(pages) + " pages), forked at 3650 in [tip - J, base): the joiner path (kind "
                  + std::to_string(static_cast<int>(o.kind)) + ", indexed " + std::to_string(indexed) + ")");
    check(h.q.empty() && h[a].tree().best().pos == 3700, "rrfix3: no body of that branch fetched; the node's chain kept");
}

// ---------------------------------------------------------------------------
void joinserve() {
    const KatNet net;
    {
        Harness y(net);
        const std::size_t a = y.add(table0(net), true);
        const pb::JoinServeFloors f = y[a].serve_floors_now();
        check(f.bodies == 0 && f.headers == 0, "joinserve: the young chain keeps from position 1 (floors {0, 0})");
    }
    KatStoreNode sn(net, 1152);
    store_chain(sn, 5700, 0x81, 1, 23);  // L 5700: x0 = L - N_rt - 1,175 = 2,365 (a span past the young chain)
    Harness h(net);
    h.nodes.push_back(node_from(h, sn.n, 1152, 0));
    pb::PathbNode& a = h[0];
    const pb::JoinServeFloors f0 = a.serve_floors_now();
    check(f0.bodies > 0 && f0.headers > 0,
          "joinserve: floors at L 5700 from join_serve_floors (bodies " + std::to_string(f0.bodies) + ", headers "
                  + std::to_string(f0.headers) + ")");
    {
        // E-102: the header floor is the claimed prefix start's lowest read record (pre_start's read_lo), at or below
        // x0 - N_rt; the body floor x0 - J_0 - 1
        const auto rec = [&](std::uint64_t x) -> std::optional<std::uint64_t> {
            const std::optional<pb::Hash32> id = sn.n.store.best_at(x);
            if (!id) return std::nullopt;
            return sn.n.node(*id).H;
        };
        const pb::LaneParams& p = pb::kRuledLaneParams;
        const pb::SpanResult sp = pb::span_bounds(p, 5700, rec, kLaneB0);
        const pb::PreStart ps = pb::pre_start(p, sp.bounds.x0, rec);
        const std::uint64_t nrt = pb::join_n_rt(p), j0 = pb::journal_j0(p, pb::kSealDepth);
        check(sp.status == pb::SpanStatus::Ok && ps.status == pb::SpanStatus::Ok && f0.headers == ps.read_lo
                      && f0.headers <= sp.bounds.x0 - nrt && f0.headers < f0.bodies && f0.bodies == sp.bounds.x0 - j0 - 1,
              "joinserve: the header floor = the prefix start's lowest read record " + std::to_string(ps.read_lo)
                      + " (x_pre " + std::to_string(ps.x_pre) + ", x0 - N_rt " + std::to_string(sp.bounds.x0 - nrt)
                      + "); the body floor = x0 - J_0 - 1");
    }
    // an attempt's first request: FC_GETHEADERS of the best tip (from and stop zero) starts the hold
    const std::vector<std::uint8_t> first = pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, pb::Hash32{}, 16});
    (void)a.serve_getheaders(9, first, h.now);
    check(a.join_holding(9), "joinserve: the attempt's first request opens the hold of its connection");
    // the best tip moves on: 48 carriers more, mined on the node
    h.mon_tip = h_pos(5700) + 1;
    for (int i = 0; i < 48; ++i) {
        if (i % 4 == 0) h.tick_monero(1);
        h.mine(0, static_cast<std::size_t>(i % 3), 900 + i);
    }
    const std::uint64_t placed = a.store().tip_pos() - 5700;
    h.q.clear();
    const pb::JoinServeFloors f1 = a.serve_floors_now();
    check(placed == 48 && f1.bodies > f0.bodies && f1.headers > f0.headers,
          "joinserve: the floors at L 5748 rise (bodies " + std::to_string(f1.bodies) + ", placed " + std::to_string(placed)
                  + ")");
    pb::JoinServeFloors r = a.retention_floors(h.now + 5);
    check(r.bodies == f0.bodies && r.headers == f0.headers, "joinserve: the open hold keeps the floors of its first request");
    // a request for a new item at or below the attempt's L continues the hold
    const pb::Hash32 low = *sn.n.store.best_at(1000);
    pb::GetCarrier q;
    q.chain_id = 0;
    q.ids = {low};
    const std::vector<std::uint8_t> fq = *pb::encode_fc_getcarrier(q, pb::kRuledLaneParams);
    (void)a.serve_getcarrier(9, fq, h.now + 10);
    // an item above the attempt's L and a repeated item do not continue it
    q.ids = {a.tree().best().id};
    (void)a.serve_getcarrier(9, *pb::encode_fc_getcarrier(q, pb::kRuledLaneParams), h.now + 18);
    (void)a.serve_getcarrier(9, fq, h.now + 19);
    r = a.retention_floors(h.now + 21);
    check(r.bodies == f0.bodies && a.join_holding(9), "joinserve: 11 s after its last new item the hold still stands");
    r = a.retention_floors(h.now + 22);
    check(r.bodies == f1.bodies && r.headers == f1.headers && !a.join_holding(9),
          "joinserve: no new item within P-53: the hold ends (a repeated item or one above L did not continue it)");
    // one hold per connection; a disconnect closes it
    (void)a.serve_getheaders(10, first, h.now + 30);
    check(a.join_holding(10), "joinserve: a second attempt's hold");
    a.disconnect(10);
    check(!a.join_holding(10) && a.retention_floors(h.now + 31).bodies == f1.bodies, "joinserve: a disconnect closes the hold");
}

// ---------------------------------------------------------------------------
// Two nodes split after a shared prefix: A mines 4, B mines 8 (heavier).
struct Split {
    std::size_t a = 0, b = 0;
    pb::Hash32 fork{}, b_tip{};
    std::vector<pb::Hash32> b_ids;
};
Split split(Harness& h) {
    Split s;
    s.a = h.add(table0(h.net), true);
    s.b = h.add(table0(h.net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero(1);
        h.mine(s.a, static_cast<std::size_t>(i % 3), 100 + i);
    }
    s.fork = h[s.a].tree().best().id;
    h.cut = {{s.a, s.b}, {s.b, s.a}};
    for (int i = 0; i < 4; ++i) h.mine(s.a, 0, 200 + i);
    for (int i = 0; i < 8; ++i) {
        h.mine(s.b, 1, 300 + i);
        s.b_ids.push_back(h[s.b].tree().best().id);
    }
    s.b_tip = h[s.b].tree().best().id;
    h.cut.clear();
    h.q.clear();
    return s;
}

// The FC_HEADERS frames B serves for A's request at the queue's front.
std::vector<std::vector<std::uint8_t>> serve_front(Harness& h, const Split& s) {
    const Msg req = h.q.front();
    h.q.pop_front();
    return h[s.b].serve_getheaders(s.a, req.frame, h.now).frames;
}

void n7b2() {
    const KatNet net;
    {
        Harness h(net);
        const Split s = split(h);
        check(h[s.a].tree().best().pos == 10 && h[s.b].tree().best().pos == 14, "n7b2: A at 10, B at 14, forked at 6");
        // B-2: FC_GETHEADERS(from, stop, 3): at most 3 headers
        const std::vector<std::vector<std::uint8_t>> f =
                h[s.b].serve_getheaders(s.a, pb::encode_fc_getheaders(pb::GetHeaders{0, s.fork, s.b_tip, 3}), h.now).frames;
        pb::HeadersReply rep;
        const bool ok = f.size() == 1
                        && pb::decode_fc_headers(f[0], 0, h[s.a].frame_bytes_headers(), pb::kRuledLaneParams, rep).ok();
        check(ok && rep.headers.size() == 3 && rep.first_pos == 7, "n7b2: serve_headers answers at most the request's max (3)");
        // N-7: a header failing its PoW at d: the server BANned, no variant of the reply indexed
        h.bad_pow.insert(s.b_ids[2]);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 16, h.now), "n7b2: A asks B for its branch");
        const std::vector<std::vector<std::uint8_t>> r1 = serve_front(h, s);
        const pb::PathbNode::HeadersOutcome o = h[s.a].on_headers(s.b, r1.at(0), h.now);
        check(o.kind == pb::PathbNode::HeadersOutcome::Kind::Ban && o.indexed == 0
                      && pb::PathbNodeTestAccess::headers(h[s.a]).size() == 0,
              "n7b2: a header failing its PoW at d: BAN, no variant indexed (kind " + std::to_string(static_cast<int>(o.kind))
                      + ", index " + std::to_string(pb::PathbNodeTestAccess::headers(h[s.a]).size()) + ")");
    }
    {
        // N-7: a reply whose second header's P_r is not resolved: DEFER, and no variant of the reply indexed (the first
        // header's PoW never ran)
        Harness h(net);
        const Split s = split(h);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 16, h.now), "n7b2 (defer): A asks B");
        const std::vector<std::vector<std::uint8_t>> r = serve_front(h, s);
        pb::HeadersReply rep;
        (void)pb::decode_fc_headers(r.at(0), 0, h[s.a].frame_bytes_headers(), pb::kRuledLaneParams, rep);
        rep.headers.resize(2);
        rep.headers[1].own.blob.prev_id = seq32(0xEE);  // a Monero block this node does not hold
        const pb::PathbNode::HeadersOutcome o = h[s.a].on_headers(s.b, *pb::encode_fc_headers(rep, h[s.a].frame_bytes_headers()), h.now);
        check(o.kind == pb::PathbNode::HeadersOutcome::Kind::Defer && pb::PathbNodeTestAccess::headers(h[s.a]).size() == 0
                      && h[s.a].tree().best().pos == 10,
              "n7b2: a P_r not resolved: DEFER, no variant indexed before its PoW (index "
                      + std::to_string(pb::PathbNodeTestAccess::headers(h[s.a]).size()) + ")");
    }
    {
        // the honest reply: indexed with path_ok after the PoW, heavier: the bodies fetched, A switches to B's chain
        Harness h(net);
        const Split s = split(h);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 16, h.now), "n7b2: A asks B (honest)");
        const std::vector<std::vector<std::uint8_t>> r2 = serve_front(h, s);
        const pb::PathbNode::HeadersOutcome o2 = h[s.a].on_headers(s.b, r2.at(0), h.now);
        check(o2.kind == pb::PathbNode::HeadersOutcome::Kind::FetchBodies && o2.indexed == 8
                      && pb::PathbNodeTestAccess::headers(h[s.a]).size() == 8,
              "n7b2: the honest branch: 8 variants indexed after their PoW, heavier: FC_GETCARRIER of its bodies (kind "
                      + std::to_string(static_cast<int>(o2.kind)) + ", indexed " + std::to_string(o2.indexed) + ")");
        h.pump();
        check(h[s.a].tree().best().id == s.b_tip && h[s.a].store().best_tip() == s.b_tip,
              "n7b2: A switched to B's heavier branch by headers first");
    }
    {
        // N-7 across pages: a variant indexed from an earlier page of a server later BANned is released
        Harness h(net);
        h.headers_frame = 1500;  // a few headers per FC_HEADERS frame
        const Split s = split(h);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 16, h.now), "n7b2 (pages): A asks B");
        pb::PathbNode::HeadersOutcome o;
        std::size_t pages = 0, indexed = 0;
        bool released = false;
        while (!h.q.empty() && pages < 10) {
            const std::vector<std::vector<std::uint8_t>> r = serve_front(h, s);
            o = h[s.a].on_headers(s.b, r.at(0), h.now);
            ++pages;
            indexed += o.indexed;
            if (o.kind != pb::PathbNode::HeadersOutcome::Kind::Continue) break;
            if (pages == 1 && indexed < s.b_ids.size()) h.bad_pow.insert(s.b_ids[indexed]);  // the next page's first header
        }
        released = pb::PathbNodeTestAccess::headers(h[s.a]).size() == 0;
        check(pages >= 2 && indexed > 0 && o.kind == pb::PathbNode::HeadersOutcome::Kind::Ban && released,
              "n7b2 (pages): " + std::to_string(pages) + " pages, " + std::to_string(indexed)
                      + " indexed before the failing header: BAN and the server's variants released (kind "
                      + std::to_string(static_cast<int>(o.kind)) + ", index "
                      + std::to_string(pb::PathbNodeTestAccess::headers(h[s.a]).size()) + ")");
    }
    {
        // B-2 / P-48: FC_GETBUCKETS stops at the lower fixed serve cap
        Harness h(net);
        h.bucket_policy = pb::BucketWirePolicy{1200, 1, 12000};
        h.serve_cap = 2400;
        const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
        for (int i = 0; i < 80; ++i) {
            h.tick_monero(2);
            h.mine(a, static_cast<std::size_t>(i % 3), 300 + i);
        }
        const pb::Hash32 at = h[a].tree().best().id;
        const std::uint64_t b0 = h[a].store().b0();
        check(h[a].request_buckets(b, at, b0, b0 + 9, h.now), "n7b2: FC_GETBUCKETS to B");
        const Msg req = h.q.front();
        h.q.pop_front();
        const std::vector<std::vector<std::uint8_t>> fr = h[b].serve_getbuckets(a, req.frame, h.now).frames;
        std::uint64_t bytes = 0;
        for (const auto& f : fr) bytes += f.size();
        check(!fr.empty() && bytes <= 2400, "n7b2: " + std::to_string(fr.size()) + " frames, " + std::to_string(bytes)
                                                    + " bytes <= the serve cap 2,400");
    }
}

// ---------------------------------------------------------------------------
void startup() {
    const KatNet net;
    const auto base = [&] {
        pb::StartupInputs in;
        in.net = pb::LaneNet::Regtest;
        in.owner_fee_bp = 100;
        in.give_author_bp = 10;
        in.journal_depth = 1152;
        in.T.compiled.push_back(pb::CompiledEpoch{0, pb::genesis_rules_digest(pb::LaneNet::Regtest),
                                                  pb::epoch0_lane_rules(pb::LaneNet::Regtest)});
        in.hf = 16;
        in.z_lt_view = 300000;
        in.buffers = pb::relay_buffers_default(16, 300000, pb::kRuledLaneParams.r_max).value();
        in.raw.pool_genesis_height = std::to_string(kPoolH);
        in.hash_at = [](std::uint64_t h) -> std::optional<pb::Hash32> { return mon_block(h); };
        in.monero_tip = kMonTop;
        return in;
    };
    const pb::StartupResult ok = pb::startup_checks(base());
    check(ok.ok() && ok.T.compiled.size() == 1 && ok.identity == pb::identity_raw(pb::LaneNet::Regtest, 0, pb::default_pool_genesis(pb::LaneNet::Regtest), kPoolH)
                  && !ok.raw_warning,
          "startup: regtest, the default raw genesis with --pool-genesis-height: started");
    const auto step = [&](pb::StartupInputs in) { return pb::startup_checks(in).refused; };
    pb::StartupInputs a = base();
    a.owner_fee_bp = 9991;
    a.journal_depth = 10;  // also refused, later
    check(step(a) == pb::StartupStep::FeeSum, "startup (1): the configured sum above 10000 bp, before the journal depth");
    a = base();
    a.owner_fee_bp = 0xFFFFFFFFu;
    a.give_author_bp = 2;
    check(step(a) == pb::StartupStep::FeeSum, "startup (1): a sum past 2^32 is not wrapped");
    a = base();
    a.journal_depth = 1151;
    a.buffers.frame = 1;  // also refused, later
    check(step(a) == pb::StartupStep::JournalDepth, "startup (2): --journal-depth 1151 below J_0, before the buffers");
    a = base();
    a.net = pb::LaneNet::Mainnet;
    a.deployments.push_back(pb::Deployment{});
    check(step(a) == pb::StartupStep::Deployments, "startup (3): a deployment file on mainnet");
    a = base();
    a.rp.grace = a.rp.window * 5;  // W_R = 5
    check(step(a) == pb::StartupStep::DeploymentTable, "startup (4): W_R above 4");
    a = base();
    a.net = pb::LaneNet::Testnet;  // the regtest table on testnet: G differs
    check(step(a) == pb::StartupStep::LaneRules, "startup (5): lane_rules_valid (the compiled G not the network's)");
    a = base();
    a.buffers.receipt -= 1;
    a.raw.pool_genesis_height.reset();  // also refused, later
    check(step(a) == pb::StartupStep::RelayBuffers, "startup (6): a receipt buffer below the default, before the identity");
    a = base();
    a.raw.pool_genesis_height.reset();
    check(step(a) == pb::StartupStep::Identity, "startup (7): a raw genesis without its height");
    a = base();
    a.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH)) + ":\"a headline\"";
    check(step(a) == pb::StartupStep::Identity, "startup (7): --pool-genesis-from with a raw genesis flag");
    a.raw = {};
    a.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH)) + ":\" edge\"";
    check(step(a) == pb::StartupStep::Identity, "startup (7): a headline with an edge space");
    a.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH + 1)) + ":\"a headline\"";
    check(step(a) == pb::StartupStep::GenesisChain, "startup (8): the block hash is not height H on this chain");
    a.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH)) + ":\"a headline\"";
    const pb::StartupResult d = pb::startup_checks(a);
    check(d.ok() && d.identity.form == pb::GenesisForm::Derived && d.identity.height == kPoolH,
          "startup: the derived form on this chain, H deep enough: started");
    a = base();
    a.net = pb::LaneNet::Stagenet;
    a.T = pb::EpochTable{};
    const pb::StartupResult w = pb::startup_checks(a);
    check(w.refused == pb::StartupStep::LaneRules, "startup: no epoch-0 rules refused");
}

// ---------------------------------------------------------------------------
// (e) on the product state (D37): A at journal depth J meets B's heavier branch by its bodies: a fork at depth J
// switches by the journal; at depth J + 1 (below the journal base) the joiner path, the store untouched.
void deep() {
    const KatNet net;
    const std::uint64_t J = 16;
    for (const std::uint64_t depth : {J, J + 1}) {
        Harness h(net);
        const std::size_t a = h.add(table0(net), true, J), b = h.add(table0(net), true, J);
        for (int i = 0; i < 6; ++i) {
            h.tick_monero(1);
            h.mine(a, static_cast<std::size_t>(i % 3), 100 + i);
        }
        const std::uint64_t fork = h[a].tree().best().pos;
        h.cut = {{a, b}, {b, a}};
        for (std::uint64_t i = 0; i < depth; ++i) {
            if (i % 4 == 0) h.tick_monero(1);
            h.mine(a, 0, 200 + static_cast<std::uint32_t>(i));
        }
        std::vector<pb::Hash32> bb;
        for (std::uint64_t i = 0; i < depth + 6; ++i) {
            if (i % 4 == 0) h.tick_monero(1);
            h.mine(b, 1, 400 + static_cast<std::uint32_t>(i));
            bb.push_back(h[b].tree().best().id);
        }
        h.cut.clear();
        h.q.clear();
        const pb::Hash32 a_tip = h[a].store().best_tip();
        const std::uint64_t a_pos = h[a].store().tip_pos();
        pb::NodeEventResult last;
        for (const pb::Hash32& id : bb) {
            const pb::CarrierBodyV3* c = h[b].bodies().get(id);
            if (c == nullptr) break;
            last = h[a].on_carrier(b, *pb::encode_fc_carrier(0, *c, pb::kRuledLaneParams.r_max));
            if (last.action != pb::NodeAction::SideBranch) break;
        }
        h.q.clear();
        const std::string tag = "deep (e) at depth " + std::to_string(depth) + " (J " + std::to_string(J) + "): ";
        check(a_pos - fork == depth, tag + "A's tip at the fork + depth");
        if (depth == J) {
            check(last.action == pb::NodeAction::Switched && h[a].store().best_tip() == h[a].tree().best().id
                          && h[a].tree().best().id != a_tip && !h[a].poisoned(),
                  tag + "a switch by the journal (action " + std::to_string(static_cast<int>(last.action)) + ")");
        } else {
            // a body whose parent lies below the journal base: DEFER (the node's own deep switch goes by headers
            // first), no verdict, no token
            check(last.action == pb::NodeAction::Parked && last.admit.missing == pb::Missing::OwnChainDeep
                          && last.admit.strike == 0 && h[a].store().best_tip() == a_tip,
                  tag + "a body below the journal base: DEFER (OwnChainDeep), 0 tokens (action "
                          + std::to_string(static_cast<int>(last.action)) + ")");
            const pb::Hash32 fork_id = *h[a].store().best_at(fork);
            check(h[a].request_headers(b, fork_id, bb.back(), 64, h.now), tag + "FC_GETHEADERS to B");
            pb::PathbNode::HeadersOutcome o;
            for (int page = 0; page < 8 && !h.q.empty(); ++page) {  // B's pages (at most P-01 = J each)
                const Msg req = h.q.front();
                h.q.pop_front();
                const std::vector<std::vector<std::uint8_t>> r = h[b].serve_getheaders(a, req.frame, h.now).frames;
                o = h[a].on_headers(b, r.at(0), h.now);
                if (o.kind != pb::PathbNode::HeadersOutcome::Kind::Continue) break;
            }
            check(o.kind == pb::PathbNode::HeadersOutcome::Kind::JoinerPath && o.fork_pos == fork && h.q.empty()
                          && h[a].store().best_tip() == a_tip && !h[a].poisoned(),
                  tag + "heavier by its headers, forked below the journal base: the joiner path, no body fetched, the "
                        "store untouched (kind " + std::to_string(static_cast<int>(o.kind)) + ")");
        }
    }
}

// ---------------------------------------------------------------------------
// The poisoned store (3.3, "as w6 does"): the latch first in every event, the status alarm, the poison mark.
void poison() {
    const KatNet net;
    {
        Harness h(net);
        const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true, 1152, true);
        for (int i = 0; i < 3; ++i) {
            h.tick_monero();
            h.mine(a, 1, 80 + i);
        }
        h.cut = {{a, b}};
        h.mine(a, 1, 90);
        const pb::Hash32 c = h[a].tree().best().id;
        const std::optional<pb::PathbJob> stale = h.job(a, 2, 91);  // a share for B's pending set, later
        check(stale.has_value(), "poison: a job for a later share");
        if (!stale) return;
        h.mine(a, 1, 92);
        h.cut.clear();
        h.q.clear();
        const std::size_t alarms0 = h[b].alarms().count();
        h[b].faults().fail_switch = true;
        const pb::NodeEventResult r = h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(c), 16));
        check(r.action == pb::NodeAction::NodeInternal && h[b].poisoned() && h[b].alarms().count() > alarms0,
              "poison: NodeInternal poisons the store and raises the status alarm");
        pb::LoadInputs in;
        in.T = table0(net);
        in.journal_depth = 1152;
        check(pb::pathb_load(*h.kvs[0], net.pool_id, net.rules_g, in).fault == pb::StoreFault::Poisoned,
              "poison: the poison mark: the next load is a load failure (the joiner path)");
        // after the poison nothing is judged: a frame that would earn a strike, a receipt, a bucket frame
        std::vector<std::uint8_t> garbage = *pb::encode_fc_carrier(0, *h[a].bodies().get(c), 16);
        garbage.resize(garbage.size() - 7);
        const pb::NodeEventResult g = h[b].on_carrier(a, garbage);
        check(g.action == pb::NodeAction::NodeInternal && g.admit.strike == 0 && g.admit.row == pb::RowId::None,
              "poison: a frame that does not decode: NodeInternal, not judged (no verdict, no token)");
        std::size_t pend0 = h[b].pending().size();
        pb::ReceiptBodyV3 rb = stale->body;
        rb.blob.nonce = 91;
        std::vector<pb::ReceiptBodyV3> one{rb};
        const std::vector<pb::NodeEventResult> rr = h[b].on_receipts(a, *pb::encode_fb_receipts(0, one, pb::kRuledLaneParams));
        check(rr.size() == 1 && rr[0].action == pb::NodeAction::NodeInternal && h[b].pending().size() == pend0 && h.q.empty(),
              "poison: an FB_RECEIPTS body: NodeInternal, not pended, not flooded");
        check(h[b].on_buckets(a, garbage, h.now).action == pb::NodeAction::NodeInternal
                      && !h[b].request_headers(a, *h[b].store().best_at(1), c, 16, h.now)
                      && !h[b].request_buckets(a, *h[b].store().best_at(1), 0, 1, h.now),
              "poison: FC_BUCKETS NodeInternal; no catch-up request is sent");
    }
    {
        // a failed commit of an extension: NodeInternal, the alarm, the mark
        Harness h(net);
        const std::size_t a = h.add(table0(net), true, 1152, true);
        h.tick_monero();
        h.mine(a, 1, 10);
        h.kvs[0]->fail_next = 1;
        h.tick_monero();
        const pb::NodeEventResult r = h.mine(a, 1, 11);
        pb::LoadInputs in;
        in.T = table0(net);
        in.journal_depth = 1152;
        check(r.action == pb::NodeAction::NodeInternal && h[a].poisoned() && h[a].alarms().count() == 1
                      && pb::pathb_load(*h.kvs[0], net.pool_id, net.rules_g, in).fault == pb::StoreFault::Poisoned
                      && h[a].make_template(h.now).status == pb::TemplateStatus::Poisoned,
              "poison: a failed extension commit: NodeInternal, one status alarm, the mark, no template");
    }
    {
        // the empty-store start writes into an empty store: stale keys of the directory deleted in its batch
        Harness h(net);
        h.kvs.push_back(std::make_unique<MemoryKv>());
        MemoryKv& kv = *h.kvs.back();
        kv.data[pb::store_keys::pcarrier(0, 7)] = "stale";
        kv.data[pb::store_keys::ar(0, 9)] = "stale";
        kv.data[pb::lane_keys::blhash(0, 4)] = "stale";
        h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true), h.io(0), &kv));
        check(!h[0].poisoned() && kv.data.count(pb::store_keys::pcarrier(0, 7)) == 0 && kv.data.count(pb::store_keys::ar(0, 9)) == 0
                      && kv.data.count(pb::lane_keys::blhash(0, 4)) == 0 && kv.data.count(pb::store_keys::phead(0)) == 1,
              "poison: the empty-store start clears the store's prefixes in its genesis batch");
    }
}

// ---------------------------------------------------------------------------
// FC_GETHEADERS with from = the zero id: the joiner's page ending at stop.
pb::HeadersReply page_of(Harness& h, std::size_t server, const pb::Hash32& stop, std::uint16_t max) {
    const pb::ServeResult r = h[server].serve_getheaders(99, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, stop, max}), h.now);
    pb::HeadersReply rep;
    if (r.frames.size() == 1) (void)pb::decode_fc_headers(r.frames[0], 0, 1u << 22, pb::kRuledLaneParams, rep);
    return rep;
}

bool links(const pb::HeadersReply& r) {
    for (std::size_t i = 1; i < r.headers.size(); ++i)
        if (r.headers[i].own.side.tip != pb::receipt_id(r.headers[i - 1].own)) return false;
    return true;
}

void joinpages() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), c = h.add(table0(net), true), e = h.add(table0(net), true);
    {
        const pb::HeadersReply r0 = page_of(h, a, pb::Hash32{}, 10);
        check(r0.headers.empty() && r0.first_pos == 0, "joinpages: a server at position 0: n = 0, first_pos 0 (L = 0)");
    }
    for (int i = 0; i < 40; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(a, static_cast<std::size_t>(i % 3), 300 + i);
    }
    const pb::Hash32 tip = h[a].tree().best().id;
    const pb::HeadersReply r1 = page_of(h, a, pb::Hash32{}, 10);
    check(r1.headers.size() == 10 && r1.first_pos == 31 && pb::receipt_id(r1.headers.back().own) == tip && links(r1),
          "joinpages: the first page (stop zero): the 10 headers ending at the best tip, first_pos 31");
    if (r1.headers.empty()) return;
    const pb::Hash32 stop2 = r1.headers.front().own.side.tip;
    const pb::HeadersReply r2 = page_of(h, a, stop2, 10);
    check(r2.headers.size() == 10 && r2.first_pos == 21 && pb::receipt_id(r2.headers.back().own) == stop2 && links(r2)
                  && r2.first_pos + r2.headers.size() == r1.first_pos,
          "joinpages: the next page ends at stop (the parent of the lowest held), first_pos + n = the lowest held");
    const pb::HeadersReply r3 = page_of(h, a, tip, 1);
    check(r3.headers.size() == 1 && r3.first_pos == 40 && pb::receipt_id(r3.headers[0].own) == tip, "joinpages: stop = tip, max 1: one header");
    const pb::HeadersReply r4 = page_of(h, a, *h[a].store().best_at(2), 10);
    check(r4.headers.size() == 2 && r4.first_pos == 1, "joinpages: position 0 is never served (stop at 2: positions 1, 2)");
    check(page_of(h, a, seq32(0x42), 10).headers.empty() && page_of(h, a, seq32(0x42), 10).first_pos == 0,
          "joinpages: a stop this node has not bound: n = 0");
    // a side part: C's lighter branch placed at A, a page ending at its tip crosses into the best chain
    for (std::size_t x = 1; x <= 40; ++x) (void)x;
    h.cut = {{a, c}, {c, a}, {e, c}, {c, e}};
    h.mine(a, 1, 500);
    h.mine(a, 1, 501);
    h.mine(a, 1, 502);
    h.mine(c, 2, 600);
    h.mine(c, 2, 601);
    h.cut.clear();
    h.q.clear();
    for (std::uint64_t x = 41; x <= 42; ++x)
        (void)h[a].on_carrier(c, *pb::encode_fc_carrier(0, *h[c].bodies().get(*h[c].store().best_at(x)), 16));
    h.q.clear();
    const pb::Hash32 side_tip = *h[c].store().best_at(42);
    const pb::HeadersReply r5 = page_of(h, a, side_tip, 5);
    check(h[a].tree().find(side_tip) != nullptr && h[a].tree().best().pos == 43 && r5.headers.size() == 5 && r5.first_pos == 38
                  && links(r5) && pb::receipt_id(r5.headers.back().own) == side_tip
                  && pb::receipt_id(r5.headers[2].own) == tip,
          "joinpages: a page ending at a side tip crosses into the best chain by parent steps");
    // a frame-limited page keeps the headers next to stop
    Harness g(net);
    g.headers_frame = 1500;
    const std::size_t s = g.add(table0(net), true);
    for (int i = 0; i < 20; ++i) {
        if (i % 3 == 0) g.tick_monero();
        g.mine(s, 1, 700 + i);
    }
    const pb::HeadersReply r6 = page_of(g, s, pb::Hash32{}, 20);
    check(!r6.headers.empty() && r6.headers.size() < 20 && pb::receipt_id(r6.headers.back().own) == g[s].tree().best().id
                  && r6.first_pos + r6.headers.size() - 1 == 20 && links(r6),
          "joinpages: a frame-limited page (" + std::to_string(r6.headers.size()) + " headers) ends at stop: the newest kept");
}

// ---------------------------------------------------------------------------
// The family C token classes and the bounded serve and receive paths.
void tokens() {
    const KatNet net;
    {
        Harness h(net);
        const std::size_t a = h.add(table0(net), true, 16), b = h.add(table0(net), true, 16);
        for (int i = 0; i < 40; ++i) {
            if (i % 3 == 0) h.tick_monero();
            h.mine(a, 1, 100 + i);
        }
        // a forward FC_GETHEADERS: at most P-01 (J = 16) headers whatever max asks
        const pb::ServeResult fw =
                h[a].serve_getheaders(b, pb::encode_fc_getheaders(pb::GetHeaders{0, h[a].tree().genesis().id, h[a].tree().best().id, 100}), h.now);
        pb::HeadersReply rep;
        const bool ok = fw.frames.size() == 1 && pb::decode_fc_headers(fw.frames[0], 0, 1u << 22, pb::kRuledLaneParams, rep).ok();
        check(ok && rep.headers.size() == 16 && rep.first_pos == 1, "tokens: FC_GETHEADERS max 100 -> 16 headers");
        // request frames that do not decode: refuse + 1 strike; above the buffer: DROP
        const std::vector<std::uint8_t> bad{0x51, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        std::vector<std::uint8_t> big(h[a].config().buffers.frame + 1, 0x52);
        check(h[a].serve_getcarrier(b, bad, h.now).token == pb::FrameToken::Strike
                      && h[a].serve_getheaders(b, bad, h.now).token == pb::FrameToken::Strike
                      && h[a].serve_getbuckets(b, bad, h.now).token == pb::FrameToken::Strike
                      && h[a].serve_getcarrier(b, big, h.now).token == pb::FrameToken::Drop
                      && h[a].serve_getheaders(b, big, h.now).token == pb::FrameToken::Drop,
              "tokens: an undecodable FC_GETCARRIER / FC_GETHEADERS / FC_GETBUCKETS: STRIKE; above the buffer: DROP");
        // an FC_HEADERS reply above the buffer: DROP, the request stays open; one that does not decode: refuse + 1 strike
        check(h[b].request_headers(a, h[b].tree().genesis().id, h[a].tree().best().id, 8, h.now) || true, "tokens: a request");
        std::vector<std::uint8_t> bigh(h[b].frame_bytes_headers() + 1, 0x53);
        const pb::PathbNode::HeadersOutcome o1 = h[b].on_headers(a, bigh, h.now);
        const std::vector<std::uint8_t> badh{0x53, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        const pb::PathbNode::HeadersOutcome o2 = h[b].on_headers(a, badh, h.now);
        const pb::PathbNode::HeadersOutcome o3 = h[b].on_headers(a, badh, h.now);
        check(o1.kind == pb::PathbNode::HeadersOutcome::Kind::OverBuffer && o2.kind == pb::PathbNode::HeadersOutcome::Kind::Undecodable
                      && o3.kind == pb::PathbNode::HeadersOutcome::Kind::Unsolicited,
              "tokens: FC_HEADERS above the buffer DROP (request open); then undecodable: STRIKE (request ended)");
    }
    {
        // N-14: the pending set reports its own eviction
        pb::PendingSet ps(2);
        const auto rec = [](std::uint8_t k, std::uint64_t hh) { return pb::PendingReceipt{seq32(k), pb::ReceiptBodyV3{}, hh, 1, 0}; };
        const bool a1 = ps.add(rec(1, 5)), a2 = ps.add(rec(2, 6)), a3 = ps.add(rec(3, 4));
        check(a1 && a2 && !a3 && !ps.holds(seq32(3)) && ps.size() == 2, "tokens: the oldest-bin newcomer evicted: add false");
        const bool a4 = ps.add(rec(4, 7));
        check(a4 && !ps.holds(seq32(1)) && ps.holds(seq32(2)) && ps.holds(seq32(4)), "tokens: the oldest bin goes first");
    }
}

// ---------------------------------------------------------------------------
// The buckets receive: undecodable frames, the closed / abandoned keys, the parked chain, the BadServed BAN, the max cap.
void receive() {
    const KatNet net;
    {
        Harness h(net);
        h.bucket_policy = pb::BucketWirePolicy{1200, 1, 12000};
        const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true), c = h.add(table0(net), true);
        for (int i = 0; i < 80; ++i) {
            h.tick_monero(2);
            h.mine(a, static_cast<std::size_t>(i % 3), 300 + i);
        }
        const pb::Hash32 at = h[a].tree().best().id;
        const std::uint64_t b0 = h[a].store().b0();
        check(h[a].request_buckets(b, at, b0, b0 + 9, h.now), "receive: FC_GETBUCKETS to B");
        std::vector<std::vector<std::uint8_t>> fr;
        {
            const Msg req = h.q.front();
            h.q.pop_front();
            fr = h[b].serve_getbuckets(a, req.frame, h.now).frames;
        }
        std::vector<std::uint8_t> other = fr.at(0);
        other[2] ^= 0x01;  // another chain_id: the frame does not decode
        const pb::BucketsEventResult u = h[a].on_buckets(b, other, h.now);
        check(u.frame.verdict == pb::BucketsFrameVerdict::Refused && u.frame.strike == 1 && h[a].open_assemblies() == 0,
              "receive: an undecodable FC_BUCKETS from an asked server: refuse + 1 strike, its requests close");
        const pb::BucketsEventResult u2 = h[a].on_buckets(c, other, h.now);
        std::vector<std::uint8_t> big(1201, 0x55);
        const pb::BucketsEventResult u3 = h[a].on_buckets(b, big, h.now);
        check(u2.frame.verdict == pb::BucketsFrameVerdict::Drop && u2.frame.strike == 0 && u3.frame.verdict == pb::BucketsFrameVerdict::Drop
                      && u3.frame.fault == pb::BucketsFault::OverBuffer && u3.frame.strike == 0,
              "receive: from a peer with no open request DROP; above the bucket frame buffer DROP");
        // the closed and abandoned keys go with the peer
        check(h[a].request_buckets(c, at, b0, b0 + 9, h.now), "receive: FC_GETBUCKETS to C");
        h.q.clear();
        const std::size_t exp = h[a].tick(h.now + pb::kAbandonTimeoutDefault + 1);
        check(exp == 1 && pb::PathbNodeTestAccess::abandoned(h[a]) == 1 && pb::PathbNodeTestAccess::closed(h[a]) == 2
                      && !h[a].request_buckets(c, at, b0, b0 + 9, h.now + 20),
              "receive: C abandoned for at (no assembly kept); closed for at");
        h[a].disconnect(c);
        h[a].disconnect(b);
        check(pb::PathbNodeTestAccess::abandoned(h[a]) == 0 && pb::PathbNodeTestAccess::closed(h[a]) == 0,
              "receive: a disconnect drops the peer's closed and abandoned keys");
    }
    {
        // a closed key for an `at` below the retained floor (base_pos - J_0) goes at the next best change
        KatStoreNode sn(net, 64);
        store_chain(sn, 1300, 0x81, 1, 23);
        Harness h(net);
        h.nodes.push_back(node_from(h, sn.n, 64, 0));
        pb::PathbNode& a = h[0];
        const pb::Hash32 deep_at = *sn.n.store.best_at(20);
        check(a.request_buckets(5, deep_at, a.store().b0(), a.store().b0() + 1, h.now), "receive: a request for an at at 20");
        h.q.clear();
        const std::vector<std::uint8_t> bad{0x55, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        (void)a.on_buckets(5, bad, h.now);
        check(pb::PathbNodeTestAccess::closed(a) == 1, "receive: (5, at 20) closed");
        h.mon_tip = h_pos(1300) + 1;
        h.tick_monero(1);
        h.mine(0, 1, 990);
        check(a.store().tip_pos() == 1301 && pb::PathbNodeTestAccess::closed(a) == 0,
              "receive: after a best change the closed key below base_pos - J_0 is gone");
    }
    {
        // a parked chain released iteratively (one placement level at a time)
        Harness h(net);
        const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
        for (int i = 0; i < 3; ++i) {
            h.tick_monero();
            h.mine(a, 1, 40 + i);
        }
        h.cut = {{b, a}};
        for (int i = 0; i < 30; ++i) h.mine(b, 1, 50 + i);
        h.cut.clear();
        h.q.clear();
        for (std::uint64_t x = 33; x >= 5; --x)
            (void)h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(*h[b].store().best_at(x)), 16));
        h.q.clear();
        (void)h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(*h[b].store().best_at(4)), 16));
        h.q.clear();
        check(h[a].tree().best().id == h[b].tree().best().id && pb::PathbNodeTestAccess::max_settle_depth(h[a]) <= 1,
              "receive: 29 parked carriers placed on their parent's arrival, one level deep (max depth "
                      + std::to_string(pb::PathbNodeTestAccess::max_settle_depth(h[a])) + ")");
    }
    {
        // n-2: a RandomX failure while released carriers are placed: the event throws, the queue is cleared and the
        // next release drains again
        Harness h(net);
        const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
        for (int i = 0; i < 3; ++i) {
            h.tick_monero();
            h.mine(a, 1, 40 + i);
        }
        h.cut = {{b, a}};
        for (int i = 0; i < 30; ++i) h.mine(b, 1, 50 + i);
        h.cut.clear();
        h.q.clear();
        const auto frame_at = [&](std::uint64_t x) {
            return *pb::encode_fc_carrier(0, *h[b].bodies().get(*h[b].store().best_at(x)), 16);
        };
        for (std::uint64_t x = 33; x >= 5; --x) (void)h[a].on_carrier(b, frame_at(x));
        h.throw_pow.insert(*h[b].store().best_at(10));
        bool threw = false;
        try {
            (void)h[a].on_carrier(b, frame_at(4));
        } catch (const std::runtime_error&) {
            threw = true;
        }
        h.q.clear();
        const std::uint64_t stopped = h[a].store().tip_pos();
        // the rest again, parked, then the first missing one: drained to the top
        for (std::uint64_t x = 33; x >= stopped + 2; --x) (void)h[a].on_carrier(b, frame_at(x));
        (void)h[a].on_carrier(b, frame_at(stopped + 1));
        h.q.clear();
        check(threw && stopped == 9 && h[a].tree().best().id == h[b].tree().best().id,
              "receive: a failure while released carriers are placed: the event throws at 10, the queue cleared; "
              "the next release drains to the top (stopped at " + std::to_string(stopped) + ")");
    }
    {
        // N-1: a P_r served bad on a later page: BAN, the server's earlier variants released
        Harness h(net);
        h.headers_frame = 1500;
        const Split s = split(h);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 16, h.now), "receive: A asks B");
        pb::PathbNode::HeadersOutcome o;
        std::size_t pages = 0, indexed = 0;
        while (!h.q.empty() && pages < 10) {
            const std::vector<std::vector<std::uint8_t>> r = serve_front(h, s);
            o = h[s.a].on_headers(s.b, r.at(0), h.now);
            ++pages;
            indexed += o.indexed;
            if (o.kind != pb::PathbNode::HeadersOutcome::Kind::Continue) break;
            if (pages == 1 && indexed < s.b_ids.size())
                h.bad_served.insert(h[s.b].bodies().get(s.b_ids[indexed])->own.blob.prev_id);
        }
        check(pages >= 2 && indexed > 0 && o.kind == pb::PathbNode::HeadersOutcome::Kind::Ban
                      && pb::PathbNodeTestAccess::headers(h[s.a]).size() == 0,
              "receive: a BadServed P_r on page 2: BAN and the server's variants released (index "
                      + std::to_string(pb::PathbNodeTestAccess::headers(h[s.a]).size()) + ")");
    }
    {
        // N-10: the branch a request accumulates is at most its max
        Harness h(net);
        h.headers_frame = 1500;
        const Split s = split(h);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "receive: A asks B for at most 3");
        const pb::PathbNode::HeadersOutcome o = h[s.a].on_headers(s.b, serve_front(h, s).at(0), h.now);
        check(o.kind == pb::PathbNode::HeadersOutcome::Kind::Keep && o.indexed == 3 && h.q.empty(),
              "receive: 3 headers, max reached: no continuation (kind " + std::to_string(static_cast<int>(o.kind)) + ")");
    }
}

// ---------------------------------------------------------------------------
// HELLO at a node: the leaf count is compared only on a best tip this node placed.
void hellobound() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 30; ++i) {
        if (i % 2 == 0) h.tick_monero();
        h.mine(a, 1, 200 + i);
    }
    const pb::PathbHello ours = h[a].our_hello(1, 0);
    pb::PathbHello theirs = h[b].our_hello(2, 0);
    check(theirs.tail.best_tip == h[a].tree().best().id, "hellobound: B's best tip is placed at A");
    theirs.tail.mmr_leaf_count += 3;
    const pb::HelloCheck c1 = h[a].on_hello(b, *pb::encode_pathb_hello(theirs), ours);
    check(c1.verdict == pb::HelloVerdict::Close && c1.strike == 0,
          "hellobound: a placed best tip with another mmr_leaf_count: the link closed, no strike");
    // a best tip A holds only as a HeaderIndex variant: no leaf-count comparison
    h.cut = {{a, b}, {b, a}};
    h.mine(a, 1, 300);
    h.mine(a, 1, 301);
    const pb::Hash32 fork = h[b].tree().best().id;
    h.mine(b, 1, 302);
    h.cut.clear();
    h.q.clear();
    check(h[a].request_headers(b, fork, h[b].tree().best().id, 8, h.now), "hellobound: A asks B's lighter branch");
    {
        const Msg req = h.q.front();
        h.q.pop_front();
        const pb::PathbNode::HeadersOutcome o = h[a].on_headers(b, h[b].serve_getheaders(a, req.frame, h.now).frames.at(0), h.now);
        check(o.kind == pb::PathbNode::HeadersOutcome::Kind::Keep && o.indexed == 1, "hellobound: B's tip indexed as a variant, not placed");
    }
    pb::PathbHello t2 = h[b].our_hello(3, 0);
    t2.tail.mmr_leaf_count += 3;
    const pb::HelloCheck c2 = h[a].on_hello(b, *pb::encode_pathb_hello(t2), h[a].our_hello(1, 0));
    check(h[a].tree().find(t2.tail.best_tip) == nullptr && c2.verdict == pb::HelloVerdict::Accept,
          "hellobound: a best tip held only as a variant (not bound here): accepted, not compared");
}

// ---------------------------------------------------------------------------
// The header path at the journal base, and a switch_best refusal on a reorg.
void base() {
    const KatNet net;
    const std::uint64_t J = 16;
    {
        Harness h(net);
        const std::size_t a = h.add(table0(net), true, J), b = h.add(table0(net), true, J);
        for (int i = 0; i < 6; ++i) {
            h.tick_monero();
            h.mine(a, 1, 100 + i);
        }
        const pb::Hash32 fork = h[a].tree().best().id;
        const std::uint64_t fpos = h[a].tree().best().pos;
        h.cut = {{a, b}, {b, a}};
        for (std::uint64_t i = 0; i < J; ++i) h.mine(a, 0, 200 + static_cast<std::uint32_t>(i));
        for (std::uint64_t i = 0; i < J + 6; ++i) h.mine(b, 1, 300 + static_cast<std::uint32_t>(i));
        h.cut.clear();
        h.q.clear();
        check(h[a].store().base_pos() == fpos, "base: A's journal base is the fork position");
        check(h[a].request_headers(b, fork, h[b].tree().best().id, 64, h.now), "base: A asks B's branch");
        pb::PathbNode::HeadersOutcome o;
        for (int page = 0; page < 8 && !h.q.empty(); ++page) {
            const Msg req = h.q.front();
            h.q.pop_front();
            o = h[a].on_headers(b, h[b].serve_getheaders(a, req.frame, h.now).frames.at(0), h.now);
            if (o.kind != pb::PathbNode::HeadersOutcome::Kind::Continue) break;
        }
        check(o.kind == pb::PathbNode::HeadersOutcome::Kind::FetchBodies && o.fork_pos == fpos,
              "base: heavier, forked exactly at the journal base: FetchBodies (kind " + std::to_string(static_cast<int>(o.kind)) + ")");
        h.pump();
        check(h[a].tree().best().id == h[b].tree().best().id && h[a].store().best_tip() == h[b].tree().best().id && !h[a].poisoned(),
              "base: the switch by the journal at its base");
    }
    {
        // N-13: switch_best refused on a switch by the journal: NodeInternal, poisoned
        Harness h(net);
        const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
        for (int i = 0; i < 4; ++i) {
            h.tick_monero();
            h.mine(a, 1, 40 + i);
        }
        h.cut = {{a, b}, {b, a}};
        h.mine(b, 9, 610);
        for (int i = 0; i < 3; ++i) h.mine(a, 2, 620 + i);
        h.cut.clear();
        h.q.clear();
        h[b].faults().fail_switch = true;
        pb::NodeEventResult last;
        for (std::uint64_t x = 5; x <= 7; ++x) {
            last = h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(*h[a].store().best_at(x)), 16));
            if (last.action != pb::NodeAction::SideBranch) break;
        }
        check(last.action == pb::NodeAction::NodeInternal && h[b].poisoned(),
              "base: switch_best refused on a switch by the journal: NodeInternal (action "
                      + std::to_string(static_cast<int>(last.action)) + ")");
    }
}

// ---------------------------------------------------------------------------
void boundary() {
    const KatNet net;
    KatNode n(net, 1152);
    const std::uint64_t f = 10;
    // main 1 .. f, then a side carrier t on f, then main f + 1 .. f + J_0 at one Monero height
    std::vector<pb::Hash32> main = scaffold_chain(n, n.tree.genesis().id, f, 0x91, [](std::uint64_t) { return kLaneB0; });
    const std::vector<pb::Hash32> m2 = scaffold_chain(n, main.back(), 2, 0x95, [](std::uint64_t) { return kLaneB0; });
    const pb::CarrierBodyV3 tc = scaffold_body(n, main.back(), kLaneB0, 0x92, 777, 3);
    check(place_direct(n, tc).outcome == pb::WriteOutcome::SideBranch, "boundary: t placed on a side branch at f + 1");
    const pb::Hash32 t = pb::receipt_id(tc.own);
    const std::uint64_t j0 = pb::admit_j0(pb::kRuledLaneParams);
    scaffold_chain(n, m2.back(), j0 - 2, 0x93, [](std::uint64_t) { return kLaneB0; });
    check(n.tree.best().pos == f + j0, "boundary: the best chain at f + J_0");
    // r on t (its coinbase on window(t)); pending at the node whose best is f + J_0
    const pb::ReceiptBodyV3 r = body_on(n, t, kLaneB0 + 1, 4, 4242);
    Harness h(net);
    h.nodes.push_back(node_from(h, n, 1152, 0));
    std::vector<pb::ReceiptBodyV3> one{r};
    const std::vector<pb::NodeEventResult> rs = h[0].on_receipts(5, *pb::encode_fb_receipts(0, one, pb::kRuledLaneParams));
    check(rs.size() == 1 && rs[0].action == pb::NodeAction::Pending, "boundary: r admitted pending (pos(best) - f = J_0)");
    const std::vector<pb::ReceiptBodyV3> c1 = pb::PathbNodeTestAccess::carried(h[0], f + j0 + 1, kLaneB0);
    check(c1.size() == 1 && pb::receipt_id(c1[0]) == pb::receipt_id(r), "boundary: carried at pos(parent(c)) - f = J_0");
    // one carrier more (not carrying r): at J_0 + 1 the receipt is left out (DEFERred on every node)
    scaffold_chain(n, n.tree.best().id, 1, 0x94, [](std::uint64_t) { return kLaneB0; });
    Harness h2(net);
    h2.nodes.push_back(node_from(h2, n, 1152, 0));
    pb::PathbNodeTestAccess::add_pending(h2[0], pb::PendingReceipt{pb::receipt_id(r), r, kLaneB0 + 1, f + 1, 0});
    const std::vector<pb::ReceiptBodyV3> c2 = pb::PathbNodeTestAccess::carried(h2[0], f + j0 + 2, kLaneB0);
    check(c2.empty() && h2[0].pending().holds(pb::receipt_id(r)),
          "boundary: left out of the carried list at pos(parent(c)) - f = J_0 + 1 (kept pending until its bin seals)");
}

// ---------------------------------------------------------------------------
void timers() {
    pb::AbandonTimers<int> at(pb::kAbandonTimeoutDefault);
    at.sent(1, 100);
    check(at.expired(111).empty() && !at.expired(112).empty() && !at.open(1), "timers: P-53 = 11 s: no frame in 12 s -> expired");
    at.sent(2, 100);
    bool alive = true;
    for (std::uint64_t k = 1; k <= 10; ++k) {
        alive = alive && at.expired(100 + 10 * k).empty();
        at.frame(2, 100 + 10 * k);
    }
    check(alive && at.open(2), "timers: restarted at each frame (10 frames 10 s apart: no expiry)");
    check(!at.expired(100 + 100 + 12).empty(), "timers: a gap of 12 s after the last frame: expired (non-service)");
    pb::BucketWirePolicy pol{1000, 1, 10000};
    pb::BucketWindow w(pol);
    check(w.may_request(1, 0), "timers: the first request opens a window");
    w.requested(1, 0);
    w.received(1, 4000, 5);
    w.received(1, 4500, 6);
    check(w.may_request(1, 10) && w.bytes(1) == 8500, "timers: 8,500 of 10,000 bytes: one frame (1,000) still fits");
    w.received(1, 600, 7);
    check(!w.may_request(1, 30) && w.window_end(1) == std::optional<std::uint64_t>(65),
          "timers: 9,100 bytes: no frame left; the next request after the window (first frame + 60 s)");
    check(w.may_request(1, 65), "timers: the window ended: a request opens a new one (the wait is not non-service)");
}

// ---------------------------------------------------------------------------
void buckets() {
    const KatNet net;
    Harness h(net);
    h.bucket_policy = pb::BucketWirePolicy{1200, 1, 12000};  // small frames: about one bin per frame
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true), c = h.add(table0(net), true);
    for (pb::PathbNode* x : {&h[a], &h[b], &h[c]}) (void)x;
    for (int i = 0; i < 80; ++i) {
        h.tick_monero(2);
        h.mine(a, static_cast<std::size_t>(i % 3), 300 + i);
    }
    const pb::Hash32 at = h[a].tree().best().id;
    const std::uint64_t lc = h[a].store().view_at(at).leaf_count();
    check(lc >= 20 && h[b].tree().best().id == at && h[c].tree().best().id == at, "buckets: 20+ bins sealed, B and C on A's tip");
    const std::uint64_t b0 = h[a].store().b0();
    // request 1: bins b0 .. b0 + 9 from B; its frames one per P-53 - 1 s: assembled whole
    check(h[a].request_buckets(b, at, b0, b0 + 9, h.now), "buckets: FC_GETBUCKETS to B");
    h.pump();  // B serves; its frames reach A at once
    check(h[a].open_assemblies() == 0, "buckets: the reply assembled (the bins proved against at's header)");
    // request 2 from B with frames held back: the frames 10 s apart arrive, then a gap of 12 s
    check(h[a].request_buckets(b, at, b0 + 10, b0 + 19, h.now), "buckets: a second request to B");
    std::vector<Msg> replies;
    {
        const Msg req = h.q.front();
        h.q.pop_front();
        for (auto& f : h[b].serve_getbuckets(a, req.frame, h.now).frames) replies.push_back(Msg{b, a, f});
    }
    check(replies.size() >= 3, "buckets: B's reply frames (" + std::to_string(replies.size()) + ")");
    if (replies.size() < 3) return;
    std::uint64_t t = h.now;
    pb::FrameOutcome o1 = h[a].on_buckets(b, replies[0].frame, t).frame;
    t += pb::kAbandonTimeoutDefault + 1;
    const std::size_t expired = h[a].tick(t);
    check(o1.verdict == pb::BucketsFrameVerdict::Accepted && expired == 1, "buckets: a gap of P-53 + 1 s ends the request (non-service)");
    // the same at asked from C; B's late frame: DROP, 0 tokens (one assembly per (peer, at))
    check(h[a].request_buckets(c, at, b0 + 10, b0 + 19, t), "buckets: the bins asked again at C");
    for (std::size_t k = 1; k < replies.size(); ++k) {
        const pb::FrameOutcome late = h[a].on_buckets(b, replies[k].frame, t + k).frame;
        check(late.verdict == pb::BucketsFrameVerdict::Drop && late.strike == 0,
              "buckets: B's late frame " + std::to_string(k) + ": DROP, 0 tokens");
    }
    h.pump();
    check(h[a].open_assemblies() == 0, "buckets: C's reply assembled");
    // a prefix reply whose frames arrive P-53 - 1 s apart: the timer restarts at each frame, assembled whole
    const std::size_t d = c;  // C again, for the next bins (its earlier request for at completed)
    h.q.clear();
    std::uint64_t t2 = t + 1000;
    check(h[a].request_buckets(d, at, b0 + 20, b0 + 29, t2), "buckets: FC_GETBUCKETS to C for the next bins");
    std::vector<std::vector<std::uint8_t>> fd;
    {
        const Msg req = h.q.front();
        h.q.pop_front();
        fd = h[d].serve_getbuckets(a, req.frame, t2).frames;
    }
    bool all = fd.size() >= 3;
    std::size_t expired2 = 0;
    for (const auto& f : fd) {
        t2 += pb::kAbandonTimeoutDefault - 1;
        expired2 += h[a].tick(t2);
        all = all && h[a].on_buckets(d, f, t2).frame.verdict == pb::BucketsFrameVerdict::Accepted;
    }
    check(all && expired2 == 0 && h[a].open_assemblies() == 0,
          "buckets: " + std::to_string(fd.size()) + " frames P-53 - 1 s apart: no expiry, assembled whole");
}
}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_node_kat\n");
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*fn)()) {
        if (only.empty() || only == name) run_part(name, fn);
    };
    run("genesis", genesis);
    run("relay", relay);
    run("race", race);
    run("carriage", carriage);
    run("repend", repend);
    run("n3", n3);
    run("own", own_share);
    run("m23", m23);
    run("restart", restart);
    run("n5", n5);
    run("hold", hold_kind2);
    run("c48", c48);
    run("rrfix3", rrfix3);
    run("deep", deep);
    run("joinserve", joinserve);
    run("n7b2", n7b2);
    run("startup", startup);
    run("poison", poison);
    run("joinpages", joinpages);
    run("tokens", tokens);
    run("receive", receive);
    run("hellobound", hellobound);
    run("base", base);
    run("boundary", boundary);
    run("timers", timers);
    run("buckets", buckets);
    return finish("v37_xmr_pathb_node_kat");
}
