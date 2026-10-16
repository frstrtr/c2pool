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
//                P-53 + 1 s ends it and the late frame DROPs, 0 tokens;
//   relaytok     the relay node (pathb_relay_node.hpp) over links delivered
//                by hand: HELLO both ways and the catch-up headers first from
//                position 0; per opcode 0x51 / 0x52 / 0x54 and 0x53 / 0x55
//                from an asked server: a frame that does not decode strikes
//                the sender once, a frame above its buffer is a DROP with no
//                token; FC_BUCKETS from a peer with no open request: DROP; the
//                attempt's server of a join: an undecodable FC_HEADERS ends the
//                attempt NotServed with 1 strike, one above the buffer NotServed
//                with no token; the next attempt completes over the relay;
//   relaym4      an empty store at position 0 whose catch-up from position 0
//                gets a reply with no header queues the peer's HELLO tip for
//                the joiner; the attempt completes over the relay;
//   relaybudget  the invalid-object budget's defaults (G = (1 + R_MAX) /
//                (2 T) = 0.85 tokens/s, C = N, G_b = 113 N, ban ceil(G_b /
//                G): 1,064 s at N 8, 133 s at N 1); the options override them;
//   relayfetch   the fetches a DEFER names, sent to the frame's sender: a
//                carrier whose parent is unknown (FC_GETCARRIER), one whose
//                carried tip's branch headers are unknown (FC_GETHEADERS of
//                t's branch, the walked carrier bound and placed), one whose
//                walked carrier's bodies are missing (FC_GETCARRIER want_bodies
//                1, its body set); each placed after the reply;
//   relaysmoke   two relay nodes over loopback TCP (pathb_relay_links.hpp),
//                each with its own PathbNode: HELLO both ways, the catch-up,
//                a carrier mined by one placed by the other; a HELLO of frame
//                version 0x01 refused and its link closed, no strike, no ban.
//   relayp15     P-15: the default capacity P-09; a first-seen receipt counts
//                one, a duplicate none; above the budget a frame is DROPPED,
//                no strike, no ban, the link kept; refilled at (1 + R_MAX) / T;
//   relayp15rx   P-15: a receipts frame whose second body's RandomX fails:
//                one job per body: the other two counted at once, the
//                second at its re-run; three first-seen, three counted;
//   alarmbound   the alarm sink counts by (row, cause) and keeps the last
//                entry: it does not grow with the node's life;
//   deferfound   a Monero block found on a job issued before a DEFER is
//                submitted (the job stays for the network-block path)
//   ownbound     the kept own shares bounded by the jobs' lifetime: a stale
//                one leaves though RandomX fails before it; clear()
//                releases the issued jobs;
//   relaystale   a gone peer's events (in flight, posted by its blocked
//                reader) skipped: no join hold for the gone peer;
//   relaytip     on_monero_tip from the follower's thread and under the node
//                lock: both return; the parked index runs again.
//   relaysq      a send queue bound below two FC_HEADERS frames (0 among
//                them) refused at start;
//   revrx_drain  RandomX throws on a released child's first hash inside its
//                parent's completion: caught, the child parked and placed;
//   relayrxhdr   RandomX throws on a catch-up header: no token, asked again;
//   relayrxtype  a std::logic_error inside an admission leaves the call (not
//                a RandomX failure);
//   relaystalem  manual mode: a queued event of a gone peer skipped;
//   relayrxbind  RandomX throws in the bind of a walked carrier: not out of
//                the relay; run again: placed;
//   relaymaxpage at the start floor 17 receipts of 945 B re-offered in one
//                frame (never paused for good);
//   rev99_complete RandomX throws on a frame's own re-admission at its
//                completion: caught; parked and placed;
//   ownrx        RandomX throws on a carried receipt of the own share:
//                RandomxFailure out, the own hash reset; the re-run places it;
//   relayrxbindr RandomX throws in the bind on the receipt path: counted;
//   relayrxbindk a bind refutes one body set, then RandomX throws at the
//                next: the refuting server's token kept;
//   relayp15once P-15 counts a frame once, at its first placement: a
//                carrier placed in its parent's drain, one that waited for its
//                DoS token, one placed on its re-run (a duplicate: none);
//   relayrxbind2 a walk placed a walked carrier, then the bind of the next
//                failed on RandomX: the placed one kept; the re-run places
//                the rest;
//   ownrxrun     the own share path: RandomX fails on an own share: kept, no
//                exit, placed by the re-run; a stale kept share dropped;
//   relayp40     P-40: one HELLO tail, no join attempt; two, the attempt runs;
//   relayp50     P-50: 1 + R_MAX relayed claim-leaf alarms kept, one more drops
//                the link (no ban, no token); solicited ones not counted;
//   relayjoint   the threaded join over TCP (the attempt on the join worker,
//                applied on the owner); a RandomX failure in an attempt ends
//                it alarmed, no token; the next attempt joins;
//   regtestk30   the regtest rig's K30 set: the golden G by default, a G of
//                its own with a rig set, a kind-2 file for epoch 1 accepted
//                at fixed = start + GRACE, refused off regtest.
// ---------------------------------------------------------------------------
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_own_share.hpp"
#include "c2pool/v37/xmr/pathb/pathb_job_source.hpp"
#include "c2pool/v37/xmr/pathb/pathb_relay_links.hpp"
#include "c2pool/v37/xmr/pathb/pathb_relay_node.hpp"
#include "c2pool/v37/xmr/pathb/pathb_startup.hpp"
#include "pathb_kat_join.hpp"
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
    static std::shared_ptr<const BoundWork> own_profile(const PathbNode& n) { return n.own_chain_.bound_work(); }
    static void memo_clear(PathbNode& n) {
        n.memo_.clear();
        n.memo_order_.clear();
    }
    static bool own_pow_set(const PathbNode& n) { return n.own_pow_.has_value(); }
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
// regtestk30: the regtest rig's K30 set (E-43): with no input the default list's G is the golden regtest G; a rig set
// gives a G of its own (rules_digest of the rig list) and K30 of its own, the start-up checks pass, and a kind-2
// file naming epoch 1 (not compiled) passes the table checks at fixed = start + GRACE; refused off regtest.
void regtestk30() {
    const pb::Hash32 golden = pb::hash_from_hex("f91737946910674cbe8dac71618f5c02ab5c6c7d4a431163c9b4d2222ce67e0e");
    const pb::PathbLaneRules def = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    const std::optional<pb::Hash32> g0 = pb::genesis_digest_for(pb::LaneNet::Regtest, def);
    const pb::RatchetParams k30{4, 8, 40};
    const std::optional<pb::PathbLaneRules> rig = pb::regtest_k30_rules(pb::LaneNet::Regtest, k30);
    const std::optional<pb::Hash32> g1 = rig ? pb::genesis_digest_for(pb::LaneNet::Regtest, *rig) : std::nullopt;
    check(g0 && *g0 == golden && rig && g1 && *g1 != golden && *g1 == pb::rules_digest(*rig)
                  && pb::ratchet_params_of(*rig).window == 4 && pb::ratchet_params_of(*rig).grace == 8
                  && pb::ratchet_params_of(*rig).timeout == 40,
          "regtestk30: the default list's G is the golden regtest G; a rig K30 set gives its own G and K30");
    check(!pb::regtest_k30_rules(pb::LaneNet::Testnet, k30) && !pb::regtest_k30_rules(pb::LaneNet::Stagenet, k30)
                  && !pb::regtest_k30_rules(pb::LaneNet::Mainnet, k30),
          "regtestk30: refused off regtest");
    // the start-up checks with the rig set and a kind-2 file naming epoch 1
    pb::StartupInputs in;
    in.net = pb::LaneNet::Regtest;
    in.journal_depth = 1152;
    in.rp = pb::ratchet_params_of(*rig);
    in.T.compiled.push_back(pb::CompiledEpoch{0, *g1, *rig});
    pb::Deployment d;
    d.epoch_no = 1;
    d.rules_digest = seq32(0x11);
    d.kind = pb::kKindFixed;
    d.start = 0;
    d.fixed = 8;
    in.deployments.push_back(d);
    in.hf = 16;
    in.z_lt_view = 300000;
    in.buffers = pb::relay_buffers_default(16, 300000, pb::kRuledLaneParams.r_max).value();
    in.raw.pool_genesis_height = std::to_string(kPoolH);
    in.hash_at = [](std::uint64_t h) -> std::optional<pb::Hash32> { return mon_block(h); };
    in.monero_tip = kMonTop;
    const pb::StartupResult r = pb::startup_checks(in);
    pb::StartupInputs early = in;
    early.deployments[0].fixed = 7;  // fixed < start + GRACE
    check(r.ok() && r.T.attempts.size() == 1 && pb::startup_checks(early).refused == pb::StartupStep::DeploymentTable,
          "regtestk30: the rig set and a kind-2 file for epoch 1 at fixed = start + GRACE start; fixed below it is refused");
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
        // n-2: a RandomX failure while released carriers are placed: the event does not throw; the failed carrier keeps
        // its parked state for the caller (take_rx_failed), the rest continue; run again, the chain drains to the top
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
        } catch (const std::exception&) {
            threw = true;
        }
        h.q.clear();
        const std::uint64_t stopped = h[a].store().tip_pos();
        const std::vector<pb::ParkedFrame> failed = h[a].take_rx_failed();
        const bool kept = failed.size() == 1 && failed[0].id == *h[b].store().best_at(10) && failed[0].peer == b;
        for (const pb::ParkedFrame& f : failed) (void)h[a].on_carrier(f.peer, f.frame);
        h.q.clear();
        check(!threw && stopped == 9 && kept && h[a].take_rx_failed().empty()
                      && h[a].tree().best().id == h[b].tree().best().id,
              "receive: a RandomX failure while released carriers are placed: no throw, stopped at "
                      + std::to_string(stopped) + ", carrier 10 kept for the caller (" + std::to_string(failed.size())
                      + "); run again, the chain drains to the top");
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

// ---------------------------------------------------------------------------
// The relay node in manual mode over links delivered by hand (no socket): node i is peer i + 1 at every other node.
struct FakeWire;
struct FakeLinks final : pb::RelayLinks {
    FakeWire* wire = nullptr;
    std::size_t self = 0;
    FrameFn frame;
    FrameFn control;
    EventFn event;
    std::set<std::uint64_t> live;
    void bind(FrameFn f, FrameFn c, EventFn e) override {
        frame = std::move(f);
        control = std::move(c);
        event = std::move(e);
    }
    void configure(const pb::PathbRelayOptions&) override {}
    bool listen(const std::string&, std::uint16_t) override { return true; }
    std::uint16_t listen_port() const override { return 0; }
    std::uint64_t dial(const std::string&, std::uint16_t) override { return 0; }
    bool send_to(std::uint64_t p, const std::vector<std::uint8_t>& f) override;
    void disconnect(std::uint64_t p) override;
    void ban_key(std::uint64_t, std::uint32_t) override {}
    bool is_banned_key(std::uint64_t) override { return false; }
    std::uint64_t addr_key(std::uint64_t) const override { return 0; }
    bool is_inbound(std::uint64_t) const override { return false; }
    bool has_peer(std::uint64_t p) const override { return live.count(p) != 0; }
    std::vector<std::uint64_t> peer_ids() const override { return {live.begin(), live.end()}; }
    std::size_t conns_from(std::uint64_t) const override { return 0; }
    std::string remote_ip(std::uint64_t) const override { return {}; }
    std::size_t n_peers() const override { return live.size(); }
    void stop() override {}
    std::size_t limit = 0;   // the per-link send queue bound the relay pages within
    std::size_t queued = 0;  // the bytes every link reports queued
    std::size_t send_queue_limit() const override { return limit; }
    std::size_t queued_bytes(std::uint64_t) const override { return queued; }
};

struct FakeWire {
    struct Msg {
        std::size_t from = 0;
        std::size_t to = 0;
        std::vector<std::uint8_t> f;
    };
    std::deque<Msg> q;
    std::mutex qm;  // send_to from a relay's own threads (threads mode)
    std::vector<FakeLinks*> links;
    std::vector<pb::PathbRelayNode*> relays;
    std::function<void(Msg&)> edit;  // edits a frame in flight
    // Delivers one frame, then runs what every relay has queued; false: nothing to deliver.
    bool step() {
        if (q.empty()) return false;
        Msg m = std::move(q.front());
        q.pop_front();
        if (edit) edit(m);
        if (!m.f.empty() && links[m.to]->live.count(m.from + 1) != 0) links[m.to]->frame(m.from + 1, m.f);
        for (pb::PathbRelayNode* r : relays) r->pump();
        return true;
    }
    void run() {
        for (pb::PathbRelayNode* r : relays) r->pump();
        while (step()) {
        }
    }
    void connect(std::size_t a, std::size_t b) {
        links[a]->live.insert(b + 1);
        links[b]->live.insert(a + 1);
        links[a]->event(b + 1, true);
        links[b]->event(a + 1, true);
    }
};

bool FakeLinks::send_to(std::uint64_t p, const std::vector<std::uint8_t>& f) {
    if (live.count(p) == 0) return false;
    const std::lock_guard<std::mutex> lk(wire->qm);
    wire->q.push_back(FakeWire::Msg{self, static_cast<std::size_t>(p - 1), f});
    return true;
}
void FakeLinks::disconnect(std::uint64_t p) {
    if (live.erase(p) == 0) return;
    FakeLinks& o = *wire->links[p - 1];
    o.live.erase(self + 1);
    event(p, false);
    o.event(self + 1, false);
}

struct KatRelay {
    std::unique_ptr<FakeLinks> links;
    std::unique_ptr<pb::PathbRelayNode> relay;
    std::size_t node = 0;
};

// A relay node in manual mode on the harness's clock with its own PathbNode (a load failure when `failed`;
// `tweak`: its options changed; `cfg_tweak`: its node's configuration; `io_tweak`: its node's I/O).
KatRelay kat_relay(Harness& h, FakeWire& w, const pb::EpochTable& T, bool launch, bool failed = false,
                   const std::function<void(pb::PathbRelayOptions&)>& tweak = nullptr,
                   const std::function<void(pb::PathbNodeConfig&)>& cfg_tweak = nullptr,
                   const std::function<void(pb::PathbNodeIo&)>& io_tweak = nullptr) {
    KatRelay k;
    k.links = std::make_unique<FakeLinks>();
    k.links->wire = &w;
    k.links->self = w.links.size();
    w.links.push_back(k.links.get());
    pb::PathbRelayOptions o;
    o.threads = false;
    o.keepalive_ms = 0;
    if (tweak) tweak(o);
    pb::RelayClock clock;
    clock.mono_ms = [&h] { return h.now * 1000; };
    clock.wall_s = [&h] { return h.now; };
    k.relay = std::make_unique<pb::PathbRelayNode>(o, *k.links, clock);
    k.node = h.nodes.size();
    pb::PathbNodeIo io = k.relay->bind_io(h.io(k.node));
    if (io_tweak) io_tweak(io);
    pb::PathbNodeConfig cfg = h.config(T, launch);
    if (cfg_tweak) cfg_tweak(cfg);
    if (failed) {
        h.kvs.push_back(std::make_unique<MemoryKv>());
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, std::move(io), h.kvs.back().get(), pb::PathbNode::LoadFailed{}));
    } else {
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, std::move(io)));
    }
    k.relay->attach(*h.nodes.back());
    k.relay->set_drive([&w] { return w.step(); });
    std::string why;
    if (!k.relay->start(why)) throw std::runtime_error(why);
    w.relays.push_back(k.relay.get());
    return k;
}

std::string op_hex(std::uint8_t op) { return "0x" + hex(&op, 1); }

void relaytok() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    bool mined = true;
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        const std::optional<pb::PathbJob> j = h.job(a.node, static_cast<std::size_t>(i % 5), 100 + i);
        mined = mined && j && h[a.node].on_own_share(*j, 100 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    w.connect(0, 1);
    w.run();
    const pb::Hash32 tip_a = h[a.node].tree().best().id;
    check(mined && a.relay->hello_ok(2) && b.relay->hello_ok(1) && h[b.node].tree().best().id == tip_a
                  && h[b.node].tree().best().pos == 6 && b.relay->stats().catchup_requests >= 1
                  && b.relay->stats().empty_store_offers == 0 && h[b.node].joiner().queue().size() == 0,
          "relaytok: HELLO both ways; B catches up headers first from position 0 to A's tip (" +
                  std::to_string(h[b.node].tree().best().pos) + ")");
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = 1;  // A at B
    const auto tok = [&](const std::vector<std::uint8_t>& f) {
        const std::uint64_t s0 = rb.strikes_of(pa), d0 = rb.stats().drops.load();
        rb.receive(pa, f);
        w.run();
        return std::make_pair(rb.strikes_of(pa) - s0, rb.stats().drops.load() - d0);
    };
    const auto big = [](std::uint8_t op, std::uint8_t ver, std::uint64_t n) {
        std::vector<std::uint8_t> f(n, 0x00);
        f[0] = op;
        f[1] = ver;
        return f;
    };
    // the requests: a frame that does not decode strikes once; above the frame buffer: DROP, no token
    const std::uint64_t fb = h[b.node].config().buffers.frame;
    for (const std::uint8_t op : {pb::kOpFcGetCarrier, pb::kOpFcGetHeaders, pb::kOpFcGetBuckets}) {
        const auto u = tok({op, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
        const auto o = tok(big(op, 0x01, fb + 1));
        check(u.first == 1 && u.second == 0 && o.first == 0 && o.second == 1,
              "relaytok: " + op_hex(op) + " that does not decode: 1 strike (" + std::to_string(u.first) +
                      "); above the frame buffer: DROP, no token (" + std::to_string(o.first) + " strikes)");
    }
    // FC_HEADERS from an asked server
    const bool asked = rb.with_node([&](pb::PathbNode& n) { return n.request_headers(pa, n.tree().genesis().id, tip_a, 8, h.now); });
    w.q.clear();  // A's own reply is not delivered
    const auto ho = tok(big(pb::kOpFcHeaders, 0x02, h[b.node].frame_bytes_headers() + 1));
    const auto hu = tok({pb::kOpFcHeaders, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    check(asked && ho.first == 0 && ho.second == 1 && hu.first == 1 && hu.second == 0,
          "relaytok: 0x53 from an asked server: above the buffer DROP, no token; then one that does not decode: 1 strike (" +
                  std::to_string(hu.first) + ")");
    // FC_BUCKETS from an asked server; then from a peer with no open request
    const bool askb = rb.with_node([&](pb::PathbNode& n) { return n.request_buckets(pa, tip_a, n.store().b0(), n.store().b0(), h.now); });
    w.q.clear();
    const auto bo = tok(big(pb::kOpFcBuckets, 0x01, h[b.node].config().bucket_policy.frame_bytes + 1));
    const auto bu = tok({pb::kOpFcBuckets, 0x01, 0x00, 0x00, 0x00, 0x00});
    const auto bl = tok({pb::kOpFcBuckets, 0x01, 0x00, 0x00, 0x00, 0x00});
    check(askb && bo.first == 0 && bo.second == 1 && bu.first == 1 && bu.second == 0 && bl.first == 0 && bl.second == 1,
          "relaytok: 0x55 from an asked server: above the buffer DROP, no token; one that does not decode: 1 strike (" +
                  std::to_string(bu.first) + "); with no open request: DROP");
    // opcodes the relay node does not handle: counted, no token, the link kept
    const std::uint64_t un0 = rb.stats().unknown_opcodes.load();
    const auto k42 = tok({0x42, 0x01, 0x00, 0x00, 0x00, 0x00});
    const auto k41 = tok({pb::kOpFbReceipts, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01});
    const auto k4a = tok({0x4a, 0x01});
    check(k42.first == 0 && k41.first == 0 && k4a.first == 0 && rb.stats().unknown_opcodes - un0 == 3 && rb.hello_ok(pa),
          "relaytok: FB_BLOCK_WON 0x42, receipts v2 (0x41 at frame version 0x01) and 0x4a: unknown, no token, the link kept");
    check(rb.stats().bans == 0, "relaytok: no ban");

    // the attempt's server of a join (a load-failed node J: A's HELLO tip is a candidate; one HELLO tail, P-40 at 1)
    KatRelay j = kat_relay(h, w, table0(net), false, true, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; });
    w.connect(0, 2);
    w.run();
    const std::uint64_t pj = 1;  // A at J
    check(j.relay->hello_ok(pj) && h[j.node].joiner().queue().size() == 1, "relaytok: a load-failed node queues A's HELLO tip");
    const auto reply_from_a = [&](std::function<void(std::vector<std::uint8_t>&)> fn) {
        w.edit = [fn](FakeWire::Msg& m) {
            if (m.from == 0 && m.to == 2 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders) fn(m.f);
        };
    };
    reply_from_a([](std::vector<std::uint8_t>& f) { f = {pb::kOpFcHeaders, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; });
    const std::optional<pb::JoinStep> s1 = j.relay->join_step();
    w.edit = nullptr;
    w.run();
    check(s1 && s1->report && s1->report->end == pb::AttemptEnd::NotServed && j.relay->strikes_of(pj) == 1
                  && j.relay->stats().join_strikes == 1,
          "relaytok: an FC_HEADERS that does not decode from the attempt's server: NotServed, 1 strike (" +
                  std::to_string(j.relay->strikes_of(pj)) + ")");
    const std::uint64_t hb = h[j.node].frame_bytes_headers() + 1;
    reply_from_a([&](std::vector<std::uint8_t>& f) { f = big(pb::kOpFcHeaders, 0x02, hb); });
    const std::optional<pb::JoinStep> s2 = j.relay->join_step();
    w.edit = nullptr;
    w.run();
    check(s2 && s2->report && s2->report->end == pb::AttemptEnd::NotServed && j.relay->strikes_of(pj) == 1,
          "relaytok: an FC_HEADERS above the buffer from the attempt's server: DROP, no token (NotServed)");
    const std::optional<pb::JoinStep> s3 = j.relay->join_step();
    w.run();
    check(s3 && s3->switched && h[j.node].tree().best().id == tip_a && j.relay->strikes_of(pj) == 1
                  && j.relay->open_tickets() == 0,
          "relaytok: the next attempt completes over the relay (the young chain to A's tip)" +
                  (s3 && s3->report ? std::string(": ") + std::to_string(static_cast<int>(s3->report->end)) : std::string()));
}

// ---------------------------------------------------------------------------
// The empty-store start: a node at position 0 whose catch-up from position 0 gets a reply with no header (a peer that
// serves nothing after position 0) queues the peer's HELLO tip for the joiner; the attempt completes over the relay.
void relaym4() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay e = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; });
    bool mined = true;
    for (int i = 0; i < 4; ++i) {
        const std::optional<pb::PathbJob> j = h.job(a.node, static_cast<std::size_t>(i), 400 + i);
        mined = mined && j && h[a.node].on_own_share(*j, 400 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    const pb::Hash32 tip_a = h[a.node].tree().best().id;
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders)
            m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);
    };
    w.connect(0, 1);
    w.run();
    w.edit = nullptr;
    check(mined && e.relay->stats().empty_store_offers == 1 && h[e.node].joiner().queue().size() == 1
                  && h[e.node].tree().best().pos == 0 && e.relay->strikes_of(1) == 0,
          "relaym4: an empty store at position 0 whose catch-up reply from position 0 carries no header queues the "
          "peer's HELLO tip for the joiner, no token");
    const std::optional<pb::JoinStep> s = e.relay->join_step();
    w.run();
    check(s && s->switched && h[e.node].tree().best().id == tip_a,
          "relaym4: the attempt at that peer completes over the relay (the young chain to its tip)");
}

// ---------------------------------------------------------------------------
// The invalid-object budget's defaults: G = (1 + R_MAX) / (2 T), C = N, G_b = n x C over n = P-23 + P-24, ban
// ceil(G_b / G); the options override them.
void relaybudget() {
    const pb::LaneParams& p = pb::kRuledLaneParams;
    const double g = static_cast<double>(1 + p.r_max) / static_cast<double>(2 * p.carrier_interval_s);
    const pb::PathbRelayOptions o0;
    const std::size_t n = o0.max_inbound + o0.max_outbound;
    check(g == 0.85 && n == 113, "relaybudget: G = (1 + R_MAX) / (2 T) = " + std::to_string(g) + " tokens/s; n = " +
                                         std::to_string(n) + " links");
    const pb::RelayBudget b8 = pb::relay_budget_default(8, n), b1 = pb::relay_budget_default(1, n);
    check(b8.dos.global_refill == g && b8.dos.per_peer_refill == g / 113.0 && b8.dos.per_peer_capacity == 8.0
                  && b8.dos.global_capacity == 904.0 && b8.ban_seconds == 1064,
          "relaybudget: N = 8: G 0.85, C 8, G_b 904, ban " + std::to_string(b8.ban_seconds) + " s");
    check(b1.dos.global_refill == g && b1.dos.per_peer_capacity == 1.0 && b1.dos.global_capacity == 113.0
                  && b1.ban_seconds == 133,
          "relaybudget: N = 1: G 0.85, C 1, G_b 113, ban " + std::to_string(b1.ban_seconds) + " s");
    FakeWire w;
    FakeLinks l0, l1;
    l0.wire = l1.wire = &w;
    pb::PathbRelayOptions o8 = o0;
    o8.threads = false;
    o8.verify_threads = 8;
    pb::RelayClock clock;
    clock.mono_ms = [] { return std::uint64_t{0}; };
    clock.wall_s = [] { return std::uint64_t{0}; };
    const pb::PathbRelayNode r1(o0, l0, clock);
    const pb::PathbRelayNode r8(o8, l1, clock);
    pb::PathbRelayOptions ov = o8;
    ov.ban_seconds = 600;
    ::c2pool::xmr::DosPolicy d;
    d.global_refill = 4.0;
    ov.dos = d;
    FakeLinks l2;
    l2.wire = &w;
    const pb::PathbRelayNode rv(ov, l2, clock);
    check(r1.budget().ban_seconds == 133 && r1.budget().dos.per_peer_capacity == 1.0 && r8.budget().ban_seconds == 1064
                  && r8.budget().dos.global_capacity == 904.0 && rv.budget().ban_seconds == 600
                  && rv.budget().dos.global_refill == 4.0,
          "relaybudget: the relay node's defaults (1 and 8 verify workers); the options override the ban and the budget");
}

// ---------------------------------------------------------------------------
// The fetches a DEFER names, sent to the frame's sender over the relay and placed after the reply.
bool mine_on(Harness& h, FakeWire& w, std::size_t node, std::size_t payee, std::uint32_t nonce) {
    const std::optional<pb::PathbJob> j = h.job(node, payee, nonce);
    const bool ok = j && h[node].on_own_share(*j, nonce, pb::Hash32{}).action == pb::NodeAction::Placed;
    w.run();
    return ok;
}

struct TipFetch {
    bool setup = false;
    bool carried = false;   // the losing node's carrier c carries a receipt whose tip is its losing sibling
    std::uint64_t n_carried = 0;  // the losing sibling's carried bodies
    bool placed = false;    // c and the losing sibling placed at X
    std::uint64_t tip_requests = 0, body_set_requests = 0, body_sets = 0, walk_placed = 0, strikes = 0;
    std::size_t index_left = 0;  // digests left in the relay's re-run index
};

// A, L race; the losing node's next carrier c carries its share on its losing sibling; X catches up from the losing
// node alone (its best chain), so c's carried tip is unknown at X. `bodies`: both siblings carry two receipts.
TipFetch relay_tip_fetch(bool bodies) {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    TipFetch out;
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    if (bodies) {
        const std::optional<pb::PathbJob> ja = h.job(a.node, 2, 350), jl = h.job(l.node, 3, 351);
        ok = ok && ja && jl && mine_on(h, w, a.node, 1, 352);
        ok = ok && h[a.node].on_own_share(*ja, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
        ok = ok && h[l.node].on_own_share(*jl, 351, pb::Hash32{}).action == pb::NodeAction::Pending;
        w.run();
    }
    // the race: the A-L link delivers nothing while each mines a sibling and takes a job on it
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 2, 400) && mine_on(h, w, l.node, 3, 401);
    const pb::Hash32 sa = h[a.node].tree().best().id, sl = h[l.node].tree().best().id;
    const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410), kl = h.job(l.node, 4, 411);
    w.edit = nullptr;
    ok = ok && sa != sl && ka && kl && h[a.node].bodies().get(sa) != nullptr && h[l.node].bodies().get(sl) != nullptr;
    if (!ok) return out;
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(sa), 16)});
    w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(sl), 16)});
    w.run();
    const bool a_lost = sl < sa;
    const std::size_t lo = a_lost ? a.node : l.node;
    const pb::Hash32 loser = a_lost ? sa : sl;
    const pb::PathbJob k = a_lost ? *ka : *kl;
    const std::uint32_t kn = a_lost ? 410 : 411;
    ok = ok && h[a.node].tree().best().id == h[l.node].tree().best().id && h[a.node].tree().best().id != loser;
    out.n_carried = h[lo].bodies().get(loser)->carried.size();
    ok = ok && h[lo].on_own_share(k, kn, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    h.tick_monero();
    ok = ok && mine_on(h, w, lo, 5, 420);
    const pb::Hash32 c = h[lo].tree().best().id;
    pb::ReceiptBodyV3 rk = k.body;
    rk.blob.nonce = kn;
    const pb::Hash32 r = pb::receipt_id(rk);
    const pb::CarrierBodyV3* cb = h[lo].bodies().get(c);
    for (const pb::ReceiptBodyV3& b : cb != nullptr ? cb->carried : std::vector<pb::ReceiptBodyV3>{})
        out.carried = out.carried || (pb::receipt_id(b) == r && b.side.tip == loser);
    out.setup = ok;
    if (!ok) return out;
    // X catches up from the losing node alone
    w.connect(lo, x.node);
    w.run();
    for (int i = 0; i < 3 && h[x.node].tree().best().id != c; ++i) {
        h.now += 1;
        x.relay->tick();
        w.run();
    }
    out.placed = h[x.node].tree().best().id == c && h[x.node].tree().find(loser) != nullptr;
    const pb::PathbRelayStats& st = x.relay->stats();
    out.tip_requests = st.tip_header_requests;
    out.body_set_requests = st.body_set_requests;
    out.body_sets = st.body_sets;
    out.walk_placed = st.walk_placed;
    out.strikes = st.strikes;
    out.index_left = x.relay->parked_index_size();
    return out;
}

void relayfetch() {
    // a carrier whose parent is unknown: the parent asked of the sender, placed, then the carrier
    {
        const KatNet net;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false);
        w.connect(0, 1);
        w.run();
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, 1, 200 + static_cast<std::uint32_t>(i));
        }
        bool dropped = false;
        w.edit = [&dropped](FakeWire::Msg& m) {
            if (!dropped && m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcCarrier) {
                m.f.clear();
                dropped = true;
            }
        };
        ok = ok && mine_on(h, w, a.node, 2, 210);
        w.edit = nullptr;
        const pb::Hash32 c1 = h[a.node].tree().best().id;
        const bool missed = dropped && h[b.node].tree().find(c1) == nullptr;
        ok = ok && mine_on(h, w, a.node, 3, 211);
        const pb::Hash32 c2 = h[a.node].tree().best().id;
        check(ok && missed && h[b.node].tree().best().id == c2 && h[b.node].tree().find(c1) != nullptr
                      && b.relay->stats().solicited_jobs >= 1 && b.relay->strikes_of(1) == 0,
              "relayfetch: a carrier whose parent is unknown: the parent fetched from the sender (FC_GETCARRIER), "
              "both placed (solicited " + std::to_string(b.relay->stats().solicited_jobs.load()) + ")");
    }
    // a carrier whose carried tip's branch headers are unknown
    {
        const TipFetch t = relay_tip_fetch(false);
        check(t.setup && t.carried && t.n_carried == 0 && t.placed && t.tip_requests >= 1 && t.walk_placed >= 1
                      && t.strikes == 0 && t.index_left == 0,
              "relayfetch: a carrier whose carried tip is unknown: t's branch headers fetched from the sender "
              "(FC_GETHEADERS), the walked carrier bound and placed, then the carrier (requests " +
                      std::to_string(t.tip_requests) + ", walked placed " + std::to_string(t.walk_placed) + ")");
    }
    // a carrier whose walked carrier's bodies are missing
    {
        const TipFetch t = relay_tip_fetch(true);
        check(t.setup && t.carried && t.n_carried >= 1 && t.placed && t.tip_requests >= 1 && t.body_set_requests >= 1
                      && t.body_sets >= 1 && t.walk_placed >= 1 && t.strikes == 0 && t.index_left == 0,
              "relayfetch: a carrier whose walked carrier carries bodies: its body set fetched from the sender "
              "(FC_GETCARRIER, want_bodies 1), the walked carrier placed, then the carrier (carried " +
                      std::to_string(t.n_carried) + ", body sets " + std::to_string(t.body_sets) + ")");
    }
}

// ---------------------------------------------------------------------------
// Two relay nodes over loopback TCP, each with its own PathbNode, their threads running.
bool wait_for(const std::function<bool()>& f, int ms) {
    for (int t = 0; t < ms; t += 10) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return f();
}

void relaysmoke() {
    const KatNet net;
    Harness h(net);
    std::atomic<std::uint64_t> rx{0};
    const auto io_of = [&](std::size_t self) {
        pb::PathbNodeIo o = h.io(self);
        o.verify = [&rx](const pb::HashingBlob&, std::uint64_t, const pb::Hash32&) {
            ++rx;
            return true;
        };
        return o;
    };
    h.tick_monero();
    pb::CarrierLinks la, lb;
    pb::PathbRelayOptions oa;
    oa.listen = true;
    oa.listen_host = "127.0.0.1";
    oa.verify_threads = 2;
    pb::PathbRelayNode ra(oa, la);
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true), ra.bind_io(io_of(0))));
    ra.attach(*h.nodes[0]);
    bool mined = true;
    for (int i = 0; i < 3; ++i) {
        const std::optional<pb::PathbJob> j = h.job(0, static_cast<std::size_t>(i), 300 + i);
        mined = mined && j && h[0].on_own_share(*j, 300 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    std::string why;
    const bool sa = ra.start(why);
    pb::PathbRelayOptions ob;
    ob.peers = {{"127.0.0.1", la.listen_port()}};
    ob.verify_threads = 2;
    pb::PathbRelayNode rb(ob, lb);
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net)), rb.bind_io(io_of(1))));
    rb.attach(*h.nodes[1]);
    const bool sb = rb.start(why);
    check(mined && sa && sb, "relaysmoke: A listens on loopback, B dials it (" + why + ")");
    const auto best = [](pb::PathbRelayNode& r) { return r.with_node([](pb::PathbNode& n) { return n.tree().best().id; }); };
    const bool linked = wait_for([&] { return ra.ready_peers().size() == 1 && rb.ready_peers().size() == 1; }, 10000);
    const pb::Hash32 tip3 = best(ra);
    const bool caught = wait_for([&] { return best(rb) == tip3; }, 10000);
    check(linked && ra.stats().hello_ok == 1 && rb.stats().hello_ok == 1 && caught,
          "relaysmoke: HELLO both ways over TCP; B catches up headers first to A's tip (linked " +
                  std::to_string(linked) + ", caught " + std::to_string(caught) + "; " + ra.describe() + " || " +
                  rb.describe() + ")");
    const pb::NodeAction placed4 = ra.with_node([&](pb::PathbNode& n) {
        const std::optional<pb::PathbJob> j = h.job(0, 4, 304);
        return j ? n.on_own_share(*j, 304, pb::Hash32{}).action : pb::NodeAction::None;
    });
    const pb::Hash32 tip4 = best(ra);
    const bool flooded = wait_for([&] { return best(rb) == tip4; }, 10000);
    check(placed4 == pb::NodeAction::Placed && tip4 != tip3 && flooded,
          "relaysmoke: a carrier A mines is flooded over TCP and placed by B");
    // an old node's HELLO (frame version 0x01): refused, the link closed, no strike, no ban
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(la.listen_port());
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bool closed = false;
    if (fd >= 0 && ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0) {
        timeval tv{};
        tv.tv_sec = 5;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::c2pool::v37n::xmr::relay::Hello old;
        old.network = 3;
        const std::vector<std::uint8_t> f = ::c2pool::v37n::xmr::relay::encode_hello(old);
        std::vector<std::uint8_t> msg;
        for (int i = 0; i < 4; ++i) msg.push_back(static_cast<std::uint8_t>(f.size() >> (8 * i)));
        msg.insert(msg.end(), f.begin(), f.end());
        (void)::send(fd, msg.data(), msg.size(), 0);
        std::uint8_t buf[4096];
        for (int i = 0; i < 64; ++i) {
            const ssize_t k = ::recv(fd, buf, sizeof buf, 0);
            if (k == 0) {
                closed = true;
                break;
            }
            if (k < 0) break;
        }
    }
    if (fd >= 0) ::close(fd);
    const bool refused = wait_for([&] { return ra.stats().hello_old_version == 1; }, 5000);
    check(refused && closed && ra.stats().strikes == 0 && ra.stats().bans == 0,
          "relaysmoke: a HELLO of frame version 0x01 refused (old=" +
                                                 std::to_string(ra.stats().hello_old_version.load()) +
                                                 "), its link closed, no strike, no ban");
    rb.stop();
    ra.stop();
}

// ---------------------------------------------------------------------------
// The prune step (P-51; the node's own horizon) over one scaffold chain built
// once: the store at 5,000 positions (a span whose body floor seals no bin),
// then 7,000 positions; side carriers forking at the default body floor at
// 7,000 (fb), one below it (fb - 1) and one above it (fb + 1), held in the
// chain's tree (not in its store).
constexpr std::uint64_t kPruneJ = 1152;
constexpr std::uint64_t kYoungL = 5000;
constexpr std::uint64_t kPruneL = 7000;

std::optional<std::uint64_t> h_rec(std::uint64_t x) { return h_pos(x); }

struct PruneFloorsWant {
    std::uint64_t bodies = 0, records = 0, sides = 0;
};

// The floors at the tip L of a chain with H(x) = h_pos(x), from the formulas: P-51 (span_bounds and pre_start; none
// while no bin is sealed at or before the body floor) or a flag (positions through L); the node's own horizon of a
// store launched here (min(s(L), L - P-04 + 1)) and the view horizon (L - J) - J_0.
PruneFloorsWant want_floors(std::uint64_t L, std::uint64_t J, std::optional<std::uint64_t> body_keep = std::nullopt,
                            std::optional<std::uint64_t> header_keep = std::nullopt,
                            std::optional<std::uint64_t> side_keep = std::nullopt) {
    const pb::LaneParams& p = pb::kRuledLaneParams;
    const std::uint64_t j0 = pb::journal_j0(p, pb::kSealDepth), nrt = pb::join_n_rt(p);
    std::uint64_t p51_bodies = 0, p51_headers = 0;
    const pb::SpanResult sp = pb::span_bounds(p, L, h_rec, kLaneB0);
    if (sp.status == pb::SpanStatus::Ok && !sp.bounds.young && sp.bounds.x0 > j0 + 1) {
        const std::uint64_t body = sp.bounds.x0 - j0 - 1;
        if (pb::bin_leaf_count(h_pos(body), kLaneB0, p.open_bins) > 0) {
            p51_bodies = body;
            if (sp.bounds.x0 > nrt) p51_headers = pb::pre_start(p, sp.bounds.x0, h_rec).read_lo;
        }
    }
    const auto through = [L](std::uint64_t n) { return L + 1 > n ? L + 1 - n : 0; };
    const std::uint64_t q0 = L + 1 - J;
    const std::uint64_t floor_h = h_pos(q0 - 1) - (p.open_bins + p.fresh_max);
    std::uint64_t s = 1;
    while (h_pos(s) <= floor_h) ++s;
    const std::uint64_t own = std::min(s, through(std::max<std::uint64_t>(1152, J)));
    const std::uint64_t view = L - J - j0;
    PruneFloorsWant w;
    w.bodies = std::min({body_keep ? through(*body_keep) : p51_bodies, own, view});
    w.sides = std::min(side_keep ? through(*side_keep) : p51_bodies, view);
    w.records = std::min({header_keep ? through(*header_keep) : p51_headers, w.bodies, w.bodies + 1 > nrt ? w.bodies + 1 - nrt : 0});
    return w;
}

struct PruneChain {
    JoinNet net{900};
    std::optional<KatStoreNode> sn;
    MemoryKv young_kv;
    std::uint64_t fb = 0;
    pb::Hash32 side_at{}, side_below{}, side_above{};
};

PruneChain& prune_chain() {
    static PruneChain* c = [] {
        auto* x = new PruneChain;
        x->fb = want_floors(kPruneL, kPruneJ).bodies;
        x->sn.emplace(x->net, kPruneJ);
        KatNode& n = x->sn->n;
        store_chain(*x->sn, x->fb + 5, 0x91, 1, 31);
        const auto side = [&](std::uint64_t fork, std::uint64_t k) {
            const pb::CarrierBodyV3 c = scaffold_carrier(n, *n.store.best_at(fork), h_pos(fork + 1), 0x93, k, 3, {});
            const bool ok = place_direct(n, c).outcome == pb::WriteOutcome::SideBranch;
            check(ok, "prune chain: a side carrier forking at " + std::to_string(fork));
            return pb::receipt_id(c.own);
        };
        x->side_at = side(x->fb, 70001);
        x->side_below = side(x->fb - 1, 70002);
        x->side_above = side(x->fb + 1, 70003);
        store_chain(*x->sn, kYoungL - n.tree.best().pos, 0x91, 1, 32);
        x->young_kv = x->sn->kv;
        store_chain(*x->sn, kPruneL - n.tree.best().pos, 0x91, 1, 33);
        check(n.tree.best().pos == kPruneL && x->fb > 0, "prune chain: 7,000 positions, the default body floor "
                                                                + std::to_string(x->fb));
        return x;
    }();
    return *c;
}

// A node loaded from a copy of `from` (the copy held by the harness and written by the node).
std::size_t load_node(Harness& h, const MemoryKv& from, pb::PathbNodeConfig cfg, pb::LoadResult* out = nullptr) {
    h.kvs.push_back(std::make_unique<MemoryKv>(from));
    MemoryKv& kv = *h.kvs.back();
    pb::LoadInputs in;
    in.T = cfg.T;
    in.journal_depth = cfg.journal_depth;
    pb::LoadResult lr = pb::pathb_load(kv, h.net.pool_id, h.net.rules_g, in);
    if (out != nullptr) out->fault = lr.fault;
    check(lr.fault == pb::StoreFault::None && lr.state.has_value(), "load_node: the store loads");
    const std::size_t i = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, h.io(i), std::move(*lr.state), &kv));
    return i;
}

// A node reloaded from `kv` (no store of its own).
std::size_t reload_node(Harness& h, MemoryKv& kv, std::uint64_t J, pb::StoreFault* fault) {
    pb::LoadInputs in;
    in.T = kat_table(h.net);
    in.journal_depth = J;
    pb::LoadResult lr = pb::pathb_load(kv, h.net.pool_id, h.net.rules_g, in);
    *fault = lr.fault;
    if (!lr.state) return SIZE_MAX;
    const std::size_t i = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(h.net), true, J), h.io(i), std::move(*lr.state), nullptr));
    return i;
}

std::size_t count_keys(const MemoryKv& kv, const std::string& prefix) {
    std::size_t n = 0;
    for (auto it = kv.data.lower_bound(prefix); it != kv.data.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it)
        ++n;
    return n;
}

std::map<std::string, std::string> keys_of(const MemoryKv& kv, const std::string& prefix) {
    std::map<std::string, std::string> out;
    for (auto it = kv.data.lower_bound(prefix); it != kv.data.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it)
        out.insert(*it);
    return out;
}

std::optional<pb::CarrierRecord> record_at(const MemoryKv& kv, std::uint64_t x) {
    const auto it = kv.data.find(pb::store_keys::pcarrier(0, x));
    if (it == kv.data.end()) return std::nullopt;
    return pb::decode_pcarrier(it->second);
}

bool header_record(const std::optional<pb::CarrierRecord>& c) {
    return c && !c->state && c->kind == pb::RecordBody::Header && c->placements.empty();
}
bool full_record(const std::optional<pb::CarrierRecord>& c) { return c && c->state && c->kind == pb::RecordBody::Carrier; }

std::string floors_text(const pb::PathbNode::PruneFloors& f) {
    return "bodies " + std::to_string(f.bodies) + ", records " + std::to_string(f.records) + ", sides " + std::to_string(f.sides);
}

// The retarget window through the tree's root (its inherited entries).
std::vector<std::pair<std::uint64_t, std::uint64_t>> root_window(const pb::PathbNode& n) {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
    const auto e = n.tree().window_entries(n.tree().genesis().id, pb::kRuledLaneParams.retarget_span);
    if (e)
        for (const pb::RetargetEntry& r : *e) out.emplace_back(r.d, r.H);
    return out;
}

// ---------------------------------------------------------------------------
// prune_young: at 5,000 positions the body floor x0(L') - J_0 - 1 seals no bin: P-51 keeps everything from position
// 1 and the prune changes nothing (no store write).
void prune_young() {
    PruneChain& c = prune_chain();
    Harness h(c.net);
    const std::size_t a = load_node(h, c.young_kv, h.config(kat_table(c.net), true, kPruneJ));
    const pb::LaneParams& p = pb::kRuledLaneParams;
    const pb::SpanResult sp = pb::span_bounds(p, kYoungL, h_rec, kLaneB0);
    const std::uint64_t body = sp.bounds.x0 - pb::journal_j0(p, pb::kSealDepth) - 1;
    check(!sp.bounds.young && body > 0 && pb::bin_leaf_count(h_pos(body), kLaneB0, p.open_bins) == 0,
          "prune young: the body floor " + std::to_string(body) + " seals no bin (lc 0)");
    const pb::LaneKv before = h.kvs.back()->data;
    const std::uint64_t commits = h.kvs.back()->commits;
    const pb::PathbNode::PruneReport r = h[a].prune(h.now);
    const pb::Hash32 one = *h[a].store().best_at(1);
    check(r.floors.bodies == 0 && r.floors.records == 0 && r.root == 0 && r.first == 0 && !r.written
                  && h[a].tree().genesis().pos == 0 && h[a].bodies().get(one) != nullptr && h[a].store().first_record_pos() == 0
                  && h.kvs.back()->data == before && h.kvs.back()->commits == commits && full_record(record_at(*h.kvs.back(), 1)),
          "prune young: everything kept from position 1 (" + floors_text(r.floors) + "; root " + std::to_string(r.root) + ")");
}

// ---------------------------------------------------------------------------
// prune_default: at 7,000 positions the default floors: bodies and tree nodes from x0(L') - J_0 - 1, carrier records
// from the retarget window through the tree's root (below the P-51 header floor), side branches from the body floor.
// One store batch; K_BLHASH, K_BLEAF, K_BMMR, K_AR unchanged; the lane digest unchanged; the pruned node serves the
// items it keeps and not the ones below; a restart reloads to the same lane digest and root window; A's bound work
// below the floor in the prune batch (K_BWORK), loaded at the restart: the same profile, the same rule (4) verdict.
void prune_default() {
    PruneChain& c = prune_chain();
    Harness h(c.net);
    const std::size_t a = load_node(h, c.sn->kv, h.config(kat_table(c.net), true, kPruneJ));
    MemoryKv& kv = *h.kvs.back();
    const PruneFloorsWant w = want_floors(kPruneL, kPruneJ);
    const pb::PathbNode::PruneFloors f = h[a].prune_floors(h.now);
    check(f.bodies == w.bodies && f.records == w.records && f.sides == w.sides && w.bodies == c.fb && w.records > 0
                  && w.records < w.bodies,
          "prune default: the floors (" + floors_text(f) + ") = the formulas (" + std::to_string(w.bodies) + ", "
                  + std::to_string(w.records) + ", " + std::to_string(w.sides) + ")");
    const std::string digest = h[a].lane_digest();
    const auto blhash = keys_of(kv, pb::lane_keys::blhash_prefix(0));
    const auto bleaf = keys_of(kv, pb::lane_keys::bleaf_prefix(0));
    const auto ar = keys_of(kv, pb::store_keys::ar_prefix(0));
    const std::string bmmr = kv.data.at(pb::lane_keys::bmmr(0));
    const std::size_t records0 = count_keys(kv, pb::store_keys::pcarrier_prefix(0));
    const std::uint64_t commits = kv.commits;
    const pb::Hash32 at_fb = *h[a].store().best_at(w.bodies), below_fb = *h[a].store().best_at(w.bodies - 1);
    const pb::Hash32 at_first = *h[a].store().best_at(w.records), below_first = *h[a].store().best_at(w.records - 1);
    const pb::PathbNode::PruneReport r = h[a].prune(h.now);
    check(r.written && kv.commits == commits + 1 && r.root == w.bodies && r.first == w.records,
          "prune default: one store batch; root " + std::to_string(r.root) + ", first record " + std::to_string(r.first));
    check(h[a].tree().genesis().pos == w.bodies && h[a].tree().genesis().id == at_fb && h[a].tree().find(below_fb) == nullptr
                  && h[a].bodies().get(at_fb) != nullptr && h[a].bodies().get(below_fb) == nullptr,
          "prune default: tree nodes and bodies from the body floor, none below");
    check(h[a].store().first_record_pos() == w.records && h[a].store().best_at(w.records) == at_first
                  && !h[a].store().best_at(w.records - 1),
          "prune default: the store's records from the record floor");
    const pb::StoreHead hd = *pb::decode_phead(kv.data.at(pb::store_keys::phead(0)));
    check(!record_at(kv, w.records - 1) && header_record(record_at(kv, w.records)) && header_record(record_at(kv, w.bodies - 1))
                  && full_record(record_at(kv, w.bodies)) && count_keys(kv, pb::store_keys::pcarrier_prefix(0)) == records0 - w.records
                  && hd.first_pos == w.records && hd.root_pos == w.bodies && hd.base_pos >= w.bodies,
          "prune default: K_PCARRIER below the record floor deleted, header records up to the body floor, the root's record "
          "whole; K_PHEAD first_pos " + std::to_string(hd.first_pos) + ", root_pos " + std::to_string(hd.root_pos));
    check(keys_of(kv, pb::lane_keys::blhash_prefix(0)) == blhash && keys_of(kv, pb::lane_keys::bleaf_prefix(0)) == bleaf
                  && keys_of(kv, pb::store_keys::ar_prefix(0)) == ar && kv.data.at(pb::lane_keys::bmmr(0)) == bmmr,
          "prune default: K_BLHASH, K_BLEAF, K_AR and K_BMMR unchanged");
    {
        // K_BWORK: the heights of positions 1 .. root - 1, each with the work A counted there below the floor
        std::set<std::uint64_t> want;
        for (std::uint64_t x = 1; x < w.bodies; ++x) want.insert(h_pos(x));
        bool keyed = count_keys(kv, pb::store_keys::bwork_prefix(0)) == want.size();
        for (const std::uint64_t ht : want) {
            const auto it = kv.data.find(pb::store_keys::bwork(0, ht));
            const auto e = it == kv.data.end() ? std::nullopt : pb::decode_bwork(it->second);
            keyed = keyed && e && e->first == ht && (e->second.lo != 0 || e->second.hi != 0);
        }
        check(keyed, "prune default: K_BWORK in the prune batch, one record per height below the floor ("
                             + std::to_string(count_keys(kv, pb::store_keys::bwork_prefix(0))) + " of "
                             + std::to_string(want.size()) + ")");
    }
    check(h[a].lane_digest() == digest, "prune default: the lane digest at the tip unchanged");
    const pb::PathbNode::PruneReport again = h[a].prune(h.now);
    check(!again.written && again.root == r.root && again.first == r.first && kv.commits == commits + 1,
          "prune default: a second prune at the same tip changes nothing");
    // serving: what it keeps, not below
    const auto carrier = [&](const pb::Hash32& id) {
        pb::GetCarrier q;
        q.chain_id = 0;
        q.ids = {id};
        q.want_bodies = true;
        return h[a].serve_getcarrier(9, *pb::encode_fc_getcarrier(q, pb::kRuledLaneParams), h.now).frames.size();
    };
    const auto page = [&](const pb::Hash32& stop, std::uint16_t max) {
        pb::HeadersReply rep;
        const auto fr = h[a].serve_getheaders(9, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, stop, max}), h.now).frames;
        if (fr.size() != 1 || !pb::decode_fc_headers(fr[0], 0, 1u << 22, pb::kRuledLaneParams, rep).ok()) rep.headers.clear();
        return rep;
    };
    const auto buckets_served = [&](const pb::Hash32& at) {
        const pb::GetBuckets q{0, at, kLaneB0, kLaneB0 + 1};
        const auto fr = h[a].serve_getbuckets(9, *pb::encode_getbuckets(q), h.now).frames;
        return !fr.empty() && fr[0] != pb::encode_buckets_not_served(0, at);
    };
    const pb::HeadersReply p1 = page(*h[a].store().best_at(w.bodies + 10), 64);
    const pb::HeadersReply p2 = page(*h[a].store().best_at(w.records + 3), 4);
    const pb::HeadersReply p3 = page(below_first, 4);
    check(carrier(at_fb) == 1 && carrier(below_fb) == 0,
          "prune default: FC_GETCARRIER serves the body at the floor, none below it");
    check(p1.first_pos < w.bodies && p1.first_pos + p1.headers.size() == w.bodies + 11 && p2.headers.size() == 4
                  && p2.first_pos == w.records
                  && pb::receipt_id(p2.headers[0].own) == at_first && p3.headers.empty(),
          "prune default: FC_GETHEADERS pages across the body floor and down to the record floor; nothing below it ("
                  + std::to_string(p1.headers.size()) + " from " + std::to_string(p1.first_pos) + ", "
                  + std::to_string(p2.headers.size()) + " from " + std::to_string(p2.first_pos) + ", "
                  + std::to_string(p3.headers.size()) + ")");
    check(buckets_served(*h[a].store().best_at(w.bodies + 1)) && !buckets_served(at_fb) && !buckets_served(below_fb),
          "prune default: FC_GETBUCKETS at a carrier above the root served; at the root and below: not served");
    // A's bound work: the pruned node keeps what it counted (from position 1); a restart loads the part below the root
    const auto pa = pb::PathbNodeTestAccess::own_profile(h[a]);
    const std::uint64_t h_root = h_pos(w.bodies);
    check(pa && pa->lowest() == h_pos(1) && pa->highest() == h_pos(kPruneL),
          "prune default: A's bound work still counts positions 1 .. L after the prune");
    // a restart
    pb::StoreFault fault = pb::StoreFault::None;
    const std::size_t b = reload_node(h, kv, kPruneJ, &fault);
    check(b != SIZE_MAX && h[b].lane_digest() == h[a].lane_digest() && h[b].tree().genesis().pos == w.bodies
                  && h[b].store().first_record_pos() == w.records && root_window(h[b]) == root_window(h[a])
                  && root_window(h[a]).size() == pb::kRuledLaneParams.retarget_span,
          "prune default: the pruned store reloads (root, first record, the root's retarget window) to the same lane digest");
    if (b == SIZE_MAX) return;
    const auto pb_ = pb::PathbNodeTestAccess::own_profile(h[b]);
    check(pb_ && pa && pb_->lowest() == h_pos(1) && pb_->highest() == h_pos(kPruneL) && pb_->at == pa->at
                  && pb_->lowest() < std::optional<std::uint64_t>(h_root),
          "prune default: after the restart A's bound work counts positions 1 .. L, equal");
    // rule (4): a candidate whose bound part starts below the root: A's work from a height below the root, w + 2 more
    // there and w + 1 less at the root's next height, w = the work below the floor at the root's height (K_BWORK).
    // From that height it replaces A; counted from the root's height (A's profile without the work below the floor)
    // it would not.
    if (!pa || !pb_ || pa->at.empty()) return;
    pb::U128 below_root{};
    if (const auto it = kv.data.find(pb::store_keys::bwork(0, h_root)); it != kv.data.end())
        if (const auto e = pb::decode_bwork(it->second)) below_root = e->second;
    const pb::U128 less = ::c2pool::xmr::native::u128_add(below_root, pb::U128{1, 0});
    const pb::U128 more = ::c2pool::xmr::native::u128_add(less, pb::U128{1, 0});
    pb::BoundWork cand;
    const std::uint64_t h_c = h_pos(w.bodies / 2);
    for (auto it = pa->at.lower_bound(h_c); it != pa->at.end(); ++it) cand.at[it->first] = it->second;
    const bool shaped = cand.at.count(h_root + 1) != 0 && !::c2pool::xmr::native::u128_less(cand.at[h_root + 1], less);
    cand.at[h_c] = ::c2pool::xmr::native::u128_add(cand.at[h_c], more);
    if (shaped) cand.at[h_root + 1] = pb::bound_work_minus(cand.at[h_root + 1], less);
    pb::Hash32 c_tip{};
    c_tip.fill(0xff);
    const bool before = pb::candidate_replaces(cand, c_tip, *pa, h[a].store().best_tip());
    const bool after = pb::candidate_replaces(cand, c_tip, *pb_, h[b].store().best_tip());
    check(h_c < h_root && shaped && before && after,
          std::string("prune default: rule (4), a candidate bound from below the root (") + std::to_string(below_root.lo)
                  + " below the floor at the root's height): replaces before the restart " + (before ? "yes" : "no")
                  + ", after " + (after ? "yes" : "no"));
}

// ---------------------------------------------------------------------------
// prune_flags: --pathb-body-keep 10 (below the node's own horizon: raised to min(s(L), L - P-04 + 1)), --pathb-
// header-keep 5,000 (records from L - 4,999), --pathb-side-keep 100 (raised to the view horizon); restart.
void prune_flags() {
    PruneChain& c = prune_chain();
    Harness h(c.net);
    pb::PathbNodeConfig cfg = h.config(kat_table(c.net), true, kPruneJ);
    cfg.body_keep = 10;
    cfg.header_keep = 5000;
    cfg.side_keep = 100;
    const std::size_t a = load_node(h, c.sn->kv, cfg);
    MemoryKv& kv = *h.kvs.back();
    const PruneFloorsWant w = want_floors(kPruneL, kPruneJ, 10, 5000, 100);
    const pb::PathbNode::PruneReport r = h[a].prune(h.now);
    check(r.floors.bodies == w.bodies && r.floors.records == w.records && r.floors.sides == w.sides
                  && w.bodies < kPruneL + 1 - 10 && w.records == kPruneL + 1 - 5000 && w.sides < kPruneL + 1 - 100,
          "prune flags: the floors (" + floors_text(r.floors) + "): bodies and sides raised to the own horizon, records at "
          "the flag");
    check(r.written && r.root == w.bodies && r.first == w.records && !record_at(kv, w.records - 1)
                  && header_record(record_at(kv, w.records)) && full_record(record_at(kv, w.bodies)),
          "prune flags: the store from the record floor " + std::to_string(w.records) + ", whole records from "
                  + std::to_string(w.bodies));
    pb::StoreFault fault = pb::StoreFault::None;
    const std::size_t b = reload_node(h, kv, kPruneJ, &fault);
    check(b != SIZE_MAX && h[b].lane_digest() == h[a].lane_digest() && root_window(h[b]) == root_window(h[a]),
          "prune flags: the restart reloads to the same lane digest");
}

// ---------------------------------------------------------------------------
// prune_side: the side branches of the tree: forking at the side floor (= the body floor) kept with their bodies;
// forking one below dropped; one above kept.
void prune_side() {
    PruneChain& c = prune_chain();
    Harness h(c.net);
    h.nodes.push_back(node_from(h, c.sn->n, kPruneJ, 0));
    pb::PathbNode& a = h[0];
    check(a.tree().find(c.side_at) != nullptr && a.tree().find(c.side_below) != nullptr && a.tree().find(c.side_above) != nullptr,
          "prune side: the three side carriers held");
    const pb::PathbNode::PruneReport r = a.prune(h.now);
    check(r.root == c.fb && r.floors.sides == c.fb, "prune side: root and side floor " + std::to_string(c.fb));
    check(a.tree().find(c.side_at) != nullptr && a.bodies().get(c.side_at) != nullptr && a.tree().find(c.side_above) != nullptr
                  && a.bodies().get(c.side_above) != nullptr,
          "prune side: the side branches forking at and above the floor kept with their bodies");
    check(a.tree().find(c.side_below) == nullptr && a.bodies().get(c.side_below) == nullptr,
          "prune side: the side branch forking below the floor dropped with its body");
}

// ---------------------------------------------------------------------------
// prune_hold: an open join hold keeps its floors (taken at its first request) while the best tip moves on; once the
// hold ends the floors of the current tip apply.
void prune_hold() {
    PruneChain& c = prune_chain();
    Harness h(c.net);
    const std::size_t a = load_node(h, c.sn->kv, h.config(kat_table(c.net), true, kPruneJ));
    const pb::JoinServeFloors f0 = h[a].serve_floors_now();
    (void)h[a].serve_getheaders(9, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, pb::Hash32{}, 16}), h.now);
    check(h[a].join_holding(9) && f0.bodies == c.fb, "prune hold: an attempt's first request opens the hold at L 7,000");
    h.mon_tip = h_pos(kPruneL) + 1;
    for (int i = 0; i < 48; ++i) {
        if (i % 4 == 0) h.tick_monero(1);
        h.mine(a, static_cast<std::size_t>(i % 3), 900 + i);
    }
    h.q.clear();
    const std::uint64_t L1 = h[a].store().tip_pos();
    const pb::JoinServeFloors f1 = h[a].serve_floors_now();
    check(L1 == kPruneL + 48 && f1.bodies > f0.bodies, "prune hold: the tip moved to " + std::to_string(L1)
                                                           + "; the floor at it " + std::to_string(f1.bodies));
    const pb::PathbNode::PruneReport r = h[a].prune(h.now + 5);
    check(r.root == f0.bodies && h[a].tree().genesis().pos == f0.bodies,
          "prune hold: the open hold's floor kept (root " + std::to_string(r.root) + ", the hold's " + std::to_string(f0.bodies) + ")");
    const pb::PathbNode::PruneReport r2 = h[a].prune(h.now + 40);
    check(!h[a].join_holding(9) && r2.root == f1.bodies,
          "prune hold: the hold ended; the current floor " + std::to_string(r2.root));
}

// ---------------------------------------------------------------------------
// below: a full node holding its chain from position 0 offers no candidate on a HELLO;
// once it pruned, a heavier branch forking below its first retained record (fork 200) is a candidate without the
// header-work condition, the attempt completes and rule (4) replaces A.
void below() {
    JoinNet net(900);
    const std::uint64_t L = 6000, f = 200;
    ChainShape sb;
    sb.nonce0 = 7300000;
    KatNode a(net, kPruneJ);
    grow(a, f);
    KatNode b(a);
    grow(a, L - f);
    grow(b, L + 200 - f, sb);
    Harness h(net);
    const std::size_t fa = h.nodes.size();
    h.nodes.push_back(node_from(h, a, kPruneJ, fa));
    const std::size_t fbn = h.nodes.size();
    h.nodes.push_back(node_from(h, b, kPruneJ, fbn));
    KatTransport tr(h, fa);
    h[fa].set_join_transport(&tr);
    const pb::HelloCheck hc = h.hello(fa, fbn);
    check(hc.verdict == pb::HelloVerdict::Accept && h[fa].joiner().queue().size() == 0,
          "below: a full node holding its chain from position 0 offers no candidate on a HELLO");
    const pb::PathbNode::PruneReport r = h[fa].prune(h.now);
    check(r.root > f && h[fa].tree().genesis().pos == r.root,
          "below: the full node pruned (root " + std::to_string(r.root) + "); the fork " + std::to_string(f) + " lies below it");
    (void)h.hello(fa, fbn);
    check(h[fa].joiner().queue().size() == 1, "below: B's tip, forking below what A holds, is a candidate");
    h.mon_tip = h_pos(L + 200) + 1;
    const pb::JoinStep st = h[fa].run_join();
    check(st.report && st.report->end == pb::AttemptEnd::Completed && st.sw.replaced && st.switched
                  && h[fa].tree().best().id == b.store.best_tip(),
          "below: the attempt completes and rule (4) replaces A" + (st.report ? std::string(": ") + rep_desc(*st.report) : std::string()));
}
// ---------------------------------------------------------------------------
// The owner's event queue: one posted event per peer in flight; a reader waits while the owner is held.
void relayq() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay b = kat_relay(h, w, table0(net), false);  // the peer's node: its HELLO bytes
    FakeLinks rl;
    rl.wire = &w;
    rl.self = w.links.size();
    w.links.push_back(&rl);
    pb::PathbRelayOptions o;
    o.threads = true;
    o.keepalive_ms = 0;
    o.discovery = false;
    pb::RelayClock clock;
    clock.mono_ms = [&h] { return h.now * 1000; };
    clock.wall_s = [&h] { return h.now; };
    pb::PathbRelayNode r(o, rl, clock);
    const std::size_t idx = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true), r.bind_io(h.io(idx))));
    r.attach(*h.nodes.back());
    std::string why;
    if (!r.start(why)) throw std::runtime_error(why);
    rl.live.insert(1);
    rl.event(1, true);
    const std::vector<std::uint8_t> hello =
            pb::encode_pathb_hello(h[b.node].our_hello(0x7a7a7a7aull, 0)).value_or(std::vector<std::uint8_t>{});
    rl.frame(1, hello);
    const bool up = wait_for([&] { return r.hello_ok(1); }, 3000);
    constexpr int kFrames = 200;
    const std::vector<std::uint8_t> ask =
            pb::encode_fc_getheaders(pb::GetHeaders{0, h[idx].tree().genesis().id, pb::Hash32{}, 1});
    std::atomic<bool> held{false};
    std::thread holder([&] {
        r.with_node([&](pb::PathbNode&) {
            held = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            return 0;
        });
    });
    (void)wait_for([&] { return held.load(); }, 1000);
    const std::uint64_t hwm0 = r.stats().owner_queue_hwm.load();
    std::thread reader([&] {
        for (int i = 0; i < kFrames; ++i) rl.frame(1, ask);
    });
    holder.join();
    reader.join();
    const std::uint64_t hwm = r.stats().owner_queue_hwm.load();
    const std::uint64_t waits = r.stats().owner_waits.load();
    const bool served = wait_for([&] {
        const std::lock_guard<std::mutex> lk(w.qm);
        std::size_t n = 0;
        for (const FakeWire::Msg& m : w.q)
            if (m.from == rl.self && !m.f.empty() && m.f[0] == pb::kOpFcHeaders) ++n;
        return n == static_cast<std::size_t>(kFrames);
    }, 5000);
    r.stop();
    check(up && served && hwm <= 2 && waits >= 1,
          "relayq: " + std::to_string(kFrames) + " FC_GETHEADERS of one peer while the owner is held: the owner's queue "
          "high-water mark " + std::to_string(hwm) + " (before them " + std::to_string(hwm0) + "), the reader waited " +
          std::to_string(waits) + " times, every request answered");
}

// The relay's re-run index: a DEFER on a carried body is indexed and leaves the index at the next placement; a strike
// on a peer whose link is gone keeps no per-peer entry.
void relayindex() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 400);
    b.relay->test_parked(1, pb::Missing::Bodies, seq32(0x51), seq32(0x52));
    const std::size_t indexed = b.relay->parked_index_size();
    ok = ok && mine_on(h, w, a.node, 2, 401);
    const std::size_t left = b.relay->parked_index_size();
    check(ok && indexed == 1 && left == 0 && h[b.node].tree().best().id == h[a.node].tree().best().id,
          "relayindex: a DEFER on a carried body indexed (" + std::to_string(indexed) + ") and gone from the index at "
          "the next placement (" + std::to_string(left) + " left)");
    const std::size_t e0 = b.relay->strike_entries();
    b.relay->test_strike(1);
    const std::size_t e1 = b.relay->strike_entries();
    w.links[1]->disconnect(1);
    w.run();
    const std::size_t e2 = b.relay->strike_entries();
    b.relay->test_strike(1);
    const std::size_t e3 = b.relay->strike_entries();
    check(e1 == e0 + 1 && e2 == e0 && e3 == e0,
          "relayindex: a strike on a live peer keeps an entry (" + std::to_string(e1) + "), none after its link is gone (" +
                  std::to_string(e3) + ")");
}

// ---------------------------------------------------------------------------
// The per-link send queue bound: at least two FC_HEADERS frames with their u32 length prefixes (P-14; the re-offer
// pages within the bound less one); a smaller bound (0 among them) is refused at start.
void relaysq() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    const std::size_t hf = static_cast<std::size_t>(h[a.node].frame_bytes_headers());
    const auto starts = [&](std::size_t bytes, std::string& why) {
        try {
            KatRelay k = kat_relay(h, w, table0(net), true, false, [bytes](pb::PathbRelayOptions& o) { o.send_queue_bytes = bytes; });
            k.relay->stop();
            w.relays.pop_back();
            return true;
        } catch (const std::runtime_error& e) {
            why = e.what();
            return false;
        }
    };
    std::string w0, w1, w2, w3;
    const std::size_t two = 2 * (hf + 4);
    const bool s0 = starts(0, w0), s1 = starts(hf, w1), s2 = starts(two - 1, w2), s3 = starts(two, w3);
    check(hf > 0 && !s0 && !s1 && !s2 && s3 && w0.find("send queue") != std::string::npos,
          "relaysq: a send queue bound below two FC_HEADERS frames with their prefixes (2 x " + std::to_string(hf + 4) +
                  " B) refused at start (0, one frame, two frames - 1: '" + w2 + "'); two frames accepted");
}

// ---------------------------------------------------------------------------
// P-15, the per-peer valid-object budget: the default capacity is P-09 (the pending cap). With a capacity of 4 at B:
// a first-seen receipt counts one, a duplicate none; once the budget is spent a frame is DROPPED (counted): no strike,
// no ban, the link kept; the bucket refills at (1 + R_MAX) / T objects/s.
void relayp15() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.peer_valid_capacity = 4; });
    KatRelay d = kat_relay(h, w, table0(net), false);
    const double cap = static_cast<double>(pb::relay_horizons(pb::kRuledLaneParams).pending_cap);
    check(d.relay->peer_valid_left(7) == cap && cap == 18432.0,
          "relayp15: the default capacity is P-09 (" + std::to_string(d.relay->peer_valid_left(7)) + ")");
    w.connect(0, 1);
    w.run();
    // six receipts B lacks: shares of jobs on A's tip after A moved on (A's carrier not delivered to B)
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 6; ++k)
        if (const std::optional<pb::PathbJob> j = h.job(a.node, k + 2, 610 + k)) jobs.push_back(*j);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    bool ok = jobs.size() == 6 && mine_on(h, w, a.node, 1, 620);
    for (std::uint32_t k = 0; ok && k < 6; ++k)
        ok = h[a.node].on_own_share(jobs[k], 610 + k, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    std::vector<pb::ReceiptBodyV3> rs;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) rs.push_back(r->body);
    ok = ok && rs.size() == 6 && h[b.node].pending().size() == 0;
    h.now += 1000;  // B's bucket full again
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = 1;  // A at B
    const auto send = [&](const pb::ReceiptBodyV3& r) {
        const std::vector<pb::ReceiptBodyV3> one{r};
        rb.receive(pa, *pb::encode_fb_receipts(0, one, pb::kRuledLaneParams));
        w.run();
    };
    const std::uint64_t d0 = rb.stats().p15_drops.load();
    const double full = rb.peer_valid_left(pa);
    send(rs[0]);
    const double one = rb.peer_valid_left(pa);
    for (int i = 0; i < 3; ++i) send(rs[0]);
    const double dup = rb.peer_valid_left(pa);
    check(ok && full == 4.0 && one == 3.0 && dup == 3.0 && rb.stats().p15_drops.load() == d0,
          "relayp15: capacity 4; a first-seen receipt counts one (" + std::to_string(one) + " left), three duplicates "
          "none (" + std::to_string(dup) + " left)");
    for (std::size_t k = 1; k < 6; ++k) send(rs[k]);
    const std::uint64_t drops = rb.stats().p15_drops.load() - d0;
    check(drops == 2 && h[b.node].pending().size() == 4 && !h[b.node].pending().holds(pb::receipt_id(rs[4]))
                  && !h[b.node].pending().holds(pb::receipt_id(rs[5])) && rb.strikes_of(pa) == 0 && rb.stats().bans == 0
                  && rb.hello_ok(pa),
          "relayp15: once the budget is spent the next two frames are dropped (" + std::to_string(drops) + "): no strike, "
          "no ban, the link kept; " + std::to_string(h[b.node].pending().size()) + " receipts held");
    {
        // dropped at its arrival: never in the verify queue
        const std::vector<pb::ReceiptBodyV3> one{rs[5]};
        rb.receive(pa, *pb::encode_fb_receipts(0, one, pb::kRuledLaneParams));
        const std::size_t vq = rb.verify_queue_size();
        w.run();
        check(rb.stats().p15_drops.load() - d0 == 3 && vq == 0,
              "relayp15: a frame above the budget is dropped at its arrival (verify queue " + std::to_string(vq) + ")");
    }
    h.now += 1;  // (1 + R_MAX) / T = 1.7 objects in a second
    send(rs[4]);
    check(rb.stats().p15_drops.load() - d0 == 3 && h[b.node].pending().holds(pb::receipt_id(rs[4])),
          "relayp15: a second later the bucket refilled: the next frame admitted (" +
                  std::to_string(rb.peer_valid_left(pa)) + " left)");
    w.links[1]->disconnect(1);
    w.run();
    check(rb.valid_entries() == 0, "relayp15: no bucket kept for a peer whose link is gone");
}

// ---------------------------------------------------------------------------
// relayp15rx: a receipts frame of three bodies whose second body's RandomX fails. The relay takes a receipts frame as
// one job per body: the first and the third are admitted and counted in P-15 at once (their first placement); the
// second is parked and run again: admitted and counted then. Three first-seen receipts, three counted, none twice.
void relayp15rx() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.peer_valid_capacity = 10; });
    w.connect(0, 1);
    w.run();
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 3; ++k)
        if (const std::optional<pb::PathbJob> j = h.job(a.node, k + 2, 710 + k)) jobs.push_back(*j);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    bool ok = jobs.size() == 3 && mine_on(h, w, a.node, 1, 720);
    for (std::uint32_t k = 0; ok && k < 3; ++k)
        ok = h[a.node].on_own_share(jobs[k], 710 + k, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    std::vector<pb::ReceiptBodyV3> rs;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) rs.push_back(r->body);
    ok = ok && rs.size() == 3 && h[b.node].pending().size() == 0;
    if (!ok) {
        check(false, "relayp15rx: setup");
        return;
    }
    h.now += 1000;  // B's bucket full
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = 1;  // A at B
    const double full = rb.peer_valid_left(pa);
    h.throw_pow.insert(pb::receipt_id(rs[1]));
    rb.receive(pa, *pb::encode_fb_receipts(0, rs, pb::kRuledLaneParams));
    w.run();
    const double after_first = rb.peer_valid_left(pa);
    const bool r0 = h[b.node].pending().holds(pb::receipt_id(rs[0])), r1 = h[b.node].pending().holds(pb::receipt_id(rs[1])),
               r2 = h[b.node].pending().holds(pb::receipt_id(rs[2]));
    const std::uint64_t fails = rb.stats().rx_failures.load();
    const double bucket_t0 = h.now;
    // the re-run (no refill: the clock of the bucket is the harness's, moved below by less than a token)
    for (int i = 0; i < 6 && h[b.node].pending().size() < 3; ++i) {
        h.now += 1;
        rb.tick();
        w.run();
    }
    const double after_rerun = rb.peer_valid_left(pa);
    // the bucket refills at (1 + R_MAX) / T = 1.7 per second, capped at the capacity
    const double refill = std::min(10.0 - after_first, (h.now - bucket_t0) * 1.7);
    std::printf("  relayp15rx: full=%.2f after_first=%.2f after_rerun=%.2f refill=%.2f held=%zu rx_failures=%llu\n", full,
                after_first, after_rerun, refill, h[b.node].pending().size(), static_cast<unsigned long long>(fails));
    check(fails >= 1 && r0 && !r1 && r2 && full - after_first == 2.0,
          "relayp15rx: RandomX failed on the second body; the first and the third admitted and counted at once (" +
                  std::to_string(full - after_first) + ")");
    check(h[b.node].pending().size() == 3 && std::abs(after_first + refill - 1.0 - after_rerun) < 1e-6
                  && rb.strikes_of(pa) == 0 && rb.stats().bans == 0,
          "relayp15rx: the re-run admits the second and counts it once; no strike, no ban");
}

// ---------------------------------------------------------------------------
// ownbound: the kept own shares are bounded by the issued jobs' lifetime. (1) Three shares kept (RandomX failing); the
// second's job goes stale; RandomX still fails on the first: the stale second leaves at once (not only from the front).
// (2) PathbJobSource::clear() releases the issued jobs: a share on one of them is stale.
void ownbound() {
    std::set<std::uint32_t> live_tids;
    pb::OwnShareRunner runner([](const pb::OwnShare&) -> pb::NodeEventResult { throw pb::RandomxFailure("kat: RandomX down"); },
                              [&](const pb::OwnShare& s) { return live_tids.count(s.template_id) != 0; });
    for (std::uint32_t t = 1; t <= 3; ++t) {
        live_tids.insert(t);
        (void)runner.submit(pb::OwnShare{t, 1, pb::PathbJob{}, t, pb::Hash32{}});
    }
    const std::size_t k0 = runner.kept();
    live_tids.erase(2);
    (void)runner.run_kept();
    check(k0 == 3 && runner.kept() == 2 && runner.stats().stale == 1,
          "ownbound: a kept share whose job went stale leaves at the next run though RandomX still fails before it (kept " +
                  std::to_string(runner.kept()) + ", stale " + std::to_string(runner.stats().stale) + ")");
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 50 + i);
    }
    pb::PathbJobSource js([&](const pb::PathbTemplate& t, const pb::PathbSession& ss) { return h[a].make_job(t, ss); });
    const pb::PathbTemplate t = h[a].make_template(h.now);
    const std::uint32_t tid = js.set_template(t, pb::JobNetwork{});
    js.bind(7, h.session(1, 7));
    ::v37::xmr::stratum::TemplateJob out;
    const bool got = t.status == pb::TemplateStatus::Ok && js.get_job(7, out);
    const bool issued = js.issued(tid, 7).has_value();
    js.clear();
    check(got && issued && !js.issued(tid, 7).has_value() && !js.has_template(),
          "ownbound: clear() withdraws the template and its issued jobs for own shares (a share on one is stale)");
}

// ---------------------------------------------------------------------------
// deferfound: a Monero block found on a job issued before a DEFER (clear()) is submitted: the job stays for the
// network-block path (network_job, rebuild_blob, the publish arm's candidate) while its own shares are stale; it
// leaves with its template (kKeptTemplates later templates).
void deferfound() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 60 + i);
    }
    pb::PathbJobSource js([&](const pb::PathbTemplate& t, const pb::PathbSession& ss) { return h[a].make_job(t, ss); });
    const pb::PathbTemplate t = h[a].make_template(h.now);
    pb::JobNetwork net_vals;
    net_vals.known = true;
    net_vals.difficulty_lo = 1000;
    const std::uint32_t tid = js.set_template(t, net_vals);
    js.bind(7, h.session(1, 7));
    ::v37::xmr::stratum::TemplateJob out;
    const bool got = t.status == pb::TemplateStatus::Ok && js.get_job(7, out);
    js.clear();  // a DEFER
    ::v37::xmr::stratum::TemplateJob rebuilt;
    check(got && !js.has_template() && !js.issued(tid, 7).has_value() && js.network_job(tid, 7).has_value() &&
                  js.rebuild_blob(tid, 7, rebuilt) && rebuilt.blob == out.blob,
          "deferfound: after a DEFER the job stays for a found block (network_job, rebuild_blob) and is stale for own "
          "shares");
    ::c2pool::xmr::node::MockMonerodTransport mon;
    mon.set_method_body("submit_block", R"({"id":"0","jsonrpc":"2.0","result":{"status":"OK"}})");
    ::c2pool::v37n::xmr::submit::LiveBlockSubmitter sub(mon);
    sub.enable_network_submit(true);
    ::c2pool::v37n::xmr::submit::LiveSubmitShareSink sink(
            sub, [&js](std::uint32_t ti, std::uint32_t en, ::c2pool::v37n::xmr::submit::BlockCandidate& c) {
                return js.candidate(ti, en, c);
            });
    sink.submit_network_block(tid, 5, 7);
    bool posted = false;
    for (const std::string& b : mon.posted_bodies()) posted = posted || b.find("submit_block") != std::string::npos;
    check(sub.calls() == 1 && sink.stale_lookups() == 0 && sink.found() == 1 && posted,
          "deferfound: a Monero block found on the pre-DEFER job is submitted (calls " + std::to_string(sub.calls()) +
                  ", stale " + std::to_string(sink.stale_lookups()) + ", found " + std::to_string(sink.found()) + ")");
    for (std::size_t k = 0; k < pb::PathbJobSource::kKeptTemplates; ++k) (void)js.set_template(t, net_vals);
    check(!js.network_job(tid, 7).has_value(), "deferfound: the job leaves with its template (kKeptTemplates later)");
}

// ---------------------------------------------------------------------------
// alarmbound: the node's alarm sink does not grow with its life: 1,000 alarms (600 R12 node-internal, 400 R9 claim)
// are 1,000 counted, 600 of them R12 node-internal read in O(1), the last one kept; no list of entries is held.
template <class S>
static std::uint64_t sink_count_of(const S& s, pb::RowId row, pb::Missing cause) {
    if constexpr (requires { s.count_of(row, cause); }) return s.count_of(row, cause);
    else return UINT64_MAX;
}
template <class S>
static bool sink_holds_list(const S& s) {
    if constexpr (requires { s.entries.size(); }) return true;
    else return false;
}
void alarmbound() {
    pb::AlarmSink sink;
    for (int i = 0; i < 1000; ++i)
        sink.raise(i < 600 ? pb::RowId::R12 : pb::RowId::R9, pb::Basis::Computed, seq32(static_cast<std::uint8_t>(i)),
                   i < 600 ? pb::Missing::NodeInternal : pb::Missing::ClaimAlarm);
    check(sink.count() == 1000 && sink_count_of(sink, pb::RowId::R12, pb::Missing::NodeInternal) == 600
                  && sink_count_of(sink, pb::RowId::R9, pb::Missing::ClaimAlarm) == 400 && !sink_holds_list(sink),
          "alarmbound: 1,000 alarms counted by (row, cause), R12 node-internal 600 read in O(1); no list of entries held");
}

// ---------------------------------------------------------------------------
// A-1: the events of a peer that run after its link went down (one in flight, one its reader posted while blocked
// behind it) are skipped: the node opens nothing for the gone peer (no join hold from its FC_GETHEADERS).
void relaystale() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay b = kat_relay(h, w, table0(net), false);
    FakeLinks rl;
    rl.wire = &w;
    rl.self = w.links.size();
    w.links.push_back(&rl);
    pb::PathbRelayOptions o;
    o.threads = true;
    o.keepalive_ms = 0;
    o.discovery = false;
    pb::RelayClock clock;
    clock.mono_ms = [&h] { return h.now * 1000; };
    clock.wall_s = [&h] { return h.now; };
    pb::PathbRelayNode r(o, rl, clock);
    const std::size_t idx = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true), r.bind_io(h.io(idx))));
    r.attach(*h.nodes.back());
    std::string why;
    if (!r.start(why)) throw std::runtime_error(why);
    rl.live.insert(1);
    rl.event(1, true);
    rl.frame(1, pb::encode_pathb_hello(h[b.node].our_hello(0x7b7b7b7bull, 0)).value_or(std::vector<std::uint8_t>{}));
    const bool up = wait_for([&] { return r.hello_ok(1); }, 3000);
    const std::vector<std::uint8_t> ask = pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, pb::Hash32{}, 1});
    const std::uint64_t w0 = r.stats().owner_waits.load(), s0 = r.stats().stale_events.load();
    std::atomic<bool> held{false};
    std::thread holder([&] {
        r.with_node([&](pb::PathbNode&) {
            held = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(600));
            return 0;
        });
    });
    (void)wait_for([&] { return held.load(); }, 1000);
    std::thread reader([&] {
        for (int i = 0; i < 4; ++i) rl.frame(1, ask);
    });
    const bool blocked = wait_for([&] { return r.stats().owner_waits.load() > w0; }, 1000);
    std::thread downer([&] {
        rl.live.erase(1);
        rl.event(1, false);
    });
    holder.join();
    reader.join();
    downer.join();
    (void)wait_for([&] { return r.stats().stale_events.load() >= s0 + 2; }, 3000);
    const std::uint64_t stale = r.stats().stale_events.load() - s0;
    const bool holding = r.with_node([](pb::PathbNode& n) { return n.join_holding(1); });
    r.stop();
    check(up && blocked && stale >= 1 && !holding,
          "relaystale: the events of a peer run after its link went down are skipped (" + std::to_string(stale) +
                  "); no join hold for the gone peer");
}

// ---------------------------------------------------------------------------
// A-2: on_monero_tip as the wiring calls it: from the follower's thread (no lock held), and from a hook that runs under
// the node lock (the lock is not re-entrant: the call runs after the holder lets go). Each returns; the parked frames
// indexed on a Monero input are run again. A call that does not return ends the KAT.
void relaytip() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay b = kat_relay(h, w, table0(net), false);
    FakeLinks rl;
    rl.wire = &w;
    rl.self = w.links.size();
    w.links.push_back(&rl);
    pb::PathbRelayOptions o;
    o.threads = true;
    o.keepalive_ms = 0;
    o.discovery = false;
    pb::RelayClock clock;
    clock.mono_ms = [&h] { return h.now * 1000; };
    clock.wall_s = [&h] { return h.now; };
    pb::PathbRelayNode r(o, rl, clock);
    const std::size_t idx = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true), r.bind_io(h.io(idx))));
    r.attach(*h.nodes.back());
    std::string why;
    if (!r.start(why)) throw std::runtime_error(why);
    rl.live.insert(1);
    rl.event(1, true);
    rl.frame(1, pb::encode_pathb_hello(h[b.node].our_hello(0x7c7c7c7cull, 0)).value_or(std::vector<std::uint8_t>{}));
    const bool up = wait_for([&] { return r.hello_ok(1); }, 3000);
    const auto watchdog = [&](std::atomic<bool>& done, const char* what) {
        if (wait_for([&] { return done.load(); }, 3000)) return;
        std::printf("  FAIL relaytip: on_monero_tip %s did not return\n", what);
        std::fflush(stdout);
        std::_Exit(1);
    };
    r.test_parked(1, pb::Missing::Seed, seq32(0x61), seq32(0x62));
    const std::size_t i1 = r.parked_index_size();
    std::atomic<bool> d1{false};
    std::thread follower([&] {
        r.on_monero_tip();
        d1 = true;
    });
    watchdog(d1, "from the follower's thread");
    follower.join();
    const std::size_t a1 = r.parked_index_size();
    r.test_parked(1, pb::Missing::MoneroBlock, seq32(0x63), seq32(0x64));
    const std::size_t i2 = r.parked_index_size();
    std::atomic<bool> d2{false};
    std::thread hook([&] {
        r.with_node([&](pb::PathbNode&) {
            r.on_monero_tip();
            return 0;
        });
        d2 = true;
    });
    watchdog(d2, "under the node lock");
    hook.join();
    const bool rerun = wait_for([&] { return r.parked_index_size() == 0; }, 3000);
    r.stop();
    check(up && i1 == 1 && a1 == 0 && i2 == 1 && rerun,
          "relaytip: on_monero_tip from the follower's thread and under the node lock both return; the parked index "
          "runs again (" + std::to_string(i1) + " -> " + std::to_string(a1) + ", " + std::to_string(i2) + " -> 0)");
}


// ---------------------------------------------------------------------------
// revrx_drain (merge-gate review vector): RandomX throws inside complete_carrier: a child carrier parked on its unknown
// parent is released by the parent's placement and admitted (its first hash) inside the parent's completion. The
// failure is caught; the released child is parked and run again: placed; 0 strikes, 0 bans.
void revrx_drain() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 3; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 200 + static_cast<std::uint32_t>(i));
    }
    bool dropped = false;
    w.edit = [&dropped](FakeWire::Msg& m) {
        if (!dropped && m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcCarrier) {
            m.f.clear();
            dropped = true;
        }
    };
    ok = ok && mine_on(h, w, a.node, 2, 210);
    w.edit = nullptr;
    const pb::Hash32 c1 = h[a.node].tree().best().id;
    const bool missed = dropped && h[b.node].tree().find(c1) == nullptr;
    const std::optional<pb::PathbJob> j = h.job(a.node, 3, 211);
    ok = ok && j && h[a.node].on_own_share(*j, 211, pb::Hash32{}).action == pb::NodeAction::Placed;
    const pb::Hash32 c2 = h[a.node].tree().best().id;
    h.throw_pow.insert(c2);
    const pb::PathbRelayStats& st = b.relay->stats();
    const std::uint64_t f0 = st.rx_failures.load();
    std::string esc;
    try {
        w.run();
    } catch (const std::exception& e) {
        esc = e.what();
    }
    const bool thrown = h.throw_pow.count(c2) == 0;
    const std::uint64_t f1 = st.rx_failures.load() - f0;
    const bool c1b = h[b.node].tree().find(c1) != nullptr, c2b = h[b.node].tree().find(c2) != nullptr;
    std::printf("  revrx_drain: ok=%d missed=%d thrown=%d escaped='%s' rx_failures=%llu c1@B=%d c2@B=%d\n", ok, missed,
                thrown, esc.c_str(), (unsigned long long)f1, c1b, c2b);
    std::string esc2;
    for (int i = 0; i < 8; ++i) {
        h.now += 1;
        try {
            b.relay->tick();
            w.run();
        } catch (const std::exception& e) {
            esc2 = e.what();
        }
    }
    const bool c2later = h[b.node].tree().find(c2) != nullptr;
    std::printf("  revrx_drain: after 8 s: c2@B=%d best@B==c2 %d strikes=%llu bans=%llu rx_failures=%llu escaped2='%s'\n",
                c2later, h[b.node].tree().best().id == c2, (unsigned long long)st.strikes.load(),
                (unsigned long long)st.bans.load(), (unsigned long long)(st.rx_failures.load() - f0), esc2.c_str());
    check(ok && missed && thrown && esc.empty() && f1 >= 1,
          "revrx_drain: RandomX reached inside complete_carrier (a released child's first hash) and caught");
    check(c2later && c1b && st.strikes.load() == 0 && st.bans.load() == 0,
          "revrx_drain: the released child placed after the failure (parked and run again), no strike, no ban");
}

// ---------------------------------------------------------------------------
// The header path: a RandomX failure on a header of the catch-up's FC_HEADERS reply is node-internal: no token; the
// catch-up asks again at the abandon timeout and the node reaches the peer's tip.
void relayrxhdr() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    bool mined = true;
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        const std::optional<pb::PathbJob> j = h.job(a.node, static_cast<std::size_t>(i % 5), 100 + i);
        mined = mined && j && h[a.node].on_own_share(*j, 100 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    const pb::Hash32 tip_a = h[a.node].tree().best().id;
    const pb::Hash32 armed = *h[a.node].store().best_at(3);
    h.throw_pow.insert(armed);
    pb::PathbRelayNode& rb = *b.relay;
    w.connect(0, 1);
    w.run();
    const std::uint64_t f1 = rb.stats().rx_failures.load();
    const bool behind = h[b.node].tree().best().id != tip_a && h.throw_pow.count(armed) == 0;
    for (int i = 0; i < 4 && h[b.node].tree().best().id != tip_a; ++i) {
        h.now += h[b.node].config().abandon_timeout_s + 1;
        rb.tick();
        w.run();
    }
    check(mined && f1 == 1 && behind && h[b.node].tree().best().id == tip_a && rb.strikes_of(1) == 0
                  && rb.stats().bans == 0 && rb.stats().catchup_requests >= 2,
          "relayrxhdr: RandomX failed on a catch-up header (" + std::to_string(f1) + " failure): no token; asked again ("
                  + std::to_string(rb.stats().catchup_requests.load()) + " requests), A's tip reached");
}

// ---------------------------------------------------------------------------
// Only a RandomX failure is node-internal: another exception inside an admission (here the seed lookup throws
// std::logic_error) leaves the relay's call (the process's outcome unchanged), no RandomX failure counted.
void relayrxtype() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    auto armed = std::make_shared<bool>(false);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, [armed](pb::PathbNodeIo& io) {
        io.seed_of = [armed, s = io.seed_of](const pb::Hash32& p) -> std::optional<pb::Hash32> {
            if (*armed) {
                *armed = false;
                throw std::logic_error("kat: seed index broken");
            }
            return s(p);
        };
    });
    w.connect(0, 1);
    w.run();
    h.tick_monero();
    *armed = true;
    std::string esc;
    try {
        (void)mine_on(h, w, a.node, 1, 700);
    } catch (const std::logic_error& e) {
        esc = e.what();
    }
    w.q.clear();
    check(esc == "kat: seed index broken" && !*armed && b.relay->stats().rx_failures == 0,
          "relayrxtype: a std::logic_error inside an admission is not taken for a RandomX failure: it leaves the call ('"
                  + esc + "'), 0 RandomX failures counted");
}

// ---------------------------------------------------------------------------
// Manual mode: an event queued for a peer whose link goes down before it runs is skipped (no join hold).
void relaystalem() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t s0 = rb.stats().stale_events.load();
    rb.receive(1, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, pb::Hash32{}, 1}));
    w.links[1]->disconnect(1);
    w.run();
    const std::uint64_t stale = rb.stats().stale_events.load() - s0;
    check(stale == 1 && !h[b.node].join_holding(1),
          "relaystalem: manual mode: an event queued for a peer whose link went down is skipped (" + std::to_string(stale)
                  + "); no join hold for it");
}


// ---------------------------------------------------------------------------
// The bind path: a RandomX failure inside bind_walked_branch (a TipBodies DEFER's walked carrier admitted in the role
// Closure: the first hash of a body only the losing sibling carries) is node-internal: it does not leave the relay; the
// parked frame runs again and the walked branch and its carrier are placed; 0 strikes, 0 bans.
void relayrxbind() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    // jobs on one tip; the tip moves; their shares are pending (two shared by A and L, one each held alone)
    const std::optional<pb::PathbJob> ja = h.job(a.node, 2, 350), jl = h.job(l.node, 3, 351);
    const std::optional<pb::PathbJob> ua = h.job(a.node, 6, 360), ul = h.job(l.node, 7, 361);
    ok = ok && ja && jl && ua && ul && mine_on(h, w, a.node, 1, 352);
    ok = ok && h[a.node].on_own_share(*ja, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[l.node].on_own_share(*jl, 351, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    // the race: the A-L link delivers nothing while each takes a share of its own and mines a sibling
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    ok = ok && h[a.node].on_own_share(*ua, 360, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[l.node].on_own_share(*ul, 361, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 2, 400) && mine_on(h, w, l.node, 3, 401);
    const pb::Hash32 sa = h[a.node].tree().best().id, sl = h[l.node].tree().best().id;
    const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410), kl = h.job(l.node, 4, 411);
    w.edit = nullptr;
    ok = ok && sa != sl && ka && kl && h[a.node].bodies().get(sa) != nullptr && h[l.node].bodies().get(sl) != nullptr;
    if (!ok) {
        check(false, "relayrxbind: setup");
        return;
    }
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(sa), 16)});
    w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(sl), 16)});
    w.run();
    const bool a_lost = sl < sa;
    const std::size_t lo = a_lost ? a.node : l.node;
    const pb::Hash32 loser = a_lost ? sa : sl;
    const pb::PathbJob k = a_lost ? *ka : *kl;
    const std::uint32_t kn = a_lost ? 410 : 411;
    pb::ReceiptBodyV3 ub = a_lost ? ua->body : ul->body;
    ub.blob.nonce = a_lost ? 360 : 361;
    const pb::Hash32 u = pb::receipt_id(ub);  // carried by the losing sibling alone
    bool only_loser = false;
    for (const pb::ReceiptBodyV3& b : h[lo].bodies().get(loser)->carried) only_loser = only_loser || pb::receipt_id(b) == u;
    ok = ok && only_loser && h[a.node].tree().best().id == h[l.node].tree().best().id;
    ok = ok && h[lo].on_own_share(k, kn, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    h.tick_monero();
    ok = ok && mine_on(h, w, lo, 5, 420);
    const pb::Hash32 c = h[lo].tree().best().id;
    if (!ok) {
        check(false, "relayrxbind: setup (the losing sibling carries a body of its own)");
        return;
    }
    // X catches up from the losing node alone; no receipt frame reaches X (u is first hashed in the bind)
    h.throw_pow.insert(u);
    w.edit = [lo, xn = x.node](FakeWire::Msg& m) {
        if (m.from == lo && m.to == xn && !m.f.empty() && m.f[0] == pb::kOpFbReceipts) m.f.clear();
    };
    const pb::PathbRelayStats& st = x.relay->stats();
    std::string esc;
    try {
        w.connect(lo, x.node);
        w.run();
        for (int i = 0; i < 6 && h[x.node].tree().best().id != c; ++i) {
            h.now += 1;
            x.relay->tick();
            w.run();
        }
    } catch (const std::exception& e) {
        esc = e.what();
    }
    w.edit = nullptr;
    const bool thrown = h.throw_pow.count(u) == 0;
    std::printf("  relayrxbind: thrown=%d escaped='%s' rx_failures=%llu walk_placed=%llu loser@X=%d c@X=%d\n", thrown,
                esc.c_str(), (unsigned long long)st.rx_failures.load(), (unsigned long long)st.walk_placed.load(),
                h[x.node].tree().find(loser) != nullptr, h[x.node].tree().best().id == c);
    check(thrown && esc.empty() && st.rx_failures.load() >= 1 && h[x.node].tree().find(loser) != nullptr
                  && h[x.node].tree().best().id == c && st.strikes.load() == 0 && st.bans.load() == 0,
          "relayrxbind: RandomX failed in the bind of a walked carrier (" + std::to_string(st.rx_failures.load())
                  + " failure): not out of the relay; run again: the walked carrier and the tip placed; no strike, no ban");
}


// ---------------------------------------------------------------------------
// relaymaxpage: at the smallest bound start() accepts (two FC_HEADERS frames with their prefixes), a pending set of 17
// receipts of the largest size (P-10, RECEIPT_MAX(15) = 945 B: one FB_RECEIPTS frame of 16,072 B) is re-offered: with
// the link's queue holding 2 B more than leaves one FC_HEADERS frame and its prefix free after the frame, the frame
// waits; with an empty queue it goes (never paused for good).
void relaymaxpage() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay probe = kat_relay(h, w, table0(net), true);
    const std::size_t hf = static_cast<std::size_t>(h[probe.node].frame_bytes_headers());
    // the smallest accepted bound, at or above two frames
    std::size_t floor = 0;
    for (std::size_t b = 2 * hf; b <= 2 * hf + 8 && floor == 0; ++b) {
        try {
            KatRelay k = kat_relay(h, w, table0(net), true, false, [b](pb::PathbRelayOptions& o) { o.send_queue_bytes = b; });
            k.relay->stop();
            w.relays.pop_back();
            floor = b;
        } catch (const std::runtime_error&) {
        }
    }
    KatRelay x = kat_relay(h, w, table0(net), true, false, [floor](pb::PathbRelayOptions& o) { o.send_queue_bytes = floor; });
    KatRelay y = kat_relay(h, w, table0(net), false);
    x.links->limit = floor;
    const std::size_t frame = 6 + 1 + 17 * pb::receipt_max(15);
    x.links->queued = floor > frame + 4 + hf + 2 ? floor - (frame + 4) - hf - 2 : 0;
    // 17 receipts of the largest size, pending at X
    const std::optional<pb::PathbJob> j = h.job(x.node, 1, 900);
    bool built = j.has_value();
    std::size_t one = 0;
    for (std::uint32_t k = 0; built && k < 17; ++k) {
        pb::ReceiptBodyV3 r = j->body;
        r.blob.nonce = 5000 + k;
        r.blob.timestamp = std::uint64_t{1} << 34;  // a varint of 5 bytes
        r.blob.tx_count = std::uint64_t{1} << 20;   // a varint of 3 bytes
        r.branch.assign(15, seq32(0x70));
        r.side.fee_rate_bp = 100;
        r.side.owner = seq32(0x71);
        r.owner = r.payee;
        std::vector<std::uint8_t> enc;
        built = pb::encode_receipt_body_v3(r, enc) == pb::WireError::None;
        one = enc.size();
        pb::PathbNodeTestAccess::add_pending(h[x.node], pb::PendingReceipt{pb::receipt_id(r), r, 0, 0, 0});
    }
    std::size_t sent_bytes = 0;
    std::uint64_t sent_frames = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from == x.links->self && !m.f.empty() && m.f[0] == pb::kOpFbReceipts) {
            ++sent_frames;
            sent_bytes = m.f.size();
            m.f.clear();
        }
    };
    w.connect(x.links->self, y.links->self);
    w.run();
    h.now += 1;
    x.relay->tick();
    w.run();
    const std::uint64_t held = sent_frames, paused = x.relay->stats().reoffer_paused.load();
    x.links->queued = 0;
    for (int i = 0; i < 4 && sent_frames == 0; ++i) {
        h.now += 1;
        x.relay->tick();
        w.run();
    }
    w.edit = nullptr;
    check(floor > 0 && built && one == pb::receipt_max(15) && held == 0 && paused >= 1,
          "relaymaxpage: the queue holding " + std::to_string(floor - (frame + 4) - hf - 2)
                  + " B: the frame waits (one FC_HEADERS frame and its prefix kept free; paused " + std::to_string(paused) + ")");
    check(floor > 0 && built && one == pb::receipt_max(15) && h[x.node].pending().size() == 17 && sent_frames == 1
                  && sent_bytes == 6 + 1 + 17 * one,
          "relaymaxpage: at the start floor " + std::to_string(floor) + " B (FC_HEADERS frame " + std::to_string(hf)
                  + " B) 17 receipts of " + std::to_string(one) + " B re-offered in one frame of "
                  + std::to_string(sent_bytes) + " B (" + std::to_string(sent_frames) + " sent, paused "
                  + std::to_string(x.relay->stats().reoffer_paused.load()) + ")");
}

// ---------------------------------------------------------------------------
// rev99_complete (merge-gate review vector): RandomX fails on a frame's OWN re-admission inside complete_carrier. X and
// Y are siblings on one tip; X then Y are begun on the verify path at one generation; X's placement changes the
// generation, so Y's completion re-admits Y. Its memo entry is gone at that moment (the FIFO turned over between
// begin_carrier and the placement; simulated by clearing the memo when the re-admission looks up its seed). Y's second
// hash throws: caught at the completion; Y parked and run again: placed; 0 strikes, 0 bans.
void rev99_complete() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    struct S {
        pb::Hash32 x{}, y{};
        bool armed = false, evicted = false;
        int y_calls = 0;
        std::size_t node = 0;
    };
    auto s = std::make_shared<S>();
    Harness* hp = &h;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, [s, hp](pb::PathbNodeIo& io) {
        io.verify = [s, v = io.verify](const pb::HashingBlob& b, std::uint64_t d, const pb::Hash32& seed) {
            if (s->armed && pb::receipt_id(b) == s->y && ++s->y_calls == 2)
                throw std::runtime_error("rev99: RandomX failed on Y's re-admission");
            return v(b, d, seed);
        };
        io.seed_of = [s, hp, f = io.seed_of](const pb::Hash32& p) -> std::optional<pb::Hash32> {
            if (s->armed && !s->evicted && s->y_calls == 1 && (*hp)[s->node].tree().find(s->x) != nullptr) {
                pb::PathbNodeTestAccess::memo_clear((*hp)[s->node]);
                s->evicted = true;
            }
            return f(p);
        };
    });
    s->node = x.node;
    w.connect(0, 1);
    w.connect(0, 2);
    w.run();
    bool ok = true;
    for (int i = 0; i < 3; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 P = h[x.node].tree().best().id;
    ok = ok && P == h[a.node].tree().best().id && P == h[l.node].tree().best().id;
    w.edit = [](FakeWire::Msg& m) { m.f.clear(); };
    ok = ok && mine_on(h, w, a.node, 2, 400) && mine_on(h, w, l.node, 3, 401);
    w.edit = nullptr;
    const pb::Hash32 X = h[a.node].tree().best().id, Y = h[l.node].tree().best().id;
    const pb::CarrierNode* nx = h[a.node].tree().find(X);
    const pb::CarrierNode* ny = h[l.node].tree().find(Y);
    ok = ok && X != Y && nx && ny && nx->parent == P && ny->parent == P && h[x.node].tree().find(X) == nullptr
         && h[x.node].tree().find(Y) == nullptr;
    if (!ok) {
        check(false, "rev99_complete: setup");
        return;
    }
    const std::vector<std::uint8_t> fx = *pb::encode_fc_carrier(0, *h[a.node].bodies().get(X), 16);
    const std::vector<std::uint8_t> fy = *pb::encode_fc_carrier(0, *h[l.node].bodies().get(Y), 16);
    s->x = X;
    s->y = Y;
    s->armed = true;
    const pb::PathbRelayStats& st = x.relay->stats();
    const std::uint64_t f0 = st.rx_failures.load();
    x.relay->receive(1, fx);
    x.relay->receive(1, fy);
    std::string esc;
    try {
        w.run();
    } catch (const std::exception& e) {
        esc = e.what();
    }
    const std::uint64_t f1 = st.rx_failures.load() - f0;
    const bool x1 = h[x.node].tree().find(X) != nullptr, y1 = h[x.node].tree().find(Y) != nullptr;
    std::printf("  rev99_complete: evicted=%d y_calls=%d escaped='%s' rx_failures=%llu X@x=%d Y@x=%d\n", s->evicted,
                s->y_calls, esc.c_str(), (unsigned long long)f1, x1, y1);
    std::string esc2;
    for (int i = 0; i < 4 && esc.empty(); ++i) {
        h.now += 1;
        try {
            x.relay->tick();
            w.run();
        } catch (const std::exception& e) {
            esc2 = e.what();
        }
    }
    const bool y2 = h[x.node].tree().find(Y) != nullptr;
    std::printf("  rev99_complete: after 4 s: Y@x=%d y_calls=%d strikes=%llu bans=%llu rx_failures=%llu escaped2='%s'\n",
                y2, s->y_calls, (unsigned long long)st.strikes.load(), (unsigned long long)st.bans.load(),
                (unsigned long long)(st.rx_failures.load() - f0), esc2.c_str());
    check(s->evicted && s->y_calls >= 2 && esc.empty() && f1 == 1 && x1 && !y1,
          "rev99_complete: RandomX failed on Y's own re-admission inside complete_carrier: caught at the completion");
    check(y2 && s->y_calls >= 3 && esc2.empty() && st.strikes.load() == 0 && st.bans.load() == 0,
          "rev99_complete: Y parked and run again: placed; no strike, no ban");
}

// ---------------------------------------------------------------------------
// ownrx: the node's own share whose carried receipt's memo entry is gone and whose RandomX fails: RandomxFailure leaves
// on_own_share (the caller re-runs the share); the own hash is not kept; the re-run places the share.
void ownrx() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        h.mine(a, 1, 20 + i);
    }
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 3; ++k) jobs.push_back(*h.job(a, k + 2, 500 + k));
    h.mine(a, 1, 30);
    std::size_t pend = 0;
    for (std::uint32_t k = 0; k < 3; ++k) pend += h[a].on_own_share(jobs[k], 500 + k, pb::Hash32{}).action == pb::NodeAction::Pending ? 1 : 0;
    const std::optional<pb::PathbJob> j = h.job(a, 1, 31);
    const bool carries = j && !j->carried.empty();
    if (!carries || pend != 3) {
        check(false, "ownrx: setup (3 pending receipts carried by the job)");
        return;
    }
    pb::PathbNodeTestAccess::memo_clear(h[a]);
    const pb::Hash32 rc = pb::receipt_id(j->carried[0]);
    h.throw_pow.insert(rc);
    bool typed = false;
    try {
        (void)h[a].on_own_share(*j, 31, pb::Hash32{});
    } catch (const pb::RandomxFailure&) {
        typed = true;
    }
    const bool kept = pb::PathbNodeTestAccess::own_pow_set(h[a]);
    const pb::NodeEventResult again = h[a].on_own_share(*j, 31, pb::Hash32{});
    check(typed && h.throw_pow.count(rc) == 0 && !kept && again.action == pb::NodeAction::Placed,
          std::string("ownrx: RandomX failed on a carried receipt of the own share: RandomxFailure out of on_own_share (")
                  + (typed ? "yes" : "no") + "), the own hash not kept (" + (kept ? "kept" : "reset")
                  + "); the re-run places the share");
}

// ---------------------------------------------------------------------------
// relayrxbindr: the bind path on the RECEIPT path (FB_RECEIPTS of a receipt whose tip is a walked carrier): a RandomX
// failure in the bind of the walked carrier (the first hash of a body only the losing sibling carries) is counted and
// alarmed; no token, no ban; nothing leaves the relay.
void relayrxbindr() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::PathbJob> ja = h.job(a.node, 2, 350), jl = h.job(l.node, 3, 351);
    const std::optional<pb::PathbJob> ua = h.job(a.node, 6, 360), ul = h.job(l.node, 7, 361);
    ok = ok && ja && jl && ua && ul && mine_on(h, w, a.node, 1, 352);
    ok = ok && h[a.node].on_own_share(*ja, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[l.node].on_own_share(*jl, 351, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    ok = ok && h[a.node].on_own_share(*ua, 360, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[l.node].on_own_share(*ul, 361, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 2, 400) && mine_on(h, w, l.node, 3, 401);
    const pb::Hash32 sa = h[a.node].tree().best().id, sl = h[l.node].tree().best().id;
    const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410), kl = h.job(l.node, 4, 411);
    w.edit = nullptr;
    ok = ok && sa != sl && ka && kl;
    if (!ok) {
        check(false, "relayrxbindr: setup");
        return;
    }
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(sa), 16)});
    w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(sl), 16)});
    w.run();
    const bool a_lost = sl < sa;
    const std::size_t lo = a_lost ? a.node : l.node;
    const pb::Hash32 loser = a_lost ? sa : sl;
    const pb::PathbJob k = a_lost ? *ka : *kl;
    const std::uint32_t kn = a_lost ? 410 : 411;
    pb::ReceiptBodyV3 ub = a_lost ? ua->body : ul->body;
    ub.blob.nonce = a_lost ? 360 : 361;
    const pb::Hash32 u = pb::receipt_id(ub);
    pb::ReceiptBodyV3 rk = k.body;
    rk.blob.nonce = kn;
    bool only_loser = false;
    for (const pb::ReceiptBodyV3& b : h[lo].bodies().get(loser)->carried) only_loser = only_loser || pb::receipt_id(b) == u;
    if (!only_loser) {
        check(false, "relayrxbindr: setup (the losing sibling carries a body of its own)");
        return;
    }
    // X catches up from the losing node alone, no receipt frame of it reaching X; then the receipt rk (tip: the loser)
    // is offered to X until its walked carrier's bind runs
    h.throw_pow.insert(u);
    w.edit = [lo, xn = x.node](FakeWire::Msg& m) {
        if (m.from == lo && m.to == xn && !m.f.empty() && m.f[0] == pb::kOpFbReceipts) m.f.clear();
    };
    const pb::PathbRelayStats& st = x.relay->stats();
    const std::vector<pb::ReceiptBodyV3> one{rk};
    const std::vector<std::uint8_t> frk = *pb::encode_fb_receipts(0, one, pb::kRuledLaneParams);
    std::string esc;
    int offers = 0;
    try {
        w.connect(lo, x.node);
        w.run();
        for (; offers < 8 && h.throw_pow.count(u) != 0; ++offers) {
            x.relay->receive(lo + 1, frk);
            w.run();
            h.now += 1;
            x.relay->tick();
            w.run();
        }
    } catch (const std::exception& e) {
        esc = e.what();
    }
    w.edit = nullptr;
    const bool thrown = h.throw_pow.count(u) == 0;
    std::printf("  relayrxbindr: offers=%d thrown=%d escaped='%s' rx_failures=%llu walk_placed=%llu loser@X=%d\n", offers,
                thrown, esc.c_str(), (unsigned long long)st.rx_failures.load(), (unsigned long long)st.walk_placed.load(),
                h[x.node].tree().find(loser) != nullptr);
    check(thrown && esc.empty() && st.rx_failures.load() >= 1 && st.strikes.load() == 0 && st.bans.load() == 0,
          "relayrxbindr: a RandomX failure in the bind on the receipt path: counted (" + std::to_string(st.rx_failures.load())
                  + "), nothing out of the relay; no strike, no ban");
}


// ---------------------------------------------------------------------------
// relayrxbindk: a bind that refutes one server's body set (a BAN or a strike collected) and then fails on RandomX at
// the next set (the first hash of a body only the losing sibling carries) keeps what it collected: the refuting
// server's token is applied; the failure is counted; nothing leaves the relay.
void relayrxbindk() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::PathbJob> ja = h.job(a.node, 2, 350), jl = h.job(l.node, 3, 351);
    const std::optional<pb::PathbJob> ua = h.job(a.node, 6, 360), ul = h.job(l.node, 7, 361);
    ok = ok && ja && jl && ua && ul && mine_on(h, w, a.node, 1, 352);
    ok = ok && h[a.node].on_own_share(*ja, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[l.node].on_own_share(*jl, 351, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    ok = ok && h[a.node].on_own_share(*ua, 360, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[l.node].on_own_share(*ul, 361, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 2, 400) && mine_on(h, w, l.node, 3, 401);
    const pb::Hash32 sa = h[a.node].tree().best().id, sl = h[l.node].tree().best().id;
    const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410), kl = h.job(l.node, 4, 411);
    w.edit = nullptr;
    ok = ok && sa != sl && ka && kl;
    if (!ok) {
        check(false, "relayrxbindk: setup");
        return;
    }
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(sa), 16)});
    w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(sl), 16)});
    w.run();
    const bool a_lost = sl < sa;
    const std::size_t lo = a_lost ? a.node : l.node, other = a_lost ? l.node : a.node;
    const pb::Hash32 loser = a_lost ? sa : sl;
    const pb::PathbJob k = a_lost ? *ka : *kl;
    const std::uint32_t kn = a_lost ? 410 : 411;
    pb::ReceiptBodyV3 ub = a_lost ? ua->body : ul->body;
    ub.blob.nonce = a_lost ? 360 : 361;
    const pb::Hash32 u = pb::receipt_id(ub);
    ok = ok && h[lo].on_own_share(k, kn, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    h.tick_monero();
    ok = ok && mine_on(h, w, lo, 5, 420);
    const pb::Hash32 c = h[lo].tree().best().id;
    const pb::CarrierBodyV3* lb = h[lo].bodies().get(loser);
    bool only_loser = false;
    for (const pb::ReceiptBodyV3& b : lb != nullptr ? lb->carried : std::vector<pb::ReceiptBodyV3>{})
        only_loser = only_loser || pb::receipt_id(b) == u;
    if (!ok || !only_loser || lb->carried.size() < 2) {
        check(false, "relayrxbindk: setup (the losing sibling carries a body of its own and one more)");
        return;
    }
    // X follows both nodes; no receipt frame reaches X; the loser's body sets X asks for are held back
    std::map<std::size_t, std::vector<std::uint8_t>> sets;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.to != x.node || m.f.empty()) return;
        if (m.f[0] == pb::kOpFbReceipts) {
            m.f.clear();
            return;
        }
        if (m.f[0] != pb::kOpFcCarrier || m.f.size() < pb::kFrameHeaderBytes) return;
        pb::CarrierBodyV3 cb;
        if (pb::decode_carrier_body_v3(m.f.data() + pb::kFrameHeaderBytes, m.f.size() - pb::kFrameHeaderBytes,
                                       pb::CarrierLimits{h[x.node].config().buffers.receipt, pb::kRuledLaneParams.r_max}, cb)
                    == pb::WireError::None
            && pb::receipt_id(cb.own) == loser) {
            sets[m.from] = m.f;
            m.f.clear();
        }
    };
    const std::vector<std::uint8_t> fc = *pb::encode_fc_carrier(0, *h[lo].bodies().get(c), 16);
    w.connect(lo, x.node);
    w.connect(other, x.node);
    w.run();
    for (int i = 0; i < 6 && sets.size() < 2; ++i) {
        for (const std::size_t from : {lo, other})
            if (sets.count(from) == 0) x.relay->receive(from + 1, fc);
        w.run();
        h.now += 1;
        x.relay->tick();
        w.run();
    }
    const bool both = sets.size() == 2;
    // the set of the lower peer id refuted (one carried body changed), the other good: delivered together
    std::string esc;
    const pb::PathbRelayStats& st = x.relay->stats();
    const std::uint64_t bans0 = st.bans.load(), f0 = st.rx_failures.load();
    std::uint64_t first_from = 0, tokens = 0;
    if (both) {
        const std::size_t p1 = std::min(lo, other), p2 = std::max(lo, other);
        pb::CarrierBodyV3 bad = *lb;
        for (pb::ReceiptBodyV3& b : bad.carried)
            if (pb::receipt_id(b) != u) {
                b.blob.nonce ^= 1;
                break;
            }
        first_from = p1 + 1;
        h.throw_pow.insert(u);
        try {
            x.relay->receive(p1 + 1, *pb::encode_fc_carrier(0, bad, 16));
            x.relay->receive(p2 + 1, sets[p2]);
            w.run();
        } catch (const std::exception& e) {
            esc = e.what();
        }
        tokens = (st.bans.load() - bans0) + x.relay->strikes_of(first_from);
    }
    w.edit = nullptr;
    const bool thrown = h.throw_pow.count(u) == 0;
    std::printf("  relayrxbindk: both=%d thrown=%d escaped='%s' rx_failures=%llu refuting server tokens=%llu\n", both, thrown,
                esc.c_str(), (unsigned long long)(st.rx_failures.load() - f0), (unsigned long long)tokens);
    check(both && thrown && esc.empty() && st.rx_failures.load() > f0 && tokens >= 1,
          "relayrxbindk: a bind that refuted a body set, then failed on RandomX: the refuting server's token applied ("
                  + std::to_string(tokens) + "), the failure counted, nothing out of the relay");
}


// ---------------------------------------------------------------------------
// relayp15once: P-15 counts a frame once, at its first placement, a re-run or not:
//   (a) a carrier parked on its unknown parent (a flood) and placed in its parent's drain: counted once (its parent, a
//       reply to this node's own FC_GETCARRIER, not);
//   (b) a carrier that waited for its DoS token (the sender's token spent by a strike): counted once when placed;
//   (c) a carrier parked on its carried tip's branch (TipUnknown -> the walk) and placed on its re-run: counted once;
//       sent again (a duplicate): not counted.
void relayp15once() {
    // (a) and (b)
    {
        const KatNet net;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false);
        w.connect(0, 1);
        w.run();
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, 1, 200 + static_cast<std::uint32_t>(i));
        }
        pb::PathbRelayNode& rb = *b.relay;
        const pb::PathbRelayStats& st = rb.stats();
        bool dropped = false;
        w.edit = [&dropped](FakeWire::Msg& m) {
            if (!dropped && m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcCarrier) {
                m.f.clear();
                dropped = true;
            }
        };
        ok = ok && mine_on(h, w, a.node, 2, 210);
        w.edit = nullptr;
        const pb::Hash32 c1 = h[a.node].tree().best().id;
        const std::uint64_t n0 = st.p15_counted.load();
        ok = ok && mine_on(h, w, a.node, 3, 211);  // c2: parked on c1, c1 fetched (solicited), c2 released in the drain
        const pb::Hash32 c2 = h[a.node].tree().best().id;
        const std::uint64_t na = st.p15_counted.load() - n0;
        check(ok && dropped && h[b.node].tree().find(c1) != nullptr && h[b.node].tree().best().id == c2 && na == 1,
              "relayp15once: (a) a carrier parked on its unknown parent and placed in the parent's drain: counted once ("
                      + std::to_string(na) + "; the parent, a reply to the node's own request, not)");
        // (b): a strike spends the sender's token; the next carrier waits for it, then is placed
        h.tick_monero();
        const std::optional<pb::PathbJob> jb = h.job(a.node, 1, 220);
        pb::CarrierBodyV3 bad = *h[a.node].bodies().get(c2);
        bad.own.side.t_origin += 1;
        const std::uint64_t s0 = rb.strikes_of(1), d0 = st.rx_deferred.load();
        rb.receive(1, *pb::encode_fc_carrier(0, bad, 16));
        w.run();
        const std::uint64_t n1 = st.p15_counted.load();
        ok = jb && h[a.node].on_own_share(*jb, 220, pb::Hash32{}).action == pb::NodeAction::Placed;
        const pb::Hash32 c3 = h[a.node].tree().best().id;
        w.run();
        const bool waited = st.rx_deferred.load() > d0 && h[b.node].tree().find(c3) == nullptr;
        for (int i = 0; i < 60 && h[b.node].tree().find(c3) == nullptr; ++i) {
            h.now += 10;
            rb.tick();
            w.run();
        }
        const std::uint64_t nb = st.p15_counted.load() - n1;
        check(ok && rb.strikes_of(1) == s0 + 1 && waited && h[b.node].tree().find(c3) != nullptr && nb == 1,
              "relayp15once: (b) a carrier that waited for its DoS token (the sender's token spent by a strike): placed, "
              "counted once (" + std::to_string(nb) + ")");
    }
    // (c)
    {
        const KatNet net;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay l = kat_relay(h, w, table0(net), true);
        KatRelay x = kat_relay(h, w, table0(net), false);
        w.connect(0, 1);
        w.run();
        bool ok = true;
        for (int i = 0; i < 4; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
        }
        w.edit = [](FakeWire::Msg& m) {
            if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
        };
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 2, 400) && mine_on(h, w, l.node, 3, 401);
        const pb::Hash32 sa = h[a.node].tree().best().id, sl = h[l.node].tree().best().id;
        const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410), kl = h.job(l.node, 4, 411);
        w.edit = nullptr;
        ok = ok && sa != sl && ka && kl;
        if (!ok) {
            check(false, "relayp15once: (c) setup");
            return;
        }
        w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(sa), 16)});
        w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(sl), 16)});
        w.run();
        const bool a_lost = sl < sa;
        const std::size_t lo = a_lost ? a.node : l.node;
        const pb::PathbJob k = a_lost ? *ka : *kl;
        const std::uint32_t kn = a_lost ? 410 : 411;
        ok = ok && h[lo].on_own_share(k, kn, pb::Hash32{}).action == pb::NodeAction::Pending;
        w.run();
        // X follows the losing node's best chain, then gets its next carrier c (carrying k's receipt, its tip the
        // losing sibling) as a flood
        w.connect(lo, x.node);
        w.run();
        const pb::PathbRelayStats& st = x.relay->stats();
        const std::uint64_t n0 = st.p15_counted.load(), r0 = st.parked_reruns.load();
        h.tick_monero();
        ok = ok && mine_on(h, w, lo, 5, 420);
        const pb::Hash32 c = h[lo].tree().best().id;
        for (int i = 0; i < 6 && h[x.node].tree().best().id != c; ++i) {
            h.now += 1;
            x.relay->tick();
            w.run();
        }
        const pb::CarrierBodyV3* cb = h[lo].bodies().get(c);
        const std::uint64_t nc = st.p15_counted.load() - n0;
        const bool rerun = st.parked_reruns.load() > r0;
        x.relay->receive(lo + 1, *pb::encode_fc_carrier(0, *cb, 16));  // the same frame again: a duplicate
        w.run();
        const std::uint64_t nd = st.p15_counted.load() - n0;
        check(ok && cb != nullptr && rerun && h[x.node].tree().best().id == c && nc >= 1 && nc <= 1 + cb->carried.size()
                      && nd == nc,
              "relayp15once: (c) a carrier parked on its carried tip's branch and placed on its re-run: counted once ("
                      + std::to_string(nc) + " objects); sent again: not counted (" + std::to_string(nd) + ")");
    }
}


// ---------------------------------------------------------------------------
// relayrxbind2: a walk that placed a walked carrier (it carries nothing), then whose bind of the next failed on RandomX
// (a body only that one carries): the placed id stays placed and counted (walk_placed), the failure counted; the
// parked frame's re-run places the rest.
void relayrxbind2() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::PathbJob> ua = h.job(a.node, 6, 360);
    // the race: A mines two (its second carries a body of A's alone), L three: A's branch loses
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    h.tick_monero();
    ok = ok && ua && mine_on(h, w, a.node, 2, 400);
    const pb::Hash32 sa1 = h[a.node].tree().best().id;
    ok = ok && h[a.node].on_own_share(*ua, 360, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && mine_on(h, w, a.node, 2, 402);
    const pb::Hash32 sa2 = h[a.node].tree().best().id;
    const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410);
    for (int i = 0; i < 3; ++i) ok = ok && mine_on(h, w, l.node, 3, 401 + 10 * static_cast<std::uint32_t>(i));
    w.edit = nullptr;
    pb::ReceiptBodyV3 ub = ua->body;
    ub.blob.nonce = 360;
    const pb::Hash32 u = pb::receipt_id(ub);
    bool in2 = false, in1 = false;
    for (const pb::ReceiptBodyV3& b : h[a.node].bodies().get(sa2)->carried) in2 = in2 || pb::receipt_id(b) == u;
    for (const pb::ReceiptBodyV3& b : h[a.node].bodies().get(sa1)->carried) in1 = in1 || pb::receipt_id(b) == u;
    ok = ok && ka && in2 && !in1;
    if (!ok) {
        check(false, "relayrxbind2: setup (a two-carrier losing branch, its second carrying a body of its own)");
        return;
    }
    for (const pb::Hash32& id : {sa1, sa2}) w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(id), 16)});
    {
        std::vector<pb::Hash32> ls;
        for (pb::Hash32 t = h[l.node].tree().best().id; ls.size() < 3; t = h[l.node].tree().find(t)->parent) ls.push_back(t);
        for (auto it = ls.rbegin(); it != ls.rend(); ++it)
            w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(*it), 16)});
    }
    w.run();
    ok = h[a.node].tree().best().id == h[l.node].tree().best().id && h[a.node].tree().find(sa2) != nullptr;
    ok = ok && h[a.node].on_own_share(*ka, 410, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 5, 420);
    const pb::Hash32 c = h[a.node].tree().best().id;
    if (!ok) {
        check(false, "relayrxbind2: setup (A follows L, c carries k on the losing branch)");
        return;
    }
    // X follows A alone; no receipt frame reaches X (u is first hashed in the bind of sa2)
    h.throw_pow.insert(u);
    w.edit = [xn = x.node](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == xn && !m.f.empty() && m.f[0] == pb::kOpFbReceipts) m.f.clear();
    };
    const pb::PathbRelayStats& st = x.relay->stats();
    std::string esc;
    std::uint64_t placed_at_fail = 0;
    bool sa1_at_fail = false;
    try {
        w.connect(a.node, x.node);
        w.run();
        for (int i = 0; i < 8 && h[x.node].tree().best().id != c; ++i) {
            if (st.rx_failures.load() > 0 && placed_at_fail == 0) {
                placed_at_fail = st.walk_placed.load();
                sa1_at_fail = h[x.node].tree().find(sa1) != nullptr && h[x.node].tree().find(sa2) == nullptr;
            }
            h.now += 1;
            x.relay->tick();
            w.run();
        }
    } catch (const std::exception& e) {
        esc = e.what();
    }
    w.edit = nullptr;
    std::printf("  relayrxbind2: thrown=%d escaped='%s' rx_failures=%llu walk_placed at the failure %llu (sa1 placed, sa2 not: "
                "%d) c@X=%d\n",
                h.throw_pow.count(u) == 0, esc.c_str(), (unsigned long long)st.rx_failures.load(),
                (unsigned long long)placed_at_fail, sa1_at_fail, h[x.node].tree().best().id == c);
    check(h.throw_pow.count(u) == 0 && esc.empty() && st.rx_failures.load() >= 1 && placed_at_fail >= 1 && sa1_at_fail
                  && h[x.node].tree().best().id == c && st.strikes.load() == 0 && st.bans.load() == 0,
          "relayrxbind2: a walk placed a walked carrier, then the bind of the next failed on RandomX: the placed one kept "
          "and counted, the failure counted; the re-run places the rest and the tip");
}


// ---------------------------------------------------------------------------
// ownrxrun: the own share path (W-E5, W-E5b): RandomX fails on a carried receipt of an own share (its memo entry gone):
// the runner keeps the share (no exit) with one alarm line; its re-run places it (a second line). A kept share whose
// job is no longer issued is dropped as stale, not run.
void ownrxrun() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        h.mine(a, 1, 20 + i);
    }
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 3; ++k) jobs.push_back(*h.job(a, k + 2, 500 + k));
    h.mine(a, 1, 30);
    std::size_t pend = 0;
    for (std::uint32_t k = 0; k < 3; ++k) pend += h[a].on_own_share(jobs[k], 500 + k, pb::Hash32{}).action == pb::NodeAction::Pending ? 1 : 0;
    const std::optional<pb::PathbJob> j = h.job(a, 1, 31);
    if (!j || j->carried.empty() || pend != 3) {
        check(false, "ownrxrun: setup (3 pending receipts carried by the job)");
        return;
    }
    bool live = true;
    std::vector<std::string> lines;
    pb::OwnShareRunner runner([&](const pb::OwnShare& s) { return h[a].on_own_share(s.job, s.nonce, s.pow_hash); },
                              [&](const pb::OwnShare&) { return live; }, [&](const std::string& l) { lines.push_back(l); });
    pb::PathbNodeTestAccess::memo_clear(h[a]);
    const pb::Hash32 rc = pb::receipt_id(j->carried[0]);
    h.throw_pow.insert(rc);
    std::string esc;
    std::optional<pb::NodeEventResult> r1;
    std::vector<pb::NodeEventResult> rs;
    try {
        r1 = runner.submit(pb::OwnShare{7, 9, *j, 31, pb::Hash32{}});
    } catch (const std::exception& e) {
        esc = e.what();
    }
    const std::size_t kept1 = runner.kept();
    const std::size_t lines1 = lines.size();
    rs = runner.run_kept();
    check(esc.empty() && !r1 && kept1 == 1 && lines1 == 1 && h.throw_pow.count(rc) == 0 && rs.size() == 1
                  && rs[0].action == pb::NodeAction::Placed && runner.kept() == 0 && runner.stats().rx_failures == 1
                  && runner.stats().reruns == 1 && lines.size() == 2,
          "ownrxrun: RandomX failed on the own share: kept (" + std::to_string(kept1) + "), no exit" +
                  (esc.empty() ? "" : " (escaped: " + esc + ")") + "; the re-run placed it (" +
                  std::to_string(rs.size()) + " run), alarm lines " + std::to_string(lines.size()));
    // stale: a kept share whose job is no longer issued is dropped, not run
    std::vector<pb::PathbJob> jobs2;
    for (std::uint32_t k = 0; k < 2; ++k)
        if (const std::optional<pb::PathbJob> jk = h.job(a, k + 2, 600 + k)) jobs2.push_back(*jk);
    h.mine(a, 1, 40);
    for (std::uint32_t k = 0; k < jobs2.size(); ++k) (void)h[a].on_own_share(jobs2[k], 600 + k, pb::Hash32{});
    const std::optional<pb::PathbJob> j2 = h.job(a, 1, 41);
    if (!j2 || j2->carried.empty()) {
        check(false, "ownrxrun: setup (a second job carrying a receipt)");
        return;
    }
    pb::PathbNodeTestAccess::memo_clear(h[a]);
    const pb::Hash32 rc2 = pb::receipt_id(j2->carried[0]);
    h.throw_pow.insert(rc2);
    const std::optional<pb::NodeEventResult> r2 = runner.submit(pb::OwnShare{8, 9, *j2, 41, pb::Hash32{}});
    h.throw_pow.insert(rc2);  // armed again: a run of the stale share would throw
    live = false;
    const std::vector<pb::NodeEventResult> rs2 = runner.run_kept();
    check(!r2 && rs2.empty() && runner.kept() == 0 && runner.stats().stale == 1 && h.throw_pow.count(rc2) == 1,
          "ownrxrun: a kept share whose job is stale is dropped, not run (stale " + std::to_string(runner.stats().stale) + ")");
    h.throw_pow.clear();
}


// ---------------------------------------------------------------------------
// relayp40: P-40: a load-failed node J holding the HELLO tail of one peer queues its tip and attempts nothing (a wait
// counted); with a second peer's HELLO tail the attempt runs and completes.
void relayp40() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), false);
    KatRelay j = kat_relay(h, w, table0(net), false, true);
    bool mined = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        const std::optional<pb::PathbJob> jb = h.job(a.node, static_cast<std::size_t>(i % 3), 700 + i);
        mined = mined && jb && h[a.node].on_own_share(*jb, 700 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    w.connect(a.node, c.node);
    w.run();
    const pb::Hash32 tip_a = h[a.node].tree().best().id;
    w.connect(a.node, j.node);
    w.run();
    const std::optional<pb::JoinStep> s1 = j.relay->join_step();
    w.run();
    const bool waited = !s1 && j.relay->stats().join_waits.load() >= 1 && j.relay->stats().join_attempts.load() == 0
                        && h[j.node].joiner().queue().size() >= 1;
    w.connect(c.node, j.node);
    w.run();
    const std::optional<pb::JoinStep> s2 = j.relay->join_step();
    w.run();
    check(mined && h[c.node].tree().best().id == tip_a && waited && s2 && s2->switched && h[j.node].tree().best().id == tip_a
                  && j.relay->stats().join_attempts.load() == 1,
          "relayp40: one HELLO tail: no attempt (waits " + std::to_string(j.relay->stats().join_waits.load()) +
                  "); two: the attempt joins A's tip");
}

// ---------------------------------------------------------------------------
// relayp50: P-50: claim-leaf alarms on frames a peer relays, 1 + R_MAX of them at once: the link kept; one more: the
// link dropped, no ban, no token, its bucket gone. Alarms on replies to the node's own requests are not counted.
void relayp50() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = 1;
    const std::uint64_t burst = 1 + pb::kRuledLaneParams.r_max;
    for (std::uint64_t i = 0; i < 3 * burst; ++i)
        rb.test_parked(pa, pb::Missing::ClaimAlarm, seq32(static_cast<std::uint8_t>(i)), pb::Hash32{}, false);
    w.run();
    const bool solicited_free = rb.hello_ok(pa) && rb.stats().claim_alarm_drops.load() == 0 && rb.stats().claim_alarms.load() == 0;
    for (std::uint64_t i = 0; i < burst; ++i)
        rb.test_parked(pa, pb::Missing::ClaimAlarm, seq32(static_cast<std::uint8_t>(0x80 + i)), pb::Hash32{}, true);
    rb.tick();
    w.run();
    const bool kept = rb.hello_ok(pa) && rb.stats().claim_alarm_drops.load() == 0 && rb.claim_entries() == 1;
    rb.test_parked(pa, pb::Missing::ClaimAlarm, seq32(0xf0), pb::Hash32{}, true);
    rb.tick();
    w.run();
    check(solicited_free && kept && rb.stats().claim_alarm_drops.load() == 1 && !rb.hello_ok(pa) && rb.stats().bans.load() == 0
                  && rb.strikes_of(pa) == 0 && rb.claim_entries() == 0,
          "relayp50: " + std::to_string(burst) + " relayed claim-leaf alarms at once: kept; one more: the link dropped, no "
          "ban, no token, its bucket gone; alarms on solicited replies not counted");
}


// ---------------------------------------------------------------------------
// relayjoint: the threaded join over loopback TCP: a load-failed node J dials A and C (HELLO tails of two peers,
// P-40); the attempt runs on J's join worker and its outcome is applied on J's owner. RandomX fails once in J's first
// attempt (the hash of A's tip): that attempt ends NodeInternal, alarmed (rx_failures), no strike, no ban, no process
// end; the next attempt joins A's tip.
void relayjoint() {
    const KatNet net;
    Harness h(net);
    h.tick_monero();
    std::atomic<bool> armed{false};
    std::atomic<std::uint64_t> thrown{0};
    pb::Hash32 tip_a{};
    std::mutex tip_m;
    const auto io_of = [&](std::size_t self, bool joiner) {
        pb::PathbNodeIo o = h.io(self);
        o.verify = [&, joiner](const pb::HashingBlob& b, std::uint64_t, const pb::Hash32&) {
            if (joiner && armed.load()) {
                std::lock_guard<std::mutex> lk(tip_m);
                if (pb::receipt_id(b) == tip_a && armed.exchange(false)) {
                    ++thrown;
                    throw std::runtime_error("kat: RandomX worker failed");
                }
            }
            return true;
        };
        return o;
    };
    std::string why;
    pb::CarrierLinks la, lc, lj;
    pb::PathbRelayOptions oa;
    oa.listen = true;
    oa.listen_host = "127.0.0.1";
    pb::PathbRelayNode ra(oa, la);
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), true), ra.bind_io(io_of(0, false))));
    ra.attach(*h.nodes[0]);
    bool mined = true;
    for (int i = 0; i < 3; ++i) {
        const std::optional<pb::PathbJob> j = h.job(0, static_cast<std::size_t>(i), 800 + i);
        mined = mined && j && h[0].on_own_share(*j, 800 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    const bool sa = ra.start(why);
    pb::PathbRelayOptions oc;
    oc.listen = true;
    oc.listen_host = "127.0.0.1";
    oc.peers = {{"127.0.0.1", la.listen_port()}};
    pb::PathbRelayNode rc(oc, lc);
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net)), rc.bind_io(io_of(1, false))));
    rc.attach(*h.nodes[1]);
    const bool sc = rc.start(why);
    const auto best = [](pb::PathbRelayNode& r) { return r.with_node([](pb::PathbNode& n) { return n.tree().best().id; }); };
    {
        std::lock_guard<std::mutex> lk(tip_m);
        tip_a = best(ra);
    }
    const bool c_caught = wait_for([&] { return best(rc) == tip_a; }, 10000);
    armed = true;
    pb::PathbRelayOptions oj;
    oj.peers = {{"127.0.0.1", la.listen_port()}, {"127.0.0.1", lc.listen_port()}};
    pb::PathbRelayNode rj(oj, lj);
    pb::PathbNodeConfig cj = h.config(table0(net));
    cj.abandon_timeout_s = 1;
    h.kvs.push_back(std::make_unique<MemoryKv>());
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cj, rj.bind_io(io_of(2, true)), h.kvs.back().get(), pb::PathbNode::LoadFailed{}));
    rj.attach(*h.nodes[2]);
    const bool sj = rj.start(why);
    const bool joined = wait_for([&] { return best(rj) == tip_a; }, 30000);
    const pb::PathbRelayStats& st = rj.stats();
    check(mined && sa && sc && sj && c_caught && joined && thrown.load() == 1 && st.rx_failures.load() >= 1
                  && st.join_attempts.load() >= 2 && st.strikes.load() == 0 && st.bans.load() == 0,
          "relayjoint: J joins A's tip on its join worker over TCP after a RandomX failure in its first attempt (thrown " +
                  std::to_string(thrown.load()) + ", rx_failures " + std::to_string(st.rx_failures.load()) + ", attempts " +
                  std::to_string(st.join_attempts.load()) + "; " + rj.describe() + ")");
    rj.stop();
    rc.stop();
    ra.stop();
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
    run("relaytok", relaytok);
    run("relaym4", relaym4);
    run("relaybudget", relaybudget);
    run("relayfetch", relayfetch);
    run("relaysmoke", relaysmoke);
    run("relayq", relayq);
    run("relayindex", relayindex);
    run("relayp15", relayp15);
    run("relayp15rx", relayp15rx);
    run("ownbound", ownbound);
    run("deferfound", deferfound);
    run("alarmbound", alarmbound);
    run("relaystale", relaystale);
    run("relaytip", relaytip);
    run("relaysq", relaysq);
    run("revrx_drain", revrx_drain);
    run("relayrxhdr", relayrxhdr);
    run("relayrxtype", relayrxtype);
    run("relaystalem", relaystalem);
    run("relayrxbind", relayrxbind);
    run("relaymaxpage", relaymaxpage);
    run("rev99_complete", rev99_complete);
    run("ownrx", ownrx);
    run("relayrxbindr", relayrxbindr);
    run("relayrxbindk", relayrxbindk);
    run("relayp15once", relayp15once);
    run("relayrxbind2", relayrxbind2);
    run("ownrxrun", ownrxrun);
    run("relayp40", relayp40);
    run("relayp50", relayp50);
    run("relayjoint", relayjoint);
    run("regtestk30", regtestk30);
    run("prune_young", prune_young);
    run("prune_default", prune_default);
    run("prune_flags", prune_flags);
    run("prune_side", prune_side);
    run("prune_hold", prune_hold);
    run("below", below);
    return finish("v37_xmr_pathb_node_kat");
}
