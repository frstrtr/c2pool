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
//                its origin bin), 1 bin after the switch (carry-bins);
//   racelate     the same, carried 3 bins after the switch (the 3+ bucket);
//   raceskip     the loser's P_r not held at its switch: repend-skipped 1;
//   carriage     17 carriable pending receipts: the first 16 in the canonical
//                order; a carriable receipt is carried by default (R2); the 16
//                carried receipts of other payees counted foreign-carried;
//   feediverse   receipts on one (tip, P_r) with one R: no multi-fee key; with
//                two template fees: one, r-min < r-max; pruned at the seal;
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
//   j1stale      a FC_HEADERS reply to a request P-53 retired: DROP, no BAN,
//                no re-ask while it is retired; a frame on another from: DROP,
//                the request open; a reply broken inside: STRIKE; failing PoW:
//                BAN with its reason;
//   relayj1stale the same through the relay's catch-up loop: no ban, the
//                DROP logged, J at the server's tip; a BANNED line names
//                its check;
//   hdrstrike    a header failing S1.3 #6, #7 or #8 on the header path: STRIKE,
//                nothing indexed; the relay strikes once and logs it;
//   hdrseed      a header whose P_r's seed is not held: DEFER (Seed), no
//                ban; asked again once held, J at the tip;
//   catchpage    an empty-store catch-up of 1,300 positions from three servers
//                finishes; one page in flight per server; the bodies asked
//                within the deferred store's free room;
//   catchhold    a server answers headers and serves no body: the other
//                servers are asked the bodies; J reaches the tip in 60 s;
//   catchslow    a server serves one body per 10 s: J reaches the tip in 60 s;
//   catchgone    a server leaves with a page of its own branch in flight: its
//                asks leave the deferred store's room at P-53; J reaches the
//                other servers' tip in 60 s;
//   catchlost    the only server loses J's first body request: the page lapses
//                at P-53; J reaches the tip in 60 s;
//   catchfull    a full deferred store: at least the first missing body per
//                page; J reaches the tip in 60 s;
//   hp_stale     one FC_GETHEADERS in flight per peer until a frame of its
//                reply arrives: an arrived reply is not retired at P-53; a
//                retired request takes no new one, its reply DROPs; the relay;
//   hp_tipkeep   tip-header outcomes (Keep with ids, Keep empty, FetchBodies)
//                keep every catch-up entry; equal tip requests merge;
//   hp_tip_in_page  a tip reply during a catch-up page leaves the page and the
//                locator as they are;
//   hp_stale_after_tip  a stale catch-up reply after a tip request (young lane,
//                the same from; an empty one): DROP; the tip request waits, then
//                gets its own reply;
//   hp_side_in_page  a join ticket after a catch-up request on one link: each
//                reply to its own request; a dropped ticket's reply DROPs;
//   hp_ctxslot   header DEFERs kept per (owner, from, stop): the catch-up and a
//                tip request on two P_r; the joiner offer for the catch-up's only;
//   hp_firstround  the template gate's first round ends at the catch-up's reply,
//                not at a tip reply;
//   hp_guard     a frame that does not start at the open request's from: DROP,
//                the request open with its clock;
//   hp_crawl     a catch-up of one page from three servers: one catch-up
//                request per server;
//   hp_qbound    a peer's waiting tip requests and tip deferrals within P-47,
//                those of objects no longer waiting first; 20,000 junk receipts;
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
//   blockblob    the block blob of a Path B job (PathbJobSource, a window of
//                three payees) pinned byte for byte: no transactions, 12
//                transactions, a set filled to within one candidate of the
//                weight cap, and a job carrying 16 receipts; each issued job
//                holds its window's N(B), f_spend, B and Z;
//   relaystale   a gone peer's events (in flight, posted by its blocked
//                reader) skipped: no join hold for the gone peer;
//   relaytip     on_monero_tip from the follower's thread and under the node
//                lock: both return; the parked index runs again.
//   relaysq      a send queue bound below two FC_HEADERS frames (0 among
//                them) refused at start;
//   revrx_drain  RandomX throws on a released child's first hash inside its
//                parent's completion: caught, the child parked and placed;
//   drainban     a carrier parked on its unknown parent, released by the
//                parent's placement, its own PoW failing (R12): its sender
//                banned (one BANNED line naming R12 and its id), no strike;
//   drainstrike  the same with its carried list out of order (R28): one
//                token of its sender's budget, no ban;
//   drainhonest  the same as mined: placed by the drain, no strike, no ban;
//   draingone    the same as drainban, its sender's link down before the
//                parent arrives from another peer: one line, nothing applied;
//   relayrxhdr   RandomX throws on a catch-up header: no token, asked again;
//   hdrnohash    the binary's verify computes no hash on a header:
//                RandomxFailure, no BAN, not memoised; asked again: placed;
//                a hash computed not meeting d: BAN (S1.3 #11);
//   relayrxnohash the same through the relay, on a catch-up header and on a
//                relayed carrier: no token, no ban, the reason logged, asked
//                again or run again; a hash not meeting d: BAN;
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
//   relayverdictlog a receipt struck (R16) or refused (R21, its bin sealed):
//                one STRIKE / REFUSE line naming the row and its id;
//   relayparkstrike a parked carrier released by its parent's placement and
//                struck (R28): its STRIKE line as a received frame's;
//   repevict     a re-pended receipt evicted by P-09 while watched: counted
//                evicted, the watch empty;
//   openstate    the open state at the best tip: its placements and
//                their receipt bodies' wire bytes, against a sum by hand;
//   opendead     a legally dead placement in an open bin counts in the
//                open state (6 of 6 placements, 2,382 B);
//   statusperiod the status line's open state and liveness, computed once
//                per status period (2 evaluations in 40 passes over 2
//                periods), against a sum by hand;
//   ownorphan    own carriers watched until confirmed (below the journal
//                base) or orphaned (a lost race): the loser counts one; a
//                third node extends the chain past J: the watches are empty;
//   liveness     the liveness line: two nodes at one tip print one hash;
//                one more placement at one node changes it there;
//   wingolden    the job, coinbase and digest bytes of a fixed run equal
//                the recorded golden;
//   wingoldenmb  the same with an owner fee of 1 bp merged back (the flag
//                fires): the bytes equal the recorded golden;
//   relayomit    the per-peer omission log: a peer's carrier with room that
//                leaves out a receipt this node holds pending is counted for
//                that peer's link; every link down empties the log;
//   relayomitgone a carrier run again after its link went down (a
//                RandomX park): counted in the total, no entry for the
//                gone link;
//   omitrules    the omission count (E3's carriable list at the parent):
//                a full carrier none; a receipt left out by one with room
//                1; the carrier's own receipt pending first not counted;
//   omitfresh    a healed partition's old carrier and a receipt on a newer
//                Monero height (h(r) > h(c) + Fresh): none;
//   omitopen     a receipt open at the best tip, sealed at a sibling's
//                child carrier's parent: none;
//   omitcompete  a receipt whose tip is the carrier's parent (it competes
//                for the carrier's position): not counted;
//   omitwalk     a receipt whose tip forks more than J_0 below the
//                carrier's parent (the honest list leaves it out): none;
//   omithonest   an all-honest three-node run (a partition, a switch by
//                the journal, the heal, three rounds): no omission logged;
//   relayswitchlog a switch line per switch and a carrier admission counted
//                once on both switch paths (a direct placement, the drain);
//   relaybindswitch a carrier a receipt's walk binds and places (switching
//                the node) is counted: its switch line, its admission;
//   relayrepend  a switch relays its re-pended receipts as FB_RECEIPTS v3
//                (paged; both switch paths: a direct placement, the drain);
//                the switching node mines no more, a peer's carrier carries
//                them;
//   revrepend2   two re-pended receipts, the second's tip on the abandoned
//                branch: parked by the peers until that tip arrives, then
//                held; a peer's carrier carries both;
//   relayqfull   a link dropped for a full queue at a relay send: a re-offer
//                drop while the peer's re-offer pages, else a live one;
//   relayrxbind2 one walk placed a walked carrier, then the bind of the next
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
//   relaypace    the join worker after a NotServed end (a short FC_HEADERS
//                reply; threads, TCP, the relay's ticks): the next attempt no
//                sooner than P-53;
//   regtestk30   the regtest rig's K30 set: the golden G by default, a G of
//                its own with a rig set, a kind-2 file for epoch 1 accepted
//                at fixed = start + GRACE, refused off regtest;
//   jobslot      the CPU miner's own slot: a job on every template after
//                66,000 stratum binds; every bind taken by its get_job (no
//                template, make_job failed, a cached job, an issue); a skip
//                counted once per template, none under a HOLD;
//   minerwithdraw  a template withdrawn while the CPU miner holds a job:
//                the job is withdrawn once; the next template is pushed;
//   minerflush   the withdraw hands the miner's queued hits on: a Monero
//                block on a held parent is submitted, one on an abandoned
//                parent refused and logged by the gated lookup; with the
//                lane gate closed they are dropped and counted;
//   ctxgate      frames parked on a Monero input run again per (cause, id)
//                only when that input is held: no storm on a P_r held
//                without its weights, no context asked for it; the seed;
//                the seal sweep by the frame's own P_r;
//   parkidx      the park index keeps only objects that wait: frames
//                evicted past the deferred store's cap leave it (at most
//                the cap more indexed);
//   catchjoin    a store not caught up whose catch-up step stays deferred
//                on a P_r no node serves: the record stays, the tip offered
//                to the joiner after kCtxTtlMs, the pair paced on that P_r;
//   catchwalk    the same past position 0: a parent walk places the
//                carriers below the P_r no node serves; the tip is still
//                offered to the joiner after kCtxTtlMs and attempted;
//   catchgate    the template gate of a store not caught up: the first
//                round in flight, verified headers whose bodies are in
//                flight; a node caught up keeps its templates;
//   catchrestart the record across a restart; a launch node writes none;
//   catchlocator the catch-up's locator steps after a partition;
//   catchkeep    a store not caught up whose one HELLO peer holds an unheld
//                lighter tip: the catch-up ends at its reply (its chain kept)
//                and the store is caught up (the record gone, templates);
//   catchlight   an unheld lighter tip: at most one locator round per HELLO,
//                none after its reply; the chain never switches;
//   catchoffer   a store not caught up, partly walked, offered an unheld
//                lighter tip: one pair, one attempt, rule (4) keeps its chain
//                and the store is caught up (no record; after a restart no
//                NoPathbPeer and no first round);
//   revcatchundec  the catch-up of a store not caught up ended by an
//                undecodable reply (STRIKE): caught up, its chain kept;
//   catchtok     the same ended by a reply that strikes (a link broken inside
//                it) or bans (a header failing its PoW at d);
//   catchheavy   a store that walked part of a chain, whose lighter
//                candidate's attempt completed (K_NCU ended), offers a heavier
//                tip whose server answers its catch-up from position 0 with no
//                header: J at that tip (C connects later; C's reply held);
//                a server that never answers: no pair, K_NCU ended;
//   catchctx     a caught-up store above position 0 whose catch-up step
//                stays deferred on a P_r no node serves past kCtxTtlMs: no
//                join pair;
//   floorpr      the floor reading of #9: a carrier on a P_r held without
//                its weights admitted; one above the floor DEFERs with no
//                context and passes on the exact weights; #12 stays exact;
//                a join replay on a band DEFER ends NotServed (no fetch, no
//                loop) and waits on the weights.
// Shards and their gather: pathb_kat_shard.hpp.
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
#include <cstring>
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
#include "c2pool/v37/xmr/pathb/pathb_status.hpp"
#include "pathb_kat_join.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_kat_shard.hpp"
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
    static std::uint64_t verify_calls(const PathbNode& n) { return n.verify_calls_; }
    // The work of the header comparison toward `peer`: its request in flight, or its paused comparison.
    static std::optional<::c2pool::xmr::native::U128> fold_work(const PathbNode& n, std::uint64_t peer) {
        if (const auto it = n.header_req_.find(peer); it != n.header_req_.end() && it->second.fold) return it->second.fold->work;
        if (const auto it = n.paused_.find(peer); it != n.paused_.end()) return it->second.work;
        return std::nullopt;
    }
    // The joiner excludes `server` (as an attempt ending Header does).
    static void exclude_server(PathbNode& n, std::uint64_t server) {
        AttemptQueue::Pair p;
        p.server = server;
        AttemptReport r;
        r.end = AttemptEnd::Header;
        r.server = server;
        (void)n.joiner_->apply(Joiner::Attempted{p, std::move(r)});
    }
    // The comparison of the request in flight to `peer` keeps no ids above F (the state of an F deep when fixed).
    static bool fold_forget_ids(PathbNode& n, std::uint64_t peer) {
        const auto it = n.header_req_.find(peer);
        if (it == n.header_req_.end() || !it->second.fold || !it->second.fold->fixed) return false;
        it->second.fold->keep_above = false;
        it->second.fold->above.clear();
        return true;
    }
    static std::uint64_t omissions(PathbNode& n, const AdmitResult& a) { return n.omissions_of(a); }
    // A frame parked through the node's own park as a DEFER of `cause` at `row` (`fetch`: the id it waits on).
    static void park(PathbNode& n, std::uint64_t peer, const std::vector<std::uint8_t>& frame, Missing cause, RowId row,
                     const Hash32& fetch = Hash32{}) {
        AdmitResult r;
        r.verdict = AdmitVerdict::Defer;
        r.row = row;
        r.missing = cause;
        r.fetch = fetch;
        n.park(peer, frame, r);
    }
    static bool amount_held(const PathbNode& n, const Hash32& tip, const Hash32& p_r) {
        return n.amounts_.count(std::make_pair(tip, p_r)) != 0;
    }
    // A body asked by a header page (FetchBodies) at time t.
    static void body_asked(PathbNode& n, const Hash32& id, std::uint64_t t) { n.bodies_asked_[id] = t; }
    static bool hf_live(const PathbNode& n) { return n.headers_first_live(); }
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
    check(h[lnode].switch_counts().carried >= 1 && h[lnode].repend_watch_size() == 0,
          "race: the losing node counts its re-pended receipt carried (" +
                  std::to_string(h[lnode].switch_counts().carried) + ") and watches none (" +
                  std::to_string(h[lnode].repend_watch_size()) + ")");
    // one Monero height between the switch and the carry: H(q) - H_s = 1
    const pb::PathbNode::SwitchCounts& sc = h[lnode].switch_counts();
    check(sc.carry_bins[0] == 0 && sc.carry_bins[1] == sc.carried && sc.carry_bins[2] == 0 && sc.carry_bins[3] == 0
                  && sc.carry_bins_max == 1 && sc.repend_skipped == 0,
          "race: the carried receipt counted 1 bin after the switch (carry-bins " + std::to_string(sc.carry_bins[0]) + "/" +
                  std::to_string(sc.carry_bins[1]) + "/" + std::to_string(sc.carry_bins[2]) + "/" +
                  std::to_string(sc.carry_bins[3]) + ", max " + std::to_string(sc.carry_bins_max) + ", skipped " +
                  std::to_string(sc.repend_skipped) + ")");
}

// ---------------------------------------------------------------------------
// racelate: the race of `race`, then the winner's next carrier at 2 Monero heights after the switch (it does not
// hold the losing receipt) and the losing node's carrier one height later carries it: H(q) - H_s = 3, the 3+ bucket.
void racelate() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(a, 1, 10 + i);
    }
    h.cut = {{a, b}, {b, a}};
    h.mine(a, 2, 900);
    h.mine(b, 3, 901);
    const pb::Hash32 ca = h[a].tree().best().id, cb = h[b].tree().best().id;
    h.cut.clear();
    (void)h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(cb), 16));
    (void)h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(ca), 16));
    h.pump();
    const pb::Hash32 loser = ca < cb ? cb : ca;
    const std::size_t lnode = ca < cb ? b : a, wnode = ca < cb ? a : b;
    const std::optional<std::uint64_t> H_s = h[lnode].best_record();
    const bool watched = h[lnode].pending().holds(loser) && h[lnode].repend_watch_size() == 1;
    h.tick_monero(2);
    const pb::NodeEventResult rw = h.mine(wnode, 4, 902);
    const bool not_carried = h[lnode].pending().holds(loser) && h[lnode].switch_counts().carried == 0;
    h.tick_monero();
    const pb::NodeEventResult rl = h.mine(lnode, 4, 903);
    const pb::LaneView v = h[wnode].store().view_at(h[wnode].tree().best().id);
    const std::optional<std::uint64_t> H_q = h[lnode].best_record();
    const pb::PathbNode::SwitchCounts& sc = h[lnode].switch_counts();
    check(watched && rw.action == pb::NodeAction::Placed && not_carried && rl.action == pb::NodeAction::Placed && v.ok()
                  && v.placed_open(loser) && H_s && H_q && *H_q == *H_s + 3,
          "racelate: the winner's carrier 2 heights after the switch leaves the losing receipt pending; the loser's next "
          "carries it (H_s " + std::to_string(H_s.value_or(0)) + ", H(q) " + std::to_string(H_q.value_or(0)) + ")");
    check(sc.carried == 1 && sc.carry_bins[0] == 0 && sc.carry_bins[1] == 0 && sc.carry_bins[2] == 0 && sc.carry_bins[3] == 1
                  && sc.carry_bins_max == 3,
          "racelate: carried 3 bins after the switch: the 3+ bucket (carry-bins " + std::to_string(sc.carry_bins[0]) + "/" +
                  std::to_string(sc.carry_bins[1]) + "/" + std::to_string(sc.carry_bins[2]) + "/" +
                  std::to_string(sc.carry_bins[3]) + ", max " + std::to_string(sc.carry_bins_max) + ")");
}

// ---------------------------------------------------------------------------
// raceskip: a sibling race on two Monero heights (each sibling on its own P_r); the losing sibling's P_r is no longer
// held when the loser switches (BadServed): the re-pend step skips its receipt: repend-skipped 1, re-pended 0, lost 0.
void raceskip() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(a, 1, 10 + i);
    }
    h.cut = {{a, b}, {b, a}};
    h.mine(a, 2, 900);
    h.tick_monero();
    h.mine(b, 3, 901);
    const pb::Hash32 ca = h[a].tree().best().id, cb = h[b].tree().best().id;
    h.cut.clear();
    const std::size_t lnode = ca < cb ? b : a, wnode = ca < cb ? a : b;
    const pb::Hash32 loser = ca < cb ? cb : ca, winner = ca < cb ? ca : cb;
    const pb::Hash32 pr_loser = h[lnode].bodies().get(loser)->own.blob.prev_id;
    const pb::Hash32 pr_winner = h[wnode].bodies().get(winner)->own.blob.prev_id;
    h.bad_served.insert(pr_loser);
    const pb::NodeEventResult sw = h[lnode].on_carrier(wnode, *pb::encode_fc_carrier(0, *h[wnode].bodies().get(winner), 16));
    const pb::PathbNode::SwitchCounts& sc = h[lnode].switch_counts();
    check(pr_loser != pr_winner && sw.action == pb::NodeAction::Switched && h[lnode].tree().best().id == winner,
          "raceskip: the siblings on two P_r; the loser switches to the winner");
    check(sc.repend_skipped == 1 && sc.repended == 0 && sc.lost == 0 && !h[lnode].pending().holds(loser),
          "raceskip: the losing receipt whose P_r is not held is skipped (repend-skipped " +
                  std::to_string(sc.repend_skipped) + ", re-pended " + std::to_string(sc.repended) + ", lost " +
                  std::to_string(sc.lost) + ")");
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
    const std::uint64_t foreign0 = h[a].amount_counts().foreign_carried;
    h[a].on_own_share(*j, 31, pb::Hash32{});
    check(foreign0 == 0 && h[a].amount_counts().foreign_carried == 16,
          "carriage: the 16 carried receipts of other payees counted foreign-carried (" +
                  std::to_string(h[a].amount_counts().foreign_carried) + ")");
    const std::optional<pb::PathbJob> j2 = h.job(a, 1, 32);
    check(j2 && j2->carried.size() == 1 && pb::receipt_id(j2->carried[0]) == all[16].second,
          "carriage: the remaining carriable receipt is carried by the next job (no omission)");
}

// ---------------------------------------------------------------------------
// feediverse: receipts on one (tip, P_r) admitted with their own R. Two shares of one R on one tip: no multi-fee key;
// two shares with different template fees on one tip: B admits both, one multi-fee key, r-min < r-max; once their
// origin bin seals at B's best tip the key is pruned.
pb::Hash32 share_id(const pb::PathbJob& j, std::uint32_t nonce) {
    pb::ReceiptBodyV3 r = j.body;
    r.blob.nonce = nonce;
    return pb::receipt_id(r);
}
void feediverse() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net));
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 20 + i);
    }
    // one R twice on one tip (the carrier that moves the tip on it too)
    h.txs.clear();
    const pb::Hash32 t1 = h[a].tree().best().id;
    const std::optional<pb::PathbJob> s1 = h.job(a, 2, 700), s2 = h.job(a, 3, 701);
    h.mine(a, 1, 702);
    const bool p1 = s1 && h[a].on_own_share(*s1, 700, pb::Hash32{}).action == pb::NodeAction::Pending;
    const bool p2 = s2 && h[a].on_own_share(*s2, 701, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.pump();
    const pb::PathbNode::AmountCounts c1 = h[b].amount_counts();
    check(p1 && p2 && h[b].pending().holds(share_id(*s1, 700)) && h[b].pending().holds(share_id(*s2, 701))
                  && s1->body.reward_total == s2->body.reward_total && c1.multi_fee == 0 && c1.keys >= 1
                  && pb::PathbNodeTestAccess::amount_held(h[b], t1, s1->body.blob.prev_id),
          "feediverse: two receipts of one R on one tip admitted by B: no multi-fee key (multi-fee " +
                  std::to_string(c1.multi_fee) + ", keys " + std::to_string(c1.keys) + ")");
    // two template fees on one tip
    const pb::Hash32 t2 = h[a].tree().best().id;
    h.txs = {{seq32(0xE1), 2000, 3000000}};
    const std::optional<pb::PathbJob> f1 = h.job(a, 4, 710);
    h.txs = {{seq32(0xE2), 1500, 7000000}};
    const std::optional<pb::PathbJob> f2 = h.job(a, 5, 711);
    h.txs.clear();
    h.mine(a, 1, 712);
    const bool q1 = f1 && h[a].on_own_share(*f1, 710, pb::Hash32{}).action == pb::NodeAction::Pending;
    const bool q2 = f2 && h[a].on_own_share(*f2, 711, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.pump();
    const pb::PathbNode::AmountCounts c2 = h[b].amount_counts();
    const std::uint64_t R1 = f1 ? f1->body.reward_total : 0, R2 = f2 ? f2->body.reward_total : 0;
    check(q1 && q2 && f1->tip == t2 && f2->tip == t2 && f1->body.blob.prev_id == f2->body.blob.prev_id
                  && R2 == R1 + 4000000 && h[b].pending().holds(share_id(*f1, 710)) && h[b].pending().holds(share_id(*f2, 711))
                  && c2.multi_fee == 1 && c2.r_min < c2.r_max && c2.r_min == s1->body.reward_total && c2.r_max == R2,
          "feediverse: two template fees on one tip (R " + std::to_string(R1) + ", " + std::to_string(R2) +
                  ") admitted by B with their own R: one multi-fee key (" + std::to_string(c2.multi_fee) + "), r-min " +
                  std::to_string(c2.r_min) + " < r-max " + std::to_string(c2.r_max));
    // the chain moves past their origin bin: the key is pruned at B
    const std::optional<std::uint64_t> origin = f1 ? h[b].receipt_origin(f1->body) : std::nullopt;
    const std::uint64_t F = h[b].config().p.open_bins;
    bool held_open = true;
    for (int i = 0; origin && i < 80; ++i) {
        const std::optional<std::uint64_t> H = h[b].best_record();
        if (H && *H >= *origin + F) break;
        held_open = held_open && pb::PathbNodeTestAccess::amount_held(h[b], t2, f1->body.blob.prev_id);
        h.tick_monero(h[b].config().p.fresh_max);
        h.mine(a, 1, 720 + static_cast<std::uint32_t>(i));
    }
    const std::optional<std::uint64_t> H = h[b].best_record();
    const pb::PathbNode::AmountCounts c3 = h[b].amount_counts();
    check(origin && H && *H >= *origin + F && held_open && !pb::PathbNodeTestAccess::amount_held(h[b], t2, f1->body.blob.prev_id)
                  && !pb::PathbNodeTestAccess::amount_held(h[b], t1, s1->body.blob.prev_id) && c3.multi_fee == 1
                  && c3.keys >= 1,
          "feediverse: the key held while its origin bin " + std::to_string(origin.value_or(0)) +
                  " is open, pruned once it seals at B (H(L) " + std::to_string(H.value_or(0)) + ", keys " +
                  std::to_string(c3.keys) + ")");
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
        // an FC_HEADERS reply above the buffer: DROP, no token (the request ends: one frame, one request); one that does
        // not decode: refuse + 1 strike (the request ends); then none open: DROP
        check(h[b].request_headers(a, h[b].tree().genesis().id, h[a].tree().best().id, 8, h.now) || true, "tokens: a request");
        std::vector<std::uint8_t> bigh(h[b].frame_bytes_headers() + 1, 0x53);
        const pb::PathbNode::HeadersOutcome o1 = h[b].on_headers(a, bigh, h.now);
        const bool again = h[b].request_headers(a, h[b].tree().genesis().id, h[a].tree().best().id, 8, h.now);
        const std::vector<std::uint8_t> badh{0x53, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        const pb::PathbNode::HeadersOutcome o2 = h[b].on_headers(a, badh, h.now);
        const pb::PathbNode::HeadersOutcome o3 = h[b].on_headers(a, badh, h.now);
        check(o1.kind == pb::PathbNode::HeadersOutcome::Kind::OverBuffer && again
                      && o2.kind == pb::PathbNode::HeadersOutcome::Kind::Undecodable
                      && o3.kind == pb::PathbNode::HeadersOutcome::Kind::Unsolicited,
              "tokens: FC_HEADERS above the buffer DROP (the request ends); asked again, undecodable: STRIKE (request ended); "
              "then none open: DROP");
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
        // E-197: max bounds one request, not the comparison: a page of max headers that ends before `stop` continues
        Harness h(net);
        h.headers_frame = 1500;
        const Split s = split(h);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "receive: A asks B for at most 3");
        const pb::PathbNode::HeadersOutcome o = h[s.a].on_headers(s.b, serve_front(h, s).at(0), h.now);
        pb::GetHeaders q;
        const bool next = h.q.size() == 1 && h.q.front().to == s.b && pb::decode_fc_getheaders(h.q.front().frame, 0, q).ok()
                          && q.from == s.b_ids[2] && q.stop == s.b_tip && q.max == 3;
        check(o.kind == pb::PathbNode::HeadersOutcome::Kind::Continue && o.indexed == 3 && next,
              "receive: 3 headers at max 3, last header not stop: Continue, the next request from the third header with "
              "max 3 (kind " + std::to_string(static_cast<int>(o.kind)) + ")");
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
    bool full_next = false;   // the next send finds the link's queue full: the link dropped, counted
    std::uint64_t full_drops = 0;
    std::uint64_t queue_full_drops() const override { return full_drops; }
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
    // A link's id at node `at` for node `from`: from + 1 on the first link, + 100 per reconnect (link ids not reused).
    std::map<std::pair<std::size_t, std::size_t>, std::uint64_t> epoch;
    std::uint64_t id(std::size_t at, std::size_t from) const {
        const auto it = epoch.find({at, from});
        return from + 1 + 100 * (it == epoch.end() ? 0 : it->second);
    }
    static std::size_t node_of(std::uint64_t p) { return static_cast<std::size_t>((p - 1) % 100); }
    // Delivers one frame, then runs what every relay has queued; false: nothing to deliver.
    bool step() {
        if (q.empty()) return false;
        Msg m = std::move(q.front());
        q.pop_front();
        if (edit) edit(m);
        if (!m.f.empty() && links[m.to]->live.count(id(m.to, m.from)) != 0) links[m.to]->frame(id(m.to, m.from), m.f);
        for (pb::PathbRelayNode* r : relays) r->pump();
        return true;
    }
    void run() {
        for (pb::PathbRelayNode* r : relays) r->pump();
        while (step()) {
        }
    }
    void connect(std::size_t a, std::size_t b) {
        links[a]->live.insert(id(a, b));
        links[b]->live.insert(id(b, a));
        links[a]->event(id(a, b), true);
        links[b]->event(id(b, a), true);
    }
    // A new link between a and b (new ids at both ends); the old one must be down.
    void reconnect(std::size_t a, std::size_t b) {
        ++epoch[{a, b}];
        ++epoch[{b, a}];
        connect(a, b);
    }
};

bool FakeLinks::send_to(std::uint64_t p, const std::vector<std::uint8_t>& f) {
    if (live.count(p) == 0) return false;
    if (full_next) {
        full_next = false;
        ++full_drops;
        disconnect(p);
        return false;
    }
    const std::lock_guard<std::mutex> lk(wire->qm);
    wire->q.push_back(FakeWire::Msg{self, FakeWire::node_of(p), f});
    return true;
}
void FakeLinks::disconnect(std::uint64_t p) {
    if (live.erase(p) == 0) return;
    FakeLinks& o = *wire->links[FakeWire::node_of(p)];
    const std::uint64_t back = wire->id(o.self, self);
    o.live.erase(back);
    event(p, false);
    o.event(back, false);
}

// The relays' log lines by node, while a vector sets it (kat_relay's log sink).
std::map<std::size_t, std::vector<std::string>>* g_relay_lines = nullptr;

struct KatRelay {
    std::unique_ptr<FakeLinks> links;
    std::unique_ptr<pb::PathbRelayNode> relay;
    std::size_t node = 0;
};

// A relay node in manual mode on the harness's clock with its own PathbNode (a load failure when `failed`;
// `tweak`: its options changed; `cfg_tweak`: its node's configuration; `io_tweak`: its node's I/O; `persist`: an empty
// store of its own in h.kvs).
KatRelay kat_relay(Harness& h, FakeWire& w, const pb::EpochTable& T, bool launch, bool failed = false,
                   const std::function<void(pb::PathbRelayOptions&)>& tweak = nullptr,
                   const std::function<void(pb::PathbNodeConfig&)>& cfg_tweak = nullptr,
                   const std::function<void(pb::PathbNodeIo&)>& io_tweak = nullptr, bool persist = false) {
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
    k.relay = std::make_unique<pb::PathbRelayNode>(o, *k.links, clock, [n = h.nodes.size()](const std::string& line) {
        if (g_relay_lines != nullptr) (*g_relay_lines)[n].push_back(line);
    });
    k.node = h.nodes.size();
    pb::PathbNodeIo io = k.relay->bind_io(h.io(k.node));
    if (io_tweak) io_tweak(io);
    pb::PathbNodeConfig cfg = h.config(T, launch);
    if (cfg_tweak) cfg_tweak(cfg);
    if (failed) {
        h.kvs.push_back(std::make_unique<MemoryKv>());
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, std::move(io), h.kvs.back().get(), pb::PathbNode::LoadFailed{}));
    } else if (persist) {
        h.kvs.push_back(std::make_unique<MemoryKv>());
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, std::move(io), h.kvs.back().get()));
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
    // FC_HEADERS from an asked server (one frame answers one request)
    const auto ask = [&] {
        const bool ok = rb.with_node([&](pb::PathbNode& n) { return n.request_headers(pa, n.tree().genesis().id, tip_a, 8, h.now); });
        w.q.clear();  // A's own reply is not delivered
        return ok;
    };
    const bool asked = ask();
    const auto ho = tok(big(pb::kOpFcHeaders, 0x02, h[b.node].frame_bytes_headers() + 1));
    const bool asked2 = ask();
    const auto hu = tok({pb::kOpFcHeaders, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    check(asked && asked2 && ho.first == 0 && ho.second == 1 && hu.first == 1 && hu.second == 0,
          "relaytok: 0x53 from an asked server: above the buffer DROP, no token; asked again, one that does not decode: "
          "1 strike (" + std::to_string(hu.first) + ")");
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
        // an old node's HELLO of 102 B: 0x40 | frame version 0x01 | magic 'C2XR' | network 3 | 95 zero bytes
        std::vector<std::uint8_t> f = {0x40, 0x01, 'C', '2', 'X', 'R', 3};
        f.resize(102, 0);
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
    check(r.floors_set && r.floors.sides == 0, "prune young: the report carries the floors it computed (floors.sides 0)");
    // a node after a load failure prunes nothing and computes no floors (the daemon prints its last computed ones)
    h.kvs.push_back(std::make_unique<MemoryKv>());
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(kat_table(c.net), false, kPruneJ), h.io(h.nodes.size()),
                                                      h.kvs.back().get(), pb::PathbNode::LoadFailed{}));
    const pb::PathbNode::PruneReport rf = h.nodes.back()->prune(h.now);
    check(!rf.floors_set && !rf.written, "prune young: after a load failure no floors are computed (floors_set 0)");
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
    check(r.floors_set && r.floors.sides == w.sides && r.floors.bodies == w.bodies && w.sides > 0,
          "prune default: the report carries the floors it applied (floors.sides " + std::to_string(r.floors.sides) +
                  ", floors.bodies " + std::to_string(r.floors.bodies) + ")");
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
// sideprune: K_PSIDE at the prune. The prune chain's three side carriers (forking at the body floor - 1, at it, above
// it) written as K_PSIDE rows, and two rows that do not place (another id beside a body): one at a position above the
// floor, one below it; the node loaded from that store holds the three; its prune at floors.sides deletes the row of
// the branch forking below the floor and the row below the floor, and keeps the other three; restarted, it holds the
// two side carriers at and above the floor only.
void sideprune() {
    PruneChain& c = prune_chain();
    Harness h(c.net);
    MemoryKv src = c.sn->kv;
    {
        pb::LaneBatch b;
        bool put = true;
        for (const pb::Hash32& id : {c.side_at, c.side_below, c.side_above})
            put = put && pb::put_side(b, 0, c.sn->n.tree, c.sn->n.store, c.sn->n.bodies, id);
        check(put && pb::commit_lane_batch(src, b), "sideprune: the three K_PSIDE rows written");
    }
    pb::Hash32 above_id{}, below_id{};
    above_id[0] = 0xa1;
    below_id[0] = 0xb1;
    {
        std::optional<pb::CarrierRecord> r = pb::decode_pside(src.data.at(pb::store_keys::pside(0, c.side_above)));
        check(r.has_value(), "sideprune: a K_PSIDE row decodes");
        if (!r) return;
        pb::LaneBatch b;
        r->id = above_id;
        r->pos = c.fb + 2;
        b.put(pb::store_keys::pside(0, above_id), pb::encode_pside(*r));
        r->id = below_id;
        r->pos = c.fb - 5;
        b.put(pb::store_keys::pside(0, below_id), pb::encode_pside(*r));
        check(pb::commit_lane_batch(src, b), "sideprune: two rows that do not place written");
    }
    const std::size_t a = load_node(h, src, h.config(kat_table(c.net), true, kPruneJ));
    MemoryKv& kv = *h.kvs.back();
    bool held = true;
    for (const pb::Hash32& id : {c.side_at, c.side_below, c.side_above})
        held = held && h[a].tree().find(id) != nullptr && h[a].bodies().get(id) != nullptr;
    check(held, "sideprune: the loaded node holds the three side carriers with their bodies (K_PSIDE)");
    const pb::PathbNode::PruneReport r = h[a].prune(h.now);
    check(r.written && r.floors.sides == c.fb && kv.data.count(pb::store_keys::pside(0, c.side_below)) == 0
                  && kv.data.count(pb::store_keys::pside(0, c.side_at)) == 1
                  && kv.data.count(pb::store_keys::pside(0, c.side_above)) == 1
                  && kv.data.count(pb::store_keys::pside(0, above_id)) == 1
                  && kv.data.count(pb::store_keys::pside(0, below_id)) == 0,
          "sideprune: the prune at floors.sides " + std::to_string(r.floors.sides) +
                  " deletes the row of the branch forking below it and the row below it; keeps the rows at and above "
                  "it (one that did not place)");
    pb::StoreFault f = pb::StoreFault::None;
    const std::size_t b = reload_node(h, kv, kPruneJ, &f);
    check(f == pb::StoreFault::None && b != SIZE_MAX && h[b].tree().find(c.side_at) != nullptr
                  && h[b].tree().find(c.side_above) != nullptr && h[b].tree().find(c.side_below) == nullptr,
          "sideprune: restarted, the side carriers forking at and above the floor are held, none below it");
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
// below: a full node holding its chain from position 0 offers no candidate on a HELLO; once it pruned (no joined x1) it
// offers none either; its catch-up's reply with no header from its root offers B's tip as a root-evidence pair: the
// fork (200) lies below its first retained record, so the candidate is in scope, the attempt completes and rule (4)
// replaces A.
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
    check(h[fa].joiner().queue().size() == 0, "below: a pruned full node offers no candidate on a HELLO");
    const bool offered = h[fa].offer_empty_store_tip(fbn, /*root_evidence=*/true);
    check(offered && h[fa].joiner().queue().size() == 1 && h[fa].joiner().queue().pairs().front().root_evidence,
          "below: the root-evidence offer: B's tip, forking below what A holds, is a candidate");
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
                  js.rebuild_blob(tid, 7, rebuilt) && rebuilt.blob == out.blob && rebuilt.withdrawn && !out.withdrawn,
          "deferfound: after a DEFER the job stays for a found block (network_job, rebuild_blob flags it withdrawn: a "
          "share on it is stale at stratum) and is stale for own shares");
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
// blockblob: the block blob of a Path B job, as the job source builds it (the header through the nonce, the miner tx
// prefix and its RCTTypeNull byte, varint(n), the transaction ids), pinned by length and keccak256 for four jobs on a
// window of three payees. V37_PATHB_BLOB_GOLDEN_PRINT=1 prints the values.
struct BlobGolden {
    const char* name;
    std::size_t len;
    const char* keccak;
};
const BlobGolden kBlobGoldens[] = {
        {"empty", 291, "9f6134c3b6179437aed084eb9a7490e9b77429ad222150e86c0ec8aa20d4d7de"},     // n_tx 0
        {"typical", 675, "49be1bf41e5a56ed759916e44fa90ea51896a82403ec18f711db8e2fa079e7a5"},   // n_tx 12
        {"nearcap", 4420, "e19f65a2734aeaa7ea215c47e379bd4bbfe7b9d7ee1595f93d5b0bc4ef258703"},  // n_tx 129, 299,951 B
        {"carried", 451, "27c00800e6a18f2ee1994ed2dc8e36a75d29b29eb8fbda93354a1d977dd74042"},   // n_tx 5, 16 carried
};

std::string hex_of_bytes(const std::uint8_t* p, std::size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(k[p[i] >> 4]);
        s.push_back(k[p[i] & 15]);
    }
    return s;
}

std::vector<pb::TemplateTx> blob_txs(std::size_t n, std::uint64_t w0, std::uint64_t dw, std::uint8_t salt) {
    std::vector<pb::TemplateTx> v;
    for (std::size_t k = 0; k < n; ++k) {
        pb::TemplateTx t;
        t.hash = seq32(static_cast<std::uint8_t>(salt + k));
        t.hash[31] = static_cast<std::uint8_t>(k >> 8);
        t.hash[30] = static_cast<std::uint8_t>(k);
        t.weight = w0 + (k * dw) % 2048;
        t.fee = 30000000 + 7919 * k;
        v.push_back(t);
    }
    return v;
}

void blockblob() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(a, 1 + i % 3, 70 + i);
    }
    struct Got {
        std::vector<std::uint8_t> blob;
        std::size_t n_tx = 0;
        std::uint64_t w_tx = 0;
        std::size_t cw = 0;
        std::size_t carried = 0;
        std::size_t outs = 0;
        bool window_values = false;  // the issued job's N, f_spend, B, Z are the template window's
        std::uint64_t n_rule = 0, f_spend = 0, min_out = 0;
    };
    auto blob_of = [&](std::size_t payee, std::uint32_t en) {
        Got g;
        pb::PathbJobSource js([&](const pb::PathbTemplate& t, const pb::PathbSession& ss) { return h[a].make_job(t, ss); });
        const pb::PathbTemplate t = h[a].make_template(h.now);
        if (t.status != pb::TemplateStatus::Ok) return g;
        const std::uint32_t tid = js.set_template(t, pb::JobNetwork{});
        js.bind(en, h.session(payee, en));
        ::v37::xmr::stratum::TemplateJob out;
        if (!js.get_job(en, out)) return g;
        const std::optional<pb::IssuedJob> ij = js.issued(tid, en);
        if (!ij) return g;
        g.blob = ij->block_blob;
        g.n_tx = t.txs.size();
        for (const pb::TemplateTx& x : t.txs) g.w_tx += x.weight;
        g.cw = ij->job.miner_tx.prefix.size() + 1;
        g.carried = ij->job.carried.size();
        g.outs = ij->job.miner_tx.outs.size();
        const pb::WindowParams wp = pb::window_params(t.window.inputs, t.window.v, pb::Hash32{});
        g.window_values = ij->n_rule == wp.N && ij->f_spend == wp.f_spend && ij->base == wp.B
                          && ij->zone == t.window.inputs.weights.zone && ij->n_rule >= 1 && ij->f_spend > 0 && ij->base > 0
                          && ij->zone > 0;
        g.n_rule = ij->n_rule;
        g.f_spend = ij->f_spend;
        g.min_out = UINT64_MAX;
        for (const pb::MinerOut& o : ij->job.miner_tx.outs) g.min_out = std::min(g.min_out, o.amount);
        return g;
    };
    std::vector<std::pair<std::string, Got>> got;
    h.txs.clear();
    got.emplace_back("empty", blob_of(1, 11));
    h.txs = blob_txs(12, 1500, 173, 0x40);
    got.emplace_back("typical", blob_of(2, 12));
    h.txs = blob_txs(240, 1400, 37, 0x60);
    got.emplace_back("nearcap", blob_of(3, 13));
    h.txs.clear();
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 17; ++k) jobs.push_back(*h.job(a, k + 2, 600 + k));
    h.mine(a, 1, 90);
    for (std::uint32_t k = 0; k < 17; ++k) (void)h[a].on_own_share(jobs[k], 600 + k, pb::Hash32{});
    h.txs = blob_txs(5, 2000, 311, 0x80);
    got.emplace_back("carried", blob_of(1, 14));

    const bool print = std::getenv("V37_PATHB_BLOB_GOLDEN_PRINT") != nullptr;
    const std::uint64_t z = 300000;
    for (std::size_t i = 0; i < got.size(); ++i) {
        const Got& g = got[i].second;
        const pb::Hash32 k = pb::keccak256_hash(g.blob);
        const std::string kh = hex_of_bytes(k.data(), k.size());
        if (print)
            std::printf("        {\"%s\", %zu, \"%s\"},   // n_tx %zu, w_tx %llu, cw %zu, outs %zu, carried %zu\n",
                        got[i].first.c_str(), g.blob.size(), kh.c_str(), g.n_tx, (unsigned long long)g.w_tx, g.cw,
                        g.outs, g.carried);
        const BlobGolden& gd = kBlobGoldens[i];
        check(!g.blob.empty() && got[i].first == gd.name && g.blob.size() == gd.len && kh == gd.keccak,
              std::string("blockblob: ") + gd.name + ": the job's block blob (" + std::to_string(g.blob.size()) +
                      " B, n_tx " + std::to_string(g.n_tx) + ") equals the pinned bytes");
    }
    check(got[0].second.n_tx == 0 && got[1].second.n_tx == 12, "blockblob: the empty and the typical job hold 0 and 12 transactions");
    const Got& nc = got[2].second;
    check(nc.n_tx > 0 && nc.n_tx < 240 && nc.w_tx + nc.cw <= z && z - (nc.w_tx + nc.cw) < 1400 + 2048,
          "blockblob: the near-cap job is filled to within one candidate of Z = 300,000 (" +
                  std::to_string(nc.w_tx + nc.cw) + " B)");
    check(got[3].second.carried == 16 && got[3].second.outs >= 3,
          "blockblob: the carried job carries 16 receipts on a window of " + std::to_string(got[3].second.outs) + " outputs");
    for (const auto& [name, g] : got)
        check(g.window_values && g.outs <= g.n_rule && g.min_out >= g.f_spend,
              "blockblob: " + name + ": the issued job holds its window's N(B) " + std::to_string(g.n_rule) +
                      ", f_spend " + std::to_string(g.f_spend) + ", B and Z; outputs " + std::to_string(g.outs) +
                      " <= N, the least " + std::to_string(g.min_out) + " >= f_spend");
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
    r.test_parked(1, pb::Missing::MoneroBlock, seq32(0x63), mon_block(kPoolH));  // a P_r the follower resolves
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
// The drain's tokens and bans: A mines c1 and c2 (c2 carries two receipts) while B gets neither; c2 reaches B first and
// is parked on its unknown parent; B fetches c1 from A and places it; the drain runs c2. kind 0: c2 as mined; 1: c2's
// own PoW fails at B; 2: c2's carried list out of order.
struct DrainRun {
    bool setup = false;           // c2 parked at B before c1 (c1 and c2 not placed there)
    bool c1 = false, c2 = false;  // placed at B at the end
    bool a_up = false;            // A's link at B up at the end
    std::uint64_t strikes = 0, strikes_a = 0, bans = 0;  // rises at B: strikes, A's strikes, bans
    std::size_t want_lines = 0, banned_lines = 0;        // B's lines equal to `want`, B's BANNED lines
    std::string want;
};
DrainRun drain_run(int kind) {
    const KatNet net;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    DrainRun out;
    bool ok = mine_on(h, w, a.node, 1, 830);
    const std::optional<pb::PathbJob> j1 = h.job(a.node, 2, 831), j2 = h.job(a.node, 3, 832);
    w.edit = [](FakeWire::Msg& m) {  // A's frames do not reach B
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && j1 && j2 && mine_on(h, w, a.node, 1, 840);  // c1
    const pb::Hash32 c1 = h[a.node].tree().best().id;
    ok = ok && h[a.node].on_own_share(*j1, 831, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[a.node].on_own_share(*j2, 832, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && mine_on(h, w, a.node, 1, 850);  // c2 carries both
    const pb::Hash32 c2 = h[a.node].tree().best().id;
    pb::CarrierBodyV3 body = *h[a.node].bodies().get(c2);
    ok = ok && body.carried.size() == 2 && h[b.node].tree().find(c1) == nullptr && pb::receipt_id(body.own) == c2;
    if (kind == 2 && body.carried.size() == 2) std::swap(body.carried[0], body.carried[1]);
    if (kind == 1) h.bad_pow.insert(c2);
    w.run();
    w.edit = nullptr;
    pb::PathbRelayNode& rb = *b.relay;
    const pb::PathbRelayStats& st = rb.stats();
    const std::uint64_t s0 = st.strikes.load(), sa0 = rb.strikes_of(1), b0 = st.bans.load();
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, body, 16)});
    w.step();  // c2 at B: parked; B's FC_GETCARRIER of c1 queued to A
    out.setup = ok && h[b.node].deferred().size() == 1 && h[b.node].tree().find(c1) == nullptr
                && h[b.node].tree().find(c2) == nullptr;
    w.run();
    for (int i = 0; i < 4 && h[b.node].tree().find(c1) == nullptr; ++i) {
        h.now += 1;
        rb.tick();
        w.run();
    }
    g_relay_lines = nullptr;
    out.c1 = h[b.node].tree().find(c1) != nullptr;
    out.c2 = h[b.node].tree().find(c2) != nullptr;
    out.a_up = rb.hello_ok(1);
    out.strikes = st.strikes.load() - s0;
    out.strikes_a = out.a_up ? rb.strikes_of(1) - sa0 : 0;
    out.bans = st.bans.load() - b0;
    out.want = kind == 1 ? "relay: peer 1 BANNED: admission row R12 of " + hex(c2.data(), 6) : std::string();
    for (const std::string& l : lines[b.node]) {
        out.want_lines += !out.want.empty() && l == out.want ? 1 : 0;
        out.banned_lines += l.find(" BANNED") != std::string::npos ? 1 : 0;
    }
    std::printf("  drain kind %d: setup %d, c1 at B %d, c2 at B %d, A up %d, strikes %llu (A %llu), bans %llu, lines %zu, "
                "BANNED lines %zu\n",
                kind, out.setup ? 1 : 0, out.c1 ? 1 : 0, out.c2 ? 1 : 0, out.a_up ? 1 : 0,
                (unsigned long long)out.strikes, (unsigned long long)out.strikes_a, (unsigned long long)out.bans,
                out.want_lines, out.banned_lines);
    return out;
}

// drainban: c2's own PoW fails at B (R12, BAN): B bans A with its reason (one BANNED line naming R12 and c2's id) and
// drops A's link; no strike.
void drainban() {
    const DrainRun r = drain_run(1);
    check(r.setup && r.c1 && !r.c2,
          "drainban: c2 parked on its unknown parent at B, c1 fetched from A and placed, c2 not placed");
    check(r.bans == 1 && r.want_lines == 1 && r.banned_lines == 1 && !r.a_up && r.strikes == 0,
          "drainban: the drained c2's BAN bans its sender: one line '" + r.want + "', A's link dropped, no strike (bans " +
                  std::to_string(r.bans) + ", lines " + std::to_string(r.want_lines) + ")");
}

// drainstrike: c2's carried list out of order (R28, STRIKE): one token of A's budget at B; no ban, A's link kept.
void drainstrike() {
    const DrainRun r = drain_run(2);
    check(r.setup && r.c1 && !r.c2,
          "drainstrike: c2 parked on its unknown parent at B, c1 fetched from A and placed, c2 not placed");
    check(r.strikes == 1 && r.strikes_a == 1 && r.bans == 0 && r.banned_lines == 0 && r.a_up,
          "drainstrike: the drained c2's STRIKE costs its sender one token: A struck once, no ban, A's link kept (strikes " +
                  std::to_string(r.strikes) + ", bans " + std::to_string(r.bans) + ")");
}

// drainhonest: c2 as mined: placed by the drain; no strike, no ban, A's link kept.
void drainhonest() {
    const DrainRun r = drain_run(0);
    check(r.setup && r.c1 && r.c2 && r.a_up && r.strikes == 0 && r.bans == 0 && r.banned_lines == 0,
          "drainhonest: c2 parked, released by c1's placement and placed: no strike, no ban, A's link kept (strikes " +
                  std::to_string(r.strikes) + ", bans " + std::to_string(r.bans) + ")");
}

// draingone: c2 (its own PoW failing at B) from A is parked at B; A's link at B goes down; B connects to C, which holds
// c1 and not c2, catches up and places c1; the drained c2's BAN names a gone link: one line, no ban applied, C's link
// kept.
void draingone() {
    const KatNet net;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    KatRelay c = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.connect(0, 2);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 860);
    w.edit = [](FakeWire::Msg& m) {  // A's frames do not reach B
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && mine_on(h, w, a.node, 1, 861);  // c1: at C, not at B
    const pb::Hash32 c1 = h[a.node].tree().best().id;
    w.edit = [](FakeWire::Msg& m) {  // nor C
        if (m.from == 0) m.f.clear();
    };
    ok = ok && mine_on(h, w, a.node, 1, 862);  // c2: at A only
    const pb::Hash32 c2 = h[a.node].tree().best().id;
    const std::vector<std::uint8_t> f2 = *pb::encode_fc_carrier(0, *h[a.node].bodies().get(c2), 16);
    h.bad_pow.insert(c2);
    w.run();
    ok = ok && h[c.node].tree().find(c1) != nullptr && h[c.node].tree().find(c2) == nullptr
         && h[b.node].tree().find(c1) == nullptr;
    w.edit = [&f2](FakeWire::Msg& m) {  // of A's frames only c2's reaches B (B's ask of c1 gets no reply)
        if (m.from == 0 && m.f != f2) m.f.clear();
    };
    pb::PathbRelayNode& rb = *b.relay;
    const pb::PathbRelayStats& st = rb.stats();
    const std::uint64_t s0 = st.strikes.load(), b0 = st.bans.load();
    w.q.push_back(FakeWire::Msg{0, 1, f2});
    w.run();
    const bool parked = h[b.node].deferred().size() == 1 && h[b.node].tree().find(c1) == nullptr
                        && h[b.node].tree().find(c2) == nullptr;
    b.links->disconnect(1);  // A's link at B down
    w.run();
    const bool gone = !rb.hello_ok(1) && h[b.node].deferred().size() == 1;
    w.connect(1, 2);  // B and C
    w.run();
    for (int i = 0; i < 4 && h[b.node].tree().find(c1) == nullptr; ++i) {
        h.now += 1;
        rb.tick();
        w.run();
    }
    g_relay_lines = nullptr;
    const std::string want = "relay: peer 1 gone: drained BAN not applied: admission row R12 of " + hex(c2.data(), 6);
    std::size_t got = 0, banned = 0;
    for (const std::string& l : lines[b.node]) {
        got += l == want ? 1 : 0;
        banned += l.find(" BANNED") != std::string::npos ? 1 : 0;
    }
    const bool c1b = h[b.node].tree().find(c1) != nullptr, c2b = h[b.node].tree().find(c2) != nullptr;
    std::printf("  draingone: setup %d, parked %d, gone %d, c1 at B %d, c2 at B %d, C up %d, strikes %llu, bans %llu, "
                "lines %zu, BANNED lines %zu\n",
                ok ? 1 : 0, parked ? 1 : 0, gone ? 1 : 0, c1b ? 1 : 0, c2b ? 1 : 0, rb.hello_ok(3) ? 1 : 0,
                (unsigned long long)(st.strikes.load() - s0), (unsigned long long)(st.bans.load() - b0), got, banned);
    check(ok && parked && gone && c1b && !c2b && rb.hello_ok(3),
          "draingone: c2 parked at B from A, A's link down, c1 from C placed, c2 not placed, C's link kept");
    check(got == 1 && banned == 0 && st.bans.load() == b0 && st.strikes.load() == s0,
          "draingone: the drained c2's BAN of a gone link: one line '" + want + "', no ban applied, no strike");
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
// hdrnohash: the header path through the binary's verify (verify_rx_at_d). RandomX computes no hash on a header (the
// seed's cache not built): RandomxFailure with its reason, no outcome (no BAN), nothing indexed, the failure not
// memoised; asked again: FetchBodies, J at S's tip. A hash computed that does not meet d on the same header: BAN,
// its reason S1.3 #11.
void hdrnohash() {
    const KatNet net;
    using K = pb::PathbNode::HeadersOutcome::Kind;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    const std::size_t j = h.add(table0(net), false);
    const std::size_t k = h.add(table0(net), false);
    h.cut = {{s, j}, {j, s}, {s, k}, {k, s}, {j, k}, {k, j}};
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 760 + static_cast<std::uint32_t>(i));
    }
    h.cut = {{s, k}, {k, s}, {j, k}, {k, j}};
    h.q.clear();
    const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id, armed = *h[s].store().best_at(3);
    h.nohash_pow.insert(armed);
    check(h[j].request_headers(s, g, tip, 64, h.now), "hdrnohash: R1");
    std::optional<pb::PathbNode::HeadersOutcome> o1;
    std::string what;
    bool typed = false;
    try {
        o1 = h[j].on_headers(s, h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0), h.now);
    } catch (const pb::RandomxFailure& e) {
        typed = true;
        what = e.what();
    } catch (const std::exception& e) {
        what = e.what();
    }
    h.q.clear();
    std::printf("  hdrnohash: outcome %s (kind %d), failure '%s', hashes not computed %llu, indexed %zu\n",
                o1 ? "returned" : "none", o1 ? static_cast<int>(o1->kind) : -1, what.c_str(),
                (unsigned long long)h.nohash_calls, pb::PathbNodeTestAccess::headers(h[j]).size());
    check(!o1 && typed && h.nohash_calls == 1 && h.nohash_pow.empty()
                  && what.find("RandomX computed no hash: kat: the seed cache could not be built") != std::string::npos
                  && pb::PathbNodeTestAccess::headers(h[j]).size() == 0,
          "hdrnohash: RandomX computed no hash on a header: RandomxFailure with its reason, no outcome (no BAN), "
          "nothing indexed");
    check(h[j].request_headers(s, g, tip, 64, h.now), "hdrnohash: asked again (the request slot free)");
    const pb::PathbNode::HeadersOutcome o2 =
            h[j].on_headers(s, h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0), h.now);
    check(o2.kind == K::FetchBodies,
          "hdrnohash: then FetchBodies (the failure not memoised; kind " + std::to_string(static_cast<int>(o2.kind)) + ")");
    h.pump();
    check(h[j].tree().best().id == tip, "hdrnohash: J at S's tip");
    // the same header, a hash computed that does not meet d: BAN, the reason S1.3 #11
    h.low_pow.insert(armed);
    check(h[k].request_headers(s, g, tip, 64, h.now), "hdrnohash: K's R1");
    std::optional<pb::PathbNode::HeadersOutcome> o3;
    std::string what3;
    try {
        o3 = h[k].on_headers(s, h[s].serve_getheaders(k, h.q.back().frame, h.now).frames.at(0), h.now);
    } catch (const std::exception& e) {
        what3 = e.what();
    }
    h.q.clear();
    check(o3 && o3->kind == K::Ban && o3->why.find("S1.3 #11 PoW below d") != std::string::npos
                  && pb::PathbNodeTestAccess::headers(h[k]).size() == 0,
          "hdrnohash: a hash computed not meeting d on that header: BAN, its reason S1.3 #11 ("
                  + (o3 ? o3->why : "no outcome: " + what3) + ")");
}

// ---------------------------------------------------------------------------
// relayrxnohash: the same through the relay node and the binary's verify (verify_rx_at_d). (a) RandomX computes no
// hash on a catch-up header: one RandomX failure, no token, no ban; the line names the peer and the reason; the
// catch-up asks again and B reaches A's tip. (b) A hash computed that does not meet d on that header: one BAN, its
// BANNED line names S1.3 #11. (c) RandomX computes no hash on a relayed carrier's admission: no token, no ban; the
// alarm names the reason; parked and run again: placed. (d) A hash computed that does not meet d on a relayed
// carrier: one BAN, its BANNED line names the admission row.
void relayrxnohash() {
    const KatNet net;
    const auto has = [](const std::vector<std::string>& ls, const std::string& a, const std::string& b) {
        for (const std::string& l : ls)
            if (l.find(a) != std::string::npos && l.find(b) != std::string::npos) return true;
        return false;
    };
    const std::string reason = "RandomX computed no hash: kat: the seed cache could not be built";
    for (const bool low : {false, true}) {
        std::map<std::size_t, std::vector<std::string>> lines;
        g_relay_lines = &lines;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false);
        bool mined = true;
        for (int i = 0; i < 6; ++i) {
            if (i % 3 == 0) h.tick_monero();
            const std::optional<pb::PathbJob> j = h.job(a.node, static_cast<std::size_t>(i % 5), 780 + i);
            mined = mined && j && h[a.node].on_own_share(*j, 780 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
        }
        const pb::Hash32 tip_a = h[a.node].tree().best().id, armed = *h[a.node].store().best_at(3);
        (low ? h.low_pow : h.nohash_pow).insert(armed);
        pb::PathbRelayNode& rb = *b.relay;
        w.connect(0, 1);
        w.run();
        const std::uint64_t f1 = rb.stats().rx_failures.load(), bans1 = rb.stats().bans.load();
        for (int i = 0; i < 4 && h[b.node].tree().best().id != tip_a && !low; ++i) {
            h.now += h[b.node].config().abandon_timeout_s + 1;
            rb.tick();
            w.run();
        }
        g_relay_lines = nullptr;
        const std::vector<std::string>& lb = lines[b.node];
        std::printf("  relayrxnohash (%s): hashes not computed %llu, RandomX failures %llu, bans %llu, strikes %llu, "
                    "catch-up requests %llu, B at %llu of %llu\n",
                    low ? "low" : "no hash", (unsigned long long)h.nohash_calls, (unsigned long long)f1,
                    (unsigned long long)bans1, (unsigned long long)rb.strikes_of(1),
                    (unsigned long long)rb.stats().catchup_requests.load(), (unsigned long long)h[b.node].tree().best().pos,
                    (unsigned long long)h[a.node].tree().best().pos);
        if (!low) {
            check(mined && h.nohash_calls == 1 && f1 == 1 && bans1 == 0 && rb.strikes_of(1) == 0
                          && has(lb, " FC_HEADERS not judged: " + reason, "(no token, no ban)")
                          && has(lb, "RandomX failing (headers of peer ", reason),
                  "relayrxnohash (a): RandomX computed no hash on a catch-up header: 1 failure, no token, no ban; the "
                  "line names the peer and the reason");
            check(h[b.node].tree().best().id == tip_a && rb.stats().bans.load() == 0 && rb.stats().catchup_requests >= 2,
                  "relayrxnohash (a): asked again (" + std::to_string(rb.stats().catchup_requests.load())
                          + " requests), A's tip reached, no ban");
        } else {
            check(mined && h.nohash_calls == 0 && f1 == 0 && bans1 == 1 && has(lb, " BANNED: ", "S1.3 #11 PoW below d"),
                  "relayrxnohash (b): a hash computed not meeting d on that header: 1 BAN, the BANNED line names S1.3 #11");
        }
    }
    for (const bool low : {false, true}) {
        std::map<std::size_t, std::vector<std::string>> lines;
        g_relay_lines = &lines;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false);
        w.connect(0, 1);
        w.run();
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, 1, 790 + static_cast<std::uint32_t>(i));
        }
        const bool synced = h[b.node].tree().best().id == h[a.node].tree().best().id;
        const std::optional<pb::PathbJob> j = h.job(a.node, 3, 795);
        ok = ok && j && h[a.node].on_own_share(*j, 795, pb::Hash32{}).action == pb::NodeAction::Placed;
        const pb::Hash32 c = h[a.node].tree().best().id;
        (low ? h.low_pow : h.nohash_pow).insert(c);
        pb::PathbRelayNode& rb = *b.relay;
        w.run();
        const std::uint64_t f1 = rb.stats().rx_failures.load(), bans1 = rb.stats().bans.load();
        const bool at_once = h[b.node].tree().find(c) != nullptr;
        for (int i = 0; i < 8 && !low && h[b.node].tree().find(c) == nullptr; ++i) {
            h.now += 1;
            rb.tick();
            w.run();
        }
        g_relay_lines = nullptr;
        const std::vector<std::string>& lb = lines[b.node];
        std::printf("  relayrxnohash (%s carrier): hashes not computed %llu, RandomX failures %llu, bans %llu, strikes "
                    "%llu, placed at once %d, placed %d\n",
                    low ? "low" : "no hash", (unsigned long long)h.nohash_calls, (unsigned long long)f1,
                    (unsigned long long)bans1, (unsigned long long)rb.strikes_of(1), at_once ? 1 : 0,
                    h[b.node].tree().find(c) != nullptr ? 1 : 0);
        if (!low) {
            check(ok && synced && h.nohash_calls == 1 && f1 == 1 && bans1 == 0 && !at_once
                          && has(lb, "RandomX failing (carrier: ", reason),
                  "relayrxnohash (c): RandomX computed no hash on a relayed carrier: 1 failure, no ban, not placed; the "
                  "alarm names the reason");
            check(h[b.node].tree().find(c) != nullptr && h[b.node].tree().best().id == c && rb.stats().bans.load() == 0
                          && rb.strikes_of(1) == 0,
                  "relayrxnohash (c): parked and run again: placed, no token, no ban");
        } else {
            check(ok && synced && h.nohash_calls == 0 && f1 == 0 && bans1 == 1 && !at_once
                          && has(lb, " BANNED: ", "admission row R"),
                  "relayrxnohash (d): a hash computed not meeting d on a relayed carrier: 1 BAN, the BANNED line names "
                  "the admission row");
        }
    }
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
// alarmed; no token, no ban; nothing leaves the relay. The bind is left to do: the same peer's next offer DEFERs on
// TipBodies again and its bind (run on every TipBodies DEFER) places the walked carrier; the receipt is admitted.
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
    const bool thrown = h.throw_pow.count(u) == 0;
    const bool loser_at_fail = h[x.node].tree().find(loser) != nullptr;
    const std::uint64_t parked_at_fail = st.receipts_parked.load();
    // the bind left to do: the same peer's next offer of rk DEFERs on TipBodies again; its bind places the loser and rk
    // is admitted
    int again = 0;
    try {
        for (; again < 8 && !h[x.node].pending().holds(pb::receipt_id(rk)); ++again) {
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
    std::printf("  relayrxbindr: offers=%d thrown=%d escaped='%s' rx_failures=%llu walk_placed=%llu loser@X=%d (at the failure %d); "
                "again %d: rk held %d, parked %llu -> %llu\n",
                offers, thrown, esc.c_str(), (unsigned long long)st.rx_failures.load(), (unsigned long long)st.walk_placed.load(),
                h[x.node].tree().find(loser) != nullptr, loser_at_fail, again, h[x.node].pending().holds(pb::receipt_id(rk)),
                (unsigned long long)parked_at_fail, (unsigned long long)st.receipts_parked.load());
    check(thrown && esc.empty() && st.rx_failures.load() >= 1 && st.strikes.load() == 0 && st.bans.load() == 0,
          "relayrxbindr: a RandomX failure in the bind on the receipt path: counted (" + std::to_string(st.rx_failures.load())
                  + "), nothing out of the relay; no strike, no ban");
    check(!loser_at_fail && h[x.node].tree().find(loser) != nullptr && h[x.node].pending().holds(pb::receipt_id(rk))
                  && st.receipts_parked.load() > parked_at_fail,
          "relayrxbindr: the bind left to do runs at the same peer's next TipBodies DEFER: the walked carrier placed, the "
          "receipt admitted");
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
        // losing sibling) as a flood; k's receipt itself does not reach X (no FB_RECEIPTS from the losing node)
        w.edit = [lo, xn = x.node](FakeWire::Msg& m) {
            if (m.from == lo && m.to == xn && !m.f.empty() && m.f[0] == pb::kOpFbReceipts) m.f.clear();
        };
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
        w.edit = nullptr;
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
// relayrepend: a switch by the journal relays the receipts it re-pended as FB_RECEIPTS v3, paged as the re-offer
// within the link's bound; the switching node mines no more and a peer's next carrier carries them (open carriage).
//   (a) the switch at a direct placement: C's carrier X loses the tie to A's Y1 (X.id > Y1.id), Y1 then Y2 reach C;
//   (b) the switch in the drain: X wins the tie (X.id < Y1.id); only Y2 reaches C, parked on its unknown parent; Y1
//       fetched and placed beside X; Y2 released and placed by drain_released: the switch; C's link to A and B is
//       full at first (the re-pend relay paused), then drains (the tick sends it).
void relayrepend() {
    for (const bool drain : {false, true}) {
        const std::string tag = drain ? "relayrepend (b) the drain path: " : "relayrepend (a) a direct placement: ";
        const KatNet net;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), true);
        KatRelay c = kat_relay(h, w, table0(net), true);
        w.connect(0, 1);
        w.connect(0, 2);
        w.connect(1, 2);
        w.run();
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, 1, 500 + static_cast<std::uint32_t>(i));
        }
        const pb::Hash32 t0 = h[a.node].tree().best().id;
        ok = ok && h[b.node].tree().best().id == t0 && h[c.node].tree().best().id == t0;
        // C cut off from A and B: A mines Y1, then C mines X on t0 (a nonce whose id loses or wins the tie with Y1)
        w.edit = [](FakeWire::Msg& m) {
            if (m.from == 2 || m.to == 2) m.f.clear();
        };
        ok = ok && mine_on(h, w, a.node, 2, 510);
        const pb::Hash32 y1 = h[a.node].tree().best().id;
        std::optional<pb::PathbJob> xj;
        std::uint32_t xn = 0;
        pb::Hash32 x{};
        for (std::uint32_t n = 520; n < 600 && !xj; ++n) {
            std::optional<pb::PathbJob> j = h.job(c.node, 7, n);
            if (!j) break;
            pb::ReceiptBodyV3 rb = j->body;
            rb.blob.nonce = n;
            const pb::Hash32 id = pb::receipt_id(rb);
            if (drain ? id < y1 : y1 < id) {
                xj = j;
                xn = n;
                x = id;
            }
        }
        ok = ok && xj && h[c.node].on_own_share(*xj, xn, pb::Hash32{}).action == pb::NodeAction::Placed
             && h[c.node].tree().best().id == x;
        w.run();
        ok = ok && mine_on(h, w, a.node, 3, 511);
        const pb::Hash32 y2 = h[a.node].tree().best().id;
        w.edit = nullptr;
        const pb::Hash32 rid = x;  // X's own receipt (a carrier's id is its own receipt's id)
        ok = ok && !h[a.node].pending().holds(rid) && !h[b.node].pending().holds(rid);
        if (!ok) {
            check(false, tag + "setup");
            continue;
        }
        const pb::PathbRelayStats& sc = c.relay->stats();
        const std::uint64_t f0 = sc.reoffer_frames.load(), p0 = sc.reoffer_paused.load();
        if (drain) {
            c.links->limit = std::size_t{1} << 20;  // every link full: the relay pages within the bound and waits
            c.links->queued = c.links->limit;
        }
        // the heal: A's chain reaches C (Y1 and Y2 in order, or Y2 alone)
        if (!drain) w.q.push_back(FakeWire::Msg{0, 2, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(y1), 16)});
        w.q.push_back(FakeWire::Msg{0, 2, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(y2), 16)});
        w.run();
        const bool switched = h[c.node].tree().best().id == y2 && h[c.node].pending().holds(rid);
        const std::uint64_t offers = sc.repend_offers.load(), offered = sc.repend_offered.load();
        bool paused = true;
        if (drain) {
            paused = sc.reoffer_paused.load() > p0 && sc.reoffer_frames.load() == f0 && !h[b.node].pending().holds(rid);
            c.links->queued = 0;
            h.now += 1;
            c.relay->tick();
            w.run();
        }
        const bool held = h[a.node].pending().holds(rid) && h[b.node].pending().holds(rid);
        check(switched && offers == 1 && offered >= 1 && sc.reoffer_frames.load() > f0 && paused && held,
              tag + "C switches to Y by its journal, X's receipt re-pended and relayed as FB_RECEIPTS v3 (offers " +
                      std::to_string(offers) + ", receipts " + std::to_string(offered) + ", frames " +
                      std::to_string(sc.reoffer_frames.load() - f0) + (drain ? ", paused while the links were full" : "") +
                      "); A and B hold it pending (" + std::to_string(h[a.node].pending().holds(rid)) + ", " +
                      std::to_string(h[b.node].pending().holds(rid)) + ")");
        // C mines no more: B's next carrier carries C's re-pended receipt
        h.tick_monero();
        const bool mined = mine_on(h, w, b.node, 4, 530);
        const pb::Hash32 tb = h[b.node].tree().best().id;
        const pb::CarrierBodyV3* cb = h[b.node].bodies().get(tb);
        bool carried = false;
        if (cb)
            for (const pb::ReceiptBodyV3& r : cb->carried) carried = carried || pb::receipt_id(r) == rid;
        check(mined && carried && h[c.node].tree().best().id == tb && !h[c.node].pending().holds(rid),
              tag + "C mines no more; B's next carrier carries C's re-pended receipt (" + std::to_string(carried) +
                      "), placed on C too: C's pending no longer holds it");
        const pb::PathbNode::SwitchCounts& scc = h[c.node].switch_counts();
        check(scc.switches == 1 && scc.repended >= 1 && scc.carried >= 1 && scc.carried + scc.sealed_pending <= scc.repended
                      && h[c.node].repend_watch_size() == 0,
              tag + "C's switch counts: re-pended " + std::to_string(scc.repended) + ", carried " +
                      std::to_string(scc.carried) + " (B's carrier), sealed pending " + std::to_string(scc.sealed_pending) +
                      "; none left watched (" + std::to_string(h[c.node].repend_watch_size()) + ")");
    }
}


// ---------------------------------------------------------------------------
// relayreoffercap: a flapping best chain and a slow peer. A and B mine competing branches apart; C (pending cap 6) gets
// them in turns, each turn one longer than the other side, so it switches back and forth by its journal and re-pends the
// receipts of the branch it leaves, again and again; C's links are full (every re-offer paused). Each peer's re-offer
// queue holds each id once and at most the pending cap of them (the oldest dropped); once the link drains it empties.
void relayreoffercap() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true, false, nullptr, [](pb::PathbNodeConfig& cfg) { cfg.pending_cap = 6; });
    KatRelay sl = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.connect(0, 2);
    w.connect(1, 2);
    w.connect(2, 3);  // the slow peer: C's only
    w.run();
    bool ok = true;
    for (int i = 0; i < 3; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 500 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 t0 = h[a.node].tree().best().id;
    ok = ok && h[b.node].tree().best().id == t0 && h[c.node].tree().best().id == t0;
    // A, B, C apart from each other (C gets A's and B's carriers by hand); C's links full: the re-offers wait
    w.edit = [](FakeWire::Msg& m) {
        if (m.from < 3 && m.to < 3) m.f.clear();
    };
    c.links->limit = std::size_t{1} << 20;
    c.links->queued = c.links->limit;
    const pb::PathbRelayStats& sc = c.relay->stats();
    const std::uint64_t pa = 1, pb_ = 2, ps = 4;  // A, B and the slow peer at C
    std::uint32_t nonce = 600;
    std::size_t la = 0, lb = 0;  // the branch lengths C holds
    const auto feed = [&](const KatRelay& m, std::uint64_t peer, std::size_t& len, std::size_t to) {
        while (ok && len < to) {
            ok = mine_on(h, w, m.node, m.node == a.node ? 2 : 3, nonce++);
            const pb::Hash32 id = h[m.node].tree().best().id;
            c.relay->receive(peer, *pb::encode_fc_carrier(0, *h[m.node].bodies().get(id), 16));
            w.run();
            h.now += 1;  // the sender's RandomX tokens refill; a parked job runs again on the tick
            c.relay->tick();
            w.run();
            ++len;
        }
    };
    std::size_t worst = 0;
    bool distinct = true;
    int switches = 0;
    feed(a, pa, la, 1);
    for (int round = 0; ok && round < 8; ++round) {
        const pb::Hash32 before = h[c.node].tree().best().id;
        if (round % 2 == 0)
            feed(b, pb_, lb, la + 1);
        else
            feed(a, pa, la, lb + 1);
        if (h[c.node].tree().best().id != before) ++switches;
        std::printf("  relayreoffercap round %d: la %zu lb %zu; C at %llu; offers %llu receipts %llu; queues %zu %zu %zu\n", round, la,
                    lb, (unsigned long long)h[c.node].tree().best().pos, (unsigned long long)sc.repend_offers.load(),
                    (unsigned long long)sc.repend_offered.load(), c.relay->reoffer_queued(pa), c.relay->reoffer_queued(pb_),
                    c.relay->reoffer_queued(ps));
        for (const std::uint64_t p : {pa, pb_, ps}) {
            worst = std::max(worst, c.relay->reoffer_queued(p));
            distinct = distinct && c.relay->reoffer_distinct(p);
        }
    }
    const std::size_t at_slow = c.relay->reoffer_queued(ps);
    std::printf("  relayreoffercap: setup %d; C switched %d times, re-pend offers %llu (receipts %llu); queue at the slow peer %zu, "
                "worst %zu, each id once %d; cap drops %llu\n",
                ok ? 1 : 0, switches, (unsigned long long)sc.repend_offers.load(), (unsigned long long)sc.repend_offered.load(),
                at_slow, worst, distinct ? 1 : 0, (unsigned long long)sc.reoffer_cap_drops.load());
    check(ok && switches >= 7 && sc.repend_offered.load() > 6 && worst <= 6 && at_slow >= 1 && distinct
                  && sc.reoffer_cap_drops.load() > 0,
          "relayreoffercap: a flapping best chain with every link full: each peer's re-offer queue holds each id once and at "
          "most the pending cap (6), the oldest dropped");
    c.links->queued = 0;
    h.now += 1;
    c.relay->tick();
    w.run();
    check(c.relay->reoffer_queued(ps) == 0 && c.relay->reoffer_queued(pa) == 0 && c.relay->reoffer_queued(pb_) == 0,
          "relayreoffercap: once the links drain the re-offer queues empty (paged within the link's bound)");
}

// ---------------------------------------------------------------------------
// relayqfull: a link the transport drops at a relay send for a full queue is counted apart: while the peer's re-offer
// pages (the link full, the re-offer paused) as a re-offer drop; otherwise as a live-traffic drop.
void relayqfull() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 900 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::PathbJob> stale = h.job(a.node, 2, 910);
    ok = ok && stale && mine_on(h, w, a.node, 1, 911)
         && h[a.node].on_own_share(*stale, 910, pb::Hash32{}).action == pb::NodeAction::Pending;  // A holds one pending
    const pb::PathbRelayStats& st = a.relay->stats();
    a.links->limit = std::size_t{1} << 20;  // A's links full: the re-offer after B's HELLO pauses
    a.links->queued = a.links->limit;
    w.connect(0, 1);
    w.run();
    const bool paging = st.reoffer_paused.load() > 0 && st.reoffer_done.load() == 0;
    a.links->full_next = true;  // A's next send to B: the queue full, the link dropped
    ok = ok && mine_on(h, w, a.node, 1, 912);
    const std::uint64_t r1 = st.reoffer_queue_full.load(), l1 = st.live_queue_full.load();
    check(ok && paging && a.links->full_drops == 1 && r1 == 1 && l1 == 0,
          "relayqfull: a drop for a full queue while B's re-offer pages: a re-offer drop (" + std::to_string(r1) +
                  "), not a live one (" + std::to_string(l1) + ")");
    a.links->queued = 0;  // the links drain: B back, its re-offer sent to the end
    w.connect(0, 1);
    w.run();
    const bool done = st.reoffer_done.load() >= 1;
    a.links->full_next = true;
    ok = ok && mine_on(h, w, a.node, 1, 913);
    const std::uint64_t r2 = st.reoffer_queue_full.load(), l2 = st.live_queue_full.load();
    check(ok && done && a.links->full_drops == 2 && r2 == 1 && l2 == 1,
          "relayqfull: a drop for a full queue with no re-offer paging: a live-traffic drop (" + std::to_string(l2) +
                  "; re-offer drops " + std::to_string(r2) + ")");
}


// ---------------------------------------------------------------------------
// revrepend2: the partitioned node C mines TWO carriers X1 (on t0) and X2 (on X1) while A mines Y1..Y3; at the heal C
// switches to Y3 and re-pends X1's and X2's own receipts. X2's receipt's tip is X1, a carrier of the abandoned branch A
// and B never saw: it DEFERs there, is parked and runs again once X1 arrives. A and B hold both receipts; B's next
// carrier carries both while C mines nothing.
void revrepend2() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.connect(0, 2);
    w.connect(1, 2);
    w.run();
    bool ok = true;
    for (int i = 0; i < 3; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 500 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 t0 = h[a.node].tree().best().id;
    ok = ok && h[b.node].tree().best().id == t0 && h[c.node].tree().best().id == t0;
    std::printf("  setup t0 ok=%d\n", ok ? 1 : 0);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 2 || m.to == 2) m.f.clear();
    };
    const bool cx1 = mine_on(h, w, c.node, 7, 520);
    const pb::Hash32 x1 = h[c.node].tree().best().id;
    const bool cx2 = mine_on(h, w, c.node, 7, 521);
    const pb::Hash32 x2 = h[c.node].tree().best().id;
    const pb::CarrierBodyV3* bx2 = h[c.node].bodies().get(x2);
    const bool x2_on_x1 = bx2 && bx2->own.side.tip == x1;
    const bool ay1 = mine_on(h, w, a.node, 2, 510);
    const pb::Hash32 y1 = h[a.node].tree().best().id;
    const bool ay2 = mine_on(h, w, a.node, 2, 511);
    const pb::Hash32 y2 = h[a.node].tree().best().id;
    const bool ay3 = mine_on(h, w, a.node, 2, 512);
    const pb::Hash32 y3 = h[a.node].tree().best().id;
    w.edit = nullptr;
    std::printf("  mined: C x1=%d x2=%d (x2's tip is x1: %d); A y1=%d y2=%d y3=%d; B best==y3 %d\n", cx1, cx2, x2_on_x1, ay1,
                ay2, ay3, h[b.node].tree().best().id == y3 ? 1 : 0);
    std::printf("  before the heal: A holds x1 %d x2 %d; B holds x1 %d x2 %d; A knows x1 %d\n",
                h[a.node].pending().holds(x1), h[a.node].pending().holds(x2), h[b.node].pending().holds(x1),
                h[b.node].pending().holds(x2), h[a.node].tree().find(x1) != nullptr ? 1 : 0);
    const pb::PathbRelayStats& sc = c.relay->stats();
    const pb::PathbRelayStats& sa = a.relay->stats();
    const std::uint64_t f0 = sc.reoffer_frames.load();
    for (const pb::Hash32& y : {y1, y2, y3})
        w.q.push_back(FakeWire::Msg{0, 2, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(y), 16)});
    w.run();
    for (int k = 0; k < 4; ++k) {
        h.now += 1;
        a.relay->tick();
        b.relay->tick();
        c.relay->tick();
        w.run();
    }
    std::printf("  after the heal: C best==y3 %d; C pending holds x1 %d x2 %d; C offers %llu receipts %llu frames %llu\n",
                h[c.node].tree().best().id == y3 ? 1 : 0, h[c.node].pending().holds(x1), h[c.node].pending().holds(x2),
                (unsigned long long)sc.repend_offers.load(), (unsigned long long)sc.repend_offered.load(),
                (unsigned long long)(sc.reoffer_frames.load() - f0));
    std::printf("  A holds x1 %d x2 %d (A knows x1 now: %d; A tip header requests %llu); B holds x1 %d x2 %d\n",
                h[a.node].pending().holds(x1), h[a.node].pending().holds(x2),
                h[a.node].tree().find(x1) != nullptr ? 1 : 0, (unsigned long long)sa.tip_header_requests.load(),
                h[b.node].pending().holds(x1), h[b.node].pending().holds(x2));
    const bool held = h[a.node].pending().holds(x1) && h[b.node].pending().holds(x1) && h[a.node].pending().holds(x2)
                      && h[b.node].pending().holds(x2);
    h.tick_monero();
    const bool mined = mine_on(h, w, b.node, 4, 530);
    const pb::Hash32 tb = h[b.node].tree().best().id;
    const pb::CarrierBodyV3* cb = h[b.node].bodies().get(tb);
    bool c1 = false, c2 = false;
    if (cb)
        for (const pb::ReceiptBodyV3& r : cb->carried) {
            c1 = c1 || pb::receipt_id(r) == x1;
            c2 = c2 || pb::receipt_id(r) == x2;
        }
    std::printf("  B mined %d; B's carrier carries x1 %d x2 %d; C pending after: x1 %d x2 %d\n", mined, c1, c2,
                h[c.node].pending().holds(x1), h[c.node].pending().holds(x2));
    check(ok && x2_on_x1, "revrepend2 setup");
    check(held, "revrepend2: A and B hold X1's and X2's re-pended receipts (X2's tip X1 on the abandoned branch)");
    check(mined && c1 && c2 && !h[c.node].pending().holds(x1) && !h[c.node].pending().holds(x2),
          "revrepend2: C mines no more; B's next carrier carries X1's and X2's re-pended receipts");
    std::printf("  park after: A parked %zu asks %zu due %zu; B parked %zu asks %zu due %zu (A parked %llu in all)\n",
                a.relay->parked_receipts(), a.relay->parked_receipt_asks(), a.relay->parked_receipts_due(),
                b.relay->parked_receipts(), b.relay->parked_receipt_asks(), b.relay->parked_receipts_due(),
                (unsigned long long)sa.receipts_parked.load());
    check(sa.receipts_parked.load() > 0 && a.relay->parked_receipts() == 0 && a.relay->parked_receipt_asks() == 0
                  && a.relay->parked_receipts_due() == 0 && b.relay->parked_receipts() == 0
                  && b.relay->parked_receipt_asks() == 0 && b.relay->parked_receipts_due() == 0
                  && a.relay->parked_index_size() == 0 && b.relay->parked_index_size() == 0,
          "revrepend2: after the heal A and B park no receipt and keep no ask record or index entry for one");
}

// ---------------------------------------------------------------------------
// relayrpark: the receipt park under junk. B (verify queue 4, pending cap 6) gets receipts of A whose tip nobody holds:
// each DEFERs before any PoW row and is parked under TipUnknown. (a) Ten parked: the cap keeps the newest six, the
// oldest four go with their index entries; none is counted in P-15. (b) The same receipt again from the same peer:
// parked once, asked once. (c) Its cause resolving with two honest receipts queued: the re-run takes the queue's free
// room (two), drops no queued job, keeps its asks (no new header request); the rest run on the next tick. (d) Re-run
// jobs dropped from the full verify queue leave the park with their asks. (e) An honest receipt parked on its unknown
// tip and admitted on its re-run is counted in P-15 once.
void relayrpark() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(
            h, w, table0(net), false, false,
            [](pb::PathbRelayOptions& o) {
                o.peer_valid_capacity = 100;
                o.verify_queue_max = 4;
            },
            [](pb::PathbNodeConfig& c) { c.pending_cap = 6; });
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 800);
    // six receipts of A: shares of jobs on A's tip after A moved on, not relayed; then A's carrier delivered to B
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t k = 0; k < 6; ++k)
        if (const std::optional<pb::PathbJob> j = h.job(a.node, k + 2, 810 + k)) jobs.push_back(*j);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && jobs.size() == 6 && mine_on(h, w, a.node, 1, 820);
    for (std::uint32_t k = 0; ok && k < 6; ++k)
        ok = h[a.node].on_own_share(jobs[k], 810 + k, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(h[a.node].tree().best().id), 16)});
    w.run();
    std::vector<pb::ReceiptBodyV3> rs;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) rs.push_back(r->body);
    ok = ok && rs.size() == 6 && h[b.node].pending().size() == 0 && h[b.node].tree().best().id == h[a.node].tree().best().id;
    std::printf("  relayrpark setup: jobs %zu, A pending %zu, B pending %zu, same best %d\n", jobs.size(), rs.size(),
                h[b.node].pending().size(), h[b.node].tree().best().id == h[a.node].tree().best().id ? 1 : 0);
    if (!ok) {
        check(false, "relayrpark: setup");
        return;
    }
    h.now += 1000;  // B's P-15 bucket full
    pb::PathbRelayNode& rb = *b.relay;
    const pb::PathbRelayStats& st = rb.stats();
    const std::uint64_t pa = 1;  // A at B
    const auto frame_of = [](const pb::ReceiptBodyV3& r) {
        return *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{r}, pb::kRuledLaneParams);
    };
    std::vector<std::vector<std::uint8_t>> junk;
    for (std::uint8_t k = 0; k < 10; ++k) {
        pb::ReceiptBodyV3 r = rs[0];
        r.side.tip.fill(0xA5);
        r.side.tip[0] = static_cast<std::uint8_t>(k + 1);
        junk.push_back(frame_of(r));
    }
    const double valid0 = rb.peer_valid_left(pa);
    const std::uint64_t parked0 = st.receipts_parked.load(), drops0 = st.parked_receipt_drops.load();
    for (const std::vector<std::uint8_t>& f : junk) {
        rb.receive(pa, f);
        w.run();
    }
    bool newest = true;
    for (std::size_t k = 0; k < junk.size(); ++k) newest = newest && rb.receipt_parked(junk[k]) == (k >= 4);
    const std::uint64_t hdr_a = st.tip_header_requests.load();
    std::printf("  (a) parked %zu (parked %llu, dropped %llu), the newest six %d, index %zu, asks %zu, header requests %llu,"
                " P-15 left %.1f -> %.1f\n",
                rb.parked_receipts(), (unsigned long long)(st.receipts_parked.load() - parked0),
                (unsigned long long)(st.parked_receipt_drops.load() - drops0), newest ? 1 : 0, rb.parked_index_size(),
                rb.parked_receipt_asks(), (unsigned long long)hdr_a, valid0, rb.peer_valid_left(pa));
    check(rb.parked_receipts() == 6 && st.parked_receipt_drops.load() - drops0 == 4 && newest
                  && rb.parked_index_size() == 6 && rb.parked_receipt_asks() == 6,
          "relayrpark (a): ten junk receipts parked under the cap of six: the oldest four go with their index entries "
          "and asks");
    check(rb.peer_valid_left(pa) == valid0 && rb.strikes_of(pa) == 0 && st.bans.load() == 0,
          "relayrpark (a): a DEFERred receipt is not counted in P-15 (no strike, no ban)");
    rb.receive(pa, junk[9]);
    w.run();
    std::printf("  (b) again: parked %zu, dropped %llu, asks %zu, header requests %llu -> %llu\n", rb.parked_receipts(),
                (unsigned long long)(st.parked_receipt_drops.load() - drops0), rb.parked_receipt_asks(),
                (unsigned long long)hdr_a, (unsigned long long)st.tip_header_requests.load());
    check(rb.parked_receipts() == 6 && st.parked_receipt_drops.load() - drops0 == 4 && rb.receipt_parked(junk[4])
                  && rb.parked_receipt_asks() == 6 && st.tip_header_requests.load() == hdr_a,
          "relayrpark (b): the same receipt again from the same peer: parked once, its peer asked once");
    rb.receive(pa, frame_of(rs[0]));
    rb.receive(pa, frame_of(rs[1]));
    const std::size_t vq0 = rb.verify_queue_size();
    const std::uint64_t qd0 = st.queue_dropped.load();
    rb.test_rerun(pb::Missing::TipUnknown);
    const std::size_t vq1 = rb.verify_queue_size(), due1 = rb.parked_receipts_due(), parked1 = rb.parked_receipts();
    w.run();
    const bool honest = h[b.node].pending().holds(pb::receipt_id(rs[0])) && h[b.node].pending().holds(pb::receipt_id(rs[1]));
    const std::size_t due2 = rb.parked_receipts_due(), parked2 = rb.parked_receipts();
    h.now += 1;
    rb.tick();
    w.run();
    std::printf("  (c) queued %zu, after the re-run: queue %zu due %zu parked %zu (dropped %llu); run: honest held %d, due %zu"
                " parked %zu; tick: due %zu parked %zu asks %zu, header requests %llu\n",
                vq0, vq1, due1, parked1, (unsigned long long)(st.queue_dropped.load() - qd0), honest ? 1 : 0, due2, parked2,
                rb.parked_receipts_due(), rb.parked_receipts(), rb.parked_receipt_asks(),
                (unsigned long long)st.tip_header_requests.load());
    check(vq0 == 2 && vq1 == 4 && due1 == 4 && parked1 == 4 && st.queue_dropped.load() == qd0 && honest,
          "relayrpark (c): the re-run takes the verify queue's free room (2 of 6); no queued job dropped; the honest "
          "receipts admitted");
    check(due2 == 4 && parked2 == 6 && rb.parked_receipts_due() == 0 && rb.parked_receipts() == 6
                  && rb.parked_receipt_asks() == 6 && st.tip_header_requests.load() == hdr_a,
          "relayrpark (c): the rest run on the next tick; every re-run parks again with its asks (no new header request)");
    rb.test_rerun(pb::Missing::TipUnknown);
    const std::size_t vq3 = rb.verify_queue_size();
    for (std::size_t k = 2; k < 6; ++k) rb.receive(pa, frame_of(rs[k]));
    const std::uint64_t qd3 = st.queue_dropped.load() - qd0;
    w.run();
    std::printf("  (d) queued %zu re-runs, %llu dropped by four honest frames: parked %zu asks %zu due %zu index %zu\n", vq3,
                (unsigned long long)qd3, rb.parked_receipts(), rb.parked_receipt_asks(), rb.parked_receipts_due(),
                rb.parked_index_size());
    check(vq3 == 4 && qd3 == 4 && rb.parked_receipts() == 2 && rb.parked_receipt_asks() == 2
                  && rb.parked_receipts_due() == 2 && rb.parked_index_size() == 0,
          "relayrpark (d): re-run jobs dropped from the full verify queue leave the park with their asks");
    // (e) an honest receipt whose tip B lacks: parked, then admitted on its re-run once the tip's branch arrives; counted
    // in P-15 once, at that admission (its DEFER run not)
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    h.tick_monero();
    bool eok = mine_on(h, w, a.node, 1, 830);
    const std::optional<pb::PathbJob> uj = h.job(a.node, 3, 831);
    eok = eok && uj && mine_on(h, w, a.node, 1, 832);
    eok = eok && h[a.node].on_own_share(*uj, 831, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    std::optional<pb::ReceiptBodyV3> u;
    for (const pb::PendingReceipt* r : h[a.node].pending().all())
        if (h[b.node].tree().find(r->body.side.tip) == nullptr) u = r->body;
    const std::uint64_t c0 = st.p15_counted.load(), parked_e = st.receipts_parked.load();
    if (u) {
        rb.receive(pa, frame_of(*u));
        w.run();
        for (int k = 0; k < 3 && !h[b.node].pending().holds(pb::receipt_id(*u)); ++k) {
            h.now += 1;
            rb.tick();
            a.relay->tick();
            w.run();
        }
    }
    const bool held_u = u && h[b.node].pending().holds(pb::receipt_id(*u));
    std::printf("  (e) setup %d, u's tip unknown at B %d; parked %llu; u held %d; P-15 counted %llu\n", eok ? 1 : 0, u ? 1 : 0,
                (unsigned long long)(st.receipts_parked.load() - parked_e), held_u ? 1 : 0,
                (unsigned long long)(st.p15_counted.load() - c0));
    check(eok && u && st.receipts_parked.load() > parked_e && held_u && st.p15_counted.load() - c0 == 1,
          "relayrpark (e): a receipt parked on its unknown tip, admitted on its re-run: counted in P-15 once, at that "
          "admission");
}

// ---------------------------------------------------------------------------
// relayhdrctx: headers-first catch-up over a Monero parent the client does not hold. A mines six carriers, the last
// three on a Monero block M that B's follower does not hold yet. B's catch-up from A's HELLO reaches the first header on
// M: the reply DEFERs; B wants M (FB_GETCTX, the carrier class) and asks the headers again once M resolves (here the
// follower's chain moving to M): B reaches A's tip with no strike and no ban.
// The follower's rows with some blocks not held (Monero blocks this node has not seen).
struct HiddenRows final : pb::IMoneroRows {
    const pb::IMoneroRows& inner;
    const std::set<pb::Hash32>& hidden;
    HiddenRows(const pb::IMoneroRows& i, const std::set<pb::Hash32>& h) : inner(i), hidden(h) {}
    std::optional<pb::BranchBlock> block(const pb::Hash32& id) const override {
        return hidden.count(id) != 0 ? std::nullopt : inner.block(id);
    }
    std::optional<pb::BranchBlock> block_at_or_below_anchor(std::uint64_t height) const override {
        return inner.block_at_or_below_anchor(height);
    }
    std::optional<pb::RowWeights> weights(const pb::Hash32& id) const override {
        return hidden.count(id) != 0 ? std::nullopt : inner.weights(id);
    }
    pb::BranchBlock anchor() const override { return inner.anchor(); }
    pb::Hash32 main_tip() const override { return inner.main_tip(); }
};

void relayhdrctx() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;  // Monero blocks B's follower does not hold
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, [&hidden, &hview](pb::PathbNodeIo& io) {
        const auto inner = io.resolve_pr;
        io.resolve_pr = [inner, &hidden](const pb::Hash32& p_r) {
            return hidden.count(p_r) != 0 ? pb::PrInfo{} : inner(p_r);
        };
        io.monero = &hview;
    });
    bool mined = true;
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        const std::optional<pb::PathbJob> j = h.job(a.node, static_cast<std::size_t>(i % 5), 900 + i);
        mined = mined && j && h[a.node].on_own_share(*j, 900 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    const pb::Hash32 tip_a = h[a.node].tree().best().id;
    const pb::CarrierBodyV3* bt = h[a.node].bodies().get(tip_a);
    const pb::Hash32 m = bt ? bt->own.blob.prev_id : pb::Hash32{};
    hidden.insert(m);
    pb::PathbRelayNode& rb = *b.relay;
    w.connect(0, 1);
    w.run();
    const std::uint64_t pos1 = h[b.node].tree().best().pos;
    const std::optional<std::uint32_t> want = rb.ctx_want_bound(m);
    const std::array<std::size_t, 3> cls = rb.ctx_wants_by_class();
    const std::uint64_t deferred = rb.stats().headers_ctx_deferred.load();
    std::printf("  relayhdrctx: mined %d; B at %llu of %llu after the HELLO; want M %d (classes %zu/%zu/%zu); deferred %llu\n",
                mined ? 1 : 0, (unsigned long long)pos1, (unsigned long long)h[a.node].tree().best().pos, want ? 1 : 0,
                cls[0], cls[1], cls[2], (unsigned long long)deferred);
    check(mined && bt && pos1 < 6 && want.has_value() && cls[1] >= 1 && deferred >= 1,
          "relayhdrctx: a catch-up header on a Monero parent B does not hold DEFERs; B wants it (the carrier class)");
    hidden.clear();  // M resolves
    rb.on_monero_tip();
    w.run();
    std::printf("  relayhdrctx: after M resolved: B at %llu, reasks %llu, strikes %llu, bans %llu\n",
                (unsigned long long)h[b.node].tree().best().pos, (unsigned long long)rb.stats().headers_ctx_reasks.load(),
                (unsigned long long)rb.strikes_of(1), (unsigned long long)rb.stats().bans.load());
    check(h[b.node].tree().best().id == tip_a && rb.stats().headers_ctx_reasks.load() >= 1 && rb.strikes_of(1) == 0
                  && rb.stats().bans.load() == 0,
          "relayhdrctx: once M resolves B asks the headers again at once and reaches A's tip; no strike, no ban");
}

// ---------------------------------------------------------------------------
// relayrxbind2: ONE walk places a walked carrier, then the bind of the next fails on RandomX (a body only that one
// carries): the placed id stays placed and counted (walk_placed), the failure counted; the parked frame's re-run places
// the rest. Both walked carriers carry a body: X asks sa1's body set (sa2's header binds only once sa1 is placed); sa2's
// body set is in X's index when sa1's arrives, so the walk that places sa1 goes on to sa2 and fails there.
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
    std::optional<pb::PathbJob> va;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        if (i == 3) va = h.job(a.node, 5, 350);
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    // v: A's share on a stale tip, pending (at A and L): A's first race carrier carries it
    ok = ok && va && h[a.node].on_own_share(*va, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
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
    ok = ok && ka && in2 && !in1 && !h[a.node].bodies().get(sa1)->carried.empty();
    if (!ok) {
        check(false, "relayrxbind2: setup (a two-carrier losing branch, each carrying a body, the second one of its own)");
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
    // A's reply with sa1's body set held back
    std::vector<std::vector<std::uint8_t>> sets;
    w.edit = [&, xn = x.node](FakeWire::Msg& m) {
        if (m.from != 0 || m.to != xn || m.f.empty()) return;
        if (m.f[0] == pb::kOpFbReceipts) {
            m.f.clear();
            return;
        }
        if (m.f[0] != pb::kOpFcCarrier || m.f.size() < pb::kFrameHeaderBytes) return;
        pb::CarrierBodyV3 cb;
        if (pb::decode_carrier_body_v3(m.f.data() + pb::kFrameHeaderBytes, m.f.size() - pb::kFrameHeaderBytes,
                                       pb::CarrierLimits{h[xn].config().buffers.receipt, pb::kRuledLaneParams.r_max}, cb)
                    == pb::WireError::None
            && pb::receipt_id(cb.own) == sa1) {
            sets.push_back(m.f);
            m.f.clear();
        }
    };
    const pb::PathbRelayStats& st = x.relay->stats();
    std::string esc;
    std::uint64_t placed_at_fail = 0, walk_before = 0;
    bool sa1_at_fail = false, captured = false;
    try {
        w.connect(a.node, x.node);
        w.run();
        for (int i = 0; i < 8 && sets.empty(); ++i) {
            h.now += 1;
            x.relay->tick();
            w.run();
        }
        walk_before = st.walk_placed.load();
        // sa2's body set into X's index (as A's reply would put it), then sa1's body set
        const bool injected = h[x.node].on_body_set(a.node + 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(sa2), 16));
        const bool both = sets.size() == 1 && injected && h[x.node].tree().find(sa1) == nullptr;
        if (!both) {
            w.edit = nullptr;
            check(false, "relayrxbind2: setup (sa1's body set asked of A " + std::to_string(sets.size()) +
                                 ", sa2's held " + std::to_string(injected) + ", sa1 not placed before)");
            return;
        }
        for (const std::vector<std::uint8_t>& f : sets) x.relay->receive(a.node + 1, f);
        w.run();
        for (int i = 0; i < 8 && h[x.node].tree().best().id != c; ++i) {
            if (st.rx_failures.load() > 0 && !captured) {
                captured = true;
                placed_at_fail = st.walk_placed.load() - walk_before;
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
          "relayrxbind2: one walk placed a walked carrier, then the bind of the next failed on RandomX: the placed one kept "
          "and counted, the failure counted; the re-run places the rest and the tip");
}


// ---------------------------------------------------------------------------
// relayrbindr: a LONE relayed receipt k whose tip ends a two-carrier branch X lacks, each carrier carrying a body X must
// fetch. Parked on TipUnknown (one header request), then twice on ClosureBodies of the same peer (sa1's body set, then
// sa2's: one cause, two objects, each asked once), then on TipBodies: the bind places both and k is admitted. The park
// asks a peer once per cause and object.
void relayrbindr() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    std::optional<pb::PathbJob> va;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        if (i == 3) va = h.job(a.node, 5, 350);
        ok = ok && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
    }
    ok = ok && va && h[a.node].on_own_share(*va, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    const std::optional<pb::PathbJob> ua = h.job(a.node, 6, 360);
    // the race: A mines two (each carrying a body), L three: A's branch loses
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
    ok = ok && ka && !h[a.node].bodies().get(sa1)->carried.empty() && !h[a.node].bodies().get(sa2)->carried.empty();
    for (const pb::Hash32& id : {sa1, sa2}) w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(id), 16)});
    {
        std::vector<pb::Hash32> ls;
        for (pb::Hash32 t = h[l.node].tree().best().id; ls.size() < 3; t = h[l.node].tree().find(t)->parent) ls.push_back(t);
        for (auto it = ls.rbegin(); it != ls.rend(); ++it)
            w.q.push_back(FakeWire::Msg{1, 0, *pb::encode_fc_carrier(0, *h[l.node].bodies().get(*it), 16)});
    }
    w.run();
    ok = ok && h[a.node].tree().best().id == h[l.node].tree().best().id && h[a.node].tree().find(sa2) != nullptr;
    // k: A's share on sa2 (the losing branch's tip), pending at A
    pb::ReceiptBodyV3 kb = ka->body;
    kb.blob.nonce = 410;
    const pb::Hash32 k = pb::receipt_id(kb);
    ok = ok && h[a.node].on_own_share(*ka, 410, pb::Hash32{}).action == pb::NodeAction::Pending && h[a.node].pending().holds(k);
    w.run();
    if (!ok) {
        check(false, "relayrbindr: setup (a two-carrier losing branch, each carrying a body; k pending at A on its tip)");
        return;
    }
    // X follows A alone: its catch-up reaches A's best (no receipt frame of A reaches X); then k alone
    const pb::PathbRelayStats& st = x.relay->stats();
    w.edit = [xn = x.node](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == xn && !m.f.empty() && m.f[0] == pb::kOpFbReceipts) m.f.clear();
    };
    w.connect(a.node, x.node);
    w.run();
    for (int i = 0; i < 6 && h[x.node].tree().best().id != h[a.node].tree().best().id; ++i) {
        h.now += 1;
        x.relay->tick();
        w.run();
    }
    w.edit = nullptr;
    const bool synced = h[x.node].tree().best().id == h[a.node].tree().best().id && h[x.node].tree().find(sa1) == nullptr;
    x.relay->receive(a.node + 1, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{kb}, pb::kRuledLaneParams));
    w.run();
    for (int i = 0; i < 12 && !h[x.node].pending().holds(k); ++i) {
        h.now += 1;
        x.relay->tick();
        w.run();
    }
    std::printf("  relayrbindr: synced %d; X holds k %d; X at A's best %d; sa1 %d sa2 %d placed at X; X parked %llu, tip header requests "
                "%llu, body set requests %llu, walk placed %llu; strikes %llu bans %llu\n",
                synced ? 1 : 0, h[x.node].pending().holds(k) ? 1 : 0,
                h[x.node].tree().best().id == h[a.node].tree().best().id ? 1 : 0,
                h[x.node].tree().find(sa1) != nullptr ? 1 : 0, h[x.node].tree().find(sa2) != nullptr ? 1 : 0,
                (unsigned long long)st.receipts_parked.load(), (unsigned long long)st.tip_header_requests.load(),
                (unsigned long long)st.body_set_requests.load(), (unsigned long long)st.walk_placed.load(),
                (unsigned long long)st.strikes.load(), (unsigned long long)st.bans.load());
    check(synced && h[x.node].pending().holds(k) && h[x.node].tree().find(sa2) != nullptr && st.receipts_parked.load() >= 2
                  && st.body_set_requests.load() >= 2 && st.strikes.load() == 0 && st.bans.load() == 0
                  && x.relay->parked_receipts() == 0,
          "relayrbindr: a lone receipt parked on a two-carrier branch: two body sets asked of one peer for one cause, "
          "the bind places both, the receipt admitted");
}

struct RevPark {
    std::size_t parked = 0, asks = 0, due = 0, index = 0;
};
RevPark revpark(pb::PathbRelayNode& r) {
    return RevPark{r.parked_receipts(), r.parked_receipt_asks(), r.parked_receipts_due(), r.parked_index_size()};
}

// ---------------------------------------------------------------------------
// relayrparkseal: SPEC DEFER, dropped without strike when its origin bin seals. B parks a relayed receipt whose tip
// nobody holds (a cause that never resolves; its P_r held, so its origin bin known). While its bin is open it stays
// parked; once A's chain moves the best record H(L) past the bin's seal (open_bins above its origin), B drops it with
// its asks and index entries, no strike, no ban.
void relayrparkseal() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 800);
    const std::optional<pb::PathbJob> j0 = h.job(a.node, 2, 810);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && j0 && mine_on(h, w, a.node, 1, 820);
    ok = ok && h[a.node].on_own_share(*j0, 810, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(h[a.node].tree().best().id), 16)});
    w.run();
    std::optional<pb::ReceiptBodyV3> base;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) base = r->body;
    ok = ok && base && h[b.node].tree().best().id == h[a.node].tree().best().id;
    if (!ok) {
        check(false, "relayrparkseal: setup");
        return;
    }
    pb::PathbRelayNode& rb = *b.relay;
    const pb::PathbRelayStats& st = rb.stats();
    const std::uint64_t pa = 1;  // A at B
    pb::ReceiptBodyV3 junk = *base;
    junk.side.tip.fill(0x5E);
    const std::optional<std::uint64_t> origin = h[b.node].receipt_origin(junk);
    rb.receive(pa, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{junk}, pb::kRuledLaneParams));
    w.run();
    const std::size_t parked0 = rb.parked_receipts(), asks0 = rb.parked_receipt_asks();
    const std::uint64_t F = h[b.node].config().p.open_bins;
    // A's chain moves up the Monero chain (a carrier's height at most fresh_max above its parent's)
    std::size_t open_steps = 0, held_open = 0;
    for (int i = 0; ok && i < 80; ++i) {
        const std::optional<std::uint64_t> H = h[b.node].best_record();
        if (H && origin && *H >= *origin + F) break;
        h.tick_monero(h[b.node].config().p.fresh_max);
        ok = mine_on(h, w, a.node, 1, 830 + static_cast<std::uint32_t>(i));
        h.now += 1;
        a.relay->tick();
        rb.tick();
        w.run();
        const std::optional<std::uint64_t> H2 = h[b.node].best_record();
        if (H2 && origin && *H2 < *origin + F) {
            ++open_steps;
            held_open += rb.parked_receipts() == 1 ? 1 : 0;
        }
    }
    h.now += 1;
    rb.tick();
    w.run();
    const std::optional<std::uint64_t> H = h[b.node].best_record();
    std::printf("  relayrparkseal: origin %llu, F %llu; parked %zu asks %zu at first; open for %zu steps (parked in %zu); H(L) %llu: "
                "parked %zu asks %zu index %zu, sealed %llu, strikes %llu bans %llu\n",
                (unsigned long long)origin.value_or(0), (unsigned long long)F, parked0, asks0, open_steps, held_open,
                (unsigned long long)H.value_or(0), rb.parked_receipts(), rb.parked_receipt_asks(), rb.parked_index_size(),
                (unsigned long long)st.parked_receipts_sealed.load(), (unsigned long long)rb.strikes_of(pa),
                (unsigned long long)st.bans.load());
    check(ok && origin && parked0 == 1 && asks0 == 1 && open_steps >= 1 && held_open == open_steps,
          "relayrparkseal: a receipt parked on a tip nobody holds stays parked while its origin bin is open");
    check(H && *H >= *origin + F && rb.parked_receipts() == 0 && rb.parked_receipt_asks() == 0 && rb.parked_index_size() == 0
                  && st.parked_receipts_sealed.load() == 1 && rb.strikes_of(pa) == 0 && st.bans.load() == 0,
          "relayrparkseal: once its origin bin seals on the best chain it is dropped with its asks and index entries; no "
          "strike, no ban");
}

// ---------------------------------------------------------------------------
// relayverdictlog: a receipt the relay strikes or refuses logs one line in the BANNED line's form, naming the row and
// the receipt's id: a receipt of another pool identity STRIKEs at R16 (one strike); a share whose origin bin sealed on
// B's best chain before it arrived REFUSEs at R21 (no token). No BANNED line.
void relayverdictlog() {
    const KatNet net;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 800);
    const bool ok0 = ok;
    const std::optional<pb::PathbJob> j0 = h.job(a.node, 2, 810);  // a share on A's tip, sent only below
    ok = ok && j0 && mine_on(h, w, a.node, 1, 820);
    const bool ok1 = ok;
    int steps = 0;
    pb::ReceiptBodyV3 late = j0 ? j0->body : pb::ReceiptBodyV3{};
    late.blob.nonce = 810;
    const std::string id12 = hex(pb::receipt_id(late).data(), 6);
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = 1;  // A at B
    // A's chain moves past the share's origin bin
    const std::optional<std::uint64_t> origin = h[b.node].receipt_origin(late);
    const std::uint64_t F = h[b.node].config().p.open_bins;
    for (int i = 0; ok && origin && i < 80; ++i) {
        const std::optional<std::uint64_t> H = h[b.node].best_record();
        if (H && *H >= *origin + F) break;
        h.tick_monero(h[b.node].config().p.fresh_max);
        ok = mine_on(h, w, a.node, 1, 1830 + static_cast<std::uint32_t>(i));
        ++steps;
        h.now += 1;
        a.relay->tick();
        rb.tick();
        w.run();
    }
    const std::optional<std::uint64_t> H = h[b.node].best_record();
    h.now += 1;
    rb.receive(pa, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{late}, pb::kRuledLaneParams));
    w.run();
    const std::uint64_t strikes0 = rb.strikes_of(pa);
    pb::ReceiptBodyV3 foreign = late;  // then the same body under another pool identity
    foreign.side.pool_id.fill(0x77);
    h.now += 1;
    rb.receive(pa, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{foreign}, pb::kRuledLaneParams));
    w.run();
    const std::uint64_t strikes1 = rb.strikes_of(pa);
    g_relay_lines = nullptr;
    const std::string strike_line = "relay: peer 1 STRIKE: admission row R16 of " + id12;
    const std::string refuse_line = "relay: peer 1 REFUSE: admission row R21 of " + id12;
    std::size_t strikes = 0, refuses = 0, others = 0;
    for (const std::string& l : lines[b.node]) {
        if (l.find(" STRIKE: ") != std::string::npos || l.find(" REFUSE: ") != std::string::npos
            || l.find(" BANNED") != std::string::npos)
            ++(l == strike_line ? strikes : l == refuse_line ? refuses : others);
    }
    std::printf("  relayverdictlog: mined %d %d, %d steps, A at %llu; origin %llu, F %llu, H(L) %llu; strike lines %zu, "
                "refuse lines %zu, others %zu; strikes %llu then %llu, bans %llu\n", ok0 ? 1 : 0, ok1 ? 1 : 0, steps,
                (unsigned long long)h[a.node].best_record().value_or(0), (unsigned long long)origin.value_or(0), (unsigned long long)F, (unsigned long long)H.value_or(0), strikes,
                refuses, others, (unsigned long long)strikes1, (unsigned long long)rb.strikes_of(pa),
                (unsigned long long)rb.stats().bans.load());
    check(ok && origin && H && *H >= *origin + F, "relayverdictlog: setup (the share's bin sealed at B)");
    check(refuses == 1 && strikes0 == 0,
          "relayverdictlog: a share whose origin bin sealed: one line '" + refuse_line + "', no token");
    check(strikes == 1 && strikes1 == strikes0 + 1 && others == 0 && rb.stats().bans.load() == 0,
          "relayverdictlog: the body under another pool identity: one line '" + strike_line + "', 1 strike, no ban");
}

// ---------------------------------------------------------------------------
// relayparkstrike: a carrier parked on an unknown parent and released by the parent's placement (the node's drain)
// logs its STRIKE line as a received frame does: A mines c1 and c2 (c2 carries two receipts) while B gets neither; B
// receives c2 with its carried list out of order, parks it (parent unknown), fetches c1 and places it; the released
// c2 STRIKEs at R28 and B logs one line naming R28 and c2's id.
void relayparkstrike() {
    const KatNet net;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 800);
    const std::optional<pb::PathbJob> j1 = h.job(a.node, 2, 801), j2 = h.job(a.node, 3, 802);
    w.edit = [](FakeWire::Msg& m) {  // A's frames do not reach B
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && j1 && j2 && mine_on(h, w, a.node, 1, 810);  // c1
    const pb::Hash32 c1 = h[a.node].tree().best().id;
    ok = ok && h[a.node].on_own_share(*j1, 801, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && h[a.node].on_own_share(*j2, 802, pb::Hash32{}).action == pb::NodeAction::Pending;
    ok = ok && mine_on(h, w, a.node, 1, 820);  // c2 carries both
    const pb::Hash32 c2 = h[a.node].tree().best().id;
    pb::CarrierBodyV3 bad = *h[a.node].bodies().get(c2);
    ok = ok && bad.carried.size() == 2 && h[b.node].tree().find(c1) == nullptr;
    if (bad.carried.size() == 2) std::swap(bad.carried[0], bad.carried[1]);
    w.run();
    w.edit = nullptr;
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, bad, 16)});
    w.run();
    for (int i = 0; i < 4 && h[b.node].tree().find(c1) == nullptr; ++i) {
        h.now += 1;
        b.relay->tick();
        w.run();
    }
    g_relay_lines = nullptr;
    const std::string want = "relay: peer 1 STRIKE: admission row R28 of " + hex(pb::receipt_id(bad.own).data(), 6);
    std::size_t got = 0;
    for (const std::string& l : lines[b.node]) got += l == want ? 1 : 0;
    std::printf("  relayparkstrike: setup %d, c1 at B %d, c2 at B %d, lines %zu\n", ok ? 1 : 0,
                h[b.node].tree().find(c1) != nullptr ? 1 : 0, h[b.node].tree().find(c2) != nullptr ? 1 : 0, got);
    check(ok && h[b.node].tree().find(c1) != nullptr && h[b.node].tree().find(c2) == nullptr,
          "relayparkstrike: B fetched and placed c1; the misordered c2 is not placed");
    check(got == 1, "relayparkstrike: the released c2 logs one line '" + want + "'");
}

// ---------------------------------------------------------------------------
// repevict: a re-pended receipt the pending set evicts (P-09, 1 here) while watched is counted evicted and leaves the
// watch. A and B race at one position (the links cut); the loser switches and re-pends its own receipt (watched); its
// share on its old tip at a newer Monero height is a receipt in a newer bin: the pending set keeps it and evicts the
// re-pended one; at the winner's next carrier the watch is empty: re-pended 1 = carried 0 + sealed pending 0 +
// evicted 1.
void repevict() {
    const KatNet net;
    Harness h(net);
    h.pending_cap = 1;
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 30 + static_cast<std::uint32_t>(i));
    }
    h.cut = {{a, b}, {b, a}};
    h.tick_monero();
    h.mine(a, 2, 940);
    h.mine(b, 3, 941);
    const pb::Hash32 ca = h[a].tree().best().id, cb = h[b].tree().best().id;
    const std::size_t lnode = ca < cb ? b : a, wnode = ca < cb ? a : b;
    h.tick_monero();
    const std::optional<pb::PathbJob> jl = h.job(lnode, 4, 950);  // the loser's job on its own tip, a newer Monero height
    h.cut.clear();
    (void)h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(cb), pb::kRuledLaneParams.r_max));
    (void)h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(ca), pb::kRuledLaneParams.r_max));
    h.pump();
    const pb::PathbNode::SwitchCounts s1 = h[lnode].switch_counts();
    const bool watched = s1.switches == 1 && s1.repended == 1 && h[lnode].repend_watch_size() == 1;
    const pb::NodeEventResult rq = jl ? h[lnode].on_own_share(*jl, 950, pb::Hash32{}) : pb::NodeEventResult{};
    h.pump();
    h.mine(wnode, 1, 960);
    const pb::PathbNode::SwitchCounts& s2 = h[lnode].switch_counts();
    check(watched && rq.action == pb::NodeAction::Pending && h[lnode].tree().best().id == h[wnode].tree().best().id,
          "repevict: the loser re-pended its receipt (watched " + std::to_string(s1.repended) + "); its next share is a "
          "receipt in a newer bin");
    check(s2.evicted == 1 && s2.carried == 0 && s2.sealed_pending == 0 && h[lnode].repend_watch_size() == 0,
          "repevict: the re-pended receipt evicted by P-09 is counted (evicted " + std::to_string(s2.evicted) +
                  ", carried " + std::to_string(s2.carried) + ", sealed pending " + std::to_string(s2.sealed_pending) +
                  "); the watch is empty (" + std::to_string(h[lnode].repend_watch_size()) + ")");
}

// The open state by hand over node a's best chain (every bin open in these short runs): one placement per own receipt
// and per carried one, each at its v3 wire size.
std::pair<std::uint64_t, std::uint64_t> open_by_hand(Harness& h, std::size_t a) {
    std::uint64_t n = 0, bytes = 0;
    std::vector<std::uint8_t> buf;
    const pb::LaneView v = h[a].store().view_at(h[a].tree().best().id);
    for (std::uint64_t x = 1; v.ok() && x <= v.pos(); ++x) {
        const std::optional<pb::Hash32> id = h[a].store().best_at(x);
        const pb::CarrierBodyV3* c = id ? h[a].bodies().get(*id) : nullptr;
        if (c == nullptr) continue;
        std::vector<const pb::ReceiptBodyV3*> rs{&c->own};
        for (const pb::ReceiptBodyV3& r : c->carried) rs.push_back(&r);
        for (const pb::ReceiptBodyV3* r : rs) {
            buf.clear();
            pb::encode_receipt_body_v3(*r, buf);
            ++n;
            bytes += buf.size();
        }
    }
    return {n, bytes};
}

// openstate: A mines 4 carriers, the last carrying a receipt B left pending; the node's open state equals the sum by
// hand over the best chain's carriers: one placement per own receipt and per carried one, each at its v3 wire size.
void openstate() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 60 + i);
    }
    const std::optional<pb::PathbJob> jb = h.job(b, 2, 70);
    h.mine(a, 1, 63);
    const bool pend = jb && h[b].on_own_share(*jb, 70, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.pump();
    h.mine(a, 1, 64);
    const auto [n, bytes] = open_by_hand(h, a);
    const pb::PathbNode::OpenState o = h[a].open_state();
    check(pend && n >= 5 && o.placements == n && o.bytes == bytes,
          "openstate: the open state at the best tip is " + std::to_string(o.placements) + " placements, " +
                  std::to_string(o.bytes) + " B; by hand " + std::to_string(n) + ", " + std::to_string(bytes) + " B");
}

// opendead: S4.7's open-state bound counts every placement held for the open bins. B's receipt on the older Monero
// height is placed dead after A's carrier at the newer height; the open state counts it with the live ones: 6 of 6
// placements, 2,382 B, as the sum by hand; the liveness line shows it dead.
void opendead() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 60 + i);
    }
    const std::optional<pb::PathbJob> jb = h.job(b, 2, 70);
    h.tick_monero();  // A's next carrier at a newer Monero height: B's receipt (on the older one) dies at that position
    h.mine(a, 1, 63);
    const bool pend = jb && h[b].on_own_share(*jb, 70, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.pump();
    h.mine(a, 1, 64);
    const pb::PathbNode::Liveness lv = h[a].liveness();
    const pb::PathbNode::OpenState o = h[a].open_state();
    const auto [n, bytes] = open_by_hand(h, a);
    check(pend && lv.dead == 1 && lv.live + lv.dead == n,
          "opendead: one dead placement in an open bin (live " + std::to_string(lv.live) + ", dead " + std::to_string(lv.dead) +
                  ")");
    check(o.placements == n && o.bytes == bytes && n == 6 && bytes == 2382,
          "opendead: the open state counts every placement held for the open bins (" + std::to_string(o.placements) +
                  " of " + std::to_string(n) + ", " + std::to_string(o.bytes) + " B of " + std::to_string(bytes) + " B)");
}

// statusperiod: the status line's open state and liveness line come from status_sample, computed once per status
// period. A's carriers carry 6 receipts of B each (B's shares on the tip before); 40 main-loop passes 0.25 s apart over
// 10 s at a 5 s status period evaluate the open state twice; a carrier placed during the first period shows from the
// second; the open state equals the sum by hand (each carrier's bodies encoded once).
void statusperiod() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    h.tick_monero();
    h.mine(a, 1, 1);
    std::uint32_t nonce = 2000;
    for (int k = 0; k < 5; ++k) {
        h.tick_monero();
        const pb::PathbTemplate t = h[b].make_template(h.now);
        std::vector<pb::PathbJob> js;
        if (t.status == pb::TemplateStatus::Ok)
            for (std::uint32_t i = 0; i < 6; ++i)
                if (const std::optional<pb::PathbJob> j = h[b].make_job(t, h.session(2 + (i % 3), nonce + i))) js.push_back(*j);
        h.mine(a, 1, nonce + 100);  // carries the receipts of the round before
        for (std::uint32_t i = 0; i < js.size(); ++i) (void)h[b].on_own_share(js[i], nonce + 200 + i, pb::Hash32{});
        h.pump();
        nonce += 1000;
    }
    std::size_t max_carried = 0;
    for (std::uint64_t x = 1; x <= h[a].tree().best().pos; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
            if (const pb::CarrierBodyV3* c = h[a].bodies().get(*id)) max_carried = std::max(max_carried, c->carried.size());
    const std::uint64_t c0 = h[a].open_state_calls();
    std::uint64_t first = 0, kept = 0;
    pb::PathbNode::StatusSample s{};
    for (int i = 0; i < 40; ++i) {
        s = h[a].status_sample(1000 + static_cast<std::uint64_t>(i / 4), 5);
        if (i == 0) {
            first = s.open.placements;
            h.mine(a, 1, nonce + 1);  // the last receipts carried: placed during the first period
        }
        if (i == 19) kept = s.open.placements;  // 4.75 s: the first period's values
    }
    const std::uint64_t evals = h[a].open_state_calls() - c0;
    const auto [n, bytes] = open_by_hand(h, a);
    const pb::PathbNode::OpenState o = h[a].open_state();
    check(evals == 2 && max_carried == 6 && first > 0 && kept == first && s.open.placements == n && n > first,
          "statusperiod: 40 passes over 2 status periods evaluate the open state " + std::to_string(evals) +
                  " times; the first period keeps its values (" + std::to_string(kept) + " placements), the second shows the "
                  "carrier placed meanwhile (" + std::to_string(s.open.placements) + ")");
    check(o.placements == n && o.bytes == bytes && s.open.bytes == bytes && s.liveness.live + s.liveness.dead == n,
          "statusperiod: the open state is " + std::to_string(o.placements) + " placements, " + std::to_string(o.bytes) +
                  " B; by hand " + std::to_string(n) + ", " + std::to_string(bytes) + " B; the liveness line counts them all");
    const pb::PathbNode::StatusSample& none = h[a].status_sample(2000, 0);
    check(none.open.placements == s.open.placements && h[a].open_state_calls() == c0 + evals + 1,
          "statusperiod: no status period (0): nothing evaluated");
}

// ownorphan: own carriers are watched (J = 4) until confirmed or orphaned. A mines 3 carriers; A and B race at one
// position, the links cut; the loser of the tie counts its carrier orphaned. C extends the winner's chain 6 positions:
// every own carrier A and B watched falls below the journal base: both watches are empty; the counts stay.
void ownorphan() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true, 4), b = h.add(table0(net), true, 4), c = h.add(table0(net), true, 4);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 30 + i);
    }
    const bool three = h[a].own_carriers() == 3 && h[a].own_watch_size() >= 1 && h[a].own_orphaned() == 0;
    h.cut = {{a, b}, {b, a}, {a, c}, {c, a}, {b, c}, {c, b}};
    h.mine(a, 2, 940);
    h.mine(b, 3, 941);
    const pb::Hash32 ca = h[a].tree().best().id, cb = h[b].tree().best().id;
    h.cut.clear();
    const std::vector<std::uint8_t> fa = *pb::encode_fc_carrier(0, *h[a].bodies().get(ca), 16);
    const std::vector<std::uint8_t> fb = *pb::encode_fc_carrier(0, *h[b].bodies().get(cb), 16);
    (void)h[a].on_carrier(b, fb);
    (void)h[b].on_carrier(a, fa);
    (void)h[c].on_carrier(a, fa);
    (void)h[c].on_carrier(b, fb);
    h.pump();
    const pb::Hash32 winner = ca < cb ? ca : cb;
    const std::size_t lnode = ca < cb ? b : a, wnode = ca < cb ? a : b;
    check(three && ca != cb && h[a].tree().best().id == winner && h[b].tree().best().id == winner
                  && h[lnode].own_orphaned() == 1 && h[wnode].own_orphaned() == 0,
          "ownorphan: A's 3 carriers watched; the loser of the race counts its carrier orphaned (" +
                  std::to_string(h[lnode].own_orphaned()) + "), the winner none (" + std::to_string(h[wnode].own_orphaned()) +
                  ")");
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(c, 4, 950 + i);
    }
    check(h[c].tree().best().id == h[a].tree().best().id && h[a].own_watch_size() == 0 && h[b].own_watch_size() == 0
                  && h[a].own_carriers() == 4 && h[lnode].own_orphaned() == 1,
          "ownorphan: C extended the chain past J: A's and B's watches are empty (" + std::to_string(h[a].own_watch_size()) +
                  ", " + std::to_string(h[b].own_watch_size()) + "); A placed " + std::to_string(h[a].own_carriers()) +
                  " own carriers, the loser's orphan count stays 1");
}

// liveness: A mines 4 carriers, B follows: at one tip both print the same liveness hash and counts. A mines one more
// with the links cut: A's hash and live count change, B's stay.
void liveness() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        h.mine(a, 1, 80 + i);
    }
    const pb::PathbNode::Liveness la = h[a].liveness(), lb = h[b].liveness();
    check(h[a].tree().best().id == h[b].tree().best().id && la.live >= 4 && la.hash == lb.hash && la.live == lb.live
                  && la.dead == lb.dead && !(la.hash == pb::Hash32{}),
          "liveness: A and B at one tip print one hash (" + hex_of_bytes(la.hash.data(), la.hash.size()).substr(0, 16) + ", live " +
                  std::to_string(la.live) + ", dead " + std::to_string(la.dead) + ")");
    h.cut = {{a, b}, {b, a}};
    h.mine(a, 1, 84);
    const pb::PathbNode::Liveness la2 = h[a].liveness(), lb2 = h[b].liveness();
    check(!(la2.hash == la.hash) && la2.live == la.live + 1 && lb2.hash == lb.hash,
          "liveness: one more placement at A changes A's hash (" + hex_of_bytes(la2.hash.data(), la2.hash.size()).substr(0, 16) + ", live " +
                  std::to_string(la2.live) + "), B's stays");
}

// wingolden: A mines 6 carriers (B's receipts pending between them); for each job the receipt body, the miner tx
// prefix and hash, the template's window_root and the lane digest after placement go into one hash, equal to the
// recorded golden.
void wingolden() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    std::vector<std::uint8_t> all;
    std::vector<std::uint8_t> buf;
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        if (i % 2 == 1)
            if (const std::optional<pb::PathbJob> jb = h.job(b, 2, 90 + i)) {
                h.mine(a, 1, 120 + i);
                (void)h[b].on_own_share(*jb, 90 + i, pb::Hash32{});
                h.pump();
            }
        const pb::PathbTemplate t = h[a].make_template(h.now);
        const std::optional<pb::PathbJob> j = t.status == pb::TemplateStatus::Ok
                                                  ? std::optional<pb::PathbJob>(h[a].make_job(t, h.session(1, 100 + i)))
                                                  : std::nullopt;
        if (!j) continue;
        buf.clear();
        pb::encode_receipt_body_v3(j->body, buf);
        all.insert(all.end(), buf.begin(), buf.end());
        all.insert(all.end(), j->miner_tx.prefix.begin(), j->miner_tx.prefix.end());
        all.insert(all.end(), j->miner_tx.tx_hash.begin(), j->miner_tx.tx_hash.end());
        all.insert(all.end(), t.window.window_root.begin(), t.window.window_root.end());
        (void)h[a].on_own_share(*j, 100 + i, pb::Hash32{});
        h.pump();
        const std::string ld = h[a].lane_digest();
        all.insert(all.end(), ld.begin(), ld.end());
    }
    const pb::Hash32 g = ::v37::sha256d(all);
    const std::string d = hex_of_bytes(g.data(), g.size());
    check(d == "9e8d753920ed4b11e71a761584fa580cf2d9368ddd50e31c99b6bdc78578abd0", "wingolden: the jobs, coinbases and digests of the fixed run equal the golden (" + d + ")");
    const pb::PathbNode::WindowFlagCounts wf = h[a].window_flags();
    check(wf.evaluated >= 1 && wf.n_dropped_bins == 0 && wf.n_cut_position == 0 && wf.merged_back <= wf.evaluated,
          "wingolden: A counted its evaluated windows (" + std::to_string(wf.evaluated) + "; N-rule drops " +
                  std::to_string(wf.n_dropped_bins) + ", position cuts " + std::to_string(wf.n_cut_position) +
                  ", merge-backs " + std::to_string(wf.merged_back) + ")");
}

// wingoldenmb: wingolden's run with B's receipts paying an owner fee of 1 bp, below the spend floor in A's windows:
// the owner merges back (the flag fires); the job, coinbase and digest bytes equal the recorded golden.
void wingoldenmb() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    pb::PathbNodeConfig cb = h.config(table0(net), true);
    cb.owner_fee_bp = 1;
    cb.owner = net.refs[6];
    const std::size_t b = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cb, h.io(b)));
    std::vector<std::uint8_t> all;
    std::vector<std::uint8_t> buf;
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        if (i % 2 == 1)
            if (const std::optional<pb::PathbJob> jb = h.job(b, 2, 90 + i)) {
                h.mine(a, 1, 120 + i);
                (void)h[b].on_own_share(*jb, 90 + i, pb::Hash32{});
                h.pump();
            }
        const pb::PathbTemplate t = h[a].make_template(h.now);
        const std::optional<pb::PathbJob> j = t.status == pb::TemplateStatus::Ok
                                                  ? std::optional<pb::PathbJob>(h[a].make_job(t, h.session(1, 100 + i)))
                                                  : std::nullopt;
        if (!j) continue;
        buf.clear();
        pb::encode_receipt_body_v3(j->body, buf);
        all.insert(all.end(), buf.begin(), buf.end());
        all.insert(all.end(), j->miner_tx.prefix.begin(), j->miner_tx.prefix.end());
        all.insert(all.end(), j->miner_tx.tx_hash.begin(), j->miner_tx.tx_hash.end());
        all.insert(all.end(), t.window.window_root.begin(), t.window.window_root.end());
        (void)h[a].on_own_share(*j, 100 + i, pb::Hash32{});
        h.pump();
        const std::string ld = h[a].lane_digest();
        all.insert(all.end(), ld.begin(), ld.end());
    }
    const pb::Hash32 g = ::v37::sha256d(all);
    const std::string d = hex_of_bytes(g.data(), g.size());
    check(d == "c1e4ec64760b58567087c386f399e63a2d00732ac62a0f1d325b6e9821623553", "wingoldenmb: the jobs, coinbases and digests of the fixed run equal the golden (" + d + ")");
    const pb::PathbNode::WindowFlagCounts wf = h[a].window_flags();
    check(wf.evaluated >= 1 && wf.merged_back >= 1 && wf.n_dropped_bins == 0 && wf.n_cut_position == 0,
          "wingoldenmb: A's windows merged the owner back (" + std::to_string(wf.merged_back) + " of " +
                  std::to_string(wf.evaluated) + " evaluated)");
}

// relayomit: the per-peer omission log. B holds a receipt pending that never reaches A (B's frames to A dropped); A's
// next carrier, with room, carries none of it: B logs one omission for A's link. B's link to A goes down: the log is
// empty, the total kept.
void relayomit() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 840);
    const std::optional<pb::PathbJob> jb = h.job(b.node, 2, 841);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 1 && m.to == 0) m.f.clear();
    };
    ok = ok && jb && mine_on(h, w, a.node, 1, 842);
    ok = ok && h[b.node].on_own_share(*jb, 841, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    pb::Hash32 q{};
    if (jb) {
        pb::ReceiptBodyV3 rb = jb->body;
        rb.blob.nonce = 841;
        q = pb::receipt_id(rb);
    }
    ok = ok && h[b.node].pending().holds(q) && !h[a.node].pending().holds(q);
    const std::uint64_t before = b.relay->omitted_total();
    ok = ok && mine_on(h, w, a.node, 1, 843);
    w.edit = nullptr;
    w.run();
    const std::uint64_t la = w.id(b.node, a.node);
    const std::map<std::uint64_t, std::uint64_t> om = b.relay->omission_counts();
    check(ok && before == 0 && om.size() == 1 && om.count(la) == 1 && om.at(la) == 1 && b.relay->omitted_total() == 1,
          "relayomit: A's carrier left out B's pending receipt: B logs one omission for A's link (" +
                  std::to_string(om.count(la) ? om.at(la) : 0) + ", links logged " + std::to_string(om.size()) + ")");
    // the verdicts by row: A's carriers placed (no row), and a receipt of A's on a tip nobody holds DEFERred at its row
    if (jb) {
        pb::ReceiptBodyV3 junk = jb->body;
        junk.blob.nonce = 841;
        junk.side.tip.fill(0x6D);
        b.relay->receive(la, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{junk}, pb::kRuledLaneParams));
        w.run();
    }
    const pb::PathbRelayNode::VerdictCounts vc = b.relay->verdict_counts();
    std::uint64_t deferred_rows = 0, carriers = 0;
    std::string seen;
    for (std::size_t row = 0; row < vc.size(); ++row)
        for (std::size_t k = 0; k < vc[row].size(); ++k) {
            if (vc[row][k] != 0) seen += " " + std::to_string(row) + "/" + std::to_string(k) + "=" + std::to_string(vc[row][k]);
            if (row != 0 && k == static_cast<std::size_t>(pb::AdmitVerdict::Defer)) deferred_rows += vc[row][k];
            if (k == static_cast<std::size_t>(pb::AdmitVerdict::AdmitCarrier)) carriers += vc[row][k];
        }
    check(carriers >= 2 && deferred_rows == 1,
          "relayomit: B's verdicts by row: " + std::to_string(carriers) + " carriers placed, " +
                  std::to_string(deferred_rows) + " receipt DEFERred at its row (row/verdict:" + seen + ")");
    w.links[b.node]->disconnect(la);
    w.run();
    check(b.relay->omission_counts().empty() && b.relay->omitted_total() == 1,
          "relayomit: B's link to A went down: the omission log is empty (" +
                  std::to_string(b.relay->omission_counts().size()) + " links), the total kept");
}

// relayomitgone: a carrier run again after its link went down keeps no omission entry. B holds a receipt pending that
// A never gets; A's next carrier (with room, without it) hits a RandomX failure at B and is parked; A's link at B goes
// down (the log is empty); the re-run places the carrier: the omission counts in the total, the log stays empty.
void relayomitgone() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 840);
    const std::optional<pb::PathbJob> jb = h.job(b.node, 2, 841);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 1 && m.to == 0) m.f.clear();
    };
    ok = ok && jb && mine_on(h, w, a.node, 1, 842);
    ok = ok && h[b.node].on_own_share(*jb, 841, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    pb::Hash32 q{};
    if (jb) {
        pb::ReceiptBodyV3 rb = jb->body;
        rb.blob.nonce = 841;
        q = pb::receipt_id(rb);
    }
    ok = ok && h[b.node].pending().holds(q) && !h[a.node].pending().holds(q);
    const std::optional<pb::PathbJob> ja = h.job(a.node, 1, 843);
    ok = ok && ja && h[a.node].on_own_share(*ja, 843, pb::Hash32{}).action == pb::NodeAction::Placed;
    const pb::Hash32 cid = h[a.node].tree().best().id;
    h.throw_pow.insert(cid);  // B's first RandomX call on A's carrier throws: node-internal, parked, run again
    w.run();
    const bool parked = h.throw_pow.count(cid) == 0 && h[b.node].tree().find(cid) == nullptr;
    const std::uint64_t la = w.id(b.node, a.node);
    w.edit = nullptr;
    w.links[b.node]->disconnect(la);
    w.run();
    const bool empty_at_down = b.relay->omission_counts().empty() && b.relay->omitted_total() == 0;
    for (int i = 0; i < 6; ++i) {
        h.now += 1;
        b.relay->tick();
        w.run();
    }
    const bool placed = h[b.node].tree().find(cid) != nullptr;
    const std::map<std::uint64_t, std::uint64_t> om = b.relay->omission_counts();
    check(ok && parked && empty_at_down && placed && !b.relay->peer_known(la),
          "relayomitgone: A's carrier parked on a RandomX failure at B, A's link down, the re-run placed it");
    check(om.empty() && b.relay->omitted_total() == 1,
          "relayomitgone: the re-run's omission counts in the total (" + std::to_string(b.relay->omitted_total()) +
                  "); no entry for the gone link (links logged " + std::to_string(om.size()) + ")");
}

// relayswitchlog: the relay logs one line per switch by the journal and counts a carrier's admission once, on both
// switch paths (relayrepend's scenario): C, cut off, mines X; A mines Y1 and Y2; at the heal Y1 and Y2 reach C in
// order (a direct placement switches) or Y2 alone (parked, then the drain of Y1's placement switches). Both paths: one
// switch line for C's one switch, and C's carrier admissions by row equal.
void relayswitchlog() {
    std::uint64_t admits[2] = {0, 0};
    for (const bool drain : {false, true}) {
        const std::string tag = drain ? "relayswitchlog (b) the drain: " : "relayswitchlog (a) a direct placement: ";
        std::map<std::size_t, std::vector<std::string>> lines;
        g_relay_lines = &lines;
        const KatNet net;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), true);
        KatRelay c = kat_relay(h, w, table0(net), true);
        w.connect(0, 1);
        w.connect(0, 2);
        w.connect(1, 2);
        w.run();
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, 1, 500 + static_cast<std::uint32_t>(i));
        }
        w.edit = [](FakeWire::Msg& m) {
            if (m.from == 2 || m.to == 2) m.f.clear();
        };
        ok = ok && mine_on(h, w, a.node, 2, 510);
        const pb::Hash32 y1 = h[a.node].tree().best().id;
        std::optional<pb::PathbJob> xj;
        std::uint32_t xn = 0;
        for (std::uint32_t n = 520; n < 600 && !xj; ++n) {
            std::optional<pb::PathbJob> j = h.job(c.node, 7, n);
            if (!j) break;
            pb::ReceiptBodyV3 rb = j->body;
            rb.blob.nonce = n;
            const pb::Hash32 id = pb::receipt_id(rb);
            if (drain ? id < y1 : y1 < id) {
                xj = j;
                xn = n;
            }
        }
        ok = ok && xj && h[c.node].on_own_share(*xj, xn, pb::Hash32{}).action == pb::NodeAction::Placed;
        w.run();
        ok = ok && mine_on(h, w, a.node, 3, 511);
        const pb::Hash32 y2 = h[a.node].tree().best().id;
        w.edit = nullptr;
        if (!drain) w.q.push_back(FakeWire::Msg{0, 2, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(y1), 16)});
        w.q.push_back(FakeWire::Msg{0, 2, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(y2), 16)});
        w.run();
        for (int i = 0; i < 3; ++i) {
            h.now += 1;
            c.relay->tick();
            w.run();
        }
        g_relay_lines = nullptr;
        const pb::PathbNode::SwitchCounts& sc = h[c.node].switch_counts();
        std::size_t n_lines = 0;
        for (const std::string& l : lines[c.node]) n_lines += l.find("relay: switch by the journal") != std::string::npos ? 1 : 0;
        const pb::PathbRelayNode::VerdictCounts vc = c.relay->verdict_counts();
        for (std::size_t row = 0; row < vc.size(); ++row)
            admits[drain ? 1 : 0] += vc[row][static_cast<std::size_t>(pb::AdmitVerdict::AdmitCarrier)];
        check(ok && h[c.node].tree().best().id == y2 && sc.switches == 1, tag + "C switched once by its journal");
        check(n_lines == sc.switches, tag + "one switch line per switch (" + std::to_string(n_lines) + " lines, " +
                                              std::to_string(sc.switches) + " switches)");
    }
    check(admits[0] == admits[1] && admits[0] >= 5,
          "relayswitchlog: C's carrier admissions by row equal on both paths (direct " + std::to_string(admits[0]) +
                  ", drain " + std::to_string(admits[1]) + ")");
}

// ---------------------------------------------------------------------------
// j1stale: an empty store J asks S for headers from position 0 (R1); no frame of R1's reply F1 arrives within P-53: R1
// is retired, and J's best moving to position 1 sends S no new request while it is; then F1 arrives: DROP, no verdict,
// nothing indexed; R2 from position 1; a copy of F1 while R2 is open is no reply to R2: DROP, R2 open; R2's own reply
// catches J up. The same `from`: no re-ask goes out while R1 is retired; F1 DROPs and the re-ask then gets its own reply.
void j1stale_chain(Harness& h, const KatNet& net, std::size_t& s, std::size_t& j) {
    s = h.add(table0(net), true);
    j = h.add(table0(net), false);
    h.cut = {{s, j}, {j, s}};
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 700 + static_cast<std::uint32_t>(i));
    }
    h.cut.clear();
    h.q.clear();
}
void j1stale() {
    const KatNet net;
    using K = pb::PathbNode::HeadersOutcome::Kind;
    {
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id, c1 = *h[s].store().best_at(1);
        check(h[s].tree().best().pos == 6 && h[j].tree().best().pos == 0, "j1stale: S at 6, J at position 0");
        check(h[j].request_headers(s, g, tip, 64, h.now), "j1stale: R1 = FC_GETHEADERS(from position 0)");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        h.now += pb::kAbandonTimeoutDefault + 1;
        check(h[j].tick(h.now) == 1, "j1stale: R1 retired (P-53) while F1 has not arrived");
        (void)h[j].on_carrier(s, *pb::encode_fc_carrier(0, *h[s].bodies().get(c1), 16));
        h.q.clear();
        check(h[j].tree().best().id == c1, "j1stale: J's best at position 1");
        check(!h[j].request_headers(s, c1, tip, 64, h.now) && h.q.empty(),
              "j1stale: no new FC_GETHEADERS to S while R1 is retired");
        const pb::PathbNode::HeadersOutcome o0 = h[j].on_headers(s, f1, h.now);
        check(o0.kind == K::Retired && o0.indexed == 0 && pb::PathbNodeTestAccess::headers(h[j]).size() == 0,
              "j1stale: F1 answers the retired R1: DROP, no BAN, nothing indexed (kind "
                      + std::to_string(static_cast<int>(o0.kind)) + ")");
        check(h[j].request_headers(s, c1, tip, 64, h.now), "j1stale: R2 = FC_GETHEADERS(from position 1)");
        const std::vector<std::uint8_t> r2 = h.q.back().frame;
        h.q.clear();
        const pb::PathbNode::HeadersOutcome o1 = h[j].on_headers(s, f1, h.now);  // a copy of F1 S was not asked for
        check(o1.kind == K::Unsolicited && o1.indexed == 0 && pb::PathbNodeTestAccess::headers(h[j]).size() == 0
                      && !o1.why.empty() && h[j].header_slot(s).has_value(),
              "j1stale: F1 is no reply to R2: DROP, no BAN, nothing indexed, R2 open (kind "
                      + std::to_string(static_cast<int>(o1.kind)) + ")");
        const pb::PathbNode::HeadersOutcome o2 = h[j].on_headers(s, h[s].serve_getheaders(j, r2, h.now).frames.at(0), h.now);
        check(o2.kind == K::FetchBodies && o2.fork_pos == 1,
              "j1stale: R2 stays open: its reply is heavier, FC_GETCARRIER of its bodies (kind "
                      + std::to_string(static_cast<int>(o2.kind)) + ")");
        h.pump();
        check(h[j].tree().best().id == tip, "j1stale: J at S's tip");
    }
    {
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id;
        check(h[j].request_headers(s, g, tip, 64, h.now), "j1stale (same from): R1");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        h.now += pb::kAbandonTimeoutDefault + 1;
        check(h[j].tick(h.now) == 1 && !h[j].request_headers(s, g, tip, 64, h.now) && h.q.empty(),
              "j1stale (same from): R1 retired, no re-ask while it is");
        const pb::PathbNode::HeadersOutcome o1 = h[j].on_headers(s, f1, h.now);
        check(h[j].request_headers(s, g, tip, 64, h.now), "j1stale (same from): R2 once F1 arrived");
        const std::vector<std::uint8_t> r2 = h.q.back().frame;
        h.q.clear();
        const pb::PathbNode::HeadersOutcome o2 = h[j].on_headers(s, h[s].serve_getheaders(j, r2, h.now).frames.at(0), h.now);
        check(o1.kind == K::Retired && o2.kind == K::FetchBodies,
              "j1stale (same from): F1 DROPs (its request retired), R2's own reply answers R2 (FetchBodies) (kinds "
                      + std::to_string(static_cast<int>(o1.kind)) + ", " + std::to_string(static_cast<int>(o2.kind)) + ")");
    }
    {
        // a reply that starts at the request and breaks inside: STRIKE (per operator ruling), no BAN, nothing indexed;
        // the reason names the link
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id;
        check(h[j].request_headers(s, g, tip, 64, h.now), "j1stale (break): R1");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        pb::HeadersReply rep;
        (void)pb::decode_fc_headers(f1, 0, h[j].frame_bytes_headers(), pb::kRuledLaneParams, rep);
        std::swap(rep.headers[2], rep.headers[3]);
        const pb::PathbNode::HeadersOutcome o = h[j].on_headers(s, *pb::encode_fc_headers(rep, h[j].frame_bytes_headers()), h.now);
        check(o.kind == K::Strike && o.indexed == 0 && pb::PathbNodeTestAccess::headers(h[j]).size() == 0
                      && o.why.find("link") != std::string::npos,
              "j1stale (break): a link broken inside the reply: STRIKE, no BAN, nothing indexed, the reason names the "
              "link (kind "
                      + std::to_string(static_cast<int>(o.kind)) + ", why '" + o.why + "')");
    }
    {
        // a header failing its PoW at d: BAN, the reason names S1.3 #11
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id;
        h.bad_pow.insert(*h[s].store().best_at(3));
        check(h[j].request_headers(s, g, tip, 64, h.now), "j1stale (pow): R1");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        const pb::PathbNode::HeadersOutcome o = h[j].on_headers(s, f1, h.now);
        check(o.kind == K::Ban && o.why.find("#11") != std::string::npos,
              "j1stale (pow): a header failing its PoW at d: BAN with its reason (why '" + o.why + "')");
    }
}

// ---------------------------------------------------------------------------
// relayj1stale: the same through the relay node's catch-up loop. J HELLOs A; A's first FC_HEADERS to J is held in
// flight; A's carrier 1 reaches J; the tick past P-53 retires the request and the catch-up sends A nothing while it is;
// the held reply arrives: DROP (logged), no ban, the link kept; then the catch-up asks again and J reaches A's tip.
void relayj1stale() {
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false);
    bool mined = true;
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        const std::uint32_t nonce = 950 + static_cast<std::uint32_t>(i);
        const std::optional<pb::PathbJob> jb = h.job(a.node, static_cast<std::size_t>(i % 5), nonce);
        mined = mined && jb && h[a.node].on_own_share(*jb, nonce, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    const pb::Hash32 tip_a = h[a.node].tree().best().id, c1 = *h[a.node].store().best_at(1);
    std::vector<std::uint8_t> held;
    w.edit = [&held](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders && held.empty()) {
            held = m.f;
            m.f.clear();
        }
    };
    w.connect(0, 1);
    w.run();
    pb::PathbRelayNode& rj = *j.relay;
    rj.receive(w.id(j.node, a.node), *pb::encode_fc_carrier(0, *h[a.node].bodies().get(c1), 16));
    w.run();
    const bool moved = h[j.node].tree().best().id == c1;
    h.now += pb::kAbandonTimeoutDefault + 1;
    rj.tick();
    const std::uint64_t asked_retired = rj.stats().catchup_requests.load();
    rj.receive(w.id(j.node, a.node), held);
    rj.pump();
    const std::uint64_t bans = rj.stats().bans.load();
    w.edit = nullptr;
    w.run();
    for (int i = 0; i < 6 && h[j.node].tree().best().id != tip_a; ++i) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    g_relay_lines = nullptr;
    const std::uint64_t asked = rj.stats().catchup_requests.load();
    bool dropped = false;
    for (const std::string& l : lines[j.node])
        if (l.find(" DROP: FC_HEADERS reply to a retired request") != std::string::npos) dropped = true;
    std::printf("  relayj1stale: mined %d, held %zu B, J moved %d, catch-up asks %llu, bans %llu, J at %llu of %llu\n",
                mined ? 1 : 0, held.size(), moved ? 1 : 0, (unsigned long long)asked, (unsigned long long)bans,
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos);
    check(mined && !held.empty() && moved && asked_retired == 1 && asked >= 2,
          "relayj1stale: a held reply, J's best moved; no re-ask while the request is retired (asks "
                  + std::to_string(asked_retired) + "), the re-ask after its reply");
    check(bans == 0 && rj.stats().bans.load() == 0 && dropped && h[j.node].tree().best().id == tip_a,
          "relayj1stale: the late reply DROPs (logged), no ban; J at A's tip");
    {
        // a due ban (a header failing its PoW at d): its BANNED line names S1.3 #11
        std::map<std::size_t, std::vector<std::string>> lines2;
        g_relay_lines = &lines2;
        Harness h2(net);
        FakeWire w2;
        KatRelay a2 = kat_relay(h2, w2, table0(net), true);
        KatRelay j2 = kat_relay(h2, w2, table0(net), false);
        for (int i = 0; i < 6; ++i) {
            if (i % 3 == 0) h2.tick_monero();
            const std::uint32_t nonce = 970 + static_cast<std::uint32_t>(i);
            const std::optional<pb::PathbJob> jb = h2.job(a2.node, static_cast<std::size_t>(i % 5), nonce);
            if (jb) (void)h2[a2.node].on_own_share(*jb, nonce, pb::Hash32{});
        }
        h2.bad_pow.insert(*h2[a2.node].store().best_at(3));
        w2.connect(0, 1);
        w2.run();
        g_relay_lines = nullptr;
        bool reasoned = false, bare = false;
        for (const auto& [n, ls] : lines2)
            for (const std::string& l : ls) {
                if (l.find(" BANNED: ") != std::string::npos && l.find("#11") != std::string::npos) reasoned = true;
                if (l.find(" BANNED") != std::string::npos && l.find(" BANNED: ") == std::string::npos
                    && l.find(" BANNED for ") == std::string::npos)
                    bare = true;
            }
        check(j2.relay->stats().bans.load() >= 1 && reasoned && !bare,
              "relayj1stale (pow): a header failing its PoW: BAN, its BANNED line names S1.3 #11 (bans "
                      + std::to_string(j2.relay->stats().bans.load()) + ")");
    }
}

// ---------------------------------------------------------------------------
// hdrstrike: on the header path a header failing S1.3 #6 (monotone h), #7 (header fields) or #8 (t_origin) is refuse
// + 1 strike, not a ban; nothing of the reply indexed; the relay strikes the server once and keeps the link.
void hdrstrike() {
    const KatNet net;
    using K = pb::PathbNode::HeadersOutcome::Kind;
    const auto run = [&net](const char* tag, const std::function<void(pb::ReceiptBodyV3&)>& edit, const char* row) {
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id;
        check(h[j].request_headers(s, g, tip, 64, h.now), std::string("hdrstrike ") + tag + ": R1");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        pb::HeadersReply rep;
        (void)pb::decode_fc_headers(f1, 0, h[j].frame_bytes_headers(), pb::kRuledLaneParams, rep);
        edit(rep.headers.back().own);  // the last header: no later link reads its id
        const pb::PathbNode::HeadersOutcome o = h[j].on_headers(s, *pb::encode_fc_headers(rep, h[j].frame_bytes_headers()), h.now);
        check(o.kind == K::Strike && o.indexed == 0 && pb::PathbNodeTestAccess::headers(h[j]).size() == 0
                      && o.why.find(row) != std::string::npos,
              std::string("hdrstrike ") + tag + ": STRIKE, nothing indexed, the reason names " + row + " (kind "
                      + std::to_string(static_cast<int>(o.kind)) + ", why '" + o.why + "')");
    };
    run("#7", [](pb::ReceiptBodyV3& b) { b.blob.major = static_cast<std::uint8_t>(b.blob.major + 1); }, "#7");
    run("#8", [](pb::ReceiptBodyV3& b) { b.side.t_origin += 1; }, "#8");
    run("#6", [](pb::ReceiptBodyV3& b) { b.blob.prev_id = mon_block(kPoolH); }, "#6");  // h below the record H
    {
        // the relay: one strike for the server, no ban, the link kept
        std::map<std::size_t, std::vector<std::string>> lines;
        g_relay_lines = &lines;
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay j = kat_relay(h, w, table0(net), false);
        for (int i = 0; i < 6; ++i) {
            if (i % 3 == 0) h.tick_monero();
            const std::uint32_t nonce = 990 + static_cast<std::uint32_t>(i);
            const std::optional<pb::PathbJob> jb = h.job(a.node, static_cast<std::size_t>(i % 5), nonce);
            if (jb) (void)h[a.node].on_own_share(*jb, nonce, pb::Hash32{});
        }
        bool edited = false;
        w.edit = [&h, &edited](FakeWire::Msg& m) {  // A's first FC_HEADERS to J: its last header's t_origin off by one
            if (edited || m.from != 0 || m.to != 1 || m.f.empty() || m.f[0] != pb::kOpFcHeaders) return;
            edited = true;
            pb::HeadersReply rep;
            if (!pb::decode_fc_headers(m.f, 0, h[1].frame_bytes_headers(), pb::kRuledLaneParams, rep).ok() || rep.headers.empty())
                return;
            rep.headers.back().own.side.t_origin += 1;
            m.f = *pb::encode_fc_headers(rep, h[1].frame_bytes_headers());
        };
        w.connect(0, 1);
        w.run();
        w.edit = nullptr;
        g_relay_lines = nullptr;
        const std::uint64_t pa = w.id(j.node, a.node);
        bool logged = false;
        for (const std::string& l : lines[j.node])
            if (l.find(" STRIKE: ") != std::string::npos && l.find("#8") != std::string::npos) logged = true;
        check(j.relay->strikes_of(pa) == 1 && j.relay->stats().bans.load() == 0 && logged,
              "hdrstrike (relay): one strike for the server, no ban, the STRIKE line names #8 (strikes "
                      + std::to_string(j.relay->strikes_of(pa)) + ", bans " + std::to_string(j.relay->stats().bans.load()) + ")");
    }
}

// ---------------------------------------------------------------------------
// hdrseed: on the header path a header whose P_r's seed is not held (S1.3 #11 SeedMissing) DEFERs: no token, no ban,
// nothing indexed; once the seed is held the request asked again reaches the server's tip.
void hdrseed() {
    const KatNet net;
    using K = pb::PathbNode::HeadersOutcome::Kind;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    bool no_seed = true;
    pb::Hash32 hidden{};
    pb::PathbNodeIo io = h.io(1);
    const auto inner = io.seed_of;
    io.seed_of = [&no_seed, &hidden, inner](const pb::Hash32& p_r) -> std::optional<pb::Hash32> {
        if (no_seed && p_r == hidden) return std::nullopt;
        return inner(p_r);
    };
    h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(table0(net), false), std::move(io), nullptr));
    const std::size_t j = 1;
    h.cut = {{s, j}, {j, s}};
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 730 + static_cast<std::uint32_t>(i));
    }
    h.cut.clear();
    h.q.clear();
    const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id;
    hidden = h[s].bodies().get(*h[s].store().best_at(6))->own.blob.prev_id;
    check(h[j].request_headers(s, g, tip, 64, h.now), "hdrseed: R1");
    const pb::PathbNode::HeadersOutcome o1 = h[j].on_headers(s, h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0), h.now);
    h.q.clear();
    check(o1.kind == K::Defer && o1.cause == pb::Missing::Seed && o1.fetch == hidden && o1.indexed == 0
                  && pb::PathbNodeTestAccess::headers(h[j]).size() == 0,
          "hdrseed: the seed of a header's P_r not held: DEFER on that P_r (Seed), nothing indexed, no BAN (kind "
                  + std::to_string(static_cast<int>(o1.kind)) + ")");
    no_seed = false;
    check(h[j].request_headers(s, g, tip, 64, h.now), "hdrseed: asked again once the seed is held");
    const pb::PathbNode::HeadersOutcome o2 = h[j].on_headers(s, h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0), h.now);
    check(o2.kind == K::FetchBodies, "hdrseed: then FetchBodies (kind " + std::to_string(static_cast<int>(o2.kind)) + ")");
    h.pump();
    check(h[j].tree().best().id == tip, "hdrseed: J at S's tip");
}

// ---------------------------------------------------------------------------
// catchpage: the empty-store catch-up beyond one page. A, B and C hold one chain of 1,300 positions (more than
// P-01 = P-47 = 1,152); J, empty, catches up from all three while the wire carries at most 100 frames per second of
// the clock. J reaches the tip; one page in flight per server (catch-up requests bounded by the pages); the bodies
// asked within the deferred store's free room (bodies asked <= the chain + P-47).
void catchpage() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;  // P-14: one FC_HEADERS frame holds a full page of P-01 headers
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.connect(0, 2);
    w.connect(1, 2);
    w.run();
    const std::uint64_t n = 1300;
    bool mined = true;
    for (std::uint64_t i = 0; i < n && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 20000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    const bool held = h[b.node].tree().best().id == tip && h[c.node].tree().best().id == tip;
    KatRelay j = kat_relay(h, w, table0(net), false);
    std::uint64_t bodies_asked = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from != j.links->self || m.f.empty() || m.f[0] != pb::kOpFcGetCarrier) return;
        pb::GetCarrier q;
        if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) bodies_asked += q.ids.size();
    };
    w.connect(3, 0);
    w.connect(3, 1);
    w.connect(3, 2);
    int secs = 0;
    for (; secs < 1800 && h[j.node].tree().best().id != tip; ++secs) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()}) {
            r->tick();
            r->pump();
        }
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    const std::uint64_t asks = j.relay->stats().catchup_requests.load();
    std::printf("  catchpage: mined %d (A at %llu, B and C held %d); J at %llu after %d s; catch-up asks %llu; bodies asked %llu\n",
                mined ? 1 : 0, (unsigned long long)h[a.node].tree().best().pos, held ? 1 : 0,
                (unsigned long long)h[j.node].tree().best().pos, secs, (unsigned long long)asks, (unsigned long long)bodies_asked);
    check(mined && held && h[a.node].tree().best().pos == n, "catchpage: A, B and C at 1,300 positions");
    check(h[j.node].tree().best().id == tip, "catchpage: J reaches the tip");
    check(asks <= 3 * (n / 1152 + 3), "catchpage: one page in flight per server (catch-up asks " + std::to_string(asks) + ")");
    check(bodies_asked <= n + 1152, "catchpage: the bodies asked within the deferred store's free room (bodies asked " + std::to_string(bodies_asked) + ")");
}

// ---------------------------------------------------------------------------
// The catch-up against servers that do not serve the bodies they are asked. catch_chain: A, B and C hold one chain of
// n positions (A mines; B and C follow over the wire). catch_second: one second of the clock, every relay's tick and
// pump, then at most 100 frames on the wire.
bool catch_chain(Harness& h, FakeWire& w, KatRelay& a, KatRelay& b, KatRelay& c, std::uint64_t n, std::uint32_t seed) {
    w.connect(a.node, b.node);
    w.connect(a.node, c.node);
    w.connect(b.node, c.node);
    w.run();
    bool mined = true;
    for (std::uint64_t i = 0; i < n && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), seed + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    return mined && h[b.node].tree().best().id == tip && h[c.node].tree().best().id == tip
           && h[a.node].tree().best().pos == n;
}
void catch_second(Harness& h, FakeWire& w, std::initializer_list<pb::PathbRelayNode*> rs) {
    h.now += 1;
    for (pb::PathbRelayNode* r : rs) {
        r->tick();
        r->pump();
    }
    for (int m = 0; m < 100 && w.step(); ++m) {
    }
}

// catchhold: A, B and C hold 300 positions; A answers J's FC_GETHEADERS first and serves no body (J's FC_GETCARRIER to
// A dropped); B and C serve. J, empty, reaches the tip within 60 s: B and C are asked the bodies.
void catchhold() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    const std::uint64_t n = 300;
    const bool ok = catch_chain(h, w, a, b, c, n, 30000);
    const pb::Hash32 tip = h[a.node].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), false);
    std::uint64_t to[3] = {0, 0, 0};
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from != j.links->self || m.f.empty() || m.f[0] != pb::kOpFcGetCarrier || m.to > 2) return;
        pb::GetCarrier q;
        if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) to[m.to] += q.ids.size();
        if (m.to == 0) m.f.clear();  // A serves no body
    };
    w.connect(3, 0);
    w.connect(3, 1);
    w.connect(3, 2);
    int secs = 0;
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs)
        catch_second(h, w, {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()});
    w.edit = nullptr;
    std::printf("  catchhold: chain %d; J at %llu of %llu after %d s; bodies asked of A %llu, B %llu, C %llu; catch-up asks %llu\n",
                ok ? 1 : 0, (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)n, secs,
                (unsigned long long)to[0], (unsigned long long)to[1], (unsigned long long)to[2],
                (unsigned long long)j.relay->stats().catchup_requests.load());
    check(ok, "catchhold: A, B and C at 300 positions");
    check(h[j.node].tree().best().id == tip && secs <= 60 && to[1] + to[2] > 0,
          "catchhold: J reaches the tip within 60 s although A serves no body (" + std::to_string(secs) + " s)");
}

// catchslow: A, B and C hold 300 positions; A answers J's FC_GETHEADERS first and serves one body every 10 s (in the
// order J asked them); B and C serve. J, empty, reaches the tip within 60 s.
void catchslow() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    const std::uint64_t n = 300;
    const bool ok = catch_chain(h, w, a, b, c, n, 31000);
    const pb::Hash32 tip = h[a.node].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), false);
    std::uint64_t to[3] = {0, 0, 0};
    std::deque<pb::Hash32> pend;
    std::set<pb::Hash32> passing;
    std::optional<pb::GetCarrier> proto;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from != j.links->self || m.f.empty() || m.f[0] != pb::kOpFcGetCarrier || m.to > 2) return;
        pb::GetCarrier q;
        if (!pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) return;
        if (m.to == 0 && q.ids.size() == 1 && passing.erase(q.ids[0]) != 0) return;  // the body A serves now
        to[m.to] += q.ids.size();
        if (m.to != 0) return;
        if (!proto) proto = q;
        for (const pb::Hash32& id : q.ids) pend.push_back(id);
        m.f.clear();
    };
    w.connect(3, 0);
    w.connect(3, 1);
    w.connect(3, 2);
    int secs = 0;
    std::uint64_t last = 0, served = 0;
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs) {
        if (!pend.empty() && h.now >= last + 10 && proto) {
            pb::GetCarrier q1 = *proto;
            q1.ids = {pend.front()};
            pend.pop_front();
            passing.insert(q1.ids[0]);
            if (const std::optional<std::vector<std::uint8_t>> f = pb::encode_fc_getcarrier(q1, pb::kRuledLaneParams)) {
                const std::lock_guard<std::mutex> lk(w.qm);
                w.q.push_back(FakeWire::Msg{j.links->self, 0, *f});
            }
            last = h.now;
            ++served;
        }
        catch_second(h, w, {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()});
    }
    w.edit = nullptr;
    std::printf("  catchslow: chain %d; J at %llu of %llu after %d s; A served %llu; bodies asked of A %llu, B %llu, C %llu; catch-up asks %llu\n",
                ok ? 1 : 0, (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)n, secs,
                (unsigned long long)served, (unsigned long long)to[0], (unsigned long long)to[1],
                (unsigned long long)to[2], (unsigned long long)j.relay->stats().catchup_requests.load());
    check(ok, "catchslow: A, B and C at 300 positions");
    check(h[j.node].tree().best().id == tip && secs <= 60,
          "catchslow: J reaches the tip within 60 s although A serves one body per 10 s (" + std::to_string(secs) + " s)");
}

// catchgone: J's deferred store holds 8. A holds 12 positions of its own branch, answers J's FC_GETHEADERS, serves no
// body, and its link drops once J asked it for bodies (a page in flight); then J links to B and C, which hold another
// chain of 100 positions. A's asks are never answered and leave the store's room at P-53: J reaches the tip of B and C
// within 60 s.
void catchgone() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), false);
    bool ok = true;
    for (std::uint32_t i = 0; i < 12; ++i)  // A's own branch (A linked to nobody)
        ok = ok && mine_on(h, w, a.node, i % 5, 32000 + i);
    w.connect(1, 2);
    w.run();
    const std::uint64_t n = 100;
    for (std::uint64_t i = 0; i < n && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, b.node, static_cast<std::size_t>(i % 5), 32100 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[b.node].tree().best().id;
    ok = ok && h[c.node].tree().best().id == tip && h[b.node].tree().best().pos == n && h[a.node].tree().best().pos == 12;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& cf) { cf.waiting_cap = 8; });
    std::uint64_t asked_a = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from != j.links->self || m.to != 0 || m.f.empty() || m.f[0] != pb::kOpFcGetCarrier) return;
        pb::GetCarrier q;
        if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) asked_a += q.ids.size();
        m.f.clear();  // A serves no body
    };
    w.connect(3, 0);
    int secs = 0;
    for (; secs < 60 && asked_a == 0; ++secs) catch_second(h, w, {a.relay.get(), j.relay.get()});
    j.links->disconnect(w.id(3, 0));
    w.run();
    const int t_gone = secs;
    w.connect(3, 1);
    w.connect(3, 2);
    for (secs = 0; secs < 600 && h[j.node].tree().best().id != tip; ++secs)
        catch_second(h, w, {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()});
    w.edit = nullptr;
    std::printf("  catchgone: chain %d; A asked %llu bodies of its branch, its link dropped at %d s; J at %llu of %llu after %d s; catch-up asks %llu\n",
                ok ? 1 : 0, (unsigned long long)asked_a, t_gone, (unsigned long long)h[j.node].tree().best().pos,
                (unsigned long long)n, secs, (unsigned long long)j.relay->stats().catchup_requests.load());
    check(ok && asked_a == 8, "catchgone: A at 12 of its own, B and C at 100; A asked the store's room (8)");
    check(h[j.node].tree().best().id == tip && secs <= 60,
          "catchgone: J reaches the tip within 60 s after A left with a page in flight (" + std::to_string(secs) + " s)");
}

// catchlost: A, J's only server, holds 100 positions; J's first body request to A (every FC_GETCARRIER frame of its
// first page) is lost on the wire. The page lapses at P-53 and J asks again: J reaches the tip within 60 s.
void catchlost() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    const std::uint64_t n = 100;
    for (std::uint64_t i = 0; i < n && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 33000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), false);
    std::uint64_t requests = 0, lost = 0, first_s = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from != j.links->self || m.f.empty() || m.f[0] != pb::kOpFcGetCarrier) return;
        if (requests++ == 0) first_s = h.now;
        if (h.now == first_s) {  // the first body request lost
            m.f.clear();
            ++lost;
        }
    };
    w.connect(1, 0);
    int secs = 0;
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs) catch_second(h, w, {a.relay.get(), j.relay.get()});
    w.edit = nullptr;
    std::printf("  catchlost: chain %d; J at %llu of %llu after %d s; body request frames %llu, lost %llu; catch-up asks %llu\n",
                ok ? 1 : 0, (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)n, secs,
                (unsigned long long)requests, (unsigned long long)lost,
                (unsigned long long)j.relay->stats().catchup_requests.load());
    check(ok && h[a.node].tree().best().pos == n, "catchlost: A at 100 positions");
    check(h[j.node].tree().best().id == tip && secs <= 60,
          "catchlost: J reaches the tip within 60 s after its first body request was lost (" + std::to_string(secs) + " s)");
}

// catchfull: J's deferred store (cap 4) is full of frames that never resolve: positions 2..6 of E's branch (its
// position 1 never sent), parked on their parents. J then catches up 20 positions from A alone: the room is 0, and at
// least the first missing body per page carries it within 60 s.
void catchfull() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay d = kat_relay(h, w, table0(net), false);
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& c) { c.waiting_cap = 4; });
    KatRelay e = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 6; ++i)  // E's own branch (E linked to nobody)
        ok = ok && mine_on(h, w, e.node, static_cast<std::size_t>(i % 5), 1700 + static_cast<std::uint32_t>(i));
    w.connect(2, 1);
    w.run();
    for (std::uint64_t x = 2; x <= 6; ++x) {
        const std::optional<pb::Hash32> id = h[e.node].store().best_at(x);
        const pb::CarrierBodyV3* body = id ? h[e.node].bodies().get(*id) : nullptr;
        if (body == nullptr) continue;
        j.relay->receive(w.id(2, 1), *pb::encode_fc_carrier(0, *body, 16));
        w.run();
    }
    const std::size_t held = h[j.node].deferred().size();
    for (int i = 0; i < 20; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 1800 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    w.connect(2, 0);
    int secs = 0;
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs)
        catch_second(h, w, {a.relay.get(), d.relay.get(), j.relay.get(), e.relay.get()});
    std::printf("  catchfull: E at %llu, parked at J %zu (cap %llu, waiting %zu); A at %llu; J at %llu after %d s; parked at the end %zu; catch-up asks %llu\n",
                (unsigned long long)h[e.node].tree().best().pos, held, (unsigned long long)h[j.node].deferred_cap(),
                h[j.node].tree().waiting(), (unsigned long long)h[a.node].tree().best().pos,
                (unsigned long long)h[j.node].tree().best().pos, secs, h[j.node].deferred().size(),
                (unsigned long long)j.relay->stats().catchup_requests.load());
    check(ok && held == 4, "catchfull: E at 6, A at 20; J's deferred store full (4 of 4) before the catch-up");
    check(h[j.node].tree().best().id == tip && secs <= 60,
          "catchfull: J reaches the tip within 60 s with a full deferred store (" + std::to_string(secs) + " s)");
}

// relaybindswitch: a carrier the walk of a receipt binds and places is counted as a received frame. A, L and X: L, cut
// off, mines z1 and z2 (carrying nothing) while A and X take A's y1. X gets a receipt of L's on z2 and no carrier of L:
// the receipt's walk fetches the branch's headers and the bind places z1 and z2, switching X to z2 by its journal. X's
// relay logs the switch line and counts every carrier X placed as an admitted carrier once.
void relaybindswitch() {
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    KatRelay x = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.connect(0, 2);
    w.connect(1, 2);
    w.run();
    bool ok = true;
    std::vector<pb::Hash32> ids;
    for (int i = 0; i < 3; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 600 + static_cast<std::uint32_t>(i));
        ids.push_back(h[a.node].tree().best().id);
    }
    w.edit = [](FakeWire::Msg& m) {  // L cut off
        if ((m.from == 1) != (m.to == 1)) m.f.clear();
    };
    ok = ok && mine_on(h, w, a.node, 1, 610);  // y1 at A and X
    ids.push_back(h[a.node].tree().best().id);
    ok = ok && mine_on(h, w, l.node, 3, 620) && mine_on(h, w, l.node, 3, 621);  // z1, z2 at L alone
    const pb::Hash32 z2 = h[l.node].tree().best().id;
    ids.push_back(*h[l.node].store().best_at(h[l.node].tree().best().pos - 1));
    ids.push_back(z2);
    const std::optional<pb::PathbJob> jz = h.job(l.node, 4, 630);
    w.edit = [](FakeWire::Msg& m) {  // L's carriers reach nobody; its headers reach X; A and L stay apart
        if ((m.from == 1 && !m.f.empty() && m.f[0] == pb::kOpFcCarrier) || (m.from == 0 && m.to == 1) ||
            (m.from == 1 && m.to == 0))
            m.f.clear();
    };
    const auto carrier_admits = [&x] {
        const pb::PathbRelayNode::VerdictCounts vc = x.relay->verdict_counts();
        std::uint64_t n = 0;
        for (std::size_t row = 0; row < vc.size(); ++row) n += vc[row][static_cast<std::size_t>(pb::AdmitVerdict::AdmitCarrier)];
        return n;
    };
    const std::uint64_t admits0 = carrier_admits();
    if (jz) {
        pb::ReceiptBodyV3 rz = jz->body;
        rz.blob.nonce = 630;
        x.relay->receive(w.id(x.node, l.node), *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{rz}, pb::kRuledLaneParams));
    }
    w.run();
    for (int i = 0; i < 4 && h[x.node].tree().best().id != z2; ++i) {
        h.now += 1;
        x.relay->tick();
        w.run();
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    std::size_t n_lines = 0;
    for (const std::string& s : lines[x.node]) n_lines += s.find("relay: switch by the journal") != std::string::npos ? 1 : 0;
    const std::uint64_t admits = carrier_admits() - admits0;
    bool held = true;
    for (const pb::Hash32& id : ids) held = held && h[x.node].tree().find(id) != nullptr;
    const pb::PathbNode::SwitchCounts& sc = h[x.node].switch_counts();
    check(ok && jz && held && h[x.node].tree().best().id == z2 && sc.switches == 1 && x.relay->stats().walk_placed.load() == 2,
          "relaybindswitch: the receipt's walk bound and placed z1 and z2 at X (walk placed " +
                  std::to_string(x.relay->stats().walk_placed.load()) + "), X switched once by its journal (" +
                  std::to_string(sc.switches) + ")");
    check(n_lines == 1 && admits == 2,
          "relaybindswitch: X logs one switch line (" + std::to_string(n_lines) + ") and counts the two bound carriers "
          "admitted (" + std::to_string(admits) + ")");
}

// Node a's best carrier as a frame; the frames its mining queued are not delivered.
std::vector<std::uint8_t> best_frame(Harness& h, std::size_t a) {
    h.q.clear();
    return *pb::encode_fc_carrier(0, *h[a].bodies().get(h[a].tree().best().id), pb::kRuledLaneParams.r_max);
}

// omitrules: the omission count of a peer's carrier (E3's carriable list at its parent). B makes 17 receipts A also
// holds: A's carrier carries the first 16 (full): no omission for the 17th. B holds a receipt A never gets: A's next
// carrier, with room, leaves it out: 1. B holds A's next carrier's own receipt pending before the carrier: not counted
// (1, the other receipt).
void omitrules() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 300 + static_cast<std::uint32_t>(i));
    }
    const std::uint64_t r_max = pb::kRuledLaneParams.r_max;
    const pb::PathbTemplate t = h[b].make_template(h.now);
    std::vector<pb::PathbJob> js;
    for (std::uint32_t i = 0; t.status == pb::TemplateStatus::Ok && i < r_max + 1; ++i)
        if (const std::optional<pb::PathbJob> j = h[b].make_job(t, h.session(2 + (i % 3), 500 + i))) js.push_back(*j);
    h.mine(a, 1, 310);
    std::size_t pend = 0;
    for (std::uint32_t i = 0; i < js.size(); ++i)
        pend += h[b].on_own_share(js[i], 600 + i, pb::Hash32{}).action == pb::NodeAction::Pending ? 1 : 0;
    h.pump();
    const bool both = pend == r_max + 1 && h[a].pending().size() == r_max + 1 && h[b].pending().size() == r_max + 1;
    (void)h.mine(a, 1, 311, false);
    const std::vector<std::uint8_t> full = best_frame(h, a);
    const pb::NodeEventResult rf = h[b].on_carrier(a, full);
    const std::size_t carried_full = h[a].bodies().get(h[a].tree().best().id)->carried.size();
    check(both && rf.action == pb::NodeAction::Placed && carried_full == r_max && rf.omitted == 0 && h[b].pending().size() == 1,
          "omitrules: A's carrier carries " + std::to_string(carried_full) + " of B's " + std::to_string(pend) +
                  " receipts (full): no omission for the one left (" + std::to_string(rf.omitted) + ")");
    // a receipt of B's that A never gets
    h.cut = {{b, a}};
    const std::optional<pb::PathbJob> jq = h.job(b, 2, 700);
    h.mine(a, 1, 312);  // carries the 17th
    const bool q_pend = jq && h[b].on_own_share(*jq, 700, pb::Hash32{}).action == pb::NodeAction::Pending &&
                        h[b].pending().size() == 1 && h[a].pending().size() == 0;
    (void)h.mine(a, 1, 313, false);
    const pb::NodeEventResult rq = h[b].on_carrier(a, best_frame(h, a));
    check(q_pend && rq.action == pb::NodeAction::Placed && rq.omitted == 1,
          "omitrules: A's carrier with room leaves out the receipt only B holds: 1 omission (" + std::to_string(rq.omitted) +
                  ")");
    // B holds A's next carrier's own receipt pending first (a receipt relayed before its carrier)
    (void)h.mine(a, 1, 314, false);
    const std::vector<std::uint8_t> fo = best_frame(h, a);
    const pb::ReceiptBodyV3 own = h[a].bodies().get(h[a].tree().best().id)->own;
    const std::vector<pb::NodeEventResult> ro =
            h[b].on_receipts(a, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{own}, pb::kRuledLaneParams));
    const bool own_pend = ro.size() == 1 && ro[0].action == pb::NodeAction::Pending && h[b].pending().size() == 2;
    const pb::NodeEventResult rc = h[b].on_carrier(a, fo);
    check(own_pend && rc.action == pb::NodeAction::Placed && rc.omitted == 1,
          "omitrules: the carrier's own receipt, pending at B before it, is not counted (" + std::to_string(rc.omitted) +
                  " omission, the receipt only B holds)");
}

// omitfresh: E3's Fresh bound. A and B are partitioned after a common tip; A mines c on it; B's branch moves on four
// Monero heights and B holds a receipt q pending on its newer tip. At the heal c reaches B (a side branch): h(q) >
// h(c) + Fresh, so c could not carry q: no omission.
void omitfresh() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 300 + static_cast<std::uint32_t>(i));
    }
    bool ok = h[a].tree().best().id == h[b].tree().best().id;
    h.cut = {{a, b}, {b, a}};
    ok = ok && h.mine(a, 1, 310).action == pb::NodeAction::Placed;
    const pb::Hash32 c = h[a].tree().best().id;
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        ok = ok && h.mine(b, 3, 320 + static_cast<std::uint32_t>(i)).action == pb::NodeAction::Placed;
    }
    const std::optional<pb::PathbJob> jb = h.job(b, 2, 330);
    h.tick_monero();
    ok = ok && h.mine(b, 3, 331).action == pb::NodeAction::Placed;
    const pb::NodeEventResult rq = jb ? h[b].on_own_share(*jb, 330, pb::Hash32{}) : pb::NodeEventResult{};
    ok = ok && rq.action == pb::NodeAction::Pending && h[b].pending().size() == 1;
    std::uint64_t hq = 0;
    for (const pb::PendingReceipt* p : h[b].pending().all()) hq = p->h;
    const pb::CarrierBodyV3* cb = h[a].bodies().get(c);
    const std::optional<std::uint64_t> hc = cb ? h[b].receipt_origin(cb->own) : std::nullopt;
    h.cut.clear();
    const pb::NodeEventResult r = h[b].on_carrier(a, *pb::encode_fc_carrier(0, *cb, pb::kRuledLaneParams.r_max));
    const std::uint64_t fresh = pb::kRuledLaneParams.fresh_max;
    check(ok && r.admit.verdict == pb::AdmitVerdict::AdmitCarrier && hc && hq > *hc + fresh && cb->carried.empty(),
          "omitfresh: A's old carrier admitted at B; h(q) " + std::to_string(hq) + " > h(c) " +
                  std::to_string(hc.value_or(0)) + " + Fresh " + std::to_string(fresh));
    check(r.omitted == 0, "omitfresh: no omission for a receipt the carrier could not carry (" + std::to_string(r.omitted) + ")");
}

// omitopen: E3's open bin at the carrier's parent. B holds a receipt q no other node gets. A's chain moves up the
// Monero chain until q's bin is the oldest open one at B's best x (A's); C, cut from A before x, mines x's sibling p one
// Monero height later (q's bin sealed at p; x stays B's best, the lower id) and then c on p: c reaches B with room and
// without q: no omission (q's bin is sealed at c's parent).
void omitopen() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true), c = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 300 + static_cast<std::uint32_t>(i));
    }
    h.cut = {{b, a}, {b, c}};  // B's frames reach nobody
    const std::optional<pb::PathbJob> jq = h.job(b, 2, 400);
    h.mine(a, 1, 401);
    bool ok = jq && h[b].on_own_share(*jq, 400, pb::Hash32{}).action == pb::NodeAction::Pending;
    std::uint64_t hq = 0;
    for (const pb::PendingReceipt* p : h[b].pending().all()) hq = p->h;
    const std::uint64_t F = pb::kRuledLaneParams.open_bins, fresh = pb::kRuledLaneParams.fresh_max;
    std::uint32_t nonce = 410;
    for (int i = 0; ok && i < 80; ++i) {  // to H(best) = h(q) + F - 2 at B: x's parent
        const std::uint64_t H = h[b].best_record().value_or(0);
        if (H + 2 >= hq + F) break;
        h.tick_monero(std::min<std::uint64_t>(fresh, hq + F - 2 - H));
        ok = h.mine(a, 1, nonce++).action == pb::NodeAction::Placed;
    }
    const std::uint64_t H_g = h[b].best_record().value_or(0);
    h.cut = {{b, a}, {b, c}, {a, c}};
    h.tick_monero();
    ok = ok && h.mine(a, 1, nonce++).action == pb::NodeAction::Placed;  // x: q's bin the oldest open one at B
    const pb::Hash32 x = h[a].tree().best().id;
    const std::uint64_t H_x = h[b].best_record().value_or(0);
    h.tick_monero();
    std::optional<pb::PathbJob> jp;
    std::uint32_t np = 0;
    for (std::uint32_t n = 900; n < 1000 && !jp; ++n) {  // C's sibling p of x with a higher id (x stays best at B)
        std::optional<pb::PathbJob> j = h.job(c, 3, n);
        if (!j) break;
        pb::ReceiptBodyV3 rb = j->body;
        rb.blob.nonce = n;
        if (x < pb::receipt_id(rb)) {
            jp = j;
            np = n;
        }
    }
    ok = ok && jp && h[c].on_own_share(*jp, np, pb::Hash32{}).action == pb::NodeAction::Placed;
    const pb::Hash32 p = h[c].tree().best().id;
    h.pump();
    const pb::CarrierNode* pn = h[b].tree().find(p);
    const bool side = pn != nullptr && h[b].tree().best().id == x && h[b].pending().size() == 1;
    (void)h.mine(c, 3, nonce++, false);
    const pb::NodeEventResult r = h[b].on_carrier(c, best_frame(h, c));
    check(ok && side && H_g + 2 == hq + F && H_x + 1 == hq + F && pn->H >= hq + F,
          "omitopen: q (bin " + std::to_string(hq) + ") open at B's best x (H " + std::to_string(H_x) +
                  "), sealed at its sibling p (H " + std::to_string(pn ? pn->H : 0) + "); F " + std::to_string(F));
    check(r.admit.verdict == pb::AdmitVerdict::AdmitCarrier && r.omitted == 0,
          "omitopen: C's carrier on p reaches B with room and without q: no omission, q's bin sealed at its parent (" +
                  std::to_string(r.omitted) + ")");
}

// omitcompete: a receipt whose tip is a carrier's parent competes for the carrier's own position and is never counted.
// A and B hold A's tip t. Cut apart, A mines c on t and B its own b1 on t; then B's shares of a job on t's parent and
// of one on t are receipts, r2 and rb (tip t), pending at B only. c reaches B with room and carries neither: r2 counts
// (1), rb does not.
void omitcompete() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(a, 1, 300 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::PathbJob> j2 = h.job(b, 2, 400);  // on t's parent
    h.mine(a, 1, 401);                                         // t, at both
    const pb::Hash32 t = h[a].tree().best().id;
    h.cut = {{a, b}, {b, a}};
    const std::optional<pb::PathbJob> jb = h.job(b, 2, 410);  // on t
    (void)h.mine(a, 1, 411, false);                            // c on t, at A only
    const std::vector<std::uint8_t> fc = best_frame(h, a);
    const pb::Hash32 c = h[a].tree().best().id;
    const bool b1 = h.mine(b, 3, 412).action == pb::NodeAction::Placed;  // B's own carrier on t
    const bool r2_pend = j2 && h[b].on_own_share(*j2, 400, pb::Hash32{}).action == pb::NodeAction::Pending;
    const bool rb_pend = jb && h[b].on_own_share(*jb, 410, pb::Hash32{}).action == pb::NodeAction::Pending;
    bool rb_on_t = false;
    for (const pb::PendingReceipt* p : h[b].pending().all()) rb_on_t = rb_on_t || p->body.side.tip == t;
    h.cut.clear();
    h.q.clear();
    const pb::NodeEventResult r = h[b].on_carrier(a, fc);
    check(r2_pend && b1 && rb_pend && rb_on_t && h[b].pending().size() == 2 && h[a].bodies().get(c)->own.side.tip == t &&
                  h[a].bodies().get(c)->carried.empty() && r.admit.verdict == pb::AdmitVerdict::AdmitCarrier,
          "omitcompete: B holds r2 (tip t's parent) and rb (tip t) pending; A's carrier c on t carries neither");
    check(r.omitted == 1, "omitcompete: c's omissions count r2, not rb, which competes for c's position (" +
                                  std::to_string(r.omitted) + ")");
}

// omitwalk: E3's walk condition for an omission (the boundary KAT's shape). r on a side tip t forking at f, pending
// at a node whose best is f + J_0 + 1 (the honest carried list leaves r out there), and r2 on the best chain. A peer's
// carrier c on the best tip with room carries neither: one omission (r2), not two (r's tip forks more than J_0 below
// c's parent).
void omitwalk() {
    const KatNet net;
    KatNode n(net, 1152);
    const std::uint64_t f = 10;
    const auto hb = [](std::uint64_t) { return kLaneB0; };
    std::vector<pb::Hash32> main = scaffold_chain(n, n.tree.genesis().id, f, 0x91, hb);
    const std::vector<pb::Hash32> m2 = scaffold_chain(n, main.back(), 2, 0x95, hb);
    const pb::CarrierBodyV3 tc = scaffold_body(n, main.back(), kLaneB0, 0x92, 777, 3);
    const bool side = place_direct(n, tc).outcome == pb::WriteOutcome::SideBranch;
    const pb::Hash32 t = pb::receipt_id(tc.own);
    const std::uint64_t j0 = pb::admit_j0(pb::kRuledLaneParams);
    scaffold_chain(n, m2.back(), j0 - 2, 0x93, hb);
    const pb::ReceiptBodyV3 r = body_on(n, t, kLaneB0 + 1, 4, 4242);
    const pb::Hash32 on = n.tree.best().id;
    const pb::ReceiptBodyV3 r2 = body_on(n, on, kLaneB0 + 1, 5, 4343);
    scaffold_chain(n, n.tree.best().id, 1, 0x94, hb);
    const pb::CarrierNode& best = n.tree.best();
    Harness h(net);
    h.nodes.push_back(node_from(h, n, 1152, 0));
    pb::PathbNodeTestAccess::add_pending(h[0], pb::PendingReceipt{pb::receipt_id(r), r, kLaneB0 + 1, f + 1, 0});
    pb::PathbNodeTestAccess::add_pending(h[0], pb::PendingReceipt{pb::receipt_id(r2), r2, kLaneB0 + 1, best.pos - 1, 0});
    const std::vector<pb::ReceiptBodyV3> cl = pb::PathbNodeTestAccess::carried(h[0], best.pos + 1, kLaneB0);
    const pb::CarrierBodyV3 c = scaffold_body(n, best.id, kLaneB0, 0x96, 999, 1);
    pb::AdmitResult a;
    a.verdict = pb::AdmitVerdict::AdmitCarrier;
    a.id = pb::receipt_id(c.own);
    a.carrier = c;
    a.store_placements.push_back(pb::admit_detail::placement_of(c.own, a.id, kLaneB0, best.pos + 1));
    const std::uint64_t om = pb::PathbNodeTestAccess::omissions(h[0], a);
    check(side && best.pos == f + j0 + 1 && h[0].pending().size() == 2 && cl.size() == 1 &&
                  pb::receipt_id(cl[0]) == pb::receipt_id(r2),
          "omitwalk: r's tip forks more than J_0 below the best tip, r2 on the chain; the honest carried list holds r2 only");
    check(om == 1, "omitwalk: c's omissions are the honest list's (r2): " + std::to_string(om));
}

// omithonest: an all-honest three-node run charges no omission. A partition {A, B} | {C}: B's receipt rb is carried on
// A's branch Y (y1, y2); C mines X (x1; x2 above y2 in id order; x3). B moves to C's side: X reaches B, which switches
// at x3 by its journal and re-pends rb and Y's own receipts (relayed to C). A, alone, mines y3 on Y; at the heal y3
// reaches B (whose pending receipts are placed on y3's parent chain) and C. Then three rounds: a receipt between
// carriers, each node mining in turn. Every node ends at one tip; no relay logs an omission.
void omithonest() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.connect(0, 2);
    w.connect(1, 2);
    w.run();
    const std::vector<KatRelay*> rs{&a, &b, &c};
    const auto settle = [&] {
        for (int i = 0; i < 4; ++i) {
            h.now += 1;
            for (KatRelay* r : rs) r->relay->tick();
            w.run();
        }
    };
    const auto alone = [&w](std::size_t n) {  // n's frames and the frames to n are dropped
        w.edit = [n](FakeWire::Msg& m) {
            if ((m.from == n) != (m.to == n)) m.f.clear();
        };
    };
    const auto frame_at = [&h](std::size_t n, const pb::Hash32& id) {
        return *pb::encode_fc_carrier(0, *h[n].bodies().get(id), pb::kRuledLaneParams.r_max);
    };
    bool ok = true;
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 1, 100 + static_cast<std::uint32_t>(i));
    }
    alone(c.node);
    const std::optional<pb::PathbJob> jb = h.job(b.node, 2, 200);
    ok = ok && mine_on(h, w, a.node, 1, 201);  // y1
    ok = ok && jb && h[b.node].on_own_share(*jb, 200, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    ok = ok && mine_on(h, w, a.node, 1, 202);  // y2 carries rb
    const pb::Hash32 y2 = h[a.node].tree().best().id;
    ok = ok && h[a.node].bodies().get(y2)->carried.size() == 1;
    ok = ok && mine_on(h, w, c.node, 3, 300);  // x1
    std::optional<pb::PathbJob> xj;
    std::uint32_t xn = 0;
    for (std::uint32_t n = 310; n < 400 && !xj; ++n) {
        std::optional<pb::PathbJob> j = h.job(c.node, 3, n);
        if (!j) break;
        pb::ReceiptBodyV3 rb = j->body;
        rb.blob.nonce = n;
        if (y2 < pb::receipt_id(rb)) {
            xj = j;
            xn = n;
        }
    }
    ok = ok && xj && h[c.node].on_own_share(*xj, xn, pb::Hash32{}).action == pb::NodeAction::Placed;  // x2
    w.run();
    ok = ok && mine_on(h, w, c.node, 3, 401);  // x3
    // B moves to C's side; X reaches B in order
    alone(a.node);
    for (std::uint64_t x = 4; x <= 6; ++x)
        if (const std::optional<pb::Hash32> id = h[c.node].store().best_at(x))
            w.q.push_back(FakeWire::Msg{c.node, b.node, frame_at(c.node, *id)});
    w.run();
    settle();
    const pb::PathbNode::SwitchCounts sb = h[b.node].switch_counts();
    ok = ok && h[b.node].tree().best().id == h[c.node].tree().best().id && sb.switches == 1 && sb.repended == 3;
    ok = ok && mine_on(h, w, a.node, 1, 203);  // y3, A alone
    const pb::Hash32 y3 = h[a.node].tree().best().id;
    w.edit = nullptr;
    w.q.push_back(FakeWire::Msg{a.node, b.node, frame_at(a.node, y3)});
    w.q.push_back(FakeWire::Msg{a.node, c.node, frame_at(a.node, y3)});
    w.run();
    settle();
    const bool y3_held = h[b.node].tree().find(y3) != nullptr && h[c.node].tree().find(y3) != nullptr;
    std::uint32_t nonce = 500;
    for (int r = 0; r < 3; ++r) {
        h.tick_monero();
        KatRelay& m = *rs[static_cast<std::size_t>(r + 1) % 3];
        KatRelay& k = *rs[static_cast<std::size_t>(r + 2) % 3];
        const std::optional<pb::PathbJob> jr = h.job(k.node, 2, nonce++);
        ok = ok && mine_on(h, w, m.node, 1, nonce++);
        ok = ok && jr && h[k.node].on_own_share(*jr, nonce++, pb::Hash32{}).action == pb::NodeAction::Pending;
        w.run();
        settle();
    }
    ok = ok && mine_on(h, w, a.node, 1, nonce++);  // carries the last round's receipt
    settle();
    const pb::Hash32 tip = h[a.node].tree().best().id;
    std::string totals;
    std::uint64_t total = 0, logged = 0;
    bool one_tip = true, none_pending = true;
    for (KatRelay* r : rs) {
        totals += " " + std::to_string(r->relay->omitted_total());
        total += r->relay->omitted_total();
        logged += r->relay->omission_counts().size();
        one_tip = one_tip && h[r->node].tree().best().id == tip;
        none_pending = none_pending && h[r->node].pending().size() == 0;
    }
    check(ok && y3_held && one_tip && none_pending,
          "omithonest: the partition, B's switch, the heal and three rounds ran; every node at one tip, nothing pending (B "
          "re-pended " + std::to_string(sb.repended) + ")");
    check(total == 0 && logged == 0, "omithonest: no relay logs an omission (totals A B C:" + totals + ")");
}

// relayrparkgone: a parked receipt's asks across reconnects. B parks a receipt of an unknown tip sent by A (one ask on
// A's link); three times A's link goes down and a new one comes up (a new link id) and A sends the receipt again: the
// gone link's ask records leave the parked receipt at its link down, so its ask set stays one record (the current
// link's), not one more per reconnect.
void relayrparkgone() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 840);
    const std::optional<pb::PathbJob> j0 = h.job(a.node, 2, 841);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && j0 && mine_on(h, w, a.node, 1, 842);
    ok = ok && h[a.node].on_own_share(*j0, 841, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    std::optional<pb::ReceiptBodyV3> base;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) base = r->body;
    if (!ok || !base) {
        check(false, "relayrparkgone: setup");
        return;
    }
    pb::PathbRelayNode& rb = *b.relay;
    pb::ReceiptBodyV3 junk = *base;
    junk.side.tip.fill(0x6D);
    const std::vector<std::uint8_t> f = *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{junk}, pb::kRuledLaneParams);
    h.now += 1000;
    rb.receive(w.id(b.node, a.node), f);
    w.run();
    const std::size_t asks0 = rb.parked_receipt_asks(), parked0 = rb.parked_receipts();
    std::string trace = std::to_string(asks0);
    bool up = true;
    for (int k = 0; k < 3; ++k) {
        w.links[b.node]->disconnect(w.id(b.node, a.node));
        w.run();
        w.reconnect(a.node, b.node);
        w.run();
        up = up && rb.hello_ok(w.id(b.node, a.node));
        h.now += 1;
        rb.receive(w.id(b.node, a.node), f);
        w.run();
        trace += " " + std::to_string(rb.parked_receipt_asks());
    }
    std::printf("  relayrparkgone: parked %zu -> %zu; asks per round %s (link at B now %llu, HELLO ok %d)\n", parked0,
                rb.parked_receipts(), trace.c_str(), (unsigned long long)w.id(b.node, a.node), up ? 1 : 0);
    check(parked0 == 1 && asks0 == 1 && up && rb.parked_receipts() == 1 && rb.parked_receipt_asks() == 1,
          "relayrparkgone: a parked receipt's asks stay one record across three reconnects of its sender (a gone link's "
          "records stripped at its link down)");
}

// ---------------------------------------------------------------------------
// revjunkbig: the receipt park at the default caps (P-09 = the pending cap, a verify queue of 4,096) under junk: one
// more than the cap's worth of receipts of unknown tips from one peer; the park holds the cap with one ask each. A re-run
// with an honest job queued takes at most the queue's free room and drops no queued job; the rest drain on the ticks,
// each tick within the room; every junk receipt parks again with its asks (no new header request).
void revjunkbig() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 800);
    const std::optional<pb::PathbJob> j0 = h.job(a.node, 2, 810);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && j0 && mine_on(h, w, a.node, 1, 820);
    ok = ok && h[a.node].on_own_share(*j0, 810, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(h[a.node].tree().best().id), 16)});
    w.run();
    std::optional<pb::ReceiptBodyV3> base;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) base = r->body;
    ok = ok && base && h[b.node].tree().best().id == h[a.node].tree().best().id;
    if (!ok) {
        check(false, "revjunkbig: setup");
        return;
    }
    h.now += 1000;
    pb::PathbRelayNode& rb = *b.relay;
    const pb::PathbRelayStats& st = rb.stats();
    const std::uint64_t pa = 1;
    const auto frame_of = [](const pb::ReceiptBodyV3& r) {
        return *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{r}, pb::kRuledLaneParams);
    };
    const std::size_t cap = h[b.node].pending_cap();
    const std::size_t n = cap + 1500;
    const auto t0 = std::chrono::steady_clock::now();
    const std::uint64_t qd_pre = st.queue_dropped.load();
    for (std::size_t q = 0; q < n; ++q) {
        pb::ReceiptBodyV3 r = *base;
        r.side.tip.fill(0x3C);
        std::memcpy(r.side.tip.data(), &q, sizeof q);
        rb.receive(pa, frame_of(r));
        if (q % 1000 == 999) w.run();
    }
    w.run();
    const auto t1 = std::chrono::steady_clock::now();
    const RevPark p0 = revpark(rb);
    std::printf("  revjunkbig: cap %zu, %zu junk sent in %.1f s: parked %zu (drops %llu) asks %zu due %zu index %zu; "
                "queue dropped %llu; tip header requests %llu\n", cap, n,
                std::chrono::duration<double>(t1 - t0).count(), p0.parked,
                (unsigned long long)st.parked_receipt_drops.load(), p0.asks, p0.due, p0.index,
                (unsigned long long)(st.queue_dropped.load() - qd_pre), (unsigned long long)st.tip_header_requests.load());
    rb.receive(pa, frame_of(*base));  // an honest job queued
    const std::size_t vq0 = rb.verify_queue_size();
    const std::uint64_t qd0 = st.queue_dropped.load(), hdr0 = st.tip_header_requests.load();
    rb.test_rerun(pb::Missing::TipUnknown);
    const std::size_t vq1 = rb.verify_queue_size(), due1 = rb.parked_receipts_due();
    w.run();
    const bool honest = h[b.node].pending().holds(pb::receipt_id(*base));
    int ticks = 0;
    for (; ticks < 20 && rb.parked_receipts_due() > 0; ++ticks) {
        h.now += 1;
        rb.tick();
        w.run();
    }
    const auto t2 = std::chrono::steady_clock::now();
    const RevPark p1 = revpark(rb);
    std::printf("  revjunkbig: re-run burst: queue %zu -> %zu, due %zu; honest held %d; ticks to drain %d (%.1f s): parked %zu asks %zu "
                "due %zu index %zu; queue dropped +%llu; tip header requests +%llu\n", vq0, vq1, due1, honest ? 1 : 0, ticks,
                std::chrono::duration<double>(t2 - t1).count(), p1.parked, p1.asks, p1.due, p1.index,
                (unsigned long long)(st.queue_dropped.load() - qd0), (unsigned long long)(st.tip_header_requests.load() - hdr0));
    check(p0.parked == cap && p0.asks == cap && p0.index == cap && p0.due == 0, "revjunkbig: the park holds the cap, one ask each");
    check(vq1 <= 4096 && st.queue_dropped.load() == qd0 && honest, "revjunkbig: the re-run burst within the verify queue's room; the honest job kept");
    check(p1.parked == cap && p1.asks == cap && p1.due == 0 && st.tip_header_requests.load() == hdr0,
          "revjunkbig: the junk re-run and parked again: maps at the cap, no new ask");
}

// ---------------------------------------------------------------------------
// revdueorder: six parked receipts (verify queue 4, pending cap 6), two honest jobs queued: the re-run takes the free
// room (two), the two OLDEST parked receipts first.
void revdueorder() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(
            h, w, table0(net), false, false,
            [](pb::PathbRelayOptions& o) {
                o.peer_valid_capacity = 100;
                o.verify_queue_max = 4;
            },
            [](pb::PathbNodeConfig& c) { c.pending_cap = 6; });
    w.connect(0, 1);
    w.run();
    bool ok = mine_on(h, w, a.node, 1, 800);
    std::vector<pb::PathbJob> jobs;
    for (std::uint32_t q = 0; q < 2; ++q)
        if (const std::optional<pb::PathbJob> j = h.job(a.node, q + 2, 810 + q)) jobs.push_back(*j);
    w.edit = [](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 1) m.f.clear();
    };
    ok = ok && jobs.size() == 2 && mine_on(h, w, a.node, 1, 820);
    for (std::uint32_t q = 0; ok && q < 2; ++q)
        ok = h[a.node].on_own_share(jobs[q], 810 + q, pb::Hash32{}).action == pb::NodeAction::Pending;
    w.run();
    w.edit = nullptr;
    w.q.push_back(FakeWire::Msg{0, 1, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(h[a.node].tree().best().id), 16)});
    w.run();
    std::vector<pb::ReceiptBodyV3> rs;
    for (const pb::PendingReceipt* r : h[a.node].pending().all()) rs.push_back(r->body);
    ok = ok && rs.size() == 2;
    if (!ok) {
        check(false, "revdueorder: setup");
        return;
    }
    h.now += 1000;
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = 1;
    const auto frame_of = [](const pb::ReceiptBodyV3& r) {
        return *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{r}, pb::kRuledLaneParams);
    };
    std::vector<std::vector<std::uint8_t>> junk;
    for (std::uint8_t q = 0; q < 6; ++q) {
        pb::ReceiptBodyV3 r = rs[0];
        r.side.tip.fill(0x77);
        r.side.tip[0] = static_cast<std::uint8_t>(q + 1);
        junk.push_back(frame_of(r));
        rb.receive(pa, junk.back());
        w.run();
    }
    rb.receive(pa, frame_of(rs[0]));
    rb.receive(pa, frame_of(rs[1]));
    rb.test_rerun(pb::Missing::TipUnknown);
    std::string taken;
    for (std::size_t q = 0; q < junk.size(); ++q) taken += rb.receipt_parked(junk[q]) ? "." : "x";
    std::printf("  revdueorder: after the re-run with two honest jobs queued (room 2): taken out of the park %s (oldest first: xx....)\n",
                taken.c_str());
    w.run();
    check(taken == "xx....", "revdueorder: the due receipts run oldest first within the free room");
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

// ---------------------------------------------------------------------------
// relaypace: the join worker's pacing after a NotServed end (threads, loopback TCP, the relay's own ticks; no
// join_step call): a load-failed J (abandon_timeout_s 2) whose one server A answers each join page with one header
// (A's FC_HEADERS frame holds one; J's request could take three) ends every attempt NotServed (a short FC_HEADERS
// reply); the next attempt is never sooner than 2 s after the last one ended.
void relaypace() {
    const KatNet net;
    std::uint64_t one = 0;  // an FC_HEADERS frame of one header
    {
        Harness h0(net);
        const std::size_t n0 = h0.add(table0(net), true);
        h0.tick_monero();
        h0.mine(n0, 0, 900);
        if (const pb::CarrierBodyV3* b = h0[n0].bodies().get(h0[n0].tree().best().id))
            if (const auto f = pb::encode_fc_headers(pb::HeadersReply{0, 1, {pb::header_of(*b)}}, 1u << 22)) one = f->size();
    }
    Harness h(net);
    h.tick_monero();
    std::string why;
    pb::CarrierLinks la, lj;
    pb::PathbRelayOptions oa;
    oa.listen = true;
    oa.listen_host = "127.0.0.1";
    pb::PathbRelayNode ra(oa, la);
    pb::PathbNodeConfig ca = h.config(table0(net), true);
    ca.headers_frame_bytes = one + (one - pb::kHeadersFrameHeadBytes) / 2;  // room for one header, not two
    h.nodes.push_back(std::make_unique<pb::PathbNode>(ca, ra.bind_io(h.io(0))));
    ra.attach(*h.nodes[0]);
    bool mined = one > pb::kHeadersFrameHeadBytes;
    for (int i = 0; i < 3; ++i) {
        const std::optional<pb::PathbJob> jb = h.job(0, static_cast<std::size_t>(i), 900 + i);
        mined = mined && jb && h[0].on_own_share(*jb, 900 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
    }
    const bool sa = ra.start(why);
    using Clk = std::chrono::steady_clock;
    std::mutex lm;
    std::vector<std::pair<Clk::time_point, std::string>> ends;
    pb::PathbRelayOptions oj;
    oj.peers = {{"127.0.0.1", la.listen_port()}};
    oj.join_min_peers = 1;
    pb::PathbRelayNode rj(oj, lj, pb::RelayClock::system(), [&](const std::string& line) {
        if (line.rfind("relay: join attempt", 0) != 0) return;
        std::lock_guard<std::mutex> lk(lm);
        ends.emplace_back(Clk::now(), line);
    });
    pb::PathbNodeConfig cj = h.config(table0(net));
    cj.abandon_timeout_s = 2;
    h.kvs.push_back(std::make_unique<MemoryKv>());
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cj, rj.bind_io(h.io(1)), h.kvs.back().get(), pb::PathbNode::LoadFailed{}));
    rj.attach(*h.nodes[1]);
    const bool sj = rj.start(why);
    std::this_thread::sleep_for(std::chrono::seconds(9));
    rj.stop();
    ra.stop();
    std::vector<std::pair<Clk::time_point, std::string>> e;
    {
        std::lock_guard<std::mutex> lk(lm);
        e = ends;
    }
    std::size_t not_served = 0;
    for (const auto& [t, line] : e)
        if (line.find(": NotServed (") != std::string::npos && line.find("a short FC_HEADERS reply") != std::string::npos)
            ++not_served;
    double min_gap = 1e9;
    for (std::size_t i = 1; i < e.size(); ++i)
        min_gap = std::min(min_gap, std::chrono::duration<double>(e[i].first - e[i - 1].first).count());
    std::printf("  relaypace: attempts %zu (NotServed, short reply %zu) in 9 s; the shortest gap %.2f s\n", e.size(),
                not_served, e.size() > 1 ? min_gap : 0.0);
    check(mined && sa && sj && e.size() >= 2 && not_served == e.size(),
          "relaypace: setup (every attempt NotServed on a short FC_HEADERS reply; " + std::to_string(e.size()) +
                  " attempts)" + (why.empty() ? "" : "; " + why));
    check(e.size() <= 5 && min_gap >= 1.9,
          "relaypace: after a NotServed end the next attempt comes no sooner than P-53 (2 s): " + std::to_string(e.size()) +
                  " attempts in 9 s, the shortest gap " + std::to_string(min_gap) + " s");
}

// ---------------------------------------------------------------------------
// ctxgate: a frame parked on a Monero input runs again only when that input is held, per (cause, id):
//   storm   ten sibling carriers whose own P_r S the follower holds without its weights (a bodiless alternative):
//           50 follower events run none of them again (one context asked for S); a DEFER waiting for the weights of
//           a held block asks none;
//   target  S's weights recorded: one event runs each of S's ten once and places them; a key on another P_r S2
//           without its weights stays;
//   seed    a key on a P_r whose seed is not known stays until the seed is known;
//   sweep   a frame parked on its own P_r X and indexed again on an older P_r Y (a carried receipt's) survives Y's
//           seal and is dropped without strike at X's.
struct SiblingFrame {
    pb::Hash32 id{};
    std::vector<std::uint8_t> frame;
};
SiblingFrame sibling_frame(Harness& h, std::size_t node, std::size_t payee, std::uint32_t nonce) {
    SiblingFrame s;
    const std::optional<pb::PathbJob> j = h.job(node, payee, nonce);
    if (!j) return s;
    pb::CarrierBodyV3 c;
    c.own = j->body;
    c.own.blob.nonce = nonce;
    c.carried = j->carried;
    s.id = pb::receipt_id(c.own);
    s.frame = pb::encode_fc_carrier(0, c, 16).value_or(std::vector<std::uint8_t>{});
    return s;
}
std::function<void(pb::PathbNodeIo&)> hide_inputs(std::set<pb::Hash32>& noweights, std::set<pb::Hash32>& noseed) {
    return [&noweights, &noseed](pb::PathbNodeIo& io) {
        const auto inner = io.resolve_pr;
        io.resolve_pr = [inner, &noweights](const pb::Hash32& p_r) {
            return noweights.count(p_r) != 0 ? pb::PrInfo{} : inner(p_r);  // held, its RowWeights not recorded
        };
        const auto seed = io.seed_of;
        io.seed_of = [seed, &noseed](const pb::Hash32& p_r) -> std::optional<pb::Hash32> {
            if (noseed.count(p_r) != 0) return std::nullopt;
            return seed(p_r);
        };
    };
}
// ---------------------------------------------------------------------------
// parkidx: the park index keeps a digest only while its object waits. A's carriers on a P_r B does not resolve park at
// B, indexed under (MoneroBlock, S). With B's deferred store capped at 4, three times as many frames (12): the store
// evicts past 4, and the index keeps at most the store's frames and 4 more (the prune once 4 digests were indexed);
// a disconnect of A drops no parked frame (only its ask records), and the index keeps the frames the store holds.
void parkidx() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> noweights, noseed;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& c) { c.waiting_cap = 4; },
                           hide_inputs(noweights, noseed));
    bool ok = true;
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 1500 + static_cast<std::uint32_t>(i));
    }
    w.connect(0, 1);
    w.run();
    for (int i = 0; i < 4 && h[b.node].tree().best().id != h[a.node].tree().best().id; ++i) {  // one page in flight
        h.now += 1;
        b.relay->tick();
        w.run();
    }
    ok = ok && h[b.node].tree().best().id == h[a.node].tree().best().id;
    h.tick_monero();
    const pb::Hash32 S = h[a.node].make_template(h.now).p_r;
    noweights.insert(S);
    std::size_t peak = 0;
    for (std::uint32_t k = 0; k < 12; ++k) {
        const SiblingFrame f = sibling_frame(h, a.node, k % 5, 1600 + k);
        b.relay->receive(1, f.frame);
        w.run();
        peak = std::max(peak, b.relay->parked_index_size());
    }
    const std::size_t idx = b.relay->parked_index_size();
    const std::size_t held = h[b.node].deferred().size();
    for (const std::uint64_t p : b.links->peer_ids()) b.links->disconnect(p);
    w.run();
    const std::size_t idx_gone = b.relay->parked_index_size();
    check(ok && held == 4 && peak <= 8 && idx <= 8 && idx >= held && idx_gone == idx,
          "parkidx: twelve frames on a P_r B does not resolve past a deferred store of 4: at most 4 + 4 indexed (peak " +
                  std::to_string(peak) + ", end " + std::to_string(idx) + ", held " + std::to_string(held) +
                  "); A's disconnect keeps the held frames indexed (" + std::to_string(idx_gone) + ")");
}

void ctxgate() {
    const KatNet net;
    {
        Harness h(net);
        FakeWire w;
        std::set<pb::Hash32> noweights, noseed;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, hide_inputs(noweights, noseed));
        bool ok = true;
        for (int i = 0; i < 6; ++i) {
            if (i % 3 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 1100 + static_cast<std::uint32_t>(i));
        }
        w.connect(0, 1);
        w.run();
        ok = ok && h[b.node].tree().best().id == h[a.node].tree().best().id;
        h.tick_monero();
        const pb::Hash32 S = h[a.node].make_template(h.now).p_r;
        noweights.insert(S);
        pb::PathbRelayNode& rb = *b.relay;
        const std::uint64_t wanted0 = rb.stats().ctx_wanted.load();
        std::vector<pb::Hash32> sib;
        for (std::uint32_t k = 0; k < 10; ++k) {
            const SiblingFrame f = sibling_frame(h, a.node, k % 5, 1200 + k);
            sib.push_back(f.id);
            rb.receive(1, f.frame);
            w.run();
        }
        const std::size_t parked = rb.parked_ctx_size(pb::Missing::MoneroBlock, S);
        const std::uint64_t r0 = rb.stats().parked_reruns.load();
        for (int k = 0; k < 50; ++k) {
            rb.on_monero_tip();
            w.run();
            h.now += 1;
            rb.tick();
            w.run();
        }
        const std::uint64_t storm = rb.stats().parked_reruns.load() - r0;
        std::printf("  ctxgate: parked on S %zu; re-runs over 50 events %llu; contexts wanted %llu; held %llu\n", parked,
                    (unsigned long long)storm, (unsigned long long)(rb.stats().ctx_wanted.load() - wanted0),
                    (unsigned long long)rb.stats().ctx_held.load());
        check(ok && parked == 10 && storm == 0 && rb.parked_ctx_size(pb::Missing::MoneroBlock, S) == 10
                      && rb.stats().ctx_wanted.load() <= wanted0 + 1,
              "ctxgate: ten carriers on a P_r held without its weights: 50 follower events run none again, one context "
              "asked (" + std::to_string(storm) + " re-runs, " + std::to_string(rb.stats().ctx_wanted.load() - wanted0) +
                      " wanted)");
        // a DEFER waiting for the weights of a block the follower holds asks no context
        const std::uint64_t held0 = rb.stats().ctx_held.load(), wanted1 = rb.stats().ctx_wanted.load();
        rb.test_parked(1, pb::Missing::MissingWeights, seq32(0x70), S);
        check(rb.stats().ctx_held.load() == held0 + 1 && rb.stats().ctx_wanted.load() == wanted1
                      && rb.parked_ctx_size(pb::Missing::MissingWeights, S) == 1,
              "ctxgate: a DEFER for the weights of a held block asks no context");
        // target: a key on S2 (held, no weights) stays when S resolves
        const pb::Hash32 S2 = mon_block(kPoolH + 3);
        noweights.insert(S2);
        rb.test_parked(1, pb::Missing::MoneroBlock, seq32(0x71), S2);
        noweights.erase(S);
        const std::uint64_t r1 = rb.stats().parked_reruns.load();
        rb.on_monero_tip();
        w.run();
        std::size_t placed = 0;
        for (const pb::Hash32& id : sib) placed += h[b.node].tree().find(id) != nullptr ? 1 : 0;
        check(rb.stats().parked_reruns.load() - r1 == 10 && placed == 10
                      && rb.parked_ctx_size(pb::Missing::MoneroBlock, S) == 0
                      && rb.parked_ctx_size(pb::Missing::MoneroBlock, S2) == 1 && rb.stats().strikes.load() == 0,
              "ctxgate: S's weights recorded: one event runs S's ten once and places them (" + std::to_string(placed) +
                      "); the key on S2 stays");
        // seed: a key on a P_r whose seed is not known
        const pb::Hash32 S3 = mon_block(kPoolH + 4);
        noseed.insert(S3);
        rb.test_parked(1, pb::Missing::Seed, seq32(0x72), S3);
        for (int k = 0; k < 5; ++k) rb.on_monero_tip();
        const std::size_t kept = rb.parked_ctx_size(pb::Missing::Seed, S3);
        noseed.erase(S3);
        rb.on_monero_tip();
        check(kept == 1 && rb.parked_ctx_size(pb::Missing::Seed, S3) == 0,
              "ctxgate: a key on a P_r with no seed stays through five events and runs once its seed is known");
    }
    {  // sweep
        Harness h(net);
        FakeWire w;
        std::set<pb::Hash32> noweights, noseed;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), true, false, nullptr, nullptr, hide_inputs(noweights, noseed));
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            h.tick_monero();
            ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 1400 + static_cast<std::uint32_t>(i));
        }
        w.connect(0, 1);
        w.run();
        ok = ok && h[b.node].tree().best().id == h[a.node].tree().best().id;
        h.tick_monero();
        const pb::Hash32 X = h[a.node].make_template(h.now).p_r;
        const pb::FollowerBranchView mon(net.rows);
        const std::optional<pb::BranchBlock> bx = mon.block(X);
        const std::uint64_t hx = bx ? bx->height : 0;
        const pb::Hash32 Y = mon_block(hx - 40);
        noweights.insert(X);
        noweights.insert(Y);
        pb::PathbRelayNode& rb = *b.relay;
        rb.receive(1, sibling_frame(h, a.node, 1, 1500).frame);
        w.run();
        const std::set<pb::Hash32> ds = rb.parked_ctx_digests(pb::Missing::MoneroBlock, X);
        ok = ok && hx != 0 && ds.size() == 1;
        if (!ok) {
            check(false, "ctxgate: sweep setup (a frame parked on its own P_r)");
            return;
        }
        const pb::Hash32 d = *ds.begin();
        rb.test_parked(1, pb::Missing::MoneroBlock, d, Y);  // also DEFERred on an older P_r (a carried receipt's)
        const std::uint64_t F = pb::kRuledLaneParams.open_bins;
        bool kept_past_y = true, y_passed = false, dropped = false;
        h.tick_monero(2);
        for (std::uint32_t i = 0; i < 160 && !dropped; ++i) {
            h.tick_monero();
            (void)mine_on(h, w, b.node, i % 5, 1600 + i);
            rb.tick();
            w.run();
            const std::uint64_t H = h[b.node].best_record().value_or(0);
            const bool held = h[b.node].deferred().holds(d);
            if (H >= hx - 40 + 1 + F && H < hx + 1 + F) {
                y_passed = true;
                kept_past_y = kept_past_y && held;
            }
            if (H >= hx + 1 + F) dropped = !held;
        }
        check(y_passed && kept_past_y && dropped && rb.stats().parked_frames_sealed.load() == 1
                      && rb.parked_ctx_size(pb::Missing::MoneroBlock, X) == 0 && rb.stats().strikes.load() == 0,
              "ctxgate: a frame indexed on an older P_r survives that bin's seal and is dropped without strike at its own "
              "P_r's (sealed " + std::to_string(rb.stats().parked_frames_sealed.load()) + ")");
    }
}

// ---------------------------------------------------------------------------
// catchjoin: a store not caught up (its record K_NCU) whose catch-up DEFERs on a P_r no node serves, before any PoW:
// the record stays (no reply that DEFERs ends the catch-up), templates continue with the unverified claim noted; once
// the step stays deferred kCtxTtlMs the peer's tip is offered to the joiner; the attempt ends NotServed on that P_r and
// the pair waits on it (no attempt per tick); a new Path B peer releases it once; the P_r resolving releases it and
// the node reaches the tip, caught up, its record gone.
std::function<void(pb::PathbNodeIo&)> hide_blocks(std::set<pb::Hash32>& hidden, const pb::FollowerBranchView& view) {
    return [&hidden, &view](pb::PathbNodeIo& io) {
        const auto inner = io.resolve_pr;
        io.resolve_pr = [inner, &hidden](const pb::Hash32& p_r) {
            return hidden.count(p_r) != 0 ? pb::PrInfo{} : inner(p_r);
        };
        io.monero = &view;
    };
}
// ---------------------------------------------------------------------------
// catchwalk: a join after a parent walk. A's chain of 8 carriers; X, the P_r of positions 4..6, no node serves J. J
// connects (its catch-up DEFERs on X); a new tip of A flooded to J is walked down: J places positions 1..3 and DEFERs
// at 4, so J's best is past position 0 when the step's context runs out. kCtxTtlMs after the step deferred, A's tip is
// still offered to the joiner and attempted.
void catchwalk() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 2500 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::Hash32> c1 = h[a.node].store().best_at(1);
    const std::optional<pb::Hash32> c4 = h[a.node].store().best_at(4);
    const pb::CarrierBodyV3* b1 = c1 ? h[a.node].bodies().get(*c1) : nullptr;
    const pb::CarrierBodyV3* b4 = c4 ? h[a.node].bodies().get(*c4) : nullptr;
    if (!ok || b1 == nullptr || b4 == nullptr || b1->own.blob.prev_id == b4->own.blob.prev_id) {
        check(false, "catchwalk: setup (A's chain, a P_r at 4 apart from 1's)");
        return;
    }
    const pb::Hash32 X = b4->own.blob.prev_id;
    hidden.insert(X);
    KatRelay j = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                           hide_blocks(hidden, hview), true);
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(0, 1);
    w.run();
    ok = mine_on(h, w, a.node, 1, 2590);  // A's new tip, flooded to J: walked down to the P_r J cannot resolve
    for (int k = 0; k < 4; ++k) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    const std::uint64_t walked_pos = h[j.node].tree().best().pos;
    for (int k = 0; k < 125; ++k) {  // 625 s
        h.now += 5;
        rj.tick();
        w.run();
    }
    const std::uint64_t offers = rj.stats().catchup_join_offers.load();
    const std::optional<pb::JoinStep> s1 = rj.join_step();
    w.run();
    std::printf("  catchwalk: J walked to %llu of %llu; join offers %llu; attempts %llu\n", (unsigned long long)walked_pos,
                (unsigned long long)h[a.node].tree().best().pos, (unsigned long long)offers,
                (unsigned long long)rj.stats().join_attempts.load());
    check(ok && walked_pos >= 1 && !h[j.node].caught_up() && offers >= 1 && s1 && s1->report
                  && rj.stats().join_attempts.load() >= 1,
          "catchwalk: J past position 0 after a parent walk (at " + std::to_string(walked_pos) +
                  "): kCtxTtlMs after the step deferred, A's tip is offered to the joiner and attempted (offers " +
                  std::to_string(offers) + ")");
}

void catchjoin() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 2100 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::Hash32> c1 = h[a.node].store().best_at(1);
    const pb::CarrierBodyV3* b1 = c1 ? h[a.node].bodies().get(*c1) : nullptr;
    if (!ok || b1 == nullptr) {
        check(false, "catchjoin: setup (A's chain)");
        return;
    }
    const pb::Hash32 X = b1->own.blob.prev_id;
    hidden.insert(X);
    KatRelay j = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                           hide_blocks(hidden, hview), true);
    MemoryKv& kvj = *h.kvs.back();
    const std::string ncu = pb::store_keys::ncu(0);
    const bool rec0 = kvj.data.count(ncu) != 0;
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(0, 1);
    w.run();
    const pb::TemplateStatus t1 = h[j.node].make_template(h.now).status;
    check(rec0 && kvj.data.count(ncu) != 0 && !h[j.node].caught_up() && h[j.node].tree().best().pos == 0
                  && rj.stats().headers_ctx_deferred.load() >= 1 && t1 != pb::TemplateStatus::CatchingUp
                  && t1 != pb::TemplateStatus::NoPathbPeer && h[j.node].unverified_claims()
                  && h[j.node].joiner().queue().size() == 0,
          "catchjoin: the catch-up DEFERs on a P_r no node serves, before any PoW: not caught up, the record stays, no "
          "template gate (the unverified claim noted), no join yet");
    std::uint64_t offers_before = 0;
    for (int k = 0; k < 125; ++k) {  // 625 s
        h.now += 5;
        rj.tick();
        w.run();
        if (k == 116) offers_before = rj.stats().catchup_join_offers.load();  // 585 s
    }
    check(offers_before == 0 && rj.stats().catchup_join_offers.load() == 1 && h[j.node].joiner().queue().size() == 1,
          "catchjoin: kCtxTtlMs after the step deferred, A's tip is offered to the joiner (" +
                  std::to_string(rj.stats().catchup_join_offers.load()) + ")");
    const std::optional<pb::JoinStep> s1 = rj.join_step();
    w.run();
    const bool ns = s1 && s1->report && s1->report->end == pb::AttemptEnd::NotServed && s1->report->unresolved_pr
                    && *s1->report->unresolved_pr == X;
    const std::uint64_t att1 = rj.stats().join_attempts.load();
    for (int k = 0; k < 20; ++k) {
        h.now += 5;
        rj.tick();
        w.run();
        (void)rj.join_step();
        w.run();
    }
    check(ns && h[j.node].joiner().queue().size() == 1 && h[j.node].joiner().queue().ready() == 0
                  && rj.stats().join_attempts.load() == att1 && att1 >= 1,
          "catchjoin: the attempt ends NotServed on that P_r; the pair waits on it: 20 ticks attempt nothing (attempts " +
                  std::to_string(rj.stats().join_attempts.load()) + ")");
    KatRelay c = kat_relay(h, w, table0(net), true);  // a new Path B peer
    w.connect(2, 1);
    w.run();
    const bool released = h[j.node].joiner().queue().ready() == 1;
    const std::optional<pb::JoinStep> s2 = rj.join_step();
    w.run();
    check(released && s2 && s2->report && s2->report->end == pb::AttemptEnd::NotServed
                  && h[j.node].joiner().queue().ready() == 0 && !h[j.node].caught_up(),
          "catchjoin: a new Path B peer releases the waiting pair once: one attempt, NotServed again, waiting again");
    hidden.erase(X);
    rj.on_monero_tip();
    w.run();
    for (int k = 0; k < 12 && h[j.node].tree().best().id != h[a.node].tree().best().id; ++k) {
        (void)rj.join_step();
        w.run();
        h.now += 1;
        rj.tick();
        w.run();
    }
    for (int k = 0; k < 3; ++k) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    std::printf("  catchjoin: J at %llu of %llu; caught up %d; releases %llu; attempts %llu\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos,
                h[j.node].caught_up() ? 1 : 0, (unsigned long long)rj.stats().join_releases.load(),
                (unsigned long long)rj.stats().join_attempts.load());
    bool rec_gone = true;
    for (const auto& kv : h.kvs) rec_gone = rec_gone && (kv.get() != &kvj || kvj.data.count(ncu) == 0);
    check(h[j.node].tree().best().id == h[a.node].tree().best().id && h[j.node].caught_up() && rec_gone
                  && rj.stats().join_releases.load() >= 1 && rj.stats().strikes.load() == 0 && rj.stats().bans.load() == 0,
          "catchjoin: the P_r resolves: the pair released, J reaches A's tip, caught up, its record gone; no token");
    (void)c;
}

// ---------------------------------------------------------------------------
// catchgate: the template gate of a store not caught up reads verified header work only:
//   round     the first catch-up round in flight (a peer whose replies never come): CatchingUp; no reply within P-53
//             ends it; a later connection never opens it again;
//   verified  headers J verified win while their bodies are in flight: CatchingUp; no progress within P-53 lapses it,
//             and that tip does not hold the gate again;
//   caught    a node caught up (its record gone) whose peer reconnects every 11 s with heavier verified headers and
//             bodies in flight: templates continue.
pb::TemplateStatus tstatus(Harness& h, std::size_t i) { return h[i].make_template(h.now).status; }
void catchgate() {
    const KatNet net;
    const auto drop = [](std::uint8_t op) {
        return [op](FakeWire::Msg& m) {
            if (m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == op) m.f.clear();
        };
    };
    {  // round
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        bool ok = true;
        for (int i = 0; i < 4; ++i) ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 2300 + static_cast<std::uint32_t>(i));
        KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
        w.edit = drop(pb::kOpFcHeaders);
        w.connect(0, 1);
        w.run();
        const pb::TemplateStatus s1 = tstatus(h, j.node);
        const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
        for (std::uint64_t k = 0; k <= p53 + 1; ++k) {
            h.now += 1;
            j.relay->tick();
            w.run();
        }
        const pb::TemplateStatus s2 = tstatus(h, j.node);
        w.links[1]->disconnect(w.id(1, 0));
        w.run();
        w.reconnect(0, 1);
        w.run();
        const pb::TemplateStatus s3 = tstatus(h, j.node);
        w.edit = nullptr;
        check(ok && s1 == pb::TemplateStatus::CatchingUp && s2 != pb::TemplateStatus::CatchingUp
                      && s3 != pb::TemplateStatus::CatchingUp && !h[j.node].caught_up(),
              "catchgate: the first round in flight holds templates (CatchingUp); no reply within P-53 ends it; a later "
              "connection does not open it again (" + std::to_string(static_cast<int>(s1)) + "/" +
                      std::to_string(static_cast<int>(s2)) + "/" + std::to_string(static_cast<int>(s3)) + ")");
    }
    {  // verified
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        bool ok = true;
        for (int i = 0; i < 4; ++i) ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 2400 + static_cast<std::uint32_t>(i));
        KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
        w.edit = drop(pb::kOpFcCarrier);
        w.connect(0, 1);
        w.run();
        const pb::TemplateStatus s1 = tstatus(h, j.node);
        const bool round_over = !h[j.node].first_round_open();
        const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
        bool held = true;
        for (std::uint64_t k = 0; k < p53 + 2 * p53 + 4; ++k) {
            h.now += 1;
            j.relay->tick();
            w.run();
            if (k + 2 < p53) held = held && tstatus(h, j.node) == pb::TemplateStatus::CatchingUp;
        }
        const pb::TemplateStatus s2 = tstatus(h, j.node);
        w.edit = nullptr;
        check(ok && round_over && s1 == pb::TemplateStatus::CatchingUp && held && s2 != pb::TemplateStatus::CatchingUp,
              "catchgate: verified heavier headers whose bodies are in flight hold templates; no progress within P-53 "
              "lapses it and the same tip does not hold them again (" + std::to_string(static_cast<int>(s2)) + ")");
    }
    {  // caught
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        bool ok = true;
        for (int i = 0; i < 4; ++i) ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 2500 + static_cast<std::uint32_t>(i));
        KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
        MemoryKv& kvj = *h.kvs.back();
        w.connect(0, 1);
        w.run();
        for (int k = 0; k < 3; ++k) {
            h.now += 1;
            j.relay->tick();
            w.run();
        }
        const bool caught = h[j.node].caught_up() && kvj.data.count(pb::store_keys::ncu(0)) == 0
                            && h[j.node].tree().best().id == h[a.node].tree().best().id;
        bool cont = true;
        for (int r = 0; r < 3; ++r) {
            w.links[1]->disconnect(w.id(1, 0));
            w.run();
            ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(r), 2600 + static_cast<std::uint32_t>(r));
            h.now += 11;
            w.edit = drop(pb::kOpFcCarrier);
            w.reconnect(0, 1);
            w.run();
            cont = cont && tstatus(h, j.node) != pb::TemplateStatus::CatchingUp;
            w.edit = nullptr;
        }
        check(ok && caught && cont, "catchgate: a node caught up (its record gone) keeps its templates while its peer "
                                    "reconnects every 11 s with heavier headers and bodies in flight");
    }
}

// ---------------------------------------------------------------------------
// catchrestart: a store not caught up keeps its record across a restart: J placed three carriers by a partial walk,
// restarted with no peer: NoPathbPeer; a peer whose claim wins opens the first round (CatchingUp) and P-53 with nothing
// in flight ends it; caught up, the record leaves and a restart builds templates; a launch node writes no record.
void catchrestart() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        h.mine(a, static_cast<std::size_t>(i), 2700 + static_cast<std::uint32_t>(i));
    }
    const std::size_t jn = h.add(table0(net), false, 1152, true);
    MemoryKv& kvj = *h.kvs.back();
    const std::string ncu = pb::store_keys::ncu(0);
    for (std::uint64_t x = 1; x <= 3; ++x) {
        const std::optional<pb::Hash32> id = h[a].store().best_at(x);
        if (id) (void)h[jn].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
        h.pump();
    }
    const bool walked = h[jn].tree().best().pos == 3 && !h[jn].caught_up() && kvj.data.count(ncu) != 0;
    const std::size_t j2 = load_node(h, kvj, h.config(table0(net)));
    MemoryKv& kv2 = *h.kvs.back();
    const pb::TemplateStatus s0 = tstatus(h, j2);
    h.hello(j2, a);
    const pb::TemplateStatus s1 = tstatus(h, j2);
    const std::uint64_t p53 = h[j2].config().abandon_timeout_s;
    h[j2].tick(h.now);
    h.now += p53 + 1;
    h[j2].tick(h.now);
    const pb::TemplateStatus s2 = tstatus(h, j2);
    check(walked && h[j2].tree().best().pos == 3 && !h[j2].caught_up() && s0 == pb::TemplateStatus::NoPathbPeer
                  && s1 == pb::TemplateStatus::CatchingUp && s2 != pb::TemplateStatus::CatchingUp
                  && s2 != pb::TemplateStatus::NoPathbPeer,
          "catchrestart: restarted at position 3 not caught up: no template with no peer; the first round with a peer; "
          "P-53 with nothing in flight ends it (" + std::to_string(static_cast<int>(s0)) + "/" +
                  std::to_string(static_cast<int>(s1)) + "/" + std::to_string(static_cast<int>(s2)) + ")");
    h[j2].note_caught_up();
    const std::size_t j3 = load_node(h, kv2, h.config(table0(net)));
    const std::size_t al = h.add(table0(net), true, 1152, true);
    MemoryKv& kva = *h.kvs.back();
    const std::size_t a2 = load_node(h, kva, h.config(table0(net), true));
    check(kv2.data.count(ncu) == 0 && h[j3].caught_up() && tstatus(h, j3) != pb::TemplateStatus::NoPathbPeer
                  && kva.data.count(ncu) == 0 && h[al].caught_up() && h[a2].caught_up()
                  && tstatus(h, a2) == pb::TemplateStatus::Ok,
          "catchrestart: caught up, the record leaves and a restart builds templates; a launch node writes none");
}

// ---------------------------------------------------------------------------
// catchlocator: after a partition B's own branch is unknown at A: the catch-up from B's tip gets empty replies and
// steps down B's chain (pos - 1, pos - 2, pos - 4) to a carrier A holds, then follows A's heavier chain.
void catchlocator() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false);
    bool ok = true;
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 2800 + static_cast<std::uint32_t>(i));
    }
    w.connect(0, 1);
    w.run();
    ok = ok && h[b.node].tree().best().id == h[a.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, b.node, static_cast<std::size_t>(i), 2900 + static_cast<std::uint32_t>(i));
    }
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 3000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip_a = h[a.node].tree().best().id;
    ok = ok && h[b.node].tree().best().pos == 9 && h[a.node].tree().best().pos == 12;
    w.reconnect(0, 1);
    w.run();
    for (int k = 0; k < 6 && h[b.node].tree().best().id != tip_a; ++k) {
        h.now += 1;
        b.relay->tick();
        w.run();
    }
    check(ok && h[b.node].tree().best().id == tip_a && b.relay->stats().catchup_steps.load() >= 3
                  && b.relay->stats().strikes.load() == 0,
          "catchlocator: B's catch-up from its own tip steps down its chain to a carrier A holds and reaches A's tip "
          "(steps " + std::to_string(b.relay->stats().catchup_steps.load()) + ")");
}

// ---------------------------------------------------------------------------
// The parent ask of a ParentUnknown DEFER (S1.3 #3, "DEFER + FC_GETCARRIER(tip)"): FC_GETCARRIER(parent) goes out only
// for a frame parked now (a copy held already asks nothing), whose parent is neither held nor parked, and which was not
// asked within P-53.
//
// pwalk_run: A, B and C hold one chain of n positions; J, empty, links to all three and catches up headers first while
// A mines k new tips, one every 2 s, each reaching J from A, B and C. The wire carries at most `per_s` frames per second
// of the clock; the servers' FC_HEADERS replies to J arrive `hold_s` seconds after they are sent (within P-53). The run
// ends with J at A's tip after the k tips, at 1,800 s, or once J's R4 DEFERs pass `stop_r4`. `prefill`: before the links,
// A's top `prefill` carriers reach J from A, newest first (each a ParentUnknown DEFER parked at J, not counted in R4).
struct PwalkRun {
    bool chain = false, mined = true, at_tip = false;
    std::uint64_t tips = 0, r4 = 0, r17 = 0, parent_asks = 0, reasks = 0, catchup = 0, strikes = 0, bans = 0, a_pos = 0, j_pos = 0;
    std::uint64_t cu_end_pos = 0;  // J's best when the catch-ups toward A, B and C had all ended (0: not seen)
    std::size_t deferred = 0, peak = 0, cap = 0, prefilled = 0;
    int secs = 0;
};
PwalkRun pwalk_run(std::uint64_t n, std::uint64_t k, std::uint64_t per_s, std::uint64_t hold_s, std::uint64_t stop_r4,
                   std::uint32_t seed, std::size_t prefill = 0) {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;  // P-14: one FC_HEADERS frame holds a full page of P-01 headers
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    PwalkRun out;
    out.chain = catch_chain(h, w, a, b, c, n, seed);
    KatRelay j = kat_relay(h, w, table0(net), false);
    const auto r4 = [&j] {
        return j.relay->verdict_counts()[static_cast<std::size_t>(pb::RowId::R4)][static_cast<std::size_t>(pb::AdmitVerdict::Defer)];
    };
    std::deque<std::pair<std::uint64_t, FakeWire::Msg>> held;  // the servers' FC_HEADERS to J, by arrival time
    std::size_t pass = 0;                                      // released frames at the front of the wire
    w.edit = [&](FakeWire::Msg& m) {
        if (pass > 0) {
            --pass;
            return;
        }
        if (m.to != j.links->self || m.f.empty() || m.f[0] != pb::kOpFcHeaders) return;
        held.emplace_back(h.now + hold_s, m);
        m.f.clear();
    };
    if (prefill > 0) {
        const std::uint64_t pa = w.id(j.node, a.node);
        std::vector<pb::Hash32> top;
        for (const pb::CarrierNode* x = &h[a.node].tree().best(); x != nullptr && x->pos > 0 && top.size() < prefill;
             x = h[a.node].tree().find(x->parent))
            top.push_back(x->id);
        for (const pb::Hash32& id : top) (void)h[j.node].on_carrier(pa, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(id), 16));
        out.prefilled = h[j.node].deferred().size();
    }
    w.connect(j.node, a.node);
    w.connect(j.node, b.node);
    w.connect(j.node, c.node);
    bool cu_seen = false;
    for (; out.secs < 1800 && r4() <= stop_r4; ++out.secs) {
        if (out.tips < k && out.secs % 2 == 1) {  // A's new tip, flooded; the wire carries it with the rest
            if (out.tips % 12 == 0) h.tick_monero();
            const std::uint32_t nonce = seed + 1000000 + static_cast<std::uint32_t>(out.tips);
            const std::optional<pb::PathbJob> jb = h.job(a.node, static_cast<std::size_t>(out.tips % 5), nonce);
            out.mined = out.mined && jb && h[a.node].on_own_share(*jb, nonce, pb::Hash32{}).action == pb::NodeAction::Placed;
            ++out.tips;
        }
        if (out.tips == k && h[j.node].tree().best().id == h[a.node].tree().best().id) break;
        h.now += 1;
        std::vector<FakeWire::Msg> due;
        while (!held.empty() && held.front().first <= h.now) {
            due.push_back(std::move(held.front().second));
            held.pop_front();
        }
        for (auto it = due.rbegin(); it != due.rend(); ++it) w.q.push_front(std::move(*it));
        pass += due.size();
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()}) {
            r->tick();
            r->pump();
        }
        for (std::uint64_t m = 0; m < per_s && w.step(); ++m) {
        }
        out.peak = std::max(out.peak, h[j.node].deferred().size());
        if (out.cu_end_pos == 0) {
            bool open = false;
            for (const KatRelay* x : {&a, &b, &c}) open = open || j.relay->catchup_view(w.id(j.node, x->node)).has_value();
            if (open) cu_seen = true;
            else if (cu_seen) out.cu_end_pos = h[j.node].tree().best().pos;
        }
    }
    w.edit = nullptr;
    out.at_tip = h[j.node].tree().best().id == h[a.node].tree().best().id;
    out.r4 = r4();
    out.r17 = j.relay->verdict_counts()[static_cast<std::size_t>(pb::RowId::R17)][static_cast<std::size_t>(pb::AdmitVerdict::Defer)];
    out.parent_asks = h[j.node].parent_asks();
    out.reasks = h[j.node].parent_reasks();
    out.catchup = j.relay->stats().catchup_requests.load();
    out.a_pos = h[a.node].tree().best().pos;
    out.j_pos = h[j.node].tree().best().pos;
    out.deferred = h[j.node].deferred().size();
    out.cap = h[j.node].deferred_cap();
    for (const KatRelay* x : {&a, &b, &c, &j}) {
        out.strikes += x->relay->stats().strikes.load();
        out.bans += x->relay->stats().bans.load();
    }
    return out;
}
void pwalk_print(const char* tag, const PwalkRun& r, std::uint64_t bound) {
    std::printf("  %s: chain %d (A at %llu); tips %llu; J at %llu after %d s; R4 DEFERs %llu (bound %llu); R17 %llu; parent "
                "asks %llu (re-asks %llu); the catch-ups all ended at %llu; deferred %zu (at most %zu); catch-up asks %llu; "
                "strikes %llu, bans %llu\n",
                tag, r.chain ? 1 : 0, (unsigned long long)r.a_pos, (unsigned long long)r.tips, (unsigned long long)r.j_pos,
                r.secs, (unsigned long long)r.r4, (unsigned long long)bound, (unsigned long long)r.r17,
                (unsigned long long)r.parent_asks, (unsigned long long)r.reasks, (unsigned long long)r.cu_end_pos, r.deferred,
                r.peak, (unsigned long long)r.catchup, (unsigned long long)r.strikes, (unsigned long long)r.bans);
}

// pwalk: N = 3,000 positions (more than P-47 = J_0 = 1,152), K = 30 tips; the wire carries at most 1,000 frames per
// second, the FC_HEADERS replies arrive 8 s after they are sent. J reaches A's tip at N + K; its R4 DEFERs within
// N + 3K + J_0; the catch-ups toward A, B and C all end at or after their HELLO tip (N); 0 strikes, 0 bans.
void pwalk_checks(const char* tag, const PwalkRun& r, std::uint64_t n, std::uint64_t k, std::uint64_t bound) {
    const std::string t = tag;
    check(r.chain && r.mined && r.tips == k, t + ": A, B and C at 3,000 positions; A mines 30 tips during J's catch-up");
    check(r.at_tip && r.j_pos == n + k, t + ": J reaches A's tip at N + K (" + std::to_string(r.j_pos) + ")");
    check(r.r4 <= bound, t + ": J's R4 DEFERs within N + 3K + J_0 (" + std::to_string(r.r4) + " of " + std::to_string(bound) + ")");
    check(r.cu_end_pos >= n, t + ": the catch-ups all end at or after the HELLO tip (at " + std::to_string(r.cu_end_pos) + ")");
    check(r.strikes == 0 && r.bans == 0, t + ": 0 strikes, 0 bans");
}
void pwalk() {
    const std::uint64_t n = 3000, k = 30, bound = n + 3 * k + pb::admit_j0(pb::kRuledLaneParams);
    const PwalkRun r = pwalk_run(n, k, 1000, 8, 4 * bound, 44000);
    pwalk_print("pwalk", r, bound);
    pwalk_checks("pwalk", r, n, k, bound);
}

// pwalkshapes: the pwalk chain over wire / FC_HEADERS reply shapes (frames per second / seconds after the send): 1,000 / 8,
// 500 / 8, 1,000 / 10, 1,500 / 8, 2,000 / 5; each as pwalk. One section per shape (pwalkshapes_<per_s>_<hold>).
template <std::uint64_t per_s, std::uint64_t hold>
void pwalkshapes() {
    const std::uint64_t n = 3000, k = 30, bound = n + 3 * k + pb::admit_j0(pb::kRuledLaneParams);
    const PwalkRun r = pwalk_run(n, k, per_s, hold, 4 * bound, 44000);
    const std::string tag = "pwalkshapes " + std::to_string(per_s) + " / " + std::to_string(hold);
    pwalk_print(tag.c_str(), r, bound);
    pwalk_checks(tag.c_str(), r, n, k, bound);
}

// pwalkfull: the pwalk chain at 500 frames per second, the FC_HEADERS replies 8 s after they are sent: J's deferred
// store reaches its cap (P-47) during the catch-up; as pwalk.
void pwalkfull() {
    const std::uint64_t n = 3000, k = 30, bound = n + 3 * k + pb::admit_j0(pb::kRuledLaneParams);
    const PwalkRun r = pwalk_run(n, k, 500, 8, 4 * bound, 44000);
    pwalk_print("pwalkfull", r, bound);
    check(r.peak == r.cap,
          "pwalkfull: J's deferred store at its cap during the catch-up (at most " + std::to_string(r.peak) + ")");
    pwalk_checks("pwalkfull", r, n, k, bound);
}

// pwalkcrawl: the pwalk chain at 500 frames per second, the FC_HEADERS replies 8 s after they are sent, J's deferred
// store full (P-47) of A's top carriers before the links: the header path gets one body per page while the store is
// full; J reaches A's tip within 1,800 s; as pwalk.
void pwalkcrawl() {
    const std::uint64_t n = 3000, k = 30, bound = n + 3 * k + pb::admit_j0(pb::kRuledLaneParams);
    const PwalkRun r = pwalk_run(n, k, 500, 8, 4 * bound, 44000, pb::admit_j0(pb::kRuledLaneParams));
    pwalk_print("pwalkcrawl", r, bound);
    std::printf("  pwalkcrawl: parked at J before the links %zu (cap %zu)\n", r.prefilled, r.cap);
    check(r.prefilled == r.cap, "pwalkcrawl: J's deferred store full before the links (" + std::to_string(r.prefilled) + ")");
    pwalk_checks("pwalkcrawl", r, n, k, bound);
}

// pwalkstall: the pwalk chain at 5,000 frames per second, the FC_HEADERS replies 8 s after they are sent; as pwalk.
void pwalkstall() {
    const std::uint64_t n = 3000, k = 30, bound = n + 3 * k + pb::admit_j0(pb::kRuledLaneParams);
    const PwalkRun r = pwalk_run(n, k, 5000, 8, 4 * bound, 44000);
    pwalk_print("pwalkstall", r, bound);
    pwalk_checks("pwalkstall", r, n, k, bound);
}

// pwalklost: A and B hold one chain; J follows both while A mines one carrier per second. E, a node of its own, holds
// A's positions 1..6 and mines e1, e2 on position 6; A places them on a side branch and floods them, and so does B. The
// wire loses e1's floods to J and B's e2, so J parks A's e2, and every FC_GETCARRIER(e1) of J is lost for 60 s. The
// relay's tick asks e1 again once per P-53 although J's best moves every second: first of A (the sender), then of B and
// A in turn (no two asks in a row to one peer); at 30 s a header page's ask of e1 is recorded, and no ask of e1 goes out
// within P-53 of it; from 2 to 1 + 60 / 11 asks in those 60 s. Then the asks pass: J holds e1 and e2 within P-53 + 2 s,
// nothing parked.
void pwalklost() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false);
    const std::size_t e = h.add(table0(net), true);
    w.connect(a.node, b.node);
    w.connect(a.node, j.node);
    w.connect(b.node, j.node);
    w.run();
    bool ok = true;
    for (int i = 0; i < 6 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 50000 + static_cast<std::uint32_t>(i));
    }
    for (std::uint64_t x = 1; x <= 6 && ok; ++x) {  // E: A's positions 1..6
        const std::optional<pb::Hash32> id = h[a.node].store().best_at(x);
        const pb::CarrierBodyV3* body = id ? h[a.node].bodies().get(*id) : nullptr;
        ok = body != nullptr && h[e].on_carrier(0, *pb::encode_fc_carrier(0, *body, 16)).action == pb::NodeAction::Placed;
    }
    std::vector<pb::Hash32> eb;  // e1, e2
    for (std::uint32_t i = 0; i < 2 && ok; ++i) {
        const std::optional<pb::PathbJob> jb = h.job(e, i % 5, 50100 + i);
        ok = jb && h[e].on_own_share(*jb, 50100 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
        if (ok) eb.push_back(h[e].tree().best().id);
    }
    h.q.clear();  // E's floods go nowhere
    for (int i = 0; i < 4 && ok; ++i) ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 50200 + static_cast<std::uint32_t>(i));
    for (int k = 0; k < 4 && h[j.node].tree().best().id != h[a.node].tree().best().id; ++k) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) r->tick();
        w.run();
    }
    ok = ok && eb.size() == 2 && h[j.node].tree().best().id == h[a.node].tree().best().id && h[j.node].tree().best().pos == 10
         && h[b.node].tree().best().id == h[a.node].tree().best().id;
    if (!ok) {
        check(false, "pwalklost: setup (A and B at 10, J on them; E's branch e1, e2 on position 6)");
        return;
    }
    const auto own_id = [&h, &j](const std::vector<std::uint8_t>& f) -> std::optional<pb::Hash32> {
        pb::CarrierBodyV3 c;
        if (f.size() <= pb::kFrameHeaderBytes
            || pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                          pb::CarrierLimits{h[j.node].config().buffers.receipt, pb::kRuledLaneParams.r_max}, c)
                       != pb::WireError::None)
            return std::nullopt;
        return pb::receipt_id(c.own);
    };
    bool lose = true;
    std::vector<std::pair<std::uint64_t, std::size_t>> asks;  // (time, the peer: 0 A, 1 B) of every ask of e1
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.to == j.links->self && m.f[0] == pb::kOpFcCarrier) {  // the floods of e1 to J, and B's e2
            const std::optional<pb::Hash32> id = own_id(m.f);
            if (id && lose && (*id == eb[0] || (*id == eb[1] && m.from == b.links->self))) m.f.clear();
            return;
        }
        if (m.from != j.links->self || m.f[0] != pb::kOpFcGetCarrier) return;
        pb::GetCarrier q;
        if (!pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) return;
        if (std::find(q.ids.begin(), q.ids.end(), eb[0]) == q.ids.end()) return;
        asks.emplace_back(h.now, m.to == a.links->self ? 0 : 1);
        if (lose) m.f.clear();
    };
    h.now += 1;
    for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) r->tick();
    for (const pb::Hash32& id : eb)  // A places E's branch (a side branch) and floods it; B places it and floods it
        (void)h[a.node].on_carrier(999, *pb::encode_fc_carrier(0, *h[e].bodies().get(id), 16));
    w.run();
    const bool parked = h[j.node].deferred().size() == 1 && h[j.node].tree().find(eb[1]) == nullptr && asks.size() == 1
                        && asks[0].second == 0;
    const std::uint64_t t0 = h.now, pos0 = h[j.node].tree().best().pos;
    const auto second = [&](std::uint32_t nonce) {
        h.now += 1;
        if (nonce % 12 == 0) h.tick_monero();
        (void)mine_on(h, w, a.node, nonce % 5, nonce);
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) {
            r->tick();
            r->pump();
        }
        w.run();
    };
    std::uint64_t t_page = 0;
    for (std::uint32_t t = 0; t < 60; ++t) {
        if (t == 30) {  // a header page asks e1 (FetchBodies): no reask of e1 within P-53 of it
            t_page = h.now;
            pb::PathbNodeTestAccess::body_asked(h[j.node], eb[0], t_page);
        }
        second(50300 + t);
    }
    const std::vector<std::pair<std::uint64_t, std::size_t>> lost = asks;
    const bool moved = h[j.node].tree().best().pos >= pos0 + 55 && h[j.node].tree().best().id == h[a.node].tree().best().id;
    lose = false;
    int secs = 0;
    for (; secs < 30 && h[j.node].tree().find(eb[0]) == nullptr; ++secs) second(50400 + static_cast<std::uint32_t>(secs));
    w.edit = nullptr;
    pb::PathbRelayNode& rj = *j.relay;
    const bool done = h[j.node].tree().find(eb[0]) != nullptr && h[j.node].tree().find(eb[1]) != nullptr;
    bool turns = lost.size() >= 3, both = false, page_quiet = true;
    std::string seq;
    for (std::size_t i = 0; i < lost.size(); ++i) {
        seq += (i ? " " : "") + std::to_string(lost[i].first - t0) + (lost[i].second == 0 ? "A" : "B");
        if (i >= 2 && lost[i].second == lost[i - 1].second) turns = false;  // the re-asks: never twice in a row to one peer
        both = both || lost[i].second == 1;
        if (lost[i].first >= t_page && lost[i].first < t_page + pb::kAbandonTimeoutDefault) page_quiet = false;
    }
    std::printf("  pwalklost: e2 parked at J %d; J's best %llu -> %llu; asks of e1 while lost (s from the park, peer): %s; "
                "header page's ask at %llu; then e1 and e2 held %d after %d s; parked %zu; strikes %llu, bans %llu\n",
                parked ? 1 : 0, (unsigned long long)pos0, (unsigned long long)h[j.node].tree().best().pos, seq.c_str(),
                (unsigned long long)(t_page - t0), done ? 1 : 0, secs, h[j.node].deferred().size(),
                (unsigned long long)rj.stats().strikes.load(), (unsigned long long)rj.stats().bans.load());
    check(parked && moved, "pwalklost: e1's floods lost, e2 parked at J (its ask of e1 to A); J's best moves every second");
    check(lost.size() >= 2 && lost.size() <= 1 + 60 / pb::kAbandonTimeoutDefault,
          "pwalklost: e1 asked again while lost, at most once per P-53 (" + std::to_string(lost.size()) + " asks in 60 s)");
    check(turns && both, "pwalklost: the re-asks of e1 go to A and B in turn (" + seq + ")");
    check(page_quiet, "pwalklost: no ask of e1 within P-53 of a header page's ask of it");
    check(done && secs <= static_cast<int>(pb::kAbandonTimeoutDefault) + 2 && h[j.node].deferred().size() == 0
                  && rj.stats().strikes.load() == 0 && rj.stats().bans.load() == 0,
          "pwalklost: once the asks pass, J holds e1 and e2 within P-53 + 2 s (" + std::to_string(secs) + " s); nothing parked");
}

// pwalksilent: as pwalklost with a fourth peer Z, linked to J only, whose own chain of 200 positions claims more work
// than J's best throughout; every FC_HEADERS of Z to J is lost, so J's catch-up toward Z stays open with no reply of its
// own. While A mines one carrier per second and every FC_GETCARRIER(e1) of J is lost for 60 s, e1 is asked at least
// twice, the first time within P-53 + 2 s of the park; the catch-up toward Z is still open at the end. Then the asks
// pass: J holds e1 and e2 within 2 x P-53 + 2 s (the turn may first fall on Z, which does not hold e1).
void pwalksilent() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false);
    KatRelay z = kat_relay(h, w, table0(net), true);
    const std::size_t e = h.add(table0(net), true);
    bool ok = true;
    for (int i = 0; i < 200 && ok; ++i)  // Z's own chain (Z linked to nobody), on one Monero height
        ok = mine_on(h, w, z.node, static_cast<std::size_t>(i % 5), 56000 + static_cast<std::uint32_t>(i));
    w.connect(a.node, b.node);
    w.connect(a.node, j.node);
    w.connect(b.node, j.node);
    w.run();
    for (int i = 0; i < 6 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 56300 + static_cast<std::uint32_t>(i));
    }
    for (std::uint64_t x = 1; x <= 6 && ok; ++x) {  // E: A's positions 1..6
        const std::optional<pb::Hash32> id = h[a.node].store().best_at(x);
        const pb::CarrierBodyV3* body = id ? h[a.node].bodies().get(*id) : nullptr;
        ok = body != nullptr && h[e].on_carrier(0, *pb::encode_fc_carrier(0, *body, 16)).action == pb::NodeAction::Placed;
    }
    std::vector<pb::Hash32> eb;  // e1, e2
    for (std::uint32_t i = 0; i < 2 && ok; ++i) {
        const std::optional<pb::PathbJob> jb = h.job(e, i % 5, 56400 + i);
        ok = jb && h[e].on_own_share(*jb, 56400 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
        if (ok) eb.push_back(h[e].tree().best().id);
    }
    h.q.clear();  // E's floods go nowhere
    for (int i = 0; i < 4 && ok; ++i) ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 56500 + static_cast<std::uint32_t>(i));
    for (int k = 0; k < 4 && h[j.node].tree().best().id != h[a.node].tree().best().id; ++k) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) r->tick();
        w.run();
    }
    ok = ok && eb.size() == 2 && h[j.node].tree().best().id == h[a.node].tree().best().id && h[j.node].tree().best().pos == 10
         && h[z.node].tree().best().pos == 200;
    if (!ok) {
        check(false, "pwalksilent: setup (A and B at 10, J on them; Z at 200 of its own; E's branch e1, e2 on position 6)");
        return;
    }
    const auto own_id = [&h, &j](const std::vector<std::uint8_t>& f) -> std::optional<pb::Hash32> {
        pb::CarrierBodyV3 c;
        if (f.size() <= pb::kFrameHeaderBytes
            || pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                          pb::CarrierLimits{h[j.node].config().buffers.receipt, pb::kRuledLaneParams.r_max}, c)
                       != pb::WireError::None)
            return std::nullopt;
        return pb::receipt_id(c.own);
    };
    bool lose = true;
    std::uint64_t z_headers = 0;
    std::vector<std::uint64_t> ask_t;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.from == z.links->self && m.to == j.links->self && m.f[0] == pb::kOpFcHeaders) {  // Z is silent
            ++z_headers;
            m.f.clear();
            return;
        }
        if (m.to == j.links->self && m.f[0] == pb::kOpFcCarrier) {  // the floods of e1 to J, and B's e2
            const std::optional<pb::Hash32> id = own_id(m.f);
            if (id && lose && (*id == eb[0] || (*id == eb[1] && m.from == b.links->self))) m.f.clear();
            return;
        }
        if (m.from != j.links->self || m.f[0] != pb::kOpFcGetCarrier) return;
        pb::GetCarrier q;
        if (!pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) return;
        if (std::find(q.ids.begin(), q.ids.end(), eb[0]) == q.ids.end()) return;
        ask_t.push_back(h.now);
        if (lose) m.f.clear();
    };
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(z.node, j.node);
    w.run();
    const std::uint64_t pz = w.id(j.node, z.node);
    const bool opened = rj.catchup_view(pz).has_value();
    h.now += 1;
    for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get(), z.relay.get()}) r->tick();
    for (const pb::Hash32& id : eb)  // A places E's branch (a side branch) and floods it; B places it and floods it
        (void)h[a.node].on_carrier(999, *pb::encode_fc_carrier(0, *h[e].bodies().get(id), 16));
    w.run();
    const std::uint64_t t_park = h.now;
    const bool parked = h[j.node].deferred().size() == 1 && h[j.node].tree().find(eb[1]) == nullptr;
    const std::uint64_t pos0 = h[j.node].tree().best().pos;
    const auto second = [&](std::uint32_t nonce) {
        h.now += 1;
        if (nonce % 12 == 0) h.tick_monero();
        (void)mine_on(h, w, a.node, nonce % 5, nonce);
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get(), z.relay.get()}) {
            r->tick();
            r->pump();
        }
        w.run();
    };
    for (std::uint32_t t = 0; t < 60; ++t) second(56600 + t);
    const std::vector<std::uint64_t> lost = ask_t;
    const bool open_end = rj.catchup_view(pz).has_value();
    const bool moved = h[j.node].tree().best().pos >= pos0 + 55 && h[j.node].tree().best().id == h[a.node].tree().best().id;
    lose = false;
    int secs = 0;
    for (; secs < 40 && h[j.node].tree().find(eb[0]) == nullptr; ++secs) second(56700 + static_cast<std::uint32_t>(secs));
    w.edit = nullptr;
    const bool done = h[j.node].tree().find(eb[0]) != nullptr && h[j.node].tree().find(eb[1]) != nullptr;
    std::string seq;
    for (std::size_t i = 0; i < lost.size(); ++i) seq += (i ? " " : "") + std::to_string(lost[i] - t_park);
    const std::uint64_t first = lost.empty() ? 999 : lost[0] - t_park;
    std::printf("  pwalksilent: catch-up toward Z opened %d, Z's FC_HEADERS lost %llu, still open after 60 s %d; e2 parked "
                "at J %d; J's best %llu -> %llu; asks of e1 while lost (s from the park): %s; then e1 and e2 held %d after "
                "%d s; parked %zu; strikes %llu, bans %llu\n",
                opened ? 1 : 0, (unsigned long long)z_headers, open_end ? 1 : 0, parked ? 1 : 0, (unsigned long long)pos0,
                (unsigned long long)h[j.node].tree().best().pos, seq.c_str(), done ? 1 : 0, secs,
                h[j.node].deferred().size(), (unsigned long long)rj.stats().strikes.load(),
                (unsigned long long)rj.stats().bans.load());
    check(opened && open_end && z_headers >= 1 && parked && moved,
          "pwalksilent: a catch-up toward the silent Z open throughout; e2 parked at J; J's best moves every second");
    check(lost.size() >= 2 && first <= pb::kAbandonTimeoutDefault + 2,
          "pwalksilent: e1 asked at least twice while the catch-up toward Z stays open, the first within P-53 + 2 s of the "
          "park (" + seq + ")");
    check(done && secs <= 2 * static_cast<int>(pb::kAbandonTimeoutDefault) + 2 && h[j.node].deferred().size() == 0
                  && rj.stats().strikes.load() == 0 && rj.stats().bans.load() == 0,
          "pwalksilent: once the asks pass, J holds e1 and e2 within 2 x P-53 + 2 s (" + std::to_string(secs) + " s)");
}

// silent_run: the pwalksilent shape. Z, linked to J only `lead` seconds before E's branch reaches J, holds its own chain
// of 200 positions (more work than J's best throughout); Z's FC_HEADERS to J are lost (late_s < 0) or arrive late_s
// seconds after they are sent. The times of J's asks of e1 are taken from the park.
struct SilentRun {
    bool ok = false, opened = false, open_end = false, parked = false, moved = false, done = false;
    std::uint64_t z_headers = 0, pos0 = 0, pos_end = 0, strikes = 0, bans = 0;
    std::vector<std::uint64_t> asks;
    int secs = 0;
    std::size_t deferred = 0;
};
SilentRun silent_run(int lead, int late_s) {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false);
    KatRelay z = kat_relay(h, w, table0(net), true);
    const std::size_t e = h.add(table0(net), true);
    SilentRun out;
    bool ok = true;
    for (int i = 0; i < 200 && ok; ++i)  // Z's own chain (Z linked to nobody), on one Monero height
        ok = mine_on(h, w, z.node, static_cast<std::size_t>(i % 5), 58000 + static_cast<std::uint32_t>(i));
    w.connect(a.node, b.node);
    w.connect(a.node, j.node);
    w.connect(b.node, j.node);
    w.run();
    for (int i = 0; i < 6 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 58300 + static_cast<std::uint32_t>(i));
    }
    for (std::uint64_t x = 1; x <= 6 && ok; ++x) {  // E: A's positions 1..6
        const std::optional<pb::Hash32> id = h[a.node].store().best_at(x);
        const pb::CarrierBodyV3* body = id ? h[a.node].bodies().get(*id) : nullptr;
        ok = body != nullptr && h[e].on_carrier(0, *pb::encode_fc_carrier(0, *body, 16)).action == pb::NodeAction::Placed;
    }
    std::vector<pb::Hash32> eb;  // e1, e2
    for (std::uint32_t i = 0; i < 2 && ok; ++i) {
        const std::optional<pb::PathbJob> jb = h.job(e, i % 5, 58400 + i);
        ok = jb && h[e].on_own_share(*jb, 58400 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
        if (ok) eb.push_back(h[e].tree().best().id);
    }
    h.q.clear();  // E's floods go nowhere
    for (int i = 0; i < 4 && ok; ++i) ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 58500 + static_cast<std::uint32_t>(i));
    for (int k = 0; k < 4 && h[j.node].tree().best().id != h[a.node].tree().best().id; ++k) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) r->tick();
        w.run();
    }
    out.ok = ok && eb.size() == 2 && h[j.node].tree().best().id == h[a.node].tree().best().id
             && h[j.node].tree().best().pos == 10 && h[z.node].tree().best().pos == 200;
    if (!out.ok) return out;
    const auto own_id = [&h, &j](const std::vector<std::uint8_t>& f) -> std::optional<pb::Hash32> {
        pb::CarrierBodyV3 c;
        if (f.size() <= pb::kFrameHeaderBytes
            || pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                          pb::CarrierLimits{h[j.node].config().buffers.receipt, pb::kRuledLaneParams.r_max}, c)
                       != pb::WireError::None)
            return std::nullopt;
        return pb::receipt_id(c.own);
    };
    bool lose = true;
    std::deque<std::pair<std::uint64_t, FakeWire::Msg>> zheld;  // Z's FC_HEADERS to J, by arrival time
    std::size_t zpass = 0;                                      // released frames at the front of the wire
    std::vector<std::uint64_t> ask_t;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (zpass > 0) {
            --zpass;
            return;
        }
        if (m.from == z.links->self && m.to == j.links->self && m.f[0] == pb::kOpFcHeaders) {
            ++out.z_headers;
            if (late_s >= 0) zheld.emplace_back(h.now + static_cast<std::uint64_t>(late_s), m);
            m.f.clear();
            return;
        }
        if (m.to == j.links->self && m.f[0] == pb::kOpFcCarrier) {  // the floods of e1 to J, and B's e2
            const std::optional<pb::Hash32> id = own_id(m.f);
            if (id && lose && (*id == eb[0] || (*id == eb[1] && m.from == b.links->self))) m.f.clear();
            return;
        }
        if (m.from != j.links->self || m.f[0] != pb::kOpFcGetCarrier) return;
        pb::GetCarrier q;
        if (!pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) return;
        if (std::find(q.ids.begin(), q.ids.end(), eb[0]) == q.ids.end()) return;
        ask_t.push_back(h.now);
        if (lose) m.f.clear();
    };
    pb::PathbRelayNode& rj = *j.relay;
    const auto second = [&](std::uint32_t nonce) {
        h.now += 1;
        if (nonce % 12 == 0) h.tick_monero();
        (void)mine_on(h, w, a.node, nonce % 5, nonce);
        std::vector<FakeWire::Msg> due;
        while (!zheld.empty() && zheld.front().first <= h.now) {
            due.push_back(std::move(zheld.front().second));
            zheld.pop_front();
        }
        for (auto it = due.rbegin(); it != due.rend(); ++it) w.q.push_front(std::move(*it));
        zpass += due.size();
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get(), z.relay.get()}) {
            r->tick();
            r->pump();
        }
        w.run();
    };
    w.connect(z.node, j.node);
    w.run();
    const std::uint64_t pz = w.id(j.node, z.node);
    out.opened = rj.catchup_view(pz).has_value();
    for (int t = 0; t < lead; ++t) second(58800 + static_cast<std::uint32_t>(t));
    h.now += 1;
    for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get(), z.relay.get()}) r->tick();
    for (const pb::Hash32& id : eb)  // A places E's branch (a side branch) and floods it; B places it and floods it
        (void)h[a.node].on_carrier(999, *pb::encode_fc_carrier(0, *h[e].bodies().get(id), 16));
    w.run();
    const std::uint64_t t_park = h.now;
    out.parked = h[j.node].deferred().size() == 1 && h[j.node].tree().find(eb[1]) == nullptr;
    out.pos0 = h[j.node].tree().best().pos;
    for (std::uint32_t t = 0; t < 60; ++t) second(58600 + t);
    for (const std::uint64_t at : ask_t) out.asks.push_back(at - t_park);
    out.open_end = rj.catchup_view(pz).has_value();
    out.moved = h[j.node].tree().best().pos >= out.pos0 + 55 && h[j.node].tree().best().id == h[a.node].tree().best().id;
    lose = false;
    for (; out.secs < 40 && h[j.node].tree().find(eb[0]) == nullptr; ++out.secs) second(58700 + static_cast<std::uint32_t>(out.secs));
    w.edit = nullptr;
    out.done = h[j.node].tree().find(eb[0]) != nullptr && h[j.node].tree().find(eb[1]) != nullptr;
    out.pos_end = h[j.node].tree().best().pos;
    out.deferred = h[j.node].deferred().size();
    out.strikes = rj.stats().strikes.load();
    out.bans = rj.stats().bans.load();
    return out;
}
// The checks of rcsilent and rclate; `cadence`: no two asks of e1 more than P-53 + 1 s apart.
void silent_checks(const std::string& tag, const SilentRun& r, bool cadence) {
    if (!r.ok) {
        check(false, tag + ": setup (A and B at 10, J on them; Z at 200 of its own; E's branch e1, e2 on position 6)");
        return;
    }
    std::string seq;
    bool steady = true;
    for (std::size_t i = 0; i < r.asks.size(); ++i) {
        seq += (i ? " " : "") + std::to_string(r.asks[i]);
        if (i > 0 && r.asks[i] - r.asks[i - 1] > pb::kAbandonTimeoutDefault + 1) steady = false;
    }
    const std::uint64_t first = r.asks.empty() ? 999 : r.asks[0];
    std::printf("  %s: catch-up toward Z opened %d, Z's FC_HEADERS %llu, still open after 60 s %d; e2 parked %d; J's best "
                "%llu -> %llu; asks of e1 while lost (s from the park): %s; then e1 and e2 held %d after %d s; parked %zu; "
                "strikes %llu, bans %llu\n",
                tag.c_str(), r.opened ? 1 : 0, (unsigned long long)r.z_headers, r.open_end ? 1 : 0, r.parked ? 1 : 0,
                (unsigned long long)r.pos0, (unsigned long long)r.pos_end, seq.c_str(), r.done ? 1 : 0, r.secs, r.deferred,
                (unsigned long long)r.strikes, (unsigned long long)r.bans);
    check(r.opened && r.open_end && r.z_headers >= 1 && r.parked && r.moved,
          tag + ": the catch-up toward Z open throughout; e2 parked at J; J's best moves every second");
    check(r.asks.size() >= 2 && first <= pb::kAbandonTimeoutDefault + 2,
          tag + ": e1 asked at least twice while lost, the first within P-53 + 2 s of the park (" + seq + ")");
    if (cadence) check(steady, tag + ": no two asks of e1 more than P-53 + 1 s apart (" + seq + ")");
    check(r.done && r.secs <= 2 * static_cast<int>(pb::kAbandonTimeoutDefault) + 2 && r.deferred == 0 && r.strikes == 0
                  && r.bans == 0,
          tag + ": then J holds e1 and e2 within 2 x P-53 + 2 s (" + std::to_string(r.secs) + " s); nothing parked");
}
// rcsilent: Z silent (its FC_HEADERS to J all lost), linked at the park (lead 0) and 20 s before it.
void rcsilent() {
    for (const int lead : {0, 20}) silent_checks("rcsilent lead " + std::to_string(lead), silent_run(lead, -1), false);
}
// rclate: Z linked at the park; its FC_HEADERS reach J P-53 + 2 s after they are sent (past P-53: each a reply to a
// retired request), or 3 s after (in time; no header of them wins).
void rclate() {
    for (const int late : {static_cast<int>(pb::kAbandonTimeoutDefault) + 2, 3})
        silent_checks("rclate " + std::to_string(late) + " s", silent_run(0, late), true);
}

// rcrehello: only a catch-up round's first request (the first after a link's first HELLO) makes headers first live, for
// at most P-53. J follows S; S HELLOs J. Round 1: J's first request R1 is live until its reply; a later request R2 of the
// round is not live, nor after S HELLOs again on the same link while R2 is in flight, nor the request R2' after that
// HELLO. Round 2, on a new link (S's link drops, S HELLOs again): its first request R3 gets no reply (S silent) while S
// HELLOs every 5 s on that link: R3 is live through P-53 and retired after it, and nothing is live after it; a frame J
// parks meanwhile asks its parent once headers first is not live.
void rcrehello() {
    const KatNet net;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    const std::size_t j = h.add(table0(net), false);
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 59000 + static_cast<std::uint32_t>(i));
    }
    h.q.clear();
    (void)h[j].tick(h.now);
    const pb::Hash32 tip = h[s].tree().best().id;
    const auto live = [&h, j] { return pb::PathbNodeTestAccess::hf_live(h[j]); };
    const auto hello = [&h, j, s] { return h.hello(j, s).verdict == pb::HelloVerdict::Accept; };
    const auto ask = [&h, j, s, &tip] {  // a catch-up request of J to S (from J's tip: an empty page)
        h.q.clear();
        return h[j].request_headers(s, tip, tip, 64, h.now);
    };
    const auto serve = [&h, j, s] {  // S answers J's open request
        for (const Msg& m : std::deque<Msg>(h.q))
            if (m.from == j && m.to == s && !m.frame.empty() && m.frame[0] == pb::kOpFcGetHeaders)
                for (const auto& f : h[s].serve_getheaders(j, m.frame, h.now).frames) (void)h[j].on_headers(s, f, h.now);
        h.q.clear();
    };
    const bool setup = h[j].tree().best().id == tip && hello();
    const bool r1 = ask();
    const bool live1 = live();
    serve();
    const bool live1_after = live();
    const bool r2 = ask();
    const bool live2 = live();
    const bool rehello2 = hello();
    const bool live2_rehello = live();
    serve();
    const bool r2b = ask();  // R2': the request after the HELLO on the same link
    const bool live2b = live();
    serve();
    h[j].disconnect(s);  // S's link drops; S links again
    const bool round2 = hello();
    const bool r3 = ask();
    const bool live3 = live();
    // a frame on a parent no node holds, parked at J from S while R3 is in flight
    pb::Hash32 parent = seq32(0xe1);
    std::optional<pb::PathbJob> jb = h.job(s, 1, 59100);
    bool parked = false;
    if (jb) {
        pb::CarrierBodyV3 c;
        c.own = jb->body;
        c.own.blob.nonce = 59100;
        c.own.side.tip = parent;
        pb::PathbNodeTestAccess::park(h[j], s, *pb::encode_fc_carrier(0, c, 16), pb::Missing::ParentUnknown, pb::RowId::R4,
                                      parent);
        parked = h[j].deferred().size() == 1;
    }
    const auto asks = [&h, j, &parent] {
        std::size_t n = 0;
        for (const Msg& m : h.q) {
            if (m.from != j || m.frame.empty() || m.frame[0] != pb::kOpFcGetCarrier) continue;
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok())
                for (const pb::Hash32& x : q.ids) n += x == parent ? 1 : 0;
        }
        return n;
    };
    std::size_t asked_live = 0;
    bool live_in = true;
    for (std::uint64_t t = 1; t <= pb::kAbandonTimeoutDefault; ++t) {  // within P-53 of R3: S HELLOs every 5 s
        h.now += 1;
        if (t % 5 == 0) (void)hello();
        (void)h[j].tick(h.now);
        h[j].reask_parents();
        live_in = live_in && live();
        asked_live += asks();
    }
    bool live_out = false;
    std::size_t asked_after = 0;
    for (std::uint64_t t = 0; t < 2 * pb::kAbandonTimeoutDefault; ++t) {  // past P-53: R3 retired; S HELLOs every 5 s
        h.now += 1;
        if (t % 5 == 0) (void)hello();
        (void)h[j].tick(h.now);
        h[j].reask_parents();
        live_out = live_out || live();
        asked_after += asks();
        h.q.clear();
    }
    const bool r4 = h[j].request_headers(s, tip, tip, 64, h.now);  // R3 retired, no reply: the slot stays taken
    std::printf("  rcrehello: R1 live %d, after its reply %d; R2 live %d, after a HELLO on the same link %d; R2' live %d; "
                "R3 (round 2, a new link) live %d, within P-53 of it %d, past it %d; parked %d; asks of its parent within "
                "P-53 %zu, past it %zu; a new request %d\n",
                live1 ? 1 : 0, live1_after ? 1 : 0, live2 ? 1 : 0, live2_rehello ? 1 : 0, live2b ? 1 : 0, live3 ? 1 : 0,
                live_in ? 1 : 0, live_out ? 1 : 0, parked ? 1 : 0, asked_live, asked_after, r4 ? 1 : 0);
    check(setup && r1 && r2 && rehello2 && r2b && round2 && r3 && parked,
          "rcrehello: setup (J on S's chain, S's HELLOs, requests)");
    check(live1 && !live1_after, "rcrehello: a round's first request is live until its reply");
    check(!live2 && !live2_rehello, "rcrehello: a later request of the round is not live, nor after a HELLO on the same link");
    check(!live2b, "rcrehello: a HELLO on the same link never makes a request first (R2' not live)");
    check(live3 && live_in && asked_live == 0, "rcrehello: round 2's first request, unanswered, live within P-53; no ask");
    check(!live_out && asked_after >= 1 && !r4,
          "rcrehello: retired at P-53, nothing live after it although S HELLOs every 5 s; the parked frame's parent asked");
}

// pwalkgone: A and B hold one chain; J follows both. E, a node of its own, holds A's positions 1..6 and mines e1, e2 on
// position 6; A places them on a side branch and floods them, and so does B. The wire loses e1's floods to J and B's e2,
// so J parks A's e2, and J's FC_GETCARRIER(e1) to A is lost; then A's link to J drops. The relay's tick asks e1 of B (the
// sender is gone): J holds e1 and e2 within P-53 + 2 s of the drop; no ask goes to A after it.
void pwalkgone() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false);
    const std::size_t e = h.add(table0(net), true);
    w.connect(a.node, b.node);
    w.connect(a.node, j.node);
    w.connect(b.node, j.node);
    w.run();
    bool ok = true;
    for (int i = 0; i < 6 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 52000 + static_cast<std::uint32_t>(i));
    }
    for (std::uint64_t x = 1; x <= 6 && ok; ++x) {  // E: A's positions 1..6
        const std::optional<pb::Hash32> id = h[a.node].store().best_at(x);
        const pb::CarrierBodyV3* body = id ? h[a.node].bodies().get(*id) : nullptr;
        ok = body != nullptr && h[e].on_carrier(0, *pb::encode_fc_carrier(0, *body, 16)).action == pb::NodeAction::Placed;
    }
    std::vector<pb::Hash32> eb;  // e1, e2
    for (std::uint32_t i = 0; i < 2 && ok; ++i) {
        const std::optional<pb::PathbJob> jb = h.job(e, i % 5, 52100 + i);
        ok = jb && h[e].on_own_share(*jb, 52100 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
        if (ok) eb.push_back(h[e].tree().best().id);
    }
    h.q.clear();  // E's floods go nowhere
    for (int i = 0; i < 4 && ok; ++i) ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 52200 + static_cast<std::uint32_t>(i));
    for (int k = 0; k < 4 && h[j.node].tree().best().id != h[a.node].tree().best().id; ++k) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) r->tick();
        w.run();
    }
    ok = ok && eb.size() == 2 && h[j.node].tree().best().id == h[a.node].tree().best().id
         && h[b.node].tree().best().id == h[a.node].tree().best().id;
    if (!ok) {
        check(false, "pwalkgone: setup (A and B at 10, J on them; E's branch e1, e2 on position 6)");
        return;
    }
    const auto own_id = [&h, &j](const std::vector<std::uint8_t>& f) -> std::optional<pb::Hash32> {
        pb::CarrierBodyV3 c;
        if (f.size() <= pb::kFrameHeaderBytes
            || pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                          pb::CarrierLimits{h[j.node].config().buffers.receipt, pb::kRuledLaneParams.r_max}, c)
                       != pb::WireError::None)
            return std::nullopt;
        return pb::receipt_id(c.own);
    };
    bool gone = false;
    std::uint64_t asks_a = 0, asks_a_after = 0, asks_b = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.to == j.links->self && m.f[0] == pb::kOpFcCarrier) {  // the floods of e1 to J, and B's e2
            const std::optional<pb::Hash32> id = own_id(m.f);
            if (id && !gone && (*id == eb[0] || (*id == eb[1] && m.from == b.links->self))) m.f.clear();
            return;
        }
        if (m.from != j.links->self || m.f[0] != pb::kOpFcGetCarrier) return;
        pb::GetCarrier q;
        if (!pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) return;
        if (std::find(q.ids.begin(), q.ids.end(), eb[0]) == q.ids.end()) return;
        if (m.to == a.links->self) {
            ++asks_a;
            asks_a_after += gone ? 1 : 0;
            m.f.clear();  // A's answer is lost
        } else if (m.to == b.links->self) {
            ++asks_b;
        }
    };
    h.now += 1;
    for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) r->tick();
    for (const pb::Hash32& id : eb)  // A places E's branch (a side branch) and floods it; B places it and floods it
        (void)h[a.node].on_carrier(999, *pb::encode_fc_carrier(0, *h[e].bodies().get(id), 16));
    w.run();
    const bool parked = h[j.node].deferred().size() == 1 && h[j.node].tree().find(eb[1]) == nullptr && asks_a == 1
                        && h[b.node].tree().find(eb[0]) != nullptr && h[b.node].tree().find(eb[1]) != nullptr;
    h.now += 1;
    j.links->disconnect(w.id(j.node, a.node));
    w.run();
    gone = true;
    int secs = 0;
    for (; secs < 30 && h[j.node].tree().find(eb[0]) == nullptr; ++secs) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get(), j.relay.get()}) {
            r->tick();
            r->pump();
        }
        w.run();
    }
    w.edit = nullptr;
    const bool done = h[j.node].tree().find(eb[0]) != nullptr && h[j.node].tree().find(eb[1]) != nullptr;
    std::printf("  pwalkgone: e2 parked at J %d (asks of e1 to A %llu); A's link dropped; asks of e1 to B %llu, to A after %llu; "
                "e1 and e2 held %d after %d s; parked %zu; strikes %llu, bans %llu\n",
                parked ? 1 : 0, (unsigned long long)asks_a, (unsigned long long)asks_b, (unsigned long long)asks_a_after,
                done ? 1 : 0, secs, h[j.node].deferred().size(), (unsigned long long)j.relay->stats().strikes.load(),
                (unsigned long long)j.relay->stats().bans.load());
    check(parked, "pwalkgone: e2 parked at J from A, its ask of e1 to A lost");
    check(done && asks_b >= 1 && asks_a_after == 0 && secs <= static_cast<int>(pb::kAbandonTimeoutDefault) + 2
                  && h[j.node].deferred().size() == 0,
          "pwalkgone: A gone, e1 asked of B: J holds e1 and e2 within P-53 + 2 s (" + std::to_string(secs) + " s)");
}

// pwalkjunk: J (deferred store cap 16) gets 100 frames from S, each a carrier on its own unknown parent, parked as
// ParentUnknown DEFERs (through the node's park). Over 4 windows of P-53, reask_parents runs every second: at most
// min(100, 16) asks per window, each parent id at most once per window, every ask to S.
void pwalkjunk() {
    const KatNet net;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    pb::PathbNodeConfig cf = h.config(table0(net), false);
    cf.waiting_cap = 16;
    const std::size_t j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cf, h.io(j)));
    h.cut = {{s, j}, {j, s}};
    for (int i = 0; i < 3; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 53000 + static_cast<std::uint32_t>(i));
    }
    h.cut.clear();
    h.q.clear();
    const pb::HelloCheck hc = h.hello(j, s);
    (void)h[j].tick(h.now);
    const std::size_t n = 100;
    for (std::uint32_t k = 0; k < n; ++k) {
        const std::optional<pb::PathbJob> jb = h.job(s, k % 5, 53100 + k);
        if (!jb) break;
        pb::CarrierBodyV3 c;
        c.own = jb->body;
        c.own.blob.nonce = 53100 + k;
        c.own.side.tip = seq32(static_cast<std::uint8_t>(0x10 + k % 200));
        c.own.side.tip[1] = static_cast<std::uint8_t>(k);  // its own unknown parent
        pb::PathbNodeTestAccess::park(h[j], s, *pb::encode_fc_carrier(0, c, 16), pb::Missing::ParentUnknown, pb::RowId::R4,
                                      c.own.side.tip);
    }
    const std::size_t held = h[j].deferred().size();
    h.q.clear();
    const std::uint64_t windows = 4, cap = 16;
    std::map<pb::Hash32, std::uint64_t> per_id;
    std::uint64_t worst = 0, total = 0, to_other = 0;
    for (std::uint64_t win = 0; win < windows; ++win) {
        std::uint64_t asks = 0;
        for (std::uint64_t t = 0; t < pb::kAbandonTimeoutDefault; ++t) {
            h.now += 1;
            (void)h[j].tick(h.now);
            h[j].reask_parents();
            for (const Msg& m : h.q) {
                if (m.from != j || m.frame.empty() || m.frame[0] != pb::kOpFcGetCarrier) continue;
                pb::GetCarrier q;
                if (!pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok()) continue;
                for (const pb::Hash32& id : q.ids) ++per_id[id];
                asks += q.ids.size();
                to_other += m.to != s ? 1 : 0;
            }
            h.q.clear();
        }
        worst = std::max(worst, asks);
        total += asks;
    }
    std::uint64_t max_id = 0;
    for (const auto& [id, k] : per_id) max_id = std::max(max_id, k);
    std::printf("  pwalkjunk: HELLO %d; parked %zu of %zu (cap %llu); asks per window at most %llu, in all %llu; one id at "
                "most %llu times over %llu windows; asks to another peer %llu\n",
                hc.verdict == pb::HelloVerdict::Accept ? 1 : 0, held, n, (unsigned long long)cap, (unsigned long long)worst,
                (unsigned long long)total, (unsigned long long)max_id, (unsigned long long)windows,
                (unsigned long long)to_other);
    check(hc.verdict == pb::HelloVerdict::Accept && held == cap, "pwalkjunk: 100 junk frames parked, the store at its cap (16)");
    check(worst <= std::min<std::uint64_t>(n, cap) && worst > 0 && max_id <= windows && to_other == 0,
          "pwalkjunk: at most min(N, P-47) asks per P-53, each parent id at most once per window, all to the sender (" +
                  std::to_string(worst) + " per window, " + std::to_string(max_id) + " per id)");
}

// pwalkskipfull: J gets 16 frames from S, each a carrier on its own unknown parent, parked as ParentUnknown DEFERs
// (through the node's park, T0); 5 s later a header page asks the parent x0 of one of them (its body in flight). Store
// cap 32 (not full): headers first is live, no parent ask within P-53 of the header page's ask. Store cap 16 (full): not
// live; the other parents are asked again at T0 + P-53, x0 not within P-53 of the header page's ask, then once (in
// the next P-53).
struct SkipFullRun {
    bool hello = false;
    std::size_t parked = 0;
    bool live = false;
    std::uint64_t x0_in = 0, x0_after = 0, others = 0, first_x0 = 0;
};
SkipFullRun pwalkskipfull_run(std::uint64_t cap) {
    const KatNet net;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    pb::PathbNodeConfig cf = h.config(table0(net), false);
    cf.waiting_cap = cap;
    const std::size_t j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cf, h.io(j)));
    h.cut = {{s, j}, {j, s}};
    for (int i = 0; i < 3; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 54000 + static_cast<std::uint32_t>(i));
    }
    h.cut.clear();
    h.q.clear();
    SkipFullRun out;
    out.hello = h.hello(j, s).verdict == pb::HelloVerdict::Accept;
    (void)h[j].tick(h.now);
    std::vector<pb::Hash32> parents;
    for (std::uint32_t k = 0; k < 16; ++k) {
        const std::optional<pb::PathbJob> jb = h.job(s, k % 5, 54100 + k);
        if (!jb) break;
        pb::CarrierBodyV3 c;
        c.own = jb->body;
        c.own.blob.nonce = 54100 + k;
        c.own.side.tip = seq32(static_cast<std::uint8_t>(0x40 + k));
        c.own.side.tip[1] = 0x5f;  // its own unknown parent
        parents.push_back(c.own.side.tip);
        pb::PathbNodeTestAccess::park(h[j], s, *pb::encode_fc_carrier(0, c, 16), pb::Missing::ParentUnknown, pb::RowId::R4,
                                      c.own.side.tip);
    }
    out.parked = h[j].deferred().size();
    h.q.clear();
    const std::uint64_t t0 = h.now, p53 = pb::kAbandonTimeoutDefault;
    const pb::Hash32 x0 = parents.empty() ? pb::Hash32{} : parents.front();
    for (std::uint64_t t = 1; t < 5 + 2 * p53; ++t) {
        h.now = t0 + t;
        if (t == 5) pb::PathbNodeTestAccess::body_asked(h[j], x0, h.now);  // a header page's ask of x0
        (void)h[j].tick(h.now);
        if (t == 6) out.live = pb::PathbNodeTestAccess::hf_live(h[j]);
        h[j].reask_parents();
        for (const Msg& m : h.q) {
            if (m.from != j || m.frame.empty() || m.frame[0] != pb::kOpFcGetCarrier) continue;
            pb::GetCarrier q;
            if (!pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok()) continue;
            for (const pb::Hash32& id : q.ids) {
                if (id != x0) {
                    out.others += t >= 5 && t < 5 + p53 ? 1 : 0;
                    continue;
                }
                if (out.first_x0 == 0) out.first_x0 = t;
                if (t < 5 + p53) ++out.x0_in;
                else ++out.x0_after;
            }
        }
        h.q.clear();
    }
    return out;
}
void pwalkskipfull() {
    const SkipFullRun a = pwalkskipfull_run(32), b = pwalkskipfull_run(16);
    for (const auto& [tag, r] : {std::make_pair("cap 32", a), std::make_pair("cap 16", b)})
        std::printf("  pwalkskipfull %s: HELLO %d; parked %zu; live after the header page's ask %d; asks of x0 within P-53 of "
                    "it %llu, after %llu (first at %llu s); asks of the other parents within that P-53 %llu\n",
                    tag, r.hello ? 1 : 0, r.parked, r.live ? 1 : 0, (unsigned long long)r.x0_in,
                    (unsigned long long)r.x0_after, (unsigned long long)r.first_x0, (unsigned long long)r.others);
    check(a.hello && a.parked == 16 && b.hello && b.parked == 16, "pwalkskipfull: 16 frames parked at cap 32 and at cap 16");
    check(a.live && a.x0_in == 0 && a.others == 0,
          "pwalkskipfull: store not full: headers first live, no parent ask within P-53 of the header page's ask");
    check(!b.live && b.x0_in == 0 && b.x0_after == 1 && b.others == 15,
          "pwalkskipfull: store full: not live; the other 15 parents asked again, x0 not within P-53 of the header page's "
          "ask, then once (" + std::to_string(b.x0_in) + " within, " + std::to_string(b.x0_after) + " after)");
}

// pwalkasked: J (deferred store cap 1,000) follows S at T. S holds 600 carriers t_k on T, none of them flooded to J;
// J holds 600 parked chains, each a frame on t_k (parked through the node's park, no sender connected). The relay's
// tick asks each t_k of S, its only peer: S's asked-carrier record stays within kAskedMax (256) at every pass (the rest
// waits for room), every reply is solicited, each t_k asked once, and J holds all 600.
void pwalkasked() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay s = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& c) { c.waiting_cap = 1000; });
    w.connect(s.node, j.node);
    w.run();
    bool ok = true;
    for (int i = 0; i < 3 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, s.node, static_cast<std::size_t>(i % 5), 54000 + static_cast<std::uint32_t>(i));
    }
    for (int k = 0; k < 4 && h[j.node].tree().best().id != h[s.node].tree().best().id; ++k) {
        h.now += 1;
        j.relay->tick();
        w.run();
    }
    const std::size_t n = 600;
    std::vector<SiblingFrame> t;
    for (std::uint32_t k = 0; k < n && ok; ++k) {
        t.push_back(sibling_frame(h, s.node, k % 5, 54100 + k));
        ok = !t.back().frame.empty();
    }
    bool quiet = true;  // S's floods of the t_k do not reach J
    std::uint64_t to_s = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (quiet && m.from == s.links->self && m.to == j.links->self && m.f[0] == pb::kOpFcCarrier) m.f.clear();
        if (m.from == j.links->self && m.to == s.links->self && m.f[0] == pb::kOpFcGetCarrier) {
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) to_s += q.ids.size();
        }
    };
    for (const SiblingFrame& f : t) (void)h[s.node].on_carrier(999, f.frame);
    w.run();
    quiet = false;
    std::size_t at_s = 0;
    for (const SiblingFrame& f : t) at_s += h[s.node].tree().find(f.id) != nullptr ? 1 : 0;
    ok = ok && at_s == n && h[j.node].tree().find(t[0].id) == nullptr;
    if (!ok) {
        check(false, "pwalkasked: setup (S holds 600 carriers on T, J none)");
        return;
    }
    for (std::uint32_t k = 0; k < n; ++k) {  // a frame on t_k whose own P_r J does not hold (it parks again once released)
        const std::optional<pb::PathbJob> jb = h.job(s.node, k % 5, 55000 + k);
        if (!jb) break;
        pb::CarrierBodyV3 c;
        c.own = jb->body;
        c.own.blob.nonce = 55000 + k;
        c.own.side.tip = t[k].id;
        c.own.blob.prev_id = seq32(0xd0);
        c.own.blob.prev_id[1] = static_cast<std::uint8_t>(k);
        c.own.blob.prev_id[2] = static_cast<std::uint8_t>(k >> 8);
        pb::PathbNodeTestAccess::park(h[j.node], pb::PathbNode::kOwnPeer, *pb::encode_fc_carrier(0, c, 16),
                                      pb::Missing::ParentUnknown, pb::RowId::R4, t[k].id);
    }
    const std::size_t parked = h[j.node].deferred().size();
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t ps = w.id(j.node, s.node);
    const std::uint64_t sol0 = rj.stats().solicited_jobs.load(), p15 = rj.stats().p15_drops.load();
    std::size_t held = 0, peak = 0, worst_pass = 0;
    int secs = 0;
    for (; secs < 60 && held < n; ++secs) {
        h.now += 1;
        const std::uint64_t before = to_s;
        rj.tick();
        peak = std::max(peak, rj.asked_carriers_of(ps));
        w.run();
        worst_pass = std::max<std::size_t>(worst_pass, to_s - before);
        held = 0;
        for (const SiblingFrame& f : t) held += h[j.node].tree().find(f.id) != nullptr ? 1 : 0;
    }
    w.edit = nullptr;
    const std::uint64_t solicited = rj.stats().solicited_jobs.load() - sol0;
    std::printf("  pwalkasked: parked %zu; J holds %zu of %zu after %d s; asks of S %llu (at most %zu in one pass); S's "
                "asked-carrier record at most %zu; solicited replies %llu; P-15 drops %llu; re-asks %llu\n",
                parked, held, n, secs, (unsigned long long)to_s, worst_pass, peak, (unsigned long long)solicited,
                (unsigned long long)(rj.stats().p15_drops.load() - p15), (unsigned long long)h[j.node].parent_reasks());
    check(parked == n && held == n, "pwalkasked: 600 parked chains towards S, J holds all 600 t_k");
    check(peak <= 256 && worst_pass <= 256 && to_s == n,
          "pwalkasked: S's asked-carrier record within kAskedMax at every pass, each t_k asked once (record at most " +
                  std::to_string(peak) + ", " + std::to_string(worst_pass) + " in one pass)");
    check(solicited >= n && rj.stats().p15_drops.load() == p15, "pwalkasked: every reply solicited, no P-15 drop");
}

// pwalkdup: J, empty, receives carriers on S's tip P (position 6), whose parent it does not hold. T1 asks P once; T1 from
// another peer and T2 (another carrier on P, within P-53) ask nothing; past P-53, T1 again (held already) asks nothing
// and T3 (parked now) asks P again; P's own frame (parked on its parent Q) asks Q; past P-53 again, T4 on P asks nothing
// (P is parked, waiting on Q).
void pwalkdup() {
    const KatNet net;
    using K = pb::Missing;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    const std::size_t j = h.add(table0(net), false);
    h.cut = {{s, j}, {j, s}};
    for (int i = 0; i < 6; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 46000 + static_cast<std::uint32_t>(i));
    }
    h.cut.clear();
    h.q.clear();
    const pb::Hash32 P = h[s].tree().best().id, Q = *h[s].store().best_at(5);
    std::vector<SiblingFrame> t;
    for (std::uint32_t i = 0; i < 4; ++i) t.push_back(sibling_frame(h, s, i % 5, 46100 + i));
    h.q.clear();
    const std::vector<std::uint8_t> pf = *pb::encode_fc_carrier(0, *h[s].bodies().get(P), 16);
    const auto asks = [&h, j](const pb::Hash32& id) {
        std::size_t n = 0;
        for (const Msg& m : h.q) {
            if (m.from != j || m.frame.empty() || m.frame[0] != pb::kOpFcGetCarrier) continue;
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok())
                for (const pb::Hash32& x : q.ids) n += x == id ? 1 : 0;
        }
        return n;
    };
    bool setup = h[s].tree().best().pos == 6 && h[j].tree().best().pos == 0;
    for (const SiblingFrame& f : t) setup = setup && !f.frame.empty() && f.id != P;
    if (!setup) {
        check(false, "pwalkdup: setup (S at 6, four carriers on its tip)");
        return;
    }
    (void)h[j].tick(h.now);
    const pb::NodeEventResult r1 = h[j].on_carrier(s, t[0].frame);
    const std::size_t a1 = asks(P);
    (void)h[j].on_carrier(7, t[0].frame);  // the same frame from another peer
    (void)h[j].on_carrier(s, t[1].frame);
    const std::size_t a2 = asks(P), held2 = h[j].deferred().size();
    h.now += pb::kAbandonTimeoutDefault + 1;
    (void)h[j].tick(h.now);
    (void)h[j].on_carrier(s, t[0].frame);  // held already
    const std::size_t a3 = asks(P);
    (void)h[j].on_carrier(s, t[2].frame);
    const std::size_t a4 = asks(P);
    const pb::NodeEventResult rp = h[j].on_carrier(s, pf);
    const std::size_t q1 = asks(Q);
    h.now += pb::kAbandonTimeoutDefault + 1;
    (void)h[j].tick(h.now);
    (void)h[j].on_carrier(s, t[3].frame);
    const std::size_t a5 = asks(P);
    std::printf("  pwalkdup: asks of P %zu, %zu, %zu, %zu, %zu; of Q %zu; parked %zu then %zu; parent asks %llu\n", a1, a2, a3,
                a4, a5, q1, held2, h[j].deferred().size(), (unsigned long long)h[j].parent_asks());
    check(r1.action == pb::NodeAction::Parked && r1.admit.missing == K::ParentUnknown && r1.admit.row == pb::RowId::R4 && a1 == 1,
          "pwalkdup: T1 on P, P not held: DEFER R4 (ParentUnknown), P asked once");
    check(a2 == 1 && held2 == 2, "pwalkdup: T1 again (another peer) and T2 within P-53: parked, P not asked again");
    check(a3 == 1, "pwalkdup: past P-53, T1 again (held already): P not asked");
    check(a4 == 2, "pwalkdup: past P-53, T3 (parked now): P asked again");
    check(rp.action == pb::NodeAction::Parked && rp.admit.missing == K::ParentUnknown && q1 == 1,
          "pwalkdup: P's own frame (Q not held): parked, Q asked once");
    check(a5 == 2 && h[j].deferred().size() == 5,
          "pwalkdup: past P-53 again, T4 on P (parked, waiting on Q): P not asked; five frames parked");
}

// sealall: the seal sweep covers every parked carrier frame (E-139 (i); ruling 40 for the boundary), not only those
// indexed for a re-run. B (journal depth 16) follows A. E, a node of its own, holds A's positions 1..6 and mines
// E7, E8 and E9 on position 6. B receives E7 once position 6 lies below its journal base: DEFER R4 (OwnChainDeep); then
// E8: DEFER R4 (ParentUnknown); E9 is parked as a Boundary DEFER at R17 through the node's own park (its admission needs
// a branch forked more than J_0 below: the admit KAT's section 4). None is in the relay's re-run index. A mines on: once
// B's record passes the three frames' own bins + F, the tick drops all three without strike.
void sealall() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& c) { c.journal_depth = 16; });
    const std::size_t e = h.add(table0(net), true);
    w.connect(a.node, b.node);
    w.run();
    bool ok = true;
    for (int i = 0; i < 6 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 47000 + static_cast<std::uint32_t>(i));
    }
    for (std::uint64_t x = 1; x <= 6 && ok; ++x) {  // E: A's positions 1..6
        const std::optional<pb::Hash32> id = h[a.node].store().best_at(x);
        const pb::CarrierBodyV3* body = id ? h[a.node].bodies().get(*id) : nullptr;
        ok = body != nullptr && h[e].on_carrier(0, *pb::encode_fc_carrier(0, *body, 16)).action == pb::NodeAction::Placed;
    }
    std::vector<pb::CarrierBodyV3> eb;  // E7, E8, E9 (on position 6's Monero tip)
    for (std::uint32_t i = 0; i < 3 && ok; ++i) {
        const std::optional<pb::PathbJob> jb = h.job(e, i % 5, 47100 + i);
        ok = jb && h[e].on_own_share(*jb, 47100 + i, pb::Hash32{}).action == pb::NodeAction::Placed;
        if (ok) eb.push_back(*h[e].bodies().get(h[e].tree().best().id));
    }
    h.q.clear();  // E's floods go nowhere
    for (int i = 0; i < 20 && ok; ++i) {  // position 6 below B's journal base
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 47200 + static_cast<std::uint32_t>(i));
    }
    ok = ok && eb.size() == 3 && h[b.node].tree().best().id == h[a.node].tree().best().id && h[b.node].store().base_pos() > 6;
    if (!ok) {
        check(false, "sealall: setup (B on A's chain past depth 16, E's branch of three on position 6)");
        return;
    }
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = w.id(b.node, a.node);
    const auto r4 = [&rb] {
        return rb.verdict_counts()[static_cast<std::size_t>(pb::RowId::R4)][static_cast<std::size_t>(pb::AdmitVerdict::Defer)];
    };
    const std::uint64_t r4_0 = r4();
    for (std::size_t i = 0; i < 2; ++i) {  // E7 (OwnChainDeep), E8 (ParentUnknown)
        h.now += 1;
        rb.receive(pa, *pb::encode_fc_carrier(0, eb[i], 16));
        w.run();
    }
    pb::PathbNodeTestAccess::park(h[b.node], pa, *pb::encode_fc_carrier(0, eb[2], 16), pb::Missing::Boundary, pb::RowId::R17);
    const std::size_t parked = h[b.node].deferred().size(), indexed = rb.parked_index_size();
    std::uint64_t lo = UINT64_MAX;
    for (const pb::CarrierBodyV3& x : eb) lo = std::min(lo, h[b.node].held_origin(x.own.blob.prev_id).value_or(0));
    const std::uint64_t F = pb::kRuledLaneParams.open_bins, sealed0 = rb.stats().parked_frames_sealed.load();
    bool kept_open = true;
    std::uint64_t H = 0;
    for (std::uint32_t i = 0; i < 200 && h[b.node].deferred().size() != 0; ++i) {
        h.tick_monero();
        (void)mine_on(h, w, a.node, i % 5, 47300 + i);
        h.now += 1;
        rb.tick();
        w.run();
        H = h[b.node].best_record().value_or(0);
        if (H < lo + F) kept_open = kept_open && h[b.node].deferred().size() == parked;
    }
    const std::uint64_t sealed = rb.stats().parked_frames_sealed.load() - sealed0;
    std::printf("  sealall: R4 DEFERs %llu; parked %zu (indexed %zu); lowest own bin %llu; H %llu; left %zu; sealed %llu\n",
                (unsigned long long)(r4() - r4_0), parked, indexed, (unsigned long long)lo, (unsigned long long)H,
                h[b.node].deferred().size(), (unsigned long long)sealed);
    check(r4() == r4_0 + 2 && parked == 3 && indexed == 0 && lo != 0,
          "sealall: E7 (OwnChainDeep) and E8 (ParentUnknown) DEFER at R4, E9 parked as a Boundary DEFER; none indexed");
    check(kept_open && h[b.node].deferred().size() == 0 && sealed == 3 && rb.stats().strikes.load() == 0,
          "sealall: kept while their bins are open, all three dropped without strike once they seal (sealed " +
                  std::to_string(sealed) + ")");
}

// placedcopy: a byte-identical copy of a carrier B placed, whose parent lies below B's journal base (depth 16), arrives:
// DEFER R4 (OwnChainDeep), counted, no token; it is not parked (the deferred store unchanged).
void placedcopy() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& c) { c.journal_depth = 16; });
    w.connect(a.node, b.node);
    w.run();
    bool ok = true;
    for (int i = 0; i < 26 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 48000 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::Hash32> c3 = h[a.node].store().best_at(3);
    ok = ok && c3 && h[b.node].tree().best().id == h[a.node].tree().best().id && h[b.node].store().base_pos() > 3
         && h[b.node].tree().find(*c3) != nullptr;
    if (!ok) {
        check(false, "placedcopy: setup (B on A's chain past depth 16)");
        return;
    }
    pb::PathbRelayNode& rb = *b.relay;
    const auto r4 = [&rb] {
        return rb.verdict_counts()[static_cast<std::size_t>(pb::RowId::R4)][static_cast<std::size_t>(pb::AdmitVerdict::Defer)];
    };
    const std::uint64_t r4_0 = r4();
    const std::size_t held0 = h[b.node].deferred().size();
    h.now += 1;
    rb.receive(w.id(b.node, a.node), *pb::encode_fc_carrier(0, *h[a.node].bodies().get(*c3), 16));
    w.run();
    std::printf("  placedcopy: R4 DEFERs %llu; parked %zu then %zu; strikes %llu, bans %llu\n", (unsigned long long)(r4() - r4_0),
                held0, h[b.node].deferred().size(), (unsigned long long)rb.stats().strikes.load(),
                (unsigned long long)rb.stats().bans.load());
    check(r4() == r4_0 + 1 && held0 == 0 && h[b.node].deferred().size() == 0 && rb.stats().strikes.load() == 0
                  && rb.stats().bans.load() == 0,
          "placedcopy: a copy of a placed carrier below the journal base: DEFER R4 counted, not parked, no token");
}

// placedvariant: B follows A. c, A's carrier on T with P_r S0, carries nothing; r is A's receipt on T with P_r S1. With S0
// held at B without its weights, a byte-identical copy of c DEFERs at R5 and is not parked. With S1 held without its
// weights, a copy of c with c's own body and the carried list {r} (other bytes, the same id) DEFERs at R19
// (MoneroBlock) and is parked; once S1's weights are held it runs again and is judged: STRIKE at R11 (the fold), one
// token, nothing left parked.
void placedvariant() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> noweights, noseed;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, hide_inputs(noweights, noseed));
    w.connect(a.node, b.node);
    w.run();
    bool ok = true;
    for (int i = 0; i < 6 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 49000 + static_cast<std::uint32_t>(i));
    }
    h.tick_monero();
    const std::optional<pb::PathbJob> jc = h.job(a.node, 1, 49100);  // c: on T, P_r S0
    h.tick_monero();
    const std::optional<pb::PathbJob> jr = h.job(a.node, 2, 49101);  // r: on T, P_r S1
    ok = ok && jc && jr && jc->body.side.tip == jr->body.side.tip && jc->body.blob.prev_id != jr->body.blob.prev_id;
    ok = ok && h[a.node].on_own_share(*jc, 49100, pb::Hash32{}).action == pb::NodeAction::Placed;
    w.run();
    const pb::Hash32 c = h[a.node].tree().best().id;
    ok = ok && h[b.node].tree().best().id == c && h[b.node].bodies().get(c) != nullptr;
    if (!ok) {
        check(false, "placedvariant: setup (B on A's chain at c; r on c's parent with a later P_r)");
        return;
    }
    const pb::Hash32 S0 = jc->body.blob.prev_id, S1 = jr->body.blob.prev_id;
    pb::PathbRelayNode& rb = *b.relay;
    const std::uint64_t pa = w.id(b.node, a.node);
    const auto vc = [&rb](pb::RowId row, pb::AdmitVerdict x) {
        return rb.verdict_counts()[static_cast<std::size_t>(row)][static_cast<std::size_t>(x)];
    };
    // the byte-identical copy
    noweights.insert(S0);
    const std::uint64_t d5 = vc(pb::RowId::R5, pb::AdmitVerdict::Defer);
    h.now += 1;
    rb.receive(pa, *pb::encode_fc_carrier(0, *h[a.node].bodies().get(c), 16));
    w.run();
    const bool deferred5 = vc(pb::RowId::R5, pb::AdmitVerdict::Defer) == d5 + 1;
    const std::size_t parked_same = h[b.node].deferred().size();
    noweights.erase(S0);
    // the copy with another carried list
    pb::CarrierBodyV3 v = *h[a.node].bodies().get(c);
    pb::ReceiptBodyV3 r = jr->body;
    r.blob.nonce = 49101;
    v.carried = {r};
    noweights.insert(S1);
    const std::uint64_t d19 = vc(pb::RowId::R19, pb::AdmitVerdict::Defer), s11 = vc(pb::RowId::R11, pb::AdmitVerdict::Strike);
    const std::uint64_t st0 = rb.strikes_of(pa);
    h.now += 1;
    rb.receive(pa, *pb::encode_fc_carrier(0, v, 16));
    w.run();
    const bool deferred19 = vc(pb::RowId::R19, pb::AdmitVerdict::Defer) == d19 + 1;
    const std::size_t parked = h[b.node].deferred().size();
    noweights.erase(S1);
    rb.on_monero_tip();
    w.run();
    const bool struck = vc(pb::RowId::R11, pb::AdmitVerdict::Strike) == s11 + 1 && rb.strikes_of(pa) == st0 + 1;
    const std::size_t left = h[b.node].deferred().size();
    std::printf("  placedvariant: the byte-identical copy: R5 DEFER %d, parked %zu; the variant: R19 DEFER %d, parked %zu, "
                "then STRIKE at R11 %d, parked %zu; bans %llu\n",
                deferred5 ? 1 : 0, parked_same, deferred19 ? 1 : 0, parked, struck ? 1 : 0, left,
                (unsigned long long)rb.stats().bans.load());
    check(deferred5 && parked_same == 0, "placedvariant: a byte-identical copy of c that DEFERs (R5) is not parked");
    check(deferred19 && parked == 1, "placedvariant: a copy of c with another carried list DEFERs at R19 and is parked");
    check(struck && left == 0 && rb.stats().bans.load() == 0,
          "placedvariant: once S1's weights are held it runs again: STRIKE at R11, nothing parked; no ban");
}

// ---------------------------------------------------------------------------
// revnotcarrier: a ParentUnknown DEFER whose parent is placed between its admission (begin_carrier) and its placement
// (complete_carrier). J holds the server chain 1..3; d (6) and e (7) are parked (e on d, d on c); p (4) and c (5) arrive
// back to back: c is admitted before p is placed (ParentUnknown), then p is placed, then c's DEFER completes: c is
// admitted again and placed, d and e are released (J at 7); no tree waiting entry is discarded.
void revnotcarrier() {
    const KatNet net;
    Harness h(net);
    const std::size_t s = h.add(table0(net), true);
    const std::size_t j = h.add(table0(net), false);
    h.cut = {{s, j}, {j, s}};
    for (int i = 0; i < 7; ++i) {
        if (i % 3 == 0) h.tick_monero();
        h.mine(s, static_cast<std::size_t>(i % 5), 51000 + static_cast<std::uint32_t>(i));
    }
    h.cut.clear();
    h.q.clear();
    const auto id_at = [&](std::uint64_t x) { return *h[s].store().best_at(x); };
    const auto frame_at = [&](std::uint64_t x) { return *pb::encode_fc_carrier(0, *h[s].bodies().get(id_at(x)), 16); };
    const auto asks = [&h, j](const pb::Hash32& id) {
        std::size_t n = 0;
        for (const Msg& m : h.q) {
            if (m.from != j || m.frame.empty() || m.frame[0] != pb::kOpFcGetCarrier) continue;
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok())
                for (const pb::Hash32& x : q.ids) n += x == id ? 1 : 0;
        }
        return n;
    };
    (void)h[j].tick(h.now);
    for (std::uint64_t x = 1; x <= 3; ++x) (void)h[j].on_carrier(s, frame_at(x));
    h.q.clear();
    const bool setup = h[s].tree().best().pos == 7 && h[j].tree().best().pos == 3;
    const pb::NodeEventResult re = h[j].on_carrier(s, frame_at(7));
    const pb::NodeEventResult rd = h[j].on_carrier(s, frame_at(6));
    const bool parked = re.action == pb::NodeAction::Parked && rd.action == pb::NodeAction::Parked
                        && h[j].tree().is_waiting(id_at(6)) && h[j].tree().is_waiting(id_at(7)) && h[j].deferred().size() == 2;
    const std::size_t ask_c0 = asks(id_at(5));
    h.q.clear();
    pb::PathbNode::CarrierTicket tp = h[j].begin_carrier(s, frame_at(4));
    pb::PathbNode::CarrierTicket tc = h[j].begin_carrier(s, frame_at(5));
    const bool c_defer = tc.admit.verdict == pb::AdmitVerdict::Defer && tc.admit.missing == pb::Missing::ParentUnknown;
    const pb::NodeEventResult rp = h[j].complete_carrier(std::move(tp));
    const pb::NodeEventResult rc = h[j].complete_carrier(std::move(tc));
    const bool c_lost = h[j].tree().find(id_at(5)) == nullptr && !h[j].tree().is_waiting(id_at(5));
    const bool d_wait = h[j].tree().is_waiting(id_at(6)) || h[j].tree().find(id_at(6)) != nullptr;
    const bool e_wait = h[j].tree().is_waiting(id_at(7)) || h[j].tree().find(id_at(7)) != nullptr;
    const std::size_t parked_after = h[j].deferred().size();
    const std::size_t ask_c1 = asks(id_at(5)), ask_p1 = asks(id_at(4));
    h.q.clear();
    // three P-53 windows: reask_parents
    for (int k = 0; k < 3; ++k) {
        h.now += pb::kAbandonTimeoutDefault + 1;
        (void)h[j].tick(h.now);
        h[j].reask_parents();
    }
    const std::size_t reask_c = asks(id_at(5));
    h.q.clear();
    // c arrives again (as the reply to such an ask would bring it): placed; are d and e released?
    const pb::NodeEventResult rc2 = h[j].on_carrier(s, frame_at(5));
    const std::uint64_t pos_after = h[j].tree().best().pos;
    const std::size_t parked_end = h[j].deferred().size();
    h.q.clear();
    for (int k = 0; k < 3; ++k) {
        h.now += pb::kAbandonTimeoutDefault + 1;
        (void)h[j].tick(h.now);
        h[j].reask_parents();
    }
    std::size_t asks_after = 0;
    for (const Msg& m : h.q) asks_after += (m.from == j && !m.frame.empty() && m.frame[0] == pb::kOpFcGetCarrier) ? 1 : 0;
    std::printf("  revnotcarrier: setup %d parked %d (c asked %zu); c begin DEFER ParentUnknown %d; p action %d, c action %d; "
                "c lost %d; d waiting %d, e waiting %d; parked %zu; asks c %zu, p %zu; reask c %zu; c again action %d; "
                "J at %llu (S at 7); parked %zu; asks after %zu\n",
                setup ? 1 : 0, parked ? 1 : 0, ask_c0, c_defer ? 1 : 0, static_cast<int>(rp.action),
                static_cast<int>(rc.action), c_lost ? 1 : 0, d_wait ? 1 : 0, e_wait ? 1 : 0, parked_after, ask_c1, ask_p1,
                reask_c, static_cast<int>(rc2.action), (unsigned long long)pos_after, parked_end, asks_after);
    check(setup && parked && c_defer, "revnotcarrier: setup (d, e parked on c; c admitted before p placed: ParentUnknown)");
    check(!c_lost, "revnotcarrier: c is not lost when its parent was placed before its DEFER parked");
    check(d_wait && e_wait, "revnotcarrier: d and e waiting or placed (no waiting entry discarded by c's park)");
    check(pos_after == 7 && parked_end == 0, "revnotcarrier: c placed, d and e released (J at " + std::to_string(pos_after) + ")");
}


// A relay node in manual mode on the harness's clock over a node loaded from a copy of `from` (the copy in h.kvs).
KatRelay kat_relay_loaded(Harness& h, FakeWire& w, const MemoryKv& from, const pb::PathbNodeConfig& cfg,
                          const std::function<void(pb::PathbRelayOptions&)>& tweak = nullptr,
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
    k.relay = std::make_unique<pb::PathbRelayNode>(o, *k.links, clock, [n = h.nodes.size()](const std::string& line) {
        if (g_relay_lines != nullptr) (*g_relay_lines)[n].push_back(line);
    });
    k.node = h.nodes.size();
    h.kvs.push_back(std::make_unique<MemoryKv>(from));
    MemoryKv& kv = *h.kvs.back();
    pb::LoadInputs in;
    in.T = cfg.T;
    in.journal_depth = cfg.journal_depth;
    pb::LoadResult lr = pb::pathb_load(kv, h.net.pool_id, h.net.rules_g, in);
    if (!lr.state) throw std::runtime_error("kat_relay_loaded: the store does not load");
    pb::PathbNodeIo io = k.relay->bind_io(h.io(k.node));
    if (io_tweak) io_tweak(io);
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, std::move(io), std::move(*lr.state), &kv));
    k.relay->attach(*h.nodes.back());
    k.relay->set_drive([&w] { return w.step(); });
    std::string why;
    if (!k.relay->start(why)) throw std::runtime_error(why);
    w.relays.push_back(k.relay.get());
    return k;
}

// A frame filter of the wire: FC_HEADERS from wire node `from` to wire node `to` dropped (that catch-up gets no reply).
std::function<void(FakeWire::Msg&)> drop_headers(std::size_t from, std::size_t to) {
    return [from, to](FakeWire::Msg& m) {
        if (m.from == from && m.to == to && !m.f.empty() && m.f[0] == pb::kOpFcHeaders) m.f.clear();
    };
}

// Two relay nodes (both launched; wire 0 = A, wire 1 = B): they mine `shared` carriers on one chain; apart, B mines
// `own` on its branch and A `more` on its chain (A's heavier).
// A decimal number, the whole string (at most 19 digits).
bool whole_u64(const std::string& s, std::uint64_t& v) {
    if (s.empty() || s.size() > 19) return false;
    v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return true;
}

// A `relay: caught up (<form>) at pos <n> t=<unix ms>` line, parsed whole.
struct CaughtLine {
    std::string form;
    std::uint64_t pos = 0, t = 0;
};
constexpr const char* kCaughtDone = "the catch-up from every HELLO peer ended by its done test";
constexpr const char* kCaughtJoin = "a join attempt completed; rule (4) kept the node's chain";
std::optional<CaughtLine> parse_caught(const std::string& l) {
    static const std::string pre = "relay: caught up (", mid = ") at pos ", tk = " t=";
    if (l.rfind(pre, 0) != 0) return std::nullopt;
    const std::size_t m = l.rfind(mid), k = l.rfind(tk);
    if (m == std::string::npos || m < pre.size() || k == std::string::npos || k < m + mid.size()) return std::nullopt;
    CaughtLine c;
    c.form = l.substr(pre.size(), m - pre.size());
    if (!whole_u64(l.substr(m + mid.size(), k - m - mid.size()), c.pos) || !whole_u64(l.substr(k + tk.size()), c.t))
        return std::nullopt;
    return c;
}
// The `relay: caught up (` lines of one node.
std::vector<std::string> caught_of(const std::map<std::size_t, std::vector<std::string>>& lines, std::size_t node) {
    std::vector<std::string> out;
    if (const auto it = lines.find(node); it != lines.end())
        for (const std::string& l : it->second)
            if (l.rfind("relay: caught up (", 0) == 0) out.push_back(l);
    return out;
}

// statustime: the status block's time line (serve_pathb prints it after `status: up=`) on the system relay clock:
// "  time: t=<unix ms>", parsed whole; three prints 3 ms apart rise, each inside the system clock's bracket.
void statustime() {
    const auto sys_ms = [] {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  std::chrono::system_clock::now().time_since_epoch())
                                                  .count());
    };
    const std::string pre = "  time: t=";
    const bool fixed = pb::status_time_line(1761700000123ULL) == "  time: t=1761700000123";
    const pb::RelayClock c = pb::RelayClock::system();
    std::vector<std::uint64_t> ts;
    bool parsed = true, inside = true;
    std::string last;
    for (int i = 0; i < 3; ++i) {
        if (i > 0) std::this_thread::sleep_for(std::chrono::milliseconds(3));
        const std::uint64_t lo = sys_ms();
        last = pb::status_time_line(c.wall_ms());
        const std::uint64_t hi = sys_ms();
        std::uint64_t t = 0;
        parsed = parsed && last.rfind(pre, 0) == 0 && whole_u64(last.substr(pre.size()), t);
        inside = inside && t >= lo && t <= hi;
        ts.push_back(t);
    }
    const bool rising = ts.size() == 3 && ts[0] < ts[1] && ts[1] < ts[2];
    std::printf("  statustime: %s; rises %llu -> %llu -> %llu\n", last.c_str(), (unsigned long long)ts[0],
                (unsigned long long)ts[1], (unsigned long long)ts[2]);
    check(fixed, "statustime: status_time_line(1761700000123) == \"  time: t=1761700000123\"");
    check(parsed && inside && rising,
          "statustime: three time lines on the system relay clock parse whole, each inside the system clock's unix-ms "
          "bracket, and rise");
}

// statusroots: the status block's roots line (serve_pathb prints it after `  time: t=`) from the current template
// (PathbJobSource::current()): "  roots: tip=<16 hex>", the tip whose window_root and mmr_root `status: up=` prints;
// "-" with no template. A's pass: the view at its start (id= on `status: up=`) at tip T; B's carrier on T reaches A in
// the pass; A's template at print is on T's successor S: the roots line names S, and S's window_root and mmr_root
// equal B's at S (B's view and template both at S); T's own window_root differs.
void statusroots() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true), b = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(i % 2 == 0 ? a : b, static_cast<std::size_t>(1 + i % 3), 300 + static_cast<std::uint32_t>(i));
    }
    const auto hex16 = [](const pb::Hash32& x) { return hex(x.data(), x.size()).substr(0, 16); };
    pb::PathbJobSource js([&](const pb::PathbTemplate& t, const pb::PathbSession& ss) { return h[a].make_job(t, ss); });
    const auto roots_now = [&js] {
        const std::optional<pb::PathbTemplate> c = js.current();
        return pb::status_roots_line(c ? &c->tip : nullptr);
    };
    const std::string none = roots_now();
    // the pass's view at its start
    const pb::Hash32 view_id = h[a].tree().best().id;
    const std::uint64_t view_pos = h[a].tree().best().pos;
    const pb::PathbTemplate t0 = h[a].make_template(h.now);
    (void)js.set_template(t0, pb::JobNetwork{});
    const std::string same = roots_now();
    // B's carrier on T reaches A within the pass
    h.tick_monero();
    const pb::NodeEventResult rb = h.mine(b, 4, 400);
    const pb::Hash32 succ = h[a].tree().best().id;
    const pb::CarrierNode* sn = h[a].tree().find(succ);
    const pb::PathbTemplate t1 = h[a].make_template(h.now);
    (void)js.set_template(t1, pb::JobNetwork{});
    const std::optional<pb::PathbTemplate> cur = js.current();
    const std::string moved = roots_now();
    const pb::PathbTemplate tb = h[b].make_template(h.now);
    js.clear();
    const std::string cleared = roots_now();
    std::printf("  statusroots: view %s pos %llu; template %s x %llu: \"%s\"; window_root %s (B at %s: %s; T: %s)\n",
                hex16(view_id).c_str(), (unsigned long long)view_pos, hex16(t1.tip).c_str(), (unsigned long long)t1.x,
                moved.c_str(), hex16(t1.window.window_root).c_str(), hex16(tb.tip).c_str(),
                hex16(tb.window.window_root).c_str(), hex16(t0.window.window_root).c_str());
    check(none == "  roots: tip=-" && pb::status_roots_line(nullptr) == "  roots: tip=-",
          "statusroots: no template: \"  roots: tip=-\"");
    check(t0.status == pb::TemplateStatus::Ok && t0.tip == view_id && same == "  roots: tip=" + hex16(view_id),
          "statusroots: the template on the view's tip: the roots line names that tip (" + same + ")");
    check(rb.action == pb::NodeAction::Placed && sn != nullptr && sn->parent == view_id && sn->pos == view_pos + 1 &&
                  t1.status == pb::TemplateStatus::Ok && t1.tip == succ && t1.x == view_pos + 2 && cur && cur->tip == succ,
          "statusroots: setup (B's carrier on the view's tip placed at A; A's template at print on that successor)");
    check(moved == "  roots: tip=" + hex16(succ) && hex16(succ) != hex16(view_id) && moved.size() == 29,
          "statusroots: the template on the view tip's successor: the roots line names the successor, not id= (" + moved +
                  ")");
    check(cur && h[b].tree().best().id == succ && tb.status == pb::TemplateStatus::Ok && tb.tip == succ &&
                  tb.window.window_root == cur->window.window_root && tb.window.mmr_root == cur->window.mmr_root &&
                  t0.window.window_root != cur->window.window_root,
          "statusroots: window_root and mmr_root of A's template equal B's at the roots tip; the view tip's window_root "
          "differs");
    check(cleared == "  roots: tip=-", "statusroots: the template withdrawn (clear()): \"  roots: tip=-\"");
}

struct Branches {
    KatRelay a, b;
    bool ok = true;
};
Branches branches(Harness& h, FakeWire& w, const KatNet& net, int shared, int own, int more, std::uint32_t nonce) {
    Branches o;
    o.a = kat_relay(h, w, table0(net), true);
    o.b = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    for (int i = 0; i < shared; ++i) {
        if (i % 3 == 0) h.tick_monero();
        o.ok = o.ok && mine_on(h, w, o.a.node, static_cast<std::size_t>(i % 5), nonce + static_cast<std::uint32_t>(i));
    }
    o.ok = o.ok && h[o.b.node].tree().best().id == h[o.a.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    h.tick_monero();
    for (int i = 0; i < own; ++i)
        o.ok = o.ok && mine_on(h, w, o.b.node, static_cast<std::size_t>(i % 5), nonce + 1000 + static_cast<std::uint32_t>(i));
    for (int i = 0; i < more; ++i) {
        if (i % 3 == 0) h.tick_monero();
        o.ok = o.ok && mine_on(h, w, o.a.node, static_cast<std::size_t>(i % 5), nonce + 2000 + static_cast<std::uint32_t>(i));
    }
    o.ok = o.ok && h[o.a.node].tree().best().pos == static_cast<std::uint64_t>(shared + more)
           && h[o.b.node].tree().best().pos == static_cast<std::uint64_t>(shared + own)
           && ::c2pool::xmr::native::u128_greater(h[o.a.node].tree().best().cum_work, h[o.b.node].tree().best().cum_work);
    return o;
}

// catchkeep: a store not caught up (its record K_NCU) holding A's chain (6 positions, placed by a walk with no HELLO,
// then restarted) whose one HELLO peer B holds a lighter branch (positions 1..4 and its own 5): the catch-up toward B's
// unheld tip steps down to the fork, its reply is kept by the node's own header work, and the catch-up ending by that
// reply leaves the store caught up: the record leaves, the chain is A's, and with no peer it builds templates.
void catchkeep() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    Branches br = branches(h, w, net, 4, 1, 2, 3100);
    const std::size_t a = br.a.node, b = br.b.node;
    const pb::Hash32 tip_a = h[a].tree().best().id;
    const std::size_t jw = h.add(table0(net), false, 1152, true);  // started empty, not launched: K_NCU
    MemoryKv& kvw = *h.kvs.back();
    for (std::uint64_t x = 1; x <= 6; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
            (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
    h.q.clear();
    const std::string ncu = pb::store_keys::ncu(0);
    const bool walked = h[jw].tree().best().id == tip_a && !h[jw].caught_up() && kvw.data.count(ncu) != 0;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
    MemoryKv& kvj = *h.kvs.back();
    const pb::TemplateStatus s0 = tstatus(h, j.node);
    const bool claim_loses = !pb::fork_choice_prefers(pb::ChainTip{h[b].tree().best().cum_work, h[b].tree().best().id},
                                                      pb::ChainTip{h[j.node].tree().best().cum_work, tip_a});
    w.edit = drop_headers(2, 1);  // B's own catch-up toward J gets no reply: B stays on its branch
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    w.connect(1, 2);
    w.run();
    const std::uint64_t t_line = h.now * 1000;  // the relay clock's wall_s() * 1000 (the KAT clock sets no wall_ms)
    const std::uint64_t asks = j.relay->stats().catchup_requests.load();
    const bool caught = h[j.node].caught_up() && kvj.data.count(ncu) == 0 && !h[j.node].first_round_open();
    const bool kept = h[j.node].tree().best().id == tip_a && !h[j.node].holds_tip(h[b].tree().best().id);
    w.links[2]->disconnect(w.id(2, 1));
    w.run();
    w.edit = nullptr;
    g_relay_lines = nullptr;
    const std::vector<std::string> cl = caught_of(lines, j.node);
    const std::optional<CaughtLine> c = cl.size() == 1 ? parse_caught(cl[0]) : std::nullopt;
    const pb::TemplateStatus s1 = tstatus(h, j.node);
    std::printf("  catchkeep: J at %llu (B at %llu); catch-up asks %llu; caught up %d; templates %d -> %d\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[b].tree().best().pos,
                (unsigned long long)asks, caught ? 1 : 0, static_cast<int>(s0), static_cast<int>(s1));
    check(br.ok && walked && claim_loses && s0 == pb::TemplateStatus::NoPathbPeer,
          "catchkeep: setup (J not caught up at A's tip 6, its record kept; B's tip 5 lighter and not held at J)");
    check(asks >= 2 && kept && caught && s1 != pb::TemplateStatus::NoPathbPeer && s1 != pb::TemplateStatus::CatchingUp,
          "catchkeep: the catch-up toward B's unheld lighter tip ends at its reply (A's chain kept) and leaves the store "
          "caught up: the record gone, templates with no peer (asks " + std::to_string(asks) + ")");
    std::printf("  catchkeep: %s\n", cl.empty() ? "no caught-up line" : cl[0].c_str());
    check(c && c->form == kCaughtDone && c->pos == 6 && c->pos == h[j.node].tree().best().pos && c->t == t_line,
          "catchkeep: one caught-up line, the done-test form ending \" at pos 6 t=" + std::to_string(t_line) +
                  "\" (J's best position, the relay clock's unix ms at the line; lines " + std::to_string(cl.size()) +
                  ")");
}

// catchlight: a lighter unheld tip costs at most one locator round per HELLO and never switches the chain. A holds
// 40 positions; B forks at 30 with two of its own. J, a full node at A's tip, meets only B: one locator round (from
// 40, 39, 38, 36, 32, 24; at most floor(log2 40) + 2 = 7 requests) ended by its reply, kept by J's own header work;
// no request in 3 x P-53 after it; a new link to B (a second HELLO) costs one round again; J's best never moves.
void catchlight() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    Branches br = branches(h, w, net, 30, 2, 10, 3400);
    const std::size_t a = br.a.node, b = br.b.node;
    const pb::Hash32 tip_a = h[a].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), true);
    w.connect(0, 2);
    w.run();
    for (int k = 0; k < 3; ++k) {
        h.now += 1;
        j.relay->tick();
        w.run();
    }
    const bool followed = h[j.node].tree().best().id == tip_a;
    w.links[2]->disconnect(w.id(2, 0));
    w.run();
    const pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t gen0 = h[j.node].best_changes();
    const std::uint64_t asks0 = rj.stats().catchup_requests.load();
    const std::uint64_t bound = 7;  // floor(log2 40) + 2
    w.edit = drop_headers(2, 1);    // B's own catch-up toward J gets no reply: B stays on its branch
    w.connect(1, 2);
    w.run();
    const std::uint64_t round1 = rj.stats().catchup_requests.load() - asks0;
    const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
    for (std::uint64_t k = 0; k < 3 * p53 + 2; ++k) {
        h.now += 1;
        j.relay->tick();
        w.run();
    }
    const std::uint64_t after = rj.stats().catchup_requests.load() - asks0 - round1;
    w.links[2]->disconnect(w.id(2, 1));
    w.run();
    w.reconnect(1, 2);
    w.run();
    const std::uint64_t round2 = rj.stats().catchup_requests.load() - asks0 - round1 - after;
    for (std::uint64_t k = 0; k < p53 + 2; ++k) {
        h.now += 1;
        j.relay->tick();
        w.run();
    }
    const std::uint64_t after2 = rj.stats().catchup_requests.load() - asks0 - round1 - after - round2;
    w.edit = nullptr;
    const bool never = h[j.node].tree().best().id == tip_a && h[j.node].best_changes() == gen0
                       && !h[j.node].holds_tip(h[b].tree().best().id) && rj.stats().strikes.load() == 0
                       && rj.stats().bans.load() == 0;
    std::printf("  catchlight: J at %llu, B at %llu; requests: round 1 %llu, after it %llu, round 2 %llu, after it %llu\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[b].tree().best().pos,
                (unsigned long long)round1, (unsigned long long)after, (unsigned long long)round2,
                (unsigned long long)after2);
    check(br.ok && followed, "catchlight: setup (J at A's tip 40; B's tip 32 on its own branch, lighter)");
    check(round1 >= 2 && round1 <= bound && after == 0 && round2 >= 2 && round2 <= bound && after2 == 0 && never,
          "catchlight: B's unheld lighter tip costs one locator round per HELLO (" + std::to_string(round1) + ", " +
                  std::to_string(round2) + " requests, at most " + std::to_string(bound) +
                  "), none after its reply; J's chain never switches");
}

// ---------------------------------------------------------------------------
// The template gate during a catch-up (E-194) and the caught-up line (E-193).
// The gate is open at node i: a template is attempted (no CatchingUp, no NoPathbPeer).
bool gate_open(Harness& h, std::size_t i) {
    const pb::TemplateStatus s = tstatus(h, i);
    return s != pb::TemplateStatus::CatchingUp && s != pb::TemplateStatus::NoPathbPeer;
}
// One frame of the wire delivered and only `pumped` run (a node in a pass of its own: frames arrive at its link and
// wait, it judges none); false: nothing to deliver.
bool step_only(FakeWire& w, std::initializer_list<pb::PathbRelayNode*> pumped) {
    if (w.q.empty()) return false;
    FakeWire::Msg m = std::move(w.q.front());
    w.q.pop_front();
    if (w.edit) w.edit(m);
    if (!m.f.empty() && w.links[m.to]->live.count(w.id(m.to, m.from)) != 0) w.links[m.to]->frame(w.id(m.to, m.from), m.f);
    for (pb::PathbRelayNode* r : pumped) r->pump();
    return true;
}
// A share of `node` placed and flooded; the wire not run (mine_on without its w.run()).
bool mine_only(Harness& h, std::size_t node, std::size_t payee, std::uint32_t nonce) {
    const std::optional<pb::PathbJob> j = h.job(node, payee, nonce);
    return j && h[node].on_own_share(*j, nonce, pb::Hash32{}).action == pb::NodeAction::Placed;
}

// gateprobe2 (E-194, the page boundary): A holds 2,600 positions (beyond two pages of P-01 = 1,152) and mines one
// carrier every 10 s; J, an empty store not caught up, catches up from A while the wire carries at most 100 frames per
// second. Read after every tick, pump and wire step: the template gate never opens while J is more than one position
// behind A (the hold belongs to the catch-up, not to one page). The caught-up line comes while A keeps mining, at A's
// position (E-193 (iv)).
void gateprobe2() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;  // P-14: one FC_HEADERS frame holds a full page of P-01 headers
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    const std::uint64_t n = 2600;
    bool mined = true;
    std::uint64_t mcount = 0;
    for (; mcount < n && mined; ++mcount) {
        if (mcount % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(mcount % 5), 40000 + static_cast<std::uint32_t>(mcount));
    }
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    w.connect(1, 0);
    int open_behind = 0, open_windows = 0, secs = 0;
    bool was_open = false;
    std::string opens;
    struct LineAt {
        std::uint64_t line = 0, j = 0, a = 0;
    };
    std::vector<LineAt> line_at;
    std::size_t scanned = 0;
    const auto observe = [&](const char* where) {
        const std::uint64_t jp = h[j.node].tree().best().pos, ap = h[a.node].tree().best().pos;
        const bool open = jp + 1 < ap && gate_open(h, j.node);
        if (open) {
            ++open_behind;
            if (!was_open && ++open_windows <= 8)
                opens += " [t" + std::to_string(secs) + " " + where + " J " + std::to_string(jp) + " A " + std::to_string(ap) + "]";
        }
        was_open = open;
        const std::vector<std::string>& lj = lines[j.node];
        for (; scanned < lj.size(); ++scanned)
            if (const std::optional<CaughtLine> c = parse_caught(lj[scanned]); c && c->form == kCaughtDone)
                line_at.push_back(LineAt{c->pos, jp, ap});
    };
    for (; secs < 1800; ++secs) {
        h.now += 1;
        if (secs % 10 == 9) {
            if (mcount % 12 == 0) h.tick_monero();
            mined = mine_on(h, w, a.node, static_cast<std::size_t>(mcount % 5), 40000 + static_cast<std::uint32_t>(mcount)) && mined;
            ++mcount;
            observe("mine");
        }
        for (pb::PathbRelayNode* r : {a.relay.get(), j.relay.get()}) {
            r->tick();
            observe("tick");
            r->pump();
            observe("pump");
        }
        for (int m = 0; m < 100 && w.step(); ++m) observe("step");
        if (h[j.node].caught_up() && secs > 60 && h[j.node].tree().best().id == h[a.node].tree().best().id) break;
    }
    g_relay_lines = nullptr;
    std::string ls;
    for (const LineAt& l : line_at)
        ls += " [pos " + std::to_string(l.line) + ", J " + std::to_string(l.j) + ", A " + std::to_string(l.a) + "]";
    std::printf("  gateprobe2: J at %llu, A at %llu after %d s; caught up %d; gate open while J more than one behind A: %d "
                "observations in %d windows%s; caught-up lines:%s\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos, secs,
                h[j.node].caught_up() ? 1 : 0, open_behind, open_windows, opens.c_str(), ls.c_str());
    check(mined && h[j.node].caught_up() && h[j.node].tree().best().id == h[a.node].tree().best().id,
          "gateprobe2: J catches up 2,600 positions and more from A while A mines one carrier every 10 s");
    check(open_behind == 0, "gateprobe2: no template while J is more than one position behind A, across the page "
                            "boundaries (" + std::to_string(open_behind) + " observations)");
    check(line_at.size() == 1 && line_at[0].line == line_at[0].j && line_at[0].j == line_at[0].a,
          "gateprobe2: one caught-up line, while A keeps mining, with J at A's position (lines " +
                  std::to_string(line_at.size()) + ")");
}

// gatepass (E-194): a pass of the node's own longer than P-53 while body frames arrive. A holds 600 positions; J, an
// empty store not caught up, catches up from A while the wire carries at most 100 frames per second. With A's page
// verified and its bodies on the wire, J's tick runs and then J's node lock is held for P-53 + 10 s: A's bodies arrive
// at J's link meanwhile and none is judged, so J's best does not move. After the pass the gate holds (the pass is the
// node's own processing, not the server's non-service), and it never opens while J is more than one position behind
// A.
void gatepass() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    const std::uint64_t n = 600;
    bool mined = true;
    for (std::uint64_t i = 0; i < n && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 47000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
    int open_behind = 0;
    const auto observe = [&] {
        if (h[j.node].tree().best().pos + 1 < h[a.node].tree().best().pos && gate_open(h, j.node)) ++open_behind;
    };
    const auto second = [&] {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), j.relay.get()}) {
            r->tick();
            observe();
            r->pump();
            observe();
        }
        for (int m = 0; m < 100 && w.step(); ++m) observe();
    };
    w.connect(1, 0);
    observe();
    int secs = 0;
    for (; secs < 120 && h[j.node].tree().best().pos < 100; ++secs) second();  // A's page verified, its bodies arriving
    h.now += 1;
    j.relay->tick();  // J's tick, then its own pass (nothing placed in between)
    observe();
    const std::uint64_t at_pass = h[j.node].tree().best().pos;
    const bool round_over = !h[j.node].first_round_open();
    const std::size_t on_wire = w.q.size();
    const bool held_before = h[j.node].delivering();
    const std::uint64_t busy0 = j.relay->node_busy_ms();
    std::uint64_t arrived = 0;
    j.relay->test_hold_node([&] {  // J's own pass: its node lock held P-53 + 10 s; A serves meanwhile
        for (std::uint64_t k = 0; k < p53 + 10; ++k) {
            h.now += 1;
            a.relay->tick();
            a.relay->pump();
            for (int m = 0; m < 100 && step_only(w, {a.relay.get()}); ++m) ++arrived;
        }
    });
    const std::uint64_t busy = j.relay->node_busy_ms() - busy0;
    const std::uint64_t in_pass = h[j.node].tree().best().pos - at_pass;
    j.relay->tick();
    const pb::TemplateStatus after = tstatus(h, j.node);
    observe();
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs) second();
    std::printf("  gatepass: J at %llu at the pass (%zu frames on the wire, first round over %d, held %d); the pass %llu ms "
                "of the node lock, %llu frames arrived, %llu placed in it; after it status %d; J at %llu after %d s; "
                "gate open while J more than one behind A: %d\n",
                (unsigned long long)at_pass, on_wire, round_over ? 1 : 0, held_before ? 1 : 0, (unsigned long long)busy,
                (unsigned long long)arrived, (unsigned long long)in_pass, static_cast<int>(after),
                (unsigned long long)h[j.node].tree().best().pos, secs, open_behind);
    check(mined && round_over && held_before && at_pass > 0 && at_pass < n && on_wire > 0,
          "gatepass: setup (A at 600; J's first round over, A's page verified, J inside it with bodies on the wire)");
    check(arrived > 0 && in_pass == 0 && busy >= (p53 + 10) * 1000,
          "gatepass: J's own pass of P-53 + 10 s (the node lock held): A's frames arrive at J's link, none judged");
    check(after == pb::TemplateStatus::CatchingUp,
          "gatepass: after a pass of J's own longer than P-53 while A's bodies arrived, the gate holds (no lapse; "
          "status " + std::to_string(static_cast<int>(after)) + ")");
    check(open_behind == 0 && h[j.node].tree().best().id == tip,
          "gatepass: J reaches A's tip; no template while J is more than one position behind A (" +
                  std::to_string(open_behind) + ")");
}

// gatepassidle (E-194): a pass of the node's own longer than P-53 with nothing in hand. A holds 1,300 positions (two
// pages of P-01); J, an empty store not caught up, catches up from A while the wire carries at most 100 frames per
// second. With A's first page placed at J and nothing in hand, J's tick asks the second page; then J's node lock is
// held for P-53 + 10 s while A's reply waits on the wire (nothing reaches J's link). Read after J's next tick, nothing in
// hand: the gate holds (the last body's delivery within P-53 of the server's time; the pass is the node's own
// processing). J then reaches A's tip.
void gatepassidle() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    const std::uint64_t n = 1300;
    bool mined = true;
    for (std::uint64_t i = 0; i < n && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 53000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
    w.connect(1, 0);
    bool page1 = false;
    int secs = 0;
    for (; secs < 120 && !page1; ++secs) {  // until A's first page is placed at J (read after every step)
        h.now += 1;
        a.relay->tick();
        a.relay->pump();
        rj.tick();
        rj.pump();
        page1 = h[j.node].tree().best().pos >= 1152;
        for (int m = 0; m < 100 && !page1 && w.step(); ++m) page1 = h[j.node].tree().best().pos >= 1152;
    }
    const std::uint64_t at_pass = h[j.node].tree().best().pos;
    h.now += 1;
    rj.tick();  // J's tick: the second page asked; then J's own pass (nothing placed, nothing arriving)
    const bool in_hand_before = !h[j.node].drain_done();
    const std::uint64_t busy0 = rj.node_busy_ms();
    std::uint64_t to_a = 0;
    rj.test_hold_node([&] {  // J's own pass: A answers, its reply waits on the wire (frames to A only delivered)
        for (std::uint64_t k = 0; k < p53 + 10; ++k) {
            h.now += 1;
            a.relay->tick();
            a.relay->pump();
            std::deque<FakeWire::Msg> keep;
            while (!w.q.empty()) {
                FakeWire::Msg m = std::move(w.q.front());
                w.q.pop_front();
                if (m.to != a.links->self) {
                    keep.push_back(std::move(m));
                    continue;
                }
                if (!m.f.empty() && w.links[m.to]->live.count(w.id(m.to, m.from)) != 0)
                    w.links[m.to]->frame(w.id(m.to, m.from), m.f);
                a.relay->pump();
                ++to_a;
            }
            w.q = std::move(keep);
        }
    });
    const std::uint64_t busy = rj.node_busy_ms() - busy0;
    const std::size_t waiting = w.q.size();
    rj.tick();
    const bool in_hand_after = !h[j.node].drain_done();
    const pb::TemplateStatus after = tstatus(h, j.node);
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs) {
        h.now += 1;
        a.relay->tick();
        a.relay->pump();
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    std::printf("  gatepassidle: J at %llu at the pass (in hand %d); the pass %llu ms of the node lock, frames to A %llu, "
                "frames waiting for J %zu; after it in hand %d, status %d; J at %llu after %d s\n",
                (unsigned long long)at_pass, in_hand_before ? 1 : 0, (unsigned long long)busy, (unsigned long long)to_a,
                waiting, in_hand_after ? 1 : 0, static_cast<int>(after), (unsigned long long)h[j.node].tree().best().pos,
                secs);
    check(mined && at_pass == 1152 && !in_hand_before && to_a >= 1 && waiting >= 1 && busy >= (p53 + 10) * 1000,
          "gatepassidle: setup (A's first page placed at J, nothing in hand; the second page asked; J's own pass of "
          "P-53 + 10 s, A's reply waiting on the wire)");
    check(!in_hand_after && after == pb::TemplateStatus::CatchingUp,
          "gatepassidle: after the pass, nothing in hand: the gate holds (status " +
                  std::to_string(static_cast<int>(after)) + ")");
    check(h[j.node].tree().best().id == tip, "gatepassidle: J reaches A's tip");
}

// gatenowin (E-194 (v)): after the first round a page or side-header delivery holds the gate only toward a tip whose
// verified header work wins. J, a store not caught up (its record K_NCU), holds A's chain (6 shared positions and 35
// of A's own, walked with no HELLO, then restarted); its one HELLO peer B holds a lighter branch (the 6 shared and 30 of
// its own), so no header B serves wins against J's best. B answers every request of J's catch-up (its locator steps,
// then its branch in pages of a few headers), one frame every 2 s, for more than P-53: past the first round the gate
// stays open throughout, and J's chain never switches.
void gatenowin() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 1500;  // a few headers per FC_HEADERS frame: B's branch in many pages
    FakeWire w;
    Branches br = branches(h, w, net, 6, 30, 35, 48000);
    const std::size_t a = br.a.node, b = br.b.node;
    const pb::Hash32 tip_a = h[a].tree().best().id, tip_b = h[b].tree().best().id;
    const std::size_t jw = h.add(table0(net), false, 1152, true);  // started empty, not launched: K_NCU
    MemoryKv& kvw = *h.kvs.back();
    const std::uint64_t la = h[a].tree().best().pos;
    for (std::uint64_t x = 1; x <= la; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
            (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
    h.q.clear();
    const bool walked = h[jw].tree().best().id == tip_a && !h[jw].caught_up();
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
    const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
    w.edit = drop_headers(2, 1);  // B's own catch-up toward J gets no reply: B stays on its branch
    w.connect(1, 2);
    const auto headers_b_to_j = [&] {
        const FakeWire::Msg& m = w.q.front();
        return m.from == 1 && m.to == 2 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders;
    };
    std::uint64_t replies = 0, after_round = 0, first_after = 0, last_after = 0, open_s = 0, held_s = 0;
    int secs = 0;
    for (; secs < 600 && !h[j.node].caught_up(); ++secs) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {br.b.relay.get(), j.relay.get()}) {
            r->tick();
            r->pump();
        }
        bool slot = secs % 2 == 0;  // one FC_HEADERS frame of B to J every 2 s
        while (!w.q.empty()) {
            if (headers_b_to_j()) {
                if (!slot) break;
                slot = false;
                const bool past_round = !h[j.node].first_round_open();
                ++replies;
                if (past_round) {
                    if (after_round++ == 0) first_after = h.now;
                    last_after = h.now;
                }
            }
            w.step();
        }
        if (!h[j.node].first_round_open() && !h[j.node].caught_up() && !h[j.node].holds_tip(tip_b))
            ++(gate_open(h, j.node) ? open_s : held_s);
    }
    w.edit = nullptr;
    std::printf("  gatenowin: B's replies to J %llu (%llu past the first round, over %llu s); seconds past the first round: "
                "gate open %llu, held %llu; J caught up %d after %d s, at A's tip %d\n",
                (unsigned long long)replies, (unsigned long long)after_round,
                (unsigned long long)(last_after - first_after), (unsigned long long)open_s, (unsigned long long)held_s,
                h[j.node].caught_up() ? 1 : 0, secs, h[j.node].tree().best().id == tip_a ? 1 : 0);
    check(br.ok && walked && !pb::fork_choice_prefers(pb::ChainTip{h[b].tree().best().cum_work, tip_b},
                                                      pb::ChainTip{h[j.node].tree().best().cum_work, tip_a}),
          "gatenowin: setup (J not caught up at A's tip, its record kept; B's tip lighter, not held at J)");
    check(after_round >= 4 && last_after - first_after > p53 && open_s > p53 && held_s == 0,
          "gatenowin: B keeps answering J's page requests inside P-53 for more than P-53 with no verified win: past the "
          "first round the gate stays open (held " + std::to_string(held_s) + " s, open " + std::to_string(open_s) + " s)");
    check(h[j.node].caught_up() && h[j.node].tree().best().id == tip_a,
          "gatenowin: the catch-up ends by its reply (B's branch kept off): J caught up on A's chain");
}

// caughtdrain (E-193): the caught-up line waits for the drain. A holds 1,300 positions (two pages of P-01) and mines
// one carrier every 10 s; J, an empty store not caught up, catches up from A (the wire at most 50 frames per second):
// A's carriers mined during the first page arrive above the HELLO tip before the second page's bodies and are parked
// at J until the HELLO tip is placed. Right after J places the HELLO tip,
// before its next tick, a pass of J's own (its node lock held 30 s) while A mines three carriers that arrive at J's
// link: J's done test then holds the HELLO tip with frames received and not judged; the line waits for them and comes
// at A's position. A keeps mining one carrier every 10 s: the line comes once (condition (iv)).
void caughtdrain() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    std::uint64_t mcount = 0;
    bool mined = true;
    for (; mcount < 1300 && mined; ++mcount) {
        if (mcount % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(mcount % 5), 49000 + static_cast<std::uint32_t>(mcount));
    }
    const pb::Hash32 hello_tip = h[a.node].tree().best().id;
    const std::uint64_t hello_pos = h[a.node].tree().best().pos;
    const auto mine_a = [&] {  // one carrier of A, flooded on the wire
        if (mcount % 12 == 0) h.tick_monero();
        mined = mine_only(h, a.node, static_cast<std::size_t>(mcount % 5), 49000 + static_cast<std::uint32_t>(mcount)) && mined;
        ++mcount;
    };
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    struct LineAt {
        std::uint64_t line = 0, j = 0, a = 0;
    };
    std::vector<LineAt> line_at;
    std::size_t scanned = 0;
    const auto scan = [&] {
        const std::vector<std::string>& lj = lines[j.node];
        for (; scanned < lj.size(); ++scanned)
            if (const std::optional<CaughtLine> c = parse_caught(lj[scanned]); c && c->form == kCaughtDone)
                line_at.push_back(LineAt{c->pos, h[j.node].tree().best().pos, h[a.node].tree().best().pos});
    };
    w.connect(1, 0);
    int secs = 0;
    bool reached = false;
    std::size_t parked_max = 0;
    const auto look = [&] {
        scan();
        parked_max = std::max(parked_max, h[j.node].deferred().size());
        reached = h[j.node].holds_tip(hello_tip);
    };
    for (; secs < 600 && !reached; ++secs) {  // until J places the HELLO tip (read after every pump and wire step)
        h.now += 1;
        if (secs % 10 == 1) mine_a();
        a.relay->tick();
        a.relay->pump();
        j.relay->tick();
        j.relay->pump();
        look();
        for (int m = 0; m < 50 && !reached && w.step(); ++m) look();
    }
    const std::uint64_t j_reach = h[j.node].tree().best().pos, a_reach = h[a.node].tree().best().pos;
    const std::size_t lines_reach = line_at.size();
    j.relay->test_hold_node([&] {  // J's own pass right after the placement: A mines three carriers meanwhile
        for (int k = 0; k < 30; ++k) {
            h.now += 1;
            if (k % 10 == 9) mine_a();
            a.relay->tick();
            a.relay->pump();
            for (int m = 0; m < 50 && step_only(w, {a.relay.get()}); ++m) {
            }
        }
    });
    const std::uint64_t a_pass = h[a.node].tree().best().pos, j_pass = h[j.node].tree().best().pos;
    j.relay->tick();  // the done test: the HELLO tip held, A's three carriers received and not judged
    scan();
    const std::size_t lines_tick = line_at.size();
    j.relay->pump();
    scan();
    for (int k = 0; k < 60; ++k, ++secs) {  // A keeps mining one carrier every 10 s
        h.now += 1;
        if (secs % 10 == 1) mine_a();
        a.relay->tick();
        a.relay->pump();
        scan();
        j.relay->tick();
        scan();
        j.relay->pump();
        scan();
        for (int m = 0; m < 50 && w.step(); ++m) scan();
    }
    g_relay_lines = nullptr;
    std::string ls;
    for (const LineAt& l : line_at)
        ls += " [pos " + std::to_string(l.line) + ", J " + std::to_string(l.j) + ", A " + std::to_string(l.a) + "]";
    std::printf("  caughtdrain: HELLO tip %llu; parked at J at most %zu; J at %llu, A at %llu at the placement; after J's "
                "pass J %llu, A %llu; lines at the done test's tick %zu; J at %llu, A at %llu after %d s; caught-up "
                "lines:%s\n",
                (unsigned long long)hello_pos, parked_max, (unsigned long long)j_reach, (unsigned long long)a_reach,
                (unsigned long long)j_pass, (unsigned long long)a_pass, lines_tick,
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos, secs,
                ls.c_str());
    check(mined && reached && parked_max > 0 && a_reach > hello_pos && j_reach == a_reach && lines_reach == 0,
          "caughtdrain: setup (A's carriers mined during the catch-up parked at J above the HELLO tip and drained at its "
          "placement; no line yet)");
    check(j_pass == j_reach && a_pass == a_reach + 3,
          "caughtdrain: J's own pass: A's three carriers arrive at J's link, none judged");
    check(lines_tick == 0, "caughtdrain: the done test holds the HELLO tip with A's frames received and not judged: no "
                           "caught-up line yet");
    check(line_at.size() == 1 && line_at[0].line == line_at[0].j && line_at[0].j == line_at[0].a
                  && line_at[0].line >= a_pass && h[j.node].caught_up(),
          "caughtdrain: one caught-up line, after the drain, at A's position, while A keeps mining one carrier every "
          "10 s (lines " + std::to_string(line_at.size()) + ")");
}

// The drain window (E-194 (vi)). A holds 600 positions; J, an empty store not caught up, catches up from A (the wire at
// most 100 frames per second). With J at 300 or more, frames of A (copies of its carriers) are parked at J's relay,
// received and not judged; then J places the HELLO tip. `drop` false: three frames, run again 20 s later. `drop` true
// (J's parked list holds at most 2): two frames that never run again; five seconds after the HELLO tip two more, run
// again 3 s later, whose parking evicts the first two. Read once per second after J's tick: its template status and
// its caught-up line.
struct DrainWindow {
    bool setup = false;
    std::uint64_t hello_pos = 0, a_pos = 0, dropped = 0;
    int held = 0, open = 0;  // reads before the line
    bool line = false, line_at_a = false, open_at_end = false, caught_up = false;
    std::uint64_t strikes = 0, bans = 0;
};
DrainWindow drain_window(bool drop) {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    DrainWindow o;
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool mined = true;
    for (std::uint64_t i = 0; i < 600 && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 50000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 hello_tip = h[a.node].tree().best().id;
    std::vector<std::vector<std::uint8_t>> copies;
    for (const std::uint64_t x : {100, 200, 300, 400})
        if (const std::optional<pb::Hash32> id = h[a.node].store().best_at(x))
            copies.push_back(*pb::encode_fc_carrier(0, *h[a.node].bodies().get(*id), 16));
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, false, [drop](pb::PathbRelayOptions& r) {
        if (drop) r.parked_max = 2;
    }, nullptr, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t pa = w.id(1, 0);  // A at J
    const std::uint64_t dropped0 = rj.stats().queue_dropped.load();
    w.connect(1, 0);
    bool parked = false, reached = false;
    for (int secs = 0; secs < 120 && !reached; ++secs) {  // until J places the HELLO tip (read after every step)
        h.now += 1;
        a.relay->tick();
        a.relay->pump();
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && !reached; ++m) {
            if (!parked && h[j.node].tree().best().pos >= 300 && copies.size() == 4) {
                if (drop) {
                    rj.test_park(pa, copies[0]);  // never run again
                    rj.test_park(pa, copies[1]);
                } else {
                    for (std::size_t k = 0; k < 3; ++k) rj.test_park(pa, copies[k], (h.now + 20) * 1000);
                }
                parked = true;
            }
            reached = h[j.node].holds_tip(hello_tip);
            if (reached || !w.step()) break;
        }
        reached = reached || h[j.node].holds_tip(hello_tip);
    }
    o.setup = mined && parked && reached;
    o.hello_pos = h[j.node].tree().best().pos;
    for (int k = 0; k < 40; ++k) {
        h.now += 1;
        if (drop && k == 5)  // two later frames evict the two that never run
            for (std::size_t c = 2; c < 4; ++c) rj.test_park(pa, copies[c], (h.now + 3) * 1000);
        rj.tick();
        if (caught_of(lines, j.node).empty()) ++(gate_open(h, j.node) ? o.open : o.held);
        rj.pump();
        a.relay->tick();
        a.relay->pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    const std::vector<std::string> cl = caught_of(lines, j.node);
    g_relay_lines = nullptr;
    const std::optional<CaughtLine> c = cl.size() == 1 ? parse_caught(cl[0]) : std::nullopt;
    o.a_pos = h[a.node].tree().best().pos;
    o.line = c && c->form == kCaughtDone;
    o.line_at_a = o.line && c->pos == o.a_pos;
    o.caught_up = h[j.node].caught_up();
    o.open_at_end = gate_open(h, j.node);
    o.dropped = rj.stats().queue_dropped.load() - dropped0;
    o.strikes = rj.stats().strikes.load();
    o.bans = rj.stats().bans.load();
    return o;
}
void print_drain(const char* name, const DrainWindow& o) {
    std::printf("  %s: J at the HELLO tip %llu; reads before the line: held %d, open %d; dropped from J's parked list "
                "%llu; line %d at A's position %d; caught up %d; gate open at the end %d; strikes %llu, bans %llu\n",
                name, (unsigned long long)o.hello_pos, o.held, o.open, (unsigned long long)o.dropped, o.line ? 1 : 0,
                o.line_at_a ? 1 : 0, o.caught_up ? 1 : 0, o.open_at_end ? 1 : 0, (unsigned long long)o.strikes,
                (unsigned long long)o.bans);
}

// drainwindow (E-194 (vi)): every HELLO tip held and frames in hand: the gate holds until they are judged; then the
// caught-up line comes at A's position and the gate opens.
void drainwindow() {
    const DrainWindow o = drain_window(false);
    print_drain("drainwindow", o);
    check(o.setup && o.hello_pos == 600, "drainwindow: setup (three frames of A parked at J, then J at the HELLO tip 600)");
    check(o.held >= 10 && o.open == 0,
          "drainwindow: while the frames are in hand the gate holds (held " + std::to_string(o.held) + ", open " +
                  std::to_string(o.open) + ")");
    check(o.line && o.line_at_a && o.caught_up && o.open_at_end && o.strikes == 0 && o.bans == 0,
          "drainwindow: the frames judged: the caught-up line at A's position, the gate open, no token");
}

// draindrop (E-193, E-194 (vi)): frames dropped while in hand leave the drain: two frames that never run again are
// evicted from J's parked list (at most 2) by two later ones; once those are judged the line comes and the gate opens.
void draindrop() {
    const DrainWindow o = drain_window(true);
    print_drain("draindrop", o);
    check(o.setup && o.hello_pos == 600, "draindrop: setup (two frames of A parked at J for good, then J at the HELLO tip 600)");
    check(o.held >= 5 && o.open == 0 && o.dropped == 2,
          "draindrop: the gate holds while frames are in hand; the two evicted (dropped " + std::to_string(o.dropped) +
                  ", held " + std::to_string(o.held) + ")");
    check(o.line && o.line_at_a && o.caught_up && o.open_at_end && o.strikes == 0 && o.bans == 0,
          "draindrop: the evicted frames leave the drain: the caught-up line at A's position, the gate open, no token");
}

// ---------------------------------------------------------------------------
// The template gate against R-CU-1's first conjunct (E-194 (vi) as worded by RDWR, 2026-10-31): frames in hand hold
// the gate whatever the catch-ups; once every HELLO catch-up ended (its done test, or its reply's own decision), a
// completed attempt is kept, or an adoption, the gate holds until K_NCU ends; before that it opens only for a catch-up
// still open (or handed to the joiner) toward a tip the node does not hold, nothing delivered and nothing in hand.
// The reads of one run, before the caught-up line: open or held, frames in hand or after the drain.
struct GateReads {
    int open_in_hand = 0, held_in_hand = 0, open_after = 0, held_after = 0;
    void read(Harness& h, std::size_t node) {
        const bool open = gate_open(h, node), in_hand = !h[node].drain_done();
        if (in_hand) ++(open ? open_in_hand : held_in_hand);
        else ++(open ? open_after : held_after);
    }
    std::string str() const {
        return "in hand open " + std::to_string(open_in_hand) + " held " + std::to_string(held_in_hand) +
               ", after the drain open " + std::to_string(open_after) + " held " + std::to_string(held_after);
    }
};

// gatesib (E-194 (vi)): A holds 600 positions; Y, a full node cut from A, holds its own tip at the same height or one
// below it that J's chain beats. J, an empty store not caught up, catches up from X (the one holding the winning tip);
// with J at 300 or more three copies of X's carriers are parked at J's relay (received and not judged, run again 30 s
// later). Once J holds X's tip, J connects to Y, whose HELLO tip J does not hold.
//   keep    Y's sibling at 599 (lighter): Y answers, J's own header work keeps its chain (Keep, Y's tip not held);
//   tie     Y's sibling at 600 (equal work, a higher id: Keep);
//   silent  Y's sibling at 599; Y never answers FC_GETHEADERS (a claim alone).
// Read after every tick of J for 40 s, until the caught-up line.
struct GateSib {
    bool setup = false, y_held = false, line = false, caught_up = false;
    GateReads r;
    int uc_in_hand = 0, uc_after = 0, no_uc_after = 0;  // unverified_claims() at the reads: in hand true; after: true, false
    std::uint64_t j_pos = 0, y_pos = 0, strikes = 0, bans = 0;
};
GateSib gate_sib(int mode) {  // 0 keep, 1 silent, 2 tie
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    GateSib o;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool mined = true;
    const std::uint64_t cut = mode == 2 ? 599 : 598;
    std::uint64_t i = 0;
    for (; i < cut && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 61000 + static_cast<std::uint32_t>(i));
    }
    const bool b_synced = h[b.node].tree().best().id == h[a.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (; i < 600 && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 61000 + static_cast<std::uint32_t>(i));
    }
    mined = mine_on(h, w, b.node, 3, 69001) && mined;  // B's own tip: 599 (keep, silent) or 600 (tie)
    // X: the node whose tip wins (A's 600, or in the tie the lower id); Y: the other
    const bool a_wins = pb::fork_choice_prefers(pb::ChainTip{h[a.node].tree().best().cum_work, h[a.node].tree().best().id},
                                                pb::ChainTip{h[b.node].tree().best().cum_work, h[b.node].tree().best().id});
    KatRelay& x = a_wins ? a : b;
    KatRelay& y = a_wins ? b : a;
    const std::size_t xw = a_wins ? 0 : 1, yw = a_wins ? 1 : 0;
    const pb::Hash32 x_tip = h[x.node].tree().best().id, y_tip = h[y.node].tree().best().id;
    o.y_pos = h[y.node].tree().best().pos;
    std::vector<std::vector<std::uint8_t>> copies;
    for (const std::uint64_t p : {100, 200, 300})
        if (const std::optional<pb::Hash32> id = h[x.node].store().best_at(p))
            copies.push_back(*pb::encode_fc_carrier(0, *h[x.node].bodies().get(*id), 16));
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(2, xw);
    const std::uint64_t px = w.id(2, xw);  // X at J
    bool parked = false, reached = false;
    for (int secs = 0; secs < 200 && !reached; ++secs) {
        h.now += 1;
        x.relay->tick();
        x.relay->pump();
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && !reached; ++m) {
            if (!parked && h[j.node].tree().best().pos >= 300 && copies.size() == 3) {
                for (const auto& f : copies) rj.test_park(px, f, (h.now + 30) * 1000);
                parked = true;
            }
            reached = h[j.node].holds_tip(x_tip);
            if (reached || !w.step()) break;
        }
        reached = reached || h[j.node].holds_tip(x_tip);
    }
    const bool in_hand_at_reach = !h[j.node].drain_done();
    w.edit = [mode, yw](FakeWire::Msg& m) {
        if (m.f.empty() || m.f[0] != pb::kOpFcHeaders) return;
        if (m.from == 2 && m.to == yw) m.f.clear();               // Y's own catch-up toward J gets no reply
        if (mode == 1 && m.from == yw && m.to == 2) m.f.clear();  // silent: Y never answers J
    };
    w.connect(2, yw);
    w.run();
    for (int k = 0; k < 40; ++k) {
        h.now += 1;
        rj.tick();
        if (caught_of(lines, j.node).empty() && !h[j.node].caught_up()) {
            o.r.read(h, j.node);
            const bool uc = h[j.node].unverified_claims();
            if (!h[j.node].drain_done())
                o.uc_in_hand += uc ? 1 : 0;
            else
                ++(uc ? o.uc_after : o.no_uc_after);
        }
        rj.pump();
        for (pb::PathbRelayNode* r : {a.relay.get(), b.relay.get()}) {
            r->tick();
            r->pump();
        }
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    o.setup = mined && b_synced && parked && reached && in_hand_at_reach && o.y_pos == (mode == 2 ? 600 : 599)
              && (mode != 2 || h[a.node].tree().best().cum_work.lo == h[b.node].tree().best().cum_work.lo);
    o.y_held = h[j.node].holds_tip(y_tip);
    o.line = caught_of(lines, j.node).size() == 1;
    o.caught_up = h[j.node].caught_up();
    o.j_pos = h[j.node].tree().best().pos;
    o.strikes = rj.stats().strikes.load();
    o.bans = rj.stats().bans.load();
    return o;
}
void gatesib() {
    for (int mode : {0, 2, 1}) {
        const GateSib o = gate_sib(mode);
        const std::string name = mode == 0 ? "gatesib keep" : mode == 2 ? "gatesib tie" : "gatesib silent";
        std::printf("  %s: setup %d; J %llu, Y's tip %llu held %d; reads before the line: %s; unverified_claims in "
                    "hand %d, after the drain %d true %d false; line %d caught up %d; strikes %llu bans %llu\n",
                    name.c_str(), o.setup ? 1 : 0, (unsigned long long)o.j_pos, (unsigned long long)o.y_pos,
                    o.y_held ? 1 : 0, o.r.str().c_str(), o.uc_in_hand, o.uc_after, o.no_uc_after, o.line ? 1 : 0,
                    o.caught_up ? 1 : 0, (unsigned long long)o.strikes, (unsigned long long)o.bans);
        check(o.setup, name + ": setup (Y's tip unheld at J, frames of X in hand when J holds X's tip)");
        check(o.r.open_in_hand == 0 && o.r.held_in_hand >= 10,
              name + ": no template while frames are in hand (" + o.r.str() + ")");
        if (mode == 1) {
            check(o.r.open_after >= 5 && !o.line && !o.caught_up,
                  name + ": after the drain a claim alone opens the gate; K_NCU set, no line (Y's catch-up open)");
            check(o.uc_in_hand == 0 && o.uc_after >= 5 && o.no_uc_after == 0,
                  name + ": unverified_claims() reads the gate: false while frames are in hand, true after the drain "
                         "(in hand " + std::to_string(o.uc_in_hand) + ", after " + std::to_string(o.uc_after) + "/" +
                         std::to_string(o.no_uc_after) + ")");
        }
        else
            check(o.r.open_after == 0 && o.line && o.caught_up && !o.y_held && o.strikes == 0 && o.bans == 0,
                  name + ": the Keep ends the catch-up with Y's tip not held; held until the line; no token");
    }
}

// gatebad (E-194 (vi)): catchtok's setup (J not caught up on A's chain; B's lighter branch, its tip not held at J),
// with three copies of A's carriers parked at J's relay (run again 20 s later) before J meets B. J's catch-up toward B
// ends by its reply's own decision:
//   strike       B's reply reaches J with a link broken inside it (STRIKE);
//   undecodable  B's reply reaches J truncated (STRIKE);
//   ban          B's tip fails its PoW at d at J (BAN; B's link dropped): with no peer left J's reads are NoPathbPeer;
//   ban, C       the ban with a third peer C (its own carrier on position 1, never answering J's FC_GETHEADERS)
//                connected first: J's catch-up toward C stays open, so after B's link drops a HELLO tip is still not
//                held; held while frames are in hand, then the claim (C) opens the gate with K_NCU set.
// Read after every tick of J for 30 s, until the caught-up line: the gate held until it.
struct GateBad {
    bool setup = false, line = false, caught_up = false, kept = false;
    GateReads r;
    std::uint64_t strikes = 0, bans = 0;
};
GateBad gate_bad(int mode) {  // 0 strike, 1 undecodable, 2 ban, 3 ban with a silent C
    const KatNet net;
    Harness h(net);
    FakeWire w;
    GateBad o;
    Branches br = mode >= 2 ? branches(h, w, net, 4, 1, 2, 3560) : branches(h, w, net, 4, 2, 3, 3570);
    const std::size_t a = br.a.node, b = br.b.node;
    const pb::Hash32 tip_a = h[a].tree().best().id;
    const std::uint64_t top = h[a].tree().best().pos;
    const std::size_t jw = h.add(table0(net), false, 1152, true);  // started empty, not launched: K_NCU
    MemoryKv& kvw = *h.kvs.back();
    std::vector<std::vector<std::uint8_t>> copies;
    for (std::uint64_t x = 1; x <= top; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x)) {
            copies.push_back(*pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
            (void)h[jw].on_carrier(77, copies.back());
        }
    h.q.clear();
    const bool walked = h[jw].tree().best().id == tip_a && !h[jw].caught_up() && copies.size() >= 3;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
    pb::PathbRelayNode& rj = *j.relay;
    std::optional<KatRelay> c;
    bool c_held = false;
    if (mode == 3) {  // C (wire 3): its own carrier on position 1; it and J never answer each other's FC_GETHEADERS
        c.emplace(kat_relay(h, w, table0(net), true));
        h.tick_monero();
        (void)mine_only(h, c->node, 4, 3590);
        c_held = h[j.node].holds_tip(h[c->node].tree().best().id);
    }
    // the frames in hand from a source of their own (B's token budget, spent by its STRIKE, does not pace them)
    for (std::size_t k = 0; k < 3; ++k) rj.test_park(77, copies[k], (h.now + 20) * 1000);
    if (mode >= 2) h.bad_pow.insert(h[b].tree().best().id);
    std::uint64_t edited = 0;
    w.edit = [mode, &edited](FakeWire::Msg& m) {
        if (m.f.empty() || m.f[0] != pb::kOpFcHeaders) return;
        if (m.from == 2 && m.to == 1) m.f.clear();  // B's own catch-up toward J gets no reply
        if ((m.from == 2 && m.to == 3) || (m.from == 3 && m.to == 2)) m.f.clear();  // J and C: no reply
        if (mode >= 2 || m.from != 1 || m.to != 2) return;
        if (mode == 1) {
            if (m.f.size() > 8) {
                m.f.resize(m.f.size() - 3);
                ++edited;
            }
            return;
        }
        pb::HeadersReply rep;
        if (!pb::decode_fc_headers(m.f, 0, 1u << 22, pb::kRuledLaneParams, rep).ok() || rep.headers.size() < 3) return;
        rep.headers.erase(rep.headers.begin() + 1);
        m.f = *pb::encode_fc_headers(rep, 1u << 22);
        ++edited;
    };
    if (mode == 3) {
        w.connect(3, 2);
        w.run();
    }
    w.connect(1, 2);
    w.run();
    for (int k = 0; k < 30; ++k) {
        h.now += 1;
        rj.tick();
        if (caught_of(lines, j.node).empty() && !h[j.node].caught_up()) o.r.read(h, j.node);
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    o.setup = br.ok && walked && (mode >= 2 || edited >= 1) && !c_held;
    o.line = caught_of(lines, j.node).size() == 1;
    o.caught_up = h[j.node].caught_up();
    o.kept = h[j.node].tree().best().id == tip_a && !h[j.node].holds_tip(h[b].tree().best().id);
    o.strikes = rj.stats().strikes.load();
    o.bans = rj.stats().bans.load();
    return o;
}
void gatebad() {
    const char* names[] = {"gatebad strike", "gatebad undecodable", "gatebad ban", "gatebad ban, C"};
    for (int mode = 0; mode < 4; ++mode) {
        const GateBad o = gate_bad(mode);
        const std::string name = names[mode];
        std::printf("  %s: setup %d; reads before the line: %s; line %d caught up %d, chain kept %d; strikes %llu bans "
                    "%llu\n",
                    name.c_str(), o.setup ? 1 : 0, o.r.str().c_str(), o.line ? 1 : 0, o.caught_up ? 1 : 0,
                    o.kept ? 1 : 0, (unsigned long long)o.strikes, (unsigned long long)o.bans);
        check(o.setup, name + ": setup (J not caught up at A's tip, frames in hand, B's tip lighter and not held)");
        if (mode == 3) {
            check(o.r.open_in_hand == 0 && o.r.held_in_hand >= 10 && o.r.open_after >= 5 && !o.line && !o.caught_up
                          && o.bans >= 1,
                  name + ": B banned, C's catch-up open: held while frames are in hand, then the claim opens the gate "
                         "with K_NCU set (" + o.r.str() + ")");
            continue;
        }
        check(o.r.open_in_hand == 0 && o.r.held_in_hand >= 10 && o.r.open_after == 0,
              name + ": the catch-up ended by its reply, B's tip not held: held until the line (" + o.r.str() + ")");
        check(o.line && o.caught_up && o.kept && (mode == 2 ? o.bans >= 1 : o.strikes >= 1 && o.bans == 0),
              name + ": the frames judged, the line; J's chain kept; the reply's token");
    }
}

// gatehand (E-166 (v), E-194 (vi)): a hand-over to the joiner is no end. J not caught up on A's chain (Branches: B's
// lighter branch, its tip not held at J), three copies of A's carriers parked at J's relay (run again 20 s later). B
// answers J's catch-up requests with no header (a server that holds none of J's chain): the locator reaches position 0
// and B's tip is handed to the joiner (one pair, not attempted: one HELLO tail, P-40). Then A connects (its tip held at
// J: that catch-up ends at once). Read after every tick of J for 30 s: held while frames are in hand; after the drain,
// with no join attempt open (the limbo), the claim (B's handed-over tip, unheld) opens the gate; K_NCU stays set and no
// caught-up line is printed.
void gatehand() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    Branches br = branches(h, w, net, 4, 1, 2, 3580);
    const std::size_t a = br.a.node, b = br.b.node;
    const pb::Hash32 tip_a = h[a].tree().best().id;
    const std::uint64_t top = h[a].tree().best().pos;
    const std::size_t jw = h.add(table0(net), false, 1152, true);
    MemoryKv& kvw = *h.kvs.back();
    std::vector<std::vector<std::uint8_t>> copies;
    for (std::uint64_t x = 1; x <= top; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x)) {
            copies.push_back(*pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
            (void)h[jw].on_carrier(77, copies.back());
        }
    h.q.clear();
    const bool walked = h[jw].tree().best().id == tip_a && !h[jw].caught_up() && copies.size() >= 3;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
    pb::PathbRelayNode& rj = *j.relay;
    for (std::size_t k = 0; k < 3; ++k) rj.test_park(w.id(2, 1), copies[k], (h.now + 20) * 1000);
    w.edit = [](FakeWire::Msg& m) {
        if (m.f.empty() || m.f[0] != pb::kOpFcHeaders) return;
        if (m.from == 2 && m.to == 1) m.f.clear();                                                       // B gets none
        if (m.from == 1 && m.to == 2) m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);  // empty
    };
    w.connect(1, 2);
    w.run();
    const std::uint64_t offers = rj.stats().empty_store_offers.load();
    const std::size_t pairs = h[j.node].joiner().queue().size();
    w.connect(0, 2);  // A: its tip held at J
    w.run();
    GateReads r;
    for (int k = 0; k < 30; ++k) {
        h.now += 1;
        rj.tick();
        if (caught_of(lines, j.node).empty() && !h[j.node].caught_up()) r.read(h, j.node);
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    const bool b_held = h[j.node].holds_tip(h[b].tree().best().id);
    std::printf("  gatehand: empty-store offers %llu, pairs %zu; reads: %s; lines %zu; caught up %d; B's tip held %d\n",
                (unsigned long long)offers, pairs, r.str().c_str(), caught_of(lines, j.node).size(),
                h[j.node].caught_up() ? 1 : 0, b_held ? 1 : 0);
    check(br.ok && walked && offers == 1 && pairs == 1 && !b_held,
          "gatehand: setup (B's tip handed to the joiner from an empty reply at position 0; one pair)");
    check(r.open_in_hand == 0 && r.held_in_hand >= 10 && r.open_after >= 5 && r.held_after == 0,
          "gatehand: held while frames are in hand; after the drain the handed-over claim opens the gate (" + r.str() +
                  ")");
    check(caught_of(lines, j.node).empty() && !h[j.node].caught_up(),
          "gatehand: the hand-over is no end: no caught-up line and K_NCU set, A's catch-up ended or not");
    check(!h[j.node].attempting() && h[j.node].drain_done() && !h[j.node].caught_up() && gate_open(h, j.node),
          "gatehand: the end state (a hand-over, no attempt open, nothing in hand): the gate open with K_NCU set");
}

// gatejp (E-166 (v), E-194 (vi)): a hand-over by JoinerPath is no end. J, a store not caught up, walked D's chain
// 1..10 (C's 1, 2 and D's own 3..10), its journal base at 6 (above tip - J); C holds C's 1, 2 and its own 3..14
// (heavier). Three copies of D's carriers are parked at J's relay (run again 20 s later). J meets C: its catch-up steps
// down to position 2, C's headers win and fork below J's journal base, so C's tip is handed to the joiner (no attempt:
// one HELLO tail, P-40). Then D connects (its tip held at J). Read after every tick of J for 30 s: held while frames
// are in hand; after the drain the handed-over claim opens the gate; no caught-up line, K_NCU set.
void gatejp() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay c = kat_relay(h, w, table0(net), true);
    KatRelay d = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, c.node, static_cast<std::size_t>(i), 5100 + static_cast<std::uint32_t>(i));
    }
    ok = ok && h[d.node].tree().best().id == h[c.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (int i = 0; i < 8; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, d.node, static_cast<std::size_t>(i % 5), 5200 + static_cast<std::uint32_t>(i));
    }
    for (int i = 0; i < 12; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), 5300 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip_c = h[c.node].tree().best().id;
    const std::size_t jw = h.add(table0(net), false, 1152, true);
    MemoryKv& kvw = *h.kvs.back();
    std::vector<std::vector<std::uint8_t>> copies;
    for (std::uint64_t x = 1; x <= 10; ++x)
        if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x)) {
            copies.push_back(*pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
            (void)h[jw].on_carrier(77, copies.back());
        }
    h.q.clear();
    ok = ok && h[jw].tree().best().pos == 10 && !h[jw].caught_up() && h[c.node].tree().best().pos == 14 &&
         copies.size() == 10;
    {  // the journal base at 6: above tip - J
        pb::StoreHead hd = *pb::decode_phead(kvw.data[pb::store_keys::phead(0)]);
        hd.base_pos = 6;
        kvw.data[pb::store_keys::phead(0)] = pb::encode_phead(hd);
    }
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t base = h[j.node].store().base_pos(), tip = h[j.node].tree().best().pos;
    const std::size_t jwire = 2;
    for (std::size_t k = 0; k < 3; ++k) rj.test_park(77, copies[k], (h.now + 20) * 1000);
    w.edit = [jwire](FakeWire::Msg& m) {  // C's and D's own catch-ups toward J get no reply
        if (!m.f.empty() && m.f[0] == pb::kOpFcHeaders && m.from == jwire) m.f.clear();
    };
    w.connect(0, jwire);
    w.run();
    const std::size_t pairs = h[j.node].joiner().queue().size();
    const bool c_held = h[j.node].holds_tip(tip_c);
    const std::uint64_t offers = rj.stats().empty_store_offers.load(), steps = rj.stats().catchup_steps.load();
    // JoinerPath: no empty reply from position 0, no deferred catch-up's offer
    const bool jp = offers == 0 && rj.stats().catchup_join_offers.load() == 0 && steps >= 1 && pairs == 1;
    w.connect(1, jwire);  // D: its tip held at J
    w.run();
    GateReads r;
    for (int k = 0; k < 30; ++k) {
        h.now += 1;
        rj.tick();
        if (caught_of(lines, j.node).empty() && !h[j.node].caught_up()) r.read(h, j.node);
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    std::printf("  gatejp: base %llu, tip %llu; locator steps %llu, empty-store offers %llu, pairs %zu, C's tip held %d; "
                "reads: %s; lines %zu; caught up %d; attempt open %d\n",
                (unsigned long long)base, (unsigned long long)tip, (unsigned long long)steps, (unsigned long long)offers,
                pairs, c_held ? 1 : 0, r.str().c_str(), caught_of(lines, j.node).size(), h[j.node].caught_up() ? 1 : 0,
                h[j.node].attempting() ? 1 : 0);
    check(ok && base == 6 && tip == 10 && jp && !c_held,
          "gatejp: setup (journal base 6 at tip 10; C's heavier tip handed to the joiner by JoinerPath; one pair)");
    check(r.open_in_hand == 0 && r.held_in_hand >= 10 && r.open_after >= 5 && r.held_after == 0,
          "gatejp: held while frames are in hand; after the drain the handed-over claim opens the gate (" + r.str() + ")");
    check(caught_of(lines, j.node).empty() && !h[j.node].caught_up() && !h[j.node].attempting(),
          "gatejp: the JoinerPath hand-over is no end: no caught-up line and K_NCU set, D's catch-up ended or not");
}

// gatejpnp (E-166 (v), P-52): gatejp's shape (J at 10, its journal base at 6; C at 14, heavier, forking at 2; D's tip
// held at J; three copies of D's carriers parked at J's relay, run again 5 s later) with no live (tip, C) pair at C's
// JoinerPath reply. Once J handles C's HELLO, C's tip is offered to the joiner and attempted; C answers the attempt's
// top page with
//   excluded  its headers 1 and 2 and E's own 3 (E cut from C at 2), whose PoW fails at J: Header, C excluded;
//   decided   its headers 1 and 2 (L held by J's chain): OutOfScope, the pair dropped.
// C's catch-up reply that decides JoinerPath is held back until the frames are judged, then given to J. Read after
// every tick of J until then.
struct JpnpOut {
    bool setup = false, line_before = false, line_at_reply = false, caught = false, open_after = false;
    std::string end;
    bool excluded = false;
    std::size_t pairs_after = 0, pairs_end = 0, lines = 0, jp_lines = 0;
    std::uint64_t strikes = 0, bans = 0;
    GateReads r;
};
JpnpOut gate_jp_np(int mode) {
    JpnpOut o;
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay c = kat_relay(h, w, table0(net), true);  // wire 0
    KatRelay d = kat_relay(h, w, table0(net), true);  // wire 1
    KatRelay e = kat_relay(h, w, table0(net), true);  // wire 2
    w.connect(0, 1);
    w.connect(0, 2);
    w.run();
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, c.node, static_cast<std::size_t>(i), 6500 + static_cast<std::uint32_t>(i));
    }
    ok = ok && h[d.node].tree().best().id == h[c.node].tree().best().id
         && h[e.node].tree().best().id == h[c.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.links[2]->disconnect(w.id(2, 0));
    w.run();
    for (int i = 0; i < 8; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, d.node, static_cast<std::size_t>(i % 5), 6600 + static_cast<std::uint32_t>(i));
    }
    h.tick_monero();
    ok = ok && mine_on(h, w, e.node, 3, 6650);  // E's own 3
    for (int i = 0; i < 12; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), 6700 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip_c = h[c.node].tree().best().id, tip_e = h[e.node].tree().best().id;
    std::vector<pb::CarrierHeader> top;
    for (std::uint64_t x = 1; x <= 2; ++x)
        if (const std::optional<pb::Hash32> id = h[c.node].store().best_at(x))
            top.push_back(pb::header_of(*h[c.node].bodies().get(*id)));
    if (mode == 0) {
        top.push_back(pb::header_of(*h[e.node].bodies().get(tip_e)));
        h.bad_pow.insert(tip_e);
    }
    const std::size_t jw = h.add(table0(net), false, 1152, true);
    MemoryKv& kvw = *h.kvs.back();
    std::vector<std::vector<std::uint8_t>> copies;
    for (std::uint64_t x = 1; x <= 10; ++x)
        if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x)) {
            copies.push_back(*pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
            (void)h[jw].on_carrier(77, copies.back());
        }
    h.q.clear();
    ok = ok && h[jw].tree().best().pos == 10 && !h[jw].caught_up() && h[c.node].tree().best().pos == 14
         && h[e.node].tree().best().pos == 3 && copies.size() == 10 && top.size() == (mode == 0 ? 3u : 2u);
    {  // the journal base at 6: above tip - J
        pb::StoreHead hd = *pb::decode_phead(kvw.data[pb::store_keys::phead(0)]);
        hd.base_pos = 6;
        kvw.data[pb::store_keys::phead(0)] = pb::encode_phead(hd);
    }
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)),
                                  [](pb::PathbRelayOptions& op) { op.join_min_peers = 1; });
    pb::PathbRelayNode& rj = *j.relay;
    const std::size_t jwire = 3;
    const std::uint64_t pc = w.id(jwire, 0);
    ok = ok && h[j.node].store().base_pos() == 6 && h[j.node].tree().best().pos == 10;
    for (std::size_t k = 0; k < 3; ++k) rj.test_park(77, copies[k], (h.now + 5) * 1000);
    std::deque<bool> asked;  // J's FC_GETHEADERS to C, in order: true = a joiner page (from the zero id)
    std::vector<std::uint8_t> held;
    bool hold = true;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.from == jwire && m.to == 0 && m.f[0] == pb::kOpFcGetHeaders) {
            pb::GetHeaders q;
            if (pb::decode_fc_getheaders(m.f, 0, q).ok()) asked.push_back(q.from == pb::Hash32{});
            return;
        }
        if (m.f[0] != pb::kOpFcHeaders) return;
        if (m.from == jwire) {  // C's and D's own catch-ups toward J: no reply
            m.f.clear();
            return;
        }
        if (m.from != 0 || m.to != jwire || asked.empty()) return;
        const bool page = asked.front();
        asked.pop_front();
        if (page) {
            m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 1, top}, 1u << 22);
            return;
        }
        if (hold && m.f.size() > 100) {  // a reply carrying C's headers: held back
            if (held.empty()) held = m.f;
            m.f.clear();
        }
    };
    w.connect(0, jwire);
    for (pb::PathbRelayNode* x : w.relays) x->pump();
    while (!(rj.hello_ok(pc) && h[j.node].has_pathb_peer()) && w.step()) {
    }
    const bool offered = h[j.node].offer_empty_store_tip(pc);
    const std::optional<pb::JoinStep> st = rj.join_step();
    o.end = st && st->report ? pb::attempt_end_name(st->report->end) : "none";
    o.excluded = h[j.node].joiner().queue().excluded(pc);
    o.pairs_after = h[j.node].joiner().queue().size();
    w.run();
    w.connect(1, jwire);  // D: its tip held at J
    w.run();
    for (int k = 0; k < 7; ++k) {
        h.now += 1;
        rj.tick();
        if (caught_of(lines, j.node).empty() && !h[j.node].caught_up()) o.r.read(h, j.node);
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    o.line_before = !caught_of(lines, j.node).empty();
    const bool drained = h[j.node].drain_done(), got = !held.empty();
    hold = false;
    w.links[jwire]->frame(pc, held);  // C's reply: JoinerPath, no live pair
    rj.pump();
    o.line_at_reply = caught_of(lines, j.node).size() == 1;
    o.open_after = gate_open(h, j.node);
    o.pairs_end = h[j.node].joiner().queue().size();
    for (int k = 0; k < 5; ++k) {
        h.now += 1;
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    o.lines = caught_of(lines, j.node).size();
    for (const std::string& l : lines[j.node])
        if (l.find("win; fork at") != std::string::npos) ++o.jp_lines;
    o.caught = h[j.node].caught_up();
    o.strikes = rj.strikes_of(pc);
    o.bans = rj.stats().bans.load();
    const bool want_end = mode == 0 ? o.end == std::string("Header") : o.end == std::string("OutOfScope");
    o.setup = ok && offered && want_end && o.excluded == (mode == 0) && o.pairs_after == 0 && got && drained
              && !h[j.node].holds_tip(tip_c);
    return o;
}
void gatejpnp() {
    const char* names[] = {"excluded", "decided"};
    for (int mode = 0; mode < 2; ++mode) {
        const JpnpOut o = gate_jp_np(mode);
        const std::string name = std::string("gatejpnp ") + names[mode];
        std::printf("  %s: setup %d; the attempt's end %s, C excluded %d, pairs %zu; reads: %s; line before %d; at C's "
                    "reply: line %d, gate open %d, pairs %zu; lines %zu; caught up %d; strikes %llu, bans %llu\n",
                    name.c_str(), o.setup ? 1 : 0, o.end.c_str(), o.excluded ? 1 : 0, o.pairs_after, o.r.str().c_str(),
                    o.line_before ? 1 : 0, o.line_at_reply ? 1 : 0, o.open_after ? 1 : 0, o.pairs_end, o.lines,
                    o.caught ? 1 : 0, (unsigned long long)o.strikes, (unsigned long long)o.bans);
        check(o.setup && !o.line_before, name + ": setup (C's pair attempted and dead before its JoinerPath reply)");
        check(o.r.open_in_hand == 0 && o.r.held_in_hand >= 4,
              name + ": held while frames are in hand (" + o.r.str() + ")");
        check(o.line_at_reply && o.open_after && o.pairs_end == 0 && o.lines == 1 && o.caught,
              name + ": no hand-over recorded: the catch-up ended by its reply, the line and K_NCU's end at the reply, "
                     "the gate open");
        check(o.strikes == 0 && o.bans == 0, name + ": 0 tokens");
    }
}

// jpdeclined (the O-17 line where the offer leaves a live pair): gatejpnp's shapes; C's JoinerPath reply arrives with
// its (tip, C) pair dead (excluded: C excluded; decided: the attempt ended OutOfScope): no JoinerPath line; the
// catch-up ends by its reply (the caught-up line at the reply).
void jpdeclined() {
    const char* names[] = {"excluded", "decided"};
    for (int mode = 0; mode < 2; ++mode) {
        const JpnpOut o = gate_jp_np(mode);
        const std::string name = std::string("jpdeclined ") + names[mode];
        std::printf("  %s: setup %d; the attempt's end %s; JoinerPath lines %zu; at C's reply: the caught-up line %d; "
                    "caught up %d\n",
                    name.c_str(), o.setup ? 1 : 0, o.end.c_str(), o.jp_lines, o.line_at_reply ? 1 : 0, o.caught ? 1 : 0);
        check(o.setup, name + ": setup (C's pair dead before its JoinerPath reply)");
        check(o.jp_lines == 0 && o.line_at_reply && o.caught,
              name + ": no JoinerPath line (no live pair); the catch-up ended by its reply");
    }
}

// drainevict (E-193): frames evicted from the deferred store (P-47) leave the drain. J's deferred store holds at most 4
// frames. A and B share 4 positions; A holds 10 more (14), B 8 of its own. J, an empty store not caught up, catches up
// from A; three copies of A's carriers are parked at J's relay (run again 20 s later) with J at 4 or more. After J
// places the HELLO tip, B's own carriers 6..12 reach J over A's link (their parents unknown at J): parked, and the
// oldest three (6..8) evicted; then B's 5..8 over the same link: placed, the four kept frames released and placed. The
// caught-up line comes once the three copies are judged.
void drainevict() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    Branches br = branches(h, w, net, 4, 8, 10, 5400);
    const std::size_t a = br.a.node, b = br.b.node;
    const pb::Hash32 tip = h[a].tree().best().id;
    const pb::Hash32 tip_b = h[b].tree().best().id;
    std::vector<std::vector<std::uint8_t>> copies, foreign, again;
    for (const std::uint64_t x : {1, 2, 3})
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
            copies.push_back(*pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
    for (std::uint64_t x = 5; x <= 12; ++x)
        if (const std::optional<pb::Hash32> id = h[b].store().best_at(x))
            (x >= 6 ? foreign : again).push_back(*pb::encode_fc_carrier(0, *h[b].bodies().get(*id), 16));
    for (std::size_t k = 0; k < 3 && k < foreign.size(); ++k) again.push_back(foreign[k]);
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    const auto cap4 = [](pb::PathbNodeConfig& cfg) { cfg.waiting_cap = 4; };
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, cap4, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t pa = w.id(2, 0);  // A at J
    w.connect(0, 2);
    bool parked = false, reached = false;
    for (int secs = 0; secs < 120 && !reached; ++secs) {
        h.now += 1;
        br.a.relay->tick();
        br.a.relay->pump();
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && !reached; ++m) {
            if (!parked && h[j.node].tree().best().pos >= 4 && copies.size() == 3) {
                for (const auto& f : copies) rj.test_park(77, f, (h.now + 20) * 1000);
                parked = true;
            }
            reached = h[j.node].holds_tip(tip);
            if (reached || !w.step()) break;
        }
        reached = reached || h[j.node].holds_tip(tip);
    }
    for (const auto& f : foreign) {  // B's carriers over A's link: their parents unknown at J
        rj.receive(pa, f);
        rj.pump();
    }
    const std::size_t deferred = h[j.node].deferred().size();
    for (const auto& f : again) {  // B's 5, then the evicted 6..8
        rj.receive(pa, f);
        rj.pump();
    }
    const bool line_before = !caught_of(lines, j.node).empty();
    for (int k = 0; k < 30 && caught_of(lines, j.node).empty(); ++k) {
        h.now += 1;
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    const std::vector<std::string> cl = caught_of(lines, j.node);
    g_relay_lines = nullptr;
    const pb::CarrierNode* nb = h[j.node].tree().find(tip_b);
    const bool b_placed = nb != nullptr && nb->verified;
    std::printf("  drainevict: parked %d, J at the HELLO tip %d; B's carriers sent %zu, the deferred store %zu "
                "(cap 4); B's 5..8 sent %zu: B's tip placed %d, the deferred store %zu; line before %d; lines %zu; "
                "caught up %d; parked %zu\n",
                parked ? 1 : 0, reached ? 1 : 0, foreign.size(), deferred, again.size(), b_placed ? 1 : 0,
                h[j.node].deferred().size(), line_before ? 1 : 0, cl.size(), h[j.node].caught_up() ? 1 : 0,
                rj.parked_size());
    check(br.ok && parked && reached && foreign.size() == 7 && deferred == 4 && again.size() == 4 && b_placed &&
                  h[j.node].deferred().size() == 0 && !line_before,
          "drainevict: setup (frames in hand at the HELLO tip; 7 frames of B parked in a store of 4: 3 evicted; "
          "B's 5..8 again: B's tip placed, the store empty)");
    check(cl.size() == 1 && h[j.node].caught_up() && rj.parked_size() == 0,
          "drainevict: the evicted frames leave the drain: the caught-up line comes once the parked frames are judged");
}

// drainleft (E-193): the jobs of a peer gone while they are in hand leave the drain. A holds 40 positions; G, a full
// node at A's tip, is connected to J too. J, an empty store not caught up, catches up from A; three copies of A's
// carriers are parked at J's relay as G's, run again 10 s later; after J places the HELLO tip G's link drops. The
// jobs run at their time and the caught-up line comes.
void drainleft() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay g = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool mined = true;
    for (std::uint64_t i = 0; i < 40 && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 5500 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    const bool g_synced = h[g.node].tree().best().id == tip;
    std::vector<std::vector<std::uint8_t>> copies;
    for (const std::uint64_t x : {10, 20, 30})
        if (const std::optional<pb::Hash32> id = h[a.node].store().best_at(x))
            copies.push_back(*pb::encode_fc_carrier(0, *h[a.node].bodies().get(*id), 16));
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(2, 0);
    w.connect(2, 1);
    const std::uint64_t pg = w.id(2, 1);  // G at J
    for (const auto& f : copies) rj.test_park(pg, f, (h.now + 10) * 1000);
    bool reached = false;
    for (int secs = 0; secs < 60 && !reached; ++secs) {
        h.now += 1;
        for (pb::PathbRelayNode* r : {a.relay.get(), g.relay.get(), j.relay.get()}) {
            r->tick();
            r->pump();
        }
        for (int m = 0; m < 100 && !reached && w.step(); ++m) reached = h[j.node].holds_tip(tip);
        reached = reached || h[j.node].holds_tip(tip);
    }
    const bool in_hand = !h[j.node].drain_done();
    const bool line_before = !caught_of(lines, j.node).empty();
    w.links[2]->disconnect(pg);  // G gone with its jobs in hand
    w.run();
    const bool g_gone = !rj.hello_ok(pg);
    for (int k = 0; k < 30 && caught_of(lines, j.node).empty(); ++k) {
        h.now += 1;
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    const std::vector<std::string> cl = caught_of(lines, j.node);
    g_relay_lines = nullptr;
    std::printf("  drainleft: J at the HELLO tip %d with G's jobs in hand %d; line before %d; G gone %d; lines %zu; "
                "caught up %d; parked %zu\n",
                reached ? 1 : 0, in_hand ? 1 : 0, line_before ? 1 : 0, g_gone ? 1 : 0, cl.size(),
                h[j.node].caught_up() ? 1 : 0, rj.parked_size());
    check(mined && g_synced && copies.size() == 3 && reached && in_hand && !line_before && g_gone,
          "drainleft: setup (J at the HELLO tip, G's jobs in hand, G's link dropped)");
    check(cl.size() == 1 && h[j.node].caught_up() && rj.parked_size() == 0,
          "drainleft: the gone peer's jobs leave the drain: the caught-up line comes");
}

// The departure rig (E-193): A and B share 4 positions, A holds 2 more (6), B 1 of its own (5, lighter). J, a store
// not caught up, walked A's chain (placed with no HELLO). Three copies of A's carriers are parked at J's relay, run
// again `park_s` after the start (none when 0). J's FC_GETHEADERS to B are recorded in order; B's reply to a catch-up
// request (from a held id): none when `silent` (a claim alone), an empty FC_HEADERS frame when `hand` (down to position
// 0: B's tip handed to the joiner), else B's own; to a joiner page (from the zero id): B's own, none when
// `pages_silent`. J's FC_HEADERS go nowhere (A's and B's catch-ups toward J get no reply).
struct DepRig {
    KatNet net;
    Harness h;
    FakeWire w;
    Branches br;
    KatRelay j;
    std::map<std::size_t, std::vector<std::string>> lines;
    std::vector<std::vector<std::uint8_t>> copies;
    std::deque<bool> asked;
    bool silent = true, hand = false, pages_silent = false, joiner_asked = false;
    pb::Hash32 tip_a{}, tip_b{};
    bool walked = false;
    std::uint64_t pa = 0, pb_ = 0;
    MemoryKv* kvj = nullptr;  // J's store
    static constexpr std::size_t jwire = 2;
    DepRig(std::uint32_t nonce, bool join, std::uint64_t park_s) : h(net) {
        br = branches(h, w, net, 4, 1, 2, nonce);
        tip_a = h[br.a.node].tree().best().id;
        tip_b = h[br.b.node].tree().best().id;
        const std::size_t jw = h.add(table0(net), false, 1152, true);
        MemoryKv& kvw = *h.kvs.back();
        for (std::uint64_t x = 1; x <= 6; ++x)
            if (const std::optional<pb::Hash32> id = h[br.a.node].store().best_at(x)) {
                copies.push_back(*pb::encode_fc_carrier(0, *h[br.a.node].bodies().get(*id), 16));
                (void)h[jw].on_carrier(77, copies.back());
            }
        h.q.clear();
        walked = br.ok && copies.size() == 6 && h[jw].tree().best().id == tip_a && !h[jw].caught_up();
        g_relay_lines = &lines;
        j = kat_relay_loaded(h, w, kvw, h.config(table0(net)), [join](pb::PathbRelayOptions& o) {
            if (join) o.join_min_peers = 1;
        });
        kvj = h.kvs.back().get();
        pa = w.id(jwire, 0);
        pb_ = w.id(jwire, 1);
        if (park_s > 0)
            for (std::size_t k = 0; k < 3; ++k) j.relay->test_park(77, copies[k], (h.now + park_s) * 1000);
        w.edit = [this](FakeWire::Msg& m) {
            if (m.f.empty()) return;
            if (m.from == jwire && m.to == 1 && m.f[0] == pb::kOpFcGetHeaders) {
                pb::GetHeaders q;
                if (pb::decode_fc_getheaders(m.f, 0, q).ok()) {
                    asked.push_back(q.from != pb::Hash32{});
                    if (q.from == pb::Hash32{}) joiner_asked = true;
                }
                return;
            }
            if (m.f[0] != pb::kOpFcHeaders) return;
            if (m.from == jwire) {
                m.f.clear();
                return;
            }
            if (m.from != 1 || m.to != jwire || asked.empty()) return;
            const bool catchup = asked.front();
            asked.pop_front();
            if (catchup && silent)
                m.f.clear();
            else if (catchup && hand)
                m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);
            else if (!catchup && pages_silent)
                m.f.clear();
        };
    }
    ~DepRig() {
        w.edit = nullptr;
        g_relay_lines = nullptr;
    }
    DepRig(const DepRig&) = delete;
    DepRig& operator=(const DepRig&) = delete;
    pb::PathbRelayNode& rj() { return *j.relay; }
    pb::PathbNode& nj() { return h[j.node]; }
    std::size_t n_lines() const { return caught_of(lines, j.node).size(); }
    // B, then A (its tip held: its catch-up ends by its done test at the start).
    void connect_b_a() {
        w.connect(1, jwire);
        w.run();
        w.connect(0, jwire);
        w.run();
    }
    // One second of J: the tick, a read before the line (`r`, when given), the pump and the wire.
    void second(GateReads* r = nullptr) {
        h.now += 1;
        rj().tick();
        if (r != nullptr && n_lines() == 0 && !nj().caught_up()) r->read(h, j.node);
        rj().pump();
        for (int m = 0; m < 100 && w.step(); ++m) {
        }
    }
    // B leaves: its link dropped, the wire run (J's departure task runs at its pump); no tick.
    void b_leaves() {
        w.links[jwire]->disconnect(pb_);
        w.run();
    }
};

// gatedepart (E-193, E-196): the departure rig.
//   drained  B a claim alone; J read 14 s (the frames judged at 5 s, the first round past P-53), then B leaves;
//   in hand  B a claim alone; B leaves with the frames in hand (run again 20 s later);
//   handed   B's catch-up handed to the joiner (its pair queued, no attempt); J read 14 s, then B leaves;
//   redial   as in hand, and B redials at once and answers: its catch-up ends by its reply (Keep).
// After the departure J is read for 30 s.
struct DepartOut {
    bool setup = false, line_before = false, open_before = false, line_at_dep = false, caught = false, gone = false;
    std::size_t pairs_before = 0, pairs_after = 0, lines = 0;
    GateReads before, after;
};
DepartOut gate_depart(int mode) {
    DepartOut o;
    const bool hand = mode == 2;
    DepRig r(5600 + static_cast<std::uint32_t>(mode) * 10, false, mode == 1 || mode == 3 ? 20 : 5);
    r.silent = !hand;
    r.hand = hand;
    r.connect_b_a();
    o.pairs_before = r.nj().joiner().queue().size();
    if (mode == 0 || mode == 2)
        for (int k = 0; k < 14; ++k) r.second(&o.before);
    o.line_before = r.n_lines() > 0;
    o.open_before = gate_open(r.h, r.j.node);
    r.b_leaves();
    o.gone = !r.rj().hello_ok(r.pb_) && r.rj().hello_ok(r.pa);
    o.line_at_dep = r.n_lines() > 0;  // before J's next tick
    o.pairs_after = r.nj().joiner().queue().size();
    if (mode == 3) {
        r.asked.clear();
        r.silent = false;
        r.w.reconnect(DepRig::jwire, 1);
        r.w.run();
    }
    for (int k = 0; k < 30; ++k) r.second(&o.after);
    o.lines = r.n_lines();
    o.caught = r.nj().caught_up();
    o.setup = r.walked && !r.nj().holds_tip(r.tip_b) && (hand ? o.pairs_before == 1 : o.pairs_before == 0);
    return o;
}
void gatedepart() {
    const char* names[] = {"drained", "in hand", "handed", "redial"};
    for (int mode = 0; mode < 4; ++mode) {
        const DepartOut o = gate_depart(mode);
        const std::string name = std::string("gatedepart ") + names[mode];
        std::printf("  %s: setup %d; pairs %zu; reads before: %s; line before %d; open before %d; B gone %d; line at "
                    "the departure %d; pairs %zu; reads after: %s; lines %zu; caught up %d\n",
                    name.c_str(), o.setup ? 1 : 0, o.pairs_before, o.before.str().c_str(), o.line_before ? 1 : 0,
                    o.open_before ? 1 : 0, o.gone ? 1 : 0, o.line_at_dep ? 1 : 0, o.pairs_after,
                    o.after.str().c_str(), o.lines, o.caught ? 1 : 0);
        check(o.setup && !o.line_before && o.gone, name + ": setup (A's catch-up ended, B's open or handed over; B gone)");
        if (mode == 0 || mode == 2) {
            check(o.before.open_in_hand == 0 && o.open_before,
                  name + ": before the departure, the drain done: the gate open by B's claim (" + o.before.str() + ")");
            check(o.line_at_dep && o.caught && o.lines == 1,
                  name + ": K_NCU's end evaluated at the departure: the line at once, caught up");
        }
        if (mode == 2) check(o.pairs_after == 0, name + ": B's pair dropped with its link (P-52)");
        if (mode == 1)
            check(!o.line_at_dep && o.after.open_in_hand == 0 && o.after.held_in_hand >= 10 && o.lines == 1 && o.caught,
                  name + ": the gate held through the drain, then the line (" + o.after.str() + ")");
        if (mode == 3)
            check(!o.line_at_dep && o.lines == 1 && o.caught,
                  name + ": B's redial before any end: one line, K_NCU ended once (lines " + std::to_string(o.lines) + ")");
    }
}

// gatelast (E-193): the departure rig with B alone (a claim). B leaves: no peer left, NoPathbPeer, K_NCU kept, no
// line, 10 s. B's tip is then placed at J (with no peer) and B redials: the done test at the start, the line.
void gatelast() {
    DepRig r(5700, false, 0);
    r.w.connect(1, DepRig::jwire);
    r.w.run();
    for (int k = 0; k < 14; ++k) r.second();
    const bool open_claim = gate_open(r.h, r.j.node);
    r.b_leaves();
    int nopeer = 0, reads = 0;
    for (int k = 0; k < 10; ++k) {
        r.second();
        ++reads;
        if (tstatus(r.h, r.j.node) == pb::TemplateStatus::NoPathbPeer) ++nopeer;
    }
    const std::size_t lines_gone = r.n_lines();
    const bool ncu_gone = !r.nj().caught_up();
    const std::vector<std::uint8_t> fb =
            *pb::encode_fc_carrier(0, *r.h[r.br.b.node].bodies().get(r.tip_b), 16);
    (void)r.nj().on_carrier(77, fb);
    r.h.q.clear();
    const bool b_held = r.nj().holds_tip(r.tip_b);
    r.asked.clear();
    r.w.reconnect(DepRig::jwire, 1);
    r.w.run();
    const std::size_t lines_redial = r.n_lines();
    std::printf("  gatelast: the gate open by B's claim %d; B gone: NoPathbPeer %d of %d reads, lines %zu, K_NCU set %d; "
                "B's tip placed %d; after B's redial lines %zu, caught up %d\n",
                open_claim ? 1 : 0, nopeer, reads, lines_gone, ncu_gone ? 1 : 0, b_held ? 1 : 0, lines_redial,
                r.nj().caught_up() ? 1 : 0);
    check(r.walked && open_claim && b_held, "gatelast: setup (B a claim alone; its tip placed at J before its redial)");
    check(nopeer == reads && lines_gone == 0 && ncu_gone,
          "gatelast: the last peer gone: NoPathbPeer, K_NCU kept, no line");
    check(lines_redial == 1 && r.nj().caught_up(), "gatelast: B's redial: the done test at the start, the line");
}

// gateattempt (E-193): the departure rig, B's catch-up handed to the joiner (its pair queued), one HELLO
// tail enough for an attempt. The attempt with B runs; when it has asked B for a page B leaves. Read at the departure
// (inside the attempt) and after the attempt's end.
void gateattempt() {
    DepRig r(5800, true, 0);
    r.silent = false;
    r.hand = true;
    r.connect_b_a();
    const std::size_t pairs = r.nj().joiner().queue().size();
    bool left = false, line_in = false, open_in = false;
    r.rj().set_drive([&] {
        if (!left && r.joiner_asked) {
            left = true;
            r.b_leaves();
            line_in = r.n_lines() > 0;
            open_in = r.nj().attempting();
            return true;
        }
        return r.w.step();
    });
    const std::optional<pb::JoinStep> st = r.rj().join_step();
    r.rj().set_drive([&w = r.w] { return w.step(); });
    r.w.run();
    const std::size_t lines_end = r.n_lines();
    const std::string end = st && st->report ? pb::attempt_end_name(st->report->end) : std::string("none");
    std::printf("  gateattempt: pairs %zu; B left during the attempt %d (attempt open %d), line then %d; the attempt's end "
                "%s; pairs after %zu; lines %zu; caught up %d\n",
                pairs, left ? 1 : 0, open_in ? 1 : 0, line_in ? 1 : 0, end.c_str(),
                r.nj().joiner().queue().size(), lines_end, r.nj().caught_up() ? 1 : 0);
    check(r.walked && pairs == 1 && left && open_in && st && st->report,
          "gateattempt: setup (B's pair attempted; B left while the attempt was open)");
    check(!line_in, "gateattempt: no end evaluated before the attempt's own end");
    check(r.nj().joiner().queue().size() == 0 && lines_end == 1 && r.nj().caught_up(),
          "gateattempt: the attempt ended, B's pairs gone: K_NCU's end evaluated, the line");
}

// gateexcl (E-193, P-52): the departure rig, B's catch-up handed to the joiner (its pair queued), the
// frames in hand (run again 20 s later), one HELLO tail enough for an attempt; B's tip fails its PoW at J. The attempt
// with B ends Header: B excluded with its pairs, its link kept. Read 30 s.
void gateexcl() {
    DepRig r(5900, true, 20);
    r.silent = false;
    r.hand = true;
    r.connect_b_a();
    const std::size_t pairs = r.nj().joiner().queue().size();
    r.h.bad_pow.insert(r.tip_b);
    const std::optional<pb::JoinStep> st = r.rj().join_step();
    r.w.run();
    const bool excluded = r.nj().joiner().queue().excluded(r.pb_);
    const bool b_up = r.rj().hello_ok(r.pb_);
    const bool header = st && st->report && st->report->end == pb::AttemptEnd::Header;
    const bool line_at_end = r.n_lines() > 0;
    GateReads g;
    for (int k = 0; k < 30; ++k) r.second(&g);
    std::printf("  gateexcl: pairs %zu; the attempt's end %s, B excluded %d, B's link up %d; line at the attempt's end "
                "%d; reads: %s; lines %zu; caught up %d\n",
                pairs, st && st->report ? pb::attempt_end_name(st->report->end) : "none", excluded ? 1 : 0,
                b_up ? 1 : 0, line_at_end ? 1 : 0, g.str().c_str(), r.n_lines(), r.nj().caught_up() ? 1 : 0);
    check(r.walked && pairs == 1 && header && excluded && b_up,
          "gateexcl: setup (B's pair attempted: Header, B excluded, its link kept)");
    check(!line_at_end && g.open_in_hand == 0 && g.held_in_hand >= 10 && r.n_lines() == 1 && r.nj().caught_up(),
          "gateexcl: the excluded server's hand-over holds nothing: the gate held through the drain, then the line (" +
                  g.str() + ")");
}

// gatens (E-193, P-52): the departure rig, B's catch-up handed to the joiner (its pair queued), the
// frames in hand (run again 5 s later), one HELLO tail enough for an attempt; B answers no joiner page. An attempt each
// second for 30 s: each ends NotServed, the pair queued again.
void gatens() {
    DepRig r(6000, true, 5);
    r.silent = false;
    r.hand = true;
    r.pages_silent = true;
    r.connect_b_a();
    const std::size_t pairs = r.nj().joiner().queue().size();
    GateReads g;
    int ns = 0, other = 0;
    for (int k = 0; k < 30; ++k) {
        r.second(&g);
        const std::optional<pb::JoinStep> st = r.rj().join_step();
        r.w.run();
        if (st && st->report) ++(st->report->end == pb::AttemptEnd::NotServed ? ns : other);
    }
    std::printf("  gatens: pairs %zu; attempts NotServed %d, other %d; pairs after %zu; reads: %s; lines %zu; caught "
                "up %d\n",
                pairs, ns, other, r.nj().joiner().queue().size(), g.str().c_str(), r.n_lines(),
                r.nj().caught_up() ? 1 : 0);
    check(r.walked && pairs == 1 && ns >= 1 && other == 0, "gatens: setup (B's pair attempted, NotServed each time)");
    check(r.nj().joiner().queue().size() == 1 && r.n_lines() == 0 && !r.nj().caught_up() && g.open_in_hand == 0
                  && g.open_after >= 5,
          "gatens: the pair queued again, the hand-over pending: no line, K_NCU set; after the drain the gate open by "
          "the claim (" + g.str() + ")");
}

// gatewindow (E-193): the departure rig, B's catch-up handed to the joiner (its pair queued), one HELLO tail enough for
// an attempt; a third peer C (its own carrier on position 1) whose last catch-up reply (a header: Keep) is held back.
// The attempt with B runs; when it has asked B for a page, C's held reply reaches J's queue, then B's link drops: C's
// reply is judged before B's departure task. Read at the departure task (inside the attempt) and after the attempt.
void gatewindow() {
    DepRig r(6300, true, 0);
    r.silent = false;
    r.hand = true;
    KatRelay kc = kat_relay(r.h, r.w, table0(r.net), true);  // wire 3
    (void)mine_only(r.h, kc.node, 4, 6390);
    const pb::Hash32 tip_c = r.h[kc.node].tree().best().id;
    std::vector<std::uint8_t> held;
    const std::function<void(FakeWire::Msg&)> base = r.w.edit;
    r.w.edit = [&](FakeWire::Msg& m) {
        if (m.from == 3 && m.to == DepRig::jwire && !m.f.empty() && m.f[0] == pb::kOpFcHeaders && m.f.size() > 100
            && held.empty()) {
            held.swap(m.f);  // C's reply carrying its header: held back
            return;
        }
        base(m);
    };
    r.connect_b_a();
    r.w.connect(3, DepRig::jwire);
    r.w.run();
    const std::size_t pairs = r.nj().joiner().queue().size();
    const bool c_held_back = !held.empty() && !r.nj().holds_tip(tip_c);
    bool left = false, line_in = false, attempting = false;
    r.rj().set_drive([&] {
        if (!left && r.joiner_asked) {
            left = true;
            r.w.links[DepRig::jwire]->frame(r.w.id(DepRig::jwire, 3), held);  // C's reply queued at J
            r.w.links[DepRig::jwire]->disconnect(r.pb_);                       // then B's departure task
            r.rj().pump();
            line_in = r.n_lines() > 0;
            attempting = r.nj().attempting();
            return true;
        }
        return r.w.step();
    });
    const std::optional<pb::JoinStep> st = r.rj().join_step();
    r.rj().set_drive([&w = r.w] { return w.step(); });
    r.w.run();
    std::printf("  gatewindow: pairs %zu; C's reply held back %d; B left during the attempt %d (attempting %d), C's "
                "reply judged first, line then %d; the attempt's end %s; lines %zu; caught up %d\n",
                pairs, c_held_back ? 1 : 0, left ? 1 : 0, attempting ? 1 : 0, line_in ? 1 : 0,
                st && st->report ? pb::attempt_end_name(st->report->end) : "none", r.n_lines(),
                r.nj().caught_up() ? 1 : 0);
    check(r.walked && pairs == 1 && c_held_back && left && attempting && st && st->report,
          "gatewindow: setup (B's pair attempted; C's Keep reply judged after B's link dropped, before its departure "
          "task)");
    check(!line_in, "gatewindow: an end event between B's link drop and its departure task: no end before the "
                    "attempt's own end");
    check(r.n_lines() == 1 && r.nj().caught_up(), "gatewindow: the attempt ended: the line");
}

// gatepoison (E-193): the departure rig, B's catch-up handed to the joiner (its pair queued), one HELLO tail enough for
// an attempt. While the attempt with B runs J's next store write fails (A mines one: J places it): the store is
// poisoned, and the attempt is not applied.
void gatepoison() {
    DepRig r(6400, true, 0);
    r.silent = false;
    r.hand = true;
    r.connect_b_a();
    const std::size_t pairs = r.nj().joiner().queue().size();
    bool done = false, mined = false, poisoned_in = false;
    r.rj().set_drive([&] {
        if (!done && r.joiner_asked) {
            done = true;
            r.kvj->fail_next = 1;
            mined = mine_on(r.h, r.w, r.br.a.node, 0, 6490);
            poisoned_in = r.nj().poisoned();
            return true;
        }
        return r.w.step();
    });
    const std::optional<pb::JoinStep> st = r.rj().join_step();
    r.rj().set_drive([&w = r.w] { return w.step(); });
    r.w.run();
    const bool open_after = r.nj().open_attempt().has_value();
    std::printf("  gatepoison: pairs %zu; A mined %d; J poisoned during the attempt %d; applied %d; the attempt's pair "
                "open after %d\n",
                pairs, mined ? 1 : 0, poisoned_in ? 1 : 0, st && st->report ? 1 : 0, open_after ? 1 : 0);
    check(r.walked && pairs == 1 && mined && poisoned_in && st && !st->report,
          "gatepoison: setup (J poisoned while the attempt with B ran; the attempt not applied)");
    check(!open_after, "gatepoison: the attempt not applied: its pair no longer open");
}

// gaterefused (E-166 (v), P-52): the departure rig with B alone; one HELLO tail enough for an attempt.
// Once J handles B's HELLO (its catch-up request on the wire) B's tip is offered to the joiner (as a deferred
// catch-up's offer is) and attempted: B's tip fails its PoW at J, the attempt ends Header, B excluded. B's catch-up
// then gets empty replies down to position 0: the offer leaves no pair. Then load_failed_: J a load failure, B's HELLO.
void gaterefused() {
    {
        DepRig r(6100, true, 0);
        r.silent = false;
        r.hand = true;
        r.w.connect(1, DepRig::jwire);
        for (pb::PathbRelayNode* x : r.w.relays) x->pump();  // the HELLOs sent
        while (!(r.rj().hello_ok(r.pb_) && r.nj().has_pathb_peer()) && r.w.step()) {
        }
        const bool offered = r.nj().offer_empty_store_tip(r.pb_);
        r.h.bad_pow.insert(r.tip_b);
        const std::optional<pb::JoinStep> st = r.rj().join_step();
        const bool header = st && st->report && st->report->end == pb::AttemptEnd::Header;
        const bool excluded = r.nj().joiner().queue().excluded(r.pb_);
        const std::size_t lines_attempt = r.n_lines();
        const std::uint64_t offers0 = r.rj().stats().empty_store_offers.load();
        r.w.run();  // the catch-up: empty replies down to position 0, no tick
        const std::size_t lines_reply = r.n_lines();
        std::printf("  gaterefused: offered %d; the attempt's end %s, B excluded %d; lines then %zu; after B's empty "
                    "replies: empty-store offers %llu, pairs %zu, lines %zu, caught up %d, B's link up %d\n",
                    offered ? 1 : 0, st && st->report ? pb::attempt_end_name(st->report->end) : "none",
                    excluded ? 1 : 0, lines_attempt, (unsigned long long)r.rj().stats().empty_store_offers.load(),
                    r.nj().joiner().queue().size(), lines_reply, r.nj().caught_up() ? 1 : 0,
                    r.rj().hello_ok(r.pb_) ? 1 : 0);
        check(r.walked && offered && header && excluded && lines_attempt == 0 && offers0 == 0,
              "gaterefused: setup (B's pair attempted before its catch-up's replies: Header, B excluded)");
        check(r.rj().stats().empty_store_offers.load() == 0 && r.nj().joiner().queue().size() == 0 && lines_reply == 1
                      && r.nj().caught_up(),
              "gaterefused: an empty reply from position 0 whose offer leaves no pair: no hand-over; the catch-up "
              "ended by its reply, the line at the reply");
    }
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay b = kat_relay(h, w, table0(net), true);
    bool mined = true;
    for (int i = 0; i < 3 && mined; ++i) {
        h.tick_monero();
        mined = mine_on(h, w, b.node, static_cast<std::size_t>(i), 6200 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[b.node].tree().best().id;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, true);
    w.connect(0, 1);
    w.run();
    for (int k = 0; k < 5; ++k) {
        h.now += 1;
        j.relay->tick();
        w.run();
    }
    g_relay_lines = nullptr;
    const bool lives = h[j.node].pair_lives(tip, w.id(1, 0));
    std::printf("  gaterefused load_failed_: B's pair lives %d; catch-up requests %llu\n", lives ? 1 : 0,
                (unsigned long long)j.relay->stats().catchup_requests.load());
    check(mined && lives, "gaterefused load_failed_: B's HELLO pair lives (P-52)");
}

// Two nodes for the header comparison (E-197): A asks, B serves. They share `shared` positions (the fork); then, cut
// from each other, A mines `a_own` and B `b_own` (B `per_h` carriers per Monero height: more raises d). A's journal
// depth j. Pages are served by hand: B answers A's FC_GETHEADERS at the head of the queue.
struct Pair2 {
    std::size_t a = 0, b = 0;
    pb::Hash32 fork{}, b_tip{};
    std::uint64_t fork_pos = 0;
    std::vector<pb::Hash32> a_ids, b_ids;
};
Pair2 pair2(Harness& h, int shared, int a_own, int b_own, int per_h = 1, std::uint64_t j = 1152, bool b_first = false) {
    Pair2 s;
    s.a = h.add(table0(h.net), true, j);
    s.b = h.add(table0(h.net), true);
    for (int i = 0; i < shared; ++i) {
        h.tick_monero(1);
        h.mine(s.a, static_cast<std::size_t>(i % 3), 7000 + static_cast<std::uint32_t>(i));
    }
    s.fork = h[s.a].tree().best().id;
    s.fork_pos = h[s.a].tree().best().pos;
    h.cut = {{s.a, s.b}, {s.b, s.a}};
    const auto mine_a = [&] {
        for (int i = 0; i < a_own; ++i) {
            h.tick_monero(1);
            h.mine(s.a, 0, 7100 + static_cast<std::uint32_t>(i));
            s.a_ids.push_back(h[s.a].tree().best().id);
        }
    };
    if (!b_first) mine_a();
    for (int i = 0; i < b_own; ++i) {
        if (i % per_h == 0) h.tick_monero(1);
        h.mine(s.b, 1, 7300 + static_cast<std::uint32_t>(i));
        s.b_ids.push_back(h[s.b].tree().best().id);
    }
    if (b_first) mine_a();
    s.b_tip = h[s.b].tree().best().id;
    return s;
}
// A's oldest queued FC_GETHEADERS to B (taken from the queue); nullopt: none.
std::optional<Msg> take_ask(Harness& h, const Pair2& s) {
    for (auto it = h.q.begin(); it != h.q.end(); ++it)
        if (it->from == s.a && it->to == s.b && !it->frame.empty() && it->frame[0] == pb::kOpFcGetHeaders) {
            Msg m = std::move(*it);
            h.q.erase(it);
            return m;
        }
    return std::nullopt;
}
// B serves A's oldest queued FC_GETHEADERS; A judges B's first frame (no request queued: Unsolicited).
pb::PathbNode::HeadersOutcome serve_page(Harness& h, const Pair2& s) {
    const std::optional<Msg> req = take_ask(h, s);
    if (!req) return pb::PathbNode::HeadersOutcome{};
    const std::vector<std::vector<std::uint8_t>> f = h[s.b].serve_getheaders(s.a, req->frame, h.now).frames;
    return h[s.a].on_headers(s.b, f.empty() ? *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22) : f.at(0),
                             h.now);
}
// A's oldest queued FC_GETHEADERS (left in the queue).
std::optional<pb::GetHeaders> next_ask(Harness& h) {
    pb::GetHeaders q;
    for (const Msg& m : h.q)
        if (!m.frame.empty() && m.frame[0] == pb::kOpFcGetHeaders && pb::decode_fc_getheaders(m.frame, 0, q).ok()) return q;
    return std::nullopt;
}
// B's headers at positions [lo, hi] of its best chain.
std::vector<pb::CarrierHeader> b_headers(Harness& h, std::size_t node, std::uint64_t lo, std::uint64_t hi) {
    std::vector<pb::CarrierHeader> v;
    for (std::uint64_t x = lo; x <= hi; ++x)
        if (const std::optional<pb::Hash32> id = h[node].store().best_at(x)) v.push_back(pb::header_of(*h[node].bodies().get(*id)));
    return v;
}
std::string kinds_str(const std::vector<pb::PathbNode::HeadersOutcome::Kind>& v) {
    std::string s;
    for (const auto k : v) s += std::to_string(static_cast<int>(k)) + ",";
    return s;
}
using HK = pb::PathbNode::HeadersOutcome::Kind;

// pagefold (E-197): A at fork 6 + 7, B at fork 6 + 9 (heavier). A asks with max 2: B's pages of 2. The comparison
// continues past max and wins at page 4 (B's 7th and 8th headers); the bodies: a journal switch onto the deciding
// page's last header. Each header hashed once (the node's verify count, its PoW memo cleared after each page).
void pagefold() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 6, 7, 9);
    const std::uint64_t v0 = pb::PathbNodeTestAccess::verify_calls(h[s.a]);
    check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 2, h.now), "pagefold: A asks B (max 2)");
    std::vector<HK> kinds;
    pb::PathbNode::HeadersOutcome o;
    for (int p = 0; p < 8; ++p) {
        o = serve_page(h, s);
        pb::PathbNodeTestAccess::memo_clear(h[s.a]);  // a later page's re-check of an earlier header hashes it again
        kinds.push_back(o.kind);
        if (o.kind != HK::Continue) break;
    }
    const std::uint64_t hashed = pb::PathbNodeTestAccess::verify_calls(h[s.a]) - v0;
    h.cut.clear();
    h.pump();
    const bool switched = !o.ids.empty() && h[s.a].tree().best().id == o.ids.back();
    const auto sc = h[s.a].switch_counts();
    std::printf("  pagefold: kinds %s fork_pos %llu; headers hashed %llu; A on the page's last header %d, switches %llu, "
                "joiner %llu\n",
                kinds_str(kinds).c_str(), (unsigned long long)o.fork_pos, (unsigned long long)hashed, switched ? 1 : 0,
                (unsigned long long)sc.switches, (unsigned long long)sc.joiner_switches);
    check(kinds.size() == 4 && kinds[0] == HK::Continue && kinds[1] == HK::Continue && kinds[2] == HK::Continue
                  && kinds[3] == HK::FetchBodies && o.fork_pos == s.fork_pos,
          "pagefold: pages of 2 at max 2: Continue x3, FetchBodies at page 4, fork point " + std::to_string(s.fork_pos));
    check(hashed == 8, "pagefold: each header hashed once (" + std::to_string(hashed) + " of 8)");
    check(switched && sc.switches >= 1 && sc.joiner_switches == 0,
          "pagefold: the bodies: a journal switch onto the deciding page's last header");
}

// stoppages (E-197; E-166 (v) at `stop`): B lighter (8) than A (10) past the fork; A asks with max 3: Continue,
// Continue, then Keep at the reply carrying `stop`.
void stoppages() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 6, 10, 8);
    check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "stoppages: A asks B (max 3)");
    std::vector<HK> kinds;
    pb::PathbNode::HeadersOutcome o;
    for (int p = 0; p < 8; ++p) {
        o = serve_page(h, s);
        kinds.push_back(o.kind);
        if (o.kind != HK::Continue) break;
    }
    std::printf("  stoppages: kinds %s; last id is stop %d; asks left %zu\n", kinds_str(kinds).c_str(),
                !o.ids.empty() && o.ids.back() == s.b_tip ? 1 : 0, h.q.size());
    check(kinds.size() == 3 && kinds[0] == HK::Continue && kinds[1] == HK::Continue && kinds[2] == HK::Keep
                  && !o.ids.empty() && o.ids.back() == s.b_tip && h.q.empty(),
          "stoppages: a lighter branch longer than max: Keep only at the reply carrying stop (" + kinds_str(kinds) + ")");
}

// sharedpage (E-197; F-D3): A asks from 3 positions below the fork with max 3: the first page holds shared headers
// only: Continue (no locator step); the second page B's own.
void sharedpage() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 6, 6, 8);
    const pb::Hash32 from = *h[s.a].store().best_at(s.fork_pos - 3);
    check(h[s.a].request_headers(s.b, from, s.b_tip, 3, h.now), "sharedpage: A asks B from fork - 3 (max 3)");
    const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
    const std::optional<pb::GetHeaders> q = next_ask(h);
    std::printf("  sharedpage: page 1 kind %d, ids %zu; next ask from the fork %d\n", static_cast<int>(o1.kind), o1.ids.size(),
                q && q->from == s.fork ? 1 : 0);
    check(o1.kind == HK::Continue && o1.ids.size() == 3 && q && q->from == s.fork && q->max == 3,
          "sharedpage: a first page of shared headers only: Continue from its last header");
}

// recordcarry (S1.3 #6 from the carried record): B 6 + 10 against A 6 + 4, max 3; page 1, B's 1st..3rd (each at a later
// Monero height); page 2, B's 4th with its P_r replaced by the P_r of B's 2nd (its h below the record B's 3rd raised, at
// or above the seed's): STRIKE.
void recordcarry() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 6, 4, 10);
    check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "recordcarry: A asks B (max 3)");
    const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
    (void)take_ask(h, s);
    std::vector<pb::CarrierHeader> pg = b_headers(h, s.b, s.fork_pos + 4, s.fork_pos + 4);
    pg[0].own.blob.prev_id = h[s.b].bodies().get(s.b_ids[1])->own.blob.prev_id;
    const pb::PathbNode::HeadersOutcome o2 =
            h[s.a].on_headers(s.b, *pb::encode_fc_headers(pb::HeadersReply{0, s.fork_pos + 4, pg}, 1u << 22), h.now);
    std::printf("  recordcarry: page 1 kind %d; page 2 kind %d (%s)\n", static_cast<int>(o1.kind), static_cast<int>(o2.kind),
                o2.why.c_str());
    check(o1.kind == HK::Continue && o2.kind == HK::Strike && o2.why.find("#6") != std::string::npos,
          "recordcarry: a page-2 header below the record page 1 raised: STRIKE (#6)");
}

// tipside (the body list of a comparison seeded off the best chain): A and B share 6; cut, A mines 6; B mines 3, which
// reach A (a held side branch, lighter), then 7 more, which do not. A's tip request to B (max 3) from B's 3rd (held at A,
// off its best chain) to B's tip: FetchBodies at the fork point 6 with the body of every checked header asked; served:
// A places them and switches onto the deciding page's last header (a journal switch).
void tipside() {
    const KatNet net;
    Harness h(net);
    Pair2 s;
    s.a = h.add(table0(net), true);
    s.b = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero(1);
        h.mine(s.a, static_cast<std::size_t>(i % 3), 7000 + static_cast<std::uint32_t>(i));
    }
    s.fork = h[s.a].tree().best().id;
    s.fork_pos = h[s.a].tree().best().pos;
    h.cut = {{s.a, s.b}, {s.b, s.a}};
    for (int i = 0; i < 6; ++i) {
        h.tick_monero(1);
        h.mine(s.a, 0, 7100 + static_cast<std::uint32_t>(i));
    }
    h.cut = {{s.a, s.b}};  // B's first 3 reach A
    for (int i = 0; i < 10; ++i) {
        if (i == 3) h.cut = {{s.a, s.b}, {s.b, s.a}};
        h.tick_monero(1);
        h.mine(s.b, 1, 7300 + static_cast<std::uint32_t>(i));
        s.b_ids.push_back(h[s.b].tree().best().id);
    }
    s.b_tip = h[s.b].tree().best().id;
    const pb::Hash32 seed = s.b_ids[2];
    const pb::CarrierNode* sn = h[s.a].tree().find(seed);
    const bool side = sn != nullptr && h[s.a].store().best_at(sn->pos) != std::optional<pb::Hash32>{seed}
                      && h[s.a].tree().find(s.b_ids[3]) == nullptr && h[s.a].tree().best().pos == s.fork_pos + 6;
    check(h[s.a].request_headers(s.b, seed, s.b_tip, 3, h.now, pb::PathbNode::HeaderOwner::Tip),
          "tipside: A's tip request to B from B's 3rd (max 3)");
    std::vector<HK> kinds;
    pb::PathbNode::HeadersOutcome o;
    std::size_t checked = 0;  // the headers the comparison checked
    for (int p = 0; p < 6; ++p) {
        o = serve_page(h, s);
        kinds.push_back(o.kind);
        checked += o.ids.size();
        if (o.kind != HK::Continue) break;
    }
    std::size_t asked = 0;
    for (const Msg& m : h.q)
        if (m.from == s.a && m.to == s.b && !m.frame.empty() && m.frame[0] == pb::kOpFcGetCarrier) {
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok()) asked += q.ids.size();
        }
    h.cut.clear();
    h.pump();
    const bool switched = !o.ids.empty() && h[s.a].tree().best().id == o.ids.back();
    const auto sc = h[s.a].switch_counts();
    std::printf("  tipside: B's 3rd held off A's best chain %d; kinds %s fork_pos %llu; bodies asked %zu of %zu checked; A on "
                "the deciding page's last header %d, switches %llu, joiner %llu\n",
                side ? 1 : 0, kinds_str(kinds).c_str(), (unsigned long long)o.fork_pos, asked, checked, switched ? 1 : 0,
                (unsigned long long)sc.switches, (unsigned long long)sc.joiner_switches);
    check(side, "tipside: setup (B's 3rd held at A off its best chain; B's 4th not held)");
    check(o.kind == HK::FetchBodies && o.fork_pos == s.fork_pos && asked == checked && asked > 0,
          "tipside: FetchBodies at the fork point, the body of every checked header asked (" + std::to_string(asked) + " of " +
                  std::to_string(checked) + ")");
    check(switched && sc.switches >= 1 && sc.joiner_switches == 0,
          "tipside: the bodies served: A switches onto the deciding page's last header");
}

// sharedforge (S1.3 #8 on every header): a continuation page of shared headers whose second carries a forged t_origin
// (its id unchanged): STRIKE.
void sharedforge() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 8, 6, 8);
    const pb::Hash32 from = *h[s.a].store().best_at(s.fork_pos - 4);
    check(h[s.a].request_headers(s.b, from, s.b_tip, 2, h.now), "sharedforge: A asks B from fork - 4 (max 2)");
    const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
    (void)take_ask(h, s);  // the continuation, answered by hand
    std::vector<pb::CarrierHeader> pg = b_headers(h, s.b, s.fork_pos - 1, s.fork_pos);
    pg[1].own.side.t_origin += 1;
    const pb::Hash32 forged_id = pb::receipt_id(pg[1].own);
    const pb::PathbNode::HeadersOutcome o2 =
            h[s.a].on_headers(s.b, *pb::encode_fc_headers(pb::HeadersReply{0, s.fork_pos - 1, pg}, 1u << 22), h.now);
    std::printf("  sharedforge: page 1 kind %d; page 2 kind %d (%s); the forged id held %d\n", static_cast<int>(o1.kind),
                static_cast<int>(o2.kind), o2.why.c_str(), h[s.a].store().best_at(s.fork_pos) == forged_id ? 1 : 0);
    check(o1.kind == HK::Continue && o2.kind == HK::Strike && h[s.a].store().best_at(s.fork_pos) == forged_id,
          "sharedforge: a held id with a forged t_origin in a shared continuation page: STRIKE (#8)");
}

// foldsplit (E-197; the fold equals the one-shot check): B mines 160 carriers past the fork at one Monero height (its d
// rises), then A 120, one per Monero height. A asks with max 64 and B's branch is served in random page sizes (1..5,
// seed 11); at every Continue the comparison's work equals the one-shot check over the same prefix; it decides
// FetchBodies on the page holding the one-shot's first winning header.
void foldsplit() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 6, 120, 160, 160, 1152, true);
    std::vector<pb::CarrierHeader> all = b_headers(h, s.b, s.fork_pos + 1, s.fork_pos + 160);
    std::vector<pb::CarrierAnnounce> ann;
    for (const pb::CarrierHeader& hd : all)
        ann.push_back(pb::CarrierAnnounce{pb::receipt_id(hd.own), hd.own.side.tip,
                                          h[s.b].tree().find(pb::receipt_id(hd.own))->h, hd.own.side.receipts_root,
                                          hd.own.side.ballot});
    const auto pass = [](const pb::CarrierAnnounce&, std::uint64_t) { return true; };
    const std::optional<std::vector<pb::SideHeader>> one = h[s.a].tree().check_side_headers(s.fork, ann, pass);
    std::set<std::uint64_t> ds;
    for (const pb::SideHeader& sh : *one) ds.insert(sh.work);
    check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 64, h.now), "foldsplit: A asks B (max 64)");
    h.q.pop_front();
    Rng rng(11);
    std::size_t at = 0;
    bool equal = true;
    pb::PathbNode::HeadersOutcome o;
    std::size_t decided_at = 0;
    while (at < all.size()) {
        const std::size_t n = std::min<std::size_t>(1 + rng.below(5), all.size() - at);
        std::vector<pb::CarrierHeader> pg(all.begin() + static_cast<std::ptrdiff_t>(at),
                                          all.begin() + static_cast<std::ptrdiff_t>(at + n));
        o = h[s.a].on_headers(s.b, *pb::encode_fc_headers(pb::HeadersReply{0, s.fork_pos + 1 + at, pg}, 1u << 22), h.now);
        at += n;
        if (o.kind != HK::Continue) {
            decided_at = at;
            break;
        }
        h.q.pop_front();
        ::c2pool::xmr::native::U128 w = h[s.a].tree().find(s.fork)->cum_work;
        for (std::size_t i = 0; i < at; ++i) w = ::c2pool::xmr::native::u128_add(w, ::c2pool::xmr::native::U128{(*one)[i].work, 0});
        const std::optional<::c2pool::xmr::native::U128> fw = pb::PathbNodeTestAccess::fold_work(h[s.a], s.b);
        equal = equal && fw && fw->lo == w.lo && fw->hi == w.hi;
    }
    // the one-shot's first winning prefix
    ::c2pool::xmr::native::U128 w = h[s.a].tree().find(s.fork)->cum_work;
    std::size_t win = 0;
    const pb::CarrierNode& best = h[s.a].tree().best();
    for (std::size_t i = 0; i < one->size(); ++i) {
        w = ::c2pool::xmr::native::u128_add(w, ::c2pool::xmr::native::U128{(*one)[i].work, 0});
        if (pb::side_work_wins(best.cum_work, best.id, w, (*one)[i].id)) {
            win = i + 1;
            break;
        }
    }
    std::printf("  foldsplit: distinct d %zu; the fold's work equal at every page %d; decided %d at header %zu (one-shot "
                "wins at %zu)\n",
                ds.size(), equal ? 1 : 0, static_cast<int>(o.kind), decided_at, win);
    check(ds.size() >= 2 && equal && o.kind == HK::FetchBodies && win > 0 && decided_at >= win && decided_at - win < 5,
          "foldsplit: random page splits: the carried work equals the one-shot check; the same winning header's page");
}

// Node `to` places node `from`'s carriers at positions [lo, hi] of its best chain (as walked frames).
void place_from(Harness& h, std::size_t to, std::size_t from, std::uint64_t lo, std::uint64_t hi) {
    for (std::uint64_t x = lo; x <= hi; ++x)
        if (const std::optional<pb::Hash32> id = h[from].store().best_at(x))
            (void)h[to].on_carrier(from, *pb::encode_fc_carrier(0, *h[from].bodies().get(*id), 16));
}

// basedrop (the win stands and the comparison ends with it where the ids above F were not kept: F deep when fixed, not
// deep at the decision). The journal base never moves back, so that state is forced after page 1 (the fold's ids
// dropped, as for a deep F). A 6 + 4, B 6 + 10, max 3:
//   plain : page 2 wins: FetchBodies asks the body of the last id (B's 6th) and names it the fetch tip; fork point 6; no
//           FC_GETHEADERS; no comparison left;
//   ended : the comparison ended (the done test) before page 2: the same.
void basedrop() {
    for (int mode = 0; mode < 2; ++mode) {
        const KatNet net;
        Harness h(net);
        const Pair2 s = pair2(h, 6, 4, 10);
        const std::string tag = std::string("basedrop ") + (mode == 0 ? "plain" : "ended");
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), tag + ": A asks B (max 3)");
        const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
        const bool forced = pb::PathbNodeTestAccess::fold_forget_ids(h[s.a], s.b);
        if (mode == 1) h[s.a].end_comparison(s.b);
        const pb::PathbNode::HeadersOutcome o = serve_page(h, s);
        std::vector<pb::Hash32> asked;
        std::size_t asks = 0;
        for (const Msg& m : h.q) {
            if (m.from != s.a || m.to != s.b || m.frame.empty()) continue;
            if (m.frame[0] == pb::kOpFcGetHeaders) ++asks;
            pb::GetCarrier q;
            if (m.frame[0] == pb::kOpFcGetCarrier && pb::decode_fc_getcarrier(m.frame, 0, pb::kRuledLaneParams, q).ok())
                asked.insert(asked.end(), q.ids.begin(), q.ids.end());
        }
        const bool open = h[s.a].header_slot(s.b).has_value() || h[s.a].comparison_paused(s.b);
        const bool last = asked.size() == 1 && asked[0] == s.b_ids[5];
        std::printf("  %s: page 1 kind %d, the ids dropped %d; page 2 kind %d fork_pos %llu; the fetch tip is B's 6th %d; "
                    "bodies asked %zu (B's 6th only %d); FC_GETHEADERS %zu; a comparison open %d\n",
                    tag.c_str(), static_cast<int>(o1.kind), forced ? 1 : 0, static_cast<int>(o.kind),
                    (unsigned long long)o.fork_pos, o.fetch_last == s.b_ids[5] ? 1 : 0, asked.size(), last ? 1 : 0, asks,
                    open ? 1 : 0);
        check(o1.kind == HK::Continue && forced, tag + ": setup (page 1; the comparison's ids above F dropped)");
        check(o.kind == HK::FetchBodies && o.fork_pos == s.fork_pos && o.fetch_last == s.b_ids[5] && last,
              tag + ": the win stands: FetchBodies asks the last id's body and names it the fetch tip");
        check(asks == 0 && !open, tag + ": no FC_GETHEADERS from F; the comparison ended with the win");
    }
}

// seedprune (the seed need not stay held: the fold carries its state from the request's send): A (journal depth 20,
// body_keep 5) and B share 1,200 positions (the fork); cut, A mines a of its own, B b. A asks B from A's position 10 with
// max 50; A prunes (its tree's root above the seed) before the first reply or between pages 1 and 2; the decision:
//   win deep (a 21, b 29; pruned before the first reply): JoinerPath, fork point 1,200;
//   win      (a 20, b 28; pruned between pages): FetchBodies, fork point 1,200;
//   loss     (a 24, b 20; pruned between pages): Keep at the reply carrying `stop`.
void seedprune() {
    struct Case {
        const char* name;
        int a_own, b_own;
        bool before;
    };
    for (const Case cs : {Case{"win deep", 21, 29, true}, Case{"win", 20, 28, false}, Case{"loss", 24, 20, false}}) {
        const KatNet net;
        Harness h(net);
        pb::PathbNodeConfig cfg = h.config(table0(net), true, 20);
        cfg.body_keep = 5;
        Pair2 s;
        s.a = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, h.io(s.a), nullptr));
        s.b = h.add(table0(net), true);
        for (std::uint32_t i = 0; i < 1200; ++i) {
            if (i % 12 == 0) h.tick_monero(1);
            h.mine(s.a, i % 5, 20000 + i);
        }
        s.fork = h[s.a].tree().best().id;
        s.fork_pos = h[s.a].tree().best().pos;
        h.cut = {{s.a, s.b}, {s.b, s.a}};
        for (int i = 0; i < cs.a_own; ++i) {
            h.tick_monero(1);
            h.mine(s.a, 0, 22000 + static_cast<std::uint32_t>(i));
        }
        for (int i = 0; i < cs.b_own; ++i) {
            h.tick_monero(1);
            h.mine(s.b, 1, 23000 + static_cast<std::uint32_t>(i));
        }
        s.b_tip = h[s.b].tree().best().id;
        const pb::Hash32 seed = *h[s.a].store().best_at(10);
        const std::string tag = std::string("seedprune ") + cs.name;
        check(h[s.a].request_headers(s.b, seed, s.b_tip, 50, h.now), tag + ": A asks B from its position 10 (max 50)");
        if (cs.before) (void)h[s.a].prune(h.now);
        std::vector<HK> kinds;
        pb::PathbNode::HeadersOutcome o;
        for (int p = 0; p < 40; ++p) {
            o = serve_page(h, s);
            kinds.push_back(o.kind);
            if (!cs.before && p == 0) (void)h[s.a].prune(h.now);
            if (o.kind != HK::Continue) break;
        }
        const std::uint64_t root = h[s.a].tree().genesis().pos;
        const bool pruned = root > 10 && h[s.a].tree().find(seed) == nullptr;
        std::printf("  %s: the seed pruned %d (root %llu, base %llu); pages %zu, the decision kind %d fork_pos %llu, at stop %d\n",
                    tag.c_str(), pruned ? 1 : 0, (unsigned long long)root, (unsigned long long)h[s.a].store().base_pos(),
                    kinds.size(), static_cast<int>(o.kind), (unsigned long long)o.fork_pos,
                    !o.ids.empty() && o.ids.back() == s.b_tip ? 1 : 0);
        check(pruned && kinds.size() > 2, tag + ": setup (the seed pruned; the comparison spans pages)");
        if (cs.a_own == 21)
            check(o.kind == HK::JoinerPath && o.fork_pos == s.fork_pos, tag + ": the win, F deep: JoinerPath at the fork point");
        else if (cs.a_own == 20)
            check(o.kind == HK::FetchBodies && o.fork_pos == s.fork_pos, tag + ": the win, F not deep: FetchBodies at the fork point");
        else
            check(o.kind == HK::Keep && !o.ids.empty() && o.ids.back() == s.b_tip, tag + ": the loss: Keep at the reply carrying stop");
    }
}

// jpnolink (the O-17 line where a pair was offered): bestmove (2)'s JoinerPath at a node with no link to the server (no
// transport): no pair offered (offered 0; the joiner's queue empty).
void jpnolink() {
    const KatNet net;
    Harness h(net);
    const Pair2 s = pair2(h, 6, 4, 12, 1, 6);
    check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "jpnolink: A asks B (max 3)");
    (void)serve_page(h, s);
    for (int i = 0; i < 4; ++i) {
        h.tick_monero(1);
        h.mine(s.a, 0, 7500 + static_cast<std::uint32_t>(i), false);
    }
    pb::PathbNode::HeadersOutcome o;
    for (int p = 0; p < 6; ++p) {
        o = serve_page(h, s);
        if (o.kind != HK::Continue) break;
    }
    std::printf("  jpnolink: kind %d; offered %d; the joiner's queue %zu\n", static_cast<int>(o.kind), o.offered ? 1 : 0,
                h[s.a].joiner().queue().size());
    check(o.kind == HK::JoinerPath && !o.offered && h[s.a].joiner().queue().size() == 0,
          "jpnolink: JoinerPath with no link to the server: no pair offered");
}

// bestmove (the fork point re-derived at the decision; F-1):
//   (1) A 6 + 4, B 6 + 10, max 3: after page 1 A places B's first 5 carriers (a journal switch onto them); page 2 wins:
//       FetchBodies, the fork point re-derived to B's 5th (6 + 5);
//   (2) A's journal depth 6: A 6 + 4, B 6 + 12, max 3; after page 1 (F = 6, within the journal) A mines 4 (its base
//       passes F); the win: JoinerPath at 6;
//   (3) A 6 + 4, B 6 + 10, max 3: page 1, then its continuation answered with no header (Paused); A mines 1 (its best
//       moves); A's next catch-up request resumes from page 1's last header; the win: FetchBodies, the fork point 6;
//   (4) A, B, C share 3; C is cut and mines 10 of its own; A and B share 3 more (the fork 6); A mines 5, B 12; A's journal
//       depth 8, max 3; after page 1 A places C's chain (a journal switch: C forks at 3); the win at page 3: F off the
//       best chain, its newest common ancestor 3 below the base: JoinerPath at 3.
void bestmove() {
    const KatNet net;
    {
        Harness h(net);
        const Pair2 s = pair2(h, 6, 4, 10);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "bestmove (1): A asks B (max 3)");
        const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
        place_from(h, s.a, s.b, s.fork_pos + 1, s.fork_pos + 5);
        const bool on_b5 = h[s.a].tree().best().id == s.b_ids[4];
        const pb::PathbNode::HeadersOutcome o2 = serve_page(h, s);
        std::printf("  bestmove (1): page 1 kind %d; A switched onto B's 5th %d; page 2 kind %d fork_pos %llu\n",
                    static_cast<int>(o1.kind), on_b5 ? 1 : 0, static_cast<int>(o2.kind), (unsigned long long)o2.fork_pos);
        check(o1.kind == HK::Continue && on_b5 && o2.kind == HK::FetchBodies && o2.fork_pos == s.fork_pos + 5,
              "bestmove (1): the node switched onto part of the branch: the fork point re-derived (" +
                      std::to_string(o2.fork_pos) + ")");
    }
    {
        Harness h(net);
        const Pair2 s = pair2(h, 6, 4, 12, 1, 6);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "bestmove (2): A asks B (max 3)");
        const std::uint64_t base0 = h[s.a].store().base_pos();
        const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
        for (int i = 0; i < 4; ++i) {
            h.tick_monero(1);
            h.mine(s.a, 0, 7500 + static_cast<std::uint32_t>(i), false);
        }
        const std::uint64_t base1 = h[s.a].store().base_pos();
        std::vector<HK> kinds;
        pb::PathbNode::HeadersOutcome o;
        for (int p = 0; p < 6; ++p) {
            o = serve_page(h, s);
            kinds.push_back(o.kind);
            if (o.kind != HK::Continue) break;
        }
        std::printf("  bestmove (2): base %llu at page 1 (kind %d), %llu after A mined 4; then kinds %s fork_pos %llu\n",
                    (unsigned long long)base0, static_cast<int>(o1.kind), (unsigned long long)base1,
                    kinds_str(kinds).c_str(), (unsigned long long)o.fork_pos);
        check(base0 <= s.fork_pos && base1 > s.fork_pos && o1.kind == HK::Continue && o.kind == HK::JoinerPath
                      && o.fork_pos == s.fork_pos,
              "bestmove (2): the base passed F during the comparison: JoinerPath at the decision");
    }
    {
        Harness h(net);
        const Pair2 s = pair2(h, 6, 4, 10);
        check(h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now), "bestmove (3): A asks B (max 3)");
        const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
        (void)take_ask(h, s);  // the continuation, answered with no header
        const pb::PathbNode::HeadersOutcome o2 =
                h[s.a].on_headers(s.b, *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22), h.now);
        h.tick_monero(1);
        h.mine(s.a, 0, 7550, false);
        const bool moved = h[s.a].tree().best().pos == s.fork_pos + 5;
        const bool asked = h[s.a].request_headers(s.b, s.fork, s.b_tip, 3, h.now);
        const std::optional<pb::GetHeaders> q = next_ask(h);
        const bool resumed = q && q->from == s.b_ids[2] && q->stop == s.b_tip && q->max == 3;
        std::vector<HK> kinds;
        pb::PathbNode::HeadersOutcome o;
        for (int p = 0; p < 6; ++p) {
            o = serve_page(h, s);
            kinds.push_back(o.kind);
            if (o.kind != HK::Continue) break;
        }
        std::printf("  bestmove (3): page 1 kind %d; the empty continuation kind %d; A's best moved %d; resumed from page 1's "
                    "last header %d; then kinds %s fork_pos %llu\n",
                    static_cast<int>(o1.kind), static_cast<int>(o2.kind), moved ? 1 : 0, resumed ? 1 : 0,
                    kinds_str(kinds).c_str(), (unsigned long long)o.fork_pos);
        check(o1.kind == HK::Continue && o2.kind == HK::Paused && moved && asked && resumed && o.kind == HK::FetchBodies
                      && o.fork_pos == s.fork_pos,
              "bestmove (3): the best moved during the pause: resumed; the win: FetchBodies, fork point " +
                      std::to_string(s.fork_pos));
    }
    {
        Harness h(net);
        const std::size_t a = h.add(table0(net), true, 8), b = h.add(table0(net), true), c = h.add(table0(net), true);
        for (int i = 0; i < 3; ++i) {
            h.tick_monero(1);
            h.mine(a, 0, 7600 + static_cast<std::uint32_t>(i));
        }
        h.cut = {{a, c}, {c, a}, {b, c}, {c, b}};
        for (int i = 0; i < 10; ++i) {
            h.tick_monero(1);
            h.mine(c, 2, 7700 + static_cast<std::uint32_t>(i));
        }
        for (int i = 0; i < 3; ++i) {
            h.tick_monero(1);
            h.mine(a, 0, 7800 + static_cast<std::uint32_t>(i));
        }
        const pb::Hash32 fork = h[a].tree().best().id;
        const std::uint64_t fork_pos = h[a].tree().best().pos;
        h.cut.insert({a, b});
        h.cut.insert({b, a});
        for (int i = 0; i < 5; ++i) {
            h.tick_monero(1);
            h.mine(a, 0, 7900 + static_cast<std::uint32_t>(i));
        }
        for (int i = 0; i < 12; ++i) {
            h.tick_monero(1);
            h.mine(b, 1, 8000 + static_cast<std::uint32_t>(i));
        }
        const Pair2 s{a, b, fork, h[b].tree().best().id, fork_pos, {}, {}};
        check(h[a].request_headers(b, fork, s.b_tip, 3, h.now), "bestmove (4): A asks B (max 3)");
        const pb::PathbNode::HeadersOutcome o1 = serve_page(h, s);
        place_from(h, a, c, 4, 13);
        const bool on_c = h[a].tree().best().id == h[c].tree().best().id;
        const std::uint64_t base = h[a].store().base_pos();
        std::vector<HK> kinds;
        pb::PathbNode::HeadersOutcome o;
        for (int p = 0; p < 6; ++p) {
            o = serve_page(h, s);
            kinds.push_back(o.kind);
            if (o.kind != HK::Continue) break;
        }
        std::printf("  bestmove (4): page 1 kind %d; A switched onto C's chain %d (base %llu); then kinds %s fork_pos %llu\n",
                    static_cast<int>(o1.kind), on_c ? 1 : 0, (unsigned long long)base, kinds_str(kinds).c_str(),
                    (unsigned long long)o.fork_pos);
        check(fork_pos == 6 && o1.kind == HK::Continue && on_c && base > 3 && o.kind == HK::JoinerPath && o.fork_pos == 3,
              "bestmove (4): the node switched to a third chain forking below F: F' = its fork point 3, below the base: "
              "JoinerPath");
    }
}

// remerge (the fork point is the prefix's last held header): B mines 4 past the fork 6, then A 8 (its 5th, Y, at
// position 11), then B 6 more. A's journal depth 4 (its base 10). B's branch is served with Y at 11 and B's 7th above
// it re-linked to Y (side.tip forged; ids unchanged): 7..10 B's 1st..4th, 11 Y, 12..15 B's 7th..10th. The win: F is
// the fork 6 (the first header not held fixed it), below the base: JoinerPath at 6.
void remerge() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true, 4), b = h.add(table0(net), true);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero(1);
        h.mine(a, 0, 8100 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 fork = h[a].tree().best().id;
    h.cut = {{a, b}, {b, a}};
    for (int i = 0; i < 4; ++i) {
        h.tick_monero(1);
        h.mine(b, 1, 8200 + static_cast<std::uint32_t>(i));
    }
    for (int i = 0; i < 8; ++i) {
        h.tick_monero(1);
        h.mine(a, 0, 8300 + static_cast<std::uint32_t>(i));
    }
    for (int i = 0; i < 6; ++i) {
        h.tick_monero(1);
        h.mine(b, 1, 8400 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 y = *h[a].store().best_at(11);
    std::vector<pb::CarrierHeader> br = b_headers(h, b, 7, 10);
    pb::CarrierHeader hy = pb::header_of(*h[a].bodies().get(y));
    hy.own.side.tip = pb::receipt_id(br.back().own);
    br.push_back(hy);
    std::vector<pb::CarrierHeader> rest = b_headers(h, b, 13, 16);  // B's 7th..10th (their h at or above Y's)
    rest[0].own.side.tip = y;
    br.insert(br.end(), rest.begin(), rest.end());
    const bool ids_kept = pb::receipt_id(hy.own) == y;
    const std::uint64_t base = h[a].store().base_pos();
    const pb::Hash32 stop = pb::receipt_id(br.back().own);
    check(h[a].request_headers(b, fork, stop, 64, h.now), "remerge: A asks B (max 64)");
    h.q.pop_front();
    const pb::PathbNode::HeadersOutcome o =
            h[a].on_headers(b, *pb::encode_fc_headers(pb::HeadersReply{0, 7, br}, 1u << 22), h.now);
    std::printf("  remerge: Y at 11 held %d (base %llu); kind %d fork_pos %llu %s\n", ids_kept ? 1 : 0,
                (unsigned long long)base, static_cast<int>(o.kind), (unsigned long long)o.fork_pos, o.why.c_str());
    check(ids_kept && base == 10 && o.kind == HK::JoinerPath && o.fork_pos == 6,
          "remerge: a held id re-linked above the fork point does not move it: JoinerPath at 6");
}

// deepband (E-197, S1.5; the fork point): A (launched) and C (a full node, not launched, journal depth j, one HELLO
// tail enough for an attempt, its deferred store cap `cap` when given) share 40 positions (the fork f = 40). C is cut
// off and mines d of its own; A mines d + 8 (heavier). Then C reconnects; C's join worker is stepped every second.
// Phase 1 (60 s, A idle): the HELLO catch-up. Phase 2 (60 s): A mines one carrier every 10 s. The join attempts at C and
// their ends, C's journal and joiner switches, and whether C holds A's tip after each phase.
struct DeepBand {
    bool setup = false, healed1 = false, healed2 = false;
    std::uint64_t f = 0, c_best = 0, base = 0, a_best = 0, sw = 0, jsw = 0, sw1 = 0, jsw1 = 0;
    int attempts = 0, oos = 0, completed = 0, jp_lines = 0;
    std::string jp_line;
};
DeepBand deep_band(std::uint64_t j, std::uint64_t d_c, std::uint64_t cap) {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    DeepBand o;
    KatRelay a = kat_relay(h, w, table0(net), true);
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay c = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; },
                           [j, cap](pb::PathbNodeConfig& cf) {
                               cf.journal_depth = j;
                               if (cap != 0) cf.waiting_cap = cap;
                           });
    w.connect(0, 1);
    w.run();
    bool ok = true;
    std::uint32_t nonce = 63000;
    for (int i = 0; i < 40 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    ok = ok && h[c.node].tree().best().id == h[a.node].tree().best().id;
    o.f = h[a.node].tree().best().pos;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (std::uint64_t i = 0; i < d_c && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    for (std::uint64_t i = 0; i < d_c + 8 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    o.c_best = h[c.node].tree().best().pos;
    o.base = h[c.node].store().base_pos();
    o.a_best = h[a.node].tree().best().pos;
    o.setup = ok && o.c_best == o.f + d_c && o.a_best == o.f + d_c + 8;
    const pb::Hash32 a_tip0 = h[a.node].tree().best().id;
    w.reconnect(0, 1);
    w.run();
    const auto step = [&] {
        h.now += 1;
        a.relay->tick();
        a.relay->pump();
        c.relay->tick();
        c.relay->pump();
        for (int m = 0; m < 200 && w.step(); ++m) {
        }
        for (int m = 0; m < 4; ++m)  // the join worker in manual mode: the queued attempts
            if (const std::optional<pb::JoinStep> s = c.relay->join_step(); !s) break;
        for (int m = 0; m < 200 && w.step(); ++m) {
        }
    };
    for (int k = 0; k < 60; ++k) step();
    o.healed1 = h[c.node].tree().best().id == a_tip0;
    o.sw1 = h[c.node].switch_counts().switches;
    o.jsw1 = h[c.node].switch_counts().joiner_switches;
    for (int k = 0; k < 60; ++k) {
        if (k % 10 == 0) {
            h.tick_monero();
            (void)mine_on(h, w, a.node, static_cast<std::size_t>(k % 5), nonce++);
        }
        step();
    }
    o.healed2 = h[c.node].tree().best().id == h[a.node].tree().best().id;
    o.sw = h[c.node].switch_counts().switches;
    o.jsw = h[c.node].switch_counts().joiner_switches;
    for (const std::string& l : lines[c.node]) {
        if (l.find("relay: join attempt at peer") != std::string::npos) {
            ++o.attempts;
            if (l.find("OutOfScope") != std::string::npos) ++o.oos;
            if (l.find("Completed") != std::string::npos) ++o.completed;
        }
        if (l.find("relay: headers from peer") != std::string::npos) {
            ++o.jp_lines;
            o.jp_line = l;
        }
    }
    g_relay_lines = nullptr;
    return o;
}
void deepband() {
    struct Case {
        std::uint64_t j, d_c, cap;
    };
    for (const Case cs : {Case{20, 15, 0}, Case{20, 18, 0}, Case{20, 19, 0}, Case{20, 20, 0}, Case{20, 21, 0},
                          Case{20, 24, 0}, Case{16, 15, 0}, Case{16, 16, 0}, Case{16, 17, 0}, Case{20, 18, 6}}) {
        const DeepBand o = deep_band(cs.j, cs.d_c, cs.cap);
        const bool deep = o.f < o.base;  // the fork point below the journal base: the joiner path (S1.5, E-38)
        const std::string tag = "deepband j " + std::to_string(cs.j) + " d " + std::to_string(cs.d_c) +
                                (cs.cap != 0 ? " cap " + std::to_string(cs.cap) : std::string());
        std::printf("  %s: setup %d; fork %llu, C best %llu, base %llu (%s), A best %llu; attempts %d (OutOfScope %d, "
                    "Completed %d); phase 1: C on A's tip %d, switches %llu, joiner %llu; phase 2: on A's tip %d, "
                    "switches %llu, joiner %llu; joiner-path lines %d%s%s\n",
                    tag.c_str(), o.setup ? 1 : 0, (unsigned long long)o.f, (unsigned long long)o.c_best,
                    (unsigned long long)o.base, deep ? "deep" : "within the journal", (unsigned long long)o.a_best,
                    o.attempts, o.oos, o.completed, o.healed1 ? 1 : 0, (unsigned long long)o.sw1,
                    (unsigned long long)o.jsw1, o.healed2 ? 1 : 0, (unsigned long long)o.sw, (unsigned long long)o.jsw,
                    o.jp_lines, o.jp_line.empty() ? "" : ": ", o.jp_line.c_str());
        check(o.setup, tag + ": setup");
        if (deep)
            check(o.healed1 && o.attempts == 1 && o.completed == 1 && o.jsw1 >= 1 && o.jp_lines == 1,
                  tag + ": the fork point below the journal base: one attempt, Completed, a joiner switch, C on A's tip");
        else
            check(o.healed1 && o.attempts == 0 && o.jsw1 == 0 && o.sw1 >= 1,
                  tag + ": the fork point within the journal: a journal switch, no join attempt, C on A's tip");
    }
}

// deeppruned (S1.5, E-38; a pruned full node offers no HELLO tip; its catch-up's reply with no header from its root
// offers the peer's tip as a root-evidence pair): deepband's shape at a pruned C. A and C (journal depth 20, body_keep 5)
// share S positions (F = S); C, cut off, mines d of its own, A d + 8 (heavier) or d - 4 (lighter: C's headers and
// carriers do not reach A); C prunes (its tree's root above 0), then reconnects; its join worker is stepped every
// second for 60 s.
//   base - 1 (d 21): one attempt, Completed, a joiner switch;
//   base (d 20), base + 1 (d 19): a journal switch in phase 1; 0 attempts;
//   lighter, root <= F < base (d 24, A d - 4): Keep at `stop`; 0 attempts;
//   F < root (d 1,200): one attempt, Completed, a joiner switch.
struct DeepPruned {
    bool setup = false, healed = false, kept = false;
    bool catchup_open = true, stop_indexed = false;  // the catch-up toward A; A's tip header indexed (the comparison read it)
    std::uint64_t f = 0, root = 0, base = 0, sw = 0, jsw = 0, strikes = 0;
    int attempts = 0, oos = 0, completed = 0;
    std::string ends;
};
DeepPruned deep_pruned(std::uint64_t shared, std::uint64_t d_c, std::uint64_t d_a, bool a_blind = false) {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    DeepPruned o;
    KatRelay a = kat_relay(h, w, table0(net), true, false);
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay c = kat_relay(h, w, table0(net), true, false, [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; },
                           [](pb::PathbNodeConfig& cf) {
                               cf.journal_depth = 20;
                               cf.body_keep = 5;
                           });
    w.connect(0, 1);
    w.run();
    bool ok = true;
    std::uint32_t nonce = 64000;
    for (std::uint64_t i = 0; i < shared && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    ok = ok && h[c.node].tree().best().id == h[a.node].tree().best().id;
    o.f = h[a.node].tree().best().pos;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (std::uint64_t i = 0; i < d_c && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    for (std::uint64_t i = 0; i < d_a && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    (void)h[c.node].prune(h.now);
    o.root = h[c.node].tree().genesis().pos;
    o.base = h[c.node].store().base_pos();
    const pb::Hash32 c_tip0 = h[c.node].tree().best().id, a_tip0 = h[a.node].tree().best().id;
    o.setup = ok && o.root > 0 && h[c.node].tree().best().pos == o.f + d_c;
    lines[c.node].clear();
    if (a_blind)  // A keeps its lighter chain: C's headers and carriers do not reach A
        w.edit = [](FakeWire::Msg& m) {
            if (m.from == 1 && m.to == 0 && !m.f.empty() && (m.f[0] == pb::kOpFcHeaders || m.f[0] == pb::kOpFcCarrier))
                m.f.clear();
        };
    w.reconnect(0, 1);
    w.run();
    for (int k = 0; k < 60; ++k) {
        h.now += 1;
        a.relay->tick();
        a.relay->pump();
        c.relay->tick();
        c.relay->pump();
        for (int m = 0; m < 400 && w.step(); ++m) {
        }
        for (int m = 0; m < 4; ++m)
            if (const std::optional<pb::JoinStep> s = c.relay->join_step(); !s) break;
        for (int m = 0; m < 400 && w.step(); ++m) {
        }
    }
    w.edit = nullptr;
    o.catchup_open = c.relay->catchup_view(w.id(1, 0)).has_value();
    o.stop_indexed = !h[c.node].headers().variants(a_tip0).empty();
    o.healed = h[c.node].tree().best().id == a_tip0;
    o.kept = h[c.node].tree().best().id == c_tip0;
    o.sw = h[c.node].switch_counts().switches;
    o.jsw = h[c.node].switch_counts().joiner_switches;
    o.strikes = c.relay->stats().strikes.load();
    for (const std::string& l : lines[c.node])
        if (l.find("relay: join attempt at peer") != std::string::npos) {
            ++o.attempts;
            if (l.find("OutOfScope") != std::string::npos) ++o.oos;
            if (l.find("Completed") != std::string::npos) ++o.completed;
            o.ends += " [" + l.substr(0, 140) + "]";
        }
    g_relay_lines = nullptr;
    return o;
}
void deeppruned() {
    struct Case {
        const char* name;
        std::uint64_t shared, d_c, d_a;
    };
    for (const Case cs : {Case{"base - 1", 1175, 21, 29}, Case{"base", 1175, 20, 28}, Case{"base + 1", 1175, 19, 27},
                          Case{"lighter", 1175, 24, 20}, Case{"F < root", 40, 1200, 1208}}) {
        const DeepPruned o = deep_pruned(cs.shared, cs.d_c, cs.d_a, std::string(cs.name) == "lighter");
        const std::string tag = std::string("deeppruned ") + cs.name;
        const std::string n0 = cs.name;
        std::printf("  %s: setup %d; F %llu, root %llu, base %llu; attempts %d (OutOfScope %d, Completed %d); on A's tip %d, "
                    "kept %d; switches %llu, joiner %llu; strikes %llu\n",
                    tag.c_str(), o.setup ? 1 : 0, (unsigned long long)o.f, (unsigned long long)o.root,
                    (unsigned long long)o.base, o.attempts, o.oos, o.completed, o.healed ? 1 : 0, o.kept ? 1 : 0,
                    (unsigned long long)o.sw, (unsigned long long)o.jsw, (unsigned long long)o.strikes);
        if (n0 == "lighter")
            std::printf("  %s: the catch-up toward A ended %d; A's tip header read (the reply carrying stop) %d\n", tag.c_str(),
                        o.catchup_open ? 0 : 1, o.stop_indexed ? 1 : 0);
        check(o.setup, tag + ": setup (C pruned: its tree's root above 0)");
        const std::string n = cs.name;
        if (n == "base - 1" || n == "F < root")
            check(o.healed && o.attempts == 1 && o.completed == 1 && o.jsw >= 1 && (n != "F < root" || o.f < o.root),
                  tag + ": one attempt, Completed, a joiner switch");
        else if (n == "lighter")
            check(o.kept && o.attempts == 0 && o.jsw == 0 && o.base > o.f && o.root <= o.f && !o.catchup_open && o.stop_indexed,
                  tag + ": root <= F < base, lighter: Keep at stop; 0 attempts");
        else
            check(o.healed && o.attempts == 0 && o.strikes == 0 && o.jsw == 0 && o.sw >= 1,
                  tag + ": a journal switch in phase 1; 0 attempts");
    }
}

// A pruned store not caught up: A and D share `shared` positions; D, cut off, mines `d_c` of its own, A `d_a`; a store
// not caught up (journal depth 20, body_keep 5) walks D's chain and prunes; it restarts from its store as C2 (wire 2).
// `hide_pos` (C2's view): the P_r of A's carrier at that position hidden (0: none).
struct PrunedRestart {
    KatNet net;
    Harness h;
    FakeWire w;
    std::set<pb::Hash32> hidden;
    HiddenRows hrows;
    pb::FollowerBranchView hview;
    KatRelay a, d, c2;
    bool ok = true;
    std::uint64_t root = 0;
    pb::Hash32 a_tip{};
    PrunedRestart(std::uint64_t shared, std::uint64_t d_c, std::uint64_t d_a, std::uint64_t hide_pos)
        : h(net), hrows(net.rows, hidden), hview(hrows) {
        a = kat_relay(h, w, table0(net), true);  // wire 0
        d = kat_relay(h, w, table0(net), true);  // wire 1
        w.connect(0, 1);
        w.run();
        std::uint32_t nonce = 69000;
        for (std::uint64_t i = 0; i < shared && ok; ++i) {
            if (i % 12 == 0) h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        ok = ok && h[d.node].tree().best().id == h[a.node].tree().best().id;
        w.links[1]->disconnect(w.id(1, 0));
        w.run();
        for (std::uint64_t i = 0; i < d_c && ok; ++i) {
            if (i % 12 == 0) h.tick_monero();
            ok = mine_on(h, w, d.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        for (std::uint64_t i = 0; i < d_a && ok; ++i) {
            if (i % 12 == 0) h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        a_tip = h[a.node].tree().best().id;
        pb::PathbNodeConfig cfg = h.config(table0(net), false, 20);
        cfg.body_keep = 5;
        h.kvs.push_back(std::make_unique<MemoryKv>());
        MemoryKv& kvw = *h.kvs.back();
        const std::size_t jw = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cfg, h.io(jw), &kvw));
        for (std::uint64_t x = 1; x <= h[d.node].tree().best().pos; ++x)
            if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x))
                (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
        h.q.clear();
        ok = ok && h[jw].tree().best().id == h[d.node].tree().best().id && !h[jw].caught_up();
        (void)h[jw].prune(h.now);
        if (hide_pos != 0)
            if (const std::optional<pb::Hash32> id = h[a.node].store().best_at(hide_pos))
                hidden.insert(h[a.node].bodies().get(*id)->own.blob.prev_id);
        c2 = kat_relay_loaded(h, w, kvw, cfg, [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; },
                              hide_blocks(hidden, hview));
        root = h[c2.node].tree().genesis().pos;
        ok = ok && root > 0 && h[c2.node].pruned_full_node() && !h[c2.node].caught_up();
    }
    PrunedRestart(const PrunedRestart&) = delete;
    PrunedRestart& operator=(const PrunedRestart&) = delete;
    // One second: A's and C2's ticks, the wire; C2's join worker when `join`.
    void second(bool join) {
        h.now += 1;
        a.relay->tick();
        c2.relay->tick();
        a.relay->pump();
        c2.relay->pump();
        for (int m = 0; m < 400 && w.step(); ++m) {
        }
        if (join)
            for (int m = 0; m < 4; ++m)
                if (const std::optional<pb::JoinStep> st = c2.relay->join_step(); !st) break;
        w.run();
    }
};

// rootevid (a pruned full node's reply with no header from its root; a store not caught up): A and D share 40; D mines
// 1,200 of its own, A 1,208; C2 walked D's chain, pruned (its root above the fork 40). C2 meets A: its catch-up's request from its
// lowest held position gets no header: the root-evidence line (that position), A's tip a root-evidence pair, the
// hand-over recorded (no caught-up line at the reply); the attempt Completed, adopted; then the caught-up line.
void rootevid() {
    PrunedRestart r(40, 1200, 1208, 0);
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    r.w.connect(0, 2);
    r.w.run();
    const std::uint64_t pa = r.w.id(2, 0);
    const auto re_lines = [&] {
        std::size_t n = 0;
        for (const std::string& l : lines[r.c2.node])
            if (l.find("(root evidence)") != std::string::npos) ++n;
        return n;
    };
    for (int k = 0; k < 10 && re_lines() == 0; ++k) r.second(false);
    const std::string want = "relay: catch-up from peer " + std::to_string(pa) + ": no header from the lowest held position " +
                             std::to_string(r.root) + ": its tip offered to the joiner (root evidence)";
    bool exact = false, marked = false;
    for (const std::string& l : lines[r.c2.node]) exact = exact || l == want;
    for (const pb::AttemptQueue::Pair& q : r.h[r.c2.node].joiner().queue().pairs())
        if (q.candidate == r.a_tip && q.server == pa) marked = q.root_evidence;
    const std::size_t caught_at_reply = caught_of(lines, r.c2.node).size();
    const bool handed = !r.c2.relay->catchup_view(pa).has_value() && r.h[r.c2.node].pair_lives(r.a_tip, pa);
    for (int k = 0; k < 30 && !r.h[r.c2.node].holds_tip(r.a_tip); ++k) r.second(true);
    for (int k = 0; k < 5; ++k) r.second(true);
    int attempts = 0, completed = 0;
    for (const std::string& l : lines[r.c2.node])
        if (l.find("relay: join attempt at peer") != std::string::npos) {
            ++attempts;
            if (l.find("Completed") != std::string::npos && l.find("adopted") != std::string::npos) ++completed;
        }
    const std::size_t caught_end = caught_of(lines, r.c2.node).size();
    g_relay_lines = nullptr;
    std::printf("  rootevid: setup %d (root %llu); root-evidence lines %zu, the text exact %d; the pair marked %d; at the "
                "reply: handed over %d, caught-up lines %zu; attempts %d (Completed, adopted %d); C2 on A's tip %d; "
                "caught-up lines %zu\n",
                r.ok ? 1 : 0, (unsigned long long)r.root, re_lines(), exact ? 1 : 0, marked ? 1 : 0, handed ? 1 : 0,
                caught_at_reply, attempts, completed, r.h[r.c2.node].holds_tip(r.a_tip) ? 1 : 0, caught_end);
    check(r.ok, "rootevid: setup (C2 a pruned full node, not caught up)");
    check(re_lines() == 1 && exact && marked,
          "rootevid: the reply with no header from C2's root: the root-evidence line; A's tip a root-evidence pair");
    check(handed && caught_at_reply == 0, "rootevid: the hand-over recorded; no caught-up line at the reply");
    check(attempts == 1 && completed == 1 && r.h[r.c2.node].holds_tip(r.a_tip) && caught_end == 1,
          "rootevid: one attempt, Completed, adopted; then the caught-up line");
}

// fd1mark (a deferred catch-up step's offer at a pruned full node): A and D share 1,200; D mines 20 of its own, A 28;
// C2 walked D's chain, pruned, the P_r of A's position 1,205 hidden at C2. C2's catch-up toward A defers on it past its
// context's time: A's tip offered to the joiner as a root-evidence pair.
void fd1mark() {
    PrunedRestart r(1200, 20, 28, 1205);
    r.w.connect(0, 2);
    r.w.run();
    const std::uint64_t pa = r.w.id(2, 0);
    bool deferred = false;
    for (int k = 0; k < 10 && !deferred; ++k) {
        r.second(false);
        deferred = r.c2.relay->header_deferred(pa, pb::PathbNode::HeaderOwner::CatchUp) > 0;
    }
    for (int k = 0; k < 130 && r.c2.relay->stats().catchup_join_offers.load() == 0; ++k) {
        r.h.now += 4;
        r.second(false);
    }
    bool queued = false, marked = false;
    for (const pb::AttemptQueue::Pair& q : r.h[r.c2.node].joiner().queue().pairs())
        if (q.candidate == r.a_tip && q.server == pa) {
            queued = true;
            marked = q.root_evidence;
        }
    std::printf("  fd1mark: setup %d (root %llu); deferred %d; offers %llu; A's tip queued %d, marked %d\n", r.ok ? 1 : 0,
                (unsigned long long)r.root, deferred ? 1 : 0,
                (unsigned long long)r.c2.relay->stats().catchup_join_offers.load(), queued ? 1 : 0, marked ? 1 : 0);
    check(r.ok && deferred, "fd1mark: setup (C2 pruned, not caught up; its catch-up step deferred on a P_r)");
    check(queued && marked, "fd1mark: the deferred step's offer at a pruned full node: A's tip a root-evidence pair");
}

// deepncu (E-193, E-194; the comparison at a store not caught up): A and D (launched) share 40 positions; D, cut off,
// mines d of its own, A d + 8 (heavier). J, a store not caught up (journal depth 20), walked D's chain; J's relay
// connects to A (one HELLO tail enough for an attempt); J's join worker is stepped every second for 60 s; the wire is
// stepped one frame at a time and J's gate is read whenever its comparison toward A is open (before its decision).
//   base - 1 (d 21): a hand-over, one attempt Completed, adopted; then the line;
//   base (d 20), base + 1 (d 19): a journal switch; then the line; the gate open.
// No line before J holds A's tip; while the comparison is open with nothing in hand the gate is open (its claim).
struct DeepNcu {
    bool setup = false, on_a = false, caught = false, line_after_tip = true;
    std::uint64_t f = 0, base = 0, sw = 0, jsw = 0;
    int attempts = 0, completed = 0, open_reads = 0, held_reads = 0;
    std::size_t lines = 0;
};
DeepNcu deep_ncu(std::uint64_t d_c) {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    DeepNcu o;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay d = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    std::uint32_t nonce = 65000;
    for (int i = 0; i < 40 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    ok = ok && h[d.node].tree().best().id == h[a.node].tree().best().id;
    o.f = h[a.node].tree().best().pos;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (std::uint64_t i = 0; i < d_c && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, d.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    for (std::uint64_t i = 0; i < d_c + 8 && ok; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    const pb::Hash32 a_tip = h[a.node].tree().best().id;
    const std::size_t jw = h.add(table0(net), false, 20, true);
    MemoryKv& kvw = *h.kvs.back();
    for (std::uint64_t x = 1; x <= o.f + d_c; ++x)
        if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x))
            (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
    h.q.clear();
    ok = ok && h[jw].tree().best().pos == o.f + d_c && !h[jw].caught_up();
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net), false, 20),
                                  [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; });
    o.base = h[j.node].store().base_pos();
    o.setup = ok;
    const std::uint64_t pa = w.id(2, 0);
    w.connect(0, 2);
    for (pb::PathbRelayNode* x : w.relays) x->pump();
    for (int k = 0; k < 60; ++k) {
        h.now += 1;
        a.relay->tick();
        j.relay->tick();
        for (int m = 0; m < 400; ++m) {
            if (pb::PathbNodeTestAccess::fold_work(h[j.node], pa) && caught_of(lines, j.node).empty() && h[j.node].drain_done()
                && !h[j.node].first_round_open())
                ++(gate_open(h, j.node) ? o.open_reads : o.held_reads);
            if (!w.step()) break;
        }
        if (!caught_of(lines, j.node).empty() && !h[j.node].holds_tip(a_tip)) o.line_after_tip = false;
        for (int m = 0; m < 4; ++m)
            if (const std::optional<pb::JoinStep> s = j.relay->join_step(); !s) break;
        w.run();
    }
    g_relay_lines = nullptr;
    o.on_a = h[j.node].tree().best().id == a_tip;
    o.caught = h[j.node].caught_up();
    o.lines = caught_of(lines, j.node).size();
    o.sw = h[j.node].switch_counts().switches;
    o.jsw = h[j.node].switch_counts().joiner_adopted + h[j.node].switch_counts().joiner_switches;
    for (const std::string& l : lines[j.node])
        if (l.find("relay: join attempt at peer") != std::string::npos) {
            ++o.attempts;
            if (l.find("Completed") != std::string::npos) ++o.completed;
        }
    return o;
}
void deepncu() {
    struct Case {
        const char* name;
        std::uint64_t d;
    };
    for (const Case cs : {Case{"base - 1", 21}, Case{"base", 20}, Case{"base + 1", 19}}) {
        const DeepNcu o = deep_ncu(cs.d);
        const std::string tag = std::string("deepncu ") + cs.name;
        std::printf("  %s: setup %d; F %llu, base %llu; attempts %d (Completed %d); on A's tip %d; switches %llu, joiner %llu; "
                    "lines %zu, caught up %d, no line before A's tip %d; gate while the comparison is open: open %d held %d\n",
                    tag.c_str(), o.setup ? 1 : 0, (unsigned long long)o.f, (unsigned long long)o.base, o.attempts,
                    o.completed, o.on_a ? 1 : 0, (unsigned long long)o.sw, (unsigned long long)o.jsw, o.lines,
                    o.caught ? 1 : 0, o.line_after_tip ? 1 : 0, o.open_reads, o.held_reads);
        check(o.setup, tag + ": setup");
        if (std::string(cs.name) == "base - 1")
            check(o.on_a && o.attempts == 1 && o.completed == 1 && o.jsw >= 1 && o.lines == 1 && o.caught,
                  tag + ": a hand-over, one attempt Completed, adopted; the line");
        else
            check(o.on_a && o.attempts == 0 && o.sw >= 1 && o.lines == 1 && o.caught,
                  tag + ": a journal switch; the line, K_NCU ended");
        check(o.line_after_tip, tag + ": no line before the comparison's end");
        check(o.open_reads >= 1 && o.held_reads == 0,
              tag + ": while the comparison is open, nothing in hand: the gate open (open " + std::to_string(o.open_reads) +
                      ", held " + std::to_string(o.held_reads) + ")");
    }
}

// The comparison rig (E-197): A (launched) and the requester share 40 positions; the requester's own branch is d long
// (a full node C mining it, journal depth 20; or, `ncu`, a store not caught up J walked D's branch), A's d + a_more
// (heavier). The requester's FC_GETHEADERS to A are recorded (time, from); A's replies to it pass through `reply_edit`
// once one of them has carried a header. `hide_tip_pr` (C only): the P_r of A's tip is hidden at C.
struct CmpRig {
    KatNet net;
    Harness h;
    FakeWire w;
    std::set<pb::Hash32> hidden;
    HiddenRows hrows;
    pb::FollowerBranchView hview;
    KatRelay a, c, d;
    std::size_t cw = 1;
    std::uint64_t pa = 0, f = 0;
    pb::Hash32 a_tip{}, a_tip_pr{};
    std::map<std::size_t, std::vector<std::string>> lines;
    std::vector<std::pair<std::uint64_t, pb::Hash32>> asks;
    bool header_seen = false, ok = true;
    std::function<void(FakeWire::Msg&)> reply_edit;
    CmpRig(bool ncu, std::uint64_t d_c, bool hide_tip_pr, std::uint64_t a_more = 8)
        : h(net), hrows(net.rows, hidden), hview(hrows) {
        a = kat_relay(h, w, table0(net), true);
        std::uint32_t nonce = 66000;
        if (!ncu) {
            c = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; },
                          [](pb::PathbNodeConfig& cf) { cf.journal_depth = 20; }, hide_tip_pr ? hide_blocks(hidden, hview) : nullptr);
        } else {
            d = kat_relay(h, w, table0(net), true);
        }
        w.connect(0, 1);
        w.run();
        for (int i = 0; i < 40 && ok; ++i) {
            if (i % 3 == 0) h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        f = h[a.node].tree().best().pos;
        w.links[1]->disconnect(w.id(1, 0));
        w.run();
        const std::size_t own = ncu ? d.node : c.node;
        for (std::uint64_t i = 0; i < d_c && ok; ++i) {
            if (i % 3 == 0) h.tick_monero();
            ok = mine_on(h, w, own, static_cast<std::size_t>(i % 5), nonce++);
        }
        for (std::uint64_t i = 0; i < d_c + a_more && ok; ++i) {
            if (i % 3 == 0) h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        a_tip = h[a.node].tree().best().id;
        a_tip_pr = h[a.node].bodies().get(a_tip)->own.blob.prev_id;
        if (hide_tip_pr) hidden.insert(a_tip_pr);
        g_relay_lines = &lines;
        if (ncu) {
            const std::size_t jw = h.add(table0(net), false, 20, true);
            MemoryKv& kvw = *h.kvs.back();
            for (std::uint64_t x = 1; x <= f + d_c; ++x)
                if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x))
                    (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
            h.q.clear();
            c = kat_relay_loaded(h, w, kvw, h.config(table0(net), false, 20),
                                 [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; });
            cw = 2;
        }
        pa = w.id(cw, 0);
        w.edit = [this](FakeWire::Msg& m) {
            if (m.f.empty()) return;
            if (m.from == cw && m.to == 0 && m.f[0] == pb::kOpFcGetHeaders) {
                pb::GetHeaders q;
                if (pb::decode_fc_getheaders(m.f, 0, q).ok()) asks.emplace_back(h.now, q.from);
                return;
            }
            if (m.from != 0 || m.to != cw || m.f[0] != pb::kOpFcHeaders) return;
            if (header_seen && reply_edit) reply_edit(m);
            if (m.f.size() > 100) header_seen = true;
        };
    }
    ~CmpRig() {
        w.edit = nullptr;
        g_relay_lines = nullptr;
    }
    CmpRig(const CmpRig&) = delete;
    CmpRig& operator=(const CmpRig&) = delete;
    pb::PathbNode& nc() { return h[c.node]; }
    void connect() {
        if (cw == 1)
            w.reconnect(0, 1);
        else
            w.connect(0, 2);
        w.run();
    }
    // One second: both ticks, the wire, the requester's join worker.
    void second() {
        h.now += 1;
        a.relay->tick();
        c.relay->tick();
        for (pb::PathbRelayNode* x : w.relays) x->pump();
        for (int m = 0; m < 400 && w.step(); ++m) {
        }
        for (int m = 0; m < 4; ++m)
            if (const std::optional<pb::JoinStep> s = c.relay->join_step(); !s) break;
        w.run();
    }
    std::size_t n_lines() const { return caught_of(lines, c.node).size(); }
};
const std::vector<std::uint8_t>& empty_headers_frame() {
    static const std::vector<std::uint8_t> f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);
    return f;
}

// emptycont (E-197 (3); the pause): J, a store not caught up (its branch 19: within the journal), asks A; A answers the
// comparison's continuation (its first page carried headers) with no header, then serves.
//   served   : no token; the next FC_GETHEADERS from the paused page's `from`, P-53 after that page's send; J reaches A's
//              tip (a journal switch); no caught-up line during the pause; then the line;
//   bestmove : as served, and during the pause J places a carrier of its own branch (its best moves): no request before
//              P-53 after the paused page's send.
void emptycont() {
    for (int mode = 0; mode < 2; ++mode) {
        CmpRig r(true, 19, false);
        int replaced = 0;
        r.reply_edit = [&](FakeWire::Msg& m) {
            if (replaced++ == 0) m.f = empty_headers_frame();
        };
        r.connect();
        std::size_t lines_pause = 0;
        bool moved = false;
        for (int k = 0; k < 40; ++k) {
            r.second();
            if (replaced > 0 && r.asks.size() >= 1 && !r.nc().holds_tip(r.a_tip)) lines_pause = std::max(lines_pause, r.n_lines());
            if (mode == 1 && replaced > 0 && !moved) {
                moved = true;  // a carrier extending J's own branch: J's best moves while the comparison is paused
                r.h.tick_monero();
                const std::optional<pb::PathbJob> j = r.h.job(r.d.node, 1, 66900);
                if (j && r.h[r.d.node].on_own_share(*j, 66900, pb::Hash32{}).action == pb::NodeAction::Placed)
                    (void)r.nc().on_carrier(77, *pb::encode_fc_carrier(0, *r.h[r.d.node].bodies().get(r.h[r.d.node].tree().best().id), 16));
            }
        }
        // the paused page: the ask answered by the replaced reply (the last ask before it), and the next ask
        std::size_t pi = 0;
        for (std::size_t i = 0; i < r.asks.size(); ++i)
            if (i + 1 < r.asks.size() && r.asks[i + 1].first > r.asks[i].first + 1 && i > 0) {
                pi = i;
                break;
            }
        const bool have = pi > 0 && pi + 1 < r.asks.size();
        const std::uint64_t gap = have ? r.asks[pi + 1].first - r.asks[pi].first : 0;
        const bool same_from = have && r.asks[pi + 1].second == r.asks[pi].second;
        const std::string tag = std::string("emptycont ") + (mode == 0 ? "served" : "bestmove");
        std::printf("  %s: asks %zu; the paused page's ask at %zu: the next ask %llu s later, from the same header %d; "
                    "J on A's tip %d; lines during the pause %zu, at the end %zu; strikes %llu\n",
                    tag.c_str(), r.asks.size(), pi, (unsigned long long)gap, same_from ? 1 : 0, r.nc().holds_tip(r.a_tip) ? 1 : 0,
                    lines_pause, r.n_lines(), (unsigned long long)r.c.relay->stats().strikes.load());
        check(r.ok && replaced >= 1 && (mode == 0 || moved), tag + ": setup (a continuation answered with no header)");
        check(have && same_from && gap >= 11 && gap <= 12,
              tag + ": resumed from the paused page's from, P-53 after its send (" + std::to_string(gap) + " s)");
        check(r.nc().holds_tip(r.a_tip) && lines_pause == 0 && r.n_lines() == 1 && r.c.relay->stats().strikes.load() == 0,
              tag + ": no token; the comparison completes; no line during the pause, then the line");
    }
}

// orphan (E-150 (3); the owner's end): J, a store not caught up (its branch 19), asks A (its branch 49); A's reply to the
// comparison's continuation (a page that does not reach A's tip) is held back. J receives A's chain from another source (J holds A's tip); at J's tick the catch-up ends by
// its done test; then the held reply reaches J: the page judged, no next FC_GETHEADERS to A.
void orphan() {
    CmpRig r(true, 19, false, 30);
    std::vector<std::uint8_t> held;
    r.reply_edit = [&](FakeWire::Msg& m) {
        if (held.empty()) held.swap(m.f);
    };
    r.connect();
    for (int k = 0; k < 2; ++k) r.second();
    const bool got = !held.empty();
    for (std::uint64_t x = r.f + 1; x <= r.h[r.a.node].tree().best().pos; ++x)
        if (const std::optional<pb::Hash32> id = r.h[r.a.node].store().best_at(x))
            (void)r.nc().on_carrier(78, *pb::encode_fc_carrier(0, *r.h[r.a.node].bodies().get(*id), 16));
    const bool holds = r.nc().holds_tip(r.a_tip);
    r.second();  // the tick: the done test ends the catch-up
    const std::size_t asks0 = r.asks.size();
    const std::uint64_t idx0 = pb::PathbNodeTestAccess::headers(r.nc()).size();
    r.w.links[r.cw]->frame(r.pa, held);
    r.c.relay->pump();
    r.w.run();
    const std::size_t asks1 = r.asks.size();
    const std::uint64_t idx1 = pb::PathbNodeTestAccess::headers(r.nc()).size();
    std::printf("  orphan: the continuation's reply held %d; J holds A's tip %d; after the reply: asks %zu -> %zu, index %llu -> "
                "%llu; lines %zu\n",
                got ? 1 : 0, holds ? 1 : 0, asks0, asks1, (unsigned long long)idx0, (unsigned long long)idx1, r.n_lines());
    check(r.ok && got && holds, "orphan: setup (a continuation's reply in flight; J holds A's tip)");
    check(asks1 == asks0 && r.n_lines() == 1, "orphan: the owner's end: the page judged, no next FC_GETHEADERS");
}

// pausedefer (E-197 (3); a Defer pauses): C, a full node (its branch 19, journal depth 20), asks A; the P_r of A's tip is
// hidden at C, so the page carrying A's tip DEFERs. 3 s later the P_r is shown and C's follower moves.
//   resumed : the next FC_GETHEADERS (from the waiting requests) from the deferred page's `from`; C reaches A's tip;
//   empty   : A answers that resumed page with no header: the next FC_GETHEADERS P-53 after the resumed page's send.
void pausedefer() {
    for (int mode = 0; mode < 2; ++mode) {
        CmpRig r(false, 19, true);
        const std::uint64_t v0 = pb::PathbNodeTestAccess::verify_calls(r.nc());
        bool shown = false, edit_armed = false;
        int replaced = 0;
        std::uint64_t shown_at = 0;
        r.reply_edit = [&](FakeWire::Msg& m) {
            if (edit_armed && replaced++ == 0) m.f = empty_headers_frame();
        };
        r.connect();
        std::size_t asks_at_show = 0;
        for (int k = 0; k < 40; ++k) {
            r.second();
            if (!shown && r.c.relay->stats().headers_ctx_deferred.load() > 0 && ++shown_at >= 3) {
                shown = true;
                asks_at_show = r.asks.size();
                edit_armed = mode == 1;
                r.hidden.erase(r.a_tip_pr);
                r.c.relay->on_monero_tip();
                r.w.run();
            }
        }
        const bool have = shown && asks_at_show >= 1 && r.asks.size() > asks_at_show;
        const bool same_from = have && r.asks[asks_at_show].second == r.asks[asks_at_show - 1].second;
        const bool done = r.nc().holds_tip(r.a_tip);
        std::uint64_t gap = 0;
        if (mode == 1 && r.asks.size() > asks_at_show + 1) gap = r.asks[asks_at_show + 1].first - r.asks[asks_at_show].first;
        const std::string tag = std::string("pausedefer ") + (mode == 0 ? "resumed" : "empty");
        const std::uint64_t hashed = pb::PathbNodeTestAccess::verify_calls(r.nc()) - v0;
        const std::uint64_t branch = r.h[r.a.node].tree().best().pos - r.f;  // A's headers above F
        std::printf("  %s: deferred %llu; asks %zu (%zu at the P_r shown); the resumed ask from the deferred page's from %d; "
                    "C on A's tip %d; strikes %llu; the next ask %llu s after the resumed one\n",
                    tag.c_str(), (unsigned long long)r.c.relay->stats().headers_ctx_deferred.load(), r.asks.size(),
                    asks_at_show, same_from ? 1 : 0, done ? 1 : 0, (unsigned long long)r.c.relay->stats().strikes.load(),
                    (unsigned long long)gap);
        check(r.ok && shown, tag + ": setup (the page carrying A's tip deferred on its P_r)");
        check(same_from && done && r.c.relay->stats().strikes.load() == 0,
              tag + ": resumed from the deferred page's from; the comparison completes; no token");
        std::printf("  %s: headers hashed %llu for A's %llu above F\n", tag.c_str(), (unsigned long long)hashed,
                    (unsigned long long)branch);
        check(hashed == branch, tag + ": each header hashed once (" + std::to_string(hashed) + " of " + std::to_string(branch) + ")");
        if (mode == 1)
            check(replaced >= 1 && gap >= 11 && gap <= 12,
                  tag + ": the resumed page answered empty: the next ask P-53 after its send (" + std::to_string(gap) + " s)");
    }
}

// pauseorphan (the owner's end; a Defer pauses): pausedefer's shape: C's comparison toward A pauses on the hidden P_r of
// A's tip (the catch-up's deferral). The P_r becomes visible to C's view (no Monero tip event); C receives A's chain from
// another source (C holds A's tip); at C's tick the catch-up ends by its done test; then the Monero tip event: no
// FC_GETHEADERS to A.
void pauseorphan() {
    CmpRig r(false, 19, true);
    r.connect();
    const std::uint64_t pa = r.w.id(r.cw, 0);  // A at C after the reconnect
    bool deferred = false;
    for (int k = 0; k < 20 && !deferred; ++k) {
        r.second();
        deferred = r.c.relay->header_deferred(pa, pb::PathbNode::HeaderOwner::CatchUp) > 0;
    }
    const bool paused = deferred && r.nc().comparison_paused(pa);
    r.hidden.erase(r.a_tip_pr);
    for (std::uint64_t x = r.f + 1; x <= r.h[r.a.node].tree().best().pos; ++x)
        if (const std::optional<pb::Hash32> id = r.h[r.a.node].store().best_at(x))
            (void)r.nc().on_carrier(78, *pb::encode_fc_carrier(0, *r.h[r.a.node].bodies().get(*id), 16));
    const bool holds = r.nc().holds_tip(r.a_tip);
    r.second();  // the tick: the done test ends the catch-up
    const std::size_t asks0 = r.asks.size(), cu = r.c.relay->catchup_peers();
    const std::size_t left = r.c.relay->header_deferred(pa, pb::PathbNode::HeaderOwner::CatchUp);
    r.c.relay->on_monero_tip();  // the P_r's event
    r.w.run();
    for (int k = 0; k < 3; ++k) r.second();
    const std::size_t asks1 = r.asks.size();
    std::printf("  pauseorphan: deferred %d, paused %d; C holds A's tip %d; after the done test: catch-ups %zu, the "
                "catch-up's deferrals %zu; asks %zu -> %zu after the P_r's event; lines %zu\n",
                deferred ? 1 : 0, paused ? 1 : 0, holds ? 1 : 0, cu, left, asks0, asks1, r.n_lines());
    check(r.ok && paused && holds, "pauseorphan: setup (the comparison paused on the P_r; C holds A's tip)");
    check(cu == 0 && asks1 == asks0,
          "pauseorphan: the catch-up ended by its done test: no FC_GETHEADERS when the P_r arrives");
}

// basedropnext (the next round is the catch-up's own locator ask): CmpRig (C a full node, its branch 19, journal depth
// 20; A's 27). A's reply to C's second page is held; C's comparison is forced to keep no ids above F (as for a deep F);
// then the reply: C asks the body of A's tip only and names it the fetch tip; no FC_GETHEADERS from F; the next
// FC_GETHEADERS is the catch-up's own locator ask (its step's point on C's best chain) once the page lapsed (P-53); C
// reaches A's tip.
void basedropnext() {
    CmpRig r(false, 19, false);
    std::vector<std::uint8_t> held;
    r.reply_edit = [&](FakeWire::Msg& m) {
        if (held.empty()) held.swap(m.f);
    };
    std::vector<std::pair<std::uint64_t, std::vector<pb::Hash32>>> bodies;  // C's FC_GETCARRIER to A (time, ids)
    const std::function<void(FakeWire::Msg&)> inner = r.w.edit;
    r.w.edit = [&](FakeWire::Msg& m) {
        if (m.from == r.cw && m.to == 0 && !m.f.empty() && m.f[0] == pb::kOpFcGetCarrier) {
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) bodies.emplace_back(r.h.now, q.ids);
        }
        inner(m);
    };
    r.connect();
    for (int k = 0; k < 3 && held.empty(); ++k) r.second();
    const std::uint64_t pa = r.w.id(r.cw, 0);
    const bool forced = !held.empty() && pb::PathbNodeTestAccess::fold_forget_ids(r.nc(), pa);
    const pb::Hash32 f_id = *r.h[r.a.node].store().best_at(r.f);
    const std::size_t asks0 = r.asks.size(), bodies0 = bodies.size();
    const std::uint64_t t0 = r.h.now;
    r.w.links[r.cw]->frame(pa, held);
    r.c.relay->pump();
    r.w.run();
    const std::optional<pb::PathbRelayNode::CatchupView> cv = r.c.relay->catchup_view(pa);
    const bool tip_named = cv && cv->fetch_tip == r.a_tip;
    const bool tip_only = bodies.size() > bodies0 && bodies[bodies0].second == std::vector<pb::Hash32>{r.a_tip};
    pb::Hash32 locator_at_ask{};  // the catch-up's locator point at its step (catchup_ask_locked)
    for (int k = 0; k < 30; ++k) {
        if (r.asks.size() == asks0)
            if (const std::optional<pb::PathbRelayNode::CatchupView> v = r.c.relay->catchup_view(pa)) {
                const pb::CarrierNode& b = r.nc().tree().best();
                const std::uint64_t root = r.nc().tree().genesis().pos;
                const std::uint64_t back = v->step == 0 ? 0 : std::uint64_t{1} << (v->step - 1);
                const std::uint64_t pos = b.pos > root && b.pos - root > back ? b.pos - back : root;
                locator_at_ask = v->step == 0 ? b.id : r.nc().store().best_at(pos).value_or(r.nc().tree().genesis().id);
            }
        r.second();
    }
    bool from_f = false;
    for (std::size_t i = asks0; i < r.asks.size(); ++i) from_f = from_f || r.asks[i].second == f_id;
    const bool next = r.asks.size() > asks0;
    const std::uint64_t gap = next ? r.asks[asks0].first - t0 : 0;
    const bool locator = next && r.asks[asks0].second == locator_at_ask;
    std::printf("  basedropnext: page 2's reply held %d, the ids dropped %d; the fetch tip is A's tip %d; the first body ask "
                "A's tip only %d; asks after the reply %zu, from F %d; the next ask %llu s after, from the catch-up's locator %d; "
                "C on A's tip %d\n",
                held.empty() ? 0 : 1, forced ? 1 : 0, tip_named ? 1 : 0, tip_only ? 1 : 0, r.asks.size() - asks0,
                from_f ? 1 : 0, (unsigned long long)gap, locator ? 1 : 0, r.nc().holds_tip(r.a_tip) ? 1 : 0);
    check(r.ok && forced, "basedropnext: setup (page 2's reply held; the comparison's ids above F dropped)");
    check(tip_named && tip_only && !from_f,
          "basedropnext: the win stands: the body of A's tip asked, named the fetch tip; no FC_GETHEADERS from F");
    check(locator && gap >= 11 && r.nc().holds_tip(r.a_tip),
          "basedropnext: the next round is the catch-up's own locator ask after P-53; C reaches A's tip");
}

// rxpause (E-113; E-197 (3): a node-internal RandomX failure pauses): CmpRig (C a full node, its branch 19, journal
// depth 20; A's 27). RandomX computes no hash on A's 50th at C (page 2): no token; the comparison pauses; the next
// FC_GETHEADERS is from page 2's `from` (page 1's last header: a resume, not a locator ask), P-53 after page 2's send;
// C reaches A's tip; each header hashed once (the failed call aside).
void rxpause() {
    CmpRig r(false, 19, false);
    const pb::Hash32 armed = *r.h[r.a.node].store().best_at(r.f + 10);
    r.h.nohash_pow.insert(armed);
    const std::uint64_t v0 = pb::PathbNodeTestAccess::verify_calls(r.nc()), n0 = r.h.nohash_calls;
    r.connect();
    const std::uint64_t pa = r.w.id(r.cw, 0);
    std::size_t at_fail = 0;
    bool paused = false;
    for (int k = 0; k < 40; ++k) {
        r.second();
        if (at_fail == 0 && r.h.nohash_calls > n0) {
            at_fail = r.asks.size();
            paused = r.nc().comparison_paused(pa);
        }
    }
    const bool next = at_fail >= 1 && r.asks.size() > at_fail;
    const bool resumed = next && r.asks[at_fail].second == r.asks[at_fail - 1].second;
    const std::uint64_t gap = next ? r.asks[at_fail].first - r.asks[at_fail - 1].first : 0;
    const std::uint64_t hashed = pb::PathbNodeTestAccess::verify_calls(r.nc()) - v0 - (r.h.nohash_calls - n0);
    const std::uint64_t branch = r.h[r.a.node].tree().best().pos - r.f;
    std::printf("  rxpause: RandomX failed %llu; paused %d; the next ask from the failed page's from %d, %llu s after its "
                "send; C on A's tip %d; strikes %llu; headers hashed %llu for A's %llu\n",
                (unsigned long long)(r.h.nohash_calls - n0), paused ? 1 : 0, resumed ? 1 : 0, (unsigned long long)gap,
                r.nc().holds_tip(r.a_tip) ? 1 : 0, (unsigned long long)r.c.relay->stats().strikes.load(),
                (unsigned long long)hashed, (unsigned long long)branch);
    check(r.ok && r.h.nohash_calls - n0 == 1 && paused, "rxpause: setup (RandomX failed on page 2; the comparison paused)");
    check(resumed && gap >= 11 && gap <= 12 && r.c.relay->stats().strikes.load() == 0,
          "rxpause: resumed from the failed page's from P-53 after its send (no locator ask); no token");
    check(r.nc().holds_tip(r.a_tip) && hashed == branch, "rxpause: C reaches A's tip; each header hashed once");
}

// tokenpause (a token ends the peer's paused comparison): emptycont's shape (J a store not caught up, its branch 19;
// A's 27): A answers the comparison's continuation with no header (paused); J's tip request to A is answered with a
// page whose second header's link is broken (STRIKE): the paused comparison ends; the catch-up stays open; its next
// FC_GETHEADERS is its own locator ask (not from the paused page's `from`); J reaches A's tip.
void tokenpause() {
    CmpRig r(true, 19, false);
    int replaced = 0;
    r.reply_edit = [&](FakeWire::Msg& m) {
        if (replaced == 0) m.f = empty_headers_frame();
        else if (replaced == 1) m.f.clear();  // A's reply to the tip request: a page by hand below
        ++replaced;
    };
    r.connect();
    for (int k = 0; k < 3 && replaced == 0; ++k) r.second();
    const std::uint64_t pa = r.w.id(r.cw, 0);
    const bool paused = replaced == 1 && r.nc().comparison_paused(pa);
    const pb::Hash32 paused_from = r.asks.empty() ? pb::Hash32{} : r.asks.back().second;
    const pb::Hash32 from = *r.nc().store().best_at(r.f);
    const bool asked = r.nc().request_headers(pa, from, r.a_tip, 3, r.h.now, pb::PathbNode::HeaderOwner::Tip);
    r.w.run();
    std::vector<pb::CarrierHeader> pg = b_headers(r.h, r.a.node, r.f + 1, r.f + 3);
    pg[1].own.side.tip = pg[0].own.side.tip;  // the second header's parent is not the first: a broken link
    r.w.links[r.cw]->frame(pa, *pb::encode_fc_headers(pb::HeadersReply{0, r.f + 1, pg}, 1u << 22));
    r.c.relay->pump();
    r.w.run();
    const std::uint64_t strikes = r.c.relay->stats().strikes.load();
    const bool ended = !r.nc().comparison_paused(pa);
    const bool open = r.c.relay->catchup_view(pa).has_value() && !r.nc().caught_up();
    const std::size_t asks0 = r.asks.size();
    pb::Hash32 locator_at_ask{};
    for (int k = 0; k < 30; ++k) {
        if (r.asks.size() == asks0)
            if (const std::optional<pb::PathbRelayNode::CatchupView> v = r.c.relay->catchup_view(pa)) {
                const pb::CarrierNode& b = r.nc().tree().best();
                const std::uint64_t root = r.nc().tree().genesis().pos;
                const std::uint64_t back = v->step == 0 ? 0 : std::uint64_t{1} << (v->step - 1);
                const std::uint64_t pos = b.pos > root && b.pos - root > back ? b.pos - back : root;
                locator_at_ask = v->step == 0 ? b.id : r.nc().store().best_at(pos).value_or(r.nc().tree().genesis().id);
            }
        r.second();
    }
    const bool next = r.asks.size() > asks0;
    const bool locator = next && r.asks[asks0].second == locator_at_ask && r.asks[asks0].second != paused_from;
    std::printf("  tokenpause: paused %d; the tip request %d; strikes %llu; the paused comparison ended %d; the catch-up "
                "open %d; the next ask the catch-up's locator ask %d; J on A's tip %d\n",
                paused ? 1 : 0, asked ? 1 : 0, (unsigned long long)strikes, ended ? 1 : 0, open ? 1 : 0, locator ? 1 : 0,
                r.nc().holds_tip(r.a_tip) ? 1 : 0);
    check(r.ok && paused && asked && replaced >= 2, "tokenpause: setup (the comparison paused; the tip request out)");
    check(strikes == 1 && ended && open, "tokenpause: the token ends the paused comparison; the catch-up stays open");
    check(locator && r.nc().holds_tip(r.a_tip), "tokenpause: the next ask is the catch-up's locator ask; J reaches A's tip");
}

// gatekept (E-178, E-194 (vi)): catchheavy's B part. J not caught up (journal depth 4) walked D's chain 1..8; B (A's
// 1, 2 and its own 3: lighter) answers J's catch-up with no header; its tip is handed to the joiner and its attempt
// completes, rule (4) keeping J's chain. A third peer C (its own carrier on position 1) never answers J's FC_GETHEADERS:
// J's catch-up toward it stays open (a claim). Three copies of D's carriers are parked at J's relay (run again 20 s
// later) before the attempt, and a due end of K_NCU is tried only at the tick (test_defer_ends). Reads: after the attempt
// (frames in hand), and after the pump that judged them, before the tick (K_NCU's end due): held in both; the
// kept-attempt line at the tick.
void gatekept() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay d = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.connect(0, 2);
    w.run();
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 4700 + static_cast<std::uint32_t>(i));
    }
    w.links[1]->disconnect(w.id(1, 0));
    w.links[2]->disconnect(w.id(2, 0));
    w.run();
    h.tick_monero();
    ok = ok && mine_on(h, w, b.node, 2, 4800);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, d.node, static_cast<std::size_t>(i % 5), 4900 + static_cast<std::uint32_t>(i));
    }
    const std::uint64_t J = 4;
    const std::size_t jw = h.add(table0(net), false, J, true);
    MemoryKv& kvw = *h.kvs.back();
    std::vector<std::vector<std::uint8_t>> copies;
    for (std::uint64_t x = 1; x <= 8; ++x)
        if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x)) {
            copies.push_back(*pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
            (void)h[jw].on_carrier(77, copies.back());
        }
    h.q.clear();
    const pb::Hash32 own_tip = h[jw].tree().best().id;
    ok = ok && h[jw].tree().best().pos == 8 && !h[jw].caught_up() && h[b.node].tree().best().pos == 3;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net), false, J),
                                  [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; });
    const std::size_t jwire = 3;
    pb::PathbRelayNode& rj = *j.relay;
    rj.test_defer_ends(true);
    KatRelay kc = kat_relay(h, w, table0(net), true);  // wire 4: its own carrier on position 1
    (void)mine_only(h, kc.node, 4, 4990);
    const pb::Hash32 tip_c = h[kc.node].tree().best().id;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    // J's FC_GETHEADERS from a held id to B: its reply carries no header; joiner pages (from the zero id) are served;
    // B's own catch-up toward J gets no reply
    std::deque<bool> asked;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.from == jwire && m.to == 1 && m.f[0] == pb::kOpFcGetHeaders) {
            pb::GetHeaders q;
            if (pb::decode_fc_getheaders(m.f, 0, q).ok()) asked.push_back(q.from != pb::Hash32{});
            return;
        }
        if (m.f[0] != pb::kOpFcHeaders) return;
        if (m.from == jwire || m.from == 4) {  // J's and C's FC_HEADERS: never answered
            m.f.clear();
            return;
        }
        if (m.from != 1 || m.to != jwire || asked.empty()) return;
        const bool catchup = asked.front();
        asked.pop_front();
        if (catchup) m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);
    };
    w.connect(1, jwire);
    w.run();
    w.connect(4, jwire);  // C: J's catch-up toward it stays open (a claim)
    w.run();
    const bool handed = h[j.node].joiner().queue().size() == 1 && !h[j.node].holds_tip(tip_c);
    for (std::size_t k = 0; k < 3; ++k) rj.test_park(w.id(jwire, 1), copies[k], (h.now + 20) * 1000);
    std::optional<pb::JoinStep> st;
    for (int k = 0; k < 40 && !(st && st->report); ++k) {
        st = rj.join_step();
        w.run();
        if (!(st && st->report)) {
            h.now += 1;
            rj.tick();
            w.run();
        }
    }
    const bool kept_attempt = st && st->report && st->report->end == pb::AttemptEnd::Completed && !st->sw.adopted
                              && !st->sw.replaced && h[j.node].tree().best().id == own_tip;
    const bool due = h[j.node].kept_due() && !h[j.node].caught_up() && caught_of(lines, j.node).empty();
    const bool held_in_hand = !h[j.node].drain_done() && !gate_open(h, j.node);
    bool held_window = false, window = false;
    int secs = 0;
    for (; secs < 40 && caught_of(lines, j.node).empty(); ++secs) {
        h.now += 1;
        rj.tick();
        rj.pump();  // the parked frames run at their time; K_NCU's end waits for the tick
        if (h[j.node].drain_done() && h[j.node].kept_due() && !window) {
            window = true;
            held_window = !gate_open(h, j.node);
        }
    }
    h.now += 1;
    rj.tick();
    w.edit = nullptr;
    g_relay_lines = nullptr;
    const std::vector<std::string> cl = caught_of(lines, j.node);
    const std::optional<CaughtLine> c = cl.size() == 1 ? parse_caught(cl[0]) : std::nullopt;
    std::printf("  gatekept: handed %d; the attempt kept J's chain %d; due %d; held in hand %d; the window (drain done, "
                "the end due) seen %d held %d; line %s; caught up %d\n",
                handed ? 1 : 0, kept_attempt ? 1 : 0, due ? 1 : 0, held_in_hand ? 1 : 0, window ? 1 : 0,
                held_window ? 1 : 0, cl.empty() ? "none" : cl[0].c_str(), h[j.node].caught_up() ? 1 : 0);
    check(ok && handed && kept_attempt, "gatekept: setup (B handed over, its attempt completes, J's chain kept)");
    check(due && held_in_hand, "gatekept: the kept attempt with frames in hand: K_NCU's end due, the gate held");
    check(window && held_window, "gatekept: the drain done, K_NCU's end due before the tick: the gate held");
    check(c && c->form == kCaughtJoin && h[j.node].caught_up() && gate_open(h, j.node),
          "gatekept: the kept-attempt line at the tick; K_NCU ended, the gate open");
}

// gatewin (E-194 (vi)): the two windows. A holds 600 positions; J, an empty store not caught up, catches up from A.
//   start  three copies of A's carriers parked at J's relay (run again 20 s later) with J at 300 or more; read right
//          after J places the HELLO tip, before its next tick (the done test not run, the catch-up not erased);
//   end    no frame parked; read right after J places the HELLO tip, before its next tick (the drain done, the done
//          test that ends K_NCU not run).
// The gate held in both; the caught-up line at a later tick.
struct GateWin {
    bool setup = false, in_hand = false, held = false, line_before = false, line_after = false;
};
GateWin gate_win(bool start) {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    GateWin o;
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool mined = true;
    for (std::uint64_t i = 0; i < 600 && mined; ++i) {
        if (i % 12 == 0) h.tick_monero();
        mined = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 52000 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    std::vector<std::vector<std::uint8_t>> copies;
    for (const std::uint64_t x : {100, 200, 300})
        if (const std::optional<pb::Hash32> id = h[a.node].store().best_at(x))
            copies.push_back(*pb::encode_fc_carrier(0, *h[a.node].bodies().get(*id), 16));
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(1, 0);
    bool parked = !start, reached = false;
    for (int secs = 0; secs < 120 && !reached; ++secs) {
        h.now += 1;
        a.relay->tick();
        a.relay->pump();
        rj.tick();
        rj.pump();
        for (int m = 0; m < 100 && !reached; ++m) {
            if (!parked && h[j.node].tree().best().pos >= 300 && copies.size() == 3) {
                for (const auto& f : copies) rj.test_park(w.id(1, 0), f, (h.now + 20) * 1000);
                parked = true;
            }
            reached = h[j.node].holds_tip(tip);
            if (reached || !w.step()) break;
        }
        reached = reached || h[j.node].holds_tip(tip);
    }
    o.setup = mined && parked && reached && copies.size() == 3;
    o.in_hand = !h[j.node].drain_done();
    o.held = !gate_open(h, j.node);
    o.line_before = !caught_of(lines, j.node).empty();
    for (int k = 0; k < 30 && caught_of(lines, j.node).empty(); ++k) {
        h.now += 1;
        rj.tick();
        rj.pump();
    }
    o.line_after = caught_of(lines, j.node).size() == 1 && h[j.node].caught_up() && gate_open(h, j.node);
    g_relay_lines = nullptr;
    return o;
}
void gatewin() {
    for (const bool start : {true, false}) {
        const GateWin o = gate_win(start);
        const std::string name = start ? "gatewin start" : "gatewin end";
        std::printf("  %s: setup %d; at the HELLO tip's placement, before the tick: frames in hand %d, gate held %d, "
                    "line %d; later the line and the gate open %d\n",
                    name.c_str(), o.setup ? 1 : 0, o.in_hand ? 1 : 0, o.held ? 1 : 0, o.line_before ? 1 : 0,
                    o.line_after ? 1 : 0);
        check(o.setup && o.in_hand == start && !o.line_before,
              name + ": setup (the HELLO tip placed, the tick not run; frames in hand " + (start ? "yes)" : "no)"));
        check(o.held, name + ": the gate held before the tick");
        check(o.line_after, name + ": the caught-up line at a later tick, then the gate open");
    }
}

// adoptdrain (E-193): an adoption at a store not caught up waits for the drain. J, an empty store not caught up, meets A
// (8 positions) while a P_r of A's chain is hidden from J: the catch-up DEFERs and A's tip is offered to the joiner
// after kCtxTtlMs. The P_r shown again (no Monero tip event: the catch-up's deferred request waits), a frame of A is
// parked at J's relay (received and not judged; run again 30 s later) and J's attempt completes and adopts: K_NCU
// stays (its record in the adopted store), no template is built and no caught-up line is printed while that frame is
// in hand; once it is judged, K_NCU ends, the record leaves the store and the caught-up line is printed.
void adoptdrain() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 2800 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    const std::optional<pb::Hash32> c1 = h[a.node].store().best_at(1);
    const pb::CarrierBodyV3* b1 = c1 ? h[a.node].bodies().get(*c1) : nullptr;
    const pb::CarrierBodyV3* bt = h[a.node].bodies().get(tip);
    if (!ok || b1 == nullptr || bt == nullptr) {
        check(false, "adoptdrain: setup (A's chain)");
        return;
    }
    const pb::Hash32 X = b1->own.blob.prev_id;
    hidden.insert(X);
    KatRelay j = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                           hide_blocks(hidden, hview), true);
    MemoryKv& kvj = *h.kvs.back();
    const std::string ncu = pb::store_keys::ncu(0);
    pb::PathbRelayNode& rj = *j.relay;
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    w.connect(0, 1);
    w.run();
    for (int k = 0; k < 130 && h[j.node].joiner().queue().size() == 0; ++k) {  // kCtxTtlMs: A's tip offered
        h.now += 5;
        rj.tick();
        w.run();
    }
    const bool offered = h[j.node].joiner().queue().size() == 1 && !h[j.node].caught_up();
    hidden.erase(X);  // the attempt resolves it; the catch-up's deferred request is not asked again before the attempt
    const std::uint64_t until_s = h.now + 30;
    rj.test_park(w.id(1, 0), *pb::encode_fc_carrier(0, *bt, 16), until_s * 1000);  // a frame of A in hand
    std::optional<pb::JoinStep> st;
    for (int k = 0; k < 12 && !(st && st->switched); ++k) {
        st = rj.join_step();
        w.run();
    }
    const bool adopted = st && st->switched && st->sw.adopted && h[j.node].joined() != nullptr;
    const bool kept = !h[j.node].caught_up() && kvj.data.count(ncu) != 0 && rj.parked_size() == 1
                      && caught_of(lines, j.node).empty();
    h.now += 1;
    rj.tick();
    w.run();
    const pb::TemplateStatus s_due = tstatus(h, j.node);
    const bool still = !h[j.node].caught_up() && kvj.data.count(ncu) != 0;
    int secs = 0;
    for (; secs < 60 && !h[j.node].caught_up(); ++secs) {  // the parked frame runs at its time and is judged
        h.now += 1;
        rj.tick();
        w.run();
    }
    const std::vector<std::string> cl = caught_of(lines, j.node);
    g_relay_lines = nullptr;
    const std::optional<CaughtLine> c = cl.size() == 1 ? parse_caught(cl[0]) : std::nullopt;
    std::printf("  adoptdrain: offered %d; adopted %d (J at %llu); K_NCU kept with the frame in hand %d, after a tick %d "
                "(status %d); caught up after %d s, the record %s; parked %zu\n",
                offered ? 1 : 0, adopted ? 1 : 0, (unsigned long long)h[j.node].tree().best().pos, kept ? 1 : 0,
                still ? 1 : 0, static_cast<int>(s_due), secs, kvj.data.count(ncu) == 0 ? "gone" : "kept",
                rj.parked_size());
    std::printf("  adoptdrain: %s\n", cl.empty() ? "no caught-up line" : cl[0].c_str());
    check(offered && adopted, "adoptdrain: setup (J's catch-up DEFERs, A's tip offered; the attempt adopts)");
    check(kept && still && (s_due == pb::TemplateStatus::CatchingUp || s_due == pb::TemplateStatus::RestsOnClaims),
          "adoptdrain: the adoption with a frame received and not judged: K_NCU stays (its record in the adopted store), "
          "no template (status " + std::to_string(static_cast<int>(s_due)) + ")");
    check(h[j.node].caught_up() && kvj.data.count(ncu) == 0 && h.now >= until_s && rj.parked_size() == 0
                  && h[j.node].tree().best().id == tip && rj.stats().strikes.load() == 0 && rj.stats().bans.load() == 0,
          "adoptdrain: the frame judged: K_NCU ends, its record leaves the store; J at A's tip; no token");
    check(c && c->form == kCaughtDone && c->pos == h[j.node].tree().best().pos,
          "adoptdrain: one caught-up line when K_NCU ends, with its \" at pos <n> t=<ms>\" suffix (lines " +
                  std::to_string(cl.size()) + ")");
}

// gateadopt (E-194 (vi)): an adoption hands over to (vi) with no open read in between. adoptdrain's setup (J empty, not
// caught up; its catch-up toward A DEFERs on a hidden P_r; A's tip offered after kCtxTtlMs; the P_r shown again; a
// frame of A parked at J's relay, run again 30 s later) with a third peer C (its own carrier on position 1) whose and
// J's FC_GETHEADERS are never answered: J's catch-up toward C stays open (a claim). A due end of K_NCU is tried only at
// the tick (test_defer_ends). Reads: after the adoption (the frame in hand), and after the pump that judged the frame,
// before the tick (the drain done, K_NCU's end due): held in both; at the tick the caught-up line, K_NCU ended.
void gateadopt() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 2900 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    const std::optional<pb::Hash32> c1 = h[a.node].store().best_at(1);
    const pb::CarrierBodyV3* b1 = c1 ? h[a.node].bodies().get(*c1) : nullptr;
    const pb::CarrierBodyV3* bt = h[a.node].bodies().get(tip);
    if (!ok || b1 == nullptr || bt == nullptr) {
        check(false, "gateadopt: setup (A's chain)");
        return;
    }
    const pb::Hash32 X = b1->own.blob.prev_id;
    hidden.insert(X);
    KatRelay j = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                           hide_blocks(hidden, hview), true);
    KatRelay c = kat_relay(h, w, table0(net), true);  // wire 2
    (void)mine_only(h, c.node, 4, 2990);
    const pb::Hash32 tip_c = h[c.node].tree().best().id;
    pb::PathbRelayNode& rj = *j.relay;
    rj.test_defer_ends(true);
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    w.edit = [](FakeWire::Msg& m) {  // J and C never answer each other's FC_GETHEADERS
        if (!m.f.empty() && m.f[0] == pb::kOpFcHeaders && ((m.from == 1 && m.to == 2) || (m.from == 2 && m.to == 1)))
            m.f.clear();
    };
    w.connect(0, 1);
    w.connect(2, 1);
    w.run();
    for (int k = 0; k < 130 && h[j.node].joiner().queue().size() == 0; ++k) {  // kCtxTtlMs: A's tip offered
        h.now += 5;
        rj.tick();
        w.run();
    }
    const bool offered = h[j.node].joiner().queue().size() == 1 && !h[j.node].caught_up();
    hidden.erase(X);  // the attempt resolves it; the catch-up's deferred request is not asked again before the attempt
    rj.test_park(w.id(1, 0), *pb::encode_fc_carrier(0, *bt, 16), (h.now + 30) * 1000);  // a frame of A in hand
    std::optional<pb::JoinStep> st;
    for (int k = 0; k < 12 && !(st && st->switched); ++k) {
        st = rj.join_step();
        w.run();
    }
    const bool adopted = st && st->switched && st->sw.adopted && h[j.node].joined() != nullptr;
    const bool due = h[j.node].adopt_due() && !h[j.node].caught_up() && caught_of(lines, j.node).empty();
    const bool held_in_hand = !h[j.node].drain_done() && !gate_open(h, j.node);
    const bool claim = !h[j.node].holds_tip(tip_c);
    bool window = false, held_window = false;
    for (int secs = 0; secs < 45 && caught_of(lines, j.node).empty(); ++secs) {
        h.now += 1;
        rj.tick();
        w.run();  // the parked frame runs at its time; K_NCU's end waits for the next tick
        if (!window && h[j.node].drain_done() && h[j.node].adopt_due()) {
            window = true;
            held_window = !gate_open(h, j.node);
        }
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    const std::vector<std::string> cl = caught_of(lines, j.node);
    const std::optional<CaughtLine> cline = cl.size() == 1 ? parse_caught(cl[0]) : std::nullopt;
    std::printf("  gateadopt: offered %d; adopted %d; due %d; held in hand %d; C's claim open %d; the window (drain "
                "done, the end due) seen %d held %d; line %s; caught up %d\n",
                offered ? 1 : 0, adopted ? 1 : 0, due ? 1 : 0, held_in_hand ? 1 : 0, claim ? 1 : 0, window ? 1 : 0,
                held_window ? 1 : 0, cl.empty() ? "none" : cl[0].c_str(), h[j.node].caught_up() ? 1 : 0);
    check(offered && adopted && claim, "gateadopt: setup (A's tip adopted with a frame in hand; C's catch-up open)");
    check(due && held_in_hand, "gateadopt: after the adoption, the frame in hand: K_NCU's end due, the gate held");
    check(window && held_window, "gateadopt: the drain done, K_NCU's end due before the tick: the gate held");
    check(cline && cline->form == kCaughtDone && h[j.node].caught_up() && gate_open(h, j.node),
          "gateadopt: the caught-up line at the tick; K_NCU ended, the gate open");
}

// adoptdefer (an adoption: the catch-ups' deferrals go, a tip request's stay): gateadopt's setup (J empty, not caught
// up; A's tip adopted; C's catch-up open, never answered). Before the adoption J notes a deferral of its catch-up toward
// C and a tip request's toward C, both on a P_r it never holds. After it: the catch-up's deferral gone, the tip
// request's kept; the deferrals' re-run (ungated): the tip request waits to be asked under its owner, no catch-up
// request.
void adoptdefer() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 2900 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    const std::optional<pb::Hash32> c1 = h[a.node].store().best_at(1);
    const pb::CarrierBodyV3* b1 = c1 ? h[a.node].bodies().get(*c1) : nullptr;
    const pb::CarrierBodyV3* bt = h[a.node].bodies().get(tip);
    if (!ok || b1 == nullptr || bt == nullptr) {
        check(false, "adoptdefer: setup (A's chain)");
        return;
    }
    const pb::Hash32 X = b1->own.blob.prev_id;
    hidden.insert(X);
    KatRelay j = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                           hide_blocks(hidden, hview), true);
    KatRelay c = kat_relay(h, w, table0(net), true);  // wire 2
    (void)mine_only(h, c.node, 4, 2990);
    const pb::Hash32 tip_c = h[c.node].tree().best().id;
    pb::PathbRelayNode& rj = *j.relay;
    w.edit = [](FakeWire::Msg& m) {  // J and C never answer each other's FC_GETHEADERS
        if (!m.f.empty() && m.f[0] == pb::kOpFcHeaders && ((m.from == 1 && m.to == 2) || (m.from == 2 && m.to == 1)))
            m.f.clear();
    };
    w.connect(0, 1);
    w.connect(2, 1);
    w.run();
    for (int k = 0; k < 130 && h[j.node].joiner().queue().size() == 0; ++k) {  // kCtxTtlMs: A's tip offered
        h.now += 5;
        rj.tick();
        w.run();
    }
    hidden.erase(X);
    const std::uint64_t pc = w.id(1, 2);
    pb::Hash32 never{};
    never[0] = 0xd5;
    never[1] = 0x5d;
    rj.test_defer_headers(pc, pb::PathbNode::HeaderOwner::CatchUp, tip, tip_c, never);
    rj.test_defer_headers(pc, pb::PathbNode::HeaderOwner::Tip, tip, tip_c, never);
    const bool both = rj.header_deferred(pc, pb::PathbNode::HeaderOwner::CatchUp) == 1
                      && rj.header_deferred(pc, pb::PathbNode::HeaderOwner::Tip) == 1;
    std::optional<pb::JoinStep> st;
    for (int k = 0; k < 12 && !(st && st->switched); ++k) {
        st = rj.join_step();
        w.run();
    }
    const bool adopted = st && st->switched && st->sw.adopted && h[j.node].joined() != nullptr;
    const std::size_t cu_def = rj.header_deferred(pc, pb::PathbNode::HeaderOwner::CatchUp);
    const std::size_t tip_def = rj.header_deferred(pc, pb::PathbNode::HeaderOwner::Tip);
    rj.test_rerun(pb::Missing::MoneroBlock);  // the deferrals asked again (ungated)
    w.run();
    const std::size_t cu_wait = rj.header_waiting(pc, pb::PathbNode::HeaderOwner::CatchUp);
    const std::size_t tip_wait = rj.header_waiting(pc, pb::PathbNode::HeaderOwner::Tip);
    w.edit = nullptr;
    std::printf("  adoptdefer: both deferrals noted %d; adopted %d; after the adoption: the catch-up's deferrals %zu, the "
                "tip request's %zu; after the re-run: waiting catch-up requests %zu, tip requests %zu\n",
                both ? 1 : 0, adopted ? 1 : 0, cu_def, tip_def, cu_wait, tip_wait);
    check(both && adopted, "adoptdefer: setup (both deferrals noted; A's tip adopted)");
    check(cu_def == 0 && tip_def == 1, "adoptdefer: the adoption drops the catch-up's deferral, the tip request's stays");
    check(cu_wait == 0 && tip_wait == 1, "adoptdefer: the tip request asked again under its owner; no catch-up request");
}

// adoptresume (a paused comparison's resume, P-53 after the paused page's send, from its last checked header):
//   adoption    : J (journal depth 4; the shared 2, then its own 10) asks C (the shared 2, then its own 10; the P_r of
//                 C's position 6 hidden at J): the comparison pauses on it (page 2), a catch-up deferral. The P_r is then
//                 shown to J's view with no Monero tip event, the stand-in for an input that never arrives: the deferral
//                 is never asked again. A (the shared 2, then its own 14) wins at J below J's base: JoinerPath, the
//                 attempt Completed, adopted. J's catch-up toward C restarts: page 1, its continuation answered with no
//                 header (paused, no catch-up deferral left); the next FC_GETHEADERS to C: from page 1's last header,
//                 P-53 after that page's send.
//   seed pruned : C (journal depth 20, body_keep 5) and A share 40; C mines 1,200 of its own, A 1,208; the P_r of A's 41st
//                 (page 3 of C's comparison from its root) hidden at C. The comparison pauses on it; 15 s later C prunes
//                 (the seed, its root, no longer held) and the P_r is shown: the deferral's re-ask is dropped (its seed
//                 not held); the resume at the next tick, from the paused page's `from`; the comparison runs to its
//                 decision (JoinerPath at 40).
void adoptresume() {
    {
        const KatNet net;
        Harness h(net);
        FakeWire w;
        std::set<pb::Hash32> hidden;
        const HiddenRows hrows(net.rows, hidden);
        const pb::FollowerBranchView hview(hrows);
        KatRelay a = kat_relay(h, w, table0(net), true);  // wire 0
        KatRelay j = kat_relay(h, w, table0(net), false, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; },
                               [](pb::PathbNodeConfig& cf) { cf.journal_depth = 4; }, hide_blocks(hidden, hview));  // wire 1
        KatRelay c = kat_relay(h, w, table0(net), false);  // wire 2
        w.connect(0, 1);
        w.connect(0, 2);
        w.run();
        bool ok = true;
        std::uint32_t nonce = 67000;
        for (int i = 0; i < 2 && ok; ++i) {
            h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        ok = ok && h[j.node].tree().best().id == h[a.node].tree().best().id
             && h[c.node].tree().best().id == h[a.node].tree().best().id;
        w.links[1]->disconnect(w.id(1, 0));
        w.links[2]->disconnect(w.id(2, 0));
        w.run();
        for (int i = 0; i < 10 && ok; ++i) {
            h.tick_monero();
            ok = mine_on(h, w, j.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        for (int i = 0; i < 14 && ok; ++i) {
            h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        for (int i = 0; i < 10 && ok; ++i) {
            h.tick_monero();
            ok = mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        const pb::Hash32 a_tip = h[a.node].tree().best().id;
        // the P_r of C's position 6 (page 2 of J's comparison from its root): A's chain names it too (the KAT's P_r
        // follows the position); it is shown to J's view before A's chain arrives, with no Monero tip event, so the
        // catch-up's deferral toward C is never asked again
        const std::optional<pb::Hash32> c6 = h[c.node].store().best_at(6);
        const pb::Hash32 c_pr = c6 ? h[c.node].bodies().get(*c6)->own.blob.prev_id : pb::Hash32{};
        ok = ok && c6 && h[j.node].tree().best().pos == 12 && h[c.node].tree().best().pos == 12
             && h[a.node].tree().best().pos == 16;
        hidden.insert(c_pr);
        std::vector<std::pair<std::uint64_t, pb::Hash32>> asks;  // J's FC_GETHEADERS to C (time, from)
        bool armed = false;
        int seen = 0;
        std::size_t paused_ask = 0;
        w.edit = [&](FakeWire::Msg& m) {
            if (m.f.empty()) return;
            if (m.from == 1 && m.to == 2 && m.f[0] == pb::kOpFcGetHeaders) {
                pb::GetHeaders q;
                if (pb::decode_fc_getheaders(m.f, 0, q).ok()) asks.emplace_back(h.now, q.from);
                return;
            }
            if (!armed || m.from != 2 || m.to != 1 || m.f[0] != pb::kOpFcHeaders) return;
            if (seen == 1) {  // the restarted comparison's continuation: no header
                m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);
                paused_ask = asks.size();
                ++seen;
            } else if (seen == 0 && m.f.size() > 100) {
                ++seen;  // its page 1
            }
        };
        const auto second = [&] {
            h.now += 1;
            for (pb::PathbRelayNode* x : w.relays) x->tick();
            for (pb::PathbRelayNode* x : w.relays) x->pump();
            for (int m = 0; m < 400 && w.step(); ++m) {
            }
            for (int m = 0; m < 4; ++m)
                if (const std::optional<pb::JoinStep> st = j.relay->join_step(); !st) break;
            w.run();
        };
        w.connect(2, 1);
        w.run();
        const std::uint64_t pc = w.id(1, 2);
        bool paused0 = false;
        for (int k = 0; k < 10 && !paused0; ++k) {
            second();
            paused0 = h[j.node].comparison_paused(pc) && j.relay->header_deferred(pc, pb::PathbNode::HeaderOwner::CatchUp) == 1;
        }
        hidden.erase(c_pr);
        w.reconnect(0, 1);
        w.run();
        bool adopted = false;
        for (int k = 0; k < 30 && !adopted; ++k) {
            second();
            adopted = h[j.node].joined() != nullptr && h[j.node].holds_tip(a_tip);
        }
        armed = true;
        bool paused1 = false, ungated = false;
        for (int k = 0; k < 30; ++k) {
            second();
            if (!paused1 && seen == 2 && h[j.node].comparison_paused(pc)) {
                paused1 = true;
                ungated = j.relay->header_deferred(pc, pb::PathbNode::HeaderOwner::CatchUp) == 0;
            }
        }
        w.edit = nullptr;
        const bool next = paused_ask >= 1 && asks.size() > paused_ask;
        const bool from_last = next && asks[paused_ask].second == asks[paused_ask - 1].second;
        const std::uint64_t gap = next ? asks[paused_ask].first - asks[paused_ask - 1].first : 0;
        std::printf("  adoptresume adoption: paused on the hidden P_r with a catch-up deferral %d; adopted %d; the restarted "
                    "comparison paused %d, no catch-up deferral %d; the next ask from the paused page's from %d, %llu s after "
                    "its send\n",
                    paused0 ? 1 : 0, adopted ? 1 : 0, paused1 ? 1 : 0, ungated ? 1 : 0, from_last ? 1 : 0,
                    (unsigned long long)gap);
        check(ok && paused0 && adopted,
              "adoptresume adoption: setup (paused on a hidden P_r, shown with no Monero tip event; A's tip adopted)");
        check(paused1 && ungated, "adoptresume adoption: the restarted comparison paused; no catch-up deferral");
        check(from_last && gap >= 11 && gap <= 12,
              "adoptresume adoption: resumed P-53 after the paused page's send, from its last checked header (" +
                      std::to_string(gap) + " s)");
    }
    {
        const KatNet net;
        Harness h(net);
        FakeWire w;
        std::set<pb::Hash32> hidden;
        const HiddenRows hrows(net.rows, hidden);
        const pb::FollowerBranchView hview(hrows);
        KatRelay a = kat_relay(h, w, table0(net), true);  // wire 0
        KatRelay c = kat_relay(h, w, table0(net), true, false, [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; },
                               [](pb::PathbNodeConfig& cf) {
                                   cf.journal_depth = 20;
                                   cf.body_keep = 5;
                               },
                               hide_blocks(hidden, hview));  // wire 1
        std::map<std::size_t, std::vector<std::string>> lines;
        g_relay_lines = &lines;
        w.connect(0, 1);
        w.run();
        bool ok = true;
        std::uint32_t nonce = 68000;
        for (int i = 0; i < 40 && ok; ++i) {
            if (i % 12 == 0) h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        w.links[1]->disconnect(w.id(1, 0));
        w.run();
        for (int i = 0; i < 1200 && ok; ++i) {
            if (i % 12 == 0) h.tick_monero();
            ok = mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        for (int i = 0; i < 1208 && ok; ++i) {
            if (i % 12 == 0) h.tick_monero();
            ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
        }
        const std::optional<pb::Hash32> a41 = h[a.node].store().best_at(41);
        const pb::Hash32 pr = a41 ? h[a.node].bodies().get(*a41)->own.blob.prev_id : pb::Hash32{};
        hidden.insert(pr);
        const pb::Hash32 seed = h[c.node].tree().genesis().id;
        std::vector<std::pair<std::uint64_t, pb::Hash32>> asks;  // C's FC_GETHEADERS to A (time, from)
        w.edit = [&](FakeWire::Msg& m) {
            if (m.from == 1 && m.to == 0 && !m.f.empty() && m.f[0] == pb::kOpFcGetHeaders) {
                pb::GetHeaders q;
                if (pb::decode_fc_getheaders(m.f, 0, q).ok()) asks.emplace_back(h.now, q.from);
            }
        };
        const auto second = [&] {
            h.now += 1;
            a.relay->tick();
            c.relay->tick();
            a.relay->pump();
            c.relay->pump();
            for (int m = 0; m < 400 && w.step(); ++m) {
            }
            for (int m = 0; m < 4; ++m)
                if (const std::optional<pb::JoinStep> st = c.relay->join_step(); !st) break;
            w.run();
        };
        w.reconnect(0, 1);
        w.run();
        const std::uint64_t pa = w.id(1, 0);
        bool paused = false;
        for (int k = 0; k < 10 && !paused; ++k) {
            second();
            paused = h[c.node].comparison_paused(pa) && c.relay->header_deferred(pa, pb::PathbNode::HeaderOwner::CatchUp) == 1;
        }
        const std::size_t asks0 = asks.size();
        const pb::Hash32 paused_from = asks.empty() ? pb::Hash32{} : asks.back().second;
        for (int k = 0; k < 15; ++k) second();
        (void)h[c.node].prune(h.now);
        const bool pruned = h[c.node].tree().find(seed) == nullptr;
        const std::uint64_t root = h[c.node].tree().genesis().pos;
        const std::size_t reasks0 = c.relay->stats().headers_ctx_reasks.load();
        hidden.erase(pr);
        c.relay->on_monero_tip();
        w.run();
        const bool dropped = c.relay->header_deferred(pa, pb::PathbNode::HeaderOwner::CatchUp) == 0
                             && c.relay->stats().headers_ctx_reasks.load() == reasks0 && asks.size() == asks0
                             && h[c.node].comparison_paused(pa);
        second();  // the next tick
        const bool resumed = asks.size() > asks0 && asks[asks0].second == paused_from;
        for (int k = 0; k < 60; ++k) second();
        g_relay_lines = nullptr;
        w.edit = nullptr;
        std::size_t jp = 0;
        for (const std::string& l : lines[c.node])
            if (l.find("win; fork at 40 ") != std::string::npos) ++jp;
        std::printf("  adoptresume seed pruned: paused %d; asks to the pause %zu; pruned %d (root %llu); the re-ask dropped "
                    "%d; resumed at the next tick from the paused page's from %d; the decision's JoinerPath line (fork 40) "
                    "%zu\n",
                    paused ? 1 : 0, asks0, pruned ? 1 : 0, (unsigned long long)root,
                    dropped ? 1 : 0, resumed ? 1 : 0, jp);
        check(ok && paused && pruned, "adoptresume seed pruned: setup (paused on the hidden P_r; the seed pruned)");
        check(dropped && resumed,
              "adoptresume seed pruned: the re-ask dropped (seed not held); the resume at the next tick from the paused "
              "page's from");
        check(jp == 1, "adoptresume seed pruned: the comparison reaches its decision (JoinerPath at 40)");
    }
}

// e185mark (an empty reply to a request from position 0 at a node that pruned meanwhile): A and C (journal depth 20,
// body_keep 5) share 1,175 (F); C, cut off, mines 24 of its own, A 20 (lighter; C's headers and carriers do not reach
// A). C reconnects unpruned; A's replies to C's catch-up carry no header (the locator walks to position 0); C prunes (its
// first prune) before the reply to its request from position 0 arrives: A's tip a root-evidence pair; its attempt
// checks the branch's work from F from C's records (its root <= F < its base): A lighter, OutOfScope, no token; C's
// chain kept.
void e185mark() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);  // wire 0
    KatRelay c = kat_relay(h, w, table0(net), true, false, [](pb::PathbRelayOptions& r) { r.join_min_peers = 1; },
                           [](pb::PathbNodeConfig& cf) {
                               cf.journal_depth = 20;
                               cf.body_keep = 5;
                           });  // wire 1
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    w.connect(0, 1);
    w.run();
    bool ok = true;
    std::uint32_t nonce = 70000;
    for (std::uint64_t i = 0; i < 1175 && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    ok = ok && h[c.node].tree().best().id == h[a.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    for (std::uint64_t i = 0; i < 24 && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, c.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    for (std::uint64_t i = 0; i < 20 && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), nonce++);
    }
    const pb::Hash32 a_tip = h[a.node].tree().best().id, c_tip = h[c.node].tree().best().id;
    const pb::Hash32 g0 = h[c.node].tree().genesis().id;
    const bool unpruned = h[c.node].tree().genesis().pos == 0;
    bool editing = true, asked0 = false;
    std::vector<std::uint8_t> held;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        // A keeps its lighter chain: C's headers and carriers do not reach A
        if (m.from == 1 && m.to == 0 && (m.f[0] == pb::kOpFcHeaders || m.f[0] == pb::kOpFcCarrier)) {
            m.f.clear();
            return;
        }
        if (!editing) return;
        if (m.from == 1 && m.to == 0 && m.f[0] == pb::kOpFcGetHeaders) {
            pb::GetHeaders q;
            if (pb::decode_fc_getheaders(m.f, 0, q).ok() && q.from == g0) asked0 = true;
            return;
        }
        if (m.from == 0 && m.to == 1 && m.f[0] == pb::kOpFcHeaders) {
            if (asked0 && held.empty()) {  // the reply to the request from position 0: held back
                held = empty_headers_frame();
                m.f.clear();
                return;
            }
            m.f = empty_headers_frame();
        }
    };
    const auto step = [&](bool join) {
        h.now += 1;
        a.relay->tick();
        c.relay->tick();
        a.relay->pump();
        c.relay->pump();
        for (int m = 0; m < 400 && w.step(); ++m) {
        }
        if (join)
            for (int m = 0; m < 4; ++m)
                if (const std::optional<pb::JoinStep> st = c.relay->join_step(); !st) break;
        w.run();
    };
    w.reconnect(0, 1);
    w.run();
    const std::uint64_t pa = w.id(1, 0);
    for (int k = 0; k < 20 && held.empty(); ++k) step(false);
    const pb::PathbNode::PruneReport pr = h[c.node].prune(h.now);
    const bool pruned = h[c.node].pruned_full_node();
    editing = false;
    if (!held.empty()) {
        w.links[1]->frame(pa, held);
        c.relay->pump();
        w.run();
    }
    bool marked = false;
    for (const pb::AttemptQueue::Pair& q : h[c.node].joiner().queue().pairs())
        if (q.candidate == a_tip && q.server == pa) marked = q.root_evidence;
    for (int k = 0; k < 10; ++k) step(true);
    int attempts = 0;
    bool w_out = false;
    std::string end;
    for (const std::string& l : lines[c.node])
        if (l.find("relay: join attempt at peer") != std::string::npos) {
            ++attempts;
            w_out = w_out || (l.find("OutOfScope") != std::string::npos && l.find("E-78's condition") != std::string::npos);
            end = l.substr(l.find(':') + 2, 160);
        }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    const bool kept = h[c.node].tree().best().id == c_tip;
    const std::uint64_t strikes = c.relay->stats().strikes.load();
    std::printf("  e185mark: setup %d; unpruned at the request from position 0 %d, pruned before its reply %d (root %llu); "
                "A's tip marked %d; attempts %d, OutOfScope by the work check %d; strikes %llu; C's chain kept %d [%s]\n",
                ok ? 1 : 0, unpruned ? 1 : 0, pruned ? 1 : 0, (unsigned long long)pr.root, marked ? 1 : 0, attempts,
                w_out ? 1 : 0, (unsigned long long)strikes, kept ? 1 : 0, end.c_str());
    check(ok && unpruned && !held.empty() && pruned,
          "e185mark: setup (C unpruned at its request from position 0, pruned before the reply)");
    check(marked, "e185mark: the reply with no header from position 0 at a node pruned meanwhile: A's tip a root-evidence pair");
    check(attempts == 1 && w_out && strikes == 0 && kept,
          "e185mark: its attempt checks the branch's work from F (A lighter): OutOfScope, no token; C's chain kept");
}

// rootevidneg (the offer at a pruned full node's root reply leaves no live pair): rootevid's shape, A excluded at C2's
// joiner before C2 meets A: no root-evidence line; the catch-up ends by its reply (the caught-up line); no attempt.
void rootevidneg() {
    PrunedRestart r(40, 1200, 1208, 0);
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    r.w.connect(0, 2);
    const std::uint64_t pa = r.w.id(2, 0);
    pb::PathbNodeTestAccess::exclude_server(r.h[r.c2.node], pa);
    const bool excluded = r.h[r.c2.node].joiner().queue().excluded(pa);
    r.w.run();
    for (int k = 0; k < 15; ++k) r.second(true);
    std::size_t re = 0;
    int attempts = 0;
    for (const std::string& l : lines[r.c2.node]) {
        if (l.find("(root evidence)") != std::string::npos) ++re;
        if (l.find("relay: join attempt at peer") != std::string::npos) ++attempts;
    }
    const std::size_t caught = caught_of(lines, r.c2.node).size();
    const bool ended = !r.c2.relay->catchup_view(pa).has_value();
    g_relay_lines = nullptr;
    std::printf("  rootevidneg: setup %d (root %llu); A excluded %d; root-evidence lines %zu; the catch-up ended %d, "
                "caught-up lines %zu; attempts %d\n",
                r.ok ? 1 : 0, (unsigned long long)r.root, excluded ? 1 : 0, re, ended ? 1 : 0, caught, attempts);
    check(r.ok && excluded, "rootevidneg: setup (C2 a pruned full node, not caught up; A excluded at its joiner)");
    check(re == 0 && ended && caught == 1 && attempts == 0,
          "rootevidneg: no live pair: no root-evidence line; the catch-up ended by its reply; no attempt");
}

// catchoffer: a store not caught up (journal depth 4) that walked A's chain to position 8 is offered B's unheld lighter
// tip (B's branch: A's 1, 2 and its own 3; the fork below the node's journal base 4): offer_empty_store_tip queues one
// pair; its one attempt completes and rule (4) keeps the node's chain (its own chain is A), which ends K_NCU; no pair
// is queued again. Restarted from its store with no peer, it builds templates; a HELLO opens no first round.
void catchoffer() {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(table0(net), true);
    const std::size_t b = h.add(table0(net), true);
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        h.mine(a, static_cast<std::size_t>(i), 3600 + static_cast<std::uint32_t>(i));
    }
    const bool shared = h[b].tree().best().id == h[a].tree().best().id;
    h.cut.insert({a, b});
    h.cut.insert({b, a});
    h.tick_monero();
    h.mine(b, 2, 3700);  // B's own carrier at 3
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(a, static_cast<std::size_t>(i % 5), 3800 + static_cast<std::uint32_t>(i));
    }
    const std::uint64_t J = 4;
    const std::size_t jn = h.add(table0(net), false, J, true);  // started empty, not launched: K_NCU
    MemoryKv& kvj = *h.kvs.back();
    for (std::uint64_t x = 1; x <= 8; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
            (void)h[jn].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
    h.q.clear();
    const pb::Hash32 own_tip = h[jn].tree().best().id;
    const pb::Hash32 tip_b = h[b].tree().best().id;
    const bool walked = h[jn].tree().best().pos == 8 && own_tip == h[a].store().best_tip() && !h[jn].caught_up()
                        && kvj.data.count(pb::store_keys::ncu(0)) != 0 && h[b].tree().best().pos == 3
                        && h[jn].store().base_pos() > 2;
    const bool lighter = ::c2pool::xmr::native::u128_greater(h[jn].tree().best().cum_work, h[b].tree().best().cum_work);
    KatTransport tr(h, jn);
    h[jn].set_join_transport(&tr);
    const pb::HelloCheck hc = h.hello(jn, b);
    const bool unheld = !h[jn].holds_tip(tip_b);
    const bool offered = h[jn].offer_empty_store_tip(b);
    const std::size_t queued = h[jn].joiner().queue().size();
    const pb::JoinStep st = h[jn].run_join();
    const bool again = h[jn].offer_empty_store_tip(b);
    std::printf("  catchoffer: J at %llu (base %llu), B at %llu; offered %d; the attempt %s; J's best kept %d; offered "
                "again %d\n",
                (unsigned long long)h[jn].tree().best().pos, (unsigned long long)h[jn].store().base_pos(),
                (unsigned long long)h[b].tree().best().pos, offered ? 1 : 0,
                st.report ? pb::attempt_end_name(st.report->end) : "none", h[jn].tree().best().id == own_tip ? 1 : 0,
                again ? 1 : 0);
    check(shared && walked && lighter && hc.verdict == pb::HelloVerdict::Accept && unheld,
          "catchoffer: setup (J walked A's 1..8, not caught up, its base above the fork; B's tip 3 lighter and not held "
          "at J)");
    check(offered && queued == 1,
          "catchoffer: B's unheld lighter tip offered to the joiner: one pair queued (" + std::to_string(queued) + ")");
    check(st.report && st.report->end == pb::AttemptEnd::Completed && !st.sw.replaced && !st.sw.adopted && !st.switched
                  && h[jn].tree().best().id == own_tip && h[jn].joined() == nullptr && !again
                  && h[jn].joiner().queue().size() == 0,
          "catchoffer: the one attempt completes and rule (4) keeps J's chain; the pair is not queued again" +
                  (st.report ? std::string(": ") + rep_desc(*st.report) : std::string(": no attempt")));
    // the completed attempt that rule (4) did not take ends K_NCU: no record; with no peer, and after a restart, no
    // NoPathbPeer and no first round
    const bool ended = st.caught_up && h[jn].caught_up() && kvj.data.count(pb::store_keys::ncu(0)) == 0;
    const std::size_t jr = load_node(h, kvj, h.config(table0(net), false, J));
    const pb::TemplateStatus s_restart = tstatus(h, jr);
    const pb::HelloCheck hr = h.hello(jr, b);
    const pb::TemplateStatus s_hello = tstatus(h, jr);
    std::printf("  catchoffer: K_NCU ended %d; restarted: caught up %d, templates %d with no peer, %d after B's HELLO; "
                "first round %d\n",
                ended ? 1 : 0, h[jr].caught_up() ? 1 : 0, static_cast<int>(s_restart), static_cast<int>(s_hello),
                h[jr].first_round_open() ? 1 : 0);
    check(ended && h[jr].caught_up() && s_restart != pb::TemplateStatus::NoPathbPeer
                  && s_restart != pb::TemplateStatus::CatchingUp && hr.verdict == pb::HelloVerdict::Accept
                  && !h[jr].first_round_open() && s_hello != pb::TemplateStatus::CatchingUp,
          "catchoffer: the completed attempt that rule (4) did not take ends K_NCU: the record gone; restarted with no "
          "peer, templates; a HELLO opens no first round");
}

// ---------------------------------------------------------------------------
// revcatchundec: catchkeep's setup, but B's FC_HEADERS replies to J arrive truncated (undecodable). The catch-up toward
// B's unheld tip ends by that reply (K::Undecodable, a STRIKE token): the store not caught up becomes caught up (the
// record leaves), its chain is kept, and with no peer it builds templates.
void revcatchundec() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    Branches br = branches(h, w, net, 4, 1, 2, 3150);
    const std::size_t b = br.b.node;
    const std::size_t a = br.a.node;
    const pb::Hash32 tip_a = h[a].tree().best().id;
    const std::size_t jw = h.add(table0(net), false, 1152, true);  // started empty, not launched: K_NCU
    MemoryKv& kvw = *h.kvs.back();
    for (std::uint64_t x = 1; x <= 6; ++x)
        if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
            (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
    h.q.clear();
    const std::string ncu = pb::store_keys::ncu(0);
    const bool walked = h[jw].tree().best().id == tip_a && !h[jw].caught_up() && kvw.data.count(ncu) != 0;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
    MemoryKv& kvj = *h.kvs.back();
    const pb::TemplateStatus s0 = tstatus(h, j.node);
    std::uint64_t truncated = 0;
    w.edit = [&truncated](FakeWire::Msg& m) {
        if (m.from == 2 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders) m.f.clear();  // B gets no reply
        if (m.from == 1 && m.to == 2 && m.f.size() > 8 && m.f[0] == pb::kOpFcHeaders) {           // J gets a broken one
            m.f.resize(m.f.size() - 3);
            ++truncated;
        }
    };
    w.connect(1, 2);
    w.run();
    const std::uint64_t asks = j.relay->stats().catchup_requests.load();
    const std::uint64_t strikes = j.relay->stats().strikes.load();
    const bool caught = h[j.node].caught_up() && kvj.data.count(ncu) == 0 && !h[j.node].first_round_open();
    const bool kept = h[j.node].tree().best().id == tip_a;
    w.links[2]->disconnect(w.id(2, 1));
    w.run();
    w.edit = nullptr;
    const pb::TemplateStatus s1 = tstatus(h, j.node);
    std::printf("  revcatchundec: J at %llu (B at %llu); truncated %llu; catch-up asks %llu; strikes %llu; caught up %d; "
                "templates %d -> %d\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[b].tree().best().pos,
                (unsigned long long)truncated, (unsigned long long)asks, (unsigned long long)strikes, caught ? 1 : 0,
                static_cast<int>(s0), static_cast<int>(s1));
    check(br.ok && walked && s0 == pb::TemplateStatus::NoPathbPeer && truncated >= 1,
          "revcatchundec: setup (J not caught up at A's tip 6; B's reply truncated)");
    check(kept && caught && strikes >= 1 && s1 != pb::TemplateStatus::NoPathbPeer && s1 != pb::TemplateStatus::CatchingUp,
          "revcatchundec: the catch-up ended by an undecodable reply (STRIKE) leaves the store caught up, chain kept");
}


// ---------------------------------------------------------------------------
// catchtok: catchkeep's setup, the catch-up toward B's unheld lighter tip ended by a reply that strikes or bans:
//   strike  B holds 4 shared and its own 5, 6; J at A's tip 7; B's reply 4, 5, 6 reaches J as 4, 6 (a link broken
//           inside the reply): STRIKE;
//   ban     B holds 4 shared and its own 5, which fails its PoW at d at J: BAN.
// Either way the store not caught up becomes caught up (the record leaves), its chain is kept, and with no peer it
// builds templates.
void catchtok() {
    const KatNet net;
    for (const bool ban : {false, true}) {
        const std::string tag = ban ? "catchtok (ban): " : "catchtok (strike): ";
        Harness h(net);
        FakeWire w;
        Branches br = ban ? branches(h, w, net, 4, 1, 2, 3260) : branches(h, w, net, 4, 2, 3, 3270);
        const std::size_t a = br.a.node, b = br.b.node;
        const pb::Hash32 tip_a = h[a].tree().best().id;
        const std::uint64_t top = h[a].tree().best().pos;
        const std::size_t jw = h.add(table0(net), false, 1152, true);  // started empty, not launched: K_NCU
        MemoryKv& kvw = *h.kvs.back();
        for (std::uint64_t x = 1; x <= top; ++x)
            if (const std::optional<pb::Hash32> id = h[a].store().best_at(x))
                (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[a].bodies().get(*id), 16));
        h.q.clear();
        const std::string ncu = pb::store_keys::ncu(0);
        const bool walked = h[jw].tree().best().id == tip_a && !h[jw].caught_up() && kvw.data.count(ncu) != 0;
        KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net)));
        MemoryKv& kvj = *h.kvs.back();
        const pb::TemplateStatus s0 = tstatus(h, j.node);
        if (ban) h.bad_pow.insert(h[b].tree().best().id);
        std::uint64_t edited = 0;
        w.edit = [ban, &edited](FakeWire::Msg& m) {
            if (m.f.empty() || m.f[0] != pb::kOpFcHeaders) return;
            if (m.from == 2 && m.to == 1) m.f.clear();  // B's own catch-up toward J gets no reply
            if (ban || m.from != 1 || m.to != 2) return;
            pb::HeadersReply rep;
            if (!pb::decode_fc_headers(m.f, 0, 1u << 22, pb::kRuledLaneParams, rep).ok() || rep.headers.size() < 3) return;
            rep.headers.erase(rep.headers.begin() + 1);
            m.f = *pb::encode_fc_headers(rep, 1u << 22);
            ++edited;
        };
        w.connect(1, 2);
        w.run();
        const pb::PathbRelayStats& st = j.relay->stats();
        const std::uint64_t asks = st.catchup_requests.load(), strikes = st.strikes.load(), bans = st.bans.load();
        const bool caught = h[j.node].caught_up() && kvj.data.count(ncu) == 0 && !h[j.node].first_round_open();
        const bool kept = h[j.node].tree().best().id == tip_a;
        if (w.links[2]->live.count(w.id(2, 1)) != 0) w.links[2]->disconnect(w.id(2, 1));
        w.run();
        w.edit = nullptr;
        const pb::TemplateStatus s1 = tstatus(h, j.node);
        std::printf("  %sJ at %llu (B at %llu); edited %llu; catch-up asks %llu; strikes %llu; bans %llu; caught up %d; "
                    "templates %d -> %d\n",
                    tag.c_str(), (unsigned long long)h[j.node].tree().best().pos,
                    (unsigned long long)h[b].tree().best().pos, (unsigned long long)edited, (unsigned long long)asks,
                    (unsigned long long)strikes, (unsigned long long)bans, caught ? 1 : 0, static_cast<int>(s0),
                    static_cast<int>(s1));
        check(br.ok && walked && s0 == pb::TemplateStatus::NoPathbPeer && (ban || edited >= 1),
              tag + "setup (J not caught up at A's tip; B's tip lighter and not held at J)");
        check(kept && caught && (ban ? bans >= 1 : strikes >= 1 && bans == 0) && s1 != pb::TemplateStatus::NoPathbPeer
                      && s1 != pb::TemplateStatus::CatchingUp,
              tag + "the catch-up ended by its reply leaves the store caught up, its chain kept (strikes " +
                      std::to_string(strikes) + ", bans " + std::to_string(bans) + ")");
    }
}

// ---------------------------------------------------------------------------
// catchheavy: a store not caught up (its record K_NCU; journal depth 4) that walked D's chain 1..8 meets B (A's 1, 2
// and its own 3: lighter) and C (A's 1, 2 and its own 3..14: heavier); both forks at 2, below J's journal base. B and C
// answer J's catch-up requests (from a held id) with no header, as servers that hold none of J's positions; their
// joiner pages are served. B's tip is offered from the empty reply at position 0 and its attempt completes, rule (4)
// keeping J's chain; then C's catch-up reaches position 0 with no header:
//   later   C connects after B's attempt;
//   open    C is connected from the start, its catch-up replies held until B's attempt is applied;
//   silent  C never answers a catch-up request (its catch-up stays open).
// later / open: C's tip is offered and its attempt replaces J's chain (J at C's tip 14). silent: no offer, J keeps its
// chain, K_NCU ended (a restart and C's HELLO open no first round).
struct HeavyResult {
    bool setup = false;
    bool b_completed = false;
    bool ncu_after_b = false;    // K_NCU still set after B's attempt
    std::uint64_t c_offers = 0;  // empty-store offers counted after B's attempt
    std::uint64_t j_pos = 0;
    bool at_c = false;
    bool ncu_end = false;        // K_NCU set at the end
    std::uint64_t c_asks = 0;    // catch-up requests after B's attempt
    std::size_t c_pairs = 0;     // the joiner's queue after C's empty reply from position 0 (before any attempt)
    bool c_again = false;        // C's tip offered again by the same server: a second pair queued
    int restart_round = -1;      // silent: after a restart and C's HELLO, the first round open (1) or not (0)
    std::vector<std::string> caught;  // J's `relay: caught up (` lines over the run
    std::uint64_t b_pos = 0, b_t = 0;  // J's best position and the relay clock's unix ms at B's attempt
};
HeavyResult catch_heavy(int mode) {  // 0 later, 1 open, 2 silent
    const KatNet net;
    Harness h(net);
    FakeWire w;
    HeavyResult out;
    KatRelay a = kat_relay(h, w, table0(net), true);  // C
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay d = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.connect(0, 2);
    w.run();
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 4100 + static_cast<std::uint32_t>(i));
    }
    ok = ok && h[b.node].tree().best().id == h[a.node].tree().best().id && h[d.node].tree().best().id == h[a.node].tree().best().id;
    w.links[1]->disconnect(w.id(1, 0));
    w.links[2]->disconnect(w.id(2, 0));
    w.run();
    h.tick_monero();
    ok = ok && mine_on(h, w, b.node, 2, 4200);
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, d.node, static_cast<std::size_t>(i % 5), 4300 + static_cast<std::uint32_t>(i));
    }
    for (int i = 0; i < 12; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 4400 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip_c = h[a.node].tree().best().id;
    const std::uint64_t J = 4;
    const std::size_t jw = h.add(table0(net), false, J, true);
    MemoryKv& kvw = *h.kvs.back();
    for (std::uint64_t x = 1; x <= 8; ++x)
        if (const std::optional<pb::Hash32> id = h[d.node].store().best_at(x))
            (void)h[jw].on_carrier(77, *pb::encode_fc_carrier(0, *h[d.node].bodies().get(*id), 16));
    h.q.clear();
    const std::string ncu = pb::store_keys::ncu(0);
    out.setup = ok && h[jw].tree().best().pos == 8 && !h[jw].caught_up() && kvw.data.count(ncu) != 0
                && h[a.node].tree().best().pos == 14 && h[b.node].tree().best().pos == 3;
    KatRelay j = kat_relay_loaded(h, w, kvw, h.config(table0(net), false, J),
                                  [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; });
    MemoryKv& kvj = *h.kvs.back();
    const std::size_t jwire = 3;
    // J's FC_GETHEADERS from a held id to B or C: its reply carries no header (held back while `hold_c`); joiner pages
    // (from the zero id) are served; B's and C's own catch-ups toward J get no reply
    std::map<std::size_t, std::deque<bool>> asked;
    std::vector<FakeWire::Msg> held;
    bool hold_c = mode == 1;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.from == jwire && (m.to == 0 || m.to == 1) && m.f[0] == pb::kOpFcGetHeaders) {
            pb::GetHeaders q;
            if (pb::decode_fc_getheaders(m.f, 0, q).ok()) asked[m.to].push_back(q.from != pb::Hash32{});
            return;
        }
        if (m.f[0] != pb::kOpFcHeaders) return;
        if (m.to != jwire && m.from == jwire) {
            m.f.clear();
            return;
        }
        if (m.to != jwire || (m.from != 0 && m.from != 1) || asked[m.from].empty()) return;
        const bool catchup = asked[m.from].front();
        asked[m.from].pop_front();
        if (!catchup) return;
        if (m.from == 0 && mode == 2) {  // silent: no reply
            m.f.clear();
            return;
        }
        m.f = *pb::encode_fc_headers(pb::HeadersReply{0, 0, {}}, 1u << 22);
        if (m.from == 0 && hold_c) {  // open: the reply held until B's attempt is applied
            held.push_back(m);
            m.f.clear();
        }
    };
    pb::PathbRelayNode& rj = *j.relay;
    const auto ticks = [&](int n) {
        for (int k = 0; k < n; ++k) {
            (void)rj.join_step();
            w.run();
            h.now += 1;
            rj.tick();
            w.run();
        }
    };
    std::map<std::size_t, std::vector<std::string>> lines;
    g_relay_lines = &lines;
    w.connect(1, jwire);
    if (mode != 0) w.connect(0, jwire);
    w.run();
    std::optional<pb::JoinStep> sb;
    for (int k = 0; k < 40 && !(sb && sb->report); ++k) {
        sb = rj.join_step();
        w.run();
        if (!(sb && sb->report)) {
            h.now += 1;
            rj.tick();
            w.run();
        }
    }
    out.b_completed = sb && sb->report && sb->report->end == pb::AttemptEnd::Completed && !sb->sw.adopted && !sb->sw.replaced
                      && sb->report->server == static_cast<std::uint64_t>(1 + 1);
    out.b_pos = h[j.node].tree().best().pos;
    out.b_t = h.now * 1000;
    out.ncu_after_b = !h[j.node].caught_up();
    const std::uint64_t offers0 = rj.stats().empty_store_offers.load();
    const std::uint64_t asks0 = rj.stats().catchup_requests.load();
    hold_c = false;
    for (FakeWire::Msg& m : held) w.q.push_back(std::move(m));
    held.clear();
    w.run();
    if (mode == 0) {
        w.connect(0, jwire);
        w.run();
    }
    if (mode != 2) {  // one pair per (tip, server): the same server's tip offered again queues none
        out.c_pairs = h[j.node].joiner().queue().size();
        out.c_again = h[j.node].offer_empty_store_tip(w.id(jwire, 0));
    }
    const std::uint64_t p53 = h[j.node].config().abandon_timeout_s;
    ticks(static_cast<int>(mode == 2 ? 5 * p53 : 3 * p53));
    out.c_offers = rj.stats().empty_store_offers.load() - offers0;
    out.c_asks = rj.stats().catchup_requests.load() - asks0;
    out.j_pos = h[j.node].tree().best().pos;
    out.at_c = h[j.node].tree().best().id == tip_c;
    out.ncu_end = !h[j.node].caught_up() || kvj.data.count(ncu) != 0;
    if (mode == 2) {
        const std::size_t jr = load_node(h, kvj, h.config(table0(net), false, J));
        (void)h.hello(jr, a.node);
        out.restart_round = h[jr].first_round_open() ? 1 : 0;
    }
    w.edit = nullptr;
    g_relay_lines = nullptr;
    out.caught = caught_of(lines, j.node);
    return out;
}
void catchheavy() {
    const char* names[] = {"later", "open", "silent"};
    for (int mode = 0; mode < 3; ++mode) {
        const HeavyResult r = catch_heavy(mode);
        const std::string tag = std::string("catchheavy (") + names[mode] + "): ";
        std::printf("  %sB's attempt completed %d; K_NCU after it %d; C: empty-store offers %llu, catch-up requests %llu; "
                    "J at %llu (at C's tip %d); K_NCU at the end %d; restarted first round %d\n",
                    tag.c_str(), r.b_completed ? 1 : 0, r.ncu_after_b ? 1 : 0, (unsigned long long)r.c_offers,
                    (unsigned long long)r.c_asks, (unsigned long long)r.j_pos, r.at_c ? 1 : 0, r.ncu_end ? 1 : 0,
                    r.restart_round);
        for (const std::string& l : r.caught) std::printf("  %s%s (B's attempt at pos %llu t=%llu)\n", tag.c_str(), l.c_str(),
                                                          (unsigned long long)r.b_pos, (unsigned long long)r.b_t);
        const std::optional<CaughtLine> c = r.caught.size() == 1 ? parse_caught(r.caught[0]) : std::nullopt;
        check(c && c->form == kCaughtJoin && c->pos == 8 && c->pos == r.b_pos && c->t == r.b_t,
              tag + "B's completed attempt: one caught-up line, the join-attempt form ending \" at pos 8 t=" +
                      std::to_string(r.b_t) + "\" (J's best position, the relay clock's unix ms at the line; lines " +
                      std::to_string(r.caught.size()) + ")");
        check(r.setup && r.b_completed, tag + "setup (J at D's 8, K_NCU; B's attempt completes, rule (4) keeps J's chain)");
        if (mode != 2)
            check(r.c_offers == 1 && r.c_pairs == 1 && !r.c_again && r.at_c && !r.ncu_end,
                  tag + "C's heavier unheld tip gets one join pair and J reaches it (offers " + std::to_string(r.c_offers) +
                          ", pairs " + std::to_string(r.c_pairs) + ", again " + std::to_string(r.c_again ? 1 : 0) +
                          ", J at " + std::to_string(r.j_pos) + ")");
        else
            check(r.c_offers == 0 && r.j_pos == 8 && !r.ncu_end && r.restart_round == 0,
                  tag + "no reply, no pair: J keeps its chain; K_NCU ended; a restart opens no first round");
    }
}

// ---------------------------------------------------------------------------
// catchctx: a caught-up store above position 0 (launched; J at A's 4) whose catch-up step stays deferred on a P_r no
// node serves (X, the P_r of A's carriers 5..7) past kCtxTtlMs: no join pair, J at 4 (the kCtxTtlMs offer reads K_NCU).
void catchctx() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), true, false, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                           hide_blocks(hidden, hview));
    pb::PathbRelayNode& rj = *j.relay;
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 3 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 4600 + static_cast<std::uint32_t>(i));
    }
    for (int k = 0; k < 3; ++k) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    ok = ok && h[j.node].tree().best().id == h[a.node].tree().best().id && h[j.node].tree().best().pos == 4;
    w.links[1]->disconnect(w.id(1, 0));
    w.run();
    h.tick_monero();
    for (int i = 0; i < 3; ++i)
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 4700 + static_cast<std::uint32_t>(i));
    const std::optional<pb::Hash32> c5 = h[a.node].store().best_at(5);
    const pb::CarrierBodyV3* b5 = c5 ? h[a.node].bodies().get(*c5) : nullptr;
    if (!ok || b5 == nullptr) {
        check(false, "catchctx: setup (J at A's 4; A at 7)");
        return;
    }
    hidden.insert(b5->own.blob.prev_id);
    const std::uint64_t def0 = rj.stats().headers_ctx_deferred.load();
    w.reconnect(0, 1);
    w.run();
    const bool deferred = rj.stats().headers_ctx_deferred.load() > def0;
    for (int k = 0; k < 125; ++k) {  // 625 s
        h.now += 5;
        rj.tick();
        w.run();
        (void)rj.join_step();
        w.run();
    }
    const std::uint64_t offers = rj.stats().catchup_join_offers.load();
    std::printf("  catchctx: J at %llu (A at %llu); deferred %d; caught up %d; kCtxTtlMs offers %llu; pairs %zu; attempts "
                "%llu\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos,
                deferred ? 1 : 0, h[j.node].caught_up() ? 1 : 0, (unsigned long long)offers,
                h[j.node].joiner().queue().size(), (unsigned long long)rj.stats().join_attempts.load());
    check(deferred && h[j.node].caught_up(), "catchctx: setup (J caught up; its catch-up step DEFERs on X)");
    check(offers == 0 && h[j.node].joiner().queue().size() == 0 && rj.stats().join_attempts.load() == 0
                  && h[j.node].tree().best().pos == 4,
          "catchctx: a caught-up store's catch-up deferred past kCtxTtlMs queues no join pair (offers " +
                  std::to_string(offers) + ")");
}

// ---------------------------------------------------------------------------
// floorpr: the floor reading of #9 (operator ruling), through the node's P_r resolution (resolve_pr_on_branch):
//   fa      A builds on S with S's weights; B holds S verified without them (a bodiless alternative): B resolves S on
//           the floor and admits A's carriers on it (B follows A's branch);
//   band    a carrier of 413 transactions (above the floor's 411 + 1) on S2, held at B without its weights: DEFER
//           (MissingWeights), no context asked; S2's weights recorded: it runs again and passes on the exact Z;
//   hfirst  headers first over a header above the floor on a P_r without its weights: DEFER, never a BAN;
//   join    a joiner whose span headers rest on S reads their heights (height_of) and completes;
//   joinband   a join replay meeting the band DEFER on S2 (held, its weights not) with an own source that answers held
//           blocks at once ends NotServed on S2 with no fetch; the pair waits on S2's weights, then completes;
//   joinrepeat a fetched input that leaves the same DEFER ends the attempt NotServed on it after one fetch;
//   exact12 #12 keeps exact weights: a carrier whose window reads a block without its weights DEFERs, no token.
// The follower's rows with the RowWeights of some blocks not recorded (their blocks held).
struct WeightlessRows final : pb::IMoneroRows {
    const pb::IMoneroRows& inner;
    const std::set<pb::Hash32>& hidden;
    WeightlessRows(const pb::IMoneroRows& i, const std::set<pb::Hash32>& h) : inner(i), hidden(h) {}
    std::optional<pb::BranchBlock> block(const pb::Hash32& id) const override { return inner.block(id); }
    std::optional<pb::BranchBlock> block_at_or_below_anchor(std::uint64_t height) const override {
        return inner.block_at_or_below_anchor(height);
    }
    std::optional<pb::RowWeights> weights(const pb::Hash32& id) const override {
        return hidden.count(id) != 0 ? std::nullopt : inner.weights(id);
    }
    pb::BranchBlock anchor() const override { return inner.anchor(); }
    pb::Hash32 main_tip() const override { return inner.main_tip(); }
};
constexpr std::uint64_t kExactZ = 600000;  // Z(P_r) above the zone (the KAT's exact value for #9)
void floorpr() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> noweights;
    const WeightlessRows wrows(net.rows, noweights);
    const pb::FollowerBranchView wview(wrows);
    const auto exact_z = [](pb::PathbNodeIo& io) {
        const auto inner = io.resolve_pr;
        io.resolve_pr = [inner](const pb::Hash32& p_r) {
            pb::PrInfo r = inner(p_r);
            r.in.z = r.in.z_lt = kExactZ;
            return r;
        };
    };
    const auto floor_io = [&wview, &wrows](pb::PathbNodeIo& io) {
        io.monero = &wview;
        io.resolve_pr = [&wview, &wrows](const pb::Hash32& p_r) {
            pb::PrInfo r = pb::resolve_pr_on_branch(wview, wrows, p_r, [&wview](const pb::Hash32& id) -> std::optional<std::uint8_t> {
                return wview.block(id) ? std::optional<std::uint8_t>(16) : std::nullopt;
            });
            if (r.status == pb::PrInfo::Status::Held && !r.in.floor) r.in.z = r.in.z_lt = kExactZ;
            return r;
        };
    };
    KatRelay a = kat_relay(h, w, table0(net), true, false, nullptr, nullptr, exact_z);
    KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, floor_io);
    pb::PathbRelayNode& rb = *b.relay;
    bool ok = true;
    for (int i = 0; i < 4; ++i) {
        if (i % 2 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 3100 + static_cast<std::uint32_t>(i));
    }
    w.connect(0, 1);
    w.run();
    ok = ok && h[b.node].tree().best().id == h[a.node].tree().best().id;
    // fa
    h.tick_monero();
    const pb::Hash32 S = h[a.node].make_template(h.now).p_r;
    noweights.insert(S);
    const pb::PrInfo prs = pb::resolve_pr_on_branch(wview, wrows, S, [&wview](const pb::Hash32& id) -> std::optional<std::uint8_t> {
        return wview.block(id) ? std::optional<std::uint8_t>(16) : std::nullopt;
    });
    bool fa = true;
    for (int i = 0; i < 3; ++i) fa = fa && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3200 + static_cast<std::uint32_t>(i));
    check(ok && prs.status == pb::PrInfo::Status::Held && prs.in.floor && prs.in.z == 300000 && prs.in.z_lt == 300000
                  && fa && h[b.node].tree().best().id == h[a.node].tree().best().id && rb.stats().strikes.load() == 0
                  && rb.stats().bans.load() == 0,
          "floorpr: a carrier on a P_r B holds without its weights resolves on the floor and is admitted (B at A's tip)");
    // band
    h.tick_monero();
    const pb::Hash32 S2 = h[a.node].make_template(h.now).p_r;
    noweights.insert(S2);
    h.txs = blob_txs(412, 400, 1, 0x30);
    const std::uint64_t wanted0 = rb.stats().ctx_wanted.load();
    const pb::NodeEventResult ra = h[a.node].on_own_share(*h.job(a.node, 2, 3300), 3300, pb::Hash32{});
    const pb::Hash32 big = h[a.node].tree().best().id;
    const pb::CarrierBodyV3* bb = h[a.node].bodies().get(big);
    w.run();
    const bool band_parked = rb.parked_ctx_size(pb::Missing::MissingWeights, S2) == 1 && h[b.node].tree().find(big) == nullptr
                             && rb.stats().ctx_wanted.load() == wanted0;
    check(ra.action == pb::NodeAction::Placed && bb != nullptr && bb->own.blob.tx_count == 413 && band_parked
                  && rb.stats().strikes.load() == 0 && rb.stats().bans.load() == 0,
          "floorpr: 413 transactions on a P_r without its weights (above the floor): DEFER MissingWeights, no context, "
          "no token");
    noweights.erase(S2);
    rb.on_monero_tip();
    w.run();
    check(h[b.node].tree().find(big) != nullptr && rb.parked_ctx_size(pb::Missing::MissingWeights, S2) == 0,
          "floorpr: its weights recorded, it runs again and passes on the exact Z(P_r)");
    h.txs.clear();
    // headers first: a fresh node C2 catching up over the 413-transaction carrier, S2 held there without its weights:
    // the header path DEFERs on S2 (its weights), no token; S2's weights recorded: it asks again and reaches A's tip
    std::set<pb::Hash32> noweights2{S2};
    const WeightlessRows wrows2(net.rows, noweights2);
    const pb::FollowerBranchView wview2(wrows2);
    KatRelay c2 = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, [&wview2, &wrows2](pb::PathbNodeIo& io) {
        io.monero = &wview2;
        io.resolve_pr = [&wview2, &wrows2](const pb::Hash32& p_r) {
            pb::PrInfo r = pb::resolve_pr_on_branch(wview2, wrows2, p_r, [&wview2](const pb::Hash32& id) -> std::optional<std::uint8_t> {
                return wview2.block(id) ? std::optional<std::uint8_t>(16) : std::nullopt;
            });
            if (r.status == pb::PrInfo::Status::Held && !r.in.floor) r.in.z = r.in.z_lt = kExactZ;
            return r;
        };
    });
    w.connect(0, 2);
    w.run();
    pb::PathbRelayNode& rc2 = *c2.relay;
    const bool hdr_deferred = rc2.stats().headers_ctx_deferred.load() >= 1 && h[c2.node].tree().find(big) == nullptr
                              && rc2.stats().bans.load() == 0 && rc2.stats().strikes.load() == 0;
    noweights2.erase(S2);
    rc2.on_monero_tip();
    w.run();
    for (int k = 0; k < 6 && h[c2.node].tree().best().id != h[a.node].tree().best().id; ++k) {
        h.now += 1;
        rc2.tick();
        w.run();
    }
    check(hdr_deferred && h[c2.node].tree().best().id == h[a.node].tree().best().id && rc2.stats().bans.load() == 0
                  && rc2.stats().headers_ctx_reasks.load() >= 1,
          "floorpr: headers first over a header above the floor on a P_r without its weights: DEFER, no ban; its weights "
          "recorded, the headers asked again and A's tip reached");
    // join: a joiner (a load failure) whose span's headers rest on S, held without its weights: their heights are read
    // (height_of on the floor's Held) and the attempt completes
    KatRelay jj = kat_relay(h, w, table0(net), false, true, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                            floor_io);
    w.connect(0, 3);
    w.run();
    const std::optional<pb::JoinStep> sj = jj.relay->join_step();
    w.run();
    check(sj && sj->report && sj->report->end == pb::AttemptEnd::Completed && sj->switched
                  && h[jj.node].tree().best().id == h[a.node].tree().best().id,
          "floorpr: a join whose headers rest on a P_r held without its weights reads their heights and completes (" +
                  std::string(sj && sj->report ? pb::attempt_end_name(sj->report->end) : "none") + ")");
    // joinband: a joiner whose own source answers every Monero block it holds at once (the production relay's
    // FB_GETCTX: its own index, Indexed, no hash), S2 held there without its weights: the replay meets the 413-transaction
    // carrier's band DEFER (MissingWeights on S2) and ends NotServed on S2 within one step, no context fetched for it;
    // the pair waits on S2's weights (no attempt meanwhile); S2's weights recorded: the pair is tried again and completes.
    // The own source answers at most 64 fetches per id (a watchdog for a re-admission loop).
    std::set<pb::Hash32> noweights3{S2};
    const WeightlessRows wrows3(net.rows, noweights3);
    const pb::FollowerBranchView wview3(wrows3);
    std::map<pb::Hash32, std::uint64_t> fetches3;
    const auto own_source_io = [&fetches3](const pb::FollowerBranchView& v, const pb::IMoneroRows& r) {
        return [&fetches3, &v, &r](pb::PathbNodeIo& io) {
            io.monero = &v;
            io.resolve_pr = [&v, &r](const pb::Hash32& p_r) {
                pb::PrInfo x = pb::resolve_pr_on_branch(v, r, p_r, [&v](const pb::Hash32& id) -> std::optional<std::uint8_t> {
                    return v.block(id) ? std::optional<std::uint8_t>(16) : std::nullopt;
                });
                if (x.status == pb::PrInfo::Status::Held && !x.in.floor) x.in.z = x.in.z_lt = kExactZ;
                return x;
            };
            io.fetch_context = [&fetches3, &v](const pb::Hash32& id, std::uint64_t) {
                return ++fetches3[id] <= 64 && v.block(id).has_value();
            };
        };
    };
    KatRelay jb = kat_relay(h, w, table0(net), false, true, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                            own_source_io(wview3, wrows3));
    w.connect(0, 4);
    w.run();
    const std::optional<pb::JoinStep> sb1 = jb.relay->join_step();
    w.run();
    const pb::Joiner& jbj = h[jb.node].joiner();
    const std::vector<std::pair<pb::Missing, pb::Hash32>> jw = jbj.queue().waits();
    const bool band_ns = sb1 && sb1->report && sb1->report->end == pb::AttemptEnd::NotServed && sb1->report->unresolved_pr
                         && *sb1->report->unresolved_pr == S2 && sb1->report->unresolved_cause == pb::Missing::MissingWeights
                         && fetches3[S2] == 0 && jw.size() == 1 && jw.front().first == pb::Missing::MissingWeights
                         && jw.front().second == S2 && jbj.queue().ready() == 0;
    jb.relay->on_monero_tip();  // a follower event with S2's weights still absent: the pair keeps waiting
    w.run();
    const std::optional<pb::JoinStep> sb2 = jb.relay->join_step();
    const bool waited = (!sb2 || !sb2->report) && h[jb.node].joiner().queue().ready() == 0;
    noweights3.erase(S2);
    jb.relay->on_monero_tip();
    w.run();
    std::optional<pb::JoinStep> sb3;
    for (int k = 0; k < 4 && !(sb3 && sb3->report && sb3->report->end == pb::AttemptEnd::Completed); ++k) {
        sb3 = jb.relay->join_step();
        w.run();
    }
    check(band_ns && waited && sb3 && sb3->report && sb3->report->end == pb::AttemptEnd::Completed
                  && h[jb.node].tree().best().id == h[a.node].tree().best().id && fetches3[S2] == 0,
          "floorpr: joinband: a join replay meeting a band DEFER on a held block ends NotServed on it at once (fetches " +
                  std::to_string(fetches3[S2]) + "), the pair waits on its weights, and completes once they are recorded (" +
                  std::string(sb1 && sb1->report ? pb::attempt_end_name(sb1->report->end) : "none") + ", " +
                  std::string(sb3 && sb3->report ? pb::attempt_end_name(sb3->report->end) : "none") + ")");
    // joinrepeat: a joiner whose source answers every fetch as resolved, one block of the span's timestamp windows not
    // held there: the replay's DEFER on it is fetched once (true), deferred again on the same input, and the attempt
    // ends NotServed on it (no second fetch, no re-admission loop)
    const pb::FollowerBranchView mon4(net.rows);
    const std::optional<pb::BranchBlock> tb4 = mon4.block(h[a.node].make_template(h.now).p_r);
    const pb::Hash32 gap = mon_block(tb4 && tb4->height > 30 ? tb4->height - 30 : 0);
    std::set<pb::Hash32> hidden4{gap};
    const HiddenRows hrows4(net.rows, hidden4);
    const pb::FollowerBranchView hview4(hrows4);
    const auto base4 = own_source_io(hview4, hrows4);
    KatRelay jr = kat_relay(h, w, table0(net), false, true, [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; }, nullptr,
                            [&base4, &fetches3](pb::PathbNodeIo& io) {
                                base4(io);
                                io.fetch_context = [&fetches3](const pb::Hash32& id, std::uint64_t) { return ++fetches3[id] <= 64; };
                            });
    fetches3.clear();
    w.connect(0, 5);
    w.run();
    const std::optional<pb::JoinStep> sr = jr.relay->join_step();
    w.run();
    const std::uint64_t fgap = fetches3[gap];
    check(sr && sr->report && sr->report->end == pb::AttemptEnd::NotServed && sr->report->unresolved_pr
                  && *sr->report->unresolved_pr == gap && fgap == 1,
          "floorpr: joinrepeat: a fetched Monero input that leaves the same DEFER ends the attempt NotServed on it (fetches " +
                  std::to_string(fgap) + ", " + std::string(sr && sr->report ? pb::attempt_end_name(sr->report->end) : "none") +
                  ", cause " + std::to_string(sr && sr->report ? static_cast<int>(sr->report->unresolved_cause) : -1) + ", " +
                  (sr && sr->report ? sr->report->what : std::string("-")) + ")");
    // exact12: the window's weights at A_t never read the floor
    h.tick_monero();
    const pb::PathbTemplate t3 = h[a.node].make_template(h.now);
    const pb::FollowerBranchView mon(net.rows);
    const std::optional<pb::BranchBlock> b3 = mon.block(t3.p_r);
    const std::uint64_t h3 = b3 ? b3->height : 0;
    for (std::uint64_t k = 1; k <= 100 && k < h3; ++k) noweights.insert(mon_block(h3 - k));
    const bool m3 = mine_on(h, w, a.node, 4, 3400);
    const pb::Hash32 c3 = h[a.node].tree().best().id;
    check(m3 && h3 != 0 && h[b.node].tree().find(c3) == nullptr && rb.stats().bans.load() == 0 && rb.stats().strikes.load() == 0
                  && rb.parked_index_size() >= 1,
          "floorpr: #12 keeps exact weights: a carrier whose window reads a block without its weights DEFERs, no token");
}

// ---------------------------------------------------------------------------
// jobslot: the CPU miner's own slot (bind_own) is never evicted by stratum jobs: over 66 templates of 1,000 stratum
// bind + get_job pairs each (66,000 > 65,536 binds) the miner's job follows every template; a stratum bind is taken by
// its get_job on every return path (no template, make_job failed, a cached job, an issue), so the sessions held stay
// the own slot; an issued extra_nonce gets a peek on the next template; MinerSlot over 30,000 templates with three
// stratum sessions each follows every template with no skip, a HOLD (clear()) adds none, and a slot with no session is
// counted once per template with its line.
pb::PathbTemplate slot_template(std::uint64_t k) {
    pb::PathbTemplate t;
    t.status = pb::TemplateStatus::Ok;
    t.h = 1000 + k;
    t.p_r = seq32(static_cast<std::uint8_t>(k));
    t.p_r[30] = static_cast<std::uint8_t>(k >> 8);
    t.p_r[31] = static_cast<std::uint8_t>(k >> 16);
    t.hf = 16;
    t.d = 16;
    return t;
}
pb::PathbJobSource::MakeJob slot_make(const bool* fail) {
    return [fail](const pb::PathbTemplate& t, const pb::PathbSession&) -> std::optional<pb::PathbJob> {
        if (fail != nullptr && *fail) return std::nullopt;
        pb::PathbJob j;
        j.body.blob.major = t.hf;
        j.body.blob.minor = t.hf;
        j.body.blob.timestamp = 1700000000ull + t.h;
        std::copy(t.p_r.begin(), t.p_r.end(), j.body.blob.prev_id.begin());
        j.body.blob.tree_root.fill(0x5a);
        j.body.blob.tx_count = 1;
        j.h = t.h;
        j.d = t.d;
        return j;
    };
}
void jobslot() {
    const pb::PathbSession s{};
    bool fail = false;
    {  // the pin
        pb::PathbJobSource js(slot_make(&fail));
        const std::uint32_t M = 0x00ffffffu;
        js.bind_own(M, s);
        std::uint32_t en = 0x01000000u;
        std::size_t followed = 0;
        for (std::uint64_t k = 0; k < 66; ++k) {
            const std::uint32_t tid = js.set_template(slot_template(k), pb::JobNetwork{});
            for (int i = 0; i < 1000; ++i) {
                js.bind(en, s);
                ::v37::xmr::stratum::TemplateJob o;
                (void)js.get_job(en++, o);
            }
            ::v37::xmr::stratum::TemplateJob m;
            if (js.get_job(M, m) && !m.blob.empty() && m.template_id == tid) ++followed;
        }
        check(followed == 66 && js.sessions_held() == 1,
              "jobslot: the miner's own slot gets a job on each of 66 templates after 66,000 stratum binds (followed " +
                      std::to_string(followed) + ", sessions held " + std::to_string(js.sessions_held()) + ")");
    }
    {  // no leak: under clear() and with make_job failing every bind is taken by its get_job
        pb::PathbJobSource js(slot_make(&fail));
        js.bind_own(7, s);
        js.clear();
        bool none = true;
        for (std::uint32_t e = 100; e < 1100; ++e) {
            js.bind(e, s);
            ::v37::xmr::stratum::TemplateJob o;
            none = none && !js.get_job(e, o);
        }
        const std::size_t after_clear = js.sessions_held();
        (void)js.set_template(slot_template(1), pb::JobNetwork{});
        fail = true;
        for (std::uint32_t e = 2000; e < 3000; ++e) {
            js.bind(e, s);
            ::v37::xmr::stratum::TemplateJob o;
            none = none && !js.get_job(e, o);
        }
        fail = false;
        check(none && after_clear == 1 && js.sessions_held() == 1 && js.make_failed() == 1000,
              "jobslot: 1,000 binds under clear() and 1,000 with make_job failing leave the own slot only (held " +
                      std::to_string(after_clear) + ", then " + std::to_string(js.sessions_held()) + ")");
    }
    {  // an issued extra_nonce: its job again on the same template, a peek on the next
        pb::PathbJobSource js(slot_make(&fail));
        const std::uint32_t t1 = js.set_template(slot_template(1), pb::JobNetwork{});
        js.bind(9, s);
        ::v37::xmr::stratum::TemplateJob a, b, c;
        const bool ga = js.get_job(9, a), gb = js.get_job(9, b);
        const std::uint32_t t2 = js.set_template(slot_template(2), pb::JobNetwork{});
        const bool gc = js.get_job(9, c);
        check(ga && gb && gc && !a.blob.empty() && b.blob == a.blob && a.template_id == t1 && c.blob.empty()
                      && c.template_id == t2 && js.issued(t1, 9).has_value() && !js.issued(t2, 9).has_value(),
              "jobslot: an issued extra_nonce gets its job again on its template and a peek on the next");
    }
    {  // MinerSlot over 30,000 templates; a HOLD; a slot with no session
        pb::PathbJobSource js(slot_make(&fail));
        const std::uint32_t M = 0x00ffff00u;
        js.bind_own(M, s);
        pb::MinerSlot slot(M), orphan(0x00ffff01u);
        std::uint32_t en = 0x02000000u;
        std::size_t followed = 0, lines = 0, orphan_lines = 0;
        const std::size_t n = 30000;
        for (std::size_t k = 0; k < n; ++k) {
            const std::uint32_t tid = js.set_template(slot_template(k), pb::JobNetwork{});
            for (int i = 0; i < 3; ++i) {
                js.bind(en, s);
                ::v37::xmr::stratum::TemplateJob o;
                (void)js.get_job(en++, o);
            }
            for (int tick = 0; tick < 2; ++tick) {
                if (const std::optional<::v37::xmr::stratum::TemplateJob> j = slot.next(js)) slot.pushed(j->template_id);
                if (slot.settle()) ++lines;
                if (const std::optional<::v37::xmr::stratum::TemplateJob> j = orphan.next(js)) orphan.pushed(j->template_id);
                if (orphan.settle()) ++orphan_lines;
            }
            if (slot.job_template() == tid) ++followed;
            if (k == n / 2) {  // a HOLD: the template withdrawn for 100 ticks
                js.clear();
                for (int tick = 0; tick < 100; ++tick) {
                    if (slot.next(js)) ++lines;
                    if (slot.settle()) ++lines;
                }
            }
        }
        check(followed == n && slot.skipped() == 0 && lines == 0,
              "jobslot: MinerSlot follows every one of 30,000 templates, no skip, a HOLD adds none (followed " +
                      std::to_string(followed) + ", skipped " + std::to_string(slot.skipped()) + ")");
        check(orphan.skipped() == n && orphan_lines == n,
              "jobslot: a slot whose job has no blob is counted once per template with its line (" +
                      std::to_string(orphan.skipped()) + " of " + std::to_string(n) + ")");
    }
}

// minerwithdraw: a template withdrawn (clear(): a DEFER, a HOLD, FORK-FUSE) while the CPU miner holds a job of it: the
// miner's job is withdrawn once (no job is current), never while a template is current or the slot holds no job, and
// the next template is pushed as a new job.
void minerwithdraw() {
    const pb::PathbSession s{};
    bool fail = false;
    pb::PathbJobSource js(slot_make(&fail));
    const std::uint32_t M = 0x00fffe00u;
    js.bind_own(M, s);
    pb::MinerSlot slot(M);
    const bool none_before = !slot.withdraw_due(js);
    const std::uint32_t t1 = js.set_template(slot_template(1), pb::JobNetwork{});
    const std::optional<::v37::xmr::stratum::TemplateJob> j1 = slot.next(js);
    if (j1) slot.pushed(j1->template_id);
    const bool none_current = !slot.withdraw_due(js);
    js.clear();
    const bool once = slot.withdraw_due(js);
    const bool not_twice = !slot.withdraw_due(js) && !slot.next(js) && !slot.settle();
    const std::uint32_t t2 = js.set_template(slot_template(2), pb::JobNetwork{});
    const std::optional<::v37::xmr::stratum::TemplateJob> j2 = slot.next(js);
    if (j2) slot.pushed(j2->template_id);
    check(none_before && j1 && j1->template_id == t1 && none_current && once && not_twice && slot.withdrawn() == 1,
          "minerwithdraw: a withdrawn template withdraws the miner's job once (withdrawn " +
                  std::to_string(slot.withdrawn()) + "), never with a current template or no job");
    check(j2 && j2->template_id == t2 && slot.job_template() == t2 && !slot.withdraw_due(js),
          "minerwithdraw: the next template is pushed as a new job");
}

// minerflush: the withdraw of the CPU miner's job hands its queued hits on (none is dropped with the lane gate open):
// the Monero block found on a held parent's template is submitted, the one on an abandoned parent's template is refused
// and logged by the gated candidate lookup (the publish arms'), a share is handed on; with the gate closed (HOLD,
// FORK-FUSE) the hits are dropped and counted.
struct FlushHit {
    std::uint32_t template_id = 0, extra_nonce = 0, nonce = 0;
    bool network = false, share = false;
};
struct FlushMiner {
    std::vector<FlushHit> queued;
    int cleared = 0;
    std::vector<FlushHit> clear_job() {
        ++cleared;
        std::vector<FlushHit> out;
        out.swap(queued);
        return out;
    }
};
void minerflush() {
    const pb::PathbSession s{};
    bool fail = false;
    pb::PathbJobSource js(slot_make(&fail));
    const std::uint32_t M = 0x00fffd00u;
    js.bind_own(M, s);
    const pb::PathbTemplate held = slot_template(11), gone = slot_template(12);
    const std::uint32_t t_held = js.set_template(held, pb::JobNetwork{});
    ::v37::xmr::stratum::TemplateJob j1, j2;
    const bool g1 = js.get_job(M, j1);
    const std::uint32_t t_gone = js.set_template(gone, pb::JobNetwork{});
    const bool g2 = js.get_job(M, j2);
    js.clear();   // the template withdrawn (a DEFER)
    std::vector<std::string> log;
    const pb::GatedCandidateLookup lookup(
            js,
            [&](const pb::GatedCandidateLookup::Candidate& c, std::string* why) {
                const bool ok = std::equal(c.prev_id.begin(), c.prev_id.end(), held.p_r.begin());
                if (!ok && why) *why = "its parent was abandoned by the own-fork guard";
                return ok;
            },
            [&](const std::string& l) { log.push_back(l); });
    FlushMiner miner;
    miner.queued = {FlushHit{t_held, M, 1, true, false}, FlushHit{t_gone, M, 2, true, false},
                    FlushHit{t_gone, M, 3, false, true}};
    std::vector<std::uint32_t> published;
    std::size_t shares = 0;
    const auto on_hit = [&](const FlushHit& h) {
        if (h.network) {
            pb::GatedCandidateLookup::Candidate c;
            if (lookup(h.template_id, h.extra_nonce, c)) published.push_back(h.template_id);
        }
        if (h.share || h.network) ++shares;
    };
    const pb::MinerWithdraw w = pb::withdraw_miner_job(miner, false, on_hit);
    const bool logged = log.size() == 1 && log[0].find("NOT PUBLISHED: template " + std::to_string(t_gone)) == 0;
    check(g1 && g2 && miner.cleared == 1 && w.submitted == 3 && w.network == 2 && w.dropped == 0 && shares == 3
                  && published.size() == 1 && published[0] == t_held,
          "minerflush: the withdraw hands on 3 queued hits (" + std::to_string(w.submitted) + "): the Monero block on the "
                  "held parent is submitted (" + std::to_string(published.size()) + " published)");
    check(lookup.refused() == 1 && logged,
          "minerflush: the Monero block on the abandoned parent is refused and logged (" +
                  std::to_string(lookup.refused()) + " refused, " + (log.empty() ? std::string("no line") : log[0]) + ")");
    FlushMiner closed;
    closed.queued = {FlushHit{t_held, M, 4, true, false}, FlushHit{t_held, M, 5, false, true}};
    std::size_t handed = 0;
    const pb::MinerWithdraw wc = pb::withdraw_miner_job(closed, true, [&](const FlushHit&) { ++handed; });
    check(closed.cleared == 1 && wc.dropped == 2 && wc.submitted == 0 && handed == 0,
          "minerflush: with the lane gate closed the queued hits are dropped and counted (" + std::to_string(wc.dropped) +
                  ")");
}

}  // namespace

// ---------------------------------------------------------------------------
// HDR-PAIR: the node's FC_GETHEADERS / FC_HEADERS pairing. One request in flight per peer, from its send until a frame
// of its reply arrives or the link drops; a request with no frame within P-53 is retired (its reply DROPs; no new
// request to the peer before it arrives); each outcome names its owner (the catch-up, a tip-header want) and only that
// owner acts on it; waiting requests queue per peer, deduplicated, never overwritten.
using HpK = pb::PathbNode::HeadersOutcome::Kind;
using HpOwner = pb::PathbNode::HeaderOwner;
std::size_t hp_getheaders(const Harness& h, std::size_t from, std::size_t to) {
    std::size_t n = 0;
    for (const Msg& m : h.q) n += m.from == from && m.to == to && !m.frame.empty() && m.frame[0] == pb::kOpFcGetHeaders ? 1 : 0;
    return n;
}
std::vector<std::uint8_t> hp_carrier(Harness& h, std::size_t n, const pb::Hash32& id) {
    return *pb::encode_fc_carrier(0, *h[n].bodies().get(id), 16);
}
bool hp_indexed(const pb::PathbNode& n, const pb::Hash32& id) { return !pb::PathbNodeTestAccess::headers(n).variants(id).empty(); }
std::string hp_kind(const pb::PathbNode::HeadersOutcome& o) { return std::to_string(static_cast<int>(o.kind)); }

// hp_stale (V1, the J1 shape): S holds 6 positions, J is empty; R1 = the catch-up from position 0. (i) R1's reply F1
// arrived (the relay's link order) and waits: P-53 + 1 s later R1 is not retired, no second FC_GETHEADERS goes to S,
// F1 is FetchBodies. (ii) F1 held on the wire past P-53: R1 retired; S's carrier 1 moves J's best; no new FC_GETHEADERS
// to S while R1 is retired; F1 DROPs (nothing indexed, no BAN); then R2 from position 1 is FetchBodies; J at S's tip.
// (iii) the relay: A's reply received and not yet handled at the tick past P-53: R1 not retired, one catch-up request,
// no retired reply, no ban; J at A's tip.
void hp_stale() {
    const KatNet net;
    {
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id;
        check(h[j].request_headers(s, g, tip, 64, h.now), "hp_stale (i): R1 = FC_GETHEADERS(from position 0)");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        h[j].headers_arrived(s);  // F1 arrived in link order; its handling waits
        h.now += pb::kAbandonTimeoutDefault + 1;
        const std::size_t expired = h[j].tick(h.now);
        const std::optional<pb::PathbNode::HeaderSlot> slot = h[j].header_slot(s);
        const bool again = h[j].request_headers(s, g, tip, 64, h.now);
        check(expired == 0 && slot && !slot->retired && !again && hp_getheaders(h, j, s) == 0,
              "hp_stale (i): F1 arrived: R1 not retired at P-53 + 1 s (expired " + std::to_string(expired) +
                      "); no second FC_GETHEADERS to S");
        const pb::PathbNode::HeadersOutcome o = h[j].on_headers(s, f1, h.now);
        check(o.kind == HpK::FetchBodies && o.owner == HpOwner::CatchUp, "hp_stale (i): F1 answers R1: FetchBodies (kind " + hp_kind(o) + ")");
        h.pump();
        check(h[j].tree().best().id == tip, "hp_stale (i): J at S's tip");
    }
    {
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id, c1 = *h[s].store().best_at(1);
        check(h[j].request_headers(s, g, tip, 64, h.now), "hp_stale (ii): R1");
        const std::vector<std::uint8_t> f1 = h[s].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        h.now += pb::kAbandonTimeoutDefault + 1;
        const std::size_t expired = h[j].tick(h.now);
        const std::optional<pb::PathbNode::HeaderSlot> slot = h[j].header_slot(s);
        (void)h[j].on_carrier(s, hp_carrier(h, s, c1));
        h.q.clear();
        const bool moved = h[j].tree().best().id == c1;
        const bool r2 = h[j].request_headers(s, c1, tip, 64, h.now);
        check(expired == 1 && slot && slot->retired && moved && !r2 && hp_getheaders(h, j, s) == 0,
              "hp_stale (ii): R1 retired at P-53 (no frame); J's best moved; no new FC_GETHEADERS to S while R1 is retired");
        const pb::PathbNode::HeadersOutcome o1 = h[j].on_headers(s, f1, h.now);
        check(o1.kind == HpK::Retired && o1.indexed == 0 && pb::PathbNodeTestAccess::headers(h[j]).size() == 0
                      && !h[j].header_slot(s).has_value(),
              "hp_stale (ii): F1 DROPs (its request retired): nothing indexed, no BAN; the slot frees (kind " + hp_kind(o1) + ")");
        check(h[j].request_headers(s, c1, tip, 64, h.now), "hp_stale (ii): R2 = FC_GETHEADERS(from position 1)");
        const std::vector<std::uint8_t> r2f = h.q.back().frame;
        h.q.clear();
        const pb::PathbNode::HeadersOutcome o2 = h[j].on_headers(s, h[s].serve_getheaders(j, r2f, h.now).frames.at(0), h.now);
        check(o2.kind == HpK::FetchBodies && o2.fork_pos == 1, "hp_stale (ii): R2's reply: FetchBodies (kind " + hp_kind(o2) + ")");
        h.pump();
        check(h[j].tree().best().id == tip, "hp_stale (ii): J at S's tip");
    }
    {
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay j = kat_relay(h, w, table0(net), false);
        bool mined = true;
        for (int i = 0; i < 6; ++i) {
            if (i % 3 == 0) h.tick_monero();
            mined = mined && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 3100 + static_cast<std::uint32_t>(i));
        }
        const pb::Hash32 tip_a = h[a.node].tree().best().id;
        std::vector<std::uint8_t> held;
        w.edit = [&held](FakeWire::Msg& m) {
            if (m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders && held.empty()) {
                held = m.f;
                m.f.clear();
            }
        };
        w.connect(0, 1);
        w.run();
        w.edit = nullptr;
        pb::PathbRelayNode& rj = *j.relay;
        const std::uint64_t pa = w.id(j.node, a.node);
        rj.receive(pa, held);  // routed in link order; its handling waits for the owner
        h.now += pb::kAbandonTimeoutDefault + 1;
        rj.tick();
        const std::uint64_t asked = rj.stats().catchup_requests.load();
        const std::optional<pb::PathbNode::HeaderSlot> slot = rj.with_node([&](pb::PathbNode& n) { return n.header_slot(pa); });
        rj.pump();
        w.run();
        for (int i = 0; i < 6 && h[j.node].tree().best().id != tip_a; ++i) {
            h.now += 1;
            rj.tick();
            w.run();
        }
        std::printf("  hp_stale (iii): held %zu B; at the tick past P-53: catch-up asks %llu, retired %d; retired replies %llu, "
                    "bans %llu; J at %llu of %llu\n",
                    held.size(), (unsigned long long)asked, slot && slot->retired ? 1 : 0,
                    (unsigned long long)rj.stats().headers_retired_dropped.load(), (unsigned long long)rj.stats().bans.load(),
                    (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos);
        check(mined && !held.empty() && asked == 1 && slot && !slot->retired && rj.stats().headers_retired_dropped.load() == 0
                      && rj.stats().bans.load() == 0 && h[j.node].tree().best().id == tip_a,
              "hp_stale (iii): the relay: A's reply arrived and waits at the tick past P-53: not retired, one catch-up "
              "request, no retired reply, no ban; J at A's tip");
    }
}

// hp_tipkeep (V3, fault 3): A, B and C hold 64 positions with a side sibling t at position 3 (all three hold it). J,
// empty, its deferred store 4 (one room of bodies per page: many catch-up pages), catches up from all three. Once J's
// best passes position 3, each server gets the tip-header requests (from position 0) of t twice (Keep with ids), of an
// id it does not hold (Keep, no ids) and of position 40 (FetchBodies). J reaches the tip; every catch-up entry is kept
// until J holds the tip; each distinct tip request goes to each server once; 0 bans.
void hp_tipkeep() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.connect(0, 2);
    w.connect(1, 2);
    w.run();
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3300 + static_cast<std::uint32_t>(i));
    }
    // the race at position 3: B, cut off, mines its sibling; then every server gets both siblings
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 1) != (m.to == 1)) m.f.clear();
    };
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 2, 3310) && mine_on(h, w, b.node, 3, 3311);
    const pb::Hash32 sa = h[a.node].tree().best().id, sb = h[b.node].tree().best().id;
    w.edit = nullptr;
    ok = ok && sa != sb;
    if (ok) {
        w.q.push_back(FakeWire::Msg{0, 1, hp_carrier(h, a.node, sa)});
        w.q.push_back(FakeWire::Msg{1, 0, hp_carrier(h, b.node, sb)});
        w.q.push_back(FakeWire::Msg{1, 2, hp_carrier(h, b.node, sb)});
        w.run();
    }
    const pb::Hash32 t = sa < sb ? sb : sa;  // equal work: the lower id wins
    const pb::Hash32 best3 = h[a.node].tree().best().id;
    ok = ok && best3 != t && h[b.node].tree().best().id == best3 && h[c.node].tree().best().id == best3
         && h[a.node].tree().find(t) != nullptr && h[b.node].tree().find(t) != nullptr && h[c.node].tree().find(t) != nullptr;
    for (int i = 0; i < 61 && ok; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 3320 + static_cast<std::uint32_t>(i));
    }
    const pb::Hash32 tip = h[a.node].tree().best().id;
    const std::optional<pb::Hash32> mid = h[a.node].store().best_at(40);
    ok = ok && mid && h[b.node].tree().best().id == tip && h[c.node].tree().best().id == tip;
    if (!ok) {
        check(false, "hp_tipkeep: setup (64 positions, a side sibling at 3 held by A, B and C)");
        return;
    }
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& cf) { cf.waiting_cap = 4; });
    std::map<std::tuple<std::size_t, pb::Hash32, pb::Hash32>, int> sent;  // J's FC_GETHEADERS by (server, from, stop)
    w.edit = [&](FakeWire::Msg& m) {
        if (m.from != j.links->self || m.f.empty() || m.f[0] != pb::kOpFcGetHeaders) return;
        pb::GetHeaders q;
        if (pb::decode_fc_getheaders(m.f, 0, q).ok()) ++sent[{m.to, q.from, q.stop}];
    };
    w.connect(3, 0);
    w.connect(3, 1);
    w.connect(3, 2);
    const pb::Hash32 g = h[j.node].tree().genesis().id, unknown = seq32(0x5a);
    bool injected = false;
    std::size_t min_peers = 3;
    int secs = 0;
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs) {
        catch_second(h, w, {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()});
        if (!injected && h[j.node].tree().best().pos >= 4 && h[j.node].tree().best().pos < 40) {
            injected = true;
            for (std::size_t s = 0; s < 3; ++s)
                for (const pb::Hash32& stop : {t, t, unknown, *mid}) j.relay->test_tip_headers(w.id(j.node, s), pb::Hash32{}, stop);
        }
        if (injected && h[j.node].tree().best().id != tip) min_peers = std::min(min_peers, j.relay->catchup_peers());
    }
    w.edit = nullptr;
    bool once = true;
    std::string counts;
    for (std::size_t s = 0; s < 3; ++s)
        for (const pb::Hash32& stop : {t, unknown, *mid}) {
            const int n = sent[{s, g, stop}];
            once = once && n == 1;
            counts += std::to_string(n);
        }
    const pb::PathbRelayStats& st = j.relay->stats();
    std::printf("  hp_tipkeep: J at %llu of %llu after %d s; injected %d; catch-up peers at least %zu; tip requests by server "
                "and stop %s; merged %llu; catch-up asks %llu; bans %llu\n",
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos, secs,
                injected ? 1 : 0, min_peers, counts.c_str(), (unsigned long long)st.header_wants_merged.load(),
                (unsigned long long)st.catchup_requests.load(), (unsigned long long)st.bans.load());
    check(injected && h[j.node].tree().best().id == tip && min_peers == 3,
          "hp_tipkeep: J reaches the tip; the three catch-up entries kept across the tip outcomes (at least " +
                  std::to_string(min_peers) + ")");
    check(once && st.header_wants_merged.load() >= 3,
          "hp_tipkeep: each distinct tip request sent once per server (" + counts + "); the equal ones merged");
    check(st.bans.load() == 0 && st.strikes.load() == 0, "hp_tipkeep: 0 bans, 0 strikes");
}

// hp_tip_in_page (V4, a tip reply during a catch-up page): A holds 40 positions and a side branch L3..L7 forking at
// position 2 (L's, cut off). J (deferred store 4) catches up from A alone: after the first page J is at 4; the next page
// P is FetchBodies, its bodies held on the wire. (a) A tip request of L7 (heavier than J's best): FetchBodies, its body
// asked; the catch-up's page (fetch_tip, fetch_ms) unchanged. (b) A tip request of an id A does not hold: Keep, no
// ids: no locator step of the catch-up. No catch-up ask while P's bodies are out; then they arrive, J at A's tip.
void hp_tip_in_page() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    for (int i = 0; i < 2; ++i) {
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3400 + static_cast<std::uint32_t>(i));
    }
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    h.tick_monero();
    for (int i = 0; i < 5; ++i) ok = ok && mine_on(h, w, l.node, 3, 3410 + static_cast<std::uint32_t>(i));
    for (int i = 0; i < 38; ++i) {
        if (i % 12 == 0) h.tick_monero();
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 3420 + static_cast<std::uint32_t>(i));
    }
    w.edit = nullptr;
    const pb::Hash32 l7 = h[l.node].tree().best().id;
    std::set<pb::Hash32> lids;
    for (std::uint64_t x = 3; x <= 7; ++x)
        if (const std::optional<pb::Hash32> id = h[l.node].store().best_at(x)) {
            lids.insert(*id);
            w.q.push_back(FakeWire::Msg{1, 0, hp_carrier(h, l.node, *id)});
        }
    w.run();
    const pb::Hash32 tip = h[a.node].tree().best().id;
    ok = ok && lids.size() == 5 && h[a.node].tree().find(l7) != nullptr && h[a.node].tree().best().pos == 40;
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& cf) { cf.waiting_cap = 4; });
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t pa = w.id(j.node, a.node);
    w.connect(2, 0);
    w.run();  // the first page: the room's 4 bodies, placed
    const std::uint64_t pos1 = h[j.node].tree().best().pos;
    std::vector<std::vector<std::uint8_t>> held;
    std::size_t side_asked = 0;
    w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if (m.from == 0 && m.to == 2 && m.f[0] == pb::kOpFcCarrier) {
            held.push_back(m.f);
            m.f.clear();
        } else if (m.from == 2 && m.to == 0 && m.f[0] == pb::kOpFcGetCarrier) {
            pb::GetCarrier q;
            if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok())
                for (const pb::Hash32& id : q.ids) side_asked += lids.count(id);
        }
    };
    h.now += 1;
    rj.tick();
    w.run();  // P: the next page, FetchBodies; its bodies held
    const std::optional<pb::PathbRelayNode::CatchupView> v0 = rj.catchup_view(pa);
    const std::uint64_t asks0 = rj.stats().catchup_requests.load();
    rj.test_tip_headers(pa, pb::Hash32{}, l7);  // (a)
    w.run();
    const std::optional<pb::PathbRelayNode::CatchupView> v1 = rj.catchup_view(pa);
    rj.test_tip_headers(pa, pb::Hash32{}, seq32(0x5b));  // (b)
    w.run();
    const std::optional<pb::PathbRelayNode::CatchupView> v2 = rj.catchup_view(pa);
    const std::uint64_t asks2 = rj.stats().catchup_requests.load();
    h.now += 1;
    rj.tick();
    w.run();
    const std::uint64_t asks3 = rj.stats().catchup_requests.load();
    w.edit = nullptr;
    for (const std::vector<std::uint8_t>& f : held) rj.receive(pa, f);
    w.run();
    for (int i = 0; i < 120 && h[j.node].tree().best().id != tip; ++i) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    std::printf("  hp_tip_in_page: J at %llu after the first page; P's bodies held %zu; side bodies asked %zu; catch-up "
                "asks %llu -> %llu -> %llu; J at %llu of %llu\n",
                (unsigned long long)pos1, held.size(), side_asked, (unsigned long long)asks0, (unsigned long long)asks2,
                (unsigned long long)asks3, (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos);
    check(ok && pos1 >= 3 && v0 && v0->fetch_tip != pb::Hash32{} && !held.empty(),
          "hp_tip_in_page: setup (A at 40 with a side branch; J past the first page, the next page's bodies in flight)");
    check(v1 && v1->fetch_tip == v0->fetch_tip && v1->fetch_ms == v0->fetch_ms && side_asked >= 1,
          "hp_tip_in_page (a): a heavier tip reply (FetchBodies): its body asked; the catch-up's page unchanged");
    check(v2 && v2->step == v0->step && asks2 == asks0 && asks3 == asks0,
          "hp_tip_in_page (b): a tip reply Keep with no ids: no locator step; no catch-up ask while P's bodies are out");
    check(h[j.node].tree().best().id == tip && rj.stats().bans.load() == 0, "hp_tip_in_page: then J at A's tip; 0 bans");
}

// hp_stale_after_tip (V5, a stale catch-up reply after a tip request): a young lane (the tip request's from is
// position 0, the catch-up's from). A holds 4 positions and a side sibling t at position 4 (L's, sent to A alone).
// C1 (the catch-up, from position 0) to A, its reply F1 held past P-53: C1 retired; the tip request T (from position 0,
// stop t) is not sent while C1 is retired; F1 DROPs; T goes out and its reply, T's own, indexes t. V5e: C1 from a
// position A does not hold, F1 empty: the same. The relay: T waits in A's queue while C1 is retired and goes out once F1
// DROPs; t indexed; J at A's tip.
void hp_stale_after_tip() {
    const KatNet net;
    for (const bool empty : {false, true}) {
        const std::string tag = empty ? "hp_stale_after_tip (V5e, empty F1): " : "hp_stale_after_tip: ";
        Harness h(net);
        const std::size_t a = h.add(table0(net), true);
        const std::size_t l = h.add(table0(net), true);
        const std::size_t m = h.add(table0(net), true);
        const std::size_t j = h.add(table0(net), false);
        for (const std::size_t x : {a, l, m, j})  // A and L share positions 1..3; M and J hear nothing
            for (const std::size_t y : {a, l, m, j})
                if (x != y && !((x == a && y == l) || (x == l && y == a))) h.cut.insert({x, y});
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            h.mine(a, static_cast<std::size_t>(i), 3500 + static_cast<std::uint32_t>(i));
        }
        h.cut.insert({a, l});
        h.cut.insert({l, a});
        h.tick_monero();
        h.mine(a, 2, 3510);
        h.mine(l, 3, 3511);
        const pb::Hash32 ya = h[a].tree().best().id, yl = h[l].tree().best().id;
        (void)h[a].on_carrier(l, hp_carrier(h, l, yl));
        h.q.clear();
        const pb::Hash32 t = ya < yl ? yl : ya, tip = h[a].tree().best().id, g = h[j].tree().genesis().id;
        bool ok = ya != yl && h[a].tree().find(t) != nullptr && tip != t && h[a].tree().best().pos == 4;
        pb::Hash32 from = g;
        if (empty) {  // J holds M's position 1, which A does not hold
            h.mine(m, 4, 3520);
            const pb::Hash32 m1 = h[m].tree().best().id;
            (void)h[j].on_carrier(m, hp_carrier(h, m, m1));
            h.q.clear();
            from = m1;
            ok = ok && h[j].tree().find(m1) != nullptr && h[a].tree().find(m1) == nullptr;
        }
        check(ok && h[j].request_headers(a, from, tip, 64, h.now), tag + "setup; C1 = the catch-up's FC_GETHEADERS to A");
        const std::vector<std::uint8_t> f1 = h[a].serve_getheaders(j, h.q.back().frame, h.now).frames.at(0);
        h.q.clear();
        pb::HeadersReply r1;
        const bool dec = pb::decode_fc_headers(f1, 0, h[j].frame_bytes_headers(), pb::kRuledLaneParams, r1).ok();
        h.now += pb::kAbandonTimeoutDefault + 1;
        const std::size_t expired = h[j].tick(h.now);
        const bool t_now = h[j].request_headers(a, g, t, 64, h.now, HpOwner::Tip);
        check(dec && r1.headers.empty() == empty && expired == 1 && !t_now && hp_getheaders(h, j, a) == 0,
              tag + "C1 retired; the tip request T (from position 0 to t) is not sent while it is");
        const pb::PathbNode::HeadersOutcome o1 = h[j].on_headers(a, f1, h.now);
        check(o1.kind == HpK::Retired && o1.indexed == 0 && !hp_indexed(h[j], t), tag + "F1 DROPs (kind " + hp_kind(o1) + ")");
        check(h[j].request_headers(a, g, t, 64, h.now, HpOwner::Tip), tag + "T sent once F1 arrived");
        const std::vector<std::uint8_t> tf = h.q.back().frame;
        h.q.clear();
        const pb::PathbNode::HeadersOutcome o2 = h[j].on_headers(a, h[a].serve_getheaders(j, tf, h.now).frames.at(0), h.now);
        check(o2.owner == HpOwner::Tip && hp_indexed(h[j], t), tag + "T's reply answers T: t indexed (kind " + hp_kind(o2) + ")");
    }
    {
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay l = kat_relay(h, w, table0(net), true);
        w.connect(0, 1);
        w.run();
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3530 + static_cast<std::uint32_t>(i));
        }
        w.edit = [](FakeWire::Msg& m) {
            if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
        };
        h.tick_monero();
        ok = ok && mine_on(h, w, a.node, 2, 3540) && mine_on(h, w, l.node, 3, 3541);
        w.edit = nullptr;
        const pb::Hash32 ya = h[a.node].tree().best().id, yl = h[l.node].tree().best().id;
        w.q.push_back(FakeWire::Msg{1, 0, hp_carrier(h, l.node, yl)});
        w.run();
        const pb::Hash32 t = ya < yl ? yl : ya, tip = h[a.node].tree().best().id;
        ok = ok && ya != yl && h[a.node].tree().find(t) != nullptr && tip != t;
        KatRelay j = kat_relay(h, w, table0(net), false);
        pb::PathbRelayNode& rj = *j.relay;
        const std::uint64_t pa = w.id(j.node, a.node);
        std::vector<std::uint8_t> held;
        w.edit = [&held](FakeWire::Msg& m) {
            if (m.from == 0 && m.to == 2 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders && held.empty()) {
                held = m.f;
                m.f.clear();
            }
        };
        w.connect(2, 0);
        w.run();
        h.now += pb::kAbandonTimeoutDefault + 1;
        rj.tick();
        w.run();
        const std::optional<pb::PathbNode::HeaderSlot> slot = rj.with_node([&](pb::PathbNode& n) { return n.header_slot(pa); });
        const std::uint64_t tips0 = rj.stats().tip_header_requests.load();
        const std::size_t waiting0 = rj.header_waiting(pa);  // a tip request of A's re-offered receipts may wait as well
        rj.test_tip_headers(pa, pb::Hash32{}, t);
        const std::size_t waiting = rj.header_waiting(pa);
        const std::uint64_t tips1 = rj.stats().tip_header_requests.load();
        w.edit = nullptr;
        rj.receive(pa, held);
        w.run();
        const bool t_indexed = rj.with_node([&](pb::PathbNode& n) { return hp_indexed(n, t); });
        for (int i = 0; i < 20 && h[j.node].tree().best().id != tip; ++i) {
            h.now += 1;
            rj.tick();
            w.run();
        }
        std::printf("  hp_stale_after_tip (relay): C1 retired %d; T waiting %zu; tip requests %llu -> %llu -> %llu; retired "
                    "replies %llu; t indexed %d; J at %llu of %llu\n",
                    slot && slot->retired ? 1 : 0, waiting, (unsigned long long)tips0, (unsigned long long)tips1,
                    (unsigned long long)rj.stats().tip_header_requests.load(),
                    (unsigned long long)rj.stats().headers_retired_dropped.load(), t_indexed ? 1 : 0,
                    (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos);
        check(ok && !held.empty() && slot && slot->retired && waiting == waiting0 + 1 && tips1 == tips0,
              "hp_stale_after_tip (relay): C1 retired; T waits in A's queue (not sent)");
        check(rj.stats().headers_retired_dropped.load() == 1 && rj.stats().tip_header_requests.load() == tips0 + waiting && t_indexed
                      && h[j.node].tree().best().id == tip && rj.stats().bans.load() == 0,
              "hp_stale_after_tip (relay): F1 DROPs, T goes out, its reply indexes t; J at A's tip; 0 bans");
    }
}

// hp_side_in_page (V6, a join ticket during a catch-up): A holds 10 positions and a side branch s1, s2 forking at
// position 4. J's catch-up request C to A is open when a join ticket S (FC_GETHEADERS from the zero id) goes to A
// (link order C, S). (i) S of s2 (A holds it): C's reply reaches the node (J catches up), S's reply the ticket (two
// headers ending at s2). (ii) S of an id A does not hold: the ticket gets the empty reply; the node's catch-up intact.
// (iii) S dropped before its reply, then a node request C2 from position 4: S's reply DROPs (counted), C2 gets its own
// reply (nothing of s1, s2 at J).
void hp_side_in_page() {
    const KatNet net;
    for (int part = 0; part < 3; ++part) {
        const std::string tag = std::string("hp_side_in_page (") + (part == 0 ? "i" : part == 1 ? "ii" : "iii") + "): ";
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay l = kat_relay(h, w, table0(net), true);
        w.connect(0, 1);
        w.run();
        bool ok = true;
        for (int i = 0; i < 4; ++i) {
            if (i % 2 == 0) h.tick_monero();
            ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3600 + static_cast<std::uint32_t>(i));
        }
        w.edit = [](FakeWire::Msg& m) {
            if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
        };
        h.tick_monero();
        ok = ok && mine_on(h, w, l.node, 3, 3610) && mine_on(h, w, l.node, 3, 3611);
        for (int i = 0; i < 6; ++i) ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i % 5), 3620 + static_cast<std::uint32_t>(i));
        w.edit = nullptr;
        const pb::Hash32 s2 = h[l.node].tree().best().id;
        const std::optional<pb::Hash32> s1 = h[l.node].store().best_at(5);
        ok = ok && s1.has_value();
        if (ok) {
            w.q.push_back(FakeWire::Msg{1, 0, hp_carrier(h, l.node, *s1)});
            w.q.push_back(FakeWire::Msg{1, 0, hp_carrier(h, l.node, s2)});
            w.run();
        }
        const pb::Hash32 tip = h[a.node].tree().best().id;
        ok = ok && h[a.node].tree().find(s2) != nullptr && h[a.node].tree().best().pos == 10;
        KatRelay j = kat_relay(h, w, table0(net), false);
        pb::PathbRelayNode& rj = *j.relay;
        const std::uint64_t pa = w.id(j.node, a.node);
        pb::JoinTransport& port = rj.test_join_transport();
        if (part < 2) {
            std::optional<FakeWire::Msg> c;  // C held on the wire until S is sent behind it
            w.edit = [&c](FakeWire::Msg& m) {
                if (!c && m.from == 2 && m.to == 0 && !m.f.empty() && m.f[0] == pb::kOpFcGetHeaders) {
                    c = m;
                    m.f.clear();
                }
            };
            w.connect(2, 0);
            w.run();
            w.edit = nullptr;
            const pb::Hash32 stop = part == 0 ? s2 : seq32(0x66);
            const std::uint64_t ticket = port.send(pa, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, stop, 2}));
            if (c) w.q.push_front(*c);  // on the wire C before S, J's request order
            const std::vector<std::vector<std::uint8_t>> got = port.collect(ticket, pb::kAbandonTimeoutDefault);
            pb::HeadersReply sr;
            const bool dec = got.size() == 1
                             && pb::decode_fc_headers(got[0], 0, h[j.node].frame_bytes_headers(), pb::kRuledLaneParams, sr).ok();
            w.run();
            for (int i = 0; i < 6 && h[j.node].tree().best().id != tip; ++i) {
                h.now += 1;
                rj.tick();
                w.run();
            }
            const bool s_ok = part == 0 ? dec && sr.headers.size() == 2 && pb::receipt_id(sr.headers.back().own) == s2
                                        : dec && sr.headers.empty();
            std::printf("  %sC held %d; the ticket got %zu frame(s), %zu header(s); J at %llu of %llu\n", tag.c_str(), c ? 1 : 0,
                        got.size(), sr.headers.size(), (unsigned long long)h[j.node].tree().best().pos,
                        (unsigned long long)h[a.node].tree().best().pos);
            check(ok && c && s_ok && h[j.node].tree().best().id == tip && rj.stats().bans.load() == 0,
                  tag + (part == 0 ? "C's reply to the node (J at A's tip), S's reply (to s2) to the ticket"
                                   : "the ticket gets S's empty reply; the node's catch-up intact (J at A's tip)"));
            continue;
        }
        w.connect(2, 0);
        w.run();
        for (int i = 0; i < 6 && h[j.node].tree().best().id != tip; ++i) {
            h.now += 1;
            rj.tick();
            w.run();
        }
        const bool caught = h[j.node].tree().best().id == tip;
        const std::uint64_t d0 = rj.stats().drops.load();
        const std::uint64_t ticket = port.send(pa, pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, s2, 2}));
        port.drop(ticket);  // the attempt ends: its reply is dropped when it comes
        rj.test_tip_headers(pa, *h[a.node].store().best_at(4), tip);  // C2: a node request from position 4
        w.run();
        const std::uint64_t drops = rj.stats().drops.load() - d0;
        const bool side = rj.with_node([&](pb::PathbNode& n) { return hp_indexed(n, *s1) || hp_indexed(n, s2) || n.tree().find(s2) != nullptr; });
        std::printf("  %sJ caught up %d; drops %llu; s1 / s2 at J %d\n", tag.c_str(), caught ? 1 : 0, (unsigned long long)drops,
                    side ? 1 : 0);
        check(ok && caught && drops == 1 && !side && rj.stats().bans.load() == 0,
              tag + "the dropped ticket's late reply DROPs; C2 gets its own reply (nothing of s1, s2 at J)");
    }
}

// hp_ctxslot (V7): J (an empty store, not caught up) catches up from A. A's positions 1..5; the P_r X of positions 2..5
// is hidden at J; a side carrier s2 at position 2 (forking at 1, L's) has a later P_r Y (no carrier of A's chain reads
// it), hidden at J too. The catch-up C DEFERs
// on X; a tip request T of s2 DEFERs on Y. X resolves: C is asked again (under the catch-up), J at A's tip; kCtxTtlMs
// with Y hidden: no joiner offer (T's deferral is not the catch-up's); Y resolves: T asked again, s2 indexed.
void hp_ctxslot() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    std::set<pb::Hash32> hidden;
    const HiddenRows hrows(net.rows, hidden);
    const pb::FollowerBranchView hview(hrows);
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay l = kat_relay(h, w, table0(net), true);
    w.connect(0, 1);
    w.run();
    bool ok = true;
    h.tick_monero();
    ok = ok && mine_on(h, w, a.node, 0, 3700);  // position 1
    w.edit = [](FakeWire::Msg& m) {
        if ((m.from == 0 && m.to == 1) || (m.from == 1 && m.to == 0)) m.f.clear();
    };
    h.tick_monero();
    for (int i = 0; i < 4; ++i)  // positions 2..5: their P_r X
        ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(1 + i), 3701 + static_cast<std::uint32_t>(i));
    h.tick_monero();
    ok = ok && mine_on(h, w, l.node, 3, 3710);  // s2 at position 2: its P_r Y
    w.edit = nullptr;
    const pb::Hash32 s2 = h[l.node].tree().best().id, tip = h[a.node].tree().best().id;
    const std::optional<pb::Hash32> a2 = h[a.node].store().best_at(2);
    const pb::CarrierBodyV3* b2 = a2 ? h[a.node].bodies().get(*a2) : nullptr;
    const pb::CarrierBodyV3* bs = h[l.node].bodies().get(s2);
    ok = ok && b2 != nullptr && bs != nullptr;
    if (!ok) {
        check(false, "hp_ctxslot: setup");
        return;
    }
    const pb::Hash32 X = b2->own.blob.prev_id, Y = bs->own.blob.prev_id;
    w.q.push_back(FakeWire::Msg{1, 0, hp_carrier(h, l.node, s2)});
    w.run();
    for (std::uint64_t x = 1; x <= 5; ++x)
        if (const pb::CarrierBodyV3* bx = h[a.node].bodies().get(*h[a.node].store().best_at(x)))
            ok = ok && (x == 1 ? bx->own.blob.prev_id != X : bx->own.blob.prev_id == X) && bx->own.blob.prev_id != Y;
    ok = ok && X != Y && h[a.node].tree().find(s2) != nullptr && h[a.node].tree().best().id == tip;
    hidden.insert(X);
    hidden.insert(Y);
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, hide_blocks(hidden, hview), true);
    pb::PathbRelayNode& rj = *j.relay;
    const std::uint64_t pa = w.id(j.node, a.node);
    w.connect(2, 0);
    w.run();
    const std::uint64_t def0 = rj.stats().headers_ctx_deferred.load();
    rj.test_tip_headers(pa, pb::Hash32{}, s2);
    w.run();
    const std::uint64_t def1 = rj.stats().headers_ctx_deferred.load();
    const std::uint64_t pos0 = h[j.node].tree().best().pos;
    hidden.erase(X);  // X resolves
    const std::uint64_t re0 = rj.stats().headers_ctx_reasks.load();
    rj.on_monero_tip();
    w.run();
    for (int i = 0; i < 6 && h[j.node].tree().best().id != tip; ++i) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    const bool at_tip = h[j.node].tree().best().id == tip;
    const std::uint64_t re1 = rj.stats().headers_ctx_reasks.load();
    const std::uint64_t off0 = rj.stats().catchup_join_offers.load();
    for (int k = 0; k < 130; ++k) {  // 650 s: past kCtxTtlMs with Y hidden
        h.now += 5;
        rj.tick();
        w.run();
    }
    const std::uint64_t offers = rj.stats().catchup_join_offers.load() - off0;
    const bool s2_before = rj.with_node([&](pb::PathbNode& n) { return hp_indexed(n, s2); });
    hidden.erase(Y);  // Y resolves
    rj.on_monero_tip();
    w.run();
    const std::uint64_t re2 = rj.stats().headers_ctx_reasks.load();
    const bool s2_after = rj.with_node([&](pb::PathbNode& n) { return hp_indexed(n, s2); });
    std::printf("  hp_ctxslot: deferred %llu -> %llu; J at %llu, then %llu of %llu; reasks %llu -> %llu -> %llu; join offers %llu; "
                "s2 indexed %d -> %d\n",
                (unsigned long long)def0, (unsigned long long)def1, (unsigned long long)pos0,
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos,
                (unsigned long long)re0, (unsigned long long)re1, (unsigned long long)re2, (unsigned long long)offers,
                s2_before ? 1 : 0, s2_after ? 1 : 0);
    check(ok && def0 >= 1 && def1 == def0 + 1 && pos0 == 0, "hp_ctxslot: the catch-up DEFERs on X, the tip request on Y");
    check(at_tip && re1 == re0 + 1, "hp_ctxslot: X resolves: the catch-up asked again under its owner; J at A's tip");
    check(offers == 0, "hp_ctxslot: kCtxTtlMs with Y hidden: no joiner offer for the tip request's deferral");
    check(!s2_before && s2_after && re2 == re1 + 1, "hp_ctxslot: Y resolves: T asked again, s2 indexed");
}

// hp_firstround (V8): an empty store with the template gate on. J HELLOs A (A's tail wins: the first round opens and the
// catch-up C goes to A; A's reply held on the wire), then B (at position 0: no catch-up). A tip request T to B is
// answered first (B holds nothing of it): the first round stays open (templates held) until C's reply ends it.
void hp_firstround() {
    const KatNet net;
    Harness h(net);
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    bool ok = true;
    for (int i = 0; i < 4; ++i) ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3800 + static_cast<std::uint32_t>(i));
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay j = kat_relay(h, w, table0(net), false, false, nullptr, nullptr, nullptr, true);
    pb::PathbRelayNode& rj = *j.relay;
    std::vector<std::uint8_t> held;
    w.edit = [&held](FakeWire::Msg& m) {
        if (m.from == 0 && m.to == 2 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders && held.empty()) {
            held = m.f;
            m.f.clear();
        }
    };
    w.connect(2, 0);
    w.run();
    const bool open1 = h[j.node].first_round_open();
    w.connect(2, 1);
    w.run();
    const std::uint64_t tips0 = rj.stats().tip_header_requests.load();
    rj.test_tip_headers(w.id(j.node, b.node), pb::Hash32{}, seq32(0x7e));
    w.run();
    const bool sent = rj.stats().tip_header_requests.load() == tips0 + 1 && rj.header_waiting(w.id(j.node, b.node)) == 0;
    const bool open2 = h[j.node].first_round_open();
    const pb::TemplateStatus s2 = h[j.node].make_template(h.now).status;
    w.edit = nullptr;
    rj.receive(w.id(j.node, a.node), held);
    w.run();
    const bool open3 = h[j.node].first_round_open();
    for (int i = 0; i < 6 && h[j.node].tree().best().id != h[a.node].tree().best().id; ++i) {
        h.now += 1;
        rj.tick();
        w.run();
    }
    std::printf("  hp_firstround: open at C %d, after T's reply %d (status %d), after C's reply %d; J at %llu of %llu\n",
                open1 ? 1 : 0, open2 ? 1 : 0, static_cast<int>(s2), open3 ? 1 : 0,
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)h[a.node].tree().best().pos);
    check(ok && !held.empty() && open1 && sent, "hp_firstround: the first round open with C in flight; T to B answered");
    check(open2 && s2 == pb::TemplateStatus::CatchingUp, "hp_firstround: T's reply leaves the first round open (templates held)");
    check(!open3 && h[j.node].tree().best().id == h[a.node].tree().best().id, "hp_firstround: C's reply ends it; J at A's tip");
}

// hp_guard (V9, a server that sends a frame it was not asked for): C = J's request to S from position 1. S sends an extra
// FC_HEADERS (valid headers that hang on position 0), then its real reply: the extra frame DROPs (no BAN, no strike,
// nothing indexed), C stays open; C's real reply is judged (FetchBodies), J at S's tip; then a frame with no request
// open: DROP. C keeps its clock: with no real reply, C is retired P-53 after its send (the extra frame counted as its
// reply's arrival does not stop it).
void hp_guard() {
    const KatNet net;
    for (const bool late : {false, true}) {
        const std::string tag = late ? "hp_guard (no real reply): " : "hp_guard: ";
        Harness h(net);
        std::size_t s = 0, j = 0;
        j1stale_chain(h, net, s, j);
        const pb::Hash32 g = h[j].tree().genesis().id, tip = h[s].tree().best().id, c1 = *h[s].store().best_at(1);
        (void)h[j].on_carrier(s, hp_carrier(h, s, c1));
        h.q.clear();
        const std::uint64_t t0 = h.now;
        check(h[j].request_headers(s, c1, tip, 64, h.now), tag + "C = FC_GETHEADERS(from position 1)");
        const std::vector<std::uint8_t> cf = h.q.back().frame;
        h.q.clear();
        const std::vector<std::uint8_t> extra =
                h[s].serve_getheaders(j, pb::encode_fc_getheaders(pb::GetHeaders{0, g, tip, 64}), h.now).frames.at(0);
        h[j].headers_arrived(s);  // the extra frame took C's place in the link order
        const pb::PathbNode::HeadersOutcome e = h[j].on_headers(s, extra, h.now);
        const std::optional<pb::PathbNode::HeaderSlot> slot = h[j].header_slot(s);
        check(e.kind == HpK::Unsolicited && e.indexed == 0 && pb::PathbNodeTestAccess::headers(h[j]).size() == 0 && slot
                      && !slot->retired,
              tag + "the extra frame (another from) DROPs: no BAN, no strike, nothing indexed; C open (kind " + hp_kind(e) + ")");
        if (late) {
            h.now = t0 + pb::kAbandonTimeoutDefault;
            const std::size_t e1 = h[j].tick(h.now);
            h.now = t0 + pb::kAbandonTimeoutDefault + 1;
            const std::size_t e2 = h[j].tick(h.now);
            const std::optional<pb::PathbNode::HeaderSlot> s2 = h[j].header_slot(s);
            check(e1 == 0 && e2 == 1 && s2 && s2->retired, tag + "C keeps its clock: retired P-53 after its send");
            continue;
        }
        const pb::PathbNode::HeadersOutcome o = h[j].on_headers(s, h[s].serve_getheaders(j, cf, h.now).frames.at(0), h.now);
        check(o.kind == HpK::FetchBodies && o.fork_pos == 1, tag + "C's real reply is judged: FetchBodies (kind " + hp_kind(o) + ")");
        h.pump();
        check(h[j].tree().best().id == tip, tag + "J at S's tip");
        const pb::PathbNode::HeadersOutcome u = h[j].on_headers(s, extra, h.now);
        check(u.kind == HpK::Unsolicited && u.owner == HpOwner::None, tag + "a frame with no request open: DROP");
    }
}

// hp_crawl (V2 with #2047's catch-up vectors): A, B and C hold 300 positions (one page); J, empty, catches up from all
// three: one catch-up request per server (its page in flight until its last asked body is placed, then J holds every
// HELLO tip); J at the tip within 60 s; 0 bans.
void hp_crawl() {
    const KatNet net;
    Harness h(net);
    h.headers_frame = 700000;
    FakeWire w;
    KatRelay a = kat_relay(h, w, table0(net), true);
    KatRelay b = kat_relay(h, w, table0(net), true);
    KatRelay c = kat_relay(h, w, table0(net), true);
    const std::uint64_t n = 300;
    const bool ok = catch_chain(h, w, a, b, c, n, 39000);
    const pb::Hash32 tip = h[a.node].tree().best().id;
    KatRelay j = kat_relay(h, w, table0(net), false);
    w.connect(3, 0);
    w.connect(3, 1);
    w.connect(3, 2);
    int secs = 0;
    for (; secs < 600 && h[j.node].tree().best().id != tip; ++secs)
        catch_second(h, w, {a.relay.get(), b.relay.get(), c.relay.get(), j.relay.get()});
    const std::uint64_t asks = j.relay->stats().catchup_requests.load();
    std::printf("  hp_crawl: chain %d; J at %llu of %llu after %d s; catch-up asks %llu; bans %llu\n", ok ? 1 : 0,
                (unsigned long long)h[j.node].tree().best().pos, (unsigned long long)n, secs, (unsigned long long)asks,
                (unsigned long long)j.relay->stats().bans.load());
    check(ok && h[j.node].tree().best().id == tip && secs <= 60 && j.relay->stats().bans.load() == 0,
          "hp_crawl: J reaches the tip within 60 s (" + std::to_string(secs) + " s); 0 bans");
    check(asks == 3, "hp_crawl: one catch-up request per server for a chain of one page (asks " + std::to_string(asks) + ")");
}

// hp_qbound (B-1): a peer's waiting tip-header requests and its tip deferrals are bounded by P-47 (the deferred store's
// cap), the entries whose parked objects no longer wait leaving first. B's header request to A is retired (A's reply
// held past P-53); A then sends junk receipts with distinct unknown tips (each DEFERs TipUnknown before any PoW row).
// (a) 20,000 of them: B's queue for A stays within P-47; 0 strikes, 0 bans; B's catch-up from C (an honest second
// server) completes. (b) deferred store 16, receipt park 6: 16 junk receipts wait (10 of them tied to receipts the park
// dropped); the 17th: the entries of the dropped receipts leave, the queue holds the parked receipts' requests only.
// (c) the deferrals: the catch-up keeps one; tip deferrals within P-47, those whose objects no longer wait leaving
// first. (d) receipt park 6: 20,000 junk receipts with one unknown tip (distinct nonces): one waiting request; the
// objects it carries at most the parked ones.
void hp_qbound() {
    const KatNet net;
    const auto junk = [](const pb::ReceiptBodyV3& base, std::uint32_t k) {
        pb::ReceiptBodyV3 r = base;
        r.side.tip.fill(0x5C);
        for (int i = 0; i < 4; ++i) r.side.tip[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(k >> (8 * i));
        return *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{r}, pb::kRuledLaneParams);
    };
    // A (0) and the server C (2) hold A's chain; B (1) connects to A with A's FC_HEADERS to B held past P-53
    const auto retired_b = [](Harness& h, FakeWire& w, KatRelay& a, KatRelay& b, std::optional<pb::ReceiptBodyV3>& base) {
        bool ok = true;
        for (int i = 0; i < 2; ++i) {
            h.tick_monero();
            ok = ok && mine_on(h, w, a.node, static_cast<std::size_t>(i), 3900 + static_cast<std::uint32_t>(i));
        }
        if (const std::optional<pb::PathbJob> j = h.job(a.node, 3, 3910)) {
            pb::ReceiptBodyV3 r = j->body;
            r.blob.nonce = 3910;
            base = r;
        }
        w.edit = [](FakeWire::Msg& m) {
            if (m.from == 0 && m.to == 1 && !m.f.empty() && m.f[0] == pb::kOpFcHeaders) m.f.clear();
        };
        w.connect(1, 0);
        w.run();
        h.now += pb::kAbandonTimeoutDefault + 1;
        b.relay->tick();
        w.run();
        w.edit = nullptr;
        const std::uint64_t pa = w.id(b.node, a.node);
        const std::optional<pb::PathbNode::HeaderSlot> s = b.relay->with_node([&](pb::PathbNode& n) { return n.header_slot(pa); });
        return ok && base.has_value() && s && s->retired;
    };
    {
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false);
        KatRelay c = kat_relay(h, w, table0(net), true);
        w.connect(0, 2);
        w.run();
        std::optional<pb::ReceiptBodyV3> base;
        const bool ok = retired_b(h, w, a, b, base) && h[c.node].tree().best().id == h[a.node].tree().best().id;
        pb::PathbRelayNode& rb = *b.relay;
        const std::uint64_t pa = w.id(b.node, a.node);
        const std::size_t bound = static_cast<std::size_t>(h[b.node].deferred_cap());
        std::size_t peak = 0;
        const auto t0 = std::chrono::steady_clock::now();
        for (std::uint32_t k = 0; ok && k < 20000; ++k) {
            rb.receive(pa, junk(*base, k));
            w.run();
            peak = std::max(peak, rb.header_waiting(pa));
        }
        const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        const pb::PathbRelayStats& st = rb.stats();
        const std::size_t waiting = rb.header_waiting(pa);
        w.connect(1, 2);
        w.run();
        const pb::Hash32 tip = h[c.node].tree().best().id;
        for (int i = 0; i < 20 && h[b.node].tree().best().id != tip; ++i) {
            h.now += 1;
            rb.tick();
            w.run();
        }
        std::printf("  hp_qbound (a): 20,000 junk receipts in %.1f s: B's queue for A %zu (peak %zu, P-47 %zu), parked "
                    "receipts %zu, reclaimed %llu, dropped %llu; strikes %llu, bans %llu; B at %llu of %llu\n",
                    secs, waiting, peak, bound, rb.parked_receipts(), (unsigned long long)st.header_wants_reclaimed.load(),
                    (unsigned long long)st.header_wants_dropped.load(), (unsigned long long)rb.strikes_of(pa),
                    (unsigned long long)st.bans.load(), (unsigned long long)h[b.node].tree().best().pos,
                    (unsigned long long)h[c.node].tree().best().pos);
        check(ok && peak <= bound && waiting >= 1 && rb.strikes_of(pa) == 0 && st.bans.load() == 0,
              "hp_qbound (a): 20,000 junk receipts from a peer whose slot is retired: its queue within P-47 (peak " +
                      std::to_string(peak) + " of " + std::to_string(bound) + "); 0 strikes, 0 bans");
        check(h[b.node].tree().best().id == tip, "hp_qbound (a): B's catch-up from the honest server C completes");
    }
    {
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& cf) {
            cf.waiting_cap = 16;
            cf.pending_cap = 6;
        });
        std::optional<pb::ReceiptBodyV3> base;
        const bool ok = retired_b(h, w, a, b, base);
        pb::PathbRelayNode& rb = *b.relay;
        const std::uint64_t pa = w.id(b.node, a.node);
        for (std::uint32_t k = 0; ok && k < 16; ++k) {
            rb.receive(pa, junk(*base, 100 + k));
            w.run();
        }
        const std::size_t w16 = rb.header_waiting(pa);
        rb.receive(pa, junk(*base, 200));
        w.run();
        const std::size_t w17 = rb.header_waiting(pa), parked = rb.parked_receipts();
        // (c) the deferrals of A at B
        const pb::Hash32 g = h[b.node].tree().genesis().id, x = mon_block(kPoolH);
        for (std::uint8_t k = 0; k < 3; ++k) rb.test_defer_headers(pa, HpOwner::CatchUp, seq32(0x40 + k), seq32(0x50), x);
        for (std::uint8_t k = 0; k < 16; ++k) rb.test_defer_headers(pa, HpOwner::Tip, g, seq32(0x60 + k), x, seq32(0x90 + k));
        const std::size_t d16 = rb.header_deferred(pa, HpOwner::Tip);
        rb.test_defer_headers(pa, HpOwner::Tip, g, seq32(0x80), x);  // untied
        const std::size_t d17 = rb.header_deferred(pa, HpOwner::Tip);
        for (std::uint8_t k = 0; k < 20; ++k) rb.test_defer_headers(pa, HpOwner::Tip, g, seq32(0xA0 + k), x);
        const std::size_t d37 = rb.header_deferred(pa, HpOwner::Tip), dc = rb.header_deferred(pa, HpOwner::CatchUp);
        std::printf("  hp_qbound (b): queue %zu after 16, %zu after 17 (parked receipts %zu); (c) tip deferrals %zu, %zu, "
                    "%zu; the catch-up's %zu\n",
                    w16, w17, parked, d16, d17, d37, dc);
        check(ok && w16 == 16 && parked == 6 && w17 == parked,
              "hp_qbound (b): at P-47 the requests of receipts the park dropped leave first: the queue holds the parked "
              "receipts' (" + std::to_string(w17) + ")");
        check(d16 == 16 && d17 == 1 && d37 == 16 && dc == 1,
              "hp_qbound (c): tip deferrals within P-47 (those whose objects no longer wait leave first); the catch-up "
              "keeps one deferral");
    }
    {
        Harness h(net);
        FakeWire w;
        KatRelay a = kat_relay(h, w, table0(net), true);
        KatRelay b = kat_relay(h, w, table0(net), false, false, nullptr, [](pb::PathbNodeConfig& cf) { cf.pending_cap = 6; });
        std::optional<pb::ReceiptBodyV3> base;
        const bool ok = retired_b(h, w, a, b, base);
        pb::PathbRelayNode& rb = *b.relay;
        const std::uint64_t pa = w.id(b.node, a.node);
        std::size_t peak = 0, peak_parked = 0;
        bool within = true;
        for (std::uint32_t k = 0; ok && k < 20000; ++k) {
            pb::ReceiptBodyV3 r = *base;
            r.side.tip.fill(0x6D);
            r.blob.nonce = 50000 + k;
            rb.receive(pa, *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{r}, pb::kRuledLaneParams));
            w.run();
            const std::size_t objs = rb.header_waiting_objects(pa), parked = rb.parked_receipts() + h[b.node].deferred().size();
            peak = std::max(peak, objs);
            peak_parked = std::max(peak_parked, parked);
            within = within && objs <= parked;
        }
        std::printf("  hp_qbound (d): 20,000 junk receipts, one tip: waiting %zu, objects %zu (peak %zu), parked %zu (peak %zu); "
                    "strikes %llu, bans %llu\n",
                    rb.header_waiting(pa), rb.header_waiting_objects(pa), peak, rb.parked_receipts(), peak_parked,
                    (unsigned long long)rb.strikes_of(pa), (unsigned long long)rb.stats().bans.load());
        check(ok && rb.header_waiting(pa) == 1 && within && peak <= 7 && rb.strikes_of(pa) == 0 && rb.stats().bans.load() == 0,
              "hp_qbound (d): one waiting request for one tip; the objects it carries at most the parked ones (peak " +
                      std::to_string(peak) + "); 0 strikes, 0 bans");
    }
}

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_node_kat\n");
    return run_sections("v37_xmr_pathb_node_kat",
                        {
                                {"genesis", genesis, 0},
                                {"relay", relay, 1},
                                {"race", race, 0},
                                {"racelate", racelate, 0},
                                {"raceskip", raceskip, 0},
                                {"carriage", carriage, 0},
                                {"feediverse", feediverse, 1},
                                {"repend", repend, 0},
                                {"n3", n3, 0},
                                {"own", own_share, 0},
                                {"m23", m23, 0},
                                {"restart", restart, 1},
                                {"n5", n5, 0},
                                {"hold", hold_kind2, 0},
                                {"c48", c48, 0},
                                {"rrfix3", rrfix3, 3},
                                {"deep", deep, 0},
                                {"joinserve", joinserve, 11},
                                {"n7b2", n7b2, 1},
                                {"startup", startup, 0},
                                {"poison", poison, 0},
                                {"joinpages", joinpages, 1},
                                {"tokens", tokens, 0},
                                {"receive", receive, 3},
                                {"hellobound", hellobound, 0},
                                {"base", base, 0},
                                {"boundary", boundary, 1},
                                {"timers", timers, 0},
                                {"j1stale", j1stale, 0},
                                {"relayj1stale", relayj1stale, 0},
                                {"hdrstrike", hdrstrike, 0},
                                {"hdrseed", hdrseed, 0},
                                {"catchpage", catchpage, 46},
                                {"catchhold", catchhold, 7},
                                {"catchslow", catchslow, 8},
                                {"catchgone", catchgone, 3},
                                {"catchlost", catchlost, 1},
                                {"catchfull", catchfull, 0},
                                {"hp_stale", hp_stale, 0},
                                {"hp_tipkeep", hp_tipkeep, 2},
                                {"hp_tip_in_page", hp_tip_in_page, 0},
                                {"hp_stale_after_tip", hp_stale_after_tip, 0},
                                {"hp_side_in_page", hp_side_in_page, 0},
                                {"hp_ctxslot", hp_ctxslot, 0},
                                {"hp_firstround", hp_firstround, 0},
                                {"hp_guard", hp_guard, 0},
                                {"hp_crawl", hp_crawl, 7},
                                {"hp_qbound", hp_qbound, 53},
                                {"buckets", buckets, 1},
                                {"relaytok", relaytok, 0},
                                {"relaym4", relaym4, 0},
                                {"relaybudget", relaybudget, 0},
                                {"relayfetch", relayfetch, 0},
                                {"relaysmoke", relaysmoke, 0},
                                {"relayq", relayq, 0},
                                {"relayindex", relayindex, 0},
                                {"relayp15", relayp15, 0},
                                {"relayp15rx", relayp15rx, 0},
                                {"ownbound", ownbound, 0},
                                {"deferfound", deferfound, 0},
                                {"blockblob", blockblob, 0},
                                {"alarmbound", alarmbound, 0},
                                {"relaystale", relaystale, 4},
                                {"relaytip", relaytip, 0},
                                {"relaysq", relaysq, 0},
                                {"revrx_drain", revrx_drain, 0},
                                {"drainban", drainban, 0},
                                {"drainstrike", drainstrike, 0},
                                {"drainhonest", drainhonest, 0},
                                {"draingone", draingone, 0},
                                {"relayrxhdr", relayrxhdr, 0},
                                {"hdrnohash", hdrnohash, 0},
                                {"relayrxnohash", relayrxnohash, 0},
                                {"relayrxtype", relayrxtype, 0},
                                {"relaystalem", relaystalem, 0},
                                {"relayrxbind", relayrxbind, 0},
                                {"relaymaxpage", relaymaxpage, 0},
                                {"rev99_complete", rev99_complete, 0},
                                {"ownrx", ownrx, 0},
                                {"relayrxbindr", relayrxbindr, 0},
                                {"relayrxbindk", relayrxbindk, 0},
                                {"relayp15once", relayp15once, 0},
                                {"relayverdictlog", relayverdictlog, 0},
                                {"relayparkstrike", relayparkstrike, 0},
                                {"repevict", repevict, 0},
                                {"openstate", openstate, 0},
                                {"opendead", opendead, 0},
                                {"statusperiod", statusperiod, 0},
                                {"ownorphan", ownorphan, 0},
                                {"liveness", liveness, 0},
                                {"wingolden", wingolden, 0},
                                {"wingoldenmb", wingoldenmb, 0},
                                {"relayomit", relayomit, 0},
                                {"relayomitgone", relayomitgone, 0},
                                {"omitrules", omitrules, 0},
                                {"omitfresh", omitfresh, 0},
                                {"omitopen", omitopen, 1},
                                {"omitcompete", omitcompete, 0},
                                {"omitwalk", omitwalk, 0},
                                {"omithonest", omithonest, 0},
                                {"relayswitchlog", relayswitchlog, 0},
                                {"relaybindswitch", relaybindswitch, 0},
                                {"relayrepend", relayrepend, 0},
                                {"revrepend2", revrepend2, 0},
                                {"relayrpark", relayrpark, 0},
                                {"relayhdrctx", relayhdrctx, 0},
                                {"relayrbindr", relayrbindr, 0},
                                {"relayrparkseal", relayrparkseal, 0},
                                {"relayrparkgone", relayrparkgone, 0},
                                {"revjunkbig", revjunkbig, 13},
                                {"revdueorder", revdueorder, 0},
                                {"relayqfull", relayqfull, 0},
                                {"relayreoffercap", relayreoffercap, 0},
                                {"relayrxbind2", relayrxbind2, 0},
                                {"ownrxrun", ownrxrun, 0},
                                {"relayp40", relayp40, 0},
                                {"relayp50", relayp50, 0},
                                {"relayjoint", relayjoint, 2},
                                {"relaypace", relaypace, 9},
                                {"regtestk30", regtestk30, 0},
                                {"prune_young", prune_young, 12, "prune_chain"},
                                {"prune_default", prune_default, 5, "prune_chain"},
                                {"prune_flags", prune_flags, 4, "prune_chain"},
                                {"prune_side", prune_side, 0, "prune_chain"},
                                {"sideprune", sideprune, 5, "prune_chain"},
                                {"prune_hold", prune_hold, 4, "prune_chain"},
                                {"below", below, 111},
                                {"jobslot", jobslot, 1},
                                {"minerwithdraw", minerwithdraw, 0},
                                {"minerflush", minerflush, 0},
                                {"ctxgate", ctxgate, 1},
                                {"parkidx", parkidx, 0},
                                {"catchjoin", catchjoin, 0},
                                {"catchwalk", catchwalk, 0},
                                {"catchgate", catchgate, 0},
                                {"gateprobe2", gateprobe2, 16},
                                {"gatepass", gatepass, 4},
                                {"gatepassidle", gatepassidle, 10},
                                {"gatenowin", gatenowin, 3},
                                {"caughtdrain", caughtdrain, 8},
                                {"drainwindow", drainwindow, 5},
                                {"draindrop", draindrop, 5},
                                {"adoptdrain", adoptdrain, 1},
                                {"gatesib", gatesib, 30},
                                {"gatebad", gatebad, 1},
                                {"gatehand", gatehand, 1},
                                {"gatejp", gatejp, 1},
                                {"gatejpnp", gatejpnp, 1},
                                {"drainevict", drainevict, 1},
                                {"drainleft", drainleft, 1},
                                {"gatedepart", gatedepart, 1},
                                {"gatelast", gatelast, 1},
                                {"gateattempt", gateattempt, 1},
                                {"gateexcl", gateexcl, 1},
                                {"gatens", gatens, 1},
                                {"gaterefused", gaterefused, 1},
                                {"gatewindow", gatewindow, 1},
                                {"gatepoison", gatepoison, 1},
                                {"gatekept", gatekept, 1},
                                {"gateadopt", gateadopt, 1},
                                {"gatewin", gatewin, 18},
                                {"deepband", deepband, 10},
                                {"deeppruned", deeppruned, 85},
                                {"deepncu", deepncu, 4},
                                {"emptycont", emptycont, 3},
                                {"orphan", orphan, 2},
                                {"pausedefer", pausedefer, 2},
                                {"pagefold", pagefold, 1},
                                {"stoppages", stoppages, 1},
                                {"sharedpage", sharedpage, 1},
                                {"sharedforge", sharedforge, 1},
                                {"recordcarry", recordcarry, 1},
                                {"tipside", tipside, 1},
                                {"basedrop", basedrop, 1},
                                {"basedropnext", basedropnext, 2},
                                {"seedprune", seedprune, 6},
                                {"jpnolink", jpnolink, 1},
                                {"rxpause", rxpause, 2},
                                {"tokenpause", tokenpause, 2},
                                {"adoptdefer", adoptdefer, 3},
                                {"adoptresume", adoptresume, 12},
                                {"rootevid", rootevid, 12},
                                {"fd1mark", fd1mark, 12},
                                {"e185mark", e185mark, 12},
                                {"rootevidneg", rootevidneg, 12},
                                {"jpdeclined", jpdeclined, 4},
                                {"pauseorphan", pauseorphan, 2},
                                {"foldsplit", foldsplit, 1},
                                {"bestmove", bestmove, 1},
                                {"remerge", remerge, 1},
                                {"catchrestart", catchrestart, 0},
                                {"catchlocator", catchlocator, 0},
                                {"pwalk", pwalk, 99},
                                {"pwalkshapes_1000_8", pwalkshapes<1000, 8>, 116},
                                {"pwalkshapes_500_8", pwalkshapes<500, 8>, 117},
                                {"pwalkshapes_1000_10", pwalkshapes<1000, 10>, 108},
                                {"pwalkshapes_1500_8", pwalkshapes<1500, 8>, 84},
                                {"pwalkshapes_2000_5", pwalkshapes<2000, 5>, 75},
                                {"pwalkfull", pwalkfull, 102},
                                {"pwalkcrawl", pwalkcrawl, 111},
                                {"pwalkstall", pwalkstall, 94},
                                {"pwalklost", pwalklost, 1},
                                {"pwalksilent", pwalksilent, 3},
                                {"rcsilent", rcsilent, 6},
                                {"rclate", rclate, 5},
                                {"rcrehello", rcrehello, 0},
                                {"pwalkgone", pwalkgone, 0},
                                {"pwalkjunk", pwalkjunk, 0},
                                {"pwalkskipfull", pwalkskipfull, 0},
                                {"pwalkasked", pwalkasked, 1},
                                {"pwalkdup", pwalkdup, 0},
                                {"sealall", sealall, 1},
                                {"placedcopy", placedcopy, 0},
                                {"placedvariant", placedvariant, 0},
                                {"revnotcarrier", revnotcarrier, 0},
                                {"statustime", statustime, 0},
                                {"statusroots", statusroots, 0},
                                {"catchkeep", catchkeep, 0},
                                {"catchlight", catchlight, 0},
                                {"catchoffer", catchoffer, 0},
                                {"revcatchundec", revcatchundec, 0},
                                {"catchtok", catchtok, 0},
                                {"catchheavy", catchheavy, 0},
                                {"catchctx", catchctx, 0},
                                {"floorpr", floorpr, 0},
                        },
                        argc, argv);
}
