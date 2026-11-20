// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_recovery_trace_kat.cpp
// The relay node's handling of honest objects, traced step by step: relay
// nodes in manual mode over the hand-delivered wire (pathb_kat_relay.hpp),
// each case a fixed scenario. A case's trace lists, per step, every carrier
// placed, every receipt pending, every request frame queued on the wire, the
// frames and receipts parked and run again, the penalties, the links and the
// relay's counters; its sha256 must equal the case's golden digest.
//   --list            the cases
//   --only=A,B        run these cases only
//   --print=A         print a case's trace
//   --traces=FILE     write every case's trace to FILE
//   --digests         print each case's digest
// Measurement modes (each prints its figures and returns; no golden):
//   --bench=n         V's thread CPU for one placement that runs n parked objects again, minus the same placement
//                     with none parked, per re-run (receipts on an unknown tip; own + 16 and own + 1 frames)
//   --benchnb=n       --bench on two nodes loaded from a store of the N(B) shape (AJBREPS repetitions, default 5;
//                     AJBBENCHKINDS a subset of 012; AJBNBWARM=0 a cold timed placement; AJBNBPROBE the window's ids
//                     copy and payee digest timed)
//   --benchnbtrace=n  --benchnb's shapes with the tracer on: each run's trace digest
//   --benchfirst=n    N(B): n fresh receipts, own + 1 and own + 16 carriers judged once each on a held window and key
//                     set; the first, second and third-and-later judgments on a fresh window entry timed apart
//   --benchrepeat=n   N(B): one Mismatch body and one MissingRef body, each judged n times
//   --benchdrain=n    n carriers DEFERred on their parent, placed through the drain when the parent arrives
//   --bencht27=n      one maintenance tick with a move of the best record and n parked own + 16 frames whose own P_r
//                     is not held (AJBT27BODY=max: the largest legal carried bodies)
//   --outsweep=CASE:STEP:LENS  CASE with every node's RandomX failing over steps [s, s + len), s = 0, STEP, ...
//   AJBMEMO=1         the trace adds a line for each change of a node's RandomX memo order (Mh N DIGEST/SIZE)
//   AJBOUT=s,len      --print / --traces with that one outage
// AJBMEMO and AJBOUT are honoured only with --print / --traces (the digests are then printed, not compared); a golden
// run refuses them. An unknown argument, a case name that does not exist and an empty selection fail.
// The trace (one line per event, each led by its step):
//   @ LABEL t=T       the step: d F>T OP (a frame delivered; "x": cut in flight, "down": its link down), t N (node N's
//                     maintenance tick), a TEXT (a scripted action); T the harness clock (s)
//   S F>T GH|GC|GB|GX a request frame queued: FC_GETHEADERS (from, stop, max), FC_GETCARRIER (ids; b: want_bodies),
//                     FC_GETBUCKETS (at, bins), FB_GETCTX (ids)
//   P N ID POS        a carrier placed at node N; R / r N ID: a receipt pending / no longer pending
//   K N DG ID CAUSE   a frame parked; k N DG C1>C2: taken and parked again; U N DG CAUSE placed|out: it left the store
//   Q N p=X d=Y       the relay's parked receipts (X) and those due (Y); I N X: its re-run index; W N X: context wants;
//                     J N X: verify jobs waiting for a token
//   L N PEER up|down  a link; X N PEER +K: strike tokens on a peer's link
//   V N ROW/VERDICT +K  admission verdicts by row; C N NAME +K: a relay counter
//   E N PEER LEVEL    at the end: the peer's valid-object budget (P-15)
//   Y N c=C h=H e=E   the cases that follow the key cache: a change of node N's key cache (computations, hits,
//                     entries)
//   A N END judged rR xX tK lL sS  a join step of node N: its attempt's end; the row and position of the last frame the
//                     attempt judged (an attempt that ends before it judges a frame keeps the previous one's); tokens;
//                     L; whether the node switched (A N -: no attempt run)
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_relay_node.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"
#include "sharechain/v37/v37_hash.hpp"

#include "pathb_kat_check.hpp"
#include "pathb_kat_join.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_kat_relay.hpp"
#include "pathb_ratchet_sim.hpp"

namespace c2pool::xmr::pathb {
// The KAT's view of a node's private state.
struct PathbNodeTestAccess {
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
    // The bucket bodies of the sealed bins dropped from the node's store (`keep`: those of the bins sealed at the best
    // tip's last `keep` positions stay), and its window cache emptied.
    static void drop_buckets(PathbNode& n, std::uint64_t keep = 0) {
        std::uint64_t from = UINT64_MAX;
        if (keep != 0) {
            const LaneView v = n.store_->view_at(n.store_->best_tip());
            from = v.ok() && v.pos() > keep ? n.store_->b0() + v.leaf_count_at(v.pos() - keep) : 0;
        }
        n.store_->prune_buckets(from);
        *n.windows_ = WindowCache{};
    }
    // A key reference the node no longer knows.
    static void forget_ref(PathbNode& n, const Hash32& id) {
        n.refs_->erase(id);
        *n.windows_ = WindowCache{};
    }
    // The order of the node's RandomX memo, as a digest of its keys (id, d, seed) and its size.
    static std::string memo_digest(const PathbNode& n) {
        std::vector<std::uint8_t> all;
        for (const auto& k : n.memo_order_) {
            all.insert(all.end(), k.id.begin(), k.id.end());
            for (int i = 0; i < 8; ++i) all.push_back(static_cast<std::uint8_t>(k.d >> (8 * i)));
            all.insert(all.end(), k.seed.begin(), k.seed.end());
        }
        const auto d = ::v37::sha256(all.data(), all.size());
        return ::pathb_kat::hex(d.data(), 6) + "/" + std::to_string(n.memo_order_.size());
    }
    // The key cache the node's admissions use (its own, or the adopted state's).
    static KeyCache& keys(PathbNode& n) { return *n.keys_; }
    static const KeyCache& keys(const PathbNode& n) { return *n.keys_; }
};
}  // namespace c2pool::xmr::pathb

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace rly = ::c2pool::v37n::xmr::relay;

namespace {

using Missing = pb::Missing;
using Hash32 = pb::Hash32;
using Frame = std::vector<std::uint8_t>;

std::string h6(const Hash32& x) { return hex(x.data(), 6); }

const char* cause_name(Missing m) {
    switch (m) {
        case Missing::ParentUnknown: return "ParentUnknown";
        case Missing::OwnChainDeep: return "OwnChainDeep";
        case Missing::TipUnknown: return "TipUnknown";
        case Missing::TipHeaders: return "TipHeaders";
        case Missing::Boundary: return "Boundary";
        case Missing::ClosureBodies: return "ClosureBodies";
        case Missing::Closure: return "Closure";
        case Missing::EpochGrace: return "EpochGrace";
        case Missing::Hold: return "Hold";
        case Missing::MoneroBlock: return "MoneroBlock";
        case Missing::Seed: return "Seed";
        case Missing::Bodies: return "Bodies";
        case Missing::TipBodies: return "TipBodies";
        case Missing::MissingBucket: return "MissingBucket";
        case Missing::MissingEntries: return "MissingEntries";
        case Missing::MissingWeights: return "MissingWeights";
        case Missing::MissingBlock: return "MissingBlock";
        case Missing::MissingRef: return "MissingRef";
        case Missing::NodeInternal: return "NodeInternal";
        case Missing::ClaimAlarm: return "ClaimAlarm";
        case Missing::CopyDeferred: return "CopyDeferred";
    }
    return "?";
}

const char* verdict_name(std::size_t v) {
    static const char* n[] = {"Strike", "Refuse", "Defer", "Duplicate", "Ban", "AdmitCarrier", "AdmitPending", "Drop"};
    return v < sizeof n / sizeof n[0] ? n[v] : "?";
}

std::string op_name(std::uint8_t op) {
    switch (op) {
        case 0: return "-";
        case pb::kOpFbHello: return "HELLO";
        case pb::kOpFbReceipts: return "RC";
        case pb::kOpFbGetCtx: return "GX";
        case pb::kOpFbCtx: return "CX";
        case pb::kOpFcCarrier: return "CA";
        case pb::kOpFcGetCarrier: return "GC";
        case pb::kOpFcGetHeaders: return "GH";
        case pb::kOpFcHeaders: return "HD";
        case pb::kOpFcGetBuckets: return "GB";
        case pb::kOpFcBuckets: return "BK";
        default: return "0x" + hex(&op, 1);
    }
}

// A carrier frame's own id (nullopt: not a carrier frame).
std::optional<Hash32> carrier_id(const Frame& f) {
    if (f.size() <= pb::kFrameHeaderBytes || f[0] != pb::kOpFcCarrier) return std::nullopt;
    pb::CarrierBodyV3 c;
    if (pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                   pb::CarrierLimits{1u << 20, pb::kRuledLaneParams.r_max}, c) != pb::WireError::None)
        return std::nullopt;
    return pb::receipt_id(c.own);
}

// The relay counters the trace follows.
struct Counter {
    const char* name;
    std::atomic<std::uint64_t> pb::PathbRelayStats::*m;
};
const Counter kCounters[] = {
        {"rerun", &pb::PathbRelayStats::parked_reruns},
        {"rewalk", &pb::PathbRelayStats::rewalks},
        {"rpark", &pb::PathbRelayStats::receipts_parked},
        {"rpdrop", &pb::PathbRelayStats::parked_receipt_drops},
        {"p15drop", &pb::PathbRelayStats::p15_drops},
        {"qdrop", &pb::PathbRelayStats::queue_dropped},
        {"notoken", &pb::PathbRelayStats::rx_deferred},
        {"solicited", &pb::PathbRelayStats::solicited_jobs},
        {"ctxwant", &pb::PathbRelayStats::ctx_wanted},
        {"ctxheld", &pb::PathbRelayStats::ctx_held},
        {"ctxgiveup", &pb::PathbRelayStats::ctx_gave_up},
        {"ctxok", &pb::PathbRelayStats::ctx_resolved},
        {"ctxunknown", &pb::PathbRelayStats::ctx_unknown_rx},
        {"hdrdefer", &pb::PathbRelayStats::headers_ctx_deferred},
        {"hdrreask", &pb::PathbRelayStats::headers_ctx_reasks},
        {"wantmerge", &pb::PathbRelayStats::header_wants_merged},
        {"wantreclaim", &pb::PathbRelayStats::header_wants_reclaimed},
        {"wantdrop", &pb::PathbRelayStats::header_wants_dropped},
        {"retired", &pb::PathbRelayStats::headers_retired_dropped},
        {"walkplaced", &pb::PathbRelayStats::walk_placed},
        {"bodyset", &pb::PathbRelayStats::body_sets},
        {"stale", &pb::PathbRelayStats::stale_events},
        {"fsealed", &pb::PathbRelayStats::parked_frames_sealed},
        {"rsealed", &pb::PathbRelayStats::parked_receipts_sealed},
        {"alarm", &pb::PathbRelayStats::claim_alarms},
        {"alarmdrop", &pb::PathbRelayStats::claim_alarm_drops},
        {"bansrc", &pb::PathbRelayStats::banned_src_dropped},
        {"droptok", &pb::PathbRelayStats::drops},
        {"ban", &pb::PathbRelayStats::bans},
        {"strike", &pb::PathbRelayStats::strikes},
        {"repend", &pb::PathbRelayStats::repend_offers},
        {"reoffer", &pb::PathbRelayStats::reoffer_frames},
        {"flood", &pb::PathbRelayStats::flood_frames},
        {"hello", &pb::PathbRelayStats::hello_ok},
        {"idxprune", &pb::PathbRelayStats::parked_index_pruned},
        {"joinrel", &pb::PathbRelayStats::join_releases},
        {"emptyoffer", &pb::PathbRelayStats::empty_store_offers},
        {"rxfail", &pb::PathbRelayStats::rx_failures},
};
constexpr std::size_t kNCounters = sizeof kCounters / sizeof kCounters[0];

// AJBMEMO set: the trace follows each node's RandomX memo order.
const bool g_memo_mode = std::getenv("AJBMEMO") != nullptr;
// An outage of every non-mining node's RandomX worker over the steps [g_out_s, g_out_s + g_out_len) (--outsweep, AJBOUT).
std::uint64_t g_out_s = 0, g_out_len = 0;

// One node's state as the trace sees it.
struct Snap {
    std::string memo;                          // AJBMEMO: the RandomX memo order
    std::array<std::uint64_t, 3> keys{};       // the cases that follow the key cache: computations, hits, entries
    std::shared_ptr<std::set<Hash32>> placed;  // the ids ever placed at the node (one set, shared, it only grows)
    std::vector<Hash32> added;                  // the ids placed since the previous snapshot
    std::set<Hash32> pending;
    std::map<Hash32, std::tuple<std::uint64_t, Missing, Hash32>> parked;  // digest -> (seq, cause, id)
    std::size_t rp = 0, rd = 0, idx = 0, wants = 0, jobs = 0;
    std::set<std::uint64_t> live;
    std::map<std::uint64_t, std::uint64_t> strikes;  // link -> tokens
    std::array<std::uint64_t, kNCounters> ctr{};
    pb::PathbRelayNode::VerdictCounts verdicts{};
};

std::string peer_name(std::uint64_t link) {
    const std::size_t n = FakeWire::node_of(link);
    const std::uint64_t e = (link - 1) / 100;
    return "n" + std::to_string(n) + (e != 0 ? "." + std::to_string(e) : std::string());
}

// The trace of one case: the steps of the wire, the ticks and the scripted actions, and what changed at each.
struct Tracer {
    Harness& h;
    FakeWire& w;
    struct Member {
        std::size_t node = 0;
        pb::PathbRelayNode* relay = nullptr;
        FakeLinks* links = nullptr;
        Snap s;
        std::set<Hash32> unplaced;  // the universe's ids not placed at the node
    };
    std::vector<Member> mem;
    std::set<Hash32> universe;  // carrier ids seen on the wire (a side carrier is looked up by id)
    std::vector<std::string> out;
    struct Level {
        std::uint64_t step;
        std::string label;
        bool shown;
    };
    std::vector<Level> stack;
    std::uint64_t steps = 0;
    bool keytrace = false;  // Y lines: each node's key cache

    Tracer(Harness& hh, FakeWire& ww) : h(hh), w(ww) {
        stack.push_back(Level{0, "start", false});
        w.on_send = [this](const FakeWire::Msg& m) { on_send(m); };
        w.on_step = [this](const FakeWire::Msg& m, std::uint8_t op, bool before) {
            if (before) {
                std::string l = "d " + std::to_string(m.from) + ">" + std::to_string(m.to) + " " + op_name(op);
                if (m.f.empty() && op != 0) l += " x";
                else if (w.links[m.to]->live.count(w.id(m.to, m.from)) == 0) l += " down";
                push(l);
                note_frame(m.f);
            } else {
                poll();
                stack.pop_back();
            }
        };
    }
    ~Tracer() {
        w.on_send = nullptr;
        w.on_step = nullptr;
    }

    void add(std::size_t node, pb::PathbRelayNode* relay, FakeLinks* links) {
        Member m;
        m.node = node;
        m.relay = relay;
        m.links = links;
        m.unplaced = universe;
        m.s = take(m);
        mem.push_back(std::move(m));
    }

    void push(const std::string& label) { stack.push_back(Level{++steps, label, false}); }
    void emit(const std::string& e) {
        Level& l = stack.back();
        if (!l.shown) {
            out.push_back(std::to_string(l.step) + " @ " + l.label + " t=" + std::to_string(h.now));
            l.shown = true;
        }
        out.push_back(std::to_string(l.step) + " " + e);
    }

    // A carrier id seen on the wire: in the universe, and unplaced at every member that has not placed it.
    void see(const Hash32& id) {
        if (!universe.insert(id).second) return;
        for (Member& m : mem)
            if (!m.s.placed || m.s.placed->count(id) == 0) m.unplaced.insert(id);
    }
    void note_frame(const Frame& f) {
        if (f.empty()) return;
        if (const std::optional<Hash32> id = carrier_id(f)) see(*id);
        if (f[0] == pb::kOpFcHeaders) {
            pb::HeadersReply rep;
            if (pb::decode_fc_headers(f, 0, 1u << 22, pb::kRuledLaneParams, rep).ok())
                for (const pb::CarrierHeader& hd : rep.headers) see(pb::receipt_id(hd.own));
        }
    }

    void on_send(const FakeWire::Msg& m) {
        note_frame(m.f);
        if (m.f.empty()) return;
        const std::string ft = std::to_string(m.from) + ">" + std::to_string(m.to) + " ";
        switch (m.f[0]) {
            case pb::kOpFcGetHeaders: {
                pb::GetHeaders q;
                if (pb::decode_fc_getheaders(m.f, 0, q).ok())
                    emit("S " + ft + "GH " + h6(q.from) + " " + h6(q.stop) + " " + std::to_string(q.max));
                else
                    emit("S " + ft + "GH ?");
                break;
            }
            case pb::kOpFcGetCarrier: {
                pb::GetCarrier q;
                if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok()) {
                    std::string ids;
                    for (const Hash32& id : q.ids) ids += (ids.empty() ? "" : ",") + h6(id);
                    emit("S " + ft + "GC " + ids + (q.want_bodies ? " b" : ""));
                } else {
                    emit("S " + ft + "GC ?");
                }
                break;
            }
            case pb::kOpFcGetBuckets: {
                pb::GetBuckets q;
                if (pb::decode_getbuckets(m.f, 0, q) == pb::BucketsWireError::None)
                    emit("S " + ft + "GB " + h6(q.at) + " " + std::to_string(q.bin_lo - kLaneB0) + "-" +
                         std::to_string(q.bin_hi - kLaneB0));
                else
                    emit("S " + ft + "GB ?");
                break;
            }
            case pb::kOpFbGetCtx: {
                std::uint32_t chain = 0;
                std::vector<Hash32> ids;
                if (rly::decode_getctx(m.f, chain, ids)) {
                    std::string s;
                    for (const Hash32& id : ids) s += (s.empty() ? "" : ",") + h6(id);
                    emit("S " + ft + "GX " + s);
                } else {
                    emit("S " + ft + "GX ?");
                }
                break;
            }
            default: break;
        }
    }

    Snap take(Member& m) {
        Snap s;
        const pb::PathbNode& n = *h.nodes[m.node];
        if (g_memo_mode) s.memo = pb::PathbNodeTestAccess::memo_digest(n);
        if (keytrace) {
            const pb::KeyCache& kc = pb::PathbNodeTestAccess::keys(n);
            s.keys = {kc.computations(), kc.hits(), static_cast<std::uint64_t>(kc.entries())};
        }
        s.placed = m.s.placed ? m.s.placed : std::make_shared<std::set<Hash32>>();
        std::set<Hash32>& pl = *s.placed;
        for (Hash32 id = n.tree().best().id; pl.count(id) == 0;) {
            pl.insert(id);
            s.added.push_back(id);
            m.unplaced.erase(id);
            const pb::CarrierNode* c = n.tree().find(id);
            if (c == nullptr || c->parent == id || c->pos == 0) break;
            id = c->parent;
        }
        for (auto it = m.unplaced.begin(); it != m.unplaced.end();) {
            if (pl.count(*it) != 0) {
                it = m.unplaced.erase(it);
            } else if (n.tree().find(*it) != nullptr) {
                pl.insert(*it);
                s.added.push_back(*it);
                it = m.unplaced.erase(it);
            } else {
                ++it;
            }
        }
        for (const pb::PendingReceipt* r : n.pending().all()) s.pending.insert(r->id);
        for (const Hash32& d : n.deferred().digests())
            if (const pb::ParkedFrame* f = n.deferred().get(d)) s.parked[d] = std::make_tuple(f->seq, f->cause, f->id);
        if (m.relay != nullptr) {
            pb::PathbRelayNode& r = *m.relay;
            s.rp = r.parked_receipts();
            s.rd = r.parked_receipts_due();
            s.idx = r.parked_index_size();
            s.wants = r.ctx_wants();
            s.jobs = r.parked_size();
            s.live = m.links->live;
            std::set<std::uint64_t> ls = s.live;
            for (const auto& [p, k] : m.s.strikes) ls.insert(p);
            for (const std::uint64_t p : ls) s.strikes[p] = r.strikes_of(p);
            for (std::size_t i = 0; i < kNCounters; ++i) s.ctr[i] = (r.stats().*(kCounters[i].m)).load();
            s.verdicts = r.verdict_counts();
        }
        return s;
    }

    void poll() {
        for (Member& m : mem) {
            Snap s = take(m);
            diff(m, m.s, s);
            m.s = std::move(s);
        }
    }

    void diff(const Member& m, const Snap& a, const Snap& b) {
        const std::string n = std::to_string(m.node);
        const pb::PathbNode& node = *h.nodes[m.node];
        std::vector<std::pair<std::uint64_t, Hash32>> placed;
        for (const Hash32& id : b.added) placed.emplace_back(node.tree().find(id) ? node.tree().find(id)->pos : 0, id);
        std::sort(placed.begin(), placed.end());
        for (const auto& [pos, id] : placed) emit("P " + n + " " + h6(id) + " " + std::to_string(pos));
        if (g_memo_mode && a.memo != b.memo) emit("Mh " + n + " " + b.memo);
        if (keytrace && a.keys != b.keys)
            emit("Y " + n + " c=" + std::to_string(b.keys[0]) + " h=" + std::to_string(b.keys[1]) + " e=" +
                 std::to_string(b.keys[2]));
        for (const Hash32& id : b.pending)
            if (a.pending.count(id) == 0) emit("R " + n + " " + h6(id));
        for (const Hash32& id : a.pending)
            if (b.pending.count(id) == 0) emit("r " + n + " " + h6(id));
        for (const auto& [d, v] : b.parked) {
            const auto it = a.parked.find(d);
            if (it == a.parked.end())
                emit("K " + n + " " + h6(d) + " " + h6(std::get<2>(v)) + " " + cause_name(std::get<1>(v)));
            else if (std::get<0>(it->second) != std::get<0>(v))
                emit("k " + n + " " + h6(d) + " " + cause_name(std::get<1>(it->second)) + ">" + cause_name(std::get<1>(v)));
        }
        for (const auto& [d, v] : a.parked)
            if (b.parked.count(d) == 0)
                emit("U " + n + " " + h6(d) + " " + cause_name(std::get<1>(v)) + " " +
                     (node.tree().find(std::get<2>(v)) != nullptr ? "placed" : "out"));
        if (m.relay == nullptr) return;
        if (a.rp != b.rp || a.rd != b.rd) emit("Q " + n + " p=" + std::to_string(b.rp) + " d=" + std::to_string(b.rd));
        if (a.idx != b.idx) emit("I " + n + " " + std::to_string(b.idx));
        if (a.wants != b.wants) emit("W " + n + " " + std::to_string(b.wants));
        if (a.jobs != b.jobs) emit("J " + n + " " + std::to_string(b.jobs));
        for (const std::uint64_t p : b.live)
            if (a.live.count(p) == 0) emit("L " + n + " " + peer_name(p) + " up");
        for (const std::uint64_t p : a.live)
            if (b.live.count(p) == 0) emit("L " + n + " " + peer_name(p) + " down");
        for (const auto& [p, k] : b.strikes) {
            const auto it = a.strikes.find(p);
            const std::uint64_t was = it == a.strikes.end() ? 0 : it->second;
            if (k > was) emit("X " + n + " " + peer_name(p) + " +" + std::to_string(k - was));
        }
        for (std::size_t row = 0; row < b.verdicts.size(); ++row)
            for (std::size_t v = 0; v < b.verdicts[row].size(); ++v)
                if (b.verdicts[row][v] != a.verdicts[row][v])
                    emit("V " + n + " R" + std::to_string(row) + "/" + verdict_name(v) + " +" +
                         std::to_string(b.verdicts[row][v] - a.verdicts[row][v]));
        for (std::size_t i = 0; i < kNCounters; ++i)
            if (b.ctr[i] != a.ctr[i]) emit("C " + n + " " + kCounters[i].name + " +" + std::to_string(b.ctr[i] - a.ctr[i]));
    }

    // The end of the case: each relay's P-15 level per live link.
    void finish() {
        push("end");
        poll();
        for (Member& m : mem) {
            if (m.relay == nullptr) continue;
            for (const std::uint64_t p : m.links->live) {
                char b[64];
                std::snprintf(b, sizeof b, "%.3f", m.relay->peer_valid_left(p));
                emit("E " + std::to_string(m.node) + " " + peer_name(p) + " " + b);
            }
        }
        stack.pop_back();
    }
};

// A case's rig: relay nodes on one harness and one wire, traced from the start.
struct Rig {
    const KatNet net;
    std::vector<std::shared_ptr<void>> keep;  // what the nodes' I/O refers to (outlives the nodes)
    Harness h;
    FakeWire w;
    std::vector<KatRelay> r;
    Tracer t;
    Rig() : h(net), t(h, w) {}
    explicit Rig(const KatNet& n) : net(n), h(net), t(h, w) {}

    using OptTweak = std::function<void(pb::PathbRelayOptions&)>;
    using CfgTweak = std::function<void(pb::PathbNodeConfig&)>;
    using IoTweak = std::function<void(pb::PathbNodeIo&)>;
    // A non-mining node's I/O with the outage of g_out_s / g_out_len (none: `io` as given).
    IoTweak outage(const IoTweak& io, bool launch) {
        if (g_out_len == 0 || launch) return io;
        return [io, this](pb::PathbNodeIo& x) {
            if (io) io(x);
            x.verify = [orig = x.verify, this](const pb::HashingBlob& b, std::uint64_t d, const Hash32& s) {
                if (t.steps >= g_out_s && t.steps < g_out_s + g_out_len) throw std::runtime_error("kat: outage span");
                return orig(b, d, s);
            };
        };
    }
    std::size_t relay(bool launch, const OptTweak& o = nullptr, const CfgTweak& c = nullptr, const IoTweak& io = nullptr,
                      const pb::EpochTable* T = nullptr, bool failed = false) {
        r.push_back(kat_relay(h, w, T != nullptr ? *T : kat_table(net), launch, failed, o, c, outage(io, launch)));
        t.add(r.back().node, r.back().relay.get(), r.back().links.get());
        return r.back().node;
    }
    pb::PathbNode& n(std::size_t i) { return h[i]; }
    pb::PathbRelayNode& rel(std::size_t i) { return *r[i].relay; }

    // A scripted action: run, then every relay's queued work, then the trace's poll.
    void act(const std::string& label, const std::function<void()>& fn) {
        t.push("a " + label);
        fn();
        for (KatRelay& k : r) k.relay->pump();
        t.poll();
        t.stack.pop_back();
    }
    // Every queued frame delivered, one per step.
    void run() {
        for (KatRelay& k : r) k.relay->pump();
        t.poll();
        while (w.step()) {
        }
    }
    void connect(std::size_t a, std::size_t b) {
        act("connect " + std::to_string(a) + "-" + std::to_string(b), [&] { w.connect(a, b); });
        run();
    }
    void reconnect(std::size_t a, std::size_t b) {
        act("reconnect " + std::to_string(a) + "-" + std::to_string(b), [&] { w.reconnect(a, b); });
        run();
    }
    void disconnect(std::size_t a, std::size_t b) {
        act("disconnect " + std::to_string(a) + "-" + std::to_string(b), [&] { w.links[a]->disconnect(w.id(a, b)); });
        run();
    }
    // `secs` seconds pass; then each node's tick (all, or `only`), each a step; then the wire.
    void tick(std::uint64_t secs = 1, std::optional<std::size_t> only = std::nullopt) {
        h.now += secs;
        for (KatRelay& k : r) {
            if (only && k.node != *only) continue;
            t.push("t " + std::to_string(k.node));
            k.relay->tick();
            for (KatRelay& q : r) q.relay->pump();
            t.poll();
            t.stack.pop_back();
        }
        run();
    }
    // Ticks of one second until `done` or `max` seconds.
    int ticks_until(const std::function<bool()>& done, int max, std::optional<std::size_t> only = std::nullopt) {
        int k = 0;
        for (; k < max && !done(); ++k) tick(1, only);
        return k;
    }
    // The follower's tip moves `by` blocks; every relay is told (as the follower's wiring does).
    void monero(std::uint64_t by = 1) {
        act("monero +" + std::to_string(by), [&] {
            h.tick_monero(by);
            for (KatRelay& k : r) k.relay->on_monero_tip();
        });
        run();
    }
    // Node i mines one share on its best tip; its action.
    pb::NodeAction mine(std::size_t i, std::size_t payee, std::uint32_t nonce) {
        pb::NodeAction a = pb::NodeAction::None;
        act("mine " + std::to_string(i), [&] {
            const std::optional<pb::PathbJob> j = h.job(i, payee, nonce);
            if (j) a = h[i].on_own_share(*j, nonce, Hash32{}).action;
        });
        run();
        return a;
    }
    // A share of a job taken earlier.
    pb::NodeAction share(std::size_t i, const pb::PathbJob& j, std::uint32_t nonce) {
        pb::NodeAction a = pb::NodeAction::None;
        act("share " + std::to_string(i), [&] { a = h[i].on_own_share(j, nonce, Hash32{}).action; });
        run();
        return a;
    }
    // A frame of `from` received at `to` (as its link delivers it), then the wire.
    // A join step's result as one trace line: A N END judged rROW xAT tTOKENS lL sSWITCHED, where ROW and AT are the row
    // and position of the last frame the attempt judged (an attempt that ends before it judges a frame keeps the
    // previous one's) (a step with no report: A N - s0/1; no step run: A N -).
    void note_join(std::size_t v, const std::optional<pb::JoinStep>& st) {
        std::string l = "A " + std::to_string(v);
        if (!st) {
            l += " -";
        } else if (!st->report) {
            l += std::string(" - s") + (st->switched ? "1" : "0");
        } else {
            const pb::AttemptReport& rp = *st->report;
            l += std::string(" ") + pb::attempt_end_name(rp.end) + " judged r" + std::to_string(static_cast<int>(rp.row)) +
                 " x" + std::to_string(rp.at) + " t" + std::to_string(rp.strike) + " l" + std::to_string(rp.L) + " s" +
                 (st->switched ? "1" : "0");
        }
        t.emit(l);
    }
    // One join step of node v as a scripted action (its result traced), then the wire.
    std::optional<pb::JoinStep> join(std::size_t v, const std::string& label) {
        std::optional<pb::JoinStep> st;
        act(label, [&] {
            st = r[v].relay->join_step();
            note_join(v, st);
        });
        run();
        return st;
    }
    void deliver(std::size_t from, std::size_t to, const Frame& f, const std::string& what) {
        act("deliver " + std::to_string(from) + ">" + std::to_string(to) + " " + what, [&] {
            t.note_frame(f);
            r[to].relay->receive(w.id(to, from), f);
        });
        run();
    }
    Frame carrier_frame(std::size_t i, const Hash32& id) {
        const pb::CarrierBodyV3* b = h[i].bodies().get(id);
        return b != nullptr ? pb::encode_fc_carrier(0, *b, 16).value_or(Frame{}) : Frame{};
    }
    static Frame receipt_frame(const pb::ReceiptBodyV3& b) {
        return pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{b}, pb::kRuledLaneParams).value_or(Frame{});
    }
    Hash32 best(std::size_t i) { return h[i].tree().best().id; }
    bool has(std::size_t i, const Hash32& id) { return h[i].tree().find(id) != nullptr; }
};

// A wire filter: frames matching `drop` are cut in flight; frames matching `hold` are cut and kept for later.
struct Filter {
    std::function<bool(const FakeWire::Msg&)> drop, hold;
    std::vector<FakeWire::Msg> held;
    void install(FakeWire& w) {
        w.edit = [this](FakeWire::Msg& m) {
            if (m.f.empty()) return;
            if (hold && hold(m)) {
                held.push_back(m);
                m.f.clear();
                return;
            }
            if (drop && drop(m)) m.f.clear();
        };
    }
};
bool is_op(const FakeWire::Msg& m, std::uint8_t op) { return !m.f.empty() && m.f[0] == op; }

// ===========================================================================
// The cases
// ===========================================================================

// D1: a carrier whose three ancestors the node lacks, from a sender that answers (one peer), or is silent with two and
// three peers (the parent asked again of the next peer in turn at each P-53).
void d1(Rig& g, int peers, int silent) {
    const std::size_t a = g.relay(true), v = g.relay(false);
    std::vector<std::size_t> others;
    for (int i = 1; i < peers; ++i) others.push_back(g.relay(false));
    g.connect(a, v);
    for (const std::size_t o : others) {
        g.connect(a, o);
        g.connect(o, v);
    }
    for (std::uint32_t i = 0; i < 2; ++i) g.mine(a, 1, 100 + i);
    Filter f;
    f.drop = [v](const FakeWire::Msg& m) { return m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    std::vector<Hash32> c;
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i == 2) g.monero();
        g.mine(a, 2, 110 + i);
        c.push_back(g.best(a));
    }
    std::set<std::size_t> mute;  // peers whose FC_CARRIER replies do not reach the node
    if (silent >= 1) mute.insert(a);
    for (int i = 0; i + 1 < silent && i < static_cast<int>(others.size()); ++i) mute.insert(others[static_cast<std::size_t>(i)]);
    f.drop = [v, mute](const FakeWire::Msg& m) { return m.to == v && mute.count(m.from) != 0 && is_op(m, pb::kOpFcCarrier); };
    const Frame top = g.carrier_frame(a, c.back());
    g.deliver(a, v, top, "c4");
    g.ticks_until([&] { return g.best(v) == c.back(); }, 50, v);
    g.w.edit = nullptr;
    check(g.best(v) == c.back(), "d1: the node reaches the sender's tip");
}

// ---------------------------------------------------------------------------
// A two-node race whose losing branch (`depth` carriers) the node V lacks: A and L race with their link cut, L's
// branch wins; V follows A's best chain. `bodies`: each losing carrier carries a receipt of A's. B (when `extra`)
// holds both branches too. k: A's share on the losing tip, pending at A (and B); not relayed to V.
struct Race {
    std::size_t a = 0, l = 0, v = 0, b = SIZE_MAX;
    std::vector<Hash32> lose;              // A's losing branch, oldest first
    pb::ReceiptBodyV3 k;                   // A's share on the losing tip
    std::vector<pb::ReceiptBodyV3> tips;   // `all_tips`: A's shares on each losing carrier, pending at A
    bool ok = false;
};
Race race(Rig& g, std::size_t depth, bool bodies, bool extra, bool all_tips = false, const Rig::CfgTweak& vcfg = nullptr) {
    Race x;
    x.a = g.relay(true);
    x.l = g.relay(true);
    x.v = g.relay(false, nullptr, vcfg);
    if (extra) x.b = g.relay(false);
    g.connect(x.a, x.l);
    if (extra) g.connect(x.a, x.b);
    bool ok = true;
    std::optional<pb::PathbJob> pend;  // a receipt the first losing carrier carries
    std::vector<std::optional<pb::PathbJob>> tj;  // jobs on each losing carrier but the last
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) g.monero();
        if (i == 3 && bodies) pend = g.h.job(x.a, 5, 350);
        ok = ok && g.mine(x.a, 1, 300 + i) == pb::NodeAction::Placed;
    }
    if (bodies) ok = ok && pend && g.share(x.a, *pend, 350) == pb::NodeAction::Pending;
    Filter f;
    f.drop = [&x](const FakeWire::Msg& m) { return (m.from == x.a && m.to == x.l) || (m.from == x.l && m.to == x.a); };
    f.install(g.w);
    g.monero();
    for (std::size_t i = 0; i < depth; ++i) {
        // u: a share on the tip before this carrier, pending once it is placed: the next losing carrier carries it
        std::optional<pb::PathbJob> u;
        if (bodies && i + 1 < depth) u = g.h.job(x.a, 6, 360 + static_cast<std::uint32_t>(i));
        ok = ok && g.mine(x.a, 2, 400 + static_cast<std::uint32_t>(i)) == pb::NodeAction::Placed;
        x.lose.push_back(g.best(x.a));
        if (u) ok = ok && g.share(x.a, *u, 360 + static_cast<std::uint32_t>(i)) == pb::NodeAction::Pending;
        if (all_tips && i + 1 < depth) tj.push_back(g.h.job(x.a, 7 + i, 430 + static_cast<std::uint32_t>(i)));
    }
    const std::optional<pb::PathbJob> kj = g.h.job(x.a, 4, 410);
    for (std::size_t i = 0; i < depth + 1; ++i) ok = ok && g.mine(x.l, 3, 500 + static_cast<std::uint32_t>(i)) == pb::NodeAction::Placed;
    g.w.edit = nullptr;
    // the branches exchanged: A's to L, L's to A
    std::vector<Hash32> ls;
    for (Hash32 t = g.best(x.l); ls.size() < depth + 1; t = g.n(x.l).tree().find(t)->parent) ls.push_back(t);
    g.act("exchange", [&] {
        for (const Hash32& id : x.lose) g.w.q.push_back(FakeWire::Msg{x.a, x.l, g.carrier_frame(x.a, id)});
        for (auto it = ls.rbegin(); it != ls.rend(); ++it) g.w.q.push_back(FakeWire::Msg{x.l, x.a, g.carrier_frame(x.l, *it)});
    });
    g.run();
    ok = ok && kj && g.best(x.a) == g.best(x.l) && g.has(x.a, x.lose.back());
    if (extra) ok = ok && g.has(x.b, x.lose.back()) && g.best(x.b) == g.best(x.a);
    x.k = kj ? kj->body : pb::ReceiptBodyV3{};
    x.k.blob.nonce = 410;
    ok = ok && kj && g.share(x.a, *kj, 410) == pb::NodeAction::Pending;
    for (std::size_t i = 0; i < tj.size(); ++i) {
        const std::uint32_t nonce = 430 + static_cast<std::uint32_t>(i);
        ok = ok && tj[i] && g.share(x.a, *tj[i], nonce) == pb::NodeAction::Pending;
        if (!tj[i]) continue;
        pb::ReceiptBodyV3 b = tj[i]->body;
        b.blob.nonce = nonce;
        x.tips.push_back(b);
    }
    if (all_tips) x.tips.push_back(x.k);
    x.ok = ok;
    check(ok, "race: setup (a losing branch of " + std::to_string(depth) + " at A, k pending on its tip)");
    return x;
}
// V follows A (and B and L) to A's best chain; no receipt frame reaches V.
bool follow(Rig& g, const Race& x, bool with_b) {
    Filter f;
    f.drop = [&x](const FakeWire::Msg& m) { return m.to == x.v && is_op(m, pb::kOpFbReceipts); };
    f.install(g.w);
    g.connect(x.a, x.v);
    if (with_b && x.b != SIZE_MAX) {
        g.connect(x.b, x.v);
        g.connect(x.l, x.v);
    }
    g.ticks_until([&] { return g.best(x.v) == g.best(x.a); }, 12, x.v);
    g.w.edit = nullptr;
    return g.best(x.v) == g.best(x.a) && !g.has(x.v, x.lose.front());
}

// D4: a carrier X whose carried tip V lacks, parked on TipUnknown, from a sender that never answers its header request;
// the copies of X from two other peers (each flooding X at its own placement) ask their own senders: X placed.
void d4_frame(Rig& g) {
    const Race x = race(g, 1, false, true);
    if (!x.ok) return;
    const bool synced = follow(g, x, true);
    // X: A's next carrier, carrying k (its tip the losing carrier); A's FC_HEADERS to V never arrive
    Filter f;
    f.drop = [&x](const FakeWire::Msg& m) { return m.from == x.a && m.to == x.v && is_op(m, pb::kOpFcHeaders); };
    f.install(g.w);
    g.monero();
    const bool mined = g.mine(x.a, 5, 420) == pb::NodeAction::Placed;
    const Hash32 c = g.best(x.a);
    g.ticks_until([&] { return g.best(x.v) == c; }, 30, x.v);
    g.w.edit = nullptr;
    check(synced && mined && g.best(x.v) == c && g.has(x.v, x.lose.back()),
          "d4 (frame): X parked on its unknown tip from a silent sender; the copies of X placed it");
}
// D4 (receipt): k parked on its unknown tip from A, which never answers; A's link closes (no re-run); a copy of k from
// B re-homes the parked receipt to B, which is asked and answers: k pending.
void d4_receipt(Rig& g) {
    const Race x = race(g, 1, false, true);
    if (!x.ok) return;
    const bool synced = follow(g, x, true);
    Filter f;
    f.drop = [&x](const FakeWire::Msg& m) { return m.from == x.a && m.to == x.v && is_op(m, pb::kOpFcHeaders); };
    f.install(g.w);
    const Frame kf = Rig::receipt_frame(x.k);
    g.deliver(x.a, x.v, kf, "k");
    g.tick(1, x.v);
    g.disconnect(x.v, x.a);
    g.ticks_until([] { return false; }, 12, x.v);
    g.deliver(x.b, x.v, kf, "k (copy)");
    g.ticks_until([&] { return g.n(x.v).pending().holds(pb::receipt_id(x.k)); }, 20, x.v);
    g.w.edit = nullptr;
    check(synced && g.n(x.v).pending().holds(pb::receipt_id(x.k)),
          "d4 (receipt): k parked from a silent sender whose link closed; a copy from B re-homed it: k pending");
}

// D6: a receipt k on a two-carrier losing branch, each carrier carrying a body: V asks the headers, then each walked
// carrier's body set of the sender in turn; the bind places both and k is admitted. `late`: the first body set's
// reply held past P-53 and delivered then.
void d6(Rig& g, bool late) {
    const Race x = race(g, 2, true, false);
    if (!x.ok) return;
    const bool synced = follow(g, x, false);
    Filter f;
    const Hash32 first = x.lose.front();
    if (late)
        f.hold = [&x, first](const FakeWire::Msg& m) {
            return m.from == x.a && m.to == x.v && is_op(m, pb::kOpFcCarrier) && carrier_id(m.f) == first;
        };
    f.install(g.w);
    g.deliver(x.a, x.v, Rig::receipt_frame(x.k), "k");
    const Hash32 k = pb::receipt_id(x.k);
    g.ticks_until([&] { return !f.held.empty() || g.n(x.v).pending().holds(k); }, 12, x.v);
    if (late) {
        g.ticks_until([] { return false; }, 12, x.v);
        g.w.edit = nullptr;
        std::vector<FakeWire::Msg> held = f.held;
        for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "held body set");
    }
    g.ticks_until([&] { return g.n(x.v).pending().holds(k); }, 20, x.v);
    g.w.edit = nullptr;
    check(synced && g.n(x.v).pending().holds(k) && g.has(x.v, x.lose.back()),
          std::string("d6") + (late ? " (late)" : "") + ": both walked carriers placed, k pending");
}

// D6 (frame): X, A's carrier carrying k (its tip the two-carrier losing branch), DEFERs on the branch; V asks A the
// headers, then the first walked carrier's body set, whose reply is lost; L's sibling of X, placed at V, runs X again:
// the body set asked of A again, the branch placed, then X.
void d6_frame(Rig& g) {
    const Race x = race(g, 2, true, false);
    if (!x.ok) return;
    const bool synced = follow(g, x, false);
    bool lost = false;
    const Hash32 first = x.lose.front();
    // X does not reach L (L's next carrier is a sibling of X); the first body-set reply of A to V is lost
    g.w.edit = [&](FakeWire::Msg& m) {
        if ((m.from == x.a && m.to == x.l) || (m.from == x.l && m.to == x.a)) m.f.clear();
        if (!lost && m.from == x.a && m.to == x.v && is_op(m, pb::kOpFcCarrier) && carrier_id(m.f) == first) {
            lost = true;
            m.f.clear();
        }
    };
    g.monero();
    const bool mined = g.mine(x.a, 5, 420) == pb::NodeAction::Placed;
    const Hash32 c = g.best(x.a);
    g.ticks_until([] { return false; }, 3, x.v);
    const bool waits = lost && !g.has(x.v, c);
    g.mine(x.l, 3, 520);
    g.connect(x.l, x.v);
    g.ticks_until([&] { return g.has(x.v, c); }, 12, x.v);
    g.w.edit = nullptr;
    check(synced && mined && waits && g.has(x.v, c) && g.has(x.v, x.lose.back()),
          "d6 (frame): the lost body set asked again after a placement's re-run; the branch and X placed");
}

// D7: as D6, the sender never serving a body set; a copy of k from B re-homes the parked receipt: B's body sets
// place the branch, k pending.
void d7(Rig& g) {
    const Race x = race(g, 2, true, true);
    if (!x.ok) return;
    const bool synced = follow(g, x, true);
    Filter f;
    f.drop = [&x](const FakeWire::Msg& m) {
        if (m.from != x.a || m.to != x.v || !is_op(m, pb::kOpFcCarrier)) return false;
        const std::optional<Hash32> id = carrier_id(m.f);
        return id && std::find(x.lose.begin(), x.lose.end(), *id) != x.lose.end();
    };
    f.install(g.w);
    const Frame kf = Rig::receipt_frame(x.k);
    g.deliver(x.a, x.v, kf, "k");
    g.ticks_until([] { return false; }, 12, x.v);
    g.deliver(x.b, x.v, kf, "k (copy)");
    const Hash32 k = pb::receipt_id(x.k);
    g.ticks_until([&] { return g.n(x.v).pending().holds(k); }, 20, x.v);
    g.w.edit = nullptr;
    check(synced && g.n(x.v).pending().holds(k), "d7: the sender never served a body set; B's copy re-homed k: k pending");
}

// D14: the sender of parked frames and receipts leaves; another peer is BANned (a carrier whose PoW fails); the sender
// reconnects with a new link id: its HELLO's catch-up and pending re-offer bring the frames' parents and the receipts'
// re-homing.
void d14(Rig& g) {
    const std::size_t a = g.relay(true), v = g.relay(false), m = g.relay(true);
    g.connect(a, v);
    g.connect(m, v);
    for (std::uint32_t i = 0; i < 2; ++i) g.mine(a, 1, 700 + i);
    Filter f;
    f.drop = [a, v](const FakeWire::Msg& x) { return x.from == a && x.to == v; };
    f.install(g.w);
    std::vector<Hash32> c;
    for (std::uint32_t i = 0; i < 3; ++i) {
        g.mine(a, 2, 710 + i);
        c.push_back(g.best(a));
    }
    // receipts of A on its tip's parent, pending at A, none at V
    std::vector<pb::ReceiptBodyV3> rs;
    const std::vector<std::optional<pb::PathbJob>> jobs = {g.h.job(a, 3, 720), g.h.job(a, 4, 721)};
    g.mine(a, 2, 713);
    c.push_back(g.best(a));
    for (std::uint32_t i = 0; i < 2; ++i) {
        if (jobs[i] && g.share(a, *jobs[i], 720 + i) == pb::NodeAction::Pending) {
            pb::ReceiptBodyV3 b = jobs[i]->body;
            b.blob.nonce = 720 + i;
            rs.push_back(b);
        }
    }
    // the top carrier and both receipts reach V; nothing of A's after them
    g.deliver(a, v, g.carrier_frame(a, c.back()), "c4");
    for (const pb::ReceiptBodyV3& b : rs) g.deliver(a, v, Rig::receipt_frame(b), "receipt");
    g.tick(1, v);
    g.disconnect(v, a);
    // M's carrier on V's tip, its PoW failing at V: BAN
    g.w.edit = nullptr;
    const std::optional<pb::PathbJob> mj = g.h.job(m, 4, 730);
    bool banned = false;
    if (mj) {
        pb::ReceiptBodyV3 mb = mj->body;
        mb.blob.nonce = 730;
        g.h.bad_pow.insert(pb::receipt_id(mb));
        g.share(m, *mj, 730);
        banned = g.rel(v).stats().bans.load() > 0;
    }
    g.ticks_until([] { return false; }, 12, v);
    g.reconnect(a, v);
    g.ticks_until([&] { return g.best(v) == c.back() && g.n(v).pending().size() == rs.size(); }, 30, v);
    check(rs.size() == 2 && banned && g.best(v) == c.back() && g.n(v).pending().size() == rs.size(),
          "d14: after the sender's reconnect its frames and receipts are placed; the banned peer's link dropped");
}


// ---------------------------------------------------------------------------
// The follower's rows with some blocks not held, or held without their weights.
struct HiddenRows final : pb::IMoneroRows {
    const pb::IMoneroRows& inner;
    const std::set<Hash32>& hidden;     // blocks not held
    const std::set<Hash32>& weightless; // blocks held without their weights
    HiddenRows(const pb::IMoneroRows& i, const std::set<Hash32>& h, const std::set<Hash32>& w)
        : inner(i), hidden(h), weightless(w) {}
    std::optional<pb::BranchBlock> block(const Hash32& id) const override {
        return hidden.count(id) != 0 ? std::nullopt : inner.block(id);
    }
    std::optional<pb::BranchBlock> block_at_or_below_anchor(std::uint64_t height) const override {
        return inner.block_at_or_below_anchor(height);
    }
    std::optional<pb::RowWeights> weights(const Hash32& id) const override {
        return hidden.count(id) != 0 || weightless.count(id) != 0 ? std::nullopt : inner.weights(id);
    }
    pb::BranchBlock anchor() const override { return inner.anchor(); }
    pb::Hash32 main_tip() const override { return inner.main_tip(); }
};
// A node's Monero view with blocks hidden (its P_r not resolved), seeds hidden, or weights hidden (the P_r resolved on
// the floor reading, as the binary's resolve_pr_on_branch does).
struct Follower {
    std::set<Hash32> hidden, noseed, weightless;
    HiddenRows rows;
    pb::FollowerBranchView view;
    bool exact = false;  // every P_r resolved on the branch, Z(P_r) 600,000 off the floor (the size rules' exact Z)
    explicit Follower(const KatNet& net) : rows(net.rows, hidden, weightless), view(rows) {}
    Rig::IoTweak io() {
        return [this](pb::PathbNodeIo& io) {
            io.monero = &view;
            const auto inner = io.resolve_pr;
            io.resolve_pr = [this, inner](const Hash32& p_r) {
                if (hidden.count(p_r) != 0) return pb::PrInfo{};
                if (!exact) return inner(p_r);
                pb::PrInfo r = pb::resolve_pr_on_branch(view, rows, p_r, [this](const Hash32& id) -> std::optional<std::uint8_t> {
                    return view.block(id) ? std::optional<std::uint8_t>(16) : std::nullopt;
                });
                if (r.status == pb::PrInfo::Status::Held && !r.in.floor) r.in.z = r.in.z_lt = 600000;
                return r;
            };
            const auto seed = io.seed_of;
            io.seed_of = [this, seed](const Hash32& p_r) -> std::optional<Hash32> {
                if (noseed.count(p_r) != 0) return std::nullopt;
                return seed(p_r);
            };
        };
    }
};
Follower& follower(Rig& g) {
    auto f = std::make_shared<Follower>(g.net);
    g.keep.push_back(f);
    return *f;
}

// A context source that asks peers (FB_GETCTX) and can judge nothing (KatNet's Monero rows have no block bodies).
void ask_only_ctx(pb::PathbRelayNode& r) {
    pb::PathbCtxSource s;
    s.chain.verified = [](const ::c2pool::v37n::xmr::relay::bytes32&) { return false; };
    s.chain.target = [](const ::c2pool::v37n::xmr::relay::bytes32&, const std::vector<rly::CtxStep>&, std::uint64_t,
                        rly::CtxTarget&, std::string& why) {
        why = "kat: no index";
        return false;
    };
    r.set_ctx_source(std::move(s));
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

// ---------------------------------------------------------------------------
// D15: a released child DEFERs inside the drain (its P_r not resolved at V): parked with no index and no ask; a copy
// of it from another peer indexes and asks; once its P_r resolves it is placed.
void d15(Rig& g) {
    Follower& fo = follower(g);
    const std::size_t a = g.relay(true), v = g.relay(false, nullptr, nullptr, fo.io()), c = g.relay(false);
    g.connect(a, v);
    g.connect(a, c);
    g.connect(c, v);
    g.mine(a, 1, 830);
    // c1 and c2 reach C, not V
    Filter f;
    f.drop = [a, c, v](const FakeWire::Msg& m) {
        return m.to == v && (m.from == a || m.from == c) && is_op(m, pb::kOpFcCarrier);
    };
    f.install(g.w);
    g.mine(a, 1, 840);
    const Hash32 c1 = g.best(a);
    g.monero();
    g.mine(a, 1, 850);
    const Hash32 c2 = g.best(a);
    const pb::CarrierBodyV3* b1 = g.n(a).bodies().get(c1);
    const pb::CarrierBodyV3* b2 = g.n(a).bodies().get(c2);
    const Hash32 p2 = b2 != nullptr ? b2->own.blob.prev_id : Hash32{};
    const bool setup = b1 != nullptr && b2 != nullptr && g.has(c, c2) && !g.has(v, c1) && p2 != b1->own.blob.prev_id;
    const Frame f2 = g.carrier_frame(a, c2), f1 = g.carrier_frame(a, c1);
    g.act("hide P_r of c2 at V", [&] { fo.hidden.insert(p2); });
    g.deliver(a, v, f2, "c2");  // parked on its unknown parent; c1 asked of A (its reply cut)
    g.w.edit = nullptr;
    g.deliver(a, v, f1, "c1");  // placed; the drain runs c2: DEFER on its P_r
    g.ticks_until([] { return false; }, 3, v);
    g.deliver(c, v, f2, "c2 (copy)");
    g.ticks_until([] { return false; }, 3, v);
    g.act("resolve P_r of c2 at V", [&] {
        fo.hidden.clear();
        g.rel(v).on_monero_tip();
    });
    g.run();
    g.ticks_until([&] { return g.has(v, c2); }, 10, v);
    check(setup && g.has(v, c1) && g.has(v, c2), "d15: c2 DEFERred in the drain, its copy indexed it; placed once P_r held");
}

// ---------------------------------------------------------------------------
// D2: B's heavier branch forks below V's journal base (depth 16); its first carrier X reaches V: parked (OwnChainDeep),
// nothing asked; B's HELLO starts V's catch-up, which finds the deep fork (the joiner path); V's join attempts over
// the relay take B's chain.
void d2(Rig& g) {
    const auto j16 = [](pb::PathbNodeConfig& c) { c.journal_depth = 16; };
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const std::size_t a = g.relay(true), b = g.relay(true), v = g.relay(false, p1, j16);
    g.connect(a, b);
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 900 + i);
    Filter f;
    f.drop = [a, b](const FakeWire::Msg& m) { return (m.from == a && m.to == b) || (m.from == b && m.to == a); };
    f.install(g.w);
    for (std::uint32_t i = 0; i < 24; ++i) {
        if (i % 3 == 0) g.monero();
        if (i < 20) g.mine(a, i % 5, 910 + i);
        g.mine(b, i % 5, 940 + i);
    }
    g.w.edit = nullptr;
    const std::optional<Hash32> x = g.n(b).store().best_at(4);
    const Hash32 tip_b = g.best(b);
    const bool deep = x && g.n(v).store().base_pos() > 3 && !g.has(v, *x);
    g.act("disconnect 0-1", [&] { g.w.links[a]->disconnect(g.w.id(a, b)); });
    g.run();
    // B's link to V: B's frames to V held until X is in, then delivered in order
    f.drop = nullptr;
    f.hold = [b, v](const FakeWire::Msg& m) { return m.from == b && m.to == v && !is_op(m, pb::kOpFbHello); };
    f.install(g.w);
    g.connect(b, v);
    if (x) g.deliver(b, v, g.carrier_frame(b, *x), "X");
    g.w.edit = nullptr;
    const std::vector<FakeWire::Msg> held = f.held;
    for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "held");
    g.tick(1, v);
    for (int i = 0; i < 40 && g.best(v) != tip_b; ++i) {
        (void)g.join(v, "join step 2");
        g.tick(1, v);
    }
    check(deep && g.best(v) == tip_b, "d2: X parked below the journal base; V reaches B's heavier chain");
}

// ---------------------------------------------------------------------------
// D3 (hold): V's build lacks the epoch the chain activates at a fixed height: from that height its frames are parked
// (Hold) and its receipts DEFER unparked; a flood copy and a HELLO re-offer are judged again and DEFER again.
void d3_hold(Rig& g) {
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    const Hash32 d1 = pb::rules_digest(r1);
    pb::EpochTable impl = kat_table(g.net);
    impl.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, 8));
    impl.compiled.push_back(pb::CompiledEpoch{1, d1, r1});
    pb::EpochTable lack = kat_table(g.net);
    lack.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, 8));
    const std::size_t a = g.relay(true, nullptr, nullptr, nullptr, &impl);
    const std::size_t c = g.relay(false, nullptr, nullptr, nullptr, &impl);
    const std::size_t v = g.relay(false, nullptr, nullptr, nullptr, &lack);
    g.connect(a, c);
    g.connect(a, v);
    g.connect(c, v);
    for (std::uint32_t i = 0; i < 11; ++i) {
        g.monero();
        g.mine(a, 1, 100 + i);
    }
    const std::vector<std::optional<pb::PathbJob>> jobs = {g.h.job(a, 2, 130), g.h.job(a, 3, 131)};
    g.mine(a, 1, 129);
    for (std::uint32_t i = 0; i < 2; ++i)
        if (jobs[i]) g.share(a, *jobs[i], 130 + i);
    g.disconnect(v, a);
    g.reconnect(a, v);
    g.ticks_until([] { return false; }, 3, v);
    check(g.n(v).tree().best().pos == 7 && g.n(v).deferred().size() > 0 && g.n(v).pending().size() == 0,
          "d3 (hold): V holds at position 7; its frames from the hold parked, its receipts not held");
}
// D3 (grace): X, a carrier V can admit, parked through the node's own park as EpochGrace (indexed for no re-run): a side
// carrier placed at V (its re-runs) and the ticks leave it; a copy of X from another peer places it.
void d3_grace(Rig& g) {
    const std::size_t a = g.relay(true), v = g.relay(false), c = g.relay(false), l = g.relay(true);
    g.connect(a, v);
    g.connect(a, c);
    g.connect(c, v);
    g.connect(a, l);
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 200 + i);
    Filter f;
    f.hold = [v](const FakeWire::Msg& m) { return m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.drop = [a, l](const FakeWire::Msg& m) { return (m.from == a && m.to == l) || (m.from == l && m.to == a); };
    f.install(g.w);
    g.monero();
    g.mine(a, 2, 210);
    const Hash32 x = g.best(a);
    g.mine(l, 3, 211);  // L's sibling of X
    const Hash32 s = g.best(l);
    f.hold = nullptr;
    f.drop = [v](const FakeWire::Msg& m) { return m.to == v && is_op(m, pb::kOpFcCarrier); };
    g.act("park X at V (EpochGrace)", [&] {
        pb::PathbNodeTestAccess::park(g.n(v), g.w.id(v, a), g.carrier_frame(a, x), Missing::EpochGrace, pb::RowId::R3);
    });
    g.w.edit = nullptr;
    g.connect(l, v);
    g.deliver(l, v, g.carrier_frame(l, s), "L's sibling");
    g.ticks_until([] { return false; }, 12, v);
    const bool kept = !g.has(v, x) && g.n(v).deferred().size() == 1;
    g.deliver(c, v, g.carrier_frame(a, x), "X (copy)");
    check(kept && g.has(v, x) && g.n(v).deferred().size() == 0,
          "d3 (grace): X parked, not run again by a placement or the ticks; its copy placed it");
}

// ---------------------------------------------------------------------------
// D5: receipts on each carrier of a four-carrier losing branch V lacks, V's tip-header bound (P-47) two; A's reply to
// the first header request held: the later requests wait in A's queue and past the bound the oldest leaves; the held
// reply delivered, the queue drains; L's next carrier on the best chain is placed at V (its re-runs); the receipt
// whose request left is never asked again.
void d5(Rig& g) {
    const Race x = race(g, 4, false, false, true, [](pb::PathbNodeConfig& c) { c.waiting_cap = 2; });
    if (!x.ok) return;
    const bool synced = follow(g, x, false);
    Filter f;
    f.hold = [&x](const FakeWire::Msg& m) { return m.from == x.a && m.to == x.v && is_op(m, pb::kOpFcHeaders); };
    f.install(g.w);
    for (const pb::ReceiptBodyV3& b : x.tips) g.deliver(x.a, x.v, Rig::receipt_frame(b), "tip receipt");
    g.tick(1, x.v);
    g.w.edit = nullptr;
    const std::vector<FakeWire::Msg> held = f.held;
    for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "held header reply");
    g.ticks_until([] { return false; }, 3, x.v);
    g.monero();
    g.mine(x.l, 1, 600);
    g.ticks_until([&] {
        for (const pb::ReceiptBodyV3& b : x.tips)
            if (!g.n(x.v).pending().holds(pb::receipt_id(b))) return false;
        return true;
    }, 40, x.v);
    g.w.edit = nullptr;
    std::size_t pend = 0;
    for (const pb::ReceiptBodyV3& b : x.tips) pend += g.n(x.v).pending().holds(pb::receipt_id(b)) ? 1 : 0;
    check(synced && x.tips.size() == 4 && g.rel(x.v).stats().header_wants_dropped.load() >= 1,
          "d5: a header request left at the bound (" + std::to_string(pend) + " of 4 receipts pending at the end)");
}

// ---------------------------------------------------------------------------
// D8: objects on Monero blocks V's follower lacks: a carrier (its context wanted, the carrier class) and three
// receipts (the receipt class at its cap, 0 here: they want none; each indexed under its block); V's peers answer
// FB_GETCTX "unknown"; the want asks each peer in turn, then gives up; a copy of the carrier re-makes its want; the
// follower catches up: every object runs again and is placed.
void d8(Rig& g) {
    Follower& fo = follower(g);
    const auto opts = [](pb::PathbRelayOptions& o) {
        o.ctx_max_rounds = 2;
        o.ctx_want_max = 0;
    };
    const std::size_t a = g.relay(true), b = g.relay(false), v = g.relay(false, opts, nullptr, fo.io());
    ask_only_ctx(g.rel(v));
    g.connect(a, b);
    g.connect(a, v);
    g.connect(b, v);
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 300 + i);
    // three receipts of A, each on a Monero block V lacks
    std::vector<pb::ReceiptBodyV3> rs;
    std::vector<std::optional<pb::PathbJob>> js;
    for (std::uint32_t i = 0; i < 3; ++i) {
        g.monero();
        const Hash32 m = g.n(a).make_template(g.h.now).p_r;
        g.act("hide a Monero block at V", [&] { fo.hidden.insert(m); });
        js.push_back(g.h.job(a, 2 + i, 310 + i));
    }
    // the carrier on the last of them; B's copy of it held
    Filter f;
    f.hold = [b, v](const FakeWire::Msg& m) { return m.from == b && m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.mine(a, 4, 320);
    const Hash32 c = g.best(a);
    f.hold = nullptr;
    f.drop = [b, v](const FakeWire::Msg& m) { return m.from == b && m.to == v && is_op(m, pb::kOpFbReceipts); };
    for (std::uint32_t i = 0; i < 3; ++i)
        if (js[i] && g.share(a, *js[i], 310 + i) == pb::NodeAction::Pending) {
            pb::ReceiptBodyV3 r = js[i]->body;
            r.blob.nonce = 310 + i;
            rs.push_back(r);
        }
    g.ticks_until([] { return false; }, 30, v);
    std::vector<FakeWire::Msg> held = f.held;
    g.w.edit = nullptr;
    for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "c (copy)");
    g.ticks_until([] { return false; }, 4, v);
    g.act("the follower catches up at V", [&] {
        fo.hidden.clear();
        g.rel(v).on_monero_tip();
    });
    g.run();
    g.ticks_until([&] { return g.has(v, c); }, 6, v);
    std::size_t pend = 0;
    for (const pb::ReceiptBodyV3& r : rs) pend += g.n(v).pending().holds(pb::receipt_id(r)) ? 1 : 0;
    check(rs.size() == 3 && held.size() == 1 && g.has(v, c),
          "d8: the carrier placed once the follower caught up (" + std::to_string(pend) + " receipts pending)");
}

// ---------------------------------------------------------------------------
// D9 (seed): a carrier on a P_r whose seed V lacks DEFERs (Seed): indexed, nothing asked; the seed held and the
// follower's event: placed. D9 (weights): a carrier of 413 transactions on a P_r V holds without its weights (above
// the floor) DEFERs (MissingWeights), no context asked; the weights recorded and the follower's event: placed.
void d9(Rig& g, bool weights) {
    Follower& fo = follower(g);
    fo.exact = weights;
    const auto exact_z = [](pb::PathbNodeIo& io) {
        const auto inner = io.resolve_pr;
        io.resolve_pr = [inner](const Hash32& p_r) {
            pb::PrInfo r = inner(p_r);
            r.in.z = r.in.z_lt = 600000;
            return r;
        };
    };
    const std::size_t a = g.relay(true, nullptr, nullptr, weights ? Rig::IoTweak(exact_z) : nullptr);
    const std::size_t v = g.relay(false, nullptr, nullptr, fo.io());
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(a, i % 5, 3100 + i);
    }
    g.monero();
    const Hash32 s = g.n(a).make_template(g.h.now).p_r;
    g.act(weights ? "the weights of P_r not held at V" : "the seed of P_r not held at V", [&] {
        if (weights)
            fo.weightless.insert(s);
        else
            fo.noseed.insert(s);
    });
    if (weights) g.h.txs = blob_txs(412, 400, 1, 0x30);
    g.mine(a, 2, 3300);
    const Hash32 c = g.best(a);
    g.h.txs.clear();
    g.ticks_until([] { return false; }, 3, v);
    const bool parked = !g.has(v, c) && g.n(v).deferred().size() == 1;
    g.act("the input held at V", [&] {
        fo.weightless.clear();
        fo.noseed.clear();
        g.rel(v).on_monero_tip();
    });
    g.run();
    check(parked && g.has(v, c), std::string("d9") + (weights ? " (weights)" : " (seed)") + ": parked, then placed");
}

// ---------------------------------------------------------------------------
// The bucket cases: A's chain long enough for bins to seal; V's store then loses the bucket bodies of the bins sealed
// before its last two positions (as a node that holds only its claims below them). `kind`: what the sender A does with
// V's FC_GETBUCKETS.
enum class Bk { Serve, Refused, NotServed, Silent, AllClosed, LinkDrop };
struct BucketRig {
    std::size_t a = 0, b = 0, v = 0, c = SIZE_MAX, m = SIZE_MAX;
    bool ok = false;
};
BucketRig bucket_rig(Rig& g, bool third) {
    BucketRig x;
    x.a = g.relay(true);
    x.b = g.relay(false);
    x.v = g.relay(false);
    if (third) x.c = g.relay(false);
    g.connect(x.a, x.b);
    g.connect(x.a, x.v);
    g.connect(x.b, x.v);
    if (third) g.connect(x.a, x.c);
    for (std::uint32_t i = 0; i < 80; ++i) {
        g.act("monero +2", [&] { g.h.tick_monero(2); });
        g.mine(x.a, i % 3, 5000 + i);
    }
    x.ok = g.best(x.v) == g.best(x.a) && g.best(x.b) == g.best(x.a);
    g.act("V drops the bucket bodies of the bins sealed before its last two positions",
          [&] { pb::PathbNodeTestAccess::drop_buckets(g.n(x.v), 2); });
    return x;
}
// D10: A's next carrier at V DEFERs on a missing bin; FC_GETBUCKETS to the sender first (B's flood copy asks B); each
// Accepted reply with a bin completed runs the parked frames again, until every bin of the window is held. Variants by
// what A does with V's FC_GETBUCKETS: serves; refused (its reply corrupted: a strike on A, the carrier's sender, whose
// invalid-object bucket the re-run then waits for); not served (A without bucket bodies); silent (P-53 abandon); A and
// B both not serving, then a full peer C whose catch-up brings the carrier again; the link to A closing at its second
// reply (then A reconnects).
void d10(Rig& g, Bk kind) {
    BucketRig x = bucket_rig(g, kind == Bk::AllClosed);
    if (!x.ok) {
        check(false, "d10: setup");
        return;
    }
    // c mined with its frames to V held; the servers' state set; then c's frames delivered in order
    Filter f;
    f.hold = [&x](const FakeWire::Msg& m) { return m.to == x.v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.act("monero +2", [&] { g.h.tick_monero(2); });
    g.mine(x.a, 1, 5200);
    const Hash32 c = g.best(x.a);
    if (kind == Bk::NotServed || kind == Bk::AllClosed)
        g.act("A drops its bucket bodies", [&] { pb::PathbNodeTestAccess::drop_buckets(g.n(x.a)); });
    if (kind == Bk::AllClosed)
        g.act("B drops its bucket bodies", [&] { pb::PathbNodeTestAccess::drop_buckets(g.n(x.b)); });
    std::uint64_t replies = 0;
    g.w.edit = [&](FakeWire::Msg& m) {
        if (m.from != x.a || m.to != x.v || !is_op(m, pb::kOpFcBuckets)) return;
        if (kind == Bk::Refused && m.f.size() > 8) m.f[m.f.size() - 1] ^= 0x5a;
        if (kind == Bk::Silent) m.f.clear();
        if (kind == Bk::LinkDrop && ++replies == 2) {
            m.f.clear();
            g.w.links[x.v]->disconnect(g.w.id(x.v, x.a));
        }
    };
    const std::vector<FakeWire::Msg> held = f.held;
    for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "c");
    g.ticks_until([&] { return g.has(x.v, c); }, 40, x.v);
    for (int k = 0; k < 16 && !g.has(x.v, c); ++k) g.tick(10, x.v);
    g.w.edit = nullptr;
    if (kind == Bk::AllClosed) {
        g.connect(x.c, x.v);
        g.ticks_until([&] { return g.has(x.v, c); }, 20, x.v);
    }
    if (kind == Bk::LinkDrop && !g.has(x.v, c)) {
        g.reconnect(x.a, x.v);
        g.ticks_until([&] { return g.has(x.v, c); }, 20, x.v);
    }
    check(g.has(x.v, c), "d10: the carrier placed after its bins were fetched");
}
// D13: A and B never answer V's FC_GETBUCKETS: at P-53 both are abandoned (closed for that carrier) and the parked
// carrier waits; C, a full peer, connects and never answers V's header request (its catch-up): when that request is
// retired at P-53 the bucket fetch runs again and goes to C, which serves: placed.
void d13(Rig& g) {
    BucketRig x = bucket_rig(g, true);
    if (!x.ok) {
        check(false, "d13: setup");
        return;
    }
    g.w.edit = [&x](FakeWire::Msg& m) {
        if (m.to != x.v || m.f.empty()) return;
        if ((m.from == x.a || m.from == x.b) && m.f[0] == pb::kOpFcBuckets) m.f.clear();
        if (m.from == x.c && m.f[0] == pb::kOpFcHeaders) m.f.clear();
    };
    g.act("monero +2", [&] { g.h.tick_monero(2); });
    g.mine(x.a, 1, 5300);
    const Hash32 c = g.best(x.a);
    g.ticks_until([] { return false; }, 14, x.v);
    const bool waits = !g.has(x.v, c);
    g.connect(x.c, x.v);
    g.ticks_until([&] { return g.has(x.v, c); }, 30, x.v);
    g.w.edit = nullptr;
    check(waits && g.has(x.v, c), "d13: the carrier waits with A and B closed; placed after the header request's P-53");
}

// ---------------------------------------------------------------------------
// D11: payee 4's first placement is A's carrier ck; V forgets payee 4's reference after placing it: A's next carrier
// (its window pays payee 4) DEFERs (MissingRef), nothing asked. L, cut from A, mined a sibling of ck for payee 4; its
// catch-up from V makes it switch to ck and re-pend it as a receipt, which V admits (the reference learned); the
// sibling as a carrier is placed at V off the best chain; then L's next carrier extends V's best chain: the parked
// carrier runs again and is placed.
void d11(Rig& g) {
    const std::size_t a = g.relay(true), v = g.relay(false), l = g.relay(true);
    g.connect(a, v);
    g.connect(a, l);
    for (std::uint32_t i = 0; i < 6; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(a, i % 4, 6000 + i);
    }
    Filter f;
    f.drop = [a, l](const FakeWire::Msg& m) { return (m.from == a && m.to == l) || (m.from == l && m.to == a); };
    f.install(g.w);
    g.monero();
    g.mine(a, 4, 6100);
    const Hash32 ck = g.best(a);
    const Hash32 p4 = pb::key_ref_identity(g.net.refs[4]);
    g.act("V forgets payee 4's reference", [&] { pb::PathbNodeTestAccess::forget_ref(g.n(v), p4); });
    g.mine(a, 0, 6101);
    const Hash32 c = g.best(a);
    g.mine(l, 4, 6102);
    const Hash32 s = g.best(l);
    g.w.edit = nullptr;
    g.ticks_until([] { return false; }, 2, v);
    const bool parked = g.has(v, ck) && !g.has(v, c);
    g.connect(l, v);
    g.deliver(l, v, g.carrier_frame(l, s), "L's sibling of ck");
    g.ticks_until([] { return false; }, 2, v);
    const bool still = !g.has(v, c);
    g.mine(l, 2, 6103);
    g.ticks_until([&] { return g.has(v, c); }, 4, v);
    check(parked && still && g.has(v, c) && g.has(v, s),
          "d11: parked on the reference; the reference learned and a side placement leave it; the next best-chain "
          "placement runs it again: placed");
}

// ---------------------------------------------------------------------------
// D12: V, 300 carriers behind A (header pages of 128 at V's journal depth), connects: its catch-up asks headers, then
// the bodies of each page (300 carrier ids asked of A in all); twenty bodies lost once (their page lapses at P-53 and
// is asked again); A mines on meanwhile (V's best moves mid-way).
void d12(Rig& g) {
    const auto j128 = [](pb::PathbNodeConfig& c) { c.journal_depth = 128; };
    const std::size_t a = g.relay(true), v = g.relay(false, nullptr, j128);
    for (std::uint32_t i = 0; i < 300; ++i) {
        if (i % 3 == 0) g.act("monero +1", [&] { g.h.tick_monero(1); });
        g.act("mine 0", [&] {
            const std::optional<pb::PathbJob> j = g.h.job(a, i % 5, 7000 + i);
            if (j) (void)g.n(a).on_own_share(*j, 7000 + i, Hash32{});
        });
    }
    std::uint64_t carriers = 0;
    g.w.edit = [&](FakeWire::Msg& m) {
        if (m.from == a && m.to == v && is_op(m, pb::kOpFcCarrier) && ++carriers > 40 && carriers <= 60) m.f.clear();
    };
    g.connect(a, v);
    for (int i = 0; i < 60 && g.best(v) != g.best(a); ++i) {
        if (i == 5 || i == 6) g.mine(a, 1, 7400 + static_cast<std::uint32_t>(i));
        g.tick(1, v);
    }
    g.w.edit = nullptr;
    check(g.best(v) == g.best(a), "d12: V caught up to A's tip");
}

// ---------------------------------------------------------------------------
// D16: one peer relays more objects than its invalid-object budget's capacity (C = 1) that DEFER on one Monero block V
// lacks, then fresh objects: no token is kept for a DEFER; the follower catches up; then a HELLO re-offer of a full
// pending set (P-09 = 24). Returns (A, V).
std::pair<std::size_t, std::size_t> d16_run(Rig& g) {
    Follower& fo = follower(g);
    const auto cap = [](pb::PathbNodeConfig& c) { c.pending_cap = 24; };
    const std::size_t a = g.relay(true, nullptr, cap), v = g.relay(false, nullptr, cap, fo.io());
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 8000 + i);
    g.monero();
    const Hash32 m = g.n(a).make_template(g.h.now).p_r;
    g.act("hide a Monero block at V", [&] { fo.hidden.insert(m); });
    std::vector<std::optional<pb::PathbJob>> jobs;
    for (std::uint32_t i = 0; i < 4; ++i) jobs.push_back(g.h.job(a, i % 5, 8100 + i));
    g.mine(a, 1, 8110);
    for (std::uint32_t i = 0; i < 4; ++i)
        if (jobs[i]) g.share(a, *jobs[i], 8100 + i);
    g.monero();
    jobs.clear();
    for (std::uint32_t i = 0; i < 3; ++i) jobs.push_back(g.h.job(a, i % 5, 8120 + i));
    g.mine(a, 1, 8111);
    for (std::uint32_t i = 0; i < 3; ++i)
        if (jobs[i]) g.share(a, *jobs[i], 8120 + i);
    g.tick(1, v);
    g.act("the follower catches up at V", [&] {
        fo.hidden.clear();
        g.rel(v).on_monero_tip();
    });
    g.run();
    g.tick(1, v);
    jobs.clear();
    for (std::uint32_t i = 0; i < 24; ++i) jobs.push_back(g.h.job(a, i % 5, 8200 + i));
    Filter f;
    f.drop = [a, v](const FakeWire::Msg& m) { return m.from == a && m.to == v; };
    f.install(g.w);
    g.mine(a, 1, 8112);
    for (std::uint32_t i = 0; i < 24; ++i)
        if (jobs[i]) g.share(a, *jobs[i], 8200 + i);
    g.w.edit = nullptr;
    g.disconnect(v, a);
    g.reconnect(a, v);
    g.ticks_until([] { return false; }, 3, v);
    check(g.n(v).pending().size() == g.n(a).pending().size(), "d16: V holds A's pending set after the re-offer");
    return {a, v};
}
void d16(Rig& g) { (void)d16_run(g); }

// ---------------------------------------------------------------------------
// D17: V restarts from its store while A mines on; it reconnects: its catch-up (headers first) and A's re-offer bring
// A's tip and pending set.
void d17(Rig& g) {
    const std::size_t a = g.relay(true);
    g.r.push_back(kat_relay(g.h, g.w, kat_table(g.net), false, false, nullptr, nullptr, nullptr, true));
    const std::size_t v = g.r.back().node;
    g.t.add(v, g.r.back().relay.get(), g.r.back().links.get());
    MemoryKv* kv = g.h.kvs.back().get();
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 6; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(a, i % 5, 9000 + i);
    }
    g.act("V stops", [&] {
        g.w.links[v]->disconnect(g.w.id(v, a));
        g.r.back().relay->stop();
        g.w.relays.erase(std::find(g.w.relays.begin(), g.w.relays.end(), g.r.back().relay.get()));
    });
    g.run();
    for (std::uint32_t i = 0; i < 5; ++i) g.mine(a, i % 5, 9100 + i);
    const std::vector<std::optional<pb::PathbJob>> jobs = {g.h.job(a, 2, 9200), g.h.job(a, 3, 9201)};
    g.mine(a, 1, 9105);
    for (std::uint32_t i = 0; i < 2; ++i)
        if (jobs[i]) g.share(a, *jobs[i], 9200 + i);
    // V again: its store loaded
    bool loaded = false;
    g.act("V restarts from its store", [&] {
        g.r.push_back(kat_relay(g.h, g.w, kat_table(g.net), false, false, nullptr, nullptr, nullptr, false,
                                [&](const pb::PathbNodeConfig& cfg, pb::PathbNodeIo io) {
                                    pb::LoadInputs in;
                                    in.T = cfg.T;
                                    in.journal_depth = cfg.journal_depth;
                                    pb::LoadResult lr = pb::pathb_load(*kv, g.net.pool_id, g.net.rules_g, in);
                                    loaded = lr.state.has_value();
                                    if (!lr.state) return std::make_unique<pb::PathbNode>(cfg, std::move(io));
                                    return std::make_unique<pb::PathbNode>(cfg, std::move(io), std::move(*lr.state), kv);
                                }));
        g.t.add(g.r.back().node, g.r.back().relay.get(), g.r.back().links.get());
    });
    const std::size_t v2 = g.r.back().node;
    g.connect(a, v2);
    g.ticks_until([&] { return g.best(v2) == g.best(a) && g.n(v2).pending().size() == 2; }, 12, v2);
    check(loaded && g.best(v2) == g.best(a) && g.n(v2).pending().size() == 2,
          "d17: the restarted node caught up to A's tip and holds A's pending set");
}

// ---------------------------------------------------------------------------
// D18: a switch by the journal across the activation height of an upgrade epoch, with a frame parked: A and L race
// from position 6; L's branch (heavier) reaches V tip first (parked on its unknown parent), then the rest: V switches.
void d18(Rig& g) {
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    const Hash32 d1 = pb::rules_digest(r1);
    pb::EpochTable impl = kat_table(g.net);
    impl.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, 8));
    impl.compiled.push_back(pb::CompiledEpoch{1, d1, r1});
    const std::size_t a = g.relay(true, nullptr, nullptr, nullptr, &impl);
    const std::size_t l = g.relay(true, nullptr, nullptr, nullptr, &impl);
    const std::size_t v = g.relay(false, nullptr, nullptr, nullptr, &impl);
    g.connect(a, l);
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 6; ++i) {
        g.monero();
        g.mine(a, 1, 1000 + i);
    }
    Filter f;
    f.drop = [a, l](const FakeWire::Msg& m) { return (m.from == a && m.to == l) || (m.from == l && m.to == a); };
    f.install(g.w);
    for (std::uint32_t i = 0; i < 3; ++i) {
        g.monero();
        g.mine(a, 2, 1100 + i);
    }
    std::vector<Hash32> lb;
    for (std::uint32_t i = 0; i < 4; ++i) {
        g.mine(l, 3, 1200 + i);
        lb.push_back(g.best(l));
    }
    g.w.edit = nullptr;
    g.connect(l, v);
    f.drop = [l, v](const FakeWire::Msg& m) { return m.from == l && m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.deliver(l, v, g.carrier_frame(l, lb.back()), "L's tip");
    g.w.edit = nullptr;
    for (std::size_t i = 0; i + 1 < lb.size(); ++i) g.deliver(l, v, g.carrier_frame(l, lb[i]), "L's branch");
    g.ticks_until([&] { return g.best(v) == lb.back(); }, 6, v);
    check(g.best(v) == lb.back(), "d18: V switched to L's branch across the activation height");
}

// ---------------------------------------------------------------------------
// The junk overlays: a peer J of V that, at the points the case names, sends V receipts on tips nobody holds (their
// header requests never answered), a variant of an honest carrier (its carried list changed: the same id, other bytes)
// and a frame that does not decode; J's FC_BUCKETS replies to V are corrupted (refused).
struct Junk {
    std::size_t j = 0, v = 0;
    std::uint32_t n = 0;
    void install(Rig& g, std::size_t jn, std::size_t vn) {
        j = jn;
        v = vn;
        g.connect(j, v);
    }
    // J's replies to V's header and bucket requests: none, and corrupted.
    std::function<void(FakeWire::Msg&)> edit() const {
        const std::size_t jj = j, vv = v;
        return [jj, vv](FakeWire::Msg& m) {
            if (m.from != jj || m.to != vv || m.f.empty()) return;
            if (m.f[0] == pb::kOpFcHeaders) m.f.clear();
            if (m.f[0] == pb::kOpFcBuckets && m.f.size() > 8) m.f[m.f.size() - 1] ^= 0x5a;
        };
    }
    void burst(Rig& g, std::size_t honest) {
        ++n;
        const std::optional<pb::PathbJob> jb = g.h.job(honest, 3, 9900 + n);
        if (jb) {
            for (std::uint8_t k = 0; k < 2; ++k) {
                pb::ReceiptBodyV3 r = jb->body;
                r.blob.nonce = 9900 + n;
                r.side.tip.fill(static_cast<std::uint8_t>(0x90 + n));
                r.side.tip[0] = k;
                g.deliver(j, v, Rig::receipt_frame(r), "junk receipt");
            }
        }
        const Hash32 t = g.best(honest);
        if (const pb::CarrierBodyV3* b = g.n(honest).bodies().get(t)) {
            pb::CarrierBodyV3 c = *b;
            if (jb) {
                pb::ReceiptBodyV3 r = jb->body;
                r.blob.nonce = 9950 + n;
                c.carried.push_back(r);
                g.deliver(j, v, pb::encode_fc_carrier(0, c, 16).value_or(Frame{}), "carrier variant");
            }
        }
        g.deliver(j, v, Frame{pb::kOpFcCarrier, 0x01, 0, 0, 0, 0, 0x00, static_cast<std::uint8_t>(n)}, "junk frame");
    }
};
// The overlays run the honest case with J connected to V from the start of the scripted part.
void jd2(Rig& g) {
    // the honest D2 with J: J connected to V before X; J's bursts around X
    const auto j16 = [](pb::PathbNodeConfig& c) { c.journal_depth = 16; };
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const std::size_t a = g.relay(true), b = g.relay(true), v = g.relay(false, p1, j16), jn = g.relay(false);
    Junk jk;
    g.connect(a, b);
    g.connect(a, v);
    jk.install(g, jn, v);
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 900 + i);
    Filter f;
    f.drop = [a, b](const FakeWire::Msg& m) { return (m.from == a && m.to == b) || (m.from == b && m.to == a); };
    f.install(g.w);
    for (std::uint32_t i = 0; i < 24; ++i) {
        if (i % 3 == 0) g.monero();
        if (i < 20) g.mine(a, i % 5, 910 + i);
        g.mine(b, i % 5, 940 + i);
    }
    g.w.edit = nullptr;
    const std::optional<Hash32> x = g.n(b).store().best_at(4);
    const Hash32 tip_b = g.best(b);
    g.act("disconnect 0-1", [&] { g.w.links[a]->disconnect(g.w.id(a, b)); });
    g.run();
    jk.burst(g, a);
    f.drop = nullptr;
    f.hold = [b, v](const FakeWire::Msg& m) { return m.from == b && m.to == v && !is_op(m, pb::kOpFbHello); };
    f.install(g.w);
    g.connect(b, v);
    if (x) g.deliver(b, v, g.carrier_frame(b, *x), "X");
    g.w.edit = jk.edit();
    const std::vector<FakeWire::Msg> held = f.held;
    for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "held");
    jk.burst(g, a);
    g.tick(1, v);
    for (int i = 0; i < 40 && g.best(v) != tip_b; ++i) {
        (void)g.join(v, "join step 2");
        g.tick(1, v);
    }
    g.w.edit = nullptr;
    check(g.best(v) == tip_b, "jd2: V reaches B's heavier chain under J's junk");
}
void jd4(Rig& g) {
    const Race x = race(g, 1, false, true);
    if (!x.ok) return;
    const bool synced = follow(g, x, true);
    Junk jk;
    jk.install(g, g.relay(false), x.v);
    const auto je = jk.edit();
    g.w.edit = [&x, je](FakeWire::Msg& m) {
        if (m.from == x.a && m.to == x.v && is_op(m, pb::kOpFcHeaders)) m.f.clear();
        je(m);
    };
    jk.burst(g, x.a);
    g.monero();
    const bool mined = g.mine(x.a, 5, 420) == pb::NodeAction::Placed;
    const Hash32 c = g.best(x.a);
    jk.burst(g, x.a);
    g.ticks_until([&] { return g.best(x.v) == c; }, 30, x.v);
    g.w.edit = nullptr;
    check(synced && mined && g.best(x.v) == c, "jd4: X placed under J's junk");
}
void jd8(Rig& g) {
    Follower& fo = follower(g);
    const auto opts = [](pb::PathbRelayOptions& o) {
        o.ctx_max_rounds = 2;
        o.ctx_want_max = 2;
    };
    const std::size_t a = g.relay(true), b = g.relay(false), v = g.relay(false, opts, nullptr, fo.io()), jn = g.relay(false);
    ask_only_ctx(g.rel(v));
    g.connect(a, b);
    g.connect(a, v);
    g.connect(b, v);
    Junk jk;
    jk.install(g, jn, v);
    g.w.edit = jk.edit();
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 300 + i);
    g.monero();
    const Hash32 m = g.n(a).make_template(g.h.now).p_r;
    g.act("hide a Monero block at V", [&] { fo.hidden.insert(m); });
    jk.burst(g, a);
    g.mine(a, 4, 320);
    const Hash32 c = g.best(a);
    jk.burst(g, a);
    g.ticks_until([] { return false; }, 30, v);
    g.act("the follower catches up at V", [&] {
        fo.hidden.clear();
        g.rel(v).on_monero_tip();
    });
    g.run();
    g.ticks_until([&] { return g.has(v, c); }, 6, v);
    g.w.edit = nullptr;
    check(g.has(v, c), "jd8: the carrier placed once the follower caught up, under J's junk");
}
void jd10(Rig& g) {
    BucketRig x = bucket_rig(g, false);
    if (!x.ok) {
        check(false, "jd10: setup");
        return;
    }
    Junk jk;
    jk.install(g, g.relay(false), x.v);
    // c mined with its frames to V held; J's copy of c first (V's bucket fetch asks J, whose reply is refused), then
    // A's and B's
    Filter f;
    f.hold = [&x](const FakeWire::Msg& m) { return m.to == x.v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.act("monero +2", [&] { g.h.tick_monero(2); });
    g.mine(x.a, 1, 5200);
    const Hash32 c = g.best(x.a);
    g.w.edit = jk.edit();
    g.deliver(jk.j, x.v, g.carrier_frame(x.a, c), "c (copy)");
    const std::vector<FakeWire::Msg> held = f.held;
    for (const FakeWire::Msg& m : held) g.deliver(m.from, m.to, m.f, "c");
    jk.burst(g, x.a);
    g.ticks_until([&] { return g.has(x.v, c); }, 40, x.v);
    for (int k = 0; k < 16 && !g.has(x.v, c); ++k) g.tick(10, x.v);
    g.w.edit = nullptr;
    check(g.has(x.v, c), "jd10: the carrier placed after its bins were fetched, under J's junk");
}
void jd12(Rig& g) {
    const auto j128 = [](pb::PathbNodeConfig& c) { c.journal_depth = 128; };
    const std::size_t a = g.relay(true), v = g.relay(false, nullptr, j128), jn = g.relay(false);
    for (std::uint32_t i = 0; i < 300; ++i) {
        if (i % 3 == 0) g.act("monero +1", [&] { g.h.tick_monero(1); });
        g.act("mine 0", [&] {
            const std::optional<pb::PathbJob> j = g.h.job(a, i % 5, 7000 + i);
            if (j) (void)g.n(a).on_own_share(*j, 7000 + i, Hash32{});
        });
    }
    Junk jk;
    jk.install(g, jn, v);
    g.w.edit = jk.edit();
    g.connect(a, v);
    for (int i = 0; i < 60 && g.best(v) != g.best(a); ++i) {
        if (i == 2 || i == 8) jk.burst(g, a);
        g.tick(1, v);
    }
    g.w.edit = nullptr;
    check(g.best(v) == g.best(a), "jd12: V caught up to A's tip under J's junk");
}
void jd16(Rig& g) {
    Follower& fo = follower(g);
    const auto cap = [](pb::PathbNodeConfig& c) { c.pending_cap = 24; };
    const std::size_t a = g.relay(true, nullptr, cap), v = g.relay(false, nullptr, cap, fo.io()), jn = g.relay(false);
    g.connect(a, v);
    Junk jk;
    jk.install(g, jn, v);
    g.w.edit = jk.edit();
    for (std::uint32_t i = 0; i < 3; ++i) g.mine(a, 1, 8000 + i);
    g.monero();
    const Hash32 m = g.n(a).make_template(g.h.now).p_r;
    g.act("hide a Monero block at V", [&] { fo.hidden.insert(m); });
    std::vector<std::optional<pb::PathbJob>> jobs;
    for (std::uint32_t i = 0; i < 4; ++i) jobs.push_back(g.h.job(a, i % 5, 8100 + i));
    g.mine(a, 1, 8110);
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (jobs[i]) g.share(a, *jobs[i], 8100 + i);
        if (i == 1) jk.burst(g, a);
    }
    g.tick(1, v);
    g.act("the follower catches up at V", [&] {
        fo.hidden.clear();
        g.rel(v).on_monero_tip();
    });
    g.run();
    jobs.clear();
    for (std::uint32_t i = 0; i < 24; ++i) jobs.push_back(g.h.job(a, i % 5, 8200 + i));
    g.w.edit = [a, v, je = jk.edit()](FakeWire::Msg& m) {
        if (m.from == a && m.to == v) m.f.clear();
        je(m);
    };
    g.mine(a, 1, 8112);
    for (std::uint32_t i = 0; i < 24; ++i)
        if (jobs[i]) g.share(a, *jobs[i], 8200 + i);
    g.w.edit = jk.edit();
    jk.burst(g, a);
    g.disconnect(v, a);
    g.reconnect(a, v);
    g.ticks_until([] { return false; }, 3, v);
    g.w.edit = nullptr;
    check(g.n(v).pending().size() == g.n(a).pending().size(), "jd16: V holds A's pending set after the re-offer, under junk");
}

// ---------------------------------------------------------------------------
// The RandomX worker failing: D11's honest carrier c, DEFERred at its own coinbase row (a payee reference V lacks).
// A worker that throws while `down`, and (when `arm` is set) goes down right after it hashes the body of nonce
// `die_at`.
struct RxDown {
    std::shared_ptr<bool> down = std::make_shared<bool>(false), arm = std::make_shared<bool>(false);
    std::uint32_t die_at = 0;
    Rig::IoTweak io() const {
        return [down = down, arm = arm, die = die_at](pb::PathbNodeIo& x) {
            x.verify = [orig = x.verify, down, arm, die](const pb::HashingBlob& b, std::uint64_t d, const Hash32& s) {
                if (*down) throw std::runtime_error("kat: the RandomX worker is down");
                const bool ok = orig(b, d, s);
                if (*arm && b.nonce == die) {
                    *down = true;
                    *arm = false;
                }
                return ok;
            };
        };
    }
};
// D11's opening with V's worker `rx`: A's ck placed at V, payee 4's reference forgotten at V, A's c (parked at V on
// the reference) and L's sibling s of ck (cut from A); returns (ck, c, s) and whether c parked.
struct D11Open {
    std::size_t a = 0, v = 0, l = 0;
    Hash32 ck{}, c{}, s{};
    bool parked = false;
};
D11Open d11_open(Rig& g, const RxDown& rx, const std::function<void()>& before_c) {
    D11Open o;
    g.keep.push_back(rx.down);
    g.keep.push_back(rx.arm);
    o.a = g.relay(true);
    o.v = g.relay(false, nullptr, nullptr, rx.io());
    o.l = g.relay(true);
    const std::size_t a = o.a, v = o.v, l = o.l;
    g.connect(a, v);
    g.connect(a, l);
    for (std::uint32_t i = 0; i < 6; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(a, i % 4, 6000 + i);
    }
    Filter f;
    f.drop = [a, l](const FakeWire::Msg& m) { return (m.from == a && m.to == l) || (m.from == l && m.to == a); };
    f.install(g.w);
    g.monero();
    g.mine(a, 4, 6100);
    o.ck = g.best(a);
    const Hash32 p4 = pb::key_ref_identity(g.net.refs[4]);
    g.act("V forgets payee 4's reference", [&] { pb::PathbNodeTestAccess::forget_ref(g.n(v), p4); });
    if (before_c) before_c();
    g.mine(a, 0, 6101);
    o.c = g.best(a);
    g.mine(l, 4, 6102);
    o.s = g.best(l);
    g.w.edit = nullptr;
    g.ticks_until([] { return false; }, 2, v);
    o.parked = g.has(v, o.ck) && !g.has(v, o.c);
    g.connect(l, v);
    g.deliver(l, v, g.carrier_frame(l, o.s), "L's sibling of ck");
    g.ticks_until([] { return false; }, 2, v);
    return o;
}

// D21E: c arrives while V's RandomX worker fails on every call for a span of steps; the hash of L's sibling fails
// inside the span; the span ends before the placement that runs c again.
void d21e(Rig& g) {
    RxDown rx;
    const D11Open o = d11_open(g, rx, [&] { g.act("V's RandomX worker goes down", [&] { *rx.down = true; }); });
    g.act("V's RandomX worker is back", [&] { *rx.down = false; });
    g.ticks_until([] { return false; }, 2, o.v);
    const bool still = !g.has(o.v, o.c);
    g.mine(o.l, 2, 6103);
    g.ticks_until([&] { return g.has(o.v, o.c); }, 4, o.v);
    check(o.parked && still && g.has(o.v, o.c) && g.has(o.v, o.s),
          "d21e: parked on the reference while the worker is down; placed after");
}

// D21F (armed) / D21G (never armed): c is first judged while V's RandomX worker is up; D21F's worker goes down right
// after it hashes L's next carrier (whose placement runs c again), then it is back; D21G's stays up.
void d21fg(Rig& g, bool armed) {
    RxDown rx;
    rx.die_at = 6103;
    const D11Open o = d11_open(g, rx, nullptr);
    g.act("V's RandomX worker will go down right after it hashes L's next carrier", [&] { *rx.arm = armed; });
    g.mine(o.l, 2, 6103);
    g.ticks_until([] { return false; }, 2, o.v);
    g.act("V's RandomX worker is back", [&] { *rx.down = false; });
    g.ticks_until([&] { return g.has(o.v, o.c); }, 6, o.v);
    check(o.parked && g.has(o.v, o.c) && g.has(o.v, o.s),
          std::string(armed ? "d21f" : "d21g") + ": c parked on the reference, placed in the end");
}

// D25: D16, then a second HELLO between A and V while both hold the same pending set: each re-offers it, so every
// receipt reaches the other side as a copy of a pending receipt.
void d25(Rig& g) {
    const auto [a, v] = d16_run(g);
    const std::size_t before = g.n(v).pending().size();
    g.disconnect(v, a);
    g.reconnect(a, v);
    g.ticks_until([] { return false; }, 3, v);
    check(before > 0 && g.n(v).pending().size() == before, "d25: the second re-offer's copies leave V's pending set as it was");
}

// ---------------------------------------------------------------------------
// The adoption step (pathb_kat_relay.hpp adopt_step) on the rig: each action traced, then the wire.
constexpr int kAdoptSteps = 4;  // test parameter: the most join steps the adoption step runs
AdoptStep rig_adopt(Rig& g, std::size_t v, std::size_t s) {
    return adopt_step(
            g.w, g.r[v], g.n(v), s, kAdoptSteps,
            [&g](const std::string& l, const std::function<void()>& fn) {
                g.act(l, fn);
                g.run();
            },
            [&g, v](const std::optional<pb::JoinStep>& st) { g.note_join(v, st); });
}
// A receipt of node i's job on its best tip (payee, nonce), as a one-body FB_RECEIPTS frame; nullopt: no job.
std::optional<pb::ReceiptBodyV3> job_receipt(Rig& g, std::size_t i, std::size_t payee, std::uint32_t nonce) {
    const std::optional<pb::PathbJob> j = g.h.job(i, payee, nonce);
    if (!j) return std::nullopt;
    pb::ReceiptBodyV3 r = j->body;
    r.blob.nonce = nonce;
    return r;
}
// KAT-H-ADOPT, the adoption step's self-test. S mines a chain; t is its best after three carriers; two receipts of
// S's jobs on t; S mines on past t; L mines a chain of its own without t (L is never connected here: it is the server
// that lacks t, for the step's mutant). V, a load failure (no own chain; a join
// candidate from one peer's HELLO tail), receives both receipts from P (an empty store: it cannot serve t): they
// DEFER TipUnknown and park. V then adopts S's chain through the step. After it: the join step switched, V's
// joiner_adopted rose by one, V's tree holds t, and V's relay holds the same parked receipts (their count, and each by
// its frame); run again (the relay's TipUnknown re-run), each passes row 17 and is pending at V.
void hadopt(Rig& g) {
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const std::size_t s = g.relay(true), l = g.relay(true), p = g.relay(false);
    const std::size_t v = g.relay(false, p1, nullptr, nullptr, nullptr, true);
    for (std::uint32_t i = 0; i < 3; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(s, i % 4, 40000 + i);
    }
    const Hash32 t = g.best(s);
    std::vector<pb::ReceiptBodyV3> rs;
    for (std::uint32_t k = 0; k < 2; ++k)
        if (const std::optional<pb::ReceiptBodyV3> r = job_receipt(g, s, 1 + k, 40100 + k)) rs.push_back(*r);
    for (std::uint32_t i = 0; i < 2; ++i) g.mine(s, 2 + i, 40010 + i);
    for (std::uint32_t i = 0; i < 4; ++i) g.mine(l, i % 4, 40200 + i);
    g.connect(p, v);
    for (const pb::ReceiptBodyV3& r : rs) g.deliver(p, v, Rig::receipt_frame(r), "a receipt on t");
    const std::size_t parked = g.rel(v).parked_receipts();
    bool each = rs.size() == 2;
    for (const pb::ReceiptBodyV3& r : rs) each = each && g.rel(v).receipt_parked(Rig::receipt_frame(r));
    const AdoptStep st = rig_adopt(g, v, s);
    const bool switched = st.switched();
    const bool counted = g.n(v).switch_counts().joiner_adopted == st.adopted_before + 1;
    bool kept = g.rel(v).parked_receipts() == st.parked_before && st.parked_before == parked;
    for (const pb::ReceiptBodyV3& r : rs) kept = kept && g.rel(v).receipt_parked(Rig::receipt_frame(r));
    check(parked == 2 && each, "hadopt: both receipts parked at V before the step (" + std::to_string(parked) + ")");
    check(switched && counted, "hadopt: the join step switched V and its joiner_adopted rose by one");
    check(g.has(v, t), "hadopt: V's tree holds t after the step");
    check(kept, "hadopt: V's relay holds the same parked receipts after the step (count and each by its frame)");
    g.act("V runs its TipUnknown receipts again", [&] { g.rel(v).test_rerun(Missing::TipUnknown); });
    g.run();
    bool pending = true;
    for (const pb::ReceiptBodyV3& r : rs)
        pending = pending && g.n(v).pending().holds(pb::receipt_id(r)) && !g.rel(v).receipt_parked(Rig::receipt_frame(r));
    check(pending, "hadopt: each parked receipt, run again after the step, passes row 17 and is pending at V");
}

// D19: the key cache through a genuine receipt and carrier (each node's key-cache counters traced). A mines t and u on
// t, neither reaching V on the wire; k, the receipt of A's share of a job on t, reaches V: parked on its tip; V's
// header ask places t by the header walk and k runs again on t; then t (a copy of a placed carrier) and u reach V.
// B's copy of k; A's carrier c carrying k. Then the entry of V's key cache at (t, k's P_r) erased by another payee
// list, and k2 (the receipt of A's share of another job on t, the same P_r) reaches V; B's copy of k2.
void d19(Rig& g) {
    g.t.keytrace = true;
    const std::size_t a = g.relay(true), b = g.relay(false), v = g.relay(false);
    g.connect(a, b);
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(a, i % 4, 41000 + i);
    }
    Filter f;
    f.drop = [a, v](const FakeWire::Msg& m) { return m.from == a && m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.mine(a, 1, 41100);
    const Hash32 t = g.best(a);
    const std::optional<pb::PathbJob> j = g.h.job(a, 2, 41101), j2 = g.h.job(a, 3, 41102);
    g.mine(a, 1, 41104);
    const Hash32 u = g.best(a);
    // a share's receipt: its job's body with the share's nonce
    const auto shared = [](const std::optional<pb::PathbJob>& jb, std::uint32_t nonce) {
        std::optional<pb::ReceiptBodyV3> r;
        if (jb) {
            r = jb->body;
            r->blob.nonce = nonce;
        }
        return r;
    };
    const std::optional<pb::ReceiptBodyV3> kb = shared(j, 41101), k2b = shared(j2, 41102);
    if (j) g.share(a, *j, 41101);
    g.w.edit = nullptr;
    g.deliver(a, v, g.carrier_frame(a, t), "t");
    const Hash32 k = kb ? pb::receipt_id(*kb) : Hash32{};
    g.ticks_until([&] { return g.n(v).pending().holds(k); }, 3, v);
    const bool k_in = g.n(v).pending().holds(k);
    g.deliver(a, v, g.carrier_frame(a, u), "u");
    if (kb) g.deliver(b, v, Rig::receipt_frame(*kb), "B's copy of k");
    g.mine(a, 4, 41103);
    const Hash32 c = g.best(a);
    g.act("V's key cache: another payee list at (t, k's P_r)", [&] {
        if (!j) return;
        const Hash32 other = seq32(0x19);
        g.rel(v).with_node([&](pb::PathbNode& n) {
            (void)pb::PathbNodeTestAccess::keys(n).get(g.net.pool_id, t, j->body.blob.prev_id, 0, std::span<const Hash32>(&other, 1),
                                                       false, [](std::size_t) { return std::optional<pb::XmrKeyRef>{}; });
        });
    });
    if (j2) g.share(a, *j2, 41102);
    g.ticks_until([] { return false; }, 2, v);
    if (k2b) g.deliver(b, v, Rig::receipt_frame(*k2b), "B's copy of k2");
    g.ticks_until([] { return false; }, 2, v);
    check(j && j2 && k_in && g.has(v, c) && k2b && g.n(v).pending().holds(pb::receipt_id(*k2b)),
          "d19: k pending at V after t, c placed, k2 pending at V");
}

// D22: V, a load failure with a key cache of one test-scale key set's room (P-36 configured: room for a key set paying
// every reference of the KAT net and the author) and a deferred store of two frames (its waiting cap configured), each
// node's key-cache counters traced. P (an empty store) delivers k (a receipt of S's job on t) and S's best carrier x:
// k parks TipUnknown at the relay, x ParentUnknown in V's deferred store. V adopts S's chain (the adoption step). k runs
// again (Match); S mines on (each new tip's key set at V; the oldest evicted); k2 (a receipt of an earlier job of S's on
// t) reaches V from P; then three of S's carriers whose first parent V lacks reach V (the deferred store's cap evicts
// one), then that parent.
void d22(Rig& g) {
    g.t.keytrace = true;
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const auto tiny = [&g](pb::PathbNodeConfig& c) {
        c.key_cache_bytes = pb::KeyCache::entry_bytes(g.net.refs.size() + 1);  // P-36: one such key set's room
        c.waiting_cap = 2;  // test parameter: the deferred store holds two frames, so a third evicts one
    };
    const std::size_t s = g.relay(true), p = g.relay(false);
    const std::size_t v = g.relay(false, p1, tiny, nullptr, nullptr, true);
    for (std::uint32_t i = 0; i < 3; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(s, i % 4, 42000 + i);
    }
    const Hash32 t = g.best(s);
    const std::optional<pb::ReceiptBodyV3> k = job_receipt(g, s, 1, 42100), k2 = job_receipt(g, s, 2, 42101);
    g.mine(s, 3, 42010);
    const Hash32 x = g.best(s);
    g.connect(p, v);
    if (k) g.deliver(p, v, Rig::receipt_frame(*k), "k on t");
    g.deliver(p, v, g.carrier_frame(s, x), "x");
    const std::size_t parked = g.rel(v).parked_receipts();
    const AdoptStep st = rig_adopt(g, v, s);
    g.act("V runs its TipUnknown receipts again", [&] { g.rel(v).test_rerun(Missing::TipUnknown); });
    g.run();
    const bool k_in = k && g.n(v).pending().holds(pb::receipt_id(*k));
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(s, i % 4, 42200 + i);
    }
    if (k2) g.deliver(p, v, Rig::receipt_frame(*k2), "k2 on t");
    Filter f;
    f.drop = [s, v](const FakeWire::Msg& m) { return m.from == s && m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    std::vector<Hash32> y;
    for (std::uint32_t i = 0; i < 4; ++i) {
        g.mine(s, i % 4, 42300 + i);
        y.push_back(g.best(s));
    }
    for (std::size_t i = 1; i < y.size(); ++i) g.deliver(s, v, g.carrier_frame(s, y[i]), "S's carrier");
    g.w.edit = nullptr;
    g.deliver(s, v, g.carrier_frame(s, y[0]), "their first parent");
    g.ticks_until([&] { return g.best(v) == g.best(s); }, 6, v);
    check(parked == 1 && st.switched() && k_in && g.has(v, t) && g.best(v) == g.best(s),
          "d22: k carried across the adoption and pending; V reaches S's tip");
}

// The journal depth the harness configures (Harness::config's default).
constexpr std::uint64_t kHarnessJ = 1152;

// ---------------------------------------------------------------------------
// The join chain, for a joiner that claims a span: kJoinL positions on JoinNet (Monero rows kJoinRowsAbove above the
// anchor), placed directly by a full node in the joiner KAT's chain shape (every third carrier carries one receipt),
// built once per process; the relays of chain_relay hold a copy of it. Test parameters, as v37_xmr_pathb_node_join_kat
// uses them for a non-young join (loadfail: a bin seals at L); each case that joins on it asserts that the join is
// not young.
constexpr std::uint64_t kJoinL = 4704, kJoinRowsAbove = 900;
const KatNet& join_net() {
    static const JoinNet n(kJoinRowsAbove);
    return n;
}
const KatNode& join_chain() {
    static const std::unique_ptr<KatNode> a = [] {
        auto n = std::make_unique<KatNode>(join_net(), kHarnessJ);
        grow(*n, kJoinL);
        return n;
    }();
    return *a;
}
// A relay on the rig whose node holds a copy of the join chain (its tree, store, AR, bodies and references).
std::size_t chain_relay(Rig& g, bool launch) {
    const KatNode& a = join_chain();
    const auto mk = [&a](const pb::PathbNodeConfig& cfg, pb::PathbNodeIo io) {
        pb::LoadedState st{kat_head(*a.net), a.tree, a.store, a.ar, a.bodies, 0, 0, {}};
        for (const auto& [id, ref] : a.net->book.refs) st.refs[id] = ref;
        st.refs[a.net->author_id] = a.net->author;
        return std::make_unique<pb::PathbNode>(cfg, std::move(io), std::move(st), nullptr);
    };
    g.r.push_back(kat_relay(g.h, g.w, kat_table(g.net), launch, false, nullptr, nullptr, g.outage(nullptr, launch), false,
                            mk));
    g.t.add(g.r.back().node, g.r.back().relay.get(), g.r.back().links.get());
    return g.r.back().node;
}
// Node i's best-chain carrier at position x.
Hash32 chain_at(Rig& g, std::size_t i, std::uint64_t x) { return g.n(i).store().best_at(x).value_or(Hash32{}); }
// A joined node's shape, for check messages.
std::string join_shape(const pb::PathbNode& n) {
    const pb::JoinedState* js = n.joined();
    if (js == nullptr) return "not joined";
    return std::string(js->young ? "young" : "not young") + ", x0 " + std::to_string(js->x0) + ", x1 " +
           std::to_string(js->x1) + ", L " + std::to_string(js->L) + ", claimed " + std::to_string(js->claimed.size());
}
bool claimed_span(const pb::PathbNode& n) {
    const pb::JoinedState* js = n.joined();
    return js != nullptr && !js->young && js->x1 > 1 && !js->claimed.empty();
}

// A carrier body with a forged carried list: the honest body of `id` at node i with its last carried receipt dropped
// (the same id, other bytes); empty when the body carries none.
Frame forged_list(Rig& g, std::size_t i, const Hash32& id) {
    const pb::CarrierBodyV3* b = g.n(i).bodies().get(id);
    if (b == nullptr || b->carried.empty()) return {};
    pb::CarrierBodyV3 c = *b;
    c.carried.pop_back();
    return pb::encode_fc_carrier(0, c, 16).value_or(Frame{});
}
// A carrier body with a forged carried list that keeps the count and the own body: the honest body of `id` at node i
// with its last carried receipt replaced by another one (its nonce changed: test data); empty when the body carries
// none.
Frame forged_list_kept(Rig& g, std::size_t i, const Hash32& id) {
    const pb::CarrierBodyV3* b = g.n(i).bodies().get(id);
    if (b == nullptr || b->carried.empty()) return {};
    pb::CarrierBodyV3 c = *b;
    c.carried.back().blob.nonce ^= 0x5a5a5a5au;
    return pb::encode_fc_carrier(0, c, 16).value_or(Frame{});
}
// Node i takes two jobs on its best tip t and mines a carrier on t; then shares the two jobs (two receipts on t, no
// longer its best) and mines a carrier carrying them; returns that carrier.
Hash32 mine_carrying_two(Rig& g, std::size_t i, std::uint32_t nonce) {
    const std::optional<pb::PathbJob> j1 = g.h.job(i, 1, nonce), j2 = g.h.job(i, 2, nonce + 1);
    g.mine(i, 3, nonce + 2);
    if (j1) g.share(i, *j1, nonce);
    if (j2) g.share(i, *j2, nonce + 1);
    g.mine(i, 4, nonce + 3);
    return g.best(i);
}

// D20 (b), master's words by run: V3's attempt (a body that is not its header) and V4's (the count kept: the fold
// row on a claim).
constexpr pb::AttemptEnd kD20NotHeaderEnd = pb::AttemptEnd::Contradiction;
constexpr pb::AttemptEnd kD20FoldClaimEnd = pb::AttemptEnd::Alarm;
constexpr pb::RowId kD20FoldClaimRow = pb::RowId::R11;

// D20: a forged carried list (forged_list) on the join chain. (a) A full node V1 (a copy of the chain) gets it from J
// before S's honest copy. (b) V2, a load failure, joins S on a claimed span (asserted), then gets the next forged list
// from J after L, before S's honest copy; J's second forged frame at V1 waits for J's next token there (ticks) and is
// then judged. V3 and V4, load failures, each join S with the body S serves for its carrier at x (the highest carrying
// position at or below V2's x1 + 1, where the attempt's fold row is a claim) replaced in flight: V3's by its forged list
// (a body that is not its header: the count differs), V4's by a forged list that keeps the count and the own body
// (forged_list_kept). Each attempt's end is asserted; S's frames to the node are cut once its join step returns, and
// its link to S closed after the step. (c) Honest frames at V1 and V2. J (an empty store) receives
// nothing. Each forged carrier c: S takes two jobs, mines c0 (reaching every peer), shares the jobs (receipts on c0's
// parent) and mines c carrying them, c's own frames to the nodes under test cut on the wire.
void d20(Rig& g) {
    g.h.mon_tip = h_pos(kJoinL) + 1;
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const std::size_t s = chain_relay(g, true), v1 = chain_relay(g, false), jn = g.relay(false);
    const std::size_t v2 = g.relay(false, p1, nullptr, nullptr, nullptr, true);
    const std::size_t v3 = g.relay(false, p1, nullptr, nullptr, nullptr, true);
    const std::size_t v4 = g.relay(false, p1, nullptr, nullptr, nullptr, true);
    std::set<std::size_t> cut;  // the nodes S's FC_CARRIER frames do not reach
    std::optional<Hash32> swap_id;
    std::size_t swap_to = SIZE_MAX;  // the node whose served body is replaced
    Frame swap;
    std::uint64_t replaced = 0;
    std::set<std::size_t> closed;  // nodes S's frames no longer reach (after their join step)
    g.w.edit = [&](FakeWire::Msg& m) {
        if (m.f.empty()) return;
        if ((m.to == jn && !is_op(m, pb::kOpFbHello)) || (m.from == s && closed.count(m.to) != 0)) {
            m.f.clear();
            return;
        }
        if (m.from != s || !is_op(m, pb::kOpFcCarrier)) return;
        if (cut.count(m.to) != 0) {
            m.f.clear();
            return;
        }
        if (swap_id && m.to == swap_to && carrier_id(m.f) == *swap_id) {
            m.f = swap;
            ++replaced;
        }
    };
    const auto forged_carrier = [&](std::uint32_t nonce, std::set<std::size_t> to) {
        const std::optional<pb::PathbJob> j1 = g.h.job(s, 1, nonce), j2 = g.h.job(s, 2, nonce + 1);
        g.mine(s, 3, nonce + 2);
        if (j1) g.share(s, *j1, nonce);
        if (j2) g.share(s, *j2, nonce + 1);
        cut = std::move(to);
        g.mine(s, 4, nonce + 3);
        cut.clear();
        return g.best(s);
    };
    const auto r11 = [&g](std::size_t v) {
        return g.rel(v).verdict_counts()[static_cast<std::size_t>(pb::RowId::R11)]
                                       [static_cast<std::size_t>(pb::AdmitVerdict::Strike)];
    };
    // the seconds one token of J's invalid-object budget takes to come back at V1 (the defaults: G / n per link)
    const pb::PathbRelayOptions o0;
    const double per_link = (1.0 + static_cast<double>(pb::kRuledLaneParams.r_max)) /
                            (2.0 * static_cast<double>(pb::kRuledLaneParams.carrier_interval_s)) /
                            static_cast<double>(o0.max_inbound + o0.max_outbound);
    const int token_s = static_cast<int>(1.0 / per_link) + 1;
    g.connect(s, v1);
    g.connect(jn, v1);
    // (a)
    const Hash32 c = forged_carrier(45100, {v1});
    const Frame fc = forged_list(g, s, c);
    const std::uint64_t a0 = r11(v1);
    g.deliver(jn, v1, fc, "c with a forged carried list");
    const bool a_word = r11(v1) == a0 + 1;
    g.deliver(s, v1, g.carrier_frame(s, c), "c");
    // (b) V2 joins S on a claimed span
    g.connect(jn, v2);
    const AdoptStep s2 = rig_adopt(g, v2, s);
    const bool span2 = s2.switched() && claimed_span(g.n(v2));
    check(span2, "d20 (b): V2 joined S on a claimed span (" + join_shape(g.n(v2)) + ")");
    if (!span2) {
        g.w.edit = nullptr;
        return;
    }
    // V3's and V4's attempts, the body of the carrying carrier at or below V2's x1 + 1 replaced in flight
    const pb::JoinedState& js2 = *g.n(v2).joined();
    std::uint64_t xs = js2.x1 + 1;
    for (; xs > js2.x0; --xs) {
        const pb::CarrierBodyV3* b = g.n(s).bodies().get(chain_at(g, s, xs));
        if (b != nullptr && !b->carried.empty()) break;
    }
    swap_id = chain_at(g, s, xs);
    const auto forged_join = [&](std::size_t vn, const Frame& body, std::uint64_t& served) {
        swap_to = vn;
        swap = body;
        replaced = 0;
        AdoptStep st = adopt_step(
                g.w, g.r[vn], g.n(vn), s, 1,
                [&g](const std::string& l, const std::function<void()>& fn) {
                    g.act(l, fn);
                    g.run();
                },
                [&g, &closed, vn](const std::optional<pb::JoinStep>& j) {
                    g.note_join(vn, j);
                    closed.insert(vn);
                });
        served = replaced;
        swap_to = SIZE_MAX;
        g.disconnect(vn, s);
        return st;
    };
    const Frame not_header = forged_list(g, s, *swap_id), kept = forged_list_kept(g, s, *swap_id);
    std::uint64_t served3 = 0, served4 = 0;
    const AdoptStep s3 = forged_join(v3, not_header, served3);
    const AdoptStep s4 = forged_join(v4, kept, served4);
    swap_id.reset();
    const auto first = [](const AdoptStep& st) -> const pb::AttemptReport* {
        return !st.all.empty() && st.all.front() && st.all.front()->report ? &*st.all.front()->report : nullptr;
    };
    const pb::AttemptReport* r3 = first(s3);
    const pb::AttemptReport* r4 = first(s4);
    check(!not_header.empty() && served3 >= 1 && r3 != nullptr && !s3.switched() && r3->end == kD20NotHeaderEnd &&
                  r3->strike == 0,
          "d20 (b): a body that is not its header (V3, served at " + std::to_string(xs) +
                  ") ends the attempt Contradiction, 0 tokens, no switch");
    check(!kept.empty() && served4 >= 1 && r4 != nullptr && !s4.switched() && r4->end == kD20FoldClaimEnd &&
                  r4->row == kD20FoldClaimRow && r4->at == xs && r4->strike == 0,
          "d20 (b): a forged list that keeps its header (V4, served at " + std::to_string(xs) + ", x1 + 1 = " +
                  std::to_string(js2.x1 + 1) + ") on the fold row's claim: the attempt ends " +
                  (r4 ? std::string(pb::attempt_end_name(r4->end)) + " at row " +
                                std::to_string(static_cast<int>(r4->row)) + ", position " + std::to_string(r4->at) +
                                ", tokens " + std::to_string(r4->strike)
                      : std::string("with no report")) +
                  ", no switch");
    // (b) after L at V2; the same frame at V1, judged once J's token there is back
    const Hash32 c2 = forged_carrier(45200, {v1, v2});
    const Frame fc2 = forged_list(g, s, c2);
    const std::uint64_t b2 = r11(v2), b1 = r11(v1);
    g.deliver(jn, v2, fc2, "c2 with a forged carried list");
    g.deliver(jn, v1, fc2, "c2 with a forged carried list");
    g.ticks_until([&] { return r11(v1) > b1; }, token_s, v1);
    const bool b_word = r11(v2) == b2 + 1 && r11(v1) == b1 + 1;
    g.deliver(s, v2, g.carrier_frame(s, c2), "c2");
    g.deliver(s, v1, g.carrier_frame(s, c2), "c2");
    // (c) honest
    g.monero();
    g.mine(s, 4, 45300);
    const Hash32 c3 = g.best(s);
    g.ticks_until([&] { return g.has(v1, c3) && g.has(v2, c3); }, 6);
    g.w.edit = nullptr;
    check(!fc.empty() && a_word && g.has(v1, c), "d20 (a): the forged list STRIKEs R11 at the full node; S's c placed");
    check(!fc2.empty() && b_word,
          "d20 (b): after L the forged list STRIKEs R11 at the joined node, and at the full node once J's token is back");
    check(g.has(v2, c2) && g.has(v1, c2) && g.has(v1, c3) && g.has(v2, c3),
          "d20 (c): the honest carriers placed at the full node and at the joined node");
}

// D23Y: a young joined node (the whole chain joined in full, no claim) with traffic during its join attempt and after
// L, then junk. S mines; A follows S. V (a load failure) is connected to A and S; their frames to V other than HELLO
// are held. S mines c and shares a job taken
// on c's parent (a receipt; A relays both): the held frames go on the wire just before V's join step, so they arrive
// while the attempt runs. After the attempt (after L) S mines on; then J's bursts at V.
void d23y(Rig& g) {
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const std::size_t s = g.relay(true), a = g.relay(false), jn = g.relay(false);
    const std::size_t v = g.relay(false, p1, nullptr, nullptr, nullptr, true);
    g.connect(s, a);
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) g.monero();
        g.mine(s, i % 4, 44000 + i);
    }
    Filter f;
    f.hold = [s, a, v](const FakeWire::Msg& m) {
        return (m.from == s || m.from == a) && m.to == v && !is_op(m, pb::kOpFbHello);
    };
    f.install(g.w);
    g.connect(s, v);
    g.connect(a, v);
    const std::optional<pb::PathbJob> j = g.h.job(s, 2, 44100);
    g.mine(s, 1, 44101);
    const Hash32 c = g.best(s);
    if (j) g.share(s, *j, 44100);
    g.w.edit = nullptr;
    g.act("the held frames on the wire: " + std::to_string(f.held.size()), [&] {
        for (FakeWire::Msg& m : f.held) g.w.q.push_back(m);
    });
    bool switched = false;
    for (int i = 0; i < kAdoptSteps && !switched; ++i) {
        const std::optional<pb::JoinStep> st = g.join(v, "join step " + std::to_string(v));
        switched = st && st->switched;
    }
    const bool young = g.n(v).joined() != nullptr && g.n(v).joined()->young;
    for (std::uint32_t i = 0; i < 2; ++i) g.mine(s, i % 4, 44200 + i);
    const Hash32 c2 = g.best(s);
    g.ticks_until([&] { return g.has(v, c2); }, 4, v);
    Junk jk;
    jk.install(g, jn, v);
    g.w.edit = jk.edit();
    jk.burst(g, s);
    g.ticks_until([] { return false; }, 2, v);
    g.w.edit = nullptr;
    check(switched && young && g.has(v, c) && g.has(v, c2),
          "d23y: V joined young; the honest carriers placed after L, under J's junk");
}

// D23: a joined node in its claimed span with honest traffic, then junk. S holds the join chain; V, a load failure,
// joins S (the adoption step): the attempt claims a span (asserted: not young, x1 > 1, claimed leaves). After L: copies
// of S's carriers at x1 - 1 and x1 (inside the claimed span) and at x1 + 1; S mines on L, then a carrier carrying the
// receipts of two shares; then J's bursts at V. No ClaimAlarm at V; S's new carriers placed at V.
void d23(Rig& g) {
    g.h.mon_tip = h_pos(kJoinL) + 1;
    const auto p1 = [](pb::PathbRelayOptions& o) { o.join_min_peers = 1; };
    const std::size_t s = chain_relay(g, true), jn = g.relay(false);
    const std::size_t v = g.relay(false, p1, nullptr, nullptr, nullptr, true);
    const AdoptStep st = rig_adopt(g, v, s);
    const bool span = st.switched() && claimed_span(g.n(v));
    check(span, "d23: V joined S on a claimed span (" + join_shape(g.n(v)) + ")");
    if (!span) return;
    const std::uint64_t x1 = g.n(v).joined()->x1;
    g.deliver(s, v, g.carrier_frame(s, chain_at(g, s, x1 - 1)), "a copy of S's carrier at x1 - 1");
    g.deliver(s, v, g.carrier_frame(s, chain_at(g, s, x1)), "a copy of S's carrier at x1");
    g.deliver(s, v, g.carrier_frame(s, chain_at(g, s, x1 + 1)), "a copy of S's carrier at x1 + 1");
    const Hash32 c = mine_carrying_two(g, s, 46000);
    g.ticks_until([&] { return g.has(v, c); }, 4, v);
    const bool placed = g.has(v, c);
    Junk jk;
    jk.install(g, jn, v);
    g.w.edit = jk.edit();
    jk.burst(g, s);
    g.ticks_until([] { return false; }, 2, v);
    g.w.edit = nullptr;
    check(placed && g.rel(v).stats().claim_alarms.load() == 0,
          "d23: S's carriers on L placed at the joined node; no ClaimAlarm there");
}

// D24F: a copy of a placed carrier after a switch across a FIXED activation height (it pins R13: each copy is judged
// in full and ends AdmitCarrier, nothing changed). D18's switch, A's losing branch two carriers (the second carrying
// two receipts of A's shares on the fork point); then a copy of each of A's carriers V placed before the switch (now
// off V's best chain), from A.
void d24f(Rig& g) {
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    const Hash32 d1 = pb::rules_digest(r1);
    pb::EpochTable impl = kat_table(g.net);
    impl.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, 8));
    impl.compiled.push_back(pb::CompiledEpoch{1, d1, r1});
    const std::size_t a = g.relay(true, nullptr, nullptr, nullptr, &impl);
    const std::size_t l = g.relay(true, nullptr, nullptr, nullptr, &impl);
    const std::size_t v = g.relay(false, nullptr, nullptr, nullptr, &impl);
    g.connect(a, l);
    g.connect(a, v);
    for (std::uint32_t i = 0; i < 6; ++i) {
        g.monero();
        g.mine(a, 1, 1000 + i);
    }
    Filter f;
    f.drop = [a, l](const FakeWire::Msg& m) { return (m.from == a && m.to == l) || (m.from == l && m.to == a); };
    f.install(g.w);
    g.monero();
    const Hash32 ac = mine_carrying_two(g, a, 1100);
    const pb::CarrierNode* acn = g.n(a).tree().find(ac);
    const std::vector<Hash32> ab = {acn != nullptr ? acn->parent : Hash32{}, ac};
    std::vector<Hash32> lb;
    for (std::uint32_t i = 0; i < 4; ++i) {
        g.mine(l, 3, 1200 + i);
        lb.push_back(g.best(l));
    }
    g.w.edit = nullptr;
    g.connect(l, v);
    f.drop = [l, v](const FakeWire::Msg& m) { return m.from == l && m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.deliver(l, v, g.carrier_frame(l, lb.back()), "L's tip");
    g.w.edit = nullptr;
    for (std::size_t i = 0; i + 1 < lb.size(); ++i) g.deliver(l, v, g.carrier_frame(l, lb[i]), "L's branch");
    g.ticks_until([&] { return g.best(v) == lb.back(); }, 6, v);
    const bool switched = g.best(v) == lb.back();
    for (const Hash32& x : ab) g.deliver(a, v, g.carrier_frame(a, x), "a copy of A's carrier");
    g.ticks_until([] { return false; }, 2, v);
    check(switched, "d24f: V switched to L's branch across the activation height");
}

// D24V: a one-branch vote activation; the losing heavier branch defers at the boundary, no switch. At every node the
// ratchet parameters are a small valid K30 set (kD24Rp: window 4, GRACE 8, TIMEOUT 40 positions; test parameters),
// and epoch 1 is a vote deployment from position kD24Start, compiled at all three nodes. A mines positions 1 .. f =
// kD24Start - 1 (V and L follow); then A and L race from f with their link cut. A's branch (A votes yes) locks window 2
// (positions 8 .. 11) and activates epoch 1 at (2 + 1) x 4 - 1 + 8 = 19; L votes no (--vote no): L's branch never
// locks. V follows A to position kD24A; then L's heavier branch (to kD24A + 2) reaches V. Then a copy of each of A's
// branch carriers, from A; then L mines kD24Span more positions (the Monero tip two heights per position). Asserted:
// L's carrier at f + GRACE + 1 is DEFER EpochGrace at row 3 and parked, its children up to L's tip ParentUnknown; A's
// copies end R13 / AdmitCarrier and none is parked; V stays on A's branch; over the span, the EpochGrace frame keeps
// its one slot, each new L position parks one ParentUnknown child, and nothing is run again.
constexpr pb::RatchetParams kD24Rp{4, 8, 40};
// kD24Span: test parameter, the L positions over which the parked frames' cost is counted.
constexpr std::uint64_t kD24Start = 8, kD24A = 20, kD24Span = 24;
void d24v(Rig& g) {
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    const Hash32 d1 = pb::rules_digest(r1);
    pb::EpochTable impl = kat_table(g.net);
    impl.attempts.push_back(ratchet_sim::vote(kD24Rp, 1, d1, kD24Start));
    impl.compiled.push_back(pb::CompiledEpoch{1, d1, r1});
    const auto yes = [](pb::PathbNodeConfig& c) { c.rp = kD24Rp; };
    const auto no = [](pb::PathbNodeConfig& c) {
        c.rp = kD24Rp;
        c.vote_no = true;
    };
    const std::size_t a = g.relay(true, nullptr, yes, nullptr, &impl);
    const std::size_t l = g.relay(true, nullptr, no, nullptr, &impl);
    const std::size_t v = g.relay(false, nullptr, yes, nullptr, &impl);
    g.connect(a, l);
    g.connect(a, v);
    for (std::uint64_t x = 1; x < kD24Start; ++x) {
        g.monero();
        g.mine(a, 1, 47000 + static_cast<std::uint32_t>(x));
    }
    Filter f;
    f.drop = [a, l](const FakeWire::Msg& m) { return (m.from == a && m.to == l) || (m.from == l && m.to == a); };
    f.install(g.w);
    std::vector<Hash32> ab;
    for (std::uint64_t x = kD24Start; x <= kD24A; ++x) {
        g.monero();
        g.mine(a, 2, 47100 + static_cast<std::uint32_t>(x));
        ab.push_back(g.best(a));
    }
    std::vector<Hash32> lb;
    for (std::uint64_t x = kD24Start; x <= kD24A + 2; ++x) {
        g.mine(l, 3, 47200 + static_cast<std::uint32_t>(x));
        lb.push_back(g.best(l));
    }
    g.w.edit = nullptr;
    const bool followed = g.best(v) == ab.back();
    const pb::CarrierNode* atip = g.n(v).tree().find(ab.back());
    const bool activated = atip != nullptr && atip->rs.epoch_cur == 1;
    const pb::CarrierNode* ltip = g.n(l).tree().find(lb.back());
    const bool l_not = ltip != nullptr && ltip->rs.epoch_cur == 0;
    const auto r3_defers = [&g, v] {
        return g.rel(v).verdict_counts()[static_cast<std::size_t>(pb::RowId::R3)]
                                       [static_cast<std::size_t>(pb::AdmitVerdict::Defer)];
    };
    const std::uint64_t r3_before = r3_defers();  // before L's branch reaches V
    g.connect(l, v);
    f.drop = [l, v](const FakeWire::Msg& m) { return m.from == l && m.to == v && is_op(m, pb::kOpFcCarrier); };
    f.install(g.w);
    g.deliver(l, v, g.carrier_frame(l, lb.back()), "L's tip");
    g.w.edit = nullptr;
    for (std::size_t i = 0; i + 1 < lb.size(); ++i) g.deliver(l, v, g.carrier_frame(l, lb[i]), "L's branch");
    g.ticks_until([&] { return g.best(v) == lb.back(); }, 6, v);
    const bool switched = g.best(v) == lb.back();
    // V's parked frames: by cause, and one id's cause; V's verdicts by row and word; V's re-runs
    const auto parked_n = [&g, v](Missing m) {
        std::size_t n = 0;
        for (const Hash32& d : g.n(v).deferred().digests())
            if (const pb::ParkedFrame* pf = g.n(v).deferred().get(d)) n += pf->cause == m ? 1 : 0;
        return n;
    };
    const auto parked_as = [&g, v](const Hash32& id, Missing m) {
        for (const Hash32& d : g.n(v).deferred().digests())
            if (const pb::ParkedFrame* pf = g.n(v).deferred().get(d); pf != nullptr && pf->id == id) return pf->cause == m;
        return false;
    };
    const auto words = [&g, v](pb::RowId row, pb::AdmitVerdict w) {
        return g.rel(v).verdict_counts()[static_cast<std::size_t>(row)][static_cast<std::size_t>(w)];
    };
    const auto reruns = [&g, v] { return g.rel(v).stats().parked_reruns.load(); };
    const std::size_t xb = kD24Start - 1 + kD24Rp.grace + 1;  // f + GRACE + 1
    const std::size_t ib = xb - kD24Start;                    // its index in L's branch
    // the boundary carrier reaches V twice (L's reply to V's catch-up, then the script's delivery of L's branch): both
    // judgments DEFER at row 3; one frame parked
    const bool boundary = parked_as(lb[ib], Missing::EpochGrace) && r3_defers() - r3_before == 2 &&
                          parked_n(Missing::EpochGrace) == 1;
    bool children = true;
    for (std::size_t i = ib + 1; i < lb.size(); ++i) children = children && parked_as(lb[i], Missing::ParentUnknown);
    const std::uint64_t r0 = reruns();
    const std::size_t held0 = g.n(v).deferred().digests().size();
    const std::uint64_t c0 = words(pb::RowId::R13, pb::AdmitVerdict::AdmitCarrier);
    for (std::size_t i = 0; i < ab.size(); ++i)
        g.deliver(a, v, g.carrier_frame(a, ab[i]), "a copy of A's carrier at " + std::to_string(kD24Start + i));
    const bool copies = words(pb::RowId::R13, pb::AdmitVerdict::AdmitCarrier) == c0 + ab.size() &&
                        g.n(v).deferred().digests().size() == held0;
    const std::size_t pu0 = parked_n(Missing::ParentUnknown);
    std::size_t moves = 0;
    std::optional<std::uint64_t> h = g.n(v).best_record();
    for (std::uint64_t k = 0; k < kD24Span; ++k) {
        g.monero(2);
        g.mine(l, 3, 47400 + static_cast<std::uint32_t>(k));
        const std::optional<std::uint64_t> h2 = g.n(v).best_record();
        moves += h2 != h ? 1 : 0;
        h = h2;
    }
    const std::size_t pu1 = parked_n(Missing::ParentUnknown);
    check(followed && activated && l_not,
          "d24v: V followed A's branch (epoch 1 active at its tip); L's branch not activated");
    check(boundary, "d24v: L's carrier at f + GRACE + 1 = " + std::to_string(xb) +
                            ": both its judgments DEFER EpochGrace at row 3, one frame parked (the only EpochGrace frame)");
    check(children, "d24v: its children up to L's tip parked ParentUnknown");
    check(copies, "d24v: A's " + std::to_string(ab.size()) + " copies end R13 / AdmitCarrier, none parked");
    check(!switched && g.best(v) == ab.back(), "d24v: V does not switch: its best is A's tip");
    check(parked_n(Missing::EpochGrace) == 1 && pu1 == pu0 + kD24Span && reruns() == r0 && moves == 0,
          "d24v: over " + std::to_string(kD24Span) + " L positions: the EpochGrace frame keeps one slot, " +
                  std::to_string(pu1 - pu0) + " ParentUnknown children parked (one per position), re-runs " +
                  std::to_string(reruns() - r0) + ", V's best record moves " + std::to_string(moves));
}

// ===========================================================================
struct Case {
    const char* name;
    std::function<void(Rig&)> run;
    const char* golden;                   // sha256 of the trace
    const KatNet& (*net)() = nullptr;     // the case's net (none: the KAT's default KatNet)
};
// The rig a case runs on.
std::unique_ptr<Rig> rig_for(const Case& c) { return c.net ? std::make_unique<Rig>(c.net()) : std::make_unique<Rig>(); }

const std::vector<Case>& cases() {
    static const std::vector<Case> c = {
            {"D1a", [](Rig& g) { d1(g, 1, 0); }, "3b291926180cfd139350e8f3ad17f54174737f4d1001a6146a660ec7b77375cb"},
            {"D1b", [](Rig& g) { d1(g, 2, 1); }, "2e52fa4438bdbb6f4c0e30b7d4dbbf5602663cfcf44d1cd544f5a297a523cabc"},
            {"D1c", [](Rig& g) { d1(g, 3, 2); }, "538257087deb8ed95fdea7b8e39d351515551aa3123da191e496144c379711cb"},
            {"D2", d2, "baaf932d3008351853910959d49f1a5026474c527bf27a4f42ca19d4638d190c"},
            {"D3a", d3_hold, "c135831d56113bbe354034a3ded15f024dd8c8dbfc9c4b8dff2465c67bdd593d"},
            {"D3b", d3_grace, "b9e9eda5f6eba44b01007693b0dab7bab45cd4adb666bc7390e58f78ab97e650"},
            {"D4a", d4_frame, "0186c669931a7a80365a2dc28184762d58347c08fc311483daea9c1dd90525ef"},
            {"D4b", d4_receipt, "4a1fbff174836985c436257e2cfd09f96f5c6e411d510308562856d2adc70b77"},
            {"D5", d5, "3cc153bf771edf886ae74bf55348386fdb478bc3a465c4d48eb5fafeb3abcf06"},
            {"D6a", [](Rig& g) { d6(g, false); }, "30d25bec32b45bd00c3a38a59b252566da239bd3a349cf12019ce3e362b95e5b"},
            {"D6b", [](Rig& g) { d6(g, true); }, "d5cb8ddf3a1e74aaa85f1aa2bc03089e23ccf540f1708261a22cb05b745263c9"},
            {"D6c", d6_frame, "d5d9b59653e90a43c0607143bcc170be7f81ba31ddd7fb80ff1d8cb6a1b1fc91"},
            {"D7", d7, "509e43e43919d4efcd2364156f29038dcb08871d71698428339762bf45cbf8f5"},
            {"D8", d8, "7eaba3b1b82155173e3b7d1c0cf6a927c726b3d7595c922b9b24ae338c53b815"},
            {"D9a", [](Rig& g) { d9(g, false); }, "f7abced86c3c6677c1b19b3696750dcb025a53e2594eb5af3aa2f3c4a0f245a0"},
            {"D9b", [](Rig& g) { d9(g, true); }, "01aa235f1a1e43e1f666656a0f6f2706199e8f10fc7dfa67603273f4de8d7b98"},
            {"D10a", [](Rig& g) { d10(g, Bk::Serve); }, "008086b7532c895817650d283ee0dcb8e5577090c3b73312cfffbd95547daf26"},
            {"D10b", [](Rig& g) { d10(g, Bk::Refused); }, "f0a38db6acfbaee764a88943389392c8724ffc81032a3ff92aa45837dc93d518"},
            {"D10c", [](Rig& g) { d10(g, Bk::NotServed); }, "88779aaa3d5732dbf3c9700b79d1a84a2ecf89b34a0b7ad7403cc176b7752f53"},
            {"D10d", [](Rig& g) { d10(g, Bk::Silent); }, "2ca47044d7ec387ff0ba5c8a72f5245e910b7db417678c48e2b72a9d8b611626"},
            {"D10e", [](Rig& g) { d10(g, Bk::AllClosed); }, "06f83bc354574d1ebc051899e89a6ee59649286b13cc85798c94a8e4766b1ef9"},
            {"D10f", [](Rig& g) { d10(g, Bk::LinkDrop); }, "37aaf7acf70a3a4614836e9689ced1ff2de3216bed73f0e10086c8bd85fc9d40"},
            {"D11", d11, "91d2c1ca8d78e223aafe14c4eafe771418219f6f76f54d468d4bcf1fb93b8659"},
            {"D12", d12, "93a1d63a5eafc6fc913b14fd71a7fa01ce59be7d459e379de785509933ba832b"},
            {"D13", d13, "296565d1bbc7ef4da187724eb5b6b3759fb8d833a4717c889216c00545adc240"},
            {"D14", d14, "7e4c66c8a2a3087bb8637eadff88e4d9ebec91ef9fdb7dcf7aa607b95040eff9"},
            {"D15", d15, "55e255269e810a5035a71dcce99a09f5d4715a297d0c8e15021c1c11498822e0"},
            {"D16", d16, "918247aed5ffe7e7b19cd32500004f911765affbb017f60886cd790a9c0ce7ed"},
            {"D17", d17, "d3c673ef96213a40aa2aec3116d5f4c5fcbeecaf82dbd6a087fdf2cef467d8a1"},
            {"D18", d18, "96d4e6e3b8b88398cadfdb11cdf05cff52b54d002df758a4682e86f5819be9cf"},
            {"J2", jd2, "de70ac5a408113e602b90a54600975733981063d44696869c1cc0e18342eb2ea"},
            {"J4", jd4, "286509d2715dc56888698763e93b5e117a9910536a242cd03d86c338cf8111a7"},
            {"J8", jd8, "090263759fd93f51dbd9121e1325b878d08ca37a181c13a80267233de2714153"},
            {"J10", jd10, "89d9df3c318a20dad72d76de25d7b85df3687ce6b398bd52ee8ee116fd9af53c"},
            {"J12", jd12, "ac06f1c812192c11c668666924b407988bba48c4f9b93f73b86126b5308d346a"},
            {"J16", jd16, "ca0b3bca86ad99b76181a17f99e81b3636fd4d2127bfd6fc2d0430aedd92f983"},
            {"D21E", d21e, "0d78e17293459500e011c9bc608d1114b9d4bae000017238c83c66e0c4248693"},
            {"D25", d25, "13c3f6af8be3761c10772f9f9073c2072c77d2a2064baf8621f162eb6ce7e0f9"},
            {"D21F", [](Rig& g) { d21fg(g, true); }, "808e1b61fae1e329b40f099ce4b4415acd8d40845961761ac1c0a1f3e634c6e2"},
            {"D21G", [](Rig& g) { d21fg(g, false); }, "9f1a035e052f2d2010320c40835d1580bd6c185656d54a6d51ae9b1341e43868"},
            {"D19", d19, "15df3830158c4e80fd18c07d0673092209edb230e7c9059469b4e452e02ae420"},
            {"D20", d20, "694ac58e001791a83d359de6b5b6570c5409da1d5433707378e3102a9579d536", join_net},
            {"D22", d22, "51c2dfc6290bea163603219c19d8b714cd6633e8dab2e8a08116bbde49f54979"},
            {"D23", d23, "1318e96f7ab4a961494aec582b09352b7679f3b9d3a32a2ec1ddd3ac4f8ccc3f", join_net},
            {"D23Y", d23y, "b6c148a6cf58c2fde8fe58cb1d8003b5de88ebbb2ffd50cd9948fb7d521be42b"},
            {"D24F", d24f, "fb700f3bfa7c886ea4f293d570a730d909e11348dcf35d2cb900a3272c0324a5"},
            {"D24V", d24v, "aef8ba5296246c3c181b348adbdb73c797bf0fba68c0fa292847cefff3d71262"},
            {"HADOPT", hadopt, "d5d91ffb56d0777829633e91634e1cafdf079df899de36c45165480d4354c31b"},
    };
    return c;
}

std::string digest_of(const std::vector<std::string>& lines) {
    std::string all;
    for (const std::string& l : lines) {
        all += l;
        all += '\n';
    }
    const auto d = ::v37::sha256(reinterpret_cast<const std::uint8_t*>(all.data()), all.size());
    return hex(d.data(), d.size());
}

std::vector<std::string> split_list(const std::string& s) {
    std::vector<std::string> out;
    std::size_t a = 0;
    for (std::size_t b = s.find(','); ; b = s.find(',', a)) {
        out.push_back(s.substr(a, b == std::string::npos ? std::string::npos : b - a));
        if (b == std::string::npos) break;
        a = b + 1;
    }
    return out;
}

// ===========================================================================
// Measurement modes: the thread CPU of the node under test (no golden). Nonces, tip bytes and tags below are test
// data (distinct values only); a repetition count or a batch size is a test parameter.
// ===========================================================================
double cpu_us() {
    timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return static_cast<double>(t.tv_sec) * 1e6 + static_cast<double>(t.tv_nsec) / 1e3;
}
// min / p50 / max of a sample.
struct Spread {
    double min = 0, p50 = 0, max = 0;
    std::size_t n = 0;
};
Spread spread(std::vector<double> v) {
    Spread s;
    if (v.empty()) return s;
    std::sort(v.begin(), v.end());
    s.min = v.front();
    s.p50 = v[v.size() / 2];
    s.max = v.back();
    s.n = v.size();
    return s;
}
std::string spread_str(const Spread& s) {
    char b[160];
    std::snprintf(b, sizeof b, "min %.2f p50 %.2f max %.2f (n %zu)", s.min, s.p50, s.max, s.n);
    return b;
}
constexpr std::size_t kWireBatch = 256;  // test parameter: frames handed to V between two wire drains
constexpr int kBenchReps = 5;           // test parameter: repetitions per figure (AJBREPS overrides)
int reps_env() {
    const char* rp = std::getenv("AJBREPS");
    return rp != nullptr && std::atoi(rp) > 0 ? std::atoi(rp) : kBenchReps;
}

// The sizes a node holds per object, printed: the decoded body and frame at the largest legal branch depth of the
// KAT's view (the receipt buffer P-10 less its margin; own + R_MAX carried), each a round trip of its encoding within
// the buffers; the key cache's and the window cache's charges; the parked frame and the pending receipt.
void sizes() {
    Rig g;
    const std::size_t a = g.relay(true);
    g.mine(a, 1, 39000);
    g.mine(a, 2, 39001);
    const std::optional<pb::PathbJob> j = g.h.job(a, 3, 39002);
    const pb::CarrierBodyV3* own = g.n(a).bodies().get(g.best(a));
    check(j.has_value() && own != nullptr, "sizes: a job and a carrier of A");
    if (!j || own == nullptr) return;
    const pb::RelayBuffers buf = g.n(a).config().buffers;
    const std::size_t depth = (buf.receipt - pb::kReceiptFixedMaxBytes) / pb::kHashBytes - pb::kBufferDepthMargin;
    pb::ReceiptBodyV3 r = j->body;
    r.branch.resize(depth, seq32(0x2d));
    const Frame rframe = Rig::receipt_frame(r);
    pb::ReceiptsFrame rf;
    const bool rok = pb::decode_fb_receipts(rframe, 0, buf, pb::kRuledLaneParams, rf).ok() && rf.bodies.size() == 1;
    pb::ReceiptBodyV3 rd;
    const bool rdec = rok && pb::decode_receipt_body_v3(rf.bodies[0].data(), rf.bodies[0].size(), pb::receipt_limits(buf),
                                                        rd) == pb::WireError::None;
    const std::size_t body_heap = sizeof(pb::ReceiptBodyV3) + rd.branch.capacity() * sizeof(Hash32);
    pb::CarrierBodyV3 c = *own;
    c.own.branch.resize(depth, seq32(0x2e));
    c.carried.assign(pb::kRuledLaneParams.r_max, r);
    const Frame cframe = pb::encode_fc_carrier(0, c, 16).value_or(Frame{});
    pb::CarrierBodyV3 cd;
    const bool cdec = cframe.size() > pb::kFrameHeaderBytes &&
                      pb::decode_carrier_body_v3(cframe.data() + pb::kFrameHeaderBytes, cframe.size() - pb::kFrameHeaderBytes,
                                                 pb::carrier_limits(buf, pb::kRuledLaneParams.r_max), cd) == pb::WireError::None;
    std::size_t frame_heap = sizeof(pb::CarrierBodyV3) + cd.own.branch.capacity() * sizeof(Hash32) +
                             cd.carried.capacity() * sizeof(pb::ReceiptBodyV3);
    for (const pb::ReceiptBodyV3& b : cd.carried) frame_heap += b.branch.capacity() * sizeof(Hash32);
    std::printf("SIZE body depth %zu: encoded %zu B (buffer %llu), decoded %zu B (sizeof ReceiptBodyV3 %zu)\n", depth,
                rf.bodies.empty() ? static_cast<std::size_t>(0) : rf.bodies[0].size(),
                static_cast<unsigned long long>(buf.receipt), body_heap, sizeof(pb::ReceiptBodyV3));
    std::printf("SIZE frame own + %llu carried at depth %zu: encoded %zu B (buffer %llu), decoded %zu B (sizeof "
                "CarrierBodyV3 %zu)\n",
                static_cast<unsigned long long>(pb::kRuledLaneParams.r_max), depth, cframe.size(),
                static_cast<unsigned long long>(buf.frame), frame_heap, sizeof(pb::CarrierBodyV3));
    std::printf("SIZE key cache entry: %zu B + %zu B per output key; window cache entry (no payee): %zu B; TipWindow %zu B\n",
                pb::KeyCache::entry_bytes(0), pb::KeyCache::entry_bytes(1) - pb::KeyCache::entry_bytes(0),
                pb::WindowCache::entry_bytes(pb::Window{}), sizeof(pb::TipWindow));
    std::printf("SIZE ParkedFrame %zu B; PendingReceipt %zu B\n", sizeof(pb::ParkedFrame), sizeof(pb::PendingReceipt));
    check(rdec && rd == r && rf.bodies[0].size() <= buf.receipt,
          "sizes: the largest legal body round-trips within the receipt buffer");
    check(cdec && cd == c && cframe.size() <= buf.frame, "sizes: the largest legal frame round-trips within the frame buffer");
}
const char* bench_kind_name(int kind) {
    return kind == 0 ? "receipt-TipUnknown" : kind == 1 ? "frame17-TipUnknown-body1" : "frame2-TipUnknown-body1";
}
// The parked objects of --bench / --benchnb: kind 0, receipts of A's job on tips nobody holds; kind 1 / 2, A's best
// carrier with 16 / 1 carried bodies of that job, each on a tip nobody holds (TipUnknown at the first carried body).
Frame bench_frame(int kind, std::size_t k, const pb::PathbJob& jb, const pb::CarrierBodyV3& own) {
    if (kind == 0) {
        pb::ReceiptBodyV3 r = jb.body;
        r.blob.nonce = 21000;
        r.side.tip.fill(0x77);
        std::memcpy(r.side.tip.data(), &k, sizeof k);
        return Rig::receipt_frame(r);
    }
    pb::CarrierBodyV3 c = own;
    c.carried.clear();
    for (std::uint32_t q = 0; q < (kind == 2 ? 1u : 16u); ++q) {
        pb::ReceiptBodyV3 r = jb.body;
        r.blob.nonce = 22000 + q;
        r.side.tip.fill(0x55);
        std::memcpy(r.side.tip.data(), &k, sizeof k);
        r.side.tip[31] = static_cast<std::uint8_t>(q);
        c.carried.push_back(r);
    }
    return pb::encode_fc_carrier(0, c, 16).value_or(Frame{});
}

// --bench: V's thread CPU for one placement that runs again n parked objects, minus the same with none parked.
struct BenchOut {
    double us = 0;
    std::uint64_t reruns = 0, parked = 0;
};
BenchOut bench_once(int kind, std::size_t n) {
    Rig g;
    const std::size_t a = g.relay(true), v = g.relay(false);
    g.w.on_send = nullptr;
    g.w.on_step = nullptr;
    const auto drain = [&] {
        for (KatRelay& k : g.r) k.relay->pump();
        while (g.w.step()) {
        }
    };
    const auto mine = [&](std::size_t i, std::size_t payee, std::uint32_t nonce) {
        if (const std::optional<pb::PathbJob> j = g.h.job(i, payee, nonce)) (void)g.h[i].on_own_share(*j, nonce, Hash32{});
        drain();
    };
    g.w.connect(a, v);
    drain();
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) {
            g.h.tick_monero(1);
            for (KatRelay& k : g.r) k.relay->on_monero_tip();
            drain();
        }
        mine(a, i % 4, 20000 + i);
    }
    g.w.edit = [a, v](FakeWire::Msg& m) {
        if (m.from == v && m.to == a) m.f.clear();
    };
    const std::optional<pb::PathbJob> jb = g.h.job(a, 3, 21000);
    const pb::CarrierBodyV3* own = g.n(a).bodies().get(g.best(a));
    for (std::size_t k = 0; k < n && jb && own; ++k) {
        g.r[v].relay->receive(g.w.id(v, a), bench_frame(kind, k, *jb, *own));
        if (k % kWireBatch == kWireBatch - 1) drain();
    }
    drain();
    BenchOut o;
    o.parked = kind == 0 ? g.rel(v).parked_receipts() : g.n(v).deferred().digests().size();
    const std::uint64_t r0 = g.rel(v).stats().parked_reruns.load();
    const double t0 = cpu_us();
    mine(a, 1, 23000);
    for (int i = 0; i < 4; ++i) drain();
    o.us = cpu_us() - t0;
    o.reruns = g.rel(v).stats().parked_reruns.load() - r0;
    return o;
}
int bench(std::size_t n, int reps) {
    const char* kinds = std::getenv("AJBBENCHKINDS");
    for (int kind = 0; kind < 3; ++kind) {
        if (kinds != nullptr && std::strchr(kinds, '0' + kind) == nullptr) continue;
        std::vector<double> per;
        BenchOut last{};
        for (int i = 0; i < reps; ++i) {
            const BenchOut z = bench_once(kind, 0);
            const BenchOut b = bench_once(kind, n);
            last = b;
            if (b.reruns > 0) per.push_back((b.us - z.us) / static_cast<double>(b.reruns));
        }
        const Spread s = spread(per);
        std::printf("BENCH kind=%s n=%zu parked=%llu reruns=%llu per_rerun_us min %.2f p50 %.2f max %.2f (reps %d)\n",
                    bench_kind_name(kind), n, static_cast<unsigned long long>(last.parked),
                    static_cast<unsigned long long>(last.reruns), s.min, s.p50, s.max, reps);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// N(B) chain scale: both relays' nodes loaded from a store of the N(B) shape (test parameters: 2,375 positions,
// 3,800 receipts, one carrier's own receipt per position and the carried receipts spread evenly, each on the parent,
// every receipt its own payee; the rows at difficulty 1e12, reseeded 1,000 below the anchor). The store is built once
// per process and copied for every node; each node is made by pathb_load, as D17 restarts a node.
constexpr std::uint64_t kNbPositions = 2375, kNbReceipts = 3800, kNbDiff = 1000000000000ull, kNbRowsBelow = 1000;
const KatNet& nb_net() {
    static const KatNet net = [] {
        KatNet n(kNbDiff);
        KatMoneroRows m;
        const pb::RowWeights w = rw(kTailAgc, 300000, 300000);
        const std::uint64_t a = kAnchorH - kNbRowsBelow;
        pb::Hash32 parent = m.seed_anchor(kMonTag, a, 100, kTs0, kNbDiff, w);
        for (std::uint64_t h = a + 1; h <= kMonTop; ++h) parent = m.add(kMonTag, h, parent, mon_ts(h), kNbDiff, w);
        n.rows = std::move(m);
        // test parameter: one identity per receipt and per position, and 64 more for the bench's own jobs
        const std::uint64_t need = kNbReceipts + kNbPositions + 64;
        for (std::uint64_t k = n.refs.size(); k < need; ++k) {
            n.refs.push_back(ref_from_secrets(20000 + 2 * k, 20001 + 2 * k));
            n.ids.push_back(n.book.add(n.refs.back()));
        }
        return n;
    }();
    return net;
}
std::unique_ptr<KatStoreNode> g_nb_sn;
pb::TipWindow nb_best_window() { return g_nb_sn->n.window(g_nb_sn->n.tree.best().id, 16); }
const MemoryKv& nb_kv() {
    std::unique_ptr<KatStoreNode>& sn = g_nb_sn;
    if (sn) return sn->kv;
    const double c0 = cpu_us();
    sn = std::make_unique<KatStoreNode>(nb_net(), kHarnessJ);
    KatNode& n = sn->n;
    const KatNet& net = nb_net();
    std::size_t payee = 0;
    const std::uint64_t carried_total = kNbReceipts - kNbPositions;
    std::uint64_t owed = 0;
    for (std::uint64_t x = 1; x <= kNbPositions; ++x) {
        const pb::CarrierNode& best = n.tree.best();
        owed += (x * carried_total) / kNbPositions - ((x - 1) * carried_total) / kNbPositions;
        std::vector<pb::ReceiptBodyV3> carried;
        while (owed > 0 && carried.size() < pb::kRuledLaneParams.r_max && x >= 2) {
            carried.push_back(scaffold_receipt(n, best.id, h_pos(x), payee++, (x << 8) ^ carried.size() ^ 0xF4000000ull));
            --owed;
        }
        canonical_sort(net, carried, best.id);
        const pb::CarrierBodyV3 c = scaffold_carrier(n, best.id, h_pos(x), 0xF4, x, payee++, carried);
        if (sn->place(c).outcome != pb::WriteOutcome::Extended || sn->poisoned) {
            std::fprintf(stderr, "benchnb: scaffold carrier not placed at %llu\n", static_cast<unsigned long long>(x));
            std::exit(3);
        }
    }
    const pb::TipWindow tw = n.window(n.tree.best().id, 16);
    std::printf("NB SHAPE positions %llu receipts %llu | best pos %llu h %llu | window %s payees %zu | kv keys %zu |"
                " build cpu %.1f ms\n",
                static_cast<unsigned long long>(kNbPositions), static_cast<unsigned long long>(kNbReceipts),
                static_cast<unsigned long long>(n.tree.best().pos), static_cast<unsigned long long>(h_pos(kNbPositions)),
                tw.ok() ? "ok" : "DEFER", tw.ok() ? tw.window->weight.size() : static_cast<std::size_t>(0),
                sn->kv.data.size(), (cpu_us() - c0) / 1e3);
    std::fflush(stdout);
    return sn->kv;
}
// Two relays A (mining) and V on a Rig of the N(B) net, their nodes loaded from copies of the N(B) store; V follows four
// shares of A; V's replies to A cut. `trace`: the tracer kept on. False: the setup failed (printed).
struct NbPair {
    std::size_t a = 0, v = 0;
    double load_us = 0;
    std::function<void()> drain;
    std::function<void(std::size_t, std::size_t, std::uint32_t)> mine;
};
NbPair nb_pair(Rig& g, bool trace) {
    NbPair p;
    g.h.mon_tip = h_pos(kNbPositions) + 1;
    const MemoryKv& base = nb_kv();
    const double l0 = cpu_us();
    const auto mk = [&](const pb::PathbNodeConfig& cfg, pb::PathbNodeIo io) {
        g.h.kvs.push_back(std::make_unique<MemoryKv>());
        g.h.kvs.back()->data = base.data;
        MemoryKv* kv = g.h.kvs.back().get();
        pb::LoadInputs in;
        in.T = cfg.T;
        in.journal_depth = cfg.journal_depth;
        pb::LoadResult lr = pb::pathb_load(*kv, g.net.pool_id, g.net.rules_g, in);
        if (!lr.state) {
            std::fprintf(stderr, "benchnb: pathb_load failed\n");
            std::exit(4);
        }
        return std::make_unique<pb::PathbNode>(cfg, std::move(io), std::move(*lr.state), kv);
    };
    g.r.push_back(kat_relay(g.h, g.w, kat_table(g.net), true, false, nullptr, nullptr, nullptr, false, mk));
    p.a = g.r.back().node;
    g.r.push_back(kat_relay(g.h, g.w, kat_table(g.net), false, false, nullptr, nullptr, nullptr, false, mk));
    p.v = g.r.back().node;
    p.load_us = cpu_us() - l0;
    if (trace) {
        for (KatRelay& k : g.r) g.t.add(k.node, k.relay.get(), k.links.get());
    } else {
        g.w.on_send = nullptr;
        g.w.on_step = nullptr;
    }
    p.drain = [&g, trace] {
        for (KatRelay& k : g.r) k.relay->pump();
        if (trace) g.t.poll();
        while (g.w.step()) {
        }
        if (trace) g.t.poll();
    };
    p.mine = [&g, d = p.drain](std::size_t i, std::size_t payee, std::uint32_t nonce) {
        if (const std::optional<pb::PathbJob> j = g.h.job(i, payee, nonce)) (void)g.h[i].on_own_share(*j, nonce, Hash32{});
        d();
    };
    const std::size_t a = p.a, v = p.v;
    g.w.connect(a, v);
    p.drain();
    const Hash32 b0 = g.best(v);
    for (std::uint32_t i = 0; i < 4; ++i) {
        if (i % 2 == 0) {
            g.h.tick_monero(1);
            for (KatRelay& k : g.r) k.relay->on_monero_tip();
            p.drain();
        }
        p.mine(a, i % 4, 20000 + i);
    }
    if (g.best(v) == b0 || !(g.best(v) == g.best(a))) {
        std::fprintf(stderr, "benchnb: V did not follow A's shares (V moved %d, equal %d)\n", !(g.best(v) == b0),
                     g.best(v) == g.best(a));
        std::exit(5);
    }
    g.w.edit = [a, v](FakeWire::Msg& m) {
        if (m.from == v && m.to == a) m.f.clear();
    };
    return p;
}
// V judges one fresh receipt of A's job on A's best tip (its window and key set held from then on).
void nb_warm(Rig& g, const NbPair& p, std::size_t payee, std::uint32_t nonce) {
    if (const std::optional<pb::PathbJob> jw = g.h.job(p.a, payee, nonce)) {
        pb::ReceiptBodyV3 rw = jw->body;
        rw.blob.nonce = nonce;
        const std::size_t p0 = g.n(p.v).pending().size();
        g.r[p.v].relay->receive(g.w.id(p.v, p.a), Rig::receipt_frame(rw));
        p.drain();
        if (g.n(p.v).pending().size() != p0 + 1) {
            std::fprintf(stderr, "benchnb: the warming receipt was not taken (pending %zu -> %zu)\n", p0,
                         g.n(p.v).pending().size());
            std::exit(7);
        }
    }
}
bool g_nb_trace = false;
std::string g_nb_last_digest;
BenchOut bench_once_nb(int kind, std::size_t n, double* load_us = nullptr) {
    Rig g(nb_net());
    const NbPair p = nb_pair(g, g_nb_trace);
    if (load_us) *load_us = p.load_us;
    const std::size_t a = p.a, v = p.v;
    const char* warm = std::getenv("AJBNBWARM");
    if (warm == nullptr || std::strcmp(warm, "0") != 0) nb_warm(g, p, 2, 24000);
    const std::optional<pb::PathbJob> jb = g.h.job(a, 3, 21000);
    const pb::CarrierBodyV3* own = g.n(a).bodies().get(g.best(a));
    for (std::size_t k = 0; k < n && jb && own; ++k) {
        g.r[v].relay->receive(g.w.id(v, a), bench_frame(kind, k, *jb, *own));
        if (k % kWireBatch == kWireBatch - 1) p.drain();
    }
    p.drain();
    BenchOut o;
    o.parked = kind == 0 ? g.rel(v).parked_receipts() : g.n(v).deferred().digests().size();
    const std::uint64_t r0 = g.rel(v).stats().parked_reruns.load();
    const Hash32 before = g.best(v);
    const double t0 = cpu_us();
    p.mine(a, 1, 23000);
    for (int i = 0; i < 4; ++i) p.drain();
    o.us = cpu_us() - t0;
    o.reruns = g.rel(v).stats().parked_reruns.load() - r0;
    if (g.best(v) == before) {
        std::fprintf(stderr, "benchnb: the timed placement did not reach V\n");
        std::exit(6);
    }
    if (g_nb_trace) g_nb_last_digest = digest_of(g.t.out) + " lines " + std::to_string(g.t.out.size());
    return o;
}
int bench_nb_trace(std::size_t n) {
    g_nb_trace = true;
    (void)nb_kv();
    for (int kind = 0; kind < 3; ++kind) {
        for (const std::size_t k : {std::size_t{0}, n}) {
            const BenchOut b = bench_once_nb(kind, k);
            std::printf("NBTRACE kind=%d n=%zu parked=%llu reruns=%llu trace %s\n", kind, k,
                        static_cast<unsigned long long>(b.parked), static_cast<unsigned long long>(b.reruns),
                        g_nb_last_digest.c_str());
            std::fflush(stdout);
        }
    }
    return 0;
}
constexpr int kProbeCalls = 200;  // test parameter: timed calls of each probe part
void nb_probe_parts() {
    (void)nb_kv();
    std::vector<double> copy_us, dig_us;
    const pb::TipWindow tw = nb_best_window();
    if (!tw.ok()) {
        std::printf("NBPROBE window DEFER\n");
        return;
    }
    const pb::Window& w = *tw.window;
    unsigned sink = 0;
    for (int i = 0; i < kProbeCalls; ++i) {
        const double c0 = cpu_us();
        std::vector<Hash32> ids;
        for (const auto& kv : w.weight) ids.push_back(kv.first);
        const double c1 = cpu_us();
        const Hash32 d = pb::KeyCache::payee_digest(ids);
        const double c2 = cpu_us();
        sink ^= d[0];
        copy_us.push_back(c1 - c0);
        dig_us.push_back(c2 - c1);
    }
    std::printf("NBPROBE payees %zu | ids copy us %s | payee_digest us %s sink %u\n", w.weight.size(),
                spread_str(spread(copy_us)).c_str(), spread_str(spread(dig_us)).c_str(), sink & 1u);
    std::fflush(stdout);
}
int bench_nb(std::size_t n, int reps) {
    (void)nb_kv();
    if (std::getenv("AJBNBPROBE") != nullptr) nb_probe_parts();
    const char* kinds = std::getenv("AJBBENCHKINDS");
    for (int kind = 0; kind < 3; ++kind) {
        if (kinds != nullptr && std::strchr(kinds, '0' + kind) == nullptr) continue;
        std::vector<double> per, zs, loads;
        BenchOut last{};
        for (int i = 0; i < reps; ++i) {
            double lz = 0, lb = 0;
            const BenchOut z = bench_once_nb(kind, 0, &lz);
            const BenchOut b = bench_once_nb(kind, n, &lb);
            last = b;
            zs.push_back(z.us);
            loads.push_back(lz);
            loads.push_back(lb);
            if (b.reruns > 0) per.push_back((b.us - z.us) / static_cast<double>(b.reruns));
        }
        const Spread s = spread(per), sz = spread(zs), sl = spread(loads);
        std::printf("BENCHNB kind=%s n=%zu parked=%llu reruns=%llu per_rerun_us min %.2f p50 %.2f max %.2f (reps %d)"
                    " | the placement alone (z) us min %.0f p50 %.0f max %.0f | two node loads us p50 %.0f\n",
                    bench_kind_name(kind), n, static_cast<unsigned long long>(last.parked),
                    static_cast<unsigned long long>(last.reruns), s.min, s.p50, s.max, reps, sz.min, sz.p50, sz.max,
                    sl.p50);
        std::fflush(stdout);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// --benchfirst=n (N(B)): the first judgments of honest objects on a held window and key set.
// - receipts: A mines a carrier c (V places it: a fresh window entry at c); then n fresh receipts of A's jobs on c,
//   each judged once by V; the first, the second and the third-and-later judgments are timed apart;
// - own + 1 / own + 16: A takes 1 / 16 jobs on its best t0 and mines c0 (V places it); V judges one fresh receipt on
//   t0 and one on c0 (the windows and key sets c's rows read are held); A shares the jobs (receipts on t0) and mines c
//   on c0 carrying them, neither reaching V on the wire; then c reaches V: its judgment and placement timed.
// AJBREPS rounds (default 5); each round its own Rig.
int bench_first(std::size_t n, int reps) {
    (void)nb_kv();
    std::vector<double> r1, r2, r3, c1, c16;
    std::size_t taken = 0, placed = 0, shaped = 0;
    for (int rep = 0; rep < reps; ++rep) {
        {
            Rig g(nb_net());
            const NbPair p = nb_pair(g, false);
            p.mine(p.a, 1, 30000 + static_cast<std::uint32_t>(rep));
            for (std::size_t k = 0; k < n; ++k) {
                const std::optional<pb::PathbJob> j = g.h.job(p.a, 5 + k, 31000 + static_cast<std::uint32_t>(k));
                if (!j) break;
                pb::ReceiptBodyV3 r = j->body;
                r.blob.nonce = 31000 + static_cast<std::uint32_t>(k);
                const Frame f = Rig::receipt_frame(r);
                const std::size_t p0 = g.n(p.v).pending().size();
                const double t0 = cpu_us();
                g.r[p.v].relay->receive(g.w.id(p.v, p.a), f);
                p.drain();
                const double us = cpu_us() - t0;
                taken += g.n(p.v).pending().size() == p0 + 1 ? 1 : 0;
                (k == 0 ? r1 : k == 1 ? r2 : r3).push_back(us);
            }
        }
        for (const std::size_t carried : {std::size_t{1}, std::size_t{16}}) {
            Rig g(nb_net());
            const NbPair p = nb_pair(g, false);
            const std::size_t a = p.a, v = p.v;
            std::vector<std::optional<pb::PathbJob>> jobs;
            for (std::size_t k = 0; k < carried; ++k) jobs.push_back(g.h.job(a, 5 + k, 32000 + static_cast<std::uint32_t>(k)));
            const std::optional<pb::PathbJob> w0 = g.h.job(a, 2, 32100);
            p.mine(a, 1, 32200 + static_cast<std::uint32_t>(rep));
            nb_warm(g, p, 3, 32101);
            if (w0) {
                pb::ReceiptBodyV3 rw = w0->body;
                rw.blob.nonce = 32100;
                g.r[v].relay->receive(g.w.id(v, a), Rig::receipt_frame(rw));
                p.drain();
            }
            // A's receipts and its next carrier do not reach V on the wire
            g.w.edit = [a, v](FakeWire::Msg& m) {
                if ((m.from == v && m.to == a) || (m.from == a && m.to == v)) m.f.clear();
            };
            for (std::size_t k = 0; k < carried; ++k)
                if (jobs[k]) (void)g.h[a].on_own_share(*jobs[k], 32000 + static_cast<std::uint32_t>(k), Hash32{});
            p.drain();
            p.mine(a, 1, 33000 + static_cast<std::uint32_t>(rep));
            const Hash32 c = g.best(a);
            const pb::CarrierBodyV3* body = g.n(a).bodies().get(c);
            const std::size_t got = body != nullptr ? body->carried.size() : 0;
            g.w.edit = [a, v](FakeWire::Msg& m) {
                if (m.from == v && m.to == a) m.f.clear();
            };
            const double t0 = cpu_us();
            g.r[v].relay->receive(g.w.id(v, a), g.carrier_frame(a, c));
            p.drain();
            const double us = cpu_us() - t0;
            placed += g.has(v, c) ? 1 : 0;
            if (got == carried && g.has(v, c)) {
                ++shaped;
                (carried == 1 ? c1 : c16).push_back(us);
            }
        }
    }
    std::printf("BENCHFIRST receipts n=%zu taken=%zu | first us %s | second us %s | third+ us %s\n", n, taken,
                spread_str(spread(r1)).c_str(), spread_str(spread(r2)).c_str(), spread_str(spread(r3)).c_str());
    std::printf("BENCHFIRST carriers placed=%zu shaped=%zu | own+1 us %s | own+16 us %s (reps %d)\n", placed, shaped,
                spread_str(spread(c1)).c_str(), spread_str(spread(c16)).c_str(), reps);
    std::fflush(stdout);
    return 0;
}

// --benchrepeat=n (N(B)): the same body judged n times by V's node (its admission only, under the node lock), each
// shape on its own Rig: a Mismatch body (a fresh receipt of A's job on A's best with its extra nonce changed: the
// canonical coinbase differs), and a MissingRef body (a fresh receipt on A's best, no object on that tip judged at V
// before, whose window pays a payee whose reference V no longer holds: its key set is never kept).
int bench_repeat(std::size_t n) {
    (void)nb_kv();
    const auto judge = [n](Rig& g, const NbPair& p, const pb::ReceiptBodyV3& r, const char* what) {
        const Frame f = Rig::receipt_frame(r);
        std::vector<double> us;
        std::string word;
        for (std::size_t k = 0; k < n; ++k) {
            std::vector<pb::NodeEventResult> rs;
            const double t0 = cpu_us();
            g.rel(p.v).with_node([&](pb::PathbNode& nd) { rs = nd.on_receipts(p.a + 1, f); });
            us.push_back(cpu_us() - t0);
            if (k == 0 && !rs.empty())
                word = std::string("R") + std::to_string(static_cast<int>(rs[0].admit.row)) + "/" +
                       verdict_name(static_cast<std::size_t>(rs[0].admit.verdict)) +
                       (rs[0].admit.missing ? std::string(" ") + cause_name(*rs[0].admit.missing) : std::string());
        }
        std::printf("BENCHREPEAT %s word %s | us %s\n", what, word.c_str(), spread_str(spread(us)).c_str());
    };
    {
        Rig g(nb_net());
        const NbPair p = nb_pair(g, false);
        nb_warm(g, p, 2, 24000);
        if (const std::optional<pb::PathbJob> j = g.h.job(p.a, 3, 34000)) {
            pb::ReceiptBodyV3 mm = j->body;
            mm.blob.nonce = 34000;
            mm.extra_nonce[0] ^= 0x01;
            judge(g, p, mm, "mismatch");
        }
    }
    {
        Rig g(nb_net());
        const NbPair p = nb_pair(g, false);
        // a payee of the store's best window, which A's best window still pays
        const pb::TipWindow tw = nb_best_window();
        const std::optional<pb::PathbJob> j = g.h.job(p.a, 3, 34001);
        if (tw.ok() && !tw.window->weight.empty() && j) {
            const Hash32 lost = tw.window->weight.rbegin()->first;
            g.rel(p.v).with_node([&](pb::PathbNode& nd) { pb::PathbNodeTestAccess::forget_ref(nd, lost); });
            pb::ReceiptBodyV3 mr = j->body;
            mr.blob.nonce = 34001;
            judge(g, p, mr, "missingref");
        } else {
            std::printf("BENCHREPEAT missingref: no window or job\n");
        }
    }
    std::fflush(stdout);
    return 0;
}

// --benchdrain=n (test chain scale): A's n carriers c1..cn whose first parent c0 V lacks reach V first (each DEFERred
// on its parent; V's asks for c0 unanswered); then c0: its placement releases c1, whose placement releases c2, and so
// on, all through the drain. The delivery of c0 timed, minus the delivery of a lone carrier, per released carrier.
int bench_drain(std::size_t n, int reps) {
    std::vector<double> per;
    std::size_t last_placed = 0;
    for (int rep = 0; rep < reps; ++rep) {
        double z = 0, b = 0;
        for (const std::size_t count : {std::size_t{0}, n}) {
            Rig g;
            const std::size_t a = g.relay(true), v = g.relay(false);
            g.w.on_send = nullptr;
            g.w.on_step = nullptr;
            g.connect(a, v);
            for (std::uint32_t i = 0; i < 4; ++i) g.mine(a, i % 4, 35000 + i);
            Filter f;
            f.drop = [a, v](const FakeWire::Msg& m) { return (m.from == a && m.to == v) || (m.from == v && m.to == a); };
            f.install(g.w);
            std::vector<Hash32> c;
            for (std::size_t i = 0; i <= count; ++i) {
                if (i % 3 == 0) g.act("monero +1", [&] { g.h.tick_monero(1); });
                g.act("mine 0", [&] {
                    if (const std::optional<pb::PathbJob> j = g.h.job(a, i % 4, 36000 + static_cast<std::uint32_t>(i)))
                        (void)g.n(a).on_own_share(*j, 36000 + static_cast<std::uint32_t>(i), Hash32{});
                });
                c.push_back(g.best(a));
            }
            for (std::size_t i = 1; i < c.size(); ++i) g.rel(v).receive(g.w.id(v, a), g.carrier_frame(a, c[i]));
            g.run();
            const double t0 = cpu_us();
            g.rel(v).receive(g.w.id(v, a), g.carrier_frame(a, c[0]));
            g.run();
            const double us = cpu_us() - t0;
            std::size_t placed = 0;
            for (const Hash32& id : c) placed += g.has(v, id) ? 1 : 0;
            (count == 0 ? z : b) = us;
            if (count == n) last_placed = placed;
            g.w.edit = nullptr;
        }
        if (n > 0) per.push_back((b - z) / static_cast<double>(n));
    }
    std::printf("BENCHDRAIN n=%zu placed=%zu (of %zu) per_released_us %s\n", n, last_placed, n + 1,
                spread_str(spread(per)).c_str());
    std::fflush(stdout);
    return 0;
}

// --bencht27=n (test chain scale): V holds n parked own + 16 frames whose own P_r V does not hold (each its own
// unknown Monero block); A's next carrier moves V's best record; V's next maintenance tick sweeps the parked frames
// (none seals). That tick is timed, minus V's tick just before the move (no move: no sweep), per parked frame.
// AJBT27BODY=max: every carried body at the largest legal branch depth of V's view (the receipt buffer P-10 less its
// margin).
int bench_t27(std::size_t n, int reps) {
    const bool maxbody = std::getenv("AJBT27BODY") != nullptr && std::strcmp(std::getenv("AJBT27BODY"), "max") == 0;
    std::vector<double> per, ticks;
    std::size_t parked = 0, bytes = 0;
    for (int rep = 0; rep < reps; ++rep) {
        Rig g;
        const std::size_t a = g.relay(true), v = g.relay(false);
        g.w.on_send = nullptr;
        g.w.on_step = nullptr;
        g.connect(a, v);
        for (std::uint32_t i = 0; i < 4; ++i) {
            if (i % 2 == 0) g.monero();
            g.mine(a, i % 4, 37000 + i);
        }
        g.w.edit = [a, v](FakeWire::Msg& m) {
            if (m.from == v && m.to == a) m.f.clear();
        };
        g.tick(1, v);  // V's sweeps meet its current best record
        const std::optional<pb::PathbJob> jb = g.h.job(a, 3, 38000);
        const pb::CarrierBodyV3* own = g.n(a).bodies().get(g.best(a));
        if (!jb || !own) return 2;
        const pb::RelayBuffers buf = g.n(v).config().buffers;
        const std::size_t depth = maxbody ? (buf.receipt - pb::kReceiptFixedMaxBytes) / pb::kHashBytes - pb::kBufferDepthMargin : 0;
        for (std::size_t k = 0; k < n; ++k) {
            pb::CarrierBodyV3 c = *own;
            c.own.blob.prev_id.fill(0x3c);
            std::memcpy(c.own.blob.prev_id.data(), &k, sizeof k);
            c.carried.clear();
            for (std::uint32_t q = 0; q < 16; ++q) {
                pb::ReceiptBodyV3 r = jb->body;
                r.blob.nonce = 38100 + q;
                if (depth > r.branch.size()) r.branch.resize(depth, seq32(0x2d));
                c.carried.push_back(r);
            }
            const Frame fr = pb::encode_fc_carrier(0, c, 16).value_or(Frame{});
            bytes = fr.size();
            g.rel(v).receive(g.w.id(v, a), fr);
            if (k % kWireBatch == kWireBatch - 1) g.run();
        }
        g.run();
        parked = g.n(v).deferred().digests().size();
        g.tick(1, v);  // the first tick with the frames parked (their periodic asks)
        g.h.now += 1;
        double t0 = cpu_us();
        g.rel(v).tick();
        const double still = cpu_us() - t0;
        g.run();
        g.monero();
        g.mine(a, 1, 38900);
        g.h.now += 1;
        t0 = cpu_us();
        g.rel(v).tick();
        const double moved = cpu_us() - t0;
        g.run();
        ticks.push_back(moved);
        if (n > 0) per.push_back((moved - still) / static_cast<double>(n));
        g.w.edit = nullptr;
    }
    std::printf("BENCHT27 n=%zu parked=%zu frame_bytes=%zu body=%s | tick with the move us %s | per parked frame us %s\n",
                n, parked, bytes, maxbody ? "max" : "kat", spread_str(spread(ticks)).c_str(),
                spread_str(spread(per)).c_str());
    std::fflush(stdout);
    return 0;
}

// --outsweep=CASE:STEP:LENS (LENS comma-separated): CASE run once with no outage, then once per (s, len) with every
// non-mining node's RandomX worker failing at steps [s, s + len), s = 0, STEP, 2 STEP, ... up to the outage-free run's
// last step. Per run: "O CASE s len" and, per node, the first step each id is placed (P) or pending (R), and every strike
// (X) and link drop (D) line.
int outsweep(const std::string& spec) {
    const auto p1 = spec.find(':'), p2 = spec.find(':', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) return 2;
    const std::string name = spec.substr(0, p1);
    const std::uint64_t step = std::strtoull(spec.substr(p1 + 1, p2 - p1 - 1).c_str(), nullptr, 10);
    std::vector<std::uint64_t> lens;
    for (const std::string& x : split_list(spec.substr(p2 + 1))) lens.push_back(std::strtoull(x.c_str(), nullptr, 10));
    const Case* cs = nullptr;
    for (const Case& c : cases())
        if (name == c.name) cs = &c;
    if (cs == nullptr || step == 0) return 2;
    const auto run1 = [&](std::uint64_t s, std::uint64_t len) {
        g_out_s = s;
        g_out_len = len;
        std::vector<std::string> lines;
        std::uint64_t last = 0;
        {
            const std::unique_ptr<Rig> g = rig_for(*cs);
            cs->run(*g);
            g->t.finish();
            lines = g->t.out;
            last = g->t.steps;
        }
        std::printf("O %s %llu %llu steps %llu\n", name.c_str(), static_cast<unsigned long long>(s),
                    static_cast<unsigned long long>(len), static_cast<unsigned long long>(last));
        std::set<std::string> seen;
        std::string tnow = "0";
        for (const std::string& l : lines) {
            const auto sp = l.find(' ');
            if (sp == std::string::npos || l.size() < sp + 3) continue;
            if (const auto tp = l.find(" t="); l[sp + 1] == '@' && tp != std::string::npos) tnow = l.substr(tp + 3);
            const char k = l[sp + 1];
            if (l[sp + 2] != ' ') continue;
            if (k == 'P' || k == 'R') {
                const auto q = l.find(' ', l.find(' ', sp + 3) + 1);
                const std::string key = std::string(1, k) + l.substr(sp + 3, q - sp - 3);
                if (seen.insert(key).second)
                    std::printf("  %c %s @%s t=%s\n", k, l.substr(sp + 3, q - sp - 3).c_str(), l.substr(0, sp).c_str(),
                                tnow.c_str());
            } else if (k == 'X' || (k == 'L' && l.find(" down") != std::string::npos)) {
                std::printf("  %c %s @%s\n", k == 'X' ? 'X' : 'D', l.substr(sp + 3).c_str(), l.substr(0, sp).c_str());
            }
        }
        return last;
    };
    const std::uint64_t last = run1(0, 0);
    for (const std::uint64_t len : lens)
        for (std::uint64_t s = 0; s <= last; s += step) (void)run1(s, len);
    g_out_s = g_out_len = 0;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_recovery_trace_kat\n");
    std::set<std::string> only;
    std::string print, traces;
    bool digests = false, only_given = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--list") {
            for (const Case& c : cases()) std::printf("%s\n", c.name);
            return 0;
        }
        if (a.rfind("--only=", 0) == 0) {
            only_given = true;
            for (const std::string& s : split_list(a.substr(7)))
                if (!s.empty()) only.insert(s);
        } else if (a.rfind("--print=", 0) == 0)
            print = a.substr(8);
        else if (a.rfind("--traces=", 0) == 0)
            traces = a.substr(9);
        else if (a == "--digests")
            digests = true;
        else if (a.rfind("--outsweep=", 0) == 0)
            return outsweep(a.substr(11));
        else if (a.rfind("--bench=", 0) == 0)
            return bench(static_cast<std::size_t>(std::strtoull(a.c_str() + 8, nullptr, 10)), reps_env());
        else if (a.rfind("--benchnbtrace=", 0) == 0)
            return bench_nb_trace(static_cast<std::size_t>(std::strtoull(a.c_str() + 15, nullptr, 10)));
        else if (a.rfind("--benchnb=", 0) == 0)
            return bench_nb(static_cast<std::size_t>(std::strtoull(a.c_str() + 10, nullptr, 10)), reps_env());
        else if (a.rfind("--benchfirst=", 0) == 0)
            return bench_first(static_cast<std::size_t>(std::strtoull(a.c_str() + 13, nullptr, 10)), reps_env());
        else if (a.rfind("--benchrepeat=", 0) == 0)
            return bench_repeat(static_cast<std::size_t>(std::strtoull(a.c_str() + 14, nullptr, 10)));
        else if (a.rfind("--benchdrain=", 0) == 0)
            return bench_drain(static_cast<std::size_t>(std::strtoull(a.c_str() + 13, nullptr, 10)), reps_env());
        else if (a.rfind("--bencht27=", 0) == 0)
            return bench_t27(static_cast<std::size_t>(std::strtoull(a.c_str() + 11, nullptr, 10)), reps_env());
        else {
            check(false, "unknown argument: " + a);
            return finish("v37_xmr_pathb_recovery_trace_kat");
        }
    }
    // a selection must name cases that exist and select at least one
    std::set<std::string> names;
    for (const Case& c : cases()) names.insert(c.name);
    for (const std::string& o : only) check(names.count(o) != 0, "--only: a case named " + o);
    if (only_given && only.empty()) {
        check(false, "--only: at least one case named");
        return finish("v37_xmr_pathb_recovery_trace_kat");
    }
    if (!print.empty()) check(names.count(print) != 0, "--print: a case named " + print);
    // AJBMEMO / AJBOUT change the traces: honoured only in a trace run (--print / --traces), whose digests are then
    // printed and not compared; refused in a golden run
    const bool trace_env = g_memo_mode || std::getenv("AJBOUT") != nullptr;
    const bool trace_run = !print.empty() || !traces.empty();
    if (trace_env && !trace_run) {
        check(false, "AJBMEMO / AJBOUT set: refused in a golden run (unset them, or use --print / --traces)");
        return finish("v37_xmr_pathb_recovery_trace_kat");
    }
    if (const char* ao = std::getenv("AJBOUT")) {  // one outage "s,len" for a --print / --traces run
        const std::vector<std::string> v = split_list(ao);
        if (v.size() == 2) {
            g_out_s = std::strtoull(v[0].c_str(), nullptr, 10);
            g_out_len = std::strtoull(v[1].c_str(), nullptr, 10);
        }
    }
    if (only.empty() && print.empty()) sizes();
    std::ofstream tf;
    if (!traces.empty()) tf.open(traces);
    std::size_t ran = 0;
    for (const Case& c : cases()) {
        if (!only.empty() && only.count(c.name) == 0) continue;
        if (!print.empty() && print != c.name) continue;
        ++ran;
        std::vector<std::string> lines;
        {
            const std::unique_ptr<Rig> g = rig_for(c);
            c.run(*g);
            g->t.finish();
            lines = g->t.out;
        }
        const std::string d = digest_of(lines);
        if (!print.empty())
            for (const std::string& l : lines) std::printf("%s\n", l.c_str());
        if (tf.is_open()) {
            tf << "# " << c.name << " " << d << "\n";
            for (const std::string& l : lines) tf << l << "\n";
        }
        if (digests) std::printf("  {\"%s\", \"%s\"},  // %zu lines\n", c.name, d.c_str(), lines.size());
        if (trace_env)
            std::printf("  %s: trace digest %s (%zu lines) not compared (AJBMEMO / AJBOUT set)\n", c.name, d.c_str(),
                        lines.size());
        else
            check(d == c.golden, std::string(c.name) + ": the trace's digest " + d + " (" + std::to_string(lines.size()) +
                                         " lines) equals its golden");
    }
    check(ran > 0, "at least one case ran");
    return finish("v37_xmr_pathb_recovery_trace_kat");
}
