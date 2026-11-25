// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_ref_identity_kat.cpp
// The payee and owner key references learned from bodies are held under their
// own identity (key_ref_identity): the node's map (PathbNode), a join
// attempt's map (JoinedState) and the map of a load (LoadedState::refs).
// INV, in every case: every key of the map is its reference's identity (a
// reference K is absent or held under K's own identity).
//   P    three relay nodes A, L, X; X follows A without A's side carriers sa1,
//        sa2; A relays a receipt on sa2; A's FC_CARRIER replies to X's body-set
//        asks are rewritten: own payee H (an honest payee) with the reference K
//        of another payee (not identity-bound):
//        P0 the rewritten reply passes the frame check and the decode, keeps
//           the id; X holds H's own reference; X's job builds;
//        P1 X asks A for sa1's body set; the reply is taken, no strike, no ban;
//           H held under its own identity; INV;
//        P2 A's next carrier: no DEFER at row 10, nothing parked on MissingRef;
//           A's next receipt pending; X's job builds;
//        P4 A's late reply to the sa2 ask (rewritten): taken, no strike, no
//           ban; H held under its own identity;
//        P5 a new P_r: X's job builds.
//   O    P1 through the owner field: a fee and owner H with K.
//   R    the honest race: X asks A and L for the body sets of sa1 and sa2; the
//        replies delivered in each of the 24 priority orders x 2 first senders;
//        in every run no reference under another identity after any frame; k
//        admitted; the next honest carrier and receipt admitted; X's job
//        builds; no strike, no ban.
//   RA   R's orders with A's replies rewritten as in P: R's predicate holds.
//   RA2  RA with the rewritten own body also stating a fee and owner K under K's own identity (a payee rewrite in a
//        body that has an owner): R's predicate holds.
//   RO   R's orders with A and L paying an owner fee: R's predicate holds.
//   J    a node joins from A; A's FC_GETCARRIER reply of the walked side
//        carrier s1 names payee HJ (first body above the walk) with K: the
//        attempt completes; HJ held under its own identity; INV on the
//        attempt's map before the adoption and on the node's map after it; the
//        next honest carrier is placed; the job builds.
//   JO   J through the owner field.
//   J2   J with the rewritten own body also stating a fee and owner K under K's own identity.
//   J1   J aimed at payee 1 (its honest body replayed below the walk).
//   JC   J with no rewrite.
//   JCO  JC with A and B paying an owner fee; A's store loaded (restart).
//   S    a scaffold store: a stored body with its payee or owner reference
//        replaced by K, its side data unchanged, the only body of that payee
//        or owner: the best chain's tip, a side carrier (K_PSIDE) own body and
//        its carried body; the load stands and INV holds on LoadedState::refs.
//   EQ   the digest of a map is sha256 over its entries in key order (key,
//        spend, view); the digests after every frame delivered on the wire and
//        every join step and request are chained per world: R, RO, JC, JCO and
//        the S store's clean load equal the goldens below.
// The relay harness (FakeWire, FakeLinks, KatRelay, kat_relay, mine_on) is
// v37_xmr_pathb_node_kat.cpp's; joining_node is v37_xmr_pathb_node_join_kat.cpp's.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_relay_links.hpp"
#include "c2pool/v37/xmr/pathb/pathb_relay_node.hpp"
#include "impl/xmr/pathb/pathb_store.hpp"
#include "pathb_kat_join.hpp"
#include "pathb_kat_lane.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_kat_store.hpp"
#include "sharechain/v37/v37_hash.hpp"

namespace c2pool::xmr::pathb {
// The KATs' view of a node's private state (read only; the join step hook).
struct PathbNodeTestAccess {
    static const std::map<Hash32, XmrKeyRef>& refs(const PathbNode& n) { return *n.refs_; }
    static void on_join_step(PathbNode& n, std::function<void(JoinedState&, std::uint64_t)> f) {
        n.joiner_->set_on_step(std::move(f));
    }
};
}  // namespace c2pool::xmr::pathb

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

// ---- read access to the relay's park index (counting only) ----
template <class Tag, typename Tag::type M>
struct Rob {
    friend typename Tag::type get(Tag) { return M; }
};
struct RParked {
    using type = std::map<pb::Missing, std::set<pb::Hash32>> pb::PathbRelayNode::*;
    friend type get(RParked);
};
template struct Rob<RParked, &pb::PathbRelayNode::parked_by_cause_>;

namespace {

using RefMap = std::map<pb::Hash32, pb::XmrKeyRef>;

pb::EpochTable table0(const KatNet& net) { return kat_table(net); }

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

// ---------------------------------------------------------------------------
// The fetches a DEFER names, sent to the frame's sender over the relay and placed after the reply.
bool mine_on(Harness& h, FakeWire& w, std::size_t node, std::size_t payee, std::uint32_t nonce) {
    const std::optional<pb::PathbJob> j = h.job(node, payee, nonce);
    const bool ok = j && h[node].on_own_share(*j, nonce, pb::Hash32{}).action == pb::NodeAction::Placed;
    w.run();
    return ok;
}

// ---------------------------------------------------------------------------
constexpr std::size_t kHPayee = 3;  // H: the honest payee named by the rewritten replies (L's payee in the race)
constexpr std::size_t kKPayee = 7;  // K: the reference the rewritten replies carry (a valid point of another identity)
constexpr std::size_t kOwner = 12;  // the owner reference of the owner-fee worlds (RO, JCO)
constexpr std::uint16_t kOwnerFeeBp = 100;  // a test value: the owner fee (bp) of RO, JCO and S; PathbNodeConfig::owner_fee_bp defaults to 0

std::string h8(const pb::Hash32& h) { return hex(h.data(), 4); }
std::string hex32(const pb::Hash32& h) { return hex(h.data(), h.size()); }
std::string idname(const std::optional<pb::Hash32>& id, const pb::Hash32& H, const pb::Hash32& Kid) {
    if (!id) return "none";
    if (*id == H) return "H (its own identity)";
    if (*id == Kid) return "K's identity (another payee)";
    return h8(*id);
}

// The identity of the key reference a map holds under `id` (nullopt: none held).
std::optional<pb::Hash32> held_in(const RefMap& m, const pb::Hash32& id) {
    const auto it = m.find(id);
    if (it == m.end()) return std::nullopt;
    return pb::key_ref_identity(it->second);
}
// References held under an identity that is not their own.
std::size_t mismatched(const RefMap& m) {
    std::size_t bad = 0;
    for (const auto& [id, ref] : m) bad += pb::key_ref_identity(ref) == id ? 0 : 1;
    return bad;
}
// K in a map: absent, under its own identity, or under another one.
std::string k_status(const RefMap& m, const pb::XmrKeyRef& K) {
    std::size_t other = 0;
    for (const auto& [id, ref] : m) other += ref == K && id != pb::key_ref_identity(K) ? 1 : 0;
    const bool own = m.count(pb::key_ref_identity(K)) != 0;
    if (other != 0) return "under another identity";
    return own ? "under its own identity" : "absent";
}
const RefMap& refs_of(const pb::PathbNode& n) { return pb::PathbNodeTestAccess::refs(n); }
std::optional<pb::Hash32> held_identity(const pb::PathbNode& n, const pb::Hash32& id) { return held_in(refs_of(n), id); }
std::size_t mismatched_refs(const pb::PathbNode& n) { return mismatched(refs_of(n)); }
std::size_t refs_held(const pb::PathbNode& n) { return refs_of(n).size(); }

// EQ: sha256 over a map's entries in key order (key, spend, view); a chain of such digests.
pb::Hash32 map_digest(const RefMap& m) {
    std::vector<std::uint8_t> b;
    b.reserve(m.size() * 96);
    for (const auto& [id, ref] : m) {
        b.insert(b.end(), id.begin(), id.end());
        b.insert(b.end(), ref.spend.begin(), ref.spend.end());
        b.insert(b.end(), ref.view.begin(), ref.view.end());
    }
    return ::v37::sha256(b.data(), b.size());
}
struct Chain {
    pb::Hash32 acc{};
    std::uint64_t points = 0;
    void add(const pb::Hash32& d) {
        std::array<std::uint8_t, 64> buf{};
        std::copy(acc.begin(), acc.end(), buf.begin());
        std::copy(d.begin(), d.end(), buf.begin() + 32);
        acc = ::v37::sha256(buf.data(), buf.size());
        ++points;
    }
    void add(const RefMap& m) { add(map_digest(m)); }
    void fold(const Chain& c) {
        const std::uint64_t p = points + c.points;
        add(c.acc);
        points = p;
    }
};
// sha256 over a store's records in key order (key length, key, value length, value).
pb::Hash32 kv_digest(const MemoryKv& kv) {
    std::vector<std::uint8_t> b;
    const auto put = [&b](const std::string& s) {
        const std::uint64_t n = s.size();
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
        b.insert(b.end(), s.begin(), s.end());
    };
    for (const auto& [k, v] : kv.data) {
        put(k);
        put(v);
    }
    return ::v37::sha256(b.data(), b.size());
}

// EQ goldens: the digest chains of R, RO, JC, JCO and S0 at c2pool 23fa2871.
const char* const kEqR = "c107e717907a7c2bcae097c447d101a11967524e78dbdd5971d09daf1e2b5580";
const char* const kEqRO = "e6c4256a0d88ae314caf1a8d815697e35b714e6047a40a1d22600f4d0d48384c";
const char* const kEqJC = "0ecea22d627ce281f6c4e1ef475ad1d292565ec90006c664ba29ba8595ed958c";
const char* const kEqJCO = "45f54f9de109988feee3a73a1a16529dc4cf297f0913eda9c341f00a7f8cfa3c";
const char* const kEqS0 = "51dc8c8ab0f007e4977359615111e50e70da92a9c7fc6a48fa4830729d202a53";

void check_eq(const char* tag, const Chain& c, const char* golden, const std::string& what) {
    const std::string d = hex32(c.acc);
    std::printf("EQ %s %s points %llu\n", tag, d.c_str(), (unsigned long long)c.points);
    check(d == golden, std::string("EQ ") + tag + ": " + what + " equal the golden (" + d + ", " + std::to_string(c.points) +
                               " digests)");
}

std::optional<pb::CarrierBodyV3> decode_cf(const std::vector<std::uint8_t>& f) {
    if (f.size() < pb::kFrameHeaderBytes || f[0] != pb::kOpFcCarrier) return std::nullopt;
    pb::CarrierBodyV3 c;
    if (pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                   pb::CarrierLimits{1u << 20, pb::kRuledLaneParams.r_max}, c)
        != pb::WireError::None)
        return std::nullopt;
    return c;
}
std::vector<std::uint8_t> fc(const pb::CarrierBodyV3& c) { return *pb::encode_fc_carrier(0, c, pb::kRuledLaneParams.r_max); }
std::vector<std::uint8_t> fb(const pb::ReceiptBodyV3& r) {
    return *pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{r}, pb::kRuledLaneParams);
}

// A carrier frame with its own body's payee field set to H and its payee reference set to K (a point that
// decompresses, of another identity); the own id (receipt_id of the blob) and the carried list unchanged. owned: the
// own body also states a fee (side.fee_rate_bp 1 when 0) and names K as its owner under K's own identity.
std::vector<std::uint8_t> rewrite_payee(const std::vector<std::uint8_t>& f, const pb::Hash32& H, const pb::XmrKeyRef& K,
                                        bool owned = false) {
    std::optional<pb::CarrierBodyV3> c = decode_cf(f);
    if (!c) return f;
    c->own.side.payee = H;
    c->own.payee = K;
    if (owned && c->own.side.fee_rate_bp == 0) {
        c->own.side.fee_rate_bp = 1;
        c->own.side.owner = pb::key_ref_identity(K);
        c->own.owner = K;
    }
    const std::optional<std::vector<std::uint8_t>> out = pb::encode_fc_carrier(0, *c, pb::kRuledLaneParams.r_max);
    return out ? *out : f;
}

// The same through the owner field: the own body states a fee (side.fee_rate_bp 1 when 0) and names H as its owner
// with K; the payee fields unchanged.
std::vector<std::uint8_t> rewrite_owner(const std::vector<std::uint8_t>& f, const pb::Hash32& H, const pb::XmrKeyRef& K) {
    std::optional<pb::CarrierBodyV3> c = decode_cf(f);
    if (!c) return f;
    if (c->own.side.fee_rate_bp == 0) c->own.side.fee_rate_bp = 1;
    c->own.side.owner = H;
    c->own.owner = K;
    const std::optional<std::vector<std::uint8_t>> out = pb::encode_fc_carrier(0, *c, pb::kRuledLaneParams.r_max);
    return out ? *out : f;
}

std::size_t parked_on(pb::PathbRelayNode& r, pb::Missing m) {
    const std::map<pb::Missing, std::set<pb::Hash32>>& idx = r.*get(RParked{});
    const auto it = idx.find(m);
    return it == idx.end() ? 0 : it->second.size();
}
std::uint64_t vcount(const pb::PathbRelayNode& r, pb::RowId row, pb::AdmitVerdict v) {
    return r.verdict_counts()[static_cast<std::size_t>(row)][static_cast<std::size_t>(v)];
}
std::string parked_summary(pb::PathbRelayNode& r) {
    std::string o;
    for (const auto& [m, ids] : r.*get(RParked{}))
        if (!ids.empty()) o += " cause" + std::to_string(static_cast<int>(m)) + ":" + std::to_string(ids.size());
    return o.empty() ? " none" : o;
}
std::string vdelta(const pb::PathbRelayNode::VerdictCounts& a, const pb::PathbRelayNode::VerdictCounts& b) {
    std::string d;
    for (std::size_t r = 0; r < b.size(); ++r)
        for (std::size_t v = 0; v < b[r].size(); ++v)
            if (b[r][v] != a[r][v]) d += " R" + std::to_string(r) + "/v" + std::to_string(v) + " +" + std::to_string(b[r][v] - a[r][v]);
    return d.empty() ? " none" : d;
}
const char* tstatus(pb::TemplateStatus s) {
    switch (s) {
        case pb::TemplateStatus::Ok: return "Ok";
        case pb::TemplateStatus::NoPathbPeer: return "NoPathbPeer";
        case pb::TemplateStatus::CatchingUp: return "CatchingUp";
        default: return "other";
    }
}

// ---------------------------------------------------------------------------
// The world of sections P, O and R: three relay nodes in manual mode. A mines four carriers (payee 1), then A and L
// race cut apart: A mines sa1 (payee 2, carrying A's stale share va) and sa2 (payee 2, carrying A's stale share ua);
// L mines l1, l2, l3 (payee 3). L's branch wins at A. k: A's share on sa2 (payee 4), pending at A. X follows A
// (catch-up to A's best, no receipt frame of A on the way): X holds L's branch, not sa1 / sa2. With x_links_l, X also
// links to L. With owner_fee, A and L pay the owner fee kOwnerFeeBp to kOwner. At every frame on the wire, and at
// every mark(), INV is checked on X's map and its digest is chained (eq).
struct World {
    KatNet net;
    Harness h{net};
    FakeWire w;
    KatRelay a, l, x;
    pb::Hash32 H{};    // the honest payee's identity (payee kHPayee)
    pb::XmrKeyRef K;   // the reference the rewritten replies carry (payee kKPayee's reference)
    pb::Hash32 Kid{};  // K's identity
    pb::Hash32 sa1{}, sa2{}, l2{}, l3{}, k{};
    pb::ReceiptBodyV3 kb;
    bool ok = false;
    std::string why;
    // the wire's edit
    bool cut_al = false;          // frames between A and L dropped (the race)
    bool drop_rcpt_to_x = false;  // FB_RECEIPTS to X dropped (X's catch-up)
    std::set<pb::Hash32> rewrite_ids;  // FC_CARRIER from A to X with these own ids: rewritten
    std::set<pb::Hash32> hold_ids;    // FC_CARRIER from A or L to X with these own ids: held back
    struct Held {
        std::size_t from = 0;
        pb::Hash32 id{};
        std::vector<std::uint8_t> f;
    };
    std::vector<Held> held;
    std::uint64_t rewritten = 0;
    bool via_owner = false;  // the rewrite goes through the owner field
    std::map<std::uint8_t, std::uint64_t> x_req;            // X's requests on the wire, by opcode
    std::vector<std::pair<std::size_t, pb::Hash32>> x_gc;   // X's FC_GETCARRIER (want_bodies 1): (to node, id)
    // INV and EQ on X's map
    std::uint64_t inv_points = 0, inv_bad = 0;
    std::size_t inv_max = 0;
    Chain eq;

    explicit World(bool x_links_l, bool owner_fee = false) {
        std::function<void(pb::PathbNodeConfig&)> fee;
        if (owner_fee)
            fee = [this](pb::PathbNodeConfig& c) {
                c.owner_fee_bp = kOwnerFeeBp;
                c.owner = net.refs[kOwner];
            };
        a = kat_relay(h, w, table0(net), true, false, nullptr, fee);
        l = kat_relay(h, w, table0(net), true, false, nullptr, fee);
        x = kat_relay(h, w, table0(net), false);
        H = pb::key_ref_identity(net.refs[kHPayee]);
        K = net.refs[kKPayee];
        Kid = pb::key_ref_identity(K);
        w.edit = [this](FakeWire::Msg& m) { on_msg(m); };
        w.connect(0, 1);
        w.run();
        bool g = true;
        std::optional<pb::PathbJob> va;
        for (int i = 0; i < 4; ++i) {
            if (i % 2 == 0) h.tick_monero();
            if (i == 3) va = h.job(a.node, 5, 350);
            g = g && mine_on(h, w, a.node, 1, 300 + static_cast<std::uint32_t>(i));
        }
        g = g && va && h[a.node].on_own_share(*va, 350, pb::Hash32{}).action == pb::NodeAction::Pending;
        w.run();
        const std::optional<pb::PathbJob> ua = h.job(a.node, 6, 360);
        cut_al = true;
        h.tick_monero();
        g = g && ua && mine_on(h, w, a.node, 2, 400);
        sa1 = h[a.node].tree().best().id;
        g = g && h[a.node].on_own_share(*ua, 360, pb::Hash32{}).action == pb::NodeAction::Pending;
        g = g && mine_on(h, w, a.node, 2, 402);
        sa2 = h[a.node].tree().best().id;
        const std::optional<pb::PathbJob> ka = h.job(a.node, 4, 410);
        g = g && mine_on(h, w, l.node, kHPayee, 401);
        g = g && mine_on(h, w, l.node, kHPayee, 411);
        l2 = h[l.node].tree().best().id;
        const std::optional<pb::PathbJob> jr = h.job(l.node, kHPayee, 499);  // on l2, at l3's P_r (no tick between)
        g = g && mine_on(h, w, l.node, kHPayee, 421);
        l3 = h[l.node].tree().best().id;
        const std::optional<pb::PathbJob> jc = h.job(l.node, kHPayee, 520);  // on l3, at l3's P_r (no tick between)
        cut_al = false;
        if (!g || !ka || !jr || !jc) {
            why = "the race";
            return;
        }
        g = !h[a.node].bodies().get(sa1)->carried.empty() && !h[a.node].bodies().get(sa2)->carried.empty();
        for (const pb::Hash32& id : {sa1, sa2})
            w.q.push_back(FakeWire::Msg{a.node, l.node, fc(*h[a.node].bodies().get(id))});
        {
            std::vector<pb::Hash32> ls;
            for (pb::Hash32 t = h[l.node].tree().best().id; ls.size() < 3; t = h[l.node].tree().find(t)->parent) ls.push_back(t);
            for (auto it = ls.rbegin(); it != ls.rend(); ++it)
                w.q.push_back(FakeWire::Msg{l.node, a.node, fc(*h[l.node].bodies().get(*it))});
        }
        w.run();
        g = g && h[a.node].tree().best().id == l3 && h[a.node].tree().find(sa2) != nullptr;
        kb = ka->body;
        kb.blob.nonce = 410;
        k = pb::receipt_id(kb);
        g = g && h[a.node].on_own_share(*ka, 410, pb::Hash32{}).action == pb::NodeAction::Pending && h[a.node].pending().holds(k);
        w.run();
        if (!g) {
            why = "A follows L; k pending at A";
            return;
        }
        // X follows A: its catch-up reaches A's best; no receipt frame reaches X
        drop_rcpt_to_x = true;
        w.connect(a.node, x.node);
        w.run();
        for (int i = 0; i < 6 && h[x.node].tree().best().id != h[a.node].tree().best().id; ++i) settle(1);
        if (x_links_l) {
            w.connect(l.node, x.node);
            w.run();
            settle(2);
        }
        drop_rcpt_to_x = false;
        ok = h[x.node].tree().best().id == l3 && h[x.node].tree().find(sa1) == nullptr && h[x.node].tree().find(sa2) == nullptr &&
             !h[x.node].pending().holds(k);
        if (!ok) why = "X synced to l3 without sa1 / sa2 / k";
        mark();
    }
    World(const World&) = delete;
    World& operator=(const World&) = delete;

    // INV on X's map, and its digest chained.
    void mark() {
        const RefMap& m = refs_of(h[x.node]);
        const std::size_t bad = mismatched(m);
        ++inv_points;
        inv_bad += bad == 0 ? 0 : 1;
        inv_max = std::max(inv_max, bad);
        eq.add(m);
    }
    void on_msg(FakeWire::Msg& m) {
        mark();
        if (m.f.empty()) return;
        const std::uint8_t op = m.f[0];
        if (cut_al && ((m.from == a.node && m.to == l.node) || (m.from == l.node && m.to == a.node))) {
            m.f.clear();
            return;
        }
        if (m.from == x.node) {
            if (op == pb::kOpFcGetCarrier || op == pb::kOpFcGetHeaders || op == pb::kOpFcGetBuckets || op == pb::kOpFbGetCtx)
                ++x_req[op];
            if (op == pb::kOpFcGetCarrier) {
                pb::GetCarrier q;
                if (pb::decode_fc_getcarrier(m.f, 0, pb::kRuledLaneParams, q).ok() && q.want_bodies)
                    for (const pb::Hash32& id : q.ids) x_gc.emplace_back(m.to, id);
            }
            return;
        }
        if (m.to != x.node) return;
        if (drop_rcpt_to_x && op == pb::kOpFbReceipts) {
            m.f.clear();
            return;
        }
        if (op != pb::kOpFcCarrier) return;
        const std::optional<pb::CarrierBodyV3> c = decode_cf(m.f);
        if (!c) return;
        const pb::Hash32 id = pb::receipt_id(c->own);
        if (hold_ids.count(id) != 0 && (m.from == a.node || m.from == l.node)) {
            held.push_back(Held{m.from, id, m.f});
            m.f.clear();
            return;
        }
        if (m.from == a.node && rewrite_ids.count(id) != 0) {
            m.f = via_owner ? rewrite_owner(m.f, H, K) : rewrite_payee(m.f, H, K);
            ++rewritten;
        }
    }
    pb::PathbNode& X() { return h[x.node]; }
    pb::PathbRelayNode& RX() { return *x.relay; }
    static std::uint64_t at_x(std::size_t node) { return node + 1; }  // node's link id at X (first link)
    void settle(int ticks) {
        for (int i = 0; i < ticks; ++i) {
            h.now += 1;
            x.relay->tick();
            w.run();
        }
    }
    std::uint64_t x_requests() const {
        std::uint64_t n = 0;
        for (const auto& [op, c] : x_req) n += c;
        return n;
    }
    std::uint64_t gc_to(std::size_t node, const pb::Hash32& id) const {
        std::uint64_t n = 0;
        for (const auto& [to, i] : x_gc) n += to == node && i == id ? 1 : 0;
        return n;
    }
};

// The next honest carrier c of A (on A's best) and an honest receipt rk of A on the same tip, both on a window
// holding H with a key set X never computed; X's own job.
struct Effects {
    bool mined = false, rk_pending_at_a = false;
    pb::Hash32 c{}, rk{};
    bool c_placed = false, rk_pending = false, best_moved = false;
    std::uint64_t r10_defer = 0, r26_defer = 0, requests = 0;
    std::int64_t missingref_parked = 0;
    std::uint64_t body_set_requests = 0, tip_header_requests = 0, bucket_requests = 0, ctx_asked = 0;
    pb::TemplateStatus tst = pb::TemplateStatus::NoTemplate;
    bool job_ok = false;
};
Effects effects(World& s, std::uint32_t nonce) {
    Effects e;
    pb::PathbNode& X = s.X();
    pb::PathbRelayNode& rx = s.RX();
    const pb::PathbRelayStats& st = rx.stats();
    s.h.tick_monero();  // a new P_r: key sets X never computed
    const std::optional<pb::PathbJob> jk = s.h.job(s.a.node, 8, nonce);
    const std::uint64_t r10 = vcount(rx, pb::RowId::R10, pb::AdmitVerdict::Defer);
    const std::uint64_t r26 = vcount(rx, pb::RowId::R26, pb::AdmitVerdict::Defer);
    const std::size_t mr = parked_on(rx, pb::Missing::MissingRef);
    const std::uint64_t xr = s.x_requests(), bsr = st.body_set_requests.load(), thr = st.tip_header_requests.load(),
                        brq = st.bucket_requests.load(), cta = st.ctx_asked.load();
    const pb::Hash32 best0 = X.tree().best().id;
    e.mined = mine_on(s.h, s.w, s.a.node, 9, nonce + 10);  // A's carrier c, flooded to X
    e.c = s.h[s.a.node].tree().best().id;
    if (jk) {
        pb::ReceiptBodyV3 rb = jk->body;
        rb.blob.nonce = nonce;
        e.rk = pb::receipt_id(rb);
        e.rk_pending_at_a = s.h[s.a.node].on_own_share(*jk, nonce, pb::Hash32{}).action == pb::NodeAction::Pending;
        s.w.run();  // A relays rk (FB_RECEIPTS) to X
    }
    s.mark();
    e.c_placed = X.tree().find(e.c) != nullptr;
    e.rk_pending = X.pending().holds(e.rk);
    e.best_moved = X.tree().best().id != best0;
    e.r10_defer = vcount(rx, pb::RowId::R10, pb::AdmitVerdict::Defer) - r10;
    e.r26_defer = vcount(rx, pb::RowId::R26, pb::AdmitVerdict::Defer) - r26;
    e.missingref_parked = static_cast<std::int64_t>(parked_on(rx, pb::Missing::MissingRef)) - static_cast<std::int64_t>(mr);
    e.requests = s.x_requests() - xr;
    e.body_set_requests = st.body_set_requests.load() - bsr;
    e.tip_header_requests = st.tip_header_requests.load() - thr;
    e.bucket_requests = st.bucket_requests.load() - brq;
    e.ctx_asked = st.ctx_asked.load() - cta;
    const pb::PathbTemplate t = X.make_template(s.h.now);
    e.tst = t.status;
    e.job_ok = X.make_job(t, s.h.session(11, nonce + 20)).has_value();
    return e;
}
void print_effects(const char* tag, const Effects& e) {
    std::printf("COUNT %s A mined c %d (on A's best), rk pending at A %d; at X: c placed %d, rk pending %d, X's best moved %d; "
                "DEFER R10 +%llu, DEFER R26 +%llu, parked on MissingRef %+lld; X's requests on the wire +%llu (body sets +%llu, "
                "tip headers +%llu, buckets +%llu, contexts +%llu); X's template %s, X's job %s\n",
                tag, e.mined, e.rk_pending_at_a, e.c_placed, e.rk_pending, e.best_moved, (unsigned long long)e.r10_defer,
                (unsigned long long)e.r26_defer, (long long)e.missingref_parked, (unsigned long long)e.requests,
                (unsigned long long)e.body_set_requests, (unsigned long long)e.tip_header_requests,
                (unsigned long long)e.bucket_requests, (unsigned long long)e.ctx_asked, tstatus(e.tst),
                e.job_ok ? "builds" : "FAILS (none)");
}

// ---------------------------------------------------------------------------
// P: A's link to X rewrites its body-set replies.
void section_p() {
    std::printf("== P: A's body-set replies to X rewritten (own payee H with the reference K) ==\n");
    auto W = std::make_unique<World>(false);
    World& s = *W;
    check(s.ok, "P setup: X synced to l3 without sa1 / sa2 / k (" + s.why + ")");
    if (!s.ok) return;
    pb::PathbNode& X = s.X();
    pb::PathbRelayNode& rx = s.RX();
    const pb::PathbRelayStats& st = rx.stats();
    const std::uint64_t pa = World::at_x(s.a.node);
    // P0: the rewritten frame passes the frame check and the decode and keeps the id; it is not identity-bound
    {
        const std::vector<std::uint8_t> hon = fc(*s.h[s.a.node].bodies().get(s.sa1));
        const std::vector<std::uint8_t> pf = rewrite_payee(hon, s.H, s.K);
        const std::optional<pb::CarrierBodyV3> pc = decode_cf(pf);
        const bool fh = pb::check_fc_carrier(pf, 0, X.config().buffers).ok();
        const bool same_id = pc && pb::receipt_id(pc->own) == s.sa1;
        const bool unbound = pc && !pb::identities_bound(pc->own);
        std::printf("COUNT P0 rewritten sa1 frame: %zu bytes (honest %zu); frame check %d, decode %d, own id = sa1 %d, "
                    "identity-bound %d; carried bodies %zu\n",
                    pf.size(), hon.size(), fh, pc.has_value(), same_id, pc ? pb::identities_bound(pc->own) : -1,
                    pc ? pc->carried.size() : 0);
        check(pf != hon && fh && pc && same_id && unbound,
              "P0 the rewritten reply passes the FC_CARRIER frame check and the decode and keeps the walked carrier's id; "
              "its own body is not identity-bound");
    }
    const std::optional<pb::Hash32> before = held_identity(X, s.H);
    const bool j0 = s.h.job(s.x.node, 11, 901).has_value();
    std::printf("COUNT P0 X at l3 (pos %llu); refs held %zu, held under another identity %zu; H (payee %zu) held as %s; "
                "X's job %s\n",
                (unsigned long long)X.tree().best().pos, refs_held(X), mismatched_refs(X), kHPayee,
                idname(before, s.H, s.Kid).c_str(), j0 ? "builds" : "FAILS");
    check(before && *before == s.H && mismatched_refs(X) == 0 && j0, "P0 X holds H's own reference; X's job builds");

    // P1: the ask and the rewritten reply
    s.rewrite_ids = {s.sa1};
    s.hold_ids = {s.sa2};
    const std::uint64_t inv0 = s.inv_bad;
    const std::uint64_t thr0 = st.tip_header_requests.load(), bsr0 = st.body_set_requests.load(),
                        bs0 = st.body_sets.load(), sk0 = st.strikes.load(), bn0 = st.bans.load();
    rx.receive(pa, fb(s.kb));  // A relays k: A's share on sa2, a tip X does not hold
    s.w.run();
    for (int i = 0; i < 12 && s.held.empty(); ++i) s.settle(1);
    s.mark();
    const std::optional<pb::Hash32> after = held_identity(X, s.H);
    std::printf("COUNT P1 k relayed by A: tip-header requests +%llu, body-set asks +%llu (sa1 of A on the wire %llu, sa2 of A "
                "%llu); A's replies rewritten %llu; body sets taken +%llu; strikes +%llu, bans +%llu; sa1 placed at X %d; "
                "A's sa2 reply held %zu; k pending at X %d; H held as %s; refs held %zu, under another identity %zu; K %s\n",
                (unsigned long long)(st.tip_header_requests.load() - thr0), (unsigned long long)(st.body_set_requests.load() - bsr0),
                (unsigned long long)s.gc_to(s.a.node, s.sa1), (unsigned long long)s.gc_to(s.a.node, s.sa2),
                (unsigned long long)s.rewritten, (unsigned long long)(st.body_sets.load() - bs0),
                (unsigned long long)(st.strikes.load() - sk0), (unsigned long long)(st.bans.load() - bn0),
                X.tree().find(s.sa1) != nullptr, s.held.size(), X.pending().holds(s.k), idname(after, s.H, s.Kid).c_str(),
                refs_held(X), mismatched_refs(X), k_status(refs_of(X), s.K).c_str());
    check(s.gc_to(s.a.node, s.sa1) >= 1 && st.body_set_requests.load() - bsr0 >= 1,
          "P1 X sends A FC_GETCARRIER (want_bodies 1) of the walked carrier sa1");
    check(s.rewritten == 1 && st.body_sets.load() - bs0 >= 1 && st.strikes.load() == sk0 && st.bans.load() == bn0,
          "P1 the rewritten reply is taken as a body set (frame check and decode); no strike, no ban");
    check(after && *after == s.H && mismatched_refs(X) == 0,
          "P1 H held under its own identity; no reference held under another identity");
    check(s.inv_bad == inv0 && k_status(refs_of(X), s.K) != "under another identity",
          "P1 INV: after every frame delivered, every key X holds is its reference's identity (K absent or under its own)");

    // P2: A's next carrier and receipt; X's job
    const pb::PathbRelayNode::VerdictCounts vc1 = rx.verdict_counts();
    const Effects e1 = effects(s, 610);
    print_effects("P2", e1);
    std::printf("COUNT P2 verdicts by row / verdict since c (2 = DEFER, 5 = CARRIER, 6 = PENDING):%s; parked by cause%s\n",
                vdelta(vc1, rx.verdict_counts()).c_str(), parked_summary(rx).c_str());
    check(e1.mined && e1.rk_pending_at_a && e1.r10_defer == 0 && e1.missingref_parked == 0 && e1.rk_pending &&
                  e1.tst == pb::TemplateStatus::Ok && e1.job_ok,
          "P2 A's next carrier makes no DEFER at row 10 and nothing is parked on MissingRef; A's next receipt is pending at "
          "X; X's job builds");

    // P4: A's late reply to its other open ask (sa2, held since P1), rewritten
    std::optional<World::Held> late;
    std::size_t held_a = 0;
    for (const World::Held& e : s.held)
        if (e.from == s.a.node && e.id == s.sa2) {
            ++held_a;
            if (!late) late = e;
        }
    s.hold_ids.clear();
    s.held.clear();
    const std::uint64_t bs1 = st.body_sets.load(), sk1 = st.strikes.load(), bn1 = st.bans.load();
    const std::uint64_t xr5 = s.x_requests();
    const pb::PathbRelayNode::VerdictCounts vc6 = rx.verdict_counts();
    std::printf("COUNT P4 before: parked by cause%s; X's deferred frames %zu\n", parked_summary(rx).c_str(), X.deferred().size());
    if (late) {
        rx.receive(pa, rewrite_payee(late->f, s.H, s.K));
        s.w.run();
        s.settle(3);
    }
    s.mark();
    std::printf("COUNT P4 after: verdicts by row / verdict since the late reply%s; parked by cause%s; X's deferred frames %zu\n",
                vdelta(vc6, rx.verdict_counts()).c_str(), parked_summary(rx).c_str(), X.deferred().size());
    const std::optional<pb::Hash32> re = held_identity(X, s.H);
    std::printf("COUNT P4 A's held replies of sa2 %zu (one sent, late, rewritten): body sets taken +%llu; strikes +%llu, bans "
                "+%llu; sa2 placed at X %d, k pending at X %d; H held as %s; c placed %d; X's requests on the wire +%llu\n",
                held_a, (unsigned long long)(st.body_sets.load() - bs1), (unsigned long long)(st.strikes.load() - sk1),
                (unsigned long long)(st.bans.load() - bn1), X.tree().find(s.sa2) != nullptr, X.pending().holds(s.k),
                idname(re, s.H, s.Kid).c_str(), X.tree().find(e1.c) != nullptr,
                (unsigned long long)(s.x_requests() - xr5));
    check(late && st.body_sets.load() - bs1 == 1 && st.strikes.load() == sk1 && st.bans.load() == bn1,
          "P4 A's late reply to its open sa2 ask (rewritten) is taken as a body set; no strike, no ban");
    check(re && *re == s.H && mismatched_refs(X) == 0,
          "P4 after the late reply H held under its own identity; no reference held under another identity");

    // P5: a new P_r; X's job
    s.h.tick_monero();
    const pb::PathbTemplate t5 = X.make_template(s.h.now);
    const bool j5 = X.make_job(t5, s.h.session(11, 905)).has_value();
    s.mark();
    std::printf("COUNT P5 X's best pos %llu; refs held under another identity %zu; c placed %d, parked by cause%s; X's "
                "template %s, X's job %s\n",
                (unsigned long long)X.tree().best().pos, mismatched_refs(X), X.tree().find(e1.c) != nullptr,
                parked_summary(rx).c_str(), tstatus(t5.status), j5 ? "builds" : "FAILS (none)");
    check(re && *re == s.H && t5.status == pb::TemplateStatus::Ok && j5, "P5 a new P_r: X's job builds (template Ok)");
    std::printf("COUNT P INV points %llu, with a reference under another identity %llu (max %zu)\n",
                (unsigned long long)s.inv_points, (unsigned long long)s.inv_bad, s.inv_max);
    check(s.inv_bad == 0, "P INV: after every frame delivered on the wire, every key X holds is its reference's identity (" +
                                  std::to_string(s.inv_points) + " points)");
}

// ---------------------------------------------------------------------------
// O: the owner field. As P1; A's sa1 reply states a fee and names H as its owner with K (the payee fields unchanged).
// The pool runs with no owner fee.
void section_o() {
    std::printf("== O: A's sa1 reply rewritten through the owner field ==\n");
    auto W = std::make_unique<World>(false);
    World& s = *W;
    check(s.ok, "O setup (" + s.why + ")");
    if (!s.ok) return;
    pb::PathbNode& X = s.X();
    pb::PathbRelayNode& rx = s.RX();
    const pb::PathbRelayStats& st = rx.stats();
    const std::vector<std::uint8_t> pf = rewrite_owner(fc(*s.h[s.a.node].bodies().get(s.sa1)), s.H, s.K);
    const std::optional<pb::CarrierBodyV3> pc = decode_cf(pf);
    const bool fh = pb::check_fc_carrier(pf, 0, X.config().buffers).ok();
    const std::optional<pb::Hash32> before = held_identity(X, s.H);
    s.via_owner = true;
    s.rewrite_ids = {s.sa1};
    s.hold_ids = {s.sa2};
    const std::uint64_t bs0 = st.body_sets.load(), sk0 = st.strikes.load(), bn0 = st.bans.load();
    rx.receive(World::at_x(s.a.node), fb(s.kb));
    s.w.run();
    for (int i = 0; i < 12 && s.held.empty(); ++i) s.settle(1);
    s.mark();
    const std::optional<pb::Hash32> after = held_identity(X, s.H);
    s.h.tick_monero();
    const pb::PathbTemplate t = X.make_template(s.h.now);
    const bool j = X.make_job(t, s.h.session(11, 907)).has_value();
    std::printf("COUNT O rewritten frame: frame check %d, decode %d, own id = sa1 %d, fee_rate_bp %u, identity-bound %d; replies "
                "rewritten %llu, body sets taken +%llu, strikes +%llu, bans +%llu; H held as %s before, %s after; refs held "
                "%zu, under another identity %zu; K %s; X's template %s, X's job %s; INV points %llu, with a reference under "
                "another identity %llu\n",
                fh, pc.has_value(), pc && pb::receipt_id(pc->own) == s.sa1, pc ? unsigned(pc->own.side.fee_rate_bp) : 0u,
                pc ? pb::identities_bound(pc->own) : -1, (unsigned long long)s.rewritten,
                (unsigned long long)(st.body_sets.load() - bs0), (unsigned long long)(st.strikes.load() - sk0),
                (unsigned long long)(st.bans.load() - bn0), idname(before, s.H, s.Kid).c_str(),
                idname(after, s.H, s.Kid).c_str(), refs_held(X), mismatched_refs(X), k_status(refs_of(X), s.K).c_str(),
                tstatus(t.status), j ? "builds" : "FAILS (none)", (unsigned long long)s.inv_points,
                (unsigned long long)s.inv_bad);
    check(fh && pc && !pb::identities_bound(pc->own) && s.rewritten == 1 && st.body_sets.load() - bs0 >= 1 &&
                  st.strikes.load() == sk0 && st.bans.load() == bn0,
          "O the reply with a fee and owner H with K passes the frame check and the decode, is not identity-bound and is "
          "taken as a body set; no strike, no ban");
    check(before && *before == s.H && after && *after == s.H && t.status == pb::TemplateStatus::Ok && j,
          "O H held under its own identity before and after; X's job builds (template Ok)");
    check(s.inv_bad == 0 && mismatched_refs(X) == 0 && k_status(refs_of(X), s.K) != "under another identity",
          "O INV: after every frame delivered, every key X holds is its reference's identity (K absent or under its own)");
}

// ---------------------------------------------------------------------------
// R: the race orders. k reaches X from both peers (first from A, or first from L; then again from each), so X asks
// each of them for the walked carriers' body sets (each peer at most once per cause and object). Their replies are
// held on the wire. Keys: 0 = A's sa1 reply, 1 = L's sa1 reply, 2 = A's sa2 reply, 3 = L's sa2 reply. At each step the
// first key of `prio` with a held reply goes to X (one reply per peer and carrier); with none held X's relay ticks,
// and while k is not pending at X, k is relayed again by A and by L. A reply whose carrier X already placed is still
// a body set (its id was asked): counted as late. rewrite: A's replies rewritten (RA; owned: RA2). owner_fee: A and L
// pay the owner fee (RO).
struct OrderRun {
    bool setup = false;
    std::string seq;
    std::size_t delivered = 0, dup = 0, late = 0, max_bad = 0, refs = 0, bad_end = 0;
    std::uint64_t asks_a = 0, asks_l = 0, body_sets = 0, strikes = 0, bans = 0, inv_points = 0, inv_bad = 0;
    bool k_pending = false, sa1 = false, sa2 = false;
    std::optional<pb::Hash32> h_ident;
    pb::Hash32 H{};
    Effects e;
    Chain eq;
    std::uint64_t merged_back = 0, evaluated = 0;
};
OrderRun run_order(const std::array<int, 4>& prio, bool rewrite, bool l_first, bool owner_fee, bool owned = false) {
    OrderRun o;
    auto W = std::make_unique<World>(true, owner_fee);
    World& s = *W;
    if (!s.ok) return o;
    o.setup = true;
    o.H = s.H;
    pb::PathbNode& X = s.X();
    pb::PathbRelayNode& rx = s.RX();
    const pb::PathbRelayStats& st = rx.stats();
    const std::uint64_t bs0 = st.body_sets.load(), sk0 = st.strikes.load(), bn0 = st.bans.load();
    s.hold_ids = {s.sa1, s.sa2};
    const std::uint64_t p1 = World::at_x(l_first ? s.l.node : s.a.node), p2 = World::at_x(l_first ? s.a.node : s.l.node);
    for (int round = 0; round < 2; ++round)
        for (const std::uint64_t p : {p1, p2}) {
            rx.receive(p, fb(s.kb));
            s.w.run();
            s.settle(round == 0 ? 4 : 2);
        }
    const std::array<std::pair<std::size_t, pb::Hash32>, 4> keys{
            {{s.a.node, s.sa1}, {s.l.node, s.sa1}, {s.a.node, s.sa2}, {s.l.node, s.sa2}}};
    std::set<std::pair<std::size_t, pb::Hash32>> done;
    int idle = 0;
    for (int step = 0; step < 60 && idle < 4; ++step) {
        std::optional<std::size_t> pick;
        for (const int p : prio) {
            for (std::size_t i = 0; i < s.held.size() && !pick; ++i)
                if (s.held[i].from == keys[p].first && s.held[i].id == keys[p].second) pick = i;
            if (pick) break;
        }
        if (!pick && !s.held.empty()) pick = 0;
        if (!pick) {
            if (!X.pending().holds(s.k)) {
                rx.receive(p1, fb(s.kb));
                s.w.run();
                rx.receive(p2, fb(s.kb));
                s.w.run();
            }
            s.settle(1);
            if (s.held.empty()) ++idle;
            continue;
        }
        idle = 0;
        const World::Held e = s.held[*pick];
        s.held.erase(s.held.begin() + static_cast<std::ptrdiff_t>(*pick));
        if (!done.insert(std::make_pair(e.from, e.id)).second) {
            ++o.dup;
            continue;
        }
        const bool from_a = e.from == s.a.node;
        const bool was_placed = X.tree().find(e.id) != nullptr;
        rx.receive(World::at_x(e.from), rewrite && from_a ? rewrite_payee(e.f, s.H, s.K, owned) : e.f);
        s.w.run();
        s.mark();
        ++o.delivered;
        o.late += was_placed ? 1 : 0;
        o.seq += std::string(from_a ? "A:" : "L:") + (e.id == s.sa1 ? "sa1" : "sa2") + (was_placed ? "(late) " : " ");
        o.max_bad = std::max(o.max_bad, mismatched_refs(X));
        s.settle(1);
        o.max_bad = std::max(o.max_bad, mismatched_refs(X));
    }
    s.hold_ids.clear();
    s.settle(2);
    s.mark();
    o.max_bad = std::max(o.max_bad, mismatched_refs(X));
    o.bad_end = mismatched_refs(X);
    o.refs = refs_held(X);
    o.asks_a = s.gc_to(s.a.node, s.sa1) + s.gc_to(s.a.node, s.sa2);
    o.asks_l = s.gc_to(s.l.node, s.sa1) + s.gc_to(s.l.node, s.sa2);
    o.body_sets = st.body_sets.load() - bs0;
    o.strikes = st.strikes.load() - sk0;
    o.bans = st.bans.load() - bn0;
    o.k_pending = X.pending().holds(s.k);
    o.sa1 = X.tree().find(s.sa1) != nullptr;
    o.sa2 = X.tree().find(s.sa2) != nullptr;
    o.h_ident = held_identity(X, s.H);
    o.e = effects(s, 610);
    s.mark();
    o.inv_points = s.inv_points;
    o.inv_bad = s.inv_bad;
    o.max_bad = std::max(o.max_bad, s.inv_max);
    o.eq = s.eq;
    o.merged_back = X.window_flags().merged_back;
    o.evaluated = X.window_flags().evaluated;
    return o;
}
void section_r() {
    std::printf("== R: the honest race (24 orders x 2 first senders); RA, RA2: A's replies rewritten; RO: an owner fee ==\n");
    struct Mode {
        const char* tag;
        bool rewrite;
        bool owner_fee;
        bool owned;
    };
    for (const Mode md : {Mode{"R", false, false, false}, Mode{"RA", true, false, false}, Mode{"RA2", true, false, true},
                          Mode{"RO", false, true, false}}) {
        int runs = 0, setups = 0, clean = 0, admitted = 0, h_own = 0, placed = 0, jobs = 0, quiet = 0;
        int four = 0, with_late = 0;
        std::size_t delivered = 0, late = 0, max_bad = 0, refs_min = SIZE_MAX, refs_max = 0;
        std::uint64_t points = 0, merged_back = 0, evaluated = 0;
        std::set<std::string> seqs;
        Chain all;
        for (const bool l_first : {false, true}) {
            std::array<int, 4> prio{0, 1, 2, 3};
            do {
                const OrderRun o = run_order(prio, md.rewrite, l_first, md.owner_fee, md.owned);
                ++runs;
                if (!o.setup) {
                    std::printf("COUNT %s first %s order %d%d%d%d: setup failed\n", md.tag, l_first ? "L" : "A", prio[0],
                                prio[1], prio[2], prio[3]);
                    continue;
                }
                ++setups;
                seqs.insert(o.seq);
                max_bad = std::max(max_bad, o.max_bad);
                const bool h_is_own = o.h_ident && *o.h_ident == o.H;
                std::printf("COUNT %s first %s order %d%d%d%d: replies [%s] delivered %zu (late %zu, repeats dropped %zu); asks "
                            "of A %llu, of L %llu; body sets %llu; strikes %llu, bans %llu; refs %zu, held under another "
                            "identity: max %zu, at the end %zu; H held as its own %d; sa1 %d sa2 %d placed, k pending %d; next "
                            "carrier c placed %d (DEFER R10 +%llu, MissingRef %+lld), rk pending %d; X's job %s; EQ %s (%llu)\n",
                            md.tag, l_first ? "L" : "A", prio[0], prio[1], prio[2], prio[3], o.seq.c_str(), o.delivered, o.late,
                            o.dup, (unsigned long long)o.asks_a, (unsigned long long)o.asks_l, (unsigned long long)o.body_sets,
                            (unsigned long long)o.strikes, (unsigned long long)o.bans, o.refs, o.max_bad, o.bad_end, h_is_own,
                            o.sa1, o.sa2, o.k_pending, o.e.c_placed, (unsigned long long)o.e.r10_defer,
                            (long long)o.e.missingref_parked, o.e.rk_pending, o.e.job_ok ? "builds" : "FAILS",
                            h8(o.eq.acc).c_str(), (unsigned long long)o.eq.points);
                delivered += o.delivered;
                late += o.late;
                four += o.delivered == 4 ? 1 : 0;
                with_late += o.late > 0 ? 1 : 0;
                clean += o.max_bad == 0 && o.inv_bad == 0 ? 1 : 0;
                admitted += o.k_pending && o.sa1 && o.sa2 ? 1 : 0;
                h_own += h_is_own ? 1 : 0;
                placed += o.e.c_placed && o.e.rk_pending ? 1 : 0;
                jobs += o.e.job_ok ? 1 : 0;
                quiet += o.strikes == 0 && o.bans == 0 ? 1 : 0;
                refs_min = std::min(refs_min, o.refs);
                refs_max = std::max(refs_max, o.refs);
                points += o.inv_points;
                merged_back += o.merged_back;
                evaluated += o.evaluated;
                all.fold(o.eq);
            } while (std::next_permutation(prio.begin(), prio.end()));
        }
        std::printf("COUNT %s summary: %d runs (%d set up), %zu distinct reply sequences; replies delivered %zu (late %zu); runs "
                    "with all four replies %d, with a late reply %d; no reference under another identity after any frame %d "
                    "(%llu points); H held as its own at the end %d; k admitted (sa1, sa2 placed) %d; next honest carrier "
                    "placed and rk admitted %d; X's job builds %d; no strike and no ban %d; max held under another identity "
                    "%zu; refs at the end %zu..%zu; X's windows evaluated %llu, owner or author merged back %llu\n",
                    md.tag, runs, setups, seqs.size(), delivered, late, four, with_late, clean, (unsigned long long)points,
                    h_own, admitted, placed, jobs, quiet, max_bad, refs_min == SIZE_MAX ? 0 : refs_min, refs_max,
                    (unsigned long long)evaluated, (unsigned long long)merged_back);
        const bool all_ok = setups == runs && clean == runs && h_own == runs && admitted == runs && placed == runs &&
                            jobs == runs && quiet == runs;
        const std::string pred = "in every order and first sender no reference is held under another identity after any "
                                 "frame; H held as its own; k admitted; the next honest carrier and receipt admitted; X's job "
                                 "builds; no strike, no ban (" + std::to_string(runs) + " runs)";
        if (std::string(md.tag) == "R") {
            check(all_ok, "R the honest race: " + pred);
            check_eq("R", all, kEqR, "the reference-map digests of the 48 runs");
        } else if (std::string(md.tag) == "RA") {
            check(all_ok, "RA A's replies rewritten: " + pred);
        } else if (std::string(md.tag) == "RA2") {
            check(all_ok, "RA2 A's replies rewritten in a body that has an owner: " + pred);
        } else {
            check(all_ok, "RO A and L paying an owner fee: " + pred);
            check_eq("RO", all, kEqRO, "the reference-map digests of the 48 runs");
        }
    }
}

// ---------------------------------------------------------------------------
// J: the join path (in-process nodes, KatTransport). A mines six carriers (payee 1); a stale share of A (payee 5) is
// pending; A and B race cut apart: A mines s1 (payee 2, carrying the stale share) and s2 (payee 2); B mines three
// (payee 3) and wins at A; A's next carrier c (payee 4) carries s2's own receipt, whose tip s1 is a side carrier; A's
// next carrier Lt is the first body of payee 9 (HJ). A node with a failed store joins from A. The rewrite: A's reply to
// the FC_GETCARRIER of s1's body set names the target with K in its own body (payee or owner field). owner_fee: A and
// B pay the owner fee, A writes its store, and A's store is loaded once the chain is built.
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
constexpr std::size_t kHJPayee = 9;
enum class Rewrite { None, Payee, Owner, PayeeOwned };
struct JoinOut {
    bool setup = false;
    std::string why;
    bool completed = false;
    std::string rep;
    std::uint64_t rewritten = 0;
    std::string carrier_replies;   // own ids of the FC_GETCARRIER replies in order (s1 / Lt marked)
    bool walked = false;           // s1 (a side carrier) placed in the joined tree: its body set was used by the walk
    std::uint64_t pos_c = 0, pos_lt = 0, pos_first = 0;  // joined positions: c (the walk), Lt, the target's first body
    std::optional<pb::Hash32> hj;  // the identity held under the target after the adoption
    std::size_t bad = 0, refs = 0;            // the node's map after the adoption
    std::size_t bad_attempt = 0, refs_attempt = 0;  // the attempt's map before the adoption
    std::size_t bad_next = 0;                 // the node's map after the next carrier
    bool attempt_state = false;
    std::string k_attempt, k_after;
    pb::AdmitVerdict v = pb::AdmitVerdict::Defer;
    pb::RowId row = pb::RowId::None;
    std::optional<pb::Missing> missing;
    pb::NodeAction action = pb::NodeAction::None;
    bool placed = false;
    pb::TemplateStatus tst = pb::TemplateStatus::NoTemplate;
    bool job_ok = false;
    Chain eq;
    std::uint64_t steps = 0, step_bad = 0;
    // owner_fee: A's store loaded
    bool loaded = false;
    std::size_t load_refs = 0, load_bad = 0, side_loaded = 0;
    std::uint64_t merged_back = 0;
};
pb::LoadResult load_store(const KatNet& net, MemoryKv& kv, std::uint64_t J) {
    pb::LoadInputs in;
    in.T = kat_table(net);
    in.journal_depth = J;
    return pb::pathb_load(kv, net.pool_id, net.rules_g, in);
}
JoinOut join_case(Rewrite rw, std::size_t target, bool owner_fee) {
    JoinOut o;
    JoinNet net(900);
    Harness h(net);
    std::size_t a = 0, b = 0;
    MemoryKv* akv = nullptr;
    if (!owner_fee) {
        a = h.add(kat_table(net), true);
        b = h.add(kat_table(net), true);
    } else {
        pb::PathbNodeConfig cf = h.config(kat_table(net), true);
        cf.owner_fee_bp = kOwnerFeeBp;
        cf.owner = net.refs[kOwner];
        a = h.nodes.size();
        h.kvs.push_back(std::make_unique<MemoryKv>());
        akv = h.kvs.back().get();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cf, h.io(a), akv));
        b = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(cf, h.io(b)));
    }
    for (int i = 0; i < 6; ++i) {
        h.tick_monero();
        h.mine(a, 1, 10 + static_cast<std::uint32_t>(i));
    }
    const std::optional<pb::PathbJob> vj = h.job(a, 5, 50);
    h.mine(a, 1, 16);
    const bool vpend = vj && h[a].on_own_share(*vj, 50, pb::Hash32{}).action == pb::NodeAction::Pending;
    h.pump();
    h.cut = {{a, b}, {b, a}};
    h.tick_monero();
    h.mine(a, 2, 900);
    const pb::Hash32 s1 = h[a].tree().best().id;
    h.tick_monero();
    h.mine(a, 2, 901);
    const pb::Hash32 s2 = h[a].tree().best().id;
    std::vector<pb::Hash32> bb;
    for (int i = 0; i < 3; ++i) {
        h.tick_monero();
        h.mine(b, 3, 950 + static_cast<std::uint32_t>(i));
        bb.push_back(h[b].tree().best().id);
    }
    h.cut.clear();
    h.q.clear();
    for (const pb::Hash32& id : bb) (void)h[a].on_carrier(b, fc(*h[b].bodies().get(id)));
    h.pump();
    h.tick_monero();
    h.mine(a, 4, 77);
    const pb::Hash32 c = h[a].tree().best().id;
    h.tick_monero();
    h.mine(a, kHJPayee, 78);
    const pb::Hash32 lt = h[a].tree().best().id;
    h.q.clear();
    const pb::Hash32 HJ = pb::key_ref_identity(net.refs[target]);
    const pb::XmrKeyRef K = net.refs[kKPayee];
    bool carries = false;
    if (const pb::CarrierBodyV3* cb = h[a].bodies().get(c))
        for (const pb::ReceiptBodyV3& r : cb->carried) carries = carries || (pb::receipt_id(r) == s2 && r.side.tip == s1);
    const pb::CarrierBodyV3* s1b = h[a].bodies().get(s1);
    const pb::CarrierBodyV3* ltb = h[a].bodies().get(lt);
    // the target's first body on A's best chain (its position; for payee 9 it must be Lt's own)
    for (pb::Hash32 t = lt; h[a].tree().find(t) != nullptr && h[a].tree().find(t)->pos > 0; t = h[a].tree().find(t)->parent) {
        const pb::CarrierBodyV3* cb = h[a].bodies().get(t);
        if (cb == nullptr) break;
        bool names = cb->own.side.payee == HJ;
        for (const pb::ReceiptBodyV3& r : cb->carried) names = names || r.side.payee == HJ;
        if (names) o.pos_first = h[a].tree().find(t)->pos;
    }
    const bool hj_first = target != kHJPayee || (ltb != nullptr && ltb->own.side.payee == HJ && o.pos_first == h[a].tree().find(lt)->pos);
    o.setup = vpend && h[a].tree().best().id == lt && h[a].tree().find(s1) != nullptr && carries && s1b != nullptr &&
              !s1b->carried.empty() && hj_first && o.pos_first > 0;
    if (!o.setup) {
        o.why = "pending " + std::to_string(vpend) + ", c carries s2 on s1 " + std::to_string(carries) + ", s1 carries " +
                std::to_string(s1b ? s1b->carried.size() : 0) + ", HJ first at Lt " + std::to_string(hj_first);
        return o;
    }
    o.merged_back = h[a].window_flags().merged_back;
    if (akv != nullptr) {
        // A's store: K_PSIDE rows for s1 and s2; loaded (a restart)
        o.eq.add(kv_digest(*akv));
        MemoryKv kv = *akv;
        const pb::LoadResult lr = load_store(net, kv, 1152);
        o.loaded = lr.fault == pb::StoreFault::None && lr.state.has_value();
        if (o.loaded) {
            o.load_refs = lr.state->refs.size();
            o.load_bad = mismatched(lr.state->refs);
            o.side_loaded = lr.state->side_loaded;
            o.eq.add(lr.state->refs);
        }
    }
    Joining k = joining_node(h, net, 1152);
    std::vector<std::string> order;
    k.tr->edit = [&](std::uint64_t, std::uint8_t op, std::vector<std::vector<std::uint8_t>>& reply) {
        if (op != pb::kOpFcGetCarrier) return;
        for (std::vector<std::uint8_t>& f : reply) {
            const std::optional<pb::CarrierBodyV3> cb = decode_cf(f);
            if (!cb) continue;
            const pb::Hash32 id = pb::receipt_id(cb->own);
            if (id == s1) {
                order.push_back("s1");
                if (rw != Rewrite::None) {
                    f = rw == Rewrite::Owner ? rewrite_owner(f, HJ, K) : rewrite_payee(f, HJ, K, rw == Rewrite::PayeeOwned);
                    ++o.rewritten;
                }
            } else if (id == lt) {
                order.push_back("Lt");
            }
        }
    };
    // EQ and INV on the attempt's map: at every step of the replay and at every request once a step ran
    pb::JoinedState* js_seen = nullptr;
    pb::PathbNodeTestAccess::on_join_step(h[k.j], [&](pb::JoinedState& js, std::uint64_t) {
        js_seen = &js;
        ++o.steps;
        o.step_bad += mismatched(js.refs) == 0 ? 0 : 1;
        o.eq.add(js.refs);
    });
    k.tr->on_request = [&] {
        if (js_seen == nullptr) return;
        ++o.steps;
        o.step_bad += mismatched(js_seen->refs) == 0 ? 0 : 1;
        o.eq.add(js_seen->refs);
    };
    h.hello(k.j, a);
    pb::JoinAttempted ta = h[k.j].attempt_join();
    k.tr->on_request = nullptr;
    pb::PathbNodeTestAccess::on_join_step(h[k.j], nullptr);
    if (ta.attempt && ta.attempt->report.state) {
        const RefMap& m = ta.attempt->report.state->refs;
        o.attempt_state = true;
        o.refs_attempt = m.size();
        o.bad_attempt = mismatched(m);
        o.k_attempt = k_status(m, K);
        o.eq.add(m);
    }
    const pb::JoinStep st = h[k.j].apply_join(std::move(ta));
    h.q.clear();
    k.tr->edit = nullptr;
    for (const std::string& x : order) o.carrier_replies += x + " ";
    o.walked = h[k.j].tree().find(s1) != nullptr;
    if (const pb::CarrierNode* n = h[k.j].tree().find(c)) o.pos_c = n->pos;
    if (const pb::CarrierNode* n = h[k.j].tree().find(lt)) o.pos_lt = n->pos;
    o.rep = st.report ? rep_desc(*st.report) : std::string("no attempt");
    o.completed = st.report && st.report->end == pb::AttemptEnd::Completed && st.switched && h[k.j].tree().best().id == lt;
    o.hj = held_identity(h[k.j], HJ);
    o.bad = mismatched_refs(h[k.j]);
    o.refs = refs_held(h[k.j]);
    o.k_after = k_status(refs_of(h[k.j]), K);
    o.eq.add(refs_of(h[k.j]));
    // after the adoption: A's next carrier on Lt (a window holding HJ, a key set the joined state never computed)
    h.tick_monero();
    (void)h.mine(a, 1, 79, false);
    const pb::Hash32 c1 = h[a].tree().best().id;
    h.q.clear();
    const pb::NodeEventResult r1 = h[k.j].on_carrier(a, fc(*h[a].bodies().get(c1)));
    h.q.clear();
    o.bad_next = mismatched_refs(h[k.j]);
    o.eq.add(refs_of(h[k.j]));
    o.action = r1.action;
    o.v = r1.admit.verdict;
    o.row = r1.admit.row;
    o.missing = r1.admit.missing;
    o.placed = h[k.j].tree().find(c1) != nullptr;
    const pb::PathbTemplate t = h[k.j].make_template(h.now);
    o.tst = t.status;
    o.job_ok = h[k.j].make_job(t, h.session(11, 5)).has_value();
    return o;
}
void section_j() {
    std::printf("== J: the join path; JC, JCO: no rewrite (JCO: an owner fee, A's store loaded) ==\n");
    const JoinNet net0(900);
    const pb::Hash32 KJ = pb::key_ref_identity(net0.refs[kKPayee]);
    struct Case {
        const char* tag;
        Rewrite rw;
        std::size_t target;
        bool owner_fee;
    };
    for (const Case cs : {Case{"JC", Rewrite::None, kHJPayee, false}, Case{"J", Rewrite::Payee, kHJPayee, false},
                          Case{"J1", Rewrite::Payee, 1, false}, Case{"JO", Rewrite::Owner, kHJPayee, false},
                          Case{"J2", Rewrite::PayeeOwned, kHJPayee, false},
                          Case{"JCO", Rewrite::None, kHJPayee, true}}) {
        const JoinOut o = join_case(cs.rw, cs.target, cs.owner_fee);
        const pb::Hash32 T = pb::key_ref_identity(net0.refs[cs.target]);
        const std::string tag = cs.tag;
        if (!o.setup) {
            check(false, tag + " setup: " + o.why);
            continue;
        }
        std::printf("COUNT %s target payee %zu (first body at position %llu): attempt %s; FC_GETCARRIER replies [%s], "
                    "rewritten %llu; s1 walked (placed in the joined tree) %d; joined positions: c (the walk) %llu, Lt %llu; "
                    "completed and adopted at Lt %d; refs %zu, held under another identity %zu; target held as %s; A's next "
                    "carrier at the joined node: action %d verdict %d row %d missing %d, placed %d; template %s, job %s\n",
                    cs.tag, cs.target, (unsigned long long)o.pos_first, o.rep.c_str(), o.carrier_replies.c_str(),
                    (unsigned long long)o.rewritten, o.walked, (unsigned long long)o.pos_c, (unsigned long long)o.pos_lt,
                    o.completed, o.refs, o.bad, idname(o.hj, T, KJ).c_str(), static_cast<int>(o.action),
                    static_cast<int>(o.v), static_cast<int>(o.row), o.missing ? static_cast<int>(*o.missing) : -1, o.placed,
                    tstatus(o.tst), o.job_ok ? "builds" : "FAILS (none)");
        std::printf("COUNT %s INV: the attempt's map before the adoption: %d, refs %zu, under another identity %zu, K %s; join "
                    "steps and requests %llu (with a reference under another identity %llu); the node's map after the "
                    "adoption: under another identity %zu, K %s; after the next carrier %zu; EQ %s (%llu)\n",
                    cs.tag, o.attempt_state, o.refs_attempt, o.bad_attempt, o.k_attempt.c_str(), (unsigned long long)o.steps,
                    (unsigned long long)o.step_bad, o.bad, o.k_after.c_str(), o.bad_next, h8(o.eq.acc).c_str(),
                    (unsigned long long)o.eq.points);
        const bool inv = o.attempt_state && o.bad_attempt == 0 && o.step_bad == 0 && o.bad == 0 && o.bad_next == 0 &&
                         o.k_attempt != "under another identity" && o.k_after != "under another identity";
        if (cs.rw == Rewrite::None) {
            check(o.completed && o.walked && o.hj && *o.hj == T && o.bad == 0 && o.placed && o.job_ok,
                  tag + " the join completes (s1 walked); HJ held as its own; the next honest carrier is placed; the job "
                        "builds");
            check(inv, tag + " INV: the attempt's map before the adoption, at every step and request, and the node's map "
                             "after it: every key is its reference's identity");
            if (cs.owner_fee) {
                std::printf("COUNT JCO A's store loaded %d: refs %zu, under another identity %zu; side carriers placed %zu; "
                            "A's windows: owner or author merged back %llu\n",
                            o.loaded, o.load_refs, o.load_bad, o.side_loaded, (unsigned long long)o.merged_back);
                check(o.loaded && o.load_bad == 0 && o.side_loaded == 2,
                      "JCO A's store (an owner fee; s1 and s2 in K_PSIDE) loads; every key of LoadedState::refs is its "
                      "reference's identity");
                check_eq("JCO", o.eq, kEqJCO, "A's store, its load and the join's reference-map digests");
            } else {
                check_eq("JC", o.eq, kEqJC, "the join's reference-map digests");
            }
        } else if (cs.target == kHJPayee) {
            check(o.completed && o.walked && o.rewritten >= 1 && o.pos_c < o.pos_lt && o.pos_first == o.pos_lt && o.hj &&
                          *o.hj == T,
                  tag + " the server's s1 body set (the walk at c, below HJ's first honest body at Lt) names HJ with K; the "
                        "attempt completes; HJ held under its own identity after the adoption");
            check(o.placed && o.tst == pb::TemplateStatus::Ok && o.job_ok,
                  tag + " after the adoption: the next honest carrier is placed; the joined node's job builds");
            check(inv, tag + " INV: the attempt's map before the adoption, at every step and request, and the node's map "
                             "after it: every key is its reference's identity (K absent or under its own)");
        } else {
            check(o.completed && o.walked && o.rewritten >= 1 && o.pos_first < o.pos_c && o.hj && *o.hj == T && o.bad == 0 &&
                          o.placed && o.job_ok,
                  tag + " the same rewrite aimed at payee 1 (its honest body replayed first, below the walk): HJ held as "
                        "its own; the next carrier is placed; the job builds");
            check(inv, tag + " INV: the attempt's map before the adoption, at every step and request, and the node's map "
                             "after it: every key is its reference's identity (K absent or under its own)");
        }
    }
}

// ---------------------------------------------------------------------------
// S: a scaffold store (pathb_kat_store.hpp) with an owner fee on four bodies: 40 carriers (own payees 0..9 in turn);
// a side carrier sc on position 35 (own payee kScPayee, owner kScOwner) carrying one receipt (payee kScrPayee, owner
// kScrOwner), in K_PSIDE; the best chain's tip at position 41 (own payee kTipPayee, owner kTipOwner). Each of these
// identities is in one body only. A tampered copy of the store replaces one stored reference by K (side data
// unchanged); the store is loaded.
constexpr std::size_t kTipPayee = 10, kTipOwner = 11, kScPayee = 12, kScOwner = 13, kScrPayee = 14, kScrOwner = 15;
constexpr std::size_t kSK = 16;  // K of section S

void with_owner(const KatNet& net, pb::ReceiptBodyV3& r, std::size_t owner) {
    r.side.fee_rate_bp = kOwnerFeeBp;
    r.side.owner = net.ids[owner];
    r.owner = net.refs[owner];
}
// The stored body under `key` (K_PSIDE when `side`, else K_PCARRIER): its own body, or its first carried body; its
// payee or owner reference set to K.
bool tamper(MemoryKv& kv, const std::string& key, bool side, bool own, bool owner, const pb::XmrKeyRef& K) {
    const auto it = kv.data.find(key);
    if (it == kv.data.end()) return false;
    std::optional<pb::CarrierRecord> c = side ? pb::decode_pside(it->second) : pb::decode_pcarrier(it->second);
    if (!c) return false;
    std::optional<pb::CarrierBodyV3> b = pb::record_body(*c, pb::kRuledLaneParams);
    if (!b || (!own && b->carried.empty())) return false;
    pb::ReceiptBodyV3& r = own ? b->own : b->carried[0];
    if (owner) {
        if (!r.owner) return false;
        r.owner = K;
    } else {
        r.payee = K;
    }
    c->bytes.clear();
    if (pb::encode_carrier_body_v3(*b, pb::kRuledLaneParams.r_max, c->bytes) != pb::WireError::None) return false;
    it->second = side ? pb::encode_pside(*c) : pb::encode_pcarrier(*c);
    return true;
}
void section_s() {
    std::printf("== S: a stored body with its payee or owner reference replaced, loaded ==\n");
    const KatNet net;
    KatStoreNode sn(net, 64);
    KatNode& n = sn.n;
    bool ok = true;
    for (std::uint64_t i = 0; i < 40 && ok; ++i) {
        const pb::CarrierNode& best = n.tree.best();
        const std::uint64_t x = best.pos + 1;
        ok = sn.place(scaffold_carrier(n, best.id, h_pos(x), 0x5c, x, i % 10, {})).outcome == pb::WriteOutcome::Extended;
    }
    // the side carrier sc on position 35, carrying a receipt on position 34
    const std::optional<pb::Hash32> fork = n.store.best_at(35), rtip = n.store.best_at(34);
    pb::Hash32 sid{};
    if (ok && fork && rtip) {
        pb::ReceiptBodyV3 r = scaffold_receipt(n, *rtip, n.tree.find(*rtip)->h, kScrPayee, 0x5d0001);
        with_owner(net, r, kScrOwner);
        pb::CarrierBodyV3 sc = scaffold_carrier(n, *fork, h_pos(36), 0x5d, 50036, kScPayee, {r});
        with_owner(net, sc.own, kScOwner);
        sid = pb::receipt_id(sc.own);
        ok = place_direct(n, sc).outcome == pb::WriteOutcome::SideBranch;
        pb::LaneBatch lb;
        ok = ok && pb::put_side(lb, 0, n.tree, n.store, n.bodies, sid) && pb::commit_lane_batch(sn.kv, lb);
    } else {
        ok = false;
    }
    // the tip on position 41
    std::uint64_t tip = 0;
    if (ok) {
        const pb::CarrierNode& best = n.tree.best();
        tip = best.pos + 1;
        pb::CarrierBodyV3 tc = scaffold_carrier(n, best.id, h_pos(tip), 0x5c, tip, kTipPayee, {});
        with_owner(net, tc.own, kTipOwner);
        ok = sn.place(tc).outcome == pb::WriteOutcome::Extended && !sn.poisoned;
    }
    check(ok && tip == 41, "S setup: 40 carriers, the side carrier sc on position 35 in K_PSIDE, the tip at position 41");
    if (!ok) return;
    const pb::XmrKeyRef K = net.refs[kSK];
    // the clean store: every identity of the six fields held under its own identity
    {
        MemoryKv kv = sn.kv;
        const pb::LoadResult r = load_store(net, kv, 64);
        const bool loaded = r.fault == pb::StoreFault::None && r.state.has_value();
        std::size_t own = 0;
        Chain eq;
        eq.add(kv_digest(sn.kv));
        if (loaded) {
            for (const std::size_t i : {kTipPayee, kTipOwner, kScPayee, kScOwner, kScrPayee, kScrOwner})
                own += held_in(r.state->refs, net.ids[i]) == std::optional<pb::Hash32>(net.ids[i]) ? 1 : 0;
            eq.add(r.state->refs);
        }
        std::printf("COUNT S0 the clean store: load %d; refs %zu, under another identity %zu; side carriers placed %zu; the six "
                    "identities held as their own %zu\n",
                    loaded, loaded ? r.state->refs.size() : 0, loaded ? mismatched(r.state->refs) : 0,
                    loaded ? r.state->side_loaded : 0, own);
        check(loaded && mismatched(r.state->refs) == 0 && r.state->side_loaded == 1 && own == 6,
              "S0 the clean store loads; sc placed from K_PSIDE; the tip's, sc's and its receipt's payee and owner held "
              "under their own identities");
        check_eq("S0", eq, kEqS0, "the clean store and its LoadedState::refs");
    }
    struct Case {
        const char* tag;
        bool side;
        bool own;
        bool owner;
        std::size_t field;
    };
    for (const Case cs : {Case{"S-best (the tip's own body, payee)", false, true, false, kTipPayee},
                          Case{"S-side (sc's own body, payee)", true, true, false, kScPayee},
                          Case{"S-side (sc's carried body, payee)", true, false, false, kScrPayee},
                          Case{"S-owner (the tip's own body, owner)", false, true, true, kTipOwner},
                          Case{"S-owner (sc's own body, owner)", true, true, true, kScOwner},
                          Case{"S-owner (sc's carried body, owner)", true, false, true, kScrOwner}}) {
        MemoryKv kv = sn.kv;
        const std::string key = cs.side ? pb::store_keys::pside(0, sid) : pb::store_keys::pcarrier(0, tip);
        const bool t = tamper(kv, key, cs.side, cs.own, cs.owner, K);
        const pb::LoadResult r = load_store(net, kv, 64);
        const bool loaded = r.fault == pb::StoreFault::None && r.state.has_value();
        const pb::Hash32 H = net.ids[cs.field];
        const std::optional<pb::Hash32> held = loaded ? held_in(r.state->refs, H) : std::nullopt;
        const std::string held_as = !loaded ? "-"
                                    : !held ? "absent"
                                    : *held == H ? "its own identity"
                                    : *held == pb::key_ref_identity(K) ? "K's identity"
                                                                        : h8(*held);
        std::printf("COUNT %s: tampered %d; load %d (fault %d); refs %zu, under another identity %zu; H held as %s; K %s; side "
                    "carriers placed %zu\n",
                    cs.tag, t, loaded, static_cast<int>(r.fault), loaded ? r.state->refs.size() : 0,
                    loaded ? mismatched(r.state->refs) : 0, held_as.c_str(),
                    loaded ? k_status(r.state->refs, K).c_str() : "-", loaded ? r.state->side_loaded : 0);
        check(t && loaded && (!cs.side || r.state->side_loaded == 1) && mismatched(r.state->refs) == 0 && (!held || *held == H),
              std::string(cs.tag) + ": the load stands; INV on LoadedState::refs: every key is its reference's identity "
                                    "(H absent or its own; K absent or under its own)");
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_ref_identity_kat\n");
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*fn)()) {
        if (only.empty() || only == name) run_part(name, fn);
    };
    run("p", section_p);
    run("o", section_o);
    run("r", section_r);
    run("j", section_j);
    run("s", section_s);
    return finish("v37_xmr_pathb_ref_identity_kat");
}
