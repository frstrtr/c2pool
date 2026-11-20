// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_relay.hpp
// Helpers for the relay KATs: relay nodes in manual mode on the harness's
// clock over links delivered by hand (no socket), one frame per step; the
// adoption step (a node with parked objects adopts a served chain through the
// relay's join step).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
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

#include "c2pool/v37/xmr/pathb/pathb_relay_node.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_kat_store.hpp"

namespace pathb_kat {

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
    // Observers (unset: none): a frame a relay queued (under qm); a frame at its step, as edited, before it is handed to
    // its link (`before`) and after every relay ran what it queued (`op` is its opcode before the edit; 0: none).
    std::function<void(const Msg&)> on_send;
    std::function<void(const Msg& m, std::uint8_t op, bool before)> on_step;
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
        const std::uint8_t op = m.f.empty() ? 0 : m.f[0];
        if (edit) edit(m);
        if (on_step) on_step(m, op, true);
        if (!m.f.empty() && links[m.to]->live.count(id(m.to, m.from)) != 0) links[m.to]->frame(id(m.to, m.from), m.f);
        for (pb::PathbRelayNode* r : relays) r->pump();
        if (on_step) on_step(m, op, false);
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

inline bool FakeLinks::send_to(std::uint64_t p, const std::vector<std::uint8_t>& f) {
    if (live.count(p) == 0) return false;
    if (full_next) {
        full_next = false;
        ++full_drops;
        disconnect(p);
        return false;
    }
    const std::lock_guard<std::mutex> lk(wire->qm);
    wire->q.push_back(FakeWire::Msg{self, FakeWire::node_of(p), f});
    if (wire->on_send) wire->on_send(wire->q.back());
    return true;
}
inline void FakeLinks::disconnect(std::uint64_t p) {
    if (live.erase(p) == 0) return;
    FakeLinks& o = *wire->links[FakeWire::node_of(p)];
    const std::uint64_t back = wire->id(o.self, self);
    o.live.erase(back);
    event(p, false);
    o.event(back, false);
}

// The relays' log lines by node, while a vector sets it (kat_relay's log sink).
inline std::map<std::size_t, std::vector<std::string>>* g_relay_lines = nullptr;

struct KatRelay {
    std::unique_ptr<FakeLinks> links;
    std::unique_ptr<pb::PathbRelayNode> relay;
    std::size_t node = 0;
};

// A relay node in manual mode on the harness's clock with its own PathbNode (a load failure when `failed`;
// `tweak`: its options changed; `cfg_tweak`: its node's configuration; `io_tweak`: its node's I/O; `persist`: an empty
// store of its own in h.kvs; `make`: its node built by the caller from the configuration and the relay's I/O).
inline KatRelay kat_relay(Harness& h, FakeWire& w, const pb::EpochTable& T, bool launch, bool failed = false,
                   const std::function<void(pb::PathbRelayOptions&)>& tweak = nullptr,
                   const std::function<void(pb::PathbNodeConfig&)>& cfg_tweak = nullptr,
                   const std::function<void(pb::PathbNodeIo&)>& io_tweak = nullptr, bool persist = false,
                   const std::function<std::unique_ptr<pb::PathbNode>(const pb::PathbNodeConfig&, pb::PathbNodeIo)>& make =
                           nullptr) {
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
    if (make) {
        h.nodes.push_back(make(cfg, std::move(io)));
    } else if (failed) {
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
// The adoption step: node v adopts the chain of server s through the relay's own join step, with what v has parked
// kept in place. The caller runs the relays in manual mode (threads = false) and has parked at v the objects the step
// carries (receipts DEFERred TipUnknown on a tip t that no state of v holds, from a peer that cannot serve t). v has no
// own chain (a load failure), so a completed attempt is an adoption; s's chain holds t. The step: v connects s (s's
// HELLO tip becomes v's join candidate, s its server); then the relay's join step (the attempt, PathbNode::apply_join,
// its adopt) runs until the node switched, at most `max_steps` times. A completed attempt ends after its L. `act` runs
// one scripted action and then the wire; `note` (if set) sees each join step's result inside that action.
struct AdoptStep {
    std::size_t parked_before = 0;                 // v's parked receipts before the join
    std::uint64_t adopted_before = 0;              // v's node: its joiner_adopted count before the join
    std::vector<std::optional<pb::JoinStep>> all;  // every join step's result, in order
    // the last join step's result (none run: nullopt)
    const std::optional<pb::JoinStep>& last() const {
        static const std::optional<pb::JoinStep> none;
        return all.empty() ? none : all.back();
    }
    bool switched() const { return last() && last()->switched; }
};
inline AdoptStep adopt_step(FakeWire& w, KatRelay& v, pb::PathbNode& vn, std::size_t s, int max_steps,
                            const std::function<void(const std::string&, const std::function<void()>&)>& act,
                            const std::function<void(const std::optional<pb::JoinStep>&)>& note = nullptr) {
    AdoptStep out;
    out.parked_before = v.relay->parked_receipts();
    out.adopted_before = vn.switch_counts().joiner_adopted;
    act("connect " + std::to_string(v.node) + "-" + std::to_string(s), [&] { w.connect(v.node, s); });
    while (static_cast<int>(out.all.size()) < max_steps && !out.switched()) {
        std::optional<pb::JoinStep> st;
        act("join step " + std::to_string(v.node), [&] {
            st = v.relay->join_step();
            if (note) note(st);
        });
        out.all.push_back(std::move(st));
    }
    return out;
}

}  // namespace pathb_kat
