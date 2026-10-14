// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_follow_template.hpp
// --follow-only, the node side (inputs and time are the caller's callbacks;
// nothing here reads a clock):
//   follow_template_record  at most one record per call:
//     1 readiness of the source snapshot (else none: pool-cold, or
//       not-ready:<the source's reason>)
//     2 P_r = the follower's main tip M, h = M + 1
//     3 hf for a child of P_r; amount_fork_fused(hf) -> none: fork-fuse
//     4 B(P_r), Z(P_r) = weights_at(P_r) (else none: missing-weights)
//     5 the candidates of the ready snapshot, in the source's order
//     6 cw(R) = the coinbase size of ONE output of R at h
//     7 select_template (the selection PathbNode::make_template runs; else
//       none: no-fit)
//   the log lines:
//     c2pool-v37-xmr: FOLLOW-ONLY network= pool=none stratum=off relay=off
//       mine=off monerod=none snapshot=
//     [follow-only] follow h= id= prev= event=extend|reorg|orphan depth= tip=
//     [follow-only] template h= prev= hf= n_tx= tx_weight= fees= reward=
//       cb_size= block_weight= zone= base= pool= warm= uptime_s= txset=
//       log-only   (one line; txset = sha256d of the selected ids in order)
//     [follow-only] template h= none reason=pool-cold|not-ready:<why>|
//       missing-weights|fork-fuse hf=<n>|no-fit
//     [follow-only] compare h= net_id= net_n_tx= net_tx_weight= our_n_tx=
//       our_tx_weight= common=   (when the network's block at h connects)
//   serve_follow_only  the loop: follower pump -> at a new main tip or a
//     backlog refresh the record routine -> the shared status lines -> web
//     status. The record is handed to nothing.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "impl/xmr/pathb/pathb_branch.hpp"    // WeightInputs
#include "impl/xmr/pathb/pathb_emission.hpp"  // amount_fork_fused
#include "impl/xmr/pathb/pathb_params.hpp"

#include "c2pool/v37/xmr/pathb/pathb_status.hpp"
#include "c2pool/v37/xmr/pathb/pathb_template_select.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------
// The source snapshot's readiness: ok; not ready with the tx pool not warm
// (pool_cold); or not ready for the source's reason `why`.
struct FollowReadiness {
    bool ok = false;
    bool pool_cold = false;
    std::string why;
};

// The follower's main tip.
struct FollowTip {
    std::uint64_t height = 0;
    Hash32 id{};
    Hash32 prev{};
};

struct FollowTemplateIo {
    std::function<FollowReadiness()> readiness;
    std::function<std::optional<FollowTip>()> main_tip;
    // the major version of a child of P_r
    std::function<std::optional<std::uint8_t>(const Hash32& p_r)> hf_for_child;
    std::function<std::optional<WeightInputs>(const Hash32& p_r)> weights_at;
    // the ready snapshot's transactions, in the source's priority order
    std::function<std::vector<TemplateTx>()> candidates;
};

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------
enum class FollowNone : std::uint8_t { Record = 0, PoolCold, NotReady, MissingWeights, ForkFuse, NoFit };

struct FollowRecord {
    FollowNone none = FollowNone::NotReady;
    std::string why;            // NotReady: the source's reason
    bool h_known = false;
    std::uint64_t h = 0;        // M + 1
    Hash32 p_r{};               // M
    std::uint8_t hf = 0;
    std::uint64_t base = 0;     // B(P_r)
    std::uint64_t zone = 0;     // Z(P_r)
    TxSelection sel;            // T, F, R, c
    std::vector<TemplateTx> txs;  // the selected transactions, in selection order

    bool ok() const noexcept { return none == FollowNone::Record; }
};

inline FollowRecord follow_template_record(const FollowTemplateIo& io, bool penalty_fill) {
    FollowRecord r;
    const std::optional<FollowTip> m = io.main_tip ? io.main_tip() : std::nullopt;
    if (m) {
        r.h_known = true;
        r.h = m->height + 1;
    }
    // 1 readiness
    const FollowReadiness rd = io.readiness ? io.readiness() : FollowReadiness{};
    if (!rd.ok) {
        r.none = rd.pool_cold ? FollowNone::PoolCold : FollowNone::NotReady;
        r.why = rd.why;
        return r;
    }
    if (!m) {
        r.none = FollowNone::NotReady;
        r.why = "no-tip";
        return r;
    }
    // 2 the parent: the Monero tip
    r.p_r = m->id;
    r.h = m->height + 1;
    // 3 FORK-FUSE
    const std::optional<std::uint8_t> hf = io.hf_for_child ? io.hf_for_child(r.p_r) : std::nullopt;
    if (!hf) {
        r.none = FollowNone::NotReady;
        r.why = "hf";
        return r;
    }
    r.hf = *hf;
    if (amount_fork_fused(r.hf)) {
        r.none = FollowNone::ForkFuse;
        return r;
    }
    // 4 the reward inputs at P_r
    const std::optional<WeightInputs> wi = io.weights_at ? io.weights_at(r.p_r) : std::nullopt;
    if (!wi) {
        r.none = FollowNone::MissingWeights;
        return r;
    }
    r.base = wi->base_reward;
    r.zone = wi->zone;
    // 5 the candidates
    const std::vector<TemplateTx> cands = io.candidates ? io.candidates() : std::vector<TemplateTx>{};
    // 6, 7 one output of R at h; the selection
    r.sel = select_template(cands, r.base, r.zone, r.hf, r.h, nullptr, penalty_fill);
    if (!r.sel.ok) {
        r.none = FollowNone::NoFit;
        return r;
    }
    for (const std::size_t i : r.sel.picked) r.txs.push_back(cands[i]);
    r.none = FollowNone::Record;
    return r;
}

// sha256d of the ids, 32 B each, in order.
inline Hash32 follow_txset(const std::vector<TemplateTx>& txs) {
    std::vector<std::uint8_t> b;
    b.reserve(txs.size() * kHashBytes);
    for (const TemplateTx& t : txs) b.insert(b.end(), t.hash.begin(), t.hash.end());
    return ::v37::sha256d(b);
}

// ---------------------------------------------------------------------------
// Log lines
// ---------------------------------------------------------------------------
inline constexpr std::string_view kFollowOnlyTag = "[follow-only] ";

inline std::string follow_hex(const Hash32& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(2 * h.size());
    for (const std::uint8_t b : h) {
        s.push_back(kHex[b >> 4]);
        s.push_back(kHex[b & 0x0f]);
    }
    return s;
}

inline std::string follow_only_start_line(std::string_view network, std::string_view snapshot_dir) {
    return "c2pool-v37-xmr: FOLLOW-ONLY network=" + std::string(network) +
           " pool=none stratum=off relay=off mine=off monerod=none snapshot=" + std::string(snapshot_dir);
}

enum class FollowEventKind : std::uint8_t { Extend, Reorg, Orphan };

inline const char* to_string(FollowEventKind k) noexcept {
    return k == FollowEventKind::Reorg ? "reorg" : k == FollowEventKind::Orphan ? "orphan" : "extend";
}

// A follower tip event; for Extend / Reorg the block that connected at
// `height`, with its transactions.
struct FollowEvent {
    FollowEventKind kind = FollowEventKind::Extend;
    std::uint64_t height = 0;
    Hash32 id{};
    Hash32 prev{};
    std::uint64_t depth = 0;
    std::uint64_t tip = 0;  // the main tip's height after the event
    std::vector<Hash32> tx_ids;
    std::uint64_t tx_weight = 0;
};

inline std::string follow_line(const FollowEvent& e) {
    return std::string(kFollowOnlyTag) + "follow h=" + std::to_string(e.height) + " id=" + follow_hex(e.id) +
           " prev=" + follow_hex(e.prev) + " event=" + to_string(e.kind) + " depth=" + std::to_string(e.depth) +
           " tip=" + std::to_string(e.tip);
}

// The log-only values of a template line.
struct FollowLogValues {
    std::uint64_t pool = 0;  // the native pool's transaction count
    std::string warm;        // the warm latch's reason: complement / timeout
    std::uint64_t uptime_s = 0;
};

inline std::string follow_none_reason(const FollowRecord& r) {
    switch (r.none) {
        case FollowNone::PoolCold: return "pool-cold";
        case FollowNone::NotReady: return "not-ready:" + r.why;
        case FollowNone::MissingWeights: return "missing-weights";
        case FollowNone::ForkFuse: return "fork-fuse hf=" + std::to_string(r.hf);
        case FollowNone::NoFit: return "no-fit";
        case FollowNone::Record: break;
    }
    return {};
}

// The record's line, or its none line.
inline std::string template_line(const FollowRecord& r, const FollowLogValues& v) {
    const std::string h = r.h_known ? std::to_string(r.h) : std::string("-");
    if (!r.ok()) return std::string(kFollowOnlyTag) + "template h=" + h + " none reason=" + follow_none_reason(r);
    const std::uint64_t T = r.sel.T, c = r.sel.coinbase;
    return std::string(kFollowOnlyTag) + "template h=" + h + " prev=" + follow_hex(r.p_r) +
           " hf=" + std::to_string(r.hf) + " n_tx=" + std::to_string(r.txs.size()) + " tx_weight=" + std::to_string(T) +
           " fees=" + std::to_string(r.sel.F) + " reward=" + std::to_string(r.sel.reward) + " cb_size=" + std::to_string(c) +
           " block_weight=" + std::to_string(T + c) + " zone=" + std::to_string(r.zone) + " base=" + std::to_string(r.base) +
           " pool=" + std::to_string(v.pool) + " warm=" + (v.warm.empty() ? std::string("-") : v.warm) +
           " uptime_s=" + std::to_string(v.uptime_s) + " txset=" + follow_hex(follow_txset(r.txs)) + " log-only";
}

// The network's block at height h against our last record for h.
inline std::string compare_line(const FollowEvent& block, const FollowRecord& ours) {
    std::set<Hash32> net(block.tx_ids.begin(), block.tx_ids.end());
    std::uint64_t common = 0;
    for (const TemplateTx& t : ours.txs) common += net.count(t.hash);
    return std::string(kFollowOnlyTag) + "compare h=" + std::to_string(block.height) + " net_id=" + follow_hex(block.id) +
           " net_n_tx=" + std::to_string(block.tx_ids.size()) + " net_tx_weight=" + std::to_string(block.tx_weight) +
           " our_n_tx=" + std::to_string(ours.txs.size()) + " our_tx_weight=" + std::to_string(ours.sel.T) +
           " common=" + std::to_string(common);
}

// ---------------------------------------------------------------------------
// serve_follow_only
// ---------------------------------------------------------------------------
struct FollowOnlyIo {
    std::function<std::vector<FollowEvent>()> pump;   // the follower's events since the last pump
    std::function<std::uint64_t()> backlog_version;   // the source's backlog version
    FollowTemplateIo tmpl;
    std::function<FollowLogValues()> log_values;
    std::function<KeptStatusValues()> status_values;
    std::function<void(const std::string&)> out;      // one log line
    std::function<void(const std::vector<std::string>&)> web;  // the web status
    std::function<std::uint64_t()> now_s;             // the caller's clock
    std::function<void()> idle;                       // between passes
    std::function<bool()> stop;
};

struct FollowOnlyOptions {
    bool penalty_fill = false;        // --pathb-penalty-fill
    std::uint64_t status_every_s = 30;  // 0: no status lines
};

struct FollowOnlyState {
    bool have_tip = false;
    Hash32 last_tip{};
    bool have_backlog = false;
    std::uint64_t last_backlog = 0;
    std::map<std::uint64_t, FollowRecord> ours;  // the last record per template height
    std::uint64_t next_status_s = 0;
    std::uint64_t passes = 0;
    std::uint64_t records = 0;
    std::uint64_t nones = 0;
    std::uint64_t compares = 0;
};

inline void follow_only_pass(FollowOnlyIo& io, const FollowOnlyOptions& o, FollowOnlyState& st) {
    const auto out = [&io](const std::string& line) {
        if (io.out) io.out(line);
    };
    ++st.passes;
    // the follower pump
    const std::vector<FollowEvent> events = io.pump ? io.pump() : std::vector<FollowEvent>{};
    for (const FollowEvent& e : events) {
        out(follow_line(e));
        if (e.kind == FollowEventKind::Orphan) continue;
        const auto it = st.ours.find(e.height);
        if (it != st.ours.end()) {
            out(compare_line(e, it->second));
            ++st.compares;
        }
        st.ours.erase(st.ours.begin(), st.ours.upper_bound(e.height));
    }
    // a new main tip or a backlog refresh: the record routine
    const std::optional<FollowTip> tip = io.tmpl.main_tip ? io.tmpl.main_tip() : std::nullopt;
    const bool new_tip = tip && (!st.have_tip || !(tip->id == st.last_tip));
    if (tip) {
        st.have_tip = true;
        st.last_tip = tip->id;
    }
    bool refresh = false;
    if (io.backlog_version) {
        const std::uint64_t bv = io.backlog_version();
        refresh = !st.have_backlog || bv != st.last_backlog;
        st.have_backlog = true;
        st.last_backlog = bv;
    }
    if (new_tip || refresh) {
        FollowRecord r = follow_template_record(io.tmpl, o.penalty_fill);
        out(template_line(r, io.log_values ? io.log_values() : FollowLogValues{}));
        if (r.ok()) {
            ++st.records;
            const std::uint64_t h = r.h;
            st.ours[h] = std::move(r);
        } else {
            ++st.nones;
        }
    }
    // the status lines, then the web status
    if (o.status_every_s != 0 && io.now_s && io.status_values) {
        const std::uint64_t now = io.now_s();
        if (now >= st.next_status_s) {
            const std::vector<std::string> lines = kept_status_lines(io.status_values());
            for (const std::string& l : lines) out(l);
            if (io.web) io.web(lines);
            st.next_status_s = now + o.status_every_s;
        }
    }
}

inline FollowOnlyState serve_follow_only(FollowOnlyIo& io, const FollowOnlyOptions& o) {
    FollowOnlyState st;
    while (!(io.stop && io.stop())) {
        follow_only_pass(io, o, st);
        if (io.idle) io.idle();
    }
    return st;
}

}  // namespace c2pool::xmr::pathb
