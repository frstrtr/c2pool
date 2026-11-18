// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_node_golden_gen: the K = 1 node golden (a SCAFFOLD golden: hf
// 16, v1's window function, a test tag). One fixed scripted Monero chain and
// lane (the node KATs' fixtures as data: KatNet, Harness), K = 1 only:
//   the start-up checks (each refusal step and two starts);
//   three in-process nodes, A mining (launch), B and C relayed: for every tip
//   each node's lane_digest, its template and the jobs of two sessions
//   (miner tx bytes, side window_root / mmr_root / rules_epoch, R);
//   the frame set: every FC_CARRIER frame A floods, judged by admit_carrier on
//   B's state before B places it; a sibling race judged on both sides; three
//   changed frames; receipts judged by admit_receipt_decoded.
//   --out=FILE / --raw=FILE / --check=FILE as v37_xmr_ring_c1_golden_gen.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_startup.hpp"
#include "pathb_kat_node.hpp"
#include "v37_xmr_ring_c1_vectors.hpp"

#ifndef RING_NODE_GEN_SHA256
#define RING_NODE_GEN_SHA256 "unset"
#endif
#ifndef RING_C1_VEC_SHA256
#define RING_C1_VEC_SHA256 "unset"
#endif

namespace c2pool::xmr::pathb {
struct PathbNodeTestAccess {
    static AdmitEnv env(PathbNode& n) { return n.env(); }
};
}  // namespace c2pool::xmr::pathb

namespace {

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
using ring_c1::Bytes;
using ring_c1::Recorder;

void put_admit(Bytes& o, const pb::AdmitResult& r) {
    o.u8(static_cast<std::uint8_t>(r.verdict));
    o.u8(static_cast<std::uint8_t>(r.row));
    o.u64(r.strike);
    o.u8(r.randomx_called ? 1 : 0);
    o.u8(r.missing ? 1 : 0);
    o.u8(r.missing ? static_cast<std::uint8_t>(*r.missing) : 0);
    o.u8(r.alarm ? 1 : 0);
    o.u64(r.body);
    o.h(r.fetch);
    o.u64(r.fetch_bin);
    o.h(r.id);
    o.u64(r.placements.size());
    o.u64(r.store_placements.size());
}

void startup(Recorder& rec) {
    const auto base = [] {
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
    auto put = [&](const std::string& name, const pb::StartupInputs& in) {
        const pb::StartupResult r = pb::startup_checks(in);
        Bytes o;
        o.u8(0x10);
        o.u8(static_cast<std::uint8_t>(r.refused));
        o.raw(std::vector<std::uint8_t>(r.why.begin(), r.why.end()));
        o.u8(r.raw_warning ? 1 : 0);
        o.u64(r.T.compiled.size());
        for (const pb::CompiledEpoch& e : r.T.compiled) {
            o.u64(e.epoch_no);
            o.h(e.digest);
        }
        o.u8(static_cast<std::uint8_t>(r.identity.network));
        o.u64(r.identity.chain_id);
        o.u8(static_cast<std::uint8_t>(r.identity.form));
        o.u64(r.identity.height);
        o.h(r.identity.pool_genesis);
        o.h(r.identity.pool_id);
        rec.add("node/startup/" + name, std::move(o));
    };
    put("ok", base());
    pb::StartupInputs a = base();
    a.owner_fee_bp = 9991;
    put("fee-sum", a);
    a = base();
    a.journal_depth = 1151;
    put("journal-depth", a);
    a = base();
    a.net = pb::LaneNet::Mainnet;
    a.deployments.push_back(pb::Deployment{});
    put("deployments", a);
    a = base();
    a.rp.grace = a.rp.window * 5;
    put("deployment-table", a);
    a = base();
    a.net = pb::LaneNet::Testnet;
    put("lane-rules", a);
    a = base();
    a.buffers.receipt -= 1;
    put("relay-buffers", a);
    a = base();
    a.raw.pool_genesis_height.reset();
    put("identity", a);
    a = base();
    a.raw = {};
    a.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH + 1)) + ":\"a headline\"";
    put("genesis-chain", a);
    a.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH)) + ":\"a headline\"";
    put("derived", a);
}

// A node's lane digest, its template and the jobs of sessions 0 and 5.
void node_state(Recorder& rec, Harness& h, std::size_t i, const std::string& at) {
    {
        const std::string d = h[i].lane_digest();
        Bytes o;
        o.u8(0x11);
        o.raw(std::vector<std::uint8_t>(d.begin(), d.end()));
        rec.add(at + "/n" + std::to_string(i) + "/lane_digest", std::move(o));
    }
    const pb::PathbTemplate t = h[i].make_template(h.now);
    {
        Bytes o;
        o.u8(0x12);
        o.u8(static_cast<std::uint8_t>(t.status));
        o.h(t.tip);
        o.u64(t.x);
        o.h(t.p_r);
        o.u64(t.h);
        o.u8(t.hf);
        o.u64(t.timestamp);
        o.u64(t.d);
        o.u64(t.base);
        o.u64(t.median);
        o.u64(t.reward);
        o.u64(t.fees);
        o.u64(t.tx_weight);
        o.u64(t.coinbase);
        o.u64(t.txs.size());
        for (const pb::TemplateTx& x : t.txs) o.h(x.hash);
        o.h(t.fetch);
        Recorder::put_tip(o, t.window, t.reward);
        rec.add(at + "/n" + std::to_string(i) + "/template", std::move(o));
    }
    if (t.status != pb::TemplateStatus::Ok) return;
    for (const std::size_t k : {std::size_t{0}, std::size_t{5}}) {
        const std::optional<pb::PathbJob> j = h[i].make_job(t, h.session(k, 7 + static_cast<std::uint32_t>(k)));
        Bytes o;
        o.u8(0x13);
        o.u8(j ? 1 : 0);
        if (j) {
            o.raw(j->miner_tx.prefix);
            o.h(j->miner_tx.tx_hash);
            o.u64(j->miner_tx.outs.size());
            for (const pb::MinerOut& x : j->miner_tx.outs) {
                o.u64(x.amount);
                o.h(x.key);
                o.u8(x.view_tag);
            }
            o.h(j->body.side.window_root);
            o.h(j->body.side.mmr_root);
            o.u16(j->body.side.rules_epoch);
            o.u64(j->body.reward_total);
            o.u64(j->d);
            o.u64(j->h);
            o.h(j->tip);
            o.u64(j->carried.size());
            for (const pb::ReceiptBodyV3& r : j->carried) o.h(pb::receipt_id(r));
        }
        rec.add(at + "/n" + std::to_string(i) + "/job-s" + std::to_string(k), std::move(o));
    }
}

void judge_frame(Recorder& rec, Harness& h, std::size_t on, const std::vector<std::uint8_t>& frame, const std::string& name) {
    const pb::AdmitResult r = pb::admit_carrier(pb::PathbNodeTestAccess::env(h[on]), frame, pb::CarrierRole::Frame);
    Bytes o;
    o.u8(0x14);
    o.h(::v37::sha256d(frame));
    put_admit(o, r);
    rec.add(name, std::move(o));
}

void judge_receipt(Recorder& rec, Harness& h, std::size_t on, const pb::ReceiptBodyV3& r, const std::string& name) {
    const std::vector<std::uint8_t> bytes = enc(r);
    const pb::AdmitResult a = pb::admit_receipt_decoded(pb::PathbNodeTestAccess::env(h[on]), r, bytes.size());
    Bytes o;
    o.u8(0x15);
    o.h(pb::receipt_id(r));
    put_admit(o, a);
    rec.add(name, std::move(o));
}

void network(Recorder& rec) {
    const KatNet net;
    Harness h(net);
    const std::size_t a = h.add(kat_table(net), true), b = h.add(kat_table(net)), c = h.add(kat_table(net));
    h.txs = {{seq32(0xE1), 2000, 3000000}, {seq32(0xE2), 1500, 2000000}};
    std::vector<std::uint8_t> last_frame;
    constexpr int kSteps = 130;
    for (int i = 0; i < kSteps; ++i) {
        const std::string at = "node/step-" + std::to_string(i);
        h.tick_monero(i < 30 ? (i % 3 == 0 ? 1 : 0) : 2);
        const pb::NodeEventResult r = h.mine(a, static_cast<std::size_t>(i % 7), 100 + static_cast<std::uint32_t>(i), false);
        {
            Bytes o;
            o.u8(0x16);
            o.u8(static_cast<std::uint8_t>(r.action));
            put_admit(o, r.admit);
            rec.add(at + "/mine", std::move(o));
        }
        std::size_t k = 0;
        for (const Msg& m : h.q)
            if (m.to == b && !m.frame.empty() && m.frame[0] == pb::kOpFcCarrier) {
                judge_frame(rec, h, b, m.frame, at + "/frame-" + std::to_string(k++));
                last_frame = m.frame;
            }
        h.pump();
        if (i % 9 == 4) {  // an unsolicited receipt: a share of B's job judged by A
            const pb::PathbTemplate t = h[b].make_template(h.now);
            if (t.status == pb::TemplateStatus::Ok) {
                const std::optional<pb::PathbJob> j = h[b].make_job(t, h.session(3, 900 + static_cast<std::uint32_t>(i)));
                if (j) {
                    pb::ReceiptBodyV3 x = j->body;
                    x.blob.nonce = 4000 + static_cast<std::uint32_t>(i);
                    judge_receipt(rec, h, a, x, at + "/receipt");
                }
            }
        }
        for (const std::size_t n : {a, b, c}) node_state(rec, h, n, at);
    }
    // three changed frames, judged on B
    if (!last_frame.empty()) {
        pb::CarrierBodyV3 body;
        const bool ok = pb::decode_carrier_body_v3(last_frame.data() + pb::kFrameHeaderBytes,
                                                   last_frame.size() - pb::kFrameHeaderBytes,
                                                   pb::CarrierLimits{1u << 20, pb::kRuledLaneParams.r_max},
                                                   body) == pb::WireError::None;
        if (ok) {
            pb::CarrierBodyV3 x = body;
            x.own.blob.tree_root[0] ^= 0x01;
            if (const auto f = pb::encode_fc_carrier(0, x, pb::kRuledLaneParams.r_max)) judge_frame(rec, h, b, *f, "node/changed/tree-root");
            x = body;
            x.own.side.tip[0] ^= 0x01;
            if (const auto f = pb::encode_fc_carrier(0, x, pb::kRuledLaneParams.r_max)) judge_frame(rec, h, b, *f, "node/changed/tip");
            x = body;
            x.own.side.pool_id[0] ^= 0x01;
            if (const auto f = pb::encode_fc_carrier(0, x, pb::kRuledLaneParams.r_max)) judge_frame(rec, h, b, *f, "node/changed/pool-id");
        }
    }
    // a sibling race on one tip: A and B each find a carrier with the links cut
    h.cut = {{a, b}, {b, a}, {a, c}, {b, c}};
    h.tick_monero();
    h.mine(a, 2, 9000);
    h.mine(b, 3, 9001);
    h.cut.clear();
    const pb::Hash32 ca = h[a].tree().best().id, cb = h[b].tree().best().id;
    const std::vector<std::uint8_t> fa = *pb::encode_fc_carrier(0, *h[a].bodies().get(ca), pb::kRuledLaneParams.r_max);
    const std::vector<std::uint8_t> fb = *pb::encode_fc_carrier(0, *h[b].bodies().get(cb), pb::kRuledLaneParams.r_max);
    judge_frame(rec, h, a, fb, "node/race/b-on-a");
    judge_frame(rec, h, b, fa, "node/race/a-on-b");
    judge_frame(rec, h, c, fa, "node/race/a-on-c");
    judge_frame(rec, h, c, fb, "node/race/b-on-c");
    for (const std::size_t n : {a, b, c}) node_state(rec, h, n, "node/race/before");
    {
        const pb::NodeEventResult ra = h[a].on_carrier(b, fb);
        const pb::NodeEventResult rb = h[b].on_carrier(a, fa);
        (void)h[c].on_carrier(a, fa);
        (void)h[c].on_carrier(b, fb);
        h.pump();
        for (const auto& [name, r] : {std::pair<std::string, pb::NodeEventResult>{"a", ra}, std::pair<std::string, pb::NodeEventResult>{"b", rb}}) {
            Bytes o;
            o.u8(0x16);
            o.u8(static_cast<std::uint8_t>(r.action));
            o.u64(r.repended);
            put_admit(o, r.admit);
            rec.add("node/race/on-carrier-" + name, std::move(o));
        }
    }
    for (int i = 0; i < 4; ++i) {
        h.tick_monero();
        const std::size_t miner = i % 2 == 0 ? a : b;
        h.mine(miner, static_cast<std::size_t>(4 + i), 9100 + static_cast<std::uint32_t>(i));
        for (const std::size_t n : {a, b, c}) node_state(rec, h, n, "node/race/after-" + std::to_string(i));
    }
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
    startup(rec);
    network(rec);
    const std::vector<std::string> header{
            "v37_xmr_ring_node_golden: SCAFFOLD golden (hf 16, v1's window function, test tag), K = 1",
            "entry points: startup_checks, PathbNode::make_template, make_job, lane_digest, admit_carrier, "
            "admit_receipt_decoded, and the node KATs' Harness",
            std::string("source-sha256 v37_xmr_ring_node_golden_gen.cpp ") + RING_NODE_GEN_SHA256,
            std::string("source-sha256 v37_xmr_ring_c1_vectors.hpp ") + RING_C1_VEC_SHA256,
    };
    const std::string text = ring_c1::golden_text(header, rec);
    const std::string out = arg_of(argc, argv, "--out="), raw = arg_of(argc, argv, "--raw="),
                      chk = arg_of(argc, argv, "--check=");
    if (!out.empty()) {
        std::ofstream f(out, std::ios::binary);
        f << text;
    }
    if (!raw.empty()) {
        const std::vector<std::uint8_t> r = ring_c1::golden_raw(rec);
        std::ofstream f(raw, std::ios::binary);
        f.write(reinterpret_cast<const char*>(r.data()), static_cast<std::streamsize>(r.size()));
    }
    bool ok = true;
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
    std::printf("v37_xmr_ring_node_golden_gen: %s: %zu records\n", ok ? "PASS" : "FAIL", rec.recs.size());
    return ok ? 0 : 1;
}
