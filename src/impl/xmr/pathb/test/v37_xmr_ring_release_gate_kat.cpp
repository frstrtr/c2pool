// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_release_gate_kat: the release gate of roundabouts slice C-3, in
// both builds (with and without V37_XMR_RING_TEST_EPOCHS).
//   (a) main_v37_xmr.cpp writes the compiled table once (epoch 0); that table
//       starts on all four networks with one compiled epoch, K17 = 1; a build
//       without the option holds no ring_rules member; with every depth known
//       and 0 no K-step function is called (the process-wide counter is
//       unchanged) across a persisted run that extends and switches across an
//       epoch-1 activation, a persisted restart and a persisted adoption; the
//       counter counts a call made on a second thread; each of the six counted
//       functions adds one per call, early returns included; a table whose epoch-1
//       list is absent arms the gate (depth unknown) and writes the same store
//       bytes and no K_KSTEP row; the headless K = 1 load (NoHead / BadHead);
//       the prefixes a store scans (its twelve, then the K-step prefix last)
//       at the empty start, the headless load and the adoption, and none of
//       the K-step prefix at a headed restart.
//   (b) a K17 = 2 epoch and no attempt: refused at LaneRules on all four
//       networks; (c) with its kind-1 attempt: refused at DeploymentTable.
//   (d) with the option: (b) and (c) refused off regtest only; on regtest ok
//       with a valid ring rule, refused without one.
//   (e) step 4b with the gate armed: a store whose AR row and K_KSTEP row are
//       at h_act 0 is refused (KStep).
// ---------------------------------------------------------------------------
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_startup.hpp"
#include "impl/xmr/pathb/pathb_kstep.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_ratchet_sim.hpp"

#ifndef V37_MAIN_SRC
#error "V37_MAIN_SRC must name src/c2pool/v37/main_v37_xmr.cpp"
#endif

namespace {

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

const std::uint64_t kFresh = pb::kRuledLaneParams.fresh_max;
constexpr std::uint64_t kJ = 64;  // the journal depth of the persisted nodes (the node KATs' restart depth)
constexpr bool kOption =
#ifdef V37_XMR_RING_TEST_EPOCHS
        true;
#else
        false;
#endif

template <class E>
concept HasRingRules = requires(const E& e) { e.ring_rules; };

// A store that records the prefixes it is asked to scan.
class CountingKv final : public pb::PathbKv {
public:
    MemoryKv mem;
    std::vector<std::string> scans;
    std::unique_ptr<pb::PathbKvBatch> batch() override { return mem.batch(); }
    pb::KvRead read(const std::string& k) override { return mem.read(k); }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        scans.push_back(prefix);
        return mem.for_each_prefix(prefix, fn);
    }
};

// The twelve prefixes of a store, in their order, then the K-step prefix.
std::vector<std::string> prefixes_with_kstep() {
    return {pb::store_keys::phead(0),        pb::store_keys::pcarrier_prefix(0), pb::store_keys::ar_prefix(0),
            pb::lane_keys::bmmr(0),          pb::lane_keys::blhash_prefix(0),    pb::lane_keys::bleaf_prefix(0),
            pb::store_keys::bwork_prefix(0), pb::store_keys::blo(0),             pb::store_keys::bclaim_prefix(0),
            pb::store_keys::ncu(0),          pb::store_keys::poison(0),          pb::store_keys::pside_prefix(0),
            pb::store_keys::kstep_prefix(0)};
}

std::size_t count_of(const std::vector<std::string>& v, const std::string& s) {
    std::size_t n = 0;
    for (const std::string& x : v) n += x == s ? 1 : 0;
    return n;
}

std::size_t kstep_keys(const MemoryKv& kv) {
    std::size_t n = 0;
    const std::string p = pb::store_keys::kstep_prefix(0);
    for (const auto& [k, v] : kv.data) n += k.compare(0, p.size(), p) == 0 ? 1 : 0;
    return n;
}

// The epoch-1 list of the node KATs' kind-2 activation: the epoch-0 list with coverage + 1 (K17 = 1).
pb::PathbLaneRules epoch1_rules() {
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    return r1;
}

constexpr std::uint64_t kFixed = 8;  // the kind-2 activation's position

// kat_table + epoch 1 by a kind-2 descriptor at kFixed; its list held or absent.
pb::EpochTable kind2_table(const KatNet& net, bool rules) {
    const pb::PathbLaneRules r1 = epoch1_rules();
    const pb::Hash32 d1 = pb::rules_digest(r1);
    pb::EpochTable T = kat_table(net);
    T.attempts.push_back(ratchet_sim::fixed2(1, d1, 1, kFixed));
    T.compiled.push_back(pb::CompiledEpoch{1, d1, rules ? std::optional<pb::PathbLaneRules>(r1) : std::nullopt});
    return T;
}

struct Miner {
    Harness& h;
    std::uint32_t nonce = 100;
    std::uint64_t mined = 0;
    void operator()(std::size_t i) {
        if (mined++ % 2 == 0) h.tick_monero();
        h.mine(i, static_cast<std::size_t>(mined % 4), nonce++);
    }
};

// Two persisted nodes extend to the fork below the activation, extend apart across it (links cut), exchange their
// branches; A switches to B's longer branch. True: the switch happened, both nodes on one tip with one AR.
bool extend_and_switch(Harness& h, Miner& mine, std::size_t a, std::size_t b) {
    const std::uint64_t fork = kFixed - 2;
    while (h[a].tree().best().pos < fork) mine(a);
    h.cut = {{a, b}, {b, a}};
    while (h[a].tree().best().pos < kFixed + 1) mine(a);
    while (h[b].tree().best().pos < kFixed + 2) mine(b);
    h.cut.clear();
    for (std::uint64_t x = fork + 1; x <= h[a].tree().best().pos; ++x)
        (void)h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(*h[a].store().best_at(x)), pb::kRuledLaneParams.r_max));
    h.pump();
    bool switched = false;
    for (std::uint64_t x = fork + 1; x <= h[b].tree().best().pos; ++x) {
        const pb::NodeEventResult r =
                h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(*h[b].store().best_at(x)), pb::kRuledLaneParams.r_max));
        switched = switched || r.action == pb::NodeAction::Switched;
        h.pump();
    }
    return switched && h[a].tree().best().id == h[b].tree().best().id && h[a].ar().rows() == h[b].ar().rows() &&
           h[a].ar().rows().size() == 1 && h[a].ar().rows()[0].h_act == kFixed;
}

std::string read_file(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// ---------------------------------------------------------------------------
// (a) MAIN's one write to the compiled table; its table on all four networks
// ---------------------------------------------------------------------------
pb::StartupInputs main_inputs(pb::LaneNet net) {
    pb::StartupInputs in;
    in.net = net;
    in.owner_fee_bp = 0;
    in.give_author_bp = pb::kDonationBp;
    const pb::PathbLaneRules rules0 = pb::epoch0_lane_rules(net);
    in.rp = pb::ratchet_params_of(rules0);
    in.journal_depth = pb::journal_j0(in.p, pb::kSealDepth);
    in.T.compiled.push_back(pb::CompiledEpoch{0, *pb::genesis_digest_for(net, rules0), rules0});
    in.hf = 16;
    in.z_lt_view = 300000;
    in.buffers = pb::relay_buffers_default(in.hf, in.z_lt_view, in.p.r_max).value();
    in.genesis_from = std::to_string(kPoolH) + ":" + pb::pid_detail::hex(mon_block(kPoolH)) + ":\"a headline\"";
    in.hash_at = [](std::uint64_t h) -> std::optional<pb::Hash32> { return mon_block(h); };
    in.monero_tip = kMonTop;
    return in;
}

void main_table() {
    // the code lines of MAIN that name the compiled table: one, the epoch-0 push
    const std::string src = read_file(V37_MAIN_SRC);
    std::istringstream lines(src);
    std::string line, only;
    std::size_t n = 0;
    while (std::getline(lines, line)) {
        const std::size_t c = line.find("//");
        const std::string code = c == std::string::npos ? line : line.substr(0, c);
        if (code.find(".compiled") != std::string::npos || code.find("ring_rules") != std::string::npos) {
            ++n;
            only = code;
        }
    }
    check(!src.empty() && n == 1 && only.find("in.T.compiled.push_back(pb::CompiledEpoch{0,") != std::string::npos,
          "(a) main_v37_xmr.cpp writes the compiled table once: the epoch-0 entry (" + std::to_string(n) + " lines)");
    for (const pb::LaneNet net : pb::kLaneNets) {
        const pb::StartupResult r = pb::startup_checks(main_inputs(net));
        check(r.ok() && r.T.compiled.size() == 1 && r.T.compiled[0].epoch_no == 0 && r.T.compiled[0].rules &&
                      r.T.compiled[0].rules->payment_groups == pb::kPaymentGroups,
              "(a) MAIN's table starts on network " + std::to_string(static_cast<int>(net)) +
                      ": one compiled epoch, K17 = kPaymentGroups (" + r.why + ")");
    }
    if constexpr (kOption)
        check(HasRingRules<pb::EpochTable>, "(a) with the option, EpochTable holds ring_rules");
    else
        check(!HasRingRules<pb::EpochTable>, "(a) without the option, EpochTable holds no ring_rules");
#ifndef V37_XMR_RING_TEST_EPOCHS
    static_assert(!HasRingRules<pb::EpochTable>);
#endif
}

// ---------------------------------------------------------------------------
// (a) zero K-step calls at K = 1, and the counter on a second thread
// ---------------------------------------------------------------------------
void zero_calls() {
    {  // an extension and a switch across the activation (persisted)
        const std::uint64_t m0 = pb::kstep_calls();
        const KatNet net;
        const pb::EpochTable T = kind2_table(net, true);
        Harness h(net);
        const std::size_t a = h.add(T, true, kJ, true), b = h.add(T, true, kJ, true);
        Miner mine{h};
        const bool sw = extend_and_switch(h, mine, a, b);
        for (int i = 0; i < 2; ++i) mine(a);
        check(!pb::table_has_k_step(T) && sw && h[b].tree().best().id == h[a].tree().best().id,
              "(a) K = 1: an extension and a switch across the epoch-1 activation (persisted)");
        check(pb::kstep_calls() == m0, "(a) zero calls: the counter unchanged across the extension and the switch (" +
                                               std::to_string(pb::kstep_calls() - m0) + ")");
    }
    {  // a persisted restart (the headed load scans no K-step prefix)
        const std::uint64_t m0 = pb::kstep_calls();
        const KatNet net;
        const pb::EpochTable T = kind2_table(net, true);
        Harness h(net);
        const std::size_t a = h.add(T, true, kJ, true), b = h.add(T, true, kJ, true);
        Miner mine{h};
        (void)extend_and_switch(h, mine, a, b);
        const std::string before = h[a].lane_digest();
        CountingKv kv;
        kv.mem.data = h.kvs[a]->data;
        pb::LoadInputs in;
        in.T = T;
        in.journal_depth = kJ;
        pb::LoadResult lr = pb::pathb_load(kv, net.pool_id, net.rules_g, in);
        const std::vector<std::string> want{pb::lane_keys::blhash_prefix(0), pb::lane_keys::bleaf_prefix(0),
                                            pb::store_keys::ar_prefix(0),    pb::store_keys::bwork_prefix(0),
                                            pb::store_keys::bclaim_prefix(0), pb::store_keys::pside_prefix(0)};
        check(lr.fault == pb::StoreFault::None && lr.state && kv.scans == want &&
                      count_of(kv.scans, pb::store_keys::kstep_prefix(0)) == 0,
              "(a) the headed restart loads and scans the lane, AR, K_BWORK, K_BCLAIM and K_PSIDE prefixes, no K-step "
              "prefix (" + std::to_string(kv.scans.size()) + " scans)");
        if (lr.state) {
            h.nodes[a] = std::make_unique<pb::PathbNode>(h.config(T, true, kJ), h.io(a), std::move(*lr.state), &kv);
            check(h[a].lane_digest() == before, "(a) the restarted node's lane digest equals");
            for (int i = 0; i < 2; ++i) mine(a);
            check(!h[a].poisoned() && h[b].tree().best().id == h[a].tree().best().id, "(a) the restarted node extends");
        }
        check(pb::kstep_calls() == m0, "(a) zero calls: the counter unchanged across the persisted restart (" +
                                               std::to_string(pb::kstep_calls() - m0) + ")");
    }
    {  // a persisted adoption (and the empty start's scans)
        const std::uint64_t m0 = pb::kstep_calls();
        const KatNet net;
        const pb::EpochTable T = kind2_table(net, true);
        Harness h(net);
        const std::size_t a = h.add(T, true, kJ), b = h.add(T, true, kJ);
        Miner mine{h};
        (void)extend_and_switch(h, mine, a, b);
        for (int i = 0; i < 4; ++i) mine(a);
        CountingKv start;
        {
            const std::size_t e = h.nodes.size();
            h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(T, true, kJ), h.io(e), &start));
            check(start.scans == prefixes_with_kstep(),
                  "(a) the empty start scans the store's twelve prefixes, then the K-step prefix (" +
                          std::to_string(start.scans.size()) + ")");
            h.nodes.back().reset();
        }
        CountingKv kv;
        const std::size_t j = h.nodes.size();
        h.nodes.push_back(std::make_unique<pb::PathbNode>(h.config(T, false, kJ), h.io(j), &kv, pb::PathbNode::LoadFailed{}));
        KatTransport tr(h, j);
        h[j].set_join_transport(&tr);
        h.hello(j, a);
        kv.scans.clear();
        const pb::JoinStep st = h[j].run_join();
        check(st.switched && st.batch_written && h[j].tree().best().id == h[a].tree().best().id &&
                      h[j].ar().rows() == h[a].ar().rows() && kstep_keys(kv.mem) == 0,
              "(a) a persisted adoption of the chain across the activation, no K_KSTEP row");
        check(kv.scans == prefixes_with_kstep(),
              "(a) the adoption scans the store's twelve prefixes, then the K-step prefix (" + std::to_string(kv.scans.size()) + ")");
        h.nodes[j].reset();
        check(pb::kstep_calls() == m0, "(a) zero calls: the counter unchanged across the persisted adoption (" +
                                               std::to_string(pb::kstep_calls() - m0) + ")");
    }
    {  // the counter is process-wide: a call on a second thread is counted
        const std::uint64_t m0 = pb::kstep_calls();
        std::thread t([] { (void)pb::depth_of_bin(pb::KStepList{}, 0, 0); });
        t.join();
        check(pb::kstep_calls() == m0 + 1, "(a) a call on a second thread is counted on the main thread");
    }
}

// ---------------------------------------------------------------------------
// (a) an absent epoch-1 list: the gate armed, the same store bytes, no K_KSTEP row
// ---------------------------------------------------------------------------
void absent_rules() {
    {  // the joiner KAT's shape: epoch 1 compiled with its list absent
        const KatNet net;
        pb::EpochTable T;
        T.compiled.push_back(pb::CompiledEpoch{0, net.rules_g, std::nullopt});
        T.compiled.push_back(pb::CompiledEpoch{1, seq32(0xA1), std::nullopt});
        check(pb::table_has_k_step(T) && !pb::depth_of_epoch(T, 1, seq32(0xA1)) && pb::depth_of_epoch(T, 0, std::nullopt) == 0,
              "(a) an epoch-1 entry without its list: the gate armed, its depth unknown (epoch 0's is 0)");
    }
    const KatNet net;
    const pb::EpochTable absent = kind2_table(net, false), held = kind2_table(net, true);
    check(pb::table_has_k_step(absent) && !pb::table_has_k_step(held) && !pb::depth_of_epoch(absent, 1, absent.compiled[1].digest),
          "(a) the kind-2 table without the epoch-1 list arms the gate; with it, not");
    const auto run = [&](const pb::EpochTable& T) {
        auto h = std::make_unique<Harness>(net);
        const std::size_t a = h->add(T, true, kJ, true), b = h->add(T, true, kJ, true);
        Miner mine{*h};
        (void)extend_and_switch(*h, mine, a, b);
        for (int i = 0; i < 2; ++i) mine(a);
        return h;
    };
    const std::unique_ptr<Harness> ha = run(absent), hh = run(held);
    bool same = ha->kvs.size() == hh->kvs.size();
    for (std::size_t k = 0; same && k < ha->kvs.size(); ++k)
        same = ha->kvs[k]->data == hh->kvs[k]->data && ha->kvs[k]->batch_sizes == hh->kvs[k]->batch_sizes;
    check(same && kstep_keys(*ha->kvs[0]) == 0 && kstep_keys(*ha->kvs[1]) == 0 && (*ha)[0].ar().rows().size() == 1,
          "(a) the armed gate writes no K_KSTEP row: the op list and the store bytes equal the K = 1 run's");
    // its restart: 4b runs (the gate) and keeps no row
    pb::LoadInputs in;
    in.T = absent;
    in.journal_depth = kJ;
    const pb::LoadResult lr = pb::pathb_load(*ha->kvs[0], net.pool_id, net.rules_g, in);
    check(lr.fault == pb::StoreFault::None && lr.state && lr.state->kbook.empty(),
          "(a) the armed gate's restart loads (an unknown pair needs no row), its book empty");
}

// ---------------------------------------------------------------------------
// (a) the headless K = 1 load
// ---------------------------------------------------------------------------
void headless() {
    const KatNet net;
    pb::LoadInputs in;
    in.T = kind2_table(net, true);
    in.journal_depth = kJ;
    {
        CountingKv kv;
        const pb::LoadResult r = pb::pathb_load(kv, net.pool_id, net.rules_g, in);
        check(r.fault == pb::StoreFault::NoHead && kv.scans == prefixes_with_kstep(),
              "(a) an empty store: NoHead, the twelve prefixes then the K-step prefix scanned");
    }
    {
        CountingKv kv;
        kv.mem.data[pb::store_keys::pcarrier(0, 3)] = "a record";
        const pb::LoadResult r = pb::pathb_load(kv, net.pool_id, net.rules_g, in);
        check(r.fault == pb::StoreFault::BadHead, "(a) a K_PCARRIER key and no K_PHEAD: BadHead");
    }
    {
        CountingKv kv;
        kv.mem.data[pb::store_keys::kstep(0, kFixed)] = "a row";
        const pb::LoadResult r = pb::pathb_load(kv, net.pool_id, net.rules_g, in);
        check(r.fault == pb::StoreFault::BadHead, "(a) a K_KSTEP key alone and no K_PHEAD: BadHead, as any store key");
    }
}

// ---------------------------------------------------------------------------
// (b), (c), (d): a K17 = 2 epoch
// ---------------------------------------------------------------------------
pb::PathbLaneRules k2_rules(pb::LaneNet net) {
    pb::PathbLaneRules r = pb::epoch0_lane_rules(net);
    r.payment_groups = 2;  // the gate's test value
    return r;
}

pb::StartupInputs k2_inputs(pb::LaneNet net, bool attempt) {
    pb::StartupInputs in = main_inputs(net);
    const pb::PathbLaneRules r2 = k2_rules(net);
    in.T.compiled.push_back(pb::CompiledEpoch{1, pb::rules_digest(r2), r2});
    if (attempt)
        in.T.attempts.push_back(pb::Deployment{1, pb::rules_digest(r2), pb::kKindVote, 0,
                                               pb::ratchet_vote_windows(in.rp) * in.rp.window, 0});
    return in;
}

void k2_epoch() {
    const std::string h2 = "compiled epoch 1: payment_groups 2 != 1 is not built";
    const std::string h3 = "attempt 0 (epoch 1): a rule set with payment_groups 2 != 1 is not built";
    for (const pb::LaneNet net : pb::kLaneNets) {
        const std::string tag = " (network " + std::to_string(static_cast<int>(net)) + ")";
        const bool off_regtest = net != pb::LaneNet::Regtest;
        const pb::StartupResult rb = pb::startup_checks(k2_inputs(net, false));
        const pb::StartupResult rc = pb::startup_checks(k2_inputs(net, true));
        if (!kOption || off_regtest) {
            const std::string tail = kOption ? " off regtest" : "";
            check(rb.refused == pb::StartupStep::LaneRules && rb.why == h2 + tail,
                  std::string(kOption ? "(d)" : "(b)") + " a K17 = 2 epoch, no attempt: refused at LaneRules" + tag + ": " + rb.why);
            check(rc.refused == pb::StartupStep::DeploymentTable && rc.why == h3 + tail,
                  std::string(kOption ? "(d)" : "(c)") + " with its kind-1 attempt: refused at DeploymentTable" + tag + ": " + rc.why);
        }
        // a later epoch's own refusal comes first (the gate runs after the table's checks)
        pb::StartupInputs later = k2_inputs(net, false);
        pb::PathbLaneRules r3 = pb::epoch0_lane_rules(net);
        r3.coverage = static_cast<std::uint8_t>(r3.coverage + 2);
        later.T.compiled.push_back(pb::CompiledEpoch{2, pb::rules_digest(pb::epoch0_lane_rules(net)), r3});
        const pb::StartupResult rl = pb::startup_checks(later);
        check(rl.refused == pb::StartupStep::LaneRules && rl.why == "compiled epoch 2: digest differs from its rules",
              "(b) a later epoch's digest refusal comes before the gate" + tag + ": " + rl.why);
    }
#ifdef V37_XMR_RING_TEST_EPOCHS
    {
        pb::StartupInputs in = k2_inputs(pb::LaneNet::Regtest, false);
        const pb::StartupResult none = pb::startup_checks(in);
        check(none.refused == pb::StartupStep::LaneRules && none.why == "compiled epoch 1: no ring rule",
              "(d) regtest without a ring rule: refused (no ring rule): " + none.why);
        in.T.ring_rules[1] = pb::RingRule{1, 1};
        const pb::StartupResult ok = pb::startup_checks(in);
        check(ok.ok(), "(d) regtest with a valid ring rule: ok (" + ok.why + ")");
        pb::StartupInputs ic = k2_inputs(pb::LaneNet::Regtest, true);
        ic.T.ring_rules[1] = pb::RingRule{1, 1};
        const pb::StartupResult okc = pb::startup_checks(ic);
        check(okc.ok(), "(d) regtest with its kind-1 attempt and a valid ring rule: ok (" + okc.why + ")");
    }
#endif
}

// ---------------------------------------------------------------------------
// (a) each counted function adds one per call, early returns included
// ---------------------------------------------------------------------------
void each_counts() {
    const KatNet net;
    const pb::EpochTable T = kat_table(net);
    Harness h(net);
    const std::size_t a = h.add(T, true, kJ), b = h.add(T, true, kJ);
    Miner mine{h};
    h.cut = {{a, b}, {b, a}};
    for (int i = 0; i < 2; ++i) mine(a);
    h.cut.clear();
    const pb::BinStore& st = h[a].store();
    const pb::LaneView v = st.view_at(st.best_tip());
    check(h[b].tree().find(st.best_tip()) == nullptr && v.ok(), "(a) B's tree does not hold A's best tip");
    const auto one = [](const std::string& what, const std::function<void()>& call) {
        const std::uint64_t m0 = pb::kstep_calls();
        call();
        const std::uint64_t d = pb::kstep_calls() - m0;
        check(d == 1, "(a) " + what + ": one call adds 1 (" + std::to_string(d) + ")");
    };
    one("depth_of_bin", [] { (void)pb::depth_of_bin(pb::KStepList{}, 0, 0); });
    one("merge_delta", [] { (void)pb::merge_delta(pb::KStepList{}, 0, 0); });
    one("sigma", [] { (void)pb::sigma(pb::KStepList{}, 0, 0, 0); });
    one("sigma, its early return (reach_low above top)", [] { (void)pb::sigma(pb::KStepList{}, 0, 1, 0); });
    pb::KStepBook book;
    const pb::ActivationRecord no_rows;
    std::optional<pb::KStepOps> ops;
    one("kbook_sync (an empty book, an AR without rows)", [&] { ops = pb::kbook_sync(book, no_rows, T, st, kFresh, 0); });
    check(ops && ops->put.empty() && ops->del.empty() && book.empty(), "(a) kbook_sync on an empty book and an AR without rows: no op");
    std::optional<pb::TipActs> early, normal;
    one("tip_acts, its early return (the tree lacks the store's best tip)",
        [&] { early = pb::tip_acts(pb::kRuledRatchetParams, T, h[b].tree(), st, h[a].ar(), h[b].tree().best(), true); });
    check(!early, "(a) tip_acts: nullopt when the tree does not hold the store's best tip");
    one("tip_acts", [&] { normal = pb::tip_acts(pb::kRuledRatchetParams, T, h[a].tree(), st, h[a].ar(), h[a].tree().best(), true); });
    check(normal && normal->consistent, "(a) tip_acts at A's own tip: consistent");
    pb::TipActs bad;
    bad.consistent = false;
    std::optional<pb::KSteps> ks;
    one("ksteps_at, its early return (inconsistent acts)", [&] { ks = pb::ksteps_at(bad, T, st, v, book, kFresh); });
    check(ks && ks->gap && ks->known_from_bin == pb::kNoKnownBin, "(a) ksteps_at on inconsistent acts: a gap knowing no bin");
}

// ---------------------------------------------------------------------------
// (e) step 4b with the gate armed: an AR row and a K_KSTEP row at h_act 0
// ---------------------------------------------------------------------------
void row_at_zero() {
    const KatNet net;
    const pb::EpochTable T = kind2_table(net, false);  // the epoch-1 list absent: the gate armed
    Harness h(net);
    const std::size_t a = h.add(T, true, kJ, true), b = h.add(T, true, kJ, true);
    Miner mine{h};
    const bool sw = extend_and_switch(h, mine, a, b);
    pb::LoadInputs in;
    in.T = T;
    in.journal_depth = kJ;
    MemoryKv plain;
    plain.data = h.kvs[a]->data;
    const pb::LoadResult l0 = pb::pathb_load(plain, net.pool_id, net.rules_g, in);
    check(pb::table_has_k_step(T) && sw && l0.fault == pb::StoreFault::None && l0.state,
          "(e) the gate armed; the persisted store with its AR row at the activation loads");
    MemoryKv kv;
    kv.data = h.kvs[a]->data;
    const auto it = kv.data.find(pb::store_keys::ar(0, kFixed));
    const std::optional<pb::ActivationRow> row =
            it == kv.data.end() ? std::nullopt : pb::decode_ar_row(it->second);
    check(row.has_value(), "(e) the store holds the AR row at the activation");
    if (!row) return;
    pb::ActivationRow r0 = *row;
    r0.h_act = 0;
    kv.data.erase(it);
    kv.data[pb::store_keys::ar(0, 0)] = pb::encode_ar_row(r0);
    kv.data[pb::store_keys::kstep(0, 0)] = pb::encode_kstep_row(pb::KStepRecord{r0.epoch, 0, 0});
    const pb::LoadResult lr = pb::pathb_load(kv, net.pool_id, net.rules_g, in);
    check(lr.fault == pb::StoreFault::KStep && !lr.state,
          "(e) the AR row moved to h_act 0 with a K_KSTEP row at 0: refused, KStep (fault " +
                  std::to_string(static_cast<int>(lr.fault)) + ")");
}

}  // namespace

int main() {
    main_table();
    zero_calls();
    each_counts();
    absent_rules();
    headless();
    row_at_zero();
    k2_epoch();
    return finish("v37_xmr_ring_release_gate_kat");
}
