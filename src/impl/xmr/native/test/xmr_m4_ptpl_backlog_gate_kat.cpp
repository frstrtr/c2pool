// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_m4_ptpl_backlog_gate_kat.cpp
//
// THE M4 LEG-1 STALL, REPRODUCED AS A NUMBER AND THEN REFUSED.
//
// WHAT THE SOAK ACTUALLY SAW. A healthy stagenet node -- synced, 8/8 peers, zero
// reorgs, zero orphans, serving from monerod and shadowing its own native arm --
// produced 2,201 P-TEMPLATE FAILs against 3,209 CLEANs, and every single recent
// FAIL carried the same one-line diff:
//
//     tx_backlog_count served=0 shadow=5     seam=TEMPLATE
//     note: 1 constraint(s) violated; [P-TPL served_by=monerod]
//
// The M4 GraduationLedger resets `clean_run` to zero on every FAIL, so a streak
// that has to reach 720 could never reach 2. The node was not diverging from the
// daemon in any way that matters: all six required EQUALITY rows -- prev_id,
// major_version, difficulty, seed_hash, median_weight, already_generated_coins --
// agreed at every height. The two numbers in that diff were simply not the same
// quantity:
//
//     served=0  the DAEMON's mempool as it offers it to a template builder in
//               get_miner_data.tx_backlog. Empty, because stagenet was quiet.
//     shadow=5  the NATIVE pool's SELECTABLE SET, admitted under the v37 relay
//               rule (structural + range-proof/commitment evidence, no key-image
//               double-spend test). Five transactions the daemon did not hold.
//
// AND THE GATE THAT FIRED WAS NOT AN EQUALITY ON THAT ROW. tx_backlog_count is a
// Regime::Measurement and always was. What FAILed was the native_backlog_famine
// CONSTRAINT, which the oracle fed BY SEAT: the SERVED seat into
// `native_backlog` and the SHADOW seat into the daemon count. In the leg where
// monerod serves, those seats hold the two arms the other way round. The
// daemon's 0 became "the native pool is starving" and the native pool's 5 became
// "the daemon is holding transactions we cannot see". Six samples of that, 30
// seconds apart, and the guard tripped -- stickily, by design, so it never
// recovered. Its failure text said "the native pool is not ingesting relayed
// transactions" about a pool that was ingesting fine (`txpool: gate=1 n=5
// acc=193 rej=0`).
//
// WHAT THIS TARGET PINS.
//
//   A  THE STALL CASE, through the REAL ParityOracle in the real leg-1 posture:
//      served by monerod with an empty daemon mempool, shadowed by a native arm
//      holding five transactions, six identical consensus inputs. Every sample
//      CLEAN, for longer than the graduation threshold, and the two by-design
//      differences still RENDERED in the diff so nothing was hidden to get there.
//
//   B  THE SAME STREAM THROUGH THE LEDGER. `clean_run` climbs past 720 and the
//      leg qualifies. This is the stall itself, measured: under the old judge
//      this number was 0 and could not move.
//
//   C  THE NEGATIVE CONTROL. A genuinely different PRODUCED TEMPLATE -- one unit
//      in each of the six consensus inputs in turn -- still FAILs (or VOIDs, for
//      the alignment key), the sentinels still revoke, and the ledger still
//      resets. A fix that made the stall case clean by making everything clean
//      would be worse than the stall.
//
//   D  M2h IS NOT GIVEN BACK. In leg 2 -- the native arm SERVING -- a native
//      pool that holds nothing while the daemon holds transactions still trips
//      the guard and still FAILs. That is the regression the constraint exists
//      for and it is untouched. In leg 1 the same shape is ADVISORY: recorded,
//      counted, visible in the status line, and not a gate, because no miner is
//      served from the native pool in that posture. Note that this is strictly
//      more sight than before, not less: fed by seat, a real leg-1 famine
//      classified as `Fed` and was invisible.
//
//   E  THE TABLE. tx_backlog_count is still a Measurement, the selected
//      transaction set is NotComparable, the required EQUALITY count is still
//      six, and the comparator version moved so no old streak can be inherited.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// STL only plus the parity headers; no RandomX, no sockets, no daemon, no clock
// of its own -- the caller hands the oracle and the ledger unix seconds, so a
// 72-hour soak runs in microseconds.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/parity/xmr_backlog_famine.hpp"
#include "impl/xmr/native/parity/xmr_graduation_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"
#include "impl/xmr/native/parity/xmr_parity_oracle.hpp"
#include "impl/xmr/native/parity/xmr_parity_sources.hpp"

using namespace c2pool::xmr::native;
using namespace c2pool::xmr::native::parity;

// ---------------------------------------------------------------------------
static int g_checks = 0;
static int g_fail   = 0;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        ++g_checks;                                       \
        const bool _ok = (cond);                          \
        if (!_ok) {                                       \
            ++g_fail;                                     \
            std::printf("  [FAIL] ");                     \
            std::printf(__VA_ARGS__);                     \
            std::printf("\n");                            \
        }                                                 \
    } while (0)

static void head(const char* s) { std::printf("\n== %s ==\n", s); }

// ---------------------------------------------------------------------------
// Fixtures: the live sample, as numbers.
//
// These are the stagenet values from the run this target exists to close, so
// that the reproduction is of the observed failure and not of a tidier cousin
// of it. Only the backlog size differs between the two arms.
// ---------------------------------------------------------------------------
namespace {

constexpr std::uint64_t kStallHeight   = 2205928;
constexpr std::size_t   kNativePoolN   = 5;   // node status: txpool gate=1 n=5
constexpr std::size_t   kDaemonPoolN   = 0;   // get_miner_data returned no tx_backlog

Hash hash_of(std::uint8_t b) {
    Hash h{};
    h.fill(b);
    return h;
}

node::MinerData miner_data(std::uint64_t height, std::size_t n_tx) {
    node::MinerData md;
    md.height                  = height;
    md.prev_id                 = hash_of(0x8e);
    md.seed_hash               = hash_of(0x2c);
    md.major_version           = 16;
    md.difficulty              = U128{/*lo=*/243310912, /*hi=*/0};
    md.median_weight           = 300000;
    md.already_generated_coins = 18446744073709551ull;
    md.median_timestamp        = 1789205000;
    for (std::size_t i = 0; i < n_tx; ++i) {
        node::TxBacklogEntry e;
        e.id        = hash_of(static_cast<std::uint8_t>(0xa0 + i));
        e.weight    = 1500 + 10 * static_cast<std::uint64_t>(i);
        e.fee       = 30000 + 1000 * static_cast<std::uint64_t>(i);
        e.blob_size = 1420;
        md.tx_backlog.push_back(e);
    }
    return md;
}

// An arm that answers with a fixed MinerData under a fixed name.
class FixedArm final : public IMinerDataSource {
public:
    FixedArm(const char* name, node::MinerData md) : name_(name), md_(std::move(md)) {}
    void set(node::MinerData md) { md_ = std::move(md); }

    const char* name() const override { return name_; }
    MinerDataReadiness readiness() const override {
        MinerDataReadiness r;
        r.tip_known = r.seed_reach = r.difficulty_window =
        r.weight_window = r.coins_known = r.hf_known = true;
        return r;
    }
    MinerDataEpoch epoch() const override {
        MinerDataEpoch e;
        e.height  = md_.height;
        e.prev_id = md_.prev_id;
        return e;
    }
    std::optional<node::MinerData> snapshot(std::string* why) const override {
        if (why) why->clear();
        return md_;
    }
    const std::vector<std::uint8_t>* tx_body(const Hash&) const override { return nullptr; }

private:
    const char*     name_;
    node::MinerData md_;
};

// One posture of the M4 soak, driven sample by sample through the real oracle.
//
// `serving` is the ARM NAME that on_serve is told produced the template, which
// is exactly what xmr_native_node.hpp passes; `shadow` is the arm the oracle
// reads for itself. Leg 1 is ("monerod", native-arm); leg 2 is ("native",
// monerod-arm). Nothing here re-implements the comparator.
struct Leg {
    const char*     serving;
    node::MinerData served_md;
    const char*     shadow_name;
    node::MinerData shadow_md;
};

struct Run {
    std::vector<SeamResult> samples;
    std::size_t clean = 0, fail = 0, voided = 0, mismatch = 0;
    std::string famine_line;
    bool        famine_tripped = false;
};

Run drive(const Leg& leg, int samples, BacklogFamineConfig fcfg = {}) {
    FixedArm shadow_arm(leg.shadow_name, leg.shadow_md);

    ParityOracle::Deps deps;
    deps.shadow_arm = &shadow_arm;

    ParityOracleConfig cfg;
    cfg.backlog_famine = fcfg;

    GraduationKey key;
    key.c2pool_commit      = "m4-ptpl-gate-kat";
    key.comparator_version = COMPARATOR_VERSION;
    key.monerod_version    = "0.18.5.0-release";
    key.net                = "stagenet";

    std::uint64_t clock = 1789200000;
    ParityOracle orc(deps, key, GraduationPolicy{}, cfg, [&clock] { return clock; });

    Run out;
    for (int i = 0; i < samples; ++i) {
        MinerDataEpoch ep;
        ep.height  = leg.served_md.height;
        ep.prev_id = leg.served_md.prev_id;
        orc.on_serve(ep, leg.served_md, leg.serving);
        for (const SeamResult& r : orc.drain()) {
            if (r.sample.kind != ProbeKind::Template) continue;
            switch (r.sample.verdict) {
                case ParityVerdict::Clean:          ++out.clean; break;
                case ParityVerdict::Fail:           ++out.fail; break;
                case ParityVerdict::Void:           ++out.voided; break;
                case ParityVerdict::ServedMismatch: ++out.mismatch; break;
            }
            out.samples.push_back(r);
        }
        clock += 20;   // the soak's own template cadence
    }
    out.famine_line    = orc.backlog_famine();
    out.famine_tripped = orc.backlog_famine_tripped();
    return out;
}

bool has_diff(const SeamResult& r, const char* field) {
    for (const FieldDiff& d : r.sample.fields) if (d.field == field) return true;
    return false;
}

const FieldDiff* find_diff(const SeamResult& r, const char* field) {
    for (const FieldDiff& d : r.sample.fields) if (d.field == field) return &d;
    return nullptr;
}

} // namespace

// ---------------------------------------------------------------------------
// SUITE A -- the stall case, through the real oracle, in the real posture.
// ---------------------------------------------------------------------------
static void suite_stall_case() {
    head("A. leg 1 (serve=monerod, shadow=native): the exact stall sample is CLEAN");

    Leg leg;
    leg.serving     = "monerod";
    leg.served_md   = miner_data(kStallHeight, kDaemonPoolN);   // daemon mempool: empty
    leg.shadow_name = "native";
    leg.shadow_md   = miner_data(kStallHeight, kNativePoolN);   // native pool: five txs

    // The soak's own guard settings: six samples, thirty seconds.
    BacklogFamineConfig fcfg;
    fcfg.consecutive = 6;
    fcfg.sustained_s = 30;

    const Run run = drive(leg, 800, fcfg);

    // A1. Not one FAIL, over more samples than the graduation threshold needs.
    CHECK(run.samples.size() == 800, "A1 expected 800 template samples, got %zu",
          run.samples.size());
    CHECK(run.fail == 0, "A1 the stall case must produce ZERO FAILs, got %zu", run.fail);
    CHECK(run.clean == run.samples.size(),
          "A1 every sample must be CLEAN: %zu/%zu (void=%zu mismatch=%zu)",
          run.clean, run.samples.size(), run.voided, run.mismatch);

    // A2. ...and the guard did not trip, however long the run.
    CHECK(!run.famine_tripped, "A2 the famine guard must not trip in leg 1: %s",
          run.famine_line.c_str());

    // A3. The by-design difference is still VISIBLE. Making the sample clean by
    // hiding the delta would be a different bug wearing this fix's clothes, so
    // both rendered rows are required to be present -- and non-scoring.
    {
        const SeamResult& r = run.samples.front();
        const FieldDiff* count = find_diff(r, "tx_backlog_count");
        CHECK(count != nullptr, "A3 tx_backlog_count must still be rendered in the diff");
        if (count != nullptr) {
            CHECK(count->served == "0" && count->shadow == "5",
                  "A3 the rendered row must carry the live numbers: served=%s shadow=%s",
                  count->served.c_str(), count->shadow.c_str());
        }
        CHECK(has_diff(r, "selected_tx_set"),
              "A3 the selected transaction set must be rendered too");
        CHECK(!has_diff(r, kBacklogFamineCheck),
              "A3 no failing constraint may appear: the famine row is only pushed when it FAILS");
        CHECK(r.constraints_failed == 0, "A3 zero constraints may fail, got %zu",
              r.constraints_failed);
        CHECK(r.equality_compared == 6 && r.equality_differed == 0,
              "A3 all six EQUALITY rows compared and agreed: %zu compared, %zu differed",
              r.equality_compared, r.equality_differed);
        CHECK(!r.sentinel_tripped, "A3 no sentinel may trip on the stall sample");
    }

    // A4. The advisory accounting is real: the shape was observed 800 times and
    // gated zero times, and the status line says so rather than going silent.
    CHECK(run.famine_line.find("advisory=800") != std::string::npos,
          "A4 the status line must report the advisory samples: %s", run.famine_line.c_str());
}

// ---------------------------------------------------------------------------
// SUITE B -- the stall itself: the graduation streak, which could not move.
// ---------------------------------------------------------------------------
static void suite_streak() {
    head("B. M4GraduationLedger: the leg-1 clean streak now climbs past the threshold");

    Leg leg;
    leg.serving     = "monerod";
    leg.served_md   = miner_data(kStallHeight, kDaemonPoolN);
    leg.shadow_name = "native";
    leg.shadow_md   = miner_data(kStallHeight, kNativePoolN);

    BacklogFamineConfig fcfg;
    fcfg.consecutive = 6;
    fcfg.sustained_s = 30;

    const Run run = drive(leg, 800, fcfg);

    GraduationKey key;
    key.c2pool_commit   = "m4-ptpl-gate-kat";
    key.monerod_version = "0.18.5.0-release";
    key.net             = "stagenet";
    M4GraduationLedger led(key, SoakThresholds::stagenet_m4());

    std::uint64_t t = 1789200000;
    for (const SeamResult& r : run.samples) {
        led.record(SoakPosture::ServeMonerodShadowNative, r, t);
        t += 20;
    }

    const PostureLeg& L = led.leg(SoakPosture::ServeMonerodShadowNative);
    CHECK(L.clean_run == 800,
          "B1 the clean streak must reach 800 (it was pinned at 0 by the stall), got %llu",
          static_cast<unsigned long long>(L.clean_run));
    CHECK(L.fail == 0, "B1 no FAIL may be recorded, got %llu",
          static_cast<unsigned long long>(L.fail));
    CHECK(L.resets == 0, "B1 the streak must never be reset, got %llu resets",
          static_cast<unsigned long long>(L.resets));
    CHECK(L.clean_run >= SoakThresholds::stagenet_m4().min_clean_samples,
          "B1 and it must clear the real M4 sample threshold");
    CHECK(led.state() != GraduationState::Revoked, "B1 nothing may have revoked the key");
}

// ---------------------------------------------------------------------------
// SUITE C -- the negative control. A genuinely different template still FAILs.
// ---------------------------------------------------------------------------
static void suite_negative_control() {
    head("C. NEGATIVE CONTROL: a genuinely different produced template still FAILs");

    struct T { const char* field; bool sentinel; node::MinerData md; };
    const node::MinerData base_md = miner_data(kStallHeight, kNativePoolN);

    std::vector<T> ts;
    { T a{"major_version", true,  miner_data(kStallHeight, kDaemonPoolN)};
      a.md.major_version += 1;           ts.push_back(a); }
    { T b{"difficulty", true,     miner_data(kStallHeight, kDaemonPoolN)};
      b.md.difficulty.lo += 1;           ts.push_back(b); }
    { T c{"seed_hash", true,      miner_data(kStallHeight, kDaemonPoolN)};
      c.md.seed_hash[7] ^= 0x01;         ts.push_back(c); }
    { T d{"median_weight", true,  miner_data(kStallHeight, kDaemonPoolN)};
      d.md.median_weight += 1;           ts.push_back(d); }
    { T e{"already_generated_coins", true, miner_data(kStallHeight, kDaemonPoolN)};
      e.md.already_generated_coins += 1; ts.push_back(e); }

    CHECK(ts.size() + 1 == TEMPLATE_SEAM.required_equality_count(),
          "C0 the control perturbs every required EQUALITY field except the alignment "
          "key prev_id (%zu of %zu)", ts.size() + 1, TEMPLATE_SEAM.required_equality_count());

    BacklogFamineConfig fcfg;
    fcfg.consecutive = 6;
    fcfg.sustained_s = 30;

    for (const T& t : ts) {
        Leg leg;
        leg.serving     = "monerod";
        leg.served_md   = t.md;        // what the daemon served: one unit off
        leg.shadow_name = "native";
        leg.shadow_md   = base_md;     // what the native arm would have produced
        const Run run = drive(leg, 8, fcfg);

        CHECK(run.fail == run.samples.size() && run.clean == 0,
              "C1 one unit in %s must FAIL every sample: %zu fail / %zu clean",
              t.field, run.fail, run.clean);
        CHECK(has_diff(run.samples.front(), t.field),
              "C1 the differing field %s must be named in the diff", t.field);
        CHECK(run.samples.front().sentinel_tripped == t.sentinel,
              "C1 %s sentinel expectation", t.field);

        // ...and the ledger does what the soak's ledger does with a FAIL.
        GraduationKey key;
        key.c2pool_commit = "m4-ptpl-gate-kat";
        key.net           = "stagenet";
        M4GraduationLedger led(key, SoakThresholds::stagenet_m4());
        std::uint64_t t0 = 1789200000;
        for (const SeamResult& r : run.samples) {
            led.record(SoakPosture::ServeMonerodShadowNative, r, t0);
            t0 += 20;
        }
        const PostureLeg& L = led.leg(SoakPosture::ServeMonerodShadowNative);
        CHECK(L.clean_run == 0, "C2 %s: a real divergence must hold the streak at 0, got %llu",
              t.field, static_cast<unsigned long long>(L.clean_run));
        CHECK(led.state() == GraduationState::Revoked,
              "C2 %s: a sentinel divergence must revoke the key", t.field);
    }

    // C3. The alignment key. A different prev_id is two arms answering about two
    // different blocks, which is VOID rather than FAIL -- and VOID is not CLEAN,
    // so it still cannot carry a streak.
    {
        node::MinerData other = miner_data(kStallHeight, kDaemonPoolN);
        other.prev_id[3] ^= 0x01;
        Leg leg;
        leg.serving     = "monerod";
        leg.served_md   = other;
        leg.shadow_name = "native";
        leg.shadow_md   = base_md;
        const Run run = drive(leg, 4, fcfg);
        CHECK(run.clean == 0, "C3 a different prev_id may never be CLEAN, got %zu clean",
              run.clean);
        CHECK(run.voided == run.samples.size(),
              "C3 a different prev_id is VOID (different questions), got %zu void of %zu",
              run.voided, run.samples.size());
    }

    // C4. A different SELECTED TRANSACTION SET, on its own, is NOT a divergence.
    // This is the by-design difference the v37 relay rule creates, and it must
    // stay out of the verdict even though the digest row makes it visible.
    {
        node::MinerData daemon_pool = miner_data(kStallHeight, 3);
        for (std::size_t i = 0; i < daemon_pool.tx_backlog.size(); ++i)
            daemon_pool.tx_backlog[i].id = hash_of(static_cast<std::uint8_t>(0xd0 + i));

        Leg leg;
        leg.serving     = "monerod";
        leg.served_md   = daemon_pool;                            // three txs, all different
        leg.shadow_name = "native";
        leg.shadow_md   = miner_data(kStallHeight, kNativePoolN);  // five, none of them shared
        const Run run = drive(leg, 40, fcfg);
        CHECK(run.clean == run.samples.size(),
              "C4 two entirely disjoint pools must still be CLEAN: %zu/%zu",
              run.clean, run.samples.size());
        CHECK(has_diff(run.samples.front(), "selected_tx_set"),
              "C4 ...and the disjointness must be visible in the report");
    }
}

// ---------------------------------------------------------------------------
// SUITE D -- M2h is not given back.
// ---------------------------------------------------------------------------
static void suite_m2h_preserved() {
    head("D. leg 2 (serve=native): a starving native pool still REFUSES");

    BacklogFamineConfig fcfg;
    fcfg.consecutive = 6;
    fcfg.sustained_s = 30;

    // D1. The M2h regression, in the posture where it costs money: the native
    // arm serves empty templates while the daemon holds transactions.
    {
        Leg leg;
        leg.serving     = "native";
        leg.served_md   = miner_data(kStallHeight, 0);   // we serve nothing
        leg.shadow_name = "monerod";
        leg.shadow_md   = miner_data(kStallHeight, 5);   // the daemon holds five
        const Run run = drive(leg, 20, fcfg);
        CHECK(run.fail > 0, "D1 a starving SERVING native arm must still FAIL");
        CHECK(run.samples.back().sample.verdict == ParityVerdict::Fail,
              "D1 the run must end in refusal, got %s",
              to_string(run.samples.back().sample.verdict));
        CHECK(run.famine_tripped, "D1 the guard must be REFUSING: %s", run.famine_line.c_str());
        CHECK(run.clean <= fcfg.consecutive,
              "D1 only the pre-threshold samples may be clean, got %zu", run.clean);
    }

    // D2. ...and the fixed behaviour in the same posture stays clean, including
    // the propagation-skew case a naive gate would false-positive on.
    {
        Leg leg;
        leg.serving     = "native";
        leg.served_md   = miner_data(kStallHeight, 1);
        leg.shadow_name = "monerod";
        leg.shadow_md   = miner_data(kStallHeight, 50);
        const Run run = drive(leg, 20, fcfg);
        CHECK(run.clean == run.samples.size(),
              "D2 holding 1 of the daemon's 50 is skew, not famine: %zu/%zu clean",
              run.clean, run.samples.size());
    }

    // D3. A REAL native famine while the DAEMON is serving. It does not gate --
    // nothing is served from the native pool in that posture -- but it is now
    // CLASSIFIED and COUNTED, which is strictly more than the seat-fed judge
    // could do: fed by seat, this same shape arrived as `Fed` and was invisible.
    {
        Leg leg;
        leg.serving     = "monerod";
        leg.served_md   = miner_data(kStallHeight, 7);   // the daemon holds seven
        leg.shadow_name = "native";
        leg.shadow_md   = miner_data(kStallHeight, 0);   // the native pool holds none
        const Run run = drive(leg, 20, fcfg);
        CHECK(run.clean == run.samples.size(),
              "D3 a leg-1 native famine must not reset the graduation streak: %zu/%zu",
              run.clean, run.samples.size());
        CHECK(!run.famine_tripped, "D3 ...and must not trip the gate in this posture");
        CHECK(run.famine_line.find("advisory=20(starved 20)") != std::string::npos,
              "D3 ...but it must be COUNTED and visible: %s", run.famine_line.c_str());
    }

    // D4. The guard's own arithmetic, directly: the posture fence is a property
    // of the guard, not only of the way the oracle happens to call it.
    {
        BacklogFamineGuard g(fcfg);
        BacklogFamineGuard::Input in;
        in.aligned        = true;
        in.native_known   = true;
        in.native_backlog = 0;
        in.daemon_known   = true;
        in.daemon_backlog = 9;
        in.native_is_serving_arm = false;
        for (std::uint64_t i = 0; i < 50; ++i) {
            in.at_unix = 1000 + i * 60;
            const auto o = g.observe(in);
            CHECK(o.check.ok, "D4 an advisory sample must never fail (sample %llu)",
                  static_cast<unsigned long long>(i));
            CHECK(o.advisory, "D4 ...and must say it was advisory");
            CHECK(o.cls == BacklogSampleClass::Starved,
                  "D4 ...while still classifying the shape it saw, got %s", to_string(o.cls));
        }
        CHECK(!g.tripped(), "D4 fifty advisory samples must not trip the guard");
        CHECK(g.streak() == 0, "D4 ...and must not build the gating streak, got %zu", g.streak());
        CHECK(g.advisory() == 50 && g.advisory_starved() == 50,
              "D4 ...but must be counted: advisory=%llu starved=%llu",
              static_cast<unsigned long long>(g.advisory()),
              static_cast<unsigned long long>(g.advisory_starved()));

        // The same guard, same numbers, with the native arm SERVING: it trips.
        in.native_is_serving_arm = true;
        for (std::uint64_t i = 0; i < 6; ++i) {
            in.at_unix = 5000 + i * 60;
            g.observe(in);
        }
        CHECK(g.tripped(), "D4 the identical shape in the serving posture must trip");
    }
}

// ---------------------------------------------------------------------------
// SUITE E -- the table, and the ledger key.
// ---------------------------------------------------------------------------
static void suite_table() {
    head("E. the P-TPL table: what is scored, what is only rendered");

    auto regime_of = [](const char* name, Regime* out) {
        for (std::size_t i = 0; i < TEMPLATE_SEAM.count; ++i)
            if (std::strcmp(TEMPLATE_SEAM.fields[i].name, name) == 0) {
                *out = TEMPLATE_SEAM.fields[i].regime;
                return true;
            }
        return false;
    };

    Regime r{};
    CHECK(regime_of("tx_backlog_count", &r) && r == Regime::Measurement,
          "E1 tx_backlog_count must remain a MEASUREMENT (rendered, never scored)");
    CHECK(regime_of("selected_tx_set", &r) && r == Regime::NotComparable,
          "E2 the selected transaction set must be NOT-COMPARABLE, by recorded decision");
    CHECK(regime_of(kBacklogFamineCheck, &r) && r == Regime::Constraint,
          "E3 the famine SHAPE stays a CONSTRAINT");
    CHECK(TEMPLATE_SEAM.required_equality_count() == 6,
          "E4 the fix must not have changed what is required: %zu",
          TEMPLATE_SEAM.required_equality_count());

    // E5. No transaction merkle root, and no equality over the selected set, has
    // crept in. Either would re-create the same false divergence in a form that
    // looks more rigorous: the two arms hold different transactions by design.
    for (std::size_t i = 0; i < TEMPLATE_SEAM.count; ++i) {
        const FieldSpec& f = TEMPLATE_SEAM.fields[i];
        const bool tx_shaped = std::strstr(f.name, "tx_") != nullptr
                            || std::strstr(f.name, "merkle") != nullptr
                            || std::strcmp(f.name, "selected_tx_set") == 0;
        if (!tx_shaped) continue;
        CHECK(f.regime != Regime::Equality,
              "E5 '%s' must never be an EQUALITY: the two pools differ by design", f.name);
    }

    // E6. The ledger key moved, so no streak earned under the seat-fed judge can
    // be inherited by this one.
    CHECK(COMPARATOR_VERSION >= 4,
          "E6 the comparator version must have moved past 3, got %u",
          static_cast<unsigned>(COMPARATOR_VERSION));

    // E7. The digest is order-independent: two arms that hold the same
    // transactions in a different selection order must not read as different.
    {
        node::MinerData a = miner_data(kStallHeight, 4);
        node::MinerData b = a;
        std::vector<node::TxBacklogEntry> rev(b.tx_backlog.rbegin(), b.tx_backlog.rend());
        b.tx_backlog = rev;
        CHECK(tx_set_digest(a.tx_backlog) == tx_set_digest(b.tx_backlog),
              "E7 the digest must not depend on selection order");
        node::MinerData c = miner_data(kStallHeight, 4);
        c.tx_backlog[2].id = hash_of(0xfe);
        CHECK(tx_set_digest(a.tx_backlog) != tx_set_digest(c.tx_backlog),
              "E7 ...but must change when the SET changes");
    }
}

// ---------------------------------------------------------------------------
// SUITE F -- configurations with no native arm at all.
// ---------------------------------------------------------------------------
static void suite_no_native_arm() {
    head("F. a bring-up with no native arm makes no famine claim at all");

    BacklogFamineConfig fcfg;
    fcfg.consecutive = 2;
    fcfg.sustained_s = 10;

    // Two daemon arms (a monerod-vs-monerod bring-up). There is no native pool
    // to starve, and picking whichever seat is nearest to hand is the bug this
    // target exists to close, so the guard must make no claim.
    Leg leg;
    leg.serving     = "monerod";
    leg.served_md   = miner_data(kStallHeight, 0);
    leg.shadow_name = "monerod-b";
    leg.shadow_md   = miner_data(kStallHeight, 11);
    const Run run = drive(leg, 30, fcfg);

    CHECK(run.clean == run.samples.size(),
          "F1 a configuration with no native arm must stay CLEAN: %zu/%zu",
          run.clean, run.samples.size());
    CHECK(!run.famine_tripped, "F1 ...and must never trip the guard: %s",
          run.famine_line.c_str());
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::printf("xmr_native_m4_ptpl_backlog_gate_kat -- the M4 leg-1 P-TPL stall\n");
    std::printf("comparator version %u\n", static_cast<unsigned>(COMPARATOR_VERSION));

    suite_stall_case();
    suite_streak();
    suite_negative_control();
    suite_m2h_preserved();
    suite_table();
    suite_no_native_arm();

    std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
