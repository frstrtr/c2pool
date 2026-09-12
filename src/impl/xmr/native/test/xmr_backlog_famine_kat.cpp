// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_backlog_famine_kat.cpp
//
// THE P-TPL BLIND SPOT, AND THE CONSTRAINT THAT CLOSES IT.
//
// WHAT WENT WRONG, stated as the thing this target reproduces. The native
// transaction pool's relay gate had no production caller, so the pool refused
// every levin-relayed transaction. Every template the native arm served carried
// n_tx=0 and fees=0. And the parity oracle reported P-TPL CLEAN at every single
// height -- because the six required EQUALITY fields (prev_id, major_version,
// difficulty, seed_hash, median_weight, already_generated_coins) all agreed, and
// every one of them is a property of the PARENT BLOCK, not of the transaction
// set. The detector was standing next to the defect and could not see it.
//
// SUITE B IS THE HEART OF THIS FILE and is worth reading before the rest: it
// runs compare_seam TWICE over the SAME two arm observations -- six EQUALITY
// fields, identical, agreeing -- and gets CLEAN without the constraint and FAIL
// with it. Nothing else about the sample changes. That is the demonstration
// that the old judge could not have caught this and the new one must.
//
// SUITE C runs the real ParityOracle over the OLD behaviour: a native arm that
// serves an empty backlog while the monerod shadow arm holds five transactions,
// height after height. With the guard disabled -- which is exactly the pre-M2h
// comparator -- every sample comes out CLEAN. With it enabled, the samples turn
// FAIL once the evidence is in. SUITE D then runs the SAME oracle over the
// POST-RESTACK behaviour (the native arm carrying the backlog M1's gate fix lets
// it ingest) and requires that the constraint never fires: a gate that refuses
// the fixed code is not a gate, it is an outage.
//
// SUITES E and F cover the two accounting findings folded alongside: a daemon
// arm that SERVES without needing a pump (so pump==0 was never the same claim
// as native-only), and a daemon arm whose cache expires (so `have_` alone can
// no longer mean READY after the daemon died).
//
// SUITE G IS THE OTHER POSTURE, and it is the one the M4 stagenet soak actually
// runs first: serve = monerod, shadow = native. The version-3 oracle read its
// "native" count off the SERVED seat and its "daemon" count off the SHADOW
// seat, so in this posture the daemon's empty mempool was judged as a native
// famine: every P-TPL sample on a healthy, ingesting node came out FAIL (2,000
// of them, 13 hours, the graduation streak reset on each), and -- the mirror --
// a real native famine would have read as fed. G1 reproduces the live shape
// (daemon 0, native 5) and requires CLEAN; G2 is the mirror and requires the
// refusal to still fire from the shadow seat. Both fail on the version-3 rule.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/parity/xmr_backlog_famine.hpp"
#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"
#include "impl/xmr/native/parity/xmr_parity_oracle.hpp"
#include "impl/xmr/native/parity/xmr_parity_sources.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/native/template/xmr_resolved_miner_data.hpp"
#include "impl/xmr/native/template/xmr_template_arm.hpp"

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
// Fixtures.
// ---------------------------------------------------------------------------
static Hash hash_of(std::uint8_t b) {
    Hash h{};
    h.fill(b);
    return h;
}

// One MinerData with a controllable backlog size. Every other field is fixed,
// which is the whole point: the six EQUALITY rows must agree so that the only
// thing that can move the verdict is the backlog.
static node::MinerData miner_data(std::uint64_t height, std::size_t n_tx) {
    node::MinerData md;
    md.height                  = height;
    md.prev_id                 = hash_of(0x11);
    md.seed_hash               = hash_of(0x22);
    md.major_version           = 16;
    md.difficulty              = U128{/*lo=*/123456, /*hi=*/0};
    md.median_weight           = 300000;
    md.already_generated_coins = 18000000000000000ull;
    md.median_timestamp        = 1700000000;
    for (std::size_t i = 0; i < n_tx; ++i) {
        node::TxBacklogEntry e;
        e.id     = hash_of(static_cast<std::uint8_t>(0x40 + i));
        e.weight = 1500;
        e.fee    = 30000 + 1000 * static_cast<std::uint64_t>(i);
        md.tx_backlog.push_back(e);
    }
    return md;
}

static BacklogFamineGuard::Input starved_at(std::uint64_t t, std::uint64_t daemon_n = 5) {
    BacklogFamineGuard::Input in;
    in.aligned        = true;
    in.at_unix        = t;
    in.native_known   = true;
    in.native_backlog = 0;
    in.daemon_known   = true;
    in.daemon_backlog = daemon_n;
    return in;
}

// ---------------------------------------------------------------------------
// SUITE A -- the guard's own arithmetic.
// ---------------------------------------------------------------------------
static void suite_guard() {
    head("A. BacklogFamineGuard: when it counts, when it does not, when it trips");

    BacklogFamineConfig cfg;
    cfg.consecutive = 4;
    cfg.sustained_s = 30;

    // A1. A fed pool is not a famine, however big the shadow's pool is.
    {
        BacklogFamineGuard g(cfg);
        BacklogFamineGuard::Input in = starved_at(1000, 500);
        in.native_backlog = 1;
        const auto o = g.observe(in);
        CHECK(o.cls == BacklogSampleClass::Fed, "A1 class: got %s", to_string(o.cls));
        CHECK(o.check.ok, "A1 a fed pool must pass");
        CHECK(g.streak() == 0, "A1 streak must stay 0, got %zu", g.streak());
    }

    // A2. Both pools empty is AGREEMENT. This is the false positive that would
    // have made the gate unusable on a quiet chain, so it is pinned.
    {
        BacklogFamineGuard g(cfg);
        BacklogFamineGuard::Input in = starved_at(1000, 0);
        const auto o = g.observe(in);
        CHECK(o.cls == BacklogSampleClass::DaemonEmpty, "A2 class: got %s", to_string(o.cls));
        CHECK(o.check.ok, "A2 both-empty must pass");
        CHECK(g.streak() == 0, "A2 streak must stay 0");
    }

    // A3. Under-threshold starvation does NOT trip: the evidence is not in yet.
    {
        BacklogFamineGuard g(cfg);
        for (std::uint64_t i = 0; i < 3; ++i) {
            const auto o = g.observe(starved_at(1000 + i * 20));
            CHECK(o.cls == BacklogSampleClass::Starved, "A3 sample %llu must be starved",
                  static_cast<unsigned long long>(i));
            CHECK(o.check.ok, "A3 sample %llu must still pass (3 of 4)",
                  static_cast<unsigned long long>(i));
        }
        CHECK(g.streak() == 3, "A3 streak must be 3, got %zu", g.streak());
        CHECK(!g.tripped(), "A3 must not have tripped yet");
    }

    // A4. The threshold, crossed in both dimensions at once, TRIPS.
    {
        BacklogFamineGuard g(cfg);
        NamedCheck last;
        for (std::uint64_t i = 0; i < 4; ++i) last = g.observe(starved_at(1000 + i * 20)).check;
        CHECK(g.tripped(), "A4 must trip at 4 samples over 60s");
        CHECK(!last.ok, "A4 the constraint must be reported failing");
        CHECK(last.name == kBacklogFamineCheck, "A4 name: got %s", last.name.c_str());
        CHECK(last.detail.find("not ingesting") != std::string::npos,
              "A4 detail must say what is wrong: %s", last.detail.c_str());
    }

    // A5. THE BURST. Four starved samples in the same second satisfy the COUNT
    // bound and must still not trip, because a template-refresh burst can
    // observe one two-second propagation window four times.
    {
        BacklogFamineGuard g(cfg);
        for (int i = 0; i < 4; ++i) g.observe(starved_at(1000));
        CHECK(g.streak() == 4, "A5 streak must reach 4");
        CHECK(!g.tripped(), "A5 a burst inside one second must NOT trip the guard");
        // ...and the elapsed bound, once genuinely met, does trip it.
        g.observe(starved_at(1040));
        CHECK(g.tripped(), "A5 the same streak across 40s must trip");
    }

    // A6. Undecidable samples carry no information: they neither grow nor clear
    // the streak. Clearing on absence would hand a flaky shadow arm a way to
    // keep the streak at zero forever.
    {
        BacklogFamineGuard g(cfg);
        g.observe(starved_at(1000));
        g.observe(starved_at(1020));
        BacklogFamineGuard::Input mis = starved_at(1030);
        mis.aligned = false;
        const auto o = g.observe(mis);
        CHECK(o.cls == BacklogSampleClass::Undecidable, "A6 misaligned must be undecidable");
        CHECK(g.streak() == 2, "A6 streak must survive an undecidable sample, got %zu", g.streak());
        BacklogFamineGuard::Input nodaemon = starved_at(1040);
        nodaemon.daemon_known = false;
        CHECK(g.observe(nodaemon).cls == BacklogSampleClass::Undecidable,
              "A6 an unanswering daemon arm must be undecidable");
        CHECK(g.streak() == 2, "A6 streak must survive an unanswered daemon arm");
        CHECK(g.undecidable() == 2, "A6 undecidable count: got %llu",
              static_cast<unsigned long long>(g.undecidable()));
        // The streak still completes across the gap.
        g.observe(starved_at(1050));
        g.observe(starved_at(1060));
        CHECK(g.tripped(), "A6 the streak must still be able to complete across the gap");
    }

    // A7. THE REFUSAL IS STICKY, and only a real recovery clears it.
    {
        BacklogFamineGuard g(cfg);
        for (std::uint64_t i = 0; i < 4; ++i) g.observe(starved_at(1000 + i * 20));
        CHECK(g.tripped(), "A7 precondition: tripped");
        BacklogFamineGuard::Input mis = starved_at(1100);
        mis.aligned = false;
        CHECK(!g.observe(mis).check.ok, "A7 an undecidable sample must NOT clear the refusal");
        BacklogFamineGuard::Input fed = starved_at(1120);
        fed.native_backlog = 3;
        const auto o = g.observe(fed);
        CHECK(o.check.ok, "A7 a fed sample must clear the refusal");
        CHECK(!g.tripped(), "A7 tripped must clear");
        CHECK(g.streak() == 0, "A7 streak must clear");
    }

    // A8. No clock supplied (the oracle's ClockFn is optional and returns 0).
    // A guard that cannot trip is worse than no guard, so the count bound stands
    // alone and the detail says so rather than silently disabling the gate.
    {
        BacklogFamineGuard g(cfg);
        NamedCheck last;
        for (int i = 0; i < 4; ++i) last = g.observe(starved_at(0)).check;
        CHECK(g.tripped(), "A8 must trip on the count bound with a dead clock");
        CHECK(last.detail.find("no clock supplied") != std::string::npos,
              "A8 must disclose the degraded bound: %s", last.detail.c_str());
    }

    // A9. Disabled is disabled: an operator with no shadow arm is not told once
    // per refresh that nothing can be compared.
    {
        BacklogFamineConfig off = cfg;
        off.enabled = false;
        BacklogFamineGuard g(off);
        for (int i = 0; i < 20; ++i) CHECK(g.observe(starved_at(1000 + i * 60)).check.ok,
                                           "A9 a disabled guard must always pass");
        CHECK(!g.tripped(), "A9 a disabled guard must never trip");
    }
}

// ---------------------------------------------------------------------------
// SUITE B -- the same two observations, judged twice.
// ---------------------------------------------------------------------------
static void suite_verdict() {
    head("B. compare_seam: six EQUALITY fields agreeing, two different verdicts");

    const node::MinerData native_md = miner_data(100, 0);   // what the native arm served
    const node::MinerData shadow_md = miner_data(100, 5);   // what monerod was holding

    ArmObservation served = template_observation("native", native_md);
    ArmObservation shadow = template_observation("monerod", shadow_md);

    // B1. WITHOUT the constraint -- the pre-M2h judge. Every required EQUALITY
    // field agrees, because none of them is about the transaction set.
    {
        CompareOptions opt;
        opt.context = "B1 no constraint";
        const SeamResult r = compare_seam(TEMPLATE_SEAM, served, shadow, opt);
        CHECK(r.sample.verdict == ParityVerdict::Clean,
              "B1 the old judge must report CLEAN (this is the blind spot): got %s (%s)",
              to_string(r.sample.verdict), r.sample.note.c_str());
        CHECK(r.equality_compared == r.equality_required && r.equality_required == 6,
              "B1 all six EQUALITY fields must have been compared: %zu/%zu",
              r.equality_compared, r.equality_required);
        CHECK(r.equality_differed == 0, "B1 nothing may have differed");
    }

    // B2. WITH the constraint failing -- and NOTHING else about the sample is
    // different. Same arms, same fields, same agreement.
    {
        BacklogFamineConfig cfg;
        cfg.consecutive = 2;
        cfg.sustained_s = 10;
        BacklogFamineGuard g(cfg);
        NamedCheck c;
        for (std::uint64_t i = 0; i < 2; ++i) c = g.observe(starved_at(1000 + i * 20)).check;
        CHECK(!c.ok, "B2 precondition: the guard has tripped");

        CompareOptions opt;
        opt.context = "B2 with constraint";
        opt.constraints.push_back(c);
        const SeamResult r = compare_seam(TEMPLATE_SEAM, served, shadow, opt);
        CHECK(r.sample.verdict == ParityVerdict::Fail,
              "B2 the constraint must turn the SAME sample into a FAIL: got %s",
              to_string(r.sample.verdict));
        CHECK(r.constraints_failed == 1, "B2 exactly one constraint must have failed, got %zu",
              r.constraints_failed);
        // The refusal must be legible in the report, not merely counted.
        bool named = false;
        for (const auto& d : r.sample.fields)
            if (d.field == kBacklogFamineCheck) named = true;
        CHECK(named, "B2 the failing constraint must appear by name in the sample fields");
    }

    // B3. ...and a passing constraint leaves CLEAN reachable, so the gate is not
    // a permanent refusal wearing a constraint's clothes.
    {
        BacklogFamineGuard g;
        BacklogFamineGuard::Input in = starved_at(1000);
        in.native_backlog = 5;
        CompareOptions opt;
        opt.constraints.push_back(g.observe(in).check);
        const SeamResult r = compare_seam(TEMPLATE_SEAM, served, shadow, opt);
        CHECK(r.sample.verdict == ParityVerdict::Clean,
              "B3 a passing constraint must leave CLEAN reachable: got %s (%s)",
              to_string(r.sample.verdict), r.sample.note.c_str());
        CHECK(r.constraints_checked == 1, "B3 the constraint must have been checked");
    }

    // B4. The table row exists, and it is a Constraint -- not an Equality, which
    // would fire on ordinary propagation skew, and not a Measurement, which is
    // what made the blind spot.
    {
        bool found_shape = false, found_count = false;
        for (std::size_t i = 0; i < TEMPLATE_SEAM.count; ++i) {
            const FieldSpec& f = TEMPLATE_SEAM.fields[i];
            if (std::strcmp(f.name, kBacklogFamineCheck) == 0) {
                found_shape = true;
                CHECK(f.regime == Regime::Constraint, "B4 famine row must be a CONSTRAINT, got %s",
                      to_string(f.regime));
            }
            if (std::strcmp(f.name, "tx_backlog_count") == 0) {
                found_count = true;
                CHECK(f.regime == Regime::Measurement,
                      "B4 the COUNT must stay a MEASUREMENT, got %s", to_string(f.regime));
            }
        }
        CHECK(found_shape, "B4 TEMPLATE_FIELDS must carry the famine row");
        CHECK(found_count, "B4 TEMPLATE_FIELDS must still carry tx_backlog_count");
        CHECK(TEMPLATE_SEAM.required_equality_count() == 6,
              "B4 the constraint must not have changed the EQUALITY count: %zu",
              TEMPLATE_SEAM.required_equality_count());
        CHECK(COMPARATOR_VERSION >= 4,
              "B4 a new gate (v3) and a re-oriented rule (v4) must each move the ledger key: "
              "COMPARATOR_VERSION=%u",
              static_cast<unsigned>(COMPARATOR_VERSION));
    }
}

// ---------------------------------------------------------------------------
// The oracle harness: a shadow arm that simply reports a fixed MinerData.
// ---------------------------------------------------------------------------
namespace {

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

// Drive N serve samples through a real ParityOracle and return the verdicts.
// The SEATS are parameters: `served_arm` is the name the serving arm reports
// itself under, `shadow_arm` the shadow's. The two backlog counts are the
// SEATS' counts, so a posture is spelled by naming the seats.
struct DriveResult {
    std::vector<ParityVerdict> verdicts;
    std::string                last_famine_detail;   // the constraint's detail on the last sample
    bool                       famine_tripped = false;
};

static DriveResult drive_seats(bool guard_enabled,
                               const char* served_arm, std::size_t served_backlog,
                               const char* shadow_arm, std::size_t shadow_backlog,
                               int samples) {
    node::MinerData shadow_md = miner_data(100, shadow_backlog);
    FixedArm shadow(shadow_arm, shadow_md);

    ParityOracle::Deps deps;
    deps.shadow_arm = &shadow;

    ParityOracleConfig cfg;
    cfg.backlog_famine.enabled     = guard_enabled;
    cfg.backlog_famine.consecutive = 3;
    cfg.backlog_famine.sustained_s = 30;

    GraduationKey key;
    key.comparator_version = COMPARATOR_VERSION;
    GraduationPolicy policy;

    std::uint64_t clock = 1000;
    ParityOracle orc(deps, key, policy, cfg, [&clock] { return clock; });

    DriveResult out;
    for (int i = 0; i < samples; ++i) {
        const node::MinerData served = miner_data(100, served_backlog);
        MinerDataEpoch ep;
        ep.height  = served.height;
        ep.prev_id = served.prev_id;
        orc.on_serve(ep, served, served_arm);
        for (const SeamResult& r : orc.drain()) {
            if (r.sample.kind != ProbeKind::Template) continue;
            out.verdicts.push_back(r.sample.verdict);
            out.last_famine_detail.clear();
            for (const auto& d : r.sample.fields)
                if (d.field == kBacklogFamineCheck) out.last_famine_detail = d.served;
        }
        clock += 20;
    }
    out.famine_tripped = orc.backlog_famine_tripped();
    return out;
}

// The serve-native posture, as suites C and D have always spelled it.
static std::vector<ParityVerdict> drive(bool guard_enabled,
                                        std::size_t native_backlog,
                                        std::size_t shadow_backlog,
                                        int samples) {
    return drive_seats(guard_enabled, "native", native_backlog, "monerod", shadow_backlog, samples)
        .verdicts;
}

static std::size_t count_of(const std::vector<ParityVerdict>& v, ParityVerdict want) {
    std::size_t n = 0;
    for (ParityVerdict x : v) if (x == want) ++n;
    return n;
}

} // namespace

// ---------------------------------------------------------------------------
// SUITE C -- the old behaviour, through the real oracle.
// ---------------------------------------------------------------------------
static void suite_old_behaviour() {
    head("C. ParityOracle over the PRE-RESTACK behaviour (native 0, shadow 5)");

    // C1. The blind spot, reproduced. This is the run the M2 verifier actually
    // observed: the native pool ingesting nothing, height after height, and the
    // oracle calling it agreement every time.
    {
        const auto v = drive(/*guard_enabled=*/false, /*native=*/0, /*shadow=*/5, 8);
        CHECK(v.size() == 8, "C1 expected 8 template samples, got %zu", v.size());
        std::size_t clean = 0;
        for (ParityVerdict x : v) if (x == ParityVerdict::Clean) ++clean;
        CHECK(clean == v.size(),
              "C1 the OLD judge must call all %zu empty templates CLEAN (the blind spot), got %zu",
              v.size(), clean);
    }

    // C2. The same run with the constraint armed: it FIRES.
    {
        const auto v = drive(/*guard_enabled=*/true, /*native=*/0, /*shadow=*/5, 8);
        CHECK(v.size() == 8, "C2 expected 8 template samples, got %zu", v.size());
        std::size_t fail = 0, clean = 0;
        for (ParityVerdict x : v) {
            if (x == ParityVerdict::Fail)  ++fail;
            if (x == ParityVerdict::Clean) ++clean;
        }
        CHECK(fail > 0, "C2 the constraint must REFUSE a sustained empty native backlog");
        // The first two samples are legitimately clean: the evidence is not in
        // yet. What must not happen is the run ENDING clean.
        CHECK(v.back() == ParityVerdict::Fail,
              "C2 the run must end in refusal, got %s", to_string(v.back()));
        CHECK(clean + fail == v.size(), "C2 every sample must be judged, none VOID");
        CHECK(clean <= 3, "C2 at most the pre-threshold samples may be clean, got %zu", clean);
    }
}

// ---------------------------------------------------------------------------
// SUITE D -- the post-restack behaviour: the gate must stay quiet.
// ---------------------------------------------------------------------------
static void suite_new_behaviour() {
    head("D. ParityOracle over the POST-RESTACK behaviour (native carries the backlog)");

    // D1. The native pool holding transactions -- what M1's relay-gate fix makes
    // possible -- must never trip the guard, however long the run.
    {
        const auto v = drive(/*guard_enabled=*/true, /*native=*/5, /*shadow=*/5, 20);
        CHECK(v.size() == 20, "D1 expected 20 template samples, got %zu", v.size());
        std::size_t clean = 0;
        for (ParityVerdict x : v) if (x == ParityVerdict::Clean) ++clean;
        CHECK(clean == v.size(),
              "D1 the fixed behaviour must stay CLEAN for all %zu samples, got %zu",
              v.size(), clean);
    }

    // D2. A native pool that is merely SMALLER than the shadow's is not a
    // famine. This is the propagation-skew false positive, pinned shut.
    {
        const auto v = drive(/*guard_enabled=*/true, /*native=*/1, /*shadow=*/50, 20);
        std::size_t clean = 0;
        for (ParityVerdict x : v) if (x == ParityVerdict::Clean) ++clean;
        CHECK(clean == v.size(),
              "D2 holding 1 of the shadow's 50 must NOT be a refusal: %zu/%zu clean",
              clean, v.size());
    }

    // D3. A quiet chain -- both pools empty -- is agreement, for as long as it
    // lasts. A pool that refused to serve on a quiet network would be worse
    // than the bug this gate exists to catch.
    {
        const auto v = drive(/*guard_enabled=*/true, /*native=*/0, /*shadow=*/0, 20);
        std::size_t clean = 0;
        for (ParityVerdict x : v) if (x == ParityVerdict::Clean) ++clean;
        CHECK(clean == v.size(), "D3 a quiet chain must stay CLEAN: %zu/%zu", clean, v.size());
    }
}

// ---------------------------------------------------------------------------
// SUITE G -- the OTHER posture: serve = monerod, shadow = native (M4 leg 1).
//
// Every scenario here is the same guard, the same table, the same two arms as
// suites C and D -- with the seats swapped, which is exactly what --serve-arm
// monerod does. Nothing about the famine question changes when the seats do;
// the version-3 rule was answering a different question in this posture.
// ---------------------------------------------------------------------------
static void suite_other_posture() {
    head("G. ParityOracle in the serve-monerod posture (the M4 leg-1 seat order)");

    // G1. THE LIVE STAGENET SHAPE, reproduced: the daemon's mempool is empty
    // (get_miner_data.tx_backlog absent), the native pool -- the shadow in this
    // posture -- holds five relayed transactions the daemon does not. A native
    // pool that HOLDS transactions is fed, not starved, whichever seat it is
    // in. Under the version-3 rule this run went FAIL from the third sample on
    // and stayed there; it must be CLEAN throughout.
    {
        const DriveResult r = drive_seats(/*guard_enabled=*/true,
                                          "monerod", /*daemon=*/0,
                                          "native",  /*native=*/5, 20);
        CHECK(r.verdicts.size() == 20, "G1 expected 20 template samples, got %zu", r.verdicts.size());
        const std::size_t clean = count_of(r.verdicts, ParityVerdict::Clean);
        CHECK(clean == r.verdicts.size(),
              "G1 daemon 0 / native 5 with monerod serving must be CLEAN for all %zu samples, got %zu "
              "(the seat-swap false famine)",
              r.verdicts.size(), clean);
        CHECK(!r.famine_tripped, "G1 the guard must not have tripped");
    }

    // G2. THE MIRROR: a real famine, seen from the shadow seat. The daemon
    // (serving) holds transactions, the native pool (shadow) holds nothing,
    // sustained. Under the version-3 rule this read as FED -- the served seat's
    // count was non-zero -- so leg 1 could not have caught the regression the
    // constraint exists for. It must refuse, and it must say which arm is
    // starved without claiming the native arm served anything.
    {
        const DriveResult r = drive_seats(/*guard_enabled=*/true,
                                          "monerod", /*daemon=*/5,
                                          "native",  /*native=*/0, 8);
        CHECK(r.verdicts.size() == 8, "G2 expected 8 template samples, got %zu", r.verdicts.size());
        CHECK(count_of(r.verdicts, ParityVerdict::Fail) > 0,
              "G2 a sustained empty NATIVE pool must be refused from the shadow seat too");
        CHECK(!r.verdicts.empty() && r.verdicts.back() == ParityVerdict::Fail,
              "G2 the run must end in refusal, got %s",
              r.verdicts.empty() ? "nothing" : to_string(r.verdicts.back()));
        CHECK(count_of(r.verdicts, ParityVerdict::Clean) <= 3,
              "G2 at most the pre-threshold samples may be clean, got %zu",
              count_of(r.verdicts, ParityVerdict::Clean));
        CHECK(r.famine_tripped, "G2 the guard must be tripped at the end of the run");
        CHECK(r.last_famine_detail.find("not ingesting") != std::string::npos,
              "G2 the detail must name the defect: %s", r.last_famine_detail.c_str());
        CHECK(r.last_famine_detail.find("shadow in this posture") != std::string::npos,
              "G2 the detail must say the native arm is the shadow, not that it served: %s",
              r.last_famine_detail.c_str());
        CHECK(r.last_famine_detail.find("every template served is empty") == std::string::npos,
              "G2 the detail must not claim the native arm served anything: %s",
              r.last_famine_detail.c_str());
    }

    // G3. A quiet chain in this posture is agreement, exactly as in D3.
    {
        const DriveResult r = drive_seats(true, "monerod", 0, "native", 0, 20);
        CHECK(count_of(r.verdicts, ParityVerdict::Clean) == r.verdicts.size() && r.verdicts.size() == 20,
              "G3 both empty must stay CLEAN: %zu/%zu",
              count_of(r.verdicts, ParityVerdict::Clean), r.verdicts.size());
    }

    // G4. Propagation skew in this posture: the daemon holds 50, the native
    // pool holds 1. Fed is fed.
    {
        const DriveResult r = drive_seats(true, "monerod", 50, "native", 1, 20);
        CHECK(count_of(r.verdicts, ParityVerdict::Clean) == r.verdicts.size() && r.verdicts.size() == 20,
              "G4 native 1 / daemon 50 must NOT be a refusal: %zu/%zu clean",
              count_of(r.verdicts, ParityVerdict::Clean), r.verdicts.size());
    }

    // G5. The same two shapes in the serve-native posture still judge as
    // suites C and D require -- the re-orientation must not have moved leg 2.
    {
        const auto fed     = drive(true, /*native=*/5, /*daemon=*/0, 20);
        const auto starved = drive(true, /*native=*/0, /*daemon=*/5, 8);
        CHECK(count_of(fed, ParityVerdict::Clean) == 20,
              "G5 native 5 / daemon 0 with native serving must be CLEAN: %zu/20",
              count_of(fed, ParityVerdict::Clean));
        CHECK(!starved.empty() && starved.back() == ParityVerdict::Fail,
              "G5 native 0 / daemon 5 with native serving must still be refused");
    }

    // G6. Arm identity is resolved by NAME, and a pair the oracle cannot tell
    // apart is undecidable: it neither refuses nor manufactures evidence. Two
    // arms that both call themselves "native", and an arm with a name the
    // guard does not know, must leave the six-field verdict alone.
    {
        const DriveResult twins = drive_seats(true, "native", 0, "native", 5, 8);
        CHECK(count_of(twins.verdicts, ParityVerdict::Clean) == twins.verdicts.size(),
              "G6 two native-named arms: undecidable, must not refuse (%zu/%zu clean)",
              count_of(twins.verdicts, ParityVerdict::Clean), twins.verdicts.size());
        CHECK(!twins.famine_tripped, "G6 two native-named arms must not trip the guard");

        const DriveResult unknown = drive_seats(true, "monerod", 5, "replay", 0, 8);
        CHECK(count_of(unknown.verdicts, ParityVerdict::Clean) == unknown.verdicts.size(),
              "G6 an unknown shadow arm name: undecidable, must not refuse (%zu/%zu clean)",
              count_of(unknown.verdicts, ParityVerdict::Clean), unknown.verdicts.size());
        CHECK(!unknown.famine_tripped, "G6 an unknown arm name must not trip the guard");

        CHECK(is_native_arm_name("native") && !is_native_arm_name("monerod")
              && !is_native_arm_name("shadow") && !is_native_arm_name("none")
              && !is_native_arm_name(nullptr),
              "G6 is_native_arm_name");
        CHECK(is_daemon_arm_name("monerod") && is_daemon_arm_name("monerod (fallback from native)")
              && !is_daemon_arm_name("native") && !is_daemon_arm_name("mon")
              && !is_daemon_arm_name(nullptr),
              "G6 is_daemon_arm_name");
    }

    // G7. A refusal earned in one posture is cleared by a fed sample in the
    // other: the guard's state is about the native pool, not about the seat.
    {
        BacklogFamineConfig cfg;
        cfg.consecutive = 2;
        cfg.sustained_s = 10;
        BacklogFamineGuard g(cfg);
        BacklogFamineGuard::Input shadow_starved = starved_at(1000);
        shadow_starved.native_serving = false;
        g.observe(shadow_starved);
        shadow_starved.at_unix = 1020;
        const auto tripped = g.observe(shadow_starved);
        CHECK(g.tripped() && !tripped.check.ok, "G7 precondition: tripped from the shadow seat");
        CHECK(tripped.check.detail.find("shadow in this posture") != std::string::npos,
              "G7 the shadow-seat wording: %s", tripped.check.detail.c_str());
        BacklogFamineGuard::Input fed = starved_at(1040);
        fed.native_backlog = 2;
        fed.native_serving = true;
        CHECK(g.observe(fed).check.ok && !g.tripped(),
              "G7 a fed native pool clears the refusal whichever seat it now sits in");
    }
}

// ---------------------------------------------------------------------------
// SUITE E -- which arm SERVED, which is not the same as which arm was pumped.
// ---------------------------------------------------------------------------
static void suite_served_by() {
    head("E. ResolvedMinerDataSource: a daemon-served template with pumps == 0");

    // A native arm that is NOT ready, a daemon arm whose cache is already warm,
    // and fallback ON. The resolver hands back the daemon arm for free, the
    // pump branch is never entered -- and the old accounting would have reported
    // "template-path get_miner_data=0" over a template the DAEMON built.
    class UnreadyArm final : public IMinerDataSource {
    public:
        const char* name() const override { return "native"; }
        MinerDataReadiness readiness() const override {
            MinerDataReadiness r;
            r.why = "native: no verified tip yet";
            return r;
        }
        MinerDataEpoch epoch() const override { return {}; }
        std::optional<node::MinerData> snapshot(std::string* why) const override {
            if (why) *why = "native: no verified tip yet";
            return std::nullopt;
        }
        const std::vector<std::uint8_t>* tx_body(const Hash&) const override { return nullptr; }
    };

    UnreadyArm native;
    FixedArm   daemon("monerod", miner_data(100, 4));

    tmpl::TemplateArmConfig cfg;
    cfg.serve    = TemplateArm::Native;
    cfg.fallback = true;
    // ArmResolver's argument order is (monerod, native).
    tmpl::ArmResolver resolver(&daemon, &native, cfg);

    bool pumped = false;
    tmpl::ResolvedMinerDataSource src(resolver, [&pumped](std::string*) {
        pumped = true;
        return true;
    });

    std::string why;
    CHECK(src.resolve(&why), "E1 the resolver must fall back and serve: %s", why.c_str());
    CHECK(!pumped, "E1 precondition: no pump was needed (the daemon cache was warm)");
    CHECK(src.daemon_pumps() == 0, "E1 pump count must be 0, got %llu",
          static_cast<unsigned long long>(src.daemon_pumps()));
    CHECK(src.served_by_daemon() == 1,
          "E1 the DAEMON served this template and must be counted, got %llu",
          static_cast<unsigned long long>(src.served_by_daemon()));
    CHECK(src.served_by_native() == 0, "E1 the native arm served nothing");
    CHECK(std::strcmp(src.name(), "monerod") == 0, "E1 the latched arm must be the daemon");

    // E2. And the native-only case: the native arm serves, for free, forever.
    {
        FixedArm ok_native("native", miner_data(100, 7));
        FixedArm any_daemon("monerod", miner_data(100, 4));
        tmpl::TemplateArmConfig c2;
        c2.serve    = TemplateArm::Native;
        c2.fallback = false;
        tmpl::ArmResolver r2(&any_daemon, &ok_native, c2);
        tmpl::ResolvedMinerDataSource s2(r2, [](std::string*) { return true; });
        for (int i = 0; i < 10; ++i) CHECK(s2.resolve(nullptr), "E2 resolve %d", i);
        CHECK(s2.served_by_native() == 10, "E2 native must have served all 10, got %llu",
              static_cast<unsigned long long>(s2.served_by_native()));
        CHECK(s2.served_by_daemon() == 0, "E2 the daemon must have served nothing");
        CHECK(s2.daemon_pumps() == 0, "E2 and cost no round trip");
    }
}

// ---------------------------------------------------------------------------
// SUITE F -- the daemon arm's cache expires.
// ---------------------------------------------------------------------------
namespace {
class ScriptedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit ScriptedTransport(std::string body) : body_(std::move(body)) {}
    void fail(std::string e) { error_ = std::move(e); }
    void ok() { error_.clear(); }
    void rpc_post(const std::string&,
                  std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r;
        if (!error_.empty()) { r.error = error_; cb(r); return; }
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&,
                       std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_, error_;
};
} // namespace

static void suite_staleness() {
    head("F. MonerodMinerDataSource: have_ alone may no longer mean READY");

    // A minimal well-formed get_miner_data reply. The production parser is the
    // one under it, deliberately: a hand-rolled second parser here would be
    // testing this file rather than the arm.
    const std::string body =
        R"({"id":"0","jsonrpc":"2.0","result":{)"
        R"("major_version":16,"height":100,)"
        R"("prev_id":"1111111111111111111111111111111111111111111111111111111111111111",)"
        R"("seed_hash":"2222222222222222222222222222222222222222222222222222222222222222",)"
        R"("difficulty":"0x1e240","median_weight":300000,)"
        R"("already_generated_coins":18000000000000000,"tx_backlog":[],"status":"OK","untrusted":false}})";

    ScriptedTransport tx(body);
    std::uint64_t now_ms = 1000;

    tmpl::MonerodArmConfig acfg;
    acfg.max_age_ms = 120000;
    tmpl::MonerodMinerDataSource arm(tx, acfg, [&now_ms] { return now_ms; });

    std::string why;
    CHECK(arm.readiness().why.find("no miner data yet") != std::string::npos,
          "F1 an unpolled arm must be fail-closed");
    CHECK(arm.poll(&why), "F1 the first poll must succeed: %s", why.c_str());
    CHECK(arm.readiness().ok(), "F2 a fresh cache is READY");
    CHECK(arm.snapshot(&why).has_value(), "F2 and answers");
    CHECK(!arm.stale(), "F2 and is not stale");

    // The daemon dies. Every subsequent poll fails, and poll() deliberately
    // leaves the cache in place so a blip does not cost a template.
    tx.fail("connection refused");
    now_ms += 60000;                       // 60 s: inside the bound
    CHECK(!arm.poll(&why), "F3 a dead daemon must fail the poll");
    CHECK(arm.readiness().ok(), "F3 a 60s-old cache is still inside the bound");
    CHECK(arm.age_ms() == 60000, "F3 age must be 60000ms, got %llu",
          static_cast<unsigned long long>(arm.age_ms()));

    now_ms += 61000;                       // 121 s: past it
    CHECK(!arm.readiness().ok(), "F4 a cache older than the bound must NOT be READY");
    CHECK(arm.stale(), "F4 and must say so");
    CHECK(arm.readiness().why.find("121s old") != std::string::npos,
          "F4 the reason must carry the age: %s", arm.readiness().why.c_str());
    CHECK(arm.readiness().why.find("connection refused") != std::string::npos,
          "F4 ...and the daemon's own last words: %s", arm.readiness().why.c_str());
    CHECK(!arm.snapshot(&why).has_value(), "F5 snapshot must refuse an expired cache too");

    // And the arm comes back when the daemon does.
    tx.ok();
    CHECK(arm.poll(&why), "F6 the daemon returns");
    CHECK(arm.readiness().ok(), "F6 and the arm is READY again");
    CHECK(arm.age_ms() == 0, "F6 the cache is fresh");

    // F7. The bound is an operator's number, and 0 means the old behaviour --
    // available, but never by accident.
    {
        ScriptedTransport t2(body);
        std::uint64_t t = 0;
        tmpl::MonerodArmConfig unbounded;
        unbounded.max_age_ms = 0;
        tmpl::MonerodMinerDataSource a2(t2, unbounded, [&t] { return t; });
        CHECK(a2.poll(nullptr), "F7 poll");
        t += 86400000;                      // a day
        CHECK(a2.readiness().ok(), "F7 max_age_ms=0 disables the bound, by explicit choice");
        CHECK(!a2.stale(), "F7 and nothing is ever stale under it");
    }
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::printf("xmr_native_backlog_famine_kat -- the P-TPL backlog CONSTRAINT\n");
    std::printf("comparator version %u\n", static_cast<unsigned>(COMPARATOR_VERSION));

    suite_guard();
    suite_verdict();
    suite_old_behaviour();
    suite_new_behaviour();
    suite_other_posture();
    suite_served_by();
    suite_staleness();

    std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
