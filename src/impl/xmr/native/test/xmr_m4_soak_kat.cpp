// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_m4_soak_kat.cpp
//
// M4: THE STREAK STATE MACHINE, THE LEDGER, AND THE REFUSAL.
//
// The M4 gate is a claim about a PROCESS, not about a function: two postures,
// each soaked until a streak of CLEAN samples is long enough, wide enough in
// blocks and old enough in wall clock, with zero non-CLEAN samples in the
// window. Every way that claim has gone wrong before is a way of accruing
// credit that was not earned, so almost every check below is a check that
// something did NOT count:
//
//   SUITE A  the streak machine. CLEAN accrues; FAIL and SERVED-MISMATCH reset
//            to zero (there is no budget of allowed failures); VOID neither
//            accrues nor resets, but a RUN of VOIDs past the cap resets anyway,
//            because a leg that stopped producing judgeable samples is a probe
//            that stopped firing and not a streak quietly holding; a reorg
//            walking the tip backwards contributes no block.
//
//   SUITE B  graduation. One leg is not two. A tip-only stream never satisfies
//            a template floor, so the cheap seam cannot carry the expensive one.
//            A key with no commit, or with a daemon version nobody ever
//            observed, cannot graduate at all. And a FAIL arriving AFTER
//            graduation takes the qualification away again, loudly.
//
//   SUITE C  persistence, including the M1 LESSON made mechanical: a ledger
//            written under comparator v2 is REFUSED by a v3 binary, and the
//            streak restarts from zero. Also refused: another commit, another
//            daemon, another network. A missing file is not an error.
//
//   SUITE D  the negative control itself, end to end through the REAL
//            comparator: two arm observations that agree on all seven required
//            P-TIP fields compare CLEAN, the injector perturbs ONE of them by
//            ONE UNIT, and the same comparator now FAILs -- and the ledger
//            resets the streak, clears the qualification and refuses to
//            graduate. That is the mechanism the live regtest mini-soak
//            exercises; here it is pinned without a daemon.
//
//   SUITE E  the driver: batches to ledger movement, a transcript with the
//            context that makes a verdict readable later, P-POOL samples
//            skipped (M1's seam is not part of the M4 criterion and must not
//            pad a streak), and an empty drain counted as silence rather than
//            as calm.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// STL only: no RandomX, no daemon, no network, no clock (the ledger takes unix
// seconds from the caller, so 72 hours pass in microseconds).
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "impl/xmr/native/parity/xmr_graduation_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"
#include "impl/xmr/native/parity/xmr_soak_driver.hpp"

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
static SeamResult sample(ProbeKind kind, ParityVerdict v, std::uint64_t height,
                         const char* note = "") {
    SeamResult r;
    r.sample.kind    = kind;
    r.sample.verdict = v;
    r.sample.height  = height;
    r.sample.note    = note;
    r.sample.classes.push_back(HeightClass::Steady);
    return r;
}

// Small enough that a KAT can satisfy it by hand, structurally identical to the
// stagenet shape.
static SoakThresholds tiny() {
    SoakThresholds t;
    t.min_clean_samples  = 6;
    t.min_blocks         = 3;
    t.min_seconds        = 30;
    t.min_tip_clean      = 3;
    t.min_template_clean = 2;
    t.max_void_run       = 4;
    return t;
}

static GraduationKey key_of(const char* commit = "abc1234",
                            const char* daemon = "0.18.5.1",
                            const char* net    = "regtest") {
    GraduationKey k;
    k.c2pool_commit   = commit;
    k.monerod_version = daemon;
    k.net             = net;
    return k;
}

// Feed one leg an alternating TIP/TEMPLATE stream of CLEAN samples, one block
// and `dt` seconds apart, and hand back the unix clock where it stopped.
static std::uint64_t run_clean(M4GraduationLedger& L, SoakPosture p, int n,
                               std::uint64_t h0 = 100, std::uint64_t t0 = 1000,
                               std::uint64_t dt = 10) {
    std::uint64_t t = t0;
    for (int i = 0; i < n; ++i) {
        const ProbeKind k = (i % 2 == 0) ? ProbeKind::Tip : ProbeKind::Template;
        L.record(p, sample(k, ParityVerdict::Clean, h0 + static_cast<std::uint64_t>(i)), t);
        t += dt;
    }
    return t;
}

// ---------------------------------------------------------------------------
// SUITE A -- the streak state machine.
// ---------------------------------------------------------------------------
static void suite_streak() {
    head("A: the streak state machine");
    const SoakPosture P = SoakPosture::ServeNativeShadowMonerod;

    // A1: CLEAN accrues samples, blocks and wall clock, and splits per seam.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, P, 6, 100, 1000, 10);
        const PostureLeg& leg = L.leg(P);
        CHECK(leg.clean_run == 6, "A1 clean_run=%llu want 6", (unsigned long long)leg.clean_run);
        // Six samples at heights 100..105: five FORWARD STEPS after the first.
        CHECK(leg.run_blocks == 5, "A1 run_blocks=%llu want 5", (unsigned long long)leg.run_blocks);
        CHECK(leg.run_seconds() == 50, "A1 span=%llu want 50", (unsigned long long)leg.run_seconds());
        CHECK(leg.run_tip_clean == 3, "A1 tip=%llu want 3", (unsigned long long)leg.run_tip_clean);
        CHECK(leg.run_tmpl_clean == 3, "A1 tpl=%llu want 3", (unsigned long long)leg.run_tmpl_clean);
        CHECK(leg.run_height_lo == 100 && leg.run_height_hi == 105,
              "A1 heights %llu..%llu", (unsigned long long)leg.run_height_lo,
              (unsigned long long)leg.run_height_hi);
        CHECK(leg.fail == 0 && leg.voided == 0, "A1 nothing else moved");
        CHECK(L.leg(SoakPosture::ServeMonerodShadowNative).clean_run == 0,
              "A1 the OTHER posture is untouched: two legs, two experiments");
    }

    // A2: one FAIL resets the whole run. Not a decrement, not an average.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, P, 6, 100, 1000, 10);
        CHECK(L.leg(P).clean_run == 6, "A2 precondition");
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Fail, 106, "difficulty differed"), 1060);
        const PostureLeg& leg = L.leg(P);
        CHECK(leg.clean_run == 0,      "A2 streak reset to 0, got %llu", (unsigned long long)leg.clean_run);
        CHECK(leg.run_blocks == 0,     "A2 blocks reset");
        CHECK(leg.run_seconds() == 0,  "A2 wall clock reset");
        CHECK(leg.run_tip_clean == 0 && leg.run_tmpl_clean == 0, "A2 per-seam reset");
        CHECK(leg.resets == 1,         "A2 the reset is COUNTED, not silent");
        CHECK(leg.fail == 1,           "A2 the failure is counted");
        CHECK(leg.clean == 6,          "A2 lifetime clean survives: the run died, the history did not");
        CHECK(leg.last_reset_why.find("FAIL") != std::string::npos,
              "A2 the reason is recorded: '%s'", leg.last_reset_why.c_str());
        CHECK(!L.graduated(), "A2 and it is not graduated");
    }

    // A3: SERVED-MISMATCH resets AND revokes -- it is the worse verdict.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, P, 4, 100, 1000, 10);
        L.record(P, sample(ProbeKind::Template, ParityVerdict::ServedMismatch, 104), 1040);
        CHECK(L.leg(P).clean_run == 0, "A3 streak reset");
        CHECK(L.state() == GraduationState::Revoked, "A3 and the KEY is revoked");
        CHECK(!L.revocations().empty(), "A3 with a recorded reason");
        // Revocation is terminal for the key: more clean samples do not undo it.
        run_clean(L, P, 20, 200, 2000, 10);
        CHECK(L.state() == GraduationState::Revoked, "A3 revocation is terminal for this key");
        CHECK(!L.graduated(), "A3 and nothing graduates after it");
    }

    // A4: VOID neither accrues nor resets. It has never been agreement.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, P, 4, 100, 1000, 10);
        const std::uint64_t before = L.leg(P).clean_run;
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Void, 104, "arms on different tips"), 1040);
        CHECK(L.leg(P).clean_run == before, "A4 VOID did not accrue and did not reset");
        CHECK(L.leg(P).voided == 1, "A4 but it IS counted");
        CHECK(L.leg(P).samples == 4, "A4 and it is not a judged sample");
    }

    // A5: a RUN of VOIDs past the cap resets. Silence is not a streak.
    {
        M4GraduationLedger L(key_of(), tiny());          // max_void_run = 4
        run_clean(L, P, 4, 100, 1000, 10);
        std::uint64_t t = 1040;
        for (int i = 0; i < 4; ++i)
            L.record(P, sample(ProbeKind::Tip, ParityVerdict::Void, 104), t += 10);
        CHECK(L.leg(P).clean_run == 4, "A5 four VOIDs is exactly at the cap, streak stands");
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Void, 104), t += 10);
        CHECK(L.leg(P).clean_run == 0, "A5 the fifth breaks it: the leg went quiet");
        CHECK(L.leg(P).resets == 1, "A5 counted as a reset");
        CHECK(L.leg(P).last_reset_why.find("VOID") != std::string::npos,
              "A5 and named as VOID rather than as a failure: '%s'",
              L.leg(P).last_reset_why.c_str());
    }
    // ...and a CLEAN sample in the middle clears the void run.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, P, 2, 100, 1000, 10);
        std::uint64_t t = 1020;
        for (int i = 0; i < 4; ++i)
            L.record(P, sample(ProbeKind::Tip, ParityVerdict::Void, 102), t += 10);
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Clean, 103), t += 10);
        for (int i = 0; i < 4; ++i)
            L.record(P, sample(ProbeKind::Tip, ParityVerdict::Void, 103), t += 10);
        CHECK(L.leg(P).clean_run == 3, "A5b a judged sample resets the void RUN, got %llu",
              (unsigned long long)L.leg(P).clean_run);
        CHECK(L.leg(P).resets == 0, "A5b and nothing was reset");
    }

    // A6: a reorg walks the tip backwards and contributes no block. Forward
    // progress only -- the conservative direction.
    {
        M4GraduationLedger L(key_of(), tiny());
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Clean, 100), 1000);
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Clean, 101), 1010);
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Clean, 100), 1020);  // reorg
        L.record(P, sample(ProbeKind::Tip, ParityVerdict::Clean, 101), 1030);  // re-adopt
        CHECK(L.leg(P).clean_run == 4, "A6 four clean samples");
        CHECK(L.leg(P).run_blocks == 1, "A6 but ONE block of forward progress, got %llu",
              (unsigned long long)L.leg(P).run_blocks);
    }

    // A7: no_sample drains are counted and touch nothing.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, P, 3, 100, 1000, 10);
        for (int i = 0; i < 5; ++i) L.note_no_sample(P);
        CHECK(L.no_sample_drains(P) == 5, "A7 no-sample drains counted");
        CHECK(L.leg(P).clean_run == 3, "A7 and the streak is untouched by them");
    }
}

// ---------------------------------------------------------------------------
// SUITE B -- what graduation requires.
// ---------------------------------------------------------------------------
static void suite_graduation() {
    head("B: graduation requires BOTH postures, both seams, and a complete key");

    // B1: one leg is not two.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        CHECK(L.leg(SoakPosture::ServeMonerodShadowNative).qualified,
              "B1 the soaked leg qualified");
        CHECK(!L.graduated(), "B1 but one posture is not graduation");
        const std::vector<std::string> sf = L.shortfalls();
        bool names_other = false;
        for (const std::string& s : sf)
            if (s.find("serve-native") != std::string::npos) names_other = true;
        CHECK(names_other, "B1 and the shortfall names the posture that has not run");
    }

    // B2: both legs, and the graduation is stamped.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        const std::uint64_t t = run_clean(L, SoakPosture::ServeNativeShadowMonerod,
                                          8, 200, 5000, 10);
        CHECK(L.graduated(), "B2 both legs qualified -> GRADUATED");
        CHECK(L.state() == GraduationState::Graduated, "B2 state");
        CHECK(L.graduated_unix() != 0 && L.graduated_unix() < t, "B2 stamped with when");
        CHECK(L.shortfalls().empty(), "B2 and nothing is outstanding");
    }

    // B3: a tip-only stream never satisfies the template floor. The cheap seam
    // cannot carry the expensive one, which is the whole reason M4 names P-TPL.
    {
        M4GraduationLedger L(key_of(), tiny());
        std::uint64_t t = 1000;
        for (int i = 0; i < 40; ++i) {
            L.record(SoakPosture::ServeMonerodShadowNative,
                     sample(ProbeKind::Tip, ParityVerdict::Clean,
                            100 + static_cast<std::uint64_t>(i)), t);
            t += 10;
        }
        const PostureLeg& leg = L.leg(SoakPosture::ServeMonerodShadowNative);
        CHECK(leg.clean_run == 40, "B3 a long clean streak");
        CHECK(leg.run_tmpl_clean == 0, "B3 with no template sample in it");
        CHECK(!leg.qualified, "B3 does NOT qualify the leg");
        bool names_tpl = false;
        for (const std::string& s : L.shortfalls())
            if (s.find("P-TPL") != std::string::npos || s.find("TPL") != std::string::npos
                || s.find("tpl") != std::string::npos) names_tpl = true;
        CHECK(names_tpl, "B3 and says so");
    }

    // B4: an incomplete key cannot graduate, however clean the samples are.
    {
        GraduationKey k = key_of();
        k.monerod_version = "unknown";              // the daemon never answered
        M4GraduationLedger L(k, tiny());
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        run_clean(L, SoakPosture::ServeNativeShadowMonerod, 8, 200, 5000, 10);
        CHECK(!L.graduated(), "B4 a graduation that cannot name the daemon it beat is not one");
        bool names_key = false;
        for (const std::string& s : L.shortfalls())
            if (s.find("monerod version") != std::string::npos) names_key = true;
        CHECK(names_key, "B4 and the shortfall says which key is missing");

        // ...and once the daemon answers, the same samples do graduate.
        L.bind_monerod_version("0.18.5.1", 9000);
        run_clean(L, SoakPosture::ServeNativeShadowMonerod, 1, 300, 9000, 10);
        CHECK(L.key().monerod_version == "0.18.5.1", "B4 version bound on first sight");
        CHECK(L.graduated(), "B4 and the key is now complete");
    }
    {
        GraduationKey k = key_of();
        k.c2pool_commit = "";
        M4GraduationLedger L(k, tiny());
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        run_clean(L, SoakPosture::ServeNativeShadowMonerod, 8, 200, 5000, 10);
        CHECK(!L.graduated(), "B4b a graduation that cannot name the code it judged is not one");
    }

    // B5: a FAIL AFTER graduation takes the qualification away again.
    {
        M4GraduationLedger L(key_of(), tiny());
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        run_clean(L, SoakPosture::ServeNativeShadowMonerod, 8, 200, 5000, 10);
        CHECK(L.graduated(), "B5 precondition: graduated");
        const std::size_t revs = L.revocations().size();
        L.record(SoakPosture::ServeNativeShadowMonerod,
                 sample(ProbeKind::Tip, ParityVerdict::Fail, 210, "seed_hash differed"), 5200);
        CHECK(!L.graduated(), "B5 one later FAIL and it is no longer graduated");
        CHECK(!L.leg(SoakPosture::ServeNativeShadowMonerod).qualified,
              "B5 the leg lost its qualification");
        CHECK(L.leg(SoakPosture::ServeMonerodShadowNative).qualified,
              "B5 the OTHER leg keeps its own: postures are judged apart");
        CHECK(L.revocations().size() > revs,
              "B5 and losing a qualification is recorded, not silent");
        CHECK(L.state() == GraduationState::Observing, "B5 back to Observing");
    }

    // B6: the stagenet numbers are the plan's, unscaled. Guarded here so that a
    // future edit that "rounds" 72 h has to change a KAT that says why.
    {
        const SoakThresholds s = SoakThresholds::stagenet_m4();
        CHECK(s.min_seconds == 72 * 3600, "B6 72 hours per posture");
        CHECK(s.min_blocks == 720, "B6 720 blocks per posture");
        CHECK(s.min_template_clean > 0, "B6 with P-TPL samples inside the window");
        const SoakThresholds r = SoakThresholds::regtest_mini();
        CHECK(r.min_clean_samples > 0 && r.min_blocks > 0 && r.min_seconds > 0
              && r.min_template_clean > 0,
              "B6 the regtest shape keeps EVERY threshold non-zero: a harness that "
              "graduates on nothing proves nothing");
        CHECK(r.min_seconds < s.min_seconds,
              "B6 and it is the scaled one, not the real gate");
    }
}

// ---------------------------------------------------------------------------
// SUITE C -- persistence, and the key that refuses to inherit.
// ---------------------------------------------------------------------------
static void suite_persistence() {
    head("C: persistence, and a key that never inherits");
    const char* path = "xmr_m4_soak_kat_ledger.json";

    // C1: round trip. Every counter that matters comes back.
    {
        M4GraduationLedger A(key_of(), tiny());
        run_clean(A, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        A.record(SoakPosture::ServeNativeShadowMonerod,
                 sample(ProbeKind::Tip, ParityVerdict::Fail, 201, "x"), 5000);
        run_clean(A, SoakPosture::ServeNativeShadowMonerod, 4, 210, 6000, 10);
        A.note_no_sample(SoakPosture::ServeNativeShadowMonerod);

        std::string why;
        CHECK(A.save(path, &why), "C1 save: %s", why.c_str());

        M4GraduationLedger B(key_of(), tiny());
        CHECK(B.load(path, &why), "C1 load: %s", why.c_str());
        const SoakPosture ps[2] = {SoakPosture::ServeMonerodShadowNative,
                                   SoakPosture::ServeNativeShadowMonerod};
        for (SoakPosture p : ps) {
            const PostureLeg& a = A.leg(p);
            const PostureLeg& b = B.leg(p);
            CHECK(a.clean_run == b.clean_run && a.run_blocks == b.run_blocks
                  && a.run_first_unix == b.run_first_unix && a.run_last_unix == b.run_last_unix
                  && a.run_tip_clean == b.run_tip_clean && a.run_tmpl_clean == b.run_tmpl_clean
                  && a.samples == b.samples && a.clean == b.clean && a.fail == b.fail
                  && a.served_mismatch == b.served_mismatch && a.voided == b.voided
                  && a.resets == b.resets && a.qualified == b.qualified
                  && a.best_clean_run == b.best_clean_run
                  && a.last_reset_why == b.last_reset_why,
                  "C1 leg %s round-trips", posture_tag(p));
            CHECK(A.no_sample_drains(p) == B.no_sample_drains(p),
                  "C1 no-sample drains round-trip for %s", posture_tag(p));
        }
        CHECK(A.state() == B.state(), "C1 state round-trips");
        CHECK(A.first_sample_unix() == B.first_sample_unix()
              && A.last_sample_unix() == B.last_sample_unix(), "C1 first/last sample");
        CHECK(A.key().comparator_version == COMPARATOR_VERSION
              && B.key().comparator_version == COMPARATOR_VERSION,
              "C1 and both are stamped with the RUNNING comparator version");

        // ...and the resumed ledger keeps accruing on the same streak rather
        // than starting a second one.
        run_clean(B, SoakPosture::ServeNativeShadowMonerod, 4, 220, 7000, 10);
        CHECK(B.leg(SoakPosture::ServeNativeShadowMonerod).clean_run == 8,
              "C1 a resumed leg continues its streak, got %llu",
              (unsigned long long)B.leg(SoakPosture::ServeNativeShadowMonerod).clean_run);
    }

    // C2: THE M1 LESSON. A ledger written under an older comparator is refused.
    {
        M4GraduationLedger A(key_of(), tiny());
        run_clean(A, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        run_clean(A, SoakPosture::ServeNativeShadowMonerod, 8, 200, 5000, 10);
        CHECK(A.graduated(), "C2 precondition: a GRADUATED ledger on disk");
        std::string json = A.to_json();

        // Rewrite the version as the one before this one. Nothing else changes:
        // the same commit, the same daemon, the same network, the same streaks.
        const std::string want = "\"comparator_version\": "
                               + std::to_string(COMPARATOR_VERSION);
        const std::string was  = "\"comparator_version\": "
                               + std::to_string(COMPARATOR_VERSION - 1);
        const std::size_t at = json.find(want);
        CHECK(at != std::string::npos, "C2 the version is in the file");
        json.replace(at, want.size(), was);

        M4GraduationLedger B(key_of(), tiny());
        std::string why;
        CHECK(!B.from_json(json, &why), "C2 a v%u ledger is REFUSED by a v%u binary",
              (unsigned)(COMPARATOR_VERSION - 1), (unsigned)COMPARATOR_VERSION);
        CHECK(why.find("key mismatch") != std::string::npos,
              "C2 and says why: '%s'", why.c_str());
        CHECK(!B.graduated(), "C2 the graduation did NOT carry across the bump");
        CHECK(B.leg(SoakPosture::ServeMonerodShadowNative).clean_run == 0
              && B.leg(SoakPosture::ServeNativeShadowMonerod).clean_run == 0,
              "C2 and both streaks restart at zero");
    }

    // C3: the other three keys, each on its own.
    {
        M4GraduationLedger A(key_of("abc1234", "0.18.5.1", "regtest"), tiny());
        run_clean(A, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        const std::string json = A.to_json();

        struct Case { GraduationKey k; const char* what; };
        const Case cases[3] = {
            {key_of("def5678", "0.18.5.1", "regtest"),  "a different c2pool commit"},
            {key_of("abc1234", "0.18.6.0", "regtest"),  "a different monerod"},
            {key_of("abc1234", "0.18.5.1", "stagenet"), "a different network"},
        };
        for (const Case& c : cases) {
            M4GraduationLedger B(c.k, tiny());
            std::string why;
            CHECK(!B.from_json(json, &why), "C3 %s is refused", c.what);
            CHECK(B.leg(SoakPosture::ServeMonerodShadowNative).clean_run == 0,
                  "C3 %s: streak restarts", c.what);
        }
        // The same key on all four, and it loads.
        M4GraduationLedger Same(key_of("abc1234", "0.18.5.1", "regtest"), tiny());
        std::string why;
        CHECK(Same.from_json(json, &why), "C3 the SAME key loads: %s", why.c_str());
        CHECK(Same.leg(SoakPosture::ServeMonerodShadowNative).clean_run == 8,
              "C3 with its streak intact");
    }

    // C4: a ledger whose daemon version is not yet bound adopts the one on
    // disk. An un-polled daemon must not make a resume look like a foreign key.
    {
        M4GraduationLedger A(key_of("abc1234", "0.18.5.1", "regtest"), tiny());
        run_clean(A, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        const std::string json = A.to_json();

        GraduationKey unbound = key_of("abc1234", "", "regtest");
        M4GraduationLedger B(unbound, tiny());
        std::string why;
        CHECK(B.from_json(json, &why), "C4 an unbound daemon version resumes: %s", why.c_str());
        CHECK(B.key().monerod_version == "0.18.5.1", "C4 and adopts what is on disk");
        CHECK(B.leg(SoakPosture::ServeMonerodShadowNative).clean_run == 8, "C4 streak intact");
    }

    // C5: a daemon that changes version UNDER the soak revokes rather than
    // silently re-keying.
    {
        M4GraduationLedger L(key_of("abc1234", "0.18.5.1", "regtest"), tiny());
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 4, 100, 1000, 10);
        L.bind_monerod_version("0.18.5.1", 1100);
        CHECK(L.state() != GraduationState::Revoked, "C5 the same version is a no-op");
        L.bind_monerod_version("0.18.6.0", 1200);
        CHECK(L.state() == GraduationState::Revoked,
              "C5 a daemon that changed under the soak revokes the key");
    }

    // C5b: the state on disk is a CACHE, not the decision. A file that claims
    // Graduated over legs that did not qualify is corrected on load.
    {
        M4GraduationLedger A(key_of(), tiny());
        run_clean(A, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        std::string json = A.to_json();
        const std::size_t at = json.find("\"state\": \"Observing\"");
        CHECK(at != std::string::npos, "C5b precondition: the ledger is Observing");
        json.replace(at, std::string("\"state\": \"Observing\"").size(),
                     "\"state\": \"Graduated\"");
        M4GraduationLedger B(key_of(), tiny());
        std::string why;
        CHECK(B.from_json(json, &why), "C5b the forged file still loads: %s", why.c_str());
        CHECK(!B.graduated(),
              "C5b but the claim is re-derived from the counters and refused");
        CHECK(!B.leg(SoakPosture::ServeNativeShadowMonerod).qualified,
              "C5b the second leg never ran and still has not");
    }

    // C6: a missing file is not an error -- an un-run experiment is ungraduated,
    // which is already the fail-closed answer. A corrupt one IS reported.
    {
        M4GraduationLedger B(key_of(), tiny());
        std::string why = "sentinel";
        CHECK(!B.load("xmr_m4_soak_kat_definitely_absent.json", &why), "C6 missing file");
        CHECK(why.empty(), "C6 and it is not reported as an error, got '%s'", why.c_str());
        CHECK(!B.from_json("{ this is not json", &why), "C6 corrupt is refused");
        CHECK(!why.empty(), "C6 and IS reported");
    }

    std::remove(path);
}

// ---------------------------------------------------------------------------
// SUITE D -- the negative control, through the real comparator.
// ---------------------------------------------------------------------------
namespace {

// A tip observer that answers a fixed, honest observation.
class CannedTip final : public ITipObserver {
public:
    explicit CannedTip(ArmObservation o) : o_(std::move(o)) {}
    ArmObservation observe() override { ++calls_; return o_; }
    std::uint64_t calls() const noexcept { return calls_; }
private:
    ArmObservation o_;
    std::uint64_t  calls_ = 0;
};

Hash id_of(std::uint8_t b) {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(b + i);
    return h;
}

// One arm's answer for P-TIP with every required EQUALITY field present.
ArmObservation tip_arm(const char* name, std::uint64_t height) {
    ArmObservation o;
    o.arm     = name;
    o.have    = true;
    o.height  = height;
    o.prev_id = id_of(0x10);
    o.fields.set("id",                    Obs::id(id_of(0x20)));
    o.fields.set("prev_id",               Obs::id(id_of(0x10)));
    o.fields.set("cumulative_difficulty", Obs::u128(U128{0, 123456}));
    o.fields.set("difficulty",            Obs::u128(U128{0, 1000}));
    o.fields.set("timestamp",             Obs::u64(1700000000));
    o.fields.set("reward",                Obs::u64(600000000000ull));
    o.fields.set("block_weight",          Obs::u64(1234));
    o.fields.set("long_term_weight",      Obs::u64(1234));
    o.fields.set("major_version",         Obs::u64(16));
    return o;
}

} // namespace

static void suite_injection() {
    head("D: the negative control, end to end through the real comparator");

    // D1: one-unit perturbation semantics, over the three renderings the Obs
    // layer produces.
    {
        CHECK(PerturbingTipObserver::perturb("1234") == "1235", "D1 decimal +1");
        CHECK(PerturbingTipObserver::perturb("1299") == "1300", "D1 decimal carries");
        CHECK(PerturbingTipObserver::perturb("999")  == "1000", "D1 decimal grows");
        CHECK(PerturbingTipObserver::perturb("0")    == "1",    "D1 zero is a real value");
        // The u128 rendering: only the LOW word moves, so a carry into the high
        // word can never be manufactured by the injector itself.
        CHECK(PerturbingTipObserver::perturb("7:42") == "7:43", "D1 u128 hi:lo");
        const std::string hexid(64, 'a');
        const std::string bumped = PerturbingTipObserver::perturb(hexid);
        CHECK(bumped.size() == 64 && bumped != hexid, "D1 a 64-hex id changes and stays an id");
        CHECK(bumped.compare(0, 63, hexid, 0, 63) == 0, "D1 by exactly one nibble");
    }

    // D2: the injector is honest until it is armed, and stops when told to.
    {
        CannedTip inner(tip_arm("native", 500));
        TipFaultInjection f;
        f.field = "difficulty";
        f.after_samples = 3;
        f.for_samples   = 2;
        PerturbingTipObserver inj(inner, f);
        const std::string honest = tip_arm("native", 500).fields.get("difficulty").value;
        for (int i = 0; i < 3; ++i)
            CHECK(inj.observe().fields.get("difficulty").value == honest,
                  "D2 observation %d is honest", i + 1);
        CHECK(inj.observe().fields.get("difficulty").value != honest, "D2 observation 4 perturbed");
        CHECK(inj.observe().fields.get("difficulty").value != honest, "D2 observation 5 perturbed");
        CHECK(inj.observe().fields.get("difficulty").value == honest,
              "D2 observation 6 is honest again: for_samples honoured");
        CHECK(inj.injected() == 2, "D2 and exactly two were injected, got %llu",
              (unsigned long long)inj.injected());
    }
    // ...and the withholding mode removes the field rather than changing it.
    {
        CannedTip inner(tip_arm("native", 500));
        TipFaultInjection f;
        f.field  = "long_term_weight";
        f.absent = true;
        PerturbingTipObserver inj(inner, f);
        const ArmObservation o = inj.observe();
        CHECK(!o.fields.get("long_term_weight").present,
              "D2b the field is ABSENT, not zero -- which is the vacuity C6 exists against");
        CHECK(o.have, "D2b the arm still answered");
    }
    // A disarmed injector is a pass-through.
    {
        CannedTip inner(tip_arm("native", 500));
        PerturbingTipObserver inj(inner, TipFaultInjection{});
        CHECK(inj.observe().fields.get("difficulty").present, "D2c disarmed: unchanged");
        CHECK(inj.injected() == 0, "D2c and nothing injected");
    }

    // D3: THE CONTROL. The same two arms, the same comparator, twice.
    {
        const ArmObservation daemon = tip_arm("monerod", 500);

        // (a) honest: CLEAN.
        {
            CannedTip inner(tip_arm("native", 500));
            PerturbingTipObserver inj(inner, TipFaultInjection{});
            const SeamResult r = compare_seam(TIP_SEAM, inj.observe(), daemon, {});
            CHECK(r.sample.verdict == ParityVerdict::Clean,
                  "D3a honest arms compare CLEAN (got %s)", to_string(r.sample.verdict));
            CHECK(r.equality_compared == r.equality_required,
                  "D3a and every required field was actually compared");
        }

        // (b) one field, one unit: FAIL. Nothing else about the sample changed.
        for (const char* field : {"cumulative_difficulty", "difficulty", "id",
                                  "timestamp", "reward", "block_weight",
                                  "long_term_weight", "major_version"}) {
            CannedTip inner(tip_arm("native", 500));
            TipFaultInjection f;
            f.field = field;
            PerturbingTipObserver inj(inner, f);
            const SeamResult r = compare_seam(TIP_SEAM, inj.observe(), daemon, {});
            CHECK(r.sample.verdict == ParityVerdict::Fail,
                  "D3b perturbing '%s' by one unit FAILS (got %s)", field,
                  to_string(r.sample.verdict));
            CHECK(r.equality_differed == 1, "D3b exactly one field differed for '%s'", field);
        }

        // (c) withholding it FAILS too -- a comparison that did not happen is
        // not one that passed.
        {
            CannedTip inner(tip_arm("native", 500));
            TipFaultInjection f;
            f.field  = "reward";
            f.absent = true;
            PerturbingTipObserver inj(inner, f);
            const SeamResult r = compare_seam(TIP_SEAM, inj.observe(), daemon, {});
            CHECK(r.sample.verdict == ParityVerdict::Fail, "D3c a withheld required field FAILS");
            CHECK(r.equality_absent == 1, "D3c and is counted as absent, not as equal");
        }

        // (d) THE WHOLE POINT: an accrued, qualified leg meets an injected
        // divergence and the ledger refuses.
        {
            M4GraduationLedger L(key_of(), tiny());
            const SoakPosture P = SoakPosture::ServeNativeShadowMonerod;
            run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
            run_clean(L, P, 8, 200, 5000, 10);
            CHECK(L.graduated(), "D3d precondition: GRADUATED on both legs");

            CannedTip inner(tip_arm("native", 500));
            TipFaultInjection f;
            f.field = "cumulative_difficulty";      // a SENTINEL field
            PerturbingTipObserver inj(inner, f);
            const SeamResult bad = compare_seam(TIP_SEAM, inj.observe(), daemon, {});
            CHECK(bad.sample.verdict == ParityVerdict::Fail, "D3d the injected sample FAILS");
            CHECK(bad.sentinel_tripped, "D3d on a SENTINEL field");

            L.record(P, bad, 6000);
            CHECK(L.leg(P).clean_run == 0, "D3d the streak RESET");
            CHECK(!L.leg(P).qualified, "D3d the leg lost its qualification");
            CHECK(!L.graduated(), "D3d and the ledger REFUSES to graduate");
            CHECK(L.state() == GraduationState::Revoked,
                  "D3d a sentinel revokes the key outright");
        }
    }
}

// ---------------------------------------------------------------------------
// SUITE E -- the driver.
// ---------------------------------------------------------------------------
static void suite_driver() {
    head("E: the soak driver");

    // E1: a batch becomes ledger movement AND a readable transcript.
    {
        M4GraduationLedger L(key_of(), tiny());
        SoakDriver::Config c;
        c.posture = SoakPosture::ServeNativeShadowMonerod;
        c.autosave_every = 0;                      // no file in this check
        SoakDriver d(L, c);

        std::vector<SeamResult> batch;
        batch.push_back(sample(ProbeKind::Tip, ParityVerdict::Clean, 100, "9 field(s) equal"));
        batch.push_back(sample(ProbeKind::Template, ParityVerdict::Clean, 100, "6 field(s) equal"));
        const std::vector<std::string> lines = d.ingest(batch, 1000);

        CHECK(lines.size() == 2, "E1 one line per sample");
        CHECK(d.recorded() == 2, "E1 both recorded");
        CHECK(L.leg(c.posture).clean_run == 2, "E1 and the streak moved");
        CHECK(!d.transcript().empty(), "E1 a transcript exists");
        const SoakEntry& e = d.transcript().back();
        CHECK(e.posture == c.posture && e.seam == ProbeKind::Template
              && e.verdict == ParityVerdict::Clean && e.height == 100
              && e.clean_run_after == 2,
              "E1 and it carries the sample's CONTEXT, not just its verdict");
        CHECK(e.render().find("serve-native") != std::string::npos,
              "E1 the rendered line names the posture: '%s'", e.render().c_str());
    }

    // E2: P-POOL is M1's seam and must not pad an M4 streak.
    {
        M4GraduationLedger L(key_of(), tiny());
        SoakDriver::Config c;
        c.autosave_every = 0;
        SoakDriver d(L, c);
        std::vector<SeamResult> batch;
        for (int i = 0; i < 20; ++i)
            batch.push_back(sample(ProbeKind::Pool, ParityVerdict::Clean, 100));
        d.ingest(batch, 1000);
        CHECK(d.recorded() == 0, "E2 twenty clean P-POOL samples recorded nothing");
        CHECK(L.leg(c.posture).clean_run == 0, "E2 and moved no M4 streak");
    }

    // E3: an empty drain is silence, counted as such, and touches no streak.
    {
        M4GraduationLedger L(key_of(), tiny());
        SoakDriver::Config c;
        c.autosave_every = 0;
        SoakDriver d(L, c);
        std::vector<SeamResult> one;
        one.push_back(sample(ProbeKind::Tip, ParityVerdict::Clean, 100));
        d.ingest(one, 1000);
        for (int i = 0; i < 5; ++i) d.ingest({}, 1010);
        CHECK(L.no_sample_drains(c.posture) == 5, "E3 five silent drains counted");
        CHECK(L.leg(c.posture).clean_run == 1, "E3 and the streak is untouched");
        CHECK(d.drains() == 6, "E3 six drains in total");
    }

    // E4: failures are held apart from the tail, so a long clean run cannot
    // push the one interesting sample out of the transcript.
    {
        M4GraduationLedger L(key_of(), tiny());
        SoakDriver::Config c;
        c.autosave_every = 0;
        c.transcript_cap = 4;
        SoakDriver d(L, c);
        std::vector<SeamResult> bad;
        bad.push_back(sample(ProbeKind::Tip, ParityVerdict::Fail, 100, "difficulty differed"));
        d.ingest(bad, 1000);
        for (int i = 0; i < 20; ++i) {
            std::vector<SeamResult> ok;
            ok.push_back(sample(ProbeKind::Tip, ParityVerdict::Clean,
                                101 + static_cast<std::uint64_t>(i)));
            d.ingest(ok, 1010 + static_cast<std::uint64_t>(i));
        }
        CHECK(d.transcript().size() == 4, "E4 the tail is bounded");
        CHECK(d.failures().size() == 1, "E4 but the failure is still there");
        CHECK(d.failures().front().verdict == ParityVerdict::Fail, "E4 and is the right one");
    }

    // E5: the one line a script greps says the whole truth, both ways.
    {
        M4GraduationLedger L(key_of(), tiny());
        SoakDriver::Config c;
        c.posture = SoakPosture::ServeNativeShadowMonerod;
        c.autosave_every = 0;
        SoakDriver d(L, c);
        CHECK(d.verdict_line().find("NOT-GRADUATED") != std::string::npos,
              "E5 fail-closed before any sample: '%s'", d.verdict_line().c_str());
        CHECK(d.verdict_line().find("shortfall=") != std::string::npos,
              "E5 and says what is missing");
        CHECK(d.verdict_line().find("shortfall=\"serve-native:") != std::string::npos,
              "E5 naming THIS posture's shortfall, not the other leg's: '%s'",
              d.verdict_line().c_str());

        // The other leg soaked clean: the shortfall shown must still be this
        // posture's, because the other leg's is a fact about a run that is done.
        run_clean(L, SoakPosture::ServeMonerodShadowNative, 8, 100, 1000, 10);
        CHECK(d.verdict_line().find("shortfall=\"serve-native:") != std::string::npos,
              "E5 still this posture's: '%s'", d.verdict_line().c_str());

        run_clean(L, SoakPosture::ServeNativeShadowMonerod, 8, 200, 5000, 10);
        const std::string line = d.verdict_line();
        CHECK(line.find("M4-VERDICT: GRADUATED") != std::string::npos,
              "E5 and GRADUATED when both legs are in: '%s'", line.c_str());
        CHECK(line.find("legs_qualified=2/2") != std::string::npos,
              "E5 naming how many legs earned it");
    }
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::printf("xmr_native_m4_soak_kat -- the M4 streak machine, ledger and refusal\n");
    std::printf("comparator version %u\n", static_cast<unsigned>(COMPARATOR_VERSION));

    suite_streak();
    suite_graduation();
    suite_persistence();
    suite_injection();
    suite_driver();

    std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
