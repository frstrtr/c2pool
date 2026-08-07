// SPDX-License-Identifier: AGPL-3.0-or-later
// SEAM red witness — the operator surface must carry a SERVED-vs-OBSERVED
// staleness block.
//
// ── THE DEFECT THIS PINS (hotel 109.161.52.148, 2026-08-07 mainnet) ─────────
//
// For one hour the node handed h=2518006 to 26 rigs while the network was at
// h=2518028. Every share those rigs produced was unpayable, and NOTHING in the
// process said so. The reason is structural, not an oversight: every staleness
// signal that exists compares the node against ITSELF.
//
//   * kStaleAfter / kRetryAfter (work_source.cpp:66, :69) are cache TTLs. They
//     schedule a RE-SOURCE; they never emit a verdict, and the executor path
//     deliberately serves the stale cache while the refresh is in flight
//     (work_source.cpp:864-889, :924). "Stale" there is a routine state, not a
//     fault, so it cannot be alarmed on without misfiring on every refresh.
//   * [EMBED-STATUS] (main_dash.cpp:6400-6525) is the periodic health line. It
//     reports describe_decline() / have_tip / payee_cursor / hdr_tip — all read
//     out of our OWN NodeCoinState and header chain. When the io thread froze,
//     that state froze with it AND the timer that prints the line lives on the
//     same `ioc`, so the line simply stopped.
//   * SmlResyncWatchdog (coin/sml_resync_watchdog.hpp) does compare two things
//     over time — but they are the SML and OUR tip. A frozen tip makes the SML
//     look perfectly current.
//   * The shadow oracle VOIDs a sample on tip-skew by design
//     (coin/embedded_oracle_shadow.hpp:788-791), so the exact condition here is
//     the one it refuses to score.
//   * node_topology already carries header_height / target_height / synced
//     (main_dash.cpp:3271-3286) — but only as fields recomputed when a browser
//     asks. Nothing compares them and nothing raises anything.
//
// So the missing thing is precisely one thing: a SERVED height, recorded where
// the template is actually handed out, compared against an INDEPENDENTLY
// observed height, with an age. This test pins that field's existence on the
// one surface every operator path already reads (embedded_arm_status_json ->
// node_topology_fn, main_dash.cpp:3286-3288).
//
// RED ON MASTER: `grep -rn serve_staleness src/` returns nothing on master;
// embedded_arm_status_json publishes only arm / no_work_reason / no_work_value
// / no_work_threshold (work_source.cpp:796-819). This file compiles against
// master and FAILS there. That failing run is the witness.
//
// This rides the EXISTING allowlisted test_dash_stratum_work_source target on
// purpose: a new add_executable absent from the build.yml --target allowlist is
// the #143 NOT_BUILT sentinel that passes by never being built (see the note at
// test/CMakeLists.txt:922-925).

#include <impl/dash/stratum/work_source.hpp>
#include <impl/dash/coin/node_coin_state.hpp>

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

// A minimal dashd-fallback template. Nothing here needs to be consensus-real:
// the surface under test is a REPORTING field, and the point is that it exists
// and carries the served height at all.
dash::coin::DashWorkData seam_work(uint32_t height)
{
    dash::coin::DashWorkData w;
    w.m_version = 0x20000000;
    w.m_previous_block.SetHex(
        "0000000000000000abcdef0123456789abcdef0123456789abcdef0123456789");
    w.m_height         = height;
    w.m_coinbase_value = 100000000ull;
    w.m_bits           = 0x1e0ffff0u;
    w.m_curtime        = 1700000000u;
    return w;
}

}  // namespace

// The incident height, verbatim. A served template must leave a RECORD of the
// height it served, on a surface that is readable without the io thread.
TEST(DashServeStalenessSeam, StatusJsonCarriesServedHeightAndObservedSkew)
{
    dash::coin::NodeCoinState cs;                 // unpopulated -> dashd arm
    auto fallback = []() -> dash::coin::DashWorkData {
        return seam_work(2518006u);               // the DEAD height, as served
    };
    auto submit = [](const std::vector<unsigned char>&, uint32_t, bool) {
        return true;
    };

    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/false);

    // Serve one template, exactly as StratumSession::send_notify_work does.
    auto tmpl = ws.get_current_work_template();
    ASSERT_FALSE(tmpl.empty());
    ASSERT_EQ(tmpl.value("height", 0u), 2518006u);

    // The operator surface. On master this object does not exist.
    const nlohmann::json st = ws.embedded_arm_status_json();
    ASSERT_TRUE(st.contains("serve_staleness"))
        << "embedded_arm_status_json publishes NO served-vs-observed block, so "
           "an hour of dead-height serving is invisible to every reader of "
           "/api/node_topology. Status was: " << st.dump();

    const nlohmann::json& ss = st["serve_staleness"];
    ASSERT_TRUE(ss.is_object()) << ss.dump();

    // The three fields that make the claim falsifiable: what we served, what
    // the world says, and whether that pair is a fault.
    EXPECT_TRUE(ss.contains("served_height"))   << ss.dump();
    EXPECT_TRUE(ss.contains("observed_height")) << ss.dump();
    EXPECT_TRUE(ss.contains("stale"))           << ss.dump();

    // And served_height must be the height we ACTUALLY handed out -- not a
    // re-read of coin state (which is exactly what froze), and not zero.
    EXPECT_EQ(ss.value("served_height", 0u), 2518006u)
        << "served_height must be recorded ON the serve path, from the template "
           "that was handed out: " << ss.dump();
}

// The surface must be readable WITHOUT the template lock. During the freeze the
// io thread held template_mutex_ across the 733 ms pre-emit gate
// (work_source.cpp:836-853); a status reader that waits on that lock is dark at
// exactly the moment it is needed. Pinned by source text because a lock
// ordering cannot be observed from outside.
TEST(DashServeStalenessSeam, StalenessBlockIsBuiltBeforeAnyLockIsTaken)
{
#ifndef DASH_WORK_SOURCE_SRC
    GTEST_SKIP() << "DASH_WORK_SOURCE_SRC not defined";
#else
    FILE* f = std::fopen(DASH_WORK_SOURCE_SRC, "rb");
    ASSERT_NE(f, nullptr) << DASH_WORK_SOURCE_SRC;
    std::string src;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) src.append(buf, n);
    std::fclose(f);

    const size_t body = src.find("DASHWorkSource::embedded_arm_status_json");
    ASSERT_NE(body, std::string::npos);
    const size_t pub  = src.find("serve_staleness", body);
    ASSERT_NE(pub, std::string::npos)
        << "embedded_arm_status_json never publishes a serve_staleness block";
    const size_t lock = src.find("serve_gate_mutex_", body);
    ASSERT_NE(lock, std::string::npos);
    EXPECT_LT(pub, lock)
        << "the staleness block must be composed from lock-free atomics BEFORE "
           "serve_gate_mutex_ is taken, so the status surface stays live while "
           "the io thread is wedged inside the serve gate";
#endif
}

// ═══════════════════════════════════════════════════════════════════════════
// C2 — THE PER-CONNECTION COINBASE PATH IS THE OTHER WAY A HEIGHT ESCAPES
// ═══════════════════════════════════════════════════════════════════════════
//
// A reviewer DELETED note_served_height(wd->m_height) from
// build_connection_coinbase (work_source.cpp:1108) and the whole target stayed
// 86/86 green — while the comment at that very site called it load-bearing.
// A guard nothing can fail is not a guard.
//
// This test touches ONLY that path: it never calls get_current_work_template,
// so the recorded served height can have come from nowhere else. Delete the
// call and this reds.
TEST(DashServeStalenessSeam, PerConnectionCoinbasePathRecordsTheServedHeight)
{
    dash::coin::NodeCoinState cs;
    auto fallback = []() -> dash::coin::DashWorkData {
        return seam_work(2518006u);
    };
    auto submit = [](const std::vector<unsigned char>&, uint32_t, bool) {
        return true;
    };

    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/false);

    // Nothing has been handed out yet.
    ASSERT_EQ(ws.last_served_height(), 0u)
        << "a fresh work source claimed to have already served a height";

    // The per-connection path, and ONLY it. This is what StratumSession calls
    // when a miner subscribes; on a node whose notify loop happens to be quiet
    // it is the only way a height reaches a rig.
    const uint256 prev_share = uint256::ZERO;
    const std::vector<unsigned char> payout_script = {
        0x76, 0xa9, 0x14,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x88, 0xac};
    const auto cb = ws.build_connection_coinbase(prev_share, "00000000",
                                                 payout_script, {});
    ASSERT_TRUE(cb.snapshot.has_header)
        << "the per-connection coinbase path did not produce a job at all, so "
           "this test cannot say anything about what it recorded";
    ASSERT_EQ(cb.snapshot.height, 2518006u);

    EXPECT_EQ(ws.last_served_height(), 2518006u)
        << "build_connection_coinbase handed h=2518006 to a miner and left NO "
           "record of it — exactly the blindness that let 26 rigs sit on a dead "
           "height for an hour";
    EXPECT_GT(ws.last_served_at_ms(), 0);

    // And it must reach the operator surface, not just the accessor.
    const nlohmann::json ss = ws.serve_staleness_json();
    EXPECT_EQ(ss.value("served_height", 0u), 2518006u) << ss.dump();
}

// ═══════════════════════════════════════════════════════════════════════════
// C4 — THE STALENESS BLOCK IS REACHABLE WITHOUT THE SERVE-GATE LOCK
// ═══════════════════════════════════════════════════════════════════════════
//
// The first cut COMPOSED the block before the lock and then blocked
// unconditionally on serve_gate_mutex_ one line later, so during the exact
// saturation this detects the status endpoint hung with it. Composing early is
// worthless if the only way to reach the result is through the lock.
TEST(DashServeStalenessSeam, StalenessBlockHasItsOwnLockFreeAccessor)
{
    dash::coin::NodeCoinState cs;
    auto fallback = []() -> dash::coin::DashWorkData {
        return seam_work(2518006u);
    };
    auto submit = [](const std::vector<unsigned char>&, uint32_t, bool) {
        return true;
    };
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/false);
    ws.get_current_work_template();

    // Reached WITHOUT going through embedded_arm_status_json at all.
    const nlohmann::json ss = ws.serve_staleness_json();
    ASSERT_TRUE(ss.is_object()) << ss.dump();
    EXPECT_EQ(ss.value("served_height", 0u), 2518006u) << ss.dump();
    EXPECT_TRUE(ss.contains("stale"))       << ss.dump();
    EXPECT_TRUE(ss.contains("stale_check")) << ss.dump();
    EXPECT_TRUE(ss.contains("d2"))          << ss.dump();
}

// The lock-free property itself, pinned by source text — a lock ORDER cannot be
// observed from outside the class, so it is read off the body that has it.
TEST(DashServeStalenessSeam, StalenessJsonBodyTakesNoLockAtAll)
{
#ifndef DASH_WORK_SOURCE_SRC
    GTEST_SKIP() << "DASH_WORK_SOURCE_SRC not defined";
#else
    FILE* f = std::fopen(DASH_WORK_SOURCE_SRC, "rb");
    ASSERT_NE(f, nullptr) << DASH_WORK_SOURCE_SRC;
    std::string src;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) src.append(buf, n);
    std::fclose(f);

    const size_t body = src.find("DASHWorkSource::serve_staleness_json");
    ASSERT_NE(body, std::string::npos);
    const size_t end = src.find("\n}", body);
    ASSERT_NE(end, std::string::npos);
    const std::string fn = src.substr(body, end - body);
    EXPECT_EQ(fn.find("lock_guard"),        std::string::npos) << fn;
    EXPECT_EQ(fn.find("unique_lock"),       std::string::npos) << fn;
    EXPECT_EQ(fn.find("serve_gate_mutex_"), std::string::npos) << fn;
    EXPECT_EQ(fn.find("template_mutex_"),   std::string::npos) << fn;

    // And embedded_arm_status_json must not BLOCK on the serve gate either: it
    // degrades with a named reason instead of hanging the whole response.
    const size_t arm = src.find("DASHWorkSource::embedded_arm_status_json");
    ASSERT_NE(arm, std::string::npos);
    const size_t arm_end = src.find("\n}", arm);
    ASSERT_NE(arm_end, std::string::npos);
    const std::string armfn = src.substr(arm, arm_end - arm);
    EXPECT_NE(armfn.find("try_to_lock"), std::string::npos)
        << "embedded_arm_status_json blocks unconditionally on a lock the SERVE "
           "PATH holds, so the status surface goes dark during exactly the "
           "saturation the sentinel exists to report: " << armfn;
    EXPECT_EQ(armfn.find("std::lock_guard<std::mutex> lk(serve_gate_mutex_)"),
              std::string::npos)
        << armfn;
#endif
}

// The topology surface must read the staleness block from the LOCK-FREE
// accessor, not dig it out of embedded_arm_status_json's result — otherwise the
// one surface that reports serve-path saturation depends on the serve path.
TEST(DashServeStalenessSeam, NodeTopologyReadsTheLockFreeAccessorDirectly)
{
#ifndef DASH_MAIN_SRC
    GTEST_SKIP() << "DASH_MAIN_SRC not defined";
#else
    FILE* f = std::fopen(DASH_MAIN_SRC, "rb");
    ASSERT_NE(f, nullptr) << DASH_MAIN_SRC;
    std::string src;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) src.append(buf, n);
    std::fclose(f);

    EXPECT_NE(src.find("c[\"serve_staleness\"] = ws->serve_staleness_json();"),
              std::string::npos)
        << "/api/node_topology does not call the lock-free accessor";
    EXPECT_EQ(src.find("if (arm.contains(\"serve_staleness\"))"),
              std::string::npos)
        << "the topology surface still sources the staleness block from the "
           "arm status, which is gated behind serve_gate_mutex_";
#endif
}

// ═══════════════════════════════════════════════════════════════════════════
// C1 / C3 / C6 ON THE SURFACE — the sentinel's standing verdict, as published
// ═══════════════════════════════════════════════════════════════════════════
//
// The detector-side proof lives in test_dash_serve_staleness_unit.cpp. This is
// the other half: what the sentinel concluded has to survive the trip to JSON
// with its per-check ages intact and D2's refusal stated rather than implied.
TEST(DashServeStalenessSeam, PublishedBlockNamesTheCheckAndKeepsAgesApart)
{
    dash::coin::NodeCoinState cs;
    auto fallback = []() -> dash::coin::DashWorkData {
        return seam_work(2518006u);
    };
    auto submit = [](const std::vector<unsigned char>&, uint32_t, bool) {
        return true;
    };
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/false);
    ws.get_current_work_template();

    // Before any sentinel poll: no verdict, and D2 explicitly unavailable
    // rather than silently "not stale".
    {
        const nlohmann::json ss = ws.serve_staleness_json();
        EXPECT_EQ(ss.value("stale", true), false)         << ss.dump();
        EXPECT_EQ(ss.value("stale_check", std::string()), "none") << ss.dump();
        EXPECT_EQ(ss.value("d2", std::string()),
                  "unavailable-no-independent-reference") << ss.dump();
        EXPECT_FALSE(ss.contains("behind")) << ss.dump();
    }

    // The incident as it presented: D1 standing for an hour, D2 blind because
    // its mirror froze with the io thread, D3 quiet because templates were
    // still going out.
    dash::stratum::DASHWorkSource::ServeStalenessReport r;
    r.observed_height = 2518006u;      // frozen mirror == the dead height
    r.observed_at_ms  = 1000;
    r.observed_src    = "peer";
    r.d2_armed        = false;         // no independent reference this poll
    r.stale           = true;
    r.stale_check     = "io-silence";
    r.stale_age_ms    = 3600000;
    r.io_silent_ms    = 3600000;
    r.skew_age_ms     = 0;
    r.serve_quiet_ms  = 900;
    ws.note_serve_observation(r);

    const nlohmann::json ss = ws.serve_staleness_json();
    EXPECT_EQ(ss.value("stale", false), true)
        << "the surface reported health while the log alarmed: " << ss.dump();
    EXPECT_EQ(ss.value("stale_check", std::string()), "io-silence") << ss.dump();
    EXPECT_EQ(ss.value("stale_age_s", 0), 3600)      << ss.dump();
    EXPECT_EQ(ss.value("io_silent_s", 0), 3600)      << ss.dump();
    EXPECT_EQ(ss.value("skew_age_s", -1), 0)         << ss.dump();
    EXPECT_EQ(ss.value("serve_quiet_s", -1), 0)      << ss.dump();
    EXPECT_EQ(ss.value("d2", std::string()),
              "unavailable-no-independent-reference")
        << "D2 was blind and the surface must SAY so; rendering it as 'no skew' "
           "is the node vouching for itself: " << ss.dump();

    // A later poll with a real outside reference flips D2 to armed, and the two
    // ages stay separate.
    r.d2_armed        = true;
    r.observed_height = 2518028u;
    r.stale_check     = "height-skew";
    r.stale_age_ms    = 480000;
    r.skew_age_ms     = 480000;
    r.io_silent_ms    = 1000;
    ws.note_serve_observation(r);

    const nlohmann::json ss2 = ws.serve_staleness_json();
    EXPECT_EQ(ss2.value("d2", std::string()), "armed")        << ss2.dump();
    EXPECT_EQ(ss2.value("stale_check", std::string()), "height-skew") << ss2.dump();
    EXPECT_EQ(ss2.value("stale_age_s", 0), 480)               << ss2.dump();
    EXPECT_EQ(ss2.value("io_silent_s", -1), 1)                << ss2.dump();
    EXPECT_EQ(ss2.value("behind", 0u), 22u)                   << ss2.dump();
}
