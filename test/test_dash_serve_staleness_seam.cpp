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
