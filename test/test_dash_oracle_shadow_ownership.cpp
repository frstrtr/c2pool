// D-DASH.ORACLE-OWNERSHIP — source-structural guard pinning WHICH THREAD is
// allowed to read NodeCoinState from the --embedded-oracle-shadow lane.
//
// THE DEFECT THIS PINS (hotel primary c2pool-dash, SIGABRT 2026-08-05
// 21:52:38 MSK, glibc "malloc(): unaligned tcache chunk detected" +
// "double free or corruption (!prev)", 25 min after deploying cdd908ce):
//
//   NodeCoinState (impl/dash/coin/node_coin_state.hpp) has ZERO mutexes, and
//   select_work() hands RAW POINTERS into its live containers out to the
//   caller — `e.mnstates = &m_mnstates` (:1066, an MnStateMachine map) and
//   `e.sml = &m_sml` (:1087, a CSimplifiedMNList vector). The embedded
//   template is then assembled by DEREFERENCING those pointers.
//
//   EmbeddedOracleShadow::process_tip() used to call
//   `coin_state_.select_work(...)` on its own WORKER THREAD while the io
//   thread concurrently mutated the very same containers — apply_diff vector
//   realloc (coin_state_maintainer.hpp:489), mnList.clear() (:482, :716),
//   apply_block RB-tree rebalance (:1092). MNState owns two heap vectors
//   (mn_state_db.hpp:60), so the overlap corrupted ALLOCATOR METADATA rather
//   than merely returning stale values — which is exactly why glibc reported
//   tcache/double-free rather than a wrong template.
//
// THE FIX: resolve the embedded arm on the tip/io thread inside on_new_tip()
// and enqueue a DEEP COPY (TipJob, all-by-value). This is the shape
// EmbeddedShadowCompare::on_serve already uses correctly
// (embedded_shadow_compare.hpp:381-387).
//
// WHY A STRUCTURAL TEST: a true data race is nondeterministic and was NOT
// reproduced under a sanitizer — the diagnosis is convergent static + timing
// evidence. A guard that asserts the OWNERSHIP SHAPE is the deterministic
// red/green this invariant admits, and it is the house pattern for exactly
// this situation (src/impl/dgb/test/race913_lock_guard_test.cpp, PR #1114).
// Move select_work() back into process_tip()/worker_loop() -> RED.
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>

#ifndef DASH_ORACLE_SHADOW_SRC
#error "DASH_ORACLE_SHADOW_SRC must be defined by CMake to the path of src/impl/dash/coin/embedded_oracle_shadow.hpp"
#endif
#ifndef DASH_MAIN_SRC
#error "DASH_MAIN_SRC must be defined by CMake to the path of src/c2pool/main_dash.cpp"
#endif
// #1134: the superseded arm-guard tripwire below now asserts the ownership split
// in the work source itself, so it needs that source too.
#ifndef DASH_WORK_SOURCE_SRC
#error "DASH_WORK_SOURCE_SRC must be defined by CMake to the path of src/impl/dash/stratum/work_source.cpp"
#endif

namespace {

std::string read_text(const char* path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

std::string read_shadow_header() { return read_text(DASH_ORACLE_SHADOW_SRC); }
std::string read_main_dash()     { return read_text(DASH_MAIN_SRC); }

// Replace every comment with spaces, preserving byte offsets and line breaks so
// the "\n    }\n" member-end anchor below still lines up. Comments must not be
// able to satisfy (or break) an assertion about what the CODE does — the doc
// blocks in this header deliberately quote the pre-fix expressions.
std::string strip_comments(const std::string& s)
{
    std::string out = s;
    enum { kCode, kLine, kBlock, kStr, kChr } st = kCode;
    for (size_t i = 0; i < out.size(); ++i) {
        const char c = out[i];
        const char n = (i + 1 < out.size()) ? out[i + 1] : '\0';
        switch (st) {
        case kCode:
            if (c == '/' && n == '/') { st = kLine;  out[i] = ' '; out[i + 1] = ' '; ++i; }
            else if (c == '/' && n == '*') { st = kBlock; out[i] = ' '; out[i + 1] = ' '; ++i; }
            else if (c == '"')  st = kStr;
            else if (c == '\'') st = kChr;
            break;
        case kLine:
            if (c == '\n') st = kCode; else out[i] = ' ';
            break;
        case kBlock:
            if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; ++i; st = kCode; }
            else if (c != '\n') out[i] = ' ';
            break;
        case kStr:
            if (c == '\\') ++i; else if (c == '"') st = kCode;
            break;
        case kChr:
            if (c == '\\') ++i; else if (c == '\'') st = kCode;
            break;
        }
    }
    return out;
}

// Byte range [begin,end) of a 4-space-indented member function body, from its
// signature line to the closing "\n    }\n" that ends it. Class members in this
// header sit at 4-space indent and every nested block closes deeper, so the
// anchor is unambiguous (verified against the shipped file by the tests below,
// which fail loudly if a signature or its terminator is missing).
struct Range { size_t begin{std::string::npos}; size_t end{std::string::npos}; };

Range member_range(const std::string& src, const std::string& signature)
{
    Range r;
    r.begin = src.find(signature);
    if (r.begin == std::string::npos) return r;
    const size_t close = src.find("\n    }\n", r.begin);
    if (close == std::string::npos) { r.begin = std::string::npos; return r; }
    r.end = close + 7;   // strlen("\n    }\n")
    return r;
}

std::string member_body(const std::string& src, const std::string& signature)
{
    const Range r = member_range(src, signature);
    if (r.begin == std::string::npos) return "";
    return src.substr(r.begin, r.end - r.begin);
}

size_t count_of(const std::string& hay, const std::string& needle)
{
    size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) { ++n; pos += needle.size(); }
    return n;
}

const char* kProcessTipSig = "void process_tip(";
const char* kWorkerLoopSig = "void worker_loop()";
const char* kOnNewTipSig   = "void on_new_tip(";

} // namespace

// ── The worker thread must not be able to reach NodeCoinState at all ────────
// process_tip() runs on worker_, started in the ctor. NodeCoinState is owned
// and mutated by the io thread and carries no lock, so a single textual
// reference to coin_state_ inside this body is the whole bug back.
TEST(DashOracleShadowOwnership, ProcessTipNeverTouchesCoinState)
{
    const std::string src  = strip_comments(read_shadow_header());
    const std::string body = member_body(src, kProcessTipSig);
    ASSERT_FALSE(body.empty()) << "process_tip(...) not found in "
                               << DASH_ORACLE_SHADOW_SRC;
    EXPECT_EQ(body.find("coin_state_"), std::string::npos)
        << "process_tip() runs on the WORKER thread and must never read "
           "NodeCoinState (no mutex; select_work() hands out raw pointers into "
           "live containers -> the 2026-08-05 heap corruption). Resolve on the "
           "tip thread in on_new_tip() and enqueue a deep copy instead.";
}

TEST(DashOracleShadowOwnership, WorkerLoopNeverTouchesCoinState)
{
    const std::string src  = strip_comments(read_shadow_header());
    const std::string body = member_body(src, kWorkerLoopSig);
    ASSERT_FALSE(body.empty()) << "worker_loop() not found";
    EXPECT_EQ(body.find("coin_state_"), std::string::npos)
        << "worker_loop() runs on the WORKER thread and must never read "
           "NodeCoinState.";
}

// ── The tip (io) thread is the ONLY legal reader ────────────────────────────
TEST(DashOracleShadowOwnership, OnNewTipResolvesTheArmOnTheTipThread)
{
    const std::string src  = strip_comments(read_shadow_header());
    const std::string body = member_body(src, kOnNewTipSig);
    ASSERT_FALSE(body.empty()) << "on_new_tip(...) not found";
    EXPECT_NE(body.find("coin_state_.select_work("), std::string::npos)
        << "on_new_tip() runs on the tip/io thread that owns NodeCoinState and "
           "is where the embedded arm must be resolved.";
}

// Exactly one select_work() call in the whole file, and it sits inside
// on_new_tip(). Catches a re-introduced second call site anywhere else
// (a new accessor, a stats path, a future compare leg).
TEST(DashOracleShadowOwnership, SelectWorkCalledOnlyFromOnNewTip)
{
    const std::string src = strip_comments(read_shadow_header());
    EXPECT_EQ(count_of(src, "select_work("), 1u)
        << "exactly one select_work() call site is expected, inside on_new_tip()";
    const Range on_tip = member_range(src, kOnNewTipSig);
    ASSERT_NE(on_tip.begin, std::string::npos) << "on_new_tip(...) not found";
    const size_t at = src.find("select_work(");
    ASSERT_NE(at, std::string::npos) << "select_work() call vanished entirely";
    EXPECT_TRUE(at > on_tip.begin && at < on_tip.end)
        << "select_work() is called from OUTSIDE on_new_tip() — only the "
           "tip/io thread may read NodeCoinState.";
}

// classify_decline() re-runs make_embedded_work_inputs() and therefore reads
// the same unguarded containers; it is the same exposure and must be sampled
// on the same thread.
TEST(DashOracleShadowOwnership, ClassifyDeclineSampledOnTheTipThread)
{
    const std::string src = strip_comments(read_shadow_header());
    ASSERT_EQ(count_of(src, "classify_decline("), 1u)
        << "expected exactly one classify_decline() sample";
    const Range on_tip = member_range(src, kOnNewTipSig);
    ASSERT_NE(on_tip.begin, std::string::npos);
    const size_t at = src.find("classify_decline(");
    EXPECT_TRUE(at > on_tip.begin && at < on_tip.end)
        << "classify_decline() re-reads m_mnstates/m_sml — it must be sampled "
           "on the tip thread beside select_work(), never on the worker.";
}

// ── The queued job must OWN what the worker reads ───────────────────────────
// A pointer/reference member would re-open the lifetime hole with none of the
// textual evidence the tests above look for.
TEST(DashOracleShadowOwnership, QueuedJobCarriesTheTemplateByValue)
{
    const std::string src = strip_comments(read_shadow_header());
    const size_t s = src.find("struct TipJob {");
    ASSERT_NE(s, std::string::npos) << "TipJob (the by-value queue element) not found";
    const size_t e = src.find("\n    };\n", s);
    ASSERT_NE(e, std::string::npos) << "TipJob has no terminator";
    const std::string body = src.substr(s, e - s);

    EXPECT_NE(body.find("DashWorkData emb;"), std::string::npos)
        << "TipJob must carry the embedded template BY VALUE (DashWorkData is "
           "all-by-value; owning it is what makes the worker read safe)";
    EXPECT_EQ(body.find("DashWorkData*"), std::string::npos)
        << "TipJob must not carry a POINTER to the template";
    EXPECT_EQ(body.find("NodeCoinState"), std::string::npos)
        << "TipJob must not reference NodeCoinState in any form";
    EXPECT_EQ(body.find("MnStateMachine"), std::string::npos)
        << "TipJob must not carry the MN state map (that is the live container)";
    EXPECT_EQ(body.find("CSimplifiedMNList"), std::string::npos)
        << "TipJob must not carry the SML (that is the live container)";
}

// The coalescing queue slot holds the job BY VALUE too — a pointer here would
// mean the tip thread still owns storage the worker dereferences.
TEST(DashOracleShadowOwnership, PendingSlotHoldsTheJobByValue)
{
    const std::string src = strip_comments(read_shadow_header());
    EXPECT_NE(src.find("std::optional<TipJob>"), std::string::npos)
        << "the coalescing queue slot must be std::optional<TipJob> (by value)";
    EXPECT_EQ(src.find("std::optional<std::pair<uint32_t, uint256>> pending_"),
              std::string::npos)
        << "the pre-fix queue element is back: it carried only (height, hash), "
           "which forced the worker to re-read NodeCoinState for the template.";
}

// ── The SIBLING exposure: DASHWorkSource::resource_template_now() ───────────
// SUPERSEDED BY #1134. This test was `RefreshExecutorStaysOffTheCoinP2PArm`.
//
// When #1135 landed, DASHWorkSource::resource_template_now() read NodeCoinState
// (populated(), select_work(), describe_decline(), embedded_template_emit_ok())
// and ran on the rpc_pool worker whenever refresh_executor_ was wired — the same
// unguarded-read shape as the oracle-shadow bug, on the SERVE path. The ONLY
// thing that made it safe was ARM EXCLUSIVITY: the executor was installed under
// `!coin_p2p` while every NodeCoinState MUTATOR lived inside `if (coin_p2p)`, so
// on the arm that had the worker the coin state happened to be write-quiescent.
// This test asserted that configuration coincidence, because a tripwire was all
// #1135 could offer without touching the serve path.
//
// #1134 replaced the coincidence with OWNERSHIP: resolve_coin_state_arm() makes
// every NodeCoinState read on the owning thread and hands the background job a
// by-value CoinStateArm. The `!coin_p2p` condition is therefore no longer
// load-bearing for this shape, and continuing to assert it would pin the exact
// configuration detail the dashd cut is going to relax.
//
// What this test pins INSTEAD: the executor may be installed on either arm,
// PROVIDED the function that executor runs owns everything it reads. Revert the
// split -> RED, with the arm-guard warning restated. The full serve-path guard
// (every reader enumerated by name, the by-value handoff, the no-op fallback)
// lives in test/test_dash_work_source_ownership.cpp.
TEST(DashOracleShadowOwnership, RefreshExecutorArmGuardSupersededByCoinStateOwnership)
{
    const std::string src = strip_comments(read_main_dash());
    ASSERT_EQ(count_of(src, "set_refresh_executor("), 1u)
        << "expected exactly one set_refresh_executor() install site in main_dash.cpp";

    const std::string ws = strip_comments(read_text(DASH_WORK_SOURCE_SRC));

    // (1) The ownership handoff exists: the executor-run overload takes the
    //     already-resolved arm BY VALUE.
    const size_t sig =
        ws.find("void DASHWorkSource::resource_template_now(CoinStateArm arm)");
    ASSERT_NE(sig, std::string::npos)
        << "resource_template_now(CoinStateArm) is gone — the #1134 ownership "
           "split has been reverted, so the rpc_pool job resolves the arm itself "
           "again and the only thing between this node and the 2026-08-05 heap "
           "corruption is the !coin_p2p install guard in main_dash.cpp. Restore "
           "the split before relaxing that guard.";

    // (2) The function the executor runs never names the coin state.
    const size_t close = ws.find("\n}\n", sig);
    ASSERT_NE(close, std::string::npos)
        << "resource_template_now(CoinStateArm) has no terminator";
    const std::string body = ws.substr(sig, close - sig);
    EXPECT_EQ(body.find("coin_state_"), std::string::npos)
        << "resource_template_now() reads NodeCoinState again. It runs on the "
           "rpc_pool worker whenever refresh_executor_ is wired; NodeCoinState "
           "has ZERO mutexes and select_work() hands raw pointers into "
           "m_mnstates/m_sml. Resolve on the owning thread "
           "(resolve_coin_state_arm) and pass a value.";

    // (3) And the owning-thread resolver is where those reads went.
    EXPECT_NE(ws.find("DASHWorkSource::resolve_coin_state_arm()"), std::string::npos)
        << "resolve_coin_state_arm() is missing — there is no owning-thread "
           "resolver for the background job to take its value from.";
}
