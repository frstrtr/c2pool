// D-DASH.WORKSOURCE-OWNERSHIP (#1134) — source-structural guard pinning WHICH
// THREAD is allowed to read NodeCoinState from the SERVE path.
//
// THE DEFECT THIS PINS (the sibling of the 2026-08-05 hotel SIGABRT that PR
// #1135 fixed, on the path that builds the templates our miners work on):
//
//   coin::NodeCoinState (impl/dash/coin/node_coin_state.hpp) has ZERO mutexes,
//   and select_work() hands RAW POINTERS into its live containers out to the
//   caller — `e.mnstates = &m_mnstates` (an MnStateMachine map) and
//   `e.sml = &m_sml` (a CSimplifiedMNList vector). build_embedded_workdata()
//   then dereferences them for the ENTIRE template assembly.
//
//   DASHWorkSource::resource_template_now() used to read that state itself —
//   populated(), select_work(), describe_decline(), embedded_template_emit_ok()
//   — and it runs on the rpc_pool worker thread whenever refresh_executor_ is
//   wired (main_dash.cpp set_refresh_executor). Meanwhile cached_work() reads
//   the same object on the io thread. Two threads, one unguarded object.
//
//   It never fired because of ARM EXCLUSIVITY and nothing else: the executor is
//   installed under `!coin_p2p`, while every NodeCoinState MUTATOR lives inside
//   the `if (coin_p2p)` block, so on the arm that has the worker the coin state
//   happened to be write-quiescent after startup. That is an accident of
//   configuration, not an invariant — and cutting dashd (removing --coin-rpc)
//   changes exactly those flags.
//
// THE FIX: split the re-source in two. resolve_coin_state_arm() makes EVERY
// NodeCoinState read on the thread that owns the state and returns a
// self-contained by-value CoinStateArm; resource_template_now(CoinStateArm)
// does the dashd RPCs, the arm log, the journal and the cache update off a
// copy and never names the coin state. Same shape as
// EmbeddedOracleShadow::on_new_tip/process_tip (#1135) and
// EmbeddedShadowCompare::on_serve.
//
// WHY A STRUCTURAL TEST: a true data race is nondeterministic and was NOT
// reproduced under a sanitizer. A guard that asserts the OWNERSHIP SHAPE is the
// deterministic red/green this invariant admits, and it is the house pattern
// for exactly this situation (src/impl/dgb/test/race913_lock_guard_test.cpp,
// PR #1114; test/test_dash_oracle_shadow_ownership.cpp, PR #1135). Move any
// coin_state_ read back into the executor-run function -> RED.
#include <gtest/gtest.h>

#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef DASH_WORK_SOURCE_SRC
#error "DASH_WORK_SOURCE_SRC must be defined by CMake to the path of src/impl/dash/stratum/work_source.cpp"
#endif
#ifndef DASH_WORK_SOURCE_HDR
#error "DASH_WORK_SOURCE_HDR must be defined by CMake to the path of src/impl/dash/stratum/work_source.hpp"
#endif

namespace {

std::string read_text(const char* path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

// Replace every comment with spaces, preserving byte offsets and line breaks.
// Comments must not be able to satisfy (or break) an assertion about what the
// CODE does — this file's own subject deliberately quotes the pre-fix
// expressions in its doc blocks.
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

struct Range { size_t begin{std::string::npos}; size_t end{std::string::npos}; };

// Byte range [begin,end) of an out-of-line member definition in work_source.cpp.
// Members here sit at column 0 and every nested block closes deeper, so the
// closing "\n}\n" is unambiguous.
Range member_range(const std::string& src, const std::string& signature)
{
    Range r;
    r.begin = src.find(signature);
    if (r.begin == std::string::npos) return r;
    const size_t close = src.find("\n}\n", r.begin);
    if (close == std::string::npos) { r.begin = std::string::npos; return r; }
    r.end = close + 3;   // strlen("\n}\n")
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

// Every out-of-line member definition, as (offset of the "DASHWorkSource::"
// token, member name). Used to name the function ENCLOSING an arbitrary offset
// without hardcoding a signature list — a newly added reader is caught by name
// instead of slipping past a stale allowlist.
struct MemberMark { size_t at; std::string name; };

std::vector<MemberMark> member_marks(const std::string& src)
{
    static const std::string kQual = "DASHWorkSource::";
    std::vector<MemberMark> out;
    size_t pos = 0;
    while ((pos = src.find(kQual, pos)) != std::string::npos) {
        size_t i = pos + kQual.size();
        std::string name;
        while (i < src.size()
               && (std::isalnum(static_cast<unsigned char>(src[i])) || src[i] == '_'))
            name.push_back(src[i++]);
        if (!name.empty()) out.push_back({pos, name});
        pos += kQual.size();
    }
    return out;
}

// The whole identifier occupying `at`, so a substring hit inside a LONGER name
// (resolve_coin_state_arm contains "coin_state_") is not mistaken for a member
// access.
std::string identifier_at(const std::string& src, size_t at)
{
    auto is_id = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    };
    size_t b = at, e = at;
    while (b > 0 && is_id(src[b - 1])) --b;
    while (e < src.size() && is_id(src[e])) ++e;
    return src.substr(b, e - b);
}

std::string enclosing_member(const std::vector<MemberMark>& marks, size_t at)
{
    std::string name = "(file scope)";
    for (const auto& m : marks) {
        if (m.at > at) break;
        name = m.name;
    }
    return name;
}

const char* kResolveSig  = "DASHWorkSource::CoinStateArm DASHWorkSource::resolve_coin_state_arm()";
const char* kSourceArgSig = "void DASHWorkSource::resource_template_now(CoinStateArm arm)";
const char* kCachedSig   = "DASHWorkSource::cached_work() const";

} // namespace

// ── The thread that is NOT the owner must not be able to reach NodeCoinState ─
// resource_template_now(CoinStateArm) is the body the refresh_executor_ job
// runs — i.e. the rpc_pool thread. A single textual reference to coin_state_
// inside it is the whole bug back.
TEST(DashWorkSourceOwnership, SourcingFunctionNeverTouchesCoinState)
{
    const std::string src  = strip_comments(read_text(DASH_WORK_SOURCE_SRC));
    const std::string body = member_body(src, kSourceArgSig);
    ASSERT_FALSE(body.empty())
        << "resource_template_now(CoinStateArm arm) not found in "
        << DASH_WORK_SOURCE_SRC
        << " — the ownership split (#1134) is absent, so the function the "
           "refresh_executor_ job runs still resolves the arm itself.";
    EXPECT_EQ(body.find("coin_state_"), std::string::npos)
        << "resource_template_now() runs on the rpc_pool worker whenever "
           "refresh_executor_ is wired and must never read NodeCoinState (no "
           "mutex; select_work() hands out raw pointers into live containers -> "
           "the 2026-08-05 heap corruption, on the SERVE path). Resolve on the "
           "owning thread in resolve_coin_state_arm() and hand it a value.";
}

// ── Enumerate EVERY coin_state_ read and name the function it sits in ───────
// The allowlist is the set of members that provably run on the coin-state
// owning thread. A new reader anywhere else fails here BY NAME, without anyone
// having to remember to extend a signature list.
TEST(DashWorkSourceOwnership, EveryCoinStateReadSitsInAnOwningThreadMember)
{
    const std::string src = strip_comments(read_text(DASH_WORK_SOURCE_SRC));
    const auto marks = member_marks(src);
    ASSERT_FALSE(marks.empty()) << "no DASHWorkSource:: member definitions found";

    // DASHWorkSource      -> the constructor's initialiser list (binds the ref)
    // resolve_coin_state_arm -> THE owning-thread resolver (#1134)
    // cached_work         -> serve-time embedded re-check; owning thread, see hpp
    // get_work            -> IWorkSource seam, no production caller (tests only)
    const std::vector<std::string> allowed = {
        "DASHWorkSource", "resolve_coin_state_arm", "cached_work", "get_work"};

    size_t pos = 0, seen = 0;
    while ((pos = src.find("coin_state_", pos)) != std::string::npos) {
        // Member accesses only — not resolve_coin_state_arm(), which merely
        // contains the member's name.
        if (identifier_at(src, pos) != "coin_state_") { pos += 11; continue; }
        ++seen;
        const std::string who = enclosing_member(marks, pos);
        bool ok = false;
        for (const auto& a : allowed) if (a == who) { ok = true; break; }
        EXPECT_TRUE(ok)
            << "NodeCoinState is read inside DASHWorkSource::" << who
            << "(), which is not on the coin-state owning-thread allowlist. "
               "NodeCoinState has ZERO mutexes and select_work() hands raw "
               "pointers into m_mnstates/m_sml; reading it off the io thread is "
               "the 2026-08-05 heap-corruption shape. Resolve on the owning "
               "thread (resolve_coin_state_arm) and pass a by-value CoinStateArm.";
        pos += 11;   // strlen("coin_state_")
    }
    EXPECT_GT(seen, 0u) << "no coin_state_ references at all — the guard has "
                           "nothing to protect; did the member get renamed?";
}

// ── The owning thread must not take a dashd RPC ─────────────────────────────
// select_work()'s fallback arm is a dashd getblocktemplate behind
// NodeRPC::m_rpc_mutex (12 s socket deadline). Resolving on the io thread is
// only correct because that arm is bound to a NO-OP here; binding the real
// fallback would convert a rare crash into routine multi-second serve stalls —
// exactly the trade PR #1135 rejected a NodeCoinState mutex for.
TEST(DashWorkSourceOwnership, OwningThreadResolutionTakesNoDashdRpc)
{
    const std::string src = strip_comments(read_text(DASH_WORK_SOURCE_SRC));
    EXPECT_EQ(src.find("coin_state_.select_work(dashd_fallback_)"), std::string::npos)
        << "select_work() is being handed the REAL dashd fallback on the "
           "coin-state owning (io) thread. That puts a 12 s getblocktemplate "
           "deadline on the thread that serves 26 stratum sessions. The "
           "fallback RPC belongs in resource_template_now(), which runs on the "
           "rpc_pool when one is wired.";

    const Range resolve = member_range(src, kResolveSig);
    ASSERT_NE(resolve.begin, std::string::npos)
        << "resolve_coin_state_arm() not found — the #1134 split is absent.";
    EXPECT_EQ(count_of(src, "coin_state_.select_work("), 1u)
        << "exactly one select_work() call site is expected, inside "
           "resolve_coin_state_arm()";
    const size_t at = src.find("coin_state_.select_work(");
    ASSERT_NE(at, std::string::npos) << "select_work() call vanished entirely";
    EXPECT_TRUE(at > resolve.begin && at < resolve.end)
        << "select_work() is called from OUTSIDE resolve_coin_state_arm() — "
           "only the coin-state owning thread may read NodeCoinState.";
}

// ── The handoff happens BEFORE the post, not inside the job ─────────────────
TEST(DashWorkSourceOwnership, CachedWorkResolvesTheArmBeforePostingTheJob)
{
    const std::string src  = strip_comments(read_text(DASH_WORK_SOURCE_SRC));
    const std::string body = member_body(src, kCachedSig);
    ASSERT_FALSE(body.empty()) << "cached_work() not found";

    const size_t resolved = body.find("resolve_coin_state_arm()");
    ASSERT_NE(resolved, std::string::npos)
        << "cached_work() does not resolve the arm at all — the background job "
           "is still reading NodeCoinState on the rpc_pool thread.";
    const size_t posted = body.find("refresh_executor_(");
    ASSERT_NE(posted, std::string::npos)
        << "the refresh_executor_ post site vanished from cached_work()";
    EXPECT_LT(resolved, posted)
        << "resolve_coin_state_arm() must run BEFORE the job is posted — "
           "resolving inside the lambda would put the NodeCoinState read back "
           "on the rpc_pool thread, which is the entire defect.";

    // The posted lambda must carry the arm; capturing `this` alone and calling
    // the no-arg overload is the pre-fix shape.
    EXPECT_NE(body.find("resource_template_now(std::move(arm))"), std::string::npos)
        << "the posted job must consume the by-value CoinStateArm resolved "
           "above, not re-derive it.";
}

// ── The value that crosses the thread boundary must OWN what it carries ─────
// A pointer/reference member would re-open the lifetime hole with none of the
// textual evidence the tests above look for.
TEST(DashWorkSourceOwnership, CoinStateArmIsAllByValue)
{
    const std::string hdr = strip_comments(read_text(DASH_WORK_SOURCE_HDR));
    const size_t s = hdr.find("struct CoinStateArm {");
    ASSERT_NE(s, std::string::npos)
        << "struct CoinStateArm (the by-value ownership handoff) not found in "
        << DASH_WORK_SOURCE_HDR;
    const size_t e = hdr.find("\n    };\n", s);
    ASSERT_NE(e, std::string::npos) << "CoinStateArm has no terminator";
    const std::string body = hdr.substr(s, e - s);

    EXPECT_NE(body.find("coin::DashWorkData  work;"), std::string::npos)
        << "CoinStateArm must carry the embedded template BY VALUE (DashWorkData "
           "is all-by-value; owning it is what makes the off-thread read safe)";
    EXPECT_EQ(body.find("DashWorkData*"), std::string::npos)
        << "CoinStateArm must not carry a POINTER to the template";
    EXPECT_EQ(body.find("NodeCoinState"), std::string::npos)
        << "CoinStateArm must not reference NodeCoinState in any form";
    EXPECT_EQ(body.find("MnStateMachine"), std::string::npos)
        << "CoinStateArm must not carry the MN state map (that is the live container)";
    EXPECT_EQ(body.find("CSimplifiedMNList"), std::string::npos)
        << "CoinStateArm must not carry the SML (that is the live container)";
    EXPECT_EQ(body.find("&"), std::string::npos)
        << "CoinStateArm must hold no reference member — the whole point is that "
           "it outlives nothing.";
}

// ── The contract text must not re-assert the thing that made this look safe ──
// The class header claimed `coin_state_` "has its own internal locking". It has
// none (grep -c -i mutex node_coin_state.hpp -> 0). That sentence is why a
// background re-source over it read as obviously fine for as long as it did.
TEST(DashWorkSourceOwnership, HeaderDoesNotClaimCoinStateLocksItself)
{
    const std::string hdr = read_text(DASH_WORK_SOURCE_HDR);   // comments ARE the subject
    EXPECT_EQ(hdr.find("`coin_state_` has its own internal locking"), std::string::npos)
        << "the threading contract still claims NodeCoinState locks itself. It "
           "contains ZERO mutexes. Say so, or the next reader repeats #1134.";
    EXPECT_NE(hdr.find("NO internal locking"), std::string::npos)
        << "the threading contract must state that coin_state_ has no internal "
           "locking and name the threads allowed to read it.";
}
