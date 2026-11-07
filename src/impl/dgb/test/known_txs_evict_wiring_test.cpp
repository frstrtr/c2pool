// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-DGB.EVICT: the m_known_txs cap must be enforced on the LIVE clean pass.
//
// Before this fix the only core::evict_known_txs_to_cap call in the DGB lane sat
// inside NodeImpl::prune_shares(), which has zero callers, so m_max_known_txs was
// never applied and m_known_txs + m_known_txs_order grew for the life of the
// process. The fix adds NodeImpl::evict_known_txs_io_phase(), called once per
// clean_tracker() cycle from its IO-phase post. It runs on the IO thread because
// remember_tx inserts into m_known_txs there with no lock (LTC #1586 shape).
//
// Two halves:
//   * behavioural: N shares' worth of remember_tx learns with a periodic
//     dgb::enforce_known_txs_cap pass stay bounded at the cap and keep the
//     newest txs; the same stream with no pass leaks past the cap (the control
//     that proves the bound assertion can fail). Re-learns, evicted-then-relearned
//     txs and a desynced recency sidecar are covered too.
//   * source-structural (same posture as race913_lock_guard_test.cpp): the
//     shipped node.cpp must call the evictor from INSIDE clean_tracker's IO-phase
//     post lambda, exactly once in the file, and must not keep a compute-thread
//     evictor in prune_shares. RED on master (no evict_known_txs_io_phase
//     anywhere); GREEN with the fix.
//
// The structural scan runs on node.cpp with comments and string/char literals
// blanked out, and finds bodies by brace matching, so a commented-out call or a
// log string cannot satisfy (or trip) a guard. The scanner itself is pinned by
// the GuardSelfCheck tests below, which feed it known-bad node.cpp shapes and
// require each one to be rejected. Lanes copying this test (#1948) should keep
// those mutants: they are what proves the guard can go RED.
//
// p2pool-merged-v36 surface: NONE (local tx-forward cache hygiene).

#include <gtest/gtest.h>

#include <cctype>
#include <cstdint>
#include <deque>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include <core/uint256.hpp>
#include <impl/dgb/known_txs_retention.hpp>

#ifndef DGB_NODE_SRC
#error "DGB_NODE_SRC must be defined by CMake to the path of src/impl/dgb/node.cpp"
#endif

namespace {

uint256 tx_hash(uint64_t i) { return uint256(i); }

// remember_tx-style learn (protocol_{legacy,actual}.cpp): a NEW hash goes into
// the map and is appended to the recency sidecar; a repeat is a no-op.
void learn(std::map<uint256, int>& known, std::deque<uint256>& order, uint64_t i)
{
    const auto h = tx_hash(i);
    if (!known.contains(h)) {
        known.emplace(h, 1);
        order.push_back(h);
    }
}

constexpr std::size_t kCap           = 64;
constexpr int         kShares        = 2000;  // shares received
constexpr int         kTxsPerShare   = 7;     // new txs each share references
constexpr int         kSharesPerClean = 25;   // shares between clean_tracker cycles

// ── source scanner ───────────────────────────────────────────────────────────

// Replace comments and string/char literal contents with spaces (newlines kept,
// so offsets and line structure survive). Braces and calls inside comments or
// strings then cannot affect the brace matcher or the call searches.
std::string strip_comments_and_literals(const std::string& src)
{
    std::string out = src;
    std::size_t i = 0;
    const std::size_t n = src.size();
    auto blank = [&](std::size_t from, std::size_t to) {
        for (std::size_t k = from; k < to && k < n; ++k)
            if (out[k] != '\n')
                out[k] = ' ';
    };
    while (i < n) {
        const char c = src[i];
        if (c == '/' && i + 1 < n && src[i + 1] == '/') {
            const auto end = src.find('\n', i);
            const std::size_t stop = (end == std::string::npos) ? n : end;
            blank(i, stop);
            i = stop;
        } else if (c == '/' && i + 1 < n && src[i + 1] == '*') {
            const auto end = src.find("*/", i + 2);
            const std::size_t stop = (end == std::string::npos) ? n : end + 2;
            blank(i, stop);
            i = stop;
        } else if (c == '"' || c == '\'') {
            // A quote between two digits is a C++14 digit separator, not a literal.
            if (c == '\'' && i > 0 && i + 1 < n && std::isxdigit(static_cast<unsigned char>(src[i - 1]))
                && std::isxdigit(static_cast<unsigned char>(src[i + 1]))) {
                ++i;
                continue;
            }
            std::size_t j = i + 1;
            while (j < n && src[j] != c && src[j] != '\n') {
                if (src[j] == '\\')
                    ++j;
                ++j;
            }
            blank(i + 1, j);
            i = (j < n) ? j + 1 : n;
        } else {
            ++i;
        }
    }
    return out;
}

// Index of the brace matching the '{' at `open`, or npos. Input must already be
// stripped of comments and literals.
std::size_t matching_brace(const std::string& s, std::size_t open)
{
    if (open >= s.size() || s[open] != '{')
        return std::string::npos;
    int depth = 0;
    for (std::size_t i = open; i < s.size(); ++i) {
        if (s[i] == '{')
            ++depth;
        else if (s[i] == '}' && --depth == 0)
            return i;
    }
    return std::string::npos;
}

// Brace-matched body (signature through closing brace) of the first DEFINITION
// of `sig`, i.e. an occurrence whose next significant token is the opening
// brace (skipping a `const`/`noexcept`/`override` tail). Empty if none.
std::string function_body(const std::string& s, const std::string& sig)
{
    for (auto pos = s.find(sig); pos != std::string::npos; pos = s.find(sig, pos + 1)) {
        const auto close_paren = s.find(')', pos + sig.size() - 1);
        if (close_paren == std::string::npos)
            return "";
        const auto next = s.find_first_of("{;", close_paren);
        if (next == std::string::npos || s[next] != '{')
            continue;  // a declaration or call, not the definition
        const auto end = matching_brace(s, next);
        if (end == std::string::npos)
            return "";
        return s.substr(pos, end + 1 - pos);
    }
    return "";
}

std::size_t count_of(const std::string& s, const std::string& needle)
{
    std::size_t n = 0;
    for (auto p = s.find(needle); p != std::string::npos; p = s.find(needle, p + 1))
        ++n;
    return n;
}

// Verdict on the clean_tracker wiring of a (raw) node.cpp. Empty == pass;
// otherwise the reason it fails. Shared by the live guard and the self-checks.
std::string clean_tracker_wiring_verdict(const std::string& raw)
{
    const std::string s = strip_comments_and_literals(raw);

    const std::string body = function_body(s, "void NodeImpl::clean_tracker()");
    if (body.empty())
        return "clean_tracker() definition not found";

    const std::string call = "evict_known_txs_io_phase();";
    if (body.find(call) == std::string::npos)
        return "clean_tracker() never enforces m_max_known_txs (m_known_txs grows unbounded)";

    // The call must sit inside an IO-phase post lambda's braces. Being textually
    // after the post is not enough: a call after the post's closing `});` still
    // runs on the compute thread and races the lock-free remember_tx insert.
    const std::string post = "boost::asio::post(*m_context";
    bool in_io_lambda = false;
    bool saw_post = false;
    for (auto p = body.find(post); p != std::string::npos; p = body.find(post, p + 1)) {
        saw_post = true;
        const auto open = body.find('{', p);
        const auto close = matching_brace(body, open);
        if (open == std::string::npos || close == std::string::npos)
            return "clean_tracker IO-phase post lambda is unbalanced";
        const auto c = body.find(call, open);
        if (c != std::string::npos && c < close)
            in_io_lambda = true;
    }
    if (!saw_post)
        return "clean_tracker IO-phase post not found";
    if (!in_io_lambda)
        return "evictor called outside the IO-phase post lambda (compute thread); it "
               "races the lock-free io-thread remember_tx insert";
    if (count_of(body, call) != 1)
        return "evictor called more than once per clean_tracker() cycle";

    // One definition plus one call in the whole file: any other caller would be
    // a second, unaudited thread context for an unlocked container.
    if (count_of(s, "evict_known_txs_io_phase(") != 2)
        return "evict_known_txs_io_phase() must have exactly one call site (clean_tracker IO phase)";

    return "";
}

std::string evictor_body_verdict(const std::string& raw)
{
    const std::string s = strip_comments_and_literals(raw);
    const std::string body = function_body(s, "void NodeImpl::evict_known_txs_io_phase()");
    if (body.empty())
        return "evict_known_txs_io_phase() not defined in node.cpp";
    if (body.find("dgb::enforce_known_txs_cap(m_known_txs, m_known_txs_order, "
                  "m_max_known_txs)") == std::string::npos)
        return "evict_known_txs_io_phase() must apply m_max_known_txs to m_known_txs";
    return "";
}

std::string prune_shares_verdict(const std::string& raw)
{
    const std::string s = strip_comments_and_literals(raw);
    const std::string body = function_body(s, "void NodeImpl::prune_shares(");
    if (body.empty())
        return "prune_shares() not found in node.cpp";
    if (body.find("evict_known_txs_to_cap") != std::string::npos
        || body.find("enforce_known_txs_cap") != std::string::npos
        || body.find("evict_known_txs_io_phase") != std::string::npos)
        return "compute-thread evictor left in prune_shares()";
    return "";
}

std::string read_node_src()
{
    std::ifstream in(DGB_NODE_SRC);
    EXPECT_TRUE(in.good()) << "cannot open " << DGB_NODE_SRC;
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Minimal node.cpp shape that passes all three guards; the mutants below each
// break exactly one property.
const char* kGoodShape = R"CPP(
void NodeImpl::prune_shares(const uint256& x)
{
    // m_known_txs eviction moved to evict_known_txs_io_phase()
    m_raw_share_cache.clear();
}

void NodeImpl::evict_known_txs_io_phase()
{
    dgb::enforce_known_txs_cap(m_known_txs, m_known_txs_order, m_max_known_txs);
}

void NodeImpl::clean_tracker()
{
    boost::asio::post(m_think_pool, [this]() {
      LOG_INFO << "clean {";
      boost::asio::post(*m_context, [this]() {
        evict_known_txs_io_phase();
        drain_pending_adds();
      });
    });
}
)CPP";

std::string mutate(const std::string& from, const std::string& to)
{
    std::string s = kGoodShape;
    const auto p = s.find(from);
    EXPECT_NE(p, std::string::npos) << "mutant anchor missing: " << from;
    if (p != std::string::npos)
        s.replace(p, from.size(), to);
    return s;
}

} // namespace

// N shares with the periodic pass: bounded at the cap, sidecar in sync, newest
// txs kept.
TEST(DgbKnownTxsEvict, PeriodicPassKeepsCacheBoundedOverNShares)
{
    std::map<uint256, int> known;
    std::deque<uint256> order;
    uint64_t next = 1;
    std::size_t evicted_total = 0;

    for (int share = 1; share <= kShares; ++share) {
        for (int k = 0; k < kTxsPerShare; ++k)
            learn(known, order, next++);
        if (share % kSharesPerClean == 0) {
            evicted_total += dgb::enforce_known_txs_cap(known, order, kCap);
            ASSERT_LE(known.size(), kCap) << "cap breached after share " << share;
            ASSERT_EQ(order.size(), known.size()) << "recency sidecar desynced";
        }
    }

    const uint64_t learned = next - 1;
    EXPECT_EQ(known.size(), kCap);
    EXPECT_EQ(evicted_total, learned - kCap);
    for (uint64_t i = next - kCap; i < next; ++i)
        EXPECT_TRUE(known.contains(tx_hash(i))) << "recent tx " << i << " evicted";
    EXPECT_FALSE(known.contains(tx_hash(next - kCap - 1))) << "stale tx survived";
}

// Under the cap the pass is a no-op and reports zero evictions.
TEST(DgbKnownTxsEvict, UnderCapIsNoOp)
{
    std::map<uint256, int> known;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= kCap; ++i)
        learn(known, order, i);
    EXPECT_EQ(dgb::enforce_known_txs_cap(known, order, kCap), 0u);
    EXPECT_EQ(known.size(), kCap);
    EXPECT_EQ(order.size(), kCap);
}

// Control: the same share stream with no pass (pre-fix master behaviour) grows
// without bound, so the bounded assertion above is not vacuous.
TEST(DgbKnownTxsEvict, NoPassGrowsPastCap)
{
    std::map<uint256, int> known;
    std::deque<uint256> order;
    uint64_t next = 1;
    for (int share = 1; share <= kShares; ++share)
        for (int k = 0; k < kTxsPerShare; ++k)
            learn(known, order, next++);
    EXPECT_GT(known.size(), kCap);
    EXPECT_EQ(known.size(), static_cast<std::size_t>(kShares) * kTxsPerShare);
    EXPECT_EQ(order.size(), known.size());
}

// Shares re-reference txs already held: repeats must not grow either container,
// so the sidecar never carries duplicate keys into the eviction walk.
TEST(DgbKnownTxsEvict, RepeatLearnsDoNotGrowEitherContainer)
{
    std::map<uint256, int> known;
    std::deque<uint256> order;
    for (int round = 0; round < 10; ++round)
        for (uint64_t i = 1; i <= kCap; ++i)
            learn(known, order, i);
    EXPECT_EQ(known.size(), kCap);
    EXPECT_EQ(order.size(), kCap);
    EXPECT_EQ(dgb::enforce_known_txs_cap(known, order, kCap), 0u);
}

// A tx evicted and later seen again is learned as NEW (newest), so the next
// pass keeps it and drops older entries instead.
TEST(DgbKnownTxsEvict, EvictedThenRelearnedTxIsKeptAsNewest)
{
    std::map<uint256, int> known;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= 2 * kCap; ++i)
        learn(known, order, i);
    ASSERT_EQ(dgb::enforce_known_txs_cap(known, order, kCap), kCap);
    ASSERT_FALSE(known.contains(tx_hash(1)));

    learn(known, order, 1);  // tx 1 comes back on a later share
    EXPECT_EQ(dgb::enforce_known_txs_cap(known, order, kCap), 1u);
    EXPECT_TRUE(known.contains(tx_hash(1))) << "relearned tx evicted as if still oldest";
    EXPECT_FALSE(known.contains(tx_hash(kCap + 1))) << "oldest survivor not evicted";
    EXPECT_EQ(known.size(), kCap);
    EXPECT_EQ(order.size(), known.size());
}

// Desync tolerance: a key erased from the map by some other path leaves a
// tombstone in the sidecar. The pass must still reach the cap on live entries
// (a tombstone must not count as an eviction) and drop leading tombstones.
TEST(DgbKnownTxsEvict, SidecarTombstonesDoNotDefeatTheCap)
{
    std::map<uint256, int> known;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= 2 * kCap; ++i)
        learn(known, order, i);
    for (uint64_t i = 1; i <= kCap / 2; ++i)
        known.erase(tx_hash(i));  // tombstones at the front of `order`
    const std::size_t live_before = known.size();

    const std::size_t evicted = dgb::enforce_known_txs_cap(known, order, kCap);
    EXPECT_EQ(known.size(), kCap);
    EXPECT_EQ(evicted, live_before - kCap) << "tombstones counted as evictions";
    ASSERT_FALSE(order.empty());
    EXPECT_TRUE(known.contains(order.front())) << "leading tombstone left in sidecar";
    EXPECT_EQ(order.size(), known.size());
}

// The live clean_tracker() cycle must call the evictor exactly once, from
// inside the IO-phase post lambda (after the compute-thread body hands back to
// *m_context), and nowhere else in node.cpp.
TEST(DgbKnownTxsEvict, CleanTrackerIoPhaseCallsEvictor)
{
    const std::string why = clean_tracker_wiring_verdict(read_node_src());
    EXPECT_TRUE(why.empty()) << why;
}

// The evictor body applies the cap to the real node containers.
TEST(DgbKnownTxsEvict, EvictorAppliesCapToNodeContainers)
{
    const std::string why = evictor_body_verdict(read_node_src());
    EXPECT_TRUE(why.empty()) << why;
}

// No compute-thread evictor left in the dead prune_shares() for a future caller
// to arm.
TEST(DgbKnownTxsEvict, PruneSharesHasNoComputeThreadEvictor)
{
    const std::string why = prune_shares_verdict(read_node_src());
    EXPECT_TRUE(why.empty()) << why;
}

// ── guard self-checks: the scanner must reject each known-bad shape ─────────

TEST(DgbKnownTxsEvictGuardSelfCheck, GoodShapePasses)
{
    EXPECT_EQ(clean_tracker_wiring_verdict(kGoodShape), "");
    EXPECT_EQ(evictor_body_verdict(kGoodShape), "");
    EXPECT_EQ(prune_shares_verdict(kGoodShape), "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, CommentedOutCallIsRejected)
{
    EXPECT_NE(clean_tracker_wiring_verdict(
                  mutate("        evict_known_txs_io_phase();\n",
                         "        // evict_known_txs_io_phase();\n")),
              "");
    EXPECT_NE(clean_tracker_wiring_verdict(
                  mutate("        evict_known_txs_io_phase();\n",
                         "        /* evict_known_txs_io_phase(); */\n")),
              "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, CallInsideStringLiteralIsRejected)
{
    EXPECT_NE(clean_tracker_wiring_verdict(
                  mutate("        evict_known_txs_io_phase();\n",
                         "        LOG_INFO << \"evict_known_txs_io_phase();\";\n")),
              "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, ComputeThreadCallIsRejected)
{
    // Moved before the IO post: runs on m_think_pool.
    std::string s = mutate("        evict_known_txs_io_phase();\n", "");
    s.replace(s.find("      LOG_INFO"), 0, "      evict_known_txs_io_phase();\n");
    EXPECT_NE(clean_tracker_wiring_verdict(s), "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, CallAfterIoPostClosesIsRejected)
{
    // Textually after the post, but outside its lambda: still the compute thread.
    // The old "call offset > post offset" guard passed this shape.
    std::string s = mutate("        evict_known_txs_io_phase();\n", "");
    s.replace(s.find("      });\n    });"), std::string("      });\n").size(),
              "      });\n      evict_known_txs_io_phase();\n");
    EXPECT_NE(clean_tracker_wiring_verdict(s), "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, SecondCallSiteIsRejected)
{
    const std::string s = std::string(kGoodShape)
        + "\nvoid NodeImpl::think()\n{\n    evict_known_txs_io_phase();\n}\n";
    EXPECT_NE(clean_tracker_wiring_verdict(s), "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, EvictorWithoutCapIsRejected)
{
    EXPECT_NE(evictor_body_verdict(
                  mutate("    dgb::enforce_known_txs_cap(m_known_txs, m_known_txs_order, "
                         "m_max_known_txs);\n",
                         "    // dgb::enforce_known_txs_cap(m_known_txs, m_known_txs_order, "
                         "m_max_known_txs);\n")),
              "");
}

TEST(DgbKnownTxsEvictGuardSelfCheck, PruneSharesEvictorIsRejected)
{
    EXPECT_NE(prune_shares_verdict(
                  mutate("    m_raw_share_cache.clear();\n",
                         "    core::evict_known_txs_to_cap(m_known_txs, m_known_txs_order, "
                         "m_max_known_txs);\n")),
              "");
}
