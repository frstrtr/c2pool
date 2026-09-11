// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-LTC.INGEST-BOUNDS — KATs + source-structural guards for the LTC ingest
// memory bounds that replace the RSS self-abort.
//
// PRODUCTION SHAPE BEING FIXED (contabo LTC node, 2026-09-09..11): the node
// self-aborted on rss_limit_mb ("=== RSS LIMIT EXCEEDED === RSS: 4047 MB") with
// "[ASYNC-DEFER] BACKPRESSURE: pending_adds at cap (256/256), dropping OLDEST
// queued batch" immediately before each abort. MAX_PENDING_ADDS was the only
// bound on the ingest path and it bounds neither the phase-1 verify backlog
// upstream of it, nor the SIZE of a batch, nor the caches downstream.
//
// Folded into the EXISTING allowlisted `share_test` target — a standalone
// add_executable would be absent from build.yml's --target list and reported
// "Not Run" by CTest (the #769 trap).

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

#include <impl/ltc/ingest_budget.hpp>
#include <impl/ltc/peer.hpp>

#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must be defined by CMake to the path of src/impl"
#endif

namespace {

// ─────────────────────────────────────────────────────────────────────────
// 1. IngestBudget — the admission bound that did not exist at all before.
// ─────────────────────────────────────────────────────────────────────────

TEST(LtcIngestBudget, AdmitsUpToTheShareCeilingThenRefuses)
{
    ltc::IngestBudget b(100, 1'000'000);
    EXPECT_TRUE(b.try_admit(60, 10));
    EXPECT_TRUE(b.try_admit(40, 10));
    EXPECT_EQ(b.shares(), 100u);
    // One share past the ceiling is refused...
    EXPECT_FALSE(b.try_admit(1, 1));
    // ...and a refusal reserves NOTHING (this is what makes a storm survivable:
    // a refused batch must not permanently consume budget).
    EXPECT_EQ(b.shares(), 100u);
    EXPECT_EQ(b.bytes(), 20u);
}

TEST(LtcIngestBudget, AdmitsUpToTheByteCeilingIndependentlyOfTheShareCeiling)
{
    ltc::IngestBudget b(1'000'000, 1024);
    EXPECT_TRUE(b.try_admit(1, 1024));
    EXPECT_FALSE(b.try_admit(1, 1));          // bytes full, shares nowhere near
    EXPECT_EQ(b.bytes(), 1024u);
    EXPECT_EQ(b.shares(), 1u);
}

TEST(LtcIngestBudget, ReleaseGivesTheReservationBackAndNeverGoesNegative)
{
    ltc::IngestBudget b(10, 1000);
    ASSERT_TRUE(b.try_admit(10, 1000));
    EXPECT_FALSE(b.try_admit(1, 1));
    b.release(10, 1000);
    EXPECT_EQ(b.shares(), 0u);
    EXPECT_EQ(b.bytes(), 0u);
    EXPECT_TRUE(b.try_admit(10, 1000));       // capacity is reusable, not spent
}

TEST(LtcIngestBudget, OneOversizedBatchIsRefusedWholeRatherThanPartiallyAdmitted)
{
    ltc::IngestBudget b(8192, 128u * 1024u * 1024u);
    EXPECT_FALSE(b.try_admit(8193, 1));
    EXPECT_EQ(b.shares(), 0u);
    EXPECT_TRUE(b.try_admit(8192, 1));
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Ancestor-walk depth bound. The recursion in download_shares had NO
//    termination condition other than reaching a hash we already hold, so a
//    challenger walk ran to genesis, pulling shares that clean_tracker Step 3
//    drops as soon as they land.
// ─────────────────────────────────────────────────────────────────────────

TEST(LtcAncestorWalkDepth, StopsExactlyAtThePruningZone)
{
    const std::uint64_t CL = 8640;            // ltc mainnet params.hpp
    const std::uint64_t zone = 2 * CL + 10;   // 17290, mirrors share_tracker's rule
    EXPECT_TRUE (ltc::walk_may_continue(0, CL));
    EXPECT_TRUE (ltc::walk_may_continue(zone - 1, CL));
    EXPECT_FALSE(ltc::walk_may_continue(zone, CL));
    EXPECT_FALSE(ltc::walk_may_continue(zone + 1000, CL));
}

TEST(LtcAncestorWalkDepth, ScalesWithChainLengthNotAHardcodedNumber)
{
    const std::uint64_t CL = 400;             // ltc testnet params.hpp
    EXPECT_TRUE (ltc::walk_may_continue(2 * CL + 9, CL));
    EXPECT_FALSE(ltc::walk_may_continue(2 * CL + 10, CL));
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Per-peer remembered-tx byte cap. p2pool bounds this store and disconnects
//    over the cap; the c2pool port carried the bound over COMMENTED OUT, so one
//    peer could grow a map of full transactions without limit — the only erase
//    path is that same peer choosing to send forget_tx.
// ─────────────────────────────────────────────────────────────────────────

TEST(LtcRememberedTxCap, ChargesEachInsertAndTripsOverTheCap)
{
    ltc::Peer peer;
    ltc::coin::MutableTransaction mtx;
    ltc::coin::Transaction tx(mtx);
    EXPECT_FALSE(peer.remembered_txs_over_cap());
    EXPECT_EQ(peer.m_remembered_txs_size, 0);

    // Just under the cap: still accepted.
    peer.remember_tx(uint256(1), tx, ltc::Peer::MAX_REMEMBERED_TXS_SIZE
                                     - ltc::Peer::REMEMBERED_TX_OVERHEAD);
    EXPECT_FALSE(peer.remembered_txs_over_cap());
    EXPECT_EQ(peer.m_remembered_txs_size, ltc::Peer::MAX_REMEMBERED_TXS_SIZE);

    // One more byte of transaction data and the peer is over.
    peer.remember_tx(uint256(2), tx, 1);
    EXPECT_TRUE(peer.remembered_txs_over_cap());
    EXPECT_EQ(peer.m_remembered_txs.size(), 2u);
}

TEST(LtcRememberedTxCap, ForgetGivesBackExactlyWhatRememberCharged)
{
    ltc::Peer peer;
    ltc::coin::MutableTransaction mtx;
    ltc::coin::Transaction tx(mtx);
    peer.remember_tx(uint256(1), tx, 5000);
    peer.remember_tx(uint256(2), tx, 7000);
    const std::int64_t both = peer.m_remembered_txs_size;
    EXPECT_EQ(both, 5000 + 7000 + 2 * ltc::Peer::REMEMBERED_TX_OVERHEAD);

    peer.forget_tx(uint256(1));
    EXPECT_EQ(peer.m_remembered_txs_size, 7000 + ltc::Peer::REMEMBERED_TX_OVERHEAD);
    EXPECT_EQ(peer.m_remembered_txs.count(uint256(1)), 0u);

    // Forgetting something never remembered must not drive the counter negative
    // (a negative counter would silently un-bound the cap).
    peer.forget_tx(uint256(999));
    peer.forget_tx(uint256(2));
    EXPECT_EQ(peer.m_remembered_txs_size, 0);
    EXPECT_TRUE(peer.m_remembered_txs.empty());
}

TEST(LtcRememberedTxCap, ReRememberingTheSameHashDoesNotDoubleCharge)
{
    ltc::Peer peer;
    ltc::coin::MutableTransaction mtx;
    ltc::coin::Transaction tx(mtx);
    peer.remember_tx(uint256(1), tx, 5000);
    peer.remember_tx(uint256(1), tx, 5000);   // insert_or_assign overwrite
    EXPECT_EQ(peer.m_remembered_txs_size, 5000 + ltc::Peer::REMEMBERED_TX_OVERHEAD);
    peer.forget_tx(uint256(1));
    EXPECT_EQ(peer.m_remembered_txs_size, 0);
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Source-structural guard: the cache eviction must stay WIRED.
//
//    This is the "not dead again" pin. prune_shares() held the only code that
//    enforced cache_max_shared_hashes / cache_max_known_txs / cache_max_raw_shares
//    and it had NO CALL SITE in the whole tree — definition, declaration, three
//    comments, and nothing else. A runtime test cannot see that: the function
//    was correct, it simply never ran. Assert the shape in the shipped source.
// ─────────────────────────────────────────────────────────────────────────

std::string read_text(const std::string& path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

// Replace every comment with spaces, preserving byte offsets. The fix's own doc
// comments deliberately name prune_shares to explain what was removed, so these
// assertions MUST run over comment-free code.
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

std::size_t count_of(const std::string& hay, const std::string& needle)
{
    std::size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) { ++n; pos += needle.size(); }
    return n;
}

TEST(LtcCacheEvictionWiring, EvictionIsDefinedAndActuallyCalled)
{
    const std::string cpp = strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/ltc/node.cpp"));
    const std::string hpp = strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/ltc/node.hpp"));

    // Definition + at least one call site. One occurrence = dead code again.
    EXPECT_GE(count_of(cpp, "evict_caches_io_phase("), 2u)
        << "evict_caches_io_phase must be DEFINED and CALLED in ltc/node.cpp — "
           "a single occurrence means the cache_max_* knobs are inert again";
    EXPECT_EQ(count_of(hpp, "evict_caches_io_phase("), 1u);

    // The never-called predecessor must be gone from the code (comments may
    // still explain the history; those are stripped above).
    EXPECT_EQ(count_of(cpp, "prune_shares"), 0u)
        << "prune_shares had no call site; it must not come back";
    EXPECT_EQ(count_of(hpp, "prune_shares"), 0u);
}

TEST(LtcCacheEvictionWiring, RawShareCacheIsErasedOnChainRemovalAndWiredInBothCtors)
{
    const std::string hpp = strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/ltc/node.hpp"));
    // m_raw_share_cache had no erase path anywhere: tie it to chain membership.
    EXPECT_EQ(count_of(hpp, "m_raw_share_cache.erase("), 1u)
        << "the on_removed hook must erase the raw-share cache entry";
    // Wired from BOTH constructors (the default ctor is the unit-test path).
    EXPECT_EQ(count_of(hpp, "wire_chain_hooks()"), 3u)
        << "wire_chain_hooks must be defined and called from both constructors";
}

TEST(LtcAncestorWalkDepth, DownloadSharesConsultsTheDepthBound)
{
    const std::string cpp = strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/ltc/node.cpp"));
    // The recursion must consult the bound, and must not recurse on a batch the
    // ingest budget refused (that combination is the re-request treadmill).
    EXPECT_GE(count_of(cpp, "walk_may_continue("), 1u)
        << "the download_shares ancestor recursion must be depth-bounded";
    EXPECT_GE(count_of(cpp, "if (!admitted)"), 1u)
        << "download_shares must not queue the next hop for a refused batch";
}

} // namespace
