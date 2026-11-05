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
//     that proves the bound assertion can fail).
//   * source-structural (same posture as race913_lock_guard_test.cpp): the
//     shipped node.cpp must call the evictor from clean_tracker's IO-phase
//     post, and must not keep a compute-thread evictor in prune_shares. RED on
//     master (no evict_known_txs_io_phase anywhere); GREEN with the fix.
//
// p2pool-merged-v36 surface: NONE (local tx-forward cache hygiene).

#include <gtest/gtest.h>

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

// Body text of `<sig>...` up to the first column-0 closing brace.
std::string function_body(const std::string& src, const std::string& sig)
{
    const auto start = src.find(sig);
    if (start == std::string::npos)
        return "";
    auto end = src.find("\n}\n", start);
    if (end == std::string::npos)
        end = src.size();
    return src.substr(start, end - start);
}

std::string read_node_src()
{
    std::ifstream in(DGB_NODE_SRC);
    EXPECT_TRUE(in.good()) << "cannot open " << DGB_NODE_SRC;
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
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

// The live clean_tracker() cycle must call the evictor, from the IO-phase post
// (after the compute-thread body hands back to *m_context), not the compute
// thread.
TEST(DgbKnownTxsEvict, CleanTrackerIoPhaseCallsEvictor)
{
    const std::string body = function_body(read_node_src(), "void NodeImpl::clean_tracker()");
    ASSERT_FALSE(body.empty()) << "clean_tracker() not found in node.cpp";

    const auto io_post = body.find("boost::asio::post(*m_context");
    ASSERT_NE(io_post, std::string::npos) << "clean_tracker IO-phase post not found";
    const auto call = body.find("evict_known_txs_io_phase();");
    ASSERT_NE(call, std::string::npos)
        << "clean_tracker() never enforces m_max_known_txs (m_known_txs grows unbounded)";
    EXPECT_GT(call, io_post)
        << "evictor called on the compute thread; it races the lock-free "
           "io-thread remember_tx insert";
}

// The evictor body applies the cap to the real node containers.
TEST(DgbKnownTxsEvict, EvictorAppliesCapToNodeContainers)
{
    const std::string body =
        function_body(read_node_src(), "void NodeImpl::evict_known_txs_io_phase()");
    ASSERT_FALSE(body.empty()) << "evict_known_txs_io_phase() not defined in node.cpp";
    EXPECT_NE(body.find("dgb::enforce_known_txs_cap(m_known_txs, m_known_txs_order, "
                        "m_max_known_txs)"),
              std::string::npos)
        << "evict_known_txs_io_phase() must apply m_max_known_txs to m_known_txs";
}

// No compute-thread evictor left in the dead prune_shares() for a future caller
// to arm.
TEST(DgbKnownTxsEvict, PruneSharesHasNoComputeThreadEvictor)
{
    const std::string body = function_body(read_node_src(), "void NodeImpl::prune_shares(");
    ASSERT_FALSE(body.empty()) << "prune_shares() not found in node.cpp";
    EXPECT_EQ(body.find("evict_known_txs_to_cap"), std::string::npos);
    EXPECT_EQ(body.find("enforce_known_txs_cap"), std::string::npos);
}
