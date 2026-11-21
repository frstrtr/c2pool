// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A locally minted share that solves a block reaches the found-block hook
// with the share readable (rides share_test).
//
// The stratum submit path (main_ltc create_share_fn) mints the share, drops
// its lock, then calls NodeImpl::notify_local_share(). That takes the tracker
// mutex EXCLUSIVELY (try_to_lock) and runs attempt_verify() inline, which
// fires the tracker hooks synchronously: m_on_block_found for a share meeting
// the block target and m_on_merged_block_check for every verified share. Both
// production hooks (main_ltc) read the share through NodeImpl::read_tracker().
// On the io thread that was a SHARED try-lock of the std::shared_mutex this
// very thread already owned: undefined behaviour, which glibc answers by
// refusing the lock. The hooks bailed at `if (!guard) return;`, so a block
// our own share solved got no found-block row (and no DOGE row) from this
// path. The compute thread was never affected: read_tracker() knows it holds
// the lock.
//
// Driven on a REAL ltc::NodeImpl with a REAL share: create_local_share() on
// testnet share targets (1 in 20 hashes passes) with header bits whose block
// target is above the share target, so the share it mints solves a block;
// notify_local_share() then verifies it for real (share_init_verify +
// share_check) and the hooks fire. RED before: the hooks got a refused guard.
//
// Also pinned: the lock is not skipped for anyone else (another thread still
// try-locks, and fails while the verify holds the lock), and the mark ends
// with the exclusive section.
//
// The startup block scan (main_ltc) fires the same hooks from
// scan_chain_for_blocks while it holds a read_tracker() SHARED guard; the
// hooks' read_tracker() took a second shared lock on that thread (undefined
// behaviour, granted by glibc's reader-preferring rwlock, so no runtime
// failure to show on master: the main_ltc call site is pinned structurally).
// Now the scan goes through NodeImpl::scan_chain_for_blocks(held, ...), and
// the hooks read under the scan's guard, in scan order, with the share link.
//
// Folded into the EXISTING allowlisted `share_test` target (the #769 trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <ctime>
#include <fstream>
#include <sstream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/log/core.hpp>

#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/dashboard_found_block.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>

namespace {

struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

// Testnet share targets (MAX_TARGET 2^256/20): a nonce search of a few dozen
// hashes mints a share. Restored on scope exit (PoolConfig is process-global).
struct TestnetScope {
    bool was;
    TestnetScope() : was(ltc::PoolConfig::is_testnet) { ltc::PoolConfig::is_testnet = true; }
    ~TestnetScope() { ltc::PoolConfig::is_testnet = was; }
};

struct HookNode : public ltc::NodeImpl
{
    HookNode() : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        // No io_context in this harness: notify_local_share's trailing
        // run_think() must take its early return (a cycle "in flight").
        m_think_running.store(true);
    }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_think_running;
};

// A genesis share minted the way create_share_fn mints one (under the
// exclusive lock, which it drops before notify_local_share). Header bits
// 0x207fffff: block target ~2^255, above the testnet share target, so any
// share that passes its PoW is a block solution.
uint256 mint_block_solving_share(HookNode& node)
{
    ltc::coin::SmallBlockHeaderType hdr;
    hdr.m_version = 0x20000000;
    hdr.m_previous_block = uint256(0xb10cULL);
    hdr.m_timestamp = static_cast<uint32_t>(std::time(nullptr));
    hdr.m_bits = 0x207fffff;

    BaseScript coinbase;
    coinbase.m_data = {0x03, 0x2a, 0x00, 0x00, 'c', '2', 'p', 'o', 'o', 'l'};

    std::vector<unsigned char> payout = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i)
        payout.push_back(static_cast<unsigned char>(0x11 + i));
    payout.push_back(0x88);
    payout.push_back(0xac);

    std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
    for (uint32_t nonce = 0; nonce < 5000; ++nonce) {
        hdr.m_nonce = nonce;
        const uint256 h = ltc::create_local_share(
            node.m_tracker, node.coin_params(), hdr, coinbase,
            /*subsidy=*/2'500'000'000ULL, /*prev_share=*/uint256(),
            /*merkle_branches=*/{}, payout);
        if (!h.IsNull())
            return h;
    }
    return uint256();
}

struct HookSeen {
    std::atomic<int> calls{0};
    std::atomic<int> refused{0};          // read_tracker() guard was falsy
    std::atomic<int> share_missing{0};    // guard ok, share not in the chain
    std::string row_share_hash;           // the dashboard row's share link
    std::string row_block_hash;
};

} // namespace

TEST(LtcLocalShareBlockHook, FoundBlockHookReadsTheShareUnderNotifyLocalShare)
{
    QuietLog quiet;
    TestnetScope testnet;
    HookNode node;

    const uint256 share = mint_block_solving_share(node);
    ASSERT_FALSE(share.IsNull()) << "no share minted in 5000 nonces";
    {
        auto g = node.read_tracker();
        ASSERT_TRUE(g);
        ASSERT_TRUE(g->chain.contains(share));
        ASSERT_FALSE(g->verified.contains(share)) << "the mint does not verify; notify does";
    }

    // The production hook's shape (main_ltc m_on_block_found): read_tracker(),
    // bail on a refused guard, else build the dashboard row off the share.
    HookSeen block, merged;
    node.m_tracker.m_on_block_found = [&](const uint256& h) {
        block.calls.fetch_add(1);
        auto guard = node.read_tracker();
        if (!guard) { block.refused.fetch_add(1); return; }
        auto& chain = guard->chain;
        if (!chain.contains(h)) { block.share_missing.fetch_add(1); return; }
        chain.get(h).share.invoke([&](auto* s) {
            const auto row = ltc::dashboard::row_from_share(h, *s, /*testnet=*/true);
            block.row_share_hash = row.share_hash;
            block.row_block_hash = row.block_hash.GetHex();
        });
    };
    // main_ltc m_on_merged_block_check opens the same way.
    node.m_tracker.m_on_merged_block_check = [&](const uint256& h, const uint256&) {
        merged.calls.fetch_add(1);
        auto guard = node.read_tracker();
        if (!guard) { merged.refused.fetch_add(1); return; }
        if (!guard->chain.contains(h)) { merged.share_missing.fetch_add(1); return; }
    };

    node.notify_local_share(share);

    {
        auto g = node.read_tracker();
        ASSERT_TRUE(g);
        ASSERT_TRUE(g->verified.contains(share)) << "notify_local_share's inline verify failed";
        auto* idx = g->chain.get_index(share);
        ASSERT_NE(idx, nullptr);
        EXPECT_TRUE(idx->is_block_solution);
    }

    ASSERT_EQ(block.calls.load(), 1) << "the share solves a block: the hook fires once";
    EXPECT_EQ(block.refused.load(), 0)
        << "read_tracker() in the found-block hook was refused: a shared try-lock of the "
           "mutex this thread holds exclusively (undefined behaviour; glibc refuses it)";
    EXPECT_EQ(block.share_missing.load(), 0);
    EXPECT_EQ(block.row_share_hash, share.GetHex()) << "the row's share link";
    EXPECT_EQ(block.row_block_hash, share.GetHex());

    ASSERT_EQ(merged.calls.load(), 1);
    EXPECT_EQ(merged.refused.load(), 0) << "the merged-block hook has the same shape";
    EXPECT_EQ(merged.share_missing.load(), 0);
}

// Inside the exclusive section the lock is skipped for the holding thread
// ONLY: another thread still try-locks (and is refused while the verify holds
// the lock), and after notify_local_share returns the holder mark is gone.
TEST(LtcLocalShareBlockHook, OnlyTheHoldingThreadSkipsTheLock)
{
    QuietLog quiet;
    TestnetScope testnet;
    HookNode node;

    const uint256 share = mint_block_solving_share(node);
    ASSERT_FALSE(share.IsNull());

    std::atomic<int> other_ok{-1};
    std::atomic<int> own_ok{-1};
    node.m_tracker.m_on_block_found = [&](const uint256&) {
        own_ok = node.read_tracker() ? 1 : 0;
        std::thread other([&] { other_ok = node.read_tracker() ? 1 : 0; });
        other.join();
    };

    node.notify_local_share(share);
    EXPECT_EQ(own_ok.load(), 1) << "the holding thread reads under its own lock";
    EXPECT_EQ(other_ok.load(), 0)
        << "another thread must still try-lock, and be refused while the verify holds it";

    // The mark ended with the exclusive section: this thread now locks for
    // real, and is refused while another thread holds the lock.
    {
        auto g = node.read_tracker();
        EXPECT_TRUE(g);
    }
    std::atomic<bool> holding{false}, release{false};
    std::thread writer([&] {
        std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
        holding = true;
        while (!release.load())
            std::this_thread::yield();
    });
    while (!holding.load())
        std::this_thread::yield();
    {
        auto g = node.read_tracker();
        EXPECT_FALSE(g) << "after notify_local_share, this thread must lock like any reader";
    }
    release = true;
    writer.join();
}

// ── the startup block scan ──────────────────────────────────────────────────

namespace {

uint256 S(uint64_t n) { return uint256(0x200000 + n); }

constexpr uint32_t kScanBlockBits = 0x1b0fffff;

// A verified trunk S(1)..S(n) with cached PoW hashes, as a reload leaves it:
// the shares in `blocks` meet the block target, the rest do not.
uint256 build_scanned_trunk(HookNode& node, int n, const std::vector<int>& blocks)
{
    const uint256 block_target = chain::bits_to_target(kScanBlockBits);
    uint256 prev;
    for (int i = 1; i <= n; ++i) {
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = S(i);
        sh->m_prev_hash = prev;
        sh->m_desired_version = 36;
        sh->m_bits = 0x1e0fffff;
        sh->m_max_bits = 0x1e0fffff;
        sh->m_min_header.m_bits = kScanBlockBits;
        sh->m_min_header.m_timestamp = 1'700'000'000u + static_cast<uint32_t>(i);
        ltc::ShareType st;
        st = sh;
        node.m_tracker.add(st);
        node.m_tracker.verified.add(node.m_tracker.chain.get_share(S(i)));
        bool is_block = false;
        for (int b : blocks)
            is_block = is_block || b == i;
        node.m_tracker.chain.get_index(S(i))->pow_hash = is_block ? block_target : ~uint256();
        prev = S(i);
    }
    return prev;
}

} // namespace

TEST(LtcLocalShareBlockHook, StartupScanHooksReadUnderTheScansGuard)
{
    QuietLog quiet;
    HookNode node;
    const uint256 tip = build_scanned_trunk(node, 10, {9, 4});

    struct Hit { uint256 hash; bool marked; bool guard_ok; std::string row_share; };
    std::vector<Hit> block_hits;
    std::vector<uint256> merged_hits;
    int merged_refused = 0;
    node.m_tracker.m_on_block_found = [&](const uint256& h) {
        Hit hit{h, node.holds_tracker_lock(), false, {}};
        auto guard = node.read_tracker();
        hit.guard_ok = static_cast<bool>(guard);
        if (guard && guard->chain.contains(h))
            guard->chain.get(h).share.invoke([&](auto* s) {
                hit.row_share = ltc::dashboard::row_from_share(h, *s, /*testnet=*/false).share_hash;
            });
        block_hits.push_back(hit);
    };
    node.m_tracker.m_on_merged_block_check = [&](const uint256& h, const uint256&) {
        auto guard = node.read_tracker();
        if (!guard) { ++merged_refused; return; }
        merged_hits.push_back(h);
    };

    {
        auto guard = node.read_tracker();   // main_ltc's scan guard (shared)
        ASSERT_TRUE(guard);
        EXPECT_FALSE(node.holds_tracker_lock()) << "a plain reader is not marked";
        node.scan_chain_for_blocks(guard, tip, 10);
    }

    ASSERT_EQ(block_hits.size(), 2u);
    EXPECT_EQ(block_hits[0].hash, S(9)) << "scan order: tip first";
    EXPECT_EQ(block_hits[1].hash, S(4));
    for (const auto& hit : block_hits) {
        EXPECT_TRUE(hit.marked) << "the hook reads under the scan's guard, no second lock";
        EXPECT_TRUE(hit.guard_ok);
        EXPECT_EQ(hit.row_share, hit.hash.GetHex()) << "the row's share link";
    }
    EXPECT_EQ(merged_refused, 0);
    EXPECT_EQ(merged_hits.size(), 10u) << "every share with a cached PoW hash";
    EXPECT_FALSE(node.holds_tracker_lock()) << "the mark ends with the scan";

    // A failed guard scans nothing (no unlocked reads, no hooks).
    std::atomic<bool> holding{false}, release{false};
    std::thread writer([&] {
        std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
        holding = true;
        while (!release.load())
            std::this_thread::yield();
    });
    while (!holding.load())
        std::this_thread::yield();
    {
        auto guard = node.read_tracker();
        EXPECT_FALSE(guard);
        node.scan_chain_for_blocks(guard, tip, 10);
    }
    release = true;
    writer.join();
    EXPECT_EQ(block_hits.size(), 2u);
    EXPECT_EQ(merged_hits.size(), 10u);
}

// main_ltc's startup scan goes through the node, holding its guard, never
// straight into the tracker under it (RED before: guard->scan_chain_for_blocks).
TEST(LtcLocalShareBlockHook, MainLtcStartupScanGoesThroughTheNode)
{
    std::ifstream in(std::string(C2POOL_IMPL_DIR) + "/../c2pool/main_ltc.cpp");
    ASSERT_TRUE(in.good());
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string src = ss.str();
    EXPECT_EQ(src.find("guard->scan_chain_for_blocks("), std::string::npos)
        << "the startup scan calls the tracker under its own read guard: the hooks "
           "then take a second shared lock on this thread";
    EXPECT_NE(src.find("p2p_node->scan_chain_for_blocks(guard,"), std::string::npos);
}
