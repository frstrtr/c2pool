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
// Folded into the EXISTING allowlisted `share_test` target (the #769 trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <ctime>
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
