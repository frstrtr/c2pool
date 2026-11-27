// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The stratum best share and the held coinbase (rides dgb_work_source_test).
//
// main_dgb never bound DGBWorkSource::set_best_share_hash_fn, so every job
// froze a NULL prev share and no local share could be credited. Pinned here:
//   - BestShareCell is refreshed only under the node's tracker guard (a busy
//     tracker leaves it unchanged);
//   - wire_best_share binds the jobs' best-share source to the cell and the
//     node's ONE best-change hook: extra action (the DOGE dirty mark), cell
//     refresh, work-generation bump; a busy tracker is retried on the io
//     context, a bounded number of times;
//   - a coinbase the producer cannot build is HELD, never empty (an empty one
//     made the stratum server serve its stub coinbase).
// ---------------------------------------------------------------------------

#include <impl/dgb/best_share_cell.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/stratum/work_source.hpp>

#include <core/pow.hpp>
#include <core/uint256.hpp>

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

struct FakeTracker {};

// dgb::NodeImpl's surface: read_tracker() (try-shared guard),
// best_share_hash(), set_on_best_share_changed().
struct BestNode {
    FakeTracker tracker;
    std::shared_mutex mtx;
    uint256 best;
    int best_reads_unlocked = 0;   // best_share_hash() called without the guard held
    bool guard_held = false;
    std::function<void()> on_best;

    struct Guard {
        std::shared_lock<std::shared_mutex> lk;
        BestNode* n;
        Guard(std::shared_lock<std::shared_mutex> l, BestNode* node) : lk(std::move(l)), n(node)
        {
            if (lk.owns_lock())
                n->guard_held = true;
        }
        Guard(Guard&& o) noexcept : lk(std::move(o.lk)), n(o.n) { o.n = nullptr; }
        ~Guard()
        {
            if (n && lk.owns_lock())
                n->guard_held = false;
        }
        explicit operator bool() const { return lk.owns_lock(); }
        FakeTracker& operator*() { return n->tracker; }
    };
    Guard read_tracker() { return Guard(std::shared_lock<std::shared_mutex>(mtx, std::try_to_lock), this); }
    uint256 best_share_hash()
    {
        if (!guard_held)
            ++best_reads_unlocked;
        return best;
    }
    void set_on_best_share_changed(std::function<void()> fn) { on_best = std::move(fn); }
};

// Holds the node's tracker exclusively on another thread (the compute thread).
struct BusyTracker {
    std::promise<void> locked, release;
    std::thread t;
    explicit BusyTracker(std::shared_mutex& m)
    {
        auto rel = release.get_future().share();
        t = std::thread([&m, this, rel] {
            std::unique_lock<std::shared_mutex> lk(m);
            locked.set_value();
            rel.wait();
        });
        locked.get_future().wait();
    }
    void done()
    {
        release.set_value();
        t.join();
    }
};

const core::SubsidyFunc kSub = [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); };

struct Ws {
    c2pool::dgb::HeaderChain chain;
    dgb::coin::Mempool mempool;
    std::unique_ptr<dgb::stratum::DGBWorkSource> make()
    {
        auto fn = [](const std::vector<unsigned char>&, uint32_t) -> bool { return false; };
        return std::make_unique<dgb::stratum::DGBWorkSource>(chain, mempool, false, fn, kSub);
    }
};

const uint256 kBestA(std::vector<unsigned char>(32, 0xa0));
const uint256 kBestB(std::vector<unsigned char>(32, 0xb0));

} // namespace

TEST(DgbStratumBestShare, CellIsRefreshedOnlyUnderTheTrackerGuard)
{
    BestNode node;
    node.best = kBestA;
    dgb::BestShareCell cell;
    ASSERT_TRUE(dgb::refresh_best_share_cell(node, cell));
    EXPECT_EQ(cell.get(), kBestA);
    EXPECT_EQ(node.best_reads_unlocked, 0) << "best_share_hash read without the tracker guard";

    node.best = kBestB;
    BusyTracker busy(node.mtx);
    EXPECT_FALSE(dgb::refresh_best_share_cell(node, cell)) << "a busy tracker is not waited for";
    EXPECT_EQ(cell.get(), kBestA) << "busy: the cell keeps the last best";
    busy.done();
    ASSERT_TRUE(dgb::refresh_best_share_cell(node, cell));
    EXPECT_EQ(cell.get(), kBestB);
}

TEST(DgbStratumBestShare, WireBindsJobsToTheCellAndTheOneHook)
{
    BestNode node;
    node.best = kBestA;
    Ws w;
    auto ws = w.make();
    boost::asio::io_context ioc;
    auto cell = std::make_shared<dgb::BestShareCell>();
    int extra = 0;
    dgb::wire_best_share(node, cell, ws.get(), ioc, [&extra]() { ++extra; });

    // Jobs read the cell (refreshed once at wiring).
    auto fn = ws->get_best_share_hash_fn();
    ASSERT_TRUE(static_cast<bool>(fn)) << "stratum jobs have a best-share source";
    EXPECT_EQ(fn(), kBestA);
    ASSERT_TRUE(static_cast<bool>(node.on_best)) << "best-change hook bound";

    // A best change: extra action, cell refresh, new jobs.
    node.best = kBestB;
    const auto gen = ws->get_work_generation();
    node.on_best();
    EXPECT_EQ(extra, 1);
    EXPECT_EQ(fn(), kBestB);
    EXPECT_EQ(ws->get_work_generation(), gen + 1);
    EXPECT_EQ(node.best_reads_unlocked, 0);
}

TEST(DgbStratumBestShare, BusyTrackerAtTheHookIsRetriedOnTheIoContext)
{
    BestNode node;
    node.best = kBestA;
    Ws w;
    auto ws = w.make();
    boost::asio::io_context ioc;
    auto cell = std::make_shared<dgb::BestShareCell>();
    dgb::wire_best_share(node, cell, ws.get(), ioc);
    auto fn = ws->get_best_share_hash_fn();

    node.best = kBestB;
    const auto gen = ws->get_work_generation();
    {
        BusyTracker busy(node.mtx);
        node.on_best();
        EXPECT_EQ(fn(), kBestA) << "busy: not refreshed yet";
        EXPECT_EQ(ws->get_work_generation(), gen) << "no new jobs on the old best";
        busy.done();
    }
    // The retry runs on the io context once the tracker is free.
    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_EQ(fn(), kBestB);
    EXPECT_EQ(ws->get_work_generation(), gen + 1);
}

TEST(DgbStratumBestShare, BusyRetriesAreBounded)
{
    BestNode node;
    node.best = kBestA;
    Ws w;
    auto ws = w.make();
    boost::asio::io_context ioc;
    auto cell = std::make_shared<dgb::BestShareCell>();
    dgb::wire_best_share(node, cell, ws.get(), ioc);
    node.best = kBestB;
    BusyTracker busy(node.mtx);
    node.on_best();
    // All tries spent while busy: the io context runs out of work by itself.
    const auto t0 = std::chrono::steady_clock::now();
    ioc.run_for(dgb::kBestShareRefreshGap * (dgb::kBestShareRefreshTries + 20));
    const auto spent = std::chrono::steady_clock::now() - t0;
    EXPECT_TRUE(ioc.stopped()) << "retries did not stop";
    EXPECT_LT(spent, dgb::kBestShareRefreshGap * (dgb::kBestShareRefreshTries + 20));
    EXPECT_EQ(ws->get_best_share_hash_fn()(), kBestA);
    busy.done();
}

TEST(DgbStratumBestShare, UnbuildableCoinbaseIsHeldNotEmpty)
{
    Ws w;
    auto ws = w.make();
    // Producer unbound.
    auto r = ws->build_connection_coinbase(kBestA, "00", Bytes{0x76, 0xa9, 0x14, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x88, 0xac}, {});
    EXPECT_TRUE(r.held);
    EXPECT_TRUE(r.coinb1.empty());
    // Producer declines (null / unknown prev, tracker busy).
    ws->set_pplns_inputs_fn([](const uint256&, const std::string&, const Bytes&,
                               const std::vector<std::pair<uint32_t, Bytes>>&, const Bytes&, const dgb::stratum::DGBWorkSource::JobBlock&)
                                -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> { return std::nullopt; });
    r = ws->build_connection_coinbase(uint256(), "00", Bytes{0x76, 0xa9, 0x14, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x88, 0xac}, {});
    EXPECT_TRUE(r.held);
    EXPECT_TRUE(r.coinb1.empty());
}

// Review dd1248abd #6: a throw while the job coinbase is built (a V35 key the
// PPLNS split cannot turn into a script) is no job, never an exception out of
// the core session's io handler.
TEST(DgbStratumBestShare, AThrowingCoinbaseBuildIsHeld)
{
    Ws w;
    auto ws = w.make();
    int calls = 0;
    ws->set_pplns_inputs_fn([&calls](const uint256&, const std::string&, const Bytes&,
                                     const std::vector<std::pair<uint32_t, Bytes>>&, const Bytes&,
                                     const dgb::stratum::DGBWorkSource::JobBlock&)
                                -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
        ++calls;
        throw std::runtime_error("V35 PPLNS key has no script");
    });
    const Bytes p2pkh{0x76, 0xa9, 0x14, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x88, 0xac};
    core::stratum::CoinbaseResult r;
    EXPECT_NO_THROW(r = ws->build_connection_coinbase(kBestA, "00", p2pkh, {}));
    EXPECT_EQ(calls, 1) << "the producer was not reached";
    EXPECT_TRUE(r.held);
    EXPECT_TRUE(r.coinb1.empty());

    // The PPLNS->coinbase build is inside the same guard.
#ifdef DGB_MAIN_SRC
    const auto src = std::filesystem::path(DGB_MAIN_SRC).parent_path().parent_path() / "impl" / "dgb" / "stratum"
                     / "work_source.cpp";
    std::ifstream f(src);
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string body = ss.str();
    const auto t = body.find("        inputs = fn(prev_share_hash, extranonce1_hex, eff_payout_script,");
    ASSERT_NE(t, std::string::npos);
    const auto b = body.find("parts = dgb::coin::build_connection_coinbase_from_pplns(*inputs);", t);
    const auto c = body.find("} catch (const std::exception& e) {", t);
    ASSERT_NE(b, std::string::npos);
    ASSERT_NE(c, std::string::npos);
    EXPECT_LT(b, c);
    EXPECT_LT(body.rfind("    try {", t), t);
#endif
}
