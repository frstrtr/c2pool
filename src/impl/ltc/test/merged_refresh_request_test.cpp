// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// MergedMiningManager::request_refresh (rides share_test): the DOGE tip
// handler asks for the merged work at once instead of waiting for the poll's
// next 1 s tick, so the DOGE template moves to the new tip half a second
// sooner on average (stale-prev time, VERIFY-F1-2.3-F2 §1.5).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/uint256.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

struct CountingBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::atomic<int> fetches{0};
    CountingBackend()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = false;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override
    {
        ++fetches;
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = 5'000'001;
        w.block_hash.SetHex(std::string(63, '0') + "a");
        return w;
    }
    c2pool::merged::AuxWork get_work_template() override { return create_aux_block(""); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return std::string(63, '0') + "a"; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

} // namespace

TEST(MergedMining, RefreshRequestFetchesWithoutWaitingForThePoll)
{
    boost::asio::io_context ioc;   // never run: no poll ticks
    c2pool::merged::MergedMiningManager mm(ioc);
    auto backend = std::make_unique<CountingBackend>();
    auto* b = backend.get();
    mm.add_chain(b->cfg, std::move(backend));
    mm.request_refresh();
    for (int i = 0; i < 300 && b->fetches.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_GE(b->fetches.load(), 1) << "fetched on request, without a poll";
    EXPECT_EQ(mm.get_current_work().at(98).height, 5'000'001);
}
