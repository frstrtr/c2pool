// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A merged (DOGE) find is recorded as the block the share committed to
// (rides share_test).
//
// try_submit_merged_blocks builds the DOGE block from the frozen snapshot
// that matches the hash committed in the share's LTC coinbase: on a stale job
// (the work was rebuilt since: a new DOGE tip, a new PPLNS split) that is an
// older snapshot than the current work. The record (/recent_blocks, the found
// block verdict) took the CURRENT work's hash and height, a block that never
// exists on the chain: once the DOGE chain was 6 deep, the verdict called our
// won block orphaned.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>
#include <c2pool/merged/merged_mining.hpp>

namespace {

struct DogeBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(62, '0') + "c1";
    int height = 5'000'001;
    int submits = 0;
    DogeBackend()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = height;
        w.coinbase_value = 1000000000000ULL + static_cast<uint64_t>(height);
        w.block_hash.SetHex(tip);
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", height}, {"bits", "1a01d2c3"},
            {"curtime", 1793210000 + height}, {"version", 0x620004},
            {"coinbasevalue", 1000000000000LL + height},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { ++submits; return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

std::string hex_of(const std::vector<uint8_t>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

} // namespace

TEST(MergedMining, StaleJobFindRecordsTheCommittedBlock)
{
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm(ioc);
    auto backend = std::make_unique<DogeBackend>();
    auto* b = backend.get();
    mm.add_chain(b->cfg, std::move(backend));
    mm.set_payout_provider([](uint32_t, uint64_t value) {
        std::vector<unsigned char> s{0x76, 0xa9, 0x14};
        s.insert(s.end(), 20, 0x5b);
        s.push_back(0x88);
        s.push_back(0xac);
        return std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{{s, value}};
    });
    struct Found { std::string symbol; int height; std::string hash; };
    std::vector<Found> found;
    mm.set_on_merged_block_found([&found](const std::string& sym, int h, const std::string& hash,
                                          bool, uint64_t) { found.push_back({sym, h, hash}); });

    // Job A: the DOGE block at 5,000,001; the share's LTC coinbase commits to it.
    mm.refresh_aux_work();
    const uint256 a_hash = mm.get_current_work().at(98).block_hash;
    const std::string parent_cb = std::string(20, 'a') + hex_of(mm.get_auxpow_commitment())
                                  + std::string(20, 'b');

    // The DOGE tip moves on before the share comes in: the current work is B.
    b->tip = std::string(62, '0') + "c2";
    b->height = 5'000'002;
    mm.refresh_aux_work();
    const uint256 b_hash = mm.get_current_work().at(98).block_hash;
    ASSERT_NE(a_hash, b_hash);

    // The stale-job share meets the DOGE target.
    uint256 parent_hash;
    parent_hash.SetHex("01");
    mm.try_submit_merged_blocks(std::string(160, 'd'), parent_cb, {}, 0, parent_hash);

    ASSERT_EQ(b->submits, 1) << "the block was built from A's snapshot and submitted";
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].hash, a_hash.GetHex()) << "the block the share committed to, not the current work";
    EXPECT_EQ(found[0].height, 5'000'001);
    const auto rec = mm.get_discovered_blocks();
    ASSERT_EQ(rec.size(), 1u);
    EXPECT_EQ(rec[0].block_hash, a_hash.GetHex());
    EXPECT_EQ(rec[0].height, 5'000'001);
}
