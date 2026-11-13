// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// /current_merged_payouts: each merged (DOGE) output is shown under the parent
// (LTC) address it is paid for, labelled from the payout provider's origins
// (get_payout_detail: the same PPLNS weights the amounts are split by):
//   explicit      the shares gave the DOGE address (login LTC,DOGE): under
//                 its LTC address, not as a row of its own;
//   auto-convert  derived from the LTC key (same hash160); a P2SH LTC parent
//                 is flagged parent_p2sh (unsafe if segwit-wrapped);
//   donation      under the LTC donation row;
// one DOGE address given by two LTC addresses: under each, with its part by
// weight (output_amount, fraction). A provider without origins keeps the old
// view (hash160 match, "auto-convert").
// Folded into the allowlisted core_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/address_utils.hpp>
#include <core/address_validator.hpp>
#include <core/web_server.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <impl/ltc/config_pool.hpp>

namespace {

using c2pool::merged::MergedMiningManager;
using c2pool::merged::MergedPayoutDetail;
using c2pool::merged::PayoutOrigin;
using Script = std::vector<unsigned char>;

Script p2pkh(unsigned char fill)
{
    Script s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}
Script p2sh(unsigned char fill)
{
    Script s{0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x87);
    return s;
}
Script p2wpkh(unsigned char fill)
{
    Script s{0x00, 0x14};
    s.insert(s.end(), 20, fill);
    return s;
}
std::string ltc_addr(const Script& s) { return core::script_to_address(s, /*is_litecoin=*/true, /*testnet=*/false); }
std::string doge_addr(const Script& s) { return core::script_to_address(s, "", 0x1e, 0x16); }

struct DogeBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(62, '0') + "c1";
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
        w.height = 5'000'001;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip);
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", 5'000'001}, {"bits", "1a01d2c3"},
            {"curtime", 1793210000}, {"version", 0x620004}, {"coinbasevalue", 1000000000000LL},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

// The parent (LTC) payout scripts and the merged (DOGE) outputs.
const Script kA = p2pkh(0x11);   // LTC P2PKH, no DOGE address
const Script kB = p2sh(0x22);    // LTC P2SH (M...), no DOGE address
const Script kC = p2pkh(0x33);   // LTC P2PKH, explicit DOGE kX
const Script kX = p2pkh(0x44);
const Script kD = p2pkh(0x66);   // LTC P2PKH and ...
const Script kE = p2wpkh(0x77);  // ... LTC P2WPKH, both explicit DOGE kY
const Script kY = p2pkh(0x55);
const Script kF = p2pkh(0x88);   // explicit DOGE kZ, no LTC payout in the window
const Script kZ = p2pkh(0x99);
const Script kDon(ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(), ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end());

struct Rig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    core::MiningInterface mi{/*testnet=*/false, /*node=*/nullptr, c2pool::address::Blockchain::LITECOIN};

    Rig()
    {
        auto backend = std::make_unique<DogeBackend>();
        auto cfg = backend->cfg;
        mm.add_chain(cfg, std::move(backend));
        mm.set_payout_provider([](uint32_t, uint64_t) { return payouts(); });
        mm.refresh_aux_work();
        nlohmann::json feed = {
            {ltc_addr(kA), 1.0}, {ltc_addr(kB), 0.5}, {ltc_addr(kC), 0.3},
            {ltc_addr(kD), 0.2}, {ltc_addr(kE), 0.4}, {ltc_addr(kDon), 0.001},
        };
        mi.set_current_payouts_fn([feed]() { return feed; });
        mi.set_merged_mining_manager(&mm);
    }

    static std::vector<std::pair<Script, uint64_t>> payouts()
    {
        return {{kA, 100'00000000ULL}, {kB, 50'00000000ULL}, {kX, 30'00000000ULL},
                {kY, 90'00000000ULL},  {kZ, 20'00000000ULL}, {kDon, 1'00000000ULL}};
    }
    static std::vector<PayoutOrigin> origins()
    {
        return {
            {kA, kA, false, 1.0}, {kB, kB, false, 1.0}, {kX, kC, true, 1.0},
            {kY, kD, true, 1.0 / 3}, {kY, kE, true, 2.0 / 3}, {kZ, kF, true, 1.0},
        };
    }
};

const nlohmann::json* only_merged(const nlohmann::json& r, const std::string& row)
{
    if (!r.contains(row)) {
        ADD_FAILURE() << "no row " << row;
        return nullptr;
    }
    const auto& m = r.at(row).at("merged");
    if (m.size() != 1) {
        ADD_FAILURE() << row << ": " << m.dump();
        return nullptr;
    }
    return &m[0];
}

} // namespace

TEST(MergedPayoutSource, LabelsAndAttachesFromTheOrigins)
{
    Rig r;
    r.mm.set_payout_detail_provider([](uint32_t, uint64_t) {
        return MergedPayoutDetail{Rig::payouts(), Rig::origins()};
    });
    const auto res = r.mi.compute_current_merged_payouts();
    ASSERT_TRUE(res.is_object());

    // auto-convert, P2PKH parent
    if (auto* m = only_merged(res, ltc_addr(kA))) {
        EXPECT_EQ(m->at("source"), "auto-convert");
        EXPECT_EQ(m->at("address"), doge_addr(kA));
        EXPECT_DOUBLE_EQ(m->at("amount").get<double>(), 100.0);
        EXPECT_EQ(m->at("parent"), ltc_addr(kA));
        EXPECT_FALSE(m->contains("parent_p2sh"));
        EXPECT_FALSE(m->contains("fraction"));
    }
    // auto-convert, P2SH parent: flagged
    if (auto* m = only_merged(res, ltc_addr(kB))) {
        EXPECT_EQ(m->at("source"), "auto-convert");
        EXPECT_EQ(m->value("parent_p2sh", false), true);
    }
    // explicit: under its LTC address, no row of its own
    if (auto* m = only_merged(res, ltc_addr(kC))) {
        EXPECT_EQ(m->at("source"), "explicit");
        EXPECT_EQ(m->at("address"), doge_addr(kX));
        EXPECT_DOUBLE_EQ(m->at("amount").get<double>(), 30.0);
        EXPECT_FALSE(m->contains("parent_p2sh"));
    }
    EXPECT_FALSE(res.contains(doge_addr(kX)));
    // one explicit DOGE address given by two LTC addresses: its part under each
    double y_total = 0;
    const std::vector<std::pair<std::string, double>> parts = {{ltc_addr(kD), 1.0 / 3}, {ltc_addr(kE), 2.0 / 3}};
    for (const auto& [row, part] : parts) {
        if (auto* m = only_merged(res, row)) {
            EXPECT_EQ(m->at("source"), "explicit");
            EXPECT_EQ(m->at("address"), doge_addr(kY));
            EXPECT_NEAR(m->at("amount").get<double>(), 90.0 * part, 1e-9);
            EXPECT_DOUBLE_EQ(m->at("output_amount").get<double>(), 90.0);
            EXPECT_NEAR(m->at("fraction").get<double>(), part, 1e-12);
            y_total += m->at("amount").get<double>();
        }
    }
    EXPECT_NEAR(y_total, 90.0, 1e-9);
    EXPECT_FALSE(res.contains(doge_addr(kY)));
    // an explicit DOGE payee with no LTC payout in the window: its LTC row at 0
    if (auto* m = only_merged(res, ltc_addr(kF))) {
        EXPECT_EQ(m->at("source"), "explicit");
        EXPECT_DOUBLE_EQ(res.at(ltc_addr(kF)).at("amount").get<double>(), 0.0);
    }
    // donation: under the LTC donation row
    if (auto* m = only_merged(res, ltc_addr(kDon))) {
        EXPECT_EQ(m->at("source"), "donation");
        EXPECT_DOUBLE_EQ(m->at("amount").get<double>(), 1.0);
    }
    // backward compatible: amounts unchanged, every merged entry has the old fields
    EXPECT_DOUBLE_EQ(res.at(ltc_addr(kA)).at("amount").get<double>(), 1.0);
    for (const auto& [row, e] : res.items())
        for (const auto& m : e.at("merged"))
            for (const char* f : {"symbol", "address", "amount", "source"})
                EXPECT_TRUE(m.contains(f)) << row << " " << f;
}

// Without origins (a provider that does not know them): the old view.
TEST(MergedPayoutSource, WithoutOriginsKeepsTheHash160View)
{
    Rig r;
    const auto res = r.mi.compute_current_merged_payouts();
    if (auto* m = only_merged(res, ltc_addr(kA))) {
        EXPECT_EQ(m->at("source"), "auto-convert");
        EXPECT_FALSE(m->contains("parent"));
    }
    if (auto* m = only_merged(res, doge_addr(kX))) {   // its own row, LTC amount 0
        EXPECT_EQ(m->at("source"), "auto-convert");
        EXPECT_DOUBLE_EQ(res.at(doge_addr(kX)).at("amount").get<double>(), 0.0);
    }
    if (auto* m = only_merged(res, ltc_addr(kDon)))
        EXPECT_EQ(m->at("source"), "donation");
}
