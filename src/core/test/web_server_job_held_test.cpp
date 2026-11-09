// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A stratum job is never built on a busy sharechain (rides core_test).
//
// build_connection_coinbase reads the sharechain twice per job: the PPLNS
// outputs at the job's prev share (pplns_fn) and the ref_hash (ref_hash_fn),
// each under a try-lock of the tracker. When the tracker was busy it used to
// carry on regardless: with the cached PPLNS of ANOTHER best share, or with a
// null ref_hash. Either coinbase gives shares that can never match their own
// generation transaction ("Cross-check FAILED" on our own share; peers
// reject it). With StratumConfig::hold_job_without_connection_coinbase (the
// LTC pool) the function returns no coinbase instead and the session holds
// the job and retries; without it (other coins) nothing changes. Pinned on
// the real MiningInterface over a mock coin node.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

namespace {

using core::MiningInterface;

struct LtcNode : public core::coin::ICoinNode {
    nlohmann::json work_data = {
        {"previousblockhash", std::string(62, '0') + "ab"}, {"version", 0x20000000},
        {"height", 100}, {"bits", "207fffff"}, {"curtime", 1600000000},
        {"coinbasevalue", 5000000000LL}, {"transactions", nlohmann::json::array()},
        {"rules", nlohmann::json::array({"csv", "!segwit", "taproot"})},
    };
    core::coin::WorkView get_work_view() override
    {
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return true; }
};

struct Rig {
    LtcNode ltc;
    MiningInterface mi{/*testnet=*/true};
    bool ref_busy{false};
    bool pplns_busy{false};
    explicit Rig(bool hold)
    {
        core::stratum::StratumConfig cfg;
        cfg.hold_job_without_connection_coinbase = hold;
        mi.set_stratum_config(cfg);
        mi.set_coin_node(&ltc);
        mi.set_pplns_fn([this](const uint256&, const uint256&, uint64_t subsidy, const std::vector<unsigned char>& don)
                            -> std::map<std::vector<unsigned char>, double> {
            if (pplns_busy)
                return {};   // the tracker try-lock failed
            return {{don, static_cast<double>(subsidy)}};
        });
        mi.set_ref_hash_fn([this](const uint256&, const std::vector<unsigned char>&,
                                  const std::vector<unsigned char>&, uint64_t, uint32_t, uint32_t,
                                  bool, const std::string&, const uint256&,
                                  const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                                  const std::vector<uint256>&) {
            MiningInterface::RefHashResult r;
            if (ref_busy)
                return r;   // the tracker try-lock failed: {}
            r.ref_hash.SetHex(std::string(64, '5'));
            r.bits = 0x207fffff;
            return r;
        });
        mi.refresh_work();
    }
    std::string job(const uint256& prev)
    {
        const std::vector<unsigned char> payout{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
        auto cbr = mi.build_connection_coinbase(prev, "aabbccdd", payout, {});
        return cbr.coinb1 + cbr.coinb2;
    }
};

uint256 h(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

} // namespace

TEST(StratumJobHeld, BusyRefHashHoldsTheJob)
{
    Rig r(/*hold=*/true);
    ASSERT_FALSE(r.job(h("01")).empty()) << "a normal job";
    r.ref_busy = true;
    EXPECT_TRUE(r.job(h("01")).empty()) << "no coinbase on a null ref_hash";
    EXPECT_EQ(r.mi.connection_coinbase_held(), 1u);
    r.ref_busy = false;
    EXPECT_FALSE(r.job(h("01")).empty());
}

TEST(StratumJobHeld, BusyPplnsAtTheJobsPrevShareHoldsTheJob)
{
    Rig r(/*hold=*/true);
    ASSERT_FALSE(r.job(h("02")).empty());
    r.pplns_busy = true;
    // another prev share than the cached PPLNS was computed at: it must be
    // recomputed, and it cannot be
    EXPECT_TRUE(r.job(h("03")).empty()) << "never the cached outputs of another best share";
    EXPECT_EQ(r.mi.connection_coinbase_held(), 1u);
    r.pplns_busy = false;
    EXPECT_FALSE(r.job(h("03")).empty());
}

TEST(StratumJobHeld, OtherWorkSourcesKeepTheirBehaviour)
{
    Rig r(/*hold=*/false);
    r.ref_busy = true;
    r.pplns_busy = true;
    EXPECT_FALSE(r.job(h("04")).empty()) << "unchanged without the flag";
    EXPECT_EQ(r.mi.connection_coinbase_held(), 0u);
}
