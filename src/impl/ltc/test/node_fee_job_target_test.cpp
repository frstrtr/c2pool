// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// --fee pays the node operator the fee: a node-fee job's share target is its
// miner's (p2pool get_work sizes desired_share_target by the local rate of
// the miner the work is for), so the operator's PPLNS weight is the fee.
//
// decide_job_payout gives a job to the operator by replacing its payout. The
// job's share target used to be sized by the local hash rate of that payout's
// key: the operator's, which has none here (pseudoshares are recorded under
// the connection's login key). A fee job then got the easiest target the
// band allows (pre_target3) while its miner's jobs sat at the hard edge
// (pre_target3/30): its shares weighed 1/30 of the work behind them, and it
// ended at its first, quick share. Field (c2pool 0.2.12.x, --fee 1, one miner
// address on ~15 connections, the node most of its sharechain): owner shares
// 2.35% of the window by count, 0.08% by weight, against ~1% due.
//
// Pinned on the real pieces of a job: MiningInterface::decide_job_payout (the
// fee draw), core::stratum::job_rate_key (whose rate sizes the job),
// ltc::stratum::job_desired_share_target (Cap 1, as ref_hash_fn applies it)
// and ltc::ShareTracker::compute_share_target (the band clip), through
// MiningInterface::build_connection_coinbase_for where a coinbase is built.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/random.hpp>
#include <core/stratum_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <impl/ltc/work_target.hpp>

namespace {

using core::MiningInterface;
using core::stratum::PayoutKey;
using Merged = std::vector<std::pair<uint32_t, std::vector<unsigned char>>>;

constexpr uint32_t kSeed = 0xfee51234u;

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

PayoutKey key_of(unsigned char b)
{
    PayoutKey k;
    k.fill(b);
    return k;
}

double attempts(uint32_t bits)
{
    return static_cast<double>(chain::target_to_average_attempts(chain::bits_to_target(bits)).GetLow64());
}

// The node's local rates by key (StratumServer::get_local_addr_rates) and a
// sharechain; a job's share bits as ref_hash_fn computes them: the rate of
// its rate key -> Cap 1 -> the band clip. No prev share in the tracker: the
// band is [MAX_TARGET/30, MAX_TARGET].
struct Node {
    ltc::ShareTracker tracker;
    std::map<PayoutKey, double> rates;
    uint32_t share_bits(const PayoutKey& rate_key)
    {
        ltc::stratum::JobTargetInputs in;
        const auto it = rates.find(rate_key);
        in.local_hash_rate = it == rates.end() ? 0.0 : it->second;
        in.share_period = ltc::PoolConfig::share_period();
        const auto desired = ltc::stratum::job_desired_share_target(in);
        return tracker.compute_share_target(uint256(), 1600000000u, desired).bits;
    }
    uint32_t easiest() { return tracker.compute_share_target(uint256(), 1600000000u, max256()).bits; }
    static uint256 max256()
    {
        uint256 t;
        t.SetHex(std::string(64, 'f'));
        return t;
    }
};

struct LtcCoin : public core::coin::ICoinNode {
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

// The stratum path of a job: decide_job_payout, then build_connection_coinbase_for
// the connection's login key, through a ref_hash_fn that sizes the share as
// main_ltc's does.
struct Rig {
    LtcCoin coin;
    Node node;
    MiningInterface mi{/*testnet=*/false};
    Rig()
    {
        mi.set_coin_node(&coin);
        mi.set_pplns_fn([](const uint256&, const uint256&, uint64_t subsidy, const std::vector<unsigned char>& don)
                            -> std::map<std::vector<unsigned char>, double> {
            return {{don, static_cast<double>(subsidy)}};
        });
        mi.set_ref_hash_fn([this](const uint256&, const std::vector<unsigned char>&,
                                  const std::vector<unsigned char>&, const PayoutKey& rate_key,
                                  uint64_t, uint32_t, uint32_t, bool, const std::string&, const uint256&,
                                  const Merged&, const std::vector<uint256>&) {
            MiningInterface::RefHashResult r;
            r.ref_hash.SetHex(std::string(64, '5'));
            r.bits = node.share_bits(rate_key);
            return r;
        });
        mi.refresh_work();
    }
    // (the job's payout, its frozen share bits)
    std::pair<std::vector<unsigned char>, uint32_t> job(const PayoutKey& login, const std::vector<unsigned char>& script)
    {
        auto payout = script;
        Merged merged;
        mi.decide_job_payout(payout, merged);
        uint256 prev;
        prev.SetHex("01");
        const auto cbr = mi.build_connection_coinbase_for(login, prev, "aabbccdd", payout, merged);
        EXPECT_FALSE(cbr.coinb1.empty());
        return {payout, cbr.snapshot.frozen_ref.bits};
    }
};

} // namespace

// A miner at the hard edge of the band (its rate wants a far harder share):
// its fee job has its share bits, not the easiest the band allows.
TEST(NodeFeeJobTarget, FeeJobHasItsMinersShareBits)
{
    Rig r;
    const auto miner = p2pkh(0x0a);
    const auto op = p2pkh(0x0e);
    const double a_easy = attempts(r.node.easiest());
    r.node.rates[key_of(0x0a)] = a_easy * 100.0;   // H/s: Cap 1 wants ~1e5 x the easiest share

    r.mi.set_node_fee(0.0, op);
    const auto [normal_payout, normal_bits] = r.job(key_of(0x0a), miner);
    ASSERT_EQ(normal_payout, miner);
    EXPECT_NEAR(attempts(normal_bits) / a_easy, 30.0, 0.1) << "the miner's jobs sit at the hard edge";

    r.mi.set_node_fee(100.0, op);
    const auto [fee_payout, fee_bits] = r.job(key_of(0x0a), miner);
    ASSERT_EQ(fee_payout, op) << "the fee draw gave the job to the operator";
    EXPECT_EQ(fee_bits, normal_bits) << "a fee job is its miner's job but for the payout; was the easiest share "
                                     << "(30x easier: 1/30 of the weight per share)";
}

// The operator mining on its own node to its own address: its own jobs are
// sized by its own rate, as any miner's.
TEST(NodeFeeJobTarget, OperatorsOwnJobsAreSizedByItsRate)
{
    Rig r;
    const auto op = p2pkh(0x0e);
    const double a_easy = attempts(r.node.easiest());
    r.node.rates[key_of(0x0e)] = a_easy * 100.0;
    r.mi.set_node_fee(100.0, op);
    const auto [payout, bits] = r.job(key_of(0x0e), op);
    EXPECT_EQ(payout, op);
    EXPECT_NEAR(attempts(bits) / a_easy, 30.0, 0.1);
}

// The operator's expected PPLNS weight over many jobs is the fee.
//
// A node like the field one: one miner address on 10 connections, its rate at
// the hard edge of the band, an easy (pre_target3) share every ~5.8 s per
// connection, all jobs rebuilt on every new share and on a template refresh
// (~every 4.2 s). Each round every connection gets a job (the fee draw is the
// real decide_job_payout, seeded), the round lasts until the first share or a
// refresh (competing exponentials), and each job is credited its expected
// weight: P(its share ends the round) x its share's attempts. A share needs
// PoW at its job's own share bits (p2pool got_response).
//
// A fee job sized by the operator's key (rate 0 -> pre_target3) is 30x
// likelier to end its round early, and the operator's weight came out at
// ~0.64 of the draws; sized by its miner, it equals the draws.
TEST(NodeFeeJobTarget, OperatorsWeightIsTheFee)
{
    core::random::seed(kSeed);
    Node node;
    MiningInterface mi{/*testnet=*/false};
    const auto miner = p2pkh(0x0a);
    const auto op = p2pkh(0x0e);
    const double fee = 1.0;   // percent
    mi.set_node_fee(fee, op);

    constexpr int kConnections = 10;
    constexpr int kRounds = 20000;
    const double a_easy = attempts(node.easiest());
    const double conn_rate = a_easy / 5.8;          // H/s per connection
    const double refresh_rate = 1.0 / 4.17;         // template refreshes / s
    node.rates[key_of(0x0a)] = conn_rate * kConnections;

    double owner = 0.0, total = 0.0;
    long draws = 0;
    for (int round = 0; round < kRounds; ++round) {
        std::vector<double> share_attempts(kConnections), share_rate(kConnections);
        std::vector<bool> is_fee(kConnections);
        double end_rate = refresh_rate;
        for (int c = 0; c < kConnections; ++c) {
            auto payout = miner;
            Merged merged;
            mi.decide_job_payout(payout, merged);
            is_fee[c] = payout == op;
            draws += is_fee[c];
            const uint32_t bits = node.share_bits(core::stratum::job_rate_key(key_of(0x0a), payout));
            share_attempts[c] = attempts(bits);
            share_rate[c] = conn_rate / share_attempts[c];
            end_rate += share_rate[c];
        }
        for (int c = 0; c < kConnections; ++c) {
            const double weight = share_rate[c] / end_rate * share_attempts[c];
            total += weight;
            if (is_fee[c])
                owner += weight;
        }
    }
    const double draw_rate = double(draws) / (double(kConnections) * kRounds);
    const double owner_fraction = owner / total;
    EXPECT_NEAR(draw_rate, fee / 100.0, 0.0015) << "the fee draw itself (random_uniform_test pins it)";
    EXPECT_NEAR(owner_fraction / draw_rate, 1.0, 0.01)
        << "the operator's weight is the jobs the fee drew: owner " << owner_fraction * 100.0
        << "% of the weight for " << draw_rate * 100.0 << "% of the jobs";
}
