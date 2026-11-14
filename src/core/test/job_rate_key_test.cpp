// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A stratum job's share target is sized by its connection's miner, also when
// the node fee gave the job's payout to the operator (rides core_test).
//
// decide_job_payout gives a job to the node operator (--fee) by replacing its
// payout script. build_connection_coinbase used to hand that substituted
// script to ref_hash_fn as the only identity, and the LTC ref_hash_fn sized
// the share target by the local hash rate of the payout's key: the
// operator's, which has none (the stratum server records a connection's
// pseudoshares under its login key). A fee job then got the easiest target
// the chain allows, its shares weighed 1/30 of the work behind them, and the
// operator got a fraction of the fee (field: 0.08% of the block for --fee 1,
// a node of ~150 GH/s that is most of its sharechain).
//
// Pinned here: MiningInterface::build_connection_coinbase_for hands
// ref_hash_fn the job's payout AND the connection's login key as the rate
// key (the key its pseudoshares are recorded under, zero for a keyless
// login), on a fee job too, while the plain build_connection_coinbase
// (callers that are no stratum connection) sizes it by the payout's key
// (core::stratum::payout_script_key). And the share gate
// (core::stratum::pool_share_bits): a submission is judged by its own job's
// share bits, not by the last job built for any connection. The stratum
// session's side (it passes its login key, it gates by the job's bits) is
// pinned over TCP in share_test NodeFeeStratumSession.*.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/stratum_types.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

namespace {

using core::MiningInterface;
using core::stratum::PayoutKey;

PayoutKey key_of(unsigned char b)
{
    PayoutKey k;
    k.fill(b);
    return k;
}

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

std::vector<unsigned char> p2sh(unsigned char b)
{
    std::vector<unsigned char> s{0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x87);
    return s;
}

std::vector<unsigned char> p2wpkh(unsigned char b)
{
    std::vector<unsigned char> s{0x00, 0x14};
    s.insert(s.end(), 20, b);
    return s;
}

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

// A MiningInterface whose ref_hash_fn records what it was asked to size.
struct Rig {
    LtcNode ltc;
    MiningInterface mi{/*testnet=*/true};
    std::vector<unsigned char> seen_payout;
    PayoutKey seen_rate_key{};
    Rig()
    {
        mi.set_coin_node(&ltc);
        mi.set_pplns_fn([](const uint256&, const uint256&, uint64_t subsidy, const std::vector<unsigned char>& don)
                            -> std::map<std::vector<unsigned char>, double> {
            return {{don, static_cast<double>(subsidy)}};
        });
        mi.set_ref_hash_fn([this](const uint256&, const std::vector<unsigned char>&,
                                  const std::vector<unsigned char>& payout, const PayoutKey& rate_key,
                                  uint64_t, uint32_t, uint32_t, bool, const std::string&, const uint256&,
                                  const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                                  const std::vector<uint256>&) {
            seen_payout = payout;
            seen_rate_key = rate_key;
            MiningInterface::RefHashResult r;
            r.ref_hash.SetHex(std::string(64, '5'));
            r.bits = 0x207fffff;
            return r;
        });
        mi.refresh_work();
    }
    // The stratum session's job: decide_job_payout, then the build for the
    // connection's login key.
    std::vector<unsigned char> job(const PayoutKey& login, const std::vector<unsigned char>& login_script)
    {
        auto payout = login_script;
        std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged;
        mi.decide_job_payout(payout, merged);
        uint256 prev;
        prev.SetHex("01");
        const auto cbr = mi.build_connection_coinbase_for(login, prev, "aabbccdd", payout, merged);
        EXPECT_FALSE(cbr.held);
        EXPECT_FALSE(cbr.coinb1.empty());
        return payout;
    }
};

} // namespace

TEST(JobRateKey, PayoutScriptKeyReadsP2pkhP2shP2wpkh)
{
    EXPECT_EQ(core::stratum::payout_script_key(p2pkh(0x11)), key_of(0x11));
    EXPECT_EQ(core::stratum::payout_script_key(p2sh(0x22)), key_of(0x22));
    EXPECT_EQ(core::stratum::payout_script_key(p2wpkh(0x33)), key_of(0x33));
    std::vector<unsigned char> p2wsh{0x00, 0x20};
    p2wsh.insert(p2wsh.end(), 32, 0x44);
    EXPECT_EQ(core::stratum::payout_script_key(p2wsh), PayoutKey{}) << "a 32-byte program has no 20-byte key";
    EXPECT_EQ(core::stratum::payout_script_key({}), PayoutKey{});
}

// The field case: --fee draws the job for the operator. Its payout is the
// operator's; the key that sizes its share target is the miner's.
TEST(NodeFeeShareTarget, FeeJobIsSizedByItsMiner)
{
    Rig r;
    const auto op = p2pkh(0x0e);
    r.mi.set_node_fee(100.0, op);   // every job is a fee job
    const auto payout = r.job(key_of(0x0a), p2pkh(0x0a));
    EXPECT_EQ(payout, op) << "the fee draw gave the job to the operator";
    EXPECT_EQ(r.seen_payout, op) << "the share commits to the operator's payout";
    EXPECT_EQ(r.seen_rate_key, key_of(0x0a))
        << "the share target is sized by the miner's local rate, not the operator's (none)";
}

TEST(NodeFeeShareTarget, NormalJobIsSizedByItsMiner)
{
    Rig r;
    r.mi.set_node_fee(0.0, p2pkh(0x0e));
    const auto payout = r.job(key_of(0x0a), p2pkh(0x0a));
    EXPECT_EQ(payout, p2pkh(0x0a));
    EXPECT_EQ(r.seen_rate_key, key_of(0x0a)) << "unchanged: the miner's key is its payout's";
}

// A keyless login (empty, P2WSH, P2TR): its pseudoshares are recorded under
// the zero key, and its jobs, fee or redistributed, are sized by it, never by
// the operator's or the redistribution recipient's key.
TEST(NodeFeeShareTarget, KeylessLoginIsSizedByItsZeroKey)
{
    Rig r;
    const auto op = p2pkh(0x0e);
    r.mi.set_redistribute_fn([] { return std::make_pair(std::string(40, 'c'), uint8_t(0)); });
    r.mi.set_node_fee(0.0, op);
    EXPECT_EQ(r.job(PayoutKey{}, {}), p2pkh(0xcc)) << "redistributed";
    EXPECT_EQ(r.seen_rate_key, PayoutKey{}) << "not the recipient's key";
    r.mi.set_node_fee(100.0, op);
    EXPECT_EQ(r.job(PayoutKey{}, {}), op);
    EXPECT_EQ(r.seen_rate_key, PayoutKey{}) << "not the operator's key: the fee job is the login's job";
}

TEST(NodeFeeShareTarget, PlainBuildIsSizedByThePayout)
{
    Rig r;
    uint256 prev;
    prev.SetHex("01");
    const auto cbr = r.mi.build_connection_coinbase(prev, "aabbccdd", p2sh(0x0c), {});
    ASSERT_FALSE(cbr.coinb1.empty());
    EXPECT_EQ(r.seen_rate_key, key_of(0x0c)) << "no stratum connection: the payout's key, as before";
}

// A submission makes a share when its PoW meets its own job's share bits (the
// bits the share carries), not the last job built for any connection.
TEST(PoolShareGate, TheJobsOwnBitsNotTheLastJobBuilt)
{
    constexpr uint32_t easy = 0x1c0bc28d, hard = 0x1b6477da;   // field: a fee job, its miner's job
    EXPECT_EQ(core::stratum::pool_share_bits(easy, hard), easy);
    EXPECT_EQ(core::stratum::pool_share_bits(hard, easy), hard);
    EXPECT_EQ(core::stratum::pool_share_bits(0, hard), hard) << "a job without frozen bits: the live ones";
}
