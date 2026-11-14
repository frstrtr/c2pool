// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH: a stratum submit is judged by its own job's share bits.
//
// The core stratum session's pool-share gate (StratumSession::handle_submit:
// "does this submit make a share?") decides with
// core::stratum::pool_share_bits(job.frozen_bits, live): the bits frozen into
// the job when it was built, the node-global live bits only for a job built
// without them. DASH sizes each miner's share target by that miner's own
// local rate (Cap 1, desired_share_target; clipped to [pre_target3/30,
// pre_target3]), so two miners on one node can have targets up to 30x apart.
// DASHWorkSource never froze its jobs' bits, so every submit was judged by the
// bits of the last job built for ANY connection: a smaller miner's shares
// that met their own (easier) target but not a bigger miner's were dropped as
// pseudoshares, keeping as little as 1/30 of its due shares at the band edge.
//
// These tests run the real DASHWorkSource producer path with a producer stub
// that gives each payout its own share bits, the way main_dash's Cap 1 does.
// Deleting the freeze in build_connection_coinbase turns them red.
// (The gate itself, core::stratum::pool_share_bits at the session's call
// site, is pinned by NodeFeeStratumSession.SubmitIsJudgedByItsJobsShareBits
// and the core PoolShareGate tests.)

#include <impl/dash/stratum/work_source.hpp>
#include <impl/dash/coin/node_coin_state.hpp>

#include <core/stratum_types.hpp>
#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <vector>

namespace {

dash::coin::DashWorkData gate_work()
{
    dash::coin::DashWorkData w;
    w.m_version = 0x20000000;
    w.m_previous_block.SetHex(
        "0000000000000000abcdef0123456789abcdef0123456789abcdef0123456789");
    w.m_height         = 2572100u;
    w.m_coinbase_value = 100000000ull;
    w.m_bits           = 0x1926142du;
    w.m_curtime        = 1794650000u;
    return w;
}

std::vector<unsigned char> p2pkh(unsigned char fill)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// Share targets of a small and a big miner, 30x apart (the Cap 1 band edge).
constexpr uint32_t SMALL_BITS = 0x1c0bc28d, SMALL_MAX = 0x1c0fffff;
constexpr uint32_t BIG_BITS   = 0x1b6477da, BIG_MAX   = 0x1c07ffff;

struct Rig {
    dash::coin::NodeCoinState cs;
    std::unique_ptr<dash::stratum::DASHWorkSource> ws;
    bool producer_declines = false;   // the producer gives no job (tracker busy)
    Rig()
    {
        auto fallback = []() -> dash::coin::DashWorkData { return gate_work(); };
        auto submit = [](const std::vector<unsigned char>&, uint32_t, bool) { return true; };
        ws = std::make_unique<dash::stratum::DASHWorkSource>(
            cs, fallback, submit, core::stratum::StratumConfig{}, /*is_testnet=*/false);
        // A producer job per payout, sized by that payout's miner (Cap 1).
        ws->set_producer_job_fn(
            [this](const uint256&, const std::vector<unsigned char>& payout,
                   const dash::coin::DashWorkData&)
                -> std::optional<dash::stratum::DASHWorkSource::ProducerJob> {
                if (producer_declines)
                    return std::nullopt;
                dash::stratum::DASHWorkSource::ProducerJob pj;
                pj.gentx_bytes.assign(64, 0x00);
                pj.nonce64_offset = 40;
                pj.ref_hash.SetHex("11");
                const bool big = payout == p2pkh(0xbb);
                pj.share_bits     = big ? BIG_BITS : SMALL_BITS;
                pj.share_max_bits = big ? BIG_MAX : SMALL_MAX;
                return pj;
            });
    }
};

} // namespace

// Every producer job carries its own share bits into the stratum job.
TEST(DashShareGateFrozenBits, ProducerJobFreezesItsShareBits)
{
    Rig r;
    const auto small = r.ws->build_connection_coinbase(uint256::ZERO, "00000000", p2pkh(0x5a), {});
    const auto big   = r.ws->build_connection_coinbase(uint256::ZERO, "00000001", p2pkh(0xbb), {});
    ASSERT_TRUE(small.snapshot.has_header);
    ASSERT_TRUE(big.snapshot.has_header);
    EXPECT_EQ(small.snapshot.frozen_ref.bits, SMALL_BITS);
    EXPECT_EQ(small.snapshot.frozen_ref.max_bits, SMALL_MAX);
    EXPECT_EQ(big.snapshot.frozen_ref.bits, BIG_BITS);
    EXPECT_EQ(big.snapshot.frozen_ref.max_bits, BIG_MAX);
}

// The small miner's job was built first, the big miner's last: the node-global
// bits are now the big miner's. The gate input the session computes for the
// small miner's submit is still its own job's bits.
TEST(DashShareGateFrozenBits, SmallMinersSubmitIsJudgedByItsOwnJobAfterABiggerJob)
{
    Rig r;
    const auto small = r.ws->build_connection_coinbase(uint256::ZERO, "00000000", p2pkh(0x5a), {});
    (void)r.ws->build_connection_coinbase(uint256::ZERO, "00000001", p2pkh(0xbb), {});
    ASSERT_EQ(r.ws->get_share_bits(), BIG_BITS) << "the live bits are the last job built";
    EXPECT_EQ(core::stratum::pool_share_bits(small.snapshot.frozen_ref.bits, r.ws->get_share_bits()),
              SMALL_BITS)
        << "judged by the big miner's bits, the small miner keeps about 1/30 of its shares";
    EXPECT_EQ(core::stratum::pool_share_bits(small.snapshot.frozen_ref.max_bits, r.ws->get_share_max_bits()),
              SMALL_MAX);
}

// A job built without a producer job (tracker busy, non-P2PKH payout) freezes
// no bits: the gate falls back to the live bits, and such a job cannot mint.
TEST(DashShareGateFrozenBits, NonProducerJobFreezesNothing)
{
    Rig r;
    (void)r.ws->build_connection_coinbase(uint256::ZERO, "00000001", p2pkh(0xbb), {});
    r.producer_declines = true;
    const auto plain = r.ws->build_connection_coinbase(uint256::ZERO, "00000000", p2pkh(0x5a), {});
    ASSERT_TRUE(plain.snapshot.has_header);
    EXPECT_EQ(plain.snapshot.frozen_ref.bits, 0u);
    EXPECT_EQ(plain.snapshot.frozen_ref.max_bits, 0u);
    EXPECT_EQ(core::stratum::pool_share_bits(plain.snapshot.frozen_ref.bits, r.ws->get_share_bits()),
              BIG_BITS) << "a job without frozen bits is gated by the live bits";
}
