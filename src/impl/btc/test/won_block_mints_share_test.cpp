// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// #887 -- the block-winning share must ALSO be written to the sharechain.
//
// BTCWorkSource::mining_submit classifies a solve tighten-first: block target,
// then share target. Because block_target <= share_target, a solve that clears
// the block target clears the share target BY DEFINITION -- it is the
// highest-work share this node will ever produce. Before #887 the won-block arm
// dispatched the block and RETURNED, so create_share_fn_ was never reached and
// the share was thrown away: our own PPLNS weight in the very window the block
// pays out from, and the strongest share peers would ever have seen from us,
// forfeited on every block won. LTC has always written on both classes
// (core/web_server.cpp).
//
// The two systems are independent -- the sharechain is not the coin blockchain
// -- and the solve belongs in both.
//
// Determinism: SHA256d of a fixed header is not steerable, so each KAT pins the
// OUTCOME CLASS by the TARGETS, not by the hash (the dgb_work_source_test
// idiom). block_nbits = 0x2100ffff expands to 0xffff << 240, i.e. ~2^256 --
// every practical digest clears it, so WonBlock is deterministic.
//
// Folded into the existing btc_share_test target (never a standalone
// add_executable -- those silently report "Not Run"; see PR #868).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/btc/stratum/work_source.hpp>
#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/coin/mempool.hpp>
#include <core/stratum_types.hpp>
#include <core/uint256.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// A BTCWorkSource over default coin deps. The submit callback records the
// won-block dispatch so the tests can pin BOTH that it happened and WHEN.
struct Fixture {
    btc::coin::BTCChainParams params = btc::coin::BTCChainParams::mainnet();
    btc::coin::HeaderChain    chain{params};
    btc::coin::Mempool        mempool;
    bool                      submit_called = false;

    std::unique_ptr<btc::stratum::BTCWorkSource> make()
    {
        auto fn = [this](const std::vector<unsigned char>&, uint32_t) -> bool {
            submit_called = true;
            return true;
        };
        return std::make_unique<btc::stratum::BTCWorkSource>(
            chain, mempool, /*is_testnet=*/false, fn);
    }
};

core::stratum::JobSnapshot make_job(uint32_t share_bits,
                                    const std::string& block_nbits)
{
    core::stratum::JobSnapshot j;
    j.coinb1        = "01000000";              // minimal well-formed coinbase head
    j.coinb2        = "00000000";              // minimal coinbase tail
    j.gbt_prevhash  = std::string(64, '0');    // 32-byte prevhash, BE display hex
    j.nbits         = "1e0fffff";              // header (share) bits
    j.version       = 0x20000000u;
    j.share_bits    = share_bits;
    j.block_nbits   = block_nbits;
    j.subsidy       = 625000000ULL;
    j.segwit_active = false;
    return j;
}

const char* kEN1 = "00000000";
const char* kEN2 = "00000000";
const char* kNT  = "60000000";
const char* kNON = "00000000";

}  // namespace

// Baseline (pre-existing behaviour, unchanged by #887): a won block still
// reaches the dual-path broadcaster.
TEST(BtcWonBlockMintsShare, WonBlockStillDispatchesBroadcaster)
{
    Fixture fx;
    auto ws = fx.make();
    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"2100ffff");
    auto result = ws->mining_submit(
        "1BitcoinEaterAddressDontSendf59kuE.w1", "job-won", kEN1, kEN2, kNT, kNON,
        "rid", /*merged_addresses=*/{}, &job);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    EXPECT_TRUE(fx.submit_called);
}

// THE #887 FIX: the won block is a share too -- create_share_fn_ must be
// reached, and it must be reached AFTER the block has already been dispatched.
TEST(BtcWonBlockMintsShare, WonBlockAlsoWritesTheShare)
{
    Fixture fx;
    auto ws = fx.make();

    bool share_written = false;
    bool saw_block_already_submitted = false;
    std::vector<uint8_t> seen_header;
    ws->set_create_share_fn(
        [&](const std::vector<unsigned char>& /*full_coinbase*/,
            const std::vector<uint8_t>&       header_80b,
            const core::stratum::JobSnapshot& /*job*/,
            const std::vector<unsigned char>& /*payout_script*/) -> uint256
        {
            share_written = true;
            seen_header   = header_80b;
            // Reward-invariant witness: the block MUST already be out.
            saw_block_already_submitted = fx.submit_called;
            return uint256(uint64_t(0xb10c5));
        });

    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"2100ffff");
    auto result = ws->mining_submit(
        "1BitcoinEaterAddressDontSendf59kuE.w1", "job-won-share", kEN1, kEN2,
        kNT, kNON, "rid", /*merged_addresses=*/{}, &job);

    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    EXPECT_TRUE(fx.submit_called);              // block dispatched, unchanged
    EXPECT_TRUE(share_written);                 // ...AND the share is written
    EXPECT_TRUE(saw_block_already_submitted);   // block FIRST, always
    EXPECT_EQ(seen_header.size(), 80u);         // the solved header, forwarded
}

// REWARD INVARIANT: a sharechain write that throws must not cost the block and
// must not turn a won block into a stratum reject.
TEST(BtcWonBlockMintsShare, WonBlockSurvivesAThrowingShareWrite)
{
    Fixture fx;
    auto ws = fx.make();
    ws->set_create_share_fn(
        [](const std::vector<unsigned char>&,
           const std::vector<uint8_t>&,
           const core::stratum::JobSnapshot&,
           const std::vector<unsigned char>&) -> uint256 {
            throw std::runtime_error("share write blew up");
        });

    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"2100ffff");
    auto result = ws->mining_submit(
        "1BitcoinEaterAddressDontSendf59kuE.w1", "job-won-throw", kEN1, kEN2,
        kNT, kNON, "rid", /*merged_addresses=*/{}, &job);

    EXPECT_TRUE(fx.submit_called);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
}

// Ordinary share path stays exactly as it was: share target cleared, block
// target not -> the share is written and NOTHING is broadcast to the network.
TEST(BtcWonBlockMintsShare, PlainShareStillWritesAndDoesNotBroadcast)
{
    Fixture fx;
    auto ws = fx.make();
    bool share_written = false;
    ws->set_create_share_fn(
        [&](const std::vector<unsigned char>&,
            const std::vector<uint8_t>&,
            const core::stratum::JobSnapshot&,
            const std::vector<unsigned char>&) -> uint256 {
            share_written = true;
            return uint256(uint64_t(0x5157));
        });

    // block_nbits = 0x03000001 -> target 1: no digest is a block.
    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"03000001");
    auto result = ws->mining_submit(
        "1BitcoinEaterAddressDontSendf59kuE.w1", "job-share", kEN1, kEN2,
        kNT, kNON, "rid", /*merged_addresses=*/{}, &job);

    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    EXPECT_TRUE(share_written);
    EXPECT_FALSE(fx.submit_called);
}
