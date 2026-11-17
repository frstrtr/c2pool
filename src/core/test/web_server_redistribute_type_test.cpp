// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A share's payout keeps its recipient's own script type (rides core_test).
//
// mining_submit replaces a miner's payout in two places: Case 3 (no usable
// address: --redistribute picks a recipient) and the node fee draw (-f: the
// operator's address). Both kept the MINER's script type: a redistributed
// share landing on a P2SH recipient paid P2PKH(<script hash>) (nobody can
// spend it; 18.55% of one contention run's LTC value), a P2WPKH one paid
// P2PKH; an operator's P2SH fee address under a P2PKH miner's type paid
// nobody, a P2PKH operator under a P2SH miner's type a script no one holds.
// The recipient's type now travels with its hash. Pinned on the real
// MiningInterface: the share creation hook sees the payout script.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/web_server.hpp>

namespace {

using core::MiningInterface;

std::vector<unsigned char> h20(unsigned char b) { return std::vector<unsigned char>(20, b); }

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    auto h = h20(b);
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

std::vector<unsigned char> p2sh(unsigned char b)
{
    std::vector<unsigned char> s{0xa9, 0x14};
    auto h = h20(b);
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return s;
}

std::vector<unsigned char> p2wpkh(unsigned char b)
{
    std::vector<unsigned char> s{0x00, 0x14};
    auto h = h20(b);
    s.insert(s.end(), h.begin(), h.end());
    return s;
}

std::string hex20(unsigned char b)
{
    static const char* H = "0123456789abcdef";
    std::string r;
    for (int i = 0; i < 20; ++i) { r += H[b >> 4]; r += H[b & 15]; }
    return r;
}

struct Rig {
    MiningInterface mi{/*testnet=*/true};
    std::optional<std::vector<unsigned char>> created;   // the created share's payout script
    MiningInterface::JobSnapshot job;
    Rig()
    {
        mi.set_create_share_fn([this](const MiningInterface::ShareCreationParams& p) {
            created = p.payout_script;
            return uint256();
        });
        job.coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
        job.coinb2 = "0000000000f2052a010000001976a914000000000000000000000000000000000000000088ac00000000";
        job.gbt_prevhash = std::string(62, '0') + "ab";
        job.nbits = "207fffff";
        job.block_nbits = "207fffff";
        job.share_bits = 0x207fffff;
        job.version = 0x20000000;
        job.subsidy = 5000000000ULL;
        job.tx_data = std::make_shared<std::vector<std::string>>();
    }
    void submit(const std::string& user)
    {
        created.reset();
        mi.mining_submit(user, "j1", "aabbccdd", "00000001", "5f5e1000", "00000002", "1", {}, &job);
    }
};

} // namespace

TEST(RedistributeType, ARedistributedShareKeepsItsRecipientsScriptType)
{
    Rig r;
    r.mi.set_address_fallback_fn([](const std::string&) { return std::pair<std::string, uint8_t>{hex20(0x0f), 2}; });
    r.submit("not-an-address");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2sh(0x0f)) << "a P2SH recipient is paid as P2SH, not P2PKH(<script hash>)";

    r.mi.set_address_fallback_fn([](const std::string&) { return std::pair<std::string, uint8_t>{hex20(0x5c), 1}; });
    r.submit("not-an-address");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2wpkh(0x5c)) << "a P2WPKH recipient is paid as P2WPKH";

    r.mi.set_address_fallback_fn([](const std::string&) { return std::pair<std::string, uint8_t>{hex20(0xa1), 0}; });
    r.submit("not-an-address");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2pkh(0xa1));
}

TEST(RedistributeType, NoRecipientOrAnUnknownTypeCreatesNoShare)
{
    Rig r;
    r.mi.set_address_fallback_fn([](const std::string&) { return std::pair<std::string, uint8_t>{std::string(), 0}; });
    r.submit("not-an-address");
    EXPECT_FALSE(r.created.has_value()) << "no share with an unresolved payout";

    r.mi.set_address_fallback_fn([](const std::string&) { return std::pair<std::string, uint8_t>{hex20(0x0f), 7}; });
    r.submit("not-an-address");
    EXPECT_FALSE(r.created.has_value()) << "a type a share cannot carry is not used";
}

TEST(RedistributeType, TheNodeFeeDrawPaysTheOperatorsOwnScriptType)
{
    Rig r;
    // Fee 100% takes every share: the draw is a continuous [0, 100) roll
    // compared as double, so this is deterministic (the old integer draw
    // returned 100 one time in 101 and this test flaked).
    // a P2SH operator, every share drawn (100%), a P2PKH miner
    r.mi.set_node_fee(100.0, p2sh(0x0e));
    r.submit("mvFaiHPVU5dYAnKcw4knKpZyzoW8UoaheA");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2sh(0x0e)) << "not P2PKH(<operator script hash>)";

    // a P2PKH operator, a P2SH miner
    r.mi.set_node_fee(100.0, p2pkh(0x0d));
    r.submit("QMycHUtqzEqzFHPZRRAPPaGrRaiwo21zws");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2pkh(0x0d)) << "not P2SH(<operator pubkey hash>)";

    // a P2WPKH operator
    r.mi.set_node_fee(100.0, p2wpkh(0x0c));
    r.submit("mvFaiHPVU5dYAnKcw4knKpZyzoW8UoaheA");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2wpkh(0x0c));
}

TEST(RedistributeType, WithoutTheFeeDrawTheMinersOwnTypeIsKept)
{
    Rig r;
    r.submit("QMycHUtqzEqzFHPZRRAPPaGrRaiwo21zws");
    ASSERT_TRUE(r.created.has_value());
    ASSERT_EQ(r.created->size(), 23u);
    EXPECT_EQ((*r.created)[0], 0xa9) << "a P2SH miner is paid as P2SH";
}
