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

#include <core/author_fee.hpp>
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

// --redistribute split (the default): work the node cannot attribute to a
// payout address pays the node owner and the donation half and half. The job
// (decide_job_payout) pays the owner's own script type with share donation
// core::kSplitShareDonation (32768 of 65535); the share made from it carries
// exactly that payout and donation (ShareCreationParams), whatever the login
// is by the time the miner submits.
namespace {
struct SplitRig : Rig {
    std::optional<std::optional<uint16_t>> donation;   // the created share's donation (outer: created)
    SplitRig()
    {
        mi.set_create_share_fn([this](const MiningInterface::ShareCreationParams& p) {
            created = p.payout_script;
            donation = p.share_donation;
            return uint256();
        });
    }
    void submit(const std::string& user)
    {
        donation.reset();
        Rig::submit(user);
    }
};
} // namespace

TEST(RedistributeSplit, AnUnusableLoginMintsTheOwnerWithTheSplitDonation)
{
    EXPECT_EQ(core::kSplitShareDonation, 32768);
    for (const auto& owner : {p2pkh(0x0a), p2sh(0x0b), p2wpkh(0x0c)}) {
        SplitRig r;
        // the old --redistribute pick lands elsewhere: split takes its place
        r.mi.set_redistribute_fn([] { return std::pair<std::string, uint8_t>{hex20(0x07), 0}; });
        ASSERT_TRUE(r.mi.set_split_owner(owner, {}));
        EXPECT_TRUE(r.mi.has_split_owner());
        // no usable address: decided at submit (a job without a payout)
        r.submit("not-an-address");
        ASSERT_TRUE(r.created.has_value());
        EXPECT_EQ(*r.created, owner) << "the owner, in its own script type";
        ASSERT_TRUE(r.donation.has_value() && r.donation->has_value());
        EXPECT_EQ(**r.donation, 32768);
        // a usable login: its own payout, the node's donation
        r.submit("mvFaiHPVU5dYAnKcw4knKpZyzoW8UoaheA");
        ASSERT_TRUE(r.created.has_value());
        EXPECT_NE(*r.created, owner);
        ASSERT_TRUE(r.donation.has_value());
        EXPECT_FALSE(r.donation->has_value());
    }
}

// The job decision: a payout a share cannot carry (empty login, P2WSH) pays
// the owner with the split donation; a usable payout is unchanged with the
// node's donation; the node fee draw comes first (a fee job is the
// operator's, with the node's donation).
TEST(RedistributeSplit, TheJobDecisionReturnsTheSplitDonation)
{
    MiningInterface mi{true};
    const auto owner = p2pkh(0x0a);
    ASSERT_TRUE(mi.set_split_owner(owner, {}));
    std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged;
    std::vector<unsigned char> payout;
    auto d = mi.decide_job_payout(payout, merged);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(*d, 32768);
    EXPECT_EQ(payout, owner);
    std::vector<unsigned char> p2wsh{0x00, 0x20};
    p2wsh.insert(p2wsh.end(), 32, 0x43);
    payout = p2wsh;
    d = mi.decide_job_payout(payout, merged);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(*d, 32768);
    EXPECT_EQ(payout, owner) << "a P2WSH primary (a share carries a 20-byte hash): the owner";
    payout = p2pkh(0x21);
    EXPECT_FALSE(mi.decide_job_payout(payout, merged).has_value());
    EXPECT_EQ(payout, p2pkh(0x21));
    mi.set_node_fee(100.0, p2sh(0x0e));
    payout.clear();
    EXPECT_FALSE(mi.decide_job_payout(payout, merged).has_value());
    EXPECT_EQ(payout, p2sh(0x0e)) << "the fee draw takes the job first";
}

// The reconnect race: the job sent right after mining.subscribe is built
// before mining.authorize, with no payout. Its job id stays active after the
// authorize, so a share found on it can be submitted (and is accepted) under
// the now-authorized login. It is minted with the payout and donation that
// job committed to: the owner and the split donation, never an empty script
// (no share) and never the login's address (its ref_hash committed to the
// owner). The session side (the job keeps its decision through the
// authorize) is pinned in share_test (MergedAuxStratumSession,
// AJobBuiltBeforeTheLoginKeepsItsSplitThroughTheAuthorize).
TEST(RedistributeSplit, TheJobBuiltBeforeTheLoginMintsTheOwnerWithTheSplitDonation)
{
    SplitRig r;
    const auto owner = p2pkh(0x0a);
    ASSERT_TRUE(r.mi.set_split_owner(owner, {}));
    // what send_notify_work did for that job: the decision on an empty payout
    std::vector<unsigned char> payout;
    std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged;
    const auto d = r.mi.decide_job_payout(payout, merged);
    r.job.has_payout = true;
    r.job.payout_script = payout;
    r.job.share_donation = d;
    // submitted after the authorize, under a usable login
    r.submit("mvFaiHPVU5dYAnKcw4knKpZyzoW8UoaheA");
    ASSERT_TRUE(r.created.has_value()) << "the miner's work is credited: a share is minted";
    EXPECT_EQ(*r.created, owner);
    ASSERT_TRUE(r.donation.has_value() && r.donation->has_value());
    EXPECT_EQ(**r.donation, 32768);
}

// No usable node-owner address: the owner half cannot be paid; the node
// keeps the old pplns behaviour (the --redistribute pick, the node's
// donation). An empty, P2WSH or zero-key owner is refused.
TEST(RedistributeSplit, WithoutAnOwnerTheOldRedistributionStays)
{
    std::vector<unsigned char> p2wsh{0x00, 0x20};
    p2wsh.insert(p2wsh.end(), 32, 0x43);
    for (const auto& bad : {std::vector<unsigned char>{}, p2wsh, p2pkh(0x00)}) {
        SplitRig r;
        r.mi.set_redistribute_fn([] { return std::pair<std::string, uint8_t>{hex20(0x07), 0}; });
        EXPECT_FALSE(r.mi.set_split_owner(bad, {}));
        EXPECT_FALSE(r.mi.has_split_owner());
        std::vector<unsigned char> payout;
        std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged;
        EXPECT_FALSE(r.mi.decide_job_payout(payout, merged).has_value());
        EXPECT_EQ(payout, p2pkh(0x07)) << "the pplns pick, as before";
        r.submit("not-an-address");
        ASSERT_TRUE(r.created.has_value());
        EXPECT_EQ(*r.created, p2pkh(0x07));
        ASSERT_TRUE(r.donation.has_value());
        EXPECT_FALSE(r.donation->has_value()) << "the node's donation";
    }
    // set, then cleared by an unusable owner: off again
    SplitRig r;
    ASSERT_TRUE(r.mi.set_split_owner(p2pkh(0x0a), {}));
    EXPECT_FALSE(r.mi.set_split_owner({}, {}));
    EXPECT_FALSE(r.mi.has_split_owner());
}

// The old modes are unchanged: without a split owner, the fee and the
// --redistribute pick decide as before and carry the node's donation.
TEST(RedistributeSplit, TheOldModesCarryTheNodesDonation)
{
    SplitRig r;
    r.mi.set_address_fallback_fn([](const std::string&) { return std::pair<std::string, uint8_t>{hex20(0x0f), 2}; });
    r.submit("not-an-address");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2sh(0x0f));
    ASSERT_TRUE(r.donation.has_value());
    EXPECT_FALSE(r.donation->has_value());
    r.mi.set_node_fee(100.0, p2pkh(0x0d));
    r.submit("mvFaiHPVU5dYAnKcw4knKpZyzoW8UoaheA");
    ASSERT_TRUE(r.created.has_value());
    EXPECT_EQ(*r.created, p2pkh(0x0d));
    ASSERT_TRUE(r.donation.has_value());
    EXPECT_FALSE(r.donation->has_value());
}
