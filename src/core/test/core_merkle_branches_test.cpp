// ---------------------------------------------------------------------------
// core_merkle_branches_test.cpp
//
// PRODUCER/CONSUMER CONTRACT PIN for core::MiningInterface::compute_merkle_branches
// (the LTC/core stratum consumer of WorkData::m_hashes).
//
// Sibling guard to PR #570 (BTC stratum merkle leaf-0 fix) + #574 (BIP141
// witness leaf-0). #570 established the SSOT producer contract: WorkData
// m_hashes is the PURE non-coinbase tx list [tx1..txN] with NO coinbase slot;
// the coinbase is leaf 0 and is prepended by each CONSUMER, never by the
// producer. The BTC consumer (get_stratum_merkle_branches) was fixed to prepend
// uint256::ZERO locally. This core consumer already honours the pure-tx
// contract -- it folds input[0] as the FIRST branch sibling (tx1), not a
// coinbase placeholder -- but had ZERO test coverage (the exact "untested
// merkle-branch contract" class the #570 bug arose from).
//
// This locks branches[0] == tx1 for a pure-tx input. If anyone later mistakenly
// "generalises" #570 by prepending a coinbase placeholder at the PRODUCER, this
// core/LTC path would silently drop tx1 and branches[0] would become all-zeros
// -- and these EXPECTs go RED. SAFE-ADDITIVE: pins present behaviour, adds no
// new logic.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <span>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <btclibs/util/strencodings.h>  // HexStr

namespace {

// HexStr of the INTERNAL (LE) bytes of a uint256 parsed from display hex --
// matches the wire encoding compute_merkle_branches emits per branch.
std::string internal_hex(const std::string& display_hex) {
    uint256 u; u.SetHex(display_hex);
    return HexStr(std::span<const unsigned char>(u.data(), 32));
}

const std::string TX1 = "1111111111111111111111111111111111111111111111111111111111111111";
const std::string TX2 = "2222222222222222222222222222222222222222222222222222222222222222";
const std::string TX3 = "3333333333333333333333333333333333333333333333333333333333333333";

} // namespace

// Leaf-0 contract: for a PURE non-coinbase tx list, the first stratum branch is
// tx1 itself (the coinbase's right-sibling at level 0), NOT a coinbase slot.
TEST(CoreMerkleBranches, PureTxListLeafZeroIsTx1NotCoinbasePlaceholder) {
    auto branches = core::MiningInterface::compute_merkle_branches({TX1, TX2, TX3});
    ASSERT_EQ(branches.size(), 2u);  // 3 tx -> {tx1, hash(tx2,tx3)}
    EXPECT_EQ(branches[0], internal_hex(TX1));

    // flip-RED tripwire: a producer-side ZERO coinbase placeholder would push
    // tx1 to branches[1] and make branches[0] the all-zero leaf.
    const std::string zero_hex =
        HexStr(std::span<const unsigned char>(uint256::ZERO.data(), 32));
    EXPECT_NE(branches[0], zero_hex);
}

// Degenerate sizes: empty -> {}, single tx -> single branch == that tx.
TEST(CoreMerkleBranches, EmptyAndSingleTxContract) {
    EXPECT_TRUE(core::MiningInterface::compute_merkle_branches({}).empty());

    auto one = core::MiningInterface::compute_merkle_branches({TX1});
    ASSERT_EQ(one.size(), 1u);
    EXPECT_EQ(one[0], internal_hex(TX1));
}
