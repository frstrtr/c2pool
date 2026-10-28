// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Merged-mining chain merkle tree slots (#2060, rides share_test).
//
// Every aux daemon checks that its chain sits at
// CAuxPow::getExpectedIndex(nonce, chain_id, h) in the chain merkle tree
// (dogecoin auxpow.cpp:157-186: "Aux POW wrong index" otherwise), with the
// nonce and size from the parent coinbase commitment (nonce 0 here). The
// builder used (chain_id * 1103515245 + 12345) % size in 64 bits: one LCG
// step short, so with two or more aux chains every aux block was refused.
// One chain (DOGE alone) puts it at slot 0 either way.
//
// Pins are the daemon formula computed offline (uint32 wrap):
//   ids {98, 1},          h = 1: slots {0, 1}            (old builder: {1, 0})
//   ids {98, 1, 20, 22},  h = 2: 98 and 22 collide (98 = 22 mod 4) for every
//                         nonce; h = 3: slots {0, 3, 2, 4} (old: {3, 6, 5, 7})
//   ids {98},             h = 0: slot 0
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include <core/uint256.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <impl/nmc/coin/header_chain.hpp>

namespace {

using c2pool::merged::AuxPowTree;

unsigned height_of(uint32_t size)
{
    unsigned h = 0;
    while ((1u << h) < size)
        ++h;
    return h;
}

} // namespace

TEST(MergedMining, TwoChainTreeSlotsMatchGetExpectedIndex)
{
    const auto t = AuxPowTree::build({98, 1});
    EXPECT_EQ(t.size, 2u);
    EXPECT_EQ(t.slot_map.at(98), 0u) << "getExpectedIndex(0, 98, 1)";
    EXPECT_EQ(t.slot_map.at(1), 1u) << "getExpectedIndex(0, 1, 1)";
}

TEST(MergedMining, CollidingChainsGrowTheTreeToTheDaemonsSlots)
{
    // 98 and 22 agree mod 4: same slot at size 4 for every nonce.
    for (uint32_t nonce = 0; nonce < 4; ++nonce)
        EXPECT_EQ(nmc::coin::aux_expected_index(nonce, 98, 2),
                  nmc::coin::aux_expected_index(nonce, 22, 2));
    const auto t = AuxPowTree::build({98, 1, 20, 22});
    EXPECT_EQ(t.size, 8u);
    EXPECT_EQ(t.slot_map.at(98), 0u);
    EXPECT_EQ(t.slot_map.at(1), 3u);
    EXPECT_EQ(t.slot_map.at(20), 2u);
    EXPECT_EQ(t.slot_map.at(22), 4u);
}

TEST(MergedMining, OneChainTreeIsSlotZero)
{
    const auto t = AuxPowTree::build({98});
    EXPECT_EQ(t.size, 1u);
    EXPECT_EQ(t.slot_map.at(98), 0u);
}

// For many chain sets: every slot is the daemon's for the tree's size,
// slots are distinct, the size is the smallest power of two where they are,
// and the proof for a chain carries the index and branch length the daemon
// checks (nChainIndex, nSize == 1 << branch length).
TEST(MergedMining, TreeSlotsAreTheDaemonsForManyChainSets)
{
    const std::vector<std::vector<uint32_t>> sets = {
        {98, 1}, {1, 98}, {98, 1, 20}, {98, 1, 20, 22}, {98, 7, 16, 1, 99},
        {2, 6, 10, 14}, {98, 1, 3, 5, 7, 9, 11, 13},
    };
    for (const auto& ids : sets) {
        const auto t = AuxPowTree::build(ids);
        const unsigned h = height_of(t.size);
        ASSERT_EQ(t.size, 1u << h);
        std::set<uint32_t> used;
        for (uint32_t cid : ids) {
            const uint32_t slot = t.slot_map.at(cid);
            EXPECT_EQ(slot, nmc::coin::aux_expected_index(0, static_cast<int32_t>(cid), h))
                << "chain " << cid << " size " << t.size;
            EXPECT_TRUE(used.insert(slot).second) << "slot " << slot << " used twice";
        }
        if (h > 0 && t.size > ids.size()) {
            // Half the size cannot hold them: two ids agree mod size / 2.
            std::set<uint32_t> half;
            bool clash = false;
            for (uint32_t cid : ids)
                clash = clash || !half.insert(nmc::coin::aux_expected_index(
                                                0, static_cast<int32_t>(cid), h - 1)).second;
            EXPECT_TRUE(clash) << "size " << t.size << " is not the smallest";
        }
        std::map<uint32_t, uint256> leaves;
        for (uint32_t cid : ids) {
            uint256 hh;
            hh.SetHex(std::to_string(1000 + cid));
            leaves[t.slot_map.at(cid)] = hh;
        }
        for (uint32_t cid : ids) {
            const auto proof = t.compute_root(leaves, t.slot_map.at(cid));
            EXPECT_EQ(proof.index, nmc::coin::aux_expected_index(
                                       0, static_cast<int32_t>(cid),
                                       static_cast<unsigned>(proof.branch.size())));
            EXPECT_EQ(t.size, 1u << proof.branch.size());
        }
    }
}
