// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::restore_block_flag: the block flag of a share reloaded from the
// sharechain store, from its PoW hash and the block target of its header
// (the test share_init_verify makes when the share is first verified).
// Pinned: a PoW hash at or below the target sets it; one above does not, also
// when it shares its first 16 hex digits with the target (a DASH or BTC share
// hash is its PoW hash, with leading zeros); a null PoW hash (not cached, not
// recomputable) leaves it clear; a flag already set is never cleared.

#include <gtest/gtest.h>

#include <core/reloaded_block_flag.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <string>

namespace {

struct Header { uint32_t m_bits{0}; };
struct Share  { Header m_min_header; };
struct Index  { bool is_block_solution{false}; };

uint256 hex(const std::string& h)
{
    uint256 v;
    v.SetHex(h);
    return v;
}

constexpr uint32_t kBits = 0x19232511;   // DASH block 2567538's bits

} // namespace

TEST(ReloadedBlockFlag, APowHashAtOrBelowTheBlockTargetSetsTheFlag)
{
    const uint256 target = chain::bits_to_target(kBits);
    Share s;
    s.m_min_header.m_bits = kBits;
    Index at, below;
    EXPECT_TRUE(core::restore_block_flag(at, s, target));
    EXPECT_TRUE(at.is_block_solution);
    EXPECT_TRUE(core::restore_block_flag(below, s, hex("000000000000002244cc74e9" + std::string(40, '0'))));
    EXPECT_TRUE(below.is_block_solution);
}

TEST(ReloadedBlockFlag, AHashAboveTheTargetIsNotABlockWhateverItsShortHash)
{
    Share s;
    s.m_min_header.m_bits = kBits;
    const uint256 target = chain::bits_to_target(kBits);
    // The same first 16 hex digits as the target, above it further on.
    std::string t = target.GetHex();
    std::string above = t.substr(0, 16) + std::string(48, 'f');
    ASSERT_EQ(above.substr(0, 16), t.substr(0, 16));
    Index idx;
    EXPECT_FALSE(core::restore_block_flag(idx, s, hex(above)));
    EXPECT_FALSE(idx.is_block_solution);
    EXPECT_FALSE(core::meets_block_target(hex(above), kBits));
}

TEST(ReloadedBlockFlag, ANullPowHashLeavesTheFlagAndASetFlagStays)
{
    Share s;
    s.m_min_header.m_bits = kBits;
    Index clear;
    EXPECT_FALSE(core::restore_block_flag(clear, s, uint256()));
    EXPECT_FALSE(clear.is_block_solution);
    Index set;
    set.is_block_solution = true;   // flagged when it was verified in this run
    EXPECT_TRUE(core::restore_block_flag(set, s, uint256()));
    EXPECT_TRUE(core::restore_block_flag(set, s, hex(std::string(64, 'f'))));
    // A header without a target (bits 0) is never a block.
    Share none;
    Index z;
    EXPECT_FALSE(core::restore_block_flag(z, none, hex("01")));
}
