// dgb::ShareTracker::compute_share_target — genesis/unknown-prev branch KAT.
//
// FENCED conformance test (no production code touched). Pins the share-target
// clamp that p2pool-v36 BaseShare.generate_transaction applies when the
// previous share is unknown (genesis / chain not yet seeded): the new share
// target is clipped to [MAX_TARGET/30, MAX_TARGET] and max_bits is taken from
// MAX_TARGET. Oracle SSOT: frstrtr/p2pool-dgb-scrypt bitcoin/data.py
// generate_transaction (pre_target clip path) with MAX_TARGET from
// networks/digibyte.py = 2**256//2**20 - 1 (2^236 - 1).
//
// compute_share_target had NO direct coverage before this slice; the genesis
// branch is the one path fully deterministic without a seeded chain, so it is
// the right anchor for a self-contained KAT.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/config_pool.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

namespace {

// A desired_target far above MAX_TARGET (forces the hi clamp).
uint256 all_ones() {
    uint256 t;
    t.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return t;
}

// The genesis branch ignores desired_timestamp; any value is fine.
constexpr uint32_t kTs = 1700000000u;

TEST(DgbShareTargetGenesis, MaxBitsFromMaxTarget) {
    dgb::ShareTracker tracker;
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(uint256(), kTs, MAX_TARGET);
    EXPECT_EQ(st.max_bits, chain::target_to_bits_upper_bound(MAX_TARGET));
}

TEST(DgbShareTargetGenesis, DesiredAboveMaxClampsToMax) {
    dgb::ShareTracker tracker;
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(uint256(), kTs, all_ones());
    // bits_target clipped to MAX_TARGET -> bits == max_bits.
    EXPECT_EQ(st.bits, chain::target_to_bits_upper_bound(MAX_TARGET));
    EXPECT_EQ(st.bits, st.max_bits);
    // resulting target never easier than MAX_TARGET.
    EXPECT_TRUE(!(chain::bits_to_target(st.bits) > MAX_TARGET));
}

TEST(DgbShareTargetGenesis, DesiredBelowFloorClampsToMaxOver30) {
    dgb::ShareTracker tracker;
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    const uint256 floor = MAX_TARGET / 30;
    // desired_target = 0 -> clipped up to MAX_TARGET/30 (data.py min clip).
    auto st = tracker.compute_share_target(uint256(), kTs, uint256());
    EXPECT_EQ(st.bits, chain::target_to_bits_upper_bound(floor));
}

TEST(DgbShareTargetGenesis, DesiredInRangePreserved) {
    dgb::ShareTracker tracker;
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    const uint256 mid = MAX_TARGET / 2;  // within (MAX_TARGET/30, MAX_TARGET)
    auto st = tracker.compute_share_target(uint256(), kTs, mid);
    EXPECT_EQ(st.bits, chain::target_to_bits_upper_bound(mid));
    // invariant: MAX_TARGET/30 <= resulting target <= MAX_TARGET.
    const uint256 tgt = chain::bits_to_target(st.bits);
    EXPECT_TRUE(!(tgt > MAX_TARGET));
    EXPECT_TRUE(!(tgt < (MAX_TARGET / 30)));
}

}  // namespace
