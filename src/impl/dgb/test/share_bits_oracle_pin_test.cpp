// dgb sharechain `bits` (compact FloatingInteger) encoding — oracle-LITERAL pin.
//
// FENCED conformance KAT (Phase B, pool/share layer; no production code touched).
//
// Pins the DGB sharechain share-difficulty `bits` field against LITERAL goldens
// produced by the oracle's own reference encoder — frstrtr/p2pool-dgb-scrypt
// bitcoin/data.py FloatingInteger.from_target_upper_bound (data.py:64-70):
//
//     n = math.natural_to_string(target)            # big-endian, minimal, no
//                                                   # leading zero byte
//     if n and ord(n[0]) >= 128: n = '\x00' + n     # sign-pad high bit
//     bits2 = (chr(len(n)) + (n + 3*chr(0))[:3])[::-1]
//     bits  = pack.IntType(32).unpack(bits2)        # => (len(n)<<24)|mant24
//
// This is the encoder the oracle applies at data.py:169-170 to set BOTH
// share_info['max_bits'] (= from_target_upper_bound(pre_target3)) and the
// per-share difficulty `bits` (= from_target_upper_bound(clip(desired_target,
// (pre_target3//30, pre_target3)))). It is the on-wire encoding of sharechain
// difficulty, so byte-drift here desyncs the whole pool/share layer from the
// oracle network.
//
// WHY a separate slice from dgb_share_target_genesis_test: that KAT asserts
// compute_share_target() == chain::target_to_bits_upper_bound(<same target>),
// i.e. SUT-vs-SUT (self-consistent but circular w.r.t. the oracle). This KAT
// pins the ABSOLUTE compact value at each canonical retarget anchor against the
// oracle reference encoder, removing the circularity: if both the SUT encoder
// and compute_share_target() drifted in lockstep, the genesis KAT would still
// pass but THESE literals would fail.
//
// Goldens (independently computed from the oracle algorithm above; MAX_TARGET =
// 2**256//2**20 - 1 = 2^236 - 1 per networks/digibyte.py):
//   target = MAX_TARGET      (2^236-1) -> bits = 0x1e0fffff
//   target = MAX_TARGET / 30  (floor)  -> bits = 0x1e008888
//   target = MAX_TARGET / 2            -> bits = 0x1e07ffff
//   target = 0 (MIN_TARGET)            -> bits = 0x00000000
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel.

#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/config_pool.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

namespace {

// Oracle-LITERAL goldens — see header block. Computed from
// FloatingInteger.from_target_upper_bound, NOT from the SUT encoder.
constexpr uint32_t ORACLE_BITS_MAX_TARGET   = 0x1e0fffffu;  // 2^236 - 1
constexpr uint32_t ORACLE_BITS_MAX_OVER_30  = 0x1e008888u;  // genesis bits floor
constexpr uint32_t ORACLE_BITS_MAX_OVER_2   = 0x1e07ffffu;  // mid-range
constexpr uint32_t ORACLE_BITS_MIN_TARGET   = 0x00000000u;  // MIN_TARGET = 0

// The genesis branch ignores desired_timestamp; any fixed value is fine.
constexpr uint32_t kTs = 1700000000u;

uint256 all_ones() {
    uint256 t;
    t.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return t;
}

// ---- Layer 1: the standalone compact encoder vs oracle literals -------------

TEST(DgbShareBitsOraclePin, MaxTargetEncodesTo1e0fffff) {
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    EXPECT_EQ(chain::target_to_bits_upper_bound(MAX_TARGET), ORACLE_BITS_MAX_TARGET);
}

TEST(DgbShareBitsOraclePin, MaxOver30EncodesTo1e008888) {
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    EXPECT_EQ(chain::target_to_bits_upper_bound(MAX_TARGET / 30), ORACLE_BITS_MAX_OVER_30);
}

TEST(DgbShareBitsOraclePin, MaxOver2EncodesTo1e07ffff) {
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    EXPECT_EQ(chain::target_to_bits_upper_bound(MAX_TARGET / 2), ORACLE_BITS_MAX_OVER_2);
}

TEST(DgbShareBitsOraclePin, MinTargetEncodesToZero) {
    EXPECT_EQ(chain::target_to_bits_upper_bound(uint256()), ORACLE_BITS_MIN_TARGET);
}

// ---- Layer 2: compute_share_target genesis ladder emits the oracle literals --
// Pins that the genesis retarget path (previous_share unknown -> pre_target3 =
// MAX_TARGET, then bits = from_target_upper_bound(clip(desired, MAX/30..MAX)))
// produces the ABSOLUTE oracle-literal compact bits, not merely a SUT-consistent
// value. This is what the on-wire share carries.

TEST(DgbShareBitsOraclePin, GenesisMaxBitsAreOracleLiteral) {
    dgb::ShareTracker tracker;
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(uint256(), kTs, MAX_TARGET);
    EXPECT_EQ(st.max_bits, ORACLE_BITS_MAX_TARGET);
}

TEST(DgbShareBitsOraclePin, GenesisDesiredAboveMaxClampsToOracleMaxBits) {
    dgb::ShareTracker tracker;
    auto st = tracker.compute_share_target(uint256(), kTs, all_ones());
    EXPECT_EQ(st.bits, ORACLE_BITS_MAX_TARGET);
    EXPECT_EQ(st.bits, st.max_bits);
}

TEST(DgbShareBitsOraclePin, GenesisDesiredBelowFloorClampsToOracleMaxOver30) {
    dgb::ShareTracker tracker;
    // desired_target = 0 -> clipped up to MAX_TARGET/30 (data.py min clip).
    auto st = tracker.compute_share_target(uint256(), kTs, uint256());
    EXPECT_EQ(st.bits, ORACLE_BITS_MAX_OVER_30);
}

TEST(DgbShareBitsOraclePin, GenesisDesiredInRangeEncodesToOracleMaxOver2) {
    dgb::ShareTracker tracker;
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(uint256(), kTs, MAX_TARGET / 2);
    EXPECT_EQ(st.bits, ORACLE_BITS_MAX_OVER_2);
}

}  // namespace
