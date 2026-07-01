// dgb::ShareTracker::compute_share_target — NON-genesis (seeded sharechain)
// branch KAT: Step-3 emergency time-based decay + Step-4 ±10% clamp.
//
// FENCED conformance test (no production code touched). The genesis/unknown-prev
// branch is already pinned by share_target_genesis_test.cpp; the deep-chain
// retarget path (acc_height >= TARGET_LOOKBEHIND) had NO direct coverage. This
// slice closes that gap and is the consensus-bearing half of compute_share_target.
//
// NON-CIRCULAR: every golden below is derived from an INDEPENDENT Python
// reference of the oracle formula (a throwaway script that re-implements
// target_utils.hpp bits_to_target / target_to_bits_upper_bound and the
// share_tracker.hpp Step-3/Step-4 arithmetic in big-ints), then transcribed as a
// literal. The test does NOT recompute any golden by calling compute_share_target
// or chain:: encoders on a SUT-derived intermediate — it asserts the SUT output
// equals the pre-computed oracle literal.
//
// Oracle SSOT: frstrtr/p2pool-dgb-scrypt bitcoin/data.py generate_transaction
// (pre_target derive -> emergency decay -> ±10% clamp) with MAX_TARGET from
// networks/digibyte.py = 2**256//2**20 - 1 (2^236 - 1); SHARE_PERIOD=15 =>
// emergency_threshold = 300s, half_life = 150s.
//
// DETERMINISM: the seeded chain uses HUGE inter-share timestamp gaps so the
// pool-attempts-per-second estimate drives pre_target to MAX_TARGET; the ±10%
// clamp then pins pre_target to the `hi` boundary, making max_bits depend ONLY
// on clamp_ref (the quantity under test) and not on the exact APS magnitude.
// desired_timestamp is measured against the TIP share's timestamp and controls
// ONLY the decay, independent of the gaps used for APS.
//
// CAVEAT (documented, not pinned): the SUT's Step-3 `eased` is a uint256, so
// `prev_max_target << halvings` silently WRAPS once the result reaches 2^256
// (here halvings >= 25 for the chosen prev_max_bits). An ideal big-int oracle
// saturates instead. This KAT deliberately exercises the saturation guard at the
// FIRST crossing (halvings=5, C4) where the SUT and a faithful big-int agree; it
// does NOT assert the extreme-decay (halvings>=25) regime, which is a known
// SUT/oracle divergence surfaced separately.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/config_pool.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <string>

namespace {

// prev (tip) share max_bits used for every case: target_to_bits_upper_bound of
// MAX_TARGET/30 (= 0x1e008888). bits_to_target(0x1e008888) = M, the clamp_ref
// base the decay scales. Oracle-verified: M*11//10 < MAX_TARGET, so the un-
// decayed and one/interp-decayed `hi` bounds all stay below MAX_TARGET (i.e.
// they exercise a real clamp, not the saturation guard) — except C4 by design.
constexpr uint32_t kPrevMaxBits = 0x1e008888u;

// TIP share timestamp. desired_timestamp is offset from THIS value to control
// the emergency decay (Step 3). The inter-share gaps below are a separate axis.
constexpr uint32_t kTipTs = 2000000000u;

// Build a hex string for a 64-hex-char (uint256) hash from a small index, so the
// 101 seeded shares get distinct, deterministic hashes.
std::string hash_hex(uint32_t i) {
    char buf[65];
    // zero-padded 64-hex; put the index in the low bytes.
    std::snprintf(buf, sizeof(buf),
        "%040x%024x", 0u, i);
    return std::string(buf);
}

// Seed a linked chain of `count` shares (genesis at index 0). Each share's
// timestamp is base_ts + i*gap (so the APS window timespan = 99*gap). All shares
// carry m_max_bits = kPrevMaxBits; the TIP (last) share's timestamp is forced to
// kTipTs so desired_timestamp deltas are well-defined regardless of `gap`.
// Returns the tip hash. acc_height after seeding `count` shares is count-1.
uint256 seed_chain(dgb::ShareTracker& tracker, uint32_t count, uint32_t gap) {
    uint256 prev;  // null for genesis
    uint256 tip;
    for (uint32_t i = 0; i < count; ++i) {
        auto* s = new dgb::MergedMiningShare();
        s->m_hash.SetHex(hash_hex(i + 1));  // +1 so index 0 isn't the null hash
        if (i == 0) s->m_prev_hash.SetNull();
        else        s->m_prev_hash = prev;
        s->m_bits = kPrevMaxBits;
        s->m_max_bits = kPrevMaxBits;
        // huge gaps -> tiny APS -> pre_target saturates to MAX_TARGET.
        s->m_timestamp = kTipTs - (count - 1 - i) * gap;
        dgb::ShareType st; st = s;
        tracker.add(st);
        prev = s->m_hash;
        tip = s->m_hash;
    }
    return tip;
}

// Seed 101 shares (acc_height = 100 = TARGET_LOOKBEHIND) so the non-genesis,
// deep-enough retarget branch is taken.
constexpr uint32_t kCount = 101u;
// HUGE gap so APS ~ 0 -> pre_target = MAX_TARGET -> ±10% clamp pins to `hi`.
constexpr uint32_t kHiGap = 1000000u;

// Assert the seeded chain actually reached the deep (non-genesis) branch: a
// genesis-branch call (null prev) would return max_bits = tubu(MAX_TARGET) =
// 0x1e0fffff; the seeded hi-clamp cases below return a strictly different,
// clamp-derived max_bits, proving the deep path was exercised.
void expect_deep_branch_distinct(uint32_t got_max_bits) {
    EXPECT_NE(got_max_bits, 0x1e0fffffu)
        << "got the genesis/MAX_TARGET max_bits — deep branch was NOT exercised";
}

// ─── C1: no decay (t <= 300), hi clamp ──────────────────────────────────────
// t=100 <= emergency_threshold => clamp_ref = M => hi = M*11//10.
// Oracle: max_bits = target_to_bits_upper_bound(M*11//10) = 0x1e00962f.
TEST(DgbShareTargetRetarget, C1_NoDecayHiClamp) {
    dgb::ShareTracker tracker;
    auto tip = seed_chain(tracker, kCount, kHiGap);
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(tip, kTipTs + 100u, MAX_TARGET);
    EXPECT_EQ(st.max_bits, 0x1e00962fu);
    // desired_target = MAX_TARGET -> clipped down to pre_target3 -> bits==max_bits.
    EXPECT_EQ(st.bits, 0x1e00962fu);
    expect_deep_branch_distinct(st.max_bits);
}

// ─── C2: one halving, no remainder ──────────────────────────────────────────
// t=450 => excess=150, halvings=1, rem=0 => clamp_ref = 2M => hi = 2M*11//10.
// Oracle: max_bits = 0x1e012c5e.
TEST(DgbShareTargetRetarget, C2_DecayOneHalvingNoRemainder) {
    dgb::ShareTracker tracker;
    auto tip = seed_chain(tracker, kCount, kHiGap);
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(tip, kTipTs + 450u, MAX_TARGET);
    EXPECT_EQ(st.max_bits, 0x1e012c5eu);
    EXPECT_EQ(st.bits, 0x1e012c5eu);
    expect_deep_branch_distinct(st.max_bits);
}

// ─── C3: linear interpolation of the fractional halving ─────────────────────
// t=525 => excess=225, halvings=1, rem=75 => clamp_ref = 2M*(150+75)//150 = 3M
// => hi = 3M*11//10. Oracle: max_bits = 0x1e01c28d.
TEST(DgbShareTargetRetarget, C3_DecayInterpolation) {
    dgb::ShareTracker tracker;
    auto tip = seed_chain(tracker, kCount, kHiGap);
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(tip, kTipTs + 525u, MAX_TARGET);
    EXPECT_EQ(st.max_bits, 0x1e01c28du);
    EXPECT_EQ(st.bits, 0x1e01c28du);
    expect_deep_branch_distinct(st.max_bits);
}

// ─── C4: decay saturates clamp_ref to MAX_TARGET ────────────────────────────
// t = 300 + 150*5 = 1050 => excess=750, halvings=5, rem=0 => eased = M << 5,
// which exceeds MAX_TARGET => clamp_ref = MAX_TARGET => hi = MAX_TARGET =>
// max_bits = tubu(MAX_TARGET) = 0x1e0fffff. halvings=5 is the FIRST shift that
// crosses MAX_TARGET; it is also well within uint256, so this case pins the
// saturation guard WITHOUT relying on the eased<<halvings overflow regime (see
// the file-level caveat: the SUT shift is a uint256, so prev_max_target<<halvings
// silently wraps once it reaches 2^256, i.e. halvings>=25 for this M — that
// extreme-decay regime is a known SUT/oracle divergence and is NOT pinned here).
// (deep-branch-distinct sanity intentionally skipped: the SATURATED clamp_ref
//  legitimately equals the genesis max_bits — the point of the case; path
//  coverage is proven by C1–C3 + C5.)
TEST(DgbShareTargetRetarget, C4_DecaySaturatesToMax) {
    dgb::ShareTracker tracker;
    auto tip = seed_chain(tracker, kCount, kHiGap);
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(tip, kTipTs + 1050u, MAX_TARGET);
    EXPECT_EQ(st.max_bits, 0x1e0fffffu);
    EXPECT_EQ(st.bits, 0x1e0fffffu);
}

// ─── C5: lo clamp (high APS drives pre_target below the lower bound) ─────────
// Small inter-share gaps (1s) => high APS => pre_target collapses far below
// clamp_ref*9//10; with t<=300 (no decay) clamp_ref = M so lo = M*9//10 and
// pre_target2 is pinned UP to lo. Oracle: max_bits = tubu(M*9//10) = 0x1d7ae0cc.
TEST(DgbShareTargetRetarget, C5_LoClamp) {
    dgb::ShareTracker tracker;
    auto tip = seed_chain(tracker, kCount, /*gap=*/1u);
    const uint256 MAX_TARGET = dgb::PoolConfig::max_target();
    auto st = tracker.compute_share_target(tip, kTipTs + 100u, MAX_TARGET);
    EXPECT_EQ(st.max_bits, 0x1d7ae0ccu);
    expect_deep_branch_distinct(st.max_bits);
}

}  // namespace
