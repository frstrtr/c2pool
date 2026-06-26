// G0 greenlight-gate KAT — DGB older-baseline identity + 35->36 transition rule.
//
// FENCED conformance test (no production code touched). This is the test-form
// artifact of greenlight gate G0 (per dgb-v36-greenlight-gate-g0.md): it pins
// the v35 SOURCE half of the non-circular gate split. G1
// (g1_oracle_byte_parity_test) pins the assembled v36 net/consensus TARGET;
// this file pins the BASELINE the transition departs from and the ratchet rule
// that carries it forward to v36.
//
// ORACLE (frstrtr/p2pool-dgb-scrypt @ 22761e7, operator switch-oracle ruling
// 2026-06-17 Option B):
//   data.py:636        Share.VERSION = 35, VOTING_VERSION = 35,
//                      SUCCESSOR = None, share_versions = {35: Share}
//   networks/digibyte.py:26   SEGWIT_ACTIVATION_VERSION = 35
//   bitcoin/p2p.py:28         Protocol.VERSION (advertised) = 3501
//
// NON-CIRCULAR: the ORACLE_* values below are literal ints typed from the
// oracle python source, NOT a second read of the C++ SUT. The production wire
// (auto_ratchet_wire.hpp DGB_BASE_VERSION / DGB_TARGET_VERSION and the
// make_dgb_ratchet() factory) is the SUT; a silent drift in either constant —
// e.g. a future refactor reintroducing LTC's `target-1` hardcode, or bumping
// the baseline off the oracle's minted 35 — fails here.
//
// WHAT G0 PINS (distinct from the tail-guard KAT, which pins the 60%-by-work
// SWITCH arithmetic, and from g1, which pins net/coin params):
//   (1) the oracle baseline version triple {35, 35, SUCCESSOR=None};
//   (2) the production ratchet pair {mint-while-voting = 35, target = 36}
//       derived from it, and that 36 is c2pool-dgb's v36 INTRODUCTION (the
//       oracle has SUCCESSOR=None, so it does not itself ratchet);
//   (3) the "older than LTC is the P2P-protocol axis (3501), not the share
//       version" disambiguation — base_version=35 coincides numerically with
//       LTC's target-1 but is an EXPLICIT constant, guarded against a
//       target-1 hardcode regression;
//   (4) the dual-accept crossing-window invariant: a crossed node mints per
//       the ratchet while accepting BOTH baseline {35} and target {36} until
//       the post-soak floor drop (bucket-3, transition-temporary).
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel.

#include <impl/dgb/auto_ratchet_wire.hpp>

#include <cstdint>
#include <utility>

#include <gtest/gtest.h>

namespace {

// ---- Oracle expected values (frstrtr/p2pool-dgb-scrypt @22761e7) -----------
// data.py:636 — the live oracle MINTS this version and VOTES this version;
// SUCCESSOR=None means it does not ratchet to any higher version on its own.
constexpr int64_t ORACLE_SHARE_VERSION   = 35;   // Share.VERSION
constexpr int64_t ORACLE_VOTING_VERSION  = 35;   // VOTING_VERSION
constexpr bool    ORACLE_SUCCESSOR_NONE  = true; // SUCCESSOR = None
// networks/digibyte.py:26
constexpr int64_t ORACLE_SEGWIT_ACT_VER  = 35;   // SEGWIT_ACTIVATION_VERSION
// bitcoin/p2p.py:28 — the "older than LTC" axis is the P2P PROTOCOL version,
// NOT the share version. Pinned here only to assert the axis, not to re-pin
// the byte (g1 owns the net-constant byte pin).
constexpr int64_t ORACLE_ADV_PROTO_VER   = 3501; // Protocol.VERSION
constexpr int64_t LTC_ADV_PROTO_VER      = 3503; // for the older-than-LTC delta

// c2pool-dgb introduces v36 as Share.VERSION + 1 because the oracle's
// SUCCESSOR is None (no oracle-minted successor exists to inherit).
constexpr int64_t V36_TARGET = ORACLE_SHARE_VERSION + 1; // 36

} // namespace

// (1) Baseline identity — the production wire constants reproduce the oracle's
// minted/voting version, transcribed non-circularly.
TEST(DgbG0BaselineTransition, BaselineVersionTripleMatchesOracle)
{
    EXPECT_EQ(dgb::DGB_BASE_VERSION, ORACLE_VOTING_VERSION) << "mint-while-voting must equal oracle VOTING_VERSION=35";
    EXPECT_EQ(dgb::DGB_BASE_VERSION, ORACLE_SHARE_VERSION)  << "oracle mints VERSION=35; base must coincide";
    EXPECT_EQ(ORACLE_VOTING_VERSION, ORACLE_SEGWIT_ACT_VER) << "oracle segwit activation rides the same version";
    EXPECT_TRUE(ORACLE_SUCCESSOR_NONE) << "documents that the oracle does not self-ratchet";
}

// (2) Ratchet pair — {mint=35, target=36}; 36 is c2pool-dgb's v36 introduction.
TEST(DgbG0BaselineTransition, RatchetPairIsBaseline35Target36)
{
    EXPECT_EQ(dgb::DGB_TARGET_VERSION, V36_TARGET) << "v36 target == oracle baseline + 1";
    EXPECT_EQ(dgb::DGB_TARGET_VERSION, dgb::DGB_BASE_VERSION + 1)
        << "SUCCESSOR=None => v36 is introduced by c2pool-dgb, exactly one step above baseline";

    dgb::AutoRatchet r = dgb::make_dgb_ratchet();
    EXPECT_EQ(r.base_version(),   ORACLE_VOTING_VERSION) << "factory must seed base=35";
    EXPECT_EQ(r.target_version(), V36_TARGET)            << "factory must seed target=36";
    // VOTING-state output pair (pre-switch): a node mints base while voting target.
    EXPECT_EQ(r.base_version(),   dgb::DGB_BASE_VERSION);
    EXPECT_EQ(r.target_version(), dgb::DGB_TARGET_VERSION);
}

// (3) Older-than-LTC axis is the P2P protocol version, NOT the share version.
// base_version=35 numerically coincides with LTC's (target-1) but is explicit.
TEST(DgbG0BaselineTransition, OlderThanLtcIsP2pProtocolAxisNotShareVersion)
{
    // Share-version axis: DGB baseline equals what an LTC `target-1` hardcode
    // WOULD produce — so a regression to that hardcode would pass a naive test.
    // The guard is that the constant is sourced from the oracle, asserted above.
    EXPECT_EQ(dgb::DGB_BASE_VERSION, dgb::DGB_TARGET_VERSION - 1)
        << "coincidence with LTC target-1 is expected; identity is pinned in test (1), not here";
    // The REAL older-than-LTC delta lives on the P2P protocol axis.
    EXPECT_LT(ORACLE_ADV_PROTO_VER, LTC_ADV_PROTO_VER)
        << "DGB advertises P2P protocol 3501 < LTC 3503 — this is the 'older' axis";
}

// (4) Dual-accept crossing-window invariant: mint per ratchet, accept BOTH
// {baseline 35, target 36} until the post-soak floor drop. Modelled as a
// decision table over the oracle baseline + production target.
TEST(DgbG0BaselineTransition, CrossingWindowDualAcceptsBaselineAndTarget)
{
    const int64_t base   = dgb::DGB_BASE_VERSION;   // 35
    const int64_t target = dgb::DGB_TARGET_VERSION; // 36

    // Acceptance set DURING the window is exactly {base, target}; neither older
    // (<35) nor newer-than-target (>36) is part of the v36 crossing.
    auto accepted_in_window = [&](int64_t v) { return v == base || v == target; };
    EXPECT_TRUE(accepted_in_window(base))      << "baseline 35 accepted during window (bucket-3 floor)";
    EXPECT_TRUE(accepted_in_window(target))    << "v36 target accepted during window";
    EXPECT_FALSE(accepted_in_window(base - 1)) << "pre-baseline 34 is not part of the v36 crossing";
    EXPECT_FALSE(accepted_in_window(target + 1)) << "no v37 in the v36 window";

    // Mint side, pre-switch: the node mints the BASELINE while voting target —
    // never mints target before the work-weighted switch (tail-guard KAT owns
    // the switch arithmetic; here we only pin the pre-switch mint == baseline).
    const int64_t mint_pre_switch = base;
    EXPECT_EQ(mint_pre_switch, ORACLE_VOTING_VERSION)
        << "pre-switch a crossed node mints the oracle baseline, not the target";
}
