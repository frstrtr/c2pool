// DASH S8 STRATUM-BINDING contract harness.
//
// The S8 get_work() arithmetic is authored as pure accessors and already
// KAT-pinned by test_dash_work_target (per-miner desired_share_target
// modulation, work.py:308-326) and test_dash_work_job_targets (the two
// job-target fields, work.py:411-426). What those KATs do NOT pin is the
// BINDING layer that sits between the assembled job targets and the stratum
// wire: how an assembled uint256 job target becomes the mining.set_difficulty
// value the miner actually receives.
//
// This harness pins that binding CONTRACT — the invariant the (future)
// DASHWorkSource must satisfy when it wires assemble_work_job_targets() output
// to a core::stratum session:
//
//   (1) DUMB_SCRYPT_DIFF multiplier — DASH is X11, a SHA256d-FAMILY net, so the
//       stratum difficulty multiplier is 1, NOT scrypt's 2**16. The shared
//       core::stratum::StratumConfig DEFAULTS to the scrypt convention (65536),
//       so a DASH work source MUST override set_difficulty_multiplier to 1.0.
//       ORACLE: frstrtr/p2pool-dash @9a0a609 networks/dash.py DUMB_SCRYPT_DIFF
//       (X11 nets = 1; scrypt LTC/DOGE = 65536).
//
//   (2) target -> wire difficulty — stratum_difficulty(target) =
//       target_to_difficulty(target) * multiplier, where diff-1 target is
//       0xFFFF * 2**208 (share difficulty-1, chain::target_to_difficulty).
//
//   (3) job binding round-trip — the min_share_target / share_target pair from
//       assemble_work_job_targets() binds to a (floor_diff, share_diff) pair
//       with floor_diff <= share_diff (the share floor is never HARDER than the
//       vardiff pseudoshare target), and clip-to-SANE is honoured at the target
//       (byte) level before the difficulty is ever computed.
//
// Every expected difficulty below is derived independently from the oracle
// integer relations (diff-1 = 0xFFFF*2**208, multiplier per net), NOT read back
// from the SUT — a true binding pin, not a tautology.
//
// PURITY: header-only accessors over core/target_utils; pure, socket-free,
// node-free. No VM200/201 dashd, no live sharechain, no io_context.

#include <gtest/gtest.h>

#include <impl/dash/stratum/work_job_targets.hpp>
#include <core/target_utils.hpp>
#include <core/stratum_types.hpp>
#include <core/uint256.hpp>

using namespace dash::stratum;

namespace {

uint256 U(const char* h) { uint256 t; t.SetHex(h); return t; }

// Oracle diff-1 (share) target = 0xFFFF * 2**208 == chain::target_to_difficulty
// max_target. share_target == this <=> stratum difficulty 1.0.
constexpr const char* D1_HEX =
    "00000000ffff0000000000000000000000000000000000000000000000000000";
// D1 >> 4  (== D1 / 16)  -> difficulty 16
constexpr const char* D1_DIV16_HEX =
    "000000000ffff000000000000000000000000000000000000000000000000000";
// D1 >> 8  (== D1 / 256) -> difficulty 256
constexpr const char* D1_DIV256_HEX =
    "0000000000ffff00000000000000000000000000000000000000000000000000";
// 2**256-1 (unconstrained target the modulation starts from)
constexpr const char* MAX_HEX =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

// Oracle SANE_TARGET_RANGE, dash mainnet (networks/dash.py:33):
//   min = (0xFFFF*2**208)//10000 ; max = 0xFFFF*2**208
constexpr const char* SMIN_HEX =
    "0000000000068db22d0e5604189374bc6a7ef9db22d0e5604189374bc6a7ef9d";
constexpr const char* SMAX_HEX = D1_HEX;  // easiest sane target == diff-1

// X11 net stratum multiplier (oracle DUMB_SCRYPT_DIFF for SHA256d-family nets).
constexpr double kDashStratumDiffMultiplier = 1.0;

// The binding under contract: assembled job target -> wire mining.set_difficulty.
double stratum_difficulty(const uint256& target, double multiplier)
{
    return chain::target_to_difficulty(target) * multiplier;
}

}  // namespace

// (1) The multiplier contract: the shared StratumConfig defaults to the scrypt
// convention; DASH (X11) must NOT inherit it — it binds at multiplier 1.0.
TEST(DashStratumBinding, X11MultiplierIsOneNotScrypt)
{
    core::stratum::StratumConfig cfg;  // shared defaults
    EXPECT_DOUBLE_EQ(cfg.set_difficulty_multiplier, 65536.0)   // scrypt default
        << "shared StratumConfig default changed; revisit DASH override";
    EXPECT_DOUBLE_EQ(kDashStratumDiffMultiplier, 1.0);
    // A DASH-configured session overrides to the X11 multiplier.
    core::stratum::StratumConfig dash_cfg;
    dash_cfg.set_difficulty_multiplier = kDashStratumDiffMultiplier;
    EXPECT_DOUBLE_EQ(dash_cfg.set_difficulty_multiplier, 1.0);
}

// (2) diff-1 target binds to wire difficulty 1.0; harder targets scale exactly.
TEST(DashStratumBinding, TargetToWireDifficultyExact)
{
    EXPECT_DOUBLE_EQ(stratum_difficulty(U(D1_HEX), kDashStratumDiffMultiplier), 1.0);
    EXPECT_DOUBLE_EQ(stratum_difficulty(U(D1_DIV16_HEX), kDashStratumDiffMultiplier), 16.0);
    EXPECT_DOUBLE_EQ(stratum_difficulty(U(D1_DIV256_HEX), kDashStratumDiffMultiplier), 256.0);
}

// (3a) No client vardiff + no measured rate: modulation returns the
// unconstrained MAX, clip-to-SANE pins the share_target at the easiest sane
// target (SMAX == diff-1), and the binding advertises difficulty 1.0.
TEST(DashStratumBinding, NoRateBindsToEasiestSane)
{
    WorkJobTargetInputs in;
    in.share_info_bits_target   = U(SMAX_HEX);
    in.sane_target_min          = U(SMIN_HEX);
    in.sane_target_max          = U(SMAX_HEX);
    in.have_desired_pseudoshare = false;
    in.local_hash_rate          = 0.0;

    WorkJobTargets jt = assemble_work_job_targets(in);
    EXPECT_EQ(jt.share_target.GetHex(), U(SMAX_HEX).GetHex());     // byte-level clip
    EXPECT_EQ(jt.min_share_target.GetHex(), U(SMAX_HEX).GetHex());
    EXPECT_DOUBLE_EQ(stratum_difficulty(jt.share_target, kDashStratumDiffMultiplier), 1.0);
    EXPECT_DOUBLE_EQ(stratum_difficulty(jt.min_share_target, kDashStratumDiffMultiplier), 1.0);
}

// (3b) Client-supplied vardiff target within SANE range binds through
// unchanged; the min_share floor (bits target) is never HARDER than the
// pseudoshare target -> floor_diff <= share_diff.
TEST(DashStratumBinding, ClientVardiffBindsFloorNoHarderThanShare)
{
    WorkJobTargetInputs in;
    in.share_info_bits_target       = U(D1_DIV16_HEX);   // share floor -> diff 16
    in.sane_target_min              = U(SMIN_HEX);
    in.sane_target_max              = U(SMAX_HEX);
    in.have_desired_pseudoshare     = true;
    in.desired_pseudoshare_target   = U(D1_DIV256_HEX);  // vardiff -> diff 256

    WorkJobTargets jt = assemble_work_job_targets(in);
    EXPECT_EQ(jt.share_target.GetHex(), U(D1_DIV256_HEX).GetHex());
    EXPECT_EQ(jt.min_share_target.GetHex(), U(D1_DIV16_HEX).GetHex());

    double floor_diff = stratum_difficulty(jt.min_share_target, kDashStratumDiffMultiplier);
    double share_diff = stratum_difficulty(jt.share_target, kDashStratumDiffMultiplier);
    EXPECT_DOUBLE_EQ(floor_diff, 16.0);
    EXPECT_DOUBLE_EQ(share_diff, 256.0);
    EXPECT_LE(floor_diff, share_diff);   // share floor never harder than vardiff
}

// (3c) A client vardiff target HARDER than sane_min clips UP to sane_min at the
// byte level before binding; the advertised difficulty tracks the clamp (the
// hardest the pool will hand out), ~10000 for dash mainnet SANE_TARGET_RANGE.
TEST(DashStratumBinding, OverHardVardiffClipsToSaneMinThenBinds)
{
    WorkJobTargetInputs in;
    in.share_info_bits_target     = U(SMAX_HEX);
    in.sane_target_min            = U(SMIN_HEX);
    in.sane_target_max            = U(SMAX_HEX);
    in.have_desired_pseudoshare   = true;
    // 0xFFFF * 2**188 == D1 >> 20: far harder than sane_min -> clips up to SMIN.
    in.desired_pseudoshare_target =
        U("0000000000000ffff00000000000000000000000000000000000000000000000");

    WorkJobTargets jt = assemble_work_job_targets(in);
    EXPECT_EQ(jt.share_target.GetHex(), U(SMIN_HEX).GetHex());  // byte-level clip UP
    double d = stratum_difficulty(jt.share_target, kDashStratumDiffMultiplier);
    EXPECT_NEAR(d, 10000.0, 1.0);   // sane_min == diff-1 // 10000
}
