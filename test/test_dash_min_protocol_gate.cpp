// KAT for the DASH min-protocol-version ratchet gate (#643, option a).
//
// Pins the two invariants integrator required for the SAFE-ADDITIVE leaf:
//   1. NO-OP AT DEFAULT: a default-constructed gate carries the oracle floor
//      (1700) and MUST admit a peer at protocol=1700. Nobody may later read the
//      landed leaf as an already-live ratchet.
//   2. PARAMETERIZED, NOT BAKED: the floor is a per-instance member, so raising
//      it rejects below-floor peers -- proving the ratchet MECHANISM works while
//      the default stays inert.

#include <gtest/gtest.h>

#include "impl/dash/config_pool.hpp"
#include "impl/dash/min_protocol_gate.hpp"

using dash::MinProtocolGate;
using dash::SharechainConfig;

// (1) Default gate == oracle accept-all floor, and it is a genuine no-op there.
TEST(DashMinProtocolGate, DefaultFloorIsOracleAcceptAll)
{
    MinProtocolGate gate;
    EXPECT_EQ(gate.min_version, SharechainConfig::MINIMUM_PROTOCOL_VERSION);
    EXPECT_EQ(gate.min_version, 1700u);

    // A peer AT the floor MUST be accepted -- this is the no-op assertion.
    EXPECT_TRUE(gate.accepts(1700u));
    EXPECT_FALSE(gate.rejects(1700u));

    // Real DASH peers advertise >= 1700, so the default admits every one.
    EXPECT_TRUE(gate.accepts(1700u));
    EXPECT_TRUE(gate.accepts(1800u));
    EXPECT_TRUE(gate.accepts(70210u));
}

// (2) Below the default floor is rejected -- boundary is >=, not >.
TEST(DashMinProtocolGate, BelowDefaultFloorRejected)
{
    MinProtocolGate gate;
    EXPECT_FALSE(gate.accepts(1699u));
    EXPECT_TRUE(gate.rejects(1699u));
    EXPECT_FALSE(gate.accepts(0u));
    // Exact boundary: floor-1 out, floor in.
    EXPECT_FALSE(gate.accepts(gate.min_version - 1));
    EXPECT_TRUE(gate.accepts(gate.min_version));
}

// (3) The floor is a settable per-instance member -- the ratchet mechanism.
//     Raising it to a hypothetical v36 value rejects the old-floor peer, but
//     this is a per-instance choice, NOT a committed constant.
TEST(DashMinProtocolGate, RatchetIsParameterizedNotBaked)
{
    // Operator knob: raise the floor at G2-migration time.
    MinProtocolGate ratcheted(1800u);
    EXPECT_EQ(ratcheted.min_version, 1800u);
    EXPECT_FALSE(ratcheted.accepts(1700u));   // old-floor peer now rejected
    EXPECT_TRUE(ratcheted.accepts(1800u));    // at-new-floor peer admitted

    // The default gate is UNAFFECTED -- proving the ratchet is per-instance and
    // the leaf commits no premature v36 constant.
    MinProtocolGate defaulted;
    EXPECT_TRUE(defaulted.accepts(1700u));
    EXPECT_EQ(defaulted.min_version, 1700u);
}
