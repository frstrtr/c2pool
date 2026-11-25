// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The one-BLS-mode guard (vendor/bls_mode_guard.hpp) detects a mixed binary.
// This translation unit is compiled with C2POOL_DASH_BLS forced on (test/
// CMakeLists.txt, set_source_files_properties) while the rest of its target
// (test_dash_work_source, which does not link dash_bls_verify) is not: the
// binary is mixed on purpose, and the guard must say so. It includes nothing
// but the guard, so no other definition differs between the two modes here.

#include <impl/dash/coin/vendor/bls_mode_guard.hpp>

#include <gtest/gtest.h>

#ifndef C2POOL_DASH_BLS
#error "test_dash_bls_mode_probe.cpp must be compiled with C2POOL_DASH_BLS (see test/CMakeLists.txt)"
#endif

TEST(DashBlsModeGuard, AMixedBinaryIsDetected)
{
    using namespace dash::coin::vendor;
    EXPECT_TRUE(bls_mode_mixed()) << "modes seen: " << bls_modes();
    EXPECT_EQ(bls_modes(), kBlsModeStub | kBlsModeBackend);
}
