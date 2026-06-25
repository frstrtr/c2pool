// dgb redistribute -> get_height_and_last SSOT byte-identity DELEGATION KAT.
//
// FENCED, additive. Pins the runtime rewire of redistribute.hpp:454-455
// (refresh_pplns_cache PPLNS-window guard) onto the SSOT free functions in
// coin/get_height_and_last_endpoints.hpp. The SSOT itself is proven against the
// p2pool-dgb-scrypt oracle by dgb_get_height_and_last_endpoints_test; this slice
// proves only that swapping the inline expression for the SSOT call changed
// NOTHING -- i.e. the rewire is value-identical, no reward-distribution drift.
//
// PRE-delegation inline (verbatim, from git history of redistribute.hpp):
//     int32_t depth = std::min(height, static_cast<int32_t>(real_chain_length()));
//     if (depth < 1) return;          // early-out: window inactive
// POST-delegation (current redistribute.hpp:454-455):
//     int32_t depth = dgb::pplns_window_depth(height, real_chain_length());
//     if (!dgb::pplns_window_active(depth)) return;
//
// NON-CIRCULAR: the "expected" side below recomputes std::min(...)/(depth < 1)
// directly from the operands -- it does NOT call the SSOT under test. We then
// assert the SSOT call reproduces that inline result across a height matrix that
// straddles every boundary (negative, 0, 1, REAL_CHAIN_LENGTH-1/=/+1).
// MUST appear in BOTH this dir CMakeLists.txt AND the build.yml --target
// allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/coin/get_height_and_last_endpoints.hpp>

#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>

using namespace dgb;

static constexpr int32_t CL_MAIN = 2880;  // REAL_CHAIN_LENGTH mainnet
static constexpr int32_t CL_TEST = 400;   // REAL_CHAIN_LENGTH testnet

// The verbatim pre-delegation inline expression, re-implemented here so the
// expectation is independent of the code under test.
static int32_t inline_depth(int32_t height, int32_t rcl) {
    return std::min(height, static_cast<int32_t>(rcl));
}
static bool inline_early_return(int32_t depth) {
    return depth < 1;
}

static void check_one(int32_t height, int32_t rcl) {
    const int32_t want_depth = inline_depth(height, rcl);
    const bool    want_ret   = inline_early_return(want_depth);

    const int32_t got_depth = pplns_window_depth(height, rcl);
    const bool    got_ret   = !pplns_window_active(got_depth);

    EXPECT_EQ(got_depth, want_depth)
        << "depth diverged at height=" << height << " rcl=" << rcl;
    EXPECT_EQ(got_ret, want_ret)
        << "early-return diverged at height=" << height << " rcl=" << rcl;
}

TEST(DgbRedistributeDelegateGhal, DepthMatchesInlineMainnet) {
    for (int32_t h : {-5, -1, 0, 1, 2, 10, 1440, CL_MAIN - 1, CL_MAIN, CL_MAIN + 1, 100000})
        check_one(h, CL_MAIN);
}

TEST(DgbRedistributeDelegateGhal, DepthMatchesInlineTestnet) {
    for (int32_t h : {-5, -1, 0, 1, 2, 10, 200, CL_TEST - 1, CL_TEST, CL_TEST + 1, 100000})
        check_one(h, CL_TEST);
}

// Boundary spot-checks pinned to absolute values (no SSOT call on the expected
// side) -- the window is INACTIVE iff clamped depth < 1, ACTIVE from height 1 up.
TEST(DgbRedistributeDelegateGhal, ActivationBoundaryAbsolute) {
    EXPECT_TRUE (!pplns_window_active(pplns_window_depth(0, CL_MAIN)));  // depth 0 -> inactive
    EXPECT_FALSE(!pplns_window_active(pplns_window_depth(1, CL_MAIN)));  // depth 1 -> active
    EXPECT_FALSE(!pplns_window_active(pplns_window_depth(CL_MAIN, CL_MAIN))); // clamped, active
    EXPECT_TRUE (!pplns_window_active(pplns_window_depth(-3, CL_MAIN))); // negative -> inactive
    EXPECT_EQ(pplns_window_depth(CL_MAIN + 50, CL_MAIN), CL_MAIN);       // clamp to RCL
}
