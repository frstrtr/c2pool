// SPDX-License-Identifier: AGPL-3.0-or-later
// D2 finder-fee integer-exactness KAT.
//
// Pins the mined-block coinbase block-finder fee split to the p2pool reference
// as INTEGER floor division, closing the latent satoshi-rounding divergence
// that the prior float path (coinbasevalue/200.0) carried onto the money path
// of a won block in src/impl/btc/stratum/work_source.cpp.
//
// Reference (jtoomim p2pool data.py generate_transaction, verified against
// ~/p2pool-jtoomim@ece15b0):
//     amounts = {script: subsidy*(199*w)//(200*W) ...}   # 99.5% by weight
//     amounts[finder]   += subsidy // 200                 # 0.5% finder fee, floor, unconditional
//     amounts[donation] += subsidy - sum(amounts)         # residual balances to subsidy
// p2pool's `subsidy` is the block-template coinbasevalue (subsidy + fees), so
// the c2pool base is coinbasevalue — matching src/core/web_server.cpp:1888.
//
// The consensus share gentx already matched this; D2 makes the block-coinbase
// path identical (integer floor, no float, unconditional application).

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>

#include <impl/btc/stratum/finder_fee.hpp>

using btc::stratum::v35_finder_fee_split;

namespace {

// The jtoomim reference operation: integer floor division, subsidy//200.
uint64_t reference_finder_fee(uint64_t coinbasevalue) { return coinbasevalue / 200; }

} // namespace

// When the donation residual covers the fee (the canonical case: donation
// ~0.5% >= finder fee ~0.5%), the moved amount equals the integer reference
// exactly — for both round and odd coinbase values.
TEST(BtcFinderFeeD2, MatchesJtoomimIntegerFormula) {
    const uint64_t big_donation = 1'000'000'000ULL;  // always covers the fee
    for (uint64_t cbv : {0ULL, 199ULL, 200ULL, 312'500'000ULL, 312'500'100ULL,
                         312'500'199ULL, 512'345'678ULL, 625'000'001ULL}) {
        EXPECT_EQ(v35_finder_fee_split(cbv, big_donation), reference_finder_fee(cbv))
            << "cbv=" << cbv;
    }
}

// Sub-200 coinbase -> floor(cbv/200)==0 -> finder gets nothing; no negative
// output, no phantom satoshi.
TEST(BtcFinderFeeD2, BelowThresholdIsZero) {
    EXPECT_EQ(v35_finder_fee_split(0ULL, 1000ULL), 0ULL);
    EXPECT_EQ(v35_finder_fee_split(199ULL, 1000ULL), 0ULL);
    EXPECT_EQ(v35_finder_fee_split(200ULL, 1000ULL), 1ULL);
}

// Donation cap: never move more than the donation holds, so the coinbase stays
// balanced (total == subsidy) and the donation output never goes negative.
TEST(BtcFinderFeeD2, CappedByDonation) {
    // Fee would be 1'562'500 but the donation only holds 1'000.
    EXPECT_EQ(v35_finder_fee_split(312'500'199ULL, 1'000ULL), 1'000ULL);
    // Exact-cover boundary and one satoshi short of it.
    EXPECT_EQ(v35_finder_fee_split(312'500'000ULL, 1'562'500ULL), 1'562'500ULL);
    EXPECT_EQ(v35_finder_fee_split(312'500'000ULL, 1'562'499ULL), 1'562'499ULL);
}

// Divergence witness: at odd coinbase values the OLD float path carried a
// fractional satoshi (coinbasevalue/200.0) onto the money path, and naive
// float-rounding disagreed with the integer floor by a full satoshi — exactly
// the divergence D2 closes.
TEST(BtcFinderFeeD2, FloatPathDivergesFromInteger) {
    const uint64_t cbv = 312'500'199ULL;
    const double   float_fee = static_cast<double>(cbv) / 200.0;   // 1562500.995
    // The old float fee carried a sub-satoshi fraction:
    EXPECT_NE(float_fee, std::trunc(float_fee));
    // Rounding that float disagrees with the integer floor by one satoshi:
    EXPECT_EQ(static_cast<uint64_t>(std::llround(float_fee)), 1'562'501ULL);
    EXPECT_EQ(v35_finder_fee_split(cbv, 1'000'000'000ULL), 1'562'500ULL);
    EXPECT_NE(static_cast<uint64_t>(std::llround(float_fee)),
              v35_finder_fee_split(cbv, 1'000'000'000ULL));
}
