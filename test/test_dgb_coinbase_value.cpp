// SPDX-License-Identifier: AGPL-3.0-or-later
// Forward-only TODO (integrator 2026-06-18): wire CoinParams::subsidy_func into
// the embedded coinbase builder + a 4-era boundary conformance test, with the
// external-daemon GBT fallback preserved.
//
// This guards src/impl/dgb/coin/embedded_coinbase_value.hpp — the SSOT that
// feeds subsidy_func(height)+fees to the embedded TemplateBuilder coinbasevalue
// (Stage 4c, work_source.cpp) and that takes a live digibyted GBT coinbasevalue
// verbatim whenever present (the external-daemon fallback that MUST PERSIST).
//
// The subsidy values themselves are byte-exact vs the p2pool-dgb-scrypt oracle
// (see test_dgb_subsidy.cpp). This test proves the *wiring*: that the embedded
// coinbasevalue is derived THROUGH the CoinParams::subsidy_func indirection
// (which params.hpp populates and which previously had zero invocation sites)
// and that subsidy + fees compose correctly at all four reward-era boundaries.

#include <gtest/gtest.h>
#include <cstdint>
#include <optional>
#include <stdexcept>

#include <core/pow.hpp>                          // core::SubsidyFunc
#include <impl/dgb/config_coin.hpp>              // dgb::CoinParams::subsidy (oracle SSOT)
#include <impl/dgb/coin/embedded_coinbase_value.hpp>

namespace {

// IDENTICAL lambda to params.hpp `p.subsidy_func` — exercises the same
// std::function indirection the live CoinParams carries.
const core::SubsidyFunc kSubsidyFunc =
    [](uint32_t height) -> uint64_t { return dgb::CoinParams::subsidy(height); };

struct EraVec { uint32_t height; uint64_t subsidy; const char* era; };

// One pin on each side of every reward-era boundary. Expected subsidy values
// are the p2pool-dgb-scrypt oracle vectors (test_dgb_subsidy.cpp).
constexpr EraVec kEraBoundaries[] = {
    {67199,   8000000000ULL, "phase1-fixed last"},
    {67200,   7960000000ULL, "phase2 -0.5%/wk first"},
    {399999,  6746441103ULL, "phase2 last"},
    {400000,  2434410000ULL, "phase3 -1%/wk first"},
    {1429999, 2157824200ULL, "phase3 last"},
    {1430000, 1078500000ULL, "phase4 monthly-decay first"},
};

} // namespace

// Zero fees: embedded coinbasevalue == the oracle subsidy, derived through the
// subsidy_func callback (not the static call) at every era boundary.
TEST(DgbCoinbaseValue, EmbeddedEqualsSubsidyAtEveryEraBoundary) {
    for (const auto& v : kEraBoundaries) {
        EXPECT_EQ(dgb::coin::embedded_coinbase_value(kSubsidyFunc, v.height, /*fees=*/0),
                  v.subsidy)
            << "embedded coinbasevalue diverged from oracle subsidy at " << v.era;
    }
}

// Non-zero fees compose additively: coinbasevalue = subsidy + total_fees.
TEST(DgbCoinbaseValue, AddsTransactionFees) {
    constexpr uint64_t kFees = 1234567ULL;
    for (const auto& v : kEraBoundaries) {
        EXPECT_EQ(dgb::coin::embedded_coinbase_value(kSubsidyFunc, v.height, kFees),
                  v.subsidy + kFees)
            << "fee addition wrong at " << v.era;
    }
}

// External-daemon fallback PERSISTS: when a GBT coinbasevalue is present it is
// authoritative and returned verbatim — the embedded derivation is bypassed,
// even when it would differ.
TEST(DgbCoinbaseValue, GbtValueTakesPrecedence) {
    constexpr uint32_t kHeight = 400000;               // phase3 boundary
    constexpr uint64_t kGbt    = 99999999999ULL;       // deliberately != subsidy+fees
    EXPECT_EQ(dgb::coin::resolve_coinbase_value(kSubsidyFunc, kHeight, /*fees=*/500,
                                                std::optional<uint64_t>{kGbt}),
              kGbt);
}

// No external daemon (nullopt): resolve derives locally via subsidy_func+fees.
TEST(DgbCoinbaseValue, NoGbtDerivesEmbedded) {
    constexpr uint32_t kHeight = 400000;
    constexpr uint64_t kFees   = 777ULL;
    EXPECT_EQ(dgb::coin::resolve_coinbase_value(kSubsidyFunc, kHeight, kFees, std::nullopt),
              dgb::CoinParams::subsidy(kHeight) + kFees);
}

// An unset subsidy_func must fail LOUDLY (no silent zero-subsidy coinbase).
TEST(DgbCoinbaseValue, UnsetSubsidyFuncThrows) {
    core::SubsidyFunc empty;
    EXPECT_THROW(dgb::coin::embedded_coinbase_value(empty, 400000, 0), std::logic_error);
}