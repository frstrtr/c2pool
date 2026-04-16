#pragma once
//
// donation_consensus.hpp — Consensus-level donation script validation for LTC p2pool shares.
//
// This module validates that coinbase transactions correctly include the
// donation output as required by the p2pool protocol. The donation script
// receives the rounding remainder from PPLNS payout distribution.
//
// Reference: frstrtr/p2pool-merged-v36 p2pool/data.py lines 114–200
//

#include "config_pool.hpp"
#include "share_tracker.hpp"

#include <core/coin_params.hpp>
#include <core/target_utils.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <vector>

namespace ltc::consensus
{

// A single coinbase output (scriptPubKey + value)
struct CoinbaseOutput
{
    std::vector<unsigned char> script;
    uint64_t value{0};
};

// Result of donation validation
struct DonationValidationResult
{
    bool valid{false};
    std::string error;
};

// Validate that a coinbase transaction contains the correct donation output.
//
// Rules (from p2pool consensus):
//   1. The donation script MUST appear as an output in the coinbase.
//   2. The donation amount >= expected_donation (from PPLNS remainder).
//   3. Pre-V36 shares use DONATION_SCRIPT (P2PK); V36+ use COMBINED_DONATION_SCRIPT (P2SH).
//
// Parameters:
//   coinbase_outputs: all outputs from the coinbase transaction
//   expected_payouts: result of ShareTracker::get_expected_payouts()
//   share_version:    the share's version number (selects donation script)
//
inline DonationValidationResult validate_donation_output(
    const std::vector<CoinbaseOutput>& coinbase_outputs,
    const std::map<std::vector<unsigned char>, double>& expected_payouts,
    int64_t share_version,
    const core::CoinParams& params)
{
    auto donation_script = params.donation_script_func(share_version);

    // Look up expected donation amount
    auto it = expected_payouts.find(donation_script);
    if (it == expected_payouts.end())
        return {true, {}}; // No donation expected (e.g., all miners set donation=0)

    double expected_amount = it->second;
    if (expected_amount <= 0.0)
        return {true, {}};

    // Find the donation output in the coinbase
    uint64_t actual_donation = 0;
    bool found = false;
    for (const auto& out : coinbase_outputs)
    {
        if (out.script == donation_script)
        {
            actual_donation += out.value;
            found = true;
        }
    }

    if (!found)
        return {false, "coinbase missing donation output for script"};

    // Allow 1-satoshi tolerance for integer rounding
    if (actual_donation + 1 < static_cast<uint64_t>(expected_amount))
        return {false, "donation output value too low"};

    return {true, {}};
}

// Verify that the sum of all coinbase outputs does not exceed the subsidy.
// The donation output is included in this sum.
inline DonationValidationResult validate_coinbase_total(
    const std::vector<CoinbaseOutput>& coinbase_outputs,
    uint64_t subsidy)
{
    uint64_t total = 0;
    for (const auto& out : coinbase_outputs)
    {
        if (total + out.value < total) // overflow check
            return {false, "coinbase output sum overflow"};
        total += out.value;
    }

    if (total > subsidy)
        return {false, "coinbase outputs exceed block subsidy"};

    return {true, {}};
}

// Build the expected payout map for consensus validation.
// This is the canonical entry point connecting ShareTracker PPLNS weights
// to the donation script selection.
inline std::map<std::vector<unsigned char>, double>
build_expected_payouts(ShareTracker& tracker,
                       const uint256& best_share_hash,
                       const uint256& block_target,
                       uint64_t subsidy,
                       int64_t share_version,
                       const core::CoinParams& params)
{
    auto donation_script = params.donation_script_func(share_version);
    return tracker.get_expected_payouts(best_share_hash, block_target, subsidy, donation_script);
}

} // namespace ltc::consensus
