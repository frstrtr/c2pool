// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// donation_consensus.hpp -- Consensus-level donation script validation for BCH
// p2pool shares.
//
// Validates that coinbase transactions include the correct donation output as
// required by the p2pool protocol. The donation script receives the rounding
// remainder from PPLNS payout distribution.
//
// Donation script is VERSION-GATED (operator ruling 2026-06-16, V36 master-compat
// with frstrtr/p2pool-merged-v36):
//   share_version <  36 -> BCH-native forrestv P2PK (static, p2poolBCH @6603b79)
//   share_version >= 36 -> COMBINED_DONATION_SCRIPT (1-of-2 P2MS->P2SH transition
//                          + AutoRatchet 95%/50% + tail-guard; merged-path is
//                          always COMBINED for cross-coin V36 parity)
// Selection is owned by bch::PoolConfig::get_donation_script(share_version); this
// module consumes it so the share validator and the template builder agree.
//
// Mirrors src/impl/ltc/donation_consensus.hpp. NOTE: build_expected_payouts()
// (the ShareTracker entry point in the LTC reference) is deferred to the BCH
// PPLNS/share_tracker port slice -- share_tracker is not yet present on
// bch/m3-coin-node. The two validators below are self-contained.
//
// Reference: frstrtr/p2pool-merged-v36 p2pool/data.py lines 114-200
//

#include "config_pool.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace bch::consensus
{

// A single coinbase output (scriptPubKey + value).
struct CoinbaseOutput
{
    std::vector<unsigned char> script;
    uint64_t value{0};
};

// Result of donation validation.
struct DonationValidationResult
{
    bool valid{false};
    std::string error;
};

// Validate that a coinbase transaction contains the correct donation output.
//
// Rules (from p2pool consensus):
//   1. The (version-gated) donation script MUST appear as a coinbase output.
//   2. The donation amount >= expected_donation (from the PPLNS remainder).
//   3. Pre-V36 shares use the P2PK script; V36+ shares use the combined P2SH.
//
// Parameters:
//   coinbase_outputs: all outputs from the coinbase transaction
//   expected_payouts: result of ShareTracker::get_expected_payouts()
//   share_version:    the share version number (selects the donation script)
inline DonationValidationResult validate_donation_output(
    const std::vector<CoinbaseOutput>& coinbase_outputs,
    const std::map<std::vector<unsigned char>, double>& expected_payouts,
    int64_t share_version)
{
    auto donation_script = PoolConfig::get_donation_script(share_version);

    // Look up the expected donation amount.
    auto it = expected_payouts.find(donation_script);
    if (it == expected_payouts.end())
        return {true, {}}; // No donation expected (e.g. all miners set donation=0).

    double expected_amount = it->second;
    if (expected_amount <= 0.0)
        return {true, {}};

    // Find the donation output(s) in the coinbase.
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

    // Allow 1-satoshi tolerance for integer rounding.
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

} // namespace bch::consensus