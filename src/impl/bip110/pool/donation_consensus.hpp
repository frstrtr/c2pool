// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// donation_consensus.hpp — reward-safety donation-output validation for the
// BIP-110 v36 sharechain. The donation output receives the rounding remainder
// from decayed-PPLNS distribution and is ALWAYS the last payout output before the
// OP_RETURN ref-commitment (data.py:114-200). v36 => COMBINED_DONATION_SCRIPT
// (P2SH 1-of-2, core::donation SSOT).
//
// PR-A ships the two PURE validators (they depend only on config_pool.hpp). The
// tracker-coupled entry point build_expected_payouts() lands with share_tracker.hpp
// in PR-A-continuation (it needs ShareTracker::get_expected_payouts + the decayed
// weight walk) — see the remaining-work map.

#include "config_pool.hpp"

#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace bip110::pool::consensus
{

struct CoinbaseOutput
{
    std::vector<unsigned char> script;
    uint64_t value{0};
};

struct DonationValidationResult
{
    bool valid{false};
    std::string error;
};

// The donation script MUST appear as a coinbase output with value >= the PPLNS
// remainder (1-sat rounding tolerance). v36 selects COMBINED_DONATION_SCRIPT.
inline DonationValidationResult validate_donation_output(
    const std::vector<CoinbaseOutput>& coinbase_outputs,
    const std::map<std::vector<unsigned char>, double>& expected_payouts,
    int64_t share_version)
{
    auto donation_script = PoolConfig::get_donation_script(share_version);

    auto it = expected_payouts.find(donation_script);
    if (it == expected_payouts.end())
        return {true, {}}; // no donation expected (all miners donation=0)

    double expected_amount = it->second;
    if (expected_amount <= 0.0)
        return {true, {}};

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

    if (actual_donation + 1 < static_cast<uint64_t>(expected_amount))
        return {false, "donation output value too low"};

    return {true, {}};
}

// The sum of all coinbase outputs (donation included) must not exceed subsidy.
inline DonationValidationResult validate_coinbase_total(
    const std::vector<CoinbaseOutput>& coinbase_outputs,
    uint64_t subsidy)
{
    uint64_t total = 0;
    for (const auto& out : coinbase_outputs)
    {
        if (total + out.value < total) // overflow
            return {false, "coinbase output sum overflow"};
        total += out.value;
    }

    if (total > subsidy)
        return {false, "coinbase outputs exceed block subsidy"};

    return {true, {}};
}

} // namespace bip110::pool::consensus
