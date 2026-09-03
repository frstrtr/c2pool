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

// ---------------------------------------------------------------------------
// File 5 — the tracker-coupled entry point the header comment forecasts.
//
// build_expected_payouts() feeds the pure validators above. It runs the v36
// decayed-PPLNS distribution over the sharechain (ShareTracker::get_expected_
// payouts, share_tracker.hpp) to produce the canonical map<scriptPubKey, amount>
// the coinbase MUST match, then hands it to validate_donation_output with
// share_version=36 => COMBINED_DONATION_SCRIPT (P2SH). Templated on TrackerT so
// donation_consensus.hpp stays decoupled from the heavy share_tracker.hpp include
// (the caller — the sharechain node's accept path — supplies the concrete
// ShareTracker & and already holds share_tracker.hpp).
//
// F11 exclude-then-append canonicalization: the donation is the rounding
// remainder and is ALWAYS the last payout output. get_expected_payouts() already
// computes it as subsidy − sum(miner amounts) and appends it under donation_script
// (share_tracker.hpp), guarding the double-count when a miner's own script equals
// the donation script via `result.contains(donation_script) ? result[...] : 0`.
// We therefore do NOT re-derive or re-append it here — build_expected_payouts is a
// thin, side-effect-free bridge that preserves that canonical map verbatim.
template <typename TrackerT>
inline std::map<std::vector<unsigned char>, double>
build_expected_payouts(TrackerT& tracker,
                       const uint256& best_share_hash,
                       const uint256& block_target,
                       uint64_t subsidy,
                       int64_t share_version = 36)
{
    auto donation_script = PoolConfig::get_donation_script(share_version);
    // The tracker owns the decayed walk + the >=1-sat donation floor tiebreak +
    // the exclude-then-append donation canonicalization. We surface its result
    // unchanged so it can be fed to validate_donation_output / validate_coinbase_total.
    return tracker.get_expected_payouts(best_share_hash, block_target, subsidy, donation_script);
}

// Convenience: build the expected map from the tracker AND run both pure
// validators against the miner's coinbase outputs in one call. This is the
// reward-safety cross-check the sharechain accept path invokes for a v36 share
// that claims to be a block solution.
template <typename TrackerT>
inline DonationValidationResult validate_payouts_against_tracker(
    TrackerT& tracker,
    const uint256& best_share_hash,
    const uint256& block_target,
    uint64_t subsidy,
    const std::vector<CoinbaseOutput>& coinbase_outputs,
    int64_t share_version = 36)
{
    auto expected = build_expected_payouts(tracker, best_share_hash, block_target,
                                           subsidy, share_version);
    auto total_res = validate_coinbase_total(coinbase_outputs, subsidy);
    if (!total_res.valid)
        return total_res;
    return validate_donation_output(coinbase_outputs, expected, share_version);
}

} // namespace bip110::pool::consensus
