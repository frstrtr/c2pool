// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The donation of every aux-chain coinbase c2pool builds.
///
/// MergedMiningManager::build_pplns_coinbase_hex writes the aux coinbase (DOGE
/// under LTC, and under DGB once its payout provider lands; NMC under BTC; the
/// other LTC aux chains): miner outputs, an OP_RETURN, and the donation
/// output, always last. That output pays merged_donation_script(), the single
/// P2PKH key of core::donation::SINGLE_P2PKH_DONATION_SCRIPT (the same bytes
/// on every chain; only the address rendering differs). The merged payout
/// providers (main_ltc.cpp P2P and solo/custodial, main_btc.cpp) hand the
/// same script to the tracker split as its donation, so the PPLNS remainder
/// lands on it.
///
/// is_merged_donation_output() is what the builder folds into that output: the
/// script itself and the combined 1-of-2 P2SH the aux coinbase paid before
/// (core::donation::COMBINED_DONATION_SCRIPT). An entry with the old script
/// (a share redistributed in "donate" mode, a miner paying the old donation
/// address) is paid to the single key, not as a miner output.
///
/// Node-local: c2pool nodes do not re-derive each other's aux coinbases (ltc
/// and btc verify_merged_coinbase_commitment, merged_payout_hash carries the
/// weights only). The parent-chain share donation is
/// core::donation::get_donation_script() and is untouched by this script.

#include <core/donation.hpp>

#include <vector>

namespace c2pool::merged
{

inline const std::vector<unsigned char>& merged_donation_script()
{
    static const std::vector<unsigned char> script(
        core::donation::SINGLE_P2PKH_DONATION_SCRIPT.begin(),
        core::donation::SINGLE_P2PKH_DONATION_SCRIPT.end());
    return script;
}

inline bool is_merged_donation_output(const std::vector<unsigned char>& script)
{
    static const std::vector<unsigned char> combined(
        core::donation::COMBINED_DONATION_SCRIPT.begin(),
        core::donation::COMBINED_DONATION_SCRIPT.end());
    return script == merged_donation_script() || script == combined;
}

} // namespace c2pool::merged
