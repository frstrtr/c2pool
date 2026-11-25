// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// --solo coinbase split (no sharechain): the node owner's fee, the donation,
// and the rest to the connected miners by hashrate, each paid to its login's
// own script (P2PKH, P2SH, P2WPKH, P2WSH, P2TR).

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace ltc {

using SoloMinerRates = std::vector<std::pair<std::vector<unsigned char>, double>>;   // (script, hashrate)

// node_owner_fee and dev_donation are percentages. The owner's fee is paid
// only with an owner script; the donation is dev_donation% or a 1-satoshi
// marker. With no miner (or no hashrate) the rest goes to the owner, else to
// the donation. The outputs add up to the subsidy exactly: the rounding
// remainder of the miners' split goes to the owner, else to the donation.
inline std::map<std::vector<unsigned char>, double> solo_payouts(
    uint64_t subsidy, const SoloMinerRates& miners, const std::vector<unsigned char>& owner_script,
    double node_owner_fee, const std::vector<unsigned char>& donation_script, double dev_donation)
{
    std::map<std::vector<unsigned char>, uint64_t> out;

    uint64_t owner_fee = 0;
    if (node_owner_fee > 0 && !owner_script.empty()) {
        owner_fee = static_cast<uint64_t>(static_cast<double>(subsidy) * node_owner_fee / 100.0);
        if (owner_fee > subsidy) owner_fee = subsidy;
        out[owner_script] += owner_fee;
    }
    uint64_t donation = dev_donation > 0
        ? static_cast<uint64_t>(static_cast<double>(subsidy) * dev_donation / 100.0) : 1;
    if (donation > subsidy - owner_fee) donation = subsidy - owner_fee;
    out[donation_script] += donation;

    const uint64_t pool = subsidy - owner_fee - donation;
    double total_rate = 0;
    for (const auto& [script, rate] : miners)
        if (!script.empty() && rate > 0) total_rate += rate;

    uint64_t paid = 0;
    if (total_rate > 0) {
        for (const auto& [script, rate] : miners) {
            if (script.empty() || rate <= 0) continue;
            uint64_t amount = static_cast<uint64_t>(static_cast<double>(pool) * (rate / total_rate));
            if (amount > pool - paid) amount = pool - paid;   // never more than the pool (float rounding)
            if (amount == 0) continue;
            out[script] += amount;
            paid += amount;
        }
    }
    const uint64_t rest = pool - paid;
    if (rest > 0)
        out[owner_script.empty() ? donation_script : owner_script] += rest;

    std::map<std::vector<unsigned char>, double> result;
    for (const auto& [script, amount] : out)
        if (amount > 0) result[script] = static_cast<double>(amount);
    return result;
}

} // namespace ltc
