// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ============================================================================
// pplns_payout_split.hpp — SSOT: PPLNS weights -> consensus-sorted payout outputs.
//
// Converts the decayed/cumulative PPLNS weight map (produced by the ShareTracker
// — see share_tracker.hpp get_v36_decayed_cumulative_weights /
// get_cumulative_weights) into the EXACT integer per-script payout amounts and
// the consensus output ordering that the coinbase carries.
//
// This is steps 2-3 of share_check.hpp generate_share_transaction() lifted into
// a pure, tracker-free, chain-free function so the SAME math can feed BOTH:
//   - generate_share_transaction()        (the share verification SSOT), and
//   - stratum/work_source build_connection_coinbase() (per-connection coinbase),
// guaranteeing emission and verification can never diverge on a payout satoshi.
//
// Port of frstrtr/p2pool-merged-v36 data.py generate_transaction() amount math:
//   V36:     amounts[script] = subsidy * weight / total_weight
//   Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
//            amounts[finder] += subsidy // 200          (0.5% finder fee)
//   donation = subsidy - sum(amounts)
//   V36 floor: donation must carry >= 1 sat (a60f7f7f) — deduct 1 from the
//              largest payout, deterministic tiebreak (amount, script).
//   order:   V36 sorted(dests, key=(amount, script))[-4000:]  (asc, keep highest);
//            pre-V36 by (amount, address string), donation counted in the 4000
//
// Pure: takes already-built weights + subsidy + finder script, so it is directly
// KAT-able against a canonical oracle vector (test/pplns_payout_split_test.cpp).
// ============================================================================

#include <core/uint256.hpp>   // uint288
#include <impl/dgb/config_pool.hpp>   // PoolConfig::is_testnet (the V35 address strings)
#include <impl/dgb/v35_address.hpp>   // v35_script_to_address (the V35 sort key)

#include <algorithm>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace dgb::coin
{

// Maximum coinbase payout outputs, matching p2pool's [-4000:] slice.
inline constexpr std::size_t PPLNS_MAX_OUTPUTS = 4000;

struct PplnsPayoutSplit
{
    // (scriptPubKey, value) pairs in final consensus order: ascending by
    // (amount, script), truncated to the highest PPLNS_MAX_OUTPUTS.
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs;
    // donation = subsidy - sum(payout amounts) (after the v36 >=1 sat floor).
    uint64_t donation_amount{0};
};

// weights / total_weight: PPLNS weight map keyed by full scriptPubKey.
// subsidy: total coinbase value to distribute (block subsidy + fees).
// use_v36_pplns: select the V36 formula (no finder fee) vs pre-V36 (0.5% fee).
// finder_script: share creator's payout script — receives the pre-V36 finder
//                fee; ignored when use_v36_pplns is true.
inline PplnsPayoutSplit compute_pplns_payout_split(
    const std::map<std::vector<unsigned char>, uint288>& weights,
    const uint288& total_weight,
    uint64_t subsidy,
    bool use_v36_pplns,
    const std::vector<unsigned char>& finder_script)
{
    std::map<std::vector<unsigned char>, uint64_t> amounts;

    // --- exact integer payout amounts (generate_share_transaction step 2) ---
    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            uint64_t amount;
            if (use_v36_pplns)
            {
                // V36: amounts[script] = subsidy * weight / total_weight
                uint288 num = uint288(subsidy) * weight;
                amount = (num / total_weight).GetLow64();
            }
            else
            {
                // Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
                uint288 num = uint288(subsidy) * (weight * 199);
                uint288 den = total_weight * 200;
                amount = (num / den).GetLow64();
            }
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    // Pre-V36: add 0.5% finder fee to share creator.
    if (!use_v36_pplns)
        amounts[finder_script] += subsidy / 200;

    // Donation = subsidy minus the sum of all payout amounts.
    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

    // V36 consensus: donation output must carry >= 1 satoshi (a60f7f7f).
    // Deduct 1 sat from the largest miner payout; deterministic tiebreak
    // (amount, script) — largest script wins when amounts are equal.
    if (use_v36_pplns)
    {
        if (donation_amount < 1 && subsidy > 0 && !amounts.empty())
        {
            auto largest = std::max_element(amounts.begin(), amounts.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            if (largest != amounts.end() && largest->second > 0)
            {
                largest->second -= 1;
                sum_amounts -= 1;
                donation_amount = subsidy - sum_amounts;
            }
        }
    }

    // --- consensus output order (generate_share_transaction step 3) ---------
    // V36: sorted(dests, key=lambda a: (amounts[a], a))[-4000:], keyed by
    //   script: ascending by (amount, script), keep the highest.
    // Pre-V36 (the python V35 network, p2pool-dgb-scrypt data.py
    //   generate_transaction): the dests are ADDRESS STRINGS, the donation one
    //   among them: sorted(key=(addr == donation_address, amounts[addr],
    //   addr))[-4000:]. So equal amounts sort by the address string ("D..." <
    //   "S..." < "dgb1..."), not by the script (where a P2WPKH 0x00... sorted
    //   first), and the donation takes one of the 4000 places: at most 3999
    //   payouts (review 713dc77a0 #6). The string of a script is its canonical
    //   address (v35_script_to_address: base58, lowercase bech32), which is the
    //   string a share minted here carries; a script without one keeps the
    //   script order after the addressed ones.
    PplnsPayoutSplit out;
    out.donation_amount = donation_amount;
    out.payout_outputs.assign(amounts.begin(), amounts.end());
    if (use_v36_pplns) {
        std::sort(out.payout_outputs.begin(), out.payout_outputs.end(),
            [](const auto& a, const auto& b) {
                if (a.second != b.second) return a.second < b.second; // asc by amount
                return a.first < b.first;                             // asc by script tiebreak
            });
    } else {
        const auto net = dgb::v35_address_net(dgb::PoolConfig::is_testnet);
        std::map<std::vector<unsigned char>, std::string> key;
        for (const auto& [script, amount] : amounts)
            key.emplace(script, dgb::v35_script_to_address(script, net));
        std::sort(out.payout_outputs.begin(), out.payout_outputs.end(),
            [&key](const auto& a, const auto& b) {
                if (a.second != b.second) return a.second < b.second; // asc by amount
                const std::string& ka = key.at(a.first);
                const std::string& kb = key.at(b.first);
                if (ka.empty() != kb.empty()) return kb.empty();      // addressed ones first
                if (ka != kb) return ka < kb;                         // asc by address string
                return a.first < b.first;
            });
    }
    const std::size_t max_payouts = use_v36_pplns ? PPLNS_MAX_OUTPUTS : PPLNS_MAX_OUTPUTS - 1;
    if (out.payout_outputs.size() > max_payouts)
        out.payout_outputs.erase(out.payout_outputs.begin(),
                                 out.payout_outputs.end() - static_cast<std::ptrdiff_t>(max_payouts));
    return out;
}

} // namespace dgb::coin