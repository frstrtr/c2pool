#pragma once
// bch::stratum::assemble_v36_coinbase_outputs
//
// PURE, oracle-conforming v36 coinbase OUTPUT-ASSEMBLY, extracted verbatim from
// BCHWorkSource::build_connection_coinbase so the byte-shape can be pinned by a
// KAT against the p2pool-merged-v36 oracle (data.py generate_transaction,
// v36_active branch ~920-1085) WITHOUT standing up the whole work source.
//
// Contract (matches the oracle exactly):
//   1. The donation/marker entry (keyed by donation_script) is separated out of
//      the PPLNS payout set and FORCED LAST (immediately before the OP_RETURN),
//      EXCLUDED from the (amount asc, script asc) sort, regardless of its amount.
//   2. V36 consensus marker rule: if the donation amount rounds to 0 while the
//      subsidy is > 0, decrement the largest PPLNS payout by 1 satoshi
//      (deterministic tiebreak on (amount, script)) and move that satoshi into
//      the donation output, so the marker always carries >= 1 satoshi.
//   3. PPLNS dests drop zero-value entries, sort (amount asc, then script asc),
//      and keep only the largest 4000 (oracle dests[-4000:]).
//   4. NO finder fee is deducted (V36 pure-PPLNS accounting); the input `payouts`
//      already reflect the no-haircut, no-finder-fee v36 amounts.
//
// Per-coin isolation: src/impl/bch/ only. Header-only (no link surface) so both
// the production TU and the fenced KAT consume the identical implementation.

#include <algorithm>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace bch::stratum {

// payouts: script -> amount (double, as emitted by the PPLNS callback), INCLUDING
//          the donation entry keyed by donation_script (pre-marker amount).
// returns: ordered (script, satoshi-amount) outputs ready to serialize, with the
//          donation/marker output appended LAST.
inline std::vector<std::pair<std::vector<unsigned char>, uint64_t>>
assemble_v36_coinbase_outputs(
    std::map<std::vector<unsigned char>, double> payouts,
    const std::vector<unsigned char>& donation_script,
    uint64_t coinbasevalue)
{
    // Separate the donation/marker entry from the PPLNS payout set.
    uint64_t donation_amount = 0;
    bool have_donation = false;
    if (!donation_script.empty()) {
        auto dit = payouts.find(donation_script);
        if (dit != payouts.end()) {
            donation_amount = static_cast<uint64_t>(dit->second);
            have_donation = true;
            payouts.erase(dit);
        }
    }

    // V36 CONSENSUS RULE (data.py: total_donation < 1 path): the donation/marker
    // output must carry >= 1 satoshi. If it rounds to 0 while subsidy > 0,
    // decrement the largest PPLNS payout by 1 sat (deterministic tiebreak on
    // (amount, script)) and move that satoshi into the donation output.
    if (have_donation && donation_amount < 1 && coinbasevalue > 0 && !payouts.empty()) {
        auto largest = payouts.begin();
        for (auto it = payouts.begin(); it != payouts.end(); ++it) {
            const uint64_t a  = static_cast<uint64_t>(it->second);
            const uint64_t la = static_cast<uint64_t>(largest->second);
            if (a > la || (a == la && it->first > largest->first)) largest = it;
        }
        if (static_cast<uint64_t>(largest->second) >= 1) {
            largest->second -= 1.0;
            donation_amount += 1;
        }
    }

    // PPLNS dests: drop zero-value entries, sort (amount asc, script asc), then
    // keep only the largest 4000 (oracle dests[-4000:]).
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> outputs;
    outputs.reserve(payouts.size() + 1);
    for (const auto& [script, amount_d] : payouts) {
        if (script.empty()) continue;
        const uint64_t amount = static_cast<uint64_t>(amount_d);
        if (amount > 0) outputs.emplace_back(script, amount);
    }
    std::sort(outputs.begin(), outputs.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second < b.second;
        return a.first < b.first;
    });
    if (outputs.size() > 4000)
        outputs.erase(outputs.begin(), outputs.end() - 4000);

    // Donation/marker output appended LAST, before the OP_RETURN. It is NOT
    // filtered by the amount>0 rule: a zero-value donation (subsidy==0) is still
    // emitted to preserve gentx_before_refhash byte-parity with the oracle.
    if (have_donation)
        outputs.emplace_back(donation_script, donation_amount);

    return outputs;
}

}  // namespace bch::stratum
