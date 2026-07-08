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

// apply_v35_finder_fee: pre-v36 (sub-36) finder fee. generate_share_transaction
// (share_check.hpp, use_v36_pplns==false branch) credits subsidy/200 to the
// share creator\x27s own script and shrinks the donation residual by the same
// amount. For a LOCALLY-authored share creator==finder==this connection\x27s
// payout_script, so mirror it exactly here: move subsidy/200 from the donation
// entry (get_v35_expected_payouts folds the ~0.5% into donation) onto
// payout_script. Total stays == subsidy. No-op when `payouts` is empty (cold
// start -> degraded single-output fallback owns that) or the fee rounds to 0.
// Pure/header-only so the production TU and the fenced dual-version KAT consume
// the IDENTICAL implementation. sv>=36 authors never call this (pure PPLNS).
// canonical_finder_script: reconstruct the finder's coinbase script EXACTLY as
// the verifier's generate_share_transaction sees it, i.e. get_share_script() =
// pubkey_hash_to_script(m_pubkey_hash, m_pubkey_type), where create_local_share
// derives (m_pubkey_hash, m_pubkey_type) from payout_script. Standard P2PKH /
// P2SH / P2WPKH scripts are returned verbatim (identity -- no behaviour change).
// A payout_script the share author cannot store as a 20-byte pubkey_hash maps as
// create_local_share does: size >= 20 -> P2PKH of the first 20 bytes; size < 20
// (incl. EMPTY) -> P2PKH(all-zeros) -- the SAME degenerate creator script the
// stored share carries. This keeps the sub-36 finder-fee target byte-identical
// author<->verifier so the gentx hash matches. Without it, an author whose miner
// authorised with a non-decodable address paid NO finder fee while the verifier
// credited subsidy/200 to P2PKH(zeros): a one-output GENTX-MISMATCH on every
// non-genesis share (the height>=2 verified-tip stall).
inline std::vector<unsigned char> canonical_finder_script(
    const std::vector<unsigned char>& payout_script)
{
    // P2PKH: 76 a9 14 <20> 88 ac  (identity)
    if (payout_script.size() == 25 && payout_script[0] == 0x76 &&
        payout_script[1] == 0xa9 && payout_script[2] == 0x14 &&
        payout_script[23] == 0x88 && payout_script[24] == 0xac)
        return payout_script;
    // P2SH: a9 14 <20> 87  (identity)
    if (payout_script.size() == 23 && payout_script[0] == 0xa9 &&
        payout_script[1] == 0x14 && payout_script[22] == 0x87)
        return payout_script;
    // P2WPKH: 00 14 <20>  (identity -- pubkey_hash_to_script(type=1) is the same)
    if (payout_script.size() == 22 && payout_script[0] == 0x00 &&
        payout_script[1] == 0x14)
        return payout_script;
    // Non-standard: mirror create_local_share's m_pubkey_hash derivation, which
    // only writes the hash when payout_script.size() >= 20 (else it stays zero).
    unsigned char h[20] = {0};
    if (payout_script.size() >= 20)
        for (size_t i = 0; i < 20; ++i) h[i] = payout_script[i];
    std::vector<unsigned char> script;
    script.reserve(25);
    script.push_back(0x76);
    script.push_back(0xa9);
    script.push_back(0x14);
    script.insert(script.end(), h, h + 20);
    script.push_back(0x88);
    script.push_back(0xac);
    return script;
}

inline void apply_v35_finder_fee(
    std::map<std::vector<unsigned char>, double>& payouts,
    const std::vector<unsigned char>& payout_script,
    const std::vector<unsigned char>& donation_script,
    uint64_t subsidy)
{
    if (payouts.empty()) return;
    const double finder_fee = static_cast<double>(subsidy / 200);
    if (finder_fee <= 0.0) return;
    // Credit the finder fee to the CANONICAL creator script the verifier
    // reconstructs from the stored share, NOT the raw connection payout_script.
    // These differ only when payout_script is non-standard/empty -- exactly the
    // case that left author (no fee) and verifier (fee to P2PKH-zeros) one
    // output apart. See canonical_finder_script().
    const auto finder_script = canonical_finder_script(payout_script);
    payouts[finder_script] += finder_fee;
    if (!donation_script.empty()) {
        auto dit = payouts.find(donation_script);
        if (dit != payouts.end() && dit->second >= finder_fee)
            dit->second -= finder_fee;
    }
}

}  // namespace bch::stratum
