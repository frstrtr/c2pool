// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// pplns_v36.hpp — the shared v36 PPLNS pieces for the private/isolated DASH
// v36 sharechain (custom --network-id). Reached only for a v36 share, which
// only that profile loads: nothing on the public v16 path calls into the v36
// window or the v36 amounts rule.
//
// ONE place for each consensus rule, so the v36 verifier (share_check.hpp
// generate_share_transaction(DashV36Share)), the v36 producer (share_producer.hpp
// build_share_v36) and the stratum coinbase builder's v36 arm
// (coinbase_builder.hpp compute_dash_payouts) cannot drift:
//
//   * v36_decayed_cumulative_weights — the exponential depth-decay PPLNS walk
//     (40-bit fixed point, half_life = CHAIN_LENGTH/4). Moved verbatim from
//     ShareTracker::get_v36_decayed_cumulative_weights, which now delegates here
//     (keeping its result cache). Exact integer arithmetic throughout.
//   * v36_pplns_window — the v36 window rule: start at the share's PARENT,
//     CHAIN_LENGTH shares, no weight cap (the decay does the windowing), and
//     refuse an unrooted chain shorter than CHAIN_LENGTH (port of the LTC v36
//     verifier guard, ltc/share_check.hpp generate_share_transaction).
//   * compute_v36_amounts — the v36 amounts rule: full weight, NO block-finder
//     fee, remainder (rounding + donation weight) to the donation script, and the
//     donation output carries >= 1 satoshi (1 sat taken from the largest miner
//     payout, tiebreak (amount, script), never from the donation key).
//
// This header sits below share_check.hpp (which includes it) and only needs the
// muldiv leaf, the sharechain constants and uint288. The PPLNS walk resolves
// get_share_script (share_check.hpp) by argument-dependent lookup at the point
// of instantiation: every caller instantiates it with a dash:: share type after
// share_check.hpp is visible.
// ============================================================================

#include "config_pool.hpp"     // SharechainConfig::chain_length()
#include "payout_muldiv.hpp"   // dash::payout::v36_worker_amount (the ONE exact muldiv)

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace dash
{

// PPLNS cumulative weights (per payout script, grand total including donation
// weight, donation weight). Moved from share_tracker.hpp unchanged (same name,
// same namespace) so the tracker, its ring buffer and the v36 gentx share one
// type.
struct CumulativeWeights
{
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

namespace v36_pplns
{

// Fixed-point decay constants (identical to DensePPLNSWindow in
// share_tracker.hpp; KAT: DashV36DecayedWeights.WalkMatchesHandIntegerGoldenAndRing).
inline constexpr uint64_t DECAY_PRECISION = 40;
inline constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
inline constexpr uint64_t LN2_MICRO = 693147;

// The v36 window length and the tracker's ring / cache key both use
// CHAIN_LENGTH, the LTC v36 verifier uses REAL_CHAIN_LENGTH. They are equal on
// every DASH network; a per-network change that split them would silently
// desynchronize the primed cache from the verifier window.
static_assert(SharechainConfig::CHAIN_LENGTH == SharechainConfig::REAL_CHAIN_LENGTH,
              "v36 PPLNS window: CHAIN_LENGTH must equal REAL_CHAIN_LENGTH");
static_assert(SharechainConfig::TESTNET_CHAIN_LENGTH == SharechainConfig::TESTNET_REAL_CHAIN_LENGTH,
              "v36 PPLNS window: TESTNET_CHAIN_LENGTH must equal TESTNET_REAL_CHAIN_LENGTH");

// (a * b) >> 40 with a 128-bit intermediate. Same value as the global
// mul128_shift(a, b, 40) the tracker's ring buffer uses; kept under its own
// name here because every coin's share_tracker.hpp defines a global
// ::mul128_shift, and this header is reachable from TUs that include those.
inline uint64_t mul_shift_precision(uint64_t a, uint64_t b)
{
#if defined(__SIZEOF_INT128__)
    return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) >> DECAY_PRECISION);
#else
    using u128 = boost::multiprecision::uint128_t;
    return static_cast<uint64_t>((u128(a) * u128(b)) >> DECAY_PRECISION);
#endif
}

// Per-depth decay factor for a window of chain_len shares
// (half_life = max(chain_len / 4, 1)).
inline uint64_t decay_per(uint32_t chain_len)
{
    const uint32_t half_life = std::max(chain_len / 4, uint32_t(1));
    return DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);
}

// "No weight cap" sentinel (2^288 - 1), the desired_weight every v36
// verification uses.
inline uint288 unlimited_weight()
{
    uint288 w;
    w.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return w;
}

} // namespace v36_pplns

// ── v36 decayed cumulative weights (the walk) ────────────────────────────────
// Matches Python: get_decayed_cumulative_weights()
// half_life = CHAIN_LENGTH // 4
// Each share's weight is multiplied by 2^(-depth/half_life)
// Fixed-point arithmetic with 40-bit precision.
// Walks from `start` (depth 0) through at most `max_shares` shares; the share
// that crosses `desired_weight` is included partially. Body moved verbatim
// from ShareTracker::get_v36_decayed_cumulative_weights.
template <typename ChainT>
CumulativeWeights v36_decayed_cumulative_weights(ChainT& chain, const uint256& start,
                                                 int32_t max_shares,
                                                 const uint288& desired_weight)
{
    if (start.IsNull())
        return {};

    using v36_pplns::DECAY_PRECISION;
    using v36_pplns::DECAY_SCALE;

    const uint64_t decay_per = v36_pplns::decay_per(SharechainConfig::chain_length());

    CumulativeWeights result;
    int32_t share_count = 0;
    uint64_t decay_fp = DECAY_SCALE; // starts at 1.0

    // Single-pass walk matching p2pool's while loop in
    // get_decayed_cumulative_weights. No pre-collection needed.
    //
    // TODO(ltc-doge): pin exact intra-walk yield boundary + optional
    // zero-divisor guard (degenerate target_ratio==0). This inner decay
    // iteration is the candidate finest-grained yield point for the V36
    // livelock lock-yield mechanism; the cooperative budget is currently
    // enforced at the COARSE per-scored-head boundary in think() Phase 3
    // (THINK_WALK_YIELD_BUDGET). Once PIE core symbolization pins the true
    // hot site, move/refine the budget check here. The zero-divisor guard
    // referenced is the `!this_total.IsNull()` proration guard just below
    // (remaining / this_total) — confirm it covers the degenerate case.
    auto cur = start;
    while (!cur.IsNull() && chain.contains(cur) && share_count < max_shares)
    {
        chain.get_share(cur).invoke([&](auto* obj) {
            auto att = chain::target_to_average_attempts(
                chain::bits_to_target(obj->m_bits));
            uint32_t don = obj->m_donation;

            uint288 decayed_att = (att * uint288(decay_fp)) >> DECAY_PRECISION;

            auto addr_w = decayed_att * static_cast<uint32_t>(65535 - don);
            auto don_w  = decayed_att * don;
            auto this_total = addr_w + don_w; // = decayed_att * 65535

            if (result.total_weight + this_total > desired_weight) {
                auto remaining = desired_weight - result.total_weight;
                if (!this_total.IsNull()) {
                    addr_w = addr_w * remaining / this_total;
                    don_w  = don_w * remaining / this_total;
                }
                this_total = remaining;
            }

            auto script = get_share_script(obj);
            result.weights[script] += addr_w;
            result.total_weight += this_total;
            result.total_donation_weight += don_w;
        });

        ++share_count;
        if (result.total_weight >= desired_weight)
            break;

        decay_fp = v36_pplns::mul_shift_precision(decay_fp, decay_per);

        auto* idx = chain.get_index(cur);
        cur = idx ? idx->tail : uint256();
    }

    return result;
}

// ── v36 window guard ─────────────────────────────────────────────────────────
// p2pool data.py:762-764 / ltc share_check.hpp: refuse to compute PPLNS over a
// window that stopped early because ancestors are missing. A chain that reaches
// genesis (get_last == null) is complete at any height; an unrooted one must
// hold at least chain_len shares. Throws std::invalid_argument.
template <typename ChainT>
void check_v36_pplns_window_depth(ChainT& chain, const uint256& prev_hash, int32_t chain_len)
{
    const auto height = chain.get_height(prev_hash);
    const auto last = chain.get_last(prev_hash);
    if (!(height >= chain_len || last.IsNull()))
        throw std::invalid_argument(
            "share chain not long enough for PPLNS verification (height="
            + std::to_string(height) + " need=" + std::to_string(chain_len) + ")");
}

// ── v36 PPLNS window (THE rule) ──────────────────────────────────────────────
// Weights for the coinbase of a v36 share whose parent is `prev_hash`:
//   * genesis / unknown parent  -> empty (the whole worker payout goes to the
//                                  donation script);
//   * otherwise                 -> the decayed walk from the PARENT (depth 0)
//                                  over CHAIN_LENGTH shares, no weight cap,
//                                  after the depth guard above.
// The live ShareTracker exposes the same rule through its result cache
// (ShareTracker::v36_pplns_window); this free form serves the producer and any
// chain without a tracker. Both evaluate the same walk, so both return the same
// weights for the same chain.
template <typename ChainT>
CumulativeWeights v36_pplns_window(ChainT& chain, const uint256& prev_hash)
{
    if (prev_hash.IsNull() || !chain.contains(prev_hash))
        return {};
    const int32_t chain_len = static_cast<int32_t>(SharechainConfig::chain_length());
    check_v36_pplns_window_depth(chain, prev_hash, chain_len);
    return v36_decayed_cumulative_weights(chain, prev_hash, chain_len,
                                          v36_pplns::unlimited_weight());
}

// ── v36 amounts (THE rule) ───────────────────────────────────────────────────
// Result of the amounts rule. `amounts` holds the non-donation payout scripts
// with amount > 0 (std::map order == script-byte order, the output order);
// `donation_amount` is the single donation output value (a weight keyed on the
// donation script itself is merged into it, the F11 rule). `pplns_sum` and
// `remainder` are the pre-merge diagnostics compute_dash_payouts logs.
struct V36Amounts
{
    std::map<std::vector<unsigned char>, uint64_t> amounts;
    uint64_t donation_amount{0};
    uint64_t pplns_sum{0};   // Σ weight-derived amounts after the floor (incl. donation key)
    uint64_t remainder{0};   // worker_payout - pplns_sum (rounding + donation weight, + floor sat)
};

// amounts[s]   = floor(weight[s] * worker_payout / total_weight)   (full weight, no finder fee)
// remainder    = worker_payout - Σ amounts                         (0 if Σ exceeds it; callers
//                                                                    check Σ == worker_payout)
// floor        : remainder == 0 && worker_payout > 0 -> take 1 sat from the largest
//                non-donation amount (tiebreak (amount, script)), remainder = 1
// donation     = amounts[donation_script] (if any) + remainder
inline V36Amounts compute_v36_amounts(const std::map<std::vector<unsigned char>, uint288>& weights,
                                      const uint288& total_weight,
                                      uint64_t worker_payout,
                                      const std::vector<unsigned char>& donation_script)
{
    V36Amounts out;
    auto& amounts = out.amounts;

    if (!total_weight.IsNull())
    {
        for (const auto& [script, weight] : weights)
        {
            const uint64_t a = payout::v36_worker_amount(weight, worker_payout, total_weight);
            if (a > 0)
                amounts[script] = a;
        }
    }

    uint64_t sum = 0;
    for (const auto& [s, a] : amounts)
        sum += a;
    uint64_t remainder = (worker_payout > sum) ? (worker_payout - sum) : 0;

    // v36 consensus (a60f7f7f): the donation output carries >= 1 satoshi.
    if (remainder < 1 && worker_payout > 0)
    {
        auto largest = amounts.end();
        for (auto it = amounts.begin(); it != amounts.end(); ++it)
        {
            if (it->first == donation_script)
                continue;
            if (largest == amounts.end()
                || it->second > largest->second
                || (it->second == largest->second && it->first > largest->first))
                largest = it;
        }
        if (largest != amounts.end() && largest->second >= 1)
        {
            largest->second -= 1;
            sum -= 1;
            remainder += 1;
        }
    }

    out.pplns_sum = sum;
    out.remainder = remainder;

    uint64_t donation_amount = remainder;
    if (auto it = amounts.find(donation_script); it != amounts.end())
    {
        donation_amount += it->second;
        amounts.erase(it);
    }
    out.donation_amount = donation_amount;

    // Drop entries the floor reduced to zero (never emitted).
    for (auto it = amounts.begin(); it != amounts.end();)
        it = (it->second == 0) ? amounts.erase(it) : std::next(it);

    return out;
}

} // namespace dash
