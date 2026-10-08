// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_reward.hpp
//
// BLOCK REWARD and ALREADY-GENERATED COINS.
//
// monerod's get_block_reward (src/cryptonote_basic/cryptonote_basic_impl.cpp),
// transcribed with its constants and its 128-bit arithmetic:
//
//   base   = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor
//   base   = max(base, FINAL_SUBSIDY_PER_MINUTE * target_minutes)   <- tail
//   zone   = get_min_block_weight(version); median = max(median, zone)
//   w <= median            -> reward = base
//   w >  2 * median        -> REJECT (the block is too big to be paid for)
//   otherwise              -> reward = base * (2*median - w) * w / median^2
//
// with MONEY_SUPPLY = 2^64 - 1, EMISSION_SPEED_FACTOR_PER_MINUTE = 20,
// FINAL_SUBSIDY_PER_MINUTE = 3e11 and, for every version this node meets,
// target = DIFFICULTY_TARGET_V2 = 120 s -> target_minutes = 2 -> speed factor 19
// and a tail of 6e11 (0.6 XMR) per block.
//
// THE PENALTY NEEDS 128 BITS AND THE ORDER OF OPERATIONS MATTERS. monerod
// computes base * multiplicand as a 128-bit product and then divides by the
// median TWICE, each time as a 128/64 division. Doing it as
// base * multiplicand / median^2 in 64 bits overflows for realistic values, and
// dividing once by median^2 is NOT the same rounding. Both spellings are
// provided below: a portable 128-bit pair (mul128/div128_64, the same shape as
// monerod's int-util.h) and, where the compiler has it, unsigned __int128 --
// and the KAT asserts the two agree over a randomized sweep, and that both
// agree with an independent boost::multiprecision computation.
//
// ALREADY-GENERATED COINS is the running sum of the PENALIZED BASE rewards --
// fees are not emission and never enter it (blockchain.cpp
// handle_block_to_main_chain):
//
//   agc <- (base < MONEY_SUPPLY - agc) ? agc + base : MONEY_SUPPLY
//
// The saturation branch is monerod's and is kept: with a tail emission the sum
// approaches MONEY_SUPPLY forever and never passes it, and a node that let it
// wrap would compute every later reward wrong.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#include "xmr_weight.hpp"

namespace c2pool::xmr::native {

// --- cryptonote_config.h ------------------------------------------------------
inline constexpr std::uint64_t MONEY_SUPPLY                     = ~static_cast<std::uint64_t>(0);
inline constexpr int           EMISSION_SPEED_FACTOR_PER_MINUTE = 20;
inline constexpr std::uint64_t FINAL_SUBSIDY_PER_MINUTE         = 300000000000ull;  // 3e11
inline constexpr std::uint64_t DIFFICULTY_TARGET_V1_SECONDS     = 60;
inline constexpr std::uint64_t DIFFICULTY_TARGET_V2_SECONDS     = 120;

// --- 128-bit helpers ----------------------------------------------------------
// The same two primitives monerod uses (contrib/epee int-util.h), written here
// so this header links nothing. The 32-bit-limb spelling is the portable one and
// is what the KAT cross-checks against __int128 and against boost.
struct U128Pair {
    std::uint64_t hi = 0;
    std::uint64_t lo = 0;
};

// The 32-bit-limb spellings are ALWAYS defined, not only on a compiler without
// __int128: the KAT drives both paths against each other and against
// boost::multiprecision, so the fallback cannot rot unnoticed on the hosts that
// never take it.
inline U128Pair mul128_portable(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t a_lo = a & 0xffffffffu, a_hi = a >> 32;
    const std::uint64_t b_lo = b & 0xffffffffu, b_hi = b >> 32;
    const std::uint64_t p0 = a_lo * b_lo;
    const std::uint64_t p1 = a_lo * b_hi;
    const std::uint64_t p2 = a_hi * b_lo;
    const std::uint64_t p3 = a_hi * b_hi;
    const std::uint64_t mid = (p0 >> 32) + (p1 & 0xffffffffu) + (p2 & 0xffffffffu);
    U128Pair r;
    r.lo = (p0 & 0xffffffffu) | (mid << 32);
    r.hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return r;
}

// Restoring division, one bit at a time: 128 iterations, no wide type. `rem`
// stays below `divisor`, so the shift below cannot overflow for any divisor
// under 2^63 -- which every median, weight and difficulty is.
inline U128Pair div128_64_portable(U128Pair n, std::uint64_t divisor,
                                   std::uint64_t* remainder = nullptr) noexcept {
    U128Pair q{};
    std::uint64_t rem = 0;
    if (divisor == 0) { if (remainder) *remainder = 0; return q; }
    for (int i = 127; i >= 0; --i) {
        const std::uint64_t bit = (i >= 64) ? ((n.hi >> (i - 64)) & 1u)
                                            : ((n.lo >> i) & 1u);
        rem = (rem << 1) | bit;
        if (rem >= divisor) {
            rem -= divisor;
            if (i >= 64) q.hi |= (static_cast<std::uint64_t>(1) << (i - 64));
            else         q.lo |= (static_cast<std::uint64_t>(1) << i);
        }
    }
    if (remainder) *remainder = rem;
    return q;
}

inline U128Pair mul128(std::uint64_t a, std::uint64_t b) noexcept {
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 p = static_cast<unsigned __int128>(a) * b;
    return U128Pair{ static_cast<std::uint64_t>(p >> 64), static_cast<std::uint64_t>(p) };
#else
    return mul128_portable(a, b);
#endif
}

// 128 / 64 -> 128, with the remainder. `divisor` must be non-zero; the quotient
// is only guaranteed to fit when the caller knows it does (monerod asserts it).
inline U128Pair div128_64(U128Pair n, std::uint64_t divisor,
                          std::uint64_t* remainder = nullptr) noexcept {
#if defined(__SIZEOF_INT128__)
    if (divisor == 0) { if (remainder) *remainder = 0; return U128Pair{}; }
    const unsigned __int128 v = (static_cast<unsigned __int128>(n.hi) << 64) | n.lo;
    const unsigned __int128 q = v / divisor;
    if (remainder) *remainder = static_cast<std::uint64_t>(v % divisor);
    return U128Pair{ static_cast<std::uint64_t>(q >> 64), static_cast<std::uint64_t>(q) };
#else
    return div128_64_portable(n, divisor, remainder);
#endif
}

// --- the base reward ----------------------------------------------------------
enum class RewardStatus : std::uint8_t {
    Ok = 0,
    BlockTooBig,   // weight > 2 * median: monerod refuses to compute a reward
};

inline const char* to_string(RewardStatus s) noexcept {
    switch (s) {
        case RewardStatus::Ok:          return "Ok";
        case RewardStatus::BlockTooBig: return "BlockTooBig";
    }
    return "?";
}

// The emission term alone (no weight penalty): what a block of at most the
// median weight pays.
inline std::uint64_t emission_base_reward(std::uint64_t already_generated_coins,
                                          std::uint8_t  version) noexcept {
    const std::uint64_t target = version < 2 ? DIFFICULTY_TARGET_V1_SECONDS
                                             : DIFFICULTY_TARGET_V2_SECONDS;
    const int target_minutes = static_cast<int>(target / 60);
    const int speed_factor   = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes - 1);

    std::uint64_t base = (MONEY_SUPPLY - already_generated_coins)
                       >> static_cast<unsigned>(speed_factor);
    const std::uint64_t tail = FINAL_SUBSIDY_PER_MINUTE * static_cast<std::uint64_t>(target_minutes);
    if (base < tail) base = tail;
    return base;
}

// monerod get_block_reward, penalty included. `reward` is the BASE reward the
// coinbase may pay before fees.
inline RewardStatus get_block_reward(std::uint64_t median_weight,
                                     std::uint64_t current_block_weight,
                                     std::uint64_t already_generated_coins,
                                     std::uint8_t  version,
                                     std::uint64_t& reward) noexcept {
    reward = 0;
    const std::uint64_t base = emission_base_reward(already_generated_coins, version);

    const std::uint64_t zone = min_block_weight(version);
    if (median_weight < zone) median_weight = zone;

    if (current_block_weight <= median_weight) {
        reward = base;
        return RewardStatus::Ok;
    }
    if (current_block_weight > 2 * median_weight) return RewardStatus::BlockTooBig;

    // multiplicand = (2*median - weight) * weight, then base * multiplicand in
    // 128 bits, then two 128/64 divisions by the median. Order and rounding are
    // monerod's; see the header comment.
    std::uint64_t multiplicand = 2 * median_weight - current_block_weight;
    multiplicand *= current_block_weight;

    U128Pair product = mul128(base, multiplicand);
    U128Pair r = div128_64(product, median_weight);
    r = div128_64(r, median_weight);
    // monerod asserts both of these; a peer block that violated them would be
    // rejected rather than paid, so they are checks here, not assertions.
    if (r.hi != 0 || r.lo >= base) return RewardStatus::BlockTooBig;

    reward = r.lo;
    return RewardStatus::Ok;
}

// --- the emission accumulator -------------------------------------------------
// blockchain.cpp: fees are NOT emission. Saturating, never wrapping.
inline std::uint64_t accumulate_generated_coins(std::uint64_t already_generated_coins,
                                                std::uint64_t base_reward) noexcept {
    return base_reward < (MONEY_SUPPLY - already_generated_coins)
         ? already_generated_coins + base_reward
         : MONEY_SUPPLY;
}

// The inverse, for a reorg: the value before the block was applied. Exact for
// every non-saturating step, which is every step a real chain takes.
inline std::uint64_t unaccumulate_generated_coins(std::uint64_t already_generated_coins,
                                                  std::uint64_t base_reward) noexcept {
    return already_generated_coins >= base_reward ? already_generated_coins - base_reward : 0;
}

// --- the coinbase check -------------------------------------------------------
// monerod validate_miner_transaction, whose shape is not the obvious one:
//
//   * the coinbase may never pay MORE than base_reward + fee;
//   * below v2 and from HF_VERSION_EXACT_COINBASE (13) it must pay EXACTLY
//     that -- a short coinbase is invalid;
//   * between v2 and v13 a miner was allowed to claim LESS (to avoid dust), and
//     the shortfall was NOT emitted: monerod rewrites the recorded base reward
//     to money_in_use - fee, so already_generated_coins grows by the smaller
//     number and the unclaimed part stays in the supply for later blocks.
//
// The last rule is why this returns the EFFECTIVE base reward rather than a
// bool: an index that accumulated the nominal reward for a v2..v12 block would
// drift the emission curve away from the chain's, silently and permanently.
inline constexpr std::uint8_t HF_VERSION_EXACT_COINBASE = 13;
inline constexpr std::uint8_t HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY = 12;

struct CoinbaseCheck {
    bool          ok            = false;
    bool          partial       = false;  // claimed less than allowed (v2..v12 only)
    std::uint64_t expected      = 0;      // base_reward + fees
    std::uint64_t effective_base = 0;     // what already_generated_coins must grow by
};

inline CoinbaseCheck check_coinbase_amount(std::uint64_t money_in_use,
                                           std::uint64_t base_reward,
                                           std::uint64_t fees,
                                           std::uint8_t  version) noexcept {
    CoinbaseCheck c;
    c.expected       = base_reward + fees;
    c.effective_base = base_reward;
    if (money_in_use > c.expected) return c;          // spends too much

    if (version < 2 || version >= HF_VERSION_EXACT_COINBASE) {
        c.ok = (money_in_use == c.expected);
        return c;
    }
    // v2 .. v12: a short claim is legal and reduces the emission actually made.
    if (money_in_use < fees) return c;                // cannot be, but never wrap
    c.partial        = (money_in_use != c.expected);
    c.effective_base = money_in_use - fees;
    c.ok             = true;
    return c;
}

// Which median the penalty is computed against: the EFFECTIVE (short-term
// bounded by long-term) median from v12, the plain 100-block median before it.
inline std::uint64_t penalty_median(std::uint64_t effective_median,
                                    std::uint64_t short_term_median,
                                    std::uint8_t  version) noexcept {
    return version >= HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY
         ? effective_median : short_term_median;
}

} // namespace c2pool::xmr::native
