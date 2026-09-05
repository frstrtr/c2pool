// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB MultiShield V4 next-target -- the DigiByte MAINNET Scrypt retarget rule.
//
// DigiByte's live difficulty algorithm (tip height >> workComputationChangeTarget
// == 1,430,000) is GetNextWorkRequiredV4 (DigiByte-Core src/pow.cpp). It is a
// GLOBAL 5-algo averaging window with a per-algo adjustment: the timespan is
// measured over the last NUM_ALGOS*nAveragingInterval == 50 blocks of ALL algos
// (via MedianTimePast deltas), the base target is the nearest same-algo
// ancestor's nBits, and a per-algo correction of NUM_ALGOS-1 minus the same-algo
// depth pulls it toward the shared cadence. This header ports that rule VERBATIM
// so the daemonless DGB arm can derive the next block's nBits from the synced
// header chain instead of fabricating diff-1 (0x1d00ffff), which made every won
// block INVALID and every sharechain share weigh against a fake coin target.
//
// SSOT: DigiByte-Core src/pow.cpp GetNextWorkRequiredV4 + consensus params
// (chainparams.cpp CMainParams). The port is empirically pinned: verify_v4.py
// re-implements this exact math and reproduces 89/89 real mainnet nBits
// (all 5 algos, nAdjustments >0/=0/<0) byte-exact; the KAT feeds the SAME 150
// vectors through this code.
//
// Header-only + std-only (depends on dgb_arith256.hpp and dgb_block_algo.hpp,
// both <cstdint>-only), so it links into the standalone GTest guard with NO
// btclibs / arith_uint256 dependency -- the same constraint header_chain.hpp's
// retarget math already lives under. The heavy 256-bit multiply/divide runs at
// true arith_uint256 width via u256 (dgb_arith256.hpp), reproducing the
// consensus overflow-truncation DigiByte-Core exhibits near powLimit.
//
// SCOPE: MAINNET only. Testnet/regtest fPowAllowMinDifficultyBlocks paths (the
// 2-minute min-diff reset and the GetLastBlockIndexForAlgoFast min-diff skip)
// are NOT ported -- the daemonless arm this feeds is mainnet-pinned. The V1/V2/V3
// dispatch below workComputationChangeTarget is likewise moot: DGB is ~24.1M
// blocks in, well past the 1.43M V4 switch.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>

#include <impl/dgb/coin/dgb_arith256.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>

namespace dgb::coin {

// DigiByte mainnet powLimit for the Scrypt/multi-algo family: (~uint256(0) >> 20)
// == arith_uint256 all-ones shifted right 20. Compact form is 0x1e0fffff. This
// is the EASIEST admissible target; bnNew is capped to it so a stall can never
// relax difficulty past the network minimum. Built limb-wise (dgb_arith256 has
// no shift-construct): bits 0..235 set, bits 236..255 zero.
inline u256 multishield_pow_limit() {
    u256 r;
    r.limb[0] = 0xFFFFFFFFFFFFFFFFULL;
    r.limb[1] = 0xFFFFFFFFFFFFFFFFULL;
    r.limb[2] = 0xFFFFFFFFFFFFFFFFULL;
    r.limb[3] = 0x00000FFFFFFFFFFFULL;   // top 20 bits clear
    return r;
}

// Compact encoding of multishield_pow_limit() -- the KAT pins target_to_compact
// (multishield_pow_limit()) == this literal, the same value DigiByte-Core's
// InitialDifficulty / powLimit.GetCompact() yields.
inline constexpr uint32_t MULTISHIELD_POW_LIMIT_COMPACT = 0x1e0fffffu;

// V4 consensus parameters (DigiByte-Core CMainParams). Literals are independent
// so this header is the single pin; the KAT fails loudly on any drift.
struct MultiShieldV4Params {
    int      num_algos               = 5;    // NUM_ALGOS (Scrypt/SHA256d/Skein/Qubit/Odo)
    int      averaging_interval      = 10;   // nAveragingInterval
    int64_t  target_timespan_v4      = 750;  // nAveragingTargetTimespanV4 = interval*75
    int64_t  min_actual_timespan     = 690;  // nMinActualTimespanV4 = 750*92/100
    int64_t  max_actual_timespan     = 870;  // nMaxActualTimespanV4 = 750*116/100
    int      local_target_adjustment = 4;    // nLocalTargetAdjustment
    u256     pow_limit               = multishield_pow_limit();
};

// Nearest-first view of one header the V4 walk reads. k==0 is the tip (the block
// the next template builds ON); k grows toward older ancestors.
struct MsHeader {
    int32_t  n_version = 0;
    uint32_t n_bits    = 0;
    int64_t  n_time    = 0;
};

// Nearest-first accessor: at(k) returns the header k blocks below the tip
// (at(0) == tip). Depth is the number of valid indices [0, depth).
using MsAccessor = std::function<MsHeader(std::size_t)>;

// DigiByte-Core GetMedianTimePast: median of the timestamps at `center` and its
// (up to) nMedianTimeSpan-1 nearest older ancestors. Reads at(center .. center+10)
// bounded by depth -- exactly the 11-wide window Core walks via pprev.
inline int64_t multishield_mtp_at(const MsAccessor& at, std::size_t depth,
                                  std::size_t center) {
    constexpr std::size_t kMedianTimeSpan = 11;
    int64_t t[kMedianTimeSpan];
    std::size_t n = 0;
    for (std::size_t j = 0; j < kMedianTimeSpan && (center + j) < depth; ++j)
        t[n++] = at(center + j).n_time;
    std::sort(t, t + n);
    return t[n / 2];
}

// Port of GetNextWorkRequiredV4(pindexLast = tip, algo). Returns the compact
// nBits the NEXT block (tip+1) must carry for `algo`, or nullopt when the local
// header window is too shallow to run the walk.
//
// nullopt is a TRUTHFUL absence, NOT DigiByte-Core's InitialDifficulty: Core
// returns InitialDifficulty (powLimit) only at chain genesis, when pindexFirst
// walks off the chain. Here a short window means our SYNC is incomplete, not
// that the chain is young -- returning powLimit would fabricate an easy target
// (the very bug this replaces). The caller must hold work back until the window
// fills (>= 61 headers: 50-back pindexFirst + its 10-ancestor MedianTimePast).
inline std::optional<uint32_t>
multishield_v4_next_bits(const MsAccessor& at, std::size_t depth,
                         const MultiShieldV4Params& params, DgbAlgo algo) {
    constexpr std::size_t kMedianTimeSpan = 11;   // Core nMedianTimeSpan
    const std::size_t first_k =
        static_cast<std::size_t>(params.num_algos) *
        static_cast<std::size_t>(params.averaging_interval);   // 50

    // pindexFirst is `first_k` blocks back; MedianTimePast(pindexFirst) reads its
    // own 10 ancestors, so the deepest index touched is first_k + 10. Require
    // that index to exist (depth >= first_k + kMedianTimeSpan == 61).
    if (depth < first_k + kMedianTimeSpan)
        return std::nullopt;

    // pindexPrevAlgo = GetLastBlockIndexForAlgoFast(tip, algo): nearest header
    // (tip inclusive) whose GetAlgo() matches. On mainnet the min-difficulty skip
    // in the "Fast" variant is dead (fPowAllowMinDifficultyBlocks == false), so a
    // plain nearest-first scan is byte-equivalent.
    std::optional<std::size_t> prev_k;
    for (std::size_t k = 0; k < depth; ++k) {
        if (dgb_block_algo(at(k).n_version) == algo) { prev_k = k; break; }
    }
    if (!prev_k)
        return std::nullopt;   // no same-algo ancestor in the window.

    // nActualTimespan = MTP(tip) - MTP(pindexFirst); damped: TS + (n - TS)/4.
    // C++ integer division truncates toward zero -- the exact behaviour Core
    // relies on for a negative (n - TS).
    int64_t actual = multishield_mtp_at(at, depth, 0)
                   - multishield_mtp_at(at, depth, first_k);
    actual = params.target_timespan_v4 +
             (actual - params.target_timespan_v4) / 4;
    if (actual < params.min_actual_timespan) actual = params.min_actual_timespan;
    if (actual > params.max_actual_timespan) actual = params.max_actual_timespan;

    // Global retarget: bnNew = SetCompact(prevAlgo.nBits) * actual / targetTS.
    // Multiply FIRST, then divide (arith_uint256 ordering, 256-bit truncation).
    u256 bn = compact_to_target(at(*prev_k).n_bits);
    bn = bn.mul_u64(static_cast<uint64_t>(actual))
           .div_u64(static_cast<uint64_t>(params.target_timespan_v4));

    // Per-algo retarget. nAdjustments = prevAlgo.height + NUM_ALGOS - 1 -
    // tip.height. Heights differ only by depth (prevAlgo is prev_k blocks below
    // the tip), so this reduces exactly to (NUM_ALGOS - 1) - prev_k.
    //   > 0  -> same-algo block is "ahead" of cadence: harden (*100 / (100+adj))
    //   < 0  -> behind: ease (*(100+adj) / 100) with an in-loop powLimit cap+break
    const long n_adjust =
        static_cast<long>(params.num_algos) - 1 - static_cast<long>(*prev_k);
    const uint64_t ease =
        static_cast<uint64_t>(100 + params.local_target_adjustment);
    if (n_adjust > 0) {
        for (long i = 0; i < n_adjust; ++i)
            bn = bn.mul_u64(100).div_u64(ease);
    } else if (n_adjust < 0) {
        for (long i = 0; i < -n_adjust; ++i) {
            bn = bn.mul_u64(ease).div_u64(100);
            if (bn > params.pow_limit) { bn = params.pow_limit; break; }
        }
    }

    if (bn > params.pow_limit)
        bn = params.pow_limit;

    return target_to_compact(bn);
}

} // namespace dgb::coin
