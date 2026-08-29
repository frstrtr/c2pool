// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// BCH ASERT (aserti3-2d) difficulty adjustment — net-new BCH-specific code.
//
// BCH replaced BTC's 2016-block 2-week retarget with ASERT at the Nov 2020
// upgrade (CHIP-2020-05). This is one of the two BCH-specific validation
// slices (M1 §4.3); it has NO analogue in src/impl/btc/.
//
// CalculateASERT() is a 1:1 fixed-point port of Bitcoin Cash Node
// src/pow.cpp:185 CalculateASERT() (decl src/pow.h:43). It is consensus
// critical and MUST stay byte-exact with BCHN — it is validated directly
// against BCHN's gold vectors (contrib/testgen/gen_asert_test_vectors.cpp,
// src/test/pow_tests.cpp). Anchor constants are from BCHN src/chainparams.cpp.
//
// NOTE: PoW HASH is unchanged (SHA256d, byte-identical to BTC — BCH is a
// standalone SHA256d parent). ASERT governs only the *target* a header must
// meet, i.e. which headers the SPV engine accepts as valid chain. It does
// NOT touch share format / PoW hash, so there is no p2pool-merged-v36
// surface change.

#include <core/uint256.hpp>

#include <cassert>
#include <cstdint>
#include <cstdlib>   // llabs

namespace bch {
namespace coin {

// ─── ASERT anchor block ──────────────────────────────────────────────────
// Per BCHN absolute-ASERT formulation the reference timestamp is the anchor
// block's *parent* timestamp (block M-1 when the anchor is block M).
struct ASERTAnchor {
    int64_t  height{0};          // anchor block height
    uint32_t nBits{0};           // anchor block nBits (compact target)
    int64_t  prev_block_time{0}; // anchor block PREVIOUS block timestamp
};

// Canonical anchors (BCHN src/chainparams.cpp).
struct ASERTParams {
    ASERTAnchor anchor;
    int64_t     half_life;        // nASERTHalfLife (seconds)
    int64_t     target_spacing;   // nPowTargetSpacing (seconds) = 600
    bool        allow_min_difficulty{false};
    uint256     pow_limit;
};

// nPowTargetSpacing is 600 s (10 min) on every BCH chain.
static constexpr int64_t BCH_TARGET_SPACING = 10 * 60;

inline uint256 bch_pow_limit() {
    // BCH mainnet/testnet powLimit (BCHN chainparams.cpp).
    uint256 v;
    v.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return v;
}

inline ASERTParams asert_mainnet() {
    return ASERTParams{
        ASERTAnchor{661647, 0x1804dafe, 1605447844},
        2 * 24 * 60 * 60,        // nASERTHalfLife = 2 days
        BCH_TARGET_SPACING,
        false,
        bch_pow_limit(),
    };
}

inline ASERTParams asert_testnet3() {
    return ASERTParams{
        ASERTAnchor{1421481, 0x1d00ffff, 1605445400},
        60 * 60,                 // nASERTHalfLife = 1 hour
        BCH_TARGET_SPACING,
        true,
        bch_pow_limit(),
    };
}

inline uint256 bch_pow_limit_regtest() {
    // BCH regtest powLimit (BCHN CRegTestParams). NOTE: top byte 0x7f does NOT
    // satisfy CalculateASERT's 32-leading-zero-bits invariant -- which is why
    // regtest runs with fPowNoRetargeting (ASERT is never invoked on regtest).
    uint256 v;
    v.SetHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return v;
}

/// BCH regtest difficulty params (BCHN CRegTestParams). fPowNoRetargeting=true,
/// so the required target is fixed at the powLimit nBits (0x207fffff) for every
/// block -- ASERT is bypassed (header_chain honours BCHChainParams::no_retargeting).
/// The anchor here is nominal (genesis) and never feeds CalculateASERT.
/// allow_min_difficulty mirrors BCHN regtest. (FINDING3: regtest must be its own
/// net so --pool --regtest serves diff-1 0x207fffff, not the testnet anchor.)
inline ASERTParams asert_regtest() {
    return ASERTParams{
        ASERTAnchor{0, 0x207fffff, 1296688602},  // genesis nBits/time (nominal)
        2 * 24 * 60 * 60,
        BCH_TARGET_SPACING,
        true,
        bch_pow_limit_regtest(),
    };
}

inline ASERTParams asert_testnet4() {
    return ASERTParams{
        ASERTAnchor{16844, 0x1d00ffff, 1605451779},
        60 * 60,
        BCH_TARGET_SPACING,
        true,
        bch_pow_limit(),
    };
}

// ─── CalculateASERT ────────────────────────────────────────────────────────
// 1:1 port of BCHN src/pow.cpp CalculateASERT(). Integer (fixed-point) math
// only — MUST remain byte-exact with BCHN.
//
//   new_target = old_target * 2^((time_diff - spacing*(height_diff+1)) / halflife)
inline uint256 CalculateASERT(const uint256& refTarget,
                              const int64_t nPowTargetSpacing,
                              const int64_t nTimeDiff,
                              const int64_t nHeightDiff,
                              const uint256& powLimit,
                              const int64_t nHalfLife) noexcept {
    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > uint256::ZERO && refTarget <= powLimit);

    // 32 leading zero bits in powLimit give room to handle overflows easily.
    assert((powLimit >> 224) == uint256::ZERO);

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // Compute the exponent (fixed-point, 16 fractional bits).
    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));
    const int64_t exponent =
        ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    // Arithmetic right shift of negative numbers is standard in C++20.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    // Decompose exponent into integer and fractional parts.
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3), 0 <= x < 1
    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);
    // always < 2^241 since refTarget < 2^224
    uint256 nextTarget = refTarget * factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0) {
        nextTarget >>= int(-shifts);
    } else {
        const uint256 nextTargetShifted = nextTarget << int(shifts);
        if ((nextTargetShifted >> int(shifts)) != nextTarget) {
            // Would have overflowed 2^256 → clamps to powLimit anyway.
            nextTarget = powLimit;
        } else {
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == uint256::ZERO) {
        nextTarget = uint256::ONE; // 0 is not a valid target, but 1 is.
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    return nextTarget;
}

// ─── Anchor-formulated next-work entry ──────────────────────────────────────
// Mirrors btc::coin::get_next_work_required()'s role but uses the absolute
// ASERT anchor formulation (BCHN GetNextASERTWorkRequired, src/pow.cpp:101).
// Returns the compact nBits the block at (tip_height+1) must meet.
//
// @param tip_height  height of the block we build on (>= anchor height)
// @param tip_time    timestamp of the tip block
// @param new_time    timestamp of the new block (for testnet min-diff rule)
inline uint32_t get_next_work_required_asert(uint32_t tip_height,
                                             int64_t tip_time,
                                             int64_t new_time,
                                             const ASERTParams& p) {
    // Testnet special rule: >2*spacing since tip → allow a min-difficulty block.
    if (p.allow_min_difficulty &&
        new_time > tip_time + 2 * p.target_spacing) {
        return p.pow_limit.GetCompact();
    }

    assert(static_cast<int64_t>(tip_height) >= p.anchor.height);

    uint256 refBlockTarget;
    refBlockTarget.SetCompact(p.anchor.nBits);

    // Time diff is measured from the anchor's PARENT timestamp (absolute ASERT).
    const int64_t nTimeDiff   = tip_time - p.anchor.prev_block_time;
    const int64_t nHeightDiff = static_cast<int64_t>(tip_height) - p.anchor.height;

    const uint256 nextTarget = CalculateASERT(refBlockTarget,
                                              p.target_spacing,
                                              nTimeDiff,
                                              nHeightDiff,
                                              p.pow_limit,
                                              p.half_life);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

} // namespace coin
} // namespace bch