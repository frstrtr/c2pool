#pragma once
// BCH ABLA (Adaptive Blocksize-Limit Algorithm, CHIP-2023-01) -- net-new
// BCH-specific code. Activated at the May 2024 upgrade; it replaces the static
// 32 MB excessive-blocksize (EB) with a control function that lets the network
// block-size limit grow with sustained demand.
//
// This is a 1:1 fixed-point port of Bitcoin Cash Node:
//   src/consensus/abla.cpp  (State::NextBlockState, Config::MakeDefault/SetMax)
//   src/consensus/abla.h    (Config / State data types)
// pinned at BCHN tag v29.0.0 (clone @89a591f). It is consensus-critical and
// MUST stay byte-exact with BCHN -- validate against BCHN gold vectors
// src/test/data/abla_test_vectors (gen: generate_abla_test_vectors.py).
//
// p2pool-merged-v36 SURFACE: NONE. ABLA governs only the *block-size limit*,
// i.e. how large a block a node will accept / how large a template we may
// build. It does NOT touch PoW hash, share format, coinbase commitment, or
// PPLNS math. In the template builder it is used purely as a LOCAL build-time
// byte budget; using a conservative (floor) value can never produce an
// invalid block, so there is zero compat risk. -- M4 size-slice (M1 ss4.4).
//
// Mainnet: MakeDefault(32 MB, fixedSize=false) -> grows.
// testnet3 / testnet4: MakeDefault(32 MB, fixedSize=true) -> no-op, fixed 32 MB.

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>

namespace bch {
namespace coin {
namespace abla {

// ONE_MEGABYTE / consensus block-size constants -- BCHN src/consensus/consensus.h
inline constexpr uint64_t ONE_MEGABYTE                = 1000000u;
inline constexpr uint64_t DEFAULT_CONSENSUS_BLOCK_SIZE = 32u * ONE_MEGABYTE;
inline constexpr uint64_t MAX_CONSENSUS_BLOCK_SIZE     = uint64_t(2000) * ONE_MEGABYTE;

// 2^7 fixed precision for the "asymmetry factor" (zeta). BCHN abla.h B7.
inline constexpr uint64_t B7 = 1u << 7u;

// muldiv(x,y,z) = x*y/z in 128-bit intermediate (BCHN abla.cpp). The platform
// is gcc/clang C++20 on linux -> use the native __int128 path BCHN selects.
inline uint64_t muldiv(uint64_t x, uint64_t y, uint64_t z) {
    assert(z != 0);
    const unsigned __int128 res =
        (static_cast<unsigned __int128>(x) * static_cast<unsigned __int128>(y))
        / static_cast<unsigned __int128>(z);
    assert(res <= static_cast<unsigned __int128>(std::numeric_limits<uint64_t>::max()));
    return static_cast<uint64_t>(res);
}

// Algorithm configuration -- part of a chain's consensus params (BCHN abla.h).
struct Config {
    uint64_t epsilon0{};         // initial/floor control block size
    uint64_t beta0{};            // initial/floor elastic buffer size
    uint64_t gammaReciprocal{};  // reciprocal of control "forget factor"
    uint64_t zeta_xB7{};         // control "asymmetry factor" (x B7)
    uint64_t thetaReciprocal{};  // reciprocal of elastic buffer decay rate
    uint64_t delta{};            // elastic buffer "gear factor"
    uint64_t epsilonMax{};       // max control block size
    uint64_t betaMax{};          // max elastic buffer size

    // Set epsilonMax / betaMax so internal ops can't overflow UINT64_MAX.
    // 1:1 BCHN Config::SetMax.
    void SetMax() {
        const uint64_t maxSafeBlocksizeLimit =
            std::numeric_limits<uint64_t>::max() / zeta_xB7 * B7;
        const uint64_t maxElasticBufferRatioNumerator =
            delta * ((zeta_xB7 - B7) * thetaReciprocal / gammaReciprocal);
        const uint64_t maxElasticBufferRatioDenominator =
            (zeta_xB7 - B7) * thetaReciprocal / gammaReciprocal + B7;
        epsilonMax = maxSafeBlocksizeLimit
            / (maxElasticBufferRatioNumerator + maxElasticBufferRatioDenominator)
            * maxElasticBufferRatioDenominator;
        betaMax = maxSafeBlocksizeLimit - epsilonMax;
    }

    bool IsFixedSize() const {
        return epsilon0 == epsilonMax && beta0 == betaMax;
    }

    // 1:1 BCHN Config::MakeDefault.
    static Config MakeDefault(uint64_t defaultBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE,
                              bool fixedSize = false) {
        Config ret;
        ret.epsilon0        = defaultBlockSize / 2u;
        ret.beta0           = defaultBlockSize / 2u;
        ret.gammaReciprocal = 37938;
        ret.zeta_xB7        = 192;
        ret.thetaReciprocal = 37938;
        ret.delta           = 10;
        if (!fixedSize) {
            ret.SetMax();
        } else {
            ret.epsilonMax = ret.epsilon0;
            ret.betaMax    = ret.beta0;
        }
        return ret;
    }
};

// Algorithm internal state for block N. The limit for block N is
// state_N.GetBlockSizeLimit(); for N+1 use NextBlockState(...).GetBlockSizeLimit().
class State {
    uint64_t blockSize{};
    uint64_t controlBlockSize{};
    uint64_t elasticBufferSize{};

public:
    State() = default;

    // Defaults from Config -- suitable for all blocks before ABLA activation
    // (the activation/floor state). 1:1 BCHN State(config, blkSize).
    State(const Config& config, uint64_t blkSize)
        : blockSize(blkSize),
          controlBlockSize(config.epsilon0),
          elasticBufferSize(config.beta0) {}

    uint64_t GetBlockSizeLimit(bool disable2GBCap = false) const {
        if (disable2GBCap)
            return controlBlockSize + elasticBufferSize;
        return std::min<uint64_t>(controlBlockSize + elasticBufferSize,
                                  MAX_CONSENSUS_BLOCK_SIZE);
    }

    uint64_t GetNextBlockSizeLimit(const Config& config, bool disable2GBCap = false) const {
        return NextBlockState(config, 0).GetBlockSizeLimit(disable2GBCap);
    }

    uint64_t GetBlockSize() const { return blockSize; }
    uint64_t GetControlBlockSize() const { return controlBlockSize; }
    uint64_t GetElasticBufferSize() const { return elasticBufferSize; }

    // Advance state to block N+1 given its size. 1:1 BCHN State::NextBlockState.
    State NextBlockState(const Config& config, const uint64_t nextBlockSize) const {
        State ret;
        ret.blockSize = nextBlockSize;

        // control function
        const uint64_t clampedBlockSize =
            std::min(this->blockSize, this->controlBlockSize + this->elasticBufferSize);
        const uint64_t amplifiedCurrentBlockSize =
            muldiv(config.zeta_xB7, clampedBlockSize, B7);

        if (amplifiedCurrentBlockSize > this->controlBlockSize) {
            const uint64_t bytesToAdd = amplifiedCurrentBlockSize - this->controlBlockSize;
            const uint64_t amplifiedBlockSizeLimit =
                muldiv(config.zeta_xB7, this->controlBlockSize + this->elasticBufferSize, B7);
            const uint64_t bytesMax = amplifiedBlockSizeLimit - this->controlBlockSize;
            const uint64_t scalingOffset =
                muldiv(muldiv(config.zeta_xB7, this->elasticBufferSize, B7), bytesToAdd, bytesMax);
            ret.controlBlockSize =
                this->controlBlockSize + (bytesToAdd - scalingOffset) / config.gammaReciprocal;
        } else {
            const uint64_t bytesToRemove = this->controlBlockSize - amplifiedCurrentBlockSize;
            ret.controlBlockSize = this->controlBlockSize - bytesToRemove / config.gammaReciprocal;
            ret.controlBlockSize = std::max(ret.controlBlockSize, config.epsilon0);
        }

        // elastic buffer function
        const uint64_t bufferDecay = this->elasticBufferSize / config.thetaReciprocal;
        if (amplifiedCurrentBlockSize > this->controlBlockSize) {
            const uint64_t bytesToAdd =
                (ret.controlBlockSize - this->controlBlockSize) * config.delta;
            ret.elasticBufferSize = this->elasticBufferSize - bufferDecay + bytesToAdd;
        } else {
            ret.elasticBufferSize = this->elasticBufferSize - bufferDecay;
        }
        ret.elasticBufferSize = std::max(ret.elasticBufferSize, config.beta0);

        ret.controlBlockSize  = std::min(ret.controlBlockSize, config.epsilonMax);
        ret.elasticBufferSize = std::min(ret.elasticBufferSize, config.betaMax);
        return ret;
    }
};

// Per-network config. Mainnet grows; testnets are fixed at 32 MB.
inline Config mainnet_config()  { return Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, /*fixedSize=*/false); }
inline Config testnet_config()  { return Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, /*fixedSize=*/true);  }

// Replay ABLA forward from a known-good anchor State over a contiguous run of
// block sizes (oldest-first), returning the State *after the last size supplied*
// -- i.e. the State whose GetBlockSizeLimit() governs the block we are about to
// build. 1:1 BCHN: repeated State::NextBlockState. The anchor MUST be the ABLA
// State of the block immediately preceding sizes[0].
//
// NOTE on the size feed: ABLA is driven by each block's *actual serialized
// size*, which the headers-only SPV header_chain structurally does not carry.
// The natural anchor on BCH is therefore a BCHN-pinned {height,State}; the live
// per-block sizes enter at the full-block / embedded-daemon layer (M5+), not
// here. Until that feed exists the template builder stays on the safe floor
// (see floor_block_size_limit / template_builder build budget).
inline State replay(State anchor, const Config& config,
                    const uint64_t* sizes, size_t n) {
    State s = anchor;
    for (size_t i = 0; i < n; ++i)
        s = s.NextBlockState(config, sizes[i]);
    return s;
}

// Conservative LOCAL build budget for the template builder when per-tip ABLA
// state is not yet replayed through the header chain: the activation/floor
// state. ABLA only ever raises the limit above this floor, so building to the
// floor can never exceed the live consensus limit. The dynamic path is
// abla::replay (above) fed a BCHN-pinned anchor + full-block sizes; that feed
// lives at the full-block/daemon layer, not the headers-only SPV chain.
inline uint64_t floor_block_size_limit(bool is_testnet) {
    const Config cfg = is_testnet ? testnet_config() : mainnet_config();
    return State(cfg, 0).GetBlockSizeLimit();
}

} // namespace abla
} // namespace coin
} // namespace bch
