/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 *
 * c2pool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * c2pool is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with c2pool. If not, see <https://www.gnu.org/licenses/>.
 */

// -----------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_coin_primitives.hpp
//
// CONSUMER-SIDE SEAM DECLARATION for the whole-block template builder.
//
// This header declares ONLY the surface the template builder consumes from the
// Monero primitives leg (varint/blob serialisation, Keccak-256 with midstate
// export, 128-bit difficulty, 128-bit mul/div, the parallel helper). It defines
// no bodies: the monero-primitives leg (X1) owns those, ported from
// tevador/RandomX + monero-project crypto-ops (both BSD-3) and Monero keccak.c.
//
// It exists here so this leg can be reasoned about and syntax-checked against a
// fixed contract without pulling the whole tree. When the trees are joined,
// delete this file and include the real headers from src/impl/xmr/coin/.
// The Monero symbol names below mirror p2pool's so the seam is a drop-in.
// -----------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <functional>

namespace c2pool::xmr {

// ---- fixed-width hash (Monero crypto::hash / p2pool `hash`) ----
constexpr size_t HASH_SIZE = 32;

struct hash {
    uint8_t h[HASH_SIZE];
    hash() : h{} {}
    bool operator==(const hash& o) const {
        for (size_t i = 0; i < HASH_SIZE; ++i) if (h[i] != o.h[i]) return false;
        return true;
    }
};

// ---- 128-bit difficulty (Monero difficulty_type; work(T) is a u64 in the lane) ----
struct difficulty_type {
    uint64_t lo = 0;
    uint64_t hi = 0;
};

// ---- CryptoNote varint (LEB128, 7 bits/byte) ----
// Two forms mirror p2pool: append-to-vector, and byte-callback (used to size a
// varint without materialising it — see get_reward_amounts_weight()).
void writeVarint(uint64_t value, std::vector<uint8_t>& out);

template <typename T>
void writeVarint(uint64_t value, T&& byte_sink) {
    while (value >= 0x80) {
        byte_sink(static_cast<uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    byte_sink(static_cast<uint8_t>(value));
}

// ---- Keccak-256 (Monero keccak.c; state = 25 * uint64, rate 136 B) ----
struct KeccakParams {
    static constexpr int HASH_DATA_AREA = 136; // bitrate r for keccak-256 / SHA3-256
};

// One-shot: md must hold mdlen bytes (32 for a Monero hash).
void keccak(const uint8_t* in, size_t inlen, uint8_t* md, int mdlen = static_cast<int>(HASH_SIZE));

// Absorb `inlen` bytes (a whole multiple of HASH_DATA_AREA) into `state`,
// leaving the sponge open. Used to cache the miner-tx prefix up to tx_extra.
void keccak_step(const uint8_t* in, int inlen, std::array<uint64_t, 25>& state);

// Absorb the remaining `inlen` (< HASH_DATA_AREA-completing) bytes into an
// already-stepped `state`, pad, and finalise; the 32-byte digest is the first
// 4 words of `state`.
void keccak_finish(const uint8_t* in, int inlen, std::array<uint64_t, 25>& state);

// Streaming one-shot where each input byte is produced by `byte_at(offset)`.
// Lets the coinbase be hashed with the extra-nonce and commitment-root patched
// in-place without mutating the stored template. md holds mdlen bytes.
// (Reference body; the real tree replaces this with the in-place absorbing loop
// from Monero keccak.c so no intermediate buffer is allocated.)
template <typename Func>
inline void keccak_custom(Func&& byte_at, int inlen, uint8_t* md, int mdlen) {
    std::vector<uint8_t> buf(static_cast<size_t>(inlen));
    for (int i = 0; i < inlen; ++i) buf[static_cast<size_t>(i)] = byte_at(i);
    keccak(buf.data(), static_cast<size_t>(inlen), md, mdlen);
}

// ---- 128-bit multiply / divide (compiler intrinsics in the real tree) ----
uint64_t umul128(uint64_t a, uint64_t b, uint64_t* hi);
uint64_t udiv128(uint64_t numhi, uint64_t numlo, uint64_t den, uint64_t* rem);

// ---- fan-out helper (thread pool in the real tree) ----
// Runs `f` on the worker pool; if `wait` the call returns after all copies join.
void parallel_run(const std::function<void()>& f, bool wait);

// ---- wall clock (p2pool seconds_since_epoch) ----
uint64_t seconds_since_epoch();

} // namespace c2pool::xmr
