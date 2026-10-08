// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Scrypt.hpp"

#include <crypto/scrypt.h>   // btclibs: PBKDF2_SHA256 (reused), le32dec/le32enc

#include <cstring>
#include <stdexcept>

namespace c2w::hdkeys {

namespace {

// Salsa20/8 core on a 64-byte block, in place (operates on 16 LE uint32).
void salsa20_8(uint8_t B[64])
{
    uint32_t x[16], in[16];
    for (int i = 0; i < 16; ++i) x[i] = in[i] = le32dec(B + 4 * i);
    auto R = [](uint32_t a, int b) { return (a << b) | (a >> (32 - b)); };
    for (int i = 0; i < 4; ++i) {  // 8 rounds = 4 double-rounds
        x[ 4] ^= R(x[ 0] + x[12], 7);  x[ 8] ^= R(x[ 4] + x[ 0], 9);
        x[12] ^= R(x[ 8] + x[ 4],13);  x[ 0] ^= R(x[12] + x[ 8],18);
        x[ 9] ^= R(x[ 5] + x[ 1], 7);  x[13] ^= R(x[ 9] + x[ 5], 9);
        x[ 1] ^= R(x[13] + x[ 9],13);  x[ 5] ^= R(x[ 1] + x[13],18);
        x[14] ^= R(x[10] + x[ 6], 7);  x[ 2] ^= R(x[14] + x[10], 9);
        x[ 6] ^= R(x[ 2] + x[14],13);  x[10] ^= R(x[ 6] + x[ 2],18);
        x[ 3] ^= R(x[15] + x[11], 7);  x[ 7] ^= R(x[ 3] + x[15], 9);
        x[11] ^= R(x[ 7] + x[ 3],13);  x[15] ^= R(x[11] + x[ 7],18);
        x[ 1] ^= R(x[ 0] + x[ 3], 7);  x[ 2] ^= R(x[ 1] + x[ 0], 9);
        x[ 3] ^= R(x[ 2] + x[ 1],13);  x[ 0] ^= R(x[ 3] + x[ 2],18);
        x[ 6] ^= R(x[ 5] + x[ 4], 7);  x[ 7] ^= R(x[ 6] + x[ 5], 9);
        x[ 4] ^= R(x[ 7] + x[ 6],13);  x[ 5] ^= R(x[ 4] + x[ 7],18);
        x[11] ^= R(x[10] + x[ 9], 7);  x[ 8] ^= R(x[11] + x[10], 9);
        x[ 9] ^= R(x[ 8] + x[11],13);  x[10] ^= R(x[ 9] + x[ 8],18);
        x[12] ^= R(x[15] + x[14], 7);  x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12],13);  x[15] ^= R(x[14] + x[13],18);
    }
    for (int i = 0; i < 16; ++i) le32enc(B + 4 * i, x[i] + in[i]);
}

// BlockMix on 2r 64-byte blocks: B (in) -> Y (out).
void blockmix_salsa8(const uint8_t* B, uint8_t* Y, uint32_t r)
{
    uint8_t X[64];
    std::memcpy(X, B + (2 * r - 1) * 64, 64);
    for (uint32_t i = 0; i < 2 * r; ++i) {
        for (int k = 0; k < 64; ++k) X[k] ^= B[i * 64 + k];
        salsa20_8(X);
        // even i -> first half, odd i -> second half (scrypt output permutation)
        uint8_t* dst = Y + ((i / 2) + (i & 1 ? r : 0)) * 64;
        std::memcpy(dst, X, 64);
    }
}

uint64_t integerify(const uint8_t* B, uint32_t r, uint64_t N)
{
    // Last 64-byte block's first 4 bytes, little-endian, mod N (N < 2^32 here).
    uint32_t j = le32dec(B + (2 * r - 1) * 64);
    return static_cast<uint64_t>(j) & (N - 1);  // N is a power of two
}

void romix(uint8_t* B, uint32_t r, uint64_t N, uint8_t* V, uint8_t* scratch)
{
    const size_t blk = 128u * r;
    uint8_t* X = scratch;                 // blk bytes
    uint8_t* Y = scratch + blk;           // blk bytes
    std::memcpy(X, B, blk);
    for (uint64_t i = 0; i < N; ++i) {
        std::memcpy(V + i * blk, X, blk);
        blockmix_salsa8(X, Y, r);
        std::memcpy(X, Y, blk);
    }
    for (uint64_t i = 0; i < N; ++i) {
        uint64_t j = integerify(X, r, N);
        for (size_t k = 0; k < blk; ++k) X[k] ^= V[j * blk + k];
        blockmix_salsa8(X, Y, r);
        std::memcpy(X, Y, blk);
    }
    std::memcpy(B, X, blk);
}

} // namespace

std::vector<uint8_t> scrypt_general(const uint8_t* passwd, size_t passwd_len,
                                    const uint8_t* salt, size_t salt_len,
                                    uint64_t N, uint32_t r, uint32_t p, size_t dkLen)
{
    if (N < 2 || (N & (N - 1)) != 0) throw std::invalid_argument("scrypt: N must be a power of two > 1");
    if (r == 0 || p == 0) throw std::invalid_argument("scrypt: r and p must be >= 1");
    if (N > 0xFFFFFFFFull) throw std::invalid_argument("scrypt: N too large for 32-bit integerify");

    const size_t blk = 128u * static_cast<size_t>(r);
    std::vector<uint8_t> B(blk * p);
    PBKDF2_SHA256(passwd, passwd_len, salt, salt_len, 1, B.data(), B.size());

    std::vector<uint8_t> V(blk * static_cast<size_t>(N));
    std::vector<uint8_t> scratch(2 * blk);
    for (uint32_t i = 0; i < p; ++i)
        romix(B.data() + i * blk, r, N, V.data(), scratch.data());

    std::vector<uint8_t> out(dkLen);
    PBKDF2_SHA256(passwd, passwd_len, B.data(), B.size(), 1, out.data(), dkLen);

    std::memset(V.data(), 0, V.size());
    std::memset(scratch.data(), 0, scratch.size());
    std::memset(B.data(), 0, B.size());
    return out;
}

} // namespace c2w::hdkeys
