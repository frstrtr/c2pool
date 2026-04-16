#pragma once

// X11 hash algorithm for Dash PoW.
// Pipeline: BLAKE→BMW→GROESTL→SKEIN→JH→KECCAK→LUFFA→CUBEHASH→SHAVITE→SIMD→ECHO
// Uses pure C sph reference implementations (from dashcore v0.16.1.1).

#include "x11/sph_blake.h"
#include "x11/sph_bmw.h"
#include "x11/sph_groestl.h"
#include "x11/sph_skein.h"
#include "x11/sph_jh.h"
#include "x11/sph_keccak.h"
#include "x11/sph_luffa.h"
#include "x11/sph_cubehash.h"
#include "x11/sph_shavite.h"
#include "x11/sph_simd.h"
#include "x11/sph_echo.h"

#include <core/uint256.hpp>

#include <cstring>
#include <span>

namespace dash
{
namespace crypto
{

// 512-bit intermediate hash (used between X11 stages)
struct alignas(64) uint512_t {
    unsigned char data[64]{};

    // Extract lower 256 bits as uint256
    uint256 trim256() const {
        uint256 result;
        std::memcpy(result.data(), data, 32);
        return result;
    }
};

// Compute X11 hash of an 80-byte block header.
// Returns 256-bit hash (lower half of final ECHO-512 output).
inline uint256 hash_x11(const unsigned char* input, size_t len)
{
    uint512_t hash[11];

    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash[0].data);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash[0].data, 64);
    sph_bmw512_close(&ctx_bmw, hash[1].data);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash[1].data, 64);
    sph_groestl512_close(&ctx_groestl, hash[2].data);

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hash[2].data, 64);
    sph_skein512_close(&ctx_skein, hash[3].data);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hash[3].data, 64);
    sph_jh512_close(&ctx_jh, hash[4].data);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash[4].data, 64);
    sph_keccak512_close(&ctx_keccak, hash[5].data);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hash[5].data, 64);
    sph_luffa512_close(&ctx_luffa, hash[6].data);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash[6].data, 64);
    sph_cubehash512_close(&ctx_cubehash, hash[7].data);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash[7].data, 64);
    sph_shavite512_close(&ctx_shavite, hash[8].data);

    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash[8].data, 64);
    sph_simd512_close(&ctx_simd, hash[9].data);

    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash[9].data, 64);
    sph_echo512_close(&ctx_echo, hash[10].data);

    return hash[10].trim256();
}

// Convenience: span-based interface matching core::PowFunc signature
inline uint256 hash_x11(std::span<const unsigned char> header)
{
    return hash_x11(header.data(), header.size());
}

} // namespace crypto
} // namespace dash
