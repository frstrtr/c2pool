// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BLAKE2b (RFC 7693) — sequential, unkeyed, variable digest length.
// Clean-room implementation following the algorithm described in RFC 7693.
// Isolated to the BIP-110 coin lane (per-coin isolation invariant).

#include "blake2b.h"

#include <string.h>

// Initialization vector (RFC 7693 section 2.6 — the SHA-512 IV).
static const uint64_t BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// Message-word schedule (RFC 7693 section 2.7).
static const uint8_t BLAKE2B_SIGMA[12][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
};

typedef struct {
    uint64_t h[8];        // chaining state
    uint64_t t[2];        // 128-bit message byte counter
    uint8_t  buf[128];    // input buffer (one block)
    size_t   buflen;      // bytes currently in buf
    size_t   outlen;      // requested digest length
} blake2b_state;

static inline uint64_t load64(const void* src)
{
    const uint8_t* p = (const uint8_t*)src;
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void store64(void* dst, uint64_t w)
{
    uint8_t* p = (uint8_t*)dst;
    p[0] = (uint8_t)(w);       p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32); p[5] = (uint8_t)(w >> 40);
    p[6] = (uint8_t)(w >> 48); p[7] = (uint8_t)(w >> 56);
}

static inline uint64_t rotr64(uint64_t w, unsigned c)
{
    return (w >> c) | (w << (64 - c));
}

#define G(r, i, a, b, c, d)                          \
    do {                                             \
        a = a + b + m[BLAKE2B_SIGMA[r][2 * (i)]];    \
        d = rotr64(d ^ a, 32);                       \
        c = c + d;                                    \
        b = rotr64(b ^ c, 24);                       \
        a = a + b + m[BLAKE2B_SIGMA[r][2 * (i) + 1]];\
        d = rotr64(d ^ a, 16);                       \
        c = c + d;                                    \
        b = rotr64(b ^ c, 63);                       \
    } while (0)

static void blake2b_compress(blake2b_state* S, const uint8_t block[128], int is_last)
{
    uint64_t m[16];
    uint64_t v[16];

    for (int i = 0; i < 16; ++i)
        m[i] = load64(block + i * 8);

    for (int i = 0; i < 8; ++i)
        v[i] = S->h[i];
    v[8]  = BLAKE2B_IV[0];
    v[9]  = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];
    v[12] = BLAKE2B_IV[4] ^ S->t[0];
    v[13] = BLAKE2B_IV[5] ^ S->t[1];
    v[14] = is_last ? ~BLAKE2B_IV[6] : BLAKE2B_IV[6];
    v[15] = BLAKE2B_IV[7];

    for (int r = 0; r < 12; ++r) {
        G(r, 0, v[0], v[4], v[8],  v[12]);
        G(r, 1, v[1], v[5], v[9],  v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8],  v[13]);
        G(r, 7, v[3], v[4], v[9],  v[14]);
    }

    for (int i = 0; i < 8; ++i)
        S->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_increment_counter(blake2b_state* S, uint64_t inc)
{
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

int bip110_blake2b(void* out, size_t out_len, const void* in, size_t in_len)
{
    if (out_len == 0 || out_len > 64)
        return -1;

    blake2b_state S;
    memset(&S, 0, sizeof(S));
    for (int i = 0; i < 8; ++i)
        S.h[i] = BLAKE2B_IV[i];
    S.outlen = out_len;

    // Parameter block, sequential unkeyed mode: the first 8 bytes are
    // digest_length | (key_length << 8) | (fanout << 16) | (depth << 24).
    // key_length = 0, fanout = 1, depth = 1.
    const uint64_t param0 =
        ((uint64_t)out_len) | (0ULL << 8) | (1ULL << 16) | (1ULL << 24);
    S.h[0] ^= param0;

    const uint8_t* p = (const uint8_t*)in;
    size_t left = in_len;

    // Process all but the final block. RFC 7693: a full buffer is only
    // compressed once we know more input (or the final marker) follows.
    while (left > 128) {
        blake2b_increment_counter(&S, 128);
        blake2b_compress(&S, p, 0);
        p += 128;
        left -= 128;
    }

    // Final block, zero-padded to 128 bytes.
    uint8_t block[128];
    memset(block, 0, sizeof(block));
    memcpy(block, p, left);
    blake2b_increment_counter(&S, (uint64_t)left);
    blake2b_compress(&S, block, 1);

    uint8_t full[64];
    for (int i = 0; i < 8; ++i)
        store64(full + i * 8, S.h[i]);
    memcpy(out, full, out_len);

    return 0;
}
