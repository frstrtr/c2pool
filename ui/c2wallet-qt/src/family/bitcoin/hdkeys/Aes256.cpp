// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Aes256.hpp"

#include "../../../secure/SecureString.hpp"

#include <cstring>

namespace c2w::hdkeys {

namespace {

const uint8_t kSBox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

uint8_t g_inv_sbox[256];
bool g_inv_ready = false;

void ensure_inv_sbox()
{
    if (g_inv_ready) return;
    for (int i = 0; i < 256; ++i) g_inv_sbox[kSBox[i]] = static_cast<uint8_t>(i);
    g_inv_ready = true;
}

inline uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1b)); }

// GF(2^8) multiply.
uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

} // namespace

Aes256::Aes256(const uint8_t key[32])
{
    ensure_inv_sbox();
    // Key expansion for Nk=8, Nr=14 -> 60 words (240 bytes).
    const int Nk = 8, Nr = 14;
    std::memcpy(rk_, key, 32);
    uint8_t rcon = 1;
    for (int i = Nk; i < 4 * (Nr + 1); ++i) {
        uint8_t t[4];
        std::memcpy(t, rk_ + 4 * (i - 1), 4);
        if (i % Nk == 0) {
            uint8_t tmp = t[0];
            t[0] = static_cast<uint8_t>(kSBox[t[1]] ^ rcon);
            t[1] = kSBox[t[2]];
            t[2] = kSBox[t[3]];
            t[3] = kSBox[tmp];
            rcon = xtime(rcon);
        } else if (i % Nk == 4) {
            for (int j = 0; j < 4; ++j) t[j] = kSBox[t[j]];
        }
        for (int j = 0; j < 4; ++j)
            rk_[4 * i + j] = static_cast<uint8_t>(rk_[4 * (i - Nk) + j] ^ t[j]);
    }
}

Aes256::~Aes256()
{
    secure::secure_wipe(rk_, sizeof(rk_));
}

void Aes256::encrypt_block(const uint8_t in[16], uint8_t out[16]) const
{
    const int Nr = 14;
    uint8_t s[16];
    std::memcpy(s, in, 16);
    for (int i = 0; i < 16; ++i) s[i] ^= rk_[i];  // AddRoundKey round 0

    for (int round = 1; round < Nr; ++round) {
        uint8_t t[16];
        // SubBytes + ShiftRows
        for (int c = 0; c < 4; ++c) {
            t[4 * c + 0] = kSBox[s[4 * c + 0]];
            t[4 * c + 1] = kSBox[s[4 * ((c + 1) % 4) + 1]];
            t[4 * c + 2] = kSBox[s[4 * ((c + 2) % 4) + 2]];
            t[4 * c + 3] = kSBox[s[4 * ((c + 3) % 4) + 3]];
        }
        // MixColumns + AddRoundKey
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = t[4 * c + 0], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
            s[4 * c + 0] = static_cast<uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
            s[4 * c + 1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
            s[4 * c + 2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
            s[4 * c + 3] = static_cast<uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
        }
        for (int i = 0; i < 16; ++i) s[i] ^= rk_[16 * round + i];
    }
    // Final round (no MixColumns)
    uint8_t t[16];
    for (int c = 0; c < 4; ++c) {
        t[4 * c + 0] = kSBox[s[4 * c + 0]];
        t[4 * c + 1] = kSBox[s[4 * ((c + 1) % 4) + 1]];
        t[4 * c + 2] = kSBox[s[4 * ((c + 2) % 4) + 2]];
        t[4 * c + 3] = kSBox[s[4 * ((c + 3) % 4) + 3]];
    }
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(t[i] ^ rk_[16 * Nr + i]);
}

void Aes256::decrypt_block(const uint8_t in[16], uint8_t out[16]) const
{
    const int Nr = 14;
    uint8_t s[16];
    std::memcpy(s, in, 16);
    for (int i = 0; i < 16; ++i) s[i] ^= rk_[16 * Nr + i];  // AddRoundKey last

    for (int round = Nr - 1; round >= 1; --round) {
        uint8_t t[16];
        // InvShiftRows + InvSubBytes
        for (int c = 0; c < 4; ++c) {
            t[4 * c + 0] = g_inv_sbox[s[4 * c + 0]];
            t[4 * c + 1] = g_inv_sbox[s[4 * ((c + 3) % 4) + 1]];
            t[4 * c + 2] = g_inv_sbox[s[4 * ((c + 2) % 4) + 2]];
            t[4 * c + 3] = g_inv_sbox[s[4 * ((c + 1) % 4) + 3]];
        }
        // AddRoundKey then InvMixColumns
        for (int i = 0; i < 16; ++i) t[i] ^= rk_[16 * round + i];
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = t[4 * c + 0], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
            s[4 * c + 0] = static_cast<uint8_t>(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
            s[4 * c + 1] = static_cast<uint8_t>(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
            s[4 * c + 2] = static_cast<uint8_t>(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
            s[4 * c + 3] = static_cast<uint8_t>(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
        }
    }
    // Final round
    uint8_t t[16];
    for (int c = 0; c < 4; ++c) {
        t[4 * c + 0] = g_inv_sbox[s[4 * c + 0]];
        t[4 * c + 1] = g_inv_sbox[s[4 * ((c + 3) % 4) + 1]];
        t[4 * c + 2] = g_inv_sbox[s[4 * ((c + 2) % 4) + 2]];
        t[4 * c + 3] = g_inv_sbox[s[4 * ((c + 1) % 4) + 3]];
    }
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(t[i] ^ rk_[i]);
}

} // namespace c2w::hdkeys
