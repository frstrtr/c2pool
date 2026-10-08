// SPDX-License-Identifier: AGPL-3.0-or-later
#include "AesCbc.hpp"

#include <cstring>

namespace c2w::hdkeys {

namespace {

// ── FIPS-197 AES (128/192/256), block = 16 bytes ────────────────────────────
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

uint8_t g_rsbox[256];
bool g_rsbox_ready = false;
void ensure_rsbox() {
    if (g_rsbox_ready) return;
    for (int i = 0; i < 256; ++i) g_rsbox[kSBox[i]] = static_cast<uint8_t>(i);
    g_rsbox_ready = true;
}

const uint8_t kRcon[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

inline uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1b)); }
inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) { if (b & 1) p ^= a; b >>= 1; a = xtime(a); }
    return p;
}

class Aes {
public:
    Aes(const uint8_t* key, size_t key_len) {
        ensure_rsbox();
        Nk_ = static_cast<int>(key_len / 4);         // 4 / 6 / 8
        Nr_ = Nk_ + 6;                                // 10 / 12 / 14
        key_expansion(key);
    }
    ~Aes() { volatile uint8_t* v = rk_; for (size_t i = 0; i < sizeof(rk_); ++i) v[i] = 0; }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16]; std::memcpy(s, in, 16);
        add_round_key(s, 0);
        for (int r = 1; r < Nr_; ++r) { sub_bytes(s); shift_rows(s); mix_columns(s); add_round_key(s, r); }
        sub_bytes(s); shift_rows(s); add_round_key(s, Nr_);
        std::memcpy(out, s, 16);
    }
    void decrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16]; std::memcpy(s, in, 16);
        add_round_key(s, Nr_);
        for (int r = Nr_ - 1; r >= 1; --r) { inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, r); inv_mix_columns(s); }
        inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, 0);
        std::memcpy(out, s, 16);
    }

private:
    int Nk_ = 4, Nr_ = 10;
    uint8_t rk_[240];    // 4*(Nr+1) words, Nr<=14 => 15*16 = 240 bytes max

    void key_expansion(const uint8_t* key) {
        const int total_words = 4 * (Nr_ + 1);
        std::memcpy(rk_, key, static_cast<size_t>(Nk_) * 4);
        uint8_t t[4];
        for (int i = Nk_; i < total_words; ++i) {
            std::memcpy(t, rk_ + (i - 1) * 4, 4);
            if (i % Nk_ == 0) {
                uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;  // RotWord
                t[0] = kSBox[t[0]]; t[1] = kSBox[t[1]]; t[2] = kSBox[t[2]]; t[3] = kSBox[t[3]];
                t[0] ^= kRcon[i / Nk_];
            } else if (Nk_ > 6 && i % Nk_ == 4) {
                t[0] = kSBox[t[0]]; t[1] = kSBox[t[1]]; t[2] = kSBox[t[2]]; t[3] = kSBox[t[3]];
            }
            for (int j = 0; j < 4; ++j) rk_[i * 4 + j] = rk_[(i - Nk_) * 4 + j] ^ t[j];
        }
    }
    void add_round_key(uint8_t s[16], int round) const {
        const uint8_t* k = rk_ + round * 16;
        for (int i = 0; i < 16; ++i) s[i] ^= k[i];
    }
    static void sub_bytes(uint8_t s[16]) { for (int i = 0; i < 16; ++i) s[i] = kSBox[s[i]]; }
    static void inv_sub_bytes(uint8_t s[16]) { for (int i = 0; i < 16; ++i) s[i] = g_rsbox[s[i]]; }
    // state is column-major: s[c*4 + r]
    static void shift_rows(uint8_t s[16]) {
        uint8_t t;
        t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        t = s[2]; s[2]=s[10]; s[10]=t; t = s[6]; s[6]=s[14]; s[14]=t;
        t = s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
    }
    static void inv_shift_rows(uint8_t s[16]) {
        uint8_t t;
        t = s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
        t = s[2]; s[2]=s[10]; s[10]=t; t = s[6]; s[6]=s[14]; s[14]=t;
        t = s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
    }
    static void mix_columns(uint8_t s[16]) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* col = s + c * 4;
            uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
            col[0] = static_cast<uint8_t>(xtime(a0) ^ (xtime(a1)^a1) ^ a2 ^ a3);
            col[1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2)^a2) ^ a3);
            col[2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3)^a3));
            col[3] = static_cast<uint8_t>((xtime(a0)^a0) ^ a1 ^ a2 ^ xtime(a3));
        }
    }
    static void inv_mix_columns(uint8_t s[16]) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* col = s + c * 4;
            uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
            col[0] = static_cast<uint8_t>(gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9));
            col[1] = static_cast<uint8_t>(gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13));
            col[2] = static_cast<uint8_t>(gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11));
            col[3] = static_cast<uint8_t>(gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14));
        }
    }
};

} // namespace

std::optional<secure::SecureBytes>
aes_cbc_decrypt_pkcs7(const uint8_t* key, size_t key_len,
                      const uint8_t iv[16],
                      const uint8_t* ct, size_t ct_len)
{
    if (key_len != 16 && key_len != 24 && key_len != 32) return std::nullopt;
    if (ct_len == 0 || (ct_len % 16) != 0) return std::nullopt;
    Aes aes(key, key_len);
    std::vector<uint8_t> buf(ct_len);
    uint8_t prev[16]; std::memcpy(prev, iv, 16);
    for (size_t off = 0; off < ct_len; off += 16) {
        uint8_t block[16];
        aes.decrypt_block(ct + off, block);
        for (int i = 0; i < 16; ++i) block[i] ^= prev[i];
        std::memcpy(buf.data() + off, block, 16);
        std::memcpy(prev, ct + off, 16);
        volatile uint8_t* v = block; for (int i = 0; i < 16; ++i) v[i] = 0;
    }
    // PKCS#7 unpad.
    uint8_t pad = buf.back();
    if (pad < 1 || pad > 16 || pad > buf.size()) { secure::secure_wipe(buf.data(), buf.size()); return std::nullopt; }
    for (size_t i = buf.size() - pad; i < buf.size(); ++i)
        if (buf[i] != pad) { secure::secure_wipe(buf.data(), buf.size()); return std::nullopt; }
    secure::SecureBytes out(buf.data(), buf.size() - pad);
    secure::secure_wipe(buf.data(), buf.size());
    return out;
}

std::vector<uint8_t>
aes_cbc_encrypt_pkcs7(const uint8_t* key, size_t key_len,
                      const uint8_t iv[16],
                      const uint8_t* pt, size_t pt_len)
{
    Aes aes(key, key_len);
    size_t pad = 16 - (pt_len % 16);          // PKCS#7: always 1..16 bytes
    std::vector<uint8_t> in(pt_len + pad);
    std::memcpy(in.data(), pt, pt_len);
    for (size_t i = pt_len; i < in.size(); ++i) in[i] = static_cast<uint8_t>(pad);
    std::vector<uint8_t> out(in.size());
    uint8_t prev[16]; std::memcpy(prev, iv, 16);
    for (size_t off = 0; off < in.size(); off += 16) {
        uint8_t block[16];
        for (int i = 0; i < 16; ++i) block[i] = in[off + i] ^ prev[i];
        aes.encrypt_block(block, out.data() + off);
        std::memcpy(prev, out.data() + off, 16);
    }
    return out;
}

} // namespace c2w::hdkeys
