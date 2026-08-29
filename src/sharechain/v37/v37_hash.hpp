#pragma once
// V37 — self-contained SHA-256 / SHA-256d (spec §6.3 S-3, §8.5).
//
// Standalone implementation so the v37 module compiles without the btclibs
// dependency tree; produces standard FIPS 180-4 SHA-256, so it is bit-equal
// to core's CSHA256/CHash256. Integration MAY swap these calls for the repo
// hashers; output is identical either way (covered by known-vector tests).

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace v37 {

using bytes32 = std::array<std::uint8_t, 32>;

namespace detail {

struct Sha256Ctx {
    std::uint32_t h[8];
    std::uint64_t len = 0;
    std::uint8_t buf[64];
    std::size_t buf_used = 0;

    Sha256Ctx() { reset(); }

    void reset() {
        static constexpr std::uint32_t init[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        std::memcpy(h, init, sizeof(h));
        len = 0;
        buf_used = 0;
    }

    static std::uint32_t rotr(std::uint32_t x, unsigned n) {
        return (x >> n) | (x << (32 - n));
    }

    void compress(const std::uint8_t* p) {
        static constexpr std::uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) |
                   (std::uint32_t(p[i * 4 + 2]) << 8) | p[i * 4 + 3];
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            std::uint32_t ch = (e & f) ^ (~e & g);
            std::uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void write(const std::uint8_t* p, std::size_t n) {
        len += n;
        while (n) {
            std::size_t take = 64 - buf_used;
            if (take > n) take = n;
            std::memcpy(buf + buf_used, p, take);
            buf_used += take;
            p += take;
            n -= take;
            if (buf_used == 64) {
                compress(buf);
                buf_used = 0;
            }
        }
    }

    bytes32 finalize() {
        std::uint64_t bits = len * 8;
        std::uint8_t pad = 0x80;
        write(&pad, 1);
        std::uint8_t zero = 0;
        while (buf_used != 56) write(&zero, 1);
        std::uint8_t lenb[8];
        for (int i = 0; i < 8; ++i)
            lenb[i] = static_cast<std::uint8_t>(bits >> (56 - i * 8));
        write(lenb, 8);
        bytes32 out;
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                out[i * 4 + j] = static_cast<std::uint8_t>(h[i] >> (24 - j * 8));
        return out;
    }
};

} // namespace detail

inline bytes32 sha256(const std::uint8_t* p, std::size_t n) {
    detail::Sha256Ctx c;
    c.write(p, n);
    return c.finalize();
}

inline bytes32 sha256d(const std::uint8_t* p, std::size_t n) {
    bytes32 first = sha256(p, n);
    return sha256(first.data(), first.size());
}

inline bytes32 sha256d(const std::vector<std::uint8_t>& v) {
    return sha256d(v.data(), v.size());
}

} // namespace v37
