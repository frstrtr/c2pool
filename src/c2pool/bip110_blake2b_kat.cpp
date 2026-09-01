// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_blake2b_kat — the KILLER known-answer test for the BIP-110 lane.
//
// Two layers of proof:
//
//   (A) PRIMITIVE. The BLAKE2b implementation reproduces the RFC 7693 Appendix
//       A vector BLAKE2b-512("abc"), plus BLAKE2b-256 vectors, so the hash core
//       is the unmodified sequential BLAKE2 function and not a lookalike.
//
//   (B) CHAIN. The full five-stage BIP-110 block-hash pipeline reproduces the
//       CANONICAL block hash of two REAL blocks from the live BIP-110 / Bitcoin
//       Knots chain (mempool.guide raw 164-byte v2 headers), and block 961640
//       satisfies its stated nBits. This is the proof that our BLAKE2b block
//       hash equals the chain's own block hash — not merely a self-consistent
//       vector.
//
// Vectors:
//   V1 = block 961640 (the first BLAKE2b block; also a hard-coded checkpoint in
//        Knots chainparams.cpp) — canonical hash
//        0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb, nBits
//        0x1a008d4f.
//   V2 = block 963396 — canonical hash
//        000000000000004f6a9d3f26f4aac32717f9b0bf5c940b17b33ac89a159f25ef.
// Both use flags=0 and a null xor_key (the live-chain layout).

#include <impl/bip110/pow.hpp>
#include <impl/bip110/crypto/blake2b.h>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>

#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

std::string to_hex(const unsigned char* p, size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(d[p[i] >> 4]);
        out.push_back(d[p[i] & 0xf]);
    }
    return out;
}

int g_fail = 0;

void expect_eq(const std::string& what, const std::string& got, const std::string& exp)
{
    if (got == exp) {
        std::printf("  [ok]   %s = %s\n", what.c_str(), got.c_str());
    } else {
        std::printf("  [FAIL] %s\n         got %s\n         exp %s\n",
                    what.c_str(), got.c_str(), exp.c_str());
        ++g_fail;
    }
}

std::string blake2b_hex(const std::string& msg_hex, size_t out_len)
{
    std::vector<unsigned char> msg = from_hex(msg_hex);
    std::vector<unsigned char> out(out_len);
    int rc = bip110_blake2b(out.data(), out.size(),
                            msg.empty() ? nullptr : msg.data(), msg.size());
    if (rc != 0) return std::string("<err>");
    return to_hex(out.data(), out.size());
}

// (A) BLAKE2b primitive vectors.
void test_primitive()
{
    std::printf("[A] BLAKE2b primitive (RFC 7693):\n");
    // "abc" = 616263
    expect_eq("BLAKE2b-512(\"abc\")", blake2b_hex("616263", 64),
              "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
              "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    expect_eq("BLAKE2b-256(\"\")", blake2b_hex("", 32),
              "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    expect_eq("BLAKE2b-256(\"abc\")", blake2b_hex("616263", 32),
              "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    // 200 bytes 0x00..0xc7 — exercises the multi-block path (> 128 bytes).
    std::string big;
    for (int i = 0; i < 200; ++i) {
        static const char* d = "0123456789abcdef";
        big.push_back(d[(i >> 4) & 0xf]);
        big.push_back(d[i & 0xf]);
    }
    expect_eq("BLAKE2b-256(0x00..0xc7)", blake2b_hex(big, 32),
              "63c3d97a9f8894d5e043a707b0fee7f7ec4c049a23bbf1079df20b4165f9e22d");
}

// (B) Full BIP-110 block hash against real chain blocks.
struct Vec { const char* name; const char* header; const char* hash; };

void test_chain_vector(const Vec& v, bool check_pow, uint32_t nbits)
{
    std::vector<unsigned char> header = from_hex(v.header);
    uint256 got = bip110::pow::blake2b_block_hash(std::span<const unsigned char>(header.data(), header.size()));
    expect_eq(std::string(v.name) + " block hash", got.GetHex(), std::string(v.hash));

    if (check_pow) {
        uint256 target = chain::bits_to_target(nbits);
        bool ok = got <= target;
        if (ok) {
            std::printf("  [ok]   %s PoW satisfies nBits 0x%08x (hash <= target)\n", v.name, nbits);
        } else {
            std::printf("  [FAIL] %s PoW does NOT satisfy nBits 0x%08x\n", v.name, nbits);
            ++g_fail;
        }
    }
}

} // namespace

int main()
{
    std::printf("=== bip110_blake2b_kat ===\n");

    test_primitive();

    std::printf("[B] BIP-110 chain block hash (mempool.guide raw v2 headers):\n");
    const Vec V1{
        "961640",
        "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb",
    };
    const Vec V2{
        "963396",
        "000000a025eb5550790b63a9c253e4e134ebeffb56b8c6a91912464433000000000000009abebcdf57d3104adc6451efaeab2edd410d773a59aec90cedfb56a0bee050ee42c9966a4f8d001a430362770000000042c9966a00000000b14cf00dba1f00000000000000000000340000000000000000000000000000000000000044b30e000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000004f6a9d3f26f4aac32717f9b0bf5c940b17b33ac89a159f25ef",
    };

    test_chain_vector(V1, /*check_pow=*/true, 0x1a008d4f);
    test_chain_vector(V2, /*check_pow=*/false, 0);

    if (g_fail == 0) {
        std::printf("RESULT: PASS — BLAKE2b primitive + BIP-110 chain block hash reproduced.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
