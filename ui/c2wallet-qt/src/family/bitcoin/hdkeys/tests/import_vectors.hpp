// SPDX-License-Identifier: AGPL-3.0-or-later
// Published KAT vectors for the M1-A import formats — AUTHORITATIVE sources:
//   * BIP38   : the BIP-0038 specification "Test vectors" section, verbatim.
//               Expected private keys are the spec WIFs, decoded through our own
//               WIF importer (no hand-transcribed scalars).
//   * scrypt  : RFC 7914 §12 test vectors (validates the general N,r,p KDF,
//               including the r=8 block-mix path BIP38 uses).
//   * AES-256 : FIPS-197 Appendix C.3 (the single published AES-256 block vector).
//   * Descriptors reuse the published BIP44/49/84/86 address vectors already in
//     test_vectors.hpp (btc_address_kats) — the account xpub is derived from the
//     BIP39 "abandon..about" seed and fed through the descriptor path.
#pragma once
#include <string>
#include <vector>

namespace c2w::hdkeys::kat {

// {passphrase, encrypted "6P..." key, expected WIF, ec_multiply}
struct Bip38Vec { const char* passphrase; const char* encrypted; const char* wif; bool ec_multiply; };
inline const std::vector<Bip38Vec>& bip38_vectors() {
    static const std::vector<Bip38Vec> V = {
        // non-EC-multiply, uncompressed
        {"TestingOneTwoThree", "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
         "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", false},
        {"Satoshi", "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
         "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", false},
        // non-EC-multiply, compressed
        {"TestingOneTwoThree", "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
         "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", false},
        {"Satoshi", "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
         "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7", false},
        // EC-multiply, no lot/sequence
        {"TestingOneTwoThree", "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
         "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2", true},
        {"Satoshi", "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
         "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH", true},
        // EC-multiply, WITH lot/sequence (lot 263183, sequence 1)
        {"MOLON LABE", "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
         "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8", true},
    };
    return V;
}

// RFC 7914 scrypt vectors: {passwd, salt, N, r, p, dkLen, expected_hex}
struct ScryptVec { const char* pass; const char* salt; uint64_t N; uint32_t r; uint32_t p; size_t dk; const char* out; };
inline const std::vector<ScryptVec>& scrypt_vectors() {
    static const std::vector<ScryptVec> V = {
        {"", "", 16, 1, 1, 64,
         "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
         "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"},
        {"pleaseletmein", "SodiumChloride", 16384, 8, 1, 64,
         "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
         "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"},
    };
    return V;
}

// FIPS-197 Appendix C.3 AES-256.
inline const char* aes256_key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
inline const char* aes256_pt_hex  = "00112233445566778899aabbccddeeff";
inline const char* aes256_ct_hex  = "8ea2b7ca516745bfeafc49904b496089";

} // namespace c2w::hdkeys::kat
