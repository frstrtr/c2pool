// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_ed25519_derivation_kat.cpp  --  X1 KAT: stealth deriv.
//
// Known-Answer Tests for the CryptoNote ECDH one-time-key surface extracted
// into ../coin/xmr_derivation.cpp (over the vendored ed25519 crypto-ops.c). The
// XMR settlement executor (W5) re-derives every coinbase output one-time key
// P_i (and, post-HF15, its view tag) from consensus data and byte-compares it
// against the block; a wrong derivation pays the wrong wallet, so these are
// consensus-critical.
//
// This target links the vendored crypto-ops.c, which references libsodium's
// crypto_verify_32; the repo carries NO libsodium, so it resolves against the
// authored, dependency-free ../coin/compat/sodium/crypto_verify_32.h shim (the
// same include-path mechanism as ../coin/compat/warnings.h). No libsodium,
// RandomX, or boost is linked.
//
// VECTOR PROVENANCE: the hard input->output vectors are the OFFICIAL Monero
// consensus crypto test vectors from monero-project tests/crypto/tests.txt
// (mirrored verbatim in SChernykh/p2pool tests/src/crypto_tests.txt). Each is
// cited inline by its source line.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "xmr_crypto_types.hpp"   // PublicKey / SecretKey / KeyDerivation / ...
#include "xmr_derivation.hpp"     // generate_key_derivation / derive_public_key / ...

using namespace xmr::coin;

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (!_ok) ++g_fail; \
} while (0)

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o; o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
std::string hex(const unsigned char* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
template <class T> T from_hex(const std::string& h) {
    T t{}; auto v = unhex(h);
    std::memcpy(t.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return t;
}
template <class T> std::string hx(const T& t) { return hex(t.data(), 32); }

// generate_key_derivation <pub A> <sec r> <ok> <derivation D>
// D = 8 * r * A. (monero tests/crypto/tests.txt)
struct GKD { const char* A; const char* r; bool ok; const char* D; };
const GKD kGKD[] = {
    { "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984",
      "eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02", true,
      "4e0bd2c41325a1b89a9f7413d4d05e0a5a4936f241dccc3c7d0c539ffe00ef67" },
    { "1ebf8c3c296bb91708b09d9a8e0639ccfd72556976419c7dc7e6dfd7599218b9",
      "e49f363fd5c8fc1f8645983647ca33d7ec9db2d255d94cd538a3cc83153c5f04", true,
      "72903ec8f9919dfcec6efb5535490527b573b3d77f9890386d373c02bf368934" },
};

// derive_public_key <derivation D> <output_index i> <base B> <ok> <derived P>
// P = H_s(D || varint(i)) * G + B. (monero tests/crypto/tests.txt)
struct DPK { const char* D; std::uint64_t i; const char* B; bool ok; const char* P; };
const DPK kDPK[] = {
    { "ca780b065e48091d910de90bcab2411db3d1a845e6d95cfd556af4138504c737", 217407,
      "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39", true,
      "d48008aff5f27d8fcdc2a3bf814ed3505530f598075f3bf7e868fea696b109f6" },
    { "13bb0039172efee53059c7a973dc5f6f3c0a07611ebb0f5609cd833d5d25846c", 1,
      "5ca5429e836cd4172b7427ca8dc639f39c299f1b8e0d00f9d3f9a5bb2e49251a", true,
      "52e0a76a5785d12737dba717fd6c90e0e7d7a1a6c758543758abe578793c7a52" },
};

} // namespace

int main() {
    std::printf("=== xmr_ed25519_derivation_kat (CryptoNote stealth derivation) ===\n");

    std::printf("== generate_key_derivation: D = 8*r*A ==\n");
    for (const GKD& v : kGKD) {
        PublicKey A = from_hex<PublicKey>(v.A);
        SecretKey r = from_hex<SecretKey>(v.r);
        KeyDerivation D{};
        bool ok = generate_key_derivation(A, r, D);
        bool match = ok && (hx(D) == v.D);
        CHECK(match, "gen_key_derivation(A=%.8s.., r=%.8s..) -> %s", v.A, v.r, hx(D).c_str());
    }

    std::printf("== derive_public_key: P = H_s(D||i)*G + B ==\n");
    for (const DPK& v : kDPK) {
        KeyDerivation D = from_hex<KeyDerivation>(v.D);
        PublicKey B = from_hex<PublicKey>(v.B);
        PublicKey P{};
        bool ok = derive_public_key(D, static_cast<std::size_t>(v.i), B, P);
        bool match = ok && (hx(P) == v.P);
        CHECK(match, "derive_public_key(D=%.8s.., i=%llu, B=%.8s..) -> %s",
              v.D, (unsigned long long)v.i, v.B, hx(P).c_str());
    }

    // Structural: derivation_to_scalar is exercised inside derive_public_key
    // above; pin it independently is non-consensus, so we assert only that a
    // second call is deterministic (same D,i -> same scalar) and index-sensitive.
    std::printf("== derivation_to_scalar determinism / index-sensitivity ==\n");
    {
        KeyDerivation D = from_hex<KeyDerivation>(kDPK[0].D);
        EcScalar s0a{}, s0b{}, s1{};
        derivation_to_scalar(D, 0, s0a);
        derivation_to_scalar(D, 0, s0b);
        derivation_to_scalar(D, 1, s1);
        CHECK(s0a == s0b, "derivation_to_scalar(D,0) deterministic");
        CHECK(s0a != s1,  "derivation_to_scalar sensitive to output index");
    }

    // Negative: an off-curve point A must be rejected by generate_key_derivation
    // (returns false), not silently produce a value. y=2 has no valid x on
    // ed25519, so its 32-byte encoding (0x02, 0x00..) is not a decodable point.
    std::printf("== negative: off-curve point rejected ==\n");
    {
        PublicKey bad{};
        std::memset(bad.data(), 0x00, 32);
        bad.data()[0] = 0x02;  // y = 2: off-curve, ge_frombytes_vartime must reject
        SecretKey r = from_hex<SecretKey>(kGKD[0].r);
        KeyDerivation D{};
        bool ok = generate_key_derivation(bad, r, D);
        CHECK(!ok, "gen_key_derivation(off-curve A y=2) rejected (returned %s)", ok ? "true" : "false");
    }

    std::printf("%s (%d failure%s)\n", g_fail ? "KAT FAILED" : "KAT OK",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
