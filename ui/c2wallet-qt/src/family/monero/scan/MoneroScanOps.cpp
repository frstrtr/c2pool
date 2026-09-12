// Copyright (c) 2014-2026, The Monero Project
//
// All rights reserved. BSD-3-Clause -- see the full license text preserved in
// src/impl/xmr/coin/xmr_derivation.cpp (same upstream file crypto.cpp) and the
// PROVENANCE block in MoneroScanOps.hpp. The function BODIES below are the
// verbatim CryptoNote / RingCT recipes; the ed25519/Keccak arithmetic is the
// already-vendored crypto-ops/keccak, and the derivation subset is xmr::coin.
// ===========================================================================
#include "MoneroScanOps.hpp"

#include <cstring>

// c2pool's extracted CryptoNote derivation subset (reused, not reimplemented).
#include "xmr_derivation.hpp"

extern "C" {
#include "vendor/crypto-ops.h"   // ge_*, sc_*  (BSD-3, vendored, byte-identical)
#include "vendor/hash-ops.h"     // cn_fast_hash (Keccak-256)
}

namespace c2wallet::monero::scanops {

namespace {

// Bridges between c2wallet's Bytes32 (std::array) and the layout-identical
// xmr::coin 32-byte aliases fed to the vendored raw-pointer API.
inline xmr::coin::PublicKey as_pub(const Bytes32& b) {
    xmr::coin::PublicKey p; std::memcpy(p.data(), b.data(), 32); return p;
}
inline xmr::coin::SecretKey as_sec(const Bytes32& b) {
    xmr::coin::SecretKey s; std::memcpy(s.data(), b.data(), 32); return s;
}
inline xmr::coin::KeyDerivation as_der(const Bytes32& b) {
    xmr::coin::KeyDerivation d; std::memcpy(d.data(), b.data(), 32); return d;
}
inline Bytes32 from32(const unsigned char* p) {
    Bytes32 b{}; std::memcpy(b.data(), p, 32); return b;
}

} // namespace

// ---- delegated to the in-tree derivation subset ---------------------------

bool key_derivation(const Bytes32& R, const Bytes32& view_sec, Bytes32& D) {
    xmr::coin::KeyDerivation d;
    if (!xmr::coin::generate_key_derivation(as_pub(R), as_sec(view_sec), d))
        return false;
    std::memcpy(D.data(), d.data(), 32);
    return true;
}

Bytes32 derivation_to_scalar(const Bytes32& D, std::uint64_t output_index) {
    xmr::coin::EcScalar s;
    xmr::coin::derivation_to_scalar(as_der(D), static_cast<std::size_t>(output_index), s);
    return from32(s.data());
}

bool derive_public_key(const Bytes32& D, std::uint64_t output_index,
                       const Bytes32& base, Bytes32& P) {
    xmr::coin::PublicKey out;
    if (!xmr::coin::derive_public_key(as_der(D), static_cast<std::size_t>(output_index),
                                      as_pub(base), out))
        return false;
    std::memcpy(P.data(), out.data(), 32);
    return true;
}

std::uint8_t view_tag(const Bytes32& D, std::uint64_t output_index) {
    xmr::coin::ViewTag vt;
    xmr::coin::derive_view_tag(as_der(D), static_cast<std::size_t>(output_index), vt);
    return vt.tag;
}

// ---- verbatim ports from crypto.cpp (composite ge_*/sc_* recipes) ---------

// crypto.cpp: crypto_ops::derive_subaddress_public_key
//   derived = P_i - H_s(D||i)*G
bool derive_subaddress_public_key(const Bytes32& one_time_pub, const Bytes32& D,
                                  std::uint64_t output_index, Bytes32& out) {
    ge_p3 p1;                                   // P_i
    if (ge_frombytes_vartime(&p1, one_time_pub.data()) != 0)
        return false;
    Bytes32 scalar = derivation_to_scalar(D, output_index);  // s = H_s(D||i)
    ge_p3 p2;
    ge_scalarmult_base(&p2, scalar.data());     // s*G
    ge_cached p3;
    ge_p3_to_cached(&p3, &p2);
    ge_p1p1 p4;
    ge_sub(&p4, &p1, &p3);                       // P_i - s*G
    ge_p2 p5;
    ge_p1p1_to_p2(&p5, &p4);
    ge_tobytes(out.data(), &p5);
    return true;
}

// crypto.cpp: crypto_ops::derive_secret_key -> x = s + base_sec (mod l)
Bytes32 derive_secret_key(const Bytes32& D, std::uint64_t output_index,
                          const Bytes32& base_sec) {
    Bytes32 scalar = derivation_to_scalar(D, output_index);
    Bytes32 out{};
    sc_add(out.data(), scalar.data(), base_sec.data());
    return out;
}

// crypto.cpp: static hash_to_ec -> H_p(P) = 8 * ge_fromfe(Keccak(P))
static bool hash_to_ec(const Bytes32& pub, ge_p3& res) {
    unsigned char h[32];
    cn_fast_hash(pub.data(), 32, reinterpret_cast<char*>(h));
    ge_p2 point;
    ge_fromfe_frombytes_vartime(&point, h);
    ge_p1p1 point2;
    ge_mul8(&point2, &point);
    ge_p1p1_to_p3(&res, &point2);
    return true;
}

// crypto.cpp: crypto_ops::generate_key_image -> I = x * H_p(P)
bool generate_key_image(const Bytes32& one_time_pub, const Bytes32& one_time_sec,
                        Bytes32& image) {
    if (sc_check(one_time_sec.data()) != 0)
        return false;
    ge_p3 point;
    if (!hash_to_ec(one_time_pub, point))
        return false;
    ge_p2 point2;
    ge_scalarmult(&point2, one_time_sec.data(), &point);
    ge_tobytes(image.data(), &point2);
    return true;
}

// ---- RingCT v2 short ecdh (rctOps.cpp) ------------------------------------

// ecdhHash(k) = Keccak("amount" || k), first 8 bytes xored into the amount.
Bytes32 commitment_mask(const Bytes32& shared_secret) {
    unsigned char buf[15 + 32];
    std::memcpy(buf, "commitment_mask", 15);
    std::memcpy(buf + 15, shared_secret.data(), 32);
    return mcrypto::hash_to_scalar(buf, sizeof(buf));   // H_s -> reduced scalar
}

static std::array<std::uint8_t, 8> ecdh_hash8(const Bytes32& shared_secret) {
    unsigned char buf[6 + 32];
    std::memcpy(buf, "amount", 6);
    std::memcpy(buf + 6, shared_secret.data(), 32);
    Bytes32 h = mcrypto::keccak256(buf, sizeof(buf));
    std::array<std::uint8_t, 8> out{};
    std::memcpy(out.data(), h.data(), 8);
    return out;
}

std::uint64_t ecdh_decode_amount(const std::array<std::uint8_t, 8>& masked,
                                 const Bytes32& shared_secret) {
    std::array<std::uint8_t, 8> mask = ecdh_hash8(shared_secret);
    std::uint64_t amount = 0;
    for (int i = 0; i < 8; ++i) {
        std::uint8_t b = masked[i] ^ mask[i];
        amount |= static_cast<std::uint64_t>(b) << (8 * i);   // little-endian
    }
    return amount;
}

std::array<std::uint8_t, 8> ecdh_encode_amount(std::uint64_t amount,
                                               const Bytes32& shared_secret) {
    std::array<std::uint8_t, 8> mask = ecdh_hash8(shared_secret);
    std::array<std::uint8_t, 8> out{};
    for (int i = 0; i < 8; ++i) {
        std::uint8_t b = static_cast<std::uint8_t>((amount >> (8 * i)) & 0xff);
        out[i] = b ^ mask[i];
    }
    return out;
}

} // namespace c2wallet::monero::scanops
