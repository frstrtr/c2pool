// Copyright (c) 2014-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
//
// ===========================================================================
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/crypto/crypto.cpp
//   Commit   : 3d3920d7487b5df7ac388b6b8577fd04d505885f (master, fetched 2026-09-05)
//   License  : BSD-3-Clause (header above preserved verbatim from upstream)
//   Subset   : the function BODIES of hash_to_scalar, secret_key_to_public_key,
//              generate_key_derivation, derivation_to_scalar, derive_public_key
//              and derive_view_tag are reproduced VERBATIM from crypto_ops:: in
//              the upstream file.
//   Adapted  : (a) wrapped in namespace xmr::coin instead of crypto::;
//              (b) upstream crypto:: POD types (public_key/secret_key/
//                  key_derivation/ec_scalar/view_tag) replaced by the
//                  layout-identical 32-byte / 1-byte aliases in
//                  xmr_crypto_types.hpp -- fed to the vendored crypto-ops
//                  raw `unsigned char*` API via .data();
//              (c) RNG-, signature-, MLSAG- and mlocker-dependent code from
//                  crypto.cpp is NOT ported (not needed for coinbase output
//                  derivation, and would drag in epee/boost/libsodium RNG);
//              (d) `abort_if_...` asserts kept as plain asserts.
//   NOT adapted: no algorithmic change. The ed25519 group/field arithmetic is
//              the vendored crypto-ops.{c,h} + crypto-ops-data.c (also BSD-3).
// ===========================================================================

#include <cassert>
#include <cstring>

#include "xmr_derivation.hpp"

extern "C" {
#include "vendor/crypto-ops.h"   // ge_*, sc_* (ed25519)  -- BSD-3, vendored
#include "vendor/hash-ops.h"     // cn_fast_hash          -- BSD-3, vendored
}
#include "vendor/varint.h"       // tools::write_varint   -- BSD-3, vendored

namespace xmr::coin {

// --- crypto.cpp: hash_to_scalar --------------------------------------------
void hash_to_scalar(const void *data, std::size_t length, EcScalar &res) {
  cn_fast_hash(data, length, reinterpret_cast<char *>(res.data()));
  sc_reduce32(res.data());
}

// --- crypto.cpp: crypto_ops::secret_key_to_public_key ----------------------
bool secret_key_to_public_key(const SecretKey &sec, PublicKey &pub) {
  ge_p3 point;
  if (sc_check(sec.data()) != 0) {
    return false;
  }
  ge_scalarmult_base(&point, sec.data());
  ge_p3_tobytes(pub.data(), &point);
  return true;
}

// --- crypto.cpp: crypto_ops::generate_key_derivation -----------------------
bool generate_key_derivation(const PublicKey &key1, const SecretKey &key2,
                             KeyDerivation &derivation) {
  ge_p3 point;
  ge_p2 point2;
  ge_p1p1 point3;
  assert(sc_check(key2.data()) == 0);
  if (ge_frombytes_vartime(&point, key1.data()) != 0) {
    return false;
  }
  ge_scalarmult(&point2, key2.data(), &point);
  ge_mul8(&point3, &point2);
  ge_p1p1_to_p2(&point2, &point3);
  ge_tobytes(derivation.data(), &point2);
  return true;
}

// --- crypto.cpp: crypto_ops::derivation_to_scalar --------------------------
void derivation_to_scalar(const KeyDerivation &derivation, std::size_t output_index,
                          EcScalar &res) {
  struct {
    KeyDerivation derivation;
    char output_index[(sizeof(std::size_t) * 8 + 6) / 7];
  } buf;
  char *end = buf.output_index;
  buf.derivation = derivation;
  tools::write_varint(end, output_index);
  assert(end <= buf.output_index + sizeof buf.output_index);
  hash_to_scalar(&buf, end - reinterpret_cast<char *>(&buf), res);
}

// --- crypto.cpp: crypto_ops::derive_public_key -----------------------------
bool derive_public_key(const KeyDerivation &derivation, std::size_t output_index,
                       const PublicKey &base, PublicKey &derived_key) {
  EcScalar scalar;
  ge_p3 point1;
  ge_p3 point2;
  ge_cached point3;
  ge_p1p1 point4;
  ge_p2 point5;
  if (ge_frombytes_vartime(&point1, base.data()) != 0) {
    return false;
  }
  derivation_to_scalar(derivation, output_index, scalar);
  ge_scalarmult_base(&point2, scalar.data());
  ge_p3_to_cached(&point3, &point2);
  ge_add(&point4, &point1, &point3);
  ge_p1p1_to_p2(&point5, &point4);
  ge_tobytes(derived_key.data(), &point5);
  return true;
}

// --- crypto.cpp: crypto_ops::derive_view_tag -------------------------------
void derive_view_tag(const KeyDerivation &derivation, std::size_t output_index,
                     ViewTag &view_tag) {
  #pragma pack(push, 1)
  struct {
    char salt[8]; // view tag domain-separator
    KeyDerivation derivation;
    char output_index[(sizeof(std::size_t) * 8 + 6) / 7];
  } buf;
  #pragma pack(pop)

  char *end = buf.output_index;
  std::memcpy(buf.salt, "view_tag", 8); // leave off null terminator
  buf.derivation = derivation;
  tools::write_varint(end, output_index);
  assert(end <= buf.output_index + sizeof buf.output_index);

  // view_tag_full = H[salt|derivation|output_index]
  Hash256 view_tag_full;
  cn_fast_hash(&buf, end - reinterpret_cast<char *>(&buf),
               reinterpret_cast<char *>(view_tag_full.data()));

  // only need a slice of view_tag_full to realize optimal perf/space efficiency
  static_assert(sizeof(ViewTag) <= 32, "view tag should not be larger than hash result");
  std::memcpy(&view_tag, view_tag_full.data(), sizeof(ViewTag));
}

} // namespace xmr::coin
