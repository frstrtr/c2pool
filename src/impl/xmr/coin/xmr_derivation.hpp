// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_derivation.hpp  --  CryptoNote ECDH one-time-key surface
//
// AUTHORED declaration (AGPL-3). The DEFINITIONS in xmr_derivation.cpp are a
// verbatim BSD-3 subset extracted from monero-project src/crypto/crypto.cpp
// (see that file's header + provenance). This header only names the surface the
// XMR-lane settlement executor (W5) and receipt verifier (W3) call.
//
// The four functions implement the standard CryptoNote stealth-address recipe
// (scoping S9 / S16), i.e. p2pool Wallet::get_eph_public_key:
//     D          = generate_key_derivation(A, r)   = 8 * r * A          (a point)
//     s_i        = derivation_to_scalar(D, i)      = H_s(D || varint(i))
//     P_i        = derive_public_key(D, i, B)      = s_i * G + B         (one-time key)
//     view_tag_i = derive_view_tag(D, i)           = H("view_tag"||D||varint(i))[0]
// where A = recipient view pub, B = recipient spend pub, r = tx secret key.
// Every v37 node re-derives (P_i, view_tag_i) from consensus data and byte-
// compares the coinbase outputs -- p2pool's "pays out to a wrong wallet at
// index i" check applied to the OWED settlement list.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>

#include "xmr_crypto_types.hpp"

namespace xmr::coin {

// D = 8 * r * A. Returns false if A is not a valid point. `sec` must be a
// reduced scalar (sc_check). (crypto.cpp: crypto_ops::generate_key_derivation)
bool generate_key_derivation(const PublicKey& A, const SecretKey& r, KeyDerivation& D);

// s_i = H_s(D || varint(i)), reduced mod l. (crypto_ops::derivation_to_scalar)
void derivation_to_scalar(const KeyDerivation& D, std::size_t output_index, EcScalar& s);

// P_i = s_i * G + B. Returns false if B is not a valid point.
// (crypto_ops::derive_public_key)
bool derive_public_key(const KeyDerivation& D, std::size_t output_index,
                       const PublicKey& B, PublicKey& P);

// view_tag_i = first byte of H("view_tag" || D || varint(i)) since HF15.
// (crypto_ops::derive_view_tag)
void derive_view_tag(const KeyDerivation& D, std::size_t output_index, ViewTag& vt);

// s = H_s(data), reduced mod l. Exposed because the deterministic-r seeding
// (scoping S16, "tx_secret_key" domain) also needs it. (crypto.cpp: hash_to_scalar)
void hash_to_scalar(const void* data, std::size_t length, EcScalar& s);

// R = sec * G. The tx public key R = r*G the settlement executor (W5) publishes
// in tx_extra 0x01; `sec` must be a reduced scalar (sc_check). Returns false if
// `sec` is not canonical. (crypto.cpp: crypto_ops::secret_key_to_public_key)
bool secret_key_to_public_key(const SecretKey& sec, PublicKey& pub);

} // namespace xmr::coin
