// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroCrypto.hpp"

#include <cstring>

// c2pool's extracted CryptoNote derivation subset (BSD-3, AGPL-declared
// surface). Reused verbatim -- hash_to_scalar and secret_key_to_public_key
// are exactly the recipe the seed/address layer needs.
#include "xmr_derivation.hpp"      // xmr::coin::{hash_to_scalar, secret_key_to_public_key}

extern "C" {
#include "vendor/crypto-ops.h"     // ge_*, sc_*  (BSD-3, vendored, byte-identical)
#include "vendor/hash-ops.h"       // cn_fast_hash (BSD-3, vendored)
}

namespace c2wallet::monero::mcrypto {

Bytes32 hash_to_scalar(const std::uint8_t* data, std::size_t len)
{
    xmr::coin::EcScalar s;
    xmr::coin::hash_to_scalar(data, len, s);
    Bytes32 out{};
    std::memcpy(out.data(), s.data(), 32);
    return out;
}

Bytes32 keccak256(const std::uint8_t* data, std::size_t len)
{
    Bytes32 out{};
    // cn_fast_hash IS Keccak-256 with a 32-byte digest (Monero's fast hash).
    cn_fast_hash(data, len, reinterpret_cast<char*>(out.data()));
    return out;
}

bool secret_to_public(const Bytes32& sec, Bytes32& pub)
{
    xmr::coin::SecretKey s;
    xmr::coin::PublicKey p;
    std::memcpy(s.data(), sec.data(), 32);
    if (!xmr::coin::secret_key_to_public_key(s, p))
        return false;
    std::memcpy(pub.data(), p.data(), 32);
    return true;
}

Bytes32 reduce32(const Bytes32& in)
{
    Bytes32 out = in;
    sc_reduce32(out.data());
    return out;
}

bool is_canonical_scalar(const Bytes32& s)
{
    return sc_check(s.data()) == 0;
}

Bytes32 scalar_add(const Bytes32& a, const Bytes32& b)
{
    Bytes32 out{};
    sc_add(out.data(), a.data(), b.data());
    return out;
}

bool point_add(const Bytes32& P, const Bytes32& Q, Bytes32& R)
{
    ge_p3 p3P, p3Q;
    if (ge_frombytes_vartime(&p3P, P.data()) != 0)
        return false;
    if (ge_frombytes_vartime(&p3Q, Q.data()) != 0)
        return false;
    ge_cached qc;
    ge_p3_to_cached(&qc, &p3Q);
    ge_p1p1 sum;
    ge_add(&sum, &p3P, &qc);
    ge_p3 p3R;
    ge_p1p1_to_p3(&p3R, &sum);
    ge_p3_tobytes(R.data(), &p3R);
    return true;
}

bool point_scalarmult(const Bytes32& s, const Bytes32& P, Bytes32& R)
{
    ge_p3 p3P;
    if (ge_frombytes_vartime(&p3P, P.data()) != 0)
        return false;
    ge_p2 r2;
    ge_scalarmult(&r2, s.data(), &p3P);
    ge_tobytes(R.data(), &r2);
    return true;
}

} // namespace c2wallet::monero::mcrypto
