// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// Wallet-local cryptographically-secure scalar source for the Monero prover.
//
// MONEY-SAFETY: the CLSAG signer and the key-image ring signature publish
// scalars that are algebraically bound to their secret nonces (CLSAG openly
// publishes the decoy s[i]; the key-image ring signature publishes c_i/r_i).
// If those nonces come from a non-cryptographic PRNG, recovering the PRNG
// state from the published scalars recovers the secret spend key. The shared
// node helper c2pool::xmr::native::rct::random_scalar_nonzero() is seeded from
// a single 64-bit std::random_device draw into std::mt19937_64 and is NOT fit
// for prover randomness. The prover therefore draws EVERY secret nonce from
// this wallet-local CSPRNG instead.
//
// It mirrors the CSPRNG already used for key generation (MoneroKey.cpp,
// generate_wallet): getrandom(2) on Linux (BCryptGenRandom on Windows), then
// sc_reduce32 to a canonical ed25519 scalar, rejecting zero and retrying --
// byte-for-byte the same reduction/rejection the node helper performs, only
// the entropy source is swapped for a vetted CSPRNG.
#pragma once

#include "family/monero/MoneroCrypto.hpp"   // Bytes32

namespace c2wallet::monero::prover {

// A uniformly-random, canonical, non-zero ed25519 scalar drawn from the OS
// CSPRNG. Fail-closed: if no vetted CSPRNG is available or the OS call cannot
// be satisfied, this throws std::runtime_error rather than return predictable
// bytes -- a prover must never sign with weak randomness.
Bytes32 csprng_scalar_nonzero();

} // namespace c2wallet::monero::prover
