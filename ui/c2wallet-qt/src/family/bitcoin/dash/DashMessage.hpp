// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH signed-message sign / verify (design §4.1.2). Port of
// frstrtr/dash-proposal-collateral sign_message.py:
//   * Dash keeps the legacy "DarkCoin Signed Message:\n" magic
//     (chainparams.cpp strMessageMagic).
//   * digest = double-SHA256( varstr(magic) ‖ varstr(message) ).
//   * 65-byte recoverable compact signature (header ‖ r ‖ s) with the
//     compressed-key header offset (+4); low-S enforced.
//   * SELF-VERIFY BY RECOVERY before emit: the recovered pubkey must hash to
//     the signing address, so a wrong key/derivation cannot emit a bad
//     signature. Used e.g. for DashCentral proposal-ownership claims.
//
// The EC recovery uses the system libsecp256k1 recovery module (design §2.4:
// system-linked secp256k1) — no re-implementation of the curve math. std-only
// header; SecureBytes carries the scalar.

#include "../../../secure/SecureString.hpp"

#include <string>

namespace c2w::dash {

// Sign `message` with the 32-byte scalar `priv32` for `address`. Returns the
// base64 signature (the only, public, artifact). Throws DashAbort if the
// recovered pubkey does not hash to `address` (refuses to emit a bad sig).
std::string sign_message(const secure::SecureBytes& priv32,
                         const std::string& message,
                         const std::string& address,
                         bool testnet);

// Verify a base64 signature over `message` claims `address`: recover the pubkey
// from the recoverable signature, confirm it hashes to `address`, and confirm
// the ECDSA signature validates. False on any mismatch or malformed input.
bool verify_message(const std::string& address,
                    const std::string& message,
                    const std::string& sig_b64,
                    bool testnet);

} // namespace c2w::dash
