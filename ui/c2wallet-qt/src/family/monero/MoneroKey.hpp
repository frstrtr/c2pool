// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/MoneroKey.hpp
//
// Family B key core (design §3.2 / §3.4): turn any supported secret form into
// the CryptoNote key set {spend_priv?, view_priv, spend_pub, view_pub}, and
// generate a fresh wallet from a vetted CSPRNG.
//
//   mnemonic  : k_s = sc_reduce32(seed);  k_v = H_s(k_s)
//   dual      : import k_s + k_v directly (both must be canonical scalars)
//   view-only : import K_s (public) + k_v; CANNOT sign
//   generate  : getrandom(2) -> sc_reduce32 -> k_s -> 25-word mnemonic
// ---------------------------------------------------------------------------
#pragma once

#include <string>

#include "MoneroCrypto.hpp"        // Bytes32
#include "addr/MoneroAddress.hpp"  // MoneroAddress, Network

namespace c2wallet::monero {

struct MoneroKeys {
    bool    has_spend_priv{false};   // false => view-only (cannot sign)
    Bytes32 spend_priv{};            // valid iff has_spend_priv
    Bytes32 view_priv{};
    Bytes32 spend_pub{};
    Bytes32 view_pub{};

    bool can_sign() const { return has_spend_priv; }

    // Zeroize the private scalars on every destruction path (design 5.3):
    // spend_priv and view_priv (incl. the view-only view_priv) must not be
    // left in freed memory. Defined out-of-line via secure::secure_wipe.
    ~MoneroKeys();
};

struct KeyImportResult {
    bool        ok{false};
    std::string error;
    MoneroKeys  keys;
};

// From a 25/24-word Monero mnemonic.
KeyImportResult keys_from_mnemonic(const std::string& phrase);

// From raw 32-byte private spend key material (as decoded from a mnemonic or a
// hex string). Applies sc_reduce32 exactly like monerod's key recovery.
KeyImportResult keys_from_spend_key(const Bytes32& spend_seed);

// Dual raw-key import: private spend + private view, 32-byte hex each. Both must
// already be canonical reduced scalars.
KeyImportResult keys_from_dual_hex(const std::string& spend_priv_hex,
                                   const std::string& view_priv_hex);

// View-only import: public spend key + private view key, 32-byte hex each.
// Produces a key set that can derive/scan but not sign.
KeyImportResult keys_view_only(const std::string& spend_pub_hex,
                               const std::string& view_priv_hex);

// The primary (standard) address for a key set.
MoneroAddress primary_address(const MoneroKeys& k, Network net = Network::Mainnet);

// Freshly generated wallet: mnemonic + full key set. Entropy from getrandom(2).
struct GeneratedWallet {
    MoneroKeys  keys;
    std::string mnemonic;
};
bool generate_wallet(GeneratedWallet& out, std::string& err);

// Hex helpers (lowercase, no prefix). Exposed for testing.
bool        hex_to_bytes32(const std::string& hex, Bytes32& out);
std::string bytes32_to_hex(const Bytes32& b);

} // namespace c2wallet::monero
