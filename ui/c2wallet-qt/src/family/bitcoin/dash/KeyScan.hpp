// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Funding-key scan for the DASH collateral / message tools (design §4.1.1:
// "scan m/44'/5'/0'/{0,1}/i for the key whose P2PKH address equals the funding
// address; HARD-ABORT if no index matches"). Port of dash_collateral_tx.py
// find_key_for_address, but every crypto step is REUSED from the M1-A hdkeys
// core (Bip39 seed, BIP32/44 derivation, secp256k1 pubkey, base58) — nothing
// re-implemented (design §2.4).
//
// The returned private scalar lives in a zeroizing SecureBytes; the short-lived
// HDKey nodes wipe their own secret material on destruction (Bip32.cpp), so a
// scanned-past index leaves no scalar in freed memory.

#include "../../../secure/SecureString.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash {

struct FoundKey {
    secure::SecureBytes priv;   // 32-byte scalar, zeroized on destruction
    std::vector<uint8_t> pub;   // 33-byte compressed pubkey (public)
    std::string path;           // e.g. "m/44'/5'/0'/0/2"
    std::string address;        // the matched funding address (== requested)
};

// Scan m/44'/{5|1}'/account'/{0[,1]}/i (external chain always; internal chain
// too when scan_internal) for the key whose DASH P2PKH address equals `address`.
//   * The match is DOUBLE-CHECKED: hash160(pubkey) must equal the address's
//     decoded hash160, AND an independent re-encode of that hash160 must equal
//     the address string (mirrors the reference tool's two-encoder cross-check).
//   * Throws DashAbort — never signs — if the mnemonic fails the BIP39 checksum
//     (reporting only a non-sensitive word count, never the phrase), or if no
//     scanned index reproduces the address.
FoundKey find_key_for_address(const std::string& mnemonic,
                              const std::string& passphrase,
                              const std::string& address,
                              bool testnet,
                              uint32_t account,
                              uint32_t scan_limit,
                              bool scan_internal);

} // namespace c2w::dash
