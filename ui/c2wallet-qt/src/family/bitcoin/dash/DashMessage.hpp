// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Signed-message sign / verify (design §4.1.2), in the Dash Core / Bitcoin Core
// `signmessage` format. Port of frstrtr/dash-proposal-collateral
// sign_message.py, brought to Core parity:
//   * digest = double-SHA256( varstr(magic) ‖ varstr(message) ); Dash keeps the
//     legacy "DarkCoin Signed Message:\n" magic (chainparams strMessageMagic).
//   * 65-byte recoverable compact signature: header ‖ r ‖ s, with
//     header = 27 + recid + (compressed ? 4 : 0). The +4 says which pubkey
//     encoding the address hashes, so an uncompressed key (WIF without the 01
//     suffix, old p2pool-era keys) signs with header 27..30 and a compressed
//     one with 31..34. RFC6979 nonce, low-S.
//   * SELF-VERIFY BEFORE EMIT: the recovered pubkey, serialized in the SAME
//     encoding the header claims, must hash to the signing address, and the
//     emitted base64 must pass verify_message; otherwise DashAbort, nothing is
//     returned. A wrong key, derivation or encoding never emits a signature.
//   * verify honours the header's compressed bit as Core's RecoverCompact
//     does, so a Core signature from an uncompressed-key address verifies.
//
// Coins: one MessageCoin row per coin. Only a row whose magic is PROVEN by a
// node-produced vector in tests/msg_vectors.hpp has kat_proven == true; the
// other rows are listed so the UI can name them, and sign / verify refuse them
// with a "no node vector" reason (mirrors the python tool's refusal).
//
// The EC recovery uses the system libsecp256k1 recovery module (design §2.4) —
// no re-implementation of the curve math. std-only header; SecureBytes carries
// the scalar.

#include "KeyScan.hpp"

#include "../../../secure/SecureString.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash {

struct MessageCoin {
    const char* ticker;        // "DASH"
    const char* magic;         // "DarkCoin Signed Message:\n"
    uint8_t     p2pkh_mainnet; // 0x4c
    uint8_t     p2pkh_testnet; // 0x8c
    bool        kat_proven;    // true only with a node vector in tests/msg_vectors.hpp
};

// The row for `ticker` (exact, case-sensitive); throws DashAbort if unknown.
const MessageCoin& message_coin(const std::string& ticker);
// Every row, DASH first.
const std::vector<MessageCoin>& message_coins();

// dsha256( varstr(magic) ‖ varstr(message) ) — the signed digest. Exposed for
// the digest-layout KAT; does not check kat_proven.
std::array<uint8_t, 32> message_digest(const MessageCoin& coin, const std::vector<uint8_t>& message);

// Sign the exact bytes `message` with the 32-byte scalar `priv32` for
// `address`, writing header 27 + recid + (compressed ? 4 : 0). Returns the
// base64 signature (the only, public, artifact). Throws DashAbort for an
// unproven coin, a malformed scalar or address, or when the self-verify does
// not reproduce `address` (never emits a bad signature).
std::string sign_message(const MessageCoin& coin,
                         const secure::SecureBytes& priv32,
                         bool compressed,
                         const std::vector<uint8_t>& message,
                         const std::string& address,
                         bool testnet);

// The same over a bound key: key.priv, key.compressed, key.address.
std::string sign_message(const MessageCoin& coin,
                         const FoundKey& key,
                         const std::vector<uint8_t>& message,
                         bool testnet);

// What verify_message found (public data only; the Verify tab shows it).
struct VerifyReport {
    bool valid = false;
    bool header_compressed = false;
    int  recid = -1;
    std::string recovered_address;   // "" when recovery did not run or failed
    std::string why;                 // "" when valid; else the first failing check
};

// Verify a base64 signature over `message` claims `address`: decode, header in
// 27..34, recover the pubkey, serialize it compressed or uncompressed as the
// header says, hash160 == the address's hash160, then an independent standard
// ECDSA verify under the recovered pubkey. False on any mismatch or malformed
// input (never throws for bad input); `report`, when given, says why.
bool verify_message(const MessageCoin& coin,
                    const std::string& address,
                    const std::vector<uint8_t>& message,
                    const std::string& sig_b64,
                    bool testnet,
                    VerifyReport* report = nullptr);

// ── the original entry points, kept as wrappers ─────────────────────────────
// DASH, compressed key, message bytes taken from the std::string as-is.
std::string sign_message(const secure::SecureBytes& priv32,
                         const std::string& message,
                         const std::string& address,
                         bool testnet);

// DASH; honours the header's compressed bit (Core parity).
bool verify_message(const std::string& address,
                    const std::string& message,
                    const std::string& sig_b64,
                    bool testnet);

} // namespace c2w::dash
