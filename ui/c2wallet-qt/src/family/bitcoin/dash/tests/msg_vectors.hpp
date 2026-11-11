// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Signed-message vectors produced by Dash Core itself (design A.7). PUBLIC
// THROWAWAY KEYS ONLY:
//   key A = BIP39 "abandon x11 about" + passphrase "TREZOR", m/44'/5'/0'/0/0,
//           compressed (the same scalar as testvec::kK7Wif in s2_vectors.hpp);
//   key U = the private scalar 1, uncompressed (its public key is G).
//
// Provenance: Dash Core RPC client v23.1.7, mainnet node vm210, 2026-11-02.
// Each signature below was produced and checked with exactly these read-only,
// wallet-free RPCs (LONG = the 300-byte message below, shell-quoted):
//
//   ssh vm210 dash-cli signmessagewithprivkey <WIF> "<message>"
//   ssh vm210 dash-cli verifymessage <address> <signature> "<message>"    -> true
//   ssh vm210 dash-cli verifymessage <address> <signature> "<message>x"   -> false
//
// with <WIF> = kWifA (testvec::kK7Wif) or kWifU, <message> = kMsgShort, LONG or
// "" (empty). The four short/long rows equal, byte for byte, the vectors the
// python stopgap `c2wallet.py sign-message` asserts in its own KATs (the
// operator's standalone tool, not part of this tree); the two empty-message
// rows were generated in the same run.

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash::msgvec {

// DASH mainnet WIF (version 0xcc), compressed: key A (== testvec::kK7Wif).
inline const char* const kWifA = "XH9QRA2nnr1X5nuQEPKbUHupdjmri24fR6HpUjm2WQRjZEaQEkvb";
// DASH mainnet WIF of the scalar 1, uncompressed (no 01 suffix): key U.
inline const char* const kWifU = "7qYrzJZWqnyCWMYswFcqaRJypGdVceudXPSxmZKsngN7fyo7aAV";
// The uncompressed public key of the scalar 1 (the generator G).
inline const char* const kPubUHex =
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

inline const char* const kAddrA = "Xn9KtWHuvMBuSbpzPFTzYG2bC9Wp2ZZJJG";
inline const char* const kAddrU = "XoyDQM3xGhFW5JqYBwTLckjqZ67Q3jZfAL";

// 25 bytes: a DashCentral proposal-ownership claim.
inline const char* const kMsgShort = "dashcentral-proposal-1556";

// 300 bytes = ("c2pool long message test " * 13)[:300]: twelve copies of the
// 25-byte phrase, ending in a space. Length >= 253 takes the compactsize 0xfd
// prefix (fd 2c 01).
inline std::string long_message()
{
    std::string s;
    for (int i = 0; i < 13; ++i) s += "c2pool long message test ";
    return s.substr(0, 300);
}

enum class Msg { Short, Long, Empty };

inline std::vector<uint8_t> message_bytes(Msg m)
{
    const std::string s = m == Msg::Short ? std::string(kMsgShort) : m == Msg::Long ? long_message() : std::string();
    return std::vector<uint8_t>(s.begin(), s.end());
}

struct CoreMsgVector {
    const char* label;
    bool key_a;          // true: key A (compressed); false: key U (uncompressed)
    Msg msg;
    const char* sig_b64; // dash-cli signmessagewithprivkey output
};

// The four design vectors (A.7 table).
inline const CoreMsgVector kCoreVectors[] = {
    {"A short", true, Msg::Short,
     "IPFklzhS3xSUKSIxB5IBWLS/r9Jbc9whftHCjweVVx1aCYwaeRLIO56GvYR6P6ITr4A13dWc20JgSBX/4oK0e6w="},
    {"A long", true, Msg::Long,
     "ICRAvFpHcV5riWsHcRVDLRpTq7RSE4Z5ihUkUaMoX6+PebAsIkz8gm6ZbJBYukR/sjtobWdk4/vgGnW0qFGPrpw="},
    {"U short", false, Msg::Short,
     "G8eyCFYTWJdgkP1fYt5Rxw++Q5QbfxU9W4Swv2E+I4XsIM35jBlz2DYjU6aCcixkbksI3CAJNlmlGODYQYlObkc="},
    {"U long", false, Msg::Long,
     "HNOzSYy447AFSCPLzN2ucDntvT75T2C3I2CZ+oII1FbPTdaJtCf1iIgQ/zHvjYFIAEkonYSgoWnzbH1bckwMXVE="},
};

// Empty message (Core accepts it): KAT M17.
inline const CoreMsgVector kCoreEmptyVectors[] = {
    {"A empty", true, Msg::Empty,
     "Hwj/IIzx5PH+Bh9TyORELtKdIv+uqBD30fJrG+P03cygeVnR5TeOULBYZ30R8Rlodq2t0rIMgzwZAB+uTfxt22A="},
    {"U empty", false, Msg::Empty,
     "G6yeXJCry8jrUqsiviGf6y2yQHb03Pll1IyTfqFUEkVCe4lW5irTQfk9LUBgFSuXk2LIKmQ0c2yKDtiI8YVPrnQ="},
};

} // namespace c2w::dash::msgvec
