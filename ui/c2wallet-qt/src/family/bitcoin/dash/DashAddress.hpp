// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH P2PKH address plumbing (design §4.1.1: "match double-checked through an
// independent base58 impl", hard-abort on wrong network / bad checksum). Ported
// from dash_collateral_tx.py addr_to_h160 / h160_to_addr, but the base58check
// codec and version bytes are REUSED from c2pool: the encoder is
// hdkeys::encode_p2pkh (btclibs base58) and the mainnet version byte 0x4c is the
// CoinParams SSOT for "DASH". Testnet 0x8c has no CoinParams row (the table
// carries mainnet only), so it is pinned here to the Dash Core value.
//
// std-only header — no btclibs / dashscript types leak, so both closures can
// include it.

#include <array>
#include <cstdint>
#include <string>

namespace c2w::dash {

// Dash Core chainparams: PUBKEY_ADDRESS. Mainnet 0x4c ('X'), testnet 0x8c ('y').
inline constexpr uint8_t kMainnetP2PKHVersion = 0x4c;
inline constexpr uint8_t kTestnetP2PKHVersion = 0x8c;

uint8_t p2pkh_version(bool testnet);

// Decode a DASH P2PKH address to its 20-byte hash160. Throws DashAbort on a bad
// base58 checksum, a wrong-length payload, or a version byte that does not match
// the requested network (the #961-class wrong-network guard).
std::array<uint8_t, 20> addr_to_h160(const std::string& addr, bool testnet);

// Encode a 20-byte hash160 as a DASH P2PKH address for the given network.
std::string h160_to_addr(const std::array<uint8_t, 20>& h160, bool testnet);

// The classic P2PKH scriptPubKey bytes for a hash160:
//   OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
std::array<uint8_t, 25> p2pkh_script(const std::array<uint8_t, 20>& h160);

} // namespace c2w::dash
