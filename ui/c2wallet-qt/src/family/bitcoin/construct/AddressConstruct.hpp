// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Address CONSTRUCTION (encode) for the script-defined Family-A output types
// (design §4.1 construct matrix). M1-A'"'"'s hdkeys/Address.hpp already builds the
// key-derived types from a pubkey/scalar — P2PK (compressed+uncompressed),
// P2PKH, P2WPKH, P2SH-P2WPKH, P2TR key-path. This module adds the remaining
// SCRIPT-defined containers, computing the receive address directly from an
// arbitrary inner script WITHOUT spending (design §4.1 "Address CREATION from an
// arbitrary inner script"):
//
//   P2SH(redeemScript)     base58check(version || hash160(redeemScript))
//   P2WSH(witnessScript)   bech32(0, SHA256(witnessScript))
//   P2SH-P2WSH(wScript)    base58check(version || hash160(OP_0 || SHA256(wScript)))
//   P2SH-P2WPKH(pubkey)    base58check(version || hash160(OP_0 || hash160(pubkey)))
//
// This is the M2-A encode surface. The full wrapped/nested SPEND (scriptSig /
// witness / control-block assembly, multi-party combine) is M3/M4 — deliberately
// NOT built here. READ-ONLY: no key material, no signing.
//
// Reuses c2pool codecs via the M1-A layer: hash160 (Bip32.hpp), the base58/
// bech32 encoders (Address.hpp), and CSHA256 (btclibs) — nothing re-implemented.

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::construct {

struct BuiltAddress {
    std::string type;                    // "P2SH","P2WSH","P2SH-P2WSH","P2SH-P2WPKH"
    std::string address;                 // encoded receive address
    std::vector<unsigned char> script;   // the scriptPubKey (coin-agnostic payload)
    std::string script_hex;
    bool ok() const { return !address.empty(); }
};

// P2SH wrapping an arbitrary redeemScript.
BuiltAddress build_p2sh(uint8_t p2sh_version, const std::vector<uint8_t>& redeem_script);

// P2WSH wrapping an arbitrary witnessScript (segwit v0; needs the coin'"'"'s HRP).
BuiltAddress build_p2wsh(const std::string& bech32_hrp, const std::vector<uint8_t>& witness_script);

// Nested P2SH-P2WSH: the redeemScript is the witness program OP_0 <SHA256(wScript)>.
BuiltAddress build_p2sh_p2wsh(uint8_t p2sh_version, const std::vector<uint8_t>& witness_script);

// P2SH-P2WPKH from a compressed pubkey: redeemScript = OP_0 <hash160(pubkey)>.
BuiltAddress build_p2sh_p2wpkh(uint8_t p2sh_version, const std::vector<uint8_t>& compressed_pubkey);

// A bare-P2MS redeemScript builder (OP_m <pk1..pkn> OP_n OP_CHECKMULTISIG) — the
// LTC+DOGE-donation inner script, usable as the redeem/witnessScript above.
// Pubkeys must be 33- or 65-byte; 1<=m<=n<=16. Returns {} on bad args.
std::vector<uint8_t> build_bare_multisig_script(int m, const std::vector<std::vector<uint8_t>>& pubkeys);

} // namespace c2w::construct
