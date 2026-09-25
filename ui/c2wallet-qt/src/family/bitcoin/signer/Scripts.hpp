// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Script assembly for the Family-A signer (design §4.1 spend matrix + the
// "Wrapped & nested scripts" subsection). scriptPubKey / redeemScript /
// witnessScript builders over the vendored dashscript CScript — we build the
// bytes, the vendored interpreter re-executes them on self-verify. Segwit-v0
// only here; taproot (BIP341/342) is M4-A.

#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace c2w::signer {

using Bytes = std::vector<uint8_t>;

// hash160(x) = RIPEMD160(SHA256(x)); sha256(x) single. Reused vendored crypto.
Bytes hash160(const Bytes& x);
Bytes sha256(const Bytes& x);

// ── scriptPubKey / script builders ─────────────────────────────────────────
CScript p2pk(const Bytes& pubkey);                       // <pubkey> OP_CHECKSIG
CScript p2pkh(const Bytes& pubkey);                      // OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG
CScript p2pkh_from_h160(const Bytes& h160v);
CScript p2sh(const CScript& redeemScript);               // OP_HASH160 <h160(redeem)> OP_EQUAL
CScript p2ms(int m, const std::vector<Bytes>& pubkeys);  // OP_m <pks> OP_n OP_CHECKMULTISIG
CScript p2wpkh(const Bytes& compressed_pubkey);          // OP_0 <h160(pubkey)>
CScript p2wsh(const CScript& witnessScript);             // OP_0 <sha256(script)>
CScript p2wpkh_program_from_h160(const Bytes& h160v);
CScript p2wsh_program_from_h256(const Bytes& h256v);

// The implicit BIP143 scriptCode for a P2WPKH input (the equivalent P2PKH
// script over the witness pubkey's hash160).
CScript p2wpkh_scriptcode(const Bytes& compressed_pubkey);

// Push one byte-vector as data using minimal encoding (CScript operator<<).
CScript push_data(const Bytes& data);

} // namespace c2w::signer
