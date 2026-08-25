// SPDX-License-Identifier: MIT
// PR-C4 — consensus-exact input-script verification over the C1 fold view.
//
// Pure-C boundary around dashcore's vendored script interpreter
// (coin/vendor/dashscript/, byte-identical to dashcore src/script/*, linked
// as a hidden-visibility shared object so its bitcoin-derived C++ symbols
// never collide with c2pool's own btclibs at final link). Only the two
// c2pool_dash_* entry points below are exported; every internal dashcore
// symbol is hidden.
//
// The DASH consensus script-flag bit values MUST equal dashcore's
// dashconsensus_SCRIPT_FLAGS_VERIFY_* (script/bitcoinconsensus.h) — the wrapper
// static_asserts the mapping. They are re-declared here so the pure-C caller
// (mempool serve path via main_dash.cpp) needs no dashcore header.

#ifndef C2POOL_DASH_SCRIPTCHECK_H
#define C2POOL_DASH_SCRIPTCHECK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// DASH consensus script-verify flags (== dashconsensus_SCRIPT_FLAGS_VERIFY_*).
enum {
    C2POOL_DASH_SCRIPT_VERIFY_P2SH    = (1u << 0),
    C2POOL_DASH_SCRIPT_VERIFY_DERSIG  = (1u << 2),
    C2POOL_DASH_SCRIPT_VERIFY_NULLDUMMY = (1u << 4),
    C2POOL_DASH_SCRIPT_VERIFY_CLTV    = (1u << 9),
    C2POOL_DASH_SCRIPT_VERIFY_CSV     = (1u << 10),
};

// Consensus-exact CheckInputScripts over ONE input, using dashcore's own
// VerifyScript + interpreter + secp256k1 ECDSA. Returns 1 iff the scriptSig of
// input `nIn` in the serialized transaction `tx_to` satisfies `script_pubkey`
// (the referenced coin's scriptPubKey) under `flags`. Returns 0 on ANY failure:
// script mismatch, out-of-range index, deserialization error, or a size
// mismatch between the deserialized tx and `tx_to_len`. FAIL-CLOSED: the caller
// treats 0 as "exclude this tx from the template".
int c2pool_dash_verify_input(const unsigned char* script_pubkey, unsigned int script_pubkey_len,
                             const unsigned char* tx_to,         unsigned int tx_to_len,
                             unsigned int nIn, unsigned int flags);

// KAT helper: compute the legacy (SigVersion::BASE, amount 0) signature hash for
// input `nIn` of serialized tx `tx_to` under scriptCode `script_code` and
// `hash_type`. Writes 32 bytes to `out32`. Returns 1 on success, 0 on
// deserialize/index error. Used ONLY by the C4 self-signing KAT to produce a
// valid signature exercising the real interpreter path; not called on the serve
// path.
int c2pool_dash_legacy_sighash(const unsigned char* tx_to, unsigned int tx_to_len,
                               unsigned int nIn,
                               const unsigned char* script_code, unsigned int script_code_len,
                               int hash_type, unsigned char* out32);

// KAT helper: Hash160 (RIPEMD160(SHA256(data))). Test-only.
void c2pool_dash_hash160(const unsigned char* data, unsigned int len, unsigned char* out20);

#ifdef __cplusplus
}
#endif

#endif // C2POOL_DASH_SCRIPTCHECK_H
