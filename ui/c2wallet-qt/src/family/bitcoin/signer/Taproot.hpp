// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP341/342 taproot — ALL NEW code (design §4.1 P2TR key-path + script-path
// rows and the "Wrapped & nested scripts" P2TR-container / multi-leaf tap-tree /
// OP_CHECKSIGADD material). The vendored dashscript interpreter is
// SigVersion::BASE only (no taproot), so this module carries:
//   * the BIP341 tagged-hash primitives (TapLeaf / TapBranch / TapTweak /
//     TapSighash) over the vendored CSHA256;
//   * tap-tree merkle folding (lexicographically-sorted pairs), the taptweak of
//     the internal key, the tweaked output key Q, the P2TR scriptPubKey and its
//     bech32m address, and the control block;
//   * the BIP341 sighash committing to ALL spent outputs' amounts + SPKs;
//   * the OP_CHECKSIGADD tapscript-multisig assembly (CHECKMULTISIG is DISABLED
//     in tapscript, §4.1); and
//   * a minimal BIP341/342 verifier for self-verify-before-emit (§5.3) — the
//     in-tree interpreter cannot check a taproot spend, so this re-derives the
//     sighash and Schnorr-verifies via libsecp256k1.
// Schnorr / x-only math is libsecp256k1 (schnorrsig + extrakeys) via Crypto.hpp
// — never hand-rolled.

#include "Scripts.hpp"

#include <script/script.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::signer {

// BIP342 opcode, absent from the Dash-era vendored script.h (which predates
// tapscript). Its raw byte is all this module needs.
static constexpr uint8_t OP_CHECKSIGADD_BYTE = 0xba;

// Default (initial) tapleaf version — BIP342 tapscript.
static constexpr uint8_t TAPROOT_LEAF_TAPSCRIPT = 0xc0;

using Witness = std::vector<Bytes>;

// One spent output (prevout): its scriptPubKey and amount. The BIP341 sighash
// commits to EVERY spent output, so the caller collects all of them.
struct SpentOutput {
    CScript spk;
    int64_t amount = 0;
};

// ── tagged hashes ───────────────────────────────────────────────────────────
uint256 tagged_hash(const std::string& tag, const std::vector<uint8_t>& msg);
uint256 tapleaf_hash(uint8_t leaf_version, const CScript& script);
uint256 tapbranch_hash(const uint256& a, const uint256& b); // sorts a,b lexicographically

// ── tap tree ──────────────────────────────────────────────────────────────
// A binary tap tree of tapscript leaves. Build with leaf()/branch(); a single
// output can commit MANY alternative scripts (multi-leaf tap tree, §4.1).
struct TapTree {
    bool leaf = false;
    uint8_t leaf_version = TAPROOT_LEAF_TAPSCRIPT;
    CScript script;                    // valid when leaf
    std::shared_ptr<TapTree> l, r;     // valid when !leaf

    static TapTree Leaf(const CScript& s, uint8_t ver = TAPROOT_LEAF_TAPSCRIPT);
    static TapTree Branch(const TapTree& a, const TapTree& b);

    uint256 merkle_root() const;
    // Sibling hashes from the target leaf up to the root, in bottom→up order
    // (the control-block merkle path). false if the leaf is not in the tree.
    bool merkle_path(const uint256& target_leaf_hash, std::vector<uint256>& out) const;
};

// ── taptweak / output key / address ───────────────────────────────────────
// t = tagged_hash("TapTweak", P ‖ merkle_root?). merkle_root may be null for a
// key-path-only output. Returns the 32-byte tweak.
uint256 taptweak(const Bytes& internal_xonly, const uint256* merkle_root);

// Q = P + int(t)·G. out_q = 32-byte x-only Q; q_parity = 0/1 Y-sign of Q (the
// control-block parity bit). false on invalid key.
bool tweak_output_key(const Bytes& internal_xonly, const uint256* merkle_root,
                      Bytes& out_q, int& q_parity);

CScript p2tr_spk(const Bytes& q_xonly);   // OP_1 <32-byte Q>

// Full P2TR output construction (design §4.1 item 4): from an internal x-only
// key and an optional tap-tree merkle root, compute Q, the scriptPubKey and the
// bech32m address. For a multi-leaf tap tree pass TapTree::merkle_root().
struct P2TROutput {
    Bytes q_xonly;      // 32-byte tweaked output key
    int   q_parity = 0; // Y-parity of Q (control-block bit)
    CScript spk;        // OP_1 <32 Q>
    std::string address;
};
P2TROutput build_p2tr(const Bytes& internal_xonly, const uint256* merkle_root,
                      const std::string& hrp = "bc");

// bech32m (BIP350) encode of a witness program. witver 1 + 32-byte Q for P2TR.
std::string bech32m_address(const std::string& hrp, int witver, const Bytes& program);

// control block = (leaf_version | q_parity) ‖ <32B internal P> ‖ <merkle path>.
Bytes control_block(const Bytes& internal_xonly, int q_parity, uint8_t leaf_version,
                    const std::vector<uint256>& merkle_path);

// ── tapscript multisig (OP_CHECKSIGADD) ─────────────────────────────────────
// k-of-n leaf: <pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD ... <pkn> OP_CHECKSIGADD
// <k> OP_NUMEQUAL. Each pk is a 32-byte x-only key.
CScript checksigadd_multisig(int k, const std::vector<Bytes>& xonly_pubkeys);

// Assemble the CHECKSIGADD witness. `sigs_in_pubkey_order` has one entry per
// pubkey (pk1..pkn); a participating signer's 64/65-byte Schnorr sig, or an
// EMPTY vector for an unused slot (BIP342 §4.1 — placeholder, never omitted).
// The stack order is the reverse of pubkey order (pk1 is checked first, so its
// slot sits on top), then the leaf script, then the control block.
Witness checksigadd_witness(const std::vector<Bytes>& sigs_in_pubkey_order,
                            const CScript& leaf, const Bytes& control_block_bytes);

// Multi-party combine: place each collected partial (xonly_pubkey -> sig) at its
// pubkey's slot, empty vector for any missing signer. `pubkeys` is pk1..pkn.
std::vector<Bytes> combine_checksigadd(
    const std::vector<Bytes>& pubkeys,
    const std::vector<std::pair<Bytes, Bytes>>& partials);

// ── BIP341/342 sighash ──────────────────────────────────────────────────────
// ext_flag = 0 key-path (BIP341), 1 script-path (BIP342); when 1, tapleaf_h is
// required. hash_type: SIGHASH_DEFAULT(0)/ALL(1)/NONE(2)/SINGLE(3) | ANYONECANPAY.
uint256 taproot_sighash(const CMutableTransaction& tx,
                        const std::vector<SpentOutput>& prevouts,
                        unsigned int nIn, int hash_type, int ext_flag,
                        const uint256* tapleaf_h);

// ── minimal BIP341/342 verifier (self-verify-before-emit) ───────────────────
// Returns "" on success, else a human-readable reason. Handles a P2TR key-path
// (single-element witness) and a script-path (control block + tapleaf), incl.
// the OP_CHECKSIG / OP_CHECKSIGADD / OP_NUMEQUAL tapscript subset.
std::string taproot_verify_input(const SpentOutput& prevout, const Witness& witness,
                                 const CMutableTransaction& tx,
                                 const std::vector<SpentOutput>& prevouts,
                                 unsigned int nIn);

bool is_p2tr(const CScript& spk); // 0x51 0x20 <32>

} // namespace c2w::signer
