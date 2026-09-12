// Copyright (c) 2014-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. See the full BSD-3 text preserved in
// src/impl/xmr/coin/xmr_derivation.cpp (same upstream family of files).
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/prover/MoneroRingctBuilder.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/ringct/rctSigs.cpp (genRctSimple,
//              the balance/pseudo-out construction), src/cryptonote_core /
//              cryptonote_tx_utils.cpp (construct_tx: output one-time keys,
//              tx_extra pubkey, per-output amount ecdh) and
//              cryptonote_format_utils.cpp (get_pre_mlsag_hash,
//              get_transaction_prefix_hash, calculate_transaction_hash).
//   License  : BSD-3-Clause (header above; full text in xmr_derivation.cpp).
//   Subset   : the OFFLINE single-sig RingCT transaction assembler + the
//              offline self-verify, re-expressed over Bytes32 and driven
//              through the already-vendored ed25519/Keccak engine, the in-tree
//              RingCT ops, the ported CLSAG signer (MoneroClsag) and the ported
//              Bulletproofs+ prover (MoneroBulletproofsPlus). Ring/decoy
//              selection is NOT here -- it is the online side (design §4.2 step
//              2); frozen ring members are supplied as an input. The
//              CryptoNote LEB128 varint is the vendored codec.
//
// This is the M4-X money-path that completes Monero's native cold-sign (design
// §4.2 steps 1,3-9 + the §5.3 self-verify-before-emit law): input selection,
// pseudo-output + output Pedersen commitments with masks balanced so
// Sum C_in(pseudo) - Sum C_out - fee*H = 0, per-output amount/mask ecdh
// encoding, Bulletproofs+ range proofs, per-input CLSAG signatures, key images,
// fee, tx_extra, and the serialized CryptoNote blob + tx_hash. Before it emits
// anything it re-runs the INDEPENDENT in-tree Bulletproofs+ verifier, the
// CLSAG verifier, a key-image recompute and the commitment-balance check, and
// refuses to emit if any leg fails.
//
// MONEY-SAFETY: the tx secret key r, the output blinding masks (drawn as
// commitment masks from the ecdh shared secret, deterministic and recoverable),
// and the pseudo-output blinding masks all originate from the wallet-local
// CSPRNG (MoneroProverRng) -- never the node helper random_scalar_nonzero().
// Every secret scalar is zeroized after use.
// ===========================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"                 // Bytes32
#include "family/monero/prover/MoneroClsag.hpp"           // CtKey, Clsag
#include "family/monero/prover/MoneroBulletproofsPlus.hpp"// BulletproofPlus

namespace c2wallet::monero::prover {

// One owned unspent output to spend, as an M2-X full-wallet scan produces it,
// plus the frozen ring the ONLINE side selected (design §4.2 step 2).
struct SpendInput {
    Bytes32            one_time_sec{};   // x_i (SECRET) -- from derive_secret_key
    std::uint64_t      amount{0};        // a_in_i (cleartext, owner knows it)
    Bytes32            amount_mask{};    // z_in_i -- the real output's commitment mask
    std::vector<CtKey> ring;             // ring members (dest,mask): decoys + the real one
    std::size_t        real_index{0};    // position of the owned member in `ring`
    std::vector<std::uint64_t> ring_global_indices; // absolute output indices, for the blob (optional)
};

// One destination. Standard/subaddress recipient public keys + amount.
struct TxDestination {
    Bytes32       spend_pub{};   // K_s
    Bytes32       view_pub{};    // K_v
    std::uint64_t amount{0};     // a_out
    bool          is_subaddress{false};
};

// The assembled transaction. All fields are public (post-sign): a signed tx is
// self-authenticating and carries no secret.
struct RingctTx {
    std::vector<unsigned char>            blob;               // serialized CryptoNote tx
    Bytes32                               tx_hash{};          // calculate_transaction_hash
    Bytes32                               prefix_hash{};      // get_transaction_prefix_hash
    Bytes32                               message{};          // pre-MLSAG hash (CLSAG message)
    Bytes32                               tx_pubkey{};        // R (tx_extra 0x01)
    std::vector<Bytes32>                  output_pubkeys{};   // P_out_j
    std::vector<std::uint8_t>             output_view_tags{};  // HF15+ view tag per output (blob byte)
    std::vector<Bytes32>                  output_commitments{};// C_out_j = z_out*G + a_out*H
    std::vector<std::array<std::uint8_t,8>> ecdh_amounts{};   // masked 8-byte amounts
    std::vector<Bytes32>                  pseudo_outs{};       // Cout_i (per input)
    std::vector<Clsag>                    clsags{};            // per-input CLSAG
    std::vector<Bytes32>                  key_images{};        // I_i (per input)
    std::vector<std::vector<CtKey>>       rings{};             // frozen ring per input (public; in tx order)
    BulletproofPlus                       bpp{};               // aggregate range proof
    std::uint64_t                         fee{0};
};

struct AssembleResult {
    bool     ok{false};
    std::string error;
    RingctTx tx;
};

// Fee = tx_weight * per_byte_rate * priority_multiplier (design §4.2 step 7).
// Priority multiplier is monerod's {1,5,25,1000} table indexed by priority-1,
// defaulting to 1 for priority 0/unknown.
std::uint64_t compute_fee(std::size_t tx_weight, std::uint64_t per_byte_rate,
                          std::uint32_t priority) noexcept;

// Assemble a full single-sig RingCT transaction OFFLINE. The tx secret r and
// the pseudo-output masks are drawn from the wallet CSPRNG; output masks are the
// deterministic ecdh commitment masks. If `self_verify` (default), the assembler
// re-runs the independent verifiers and REFUSES to emit (ok=false, blob cleared)
// on any failure. `payment_id_nonce`, if non-empty, is written as a tx_extra
// nonce (0x02); pass the already-encrypted 8-byte integrated payment id prefixed
// with 0x01, or an arbitrary nonce -- read+warn only, never generated here.
AssembleResult assemble_ringct_tx(const std::vector<SpendInput>& inputs,
                                  const std::vector<TxDestination>& dests,
                                  std::uint64_t fee,
                                  const std::vector<std::uint8_t>& payment_id_nonce = {},
                                  bool self_verify = true);

// Offline self-verify-before-emit (design §5.3). Runs, on PUBLIC tx data only:
//   * the INDEPENDENT in-tree Bulletproofs+ verifier over tx.bpp, and the bind
//     check scalarmult8(bpp.V[j]) == output_commitments[j];
//   * clsag_verify for every input against its ring and pseudo-out;
//   * the commitment balance Sum pseudo_outs - Sum C_out - fee*H == identity.
// The frozen rings travel with the tx (tx.rings, in tx order), so no secret is
// needed for these public checks. Returns false with `why` on the first failing
// leg.
bool self_verify_tx_public(const RingctTx& tx, std::string& why);

// The key-image leg of self-verify needs the spend secrets, so it is checked at
// assembly time; exposed for the KAT: recompute I_i = x_i*H_p(P_real_i) and
// compare to tx.key_images[i]. Returns false with `why` on mismatch.
bool self_verify_key_images(const std::vector<SpendInput>& inputs,
                            const RingctTx& tx, std::string& why);

} // namespace c2wallet::monero::prover
