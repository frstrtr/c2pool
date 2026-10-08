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
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. Full BSD-3 text: xmr_derivation.cpp.
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/artifact/MoneroArtifact.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/wallet/wallet2.h / wallet2.cpp
//              (the four cold-signing artifacts and their magic strings:
//               export_outputs / import_outputs_from_str  [OUTPUT_EXPORT_FILE_MAGIC],
//               export_key_images / import_key_images     [KEY_IMAGE_EXPORT_FILE_MAGIC],
//               save_tx / load_unsigned_tx  (struct unsigned_tx_set,
//               tx_construction_data, cryptonote::tx_source_entry)
//                                                          [UNSIGNED_TX_PREFIX],
//               sign_tx / load_tx           (struct signed_tx_set, pending_tx)
//                                                          [SIGNED_TX_PREFIX]);
//              src/cryptonote_basic/cryptonote_format_utils.cpp for the tx blob
//              this signed_txset carries (produced by MoneroRingctBuilder).
//   License  : BSD-3-Clause (header above; full text in xmr_derivation.cpp).
//   Subset   : the OFFLINE marshaling of the four public artifacts that cross
//              the air gap (design §5.4 Family B). Decision 9 (LOCKED
//              2026-09-12): adopt monero's binary layouts VERBATIM for interop,
//              so a stock monero-wallet-cli can serve as a fallback counterparty.
//
// PARITY NOTE (honest limit, addressed in the .cpp and the KAT):
//   Monero wraps each artifact's payload in TWO layers this Qt-free, boost-free,
//   libsodium-free module cannot reproduce from headers alone:
//     (1) a boost::archive::portable_binary_[io]archive framing of the outer
//         container structs (transfer_details / tx_construction_data / pending_tx);
//     (2) a chacha20 encryption+MAC layer keyed on the wallet view secret key
//         (encrypt_with_view_secret_key), which is also monero's tamper check.
//   We therefore mirror monero's magic-string prefixes VERBATIM and each inner
//   record's FIELD ORDER faithfully over the CryptoNote LEB128 varint framing
//   (tools::write_varint -- the same put_varint the tx blob uses), and stand in
//   for the chacha MAC with an 8-byte keccak integrity footer so tamper is
//   detected today. Replacing the footer with monero's chacha-view-key envelope
//   and the boost archive is the documented byte-parity gap; the signed tx blob
//   itself (the interop-critical payload) is carried VERBATIM from M4-X.
// ===========================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"                  // Bytes32
#include "family/monero/MoneroKey.hpp"                     // MoneroKeys
#include "family/monero/scan/MoneroScanner.hpp"            // ExportedOutput, SubaddressIndex
#include "family/monero/prover/MoneroClsag.hpp"            // CtKey
#include "family/monero/prover/MoneroKeyImage.hpp"         // ExportedKeyImage
#include "family/monero/prover/MoneroRingctBuilder.hpp"    // RingctTx, SpendInput, TxDestination

namespace c2wallet::monero::artifact {

// ── monero magic-string prefixes, VERBATIM (wallet2.cpp) ────────────────────
// The trailing byte of each is monero's artifact version number (a raw byte,
// not an ASCII digit); it may bump across monero releases. Values below match
// the recent monero series; parse() accepts the exact string only.
extern const char OUTPUT_EXPORT_MAGIC[];       // "Monero output export\004"
extern const char KEY_IMAGE_EXPORT_MAGIC[];    // "Monero key image export\002"
extern const char UNSIGNED_TX_MAGIC[];         // "Monero unsigned tx set\005"
extern const char SIGNED_TX_MAGIC[];           // "Monero signed tx set\005"

// ── (1) outputs export  (online view-only  ->  offline full wallet) ─────────
// monero: wallet2::export_outputs -> std::pair<uint64_t /*offset*/,
//   std::vector<exported_transfer_details>>. Carries the wallet's OWN outputs
// and NO secret (no view/spend key, no one-time secret x_i, no key image).
std::vector<unsigned char> produce_outputs_export(
    const std::vector<ExportedOutput>& outs, std::uint64_t offset = 0);

bool parse_outputs_export(const std::vector<unsigned char>& blob,
                          std::vector<ExportedOutput>& outs,
                          std::uint64_t& offset, std::string& err);

// ── (2) key-image export  (offline full wallet  ->  online view-only) ───────
// monero: wallet2::export_key_images -> std::pair<uint64_t /*offset*/,
//   std::vector<std::pair<crypto::key_image, crypto::signature>>>. Public: the
// image I_i and a ring signature proving ownership -- NO secret x_i. We also
// carry the one-time pubkey P_i so the online side can bind image<->output.
std::vector<unsigned char> produce_key_image_export(
    const std::vector<prover::ExportedKeyImage>& imgs, std::uint64_t offset = 0);

bool parse_key_image_export(const std::vector<unsigned char>& blob,
                            std::vector<prover::ExportedKeyImage>& imgs,
                            std::uint64_t& offset, std::string& err);

// ── (3) unsigned txset  (online view-only  ->  offline full wallet) ─────────
// monero: struct unsigned_tx_set { std::vector<tx_construction_data> txes; ... }.
// Each source (cryptonote::tx_source_entry) carries the FROZEN ring the online
// side selected + the real output's provenance (R + in-tx index) so the offline
// full wallet RE-DERIVES the one-time secret x_i from ITS OWN keys -- the
// unsigned set itself holds NO spend secret. Destinations + fee + tx_extra +
// change (change is one of the destinations, owner-directed) travel frozen too.
struct UnsignedTxSource {
    std::vector<std::uint64_t> ring_global_indices;  // absolute output indices (frozen)
    std::vector<prover::CtKey> ring;                 // frozen decoys + the real member
    std::uint64_t              real_index{0};        // position of the real member in `ring`
    Bytes32                    real_out_tx_key{};    // R of the tx that created the real output
    std::uint64_t              real_output_in_tx_index{0}; // i within that tx
    std::uint64_t              amount{0};            // cleartext amount of the real output
    Bytes32                    mask{};               // rct commitment mask of the real output
};

struct UnsignedTxSet {
    std::vector<UnsignedTxSource>      sources;
    std::vector<prover::TxDestination> dests;        // splitted_dsts incl. change
    std::uint64_t                      fee{0};
    std::vector<std::uint8_t>          tx_extra;      // frozen extra (e.g. payment-id nonce)
};

std::vector<unsigned char> produce_unsigned_txset(const UnsignedTxSet& u);

bool parse_unsigned_txset(const std::vector<unsigned char>& blob,
                          UnsignedTxSet& u, std::string& err);

// Bridge: turn a parsed UnsignedTxSet into the M4-X assembler's SpendInputs by
// re-deriving each real output's one-time secret x_i from the offline wallet's
// keys (monero wallet2::sign_tx re-derivation). FULL WALLET ONLY: returns false
// if `keys` is view-only. This is the offline side's step before assembly; the
// derived x_i live only inside the returned SpendInputs.
bool sources_to_spend_inputs(const UnsignedTxSet& u, const MoneroKeys& keys,
                             std::vector<prover::SpendInput>& out, std::string& err);

// ── (4) signed txset  (offline full wallet  ->  online view-only) ───────────
// monero: struct signed_tx_set { std::vector<pending_tx> ptx;
//   std::vector<crypto::key_image> key_images; ... }; pending_tx carries the
// fully-signed cryptonote::transaction. We carry the serialized CryptoNote tx
// blob VERBATIM (from MoneroRingctBuilder -- the interop-critical bytes), its
// tx_hash, and the per-input key images. A signed tx is self-authenticating and
// carries no secret.
struct SignedTxSet {
    std::vector<unsigned char> tx_blob;    // serialized CryptoNote tx (verbatim)
    Bytes32                    tx_hash{};
    std::vector<Bytes32>       key_images;
};

std::vector<unsigned char> produce_signed_txset(const prover::RingctTx& tx);

bool parse_signed_txset(const std::vector<unsigned char>& blob,
                        SignedTxSet& s, std::string& err);

} // namespace c2wallet::monero::artifact
