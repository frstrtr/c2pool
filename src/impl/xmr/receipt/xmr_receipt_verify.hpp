// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/receipt/xmr_receipt_verify.hpp
//   Real verification + construction for the Family-B (Monero) work receipt.
//
// X4 (real impl): this is the body the foundation scaffold only declared. Every
// crypto step is wired to X1's already-vendored primitives (do NOT re-vendor):
//   * xmr::coin::KeccakMidstate  -- resumable Keccak-256 (coinbase opening)
//   * xmr::coin::coinbase_tx_hash / tree_root / make_coinbase_branch /
//     verify_branch                                     (xmr_blob.{hpp,cpp})
//   * xmr::coin::keccak256                              (xmr_keccak_midstate.hpp)
// It touches NO src/sharechain/v37 consensus-digest code (hard fence, scoping §B).
//
// Two entry points, matching the two things the receipt must do:
//
//   verify_crypto_opening()  -- the STRUCTURAL CORE (U3 question): resume the
//       Keccak midstate over tail||tx_extra, prove H(prefix), form the RCTTypeNull
//       coinbase tx hash, walk the tree branch, and require the recomputed root ==
//       the tree_root inside the RandomX-signed hashing blob. This is what the
//       block-3000000 KAT proves end-to-end. No v37 side data needed; a raw
//       mainnet block has none.
//
//   verify_receipt()         -- the full keyed_heavy W2 ADMISSION ORDER for a
//       v37-produced receipt: dedup -> expiry -> structural+binding -> R-1 target
//       -> RandomX LAST, with RandomX CI-gated (null rx_check => SkippedCIGated).
//       So a replayed or expired receipt is rejected at stage 1/2 and NEVER forces
//       the heavy hash. open_and_bind additionally recomputes the tx_extra 0x03 MM
//       leaf from the bound side data and reads T_origin / identity / chain_id.
//
// Plus construction helpers (build_coinbase_opening / build_v37_receipt) used by
// the KAT and by the wire/template legs to MINT a receipt from coinbase bytes.
//
// FCMP++/CARROT FENCE: verification only OPENS an existing coinbase's prefix; it
// derives no output keys. Fork-agnostic (see xmr_receipt.hpp header).
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "xmr_receipt.hpp"
#include "xmr_admission.hpp"

namespace v37 {
namespace xmr {
namespace verify {

// ---- hashing-blob parse -----------------------------------------------------
// Decode get_block_hashing_blob:
//   varint(major) varint(minor) varint(timestamp) prev_id[32] nonce[4 LE]
//   tree_root[32] varint(n_tx)
// Recovers the embedded tree_root (what the coinbase opening must reconcile to),
// prev_id (the origin-bin key), and n_tx. Total: false on any truncation.
struct ParsedBlob {
    u64     major = 0, minor = 0, timestamp = 0, n_tx = 0;
    bytes32 prev_id{};
    bytes32 tree_root{};
    std::size_t header_len = 0;   // offset of tree_root within the blob
};
bool parse_hashing_blob(const HashingBlob& blob, ParsedBlob& out);

// ---- tx_extra parse ---------------------------------------------------------
// Parse the CryptoNote tx_extra tag stream. Recognizes 0x01 pubkey, 0x02 nonce,
// 0x03 merge-mining {varint(depth) || root[32]} (== settle-leg assemble_tx_extra).
// Unknown tags before/after are tolerated only if length-parseable; a malformed
// stream is a hard reject (returns false). 0x00 padding runs to end (monerod rule).
struct ParsedTxExtra {
    bool    has_pubkey = false; bytes32 pubkey{};
    bool    has_nonce  = false; std::vector<u8> nonce;
    bool    has_mm     = false; u64 mm_depth = 0; bytes32 mm_root{};
};
bool parse_tx_extra(const std::vector<u8>& extra, ParsedTxExtra& out);

// ---- commitment helpers (byte-identical to the settle leg) ------------------
// info_digest = keccak256(canonical side data). Canonical encoding:
//   t_origin.lo(LE8) t_origin.hi(LE8) payout_identity[32] chain_id(LE4) prev_own_share[32]
bytes32 side_data_digest(const ReceiptSideData& sd);

// mm_leaf = keccak256(MM_LEAF_DOMAIN || chain_id(LE4) || C). Reuses the settle
// leg's mm_commitment_root construction with C := the receipt's info_digest.
bytes32 mm_commitment_leaf(u32 chain_id, const bytes32& commitment);

// ---- coinbase-opening construction ------------------------------------------
// Capture a CoinbaseOpening from the full serialized miner_tx prefix and the
// offset at which the tx_extra bytes begin (i.e. just after the extra-length
// varint). midstate/prefix_tail are taken from X1's KeccakMidstate byte-exactly;
// tx_extra := prefix_bytes[extra_start..end]. False if extra_start is out of range.
bool build_coinbase_opening(const std::vector<u8>& prefix_bytes,
                            std::size_t extra_start, CoinbaseOpening& out);

// Resume a CoinbaseOpening -> H(prefix) (the tx-prefix hash). Reconstructs X1's
// KeccakMidstate from (midstate, prefix_tail), absorbs tx_extra, finalizes.
bool resume_prefix_hash(const CoinbaseOpening& o, bytes32& h_prefix_out);

// ---- structural core --------------------------------------------------------
// The U3 opening: resume -> H(prefix) -> coinbase tx hash -> tree branch -> root
// == blob's tree_root. Fills tree_root + miner_tx_hash in `out`; leaves the v37
// binding fields (t_origin/identity/chain_id) UNSET (a raw block carries none).
// This is "verify() end-to-end EXCEPT RandomX" for a mainnet block.
bool verify_crypto_opening(const MoneroReceipt& r, OpenedCommitment& out,
                           std::string* why = nullptr);

// ---- full binding open (structural stage of the admission order) ------------
// verify_crypto_opening + the v37 side-data binding: require r.side_data present,
// info_digest == keccak256(side_data), the tx_extra 0x03 leaf == mm_commitment_leaf
// (chain_id, info_digest), chain_id == lane, payout_identity == carrier. Reads
// T_origin/identity/chain_id into `out`. This is AdmissionHooks::open_and_bind.
bool open_and_bind_impl(const MoneroReceipt& r, const bytes32& carrier_identity,
                        u32 lane_chain_id, OpenedCommitment& out,
                        std::string* why = nullptr);

// ---- receipt construction (mint) --------------------------------------------
// Build a complete v37 MoneroReceipt around a coinbase whose prefix is
// [head || tx_extra], where tx_extra already carries the 0x03 MM leaf committing
// side_data's info_digest. `other_leaves` are the non-coinbase tx hashes (may be
// empty => n_tx == 1 => tree_root == coinbase hash). Fills every field incl. the
// hashing_blob (header || tree_root || varint(n_tx)) and the tree branch for
// leaf 0. Returns false if the inputs are inconsistent.
struct BuildInputs {
    // Monero block header fields (for the hashing blob).
    u8      major = 16, minor = 16;
    u64     timestamp = 0;
    bytes32 prev_id{};
    u32     nonce = 0;
    // Coinbase prefix, split at the tx_extra boundary (extra_start = head length).
    std::vector<u8> prefix_bytes;
    std::size_t     extra_start = 0;
    // Non-coinbase leaves (tx hashes), coinbase is always leaf 0.
    std::vector<bytes32> other_leaves;
    // v37 side data (its info_digest must already be committed in prefix's 0x03).
    ReceiptSideData side_data;
    // seed policy
    SeedRefPolicy seed_policy = SeedRefPolicy::DerivedFromBin;
};
bool build_v37_receipt(const BuildInputs& in, MoneroReceipt& out, std::string* why = nullptr);

// ---- front door -------------------------------------------------------------
// Wire the real hooks and run admit_receipt_keyed_heavy. rx_check == null (the
// default) CI-gates the heavy hash (RandomXStatus::SkippedCIGated on accept). The
// index oracles default to KAT-friendly stubs if left null; production wiring
// supplies the node index. `opened` receives the bound commitment on accept.
struct VerifyConfig {
    // index oracles (nullable => defaults suitable for the KAT)
    std::function<bool(const HashingBlob&, u64&)>              bin_of;
    std::function<bool(u64, Difficulty&)>                      consensus_difficulty;
    std::function<bool(u64, const SeedRef&, bytes32&)>         seed_for_bin;
    std::function<bool(const bytes32&)>                        seen;
    // heavy hasher; null => CI-gated skip.
    std::function<bool(const bytes32&, const HashingBlob&, const Difficulty&, bytes32&)> rx_check;
};
AdmitOutcome verify_receipt(const MoneroReceipt& r,
                            const bytes32& carrier_identity,
                            u64 carrier_bin,
                            u32 lane_chain_id,
                            const LaneKeyedHeavy& lp,
                            const VerifyConfig& cfg,
                            OpenedCommitment& opened);

// cheap dedup identity: receipt_id = keccak256(hashing_blob). Exposed so the
// caller (and the KAT) can pre-seed a dedup store to exercise the replay path.
bytes32 cheap_receipt_id(const HashingBlob& blob);

} // namespace verify
} // namespace xmr
} // namespace v37
