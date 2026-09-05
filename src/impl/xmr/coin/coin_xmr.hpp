// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/coin_xmr.hpp  --  Family B (XMR lane) primitive facade
//
// AUTHORED for c2pool (not ported). Single umbrella header for the Monero
// primitive layer, occupying the src/impl/<coin>/coin/ slot that the
// Bitcoin-family lanes fill with SHA256d merkle / scriptSig gentx. This tree is
// wire-incompatible with those (Levin p2p, CryptoNote varint/blob, Keccak tree
// hashes, ed25519) -- reuse is ~0% BELOW the sharechain seam and ~100% ABOVE it
// (V37Engine, lanes, W2/W3/W4, storage). Nothing here touches src/sharechain/v37
// consensus-digest code (scoping S B / hard fence).
//
// What lives under coin/ (this leg -- X1 "Monero primitives"):
//   xmr_crypto_types.hpp   POD key/scalar/hash/view-tag byte-strings          [authored]
//   xmr_keccak_midstate.hpp Keccak-256 + resumable midstate (coinbase opening) [authored over vendored keccak]
//   xmr_derivation.{hpp,cpp} generate_key_derivation / derivation_to_scalar /
//                            derive_public_key / derive_view_tag               [BSD-3 subset of crypto.cpp]
//   xmr_seedheight.hpp     RandomX seed_height((h-64-1)&~2047), epoch edges    [authored]
//   xmr_check_hash.hpp     128-bit difficulty test hash*d <= 2^256-1           [authored, oracle: difficulty.cpp]
//   xmr_pow_select.hpp     major_version -> PoW algo; RandomX-v2 / CARROT fences [authored]
//   xmr_blob.{hpp,cpp}     CryptoNote varint/blob; hashing-blob; coinbase tx
//                          hash; tree_root/branch                              [authored over vendored varint/tree-hash]
//   vendor/                verbatim BSD-3 monero-project crypto (see PROVENANCE.md)
//
// NOT in this leg (sibling legs / later X-milestones): the RandomX hasher wrapper
// with epoch cache management (randomx-vendor leg, tevador/RandomX BSD-3); the
// monerod JSON-RPC + ZMQ adapter; the CryptoNote/XMRig stratum dialect; the
// whole-block template builder; the W5 settlement executor (deterministic-r,
// K_fair output order, exact-sum residual sink). Those consume this surface.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#include "xmr_crypto_types.hpp"
#include "xmr_keccak_midstate.hpp"
#include "xmr_derivation.hpp"
#include "xmr_seedheight.hpp"
#include "xmr_check_hash.hpp"
#include "xmr_pow_select.hpp"
#include "xmr_blob.hpp"

namespace xmr::coin {

// -- Monero consensus constants the lane pins (monero-project cryptonote_config.h) --
inline constexpr std::uint64_t COIN                      = 1000000000000ULL; // 1e12 piconero
inline constexpr std::uint64_t FINAL_SUBSIDY_PER_MINUTE  = 300000000000ULL;  // -> 0.6 XMR/block
inline constexpr std::uint32_t DIFFICULTY_TARGET_V2      = 120;              // seconds/block
inline constexpr std::uint32_t MINED_MONEY_UNLOCK_WINDOW = 60;              // -> D_conf floor 60
inline constexpr std::uint8_t  HF_VERSION_MIN_V2_COINBASE_TX      = 12;
inline constexpr std::uint8_t  HF_VERSION_REJECT_SIGS_IN_COINBASE = 12;
inline constexpr std::uint8_t  HF_VERSION_EXACT_COINBASE          = 13; // Sum(vout)==reward+fees
inline constexpr std::uint8_t  HF_VERSION_VIEW_TAGS               = 15; // txout_to_tagged_key

// One-time output key + view tag for payee (spend=B, view=A) at output index i,
// given tx secret r. == p2pool Wallet::get_eph_public_key (scoping S16). Every
// v37 node runs this to byte-compare the coinbase OWED settlement list.
// GUARDED: coinbase derivation is pinned pre-CARROT (xmr_pow_select FENCE 2).
inline bool get_eph_public_key(std::uint8_t major_version,
                               const PublicKey& view_pub_A, const PublicKey& spend_pub_B,
                               const SecretKey& tx_sec_r, std::size_t output_index,
                               PublicKey& out_eph, ViewTag& out_view_tag) {
    if (!coinbase_derivation_is_pre_carrot(major_version)) return false; // FENCE 2
    KeyDerivation D;
    if (!generate_key_derivation(view_pub_A, tx_sec_r, D)) return false; // D = 8*r*A
    if (!derive_public_key(D, output_index, spend_pub_B, out_eph)) return false; // P_i
    derive_view_tag(D, output_index, out_view_tag);
    return true;
}

} // namespace xmr::coin
