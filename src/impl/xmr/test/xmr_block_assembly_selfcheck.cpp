// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_block_assembly_selfcheck.cpp   (X9 option B)
//
// 3-line driver for the whole-block-assembly self-check (K0..K6 in
// xmr_block_assembly.hpp::kat::selfcheck): proves the X9 option-B components
// integrate and are byte-correct WITHOUT monerod or RandomX —
//   K0  primitive bodies (varint / Keccak one-shot + midstate / mul-div-128)
//       byte-identical to the vendored oracle for every split;
//   K1  regtest-shape sink-only coinbase (empty ledger, whole reward -> sink);
//   K2  6 owed + fixed + sink, K_fair oldest-owed-first order preserved;
//   K3  penalty-zone reward/payee-set fixpoint (rebuild at the wanted reward);
//   K4  same set at the final reward (adopted in pass 1);
//   K5/K6 fail-closed (CARROT fence, missing residual sink, cap too small);
//   and for each template + extra_nonce: (a) the template miner_tx prefix ==
//   X6 build_coinbase().prefix, (b/c) the hashing-blob tree root == tree_root
//   ([X6 coinbase leaf] ++ tx ids) with a verifying branch, (d) both blobs
//   share the header and the block id computes, (e) the served prefix re-parses
//   and canonical_coinbase_matches() == true (the W3 ACCEPT re-derivation), with
//   a negative control. i.e. "the X6 K_fair coinbase IS the block's coinbase."
//
// The primitive bodies come from linking xmr_template (xmr_coin_primitives.o);
// this TU does NOT define XMR_BLOCK_ASSEMBLY_IMPLEMENT_PRIMITIVES (the ODR rule).
// ---------------------------------------------------------------------------
#define XMR_BLOCK_ASSEMBLY_SELFCHECK_MAIN
#include "impl/xmr/template/xmr_block_assembly.hpp"
