// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/anchor/xmr_anchor_embedded.hpp
//
// The RELEASE-PINNED bundles compiled into the binary, one per network, and the
// lookup load_anchor() uses when it is given no path.
//
// R-ANCHOR, THE SHIPPED HALF. The ruling is "release-pinned self-generated
// bundle": the artefact a cold start trusts is minted by us, reviewed by us and
// frozen into the release, exactly the way monerod compiles in its own
// checkpoints. A daemon-minted bundle at boot (M0-M4) is the same struct from a
// live daemon; this file is the M5 path, where there is no daemon to ask.
//
// WHY #include AND NOT A GENERATED .cpp. The .inc IS the file on disk: it opens
// with a raw-string frame, so the identical bytes load from a path and from the
// binary, and there is no second copy to drift. A raw string literal is one
// preprocessing token formed before directives are considered, which is what
// makes the '#' provenance comments inside the bundle safe to embed verbatim.
//
// A NETWORK WITH NO BUNDLE RETURNS nullptr, and load_anchor() then refuses with
// "this build carries no embedded anchor bundle" rather than starting on
// nothing. Adding a network here is deliberately a code change plus a review of
// the bytes, not a config knob.
//
// PROVENANCE lives in the '#' header of each .inc: which daemon minted it, at
// which tip, on which date, how deep the anchor sits. Those lines are outside
// the digest on purpose (xmr_anchor_codec.hpp, THE DIGEST RULE) so a release can
// annotate a bundle without changing what the digest protects.
// ---------------------------------------------------------------------------
#pragma once

#include "impl/xmr/native/consensus/xmr_hf_table.hpp"   // XmrNet

namespace c2pool::xmr::native {

// --- stagenet ---------------------------------------------------------------
// THE PINNED ONE: format 2 at H_a 2213803, committing the output/spent roots of
// the release's stagenet output-set snapshot. Its file sha256 and the
// snapshot's are pinned in xmr_anchor_pinned.hpp and listed in
// docs/xmr-lane/PINNED-SNAPSHOTS.md. Minted from a synced monerod 0.18.5.1
// over read-only RPC; see the '#' header inside the file for tip, date and
// burial depth.
inline constexpr const char* ANCHOR_EMBEDDED_STAGENET =
#include "impl/xmr/native/anchor/xmr_chain_anchor_stagenet_f2.inc"
;

// The earlier FORMAT-1 stagenet bundle (H_a 2204000, no committed output
// set). No longer what a stagenet node boots from; kept compiled so the codec
// KAT keeps a real format-1 bundle to read back byte for byte.
inline constexpr const char* ANCHOR_EMBEDDED_STAGENET_F1 =
#include "impl/xmr/native/anchor/xmr_chain_anchor_stagenet.inc"
;

// --- mainnet ----------------------------------------------------------------
// THE PINNED ONE: format 2 at H_a 3765865, minted from the operator's own
// synced monerod and pinned like stagenet. The 18 GB output-set snapshot it
// commits to ships beside the release, not inside the binary.
inline constexpr const char* ANCHOR_EMBEDDED_MAINNET =
#include "impl/xmr/native/anchor/xmr_chain_anchor_mainnet_f2.inc"
;

// --- testnet / regtest ------------------------------------------------------
// Not minted. Regtest has no stable chain to pin at all -- a regtest node is
// expected to pass --anchor-path or to start from its own daemon.
inline constexpr const char* ANCHOR_EMBEDDED_TESTNET = nullptr;
inline constexpr const char* ANCHOR_EMBEDDED_REGTEST = nullptr;

// The lookup load_anchor() uses for an empty path. nullptr is a refusal, never
// an empty bundle.
inline const char* anchor_embedded_text(XmrNet net) noexcept {
    switch (net) {
        case XmrNet::Mainnet:  return ANCHOR_EMBEDDED_MAINNET;
        case XmrNet::Testnet:  return ANCHOR_EMBEDDED_TESTNET;
        case XmrNet::Stagenet: return ANCHOR_EMBEDDED_STAGENET;
        case XmrNet::Regtest:  return ANCHOR_EMBEDDED_REGTEST;
    }
    return nullptr;
}

}  // namespace c2pool::xmr::native
