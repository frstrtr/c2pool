// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/settle/xmr_carrot.hpp  --  CARROT / FCMP++ coinbase-output
//                                         derivation SEAM  (SCAFFOLD ONLY)
//
// ===========================================================================
//   STATUS: SCAFFOLD. NO CONFORMANT DERIVATION IS IMPLEMENTED HERE.
// ===========================================================================
//   Every entry point in this header FAILS CLOSED. `DERIVATION_IMPLEMENTED`
//   is false, and the W5-XMR coinbase builder keeps returning
//   BuildError::CarrotFence for any Monero major_version in the CARROT regime.
//   Nothing in this translation unit may ever produce a coinbase output key.
//
//   WHY A SCAFFOLD AND NOT AN IMPLEMENTATION -- the honest reading of the
//   upstream state, verified against primary sources (not aggregators):
//
//     * monero-project/monero `master` AND `release-v0.18`:
//       src/hardforks/hardforks.cpp mainnet table ENDS AT { 16, 2689608 }
//       (v16, activated 2022-06-30). There is no v17 row. Re-verified
//       2026-09-17.
//     * monero-project/monero `master` has NO src/carrot_core directory and
//       NO HF_VERSION_CARROT / FCMP++ constants in src/cryptonote_config.h.
//     * The newest upstream release is the v0.18.5.x line (CLI 0.18.5.1,
//       2026-07-08). There is no v0.19 / FCMP++ release.
//     * The CARROT + FCMP++ code lives on the seraphis-migration/monero fork
//       (`fcmp++-stage`, `fcmp++-beta-stressnet`), where cryptonote_config.h
//       sets HF_VERSION_FCMP_PLUS_PLUS = HF_VERSION_CARROT = 17 and the
//       mainnet fork rows { 17, 2689609 } / { 18, 2689610 } are explicitly
//       commented "Mock values for tests".
//     * Upstream integration is in flight, NOT merged: carrot_core (#9559,
//       open, under review), FCMP++ integration (#9436, draft), carrot_impl
//       (#9697, draft), RandomX V2 + PoW commitments in v17 (#10038, open and
//       contested). The "fcmp++ hf" milestone is incomplete.
//     * No mainnet fork height and no fork date have been announced.
//
//   CONSEQUENCE: 17 is the de-facto expected fork number, but it is NOT pinned
//   by any upstream release, and there are NO published reference vectors for
//   CARROT *coinbase* enotes that c2pool could pin a KAT against. Implementing
//   a derivation now would mean inventing conformance. The lane therefore keeps
//   the fence and ships the SEAM: the exact shape of the future call, the
//   transcription of the constants, and an explicit statement of what is still
//   missing. See docs/xmr-lane/carrot-coinbase-seam.md.
//
// ---------------------------------------------------------------------------
//   SOURCES OF RECORD (for whoever implements this later)
//     * jeffro256/carrot -- carrot.md (the design text; carries no version,
//       no status marker and no test vectors).
//     * seraphis-migration/monero `fcmp++-stage` -- the reference
//       implementation, which is AUTHORITATIVE wherever the design text is
//       under-specified (the keyed hashing and the length-prefixed transcript
//       are implementation facts the prose writes as plain concatenation):
//         src/carrot_core/{enote_utils,payment_proposal,hash_functions}.cpp
//         src/carrot_core/{transcript_fixed.h,config.h}
//         src/carrot_impl/format_utils.cpp        (tx assembly)
//         src/cryptonote_core/                    (consensus checks)
//
//   The constants below are a TRANSCRIPTION of that reference implementation.
//   They are documentation for the seam. They have NOT been validated against
//   any published test vector, they are NOT consensus in c2pool, and nothing
//   in the shipped lane consumes them. Treat every one as provisional until
//   upstream tags a release.
//
//   HEADER-ONLY ON PURPOSE. The refusing bodies are `inline` here rather than in
//   a sibling .cpp because seven different CMake targets already compile
//   ../settle/xmr_coinbase.cpp; a new translation unit would have to be added to
//   every one of them, and a single missed site is a link error in a distant
//   target. When the derivation is really implemented it will need a .cpp (and
//   those seven source lists updated in the same commit) -- that is part of the
//   lift, not of this scaffold.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_crypto_types.hpp"    // Bytes32, PublicKey, SecretKey
#include "sharechain/v37/v37_descriptor_xmr.hpp" // ScriptRef + the pre-CARROT fence

namespace v37 {
namespace xmr {
namespace settle {
namespace carrot {

// ---------------------------------------------------------------------------
// THE GATE. Flip this to true ONLY together with (a) a derivation that matches
// a tagged upstream release, (b) reference vectors pinned in a KAT, and (c) an
// operator ruling lifting the fence. Nothing else may read it as "ready".
// ---------------------------------------------------------------------------
inline constexpr bool DERIVATION_IMPLEMENTED = false;

// Whether a c2pool node may build a CARROT-regime coinbase at all. Fail-closed
// by construction: it is exactly DERIVATION_IMPLEMENTED.
inline constexpr bool conformant() { return DERIVATION_IMPLEMENTED; }

// The fork number CARROT + FCMP++ are EXPECTED to activate at. Recorded for the
// seam only; the shipped fence is the descriptor's
// XMR_PRECARROT_MAX_MAJOR_VERSION and does not depend on this value being right.
inline constexpr std::uint8_t CARROT_EXPECTED_MAJOR_VERSION = 17;

// True once upstream monero-project/monero pins the fork in a tagged release.
// It does not, as of 2026-09-17, so this is false and the seam stays shut.
inline constexpr bool UPSTREAM_FORK_PINNED = false;

// ---------------------------------------------------------------------------
// TRANSCRIBED CONSTANTS (provisional; see the banner). Domain separators are
// the exact byte strings in carrot_core/config.h.
// ---------------------------------------------------------------------------
inline constexpr char DS_SENDING_KEY_NORMAL[]      = "Carrot sending key normal";
inline constexpr char DS_SENDER_RECEIVER_SECRET[]  = "Carrot sender-receiver secret";
inline constexpr char DS_COINBASE_EXTENSION_G[]    = "Carrot coinbase extension G";
inline constexpr char DS_COINBASE_EXTENSION_T[]    = "Carrot coinbase extension T";
inline constexpr char DS_VIEW_TAG[]                = "Carrot view tag";
inline constexpr char DS_ENCRYPTION_MASK_ANCHOR[]  = "Carrot encryption mask anchor";

// input_context prefix bytes: 'C' for a coinbase enote, 'R' for RingCT.
inline constexpr unsigned char INPUT_CONTEXT_COINBASE = 0x43;  // 'C'
inline constexpr unsigned char INPUT_CONTEXT_RINGCT   = 0x52;  // 'R'

// input_context (coinbase) = 'C' || IntToBytes256(height), i.e. 1 + 32 bytes,
// where IntToBytes256 is the 32-byte little-endian encoding (so: u64le(height)
// followed by 24 zero bytes).
inline constexpr std::size_t INPUT_CONTEXT_COINBASE_LEN = 33;

inline constexpr std::size_t ANCHOR_LEN   = 16;  // anchor_norm, MUST be non-zero
inline constexpr std::size_t VIEW_TAG_LEN = 3;   // H_3 -- 3 bytes, not 1
inline constexpr std::size_t D_E_LEN      = 32;  // X25519 ephemeral pubkey

// BLAKE2b personalisation used by every Carrot hash: "Monero", zero-padded to
// 16 bytes. Keyed variants feed the 32-byte key as a standard keyed-BLAKE2b key.
inline constexpr char BLAKE2B_PERSONAL[] = "Monero";

// ---------------------------------------------------------------------------
// WHAT A CARROT COINBASE OUTPUT IS. Shape only -- this struct is never filled
// by shipped code while DERIVATION_IMPLEMENTED is false.
// ---------------------------------------------------------------------------
struct CarrotCoinbaseEnote {
    ::xmr::coin::PublicKey onetime_address{};                 // K_o
    std::uint64_t          amount = 0;                        // plaintext, coinbase
    unsigned char          ephemeral_pubkey[D_E_LEN]{};       // D_e (X25519)
    unsigned char          view_tag[VIEW_TAG_LEN]{};          // 3 bytes
    unsigned char          anchor_enc[ANCHOR_LEN]{};          // encrypted anchor
};

// The inputs one CARROT coinbase output needs.
struct CarrotCoinbaseRequest {
    ::v37::ScriptRef pay;            // payee (K_s || K_v), MAIN address only
    std::uint64_t    amount = 0;     // piconero
    std::uint64_t    height = 0;     // block height -> input_context
    unsigned char    anchor_norm[ANCHOR_LEN]{};  // 16 bytes, MUST be non-zero
};

// Why a CARROT call refused.
enum class CarrotError : std::uint8_t {
    None = 0,
    NotImplemented,      // the scaffold: no conformant derivation exists
    UpstreamNotPinned,   // monero-project has not tagged the fork
    BadPayeeDescriptor,  // not an XMR kind / wrong width
    SubaddressForbidden, // coinbase enotes are main-address only
    NullAnchor,          // anchor_norm is all-zero
};

inline const char* to_string(CarrotError e) {
    switch (e) {
        case CarrotError::None:                return "none";
        case CarrotError::NotImplemented:      return "CARROT derivation not implemented (scaffold)";
        case CarrotError::UpstreamNotPinned:   return "upstream monero-project has not pinned the CARROT fork";
        case CarrotError::BadPayeeDescriptor:  return "payee is not a valid XMR ref";
        case CarrotError::SubaddressForbidden: return "coinbase enotes are main-address only";
        case CarrotError::NullAnchor:          return "anchor_norm is all-zero";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// THE SEAM. Both entry points return false and set *err = NotImplemented for as
// long as DERIVATION_IMPLEMENTED is false. They exist so the future
// implementation has one obvious place to land and one obvious contract, and so
// that a KAT can PROVE the lane refuses rather than guesses.
//
// The derivation the implementer must fill in, as far as it has been captured
// from the reference implementation (steps 1-7 below are transcribed; the
// remaining steps are NOT captured and are named in the gap list):
//
//   PRIMITIVES
//     H_b^{key}(x)  = BLAKE2b, digest_length = b, key_length = (key ? 32 : 0),
//                     fanout 1, depth 1, personal = BLAKE2B_PERSONAL padded to
//                     16 bytes; keyed form is standard keyed BLAKE2b.
//     SecretDerive  = H_32 ; view tag = H_3 ; masks = H_16
//     ScalarDerive  = sc_reduce(H_64(x))     (BytesToInt512 mod l)
//     transcript    = u8(len(ds)) || ds (no NUL) || fields, each field raw and
//                     fixed-width, integers little-endian (u64 amount = 8 B LE)
//     X25519        = UNCLAMPED scalar mult throughout; base B has x = 9
//     ConvertPointE(K) : x = (1 + y) / (1 - y) from the Ed25519 y coordinate
//     Generators    : G (ed25519 base), H, T = Hp2(Keccak256("Monero Generator T"))
//
//   PER COINBASE OUTPUT, payee MAIN address (K_s spend, K_v view), amount a,
//   height h  -- reference: get_coinbase_enote_v1 / get_external_output_proposal_
//   parts / get_output_proposal_parts:
//     1. input_context = 'C' || u64le(h) || 24 zero bytes            (33 bytes)
//     2. anchor_norm   = 16 bytes, MUST be non-zero. SENDER-CHOSEN. monerod uses
//        random (gen_janus_anchor()); a pool cannot, because every node must
//        re-derive the identical coinbase. This is a v37 DESIGN DECISION, not a
//        conformance item -- the v37 analogue of derive_tx_secret_key(). For
//        reference, P2Pool (Go consensus v5, carrot/p2pool.go) defines its own:
//          anchor = H_16^{key = seed}("P2Pool deterministic Carrot output
//                   randomness" || input_context || K_s || K_v || u32le(nonce))
//        with nonce incremented until the result is non-zero.
//     3. d_e   = ScalarDerive( tr(DS_SENDING_KEY_NORMAL, anchor_norm[16],
//                                 input_context[33], K_s[32], K_v[32],
//                                 pid[8] = 0) )
//                (K_v IS in the transcript: carrot_core enote_utils.cpp
//                make_carrot_enote_ephemeral_privkey, fcmp++-stage)
//                (unkeyed; the payment id MUST be null for a coinbase)
//     4. D_e   = d_e * B    (X25519, unclamped; 32-byte x-coordinate; carried in
//                tx_extra as a 32-byte pubkey). The subaddress form
//                d_e * ConvertPointE(K_s^j) is FORBIDDEN for coinbase
//                (the reference throws bad_address_type).
//     5. s_sr  = d_e * ConvertPointE(K_v)   (unclamped X25519; K_v must be in
//                the prime-order subgroup -- which the v37 descriptor torsion
//                rule already guarantees). Recipient side: s_sr = k_v * D_e.
//     6. s_sr_ctx = H_32^{key = s_sr}( tr(DS_SENDER_RECEIVER_SECRET,
//                                         D_e[32], input_context[33]) )
//     7. k_g = ScalarDerive^{key = s_sr_ctx}( tr(DS_COINBASE_EXTENSION_G,
//                                               u64le(a), K_s[32]) )
//        k_t = ScalarDerive^{key = s_sr_ctx}( tr(DS_COINBASE_EXTENSION_T,
//                                               u64le(a), K_s[32]) )
//
//   GAP LIST -- NOT CAPTURED, and therefore NOT guessed here:
//     (G1) the assembly of K_o from K_s, k_g, k_t and the generators;
//     (G2) the exact view-tag transcript (which fields, in which order);
//     (G3) the anchor encryption (DS_ENCRYPTION_MASK_ANCHOR) and whether a
//          coinbase enote carries anchor_enc at all;
//     (G4) the serialized coinbase output/tx_extra layout under FCMP++
//          (output type tag, where D_e lives, MAX_TX_EXTRA_SIZE = 1060);
//     (G5) the v17 consensus caps that bound the K_fair output count --
//          FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS = 10000, REJECT_MANY_MINER_OUTPUTS,
//          REJECT_UNLOCK_TIME, REJECT_LARGE_EXTRA, the 2026 scaling rules;
//     (G6) whether v17 also changes the PoW hashing blob (RandomX v2 +
//          commitments, monero-project/monero#10038, open and contested),
//          which would move the W3 receipt/oracle seam, not this one;
//     (G7) reference vectors for a CARROT COINBASE enote. None are published.
//          Without (G7) no KAT can pin conformance, so the fence MUST stay up.
// ---------------------------------------------------------------------------

// The scaffold contract, asserted where the bodies are. If this fires, someone
// set DERIVATION_IMPLEMENTED without replacing the refusing bodies below.
static_assert(!DERIVATION_IMPLEMENTED,
              "the CARROT seam still contains only refusing stubs: implement "
              "derive_coinbase_enote()/derive_deterministic_anchor() against a "
              "TAGGED upstream release with pinned reference vectors before "
              "flipping DERIVATION_IMPLEMENTED");

// Derive one CARROT coinbase enote. ALWAYS returns false in this scaffold.
//
// REFUSING STUB. The derivation this must one day contain is written out, step
// by step and gap by gap, in the seam comment above. It is deliberately NOT
// approximated: a partially-right coinbase derivation pays real money to keys
// nobody can spend, and an unspendable coinbase is not a test failure, it is a
// burned block reward.
inline bool derive_coinbase_enote(const CarrotCoinbaseRequest& /*req*/,
                                  CarrotCoinbaseEnote& out,
                                  CarrotError* err = nullptr) {
    out = CarrotCoinbaseEnote{};   // leave nothing half-filled for a caller to use
    if (err) *err = CarrotError::NotImplemented;
    return false;
}

// Derive the deterministic per-output anchor (the v37 design decision named in
// step 2). ALWAYS returns false in this scaffold.
//
// REFUSING STUB. monerod picks the anchor at random, which a pool cannot do,
// because every node must re-derive the identical coinbase byte-for-byte.
// Picking it wrongly is a silent privacy failure (Janus-style address linkage),
// not a build error, so it is an operator ruling and not a transcription.
inline bool derive_deterministic_anchor(const ::v37::ScriptRef& /*pay*/,
                                        std::uint64_t /*height*/,
                                        const ::v37::bytes32& /*lane_commitment*/,
                                        unsigned char out_anchor[ANCHOR_LEN],
                                        CarrotError* err = nullptr) {
    for (std::size_t i = 0; i < ANCHOR_LEN; ++i) out_anchor[i] = 0;
    if (err) *err = CarrotError::NotImplemented;
    return false;
}

// One line naming why the CARROT arm refuses, for BuiltCoinbase::detail and for
// operator-facing logs. Stable enough to grep, verbose enough to act on.
inline const char* seam_status() {
    return "CARROT coinbase derivation is a SCAFFOLD: monero-project/monero "
           "master tops at hard-fork major_version 16, no CARROT/FCMP++ release "
           "is tagged, and no coinbase-enote reference vectors are published, so "
           "no conformant derivation can be written or pinned. The fence stays "
           "up (fail-closed). Seam: src/impl/xmr/settle/xmr_carrot.hpp, "
           "docs/xmr-lane/carrot-coinbase-seam.md.";
}

} // namespace carrot
} // namespace settle
} // namespace xmr
} // namespace v37
