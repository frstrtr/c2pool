#pragma once
/*
 * v37_descriptor_xmr.hpp — Monero (XMR) payout-target kinds for the V37
 * PayoutDescriptor canon. Family B: XMR / RandomX settlement lane.
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details. You should have received a copy of the GNU Affero General Public
 * License along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS
 *
 *   An EXTENSION of the ratified V37 PayoutDescriptor canon
 *   (src/sharechain/v37/v37_descriptor.hpp §6.3). It does NOT rewrite the
 *   canon. It adds two payout-target kinds for the Monero coinbase, whose
 *   payout target is NOT a script but a pair of ed25519 public keys:
 *
 *       XMR_STD = 0x10   payload = spend_pub B (32) || view_pub A (32)  = 64 B
 *       XMR_SUB = 0x11   payload = sub-spend D_i (32) || main-view A (32) = 64 B
 *
 *   The Monero coinbase (miner_tx) has NO output script of any kind: the
 *   on-chain output is a *derived* one-time (stealth) key
 *       P_i = H_s(8 r A || i) G + B          (main address)
 *   never the descriptor bytes themselves (scoping §13.2). So the canon's
 *   kind-255 RAW ("these raw bytes ARE the output script") would SILENTLY
 *   MIS-SETTLE a Monero payout — a distinct kind family is mandatory, not
 *   kind-255. The identity is the exact (kind, payload) of `pay`, S-1/S-3
 *   unchanged: main address and subaddress are two distinct identities, as
 *   they should be.
 *
 *   Canon rule 1 is RESTATED for the whole descriptor surface:
 *       "payout-TARGET bytes, never address strings"
 *   (was "scripts, never address strings"). The base58 "4.."/"8.." address
 *   string is decoded + checksum-verified ONCE at the boundary; the canon
 *   only ever holds the raw 32-byte key material, never the printable string.
 *
 * TORSION / PRIME-ORDER CHECK (the one new validity rule)
 *
 *   Every 32-byte payload half is an ed25519 point encoding and MUST be
 *   validated to lie in the prime-order subgroup (torsion-free, not a
 *   small-order point). Without this an attacker can register a descriptor
 *   whose points are on the curve but carry a torsion component; that is the
 *   class of bug p2pool guards with Wallet::torsion_check(). See
 *   xmr_point_check_fn below — the canon supplies the crypto backend; this
 *   header is fail-closed (no backend => XMR descriptors are INVALID, never
 *   silently accepted).
 *
 *   Reference algorithm (re-expressed, NOT copied) mirrors, in intent,
 *   SChernykh/p2pool @ src/wallet.cpp `Wallet::torsion_check()` (GPL-3.0;
 *   combinable into this AGPL-3.0 work under AGPLv3 §13). It decodes each point
 *   with Monero `ge_frombytes_vartime()` (crypto-ops.h, BSD-3, ref10; rejects
 *   non-canonical / off-curve), rejects the identity, and requires prime-order
 *   subgroup membership via the exact cofactor test  [L]P == 𝒪  (L = the
 *   ed25519 group order). Because the group is Z_L × Z_8 and gcd(L,8)=1, this
 *   holds IFF P is torsion-free, so it rejects every small-order point AND any
 *   mixed prime+torsion point. It uses ONLY the ge_* primitives X1 vendored —
 *   it does NOT depend on monero/fcmp_pp (out of tree; FCMP-fenced to X6). The
 *   conforming backend adapter is xmr_descriptor_xmr_point_check_ref10.cpp;
 *   the torsion KAT (test/xmr_torsion_kat.cpp) proves accept/reject including
 *   the mixed-point adversarial case.
 *
 * FCMP++ / CARROT FENCE  (READ BEFORE EXTENDING)
 *
 *   FCMP++/CARROT may rewrite Monero coinbase-output derivation and address
 *   semantics (view-tag scheme, one-time-key derivation, possibly the address
 *   encoding). The (B, A) / (D_i, A) payloads and this torsion rule are
 *   PINNED to the pre-CARROT regime: Monero hard-fork major_version <=
 *   XMR_PRECARROT_MAX_MAJOR_VERSION. A lane building a coinbase for a block
 *   whose major_version exceeds this MUST NOT reuse these kinds unreviewed —
 *   see the guard xmr_precarrot_ok() and the note in XMR-DESCRIPTOR-KINDS.md.
 *   `monero/master` hardforks.cpp tops at v16 as of 2026-09-05.
 *
 * RATIFIED-CANON STATUS: kind bytes are consensus ("every script has exactly
 *   one canon"). Landing these kinds is a canon change and REQUIRES an
 *   integrator tap. This header is the reference for that change; the exact
 *   canon-side edits are itemised in XMR-DESCRIPTOR-KINDS.md.
 * ---------------------------------------------------------------------------
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "v37_descriptor.hpp"   // the ratified canon — included, never edited here
#include "v37_hash.hpp"         // sha256d, bytes32

namespace v37 {
namespace xmr {

// --- Kind bytes (reserved in the ScriptKind byte space; see canon note) -----
// ScriptKind is `enum class : std::uint8_t` with a fixed underlying type, so
// any in-range byte is a well-defined value even before the enumerators are
// added to the canon. Once the integrator taps the canon change, these become
// named enumerators ScriptKind::XMR_STD / ScriptKind::XMR_SUB.
inline constexpr ScriptKind XMR_STD = static_cast<ScriptKind>(0x10);
inline constexpr ScriptKind XMR_SUB = static_cast<ScriptKind>(0x11);

inline constexpr std::size_t XMR_POINT_LEN   = 32;  // one ed25519 point encoding
inline constexpr std::size_t XMR_PAYLOAD_LEN = 64;  // B||A or D_i||A_main

// --- byte-denominated h_min table rows (scoping §16, §2.3) ------------------
// Monero coinbase output = 1 (type tag) + 32 (key) + 1 (view tag) + varint
// amount [5..8] = 39..42 B. Take the fixed worst case. There is NO consensus
// or relay dust rule on Monero (validate_miner_transaction sums plaintext
// amounts; p2pool pays ~0.00027 XMR routinely) => dust = 0.
inline constexpr std::uint32_t XMR_OUTPUT_SIZE_BYTES = 42;  // size(kind)
inline constexpr std::uint64_t XMR_DUST              = 0;   // dust(kind)

inline constexpr std::uint32_t xmr_size(ScriptKind k) {
    return (k == XMR_STD || k == XMR_SUB) ? XMR_OUTPUT_SIZE_BYTES : 0;
}
inline constexpr std::uint64_t xmr_dust(ScriptKind /*k*/) { return XMR_DUST; }

// --- FCMP++/CARROT fence ----------------------------------------------------
// Pin these descriptor semantics to the pre-CARROT Monero regime.
inline constexpr std::uint8_t XMR_PRECARROT_MAX_MAJOR_VERSION = 16;  // mainnet v16
inline constexpr bool xmr_precarrot_ok(std::uint8_t monero_major_version) {
    return monero_major_version <= XMR_PRECARROT_MAX_MAJOR_VERSION;
}

inline constexpr bool is_xmr_kind(ScriptKind k) {
    return k == XMR_STD || k == XMR_SUB;
}

// --- Point-validity backend (the torsion check) -----------------------------
// Contract: return true IFF the 32-byte little-endian ed25519 point encoding
// `pt` decodes to a canonical, on-curve point that lies in the prime-order
// subgroup (torsion-free) and is not a small-order/identity point.
//
// The canon injects a concrete predicate (see xmr_point_check_ref10.cpp, which
// binds ge_frombytes_vartime + fcmp_pp::mul8_is_identity +
// fcmp_pp::torsion_check_vartime). This header is FAIL-CLOSED: if no backend
// is installed, is_valid_point() returns false, so an XMR descriptor cannot be
// declared valid without the real crypto check. It NEVER silently passes.
using xmr_point_check_fn = bool (*)(const std::uint8_t* pt /*32 bytes*/);

inline xmr_point_check_fn& point_check_backend() {
    static xmr_point_check_fn fn = nullptr;  // fail-closed default
    return fn;
}
inline void set_point_check_backend(xmr_point_check_fn fn) {
    point_check_backend() = fn;
}
inline bool is_valid_point(const std::uint8_t* pt) {
    auto fn = point_check_backend();
    return fn != nullptr && fn(pt);
}

// --- well-formedness + validity for an XMR ScriptRef ------------------------
// Structural: kind is an XMR kind and payload is exactly 64 bytes. This is the
// row the canon's PayoutDescriptor::ref_well_formed() must gain (returns
// payload.size() == 64 for XMR_STD / XMR_SUB).
inline bool xmr_ref_well_formed(const ScriptRef& r) {
    return is_xmr_kind(r.kind) && r.payload.size() == XMR_PAYLOAD_LEN;
}

// Full validity: well-formed AND both 32-byte halves pass the torsion /
// prime-order check via the installed backend. This is the check the canon's
// PayoutDescriptor::valid() must invoke for XMR kinds.
inline bool xmr_ref_valid(const ScriptRef& r) {
    if (!xmr_ref_well_formed(r)) return false;
    const std::uint8_t* p0 = r.payload.data();               // spend/sub-spend
    const std::uint8_t* p1 = r.payload.data() + XMR_POINT_LEN; // view
    return is_valid_point(p0) && is_valid_point(p1);
}

// Validate a whole PayoutDescriptor whose `pay` (or any XMR aux ref) carries an
// XMR kind. Non-XMR refs defer to the canon's own valid(). This is what the
// wired canon does inline; provided here for pre-tap use and for tests.
inline bool xmr_descriptor_valid(const PayoutDescriptor& d,
                                 bool allow_attribution = false) {
    // XMR pay: enforce the torsion rule (the canon's ref_well_formed by itself
    // would reject the unknown kind byte; here we accept it once valid).
    if (is_xmr_kind(d.pay.kind)) {
        if (!xmr_ref_valid(d.pay)) return false;
        if (d.attribution.has_value() && !allow_attribution) return false;
        if (!d.raw_script.empty()) return false;  // XMR kinds carry no raw script
        // aux: each entry must be either a canon ref or a valid XMR ref, and
        // chain_id strictly ascending (same rule as the canon).
        if (d.aux.size() > 0xffff) return false;
        for (std::size_t i = 0; i < d.aux.size(); ++i) {
            if (i > 0 && !(d.aux[i - 1].chain_id < d.aux[i].chain_id)) return false;
            const ScriptRef& ar = d.aux[i].ref;
            if (is_xmr_kind(ar.kind)) { if (!xmr_ref_valid(ar)) return false; }
            else if (!PayoutDescriptor::ref_well_formed(ar)) return false;
        }
        return true;
    }
    // Non-XMR pay: the canon core owns validity, but an XMR-kind ref carried in
    // the ATTRIBUTION slot or any AUX entry still needs the torsion / prime-order
    // check (the canon core would otherwise reject the unknown kind byte). Every
    // such XMR-kind ref MUST be validated HERE and then EXCLUDED from the
    // descriptor we delegate to the core: the core valid() re-enters the P-1
    // dispatch prologue on ANY XMR kind it still sees, so handing it a descriptor
    // that still carries an XMR attribution (or XMR aux) makes
    //   xmr_descriptor_valid -> valid() -> dispatch -> xmr_descriptor_valid ...
    // cycle forever (unbounded recursion -> stack overflow SIGSEGV -- a
    // consensus-DoS reachable at allow_attribution=false, the V37.0 default).
    // `pay` is non-XMR by construction in this branch; once the XMR attribution
    // and XMR aux are stripped, the delegated descriptor carries NO XMR kind and
    // therefore CANNOT re-enter the dispatch -- the recursion is structurally
    // impossible and valid() is total for every input.

    // Honour the F-2 attribution gate up front, so an XMR attribution yields the
    // SAME verdict the canon core gives a non-XMR attribution: present under the
    // V37.0 default (allow_attribution=false) => reject. Without this, stripping
    // the XMR attribution below would let a disallowed attribution slip through.
    if (d.attribution.has_value() && !allow_attribution) return false;
    if (d.attribution.has_value() && is_xmr_kind(d.attribution->kind)) {
        if (!xmr_ref_valid(*d.attribution)) return false;  // torsion / prime-order
    }
    for (const auto& e : d.aux) {
        if (is_xmr_kind(e.ref.kind) && !xmr_ref_valid(e.ref)) return false;
    }
    // Delegate the remainder to the canon core with EVERY XMR-kind ref stripped:
    // the XMR attribution (already torsion-checked above) is removed, and only
    // non-XMR aux entries are carried over. The delegated valid() thus sees no
    // XMR kind and never re-dispatches.
    PayoutDescriptor tmp = d;
    if (tmp.attribution.has_value() && is_xmr_kind(tmp.attribution->kind))
        tmp.attribution.reset();
    tmp.aux.clear();
    for (const auto& e : d.aux)
        if (!is_xmr_kind(e.ref.kind)) tmp.aux.push_back(e);
    return tmp.valid(allow_attribution);
}

// --- constructors -----------------------------------------------------------
// Build the payout-target ScriptRef from raw 32-byte key material. Inputs are
// the DECODED keys (base58 address string already stripped + checksum-checked
// at the boundary — "payout-target bytes, never address strings").
inline ScriptRef make_xmr_std(const std::array<std::uint8_t, 32>& spend_B,
                              const std::array<std::uint8_t, 32>& view_A) {
    ScriptRef r;
    r.kind = XMR_STD;
    r.payload.reserve(XMR_PAYLOAD_LEN);
    r.payload.insert(r.payload.end(), spend_B.begin(), spend_B.end());
    r.payload.insert(r.payload.end(), view_A.begin(), view_A.end());
    return r;
}
inline ScriptRef make_xmr_sub(const std::array<std::uint8_t, 32>& sub_spend_D,
                              const std::array<std::uint8_t, 32>& main_view_A) {
    ScriptRef r;
    r.kind = XMR_SUB;
    r.payload.reserve(XMR_PAYLOAD_LEN);
    r.payload.insert(r.payload.end(), sub_spend_D.begin(), sub_spend_D.end());
    r.payload.insert(r.payload.end(), main_view_A.begin(), main_view_A.end());
    return r;
}

// The canon identity_key() (sha256d of VERSION||kind||len||payload) works
// unchanged for XMR kinds — append_ref's u8 length field already fits 64. This
// helper just wraps `pay` into a descriptor and returns its identity key.
inline bytes32 xmr_identity_key(const ScriptRef& pay) {
    PayoutDescriptor d;
    d.pay = pay;
    return d.identity_key();
}

// ---------------------------------------------------------------------------
// KATs (Known-Answer Tests)
// ---------------------------------------------------------------------------
// (1) identity_key goldens — HARD, computed offline with SHA-256 only, so they
//     hold with no crypto backend. B/A are real ed25519 public keys (clamped
//     scalar * basepoint => prime-order points) so they double as torsion-PASS
//     inputs when a backend is installed.
// (2) torsion vectors — spec vectors to run against the installed backend:
//     the ed25519 basepoint MUST pass; the order-1 identity point MUST fail.
namespace kat {

struct IdentityKatRow {
    ScriptKind             kind;
    std::array<std::uint8_t, 32> p0;            // spend / sub-spend
    std::array<std::uint8_t, 32> p1;            // view
    bytes32                expected_identity_key;
};

// XMR_STD: B (spend), A (view) -> identity_key = sha256d(01 10 40 || B || A)
inline constexpr IdentityKatRow STD_KAT = {
    XMR_STD,
    // B (spend_pub), 32 bytes
    {0x75, 0xb6, 0x25, 0xd5, 0x52, 0x09, 0x2c, 0x5d, 0x10, 0xe4, 0x05, 0xea, 0x79, 0x74, 0xab, 0xd8, 0xea, 0xa4, 0x34, 0x88, 0x77, 0x8e, 0x4a, 0x8b, 0xe9, 0xf8, 0x4d, 0x63, 0x05, 0xef, 0x46, 0xb5},
    // A (view_pub), 32 bytes
    {0xf1, 0xb6, 0xe0, 0x90, 0x6e, 0xb3, 0xcb, 0xb9, 0x97, 0x47, 0x5d, 0x0a, 0xcb, 0x17, 0x34, 0x79, 0x84, 0x5d, 0x7e, 0x06, 0xe1, 0x46, 0xf0, 0x18, 0x60, 0x26, 0xf3, 0xac, 0x93, 0x29, 0xae, 0x7a},
    // expected identity_key = sha256d(preimage), 32 bytes
    {0x25, 0xaa, 0x4c, 0x3f, 0x55, 0x28, 0x1b, 0xcc, 0x52, 0xbd, 0x7c, 0x05, 0x1f, 0xf1, 0x77, 0x80, 0x54, 0xdd, 0x92, 0xce, 0xf9, 0x36, 0x24, 0x74, 0x8e, 0xf2, 0x06, 0x15, 0x6b, 0x34, 0xba, 0xcc},
};

// XMR_SUB: D_i (sub-spend), A_main (view) -> sha256d(01 11 40 || D_i || A_main)
inline constexpr IdentityKatRow SUB_KAT = {
    XMR_SUB,
    // D_i (sub-spend), 32 bytes
    {0xab, 0xcb, 0x58, 0x15, 0x7b, 0xaa, 0xae, 0x8e, 0xab, 0x43, 0x6b, 0x16, 0xee, 0xa3, 0x89, 0x9a, 0x99, 0x6c, 0xa9, 0x15, 0x12, 0x36, 0x59, 0xcb, 0x23, 0x7b, 0x88, 0x88, 0x34, 0xef, 0x26, 0xa4},
    // A_main (view), 32 bytes — same main-wallet view key as STD_KAT.A
    {0xf1, 0xb6, 0xe0, 0x90, 0x6e, 0xb3, 0xcb, 0xb9, 0x97, 0x47, 0x5d, 0x0a, 0xcb, 0x17, 0x34, 0x79, 0x84, 0x5d, 0x7e, 0x06, 0xe1, 0x46, 0xf0, 0x18, 0x60, 0x26, 0xf3, 0xac, 0x93, 0x29, 0xae, 0x7a},
    // expected identity_key, 32 bytes
    {0xe3, 0x21, 0x19, 0x29, 0x03, 0xe6, 0x38, 0xcb, 0x42, 0xfc, 0x37, 0x45, 0x2b, 0x36, 0x33, 0xef, 0x01, 0x52, 0xf1, 0x2e, 0xaf, 0x1f, 0xdc, 0xa7, 0xfb, 0x6a, 0xac, 0x7a, 0xba, 0x2e, 0x05, 0x55},
};

// Torsion spec vectors (execute against the installed backend).
inline constexpr std::array<std::uint8_t, 32> TORSION_PASS_BASEPOINT = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
inline constexpr std::array<std::uint8_t, 32> TORSION_FAIL_IDENTITY = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Runs the identity_key KATs (SHA-256 only; no backend needed). Returns true
// iff every row's computed identity_key equals its golden.
inline bool check_identity_kats() {
    auto one = [](const IdentityKatRow& row) -> bool {
        ScriptRef pay;
        pay.kind = row.kind;
        pay.payload.assign(row.p0.begin(), row.p0.end());
        pay.payload.insert(pay.payload.end(), row.p1.begin(), row.p1.end());
        return xmr_identity_key(pay) == row.expected_identity_key;
    };
    return one(STD_KAT) && one(SUB_KAT);
}

// Runs the torsion spec vectors against the installed backend. Returns true iff
// a backend is installed AND basepoint passes AND identity point fails. With no
// backend installed it returns false (fail-closed) — call only after
// set_point_check_backend().
inline bool check_torsion_kats() {
    return is_valid_point(TORSION_PASS_BASEPOINT.data()) &&
           !is_valid_point(TORSION_FAIL_IDENTITY.data());
}

} // namespace kat
} // namespace xmr
} // namespace v37
