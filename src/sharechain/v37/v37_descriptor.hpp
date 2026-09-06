#pragma once
// V37 PayoutDescriptor v1 — the ratified identity canon.
// Spec: docs/c2pool-v37-mrr-roundabout-buffer.md §6.3 (OQ-3 + S-1/S-2/S-3).
//
//   * scripts, never address strings — the canon operates on script bytes
//   * total function: known templates -> kinds 0..4, anything else ->
//     kind 255 = SHA256d(raw script); every script has exactly one canon
//   * identity = exact (kind, payload) of `pay` — no cross-kind collapsing
//     (S-1); aux entries are attributes, not identity
//   * attribution slot present in the serialization, MUST be absent under
//     V37.0 validity rules (F-2; enabled later by validity-rule change)
//   * serialization: fixed field order, fixed-width little-endian integers,
//     no varints; identity key = SHA256d of canonical bytes (S-3)

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

#include "v37_hash.hpp"

namespace v37 {

enum class ScriptKind : std::uint8_t {
    P2PKH  = 0,   // payload: hash160 (20)
    P2SH   = 1,   // payload: hash160 (20)
    P2WPKH = 2,   // payload: hash160 (20)
    P2WSH  = 3,   // payload: sha256  (32)
    P2TR   = 4,   // payload: x-only key (32)
    RAW    = 255, // payload: sha256d(raw script) (32)
};

struct ScriptRef {
    ScriptKind kind = ScriptKind::RAW;
    std::vector<std::uint8_t> payload;  // 20 or 32 bytes per kind

    friend bool operator==(const ScriptRef& a, const ScriptRef& b) {
        return a.kind == b.kind && a.payload == b.payload;  // S-1: exact
    }
    friend bool operator<(const ScriptRef& a, const ScriptRef& b) {
        if (a.kind != b.kind) return a.kind < b.kind;
        return a.payload < b.payload;
    }
};

// Canonicalize raw output-script bytes into a ScriptRef. Total: every input
// maps to exactly one ScriptRef (rule 2 of the canon).
inline ScriptRef canonicalize_script(const std::vector<std::uint8_t>& s) {
    ScriptRef r;
    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
        s[23] == 0x88 && s[24] == 0xac) {
        r.kind = ScriptKind::P2PKH;
        r.payload.assign(s.begin() + 3, s.begin() + 23);
        return r;
    }
    // P2SH: OP_HASH160 <20> OP_EQUAL
    if (s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) {
        r.kind = ScriptKind::P2SH;
        r.payload.assign(s.begin() + 2, s.begin() + 22);
        return r;
    }
    // P2WPKH: OP_0 <20>
    if (s.size() == 22 && s[0] == 0x00 && s[1] == 0x14) {
        r.kind = ScriptKind::P2WPKH;
        r.payload.assign(s.begin() + 2, s.end());
        return r;
    }
    // P2WSH: OP_0 <32>
    if (s.size() == 34 && s[0] == 0x00 && s[1] == 0x20) {
        r.kind = ScriptKind::P2WSH;
        r.payload.assign(s.begin() + 2, s.end());
        return r;
    }
    // P2TR: OP_1 <32>
    if (s.size() == 34 && s[0] == 0x51 && s[1] == 0x20) {
        r.kind = ScriptKind::P2TR;
        r.payload.assign(s.begin() + 2, s.end());
        return r;
    }
    // Fallback: contain the exotic script in kind 255.
    r.kind = ScriptKind::RAW;
    auto h = sha256d(s);
    r.payload.assign(h.begin(), h.end());
    return r;
}

struct AuxEntry {
    std::uint32_t chain_id = 0;
    ScriptRef ref;
};

// ===========================================================================
// P-1 — XMR (Family B) payout-kind activation dispatch  (ADD-ONLY)
//
// The ratified canon (kinds 0..4 + RAW=255) rejects every other kind byte as
// unknown (see ref_well_formed's trailing `return false`). Two kind bytes are
// reserved by the isolated extension header v37_descriptor_xmr.hpp for Monero
// payout targets:
//
//     XMR_STD = 0x10   payload = spend_pub B (32) || view_pub A (32)  = 64 B
//     XMR_SUB = 0x11   payload = sub-spend D_i (32) || main-view A (32) = 64 B
//
// whose validity is NOT a script-width check but an ed25519 structural + prime-
// order (torsion) check (xmr_ref_valid / xmr_descriptor_valid). P-1 wires the
// canon to RECOGNIZE these two kinds: PayoutDescriptor::valid() delegates a
// descriptor that carries an XMR kind to the installed XMR validator instead of
// rejecting it as unknown.
//
// WHY A REGISTRATION HOOK (not a direct call / #include): v37_descriptor_xmr.hpp
// #includes THIS canon header, so the canon cannot #include it back (circular).
// The seam is therefore a function-pointer hook — the exact pattern the XMR
// header already uses for its ed25519 point-check backend. The concrete
// validator (xmr::xmr_descriptor_valid) is installed alongside the torsion
// backend (v37_descriptor_xmr_point_check_ref10.cpp) or, in tests, directly.
//
// ADD-ONLY INVARIANT (the whole point of P-1): a descriptor that carries NO XMR
// kind never enters the dispatch branch, so its validity AND every consensus
// digest (identity_key / canonical_bytes — both left completely untouched) are
// BYTE-IDENTICAL to the pre-P-1 canon. No existing kind's behavior changes; the
// two kind-byte values are unchanged; there is no collision (0x10/0x11 were
// previously unknown-and-rejected). FAIL-CLOSED: with no validator installed an
// XMR descriptor is rejected exactly as the unknown kind byte was before P-1.
// ===========================================================================

struct PayoutDescriptor;  // forward decl for the dispatch-hook signature

// The two reserved XMR kind bytes (consensus reservation; mirrors
// v37_descriptor_xmr.hpp XMR_STD/XMR_SUB and is_xmr_kind()). Naming them here is
// only the DISPATCH decision — the actual XMR validity logic is never
// reimplemented in the canon; it stays entirely in the extension header and is
// reached solely through the hook below.
inline bool is_xmr_dispatch_kind(ScriptKind k) {
    const auto b = static_cast<std::uint8_t>(k);
    return b == 0x10 || b == 0x11;
}

// Whole-descriptor XMR validator hook. Installed by the XMR extension via
// set_xmr_descriptor_validator(&v37::xmr::xmr_descriptor_valid). Fail-closed
// default (nullptr) => XMR-carrying descriptors are rejected, identical to the
// pre-P-1 unknown-kind rejection.
using xmr_descriptor_validator_fn =
    bool (*)(const PayoutDescriptor& d, bool allow_attribution);
inline xmr_descriptor_validator_fn& xmr_descriptor_validator() {
    static xmr_descriptor_validator_fn fn = nullptr;  // fail-closed
    return fn;
}
inline void set_xmr_descriptor_validator(xmr_descriptor_validator_fn fn) {
    xmr_descriptor_validator() = fn;
}

struct PayoutDescriptor {
    static constexpr std::uint8_t VERSION = 1;

    ScriptRef pay;                          // THE payout identity
    std::optional<ScriptRef> attribution;   // F-2 slot; MUST be absent V37.0
    std::vector<AuxEntry> aux;              // sorted ascending, unique chain_id
    // Carried alongside (NOT part of canonical identity bytes) so kind-255
    // payouts remain constructible:
    std::vector<std::uint8_t> raw_script;

    // Validity per the ratified canon. allow_attribution stays false for the
    // whole of V37.0; flipping it is the V37.x validity-rule change.
    bool valid(bool allow_attribution = false) const {
        // --- P-1 XMR (Family B) activation dispatch (ADD-ONLY; see the block
        // above AuxEntry). If THIS descriptor carries a reserved XMR kind
        // (0x10/0x11) in pay, attribution, or any aux ref, hand the whole
        // validity decision to the installed XMR validator. A descriptor with
        // NO XMR kind skips this branch entirely and takes the byte-identical
        // pre-P-1 path below. Fail-closed when no validator is installed.
        {
            bool has_xmr = is_xmr_dispatch_kind(pay.kind);
            if (!has_xmr && attribution.has_value())
                has_xmr = is_xmr_dispatch_kind(attribution->kind);
            if (!has_xmr)
                for (const auto& e : aux)
                    if (is_xmr_dispatch_kind(e.ref.kind)) { has_xmr = true; break; }
            if (has_xmr) {
                auto fn = xmr_descriptor_validator();
                return fn != nullptr && fn(*this, allow_attribution);
            }
        }
        // --- unchanged canon below: byte-identical to master for any
        //     descriptor that carries no XMR kind ---------------------------
        if (attribution.has_value() && !allow_attribution) return false;
        if (attribution.has_value() && !ref_well_formed(*attribution))
            return false;
        if (aux.size() > 0xffff)
            return false;  // canonical u16 count field must not truncate
        for (std::size_t i = 0; i < aux.size(); ++i) {
            if (i > 0 && !(aux[i - 1].chain_id < aux[i].chain_id))
                return false;  // unsorted or duplicate chain_id: malformed
            if (!ref_well_formed(aux[i].ref)) return false;
        }
        if (!ref_well_formed(pay)) return false;
        if (pay.kind == ScriptKind::RAW) {
            // The carried script must BIND to the identity: re-canonicalize
            // and require exact equality. This enforces both the hash
            // binding (payload == sha256d(raw_script)) and the one-canon
            // rule (a template script smuggled under kind 255 canonicalizes
            // to its template kind and fails the comparison).
            if (raw_script.empty()) return false;
            if (!(canonicalize_script(raw_script) == pay)) return false;
        } else {
            // Template kinds derive their script from (kind, payload); a
            // carried raw_script has no meaning and is rejected as malformed.
            if (!raw_script.empty()) return false;
        }
        return true;
    }

    // Payload widths are part of the canon: 20 bytes for hash160 kinds,
    // 32 for sha256/x-only/raw-hash kinds.
    static bool ref_well_formed(const ScriptRef& r) {
        switch (r.kind) {
        case ScriptKind::P2PKH:
        case ScriptKind::P2SH:
        case ScriptKind::P2WPKH: return r.payload.size() == 20;
        case ScriptKind::P2WSH:
        case ScriptKind::P2TR:
        case ScriptKind::RAW:    return r.payload.size() == 32;
        }
        return false;  // unknown kind byte
    }

    // Canonical serialization (§6.3 rule 6): the identity preimage.
    std::vector<std::uint8_t> canonical_bytes() const {
        std::vector<std::uint8_t> out;
        out.push_back(VERSION);
        append_ref(out, pay);
        out.push_back(attribution.has_value() ? 1 : 0);
        if (attribution.has_value()) append_ref(out, *attribution);
        std::uint16_t n = static_cast<std::uint16_t>(aux.size());
        out.push_back(static_cast<std::uint8_t>(n));
        out.push_back(static_cast<std::uint8_t>(n >> 8));
        for (const auto& e : aux) {
            for (int i = 0; i < 4; ++i)
                out.push_back(static_cast<std::uint8_t>(e.chain_id >> (8 * i)));
            append_ref(out, e.ref);
        }
        return out;
    }

    // Identity key (S-3): SHA256d of canonical bytes. Note: identity ignores
    // aux *values* only in the sense that aux are attributes of the same
    // miner; the intern layer keys on `pay` alone (see MinerIntern).
    bytes32 identity_key() const {
        auto pay_only = identity_preimage();
        return sha256d(pay_only);
    }

    // Identity = exact (kind, payload) of `pay` (canon rule 3) — attribution
    // and aux do not change who the miner is.
    std::vector<std::uint8_t> identity_preimage() const {
        std::vector<std::uint8_t> out;
        out.push_back(VERSION);
        append_ref(out, pay);
        return out;
    }

private:
    static void append_ref(std::vector<std::uint8_t>& out, const ScriptRef& r) {
        out.push_back(static_cast<std::uint8_t>(r.kind));
        out.push_back(static_cast<std::uint8_t>(r.payload.size()));
        out.insert(out.end(), r.payload.begin(), r.payload.end());
    }
};

} // namespace v37
