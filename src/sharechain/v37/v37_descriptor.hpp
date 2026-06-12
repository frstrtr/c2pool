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
        if (attribution.has_value() && !allow_attribution) return false;
        for (std::size_t i = 0; i < aux.size(); ++i) {
            if (i > 0 && !(aux[i - 1].chain_id < aux[i].chain_id))
                return false;  // unsorted or duplicate chain_id: malformed
        }
        if (pay.kind == ScriptKind::RAW && raw_script.empty())
            return false;  // kind 255 must carry the script for payment
        return true;
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
