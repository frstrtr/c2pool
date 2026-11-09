// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash Core's encoding rules for the BLS objects in provider payloads
// (src/bls/bls.h, v24.0.0), with the dashbls backend. The rules are the
// inline functions below (header-only, so code that does not link
// dash_bls_verify can run them too); bls_verify.cpp exports them as
// bls_pubkey_core_valid / bls_sig_core_decodes. Without a BLS backend both
// answer only the all-zero case (no curve math) and otherwise return
// nullopt: the caller cannot tell a valid encoding from an invalid one and
// must refuse, never accept.

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#ifdef C2POOL_DASH_BLS
#include <dashbls/bls.hpp>
#include <dashbls/elements.hpp>
#endif

namespace dash {
namespace coin {
namespace vendor {

namespace bls_canonical_detail {
#ifdef C2POOL_DASH_BLS
/// CBLSWrapper::SetBytes(bytes, legacy) leaves the object valid AND
/// CheckMalleable(bytes, legacy) holds.
template <typename Element, size_t N>
inline bool core_set_bytes_canonical(const std::array<uint8_t, N>& b, bool legacy)
{
    bool all_zero = true;
    for (uint8_t c : b) if (c != 0) { all_zero = false; break; }
    if (all_zero) return false;                       // SetBytes: Reset()
    try {
        const Element e = Element::FromBytes(bls::Bytes(b.data(), N), legacy);
        if (e == Element()) return false;             // the identity: Reset()
        const std::vector<uint8_t> v = e.Serialize(legacy);
        return v.size() == N && std::equal(v.begin(), v.end(), b.begin());
    } catch (...) {
        return false;                                 // decode failure: Reset()
    }
}
#endif
} // namespace bls_canonical_detail

/// bls_pubkey_core_valid, header-only (the rule itself).
inline std::optional<bool> bls_pubkey_core_valid_inline(const std::array<uint8_t, 48>& key, bool legacy)
{
    // All-zero bytes: CBLSWrapper::SetBytes resets, no BLS math involved.
    if (std::all_of(key.begin(), key.end(), [](uint8_t c) { return c == 0; })) return false;
#ifdef C2POOL_DASH_BLS
    return bls_canonical_detail::core_set_bytes_canonical<bls::G1Element, 48>(key, legacy);
#else
    (void)legacy;
    return std::nullopt;
#endif
}

/// bls_sig_core_decodes, header-only (the rule itself).
inline std::optional<bool> bls_sig_core_decodes_inline(const std::array<uint8_t, 96>& sig, bool legacy)
{
    // All-zero bytes: an invalid object, which re-encodes as zeros, so
    // CheckMalleable holds and Unserialize does not throw.
    if (std::all_of(sig.begin(), sig.end(), [](uint8_t c) { return c == 0; })) return true;
#ifdef C2POOL_DASH_BLS
    return bls_canonical_detail::core_set_bytes_canonical<bls::G2Element, 96>(sig, legacy)
        || bls_canonical_detail::core_set_bytes_canonical<bls::G2Element, 96>(sig, !legacy);
#else
    (void)legacy;
    return std::nullopt;
#endif
}

/// CBLSLazyPublicKey::Get().IsValid() for an operator key read under
/// `legacy` (the payload version's scheme: legacy iff nVersion 1; always
/// basic for ProUpSharedRegTx): CBLSWrapper::SetBytes (all-zero bytes, a
/// decode failure or the identity point are invalid) followed by
/// CheckMalleable (the re-encoding under the same scheme must equal the
/// bytes). Core's reason on failure is bad-protx-key-null.
std::optional<bool> bls_pubkey_core_valid(const std::array<uint8_t, 48>& key, bool legacy);

/// CBLSSignature::Unserialize(s, legacy) succeeds, i.e. does not throw
/// "malleable BLS object": the 96 bytes are all zero (a null signature), or a
/// canonical encoding under `legacy`, or under the opposite scheme. A
/// payload failing this does not decode in Core (GetTxPayload fails:
/// bad-protx-payload).
std::optional<bool> bls_sig_core_decodes(const std::array<uint8_t, 96>& sig, bool legacy);

/// The two checks above as a pair of function pointers, so a rule caller can
/// be handed them as a value. Production code always uses the defaults (the
/// dashbls backend); a test of a build without the backend may supply an
/// oracle of answers dashd confirmed.
struct BlsEncodingChecks
{
    std::optional<bool> (*pubkey_valid)(const std::array<uint8_t, 48>&, bool) = &bls_pubkey_core_valid;
    std::optional<bool> (*sig_decodes)(const std::array<uint8_t, 96>&, bool)  = &bls_sig_core_decodes;
};

/// The same checks through the header-only functions: for code linked
/// without dash_bls_verify (the template selection path of every target
/// that includes the embedded builder).
inline BlsEncodingChecks bls_encoding_checks_inline()
{
    return BlsEncodingChecks{&bls_pubkey_core_valid_inline, &bls_sig_core_decodes_inline};
}

} // namespace vendor
} // namespace coin
} // namespace dash
