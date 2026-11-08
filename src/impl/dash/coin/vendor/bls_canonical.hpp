// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash Core's encoding rules for the BLS objects in provider payloads
// (src/bls/bls.h, v24.0.0), with the dashbls backend. Implemented in
// bls_verify.cpp (link dash_bls_verify). Without a BLS backend both answer
// only the all-zero case (no curve math) and otherwise return nullopt: the
// caller cannot tell a valid encoding from an invalid one and must refuse,
// never accept.

#include <array>
#include <cstdint>
#include <optional>

namespace dash {
namespace coin {
namespace vendor {

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

} // namespace vendor
} // namespace coin
} // namespace dash
