// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The secp256k1 verifier the provider-tx checks use (protx_check.hpp
/// ProTxEcdsaVerifyFn): CHashSigner::VerifyHash (Dash Core
/// src/util/message.cpp / src/masternode/... hash signer) recovers the public
/// key from a 65-byte compact signature over the hash and compares its key ID.
/// The recovery is the one the SPORK listener already uses
/// (spork.hpp spork_compact_sig_matches); a header byte outside 27..34 is
/// refused, which can only exclude a tx Core would accept, never the reverse.
/// Kept out of protx_check.hpp so a target without the secp256k1 module
/// headers can still fold (it then refuses the txs that need this).

#include <impl/dash/coin/spork.hpp>

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace dash {
namespace coin {

inline bool protx_ecdsa_verify_hash(const uint256& hash, const std::vector<uint8_t>& sig,
                                    const uint160& key_id)
{
    std::array<uint8_t, 20> id{};
    std::memcpy(id.data(), key_id.data(), id.size());
    return spork_compact_sig_matches(hash, sig, id);
}

} // namespace coin
} // namespace dash
