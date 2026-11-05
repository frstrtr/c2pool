// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash transaction version/type rules, ported through Dash Core v23.1.9.
///
/// The 32-bit wire field is nVersion (LOW 16 bits, read as int16_t) and nType
/// (HIGH 16 bits, uint16_t) — dashd primitives/transaction.h. c2pool keeps
/// the low half in `int32_t version` as 0..65535 (transaction.hpp), which
/// round-trips the wire bytes exactly; every rule below reads the low half as
/// the int16_t dashd sees.
///
///   * tx_is_special_version  — CTransaction::IsSpecialTxVersion():
///     nVersion >= SPECIAL_VERSION (3), signed int16 compare. The extra
///     payload exists on the wire iff IsSpecialTxVersion() && nType != 0
///     (transaction.h SERIALIZE_METHODS). Earlier c2pool code gated on
///     `version == 3`, which disagrees with dashd for low-16 in [4, 0x7FFF]
///     with a non-zero type.
///   * contextual_tx_check    — ContextualCheckTransaction (validation.cpp
///     :317-349 @ v23.1.9) for a post-DIP3 context: the special-type
///     whitelist, the coinbase type, and the v23.1.9 rule that rejects a
///     negative nVersion (07494dd62, `bad-txns-version`). The size-limit tail
///     of that function (bad-txns-oversize) is not part of this port.
///
/// Callers decide WHEN the context is post-DIP3: the mempool and the template
/// selector always are (they only serve the live tip); chain folds gate on the
/// block height (DIP3 is active for a block at height > dip0003_height, i.e.
/// DeploymentActiveAfter(pindexPrev)).

#include <cstdint>
#include <optional>
#include <string_view>

namespace dash {
namespace coin {

/// dashd TxType (primitives/transaction.h).
namespace tx_type {
inline constexpr uint16_t NORMAL                    = 0;
inline constexpr uint16_t PROVIDER_REGISTER         = 1;
inline constexpr uint16_t PROVIDER_UPDATE_SERVICE   = 2;
inline constexpr uint16_t PROVIDER_UPDATE_REGISTRAR = 3;
inline constexpr uint16_t PROVIDER_UPDATE_REVOKE    = 4;
inline constexpr uint16_t COINBASE                  = 5;
inline constexpr uint16_t QUORUM_COMMITMENT         = 6;
inline constexpr uint16_t MNHF_SIGNAL               = 7;
inline constexpr uint16_t ASSET_LOCK                = 8;
inline constexpr uint16_t ASSET_UNLOCK              = 9;
} // namespace tx_type

/// The low 16 bits of the version field, read as dashd's int16_t nVersion.
constexpr int16_t wire_version_i16(int32_t version)
{
    return static_cast<int16_t>(static_cast<uint16_t>(version & 0xFFFF));
}

/// nVersion < 0 (low 16 in 0x8000..0xFFFF).
constexpr bool tx_version_is_negative(int32_t version)
{
    return wire_version_i16(version) < 0;
}

/// dashd CTransaction::IsSpecialTxVersion(): nVersion >= 3 as int16_t.
constexpr bool tx_is_special_version(int32_t version)
{
    return wire_version_i16(version) >= 3;
}

/// The extra payload is on the wire iff IsSpecialTxVersion() && nType != 0.
constexpr bool tx_has_extra_payload(int32_t version, uint16_t type)
{
    return tx_is_special_version(version) && type != tx_type::NORMAL;
}

/// The nType values ContextualCheckTransaction accepts on a special-version tx.
constexpr bool tx_type_is_known(uint16_t type)
{
    return type <= tx_type::ASSET_UNLOCK;
}

/// ContextualCheckTransaction (post-DIP3 branch), in dashd's check order.
/// Returns the dashd reject reason, or nullopt when the tx passes. Works on
/// any tx shape with `version`, `type` (MutableTransaction / Transaction).
template <typename Tx>
std::optional<std::string_view> contextual_tx_check(const Tx& tx, bool is_coinbase)
{
    if (tx_is_special_version(tx.version)) {
        if (!tx_type_is_known(tx.type))
            return std::string_view{"bad-txns-type"};
        if (is_coinbase && tx.type != tx_type::COINBASE)
            return std::string_view{"bad-txns-cb-type"};
    } else if (tx.type != tx_type::NORMAL) {
        return std::string_view{"bad-txns-type"};
    }
    // v23.1.9 (07494dd62): releases that sign-extended nVersion over nType
    // re-serialized a negative nVersion with nType 0xffff, so such a block was
    // accepted only by peers that received the miner's own bytes.
    if (tx_version_is_negative(tx.version))
        return std::string_view{"bad-txns-version"};
    return std::nullopt;
}

} // namespace coin
} // namespace dash
