// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The Dash transaction id, with the Dash Core v24 stable-txid rule for asset
/// unlocks, and the instance hash.
///
/// Ported from Dash Core v24.0.0 src/primitives/transaction.{h,cpp}:
///   IsAssetUnlockPayload(tx): special-version tx of type 9 whose payload is
///       exactly ASSET_UNLOCK_PAYLOAD_SIZE = 1 + 8 + 4 + 132 = 145 bytes;
///   IsAssetUnlockWithStableTxid(tx): that, with payload[0] (the payload
///       version) >= ASSET_UNLOCK_STABLE_TXID_VERSION = 2;
///   GetHash / ComputeHash: for such an unlock, SHA256d of the serialization
///       with its LAST 132 bytes zeroed (requestedHeight, quorumHash and
///       quorumSig: the payload is serialized last), so every re-signed
///       instance of one withdrawal shares one txid; for every other tx,
///       SHA256d of the serialization;
///   GetInstanceHash: SHA256d of the full serialization (equal to the txid
///       for every other tx).
/// The rule depends on the bytes only, not on activation: a version-2 unlock
/// is invalid in a block before DEPLOYMENT_V24, and after it every node keys
/// it by the stable txid (block merkle root, outpoints, inv announcements to
/// peers below protocol 70242). The CbTx v4 merkleRootAssetUnlocks commits the
/// instance hashes (cbtx_asset_unlocks.hpp).
///
/// Every tx-hash site of the embedded node goes through dash_txid():
/// utxo_adapter.hpp (UTXO lanes, mempool, template), block_producer.hpp (body
/// binding), block_json.hpp, the coin P2P pull slots, the projection and
/// replay folds, the compact-block codec and the sharechain's remembered txs.

#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace dash {
namespace coin {

inline constexpr size_t  kAssetUnlockQuorumInfoSize    = 4 + 32 + 96;
inline constexpr size_t  kAssetUnlockPayloadSize       = 1 + 8 + 4 + kAssetUnlockQuorumInfoSize;
inline constexpr uint8_t kAssetUnlockStableTxidVersion = 2;

/// IsAssetUnlockPayload.
template <typename Tx>
inline bool is_asset_unlock_payload(const Tx& tx)
{
    return tx_is_special_version(tx.version) && tx.type == tx_type::ASSET_UNLOCK
        && tx.extra_payload.size() == kAssetUnlockPayloadSize;
}

/// IsAssetUnlockWithStableTxid.
template <typename Tx>
inline bool is_asset_unlock_with_stable_txid(const Tx& tx)
{
    return is_asset_unlock_payload(tx) && tx.extra_payload[0] >= kAssetUnlockStableTxidVersion;
}

inline uint256 dash_sha256d(std::span<const unsigned char> bytes)
{
    uint256 h;
    CHash256().Write(bytes).Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

/// CTransaction::GetHash.
inline uint256 dash_txid(const MutableTransaction& tx)
{
    auto packed = ::pack(tx);
    auto sp = packed.get_span();
    const auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    if (!is_asset_unlock_with_stable_txid(tx))
        return dash_sha256d(std::span<const unsigned char>(p, sp.size()));
    std::vector<unsigned char> buf(p, p + sp.size());
    std::fill(buf.end() - static_cast<std::ptrdiff_t>(kAssetUnlockQuorumInfoSize), buf.end(), 0);
    return dash_sha256d(std::span<const unsigned char>(buf.data(), buf.size()));
}

/// CTransaction::GetInstanceHash: SHA256d of the full serialization.
inline uint256 dash_instance_hash(const MutableTransaction& tx)
{
    auto packed = ::pack(tx);
    auto sp = packed.get_span();
    return dash_sha256d(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()), sp.size()));
}

} // namespace coin
} // namespace dash
