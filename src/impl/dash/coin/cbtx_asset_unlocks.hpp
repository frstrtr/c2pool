// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// CbTx version 4 (Dash Core v24): which CbTx version a block must carry, and
/// merkleRootAssetUnlocks, the root a version-4 CbTx commits.
///
/// Ported from Dash Core v24.0.0:
///   src/evo/cbtx.cpp            CheckCbTx: version 4 is required exactly when
///                               DEPLOYMENT_V24 and DEPLOYMENT_V20 are active
///                               for the block, and forbidden otherwise
///                               (bad-cbtx-version)
///   src/evo/cbtx.cpp            CalcCbTxMerkleRootAssetUnlocks: the merkle
///                               root of the INSTANCE hashes of the block's
///                               asset unlocks with a stable txid, in block
///                               order; null (zero) when there are none
///   src/primitives/transaction.h IsAssetUnlockPayload /
///                               IsAssetUnlockWithStableTxid: a special tx of
///                               type 9 whose payload is exactly 145 bytes and
///                               whose payload version byte is >= 2
///   src/primitives/transaction.cpp GetInstanceHash: SHA256d of the full
///                               serialization (for such an unlock the txid
///                               zeroes the trailing 132 quorum bytes instead;
///                               that txid change is slice S5)
/// A version-1 unlock is not a leaf (testnet block 1,578,005 carries one and
/// commits a null root).

#include <impl/dash/coin/dash_txid.hpp>          // IsAssetUnlockWithStableTxid, GetInstanceHash
#include <impl/dash/coin/quorum_root.hpp>        // compute_merkle_root_local (ComputeMerkleRoot)
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace dash {
namespace coin {

/// CTransaction::GetInstanceHash (dash_txid.hpp); the name the CbTx code and
/// its KATs use.
inline uint256 tx_full_serialization_hash(const MutableTransaction& tx)
{
    return dash_instance_hash(tx);
}

namespace cbtx_detail {
template <typename TxRange>
inline uint256 asset_unlock_root(const TxRange& txs)
{
    std::vector<uint256> leaves;
    for (const auto& tx : txs)
        if (is_asset_unlock_with_stable_txid(tx))
            leaves.push_back(tx_full_serialization_hash(MutableTransaction(tx)));
    return compute_merkle_root_local(std::move(leaves));
}
} // namespace cbtx_detail

/// CalcCbTxMerkleRootAssetUnlocks over the block's transactions in block
/// order (the coinbase, if present, is never a leaf).
inline uint256 compute_merkle_root_asset_unlocks(const std::vector<MutableTransaction>& txs)
{
    return cbtx_detail::asset_unlock_root(txs);
}
/// The same over a template body (DashWorkData::m_txs).
inline uint256 compute_merkle_root_asset_unlocks(const std::vector<Transaction>& txs)
{
    return cbtx_detail::asset_unlock_root(txs);
}

/// The CbTx version CheckCbTx requires for a block (post-DIP0008; the
/// embedded node only builds post-V20 blocks): 4 when v24 and v20 are both
/// active, 3 when only v20 is.
inline uint16_t required_cbtx_version(bool v20_active, bool v24_active)
{
    if (v20_active && v24_active) return vendor::CCbTx::VERSION_MERKLE_ROOT_ASSETUNLOCKS;
    if (v20_active) return vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    return vendor::CCbTx::VERSION_MERKLE_ROOT_QUORUMS;
}

} // namespace coin
} // namespace dash
