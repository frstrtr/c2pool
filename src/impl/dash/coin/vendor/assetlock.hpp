#pragma once

// Vendored from dashcore/src/evo/assetlocktx.h @ develop cfad414
// Phase C-TEMPLATE step 13: DIP-0027 asset-lock special tx payloads.
//
// Two payload types:
//
//   CAssetLockPayload   — special tx type 8 (TRANSACTION_ASSET_LOCK)
//                         Locks DASH from regular UTXO inputs into the
//                         credit pool. The tx vouts are OP_RETURN
//                         markers; the actual credit amounts come from
//                         the payload's creditOutputs vector. Pool
//                         balance changes by +sum(creditOutputs.value).
//
//   CAssetUnlockPayload — special tx type 9 (TRANSACTION_ASSET_UNLOCK)
//                         Mints UTXO from the credit pool. The tx has
//                         NO regular inputs (treasury-class spend
//                         secured by the LLMQ signature in payload).
//                         Pool balance changes by -sum(tx.vouts.value).
//                         (The 'fee' field in the payload is the
//                         miner fee deducted from the unlock total —
//                         it goes to the miner's coinbase, NOT into
//                         the credit pool, so it doesn't appear in
//                         the credit-pool delta.)
//
// Adaptations from upstream:
//   1. CBLSSignature (96-byte BLS sig) → std::array<uint8_t, 96>.
//      We store wire bytes opaquely; verification is Phase L material.
//   2. CTxOut → c2pool's TxOut (same wire format: int64 value +
//      OPScript scriptPubKey).
//   3. SERIALIZE_METHODS body re-expressed in pack.hpp form.
//
// What's NOT vendored (kept as TODO for full DIP-0027 enforcement):
//   - GetRequestId() — derives the BLS sign-id for the unlock; needs
//     LLMQ params + the active quorum set
//   - VerifyQuorumSig() — full BLS verification
//   - GetMaximumAssetLockTxSize() / GetMaximumAssetUnlockTxSize() —
//     ConsensusLimit checks
//   - Limits on consecutive unlock heights, quorum-rotation
//     constraints, etc.
//
// At MVP this is balance-accounting only: scan blocks, sum the
// payload deltas, compare against the next-block CCbTx.creditPoolBalance.

#include <impl/dash/coin/vendor/shim.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/log.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

using ::bitcoin_family::coin::TxOut;

struct CAssetLockPayload
{
    static constexpr uint16_t SPECIALTX_TYPE     = 8;
    static constexpr uint8_t  CURRENT_VERSION    = 1;

    uint8_t                nVersion{CURRENT_VERSION};
    std::vector<TxOut>     creditOutputs;

    SERIALIZE_METHODS(CAssetLockPayload)
    {
        READWRITE(obj.nVersion, obj.creditOutputs);
    }

    int64_t total_credit() const
    {
        int64_t sum = 0;
        for (const auto& o : creditOutputs) sum += o.value;
        return sum;
    }
};

struct CAssetUnlockPayload
{
    static constexpr uint16_t SPECIALTX_TYPE     = 9;
    static constexpr uint8_t  CURRENT_VERSION    = 1;
    static constexpr size_t   BLS_SIG_SIZE       = 96;

    uint8_t                            nVersion{CURRENT_VERSION};
    uint64_t                           index{0};
    uint32_t                           fee{0};
    uint32_t                           requestedHeight{0};
    uint256                            quorumHash;
    std::array<uint8_t, BLS_SIG_SIZE>  quorumSig{};

    SERIALIZE_METHODS(CAssetUnlockPayload)
    {
        READWRITE(obj.nVersion, obj.index, obj.fee, obj.requestedHeight,
                  obj.quorumHash,
                  Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.quorumSig));
    }
};

/// Decode a CAssetLockPayload from a tx's extra_payload bytes. Returns
/// false on empty / malformed / trailing-garbage payload.
inline bool parse_assetlock_payload(
    const std::vector<unsigned char>& extra_payload, CAssetLockPayload& out)
{
    if (extra_payload.empty()) return false;
    try {
        ::PackStream s(extra_payload);
        s >> out;
        if (s.cursor_size() != 0) {
            LOG_WARNING << "[ASSETLOCK] " << s.cursor_size()
                        << " trailing bytes after CAssetLockPayload "
                           "(v=" << static_cast<int>(out.nVersion)
                        << ") — possible wire-format drift";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_WARNING << "[ASSETLOCK] parse failed: " << e.what()
                    << " payload_size=" << extra_payload.size();
        return false;
    }
}

/// Decode a CAssetUnlockPayload from a tx's extra_payload bytes.
inline bool parse_assetunlock_payload(
    const std::vector<unsigned char>& extra_payload, CAssetUnlockPayload& out)
{
    if (extra_payload.empty()) return false;
    try {
        ::PackStream s(extra_payload);
        s >> out;
        if (s.cursor_size() != 0) {
            LOG_WARNING << "[ASSETUNLOCK] " << s.cursor_size()
                        << " trailing bytes after CAssetUnlockPayload "
                           "(v=" << static_cast<int>(out.nVersion)
                        << ") — possible wire-format drift";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_WARNING << "[ASSETUNLOCK] parse failed: " << e.what()
                    << " payload_size=" << extra_payload.size();
        return false;
    }
}

} // namespace vendor
} // namespace coin
} // namespace dash
