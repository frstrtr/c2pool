// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// #107 PHASE 2 — ACCRUE the pending type-8 (asset-lock) DIP-0027 credit-pool
/// term into OUR embedded CbTx, so the committed creditPoolBalance matches what
/// dashd computes and the `gbt-xcheck-modulo-special-explained` swap
/// (dash/stratum/work_source.cpp) stops firing on the EXPLAINED case.
///
/// PHASE 1 (special_tx_pool_delta.hpp) only EXPLAINED a divergence after the
/// fact, over dashd's OWN already-validated tx list, using
/// Σ payload.creditOutputs. This header ports the arithmetic dashd actually
/// COMMITS a block with — which is NOT the same source, even though the two are
/// numerically equal for a valid tx:
///
///   dashd's per-block credit-pool lock term is the value of the FIRST OP_RETURN
///   output of the lock tx (evo/creditpool.cpp:262-276), NOT the sum of
///   payload.creditOutputs. They are equal ONLY because CheckAssetLockTx
///   (evo/assetlocktx.cpp:90-92) enforces
///       Σ payload.creditOutputs == returnAmount (the OP_RETURN value).
///   A value that COMMITS to a block must be byte-exact against the source
///   validation re-derives from, not merely equal-by-invariant to another
///   field, so this header reads the OP_RETURN output — dashd's source — and
///   validates the invariant rather than assuming it.
///
/// WHERE THE COMMITTED VALUE LANDS AND IS CHECKED (a wrong fold = a rejected
/// block, not a warning):
///   - GetTotalLocked() = pool.locked + sessionLocked − sessionUnlocked
///                        + platformReward           (evo/creditpool.h:98-100)
///   - written into the CbTx at node/miner.cpp:314
///   - re-derived from the block's OWN txs and compared by the validator at
///     evo/specialtxman.cpp:749-755 → mismatch = bad-cbtx-assetlocked-amount
///     = REJECTED BLOCK.
///
/// TYPE-8 SAFETY (no quorum signature needed): CheckAssetLockTx
/// (evo/assetlocktx.cpp:44-95) is a PURE function of tx bytes — nType==8,
/// exactly one OP_RETURN output whose value is in MoneyRange, payload parses,
/// version in [1, CURRENT_VERSION], creditOutputs non-empty and each in
/// MoneyRange, and Σ creditOutputs == OP_RETURN value. We reproduce it here so
/// a lock is folded ONLY when it would be a valid block member. Type-9 (unlock)
/// is DELIBERATELY OUT OF SCOPE: it needs the platform-LLMQ signature-verify +
/// header index + global dedup CRangesSet + sliding withdrawal limit state
/// machines that this daemonless build does not carry, so this header never
/// accrues an unlock term.
///
/// Reuses the vendored payload parser (assetlock.hpp::parse_assetlock_payload)
/// and the SPECIALTX_TYPE constant rather than re-deriving them.

#include <impl/dash/coin/vendor/assetlock.hpp>

#include <core/log.hpp>

#include <cstdint>
#include <vector>

namespace dash {
namespace coin {

/// DASH MoneyRange upper bound: MAX_MONEY = 21e6 * COIN (dashcore
/// consensus/amount.h; dashcore inherits Bitcoin's 21M cap). Same constant the
/// governance-object and UTXO adapters use.
inline constexpr int64_t k_dash_max_money = 21'000'000LL * 100'000'000LL;

/// OP_RETURN opcode (0x6a). A type-8 lock encodes the locked amount as the
/// value of a bare OP_RETURN output; the payload's creditOutputs describe how
/// that amount is credited on the Platform side.
inline constexpr unsigned char k_op_return = 0x6a;

inline bool money_in_range(int64_t v) { return v >= 0 && v <= k_dash_max_money; }

/// dashcore evo/creditpool.cpp:262-276 — the credit-pool contribution of a
/// TRANSACTION_ASSET_LOCK is the value of the FIRST output whose scriptPubKey
/// is OP_RETURN. Returns that value, or -1 when the tx carries no OP_RETURN
/// output (which CheckAssetLockTx forbids for a valid lock; the caller must
/// have validated first).
template <typename Tx>
inline int64_t asset_lock_first_op_return_value(const Tx& tx)
{
    for (const auto& out : tx.vout) {
        const auto& script = out.scriptPubKey.m_data;
        if (script.empty() || script[0] != k_op_return) continue;
        return out.value;    // FIRST OP_RETURN only — matches dashd's `break`.
    }
    return -1;
}

/// Port of dashcore evo/assetlocktx.cpp:44-95 CheckAssetLockTx as a PURE
/// function of tx bytes. A type-8 tx that passes this is a valid block member,
/// so folding its credit term into our CbTx cannot desync our pool from what
/// validation re-derives from the SAME tx in the block body.
template <typename Tx>
inline bool check_asset_lock_tx(const Tx& tx)
{
    if (tx.type != vendor::CAssetLockPayload::SPECIALTX_TYPE) return false;

    vendor::CAssetLockPayload pl;
    if (!vendor::parse_assetlock_payload(tx.extra_payload, pl)) return false;
    // version in [1, CURRENT_VERSION] (dashd: nVersion == 0 || > CURRENT is bad)
    if (pl.nVersion == 0 || pl.nVersion > vendor::CAssetLockPayload::CURRENT_VERSION)
        return false;
    if (pl.creditOutputs.empty()) return false;

    int64_t credit_sum = 0;
    for (const auto& o : pl.creditOutputs) {
        if (!money_in_range(o.value)) return false;
        credit_sum += o.value;
        if (!money_in_range(credit_sum)) return false;   // overflow guard
    }

    // Exactly one OP_RETURN output; its value in MoneyRange.
    unsigned return_count = 0;
    int64_t   return_amount = 0;
    for (const auto& out : tx.vout) {
        const auto& script = out.scriptPubKey.m_data;
        if (script.empty() || script[0] != k_op_return) continue;
        // dashd requires the marker output to be a bare 2-byte OP_RETURN
        // (OP_RETURN + a single push-count/opcode byte); a longer OP_RETURN
        // script is rejected (assetlocktx.cpp "assetlocktx-non-empty-return").
        if (script.size() != 2) return false;
        if (!money_in_range(out.value)) return false;
        return_amount += out.value;
        ++return_count;
    }
    if (return_count != 1) return false;

    // The invariant that makes first-OP_RETURN and Σ creditOutputs equal
    // (assetlocktx.cpp:90-92). We do not assume it — we require it.
    if (credit_sum != return_amount) return false;

    return true;
}

/// Result of folding the pending type-8 locks a template would carry.
struct AssetLockFold {
    /// Signed pool accrual (always >= 0 here: locks only add; type-9 is out of
    /// scope). This is Σ first-OP_RETURN value over the VALID locks.
    int64_t  accrued{0};
    /// How many type-8 locks were folded.
    unsigned count{0};
    /// How many type-8 candidates were REJECTED by check_asset_lock_tx (would
    /// not be valid block members). A non-zero value means our fold is a strict
    /// subset of the candidates — the xcheck stays fail-closed on any residual
    /// pool disagreement, so this is diagnostic, not a correctness lever.
    unsigned rejected{0};
};

/// Fold the pending type-8 asset-lock txs into a credit-pool accrual using
/// dashd's EXACT first-OP_RETURN arithmetic. Non-type-8 txs are ignored; an
/// invalid type-8 (fails CheckAssetLockTx) is skipped and counted in
/// `rejected` (dashd's getblocktemplate would not include it either).
template <typename TxRange>
inline AssetLockFold pending_asset_lock_fold(const TxRange& txs)
{
    AssetLockFold out;
    for (const auto& tx : txs) {
        if (tx.type != vendor::CAssetLockPayload::SPECIALTX_TYPE) continue;
        if (!check_asset_lock_tx(tx)) { ++out.rejected; continue; }
        out.accrued += asset_lock_first_op_return_value(tx);
        ++out.count;
    }
    return out;
}

} // namespace coin
} // namespace dash
