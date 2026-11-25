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
/// TYPE-8 SAFETY (no quorum signature needed): CheckAssetLockTx (Dash Core
/// v24, evo/assetlocktx.cpp:28-87) is a PURE function of tx bytes; see
/// asset_lock_refusal() below for the exact rule list. We reproduce it here so
/// a lock is folded ONLY when it would be a valid block member, and template
/// selection (Mempool::get_sorted_txs_with_fees) applies the same check, so a
/// lock the fold refuses can never ride the body either. Type-9 (unlock)
/// is DELIBERATELY OUT OF SCOPE: it needs the platform-LLMQ signature-verify +
/// header index + global dedup CRangesSet + sliding withdrawal limit state
/// machines that this daemonless build does not carry, so this header never
/// accrues an unlock term.
///
/// Reuses the vendored payload parser (assetlock.hpp::parse_assetlock_payload)
/// and the SPECIALTX_TYPE constant rather than re-deriving them.

#include <impl/dash/coin/vendor/assetlock.hpp>

#include <core/log.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <optional>
#include <string>
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

/// CAssetLockPayload::CURRENT_VERSION in Dash Core v24 (version 2 is valid only
/// after DEPLOYMENT_V24). The vendored payload keeps CURRENT_VERSION = 1, the
/// highest version our template may carry.
inline constexpr uint8_t k_asset_lock_max_version = 2;

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

/// CScript::IsPayToPublicKeyHash(): OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
/// OP_CHECKSIG, exactly 25 bytes.
inline bool asset_lock_script_is_p2pkh(const std::vector<unsigned char>& s)
{
    return s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14
        && s[23] == 0x88 && s[24] == 0xac;
}

/// CScript::IsPayToScriptHash(): OP_HASH160 <20> OP_EQUAL, exactly 23 bytes.
inline bool asset_lock_script_is_p2sh(const std::vector<unsigned char>& s)
{
    return s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87;
}

/// Port of CheckAssetLockTx (Dash Core v24, src/evo/assetlocktx.cpp:28-87) as a
/// PURE function of tx bytes. Returns Core's reject reason for the first check
/// that fails, in Core's order, or nullopt for a lock that is a valid block
/// member under the given rules:
///   * nType == 8;
///   * every OP_RETURN output is exactly `6a 00`, carries a non-zero value in
///     MoneyRange, and there is exactly one of them;
///   * the payload parses; its version is in [1, 2], and version 2 only once
///     DEPLOYMENT_V24 is active for the block;
///   * creditOutputs is non-empty, each value non-zero and the running sum in
///     MoneyRange; a version-1 credit output must be P2PKH, a version-2 one
///     P2PKH or P2SH;
///   * Σ creditOutputs equals the OP_RETURN value.
/// The P2PKH rule, the `6a 00` byte and the non-zero values were missing from
/// the earlier port, so a lock dashd rejects could be folded into our CbTx
/// creditPoolBalance and ride the template body.
template <typename Tx>
inline std::optional<std::string> asset_lock_refusal(const Tx& tx, bool v24_active = false)
{
    if (tx.type != vendor::CAssetLockPayload::SPECIALTX_TYPE) return "bad-assetlocktx-type";

    int64_t return_amount = 0;
    for (const auto& out : tx.vout) {
        const auto& script = out.scriptPubKey.m_data;
        if (script.empty() || script[0] != k_op_return) continue;
        if (script.size() != 2 || script[1] != 0) return "bad-assetlocktx-non-empty-return";
        if (out.value == 0 || !money_in_range(out.value)) return "bad-assetlocktx-opreturn-outofrange";
        if (return_amount > 0) return "bad-assetlocktx-multiple-return";
        return_amount = out.value;
    }
    if (return_amount == 0) return "bad-assetlocktx-no-return";

    vendor::CAssetLockPayload pl;
    if (!vendor::parse_assetlock_payload(tx.extra_payload, pl)) return "bad-assetlocktx-payload";
    if (pl.nVersion == 0 || pl.nVersion > k_asset_lock_max_version) return "bad-assetlocktx-version";
    if (!v24_active && pl.nVersion > vendor::CAssetLockPayload::CURRENT_VERSION)
        return "bad-assetlocktx-version-2";
    if (pl.creditOutputs.empty()) return "bad-assetlocktx-emptycreditoutputs";

    int64_t credit_sum = 0;
    for (const auto& o : pl.creditOutputs) {
        if (o.value == 0 || !money_in_range(o.value) || !money_in_range(credit_sum + o.value))
            return "bad-assetlocktx-credit-outofrange";
        credit_sum += o.value;
        const auto& spk = o.scriptPubKey.m_data;
        if (pl.nVersion >= 2) {
            if (!asset_lock_script_is_p2pkh(spk) && !asset_lock_script_is_p2sh(spk))
                return "bad-assetlocktx-script-pubkey";
        } else if (!asset_lock_script_is_p2pkh(spk)) {
            return "bad-assetlocktx-pubKeyHash";
        }
    }
    // The invariant that makes first-OP_RETURN and Σ creditOutputs equal.
    // We do not assume it; we require it.
    if (credit_sum != return_amount) return "bad-assetlocktx-creditamount";
    return std::nullopt;
}

/// A type-8 tx that passes this is a valid block member before DEPLOYMENT_V24,
/// so folding its credit term into our CbTx cannot desync our pool from what
/// validation re-derives from the SAME tx in the block body. The template
/// never carries a version-2 lock: it needs v24 to be valid, and Dash Core v24
/// keeps it nonstandard (specialtxman.cpp IsAssetLockTxStandard), so a
/// version-2 lock is refused here at every height.
template <typename Tx>
inline bool check_asset_lock_tx(const Tx& tx)
{
    return !asset_lock_refusal(tx, /*v24_active=*/false).has_value();
}

/// Dash Core v24 IsStandardSpecialTx (src/evo/specialtxman.cpp) for an asset
/// lock: the reason a standard-relaying node refuses it, or nullopt. More than
/// MAX_STANDARD_ASSET_LOCK_INPUTS (100) inputs or a serialization over 20480
/// bytes exceeds what Platform's funding state transition can carry; a version
/// 2 payload is not yet standard. Policy, not consensus: the template leaves
/// such a lock out (good citizen), dashd's own miner would never see it.
template <typename Tx>
inline std::optional<std::string> asset_lock_standard_refusal(const Tx& tx)
{
    if (tx.type != vendor::CAssetLockPayload::SPECIALTX_TYPE) return std::nullopt;
    if (tx.vin.size() > 100) return std::string("assetlocktx-too-many-inputs");
    if (::pack(tx).get_span().size() > 20480) return std::string("assetlocktx-too-big");
    vendor::CAssetLockPayload pl;
    if (vendor::parse_assetlock_payload(tx.extra_payload, pl) && pl.nVersion >= 2)
        return std::string("assetlocktx-version-2");
    return std::nullopt;
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
