// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Variant B (#143 / task wtrv69elc) — the LIGHT bridge struct between the
/// CreditPool INDEX follower (credit_pool_idx.hpp, the producer) and the
/// embedded template builder (embedded_gbt.hpp, the consumer).
///
/// DELIBERATELY minimal includes: embedded_gbt.hpp must be able to accept an
/// admission WITHOUT pulling the follower, the BLS verify declarations or the
/// LevelDB persistence into every target that links the template builder. The
/// struct is pure data; every verification already happened on the producer
/// side (fail-closed predicate + per-candidate ARM-3 checks), and a nullptr /
/// empty admission at the single template-side call site means EXCLUDE-ALL —
/// today's proven-valid behavior, byte-identical.

#include <impl/dash/coin/transaction.hpp>

#include <cstdint>
#include <vector>

namespace dash {
namespace coin {

/// The verified type-9 (asset-unlock) set a template at height H may carry.
/// Produced ONLY by CreditPoolIdxFollower::try_admit_unlocks under the full
/// fail-closed predicate (--embedded-accrue-asset-unlocks ON + real BLS +
/// proven-complete + fresh-at-parent + per-candidate checks). Consumed by
/// build_embedded_workdata via a SAFE-ADDITIVE trailing parameter.
struct AssetUnlockAdmission {
    /// The admitted unlock txs, in admission order. Ordinary template
    /// content — NOT reward logic (reward_path_note): they ride the tx list
    /// like any selected tx.
    std::vector<MutableTransaction> txs;

    /// Σ (payload.fee + Σ vout.value) over `txs` — the GROSS amount that
    /// leaves the credit pool (dashd GetDataFromUnlockTx, creditpool.cpp:33-49).
    /// The committed CbTx creditPoolBalance must be reduced by exactly this.
    int64_t gross_unlocked{0};

    /// Σ payload.fee over `txs` — the miner-fee term (dashd GetAssetUnlockFee,
    /// assetlocktx.cpp:200-212). Added to the template's total_fees so
    /// block_value stays exact; the coinbase-split FORMULA is untouched.
    int64_t total_payload_fees{0};

    bool empty() const { return txs.empty(); }
};

} // namespace coin
} // namespace dash
