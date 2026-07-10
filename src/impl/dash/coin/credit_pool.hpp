// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 13: DIP-0027 credit-pool state machine.
///
/// Tracks the running creditPoolBalance reported in CCbTx.creditPoolBalance
/// (CCbTx.VERSION_CLSIG_AND_BALANCE / version 3+).
///
/// Per-block delta from dashcore evo/creditpool.cpp::DiffFromBlock:
///   For each tx in the block (excluding coinbase):
///     - Type 8 (TRANSACTION_ASSET_LOCK):
///         pool += sum(payload.creditOutputs.value)
///     - Type 9 (TRANSACTION_ASSET_UNLOCK):
///         pool -= sum(tx.vout.value)   // gross withdrawal; the
///                                      // payload.fee is paid to the
///                                      // miner from the unlock total
///                                      // and does NOT come back into
///                                      // the pool
///
/// Bootstrap: seed from the first observed CCbTx.creditPoolBalance
/// before applying any deltas (similar pattern to MnStateMachine
/// bootstrap from snapshot). Persistence via CreditPoolDb (sister of
/// SMLDb / QuorumDb / MnStateDb).
///
/// At MVP (this commit): in-memory only. Persistence + sentinel
/// cross-check land in step 13b. Cold-start re-seeds from the first
/// post-restart observed CCbTx.

#include <impl/dash/coin/vendor/assetlock.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/log.hpp>

#include <cstdint>
#include <optional>

namespace dash {
namespace coin {

class CreditPool
{
public:
    /// Apply a block to the pool. Returns the per-block delta on
    /// success, or std::nullopt if the pool is uninitialized (no seed
    /// observed yet — caller should seed from CCbTx.creditPoolBalance).
    std::optional<int64_t> apply_block(
        const BlockType& block, uint32_t height)
    {
        if (!m_initialized) return std::nullopt;

        int64_t delta = 0;
        size_t locks = 0, unlocks = 0;

        // Skip cb (index 0) — it's the special-tx-5 CCbTx itself,
        // which doesn't carry asset-lock/unlock payloads.
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.type == vendor::CAssetLockPayload::SPECIALTX_TYPE
                && !tx.extra_payload.empty()) {
                vendor::CAssetLockPayload p;
                if (vendor::parse_assetlock_payload(tx.extra_payload, p)) {
                    delta += p.total_credit();
                    ++locks;
                }
                // parse failures already log; skip the tx for accounting
            } else if (tx.type == vendor::CAssetUnlockPayload::SPECIALTX_TYPE) {
                // For unlocks, the deduction is sum of vout values
                // (gross withdrawal). Payload parse is informational —
                // not strictly required for the balance math, but we
                // do it to keep the [ASSETUNLOCK] log consistent and
                // catch wire-format drift early.
                int64_t out_sum = 0;
                for (const auto& v : tx.vout) out_sum += v.value;
                delta -= out_sum;
                ++unlocks;
                // Optional payload parse for diagnostics.
                if (!tx.extra_payload.empty()) {
                    vendor::CAssetUnlockPayload up;
                    vendor::parse_assetunlock_payload(tx.extra_payload, up);
                }
            }
        }

        m_balance += delta;
        m_height = height;

        if (delta != 0 || locks != 0 || unlocks != 0) {
            LOG_INFO << "[CREDITPOOL] h=" << height
                     << " delta=" << delta
                     << " locks=" << locks
                     << " unlocks=" << unlocks
                     << " balance=" << m_balance;
        }
        return delta;
    }

    /// Seed the pool from an observed CCbTx.creditPoolBalance. The
    /// CCbTx field reports the balance AFTER applying that block's
    /// activity, so on the next block we apply deltas on top of this.
    void seed(int64_t balance, uint32_t height)
    {
        m_balance     = balance;
        m_height      = height;
        m_initialized = true;
        LOG_INFO << "[CREDITPOOL] seeded h=" << height
                 << " balance=" << balance;
    }

    int64_t balance() const { return m_balance; }
    uint32_t height() const { return m_height; }
    bool initialized() const { return m_initialized; }

    void clear()
    {
        m_balance = 0;
        m_height = 0;
        m_initialized = false;
    }

private:
    int64_t  m_balance{0};
    uint32_t m_height{0};
    bool     m_initialized{false};
};

} // namespace coin
} // namespace dash