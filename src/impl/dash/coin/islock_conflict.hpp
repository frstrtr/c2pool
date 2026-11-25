// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// InstantSend-lock conflicts in an ALREADY-BUILT block body (N2).
///
/// Dash Core rejects a block that carries a tx spending an outpoint a known
/// islock assigns to a different txid, unless that block is itself
/// ChainLocked (v24.0.2 src/validation.cpp:2811-2829, ConnectBlock
/// "conflict-tx-lock"; the conflict test is CInstantSendManager::
/// GetConflictingLock, src/instantsend/instantsend.cpp:428-445). A freshly
/// found block is never ChainLocked when the network first connects it, and
/// masternodes hold every islock they signed, so such a block is lost.
///
/// The template builder already keeps these txs out of NEW templates (the G4
/// selection guard in Mempool::get_sorted_txs_with_fees). What it cannot do is
/// fix a template that was built and served BEFORE the islock reached us: the
/// job miners are hashing still carries the tx. This header holds the two
/// pure pieces the fix needs, so both are KAT-able without a live node:
///
///   * first_islock_conflict(): scan a body against an outpoint -> locked-txid
///     lookup (used by the emit gate's belt over the VERIFIED islock map, and
///     by the proactive check against one just-verified lock);
///   * IslockRefreshCoalescer: at most one forced work refresh per interval,
///     with one trailing refresh so a second conflict inside the interval is
///     not dropped.
///
/// Only BLS-VERIFIED islocks may drive either action. The unverified relay
/// lane (any peer) must not: a forged lock could otherwise refuse templates or
/// force clean_jobs notifies (an ASIC work flush) on demand.

#include <impl/dash/coin/dash_txid.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <core/uint256.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace dash::coin {

struct IslockConflict {
    size_t                       index{0};       // position in the body
    uint256                      txid;           // the conflicting body tx
    uint256                      locked_txid;    // the txid the islock locks the outpoint to
    std::pair<uint256, uint32_t> outpoint;
};

/// First body tx that spends an outpoint `locked_txid_of(outpoint)` assigns to
/// a DIFFERENT txid. `txids` is used when it lines up with `txs` (the ids the
/// header's merkle root commits); otherwise the id is computed. The id is only
/// needed for a tx that spends a locked outpoint, so the common case (no lock
/// on any input) never hashes.
template <typename TxT, typename LookupFn>
std::optional<IslockConflict>
first_islock_conflict(const std::vector<TxT>& txs, const std::vector<uint256>& txids,
                      LookupFn&& locked_txid_of)
{
    const bool ids_aligned = txids.size() == txs.size();
    for (size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs[i];
        std::optional<uint256> id;
        for (const auto& vin : tx.vin) {
            const std::pair<uint256, uint32_t> op{vin.prevout.hash, vin.prevout.index};
            const std::optional<uint256> locked = locked_txid_of(op);
            if (!locked) continue;
            if (!id) id = ids_aligned ? txids[i] : dash_txid(MutableTransaction(tx));
            if (*locked != *id) return IslockConflict{i, *id, *locked, op};
        }
    }
    return std::nullopt;
}

/// Does `txs` spend any of `inputs` under a txid other than `locked_txid`?
/// The proactive check run once per just-verified islock against the served
/// template.
template <typename TxT>
std::optional<IslockConflict>
body_conflicts_with_lock(const std::vector<TxT>& txs, const std::vector<uint256>& txids,
                         const uint256& locked_txid,
                         const std::vector<std::pair<uint256, uint32_t>>& inputs)
{
    if (inputs.empty() || txs.empty()) return std::nullopt;
    const std::set<std::pair<uint256, uint32_t>> locked(inputs.begin(), inputs.end());
    return first_islock_conflict(txs, txids,
        [&](const std::pair<uint256, uint32_t>& op) -> std::optional<uint256> {
            if (locked.count(op)) return locked_txid;
            return std::nullopt;
        });
}

/// At most one forced refresh per `min_gap`. A trigger inside the gap asks the
/// caller to schedule ONE trailing refresh at the end of the gap (further
/// triggers before it fires are absorbed): a second verified conflict that
/// lands just after a refresh is still acted on, within `min_gap`.
class IslockRefreshCoalescer {
public:
    using clock = std::chrono::steady_clock;
    enum class Act { FireNow, ScheduleTrailing, AlreadyPending };
    struct Decision {
        Act               act;
        clock::duration   delay{};   // ScheduleTrailing only
    };

    explicit IslockRefreshCoalescer(clock::duration min_gap = std::chrono::seconds(1))
        : m_min_gap(min_gap) {}

    Decision on_trigger(clock::time_point now) {
        if (m_pending) return {Act::AlreadyPending};
        if (!m_have_last || now - m_last >= m_min_gap) {
            m_last = now;
            m_have_last = true;
            return {Act::FireNow};
        }
        m_pending = true;
        return {Act::ScheduleTrailing, m_min_gap - (now - m_last)};
    }

    /// The scheduled trailing refresh ran.
    void on_trailing_fired(clock::time_point now) {
        m_pending = false;
        m_last = now;
        m_have_last = true;
    }

    bool pending() const { return m_pending; }

private:
    clock::duration   m_min_gap;
    clock::time_point m_last{};
    bool              m_have_last{false};
    bool              m_pending{false};
};

} // namespace dash::coin
