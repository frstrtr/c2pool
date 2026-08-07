// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// #107 — EXPLAIN a creditPool divergence instead of alarming on it.
///
/// Our template builder excludes every Dash special tx by design (C-3, see
/// mempool.hpp): the builder does not yet apply DIP-0027 asset movement to the
/// credit pool, so including such a tx while leaving the pool untouched would
/// commit a wrong CbTx. Excluding it keeps our template INTERNALLY CONSISTENT
/// and therefore consensus-valid.
///
/// The consequence is that whenever dashd's template carries pending asset
/// locks/unlocks, its CbTx creditPoolBalance differs from ours by EXACTLY the
/// summed effect of those txs:
///
///   lock   (type 8): pool += sum(payload.creditOutputs[].value)
///   unlock (type 9): pool -= (payload.fee + sum(tx.vout[].value))
///
/// dashd hands us its tx list along with the template, so this is an equation
/// and not a guess: if embedded_pool + delta == dashd_pool the divergence is
/// FULLY ACCOUNTED FOR by a by-design exclusion, and the graduation statistics
/// must not count it as drift. Anything else stays an unexplained mismatch.
///
/// Kept as a free function over a tx range so the KATs can pin the arithmetic
/// without a live daemon, a stratum session, or a populated coin state.

#include <impl/dash/coin/vendor/assetlock.hpp>

#include <cstdint>
#include <vector>

namespace dash {
namespace coin {

struct SpecialPoolDelta {
    /// Summed DIP-0027 effect of the special txs seen (signed: locks add,
    /// unlocks subtract). Meaningless when `unparsable` is true.
    int64_t  delta{0};
    /// How many special txs contributed. Zero means the divergence has
    /// nothing to do with asset movement.
    unsigned count{0};
    /// A special tx was present but its payload did not parse. We then know
    /// NOTHING about the true delta, so nothing may be explained by it.
    bool     unparsable{false};

    /// The equation: does our pool plus this movement land exactly on dashd's?
    /// Requires at least one special tx and a clean parse — an accidental
    /// zero-tx "match" is never an explanation.
    bool explains(int64_t embedded_pool, int64_t dashd_pool) const {
        return !unparsable && count > 0 && embedded_pool + delta == dashd_pool;
    }
};

/// Compute the pending asset movement carried by `txs` (dashd's template tx
/// list). Non-special txs are ignored; the first unparsable special payload
/// aborts with unparsable=true (a partial sum would be worse than no sum).
template <typename TxRange>
inline SpecialPoolDelta special_tx_pool_delta(const TxRange& txs)
{
    SpecialPoolDelta out;
    for (const auto& t : txs) {
        if (t.type == vendor::CAssetLockPayload::SPECIALTX_TYPE) {
            vendor::CAssetLockPayload pl;
            if (!vendor::parse_assetlock_payload(t.extra_payload, pl)) {
                out.unparsable = true;
                return out;
            }
            int64_t sum = 0;
            for (const auto& o : pl.creditOutputs) sum += o.value;
            out.delta += sum;
            ++out.count;
        } else if (t.type == vendor::CAssetUnlockPayload::SPECIALTX_TYPE) {
            vendor::CAssetUnlockPayload pl;
            if (!vendor::parse_assetunlock_payload(t.extra_payload, pl)) {
                out.unparsable = true;
                return out;
            }
            int64_t vout_sum = 0;
            for (const auto& o : t.vout) vout_sum += o.value;
            out.delta -= (static_cast<int64_t>(pl.fee) + vout_sum);
            ++out.count;
        }
    }
    return out;
}

} // namespace coin
} // namespace dash
