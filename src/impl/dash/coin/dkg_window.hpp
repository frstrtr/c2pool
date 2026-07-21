// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DKG mining-phase (quorum-commitment) height guard for the embedded arm.
///
/// review PR #780 BLOCKER-1 (CRITICAL): dashd's block-N CbTx quorum set is the
/// active-until-prev-block set PLUS block-N's OWN type-6 (QUORUM_COMMITMENT)
/// special txs, and those commitment txs are MANDATORY IN-BLOCK during a DKG
/// mining phase (dashcore llmq/blockprocessor.cpp:
///   GetNumCommitmentsRequired(llmqParams, height) > 0
///   => the block MUST carry that many commitments, else bad-qc-missing).
///
/// The embedded arm (a) strips ALL special txs (C-3 exclude_special), so it
/// never places the mandatory commitment tx in the block body, AND (b) computes
/// merkleRootQuorums from the mnlistdiff-fed until-prev set only, omitting the
/// current block's commitments. On any DKG mining-phase height that block is
/// consensus-invalid two ways over (bad-qc-missing + wrong merkleRootQuorums).
///
/// PHASE-1 (reward-safe interim): refuse the embedded arm — fail closed to the
/// reward-safe dashd fallback — at any height where a commitment MAY be required
/// for ANY enabled llmqType. This is a coarse but consensus-safe
/// OVER-approximation of dashcore's IsMiningPhase: it refuses the entire mining
/// window [dkgMiningWindowStart, dkgMiningWindowEnd] of every enabled type's DKG
/// cycle (it does not track the per-cycle "already mined" refinement, so it may
/// over-refuse near a boundary — always to the safe dashd fallback, never losing
/// a block).
///
/// MAINTENANCE: these windows are copied from dashcore llmq/params.h. RE-DIFF
/// this table against llmq/params.h (dkgInterval / dkgMiningWindowStart /
/// dkgMiningWindowEnd per enabled llmqType) on every vendored-dashcore pin bump —
/// a params change silently narrows the guard and can let a qc height through.
///
/// Params are dashcore mainnet+testnet llmq/params.h @ develop (verbatim):
///   LLMQ_50_60  / LLMQ_100_67 / LLMQ_25_67 : dkgInterval 24,  window [10,18]
///   LLMQ_400_60                            : dkgInterval 288, window [20,28]
///   LLMQ_400_85                            : dkgInterval 576, window [20,48]
///   LLMQ_60_75 (rotated)                   : dkgInterval 288, window [42,50]
/// The (24,10,18) window covers types 1/4/6 on both networks; the rest are on
/// both mainnet and testnet. Taking the union is network-agnostic and fail-safe.

#include <cstdint>

namespace dash {
namespace coin {

/// True if `height` falls inside the DKG mining window of any enabled llmqType,
/// i.e. a commitment MAY be required in-block at this height. When true, the
/// embedded arm must refuse (route to the dashd fallback).
inline bool is_dkg_commitment_window(uint32_t height)
{
    struct Win { uint32_t interval, start, end; };
    // Union of every enabled non-test llmqType's DKG mining window.
    static constexpr Win kWindows[] = {
        { 24,  10, 18 },   // LLMQ_50_60 / LLMQ_100_67 / LLMQ_25_67
        { 288, 20, 28 },   // LLMQ_400_60
        { 576, 20, 48 },   // LLMQ_400_85
        { 288, 42, 50 },   // LLMQ_60_75 (rotated)
    };
    for (const auto& w : kWindows) {
        const uint32_t phase = height % w.interval;
        if (phase >= w.start && phase <= w.end)
            return true;
    }
    return false;
}

} // namespace coin
} // namespace dash
