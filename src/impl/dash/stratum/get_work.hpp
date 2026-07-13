// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 9 (capstone): the fused dash get_work() consumer.
///
/// Every prior slice landed one HALF of get_work in isolation:
///   * select_dash_work() / NodeCoinState::select_work() (work_source.hpp,
///     node_coin_state.hpp, #672/#673) -- the TEMPLATE source: prefer the
///     locally-assembled embedded template (build_embedded_workdata, oracle
///     parity vs frstrtr/p2pool-dash getwork(), older-than-v35) when the
///     node-held coin-state bundle is populated by the 4-leg reception wire
///     (#693/#694), else the RETAINED dashd getblocktemplate fallback;
///   * assemble_work_job_targets() (work_job_targets.hpp) -- the per-miner
///     JOB-TARGET arithmetic (work.py:368-426).
///
/// Nothing fused them: no production (non-test) caller ever ran
/// NodeCoinState::select_work() to source a template AND assembled the miner
/// job over it -- the two halves were exercised only by their own unit KATs.
/// get_work() is that single miner-facing entry point -- the
/// "DASHWorkSource::get_work()" the stratum headers reference as future work.
///
/// CONTRACT (matches the S8 embedded-arm invariants):
///   * the hot path reads the node-held NodeCoinState -- NO direct dashd poll
///     when the bundle is populated (the embedded arm assembles locally);
///   * dashd_fallback is REQUIRED and is invoked ONLY on a set-gap
///     (unpopulated / invalidated bundle) -- the always-reachable safety path
///     and the [GBT-XCHECK] cross-check, NEVER removed;
///   * the job-target assembly is a pure transform of caller inputs and rides
///     on top of EITHER template source unchanged.
///
/// STRICTLY single-coin: src/impl/dash/ only, no bitcoin_family / src/core
/// reach beyond the shared uint256/DashWorkData types the halves already use.

#include <impl/dash/coin/node_coin_state.hpp>       // NodeCoinState, WorkSelection, WorkSource
#include <impl/dash/coin/rpc_data.hpp>              // DashWorkData
#include <impl/dash/stratum/work_job_targets.hpp>   // assemble_work_job_targets, WorkJobTargets, WorkJobTargetInputs

#include <functional>
#include <utility>

namespace dash::stratum {

/// The miner-facing result of get_work(): which arm sourced the template, the
/// selected block template itself, and the assembled stratum job targets.
struct GetWork {
    coin::WorkSource   source{coin::WorkSource::DashdFallback};
    coin::DashWorkData work;
    WorkJobTargets     targets;
};

/// Fused get_work(): source the base block template off the node-held
/// coin-state (embedded when populated, retained dashd fallback on a set-gap)
/// and assemble the per-miner job targets over it. dashd_fallback is REQUIRED
/// -- it is the always-reachable safety/cross-check arm and is only invoked
/// when the embedded bundle is unavailable.
inline GetWork get_work(
    const coin::NodeCoinState& coin_state,
    const std::function<coin::DashWorkData()>& dashd_fallback,
    const WorkJobTargetInputs& job_in)
{
    coin::WorkSelection sel = coin_state.select_work(dashd_fallback);
    WorkJobTargets targets  = assemble_work_job_targets(job_in);
    return GetWork{ sel.source, std::move(sel.work), targets };
}

}  // namespace dash::stratum
