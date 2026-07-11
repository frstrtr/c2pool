// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 5 (capstone): embedded-vs-dashd work-source selector.
///
/// build_embedded_workdata() (embedded_gbt.hpp) is source-complete and pinned
/// by test_dash_embedded_gbt (oracle: frstrtr/p2pool-dash getwork(),
/// older-than-v35 semantics). What was missing is a LIVE consumer: the running
/// node's get_work path must PREFER the locally-assembled embedded template and
/// fall back to dashd getblocktemplate only when the embedded coin-state bundle
/// is unavailable.
///
/// select_dash_work() is that branch point. When the EmbeddedWorkInputs bundle
/// is viable (masternode list + mempool + header-tip params all present) it
/// assembles the template LOCALLY via build_embedded_workdata() — the
/// oracle-parity path. Otherwise it invokes the supplied dashd fallback.
///
/// The external-daemon (dashd RPC) arm is NEVER removed: it is BOTH the fallback
/// AND the [GBT-XCHECK] cross-check. viable()==false must always route there.

#include <impl/dash/coin/embedded_gbt.hpp>       // build_embedded_workdata
#include <impl/dash/coin/mn_state_machine.hpp>   // MnStateMachine
#include <impl/dash/coin/mempool.hpp>            // Mempool
#include <impl/dash/coin/rpc_data.hpp>           // DashWorkData

#include <core/uint256.hpp>

#include <ctime>
#include <cstdint>
#include <functional>
#include <utility>

namespace dash {
namespace coin {

/// The inputs build_embedded_workdata() consumes, plus a validity flag. For the
/// embedded path to be taken, has_state must be true AND both pointers non-null
/// (viable()). Until NodeImpl carries embedded coin-state in-process, callers
/// leave has_state=false and the selector routes to the dashd fallback.
struct EmbeddedWorkInputs {
    bool                  has_state{false};
    uint32_t              prev_height{0};
    uint256               prev_hash;
    const MnStateMachine* mnstates{nullptr};
    const Mempool*        mempool{nullptr};
    uint32_t              bits_for_next{0};
    uint32_t              mtp_at_tip{0};
    uint8_t               address_version{0};
    uint8_t               address_p2sh_version{0};
    // Optional seams. 0 => use build_embedded_workdata's own SAFE-ADDITIVE
    // defaults (std::time(nullptr) / 0x20000000 BIP9 baseline).
    uint32_t              curtime{0};
    uint32_t              version{0};

    bool viable() const {
        return has_state && mnstates != nullptr && mempool != nullptr;
    }
};

enum class WorkSource { Embedded, DashdFallback };

struct WorkSelection {
    DashWorkData work;
    WorkSource   source{WorkSource::DashdFallback};
};

/// Injectable core — the routing decision, testable without a live daemon or a
/// populated MN/mempool harness. Production binds embedded_builder to the real
/// build_embedded_workdata() closure (see the 2-arg overload below).
inline WorkSelection select_dash_work(
    const EmbeddedWorkInputs& emb,
    const std::function<DashWorkData()>& embedded_builder,
    const std::function<DashWorkData()>& dashd_fallback)
{
    if (emb.viable())
        return WorkSelection{embedded_builder(), WorkSource::Embedded};
    return WorkSelection{dashd_fallback(), WorkSource::DashdFallback};
}

/// Production entry point: builds the embedded template from `emb` when viable,
/// else calls `dashd_fallback` (the retained external-daemon getblocktemplate
/// arm). dashd_fallback is REQUIRED — it is the always-reachable safety path.
inline WorkSelection select_dash_work(
    const EmbeddedWorkInputs& emb,
    const std::function<DashWorkData()>& dashd_fallback)
{
    return select_dash_work(
        emb,
        [&emb]() {
            return build_embedded_workdata(
                emb.prev_height, emb.prev_hash, *emb.mnstates, *emb.mempool,
                emb.bits_for_next, emb.mtp_at_tip,
                emb.address_version, emb.address_p2sh_version,
                emb.curtime ? emb.curtime
                            : static_cast<uint32_t>(std::time(nullptr)),
                emb.version ? emb.version : 0x20000000u);
        },
        dashd_fallback);
}

} // namespace coin
} // namespace dash
