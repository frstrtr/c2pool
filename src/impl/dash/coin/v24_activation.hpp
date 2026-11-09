// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The Dash Core v24 switch for the engines that fold MINED blocks: the
/// payee projection (MnStateMachine) and the root-checked replay folds
/// (DmlFoldEngine). Each needs to know, for every block it folds, whether
/// DEPLOYMENT_V24 is active for it (Core DeploymentActiveAfter(pindexPrev,
/// V24)).
///
/// The block says so itself. Dash Core requires CbTx version 4 exactly when
/// V24 (and V20) is active for the block (CheckCbTx, bad-cbtx-version), so
/// every block from V20 on states the switch, and v24 starts long after V20
/// on every network. That statement decides how the block is folded
/// (v24_block_switch). It is never "learned" into an activation height: a
/// block on a branch that is reorged away, or one dashd rejects, cannot
/// move the switch of any other block.
///
///   * A block whose CbTx version Dash Core rejects (CheckCbTx,
///     bad-cbtx-version: version 0 or 5+, below 3 from V20 on, 3+ before V20,
///     and 4 below the earliest height v24 can be active on its network,
///     v24_earliest_unmeasured_activation) is refused by the engines before
///     any mutation.
///   * The activation height the deployment tracking derives
///     (V24ActivationWire, v24_activation_wire.hpp) is a cross-check: a block
///     that disagrees with it is folded as it states (it is the chain), and
///     the disagreement is logged and counted. A wrong height can therefore
///     never stall a fold; the tracking's own CbTx cross-check latches on the
///     same disagreement and the wire withdraws the height.
///   * A block that states nothing (no CbTx version 3+, i.e. before V20)
///     follows the pushed height, unknown meaning inactive.

#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

namespace dash {
namespace coin {

/// "No activation height known" in the engines (never active by height).
inline constexpr uint32_t kV24HeightUnknown = std::numeric_limits<uint32_t>::max();

/// The CbTx version a block states, or nullopt when its coinbase carries no
/// parseable CbTx (before DIP-3).
template <typename Block>
std::optional<uint16_t> block_cbtx_version(const Block& block)
{
    if (block.m_txs.empty() || block.m_txs[0].type != 5) return std::nullopt;
    vendor::CCbTx cb;
    if (!vendor::parse_cbtx(block.m_txs[0].extra_payload, cb)) return std::nullopt;
    return cb.nVersion;
}

/// Why `height` cannot be the v24 activation height on `net`, or nullopt.
/// The buried height where the network has one; otherwise the first block of
/// a versionbits period, not below the earliest possible activation.
inline std::optional<std::string> v24_activation_height_refusal(DashNetwork net, uint32_t height)
{
    const auto& p = dash_deployment_params(net);
    if (p.v24_buried_height) {
        if (height == *p.v24_buried_height) return std::nullopt;
        return "not the buried activation height " + std::to_string(*p.v24_buried_height);
    }
    const int64_t period = vb_period(p, p.dep(DashDeployment::V24));
    if (height == 0 || height == kV24HeightUnknown) return std::string("not a height");
    if (period <= 0 || height % period != 0)
        return "not the first block of a " + std::to_string(period) + "-block period";
    const uint32_t earliest = std::max<uint32_t>(v24_earliest_unmeasured_activation(net),
                                                 static_cast<uint32_t>(2 * period));
    if (height < earliest) return "below the earliest possible activation " + std::to_string(earliest);
    return std::nullopt;
}

/// The v24 switch of one mined block (see the file comment).
struct V24BlockSwitch
{
    bool active{false};
    /// dashd rejects this block (CbTx version 4 where v24 cannot be active).
    std::optional<std::string> invalid;
    /// The pushed activation height and the block's statement disagree. The
    /// block is folded as it states; this is for the log and the counters.
    std::optional<std::string> contradiction;
};

/// CheckCbTx's version rules that do not need the v24 state: the version is
/// one Core knows (1..4), at least 3 from V20 on and below 3 before it.
/// `v20_height` 0: the V20 rules are not checked (not known here).
inline std::optional<std::string> cbtx_version_refusal(uint32_t height, std::optional<uint16_t> cbtx_version,
                                                       uint32_t v20_height)
{
    if (!cbtx_version) {
        if (v20_height != 0 && height >= v20_height)
            return "bad-cbtx-version: the block at h=" + std::to_string(height) + " carries no CbTx after V20";
        return std::nullopt;
    }
    const uint16_t v = *cbtx_version;
    if (v == 0 || v > vendor::CCbTx::VERSION_MERKLE_ROOT_ASSETUNLOCKS)
        return "bad-cbtx-version: CbTx version " + std::to_string(v) + " at h=" + std::to_string(height)
             + " is not one Dash Core knows";
    if (v20_height != 0) {
        const bool v20 = height >= v20_height;
        if (v20 && v < vendor::CCbTx::VERSION_CLSIG_AND_BALANCE)
            return "bad-cbtx-version: CbTx version " + std::to_string(v) + " at h=" + std::to_string(height)
                 + " after V20 (" + std::to_string(v20_height) + ")";
        if (!v20 && v >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE)
            return "bad-cbtx-version: CbTx version " + std::to_string(v) + " at h=" + std::to_string(height)
                 + " before V20 (" + std::to_string(v20_height) + ")";
    }
    return std::nullopt;
}

/// `earliest`: the earliest height v24 can be active on the network
/// (v24_earliest_unmeasured_activation); `v20_height`: the network's V20
/// height. 0: that bound is not checked.
inline V24BlockSwitch v24_block_switch(uint32_t height, uint32_t activation_height,
                                       std::optional<uint16_t> cbtx_version, uint32_t earliest = 0,
                                       uint32_t v20_height = 0)
{
    V24BlockSwitch s;
    if (auto why = cbtx_version_refusal(height, cbtx_version, v20_height)) {
        s.invalid = std::move(why);
        return s;
    }
    const bool states = cbtx_version && *cbtx_version >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    const bool stated = states && *cbtx_version >= vendor::CCbTx::VERSION_MERKLE_ROOT_ASSETUNLOCKS;
    const bool known = activation_height != kV24HeightUnknown;
    const bool by_height = known && height >= activation_height;
    s.active = states ? stated : by_height;
    if (stated && earliest != 0 && height < earliest)
        s.invalid = "bad-cbtx-version: the block at h=" + std::to_string(height) + " states v24 (CbTx version "
                  + std::to_string(*cbtx_version) + ") below the earliest possible activation "
                  + std::to_string(earliest);
    if (states && known && stated != by_height)
        s.contradiction = "Dash Core v24 switch at h=" + std::to_string(height) + ": the tracked activation height "
                        + std::to_string(activation_height) + " says " + (by_height ? "active" : "inactive")
                        + " but the block's CbTx is version " + std::to_string(*cbtx_version)
                        + " (folded as the block states)";
    return s;
}

} // namespace coin
} // namespace dash
