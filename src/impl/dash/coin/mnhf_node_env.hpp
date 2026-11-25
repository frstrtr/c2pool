// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The MnhfCheckEnv (mnhf_check.hpp) the running node gives its template
/// builder and emit gate: Dash Core's CheckMNHFTx inputs from the node's own
/// state. One factory for c2pool-dash and the KATs (test_dash_v24_alltx.cpp),
/// so the tests run the wiring the node runs.
///
///   * chain_height_of: the quorum block is a header of OUR main chain at or
///     below the parent (Core: LookupBlockIndex + chain.Contains, and the
///     signing quorum must be mined before the block being built). Unknown
///     once the node tears its header chain down (`alive` drops).
///   * quorum_public_key: the active quorum set (Core GetQuorum).
///   * verify_sig: the BLS recovered signature (CBLSSignature::VerifyInsecure).
///   * bit_staged: the EHF tracker's signals at the parent (Core
///     GetSignalsStage); unknown wherever the tracker does not cover the
///     parent with verified bodies, and then the signal stays out.

#include <impl/dash/coin/mnhf_check.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>   // verify_chainlock_sig
#include <impl/dash/coin/versionbits.hpp>         // kNoSignalHeight

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace dash {
namespace coin {

using MnhfQuorumKeyFn = std::function<std::optional<std::array<uint8_t, 48>>(uint8_t llmq_type, const uint256& quorum)>;

/// HeaderChain: get_header(hash) and get_header_by_height(height), each an
/// optional-like of an entry with .height and .hash. EhfTracker: covers(prev),
/// verified_coverage(), signal_height(bit, prev).
template <typename HeaderChain, typename EhfTracker>
MnhfCheckEnv make_node_mnhf_check_env(DashNetwork net, const HeaderChain* chain,
                                      std::shared_ptr<const EhfTracker> tracker,
                                      std::shared_ptr<const std::atomic<bool>> alive,
                                      MnhfQuorumKeyFn quorum_public_key)
{
    MnhfCheckEnv env;
    env.net = net;
    env.chain_height_of = [chain, alive](const uint256& h, uint32_t prev_height) -> std::optional<uint32_t> {
        if (!chain || !alive || !alive->load()) return std::nullopt;
        const auto e = chain->get_header(h);
        if (!e || e->height > prev_height) return std::nullopt;
        const auto main = chain->get_header_by_height(e->height);
        if (!main || main->hash != h) return std::nullopt;
        return static_cast<uint32_t>(e->height);
    };
    env.quorum_public_key = std::move(quorum_public_key);
    env.verify_sig = [](const std::array<uint8_t, 48>& pk, const uint256& h, const std::array<uint8_t, 96>& sig) {
        return vendor::verify_chainlock_sig(pk, h, sig);
    };
    env.bit_staged = [tracker](uint8_t bit, uint32_t prev) -> std::optional<bool> {
        if (!tracker || !tracker->covers(prev) || tracker->verified_coverage() < static_cast<int64_t>(prev))
            return std::nullopt;
        return tracker->signal_height(bit, prev) != kNoSignalHeight;
    };
    return env;
}

} // namespace coin
} // namespace dash
