// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_startup.hpp
// Path B start-up refusals, in this order (E1):
//   1  the configured sum: node-owner fee + give-author <= 10000 bp
//   2  --journal-depth below J_0 = 1,152
//   3  merge_configured_deployments (--pathb-deployments; test networks)
//   4  deployment_table_valid (its first check is K30's W_R <= 4, on every
//      network, regtest included)
//   5  lane_rules_valid
//   6  check_relay_buffers
//   7  the pool identity: the headline, the raw form on mainnet, a raw form
//      without its height
//   8  the block hash at H on the node's own chain (genesis_chain_refusal)
// then the store (pathb_load; an empty store starts from position 0; a load
// failure takes the joiner path), which the caller runs.
// The Path B policy flags not named by their own modules.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_joiner.hpp"
#include "impl/xmr/pathb/pathb_pool_identity.hpp"
#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"

namespace c2pool::xmr::pathb {

// P-51 (policy; Appendix P P-51 as corrected): the serving retention of a
// join, from join_serve_floors; none below the node's own horizon.
inline constexpr std::string_view kBodyKeepFlag = "--pathb-body-keep";
inline constexpr std::string_view kHeaderKeepFlag = "--pathb-header-keep";
inline constexpr std::string_view kSideKeepFlag = "--pathb-side-keep";
// Kind-2 descriptors (test networks only).
inline constexpr std::string_view kDeploymentsFlag = "--pathb-deployments";

enum class StartupStep : std::uint8_t {
    Ok = 0,
    FeeSum = 1,
    JournalDepth = 2,
    Deployments = 3,
    DeploymentTable = 4,
    LaneRules = 5,
    RelayBuffers = 6,
    Identity = 7,
    GenesisChain = 8,
};

struct StartupInputs {
    LaneNet net = LaneNet::Regtest;
    std::uint32_t chain_id = 0;
    std::uint32_t owner_fee_bp = 0;    // --node-owner-fee-pct
    std::uint32_t give_author_bp = 0;  // --give-author-pct
    std::uint64_t journal_depth = 0;   // --journal-depth (P-01)
    LaneParams p = kRuledLaneParams;
    RatchetParams rp = kRuledRatchetParams;
    EpochTable T;                         // the compiled table
    std::vector<Deployment> deployments;  // --pathb-deployments FILE (empty: none)
    std::uint8_t hf = 16;                 // the follower view's hf and Z_lt
    std::uint64_t z_lt_view = 0;
    RelayBuffers buffers{};                         // P-10, P-11 as configured
    std::optional<std::string> genesis_from;        // --pool-genesis-from
    RawStartInputs raw;                             // --pool-genesis / --pool-genesis-height
    std::function<std::optional<Hash32>(std::uint64_t)> hash_at;  // the follower's block id at a height
    std::uint64_t monero_tip = 0;
};

struct StartupResult {
    StartupStep refused = StartupStep::Ok;
    std::string why;
    EpochTable T;           // the merged table
    PoolIdentity identity;  // when ok
    bool raw_warning = false;  // print kRawGenesisWarning (testnet / stagenet raw form)

    bool ok() const noexcept { return refused == StartupStep::Ok; }
};

inline StartupResult startup_checks(const StartupInputs& in) {
    StartupResult out;
    const auto refuse = [&](StartupStep s, std::string why) {
        out.refused = s;
        out.why = std::move(why);
        return out;
    };
    // 1
    if (in.owner_fee_bp + in.give_author_bp > 10000u)
        return refuse(StartupStep::FeeSum, "--node-owner-fee-pct + --give-author-pct = " +
                                                   std::to_string(in.owner_fee_bp + in.give_author_bp) +
                                                   " bp, above 10000 bp");
    // 2
    if (const std::optional<std::string> r = journal_depth_refusal(in.p, in.journal_depth))
        return refuse(StartupStep::JournalDepth, *r);
    // 3, 4, 5
    out.T = in.T;
    if (const StartupCheck c = merge_configured_deployments(in.net, out.T, in.deployments); !c.ok)
        return refuse(StartupStep::Deployments, c.why);
    if (const StartupCheck c = deployment_table_valid(in.rp, in.net, out.T); !c.ok)
        return refuse(StartupStep::DeploymentTable, c.why);
    if (const StartupCheck c = lane_rules_valid(in.net, out.T); !c.ok) return refuse(StartupStep::LaneRules, c.why);
    // 6
    switch (check_relay_buffers(in.hf, in.z_lt_view, in.p.r_max, in.buffers)) {
        case BufferCheck::Ok: break;
        case BufferCheck::ReceiptBelowMinimum: return refuse(StartupStep::RelayBuffers, "the receipt buffer is below the default");
        case BufferCheck::FrameBelowMinimum: return refuse(StartupStep::RelayBuffers, "the frame buffer is below the default");
        case BufferCheck::ViewOutOfDomain: return refuse(StartupStep::RelayBuffers, "the view's hf or Z_lt is out of the buffers' domain");
    }
    // 7: one form only
    if (in.genesis_from && (in.raw.pool_genesis || in.raw.pool_genesis_height))
        return refuse(StartupStep::Identity, "genesis: --pool-genesis-from with a raw genesis flag");
    if (in.genesis_from) {
        GenesisSpec g;
        if (std::string r = parse_genesis_from(*in.genesis_from, g); !r.empty())
            return refuse(StartupStep::Identity, r);  // the headline grammar first (parse_genesis_from runs it)
        // 8
        const std::optional<Hash32> at = in.hash_at ? in.hash_at(g.height) : std::nullopt;
        if (std::string r = genesis_chain_refusal(g, at, in.monero_tip); !r.empty())
            return refuse(StartupStep::GenesisChain, r);
        out.identity = identity_derived(in.net, in.chain_id, g);
        return out;
    }
    const RawIdentity ri = raw_identity_from(in.net, in.chain_id, in.raw);
    if (!ri.refusal.empty()) return refuse(StartupStep::Identity, ri.refusal);
    out.identity = ri.identity;
    out.raw_warning = in.net == LaneNet::Testnet || in.net == LaneNet::Stagenet;
    return out;
}

}  // namespace c2pool::xmr::pathb
