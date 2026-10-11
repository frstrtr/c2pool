// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_follow_only.hpp
// --follow-only, the configuration side (pure functions of XmrNodeConfig):
//   apply_follow_only     under --follow-only: arm order p2p-first, template
//                         source native, no_daemon_rpc
//   follow_only_refusal   one fixed text per refused input, in this order:
//                         the mainnet fence; the pool identity; the pool start
//                         and pool policy flags; mining and serving; the Path B
//                         relay; monerod; the evidence inputs
//   run_plan_of           the parts the daemon constructs, both modes
//   follow_only_dir       <data>/<network>/follow_only/<G hex>, and the
//                         RowWeights table path in it
//   removed_flag_refusal  "<flag>: removed at the S4w flag day"
// The given-flag queries the mode refusals share (flag_given, the stratum,
// mining and relay families).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "c2pool/v37/xmr/xmr_node_config.hpp"

namespace c2pool::v37n::xmr::pathb_mode {

// ---------------------------------------------------------------------------
// Flags and fixed texts
// ---------------------------------------------------------------------------
inline constexpr std::string_view kFollowOnlyFlag = "--follow-only";
inline constexpr std::string_view kWarmTimeoutFlag = "--native-txpool-warm-timeout-ms";
inline constexpr std::string_view kMainnetFenceText = "mainnet requires --i-understand-mainnet (prototype safety)";
inline constexpr std::string_view kRemovedAtFlagDay = "removed at the S4w flag day";
inline constexpr std::string_view kFollowOnlyRefuses = "--follow-only refuses ";

inline constexpr std::string_view kStratumPrefix = "--stratum-";
inline constexpr std::string_view kMineFlag = "--mine";
inline constexpr std::string_view kMinePrefix = "--mine-";
inline constexpr std::string_view kRelayPrefix = "--relay-";
inline constexpr std::string_view kNoRelayPrefix = "--no-relay-";
inline constexpr std::string_view kRelayListenFlag = "--relay-listen";
inline constexpr std::string_view kRelayPeerFlag = "--relay-peer";
inline constexpr std::string_view kNativeInjectPrefix = "--native-inject";

// The pool identity inputs.
inline constexpr std::array<std::string_view, 3> kPoolIdentityFlags = {
        "--pool-genesis-from",
        "--pool-genesis",
        "--pool-genesis-height",
};

// The pool start, pool policy and rig flags refused under --follow-only
// (--pathb-penalty-fill is allowed).
inline constexpr std::array<std::string_view, 16> kFollowOnlyPoolFlags = {
        "--pathb-launch",
        "--vote",
        "--journal-depth",
        "--pathb-body-keep",
        "--pathb-header-keep",
        "--pathb-side-keep",
        "--pathb-key-cache-mb",
        "--pathb-abandon-timeout",
        "--pathb-waiting-cap",
        "--pathb-bucket-serve-cap",
        "--pathb-claim-alarm-rate",
        "--pathb-bucket-frame",
        "--join-min-peers",
        "--pathb-bucket-inflight",
        "--pathb-bucket-rate",
        "--pathb-deployments",
};

// Payout inputs without a configuration field (--payout-address has one).
inline constexpr std::array<std::string_view, 3> kFollowOnlyPayoutFlags = {
        "--give-author-pct",
        "--node-owner-fee-pct",
        "--node-owner-address",
};

// Monerod inputs refused at any value, without a configuration field
// (--native-parity-monerod has one).
inline constexpr std::array<std::string_view, 4> kFollowOnlyMonerodFlags = {
        "--native-template-fallback",
        "--rpc-host",
        "--rpc-port",
        "--zmq-port",
};

inline std::string removed_flag_refusal(std::string_view flag) {
    return std::string(flag) + ": " + std::string(kRemovedAtFlagDay);
}

// ---------------------------------------------------------------------------
// Given-flag queries
// ---------------------------------------------------------------------------
inline bool flag_given(const XmrNodeConfig& c, std::string_view name) {
    for (const GivenFlag& f : c.given_flags)
        if (f.name == name) return true;
    return false;
}

// The value of the last occurrence of `name`.
inline std::optional<std::string> flag_value(const XmrNodeConfig& c, std::string_view name) {
    std::optional<std::string> v;
    for (const GivenFlag& f : c.given_flags)
        if (f.name == name) v = f.value;
    return v;
}

inline bool starts_with(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.substr(0, p.size()) == p; }

inline bool is_stratum_input(std::string_view name) { return starts_with(name, kStratumPrefix); }
inline bool is_mine_input(std::string_view name) { return name == kMineFlag || starts_with(name, kMinePrefix); }
inline bool is_relay_input(std::string_view name) {
    return starts_with(name, kRelayPrefix) || starts_with(name, kNoRelayPrefix);
}

template <class Pred>
inline std::optional<std::string> first_given(const XmrNodeConfig& c, Pred&& pred) {
    for (const GivenFlag& f : c.given_flags)
        if (pred(std::string_view(f.name))) return f.name;
    return std::nullopt;
}

// The first stratum input given.
inline std::optional<std::string> stratum_input(const XmrNodeConfig& c) { return first_given(c, is_stratum_input); }

// The first mining input given (--mine, --mine-*), or --mine as a field.
inline std::optional<std::string> mine_input(const XmrNodeConfig& c) {
    if (std::optional<std::string> f = first_given(c, is_mine_input)) return f;
    if (c.mine_enabled) return std::string(kMineFlag);
    return std::nullopt;
}

// The first Path B relay input given (--relay-*, --no-relay-*), or the relay
// fields.
inline std::optional<std::string> relay_input(const XmrNodeConfig& c) {
    if (std::optional<std::string> f = first_given(c, is_relay_input)) return f;
    if (!c.relay_listen.empty()) return std::string(kRelayListenFlag);
    if (!c.relay_peers.empty()) return std::string(kRelayPeerFlag);
    return std::nullopt;
}

// The first --native-inject* input given, or the inject fields.
inline std::optional<std::string> native_inject_input(const XmrNodeConfig& c) {
    if (std::optional<std::string> f = first_given(c, [](std::string_view n) { return starts_with(n, kNativeInjectPrefix); }))
        return f;
    if (c.native_inject || !c.native_inject_dir.empty() || !c.native_inject_hex.empty()) return std::string(kNativeInjectPrefix);
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// The mainnet fence (master's text)
// ---------------------------------------------------------------------------
inline std::string mainnet_fence_refusal(const XmrNodeConfig& c) {
    if (c.network == MoneroNetwork::Mainnet && !c.i_understand_mainnet) return std::string(kMainnetFenceText);
    return {};
}

// ---------------------------------------------------------------------------
// The entry effects
// ---------------------------------------------------------------------------
inline void apply_follow_only(XmrNodeConfig& c) {
    if (!c.follow_only) return;
    c.arm_order = ArmOrderMode::P2PFirst;
    c.template_source = TemplateSourceMode::Native;
    c.no_daemon_rpc = true;
}

// ---------------------------------------------------------------------------
// follow_only_refusal
// ---------------------------------------------------------------------------
namespace fo_detail {
inline std::string refused(std::string_view input) { return std::string(kFollowOnlyRefuses) + std::string(input); }

template <std::size_t N>
inline std::optional<std::string_view> first_listed(const XmrNodeConfig& c, const std::array<std::string_view, N>& list) {
    for (std::string_view f : list)
        if (flag_given(c, f)) return f;
    return std::nullopt;
}
}  // namespace fo_detail

inline std::string follow_only_refusal(const XmrNodeConfig& c) {
    using fo_detail::first_listed;
    using fo_detail::refused;
    if (!c.follow_only) return {};
    // the mainnet fence
    if (std::string r = mainnet_fence_refusal(c); !r.empty()) return r;
    // the pool identity
    if (const auto f = first_listed(c, kPoolIdentityFlags)) return refused(*f);
    // the pool start and the pool policy
    if (const auto f = first_listed(c, kFollowOnlyPoolFlags)) return refused(*f);
    // mining and serving
    if (const auto f = mine_input(c)) return refused(*f);
    if (const auto f = stratum_input(c)) return refused(*f);
    if (flag_given(c, "--payout-address") || !c.payout_address.empty()) return refused("--payout-address");
    if (const auto f = first_listed(c, kFollowOnlyPayoutFlags)) return refused(*f);
    // the Path B relay
    if (const auto f = relay_input(c)) return refused(*f);
    // monerod
    if (flag_given(c, "--native-parity-monerod") || c.native_parity_monerod) return refused("--native-parity-monerod");
    if (flag_value(c, "--xmr-template-source") == std::optional<std::string>("monerod"))
        return refused("--xmr-template-source monerod");
    if (flag_value(c, "--arm-order") == std::optional<std::string>("daemon-first")) return refused("--arm-order daemon-first");
    if (const auto f = first_listed(c, kFollowOnlyMonerodFlags)) return refused(*f);
    if (flag_given(c, "--coinbase")) return removed_flag_refusal("--coinbase");
    // the evidence inputs
    if (flag_given(c, "--native-solo") || c.native_solo) return refused("--native-solo");
    if (flag_given(c, "--native-force-synced") || c.native_force_synced) return refused("--native-force-synced");
    if (flag_given(c, "--native-allow-unverified-pow") || c.native_allow_unverified_pow)
        return refused("--native-allow-unverified-pow");
    if (flag_given(c, "--no-good-citizen") || c.no_good_citizen) return refused("--no-good-citizen");
    if (const auto f = native_inject_input(c)) return refused(*f);
    if (c.native_txpool_warm_timeout_ms == 0) return refused(std::string(kWarmTimeoutFlag) + " 0");
    return {};
}

// ---------------------------------------------------------------------------
// run_plan_of
// ---------------------------------------------------------------------------
struct RunPlan {
    // both modes
    bool native_node = false;        // the native Monero node: follower, chain index, tx pool, warm latch
    bool follower_adapter = false;   // RowWeights per connected row, weights_at
    bool status_function = false;    // the shared status lines
    // --follow-only
    bool follow_template = false;    // the template record routine
    bool serve_follow_only = false;
    // the pool
    bool serve_pathb = false;
    bool pathb_node = false;
    bool carrier_tree = false;
    bool bin_store = false;
    bool activation_record = false;
    bool store = false;              // the store archive and its pathb_db directory
    bool joiner = false;
    bool relay_node = false;         // the Path B relay and HELLO
    bool stratum_listener = false;
    bool job_binder = false;
    bool miner = false;              // --mine
    bool publisher = false;          // the block publisher
    bool monerod_transport = false;
};

inline RunPlan run_plan_of(const XmrNodeConfig& c) {
    RunPlan p;
    p.native_node = true;
    p.follower_adapter = true;
    p.status_function = true;
    if (c.follow_only) {
        p.follow_template = true;
        p.serve_follow_only = true;
        return p;
    }
    p.serve_pathb = true;
    p.pathb_node = true;
    p.carrier_tree = true;
    p.bin_store = true;
    p.activation_record = true;
    p.store = true;
    p.joiner = true;
    p.relay_node = true;
    p.stratum_listener = true;
    p.job_binder = true;
    p.miner = c.mine_enabled;
    p.publisher = true;
    p.monerod_transport = true;
    return p;
}

// ---------------------------------------------------------------------------
// The follow-only directory, keyed by network and the compiled G
// ---------------------------------------------------------------------------
inline constexpr std::string_view kFollowOnlyDirName = "follow_only";
inline constexpr std::string_view kRowWeightsFileName = "row_weights";

inline std::string follow_only_dir(const std::string& data_dir, MoneroNetwork net, const std::array<std::uint8_t, 32>& g) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(2 * g.size());
    for (const std::uint8_t b : g) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0f]);
    }
    return data_dir + "/" + net_dir(net) + "/" + std::string(kFollowOnlyDirName) + "/" + hex;
}

inline std::string follow_only_row_weights_path(const std::string& dir) { return dir + "/" + std::string(kRowWeightsFileName); }

}  // namespace c2pool::v37n::xmr::pathb_mode
