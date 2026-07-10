// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::coin -- launcher-slice-3 RPC request-shape SSOT (pure, dependency-light).
//
// Single source of truth for the oracle-pinned external-RPC contract values
// that NodeRPC::check()/getwork() depend on, factored out of rpc.cpp so a
// standalone test TU can guard them WITHOUT linking the boost::beast /
// jsonrpccxx transport (i.e. without building the dash coin transport TU):
//
//   1. DASH_MIN_DAEMON_VERSION -- the getnetworkinfo["version"] accept floor,
//      conformed to the DASH oracle frstrtr/p2pool-dash (older-than-v35
//      baseline -> dashd v0.17 line, protocol/version family). DASH p2pool
//      runs against Dash Core's DIP3/DIP4-capable daemons; the floor pins the
//      minimum that returns the masternode/superblock/coinbase_payload GBT
//      fields getwork() consumes.
//   2. make_gbt_request() -- DASH getblocktemplate body. THIS IS THE KEY
//      DASH<->DGB DIVERGENCE: DASH is X11 and has NO segwit, so the body does
//      NOT carry DGB's {"algo":"scrypt"} param and does NOT inject a "segwit"
//      rule. dashd getblocktemplate is called with the plain rules array the
//      caller supplies (default {} -> base template carrying the masternode +
//      superblock payment fields and the DIP3/DIP4 coinbasevalue/payload).
//      Conforms to dashd getblocktemplate semantics + the p2pool-dash oracle
//      getwork() (older-than-v35), NOT a Bitcoin/DGB segwit template.
//   3. DASH chain-identity genesis hashes -- so check() can probe a real dashd
//      on the selected network. Pinned here (and mirrored from
//      coin/header_chain.hpp) as a bucket-1 ISOLATION PRIMITIVE: per-coin AND
//      per-net, never standardized cross-coin.
//
// Header-only + nlohmann-only: includes nothing from the transport stack, so
// the guard test is a clean standalone link.
// ---------------------------------------------------------------------------

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace dash
{

namespace coin
{

// Minimum acceptable dashd getnetworkinfo["version"] int. DASH p2pool conforms
// to its OWN older-than-v35 oracle (operator 2026-06-17 per-coin re-scope); the
// floor is Dash Core 0.17 (the first line returning the DIP3/DIP4 masternode +
// coinbase_payload GBT fields getwork() parses). 170000 == Dash Core 0.17.0.0.
inline constexpr int DASH_MIN_DAEMON_VERSION = 170000;

// True iff a daemon advertising getnetworkinfo["version"]==v clears the floor.
inline bool daemon_version_acceptable(int version)
{
    return DASH_MIN_DAEMON_VERSION <= version;
}

// Build the DASH getblocktemplate request body. DASH is X11 with NO segwit, so
// -- unlike DGB -- the body carries NO "algo" param and injects NO "segwit"
// rule: it is the plain {"rules": <caller rules>} dashd expects. The default
// (empty rules) yields dashd's base template, which already carries the
// masternode/superblock payment arrays and the DIP3/DIP4 coinbasevalue +
// coinbase_payload fields DashWorkData consumes. Conforms to dashd
// getblocktemplate + the p2pool-dash oracle getwork() (older-than-v35).
inline nlohmann::json make_gbt_request(const std::vector<std::string>& rules = {})
{
    return nlohmann::json::object({{"rules", rules}});
}

// DASH chain-identity genesis hashes (Dash Core chainparams.cpp; mirrored from
// src/impl/dash/coin/header_chain.hpp seed). NodeRPC::check() probes
// getblockheader(genesis) to confirm it is talking to a real dashd on the
// selected network (a wrong-coin daemon does not answer). Bucket-1 ISOLATION
// PRIMITIVE -- KEEP per-coin in v36 AND v37, never standardize; pinned in this
// SSOT only so a standalone TU can guard against accidental drift WITHOUT
// linking the boost::beast transport.
inline constexpr const char* DASH_GENESIS_MAIN =
    "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6";
inline constexpr const char* DASH_GENESIS_TEST =
    "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c";

// The genesis hash NodeRPC::check() probes for the selected network.
inline const char* dash_genesis_hash(bool testnet)
{
    return testnet ? DASH_GENESIS_TEST : DASH_GENESIS_MAIN;
}

} // namespace coin

} // namespace dash