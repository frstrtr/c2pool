#pragma once

// ---------------------------------------------------------------------------
// dgb::coin -- M3 RPC request-shape SSOT (pure, dependency-light).
//
// Single source of truth for the two oracle-pinned external-RPC contract
// values that NodeRPC::check()/getwork() depend on, factored out of rpc.cpp
// so a standalone test TU can guard them WITHOUT linking the boost::beast /
// jsonrpccxx transport (i.e. without entering the dgb OBJECT lib):
//
//   1. DGB_MIN_DAEMON_VERSION -- the getnetworkinfo["version"] accept floor,
//      conformed to oracle frstrtr/p2pool-dgb-scrypt networks/digibyte.py
//      VERSION_CHECK (82202 == DigiByte Core 7.17.2, oracle HEAD 22761e7).
//   2. make_gbt_request() -- DigiByte getblocktemplate body. DGB GBT requires
//      the "segwit" rule AND a SEPARATE top-level "algo" param; V36 is
//      Scrypt-only so algo is always "scrypt". "scrypt" is the mining
//      algorithm, NOT a BIP9 rule -- the prior Path-A stub note rules=
//      ["scrypt"] was wrong; the shape is {"rules":[...],"algo":"scrypt"}.
//
// Header-only + nlohmann-only: includes nothing from the transport stack, so
// it builds on master today and the guard test is a clean standalone link.
// ---------------------------------------------------------------------------

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace dgb
{

namespace coin
{

// Minimum acceptable digibyted getnetworkinfo["version"] int (oracle-equivalent
// to p2pool-dgb-scrypt VERSION_CHECK: floor 82202 == DigiByte Core 7.17.2).
inline constexpr int DGB_MIN_DAEMON_VERSION = 82202;

// True iff a daemon advertising getnetworkinfo["version"]==v clears the floor.
inline bool daemon_version_acceptable(int version)
{
    return DGB_MIN_DAEMON_VERSION <= version;
}

// Build the DigiByte getblocktemplate request body: segwit rule(s) plus the
// mandatory separate Scrypt algo param. V36 c2pool-dgb is Scrypt-only.
inline nlohmann::json make_gbt_request(const std::vector<std::string>& rules)
{
    return nlohmann::json::object({{"rules", rules}, {"algo", "scrypt"}});
}

} // namespace coin

} // namespace dgb
