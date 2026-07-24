// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin::submitblock_result_accepted -- shared classifier for a coin
// daemon's `submitblock` RPC result under the dual-path won-block contract.
//
// submitblock returns JSON null on ACCEPT; a non-null string is the reject
// reason. A "duplicate" / "inconclusive" / "already-have" result means the
// block is ALREADY on the network — the OTHER broadcast arm (our own P2P relay,
// or a peer that won the very race we are submitting into) landed it first.
// That is SUCCESS (the block reached the network), NOT a failure. The lone
// exception is a "duplicate-invalid" reason: the block was rejected as invalid,
// a genuine failure.
//
// Historically LTC/BTC/DGB NodeRPC::submit_block_hex classified with a bare
// `result.is_null()`, so a daemon "duplicate" (the common dual-path / race
// outcome) surfaced as FALSE and a WON block was reported as a reject through
// the shared web_server submit seam. This predicate lifts them onto the same
// contract BCH and DASH already implement. Pure over the JSON so a KAT can pin
// it without a live RPC client.
// ---------------------------------------------------------------------------

#include <string>

#include <nlohmann/json.hpp>

namespace core::coin {

inline bool submitblock_result_accepted(const nlohmann::json& result)
{
    if (result.is_null()) return true;      // canonical accept
    if (!result.is_string()) return false;  // unexpected shape — treat as reject
    std::string code = result.get<std::string>();
    for (char& c : code)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    const bool already_have = code == "duplicate"
                           || code.find("inconclusive") != std::string::npos
                           || code.find("already") != std::string::npos;
    return already_have && code.find("invalid") == std::string::npos;
}

} // namespace core::coin
