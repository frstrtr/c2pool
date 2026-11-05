// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// S4: the best ChainLock the node adopted, as JSON, for the daemonless
/// getblockchaininfo (main_dash's coin-chain-query hook) — the shape of
/// dashd's getbestchainlock {blockhash, height, known_block}, plus how the
/// lock was justified (provenance). The signature is not carried: it stays
/// NodeCoinState-confined and no caller needs it.
///
/// Read-only: it renders core::obs::best_chainlock()'s snapshot and asks the
/// header chain (a hash-at-height lookup, mutex-guarded in HeaderChain)
/// whether that block is on the chain we hold. chain_rpc.hpp stays
/// header-chain-only and untouched; the augmentation lives here so a KAT can
/// pin it without a running node.

#include <core/inject_ledger_obs.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>

namespace dash {
namespace coin {

/// The current chain's block hash at a height (nullopt = not held).
using ChainHashAtHeightFn = std::function<std::optional<uint256>(uint32_t)>;

/// {height, blockhash, provenance, updated_at, known_block}; null when no
/// ChainLock was ever published. blockhash is null when the adoption did not
/// name a hash (a chain-committed cbTx carries only the height and no height
/// index was wired); known_block is then null too, never a guess. Otherwise
/// known_block says whether the chain we hold has that block at that height.
inline nlohmann::json best_chainlock_json(const std::optional<::core::obs::BestChainLock>& cl,
                                          const ChainHashAtHeightFn& hash_at_height)
{
    if (!cl) return nullptr;
    nlohmann::json j;
    j["height"]     = cl->height;
    j["provenance"] = cl->provenance;
    j["updated_at"] = cl->updated_at;
    if (cl->blockhash.IsNull()) {
        j["blockhash"]   = nullptr;
        j["known_block"] = nullptr;
        return j;
    }
    j["blockhash"] = cl->blockhash.GetHex();
    if (!hash_at_height || cl->height <= 0) {
        j["known_block"] = nullptr;
        return j;
    }
    const auto h = hash_at_height(static_cast<uint32_t>(cl->height));
    j["known_block"] = h.has_value() && *h == cl->blockhash;
    return j;
}

/// Add the best ChainLock to a getblockchaininfo result object: under
/// "bestchainlock" when one was published, else as a named absence under
/// "unavailable" (chain_rpc's convention: never a zero, never a silent omit).
/// A non-object result (a refusal) is left as it is.
inline void add_best_chainlock(nlohmann::json& getblockchaininfo_result,
                               const std::optional<::core::obs::BestChainLock>& cl,
                               const ChainHashAtHeightFn& hash_at_height)
{
    if (!getblockchaininfo_result.is_object()) return;
    if (cl) {
        getblockchaininfo_result["bestchainlock"] = best_chainlock_json(cl, hash_at_height);
        return;
    }
    auto& un = getblockchaininfo_result["unavailable"];
    if (!un.is_object()) un = nlohmann::json::object();
    un["bestchainlock"] = "no ChainLock adopted yet (verified clsig or chain-committed cbTx)";
}

} // namespace coin
} // namespace dash
