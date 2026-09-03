// SPDX-License-Identifier: AGPL-3.0-or-later
//
// sharechain_window_report.hpp — the /sharechain/window dashboard REPORTING
// transform for the bip110 sharechain lane (M3).
//
// Problem it fixes: on a live bip110 node with a full PPLNS window, GET
// /sharechain/window served the stub {shares:[]} (web_server.cpp
// rest_sharechain_window returns the stub when MiningInterface::
// m_sharechain_window_fn is unwired). That left the sharechain-transparency
// EXPLORER empty AND the "Current Payouts" card's V36? column blank — the
// column is filled entirely client-side by getMinerVersion(addr) scanning
// defrag.shares (= this window) for s.m === addr (dashboard.html). bip110 never
// installed the seam; DASH/BTC/LTC do.
//
// The transform walks the SAME tallest-chain PPLNS window ShareTracker feeds
// the coinbase + /current_payouts from — it is a READ-ONLY snapshot of the
// window the node already holds. It never touches share_check gentx,
// build_connection_coinbase, the donation consensus, or any reward path. The
// transform lives here (not inline in main) so the KAT drives the EXACT code
// the dashboard runs — same pattern as current_payouts_report.hpp.
//
// Field shape mirrors the BTC producer (main_btc.cpp set_sharechain_window_fn)
// with TWO deliberate bip110 corrections vs BTC:
//   (a) s["m"] is the base58 ADDRESS (via current_payouts_script_to_address),
//       NOT the raw script hex BTC emits — so getMinerVersion's s.m === addr
//       matches the /current_payouts keys (which ARE addresses) and the V36?
//       column fills. Script-hex is kept only as a last-resort fallback.
//   (b) s["V"] carries the share version (36 for MergedMiningShare) — BTC omits
//       it; getMinerVersion tallies s.V, so without it the column reads 0.

#pragma once

#include "share_tracker.hpp"                 // bip110::pool::ShareTracker
#include "share_check.hpp"                    // bip110::pool::get_share_script
#include "current_payouts_report.hpp"         // current_payouts_script_to_address
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h>       // HexStr (script-hex fallback for s.m / my_address)

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace bip110::pool
{

// Build the /sharechain/window JSON for the explorer + V36? column. `best_share`
// is the LOCK-FREE published snapshot best — read by the caller BEFORE taking
// the tracker read guard (nested shared-lock hazard). `window_size` is the
// PPLNS window length; `my_address` / `fee_hash160` are display markers.
//
// Empty when the chain has no best share — rendered honestly, NEVER faked.
inline nlohmann::json sharechain_window_report(
    ShareTracker& tracker, const uint256& best_share,
    std::uint32_t window_size,
    const std::string& my_address, const std::string& fee_hash160,
    bool testnet)
{
    nlohmann::json result = nlohmann::json::object();
    auto& chain    = tracker.chain;
    auto& verified = tracker.verified;

    result["best_hash"]    = best_share.IsNull() ? "" : best_share.GetHex();
    result["chain_length"] = static_cast<int>(chain.size());
    result["window_size"]  = static_cast<int>(window_size);
    result["my_address"]   = my_address;
    result["fee_hash160"]  = fee_hash160;

    nlohmann::json shares_arr = nlohmann::json::array();
    if (!best_share.IsNull()) {
        int height = chain.get_height(best_share);
        int walk = std::min(height, static_cast<int>(window_size));
        if (walk > 0) {
            try {
                int pos = 0;
                auto view = chain.get_chain(best_share, static_cast<uint64_t>(walk));
                for (auto [hash, data] : view) {
                    nlohmann::json s;
                    s["h"] = hash.GetHex().substr(0, 16);
                    s["H"] = hash.GetHex();
                    s["p"] = pos++;
                    s["v"] = verified.contains(hash) ? 1 : 0;
                    auto* idx = chain.get_index(hash);
                    if (idx && idx->is_block_solution) s["blk"] = 1;
                    data.share.invoke([&](auto* obj) {
                        s["t"]  = obj->m_timestamp;
                        s["b"]  = obj->m_bits;
                        s["a"]  = obj->m_absheight;
                        s["dv"] = obj->m_desired_version;
                        // (b) native share version — BTC omits this; the V36?
                        // column tallies s.V.
                        s["V"]  = static_cast<int>(obj->version);
                        // (a) ADDRESS form so s.m === addr matches the
                        // /current_payouts keys; raw script hex only as fallback.
                        auto script = get_share_script(obj);
                        std::string addr =
                            current_payouts_script_to_address(script, testnet);
                        if (addr.empty())
                            addr = HexStr(script);
                        s["m"] = addr;
                    });
                    shares_arr.push_back(std::move(s));
                }
            } catch (const std::exception&) {
                // Partial/failed walk -> serve what we have (honest), never fake.
            }
        }
    }
    int total_n = static_cast<int>(shares_arr.size());
    result["shares"] = std::move(shares_arr);
    result["total"]  = total_n;
    return result;
}

} // namespace bip110::pool
