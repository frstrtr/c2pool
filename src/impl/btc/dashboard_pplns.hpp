// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BTC dashboard PPLNS read-model — the pool-wide "Current Payouts".
//
// Answers ONE question: "what would a block found RIGHT NOW pay?" — the
// pool-wide PPLNS split over the window anchored on the node's current best
// share. This is the source for /current_payouts (the #939 direct seam),
// /current_merged_payouts (the main dashboard treemap, which wraps the primary
// payouts) and the window feeder's own `pplns_current` fallback.
//
// Why BTC could not simply reuse MiningInterface's own PPLNS cache
// ----------------------------------------------------------------
// The web MiningInterface's cache (rest_current_payouts's coinbase-builder
// branch, and start_pplns_precompute) only fills once refresh_work() has stored
// an m_cached_template carrying bits + coinbasevalue (web_server.cpp ~3137).
// The BTC dashboard stands up a NULL-IMiningNode web MI that never runs
// refresh_work() — a fully daemonless / zero-local-miner relay never pumps the
// template cache — so that path wires green and stays inert (admitted at
// main_btc.cpp §3). The same class of bug DASH documents in its own
// dashboard_pplns.hpp header. So the payouts are computed DIRECTLY from the
// sharechain the node already holds, exactly as the stratum coinbase would:
//   * ShareTracker::get_v35_expected_payouts / get_expected_payouts — the SAME
//     pure chain walk the mint uses at main_btc.cpp §"stratum coinbase" (the
//     v35 flat / v36 decayed PPLNS weight allocator). No payout arithmetic is
//     re-implemented here.
//
// Finder fee: the pre-v36 (v35) allocator returns amounts WITHOUT the
// subsidy/200 block-finder fee — "caller adds subsidy/200 to the share
// creator's script" (share_tracker.hpp get_v35_expected_payouts). A pool-wide
// view has no finder (the next block's winner is unknown), so the fee is simply
// left unallocated and the donation output absorbs the remainder — the same
// "finder fee omitted" contract the DASH pool-wide view documents. The v36
// allocator has no finder fee at all.
//
// This is DISPLAY-ONLY and READ-ONLY: it walks the sharechain under the
// caller's read guard, reads no mutable / verified state, sends no wire bytes,
// and builds no coinbase. Every empty / failed condition returns {} (an honest
// miss, never a fabricated row) — mirroring the p2pool get_expected_payouts
// empty guard (a missing best share) and the DASH view's empty semantics.

#include "share_tracker.hpp"        // btc::ShareTracker, get_{v35_,}expected_payouts
#include "config_pool.hpp"          // btc::PoolConfig::get_donation_script

#include <core/target_utils.hpp>    // chain::bits_to_target
#include <core/address_utils.hpp>   // core::classify_script
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h>  // HexStr

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace btc {
namespace dashboard {

// Pool-wide PPLNS split over the window anchored on `best`.
//
//   share_version : the live share version for `best` (AutoRatchet's answer);
//                   selects the v35 flat vs v36 decayed allocator + the
//                   matching donation script, exactly as the stratum coinbase.
//   block_bits    : COIN block nBits for the difficulty epoch the payout
//                   belongs to (GBT bits, or the header tip's bits on a
//                   zero-rig relay that never built work).
//   subsidy_sat   : full block reward the split is taken from (satoshi).
//
// Returns {address: amount in BTC} — the PPLNS workers plus the donation
// output. {} on null best / zero subsidy / zero bits / empty window / throw.
inline nlohmann::json pplns_payouts_current(
    btc::ShareTracker& tracker,
    const uint256& best,
    int share_version,
    uint32_t block_bits,
    uint64_t subsidy_sat,
    bool testnet)
{
    if (best.IsNull() || subsidy_sat == 0 || block_bits == 0)
        return nlohmann::json::object();

    const uint256 block_target = chain::bits_to_target(block_bits);
    const auto donation = btc::PoolConfig::get_donation_script(share_version);

    // The allocator's map value is the payout in SATOSHI (as double), exactly
    // as generate_share_transaction computes it; empty on a cold/too-short
    // window. Never re-implemented here — the mint's own function is called.
    std::map<std::vector<unsigned char>, double> raw;
    try {
        raw = (share_version < 36)
            ? tracker.get_v35_expected_payouts(best, block_target, subsidy_sat, donation)
            : tracker.get_expected_payouts(best, block_target, subsidy_sat, donation);
    } catch (const std::exception&) {
        return nlohmann::json::object();   // allocator threw — report nothing, not a guess
    }
    if (raw.empty())
        return nlohmann::json::object();

    nlohmann::json out = nlohmann::json::object();
    for (const auto& [script, amount_sat] : raw) {
        if (amount_sat <= 0.0) continue;
        // classify_script decodes P2PKH / P2SH / P2WPKH / P2WSH / P2TR AND the
        // v35 P2PK donation (hashed to a P2PKH address) — the same fold
        // web_server.cpp does by hand for the cached-outputs path. Undecodable
        // scripts fall back to raw hex so nothing is silently dropped.
        std::string addr;
        auto cls = core::classify_script(script, /*is_litecoin=*/false, testnet);
        if (!cls.addresses.empty())
            addr = cls.addresses.front();
        if (addr.empty())
            addr = HexStr(script);
        const double amount_btc = amount_sat / 1e8;
        if (out.contains(addr))
            out[addr] = out[addr].get<double>() + amount_btc;
        else
            out[addr] = amount_btc;
    }
    return out;
}

} // namespace dashboard
} // namespace btc
