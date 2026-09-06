// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCH dashboard PPLNS read-model — the pool-wide "Current Payouts".
//
// BCH-lane mirror of src/impl/btc/dashboard_pplns.hpp. Answers ONE question:
// "what would a block found RIGHT NOW pay?" — the pool-wide PPLNS split over
// the window anchored on the node's current best share. This is the source for
// /current_payouts and the window feeder's own `pplns_current` fallback on a
// BCH pool (LIVE on contabo :9349) that today ships NO current-payouts surface.
//
// Why BCH cannot simply reuse MiningInterface's own PPLNS cache
// ------------------------------------------------------------
// Same class of bug BTC/DASH document: the web MiningInterface cache only fills
// once refresh_work() has stored a template carrying bits + coinbasevalue. A
// fully daemonless / zero-local-miner relay never pumps that cache, so the path
// wires green and stays inert. So the payouts are computed DIRECTLY from the
// sharechain the node already holds, exactly as the stratum coinbase would:
//   * ShareTracker::get_v35_expected_payouts / get_expected_payouts — the SAME
//     pure chain walk the mint uses (v35 flat / v36 decayed PPLNS allocator).
//     No payout arithmetic is re-implemented here.
//
// Finder fee: the pre-v36 (v35) allocator returns amounts WITHOUT the
// subsidy/200 block-finder fee. A pool-wide view has no finder (the next
// block's winner is unknown), so the fee is left unallocated and the donation
// output absorbs the remainder. The v36 allocator has no finder fee at all.
//
// Address rendering: classify_script is driven with bitcoin (not litecoin)
// chain params, so worker/donation scripts render to BCH legacy base58
// ('1'.../'3'...) — identical to BTC. Native CashAddr display encoding is a
// core-touching follow-up (would add a coin-registered script->cashaddr
// encoder in src/core), deliberately OUT of this fenced src/impl/bch-only
// slice. Undecodable scripts fall back to raw hex so nothing is dropped.
//
// This is DISPLAY-ONLY and READ-ONLY: it walks the sharechain under the
// caller's read guard, reads no mutable / verified state, sends no wire bytes,
// and builds no coinbase. Every empty / failed condition returns {} (an honest
// miss, never a fabricated row).

#include "share_tracker.hpp"        // bch::ShareTracker, get_{v35_,}expected_payouts
#include "config_pool.hpp"          // bch::PoolConfig::get_donation_script

#include <core/target_utils.hpp>    // chain::bits_to_target
#include <core/address_utils.hpp>   // core::classify_script
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h>  // HexStr

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace bch {
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
// Returns {address: amount in BCH} — the PPLNS workers plus the donation
// output. {} on null best / zero subsidy / zero bits / empty window / throw.
inline nlohmann::json pplns_payouts_current(
    bch::ShareTracker& tracker,
    const uint256& best,
    int share_version,
    uint32_t block_bits,
    uint64_t subsidy_sat,
    bool testnet)
{
    if (best.IsNull() || subsidy_sat == 0 || block_bits == 0)
        return nlohmann::json::object();

    const uint256 block_target = chain::bits_to_target(block_bits);
    const auto donation = bch::PoolConfig::get_donation_script(share_version);

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
        // classify_script decodes P2PKH / P2SH AND the v35 P2PK donation
        // (hashed to a P2PKH address). BCH is not litecoin -> bitcoin params.
        // Undecodable scripts fall back to raw hex so nothing is silently
        // dropped.
        std::string addr;
        auto cls = core::classify_script(script, /*is_litecoin=*/false, testnet);
        if (!cls.addresses.empty())
            addr = cls.addresses.front();
        if (addr.empty())
            addr = HexStr(script);
        const double amount_bch = amount_sat / 1e8;
        if (out.contains(addr))
            out[addr] = out[addr].get<double>() + amount_bch;
        else
            out[addr] = amount_bch;
    }
    return out;
}

} // namespace dashboard
} // namespace bch
