// SPDX-License-Identifier: AGPL-3.0-or-later
//
// current_payouts_report.hpp — the /current_payouts dashboard REPORTING transform
// for the bip110 sharechain lane (M3).
//
// Problem it fixes: on a live bip110 node with a full PPLNS window, GET
// /current_payouts returned {} and the dashboard "Current Payouts" card showed
// "0.0000 BIP110" over an empty ADDRESS / V36? / AMOUNT table. Root cause: the
// #939 direct seam (MiningInterface::set_current_payouts_fn) was wired ONLY by
// DASH; bip110 never installed it, and the two other sources feeding
// rest_current_payouts() are dead on this lane (MI stratum is off so refresh_work()
// never fills the PPLNS cache, and no PayoutManager is set). So the handler fell
// through all three and reported {} — see web_server.cpp:2408 rest_current_payouts.
//
// The fix wires the seam with the SAME PPLNS SSOT that mints the coinbase:
// ShareTracker::get_expected_payouts (share_tracker.hpp), i.e. the exact map the
// work_source pplns_fn_ (main_bip110.cpp) already emits into the minted coinbase.
// This is a READ-ONLY PREVIEW of the split the node WOULD pay on the next block —
// it never touches share_check gentx, build_connection_coinbase, the donation
// consensus, or any reward path. The transform lives here (not inline in main) so
// the KAT drives the EXACT code the dashboard runs.

#pragma once

#include "share_tracker.hpp"                 // bip110::pool::ShareTracker::get_expected_payouts
#include <core/address_utils.hpp>            // core::script_to_address
#include <core/uint256.hpp>

#include <btclibs/crypto/sha256.h>           // CSHA256   (P2PK -> P2PKH fallback)
#include <btclibs/crypto/ripemd160.h>        // CRIPEMD160 (Hash160)
#include <btclibs/util/strencodings.h>       // HexStr    (last-resort raw-script key)

#include <nlohmann/json.hpp>

#include <cstdint>
#include <exception>
#include <map>
#include <span>
#include <string>
#include <vector>

namespace bip110::pool
{

// Resolve a scriptPubKey to a bip110 (BITCOIN-encoding — bip110 forks BTC at
// 961640) address string, with the P2PK -> P2PKH Hash160 fallback for the
// canonical p2pool donation pubkey script. Mirrors the resolver +
// P2PK-fallback in MiningInterface::rest_current_payouts (web_server.cpp:
// 2426-2467) so the direct seam renders the same address strings the cache
// path would have.
inline std::string current_payouts_script_to_address(
    const std::vector<unsigned char>& script, bool testnet)
{
    std::string addr = core::script_to_address(script, /*is_litecoin=*/false, testnet);
    if (addr.empty() && script.size() > 33 && script.back() == 0xac) {
        // P2PK: PUSH<len> <pubkey> OP_CHECKSIG -> Hash160(pubkey) -> P2PKH address.
        std::size_t pk_len = script[0];
        if (pk_len + 1 == script.size() - 1) {
            unsigned char sha[32], rip[20];
            CSHA256().Write(&script[1], pk_len).Finalize(sha);
            CRIPEMD160().Write(sha, 32).Finalize(rip);
            std::vector<unsigned char> p2pkh = {0x76, 0xa9, 0x14};
            p2pkh.insert(p2pkh.end(), rip, rip + 20);
            p2pkh.push_back(0x88);
            p2pkh.push_back(0xac);
            addr = core::script_to_address(p2pkh, /*is_litecoin=*/false, testnet);
        }
    }
    return addr;
}

// Build the /current_payouts JSON object { address : coins } — the projected
// next-block PPLNS split across the ENTIRE decayed sharechain window, folding the
// donation residual into the canonical donation script's address. It is the exact
// split build_connection_coinbase's pplns_fn_ would mint, computed off the SAME
// ShareTracker::get_expected_payouts SSOT — integer-exact vs generate_share_
// transaction — so the card previews what the node WOULD pay without touching any
// consensus/reward/coinbase path.
//
// Contract (matches the DASH seam, web_server.cpp:2418): returns { addr : coins }
// (coins == satoshi / 1e8). Empty object when the chain has no best share or the
// window yields no outputs — rendered honestly, NEVER faked.
inline nlohmann::json current_payouts_report(
    ShareTracker& tracker, const uint256& best_share,
    const uint256& block_target, std::uint64_t subsidy,
    const std::vector<unsigned char>& donation_script, bool testnet)
{
    nlohmann::json out = nlohmann::json::object();
    if (best_share.IsNull())
        return out;

    std::map<std::vector<unsigned char>, double> pmap;
    try {
        pmap = tracker.get_expected_payouts(best_share, block_target, subsidy, donation_script);
    } catch (const std::exception&) {
        return nlohmann::json::object();   // tracker walk failed -> honest empty
    }

    for (const auto& [script, amount_sat] : pmap) {
        if (script.empty())
            continue;
        std::string addr = current_payouts_script_to_address(script, testnet);
        if (addr.empty())
            addr = HexStr(std::span<const unsigned char>(script.data(), script.size()));
        // p2pool seam contract returns coins (not satoshis), same as DASH.
        out[addr] = static_cast<double>(amount_sat) / 1e8;
    }
    return out;
}

} // namespace bip110::pool
