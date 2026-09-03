// SPDX-License-Identifier: AGPL-3.0-or-later
//
// share_detail_report.hpp — the GET /web/share/<hash> per-share DETAIL document
// for the bip110 sharechain lane (M3), at DASH parity.
//
// Problem it fixes (live, contabo :8086): the bip110 /web/share handler emitted a
// REDUCED flat object — only the 12 keys
//   [absheight,bits,desired_version,hash,height,is_block_solution,
//    miner_address,miner_script,stale_info,timestamp,verified,version]
// MISSING parent/far_parent/type_name/children + local/share_data/block/pplns.
// share.html renderShare reads share.parent.substr(-8); on the reduced object
// share.parent is undefined -> TypeError -> renderShare aborts -> the individual
// share page hangs on "Loading". DASH's build_share_detail (dashboard_views.hpp)
// returns the RICH schema and its page renders. This transform gives bip110 the
// SAME rich document, sourced from the SAME sharechain node — every field is read
// off the tracked share (share.hpp) or the const PPLNS window walk the coinbase +
// /current_payouts already run; nothing is fabricated, unreachable fields are
// omitted honestly.
//
// The transform lives here (not inline in main) so the KAT binds the EXACT code
// the dashboard serves — same pattern as current_payouts_report.hpp /
// sharechain_window_report.hpp.
//
// READ-ONLY: const walks only (get_index / get_share / get_expected_payouts via
// current_payouts_report). It never touches share bytes, gentx, the coinbase,
// the donation consensus, the reward path, or any wire message. A failure here is
// a display-surface regression, never a consensus/reward one.

#pragma once

#include "share_tracker.hpp"                  // bip110::pool::ShareTracker
#include "share_check.hpp"                    // bip110::pool::get_share_script
#include "current_payouts_report.hpp"         // current_payouts_report (PPLNS SSOT)

#include <core/uint256.hpp>
#include <core/target_utils.hpp>              // chain::bits_to_target, target_to_difficulty
#include <core/address_utils.hpp>             // core::script_to_address

#include <btclibs/util/strencodings.h>        // HexStr

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace bip110::pool
{

// Build the RICH /web/share/<hash> document (DASH-parity). `donation_script` is
// the pool donation output the PPLNS window is projected against (identical to
// the /current_payouts seam: PoolConfig::get_donation_script(36)); `testnet`
// selects the address form. Returns {"error": ...} on a miss so core's
// rest_web_share() keeps its not-found fallback contract — same as DASH.
//
// The found-block enrichment (block_height/confirmations/status) stays in the
// caller: it reads MiningInterface::get_found_blocks(), a node surface this pure
// transform deliberately does not depend on.
inline nlohmann::json build_share_detail(
    ShareTracker& tracker, const std::string& hash_hex,
    const std::vector<unsigned char>& donation_script, bool testnet)
{
    auto& chain    = tracker.chain;
    auto& verified = tracker.verified;

    uint256 hash;
    hash.SetHex(hash_hex);
    if (hash.IsNull() || !chain.contains(hash))
        return nlohmann::json{{"error", "share not found"}};

    nlohmann::json result;

    auto* idx = chain.get_index(hash);
    const bool is_block = idx && idx->is_block_solution;
    result["is_block_solution"] = is_block;
    result["hash"]     = hash.GetHex();
    result["verified"] = verified.contains(hash);
    result["height"]   = chain.get_height(hash);

    // PPLNS anchor is captured inside the invoke (window is anchored on the
    // share's PARENT, with the share's OWN recorded subsidy/bits — exactly how
    // this share's gentx was minted) and computed after, still under the guard.
    uint256  pplns_parent;
    uint32_t pplns_bits    = 0;
    uint64_t pplns_subsidy = 0;

    chain.get_share(hash).invoke([&](auto* obj) {
        using ShareT = std::remove_pointer_t<decltype(obj)>;

        // ── back-compat flat keys (the reduced schema's 12) ──────────────────
        result["timestamp"]       = obj->m_timestamp;
        result["bits"]            = obj->m_bits;
        result["absheight"]       = obj->m_absheight;
        result["version"]         = static_cast<int>(ShareT::version);
        result["desired_version"] = obj->m_desired_version;
        result["stale_info"]      = static_cast<int>(obj->m_stale_info);

        const auto script = get_share_script(obj);
        const std::string addr = core::script_to_address(script, /*is_litecoin=*/false, testnet);
        result["miner_address"] = addr.empty() ? HexStr(script) : addr;
        result["miner_script"]  = HexStr(script);

        // ── DASH-parity rich fields (dashboard_views.hpp:345-407) ────────────
        result["parent"]     = obj->m_prev_hash.GetHex();
        result["far_parent"] = obj->m_far_share_hash.GetHex();
        result["type_name"]  = "V" + std::to_string(ShareT::version);
        // No reverse (parent -> children) index on the shared ShareChain, so
        // children stay empty rather than being faked — same as DASH :404-407.
        result["children"]   = nlohmann::json::array();

        nlohmann::json local_j;
        local_j["verified"]                 = verified.contains(hash);
        local_j["time_first_seen"]          = idx ? idx->time_seen : 0;
        local_j["peer_first_received_from"] = obj->peer_addr.to_string();
        result["local"] = local_j;

        const double diff =
            chain::target_to_difficulty(chain::bits_to_target(obj->m_bits));
        const double min_diff =
            chain::target_to_difficulty(chain::bits_to_target(obj->m_max_bits));

        nlohmann::json sd;
        sd["timestamp"]       = obj->m_timestamp;
        sd["target"]          = obj->m_bits;
        sd["max_target"]      = obj->m_max_bits;
        sd["payout_address"]  = addr.empty() ? HexStr(script) : addr;
        sd["pubkey_hash"]     = obj->m_pubkey_hash.GetHex();
        // bip110 = p2pool donation encoding: 1/65535 units (share_tracker.hpp
        // donation divisor) — NOT DASH's 1/65536.
        sd["donation"]        = static_cast<double>(obj->m_donation) / 65535.0;
        sd["stale_info"]      = static_cast<int>(obj->m_stale_info);
        sd["nonce"]           = obj->m_nonce;
        sd["desired_version"] = obj->m_desired_version;
        sd["absheight"]       = obj->m_absheight;
        sd["abswork"]         = obj->m_abswork.GetHex();
        sd["difficulty"]      = diff;
        sd["min_difficulty"]  = min_diff;
        result["share_data"]  = sd;

        auto& hdr = obj->m_min_header;
        nlohmann::json hdr_j;
        hdr_j["version"]        = hdr.m_version;
        hdr_j["previous_block"] = hdr.m_previous_block.GetHex();
        hdr_j["merkle_root"]    = "";
        hdr_j["timestamp"]      = hdr.m_timestamp;
        hdr_j["target"]         = hdr.m_bits;
        hdr_j["nonce"]          = hdr.m_nonce;

        nlohmann::json gentx_j;
        gentx_j["hash"]             = "";
        gentx_j["coinbase"]         = HexStr(obj->m_coinbase.m_data);
        gentx_j["value"]            = static_cast<double>(obj->m_subsidy) / 1e8;
        gentx_j["last_txout_nonce"] = obj->m_last_txout_nonce;

        nlohmann::json block_j;
        block_j["hash"]                     = hash.GetHex();
        block_j["header"]                   = hdr_j;
        block_j["gentx"]                    = gentx_j;
        block_j["other_transaction_hashes"] = nlohmann::json::array();
        result["block"] = block_j;

        // v36 metadata (share.html:641-665 renders it; good-citizen: serve what
        // we hold, honest about what we don't).
        nlohmann::json v36_j;
        v36_j["merged_payout_hash"] = obj->m_merged_payout_hash.GetHex();
        v36_j["message_data_size"]  = static_cast<std::uint64_t>(obj->m_message_data.m_data.size());
        result["v36_metadata"] = v36_j;

        pplns_parent  = obj->m_prev_hash;
        pplns_bits    = obj->m_min_header.m_bits;
        pplns_subsidy = obj->m_subsidy;
    });

    // ── PPLNS window for THIS share (DASH main_dash.cpp:1983-1995 analog) ─────
    // Anchored on the PARENT with the share's own recorded subsidy/bits — the
    // exact window this share's gentx was minted against. current_payouts_report
    // returns {} on a null anchor or a thrown walk, so a tail share (parent not
    // yet in the local window) degrades to no pplns honestly, never faked.
    if (!pplns_parent.IsNull() && pplns_subsidy != 0) {
        nlohmann::json pj = current_payouts_report(
            tracker, pplns_parent, chain::bits_to_target(pplns_bits),
            pplns_subsidy, donation_script, testnet);
        if (pj.is_object() && !pj.empty()) {
            result["pplns"] = pj;
            // pplns_meta is DASH-parity only (share.html reads share.pplns, not
            // pplns_meta). bip110 has no MN/special payments -> the whole subsidy
            // is the miners' worker payout.
            result["pplns_meta"] = {
                {"subsidy",        static_cast<double>(pplns_subsidy) / 1e8},
                {"payments_total", 0.0},
                {"worker_payout",  static_cast<double>(pplns_subsidy) / 1e8},
                {"recipients",     pj.size()},
            };
        }
    }

    return result;
}

} // namespace bip110::pool
