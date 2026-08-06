// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH dashboard read-models: the sharechain WINDOW, the incremental DELTA and
// the individual SHARE DETAIL document.
//
// These are the DASH ports of the three builders main_ltc.cpp wires inline:
//   * window       -> main_ltc.cpp:3730 (MiningInterface::set_sharechain_window_fn)
//   * delta        -> main_ltc.cpp:3946 (MiningInterface::set_sharechain_delta_fn)
//   * share detail -> main_ltc.cpp:4077 (MiningInterface::set_share_lookup_fn)
//
// The three seams were never bound on the DASH lane, so core answered from the
// FALLBACK STUBS (web_server.cpp:2907 window, :3313 delta, :6768 share) — a
// well-formed HTTP 200 carrying `{"shares":[],"total":0,...}` / `{}`. That is
// the whole defect: no 404, no log line, no error anywhere; the dashboard's
// `if (!data.shares) return` guard (dashboard.html:5011) sails straight through
// a truthy empty array and renders nothing. Every consumer of those three
// endpoints — the defragmenter grid, Best Share / This Node / heads / tails
// cells, share.html, /pplns/current's per-miner enrichment — is dark as a
// result.
//
// Why a header instead of three more lambdas in main_dash.cpp: the builders are
// pure functions of (tracker, view context) with no io_context, no socket and
// no MiningInterface, which makes them directly KAT-able against a real
// dash::ShareTracker. main_dash.cpp keeps only the binding.
//
// LOCKING CONTRACT: every entry point here takes an ALREADY-LOCKED tracker
// (dash::Node::read_tracker() guard held by the caller) and only READS it.
// Nothing in this header acquires a lock, mutates chain state, or touches
// consensus.

#include "share_chain.hpp"     // dash::ShareChain / ShareIndex / DashShare
#include "share_check.hpp"     // dash::get_share_script, pubkey_hash_to_script2
#include "config_pool.hpp"     // dash::SharechainConfig

#include <core/address_utils.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace dash {
namespace dashboard {

// ── View context ────────────────────────────────────────────────────────────
// Everything the builders need that does NOT live on the tracker. Passed in by
// the main_dash binding so this header never reaches into MiningInterface.
struct ViewContext
{
    bool        testnet{false};
    uint32_t    window_size{0};        ///< SharechainConfig::chain_length()
    std::string my_address;            ///< local payout address ("mine" marking)
    std::string fee_hash160;           ///< node-fee hash160 (fee-share marking)
    /// 16-hex short hashes of shares known to have solved a DASH block, from
    /// the found-block store (survives restart; the index flag does not).
    std::vector<std::string> found_block_short_hashes;
    /// Hard cap on the delta walk, matching main_ltc.cpp:4029.
    int delta_max_shares{200};
};

// ── Address rendering ───────────────────────────────────────────────────────
// DASH base58 version bytes (params.hpp: 76/'X' mainnet, 140/'y' testnet;
// 16/'7' and 19 for P2SH). Identical to the resolver rest_current_payouts()
// already uses for Blockchain::DASH (web_server.cpp:2384), so an address the
// window renders and the same address in /current_payouts are byte-equal.
inline std::string script_to_dash_address(const std::vector<unsigned char>& script,
                                          bool testnet)
{
    return core::script_to_address(script, "",
                                   testnet ? 140 : 76,
                                   testnet ?  19 : 16);
}

// ── Coinbase tag extraction ─────────────────────────────────────────────────
// Longest printable-ASCII run in the share's coinbase scriptSig, shown as the
// miner's self-identification in the grid tooltip. Same rule as
// main_ltc.cpp:3800 — >= 10 chars, must contain a letter, truncated at 48 —
// so the two coins' grids read identically.
inline std::string coinbase_tag(const std::vector<unsigned char>& data)
{
    std::string best_run;
    std::string cur_run;
    for (auto c : data) {
        if (c >= 32 && c <= 126) {
            cur_run += static_cast<char>(c);
        } else {
            if (cur_run.size() > best_run.size()) best_run = cur_run;
            cur_run.clear();
        }
    }
    if (cur_run.size() > best_run.size()) best_run = cur_run;

    bool has_letter = false;
    for (auto c : best_run) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) { has_letter = true; break; }
    }
    if (best_run.size() < 10 || !has_letter) return {};
    if (best_run.size() > 48) best_run.resize(48);
    return best_run;
}

// ── Tallest head ────────────────────────────────────────────────────────────
// The grid follows the TALLEST RAW head rather than the verified best so it
// keeps moving during sync (main_ltc.cpp:3740). This is display-only and never
// feeds mint/payout election — those go through mint_runloop's
// select_best_share(), which is work-weighted over the VERIFIED chain.
template <typename ChainT>
inline uint256 tallest_head(ChainT& chain, int32_t& height_out)
{
    uint256 best;
    int32_t best_height = -1;
    for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
        (void)tail_hash;
        const int32_t h = chain.get_height(head_hash);
        if (h > best_height) { best = head_hash; best_height = h; }
    }
    height_out = best_height;
    return best;
}

// ── One grid cell ───────────────────────────────────────────────────────────
// Key names are the SHARED wire contract the dashboard front-end already
// speaks (dashboard.html defrag.getColor / showTooltip / makeShareCell):
//   h  short hash (16 hex)     H  full hash          p  position in the walk
//   v  verified (0/1)          blk block solution    t  share timestamp
//   V  share wire version      s  stale_info         b  share nBits
//   a  absheight               dv desired_version    m  miner address
//   cb coinbase tag            fee node-fee share
template <typename ChainT>
inline nlohmann::json share_cell(ChainT& chain, ChainT& verified,
                                 const uint256& hash, int pos,
                                 const ViewContext& ctx)
{
    nlohmann::json s;
    const std::string full = hash.GetHex();
    s["h"] = full.substr(0, 16);
    s["H"] = full;
    s["p"] = pos;
    s["v"] = verified.contains(hash) ? 1 : 0;

    auto* idx = chain.get_index(hash);
    if (idx && idx->is_block_solution)
        s["blk"] = 1;

    chain.get_share(hash).invoke([&](auto* obj) {
        s["t"]  = obj->m_timestamp;
        s["V"]  = std::remove_pointer_t<decltype(obj)>::version;
        s["s"]  = static_cast<int>(obj->m_stale_info);
        s["b"]  = obj->m_bits;
        s["a"]  = obj->m_absheight;
        s["dv"] = obj->m_desired_version;

        const auto script = dash::get_share_script(obj);
        const std::string addr = script_to_dash_address(script, ctx.testnet);
        s["m"] = addr.empty() ? HexStr(script) : addr;

        const std::string tag = coinbase_tag(obj->m_coinbase.m_data);
        if (!tag.empty()) s["cb"] = tag;

        // DASH sharechain payouts are P2PKH-keyed, so the fee test is a direct
        // hash160 compare — no script-shape dispatch (LTC needs one because it
        // carries P2PKH / P2WPKH / P2SH payout scripts; DASH is always-P2PKH,
        // share_check.hpp pubkey_hash_to_script2).
        if (!ctx.fee_hash160.empty() && obj->m_pubkey_hash.GetHex() == ctx.fee_hash160)
            s["fee"] = 1;
    });

    return s;
}

// ── Heads array ─────────────────────────────────────────────────────────────
template <typename ChainT>
inline nlohmann::json heads_array(ChainT& chain)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
        (void)tail_hash;
        arr.push_back(head_hash.GetHex().substr(0, 16));
    }
    return arr;
}

// ── Window ──────────────────────────────────────────────────────────────────
// Full grid payload: up to chain_length() shares walked back from the tallest
// head. Port of main_ltc.cpp:3730 minus the merged-mining (DOGE) legs, which
// have no DASH equivalent — DASH is standalone X11 with no AuxPoW child, so
// `doge_blocks` is intentionally ABSENT rather than an empty array pretending
// a merged chain exists.
template <typename TrackerT>
inline nlohmann::json build_window(TrackerT& tracker, const ViewContext& ctx)
{
    auto& chain    = tracker.chain;
    auto& verified = tracker.verified;

    nlohmann::json result;

    int32_t best_height = -1;
    const uint256 best = tallest_head(chain, best_height);

    result["best_hash"]    = best.IsNull() ? "" : best.GetHex();
    result["chain_length"] = static_cast<int>(chain.size());
    result["window_size"]  = static_cast<int>(ctx.window_size);
    result["my_address"]   = ctx.my_address;
    result["fee_hash160"]  = ctx.fee_hash160;

    nlohmann::json shares_arr = nlohmann::json::array();
    if (!best.IsNull()) {
        const int height = chain.get_height(best);
        const int walk   = std::min(height, static_cast<int>(ctx.window_size));
        if (walk > 0) {
            try {
                int pos = 0;
                for (auto [hash, data] : chain.get_chain(best, walk)) {
                    (void)data;
                    shares_arr.push_back(share_cell(chain, verified, hash, pos++, ctx));
                }
            } catch (...) {
                // Partial results on chain inconsistency — same tolerance as
                // main_ltc.cpp:3848. A truncated grid is honest; a thrown
                // exception here would surface as the empty stub again.
            }
        }
    }

    nlohmann::json blocks_arr = nlohmann::json::array();
    for (const auto& sh : ctx.found_block_short_hashes)
        blocks_arr.push_back(sh);

    result["shares"] = std::move(shares_arr);
    result["heads"]  = heads_array(chain);
    result["blocks"] = std::move(blocks_arr);
    result["total"]  = static_cast<int>(chain.size());
    return result;
}

// ── Delta ───────────────────────────────────────────────────────────────────
// Only the shares NEWER than `since_hash` (which the client already holds),
// capped at ctx.delta_max_shares. Port of main_ltc.cpp:3946.
template <typename TrackerT>
inline nlohmann::json build_delta(TrackerT& tracker, const std::string& since_hash,
                                  const ViewContext& ctx)
{
    auto& chain    = tracker.chain;
    auto& verified = tracker.verified;

    nlohmann::json result;

    int32_t best_height = -1;
    const uint256 best = tallest_head(chain, best_height);

    nlohmann::json shares_arr = nlohmann::json::array();
    int count = 0;

    if (!best.IsNull()) {
        const int walk = std::min(static_cast<int>(chain.get_height(best)),
                                  static_cast<int>(ctx.window_size));
        try {
            for (auto [hash, data] : chain.get_chain(best, walk)) {
                (void)data;
                const std::string full  = hash.GetHex();
                const std::string short_h = full.substr(0, 16);
                if (short_h == since_hash || full == since_hash)
                    break;   // reached what the client already has
                shares_arr.push_back(share_cell(chain, verified, hash, count, ctx));
                if (++count >= ctx.delta_max_shares) break;
            }
        } catch (...) {
            // partial delta — the client reconciles on the next full window
        }
    }

    nlohmann::json blocks_arr = nlohmann::json::array();
    for (const auto& sh : ctx.found_block_short_hashes)
        blocks_arr.push_back(sh);

    result["shares"] = std::move(shares_arr);
    result["count"]  = count;
    result["tip"]    = best.IsNull() ? "" : best.GetHex().substr(0, 16);
    result["heads"]  = heads_array(chain);
    result["blocks"] = std::move(blocks_arr);
    return result;
}

// ── Individual share detail ─────────────────────────────────────────────────
// The document behind /web/share/<hash> and web-static/share.html. Port of
// main_ltc.cpp:4077; the merged-mining (DOGE block) legs are dropped for the
// same reason as in build_window, and a DASH-specific `dash_metadata` block is
// added for the masternode/DIP4 fields the DASH share carries and LTC has no
// analogue for (share.hpp: m_payment_amount, m_packed_payments,
// m_coinbase_payload).
//
// Returns {"error": ...} on a miss so core's rest_web_share() keeps its
// existing not-found contract (web_server.cpp:6771 treats an "error" key as
// "not answered" and falls back).
template <typename TrackerT>
inline nlohmann::json build_share_detail(TrackerT& tracker, const std::string& hash_hex,
                                         const ViewContext& ctx)
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

    chain.get_share(hash).invoke([&](auto* obj) {
        using ShareT = std::remove_pointer_t<decltype(obj)>;

        result["parent"]     = obj->m_prev_hash.GetHex();
        result["far_parent"] = obj->m_far_share_hash.GetHex();
        result["version"]    = ShareT::version;
        result["type_name"]  = "V" + std::to_string(ShareT::version);

        nlohmann::json local_j;
        local_j["verified"]                 = verified.contains(hash);
        local_j["time_first_seen"]          = idx ? idx->time_seen : 0;
        local_j["peer_first_received_from"] = obj->peer_addr.to_string();
        result["local"] = local_j;

        const auto script = dash::get_share_script(obj);
        const std::string addr = script_to_dash_address(script, ctx.testnet);

        const double target_diff =
            chain::target_to_difficulty(chain::bits_to_target(obj->m_bits));
        const double max_target_diff =
            chain::target_to_difficulty(chain::bits_to_target(obj->m_max_bits));

        nlohmann::json sd;
        sd["timestamp"]       = obj->m_timestamp;
        sd["target"]          = obj->m_bits;
        sd["max_target"]      = obj->m_max_bits;
        sd["payout_address"]  = addr.empty() ? HexStr(script) : addr;
        sd["pubkey_hash"]     = obj->m_pubkey_hash.GetHex();
        // DASH encodes donation in 1/65536 units (share.hpp m_donation, and the
        // 65535 divisor in pplns.hpp) — NOT LTC's percent-of-65536 reading.
        sd["donation"]        = static_cast<double>(obj->m_donation) / 65536.0;
        sd["stale_info"]      = static_cast<int>(obj->m_stale_info);
        sd["nonce"]           = obj->m_nonce;
        sd["desired_version"] = obj->m_desired_version;
        sd["absheight"]       = obj->m_absheight;
        sd["abswork"]         = obj->m_abswork.GetHex();
        sd["difficulty"]      = target_diff;
        sd["min_difficulty"]  = max_target_diff;
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
        gentx_j["hash"]              = "";
        gentx_j["coinbase"]          = HexStr(obj->m_coinbase.m_data);
        gentx_j["value"]             = static_cast<double>(obj->m_subsidy) / 1e8;
        gentx_j["last_txout_nonce"]  = obj->m_last_txout_nonce;

        nlohmann::json block_j;
        block_j["hash"]                      = hash.GetHex();
        block_j["header"]                    = hdr_j;
        block_j["gentx"]                     = gentx_j;
        block_j["other_transaction_hashes"]  = nlohmann::json::array();
        result["block"] = block_j;

        // No reverse (parent -> children) index on the shared ShareChain, so
        // children stay empty rather than being faked — same position
        // main_ltc.cpp:4193 takes.
        result["children"] = nlohmann::json::array();

        // ── DASH-specific: masternode / DIP4 coinbase payload ───────────────
        nlohmann::json dash_j;
        dash_j["payment_amount"] = static_cast<double>(obj->m_payment_amount) / 1e8;
        nlohmann::json payments = nlohmann::json::array();
        for (const auto& p : obj->m_packed_payments) {
            nlohmann::json pj;
            pj["amount"] = static_cast<double>(p.m_amount) / 1e8;
            const auto pm_script = dash::decode_payee_script(
                p.m_payee, ctx.testnet ? 140 : 76, ctx.testnet ? 19 : 16);
            const std::string pm_addr = script_to_dash_address(pm_script, ctx.testnet);
            // m_payee is already the oracle's text form (base58 address, or
            // "!<hex script>") — surface it verbatim when it does not decode
            // to a renderable address rather than inventing one.
            pj["payee"] = pm_addr.empty() ? p.m_payee : pm_addr;
            payments.push_back(std::move(pj));
        }
        dash_j["packed_payments"]        = std::move(payments);
        dash_j["coinbase_payload_bytes"] = obj->m_coinbase_payload.m_data.size();
        result["dash_metadata"] = std::move(dash_j);
    });

    return result;
}

} // namespace dashboard
} // namespace dash
