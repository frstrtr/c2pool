// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The sharechain documents the dashboard reads, built from a coin's share
// tracker:
//
//   /sharechain/window  window_json(snapshot(...))      the explorer grid
//   /sharechain/delta   delta_json(snapshot(..., since)) its live updates
//   /sharechain/tip     tip_of(tracker)                  the update poll
//   /web/share/<hash>   share_detail(...)                share.html
//
// For the coins whose shares carry the p2pool share fields (m_prev_hash,
// m_far_share_hash, m_min_header, m_coinbase, m_bits, m_max_bits, m_absheight,
// m_abswork, m_desired_version, m_stale_info, ...): BTC and BCH. The field
// names and value shapes are those the LTC node serves (main_ltc.cpp), which
// web-static/dashboard.html and share.html were written against.
//
// Locking: every function that takes a tracker reads it, so the caller holds
// the node's read guard (read_tracker()) across the call. snapshot() copies
// plain values out, so the caller releases the guard before window_json() /
// delta_json() build the JSON. share_detail() builds its small document under
// the guard. Nothing here writes the tracker.

#include <core/address_utils.hpp>      // core::classify_script
#include <core/target_utils.hpp>       // chain::bits_to_target, target_to_difficulty
#include <core/uint256.hpp>
#include <core/view_block_hashes.hpp>  // core::found_block_hashes_in
#include <core/web_server.hpp>         // core::SharechainTip

#include <btclibs/util/strencodings.h> // HexStr

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace core::sharechain_views {

// One share of a window or delta, copied out of the tracker.
struct ShareRow {
    uint256  hash;
    bool     verified = false;
    bool     block = false;             // the share solved a block (tracker index flag)
    uint32_t timestamp = 0;
    uint32_t bits = 0;
    uint32_t absheight = 0;
    int64_t  version = 0;               // share version (the share type)
    int      stale = 0;                 // stale_info as stored: 0, 253 orphan, 254 dead
    uint64_t desired_version = 0;
    std::vector<unsigned char> script;  // payout scriptPubKey
    std::string coinbase_text;          // printable coinbase text, or empty
};

// The tracker state a window or delta document is built from.
struct ChainSnapshot {
    uint256      best;                  // tallest head; null when the chain is empty
    int32_t      best_height = -1;
    std::size_t  chain_size = 0;
    std::vector<uint256> heads;
    std::vector<ShareRow> rows;         // newest first
};

// The longest printable-ASCII run of a coinbase script: shown when it is at
// least 10 characters and holds a letter, cut to 48 (main_ltc.cpp window).
inline std::string coinbase_text(const std::vector<unsigned char>& data)
{
    std::string best_run, cur_run;
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
    for (auto c : best_run)
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) { has_letter = true; break; }
    if (best_run.size() < 10 || !has_letter) return {};
    if (best_run.size() > 48) best_run.resize(48);
    return best_run;
}

// The address a payout script is shown as: the same decode the coins'
// /current_payouts uses (classify_script, bitcoin parameters), so a window
// row's miner matches its payout key. Raw hex when it does not decode.
inline std::string script_address(const std::vector<unsigned char>& script, bool testnet)
{
    auto cls = core::classify_script(script, /*is_litecoin=*/false, testnet);
    if (!cls.addresses.empty() && !cls.addresses.front().empty())
        return cls.addresses.front();
    return HexStr(script);
}

// The 20-byte hash a P2PKH / P2WPKH / P2SH script pays, as hex; empty otherwise.
inline std::string script_hash160(const std::vector<unsigned char>& script)
{
    int off = -1;
    if (script.size() == 25 && script[0] == 0x76) off = 3;
    else if (script.size() == 22 && script[0] == 0x00) off = 2;
    else if (script.size() == 23 && script[0] == 0xa9) off = 2;
    if (off < 0) return {};
    return HexStr(std::vector<unsigned char>(script.begin() + off, script.begin() + off + 20));
}

// The payout script of a share, empty when the coin's decoder refuses it (a
// share in the tracker has passed verification, so it does not).
template <typename ScriptOf, typename ShareT>
std::vector<unsigned char> payout_script(ScriptOf&& script_of, const ShareT* obj)
{
    try {
        return script_of(obj);
    } catch (const std::exception&) {
        return {};
    }
}

// The tallest head of the chain (not the verified best), so the views stay
// current while verification catches up.
template <typename Chain>
std::pair<uint256, int32_t> tallest_head(Chain& chain)
{
    uint256 best;
    int32_t best_height = -1;
    for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
        (void)tail_hash;
        const auto h = chain.get_height(head_hash);
        if (h > best_height) { best = head_hash; best_height = h; }
    }
    return {best, best_height};
}

// Copy the shares from the tallest head back, newest first: at most
// `window_size` of them, stopping before the share `since` names (its 16-hex
// short hash or its full hash), and after `cap` rows. `script_of(obj)` is the
// coin's get_share_script.
template <typename Tracker, typename ScriptOf>
ChainSnapshot snapshot(Tracker& tracker, uint32_t window_size, ScriptOf&& script_of,
                       const std::string& since = {}, std::size_t cap = SIZE_MAX)
{
    ChainSnapshot snap;
    auto& chain    = tracker.chain;
    auto& verified = tracker.verified;
    std::tie(snap.best, snap.best_height) = tallest_head(chain);
    snap.chain_size = chain.size();
    for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
        (void)tail_hash;
        snap.heads.push_back(head_hash);
    }
    if (snap.best.IsNull())
        return snap;

    const int walk = std::min(static_cast<int>(chain.get_height(snap.best)),
                              static_cast<int>(window_size));
    if (walk <= 0)
        return snap;
    try {
        for (auto [hash, data] : chain.get_chain(snap.best, static_cast<uint64_t>(walk))) {
            if (!since.empty()) {
                const std::string full = hash.GetHex();
                if (full == since || full.substr(0, 16) == since)
                    break;
            }
            ShareRow r;
            r.hash = hash;
            r.verified = verified.contains(hash);
            auto* idx = chain.get_index(hash);
            r.block = idx && idx->is_block_solution;
            data.share.invoke([&](auto* obj) {
                using ShareT = std::remove_pointer_t<decltype(obj)>;
                r.timestamp       = obj->m_timestamp;
                r.bits            = obj->m_bits;
                r.absheight       = obj->m_absheight;
                r.version         = ShareT::version;
                r.stale           = static_cast<int>(obj->m_stale_info);
                r.desired_version = obj->m_desired_version;
                r.script          = payout_script(script_of, obj);
                r.coinbase_text   = coinbase_text(obj->m_coinbase.m_data);
            });
            snap.rows.push_back(std::move(r));
            if (snap.rows.size() >= cap)
                break;
        }
    } catch (const std::exception&) {
        // A chain changed under an unguarded caller or a broken link: serve
        // the rows read so far.
    }
    return snap;
}

// The rows as the explorer reads them: h (16-hex), H (full hash), p (position,
// 0 = newest), v (verified 0/1), blk (solved a block), t, V (share version),
// s (stale_info), b (bits), a (absheight), dv (desired version), m (payout
// address), cb (coinbase text), fee (pays the node fee address).
inline nlohmann::json rows_json(const std::vector<ShareRow>& rows,
                                const std::string& fee_hash160, bool testnet)
{
    std::unordered_map<std::string, std::pair<std::string, bool>> by_script;
    nlohmann::json out = nlohmann::json::array();
    int pos = 0;
    for (const auto& r : rows) {
        const std::string key(r.script.begin(), r.script.end());
        auto it = by_script.find(key);
        if (it == by_script.end()) {
            const bool fee = !fee_hash160.empty() && script_hash160(r.script) == fee_hash160;
            it = by_script.emplace(key, std::make_pair(script_address(r.script, testnet), fee)).first;
        }
        nlohmann::json s;
        const std::string full = r.hash.GetHex();
        s["h"]  = full.substr(0, 16);
        s["H"]  = full;
        s["p"]  = pos++;
        s["v"]  = r.verified ? 1 : 0;
        if (r.block) s["blk"] = 1;
        s["t"]  = r.timestamp;
        s["V"]  = r.version;
        s["s"]  = r.stale;
        s["b"]  = r.bits;
        s["a"]  = r.absheight;
        s["dv"] = r.desired_version;
        s["m"]  = it->second.first;
        if (!r.coinbase_text.empty()) s["cb"] = r.coinbase_text;
        if (it->second.second) s["fee"] = 1;
        out.push_back(std::move(s));
    }
    return out;
}

inline nlohmann::json short_hashes(const std::vector<uint256>& hashes)
{
    nlohmann::json out = nlohmann::json::array();
    for (const auto& h : hashes) out.push_back(h.GetHex().substr(0, 16));
    return out;
}

inline nlohmann::json short_hashes(const std::vector<std::string>& hashes)
{
    nlohmann::json out = nlohmann::json::array();
    for (const auto& h : hashes) out.push_back(h.substr(0, 16));
    return out;
}

// /sharechain/window. `found_share_hashes`: the full share hashes of the
// found-block ledger (MiningInterface::found_block_share_hash of each row).
inline nlohmann::json window_json(const ChainSnapshot& snap, uint32_t window_size,
                                  const std::string& my_address,
                                  const std::string& fee_hash160,
                                  const std::vector<std::string>& found_share_hashes,
                                  bool testnet)
{
    nlohmann::json result = nlohmann::json::object();
    result["best_hash"]    = snap.best.IsNull() ? "" : snap.best.GetHex();
    result["chain_length"] = static_cast<int>(snap.chain_size);
    result["window_size"]  = static_cast<int>(window_size);
    result["my_address"]   = my_address;
    result["fee_hash160"]  = fee_hash160;
    nlohmann::json shares  = rows_json(snap.rows, fee_hash160, testnet);
    result["block_hashes"] = core::found_block_hashes_in(shares, found_share_hashes);
    result["shares"]       = std::move(shares);
    result["heads"]        = short_hashes(snap.heads);
    result["blocks"]       = short_hashes(found_share_hashes);
    result["total"]        = static_cast<int>(snap.chain_size);
    return result;
}

// /sharechain/delta: the shares newer than the client's cursor. block_hashes
// is left out when none of the new shares solved a block (the client keeps
// what it has).
inline nlohmann::json delta_json(const ChainSnapshot& snap,
                                 const std::string& fee_hash160,
                                 const std::vector<std::string>& found_share_hashes,
                                 bool testnet)
{
    nlohmann::json result = nlohmann::json::object();
    nlohmann::json shares = rows_json(snap.rows, fee_hash160, testnet);
    nlohmann::json block_hashes = core::found_block_hashes_in(shares, found_share_hashes);
    result["count"]  = static_cast<int>(snap.rows.size());
    result["shares"] = std::move(shares);
    result["tip"]    = snap.best.IsNull() ? "" : snap.best.GetHex().substr(0, 16);
    result["heads"]  = short_hashes(snap.heads);
    result["blocks"] = short_hashes(found_share_hashes);
    if (!block_hashes.empty())
        result["block_hashes"] = std::move(block_hashes);
    return result;
}

// /sharechain/tip: the tallest head's short hash, its height and the number of
// shares held; nullopt while the chain is empty.
template <typename Tracker>
std::optional<core::SharechainTip> tip_of(Tracker& tracker)
{
    auto& chain = tracker.chain;
    auto [best, best_height] = tallest_head(chain);
    if (best.IsNull() && chain.size() == 0)
        return std::nullopt;
    core::SharechainTip t;
    t.hash   = best.IsNull() ? "" : best.GetHex().substr(0, 16);
    t.height = best_height;
    t.total  = static_cast<int32_t>(chain.size());
    return t;
}

// /web/share/<hash>: the document share.html renders. {"error": "share not
// found"} for a hash the tracker does not hold. `donation_divisor` turns the
// share's donation field into a fraction (p2pool: 65535). The block header
// carries no merkle root and the generation transaction hash is not derived
// here: both are null with a note, never made up.
template <typename Tracker, typename ScriptOf>
nlohmann::json share_detail(Tracker& tracker, const std::string& hash_hex,
                            ScriptOf&& script_of, bool testnet, double donation_divisor)
{
    auto& chain    = tracker.chain;
    auto& verified = tracker.verified;

    uint256 hash;
    hash.SetHex(hash_hex);
    if (hash.IsNull() || !chain.contains(hash))
        return nlohmann::json{{"error", "share not found"}};

    nlohmann::json result = nlohmann::json::object();
    auto* idx = chain.get_index(hash);
    result["hash"]              = hash.GetHex();
    result["is_block_solution"] = idx && idx->is_block_solution;
    result["is_doge_block"]     = false;
    result["height"]            = chain.get_height(hash);

    chain.get_share(hash).invoke([&](auto* obj) {
        using ShareT = std::remove_pointer_t<decltype(obj)>;
        result["parent"]     = obj->m_prev_hash.GetHex();
        result["far_parent"] = obj->m_far_share_hash.GetHex();
        result["type_name"]  = "V" + std::to_string(ShareT::version);
        result["version"]    = ShareT::version;

        nlohmann::json local_j;
        local_j["verified"]                 = verified.contains(hash);
        local_j["time_first_seen"]          = idx ? idx->time_seen : 0;
        local_j["peer_first_received_from"] = obj->peer_addr.to_string();
        result["local"] = local_j;

        const auto script = payout_script(script_of, obj);
        nlohmann::json sd;
        sd["timestamp"]       = obj->m_timestamp;
        sd["target"]          = obj->m_bits;
        sd["max_target"]      = obj->m_max_bits;
        sd["payout_address"]  = script_address(script, testnet);
        sd["donation"]        = static_cast<double>(obj->m_donation) / donation_divisor;
        sd["stale_info"]      = static_cast<int>(obj->m_stale_info);
        sd["nonce"]           = obj->m_nonce;
        sd["desired_version"] = obj->m_desired_version;
        sd["absheight"]       = obj->m_absheight;
        sd["abswork"]         = obj->m_abswork.GetHex();
        sd["difficulty"]      = chain::target_to_difficulty(chain::bits_to_target(obj->m_bits));
        sd["min_difficulty"]  = chain::target_to_difficulty(chain::bits_to_target(obj->m_max_bits));
        result["share_data"] = sd;

        const auto& hdr = obj->m_min_header;
        nlohmann::json hdr_j;
        hdr_j["version"]        = hdr.m_version;
        hdr_j["previous_block"] = hdr.m_previous_block.GetHex();
        hdr_j["merkle_root"]    = nullptr;
        hdr_j["timestamp"]      = hdr.m_timestamp;
        hdr_j["target"]         = hdr.m_bits;
        hdr_j["nonce"]          = hdr.m_nonce;

        nlohmann::json gentx_j;
        gentx_j["hash"]             = nullptr;
        gentx_j["coinbase"]         = HexStr(obj->m_coinbase.m_data);
        gentx_j["value"]            = static_cast<double>(obj->m_subsidy) / 1e8;
        gentx_j["last_txout_nonce"] = obj->m_last_txout_nonce;

        nlohmann::json block_j;
        block_j["hash"]   = hash.GetHex();
        block_j["header"] = hdr_j;
        block_j["gentx"]  = gentx_j;
        block_j["derive_note"] = "merkle root and generation tx hash are not derived for this coin";
        block_j["other_transaction_hashes"] = nullptr;
        block_j["other_transaction_hashes_note"] =
            "not carried by v34+ shares (merkle link only)";
        result["block"] = block_j;

        if constexpr (requires { obj->m_merged_addresses; }) {
            nlohmann::json merged = nlohmann::json::array();
            for (const auto& ma : obj->m_merged_addresses) {
                nlohmann::json a;
                a["chain_id"]   = ma.m_chain_id;
                a["script_hex"] = HexStr(ma.m_script.m_data);
                merged.push_back(std::move(a));
            }
            nlohmann::json v36_j;
            v36_j["merged_addresses"]   = std::move(merged);
            v36_j["merged_payout_hash"] = obj->m_merged_payout_hash.GetHex();
            v36_j["message_data_hex"]   = HexStr(obj->m_message_data.m_data);
            v36_j["message_data_size"]  = obj->m_message_data.m_data.size();
            result["v36_metadata"] = v36_j;
        }
    });

    nlohmann::json children = nlohmann::json::array();
    const auto& rev = chain.get_reverse();
    if (auto it = rev.find(hash); it != rev.end())
        for (const auto& child : it->second)
            children.push_back(child.GetHex());
    result["children"] = std::move(children);
    return result;
}

// Height, confirmations and status of the block a share solved, from the
// found-block ledger rows (MiningInterface::get_found_blocks). `is_primary`
// picks this coin's own rows (a merged row names the same share). share.html
// reads block_height / block_confirmations.
template <typename FoundBlocks, typename IsPrimary>
void add_found_block_fields(nlohmann::json& detail, const FoundBlocks& found, IsPrimary&& is_primary)
{
    if (!detail.value("is_block_solution", false)) return;
    const std::string h = detail.value("hash", std::string{});
    for (const auto& fb : found) {
        if (!is_primary(fb)) continue;
        if (fb.hash == h || (!fb.share_hash.empty() && fb.share_hash == h)) {
            detail["block_height"]        = fb.height;
            detail["block_confirmations"] = fb.confirmations;
            detail["block_status"]        = static_cast<int>(fb.status);
            return;
        }
    }
}

} // namespace core::sharechain_views
