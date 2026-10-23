// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin MWEB block-shape invariant (Litecoin extension blocks).
//
// After MWEB activation every Litecoin block must end its transaction list
// with the HogEx (integrating) transaction and must carry the serialized MWEB
// block after the transactions ("01" + mweb). A block that drops either half
// is rejected by litecoind with "mweb-missing" and the reward is lost.
//
// One predicate, three choke points:
//   1. block assembly   (MiningInterface::build_block_from_stratum)
//   2. template ingress (MiningInterface::refresh_work)
//   3. LTC embedded template builder (TemplateBuilder::build_template)
// Header-only and pure over hex/json so the KATs can pin it directly.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace core::coin {

namespace mweb_shape_detail {
inline int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline int hex_byte_at(std::string_view hex, size_t index)
{
    const int hi = hex_nibble(hex[index * 2]);
    const int lo = hex_nibble(hex[index * 2 + 1]);
    return (hi < 0 || lo < 0) ? -1 : (hi << 4) | lo;
}
} // namespace mweb_shape_detail

/// True when `tx_hex` is a HogEx serialization: the extended format (empty
/// dummy vin, byte 4 == 0x00) with the MWEB flag bit 0x08 set in byte 5.
inline bool tx_hex_is_hogex(std::string_view tx_hex)
{
    if (tx_hex.size() < 12)
        return false;
    const int dummy = mweb_shape_detail::hex_byte_at(tx_hex, 4);
    const int flags = mweb_shape_detail::hex_byte_at(tx_hex, 5);
    return dummy == 0x00 && flags >= 0 && (flags & 0x08) != 0;
}

/// Shape check over the last non-coinbase transaction (nullptr = the block
/// carries no template transactions) and the MWEB extension data.
/// Returns the refusal reason, or nullopt when the shape is consistent:
///   - mweb data present but the last tx is not a HogEx (or there is none);
///   - MWEB active but no mweb data;
///   - the last tx is a HogEx but there is no mweb data.
inline std::optional<std::string> check_block_shape(const std::string* last_tx_hex,
                                                    const std::string& mweb,
                                                    bool mweb_active)
{
    const bool last_is_hogex = last_tx_hex && tx_hex_is_hogex(*last_tx_hex);
    if (!mweb.empty() && !last_is_hogex) {
        return last_tx_hex
            ? std::string("mweb data present but the last transaction is not a HogEx")
            : std::string("mweb data present but the block has no transactions after the coinbase");
    }
    if (mweb_active && mweb.empty())
        return std::string("MWEB is active but the mweb extension data is empty");
    if (last_is_hogex && mweb.empty())
        return std::string("the last transaction is a HogEx but the mweb extension data is empty");
    return std::nullopt;
}

/// check_block_shape over the template transactions (coinbase excluded).
inline std::optional<std::string> check_block_shape(const std::vector<std::string>& txs_hex,
                                                    const std::string& mweb,
                                                    bool mweb_active)
{
    return check_block_shape(txs_hex.empty() ? nullptr : &txs_hex.back(), mweb, mweb_active);
}

/// True when a getblocktemplate-shaped "rules" array names the MWEB
/// deployment ("mweb", or "!mweb" for the forced-rule spelling).
inline bool template_rules_have_mweb(const nlohmann::json& tmpl)
{
    if (!tmpl.is_object() || !tmpl.contains("rules") || !tmpl["rules"].is_array())
        return false;
    for (const auto& r : tmpl["rules"])
        if (r.is_string() && (r == "mweb" || r == "!mweb"))
            return true;
    return false;
}

/// check_block_shape over a getblocktemplate-shaped json. Uses the same view
/// of the template the block assembler uses: the last "transactions" entry
/// that carries "data", the "mweb" field, and MWEB-active from the rules.
inline std::optional<std::string> check_template_shape(const nlohmann::json& tmpl)
{
    if (!tmpl.is_object())
        return std::nullopt;
    const std::string* last_tx_hex = nullptr;
    if (tmpl.contains("transactions") && tmpl["transactions"].is_array()) {
        const auto& txs = tmpl["transactions"];
        for (auto it = txs.rbegin(); it != txs.rend(); ++it) {
            if (it->is_object() && it->contains("data") && (*it)["data"].is_string()) {
                last_tx_hex = &(*it)["data"].get_ref<const std::string&>();
                break;
            }
        }
    }
    static const std::string kEmpty;
    const std::string& mweb = (tmpl.contains("mweb") && tmpl["mweb"].is_string())
        ? tmpl["mweb"].get_ref<const std::string&>() : kEmpty;
    return check_block_shape(last_tx_hex, mweb, template_rules_have_mweb(tmpl));
}

} // namespace core::coin
