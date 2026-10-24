// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin structural check of a block template's transactions (Litecoin).
//
// check_block_shape (mweb_shape.hpp) looks at the last transaction and the
// mweb field only. This walks every transaction's "data" the way litecoind
// deserializes it and refuses a template that can only yield a block
// litecoind rejects, so a parser or mempool bug costs a HOLD and a counter
// instead of a found block:
//   1 tx-undecodable            the hex does not walk as exactly one tx
//   5 tx-unknown-flags          serialization flags other than 0x01 / 0x08
//   3 tx-carries-mweb-data      an mw::Transaction in a block tx (mweb_node.cpp
//                               CheckBlock: unexpected-mweb-data)
//   2 tx-vin-empty/tx-vout-empty (consensus/tx_check.cpp)
//   4 mweb-flag-not-last        the MWEB flag on a tx that is not last
//     hogex-missing             MWEB active and the last tx is not a HogEx
//                               (mweb_node.cpp ContextualCheckBlock)
//   6 txid-mismatch             the template's "txid" is not the tx's txid
//                               (stratum merkle branches and shares use it)
//   7 pegins-missing / pegin-mismatch / extra-hogex-input
//                               pegin outputs of txs before the HogEx, in
//                               order, are exactly HogEx inputs 1.. (as
//                               mweb_node.cpp ContextualCheckBlock checks them)
//   8 fee-exceeds-coinbasevalue the listed fees sum above coinbasevalue
// plus a warning-only fee outlier (one tx's fee above 1 coin).
//
// Choke points: template ingress (MiningInterface::refresh_work), block
// assembly (rules 1-5 over the frozen job, build_block_from_stratum) and the
// LTC embedded TemplateBuilder. Header-only and pure over hex/json so the
// KATs can pin it directly. The mw::Transaction grammar is litecoind's
// (impl/ltc/coin/mweb_tx_wire.hpp).
// ---------------------------------------------------------------------------

#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <core/coin/mweb_shape.hpp>
#include <impl/ltc/coin/mweb_tx_wire.hpp>

#include <cstdint>
#include <cstdio>
#include <ios>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace core::coin {

/// What one serialized transaction is made of.
struct TxShape {
    int32_t version{0};
    uint8_t flags{0};                       // serialization flags (0 = legacy format)
    size_t n_vin{0}, n_vout{0};
    std::vector<std::pair<uint256, uint32_t>> prevouts;
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> vout;
    std::optional<uint8_t> mweb_presence;   // set when flag 0x08 is
    bool consumed_all{false};               // the walk ended at the last byte
    uint256 txid;                           // SHA256d(version | vin | vout | locktime)
};

namespace template_txs_detail {

inline std::optional<std::vector<unsigned char>> decode_hex(std::string_view hex)
{
    if (hex.size() % 2 != 0)
        return std::nullopt;
    std::vector<unsigned char> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int b = mweb_shape_detail::hex_byte_at(hex, i);
        if (b < 0)
            return std::nullopt;
        out[i] = static_cast<unsigned char>(b);
    }
    return out;
}

using Reader = ltc::coin::mweb_wire::SpanReader;

inline uint64_t compact(Reader& r) { return ltc::coin::mweb_wire::read_compact_size(r); }

inline void skip(Reader& r, uint64_t n)
{
    if (n > r.remaining())
        throw std::ios_base::failure("walk_tx_hex: end of data");
    r.pos += static_cast<size_t>(n);
}

inline void read_vin(Reader& r, TxShape& t, uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i) {
        uint256 h;
        ltc::coin::mweb_wire::read_bytes(r, h.data(), 32);
        uint32_t index = 0;
        for (int b = 0; b < 4; ++b)
            index |= static_cast<uint32_t>(ltc::coin::mweb_wire::read_u8(r)) << (8 * b);
        skip(r, compact(r));  // scriptSig
        skip(r, 4);           // sequence
        t.prevouts.emplace_back(h, index);
    }
    t.n_vin = static_cast<size_t>(n);
}

inline void read_vout(Reader& r, TxShape& t, uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t v = 0;
        for (int b = 0; b < 8; ++b)
            v |= static_cast<uint64_t>(ltc::coin::mweb_wire::read_u8(r)) << (8 * b);
        const uint64_t len = compact(r);
        if (len > r.remaining())
            throw std::ios_base::failure("walk_tx_hex: end of data");
        std::vector<uint8_t> spk(r.buf.begin() + r.pos, r.buf.begin() + r.pos + len);
        r.pos += static_cast<size_t>(len);
        t.vout.emplace_back(static_cast<int64_t>(v), std::move(spk));
    }
    t.n_vout = static_cast<size_t>(n);
}

} // namespace template_txs_detail

/// Walk one transaction as litecoind's UnserializeTransaction does (witness
/// and MWEB allowed). nullopt when the hex is not hex or the walk throws
/// where litecoind's would (truncation, non-canonical sizes, superfluous
/// witness, a HogEx without outputs, a malformed mw::Transaction). Unknown
/// flags stop the walk before the locktime (consumed_all stays false), as
/// litecoind throws there.
inline std::optional<TxShape> walk_tx_hex(std::string_view hex)
{
    namespace d = template_txs_detail;
    auto bytes = d::decode_hex(hex);
    if (!bytes)
        return std::nullopt;
    const std::span<const unsigned char> b(bytes->data(), bytes->size());
    try {
        d::Reader r(b);
        TxShape t;
        uint32_t ver = 0;
        for (int i = 0; i < 4; ++i)
            ver |= static_cast<uint32_t>(ltc::coin::mweb_wire::read_u8(r)) << (8 * i);
        t.version = static_cast<int32_t>(ver);

        size_t body_from = r.pos;  // where the stripped body (vin count) starts
        uint64_t n = d::compact(r);
        if (n == 0) {
            t.flags = ltc::coin::mweb_wire::read_u8(r);
            if (t.flags != 0) {
                body_from = r.pos;
                d::read_vin(r, t, d::compact(r));
                d::read_vout(r, t, d::compact(r));
            }
        } else {
            d::read_vin(r, t, n);
            d::read_vout(r, t, d::compact(r));
        }
        const size_t body_to = r.pos;

        uint8_t flags = t.flags;
        if (flags & 0x01) {
            flags ^= 0x01;
            bool any = false;
            for (size_t i = 0; i < t.n_vin; ++i) {
                const uint64_t items = d::compact(r);
                any = any || items > 0;
                for (uint64_t k = 0; k < items; ++k)
                    d::skip(r, d::compact(r));
            }
            if (!any)
                return std::nullopt;  // "Superfluous witness record"
        }
        if (flags & 0x08) {
            flags ^= 0x08;
            t.mweb_presence = ltc::coin::mweb_wire::read_u8(r);
            if (*t.mweb_presence == 0x01)
                ltc::coin::mweb_wire::read_mw_transaction(r);
            else if (t.n_vout == 0)
                return std::nullopt;  // "Missing HogEx output"
        }
        if (flags)
            return t;  // unknown flags: litecoind throws before the locktime

        const size_t lock_at = r.pos;
        d::skip(r, 4);
        t.consumed_all = r.remaining() == 0;

        std::vector<unsigned char> stripped;
        stripped.reserve(4 + (body_to - body_from) + 4);
        stripped.insert(stripped.end(), b.begin(), b.begin() + 4);
        stripped.insert(stripped.end(), b.begin() + body_from, b.begin() + body_to);
        stripped.insert(stripped.end(), b.begin() + lock_at, b.begin() + lock_at + 4);
        t.txid = Hash(std::span<const unsigned char>(stripped.data(), stripped.size()));
        return t;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
}

struct TemplateTxRefusal {
    std::string code;
    size_t index{0};       // into "transactions" (coinbase excluded)
    std::string txid;      // the entry's txid as computed, when it walked
    std::string detail;
};

/// Fee above which one entry is reported as an outlier (warning only).
inline constexpr int64_t kTemplateFeeOutlierSat = 100'000'000;

/// Rules 1-5 over serialized transactions (coinbase excluded), in order.
/// `shapes` receives the walked transactions when given.
inline std::optional<TemplateTxRefusal> check_tx_list(const std::vector<std::string_view>& txs_hex,
                                                     bool mweb_active,
                                                     std::vector<TxShape>* shapes = nullptr)
{
    std::vector<TxShape> local;
    std::vector<TxShape>& walked = shapes ? *shapes : local;
    walked.clear();
    walked.reserve(txs_hex.size());
    for (size_t i = 0; i < txs_hex.size(); ++i) {
        auto t = walk_tx_hex(txs_hex[i]);
        if (!t)
            return TemplateTxRefusal{"tx-undecodable", i, "", "does not deserialize"};
        const std::string txid = t->consumed_all ? t->txid.GetHex() : std::string();
        if (t->flags & ~0x09) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "0x%02x", t->flags);
            return TemplateTxRefusal{"tx-unknown-flags", i, txid, std::string("flags ") + buf};
        }
        if (!t->consumed_all)
            return TemplateTxRefusal{"tx-undecodable", i, "", "bytes after the locktime"};
        if (t->mweb_presence && *t->mweb_presence == 0x01)
            return TemplateTxRefusal{"tx-carries-mweb-data", i, txid, "an mw::Transaction in a block tx"};
        if (t->n_vin == 0)
            return TemplateTxRefusal{"tx-vin-empty", i, txid, "no inputs"};
        if (t->n_vout == 0)
            return TemplateTxRefusal{"tx-vout-empty", i, txid, "no outputs"};
        if ((t->flags & 0x08) && i + 1 != txs_hex.size())
            return TemplateTxRefusal{"mweb-flag-not-last", i, txid, "HogEx flag on a tx that is not last"};
        walked.push_back(std::move(*t));
    }
    if (mweb_active && (walked.empty() || !(walked.back().flags & 0x08)))
        return TemplateTxRefusal{"hogex-missing", walked.empty() ? 0 : walked.size() - 1,
                                 walked.empty() ? "" : walked.back().txid.GetHex(),
                                 "MWEB is active and the last tx is not a HogEx"};
    return std::nullopt;
}

/// Rule 7: the pegin outputs of the transactions before the HogEx, in order,
/// are exactly the HogEx inputs after the first (the previous HogEx's
/// output). Pass the walked transactions with the HogEx last.
inline std::optional<TemplateTxRefusal> check_hogex_pegins(const std::vector<TxShape>& txs)
{
    if (txs.empty() || !(txs.back().flags & 0x08))
        return std::nullopt;
    const TxShape& hogex = txs.back();
    const size_t hogex_index = txs.size() - 1;
    size_t next = 1;
    for (size_t i = 0; i + 1 < txs.size(); ++i) {
        for (size_t n = 0; n < txs[i].vout.size(); ++n) {
            const auto& spk = txs[i].vout[n].second;
            if (!ltc::coin::mweb_wire::pegin_kernel_of(std::span<const unsigned char>(spk.data(), spk.size())))
                continue;
            if (hogex.prevouts.size() <= next)
                return TemplateTxRefusal{"pegins-missing", i, txs[i].txid.GetHex(),
                                         "pegin output " + std::to_string(n) + " has no HogEx input"};
            const auto& in = hogex.prevouts[next++];
            if (in.first != txs[i].txid || in.second != n)
                return TemplateTxRefusal{"pegin-mismatch", i, txs[i].txid.GetHex(),
                                         "HogEx input " + std::to_string(next - 1)
                                         + " is not pegin output " + std::to_string(n)};
        }
    }
    if (next != hogex.prevouts.size())
        return TemplateTxRefusal{"extra-hogex-input", hogex_index, hogex.txid.GetHex(),
                                 std::to_string(hogex.prevouts.size() - next) + " HogEx input(s) match no pegin output"};
    return std::nullopt;
}

/// All rules over a getblocktemplate-shaped json (the "transactions" entries
/// carry "data", "txid" and optionally "fee"). `fee_outliers` counts entries
/// above kTemplateFeeOutlierSat (not a refusal).
inline std::optional<TemplateTxRefusal> check_template_txs(const nlohmann::json& tmpl,
                                                          size_t* fee_outliers = nullptr)
{
    if (fee_outliers)
        *fee_outliers = 0;
    if (!tmpl.is_object() || !tmpl.contains("transactions") || !tmpl["transactions"].is_array())
        return std::nullopt;
    const auto& entries = tmpl["transactions"];
    std::vector<std::string_view> hex;
    hex.reserve(entries.size());
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        if (!e.is_object() || !e.contains("data") || !e["data"].is_string())
            return TemplateTxRefusal{"tx-undecodable", i, "", "no data"};
        hex.emplace_back(e["data"].get_ref<const std::string&>());
    }

    std::vector<TxShape> txs;
    if (auto r = check_tx_list(hex, template_rules_have_mweb(tmpl), &txs))
        return r;

    int64_t fee_sum = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        const std::string txid = txs[i].txid.GetHex();
        if (!e.contains("txid") || !e["txid"].is_string() || e["txid"].get<std::string>() != txid)
            return TemplateTxRefusal{"txid-mismatch", i, txid,
                                     "template txid " + (e.contains("txid") ? e["txid"].dump() : std::string("missing"))};
        if (e.contains("fee") && e["fee"].is_number_integer()) {
            const int64_t fee = e["fee"].get<int64_t>();
            if (fee < 0)
                return TemplateTxRefusal{"fee-exceeds-coinbasevalue", i, txid, "negative fee"};
            if (fee > kTemplateFeeOutlierSat && fee_outliers)
                ++*fee_outliers;
            fee_sum = (fee > std::numeric_limits<int64_t>::max() - fee_sum)
                ? std::numeric_limits<int64_t>::max() : fee_sum + fee;
        }
    }

    if (auto r = check_hogex_pegins(txs))
        return r;

    if (tmpl.contains("coinbasevalue") && tmpl["coinbasevalue"].is_number_integer()) {
        const int64_t cbv = tmpl["coinbasevalue"].get<int64_t>();
        if (fee_sum > cbv)
            return TemplateTxRefusal{"fee-exceeds-coinbasevalue", 0, "",
                                     "fees " + std::to_string(fee_sum) + " > coinbasevalue " + std::to_string(cbv)};
    }
    return std::nullopt;
}

} // namespace core::coin
