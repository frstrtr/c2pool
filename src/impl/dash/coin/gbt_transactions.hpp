// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The transaction list of a dashd getblocktemplate reply, read into
/// DashWorkData (m_tx_data_hex, m_txs, m_tx_hashes, m_tx_fees, in order).
///
/// THE TXID. m_tx_hashes feeds the stratum merkle branches and so the header
/// root every miner hashes; it must be the id the block's merkle root commits
/// to, CTransaction::GetHash. From Dash Core v24 that is not the SHA256d of an
/// entry's bytes for a version 2 asset unlock: its quorum signing info is
/// zeroed before hashing (dash_txid.hpp), and the SHA256d of the whole bytes is
/// its instance hash instead. A header folded over instance hashes is rejected
/// by dashd as bad-txnmrklroot. dashd lists GetHash as each entry's "hash"
/// (rpc/mining.cpp getblocktemplate); it sends no "txid" key.
///
/// gbt_entry_txid is the per-entry rule, pure:
///   * the entry has a "hash": dashd's "hash". It is Core's own GetHash of the
///     very bytes the block body carries, so it is the id the validator
///     recomputes. When the bytes also deserialize completely, dash_txid of the
///     parsed tx is cross-checked against it; a disagreement can only mean a
///     defect in dash_txid, and is reported to the caller;
///   * no "hash", the bytes deserialized completely (no trailing bytes):
///     dash_txid of the parsed tx, the same derivation every other tx-hash
///     site of the node uses;
///   * neither: the SHA256d of the bytes, which is right only for a tx whose
///     txid covers all of its bytes (reported to the caller).

#include <impl/dash/coin/dash_txid.hpp>
#include "rpc_data.hpp"
#include "transaction.hpp"

#include <btclibs/util/strencodings.h>   // ParseHex, IsHex

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct GbtEntryTxid {
    enum class Source { ParsedTx, GbtHash, RawBytes };
    uint256 txid;                    // the id served
    Source  source{Source::ParsedTx};
    uint256 derived;                 // dash_txid of the parsed tx (null when it did not parse)
    bool    hash_disagrees{false};   // dashd's "hash" differs from `derived`
};

/// The txid of one getblocktemplate entry. `parsed` is the entry's tx when its
/// bytes deserialized completely, else nullptr; `gbt_hash` is the entry's
/// "hash" when it has one; `raw` is the entry's bytes.
inline GbtEntryTxid gbt_entry_txid(const MutableTransaction* parsed,
                                   const std::optional<uint256>& gbt_hash,
                                   std::span<const unsigned char> raw)
{
    GbtEntryTxid r;
    if (parsed != nullptr)
        r.derived = dash_txid(*parsed);
    if (gbt_hash.has_value()) {
        r.txid = *gbt_hash;
        r.source = GbtEntryTxid::Source::GbtHash;
        r.hash_disagrees = parsed != nullptr && r.derived != *gbt_hash;
        return r;
    }
    if (parsed != nullptr) {
        r.txid = r.derived;
        r.source = GbtEntryTxid::Source::ParsedTx;
        return r;
    }
    r.txid = dash_sha256d(raw);
    r.source = GbtEntryTxid::Source::RawBytes;
    return r;
}

/// What append_gbt_transactions saw that the caller should log.
struct GbtTxReadReport {
    struct Disagreement {
        size_t  index;
        uint256 gbt_hash;       // dashd's "hash" (the id served)
        uint256 derived_txid;   // dash_txid of the parsed tx (not served)
    };
    struct ParseFailure {
        size_t      index;
        std::string what;
        bool        used_gbt_hash;   // false: fell back to the SHA256d of the bytes
    };
    struct BadHash {                 // a "hash" that is not 64 hex chars: treated as absent
        size_t      index;
        std::string value;
    };
    struct TxidHashMismatch {        // both "txid" and "hash", and they differ ("hash" served)
        size_t  index;
        uint256 txid;
        uint256 hash;
    };
    std::vector<Disagreement>     disagreements;
    std::vector<ParseFailure>     parse_failures;
    std::vector<BadHash>          bad_hashes;
    std::vector<TxidHashMismatch> txid_hash_mismatches;
};

/// A 32-byte id in display hex (64 hex chars), as getblocktemplate lists it.
inline std::optional<uint256> gbt_id_field(const nlohmann::json& entry, const char* key)
{
    if (!entry.is_object() || !entry.contains(key)) return std::nullopt;
    const auto& v = entry[key];
    if (!v.is_string()) return std::nullopt;
    const std::string& s = v.get_ref<const std::string&>();
    if (s.size() != 64 || !IsHex(s)) return std::nullopt;
    return uint256S(s);
}

/// Append every entry of a getblocktemplate "transactions" array to w. An entry
/// is an object with "data" (and usually "hash", "fee"), or a bare hex string.
/// An entry that carries no transaction bytes -- an object without a "data"
/// string, an empty or non-hex body, any other JSON value -- fails the whole
/// read (std::runtime_error) and leaves w untouched: a template that silently
/// dropped one of dashd's txs would no longer be dashd's template. A tx that
/// fails to deserialize keeps its slot in m_txs (whatever the codec read) so
/// the four vectors stay index-aligned.
inline GbtTxReadReport append_gbt_transactions(const nlohmann::json& txs, DashWorkData& w)
{
    GbtTxReadReport rep;
    if (!txs.is_array()) return rep;
    std::vector<std::string> data_hexes;
    std::vector<Transaction> parsed_txs;
    std::vector<uint256>     hashes;
    std::vector<uint64_t>    fees;
    for (const auto& entry : txs) {
        const size_t index = w.m_tx_data_hex.size() + data_hexes.size();
        std::string data_hex;
        if (entry.is_object() && entry.contains("data") && entry["data"].is_string())
            data_hex = entry["data"].get<std::string>();
        else if (entry.is_string())
            data_hex = entry.get<std::string>();
        else
            throw std::runtime_error("getblocktemplate transaction " + std::to_string(index) +
                                     " carries no \"data\" string");
        if (data_hex.empty() || data_hex.size() % 2 != 0 || !IsHex(data_hex))
            throw std::runtime_error("getblocktemplate transaction " + std::to_string(index) +
                                     " \"data\" is not a hex transaction");
        const std::vector<unsigned char> raw = ParseHex(data_hex);

        // DASH tx codec: the version|(type<<16) field + DIP2 special-tx payload.
        MutableTransaction mtx;
        bool parsed = false;
        std::string parse_error;
        try {
            PackStream ps(raw);
            ps >> mtx;
            parsed = ps.empty();
            if (!parsed) parse_error = "trailing bytes after the transaction";
        } catch (const std::exception& ex) {
            parse_error = ex.what();
        }

        const std::optional<uint256> gbt_hash = gbt_id_field(entry, "hash");
        if (!gbt_hash && entry.is_object() && entry.contains("hash"))
            rep.bad_hashes.push_back({index, entry["hash"].dump()});
        if (const auto gbt_txid = gbt_id_field(entry, "txid");
            gbt_txid && gbt_hash && *gbt_txid != *gbt_hash)
            rep.txid_hash_mismatches.push_back({index, *gbt_txid, *gbt_hash});

        const GbtEntryTxid id = gbt_entry_txid(parsed ? &mtx : nullptr, gbt_hash,
                                               std::span<const unsigned char>(raw));
        if (id.hash_disagrees)
            rep.disagreements.push_back({index, *gbt_hash, id.derived});
        if (!parsed)
            rep.parse_failures.push_back(
                {index, parse_error, id.source == GbtEntryTxid::Source::GbtHash});

        uint64_t fee = 0;
        if (entry.is_object() && entry.contains("fee"))
            fee = entry["fee"].get<uint64_t>();

        data_hexes.push_back(std::move(data_hex));
        parsed_txs.emplace_back(mtx);   // Transaction(MutableTransaction) is explicit
        hashes.push_back(id.txid);
        fees.push_back(fee);
    }
    w.m_tx_data_hex.insert(w.m_tx_data_hex.end(), std::make_move_iterator(data_hexes.begin()),
                           std::make_move_iterator(data_hexes.end()));
    w.m_txs.insert(w.m_txs.end(), std::make_move_iterator(parsed_txs.begin()),
                   std::make_move_iterator(parsed_txs.end()));
    w.m_tx_hashes.insert(w.m_tx_hashes.end(), hashes.begin(), hashes.end());
    w.m_tx_fees.insert(w.m_tx_fees.end(), fees.begin(), fees.end());
    return rep;
}

} // namespace coin
} // namespace dash
