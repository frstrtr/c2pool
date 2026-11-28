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
///   * the bytes deserialized completely (no trailing bytes): dash_txid of the
///     parsed tx, the same derivation every other tx-hash site of the node
///     uses. dashd's "hash", when present, is cross-checked against it and a
///     disagreement is reported to the caller;
///   * the bytes did not deserialize: dashd's "hash";
///   * neither: the SHA256d of the bytes, which is right only for a tx whose
///     txid covers all of its bytes (reported to the caller).

#include <impl/dash/coin/dash_txid.hpp>
#include "rpc_data.hpp"
#include "transaction.hpp"

#include <btclibs/util/strencodings.h>   // ParseHex

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct GbtEntryTxid {
    enum class Source { ParsedTx, GbtHash, RawBytes };
    uint256 txid;
    Source  source{Source::ParsedTx};
    bool    hash_disagrees{false};   // ParsedTx only: dashd's "hash" differs from txid
};

/// The txid of one getblocktemplate entry. `parsed` is the entry's tx when its
/// bytes deserialized completely, else nullptr; `gbt_hash` is the entry's
/// "hash" when it has one; `raw` is the entry's bytes.
inline GbtEntryTxid gbt_entry_txid(const MutableTransaction* parsed,
                                   const std::optional<uint256>& gbt_hash,
                                   std::span<const unsigned char> raw)
{
    GbtEntryTxid r;
    if (parsed != nullptr) {
        r.txid = dash_txid(*parsed);
        r.source = GbtEntryTxid::Source::ParsedTx;
        r.hash_disagrees = gbt_hash.has_value() && *gbt_hash != r.txid;
        return r;
    }
    if (gbt_hash.has_value()) {
        r.txid = *gbt_hash;
        r.source = GbtEntryTxid::Source::GbtHash;
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
        uint256 txid;       // dash_txid of the parsed tx (the one used)
        uint256 gbt_hash;   // dashd's "hash"
    };
    struct ParseFailure {
        size_t      index;
        std::string what;
        bool        used_gbt_hash;   // false: fell back to the SHA256d of the bytes
    };
    std::vector<Disagreement> disagreements;
    std::vector<ParseFailure> parse_failures;
};

/// Append every entry of a getblocktemplate "transactions" array to w. An entry
/// is an object with "data" (and usually "hash", "fee"), or a bare hex string;
/// an entry with no bytes is skipped. A tx that fails to deserialize keeps its
/// slot in m_txs (whatever the codec read) so the four vectors stay
/// index-aligned.
inline GbtTxReadReport append_gbt_transactions(const nlohmann::json& txs, DashWorkData& w)
{
    GbtTxReadReport rep;
    if (!txs.is_array()) return rep;
    for (const auto& entry : txs) {
        std::string data_hex;
        if (entry.is_object() && entry.contains("data") && entry["data"].is_string())
            data_hex = entry["data"].get<std::string>();
        else if (entry.is_string())
            data_hex = entry.get<std::string>();
        if (data_hex.empty())
            continue;

        const size_t index = w.m_tx_data_hex.size();
        w.m_tx_data_hex.push_back(data_hex);
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
        w.m_txs.emplace_back(mtx);   // Transaction(MutableTransaction) is explicit

        std::optional<uint256> gbt_hash;
        if (entry.is_object() && entry.contains("hash") && entry["hash"].is_string())
            gbt_hash = uint256S(entry["hash"].get<std::string>());

        const GbtEntryTxid id = gbt_entry_txid(parsed ? &mtx : nullptr, gbt_hash,
                                               std::span<const unsigned char>(raw));
        w.m_tx_hashes.push_back(id.txid);
        if (id.hash_disagrees)
            rep.disagreements.push_back({index, id.txid, *gbt_hash});
        if (!parsed)
            rep.parse_failures.push_back(
                {index, parse_error, id.source == GbtEntryTxid::Source::GbtHash});

        uint64_t fee = 0;
        if (entry.is_object() && entry.contains("fee"))
            fee = entry["fee"].get<uint64_t>();
        w.m_tx_fees.push_back(fee);
    }
    return rep;
}

} // namespace coin
} // namespace dash
