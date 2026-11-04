// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// gettxoutsetinfo for a UTXO DB (c2pool --utxo-stats <dir>), to compare the
/// DOGE full set with Dogecoin Core 1.14.9's at the same best block.
///
/// Dogecoin Core 1.14.9 GetUTXOStats (src/rpc/blockchain.cpp:874-912, the
/// Bitcoin 0.14 per-tx CCoins layout) hashes, with a CHashWriter (double
/// SHA256): the best block hash, then for each txid in the coins DB's order
/// (key 'c' + the txid's 32 bytes, so the txid's serialized bytes compared
/// bytewise) the txid, for each unspent output in index order VARINT(i+1)
/// and the CTxOut (nValue int64 LE, the script with its CompactSize), then
/// VARINT(0). Nothing else: not the tx version, the height or the coinbase
/// flag. An output IsUnspendable (OP_RETURN first, or over 10,000 bytes)
/// never enters the set (CCoins::ClearUnspendable); a txid with no unspent
/// output has no entry. transactions / txouts count the entries and the
/// hashed outputs; total_amount sums their values (arith_uint256 in Core:
/// DOGE's supply passes INT64_MAX koinu).
///
/// This set is per outpoint ('C' + txid + index LE): the scan groups the
/// records of a txid (adjacent: the same 32-byte prefix) and hashes its
/// outputs in index order (index LE bytes do not sort numerically:
/// 256 = 00 01 00 00 comes before 1 = 01 00 00 00). So hash_serialized is
/// bit-exact with Core's at the same best block, given the same coins.
///
/// bytes_serialized is Core's 32 + GetValueSize() per txid: the CCoins
/// value (coins.h CCoins::Serialize: VARINT(nVersion), the header code, the
/// spentness mask, each output through CTxOutCompressor, VARINT(nHeight)).
/// This set does not keep the tx version: it is counted as one byte, exact
/// for every version 0..127 (DOGE's are 1 and 2).

#include "utxo.hpp"
#include "utxo_view_db.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace core {
namespace coin {

/// A 128-bit unsigned sum without __int128 (MSVC has none): Core sums in
/// arith_uint256, and DOGE's supply passes INT64_MAX koinu (2^64 later).
struct Amount128 {
    uint64_t hi{0};
    uint64_t lo{0};
    void add(uint64_t v)
    {
        lo += v;
        if (lo < v)
            ++hi;
    }
    bool operator==(const Amount128&) const = default;
};

struct UtxoStats {
    bool        ok{false};          // false: a scan error (nothing below means anything)
    uint32_t    best_height{0};     // the 'B' record
    uint256     best_block;
    SyncState   sync;               // the 'S' record
    uint64_t    transactions{0};    // txids with an unspent output
    uint64_t    txouts{0};          // unspent outputs
    Amount128   total_amount;       // koinu
    uint64_t    bytes_serialized{0};
    uint256     hash_serialized;    // GetHex() is gettxoutsetinfo's hash_serialized
    uint64_t    unspendable_skipped{0};  // records that IsUnspendable (the set never writes one)
};

/// `progress` (optional) is called every 10,000,000 records scanned.
UtxoStats utxo_stats(UTXOViewDB& db, const std::function<void(uint64_t records)>& progress = {});

/// Core's ValueFromAmount for an arith_uint256: "Q.RRRRRRRR".
std::string format_coin_amount(Amount128 koinu);

/// The decimal digits of a 128-bit amount.
std::string u128_to_string(Amount128 v);

} // namespace coin
} // namespace core
