// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// A digest of a UTXO DB (c2pool --utxo-digest <dir>): SHA256 over every
/// coin record ('C' key and value, in LevelDB key order), then the sync
/// state ('S') and the best block ('B') records. Two DBs with the same
/// digest hold the same set at the same block: a set built on one host and
/// copied to another is checked by digesting it on both.
///
/// Each record enters the hash as varint(key size) key varint(value size)
/// value (write_varint, LEB128), so no two record lists hash alike by
/// concatenation. An absent 'S' or 'B' record enters as an empty key.

#include "utxo.hpp"
#include "utxo_view_db.hpp"

#include <btclibs/crypto/sha256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace core {
namespace coin {

struct UtxoDigest {
    bool        ok{false};       // false: a scan error (the digest means nothing)
    std::string sha256_hex;      // the digest, bytes in hash output order
    uint64_t    coins{0};        // 'C' records
    uint64_t    record_bytes{0}; // their keys and values
    uint32_t    best_height{0};
    uint256     best_block;
    SyncState   sync;            // {anchor unknown} without an 'S' record
};

inline UtxoDigest utxo_digest(UTXOViewDB& db)
{
    UtxoDigest d;
    CSHA256 sha;
    auto feed = [&sha](const std::string& key, const std::vector<uint8_t>& value) {
        std::vector<uint8_t> buf;
        write_varint(buf, key.size());
        buf.insert(buf.end(), key.begin(), key.end());
        write_varint(buf, value.size());
        buf.insert(buf.end(), value.begin(), value.end());
        sha.Write(buf.data(), buf.size());
    };
    const bool scanned = db.for_each_record(std::string(1, 'C'),
        [&](const std::string& key, const std::vector<uint8_t>& value) {
            feed(key, value);
            ++d.coins;
            d.record_bytes += key.size() + value.size();
            return true;
        });
    if (!scanned)
        return d;
    for (const std::string& key : {UTXOViewDB::make_sync_key(), UTXOViewDB::make_state_key()}) {
        std::vector<uint8_t> value;
        if (db.get_record(key, value))
            feed(key, value);
        else
            feed(std::string(), {});
    }
    unsigned char out[CSHA256::OUTPUT_SIZE];
    sha.Finalize(out);
    static const char* hex = "0123456789abcdef";
    d.sha256_hex.reserve(2 * CSHA256::OUTPUT_SIZE);
    for (unsigned char c : out) {
        d.sha256_hex.push_back(hex[c >> 4]);
        d.sha256_hex.push_back(hex[c & 15]);
    }
    d.best_height = db.get_best_height();
    d.best_block = db.get_best_block();
    d.sync = db.get_sync_state();
    d.ok = true;
    return d;
}

} // namespace coin
} // namespace core
