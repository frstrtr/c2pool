#pragma once

/// UTXO set hashes, byte-compatible with Dash Core v23.1.7
/// `gettxoutsetinfo` (src/kernel/coinstats.cpp):
///
///   muhash             MuHash3072 over TxOutSer(outpoint, coin) per coin:
///                        outpoint (txid 32 B, n u32 LE)
///                        u32 LE  nHeight*2 + fCoinBase
///                        CTxOut  (nValue i64 LE, CompactSize + scriptPubKey)
///                      finalized SHA256 of the 384-byte normalized number.
///                      Order-independent.
///   hash_serialized_2  double-SHA256 stream: hashBlock first (PrepareHash),
///                      then per txid group, outputs in ascending vout
///                      (ApplyHash(HashWriter&)):
///                        txid, VARINT((nHeight*2 + fCoinBase) ? 1u : 0u),
///                        per output VARINT(n+1), script (CompactSize),
///                        VARINT(nValue); VARINT(0) after the group's last.
///                      The second line binds as `(...) ? 1u : 0u` (C++
///                      precedence): dashd v23.1.x folds the literal 1 for
///                      every real group, not the height code. That is the
///                      shipped behaviour and therefore the spec here; the
///                      W3 fold (impl/dash/coin/replay_utxo_fold.hpp
///                      apply_hash_group) transcribes the same line.
///
/// Both are printed by dashd through uint256::GetHex (reversed byte order);
/// so are ours (core uint256::GetHex).
///
/// Coins are fed one at a time. hash_serialized_2 needs txid groups to arrive
/// contiguously and in ascending txid byte order (memcmp over the 32 internal
/// bytes) — the LevelDB key order of Core's chainstate, of a `dumptxoutset`
/// file and of UTXOViewDB ('C' + txid + vout LE). Inside a group any order is
/// accepted (UTXOViewDB's LE vout key does not sort numerically above 255).
/// A group that comes back after a later txid, or a repeated outpoint,
/// refuses: the stream is not a set in key order.

#include "utxo.hpp"

#include <core/crypto/muhash.hpp>
#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>

#include <btclibs/crypto/sha256.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace core::coin {

/// kernel/coinstats.cpp TxOutSer(outpoint, coin): the muhash element bytes.
void TxOutSer(std::vector<unsigned char>& out, const Outpoint& outpoint, const Coin& coin);

/// Result of hashing a set.
struct UtxoSetHashes {
    uint256  best_block;          // hashBlock folded into hash_serialized_2
    uint256  muhash;              // valid when computed
    uint256  hash_serialized_2;   // valid when computed
    bool     have_muhash{false};
    bool     have_hash_serialized_2{false};
    uint64_t coins{0};
    uint64_t tx_groups{0};        // nTransactions
    uint64_t total_amount{0};     // sum of nValue (saturating; informational)
    uint64_t zero_value_coins{0}; // nValue == 0 (kept by Core, informational)
    uint64_t empty_script_coins{0};
};

class UtxoSetHasher {
public:
    struct Options {
        bool muhash = true;
        bool hash_serialized_2 = true;
    };

    explicit UtxoSetHasher(const uint256& best_block)
        : UtxoSetHasher(best_block, Options{}) {}
    UtxoSetHasher(const uint256& best_block, Options opts);

    /// Feed one coin. False = refused (see refusal()); every later call is a
    /// no-op that returns false.
    bool add(const Outpoint& outpoint, const Coin& coin);

    /// Close the last group and finalize. nullopt when refused.
    std::optional<UtxoSetHashes> finalize();

    const std::string& refusal() const { return m_refusal; }

private:
    void flush_group();

    Options       m_opts;
    UtxoSetHashes m_out;
    core::crypto::MuHash3072 m_muhash;
    CSHA256       m_serialized;   // first SHA256 round of HashWriter
    bool          m_have_group{false};
    uint256       m_group_txid;
    std::map<uint32_t, Coin> m_group;
    std::vector<unsigned char> m_buf;
    std::string   m_refusal;
    bool          m_finalized{false};
};

/// The two hashes of a UTXOViewDB, read straight from its LevelDB records:
/// 'B' (best block hash + height; the hash seeds hash_serialized_2) and every
/// 'C' + txid + vout LE -> serialize_coin record, in key order. The store must
/// be open. nullopt on a scan error, a malformed key or value, a missing 'B',
/// or an ordering refusal — never a partial answer.
struct UtxoViewDbHashes {
    UtxoSetHashes hashes;
    uint32_t      best_height{0};
};
std::optional<UtxoViewDbHashes> hash_utxo_view_db(core::LevelDBStore& store,
                                                  UtxoSetHasher::Options opts,
                                                  std::string& refusal);

/// UTXOViewDB 'B' record codec (best block hash 32 B + height u32 LE), the
/// layout UTXOViewDB::write_batch writes and load_best_block reads.
std::vector<uint8_t> encode_view_db_best(const uint256& best_block, uint32_t best_height);
bool decode_view_db_best(const std::vector<uint8_t>& data, uint256& best_block, uint32_t& best_height);

/// UTXOViewDB 'C' key for an outpoint.
std::string view_db_coin_key(const Outpoint& op);

/// Strict UTXOViewDB 'C' value decode (serialize_coin): three checked LEB128
/// varints, the script, and no trailing byte. False on any defect.
bool decode_view_db_coin(const std::vector<uint8_t>& value, Coin& coin);

} // namespace core::coin
