#pragma once

/// UTXO snapshot files in the Dash Core v23 / Bitcoin Core v22 `dumptxoutset`
/// layout, and their import into / dump from a UTXOViewDB.
///
/// File layout (Dash Core v23.1.7 src/node/utxo_snapshot.h SnapshotMetadata,
/// src/rpc/blockchain.cpp CreateUTXOSnapshot: `afile << metadata;` then per
/// chainstate cursor entry `afile << key; afile << coin;`):
///
///   uint256  base_blockhash    32 B, internal byte order
///   uint64   coins_count        8 B, LE
///   coins_count x
///     COutPoint                txid 32 B + n u32 LE
///     Coin                     VARINT(nHeight*2 + fCoinBase)
///                              VARINT(CompressAmount(nValue))
///                              ScriptCompression (coin_compressor.hpp)
///
/// No magic, no version, no height (those came with Bitcoin Core v28): the
/// height and the chain come from a pin and from the node's header chain.
/// Coins are in chainstate key order: txid bytes ascending, then vout
/// ascending (Core's key is 'C' + txid + VARINT(n), which sorts numerically).
///
/// A file may be split into parts that concatenate in order; each part has
/// its own size and sha256 in the pin.
///
/// UTXOViewDB records written by the importer (utxo_view_db.hpp schema):
///   'C' + txid + vout LE -> serialize_coin(Coin{value, script, height,
///                                               coinbase, pegout=false})
///   'B'                  -> base_blockhash + height LE (written last)

#include "utxo.hpp"
#include "utxo_set_hash.hpp"

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>

#include <btclibs/crypto/sha256.h>

#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace core::coin {

// ─── Named refusals ─────────────────────────────────────────────────────────

namespace snapshot_refusal {
inline constexpr const char* kOpenFailed          = "utxo-snapshot-open-failed";
inline constexpr const char* kTruncated           = "utxo-snapshot-truncated";
inline constexpr const char* kOverrun             = "utxo-snapshot-overrun";
inline constexpr const char* kUnordered           = "utxo-snapshot-unordered";
inline constexpr const char* kUnspendable         = "utxo-snapshot-unspendable";
inline constexpr const char* kBadCoin             = "utxo-snapshot-bad-coin";
inline constexpr const char* kSha256Mismatch      = "utxo-snapshot-sha256-mismatch";
inline constexpr const char* kBaseMismatch        = "utxo-snapshot-base-mismatch";
inline constexpr const char* kCountMismatch       = "utxo-snapshot-count-mismatch";
inline constexpr const char* kNotInHeaderChain    = "utxo-snapshot-base-not-in-header-chain";
inline constexpr const char* kNoHeaderChain       = "utxo-snapshot-no-header-chain";
inline constexpr const char* kMuhashMismatch      = "utxo-snapshot-muhash-mismatch";
inline constexpr const char* kHashSer2Mismatch    = "utxo-snapshot-hash-serialized-2-mismatch";
inline constexpr const char* kNoPin               = "utxo-snapshot-no-pin";
inline constexpr const char* kDbHeld              = "utxo-snapshot-db-held";
inline constexpr const char* kDbOpenFailed        = "utxo-snapshot-db-open-failed";
inline constexpr const char* kDbNotEmpty          = "utxo-snapshot-db-not-empty";
inline constexpr const char* kDbWriteFailed       = "utxo-snapshot-db-write-failed";
inline constexpr const char* kChangedDuringImport = "utxo-snapshot-changed-during-import";
inline constexpr const char* kWriteFailed         = "utxo-snapshot-write-failed";
inline constexpr const char* kDbNoBest            = "utxo-snapshot-db-no-best-block";
inline constexpr const char* kDbCorrupt           = "utxo-snapshot-db-corrupt";
inline constexpr const char* kCountChanged        = "utxo-snapshot-db-count-changed";
inline constexpr const char* kSpentShapedCoin     = "utxo-snapshot-spent-shaped-coin";
} // namespace snapshot_refusal

// ─── Metadata ───────────────────────────────────────────────────────────────

inline constexpr size_t SNAPSHOT_METADATA_SIZE = 40;

struct SnapshotMetadata {
    uint256  base_blockhash;
    uint64_t coins_count{0};
};

struct SnapshotPartDigest {
    std::string path;
    uint64_t    bytes{0};
    std::string sha256;   // lowercase hex, sha256sum order
};

/// Lowercase hex of raw bytes (sha256sum order, not reversed).
std::string bytes_to_hex(const unsigned char* p, size_t n);

/// Strict 64-hex-digit parse into a uint256 in GetHex (display) order.
bool parse_hash_hex(const std::string& hex, uint256& out);

// ─── Reader ─────────────────────────────────────────────────────────────────

/// Streaming reader. Every refusal is named (snapshot_refusal) and leaves the
/// reader refused; nothing is buffered beyond one read block.
class SnapshotReader {
public:
    explicit SnapshotReader(std::vector<std::string> part_paths, size_t buffer_bytes = 1 << 20);
    ~SnapshotReader();
    SnapshotReader(const SnapshotReader&) = delete;
    SnapshotReader& operator=(const SnapshotReader&) = delete;

    /// Open the first part and read the 40-byte metadata.
    bool open();
    const SnapshotMetadata& metadata() const { return m_meta; }

    /// Next coin. False when coins_count coins have been read (refused() is
    /// then false) or on a refusal.
    bool next(Outpoint& outpoint, Coin& coin);

    /// After the last coin: the stream must end exactly there (else overrun);
    /// completes the per-part digests.
    bool finish();

    bool refused() const { return !m_refusal.empty(); }
    const std::string& refusal() const { return m_refusal; }
    const std::string& detail() const { return m_detail; }
    uint64_t coins_read() const { return m_coins; }
    uint64_t bytes_read() const { return m_total_bytes; }
    const std::vector<SnapshotPartDigest>& parts() const { return m_parts; }

    // Stream interface for the coin codec (coin_compressor.hpp).
    bool read(unsigned char* dst, size_t n);
    bool skip(size_t n);

private:
    bool fill();
    bool refuse(const char* name, std::string detail);
    void close_part();

    std::vector<std::string> m_paths;
    size_t m_part_index{0};
    std::FILE* m_file{nullptr};
    std::vector<unsigned char> m_buf;
    size_t m_pos{0};
    size_t m_len{0};
    CSHA256 m_part_sha;
    uint64_t m_part_bytes{0};
    uint64_t m_total_bytes{0};
    bool m_eof_all{false};
    std::vector<SnapshotPartDigest> m_parts;

    SnapshotMetadata m_meta;
    uint64_t m_coins{0};
    bool m_have_prev{false};
    Outpoint m_prev;
    std::string m_refusal;
    std::string m_detail;
};

// ─── Writer ─────────────────────────────────────────────────────────────────

/// Writes `path`.incomplete and renames it to `path` on a successful finish()
/// (the dumptxoutset convention). Coins must be appended in key order.
class SnapshotWriter {
public:
    explicit SnapshotWriter(std::string path);
    ~SnapshotWriter();
    SnapshotWriter(const SnapshotWriter&) = delete;
    SnapshotWriter& operator=(const SnapshotWriter&) = delete;

    bool begin(const SnapshotMetadata& meta);
    bool append(const Outpoint& outpoint, const Coin& coin);
    bool finish();

    const std::string& refusal() const { return m_refusal; }
    const std::string& detail() const { return m_detail; }
    std::string sha256_hex() const { return m_sha256; }
    uint64_t bytes() const { return m_bytes; }
    uint64_t coins() const { return m_coins; }

private:
    bool write(const unsigned char* p, size_t n);
    bool refuse(const char* name, std::string detail);

    std::string m_path;
    std::string m_tmp_path;
    std::FILE* m_file{nullptr};
    CSHA256 m_sha;
    std::string m_sha256;
    uint64_t m_bytes{0};
    SnapshotMetadata m_meta;
    uint64_t m_coins{0};
    bool m_have_prev{false};
    Outpoint m_prev;
    std::vector<unsigned char> m_buf;
    bool m_finished{false};
    std::string m_refusal;
    std::string m_detail;
};

// ─── Pin ────────────────────────────────────────────────────────────────────

inline constexpr const char* kSnapshotPinMagic = "c2pool-utxo-snapshot/1";
inline constexpr const char* kSnapshotFormat   = "dashcore-v23-utxo-v1";

/// What a snapshot must match before it is loaded (the `.inc` pin of the
/// design, section 5.4). Hashes are in GetHex order; part sha256 in
/// sha256sum order.
struct SnapshotPin {
    std::string coin;
    std::string network;
    uint32_t    height{0};
    uint256     blockhash;
    uint64_t    coins{0};
    uint256     muhash;
    std::optional<uint256> hash_serialized_2;
    std::string format{kSnapshotFormat};
    struct Part {
        uint64_t    size{0};
        std::string sha256;
    };
    std::vector<Part> parts;   // empty = file bytes not pinned (explicit-expect path only)
    std::string url;
    std::string sources;
    std::string generated;
};

/// The pin's digest domain (the MN checkpoint's rule): SHA-256 over every line
/// except blank lines, `#` comments and the `digest` line, each stripped of
/// trailing whitespace and terminated by '\n', in order. Lowercase hex.
std::string snapshot_pin_digest(const std::string& text);

/// Parse + validate a pin (plain lines, or the `.inc` string-literal form).
/// Fail-closed: any unknown, duplicate, missing or malformed line, a wrong
/// magic or format, or a digest that does not match.
std::optional<SnapshotPin> parse_snapshot_pin(const std::string& text, std::string& error);

/// Render a pin as text lines, digest last.
std::string render_snapshot_pin(const SnapshotPin& pin);

/// Render a pin in the checkpoint `.inc` style: one "line\n" literal per line.
std::string render_snapshot_pin_inc(const SnapshotPin& pin);

// ─── Read-only scan of a snapshot file ──────────────────────────────────────

struct SnapshotScanResult {
    bool ok{false};
    std::string refusal;
    std::string detail;
    SnapshotMetadata meta;
    UtxoSetHashes hashes;
    std::vector<SnapshotPartDigest> parts;
    uint64_t bytes{0};
    uint64_t special_scripts[6]{};   // compressed-form counts by nSize 0..5
    uint64_t raw_scripts{0};
};

struct SnapshotScanOptions {
    UtxoSetHasher::Options hashes;
    uint64_t log_every{0};
    std::function<void(const std::string&)> log;
};

/// Decode a whole file: metadata, every coin (order, codec, unspendable,
/// truncation, overrun), the two set hashes (hash_serialized_2 seeded with
/// the base blockhash) and the per-part sha256. Writes nothing.
SnapshotScanResult scan_utxo_snapshot(const std::vector<std::string>& parts,
                                      const SnapshotScanOptions& opts = {});

// ─── Import ─────────────────────────────────────────────────────────────────

/// Block hash of the node's header chain at a height; nullopt = not held.
using HeaderLookup = std::function<std::optional<uint256>(uint32_t height)>;

struct SnapshotImportOptions {
    /// Required: the base must be our header at pin.height.
    HeaderLookup hash_at_height;
    /// An offline tool has no header chain. Only then may the check be
    /// skipped, and only by saying so here; the node re-checks at open.
    bool offline_no_header_chain{false};
    size_t batch_records{16384};
    uint64_t log_every{500000};
    std::function<void(const std::string&)> log;
    core::LevelDBOptions db_options = default_db_options();
    /// TEST ONLY: fail the write pass after this many coins have been
    /// committed (exercises the wipe-back-to-empty path). 0 = off.
    uint64_t test_fail_write_after{0};
    /// Records written in the final synced batch together with 'B' (a node's
    /// sync state and assumed-base record), so the set and what describes it
    /// land at once or not at all.
    std::vector<std::pair<std::string, std::vector<uint8_t>>> final_records;
    /// Refuse a coin with value 0 and an empty script. Core stores one like
    /// any other coin, but core::coin::Coin::is_spent() reads it as "absent",
    /// so a node whose paths rely on is_spent() refuses the set instead of
    /// drifting silently (utxo-snapshot-spent-shaped-coin).
    bool refuse_spent_shaped_coins{false};

    static core::LevelDBOptions default_db_options()
    {
        core::LevelDBOptions o;
        o.write_buffer_size = 64 * 1024 * 1024;
        o.block_cache_size = 32 * 1024 * 1024;
        return o;
    }
};

struct SnapshotImportResult {
    bool ok{false};
    std::string refusal;
    std::string detail;
    uint64_t coins{0};
    uint256  base_blockhash;
    uint32_t best_height{0};
    UtxoSetHashes hashes;
    std::vector<SnapshotPartDigest> parts;
    double verify_seconds{0};
    double write_seconds{0};
};

/// Import `parts` into the EMPTY UTXOViewDB at `db_path`.
///
/// Two passes. The verify pass decodes the whole file and checks, in order:
/// metadata base == pin.blockhash, coins_count == pin.coins, the base is the
/// header at pin.height, every coin (codec, key order, no unspendable
/// script), no truncation / overrun, every part's size and sha256, muhash ==
/// pin.muhash, hash_serialized_2 == pin's when it carries one. Nothing is
/// written before all of them agree. The write pass decodes the file again
/// into 'C' records in batches, then writes 'B' last, synced. If the file
/// bytes differ from the verify pass, or a write fails, every key is wiped
/// and the DB is left empty.
///
/// The DB must be empty (no key at all) and not held by another process.
SnapshotImportResult import_utxo_snapshot(const std::vector<std::string>& parts,
                                          const std::string& db_path,
                                          const SnapshotPin& pin,
                                          const SnapshotImportOptions& opts);

// ─── Dump ───────────────────────────────────────────────────────────────────

struct SnapshotDumpResult {
    bool ok{false};
    std::string refusal;
    std::string detail;
    uint64_t coins{0};
    uint256  base_blockhash;
    uint32_t base_height{0};
    UtxoSetHashes hashes;
    std::string sha256;
    uint64_t bytes{0};
};

/// Write the set of an open UTXOViewDB as a snapshot file at `out_path`:
/// 'B' is the base, the 'C' records are counted first, then written grouped
/// per txid in ascending vout (UTXOViewDB keys sort vout LE). The two hashes
/// are taken over the coins as written. The pegout flag is not part of the
/// Core layout and is not carried.
SnapshotDumpResult dump_utxo_snapshot(core::LevelDBStore& store, const std::string& out_path);

// ─── DB helpers ─────────────────────────────────────────────────────────────

/// True when the LevelDB LOCK of `dir` is held: by this process (an open
/// descriptor of <dir>/LOCK in /proc/self/fd, holder = our pid, checked first
/// so the probe below never runs where closing a descriptor would drop our own
/// record lock), or by another process (fcntl F_GETLK on <dir>/LOCK, the
/// record lock LevelDB's env_posix takes). A missing LOCK file is not held.
/// Without /proc (not Linux) the self check is skipped: there the caller must
/// not probe a DB it has open.
bool leveldb_dir_lock_held(const std::string& dir, long* holder_pid = nullptr);

/// True when the store holds no key at all.
bool leveldb_store_empty(core::LevelDBStore& store);

/// Delete every key in batches, then compact. True when the store is empty
/// afterwards.
bool leveldb_wipe_all(core::LevelDBStore& store, size_t batch_records = 16384);

} // namespace core::coin
