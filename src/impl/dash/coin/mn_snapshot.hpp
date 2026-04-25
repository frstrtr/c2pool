#pragma once

/// Phase C-PAY step 3 (Path C): DMN snapshot loader.
///
/// The forward-only per-block state machine (step 4) can only learn
/// about MNs that REGISTER inside our observation window — currently
/// from the header checkpoint forward (~height 2,400,000 on mainnet).
/// MNs registered before that point would be permanently unknown to
/// us, breaking GetProjectedMNPayees.
///
/// Path C bootstrap solution: ship a checkpointed DMN snapshot
/// (~660 KB binary) in-tree, validated against a hardcoded SHA256d
/// pin. At first run (mn_state_db empty), the loader populates
/// MnStateDb from the snapshot. The per-block state machine then
/// updates state forward from the snapshot's height.
///
/// Operator's fallback paths (the "RPC stays optional" promise):
///   1. `--dash-mn-snapshot PATH`  → operator-supplied file (overrides
///      the in-tree default; useful for testing or when running
///      against testnet/regtest)
///   2. Default in-tree file       → ships with the build
///   3. `--dashd-rpc HOST:PORT:USER:PASS` (existing flag) → if the
///      operator has a dashd anyway, prefer fresh state from
///      `protx list registered`. Wired in a follow-up commit; this
///      file's API is RPC-agnostic on purpose.
///
/// Refresh cadence: maintainer regenerates the in-tree snapshot once
/// per release cycle (or whenever the MN set has materially churned)
/// using the tools/dash_dump_dmn.py companion script (lands in a
/// follow-up commit). Stale snapshots are SAFE — the cross-check at
/// startup ("every MN in snapshot must also appear in current SML")
/// rejects MNs that have unregistered, and the per-block state
/// machine adds any MN that registered after the snapshot was cut.
///
/// File format (little-endian):
///   [4B  MAGIC]  = "DMNS"
///   [2B  VERSION]
///   [4B  snapshot_height]
///   [32B snapshot_block_hash]
///   [4B  entry_count]
///   for each entry:
///     [32B  proRegTxHash]
///     [pack(MNState): variable length]
///
/// Integrity: a hardcoded SHA256d of the entire file is checked at
/// load time against the file we read. Tampering or partial writes
/// fail loudly. The pin lives in `KNOWN_SNAPSHOTS[]` below.

#include <impl/dash/coin/mn_state_db.hpp>

#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct DmnSnapshot
{
    uint16_t version{2};  // v1: MN entries only. v2: + credit_pool_balance.
    uint32_t height{0};
    uint256  block_hash;
    std::vector<std::pair<uint256, MNState>> entries;
    // -1 = "not present in this snapshot" (v1 files OR v2 files where the
    // dumper couldn't query the balance). When >= 0, the loader seeds
    // credit_pool with this value so the bootstrap drain can apply
    // h=snapshot+1..tip deltas without double-counting.
    int64_t  credit_pool_balance{-1};
};

/// A single in-tree snapshot entry: file path (relative to the binary
/// or absolute) + the SHA256d hash that file MUST match.
struct DmnSnapshotPin
{
    const char* path;
    uint256     expected_sha256d;
};

/// Hardcoded list of trusted snapshots shipped with the build. Order
/// matters: the loader tries them in sequence, picking the FIRST one
/// whose file exists AND hashes correctly. Maintainers add a new
/// entry at the TOP each release; we keep the previous pins around
/// for old install paths that haven't pulled the new snapshot yet.
///
/// To produce a new entry:
///   c2pool-dash --dump-mn-snapshot data/dash/dmn_snapshot_h<H>.dat \
///               --dashd-rpc HOST:PORT:USER:PASS [--testnet]
/// then paste the printed `{ path, pin }` line at the TOP of v below.
inline const std::vector<DmnSnapshotPin>& known_snapshots()
{
    static const std::vector<DmnSnapshotPin> v = {
        // Phase C-PAY step 3c: first in-tree snapshot (2026-04-24).
        // Sourced from dashrpc on .24 against block 0000000000000008…
        // at height 2460249. 2936 active MN entries, 747904 B on disk.
        { "data/dash/dmn_snapshot_h2460249.dat",
          uint256S("4b5e59b62b7c9c867598a3fbbe5ade7a3f25f7273a142919a765e5c4cae601c7") },
    };
    return v;
}

inline constexpr std::array<uint8_t, 4> SNAPSHOT_MAGIC{'D', 'M', 'N', 'S'};
// v1: original (MN entries only).
// v2: appends 8-byte int64 credit_pool_balance after the MN entries
//     so bootstrap drain can re-seed CreditPoolDb at snapshot_height
//     and replay h=snapshot+1..tip deltas without double-counting.
inline constexpr uint16_t SNAPSHOT_VERSION_V1 = 1;
inline constexpr uint16_t SNAPSHOT_VERSION    = 2;

/// Compute SHA256d of a byte span — bit-identical to dashcore's
/// SHA256d so the maintainer-side script can use the same algorithm.
inline uint256 sha256d_bytes(std::span<const uint8_t> bytes)
{
    uint256 out;
    CHash256()
        .Write(std::span<const unsigned char>(bytes.data(), bytes.size()))
        .Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

/// Serialize a DmnSnapshot to the wire format described in the
/// preamble. Used by the maintainer-side script (via a small C++ tool
/// or by replicating the logic in Python) and by the in-test
/// round-trip self-test.
inline std::vector<uint8_t> encode_snapshot(const DmnSnapshot& snap)
{
    std::vector<uint8_t> out;
    out.reserve(64 + snap.entries.size() * 240);
    auto write_u16 = [&](uint16_t v) {
        out.push_back(uint8_t(v & 0xFF));
        out.push_back(uint8_t((v >> 8) & 0xFF));
    };
    auto write_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            out.push_back(uint8_t((v >> (i * 8)) & 0xFF));
    };
    auto write_bytes = [&](const uint8_t* p, size_t n) {
        out.insert(out.end(), p, p + n);
    };

    write_bytes(SNAPSHOT_MAGIC.data(), 4);
    write_u16(snap.version);
    write_u32(snap.height);
    write_bytes(snap.block_hash.data(), 32);
    write_u32(static_cast<uint32_t>(snap.entries.size()));
    for (const auto& [hash, state] : snap.entries) {
        write_bytes(hash.data(), 32);
        auto stream = ::pack(state);
        auto sp = stream.get_span();
        write_bytes(reinterpret_cast<const uint8_t*>(sp.data()), sp.size());
    }
    // v2 trailer: 8-byte int64 credit_pool_balance (LE). -1 sentinel
    // means "not known" (operator dumped without dashd RPC, or some
    // failure in the cbtx parse). Loader treats -1 as "do not seed".
    if (snap.version >= SNAPSHOT_VERSION) {
        uint64_t u = static_cast<uint64_t>(snap.credit_pool_balance);
        for (int i = 0; i < 8; ++i)
            out.push_back(uint8_t((u >> (i * 8)) & 0xFF));
    }
    return out;
}

/// Parse + integrity-check + size-validate a snapshot from raw bytes.
/// `expected_sha256d` is the trusted pin (uint256{} = skip integrity
/// check, used only by the round-trip self-test). Returns true on
/// fully-consumed parse + matching hash.
inline bool decode_snapshot(const std::vector<uint8_t>& bytes,
                            const uint256& expected_sha256d,
                            DmnSnapshot& out)
{
    // Integrity check.
    if (!expected_sha256d.IsNull()) {
        auto actual = sha256d_bytes(std::span<const uint8_t>(
            bytes.data(), bytes.size()));
        if (actual != expected_sha256d) {
            LOG_WARNING << "[MNS-SNAP] integrity check FAILED — "
                        << " expected=" << expected_sha256d.GetHex().substr(0, 16)
                        << " actual="   << actual.GetHex().substr(0, 16)
                        << " — REJECTING snapshot";
            return false;
        }
    }

    if (bytes.size() < 4 + 2 + 4 + 32 + 4) return false;
    size_t off = 0;
    auto take = [&](size_t n) -> const uint8_t* {
        if (off + n > bytes.size()) return nullptr;
        const uint8_t* p = bytes.data() + off;
        off += n;
        return p;
    };
    auto read_u16 = [&]() -> uint16_t {
        auto p = take(2);
        return p ? uint16_t(p[0]) | (uint16_t(p[1]) << 8) : 0;
    };
    auto read_u32 = [&]() -> uint32_t {
        auto p = take(4);
        if (!p) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= uint32_t(p[i]) << (i * 8);
        return v;
    };

    auto magic = take(4);
    if (!magic || std::memcmp(magic, SNAPSHOT_MAGIC.data(), 4) != 0) {
        LOG_WARNING << "[MNS-SNAP] bad magic (not DMNS file)";
        return false;
    }
    out.version = read_u16();
    if (out.version != SNAPSHOT_VERSION_V1
        && out.version != SNAPSHOT_VERSION) {
        LOG_WARNING << "[MNS-SNAP] unsupported version "
                    << out.version << " (expected "
                    << SNAPSHOT_VERSION_V1 << " or "
                    << SNAPSHOT_VERSION << ")";
        return false;
    }
    out.height = read_u32();
    auto bh = take(32);
    if (!bh) return false;
    std::memcpy(out.block_hash.data(), bh, 32);
    uint32_t n = read_u32();
    out.entries.clear();
    out.entries.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto h = take(32);
        if (!h) return false;
        uint256 pro;
        std::memcpy(pro.data(), h, 32);
        try {
            // Variable-length MNState — we let pack.hpp tell us how
            // many bytes it consumed via cursor_size() on the stream
            // tail. Note: PackStream::size() returns the UNDERLYING
            // vector size (not remaining bytes); cursor_size() is the
            // remaining-after-cursor count we want here.
            std::vector<uint8_t> tail(bytes.begin() + off, bytes.end());
            const size_t tail_initial = tail.size();
            ::PackStream ps(tail);
            MNState st;
            ps >> st;
            size_t consumed = tail_initial - ps.cursor_size();
            off += consumed;
            out.entries.emplace_back(pro, std::move(st));
        } catch (const std::exception& ex) {
            LOG_WARNING << "[MNS-SNAP] entry " << i
                        << " deserialize failed: " << ex.what();
            return false;
        }
    }
    // v2 trailer: 8-byte int64 credit_pool_balance.
    out.credit_pool_balance = -1;  // default for v1 OR missing trailer
    if (out.version >= SNAPSHOT_VERSION) {
        if (off + 8 > bytes.size()) {
            LOG_WARNING << "[MNS-SNAP] v2 file missing 8-byte credit_pool trailer";
            return false;
        }
        uint64_t u = 0;
        for (int i = 0; i < 8; ++i)
            u |= uint64_t(bytes[off + i]) << (i * 8);
        out.credit_pool_balance = static_cast<int64_t>(u);
        off += 8;
    }
    if (off != bytes.size()) {
        LOG_WARNING << "[MNS-SNAP] " << (bytes.size() - off)
                    << " trailing bytes — rejecting";
        return false;
    }
    return true;
}

/// Read a snapshot file from disk. Returns true on success
/// (file exists + integrity hash matches + parse fully consumes).
inline bool load_snapshot_file(const std::string& path,
                               const uint256& expected_sha256d,
                               DmnSnapshot& out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        LOG_WARNING << "[MNS-SNAP] cannot open " << path;
        return false;
    }
    std::vector<uint8_t> bytes(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    if (!decode_snapshot(bytes, expected_sha256d, out)) return false;
    LOG_INFO << "[MNS-SNAP] loaded " << out.entries.size()
             << " entries from " << path
             << " (height=" << out.height
             << " block=" << out.block_hash.GetHex().substr(0, 16) << ")";
    return true;
}

/// Walk known_snapshots() in order, return the first one that loads
/// cleanly. Operator-supplied --dash-mn-snapshot path takes priority
/// (passed in `cli_override_path`, empty = no override).
inline bool try_load_any_snapshot(const std::string& cli_override_path,
                                  DmnSnapshot& out)
{
    if (!cli_override_path.empty()) {
        // CLI override: the operator vouches for the file. We still
        // run the format parser (catches truncation / version drift)
        // but skip the SHA256d pin check.
        if (load_snapshot_file(cli_override_path, uint256{}, out)) {
            LOG_INFO << "[MNS-SNAP] using operator-supplied snapshot "
                     << cli_override_path << " (no pin check)";
            return true;
        }
        LOG_WARNING << "[MNS-SNAP] operator-supplied snapshot "
                    << cli_override_path << " failed to load — "
                       "falling back to in-tree pins";
    }
    for (const auto& pin : known_snapshots()) {
        if (load_snapshot_file(pin.path, pin.expected_sha256d, out)) {
            return true;
        }
    }
    return false;
}

/// Cross-check loaded snapshot against the current SML: every MN in
/// the snapshot SHOULD also appear in our current SML (because the
/// SML is the live MN set, and a snapshot MN should be in it unless
/// it has unregistered between snapshot-cut and now). MNs in the
/// snapshot that are NOT in the SML are dropped from the bootstrap
/// (they unregistered — we don't want stale state). MNs in the SML
/// that are NOT in the snapshot are kept as-is (they registered
/// after the snapshot was cut — the per-block state machine will
/// fill them in once it sees their ProRegTx, OR they'll have
/// scriptPayout=empty until then which causes [PAY] mismatch we can
/// log).
inline std::vector<std::pair<uint256, MNState>>
filter_snapshot_against_sml(const DmnSnapshot& snap,
                            const vendor::CSimplifiedMNList& sml)
{
    std::vector<std::pair<uint256, MNState>> filtered;
    filtered.reserve(snap.entries.size());
    size_t dropped = 0;
    for (const auto& [hash, state] : snap.entries) {
        bool in_sml = false;
        for (const auto& e : sml.mnList) {
            if (e.proRegTxHash == hash) { in_sml = true; break; }
        }
        if (in_sml) {
            filtered.emplace_back(hash, state);
        } else {
            ++dropped;
        }
    }
    if (dropped > 0) {
        LOG_INFO << "[MNS-SNAP] cross-check vs SML: dropped "
                 << dropped << " stale entries (unregistered since "
                 "snapshot was cut)";
    }
    return filtered;
}

} // namespace coin
} // namespace dash
