// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH FULL-HISTORY REPLAY — W2: the multi-peer archival BULK block-fetch lane.
//
// Design source: docs/DASH_FULL_HISTORY_REPLAY_MODE.md (frstrtr/the), §4.1/§4.3
// and WP table §6 (W2). This work package supplies the TRANSPORT for the replay
// fold (W1): it walks the header chain back to GENESIS (extending the existing
// 2400000 fast-start anchor), then getdata's full block bodies in large
// pipelined batches ACROSS the coin-P2P peer pool, verifies each body against
// its PoW header, hands it to the fold consumer strictly in height order, and
// PRUNES it — bodies are never persisted (fetch → fold → prune; ~30-40 GB
// total stream, bounded work-ahead buffer, nothing retained).
//
// ── What lives here (all io-thread confined, KAT-able pieces pure) ─────────
//
//   * HeaderBackfill    — genesis→anchor header walker. The main HeaderChain
//     fast-starts at 2400000 (header_chain.hpp:92) and its height index only
//     covers anchor→tip; replay needs per-height hashes from genesis. The
//     backfill walks FORWARD from the known genesis hash, X11-PoW-checking and
//     prev-linking every header, and MUST terminate by producing exactly the
//     fast-start anchor hash at the anchor height (the JOIN CHECK). Because
//     every header commits its predecessor, a matching anchor hash pins the
//     entire pre-anchor segment byte-for-byte down to genesis — the same
//     induction the spec's §4.2 layer-2 argument rides. Join mismatch is
//     fail-closed and LOUD: it means a hostile peer or a wrong chain, and the
//     lane refuses to fetch a single body off an unpinned index.
//
//   * BulkBlockScheduler — pure request planner. Range-partitions the wanted
//     height span into contiguous per-peer batches, caps in-flight requests
//     per peer, re-requests on timeout / notfound / peer loss (rotating away
//     from the peer that failed), and tallies per-peer throughput for the
//     [BULK] telemetry line. No sockets, no clocks of its own — every decision
//     is a function of (now, peers, cursor) so the KATs drive it directly.
//
//   * BulkFetchLane      — the driver glue. Owns the work-ahead body buffer,
//     the in-order delivery loop into IReplayBlockConsumer, the resumable
//     high-water cursor (ReplayCursorStore), the optional capture writer, and
//     the telemetry. Wired to the CoinClient via narrow seams (function
//     injections + the headers/body demux filters) so it can be stood up in a
//     test with no network at all.
//
//   * IReplayBlockConsumer — the W1 fold seam. W2 ships the interface plus a
//     counting stub (CountingReplayConsumer) and the capture consumer; the W1
//     fold engine implements the same interface and simply replaces the stub.
//
//   * BulkCaptureWriter / --replay-bulk-capture — OPTIONAL side utility: cache
//     the raw bodies into append-only segment files on a fleet host so test
//     re-folds do not re-pull 30-40 GB from the network. Capture is a
//     CONSUMER decoration, never a requirement — the production flow stays
//     fetch → fold → prune.
//
// ── PRIORITY INVARIANT: bulk NEVER starves the tip lane ────────────────────
//
// The tip lane (new-block inv → getheaders + tracked body pull, p2p_client.hpp
// BODY_REREQUEST_*) is the money path; bulk is strictly lower priority:
//
//   1. bulk bodies are never requested from the PRIMARY peer while any other
//      handshaked peer exists (the primary carries every request/response leg
//      — mnlistdiff/qrinfo/govsync — and the tip-follow getheaders default);
//   2. NO new bulk getdata is issued while a tracked tip body is outstanding
//      (tip_busy seam = pending_body_count() > 0) — in-flight bulk requests
//      complete, fresh ones wait;
//   3. bulk never requests within TIP_EXCLUSION blocks of the header tip: the
//      live edge belongs to the tip lane, and a bulk-consumed body demuxed
//      away from the full_block event must never be one the live ingest legs
//      were waiting for;
//   4. per-peer in-flight caps keep every socket's reply queue short, so a
//      tip-lane request issued to a bulk-serving peer is answered within a
//      bounded backlog (~cap × avg body size), not behind a megabatch.
//
// ── Verification per body (spec §4.1: "nothing else in the body is read") ──
//
// A body is accepted only if (a) X11(its 80-byte header) equals the hash the
// scheduler requested — which the backfill/header-chain index pinned under
// PoW + the anchor join — and (b) the tx set folds to the header's committed
// hashMerkleRoot via the CVE-2012-2459-guarded fold the serve path already
// uses (block_producer.hpp block_body_binds_to_header). A body failing (b) is
// counted corrupt and re-requested from a different peer. No script
// execution, no UTXO reads — acceptance-predicate skipping per spec §4.2.
//
// Feature-flagged (--replay-bulk / --replay-bulk-capture): absent, nothing
// here is constructed and no CoinClient filter is registered — the serve path
// is byte-identical. DASH-lane only; header-only to match the sibling leaves.

#include "block.hpp"
#include "block_producer.hpp"   // block_body_binds_to_header (body↔header bind)
#include "header_chain.hpp"     // check_pow / x11_hash / DashChainParams

#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

// DIP0003 activation on mainnet — the first height whose body the fold
// consumes (spec §4.1: "Replay from DIP3 activation (h=1028160) forward").
static constexpr uint32_t MAINNET_DIP3_HEIGHT = 1028160;

// ── W1 fold seam ───────────────────────────────────────────────────────────
//
// The bulk lane hands every verified body to exactly ONE consumer, strictly
// in ascending height order with no gaps (the fold is a strict left fold over
// the chain). Returning false REFUSES the block: the lane fails closed with a
// named cause and stops fetching — a fold that cannot proceed must never be
// silently skipped past (a gap would desync every subsequent root check).
class IReplayBlockConsumer
{
public:
    virtual ~IReplayBlockConsumer() = default;
    /// `height`/`hash` are pinned by the PoW header index; `block` has passed
    /// the merkle body↔header bind. The reference is only valid for the call —
    /// the lane PRUNES the body immediately after (consumers must copy what
    /// they keep, which for the W1 fold is derived state, never the body).
    virtual bool on_replay_block(uint32_t height, const uint256& hash,
                                 const BlockType& block) = 0;
};

// Counting stub consumer: the W2 stand-in for the W1 fold. Counts blocks and
// bytes, asserts the in-order/no-gap contract, and can be armed to refuse at
// a given height (fail-closed KAT). Also the production default under
// --replay-bulk until W1 lands — throughput soaks measure the transport with
// exactly this consumer.
class CountingReplayConsumer : public IReplayBlockConsumer
{
    uint64_t m_blocks{0};
    uint64_t m_bytes{0};
    uint64_t m_txs{0};
    uint32_t m_last_height{0};
    bool     m_have_last{false};
    bool     m_order_violated{false};
    uint32_t m_refuse_at{0};        // 0 = never refuse

public:
    void set_refuse_at(uint32_t h) { m_refuse_at = h; }

    bool on_replay_block(uint32_t height, const uint256& /*hash*/,
                         const BlockType& block) override
    {
        if (m_refuse_at != 0 && height >= m_refuse_at)
            return false;
        if (m_have_last && height != m_last_height + 1)
            m_order_violated = true;
        m_last_height = height;
        m_have_last = true;
        ++m_blocks;
        m_txs += block.m_txs.size();
        auto packed = ::pack(block);
        m_bytes += packed.size();
        return true;
    }

    uint64_t blocks() const { return m_blocks; }
    uint64_t bytes() const { return m_bytes; }
    uint64_t txs() const { return m_txs; }
    uint32_t last_height() const { return m_last_height; }
    bool order_violated() const { return m_order_violated; }
};

// ── Resumable high-water cursor ────────────────────────────────────────────
//
// One tiny versioned file: the highest height DELIVERED to the consumer plus
// its hash. Written atomically (tmp + rename) so a crash can never leave a
// torn cursor; a stale-but-consistent cursor only costs re-fetching the tail
// since the last write. The HASH is stored alongside the height so a resumed
// lane can prove it is still on the same chain before trusting the cursor
// (mismatch ⇒ refuse with a named cause, never silently re-fold a different
// branch — the standing "version it so an old binary fails loud" trap).
class ReplayCursorStore
{
public:
    struct Cursor
    {
        uint32_t height{0};
        uint256  hash;
    };

private:
    std::string m_path;

public:
    explicit ReplayCursorStore(std::string path) : m_path(std::move(path)) {}

    const std::string& path() const { return m_path; }

    std::optional<Cursor> load() const
    {
        std::ifstream in(m_path);
        if (!in) return std::nullopt;
        std::string magic, version, hash_hex;
        uint32_t height = 0;
        in >> magic >> version >> height >> hash_hex;
        if (!in || magic != "c2pool-replay-cursor" || version != "v1" ||
            hash_hex.size() != 64)
        {
            LOG_WARNING << "[BULK] cursor file " << m_path
                        << " unreadable or wrong version — ignoring (restart "
                           "from configured start height)";
            return std::nullopt;
        }
        Cursor c;
        c.height = height;
        c.hash.SetHex(hash_hex);
        return c;
    }

    bool store(const Cursor& c) const
    {
        const std::string tmp = m_path + ".tmp";
        {
            std::ofstream out(tmp, std::ios::trunc);
            if (!out) return false;
            out << "c2pool-replay-cursor v1 " << c.height << " "
                << c.hash.GetHex() << "\n";
            if (!out) return false;
        }
        std::error_code ec;
        std::filesystem::rename(tmp, m_path, ec);
        return !ec;
    }
};

// ── Capture side-channel (--replay-bulk-capture DIR) ───────────────────────
//
// Append-only segment files, SEGMENT_SPAN blocks each, one length-prefixed
// record per block: [u32 magic][u32 height][32B hash][u32 size][size bytes].
// One file per 10k blocks keeps the fleet cache to ~150 files/1.49M blocks
// instead of 1.49M inodes, and a torn tail record (crash mid-append) is
// detected by the magic/size framing on read and simply truncates that
// segment's usable prefix. This is a TEST-REFOLD cache, not consensus state.
class BulkCaptureWriter
{
public:
    static constexpr uint32_t RECORD_MAGIC = 0x43325242;   // "C2RB"
    static constexpr uint32_t SEGMENT_SPAN = 10000;

    struct Record
    {
        uint32_t height{0};
        uint256  hash;
        std::vector<uint8_t> bytes;
    };

private:
    std::string m_dir;
    std::ofstream m_out;
    uint32_t m_open_segment{UINT32_MAX};
    uint64_t m_records{0};
    uint64_t m_bytes{0};
    bool     m_failed{false};

    static void put_u32(std::ofstream& out, uint32_t v)
    {
        unsigned char b[4] = {
            static_cast<unsigned char>(v & 0xFF),
            static_cast<unsigned char>((v >> 8) & 0xFF),
            static_cast<unsigned char>((v >> 16) & 0xFF),
            static_cast<unsigned char>((v >> 24) & 0xFF)};
        out.write(reinterpret_cast<const char*>(b), 4);
    }

    static bool get_u32(std::ifstream& in, uint32_t& v)
    {
        unsigned char b[4];
        if (!in.read(reinterpret_cast<char*>(b), 4)) return false;
        v = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
            (static_cast<uint32_t>(b[2]) << 16) |
            (static_cast<uint32_t>(b[3]) << 24);
        return true;
    }

public:
    explicit BulkCaptureWriter(std::string dir) : m_dir(std::move(dir))
    {
        std::error_code ec;
        std::filesystem::create_directories(m_dir, ec);
        if (ec)
        {
            LOG_ERROR << "[BULK] capture dir " << m_dir
                      << " cannot be created: " << ec.message()
                      << " — capture DISABLED (fetch/fold unaffected)";
            m_failed = true;
        }
    }

    static std::string segment_name(uint32_t segment_base)
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "blocks_%09u.seg", segment_base);
        return buf;
    }

    bool failed() const { return m_failed; }
    uint64_t records() const { return m_records; }
    uint64_t bytes_written() const { return m_bytes; }
    const std::string& dir() const { return m_dir; }

    bool append(uint32_t height, const uint256& hash,
                const std::vector<uint8_t>& raw)
    {
        if (m_failed) return false;
        const uint32_t segment = (height / SEGMENT_SPAN) * SEGMENT_SPAN;
        if (segment != m_open_segment || !m_out.is_open())
        {
            if (m_out.is_open()) m_out.close();
            const std::string path =
                (std::filesystem::path(m_dir) / segment_name(segment)).string();
            m_out.open(path, std::ios::binary | std::ios::app);
            if (!m_out)
            {
                LOG_ERROR << "[BULK] capture segment " << path
                          << " cannot be opened — capture DISABLED";
                m_failed = true;
                return false;
            }
            m_open_segment = segment;
        }
        put_u32(m_out, RECORD_MAGIC);
        put_u32(m_out, height);
        m_out.write(reinterpret_cast<const char*>(hash.data()), 32);
        put_u32(m_out, static_cast<uint32_t>(raw.size()));
        m_out.write(reinterpret_cast<const char*>(raw.data()),
                    static_cast<std::streamsize>(raw.size()));
        if (!m_out)
        {
            LOG_ERROR << "[BULK] capture write failed (disk full?) — "
                         "capture DISABLED (fetch/fold unaffected)";
            m_failed = true;
            return false;
        }
        m_out.flush();
        ++m_records;
        m_bytes += 44 + raw.size();
        return true;
    }

    /// Read every intact record of one segment file. A torn tail (magic or
    /// framing mismatch) ends the read at the last intact record — the
    /// re-fold utility then re-fetches from there.
    static std::vector<Record> read_segment(const std::string& path)
    {
        std::vector<Record> out;
        std::ifstream in(path, std::ios::binary);
        if (!in) return out;
        while (true)
        {
            uint32_t magic = 0, height = 0, size = 0;
            if (!get_u32(in, magic) || magic != RECORD_MAGIC) break;
            if (!get_u32(in, height)) break;
            Record rec;
            rec.height = height;
            unsigned char hb[32];
            if (!in.read(reinterpret_cast<char*>(hb), 32)) break;
            std::memcpy(rec.hash.data(), hb, 32);
            if (!get_u32(in, size)) break;
            rec.bytes.resize(size);
            if (size > 0 &&
                !in.read(reinterpret_cast<char*>(rec.bytes.data()), size))
                break;
            out.push_back(std::move(rec));
        }
        return out;
    }
};

// Capture consumer decoration: append the raw body to the fleet cache, then
// forward to the inner consumer (the fold / the counting stub). A capture
// failure never fails the fold — the cache is an optimization, the fold is
// the product — so append errors log, disable capture, and the inner verdict
// alone decides.
class CaptureReplayConsumer : public IReplayBlockConsumer
{
    BulkCaptureWriter m_writer;
    IReplayBlockConsumer* m_inner;   // borrowed, never owned

public:
    CaptureReplayConsumer(const std::string& dir, IReplayBlockConsumer* inner)
        : m_writer(dir), m_inner(inner) {}

    BulkCaptureWriter& writer() { return m_writer; }

    bool on_replay_block(uint32_t height, const uint256& hash,
                         const BlockType& block) override
    {
        if (!m_writer.failed())
        {
            auto packed = ::pack(block);
            std::vector<uint8_t> raw(
                reinterpret_cast<const uint8_t*>(packed.data()),
                reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());
            m_writer.append(height, hash, raw);
        }
        return m_inner ? m_inner->on_replay_block(height, hash, block) : true;
    }
};

// TEE consumer decoration (Variant B, #143): hand every verified body to TWO
// consumers so a sister lane (the CreditPool INDEX follower,
// credit_pool_idx.hpp) shares the SAME 30-40 GB bulk fetch instead of
// repeating it — and sees the body BEFORE drain_buffer() prunes it, which is
// the only moment the type-8/9 payloads exist in memory.
//
// SEMANTICS (deliberate, both directions fail closed):
//   * PRIMARY refuses  -> the lane refuses (unchanged W1 contract: a fold
//     that cannot proceed must never be silently skipped past).
//   * SIDE refuses     -> the lane ALSO refuses. The side lane's refusal
//     means ITS provenance broke mid-stream; pressing on would leave the two
//     lanes' cursors disagreeing about what "delivered" means for this run.
//     The side consumer is expected to have ALREADY latched its own
//     fail-closed state (proven_complete=0 + wipe) before returning false,
//     so the shared lane stopping is a named, restartable condition — never
//     a silent divergence. Callers that want a purely observational side
//     lane must wrap it so it never refuses.
class TeeReplayConsumer : public IReplayBlockConsumer
{
    IReplayBlockConsumer* m_primary;   // borrowed, never owned
    IReplayBlockConsumer* m_side;      // borrowed, never owned

public:
    TeeReplayConsumer(IReplayBlockConsumer* primary, IReplayBlockConsumer* side)
        : m_primary(primary), m_side(side) {}

    bool on_replay_block(uint32_t height, const uint256& hash,
                         const BlockType& block) override
    {
        // Side FIRST: it must see the body even if the primary then refuses
        // (the primary's refusal poisons the lane anyway; the side lane's
        // ledger stays honest either way because it only advances on its own
        // clean apply).
        const bool side_ok =
            m_side == nullptr || m_side->on_replay_block(height, hash, block);
        const bool primary_ok =
            m_primary == nullptr || m_primary->on_replay_block(height, hash, block);
        return side_ok && primary_ok;
    }
};

// ── Genesis→anchor header backfill ─────────────────────────────────────────
//
// Forward walker over `headers` batches. Holds ONLY the per-height hash
// (32 B × 2.4M ≈ 77 MB — the body-fetch index) plus a rolling claim window;
// full IndexEntry storage stays the main HeaderChain's job for anchor→tip.
//
// Validation per header: prev-hash must equal the current walker tip, and
// X11(header) must satisfy the header's own nBits under the network pow_limit
// (check_pow — the anti-DoS floor). Target-CORRECTNESS (DGW) is not re-derived
// here: the JOIN CHECK subsumes it — a segment that terminates in the exact
// fast-start anchor hash is prev-hash-pinned all the way down, so a forged
// mid-segment header would need the entire suffix re-mined onto the real
// anchor. (The main chain's own DGW check is log-only for the same reason,
// header_chain.hpp:616.) Genesis is additionally pinned to the known
// params.genesis_hash, and the walk FAILS CLOSED, loudly, on a join mismatch.
//
// Persistence: hashes are flushed to LevelDB in full CHUNK_SPAN chunks (one
// 320 KB value per 10k heights), so a restart reloads ~240 values instead of
// re-syncing 2.4M headers; at most the partial tail chunk is re-fetched.
class HeaderBackfill
{
public:
    static constexpr uint32_t CHUNK_SPAN = 10000;
    static constexpr size_t   CLAIM_WINDOW = 4096;

private:
    uint256  m_genesis_hash;
    uint32_t m_anchor_height{0};
    uint256  m_anchor_hash;
    uint256  m_pow_limit;
    bool     m_check_pow{true};

    // heights [0, m_hashes.size()) — m_hashes[0] is the genesis hash.
    std::vector<uint256> m_hashes;
    bool m_complete{false};
    bool m_failed{false};
    std::string m_fail_cause;

    // Rolling recent-hash window: batch claim + duplicate suppression. Old
    // entries expire FIFO; a stale batch older than the window falls through
    // to the main chain, orphan-rejects there, and is re-served next kick.
    std::map<uint256, uint32_t> m_recent;
    std::deque<uint256> m_recent_order;

    std::unique_ptr<core::LevelDBStore> m_db;
    uint32_t m_persisted_chunks{0};

    uint64_t m_headers_accepted{0};
    uint64_t m_headers_rejected{0};

    void note_recent(const uint256& h, uint32_t height)
    {
        m_recent.emplace(h, height);
        m_recent_order.push_back(h);
        while (m_recent_order.size() > CLAIM_WINDOW)
        {
            m_recent.erase(m_recent_order.front());
            m_recent_order.pop_front();
        }
    }

    void fail(const std::string& cause)
    {
        m_failed = true;
        m_fail_cause = cause;
        LOG_ERROR << "[BULK] header backfill FAILED CLOSED cause=" << cause
                  << " walker_height=" << (m_hashes.empty() ? 0 : m_hashes.size() - 1)
                  << " — replay bulk lane refuses to fetch bodies off an "
                     "unpinned header index";
    }

    static std::string chunk_key(uint32_t chunk_index)
    {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "rc%08u", chunk_index);
        return buf;
    }

    void persist_full_chunks()
    {
        if (!m_db || !m_db->is_open()) return;
        const uint32_t full_chunks =
            static_cast<uint32_t>(m_hashes.size() / CHUNK_SPAN);
        if (full_chunks <= m_persisted_chunks) return;
        auto batch = m_db->create_batch();
        for (uint32_t c = m_persisted_chunks; c < full_chunks; ++c)
        {
            std::vector<uint8_t> blob;
            blob.reserve(CHUNK_SPAN * 32);
            for (uint32_t i = 0; i < CHUNK_SPAN; ++i)
            {
                const uint256& h = m_hashes[static_cast<size_t>(c) * CHUNK_SPAN + i];
                blob.insert(blob.end(), h.data(), h.data() + 32);
            }
            batch.put(chunk_key(c), blob);
        }
        std::vector<uint8_t> count(4);
        count[0] = full_chunks & 0xFF;
        count[1] = (full_chunks >> 8) & 0xFF;
        count[2] = (full_chunks >> 16) & 0xFF;
        count[3] = (full_chunks >> 24) & 0xFF;
        batch.put("rc_count", count);
        if (batch.commit_sync())
            m_persisted_chunks = full_chunks;
        else
            LOG_WARNING << "[BULK] header-backfill chunk persist FAILED "
                           "(progress kept in memory; resume will re-sync)";
    }

    void load_persisted()
    {
        if (!m_db || !m_db->is_open()) return;
        std::vector<uint8_t> count;
        if (!m_db->get("rc_count", count) || count.size() != 4) return;
        const uint32_t chunks = static_cast<uint32_t>(count[0]) |
                                (static_cast<uint32_t>(count[1]) << 8) |
                                (static_cast<uint32_t>(count[2]) << 16) |
                                (static_cast<uint32_t>(count[3]) << 24);
        // persist_full_chunks() writes m_hashes[0] onward, so chunk 0 already
        // carries the genesis hash in slot 0 — while the constructor has
        // ALREADY seeded the walker with genesis before calling here.
        // Appending the chunks onto that seed shifts every persisted hash up
        // one height (m_hashes[h] then holds height h-1's hash) and the JOIN
        // CHECK fails closed with anchor-join-mismatch on every restart-resume
        // even though the store is byte-perfect. Rebuild the walker from the
        // store alone; the genesis pin below still validates slot 0, and the
        // torn/mismatch paths re-seed the pristine genesis walker.
        m_hashes.clear();
        m_recent.clear();
        m_recent_order.clear();
        m_hashes.reserve(static_cast<size_t>(chunks) * CHUNK_SPAN);
        for (uint32_t c = 0; c < chunks; ++c)
        {
            std::vector<uint8_t> blob;
            if (!m_db->get(chunk_key(c), blob) || blob.size() != CHUNK_SPAN * 32)
            {
                LOG_WARNING << "[BULK] header-backfill chunk " << c
                            << " missing/torn — resuming from chunk boundary "
                            << m_hashes.size();
                break;
            }
            for (uint32_t i = 0; i < CHUNK_SPAN; ++i)
            {
                uint256 h;
                std::memcpy(h.data(), blob.data() + static_cast<size_t>(i) * 32, 32);
                m_hashes.push_back(h);
            }
            m_persisted_chunks = c + 1;
        }
        if (!m_hashes.empty())
        {
            // The stored chain must still start at OUR genesis — a store from
            // a different network fails loud, not silent.
            if (m_hashes[0] != m_genesis_hash)
            {
                LOG_WARNING << "[BULK] header-backfill store genesis mismatch "
                               "— discarding persisted walk";
                m_hashes.clear();
                m_persisted_chunks = 0;
                m_hashes.push_back(m_genesis_hash);   // pristine walker
                note_recent(m_genesis_hash, 0);
                return;
            }
            for (size_t i = m_hashes.size() > CLAIM_WINDOW
                     ? m_hashes.size() - CLAIM_WINDOW : 0;
                 i < m_hashes.size(); ++i)
                note_recent(m_hashes[i], static_cast<uint32_t>(i));
            LOG_INFO << "[BULK] header backfill resumed at height "
                     << (m_hashes.size() - 1) << "/" << m_anchor_height
                     << " (" << m_persisted_chunks << " persisted chunk[s])";
            check_join();
        }
        else
        {
            // rc_count present but chunk 0 missing/torn — same pristine
            // walker a no-store start gets.
            m_persisted_chunks = 0;
            m_hashes.push_back(m_genesis_hash);
            note_recent(m_genesis_hash, 0);
        }
    }

    void check_join()
    {
        if (m_failed || m_complete) return;
        if (m_hashes.size() <= m_anchor_height) return;
        // Walker reached the anchor height: the JOIN CHECK.
        if (m_hashes[m_anchor_height] == m_anchor_hash)
        {
            m_complete = true;
            LOG_INFO << "[BULK] header backfill COMPLETE: genesis→"
                     << m_anchor_height << " JOINED the fast-start anchor ("
                     << m_anchor_hash.GetHex().substr(0, 16)
                     << "…) — pre-anchor chain is anchor-pinned to genesis";
        }
        else
        {
            fail("anchor-join-mismatch walker=" +
                 m_hashes[m_anchor_height].GetHex().substr(0, 16) +
                 " expected=" + m_anchor_hash.GetHex().substr(0, 16));
        }
    }

public:
    /// `db_path` empty ⇒ in-memory only (tests). `check_pow=false` is a
    /// TEST-ONLY relaxation for synthetic header chains.
    HeaderBackfill(const uint256& genesis_hash,
                   uint32_t anchor_height, const uint256& anchor_hash,
                   const uint256& pow_limit,
                   const std::string& db_path = "",
                   bool check_pow_flag = true)
        : m_genesis_hash(genesis_hash)
        , m_anchor_height(anchor_height)
        , m_anchor_hash(anchor_hash)
        , m_pow_limit(pow_limit)
        , m_check_pow(check_pow_flag)
    {
        m_hashes.push_back(genesis_hash);
        note_recent(genesis_hash, 0);
        if (!db_path.empty())
        {
            core::LevelDBOptions opts;
            opts.write_buffer_size = 2 * 1024 * 1024;
            opts.block_cache_size = 2 * 1024 * 1024;
            m_db = std::make_unique<core::LevelDBStore>(db_path, opts);
            if (!m_db->open())
            {
                LOG_WARNING << "[BULK] header-backfill LevelDB open FAILED at "
                            << db_path << " — walking without persistence";
                m_db.reset();
            }
            else
            {
                load_persisted();
            }
        }
    }

    bool complete() const { return m_complete; }
    bool failed() const { return m_failed; }
    const std::string& fail_cause() const { return m_fail_cause; }
    uint32_t anchor_height() const { return m_anchor_height; }
    /// Height of the highest linked header (the walker tip).
    uint32_t tip_height() const
    {
        return static_cast<uint32_t>(m_hashes.size() - 1);
    }
    const uint256& tip_hash() const { return m_hashes.back(); }
    uint64_t headers_accepted() const { return m_headers_accepted; }
    uint64_t headers_rejected() const { return m_headers_rejected; }

    std::optional<uint256> hash_at(uint32_t height) const
    {
        if (height >= m_hashes.size()) return std::nullopt;
        // Pre-anchor hashes are only trustworthy once the join has pinned the
        // segment; before that they are a walk in progress, not an index.
        if (!m_complete && height > 0) return std::nullopt;
        return m_hashes[height];
    }

    /// Would this `headers` batch extend the backfill walk? The demux
    /// predicate: a batch whose first prev-hash lands in our recent window is
    /// OURS (consumed before the tip-lane's new_headers event); anything else
    /// falls through to the main HeaderChain untouched.
    bool claims(const std::vector<BlockType>& batch) const
    {
        if (m_complete || m_failed || batch.empty()) return false;
        return m_recent.find(batch.front().m_previous_block) != m_recent.end();
    }

    /// Fold a claimed batch into the walk. Returns headers accepted.
    int add_headers(const std::vector<BlockType>& batch)
    {
        if (m_complete || m_failed) return 0;
        int accepted = 0;
        for (const auto& b : batch)
        {
            if (m_complete) break;
            if (b.m_previous_block != m_hashes.back())
            {
                // Duplicate/overlap (re-served after a re-kick) or out-of-order
                // garbage — count and skip; the walk only ever extends its tip.
                ++m_headers_rejected;
                continue;
            }
            const auto header = static_cast<BlockHeaderType>(b);
            auto packed = ::pack(header);
            const uint256 bhash = dash::crypto::hash_x11(packed.get_span());
            if (m_check_pow && !check_pow(bhash, header.m_bits, m_pow_limit))
            {
                ++m_headers_rejected;
                LOG_WARNING << "[BULK] backfill header PoW FAIL at height "
                            << m_hashes.size() << " — batch dropped";
                break;   // a bad link poisons the rest of the batch
            }
            const uint32_t new_height = static_cast<uint32_t>(m_hashes.size());
            if (new_height > m_anchor_height)
            {
                // Peer served past the anchor despite the stop hash; the walk
                // ends at the anchor by definition.
                break;
            }
            m_hashes.push_back(bhash);
            note_recent(bhash, new_height);
            ++m_headers_accepted;
            ++accepted;
            if (new_height == m_anchor_height)
                check_join();
        }
        if (accepted > 0)
        {
            persist_full_chunks();
            if ((m_hashes.size() % 100000) < static_cast<size_t>(accepted))
                LOG_INFO << "[BULK] header backfill: " << tip_height() << "/"
                         << m_anchor_height << " ("
                         << (100.0 * tip_height() / m_anchor_height) << "%)";
        }
        return accepted;
    }
};

// ── Pure bulk-request planner ──────────────────────────────────────────────
//
// Owns WHICH heights are asked of WHICH peer and when to ask again; owns no
// sockets, no clock, no bodies. All state transitions are driven by the lane:
//   pump()        → new (peer, batch-of-hashes) assignments to issue
//   on_body()     → a requested body arrived (from whichever peer)
//   on_notfound() → the asked peer does not have it (archival gap) — requeue,
//                   avoid that peer on the retry
//   service()     → timeouts + requests stranded on departed peers → requeue
//   requeue()     → lane-detected corruption (merkle bind fail) → refetch
class BulkBlockScheduler
{
public:
    struct Config
    {
        uint32_t window{2000};            // max heights ahead of the delivered cursor (spec §4.3 bounded work-ahead)
        uint32_t per_peer_inflight{32};   // outstanding bodies per peer (keeps reply queues short — priority inv. 4)
        uint32_t batch{16};               // invs per getdata message
        int64_t  request_timeout_sec{30}; // unanswered this long ⇒ re-request elsewhere
        // dashd net_processing BLOCK_STALLING_TIMEOUT parity. A peer that leaves
        // `demote_after` consecutive getdata unanswered (its deep-history bodies
        // never arrive — the whole run measured notfound=0: non-archival peers
        // silently drop the request rather than decline it) is held OFF fresh
        // contiguous-range assignment for `demote_cooldown_sec`, so the in-order
        // delivery cursor stops being handed work-ahead behind a peer that never
        // answers. Purely fetch-side WHO/WHEN: no height is ever skipped (timed-
        // out heights are requeued exactly as before), and a single delivered
        // body clears the demotion. demote_after=0 restores pre-port behaviour.
        uint32_t demote_after{3};
        int64_t  demote_cooldown_sec{60};
    };

    struct PeerTally
    {
        uint64_t blocks{0};
        uint64_t bytes{0};
        uint32_t inflight{0};
        uint32_t timeouts{0};        // cumulative unanswered-getdata timeouts (telemetry)
        uint32_t timeout_streak{0};  // consecutive timeouts since this peer last delivered a body
        int64_t  demoted_until{0};   // held off FRESH range assignment until this wall-second (0 = eligible)
    };

    struct Assignment
    {
        std::string peer;
        std::vector<std::pair<uint32_t, uint256>> blocks;   // (height, hash)
    };

private:
    struct Req
    {
        uint32_t    height{0};
        std::string peer;
        int64_t     at{0};
        int         attempts{0};
    };

    Config m_cfg;
    uint32_t m_start{0};
    uint32_t m_next{0};           // next never-requested height
    uint32_t m_delivered{0};      // high-water: all ≤ this handed to consumer
    uint32_t m_target_end{0};     // inclusive fetch ceiling (tip − exclusion)

    std::map<uint256, Req> m_inflight;                       // by hash
    std::deque<std::pair<uint32_t, std::string>> m_retry;    // (height, avoid-peer)
    std::map<std::string, PeerTally> m_tallies;
    std::size_t m_rr{0};                                     // round-robin cursor

    uint64_t m_rerequests{0};
    uint64_t m_notfound{0};
    uint64_t m_timeouts{0};

public:
    void configure(const Config& cfg) { m_cfg = cfg; }
    const Config& cfg() const { return m_cfg; }

    /// Begin (or resume) at `start` — the first height to fetch. `delivered`
    /// is start−1 by construction: nothing below start is wanted.
    void reset(uint32_t start)
    {
        m_start = start;
        m_next = start;
        m_delivered = start > 0 ? start - 1 : 0;
        m_inflight.clear();
        m_retry.clear();
    }

    void set_target_end(uint32_t end_inclusive) { m_target_end = end_inclusive; }
    uint32_t target_end() const { return m_target_end; }
    void note_delivered(uint32_t height)
    {
        if (height > m_delivered) m_delivered = height;
    }
    uint32_t delivered() const { return m_delivered; }
    uint32_t next_height() const { return m_next; }

    std::size_t inflight_count() const { return m_inflight.size(); }
    std::size_t retry_count() const { return m_retry.size(); }
    uint64_t rerequests() const { return m_rerequests; }
    uint64_t notfound_count() const { return m_notfound; }
    uint64_t timeout_count() const { return m_timeouts; }
    const std::map<std::string, PeerTally>& tallies() const { return m_tallies; }

    /// Peers currently held off fresh-range assignment (stall-demoted). Purely
    /// observational — for telemetry / the live [BULK] line.
    std::size_t demoted_count(int64_t now) const
    {
        std::size_t n = 0;
        for (const auto& [key, t] : m_tallies)
            if (t.demoted_until > now) ++n;
        return n;
    }

    bool is_inflight(const uint256& hash) const
    {
        return m_inflight.find(hash) != m_inflight.end();
    }

    /// A requested body arrived (identified by the hash the block handler
    /// computed from its own header — arrival hash == requested hash is what
    /// pins the header). Returns its height, or nullopt for a body we never
    /// asked for (NOT ours — the caller lets it fall through to the tip lane).
    std::optional<uint32_t> on_body(const uint256& hash, std::size_t raw_size)
    {
        auto it = m_inflight.find(hash);
        if (it == m_inflight.end()) return std::nullopt;
        const uint32_t height = it->second.height;
        auto& t = m_tallies[it->second.peer];
        ++t.blocks;
        t.bytes += raw_size;
        // A delivered body proves the peer is serving: clear its stall streak
        // and any demotion so it is immediately re-eligible for fresh ranges.
        t.timeout_streak = 0;
        t.demoted_until = 0;
        if (t.inflight > 0) --t.inflight;
        m_inflight.erase(it);
        return height;
    }

    /// The asked peer answered notfound (pruned/archival gap): requeue at the
    /// FRONT (oldest heights gate the in-order delivery cursor) avoiding that
    /// peer, so the retry lands on a neighbour that may hold it.
    bool on_notfound(const uint256& hash)
    {
        auto it = m_inflight.find(hash);
        if (it == m_inflight.end()) return false;
        ++m_notfound;
        auto& t = m_tallies[it->second.peer];
        if (t.inflight > 0) --t.inflight;
        m_retry.emplace_front(it->second.height, it->second.peer);
        m_inflight.erase(it);
        return true;
    }

    /// Lane-side refusal (merkle bind failure): fetch the height again from
    /// anyone but the peer that served the corrupt body.
    void requeue(uint32_t height, const std::string& avoid_peer)
    {
        ++m_rerequests;
        m_retry.emplace_front(height, avoid_peer);
    }

    /// Timeouts + stranded requests. `live_peers` is the CURRENT eligible set;
    /// a request whose peer churned out of the pool is requeued immediately
    /// rather than waiting out its timeout.
    void service(int64_t now, const std::vector<std::string>& live_peers)
    {
        for (auto it = m_inflight.begin(); it != m_inflight.end();)
        {
            const bool peer_gone =
                std::find(live_peers.begin(), live_peers.end(),
                          it->second.peer) == live_peers.end();
            const bool timed_out =
                (now - it->second.at) >= m_cfg.request_timeout_sec;
            if (!peer_gone && !timed_out) { ++it; continue; }
            auto& t = m_tallies[it->second.peer];
            if (timed_out)
            {
                ++m_timeouts;
                ++t.timeouts;
                ++t.timeout_streak;
                // dashd BLOCK_STALLING_TIMEOUT parity: after `demote_after`
                // consecutive unanswered getdata (no delivery in between), hold
                // this peer off fresh-range assignment for the cooldown. A
                // departed peer (peer_gone) is a topology event, not a serve
                // failure — it does not accrue the stall streak.
                if (m_cfg.demote_after > 0 &&
                    t.timeout_streak >= m_cfg.demote_after)
                    t.demoted_until = now + m_cfg.demote_cooldown_sec;
            }
            if (t.inflight > 0) --t.inflight;
            m_retry.emplace_front(it->second.height, it->second.peer);
            it = m_inflight.erase(it);
        }
    }

    /// Plan new assignments. `hash_at` resolves a height to its pinned hash
    /// (nullopt ⇒ the header index does not cover it yet — stop there).
    /// `buffered` is the lane's current work-ahead buffer occupancy; combined
    /// with the window it bounds total residency (spec §4.3: bounded buffer,
    /// nothing retained). Fresh heights are handed out as CONTIGUOUS runs per
    /// peer (range partitioning), retries go first.
    std::vector<Assignment> pump(
        int64_t now,
        const std::vector<std::string>& peers,
        const std::function<std::optional<uint256>(uint32_t)>& hash_at,
        std::size_t buffered)
    {
        std::vector<Assignment> out;
        if (peers.empty()) return out;

        // Drop tallies' inflight for peers that vanished (service() already
        // requeued their requests); keep their historical block/byte tallies.
        for (auto& [key, t] : m_tallies)
            if (std::find(peers.begin(), peers.end(), key) == peers.end())
                t.inflight = 0;

        const uint64_t budget_total =
            static_cast<uint64_t>(m_delivered) + m_cfg.window;

        // dashd BLOCK_STALLING_TIMEOUT parity (fresh-range side): is ANY peer
        // currently un-demoted? If every peer is stalled we must still hand out
        // fresh ranges (liveness — never freeze the fetch), so the demotion gate
        // is bypassed in that degenerate case. Retries are never gated here: the
        // oldest missing height must be able to land on whichever peer's slot is
        // free (the per-height avoid-peer already steers it off the last failer).
        bool any_fresh_eligible = false;
        for (const auto& p : peers)
        {
            auto ti = m_tallies.find(p);
            if (ti == m_tallies.end() || ti->second.demoted_until <= now)
            {
                any_fresh_eligible = true;
                break;
            }
        }

        for (std::size_t pi = 0; pi < peers.size(); ++pi)
        {
            const std::string& peer = peers[(m_rr + pi) % peers.size()];
            auto& tally = m_tallies[peer];
            if (tally.inflight >= m_cfg.per_peer_inflight) continue;
            // A demoted peer still takes retries below, but is skipped for fresh
            // contiguous ranges while any healthy peer remains.
            const bool fresh_ok =
                !any_fresh_eligible || tally.demoted_until <= now;
            uint32_t capacity = std::min<uint32_t>(
                m_cfg.batch, m_cfg.per_peer_inflight - tally.inflight);

            Assignment a;
            a.peer = peer;

            // Retries first: oldest missing heights gate the delivery cursor.
            while (capacity > 0 && !m_retry.empty())
            {
                auto [height, avoid] = m_retry.front();
                if (avoid == peer && peers.size() > 1)
                    break;   // let another peer's slot take this one
                m_retry.pop_front();
                auto h = hash_at(height);
                if (!h) continue;   // index shrank (should not happen) — drop
                m_inflight[*h] = Req{height, peer, now,
                                     /*attempts=*/1};
                a.blocks.emplace_back(height, *h);
                ++tally.inflight;
                --capacity;
            }

            // Then a fresh CONTIGUOUS range for this peer (unless it is demoted
            // and healthy peers remain — dashd BLOCK_STALLING_TIMEOUT parity).
            while (fresh_ok && capacity > 0 && m_next <= m_target_end &&
                   static_cast<uint64_t>(m_next) <= budget_total &&
                   (static_cast<uint64_t>(m_inflight.size()) + buffered) <
                       m_cfg.window)
            {
                auto h = hash_at(m_next);
                if (!h) break;   // header index ends here for now
                m_inflight[*h] = Req{m_next, peer, now, 0};
                a.blocks.emplace_back(m_next, *h);
                ++tally.inflight;
                --capacity;
                ++m_next;
            }

            if (!a.blocks.empty()) out.push_back(std::move(a));
        }
        if (!peers.empty()) m_rr = (m_rr + 1) % peers.size();
        return out;
    }
};

// ── The lane: glue between scheduler, backfill, consumer and the client ────
//
// Constructed only under --replay-bulk. All seams are injected functions so
// the KATs stand the whole lane up with no CoinClient and no io_context; in
// production main_dash wires them to the client's named-peer sends and demux
// filters and pumps tick() from a 1 s core::Timer on the io thread.
class BulkFetchLane
{
public:
    struct Seams
    {
        // Height → pinned hash: backfill for pre-anchor, HeaderChain above.
        std::function<std::optional<uint256>(uint32_t)> hash_at;
        // Current main header-chain tip height.
        std::function<uint32_t()> chain_height;
        // Handshaked peers ELIGIBLE for bulk (primary excluded unless alone).
        std::function<std::vector<std::string>()> eligible_peers;
        // One getdata(block…) with the given hashes to the named peer.
        std::function<void(const std::string&, const std::vector<uint256>&)>
            send_getdata;
        // getheaders(locator=[backfill tip], stop=anchor) to the named peer.
        std::function<void(const std::string&, const uint256& locator_hash,
                           const uint256& stop)> send_getheaders;
        // Tip lane busy right now? (pending tracked tip body) — priority inv. 2.
        std::function<bool()> tip_busy;
        // OPTIONAL. A HIGHER-priority coin-P2P consumer is mid-fetch right now —
        // specifically the embedded MN-checkpoint anchor->tip fold building the
        // payee queue (main_dash wires this to MnCheckpointLane::bridging_active).
        // While it returns true this lane yields BOTH its body pump AND its
        // header-backfill getheaders, because the fold's block-body getdata and
        // this backfill's headers share ONE response demux on the coin-P2P link
        // and the fold gates the money arm — it must build its queue first. This
        // is the same class of guard as tip_busy (the live-tip body edge), for a
        // different higher-priority consumer (the one-shot cold-start payee
        // derivation). Null (KATs, any embedding without the fold) ⇒ this lane
        // behaves BYTE-IDENTICALLY to before this seam existed.
        std::function<bool()> defer_to_higher_priority;
    };

    struct Config
    {
        uint32_t start_height{MAINNET_DIP3_HEIGHT};
        uint32_t tip_exclusion{12};          // live edge belongs to the tip lane
        int64_t  telemetry_interval_sec{30};
        int64_t  backfill_rekick_sec{15};    // headers stall re-kick
        uint32_t cursor_persist_every{512};  // delivered blocks between cursor writes
    };

private:
    Seams  m_seams;
    Config m_cfg;
    BulkBlockScheduler m_sched;
    HeaderBackfill*    m_backfill;   // borrowed; nullptr ⇒ no pre-anchor span (testnet / no fast-start)
    IReplayBlockConsumer* m_consumer;
    ReplayCursorStore* m_cursor;     // borrowed; nullptr ⇒ no persistence (tests)

    std::map<uint32_t, BlockType> m_buffer;   // received, awaiting in-order delivery
    uint32_t m_delivered{0};
    bool m_cursor_checked{false};
    std::optional<ReplayCursorStore::Cursor> m_resume;

    bool m_failed{false};
    std::string m_fail_cause;

    // Telemetry window.
    int64_t  m_last_telemetry{0};
    uint64_t m_window_blocks{0};
    uint64_t m_window_bytes{0};
    uint64_t m_total_blocks{0};
    uint64_t m_total_bytes{0};
    uint64_t m_corrupt_bodies{0};
    uint32_t m_delivered_since_persist{0};

    int64_t m_last_backfill_kick{0};
    std::size_t m_backfill_rr{0};

    void fail(const std::string& cause)
    {
        if (m_failed) return;
        m_failed = true;
        m_fail_cause = cause;
        LOG_ERROR << "[BULK] lane FAILED CLOSED cause=" << cause
                  << " delivered=" << m_delivered
                  << " — bulk fetching stopped (tip lane unaffected)";
    }

    void persist_cursor(bool force)
    {
        if (!m_cursor || m_delivered < m_cfg.start_height) return;
        if (!force && m_delivered_since_persist < m_cfg.cursor_persist_every)
            return;
        auto h = m_seams.hash_at(m_delivered);
        if (!h) return;
        ReplayCursorStore::Cursor c;
        c.height = m_delivered;
        c.hash = *h;
        if (m_cursor->store(c))
            m_delivered_since_persist = 0;
    }

    /// Deliver the contiguous prefix of the buffer to the consumer, PRUNE it.
    void drain_buffer()
    {
        while (!m_failed)
        {
            auto it = m_buffer.find(m_delivered + 1);
            if (it == m_buffer.end()) break;
            const uint32_t height = it->first;
            auto h = m_seams.hash_at(height);
            if (!h) break;   // cannot name the hash (index regressed) — hold
            if (!m_consumer->on_replay_block(height, *h, it->second))
            {
                fail("consumer-refused height=" + std::to_string(height));
                break;
            }
            m_buffer.erase(it);   // PRUNE — the body is gone the moment it folds
            m_delivered = height;
            m_sched.note_delivered(height);
            ++m_delivered_since_persist;
            persist_cursor(false);
        }
    }

    void maybe_kick_backfill(int64_t now)
    {
        if (!m_backfill || m_backfill->complete() || m_backfill->failed())
            return;
        // Yield the shared response demux to a higher-priority coin-P2P
        // consumer (the MN-checkpoint anchor->tip fold): its block-body getdata
        // and this getheaders walk contend for the same link, and the fold's
        // payee queue gates the money arm. Hold the header walk until the fold
        // has published. Null seam ⇒ unchanged.
        if (m_seams.defer_to_higher_priority && m_seams.defer_to_higher_priority())
            return;
        if ((now - m_last_backfill_kick) < m_cfg.backfill_rekick_sec) return;
        auto peers = m_seams.eligible_peers();
        if (peers.empty()) return;
        const std::string& peer = peers[m_backfill_rr++ % peers.size()];
        m_seams.send_getheaders(peer, m_backfill->tip_hash(),
                                uint256::ZERO /* stop: serve max batches; the
                                walker itself stops at the anchor */);
        m_last_backfill_kick = now;
    }

    void maybe_log_telemetry(int64_t now)
    {
        if (m_last_telemetry != 0 &&
            (now - m_last_telemetry) < m_cfg.telemetry_interval_sec)
            return;
        const int64_t span = m_last_telemetry == 0
            ? m_cfg.telemetry_interval_sec : (now - m_last_telemetry);
        m_last_telemetry = now;
        const double blk_s = span > 0 ? double(m_window_blocks) / span : 0.0;
        const double mb_s  = span > 0
            ? double(m_window_bytes) / (1024.0 * 1024.0) / span : 0.0;
        std::ostringstream peers;
        for (const auto& [key, t] : m_sched.tallies())
        {
            if (t.blocks == 0 && t.inflight == 0) continue;
            peers << " " << key << "=" << t.blocks << "blk/"
                  << (t.bytes / (1024 * 1024)) << "MB"
                  << (t.inflight ? ("(+" + std::to_string(t.inflight) + ")")
                                 : "")
                  << (t.demoted_until > now ? "!D" : "");
        }
        LOG_INFO << "[BULK] delivered=" << m_delivered << "/"
                 << m_sched.target_end()
                 << " rate=" << blk_s << "blk/s " << mb_s << "MB/s"
                 << " total=" << m_total_blocks << "blk/"
                 << (m_total_bytes / (1024 * 1024)) << "MB"
                 << " inflight=" << m_sched.inflight_count()
                 << " buffer=" << m_buffer.size()
                 << " retry=" << m_sched.retry_count()
                 << " demoted=" << m_sched.demoted_count(now)
                 << " hdr="
                 << (m_backfill
                         ? (m_backfill->complete()
                                ? std::string("joined")
                                : (m_backfill->failed()
                                       ? std::string("FAILED")
                                       : std::to_string(m_backfill->tip_height())
                                         + "/"
                                         + std::to_string(
                                               m_backfill->anchor_height())))
                         : std::string("n/a"))
                 << " rereq=" << m_sched.rerequests()
                 << " timeout=" << m_sched.timeout_count()
                 << " notfound=" << m_sched.notfound_count()
                 << " corrupt=" << m_corrupt_bodies
                 << " peers[" << peers.str() << " ]";
        m_window_blocks = 0;
        m_window_bytes = 0;
    }

    /// Cursor resume: trust the persisted high-water only after proving its
    /// hash still names OUR chain at that height (lazy — the backfill may not
    /// cover the height yet). Mismatch ⇒ fail closed with a named cause.
    void maybe_check_cursor()
    {
        if (m_cursor_checked || !m_resume) return;
        auto h = m_seams.hash_at(m_resume->height);
        if (!h) return;   // index not there yet — check again next tick
        if (*h != m_resume->hash)
        {
            fail("resume-cursor-hash-mismatch height=" +
                 std::to_string(m_resume->height) +
                 " stored=" + m_resume->hash.GetHex().substr(0, 16) +
                 " chain=" + h->GetHex().substr(0, 16));
            return;
        }
        m_cursor_checked = true;
        LOG_INFO << "[BULK] resume cursor VERIFIED at height "
                 << m_resume->height << " — resuming fetch from "
                 << (m_resume->height + 1);
    }

public:
    BulkFetchLane(Seams seams, Config cfg,
                  HeaderBackfill* backfill,
                  IReplayBlockConsumer* consumer,
                  ReplayCursorStore* cursor)
        : m_seams(std::move(seams))
        , m_cfg(cfg)
        , m_backfill(backfill)
        , m_consumer(consumer)
        , m_cursor(cursor)
    {
        uint32_t start = m_cfg.start_height;
        if (m_cursor)
        {
            m_resume = m_cursor->load();
            if (m_resume && m_resume->height >= start)
            {
                start = m_resume->height + 1;
                LOG_INFO << "[BULK] cursor found: delivered high-water "
                         << m_resume->height
                         << " (hash check deferred until the header index "
                            "covers it)";
            }
            else
            {
                m_resume.reset();
                m_cursor_checked = true;   // nothing to verify
            }
        }
        else
        {
            m_cursor_checked = true;
        }
        m_sched.reset(start);
        m_delivered = start > 0 ? start - 1 : 0;
    }

    BulkBlockScheduler& scheduler() { return m_sched; }
    uint32_t delivered() const { return m_delivered; }
    std::size_t buffer_size() const { return m_buffer.size(); }
    bool failed() const { return m_failed; }
    const std::string& fail_cause() const { return m_fail_cause; }
    uint64_t total_blocks() const { return m_total_blocks; }
    uint64_t total_bytes() const { return m_total_bytes; }
    uint64_t corrupt_bodies() const { return m_corrupt_bodies; }

    /// Headers demux filter body (registered on the CoinClient): claim and
    /// fold backfill batches; everything else falls through to new_headers.
    bool on_headers(const std::string& /*peer_key*/,
                    const std::vector<BlockType>& batch)
    {
        if (!m_backfill || !m_backfill->claims(batch)) return false;
        const int accepted = m_backfill->add_headers(batch);
        if (accepted > 0 && !m_backfill->complete() && !m_backfill->failed())
        {
            // Self-propel: immediately ask for the next span. The stall
            // re-kick in tick() is only the backstop.
            auto peers = m_seams.eligible_peers();
            if (!peers.empty())
            {
                const std::string& peer =
                    peers[m_backfill_rr++ % peers.size()];
                m_seams.send_getheaders(peer, m_backfill->tip_hash(),
                                        uint256::ZERO);
            }
        }
        return true;   // claimed — never reaches the tip-lane header ingest
    }

    /// Block-body demux filter body (registered on the CoinClient). `hash` is
    /// X11 of the body's own header — equality with the scheduled hash pins
    /// the header; the merkle bind then pins the tx set to that header.
    /// Returns true when the body was OURS (consumed; skip full_block event).
    bool on_block_body(const uint256& hash, const BlockType& block)
    {
        if (m_failed)
        {
            // Still consume stragglers we asked for, so they don't leak into
            // the tip lane's full_block ingest; just don't fold them.
            return m_sched.on_body(hash, 0).has_value();
        }
        if (!m_sched.is_inflight(hash)) return false;   // not ours — tip lane's body
        const std::size_t raw_size = ::pack(block).size();
        auto height = m_sched.on_body(hash, raw_size);
        if (!height) return false;   // unreachable (checked above); belt+braces

        if (!block_body_binds_to_header(block))
        {
            ++m_corrupt_bodies;
            LOG_WARNING << "[BULK] body MERKLE-BIND FAIL height=" << *height
                        << " hash=" << hash.GetHex().substr(0, 16)
                        << "… — re-requesting from a different peer";
            // The tally already credited the serving peer; requeue avoids it.
            m_sched.requeue(*height, std::string{});
            return true;   // consumed (and rejected) — never fold, never leak
        }

        ++m_total_blocks;
        ++m_window_blocks;
        m_total_bytes += raw_size;
        m_window_bytes += raw_size;
        if (*height <= m_delivered)
            return true;   // duplicate (double-answered re-request) — pruned
        m_buffer[*height] = block;
        drain_buffer();
        return true;
    }

    /// notfound(block) callback body.
    void on_notfound(const uint256& hash) { m_sched.on_notfound(hash); }

    /// One pump: drive the backfill, service timeouts, plan + issue bulk
    /// getdata (unless the tip lane is busy), telemetry. Call ~1/s.
    void tick(int64_t now)
    {
        maybe_check_cursor();
        if (m_failed)
        {
            maybe_log_telemetry(now);
            return;
        }
        maybe_kick_backfill(now);

        const auto peers = m_seams.eligible_peers();
        m_sched.service(now, peers);

        // Fetch ceiling: stay clear of the live edge (priority invariant 3).
        const uint32_t tip = m_seams.chain_height();
        m_sched.set_target_end(tip > m_cfg.tip_exclusion
                                   ? tip - m_cfg.tip_exclusion : 0);

        // STRICT PRIORITY: no new bulk requests while a tracked tip body is
        // outstanding (invariant 2). In-flight bulk completes on its own.
        if (!peers.empty() && m_cursor_checked &&
            !(m_seams.tip_busy && m_seams.tip_busy()) &&
            !(m_seams.defer_to_higher_priority &&
              m_seams.defer_to_higher_priority()))
        {
            auto assignments = m_sched.pump(
                now, peers, m_seams.hash_at, m_buffer.size());
            for (const auto& a : assignments)
            {
                std::vector<uint256> hashes;
                hashes.reserve(a.blocks.size());
                for (const auto& [h, hash] : a.blocks) hashes.push_back(hash);
                m_seams.send_getdata(a.peer, hashes);
            }
        }
        maybe_log_telemetry(now);
    }

    /// Clean-shutdown hook: force-persist the cursor.
    void flush() { persist_cursor(true); }
};

} // namespace replay
} // namespace coin
} // namespace dash
