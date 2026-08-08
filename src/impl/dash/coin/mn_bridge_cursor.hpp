// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Task #91 step 2: the MN-CKPT payee bridge's RESUMABLE cursor.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE DEFECT THIS CLOSES
/// ─────────────────────────────────────────────────────────────────────────
/// The bridge (mn_checkpoint_lane.hpp) replays every block from the pinned
/// anchor to the header tip, and threw all of it away on exit. Verbatim from
/// a 2026-08-04 restart that had ALREADY completed exactly that work:
///
///     [MN-CKPT] bridge START: replaying h=2513001..2516913 (3913 blocks)
///
/// The cost is not CPU. #1126's own measurement: the lane is EVENT-BOUND —
/// it re-drives its request window only when the tip changes (~2.5 min per
/// mainnet block) and bursts at ~375 blk/s when it does fire — so the wall
/// clock is roughly "number of stalled windows x block interval". That is
/// ~26 of the ~34 minutes of a pure-daemonless cold start, paid again on
/// every process start.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY THIS IS ONE FILE, ONE RECORD, ONE RENAME
/// ─────────────────────────────────────────────────────────────────────────
/// "A cursor must be authoritative and must refuse to half-resume" is the
/// W1/W2 lesson (project_replay_tier_a_proven_3851_blocks): the bulk lane's
/// persistent cursor and the fold's anchor were once INDEPENDENT, so a
/// restart resumed the lane at h=2513098 while the fold sat at h=2513000 —
/// a silently skipped range, which on THIS lane means a wrong payee queue,
/// which means a coinbase the network rejects.
///
/// The structural answer is to make a partial state UNREPRESENTABLE rather
/// than to police it:
///
///   * ONE record holds the masternode set AND the height it is as-of AND
///     the provenance it descends from. There is no "cursor only" record and
///     no "entries only" record, so a cursor can never be paired with a set
///     from a different height.
///   * The record is written to `<path>.tmp` and moved into place with a
///     single rename(2) — the same atomic-publish idiom ReplayCursorStore
///     (replay_bulk_fetch.hpp) already uses in this tree. A torn write is
///     never observable; the reader sees the old record or the new one.
///   * A payload digest covers the whole record. Truncation, bit rot and a
///     half-flushed file all read back as CORRUPT, which is a COLD start,
///     not a half-resume.
///   * A FORMAT VERSION is checked before anything is believed. The MnStateDb
///     v1->v2 lesson: a schema change that deserialises entry-by-entry gets
///     SILENTLY SKIPPED rows, i.e. a partial set under a believed cursor.
///     Here a version mismatch discards the whole record and says so.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT IS PERSISTED IS WHAT WAS DELIVERED
/// ─────────────────────────────────────────────────────────────────────────
/// #1128 hit the inverse and it destroyed derived state: a lane's floor taken
/// from an aspirational CEILING (`max(delivered, target_end)`) instead of the
/// DELIVERED high-water orphaned every height in between. So `cursor_height`
/// here is the height of the last block `apply_block` ACTUALLY folded with no
/// desync and no gap — never `m_requested_through`, never the replay target,
/// never the tip. The store is written from exactly one site, after a
/// successful apply, and `applied` rides along so the reader can check the
/// arithmetic (see `contiguous()` below) instead of trusting the writer.
///
/// FENCED: src/impl/dash only. Read and written solely by MnCheckpointLane.

#include <impl/dash/coin/mn_state_db.hpp>        // MNState + its pack methods

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// Everything the bridge needs to stand back up exactly where it stopped.
///
/// The fields are grouped by WHAT MAKES THEM SAFE, not by where they live in
/// the lane, because that is the order a reviewer has to check them in.
struct MnBridgeCursor
{
    // ── PROVENANCE. What lineage this state descends from. Every one of
    // these is compared against the anchor the running binary carries, and
    // any difference is a COLD start: a set derived from a different anchor
    // is a set with a different trust root.
    uint32_t    anchor_height{0};
    uint256     anchor_hash;
    std::string anchor_source;
    uint32_t    anchor_count{0};
    uint32_t    anchor_eligible{0};
    uint32_t    anchor_ineligible{0};

    // ── DELIVERED. The height actually folded, and the block that was folded
    // at it. `cursor_hash` is what makes a resume refuse across a reorg: it
    // is checked against OUR OWN PoW-validated header chain before a single
    // entry is believed.
    uint32_t    cursor_height{0};
    uint256     cursor_hash;
    uint32_t    applied{0};

    // ── SPENT BUDGETS AND LATCHES. A resumed bridge must not be handed a
    // fresh budget for work a previous process already spent: that would make
    // a restart LOOSER than a continuous run, and every one of these caps
    // exists to stop a runaway from hammering a peer or from overriding the
    // projection wholesale. Carrying them forward keeps restart-equivalence
    // (the KAT that pins it compares a continuous bridge against a restarted
    // one field for field, so this list cannot silently drift).
    uint32_t    folds{0};
    uint32_t    first_fold_height{0};
    uint32_t    last_fold_height{0};
    uint32_t    sml_folded_at{0};
    uint32_t    abandoned_folds{0};
    uint32_t    ondemand_folds{0};
    uint32_t    ondemand_excluded{0};
    uint32_t    ondemand_abandoned{0};
    uint32_t    revive_probes{0};
    uint32_t    revive_unmeasured{0};
    uint32_t    revive_declined{0};
    uint32_t    sml_recovered{0};
    uint32_t    pose_removed{0};
    uint32_t    pose_reinstated{0};
    uint32_t    tx_revived{0};
    uint32_t    revive_dropped{0};
    uint32_t    registered{0};
    uint32_t    spent{0};

    // ── THE SET ITSELF, as of `cursor_height`.
    std::vector<std::pair<uint256, MNState>> entries;

    /// THE ANTI-GAP ARITHMETIC, checkable by the READER from the record alone.
    ///
    /// The bridge folds exactly one block per height from anchor+1 up to the
    /// cursor — apply_block is forward-CONTIGUOUS and refuses anything else —
    /// so a truthful record always satisfies
    ///
    ///     applied == cursor_height - anchor_height
    ///
    /// A record that does not is describing a state that skipped heights.
    /// That is the exact shape of the W1/W2 defect, and it is refused rather
    /// than resumed. This is deliberately not an assert at the write site:
    /// the point is that the READER does not have to trust the writer.
    bool contiguous() const
    {
        if (cursor_height <= anchor_height) return false;
        return applied == (cursor_height - anchor_height);
    }
};

/// Atomic single-record store for MnBridgeCursor.
///
/// On-disk layout (all integers little-endian, no padding):
///
///     "c2pool-mn-bridge-cursor\n"   24 bytes, exact
///     u32   format version
///     u64   payload length
///     ...   payload
///     32B   CHash256(payload)
///
/// The digest is over the PAYLOAD ONLY so a length that disagrees with the
/// file size is caught before any allocation is sized from it.
class MnBridgeCursorStore
{
public:
    /// Bump on ANY change to the payload encoding or to MNState's pack
    /// methods. A stale-format record is discarded whole; it is never
    /// partially interpreted (the MnStateDb v1->v2 lesson).
    static constexpr uint32_t kFormatVersion = 1;

    explicit MnBridgeCursorStore(std::string path) : m_path(std::move(path)) {}

    const std::string& path() const { return m_path; }

    /// nullopt = nothing usable on disk. `why` always names the reason, and
    /// an absent file is NOT an error (it is a first run).
    std::optional<MnBridgeCursor> load(std::string& why) const
    {
        std::error_code ec;
        if (!std::filesystem::exists(m_path, ec)) {
            why = "no persisted cursor at " + m_path + " (first run for this"
                  " data directory)";
            return std::nullopt;
        }
        std::ifstream in(m_path, std::ios::binary);
        if (!in) { why = "cursor file " + m_path + " is unreadable"; return std::nullopt; }
        std::vector<uint8_t> raw((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
        const size_t kHdr = kMagicLen + 4 + 8;
        if (raw.size() < kHdr + 32) {
            why = "cursor file is TRUNCATED (" + std::to_string(raw.size())
                  + " bytes, header alone needs " + std::to_string(kHdr + 32)
                  + ")";
            return std::nullopt;
        }
        if (std::memcmp(raw.data(), kMagic, kMagicLen) != 0) {
            why = "cursor file does not carry the expected magic — it is not"
                  " an MN-CKPT bridge cursor";
            return std::nullopt;
        }
        const uint32_t ver = rd_u32(raw.data() + kMagicLen);
        if (ver != kFormatVersion) {
            why = "cursor file is format v" + std::to_string(ver)
                  + ", this build writes v" + std::to_string(kFormatVersion)
                  + " — discarding the whole record rather than interpreting"
                    " part of it";
            return std::nullopt;
        }
        const uint64_t len = rd_u64(raw.data() + kMagicLen + 4);
        if (len > raw.size() || raw.size() != kHdr + len + 32) {
            why = "cursor file length field (" + std::to_string(len)
                  + ") disagrees with the file size ("
                  + std::to_string(raw.size()) + ") — TORN or truncated write";
            return std::nullopt;
        }
        uint256 want;
        std::memcpy(want.data(), raw.data() + kHdr + len, 32);
        uint256 got;
        CHash256()
            .Write(std::span<const unsigned char>(raw.data() + kHdr,
                                                  static_cast<size_t>(len)))
            .Finalize(std::span<unsigned char>(got.data(), 32));
        if (want != got) {
            why = "cursor file digest MISMATCH (want " + want.GetHex().substr(0, 16)
                  + ", got " + got.GetHex().substr(0, 16)
                  + ") — the record is corrupt";
            return std::nullopt;
        }
        MnBridgeCursor c;
        try {
            decode(raw.data() + kHdr, static_cast<size_t>(len), c);
        } catch (const std::exception& e) {
            why = std::string("cursor payload failed to decode: ") + e.what();
            return std::nullopt;
        }
        why = "loaded a persisted cursor: h=" + std::to_string(c.cursor_height)
              + " with " + std::to_string(c.entries.size()) + " masternodes,"
                " anchor h=" + std::to_string(c.anchor_height);
        return c;
    }

    /// Write-then-rename. Returns false on ANY failure, and the caller treats
    /// that as "persistence is not working" rather than retrying silently:
    /// a bridge that cannot save is still CORRECT, it is only slow again, and
    /// the one thing it must never do is believe it saved when it did not.
    bool store(const MnBridgeCursor& c) const
    {
        std::vector<uint8_t> payload;
        encode(c, payload);

        std::vector<uint8_t> out;
        out.reserve(kMagicLen + 12 + payload.size() + 32);
        out.insert(out.end(), kMagic, kMagic + kMagicLen);
        wr_u32(out, kFormatVersion);
        wr_u64(out, payload.size());
        out.insert(out.end(), payload.begin(), payload.end());
        uint256 digest;
        CHash256()
            .Write(std::span<const unsigned char>(payload.data(), payload.size()))
            .Finalize(std::span<unsigned char>(digest.data(), 32));
        out.insert(out.end(), digest.data(), digest.data() + 32);

        const std::string tmp = m_path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) return false;
            f.write(reinterpret_cast<const char*>(out.data()),
                    static_cast<std::streamsize>(out.size()));
            if (!f) return false;
            f.flush();
            if (!f) return false;
        }
        std::error_code ec;
        std::filesystem::rename(tmp, m_path, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            return false;
        }
        return true;
    }

    /// Remove the record. Used when the state it describes must NEVER be
    /// resumed into — a fail-closed bridge and a re-arm both qualify (see the
    /// call sites in mn_checkpoint_lane.hpp).
    bool erase() const
    {
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
        std::error_code ec2;
        std::filesystem::remove(m_path + ".tmp", ec2);
        return !ec;
    }

private:
    static constexpr char kMagic[] = "c2pool-mn-bridge-cursor\n";
    static constexpr size_t kMagicLen = sizeof(kMagic) - 1;   // 24, no NUL

    std::string m_path;

    static void wr_u32(std::vector<uint8_t>& o, uint32_t v)
    {
        o.push_back(uint8_t( v        & 0xFF));
        o.push_back(uint8_t((v >>  8) & 0xFF));
        o.push_back(uint8_t((v >> 16) & 0xFF));
        o.push_back(uint8_t((v >> 24) & 0xFF));
    }
    static void wr_u64(std::vector<uint8_t>& o, uint64_t v)
    {
        for (int i = 0; i < 8; ++i) o.push_back(uint8_t((v >> (8 * i)) & 0xFF));
    }
    static uint32_t rd_u32(const uint8_t* p)
    {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
             | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }
    static uint64_t rd_u64(const uint8_t* p)
    {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
        return v;
    }
    static void wr_hash(std::vector<uint8_t>& o, const uint256& h)
    {
        o.insert(o.end(), h.data(), h.data() + 32);
    }
    static void wr_str(std::vector<uint8_t>& o, const std::string& s)
    {
        wr_u32(o, static_cast<uint32_t>(s.size()));
        o.insert(o.end(), s.begin(), s.end());
    }

    /// Bounds-checked reader. Every accessor throws rather than returning a
    /// default, because a default here is exactly the "silently partial
    /// record" this file exists to make impossible.
    struct Reader
    {
        const uint8_t* p;
        size_t         n;
        size_t         at{0};

        void need(size_t k) const
        {
            if (at + k > n) throw std::runtime_error("payload underrun");
        }
        uint32_t u32() { need(4); uint32_t v = rd_u32(p + at); at += 4; return v; }
        uint64_t u64() { need(8); uint64_t v = rd_u64(p + at); at += 8; return v; }
        uint256 hash()
        {
            need(32);
            uint256 h;
            std::memcpy(h.data(), p + at, 32);
            at += 32;
            return h;
        }
        std::string str()
        {
            const uint32_t k = u32();
            if (k > (1u << 20)) throw std::runtime_error("string too long");
            need(k);
            std::string s(reinterpret_cast<const char*>(p + at), k);
            at += k;
            return s;
        }
        std::vector<uint8_t> blob()
        {
            const uint32_t k = u32();
            if (k > (1u << 24)) throw std::runtime_error("blob too long");
            need(k);
            std::vector<uint8_t> b(p + at, p + at + k);
            at += k;
            return b;
        }
    };

    static void encode(const MnBridgeCursor& c, std::vector<uint8_t>& o)
    {
        wr_u32(o, c.anchor_height);
        wr_hash(o, c.anchor_hash);
        wr_str(o, c.anchor_source);
        wr_u32(o, c.anchor_count);
        wr_u32(o, c.anchor_eligible);
        wr_u32(o, c.anchor_ineligible);

        wr_u32(o, c.cursor_height);
        wr_hash(o, c.cursor_hash);
        wr_u32(o, c.applied);

        wr_u32(o, c.folds);
        wr_u32(o, c.first_fold_height);
        wr_u32(o, c.last_fold_height);
        wr_u32(o, c.sml_folded_at);
        wr_u32(o, c.abandoned_folds);
        wr_u32(o, c.ondemand_folds);
        wr_u32(o, c.ondemand_excluded);
        wr_u32(o, c.ondemand_abandoned);
        wr_u32(o, c.revive_probes);
        wr_u32(o, c.revive_unmeasured);
        wr_u32(o, c.revive_declined);
        wr_u32(o, c.sml_recovered);
        wr_u32(o, c.pose_removed);
        wr_u32(o, c.pose_reinstated);
        wr_u32(o, c.tx_revived);
        wr_u32(o, c.revive_dropped);
        wr_u32(o, c.registered);
        wr_u32(o, c.spent);

        wr_u64(o, c.entries.size());
        for (const auto& [h, st] : c.entries) {
            wr_hash(o, h);
            // MNState rides its OWN pack methods, exactly as MnStateDb
            // persists it. One encoder for the struct means a field added
            // there cannot be forgotten here — it changes the byte length,
            // the digest, and (because kFormatVersion must be bumped with it)
            // the version gate.
            auto stream = ::pack(st);
            auto sp = stream.get_span();
            wr_u32(o, static_cast<uint32_t>(sp.size()));
            const auto* b = reinterpret_cast<const uint8_t*>(sp.data());
            o.insert(o.end(), b, b + sp.size());
        }
    }

    static void decode(const uint8_t* p, size_t n, MnBridgeCursor& c)
    {
        Reader r{p, n};
        c.anchor_height     = r.u32();
        c.anchor_hash       = r.hash();
        c.anchor_source     = r.str();
        c.anchor_count      = r.u32();
        c.anchor_eligible   = r.u32();
        c.anchor_ineligible  = r.u32();

        c.cursor_height     = r.u32();
        c.cursor_hash       = r.hash();
        c.applied           = r.u32();

        c.folds             = r.u32();
        c.first_fold_height = r.u32();
        c.last_fold_height  = r.u32();
        c.sml_folded_at     = r.u32();
        c.abandoned_folds   = r.u32();
        c.ondemand_folds    = r.u32();
        c.ondemand_excluded = r.u32();
        c.ondemand_abandoned = r.u32();
        c.revive_probes     = r.u32();
        c.revive_unmeasured = r.u32();
        c.revive_declined   = r.u32();
        c.sml_recovered     = r.u32();
        c.pose_removed      = r.u32();
        c.pose_reinstated   = r.u32();
        c.tx_revived        = r.u32();
        c.revive_dropped    = r.u32();
        c.registered        = r.u32();
        c.spent             = r.u32();

        const uint64_t count = r.u64();
        if (count > 200000) throw std::runtime_error("entry count implausible");
        c.entries.clear();
        c.entries.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            uint256 h = r.hash();
            auto blob = r.blob();
            MNState st;
            ::PackStream ps(std::vector<unsigned char>(blob.begin(), blob.end()));
            ps >> st;
            c.entries.emplace_back(h, std::move(st));
        }
        // Trailing bytes mean the writer and the reader disagree about the
        // shape of the record. Refuse: "it parsed a prefix" is precisely the
        // half-resume this store must not permit.
        if (r.at != n) throw std::runtime_error("payload has trailing bytes");
    }
};

} // namespace coin
} // namespace dash
