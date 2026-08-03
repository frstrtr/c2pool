// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// DIP-0024 rotated-quorum sourcing, wire layer: CGetQuorumRotationInfo /
// CQuorumRotationInfo ("getqrinfo" / "qrinfo").
//
// WHY THIS EXISTS
// ---------------
// A NON-rotated quorum's member set is derivable from ONE snapshot at the
// work block (base - 8): that is what quorum_member_source.hpp's getmnlistd
// path does. A ROTATED (DIP-24) quorum's set is NOT — dashcore's
// ComputeQuorumMembersByQuarterRotation assembles it from the three
// quarter-rotation SNAPSHOTS plus the cycle-base mnlistdiffs, and the ONLY
// wire message that carries those is qrinfo.
//
// WIRE FORMAT — PINNED FROM A REAL CAPTURE, NOT FROM THE HEADER COMMENT
// ---------------------------------------------------------------------
// The field order below was pinned byte-exactly against a real 602'189-byte
// qrinfo captured read-only from testnet (llmq_60_75 cycle base 1520064); the
// fixture is test/fixtures/dash_testnet_qrinfo_1520064.bin and the KAT decodes
// it with ZERO bytes left over.
//
// ⚠ ONE FIELD ORDER DIFFERS FROM THE ORDER YOU WOULD GUESS FROM THE UPSTREAM
// CLASS LAYOUT: in CQuorumSnapshot the wire puts `mnSkipListMode` FIRST, then
// the activeQuorumMembers bitset, then mnSkipList — NOT bitset-first as the
// member declaration order suggests. Decoding bitset-first desynchronises the
// whole message (it "parses" the first snapshot and then overruns). The
// capture is the authority here; do not reorder without re-pinning.
//
// NESTING CONSTRAINT (the reason this is not a two-line struct)
// -------------------------------------------------------------
// smldiff.hpp's CSimplifiedMNListDiff deliberately DRAINS THE REST OF THE
// STREAM into its opaque `quorum_tail`. That is correct for a standalone
// "mnlistdiff" message (the diff IS the whole payload) but makes the type
// impossible to nest: inside qrinfo each diff is followed by more fields, and
// a draining reader would swallow them. So this header reads nested diffs with
// an explicitly STRUCTURED tail (deletedQuorums + newQuorums + quorumsCLSigs)
// that consumes exactly its own bytes, and then re-materialises the byte-exact
// opaque `quorum_tail` so that every existing consumer of a
// CSimplifiedMNListDiff (parse_quorum_tail, authenticate_historical_snapshot,
// apply_diff) behaves identically whether the diff arrived standalone or
// nested. The re-materialisation is SELF-CHECKING: if re-serialising the
// parsed tail does not reproduce exactly the number of bytes consumed, the
// decode FAILS CLOSED rather than handing back a diff with a silently wrong
// tail.
// ═══════════════════════════════════════════════════════════════════════════

#include <impl/dash/coin/vendor/smldiff.hpp>          // CSimplifiedMNListDiff
#include <impl/dash/coin/vendor/quorum_tail.hpp>      // QuorumTail
#include <impl/dash/coin/vendor/llmq_commitment.hpp>  // CFinalCommitment, DynBitSetFormat

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <optional>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// ── CQuorumSnapshot (dashcore llmq/snapshot.h) ────────────────────────────
// Records, for one quarter-rotation cycle boundary, which members of the
// sorted MN list were "active" and how the skip list encodes the rest.
struct CQuorumSnapshot
{
    // dashcore SnapshotSkipMode.
    static constexpr int32_t MODE_NO_SKIPPING       = 0;
    static constexpr int32_t MODE_SKIPPING_ENTRIES  = 1;
    static constexpr int32_t MODE_NO_SKIPPING_ENTRIES = 2;
    static constexpr int32_t MODE_ALL_SKIPPED       = 3;

    // Bound on the encoded sizes: a malicious peer must not be able to make
    // us allocate unboundedly from a 3-byte length prefix. Testnet's real
    // list is 371 entries with a 523-entry skip list; 100k is far above any
    // plausible MN count while still refusing an 0xffffffff length.
    static constexpr size_t kMaxEntries = 100'000;

    int32_t              mnSkipListMode{MODE_NO_SKIPPING};
    std::vector<bool>    activeQuorumMembers;
    std::vector<int32_t> mnSkipList;

    // WIRE ORDER IS mode, bitset, skiplist — see the header note.
    C2POOL_SERIALIZE_METHODS(CQuorumSnapshot)
    {
        READWRITE(obj.mnSkipListMode,
                  Using<DynBitSetFormat>(obj.activeQuorumMembers),
                  obj.mnSkipList);
    }

    bool sane() const
    {
        if (mnSkipListMode < MODE_NO_SKIPPING || mnSkipListMode > MODE_ALL_SKIPPED)
            return false;
        if (activeQuorumMembers.size() > kMaxEntries) return false;
        if (mnSkipList.size() > kMaxEntries) return false;
        return true;
    }
};

// ── nested CSimplifiedMNListDiff ──────────────────────────────────────────
// Read one diff from a stream that CONTINUES past it. Returns false (fail
// closed) if the structured tail cannot be re-materialised byte-exactly.
template <typename Stream>
inline bool unserialize_nested_mnlistdiff(Stream& s, CSimplifiedMNListDiff& out)
{
    // Head: everything up to and including mnList is unambiguous and
    // self-delimiting, so it can be read with the existing field types.
    s >> out.nVersion;
    s >> out.baseBlockHash;
    s >> out.blockHash;
    s >> out.cbTxMerkleTree;
    s >> out.cbTx;
    s >> out.deletedMNs;
    s >> out.mnList;

    // Tail: STRUCTURED (so it consumes exactly its own bytes), then
    // re-serialised back into the opaque field every other consumer reads.
    const size_t before = s.cursor_size();

    QuorumTail tail;
    {
        uint64_t n = ReadCompactSize(s);
        if (n > CQuorumSnapshot::kMaxEntries) return false;
        tail.deletedQuorums.clear();
        tail.deletedQuorums.reserve(static_cast<size_t>(n));
        for (uint64_t i = 0; i < n; ++i) {
            uint8_t llmq_type = 0;
            uint256 hash;
            s >> llmq_type;
            s >> hash;
            tail.deletedQuorums.emplace_back(llmq_type, hash);
        }
    }
    {
        uint64_t n = ReadCompactSize(s);
        if (n > CQuorumSnapshot::kMaxEntries) return false;
        tail.newQuorums.clear();
        tail.newQuorums.reserve(static_cast<size_t>(n));
        for (uint64_t i = 0; i < n; ++i) {
            CFinalCommitment c;
            s >> c;
            tail.newQuorums.push_back(std::move(c));
        }
    }
    {
        uint64_t n = ReadCompactSize(s);
        if (n > CQuorumSnapshot::kMaxEntries) return false;
        tail.quorumsCLSigs.clear();
        tail.quorumsCLSigs.reserve(static_cast<size_t>(n));
        for (uint64_t i = 0; i < n; ++i) {
            std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE> sig{};
            s.read(std::as_writable_bytes(std::span{sig}));
            uint64_t m = ReadCompactSize(s);
            if (m > CQuorumSnapshot::kMaxEntries) return false;
            std::vector<uint16_t> indices;
            indices.reserve(static_cast<size_t>(m));
            for (uint64_t j = 0; j < m; ++j) {
                uint16_t idx = 0;
                s >> idx;
                indices.push_back(idx);
            }
            tail.quorumsCLSigs.emplace_back(sig, std::move(indices));
        }
    }
    const size_t consumed = before - s.cursor_size();

    // Re-materialise the opaque tail byte-exactly. SELF-CHECKING: a length
    // mismatch means our structured grammar is not the inverse of the wire's,
    // so we refuse the whole diff instead of returning a wrong tail.
    ::PackStream ts;
    WriteCompactSize(ts, tail.deletedQuorums.size());
    for (const auto& [llmq_type, hash] : tail.deletedQuorums) {
        ts << llmq_type;
        ts << hash;
    }
    WriteCompactSize(ts, tail.newQuorums.size());
    for (const auto& c : tail.newQuorums) ts << c;
    WriteCompactSize(ts, tail.quorumsCLSigs.size());
    for (const auto& [sig, indices] : tail.quorumsCLSigs) {
        ts.write(std::as_bytes(std::span{sig}));
        WriteCompactSize(ts, indices.size());
        for (uint16_t idx : indices) ts << idx;
    }

    out.quorum_tail.assign(reinterpret_cast<const unsigned char*>(ts.data()),
                           reinterpret_cast<const unsigned char*>(ts.data())
                               + ts.cursor_size());
    return out.quorum_tail.size() == consumed;
}

// ── CGetQuorumRotationInfo (request) ──────────────────────────────────────
struct CGetQuorumRotationInfo
{
    std::vector<uint256> baseBlockHashes;
    uint256              blockRequestHash;
    bool                 extraShare{false};

    C2POOL_SERIALIZE_METHODS(CGetQuorumRotationInfo)
    {
        READWRITE(obj.baseBlockHashes, obj.blockRequestHash, obj.extraShare);
    }
};

// ── CQuorumRotationInfo (reply) ───────────────────────────────────────────
// Deliberately NOT given a C2POOL_SERIALIZE_METHODS: the nested diffs need the
// fail-closed reader above, which returns a bool. Use decode_quorum_rotation_info.
struct CQuorumRotationInfo
{
    CQuorumSnapshot        quorumSnapshotAtHMinusC;
    CQuorumSnapshot        quorumSnapshotAtHMinus2C;
    CQuorumSnapshot        quorumSnapshotAtHMinus3C;

    CSimplifiedMNListDiff  mnListDiffTip;
    CSimplifiedMNListDiff  mnListDiffH;
    CSimplifiedMNListDiff  mnListDiffAtHMinusC;
    CSimplifiedMNListDiff  mnListDiffAtHMinus2C;
    CSimplifiedMNListDiff  mnListDiffAtHMinus3C;

    bool                                 extraShare{false};
    std::optional<CQuorumSnapshot>       quorumSnapshotAtHMinus4C;
    std::optional<CSimplifiedMNListDiff> mnListDiffAtHMinus4C;

    std::vector<CFinalCommitment>       lastCommitmentPerIndex;
    std::vector<CQuorumSnapshot>        quorumSnapshotList;
    std::vector<CSimplifiedMNListDiff>  mnListDiffList;
};

/// Decode a qrinfo payload. Returns false (fail closed) on ANY malformation,
/// on a nested-diff tail mismatch, or on TRAILING BYTES — a peer must not be
/// able to smuggle unread bytes past us.
inline bool decode_quorum_rotation_info(const std::vector<unsigned char>& payload,
                                        CQuorumRotationInfo& out)
{
    try {
        ::PackStream s(payload);

        s >> out.quorumSnapshotAtHMinusC;
        s >> out.quorumSnapshotAtHMinus2C;
        s >> out.quorumSnapshotAtHMinus3C;
        if (!out.quorumSnapshotAtHMinusC.sane()
            || !out.quorumSnapshotAtHMinus2C.sane()
            || !out.quorumSnapshotAtHMinus3C.sane()) return false;

        if (!unserialize_nested_mnlistdiff(s, out.mnListDiffTip))         return false;
        if (!unserialize_nested_mnlistdiff(s, out.mnListDiffH))           return false;
        if (!unserialize_nested_mnlistdiff(s, out.mnListDiffAtHMinusC))   return false;
        if (!unserialize_nested_mnlistdiff(s, out.mnListDiffAtHMinus2C))  return false;
        if (!unserialize_nested_mnlistdiff(s, out.mnListDiffAtHMinus3C))  return false;

        uint8_t extra = 0;
        s >> extra;
        out.extraShare = (extra != 0);
        if (out.extraShare) {
            CQuorumSnapshot snap4c;
            s >> snap4c;
            if (!snap4c.sane()) return false;
            CSimplifiedMNListDiff diff4c;
            if (!unserialize_nested_mnlistdiff(s, diff4c)) return false;
            out.quorumSnapshotAtHMinus4C = std::move(snap4c);
            out.mnListDiffAtHMinus4C     = std::move(diff4c);
        }

        {
            uint64_t n = ReadCompactSize(s);
            if (n > CQuorumSnapshot::kMaxEntries) return false;
            out.lastCommitmentPerIndex.clear();
            out.lastCommitmentPerIndex.reserve(static_cast<size_t>(n));
            for (uint64_t i = 0; i < n; ++i) {
                CFinalCommitment c;
                s >> c;
                out.lastCommitmentPerIndex.push_back(std::move(c));
            }
        }
        {
            uint64_t n = ReadCompactSize(s);
            if (n > CQuorumSnapshot::kMaxEntries) return false;
            out.quorumSnapshotList.clear();
            out.quorumSnapshotList.reserve(static_cast<size_t>(n));
            for (uint64_t i = 0; i < n; ++i) {
                CQuorumSnapshot snap;
                s >> snap;
                if (!snap.sane()) return false;
                out.quorumSnapshotList.push_back(std::move(snap));
            }
        }
        {
            uint64_t n = ReadCompactSize(s);
            if (n > CQuorumSnapshot::kMaxEntries) return false;
            out.mnListDiffList.clear();
            out.mnListDiffList.reserve(static_cast<size_t>(n));
            for (uint64_t i = 0; i < n; ++i) {
                CSimplifiedMNListDiff d;
                if (!unserialize_nested_mnlistdiff(s, d)) return false;
                out.mnListDiffList.push_back(std::move(d));
            }
        }

        // No trailing bytes.
        return s.cursor_size() == 0;
    } catch (...) {
        return false;   // short read / bad compact size => fail closed
    }
}

} // namespace vendor
} // namespace coin
} // namespace dash
