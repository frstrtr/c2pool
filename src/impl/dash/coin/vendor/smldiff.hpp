#pragma once

// Vendored from dashcore/src/evo/smldiff.h @ develop cfad414
// (Dash Core v23.1-dev). Phase C-SML step 3.
//
// Adaptations:
//
//   1. Same wire-version pinning as simplifiedmns.hpp — we assume
//      MNLISTDIFF_VERSION_ORDER (70229) is active because we advertise
//      proto 70230. Therefore nVersion is the FIRST field, and the
//      legacy "nVersion after cbTx" branch is omitted.
//
//   2. MNLISTDIFF_CHAINLOCKS_PROTO_VERSION (70230) is also active at
//      our exact advertised version, so quorumsCLSigs IS in the wire
//      format. We don't interpret it — see point 4.
//
//   3. CPartialMerkleTree is reimplemented as a 3-field struct with
//      opaque vBits bytes (we never need to walk the proof — we have
//      the full block from Phase U and the cbTx is included verbatim
//      below). Wire format: nTransactions LE32 | vHash[] | vBits[]
//      (vBits as CompactSize-prefixed packed bytes).
//
//   4. The trailing quorum data (deletedQuorums, newQuorums,
//      quorumsCLSigs) is slurped into an opaque `quorum_tail`
//      std::vector<uint8_t>. apply_diff doesn't need it (Phase C-QUO
//      will re-vendor properly with CFinalCommitment + DYNBITSET +
//      BLS sig map). For now opaque-tail keeps round-trip of unknown
//      bytes correct in case we want to retransmit a cached diff.
//
//   5. apply_diff(current, diff) is hand-written to mirror dashcore's
//      semantics: erase entries from `current` whose proRegTxHash is
//      in deletedMNs, then for each entry in diff.mnList replace the
//      existing entry (matched by proRegTxHash) or insert if new,
//      then re-sort the resulting list. Dashcore uses a different
//      data structure internally but the observable result on a
//      sorted SML is identical.

#include <impl/dash/coin/vendor/shim.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// Minimal CPartialMerkleTree — wire-skip-only. We never reconstruct the
// tree; the cbTxMerkleTree exists in the diff so a verifying node can
// confirm the cbTx is in the block, but we already have the full block
// from Phase U so the proof is redundant for us.
struct CPartialMerkleTreeStub
{
    uint32_t                   nTransactions{0};
    std::vector<uint256>       vHash;
    std::vector<unsigned char> vBitsBytes;  // packed bits, opaque

    SERIALIZE_METHODS(CPartialMerkleTreeStub)
    {
        READWRITE(obj.nTransactions, obj.vHash, obj.vBitsBytes);
    }
};

struct CSimplifiedMNListDiff
{
    static constexpr uint16_t CURRENT_VERSION = 1;

    uint16_t                              nVersion{CURRENT_VERSION};
    uint256                               baseBlockHash;
    uint256                               blockHash;
    CPartialMerkleTreeStub                cbTxMerkleTree;
    ::dash::coin::MutableTransaction      cbTx;
    std::vector<uint256>                  deletedMNs;
    std::vector<CSimplifiedMNListEntry>   mnList;

    // Opaque tail: deletedQuorums + newQuorums + quorumsCLSigs.
    // Phase C-QUO will replace this with structured fields.
    std::vector<unsigned char>            quorum_tail;

    SERIALIZE_METHODS(CSimplifiedMNListDiff)
    {
        READWRITE(obj.nVersion,
                  obj.baseBlockHash,
                  obj.blockHash,
                  obj.cbTxMerkleTree,
                  obj.cbTx,
                  obj.deletedMNs,
                  obj.mnList);
        // Drain remaining stream bytes as the opaque quorum tail.
        if constexpr (std::is_same_v<Formatter, UnserializeFormatter>) {
            size_t tail = stream.cursor_size();
            obj.quorum_tail.resize(tail);
            if (tail) {
                stream.read(std::as_writable_bytes(
                    std::span{obj.quorum_tail}));
            }
        } else {
            if (!obj.quorum_tail.empty()) {
                stream.write(std::as_bytes(
                    std::span{obj.quorum_tail}));
            }
        }
    }
};

// Apply a CSimplifiedMNListDiff to a CSimplifiedMNList in place.
// Mirrors dashcore semantics (modulo internal data-structure choice):
//   1. Remove entries whose proRegTxHash appears in diff.deletedMNs.
//   2. For each entry in diff.mnList, replace the existing entry with
//      the same proRegTxHash, or insert if not present.
//   3. Re-sort by proRegTxHash to keep merkle-root computation stable.
// Returns the number of entries added/updated and the number deleted.
struct ApplyDiffResult
{
    size_t added_or_updated{0};
    size_t deleted{0};
};

inline ApplyDiffResult apply_diff(CSimplifiedMNList& current,
                                  const CSimplifiedMNListDiff& diff)
{
    ApplyDiffResult result;

    if (!diff.deletedMNs.empty()) {
        // Build a set for O(N log M) lookup; deletedMNs is typically
        // small (single-digit) so a sorted vector is enough.
        std::vector<uint256> del = diff.deletedMNs;
        std::sort(del.begin(), del.end());
        auto in_del = [&del](const uint256& h) {
            return std::binary_search(del.begin(), del.end(), h);
        };
        auto before = current.mnList.size();
        current.mnList.erase(
            std::remove_if(current.mnList.begin(), current.mnList.end(),
                [&](const CSimplifiedMNListEntry& e) {
                    return in_del(e.proRegTxHash);
                }),
            current.mnList.end());
        result.deleted = before - current.mnList.size();
    }

    for (const auto& incoming : diff.mnList) {
        auto it = std::find_if(current.mnList.begin(), current.mnList.end(),
            [&](const CSimplifiedMNListEntry& e) {
                return e.proRegTxHash == incoming.proRegTxHash;
            });
        if (it != current.mnList.end()) {
            *it = incoming;
        } else {
            current.mnList.push_back(incoming);
        }
        ++result.added_or_updated;
    }

    current.sort();
    return result;
}

} // namespace vendor
} // namespace coin
} // namespace dash
