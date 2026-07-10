// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Vendored from dashcore/src/evo/cbtx.h @ develop cfad414
// (Dash Core v23.1-dev, current `develop` branch as of 2026-04-23).
//
// Adaptations from upstream:
//   1. CCbTx::Version is an `enum class` upstream, kept serializable via
//      `is_serializable_enum` template specialization. pack.hpp doesn't
//      have an equivalent specialization machinery; we store nVersion as
//      a raw uint16_t and expose the named values as constexpr constants.
//   2. CBLSSignature is replaced by a 96-byte std::array. We don't
//      verify BLS signatures at Phase C-SML — Phase L will introduce a
//      real BLS lib and migrate this field. The wire bytes are
//      preserved unchanged so future verification can re-hydrate.
//   3. CAmount → int64_t (c2pool has no CAmount typedef; the wire
//      width is identical, signed 64-bit LE).
//   4. SERIALIZE_METHODS body re-expressed in pack.hpp form. See
//      vendor/shim.hpp preamble for why pack.hpp + btclibs/serialize.h
//      cannot share a translation unit.
//   5. The validation functions (CheckCbTx, CalcCbTxMerkleRootQuorums,
//      GetNonNullCoinbaseChainlock) are NOT vendored — they require
//      ChainstateManager + CDeterministicMNList + LLMQ infrastructure
//      we don't have. We only need wire decode + the merkleRootMNList
//      field to verify against our own SML in Phase C-SML step 7.

#include <impl/dash/coin/vendor/shim.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/log.hpp>

#include <array>
#include <cstdint>
#include <sstream>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

struct CCbTx
{
    static constexpr uint16_t VERSION_INVALID             = 0;
    static constexpr uint16_t VERSION_MERKLE_ROOT_MNLIST  = 1;
    static constexpr uint16_t VERSION_MERKLE_ROOT_QUORUMS = 2;
    static constexpr uint16_t VERSION_CLSIG_AND_BALANCE   = 3;

    static constexpr size_t BLS_SIG_SIZE = 96;

    uint16_t                          nVersion{VERSION_MERKLE_ROOT_QUORUMS};
    int32_t                           nHeight{0};
    uint256                           merkleRootMNList;
    uint256                           merkleRootQuorums;
    uint32_t                          bestCLHeightDiff{0};
    std::array<uint8_t, BLS_SIG_SIZE> bestCLSignature{};
    int64_t                           creditPoolBalance{0};

    C2POOL_SERIALIZE_METHODS(CCbTx)
    {
        READWRITE(obj.nVersion, obj.nHeight, obj.merkleRootMNList);
        if (obj.nVersion >= VERSION_MERKLE_ROOT_QUORUMS) {
            READWRITE(obj.merkleRootQuorums);
            if (obj.nVersion >= VERSION_CLSIG_AND_BALANCE) {
                READWRITE(VarInt(obj.bestCLHeightDiff));
                READWRITE(Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.bestCLSignature));
                READWRITE(obj.creditPoolBalance);
            }
        }
    }

    // True if any byte of bestCLSignature is non-zero. Empty (all-zero)
    // sigs are valid wire encodings — they signal "no chainlock for the
    // window" — and must NOT be treated as verification failures.
    bool has_best_cl_signature() const
    {
        for (auto b : bestCLSignature) if (b != 0) return true;
        return false;
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "v=" << nVersion
           << " h=" << nHeight
           << " mnlist=" << merkleRootMNList.GetHex().substr(0, 16);
        if (nVersion >= VERSION_MERKLE_ROOT_QUORUMS)
            os << " quorums=" << merkleRootQuorums.GetHex().substr(0, 16);
        if (nVersion >= VERSION_CLSIG_AND_BALANCE) {
            os << " clHeightDiff=" << bestCLHeightDiff
               << " clSig=" << (has_best_cl_signature() ? "set" : "null")
               << " creditPool=" << creditPoolBalance;
        }
        return os.str();
    }
};

// Decode CCbTx from a coinbase tx's extra_payload bytes. Returns false
// if the payload is empty, malformed, or has trailing garbage.
inline bool parse_cbtx(const std::vector<unsigned char>& extra_payload, CCbTx& out)
{
    if (extra_payload.empty()) return false;
    try {
        ::PackStream s(extra_payload);
        s >> out;
        // Strict: trailing bytes after the CCbTx mean we have a wrong
        // version assumption or upstream added a new field. Either way
        // the merkle-root-mn-list field we just read may be off.
        if (s.cursor_size() != 0) {
            LOG_WARNING << "[CBTX] " << s.cursor_size()
                        << " trailing bytes after CCbTx (v=" << out.nVersion
                        << ") — possible wire-format drift";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_WARNING << "[CBTX] parse failed: " << e.what()
                    << " payload_size=" << extra_payload.size();
        return false;
    }
}

} // namespace vendor
} // namespace coin
} // namespace dash