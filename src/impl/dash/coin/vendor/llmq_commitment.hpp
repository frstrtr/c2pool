// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Vendored from dashcore/src/llmq/commitment.h @ develop cfad414
// (Dash Core v23.1-dev). Phase C-QUO step 1.
//
// Adaptations from upstream:
//
//   1. nVersion stored as raw uint16_t — pack.hpp doesn't support enum-
//      class serialization with the is_serializable_enum specialization
//      machinery dashcore uses. Named constants kept as constexpr.
//
//   2. LLMQType (Consensus::LLMQType) is uint8_t under the hood. We
//      store as raw uint8_t and define the named-quorum constants as
//      readable constexpr values.
//
//   3. CBLSPublicKey replaced by 48-byte std::array. CBLSSignature
//      replaced by 96-byte std::array. We store wire bytes opaquely;
//      Phase L picks a real BLS lib and adds verification.
//
//   4. CBLSPublicKeyVersionWrapper / CBLSSignatureVersionWrapper just
//      pick legacy-vs-basic curve scheme — at the wire layer both
//      variants emit the same number of bytes (48 / 96), so we drop
//      the wrappers and serialize raw. The legacy/basic flag matters
//      only at point-decompression time, which we don't do.
//
//   5. SERIALIZE_METHODS body re-expressed in pack.hpp form (1-arg
//      macro, formatter-type discrimination). DYNBITSET is implemented
//      below as DynBitSetFormat — wire-identical to dashcore's
//      DynamicBitSetFormatter (CompactSize(nBits) + ceil(nBits/8)
//      bytes, LSB-first within each byte, with a trailing-pad-zero
//      check on read for malleation resistance).
//
//   6. Validation methods (Verify, VerifySignatureAsync, VerifyNull,
//      VerifySizes) are NOT vendored — they require BLS verification,
//      LLMQParams from chain context, and CCheckQueueControl. Phase L
//      will add a minimal verifier.

#include <impl/dash/coin/vendor/shim.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// ── DYNBITSET formatter ────────────────────────────────────────────────────
//
// Wire format:
//   CompactSize(nBits)
//   ceil(nBits/8) bytes packed LSB-first within each byte:
//       byte[i] bit (1 << j) holds vec[i*8 + j]
//   Read MUST verify trailing pad bits in the last byte are zero
//   (dashcore serialize.h:447-452 — protects against malleation).
struct DynBitSetFormat
{
    template <typename Stream>
    static void Write(Stream& s, const std::vector<bool>& vec)
    {
        WriteCompactSize(s, vec.size());
        std::vector<uint8_t> bytes((vec.size() + 7) / 8, 0);
        for (size_t p = 0; p < vec.size(); ++p) {
            if (vec[p]) bytes[p / 8] |= static_cast<uint8_t>(1u << (p % 8));
        }
        if (!bytes.empty()) {
            s.write(std::as_bytes(std::span{bytes}));
        }
    }

    template <typename Stream>
    static void Read(Stream& s, std::vector<bool>& vec)
    {
        size_t n = ReadCompactSize(s);
        vec.assign(n, false);
        size_t nbytes = (n + 7) / 8;
        std::vector<uint8_t> bytes(nbytes, 0);
        if (nbytes > 0) {
            s.read(std::as_writable_bytes(std::span{bytes}));
        }
        for (size_t p = 0; p < n; ++p) {
            vec[p] = (bytes[p / 8] & static_cast<uint8_t>(1u << (p % 8))) != 0;
        }
        if (nbytes * 8 != n) {
            // Validate trailing pad bits are zero (matches upstream).
            size_t rem = nbytes * 8 - n;
            uint8_t mask = static_cast<uint8_t>(~(0xffu >> rem));
            if (bytes.back() & mask) {
                throw std::ios_base::failure(
                    "DynBitSet: out-of-range bits set");
            }
        }
    }
};

// ── CFinalCommitment ──────────────────────────────────────────────────────

struct CFinalCommitment
{
    static constexpr uint16_t LEGACY_BLS_NON_INDEXED_QUORUM_VERSION = 1;
    static constexpr uint16_t LEGACY_BLS_INDEXED_QUORUM_VERSION     = 2;
    static constexpr uint16_t BASIC_BLS_NON_INDEXED_QUORUM_VERSION  = 3;
    static constexpr uint16_t BASIC_BLS_INDEXED_QUORUM_VERSION      = 4;

    static constexpr size_t BLS_PUBKEY_SIZE = 48;
    static constexpr size_t BLS_SIG_SIZE    = 96;

    // LLMQType named values for production quorums (dashcore params.h:14).
    // 0xff = LLMQ_NONE.
    static constexpr uint8_t LLMQ_NONE      = 0xff;
    static constexpr uint8_t LLMQ_50_60     = 1;
    static constexpr uint8_t LLMQ_400_60    = 2;
    static constexpr uint8_t LLMQ_400_85    = 3;
    static constexpr uint8_t LLMQ_100_67    = 4;
    static constexpr uint8_t LLMQ_60_75     = 5;
    static constexpr uint8_t LLMQ_25_67     = 6;

    uint16_t                              nVersion{LEGACY_BLS_NON_INDEXED_QUORUM_VERSION};
    uint8_t                               llmqType{LLMQ_NONE};
    uint256                               quorumHash;
    int16_t                               quorumIndex{0};        // only if INDEXED variant
    std::vector<bool>                     signers;                // DYNBITSET
    std::vector<bool>                     validMembers;           // DYNBITSET
    std::array<uint8_t, BLS_PUBKEY_SIZE>  quorumPublicKey{};
    uint256                               quorumVvecHash;
    std::array<uint8_t, BLS_SIG_SIZE>     quorumSig{};
    std::array<uint8_t, BLS_SIG_SIZE>     membersSig{};

    bool is_indexed_version() const
    {
        return nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION
            || nVersion == BASIC_BLS_INDEXED_QUORUM_VERSION;
    }

    C2POOL_SERIALIZE_METHODS(CFinalCommitment)
    {
        READWRITE(obj.nVersion, obj.llmqType, obj.quorumHash);
        if (obj.nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION
            || obj.nVersion == BASIC_BLS_INDEXED_QUORUM_VERSION) {
            READWRITE(obj.quorumIndex);
        }
        READWRITE(Using<DynBitSetFormat>(obj.signers),
                  Using<DynBitSetFormat>(obj.validMembers),
                  Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(obj.quorumPublicKey),
                  obj.quorumVvecHash,
                  Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.quorumSig),
                  Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.membersSig));
    }

    int CountSigners() const
    {
        return static_cast<int>(
            std::count(signers.begin(), signers.end(), true));
    }

    int CountValidMembers() const
    {
        return static_cast<int>(
            std::count(validMembers.begin(), validMembers.end(), true));
    }
};

// ── CFinalCommitmentTxPayload ─────────────────────────────────────────────
//
// The wrapping payload for type-6 (TRANSACTION_QUORUM_COMMITMENT)
// special txs. Each accepted Dash block can carry one or more of
// these — they're how a successfully-finalized DKG cycle's commitment
// gets committed to the chain.
//
// We parse them in on_full_block to track per-quorum mining heights
// (Phase C-TEMPLATE step 3 prep): merkleRootQuorums computation needs
// to order quorums by mining height (newest-first per llmqType), and
// mnlistdiff alone doesn't carry that info — only the chain does.
//
// Vendored from dashcore/src/llmq/commitment.h:147-165 @ cfad414.
struct CFinalCommitmentTxPayload
{
    static constexpr uint16_t SPECIALTX_TYPE = 6;
    static constexpr uint16_t CURRENT_VERSION = 1;

    uint16_t          nVersion{CURRENT_VERSION};
    uint32_t          nHeight{0};
    CFinalCommitment  commitment;

    C2POOL_SERIALIZE_METHODS(CFinalCommitmentTxPayload)
    {
        READWRITE(obj.nVersion, obj.nHeight, obj.commitment);
    }
};

inline bool parse_qfcommit_payload(const std::vector<unsigned char>& bytes,
                                   CFinalCommitmentTxPayload& out)
{
    if (bytes.empty()) return false;
    try {
        ::PackStream s(bytes);
        s >> out;
        // Match the strict-tail policy from parse_protx_payload — an
        // unconsumed remainder is a wire-format drift smell.
        return s.cursor_size() == 0;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace vendor
} // namespace coin
} // namespace dash