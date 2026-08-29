// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::coin -- won-block ASSEMBLY SSOT + pre-broadcast self-check.
//
// WHY THIS EXISTS (G2 zero-blocks root cause, 2026-07-23)
// -------------------------------------------------------
// The live pool accumulated ~774k accepted solutions and produced ZERO blocks.
// The dispatcher was fine; every won block was REJECTED by the node with
// `bad-txnmrklroot`. The relayed body measured 155 bytes:
//
//     80 (header) + 1 (tx-count varint) + 74 (generation transaction)
//
// and that 74-byte generation transaction decomposes as
//
//     62 (first coinbase segment) + 8 (extranonce) + 4 (locktime)
//
// The 62-byte first segment is
//     4 version | 1 vin-count | 32 prevout-hash | 4 prevout-index
//   | 1 scriptSig-len | 15 scriptSig | 4 sequence | 1 OUTPUT-COUNT = 0x00
//
// i.e. the first segment TERMINATES AT AN OUTPUT COUNT OF ZERO, and the miner's
// 8 extranonce bytes are then spliced AFTER the (empty) output vector, in front
// of the locktime. The bytes the miner hashed therefore do not deserialize as
// the transaction anyone downstream reconstructs, so the recomputed root never
// equals the header's root. Two independent defects produced it:
//
//   (a) the job builder emitted a generation transaction with zero outputs
//       whenever the commitment output was suppressed (no reference hash) and
//       the payout set was empty, and
//   (b) the extranonce slot is only well-defined when it sits INSIDE a real
//       commitment output; with no such output the splice point degenerates to
//       "end of the output vector".
//
// (a)+(b) are fixed at the source in the stratum job builder (fail-closed: a
// zero-output generation transaction is never published, and the extranonce
// slot always lands inside a real commitment output). THIS file is the second,
// independent line of defence: nothing is relayed until the assembled block has
// been re-deserialized from its own wire bytes and its transaction root
// recomputed and matched against the header the miner actually solved.
//
// Mirrors the shape nmc/dgb already ship (assemble_won_block +
// reconstruct_won_block), with a BCH-native addition: verify_assembled_block()
// is a hard gate, not advisory. A mismatch REFUSES the relay and names the
// reason instead of shipping a body the node will reject.
//
// Per-coin isolation: src/impl/bch/ ONLY. Shared base (src/core,
// bitcoin_family) untouched. p2pool-merged-v36 SURFACE: NONE -- this is parent
// block framing, not share format / PPLNS / coinbase-commitment semantics.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include "block.hpp"        // BlockType / BlockHeaderType / SmallBlockHeaderType
#include "mempool.hpp"      // compute_txid
#include "merkle.hpp"       // compute_merkle_root
#include "transaction.hpp"  // MutableTransaction

namespace bch
{
namespace coin
{

/// Verdict of the pre-broadcast self-check. `ok == false` means DO NOT RELAY.
struct BlockSelfCheck
{
    bool        ok = false;
    const char* reason = "unchecked";  ///< static reason string; "" when ok
    size_t      tx_count = 0;
    size_t      gentx_outputs = 0;
    uint256     header_merkle_root{};    ///< as carried by the assembled header
    uint256     computed_merkle_root{};  ///< recomputed from the decoded tx list

    explicit operator bool() const { return ok; }
};

/// A fully assembled + self-checked won block.
///   bytes : the blob the embedded P2P relay sends
///   hex   : the SAME block for the external BCHN submitblock RPC fallback
/// `check.ok` is the relay gate; assemble_and_verify_won_block() only ever
/// hands back a value whose check passed.
struct AssembledBlock
{
    std::vector<unsigned char> bytes;
    std::string                hex;
    BlockSelfCheck             check;
};

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Serialize `header80 || CompactSize(1 + other_txs) || gentx_bytes || other_txs`.
///
/// The generation transaction is passed as the EXACT serialized buffer its txid
/// was hashed from, so the relayed coinbase is byte-identical to the one
/// consensus and the sharechain validated -- there is no second derivation path
/// and therefore no divergence risk. `other_txs` is any range of pointers to a
/// type the PackStream `<<` operator accepts (coin::Transaction on the pool
/// reconstruct path, coin::MutableTransaction on the template path).
template <class OtherTxPtrRange>
inline std::vector<unsigned char>
frame_won_block(std::span<const unsigned char> header80,
                std::span<const unsigned char> gentx_bytes,
                const OtherTxPtrRange& other_txs)
{
    PackStream block_stream;
    block_stream.write(std::as_bytes(header80));

    size_t n_other = 0;
    for (auto it = other_txs.begin(); it != other_txs.end(); ++it) ++n_other;
    WriteCompactSize(block_stream, static_cast<uint64_t>(1 + n_other));

    block_stream.write(std::as_bytes(gentx_bytes));
    for (const auto* tx : other_txs)
        block_stream << *tx;

    auto sp = block_stream.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

/// Typed framing overload: `[gentx] ++ other_txs` through the proven BlockType
/// codec (the same codec NodeRPC::submit_block and the P2P relay use), so the
/// result is byte-identical to a daemon-built block. Mirrors the nmc/dgb SSOT.
inline std::vector<unsigned char>
frame_won_block(const BlockHeaderType& header,
                const MutableTransaction& gentx,
                const std::vector<MutableTransaction>& other_txs)
{
    BlockType block;
    static_cast<BlockHeaderType&>(block) = header;
    block.m_txs.reserve(1 + other_txs.size());
    block.m_txs.push_back(gentx);
    for (const auto& tx : other_txs)
        block.m_txs.push_back(tx);

    PackStream packed = pack<BlockType>(block);
    auto sp = packed.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// ---------------------------------------------------------------------------
// Pre-broadcast self-check -- the gate that would have caught the 155-byte body
// ---------------------------------------------------------------------------

/// Re-deserialize `block_bytes` FROM ITS OWN WIRE ENCODING and recompute the
/// transaction merkle root over the decoded transaction list, then match it
/// against the root carried by the decoded header.
///
/// This deliberately re-parses rather than reusing the in-memory objects: the
/// G2 failure was precisely a body whose in-memory intent and wire encoding
/// disagreed. Only a round trip through the wire form can see that.
///
/// Additional structural gates, each of which independently rejects the exact
/// 155-byte body that lost 774k solutions:
///   * at least one transaction (a headerless / txless body is not a block);
///   * the generation transaction has exactly one input; and
///   * the generation transaction has AT LEAST ONE OUTPUT -- a zero-output
///     generation transaction is unspendable, pays nobody, and is the state in
///     which the extranonce splice point degenerates.
///   * no trailing bytes after the decoded block (a short-read would otherwise
///     silently pass).
inline BlockSelfCheck verify_assembled_block(std::span<const unsigned char> block_bytes)
{
    BlockSelfCheck r;

    if (block_bytes.size() < 81) {   // 80-byte header + at least a tx count
        r.reason = "block shorter than a header plus transaction count";
        return r;
    }

    BlockType decoded;
    try {
        PackStream stream(std::vector<unsigned char>(block_bytes.begin(), block_bytes.end()));
        stream >> decoded;
        if (stream.cursor_size() != 0) {
            r.reason = "trailing bytes after decoded block";
            return r;
        }
    } catch (const std::exception&) {
        r.reason = "assembled block does not re-deserialize";
        return r;
    } catch (...) {
        r.reason = "assembled block does not re-deserialize";
        return r;
    }

    r.tx_count = decoded.m_txs.size();
    r.header_merkle_root = decoded.m_merkle_root;

    if (decoded.m_txs.empty()) {
        r.reason = "block carries no transactions";
        return r;
    }

    const auto& gentx = decoded.m_txs.front();
    r.gentx_outputs = gentx.vout.size();

    if (gentx.vin.size() != 1) {
        r.reason = "generation transaction does not have exactly one input";
        return r;
    }
    if (gentx.vout.empty()) {
        // The G2 signature: output count zero, extranonce spliced after the
        // output vector. Refuse loudly rather than relay an unspendable body.
        r.reason = "generation transaction has ZERO outputs";
        return r;
    }

    std::vector<uint256> txids;
    txids.reserve(decoded.m_txs.size());
    for (const auto& tx : decoded.m_txs)
        txids.push_back(compute_txid(tx));
    r.computed_merkle_root = compute_merkle_root(std::move(txids));

    if (r.computed_merkle_root != r.header_merkle_root) {
        r.reason = "recomputed transaction root does not match the solved header";
        return r;
    }

    r.ok = true;
    r.reason = "";
    return r;
}

// ---------------------------------------------------------------------------
// Assemble + gate
// ---------------------------------------------------------------------------

/// Frame a won block and REFUSE to hand it back unless the self-check passes.
/// `out_check` (optional) receives the verdict either way, so callers can log
/// the named reason on refusal.
template <class OtherTxPtrRange>
inline std::optional<AssembledBlock>
assemble_and_verify_won_block(std::span<const unsigned char> header80,
                              std::span<const unsigned char> gentx_bytes,
                              const OtherTxPtrRange& other_txs,
                              BlockSelfCheck* out_check = nullptr)
{
    AssembledBlock out;
    out.bytes = frame_won_block(header80, gentx_bytes, other_txs);
    out.check = verify_assembled_block(out.bytes);
    if (out_check) *out_check = out.check;
    if (!out.check.ok)
        return std::nullopt;

    out.hex = HexStr(std::span<const unsigned char>(out.bytes.data(), out.bytes.size()));
    return out;
}

/// Typed overload (BlockType codec path).
inline std::optional<AssembledBlock>
assemble_and_verify_won_block(const BlockHeaderType& header,
                              const MutableTransaction& gentx,
                              const std::vector<MutableTransaction>& other_txs,
                              BlockSelfCheck* out_check = nullptr)
{
    AssembledBlock out;
    out.bytes = frame_won_block(header, gentx, other_txs);
    out.check = verify_assembled_block(out.bytes);
    if (out_check) *out_check = out.check;
    if (!out.check.ok)
        return std::nullopt;

    out.hex = HexStr(std::span<const unsigned char>(out.bytes.data(), out.bytes.size()));
    return out;
}

} // namespace coin
} // namespace bch
