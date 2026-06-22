#pragma once

/// DOGE AuxPoW Header Parser — Phase 5.8 (M3: structured parser)
///
/// Dogecoin blocks after AuxPoW activation (height 371,337 mainnet, 0 testnet4alpha)
/// carry EXTENDED headers in P2P messages:
///
///   CPureBlockHeader (80 bytes)   — standard Bitcoin header
///   + CAuxPow (variable)          — merge-mining proof (present iff IsAuxpow())
///   + tx_count (CompactSize)      — 0 in a 'headers' message
///
/// M3 replaces the byte-skip parser with a STRUCTURED parse: the AuxPoW proof is
/// deserialized into the CAuxPow / CMerkleTx / CMerkleLink types declared in
/// auxpow.hpp (Phase 5.8 M2) through the standard pack.hpp serialization surface,
/// rather than merely advancing the stream cursor past it. The 80-byte base
/// header is still what HeaderChain consumes; the populated CAuxPow is now
/// available for proof validation (CAuxPow::check_proof, future milestone).
///
/// The structured single-header primitive is doge::coin::parse_aux_header
/// (defined in auxpow.hpp). This file provides the P2P message-level glue:
///   - parse_doge_header          — legacy pos/end shim (one extended header)
///   - parse_doge_headers_message — a 'headers' batch (CompactSize count + N)
///   - parse_doge_block           — a full block (header + AuxPoW + tx list)

#include <impl/doge/coin/auxpow.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace doge {
namespace coin {

using ltc::coin::BlockHeaderType;

// is_auxpow_version() and parse_aux_header() are provided by auxpow.hpp.

/// Parse one DOGE extended header from a raw byte range, advancing `pos`.
///
/// Structured parse: reads the 80-byte base header, deserializes the AuxPoW
/// proof into a CAuxPow when IsAuxpow(version) is set, then consumes the
/// trailing tx_count (CompactSize, always 0 in a 'headers' message).
/// Returns the base header; `pos` is advanced past the full extended header.
/// Throws on truncation/parse failure.
inline BlockHeaderType parse_doge_header(const uint8_t*& pos, const uint8_t* end)
{
    if (end - pos < 80)
        throw std::runtime_error("DOGE header: not enough data for base header");

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(pos),
        static_cast<size_t>(end - pos)));
    const size_t avail = ps.cursor_size();

    CAuxPow<> aux;
    bool has_aux = false;
    BlockHeaderType hdr = parse_aux_header(ps, aux, has_aux);

    // tx_count (CompactSize) — always 0 in a 'headers' message.
    if (ps.cursor_size() > 0)
        (void)ReadCompactSize(ps);

    pos += avail - ps.cursor_size();
    return hdr;
}

/// Parse a batch of DOGE headers from a P2P 'headers' message payload.
/// Returns the vector of base BlockHeaderType (AuxPoW proofs are parsed then
/// dropped; HeaderChain validates against the 80-byte base header).
inline std::vector<BlockHeaderType> parse_doge_headers_message(
    const uint8_t* data, size_t len)
{
    std::vector<BlockHeaderType> result;
    if (data == nullptr || len == 0)
        return result;

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(data), len));

    uint64_t count = 0;
    try {
        count = ReadCompactSize(ps);
    } catch (const std::exception&) {
        return result;
    }

    // A 'headers' message carries at most 2000; cap the speculative reserve.
    result.reserve(static_cast<size_t>(std::min<uint64_t>(count, 4096)));

    CAuxPow<> aux;
    bool has_aux = false;
    for (uint64_t i = 0; i < count && ps.cursor_size() > 0; ++i) {
        try {
            result.push_back(parse_aux_header(ps, aux, has_aux));
            // tx_count (CompactSize) — always 0 in a 'headers' message.
            if (ps.cursor_size() > 0)
                (void)ReadCompactSize(ps);
        } catch (const std::exception&) {
            // Truncated header — return what parsed cleanly.
            break;
        }
    }
    return result;
}

/// Parse a DOGE full block from raw P2P bytes.
/// Structured parse of the header + AuxPoW proof, then the standard tx list.
/// Returns a BlockType with the base header and transactions.
/// Throws on parse failure.
inline ltc::coin::BlockType parse_doge_block(const uint8_t* data, size_t len)
{
    using ltc::coin::BlockType;

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(data), len));

    CAuxPow<> aux;
    bool has_aux = false;
    BlockHeaderType hdr = parse_aux_header(ps, aux, has_aux);

    BlockType block;
    static_cast<BlockHeaderType&>(block) = hdr;
    ::Unserialize(ps, TX_WITH_WITNESS(block.m_txs));
    return block;
}

} // namespace coin
} // namespace doge
