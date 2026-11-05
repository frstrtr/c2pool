// SPDX-License-Identifier: AGPL-3.0-or-later
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
///   - parse_doge_headers         — a 'headers' batch (CompactSize count + N),
///                                  with where it stopped if it did not finish
///   - parse_doge_headers_message — the same, the headers only (the raw
///                                  headers parser seam)
///   - parse_doge_block           — a full block (header + AuxPoW + tx list)

#include <impl/doge/coin/auxpow.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
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

/// A parsed 'headers' message: the entries that parsed and link, and where
/// parsing stopped when it did not reach the message's count.
struct DogeHeadersParse
{
    std::vector<BlockHeaderType> headers;  // the clean prefix, in message order
    uint64_t                     count{0}; // entries the message declares
    /// Set when fewer than `count` headers are returned: entries
    /// [truncated_at, count) are not. An entry failed to parse (error,
    /// failed_index and failed_offset say which, where and why), the
    /// payload ended before the count, or the count itself did not parse
    /// (0, with error). nullopt: the whole message parsed.
    std::optional<size_t>        truncated_at;
    size_t                       failed_index{0};
    size_t                       failed_offset{0};
    std::string                  error;
};

/// Parse a batch of DOGE headers from a P2P 'headers' message payload
/// (AuxPoW proofs are parsed then dropped; HeaderChain validates against the
/// 80-byte base header).
///
/// An entry that does not parse ends the batch. The cursor is then wherever
/// that entry left it, and an earlier entry may have gone wrong without
/// throwing (a mis-read field puts the next "entry" inside its bytes), so
/// what parsed before the failure is cut back to the prefix whose headers
/// link, each to the one before it: a 'headers' message is a chain (Core
/// refuses one that is not), and garbage read as a header does not link.
/// The caller gets that clean prefix and truncated_at: a parse failure,
/// never a batch that reads like another chain.
inline DogeHeadersParse parse_doge_headers(const uint8_t* data, size_t len)
{
    DogeHeadersParse r;
    if (data == nullptr || len == 0)
        return r;

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(data), len));

    try {
        r.count = ReadCompactSize(ps);
    } catch (const std::exception& e) {
        r.truncated_at = 0;
        r.error = e.what();
        LOG_WARNING << "DOGE headers: the count of a " << len << "-byte message does not parse ("
                    << e.what() << ")";
        return r;
    }

    // A 'headers' message carries at most 2000; cap the speculative reserve.
    r.headers.reserve(static_cast<size_t>(std::min<uint64_t>(r.count, 4096)));

    CAuxPow<> aux;
    bool has_aux = false;
    bool failed = false;
    for (uint64_t i = 0; i < r.count && ps.cursor_size() > 0; ++i) {
        const size_t at = len - ps.cursor_size();
        try {
            BlockHeaderType hdr = parse_aux_header(ps, aux, has_aux);
            // tx_count (CompactSize) — always 0 in a 'headers' message.
            if (ps.cursor_size() > 0)
                (void)ReadCompactSize(ps);
            r.headers.push_back(hdr);
        } catch (const std::exception& e) {
            failed = true;
            r.failed_index = static_cast<size_t>(i);
            r.failed_offset = at;
            r.error = e.what();
            break;
        }
    }
    if (r.headers.size() >= r.count)
        return r;

    const size_t parsed = r.headers.size();
    size_t keep = parsed;
    for (size_t k = 1; k < parsed; ++k) {
        if (r.headers[k].m_previous_block != Hash(pack(r.headers[k - 1]).get_span())) {
            keep = k;
            break;
        }
    }
    r.headers.resize(keep);
    r.truncated_at = keep;
    if (failed) {
        LOG_WARNING << "DOGE headers: entry " << r.failed_index << " of " << r.count << " at offset "
                    << r.failed_offset << " of " << len << " bytes does not parse (" << r.error
                    << "); returning the " << keep << " headers before it that link"
                    << (keep < parsed ? " (" + std::to_string(parsed - keep) + " more did not link)" : "");
    } else {
        LOG_WARNING << "DOGE headers: the message ends after " << parsed << " of " << r.count
                    << " entries (" << len << " bytes); returning the " << keep << " that link";
    }
    return r;
}

/// The headers of parse_doge_headers: the clean prefix (the raw headers
/// parser seam of CoinBroadcaster / NodeP2P).
inline std::vector<BlockHeaderType> parse_doge_headers_message(
    const uint8_t* data, size_t len)
{
    return parse_doge_headers(data, len).headers;
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
    ::Unserialize(ps, ltc::coin::TX_WITH_WITNESS(block.m_txs));
    return block;
}

} // namespace coin
} // namespace doge