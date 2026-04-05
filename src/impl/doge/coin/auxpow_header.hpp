#pragma once

/// DOGE AuxPoW Header Parser — Phase 5.8
///
/// Dogecoin blocks after AuxPoW activation (height 371,337 mainnet, 0 testnet4alpha)
/// have EXTENDED headers in P2P messages:
///
///   CPureBlockHeader (80 bytes)   — standard Bitcoin header
///   + CAuxPow (variable)          — merge-mining proof (if IsAuxpow())
///   + tx_count (varint)           — always 0 in 'headers' message
///
/// CAuxPow = CMerkleTx + vChainMerkleBranch + nChainIndex + parentBlock(80B)
/// CMerkleTx = CTransaction(variable) + hashBlock(32B) + vMerkleBranch + nIndex(4B)
///
/// We only need the 80-byte base header for HeaderChain validation.
/// This parser reads and SKIPS the AuxPoW data to advance the stream.

#include <impl/ltc/coin/block.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <vector>
#include <span>

namespace doge {
namespace coin {

using ltc::coin::BlockHeaderType;

/// Check if a block version indicates AuxPoW (version bit 0x100 set).
/// Matches dogecoin/src/primitives/pureheader.h CPureBlockHeader::IsAuxpow()
inline bool is_auxpow_version(int32_t version) {
    return (version & 0x100) != 0;
}

/// Parse a DOGE extended header from a byte stream.
/// Extracts the 80-byte base header and skips AuxPoW data if present.
///
/// Returns the base header, or throws on parse failure.
/// The stream position advances past the full extended header.
///
/// Wire format:
///   [base_header: 80B]
///   [if IsAuxpow(version):]
///     [coinbase_tx: CTransaction — variable]
///     [hashBlock: 32B]
///     [vMerkleBranch: varint_count + N*32B]
///     [nIndex: 4B]
///     [vChainMerkleBranch: varint_count + N*32B]
///     [nChainIndex: 4B]
///     [parentBlock: 80B — CPureBlockHeader]
///   [tx_count: varint — always 0 in headers message]
inline BlockHeaderType parse_doge_header(const uint8_t*& pos, const uint8_t* end)
{
    // Need at least 80 bytes for base header
    if (end - pos < 80)
        throw std::runtime_error("DOGE header: not enough data for base header");

    // Parse 80-byte base header
    BlockHeaderType hdr;
    {
        PackStream ps(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(pos), 80));
        ps >> hdr;
    }
    pos += 80;

    // If AuxPoW version, skip the AuxPoW proof data
    if (is_auxpow_version(hdr.m_version)) {
        // Skip CMerkleTx: CTransaction + hashBlock + vMerkleBranch + nIndex

        // 1. Skip CTransaction (variable length)
        //    Format: version(4) + [marker(1) + flag(1) if segwit] +
        //            vin_count(varint) + vins + vout_count(varint) + vouts +
        //            [witness data if segwit] + locktime(4)
        {
            if (end - pos < 4) throw std::runtime_error("DOGE auxpow: truncated tx version");
            // TX version
            pos += 4;
            // Check for segwit marker (0x00 0x01)
            bool is_segwit = false;
            if (end - pos >= 2 && pos[0] == 0x00 && pos[1] != 0x00) {
                is_segwit = true;
                pos += 2; // skip marker + flag
            }
            // Read vin_count
            auto read_varint = [&]() -> uint64_t {
                if (pos >= end) throw std::runtime_error("DOGE auxpow: truncated varint");
                uint8_t first = *pos++;
                if (first < 0xfd) return first;
                if (first == 0xfd) {
                    if (end - pos < 2) throw std::runtime_error("truncated varint16");
                    uint16_t v = pos[0] | (pos[1] << 8); pos += 2; return v;
                }
                if (first == 0xfe) {
                    if (end - pos < 4) throw std::runtime_error("truncated varint32");
                    uint32_t v = pos[0] | (pos[1]<<8) | (pos[2]<<16) | (pos[3]<<24);
                    pos += 4; return v;
                }
                // 0xff
                if (end - pos < 8) throw std::runtime_error("truncated varint64");
                uint64_t v = 0;
                for (int i = 0; i < 8; i++) v |= (uint64_t(pos[i]) << (i*8));
                pos += 8; return v;
            };

            // Skip vins
            uint64_t vin_count = read_varint();
            for (uint64_t i = 0; i < vin_count; i++) {
                if (end - pos < 36) throw std::runtime_error("truncated vin");
                pos += 32; // prev_hash
                pos += 4;  // prev_index
                uint64_t script_len = read_varint();
                if (end - pos < static_cast<ptrdiff_t>(script_len)) throw std::runtime_error("truncated vin script");
                pos += script_len;
                if (end - pos < 4) throw std::runtime_error("truncated vin sequence");
                pos += 4; // sequence
            }
            // Skip vouts
            uint64_t vout_count = read_varint();
            for (uint64_t i = 0; i < vout_count; i++) {
                if (end - pos < 8) throw std::runtime_error("truncated vout value");
                pos += 8; // value
                uint64_t script_len = read_varint();
                if (end - pos < static_cast<ptrdiff_t>(script_len)) throw std::runtime_error("truncated vout script");
                pos += script_len;
            }
            // Skip witness data if segwit
            if (is_segwit) {
                for (uint64_t i = 0; i < vin_count; i++) {
                    uint64_t stack_items = read_varint();
                    for (uint64_t j = 0; j < stack_items; j++) {
                        uint64_t item_len = read_varint();
                        if (end - pos < static_cast<ptrdiff_t>(item_len)) throw std::runtime_error("truncated witness");
                        pos += item_len;
                    }
                }
            }
            // Skip locktime
            if (end - pos < 4) throw std::runtime_error("truncated locktime");
            pos += 4;
        }

        // 2. Skip hashBlock (32 bytes)
        if (end - pos < 32) throw std::runtime_error("truncated hashBlock");
        pos += 32;

        // 3. Skip vMerkleBranch (varint count + N*32 bytes)
        {
            auto read_varint = [&]() -> uint64_t {
                if (pos >= end) throw std::runtime_error("truncated varint");
                uint8_t first = *pos++;
                if (first < 0xfd) return first;
                if (first == 0xfd) { uint16_t v = pos[0]|(pos[1]<<8); pos+=2; return v; }
                if (first == 0xfe) { uint32_t v = pos[0]|(pos[1]<<8)|(pos[2]<<16)|(pos[3]<<24); pos+=4; return v; }
                uint64_t v = 0; for(int i=0;i<8;i++) v|=(uint64_t(pos[i])<<(i*8)); pos+=8; return v;
            };
            uint64_t count = read_varint();
            if (end - pos < static_cast<ptrdiff_t>(count * 32)) throw std::runtime_error("truncated merkle branch");
            pos += count * 32;
        }

        // 4. Skip nIndex (4 bytes)
        if (end - pos < 4) throw std::runtime_error("truncated nIndex");
        pos += 4;

        // 5. Skip vChainMerkleBranch (varint count + N*32 bytes)
        {
            auto read_varint = [&]() -> uint64_t {
                if (pos >= end) throw std::runtime_error("truncated varint");
                uint8_t first = *pos++;
                if (first < 0xfd) return first;
                if (first == 0xfd) { uint16_t v = pos[0]|(pos[1]<<8); pos+=2; return v; }
                if (first == 0xfe) { uint32_t v = pos[0]|(pos[1]<<8)|(pos[2]<<16)|(pos[3]<<24); pos+=4; return v; }
                uint64_t v = 0; for(int i=0;i<8;i++) v|=(uint64_t(pos[i])<<(i*8)); pos+=8; return v;
            };
            uint64_t count = read_varint();
            if (end - pos < static_cast<ptrdiff_t>(count * 32)) throw std::runtime_error("truncated chain merkle branch");
            pos += count * 32;
        }

        // 6. Skip nChainIndex (4 bytes)
        if (end - pos < 4) throw std::runtime_error("truncated nChainIndex");
        pos += 4;

        // 7. Skip parentBlock (80-byte CPureBlockHeader)
        if (end - pos < 80) throw std::runtime_error("truncated parentBlock");
        pos += 80;
    }

    // Skip tx_count varint (always 0 in headers message)
    if (pos < end) {
        uint8_t tx_count = *pos++;
        (void)tx_count; // should be 0
    }

    return hdr;
}

/// Parse a batch of DOGE headers from a P2P 'headers' message payload.
/// Returns vector of base BlockHeaderType (80-byte headers only, AuxPoW skipped).
inline std::vector<BlockHeaderType> parse_doge_headers_message(
    const uint8_t* data, size_t len)
{
    std::vector<BlockHeaderType> result;
    const uint8_t* pos = data;
    const uint8_t* end = data + len;

    // First: read the header count varint
    if (pos >= end) return result;
    uint64_t count = 0;
    {
        uint8_t first = *pos++;
        if (first < 0xfd) count = first;
        else if (first == 0xfd && end - pos >= 2) { count = pos[0]|(pos[1]<<8); pos+=2; }
        else if (first == 0xfe && end - pos >= 4) { count = pos[0]|(pos[1]<<8)|(pos[2]<<16)|(pos[3]<<24); pos+=4; }
        else return result;
    }

    result.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count && pos < end; i++) {
        try {
            result.push_back(parse_doge_header(pos, end));
        } catch (const std::exception& e) {
            // Truncated header — return what we have
            break;
        }
    }
    return result;
}

/// Parse a DOGE full block from raw P2P bytes.
/// Handles AuxPoW: reads 80-byte header, skips AuxPoW proof if present,
/// then reads the standard transaction list.
///
/// Returns a BlockType with the correct header and transactions.
/// Throws on parse failure.
inline ltc::coin::BlockType parse_doge_block(const uint8_t* data, size_t len)
{
    using ltc::coin::BlockType;
    using ltc::coin::BlockHeaderType;

    const uint8_t* pos = data;
    const uint8_t* end = data + len;

    // Step 1: Parse 80-byte base header
    if (end - pos < 80)
        throw std::runtime_error("DOGE block: not enough data for header");

    BlockHeaderType hdr;
    {
        PackStream ps(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(pos), 80));
        ps >> hdr;
    }
    pos += 80;

    // Step 2: Skip AuxPoW if present
    if (is_auxpow_version(hdr.m_version)) {
        // Reuse the same AuxPoW skip logic from parse_doge_header.
        // We need to skip: CTransaction + hashBlock(32) + vMerkleBranch + nIndex(4)
        //                 + vChainMerkleBranch + nChainIndex(4) + parentBlock(80)
        auto read_varint = [&]() -> uint64_t {
            if (pos >= end) throw std::runtime_error("DOGE block auxpow: truncated varint");
            uint8_t first = *pos++;
            if (first < 0xfd) return first;
            if (first == 0xfd) {
                if (end - pos < 2) throw std::runtime_error("truncated varint16");
                uint16_t v = pos[0] | (pos[1] << 8); pos += 2; return v;
            }
            if (first == 0xfe) {
                if (end - pos < 4) throw std::runtime_error("truncated varint32");
                uint32_t v = pos[0] | (pos[1]<<8) | (pos[2]<<16) | (pos[3]<<24);
                pos += 4; return v;
            }
            if (end - pos < 8) throw std::runtime_error("truncated varint64");
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= (uint64_t(pos[i]) << (i*8));
            pos += 8; return v;
        };

        // 1. Skip CTransaction (coinbase of parent block)
        {
            if (end - pos < 4) throw std::runtime_error("DOGE block auxpow: truncated tx version");
            pos += 4; // tx version
            bool is_segwit = false;
            if (end - pos >= 2 && pos[0] == 0x00 && pos[1] != 0x00) {
                is_segwit = true;
                pos += 2;
            }
            uint64_t vin_count = read_varint();
            for (uint64_t i = 0; i < vin_count; i++) {
                if (end - pos < 36) throw std::runtime_error("truncated vin");
                pos += 32 + 4; // prev_hash + prev_index
                uint64_t script_len = read_varint();
                if (end - pos < static_cast<ptrdiff_t>(script_len)) throw std::runtime_error("truncated vin script");
                pos += script_len;
                if (end - pos < 4) throw std::runtime_error("truncated vin sequence");
                pos += 4;
            }
            uint64_t vout_count = read_varint();
            for (uint64_t i = 0; i < vout_count; i++) {
                if (end - pos < 8) throw std::runtime_error("truncated vout value");
                pos += 8;
                uint64_t script_len = read_varint();
                if (end - pos < static_cast<ptrdiff_t>(script_len)) throw std::runtime_error("truncated vout script");
                pos += script_len;
            }
            if (is_segwit) {
                for (uint64_t i = 0; i < vin_count; i++) {
                    uint64_t stack_items = read_varint();
                    for (uint64_t j = 0; j < stack_items; j++) {
                        uint64_t item_len = read_varint();
                        if (end - pos < static_cast<ptrdiff_t>(item_len)) throw std::runtime_error("truncated witness");
                        pos += item_len;
                    }
                }
            }
            if (end - pos < 4) throw std::runtime_error("truncated locktime");
            pos += 4;
        }

        // 2. Skip hashBlock (32 bytes)
        if (end - pos < 32) throw std::runtime_error("truncated hashBlock");
        pos += 32;

        // 3. Skip vMerkleBranch
        {
            uint64_t count = read_varint();
            if (end - pos < static_cast<ptrdiff_t>(count * 32)) throw std::runtime_error("truncated merkle branch");
            pos += count * 32;
        }

        // 4. Skip nIndex (4 bytes)
        if (end - pos < 4) throw std::runtime_error("truncated nIndex");
        pos += 4;

        // 5. Skip vChainMerkleBranch
        {
            uint64_t count = read_varint();
            if (end - pos < static_cast<ptrdiff_t>(count * 32)) throw std::runtime_error("truncated chain merkle branch");
            pos += count * 32;
        }

        // 6. Skip nChainIndex (4 bytes)
        if (end - pos < 4) throw std::runtime_error("truncated nChainIndex");
        pos += 4;

        // 7. Skip parentBlock (80 bytes)
        if (end - pos < 80) throw std::runtime_error("truncated parentBlock");
        pos += 80;
    }

    // Step 3: Parse transaction list from remaining bytes
    BlockType block;
    static_cast<BlockHeaderType&>(block) = hdr;
    {
        size_t remaining = end - pos;
        PackStream ps(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(pos), remaining));
        ::Unserialize(ps, TX_WITH_WITNESS(block.m_txs));
    }

    return block;
}

} // namespace coin
} // namespace doge
