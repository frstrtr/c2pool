// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #946 found-block explorer: the two body facts a /recent_blocks row carries
// that the 80-byte header cannot give -- the coinbase txid and the block's
// transaction count. Read straight from the serialized block the node just
// submitted, so the own-find writer needs no per-coin template plumbing.
//
// Coin-agnostic over the bitcoin-family wire format: header(80) |
// compactsize tx_count | coinbase tx | ... Only the coinbase is walked. The
// txid is double-SHA256 of the NON-witness serialization, so a segwit coinbase
// (marker 0x00, flag 0x01) has its marker, flag and witness stacks stripped
// before hashing. Any other flag value (e.g. an LTC MWEB 0x08 tx, which a
// coinbase never is) is refused rather than guessed: the row keeps a JSON-null
// coinbase_txid, never a wrong one. Truncated or malformed input -> nullopt.

#pragma once

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace core {

struct BlockBodySummary {
    std::string coinbase_txid;  // display-order hex (same as GetHex / explorers)
    uint32_t    tx_count = 0;   // coinbase included
};

namespace detail {

// Bounds-checked cursor over the raw block bytes.
struct BlockCursor {
    const std::vector<unsigned char>& b;
    size_t pos = 0;

    bool skip(uint64_t n)
    {
        if (n > b.size() - pos) return false;
        pos += static_cast<size_t>(n);
        return true;
    }

    bool compact_size(uint64_t& out)
    {
        if (pos >= b.size()) return false;
        const unsigned char lead = b[pos++];
        int width = 0;
        if (lead < 0xfd) { out = lead; return true; }
        if (lead == 0xfd) width = 2;
        else if (lead == 0xfe) width = 4;
        else width = 8;
        if (static_cast<size_t>(width) > b.size() - pos) return false;
        out = 0;
        for (int i = 0; i < width; ++i)
            out |= static_cast<uint64_t>(b[pos + i]) << (8 * i);
        pos += width;
        return true;
    }

    // compactsize length prefix followed by that many bytes
    bool skip_var_bytes()
    {
        uint64_t n = 0;
        return compact_size(n) && skip(n);
    }
};

} // namespace detail

inline std::optional<BlockBodySummary>
summarize_block_body(const std::vector<unsigned char>& block)
{
    constexpr size_t kHeaderSize = 80;
    if (block.size() <= kHeaderSize) return std::nullopt;

    detail::BlockCursor c{block, kHeaderSize};
    uint64_t n_tx = 0;
    if (!c.compact_size(n_tx) || n_tx == 0 || n_tx > UINT32_MAX)
        return std::nullopt;

    // Coinbase: version | [marker flag] | vin | vout | [witness] | locktime
    const size_t tx_start = c.pos;
    if (!c.skip(4)) return std::nullopt;
    const size_t version_end = c.pos;

    bool segwit = false;
    if (c.pos + 1 < block.size() && block[c.pos] == 0x00) {
        if (block[c.pos + 1] != 0x01) return std::nullopt;  // unknown flag
        segwit = true;
        c.pos += 2;
    }
    const size_t io_start = c.pos;

    uint64_t n_in = 0;
    if (!c.compact_size(n_in) || n_in == 0) return std::nullopt;
    for (uint64_t i = 0; i < n_in; ++i) {
        if (!c.skip(36) || !c.skip_var_bytes() || !c.skip(4))
            return std::nullopt;
    }
    uint64_t n_out = 0;
    if (!c.compact_size(n_out)) return std::nullopt;
    for (uint64_t i = 0; i < n_out; ++i) {
        if (!c.skip(8) || !c.skip_var_bytes()) return std::nullopt;
    }
    const size_t io_end = c.pos;

    if (segwit) {
        for (uint64_t i = 0; i < n_in; ++i) {
            uint64_t n_items = 0;
            if (!c.compact_size(n_items)) return std::nullopt;
            for (uint64_t k = 0; k < n_items; ++k)
                if (!c.skip_var_bytes()) return std::nullopt;
        }
    }
    const size_t locktime_start = c.pos;
    if (!c.skip(4)) return std::nullopt;

    std::vector<unsigned char> stripped;
    stripped.reserve((version_end - tx_start) + (io_end - io_start) + 4);
    stripped.insert(stripped.end(), block.begin() + tx_start, block.begin() + version_end);
    stripped.insert(stripped.end(), block.begin() + io_start, block.begin() + io_end);
    stripped.insert(stripped.end(), block.begin() + locktime_start,
                    block.begin() + locktime_start + 4);

    BlockBodySummary out;
    out.coinbase_txid = Hash(stripped).GetHex();
    out.tx_count = static_cast<uint32_t>(n_tx);
    return out;
}

} // namespace core
