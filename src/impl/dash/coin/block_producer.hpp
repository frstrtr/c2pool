#pragma once

// ---------------------------------------------------------------------------
// dash::coin block PRODUCER (launcher slice 5).
//
// The "c2pool-dash builds and wins the block itself" lever. Slice 3/4 only
// re-SUBMITTED a pre-built block hex via NodeRPC::submit_block_hex. This header
// closes the producer gap: given a DashWorkData (from dashd getblocktemplate via
// NodeRPC::getwork(), or the embedded build_embedded_workdata path) plus an
// already-assembled coinbase tx (dash::coinbase::build -> CoinbaseLayout.bytes),
// it:
//   - folds the block merkle root over [coinbase_txid] + work.m_tx_hashes,
//   - serializes the 80-byte X11 header,
//   - X11-mines the nonce until hash_x11(header) meets the compact-bits target,
//   - serializes the FULL block (header || CompactSize(ntx) || coinbase || txs),
//   - and hands the hex to the EXISTING submit arm.
//
// PER-COIN ISOLATION: header-only, src/impl/dash only. Reuses the dash merkle
// fold idiom (sha256d, duplicate-last on odd), the dash X11 PoW entry, and the
// DASH tx-data hex already parsed by NodeRPC::getwork(). No src/core edit, no
// other coin touched, dashd-RPC fallback untouched.
//
// Byte order: all header/CompactSize fields are little-endian on the wire; the
// x86_64 CI target is LE so memcpy of host integers is the wire form (this
// mirrors main_dash.cpp::serialize_header). uint256::data() is the internal LE
// byte order, which is the on-wire order for prev_block / merkle_root (the same
// order hash_x11 already consumes in the X11 KATs).
// ---------------------------------------------------------------------------

#include "rpc_data.hpp"                       // dash::coin::DashWorkData
#include <impl/dash/crypto/hash_x11.hpp>      // dash::crypto::hash_x11
#include <impl/dash/coinbase_builder.hpp>     // dash::coinbase::sha256d (Hash sha256d)

#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>        // HexStr, ParseHex

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

// sha256d over a byte span (reuse the coinbase_builder helper, which is just
// core::Hash). Kept local so callers of block_producer don't need to reach
// into the coinbase namespace.
inline uint256 bp_sha256d(std::span<const unsigned char> a)
{
    return dash::coinbase::sha256d(a);
}

// Standard Bitcoin/Dash merkle root fold. txids[0] is the coinbase txid.
// Duplicate the last element on odd-sized layers. Empty -> ZERO; single ->
// that element. Hashes are in internal (LE) byte order throughout; the result
// is the merkle_root in the same order the 80-byte header carries.
inline uint256 compute_merkle_root(const std::vector<uint256>& txids)
{
    if (txids.empty()) return uint256::ZERO;
    std::vector<uint256> layer = txids;
    while (layer.size() > 1) {
        if (layer.size() % 2 == 1)
            layer.push_back(layer.back());          // duplicate last on odd
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            unsigned char buf[64];
            std::memcpy(buf,      layer[i].data(),     32);
            std::memcpy(buf + 32, layer[i + 1].data(), 32);
            next.push_back(bp_sha256d(std::span<const unsigned char>(buf, 64)));
        }
        layer.swap(next);
    }
    return layer[0];
}

// Compact nBits -> 256-bit target (Bitcoin/Dash compact form). uint256 carries
// SetCompact directly.
inline uint256 target_from_nbits(uint32_t nbits)
{
    uint256 target;
    target.SetCompact(nbits);
    return target;
}

// A PoW hash (internal LE order, as returned by hash_x11) meets the target iff
// powhash <= target_from_nbits(nbits). uint256 comparison is value comparison.
inline bool meets_target(const uint256& powhash, uint32_t nbits)
{
    return powhash <= target_from_nbits(nbits);
}

// Serialize the 80-byte DASH block header into out[80] (LE host == wire on the
// x86_64 target). merkle_root and prev_block are passed in internal LE order.
inline void serialize_header80(unsigned char out[80],
                               int32_t version,
                               const uint256& prev_block,
                               const uint256& merkle_root,
                               uint32_t time,
                               uint32_t bits,
                               uint32_t nonce)
{
    size_t off = 0;
    std::memcpy(out + off, &version, 4);             off += 4;
    std::memcpy(out + off, prev_block.data(), 32);   off += 32;
    std::memcpy(out + off, merkle_root.data(), 32);  off += 32;
    std::memcpy(out + off, &time, 4);                off += 4;
    std::memcpy(out + off, &bits, 4);                off += 4;
    std::memcpy(out + off, &nonce, 4);               off += 4;
}

// CompactSize (Bitcoin "varint") encoder.
inline void append_compact_size(std::vector<unsigned char>& out, uint64_t n)
{
    if (n < 0xfd) {
        out.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xffff) {
        out.push_back(0xfd);
        out.push_back(static_cast<unsigned char>(n & 0xff));
        out.push_back(static_cast<unsigned char>((n >> 8) & 0xff));
    } else if (n <= 0xffffffffULL) {
        out.push_back(0xfe);
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<unsigned char>((n >> (8 * i)) & 0xff));
    } else {
        out.push_back(0xff);
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<unsigned char>((n >> (8 * i)) & 0xff));
    }
}

// Coinbase txid: sha256d of the raw coinbase bytes (DASH non-witness canonical
// serialization == the txid preimage; matches NodeRPC::getwork()'s recompute).
inline uint256 coinbase_txid(const std::vector<unsigned char>& coinbase_bytes)
{
    return bp_sha256d(std::span<const unsigned char>(
        coinbase_bytes.data(), coinbase_bytes.size()));
}

// Assemble the FULL block as raw bytes:
//   80-byte header
//   CompactSize(1 + work.m_txs.size())
//   coinbase_bytes
//   each tx (decoded from work.m_tx_data_hex)
// The merkle root is folded over [coinbase_txid] + work.m_tx_hashes.
inline std::vector<unsigned char> serialize_full_block(
    const DashWorkData& work,
    const std::vector<unsigned char>& coinbase_bytes,
    uint32_t nonce,
    uint32_t time)
{
    std::vector<uint256> txids;
    txids.reserve(1 + work.m_tx_hashes.size());
    txids.push_back(coinbase_txid(coinbase_bytes));
    for (const auto& h : work.m_tx_hashes) txids.push_back(h);
    const uint256 merkle_root = compute_merkle_root(txids);

    std::vector<unsigned char> block;
    block.reserve(80 + 9 + coinbase_bytes.size() + work.m_tx_data_hex.size() * 256);

    unsigned char hdr[80];
    serialize_header80(hdr, work.m_version, work.m_previous_block, merkle_root,
                       time, work.m_bits, nonce);
    block.insert(block.end(), hdr, hdr + 80);

    // tx count = coinbase + GBT txs. Use m_tx_data_hex as the canonical tx
    // count/source (the raw hex we will emit verbatim).
    const uint64_t ntx = 1 + work.m_tx_data_hex.size();
    append_compact_size(block, ntx);

    block.insert(block.end(), coinbase_bytes.begin(), coinbase_bytes.end());
    for (const auto& tx_hex : work.m_tx_data_hex) {
        auto raw = ParseHex(tx_hex);
        block.insert(block.end(), raw.begin(), raw.end());
    }
    return block;
}

// Hex-encode the full serialized block (the form NodeRPC::submit_block_hex eats).
inline std::string serialize_full_block_hex(
    const DashWorkData& work,
    const std::vector<unsigned char>& coinbase_bytes,
    uint32_t nonce,
    uint32_t time)
{
    auto block = serialize_full_block(work, coinbase_bytes, nonce, time);
    return HexStr(std::span<const unsigned char>(block.data(), block.size()));
}

struct MineResult {
    bool        found{false};
    uint32_t    nonce{0};
    uint32_t    time{0};
    std::string block_hex;
    uint256     block_hash;     // X11 PoW hash (internal LE order) of the winning header
};

// X11-mine the header over the nonce range [0, max_nonce] until the PoW hash
// meets the compact-bits target. Returns the first winning nonce. On regtest
// bits (e.g. 0x207fffff) the target is trivial -> found almost immediately.
//
// The time used is work.m_curtime (the GBT curtime). The merkle root is folded
// once (it does not depend on the nonce) and the header's nonce field is the
// only mutated word across the loop.
inline MineResult mine_block(const DashWorkData& work,
                             const std::vector<unsigned char>& coinbase_bytes,
                             uint64_t max_nonce)
{
    MineResult r;
    r.time = work.m_curtime;

    std::vector<uint256> txids;
    txids.reserve(1 + work.m_tx_hashes.size());
    txids.push_back(coinbase_txid(coinbase_bytes));
    for (const auto& h : work.m_tx_hashes) txids.push_back(h);
    const uint256 merkle_root = compute_merkle_root(txids);

    unsigned char hdr[80];
    serialize_header80(hdr, work.m_version, work.m_previous_block, merkle_root,
                       work.m_curtime, work.m_bits, 0);

    for (uint64_t n = 0; n <= max_nonce; ++n) {
        const uint32_t nonce = static_cast<uint32_t>(n);
        std::memcpy(hdr + 76, &nonce, 4);            // overwrite nonce word only
        const uint256 pow = dash::crypto::hash_x11(hdr, 80);
        if (meets_target(pow, work.m_bits)) {
            r.found      = true;
            r.nonce      = nonce;
            r.block_hash = pow;
            r.block_hex  = serialize_full_block_hex(work, coinbase_bytes,
                                                    nonce, work.m_curtime);
            return r;
        }
        if (nonce == 0xffffffffu) break;             // guard against u32 wrap
    }
    return r;
}

} // namespace coin
} // namespace dash
