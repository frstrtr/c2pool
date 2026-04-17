#pragma once

// Stratum submit validator for Dash.
//
// Given a SubmittedShare + the frozen JobContext that was issued to the
// miner, reconstructs the full 80-byte block header and computes its X11
// hash. Compares against the share target and the block target to decide:
//
//   - is_block     → hash <= block_target         (full block — submit via RPC!)
//   - valid_share  → hash <= share_target         (count for PPLNS / accept)
//   - otherwise    → rejected as below-difficulty
//
// On a block hit, also assembles the full block hex ready for submitblock.
//
// Scope boundary:
//   * We do NOT touch the sharechain / PPLNS here. Callers get a bool and a
//     uint256 hash; deeper integration belongs in a higher layer.
//   * We assume extranonce1 is empty (matches our subscribe response).

#include "stratum.hpp"                              // JobContext
#include "coinbase_builder.hpp"                     // EXTRANONCE2_SIZE
#include "crypto/hash_x11.hpp"

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

namespace dash {
namespace submit {

struct ValidationResult {
    bool     valid_share{false};        // hash <= share target
    bool     is_block{false};           // hash <= block target
    uint256  x11_hash;                  // the 80-byte X11 result
    uint256  merkle_root;               // computed root — for logging only
    std::string block_hex;              // populated iff is_block
    std::string reject_reason;
};

// Compute share target from bdiff-style difficulty:
//   target = 0xffff_0000 * 2^192 / difficulty
// For diff=1 this produces the canonical bdiff1 target (compact 0x1d00ffff).
// Very small diffs (< ~1.5e-5) would overflow the uint64 top word; we clamp
// the target to all-ones (equivalent to "accept every hash").
inline uint256 target_from_difficulty(double diff)
{
    constexpr double C = 65535.0 * 4294967296.0;         // 0xffff * 2^32
    constexpr double U64_MAX_D = 1.8446744073709551e19;  // ~2^64
    uint256 t;

    if (diff <= 0.0) {
        // treat as "accept anything"
        for (int i = 0; i < 32; ++i) t.data()[i] = 0xff;
        return t;
    }
    double v = C / diff;
    if (v >= U64_MAX_D) {
        // Target overflows the uint256 encoding we use (top64 << 192);
        // cap at all-ones (near-max uint256) — effectively permissive.
        for (int i = 0; i < 32; ++i) t.data()[i] = 0xff;
        return t;
    }
    uint64_t top64 = static_cast<uint64_t>(v);
    if (top64 == 0) top64 = 1;
    t = uint256(top64);
    t <<= 192;
    return t;
}

// Parse a BE-hex encoded uint32 (miner submits ntime/nonce in BE hex).
inline bool parse_be_u32_hex(const std::string& hex, uint32_t& out)
{
    if (hex.size() != 8) return false;
    try {
        out = static_cast<uint32_t>(std::stoul(hex, nullptr, 16));
        return true;
    } catch (...) { return false; }
}

// Serialize a compact-size VarInt for the block tx-count field.
inline void write_varint(std::vector<unsigned char>& out, uint64_t n)
{
    if (n < 253) {
        out.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0xfd);
        out.push_back(static_cast<unsigned char>(n & 0xff));
        out.push_back(static_cast<unsigned char>((n >> 8) & 0xff));
    } else if (n <= 0xFFFFFFFFu) {
        out.push_back(0xfe);
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<unsigned char>((n >> (8 * i)) & 0xff));
    } else {
        out.push_back(0xff);
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<unsigned char>((n >> (8 * i)) & 0xff));
    }
}

inline ValidationResult validate(const stratum::SubmittedShare& s,
                                 const stratum::JobContext& ctx)
{
    ValidationResult r;

    // 1. Parse miner inputs.
    auto en2 = ParseHex(s.extranonce2_hex);
    if (en2.size() != dash::coinbase::EXTRANONCE2_SIZE) {
        r.reject_reason = "extranonce2 bad length";
        return r;
    }
    uint32_t miner_ntime = 0, miner_nonce = 0;
    if (!parse_be_u32_hex(s.ntime_hex, miner_ntime)) {
        r.reject_reason = "ntime hex malformed";
        return r;
    }
    if (!parse_be_u32_hex(s.nonce_hex, miner_nonce)) {
        r.reject_reason = "nonce hex malformed";
        return r;
    }

    // 2. Reconstruct coinbase: coinb1 + extranonce2 + coinb2. (extranonce1
    //    is empty per our subscribe response.)
    std::vector<unsigned char> coinbase;
    coinbase.reserve(ctx.coinb1_bytes.size() + en2.size() + ctx.coinb2_bytes.size());
    coinbase.insert(coinbase.end(), ctx.coinb1_bytes.begin(), ctx.coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en2.begin(), en2.end());
    coinbase.insert(coinbase.end(), ctx.coinb2_bytes.begin(), ctx.coinb2_bytes.end());

    uint256 coinbase_txid = Hash(coinbase);

    // 3. Walk merkle branches starting from coinbase_txid.
    uint256 root = coinbase_txid;
    for (const auto& branch : ctx.merkle_branches_le) {
        if (branch.size() != 32) {
            r.reject_reason = "bad merkle branch length";
            return r;
        }
        std::vector<unsigned char> buf(64);
        std::memcpy(buf.data(),      root.data(),    32);
        std::memcpy(buf.data() + 32, branch.data(),  32);
        root = Hash(buf);
    }
    r.merkle_root = root;

    // 4. Build 80-byte block header.
    std::vector<unsigned char> hdr(80);
    auto write_u32_le = [&](size_t off, uint32_t v) {
        hdr[off + 0] = static_cast<unsigned char>(v      & 0xff);
        hdr[off + 1] = static_cast<unsigned char>((v>> 8)& 0xff);
        hdr[off + 2] = static_cast<unsigned char>((v>>16)& 0xff);
        hdr[off + 3] = static_cast<unsigned char>((v>>24)& 0xff);
    };
    write_u32_le(0, static_cast<uint32_t>(ctx.version));
    if (ctx.prev_hash_le.size() != 32) {
        r.reject_reason = "bad prev_hash size";
        return r;
    }
    std::memcpy(&hdr[4],  ctx.prev_hash_le.data(), 32);
    std::memcpy(&hdr[36], root.data(),             32);
    write_u32_le(68, miner_ntime);
    write_u32_le(72, ctx.nbits);
    write_u32_le(76, miner_nonce);

    // 5. X11 PoW hash.
    r.x11_hash = dash::crypto::hash_x11(hdr.data(), 80);

    // 6. Compare to share and block targets.
    uint256 block_target;
    block_target.SetCompact(ctx.nbits);
    uint256 share_target = target_from_difficulty(ctx.share_difficulty);

    r.is_block    = (r.x11_hash <= block_target);
    r.valid_share = r.is_block || (r.x11_hash <= share_target);
    if (!r.valid_share) {
        r.reject_reason = "low difficulty share (hash > target)";
        return r;
    }

    // 7. If block, assemble full block hex.
    if (r.is_block) {
        std::vector<unsigned char> block;
        block.reserve(80 + 5 + coinbase.size() + ctx.tx_data_hex.size() * 200);
        block.insert(block.end(), hdr.begin(), hdr.end());
        write_varint(block, ctx.tx_data_hex.size() + 1);            // +1 for coinbase
        block.insert(block.end(), coinbase.begin(), coinbase.end());
        r.block_hex = HexStr(block);
        // Append the (already hex-encoded) non-coinbase transactions verbatim.
        for (const auto& hx : ctx.tx_data_hex) r.block_hex += hx;
    }
    return r;
}

} // namespace submit
} // namespace dash
