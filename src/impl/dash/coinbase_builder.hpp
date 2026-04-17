#pragma once

// Dash coinbase TX assembly for Stratum mining.
// Produces a serialized coinbase whose scriptSig has an 8-byte extranonce2
// placeholder, plus the coinb1/coinb2 slice indices a Stratum server needs
// to push mining.notify work.
//
// Layout:
//   coinbase_tx serialization =
//     [ver|type : int32 LE]
//     [VarInt 1]                             ← num_inputs = 1
//     [TxIn:
//        [prev_hash 32B = 0]
//        [prev_n   uint32 = 0xFFFFFFFF]
//        [VarStr script_sig:
//           VarInt script_len
//           [push_height_bip34]              ← e.g. 03 XX XX XX for mainnet
//           [pool_tag]                       ← "/c2pool-dash:0.1/"
//           [EXTRANONCE_PLACEHOLDER = 8 B]   ← the 8 bytes miner fills
//        ]
//        [sequence uint32 = 0xFFFFFFFF]
//     ]
//     [VarInt num_outputs]
//       [TxOut miner_payout]
//       [TxOut masternode + superblock + platform payments...]
//     [locktime uint32 = 0]
//     [optional VarStr extra_payload]        ← DIP3/DIP4 CBTX
//
// Coinb1 = bytes from start through (and including) pool_tag.
// Coinb2 = bytes from first byte after the 8-byte placeholder through end.
// Miner fills the 8-byte placeholder with its own extranonce2.
// Assembly: coinb1 + extranonce2(8B) + coinb2  ==  original serialization
//                                                  with zeros replaced.

#include "coin/transaction.hpp"
#include "coin/rpc_data.hpp"
#include "share_check.hpp"                 // decode_payee_script

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/coin_params.hpp>
#include <btclibs/util/strencodings.h>

namespace dash {
namespace coinbase {

static constexpr size_t EXTRANONCE2_SIZE = 8;

// Output of build(): raw coinbase bytes + indices of the 8-byte placeholder.
struct CoinbaseLayout {
    std::vector<unsigned char> bytes;       // full serialized coinbase
    size_t extranonce_offset{0};            // first byte of the 8B placeholder
    // bytes[extranonce_offset .. extranonce_offset + EXTRANONCE2_SIZE) are zeros.
};

// BIP34 minimal push of a positive integer. Writes length byte + height LE.
// Returns the encoded push bytes.
inline std::vector<unsigned char> push_bip34_height(uint32_t height)
{
    std::vector<unsigned char> le;
    le.reserve(4);
    uint32_t h = height;
    while (h) {
        le.push_back(static_cast<unsigned char>(h & 0xff));
        h >>= 8;
    }
    if (le.empty()) le.push_back(0x00);                 // push 0 → [01 00]
    // If top bit set, append 0x00 to avoid sign interpretation.
    if (le.back() & 0x80) le.push_back(0x00);

    std::vector<unsigned char> out;
    out.reserve(1 + le.size());
    out.push_back(static_cast<unsigned char>(le.size()));
    out.insert(out.end(), le.begin(), le.end());
    return out;
}

// Build the coinbase TX. Returns serialized bytes and the offset of the
// 8-byte extranonce placeholder within them.
//
//   work         — parsed GBT (previous_block, coinbase_value, payments, ...)
//   miner_script — scriptPubKey for the miner payout (from address/pubkey)
//   pool_tag     — arbitrary short tag for the coinbase script (e.g. "/c2pool-dash:0.1/")
//   params       — coin params (for address version decoding in packed_payments)
inline CoinbaseLayout build(const dash::coin::DashWorkData& work,
                            const std::vector<unsigned char>& miner_script,
                            const std::string& pool_tag,
                            const core::CoinParams& params)
{
    using namespace dash::coin;

    MutableTransaction tx;

    // ── Input: coinbase ─────────────────────────────────────────────────
    TxIn in;
    in.prevout.hash  = uint256::ZERO;
    in.prevout.index = 0xFFFFFFFFu;
    in.sequence      = 0xFFFFFFFFu;

    // scriptSig = [BIP34 height push] [pool_tag raw bytes] [8-byte extranonce placeholder]
    std::vector<unsigned char> script;
    auto h_push = push_bip34_height(work.m_height);
    script.insert(script.end(), h_push.begin(), h_push.end());
    script.insert(script.end(), pool_tag.begin(), pool_tag.end());
    // Record position where the 8-byte placeholder begins *within the scriptSig*.
    size_t script_en_offset = script.size();
    script.resize(script.size() + EXTRANONCE2_SIZE, 0x00);

    in.scriptSig = OPScript(script.data(), script.data() + script.size());
    tx.vin.push_back(std::move(in));

    // ── Outputs ─────────────────────────────────────────────────────────
    // Miner receives the block reward minus all masternode+treasury payments.
    uint64_t miner_value = (work.m_coinbase_value > work.m_payment_amount)
        ? work.m_coinbase_value - work.m_payment_amount
        : 0;
    {
        TxOut o;
        o.value = static_cast<int64_t>(miner_value);
        o.scriptPubKey = OPScript(miner_script.data(), miner_script.data() + miner_script.size());
        tx.vout.push_back(std::move(o));
    }
    // Masternode + superblock + platform payments.
    for (const auto& p : work.m_packed_payments) {
        if (p.amount == 0) continue;
        auto ps = dash::decode_payee_script(
            p.payee, params.address_version, params.address_p2sh_version);
        if (ps.empty()) continue;                       // skip unparseable payees
        TxOut o;
        o.value = static_cast<int64_t>(p.amount);
        o.scriptPubKey = OPScript(ps.data(), ps.data() + ps.size());
        tx.vout.push_back(std::move(o));
    }

    // ── DIP3/DIP4 CBTX ──────────────────────────────────────────────────
    if (!work.m_coinbase_payload.empty()) {
        tx.version = 3;
        tx.type    = 5;
        tx.extra_payload = work.m_coinbase_payload;
    }
    tx.locktime = 0;

    // ── Serialize + locate placeholder ──────────────────────────────────
    auto packed = pack(tx);
    auto raw = packed.get_span();                       // span<byte>
    CoinbaseLayout out;
    out.bytes.reserve(raw.size());
    for (auto b : raw)
        out.bytes.push_back(static_cast<unsigned char>(b));

    // Find the zero 8-byte placeholder by searching forward from a known
    // lower bound: the scriptSig starts after
    //   4 (ver|type) + VarInt(1) + 32 (prev_hash) + 4 (prev_n) + VarInt(script_len)
    // Finding the exact VarInt width is fiddly; simpler: scan for the first
    // run of >= EXTRANONCE2_SIZE consecutive zeros that match the expected
    // tail of scriptSig. Since we know pool_tag is non-zero, the 8-zero run
    // immediately after pool_tag is unique.
    //
    // Build a needle = last byte of pool_tag + 8 zeros, then locate it.
    if (pool_tag.empty()) {
        // Without a tag we can't disambiguate — require caller provide one.
        throw std::runtime_error("coinbase_builder: pool_tag must be non-empty");
    }
    std::vector<unsigned char> needle;
    needle.reserve(1 + EXTRANONCE2_SIZE);
    needle.push_back(static_cast<unsigned char>(pool_tag.back()));
    needle.insert(needle.end(), EXTRANONCE2_SIZE, 0x00);

    auto it = std::search(out.bytes.begin(), out.bytes.end(), needle.begin(), needle.end());
    if (it == out.bytes.end())
        throw std::runtime_error("coinbase_builder: extranonce placeholder not found");
    // First byte AFTER the pool_tag tail byte is the placeholder start.
    out.extranonce_offset = static_cast<size_t>((it - out.bytes.begin()) + 1);
    return out;
}

// Split the coinbase bytes into coinb1 / coinb2 (hex-encoded) around the
// 8-byte extranonce2 placeholder.
struct CoinbSplit {
    std::string coinb1_hex;
    std::string coinb2_hex;
};

inline CoinbSplit split_coinb(const CoinbaseLayout& lay)
{
    if (lay.extranonce_offset + EXTRANONCE2_SIZE > lay.bytes.size())
        throw std::runtime_error("coinbase_builder: bad extranonce offset");
    std::span<const unsigned char> b1(lay.bytes.data(), lay.extranonce_offset);
    std::span<const unsigned char> b2(lay.bytes.data() + lay.extranonce_offset + EXTRANONCE2_SIZE,
                                       lay.bytes.size() - lay.extranonce_offset - EXTRANONCE2_SIZE);
    return CoinbSplit{HexStr(b1), HexStr(b2)};
}

// Compute sha256d of concatenated bytes.
inline uint256 sha256d(std::span<const unsigned char> a)
{
    return Hash(a);
}

// Compute merkle branches for index 0 (coinbase) given the list of all
// transaction hashes (coinbase hash at [0] is ignored — the miner computes
// it themselves). Returns 64-hex strings (not byte-reversed).
//
// Standard Bitcoin merkle tree with last-node duplication for odd layers.
inline std::vector<std::string> merkle_branches_for_coinbase(
    const std::vector<uint256>& tx_hashes_including_coinbase_placeholder)
{
    std::vector<std::string> out;
    if (tx_hashes_including_coinbase_placeholder.size() <= 1) return out;

    std::vector<uint256> layer = tx_hashes_including_coinbase_placeholder;
    while (layer.size() > 1) {
        // Record sibling of index 0 at this layer.
        out.push_back(layer[1].GetHex());
        // Build next layer: pairs, duplicating tail if odd.
        if (layer.size() % 2 == 1)
            layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            // Concat a || b, sha256d, store.
            std::vector<unsigned char> buf(64);
            std::memcpy(buf.data(),      layer[i].data(),     32);
            std::memcpy(buf.data() + 32, layer[i + 1].data(), 32);
            next.push_back(sha256d(buf));
        }
        layer.swap(next);
    }
    return out;
}

// ── Stratum wire formatting helpers ─────────────────────────────────────────

// Stratum's "prevhash" notify field is the LE byte dump of the uint256 with
// every 4-byte word byte-reversed (historic quirk inherited from Bitcoin).
//
//   in :  [B0 B1 B2 B3][B4 B5 B6 B7]...[B28 B29 B30 B31]
//   out:  [B3 B2 B1 B0][B7 B6 B5 B4]...[B31 B30 B29 B28]
inline std::string swap4_hex(std::span<const unsigned char> data)
{
    if (data.size() % 4 != 0) throw std::runtime_error("swap4_hex: len %4 != 0");
    std::vector<unsigned char> out(data.size());
    for (size_t i = 0; i < data.size(); i += 4) {
        out[i + 0] = data[i + 3];
        out[i + 1] = data[i + 2];
        out[i + 2] = data[i + 1];
        out[i + 3] = data[i + 0];
    }
    return HexStr(out);
}

// 4-byte big-endian hex of a uint32 (what Stratum expects for version/nbits/ntime).
inline std::string be_hex_u32(uint32_t v)
{
    unsigned char b[4] = {
        static_cast<unsigned char>((v >> 24) & 0xff),
        static_cast<unsigned char>((v >> 16) & 0xff),
        static_cast<unsigned char>((v >>  8) & 0xff),
        static_cast<unsigned char>((v >>  0) & 0xff),
    };
    return HexStr(std::span<const unsigned char>(b, 4));
}

// Convert compact nbits → share difficulty (Bitcoin bdiff formula).
//   diff = 0xffff0000 * 2^192 / (target + 1)
inline double bits_to_difficulty(uint32_t nbits)
{
    uint256 target;
    target.SetCompact(nbits);
    if (target.IsNull()) return 0.0;
    // Shift target right by 192 bits so we stay in double precision; the
    // bdiff constant is 0xffff0000, i.e. 2^32 * 0xffff / 0x10000 ≈ 4.29e9.
    // target >> 192 gives the top 64 bits as a uint64.
    uint256 shifted = target >> 192;
    uint64_t top = shifted.GetLow64();
    if (top == 0) return 0.0;
    const double bdiff_const = 4294901760.0;  // 0xffff0000
    return bdiff_const / static_cast<double>(top);
}

// ── One-shot: DashWorkData + miner_script → stratum::Job ────────────────────
//
// Also returns the CoinbaseLayout so the submit path can reconstruct the
// exact coinbase bytes with the miner's extranonce2 substituted in.

} // namespace coinbase
} // namespace dash

#include <impl/dash/stratum.hpp>
#include <random>
#include <sstream>
#include <iomanip>

namespace dash {
namespace job {

struct BuiltJob {
    stratum::Job job;
    coinbase::CoinbaseLayout coinbase;
};

inline std::string random_job_id()
{
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::ostringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0')
       << (static_cast<uint32_t>(rng()) & 0xffffffffu);
    return ss.str();
}

inline BuiltJob build_from_work(const dash::coin::DashWorkData& work,
                                const std::vector<unsigned char>& miner_script,
                                const std::string& pool_tag,
                                const core::CoinParams& params,
                                double share_difficulty)
{
    using namespace dash::coinbase;

    BuiltJob out;
    out.coinbase = build(work, miner_script, pool_tag, params);
    auto sp = split_coinb(out.coinbase);

    // Merkle branches: prepend a zero placeholder for the coinbase slot
    // (its real hash depends on the miner's extranonce2, so we never emit
    // branch[0] that references it — see merkle_branches_for_coinbase).
    std::vector<uint256> layer;
    layer.reserve(work.m_tx_hashes.size() + 1);
    layer.push_back(uint256::ZERO);
    for (const auto& h : work.m_tx_hashes) layer.push_back(h);
    auto branches = dash::coinbase::merkle_branches_for_coinbase(layer);

    auto prev_chars = work.m_previous_block.GetChars();
    std::span<const unsigned char> prev_span(
        reinterpret_cast<const unsigned char*>(prev_chars.data()), 32);

    out.job.job_id          = random_job_id();
    out.job.prevhash_hex    = dash::coinbase::swap4_hex(prev_span);
    out.job.coinb1_hex      = sp.coinb1_hex;
    out.job.coinb2_hex      = sp.coinb2_hex;
    out.job.merkle_branches_hex = std::move(branches);
    out.job.version_hex     = dash::coinbase::be_hex_u32(static_cast<uint32_t>(work.m_version));
    out.job.nbits_hex       = dash::coinbase::be_hex_u32(work.m_bits);
    out.job.ntime_hex       = dash::coinbase::be_hex_u32(work.m_curtime);
    out.job.clean_jobs      = true;
    out.job.share_difficulty = share_difficulty;
    return out;
}

} // namespace job
} // namespace dash
