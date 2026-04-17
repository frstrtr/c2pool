#pragma once

// Dash coinbase TX assembly for p2pool-dash v16 compatible Stratum mining.
//
// The layout is dictated by the hash_link mechanism documented in
// share_check.hpp::compute_gentx_before_refhash:
//
//   [ver|type int32]
//   [vin VarInt = 1]
//   [TxIn:
//      [prev_hash 32B zeros][prev_n 0xFFFFFFFF]
//      [VarStr scriptSig:
//         [BIP34 height push][pool_tag]          ← no extranonce here anymore
//      ]
//      [sequence 0xFFFFFFFF]
//   ]
//   [vout VarInt]
//     [worker_payouts…]                          ← PPLNS splits
//     [packed_payments…]                         ← masternode/superblock/platform
//     [donation_output:
//        [value i64][VarStr DONATION_SCRIPT]     ← constant tail; value usually 0
//     ]
//     [op_return_output:
//        [value i64 = 0][VarStr (42B):
//           [0x6a OP_RETURN][0x28 push40]
//           [ref_hash 32B]      ← pool fills; PPLNS commitment
//           [nonce64 8B]        ← miner fills via Stratum extranonce2
//        ]
//     ]
//   [locktime 4B = 0]
//   [optional VarStr extra_payload]              ← DIP3/DIP4 CBTX
//
// The 8-byte `nonce64` placeholder is the Stratum extranonce2 slot.
// Coinb1 = bytes[0 : nonce64_offset]      ( includes ref_hash )
// Coinb2 = bytes[nonce64_offset + 8 : ]   ( starts at locktime )

#include "coin/transaction.hpp"
#include "coin/rpc_data.hpp"
#include "share_check.hpp"                 // decode_payee_script, pubkey_hash_to_script2, DONATION_SCRIPT

#include <algorithm>
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

static constexpr size_t EXTRANONCE2_SIZE = 8;          // = nonce64 width

// One miner payout row: scriptPubKey + amount (sat).
struct MinerPayout {
    std::vector<unsigned char> script;
    uint64_t                   amount{0};
};

// Replica of p2pool-dash/p2pool/data.py:181-231 generate_transaction
// tx_outs construction. Returns tx_outs in the exact on-wire order:
//     worker_tx (sorted by script bytes, excluding DONATION) ||
//     payments_tx (packed_payments in GBT order)             ||
//     donation_tx (always one entry, even at value 0)
// Does NOT include the OP_RETURN — coinbase::build() appends that.
//
// For genesis (no previous shares on the chain), pass an empty weights
// map and total_weight == 0. For non-genesis shares the caller must
// supply tracker-derived PPLNS weights from get_cumulative_weights —
// TODO, not yet ported from p2pool's skiplist.
//
// Scope boundary: this builds the canonical p2pool-dash tx_outs layout.
// Callers that want c2pool-native PPLNS must compute their own
// distribution and build the coinbase directly.
inline std::vector<MinerPayout> compute_dash_payouts(
    uint64_t subsidy,
    const std::vector<dash::coin::PackedPayment>& packed_payments,
    const uint160& miner_pubkey_hash,
    const std::map<std::vector<unsigned char>, uint64_t>& weights,
    uint64_t total_weight,
    const core::CoinParams& params)
{
    using Script = std::vector<unsigned char>;
    const Script donation_script(dash::DONATION_SCRIPT.begin(),
                                  dash::DONATION_SCRIPT.end());

    // 1. payments_tx: preserves GBT order, drops zero-value entries + undecodable payees.
    std::vector<MinerPayout> payments_tx;
    payments_tx.reserve(packed_payments.size());
    uint64_t total_payments = 0;
    for (const auto& p : packed_payments) {
        if (p.amount == 0) continue;
        auto pm_script = dash::decode_payee_script(
            p.payee, params.address_version, params.address_p2sh_version);
        if (pm_script.empty()) continue;
        MinerPayout out;
        out.amount = p.amount;
        out.script = std::move(pm_script);
        payments_tx.push_back(std::move(out));
        total_payments += p.amount;
    }

    // 2. worker_payout = subsidy - Σpayment_amounts
    uint64_t worker_payout = (subsidy > total_payments) ? (subsidy - total_payments) : 0;

    // 3. amounts[script] = worker_payout * 49 * weight / (50 * total_weight)
    //    (empty for genesis; TODO for non-genesis once skiplist is ported).
    std::map<Script, uint64_t> amounts;
    if (total_weight > 0) {
        // uint128-ish: worker_payout < 2^50, 49 < 2^6, weight < ~2^80 for a few
        // shares; use explicit 128-bit to avoid silent overflow.
        __uint128_t den = static_cast<__uint128_t>(total_weight) * 50;
        for (const auto& [script, w] : weights) {
            __uint128_t num = static_cast<__uint128_t>(w)
                            * static_cast<__uint128_t>(worker_payout)
                            * 49;
            amounts[script] = static_cast<uint64_t>(num / den);
        }
    }

    // 4. amounts[this_script] += worker_payout // 50  (2 % block-finder).
    auto this_script = dash::pubkey_hash_to_script2(miner_pubkey_hash);
    amounts[this_script] = amounts[this_script] + (worker_payout / 50);

    // 5. amounts[DONATION] += worker_payout - Σamounts  (remainder incl. rounding).
    uint64_t current_sum = 0;
    for (const auto& [s, a] : amounts) current_sum += a;
    uint64_t donation_remainder = (worker_payout > current_sum)
        ? (worker_payout - current_sum) : 0;
    amounts[donation_script] = amounts[donation_script] + donation_remainder;

    // Sanity: Σ(amounts) == worker_payout (matches p2pool-dash assertion).
    {
        uint64_t check = 0;
        for (const auto& [s, a] : amounts) check += a;
        if (check != worker_payout)
            throw std::runtime_error("compute_dash_payouts: amounts sum mismatch");
    }

    // 6. worker_tx = amounts sorted by script bytes, excluding DONATION,
    //               dropping zero-value entries. std::map is already sorted.
    std::vector<MinerPayout> worker_tx;
    worker_tx.reserve(amounts.size());
    for (const auto& [script, amount] : amounts) {
        if (script == donation_script) continue;
        if (amount == 0) continue;
        MinerPayout out;
        out.amount = amount;
        out.script = script;
        worker_tx.push_back(std::move(out));
    }

    // 7. donation_tx — always emitted even at value 0.
    MinerPayout donation_out;
    donation_out.amount = amounts[donation_script];
    donation_out.script = donation_script;

    // 8. Final order: worker_tx || payments_tx || donation_tx.
    std::vector<MinerPayout> result;
    result.reserve(worker_tx.size() + payments_tx.size() + 1);
    for (auto& o : worker_tx)   result.push_back(std::move(o));
    for (auto& o : payments_tx) result.push_back(std::move(o));
    result.push_back(std::move(donation_out));
    return result;
}

// Result of build(): raw coinbase bytes + key offsets.
struct CoinbaseLayout {
    std::vector<unsigned char> bytes;
    size_t ref_hash_offset{0};   // first byte of the 32B ref_hash region
    size_t nonce64_offset{0};    // first byte of the 8B nonce64 placeholder
                                 // (always == ref_hash_offset + 32)
};

// BIP34 minimal push of a positive integer. Writes length byte + height LE.
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
    if (le.back() & 0x80) le.push_back(0x00);           // avoid sign

    std::vector<unsigned char> out;
    out.reserve(1 + le.size());
    out.push_back(static_cast<unsigned char>(le.size()));
    out.insert(out.end(), le.begin(), le.end());
    return out;
}

// Convert compact nbits → share difficulty (Bitcoin bdiff formula).
inline double bits_to_difficulty(uint32_t nbits)
{
    uint256 target;
    target.SetCompact(nbits);
    if (target.IsNull()) return 0.0;
    uint256 shifted = target >> 192;
    uint64_t top = shifted.GetLow64();
    if (top == 0) return 0.0;
    const double bdiff_const = 4294901760.0;  // 0xffff0000
    return bdiff_const / static_cast<double>(top);
}

// Build the coinbase TX in the p2pool-dash v16 layout.
//
//   work             — parsed GBT
//   tx_outs_ordered  — full output list in p2pool-dash generate_transaction
//                      order: worker_tx || payments_tx || donation_tx.
//                      Must end with a donation output whose script ==
//                      DONATION_SCRIPT so gentx_before_refhash lines up.
//                      Zero-value entries are emitted as-is (callers that
//                      want to strip them should do so before calling).
//   pool_tag         — short tag in coinbase scriptSig (no extranonce)
//   params           — coin params (unused here; retained for symmetry)
//   ref_hash         — 32B PPLNS commitment embedded in OP_RETURN
inline CoinbaseLayout build(const dash::coin::DashWorkData& work,
                            const std::vector<MinerPayout>& tx_outs_ordered,
                            const std::string& pool_tag,
                            const core::CoinParams& params,
                            const uint256& ref_hash)
{
    (void)params;
    using namespace dash::coin;

    MutableTransaction tx;

    // ── Input ───────────────────────────────────────────────────────────
    TxIn in;
    in.prevout.hash  = uint256::ZERO;
    in.prevout.index = 0xFFFFFFFFu;
    in.sequence      = 0xFFFFFFFFu;
    {
        std::vector<unsigned char> script;
        auto h_push = push_bip34_height(work.m_height);
        script.insert(script.end(), h_push.begin(), h_push.end());
        script.insert(script.end(), pool_tag.begin(), pool_tag.end());
        in.scriptSig = OPScript(script.data(), script.data() + script.size());
    }
    tx.vin.push_back(std::move(in));

    // ── Outputs (caller-ordered tx_outs + OP_RETURN) ────────────────────
    //
    // Caller (share_builder / compute_dash_payouts) has already put the
    // tx_outs into the exact p2pool-dash generate_transaction order,
    // including a guaranteed donation output at the tail. We trust that
    // and just append.
    if (tx_outs_ordered.empty())
        throw std::runtime_error("coinbase_builder: empty tx_outs_ordered");
    if (tx_outs_ordered.back().script !=
        std::vector<unsigned char>(dash::DONATION_SCRIPT.begin(),
                                    dash::DONATION_SCRIPT.end()))
        throw std::runtime_error(
            "coinbase_builder: last output must be DONATION_SCRIPT");

    for (const auto& p : tx_outs_ordered) {
        TxOut o;
        o.value = static_cast<int64_t>(p.amount);
        o.scriptPubKey = OPScript(
            p.script.data(), p.script.data() + p.script.size());
        tx.vout.push_back(std::move(o));
    }
    // OP_RETURN output carrying [0x6a][0x28][ref_hash 32B][nonce64 8B].
    {
        std::vector<unsigned char> op_ret;
        op_ret.reserve(2 + 32 + 8);
        op_ret.push_back(0x6a);                             // OP_RETURN
        op_ret.push_back(0x28);                             // push 40 bytes
        op_ret.insert(op_ret.end(), ref_hash.data(), ref_hash.data() + 32);
        op_ret.insert(op_ret.end(), EXTRANONCE2_SIZE, 0x00); // nonce64 placeholder
        TxOut o;
        o.value = 0;
        o.scriptPubKey = OPScript(op_ret.data(), op_ret.data() + op_ret.size());
        tx.vout.push_back(std::move(o));
    }

    // ── DIP3/DIP4 ───────────────────────────────────────────────────────
    if (!work.m_coinbase_payload.empty()) {
        tx.version = 3;
        tx.type    = 5;
        tx.extra_payload = work.m_coinbase_payload;
    }
    tx.locktime = 0;

    // ── Serialize ───────────────────────────────────────────────────────
    auto packed = pack(tx);
    auto raw = packed.get_span();
    CoinbaseLayout out;
    out.bytes.reserve(raw.size());
    for (auto b : raw) out.bytes.push_back(static_cast<unsigned char>(b));

    // ── Locate ref_hash / nonce64 positions from the tail ───────────────
    // Tail layout (bytes, from end of tx moving toward start):
    //   [VarStr extra_payload]?   — length = payload_varstr_size
    //   [locktime 4B]
    //   [nonce64 8B]              ← EXTRANONCE2_SIZE bytes of zeros (miner fills)
    //   [ref_hash 32B]            ← the ref_hash we just embedded
    //   [0x28 push40]
    //   [0x6a OP_RETURN]
    //   [0x2a VarInt script_len 42]
    //   [value i64 = 0]
    //
    // So offsets-from-end:
    //   nonce64_offset  = total - payload_varstr_size - 4 - 8
    //   ref_hash_offset = total - payload_varstr_size - 4 - 8 - 32
    size_t payload_varstr_size = 0;
    if (tx.type != 0 && !tx.extra_payload.empty()) {
        PackStream ps;
        BaseScript bs; bs.m_data = tx.extra_payload;
        ps << bs;
        payload_varstr_size = ps.size();
    }
    const size_t total = out.bytes.size();
    if (total < payload_varstr_size + 4 + 8 + 32)
        throw std::runtime_error("coinbase_builder: tx shorter than known tail");
    out.nonce64_offset  = total - payload_varstr_size - 4 - 8;
    out.ref_hash_offset = out.nonce64_offset - 32;

    // Sanity: bytes at ref_hash_offset must equal the ref_hash we embedded.
    if (std::memcmp(out.bytes.data() + out.ref_hash_offset, ref_hash.data(), 32) != 0)
        throw std::runtime_error("coinbase_builder: ref_hash offset mismatch");
    // Sanity: bytes at nonce64_offset must be 8 zero bytes.
    for (size_t i = 0; i < EXTRANONCE2_SIZE; ++i) {
        if (out.bytes[out.nonce64_offset + i] != 0x00)
            throw std::runtime_error("coinbase_builder: nonce64 placeholder not zeroed");
    }

    return out;
}

// Split coinbase bytes into coinb1 / coinb2 hex around the 8-byte nonce64
// slot. The miner inserts its extranonce2 in that slot.
struct CoinbSplit {
    std::string coinb1_hex;
    std::string coinb2_hex;
};

inline CoinbSplit split_coinb(const CoinbaseLayout& lay)
{
    if (lay.nonce64_offset + EXTRANONCE2_SIZE > lay.bytes.size())
        throw std::runtime_error("split_coinb: bad nonce64 offset");
    std::span<const unsigned char> b1(lay.bytes.data(), lay.nonce64_offset);
    std::span<const unsigned char> b2(
        lay.bytes.data() + lay.nonce64_offset + EXTRANONCE2_SIZE,
        lay.bytes.size() - lay.nonce64_offset - EXTRANONCE2_SIZE);
    return CoinbSplit{HexStr(b1), HexStr(b2)};
}

// Compute sha256d of concatenated bytes.
inline uint256 sha256d(std::span<const unsigned char> a)
{
    return Hash(a);
}

// Merkle branches for index 0 with placeholder at [0]. (Siblings along the
// path do not depend on [0] even though it participates in the reduction.)
inline std::vector<uint256> merkle_branches_raw(
    const std::vector<uint256>& tx_hashes_including_coinbase_placeholder)
{
    std::vector<uint256> out;
    if (tx_hashes_including_coinbase_placeholder.size() <= 1) return out;

    std::vector<uint256> layer = tx_hashes_including_coinbase_placeholder;
    while (layer.size() > 1) {
        out.push_back(layer[1]);
        if (layer.size() % 2 == 1)
            layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            std::vector<unsigned char> buf(64);
            std::memcpy(buf.data(),      layer[i].data(),     32);
            std::memcpy(buf.data() + 32, layer[i + 1].data(), 32);
            next.push_back(sha256d(buf));
        }
        layer.swap(next);
    }
    return out;
}

inline std::vector<std::string> merkle_branches_hex(const std::vector<uint256>& raw)
{
    std::vector<std::string> out;
    out.reserve(raw.size());
    for (const auto& h : raw) out.push_back(h.GetHex());
    return out;
}

// ── Stratum wire formatting helpers ─────────────────────────────────────────

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

} // namespace coinbase
} // namespace dash
