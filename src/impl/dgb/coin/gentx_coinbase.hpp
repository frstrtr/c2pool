// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ============================================================================
// gentx_coinbase.hpp — SSOT non-witness coinbase (gentx) assembler.
//
// Single source of the p2pool coinbase wire layout. Consumed by:
//   - share_check.hpp generate_share_transaction()  (the verification SSOT)
//   - share_check.hpp create_local_share()          (the "same format as" smell)
//   - won-block reconstruction (as_block framing)
// so that emission and verification can never diverge on a byte.
//
// Produces the NON-WITNESS serialization and its double-SHA256 txid
// (== p2pool gentx_hash). Byte layout mirrors
// frstrtr/p2pool-merged-v36 data.py generate_transaction():
//
//   version(4 LE = 1)
//   vin_count(varint = 1)
//   vin[0] = prev_hash(32 zero) | prev_idx(0xffffffff) | script(VarStr) | seq(0xffffffff)
//   vout_count(varint)
//   vouts: [segwit_commitment?] ++ payout_outputs ++ donation ++ op_return_commitment
//          each vout = value(8 LE) | script(VarStr)
//   lock_time(4 = 0)
//
// Pure: takes already-built script/amount inputs (no tracker, no share template
// dependency) so it is directly KAT-able against a canonical oracle vector.
// ============================================================================

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace dgb::coin
{

struct GentxCoinbase
{
    std::vector<unsigned char> bytes; // non-witness serialization
    uint256 txid;                     // double-SHA256(bytes) == gentx_hash
};

// payout_outputs: (scriptPubKey, value) pairs in final consensus order.
// segwit_commitment_script / segwit absent -> no witness-commitment vout.
inline GentxCoinbase assemble_gentx_coinbase(
    const std::vector<unsigned char>& coinbase_script,
    const std::optional<std::vector<unsigned char>>& segwit_commitment_script,
    const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payout_outputs,
    uint64_t donation_amount,
    const std::vector<unsigned char>& donation_script,
    const std::vector<unsigned char>& op_return_script)
{
    PackStream tx;

    // tx version = 1
    uint32_t tx_version = 1;
    tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&tx_version), 4));

    // vin count = 1
    {
        unsigned char one = 1;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1));
    }

    // vin[0]: prev_output = 0...0:ffffffff, script = coinbase, sequence = 0xffffffff
    {
        uint256 zero_hash;
        tx << zero_hash;
        uint32_t prev_idx = 0xffffffff;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&prev_idx), 4));
        BaseScript cb; cb.m_data = coinbase_script;
        tx << cb;
        uint32_t seq = 0xffffffff;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4));
    }

    // vout count
    size_t n_outs = payout_outputs.size() + 1 /* donation */ + 1 /* OP_RETURN */
                  + (segwit_commitment_script.has_value() ? 1 : 0);
    if (n_outs < 253)
    {
        uint8_t cnt = static_cast<uint8_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1));
    }
    else
    {
        uint8_t marker = 0xfd;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&marker), 1));
        uint16_t cnt = static_cast<uint16_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2));
    }

    auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
        BaseScript bs; bs.m_data = script;
        tx << bs;
    };

    // segwit witness-commitment vout (value 0)
    if (segwit_commitment_script.has_value())
        write_txout(0, segwit_commitment_script.value());

    // PPLNS payout outputs (caller supplies final sorted order)
    for (auto& [script, amount] : payout_outputs)
        write_txout(amount, script);

    // donation output
    write_txout(donation_amount, donation_script);

    // OP_RETURN ref commitment (value 0)
    write_txout(0, op_return_script);

    // lock_time = 0
    {
        uint32_t locktime = 0;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&locktime), 4));
    }

    GentxCoinbase out;
    out.bytes.assign(reinterpret_cast<const unsigned char*>(tx.data()),
                     reinterpret_cast<const unsigned char*>(tx.data()) + tx.size());
    auto sp = std::span<const unsigned char>(out.bytes.data(), out.bytes.size());
    out.txid = Hash(sp);
    return out;
}

} // namespace dgb::coin