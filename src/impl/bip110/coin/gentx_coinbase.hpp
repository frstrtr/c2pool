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
// frstrtr/p2pool-merged-v36 data.py (BTC parent) generate_transaction():
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

namespace bip110::coin
{

struct GentxCoinbase
{
    std::vector<unsigned char> bytes;       // non-witness serialization (txid/merkle source)
    uint256 txid;                           // double-SHA256(bytes) == gentx_hash
    // BIP144 (segwit) serialization used for the BLOCK BODY when a witness
    // commitment output is present:
    //   version | 0x00 0x01 (marker+flag) | vin | vout |
    //   witness_for_input0{ 0x01 (stack items) | 0x20 (len 32) | reserved(32) }
    //   | locktime
    // The 32-byte reserved value is the caller-supplied witness_reserved_value
    // (defaults to 32 zeros). Segwit consensus recomputes the coinbase witness
    // commitment as SHA256d(witness_merkle_root || reserved) and checks it against
    // the aa21a9ed commitment output — so the reserved value spliced here MUST be
    // the SAME 32 bytes the commitment output was computed over, or the won block
    // is rejected with bad-witness-merkle-match. OFF/M2 (commitment over reserved
    // 0*32) => empty arg => 32 zeros. Flag-ON P2Pool (commitment over '[P2Pool]'*4)
    // => caller passes those 32 bytes.
    // Knots/Core CheckWitnessMalleation REQUIRES exactly one 32-byte witness
    // element on the coinbase input whenever a commitment output exists;
    // shipping `bytes` (empty witness stack) => bad-witness-nonce-size => the
    // won block is rejected by fork peers AND submitblock. When there is no
    // commitment output, block_bytes == bytes (no witness, as before).
    // txid/merkle stay over the NON-witness `bytes` (segwit-invariant).
    std::vector<unsigned char> block_bytes;
};

// payout_outputs: (scriptPubKey, value) pairs in final consensus order.
// segwit_commitment_script / segwit absent -> no witness-commitment vout.
inline GentxCoinbase assemble_gentx_coinbase(
    const std::vector<unsigned char>& coinbase_script,
    const std::optional<std::vector<unsigned char>>& segwit_commitment_script,
    const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payout_outputs,
    uint64_t donation_amount,
    const std::vector<unsigned char>& donation_script,
    const std::vector<unsigned char>& op_return_script,
    // Block-body witness reserved value (coinbase input witness stack item). Empty
    // => 32 zeros (OFF/M2, byte-identical to before). On the flag-ON P2Pool path
    // the caller passes '[P2Pool]'*4 to match the P2Pool witness commitment.
    const std::vector<unsigned char>& witness_reserved_value = {})
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
    out.txid = Hash(sp);   // txid/merkle over the NON-witness bytes (segwit-invariant)

    // ── BIP144 block-body serialization ──────────────────────────────────────
    // When a witness-commitment output exists, the coinbase carried in the block
    // MUST expose exactly one 32-byte witness element (the reserved value) on its
    // single input, or Knots/Core CheckWitnessMalleation rejects it with
    // bad-witness-nonce-size. Splice the marker+flag after the 4-byte version and
    // the witness+locktime around the non-witness body:
    //   version(4) | 0x00 0x01 | vin | vout | witness | locktime(4)
    // The reserved value is witness_reserved_value (or 32 zeros when empty) — it
    // MUST be the SAME preimage the commitment output consumed
    // (SHA256d(witness_merkle_root || reserved)). OFF/M2: reserved 0*32 matches the
    // M2 commitment over reserved 0*32. Flag-ON: reserved '[P2Pool]'*4 matches the
    // P2Pool commitment over the real witness root. No commitment output => no
    // witness => block_bytes == bytes (byte-unchanged).
    if (segwit_commitment_script.has_value() && out.bytes.size() >= 8)
    {
        const size_t n = out.bytes.size();
        std::vector<unsigned char>& b = out.block_bytes;
        b.reserve(n + 2 + 34);
        // version (4)
        b.insert(b.end(), out.bytes.begin(), out.bytes.begin() + 4);
        // segwit marker + flag
        b.push_back(0x00);
        b.push_back(0x01);
        // vin || vout  (everything between version and locktime)
        b.insert(b.end(), out.bytes.begin() + 4, out.bytes.begin() + (n - 4));
        // witness for input[0]: 1 stack item, 32-byte reserved value.
        b.push_back(0x01);                 // stack item count
        b.push_back(0x20);                 // element length = 32
        if (witness_reserved_value.size() == 32)
            b.insert(b.end(), witness_reserved_value.begin(),
                     witness_reserved_value.end());   // flag-ON: '[P2Pool]'*4
        else
            b.insert(b.end(), 32, 0x00);   // OFF/M2: 32-zero reserved value
        // locktime (4)
        b.insert(b.end(), out.bytes.begin() + (n - 4), out.bytes.end());
    }
    else
    {
        out.block_bytes = out.bytes;       // no commitment -> no witness needed
    }
    return out;
}

} // namespace bip110::coin