// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::coin::sigops — conservative, fail-closed sigop accounting for the
// daemonless block assembler (GAP3). BIP-110 is a Bitcoin fork, so the sigop
// model is IDENTICAL to Bitcoin Core: legacy sigops (scriptSig + scriptPubKey)
// scaled by WITNESS_SCALE_FACTOR, plus P2SH redeem-script sigops (scaled), plus
// unscaled witness sigops. Cloned NOT shared (per-coin isolation) from Bitcoin
// Core src/consensus/tx_verify.cpp GetTransactionSigOpCost + src/script/
// interpreter.cpp CountWitnessSigOps + src/script/script.cpp GetSigOpCount.
//
// Under GAP2's inclusion rule every candidate input's prevout script is
// resolvable — from the confirmed UTXO Coin (Coin stores scriptPubKey) or from
// an in-template parent's vout — so an unresolved prevout is genuinely
// exceptional and returns std::nullopt (⇒ the assembler EXCLUDES the tx, fail
// closed). The cap is the weight-scaled conservative bound RDTS_MAX_BLOCK_
// SIGOPS_COST (params.hpp): stricter than Bitcoin's unscaled 80000, so on doubt
// we exclude a valid tx (an inclusion-% cost) but NEVER admit an invalid one.
// ZERO DASH code.
// ---------------------------------------------------------------------------

#include "transaction.hpp"

#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace bip110 {
namespace coin {
namespace sigops {

inline constexpr uint32_t WITNESS_SCALE_FACTOR      = 4;
inline constexpr uint32_t MAX_PUBKEYS_PER_MULTISIG  = 20;

// Opcodes we care about (values are the canonical Bitcoin script opcodes).
enum : unsigned char {
    OP_0                 = 0x00,
    OP_PUSHDATA1         = 0x4c,
    OP_PUSHDATA2         = 0x4d,
    OP_PUSHDATA4         = 0x4e,
    OP_1                 = 0x51,
    OP_16                = 0x60,
    OP_EQUAL             = 0x87,
    OP_HASH160           = 0xa9,
    OP_CHECKSIG          = 0xac,
    OP_CHECKSIGVERIFY    = 0xad,
    OP_CHECKMULTISIG     = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
};

// Advance `pc` over one opcode + any inline push payload. Returns false at end
// of script or on a truncated push. On success sets `opcode` and, for a push,
// exposes the payload [push_begin, push_begin+push_len).
inline bool get_op(const std::vector<unsigned char>& s, size_t& pc,
                   unsigned char& opcode, size_t& push_begin, size_t& push_len)
{
    push_len = 0; push_begin = pc;
    if (pc >= s.size()) return false;
    opcode = s[pc++];
    if (opcode > OP_PUSHDATA4) return true;   // not a push
    size_t nsize = 0;
    if (opcode < OP_PUSHDATA1) {
        nsize = opcode;
    } else if (opcode == OP_PUSHDATA1) {
        if (pc + 1 > s.size()) return false;
        nsize = s[pc]; pc += 1;
    } else if (opcode == OP_PUSHDATA2) {
        if (pc + 2 > s.size()) return false;
        nsize = size_t(s[pc]) | (size_t(s[pc + 1]) << 8); pc += 2;
    } else { // OP_PUSHDATA4
        if (pc + 4 > s.size()) return false;
        nsize = size_t(s[pc]) | (size_t(s[pc + 1]) << 8)
              | (size_t(s[pc + 2]) << 16) | (size_t(s[pc + 3]) << 24); pc += 4;
    }
    push_begin = pc;
    push_len = nsize;
    if (pc + nsize > s.size()) return false;  // truncated push
    pc += nsize;
    return true;
}

// CScript::GetSigOpCount(fAccurate) — Bitcoin Core src/script/script.cpp.
inline uint32_t script_sigops(const std::vector<unsigned char>& s, bool accurate)
{
    uint32_t n = 0;
    unsigned char last = 0xff;  // OP_INVALIDOPCODE sentinel
    size_t pc = 0;
    unsigned char op; size_t pb, pl;
    while (get_op(s, pc, op, pb, pl)) {
        if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY) {
            ++n;
        } else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) {
            if (accurate && last >= OP_1 && last <= OP_16)
                n += (last - (OP_1 - 1));  // DecodeOP_N
            else
                n += MAX_PUBKEYS_PER_MULTISIG;
        }
        last = op;
    }
    return n;
}

inline bool is_p2sh(const std::vector<unsigned char>& s) {
    return s.size() == 23 && s[0] == OP_HASH160 && s[1] == 0x14 && s[22] == OP_EQUAL;
}

// scriptSig is push-only (P2SH sigScripts must be) — grab the LAST push, which
// is the serialized redeem/witness subscript.
inline bool last_push(const std::vector<unsigned char>& s, std::vector<unsigned char>& out)
{
    size_t pc = 0; unsigned char op; size_t pb, pl;
    bool any = false;
    while (get_op(s, pc, op, pb, pl)) {
        if (op > OP_PUSHDATA4) return false;  // non-push opcode ⇒ not push-only
        out.assign(s.begin() + pb, s.begin() + pb + pl);
        any = true;
    }
    return any;
}

// Is `spk` a vN witness program? Returns version + program on success.
inline bool witness_program(const std::vector<unsigned char>& spk,
                            int& version, std::vector<unsigned char>& program)
{
    if (spk.size() < 4 || spk.size() > 42) return false;
    if (spk[0] != OP_0 && (spk[0] < OP_1 || spk[0] > OP_16)) return false;
    // second byte is a direct push of (size-2) bytes
    if (size_t(spk[1] + 2) != spk.size()) return false;
    version = (spk[0] == OP_0) ? 0 : (spk[0] - (OP_1 - 1));
    program.assign(spk.begin() + 2, spk.end());
    return true;
}

// interpreter.cpp WitnessSigOps for the v0 programs (P2WPKH / P2WSH).
inline uint32_t witness_sigops(int version, const std::vector<unsigned char>& program,
                               const OPScriptWitness& witness)
{
    if (version == 0) {
        if (program.size() == 20) return 1;  // P2WPKH
        if (program.size() == 32 && !witness.stack.empty()) {
            const auto& subscript = witness.stack.back();
            return script_sigops(subscript, /*accurate=*/true);
        }
    }
    // Future witness versions: no sigops accounted (matches Core).
    return 0;
}

// CountWitnessSigOps — resolves the witness program from the prevout scriptPubKey
// (native) or the P2SH-wrapped push in scriptSig.
inline uint32_t count_witness_sigops(const std::vector<unsigned char>& scriptSig,
                                     const std::vector<unsigned char>& prevSpk,
                                     const OPScriptWitness& witness)
{
    int version; std::vector<unsigned char> program;
    if (witness_program(prevSpk, version, program))
        return witness_sigops(version, program, witness);
    if (is_p2sh(prevSpk)) {
        std::vector<unsigned char> redeem;
        if (last_push(scriptSig, redeem) && witness_program(redeem, version, program))
            return witness_sigops(version, program, witness);
    }
    return 0;
}

// GetTransactionSigOpCost analogue. prevout_script resolves an outpoint's
// scriptPubKey (confirmed coin OR in-template parent vout); returns nullopt if
// any non-coinbase input's prevout script cannot be resolved (⇒ exclude).
// The caller passes is_coinbase=false for all mempool candidates.
inline std::optional<uint32_t> tx_sigop_cost(
    const MutableTransaction& tx,
    const std::function<std::optional<std::vector<unsigned char>>(const uint256&, uint32_t)>& prevout_script)
{
    // Legacy sigops: own scriptSigs + own scriptPubKeys, scaled ×4.
    uint32_t legacy = 0;
    for (const auto& in : tx.vin)  legacy += script_sigops(in.scriptSig.m_data, /*accurate=*/false);
    for (const auto& out : tx.vout) legacy += script_sigops(out.scriptPubKey.m_data, /*accurate=*/false);
    uint64_t cost = uint64_t(legacy) * WITNESS_SCALE_FACTOR;

    // P2SH (scaled ×4) + witness (unscaled) sigops need each prevout script.
    for (const auto& in : tx.vin) {
        auto spk = prevout_script(in.prevout.hash, in.prevout.index);
        if (!spk) return std::nullopt;   // unresolvable ⇒ fail closed
        if (is_p2sh(*spk)) {
            std::vector<unsigned char> redeem;
            if (last_push(in.scriptSig.m_data, redeem))
                cost += uint64_t(script_sigops(redeem, /*accurate=*/true)) * WITNESS_SCALE_FACTOR;
        }
        cost += count_witness_sigops(in.scriptSig.m_data, *spk, in.scriptWitness);
    }
    if (cost > 0xffffffffULL) return 0xffffffffu;
    return static_cast<uint32_t>(cost);
}

} // namespace sigops
} // namespace coin
} // namespace bip110
