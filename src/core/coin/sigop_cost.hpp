// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin::sigops -- the signature-operation count of scripts, as Bitcoin
// Core and its forks (Litecoin Core 0.21.4, Dogecoin Core 1.14.9) count it
// for the block limit:
//   script_sigops      CScript::GetSigOpCount(bool fAccurate)
//                      (script/script.cpp)
//   p2sh_sigops        CScript::GetSigOpCount(const CScript& scriptSig): the
//                      redeem script's accurate count (script/script.cpp)
//   witness_sigops     CountWitnessSigOps / WitnessSigOps
//                      (script/interpreter.cpp)
//   is_p2sh            CScript::IsPayToScriptHash
//   witness_program    CScript::IsWitnessProgram
//   is_push_only       CScript::IsPushOnly
// A transaction's cost is GetTransactionSigOpCost
// (consensus/tx_verify.cpp): legacy sigops (every scriptSig and
// scriptPubKey, inaccurate) x scale, then -- not for a coinbase -- P2SH
// sigops x scale and the witness sigops unscaled. SigopRules says which
// parts a chain counts and its block limit: Litecoin counts all three at
// scale WITNESS_SCALE_FACTOR (4) within MAX_BLOCK_SIGOPS_COST (80,000);
// Dogecoin has no segwit (legacy and P2SH only) within 20,000 sigops.
// Header-only and pure over bytes, so the KATs pin it directly.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace core::coin::sigops {

/// Which sigops a chain counts and its block limit, in cost units.
struct SigopRules {
    bool     p2sh{true};             // SCRIPT_VERIFY_P2SH (BIP16)
    bool     witness{true};          // SCRIPT_VERIFY_WITNESS (BIP141)
    uint32_t scale{4};               // cost of one legacy or P2SH sigop
    int64_t  max_block_cost{80'000}; // the block's limit

    bool operator==(const SigopRules&) const = default;
};

/// Litecoin Core 0.21.4 consensus/consensus.h: MAX_BLOCK_SIGOPS_COST 80,000,
/// WITNESS_SCALE_FACTOR 4; P2SH and segwit active (ConnectBlock flags).
inline constexpr SigopRules LTC_SIGOP_RULES{true, true, 4, 80'000};

/// Dogecoin Core 1.14.9: no segwit; the block's legacy and P2SH sigops at
/// most 20,000 (MAX_BLOCK_SIGOPS; the same as 80,000 cost at scale 4 with no
/// witness part).
inline constexpr SigopRules DOGE_SIGOP_RULES{true, false, 1, 20'000};

inline constexpr unsigned char OP_0 = 0x00;
inline constexpr unsigned char OP_PUSHDATA1 = 0x4c;
inline constexpr unsigned char OP_PUSHDATA2 = 0x4d;
inline constexpr unsigned char OP_PUSHDATA4 = 0x4e;
inline constexpr unsigned char OP_1 = 0x51;
inline constexpr unsigned char OP_16 = 0x60;
inline constexpr unsigned char OP_HASH160 = 0xa9;
inline constexpr unsigned char OP_EQUAL = 0x87;
inline constexpr unsigned char OP_CHECKSIG = 0xac;
inline constexpr unsigned char OP_CHECKSIGVERIFY = 0xad;
inline constexpr unsigned char OP_CHECKMULTISIG = 0xae;
inline constexpr unsigned char OP_CHECKMULTISIGVERIFY = 0xaf;
inline constexpr unsigned MAX_PUBKEYS_PER_MULTISIG = 20;

using Bytes = std::span<const unsigned char>;

/// GetScriptOp (script/script.cpp): one opcode and, for a push, its data.
/// False at the end of the script or on a truncated push.
inline bool get_op(Bytes s, size_t& pc, unsigned char& opcode, Bytes* data = nullptr)
{
    if (data)
        *data = {};
    if (pc >= s.size())
        return false;
    opcode = s[pc++];
    if (opcode > OP_PUSHDATA4)
        return true;
    size_t n = 0;
    if (opcode < OP_PUSHDATA1) {
        n = opcode;
    } else if (opcode == OP_PUSHDATA1) {
        if (s.size() - pc < 1)
            return false;
        n = s[pc];
        pc += 1;
    } else if (opcode == OP_PUSHDATA2) {
        if (s.size() - pc < 2)
            return false;
        n = static_cast<size_t>(s[pc]) | static_cast<size_t>(s[pc + 1]) << 8;
        pc += 2;
    } else {
        if (s.size() - pc < 4)
            return false;
        n = static_cast<size_t>(s[pc]) | static_cast<size_t>(s[pc + 1]) << 8
          | static_cast<size_t>(s[pc + 2]) << 16 | static_cast<size_t>(s[pc + 3]) << 24;
        pc += 4;
    }
    if (s.size() - pc < n)
        return false;
    if (data)
        *data = s.subspan(pc, n);
    pc += n;
    return true;
}

/// CScript::GetSigOpCount(bool fAccurate).
inline unsigned script_sigops(Bytes s, bool accurate)
{
    unsigned n = 0;
    size_t pc = 0;
    unsigned char last = 0xff;  // OP_INVALIDOPCODE
    unsigned char op = 0;
    while (pc < s.size()) {
        if (!get_op(s, pc, op))
            break;
        if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY) {
            n += 1;
        } else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) {
            if (accurate && last >= OP_1 && last <= OP_16)
                n += static_cast<unsigned>(last - OP_1 + 1);  // DecodeOP_N
            else
                n += MAX_PUBKEYS_PER_MULTISIG;
        }
        last = op;
    }
    return n;
}

/// CScript::IsPayToScriptHash: OP_HASH160 PUSH20 <20> OP_EQUAL.
inline bool is_p2sh(Bytes s)
{
    return s.size() == 23 && s[0] == OP_HASH160 && s[1] == 0x14 && s[22] == OP_EQUAL;
}

/// CScript::IsWitnessProgram.
inline bool witness_program(Bytes s, int& version, Bytes& program)
{
    if (s.size() < 4 || s.size() > 42)
        return false;
    if (s[0] != OP_0 && (s[0] < OP_1 || s[0] > OP_16))
        return false;
    if (static_cast<size_t>(s[1]) + 2 != s.size())
        return false;
    version = s[0] == OP_0 ? 0 : s[0] - OP_1 + 1;
    program = s.subspan(2);
    return true;
}

/// CScript::IsPushOnly (OP_RESERVED counts as a push).
inline bool is_push_only(Bytes s)
{
    size_t pc = 0;
    unsigned char op = 0;
    while (pc < s.size()) {
        if (!get_op(s, pc, op))
            return false;
        if (op > OP_16)
            return false;
    }
    return true;
}

/// CScript::GetSigOpCount(const CScript& scriptSig) for a P2SH prevout: the
/// accurate count of the last item the scriptSig pushes (0 when the
/// scriptSig has another opcode or does not parse); for any other prevout
/// its own accurate count.
inline unsigned p2sh_sigops(Bytes prevout_spk, Bytes script_sig)
{
    if (!is_p2sh(prevout_spk))
        return script_sigops(prevout_spk, true);
    size_t pc = 0;
    unsigned char op = 0;
    Bytes data;
    while (pc < script_sig.size()) {
        if (!get_op(script_sig, pc, op, &data))
            return 0;
        if (op > OP_16)
            return 0;
    }
    return script_sigops(data, true);
}

/// WitnessSigOps (script/interpreter.cpp): v0 keyhash 1, v0 scripthash the
/// accurate count of the witness script, every other version 0.
inline unsigned witness_program_sigops(int version, Bytes program,
                                       const std::vector<std::vector<unsigned char>>& witness)
{
    if (version == 0) {
        if (program.size() == 20)
            return 1;
        if (program.size() == 32 && !witness.empty())
            return script_sigops(Bytes(witness.back().data(), witness.back().size()), true);
    }
    return 0;
}

/// CountWitnessSigOps with SCRIPT_VERIFY_WITNESS set: a witness program
/// prevout, or a P2SH prevout whose push-only scriptSig pushes one last.
inline unsigned witness_sigops(Bytes script_sig, Bytes prevout_spk,
                               const std::vector<std::vector<unsigned char>>& witness)
{
    int version = 0;
    Bytes program;
    if (witness_program(prevout_spk, version, program))
        return witness_program_sigops(version, program, witness);
    if (is_p2sh(prevout_spk) && is_push_only(script_sig)) {
        size_t pc = 0;
        unsigned char op = 0;
        Bytes data;
        while (pc < script_sig.size())
            get_op(script_sig, pc, op, &data);
        if (witness_program(data, version, program))
            return witness_program_sigops(version, program, witness);
    }
    return 0;
}

/// The legacy sigops of a serialized transaction (GetLegacySigOpCount over
/// every scriptSig and scriptPubKey): what a coinbase costs, x scale. The
/// witness and MWEB parts carry none and are not read. nullopt when the hex
/// does not parse.
inline std::optional<unsigned> tx_hex_legacy_sigops(std::string_view hex)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (hex.size() % 2 != 0)
        return std::nullopt;
    std::vector<unsigned char> b(hex.size() / 2);
    for (size_t i = 0; i < b.size(); ++i) {
        const int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        b[i] = static_cast<unsigned char>(hi << 4 | lo);
    }
    size_t p = 0;
    auto need = [&](size_t n) { return b.size() - p >= n; };
    auto compact = [&](uint64_t& v) -> bool {
        if (!need(1))
            return false;
        const unsigned char c = b[p++];
        size_t k = c < 0xfd ? 0 : c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
        if (!need(k))
            return false;
        v = c < 0xfd ? c : 0;
        for (size_t i = 0; i < k; ++i)
            v |= static_cast<uint64_t>(b[p + i]) << (8 * i);
        p += k;
        return true;
    };
    if (!need(4))
        return std::nullopt;
    p += 4;
    uint64_t n_in = 0;
    if (!compact(n_in))
        return std::nullopt;
    if (n_in == 0) {  // extended format: flag byte, then the inputs
        if (!need(1))
            return std::nullopt;
        ++p;
        if (!compact(n_in))
            return std::nullopt;
    }
    unsigned n = 0;
    for (uint64_t i = 0; i < n_in; ++i) {
        uint64_t len = 0;
        if (!need(36))
            return std::nullopt;
        p += 36;
        if (!compact(len) || !need(len))
            return std::nullopt;
        n += script_sigops(Bytes(b.data() + p, static_cast<size_t>(len)), false);
        p += static_cast<size_t>(len);
        if (!need(4))
            return std::nullopt;
        p += 4;
    }
    uint64_t n_out = 0;
    if (!compact(n_out))
        return std::nullopt;
    for (uint64_t i = 0; i < n_out; ++i) {
        uint64_t len = 0;
        if (!need(8))
            return std::nullopt;
        p += 8;
        if (!compact(len) || !need(len))
            return std::nullopt;
        n += script_sigops(Bytes(b.data() + p, static_cast<size_t>(len)), false);
        p += static_cast<size_t>(len);
    }
    return n;
}

} // namespace core::coin::sigops
