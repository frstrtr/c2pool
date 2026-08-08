// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Sigop accounting for the embedded DASH template builder — G2 of the
/// ConnectBlock reject-surface audit
/// (frstrtr/the docs/DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md).
///
/// dashd rejects a block whose accumulated legacy+P2SH sigop count exceeds
/// MaxBlockSigOps (validation.cpp:2535 `bad-blk-sigops`; consensus/consensus.h
/// MAX_BLOCK_SIGOPS_PER_MB * 2 = 40'000 at the DIP-0001 2 MB size). dashd's
/// own miner enforces the cap per selected package (node/miner.cpp
/// TestPackage); before this file the embedded selection bounded bytes only,
/// so bare-multisig-stuffed standard txs (20 sigops per OP_CHECKMULTISIG
/// output) could exceed 40k inside the 1.99 MB byte cap.
///
/// This is a standalone header-only port of dashd's counting rules
/// (script/script.cpp CScript::GetSigOpCount + tx_verify.cpp
/// GetLegacySigOpCount / GetP2SHSigOpCount) over raw script bytes, so
/// mempool.hpp does not grow a btclibs CScript link dependency (the
/// btclibs-SCC trap — see mempool_ingest.hpp).
///
/// Counting rules mirrored EXACTLY:
///  - legacy count (fAccurate=false): every scriptSig and every scriptPubKey
///    in the tx; OP_CHECKSIG(VERIFY) = 1, OP_CHECKMULTISIG(VERIFY) = 20
///    (MAX_PUBKEYS_PER_MULTISIG) regardless of the preceding OP_N.
///  - P2SH count (fAccurate=true): when the PREVOUT scriptPubKey is P2SH
///    (OP_HASH160 <20> OP_EQUAL) and the scriptSig is push-only, the LAST
///    pushed datum is the redeemScript; count it with OP_N-aware multisig
///    (OP_N CHECKMULTISIG = N). A non-push scriptSig contributes 0, exactly
///    as CScript::GetSigOpCount(scriptSig) returns 0 there.
///  - malformed script tails (truncated pushdata) stop the scan, exactly as
///    CScript::GetOp fails out of the loop.

#include <cstdint>
#include <cstddef>
#include <vector>

namespace dash {
namespace coin {

/// dashd consensus/consensus.h: MaxBlockSigOps(fDIP0001Active=true)
/// = MAX_BLOCK_SIGOPS_PER_MB(20'000) * MaxBlockSize(2 MB)/1MB = 40'000.
/// DIP-0001 activated on mainnet in 2017; every height this builder can
/// serve is fDIP0001Active.
inline constexpr uint32_t DASH_MAX_BLOCK_SIGOPS = 40'000;

/// dashd node/miner.cpp BlockAssembler::resetBlock(): nBlockSigOps = 100 —
/// the reserve for the coinbase (whose payee/superblock outputs are appended
/// after tx selection). We mirror the same reserve so the selection bound is
/// never looser than the oracle miner's.
inline constexpr uint32_t DASH_COINBASE_SIGOPS_RESERVE = 100;

/// dashd script/script.h MAX_PUBKEYS_PER_MULTISIG.
inline constexpr uint32_t DASH_MAX_PUBKEYS_PER_MULTISIG = 20;

namespace detail {
// Opcode bytes (script/script.h). Only the ones the counter needs.
inline constexpr uint8_t OP_PUSHDATA1          = 0x4c;
inline constexpr uint8_t OP_PUSHDATA2          = 0x4d;
inline constexpr uint8_t OP_PUSHDATA4          = 0x4e;
inline constexpr uint8_t OP_RESERVED           = 0x50;
inline constexpr uint8_t OP_1                  = 0x51;
inline constexpr uint8_t OP_16                 = 0x60;
inline constexpr uint8_t OP_CHECKSIG           = 0xac;
inline constexpr uint8_t OP_CHECKSIGVERIFY     = 0xad;
inline constexpr uint8_t OP_CHECKMULTISIG      = 0xae;
inline constexpr uint8_t OP_CHECKMULTISIGVERIFY= 0xaf;
inline constexpr uint8_t OP_HASH160            = 0xa9;
inline constexpr uint8_t OP_EQUAL              = 0x87;

/// One CScript::GetOp step over raw bytes. Advances `pc`; fills `opcode` and,
/// for pushes, [data_begin, data_end). Returns false on a truncated push
/// (scan must stop, mirroring GetOp's failure).
inline bool get_op(const std::vector<unsigned char>& s, size_t& pc,
                   uint8_t& opcode, size_t& data_begin, size_t& data_end)
{
    data_begin = data_end = 0;
    if (pc >= s.size()) return false;
    opcode = s[pc++];
    if (opcode <= OP_PUSHDATA4) {
        size_t n = 0;
        if (opcode < OP_PUSHDATA1) {
            n = opcode;
        } else if (opcode == OP_PUSHDATA1) {
            if (pc + 1 > s.size()) return false;
            n = s[pc];
            pc += 1;
        } else if (opcode == OP_PUSHDATA2) {
            if (pc + 2 > s.size()) return false;
            n = static_cast<size_t>(s[pc]) | (static_cast<size_t>(s[pc + 1]) << 8);
            pc += 2;
        } else { // OP_PUSHDATA4
            if (pc + 4 > s.size()) return false;
            n = static_cast<size_t>(s[pc])
              | (static_cast<size_t>(s[pc + 1]) << 8)
              | (static_cast<size_t>(s[pc + 2]) << 16)
              | (static_cast<size_t>(s[pc + 3]) << 24);
            pc += 4;
        }
        if (pc + n > s.size()) return false;
        data_begin = pc;
        data_end   = pc + n;
        pc += n;
    }
    return true;
}
} // namespace detail

/// CScript::GetSigOpCount(fAccurate) over raw script bytes.
inline uint32_t count_script_sigops(const std::vector<unsigned char>& script,
                                    bool accurate)
{
    using namespace detail;
    uint32_t n = 0;
    size_t pc = 0, db = 0, de = 0;
    uint8_t opcode = 0;
    uint8_t last_opcode = 0xff; // OP_INVALIDOPCODE
    while (pc < script.size()) {
        if (!get_op(script, pc, opcode, db, de)) break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY) {
            ++n;
        } else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY) {
            if (accurate && last_opcode >= OP_1 && last_opcode <= OP_16)
                n += static_cast<uint32_t>(last_opcode) - (OP_1 - 1); // DecodeOP_N
            else
                n += DASH_MAX_PUBKEYS_PER_MULTISIG;
        }
        last_opcode = opcode;
    }
    return n;
}

/// CScript::IsPayToScriptHash(): exactly OP_HASH160 <20 bytes> OP_EQUAL.
inline bool is_p2sh_script(const std::vector<unsigned char>& script)
{
    return script.size() == 23
        && script[0]  == detail::OP_HASH160
        && script[1]  == 0x14
        && script[22] == detail::OP_EQUAL;
}

/// CScript::GetSigOpCount(scriptSig) P2SH branch: sigops of the redeemScript
/// (the LAST datum a push-only scriptSig pushes), counted fAccurate=true.
/// Returns 0 when the scriptSig contains any non-push opcode or is malformed
/// — byte-exact with dashd (such an input cannot pass P2SH evaluation anyway).
inline uint32_t count_p2sh_sigops(const std::vector<unsigned char>& script_sig)
{
    using namespace detail;
    size_t pc = 0, db = 0, de = 0;
    uint8_t opcode = 0;
    size_t last_db = 0, last_de = 0;
    while (pc < script_sig.size()) {
        if (!get_op(script_sig, pc, opcode, db, de)) return 0;
        if (opcode > OP_16) return 0;
        last_db = db;
        last_de = de;
    }
    std::vector<unsigned char> redeem(script_sig.begin() + last_db,
                                      script_sig.begin() + last_de);
    return count_script_sigops(redeem, /*accurate=*/true);
}

} // namespace coin
} // namespace dash
