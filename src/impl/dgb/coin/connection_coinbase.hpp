// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ============================================================================
// connection_coinbase.hpp — per-connection Stratum coinbase assembler + split.
//
// Builds the gentx (via the gentx_coinbase.hpp SSOT) for the prospective NEXT
// share at a single Stratum connection, then splits it into the Stratum
// coinb1/coinb2 pair around the 8-byte extranonce slot embedded in the
// OP_RETURN ref commitment. The invariant the submit path relies on:
//
//   coinb1 || extranonce1(4) || extranonce2(4) || coinb2  ==  full gentx bytes
//
// c2pool places the per-miner extranonce in the OP_RETURN's last_txout_nonce
// slot (NOT the scriptSig), so the split point is purely positional: the
// 8-byte nonce occupies bytes [N-12, N-4) and the 4-byte locktime is [N-4, N).
// This mirrors frstrtr/p2pool-dgb-scrypt work.py get_work() coinbase framing.
//
// Pure: takes an already-resolved scriptSig, the PPLNS payout outputs, the
// donation pair, and the (ref_hash, last_txout_nonce) computed by the caller's
// ShareTracker seam. No tracker / chain dependency, so it is directly KAT-able
// against the canonical oracle wire (see test/connection_coinbase_test.cpp).
// ============================================================================

#include "gentx_coinbase.hpp"
#include "pplns_payout_split.hpp"   // compute_pplns_payout_split SSOT

#include <core/uint256.hpp>
#include <util/strencodings.h>   // HexStr
#include <btclibs/span.h>        // Span

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dgb::coin
{

// Caller-resolved inputs for one connection's coinbase. payout_outputs are the
// PPLNS (scriptPubKey, value) pairs already in final consensus order (sorted
// asc by amount, asc by script — see share_check.hpp generate_share_transaction
// step 3). segwit_commitment_script present iff this share carries segwit data.
struct ConnCoinbaseInputs
{
    std::vector<unsigned char> coinbase_script;   // scriptSig (BIP34 height + pool tag)
    std::optional<std::vector<unsigned char>> segwit_commitment_script;
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs;
    uint64_t donation_amount{0};
    std::vector<unsigned char> donation_script;
    uint256  ref_hash;                            // p2pool ref_hash (32B)
    uint64_t last_txout_nonce{0};                 // OP_RETURN nonce (extranonce slot)
};

struct ConnCoinbaseParts
{
    std::string   coinb1;   // hex: gentx bytes up to (not incl.) the 8B nonce slot
    std::string   coinb2;   // hex: locktime tail (the 4 bytes after the nonce slot)
    GentxCoinbase gentx;    // full non-witness bytes + txid (nonce slot filled in)
};

// OP_RETURN ref commitment script: 0x6a 0x28 || ref_hash(32 LE) || nonce(8 LE).
// Byte-identical to share_check.hpp's commitment (the verification SSOT).
inline std::vector<unsigned char> build_ref_op_return(const uint256& ref_hash,
                                                      uint64_t last_txout_nonce)
{
    std::vector<unsigned char> s;
    s.reserve(2 + 32 + 8);
    s.push_back(0x6a);                 // OP_RETURN
    s.push_back(0x28);                 // PUSH 40 (32 ref_hash + 8 nonce)
    auto rb = ref_hash.GetChars();     // 32 LE bytes
    s.insert(s.end(), rb.begin(), rb.end());
    for (int i = 0; i < 8; ++i)
        s.push_back(static_cast<unsigned char>((last_txout_nonce >> (8 * i)) & 0xff));
    return s;
}

// Assemble the per-connection coinbase and split it for Stratum.
inline ConnCoinbaseParts build_connection_coinbase_parts(const ConnCoinbaseInputs& in)
{
    auto op_return = build_ref_op_return(in.ref_hash, in.last_txout_nonce);

    GentxCoinbase g = assemble_gentx_coinbase(
        in.coinbase_script,
        in.segwit_commitment_script,
        in.payout_outputs,
        in.donation_amount,
        in.donation_script,
        op_return);

    // Positional split: OP_RETURN is the final vout, so its 8-byte
    // last_txout_nonce is at [N-12, N-4) and the locktime at [N-4, N).
    //   coinb1 = bytes[0, N-12)        (up to & incl. ref_hash)
    //   coinb2 = bytes[N-4, N)         (locktime)
    // The dropped 8 bytes are filled at submit by extranonce1 || extranonce2.
    const auto& b = g.bytes;
    const size_t n = b.size();
    // n is always >= 12 (vin + >=1 vout + op_return(51) + locktime(4)); the
    // op_return alone is 51 bytes, so this holds for every valid assembly.

    ConnCoinbaseParts out;
    out.coinb1 = HexStr(Span<const unsigned char>(b.data(), n - 12));
    out.coinb2 = HexStr(Span<const unsigned char>(b.data() + (n - 4), 4));
    out.gentx  = std::move(g);
    return out;
}


// ============================================================================
// PPLNS-sourced per-connection coinbase (the #328/#329 SSOT bridge).
//
// Instead of pre-resolved payout_outputs/donation_amount, the caller passes the
// raw PPLNS weight map + subsidy and we delegate the amount split to
// compute_pplns_payout_split() -- the SAME helper share_check.hpp
// generate_share_transaction() (the verification path) calls (see #329). The
// per-connection coinbase a miner hashes and the coinbase the share check
// enforces are therefore byte-identical on every payout satoshi BY
// CONSTRUCTION: there is exactly one payout implementation, not two that must
// be kept in agreement. No payout arithmetic lives here -- pure delegation +
// field forwarding into build_connection_coinbase_parts().
// ============================================================================
struct ConnCoinbasePplnsInputs
{
    std::vector<unsigned char> coinbase_script;   // scriptSig (BIP34 height + tag)
    std::optional<std::vector<unsigned char>> segwit_commitment_script;
    // PPLNS weight map + total, exactly as produced by the ShareTracker
    // (share_tracker.hpp get_v36_decayed_cumulative_weights / get_cumulative_weights).
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288  total_weight;
    uint64_t subsidy{0};                          // block subsidy + fees to split
    bool     use_v36_pplns{true};                 // V36 (no finder fee) vs pre-V36
    std::vector<unsigned char> finder_script;     // pre-V36 0.5% finder-fee target
    std::vector<unsigned char> donation_script;
    uint256  ref_hash;                            // p2pool ref_hash (32B)
    uint64_t last_txout_nonce{0};                 // OP_RETURN nonce (extranonce slot)

    // DGB-as-DOGE-parent merged-mining commitment (-DAUX_DOGE=ON path only).
    // The pre-built 44-byte AuxPoW MM tag (magic fabe6d6d || aux_merkle_root32 BE
    // || size4 LE || nonce4 LE) produced by dgb::coin::build_aux_mm_commitment
    // (the #475 SSOT).  When set, it is appended to the coinbase scriptSig at
    // mint so a won DGB block carries the DOGE merged-mining commitment the aux
    // verifier decodes.  DEFAULT nullopt -> coinbase_script is emitted unchanged,
    // so the assembled coinbase is BYTE-IDENTICAL to the standalone-parent build.
    // The producer (main_dgb seam) only ever populates this under #ifdef AUX_DOGE;
    // sourcing a LIVE aux merkle root is the gated DC routing slice, not this one.
    std::optional<std::vector<unsigned char>> aux_mm_commitment;
};

inline ConnCoinbaseParts build_connection_coinbase_from_pplns(const ConnCoinbasePplnsInputs& in)
{
    PplnsPayoutSplit split = compute_pplns_payout_split(
        in.weights, in.total_weight, in.subsidy, in.use_v36_pplns, in.finder_script);

    ConnCoinbaseInputs ci;
    ci.coinbase_script          = in.coinbase_script;
    // Embed-at-mint: append the DGB-as-DOGE-parent MM commitment to the
    // coinbase scriptSig when present.  nullopt (default / standalone parent)
    // leaves coinbase_script byte-identical -- the no-op is structural.
    if (in.aux_mm_commitment)
        ci.coinbase_script.insert(ci.coinbase_script.end(),
                                  in.aux_mm_commitment->begin(),
                                  in.aux_mm_commitment->end());
    ci.segwit_commitment_script = in.segwit_commitment_script;
    ci.payout_outputs           = std::move(split.payout_outputs);
    ci.donation_amount          = split.donation_amount;
    ci.donation_script          = in.donation_script;
    ci.ref_hash                 = in.ref_hash;
    ci.last_txout_nonce         = in.last_txout_nonce;
    return build_connection_coinbase_parts(ci);
}

} // namespace dgb::coin