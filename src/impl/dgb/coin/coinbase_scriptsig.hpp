// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ============================================================================
// coinbase_scriptsig.hpp — SSOT for the DGB production coinbase scriptSig.
//
// The p2pool/c2pool per-connection coinbase carries a scriptSig of the form:
//
//     [BIP34 minimally-encoded height push][/c2pool-dgb/ pool-tag push]
//
// which is what every other lane already emits (LTC `/c2pool/`, BTC
// `/c2pool-btc/`, BCH `/c2pool-bch/`, DASH `/P2Pool-DASH/c2pool/`). DGB was the
// odd one out (#902): the production per-connection coinbase left the scriptSig
// EMPTY because main_dgb never populated ConnPplnsAssemblyInputs::coinbase_script.
// An empty scriptSig has no BIP34 height push, so a won DGB block is a
// `bad-cb-height` rejection the moment the mint seam is bound (#884) and DGB
// starts producing production coinbases. This header is the ONE place that
// scriptSig is built, so the ref-preimage commitment (WorkRefHashInputs
// ::coinbase_scriptSig) and the emitted connection coinbase (ConnPplnsAssembly
// Inputs::coinbase_script) are populated from the SAME bytes and can never
// diverge (a divergence would self-reject our own shares — the #901 finding).
//
// Pure: no tracker/chain handle, so it is directly KAT-able against a
// hand-computed vector (see test/connection_coinbase_test.cpp).
// ============================================================================

#include <cstdint>
#include <string_view>
#include <vector>

namespace dgb::coin
{

// The DGB pool tag stamped into the coinbase scriptSig. Mirrors the per-lane
// convention (LTC `/c2pool/`, BTC `/c2pool-btc/`, BCH `/c2pool-bch/`).
inline constexpr std::string_view DGB_POOL_TAG = "/c2pool-dgb/";

// BIP34 minimally-encoded height push for the coinbase scriptSig.
// Returns [OP_PUSHBYTES_n][n height bytes, little-endian], where n is the
// smallest byte count that encodes the height with the high bit of the top
// byte clear (script-integer sign-safety — a set high bit would be parsed as a
// negative number). Byte-identical to btc::stratum::bip34_height_push.
inline std::vector<unsigned char> bip34_height_push(uint32_t h)
{
    std::vector<unsigned char> enc;
    uint32_t tmp = h;
    while (tmp) {
        enc.push_back(static_cast<unsigned char>(tmp & 0xff));
        tmp >>= 8;
    }
    if (enc.empty())        enc.push_back(0);       // height 0 -> single 0x00
    if (enc.back() & 0x80)  enc.push_back(0);       // sign-bit safety pad

    std::vector<unsigned char> out;
    out.reserve(1 + enc.size());
    out.push_back(static_cast<unsigned char>(enc.size()));  // OP_PUSHBYTES_n
    out.insert(out.end(), enc.begin(), enc.end());
    return out;
}

// Build the full production coinbase scriptSig for the block at
// `next_block_height` (the coin block the next share builds on top of, i.e.
// dgb::coin::HeaderChain::next_block_height()). Layout:
//   [BIP34 height push] || [1-byte push opcode = tag length] || DGB_POOL_TAG
// The tag is a bare data push (opcode == length for 1..75 bytes), matching the
// btc lane. Result is a valid coinbase scriptSig (well under the 100-byte
// consensus cap and above the 2-byte floor share_init_verify enforces).
inline std::vector<unsigned char> build_coinbase_scriptsig(uint32_t next_block_height)
{
    std::vector<unsigned char> s = bip34_height_push(next_block_height);
    // Bare data push: for 1..75 bytes the push opcode IS the length.
    if (!DGB_POOL_TAG.empty() && DGB_POOL_TAG.size() < 76) {
        s.push_back(static_cast<unsigned char>(DGB_POOL_TAG.size()));
        s.insert(s.end(), DGB_POOL_TAG.begin(), DGB_POOL_TAG.end());
    }
    return s;
}

} // namespace dgb::coin
