// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// btc::stratum::bip34_height_push — BIP34 height push for the coinbase
// scriptSig, byte-identical to Bitcoin Core's `CScript() << nHeight` (the
// prefix ContextualCheckBlock compares against -> bad-cb-height on mismatch)
// and to the p2pool reference (script.create_push_script, which emits
// OP_1..OP_16 for small ints):
//   h == 0       -> OP_0               (0x00)
//   1 <= h <= 16 -> OP_1..OP_16        (0x51..0x60), NOT a 1-byte data push
//   h >= 17      -> [OP_PUSHBYTES_n][n height bytes, little-endian], n minimal
//                   with the top byte's high bit clear (script-integer
//                   sign-safety -- a set high bit would parse as negative).
// Heights 0..16 only occur on a fresh regtest/testnet chain, but there a
// data-push encoding is a guaranteed bad-cb-height block loss. Mainnet
// heights (>16) are byte-identical to the pre-fix encoding.
// Port of the DGB fix (dgb::coin::bip34_height_push, #1810).

#include <cstdint>
#include <vector>

namespace btc::stratum {

inline std::vector<uint8_t> bip34_height_push(uint32_t h)
{
    if (h == 0)
        return {0x00};                                  // OP_0
    if (h <= 16)
        return {static_cast<uint8_t>(0x50 + h)};        // OP_1..OP_16

    std::vector<uint8_t> enc;
    uint32_t tmp = h;
    while (tmp) {
        enc.push_back(static_cast<uint8_t>(tmp & 0xff));
        tmp >>= 8;
    }
    if (enc.back() & 0x80) enc.push_back(0);            // sign-bit safety pad

    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(enc.size()));   // OP_PUSHBYTES_n
    out.insert(out.end(), enc.begin(), enc.end());
    return out;
}

} // namespace btc::stratum
