// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// donation.hpp — Chain-agnostic c2pool donation script (SINGLE SOURCE OF TRUTH).
//
// The donation output receives the rounding remainder from PPLNS payout
// distribution. The script bytes are IDENTICAL across every coin c2pool mines
// (btc/ltc/bch/dgb): they carry no network version byte, and the v36 redeem
// hash160 is uniform. Only the base58 *rendering* of the address differs per
// coin prefix — never the script the coinbase actually commits to.
//
// Because the bytes are coin-invariant, they live here in core/ and every
// per-coin PoolConfig delegates to core::donation::get_donation_script(). The
// previously-duplicated per-coin arrays are removed: the defect was ownership
// living in a per-coin namespace, not the script content (operator FLAG6
// re-scope 2026-06-17 — donation must be bitcoin-agnostic).
//
// Provenance:
//   Pre-V36 (P2PK): forrestv/jtoomim BTC p2pool data.py:68 uncompressed
//     pubkey. Bit-identical across coins (verified 2026-04-28).
//   V36+ (P2SH 1-of-2 multisig): forrestv + frstrtr/c2pool dev key. The 20-byte
//     redeem hash160 (8c627262..8e85) is the shared cross-coin v36 donation
//     target (operator FLAG6 ruling 2026-06-17, option-b).
//

#include <array>
#include <cstdint>
#include <vector>

namespace core::donation
{

// Pre-V36 donation script — P2PK: OP_PUSHBYTES_65 <uncompressed pubkey> OP_CHECKSIG.
inline constexpr std::array<uint8_t, 67> DONATION_SCRIPT = {
    0x41, // OP_PUSHBYTES_65
    0x04, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
    0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
    0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
    0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
    0xd1, 0xb3, 0xd8, 0x09, 0x04, 0x96, 0xb5, 0x32,
    0x56, 0x78, 0x6b, 0xf5, 0xc8, 0x29, 0x32, 0xec,
    0x23, 0xc3, 0xb7, 0x4d, 0x9f, 0x05, 0xa6, 0xf9,
    0x5a, 0x8b, 0x55, 0x29, 0x35, 0x26, 0x56, 0x66,
    0x4b,
    0xac  // OP_CHECKSIG
};

// V36+ donation script — P2SH: OP_HASH160 <hash160(redeem)> OP_EQUAL.
inline constexpr std::array<uint8_t, 23> COMBINED_DONATION_SCRIPT = {
    0xa9, // OP_HASH160
    0x14, // PUSH 20 bytes
    0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
    0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
    0x36, 0xbe, 0x8e, 0x85,
    0x87  // OP_EQUAL
};

// Single-key donation script — P2PKH: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY
// OP_CHECKSIG over hash160 20cb5c22b1e4d5947e5c112c7696b51ad9af3c61. Two users:
//   - DASH: the share donation output (p2pool-dash data.py DONATION_SCRIPT,
//     XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u); impl/dash/share_check.hpp.
//   - every aux-chain coinbase c2pool builds (DOGE under LTC, and under DGB
//     once its payout provider lands; NMC under BTC; the other LTC aux
//     chains): its always-last donation output
//     and the PPLNS remainder, through c2pool::merged::merged_donation_script()
//     (c2pool/merged/merged_donation.hpp). The same bytes on every chain: on
//     DOGE D88Vn6Dyct7DKfVCfR3syHkjyNx9gEyyiv (mainnet) and
//     nXBZW6xtYrZwCe4PhEhLDhM3DFLSd1pa1R (testnet).
// Never a parent-chain (LTC/BTC/DGB/BCH) share donation: get_donation_script()
// below is.
inline constexpr std::array<uint8_t, 25> SINGLE_P2PKH_DONATION_SCRIPT = {
    0x76, // OP_DUP
    0xa9, // OP_HASH160
    0x14, // PUSH 20 bytes
    0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94,
    0x7e, 0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a,
    0xd9, 0xaf, 0x3c, 0x61,
    0x88, // OP_EQUALVERIFY
    0xac  // OP_CHECKSIG
};

// Returns the donation script for a given share version.
// Pre-V36 shares use the P2PK script; V36+ shares use the combined P2SH script.
inline std::vector<unsigned char> get_donation_script(int64_t share_version)
{
    if (share_version >= 36)
        return {COMBINED_DONATION_SCRIPT.begin(), COMBINED_DONATION_SCRIPT.end()};
    return {DONATION_SCRIPT.begin(), DONATION_SCRIPT.end()};
}

} // namespace core::donation