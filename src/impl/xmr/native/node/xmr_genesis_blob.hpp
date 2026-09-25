// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/impl/xmr/native/node/xmr_genesis_blob.hpp
//
// THE TRUST ROOT, WITHOUT A PEER TO ASK FOR IT.
//
// The genesis path in xmr_chain_boot.hpp seeds row 0 from the genesis BLOB and
// derives every number in the row from this repository's own parser. It gets
// that blob over levin, because a node that has a peer may as well ask one.
//
// A node with NO peer cannot. That is not an edge case: it is the solo
// configuration -- one process, its own chain, its own template, its own
// hashing, its own find -- and there is no network in it to ask. So the blob is
// assembled here instead, from the two constants monerod itself assembles it
// from:
//
//   * GENESIS_TX -- one coinbase transaction, byte-identical on all four
//     networks (cryptonote::config::GENESIS_TX in cryptonote_config.h). The
//     same literal is already in this tree twice, in the O-2 live-submit
//     selfcheck and in the M0 node KAT's mainnet genesis fixture.
//   * GENESIS_NONCE -- 10000 mainnet, 10001 testnet. A fakechain (monerod
//     --regtest) daemon carries the MAINNET network id and the MAINNET genesis
//     on the wire, which is the whole reason NativeNet keeps "which wire" and
//     "which hard-fork table" as two separate facts, so regtest reuses the
//     mainnet nonce here.
//
// STAGENET IS DELIBERATELY ABSENT, and that is a finding rather than an
// omission. Assembling the stagenet blob from this same GENESIS_TX under nonce
// 10002 -- the value monerod's stagenet config carries -- produces a block
// whose id is NOT the STAGENET_GENESIS pinned in p2p/chain_seeds.hpp, while the
// identical construction reproduces the mainnet and testnet pins exactly (see
// v37_xmr_daemonless_selfmine_kat, suite A). One of those two constants is
// therefore wrong, and this header is not the place to decide which: the pinned
// id is a LIVE wire constant -- it terminates every locator we send to a
// stagenet peer, and the node is running against stagenet today -- so changing
// it on the strength of a local derivation would be trading a checkable
// mismatch for an unnoticed one. So stagenet gets NO local blob, the only
// caller (regtest-only --native-solo) never needs one, and the mismatch is left
// where somebody can see it.
//
// The rest of the header is fixed by the genesis block itself: major 1, minor
// 0, timestamp 0, prev_id all-zero, no transactions.
//
// NOTHING HERE IS TRUSTED. These bytes are an INPUT to the same
// genesis_row_from_blob() gate the levin path feeds: the id is recomputed from
// the blob and compared against the per-network pinned genesis id in
// p2p/chain_seeds.hpp, and a mismatch is a refusal, not a warning. A wrong
// constant in this file cannot walk the node onto a chain of its author's
// choosing -- it can only make a solo boot fail, loudly, at start.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. No
// consensus digest, no src/sharechain/v37.
//
// Header-only. STL only.
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/chain_seeds.hpp"

namespace c2pool::xmr::native::rt {

namespace levinns = ::c2pool::xmr::native::levin;

// cryptonote::config::GENESIS_TX -- the one coinbase transaction of block 0,
// the same bytes on mainnet, testnet, stagenet and fakechain.
inline constexpr const char* GENESIS_TX_HEX =
    "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f51"
    "42ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a2"
    "8e9d0bc890d1";

// cryptonote::config::GENESIS_NONCE, per network. Serialised into the header as
// a raw little-endian uint32 (block_header uses FIELD(nonce), not VARINT_FIELD).
//
// ZERO means "this network has no verified local construction" -- see the
// stagenet note in the header comment -- and local_genesis_blob() turns that
// into an empty blob, which every caller reports as a boot refusal.
inline constexpr std::uint32_t genesis_nonce(levinns::XmrNet net) noexcept {
    switch (net) {
        case levinns::XmrNet::Testnet:  return 10001;
        case levinns::XmrNet::Stagenet: return 0;
        case levinns::XmrNet::Mainnet:  break;
    }
    return 10000;
}

namespace detail {

inline int genesis_hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Returns an EMPTY vector on malformed input; every caller treats that as a
// refusal, so a typo in the literal above cannot become a short blob that
// happens to parse.
inline std::vector<std::uint8_t> genesis_bytes_from_hex(const char* hex) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; hex[i] != '\0'; i += 2) {
        if (hex[i + 1] == '\0') return {};
        const int hi = genesis_hex_nibble(hex[i]);
        const int lo = genesis_hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

} // namespace detail

// ---------------------------------------------------------------------------
// The complete serialised genesis block of `net`, byte-for-byte what a peer
// would have answered a NOTIFY_REQUEST_GET_OBJECTS for the pinned genesis id
// with. Empty means this network has no verified local construction (stagenet,
// today) or that the literals above are malformed -- every caller reports
// either as a boot refusal, never as a blob it will try anyway.
// ---------------------------------------------------------------------------
inline std::vector<std::uint8_t> local_genesis_blob(levinns::XmrNet net) {
    const std::uint32_t nonce = genesis_nonce(net);
    if (nonce == 0) return {};   // no verified construction for this network
    const std::vector<std::uint8_t> tx = detail::genesis_bytes_from_hex(GENESIS_TX_HEX);
    if (tx.empty()) return {};

    std::vector<std::uint8_t> blob;
    blob.reserve(1 + 1 + 1 + 32 + 4 + tx.size() + 1);
    blob.push_back(0x01);                 // varint major_version = 1
    blob.push_back(0x00);                 // varint minor_version = 0
    blob.push_back(0x00);                 // varint timestamp     = 0
    blob.insert(blob.end(), 32, 0x00);    // prev_id              = 0
    for (int i = 0; i < 4; ++i)           // raw LE uint32 nonce
        blob.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));
    blob.insert(blob.end(), tx.begin(), tx.end());
    blob.push_back(0x00);                 // varint tx_hashes count = 0
    return blob;
}

} // namespace c2pool::xmr::native::rt
