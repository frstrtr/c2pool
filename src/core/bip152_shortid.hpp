// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
/// BIP 152 short transaction ids (bitcoin/bitcoin blockencodings.cpp
/// CBlockHeaderAndShortTxIDs::FillShortTxIDSelector / GetShortID).
///
/// One derivation for every coin layer that relays compact blocks. Each layer
/// keeps its own wire types and calls these from CompactBlock::GetSipHashKeys.
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/siphash.h>
#include <cstdint>
#include <utility>

namespace bip152 {

/// k0/k1 are the first two little-endian 64-bit words of a SINGLE SHA256 over
/// the serialized header followed by the nonce (u64 LE). No double hash, no XOR.
template <typename Header>
inline std::pair<uint64_t, uint64_t> siphash_keys(const Header& header, uint64_t nonce)
{
    PackStream ps;
    ps << header;
    ps << nonce;
    auto sp = ps.get_span();
    uint256 h;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(sp.data()), sp.size())
        .Finalize(h.data());
    return {h.GetUint64(0), h.GetUint64(1)};
}

/// 48-bit short id of a txid (v1) or wtxid (v2).
inline uint64_t short_id(uint64_t k0, uint64_t k1, const uint256& id)
{
    return SipHashUint256(k0, k1, id) & 0xFFFFFFFFFFFFULL;
}

} // namespace bip152
