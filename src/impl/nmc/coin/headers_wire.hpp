// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// NMC (Namecoin) P2P 'headers' message parser — AuxPoW-carrying.
///
/// The shared CoinBroadcaster/NodeP2P 'headers' path yields only the 80-byte
/// base header (RawHeadersParser drops any AuxPoW). Namecoin has been AuxPoW
/// since 2014, so a plain base-header feed admits NOTHING past the activation
/// height — the tip never advances and is_synced() stays false forever
/// (issue #980). This parser recovers the AuxPoW proof: fed the raw 'headers'
/// payload (via NodeP2P::set_raw_headers_sink), it returns each entry as a base
/// BlockHeaderType PLUS the parsed std::optional<AuxPow>, so the host can call
/// add_auxpow_header (proof-verified admission) for merge-mined entries and
/// add_header (own-PoW admission) for plain ones.
///
/// Wire layout per 'headers' entry (Namecoin CBlock header serialization):
///   CPureBlockHeader (80 bytes)       — standard Bitcoin-form header
///   + CAuxPow (variable)              — present iff (version & 0x100) is set
///   + tx_count (CompactSize)          — always 0 in a 'headers' message
/// preceded by a CompactSize count of entries. Mirrors the tolerant contract of
/// doge::coin::parse_doge_headers_message (auxpow_header.hpp): a truncated tail
/// returns what parsed cleanly rather than throwing.
///
/// Per-coin isolation: emits nmc::coin types directly — there is NO ltc->nmc
/// convert anywhere on this path. The shared seam only ever sees plain bytes
/// (the RawHeadersSink signature), so nothing nmc leaks into the ltc tree.

#include "header_chain.hpp"   // nmc::coin::{BlockHeaderType, AuxPow}

#include <core/pack.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace nmc {
namespace coin {

/// Namecoin sets bit 0x100 of the block version when the header carries an
/// AuxPoW proof (the high 16 bits carry the chain id; the low bits the base
/// version). Byte-faithful with Namecoin/Bitcoin auxpow (CPureBlockHeader).
inline bool is_auxpow_version(int64_t version) {
    return (version & 0x100) != 0;
}

/// One parsed 'headers' entry: the 80-byte base header and, iff the version
/// flags AuxPoW, the merge-mining proof that backs it.
struct WireHeader {
    BlockHeaderType        header;
    std::optional<AuxPow>  auxpow;
};

/// Parse a Namecoin P2P 'headers' message payload into (header, optional AuxPoW)
/// entries. Returns entries that parsed cleanly; a truncated tail is dropped
/// (DOGE parity). `data == nullptr` or `len == 0` yields an empty vector.
inline std::vector<WireHeader> parse_nmc_headers_message(const uint8_t* data, size_t len) {
    std::vector<WireHeader> result;
    if (data == nullptr || len == 0)
        return result;

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(data), len));

    uint64_t count = 0;
    try {
        count = ReadCompactSize(ps);
    } catch (const std::exception&) {
        return result;
    }

    // A 'headers' message carries at most 2000; cap the speculative reserve.
    result.reserve(static_cast<size_t>(std::min<uint64_t>(count, 4096)));

    for (uint64_t i = 0; i < count && ps.cursor_size() > 0; ++i) {
        try {
            WireHeader wh;
            ps >> wh.header;                 // 80-byte base header
            if (is_auxpow_version(static_cast<int64_t>(wh.header.m_version))) {
                AuxPow ap;
                ps >> ap;                    // byte-faithful CAuxPow Unserialize
                wh.auxpow = std::move(ap);
            }
            // tx_count (CompactSize) — always 0 in a 'headers' message.
            if (ps.cursor_size() > 0)
                (void)ReadCompactSize(ps);
            result.push_back(std::move(wh));
        } catch (const std::exception&) {
            // Truncated entry — return what parsed cleanly.
            break;
        }
    }
    return result;
}

} // namespace coin
} // namespace nmc
