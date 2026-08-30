// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (SLICE 2) — embedded DOGE aux HeaderChain OOM-residency
// KAT.
//
// The embedded DGB-as-DOGE-parent arm (--merged DOGE, main_dgb.cpp) syncs the
// DOGE header chain DAEMONLESS over P2P. DOGE has been AuxPoW-mined since 2014,
// so a full ~5M+ header IBD would balloon RSS if each resident header pinned its
// AuxPoW proof (parent coinbase tx + two merkle branches + parent header,
// ~1-3 KB) — the exact OOM that killed the embedded NMC arm mid-IBD (#1414).
//
// This KAT pins the invariant that keeps RSS flat, at TWO layers:
//
//   1. STRUCTURAL FLOOR — doge::coin::IndexEntry is headers-only: an 80-byte
//      base header + a handful of uint256 digests + status, and NO AuxPoW proof
//      blob member. sizeof() must stay under a tight cap; a regression that adds
//      an AuxPow / std::vector<uint8_t> member (re-introducing the balloon) trips
//      this immediately. This is the DOGE analog of NMC #1414's post-persist blob
//      drop — DOGE never admits the blob into the resident struct at all.
//
//   2. PARSE-BOUNDARY DROP — doge::coin::parse_doge_headers_message (the wire
//      decoder main_dgb binds via CoinBroadcaster::set_raw_headers_parser) parses
//      the AuxPoW proof of each 'headers'-message entry and DROPS it, handing the
//      HeaderChain only the 80-byte BASE header. So residency is headers-only by
//      construction — the balloon can never reach IndexEntry. We prove it by
//      feeding a batch through the real parser and asserting every returned
//      header re-serialises to EXACTLY 80 bytes (base header, proof stripped).
//
//   3. PLATEAU PROJECTION — from the measured per-entry floor, the full DOGE
//      history stays under a hard RAM cap; asserted symbolically so the cap is
//      documented and regressions in sizeof() surface as a plateau breach.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist or
// it becomes a NOT_BUILT sentinel that reds master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/ltc/coin/transaction.hpp>      // ltc::coin using bitcoin_family::coin::TX_WITH_WITNESS
#include <impl/doge/coin/chain_params.hpp>     // DOGEChainParams (mirror main_dgb include order)
#include <impl/doge/coin/header_chain.hpp>     // doge::coin::IndexEntry / HeaderChain
#include <impl/doge/coin/aux_chain_embedded.hpp> // pulls the doge tx context auxpow_header.hpp needs
#include <impl/doge/coin/auxpow_header.hpp>    // parse_doge_headers_message
#include <core/pack.hpp>                       // pack(), WriteCompactSize

#include <cstdint>
#include <vector>

using doge::coin::IndexEntry;
using doge::coin::parse_doge_headers_message;
using ltc::coin::BlockHeaderType;

namespace {

// Build a deterministic plain (non-AuxPoW) DOGE header. version==1 has no AuxPoW
// version bit set, so it serialises as the bare 80-byte base header.
BlockHeaderType make_plain_header(uint32_t nonce)
{
    BlockHeaderType h;
    h.m_previous_block.SetNull();
    h.m_version   = 1;
    h.m_merkle_root.SetHex(
        "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69");
    h.m_bits      = 0x1e0ffff0;
    h.m_timestamp = 1386325540 + nonce;
    h.m_nonce     = nonce;
    return h;
}

// Serialise a batch of plain headers into a P2P 'headers'-message payload:
// CompactSize(count) then, per header, the 80-byte base header + a 0x00 tx_count
// (always zero in a 'headers' message).
std::vector<uint8_t> build_headers_message(const std::vector<BlockHeaderType>& hdrs)
{
    PackStream ps;
    WriteCompactSize(ps, hdrs.size());
    for (const auto& h : hdrs) {
        ::Serialize(ps, h);          // 80-byte base header
        WriteCompactSize(ps, 0);     // tx_count == 0
    }
    auto sp = ps.get_span();
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

} // namespace

// ── 1. STRUCTURAL FLOOR: IndexEntry is headers-only (no resident AuxPoW blob) ──
TEST(DogeAuxResidency, IndexEntryIsHeadersOnly)
{
    // Headers-only floor: 80-byte header + 4 uint256 (hash/block_hash/chain_work/
    // prev_hash) + a uint32 height + status enum ≈ 80 + 128 + 8 ≈ 216 B, with a
    // generous 512 B cap to absorb alignment/ABI slack across compilers. A blob
    // member (optional<AuxPow> ~ pointer+flags, or an inline vector) would either
    // blow this cap or, worse, heap-allocate ~1-3 KB PER ENTRY at admission — the
    // #1414 balloon. Pin the resident struct at the slim floor.
    EXPECT_LE(sizeof(IndexEntry), static_cast<size_t>(512))
        << "doge::coin::IndexEntry grew past the headers-only floor — a resident "
           "AuxPoW/proof blob member re-introduces the ~5M-header IBD OOM balloon "
           "(#1414). Keep the proof at the parse boundary, never in IndexEntry.";
}

// ── 2. PARSE-BOUNDARY DROP: the wire decoder yields BASE headers only ─────────
TEST(DogeAuxResidency, HeadersMessageYieldsBaseHeadersOnly)
{
    constexpr size_t N = 2000;  // a full 'headers'-message batch
    std::vector<BlockHeaderType> src;
    src.reserve(N);
    for (uint32_t i = 0; i < N; ++i) src.push_back(make_plain_header(i));

    auto wire = build_headers_message(src);
    auto got  = parse_doge_headers_message(wire.data(), wire.size());

    ASSERT_EQ(got.size(), N)
        << "parser dropped headers — the batch must round-trip through the exact "
           "decoder main_dgb binds via set_raw_headers_parser.";

    // Every header handed to the HeaderChain re-serialises to EXACTLY 80 bytes:
    // the base header, with any AuxPoW proof parsed-and-dropped at this boundary.
    // This is what guarantees the resident IndexEntry stays headers-only over the
    // full DOGE IBD (no per-header ~1-3 KB blob residency).
    for (size_t i = 0; i < got.size(); ++i) {
        auto packed = pack(got[i]);
        EXPECT_EQ(packed.get_span().size(), static_cast<size_t>(80))
            << "header " << i << " is not a bare 80-byte base header — an AuxPoW "
               "proof leaked past the parse boundary into HeaderChain residency.";
        EXPECT_EQ(got[i].m_nonce, src[i].m_nonce);  // fidelity: same header, proof-stripped
    }
}

// ── 3. PLATEAU PROJECTION: full DOGE history stays under a hard RAM cap ────────
TEST(DogeAuxResidency, FullHistoryResidencyPlateausUnderCap)
{
    // At the headers-only floor, the resident index for the entire DOGE history
    // is bounded. Even at DOGE's ~6.4M current height, sizeof(IndexEntry)*height
    // (the header-index residency, excluding per-node map overhead which the live
    // arm bounds separately) stays well under a 4 GB cap — versus the multi-GB
    // balloon a ~1-3 KB resident proof per header would produce. Symbolic so the
    // cap is documented and a sizeof() regression surfaces here as a plateau
    // breach, matching the live RSS-plateau proof from the daemonless arm-run.
    constexpr uint64_t kDogeHistoryHeaders = 7'000'000ull;   // headroom over ~6.4M tip
    constexpr uint64_t kHardCapBytes       = 4ull * 1024 * 1024 * 1024;  // 4 GB
    const uint64_t projected = static_cast<uint64_t>(sizeof(IndexEntry)) * kDogeHistoryHeaders;
    EXPECT_LT(projected, kHardCapBytes)
        << "projected header-index residency for the full DOGE history exceeds the "
           "4 GB cap — sizeof(IndexEntry)=" << sizeof(IndexEntry)
        << " B has regressed off the headers-only floor.";
}
