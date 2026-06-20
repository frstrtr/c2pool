#pragma once
// ---------------------------------------------------------------------------
// c2pool::dgb::make_header_sample -- embedded-ingest SSOT that builds a
// HeaderSample (coin/header_chain.hpp) from a fully-parsed DigiByte block
// header (coin/block.hpp BlockHeaderType). This is the boundary the embedded
// P2P header-download path crosses to feed HeaderChain::validate_and_append:
// it is the ONE place a wire header becomes the algo-agnostic sample the
// Scrypt-only retarget/continuity walk consumes.
//
// What it populates (each a pure function of the header bytes):
//   * n_version  <- m_version       (drives dgb_header_disposition: Scrypt vs
//                                     continuity vs reject)
//   * n_time     <- m_timestamp     (MTP monotonicity gate + retarget timespan)
//   * target     <- compact_to_target(m_bits)  -- the declared PoW target,
//                   expanded from nBits exactly as DigiByte Core's
//                   arith_uint256::SetCompact (bnTarget). Required: a sample
//                   with target == 0 is rejected by validate_and_append, so an
//                   ingestable sample MUST decode bits here.
//   * block_hash <- sha256d(80-byte header)     -- DGB's block identity hash
//                   (params.hpp block_hash_func == core::pow::sha256d), stored
//                   little-endian via u256::from_le_bytes so that
//                   u256_be_display_hex(block_hash) renders the canonical
//                   big-endian explorer/GBT hash. This is what lights up
//                   HeaderChain::tip_hash() -> previousblockhash in the work
//                   template (previously always nullopt: "0 == not populated").
//   * pow_hash   <- scrypt(80-byte header) for Scrypt-algo headers, else 0.
//                   This is the field validate_and_append's PoW-satisfaction
//                   gate (pow_hash <= target) consumes, and that gate runs only
//                   on the VALIDATE_SCRYPT disposition -- so non-Scrypt
//                   continuity headers leave it 0 (their gate never reads it).
//                   Stored little-endian via from_le_bytes, the SAME u256
//                   convention as target, so the two compare directly. (Lands
//                   the scrypt(header) fill deferred from the #227 skeleton.)
//
// btclibs-bearing: includes core/pow.hpp's Hash (sha256d) and core/pack.hpp, so
// this header is for the FULL build + a btclibs-linking test TU, NOT the
// deliberately btclibs-free header_chain.hpp/dgb_arith256.hpp limited TU.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <span>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/pow.hpp>                     // core::pow::scrypt (80-byte hdr -> uint256)
#include <core/uint256.hpp>

#include <impl/dgb/coin/block.hpp>          // dgb::coin::BlockHeaderType
#include <impl/dgb/coin/dgb_block_algo.hpp> // dgb::coin::is_scrypt_header
#include <impl/dgb/coin/header_chain.hpp>   // c2pool::dgb::HeaderSample, u256

namespace c2pool::dgb {

// Expand a compact "nBits" difficulty target into a full 256-bit value,
// mirroring DigiByte Core arith_uint256::SetCompact (Bitcoin's bnTarget
// decode): the high byte is a base-256 exponent, the low 3 bytes the mantissa.
//
//   target = mantissa * 256^(exponent - 3)
//
// The sign bit (0x00800000) and the overflow/negative flags SetCompact sets
// are not reproduced: a block header's declared target is never negative, and
// an over-pow_limit mantissa is caught by validate_and_append's pow_limit
// ceiling -- so the numeric expansion is all the ingest path needs. The
// multiply runs through u256::mul_u64(256), which truncates at 256 bits exactly
// as arith_uint256 does, so a pathological huge exponent saturates rather than
// wrapping into a small value.
inline u256 compact_to_target(uint32_t bits)
{
    const uint32_t mantissa = bits & 0x007fffffu;
    const uint32_t exponent = bits >> 24;

    u256 target = u256::from_u64(mantissa);
    if (exponent <= 3) {
        for (uint32_t i = 0, n = 3 - exponent; i < n; ++i)
            target = target.div_u64(256);
    } else {
        for (uint32_t i = 0, n = exponent - 3; i < n; ++i)
            target = target.mul_u64(256);
    }
    return target;
}

// Build the ingestable HeaderSample from a parsed block header. Pure function
// of the header bytes -- no chain state, no daemon. See file header for the
// per-field rationale; pow_hash is intentionally left 0 (scrypt digest lands
// at the daemon-port boundary).
inline HeaderSample make_header_sample(const ::dgb::coin::BlockHeaderType& h)
{
    HeaderSample s;
    s.n_version = static_cast<int32_t>(h.m_version);
    s.n_time    = static_cast<int64_t>(h.m_timestamp);
    s.target    = compact_to_target(h.m_bits);

    // Serialize once: the block-identity hash and the Scrypt PoW digest are
    // both pure functions of the same canonical 80-byte header.
    auto packed = pack(h);
    auto header_span = packed.get_span();

    // sha256d over the canonical 80-byte serialization (params.hpp block hash
    // func). uint256 stores the digest little-endian; from_le_bytes reads it in
    // the SAME order so u256_be_display_hex round-trips to GetHex().
    uint256 id = Hash(header_span);
    s.block_hash = u256::from_le_bytes(
        reinterpret_cast<const unsigned char*>(id.begin()));

    // pow_hash = scrypt(header) for Scrypt-algo headers ONLY. The satisfaction
    // gate (pow_hash <= target) runs solely on the VALIDATE_SCRYPT disposition;
    // non-Scrypt continuity (and reject-disposition) headers leave pow_hash == 0
    // -- their gate never reads it, and scrypt over a non-Scrypt header would be
    // a meaningless cycle. from_le_bytes gives the SAME u256 shape as target so
    // the gate compares them directly.
    if (::dgb::coin::is_scrypt_header(s.n_version)) {
        uint256 ph = core::pow::scrypt(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(header_span.data()),
            header_span.size()));
        s.pow_hash = u256::from_le_bytes(
            reinterpret_cast<const unsigned char*>(ph.begin()));
    } else {
        s.pow_hash = 0;
    }
    return s;
}

} // namespace c2pool::dgb
