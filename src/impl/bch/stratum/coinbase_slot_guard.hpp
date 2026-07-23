// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::stratum -- structural guard on the coinb1 / extranonce seam.
//
// A Stratum job hands the miner (coinb1, coinb2) and the miner builds
//
//     coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
//
// so the extranonce is spliced at whatever byte offset coinb1 happens to end
// at. That is only a valid transaction if the seam lands INSIDE a script that
// has room for it. On BCH the extranonce rides the tail of the last output's
// OP_RETURN commitment: a 42-byte script `OP_RETURN PUSH_40 <32-byte reference
// hash> <8-byte nonce>` whose final 8 bytes are exactly the extranonce, so
// coinb1 stops 8 bytes short of the script's declared length and the miner
// completes it.
//
// If the commitment output is ever suppressed, coinb1 instead terminates right
// after the output-count varint and the extranonce lands between the output
// vector and the locktime. The result is a transaction the miner hashed but
// nobody can decode -- the recomputed transaction root never matches the solved
// header, and every won block is rejected `bad-txnmrklroot`. That is the G2
// zero-blocks failure (62-byte coinb1 ending in an output count of zero; ~774k
// accepted solutions, no blocks).
//
// coinb1_ends_in_commitment_slot() is the machine-checkable statement of the
// invariant. It fully parses coinb1 as a truncated BCH generation transaction
// and returns true only when the seam is the 8-byte tail of a real OP_RETURN
// commitment output.
//
// Per-coin isolation: src/impl/bch/ ONLY. p2pool-merged-v36 SURFACE: NONE --
// this inspects the job wire split, not the share format or the coinbase's
// consensus meaning.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bch
{
namespace stratum
{

/// Byte layout of the BCH commitment output that carries the extranonce.
inline constexpr uint8_t  kCommitmentScriptLen  = 0x2a;  ///< 42 bytes
inline constexpr uint8_t  kOpReturn             = 0x6a;
inline constexpr uint8_t  kPush40               = 0x28;
inline constexpr size_t   kExtranonceBytes      = 8;     ///< en1 (4) + en2 (4)
/// What must still be present in coinb1 for the final output: 8-byte value +
/// 1-byte script length + (42 - 8) bytes of the script.
inline constexpr size_t   kCommitmentTailBytes  =
    8 + 1 + (static_cast<size_t>(kCommitmentScriptLen) - kExtranonceBytes);

namespace detail
{

/// Minimal CompactSize reader. Returns false on truncation or a value that
/// cannot be a sane count/length for a coinbase.
inline bool read_varint(const std::vector<uint8_t>& b, size_t& pos, uint64_t& out)
{
    if (pos >= b.size()) return false;
    const uint8_t first = b[pos++];
    if (first < 0xfd) { out = first; return true; }
    size_t n = (first == 0xfd) ? 2 : (first == 0xfe) ? 4 : 8;
    if (pos + n > b.size()) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(b[pos + i]) << (8 * i);
    pos += n;
    out = v;
    return true;
}

} // namespace detail

/// True iff `coinb1` is a generation transaction truncated EXACTLY at the
/// 8-byte extranonce slot inside a final OP_RETURN commitment output.
///
/// Checks, in order:
///   * 4-byte version, exactly one input, 32-byte null prevout hash;
///   * a scriptSig whose declared length is present in full;
///   * 4-byte sequence;
///   * an output count of AT LEAST ONE (a zero-output generation transaction is
///     the G2 failure shape and is rejected here);
///   * every output but the last fully present; and
///   * the last output present up to -- and only up to -- its extranonce slot:
///     value, script length 0x2a, then `OP_RETURN PUSH_40` and 32 bytes, with
///     the trailing 8 bytes absent because the miner supplies them.
inline bool coinb1_ends_in_commitment_slot(const std::vector<uint8_t>& coinb1)
{
    size_t pos = 0;

    if (coinb1.size() < 4) return false;
    pos += 4;                                     // tx version

    uint64_t vin_count = 0;
    if (!detail::read_varint(coinb1, pos, vin_count)) return false;
    if (vin_count != 1) return false;             // coinbase: exactly one input

    if (pos + 36 > coinb1.size()) return false;
    for (size_t i = 0; i < 32; ++i)
        if (coinb1[pos + i] != 0x00) return false; // null prevout hash
    pos += 36;                                     // prevout hash + index

    uint64_t sslen = 0;
    if (!detail::read_varint(coinb1, pos, sslen)) return false;
    if (sslen > 100) return false;                 // consensus scriptSig cap
    if (pos + sslen + 4 > coinb1.size()) return false;
    pos += static_cast<size_t>(sslen) + 4;         // scriptSig + sequence

    uint64_t out_count = 0;
    if (!detail::read_varint(coinb1, pos, out_count)) return false;
    if (out_count == 0) return false;              // <-- the G2 signature

    // All outputs except the last must be complete.
    for (uint64_t i = 0; i + 1 < out_count; ++i) {
        if (pos + 8 > coinb1.size()) return false;
        pos += 8;                                  // value
        uint64_t slen = 0;
        if (!detail::read_varint(coinb1, pos, slen)) return false;
        if (pos + slen > coinb1.size()) return false;
        pos += static_cast<size_t>(slen);
    }

    // The last output must be the commitment, truncated at the extranonce slot.
    if (coinb1.size() - pos != kCommitmentTailBytes) return false;
    pos += 8;                                      // value (0 sats)
    if (coinb1[pos++] != kCommitmentScriptLen) return false;
    if (coinb1[pos++] != kOpReturn) return false;
    if (coinb1[pos++] != kPush40) return false;

    // Remaining bytes are the 32-byte reference hash; the 8-byte nonce slot is
    // deliberately absent -- that is the seam the extranonce fills.
    return (coinb1.size() - pos) == 32;
}

} // namespace stratum
} // namespace bch
