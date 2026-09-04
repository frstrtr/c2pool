#pragma once
// V37 Track A2 / W2 — RDWR receipt model + PoW recompute + work narrowing.
// CONSUMER-tree code (src/c2pool/v37/), alongside the W0 V37Engine shell. The
// pure header-only consensus module (src/sharechain/v37/) is NOT touched here
// except the one owed, digest-neutral L0F_RECEIPT constant (v37_lane.hpp).
//
// Spec: /home/ubuntu/v37-work/v37-a2-w2-ingestion-spec.md §2 (the receipt type
// and its RDWR envelope) and §4.1 (the credit basis), and the KAT plan §2
// (/home/ubuntu/v37-work/v37-a2-w2-kat-plan.md). Reference model reproduced
// bit-for-bit: proto/w2-rdwr-kat/harness/rdwr_ref.py, golden stamp
//   7ac46235e65022ed69afe426f5bf5f8767207ec201050b10e36b7106658d8b51.
//
// This slice ships the SYNTHETIC receipt (the wire packing / info_digest
// minimalization is SF-OQ1, the integrator's — W2 depends only on the field
// SET and its binding meaning, not the byte layout): a header-shaped preimage
// whose real sha256d PoW commits the RDWR 4-tuple of spec §2.1
//   (chain_id, payout-descriptor identity, recent mainchain block hash,
//    miner's previous on-chain share hash)
// so every binding check is stateless against committed bytes and tampering
// the preimage really breaks the PoW.
//
// stdlib-only (v37_hash.hpp + the C++20 standard library), so the W2 admission
// path is unit-testable without Boost/gtest, exactly like the W0/W1 suites.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // bytes32, sha256, sha256d
#include <sharechain/v37/v37_lane.hpp>   // u64, L0F_RECEIPT (the owed constant)
#include <sharechain/v37/v37_descriptor.hpp>  // PayoutDescriptor

namespace c2pool::v37n {

using ::v37::bytes32;
using ::v37::sha256d;
using u64 = std::uint64_t;

// ── W2-layer consensus parameters ─────────────────────────────────────────
// KP-F1 (KAT plan §7): N_CTX and R_MAX are NOT LaneParams fields. The shipped
// LaneParams is {window, c0, rollup, level_caps, half_life, journal_depth} —
// adding N_CTX/R_MAX to that header leaf WOULD change the consensus digest
// (the header leaf hashes geometry). So they live HERE, as W2-layer consensus
// params (values from docs/c2pool-v37-share-format.md §7), never baked into the
// lane header leaf. FLAG (dispatch): whether these must become digest-committed
// LaneParams (a NON-digest-neutral header change, unlike L0F_RECEIPT) is an
// open integrator question; W2 does not silently commit them.
constexpr u64           W2_N_CTX           = 2;              // context window bins
constexpr u64           W2_DEDUP_RETENTION = W2_N_CTX + 2;   // §5 retention horizon
constexpr std::uint32_t W2_R_MAX           = 4;              // receipts per carrier

// L0F_RECEIPT annotation bit — the header symbol (this PR's owed one-liner,
// v37_lane.hpp). Named here so the emitter and tests share one definition.
constexpr std::uint32_t W2_L0F_RECEIPT = ::v37::L0F_RECEIPT;
constexpr std::uint32_t W2_CARRIER_FLAGS = 0x00;
static_assert(W2_L0F_RECEIPT == 0x04,
              "W2 spec §6 pins the receipt bit to the one free low bit");

// ── the consensus retarget schedule (share target per origin bin) ──────────
// Reference convention: a target is expressed as a leading-zero-bit count `lz`
// (the compact "bits" field of the synthetic header); the consensus target for
// a bin is easy below the retarget boundary, one bit harder at/after it.
constexpr u64      W2_RETARGET_BIN = 1000;
constexpr unsigned W2_LZ_EASY      = 8;
constexpr unsigned W2_LZ_HARD      = 9;

inline unsigned consensus_lz(u64 bin_h) {
    return bin_h >= W2_RETARGET_BIN ? W2_LZ_HARD : W2_LZ_EASY;
}

// ── work(target) — the difficulty-derived expected-attempts value ──────────
// For a leading-zero-bit target `lz`, work(T) = 2^256/(T+1) = 2^lz exactly (a
// target of `lz` leading zeros then all-ones has T+1 = 2^(256-lz)). This is the
// value the lane wants as u64 w_raw. KP-F2 (KAT plan §7): the real v36 helper
// chain::target_to_average_attempts yields a uint288; narrowing it to u64 is
// UNDEFINED if done naively. We SATURATE (clamp to UINT64_MAX), never silently
// truncate/wrap — the discipline the #859 fix established. lz >= 64 overflows a
// u64 and is clamped.
inline u64 work_of_lz(unsigned lz) {
    if (lz >= 64) return UINT64_MAX;          // saturate, never wrap (KP-F2/#859)
    return u64(1) << lz;
}

// Leading-zero BITS of a 32-byte big-endian hash (b[0] is the most significant
// byte). Mirrors rdwr_ref.leading_zero_bits exactly.
inline unsigned leading_zero_bits(const bytes32& b) {
    unsigned n = 0;
    for (std::uint8_t byte : b) {
        if (byte == 0) { n += 8; continue; }
        for (int k = 7; k >= 0; --k) {
            if (byte & (1u << k)) return n;
            ++n;
        }
        break;
    }
    return n;
}

// ── the full-256-bit target narrowing (KP-F2, W2's own pure function) ──────
// floor(2^256 / (T+1)) narrowed to u64 WITH SATURATION. This is the exact,
// stdlib-only analogue of chain::target_to_average_attempts (uint288) followed
// by the safe narrow. Peers MUST narrow identically — it is consensus-relevant.
// Unit-tested to (a) agree with work_of_lz on leading-zero-bit targets and
// (b) clamp (never wrap) when the attempt count exceeds u64.
inline u64 work_from_target(const bytes32& target_be) {
    // Is T all-ones (2^256-1)?  Then T+1 = 2^256 and 2^256/2^256 = 1.
    bool all_ones = true;
    for (std::uint8_t x : target_be) if (x != 0xff) { all_ones = false; break; }
    if (all_ones) return 1;

    // D = T + 1 as five little-endian 64-bit limbs (limb[0] least significant).
    // T <= 2^256-2 here, so D fits in the low four limbs; the 5th limb gives
    // the shift-in headroom the long division needs.
    std::array<u64, 5> D{}, R{}, Q{};
    for (int limb = 0; limb < 4; ++limb) {
        u64 v = 0;
        for (int byte = 0; byte < 8; ++byte) {
            // big-endian: most significant byte is target_be[0]
            int idx = 31 - (limb * 8 + byte);
            v |= u64(target_be[idx]) << (8 * byte);
        }
        D[limb] = v;
    }
    // +1
    for (int i = 0; i < 5; ++i) { if (++D[i] != 0) break; }

    auto shl1 = [](std::array<u64, 5>& a) {
        u64 carry = 0;
        for (int i = 0; i < 5; ++i) {
            u64 nc = a[i] >> 63;
            a[i] = (a[i] << 1) | carry;
            carry = nc;
        }
    };
    auto ge = [](const std::array<u64, 5>& a, const std::array<u64, 5>& b) {
        for (int i = 4; i >= 0; --i)
            if (a[i] != b[i]) return a[i] > b[i];
        return true;  // equal
    };
    auto sub = [](std::array<u64, 5>& a, const std::array<u64, 5>& b) {
        unsigned __int128 borrow = 0;
        for (int i = 0; i < 5; ++i) {
            unsigned __int128 cur =
                (unsigned __int128)a[i] - b[i] - borrow;
            a[i] = (u64)cur;
            borrow = (cur >> 64) & 1;  // 1 if it wrapped (borrow out)
        }
    };

    // Dividend N = 2^256: only bit 256 is set. Long-divide MSB-first.
    for (int i = 256; i >= 0; --i) {
        shl1(R);
        if (i == 256) R[0] |= 1;   // the single set bit of 2^256
        shl1(Q);
        if (ge(R, D)) { sub(R, D); Q[0] |= 1; }
    }
    // Narrow to u64 with saturation: any high limb set => overflow => clamp.
    if (Q[1] | Q[2] | Q[3] | Q[4]) return UINT64_MAX;
    return Q[0];
}

// Build a leading-zero-bit target (lz zero bits, then all ones) — the target
// whose work is exactly 2^lz. Lets the narrowing unit test bridge the compact
// `lz` form and the full-256-bit path.
inline bytes32 target_of_lz(unsigned lz) {
    bytes32 t;
    t.fill(0xff);
    // Big-endian array: t[0] is the most significant byte, bit 7 its MSB. Clear
    // the top lz bits, MSB-first (m=0 is the most significant bit overall).
    for (unsigned m = 0; m < lz && m < 256; ++m) {
        unsigned byte = m / 8;
        unsigned pos = 7 - (m % 8);
        t[byte] &= (std::uint8_t)~(1u << pos);
    }
    return t;
}

// ── mainchain bin resolution (share-format §2) ─────────────────────────────
// bin(x) = mainchain height of x.header.hashPrevBlock. The synthetic block
// hash of a height mirrors rdwr_ref.mainchain_hash.
inline bytes32 mainchain_hash(u64 height) {
    std::vector<std::uint8_t> v;
    const char tag[] = "mainchain-block";   // 15 bytes, no NUL
    for (int i = 0; i < 15; ++i) v.push_back((std::uint8_t)tag[i]);
    for (int i = 0; i < 8; ++i) v.push_back((std::uint8_t)(height >> (8 * i)));
    return sha256d(v);
}

// ── the RDWR work event (carrier or receipt) ───────────────────────────────
// The synthetic header-shaped record. `descriptor`/`identity` are carried
// alongside: `identity` is the payout-descriptor identity key committed INSIDE
// the hashed preimage (binding); `descriptor` is the real PayoutDescriptor the
// accepted work is pushed under (self-carriage, spec §4.3) — NOT part of the
// preimage. The preimage byte layout mirrors rdwr_ref.WorkEvent.preimage so the
// PoW/dedup keys are computed identically.
struct WorkEvent {
    std::uint32_t chain_id = 0;
    bytes32 identity{};            // payout-descriptor identity key (in preimage)
    bytes32 prev_block_hash{};     // header.hashPrevBlock -> origin bin (preimage)
    bytes32 prev_own_share{};      // miner's previous chained share (preimage)
    std::uint32_t lz_bits = 0;     // the target this work was mined against
    u64 nonce = 0;
    ::v37::PayoutDescriptor descriptor;  // real descriptor (self-carriage push)
    std::string tag;                     // bookkeeping only (NOT in preimage)

    std::vector<std::uint8_t> preimage() const {
        std::vector<std::uint8_t> v;
        for (int i = 0; i < 4; ++i)
            v.push_back((std::uint8_t)(chain_id >> (8 * i)));
        v.insert(v.end(), identity.begin(), identity.end());
        v.insert(v.end(), prev_block_hash.begin(), prev_block_hash.end());
        v.insert(v.end(), prev_own_share.begin(), prev_own_share.end());
        for (int i = 0; i < 4; ++i)
            v.push_back((std::uint8_t)(lz_bits >> (8 * i)));
        for (int i = 0; i < 8; ++i)
            v.push_back((std::uint8_t)(nonce >> (8 * i)));
        return v;
    }
    bytes32 hash() const { return sha256d(preimage()); }
    bool meets_own_target() const {
        return leading_zero_bits(hash()) >= lz_bits;
    }
    u64 work() const { return work_of_lz(lz_bits); }
};

inline const bytes32 W2_GENESIS_PREV_OWN = bytes32{};  // all-zero sentinel

} // namespace c2pool::v37n
