#pragma once
// V37 MRR roundabout — fixed-point arithmetic + deterministic decay tables.
// Spec: docs/c2pool-v37-mrr-roundabout-buffer.md §8.1–8.3.
//
// Consensus rules enforced here:
//   * no floating point anywhere
//   * every multiply truncates toward zero
//   * the ratified default lane geometry (half_life 2160, E 4096, Q62) uses
//     the EXACT per-entry hl-th-root decay base pinned bit-for-bit by the
//     ratified golden d659c801 (see DecayTables::init and
//     v37_decay_canonical.hpp); non-ratified geometries (test harness only)
//     retain the V36-lineage iterated truncating-multiply construction
//
// Range pinning (the "exact ranges to be pinned in the implementation spec"
// of §8.1): FRAC_BITS = 62, not 64. Rationale: with Q62 every table entry
// (decay <= 1.0, inverse-decay <= 2^{E/half_life} < 4.0) fits a u64, every
// w_raw (full u64 range) x table product fits native unsigned __int128, and
// accumulator sums fit U256. Q62 is 2^22 finer than V36's Q40. Flagged in
// IMPLEMENTATION-NOTES.md as an erratum against the spec's "64 fractional
// bits" wording; the spec delegates final range pinning here.

#include <array>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

#include "v37_decay_canonical.hpp"  // generated exact-root base (golden d659c801)

namespace v37 {

using u64  = std::uint64_t;
using u128 = unsigned __int128;

static constexpr unsigned FRAC_BITS = 62;
static constexpr u64 Q_ONE = u64(1) << FRAC_BITS;            // 1.0 in Q62
static constexpr u64 LN2_MICRO = 693147;                     // V36 lineage

// Q-scale drift tripwire between this header and the generated canonical
// table. Both sides are compile-time constants, so this belongs in the build
// and not in DecayTables::init's runtime gate: as a runtime term it could
// only ever be true, and were the two to disagree the gate would go
// permanently false and every node would SILENTLY use the first-order base
// instead of the ratified golden d659c801. Fail the build instead.
static_assert(FRAC_BITS == decay_canonical::CANON_FRAC_BITS,
              "v37: FRAC_BITS must match the Q-scale of the generated "
              "canonical decay table (v37_decay_canonical.hpp); regenerate "
              "the table with tools/gen_decay_canonical.py if it changes");

// ── U256: minimal unsigned 256-bit integer (4 x u64 limbs, little-endian) ──
// Only the operations the consensus path needs; all wrap-free uses are
// guarded by the Q62 range pinning above.
struct U256 {
    std::array<u64, 4> v{0, 0, 0, 0};

    constexpr U256() = default;
    constexpr U256(u64 x) : v{x, 0, 0, 0} {}
    static U256 from_u128(u128 x) {
        U256 r;
        r.v[0] = static_cast<u64>(x);
        r.v[1] = static_cast<u64>(x >> 64);
        return r;
    }
    bool is_zero() const { return !(v[0] | v[1] | v[2] | v[3]); }

    U256& operator+=(const U256& o) {
        u128 c = 0;
        for (int i = 0; i < 4; ++i) {
            u128 s = u128(v[i]) + o.v[i] + c;
            v[i] = static_cast<u64>(s);
            c = s >> 64;
        }
        return *this;  // overflow impossible under range pinning
    }
    U256& operator-=(const U256& o) {
        u128 borrow = 0;
        for (int i = 0; i < 4; ++i) {
            u128 d = u128(v[i]) - o.v[i] - borrow;
            v[i] = static_cast<u64>(d);
            borrow = (d >> 64) ? 1 : 0;
        }
        return *this;  // callers only subtract amounts previously added
    }
    friend U256 operator+(U256 a, const U256& b) { a += b; return a; }
    friend U256 operator-(U256 a, const U256& b) { a -= b; return a; }
    friend bool operator==(const U256& a, const U256& b) { return a.v == b.v; }
    friend bool operator!=(const U256& a, const U256& b) { return !(a == b); }
    friend bool operator<(const U256& a, const U256& b) {
        for (int i = 3; i >= 0; --i)
            if (a.v[i] != b.v[i]) return a.v[i] < b.v[i];
        return false;
    }

    // (this * m) >> FRAC_BITS, truncating — the Q62 scale-application step.
    // Used for: acc x decay (query), bucket scaled x epoch shift.
    U256 mul_q(u64 m) const {
        // 256 x 64 -> 320-bit intermediate held as 5 limbs, then >> 62.
        u64 r[5] = {0, 0, 0, 0, 0};
        u128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            u128 p = u128(v[i]) * m + carry;
            r[i] = static_cast<u64>(p);
            carry = p >> 64;
        }
        r[4] = static_cast<u64>(carry);
        U256 out;
        constexpr unsigned s = FRAC_BITS;          // 62: cross-limb shift
        for (int i = 0; i < 4; ++i)
            out.v[i] = (r[i] >> s) | (u64(r[i + 1]) << (64 - s));
        // r[4] >> s contributes to out.v[3]'s high bits:
        // already folded via r[4] << (64-s) above when i==3.
        return out;
    }

    std::string hex() const {
        static const char* d = "0123456789abcdef";
        std::string s;
        for (int i = 3; i >= 0; --i)
            for (int j = 15; j >= 0; --j)
                s.push_back(d[(v[i] >> (j * 4)) & 0xf]);
        return s;
    }
};

// (a * b) >> FRAC_BITS for two u64 Q62 factors (both values < 4.0).
inline u64 mul_q64(u64 a, u64 b) {
    return static_cast<u64>((u128(a) * b) >> FRAC_BITS);
}

// ── Deterministic decay tables (§8.2) ─────────────────────────────────────
// All entries are generated by integer-only, iterated, truncating procedures
// anchored on LN2_MICRO — identical on every conforming platform.
struct DecayTables {
    u64 half_life = 0;
    u64 epoch_len = 0;          // E
    u64 decay_per = 0;          // lambda = 2^(-1/half_life), Q62
    u64 inv_per = 0;            // lambda^(-1), Q62 (value slightly > 1.0)

    std::vector<u64> decay;     // decay[d]   = lambda^d,    Q62, d in [0, span]
    std::vector<u64> inv_decay; // inv_decay[j] = lambda^-j, Q62, j in [0, E)
    std::vector<u64> epoch_shift; // epoch_shift[i] = lambda^(E*i), Q62

    void init(u64 half_life_, u64 epoch_len_, u64 max_depth, u64 max_epochs) {
        if (half_life_ == 0 || epoch_len_ == 0)
            throw std::invalid_argument("v37: zero decay parameter");
        half_life = half_life_;
        epoch_len = epoch_len_;

        // ── Canonical exact-root path (ruling option (i); golden d659c801) ──
        // For the ratified default lane geometry the decay base is the EXACT
        // per-entry hl-th root of a power of two,
        //   decay[d]     = floor( (2^(FRAC_BITS*half_life - d))^(1/half_life) )
        //   inv_decay[j] = floor( (2^(FRAC_BITS*half_life + j))^(1/half_life) )
        // pinned bit-for-bit by the ratified golden vector d659c801. Computing
        // that root at runtime would require ~134-kbit bignum arithmetic in the
        // consensus path (2^(FRAC_BITS*half_life) is ~133,920 bits), so the
        // values are embedded (v37_decay_canonical.hpp, generated FROM the
        // golden and self-verified against its published anchors). This path is
        // deterministic-by-construction and trivially bit-matches the golden.
        // decay_per / inv_per become the EXACT per-step factors lambda,
        // lambda^-1 (= decay[1], inv_decay[1]) rather than the first-order
        // approximation. epoch_shift is derived from the exact decay[epoch_len].
        // The ratified geometry is identified by (half_life, epoch_len) alone
        // — exactly the pair the lane digest commits. max_depth is NOT digest-
        // committed (it is derived caller-side as epoch_len + c0), so it must
        // never be allowed to silently divert the ratified geometry off the
        // golden base: two nodes agreeing on every committed parameter would
        // then build different decay tables with nothing to attribute the
        // divergence to. A depth the embedded canonical table cannot serve is
        // therefore refused, not downgraded to the first-order base.
        namespace dc = decay_canonical;
        if (half_life == dc::CANON_HALF_LIFE && epoch_len == dc::CANON_EPOCH_LEN) {
            if (max_depth > dc::CANON_MAX_DEPTH)
                throw std::invalid_argument(
                    "v37: ratified lane geometry (half_life 2160, E 4096) "
                    "requested with max_depth beyond the canonical table; "
                    "refusing to fall back to the non-golden first-order base");
            decay_per = dc::DECAY[1];
            inv_per   = dc::INV_DECAY[1];

            decay.assign(max_depth + 1, 0);
            for (u64 d = 0; d <= max_depth; ++d)
                decay[d] = dc::DECAY[d];

            inv_decay.assign(epoch_len, 0);
            for (u64 j = 0; j < epoch_len; ++j)
                inv_decay[j] = dc::INV_DECAY[j];

            if (max_depth < epoch_len)
                throw std::invalid_argument("v37: decay table shorter than epoch");
            epoch_shift.assign(max_epochs + 1, 0);
            epoch_shift[0] = Q_ONE;
            for (u64 i = 1; i <= max_epochs; ++i)
                epoch_shift[i] = mul_q64(epoch_shift[i - 1], decay[epoch_len]);
            return;
        }

        // ── Non-ratified geometry: V36-lineage first-order construction ──
        // Only the default geometry above is consensus-ratified / golden-pinned;
        // non-default geometries appear solely in the test harness and are not
        // consensus objects (the lane digest commits half_life, so they are
        // already distinct). Ratifying any new geometry requires generating and
        // embedding its exact-root golden (or a runtime bignum root) here.
        //   decay_per = 1.0 - ln2/half_life  (first-order, exactly as V36's
        //   Q40 formula, widened): Q_ONE - (Q_ONE * LN2_MICRO) / (1e6 * HL)
        decay_per = Q_ONE - static_cast<u64>(
            (u128(Q_ONE) * LN2_MICRO) / (u128(1000000) * half_life));

        // inv_per = floor(2^124 / decay_per): the Q62 reciprocal of a Q62
        // value (2^124 = Q_ONE << FRAC_BITS fits u128 exactly).
        inv_per = static_cast<u64>((u128(Q_ONE) << FRAC_BITS) / decay_per);

        decay.assign(max_depth + 1, 0);
        decay[0] = Q_ONE;
        for (u64 d = 1; d <= max_depth; ++d)
            decay[d] = mul_q64(decay[d - 1], decay_per);

        inv_decay.assign(epoch_len, 0);
        inv_decay[0] = Q_ONE;
        for (u64 j = 1; j < epoch_len; ++j) {
            inv_decay[j] = mul_q64(inv_decay[j - 1], inv_per);
            // Headroom guard: the true sequence is strictly increasing
            // (every entry >= 1.0 and inv_per > 1.0), so any non-increase
            // is a u64 wrap — the lane geometry violates the inverse-decay
            // headroom (requires lambda^-(E-1) < 4.0, i.e. roughly
            // epoch_len <= 2 * half_life). Refuse rather than corrupt.
            if (inv_decay[j] <= inv_decay[j - 1])
                throw std::invalid_argument(
                    "v37: epoch_len/half_life ratio overflows inverse-decay "
                    "headroom (need lambda^-(E-1) < 4.0)");
        }

        if (max_depth < epoch_len)
            throw std::invalid_argument("v37: decay table shorter than epoch");
        epoch_shift.assign(max_epochs + 1, 0);
        epoch_shift[0] = Q_ONE;
        for (u64 i = 1; i <= max_epochs; ++i)
            epoch_shift[i] = mul_q64(epoch_shift[i - 1], decay[epoch_len]);
    }
};

} // namespace v37
