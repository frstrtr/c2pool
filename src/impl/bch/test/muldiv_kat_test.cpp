// ---------------------------------------------------------------------------
// bch::abla muldiv 128-bit KAT -- the guard for the MSVC-portability rework.
//
// abla.hpp evaluates x*y/z (BCHN control function) in a 128-bit intermediate.
// GCC/Clang use native unsigned __int128; MSVC (no __int128, error C4235) falls
// back to boost::multiprecision::uint128_t. Both must be BIT-IDENTICAL or the
// Windows package would silently diverge from the shipping Linux/macOS ABLA.
//
// This test pins that in two layers:
//   A. cross-platform known-answers: muldiv() must produce exact fixed results
//      on EVERY compiler (this is all MSVC can run -- no native to diff).
//   B. Linux-only equivalence sweep (guarded by __SIZEOF_INT128__): the portable
//      path must equal the native path across the full ABLA operand space plus a
//      deterministic wide-operand fuzz. Proving portable == native on the trusted
//      platform is what certifies the MSVC path we cannot run here.
//
// Build-INERT wrt consensus surface: pure header math, no node/RPC/boost-graph.
// p2pool-merged-v36 surface: NONE (ABLA is a LOCAL build-time byte budget only).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <limits>

#include "../coin/abla.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bch::coin::abla::muldiv;
using bch::coin::abla::muldiv_portable;
using bch::coin::abla::B7;

constexpr uint64_t U64MAX = std::numeric_limits<uint64_t>::max();

// Deterministic 64-bit LCG (no <random>, no Date/rand) -- reproducible vectors.
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

} // namespace

int main() {
    // ---- A. cross-platform known answers (run on ALL compilers incl. MSVC) ----
    // hand-computed; several exercise a product > 2^64 so the true 128-bit
    // intermediate is required (a 64-bit multiply would wrap and fail these).
    CHECK(muldiv(192, 16000000ULL, 128) == 24000000ULL);            // ABLA amplify shape
    CHECK(muldiv(6, 7, 2) == 21ULL);
    CHECK(muldiv(0, 12345, 7) == 0ULL);
    CHECK(muldiv(U64MAX, 1, 1) == U64MAX);
    CHECK(muldiv(U64MAX, U64MAX, U64MAX) == U64MAX);                // product ~2^128
    CHECK(muldiv(1000000000000000000ULL, 1000000000ULL,
                 1000000000000ULL) == 1000000000000000ULL);         // 1e27 intermediate
    CHECK(muldiv(B7, 32ULL * 1000000ULL, B7) == 32ULL * 1000000ULL);// identity via B7

    // portable path must independently satisfy the same known answers
    CHECK(muldiv_portable(192, 16000000ULL, 128) == 24000000ULL);
    CHECK(muldiv_portable(U64MAX, U64MAX, U64MAX) == U64MAX);
    CHECK(muldiv_portable(1000000000000000000ULL, 1000000000ULL,
                          1000000000000ULL) == 1000000000000000ULL);

#if defined(__SIZEOF_INT128__)
    using bch::coin::abla::muldiv_native;

    // ---- B1. exact ABLA-domain vectors: native == portable ----
    // operand shapes taken straight from State::NextBlockState call sites.
    const uint64_t sizes[] = {
        0, 1, B7, 192, 37938, 1000000ULL, 16ULL * 1000000ULL,
        32ULL * 1000000ULL, 2000ULL * 1000000ULL, (1ULL << 40), (1ULL << 62)
    };
    for (uint64_t x : sizes)
        for (uint64_t y : sizes)
            for (uint64_t z : sizes) {
                if (z == 0) continue;
                // only compare where the true quotient fits uint64_t (the ABLA
                // invariant); otherwise both paths take low-64 of an out-of-range
                // value and the comparison is not meaningful.
                const unsigned __int128 q =
                    (static_cast<unsigned __int128>(x) * y) / z;
                if (q > static_cast<unsigned __int128>(U64MAX)) continue;
                CHECK(muldiv_native(x, y, z) == muldiv_portable(x, y, z));
            }

    // ---- B2. wide deterministic fuzz: native == portable ----
    Lcg rng(0x9E3779B97F4A7C15ULL);
    int compared = 0;
    for (int i = 0; i < 200000; ++i) {
        const uint64_t x = rng.next();
        const uint64_t y = rng.next();
        uint64_t z = rng.next();
        if (z == 0) z = 1;
        const unsigned __int128 q =
            (static_cast<unsigned __int128>(x) * y) / z;
        if (q > static_cast<unsigned __int128>(U64MAX)) continue; // keep in-domain
        ++compared;
        if (muldiv_native(x, y, z) != muldiv_portable(x, y, z)) {
            std::cerr << "FAIL fuzz: x=" << x << " y=" << y << " z=" << z << "\n";
            ++failures;
        }
    }
    CHECK(compared > 1000); // sanity: the domain filter did not reject everything
    std::cerr << "muldiv KAT: native==portable over " << compared << " fuzz vectors\n";
#else
    std::cerr << "muldiv KAT: no __int128 (MSVC) -- known-answer layer only\n";
#endif

    if (failures) { std::cerr << failures << " CHECK(s) FAILED\n"; return 1; }
    std::cerr << "muldiv_kat_test: ALL PASS\n";
    return 0;
}
