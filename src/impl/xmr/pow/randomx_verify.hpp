// SPDX-License-Identifier: AGPL-3.0-or-later
//
// randomx_verify.hpp — c2pool-side light-mode RandomX proof verifier for the
// v37 Work-Receipts "Family B: XMR lane".
//
// This is c2pool's OWN wrapper around the vendored tevador/RandomX library
// (BSD-3, see third_party/randomx/). It contains NO upstream code: only the
// C API of RandomX (randomx.h) and Monero's target-check ARITHMETIC RULE are
// used here. The RandomX library itself is linked as librandomx.a.
//
// Scope of this file (leg: randomx-vendor):
//   * two-cache (current / next) 256 MiB light-verify manager with the
//     Monero 2048-block epoch / 64-block seed lag;
//   * one reusable light VM (cache-only, NEVER the 2 GiB dataset);
//   * the Monero PoW acceptance test  hash * difficulty < 2^256
//     (a faithful re-expression of monero-project/monero
//      src/cryptonote_basic/difficulty.cpp check_hash_64 / check_hash_128,
//      BSD-3 — algorithm only, no code copied);
//   * a per-Monero-hard-fork algorithm pin that keeps RANDOMX_FLAG_V2 OFF for
//     mainnet rx/0 (turning it on is a CONSENSUS change — fence it to a fork).
//
// Out of scope here (other legs): the miner_tx / coinbase-output derivation
// (that is pre-CARROT and lives behind the W5-XMR guard), stratum, monerod RPC.
//
// Design invariants (from v37-monero-randomx-lane-scoping.md §1.3/§1.4):
//   I1  keyed_heavy lanes run RandomX LAST; verify() must be reached only after
//       dedup/expiry/binding/target-bits checks have passed upstream.
//   I2  verify() NEVER initializes an Argon2d cache on the hot path. The seed
//       for the receipt's bin must already be resident (prefetch_epoch()).
//       An unknown seed returns SeedNotResident — it is the caller's DoS gate.
//   I3  light verify only: FULL_MEM is never set; per-node cost is 256 MiB
//       (+256 MiB across an epoch rollover) + 2 MiB scratchpad per VM.

#ifndef C2POOL_XMR_RANDOMX_VERIFY_HPP
#define C2POOL_XMR_RANDOMX_VERIFY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "randomx.h"  // vendored BSD-3, third_party/randomx/randomx.h

namespace c2pool::xmr {

// ---------------------------------------------------------------------------
// Monero epoch geometry (mirrors monero-project/monero rx-slow-hash.c).
//   SEEDHASH_EPOCH_BLOCKS = 2048  (~2.8 d), SEEDHASH_EPOCH_LAG = 64 (~2 h).
// The RandomX key for a block at height h is the block ID (hash) at
// seed_height(h). The 64-block lag guarantees that seed block is already
// deep/final, so the next epoch's cache can always be precomputed early.
// ---------------------------------------------------------------------------
static constexpr uint64_t kSeedhashEpochBlocks = 2048;  // must be a power of two
static constexpr uint64_t kSeedhashEpochLag    = 64;
static constexpr std::size_t kSeedHashSize      = 32;    // Monero block id length
using SeedHash = std::array<uint8_t, kSeedHashSize>;

// seed_height(h): height of the block whose id keys the RandomX cache for h.
// Faithful to monero rx_seedheight().
inline uint64_t seed_height(uint64_t height) noexcept {
    if (height <= kSeedhashEpochBlocks + kSeedhashEpochLag) return 0;
    return (height - kSeedhashEpochLag - 1) & ~(kSeedhashEpochBlocks - 1);
}

// The two seed heights kept live for height h: the current epoch's and the
// next epoch's (monero rx_seedheights()). A receipt binned within N_CTX of an
// epoch boundary may reference either; two resident caches always suffice.
struct SeedHeights { uint64_t current; uint64_t next; };
inline SeedHeights seed_heights(uint64_t height) noexcept {
    return SeedHeights{ seed_height(height),
                        seed_height(height + kSeedhashEpochLag) };
}

// ---------------------------------------------------------------------------
// Monero PoW algorithm pin, per mainchain hard-fork major_version.
// rx/0 (current mainnet, HF >= 12) == RandomX v1 semantics: RANDOMX_FLAG_V2 OFF.
// RANDOMX_FLAG_V2 changes the hash (KAT 22ec.. vs 6391..); enabling it is a
// consensus fork and MUST be gated to the Monero major_version that adopts it.
// ---------------------------------------------------------------------------
enum class PowAlgo : uint8_t {
    RX_0 = 0,   // Monero mainnet "rx/0" — RandomX v1. Pinned default.
    // RX_2  reserved: a future Monero fork adopting RandomX 2.0. Do NOT enable
    //       until a mainnet major_version pins it (OQ-X: RandomX v2 / #8827).
};

inline randomx_flags algo_variant_flag(PowAlgo a) noexcept {
    switch (a) {
        case PowAlgo::RX_0: default: return RANDOMX_FLAG_DEFAULT;  // V2 OFF
    }
}

// ---------------------------------------------------------------------------
// Monero acceptance test:  hash * difficulty < 2^256.
// hash is read as a 256-bit little-endian integer (4 x uint64 LE words).
// Ported (algorithm, not source) from monero difficulty.cpp check_hash_64 /
// check_hash_128 (BSD-3). Returns true iff the 256-bit hash meets `difficulty`.
// ---------------------------------------------------------------------------
namespace detail {

inline uint64_t load_le64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}
inline uint64_t umul128(uint64_t a, uint64_t b, uint64_t& hi) noexcept {
    unsigned __int128 p = static_cast<unsigned __int128>(a) * b;
    hi = static_cast<uint64_t>(p >> 64);
    return static_cast<uint64_t>(p);
}
// carry predicates, exactly as monero difficulty.cpp
inline bool cadd(uint64_t a, uint64_t b) noexcept { return a + b < a; }
inline bool cadc(uint64_t a, uint64_t b, bool c) noexcept {
    return a + b < a || (c && a + b == static_cast<uint64_t>(-1));
}

} // namespace detail

// 64-bit difficulty path (share targets / T_origin — fits u64 per scoping §3).
inline bool meets_difficulty_64(const uint8_t hash[32], uint64_t difficulty) noexcept {
    using namespace detail;
    const uint64_t w0 = load_le64(hash +  0);
    const uint64_t w1 = load_le64(hash +  8);
    const uint64_t w2 = load_le64(hash + 16);
    const uint64_t w3 = load_le64(hash + 24);
    uint64_t low, high, top, cur;
    // Top word first — most random hashes fail here (cheap early-out).
    top = umul128(w3, difficulty, high);
    if (high != 0) return false;
    low = umul128(w0, difficulty, cur);
    low = umul128(w1, difficulty, high);
    bool carry = cadd(cur, low);
    cur = high;
    low = umul128(w2, difficulty, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
}

// 128-bit difficulty path (full Monero difficulty_type). Delegates to the
// 64-bit path when the high half is zero. Checks that (hash * difficulty)
// has no bits at or above 2^256 (limbs p4,p5 must be zero).
inline bool meets_difficulty_128(const uint8_t hash[32],
                                 uint64_t diff_lo, uint64_t diff_hi) noexcept {
    if (diff_hi == 0) return meets_difficulty_64(hash, diff_lo);
    const uint64_t w[4] = { detail::load_le64(hash + 0), detail::load_le64(hash + 8),
                            detail::load_le64(hash + 16), detail::load_le64(hash + 24) };
    const uint64_t d[2] = { diff_lo, diff_hi };
    uint64_t p[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 2; ++j) {
            unsigned __int128 cur =
                static_cast<unsigned __int128>(w[i]) * d[j] + p[i + j] + carry;
            p[i + j] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
        }
        int k = i + 2;
        while (carry) {
            unsigned __int128 cur = static_cast<unsigned __int128>(p[k]) + carry;
            p[k] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
        }
    }
    return p[4] == 0 && p[5] == 0;
}

// ---------------------------------------------------------------------------
// Flag policy for LIGHT verification.
//   base = randomx_get_flags() (auto-detects HARD_AES / ARGON2_* for this CPU)
//   + JIT (fast light execution)
//   + the pinned algorithm variant (RX_0 -> V2 OFF)
//   optionally + LARGE_PAGES (needs hugepages configured) and + SECURE (W^X).
//   NEVER + FULL_MEM (that is the 2 GiB dataset / fast mode — not us).
// ---------------------------------------------------------------------------
struct VerifierOptions {
    PowAlgo algo        = PowAlgo::RX_0;
    bool    use_jit     = true;
    bool    large_pages = false;  // opt-in: OOM-pressured hosts default OFF
    bool    secure_jit  = false;  // opt-in: W^X JIT pages (RANDOMX_FLAG_SECURE)
};

inline randomx_flags cache_flags(const VerifierOptions& o) noexcept {
    randomx_flags f = randomx_get_flags();           // ARGON2_* speedups, HARD_AES
    if (o.use_jit)     f = f | RANDOMX_FLAG_JIT;      // faster cache/dataset init path
    if (o.large_pages) f = f | RANDOMX_FLAG_LARGE_PAGES;
    f = f | algo_variant_flag(o.algo);
    // Cache MUST NOT carry FULL_MEM/SECURE; strip anything not valid for a cache.
    // RANDOMX_FLAG_V2 only exists on post-2.0 upstream pins; guard so this
    // header compiles against the consensus pin (12f2c2f, rx/0, no V2) too.
    int allowed = RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2;
#ifdef RANDOMX_FLAG_V2
    allowed |= RANDOMX_FLAG_V2;
#endif
    f = f & static_cast<randomx_flags>(allowed);
    return f;
}
inline randomx_flags vm_flags(const VerifierOptions& o) noexcept {
    randomx_flags f = randomx_get_flags();           // includes HARD_AES if present
    if (o.use_jit)     f = f | RANDOMX_FLAG_JIT;
    if (o.large_pages) f = f | RANDOMX_FLAG_LARGE_PAGES;   // scratchpad in hugepages
    if (o.secure_jit)  f = f | RANDOMX_FLAG_SECURE;
    f = f | algo_variant_flag(o.algo);
    // Light VM: explicitly clear FULL_MEM (dataset mode).
    f = f & static_cast<randomx_flags>(~static_cast<int>(RANDOMX_FLAG_FULL_MEM));
    return f;
}

// ---------------------------------------------------------------------------
// RAII cache slot (one 256 MiB Argon2d cache keyed to a seed hash).
// ---------------------------------------------------------------------------
class CacheSlot {
public:
    CacheSlot() = default;
    explicit CacheSlot(randomx_flags flags) { cache_ = randomx_alloc_cache(flags); }
    ~CacheSlot() { if (cache_) randomx_release_cache(cache_); }
    CacheSlot(const CacheSlot&) = delete;
    CacheSlot& operator=(const CacheSlot&) = delete;
    CacheSlot(CacheSlot&& o) noexcept
        : cache_(o.cache_), key_(o.key_), keyed_(o.keyed_) { o.cache_ = nullptr; o.keyed_ = false; }
    CacheSlot& operator=(CacheSlot&& o) noexcept {
        if (this != &o) {
            if (cache_) randomx_release_cache(cache_);
            cache_ = o.cache_; key_ = o.key_; keyed_ = o.keyed_;
            o.cache_ = nullptr; o.keyed_ = false;
        }
        return *this;
    }

    bool ok()      const noexcept { return cache_ != nullptr; }
    bool keyed()   const noexcept { return keyed_; }
    const SeedHash& key() const noexcept { return key_; }
    randomx_cache* raw() const noexcept { return cache_; }
    bool holds(const SeedHash& k) const noexcept { return keyed_ && k == key_; }

    // (Re)key the cache. This is the EXPENSIVE Argon2d init (seconds). It runs
    // only via prefetch_epoch(), never on the verify() hot path (invariant I2).
    // No-op if already keyed to the same seed (randomx_init_cache dedups too).
    bool rekey(const SeedHash& k) {
        if (!cache_) return false;
        if (keyed_ && k == key_) return true;
        randomx_init_cache(cache_, k.data(), k.size());
        key_ = k; keyed_ = true;
        return true;
    }

private:
    randomx_cache* cache_ = nullptr;
    SeedHash       key_{};
    bool           keyed_ = false;
};

// ---------------------------------------------------------------------------
// LightVerifier: two resident caches + one light VM, for one worker thread.
// Not thread-safe; give each verifying thread its own instance (caches may be
// shared read-only across VMs, but keep it simple: one-thread-one-verifier,
// as p2pool does per hashing thread).
// ---------------------------------------------------------------------------
enum class VerifyStatus {
    Accept,           // PoW valid AND meets difficulty
    BelowTarget,      // PoW computed, but hash * difficulty >= 2^256 (fails R-1)
    SeedNotResident,  // seed not prefetched — caller violated invariant I2
    NotInitialized,   // alloc failed (OOM) — see init()
};

class LightVerifier {
public:
    LightVerifier() = default;
    ~LightVerifier() { if (vm_) randomx_destroy_vm(vm_); }
    LightVerifier(const LightVerifier&) = delete;
    LightVerifier& operator=(const LightVerifier&) = delete;

    // Allocate the two cache slots and the VM. Returns false on OOM.
    bool init(const VerifierOptions& opts = {}) {
        opts_ = opts;
        cur_  = CacheSlot(cache_flags(opts_));
        next_ = CacheSlot(cache_flags(opts_));
        if (!cur_.ok() || !next_.ok()) return false;
        // VM starts pointed at cur_ (must be keyed before first hash).
        vm_ = randomx_create_vm(vm_flags(opts_), cur_.raw(), nullptr);
        return vm_ != nullptr;
    }

    // Prefetch (Argon2d init) the caches for the two epochs live at `height`.
    // Caller supplies the two seed block hashes (mainchain ids at the two
    // seed_heights). Returns false only on a null cache (init not done).
    // EXPENSIVE — call off the admission hot path (e.g. on new mainchain tip,
    // or when a peer first advertises a bin in a not-yet-resident epoch).
    bool prefetch_epoch(const SeedHash& current_seed,
                        const std::optional<SeedHash>& next_seed) {
        if (!cur_.ok()) return false;
        // Keep whichever slot already holds a needed seed; rekey the other.
        if (!slot_for(current_seed)) {
            // pick the slot that is NOT holding next_seed to rekey
            CacheSlot* victim = pick_victim(next_seed ? &*next_seed : nullptr,
                                            current_seed);
            if (victim) victim->rekey(current_seed);
        }
        if (next_seed && !slot_for(*next_seed)) {
            CacheSlot* victim = pick_victim(&current_seed, *next_seed);
            if (victim) victim->rekey(*next_seed);
        }
        return true;
    }

    // The verify hot path (invariant I1: reached last, after cheap checks).
    // `seed` is the RandomX key for the receipt's bin (resolved by the caller
    // from seed_height(bin) against the mainchain index). MUST already be
    // resident (invariant I2) — otherwise SeedNotResident, and the caller must
    // treat it as a not-yet-verifiable carrier (queue for prefetch, do not hash).
    VerifyStatus verify(const uint8_t* blob, std::size_t blob_len,
                        const SeedHash& seed, uint64_t difficulty,
                        uint8_t out_hash[32]) {
        if (!vm_) return VerifyStatus::NotInitialized;
        CacheSlot* slot = slot_for(seed);
        if (!slot) return VerifyStatus::SeedNotResident;
        if (bound_ != slot->raw()) {                 // re-point VM if needed (cheap)
            randomx_vm_set_cache(vm_, slot->raw());
            bound_ = slot->raw();
        }
        uint8_t local[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(vm_, blob, blob_len, local);   // ~10-15 ms light
        if (out_hash) std::memcpy(out_hash, local, RANDOMX_HASH_SIZE);
        return meets_difficulty_64(local, difficulty)
                   ? VerifyStatus::Accept : VerifyStatus::BelowTarget;
    }

    // Convenience 128-bit-difficulty overload.
    VerifyStatus verify(const uint8_t* blob, std::size_t blob_len,
                        const SeedHash& seed, uint64_t diff_lo, uint64_t diff_hi,
                        uint8_t out_hash[32]) {
        if (!vm_) return VerifyStatus::NotInitialized;
        CacheSlot* slot = slot_for(seed);
        if (!slot) return VerifyStatus::SeedNotResident;
        if (bound_ != slot->raw()) { randomx_vm_set_cache(vm_, slot->raw()); bound_ = slot->raw(); }
        uint8_t local[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(vm_, blob, blob_len, local);
        if (out_hash) std::memcpy(out_hash, local, RANDOMX_HASH_SIZE);
        return meets_difficulty_128(local, diff_lo, diff_hi)
                   ? VerifyStatus::Accept : VerifyStatus::BelowTarget;
    }

    // Raw hash without a target test (for KATs / re-verification of mainnet
    // blocks). Same residency requirement.
    bool hash(const uint8_t* blob, std::size_t blob_len,
              const SeedHash& seed, uint8_t out_hash[32]) {
        if (!vm_) return false;
        CacheSlot* slot = slot_for(seed);
        if (!slot) return false;
        if (bound_ != slot->raw()) { randomx_vm_set_cache(vm_, slot->raw()); bound_ = slot->raw(); }
        randomx_calculate_hash(vm_, blob, blob_len, out_hash);
        return true;
    }

    bool seed_resident(const SeedHash& s) const noexcept {
        return cur_.holds(s) || next_.holds(s);
    }

private:
    CacheSlot* slot_for(const SeedHash& s) noexcept {
        if (cur_.holds(s))  return &cur_;
        if (next_.holds(s)) return &next_;
        return nullptr;
    }
    // choose a slot to overwrite that does NOT currently hold `keep`
    CacheSlot* pick_victim(const SeedHash* keep, const SeedHash& /*incoming*/) noexcept {
        auto held_keep = [&](const CacheSlot& s) {
            return keep && s.holds(*keep);
        };
        if (!held_keep(cur_))  return &cur_;
        if (!held_keep(next_)) return &next_;
        return &cur_;  // both hold keep (can't happen with distinct seeds); safe fallback
    }

    VerifierOptions opts_{};
    CacheSlot       cur_{};
    CacheSlot       next_{};
    randomx_vm*     vm_    = nullptr;
    randomx_cache*  bound_ = nullptr;  // which cache the VM currently points at
};

} // namespace c2pool::xmr

#endif // C2POOL_XMR_RANDOMX_VERIFY_HPP
