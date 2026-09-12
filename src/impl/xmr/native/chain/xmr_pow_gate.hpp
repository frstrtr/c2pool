// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_pow_gate.hpp
//
// THE PROOF-OF-WORK GATE: the rule that decides which rows the index is allowed
// to call verified, and the seed schedule that makes the RandomX check possible
// at all.
//
// WHY A ROW IS ALLOWED TO CARRY `pow_verified`. R-LEVEL pins the node at L4
// PRUNED-AUTHENTICATED: for every block above the anchor we check structure,
// prev-link, fork version, timestamp window, our own next-difficulty, the block
// weight against the median, the coinbase exact-sum -- and RandomX against the
// difficulty WE computed. What we deliberately do not check is the transaction
// bodies' cryptography (ring signatures, range proofs, key images), which is a
// separate ruling and ~200 GB of state.
//
// L4 IS SOUND FOR A POOL BECAUSE THE TX ROOT IS POW-COMMITTED. The hashing blob
// RandomX signs contains the tree root over (miner_tx_hash, tx_hashes...), so
// the id list inside a block is not a peer's claim: it is the thing the work was
// spent on. Authenticating each pruned body against that list (xmr_block_eval.hpp
// step 3) therefore turns "bytes a stranger sent" into "the bytes the miner
// committed to", which is exactly what the weights and fees -- and through them
// the median, the penalty and the reward -- must be derived from. The residual
// exposure is a valid-PoW, consensus-invalid block: it costs the attacker a full
// network block to cost us a couple of minutes of template staleness, and the
// honest chain's cumulative difficulty corrects it. That is the same exposure
// every non-validating consumer of Monero carries.
//
// THE SEED SCHEDULE IS THE WHOLE COST STORY. A RandomX hash needs the 256 MiB
// Argon2d cache keyed by the block id at rx_seedheight(h) = (h-65) & ~2047. That
// key changes once per 2048 blocks, and the 64-block lag means the next epoch's
// key block is already buried before it is needed -- so a node that follows the
// tip re-keys ONCE per epoch, off the hot path, and never stalls a block. This
// gate owns that schedule: it resolves the seed for a height THROUGH THE BRANCH
// being verified (an alt branch across an epoch edge has its own seed, monerod
// blockchain.cpp does the same), prefetches the pair when the lag window opens,
// and counts every re-key so the telemetry can prove the "one per epoch" claim.
//
// WHAT IS NOT HERE. No RandomX. This header has no dependency on librandomx and
// links nothing: the verifier is an interface, and the adapter below is a
// TEMPLATE over anything shaped like c2pool::xmr::LightVerifier. That is what
// lets the whole index -- fork choice, reorg, burial -- be tested on a host with
// no RandomX build, while the RandomX lifecycle component instantiates the same
// adapter with the real light verifier and its two keyed cache slots. The
// adapter's logic is therefore compiled and exercised by the KAT (against a
// model verifier) rather than being an untested wiring stub.
//
// FAIL-CLOSED, TWICE. A missing seed is NOT a rejection and NOT a peer fault: it
// is "ask me again once the cache is keyed" (SeedMissing), because treating an
// unkeyed cache as a bad block would ban honest peers during an epoch rollover.
// A verifier that cannot run at all is VerifierDown, which stops the frontier
// from advancing rather than pretending blocks were checked. Only BelowTarget --
// a hash that really does not meet the difficulty we computed -- is the peer's
// fault, and it is the one fault worth a 24 h ban.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native {

// --- R-LEVEL -----------------------------------------------------------------
// The pinned default is L4. L3 exists as a NAMED, telemetry-visible degradation
// (headers plus PoW, peer-claimed weights) so that if it is ever wanted it is a
// decision someone made and the status line reports, not a silent drift.
enum class VerificationLevel : std::uint8_t {
    L3HeaderPow           = 3,
    L4PrunedAuthenticated = 4,   // R-LEVEL: the default, and the only one wired
};

inline const char* to_string(VerificationLevel l) noexcept {
    switch (l) {
        case VerificationLevel::L3HeaderPow:           return "L3-header-pow";
        case VerificationLevel::L4PrunedAuthenticated: return "L4-pruned-authenticated";
    }
    return "?";
}

// --- the verdict --------------------------------------------------------------
enum class PowVerdict : std::uint8_t {
    Accept = 0,     // hash computed and meets the difficulty we computed
    BelowTarget,    // hash computed and does NOT meet it -- the peer's fault
    SeedMissing,    // the seed id is not resolvable / not resident -- retry
    VerifierDown,   // no verifier, or it failed to initialise -- our fault
    Skipped,        // PoW checking is off for this run (explicitly, not silently)
};

inline const char* to_string(PowVerdict v) noexcept {
    switch (v) {
        case PowVerdict::Accept:       return "Accept";
        case PowVerdict::BelowTarget:  return "BelowTarget";
        case PowVerdict::SeedMissing:  return "SeedMissing";
        case PowVerdict::VerifierDown: return "VerifierDown";
        case PowVerdict::Skipped:      return "Skipped";
    }
    return "?";
}

// Only a hash that really missed the target is the sender's fault. Everything
// else is our own state being not-ready, and banning on it would be a bug that
// looks like a security feature.
inline constexpr bool pow_verdict_is_peer_fault(PowVerdict v) noexcept {
    return v == PowVerdict::BelowTarget;
}

// A row may be counted as verified only on Accept. Skipped is honest about
// having checked nothing, which is why it does not advance the frontier.
inline constexpr bool pow_verdict_is_verified(PowVerdict v) noexcept {
    return v == PowVerdict::Accept;
}

// --- the seam -----------------------------------------------------------------
// What the index needs from a proof-of-work verifier, and nothing more.
class IPowSource {
public:
    virtual ~IPowSource() = default;

    // Make the caches for these seeds resident. EXPENSIVE (Argon2d, ~0.7-2 s per
    // key) and therefore never called from a path that must answer quickly: the
    // gate calls it when the epoch changes or when the lag window opens.
    virtual bool prefetch(const Hash& current_seed,
                          const std::optional<Hash>& next_seed) = 0;

    virtual bool seed_resident(const Hash& seed) const = 0;

    // `blob` is the block's HASHING blob (header ‖ tree_root ‖ varint(n_tx+1)),
    // never the wire blob. `difficulty` is the value the index computed for this
    // block on its own branch -- never a peer's claim.
    virtual PowVerdict verify(const std::uint8_t* blob, std::size_t blob_len,
                              const Hash& seed, const U128& difficulty,
                              Hash& pow_hash_out) = 0;

    // For the telemetry line; a source that cannot run says so.
    virtual RandomXMode mode() const { return RandomXMode::Disabled; }
};

// --- the "no verifier" source --------------------------------------------------
// Used by replays of recorded history (the work was verified when the chain was
// built) and by KATs that are testing topology, not hashes. It returns Skipped,
// never Accept: nothing in the index can mistake it for a check that happened.
class NoPowSource final : public IPowSource {
public:
    bool prefetch(const Hash&, const std::optional<Hash>&) override { return true; }
    bool seed_resident(const Hash&) const override { return true; }
    PowVerdict verify(const std::uint8_t*, std::size_t, const Hash&, const U128&,
                      Hash&) override {
        return PowVerdict::Skipped;
    }
    RandomXMode mode() const override { return RandomXMode::Disabled; }
};

// --- the adapter ---------------------------------------------------------------
// Wraps anything shaped like c2pool::xmr::LightVerifier:
//
//     bool         init(...);                       // caller's business
//     bool         prefetch_epoch(const Hash& current, const std::optional<Hash>& next);
//     bool         seed_resident(const Hash&) const;
//     VerifyStatus verify(const uint8_t* blob, size_t len, const Hash& seed,
//                         uint64_t diff_lo, uint64_t diff_hi, uint8_t out[32]);
//
// where VerifyStatus has the enumerators Accept / BelowTarget / SeedNotResident /
// NotInitialized. It is a template rather than a concrete class for one reason
// that matters: including the real verifier's header would drag librandomx into
// every consumer of the index, and then the index could not be built -- or
// tested -- on a leg that does not link RandomX. Duck typing keeps the whole of
// this logic compiled and covered by the KAT (which instantiates it with a model
// verifier) while the RandomX lifecycle component instantiates the very same
// code with the real one.
template <class Verifier>
class LightVerifierPowSource final : public IPowSource {
public:
    explicit LightVerifierPowSource(Verifier& v, RandomXMode mode = RandomXMode::LightJit)
        : v_(v), mode_(mode) {}

    bool prefetch(const Hash& current_seed,
                  const std::optional<Hash>& next_seed) override {
        return v_.prefetch_epoch(current_seed, next_seed);
    }

    bool seed_resident(const Hash& seed) const override { return v_.seed_resident(seed); }

    PowVerdict verify(const std::uint8_t* blob, std::size_t blob_len,
                      const Hash& seed, const U128& difficulty,
                      Hash& pow_hash_out) override {
        using Status = decltype(v_.verify(blob, blob_len, seed, difficulty.lo,
                                          difficulty.hi, pow_hash_out.data()));
        const Status s = v_.verify(blob, blob_len, seed, difficulty.lo, difficulty.hi,
                                   pow_hash_out.data());
        if (s == Status::Accept)          return PowVerdict::Accept;
        if (s == Status::BelowTarget)     return PowVerdict::BelowTarget;
        if (s == Status::SeedNotResident) return PowVerdict::SeedMissing;
        return PowVerdict::VerifierDown;
    }

    RandomXMode mode() const override { return mode_; }

private:
    Verifier&   v_;
    RandomXMode mode_;
};

// --- the gate -------------------------------------------------------------------
// Seed resolution + prefetch schedule + verdict + counters.
//
// SEED RESOLUTION IS BRANCH-LOCAL. `SeedLookup` is supplied by the index and is
// asked for the id at an epoch height ON THE BRANCH BEING VERIFIED. On the main
// chain that is just a row lookup; on an alt branch that crosses an epoch edge
// the answer is the alt branch's own block, which is why the lookup takes the
// branch's tip as context rather than reading a global table.
class PowGate {
public:
    // (epoch_height, branch_tip_id) -> the id of the block at that height on the
    // branch that ends at branch_tip_id. nullopt = we cannot see that far back,
    // which is SeedMissing, not a rejection.
    using SeedLookup = std::function<std::optional<Hash>(std::uint64_t epoch_height,
                                                         const Hash& branch_tip_id)>;

    PowGate(IPowSource& source, SeedLookup lookup,
            VerificationLevel level = VerificationLevel::L4PrunedAuthenticated)
        : source_(&source), lookup_(std::move(lookup)), level_(level) {}

    void set_source(IPowSource& source) noexcept { source_ = &source; }
    VerificationLevel level() const noexcept { return level_; }
    RandomXMode mode() const { return source_->mode(); }

    // The result of one gate pass, kept whole so the caller can attribute a
    // fault, record a pow hash, or decide to retry.
    struct Result {
        PowVerdict verdict   = PowVerdict::Skipped;
        Hash       pow_hash{};
        Hash       seed{};
        bool       rekeyed   = false;   // this call paid for an Argon2d re-key
    };

    // `parent_id` identifies the branch: for a candidate at `height`, the seed
    // block is at rx_seedheight(height), which is at or below the parent.
    Result check(std::uint64_t height, const Hash& parent_id,
                 const std::vector<std::uint8_t>& hashing_blob,
                 const U128& difficulty) {
        Result r;

        const SeedPair pair = seed_pair_for_height(height);
        const std::optional<Hash> seed = lookup_(pair.seed_height, parent_id);
        if (!seed) {
            r.verdict = PowVerdict::SeedMissing;
            ++seed_misses_;
            return r;
        }
        r.seed = *seed;

        // Prefetch. The next epoch's key is asked for only inside the lag
        // window, which is the whole point of the 64-block lag: by then the key
        // block is buried and its id cannot change under a shallow reorg.
        std::optional<Hash> next;
        if (pair.in_lag_window) next = lookup_(pair.next_seed_height, parent_id);

        if (!source_->seed_resident(*seed) || (next && !source_->seed_resident(*next))) {
            if (!source_->prefetch(*seed, next)) {
                r.verdict = PowVerdict::VerifierDown;
                return r;
            }
            r.rekeyed = true;
            ++rekeys_;
        }

        r.verdict = source_->verify(hashing_blob.data(), hashing_blob.size(), *seed,
                                    difficulty, r.pow_hash);
        switch (r.verdict) {
            case PowVerdict::Accept:      ++verified_; break;
            case PowVerdict::BelowTarget: ++failed_;   break;
            case PowVerdict::SeedMissing: ++seed_misses_; break;
            default: break;
        }
        return r;
    }

    std::uint64_t verified()    const noexcept { return verified_; }
    std::uint64_t failed()      const noexcept { return failed_; }
    std::uint64_t rekeys()      const noexcept { return rekeys_; }
    std::uint64_t seed_misses() const noexcept { return seed_misses_; }

private:
    IPowSource*       source_;
    SeedLookup        lookup_;
    VerificationLevel level_;

    std::uint64_t verified_    = 0;
    std::uint64_t failed_      = 0;
    std::uint64_t rekeys_      = 0;
    std::uint64_t seed_misses_ = 0;
};

} // namespace c2pool::xmr::native
