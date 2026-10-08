// SPDX-License-Identifier: AGPL-3.0-or-later
//
// randomx_init_lock.hpp — one process-wide lock around RandomX cache/dataset
// INITIALISATION.
//
// WHY THIS EXISTS (an observed crash, not a theoretical hazard)
//   The node already keys RandomX caches from the stratum-listener thread
//   (O2RandomXVerifier::ensure_seeds -> LightVerifier::prefetch_epoch ->
//   CacheSlot::rekey -> randomx_init_cache). The in-process CPU miner
//   (xmr_cpu_miner.hpp) keys its OWN cache from the main loop thread. When a
//   template change made both fire at the same instant on a 2026-09-17 regtest
//   run, the process died with SIGFPE inside randomx_reciprocal(), reached
//   from randomx::initCacheCompile() — i.e. a superscalar-program immediate
//   that must never be zero was read as zero while the other thread was still
//   filling its Argon2d blocks:
//
//     Thread 3  randomx_reciprocal  <- initCache <- initCacheCompile
//                                  <- randomx_init_cache
//                                  <- LightVerifier::prefetch_epoch
//     Thread 1  fill_block <- randomx_argon2_fill_segment_avx2
//                          <- initCache <- randomx_init_cache
//                          <- CpuMiner::rekey
//
//   We have NOT root-caused which piece of librandomx state is shared across
//   two concurrent randomx_init_cache() calls on DISTINCT caches, and we do not
//   patch the vendored BSD-3 library to find out. Serialising initialisation
//   removes the overlap outright, is free in steady state (a cache is keyed
//   once per ~2048-block Monero epoch, or once per miner start) and costs
//   nothing on the hashing hot path, which never touches this lock.
//
// SCOPE
//   Guard the *init* calls only:  randomx_init_cache / randomx_init_dataset.
//   NOT randomx_calculate_hash*, NOT randomx_create_vm, NOT alloc/release.
//   Holding it across a hash would serialise mining and is a bug.
//
//   Header-only and dependency-free on purpose: both the verifier
//   (randomx_verify.hpp) and the miner (xmr_cpu_miner.hpp) include it, and the
//   function-local static gives exactly one mutex per process with no static
//   initialisation order to reason about.

#ifndef C2POOL_XMR_RANDOMX_INIT_LOCK_HPP
#define C2POOL_XMR_RANDOMX_INIT_LOCK_HPP

#include <mutex>

namespace c2pool::xmr {

// The one lock. Function-local static: thread-safe construction (C++11 magic
// statics), no global ctor ordering, usable from any TU.
inline std::mutex& randomx_init_mutex() noexcept {
    static std::mutex m;
    return m;
}

} // namespace c2pool::xmr

#endif // C2POOL_XMR_RANDOMX_INIT_LOCK_HPP
