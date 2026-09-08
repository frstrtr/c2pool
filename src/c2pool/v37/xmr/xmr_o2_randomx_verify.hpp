// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_o2_randomx_verify.hpp   (Track A2 / X9 O-2, piece 2)
//
// RUNTIME RandomX verify for the c2pool-v37-xmr daemon: the IPowVerifier seam
// of the X5 stratum server (impl/xmr/stratum/xmr_stratum.hpp) implemented over
// the production light-mode verifier (impl/xmr/pow/randomx_verify.hpp,
// librandomx). X8 (#1512) proved that verifier against a REAL mainnet block in
// CI; this component puts the same call sequence — init -> prefetch_epoch ->
// hash()/verify() — on the daemon's LIVE submit path so that every share a
// miner submits is re-hashed here, and a share is promoted to a network block
// only under Monero's EXACT acceptance rule (hash * difficulty < 2^256).
//
// What it fixes versus the two earlier IPowVerifier adapters in the tree:
//   * mbp_wiring.hpp LivePowVerifier never prefetches a seed, so every call
//     returns SeedNotResident ("Couldn't check PoW"). Here the seeds of the
//     current template (seed_hash + next_seed_hash) are prefetched by the
//     new-template hook, OFF the submit path (invariant I2 of randomx_verify).
//   * both adapters decide the NETWORK block with the top-64-bit-word <= target
//     approximation. That test is a strict SUPERSET of Monero's rule (it can
//     accept a boundary hash monerod rejects), so it is fine as the stratum
//     server's cheap gate but must not be what triggers submit_block. This
//     component exposes verify_network_block(), the exact 128-bit rule via
//     c2pool::xmr::meets_difficulty_128 on the template's
//     difficulty / difficulty_top64, for the share sink to call before it
//     patches the nonce and submits.
//
// FAIL-CLOSED. When RandomX is compiled out (V37_XMR_O2_WITH_RANDOMX not
// defined), disabled (cfg.randomx_enabled == false), or failed to initialise,
// randomx_hash() returns false (=> SubmitError::CouldNotCheck for every share)
// and verify_network_block() returns VerifyUnavailable, so no unverified block
// can ever be submitted (xmr_node_config.hpp: "no unverified block is ever
// submitted"). The daemon may still run observe-side in that state.
//
// THREADING (O-2 assembly contract, survey §E). LightVerifier is NOT
// thread-safe, so this object is owned by the stratum LISTENER thread: init(),
// drain_pending()/ensure_seeds(), randomx_hash(), verify_network_block() are
// listener-thread calls. The ONLY cross-thread entry is post_seeds() — the main
// thread's template refresher hands over the new template's seed pair through a
// mutex-guarded mailbox, and the listener applies it (Argon2d cache init,
// seconds on an epoch change, no-op otherwise) when it wakes for the
// "template changed" signal, BEFORE it broadcast_job()s. Counters are atomics
// so the main loop can print them (O-3 observability).
//
// CONSUMER-TREE ONLY: no consensus digest; calls the merged pow/ + stratum/
// seams exactly as their headers document. Header-only, no new CMake target of
// its own — the assemble step links `randomx` into c2pool-v37-xmr and defines
// V37_XMR_O2_WITH_RANDOMX (see the O-2 integration notes).
// ===========================================================================
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/stratum/xmr_stratum.hpp"

#if defined(V37_XMR_O2_WITH_RANDOMX)
#include "impl/xmr/pow/randomx_verify.hpp"   // LightVerifier, meets_difficulty_128
#endif

namespace c2pool::v37n::xmr::o2 {

namespace strat = ::v37::xmr::stratum;

// 32-byte RandomX seed (a Monero block id) / 32-byte PoW hash. Same shape as
// strat::TemplateJob::seed_hash and c2pool::xmr::SeedHash (std::array<u8,32>),
// so the stratum job's seed is passed through without conversion.
using Seed32 = std::array<std::uint8_t, strat::HASH_SIZE>;
using Hash32 = std::array<std::uint8_t, strat::HASH_SIZE>;

// ---------------------------------------------------------------------------
// Policy — the daemon's RandomX knobs (xmr_node_config.hpp:103-109 +
// --randomx in main_v37_xmr.cpp). from_config() is a template so this header
// stays free of the config/sharechain includes (any struct with the two
// fields works, e.g. XmrNodeConfig).
// ---------------------------------------------------------------------------
struct RandomXPolicy {
    bool enabled     = false;   // cfg.randomx_enabled   (--randomx)
    bool large_pages = false;   // cfg.randomx_large_pages
    bool secure_jit  = false;   // RANDOMX_FLAG_SECURE (W^X JIT pages); opt-in
    // Invariant I2 of randomx_verify.hpp: never Argon2d-init a cache on the
    // submit hot path. Default STRICT: a submit whose seed is not resident
    // gets CouldNotCheck. Set true only for single-rig demos where a missed
    // new-template hook is preferable to a rejected share (it then costs
    // ~1-2 s once per epoch, on the listener thread, inside that submit).
    bool lazy_prefetch_on_miss = false;

    template <class Cfg>
    static RandomXPolicy from_config(const Cfg& c) {
        RandomXPolicy p;
        p.enabled     = c.randomx_enabled;
        p.large_pages = c.randomx_large_pages;
        return p;
    }
};

// Monero difficulty_type as returned by get_block_template / get_miner_data:
// `difficulty` (low 64) and `difficulty_top64` (high 64). Regtest/stagenet
// (and mainnet today) fit in `lo`; `hi` is carried so the rule stays exact.
struct NetworkDifficulty {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
    bool is_zero() const noexcept { return lo == 0 && hi == 0; }
};

// Outcome of the exact network-block gate (verify_network_block).
enum class NetworkVerdict : std::uint8_t {
    Accept,             // re-hashed here; hash * difficulty < 2^256  -> submit it
    BelowTarget,        // re-hashed here; does NOT meet the network difficulty
    SeedNotResident,    // seed not prefetched (new-template hook missed)
    VerifyUnavailable,  // RandomX compiled out / disabled / init failed (fail-closed)
    Malformed,          // empty blob or zero difficulty — never a block
};

inline const char* to_string(NetworkVerdict v) noexcept {
    switch (v) {
        case NetworkVerdict::Accept:            return "Accept";
        case NetworkVerdict::BelowTarget:       return "BelowTarget";
        case NetworkVerdict::SeedNotResident:   return "SeedNotResident";
        case NetworkVerdict::VerifyUnavailable: return "VerifyUnavailable";
        case NetworkVerdict::Malformed:         return "Malformed";
    }
    return "?";
}

// Plain-value counters snapshot for the main loop's periodic status line.
struct RandomXStats {
    std::uint64_t hashes          = 0;  // randomx_hash() calls that produced a hash
    std::uint64_t seed_misses     = 0;  // randomx_hash() refused: seed not resident
    std::uint64_t unavailable     = 0;  // randomx_hash() refused: engine unavailable
    std::uint64_t prefetches      = 0;  // ensure_seeds() calls that (re)keyed a cache
    std::uint64_t network_accepts = 0;  // verify_network_block() -> Accept
    std::uint64_t network_rejects = 0;  // verify_network_block() -> anything else
    std::uint64_t memo_hits       = 0;  // network verify reused the submit's hash
};

// ---------------------------------------------------------------------------
// O2RandomXVerifier — the runtime IPowVerifier + exact network gate.
// ---------------------------------------------------------------------------
class O2RandomXVerifier final : public strat::IPowVerifier {
public:
    enum class Mode : std::uint8_t {
        CompiledOut,   // V37_XMR_O2_WITH_RANDOMX not defined (light build)
        Disabled,      // policy.enabled == false (--randomx not given)
        InitFailed,    // librandomx present but cache/VM alloc failed (OOM?)
        Jit,           // ready: JIT-compiled light VM (fast path)
        Interpreter,   // ready: portable interpreter (JIT refused, e.g. W^X)
    };

    static const char* to_string(Mode m) noexcept {
        switch (m) {
            case Mode::CompiledOut: return "compiled-out";
            case Mode::Disabled:    return "disabled";
            case Mode::InitFailed:  return "init-failed";
            case Mode::Jit:         return "jit";
            case Mode::Interpreter: return "interpreter";
        }
        return "?";
    }

    O2RandomXVerifier() = default;
    O2RandomXVerifier(const O2RandomXVerifier&) = delete;
    O2RandomXVerifier& operator=(const O2RandomXVerifier&) = delete;

    // -----------------------------------------------------------------------
    // init — allocate 2 x 256 MiB light caches + 1 light VM (never FULL_MEM).
    // JIT first; if randomx_create_vm refuses JIT pages, retry with the
    // portable interpreter (identical hashes; pattern of randomx_verify_kat
    // suite C). Returns ready(). Call once, before the listener starts
    // serving (from the listener thread, or from main BEFORE the listener
    // thread is spawned — the object has no thread affinity, only a
    // no-concurrent-use rule).
    // -----------------------------------------------------------------------
    bool init(const RandomXPolicy& policy) {
        m_policy = policy;
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!policy.enabled) { set_mode(Mode::Disabled); return false; }
        ::c2pool::xmr::VerifierOptions opts;      // algo = RX_0 (RANDOMX_FLAG_V2 OFF)
        opts.large_pages = policy.large_pages;
        opts.secure_jit  = policy.secure_jit;
        opts.use_jit     = true;
        if (m_vm.init(opts)) { set_mode(Mode::Jit); return true; }
        // init() is safe to re-run: a failed randomx_create_vm leaves vm_ null
        // and the CacheSlots are move-reassigned (frees any cache already
        // allocated) — see the KAT's suite-C comment.
        opts.use_jit = false;
        if (m_vm.init(opts)) { set_mode(Mode::Interpreter); return true; }
        set_mode(Mode::InitFailed);
        return false;
#else
        set_mode(Mode::CompiledOut);
        return false;
#endif
    }

    Mode mode() const noexcept { return static_cast<Mode>(m_mode.load(std::memory_order_acquire)); }
    bool ready() const noexcept {
        const Mode m = mode();
        return m == Mode::Jit || m == Mode::Interpreter;
    }
    // The fail-closed switch the share sink must consult: a network block may
    // be submitted only when this is true (and verify_network_block() said
    // Accept for the exact bytes being submitted).
    bool network_blocks_allowed() const noexcept { return ready(); }
    const RandomXPolicy& policy() const noexcept { return m_policy; }

    // -----------------------------------------------------------------------
    // Seed handling (the LivePowVerifier defect fix).
    //
    // post_seeds   — ANY thread (the main loop's template refresher). Parks the
    //                template's {seed_hash, next_seed_hash} in the mailbox.
    // drain_pending — LISTENER thread. Applies a parked seed pair via
    //                ensure_seeds(). Call it first thing when the listener
    //                wakes for "template changed", before broadcast_job().
    //                Returns true iff a pair was applied.
    // ensure_seeds — LISTENER thread. prefetch_epoch(current, next): Argon2d
    //                inits only the caches not already keyed (seconds on an
    //                epoch change, no-op otherwise). Returns residency of
    //                `current`.
    // on_template  — convenience: ensure_seeds(job.seed_hash, job.next_seed_hash)
    //                for any struct shaped like strat::TemplateJob.
    // -----------------------------------------------------------------------
    void post_seeds(const Seed32& current, const std::optional<Seed32>& next) {
        std::lock_guard<std::mutex> lk(m_mail_mu);
        m_mail_cur  = current;
        m_mail_next = next;
        m_mail_full = true;
    }

    bool drain_pending() {
        Seed32 cur{};
        std::optional<Seed32> next;
        {
            std::lock_guard<std::mutex> lk(m_mail_mu);
            if (!m_mail_full) return false;
            cur = m_mail_cur; next = m_mail_next;
            m_mail_full = false;
        }
        ensure_seeds(cur, next);
        return true;
    }

    bool ensure_seeds(const Seed32& current, const std::optional<Seed32>& next) {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!ready()) return false;
        const bool cur_res  = m_vm.seed_resident(current);
        const bool next_res = !next || m_vm.seed_resident(*next);
        if (cur_res && next_res) return true;                    // nothing to do
        if (!m_vm.prefetch_epoch(current, next)) return false;    // null cache (init not done)
        m_stat_prefetches.fetch_add(1, std::memory_order_relaxed);
        return m_vm.seed_resident(current);
#else
        (void)current; (void)next;
        return false;
#endif
    }

    template <class Job>
    bool on_template(const Job& job) { return ensure_seeds(job.seed_hash, job.next_seed_hash); }

    bool seed_resident(const Seed32& seed) const noexcept {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        return ready() && m_vm.seed_resident(seed);
#else
        (void)seed;
        return false;
#endif
    }

    // -----------------------------------------------------------------------
    // IPowVerifier — what XmrStratumServer::handle_submit calls
    // (xmr_stratum.cpp:393 / :403 / :409). Listener thread.
    // -----------------------------------------------------------------------

    // Authoritative re-hash of the submitted share's blob (nonce already
    // patched by the server). false => SubmitError::CouldNotCheck. Never
    // trusts the client's `result`. Under invariant I2 a non-resident seed is
    // a refusal, not a cache init — unless policy.lazy_prefetch_on_miss.
    bool randomx_hash(const std::uint8_t* blob, std::size_t blob_size,
                      std::uint64_t height,
                      const Seed32& seed_hash,
                      Hash32& out_hash,
                      bool /*force_light: this verifier is light-only*/ = false) override {
        (void)height;   // epoch selection is the template's seed_hash (monerod-supplied)
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!ready() || !blob || blob_size == 0) {
            m_stat_unavailable.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if (!m_vm.seed_resident(seed_hash)) {
            if (!m_policy.lazy_prefetch_on_miss ||
                !m_vm.prefetch_epoch(seed_hash, std::nullopt) ||
                !m_vm.seed_resident(seed_hash)) {
                m_stat_seed_misses.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            m_stat_prefetches.fetch_add(1, std::memory_order_relaxed);
        }
        if (!m_vm.hash(blob, blob_size, seed_hash, out_hash.data())) {
            m_stat_seed_misses.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        m_stat_hashes.fetch_add(1, std::memory_order_relaxed);
        remember(blob, blob_size, seed_hash, out_hash);
        return true;
#else
        (void)blob; (void)blob_size; (void)seed_hash; (void)out_hash;
        m_stat_unavailable.fetch_add(1, std::memory_order_relaxed);
        return false;
#endif
    }

    // The u64-target test the seam documents (top 64-bit LE word <= target,
    // target = 0xFFFF…/difficulty per xmr_stratum.cpp target_from_diff). It is
    // exactly Monero's rule when the low 192 bits contribute no carry, and a
    // SUPERSET of it otherwise — correct for the lane/share target, and safe
    // as the server's cheap network pre-gate because it never misses a real
    // block; the exact decision is verify_network_block() below.
    bool meets_target(const Hash32& hash, std::uint64_t target) const override {
        std::uint64_t top = 0;
        for (int i = 0; i < 8; ++i)
            top |= static_cast<std::uint64_t>(hash[strat::HASH_SIZE - 8 + i]) << (8 * i);
        return top <= target;
    }

    // -----------------------------------------------------------------------
    // EXACT network-block gate — for IShareSink::submit_network_block.
    //
    // `blob` = the hashing blob with the winning nonce patched (the same bytes
    // the server just hashed); `seed` = the template's seed_hash; `diff` = the
    // template's {difficulty, difficulty_top64}. Re-hashes (or reuses the
    // byte-identical hash memoised by the preceding randomx_hash() call) and
    // applies c2pool::xmr::meets_difficulty_128 — hash * difficulty < 2^256,
    // the rule monerod's submit_block will apply. Only an Accept may lead to a
    // submit_block; out_hash receives the PoW hash for logging.
    // Listener thread.
    // -----------------------------------------------------------------------
    NetworkVerdict verify_network_block(const std::uint8_t* blob, std::size_t blob_size,
                                        const Seed32& seed, NetworkDifficulty diff,
                                        Hash32& out_hash) {
        if (!blob || blob_size == 0 || diff.is_zero()) { count_reject(); return NetworkVerdict::Malformed; }
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!ready()) { count_reject(); return NetworkVerdict::VerifyUnavailable; }
        if (!m_vm.seed_resident(seed)) { count_reject(); return NetworkVerdict::SeedNotResident; }
        if (recall(blob, blob_size, seed, out_hash)) {
            m_stat_memo_hits.fetch_add(1, std::memory_order_relaxed);
        } else if (!m_vm.hash(blob, blob_size, seed, out_hash.data())) {
            count_reject(); return NetworkVerdict::SeedNotResident;
        } else {
            m_stat_hashes.fetch_add(1, std::memory_order_relaxed);
            remember(blob, blob_size, seed, out_hash);
        }
        if (::c2pool::xmr::meets_difficulty_128(out_hash.data(), diff.lo, diff.hi)) {
            m_stat_network_accepts.fetch_add(1, std::memory_order_relaxed);
            return NetworkVerdict::Accept;
        }
        count_reject();
        return NetworkVerdict::BelowTarget;
#else
        (void)seed; (void)out_hash;
        count_reject();
        return NetworkVerdict::VerifyUnavailable;
#endif
    }

    // Exact rule on an already-computed hash (no residency needed). Fail-closed
    // when RandomX is compiled out: without the engine nothing here has been
    // verified, so nothing may be promoted.
    static bool meets_network_difficulty(const Hash32& hash, NetworkDifficulty diff) noexcept {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (diff.is_zero()) return false;
        return ::c2pool::xmr::meets_difficulty_128(hash.data(), diff.lo, diff.hi);
#else
        (void)hash; (void)diff;
        return false;
#endif
    }

    // -----------------------------------------------------------------------
    // Observability (any thread).
    // -----------------------------------------------------------------------
    RandomXStats stats() const noexcept {
        RandomXStats s;
        s.hashes          = m_stat_hashes.load(std::memory_order_relaxed);
        s.seed_misses     = m_stat_seed_misses.load(std::memory_order_relaxed);
        s.unavailable     = m_stat_unavailable.load(std::memory_order_relaxed);
        s.prefetches      = m_stat_prefetches.load(std::memory_order_relaxed);
        s.network_accepts = m_stat_network_accepts.load(std::memory_order_relaxed);
        s.network_rejects = m_stat_network_rejects.load(std::memory_order_relaxed);
        s.memo_hits       = m_stat_memo_hits.load(std::memory_order_relaxed);
        return s;
    }

    // One status line for stdout, e.g.
    //   "randomx: mode=jit enabled=1 large_pages=0 hashes=17 seed_misses=0
    //    unavailable=0 prefetches=1 net_accept=1 net_reject=0 memo_hits=1"
    std::string describe() const {
        const RandomXStats s = stats();
        std::string o = "randomx: mode=";
        o += to_string(mode());
        o += " enabled=";     o += m_policy.enabled ? '1' : '0';
        o += " large_pages="; o += m_policy.large_pages ? '1' : '0';
        o += " lazy=";        o += m_policy.lazy_prefetch_on_miss ? '1' : '0';
        o += " hashes=";      o += std::to_string(s.hashes);
        o += " seed_misses="; o += std::to_string(s.seed_misses);
        o += " unavailable="; o += std::to_string(s.unavailable);
        o += " prefetches=";  o += std::to_string(s.prefetches);
        o += " net_accept=";  o += std::to_string(s.network_accepts);
        o += " net_reject=";  o += std::to_string(s.network_rejects);
        o += " memo_hits=";   o += std::to_string(s.memo_hits);
        return o;
    }

private:
    void set_mode(Mode m) noexcept { m_mode.store(static_cast<std::uint8_t>(m), std::memory_order_release); }
    void count_reject() noexcept { m_stat_network_rejects.fetch_add(1, std::memory_order_relaxed); }

    // Single-entry memo of the last hash computed: handle_submit calls
    // randomx_hash() and then, on the same thread, the sink calls
    // verify_network_block() on the SAME bytes. Reuse only on byte-identical
    // blob AND seed; anything else recomputes. Listener thread only.
    void remember(const std::uint8_t* blob, std::size_t n, const Seed32& seed, const Hash32& hash) {
        m_memo_blob.assign(blob, blob + n);
        m_memo_seed  = seed;
        m_memo_hash  = hash;
        m_memo_valid = true;
    }
    bool recall(const std::uint8_t* blob, std::size_t n, const Seed32& seed, Hash32& hash) const {
        if (!m_memo_valid || m_memo_blob.size() != n || m_memo_seed != seed) return false;
        if (n && std::memcmp(m_memo_blob.data(), blob, n) != 0) return false;
        hash = m_memo_hash;
        return true;
    }

    RandomXPolicy              m_policy{};
    std::atomic<std::uint8_t>  m_mode{static_cast<std::uint8_t>(Mode::CompiledOut)};

#if defined(V37_XMR_O2_WITH_RANDOMX)
    ::c2pool::xmr::LightVerifier m_vm;           // listener thread only
#endif

    // seed mailbox (main thread -> listener thread)
    std::mutex             m_mail_mu;
    Seed32                 m_mail_cur{};
    std::optional<Seed32>  m_mail_next;
    bool                   m_mail_full = false;

    // last-hash memo (listener thread only)
    std::vector<std::uint8_t> m_memo_blob;
    Seed32                    m_memo_seed{};
    Hash32                    m_memo_hash{};
    bool                      m_memo_valid = false;

    // counters (relaxed atomics; read by the main loop for status lines)
    std::atomic<std::uint64_t> m_stat_hashes{0};
    std::atomic<std::uint64_t> m_stat_seed_misses{0};
    std::atomic<std::uint64_t> m_stat_unavailable{0};
    std::atomic<std::uint64_t> m_stat_prefetches{0};
    std::atomic<std::uint64_t> m_stat_network_accepts{0};
    std::atomic<std::uint64_t> m_stat_network_rejects{0};
    std::atomic<std::uint64_t> m_stat_memo_hits{0};
};

} // namespace c2pool::v37n::xmr::o2
