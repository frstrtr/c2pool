// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_node_rx_verify.hpp
//
// The Path B node's RandomX verifier (receipts, carriers, headers, contexts):
// three light caches and one light VM.
//   * two PIN slots hold the main-chain seeds the open heights name (at most
//     two, set_pins); a pin slot whose seed left the set keeps it until a new
//     pin needs the slot; a pin whose seed height now names another id (a
//     reorg) is released; a pinned seed held in the third slot is promoted in
//     place (no build);
//   * the third slot holds every other seed (alternative branches, old main
//     seeds), the newest replacing the one held.
// A hash never builds a cache unless policy.lazy_prefetch_on_miss (node_rx_policy
// sets it false); a seed not keyed answers RxHash::NotKeyed. key() builds a cache
// off the verifier's lock (the keying thread) and installs it.
// Thread-safe: m_mu guards the slots, the VM and the pin set (held for a hash,
// a residency read, an install; never across a build).
// ===========================================================================
#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/xmr_o2_randomx_verify.hpp"  // RandomXPolicy, O2RandomXVerifier::Mode, Seed32

#if defined(V37_XMR_O2_WITH_RANDOMX)
#include "impl/xmr/pow/randomx_verify.hpp"
#endif

namespace c2pool::v37n::xmr::o2 {

// The node verifier's policy: a hash call never builds a cache.
template <class Cfg>
inline RandomXPolicy node_rx_policy(const Cfg& c) {
    RandomXPolicy p = RandomXPolicy::from_config(c);
    p.lazy_prefetch_on_miss = false;
    return p;
}

struct NodeRxStats {
    std::uint64_t hashes = 0;
    std::uint64_t seed_misses = 0;
    std::uint64_t unavailable = 0;
    std::uint64_t prefetches = 0;  // caches built inside a hash call
    std::uint64_t adopted = 0;     // caches installed by key()
    std::uint64_t promoted = 0;    // pinned seeds taken in place from the third slot
    std::uint64_t released = 0;    // pin slots freed (their seed height names another id)
    std::uint64_t key_failed = 0;
};

class NodeRxVerifier final {
public:
    using Mode = O2RandomXVerifier::Mode;
    using Seed = Seed32;
    using Pin = std::pair<std::uint64_t, Seed>;
    enum class Hashed : std::uint8_t { Ok, NotKeyed, NotReady, Fault };
    static constexpr std::size_t kSlots = 3;

    NodeRxVerifier() = default;
    ~NodeRxVerifier() {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (m_vm) randomx_destroy_vm(m_vm);
#endif
    }
    NodeRxVerifier(const NodeRxVerifier&) = delete;
    NodeRxVerifier& operator=(const NodeRxVerifier&) = delete;

    bool init(const RandomXPolicy& policy) {
        m_policy = policy;
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!policy.enabled) {
            set_mode(Mode::Disabled);
            return false;
        }
        ::c2pool::xmr::VerifierOptions opts;
        opts.large_pages = policy.large_pages;
        opts.secure_jit = policy.secure_jit;
        opts.use_jit = true;
        if (init_(opts)) {
            set_mode(Mode::Jit);
            return true;
        }
        opts.use_jit = false;
        if (init_(opts)) {
            set_mode(Mode::Interpreter);
            return true;
        }
        set_mode(Mode::InitFailed);
        return false;
#else
        set_mode(Mode::CompiledOut);
        return false;
#endif
    }

    Mode mode() const noexcept { return static_cast<Mode>(m_mode.load(std::memory_order_acquire)); }
    bool ready() const {
        const Mode m = mode();
        return m == Mode::Jit || m == Mode::Interpreter;
    }
    std::string mode_name() const { return O2RandomXVerifier::to_string(mode()); }
    const RandomXPolicy& policy() const noexcept { return m_policy; }

    bool resident(const Seed& s) const {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!ready()) return false;
        std::lock_guard<std::mutex> lk(m_mu);
        return slot_of_(s) >= 0;
#else
        (void)s;
        return false;
#endif
    }
    bool seed_resident(const Seed& s) const { return resident(s); }

    Hashed hash(const std::vector<std::uint8_t>& bytes, const Seed& seed, Hash32& pow) {
        using RxHash = Hashed;
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!ready()) {
            m_unavailable.fetch_add(1, std::memory_order_relaxed);
            return RxHash::NotReady;
        }
        if (bytes.empty()) {
            m_unavailable.fetch_add(1, std::memory_order_relaxed);
            return RxHash::Fault;
        }
        std::unique_lock<std::mutex> lk(m_mu);
        int i = slot_of_(seed);
        if (i < 0 && m_policy.lazy_prefetch_on_miss) {
            lk.unlock();
            ::c2pool::xmr::CacheSlot s = build_(seed);
            lk.lock();
            if (s.keyed() && slot_of_(seed) < 0 && adopt_locked_(std::move(s)))
                m_prefetches.fetch_add(1, std::memory_order_relaxed);
            i = slot_of_(seed);
        }
        if (i < 0) {
            m_seed_misses.fetch_add(1, std::memory_order_relaxed);
            return RxHash::NotKeyed;
        }
        bind_(static_cast<std::size_t>(i));
        randomx_calculate_hash(m_vm, bytes.data(), bytes.size(), pow.data());
        m_hashes.fetch_add(1, std::memory_order_relaxed);
        return RxHash::Ok;
#else
        (void)bytes;
        (void)seed;
        (void)pow;
        m_unavailable.fetch_add(1, std::memory_order_relaxed);
        return RxHash::NotReady;
#endif
    }

    // The keying thread: the seed's cache built off m_mu, then installed (a pinned seed in a pin slot, any other in
    // the third slot). true: the seed is resident.
    bool key(const Seed& seed) {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!ready()) {
            m_key_failed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(m_mu);
            if (slot_of_(seed) >= 0) return true;
        }
        ::c2pool::xmr::CacheSlot s = build_(seed);
        std::lock_guard<std::mutex> lk(m_mu);
        if (slot_of_(seed) >= 0) return true;
        if (!s.keyed() || !adopt_locked_(std::move(s))) {
            m_key_failed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        m_adopted.fetch_add(1, std::memory_order_relaxed);
        return true;
#else
        (void)seed;
        m_key_failed.fetch_add(1, std::memory_order_relaxed);
        return false;
#endif
    }

    void set_pins(const std::vector<Pin>& pins) {
        std::lock_guard<std::mutex> lk(m_mu);
        const std::vector<Pin> old = m_pins;
        m_pins.assign(pins.begin(), pins.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(pins.size(), 2)));
#if defined(V37_XMR_O2_WITH_RANDOMX)
        // a pin slot whose seed left the set while its seed height names another id now: released
        for (std::size_t i = 0; i < kSlots; ++i) {
            if (!m_pin_role[i] || !m_slot[i].keyed() || pinned_(m_slot[i].key())) continue;
            bool renamed = false;
            for (const Pin& o : old)
                if (o.second == m_slot[i].key())
                    for (const Pin& n : m_pins) renamed = renamed || (n.first == o.first && n.second != o.second);
            if (renamed) release_(i);
        }
        // a pinned seed held in the third slot: promoted in place
        for (const Pin& n : m_pins) {
            const int a = alt_slot_();
            if (a < 0 || !m_slot[a].holds(n.second)) continue;
            const int j = free_pin_slot_();
            if (j < 0) continue;
            m_pin_role[a] = true;
            m_pin_role[j] = false;
            m_promoted.fetch_add(1, std::memory_order_relaxed);
        }
#endif
    }

    std::vector<Pin> pins() const {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_pins;
    }
    // The seeds resident, slot by slot, with the slot's role (true: pin).
    std::vector<std::pair<bool, Seed>> slots() const {
        std::vector<std::pair<bool, Seed>> out;
#if defined(V37_XMR_O2_WITH_RANDOMX)
        std::lock_guard<std::mutex> lk(m_mu);
        for (std::size_t i = 0; i < kSlots; ++i)
            if (m_slot[i].keyed()) out.emplace_back(m_pin_role[i], m_slot[i].key());
#endif
        return out;
    }

    NodeRxStats stats() const noexcept {
        NodeRxStats s;
        s.hashes = m_hashes.load(std::memory_order_relaxed);
        s.seed_misses = m_seed_misses.load(std::memory_order_relaxed);
        s.unavailable = m_unavailable.load(std::memory_order_relaxed);
        s.prefetches = m_prefetches.load(std::memory_order_relaxed);
        s.adopted = m_adopted.load(std::memory_order_relaxed);
        s.promoted = m_promoted.load(std::memory_order_relaxed);
        s.released = m_released.load(std::memory_order_relaxed);
        s.key_failed = m_key_failed.load(std::memory_order_relaxed);
        return s;
    }

    std::string describe() const {
        const NodeRxStats s = stats();
        std::string o = "randomx: mode=";
        o += O2RandomXVerifier::to_string(mode());
        o += " enabled=";
        o += m_policy.enabled ? '1' : '0';
        o += " large_pages=";
        o += m_policy.large_pages ? '1' : '0';
        o += " lazy=";
        o += m_policy.lazy_prefetch_on_miss ? '1' : '0';
        o += " slots=" + std::to_string(kSlots);
        o += " hashes=" + std::to_string(s.hashes);
        o += " seed_misses=" + std::to_string(s.seed_misses);
        o += " unavailable=" + std::to_string(s.unavailable);
        o += " prefetches=" + std::to_string(s.prefetches);
        o += " adopted=" + std::to_string(s.adopted);
        o += " promoted=" + std::to_string(s.promoted);
        o += " released=" + std::to_string(s.released);
        o += " key_failed=" + std::to_string(s.key_failed);
        return o;
    }

private:
    void set_mode(Mode m) noexcept { m_mode.store(static_cast<std::uint8_t>(m), std::memory_order_release); }
    bool pinned_(const Seed& s) const {
        for (const Pin& p : m_pins)
            if (p.second == s) return true;
        return false;
    }

#if defined(V37_XMR_O2_WITH_RANDOMX)
    bool init_(const ::c2pool::xmr::VerifierOptions& o) {
        std::lock_guard<std::mutex> lk(m_mu);
        if (m_vm) {
            randomx_destroy_vm(m_vm);
            m_vm = nullptr;
        }
        m_opts = o;
        m_bound = nullptr;
        m_bound_keyed = false;
        for (auto& s : m_slot) {
            s = ::c2pool::xmr::CacheSlot(::c2pool::xmr::cache_flags(o));
            if (!s.ok()) return false;
        }
        m_vm = randomx_create_vm(::c2pool::xmr::vm_flags(o), m_slot[0].raw(), nullptr);
        return m_vm != nullptr;
    }
    int slot_of_(const Seed& s) const {
        for (std::size_t i = 0; i < kSlots; ++i)
            if (m_slot[i].holds(s)) return static_cast<int>(i);
        return -1;
    }
    int alt_slot_() const {
        for (std::size_t i = 0; i < kSlots; ++i)
            if (!m_pin_role[i]) return static_cast<int>(i);
        return -1;
    }
    // A pin slot not holding a pinned seed: an unkeyed one first, else one whose seed left the set.
    int free_pin_slot_() const {
        for (std::size_t i = 0; i < kSlots; ++i)
            if (m_pin_role[i] && !m_slot[i].keyed()) return static_cast<int>(i);
        for (std::size_t i = 0; i < kSlots; ++i)
            if (m_pin_role[i] && !pinned_(m_slot[i].key())) return static_cast<int>(i);
        return -1;
    }
    ::c2pool::xmr::CacheSlot build_(const Seed& seed) const {
        randomx_flags f;
        {
            std::lock_guard<std::mutex> lk(m_mu);
            f = ::c2pool::xmr::cache_flags(m_opts);
        }
        ::c2pool::xmr::CacheSlot s(f);
        if (s.ok()) s.rekey(seed);
        return s;
    }
    bool adopt_locked_(::c2pool::xmr::CacheSlot&& built) {
        if (!m_vm || !built.ok() || !built.keyed() || slot_of_(built.key()) >= 0) return false;
        const int v = pinned_(built.key()) ? free_pin_slot_() : alt_slot_();
        if (v < 0) return false;
        const std::size_t i = static_cast<std::size_t>(v);
        const bool was_bound = m_bound == m_slot[i].raw();
        ::c2pool::xmr::CacheSlot gone = std::move(m_slot[i]);  // alive until the VM is re-bound
        m_slot[i] = std::move(built);
        if (was_bound) {
            m_bound_keyed = false;
            bind_(i);
        }
        return true;
    }
    void release_(std::size_t i) {
        if (m_bound == m_slot[i].raw()) {
            m_bound = nullptr;
            m_bound_keyed = false;
            for (std::size_t j = 0; j < kSlots; ++j)
                if (j != i && m_slot[j].keyed()) {
                    bind_(j);
                    break;
                }
        }
        ::c2pool::xmr::CacheSlot gone = std::move(m_slot[i]);
        m_released.fetch_add(1, std::memory_order_relaxed);
    }
    void bind_(std::size_t i) {
        ::c2pool::xmr::CacheSlot& s = m_slot[i];
        if (m_bound != s.raw() || !m_bound_keyed || m_bound_key != s.key()) {
            randomx_vm_set_cache(m_vm, s.raw());
            m_bound = s.raw();
            m_bound_key = s.key();
            m_bound_keyed = true;
        }
    }

    ::c2pool::xmr::VerifierOptions m_opts{};
    ::c2pool::xmr::CacheSlot m_slot[kSlots];
    bool m_pin_role[kSlots] = {true, true, false};
    randomx_vm* m_vm = nullptr;
    randomx_cache* m_bound = nullptr;
    ::c2pool::xmr::SeedHash m_bound_key{};
    bool m_bound_keyed = false;
#endif

    RandomXPolicy m_policy{};
    std::atomic<std::uint8_t> m_mode{static_cast<std::uint8_t>(Mode::CompiledOut)};
    std::vector<Pin> m_pins;
    mutable std::mutex m_mu;
    std::atomic<std::uint64_t> m_hashes{0}, m_seed_misses{0}, m_unavailable{0}, m_prefetches{0}, m_adopted{0},
            m_promoted{0}, m_released{0}, m_key_failed{0};
};

}  // namespace c2pool::v37n::xmr::o2
