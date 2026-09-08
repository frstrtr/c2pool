#pragma once
// V37 Track A2 step (b)(2) — the LIVE mainchain index for carrier admission.
// CONSUMER-tree code (src/c2pool/v37/). Implements the W2 IMainchainIndex seam
// (w2_admission.hpp:46-49) against the node's REAL coin daemon instead of the
// synthetic {mainchain_hash(h) -> h} map the W2/W3 KATs install, and keeps that
// synthetic model reachable as a sibling class so the KATs and the daemon's
// --carrier-synthetic-index debug flag select ONE of the two behind ONE seam.
//
// NON-CONSENSUS: this is the node's view of its own mainchain, injected through
// the seam. Every append still rides CarrierRelay -> CarrierIngest -> V37Engine;
// nothing under src/sharechain/v37 is touched.
//
// THE SEAM CONTRACT (w2_admission.hpp:44-45): "height_of(hashPrevBlock) with a
// CONTEXT HORIZON; unresolvable within the horizon -> nullopt". W2 consumes it at
// admit :198 (carrier bin -> REJECT_POW on nullopt / lz != consensus_lz(bin)),
// validate_receipt :169 (R-1 pin) and admit :226 (origin bin); receipts are
// bounded by N_CTX=2 RELATIVE TO THE CARRIER BIN (:180), never relative to the
// tip. So the horizon vs the tip is THIS class's job — the synthetic map had it
// by construction (tip-64..tip), a live daemon answers getblockheader for ANY
// known header on ANY branch (dash_rpc_coin_backend.hpp:405-411). Without the
// horizon a carrier keyed to a side-branch block, or to an ancient block whose
// consensus_lz is the EASY 8 bits (w2_receipt.hpp:77-79), would be admitted.
//
// WHAT height_of RESOLVES (LiveMainchainIndex):
//   Have + on the active chain + tip - height <= horizon     -> height
//   Have, off the active chain (dashd confirmations == -1)   -> nullopt (inactive)
//   Have, tip - height > horizon                             -> nullopt (beyond horizon)
//   Have, height > tip (index's tip view was stale)          -> refresh the tip ONCE,
//                                                               then re-judge; still
//                                                               ahead -> nullopt (future)
//   Missing (dashd answered -5 "Block not found")            -> nullopt, NO retry
//   Unknown (transport hiccup / -28 warmup / IBD tip)        -> bounded in-index retry
//                                                               (Options::unknown_patience,
//                                                               default 2 s) then nullopt
//
// TRI-STATE (survey gap I-2): the seam is binary (optional), so a transient
// dashd outage on a REJECT_POW path would otherwise be indistinguishable from a
// bogus carrier. The retry is bounded and small BECAUSE height_of runs on the
// peer reader thread (carrier_net.hpp reader_loop -> CarrierRelay::handle_inbound
// -> CarrierIngest AdmitFn) UNDER CarrierIngest::m_mtx (carrier_ingest.hpp:110),
// and on the stratum submit thread for the node's own emitted wins
// (CarrierEmitter -> CarrierRelay::handle_local -> the same AdmitFn). A 2 s
// stall there under a dashd hiccup is acceptable at bring-up; it is NOT a
// substitute for a defer/re-flood path (RelaySeenSet marks only on admitted,
// w3_relay.hpp, so a peer's later re-flood can still admit; the ORIGIN node's
// own win has no retry beyond this — stated, not solved here).
//
// COST (survey gap I-3): W2 asks height_of up to 1 + 2*R_MAX = 9 times per
// carrier (:198, :169, :226), and the receipt hash is asked TWICE (:169 and
// :226). A header's height is immutable and its active-chain status changes only
// on a reorg, so Have results are cached per hash for Options::cache_ttl
// (default 2 s, i.e. a few height-watch polls) — the second ask of the same
// hash and every carrier keyed to the same recent block cost no RPC. Missing
// and Unknown are never cached (a block may arrive a moment later). The cache
// is bounded (Options::cache_cap; cleared wholesale when full — a cache, not
// state). invalidate() drops it; the daemon may call it on its D11 reorg
// signal (optional; the TTL bounds staleness anyway).
//
// THE TIP: the horizon needs the node's best active height. Two sources, both
// optional, combined: observe_tip(h) is a PUSH from the daemon's height-watch
// (one line in its poll loop; zero RPC on the reader thread), and TipFn is a
// PULL fallback (the backend's sticky best_tip(); one getblockchaininfo per
// Options::cache_ttl at most, plus one forced refresh when a header claims to
// be ahead of the cached tip). With neither source ever answering, EVERYTHING
// is unresolvable (fail-closed) — by design.
//
// BYTE ORDER (D6): a WorkEvent.prev_block_hash is header/INTERNAL order
// (w2_receipt.hpp share-format §2), the reverse of the display hex dashd's
// getblockheader parses. This header is stdlib-only and does not know dashd;
// the bound ProbeFn does the reversal — make_backend_probe() takes the
// display-hex function explicitly (the daemon passes
// c2pool::v37n::btc::display_hex_of_bytes32, dash_rpc_coin_backend.hpp:196-198)
// so the ONE byte-order pin stays in the backend header and is never duplicated
// here. (The landed b4c91687 bug — hex32(prev) internal-order hex fed to a
// display-hex API, main_v37_btc_dash.cpp@b4c91687:316-319 — is exactly the
// duplication this refuses.)
//
// STAYS SYNTHETIC / OUT OF SCOPE (honest boundary): the carrier's PoW envelope
// (sha256d over the RDWR preimage, lz bits, consensus_lz schedule) and the
// share tracker (MemShareTracker — a sharechain fact dashd cannot answer; its
// real binding is the W6 persisted share store). This file de-synthesizes the
// INDEX only.
//
// stdlib-only (like carrier_ingest.hpp / carrier_emit.hpp): usable from the
// Threads-only KATs. The daemon instantiates the make_backend_* templates with
// its DashRpcCoinBackend; nothing here includes the heavy backend header.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

#include "w2_admission.hpp"   // IMainchainIndex (the fixed W2 seam)
#include "w2_receipt.hpp"     // bytes32, u64, mainchain_hash (the synthetic KAT model)

namespace c2pool::v37n {

// ── one header probe, honestly tri-state (mirrors btc::HeaderProbe) ─────────
struct IndexProbe {
    enum class State : std::uint8_t { Have = 0, Missing = 1, Unknown = 2 };
    State state           = State::Unknown;
    u64   height          = 0;       // valid when Have (any branch)
    bool  on_active_chain = false;   // valid when Have

    static IndexProbe have(u64 h, bool active) {
        IndexProbe p; p.state = State::Have; p.height = h; p.on_active_chain = active; return p;
    }
    static IndexProbe missing() { IndexProbe p; p.state = State::Missing; return p; }
    static IndexProbe unknown() { return IndexProbe{}; }
};

// ═══════════════════════════════════════════════════════════════════════════
// LiveMainchainIndex — IMainchainIndex over a live header probe + a tip view,
// with the context horizon, bounded Unknown retry, and a per-hash Have cache.
// Thread-safe on its own (the mutex guards only the caches/stats; it is NEVER
// held across a probe, a tip pull, or a retry sleep).
// ═══════════════════════════════════════════════════════════════════════════
class LiveMainchainIndex final : public IMainchainIndex {
public:
    // prev_block_hash in header/INTERNAL order -> one header probe.
    using ProbeFn = std::function<IndexProbe(const bytes32& prev_block_internal)>;
    // The node's best ACTIVE height; nullopt when unknown (unreachable / IBD).
    using TipFn   = std::function<std::optional<u64>()>;

    struct Options {
        u64                       horizon = 64;             // == the KAT model's tip-64..tip
        std::chrono::milliseconds unknown_patience{2000};   // bounded retry on Unknown
        std::chrono::milliseconds unknown_backoff{100};
        std::chrono::milliseconds cache_ttl{2000};          // Have entries + pulled tip
        std::size_t               cache_cap = 4096;         // entries; cleared when hit
    };

    // (two ctors rather than `Options opt = {}`: GCC 13 rejects a defaulted
    //  argument of a nested struct with default member initializers here —
    //  the same note as DashRpcCoinBackend's constructors.)
    LiveMainchainIndex(ProbeFn probe, TipFn tip)
        : m_probe(std::move(probe)), m_tip(std::move(tip)), m_opt() {}
    LiveMainchainIndex(ProbeFn probe, TipFn tip, Options opt)
        : m_probe(std::move(probe)), m_tip(std::move(tip)), m_opt(opt) {}

    // ── the seam ────────────────────────────────────────────────────────────
    std::optional<u64> height_of(const bytes32& prev_block_hash) const override {
        using clock = std::chrono::steady_clock;
        std::optional<clock::time_point> deadline;   // armed on the first Unknown

        // Bounded wait on Unknown: false = keep trying, true = patience spent.
        auto spent = [&]() -> bool {
            const auto now = clock::now();
            if (!deadline) deadline = now + m_opt.unknown_patience;
            if (now >= *deadline) return true;
            { std::lock_guard<std::mutex> g(m_mu); ++m_st.unknown_retries; }
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now);
            std::this_thread::sleep_for(std::min(m_opt.unknown_backoff, left));
            return false;
        };

        // (1) the header: cache, else probe (retry only on Unknown).
        IndexProbe p;
        for (;;) {
            if (auto c = cached(prev_block_hash)) { p = *c; break; }
            p = m_probe ? m_probe(prev_block_hash) : IndexProbe::unknown();
            { std::lock_guard<std::mutex> g(m_mu); ++m_st.probes; }
            if (p.state == IndexProbe::State::Have)    { remember(prev_block_hash, p); break; }
            if (p.state == IndexProbe::State::Missing) { bump(&Stats::missing); return std::nullopt; }
            if (spent())                               { bump(&Stats::unknown_exhausted); return std::nullopt; }
        }
        if (!p.on_active_chain) { bump(&Stats::inactive); return std::nullopt; }

        // (2) the horizon against the tip. If the header claims to be AHEAD of
        //     the tip view, that view was stale: force ONE refresh, re-judge;
        //     still ahead -> "future" (never spun on).
        bool force = false, refreshed = false;
        for (;;) {
            const std::optional<u64> tip = tip_view(force);
            force = false;
            if (!tip) {   // no tip known at all yet (no push, no good pull)
                if (spent()) { bump(&Stats::unknown_exhausted); return std::nullopt; }
                force = true;   // after the backoff, pull again
                continue;
            }
            if (p.height > *tip) {
                if (!refreshed) { refreshed = true; force = true; continue; }
                bump(&Stats::future);
                return std::nullopt;
            }
            if (*tip - p.height > m_opt.horizon) { bump(&Stats::beyond_horizon); return std::nullopt; }
            bump(&Stats::resolved);
            return p.height;
        }
    }

    // ── tip push (from the daemon's height-watch; optional) ─────────────────
    void observe_tip(u64 height) {
        std::lock_guard<std::mutex> g(m_mu);
        m_tip_height = height;
        m_tip_at     = std::chrono::steady_clock::now();
    }
    // Drop the Have cache (e.g. on a reorg signal). The tip view is kept.
    void invalidate() {
        std::lock_guard<std::mutex> g(m_mu);
        m_cache.clear();
        ++m_st.invalidations;
    }

    // ── telemetry (never consensus) ─────────────────────────────────────────
    struct Stats {
        std::uint64_t probes = 0, cache_hits = 0, resolved = 0;
        std::uint64_t missing = 0, inactive = 0, beyond_horizon = 0, future = 0;
        std::uint64_t unknown_retries = 0, unknown_exhausted = 0;
        std::uint64_t tip_pulls = 0, invalidations = 0;
    };
    Stats stats() const { std::lock_guard<std::mutex> g(m_mu); return m_st; }
    const Options& options() const { return m_opt; }

private:
    struct Entry { IndexProbe p; std::chrono::steady_clock::time_point at; };

    std::optional<IndexProbe> cached(const bytes32& h) const {
        std::lock_guard<std::mutex> g(m_mu);
        auto it = m_cache.find(h);
        if (it == m_cache.end()) return std::nullopt;
        if (std::chrono::steady_clock::now() - it->second.at >= m_opt.cache_ttl) {
            m_cache.erase(it);
            return std::nullopt;
        }
        ++m_st.cache_hits;
        return it->second.p;
    }
    void remember(const bytes32& h, const IndexProbe& p) const {
        std::lock_guard<std::mutex> g(m_mu);
        if (m_cache.size() >= m_opt.cache_cap) m_cache.clear();
        m_cache[h] = Entry{p, std::chrono::steady_clock::now()};
    }
    // The tip view: the fresh cached value (pushed or pulled), else a pull
    // through TipFn (stored on success), else the last-known value even if
    // stale (sticky, like the backend's own best_tip(); a push-only index has
    // no other source), else nullopt. `force` skips the freshness check.
    std::optional<u64> tip_view(bool force) const {
        {
            std::lock_guard<std::mutex> g(m_mu);
            const bool fresh = m_tip_height.has_value() &&
                (std::chrono::steady_clock::now() - m_tip_at) < m_opt.cache_ttl;
            if ((fresh && !force) || !m_tip) return m_tip_height;
        }
        std::optional<u64> t;
        try { t = m_tip(); } catch (const std::exception&) { t.reset(); }
        std::lock_guard<std::mutex> g(m_mu);
        ++m_st.tip_pulls;
        if (t) { m_tip_height = t; m_tip_at = std::chrono::steady_clock::now(); }
        return m_tip_height;   // sticky last-known on a failed pull
    }
    void bump(std::uint64_t Stats::*f) const {
        std::lock_guard<std::mutex> g(m_mu);
        ++(m_st.*f);
    }

    ProbeFn m_probe;
    TipFn   m_tip;
    Options m_opt;
    mutable std::mutex                            m_mu;
    mutable std::map<bytes32, Entry>              m_cache;
    mutable std::optional<u64>                    m_tip_height;
    mutable std::chrono::steady_clock::time_point m_tip_at{};
    mutable Stats                                 m_st;
};

// ═══════════════════════════════════════════════════════════════════════════
// SyntheticMainchainIndex — the W2/W3 KAT model behind the SAME seam:
// {mainchain_hash(h) -> h | h in [tip-horizon, tip]} (w2_receipt.hpp:191-197),
// byte-for-byte the resolver v37_a2_multinode_test.cpp:99-107 and the daemon's
// --carrier-synthetic-index branch (main_v37_btc_dash.cpp:336-349) build by hand.
// Kept so the KATs and the debug flag stay selectable; set_tip() lets a
// loopback drill advance the synthetic chain. NOT the live chain: under this
// index the daemon's own wins (keyed to REAL parent hashes) are REJECT_POW
// locally by design — the daemon warns once at boot.
// ═══════════════════════════════════════════════════════════════════════════
class SyntheticMainchainIndex final : public IMainchainIndex {
public:
    explicit SyntheticMainchainIndex(u64 tip, u64 horizon = 64) { set_tip(tip, horizon); }

    std::optional<u64> height_of(const bytes32& prev_block_hash) const override {
        std::lock_guard<std::mutex> g(m_mu);
        auto it = m_by_hash.find(prev_block_hash);
        return it == m_by_hash.end() ? std::nullopt : std::optional<u64>(it->second);
    }
    void set_tip(u64 tip, u64 horizon = 64) {
        std::map<bytes32, u64> m;
        const u64 lo = tip > horizon ? tip - horizon : 0;
        for (u64 x = lo; x <= tip; ++x) m[mainchain_hash(x)] = x;
        std::lock_guard<std::mutex> g(m_mu);
        m_by_hash = std::move(m);
        m_tip     = tip;
        m_horizon = horizon;
    }
    u64 tip() const     { std::lock_guard<std::mutex> g(m_mu); return m_tip; }
    u64 horizon() const { std::lock_guard<std::mutex> g(m_mu); return m_horizon; }

private:
    mutable std::mutex     m_mu;
    std::map<bytes32, u64> m_by_hash;
    u64 m_tip = 0, m_horizon = 64;
};

// ═══════════════════════════════════════════════════════════════════════════
// Backend bindings — templates so this header stays stdlib-only; the daemon
// instantiates them with DashRpcCoinBackend (dash_rpc_coin_backend.hpp), whose
// surface they rely on:
//   HeaderProbe probe_header(const std::string& display_hex) noexcept
//       -> .state (Have/Missing/Unknown), .height, .on_active_chain()   (:422-447)
//   CoinTip best_tip()  -> .height, .hash (sticky last-good; {0,"",0} before
//       the first good read; may throw ChainMismatch)                  (:330-338)
// `display_hex_of` = the byte-order pin (btc::display_hex_of_bytes32, :196-198):
// internal 32 bytes -> the display hex getblockheader parses.
// ═══════════════════════════════════════════════════════════════════════════
template <class Backend>
LiveMainchainIndex::ProbeFn
make_backend_probe(std::shared_ptr<Backend> be,
                   std::function<std::string(const bytes32&)> display_hex_of) {
    return [be, display_hex_of](const bytes32& prev_internal) -> IndexProbe {
        if (!be || !display_hex_of) return IndexProbe::unknown();
        const auto p = be->probe_header(display_hex_of(prev_internal));
        using S = std::decay_t<decltype(p.state)>;
        if (p.state == S::Missing) return IndexProbe::missing();
        if (p.state != S::Have)    return IndexProbe::unknown();
        return IndexProbe::have(static_cast<u64>(p.height), p.on_active_chain());
    };
}

template <class Backend>
LiveMainchainIndex::TipFn make_backend_tip(std::shared_ptr<Backend> be) {
    return [be]() -> std::optional<u64> {
        if (!be) return std::nullopt;
        try {
            const auto t = be->best_tip();
            if (t.hash.empty()) return std::nullopt;   // {0,"",0}: no good read yet
            return static_cast<u64>(t.height);
        } catch (const std::exception&) {
            // ChainMismatch is FATAL for the daemon — but the height-watch owns
            // that exit (main_v37_btc_dash.cpp exit 9). Here: fail closed.
            return std::nullopt;
        }
    };
}

template <class Backend>
std::unique_ptr<LiveMainchainIndex>
make_live_mainchain_index(std::shared_ptr<Backend> be,
                          std::function<std::string(const bytes32&)> display_hex_of,
                          LiveMainchainIndex::Options opt) {
    return std::make_unique<LiveMainchainIndex>(
        make_backend_probe<Backend>(be, std::move(display_hex_of)),
        make_backend_tip<Backend>(be), opt);
}

} // namespace c2pool::v37n
