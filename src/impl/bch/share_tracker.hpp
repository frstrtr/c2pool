#pragma once

// share_tracker.hpp -- BCH PPLNS / expected-payouts engine (M3 slice 16).
//
// Ports the PPLNS window accumulator and the expected-payouts entry points from
// the LTC reference (src/impl/ltc/share_tracker.hpp).  The PPLNS window
// structures (CumulativeWeights / PPLNSEntry / DensePPLNSWindow / HeadPPLNS) and
// the payout entry points (get_expected_payouts / get_v35_expected_payouts) plus
// their direct weight helpers (get_cumulative_weights /
// get_v36_decayed_cumulative_weights) are BYTE-IDENTICAL across the BTC and LTC
// references -- i.e. coin-independent.  They are reproduced here verbatim so the
// BCH payout math is bit-exact with p2pool-merged-v36 (V36 master-compat law).
//
// SCOPE (M3 slice 16): this file lands ONLY the PPLNS/payout surface of
// ShareTracker.  The remaining ShareTracker body (verify_share, think(),
// head-scoring, version counting, block scanning, and skip-list maintenance
// beyond the weights skiplist) is ported in subsequent M3 slices and extends
// THIS class.
//
// STANDALONE-PARENT NOTE: BCH is a standalone SHA256d parent (NOT merged-mined).
// The LTC reference additionally carries merged-mining machinery
// (merged_weights_delta, m_miner_merged_addr, get_merged_expected_payouts,
// CoinParams-driven verify, get_desired_version_weights) that BTC -- the other
// standalone SHA256d parent -- does NOT.  Whether the FULL BCH ShareTracker
// mirrors LTC (merged infra carried inert) or BTC (merged infra absent) is a
// structural decision deferred to integrator; it does NOT affect this slice,
// whose ported surface is byte-identical across both references.
//
// source-only: impl_bch stays CMake-unregistered (bch stays skip-green).
//
// Reference: frstrtr/p2pool-merged-v36 p2pool/data.py
//   (get_expected_payouts, get_decayed_cumulative_weights).

#include <cstdint>   // mul128_shift below uses uint64_t before the include block

// Portable 128-bit multiply-shift: (a * b) >> shift
// GCC/Clang have __uint128_t; MSVC uses _umul128 intrinsic.
// shift must be in [1, 63] to avoid undefined behavior from 64-bit shifts.
#ifdef _MSC_VER
#include <intrin.h>
inline uint64_t mul128_shift(uint64_t a, uint64_t b, unsigned shift) {
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    if (shift == 0)  return lo;   // (a*b) >> 0 — just the low 64 bits
    if (shift >= 64) return hi >> (shift - 64);
    return (hi << (64 - shift)) | (lo >> shift);
}
#else
inline uint64_t mul128_shift(uint64_t a, uint64_t b, unsigned shift) {
    return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) >> shift);
}
#endif

#include "share.hpp"
#include "share_check.hpp"
#include "config_pool.hpp"

#include <core/target_utils.hpp>
#include <core/coin_params.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <sharechain/weights_skiplist.hpp>
#include <btclibs/base58.h>
#include <btclibs/bech32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace bch
{

struct CumulativeWeights
{
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

// ── Dense PPLNS Ring Buffer ──────────────────────────────────────────────
// Stores PPLNS-relevant data for each share in the sliding window as a
// contiguous array. Eliminates hash map pointer-chasing during PPLNS walks:
// 8640 sequential reads over ~500KB (fits L2 cache) vs 8640 random hash map
// lookups. ~10x faster per PPLNS computation.
//
// The precomputed decay table guarantees bit-exact results: it uses the same
// iterative truncation as the walk-based code (decay_fp[d+1] = (decay_fp[d]
// * decay_per) >> PRECISION), just stored in a table instead of recomputed.

struct PPLNSEntry {
    uint288 att;                            // target_to_average_attempts(bits_to_target(bits))
    uint32_t donation{0};                   // share donation field
    std::vector<unsigned char> script;      // payout script (variable-length)
};

class DensePPLNSWindow {
public:
    static constexpr uint64_t DECAY_PRECISION = 40;
    static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
    static constexpr uint64_t LN2_MICRO = 693147;

    // Precomputed decay table: decay_table[d] = iterative decay factor at depth d.
    // Computed once, reused for every PPLNS walk. Thread-safe after init.
    //
    // Out-of-line definitions mirror ltc/node.cpp:16-18 and land with the BCH
    // node.cpp port slice:
    //   std::vector<uint64_t> bch::DensePPLNSWindow::s_decay_table;
    //   uint64_t              bch::DensePPLNSWindow::s_decay_per = 0;
    //   bool                  bch::DensePPLNSWindow::s_table_initialized = false;
    static std::vector<uint64_t> s_decay_table;
    static uint64_t s_decay_per;
    static bool s_table_initialized;

    static void init_decay_table(uint32_t chain_len) {
        if (s_table_initialized && s_decay_table.size() == chain_len)
            return;
        uint32_t half_life = std::max(chain_len / 4, uint32_t(1));
        s_decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);
        s_decay_table.resize(chain_len);
        s_decay_table[0] = DECAY_SCALE;
        for (uint32_t d = 1; d < chain_len; ++d)
            s_decay_table[d] = mul128_shift(s_decay_table[d-1], s_decay_per, DECAY_PRECISION);
        s_table_initialized = true;
    }

    // Deque of share entries: index 0 = depth 0 (shallowest/newest in window).
    // Deque gives O(1) push/pop at both ends for forward and backward slides.
    std::deque<PPLNSEntry> m_entries;
    uint256 m_tip_hash;     // hash of the share whose prev_hash starts this window
    int32_t m_chain_len{0}; // target window size

    // Build ring from chain data. O(chain_len) hash map lookups — done once.
    // After rebuild, m_entries[0] = share at start (depth 0),
    //                 m_entries[n-1] = deepest share in window.
    template <typename ChainT>
    void rebuild(ChainT& chain, const uint256& start, int32_t chain_len) {
        init_decay_table(static_cast<uint32_t>(chain_len));
        m_entries.clear();
        m_tip_hash = start;
        m_chain_len = chain_len;

        auto cur = start;
        while (!cur.IsNull() && chain.contains(cur)
               && static_cast<int32_t>(m_entries.size()) < chain_len)
        {
            PPLNSEntry entry;
            chain.get_share(cur).invoke([&](auto* obj) {
                entry.att = chain::target_to_average_attempts(
                    chain::bits_to_target(obj->m_bits));
                entry.donation = obj->m_donation;
                entry.script = get_share_script(obj);
            });
            m_entries.push_back(std::move(entry));

            auto* idx = chain.get_index(cur);
            cur = idx ? idx->tail : uint256();
        }
    }

    // Slide window forward: new share enters at front (depth 0), oldest drops.
    // Used when extending verification toward the chain tip.
    void slide_forward(PPLNSEntry entering) {
        m_entries.push_front(std::move(entering));
        if (static_cast<int32_t>(m_entries.size()) > m_chain_len)
            m_entries.pop_back();
    }

    // Slide window backward: shallowest share drops, new deeper share added.
    // Used by think() Phase 2 which walks backward via get_chain(last, N).
    // Each successive share to verify needs PPLNS shifted 1 step deeper.
    void slide_backward(PPLNSEntry deeper_entry) {
        if (!m_entries.empty())
            m_entries.pop_front();
        m_entries.push_back(std::move(deeper_entry));
    }

    // Compute V36 decayed PPLNS weights from ring buffer.
    // Bit-exact with the walk-based code: uses precomputed s_decay_table.
    // Sequential-ish memory access (deque blocks) — ~80μs vs ~500μs hash map.
    CumulativeWeights compute_v36_weights() const {
        CumulativeWeights result;
        int32_t n = static_cast<int32_t>(m_entries.size());
        for (int32_t d = 0; d < n; ++d) {
            auto& e = m_entries[d];
            uint288 decayed_att = (e.att * uint288(s_decay_table[d])) >> DECAY_PRECISION;
            auto addr_w = decayed_att * static_cast<uint32_t>(65535 - e.donation);
            auto don_w  = decayed_att * e.donation;
            auto this_total = addr_w + don_w;
            result.weights[e.script] += addr_w;
            result.total_weight += this_total;
            result.total_donation_weight += don_w;
        }
        return result;
    }

    bool empty() const { return m_entries.empty(); }
    int32_t size() const { return static_cast<int32_t>(m_entries.size()); }
};

// ── Head-Level Incremental PPLNS ─────────────────────────────────────────
// Maintains a DensePPLNSWindow + cached CumulativeWeights per active head.
// When verifying consecutive shares along a chain:
//   1. rebuild() at first share's parent: O(chain_len) — one hash map walk
//   2. extend() for each subsequent share: O(1) ring push + O(chain_len) dense recompute
// Total for N shares: O(chain_len + N × chain_len) sequential ops
// vs current: O(N × chain_len) random hash map ops — ~10x faster per op.

class HeadPPLNS {
    DensePPLNSWindow m_ring;
    CumulativeWeights m_cached;
    bool m_dirty{true};

public:
    // Cold start: build ring from chain. O(chain_len) hash map lookups.
    template <typename ChainT>
    void rebuild(ChainT& chain, const uint256& start, int32_t chain_len) {
        m_ring.rebuild(chain, start, chain_len);
        m_dirty = true;
    }

    // Extend forward: new share enters at depth 0. O(1) ring update.
    // Used when verifying toward chain tip (new shares extending verified head).
    template <typename ChainT>
    void extend_forward(ChainT& chain, const uint256& new_share_hash) {
        PPLNSEntry entry;
        chain.get_share(new_share_hash).invoke([&](auto* obj) {
            entry.att = chain::target_to_average_attempts(
                chain::bits_to_target(obj->m_bits));
            entry.donation = obj->m_donation;
            entry.script = get_share_script(obj);
        });
        m_ring.slide_forward(std::move(entry));
        m_dirty = true;
    }

    // Extend backward: depth-0 drops, new deeper share added. O(1) ring update.
    // Used by think() Phase 2 which walks backward via get_chain(last, N).
    template <typename ChainT>
    void extend_backward(ChainT& chain, const uint256& deeper_share_hash) {
        PPLNSEntry entry;
        chain.get_share(deeper_share_hash).invoke([&](auto* obj) {
            entry.att = chain::target_to_average_attempts(
                chain::bits_to_target(obj->m_bits));
            entry.donation = obj->m_donation;
            entry.script = get_share_script(obj);
        });
        m_ring.slide_backward(std::move(entry));
        m_dirty = true;
    }

    // Get cached weights. Recomputes from ring if dirty.
    // O(chain_len) dense sequential reads, ~50μs.
    const CumulativeWeights& weights() {
        if (m_dirty) {
            m_cached = m_ring.compute_v36_weights();
            m_dirty = false;
        }
        return m_cached;
    }

    bool valid() const { return !m_ring.empty(); }
    int32_t window_size() const { return m_ring.size(); }
    const DensePPLNSWindow& ring() const { return m_ring; }
};

// --- ShareTracker (M3 slice 16: PPLNS / expected-payouts surface only) ---
// Subsequent M3 slices extend this class with verify_share(), think(),
// head-scoring, version counting and block scanning.
class ShareTracker
{
public:
    ShareChain chain;

    // -- PPLNS cumulative weights computation (O(log n) via skip list) --
    CumulativeWeights get_cumulative_weights(const uint256& start, int32_t max_shares, const uint288& desired_weight)
    {
        if (start.IsNull())
            return {};

        ensure_weights_skiplist();
        auto sl_result = m_weights_skiplist->query(start, max_shares, desired_weight);
        return CumulativeWeights{
            std::move(sl_result.weights),
            sl_result.total_weight,
            sl_result.total_donation_weight
        };
    }

    // -- V36 PPLNS with exponential depth-decay --
    // Matches Python: get_decayed_cumulative_weights()
    // half_life = CHAIN_LENGTH // 4
    // Each share's weight is multiplied by 2^(-depth/half_life)
    // Fixed-point arithmetic with 40-bit precision.
    //
    // Result is cached keyed by (start_hash, max_shares) — invalidated
    // when the chain head changes.  This makes repeated calls for the
    // same share (e.g. during verify_share + get_expected_payouts) O(1).
    CumulativeWeights get_v36_decayed_cumulative_weights(
        const uint256& start, int32_t max_shares, const uint288& desired_weight)
    {
        if (start.IsNull())
            return {};

        // Cache: keyed by (start_hash, max_shares, desired_weight).
        // Same inputs always produce same outputs (deterministic walk).
        // Invalidated when chain head changes (new shares added/removed).
        // No consensus risk — cached result is byte-identical to fresh computation.
        if (m_decayed_cache_valid && m_decayed_cache_start == start
            && m_decayed_cache_shares == max_shares
            && m_decayed_cache_desired == desired_weight)
            return m_decayed_cache_result;

        static constexpr uint64_t DECAY_PRECISION = 40;
        static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
        static constexpr uint64_t LN2_MICRO = 693147;

        uint32_t half_life = std::max(PoolConfig::chain_length() / 4, uint32_t(1));
        uint64_t decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);

        CumulativeWeights result;
        int32_t share_count = 0;
        uint64_t decay_fp = DECAY_SCALE; // starts at 1.0

        // Single-pass walk matching p2pool's while loop in
        // get_decayed_cumulative_weights. No pre-collection needed.
        auto cur = start;
        while (!cur.IsNull() && chain.contains(cur) && share_count < max_shares)
        {
            chain.get_share(cur).invoke([&](auto* obj) {
                auto att = chain::target_to_average_attempts(
                    chain::bits_to_target(obj->m_bits));
                uint32_t don = obj->m_donation;

                uint288 decayed_att = (att * uint288(decay_fp)) >> DECAY_PRECISION;

                auto addr_w = decayed_att * static_cast<uint32_t>(65535 - don);
                auto don_w  = decayed_att * don;
                auto this_total = addr_w + don_w; // = decayed_att * 65535

                if (result.total_weight + this_total > desired_weight) {
                    auto remaining = desired_weight - result.total_weight;
                    if (!this_total.IsNull()) {
                        addr_w = addr_w * remaining / this_total;
                        don_w  = don_w * remaining / this_total;
                    }
                    this_total = remaining;
                }

                auto script = get_share_script(obj);
                result.weights[script] += addr_w;
                result.total_weight += this_total;
                result.total_donation_weight += don_w;
            });

            ++share_count;
            if (result.total_weight >= desired_weight)
                break;

            decay_fp = mul128_shift(decay_fp, decay_per, DECAY_PRECISION);

            auto* idx = chain.get_index(cur);
            cur = idx ? idx->tail : uint256();
        }

        // Cache result (single-entry, invalidated on chain change)
        m_decayed_cache_start = start;
        m_decayed_cache_shares = max_shares;
        m_decayed_cache_desired = desired_weight;
        m_decayed_cache_result = result;
        m_decayed_cache_valid = true;

        return result;
    }

    // -- Expected payouts from PPLNS weights --
    // Uses exact integer arithmetic matching generate_share_transaction():
    //   V36: amount = (uint288(subsidy) * weight / total_weight).GetLow64()
    //   donation = subsidy - sum(amounts)
    std::map<std::vector<unsigned char>, double>
    get_expected_payouts(const uint256& best_share_hash, const uint256& block_target, uint64_t subsidy,
                         const std::vector<unsigned char>& donation_script)
    {
        // Pass REAL_CHAIN_LENGTH as max_shares — the walk naturally stops
        // when the chain ends, matching p2pool's direct iteration pattern.
        // Do NOT use cached get_height() which can be stale in multi-threaded context.
        auto chain_len = static_cast<int32_t>(PoolConfig::real_chain_length());
        // V36: remove desired_weight cap — exponential decay handles windowing.
        // See generate_share_transaction() for detailed rationale.
        uint288 unlimited_weight;
        unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        {
            static int ep_log = 0;
            if (ep_log++ % 20 == 0) {
                LOG_DEBUG_DIAG << "[EP-PPLNS] v36 start=" << best_share_hash.GetHex().substr(0, 16)
                         << " chain_len=" << chain_len
                         << " subsidy=" << subsidy;
            }
        }
        auto [weights, total_weight, donation_weight] = get_v36_decayed_cumulative_weights(best_share_hash, chain_len, unlimited_weight);

        std::map<std::vector<unsigned char>, double> result;
        uint64_t sum = 0;

        if (!total_weight.IsNull())
        {
            for (const auto& [script, weight] : weights)
            {
                // Exact integer division matching generate_share_transaction (V36)
                uint64_t amount = (uint288(subsidy) * weight / total_weight).GetLow64();
                if (amount > 0)
                {
                    result[script] = static_cast<double>(amount);
                    sum += amount;
                }
            }
        }

        // Remainder goes to donation (matches generate_share_transaction)
        uint64_t donation_amount = (subsidy > sum) ? (subsidy - sum) : 0;

        // V36 consensus: donation output must carry >= 1 satoshi (a60f7f7f)
        if (donation_amount < 1 && subsidy > 0 && !result.empty()) {
            // Deterministic tiebreak: (amount, script) — largest script wins when equal
            auto largest = std::max_element(result.begin(), result.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            if (largest != result.end() && largest->second >= 1.0) {
                largest->second -= 1.0;
                sum -= 1;
                donation_amount = subsidy - sum;
            }
        }

        result[donation_script] = (result.contains(donation_script) ? result[donation_script] : 0.0)
                                  + static_cast<double>(donation_amount);

        return result;
    }

    // -- V35 PPLNS expected payouts --
    // Flat (non-decayed) weights, GRANDPARENT start, height-1 window.
    // Returns amounts WITHOUT finder fee — caller adds subsidy/200 to the
    // share creator's script.  Donation absorbs the remainder.
    // Reference: p2pool data.py lines 878-965
    std::map<std::vector<unsigned char>, double>
    get_v35_expected_payouts(const uint256& best_share_hash, const uint256& block_target, uint64_t subsidy,
                             const std::vector<unsigned char>& donation_script)
    {
        // V35: PPLNS starts from the GRANDPARENT (prev_share.prev_hash)
        // Reference: data.py line 884
        uint256 pplns_start;
        if (!best_share_hash.IsNull() && chain.contains(best_share_hash)) {
            chain.get(best_share_hash).share.invoke([&](auto* s) {
                pplns_start = s->m_prev_hash;  // grandparent
            });
        }

        if (pplns_start.IsNull()) {
            // No grandparent: all subsidy to donation
            std::map<std::vector<unsigned char>, double> result;
            result[donation_script] = static_cast<double>(subsidy);
            return result;
        }

        // V35: max_shares = max(0, min(height, REAL_CHAIN_LENGTH) - 1)
        // Reference: data.py line 885
        auto height = chain.get_height(best_share_hash);
        int32_t max_shares = std::max(0, std::min(height, static_cast<int32_t>(PoolConfig::real_chain_length())) - 1);

        // V35: desired_weight = 65535 * SPREAD * target_to_average_attempts(block_target)
        // Reference: data.py line 886
        uint288 desired_weight = chain::target_to_average_attempts(block_target)
                                 * uint288(PoolConfig::SPREAD) * uint288(65535);

        {
            static int ep35_log = 0;
            if (ep35_log++ % 20 == 0) {
                LOG_DEBUG_DIAG << "[EP-PPLNS] v35 start=" << pplns_start.GetHex().substr(0, 16)
                         << " max_shares=" << max_shares
                         << " desired_w=" << desired_weight.GetLow64()
                         << " subsidy=" << subsidy
                         << " best=" << best_share_hash.GetHex().substr(0, 16);
            }
        }
        // Flat weight accumulation with hard cap (existing get_cumulative_weights)
        auto [weights, total_weight, donation_weight] = get_cumulative_weights(pplns_start, max_shares, desired_weight);

        std::map<std::vector<unsigned char>, double> result;
        uint64_t sum = 0;

        if (!total_weight.IsNull())
        {
            for (const auto& [script, weight] : weights)
            {
                // V35: 99.5% to PPLNS — subsidy * 199 * weight / (200 * total_weight)
                // Reference: data.py line 924
                uint64_t amount = (uint288(subsidy) * uint288(199) * weight / (uint288(200) * total_weight)).GetLow64();
                if (amount > 0)
                {
                    result[script] = static_cast<double>(amount);
                    sum += amount;
                }
            }
        }

        // Remainder goes to donation (includes the ~0.5% finder fee portion;
        // caller subtracts subsidy/200 for the finder and assigns it per-connection)
        // V35: NO minimum donation enforcement (unlike v36)
        uint64_t donation_amount = (subsidy > sum) ? (subsidy - sum) : 0;
        result[donation_script] = (result.contains(donation_script) ? result[donation_script] : 0.0)
                                  + static_cast<double>(donation_amount);

        // Periodic diagnostic dump for cross-impl comparison
        {
            static int v35_dump = 0;
            if (v35_dump++ < 10 || v35_dump % 60 == 0) {
                LOG_DEBUG_DIAG << "[V35-PPLNS] subsidy=" << subsidy << " addrs=" << weights.size()
                         << " total_w=" << total_weight.GetLow64()
                         << " max_shares=" << max_shares << " sum=" << sum
                         << " donation=" << donation_amount
                         << " prev=" << best_share_hash.GetHex().substr(0, 16)
                         << " grandparent=" << pplns_start.GetHex().substr(0, 16);
            }
        }

        return result;
    }

private:
    // Previous-share lambda for RAW chain (work templates, general PPLNS)
    auto make_previous_fn()
    {
        return [this](const uint256& hash) -> uint256 {
            if (!chain.contains(hash)) return uint256{};
            return chain.get_index(hash)->tail;
        };
    }

    void ensure_weights_skiplist()
    {
        if (m_weights_skiplist)
            return;
        m_weights_skiplist.emplace(
            [this](const uint256& hash) -> chain::WeightsDelta {
                chain::WeightsDelta delta;
                if (!chain.contains(hash)) return delta;
                delta.share_count = 1;
                chain.get_share(hash).invoke([&](auto* obj) {
                    auto target = chain::bits_to_target(obj->m_bits);
                    auto att = chain::target_to_average_attempts(target);
                    delta.total_weight = att * 65535;
                    delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);
                    auto addr_bytes = get_share_script(obj);
                    delta.weights[addr_bytes] = att * static_cast<uint32_t>(65535 - obj->m_donation);
                });
                return delta;
            },
            make_previous_fn()
        );
    }

    // -- Skip list caches for O(log n) weight queries --
    std::optional<chain::WeightsSkipList> m_weights_skiplist;

    // -- Decayed weights result cache --
    // Avoids recomputing the O(chain_length) walk when the same
    // (start, max_shares) is queried multiple times between chain changes
    // (e.g. verify_share + get_expected_payouts for the same share).
    bool m_decayed_cache_valid{false};
    uint256 m_decayed_cache_start;
    int32_t m_decayed_cache_shares{0};
    uint288 m_decayed_cache_desired;
    CumulativeWeights m_decayed_cache_result;
};

} // namespace bch
