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

#include <core/version_gate.hpp>   // SSOT: core::version_gate::is_v36_active
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
#include <climits>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
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

// --- Scoring types (coin-independent; mirror of btc SSOT) ---
// These carry NO merged-mining / segwit surface. BCH is a standalone SHA256d
// parent — the score math is the same family as btc (the only BCH divergence
// is the 600s BLOCK_PERIOD applied in ShareTracker::score()).

struct TailScore
{
    int32_t chain_len{};
    uint288 hashrate;
    uint288 best_head_work;  // tiebreak: raw chain work of best head

    friend bool operator<(const TailScore& a, const TailScore& b)
    {
        return std::tie(a.chain_len, a.hashrate, a.best_head_work)
             < std::tie(b.chain_len, b.hashrate, b.best_head_work);
    }
};

struct HeadScore
{
    // p2pool: (work - min(punish,1)*ata(target), -reason, -time_seen)
    // Sorted ascending, .back() = best.
    uint288 adjusted_work;   // work - punishment_deduction
    int32_t neg_reason{};    // -reason (higher = less punished = better)
    int64_t neg_time_seen{}; // -time_seen (higher = seen earlier = better)

    friend bool operator<(const HeadScore& a, const HeadScore& b)
    {
        if (a.adjusted_work < b.adjusted_work) return true;
        if (b.adjusted_work < a.adjusted_work) return false;
        return std::tie(a.neg_reason, a.neg_time_seen) < std::tie(b.neg_reason, b.neg_time_seen);
    }
};

struct TraditionalScore
{
    // p2pool: (work, -time_seen, -reason). No is_local. Sorted ascending.
    uint288 work;
    int64_t neg_time_seen{};
    int32_t neg_reason{};

    friend bool operator<(const TraditionalScore& a, const TraditionalScore& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        return std::tie(a.neg_time_seen, a.neg_reason) < std::tie(b.neg_time_seen, b.neg_reason);
    }
};

template <typename ScoreT>
struct DecoratedData
{
    ScoreT score;
    uint256 hash;

    friend bool operator<(const DecoratedData& a, const DecoratedData& b)
    {
        return a.score < b.score;
    }
};

// -- think() result (mirror of btc TrackerThinkResult; SSOT for the field set) --
// Produced by think() and consumed by the node-layer run_think() loop:
//   best                = new best verified head (null when nothing verified)
//   desired             = (peer, hash) shares to download from peers
//   bad_peer_addresses  = peers that served unverifiable shares (ban targets)
//   top5_heads          = best-scored heads protected from head-pruning
// The s1 link-skeleton think() returns this EMPTY; s2 populates it.
struct TrackerThinkResult
{
    uint256 best;
    std::vector<std::pair<NetService, uint256>> desired;
    std::set<NetService> bad_peer_addresses;
    bool punish_aggressively{false};
    std::vector<uint256> top5_heads;
};

// --- ShareTracker (M3 slice 16: PPLNS / expected-payouts surface only) ---
// Subsequent M3 slices extend this class with verify_share(), think(),
// head-scoring, version counting and block scanning.
class ShareTracker
{
public:
    ShareChain chain;

    // Verified best-chain mirror (p2pool known_verified pattern): shares that
    // have passed full PoW + context verification.  Work/template selection and
    // block scanning run against this sub-chain, never the raw "chain" buffer.
    ShareChain verified;

    // -- ctor/dtor: wire the verified SubsetTracker (mirror btc SSOT) --
    // p2pool SubsetTracker pattern: the verified mirror navigates through the
    // MAIN tracker's skip list (verified.get_nth_parent_hash delegates to
    // subset_of.get_nth_parent_hash). WeightsSkipList subscribes to the raw
    // chain's removed signal so pruned shares leave no stale weight entries.
    // (data.py SubsetTracker; node.py clean_tracker prune path.)
    ShareTracker()
    {
        verified.set_parent_chain(&chain);
        chain.on_removed([this](const uint256& hash) {
            invalidate_weight_caches(hash);
            m_verify_fail_count.erase(hash);
        });
    }
    ~ShareTracker()
    {
        // verified borrows raw share pointers from chain — free its indexes
        // only, then let chain's destructor free the share data.
        verified.clear_unowned();
    }

    // -- Node-layer callback hooks (wired by the pool node in node.hpp) --
    // BCH is a SHA256d standalone-parent chain: NO merged-mining / AuxPoW, so
    // there is no m_on_merged_block_check (present in btc for the DOGE aux leg).
    // Fired when a share passes verification (LevelDB known_verified persistence).
    std::function<void(const uint256&)> m_on_share_verified;
    // Fired when a verified share meets the BCH block target (found block).
    std::function<void(const uint256&)> m_on_block_found;
    // Fired for every verified share with its difficulty + miner script
    // (best-share difficulty tracking for the dashboard).
    std::function<void(double difficulty, const std::string& miner)> m_on_share_difficulty;

    // -- V36 think() lock-yield continuation flags (mirror p2pool reactor) --
    // Set by think() when its cooperative-yield budget is exhausted so the
    // node-layer run_think() schedules a deferred continuation. The s1 link-
    // stub think() returns immediately and never yields, so these stay false.
    bool m_think_needs_continue{false};
    bool m_think_walk_needs_continue{false};

    // -- Share ingest: add() = RAW chain buffering only (NOT consensus) --
    // A received share enters the PPLNS / payout / block-found path ONLY once
    // attempt_verify() promotes it into `verified`. add() merely buffers it in
    // the raw `chain`. BCH is a SHA256d standalone parent: no merged-mining, so
    // (unlike btc) there is no try_register_merged_addr() leg here.
    // -- Add share to the main chain (raw-pointer form) --
    // Mirrors btc::ShareTracker::add(ShareT*) (SSOT) so create_local_share()
    // can hand off a freshly heap-allocated concrete share (PaddingBugfixShare /
    // MergedMiningShare) without the caller wrapping it into the ShareType
    // variant. This overload was missing on BCH -- create_local_share is the
    // first caller, so its instantiation surfaced the gap. BCH is a SHA256d
    // standalone parent: no try_register_merged_addr leg (see add(ShareType)).
    template <typename ShareT>
    void add(ShareT* share)
    {
        if (!chain.contains(share->m_hash))
            chain.add(share);
    }

    void add(ShareType share)
    {
        auto h = share.hash();
        if (!chain.contains(h))
            chain.add(share);
    }

    // -- s0 CONSENSUS THINK-ENGINE (M5): full verify + reorg/score + PPLNS --
    // Ports the p2pool BCH consensus core (attempt_verify / score / think
    // Phase 1-6) from the btc SSOT, conformed against the p2poolBCH @6603b79
    // oracle (p2pool/data.py attempt_verify:716-728, think:731-845, score:866-878;
    // p2pool/node.py clean_tracker head-protection:348-373).
    //
    // BCH divergences from the btc donor (oracle-driven):
    //   * NO merged-mining: BCH is a SHA256d standalone parent. There is no
    //     m_on_merged_block_check / try_register_merged_addr / DOGE aux leg.
    //   * score() uses BCH PARENT.BLOCK_PERIOD = 600s (oracle
    //     p2pool/bitcoin/networks/bitcoincash.py:24), NOT the btc/LTC 150s.
    //   * NO SegWit: the share/template witness path does not exist on BCH; the
    //     think-engine never touches witness data (share_check.hpp gates segwit
    //     OFF for BCH via is_segwit_activated()==false).
    //   * ASERT DAA / CashTokens transparency are handled in verify_share()
    //     (share_check.hpp), not in the think-engine — no special handling here.
    // The PPLNS budget walk (get_v36_decayed_cumulative_weights) is byte-identical
    // to the oracle weight split decayed_att*(65535-don)/decayed_att*don
    // (p2poolBCH/p2pool/data.py:673-674, get_decayed_cumulative_weights).

    // -- Attempt to verify a share (oracle data.py:716-728) --
    // Returns true if the share is verified (already, or newly promoted into the
    // `verified` SubsetTracker). p2pool has NO permanently-unverifiable concept;
    // it retries share.check() every think() — a share that failed on a transient
    // fork may succeed once the fork resolves. (data.py: attempt_verify is called
    // unconditionally in the think() walk every cycle.)
    bool attempt_verify(const uint256& share_hash)
    {
        if (verified.contains(share_hash))
            return true;

        // oracle: height, last = self.get_height_and_last(share.hash)
        //         if height < self.net.CHAIN_LENGTH + 1 and last is not None:
        //             raise AssertionError()
        // Chain too short and unrooted: cannot verify yet. The share isn't bad;
        // its parents haven't arrived. generate_share_transaction needs
        // CHAIN_LENGTH ancestors for correct PPLNS — verifying with a truncated
        // window produces a wrong coinbase (GENTX-MISMATCH). Phase 2 naturally
        // extends verification once parents arrive.
        auto acc_height = chain.get_acc_height(share_hash);
        auto last = chain.get_last(share_hash);
        if (acc_height < static_cast<int32_t>(PoolConfig::chain_length()) + 1 && !last.IsNull())
            return false;

        // oracle: share.gentx = share.check(self, known_txs, ...)
        // verify_share (share_check.hpp) runs init-phase (hash-link, merkle,
        // SHA256d PoW, ASERT context) + check-phase (gentx/coinbase comparison).
        // It throws on any failure. BCH-faithful: no segwit, no merged leg.
        try
        {
            auto& share_var = chain.get_share(share_hash);
            share_var.ACTION({
                auto computed_hash = verify_share(*obj, *this);
                (void)computed_hash;
            });
        }
        catch (const std::exception& e)
        {
            // Counter for log throttling only — p2pool retries every think().
            auto& cnt = m_verify_fail_count[share_hash];
            ++cnt;
            if (cnt <= 3 || cnt % 10 == 0)
                LOG_WARNING << "attempt_verify FAILED (" << cnt
                            << ") for " << share_hash.ToString().substr(0,16)
                            << " acc_height=" << acc_height
                            << " last=" << (last.IsNull() ? "null" : last.ToString().substr(0,16))
                            << " error: " << e.what();
            return false;
        }

        // Success — clear any previous fail count.
        m_verify_fail_count.erase(share_hash);

        // Cache the SHA256d pow_hash on the index (restart block-scan reuse —
        // avoids recomputing SHA256d). g_last_pow_hash is set by share_init_verify
        // (share_check.hpp). BCH PoW is SHA256d (same family as btc).
        if (!g_last_pow_hash.IsNull()) {
            auto* idx = chain.get_index(share_hash);
            if (idx) idx->pow_hash = g_last_pow_hash;
        }

        // Promote into the verified SubsetTracker.
        auto& share_var = chain.get_share(share_hash);
        if (!verified.contains(share_hash))
            verified.add(share_var);

        // Notify LevelDB known_verified persistence layer.
        if (m_on_share_verified)
            m_on_share_verified(share_hash);

        // Block detection: share_init_verify flags a block solution when the
        // share's SHA256d pow meets the BCH parent block target. Mirrors p2pool
        // tracker.verified.added watcher (node.py). BCH standalone-parent: NO
        // merged DOGE-target leg here.
        if (m_on_block_found && g_last_init_is_block) {
            g_last_init_is_block = false;
            auto* idx = chain.get_index(share_hash);
            if (idx) idx->is_block_solution = true;
            m_on_block_found(share_hash);
        }

        // Report share difficulty for the best-share dashboard tracking.
        if (m_on_share_difficulty) {
            share_var.invoke([&](auto* s) {
                double diff = chain::target_to_difficulty(chain::bits_to_target(s->m_bits));
                std::string miner;
                if constexpr (requires { s->m_pubkey_hash; })
                    miner = s->m_pubkey_hash.GetHex();
                else if constexpr (requires { s->m_address; })
                    miner = HexStr(s->m_address.m_data);
                m_on_share_difficulty(diff, miner);
            });
        }

        // Naughty propagation: if the parent is naughty, increment up to 6
        // generations (data.py ancestor punishment for invalid-block shares).
        {
            uint256 prev_hash;
            share_var.invoke([&](auto* obj) { prev_hash = obj->m_prev_hash; });
            if (!prev_hash.IsNull() && chain.contains(prev_hash)) {
                auto* parent_idx = chain.get_index(prev_hash);
                if (parent_idx && parent_idx->naughty > 0) {
                    auto* my_idx = chain.get_index(share_hash);
                    if (my_idx) {
                        my_idx->naughty = parent_idx->naughty + 1;
                        if (my_idx->naughty > 6) my_idx->naughty = 0;
                    }
                }
            }
        }

        // V34+ (incl. V36) shares carry transaction_hash_refs, not embedded txs,
        // so other_txs is always None → p2pool SKIPS the block weight/size check
        // (data.py). Coinbase correctness is already enforced by verify_share's
        // generate_share_transaction comparison. CashTokens carry transparently.
        return true;
    }

    // -- Score a verified chain (oracle data.py:866-878) --
    // Returns (chain_len, hashrate) — higher is better. Uses self.verified for
    // ALL operations (using the raw chain inflates height with unverified shares
    // and breaks tie-breaking). BCH divergence: PARENT.BLOCK_PERIOD = 600s.
    TailScore score(const uint256& share_hash,
                    const std::function<int32_t(uint256)>& block_rel_height_func)
    {
        uint288 score_res;

        // oracle: head_height = self.verified.get_height(share_hash)
        //         if head_height < self.net.CHAIN_LENGTH: return head_height, None
        auto head_height = verified.get_acc_height(share_hash);
        if (head_height < static_cast<int32_t>(PoolConfig::chain_length()))
            return {head_height, score_res};

        // oracle: end_point = self.verified.get_nth_parent_hash(
        //             share_hash, self.net.CHAIN_LENGTH*15//16)
        auto end_point = verified.get_nth_parent_via_skip(share_hash,
            (PoolConfig::chain_length() * 15) / 16);

        // oracle: block_height = max(block_rel_height_func(share.header['previous_block'])
        //             for share in self.verified.get_chain(end_point, CHAIN_LENGTH//16))
        std::optional<int32_t> block_height;
        auto tail_count = std::min(
            static_cast<int32_t>(PoolConfig::chain_length() / 16),
            verified.get_acc_height(end_point));
        if (tail_count <= 0)
            return {static_cast<int32_t>(PoolConfig::chain_length()), score_res};

        auto tail_view = verified.get_chain(end_point, tail_count);
        for (auto [hash, data] : tail_view)
        {
            uint256 prev_block;
            data.share.invoke([&](auto* obj) {
                prev_block = obj->m_min_header.m_previous_block;
            });
            auto bh = block_rel_height_func(prev_block);
            if (!block_height.has_value() || bh > block_height.value())
                block_height = bh;
        }

        // c2pool returns confirmations (1=tip, 0=unknown, -1=off-main-chain);
        // p2pool returns relative height. When the block can't be resolved,
        // p2pool computes work/(1e9*BLOCK_PERIOD) — tiny but non-zero, so the
        // higher-work chain wins (stable, no oscillation). Match it.
        if (!block_height.has_value() || block_height.value() <= 0)
            block_height = 1000000;

        // oracle: self.verified.get_delta(share_hash, end_point).work
        auto total_work = verified.get_delta_work(share_hash, end_point);

        // oracle: ((0 - block_height + 1) * self.net.PARENT.BLOCK_PERIOD)
        // BCH PARENT.BLOCK_PERIOD = 600s (bitcoincash.py:24), NOT LTC's 150s.
        auto time_span = block_height.value() * 600;
        if (time_span <= 0)
            time_span = 1;

        score_res = total_work / static_cast<uint32_t>(time_span);
        return {static_cast<int32_t>(PoolConfig::chain_length()), score_res};
    }

    // -- Best-chain selection with verification + punishment (oracle think) --
    // bootstrap_mode: removes the per-call verification budget so the entire
    // chain is verified in one pass (initial sync, no IO needs the lock).
    // Oracle: p2pool/data.py:731-845 (Tracker.think); p2pool runs think()
    // synchronously on the reactor. The known_txs/feecache/block_abs_height
    // args fold into verify_share via share_check.hpp.
    TrackerThinkResult think(const std::function<int32_t(uint256)>& block_rel_height_func,
                             const uint256& /*previous_block*/,
                             uint32_t /*bits*/,
                             bool bootstrap_mode = false)
    {
        // oracle: desired is a set of (peer_addr, hash, max_timestamp, min_target).
        // The timestamp filters stale requests at return time.
        struct DesiredEntry {
            NetService peer;
            uint256 hash;
            uint32_t max_timestamp{0};
        };
        std::vector<DesiredEntry> desired;
        std::set<uint256> desired_hashes;   // oracle: desired = set() — dedup by hash
        std::set<NetService> bad_peer_addresses;

        // ── Phase 1: verify unverified heads; collect bad shares ───────────
        // oracle data.py:740-755. For each raw head not yet verified, walk back
        // and attempt_verify; the first success breaks; failing shares -> bads;
        // a for/else with no success on a rooted chain requests the parent.
        std::vector<uint256> bads;
        {
            auto heads_snapshot = chain.get_heads();
            for (auto& [head_hash, tail_hash] : heads_snapshot)
            {
                if (verified.get_heads().contains(head_hash))
                    continue;
                if (!chain.contains(head_hash)) continue;

                auto [head_height, last] = chain.get_height_and_last(head_hash);

                // oracle: get_chain(head, head_height if last is None
                //                   else min(5, max(0, head_height - CHAIN_LENGTH)))
                auto walk_count = last.IsNull()
                    ? head_height
                    : std::min(5, std::max(0, head_height - static_cast<int32_t>(PoolConfig::chain_length())));

                if (walk_count <= 0) {
                    // oracle for/else: walk produced nothing → request parent.
                    // Skip parent requests for chains already in the pruning zone
                    // (>= 2*CHAIN_LENGTH+10) — clean_tracker would re-prune them.
                    if (!last.IsNull()) {
                        auto CL_prune = static_cast<int32_t>(PoolConfig::chain_length());
                        if (head_height < 2 * CL_prune + 10 && !desired_hashes.count(last)) {
                            NetService peer;
                            uint32_t head_ts = 0;
                            chain.get_share(head_hash).invoke([&](auto* obj) {
                                peer = obj->peer_addr;
                                head_ts = obj->m_timestamp;
                            });
                            desired_hashes.insert(last);
                            desired.push_back({peer, last, head_ts});
                        }
                    }
                    continue;
                }

                bool verified_one = false;
                try {
                    auto chain_view = chain.get_chain(head_hash, walk_count);
                    for (auto [hash, data] : chain_view)
                    {
                        if (attempt_verify(hash)) { verified_one = true; break; }
                        // oracle data.py: bads.append(share.hash) — ALL failing
                        // shares go to bads; p2pool has no unverifiable filter.
                        bads.push_back(hash);
                    }
                } catch (const std::exception& ex) {
                    LOG_WARNING << "[think-P1] exception walking head "
                                << head_hash.GetHex().substr(0,16)
                                << " height=" << head_height << " walk=" << walk_count
                                << ": " << ex.what();
                    continue;
                }

                // oracle for/else: loop completed without break AND unrooted.
                if (!verified_one && !last.IsNull())
                {
                    auto CL_prune = static_cast<int32_t>(PoolConfig::chain_length());
                    if (head_height < 2 * CL_prune + 10 && !desired_hashes.count(last)) {
                        NetService peer;
                        uint32_t head_ts = 0;
                        chain.get_share(head_hash).invoke([&](auto* obj) {
                            peer = obj->peer_addr;
                            head_ts = obj->m_timestamp;
                        });
                        desired_hashes.insert(last);
                        desired.push_back({peer, last, head_ts});
                    }
                }
            }
        }

        // ── Remove bad shares (oracle data.py:756-768) ─────────────────────
        // p2pool tries self.remove(bad) for ALL bads; catches NotImplementedError
        // for mid-chain shares (have dependents). chain.remove() returns false
        // in that case (equivalent). NO leaf-only filter — p2pool has none.
        {
            int removed_count = 0;
            for (const auto& bad : bads)
            {
                if (verified.contains(bad)) continue;   // oracle: assert bad not in verified
                if (!chain.contains(bad)) continue;

                NetService bad_peer;
                try {
                    chain.get_share(bad).invoke([&](auto* obj) { bad_peer = obj->peer_addr; });
                } catch (...) {}
                if (bad_peer.port() != 0)
                    bad_peer_addresses.insert(bad_peer);

                try {
                    invalidate_weight_caches(bad);
                    if (verified.contains(bad)) verified.remove(bad);
                    if (chain.remove(bad)) ++removed_count;
                } catch (...) {}
            }
            if (removed_count > 0)
                LOG_INFO << "[think-P1] removed " << removed_count
                         << " shares (bads=" << bads.size() << " + descendants)";
        }

        // ── Phase 2: extend verification from verified heads ───────────────
        // oracle data.py:769-788. Budget-limited per call (cooperative yield) to
        // avoid pinning the compute lock; remainder picked up next run_think().
        constexpr int THINK_VERIFY_BUDGET = 100;
        int budget_remaining = bootstrap_mode ? INT_MAX : THINK_VERIFY_BUDGET;
        m_think_needs_continue = false;

        // V36 livelock mirror: cooperative-yield budget for the scoring walk.
        // Sized FAR above a normal full-window pass so it NEVER trips on healthy
        // load (semantics unchanged); a pure starvation circuit breaker.
        constexpr int THINK_WALK_YIELD_BUDGET = 1000000;
        int walk_budget_remaining = bootstrap_mode ? INT_MAX : THINK_WALK_YIELD_BUDGET;
        m_think_walk_needs_continue = false;

        // Sort verified heads by work (descending) so the best chain gets budget
        // priority. p2pool iterates in arbitrary order but has no budget; with a
        // budget, a low-work side chain going first could starve the best chain.
        std::vector<std::pair<uint256, uint256>> sorted_vheads(
            verified.get_heads().begin(), verified.get_heads().end());
        std::sort(sorted_vheads.begin(), sorted_vheads.end(),
            [this](const auto& a, const auto& b) {
                auto wa = verified.contains(a.first) ? verified.get_work(a.first) : uint288{};
                auto wb = verified.contains(b.first) ? verified.get_work(b.first) : uint288{};
                return wa > wb;
            });

        for (auto& [head_hash, tail_hash] : sorted_vheads)
        {
            if (budget_remaining <= 0) { m_think_needs_continue = true; break; }
            if (!chain.contains(head_hash)) continue;

            auto [head_height, last_hash] = verified.get_height_and_last(head_hash);
            if (!chain.contains(last_hash)) continue;

            auto [last_height, last_last_hash] = chain.get_height_and_last(last_hash);

            // oracle data.py:774-776 EXACTLY:
            //   want = max(CHAIN_LENGTH - head_height, 0)
            //   can  = max(last_height - 1 - CHAIN_LENGTH, 0) if last_last_hash
            //          is not None else last_height
            //   get  = min(want, can)
            auto CL = static_cast<int32_t>(PoolConfig::chain_length());
            auto want = std::max(CL - head_height, 0);
            auto can = last_last_hash.IsNull()
                ? last_height
                : std::max(last_height - 1 - CL, 0);
            auto to_get = std::min(want, can);

            if (to_get > 0)
            {
                // Carry-forward PPLNS ring: build once at the first share's
                // prev_hash, slide backward thereafter, and prime the decayed
                // cache so verify_share's get_v36_decayed_cumulative_weights hits
                // O(1). The ring uses the precomputed decay table — BIT-EXACT
                // with the iterative walk (same per-step truncation). The weight
                // split is the oracle's (p2poolBCH/p2pool/data.py:673-674).
                HeadPPLNS head_pplns;
                bool pplns_active = false;
                auto CL_i32 = static_cast<int32_t>(PoolConfig::chain_length());

                auto chain_view = chain.get_chain(last_hash, to_get);
                int p2_verified_count = 0;
                for (auto [hash, data] : chain_view)
                {
                    if (budget_remaining <= 0) { m_think_needs_continue = true; break; }

                    uint256 prev_hash;
                    int share_ver = 0;
                    data.share.invoke([&](auto* obj) {
                        prev_hash = obj->m_prev_hash;
                        share_ver = obj->version;
                    });
                    if (core::version_gate::is_v36_active(share_ver))
                    {
                        if (!prev_hash.IsNull() && chain.contains(prev_hash)) {
                            if (!pplns_active) {
                                head_pplns.rebuild(chain, prev_hash, CL_i32);
                                pplns_active = true;
                            } else {
                                auto ring_depth = head_pplns.window_size();
                                if (ring_depth > 0) {
                                    // deep_hash IS the new tail entry (depth
                                    // chain_len-1 from the new start). Taking its
                                    // .tail would shift one step too deep → an
                                    // off-by-one PPLNS error → GENTX mismatch.
                                    auto deep_hash = chain.get_nth_parent_via_skip(
                                        prev_hash, std::min(ring_depth - 1, CL_i32 - 1));
                                    if (!deep_hash.IsNull() && chain.contains(deep_hash))
                                        head_pplns.extend_backward(chain, deep_hash);
                                    else
                                        head_pplns.rebuild(chain, prev_hash, CL_i32);
                                }
                            }
                            if (pplns_active && head_pplns.valid()) {
                                auto& w = const_cast<HeadPPLNS&>(head_pplns).weights();
                                prime_pplns_cache(prev_hash, CL_i32, w);
                            }
                        }
                    }

                    // p2pool has no budget — already-verified shares are free
                    // (a head walking through another head's verified territory).
                    bool was_already_verified = verified.contains(hash);
                    if (!attempt_verify(hash)) break;
                    ++p2_verified_count;
                    if (!was_already_verified) --budget_remaining;
                }
            }

            // oracle data.py:781-788: request more shares if the verified chain
            // is still short. Skip if the MAIN chain is already in the pruning
            // zone (the unverified shares exist — they just need verification).
            if (head_height < static_cast<int32_t>(PoolConfig::chain_length()) && !last_last_hash.IsNull())
            {
                auto main_ht = chain.get_height(head_hash);
                auto CL_prune = static_cast<int32_t>(PoolConfig::chain_length());
                if (main_ht < 2 * CL_prune + 10 && !desired_hashes.count(last_last_hash)) {
                    NetService peer;
                    uint32_t head_ts = 0;
                    chain.get_share(head_hash).invoke([&](auto* obj) {
                        peer = obj->peer_addr;
                        head_ts = obj->m_timestamp;
                    });
                    desired_hashes.insert(last_last_hash);
                    desired.push_back({peer, last_last_hash, head_ts});
                }
            }
        }

        // ── Phase 3: score tails — pick the best tail (oracle data.py:790) ──
        // decorated_tails = sorted(score(max(verified.tails[t], key=verified.get_work), ...)
        //                          for t in verified.tails); best = decorated_tails[-1].
        std::vector<DecoratedData<TailScore>> decorated_tails;
        for (auto& [tail_hash, head_hashes] : verified.get_tails())
        {
            // COARSE walk-yield boundary: checked once per scored head (not in the
            // inner decay loop). Trips only on a degenerate window.
            if (walk_budget_remaining <= 0) {
                m_think_walk_needs_continue = true;
                LOG_WARNING << "[think-WALK-YIELD] scoring-walk budget exhausted; "
                               "deferring remaining tails to continuation";
                break;
            }

            uint256 best_head;
            uint288 best_work;
            bool first = true;
            for (const auto& hh : head_hashes)
            {
                if (!verified.contains(hh)) continue;
                auto w = verified.get_work(hh);
                if (first || w > best_work) { best_work = w; best_head = hh; first = false; }
            }

            if (!best_head.IsNull())
            {
                try {
                    auto s = score(best_head, block_rel_height_func);
                    s.best_head_work = best_work;   // tiebreak by total work
                    decorated_tails.push_back({s, tail_hash});
                    walk_budget_remaining -= std::max(s.chain_len, 1);
                } catch (const std::exception&) {
                    // Chain concurrently modified — skip; scored next cycle.
                }
            }
        }
        std::sort(decorated_tails.begin(), decorated_tails.end());

        uint256 best_tail;
        TailScore best_tail_score{};
        if (!decorated_tails.empty()) {
            best_tail = decorated_tails.back().hash;
            best_tail_score = decorated_tails.back().score;
        }
        (void)best_tail_score;

        // ── Phase 4: score heads within the best tail (oracle data.py:793-810) ──
        // decorated_heads sort key = (work_of_5th_ancestor - min(punish,1)*ata(target),
        //                             -reason, -time_seen). traditional_sort drops the
        //                             punishment deduction. BCH head-scoring punishes
        //                             only naughty (invalid-block) heads — the canonical
        //                             60% weighted version-switch is the check() gate
        //                             (share_check), NOT head-scoring.
        std::vector<DecoratedData<HeadScore>> decorated_heads;
        std::vector<DecoratedData<TraditionalScore>> traditional_sort;

        if (verified.get_tails().contains(best_tail))
        {
            const auto& head_hashes = verified.get_tails().at(best_tail);
            for (const auto& hh : head_hashes)
            {
                if (!verified.contains(hh)) continue;
                try {
                    // oracle: verified.get_work(verified.get_nth_parent_hash(
                    //             h, min(5, verified.get_height(h))))
                    auto v_height = verified.get_acc_height(hh);
                    auto recent_ancestor = verified.get_nth_parent_via_skip(hh, std::min(5, v_height));
                    uint288 work_score = verified.get_work(recent_ancestor);

                    auto* head_idx = chain.get_index(hh);
                    if (!head_idx) continue;
                    int64_t ts = head_idx->time_seen;

                    int32_t reason = 0;
                    if (head_idx->naughty > 0)
                        reason = head_idx->naughty;

                    uint288 adjusted_work = work_score;
                    if (reason > 0)
                        adjusted_work = adjusted_work - head_idx->work; // min(reason,1)*ata(target)

                    decorated_heads.push_back({{adjusted_work, -reason, -ts}, hh});
                    traditional_sort.push_back({{work_score, -ts, -reason}, hh});
                } catch (const std::exception&) {
                    // Chain concurrently modified — skip; retried next cycle.
                }
            }
            std::sort(decorated_heads.begin(), decorated_heads.end());
            std::sort(traditional_sort.begin(), traditional_sort.end());
        }

        // oracle: punish_aggressively = traditional_sort[-1][0][2]
        bool punish_aggressively = !traditional_sort.empty()
            && traditional_sort.back().score.neg_reason != 0;

        // ── Phase 5: determine best share (oracle data.py:812-836) ─────────
        // Walk back through punished (naughty) shares, then find the best
        // non-naughty descendent.
        uint256 best;
        if (!decorated_heads.empty())
            best = decorated_heads.back().hash;

        if (!best.IsNull() && chain.contains(best))
        {
            auto* best_idx = chain.get_index(best);
            if (best_idx && best_idx->naughty > 0)
            {
                while (best_idx && best_idx->naughty > 0)
                {
                    uint256 prev;
                    chain.get_share(best).invoke([&](auto* obj) { prev = obj->m_prev_hash; });
                    if (prev.IsNull() || !chain.contains(prev)) break;
                    best = prev;
                    best_idx = chain.get_index(best);

                    if (best_idx && best_idx->naughty == 0)
                    {
                        // oracle best_descendent: deepest non-naughty child.
                        std::function<std::pair<int,uint256>(const uint256&, int)> best_desc;
                        best_desc = [&](const uint256& h, int limit) -> std::pair<int,uint256> {
                            if (limit < 0) return {0, h};
                            auto& rev = chain.get_reverse();
                            auto rit = rev.find(h);
                            if (rit == rev.end() || rit->second.empty())
                                return {0, h};
                            std::pair<int,uint256> best_kid = {-1, h};
                            for (const auto& child : rit->second) {
                                auto* cidx = chain.get_index(child);
                                if (cidx && cidx->naughty > 0) continue;
                                auto [gen, hash] = best_desc(child, limit - 1);
                                if (gen + 1 > best_kid.first)
                                    best_kid = {gen + 1, hash};
                            }
                            return best_kid.first >= 0 ? best_kid : std::pair<int,uint256>{0, h};
                        };
                        auto [gens, desc_hash] = best_desc(best, 20);
                        (void)gens;
                        best = desc_hash;
                        break;
                    }
                }
            }
        }

        // ── Phase 6: timestamp cutoff + desired filter (oracle data.py:838-844) ──
        // timestamp_cutoff = min(now, best.timestamp) - 3600 (or now - 24h if no best).
        // return best, [(peer, hash) for ... in desired if ts >= timestamp_cutoff]
        uint32_t timestamp_cutoff;
        if (!best.IsNull() && chain.contains(best))
        {
            uint32_t best_ts = 0;
            chain.get_share(best).invoke([&](auto* obj) { best_ts = obj->m_timestamp; });
            timestamp_cutoff = std::min(static_cast<uint32_t>(now_seconds()), best_ts) - 3600;
        }
        else
        {
            timestamp_cutoff = static_cast<uint32_t>(now_seconds()) - 24 * 60 * 60;
        }

        std::vector<std::pair<NetService, uint256>> desired_result;
        for (auto& d : desired) {
            if (d.max_timestamp >= timestamp_cutoff)
                desired_result.emplace_back(d.peer, d.hash);
        }

        // Top-5 scored heads for clean_tracker head-protection
        // (oracle p2pool/node.py:356 — decorated_heads[-5:]).
        std::vector<uint256> top5;
        {
            size_t start = decorated_heads.size() > 5 ? decorated_heads.size() - 5 : 0;
            for (size_t i = start; i < decorated_heads.size(); ++i)
                top5.push_back(decorated_heads[i].hash);
        }

        return {best, desired_result, bad_peer_addresses, punish_aggressively, std::move(top5)};
    }

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

    // -- Startup block-solution scan (BCH standalone parent) --
    // Walk the verified best chain and fire m_on_block_found for any share whose
    // cached pow_hash meets the parent BCH block target. BCH is SHA256d
    // standalone (NOT merged-mined), so there is no merged-coinbase leg: this
    // mirrors btc share_tracker::scan_chain_for_blocks MINUS that check. O(1) per
    // share -- uses the pow_hash cached at init_verify, no SHA256d recompute.
    // The m_on_block_found sink is wired by the pool node to BOTH broadcast
    // paths: embedded P2P (Node::submit_block_p2p) + external submitblock RPC
    // fallback (CoinNode::submit_block_hex). Zero p2pool-v36 surface (block
    // detection, not share/PPLNS/coinbase bytes). Returns found-block count.
    int scan_chain_for_blocks(const uint256& tip, int max_shares)
    {
        if (tip.IsNull() || max_shares <= 0) return 0;
        int found = 0;
        uint256 pos = tip;
        for (int i = 0; i < max_shares && !pos.IsNull(); ++i) {
            if (!chain.contains(pos)) break;
            auto* idx = chain.get_index(pos);
            if (!idx) break;

            const uint256 pow = idx->pow_hash;
            if (pow.IsNull()) { pos = idx->tail; continue; }

            chain.get_share(pos).invoke([&](auto* obj) {
                // BCH block solution test: SHA256d pow vs the PARENT block
                // target carried in the share's m_min_header.m_bits (NOT the
                // share-difficulty m_bits). Conforms to verify_share's block
                // detection (share_check.hpp:745) and the btc donor scan
                // (m_min_header.m_bits). BCH is a standalone SHA256d parent —
                // no merged DOGE-target leg.
                const uint256 block_target = chain::bits_to_target(obj->m_min_header.m_bits);
                if (!block_target.IsNull() && pow <= block_target) {
                    idx->is_block_solution = true;
                    if (m_on_block_found) { m_on_block_found(pos); ++found; }
                }
            });
            pos = idx->tail;
        }
        return found;
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
    // -- think-engine support state (mirror btc SSOT) --
    // Retry counter for log throttling only — p2pool retries every think() with
    // no limit. Cleared on successful verification or on the chain removed signal.
    std::unordered_map<uint256, int, ShareHasher> m_verify_fail_count;

    static int64_t now_seconds()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // Invalidate all weight caches for a hash (chain mutated). BCH carries only
    // the flat-weights skiplist + the decayed result cache — NO merged-mining
    // skiplists (standalone SHA256d parent). Wired to chain.on_removed in ctor.
    void invalidate_weight_caches(const uint256& hash)
    {
        if (m_weights_skiplist) m_weights_skiplist->forget(hash);
        m_decayed_cache_valid = false; // chain changed — decayed cache stale
    }

    // Pre-populate the decayed-weights cache from a HeadPPLNS ring buffer so
    // verify_share -> get_v36_decayed_cumulative_weights() hits O(1). The ring
    // uses the precomputed decay table which is BIT-EXACT with the iterative
    // walk (identical per-step truncation) — NOT an approximation.
    void prime_pplns_cache(const uint256& start, int32_t max_shares,
                           const CumulativeWeights& weights)
    {
        m_decayed_cache_start = start;
        m_decayed_cache_shares = max_shares;
        // Verification always uses an unlimited desired_weight.
        m_decayed_cache_desired.SetHex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        m_decayed_cache_result = weights;
        m_decayed_cache_valid = true;
    }

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
    // -- Per-aux-chain merged skip lists (s0 port, btc SSOT share_tracker.hpp:2699/2815) --
    // BCH is a standalone parent so m_merged_coinbase_info is empty at runtime and these
    // never get a real chain_id; carried so verify_merged_coinbase_commitment compiles.
    std::unordered_map<uint32_t, chain::WeightsSkipList> m_merged_skiplists;

    // -- Decayed weights result cache --
    // Avoids recomputing the O(chain_length) walk when the same
    // (start, max_shares) is queried multiple times between chain changes
    // (e.g. verify_share + get_expected_payouts for the same share).
    bool m_decayed_cache_valid{false};
    uint256 m_decayed_cache_start;
    int32_t m_decayed_cache_shares{0};
    uint288 m_decayed_cache_desired;
    CumulativeWeights m_decayed_cache_result;

public:
    // -- Pool hashrate estimation --
    /// Pool hashrate estimation -- matches p2pool get_pool_attempts_per_second exactly.
    /// Uses skip list O(log n) for ancestor lookup + TrackerView delta cache O(1) for work sum.
    /// BCH-faithful: SHA256d work/target math, identical to the shared p2pool formula
    /// (no scrypt, no merged-mining divergence -- coin-independent).
    ///
    /// p2pool (data.py:2489-2499):
    ///   near = tracker.items[previous_share_hash]
    ///   far  = tracker.items[tracker.get_nth_parent_hash(previous_share_hash, dist - 1)]
    ///   attempts = tracker.get_delta(near.hash, far.hash).min_work   (if min_work)
    ///            = tracker.get_delta(near.hash, far.hash).work        (otherwise)
    ///   time = near.timestamp - far.timestamp
    ///   return attempts // time   (integer=True in generate_transaction)
    uint288 get_pool_attempts_per_second(const uint256& share_hash, int32_t dist, bool use_min_work = false)
    {
        if (dist < 2 || !chain.contains(share_hash))
            return uint288(0);

        // p2pool: far = tracker.items[tracker.get_nth_parent_hash(share_hash, dist - 1)]
        auto far_hash = chain.get_nth_parent_via_skip(share_hash, dist - 1);
        if (far_hash.IsNull() || !chain.contains(far_hash))
            return uint288(0);

        // Verify skip list vs naive walk (periodic -- detect stale pointers)
        {
            static int skip_verify = 0;
            if (skip_verify++ % 100 == 0) {
                try {
                    auto naive_far = chain.get_nth_parent_key(share_hash, dist - 1);
                    if (naive_far != far_hash) {
                        LOG_ERROR << "[SKIP-MISMATCH] dist=" << dist
                                  << " skip=" << far_hash.GetHex().substr(0,16)
                                  << " naive=" << naive_far.GetHex().substr(0,16)
                                  << " near=" << share_hash.GetHex().substr(0,16);
                    }
                } catch (...) {}
            }
        }

        // p2pool: tracker.get_delta(near.hash, far.hash)  -- O(1) via TrackerView
        auto delta = chain.get_delta(share_hash, far_hash);
        uint288 attempts = use_min_work ? delta.min_work : delta.work;

        // p2pool: time = near.timestamp - far.timestamp; if time <= 0: time = 1
        uint32_t near_ts = 0, far_ts = 0;
        chain.get_share(share_hash).invoke([&](auto* obj) { near_ts = obj->m_timestamp; });
        chain.get_share(far_hash).invoke([&](auto* obj) { far_ts = obj->m_timestamp; });

        int32_t time_span = static_cast<int32_t>(near_ts) - static_cast<int32_t>(far_ts);
        if (time_span <= 0) time_span = 1;

        return attempts / uint288(time_span);
    }

    // -- Share target computation (p2pool generate_transaction Phase 1) --
    // Computes {max_bits, bits} for a new/received share, matching p2pool-v36
    // BaseShare.generate_transaction():
    //   1. Derive pre_target from the pool hashrate estimate
    //   2. Clamp to ±10% of the previous share's max_target
    //   3. Apply emergency time-based decay (death-spiral prevention)
    //   4. Clamp to [MIN_TARGET, MAX_TARGET]
    // BCH-faithful: SHA256d work/target math (same family as btc), no scrypt,
    // no merged-mining divergence — coin-independent. The BCH ASERT DAA governs
    // the PARENT block header (verify_share/share_check), NOT this share-diff
    // retarget, which is the p2pool sharechain retarget shared by all coins.
    // verify_share (share_check.hpp) calls this to cross-check the share's bits.
    struct ShareTarget {
        uint32_t max_bits;
        uint32_t bits;
    };

    ShareTarget compute_share_target(
        const uint256& prev_share_hash,
        uint32_t desired_timestamp,
        const uint256& desired_target)
    {
        // MAX_TARGET: BCH share difficulty floor (PoolConfig::max_target()).
        const uint256 MAX_TARGET = PoolConfig::max_target();

        if (prev_share_hash.IsNull() || !chain.contains(prev_share_hash))
        {
            // Genesis or unknown prev: MAX_TARGET for max_bits; clip
            // desired_target to [MAX_TARGET/30, MAX_TARGET] for bits.
            auto pre_target3 = MAX_TARGET;
            auto max_bits = chain::target_to_bits_upper_bound(pre_target3);
            uint256 bits_lo = pre_target3 / 30;
            if (bits_lo.IsNull()) bits_lo = uint256(1);
            uint256 bits_target = desired_target;
            if (bits_target < bits_lo) bits_target = bits_lo;
            if (bits_target > pre_target3) bits_target = pre_target3;
            auto bits = chain::target_to_bits_upper_bound(bits_target);
            return {max_bits, bits};
        }

        // Accumulated height from the skip-list cache — O(1) and correct after
        // pruning (a raw get_height stops at a pruned tail and under-counts).
        auto acc_height = chain.get_acc_height(prev_share_hash);

        // Not enough chain depth for proper difficulty calculation.
        if (acc_height < static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND))
        {
            auto pre_target3 = MAX_TARGET;
            auto max_bits = chain::target_to_bits_upper_bound(pre_target3);
            uint256 bits_lo = pre_target3 / 30;
            if (bits_lo.IsNull()) bits_lo = uint256(1);
            uint256 bits_target = desired_target;
            if (bits_target < bits_lo) bits_target = bits_lo;
            if (bits_target > pre_target3) bits_target = pre_target3;
            auto bits = chain::target_to_bits_upper_bound(bits_target);
            return {max_bits, bits};
        }

        // Step 1: derive target from pool hashrate (min_work APS, all shares).
        auto aps = get_pool_attempts_per_second(prev_share_hash,
            PoolConfig::TARGET_LOOKBEHIND, /*min_work=*/true);

        uint256 pre_target;
        if (aps.IsNull())
        {
            pre_target = MAX_TARGET;
        }
        else
        {
            // pre_target = 2^256 / (SHARE_PERIOD * aps) - 1
            uint288 two_256;
            two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
            uint288 divisor = aps * static_cast<uint32_t>(PoolConfig::share_period());
            if (divisor.IsNull())
                divisor = uint288(1);
            uint288 result = two_256 / divisor;
            if (result > uint288(1))
                result = result - uint288(1);
            uint288 max_288;
            max_288.SetHex(MAX_TARGET.GetHex());
            if (result > max_288)
                pre_target = MAX_TARGET;
            else
                pre_target.SetHex(result.GetHex());
        }

        // Step 2: previous share's max_target.
        uint256 prev_max_target;
        chain.get_share(prev_share_hash).invoke([&](auto* obj) {
            prev_max_target = chain::bits_to_target(obj->m_max_bits);
        });

        // Step 3: emergency time-based decay (death-spiral prevention).
        // Doubles the target every SHARE_PERIOD*10s past a SHARE_PERIOD*20s
        // since-last-share threshold.
        uint256 clamp_ref_target = prev_max_target;
        uint32_t prev_ts = 0;
        chain.get_share(prev_share_hash).invoke([&](auto* obj) {
            prev_ts = obj->m_timestamp;
        });

        if (prev_ts > 0 && desired_timestamp > prev_ts)
        {
            auto time_since_share = desired_timestamp - prev_ts;
            auto emergency_threshold = PoolConfig::share_period() * 20;
            if (time_since_share > emergency_threshold)
            {
                auto half_life = PoolConfig::share_period() * 10;
                auto excess = time_since_share - emergency_threshold;
                auto halvings = excess / half_life;
                auto remainder = excess % half_life;
                uint256 eased = prev_max_target;
                if (halvings < 256)
                    eased <<= halvings;
                else
                    eased = MAX_TARGET;
                uint288 eased_288;
                eased_288.SetHex(eased.GetHex());
                eased_288 = eased_288 * static_cast<uint32_t>(half_life + remainder);
                eased_288 = eased_288 / static_cast<uint32_t>(half_life);
                uint288 max_288;
                max_288.SetHex(MAX_TARGET.GetHex());
                if (eased_288 > max_288)
                    clamp_ref_target = MAX_TARGET;
                else
                    clamp_ref_target.SetHex(eased_288.GetHex());
            }
        }

        // Step 4: clamp pre_target to ±10% of clamp_ref_target.
        uint256 lo;
        {
            uint288 lo_288;
            lo_288.SetHex(clamp_ref_target.GetHex());
            lo_288 = lo_288 * 9 / 10;
            uint288 max_288;
            max_288.SetHex(MAX_TARGET.GetHex());
            if (lo_288 > max_288) lo = MAX_TARGET;
            else lo.SetHex(lo_288.GetHex());
        }
        uint256 hi;
        {
            uint288 hi_288;
            hi_288.SetHex(clamp_ref_target.GetHex());
            hi_288 = hi_288 * 11;
            hi_288 = hi_288 / 10;
            uint288 max_288;
            max_288.SetHex(MAX_TARGET.GetHex());
            if (hi_288 > max_288) hi = MAX_TARGET;
            else hi.SetHex(hi_288.GetHex());
        }

        uint256 pre_target2 = pre_target;
        if (pre_target2 < lo) pre_target2 = lo;
        if (pre_target2 > hi) pre_target2 = hi;

        // Step 5: clamp to network limits; never zero (bits=0 is invalid).
        uint256 pre_target3 = pre_target2;
        if (pre_target3.IsNull()) pre_target3 = uint256(1);
        if (pre_target3 > MAX_TARGET) pre_target3 = MAX_TARGET;

        auto max_bits = chain::target_to_bits_upper_bound(pre_target3);

        // bits = from_target_upper_bound(clip(desired_target, (pre_target3/30, pre_target3)))
        uint256 bits_lo = pre_target3 / 30;
        if (bits_lo.IsNull()) bits_lo = uint256(1);
        uint256 bits_target = desired_target;
        if (bits_target < bits_lo) bits_target = bits_lo;
        if (bits_target > pre_target3) bits_target = pre_target3;
        auto bits = chain::target_to_bits_upper_bound(bits_target);

        return {max_bits, bits};
    }

    // -- V36 PPLNS walk dump (diagnostic; called by verify_share on mismatch) --
    // Per-share decayed-weight trace for cross-impl comparison against p2pool's
    // [PARENT-PPLNS] output. Uses the SAME weight split as the oracle
    // (p2poolBCH/p2pool/data.py:673-674): decayed_att*(65535-don) to the miner
    // script, decayed_att*don to donation. Read-only — no consensus mutation.
    void dump_v36_pplns_walk(const uint256& start_hash, int32_t max_shares)
    {
        if (start_hash.IsNull() || !chain.contains(start_hash))
        {
            LOG_WARNING << "[PPLNS-WALK] start=" << start_hash.GetHex().substr(0,16)
                        << " NOT IN CHAIN — walk aborted";
            return;
        }

        static constexpr uint64_t DECAY_PRECISION = 40;
        static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
        static constexpr uint64_t LN2_MICRO = 693147;

        uint32_t half_life = std::max(PoolConfig::chain_length() / 4, uint32_t(1));
        uint64_t decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);

        int32_t share_count = 0;
        uint64_t decay_fp = DECAY_SCALE;
        uint288 running_total;
        uint288 running_donation;
        std::map<std::vector<unsigned char>, uint288> per_addr_weight;

        auto height = chain.get_height(start_hash);
        auto last = chain.get_last(start_hash);

        LOG_WARNING << "[PPLNS-WALK] start=" << start_hash.GetHex().substr(0, 16)
                    << " max_shares=" << max_shares
                    << " height=" << height
                    << " last=" << (last.IsNull() ? "null" : last.GetHex().substr(0, 16))
                    << " half_life=" << half_life
                    << " decay_per=" << decay_per;

        auto cur = start_hash;
        while (!cur.IsNull() && chain.contains(cur) && share_count < max_shares)
        {
            chain.get_share(cur).invoke([&](auto* obj) {
                auto target = chain::bits_to_target(obj->m_bits);
                auto att = chain::target_to_average_attempts(target);
                uint32_t don = obj->m_donation;

                uint288 decayed_att = (att * uint288(decay_fp)) >> DECAY_PRECISION;
                auto addr_w = decayed_att * static_cast<uint32_t>(65535 - don);
                auto don_w  = decayed_att * don;

                auto script = get_share_script(obj);
                per_addr_weight[script] += addr_w;
                running_total += addr_w + don_w;
                running_donation += don_w;

                static const char* HX = "0123456789abcdef";
                std::string sh;
                for (size_t i = 0; i < std::min(script.size(), size_t(20)); ++i) {
                    sh += HX[script[i] >> 4];
                    sh += HX[script[i] & 0xf];
                }

                LOG_WARNING << "[PPLNS-WALK]   #" << share_count
                            << " hash=" << cur.GetHex().substr(0, 16)
                            << " script=" << sh
                            << " bits=0x" << std::hex << obj->m_bits << std::dec
                            << " don=" << don
                            << " att=" << att.GetLow64()
                            << " decay_fp=" << decay_fp
                            << " decayed=" << decayed_att.GetLow64()
                            << " addr_w=" << addr_w.GetLow64()
                            << " running=" << running_total.GetLow64();
            });

            ++share_count;
            decay_fp = mul128_shift(decay_fp, decay_per, DECAY_PRECISION);
            auto* idx = chain.get_index(cur);
            cur = idx ? idx->tail : uint256();
        }

        LOG_WARNING << "[PPLNS-WALK] SUMMARY: shares=" << share_count
                    << " addrs=" << per_addr_weight.size()
                    << " total_w=" << running_total.GetLow64()
                    << " don_w=" << running_donation.GetLow64();
        for (const auto& [script, weight] : per_addr_weight)
        {
            static const char* HX = "0123456789abcdef";
            std::string sh;
            for (size_t i = 0; i < std::min(script.size(), size_t(20)); ++i) {
                sh += HX[script[i] >> 4];
                sh += HX[script[i] & 0xf];
            }
            double pct = running_total.IsNull() ? 0.0 :
                static_cast<double>(weight.GetLow64()) / static_cast<double>(running_total.GetLow64()) * 100.0;
            LOG_WARNING << "[PPLNS-WALK]   " << sh
                        << " w=" << weight.GetLow64()
                        << " pct=" << std::fixed << std::setprecision(2) << pct << "%";
        }

        if (share_count < max_shares && !cur.IsNull()) {
            LOG_WARNING << "[PPLNS-WALK] CHAIN GAP: walk stopped at share #" << share_count
                        << " — next hash " << cur.GetHex().substr(0, 16)
                        << " is " << (chain.contains(cur) ? "IN chain (walk bug)" : "NOT IN chain (missing share)")
                        << ". Expected " << max_shares << " shares.";
        }
    }

    // -- AutoRatchet: PPLNS-weighted desired-version tally (canonical) --
    // Mirrors p2pool get_desired_version_counts (data.py:2651): walk `lookbehind`
    // shares back from share_hash and accumulate per-desired-version WORK weight
    // (idx->work = target_to_average_attempts), NOT a flat share count. Consumed by
    // share_check's 60% weighted version-switch boundary gate. BCH is a standalone
    // SHA256d parent — no merged/aux dimension here.
    std::map<uint64_t, uint288> get_desired_version_weights(const uint256& share_hash, int32_t lookbehind)
    {
        std::map<uint64_t, uint288> weights;
        if (!chain.contains(share_hash))
            return weights;
        auto height = chain.get_height(share_hash);
        auto actual = std::min(lookbehind, height);
        if (actual <= 0)
            return weights;

        auto view = chain.get_chain(share_hash, actual);
        for (auto [hash, data] : view)
        {
            uint64_t dv = 0;
            data.share.invoke([&](auto* obj) { dv = obj->m_desired_version; });
            auto* idx = chain.get_index(hash);
            if (idx)
                weights[dv] = weights[dv] + idx->work;
        }
        return weights;
    }

    // ───────────────────────────────────────────────────────────────────────
    // V36 merged-payout-hash machinery  (s0 port from btc::ShareTracker SSOT)
    //
    // BCH is a STANDALONE SHA256d parent (oracle bitcoincash.py has NO merged /
    // aux config), so at RUNTIME the share_check guard
    // `!share.m_merged_payout_hash.IsNull()` keeps these bodies dead.  They must
    // still COMPILE because share_check.hpp std::visit-instantiates over every
    // ShareVariant incl MergedMiningShare = BaseShare<36>.  Ported structurally
    // from src/impl/btc/share_tracker.hpp (SSOT carries the full v36 machinery
    // because BTC is also a standalone v36 parent) and conformed to
    // p2pool-merged-v36 p2pool/data.py.  No SegWit (BCH has none); SHA256d
    // coinbase/merkle preserved.  The DOGE/NMC aux-payout diagnostic block of
    // the btc donor is DROPPED here (no aux chains for a standalone parent).
    // ───────────────────────────────────────────────────────────────────────

    // -- merged_weights_delta (no-chain_id / v36 path) --
    // SSOT: btc::ShareTracker::merged_weights_delta (share_tracker.hpp:2311-2375).
    // Oracle: MergedWeightsSkipList.get_delta (data.py:1864-1900) and
    // get_v36_merged_weights (data.py invoked from compute_merged_payout_hash).
    // Pre-V36 shares count toward window sizing (share_count=1) but contribute
    // ZERO weight (p2pool returns (1, {}, 0, 0)).  Default address key is the RAW
    // parent script (share.new_script), hex-encoded by compute_merged_payout_hash.
    // BCH carries no explicit merged_addresses / m_miner_merged_addr, so the
    // per-chain (chain_id) resolution tiers of the SSOT are structurally absent
    // here; the standalone-parent path only ever calls with chain_id == nullopt.
    template <class ShareT>
    chain::WeightsDelta merged_weights_delta(ShareT* obj, std::optional<uint32_t> chain_id)
    {
        (void)chain_id;  // standalone parent: only the nullopt / v36 path is live
        chain::WeightsDelta delta;
        delta.share_count = 1;
        if (obj->m_desired_version < 36)
            return delta;   // pre-V36: window-sizing only, zero weight (data.py:1870)

        auto target = chain::bits_to_target(obj->m_bits);
        auto att = chain::target_to_average_attempts(target);
        auto parent_script = get_share_script(obj);   // raw scriptPubKey = new_script
        if (parent_script.empty())
            return delta;

        // Default key: RAW parent script, matching p2pool address_key =
        // share.new_script (data.py:1877).
        delta.total_weight = att * 65535;
        delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);
        delta.weights[parent_script] = att * static_cast<uint32_t>(65535 - obj->m_donation);
        return delta;
    }

    // Per-hash wrapper: bounds-check the raw chain, dispatch to merged_weights_delta.
    // SSOT: btc::ShareTracker::merged_weights_delta_for_hash (share_tracker.hpp:2378-2387).
    chain::WeightsDelta merged_weights_delta_for_hash(
        const uint256& hash, std::optional<uint32_t> chain_id)
    {
        chain::WeightsDelta delta;
        if (!chain.contains(hash)) return delta;
        chain.get_share(hash).invoke([&](auto* obj) {
            delta = merged_weights_delta(obj, chain_id);
        });
        return delta;
    }


    // -- Merged mining: per-chain PPLNS weights --
    // SSOT: btc::ShareTracker::get_merged_cumulative_weights (share_tracker.hpp:2205-2274).
    // For a specific aux chain_id, walk the share chain via the per-chain skip
    // list and accumulate PPLNS weights for V36-signaling shares.  Standalone
    // BCH never receives a real chain_id (m_merged_coinbase_info empty); carried
    // so verify_merged_coinbase_commitment instantiates/compiles.  The btc
    // [DOGE-PPLNS] per-address diagnostic block is DROPPED (no aux chains).
    CumulativeWeights get_merged_cumulative_weights(
        const uint256& start, int32_t max_shares,
        const uint288& desired_weight, uint32_t target_chain_id)
    {
        if (start.IsNull())
            return {};

        auto& sl = ensure_merged_skiplist(target_chain_id);
        auto result = sl.query(start, max_shares, desired_weight);
        return {std::move(result.weights), result.total_weight, result.total_donation_weight};
    }

    // SSOT: btc::ShareTracker::ensure_merged_skiplist (share_tracker.hpp:2815-2833).
    // Lazily builds a per-chain_id WeightsSkipList whose delta fn dispatches to
    // merged_weights_delta_for_hash with the chain_id (the per-chain path, which
    // for BCH collapses to the default raw-script key since no merged_addresses).
    chain::WeightsSkipList& ensure_merged_skiplist(uint32_t chain_id)
    {
        auto it = m_merged_skiplists.find(chain_id);
        if (it != m_merged_skiplists.end())
            return it->second;

        auto [new_it, _] = m_merged_skiplists.emplace(
            chain_id,
            chain::WeightsSkipList(
                [this, chain_id](const uint256& hash) -> chain::WeightsDelta {
                    return merged_weights_delta_for_hash(hash, chain_id);
                },
                make_previous_fn()
            )
        );
        return new_it->second;
    }

    // -- compute_merged_payout_hash --
    // SSOT: btc::ShareTracker::compute_merged_payout_hash (share_tracker.hpp:2398-2573).
    // Oracle: p2pool/data.py compute_merged_payout_hash (data.py:2782-2840).
    // Deterministic hash of V36-only PPLNS weight distribution; committed into
    // V36 shares so peers can verify merged payouts.  Walks the RAW chain (not
    // verified) matching p2pool (tracker, not tracker.verified).  Format:
    // "script_hex:weight|...|T:total|D:donation" -> SHA256d (bitcoin_data.hash256).
    // Returns zero uint256 when no V36 shares in window / no share history.
    uint256 compute_merged_payout_hash(
        const uint256& prev_share_hash, const uint256& block_target)
    {
        (void)block_target;  // V36 uses unlimited desired_weight (decay windows)
        if (prev_share_hash.IsNull())
            return uint256{};

        // RAW chain, matching p2pool compute_merged_payout_hash (data.py:2807).
        if (!chain.contains(prev_share_hash))
            return uint256{};

        auto height = chain.get_height(prev_share_hash);
        if (height == 0)
            return uint256{};   // data.py:2808-2809

        // Unlimited desired_weight -- V36 exponential decay handles windowing
        // (data.py:2814 uses 2**288 - 1).
        uint288 unlimited_weight;
        unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // chain_length = min(height, REAL_CHAIN_LENGTH)  (data.py:2812).
        auto chain_len = std::min(static_cast<int32_t>(height),
                                  static_cast<int32_t>(PoolConfig::real_chain_length()));

        // Walk RAW chain via WeightsSkipList; prev fn = raw chain tail (data.py:2807).
        auto raw_prev_fn = [this](const uint256& hash) -> uint256 {
            if (!chain.contains(hash)) return uint256{};
            return chain.get_index(hash)->tail;
        };
        chain::WeightsSkipList raw_sl(
            [this](const uint256& hash) -> chain::WeightsDelta {
                return merged_weights_delta_for_hash(hash, std::nullopt);
            },
            std::move(raw_prev_fn)
        );
        auto result = raw_sl.query(prev_share_hash, chain_len, unlimited_weight);
        auto weights = std::move(result.weights);
        auto total_weight = result.total_weight;
        auto donation_weight = result.total_donation_weight;

        if (weights.empty() || total_weight.IsNull())
            return uint256{};   // data.py:2818-2819

        // Decimal stringify (Python '%d' formatting).
        auto to_decimal = [](const uint288& val) -> std::string {
            if (val.IsNull()) return "0";
            uint288 tmp = val;
            std::string out;
            while (!tmp.IsNull()) {
                uint32_t rem = 0;
                for (int i = uint288::WIDTH - 1; i >= 0; --i) {
                    uint64_t cur = (static_cast<uint64_t>(rem) << 32) | tmp.pn[i];
                    tmp.pn[i] = static_cast<uint32_t>(cur / 10);
                    rem = static_cast<uint32_t>(cur % 10);
                }
                out.push_back('0' + static_cast<char>(rem));
            }
            std::reverse(out.begin(), out.end());
            return out;
        };

        // Script bytes -> hex (p2pool key.encode('hex'), data.py:2830).
        auto script_to_hex = [](const std::vector<unsigned char>& script) -> std::string {
            static const char digits[] = "0123456789abcdef";
            std::string hex;
            hex.reserve(script.size() * 2);
            for (unsigned char c : script) {
                hex.push_back(digits[c >> 4]);
                hex.push_back(digits[c & 0xf]);
            }
            return hex;
        };

        // Deterministic serialization: sorted by script hex (V36 consensus,
        // data.py:2826-2833).
        std::map<std::string, uint288> sorted_by_script;
        for (const auto& [script, w] : weights)
            sorted_by_script[script_to_hex(script)] += w;

        std::string payload;
        for (const auto& [script_hex, w] : sorted_by_script)
        {
            if (!payload.empty())
                payload.push_back('|');
            payload += script_hex;
            payload.push_back(':');
            payload += to_decimal(w);
        }
        payload += "|T:";
        payload += to_decimal(total_weight);
        payload += "|D:";
        payload += to_decimal(donation_weight);

        // SHA256d (bitcoin_data.hash256, data.py:2834).
        auto span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
        auto hash_result = Hash(span);

        {
            static int32_t s_last_log_height = -1;
            if (static_cast<int32_t>(height) != s_last_log_height) {
                s_last_log_height = static_cast<int32_t>(height);
                LOG_INFO << "[MERGED-PPLNS] height=" << height
                         << " chain_len=" << chain_len
                         << " addrs=" << sorted_by_script.size()
                         << " total_w=" << to_decimal(total_weight)
                         << " don_w=" << to_decimal(donation_weight)
                         << " hash=" << hash_result.GetHex();
            }
        }

        return hash_result;
    }
};

} // namespace bch
