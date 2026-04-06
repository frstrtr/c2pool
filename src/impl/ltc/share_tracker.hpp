#pragma once

#include "share.hpp"
#include "share_check.hpp"
#include "config_pool.hpp"

#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <sharechain/weights_skiplist.hpp>
#include <btclibs/base58.h>
#include <btclibs/bech32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace ltc
{

struct StaleCounts
{
    uint64_t orphan_count = 0;
    uint64_t doa_count = 0;
    uint64_t total = 0;
};

// --- Scoring types ---

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
    // Sorted ascending, .back() = best. Standard < comparison.
    uint288 adjusted_work;  // work - punishment_deduction
    int32_t neg_reason{};   // -reason (higher = less punished = better)
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
    // p2pool: (work, -time_seen, -reason)
    // No is_local. Sorted ascending, .back() = best.
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

// --- Result types ---

struct TrackerThinkResult
{
    uint256 best;
    std::vector<std::pair<NetService, uint256>> desired;
    std::set<NetService> bad_peer_addresses;
    bool punish_aggressively{false};
    // Top-5 scored heads from Phase 4 — used by clean_tracker() to protect
    // the best chains from head pruning (p2pool node.py:363).
    std::vector<uint256> top5_heads;
};

struct CumulativeWeights
{
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

// --- ShareTracker ---

class ShareTracker
{
public:
    ShareChain chain;
    ShareChain verified;

    // Runtime v36_active flag — set by AutoRatchet when state is ACTIVATED or CONFIRMED.
    // Used by generate_share_transaction to select PPLNS formula at runtime,
    // matching p2pool's behavior (data.py:879, work.py:759).
    bool is_v36_active() const { return v36_active_.load(std::memory_order_relaxed); }
    void set_v36_active(bool active) { v36_active_.store(active, std::memory_order_relaxed); }

    // Set by think() Phase 2 when verification budget is exhausted.
    // Checked by run_think() to schedule a deferred continuation.
    bool m_think_needs_continue{false};

private:
    std::atomic<bool> v36_active_{false};

    // Retry counter for log throttling only — p2pool retries every think()
    // with no limit.  Counter is cleared on successful verification or
    // when the share is removed from the chain (on_removed signal).
    std::unordered_map<uint256, int, ShareHasher> m_verify_fail_count;

    static int64_t now_seconds()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

public:
    // Callback fired when a share passes verification (for LevelDB persistence)
    std::function<void(const uint256&)> m_on_share_verified;
    // Callback fired when a verified share meets the block target (found block)
    std::function<void(const uint256&)> m_on_block_found;
    // Callback fired when a verified share meets a merged chain target (DOGE block)
    // Args: share_hash, pow_hash (for target comparison by caller)
    std::function<void(const uint256&, const uint256&)> m_on_merged_block_check;

    // Scan the verified best chain for block solutions after startup.
    // Calls share_init_verify (scrypt) on each share (~1ms each), then checks
    // g_last_init_is_block and g_last_pow_hash to fire block callbacks.
    void scan_chain_for_blocks(const uint256& tip, int max_shares)
    {
        if (tip.IsNull() || max_shares <= 0) return;
        int scanned = 0, found_ltc = 0;
        uint256 pos = tip;
        for (int i = 0; i < max_shares && !pos.IsNull(); ++i) {
            if (!chain.contains(pos)) break;
            auto& cd = chain.get(pos);
            cd.share.invoke([&](auto* s) {
                try {
                    g_last_init_is_block = false;
                    g_last_pow_hash = uint256();
                    share_init_verify(*s, true);  // computes scrypt + sets flags
                    ++scanned;

                    if (g_last_init_is_block && m_on_block_found) {
                        auto* idx = chain.get_index(pos);
                        if (idx) idx->is_block_solution = true;
                        m_on_block_found(pos);
                        ++found_ltc;
                    }
                    if (m_on_merged_block_check && !g_last_pow_hash.IsNull())
                        m_on_merged_block_check(pos, g_last_pow_hash);
                } catch (...) {}  // share_init_verify may throw on corrupt shares
                pos = s->m_prev_hash;
            });
        }
        LOG_INFO << "[BLOCK-SCAN] Scanned " << scanned << "/" << max_shares
                 << " shares: " << found_ltc << " LTC block(s) detected";
    }

    ShareTracker() {
        // p2pool SubsetTracker pattern: verified shares navigation
        // through the MAIN tracker's skip list.
        // SubsetTracker.get_nth_parent_hash = subset_of.get_nth_parent_hash
        verified.set_parent_chain(&chain);

        // Connect weight skip list invalidation to chain's removed signal.
        // p2pool: WeightsSkipList subscribes to tracker.removed via watch_weakref.
        // Without this, pruned shares leave stale entries in weight caches.
        chain.on_removed([this](const uint256& hash) {
            invalidate_weight_caches(hash);
            m_verify_fail_count.erase(hash);
        });
    }
    ~ShareTracker()
    {
        // verified borrows raw share pointers from chain — free its
        // indexes only, then let chain's destructor free the share data.
        verified.clear_unowned();
    }

    // -- Add share to the main chain --
    template <typename ShareT>
    void add(ShareT* share)
    {
        if (!chain.contains(share->m_hash))
        {
            try_register_merged_addr(share);
            chain.add(share);
        }
    }

    void add(ShareType share)
    {
        auto h = share.hash();
        if (!chain.contains(h))
        {
            // Register before chain.add() which may move the variant
            share.invoke([this](auto* obj) { try_register_merged_addr(obj); });
            chain.add(share);
        }
    }

    // -- Attempt to verify a share --
    // Returns true if share is verified (already or newly).
    // P2: share.check() will be wired here; for now we accept shares
    // that have sufficient chain depth.
    bool attempt_verify(const uint256& share_hash)
    {
        if (verified.contains(share_hash))
            return true;

        // p2pool has NO permanently-unverifiable concept — it retries
        // share.check() every think() call.  Shares that failed during a
        // temporary fork may succeed once the fork resolves and the PPLNS
        // walk changes.  Skipping re-verification created permanent gaps
        // in the verified chain → fragmentation (52 verified_tails).

        // NO parent-in-verified filter. p2pool doesn't have one.
        // p2pool's attempt_verify has only the guard (height < CL+1 && unrooted).
        // score() uses verified for height/work/chain (matching p2pool),
        // so fragmentation in the raw chain tracker doesn't affect scoring.

        // p2pool: height, last = self.get_height_and_last(share.hash)
        // p2pool's get_height uses get_delta_to_last() which walks through
        // SubsetTracker's cached deltas — equivalent to our acc cache.
        // Using acc cache height (not O(n) walk) matches p2pool's pattern
        // and gives correct height after pruning.
        auto acc_height = chain.get_acc_height(share_hash);
        auto last = chain.get_last(share_hash);

        // p2pool: if height < self.net.CHAIN_LENGTH + 1 and last is not None:
        //             raise AssertionError()
        // Chain too short and unrooted — cannot verify yet.
        // The share isn't bad; its parents haven't arrived to fill the gap.
        // DO NOT bypass this guard even if the parent is verified —
        // generate_share_transaction needs CHAIN_LENGTH ancestors for correct
        // PPLNS. Verifying with 3 ancestors produces wrong coinbase → GENTX-MISMATCH.
        // Phase 2 naturally extends verification when parents arrive.
        if (acc_height < static_cast<int32_t>(PoolConfig::chain_length()) + 1 && !last.IsNull())
        {
            return false;
        }

        // P2: init-phase verification (hash-link, merkle, PoW) + check-phase
        try
        {
            auto t0 = std::chrono::steady_clock::now();
            auto& share_var = chain.get_share(share_hash);
            share_var.ACTION({
                auto computed_hash = verify_share(*obj, *this);
                (void)computed_hash;
            });
            {
                auto dt = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0).count();
                static int64_t total_us = 0, count = 0;
                total_us += dt; ++count;
                if (count % 50 == 0)
                    LOG_INFO << "[VERIFY-PERF] last=" << dt << "us avg="
                             << (total_us/count) << "us count=" << count;
            }
        }
        catch (const std::exception& e)
        {
            // Counter for log throttling only — p2pool retries every think().
            auto& cnt = m_verify_fail_count[share_hash];
            ++cnt;
            // Log first 3 failures verbosely, then every 10th to avoid spam.
            if (cnt <= 3 || cnt % 10 == 0)
                LOG_WARNING << "attempt_verify FAILED (" << cnt
                            << ") for " << share_hash.ToString().substr(0,16)
                            << " acc_height=" << acc_height << " last=" << (last.IsNull() ? "null" : last.ToString().substr(0,16))
                            << " error: " << e.what();
            return false;
        }

        // Success — clear any previous fail count
        m_verify_fail_count.erase(share_hash);

        // Add to verified chain
        auto& share_var = chain.get_share(share_hash);
        if (!verified.contains(share_hash))
            verified.add(share_var);

        // Notify LevelDB persistence layer
        if (m_on_share_verified)
            m_on_share_verified(share_hash);

        // Block detection: if share_init_verify flagged this share as a block solution,
        // fire the callback. Matches p2pool's tracker.verified.added watcher (node.py:289).
        if (m_on_block_found && g_last_init_is_block) {
            g_last_init_is_block = false;
            auto* idx = chain.get_index(share_hash);
            if (idx) idx->is_block_solution = true;
            m_on_block_found(share_hash);
        }

        // Merged block detection: check ALL verified shares against DOGE target.
        // A share can meet the DOGE target without meeting the LTC target
        // (DOGE difficulty is much lower). The pow_hash was cached by share_init_verify.
        if (m_on_merged_block_check && !g_last_pow_hash.IsNull()) {
            m_on_merged_block_check(share_hash, g_last_pow_hash);
        }

        // Naughty propagation: if parent is naughty, increment (up to 6 generations)
        // Python data.py:1432-1438 — ancestor punishment for invalid block shares
        {
            uint256 prev_hash;
            share_var.invoke([&](auto* obj) { prev_hash = obj->m_prev_hash; });
            if (!prev_hash.IsNull() && chain.contains(prev_hash)) {
                auto* parent_idx = chain.get_index(prev_hash);
                if (parent_idx && parent_idx->naughty > 0) {
                    auto* my_idx = chain.get_index(share_hash);
                    if (my_idx) {
                        my_idx->naughty = parent_idx->naughty + 1;
                        if (my_idx->naughty > 6) my_idx->naughty = 0; // reset after 6 generations
                    }
                }
            }
        }

        // Block weight/size check: Python data.py:1508-1511 checks gentx + txs
        // against BLOCK_MAX_WEIGHT/SIZE, but only when other_txs is available.
        // For V34+ (including V36), other_txs is always None (shares use
        // transaction_hash_refs, not embedded txs), so Python SKIPS this check.
        // Therefore this is intentionally not computed for V36 shares.
        // The coinbase correctness is already verified by share_check() via
        // generate_share_transaction comparison.

        return true;
    }

    // -- Score a chain from share_hash to CHAIN_LENGTH*15/16 ancestor --
    // Returns (chain_len, hashrate_score) — higher is better.
    // p2pool data.py:2335-2347 — uses self.verified for ALL operations.
    // May throw if the chain is concurrently modified.
    TailScore score(const uint256& share_hash,
                    const std::function<int32_t(uint256)>& block_rel_height_func)
    {
        uint288 score_res;

        // p2pool: head_height = self.verified.get_height(share_hash)
        // Must use VERIFIED height — using chain inflates height with
        // unverified shares, causing short verified chains to tie on
        // chain_len with long chains and win on hashrate tiebreak.
        auto head_height = verified.get_acc_height(share_hash);
        if (head_height < static_cast<int32_t>(PoolConfig::chain_length()))
            return {head_height, score_res};

        // p2pool: end_point = self.verified.get_nth_parent_hash(
        //     share_hash, self.net.CHAIN_LENGTH*15//16)
        // SubsetTracker delegates to parent's skip list (shared navigation).
        auto end_point = verified.get_nth_parent_via_skip(share_hash,
            (PoolConfig::chain_length() * 15) / 16);

        // p2pool: self.verified.get_chain(end_point, self.net.CHAIN_LENGTH//16)
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

        // c2pool returns confirmations (1=tip, 0=unknown, -1=off-main-chain).
        // p2pool returns relative height (0=tip, -N=behind, -1e9=unknown).
        // When p2pool can't resolve a block, it computes score = work / (1e9 * 150)
        // — tiny but non-zero, so both chains get similar scores and the one
        // with more work wins (stable).  c2pool must match: use a very large
        // confirmation count so the score is tiny but non-zero, preventing
        // oscillation where short chains beat long chains simply because the
        // long chain's old blocks are unresolvable.
        if (!block_height.has_value() || block_height.value() <= 0)
            block_height = 1000000;  // ~1M confirmations → time_span ≈ 150M seconds

        // p2pool: self.verified.get_delta(share_hash, end_point).work
        auto total_work = verified.get_delta_work(share_hash, end_point);

        // p2pool: (0 - block_height + 1) * BLOCK_PERIOD
        // c2pool confirmations: 1=tip → 150s, 4 → 600s (matches p2pool).
        auto time_span = block_height.value() * 150; // LTC BLOCK_PERIOD = 150s
        if (time_span <= 0)
            time_span = 1;

        score_res = total_work / static_cast<uint32_t>(time_span);
        return {static_cast<int32_t>(PoolConfig::chain_length()), score_res};
    }

    // -- Best-chain selection with verification and punishment --
    TrackerThinkResult think(const std::function<int32_t(uint256)>& block_rel_height_func,
                             const uint256& previous_block,
                             uint32_t bits)
    {
        std::vector<std::pair<NetService, uint256>> desired;
        std::set<NetService> bad_peer_addresses;

        // Phase 1: Verify unverified heads, remove bad shares.
        // Exact translation of p2pool data.py:2077-2108.
        // For each unverified head: walk backward, try to verify.
        // If verification fails: remove the share (it's bad).
        // If no verification possible and chain unrooted: request parents.
        std::vector<uint256> bads;
        {
            // Snapshot heads — we'll modify chain during iteration
            auto heads_snapshot = chain.get_heads();
            int p1_skipped = 0, p1_walk0 = 0, p1_walked = 0, p1_verified = 0, p1_caught = 0;
            {
                static int p1_log = 0;
                if (p1_log++ % 10 == 0)
                    LOG_INFO << "[think-P1] raw_heads=" << heads_snapshot.size()
                             << " verified_heads=" << verified.get_heads().size();
            }
            for (auto& [head_hash, tail_hash] : heads_snapshot)
            {
                if (verified.get_heads().contains(head_hash)) {
                    ++p1_skipped;
                    continue;
                }

                if (!chain.contains(head_hash)) continue;

                auto [head_height, last] = chain.get_height_and_last(head_hash);

                // get_height now returns accumulated height (including parent
                // chain for new_fork shares). get_last follows segments to
                // the true last. No special fork detection needed.
                auto walk_count = last.IsNull()
                    ? head_height
                    : std::min(5, std::max(0, head_height - static_cast<int32_t>(PoolConfig::chain_length())));

                if (walk_count <= 0) {
                    ++p1_walk0;
                    // p2pool: when walk_count=0, get_chain returns nothing,
                    // no shares added to bads.  for/else requests parents.
                    // Do NOT remove height-1 unrooted heads as "stumps" —
                    // they're new peer shares whose parents haven't arrived yet.
                    // clean_tracker() eats truly stale heads after 300s.
                    if (!last.IsNull()) {
                        NetService peer;
                        chain.get_share(head_hash).invoke([&](auto* obj) {
                            peer = obj->peer_addr;
                        });
                        desired.emplace_back(peer, last);
                    }
                    continue;
                }

                ++p1_walked;
                bool verified_one = false;
                try {
                    auto chain_view = chain.get_chain(head_hash, walk_count);
                    for (auto [hash, data] : chain_view)
                    {
                        if (attempt_verify(hash))
                        {
                            verified_one = true;
                            ++p1_verified;
                            break;
                        }
                        // p2pool data.py:2215: bads.append(share.hash)
                        // ALL failing shares go into bads — p2pool has no
                        // permanently-unverifiable filter.  remove() returns
                        // false for mid-chain shares (NotImplementedError in
                        // p2pool), which is caught below.
                        bads.push_back(hash);
                    }
                } catch (const std::exception& ex) {
                    ++p1_caught;
                    LOG_WARNING << "[think-P1] exception walking head " << head_hash.GetHex().substr(0,16)
                                << " height=" << head_height << " walk=" << walk_count
                                << ": " << ex.what();
                    continue;
                }

                // Python for/else: if loop completed without break AND unrooted
                if (!verified_one && !last.IsNull())
                {
                    NetService peer;
                    chain.get_share(head_hash).invoke([&](auto* obj) {
                        peer = obj->peer_addr;
                    });
                    desired.emplace_back(peer, last);
                }
            }

            // Diagnostic: per-cycle summary
            {
                static int p1_sum_log = 0;
                if (p1_sum_log++ % 5 == 0)
                    LOG_INFO << "[think-P1-summary] heads=" << heads_snapshot.size()
                             << " skipped_verified=" << p1_skipped
                             << " walk0=" << p1_walk0
                             << " walked=" << p1_walked
                             << " verified=" << p1_verified
                             << " caught=" << p1_caught
                             << " bads=" << bads.size();
            }
        }

        // Phase 1.5 removed — was NOT in p2pool and caused GENTX-MISMATCH.
        // It tried to forward-propagate verification from verified parents to
        // unverified children, but children on stub forks (chain_len < CHAIN_LENGTH)
        // got verified with truncated PPLNS → wrong coinbase.
        // p2pool's Phase 2 naturally handles forward extension via rooted chains.

        // Remove bad shares (p2pool data.py:2224-2236).
        // p2pool tries self.remove(bad) for ALL bads — catches
        // NotImplementedError for mid-chain shares (have dependents).
        // c2pool's chain.remove() returns false for that case.
        // NO leaf-only filter — p2pool doesn't have one.
        {
            int removed_count = 0;
            for (const auto& bad : bads)
            {
                if (verified.contains(bad))
                    continue; // p2pool: raise ValueError (should never happen)
                if (!chain.contains(bad)) continue;

                NetService bad_peer;
                try {
                    chain.get_share(bad).invoke([&](auto* obj) {
                        bad_peer = obj->peer_addr;
                    });
                } catch (...) {}
                if (bad_peer.port() != 0)
                    bad_peer_addresses.insert(bad_peer);

                // p2pool data.py:2233-2236:
                //   try: self.remove(bad)
                //   except NotImplementedError: pass
                // chain.remove() returns false for mid-chain shares
                // (equivalent to NotImplementedError).
                try {
                    invalidate_weight_caches(bad);
                    if (verified.contains(bad))
                        verified.remove(bad);
                    if (chain.remove(bad))
                        ++removed_count;
                } catch (...) {}
            }
            if (removed_count > 0) {
                LOG_INFO << "[think-P1] removed " << removed_count
                         << " shares (bads=" << bads.size() << " + descendants)";
            }
        }

        // Phase 2: Extend verification from verified heads.
        // Budget-limited: verify up to THINK_VERIFY_BUDGET shares per call to
        // prevent blocking the io_context for tens of seconds. Remaining shares
        // are picked up by the next run_think() call (deferred via post()).
        // p2pool avoids this problem by persisting verified status — we do too
        // now, so budgeting is a safety net for cold starts only.
        constexpr int THINK_VERIFY_BUDGET = 100;
        int budget_remaining = THINK_VERIFY_BUDGET;
        m_think_needs_continue = false;
        {
            static int p2_skip_log = 0;
            if (p2_skip_log++ % 20 == 0)
                LOG_INFO << "[think-P2-iter] verified_heads=" << verified.get_heads().size()
                         << " chain=" << chain.size() << " verified=" << verified.size();
        }
        for (auto& [head_hash, tail_hash] : verified.get_heads())
        {
            if (budget_remaining <= 0) {
                m_think_needs_continue = true;
                break;
            }

            if (!chain.contains(head_hash)) {
                static int skip1 = 0;
                if (skip1++ < 5) LOG_WARNING << "[think-P2] skip: head not in chain " << head_hash.GetHex().substr(0,16);
                continue;
            }

            auto [head_height, last_hash] = verified.get_height_and_last(head_hash);
            if (!chain.contains(last_hash)) {
                static int skip2 = 0;
                if (skip2++ < 5) LOG_WARNING << "[think-P2] skip: last not in chain " << last_hash.GetHex().substr(0,16)
                                             << " head_height=" << head_height;
                continue;
            }

            auto [last_height, last_last_hash] = chain.get_height_and_last(last_hash);

            // p2pool data.py:2098-2103 EXACTLY:
            //   want = max(self.net.CHAIN_LENGTH - head_height, 0)
            //   can = max(last_height - 1 - self.net.CHAIN_LENGTH, 0) if last_last_hash is not None else last_height
            //   get = min(want, can)
            auto CL = static_cast<int32_t>(PoolConfig::chain_length());
            auto want = std::max(CL - head_height, 0);
            auto can = last_last_hash.IsNull()
                ? last_height
                : std::max(last_height - 1 - CL, 0);
            auto to_get = std::min(want, can);

            {
                static int p2_log = 0;
                if (p2_log++ % 20 == 0)
                    LOG_INFO << "[think-P2] head_height=" << head_height
                             << " last_height=" << last_height
                             << " last_rooted=" << last_last_hash.IsNull()
                             << " to_get=" << to_get;
            }

            if (to_get > 0)
            {
                auto chain_view = chain.get_chain(last_hash, to_get);
                int p2_verified_count = 0;
                for (auto [hash, data] : chain_view)
                {
                    if (budget_remaining <= 0) {
                        m_think_needs_continue = true;
                        LOG_INFO << "[think-P2] budget exhausted after " << p2_verified_count
                                 << " verifications, deferring remainder";
                        break;
                    }
                    if (!attempt_verify(hash))
                        break;
                    ++p2_verified_count;
                    --budget_remaining;
                    if (p2_verified_count % 50 == 0)
                        LOG_INFO << "[think-P2] verifying: " << p2_verified_count << "/" << to_get
                                 << " verified_total=" << verified.size();
                }
            }

            // Request more shares if verified chain is short
            if (head_height < static_cast<int32_t>(PoolConfig::chain_length()) && !last_last_hash.IsNull())
            {
                NetService peer;
                chain.get_share(head_hash).invoke([&](auto* obj) {
                    peer = obj->peer_addr;
                });
                desired.emplace_back(peer, last_last_hash);
            }
        }

        // Phase 3: Score tails — pick the best tail
        // p2pool: decorated_tails = sorted((self.score(
        //   max(self.verified.tails[tail_hash], key=self.verified.get_work), ...
        // Uses VERIFIED.get_work (verified TrackerView), NOT chain.get_work.
        // SubsetTracker.get_work walks verified items only.
        std::vector<DecoratedData<TailScore>> decorated_tails;
        for (auto& [tail_hash, head_hashes] : verified.get_tails())
        {
            // p2pool: max(verified.tails[tail_hash], key=verified.get_work)
            uint256 best_head;
            uint288 best_work;
            bool first = true;
            for (const auto& hh : head_hashes)
            {
                if (!verified.contains(hh)) continue;
                auto w = verified.get_work(hh);
                if (first || w > best_work)
                {
                    best_work = w;
                    best_head = hh;
                    first = false;
                }
            }

            if (!best_head.IsNull())
            {
                try {
                    auto s = score(best_head, block_rel_height_func);
                    s.best_head_work = best_work;  // tiebreak by total work
                    decorated_tails.push_back({s, tail_hash});
                } catch (const std::exception&) {
                    // Chain was concurrently modified (trim removed an
                    // ancestor).  Skip this tail — will be scored next cycle.
                }
            }
        }
        std::sort(decorated_tails.begin(), decorated_tails.end());

        uint256 best_tail;
        TailScore best_tail_score{};
        if (!decorated_tails.empty())
        {
            best_tail = decorated_tails.back().hash;
            best_tail_score = decorated_tails.back().score;
        }

        // Debug: log scoring when multiple tails compete
        if (decorated_tails.size() > 1) {
            static int score_log = 0;
            if (score_log++ % 10 == 0) {
                for (auto& dt : decorated_tails) {
                    LOG_INFO << "[SCORE-TAIL] tail=" << dt.hash.GetHex().substr(0,16)
                             << " chain_len=" << dt.score.chain_len
                             << " hashrate=" << dt.score.hashrate.IsNull()
                             << (dt.hash == best_tail ? " ← WINNER" : "");
                }
            }
        }

        // Phase 4: Score heads within the best tail — pick the best head
        std::vector<DecoratedData<HeadScore>> decorated_heads;
        std::vector<DecoratedData<TraditionalScore>> traditional_sort;

        if (verified.get_tails().contains(best_tail))
        {
            const auto& head_hashes = verified.get_tails().at(best_tail);
            for (const auto& hh : head_hashes)
            {
                if (!verified.contains(hh))
                    continue;

                try {
                    // p2pool Phase 4:
                    // self.verified.get_work(self.verified.get_nth_parent_hash(h, min(5, self.verified.get_height(h))))
                    // verified.get_height uses verified TrackerView
                    // verified.get_nth_parent_hash uses SHARED skip list (main tracker)
                    // verified.get_work uses verified TrackerView
                    auto v_height = verified.get_acc_height(hh);
                    auto recent_ancestor = verified.get_nth_parent_via_skip(hh, std::min(5, v_height));
                    uint288 work_score = verified.get_work(recent_ancestor);

                    auto* head_idx = chain.get_index(hh);
                    if (!head_idx) continue;
                    int64_t ts = head_idx->time_seen;

                    // Punish heads: version obsolescence OR naughty (invalid block)
                    int32_t reason = 0;
                    {
                        auto share_version = chain.get_share(hh).version();
                        auto lookbehind = static_cast<int32_t>(PoolConfig::chain_length());
                        if (should_punish_version(hh, share_version, lookbehind))
                            reason = 1;
                        auto* idx = chain.get_index(hh);
                        if (idx && idx->naughty > 0)
                            reason = std::max(reason, idx->naughty);
                    }

                    // p2pool: sort key = (work - min(punish,1)*ata(target), -reason, -time_seen)
                    // peer_addr is None is COMMENTED OUT in p2pool — no is_local dimension.
                    // Punishment deducted from work: a punished share is mathematically behind.
                    uint288 adjusted_work = work_score;
                    if (reason > 0) {
                        // Deduct one share's worth of attempts (min(reason,1) * ata(target))
                        auto* share_idx = chain.get_index(hh);
                        if (share_idx)
                            adjusted_work = adjusted_work - share_idx->work;
                    }
                    decorated_heads.push_back({{adjusted_work, -reason, -ts}, hh});
                    traditional_sort.push_back({{work_score, -ts, -reason}, hh});
                } catch (const std::exception&) {
                    // Chain concurrently modified — skip this head, retry next cycle
                }
            }
            std::sort(decorated_heads.begin(), decorated_heads.end());
            std::sort(traditional_sort.begin(), traditional_sort.end());
        }

        // p2pool: self.punish = punish value from Phase 5 (walk-back result)
        bool punish_aggressively = !traditional_sort.empty() && traditional_sort.back().score.neg_reason != 0;

        // Phase 5: Determine best share — p2pool data.py:2142-2166
        // Walk back through punished shares, then find best non-naughty descendent.
        uint256 best;
        int32_t punish_val = 0;
        if (!decorated_heads.empty())
            best = decorated_heads.back().hash;

        if (!best.IsNull() && chain.contains(best))
        {
            // Check if best share should be punished
            auto* best_idx = chain.get_index(best);
            if (best_idx && best_idx->naughty > 0)
            {
                // Walk back through punished shares
                while (best_idx && best_idx->naughty > 0)
                {
                    uint256 prev;
                    chain.get_share(best).invoke([&](auto* obj) {
                        prev = obj->m_prev_hash;
                    });
                    if (prev.IsNull() || !chain.contains(prev)) break;
                    best = prev;
                    best_idx = chain.get_index(best);

                    // p2pool: if not punish, find best descendent
                    if (best_idx && best_idx->naughty == 0)
                    {
                        // Find deepest non-naughty child via reverse map
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
                        best = desc_hash;
                        break;
                    }
                }
            }
            punish_val = (best_idx && best_idx->naughty > 0) ? best_idx->naughty : 0;
        }

        // Phase 6: Compute cutoffs for desired shares filtering
        uint32_t timestamp_cutoff;
        if (!best.IsNull() && chain.contains(best))
        {
            uint32_t best_ts = 0;
            chain.get_share(best).invoke([&](auto* obj) {
                best_ts = obj->m_timestamp;
            });
            timestamp_cutoff = std::min(static_cast<uint32_t>(now_seconds()), best_ts) - 3600;
        }
        else
        {
            timestamp_cutoff = static_cast<uint32_t>(now_seconds()) - 24 * 60 * 60;
        }

        // Filter desired by cutoff
        std::vector<std::pair<NetService, uint256>> desired_result;
        // For now, pass through all desired (timestamp filtering requires share timestamps at tail)
        desired_result = std::move(desired);

        // Extract top-5 scored heads for clean_tracker (p2pool node.py:363)
        std::vector<uint256> top5;
        {
            size_t start = decorated_heads.size() > 5 ? decorated_heads.size() - 5 : 0;
            for (size_t i = start; i < decorated_heads.size(); ++i)
                top5.push_back(decorated_heads[i].hash);
        }

        return {best, desired_result, bad_peer_addresses, punish_aggressively, std::move(top5)};
    }

    // -- Pool hashrate estimation --
    /// Pool hashrate estimation — matches p2pool get_pool_attempts_per_second exactly.
    /// Uses skip list O(log n) for ancestor lookup + TrackerView delta cache O(1) for work sum.
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

        // Verify skip list vs naive walk (periodic — detect stale pointers)
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

        // p2pool: tracker.get_delta(near.hash, far.hash)  — O(1) via TrackerView
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

    // -- Share target computation --
    // Computes max_bits and bits for a new share, matching p2pool-v36
    // BaseShare.generate_transaction():
    //   1. Derive pre_target from pool hashrate estimate
    //   2. Clamp to ±10% of previous share's max_target
    //   3. Apply emergency time-based decay (death spiral prevention)
    //   4. Clamp to [MIN_TARGET, MAX_TARGET]
    // Returns {max_bits, bits}.
    struct ShareTarget {
        uint32_t max_bits;
        uint32_t bits;
    };

    ShareTarget compute_share_target(
        const uint256& prev_share_hash,
        uint32_t desired_timestamp,
        const uint256& desired_target)
    {
        // MAX_TARGET: network-specific share difficulty floor
        // Mainnet: 2^236 - 1, Testnet: 2^256/20 - 1  (from PoolConfig)
        const uint256 MAX_TARGET = PoolConfig::max_target();

        if (prev_share_hash.IsNull() || !chain.contains(prev_share_hash))
        {
            // Genesis or unknown prev: use MAX_TARGET for max_bits,
            // clip desired_target to [MAX_TARGET/30, MAX_TARGET] for bits.
            // Matches p2pool generate_transaction (data.py:746-774).
            auto pre_target3 = MAX_TARGET;
            auto max_bits = chain::target_to_bits_upper_bound(pre_target3);
            // No round-up guard needed — truncation matches p2pool's actual behavior
            uint256 bits_lo = pre_target3 / 30;
            if (bits_lo.IsNull()) bits_lo = uint256(1);
            uint256 bits_target = desired_target;
            if (bits_target < bits_lo) bits_target = bits_lo;
            if (bits_target > pre_target3) bits_target = pre_target3;
            auto bits = chain::target_to_bits_upper_bound(bits_target);
            // No round-up guard needed — truncation matches p2pool's actual behavior
            return {max_bits, bits};
        }

        // Use accumulated height from skip list cache — O(1) and correct
        // even after pruning (get_height walks until chain end, stops at
        // pruned tail → returns short value → triggers MAX_TARGET fallback).
        auto acc_height = chain.get_acc_height(prev_share_hash);

        // Not enough chain depth for proper difficulty calculation.
        if (acc_height < static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND))
        {
            // Collapse detection: many shares exist but best chain is short
            auto total_shares = chain.size();
            if (total_shares > 2 * PoolConfig::chain_length()
                && acc_height < static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND)) {
                static int collapse_warn = 0;
                if (collapse_warn++ < 20) {
                    // Walk raw chain to find actual contiguous height
                    int32_t walked = 0;
                    auto cur = prev_share_hash;
                    while (!cur.IsNull() && chain.contains(cur) && walked < 1000) {
                        ++walked;
                        auto* idx = chain.get_index(cur);
                        cur = idx ? idx->tail : uint256();
                    }
                    LOG_WARNING << "[COLLAPSE-DETECT] Chain structurally broken:"
                                << " total_shares=" << total_shares
                                << " acc_height=" << acc_height
                                << " walked_height=" << walked
                                << " tails=" << chain.get_tails().size()
                                << " heads=" << chain.get_heads().size()
                                << " TARGET_LOOKBEHIND=" << PoolConfig::TARGET_LOOKBEHIND
                                << " prev=" << prev_share_hash.GetHex().substr(0,16);
                }
            }
            auto pre_target3 = MAX_TARGET;
            auto max_bits = chain::target_to_bits_upper_bound(pre_target3);
            // No round-up guard needed — truncation matches p2pool's actual behavior
            uint256 bits_lo = pre_target3 / 30;
            if (bits_lo.IsNull()) bits_lo = uint256(1);
            uint256 bits_target = desired_target;
            if (bits_target < bits_lo) bits_target = bits_lo;
            if (bits_target > pre_target3) bits_target = pre_target3;
            auto bits = chain::target_to_bits_upper_bound(bits_target);
            // No round-up guard needed — truncation matches p2pool's actual behavior
            return {max_bits, bits};
        }

        // Step 1: Derive target from pool hashrate.
        // Use prev_share_hash directly — all shares counted equally.
        // p2pool's algorithm: aps from the entire chain, no filtering.
        auto aps = get_pool_attempts_per_second(prev_share_hash,
            PoolConfig::TARGET_LOOKBEHIND, /*min_work=*/true);

        // Full APS diagnostic for cross-implementation comparison.
        // Dumps all inputs so p2pool's values can be compared.
        {
            static int cst_diag = 0;
            if (cst_diag++ % 50 == 0) {
                auto far_hash = chain.get_nth_parent_via_skip(prev_share_hash,
                    static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND) - 1);
                uint32_t near_ts = 0, far_ts = 0;
                chain.get_share(prev_share_hash).invoke([&](auto* obj) { near_ts = obj->m_timestamp; });
                if (!far_hash.IsNull() && chain.contains(far_hash))
                    chain.get_share(far_hash).invoke([&](auto* obj) { far_ts = obj->m_timestamp; });
                auto delta = (!far_hash.IsNull() && chain.contains(far_hash))
                    ? chain.get_delta(prev_share_hash, far_hash)
                    : decltype(chain.get_delta(prev_share_hash, prev_share_hash)){};
                LOG_INFO << "[CST-APS] aps=" << aps.GetLow64()
                         << " height=" << acc_height
                         << " prev=" << prev_share_hash.GetHex().substr(0,16)
                         << " far=" << (far_hash.IsNull() ? "null" : far_hash.GetHex().substr(0,16))
                         << " near_ts=" << near_ts << " far_ts=" << far_ts
                         << " timespan=" << (int32_t(near_ts) - int32_t(far_ts))
                         << " delta_h=" << delta.height
                         << " delta_min_work=" << delta.min_work.GetLow64()
                         << " delta_work=" << delta.work.GetLow64();
            }
        }

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
            // Clamp to 256-bit range
            uint288 max_288;
            max_288.SetHex(MAX_TARGET.GetHex());
            if (result > max_288)
            {
                pre_target = MAX_TARGET;
            }
            else
            {
                pre_target.SetHex(result.GetHex());
            }
        }

        // Step 2: Get previous share's max_target
        uint256 prev_max_target;
        chain.get_share(prev_share_hash).invoke([&](auto* obj) {
            prev_max_target = chain::bits_to_target(obj->m_max_bits);
        });

        // Step 3: Emergency time-based decay (death spiral prevention)
        // Phase 1b from p2pool-v36: doubles target every SHARE_PERIOD * 10
        // seconds past the threshold of SHARE_PERIOD * 20 seconds since last share.
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
                // 2^halvings with linear interpolation for fractional part
                uint256 eased = prev_max_target;
                if (halvings < 256)
                    eased <<= halvings;
                else
                    eased = MAX_TARGET;
                // Linear interpolation: eased = eased * (half_life + remainder) / half_life
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

        // Step 4: Clamp pre_target to ±10% of clamp_ref_target
        // pre_target2 = clip(pre_target, (clamp_ref * 9/10, clamp_ref * 11/10))
        // p2pool: target * 9 // 10 (multiply first, then divide)
        uint256 lo;
        {
            uint288 lo_288;
            lo_288.SetHex(clamp_ref_target.GetHex());
            lo_288 = lo_288 * 9 / 10;
            uint288 max_288;
            max_288.SetHex(MAX_TARGET.GetHex());
            if (lo_288 > max_288)
                lo = MAX_TARGET;
            else
                lo.SetHex(lo_288.GetHex());
        }
        uint256 hi;
        {
            uint288 hi_288;
            hi_288.SetHex(clamp_ref_target.GetHex());
            hi_288 = hi_288 * 11;
            hi_288 = hi_288 / 10;
            uint288 max_288;
            max_288.SetHex(MAX_TARGET.GetHex());
            if (hi_288 > max_288)
                hi = MAX_TARGET;
            else
                hi.SetHex(hi_288.GetHex());
        }

        uint256 pre_target2 = pre_target;
        if (pre_target2 < lo) pre_target2 = lo;
        if (pre_target2 > hi) pre_target2 = hi;

        // Step 5: Clamp to network limits [MIN_TARGET, MAX_TARGET]
        // Ensure target is never zero (would produce bits=0 → "share target is zero" error)
        uint256 pre_target3 = pre_target2;
        if (pre_target3.IsNull()) pre_target3 = uint256(1);
        if (pre_target3 > MAX_TARGET) pre_target3 = MAX_TARGET;

        auto max_bits = chain::target_to_bits_upper_bound(pre_target3);

        // No round-up guard needed — truncation matches p2pool's actual behavior

        // Apply 1.67% share cap: desired_target cannot be easier than
        // pool_target / 0.0167 ≈ pool_target * 60. This ensures no single
        // miner can produce more than ~1.67% of all shares (anti-spam).
        // P2pool ref: work.py line 2402: hashrate * SHARE_PERIOD / 0.0167
        uint256 cap_target = pre_target3; // default: pool target (1 share/period)
        // cap_target represents the easiest target a single miner should use.
        // At pool target difficulty, a miner with all pool hashrate produces
        // 1 share/period. At pre_target3 (the pool target), that's 100%.
        // desired_target is already clipped to [pre_target3//30, pre_target3]
        // so the cap is inherently enforced by the upper clamp to pre_target3.

        // DUST threshold: if the pool share target is too hard for tiny miners,
        // allow shares at up to 30x easier difficulty (pre_target3 * 30 would be
        // out of bounds, so the 30x range [pre_target3//30, pre_target3] is the
        // full allowed range — this is already how p2pool works).
        // The key fix is that desired_target = MAX_TARGET (from caller), which
        // gets clipped to pre_target3 here — shares at pool difficulty.
        // Tiny miners simply find them less often, proportional to hashrate.

        // bits = from_target_upper_bound(clip(desired_target, (pre_target3/30, pre_target3)))
        uint256 bits_lo = pre_target3 / 30;
        if (bits_lo.IsNull()) bits_lo = uint256(1);
        uint256 bits_target = desired_target;
        if (bits_target < bits_lo) bits_target = bits_lo;
        if (bits_target > pre_target3) bits_target = pre_target3;
        auto bits = chain::target_to_bits_upper_bound(bits_target);

        // Periodic full-chain diagnostic for cross-implementation comparison.
        // Dumps all intermediate values so p2pool's computation can be matched.
        {
            static int cst_full = 0;
            if (cst_full++ % 200 == 0) {
                LOG_INFO << "[CST-FULL] max_bits=0x" << std::hex << max_bits
                         << " bits=0x" << bits << std::dec
                         << " aps=" << aps.GetLow64()
                         << " pre_target_bits=0x" << std::hex
                         << chain::target_to_bits_upper_bound(pre_target)
                         << " clamp_ref_bits=0x"
                         << chain::target_to_bits_upper_bound(clamp_ref_target)
                         << " lo_bits=0x" << chain::target_to_bits_upper_bound(lo)
                         << " hi_bits=0x" << chain::target_to_bits_upper_bound(hi)
                         << " pre2_bits=0x" << chain::target_to_bits_upper_bound(pre_target2)
                         << " pre3_bits=0x" << chain::target_to_bits_upper_bound(pre_target3)
                         << std::dec
                         << " height=" << acc_height
                         << " prev=" << prev_share_hash.GetHex().substr(0,16);
            }
        }
        return {max_bits, bits};
    }

    // -- Minimum viable hashrate for dashboard display --
    // Returns the minimum hashrate (H/s) needed to produce at least 1 share
    // per PPLNS window. With DUST (30x range), tiny miners get easier shares.
    struct MinerThresholds {
        double min_hashrate_normal;  // H/s at pool share difficulty
        double min_hashrate_dust;    // H/s at 30x easier (DUST)
        double min_payout_ltc;       // LTC per share at pool difficulty
        double pool_hashrate;        // current pool H/s estimate
    };

    MinerThresholds get_miner_thresholds(const uint256& prev_share_hash,
                                          uint64_t block_subsidy_sat)
    {
        MinerThresholds t{};
        if (prev_share_hash.IsNull() || !chain.contains(prev_share_hash))
            return t;

        auto [height, last] = chain.get_height_and_last(prev_share_hash);
        if (height < 2) return t;

        auto lookback = std::min(height,
            static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND));
        auto aps = get_pool_attempts_per_second(prev_share_hash,
            lookback, /*min_work=*/true);

        double pool_hr = 0;
        {
            uint288 aps_288 = aps;
            // Convert uint288 to double (approximate)
            for (int i = uint288::WIDTH - 1; i >= 0; --i) {
                pool_hr = pool_hr * 4294967296.0 + aps_288.pn[i];
            }
        }
        t.pool_hashrate = pool_hr;

        double share_period = static_cast<double>(PoolConfig::share_period());
        double chain_length = static_cast<double>(PoolConfig::real_chain_length());

        // min_hashrate = pool_share_att / window = pool_hr / chain_length
        t.min_hashrate_normal = pool_hr / chain_length;
        t.min_hashrate_dust = t.min_hashrate_normal / 30.0; // 30x DUST range

        // min_payout = block_subsidy / chain_length (one share in full window)
        t.min_payout_ltc = static_cast<double>(block_subsidy_sat) / 1e8 / chain_length;

        return t;
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

            decay_fp = static_cast<uint64_t>(
                (static_cast<__uint128_t>(decay_fp) * decay_per) >> DECAY_PRECISION);

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
                LOG_INFO << "[EP-PPLNS] v36 start=" << best_share_hash.GetHex().substr(0, 16)
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
                LOG_INFO << "[EP-PPLNS] v35 start=" << pplns_start.GetHex().substr(0, 16)
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
                LOG_INFO << "[V35-PPLNS] subsidy=" << subsidy << " addrs=" << weights.size()
                         << " total_w=" << total_weight.GetLow64()
                         << " max_shares=" << max_shares << " sum=" << sum
                         << " donation=" << donation_amount
                         << " prev=" << best_share_hash.GetHex().substr(0, 16)
                         << " grandparent=" << pplns_start.GetHex().substr(0, 16);
            }
        }

        return result;
    }

    // -- Stale share proportion --
    float get_average_stale_prop(const uint256& share_hash, uint64_t lookbehind)
    {
        auto height = chain.get_height(share_hash);
        auto actual_lookbehind = std::min(static_cast<int32_t>(lookbehind), height);
        if (actual_lookbehind <= 0)
            return 0.0f;

        float stale_count = 0;
        auto view = chain.get_chain(share_hash, actual_lookbehind);
        for (auto [hash, data] : view)
        {
            StaleInfo si = StaleInfo::none;
            data.share.invoke([&](auto* obj) { si = obj->m_stale_info; });
            if (si != StaleInfo::none)
                stale_count += 1.0f;
        }

        return stale_count / (stale_count + static_cast<float>(actual_lookbehind));
    }

    // -- Stale share counts by type --
    StaleCounts get_stale_counts(const uint256& share_hash, uint64_t lookbehind)
    {
        StaleCounts counts;
        auto height = chain.get_height(share_hash);
        auto actual_lookbehind = std::min(static_cast<int32_t>(lookbehind), height);
        if (actual_lookbehind <= 0)
            return counts;

        auto view = chain.get_chain(share_hash, actual_lookbehind);
        for (auto [hash, data] : view)
        {
            StaleInfo si = StaleInfo::none;
            data.share.invoke([&](auto* obj) { si = obj->m_stale_info; });
            if (si == StaleInfo::orphan)
                counts.orphan_count++;
            else if (si == StaleInfo::doa)
                counts.doa_count++;
        }
        counts.total = counts.orphan_count + counts.doa_count;
        return counts;
    }

    // -- Stale change callback registration --
    using stale_callback_t = std::function<void(const uint256& /*share_hash*/, StaleInfo /*new_stale_info*/)>;

    void subscribe_stale_change(stale_callback_t cb)
    {
        m_stale_callbacks.push_back(std::move(cb));
    }

    void notify_stale_change(const uint256& share_hash, StaleInfo info)
    {
        for (auto& cb : m_stale_callbacks)
            cb(share_hash, info);
    }

    // -- Version counting for AutoRatchet upgrade coordination --
    // Walks back `lookbehind` shares from `share_hash` and counts
    // how many desire each version. Returns map of version → count.
    // Python ref: tracker.get_desired_version_counts(...)
    std::map<uint64_t, int32_t> get_desired_version_counts(const uint256& share_hash, int32_t lookbehind)
    {
        std::map<uint64_t, int32_t> counts;
        if (!chain.contains(share_hash))
            return counts;
        auto height = chain.get_height(share_hash);
        auto actual = std::min(lookbehind, height);
        if (actual <= 0)
            return counts;

        auto view = chain.get_chain(share_hash, actual);
        for (auto [hash, data] : view)
        {
            uint64_t dv = 0;
            data.share.invoke([&](auto* obj) { dv = obj->m_desired_version; });
            counts[dv]++;
        }
        return counts;
    }

    // -- Merged mining: per-chain PPLNS weights --
    // For a specific aux chain_id, walk the share chain and accumulate PPLNS
    // weights for V36-signaling shares.  Uses O(log n) skip list.
    CumulativeWeights get_merged_cumulative_weights(
        const uint256& start, int32_t max_shares,
        const uint288& desired_weight, uint32_t target_chain_id)
    {
        if (start.IsNull())
            return {};

        auto& sl = ensure_merged_skiplist(target_chain_id);
        auto result = sl.query(start, max_shares, desired_weight);

        // [DOGE-PPLNS] Per-address breakdown — shows whether autoconverted
        // addresses appear in merged PPLNS weights.  Log once per new height.
        {
            static int32_t s_last_doge_height = -1;
            auto h = chain.get_height(start);
            if (h != s_last_doge_height) {
                s_last_doge_height = h;
                auto to_dec = [](const uint288& val) -> std::string {
                    if (val.IsNull()) return "0";
                    uint288 tmp = val; std::string r;
                    while (!tmp.IsNull()) {
                        uint32_t rem = 0;
                        for (int i = uint288::WIDTH - 1; i >= 0; --i) {
                            uint64_t cur = (static_cast<uint64_t>(rem) << 32) | tmp.pn[i];
                            tmp.pn[i] = static_cast<uint32_t>(cur / 10);
                            rem = static_cast<uint32_t>(cur % 10);
                        }
                        r.push_back('0' + static_cast<char>(rem));
                    }
                    std::reverse(r.begin(), r.end());
                    return r;
                };
                auto to_hex = [](const std::vector<unsigned char>& s) -> std::string {
                    static const char* H = "0123456789abcdef";
                    std::string r; r.reserve(s.size() * 2);
                    for (auto b : s) { r += H[b >> 4]; r += H[b & 0xf]; }
                    return r;
                };
                // Classify script type for diagnostics
                auto classify = [](const std::vector<unsigned char>& s) -> const char* {
                    if (is_merged_key(s)) return "MERGED";
                    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9) return "P2PKH";
                    if (s.size() == 23 && s[0] == 0xa9) return "P2SH";
                    if (s.size() == 22 && s[0] == 0x00 && s[1] == 0x14) return "P2WPKH-RAW";
                    if (s.size() == 34 && s[0] == 0x00 && s[1] == 0x20) return "P2WSH-RAW";
                    if (s.size() == 34 && s[0] == 0x51 && s[1] == 0x20) return "P2TR-RAW";
                    return "OTHER";
                };
                LOG_INFO << "[DOGE-PPLNS] chain_id=" << target_chain_id
                         << " height=" << h
                         << " max_shares=" << max_shares
                         << " addrs=" << result.weights.size()
                         << " total_w=" << to_dec(result.total_weight)
                         << " don_w=" << to_dec(result.total_donation_weight)
                         << " start=" << start.GetHex().substr(0, 16);
                for (const auto& [key, w] : result.weights) {
                    double pct = 0;
                    if (!result.total_weight.IsNull())
                        pct = (w * 10000 / result.total_weight).GetLow64() / 100.0;
                    auto hex = to_hex(key);
                    LOG_INFO << "[DOGE-PPLNS]   " << classify(key)
                             << " " << hex.substr(0, 40)
                             << " w=" << to_dec(w)
                             << " pct=" << std::fixed << std::setprecision(2) << pct << "%";
                }
            }
        }

        return {std::move(result.weights), result.total_weight, result.total_donation_weight};
    }

    // -- V36-only unified merged weights (no chain_id) --
    // Accumulates PPLNS weights for V36-signaling shares ONLY, keyed by
    // parent chain address.  Uses O(log n) skip list.
    CumulativeWeights get_v36_merged_weights(
        const uint256& start, int32_t max_shares, const uint288& desired_weight)
    {
        if (start.IsNull())
            return {};

        ensure_v36_skiplist();
        auto result = m_v36_weights_skiplist->query(start, max_shares, desired_weight);
        return {std::move(result.weights), result.total_weight, result.total_donation_weight};
    }

    // -- compute_merged_payout_hash --
    // Deterministic hash of V36-only PPLNS weight distribution.
    // Committed into V36 shares so peers can verify that the share creator's
    // merged mining payouts match the expected distribution.
    //
    // Format: sorted "addr_hex:weight|...|T:total|D:donation" → SHA256d
    // Returns zero uint256 if no V36 shares in window.
    //
    // Python ref: p2pool/data.py compute_merged_payout_hash()
    uint256 compute_merged_payout_hash(
        const uint256& prev_share_hash, const uint256& block_target)
    {
        if (prev_share_hash.IsNull())
            return uint256{};

        // Use RAW chain — matches p2pool's compute_merged_payout_hash()
        // which uses tracker (raw), not tracker.verified.
        // Using verified chain caused zero returns when prev_share wasn't
        // yet verified → ref_hash mismatch → GENTX-FAIL.
        if (!chain.contains(prev_share_hash))
            return uint256{};

        auto height = chain.get_height(prev_share_hash);
        if (height == 0)
            return uint256{};

        // No chain depth guard — p2pool computes merged_payout_hash for ANY
        // height > 0 using chain_length = min(height, REAL_CHAIN_LENGTH).
        // The previous guard (height < CHAIN_LENGTH → return zero) caused
        // ref_hash mismatch because p2pool computed a real hash while c2pool
        // returned zero.

        // Unlimited desired_weight — V36 exponential decay handles windowing.
        uint288 unlimited_weight;
        unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        auto chain_len = std::min(height,
                                  static_cast<int32_t>(PoolConfig::real_chain_length()));

        // Walk RAW chain (not verified) — matches p2pool's compute_merged_payout_hash
        // which uses tracker (raw). Using verified chain causes hash mismatch when
        // the verified chain is shorter (during sync or with missing ancestors).
        auto raw_prev_fn = [this](const uint256& hash) -> uint256 {
            if (!chain.contains(hash)) return uint256{};
            return chain.get_index(hash)->tail;
        };
        chain::WeightsSkipList raw_sl(
            [this](const uint256& hash) -> chain::WeightsDelta {
                chain::WeightsDelta delta;
                if (!chain.contains(hash)) return delta;
                delta.share_count = 1;
                chain.get_share(hash).invoke([&](auto* obj) {
                    if (obj->m_desired_version < 36) return;
                    auto target = chain::bits_to_target(obj->m_bits);
                    auto att = chain::target_to_average_attempts(target);
                    delta.total_weight = att * 65535;
                    delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);
                    auto raw_script = get_share_script(obj);
                    if (raw_script.empty()) return;
                    // Normalize P2WPKH→P2PKH for merged chain compatibility.
                    // P2TR/P2WSH → empty → skipped (unconvertible).
                    auto script = normalize_script_for_merged(raw_script);
                    if (script.empty()) return;
                    delta.weights[script] = att * static_cast<uint32_t>(65535 - obj->m_donation);
                });
                return delta;
            },
            std::move(raw_prev_fn)
        );
        auto result = raw_sl.query(prev_share_hash, chain_len, unlimited_weight);
        auto weights = std::move(result.weights);
        auto total_weight = result.total_weight;
        auto donation_weight = result.total_donation_weight;

        if (weights.empty() || total_weight.IsNull())
            return uint256{};

        // Convert uint288 to decimal string, matching Python's '%d' formatting
        auto to_decimal = [](const uint288& val) -> std::string {
            if (val.IsNull()) return "0";
            uint288 tmp = val;
            std::string result;
            while (!tmp.IsNull()) {
                uint32_t rem = 0;
                for (int i = uint288::WIDTH - 1; i >= 0; --i) {
                    uint64_t cur = (static_cast<uint64_t>(rem) << 32) | tmp.pn[i];
                    tmp.pn[i] = static_cast<uint32_t>(cur / 10);
                    rem = static_cast<uint32_t>(cur % 10);
                }
                result.push_back('0' + static_cast<char>(rem));
            }
            std::reverse(result.begin(), result.end());
            return result;
        };

        // Convert script bytes to hex string for deterministic serialization.
        // V36 consensus: sort and serialize by script hex (not address string).
        // Matches p2pool's compute_merged_payout_hash() which uses script.encode('hex').
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

        // Deterministic serialization: sorted by script hex (V36 consensus)
        // Format: "script_hex1:weight1|script_hex2:weight2|...|T:total|D:donation"
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
        // Append total and donation
        payload += "|T:";
        payload += to_decimal(total_weight);
        payload += "|D:";
        payload += to_decimal(donation_weight);

        // SHA256d (hash256 in p2pool)
        auto span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
        auto hash_result = Hash(span);

        // Per-address merged PPLNS breakdown — log once per new chain height
        // for death valley comparison between p2pool and c2pool.
        {
            static int32_t s_last_log_height = -1;
            if (height != s_last_log_height) {
                s_last_log_height = height;
                LOG_INFO << "[MERGED-PPLNS] height=" << height
                         << " chain_len=" << chain_len
                         << " addrs=" << sorted_by_script.size()
                         << " total_w=" << to_decimal(total_weight)
                         << " don_w=" << to_decimal(donation_weight);
                for (const auto& [script_hex, w] : sorted_by_script) {
                    double pct = 0;
                    if (!total_weight.IsNull()) {
                        pct = (w * 10000 / total_weight).GetLow64() / 100.0;
                    }
                    LOG_INFO << "[MERGED-PPLNS]   " << script_hex.substr(0, 40)
                             << " w=" << to_decimal(w)
                             << " pct=" << std::fixed << std::setprecision(2) << pct << "%";
                }
                LOG_INFO << "[MERGED-PPLNS]   hash=" << hash_result.GetHex();

                // DOGE payout weights (chain_id=98, with Tier 1/1.5/2 resolution)
                // This is what actually determines DOGE coinbase outputs.
                // During death valley, compare address count and keys vs [MERGED-PPLNS].
                constexpr uint32_t DOGE_CHAIN_ID = 98;
                uint288 doge_unlimited;
                doge_unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                auto doge_result = get_merged_cumulative_weights(
                    prev_share_hash, chain_len, doge_unlimited, DOGE_CHAIN_ID);
                auto classify_doge = [](const std::vector<unsigned char>& s) -> const char* {
                    if (is_merged_key(s)) return "MERGED";
                    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9) return "P2PKH";
                    if (s.size() == 23 && s[0] == 0xa9) return "P2SH";
                    if (s.size() == 22 && s[0] == 0x00 && s[1] == 0x14) return "P2WPKH-RAW";
                    if (s.size() == 34 && s[0] == 0x00 && s[1] == 0x20) return "P2WSH-RAW";
                    if (s.size() == 34 && s[0] == 0x51 && s[1] == 0x20) return "P2TR-RAW";
                    return "OTHER";
                };
                auto doge_miner_w = doge_result.total_weight - doge_result.total_donation_weight;
                LOG_INFO << "[DOGE-PAYOUT] height=" << height
                         << " addrs=" << doge_result.weights.size()
                         << " total_w=" << to_decimal(doge_result.total_weight)
                         << " don_w=" << to_decimal(doge_result.total_donation_weight);
                for (const auto& [script, w] : doge_result.weights) {
                    double pct = 0;
                    if (!doge_miner_w.IsNull())
                        pct = (w * 10000 / doge_miner_w).GetLow64() / 100.0;
                    LOG_INFO << "[DOGE-PAYOUT]   " << classify_doge(script)
                             << " " << script_to_hex(script).substr(0, 50)
                             << " w=" << to_decimal(w)
                             << " pct=" << std::fixed << std::setprecision(2) << pct << "%";
                }
            }
        }

        return hash_result;
    }

    // -- Merged mining: per-chain expected payouts --
    // Given an aux chain's subsidy and chain_id, computes the expected payout
    // distribution using merged PPLNS weights.
    // Uses INTEGER arithmetic matching p2pool's build_canonical_merged_coinbase
    // exactly — no floating point anywhere.
    //
    // p2pool algorithm:
    //   grand_total = total_weight (already includes donation_weight)
    //   donation_amount = coinbase_value * donation_weight // grand_total
    //   miners_reward = coinbase_value - donation_amount
    //   accepted_total = sum of convertible miner weights (== total_weight - donation_weight here)
    //   per_miner = miners_reward * w // accepted_total
    //   rounding_remainder = miners_reward - sum(per_miner)
    //   final_donation = donation_amount + rounding_remainder
    std::map<std::vector<unsigned char>, uint64_t>
    get_merged_expected_payouts(const uint256& best_share_hash,
                                const uint256& block_target,
                                uint64_t subsidy,
                                uint32_t chain_id,
                                const std::vector<unsigned char>& donation_script,
                                const std::vector<unsigned char>& operator_ltc_script = {},
                                const std::vector<unsigned char>& operator_merged_script = {})
    {
        auto chain_len = std::min(chain.get_height(best_share_hash),
                                  static_cast<int32_t>(PoolConfig::real_chain_length()));
        // Unlimited desired_weight — exponential decay handles windowing.
        uint288 unlimited_weight;
        unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        auto [weights, total_weight, donation_weight] =
            get_merged_cumulative_weights(best_share_hash, chain_len, unlimited_weight, chain_id);

        std::map<std::vector<unsigned char>, uint64_t> result;

        if (total_weight.IsNull() || subsidy == 0)
            return result;

        // Integer division matching p2pool exactly (using uint288 throughout
        // to avoid uint64 truncation — total_weight routinely exceeds 2^64):
        // donation_amount = subsidy * donation_weight // total_weight
        uint288 subsidy288(subsidy);
        uint64_t donation_amount = 0;
        if (!donation_weight.IsNull()) {
            donation_amount = (subsidy288 * donation_weight / total_weight).GetLow64();
        }

        // finder_fee = 0 (CANONICAL_MERGED_FINDER_FEE_PER_MILLE = 0 in p2pool)
        uint64_t miners_reward = subsidy - donation_amount;

        // p2pool data.py:220-269: accepted_total_weight is the sum of ONLY
        // convertible weights (after filtering unconvertible P2WSH/P2TR).
        // NOT total_weight - donation_weight (which includes unconvertible).
        // First pass: resolve scripts and compute accepted_total
        struct ResolvedEntry {
            std::vector<unsigned char> script;
            uint288 weight;
        };
        std::vector<ResolvedEntry> resolved;
        uint288 accepted_total;
        for (const auto& [key, weight] : weights) {
            std::vector<unsigned char> script;
            if (!operator_ltc_script.empty() && !operator_merged_script.empty() && key == operator_ltc_script) {
                script = operator_merged_script;
            } else {
                script = resolve_merged_payout_script(key);
            }
            if (script.empty()) continue;  // Unconvertible (P2WSH, P2TR) — skip
            resolved.push_back({std::move(script), weight});
            accepted_total = accepted_total + weight;
        }

        // Second pass: distribute miners_reward proportionally (uint288 arithmetic)
        uint64_t total_distributed = 0;
        uint288 miners_reward288(miners_reward);
        for (const auto& entry : resolved) {
            uint64_t amount = !accepted_total.IsNull()
                ? (miners_reward288 * entry.weight / accepted_total).GetLow64()
                : 0;
            if (amount > 0) {
                result[entry.script] += amount;
                total_distributed += amount;
            }
        }

        // Rounding remainder → donation (integer division truncates)
        // Guard against uint64 underflow: total_distributed can exceed miners_reward
        // when per-miner rounding accumulates beyond the pool (rare with many miners).
        uint64_t remainder = (total_distributed <= miners_reward) ? (miners_reward - total_distributed) : 0;
        uint64_t final_donation = donation_amount + remainder;

        // V36 CONSENSUS RULE: Donation must be >= 1 satoshi
        if (final_donation < 1 && static_cast<int64_t>(subsidy) > 0 && !result.empty()) {
            // Deduct from largest miner (deterministic tiebreak by script)
            auto largest = std::max_element(result.begin(), result.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            if (largest != result.end()) {
                largest->second -= 1;
                final_donation += 1;
            }
        }

        result[donation_script] = (result.contains(donation_script) ? result[donation_script] : 0ULL)
                                  + static_cast<uint64_t>(final_donation);

        return result;
    }

    // Returns true if shares at `share_version` should be punished because
    // a newer version has reached the 95% activation threshold.
    // Python ref: share.check() version_after_check logic
    bool should_punish_version(const uint256& share_hash, int64_t share_version, int32_t lookbehind)
    {
        if (!chain.contains(share_hash))
            return false;
        auto counts = get_desired_version_counts(share_hash, lookbehind);
        auto height = chain.get_height(share_hash);
        auto actual = std::min(lookbehind, height);
        if (actual <= 0)
            return false;

        // Check if any version higher than share_version has >= 95% support
        for (auto& [ver, count] : counts)
        {
            if (static_cast<int64_t>(ver) > share_version)
            {
                if (count * 100 >= actual * 95) // 95% threshold
                    return true;
            }
        }
        return false;
    }

private:
    std::vector<stale_callback_t> m_stale_callbacks;

    // -- Skip list caches for O(log n) weight queries --
    std::optional<chain::WeightsSkipList> m_weights_skiplist;
    std::optional<chain::WeightsSkipList> m_v36_weights_skiplist;
    std::unordered_map<uint32_t, chain::WeightsSkipList> m_merged_skiplists;

    // -- Retroactive merged address lookup table --
    // Maps (chain_id) → (parent_script → explicit_merged_script).
    // Populated incrementally as V36 shares with explicit merged_addresses
    // are added.  Used as "Tier 1.5" in the merged skip list lambda:
    // when a V36 share has empty merged_addresses (activation-boundary race),
    // look up the same miner's explicit address from their other shares.
    std::unordered_map<uint32_t,
        std::map<std::vector<unsigned char>, std::vector<unsigned char>>> m_miner_merged_addr;

    // Register explicit merged addresses from a share into the lookup table.
    // If a NEW miner→address mapping is discovered, invalidates the merged
    // skip list for that chain_id so affected shares get recomputed.
    template <typename ShareT>
    void try_register_merged_addr(ShareT* share)
    {
        if constexpr (requires { share->m_merged_addresses; })
        {
            if (share->m_desired_version < 36) return;
            if (share->m_merged_addresses.empty()) return;
            auto parent_script = get_share_script(share);
            if (parent_script.empty()) return;
            for (const auto& entry : share->m_merged_addresses)
            {
                if (entry.m_script.m_data.empty()) continue;
                auto& lookup = m_miner_merged_addr[entry.m_chain_id];
                bool any_new = false;
                // Register under raw script (primary key)
                // p2pool v0.14.5: lookup[item.new_script] = script
                auto [it, inserted] = lookup.emplace(parent_script, entry.m_script.m_data);
                if (inserted) any_new = true;
                // Also register under normalized P2PKH form so
                // Tier 1.5 catches shares with different script encoding.
                // p2pool v0.14.5: lookup[normalized] = script
                auto normalized = normalize_script_for_merged(parent_script);
                if (!normalized.empty() && normalized != parent_script) {
                    auto [it2, ins2] = lookup.emplace(normalized, entry.m_script.m_data);
                    if (ins2) any_new = true;
                }
                if (any_new)
                {
                    // New mapping — stale skip list entries used auto-convert
                    // for this miner; recreate to use the explicit address.
                    m_merged_skiplists.erase(entry.m_chain_id);
                    auto to_hex_short = [](const std::vector<unsigned char>& s, size_t n = 20) {
                        static const char* H = "0123456789abcdef";
                        std::string r; for (size_t i = 0; i < std::min(s.size(), n); ++i) { r += H[s[i]>>4]; r += H[s[i]&0xf]; }
                        return r;
                    };
                    LOG_INFO << "[MERGED-REG] NEW chain_id=" << entry.m_chain_id
                             << " parent=" << to_hex_short(parent_script)
                             << " merged=" << to_hex_short(entry.m_script.m_data)
                             << " — skiplist invalidated";
                }
            }
        }
    }

    // Previous-share lambda for RAW chain (work templates, general PPLNS)
    auto make_previous_fn()
    {
        return [this](const uint256& hash) -> uint256 {
            if (!chain.contains(hash)) return uint256{};
            return chain.get_index(hash)->tail;
        };
    }

    // Previous-share lambda for VERIFIED chain (consensus hash computation).
    // Ensures compute_merged_payout_hash only walks shares that all peers
    // agree on — prevents c2pool's own unverified shares from polluting
    // the weight distribution and causing consensus divergence.
    auto make_verified_previous_fn()
    {
        return [this](const uint256& hash) -> uint256 {
            if (!verified.contains(hash)) return uint256{};
            return verified.get_index(hash)->tail;
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

    void ensure_v36_skiplist()
    {
        if (m_v36_weights_skiplist)
            return;
        m_v36_weights_skiplist.emplace(
            [this](const uint256& hash) -> chain::WeightsDelta {
                chain::WeightsDelta delta;
                if (!chain.contains(hash)) return delta;
                delta.share_count = 1;
                chain.get_share(hash).invoke([&](auto* obj) {
                    if (obj->m_desired_version < 36) return;
                    auto target = chain::bits_to_target(obj->m_bits);
                    auto att = chain::target_to_average_attempts(target);
                    auto raw_script = get_share_script(obj);
                    if (raw_script.empty()) return;
                    // Normalize P2WPKH→P2PKH for merged chain compatibility.
                    // P2TR/P2WSH → empty → skipped (unconvertible).
                    auto script = normalize_script_for_merged(raw_script);
                    if (script.empty()) return;
                    // Only set total_weight/donation for convertible scripts
                    // (matching p2pool: unconvertible → (1, {}, 0, 0))
                    delta.total_weight = att * 65535;
                    delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);
                    delta.weights[script] = att * static_cast<uint32_t>(65535 - obj->m_donation);
                });
                return delta;
            },
            make_previous_fn()
        );
    }

    chain::WeightsSkipList& ensure_merged_skiplist(uint32_t chain_id)
    {
        auto it = m_merged_skiplists.find(chain_id);
        if (it != m_merged_skiplists.end())
            return it->second;

        auto [new_it, _] = m_merged_skiplists.emplace(
            chain_id,
            chain::WeightsSkipList(
                [this, chain_id](const uint256& hash) -> chain::WeightsDelta {
                    chain::WeightsDelta delta;
                    if (!chain.contains(hash)) return delta;
                    delta.share_count = 1;
                    chain.get_share(hash).invoke([&](auto* obj) {
                        if (obj->m_desired_version < 36) return;
                        auto target = chain::bits_to_target(obj->m_bits);
                        auto att = chain::target_to_average_attempts(target);
                        // NOTE: total_weight and donation_weight are set AFTER
                        // convertibility check below.  p2pool returns (1, {}, 0, 0)
                        // for unconvertible scripts — zero total, zero donation.
                        // Setting them here would inflate the denominator.

                        std::vector<unsigned char> weight_key;
                        const char* tier_name = "raw:v35";
                        // p2pool gates Tier 1 + 1.5 on share.VERSION >= 36.
                        // V35-format shares always use raw parent script as key,
                        // even if desired_version >= 36.  This keeps V35 and V36
                        // weight entries separate per miner during the mixed window.
                        if constexpr (requires { obj->m_merged_addresses; })
                        {
                            tier_name = "T3:skip";
                            // Tier 1: explicit merged_addresses for this chain
                            for (const auto& entry : obj->m_merged_addresses)
                            {
                                if (entry.m_chain_id == chain_id)
                                {
                                    weight_key = make_merged_key(entry.m_script.m_data);
                                    tier_name = "T1:explicit";
                                    break;
                                }
                            }
                            // Tier 1.5: retroactive lookup — same miner's
                            // explicit merged address from their other shares.
                            // p2pool v0.14.5: try raw, then normalized P2PKH form.
                            if (weight_key.empty())
                            {
                                auto parent_script = get_share_script(obj);
                                auto table_it = m_miner_merged_addr.find(chain_id);
                                if (table_it != m_miner_merged_addr.end())
                                {
                                    auto miner_it = table_it->second.find(parent_script);
                                    if (miner_it == table_it->second.end()) {
                                        auto norm = normalize_script_for_merged(parent_script);
                                        if (!norm.empty() && norm != parent_script)
                                            miner_it = table_it->second.find(norm);
                                    }
                                    if (miner_it != table_it->second.end()) {
                                        weight_key = make_merged_key(miner_it->second);
                                        tier_name = "T1.5:retro";
                                    }
                                }
                                // Tier 2: normalize P2WPKH→P2PKH for merged
                                // chain compatibility. P2TR/P2WSH → empty → skipped.
                                if (weight_key.empty())
                                    weight_key = normalize_script_for_merged(parent_script);
                            }
                        }
                        else
                        {
                            // V35-format share: normalize P2WPKH→P2PKH for merged
                            // chain compatibility. P2TR/P2WSH → empty → skipped.
                            weight_key = normalize_script_for_merged(get_share_script(obj));
                        }
                        // Per-share tier diagnostic
                        // Log every T1/T1.5/MERGED hit and every 200th otherwise
                        {
                            static int s_tier_log_ctr = 0;
                            bool is_merged = is_merged_key(weight_key);
                            bool is_p2wpkh = !is_merged && weight_key.size() == 22 &&
                                             weight_key[0] == 0x00 && weight_key[1] == 0x14;
                            if (is_merged || is_p2wpkh || s_tier_log_ctr++ % 200 == 0) {
                                auto to_hex_short = [](const std::vector<unsigned char>& s, size_t n = 20) {
                                    static const char* H = "0123456789abcdef";
                                    std::string r; for (size_t i = 0; i < std::min(s.size(), n); ++i) { r += H[s[i]>>4]; r += H[s[i]&0xf]; }
                                    return r;
                                };
                                auto parent_script = get_share_script(obj);
                                LOG_INFO << "[DOGE-TIER] " << tier_name
                                         << " chain_id=" << chain_id
                                         << " ver=" << obj->version
                                         << " dv=" << obj->m_desired_version
                                         << " parent=" << to_hex_short(parent_script)
                                         << " key=" << to_hex_short(weight_key)
                                         << " bits=0x" << std::hex << obj->m_bits << std::dec;
                                // For V36 shares, log merged_addresses status
                                if constexpr (requires { obj->m_merged_addresses; }) {
                                    LOG_INFO << "[DOGE-TIER]   merged_addrs=" << obj->m_merged_addresses.size()
                                             << " ver=" << obj->version;
                                    for (const auto& entry : obj->m_merged_addresses) {
                                        LOG_INFO << "[DOGE-TIER]   chain_id=" << entry.m_chain_id
                                                 << " script_len=" << entry.m_script.m_data.size()
                                                 << " script=" << to_hex_short(entry.m_script.m_data);
                                    }
                                }
                            }
                        }
                        // Tier 3: unconvertible — skip, weight redistributed
                        // p2pool: return (1, {}, 0, 0) — share counts but zero weight
                        if (weight_key.empty()) return;
                        // Only set total_weight/donation for convertible scripts
                        // (matching p2pool MergedWeightsSkipList.get_delta)
                        delta.total_weight = att * 65535;
                        delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);
                        delta.weights[weight_key] = att * static_cast<uint32_t>(65535 - obj->m_donation);
                    });
                    return delta;
                },
                make_previous_fn()
            )
        );
        return new_it->second;
    }

    void invalidate_weight_caches(const uint256& hash)
    {
        if (m_weights_skiplist) m_weights_skiplist->forget(hash);
        if (m_v36_weights_skiplist) m_v36_weights_skiplist->forget(hash);
        for (auto& [_, sl] : m_merged_skiplists) sl.forget(hash);
        m_decayed_cache_valid = false; // chain changed — decayed cache stale
    }

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

} // namespace ltc
