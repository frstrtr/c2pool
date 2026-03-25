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
    uint288 work;
    int32_t reason{};
    int32_t is_local{};  // 1=local, 0=peer — peer wins tiebreak
    int64_t time_seen{};

    friend bool operator<(const HeadScore& a, const HeadScore& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        // p2pool: sort by (-reason, peer_addr is None, -time_seen)
        // is_local=0 (peer) sorts BEFORE is_local=1 (local) → peer wins
        return std::tie(a.reason, a.is_local, a.time_seen) > std::tie(b.reason, b.is_local, b.time_seen);
    }
};

struct TraditionalScore
{
    uint288 work;
    int64_t time_seen{};
    int32_t is_local{};
    int32_t reason{};

    friend bool operator<(const TraditionalScore& a, const TraditionalScore& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        return std::tie(a.time_seen, a.is_local, a.reason) > std::tie(b.time_seen, b.is_local, b.reason);
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

private:
    static int64_t now_seconds()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

public:
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
            chain.add(share);
    }

    void add(ShareType share)
    {
        auto h = share.hash();
        if (!chain.contains(h))
            chain.add(share);
    }

    // -- Attempt to verify a share --
    // Returns true if share is verified (already or newly).
    // P2: share.check() will be wired here; for now we accept shares
    // that have sufficient chain depth.
    bool attempt_verify(const uint256& share_hash)
    {
        if (verified.contains(share_hash))
            return true;

        // NO parent-in-verified filter. p2pool doesn't have one.
        // p2pool's attempt_verify has only the guard (height < CL+1 && unrooted).
        // Fragmentation doesn't affect scoring because scoring uses
        // chain.get_work() (SubsetTracker pattern), not verified.get_work().

        // p2pool: height, last = self.get_height_and_last(share.hash)
        // p2pool's get_height uses get_delta_to_last() which walks through
        // SubsetTracker's cached deltas — equivalent to our acc cache.
        // Using acc cache height (not O(n) walk) matches p2pool's pattern
        // and gives correct height after pruning.
        auto acc_height = chain.get_acc_height(share_hash);
        auto last = chain.get_last(share_hash);

        // p2pool: if height < self.net.CHAIN_LENGTH + 1 and last is not None:
        //             raise AssertionError()
        if (acc_height < static_cast<int32_t>(PoolConfig::chain_length()) + 1 && !last.IsNull())
        {
            // Debug: why is the chain unrooted?
            static int unrooted_log = 0;
            if (unrooted_log++ < 10) {
                bool last_in_chain = chain.contains(last);
                LOG_WARNING << "[UNROOTED] share=" << share_hash.GetHex().substr(0,16)
                            << " acc_height=" << acc_height << " last=" << last.GetHex().substr(0,16)
                            << " last_in_chain=" << last_in_chain
                            << " chain_size=" << chain.size();
            }
            // Check if parent is already verified — if so, we can verify this share
            uint256 prev_hash;
            chain.get_share(share_hash).invoke([&](auto* obj) {
                prev_hash = obj->m_prev_hash;
            });
            if (prev_hash.IsNull() || !verified.contains(prev_hash))
                return false;
            // Parent is verified — proceed with verification
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
            LOG_WARNING << "attempt_verify FAILED for " << share_hash.ToString().substr(0,16)
                        << " acc_height=" << acc_height << " last=" << (last.IsNull() ? "null" : last.ToString().substr(0,16))
                        << " error: " << e.what();
            return false;
        }

        // Add to verified chain
        auto& share_var = chain.get_share(share_hash);
        if (!verified.contains(share_hash))
            verified.add(share_var);

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
    // May throw if the chain is concurrently modified (think runs on a
    // background thread).  Callers should catch or use the safe wrapper.
    TailScore score(const uint256& share_hash,
                    const std::function<int32_t(uint256)>& block_rel_height_func)
    {
        uint288 score_res;

        // Use CHAIN for navigation (p2pool SubsetTracker pattern).
        // verified is only for membership checks, not navigation.
        auto head_height = chain.get_height(share_hash);
        if (head_height < static_cast<int32_t>(PoolConfig::chain_length()))
            return {head_height, score_res};

        auto end_point = chain.get_nth_parent_key(share_hash,
            (PoolConfig::chain_length() * 15) / 16);

        // Find max block_rel_height in the tail 1/16 of the chain
        std::optional<int32_t> block_height;
        auto tail_count = std::min(
            static_cast<int32_t>(PoolConfig::chain_length() / 16),
            chain.get_height(end_point));
        if (tail_count <= 0)
            return {static_cast<int32_t>(PoolConfig::chain_length()), score_res};

        auto tail_view = chain.get_chain(end_point, tail_count);
        for (auto [hash, data] : tail_view)
        {
            // Access the share's min_header.previous_block via the variant
            uint256 prev_block;
            data.share.invoke([&](auto* obj) {
                prev_block = obj->m_min_header.m_previous_block;
            });

            auto bh = block_rel_height_func(prev_block);
            if (!block_height.has_value() || bh > block_height.value())
                block_height = bh;
        }

        if (!block_height.has_value() || block_height.value() >= 0)
            return {static_cast<int32_t>(PoolConfig::chain_length()), score_res};

        // Compute work using CHAIN (raw tracker), not verified.
        uint288 total_work;
        auto c_dist = chain.get_height(share_hash) - chain.get_height(end_point);
        if (c_dist > 0) {
            try {
                auto view = chain.get_chain(share_hash, c_dist);
                for (auto [hash, data] : view) {
                    if (hash == end_point) break;
                    data.share.invoke([&](auto* obj) {
                        total_work += chain::target_to_average_attempts(
                            chain::bits_to_target(obj->m_bits));
                    });
                }
            } catch (...) {}
        }

        auto time_span = (-block_height.value() + 1) * 150; // LTC BLOCK_PERIOD = 150s
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

        // Phase 1.5: Forward-extend verification using reverse map.
        // After Phase 1 verified some shares, try to verify their CHILDREN
        // that are in chain but not yet verified. This propagates verification
        // forward through unrooted peer chains in a single think() cycle.
        // p2pool doesn't need this because Phase 2 handles it (rooted chains).
        {
            bool extended = true;
            int fwd_count = 0;
            // Start from verified shares that have unverified children in raw chain.
            // Check ALL verified shares (not just heads) — children may have
            // arrived after the parent was verified but before it became a head.
            std::vector<uint256> to_check;
            for (auto& [vh, vt] : verified.get_heads())
                to_check.push_back(vh);
            // Also scan raw chain's reverse map for verified parents with unverified children
            for (auto& [parent, children] : chain.get_reverse()) {
                if (!verified.contains(parent)) continue;
                for (const auto& child : children) {
                    if (!verified.contains(child) && chain.contains(child))
                        to_check.push_back(parent);
                }
            }

            while (!to_check.empty() && fwd_count < 10000) {
                auto parent = to_check.back();
                to_check.pop_back();
                auto rev_it = chain.get_reverse().find(parent);
                if (rev_it == chain.get_reverse().end()) {
                    static int no_children = 0;
                    if (no_children++ < 5)
                        LOG_INFO << "[P1.5] no children for " << parent.GetHex().substr(0,16);
                    continue;
                }
                for (const auto& child : rev_it->second) {
                    if (verified.contains(child)) continue;
                    if (!chain.contains(child)) continue;
                    auto [ch, cl] = chain.get_height_and_last(child);
                    static int child_log = 0;
                    if (child_log++ < 10)
                        LOG_INFO << "[P1.5] trying child " << child.GetHex().substr(0,16)
                                 << " height=" << ch << " last=" << (cl.IsNull() ? "null" : cl.GetHex().substr(0,16));
                    if (attempt_verify(child)) {
                        ++fwd_count;
                        to_check.push_back(child);
                    }
                }
            }
            if (fwd_count > 0) {
                static int fwd_log = 0;
                if (fwd_log++ < 10 || fwd_count > 10)
                    LOG_INFO << "[think-P1.5] forward-extended " << fwd_count << " shares";
            }
        }

        // Remove bad shares (p2pool data.py:2133-2145).
        // p2pool removes ONLY the bad shares themselves — NO cascade.
        // clean_tracker() handles stale heads later (300s age check).
        // The previous cascade removal was catastrophically wrong:
        // it followed reverse map which includes MAIN CHAIN children,
        // destroying the entire chain above the fork point.
        {
            std::vector<uint256> to_remove;
            for (const auto& bad : bads)
            {
                if (verified.contains(bad))
                    continue;
                // Only remove LEAF shares (no children in the chain).
                // Removing a share with children breaks their prev_hash
                // chain → cascading GENTX failures. p2pool avoids this
                // because GENTX rarely fails between p2pool nodes.
                auto& rev = chain.get_reverse();
                auto rit = rev.find(bad);
                if (rit != rev.end() && !rit->second.empty())
                    continue; // has children — don't remove
                to_remove.push_back(bad);
            }
            for (const auto& bad : to_remove)
            {
                if (!chain.contains(bad)) continue;

                NetService bad_peer;
                try {
                    chain.get_share(bad).invoke([&](auto* obj) {
                        bad_peer = obj->peer_addr;
                    });
                } catch (...) {}
                if (bad_peer.port() != 0)
                    bad_peer_addresses.insert(bad_peer);

                try {
                    invalidate_weight_caches(bad);
                    if (verified.contains(bad))
                        verified.remove(bad);
                    chain.remove(bad);
                } catch (...) {}
            }
            if (!to_remove.empty()) {
                LOG_INFO << "[think-P1] removed " << to_remove.size()
                         << " shares (bads=" << bads.size() << " + descendants)";
            }
        }

        // Phase 2: Extend verification from verified heads.
        // Matches p2pool: verify ALL shares in one pass (no budget limit).
        // p2pool does this in a single think() call — any artificial budget
        // causes c2pool to fall behind the growing chain, creating forks.
        {
            static int p2_skip_log = 0;
            if (p2_skip_log++ % 20 == 0)
                LOG_INFO << "[think-P2-iter] verified_heads=" << verified.get_heads().size()
                         << " chain=" << chain.size() << " verified=" << verified.size();
        }
        for (auto& [head_hash, tail_hash] : verified.get_heads())
        {
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
                for (auto [hash, data] : chain_view)
                {
                    if (!attempt_verify(hash))
                        break;
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

                    // p2pool: sort key = (work - punish*att, -reason, -time_seen)
                    // p2pool has commented-out: self.items[h].peer_addr is None
                    // which deprioritizes local shares. c2pool enables this to break
                    // the local fork feedback loop (local→best→local→best cycle).
                    bool is_local = false;
                    chain.get_share(hh).invoke([&](auto* obj) {
                        is_local = (obj->peer_addr.port() == 0);
                    });
                    // is_local=true sorts AFTER is_local=false (peer wins tiebreak)
                    decorated_heads.push_back({{work_score, reason, is_local ? 1 : 0, -ts}, hh});
                    traditional_sort.push_back({{work_score, -ts, is_local ? 1 : 0, reason}, hh});
                } catch (const std::exception&) {
                    // Chain concurrently modified — skip this head, retry next cycle
                }
            }
            std::sort(decorated_heads.begin(), decorated_heads.end());
            std::sort(traditional_sort.begin(), traditional_sort.end());
        }

        // p2pool: self.punish = punish value from Phase 5 (walk-back result)
        bool punish_aggressively = !traditional_sort.empty() && traditional_sort.back().score.reason != 0;

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
    /// Uses skip list (O(log n)) + TrackerView delta cache (O(1)).
    /// p2pool: tracker.get_delta(near.hash, far.hash).work / time
    uint288 get_pool_attempts_per_second(const uint256& share_hash, int32_t dist, bool use_min_work = false)
    {
        if (dist < 2 || !chain.contains(share_hash))
            return uint288(0);

        auto actual_height = chain.get_acc_height(share_hash);
        if (actual_height < dist)
            return uint288(0);

        // p2pool: far = tracker.get_nth_parent_hash(prev, dist - 1) — O(log n)
        LOG_TRACE << "[APS] get_nth_parent_via_skip(dist=" << (dist-1) << ")...";
        auto far_hash = chain.get_nth_parent_via_skip(share_hash, dist - 1);
        LOG_TRACE << "[APS] skip done, far=" << far_hash.GetHex().substr(0,16);
        if (far_hash.IsNull() || !chain.contains(far_hash))
            return uint288(0);

        // p2pool: attempts = tracker.get_delta(near.hash, far.hash).work
        // p2pool uses get_delta which calls get_delta_to_last for BOTH shares.
        // Both walks reach the same chain end → subtraction is valid.
        // get_delta_to_last ALWAYS walks the actual chain (no stale cache) because
        // _get_delta combines cached delta with ref delta, and refs are updated
        // by handle_remove_special on pruning.
        auto delta = chain.get_delta(share_hash, far_hash);
        uint288 attempts = use_min_work ? delta.min_work : delta.work;

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
            uint256 bits_lo = pre_target3 / 30;
            if (bits_lo.IsNull()) bits_lo = uint256(1);
            uint256 bits_target = desired_target;
            if (bits_target < bits_lo) bits_target = bits_lo;
            if (bits_target > pre_target3) bits_target = pre_target3;
            auto bits = chain::target_to_bits_upper_bound(bits_target);
            return {max_bits, bits};
        }

        // Use accumulated height from skip list cache — O(1) and correct
        // even after pruning (get_height walks until chain end, stops at
        // pruned tail → returns short value → triggers MAX_TARGET fallback).
        auto acc_height = chain.get_acc_height(prev_share_hash);

        // Not enough chain depth for proper difficulty calculation.
        if (acc_height < static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND))
        {
            auto pre_target3 = MAX_TARGET;
            auto max_bits = chain::target_to_bits_upper_bound(pre_target3);
            // bits = clip(desired_target, [pre_target3/30, pre_target3])
            uint256 bits_lo = pre_target3 / 30;
            if (bits_lo.IsNull()) bits_lo = uint256(1);
            uint256 bits_target = desired_target;
            if (bits_target < bits_lo) bits_target = bits_lo;
            if (bits_target > pre_target3) bits_target = pre_target3;
            auto bits = chain::target_to_bits_upper_bound(bits_target);
            return {max_bits, bits};
        }

        // Step 1: Derive target from pool hashrate.
        // Use prev_share_hash directly — all shares counted equally.
        // p2pool's algorithm: aps from the entire chain, no filtering.
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

        {
            static int cst_log = 0;
            if (cst_log++ % 20 == 0) {
                // Check if the walk went through local shares
                bool is_local = false;
                chain.get_share(prev_share_hash).invoke([&](auto* obj) {
                    is_local = (obj->peer_addr.port() == 0);
                });
                LOG_INFO << "[CST] aps=" << aps.GetLow64()
                         << " period=" << PoolConfig::share_period()
                         << " height=" << acc_height
                         << " prev=" << prev_share_hash.GetHex().substr(0,16)
                         << " prev_is_local=" << is_local;
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

    // -- PPLNS cumulative weights computation --
    CumulativeWeights get_cumulative_weights(const uint256& start, int32_t max_shares, const uint288& desired_weight)
    {
        if (start.IsNull())
            return {};

        auto [start_height, last] = chain.get_height_and_last(start);

        // Clamp chain to max_shares
        uint256 end_hash = last;
        if (start_height > max_shares)
            end_hash = chain.get_nth_parent_key(start, max_shares);

        // Walk shares individually via prev_hash (hash-dict navigation).
        // This works across new_fork segment boundaries — unlike
        // get_interval() which subtracts accumulated values that are
        // wrong for fork shares.  O(max_shares) but max_shares ≤
        // CHAIN_LENGTH (800), each step is O(1) hash lookup.
        {
            CumulativeWeights result;
            uint256 cur = start;
            for (int32_t i = 0; i < max_shares && !cur.IsNull() && chain.contains(cur); ++i) {
                auto& share_data = chain.get_share(cur);
                uint256 next_cur;
                share_data.invoke([&](auto* obj) {
                    auto att = chain::target_to_average_attempts(
                        chain::bits_to_target(obj->m_bits));
                    uint32_t don = obj->m_donation;

                    std::vector<unsigned char> script;
                    if constexpr (requires { obj->m_pubkey_hash; }) {
                        script = {0x76, 0xa9, 0x14};
                        auto* hash_bytes = obj->m_pubkey_hash.data();
                        script.insert(script.end(), hash_bytes, hash_bytes + 20);
                        script.push_back(0x88);
                        script.push_back(0xac);
                    } else if constexpr (requires { obj->m_address; }) {
                        script = obj->m_address.m_data;
                    }

                    auto share_total = att * 65535;
                    auto share_addr_w = att * static_cast<uint32_t>(65535 - don);
                    auto share_don_w = att * don;

                    // Partial last share if we'd exceed desired_weight
                    if (result.total_weight + share_total > desired_weight) {
                        auto remaining = desired_weight - result.total_weight;
                        if (!share_total.IsNull()) {
                            share_addr_w = remaining / 65535 * share_addr_w / (share_total / 65535);
                            share_don_w = remaining / 65535 * share_don_w / (share_total / 65535);
                        }
                        share_total = remaining;
                    }

                    result.weights[script] = result.weights[script] + share_addr_w;
                    result.total_weight = result.total_weight + share_total;
                    result.total_donation_weight = result.total_donation_weight + share_don_w;
                    next_cur = obj->m_prev_hash;
                });
                cur = next_cur;
                if (result.total_weight >= desired_weight)
                    break;
            }
            return result;
        }
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

        // Walk the chain directly (matches p2pool's while loop in
        // get_decayed_cumulative_weights). Do NOT use TrackerView's cached
        // get_height() — it can become stale in multi-threaded context when
        // clean_tracker() removes shares concurrently.
        // Collect share hashes for the walk, then iterate.
        std::vector<uint256> walk_hashes;
        walk_hashes.reserve(std::min(max_shares, int32_t(500)));
        {
            auto cur = start;
            while (!cur.IsNull() && chain.contains(cur)
                   && static_cast<int32_t>(walk_hashes.size()) < max_shares) {
                walk_hashes.push_back(cur);
                auto* idx = chain.get_index(cur);
                cur = idx ? idx->tail : uint256();
            }
        }
        auto walk_count = static_cast<int32_t>(walk_hashes.size());

        LOG_INFO << "[PPLNS-WALK] start=" << start.GetHex().substr(0, 16)
                 << " max_shares=" << max_shares
                 << " walk_count=" << walk_count
                 << " half_life=" << half_life
                 << " decay_per=" << decay_per;

        static int decay_dump = 0;
        bool do_dump = (decay_dump++ < 2);

        for (const auto& hash : walk_hashes)
        {
            if (!chain.contains(hash)) break; // safety: share removed during walk
            chain.get_share(hash).invoke([&](auto* obj) {
                auto att = chain::target_to_average_attempts(
                    chain::bits_to_target(obj->m_bits));
                uint32_t don = obj->m_donation;

                // Apply exponential decay: decayed_att = att * decay_fp >> PRECISION
                uint288 decayed_att = (att * uint288(decay_fp)) >> DECAY_PRECISION;

                if (do_dump && share_count < 5) {
                    LOG_INFO << "[DECAY-WALK] #" << share_count
                             << " bits=0x" << std::hex << obj->m_bits << std::dec
                             << " att=" << att.GetLow64()
                             << " decay_fp=" << decay_fp
                             << " decayed_att=" << decayed_att.GetLow64()
                             << " don=" << don
                             << " hash=" << hash.GetHex().substr(0, 16);
                }

                auto addr_w = decayed_att * static_cast<uint32_t>(65535 - don);
                auto don_w  = decayed_att * don;
                auto this_total = addr_w + don_w; // = decayed_att * 65535

                // Cap at desired_weight (partial last share)
                if (result.total_weight + this_total > desired_weight) {
                    auto remaining = desired_weight - result.total_weight;
                    if (!this_total.IsNull()) {
                        addr_w = addr_w * remaining / this_total;
                        don_w  = don_w * remaining / this_total;
                    }
                    this_total = remaining;
                }

                // Use pointer to existing script data — avoid allocation.
                // get_share_script returns by value, but for V36 shares with
                // m_address, the data is already in the share object.
                auto script = get_share_script(obj);

                result.weights[script] += addr_w;
                result.total_weight += this_total;
                result.total_donation_weight += don_w;
            });

            ++share_count;
            if (result.total_weight >= desired_weight)
                break;

            // Decay for next (older) share.
            // 128-bit multiply avoids overflow: decay_fp × decay_per ≈ 2^80.
            decay_fp = static_cast<uint64_t>(
                (static_cast<__uint128_t>(decay_fp) * decay_per) >> DECAY_PRECISION);
        }

        if (do_dump) {
            LOG_INFO << "[DECAY-WALK] TOTAL: shares=" << share_count
                     << " addrs=" << result.weights.size()
                     << " total_w=" << result.total_weight.GetLow64()
                     << " don_w=" << result.total_donation_weight.GetLow64()
                     << " start=" << start.GetHex().substr(0, 16)
                     << " max_shares=" << max_shares;
            for (auto& [script, w] : result.weights) {
                auto script_hex = std::string();
                for (auto b : script) {
                    static const char* H = "0123456789abcdef";
                    script_hex += H[b >> 4]; script_hex += H[b & 0xf];
                }
                LOG_INFO << "[DECAY-WALK]   " << script_hex.substr(0, 40)
                         << " weight=" << w.GetLow64();
            }
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
                    delta.weights[raw_script] = att * static_cast<uint32_t>(65535 - obj->m_donation);
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

        // Log payload periodically (every 15s)
        {
            static auto last_log = std::chrono::steady_clock::now() - std::chrono::seconds(30);
            auto now = std::chrono::steady_clock::now();
            if (now - last_log > std::chrono::seconds(15)) {
                last_log = now;
                LOG_INFO << "[merged_payout_hash] chain_len=" << chain_len
                         << " raw_height=" << height
                         << " weights=" << sorted_by_script.size()
                         << " total_weight=" << to_decimal(total_weight)
                         << " payload(" << payload.size() << ")=" << payload.substr(0, 200);
            }
        }

        // SHA256d (hash256 in p2pool)
        auto span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
        return Hash(span);
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
                                const std::vector<unsigned char>& donation_script)
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

        // Integer division matching p2pool exactly:
        // grand_total = total_weight (includes donation_weight)
        // donation_amount = subsidy * donation_weight // grand_total
        uint64_t grand_total_lo = total_weight.GetLow64();
        uint64_t donation_w_lo = donation_weight.GetLow64();

        // For large weights, use double only for the ratio, then truncate
        // This matches Python's integer // on arbitrary-precision ints
        uint64_t donation_amount = 0;
        if (!donation_weight.IsNull()) {
            // donation_amount = subsidy * donation_weight // grand_total
            // Use 128-bit arithmetic to avoid overflow
            __uint128_t num = static_cast<__uint128_t>(subsidy) * donation_w_lo;
            donation_amount = static_cast<uint64_t>(num / grand_total_lo);
        }

        // finder_fee = 0 (CANONICAL_MERGED_FINDER_FEE_PER_MILLE = 0 in p2pool)
        uint64_t miners_reward = subsidy - donation_amount;

        // accepted_total = total_weight - donation_weight (all miner weights)
        uint64_t accepted_total = grand_total_lo - donation_w_lo;

        uint64_t total_distributed = 0;
        for (const auto& [script, weight] : weights) {
            uint64_t w = weight.GetLow64();
            // amount = miners_reward * w // accepted_total
            __uint128_t num = static_cast<__uint128_t>(miners_reward) * w;
            uint64_t amount = (accepted_total > 0) ?
                static_cast<uint64_t>(num / accepted_total) : 0;
            if (amount > 0) {
                result[script] = amount;
                total_distributed += amount;
            }
        }

        // Rounding remainder → donation (integer division truncates)
        uint64_t rounding_remainder = miners_reward - total_distributed;
        uint64_t final_donation = donation_amount + rounding_remainder;

        // V36 CONSENSUS RULE: Donation must be >= 1 satoshi
        if (final_donation < 1 && subsidy > 0 && !result.empty()) {
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
                                  + final_donation;

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
                    delta.total_weight = att * 65535;
                    delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);
                    // Use the ORIGINAL script (not normalized) so that
                    // compute_merged_payout_hash produces the correct address
                    // encoding (bech32 for P2WPKH, base58 for P2PKH/P2SH) —
                    // matching Python p2pool's share.address key format.
                    auto raw_script = get_share_script(obj);
                    if (raw_script.empty()) return;
                    delta.weights[raw_script] = att * static_cast<uint32_t>(65535 - obj->m_donation);
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
                        delta.total_weight = att * 65535;
                        delta.total_donation_weight = att * static_cast<uint32_t>(obj->m_donation);

                        std::vector<unsigned char> weight_key;
                        // Tier 1: explicit merged_addresses for this chain
                        if constexpr (requires { obj->m_merged_addresses; })
                        {
                            for (const auto& entry : obj->m_merged_addresses)
                            {
                                if (entry.m_chain_id == chain_id)
                                {
                                    weight_key = entry.m_script.m_data;
                                    break;
                                }
                            }
                        }
                        // Tier 2: auto-convert parent script (P2WPKH→P2PKH etc.)
                        if (weight_key.empty())
                        {
                            auto raw = get_share_script(obj);
                            weight_key = normalize_script_for_merged(raw);
                        }
                        // Tier 3: unconvertible — skip, weight redistributed
                        if (weight_key.empty()) return;
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
