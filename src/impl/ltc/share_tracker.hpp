#pragma once

#include "share.hpp"
#include "config_pool.hpp"

#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <set>
#include <vector>

namespace ltc
{

// --- Scoring types ---

struct TailScore
{
    int32_t chain_len{};
    uint288 hashrate;

    friend bool operator<(const TailScore& a, const TailScore& b)
    {
        return std::tie(a.chain_len, a.hashrate) < std::tie(b.chain_len, b.hashrate);
    }
};

struct HeadScore
{
    uint288 work;
    int32_t reason{};
    int64_t time_seen{};

    friend bool operator<(const HeadScore& a, const HeadScore& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        // Higher reason and higher time_seen sort LOWER (punished shares rank below)
        return std::tie(a.reason, a.time_seen) > std::tie(b.reason, b.time_seen);
    }
};

struct TraditionalScore
{
    uint288 work;
    int64_t time_seen{};
    int32_t reason{};

    friend bool operator<(const TraditionalScore& a, const TraditionalScore& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        return std::tie(a.time_seen, a.reason) > std::tie(b.time_seen, b.reason);
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
    ShareTracker() = default;

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

        auto [height, last] = chain.get_height_and_last(share_hash);

        // Need CHAIN_LENGTH + 1 depth, or the chain must be rooted (last == null)
        if (height < static_cast<int32_t>(PoolConfig::CHAIN_LENGTH) + 1 && !last.IsNull())
            return false;

        // TODO (P2): call share.check() here for full PoW + coinbase verification
        // For now, accept the share as verified

        // Add to verified chain
        auto& share_var = chain.get_share(share_hash);
        if (!verified.contains(share_hash))
            verified.add(share_var);

        return true;
    }

    // -- Score a chain from share_hash to CHAIN_LENGTH*15/16 ancestor --
    // Returns (chain_len, hashrate_score) — higher is better
    TailScore score(const uint256& share_hash,
                    const std::function<int32_t(uint256)>& block_rel_height_func)
    {
        uint288 score_res;

        auto head_height = verified.get_height(share_hash);
        if (head_height < static_cast<int32_t>(PoolConfig::CHAIN_LENGTH))
            return {head_height, score_res};

        auto end_point = verified.get_nth_parent_key(share_hash,
            (PoolConfig::CHAIN_LENGTH * 15) / 16);

        // Find max block_rel_height in the tail 1/16 of the chain
        std::optional<int32_t> block_height;
        auto tail_count = std::min(
            static_cast<int32_t>(PoolConfig::CHAIN_LENGTH / 16),
            verified.get_height(end_point));
        if (tail_count <= 0)
            return {static_cast<int32_t>(PoolConfig::CHAIN_LENGTH), score_res};

        auto tail_view = verified.get_chain(end_point, tail_count);
        for (auto& [hash, data] : tail_view)
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
            return {static_cast<int32_t>(PoolConfig::CHAIN_LENGTH), score_res};

        // Get accumulated work between share_hash and end_point on the verified chain
        auto interval = verified.get_interval(share_hash, end_point);
        auto time_span = (-block_height.value() + 1) * 150; // LTC BLOCK_PERIOD = 150s
        if (time_span <= 0)
            time_span = 1;

        score_res = interval.work / static_cast<uint32_t>(time_span);
        return {static_cast<int32_t>(PoolConfig::CHAIN_LENGTH), score_res};
    }

    // -- Best-chain selection with verification and punishment --
    TrackerThinkResult think(const std::function<int32_t(uint256)>& block_rel_height_func,
                             const uint256& previous_block,
                             uint32_t bits)
    {
        std::vector<std::pair<NetService, uint256>> desired;
        std::set<NetService> bad_peer_addresses;

        // Phase 1: Try to verify unverified heads
        std::vector<uint256> bads;
        for (auto& [head_hash, tail_hash] : chain.get_heads())
        {
            // Skip heads that are already verified heads
            if (verified.get_heads().contains(head_hash))
                continue;

            auto [head_height, last] = chain.get_height_and_last(head_hash);
            auto walk_count = last.IsNull()
                ? head_height
                : std::min(5, std::max(0, head_height - static_cast<int32_t>(PoolConfig::CHAIN_LENGTH)));

            if (walk_count <= 0)
                continue;

            bool any_verified = false;
            auto chain_view = chain.get_chain(head_hash, walk_count);
            for (auto& [hash, data] : chain_view)
            {
                if (attempt_verify(hash))
                {
                    any_verified = true;
                    break;
                }
                bads.push_back(hash);
            }

            // If we couldn't verify anything and chain isn't rooted, request more shares
            if (!any_verified && !last.IsNull())
            {
                uint32_t desired_timestamp = 0;
                uint32_t desired_bits = 0;
                NetService peer;

                // Get info from the head share
                chain.get_share(head_hash).invoke([&](auto* obj) {
                    desired_timestamp = obj->m_timestamp;
                    desired_bits = obj->m_bits;
                    peer = obj->peer_addr;
                });

                desired.emplace_back(peer, last);
            }
        }

        // Remove bad shares and collect bad peers
        for (const auto& bad : bads)
        {
            if (verified.contains(bad))
                continue; // safety check

            NetService bad_peer;
            chain.get_share(bad).invoke([&](auto* obj) {
                bad_peer = obj->peer_addr;
            });
            bad_peer_addresses.insert(bad_peer);

            // TODO (P5): chain.remove(bad) — remove() not yet implemented
        }

        // Phase 2: Extend verification from verified heads
        for (auto& [head_hash, tail_hash] : verified.get_heads())
        {
            auto [head_height, last_hash] = verified.get_height_and_last(head_hash);
            auto [last_height, last_last_hash] = chain.get_height_and_last(last_hash);

            auto want = std::max(static_cast<int32_t>(PoolConfig::CHAIN_LENGTH) - head_height, 0);
            auto can = last_last_hash.IsNull()
                ? last_height
                : std::max(last_height - 1 - static_cast<int32_t>(PoolConfig::CHAIN_LENGTH), 0);
            auto to_get = std::min(want, can);

            if (to_get > 0)
            {
                auto chain_view = chain.get_chain(last_hash, to_get);
                for (auto& [hash, data] : chain_view)
                {
                    if (!attempt_verify(hash))
                        break;
                }
            }

            // Request more shares if verified chain is short
            if (head_height < static_cast<int32_t>(PoolConfig::CHAIN_LENGTH) && !last_last_hash.IsNull())
            {
                NetService peer;
                chain.get_share(head_hash).invoke([&](auto* obj) {
                    peer = obj->peer_addr;
                });
                desired.emplace_back(peer, last_last_hash);
            }
        }

        // Phase 3: Score tails — pick the best tail
        std::vector<DecoratedData<TailScore>> decorated_tails;
        for (auto& [tail_hash, head_hashes] : verified.get_tails())
        {
            // Find the head with the most accumulated work
            uint256 best_head;
            uint288 best_work;
            bool first = true;
            for (const auto& hh : head_hashes)
            {
                auto idx = verified.get_index(hh);
                if (first || idx->work > best_work)
                {
                    best_work = idx->work;
                    best_head = hh;
                    first = false;
                }
            }

            if (!best_head.IsNull())
            {
                auto s = score(best_head, block_rel_height_func);
                decorated_tails.push_back({s, tail_hash});
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

        // Phase 4: Score heads within the best tail — pick the best head
        std::vector<DecoratedData<HeadScore>> decorated_heads;
        std::vector<DecoratedData<TraditionalScore>> traditional_sort;

        if (verified.get_tails().contains(best_tail))
        {
            const auto& head_hashes = verified.get_tails().at(best_tail);
            for (const auto& hh : head_hashes)
            {
                auto v_height = verified.get_height(hh);
                auto recent_ancestor = verified.get_nth_parent_key(hh, std::min(5, v_height));
                uint288 work_score = verified.get_index(recent_ancestor)->work;

                auto* head_idx = chain.get_index(hh);
                int64_t ts = head_idx->time_seen;

                // No punishment for now (P2 will add should_punish_reason)
                int32_t reason = 0;

                decorated_heads.push_back({{work_score, reason, ts}, hh});
                traditional_sort.push_back({{work_score, ts, reason}, hh});
            }
            std::sort(decorated_heads.begin(), decorated_heads.end());
            std::sort(traditional_sort.begin(), traditional_sort.end());
        }

        bool punish_aggressively = !traditional_sort.empty() && traditional_sort.back().score.reason != 0;

        // Phase 5: Determine best share
        uint256 best;
        if (!decorated_heads.empty())
            best = decorated_heads.back().hash;

        // Phase 6: Compute cutoffs for desired shares filtering
        uint32_t timestamp_cutoff;
        if (!best.IsNull())
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

        return {best, desired_result, bad_peer_addresses, punish_aggressively};
    }

    // -- Pool hashrate estimation --
    uint288 get_pool_attempts_per_second(const uint256& share_hash, int32_t dist, bool use_min_work = false)
    {
        if (dist < 2)
            return uint288(0);

        auto far_hash = chain.get_nth_parent_key(share_hash, dist - 1);
        auto interval = chain.get_interval(share_hash, far_hash);

        // Get timestamps
        uint32_t near_ts = 0, far_ts = 0;
        chain.get_share(share_hash).invoke([&](auto* obj) { near_ts = obj->m_timestamp; });
        chain.get_share(far_hash).invoke([&](auto* obj) { far_ts = obj->m_timestamp; });

        auto time = static_cast<int32_t>(near_ts) - static_cast<int32_t>(far_ts);
        if (time <= 0)
            time = 1;

        return (use_min_work ? interval.min_work : interval.work) / static_cast<uint32_t>(time);
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

        // Get the full interval from start to end
        auto interval = chain.get_interval(start, end_hash);

        // If total weight is within desired, return the full interval's weights
        if (interval.total_weight <= desired_weight)
        {
            return {
                interval.weight_amounts,
                interval.total_weight,
                interval.total_donation_weight
            };
        }

        // Walk the chain to find the cutoff point where total_weight >= desired_weight
        // This is the slow path; walks share-by-share from start toward end
        std::map<std::vector<unsigned char>, uint288> weights;
        uint288 accum_total;
        uint288 accum_donation;

        auto walk_count = std::min(start_height, max_shares);
        auto walk_view = chain.get_chain(start, walk_count);
        for (auto& [hash, data] : walk_view)
        {
            if (hash == end_hash)
                break;

            auto* idx = data.index;
            // Per-share values: from this single share's contribution
            // We need per-share data, so reconstruct from the share
            uint288 share_att;
            uint32_t share_donation = 0;
            std::vector<unsigned char> addr_bytes;

            data.share.invoke([&](auto* obj) {
                auto target = chain::bits_to_target(obj->m_bits);
                share_att = chain::target_to_average_attempts(target);
                share_donation = obj->m_donation;

                if constexpr (requires { obj->m_address; })
                    addr_bytes = obj->m_address.m_data;
                else
                    addr_bytes = obj->m_pubkey_hash.GetChars();
            });

            uint288 share_total = share_att * 65535;
            uint288 share_don = share_att * share_donation;

            // Check if adding this share would exceed desired weight
            if (accum_total + share_total > desired_weight)
            {
                // Proportional inclusion of the last share
                auto remaining = desired_weight - accum_total;
                auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_donation);

                uint288 partial_addr;
                if (!share_total.IsNull())
                    partial_addr = remaining / 65535 * share_addr_weight / (share_total / 65535);

                if (weights.contains(addr_bytes))
                    weights[addr_bytes] += partial_addr;
                else
                    weights[addr_bytes] = partial_addr;

                uint288 partial_donation;
                if (!share_total.IsNull())
                    partial_donation = remaining / 65535 * share_don / (share_total / 65535);

                accum_donation += partial_donation;
                accum_total = desired_weight;
                break;
            }

            // Full inclusion
            auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_donation);
            if (weights.contains(addr_bytes))
                weights[addr_bytes] += share_addr_weight;
            else
                weights[addr_bytes] = share_addr_weight;

            accum_total += share_total;
            accum_donation += share_don;
        }

        return {weights, accum_total, accum_donation};
    }

    // -- Expected payouts from PPLNS weights --
    std::map<std::vector<unsigned char>, double>
    get_expected_payouts(const uint256& best_share_hash, const uint256& block_target, uint64_t subsidy,
                         const std::vector<unsigned char>& donation_script)
    {
        auto chain_len = std::min(chain.get_height(best_share_hash),
                                  static_cast<int32_t>(PoolConfig::REAL_CHAIN_LENGTH));
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * PoolConfig::SHARE_PERIOD * 65535; // SPREAD ≈ SHARE_PERIOD for LTC

        auto [weights, total_weight, donation_weight] = get_cumulative_weights(best_share_hash, chain_len, max_weight);

        std::map<std::vector<unsigned char>, double> result;
        double sum = 0;

        if (!total_weight.IsNull())
        {
            for (const auto& [script, weight] : weights)
            {
                double payout = subsidy * (weight.getdouble() / total_weight.getdouble());
                result[script] = payout;
                sum += payout;
            }
        }

        // Remainder goes to donation
        result[donation_script] = (result.contains(donation_script) ? result[donation_script] : 0.0)
                                  + static_cast<double>(subsidy) - sum;

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
        for (auto& [hash, data] : view)
        {
            StaleInfo si = StaleInfo::none;
            data.share.invoke([&](auto* obj) { si = obj->m_stale_info; });
            if (si != StaleInfo::none)
                stale_count += 1.0f;
        }

        return stale_count / (stale_count + static_cast<float>(actual_lookbehind));
    }
};

} // namespace ltc
