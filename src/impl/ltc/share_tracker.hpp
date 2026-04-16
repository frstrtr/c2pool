#pragma once

#include "share.hpp"
#include "share_check.hpp"
#include "config_pool.hpp"

#include <core/coin_params.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <sharechain/weights_skiplist.hpp>
#include <btclibs/base58.h>

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
    const core::CoinParams* m_params = nullptr;

private:
    static int64_t now_seconds()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

public:
    ShareTracker() = default;
    explicit ShareTracker(const core::CoinParams* params) : m_params(params) {}
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

        auto [height, last] = chain.get_height_and_last(share_hash);

        // Need CHAIN_LENGTH + 1 depth, or the chain must be rooted (last == null)
        if (height < static_cast<int32_t>(m_params->chain_length) + 1 && !last.IsNull())
            return false;

        // P2: init-phase verification (hash-link, merkle, PoW) + check-phase
        try
        {
            auto& share_var = chain.get_share(share_hash);
            share_var.ACTION({
                auto computed_hash = verify_share(*obj, *this, *m_params);
                // verify_share runs both init (PoW/hash-link) and check (PPLNS/gentx)
                (void)computed_hash;
            });
        }
        catch (const std::exception& e)
        {
            LOG_WARNING << "attempt_verify FAILED for " << share_hash.ToString().substr(0,16)
                        << " height=" << height << " last=" << (last.IsNull() ? "null" : last.ToString().substr(0,16))
                        << " error: " << e.what();
            return false; // verification failed
        }

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
        if (head_height < static_cast<int32_t>(m_params->chain_length))
            return {head_height, score_res};

        auto end_point = verified.get_nth_parent_key(share_hash,
            (m_params->chain_length * 15) / 16);

        // Find max block_rel_height in the tail 1/16 of the chain
        std::optional<int32_t> block_height;
        auto tail_count = std::min(
            static_cast<int32_t>(m_params->chain_length / 16),
            verified.get_height(end_point));
        if (tail_count <= 0)
            return {static_cast<int32_t>(m_params->chain_length), score_res};

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
            return {static_cast<int32_t>(m_params->chain_length), score_res};

        // Get accumulated work between share_hash and end_point on the verified chain
        auto interval = verified.get_interval(share_hash, end_point);
        auto time_span = (-block_height.value() + 1) * 150; // LTC BLOCK_PERIOD = 150s
        if (time_span <= 0)
            time_span = 1;

        score_res = interval.work / static_cast<uint32_t>(time_span);
        return {static_cast<int32_t>(m_params->chain_length), score_res};
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
                : std::min(5, std::max(0, head_height - static_cast<int32_t>(m_params->chain_length)));

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

            invalidate_weight_caches(bad);
            chain.remove(bad);
            LOG_WARNING << "Removed bad share " << bad.GetHex().substr(0, 16) << "... from chain";
        }

        // Phase 2: Extend verification from verified heads
        for (auto& [head_hash, tail_hash] : verified.get_heads())
        {
            if (!chain.contains(head_hash))
                continue;

            auto [head_height, last_hash] = verified.get_height_and_last(head_hash);
            if (!chain.contains(last_hash))
                continue;

            auto [last_height, last_last_hash] = chain.get_height_and_last(last_hash);

            auto want = std::max(static_cast<int32_t>(m_params->chain_length) - head_height, 0);
            auto can = last_last_hash.IsNull()
                ? last_height
                : std::max(last_height - 1 - static_cast<int32_t>(m_params->chain_length), 0);
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
            if (head_height < static_cast<int32_t>(m_params->chain_length) && !last_last_hash.IsNull())
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
                if (!chain.contains(hh))
                    continue;

                auto v_height = verified.get_height(hh);
                auto recent_ancestor = verified.get_nth_parent_key(hh, std::min(5, v_height));
                uint288 work_score = verified.get_index(recent_ancestor)->work;

                auto* head_idx = chain.get_index(hh);
                int64_t ts = head_idx->time_seen;

                // Punish heads whose version is below a 95%-activated newer version
                int32_t reason = 0;
                {
                    auto share_version = chain.get_share(hh).version();
                    auto lookbehind = static_cast<int32_t>(m_params->chain_length);
                    if (should_punish_version(hh, share_version, lookbehind))
                        reason = 1;
                }

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

        return {best, desired_result, bad_peer_addresses, punish_aggressively};
    }

    // -- Pool hashrate estimation --
    uint288 get_pool_attempts_per_second(const uint256& share_hash, int32_t dist, bool use_min_work = false)
    {
        if (dist < 2 || !chain.contains(share_hash))
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
        const uint256 MAX_TARGET = m_params->max_target;

        if (prev_share_hash.IsNull())
            return {chain::target_to_bits_upper_bound(MAX_TARGET),
                    chain::target_to_bits_upper_bound(MAX_TARGET)};

        auto [height, last] = chain.get_height_and_last(prev_share_hash);

        // Not enough chain depth: use MAX_TARGET
        if (height < static_cast<int32_t>(m_params->target_lookbehind))
        {
            auto max_bits = chain::target_to_bits_upper_bound(MAX_TARGET);
            return {max_bits, max_bits};
        }

        // Step 1: Derive target from pool hashrate
        auto aps = get_pool_attempts_per_second(prev_share_hash,
            m_params->target_lookbehind, /*min_work=*/true);

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
            uint288 divisor = aps * static_cast<uint32_t>(m_params->share_period);
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
            auto emergency_threshold = m_params->share_period * 20;
            if (time_since_share > emergency_threshold)
            {
                auto half_life = m_params->share_period * 10;
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
        uint256 lo = clamp_ref_target / 10 * 9;
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

        // bits = from_target_upper_bound(clip(desired_target, (pre_target3/30, pre_target3)))
        uint256 bits_lo = pre_target3 / 30;
        if (bits_lo.IsNull()) bits_lo = uint256(1);
        uint256 bits_target = desired_target;
        if (bits_target < bits_lo) bits_target = bits_lo;
        if (bits_target > pre_target3) bits_target = pre_target3;
        auto bits = chain::target_to_bits_upper_bound(bits_target);

        return {max_bits, bits};
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

        // If end_hash is the chain tail (not an actual share), walk manually
        // to collect weights. This happens when the chain is shorter than
        // max_shares — the tail is the null prev_hash of the genesis share.
        if (!chain.contains(end_hash)) {
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

        // Get the full interval from start to end
        auto interval = chain.get_interval(start, end_hash);

        // If total weight is within desired, return the full interval's weights (O(1))
        if (interval.total_weight <= desired_weight)
        {
            return {
                interval.weight_amounts,
                interval.total_weight,
                interval.total_donation_weight
            };
        }

        // Slow path: O(log n) skip list query
        ensure_weights_skiplist();
        auto result = m_weights_skiplist->query(start, max_shares, desired_weight);
        return {std::move(result.weights), result.total_weight, result.total_donation_weight};
    }

    // -- V36 PPLNS with exponential depth-decay --
    // Matches Python: get_decayed_cumulative_weights()
    // half_life = CHAIN_LENGTH // 4
    // Each share's weight is multiplied by 2^(-depth/half_life)
    // Fixed-point arithmetic with 40-bit precision
    CumulativeWeights get_v36_decayed_cumulative_weights(
        const uint256& start, int32_t max_shares, const uint288& desired_weight)
    {
        if (start.IsNull())
            return {};

        static constexpr uint64_t DECAY_PRECISION = 40;
        static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
        static constexpr uint64_t LN2_MICRO = 693147;

        uint32_t half_life = std::max(m_params->chain_length / 4, uint32_t(1));
        uint64_t decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);

        CumulativeWeights result;
        int32_t share_count = 0;
        uint64_t decay_fp = DECAY_SCALE; // starts at 1.0

        uint256 cur = start;
        while (!cur.IsNull() && chain.contains(cur) && share_count < max_shares)
        {
            auto& share_data = chain.get_share(cur);
            uint256 next_cur;

            share_data.invoke([&](auto* obj) {
                auto att = chain::target_to_average_attempts(
                    chain::bits_to_target(obj->m_bits));
                uint32_t don = obj->m_donation;

                // Apply exponential decay: decayed_att = att * decay_fp >> PRECISION
                uint288 decayed_att = (att * uint288(decay_fp)) >> DECAY_PRECISION;

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

                std::vector<unsigned char> script = get_share_script(obj);

                result.weights[script] = result.weights[script] + addr_w;
                result.total_weight = result.total_weight + this_total;
                result.total_donation_weight = result.total_donation_weight + don_w;
                next_cur = obj->m_prev_hash;
            });

            ++share_count;
            if (result.total_weight >= desired_weight)
                break;

            cur = next_cur;
            // Decay for next (older) share
            // Use 128-bit multiply to avoid overflow: decay_fp and decay_per are both ~2^40,
            // their product is ~2^80 which overflows uint64_t (max 2^64).
            decay_fp = static_cast<uint64_t>(
                (static_cast<__uint128_t>(decay_fp) * decay_per) >> DECAY_PRECISION);
        }

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
        auto chain_len = std::min(chain.get_height(best_share_hash),
                                  static_cast<int32_t>(m_params->real_chain_length));
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * m_params->spread * 65535;

        // V36: use exponential depth-decay (matching Python's get_decayed_cumulative_weights)
        auto [weights, total_weight, donation_weight] = get_v36_decayed_cumulative_weights(best_share_hash, chain_len, max_weight);

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
            auto largest = std::max_element(result.begin(), result.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
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
        for (auto& [hash, data] : view)
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
        for (auto& [hash, data] : view)
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
        for (auto& [hash, data] : view)
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

        auto height = chain.get_height(prev_share_hash);
        if (height == 0)
            return uint256{};

        auto max_weight = chain::target_to_average_attempts(block_target)
                          * m_params->spread * 65535;
        auto chain_len = std::min(height,
                                  static_cast<int32_t>(m_params->real_chain_length));

        auto [weights, total_weight, donation_weight] =
            get_v36_merged_weights(prev_share_hash, chain_len, max_weight);

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

        // Convert script bytes to base58check address string,
        // matching Python's share.address format used as dict key.
        auto script_to_address = [](const std::vector<unsigned char>& script) -> std::string {
            // P2PKH: OP_DUP OP_HASH160 <20> <hash160> OP_EQUALVERIFY OP_CHECKSIG
            if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9
                && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
            {
                unsigned char addr_ver = m_params->address_version;
                std::vector<unsigned char> data = {addr_ver};
                data.insert(data.end(), script.begin() + 3, script.begin() + 23);
                return EncodeBase58Check(data);
            }
            // P2SH: OP_HASH160 <20> <hash160> OP_EQUAL
            if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14
                && script[22] == 0x87)
            {
                unsigned char addr_ver = m_params->address_p2sh_version;
                std::vector<unsigned char> data = {addr_ver};
                data.insert(data.end(), script.begin() + 2, script.begin() + 22);
                return EncodeBase58Check(data);
            }
            // Unknown script: fall back to hex encoding
            std::string hex;
            for (unsigned char c : script) {
                static const char digits[] = "0123456789abcdef";
                hex.push_back(digits[c >> 4]);
                hex.push_back(digits[c & 0xf]);
            }
            return hex;
        };

        // Deterministic serialization: sorted by address key (matches Python)
        // Format: "addr1:weight1|addr2:weight2|...|T:total|D:donation"
        // where addr is base58check address string and weight is decimal integer
        std::map<std::string, uint288> sorted_by_addr;
        for (const auto& [script, w] : weights)
            sorted_by_addr[script_to_address(script)] += w;

        std::string payload;
        for (const auto& [addr_key, w] : sorted_by_addr)
        {
            if (!payload.empty())
                payload.push_back('|');
            payload += addr_key;
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
        return Hash(span);
    }

    // -- Merged mining: per-chain expected payouts --
    // Given an aux chain's subsidy and chain_id, computes the expected payout
    // distribution using merged PPLNS weights.
    std::map<std::vector<unsigned char>, double>
    get_merged_expected_payouts(const uint256& best_share_hash,
                                const uint256& block_target,
                                uint64_t subsidy,
                                uint32_t chain_id,
                                const std::vector<unsigned char>& donation_script)
    {
        auto chain_len = std::min(chain.get_height(best_share_hash),
                                  static_cast<int32_t>(m_params->real_chain_length));
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * m_params->spread * 65535;

        auto [weights, total_weight, donation_weight] =
            get_merged_cumulative_weights(best_share_hash, chain_len, max_weight, chain_id);

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

        result[donation_script] = (result.contains(donation_script) ? result[donation_script] : 0.0)
                                  + static_cast<double>(subsidy) - sum;

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

    // Previous-share lambda shared by all skip lists
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
                    auto addr_bytes = get_share_script(obj);
                    delta.weights[addr_bytes] = att * static_cast<uint32_t>(65535 - obj->m_donation);
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
                        if (weight_key.empty())
                            weight_key = get_share_script(obj);
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
    }
};

} // namespace ltc
