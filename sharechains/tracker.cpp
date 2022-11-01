#include "tracker.h"
#include "share.h"

using namespace shares;

#include <univalue.h>
#include <btclibs/uint256.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libdevcore/random.h>
#include <libcoind/data.h>

#include <map>
#include <queue>
#include <tuple>
#include <memory>
#include <cmath>
#include <algorithm>
#include <iterator>
#include <boost/optional.hpp>
#include <boost/format.hpp>

using std::find;
using std::map;
using std::queue;
using std::shared_ptr;

#include <boost/format.hpp>

ShareTracker::ShareTracker(shared_ptr<c2pool::Network> _net) : SharePrefsum2(), verified(*this), net(_net), parent_net(_net->parent)
{

}

ShareType ShareTracker::get(uint256 hash)
{
	try
	{
		auto share = SharePrefsum2::items.at(hash);
		return share;
	}
	catch (const std::out_of_range &e)
	{
        LOG_WARNING << "ShareTracker.get(" << hash.GetHex() << "): out of range!";
		return nullptr;
	}
}

void ShareTracker::add(ShareType share)
{
	if (!share)
	{
		LOG_WARNING << "ShareTracker::add called, when share = nullptr!";
		return;
	}

	if (!SharePrefsum2::exists(share->hash))
	{
        SharePrefsum2::add(share);
	} else
	{
		LOG_WARNING << share->hash.ToString() << " item already present";
	}
}

void ShareTracker::remove(uint256 hash)
{
    auto res = get(hash);
    //TODO:

    removed.happened(res);
}

bool ShareTracker::attempt_verify(ShareType share)
{
	if (verified.exists(share->hash))
	{
		return true;
	}

	try
	{
		share->check(shared_from_this());
	}
	catch (const std::invalid_argument &e)
	{
		LOG_WARNING << e.what() << '\n';
		return false;
	}

	verified.add(share);
	return true;
}

TrackerThinkResult ShareTracker::think(boost::function<int32_t(uint256)> block_rel_height_func, uint256 previous_block, uint32_t bits, std::map<uint256, coind::data::tx_type> known_txs)
{
    std::set<desired_type> desired;
    std::set<std::tuple<std::string, std::string>> bad_peer_addresses;

    std::vector<uint256> bads;

    // TODO: Wanna for optimization?
    for (auto [head, element] : sum)
    {
        if (verified.exists(head))
            continue;
        auto [head_height, last] = get_height_and_last(head);

        {
            auto get_chain_f = get_chain(head, last.IsNull() ? head_height : std::min(5, std::max(0, head_height -
                                                                                                     net->CHAIN_LENGTH)));

            uint256 _hash;
            bool _verified = false;
            while (get_chain_f(_hash))
            {
                if (attempt_verify(get(_hash)))
                {
                    _verified = true;
                    break;
                }
                bads.push_back(_hash);
            }
            if (!_verified && !last.IsNull())
            {
                uint32_t desired_timestamp = *items[head]->timestamp;
                uint256 desired_target = items[head]->target;

                uint256 temp_hash;
                auto get_chain_f2 = get_chain(head, std::min(head_height, 5));
                while (get_chain_f2(temp_hash))
                {
                    desired_timestamp = std::max(desired_timestamp, *items[temp_hash]->timestamp);
                    desired_target = std::min(desired_target, items[temp_hash]->target);
                }

                std::tuple<std::string, std::string> _peer_addr;
                if (!sum[last].next.empty())
                {
                    auto peer_addr_hash = c2pool::random::RandomChoice(sum[last].next)->first;
                    _peer_addr = items[peer_addr_hash]->peer_addr;
                } else {
                    _peer_addr = items[last]->peer_addr;
                }

                desired.insert({
                                       _peer_addr,
                                       last,
                                       desired_timestamp,
                                       desired_target
                               });
            }
        }
    }

    for (auto bad : bads)
    {
        assert(verified.items.count(bad) == 0);

        auto bad_share = items[bad];
        bad_peer_addresses.insert(bad_share->peer_addr);

        try
        {
            remove(bad);
        } catch (const std::error_code &ec)
        {
            LOG_ERROR << "BAD REMOVE ERROR:  " << ec.message();
        }
    }

    // try to get at least CHAIN_LENGTH height for each verified head, requesting parents if needed
    for (auto head : verified.sum)
    {
        // TODO: error here
        auto [head_height, last_hash] = verified.get_height_and_last(head.first);
        auto [last_height, last_last_hash] = get_height_and_last(last_hash);
        // XXX: review boundary conditions
        auto want = std::max(net->CHAIN_LENGTH - head_height, 0);
        auto can = last_last_hash.IsNull() ? last_height : std::max(last_height - 1 - net->CHAIN_LENGTH, 0);
        auto _get = std::min(want, can);

        uint256 share_hash;
        while(get_chain(last_hash, _get)(share_hash))
        {
            if (!attempt_verify(get(share_hash)))
                break;
        }
        if (head_height < net->CHAIN_LENGTH && !last_last_hash.IsNull())
        {
            uint32_t desired_timestamp = *items[head.first]->timestamp;
            uint256 desired_target = items[head.first]->target;

            uint256 temp_hash;
            while (get_chain(head.first, std::min(head_height, 5))(temp_hash))
            {
                desired_timestamp = std::max(desired_timestamp, *items[temp_hash]->timestamp);
                desired_target = std::min(desired_target, items[temp_hash]->target);
            }

            desired.insert({
                                   items[c2pool::random::RandomChoice(verified.sum[last_hash].next)->first]->peer_addr,
                                   last_last_hash,
                                   desired_timestamp,
                                   desired_target
                           });
        }
    }

    // decide best tree
    std::vector<std::tuple<std::tuple<int32_t, uint256>, uint256>> decorated_tails;
    for (auto tail_hash : verified.sum)
    {
        auto max_el = std::max_element(tail_hash.second.next.begin(), tail_hash.second.next.end(),
                         [&](const std::map<uint256, element_type>::iterator &a, const std::map<uint256, element_type>::iterator &b)
                         {
                            return verified.get_work(a->first) < verified.get_work(b->first);
                         });

        auto _score = std::make_tuple(score((*max_el)->first, block_rel_height_func), tail_hash.first);
        decorated_tails.push_back(_score);
    }
    std::sort(decorated_tails.begin(), decorated_tails.end()); //TODO: test for compare with p2pool

    auto [best_tail_score, best_tail] = decorated_tails.empty() ? std::make_tuple(std::make_tuple(0, uint256::ZERO), uint256::ZERO) : decorated_tails.back();

    // decide best verified head
    std::vector<std::tuple<std::tuple<uint256, int32_t, int32_t>, uint256>> decorated_heads;
    // TODO: +0 element
    if (verified.sum.find(best_tail) != verified.sum.end())
    {
        for (auto h: verified.sum[best_tail].next)
        {
            auto el = std::make_tuple(
                    verified.get_work(
                            verified.get_nth_parent_key(h->first, std::min(5, verified.get_height(h->first)))),
                    -std::get<0>(should_punish_reason(h->second.get_value(), previous_block, bits, known_txs)),
                    -h->second.get_value()->time_seen
            );
            decorated_heads.emplace_back(el, h->first);
        }
    }
    std::sort(decorated_heads.begin(), decorated_heads.end()); //TODO: test for compare with p2pool
    //TODO: debug print heads. Top 10.

    auto [best_head_score, best] = decorated_heads.empty() ? std::make_tuple(std::make_tuple(uint256::ZERO, 0, 0), uint256::ZERO) : decorated_heads.back();

    uint32_t timestamp_cutoff;
    arith_uint256 target_cutoff;

    if (!best.IsNull())
    {
        auto best_share = items[best];
        auto [punish,  punish_reason] = should_punish_reason(best_share, previous_block, bits, known_txs);
        if (punish)
        {
            LOG_INFO << "Punishing share for " << punish_reason << "! Jumping from " << best.ToString() << " to " << best_share->previous_hash->ToString() << "!";
            best = *best_share->previous_hash;
        }

        timestamp_cutoff = std::min((uint32_t)c2pool::dev::timestamp(), *best_share->timestamp) - 3600;

        target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        target_cutoff /= std::get<1>(best_tail_score).IsNull() ? UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) : (UintToArith256(std::get<1>(best_tail_score)) * net->SHARE_PERIOD + 1) * 2;
    } else
    {
        timestamp_cutoff = c2pool::dev::timestamp() - 24*60*60;
        target_cutoff = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    }

    //TODO: debug print data

    auto _target_cutoff = ArithToUint256(target_cutoff);

    std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired_result;
    for (auto [peer_addr, hash, ts, targ] : desired)
    {
        if (ts >= timestamp_cutoff)
            desired_result.push_back({peer_addr, hash});
    }

    return {best, desired_result, decorated_heads, bad_peer_addresses};
}

arith_uint256 ShareTracker::get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work)
{
	assert(("get_pool_attempts_per_second: assert for dist >= 2", dist >= 2));
    auto near = get(previous_share_hash);
    auto far = get(SharePrefsum2::get_nth_parent_key(previous_share_hash,dist - 1));
	auto attempts_delta = SharePrefsum2::get_sum(previous_share_hash, far->hash);

	auto time = *near->timestamp - *far->timestamp;
	if (time <= 0)
	{
		time = 1;
	}

	arith_uint256 res;
	if (min_work)
	{
		res = attempts_delta.min_work;
	} else
	{
		res = attempts_delta.work;
	}
	res /= time;

	return res;
}

std::vector<uint256> ShareTracker::get_other_tx_hashes(ShareType share)
{
    uint64_t parents_needed = 0;
    if (!(*share->share_info)->transaction_hash_refs.empty())
    {
        for (auto [share_count, tx_count]: (*share->share_info)->transaction_hash_refs)
        {
            parents_needed = std::max(parents_needed, share_count);
        }
    }
    auto parents = get_height(share->hash);
    if (parents < parents_needed)
        return {};

    std::vector<ShareType> last_shares;

    uint256 last_share_hash;
    while (get_chain(share->hash, parents_needed + 1)(last_share_hash))
    {
        last_shares.push_back(get(last_share_hash));
    }

    std::vector<uint256> result;
    for (auto [share_count, tx_count]: (*share->share_info)->transaction_hash_refs)
    {
        result.push_back(last_shares[share_count]->share_info->get()->new_transaction_hashes[tx_count]);
    }
    return result;
}

std::vector<coind::data::tx_type> ShareTracker::_get_other_txs(ShareType share, const std::map<uint256, coind::data::tx_type> &known_txs)
{
    auto other_tx_hashes = get_other_tx_hashes(share);

    if (other_tx_hashes.empty())
    {
        return {}; // not all parents present
    }

    if (std::all_of(other_tx_hashes.begin(), other_tx_hashes.end(), [&](uint256 tx_hash) { return known_txs.count(tx_hash) > 0; }))
    {
        return {}; // not all txs present
    }

    std::vector<coind::data::tx_type> result;
    std::for_each(other_tx_hashes.begin(), other_tx_hashes.end(), [&](uint256 &tx_hash){
        result.push_back(known_txs.at(tx_hash));
    });

    return result;
}

std::tuple<bool, std::string> ShareTracker::should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits,
                                                                 const std::map<uint256, coind::data::tx_type> &known_txs)
{
    if (UintToArith256(share->pow_hash) <= UintToArith256(share->header.stream()->bits.bits.target()))
        return {-1, "block_solution"};

    auto other_txs = _get_other_txs(share, known_txs);
    if (!other_txs.empty())
    {
        // Оптимизация?: два all_txs_size; stripped_txs_size -- за один цикл, а не два.
        auto all_txs_size = std::accumulate(other_txs.begin(), other_txs.end(), 0, [&](const int32_t &a, coind::data::tx_type tx)-> int32_t{
            coind::data::stream::TransactionType_stream packed_tx = tx;

            PackStream stream;
            stream << packed_tx;
            return a + stream.size();
        });

        auto stripped_txs_size = std::accumulate(other_txs.begin(), other_txs.end(), 0, [&](const int32_t &a, coind::data::tx_type tx)-> int32_t{
            auto stream_txid = coind::data::stream::TxIDType_stream(tx->version,tx->tx_ins, tx->tx_outs, tx->lock_time);
            PackStream stream;
            stream << stream_txid;

            return a + stream.size();
        });

        //TODO: c2pool::DEBUG -> print stripped_txs_size
        if ((all_txs_size + 3 * stripped_txs_size + 4*80 + share->gentx_weight) > net->BLOCK_MAX_WEIGHT)
            return {true, "txs over block weight limit"};
        if ((stripped_txs_size + 80 + share->gentx_size) > net->BLOCK_MAX_SIZE)
            return {true, "txs over block size limit"};
    }
    return {false, ""};
}
