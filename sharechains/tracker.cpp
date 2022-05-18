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

ShareTracker::ShareTracker(shared_ptr<c2pool::Network> _net) : PrefsumShare(), verified(*this), net(_net), parent_net(_net->parent)
{

}

ShareType ShareTracker::get(uint256 hash)
{
	try
	{
		auto share = PrefsumShare::items.at(hash);
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

	if (!PrefsumShare::exists(share->hash))
	{
        PrefsumShare::add(share);
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
            if (_verified && !last.IsNull())
            {
                uint32_t desired_timestamp = *items[head]->timestamp;
                uint256 desired_target = items[head]->target;

                uint256 temp_hash;
                while (get_chain(head, std::min(head_height, 5))(temp_hash))
                {
                    desired_timestamp = std::max(desired_timestamp, *items[temp_hash]->timestamp);
                    desired_target = std::min(desired_target, items[temp_hash]->target);
                }

                desired.insert({
                                       c2pool::random::RandomChoice(sum[last].nexts)->second.element->peer_addr,
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
                                   c2pool::random::RandomChoice(verified.sum[last_hash].nexts)->second.element->peer_addr,
                                   last_last_hash,
                                   desired_timestamp,
                                   desired_target
                           });
        }
    }

    // decide best tree
    std::vector<std::tuple<int32_t, uint256>> decorated_tails;
    for (auto tail_hash : verified.sum)
    {
        auto max_el = std::max_element(tail_hash.second.nexts.begin(), tail_hash.second.nexts.end(),
                         [&](const std::map<uint256, element_type>::iterator &a, const std::map<uint256, element_type>::iterator &b)
                         {
                            return verified.get_work(a->first) < verified.get_work(b->first);
                         });

        auto _score = score((*max_el)->first, block_rel_height_func);
        decorated_tails.push_back(_score);
    }
    std::sort(decorated_tails.begin(), decorated_tails.end()); //TODO: test for compare with p2pool

    auto [best_tail_score, best_tail] = decorated_tails.empty() ? std::make_tuple(0, uint256::ZERO) : decorated_tails.back();

    // decide best verified head
    std::vector<std::tuple<int>> decorated_heads;
    for (auto h : verified.sum[best_tail].nexts)
    {
        //TODO:
//        std::make_tuple(
//                verified.get_work(verified.get_nth_parent_hash(h->first, std::min(5, verified.get_height(h->first)))),
//                -h->second.element.
//                )
    }
}

arith_uint256 ShareTracker::get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work)
{
	assert(dist >= 2);
    auto near = get(previous_share_hash);
    auto far = get(PrefsumShare::get_nth_parent_hash(previous_share_hash,dist - 1));
	auto attempts_delta = PrefsumShare::get_delta(previous_share_hash, far->hash);

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
    //TODO:
    return std::tuple<bool, std::string>();
}
