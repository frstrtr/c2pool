#include "tracker.h"
#include "share.h"

using namespace c2pool::shares;

#include <univalue.h>
#include <btclibs/uint256.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libcoind/data.h>

#include <map>
#include <queue>
#include <memory>
#include <cmath>
#include <algorithm>
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

TrackerThinkResult ShareTracker::think(boost::function<int32_t(uint256)> block_rel_height_func)
{
    //TODO:
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