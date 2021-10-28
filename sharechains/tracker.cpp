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

namespace c2pool::shares
{
    ShareTracker::ShareTracker() : verified(shares)
    {
    }

    shared_ptr<BaseShare> ShareTracker::get(uint256 hash)
    {
        try
        {
            auto share = shares.items.at(hash);
            return share;
        }
        catch (const std::out_of_range &e)
        {
            return nullptr;
        }
    }

    void ShareTracker::add(shared_ptr<BaseShare> share)
    {
        if (!share)
        {
            LOG_WARNING << "ShareTracker::add called, when share = nullptr!";
            return;
        }

        if (!shares.exists(share->hash))
        {
            shares.add(share);
        }
        else
        {
            LOG_WARNING << share->hash.ToString() << " item already present"; //TODO: for what???
        }
    }

    bool ShareTracker::attempt_verify(shared_ptr<BaseShare> share)
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

    TrackerThinkResult ShareTracker::think()
    {
    }

    uint256 ShareTracker::get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work){
        assert(dist >= 2);
        auto near = shares.items[previous_share_hash]; //TODO: rework for shares.get_item()
        auto far = shares.items[shares.get_nth_parent_hash(previous_share_hash, dist-1)]; //TODO: rework for shares.get_item()
        auto attempts_delta = shares.get_delta(previous_share_hash, far->hash);

        auto time = near->timestamp - far->timestamp;
        if (time <= 0){
            time = 1;
        }

        arith_uint256 res;
        if (min_work){
            res = attempts_delta.min_work;
        } else {
            res = attempts_delta.work;
        }
        res /= time;

        return ArithToUint256(res);
    }
}