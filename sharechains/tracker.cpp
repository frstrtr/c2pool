#include "tracker.h"
#include "share.h"
using namespace c2pool::shares::share;

#include <univalue.h>
#include <btclibs/uint256.h>
#include <devcore/logger.h>
#include <devcore/common.h>


#include <map>
#include <queue>
#include <memory>
using std::map;
using std::queue;
using std::shared_ptr;

#include <boost/format.hpp>

namespace c2pool::shares::tracker
{
    void LookbehindDelta::push(shared_ptr<BaseShare> share)
    {
        if (_queue.size() == LOOKBEHIND)
        {
            shared_ptr<BaseShare> temp = _queue.front();

            work = work - coind::data::target_to_average_attempts(temp->target);
            min_work = min_work - coind::data::target_to_average_attempts(temp->max_target);
            _queue.pop();
        }

        _queue.push(share);
        work = work + coind::data::target_to_average_attempts(share->target);
        min_work = min_work + coind::data::target_to_average_attempts(share->max_target);
    }
}

namespace c2pool::shares::tracker
{
    ShareTracker::ShareTracker() {}

    shared_ptr<BaseShare> ShareTracker::get(uint256 hash){
        try
        {
            auto share = items.at(hash);
            return share;
        }
        catch(const std::out_of_range& e)
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

        if (items.find(share->hash) != items.end())
        {
            items[share->hash] = share;
        }
        else
        {
            LOG_WARNING << share->hash.ToString() << " item already present"; //TODO: for what???
        }

        lookbehind_items.push(share);
    }

    bool ShareTracker::attempt_verify(BaseShare share)
    {
        if (verified.find(share.hash) != verified.end())
        {
            return true;
        }

        try
        {
            if (share.timestamp > (c2pool::dev::timestamp() + 600))
            {
                throw std::invalid_argument((boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} % (share.timestamp - c2pool::dev::timestamp())).str());
            }
            
            if (share.pre)
        }
        catch (const std::invalid_argument &e)
        {
            LOG_WARNING << e.what() << '\n';
            return false;
        }
    }

    TrackerThinkResult ShareTracker::think()
    {
    }
}