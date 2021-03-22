#pragma once

#include <lib/univalue/include/univalue.h>
#include <btclibs/uint256.h>
#include <devcore/logger.h>

#include <map>
#include <queue>
#include <memory>
using std::map;
using std::queue;
using std::shared_ptr;

namespace c2pool::shares::share
{
    class BaseShare;
} // namespace c2pool::shares::tracker

using namespace c2pool::shares::share;

#define LOOKBEHIND 200

namespace c2pool::shares::tracker
{
    class LookbehindDelta
    {
    private:
        queue<shared_ptr<BaseShare>> _queue;

        uint256 work;
        uint256 min_work;

    public:
        size_t size()
        {
            return _queue.size();
        }

        void push(shared_ptr<BaseShare> share)
        {
            if (_queue.size() == LOOKBEHIND)
            {
                //TODO:
                //auto temp = _queue.pop();
                //work -= bitcoin_data.target_to_average_attempts(temp.max_target)
                //min_work = bitcoin_data.target_to_average_attempts(temp.max_target)
            }

            _queue.push(share);
            //work += bitcoin_data.target_to_average_attempts(share.target)
            //min_work += bitcoin_data.target_to_average_attempts(share.max_target)
        }
    };

    class ShareTracker
    {
    private:
        map<uint256, shared_ptr<BaseShare>> items;
        LookbehindDelta lookbehind_items;

    public:
        void add(shared_ptr<BaseShare> share);
    };
} // namespace c2pool::shares::tracker
