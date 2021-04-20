#pragma once

#include <univalue.h>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <coind/data.h>
#include <devcore/logger.h>

#include <map>
#include <vector>
#include <set>
#include <tuple>
#include <string>
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
    struct TrackerThinkResult
    {
        uint256 best_hash;
        std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired;
        std::vector<uint256> decorated_heads; //TODO: TYPE???
        std::set<std::tuple<std::string, std::string>> bad_peer_addresses;
    };

    class LookbehindDelta
    {
    private:
        queue<shared_ptr<BaseShare>> _queue;

        arith_uint256 work;
        arith_uint256 min_work;

    public:
        size_t size()
        {
            return _queue.size();
        }

        void push(shared_ptr<BaseShare> share);
    };

    class ShareTracker
    {
    private:
        map<uint256, shared_ptr<BaseShare>> items;
        LookbehindDelta lookbehind_items;

    public:
        ShareTracker();

        void add(shared_ptr<BaseShare> share);

        TrackerThinkResult think();
    };
} // namespace c2pool::shares::tracker
