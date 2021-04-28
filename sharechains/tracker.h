#pragma once

#include <univalue.h>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <coind/data.h>
#include <devcore/logger.h>

#include <map>
#include <vector>
#include <string>
#include <memory>
#include <set>
#include <tuple>

#include <queue> //TODO: remove
using namespace std;

namespace c2pool::shares::share
{
    class BaseShare;
} // namespace c2pool::shares::tracker

using namespace c2pool::shares::share;

#define LOOKBEHIND 200
//TODO: multi_index for more speed https://www.boost.org/doc/libs/1_76_0/libs/multi_index/doc/index.html
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

        map<uint256, bool> verified; //share.hash -> is verified

    public:
        ShareTracker();

        shared_ptr<BaseShare> get(uint256 hash);
        void add(shared_ptr<BaseShare> share);

        bool attempt_verify(BaseShare share);

        TrackerThinkResult think();
    };
} // namespace c2pool::shares::tracker
