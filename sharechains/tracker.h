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
#include <deque>
using std::map;
using std::queue;
using std::shared_ptr;
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

    struct PrefixSumShareElement
    {
    public:
        arith_uint256 work;
        arith_uint256 min_work;
        int height;

        PrefixSumShareElement &operator+=(const PrefixSumShareElement &rhs)
        {
            work += rhs.work;
            min_work += rhs.min_work;
            height += rhs.height;
            return *this;
        }

        PrefixSumShareElement &operator-=(const PrefixSumShareElement &rhs)
        {
            work -= rhs.work;
            min_work -= rhs.min_work;
            height -= rhs.height;
            return *this;
        }

        friend PrefixSumShareElement operator-(PrefixSumShareElement lhs, const PrefixSumShareElement &rhs)
        {
            lhs.work -= rhs.work;
            lhs.min_work -= rhs.min_work;
            lhs.height -= rhs.height;
            return lhs;
        }

        friend PrefixSumShareElement operator+(PrefixSumShareElement lhs, const PrefixSumShareElement &rhs)
        {
            lhs.work += rhs.work;
            lhs.min_work += rhs.min_work;
            lhs.height += rhs.height;
            return lhs;
        }
    };

    //https://en.wikipedia.org/wiki/Prefix_sum
    class PrefixSumShare
    {
    protected:
        deque<PrefixSumShareElement> _sum;
        int max_size;
        int real_max_size;

    private:
        void resize()
        {
            auto delta = _sum[max_size - 1];
            for (int i = 0; i < max_size; i++)
            {
                //delta += sum.front();
                _sum.pop_front();
            }
            for (auto &item : _sum)
            {
                item -= delta;
            }
        }

    public:
        PrefixSumShare(int _max_size)
        {
            max_size = _max_size;
            real_max_size = max_size * 4;
        }

        void init(vector<int> a)
        {
            int i = 0;
            if (_sum.empty())
            {
                _sum.push_back(a[i]);
                i++;
            }
            for (; i < a.size(); i++)
            {
                _sum.push_back(_sum.back() + a[i]);
            }
        }

        void add(PrefixSumShareElement v)
        {
            if (_sum.size() >= real_max_size)
            {
                resize();
            }
            if (!_sum.empty())
            {
                v += _sum.back();
            }
            _sum.push_back(v);
        }

        void remove(int index)
        {
            if ((_sum.size() <= index) && (index < 0))
            {
                throw std::out_of_range("size of sum < index in prefix_sum.remove");
            }
            if (_sum.size() - 1 == index)
            {
                _sum.pop_back();
            }
            else
            {
                PrefixSumShareElement v;
                if (index - 1 < 0)
                {
                    v = _sum[index];
                }
                else
                {
                    v = _sum[index] - _sum[index - 1];
                }
                for (auto item = _sum.begin() + index + 1; item != _sum.end(); item++)
                {
                    *item -= v;
                }
                _sum.erase(_sum.begin() + index);
            }
        }
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
