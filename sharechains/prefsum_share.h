#include <univalue.h>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <devcore/logger.h>

#include <map>
#include <vector>
#include <set>
#include <tuple>
#include <string>
#include <memory>
#include <deque>
using std::map;
using std::shared_ptr;
using namespace std;

namespace c2pool::shares::tracker
{
    struct PrefixSumShareElement
    {
        uint256 hash; //head
        //TODO: ? uint256 previous_hash; //tail

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
        map<uint256, deque<PrefixSumShareElement>::iterator> _reverse;
        int max_size;
        int real_max_size;

    private:
        void resize()
        {
            auto delta = _sum[max_size - 1];
            for (int i = 0; i < max_size; i++)
            {
                reverse_remove(_sum.front().hash);
                _sum.pop_front();
            }
            for (auto &item : _sum)
            {
                item -= delta;
            }
        }

        void reverse_add(uint256 hash, deque<PrefixSumShareElement>::iterator _it);

        void reverse_remove(uint256 hash);

    public:
        PrefixSumShare(int _max_size)
        {
            max_size = _max_size;
            real_max_size = max_size * 4;
        }

        void init(vector<PrefixSumShareElement> a)
        {
            for (auto item : a)
            {
                add(item);
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
            reverse_add(v.hash, _sum.end() - 1);
        }

        void remove(int index)
        {
            if ((_sum.size() <= index) && (index < 0))
            {
                throw std::out_of_range("size of sum < index in prefix_sum.remove");
            }
            if (_sum.size() - 1 == index)
            {
                reverse_remove(_sum.back().hash);
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

                auto it_for_remove = _sum.begin() + index;
                reverse_remove(it_for_remove->hash);
                _sum.erase(it_for_remove);
            }
        }

        size_t size()
        {
            return _sum.size();
        }
    };
}