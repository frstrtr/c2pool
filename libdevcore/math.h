#pragma once

#include <algorithm>
#include <vector>
#include <map>
#include <string>
#include <initializer_list>
#include <btclibs/uint256.h>

#include "common.h"

using namespace std;

//TODO:
// skipped:
// - generator nth
// - geometric, reversed, flatten_linked_list [useless, for skiplist]
// - perfect_round [lol]
//  For tests:
//      - add_tuples
//      - reversed
//  For statistics:
//      - format, format_dt
//      - erf
//      - find_root
//      - ierf
//      - binomial_conf_interval
//      - format_binomial_conf
//      - weighted_choice

namespace math
{
    template <typename T>
    auto median(vector<T> values)
    {
        size_t size = values.size();

        if (size == 0)
        {
            //throw?
            return 0;
        }
        else
        {
            sort(values.begin(), values.end());
            if (size % 2 == 0)
            {
                return (values[size / 2 - 1] + values[size / 2]) / 2;
            }
            else
            {
                return values[size / 2];
            }
        }
    }

    template <typename T>
    auto mean(vector<T> values)
    {
        T total;
        int count = 0;

        for (auto v : values)
        {
            total += v;
            count += 1;
        }

        return total / count;
    }

    template <typename T>
    T clip(T value, T low, T high)
    {
        return clamp(value, low, high);
    }

    //without alphabet arg for base58
    std::vector<unsigned char> natural_to_string(uint256 n);

    // string_to_natural

    //example: merge_dicts({map1, map2, map3});
    template <typename KEY, typename VALUE>
    map<KEY, VALUE> merge_dicts(std::initializer_list<map<KEY, VALUE>> dicts)
    {
        map<KEY, VALUE> result;
        for (auto dict : dicts)
        {
            for (auto pair : dict)
            {
                result[pair.first] = pair.second;
            }
        }

        return result;
    }

    template <typename IteratorValue>
    std::vector<typename IteratorValue::value_type> every_nth_element(IteratorValue begin, IteratorValue end, int32_t n)
    {
        std::vector<typename IteratorValue::value_type> result;
        for (auto it = begin; it < end; it+=n)
        {
            result.push_back(*it);
        }
        return result;
    }

    template <typename T>
    class RateMonitor
    {
    private:
        int32_t max_lookback_time;
        std::vector<std::pair<int32_t, T>> datums;

        int32_t first_timestamp;

        void prune()
        {
            auto start_time = c2pool::dev::timestamp() - max_lookback_time;

            int i = 0;
            for (auto [ts, datum]: datums)
            {
                if (ts > start_time)
                {
                    datums.erase(datums.begin(), datums.begin() + i);
                }
            }
        }

    public:
        RateMonitor(int32_t _max_lookback_time) : max_lookback_time(_max_lookback_time), first_timestamp(0)
        {}

        void add_datum(T datum)
        {
            prune();

            int32_t t = c2pool::dev::timestamp();
            if (first_timestamp == 0)
                first_timestamp = t;
            else
                datums.push_back(std::make_pair(t, datum));
        }

        std::tuple<std::vector<T>, int32_t> get_datums_in_last(int32_t dt = 0)
        {
            if (dt == 0)
                dt = max_lookback_time;

            assert(dt <= max_lookback_time);

            prune();
            int32_t now = c2pool::dev::timestamp();
            std::vector<T> res;
            for (auto [ts, datum]: datums)
            {
                if (ts > now - dt)
                    res.push_back(datum);
            }

            return std::make_tuple(res, first_timestamp != 0 ? min(dt, now - first_timestamp) : 0);
        }
    };
}