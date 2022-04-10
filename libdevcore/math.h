#pragma once

#include <algorithm>
#include <vector>
#include <map>
#include <string>
#include <initializer_list>
#include <btclibs/uint256.h>

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
//      - RateMonitor

namespace c2pool::math
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
    string natural_to_string(uint256 n);

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
}