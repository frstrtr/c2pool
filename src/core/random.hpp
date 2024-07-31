#pragma once
#include <vector>
#include <map>
#include <list>
#include <core/uint256.hpp>

namespace core::random
{
    // [min, max)
    int random_int(int min, int max);

    // [min, max]
    float random_float(float min, float max);

    std::vector<unsigned char> random_bytes(int32_t length);

	uint256 random_uint256();

    template <typename T>
    T random_choice(std::vector<T> &list)
    {
        int pos = core::random::random_int(0, list.size());
        return list[pos];
    }

    template <typename T>
    T random_choice(const std::vector<T> &list)
    {
        int pos = core::random::random_int(0, list.size());
        return list[pos];
    }


    template <typename Key, typename Value>
    Value random_choice(std::map<Key, Value> _map)
    {
        int pos = core::random::random_int(0, _map.size());
        auto item = _map.begin();
        std::advance(item, pos);
        return item->second;
    }

    template <typename Value>
    Value random_choice(std::list<Value> _list)
    {
        int pos = core::random::random_int(0, _list.size());
        auto item = _list.begin();
        std::advance(item, pos);
        return *item;
    }

    ///l = <среднее желаемое число>
    double expovariate(double l);

    unsigned long long random_nonce();
} // namespace core::random