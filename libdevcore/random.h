#pragma once
#include <vector>
#include <map>
#include <list>
#include <btclibs/uint256.h>

namespace c2pool::random
{
    ///[min, max)
    int RandomInt(int min, int max);

    ///[min, max]
    float RandomFloat(float min, float max);

    std::vector<unsigned char> random_bytes(int32_t length);

	uint256 random_uint256();

    template <typename T>
    T RandomChoice(std::vector<T> &list)
    {
        int pos = RandomInt(0, list.size());
        return list[pos];
    }


    template <typename Key, typename Value>
    Value RandomChoice(std::map<Key, Value> _map)
    {
        int pos = RandomInt(0, _map.size());
        auto item = _map.begin();
        std::advance(item, pos);
        return item->second;
    }

    template <typename Value>
    Value RandomChoice(std::list<Value> _list)
    {
        int pos = RandomInt(0, _list.size());
        auto item = _list.begin();
        std::advance(item, pos);
        return *item;
    }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l);

    unsigned long long randomNonce();
} // namespace c2pool::random