#pragma once
#include <vector>
#include <map>
#include <list>
#include <stdexcept>
#include <core/uint256.hpp>

namespace core::random
{
    // [min, max)
    int random_int(int min, int max);

    // [min, max]
    float random_float(float min, float max);

    std::vector<unsigned char> random_bytes(int32_t length);

	uint256 random_uint256();

    // random_choice on an EMPTY container used to be undefined behaviour:
    // random_int(0, 0) returns 0, and the vector overload then indexed [0]
    // past the end while the map/list overloads dereferenced end(). Every
    // call site is expected to guard on !container.empty() first; this throw
    // is the defence-in-depth backstop so a missed guard degrades into a
    // logged handler error (the protocol dispatchers wrap handle() in a
    // catch(const std::exception&)) instead of a freed-memory read.
    [[noreturn]] inline void throw_empty_choice()
    {
        throw std::out_of_range("core::random::random_choice on empty container");
    }

    template <typename T>
    T random_choice(std::vector<T> &list)
    {
        if (list.empty())
            throw_empty_choice();
        int pos = core::random::random_int(0, list.size());
        return list[pos];
    }

    template <typename T>
    T random_choice(const std::vector<T> &list)
    {
        if (list.empty())
            throw_empty_choice();
        int pos = core::random::random_int(0, list.size());
        return list[pos];
    }


    template <typename Key, typename Value>
    Value random_choice(std::map<Key, Value> _map)
    {
        if (_map.empty())
            throw_empty_choice();
        int pos = core::random::random_int(0, _map.size());
        auto item = _map.begin();
        std::advance(item, pos);
        return item->second;
    }

    template <typename Value>
    Value random_choice(std::list<Value> _list)
    {
        if (_list.empty())
            throw_empty_choice();
        int pos = core::random::random_int(0, _list.size());
        auto item = _list.begin();
        std::advance(item, pos);
        return *item;
    }

    /// l = desired mean value
    double expovariate(double l);

    unsigned long long random_nonce();
} // namespace core::random
