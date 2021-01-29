#pragma once

namespace c2pool::random
{
    ///[min, max)
    int RandomInt(int min, int max);

    ///[min, max]
    float RandomFloat(float min, float max);

    template <typename T>
    T RandomChoice(std::vector<T> &list);

    //TODO: Remake?
    // template <typename K, typename V, typename Compare = std::less<K>,
    //           typename Alloc = std::allocator<std::pair<const K, V>>>
    // V RandomChoice(std::map<K, V, Compare, Alloc> m)
    // { //TODO: THIS WANNA TEST
    //     int pos = RandomInt(0, m.size());
    //     std::iterator item = m.cbegin();
    //     return std::advance(item, pos);
    // }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l);

    unsigned long long RandomNonce();
} // namespace c2pool::random