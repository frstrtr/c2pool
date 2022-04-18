#include "random.h"
#include <boost/random.hpp>
#include <ctime>
#include <cmath>
#include <vector>

namespace c2pool::random
{
    using namespace boost::random;

    boost::random::mt19937 generator(std::time(0));

    ///[min, max)
    int RandomInt(int min, int max)
    {
        boost::random::uniform_int_distribution<> rnd(min, max - 1);
        return rnd(generator);
    }

    ///[min, max]
    float RandomFloat(float min, float max)
    {
        float Min = float(min), Max = float(max);
        boost::random::uniform_int_distribution<> rnd(Min, Max);
        float res = ((float)rnd(generator) / Max);
        float range = Max - Min;
        res = (res * range) + Min;
        return res;
    }

    std::vector<unsigned char> random_bytes(int32_t length)
    {
        std::vector<unsigned char> bytes;

        for (int i = 0; i < length; i++)
        {
            bytes.emplace_back(c2pool::random::RandomInt(0, 256));
        }

    }

    template <typename T>
    T RandomChoice(std::vector<T> &list)
    {
        int pos = RandomInt(0, list.size());
        return list[pos];
    }

    // template <typename K, typename V, typename Compare = std::less<K>,
    //     typename Alloc = std::allocator<std::pair<const K, V> > >
    // V RandomChoice(std::map<K, V, Compare, Alloc> map)
    // { //TODO: THIS WANNA TEST
    //     int pos = RandomInt(0, map.size());
    //     return std::advance(map.begin(), pos);
    // }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l)
    {
        return (log(RandomInt(1, RAND_MAX) + 1) - log(RAND_MAX)) / (-1 / l);
    }

    unsigned long long RandomNonce()
    {
        boost::random::uniform_int_distribution<unsigned long long> rnd(0, 0xFFFFFFFFFFFFFFFF);
        return rnd(generator);
    }

} // namespace c2pool::random