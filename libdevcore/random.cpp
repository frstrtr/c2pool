#include "random.h"
#include <boost/random.hpp>
#include <ctime>
#include <cmath>
#include <vector>

namespace c2pool::random
{
    using namespace boost::random;

    boost::random::mt19937 generator(std::time(nullptr));

    ///[min, max)
    int RandomInt(int min, int max)
    {
        if (min == max)
            return min;
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
        bytes.reserve(length);

        for (int i = 0; i < length; i++)
        {
            bytes.emplace_back(c2pool::random::RandomInt(0, 256));
        }
		return bytes;
    }

	uint256 random_uint256()
	{
		auto bytes = random_bytes(32);
		uint256 result(bytes);
		return result;
	}

    ///l = <среднее желаемое число>
    double Expovariate(double l)
    {
        boost::random::exponential_distribution<double> rnd(l);
        return rnd(generator);
//        return (log(RandomInt(1, RAND_MAX) + 1) - log(RAND_MAX)) / (-1 / l);
    }

    unsigned long long randomNonce()
    {
        boost::random::uniform_int_distribution<unsigned long long> rnd(0, 0xFFFFFFFFFFFFFFFF);
        return rnd(generator);
    }

} // namespace c2pool::random