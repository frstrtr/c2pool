#include "random.hpp"
#include <random>
#include <ctime>
#include <cmath>

namespace core::random
{
    std::mt19937 generator(std::time(nullptr));

    ///[min, max)
    int random_int(int min, int max)
    {
        if (min == max)
            return min;
        std::uniform_int_distribution<> rnd(min, max - 1);
        return rnd(generator);
    }

    ///[min, max]
    float random_float(float min, float max)
    {
        float Min = float(min), Max = float(max);
        std::uniform_int_distribution<> rnd(Min, Max);
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
            bytes.emplace_back(core::random::random_int(0, 256));
        }
		return bytes;
    }

	uint256 random_uint256()
	{
		auto bytes = core::random::random_bytes(32);
		uint256 result(bytes);
		return result;
	}

    /// l = desired mean value
    double expovariate(double l)
    {
        std::exponential_distribution<double> rnd(l);
        return rnd(generator);
    }

    unsigned long long random_nonce()
    {
        std::uniform_int_distribution<unsigned long long> rnd(0, 0xFFFFFFFFFFFFFFFF);
        return rnd(generator);
    }

} // namespace core::random
