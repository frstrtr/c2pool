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

    void seed(uint32_t value)
    {
        generator.seed(value);
    }

    ///[min, max)
    // A continuous uniform draw (p2pool: random.uniform). It used to be a
    // std::uniform_int_distribution over [min, max] divided back down, so
    // random_float(0, 100) returned only the 101 integers 0..100 and
    // random_float(0, 1) only 0 or 1: the node-fee draw `roll < fee` took the
    // fee with probability ceil(fee)/101, and `random_float(0, 1) < 0.8` held
    // 50% of the time.
    double random_double(double min, double max)
    {
        if (!(min < max))
            return min;
        std::uniform_real_distribution<double> rnd(min, max);
        double res = rnd(generator);
        // uniform_real_distribution may round up to max (LWG 2524); the
        // interval is half-open, so max is never returned.
        if (!(res < max))
            res = std::nextafter(max, min);
        if (res < min)
            res = min;
        return res;
    }

    ///[min, max)
    float random_float(float min, float max)
    {
        if (!(min < max))
            return min;
        float res = static_cast<float>(random_double(min, max));
        // narrowing a double just under max can round to max itself.
        if (!(res < max))
            res = std::nextafter(max, min);
        if (res < min)
            res = min;
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
