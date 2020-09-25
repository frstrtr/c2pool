#include "other.h"
#include <iostream>
#include <boost/random.hpp>
#include <vector>
#include <ctime>
#include <cmath>
#include <cstring>
#include <sstream>
#include <string>
#include <map>
#include <memory>
#include <iterator>

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

    template <typename T>
    T RandomChoice(std::vector<T> &list)
    {
        int pos = RandomInt(0, list.size());
        return list[pos];
    }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l)
    {
        return (log(RandomInt(1, RAND_MAX) + 1) - log(RAND_MAX)) / (-1/l);
    }

    unsigned long long RandomNonce()
    {
        boost::random::uniform_int_distribution<unsigned long long> rnd(0, 0xFFFFFFFFFFFFFFFF);
        return rnd(generator);
    }

} // namespace c2pool::random

namespace c2pool::time
{
    int timestamp()
    {
        return std::time(nullptr);
    }
} // namespace c2pool::time

namespace c2pool::str
{
    void substr(char *dest, char *source, int from, unsigned int length)
    {
        memcpy(dest, source + from, length);
        dest[length] = 0;
    }

    char *from_bytes_to_strChar(char *source)
    {
        std::stringstream ss;
        ss << source;
        int buff;
        std::string str_result = "";
        while (ss >> buff)
        {
            unsigned char bbuff = buff;
            str_result += bbuff;
        }
        // std::cout << "lentgth ss: " << str_result.length() << std::endl;
        // std::cout << "str_result: " << str_result << std::endl;
        // std::cout << "str_result.c_str(): " << str_result.c_str() << std::endl;
        unsigned char *result = new unsigned char[str_result.length() + 1];
        memcpy(result, str_result.c_str(), str_result.length());

        return (char *)result;
    }

    bool compare_str(const void* first_str, const void* second_str, unsigned int length)
    {
        if (memcmp(first_str, second_str, length) == 0)
            return true;
        return false;
    }

    int str_to_int(std::string s){
        std::stringstream ss;
        ss << s;
        int res;
        ss >> res;
        return res;
    }
} // namespace c2pool::str