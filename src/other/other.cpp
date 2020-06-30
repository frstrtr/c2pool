#include "other.h"
#include <iostream>
#include <boost/random.hpp>
#include <vector>
#include <ctime>
#include <cmath>
#include <cstring>
#include <sstream>

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

    template <typename K, typename V>
    V RandomChoice(std::map<K, V> map)
    { //TODO: THIS WANNA TEST
        int pos = RandomInt(0, map.size());
        return std::advance(map.begin(), pos);
    }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l)
    {
        return (log(RandomInt(1, RAND_MAX) + 1) - log(RAND_MAX)) / (-l);
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
    void substr(char *dest, char *source, int from, int length)
    {
        strncpy(dest, source + from, length);
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
            char bbuff = buff;
            str_result += bbuff;
        }
        // std::cout << "lentgth ss: " << str_result.length() << std::endl;
        // std::cout << "str_result: " << str_result << std::endl;
        // std::cout << "str_result.c_str(): " << str_result.c_str() << std::endl;
        char *result = new char[str_result.length() + 1];
        memcpy(result, str_result.c_str(), str_result.length());
        // for (int i = 0; i < str_result.length(); i++)
        // {
            
        // }

        
        return result;
    }
} // namespace c2pool::str